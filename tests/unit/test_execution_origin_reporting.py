"""Reporting regressions for execution-originated findings."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    AuditQualityStatus,
    AuditReport,
    CandidateFinding,
    CandidateOriginKind,
    Evidence,
    EvidenceStrength,
    ExecutionOriginDispositionKind,
    ExecutionOriginRejectionCategory,
    Finding,
    FindingOriginKind,
    FindingStatus,
    InvariantExecutionCandidateProvenance,
    InvariantExecutionOriginDisposition,
    InvariantExecutionResult,
    InvariantSuite,
    Location,
    LocationValidation,
    ModelVote,
    RepositoryMap,
    ScannerFinding,
    Severity,
    VerificationTest,
    execution_origin_location_validation_sha256,
)
from mmaudit.orchestration.consensus import (
    bind_model_analysis_to_execution_origin,
    group_candidates,
    merge_group,
)
from mmaudit.orchestration.pipeline import _scanner_findings_for_report
from mmaudit.orchestration.run_status import (
    assess_minimum_analysis_floor,
    minimum_analysis_floor_quality_gate,
)
from mmaudit.reporting.markdown import render_markdown
from mmaudit.reporting.sarif import generate_sarif
from tests.unit.test_execution_candidates import (
    _build as _build_execution_candidates,
)
from tests.unit.test_execution_candidates import (
    _inputs as _execution_inputs,
)
from tests.unit.test_execution_candidates import (
    _reseal_execution,
)


def _provenance() -> InvariantExecutionCandidateProvenance:
    return InvariantExecutionCandidateProvenance.sealed(
        invariant_id="invariant-accounting",
        invariant_evidence_sha256="1" * 64,
        harness_name="SyntheticAccountingHarness",
        harness_spec_sha256="2" * 64,
        property_corpus_sha256="3" * 64,
        property_ids=(f"prop-{'4' * 24}",),
        property_hashes=("4" * 64,),
        execution_result_sha256="5" * 64,
        execution_observation_sha256="6" * 64,
        executable_sha256="7" * 64,
        source_sha256="8" * 64,
        compiler_version="forge 1.5.0 / solc 0.8.30",
        compiler_sha256="9" * 64,
        isolation_backend="rootless-container",
        isolation_attestation_sha256="a" * 64,
        attempts=2,
        successful_attempts=2,
        minimized=True,
        source_locations=(
            Location(
                path="src/SyntheticVault.sol",
                start_line=11,
                end_line=14,
                symbol="account",
                content_hash="b" * 64,
            ),
        ),
    )


def _execution_candidate(
    provenance: InvariantExecutionCandidateProvenance,
) -> CandidateFinding:
    return CandidateFinding(
        candidate_id=f"exec-{provenance.provenance_sha256[:24]}",
        origin_kind=CandidateOriginKind.DETERMINISTIC_EXECUTION,
        execution_provenance=provenance,
        title="Executed accounting invariant",
        severity=Severity.HIGH,
        confidence=0.94,
        cwe=["CWE-682"],
        summary="Repeated local execution observed an incorrect accounting transition.",
        impact="The declared accounting invariant does not hold.",
        preconditions=["The bounded synthetic action is reachable."],
        locations=list(provenance.source_locations),
        attack_path=["Exercise the bounded synthetic accounting action."],
        evidence=[
            Evidence(
                type="execution",
                source="mmaudit-foundry-invariant",
                description="Two fresh local attempts produced the same counterexample.",
                rule_id=provenance.invariant_id,
                fingerprint=provenance.provenance_sha256,
            )
        ],
        false_positive_conditions=["The typed invariant does not express intended behavior."],
        recommendation="Correct the transition and rerun the local invariant campaign.",
        verification_test=VerificationTest(
            description="Replay the typed invariant in a fresh isolated workspace."
        ),
        role=None,
        model_family=None,
    )


def _model_candidate(
    provenance: InvariantExecutionCandidateProvenance,
    *,
    commentary: str,
) -> CandidateFinding:
    candidate = CandidateFinding(
        candidate_id="candidate-model-commentary",
        title="Executed accounting invariant",
        severity=Severity.CRITICAL,
        confidence=0.99,
        cwe=["CWE-682"],
        summary=commentary,
        impact="A model supplied an impact interpretation.",
        preconditions=["The model assumes the bounded action is reachable."],
        locations=list(provenance.source_locations),
        attack_path=["A model described a possible consequence."],
        evidence=[
            Evidence(
                type="model",
                source="business_logic",
                description=commentary,
            )
        ],
        false_positive_conditions=["The model interpretation may be incorrect."],
        recommendation="A model suggested an additional remediation.",
        verification_test=VerificationTest(
            description="Review the model commentary against the local witness."
        ),
        role="business_logic",
        model_family="synthetic/model-family",
        model_votes=[
            ModelVote(
                role="business_logic",
                requested_model="synthetic/model",
                returned_model="synthetic/model",
                family="synthetic/model-family",
                verdict="commentary",
                rationale=commentary,
            )
        ],
    )
    return bind_model_analysis_to_execution_origin(
        execution_candidate=_execution_candidate(provenance),
        model_candidate=candidate,
    )


def _execution_finding(
    provenance: InvariantExecutionCandidateProvenance,
    *,
    model_commentary: bool = False,
) -> Finding:
    evidence = [
        Evidence(
            type="execution",
            source="mmaudit-foundry-invariant",
            description="Two fresh local attempts produced the same counterexample.",
            rule_id=provenance.invariant_id,
            fingerprint=provenance.provenance_sha256,
        )
    ]
    votes: list[ModelVote] = []
    if model_commentary:
        evidence.append(
            Evidence(
                type="model",
                source="business_logic",
                description="A model supplied bounded impact commentary.",
            )
        )
        votes.append(
            ModelVote(
                role="business_logic",
                requested_model="synthetic/model",
                returned_model="synthetic/model",
                family="synthetic/model-family",
                verdict="commentary",
                rationale="Bounded impact commentary only.",
            )
        )
    return Finding(
        id="MMA-EXECUTION001",
        group_id="group-execution001",
        origin_kind=FindingOriginKind.DETERMINISTIC_EXECUTION,
        execution_provenance=(provenance,),
        title="Executed accounting invariant",
        status=FindingStatus.CONFIRMED,
        severity=Severity.HIGH,
        confidence=0.94,
        cwe=["CWE-682"],
        summary="Repeated local execution observed an incorrect accounting transition.",
        impact="The declared accounting invariant does not hold.",
        preconditions=["The bounded synthetic action is reachable."],
        locations=list(provenance.source_locations),
        attack_path=["Exercise the bounded synthetic accounting action."],
        evidence=evidence,
        false_positive_conditions=["The typed invariant does not express intended behavior."],
        recommendation="Correct the transition and rerun the local invariant campaign.",
        verification_test=VerificationTest(
            description="Replay the typed invariant in a fresh isolated workspace."
        ),
        model_votes=votes,
        location_validation=LocationValidation(
            valid=True,
            content_hash=execution_origin_location_validation_sha256((provenance,)),
        ),
        contributing_candidate_ids=[f"exec-{provenance.provenance_sha256[:24]}"],
        evidence_strength=EvidenceStrength.DETERMINISTIC_EXECUTION_COUNTEREXAMPLE,
    )


def _review_finding(origin_kind: FindingOriginKind) -> Finding:
    is_static = origin_kind is FindingOriginKind.STATIC_ANALYZER
    label = "Static analyzer" if is_static else "Model review"
    return Finding(
        id="MMA-STATIC001" if is_static else "MMA-MODEL001",
        group_id="group-static001" if is_static else "group-model001",
        origin_kind=origin_kind,
        title=f"{label} observation",
        status=FindingStatus.NEEDS_REVIEW,
        severity=Severity.MEDIUM,
        confidence=0.75,
        summary=f"{label} identified a synthetic condition for local review.",
        impact="The condition may affect expected behavior.",
        preconditions=["The cited path is reachable."],
        locations=[
            Location(
                path="src/ReviewTarget.sol",
                start_line=20 if is_static else 30,
                end_line=22 if is_static else 32,
                symbol="reviewTarget",
            )
        ],
        attack_path=["Review the cited synthetic condition."],
        evidence=[
            Evidence(
                type="scanner" if is_static else "model",
                source="semgrep" if is_static else "business_logic",
                description=f"{label} evidence.",
                rule_id="synthetic-rule" if is_static else None,
                fingerprint="scanner-fingerprint" if is_static else None,
            )
        ],
        false_positive_conditions=["The cited path is unreachable."],
        recommendation="Validate the condition with a safe local regression.",
        verification_test=VerificationTest(
            description="Run a synthetic local regression for the cited condition."
        ),
        location_validation=LocationValidation(valid=True, content_hash="d" * 64),
        contributing_candidate_ids=[
            "scanner-fingerprint" if is_static else "candidate-model-review"
        ],
        evidence_strength=(
            EvidenceStrength.DETERMINISTIC_ANALYZER
            if is_static
            else EvidenceStrength.MODEL_INFERENCE
        ),
    )


def _report(
    findings: list[Finding],
    *,
    rejected_findings: list[Finding] | None = None,
) -> AuditReport:
    report = AuditReport(
        schema_version="1.0",
        run_id="run-execution-origin-reporting",
        generated_at=datetime.now(UTC),
        completed=True,
        incomplete_reasons=[],
        repository=RepositoryMap(
            root_name="synthetic-origin-fixture",
            languages={"Solidity": 2},
            frameworks=[],
            manifests=[],
            entry_points=[],
            api_surfaces=[],
            auth_components=[],
            data_layers=[],
            network_clients=[],
            file_handlers=[],
            configuration_files=[],
            sensitive_processing=[],
            security_tests=[],
            files=[],
        ),
        configuration_hash="configuration-hash",
        model_configuration_hash="model-configuration-hash",
        privacy={
            "code_egress_enabled": False,
            "require_zdr": True,
            "redact_secrets": True,
            "store_raw_prompts": False,
            "store_raw_responses": False,
        },
        scanner_runs=[],
        usage=[],
        budget_usd=0,
        accounted_cost_usd=0,
        findings=[],
        rejected_findings=[],
        metadata={"configured_models": {}},
    )
    # Reporting is the unit under test. Each Finding is independently schema-validated;
    # runtime evidence binding is covered by the AuditReport schema tests.
    return report.model_copy(
        update={
            "findings": findings,
            "rejected_findings": rejected_findings or [],
        }
    )


def _execution_runtime(
    tmp_path: Path,
) -> tuple[InvariantSuite, InvariantExecutionResult, InvariantExecutionCandidateProvenance]:
    repository, suite, harness, corpus, execution = _execution_inputs(tmp_path)
    build = _build_execution_candidates(repository, suite, harness, corpus, execution)
    assert len(build.candidates) == 1
    provenance = build.candidates[0].execution_provenance
    assert provenance is not None
    return suite, execution, provenance


def _rejected_execution_finding(
    provenance: InvariantExecutionCandidateProvenance,
) -> Finding:
    payload = _execution_finding(provenance).model_dump(mode="python")
    payload.update(
        {
            "status": FindingStatus.REJECTED,
            "disagreement": "Synthetic evidence did not survive validation.",
            "location_validation": LocationValidation(
                valid=False,
                errors=["Synthetic source-location validation rejected this candidate."],
            ).model_dump(mode="python"),
        }
    )
    return Finding.model_validate(payload)


def _current_execution_report(
    findings: list[Finding],
    *,
    rejected_findings: list[Finding] | None = None,
    invariants: InvariantSuite | None = None,
    invariant_executions: list[InvariantExecutionResult] | None = None,
    dispositions: list[InvariantExecutionOriginDisposition] | None = None,
) -> AuditReport:
    repository = _report([]).repository
    floor = assess_minimum_analysis_floor(
        repository=repository,
        compilations=[],
        scanner_runs=[],
        usage=[],
        required_model_roles=[],
        coverage_metrics={},
        solidity_applicable=False,
        static_analysis_applicable=True,
        model_review_applicable=False,
        scanner_only=True,
    )
    execution_dispositions = dispositions or []
    rejected_dispositions = [
        disposition
        for disposition in execution_dispositions
        if disposition.kind is ExecutionOriginDispositionKind.REJECTED
    ]
    incomplete_reasons = sorted(
        {
            *floor.limitations,
            *(
                [
                    "execution-origin evidence rejected: "
                    + min(
                        rejected_dispositions,
                        key=lambda disposition: disposition.execution_index,
                    ).rejection_detail
                ]
                if rejected_dispositions
                else []
            ),
        }
    )
    return AuditReport(
        schema_version="1.2",
        run_id="run-execution-origin-reporting",
        generated_at=datetime.now(UTC),
        completed=False,
        incomplete_reasons=incomplete_reasons,
        repository=repository,
        configuration_hash="configuration-hash",
        model_configuration_hash="model-configuration-hash",
        privacy={
            "code_egress_enabled": False,
            "require_zdr": True,
            "redact_secrets": True,
            "store_raw_prompts": False,
            "store_raw_responses": False,
        },
        scanner_runs=[],
        usage=[],
        budget_usd=0,
        accounted_cost_usd=0,
        findings=findings,
        rejected_findings=rejected_findings or [],
        quality_status=AuditQualityStatus.FAILED,
        run_status=floor.run_status,
        minimum_analysis_floor=floor,
        quality_gates=[minimum_analysis_floor_quality_gate(floor)],
        invariants=invariants,
        invariant_executions=invariant_executions or [],
        execution_origin_dispositions=execution_dispositions,
        metadata={
            "configured_models": {},
            "scanner_only": True,
            "solidity": {"projects": [], "compilation": []},
        },
    )


def _sarif_result(finding: Finding) -> tuple[dict[str, object], dict[str, object]]:
    run = generate_sarif([finding])["runs"][0]
    return run["tool"]["driver"]["rules"][0], run["results"][0]


def test_markdown_distinguishes_originated_and_rejected_runtime_origins(
    tmp_path: Path,
) -> None:
    suite, execution, provenance = _execution_runtime(tmp_path / "originated")
    originated = InvariantExecutionOriginDisposition(
        execution_index=0,
        invariant_id=provenance.invariant_id,
        harness_name=provenance.harness_name,
        execution_result_sha256=provenance.execution_result_sha256,
        kind=ExecutionOriginDispositionKind.ORIGINATED,
        candidate_id=f"exec-{provenance.provenance_sha256[:24]}",
        execution_provenance=provenance,
    )
    rejected_execution = _reseal_execution(
        execution,
        invariant_id="invariant-rejected-source",
        harness_name="Rejected | Harness",
    )
    rejected = InvariantExecutionOriginDisposition(
        execution_index=1,
        invariant_id=rejected_execution.invariant_id,
        harness_name=rejected_execution.harness_name,
        execution_result_sha256=rejected_execution.canonical_result_sha256(),
        kind=ExecutionOriginDispositionKind.REJECTED,
        rejection_category=ExecutionOriginRejectionCategory.SOURCE_BINDING,
        rejection_detail="Current source <changed> | exact location no longer validates.",
    )
    report = _current_execution_report(
        [],
        rejected_findings=[_rejected_execution_finding(provenance)],
        invariants=suite,
        invariant_executions=[execution, rejected_execution],
        dispositions=[originated, rejected],
    )

    markdown = render_markdown(report)

    assert "## Deterministic execution-origin dispositions" in markdown
    assert "Runtime counterexamples dispositioned: 2" in markdown
    assert "Originated candidates: 1" in markdown
    assert "Rejected before candidate creation: 1" in markdown
    assert "`originated`" in markdown
    assert originated.candidate_id in markdown
    assert provenance.provenance_sha256[:12] in markdown
    assert "`rejected`" in markdown
    assert "`source_binding`" in markdown
    assert "Rejected \\| Harness" in markdown
    assert "Current source &lt;changed&gt; \\| exact location no longer validates." in markdown
    assert "is not a finding, and is omitted from SARIF" in markdown

    sarif = generate_sarif(report.findings)["runs"][0]
    assert sarif["tool"]["driver"]["rules"] == []
    assert sarif["results"] == []


def test_execution_origin_disposition_markdown_is_bounded(tmp_path: Path) -> None:
    suite, base_execution, _ = _execution_runtime(tmp_path / "bounded")
    executions = [
        _reseal_execution(
            base_execution,
            invariant_id=f"invariant-bounded-{index:03d}",
            harness_name=f"BoundedHarness{index:03d}",
        )
        for index in range(25)
    ]
    dispositions = [
        InvariantExecutionOriginDisposition(
            execution_index=index,
            invariant_id=execution.invariant_id,
            harness_name=execution.harness_name,
            execution_result_sha256=execution.canonical_result_sha256(),
            kind=ExecutionOriginDispositionKind.REJECTED,
            rejection_category=ExecutionOriginRejectionCategory.RUNTIME_EVIDENCE,
            rejection_detail=f"bounded-marker-{index:03d}",
        )
        for index, execution in enumerate(executions)
    ]
    report = _current_execution_report(
        [],
        invariants=suite,
        invariant_executions=executions,
        dispositions=dispositions,
    )

    markdown = render_markdown(report)

    assert "Runtime counterexamples dispositioned: 25" in markdown
    assert "Originated candidates: 0" in markdown
    assert "Rejected before candidate creation: 25" in markdown
    assert "bounded-marker-019" in markdown
    assert "bounded-marker-020" not in markdown
    assert markdown.count("| `rejected` |") == 20
    assert "5 additional disposition record(s) remain in the JSON forensic artifacts." in markdown


def test_markdown_and_sarif_distinguish_all_discovery_origins(tmp_path: Path) -> None:
    suite, execution, provenance = _execution_runtime(tmp_path)
    findings = [
        _review_finding(FindingOriginKind.MODEL_REVIEW),
        _execution_finding(provenance),
        _review_finding(FindingOriginKind.STATIC_ANALYZER),
    ]
    disposition = InvariantExecutionOriginDisposition(
        execution_index=0,
        invariant_id=provenance.invariant_id,
        harness_name=provenance.harness_name,
        execution_result_sha256=provenance.execution_result_sha256,
        kind=ExecutionOriginDispositionKind.ORIGINATED,
        candidate_id=f"exec-{provenance.provenance_sha256[:24]}",
        execution_provenance=provenance,
    )

    markdown = render_markdown(
        _current_execution_report(
            findings,
            invariants=suite,
            invariant_executions=[execution],
            dispositions=[disposition],
        )
    )

    assert (
        "Finding discovery origins: deterministic execution=1, model review=1, static analyzer=1."
        in markdown
    )
    assert "Discovery origin: **Independent model review**" in markdown
    assert "Discovery origin: **Deterministic execution**" in markdown
    assert "Discovery origin: **Static analyzer**" in markdown
    assert "replay-confirmed deterministic invariant counterexample" in markdown
    assert (
        "Confirmed:** passed the deterministic consensus gate and verifier review" not in markdown
    )

    sarif = generate_sarif(findings)["runs"][0]
    rules = {rule["id"]: rule for rule in sarif["tool"]["driver"]["rules"]}
    results = {result["ruleId"]: result for result in sarif["results"]}
    expected_origins = {
        "MMA-MODEL001": FindingOriginKind.MODEL_REVIEW,
        "MMA-EXECUTION001": FindingOriginKind.DETERMINISTIC_EXECUTION,
        "MMA-STATIC001": FindingOriginKind.STATIC_ANALYZER,
    }
    for finding_id, origin in expected_origins.items():
        assert rules[finding_id]["properties"]["findingOrigin"] == origin.value
        assert f"origin/{origin.value}" in rules[finding_id]["properties"]["tags"]
        assert results[finding_id]["properties"]["findingOrigin"] == origin.value
        assert f"[{origin.value}]" in results[finding_id]["message"]["text"]


def test_legacy_report_version_cannot_claim_execution_origin() -> None:
    report = _report([_execution_finding(_provenance())])

    with pytest.raises(ValidationError, match=r"report schema 1\.2"):
        AuditReport.model_validate(report.model_dump(mode="python"))


def test_scanner_report_conversion_preserves_static_analyzer_origin(tmp_path: Path) -> None:
    source = tmp_path / "src" / "ScannerTarget.sol"
    source.parent.mkdir(parents=True)
    source.write_text(
        "pragma solidity 0.8.30;\ncontract ScannerTarget {}\n",
        encoding="utf-8",
    )
    scanner = ScannerFinding(
        scanner="semgrep",
        rule_id="synthetic-rule",
        title="Synthetic scanner observation",
        severity=Severity.MEDIUM,
        message="A deterministic analyzer matched a synthetic rule.",
        locations=[
            Location(
                path="src/ScannerTarget.sol",
                start_line=2,
                end_line=2,
                symbol="ScannerTarget",
            )
        ],
        fingerprint="synthetic-scanner-fingerprint",
    )

    finding = _scanner_findings_for_report(tmp_path, [scanner])[0]

    assert finding.origin_kind is FindingOriginKind.STATIC_ANALYZER
    markdown = render_markdown(_report([finding]))
    rule, result = _sarif_result(finding)
    assert "Discovery origin: **Static analyzer**" in markdown
    assert rule["properties"]["findingOrigin"] == FindingOriginKind.STATIC_ANALYZER.value
    assert result["properties"]["findingOrigin"] == FindingOriginKind.STATIC_ANALYZER.value


def test_execution_reporting_retains_nonmodel_attribution_and_origin_identity(
    tmp_path: Path,
) -> None:
    suite, execution, provenance = _execution_runtime(tmp_path)
    finding = _execution_finding(provenance, model_commentary=True)
    disposition = InvariantExecutionOriginDisposition(
        execution_index=0,
        invariant_id=provenance.invariant_id,
        harness_name=provenance.harness_name,
        execution_result_sha256=provenance.execution_result_sha256,
        kind=ExecutionOriginDispositionKind.ORIGINATED,
        candidate_id=f"exec-{provenance.provenance_sha256[:24]}",
        execution_provenance=provenance,
    )

    markdown = render_markdown(
        _current_execution_report(
            [finding],
            invariants=suite,
            invariant_executions=[execution],
            dispositions=[disposition],
        )
    )
    rule, result = _sarif_result(finding)

    assert "Discovery origin: **Deterministic execution**" in markdown
    assert (
        "This finding originated from deterministic execution and is not model-attributed."
        in markdown
    )
    assert (
        "Model contribution is limited to impact, exploitability, and remediation analysis; "
        "it cannot alter the execution-bound identity or location."
    ) in markdown
    assert "Discovery origin: **Independent model review**" not in markdown
    assert provenance.provenance_sha256[:12] in markdown

    for properties in (rule["properties"], result["properties"]):
        assert properties["findingOrigin"] == FindingOriginKind.DETERMINISTIC_EXECUTION.value
        assert properties["groupId"] == finding.group_id
        assert properties["executionProvenanceSha256s"] == [provenance.provenance_sha256]
    assert "origin/deterministic_execution" in rule["properties"]["tags"]
    assert "origin/model_review" not in rule["properties"]["tags"]


def test_sarif_origin_fingerprint_is_stable_under_model_commentary() -> None:
    provenance = _provenance()
    original = _execution_finding(provenance)
    with_commentary = Finding.model_validate(
        {
            **original.model_dump(mode="python"),
            "severity": Severity.CRITICAL,
            "confidence": 0.51,
            "impact": "A model supplied a different impact interpretation.",
            "recommendation": "A model supplied different remediation commentary.",
            "evidence": [
                *original.evidence,
                Evidence(
                    type="model",
                    source="business_logic",
                    description="Non-authoritative impact commentary.",
                ),
            ],
            "model_votes": [
                ModelVote(
                    role="business_logic",
                    requested_model="synthetic/model",
                    returned_model="synthetic/model",
                    family="synthetic/model-family",
                    verdict="commentary",
                    rationale="Non-authoritative impact commentary.",
                )
            ],
        }
    )

    _, original_result = _sarif_result(original)
    _, commentary_result = _sarif_result(with_commentary)

    expected = hashlib.sha256(
        json.dumps(
            {
                "finding_id": original.id,
                "group_id": original.group_id,
                "origin_kind": original.origin_kind.value,
                "execution_provenance_sha256s": [provenance.provenance_sha256],
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()
    assert original_result["partialFingerprints"]["mmaudit/origin/v1"] == expected
    assert commentary_result["partialFingerprints"]["mmaudit/origin/v1"] == expected
    assert (
        commentary_result["properties"]["executionProvenanceSha256s"]
        == original_result["properties"]["executionProvenanceSha256s"]
    )
    assert commentary_result["properties"]["groupId"] == original_result["properties"]["groupId"]


def test_mixed_model_commentary_cannot_control_execution_group_or_evidence() -> None:
    provenance = _provenance()
    execution = _execution_candidate(provenance)
    model = _model_candidate(
        provenance,
        commentary="A model supplied impact and remediation commentary.",
    )
    execution_group = group_candidates([execution])[0]
    mixed_group = group_candidates([model, execution])[0]

    assert mixed_group.group_id == execution_group.group_id
    assert mixed_group.execution_candidates == (execution,)

    validations = {
        execution.candidate_id: LocationValidation(valid=True, content_hash="c" * 64),
        model.candidate_id: LocationValidation(valid=True, content_hash="d" * 64),
    }
    finding = merge_group(
        mixed_group,
        decisions={},
        validations=validations,
        scanner_findings=[],
        judge=None,
    )

    assert finding.origin_kind is FindingOriginKind.DETERMINISTIC_EXECUTION
    assert finding.group_id == execution_group.group_id
    assert finding.execution_provenance == (provenance,)
    assert finding.locations == list(provenance.source_locations)
    assert finding.title == execution.title
    assert finding.summary == execution.summary
    assert finding.impact == execution.impact
    assert finding.recommendation == execution.recommendation
    assert finding.evidence_strength is EvidenceStrength.DETERMINISTIC_EXECUTION_COUNTEREXAMPLE
    assert {item.type for item in finding.evidence} == {"execution", "model", "repository"}
    host_links = [
        item
        for item in finding.evidence
        if item.type == "repository" and item.source == "mmaudit-host-execution-link"
    ]
    assert len(host_links) == 1
    assert host_links[0].rule_id == provenance.invariant_id
    assert host_links[0].fingerprint == provenance.provenance_sha256
    assert finding.model_votes == model.model_votes

    rule, result = _sarif_result(finding)
    assert rule["properties"]["groupId"] == execution_group.group_id
    assert result["properties"]["executionProvenanceSha256s"] == [provenance.provenance_sha256]


def test_rejected_markdown_uses_origin_neutral_wording_and_sarif_omits_results(
    tmp_path: Path,
) -> None:
    suite, execution, provenance = _execution_runtime(tmp_path)
    rejected = [
        finding.model_copy(
            update={
                "status": FindingStatus.REJECTED,
                "disagreement": "Synthetic evidence did not survive validation.",
            }
        )
        for finding in (
            _review_finding(FindingOriginKind.MODEL_REVIEW),
            _rejected_execution_finding(provenance),
            _review_finding(FindingOriginKind.STATIC_ANALYZER),
        )
    ]
    disposition = InvariantExecutionOriginDisposition(
        execution_index=0,
        invariant_id=provenance.invariant_id,
        harness_name=provenance.harness_name,
        execution_result_sha256=provenance.execution_result_sha256,
        kind=ExecutionOriginDispositionKind.ORIGINATED,
        candidate_id=f"exec-{provenance.provenance_sha256[:24]}",
        execution_provenance=provenance,
    )

    markdown = render_markdown(
        _current_execution_report(
            [],
            rejected_findings=rejected,
            invariants=suite,
            invariant_executions=[execution],
            dispositions=[disposition],
        )
    )

    assert (
        "3 candidate group(s) were rejected. Rejection details and origin-specific "
        "contributing evidence remain in the JSON artifacts."
    ) in markdown
    assert "[Independent model review]" in markdown
    assert "[Deterministic execution]" in markdown
    assert "[Static analyzer]" in markdown
    assert "model-proposed candidate" not in markdown
    sarif = generate_sarif(rejected)["runs"][0]
    assert sarif["tool"]["driver"]["rules"] == []
    assert sarif["results"] == []
