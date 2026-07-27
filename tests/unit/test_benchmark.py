from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mmaudit.benchmark.claims import SuperiorityClaimStatus
from mmaudit.benchmark.engine import (
    BenchmarkManifest,
    BenchmarkManifestPayload,
    BenchmarkReport,
    BenchmarkStatus,
    evaluate_benchmark,
    load_manifest,
    validate_benchmark_ground_truth,
    write_benchmark_report,
)
from mmaudit.benchmark.mutations import (
    MutationKind,
    MutationPropertyOutcome,
    MutationScorecard,
    MutationTestOutcome,
    score_mutation_outcomes,
)
from mmaudit.models.schemas import (
    AuditProfile,
    AuditReport,
    Evidence,
    EvidenceStrength,
    Finding,
    FindingStatus,
    Location,
    LocationValidation,
    MaximumAssuranceAssessment,
    MaximumAssuranceStatus,
    RepositoryMap,
    ReproductionState,
    VerificationTest,
)

ROOT = Path(__file__).parents[2]
PROPERTY_A = "prop-" + ("a" * 24)
PROPERTY_B = "prop-" + ("b" * 24)


def _finding(case, *, status: FindingStatus = FindingStatus.CONFIRMED) -> Finding:
    return Finding(
        id=f"MMA-BENCH-{case.id}",
        title=case.category,
        status=status,
        severity=case.minimum_severity,
        confidence=0.95,
        cwe=case.expected_cwe,
        summary="Synthetic benchmark match.",
        impact="The planted local fixture property can be violated.",
        preconditions=["Synthetic fixture is exercised locally"],
        locations=[
            Location(
                path=case.path,
                start_line=case.start_line,
                end_line=case.end_line,
            )
        ],
        attack_path=["Invoke the planted local sequence", "Observe the violated property"],
        evidence=[
            Evidence(
                type="reproduction",
                source="mmaudit-local-fork-reproduction",
                description="Synthetic local reproduction.",
                rule_id="reproduced_and_minimized",
                fingerprint=f"hash-{case.id}",
            )
        ],
        false_positive_conditions=["The fixture is replaced with its patched control"],
        recommendation="Apply the fixture's documented local guard.",
        verification_test=VerificationTest(description="Run the synthetic regression test"),
        location_validation=LocationValidation(valid=True, content_hash="a" * 64),
        evidence_strength=EvidenceStrength.MINIMIZED_LOCAL_FORK_REPRODUCTION,
        reproduction_state=ReproductionState.REPRODUCED_AND_MINIMIZED,
    )


def _report(
    findings: list[Finding], *, root_name: str = "maximum_assurance_protocol"
) -> AuditReport:
    return AuditReport(
        schema_version="1.0",
        run_id="benchmark-run",
        generated_at=datetime.now(UTC),
        completed=True,
        incomplete_reasons=[],
        repository=RepositoryMap(
            root_name=root_name,
            languages={"Solidity": 13},
            frameworks=["Foundry"],
            manifests=["foundry.toml"],
            entry_points=[],
            api_surfaces=[],
            auth_components=[],
            data_layers=[],
            network_clients=[],
            file_handlers=[],
            configuration_files=["foundry.toml"],
            sensitive_processing=[],
            security_tests=[],
            files=[],
        ),
        configuration_hash="a" * 64,
        model_configuration_hash="b" * 64,
        privacy={"code_egress_enabled": True},
        scanner_runs=[],
        usage=[],
        budget_usd=20,
        accounted_cost_usd=1,
        findings=findings,
        rejected_findings=[],
        metadata={
            "duration_seconds": 12.5,
            "time_to_first_candidate_seconds": 2.25,
            "solidity": {
                "coverage": {
                    "contracts_indexed": 13,
                    "quality_metrics": {
                        "public_external_entry_points_reviewed": {
                            "numerator": 12,
                            "denominator": 12,
                            "percentage": 100.0,
                            "state": "model_only",
                            "detail": "synthetic benchmark coverage",
                        },
                        "external_calls_classified": {
                            "numerator": 4,
                            "denominator": 4,
                            "percentage": 100.0,
                            "state": "deterministic",
                            "detail": "synthetic external-call graph coverage",
                        },
                        "asset_flows_classified": {
                            "numerator": 3,
                            "denominator": 3,
                            "percentage": 100.0,
                            "state": "deterministic",
                            "detail": "synthetic asset-flow graph coverage",
                        },
                        "storage_variables_modelled": {
                            "numerator": 5,
                            "denominator": 5,
                            "percentage": 100.0,
                            "state": "deterministic",
                            "detail": "synthetic storage-layout coverage",
                        },
                        "invariants_executed": {
                            "numerator": 2,
                            "denominator": 2,
                            "percentage": 100.0,
                            "state": "deterministic",
                            "detail": "synthetic invariant execution coverage",
                        },
                        "economic_templates_executed": {
                            "numerator": 1,
                            "denominator": 1,
                            "percentage": 100.0,
                            "state": "deterministic",
                            "detail": "synthetic economic simulation coverage",
                        },
                        "economic_templates_with_typed_harness": {
                            "numerator": 1,
                            "denominator": 1,
                            "percentage": 100.0,
                            "state": "deterministic",
                            "detail": "synthetic typed economic harness coverage",
                        },
                    },
                }
            },
        },
    )


def _reports_by_repository(cases) -> dict[str, AuditReport]:
    grouped: dict[str, list[Finding]] = {}
    for case in cases:
        grouped.setdefault(case.repository_id, []).append(_finding(case))
    return {
        repository_id: _report(findings, root_name=repository_id)
        for repository_id, findings in grouped.items()
    }


def _complete_maximum(report: AuditReport) -> AuditReport:
    return report.model_copy(
        update={
            "maximum_assurance": MaximumAssuranceAssessment(
                requested=True,
                required=True,
                downgrade_allowed=False,
                downgraded=False,
                status=MaximumAssuranceStatus.COMPLETE,
            )
        }
    )


def _mutation_outcome(
    property_id: str,
    mutation_id: str,
    outcome: MutationTestOutcome,
) -> MutationPropertyOutcome:
    return MutationPropertyOutcome(
        mutation_id=mutation_id,
        mutation_kind=MutationKind.ACCOUNTING_OPERATOR_REPLACEMENT,
        property_id=property_id,
        outcome=outcome,
        evidence_sha256="c" * 64,
    )


def _passing_mutation_scorecard() -> MutationScorecard:
    return score_mutation_outcomes(
        property_corpus_hash="d" * 64,
        expected_property_ids=[PROPERTY_A, PROPERTY_B],
        property_repositories={
            PROPERTY_A: "maximum_assurance_protocol",
            PROPERTY_B: "economic_erc4626",
        },
        outcomes=[
            _mutation_outcome(PROPERTY_A, "mut-accounting-a", MutationTestOutcome.KILLED),
            _mutation_outcome(PROPERTY_B, "mut-accounting-b", MutationTestOutcome.KILLED),
        ],
        minimum_property_kill_score=1,
    )


def test_benchmark_measures_recall_safe_controls_and_evidence_caps() -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    vulnerable = [case for case in manifest.cases if case.variant == "vulnerable"]
    report = evaluate_benchmark(
        manifest,
        _reports_by_repository(vulnerable),
        profile=AuditProfile.STANDARD,
    )
    assert report.status is BenchmarkStatus.PASSED
    assert report.recall == report.critical_recall == 1
    assert all(value == 1 for value in report.recall_by_severity.values())
    assert report.precision == 1
    assert report.false_positive_rate == 0
    assert report.safe_high_critical_confirmations == 0
    assert report.reproduction_success_rate == 1
    assert report.vulnerable_cases_reproduced == report.vulnerable_cases
    report_count = len({case.repository_id for case in vulnerable})
    assert report.total_cost_usd == report_count
    assert report.total_runtime_seconds == 12.5 * report_count
    assert report.time_to_first_valid_finding_seconds == 2.25
    coverage = report.coverage_metrics["public_external_entry_points_reviewed"]
    assert coverage.numerator == coverage.denominator == 12 * report_count
    assert coverage.percentage == 100
    assert report.coverage_metrics["asset_flows_classified"].percentage == 100
    assert report.evidence_cap_bypasses == 0
    assert report.superiority_claim.status is SuperiorityClaimStatus.NOT_EVALUATED
    assert all(gate.passed for gate in report.gates)


def test_benchmark_has_secure_counterpart_and_valid_source_range_for_every_class() -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    fixtures = {
        "maximum_assurance_protocol": ROOT
        / "tests"
        / "fixtures"
        / "solidity"
        / "maximum_assurance_protocol",
        "economic_erc4626": ROOT / "tests" / "fixtures" / "solidity" / "economic_erc4626",
    }
    vulnerable_categories = {
        case.category for case in manifest.cases if case.variant == "vulnerable"
    }
    safe_categories = {case.category for case in manifest.cases if case.variant == "safe"}
    assert vulnerable_categories <= safe_categories
    assert len([case for case in manifest.cases if case.variant == "safe"]) >= len(
        [case for case in manifest.cases if case.variant == "vulnerable"]
    )
    bindings = validate_benchmark_ground_truth(manifest, workspace_root=ROOT)
    assert len(bindings) == 15
    assert manifest.corpus_sha256 == (
        "186534e1d0d263920d42041e39b05fd6fb4acc57f5e7e4c9c1321a403756845b"
    )
    for case in manifest.cases:
        path = fixtures[case.repository_id] / case.path
        assert path.is_file()
        assert case.end_line <= len(path.read_text(encoding="utf-8").splitlines())


def test_benchmark_ground_truth_rejects_manifest_and_source_tampering(
    tmp_path: Path,
) -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    tampered_manifest = manifest.model_dump(mode="json")
    tampered_manifest["description"] = "tampered"
    with pytest.raises(ValueError, match="corpus hash"):
        BenchmarkManifest.model_validate(tampered_manifest)
    sensitive_manifest = manifest.model_dump(mode="json", exclude={"corpus_sha256"})
    sensitive_manifest["cases"][0]["path"] = ".env"
    with pytest.raises(ValueError, match="source file"):
        BenchmarkManifestPayload.model_validate(sensitive_manifest)

    for repository in manifest.repositories:
        shutil.copytree(
            ROOT / repository.source_root,
            tmp_path / repository.source_root,
        )
    case = manifest.cases[0]
    repository = next(
        item for item in manifest.repositories if item.repository_id == case.repository_id
    )
    source = tmp_path / repository.source_root / case.path
    source.write_text(
        source.read_text(encoding="utf-8") + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="source hash changed"):
        validate_benchmark_ground_truth(manifest, workspace_root=tmp_path)


def test_mutation_scorecard_requires_exact_repository_attribution() -> None:
    with pytest.raises(ValueError, match="one repository binding"):
        score_mutation_outcomes(
            property_corpus_hash="d" * 64,
            expected_property_ids=[PROPERTY_A],
            property_repositories={PROPERTY_B: "economic_erc4626"},
            outcomes=[],
            minimum_property_kill_score=1,
        )


def test_published_benchmark_manifest_schema_is_strict_and_bounded() -> None:
    schema = json.loads(
        (ROOT / "schemas" / "benchmark_manifest.schema.json").read_text(encoding="utf-8")
    )

    assert schema["additionalProperties"] is False
    assert schema["properties"]["cases"]["maxItems"] == 10_000
    assert schema["$defs"]["blinding"]["additionalProperties"] is False
    assert schema["$defs"]["repository"]["additionalProperties"] is False
    assert schema["$defs"]["case"]["additionalProperties"] is False
    assert schema["$defs"]["case"]["properties"]["source_sha256"]["pattern"] == ("^[0-9a-f]{64}$")
    assert schema["properties"]["corpus_sha256"]["pattern"] == "^[0-9a-f]{64}$"


def test_per_repository_metrics_prevent_aggregate_masking() -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    vulnerable = [case for case in manifest.cases if case.variant == "vulnerable"]
    reports = _reports_by_repository(vulnerable)
    reports["economic_erc4626"] = _report([], root_name="economic_erc4626")

    result = evaluate_benchmark(
        manifest,
        reports,
        profile=AuditProfile.STANDARD,
    )

    repositories = {item.repository_id: item for item in result.repository_metrics}
    assert result.critical_recall == 1
    assert result.recall > 0.9
    assert repositories["maximum_assurance_protocol"].recall == 1
    assert repositories["economic_erc4626"].recall == 0
    assert repositories["economic_erc4626"].location_accuracy == 0
    assert repositories["economic_erc4626"].reproduction_success_rate == 0
    assert repositories["economic_erc4626"].cost_usd == 1
    assert repositories["economic_erc4626"].runtime_seconds == 12.5
    assert result.status is BenchmarkStatus.FAILED
    assert not {gate.name: gate.passed for gate in result.gates}["repository_metrics_unmasked"]

    tampered = result.model_dump(mode="json")
    tampered["repository_metrics"][0]["recall"] = 1
    with pytest.raises(ValueError, match="repository benchmark recall"):
        BenchmarkReport.model_validate(tampered)


def test_overlapping_but_inexact_location_fails_location_gate() -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    vulnerable = [case for case in manifest.cases if case.variant == "vulnerable"]
    selected = vulnerable[0]
    reports = _reports_by_repository(vulnerable)
    replacement_findings = []
    for case in vulnerable:
        if case.repository_id != selected.repository_id:
            continue
        finding = _finding(case)
        if case.id == selected.id:
            location = finding.locations[0].model_copy(update={"end_line": case.end_line + 1})
            finding = finding.model_copy(update={"locations": [location]})
        replacement_findings.append(finding)
    reports[selected.repository_id] = _report(
        replacement_findings,
        root_name=selected.repository_id,
    )

    result = evaluate_benchmark(
        manifest,
        reports,
        profile=AuditProfile.STANDARD,
    )

    assert result.recall == 1
    assert result.location_accuracy < 1
    assert result.status is BenchmarkStatus.FAILED
    assert not {gate.name: gate.passed for gate in result.gates}["exact_ground_truth_locations"]


def test_benchmark_fails_on_safe_confirmation_and_model_only_confirmation() -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    vulnerable = [case for case in manifest.cases if case.variant == "vulnerable"]
    safe = next(case for case in manifest.cases if case.variant == "safe")
    unsafe_confirmation = _finding(safe).model_copy(
        update={
            "evidence_strength": EvidenceStrength.MODEL_INFERENCE,
            "evidence": [
                Evidence(
                    type="model",
                    source="source_audit",
                    description="Unsupported model-only assertion.",
                )
            ],
            "reproduction_state": ReproductionState.NOT_ATTEMPTED,
        }
    )
    report = evaluate_benchmark(
        manifest,
        {
            **_reports_by_repository(vulnerable),
            safe.repository_id: _report(
                [
                    *[
                        _finding(case)
                        for case in vulnerable
                        if case.repository_id == safe.repository_id
                    ],
                    unsafe_confirmation,
                ],
                root_name=safe.repository_id,
            ),
        },
        profile=AuditProfile.STANDARD,
    )
    assert report.status is BenchmarkStatus.FAILED
    assert report.safe_high_critical_confirmations == 1
    assert report.evidence_cap_bypasses == 1
    repository = next(
        item for item in report.repository_metrics if item.repository_id == safe.repository_id
    )
    assert repository.safe_false_confirmations == 1
    assert {gate.name for gate in report.gates if not gate.passed} >= {
        "safe_control_false_confirmations",
        "evidence_caps",
    }


def test_maximum_assurance_benchmark_requires_semantic_coverage_metrics() -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    vulnerable = [case for case in manifest.cases if case.variant == "vulnerable"]
    reports = {
        repository_id: _complete_maximum(report)
        for repository_id, report in _reports_by_repository(vulnerable).items()
    }
    report = evaluate_benchmark(
        manifest,
        reports,
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        mutation_scorecard=_passing_mutation_scorecard(),
    )
    assert report.status is BenchmarkStatus.PASSED
    assert {gate.name: gate.passed for gate in report.gates}["maximum_assurance_semantic_coverage"]

    first_repository = next(iter(reports))
    coverage = reports[first_repository].metadata["solidity"]["coverage"]["quality_metrics"]
    del coverage["asset_flows_classified"]
    downgraded = evaluate_benchmark(
        manifest,
        reports,
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        mutation_scorecard=_passing_mutation_scorecard(),
    )
    assert downgraded.status is BenchmarkStatus.FAILED
    failed = {gate.name: gate.detail for gate in downgraded.gates if not gate.passed}
    assert "maximum_assurance_semantic_coverage" in failed
    assert "asset_flows_classified" in failed["maximum_assurance_semantic_coverage"]


def test_maximum_assurance_property_mutation_gate_passes_and_serializes(
    tmp_path: Path,
) -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    vulnerable = [case for case in manifest.cases if case.variant == "vulnerable"]
    reports = {
        repository_id: _complete_maximum(report)
        for repository_id, report in _reports_by_repository(vulnerable).items()
    }
    result = evaluate_benchmark(
        manifest,
        reports,
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        mutation_scorecard=_passing_mutation_scorecard(),
    )

    assert result.status is BenchmarkStatus.PASSED
    assert result.mutation_scorecard is not None
    assert result.mutation_scorecard.gate_passed
    assert {item.repository_id: item.mutation_kill_score for item in result.repository_metrics} == {
        "economic_erc4626": 1,
        "maximum_assurance_protocol": 1,
    }
    tampered = result.model_dump(mode="json")
    tampered["repository_metrics"][0]["mutation_kill_score"] = 0
    with pytest.raises(ValueError, match="repository mutation metrics"):
        BenchmarkReport.model_validate(tampered)
    gate = {item.name: item for item in result.gates}["maximum_assurance_property_mutation_score"]
    assert gate.passed
    output = tmp_path / "benchmark.json"
    write_benchmark_report(output, result)
    assert BenchmarkReport.model_validate_json(output.read_text(encoding="utf-8")) == result


def test_surviving_mutation_blocks_maximum_assurance() -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    vulnerable = [case for case in manifest.cases if case.variant == "vulnerable"]
    reports = {
        repository_id: _complete_maximum(report)
        for repository_id, report in _reports_by_repository(vulnerable).items()
    }
    scorecard = score_mutation_outcomes(
        property_corpus_hash="d" * 64,
        expected_property_ids=[PROPERTY_A, PROPERTY_B],
        property_repositories={
            PROPERTY_A: "maximum_assurance_protocol",
            PROPERTY_B: "economic_erc4626",
        },
        outcomes=[
            _mutation_outcome(PROPERTY_A, "mut-accounting-a", MutationTestOutcome.KILLED),
            _mutation_outcome(PROPERTY_B, "mut-accounting-b", MutationTestOutcome.SURVIVED),
        ],
        minimum_property_kill_score=1,
    )

    result = evaluate_benchmark(
        manifest,
        reports,
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        mutation_scorecard=scorecard,
    )
    gate = {item.name: item for item in result.gates}["maximum_assurance_property_mutation_score"]
    assert result.status is BenchmarkStatus.FAILED
    assert not gate.passed
    assert PROPERTY_B in gate.detail
    payload = result.model_dump(mode="json")
    next(
        item
        for item in payload["gates"]
        if item["name"] == "maximum_assurance_property_mutation_score"
    )["passed"] = True
    with pytest.raises(ValueError, match="mutation gate is inconsistent"):
        BenchmarkReport.model_validate(payload)


def test_aggregate_mutation_score_cannot_hide_unexercised_property() -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    vulnerable = [case for case in manifest.cases if case.variant == "vulnerable"]
    reports = {
        repository_id: _complete_maximum(report)
        for repository_id, report in _reports_by_repository(vulnerable).items()
    }
    scorecard = score_mutation_outcomes(
        property_corpus_hash="d" * 64,
        expected_property_ids=[PROPERTY_A, PROPERTY_B],
        property_repositories={
            PROPERTY_A: "maximum_assurance_protocol",
            PROPERTY_B: "economic_erc4626",
        },
        outcomes=[
            _mutation_outcome(PROPERTY_A, "mut-accounting-a", MutationTestOutcome.KILLED),
        ],
        minimum_property_kill_score=1,
    )

    assert scorecard.overall_kill_score == 1
    assert not scorecard.gate_passed
    assert scorecard.property_scores[1].kill_score is None
    result = evaluate_benchmark(
        manifest,
        reports,
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        mutation_scorecard=scorecard,
    )
    gate = {item.name: item for item in result.gates}["maximum_assurance_property_mutation_score"]
    assert result.status is BenchmarkStatus.FAILED
    assert not gate.passed
    assert PROPERTY_B in gate.detail
