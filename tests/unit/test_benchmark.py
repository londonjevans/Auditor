from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.benchmark.claims import SuperiorityClaimStatus
from mmaudit.benchmark.engine import (
    MAXIMUM_ASSURANCE_CORE_CLAUSES,
    BenchmarkManifest,
    BenchmarkManifestPayload,
    BenchmarkMetricState,
    BenchmarkReport,
    BenchmarkReportInputStatus,
    BenchmarkStatus,
    benchmark_certification_failures,
    evaluate_benchmark,
    load_manifest,
    load_reports,
    validate_benchmark_ground_truth,
    write_benchmark_report,
)
from mmaudit.benchmark.mutations import (
    MutationKind,
    MutationPropertyOutcome,
    MutationScorecard,
    MutationScorecardEvidenceOrigin,
    MutationTestOutcome,
    score_mutation_outcomes,
)
from mmaudit.models.schemas import (
    AnalysisState,
    AuditProfile,
    AuditQualityStatus,
    AuditReport,
    CoverageMetric,
    CoverageProvenance,
    Evidence,
    EvidenceStrength,
    Finding,
    FindingStatus,
    Location,
    LocationValidation,
    MaximumAssuranceAssessment,
    MaximumAssuranceRequirement,
    MaximumAssuranceStatus,
    RepositoryMap,
    ReproductionState,
    Severity,
    SolidityCoverage,
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
                content_hash=case.source_sha256,
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
        location_validation=LocationValidation(valid=True, content_hash=case.source_sha256),
        contributing_candidate_ids=[f"candidate-{case.id}"],
        evidence_strength=EvidenceStrength.MINIMIZED_LOCAL_FORK_REPRODUCTION,
        reproduction_state=ReproductionState.REPRODUCED_AND_MINIMIZED,
    )


def _report(
    findings: list[Finding], *, root_name: str = "maximum_assurance_protocol"
) -> AuditReport:
    def coverage_metric(
        numerator: int,
        denominator: int,
        *,
        state: AnalysisState = AnalysisState.DETERMINISTIC,
    ) -> CoverageMetric:
        return CoverageMetric(
            numerator=numerator,
            denominator=denominator,
            population=denominator,
            percentage=round((numerator / denominator) * 100, 4),
            exclusions=[],
            not_applicable_evidence=[],
            confidence=1,
            provenance=[CoverageProvenance.RUNTIME],
            failures=[] if numerator == denominator else ["synthetic coverage gap"],
            state=state,
            detail="synthetic typed benchmark coverage",
        )

    quality_metrics = {
        "compiler_contracts_indexed": coverage_metric(13, 13),
        "public_external_entry_points_reviewed": coverage_metric(
            12,
            12,
            state=AnalysisState.MODEL_ONLY,
        ),
        "privileged_entry_points_reviewed": coverage_metric(
            2,
            2,
            state=AnalysisState.MODEL_ONLY,
        ),
        "high_value_paths_reviewed": coverage_metric(
            3,
            3,
            state=AnalysisState.MODEL_ONLY,
        ),
        "external_calls_classified": coverage_metric(4, 4),
        "asset_flows_classified": coverage_metric(3, 3),
        "storage_variables_modelled": coverage_metric(5, 5),
        "invariants_executed": coverage_metric(2, 2),
        "economic_templates_executed": coverage_metric(1, 1),
        "economic_templates_with_typed_harness": coverage_metric(1, 1),
    }
    solidity_coverage = SolidityCoverage(
        contracts_indexed=13,
        quality_metrics=quality_metrics,
    )
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
        solidity_coverage=solidity_coverage,
        metadata={
            "duration_seconds": 12.5,
            "time_to_first_candidate_seconds": 2.25,
            "solidity": {
                "coverage": solidity_coverage.model_dump(mode="json"),
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
            "audit_profile": AuditProfile.MAXIMUM_ASSURANCE,
            "maximum_assurance": MaximumAssuranceAssessment(
                requested=True,
                required=True,
                downgrade_allowed=False,
                downgraded=False,
                status=MaximumAssuranceStatus.COMPLETE,
                requirements=[
                    MaximumAssuranceRequirement(
                        engine=engine,
                        required=True,
                        passed=True,
                        blocking=False,
                        state=AnalysisState.DETERMINISTIC,
                        detail=f"synthetic passing core clause: {engine}",
                    )
                    for engine in MAXIMUM_ASSURANCE_CORE_CLAUSES
                ],
            ),
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


def _planned_unattested_mutation_scorecard() -> MutationScorecard:
    scorecard = score_mutation_outcomes(
        property_corpus_hash="d" * 64,
        expected_property_ids=[PROPERTY_A, PROPERTY_B],
        property_repositories={
            PROPERTY_A: "maximum_assurance_protocol",
            PROPERTY_B: "economic_erc4626",
        },
        outcomes=[
            _mutation_outcome(PROPERTY_A, "mut-accounting-a", MutationTestOutcome.INCONCLUSIVE),
            _mutation_outcome(PROPERTY_B, "mut-accounting-b", MutationTestOutcome.INCONCLUSIVE),
        ],
        minimum_property_kill_score=1,
    )
    payload = scorecard.model_dump(mode="python")
    payload.update(
        evidence_origin=MutationScorecardEvidenceOrigin.PLANNED_UNATTESTED,
        applicability_plan_sha256="e" * 64,
    )
    return MutationScorecard.model_validate(payload)


def test_benchmark_measures_recall_safe_controls_and_evidence_caps() -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    vulnerable = [case for case in manifest.cases if case.variant == "vulnerable"]
    report = evaluate_benchmark(
        manifest,
        _reports_by_repository(vulnerable),
        profile=AuditProfile.STANDARD,
    )
    assert report.status is BenchmarkStatus.FAILED
    assert report.recall == report.critical_recall == 1
    assert all(value == 1 for value in report.recall_by_severity.values())
    assert report.precision == 1
    assert report.false_positive_rate == 0
    assert report.safe_high_critical_confirmations == 0
    assert report.reproduction_success_rate is None
    assert report.metrics.reproduction_success_rate.state.value == "NOT_EVALUABLE"
    assert report.vulnerable_cases_reproduced == 0
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
    assert not {gate.name: gate.passed for gate in report.gates}["repository_metrics_unmasked"]


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


def test_location_hash_and_range_must_validate_on_the_same_location() -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    vulnerable = [case for case in manifest.cases if case.variant == "vulnerable"]
    selected = vulnerable[0]
    reports = _reports_by_repository(vulnerable)
    report = reports[selected.repository_id]
    findings: list[Finding] = []
    for finding in report.findings:
        if finding.id != f"MMA-BENCH-{selected.id}":
            findings.append(finding)
            continue
        findings.append(
            finding.model_copy(
                update={
                    "locations": [
                        finding.locations[0].model_copy(update={"content_hash": "0" * 64}),
                        finding.locations[0].model_copy(
                            update={
                                "start_line": selected.end_line + 100,
                                "end_line": selected.end_line + 100,
                                "content_hash": selected.source_sha256,
                            }
                        ),
                    ],
                }
            )
        )
    reports[selected.repository_id] = report.model_copy(update={"findings": findings})

    result = evaluate_benchmark(
        manifest,
        reports,
        profile=AuditProfile.STANDARD,
    )
    selected_result = next(
        case_result for case_result in result.case_results if case_result.case_id == selected.id
    )

    assert not selected_result.detected
    assert not selected_result.exact_location


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


def test_medium_safe_confirmation_is_not_mislabeled_as_high_critical() -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    vulnerable = [case for case in manifest.cases if case.variant == "vulnerable"]
    safe_medium = next(
        case
        for case in manifest.cases
        if case.variant == "safe" and case.minimum_severity is Severity.MEDIUM
    )
    reports = _reports_by_repository(vulnerable)
    report = reports[safe_medium.repository_id]
    reports[safe_medium.repository_id] = report.model_copy(
        update={"findings": [*report.findings, _finding(safe_medium)]}
    )

    result = evaluate_benchmark(manifest, reports, profile=AuditProfile.STANDARD)
    safe_gate = next(
        gate for gate in result.gates if gate.name == "safe_control_false_confirmations"
    )

    assert result.safe_high_critical_confirmations == 0
    assert safe_gate.passed
    assert safe_gate.detail.startswith("0 safe high/critical")
    assert result.metrics.safe_near_miss_rejection_rate.state is BenchmarkMetricState.FAIL


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
    assert report.status is BenchmarkStatus.INCOMPLETE
    initial_semantic_gate = {gate.name: gate for gate in report.gates}[
        "maximum_assurance_semantic_coverage"
    ]
    assert not initial_semantic_gate.passed
    for name in (
        "audited_suite_contract_statement_coverage",
        "audited_suite_function_statement_coverage",
        "audited_suite_critical_function_assertion_coverage",
    ):
        assert report.coverage_metrics[name].state is BenchmarkMetricState.NOT_EVALUABLE
        assert name in initial_semantic_gate.detail

    first_repository = next(iter(reports))
    solidity_coverage = reports[first_repository].solidity_coverage
    assert solidity_coverage is not None
    quality_metrics = {
        name: metric
        for name, metric in solidity_coverage.quality_metrics.items()
        if name != "asset_flows_classified"
    }
    reports[first_repository] = reports[first_repository].model_copy(
        update={
            "solidity_coverage": solidity_coverage.model_copy(
                update={"quality_metrics": quality_metrics}
            )
        }
    )
    downgraded = evaluate_benchmark(
        manifest,
        reports,
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        mutation_scorecard=_passing_mutation_scorecard(),
    )
    assert downgraded.status is BenchmarkStatus.INCOMPLETE
    failed = {gate.name: gate.detail for gate in downgraded.gates if not gate.passed}
    assert "maximum_assurance_semantic_coverage" in failed
    assert "asset_flows_classified" in failed["maximum_assurance_semantic_coverage"]


def test_declarative_mutation_scorecard_cannot_satisfy_maximum_assurance_and_serializes(
    tmp_path: Path,
) -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    vulnerable = [case for case in manifest.cases if case.variant == "vulnerable"]
    reports = {
        repository_id: _complete_maximum(report)
        for repository_id, report in _reports_by_repository(vulnerable).items()
    }
    scorecard = _passing_mutation_scorecard()
    assert scorecard.evidence_origin is MutationScorecardEvidenceOrigin.DECLARATIVE
    assert scorecard.gate_passed

    result = evaluate_benchmark(
        manifest,
        reports,
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        mutation_scorecard=scorecard,
    )

    assert result.status is BenchmarkStatus.INCOMPLETE
    assert result.mutation_scorecard is not None
    assert result.mutation_scorecard.gate_passed
    assert {item.repository_id: item.mutation_kill_score for item in result.repository_metrics} == {
        "economic_erc4626": None,
        "maximum_assurance_protocol": None,
    }
    assert all(item.mutation_gate_passed is False for item in result.repository_metrics)
    assert result.metrics.invariant_mutation_score.state is BenchmarkMetricState.NOT_EVALUABLE
    gates = {item.name: item for item in result.gates}
    for gate_name in (
        "maximum_assurance_repository_mutation_score",
        "maximum_assurance_property_mutation_score",
    ):
        assert gates[gate_name].state is BenchmarkMetricState.NOT_EVALUABLE
        assert not gates[gate_name].passed
    assert PROPERTY_A in gates["maximum_assurance_property_mutation_score"].detail
    assert PROPERTY_B in gates["maximum_assurance_property_mutation_score"].detail

    tampered = result.model_dump(mode="json")
    tampered["repository_metrics"][0]["mutation_kill_score"] = 0
    with pytest.raises(ValueError, match="repository mutation metrics"):
        BenchmarkReport.model_validate(tampered)
    output = tmp_path / "benchmark.json"
    write_benchmark_report(output, result)
    assert BenchmarkReport.model_validate_json(output.read_text(encoding="utf-8")) == result


def test_planned_unattested_mutation_scorecard_cannot_satisfy_maximum_assurance() -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    vulnerable = [case for case in manifest.cases if case.variant == "vulnerable"]
    reports = {
        repository_id: _complete_maximum(report)
        for repository_id, report in _reports_by_repository(vulnerable).items()
    }
    scorecard = _planned_unattested_mutation_scorecard()
    assert scorecard.evidence_origin is MutationScorecardEvidenceOrigin.PLANNED_UNATTESTED
    assert not scorecard.gate_passed
    assert all(
        outcome.outcome is MutationTestOutcome.INCONCLUSIVE for outcome in scorecard.outcomes
    )

    result = evaluate_benchmark(
        manifest,
        reports,
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        mutation_scorecard=scorecard,
    )

    assert result.status is BenchmarkStatus.INCOMPLETE
    assert result.metrics.invariant_mutation_score.state is BenchmarkMetricState.NOT_EVALUABLE
    assert all(item.mutation_kill_score is None for item in result.repository_metrics)
    assert all(item.mutation_gate_passed is False for item in result.repository_metrics)
    gates = {item.name: item for item in result.gates}
    for gate_name in (
        "maximum_assurance_repository_mutation_score",
        "maximum_assurance_property_mutation_score",
    ):
        assert gates[gate_name].state is BenchmarkMetricState.NOT_EVALUABLE
        assert not gates[gate_name].passed
    assert BenchmarkReport.model_validate(result.model_dump(mode="python")) == result


def test_forged_runtime_mutation_origin_is_rejected_before_evaluation_or_write(
    tmp_path: Path,
) -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    vulnerable = [case for case in manifest.cases if case.variant == "vulnerable"]
    reports = {
        repository_id: _complete_maximum(report)
        for repository_id, report in _reports_by_repository(vulnerable).items()
    }
    declarative = _passing_mutation_scorecard()
    forged = declarative.model_copy(update={"evidence_origin": "runtime_attested"})

    with (
        pytest.warns(UserWarning, match="PydanticSerializationUnexpectedValue"),
        pytest.raises(ValidationError),
    ):
        evaluate_benchmark(
            manifest,
            reports,
            profile=AuditProfile.MAXIMUM_ASSURANCE,
            mutation_scorecard=forged,
        )

    valid = evaluate_benchmark(
        manifest,
        reports,
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        mutation_scorecard=declarative,
    )
    forged_report = valid.model_copy(update={"mutation_scorecard": forged})
    output = tmp_path / "forged-benchmark.json"
    with (
        pytest.warns(UserWarning, match="PydanticSerializationUnexpectedValue"),
        pytest.raises(ValidationError),
    ):
        write_benchmark_report(output, forged_report)
    assert not output.exists()


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
    assert result.status is BenchmarkStatus.INCOMPLETE
    assert not gate.passed
    assert PROPERTY_B in gate.detail
    payload = result.model_dump(mode="json")
    next(
        item
        for item in payload["gates"]
        if item["name"] == "maximum_assurance_property_mutation_score"
    )["passed"] = True
    with pytest.raises(ValueError, match="gate pass flag"):
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
    assert result.status is BenchmarkStatus.INCOMPLETE
    assert not gate.passed
    assert PROPERTY_B in gate.detail


def test_empty_reports_make_every_required_denominator_not_evaluable() -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")

    result = evaluate_benchmark(
        manifest,
        {},
        profile=AuditProfile.STANDARD,
    )

    assert result.status is BenchmarkStatus.INCOMPLETE
    assert result.reports_expected == len(manifest.repositories)
    assert result.reports_attempted == result.reports_parsed == result.reports_loaded == 0
    assert all(item.status is BenchmarkReportInputStatus.MISSING for item in result.report_inputs)
    assert result.recall is None
    assert result.precision is None
    assert result.location_accuracy is None
    assert result.reproduction_success_rate is None
    for metric in (
        result.metrics.overall_recall,
        result.metrics.critical_recall,
        result.metrics.confirmed_precision,
        result.metrics.exact_location_accuracy,
        result.metrics.reproduction_success_rate,
        result.metrics.model_call_success_rate,
    ):
        assert metric.state is BenchmarkMetricState.NOT_EVALUABLE
        assert metric.value is None
    assert all(not gate.passed for gate in result.gates)
    assert benchmark_certification_failures(result)


def test_failed_and_stale_reports_remain_in_attempt_and_case_denominators() -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    vulnerable = [case for case in manifest.cases if case.variant == "vulnerable"]
    reports = _reports_by_repository(vulnerable)
    first_repository = next(iter(reports))
    reports[first_repository] = reports[first_repository].model_copy(
        update={
            "completed": False,
            "quality_status": AuditQualityStatus.FAILED,
        }
    )
    second_repository = next(
        repository_id for repository_id in reports if repository_id != first_repository
    )
    reports[second_repository] = reports[second_repository].model_copy(
        update={
            "repository": reports[second_repository].repository.model_copy(
                update={"root_name": "different_repository"}
            )
        }
    )

    result = evaluate_benchmark(
        manifest,
        reports,
        profile=AuditProfile.STANDARD,
    )

    assert result.status is BenchmarkStatus.INCOMPLETE
    assert result.reports_attempted == result.reports_parsed == 2
    assert result.reports_loaded == 0
    assert {item.status for item in result.report_inputs} == {
        BenchmarkReportInputStatus.FAILED,
        BenchmarkReportInputStatus.STALE,
    }
    assert result.metrics.overall_recall.denominator == result.vulnerable_cases
    assert result.metrics.overall_recall.evaluated == 0
    assert result.metrics.overall_recall.state is BenchmarkMetricState.NOT_EVALUABLE
    assert all(not case.evaluated for case in result.case_results)


def test_missing_report_keeps_aggregate_coverage_inconclusive() -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    vulnerable = [case for case in manifest.cases if case.variant == "vulnerable"]
    reports = _reports_by_repository(vulnerable)
    reports.pop(sorted(reports)[0])

    result = evaluate_benchmark(
        manifest,
        reports,
        profile=AuditProfile.STANDARD,
    )

    assert result.reports_loaded == 1
    assert result.reports_missing_coverage == 1
    assert (
        result.coverage_metrics["public_external_entry_points_reviewed"].state
        is BenchmarkMetricState.INCONCLUSIVE
    )
    assert result.metrics.entry_point_coverage.state is BenchmarkMetricState.INCONCLUSIVE
    assert next(gate for gate in result.gates if gate.name == "coverage_present").state is (
        BenchmarkMetricState.INCONCLUSIVE
    )
    assert next(gate for gate in result.gates if gate.name == "evidence_caps").state is (
        BenchmarkMetricState.INCONCLUSIVE
    )


def test_malformed_report_load_is_typed_and_not_removed_from_inventory(
    tmp_path: Path,
) -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    repository_ids = {repository.repository_id for repository in manifest.repositories}
    malformed_repository = sorted(repository_ids)[0]
    (tmp_path / f"{malformed_repository}.json").write_text("{", encoding="utf-8")

    reports, inputs, limitations = load_reports(
        tmp_path,
        repository_ids,
        profile=AuditProfile.STANDARD,
    )

    assert reports == {}
    by_repository = {item.repository_id: item for item in inputs}
    assert by_repository[malformed_repository].status is BenchmarkReportInputStatus.MALFORMED
    assert by_repository[malformed_repository].attempted
    assert not by_repository[malformed_repository].parsed
    assert {item.status for item in inputs if item.repository_id != malformed_repository} == {
        BenchmarkReportInputStatus.MISSING
    }
    assert len(limitations) == len(repository_ids)


def test_report_reader_falls_back_to_valid_legacy_solidity_coverage(tmp_path: Path) -> None:
    repository_id = "legacy-coverage-fixture"
    report = _report([], root_name=repository_id)
    expected_coverage = report.solidity_coverage
    assert expected_coverage is not None
    payload = report.model_dump(mode="json")
    del payload["solidity_coverage"]
    (tmp_path / f"{repository_id}.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    reports, inputs, limitations = load_reports(
        tmp_path,
        {repository_id},
        profile=AuditProfile.STANDARD,
    )

    assert limitations == []
    assert inputs[0].status is BenchmarkReportInputStatus.USABLE
    assert reports[repository_id].solidity_coverage is None
    assert reports[repository_id].effective_solidity_coverage() == expected_coverage


def test_required_zero_denominator_semantic_coverage_cannot_pass() -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    vulnerable = [case for case in manifest.cases if case.variant == "vulnerable"]
    reports = {
        repository_id: _complete_maximum(report)
        for repository_id, report in _reports_by_repository(vulnerable).items()
    }
    for repository_id, report in list(reports.items()):
        coverage = report.solidity_coverage
        assert coverage is not None
        quality_metrics = dict(coverage.quality_metrics)
        for name in (
            "public_external_entry_points_reviewed",
            "external_calls_classified",
            "asset_flows_classified",
            "storage_variables_modelled",
            "invariants_executed",
            "economic_templates_executed",
            "economic_templates_with_typed_harness",
        ):
            quality_metrics[name] = CoverageMetric(
                numerator=0,
                denominator=0,
                population=0,
                percentage=None,
                exclusions=[],
                not_applicable_evidence=["synthetic empty population"],
                confidence=1,
                provenance=[CoverageProvenance.RUNTIME],
                failures=[],
                state=AnalysisState.DETERMINISTIC,
                detail="synthetic zero denominator",
            )
        reports[repository_id] = report.model_copy(
            update={
                "solidity_coverage": coverage.model_copy(
                    update={"quality_metrics": quality_metrics}
                )
            }
        )

    result = evaluate_benchmark(
        manifest,
        reports,
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        mutation_scorecard=_passing_mutation_scorecard(),
    )

    semantic_gate = {gate.name: gate for gate in result.gates}[
        "maximum_assurance_semantic_coverage"
    ]
    assert not semantic_gate.passed
    assert semantic_gate.state is BenchmarkMetricState.FAIL
    assert (
        result.coverage_metrics["public_external_entry_points_reviewed"].state
        is BenchmarkMetricState.NOT_EVALUABLE
    )


def test_invalid_location_and_unmatched_finding_reduce_precision_and_recall() -> None:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    vulnerable = [case for case in manifest.cases if case.variant == "vulnerable"]
    reports = _reports_by_repository(vulnerable)
    selected = vulnerable[0]
    report = reports[selected.repository_id]
    findings = [
        (
            finding.model_copy(
                update={
                    "location_validation": LocationValidation(
                        valid=False,
                        errors=["synthetic hash mismatch"],
                    )
                }
            )
            if finding.id == f"MMA-BENCH-{selected.id}"
            else finding
        )
        for finding in report.findings
    ]
    reports[selected.repository_id] = report.model_copy(update={"findings": findings})

    result = evaluate_benchmark(
        manifest,
        reports,
        profile=AuditProfile.STANDARD,
    )

    assert result.metrics.overall_recall.state is BenchmarkMetricState.FAIL
    assert result.metrics.confirmed_precision.state is BenchmarkMetricState.FAIL
    assert result.metrics.exact_location_accuracy.state is BenchmarkMetricState.FAIL
