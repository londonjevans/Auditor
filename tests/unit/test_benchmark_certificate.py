from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.benchmark.certificate import (
    BenchmarkCertificate,
    BenchmarkCertificateBindingSet,
    BenchmarkCertificateFileInputs,
    BenchmarkCertificatePayload,
    BenchmarkCertificateVerification,
    CertificateComponentBinding,
    CertificateMismatchKind,
    CertificateVerificationOrigin,
    CertificateVerificationStatus,
    bind_certificate_file,
    bind_certificate_projection,
    build_file_backed_benchmark_certificate,
    load_benchmark_certificate,
    observe_file_backed_certificate,
    seal_benchmark_certificate,
    verify_benchmark_certificate,
    verify_file_backed_benchmark_certificate,
    write_benchmark_certificate,
)
from mmaudit.benchmark.engine import (
    MAXIMUM_ASSURANCE_CORE_CLAUSES,
    BenchmarkBlindingProtocol,
    BenchmarkCase,
    BenchmarkCaseResult,
    BenchmarkCoverageMetric,
    BenchmarkGate,
    BenchmarkManifest,
    BenchmarkManifestPayload,
    BenchmarkMetricDirection,
    BenchmarkMetrics,
    BenchmarkMetricState,
    BenchmarkRateMetric,
    BenchmarkReport,
    BenchmarkReportInput,
    BenchmarkReportInputStatus,
    BenchmarkRepository,
    BenchmarkRepositoryMetrics,
    BenchmarkResourceMetric,
    BenchmarkResourceMetrics,
    seal_benchmark_manifest,
)
from mmaudit.benchmark.mutations import (
    MutationKind,
    MutationPropertyOutcome,
    MutationTestOutcome,
    score_mutation_outcomes,
)
from mmaudit.models.schemas import AuditProfile, Severity
from mmaudit.orchestration.manifest import canonical_sha256

COMMIT = "a" * 40
PROPERTY_ID = "prop-" + ("a" * 24)
MAXIMUM_ASSURANCE_GATE_NAMES = (
    "known_critical_recall",
    "safe_control_false_confirmations",
    "exact_ground_truth_locations",
    "repository_metrics_unmasked",
    "evidence_caps",
    "coverage_present",
    "maximum_assurance_complete",
    "maximum_assurance_repository_mutation_score",
    "maximum_assurance_semantic_coverage",
    "maximum_assurance_property_mutation_score",
    "maximum_assurance_real_model_calls",
    "maximum_assurance_substantive_model_review",
)


def _bindings(*, configuration_value: str = "base") -> BenchmarkCertificateBindingSet:
    return BenchmarkCertificateBindingSet(
        configuration=[
            bind_certificate_projection(
                "config/full",
                {"profile": configuration_value},
            )
        ],
        prompts=[
            bind_certificate_projection("prompt/discovery", {"template": "discover"}),
            bind_certificate_projection("prompt/verification", {"template": "verify"}),
        ],
        models=[
            bind_certificate_projection(
                "model/root-lineage-a",
                {"model": "synthetic-model", "lineage": "lineage-a"},
            )
        ],
        tools=[
            bind_certificate_projection(
                "tool/scanner",
                {"name": "synthetic-scanner", "version": "1.0", "sha256": "b" * 64},
            )
        ],
        compilers=[
            bind_certificate_projection(
                "compiler/solc",
                {"version": "0.8.30", "sha256": "c" * 64},
            )
        ],
        corpus=[
            bind_certificate_projection(
                "corpus/manifest",
                {"name": "synthetic-corpus", "cases": ["unsafe", "safe"]},
            )
        ],
        ground_truth=[
            bind_certificate_projection(
                "ground-truth/blinded",
                {"case_hashes": ["d" * 64, "e" * 64]},
            )
        ],
    )


def _report_binding() -> CertificateComponentBinding:
    return bind_certificate_projection(
        "benchmark-report",
        {"status": "passed", "gates": [{"name": "synthetic", "passed": True}]},
    )


def _benchmark_manifest() -> BenchmarkManifest:
    cases = [
        BenchmarkCase(
            id=f"case-{index:03d}-{severity.value}-{variant}",
            repository_id="synthetic_repository",
            variant="vulnerable" if variant == "unsafe" else "safe",
            category="Synthetic defensive condition",
            path="src/Synthetic.sol",
            start_line=index,
            end_line=index,
            source_sha256="f" * 64,
            minimum_severity=severity,
            expected_cwe=[],
            source_attribution="Synthetic local certificate fixture.",
            training_exposure="unknown",
        )
        for index, (severity, variant) in enumerate(
            (
                (Severity.CRITICAL, "unsafe"),
                (Severity.HIGH, "unsafe"),
                (Severity.MEDIUM, "unsafe"),
                (Severity.CRITICAL, "safe"),
                (Severity.HIGH, "safe"),
            ),
            start=1,
        )
    ]
    return seal_benchmark_manifest(
        BenchmarkManifestPayload(
            name="Synthetic file-backed benchmark",
            description="Synthetic manifest for certificate inventory binding.",
            blinding=BenchmarkBlindingProtocol(),
            repositories=[
                BenchmarkRepository(
                    repository_id="synthetic_repository",
                    source_root="tests/fixtures/synthetic_repository",
                )
            ],
            cases=cases,
        )
    )


def _certificate() -> BenchmarkCertificate:
    return seal_benchmark_certificate(
        BenchmarkCertificatePayload(
            certificate_id="synthetic-certificate",
            benchmark_name="Synthetic defensive benchmark",
            profile=AuditProfile.MAXIMUM_ASSURANCE,
            repository_git_commit=COMMIT,
            bindings=_bindings(),
            benchmark_report=_report_binding(),
        )
    )


def _passing_rate(
    numerator: int = 1,
    denominator: int = 1,
    *,
    direction: BenchmarkMetricDirection = BenchmarkMetricDirection.MINIMUM,
) -> BenchmarkRateMetric:
    threshold = 0.0 if direction is BenchmarkMetricDirection.MAXIMUM else 1.0
    return BenchmarkRateMetric(
        numerator=numerator,
        denominator=denominator,
        evaluated=denominator,
        value=round(numerator / denominator, 6),
        state=BenchmarkMetricState.PASS,
        threshold=threshold,
        direction=direction,
        detail="Synthetic abstract certification metric.",
    )


def _informational_rate(
    numerator: int,
    denominator: int,
) -> BenchmarkRateMetric:
    return BenchmarkRateMetric(
        numerator=numerator,
        denominator=denominator,
        evaluated=denominator,
        value=round(numerator / denominator, 6),
        state=BenchmarkMetricState.NOT_APPLICABLE,
        threshold=None,
        direction=BenchmarkMetricDirection.INFORMATIONAL,
        detail="Synthetic informational metric without a release threshold.",
    )


def _benchmark_report() -> BenchmarkReport:
    manifest = _benchmark_manifest()
    mutation_scorecard = score_mutation_outcomes(
        property_corpus_hash="d" * 64,
        expected_property_ids=[PROPERTY_ID],
        property_repositories={PROPERTY_ID: "synthetic_repository"},
        outcomes=[
            MutationPropertyOutcome(
                mutation_id="mut-accounting",
                mutation_kind=MutationKind.ACCOUNTING_OPERATOR_REPLACEMENT,
                property_id=PROPERTY_ID,
                outcome=MutationTestOutcome.KILLED,
                evidence_sha256="e" * 64,
            )
        ],
        minimum_property_kill_score=1,
    )
    report_input = BenchmarkReportInput(
        repository_id="synthetic_repository",
        status=BenchmarkReportInputStatus.USABLE,
        attempted=True,
        parsed=True,
        usable=True,
        maximum_assurance_status="COMPLETE",
        maximum_assurance_required_clauses=sorted(MAXIMUM_ASSURANCE_CORE_CLAUSES),
        detail="Synthetic report input is complete and eligible.",
    )
    coverage_metrics = {
        name: BenchmarkCoverageMetric(
            numerator=1,
            denominator=1,
            evaluated=1,
            percentage=100,
            state=BenchmarkMetricState.PASS,
            detail=f"Synthetic complete coverage for {name}.",
        )
        for name in (
            "compiler_contracts_indexed",
            "public_external_entry_points_reviewed",
            "privileged_entry_points_reviewed",
            "high_value_paths_reviewed",
            "external_calls_classified",
            "asset_flows_classified",
            "storage_variables_modelled",
            "invariants_executed",
            "economic_templates_executed",
            "economic_templates_with_typed_harness",
        )
    }
    repository_metrics = BenchmarkRepositoryMetrics(
        repository_id="synthetic_repository",
        report_status=BenchmarkReportInputStatus.USABLE,
        report_attempted=True,
        report_parsed=True,
        report_loaded=True,
        cases_evaluated=5,
        vulnerable_cases=3,
        vulnerable_cases_detected=3,
        recall=1,
        critical_cases=1,
        critical_cases_detected=1,
        critical_recall=1,
        safe_cases=2,
        ambiguous_cases=0,
        safe_false_confirmations=0,
        safe_high_critical_confirmations=0,
        safe_false_confirmation_rate=0,
        location_cases=3,
        exact_locations=3,
        location_accuracy=1,
        vulnerable_cases_reproduced=3,
        reproduction_success_rate=1,
        mutation_property_ids=[PROPERTY_ID],
        mutation_kill_score=1,
        mutation_gate_passed=True,
        evidence_cap_bypasses=0,
        model_only_findings_kept_below_confirmed=0,
        coverage_metrics=coverage_metrics,
        cost_usd=0,
        total_tokens=1,
        runtime_seconds=1,
        time_to_first_valid_finding_seconds=0.25,
    )
    metrics = BenchmarkMetrics(
        overall_recall=_passing_rate(3, 3),
        critical_recall=_passing_rate(),
        high_recall=_passing_rate(),
        medium_recall=_passing_rate(),
        confirmed_precision=_passing_rate(3, 3),
        all_finding_precision=_informational_rate(3, 3),
        false_confirmed_critical_rate=_passing_rate(
            0,
            1,
            direction=BenchmarkMetricDirection.MAXIMUM,
        ),
        false_confirmed_high_rate=_passing_rate(
            0,
            1,
            direction=BenchmarkMetricDirection.MAXIMUM,
        ),
        safe_near_miss_rejection_rate=_passing_rate(2, 2),
        exact_location_accuracy=_passing_rate(3, 3),
        attack_path_reachability_accuracy=_informational_rate(3, 3),
        reproduction_success_rate=_passing_rate(3, 3),
        symbolic_counterexample_success_rate=_informational_rate(1, 1),
        formal_property_mutation_score=_informational_rate(1, 1),
        invariant_mutation_score=_passing_rate(),
        contract_coverage=_passing_rate(),
        entry_point_coverage=_passing_rate(),
        privileged_function_coverage=_passing_rate(),
        asset_moving_function_coverage=_passing_rate(),
        external_call_coverage=_passing_rate(),
        model_call_success_rate=_passing_rate(),
        model_review_coverage=_passing_rate(),
        critical_model_review_coverage=_passing_rate(),
        economic_template_applicability_coverage=_passing_rate(),
        economic_template_execution_coverage=_passing_rate(),
    )
    case_results = [
        BenchmarkCaseResult(
            case_id=f"case-{index:03d}-{severity.value}-unsafe",
            repository_id="synthetic_repository",
            variant="vulnerable",
            minimum_severity=severity,
            evaluated=True,
            detected=True,
            confirmed=True,
            reproduction_attempted=True,
            reproduced=True,
            exact_location=True,
            matched_finding_ids=[f"finding-{index:03d}"],
            confirmed_finding_ids=[f"finding-{index:03d}"],
            cwe_match=True,
        )
        for index, severity in enumerate(
            (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM),
            start=1,
        )
    ]
    case_results.extend(
        [
            BenchmarkCaseResult(
                case_id=f"case-{index:03d}-{severity.value}-safe",
                repository_id="synthetic_repository",
                variant="safe",
                minimum_severity=severity,
                evaluated=True,
                detected=False,
                confirmed=False,
            )
            for index, severity in enumerate(
                (Severity.CRITICAL, Severity.HIGH),
                start=4,
            )
        ]
    )
    gates = [
        BenchmarkGate(
            name=name,
            state=BenchmarkMetricState.PASS,
            passed=True,
            detail=f"Synthetic abstract evidence passed {name}.",
        )
        for name in MAXIMUM_ASSURANCE_GATE_NAMES
    ]
    return BenchmarkReport(
        schema_version="3.0",
        corpus_name=manifest.name,
        corpus_sha256=manifest.corpus_sha256,
        blinding=manifest.blinding,
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        status="passed",
        reports_expected=1,
        reports_attempted=1,
        reports_parsed=1,
        reports_loaded=1,
        report_inputs=[report_input],
        vulnerable_cases=3,
        vulnerable_cases_detected=3,
        vulnerable_cases_reproduced=3,
        critical_cases=1,
        critical_cases_detected=1,
        safe_cases=2,
        ambiguous_cases=0,
        safe_high_critical_confirmations=0,
        evidence_cap_bypasses=0,
        reports_missing_coverage=0,
        model_only_findings_kept_below_confirmed=0,
        active_findings=3,
        active_findings_matching_vulnerable_cases=3,
        confirmed_findings=3,
        confirmed_findings_matching_vulnerable_cases=3,
        recall=1,
        recall_by_severity={"critical": 1, "high": 1, "medium": 1},
        critical_recall=1,
        precision=1,
        false_positive_rate=0,
        safe_false_confirmation_rate=0,
        reproduction_success_rate=1,
        location_cases=3,
        exact_locations=3,
        location_accuracy=1,
        total_cost_usd=0,
        total_tokens=1,
        total_runtime_seconds=1,
        time_to_first_valid_finding_seconds=0.25,
        resource_metrics=BenchmarkResourceMetrics(
            cost_usd=BenchmarkResourceMetric(
                observations=1,
                total=0,
                average=0,
                worst=0,
                state=BenchmarkMetricState.NOT_APPLICABLE,
                detail="Synthetic observed zero-cost report.",
            ),
            runtime_seconds=BenchmarkResourceMetric(
                observations=1,
                total=1,
                average=1,
                worst=1,
                state=BenchmarkMetricState.NOT_APPLICABLE,
                detail="Synthetic observed report runtime.",
            ),
        ),
        metrics=metrics,
        mutation_scorecard=mutation_scorecard,
        coverage_metrics=coverage_metrics,
        repository_metrics=[repository_metrics],
        case_results=case_results,
        gates=gates,
        limitations=[],
    )


def _write_file_backed_components(
    tmp_path: Path,
    report: BenchmarkReport | dict[str, Any],
) -> tuple[Path, BenchmarkCertificateFileInputs]:
    component_root = tmp_path / "components"
    component_root.mkdir(parents=True)
    report_json = (
        report.model_dump_json()
        if isinstance(report, BenchmarkReport)
        else json.dumps(report, sort_keys=True)
    )
    contents = {
        "mmaudit.toml": 'profile = "maximum-assurance"\n',
        "prompt.md": "Synthetic defensive prompt.\n",
        "models.json": '{"lineage":"synthetic-a"}\n',
        "tools.json": '{"scanner":"synthetic","version":"1"}\n',
        "compilers.json": '{"compiler":"solc","version":"0.8.30"}\n',
        "corpus.json": _benchmark_manifest().model_dump_json() + "\n",
        "ground-truth.json": '{"case_hashes":["aaaaaaaa"]}\n',
        "benchmark-results.json": report_json,
    }
    for name, content in contents.items():
        (component_root / name).write_text(content, encoding="utf-8")
    return (
        component_root,
        BenchmarkCertificateFileInputs(
            configuration=["mmaudit.toml"],
            prompts=["prompt.md"],
            models=["models.json"],
            tools=["tools.json"],
            compilers=["compilers.json"],
            corpus=["corpus.json"],
            ground_truth=["ground-truth.json"],
            benchmark_report="benchmark-results.json",
        ),
    )


def _write_file_backed_certificate(
    tmp_path: Path,
) -> tuple[Path, Path, BenchmarkCertificate]:
    component_root, inputs = _write_file_backed_components(
        tmp_path,
        _benchmark_report(),
    )
    certificate = build_file_backed_benchmark_certificate(
        component_root=component_root,
        inputs=inputs,
        repository_git_commit=COMMIT,
        certificate_id="file-backed-certificate",
    )
    certificate_path = tmp_path / "benchmark-certificate.json"
    write_benchmark_certificate(certificate_path, certificate)
    return component_root, certificate_path, certificate


def _invalid_report_payload(mutation: str) -> dict[str, Any]:
    payload = _benchmark_report().model_dump(mode="json")
    if mutation == "missing_gate":
        payload["gates"] = [
            gate
            for gate in payload["gates"]
            if gate["name"] != "maximum_assurance_real_model_calls"
        ]
    elif mutation == "missing_metric":
        del payload["metrics"]["model_review_coverage"]
    elif mutation == "failed_required_metric":
        payload["metrics"]["model_review_coverage"] = {
            "numerator": 0,
            "denominator": 1,
            "evaluated": 1,
            "value": 0,
            "state": "FAIL",
            "threshold": 1,
            "direction": "minimum",
            "detail": "Synthetic substantive review did not meet its threshold.",
        }
    elif mutation == "zero_denominator_required_metric":
        payload["metrics"]["model_review_coverage"] = {
            "numerator": 0,
            "denominator": 0,
            "evaluated": 0,
            "value": None,
            "state": "NOT_EVALUABLE",
            "threshold": 1,
            "direction": "minimum",
            "detail": "Synthetic substantive review had no evaluable calls.",
        }
    elif mutation == "incomplete_case_inventory":
        safe_case = next(case for case in payload["case_results"] if case["variant"] == "safe")
        safe_case["evaluated"] = False
        safe_case["limitation"] = "Synthetic safe control was not evaluated."
    elif mutation == "legacy_report":
        payload["schema_version"] = "2.0"
    elif mutation == "missing_schema_version":
        del payload["schema_version"]
    elif mutation == "coverage_counter_bypass":
        payload["coverage_metrics"] = {}
        payload["reports_missing_coverage"] = 1
        payload["evidence_cap_bypasses"] = 1
    elif mutation == "negative_contribution":
        payload["unique_finding_contribution_by_role"] = {"source_audit": -1}
    elif mutation == "resource_summary_tamper":
        payload["resource_metrics"]["runtime_seconds"].update(
            {
                "observations": 100,
                "average": 0.01,
                "worst": 0,
            }
        )
    elif mutation == "precision_evidence_tamper":
        for case in payload["case_results"]:
            if case["variant"] == "vulnerable":
                case["confirmed"] = False
                case["confirmed_finding_ids"] = []
    elif mutation == "duplicate_confirmed_finding":
        vulnerable_case = next(
            case for case in payload["case_results"] if case["variant"] == "vulnerable"
        )
        vulnerable_case["confirmed_finding_ids"] *= 2
    elif mutation == "threshold_override":
        payload["metrics"]["confirmed_precision"]["threshold"] = 0
    elif mutation == "missing_runtime":
        payload["repository_metrics"][0]["runtime_seconds"] = None
        payload["total_runtime_seconds"] = None
        payload["resource_metrics"]["runtime_seconds"] = {
            "observations": 0,
            "total": None,
            "average": None,
            "worst": None,
            "state": "NOT_EVALUABLE",
            "detail": "Synthetic runtime observation is unavailable.",
        }
    elif mutation == "nonfinite_resource":
        payload["resource_metrics"]["runtime_seconds"]["total"] = float("inf")
    else:
        raise AssertionError(f"unknown synthetic report mutation: {mutation}")
    return payload


def _replace_report_and_reseal_certificate(
    *,
    component_root: Path,
    certificate_path: Path,
    certificate: BenchmarkCertificate,
    report_payload: dict[str, Any],
) -> None:
    (component_root / "benchmark-results.json").write_text(
        json.dumps(report_payload, sort_keys=True),
        encoding="utf-8",
    )
    observed_bindings, observed_report = observe_file_backed_certificate(
        certificate,
        component_root=component_root,
    )
    manually_resealed = seal_benchmark_certificate(
        BenchmarkCertificatePayload(
            certificate_id=certificate.certificate_id,
            benchmark_name=certificate.benchmark_name,
            profile=certificate.profile,
            repository_git_commit=certificate.repository_git_commit,
            bindings=observed_bindings,
            benchmark_report=observed_report,
        )
    )
    write_benchmark_certificate(certificate_path, manually_resealed)


def test_certificate_round_trip_and_current_verification_are_deterministic(
    tmp_path: Path,
) -> None:
    certificate = _certificate()
    second = _certificate()
    path = tmp_path / "benchmark-certificate.json"

    write_benchmark_certificate(path, certificate)
    loaded = load_benchmark_certificate(path)
    first_verification = verify_benchmark_certificate(
        loaded,
        repository_git_commit=COMMIT,
        bindings=_bindings(),
        benchmark_report=_report_binding(),
    )
    second_verification = verify_benchmark_certificate(
        second,
        repository_git_commit=COMMIT,
        bindings=_bindings(),
        benchmark_report=_report_binding(),
    )

    assert loaded == certificate == second
    assert loaded.bindings_sha256
    assert loaded.certificate_sha256
    assert first_verification == second_verification
    assert first_verification.status is CertificateVerificationStatus.CURRENT
    assert first_verification.mismatches == []
    assert first_verification.observed_bindings_sha256 == loaded.bindings_sha256
    assert first_verification.origin is CertificateVerificationOrigin.IN_MEMORY
    assert first_verification.file_backed_evidence is None


def test_file_backed_verification_attests_exact_loaded_passed_report(
    tmp_path: Path,
) -> None:
    component_root, certificate_path, certificate = _write_file_backed_certificate(tmp_path)

    verification = verify_file_backed_benchmark_certificate(
        certificate_path,
        component_root=component_root,
        repository_git_commit=COMMIT,
    )

    assert verification.status is CertificateVerificationStatus.CURRENT
    assert verification.origin is CertificateVerificationOrigin.FILE_BACKED
    assert verification.file_backed_evidence is not None
    evidence = verification.file_backed_evidence
    assert evidence.certificate_loaded is True
    assert (
        evidence.certificate_file_sha256
        == hashlib.sha256(certificate_path.read_bytes()).hexdigest()
    )
    assert evidence.benchmark_report_loaded is True
    assert (
        evidence.benchmark_report_file_sha256
        == hashlib.sha256((component_root / "benchmark-results.json").read_bytes()).hexdigest()
    )
    assert evidence.benchmark_report_status == "passed"
    assert evidence.benchmark_report_gate_count == len(MAXIMUM_ASSURANCE_GATE_NAMES)
    assert evidence.benchmark_name == "Synthetic file-backed benchmark"
    assert evidence.benchmark_profile is AuditProfile.MAXIMUM_ASSURANCE
    assert evidence.benchmark_reports_expected == 1
    assert evidence.benchmark_reports_loaded == 1
    assert verification.certificate_sha256 == certificate.certificate_sha256
    assert (
        BenchmarkCertificateVerification.model_validate_json(verification.model_dump_json())
        == verification
    )


def test_file_backed_certificate_requires_exact_bound_corpus_case_inventory(
    tmp_path: Path,
) -> None:
    manifest = _benchmark_manifest()
    payload = BenchmarkManifestPayload.model_validate(
        manifest.model_dump(mode="json", exclude={"corpus_sha256"})
    )
    expanded = seal_benchmark_manifest(
        payload.model_copy(
            update={
                "cases": [
                    *payload.cases,
                    BenchmarkCase(
                        id="case-006-high-safe",
                        repository_id="synthetic_repository",
                        variant="safe",
                        category="Synthetic defensive condition",
                        path="src/Synthetic.sol",
                        start_line=6,
                        end_line=6,
                        source_sha256="f" * 64,
                        minimum_severity=Severity.HIGH,
                        expected_cwe=[],
                        source_attribution="Synthetic local certificate fixture.",
                        training_exposure="unknown",
                    ),
                ]
            }
        )
    )
    report_payload = _benchmark_report().model_dump(mode="json")
    report_payload["corpus_sha256"] = expanded.corpus_sha256
    component_root, inputs = _write_file_backed_components(tmp_path, report_payload)
    (component_root / "corpus.json").write_text(
        expanded.model_dump_json() + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="case inventory differs"):
        build_file_backed_benchmark_certificate(
            component_root=component_root,
            inputs=inputs,
            repository_git_commit=COMMIT,
            certificate_id="mismatched-corpus-inventory",
        )


def test_legacy_hand_constructed_current_verification_remains_non_file_backed() -> None:
    payload = {
        "schema_version": "1.0",
        "certificate_sha256": "a" * 64,
        "status": "current",
        "observed_repository_git_commit": COMMIT,
        "observed_bindings_sha256": "b" * 64,
        "mismatches": [],
    }
    payload["verification_sha256"] = canonical_sha256(payload)

    verification = BenchmarkCertificateVerification.model_validate(payload)
    round_tripped = BenchmarkCertificateVerification.model_validate_json(
        verification.model_dump_json()
    )

    assert verification.status is CertificateVerificationStatus.CURRENT
    assert verification.origin is CertificateVerificationOrigin.IN_MEMORY
    assert verification.file_backed_evidence is None
    assert round_tripped == verification


@pytest.mark.parametrize(
    ("mutation", "error_pattern"),
    [
        pytest.param("missing_gate", "gate portfolio", id="missing_gate"),
        pytest.param("missing_metric", "model_review_coverage", id="missing_metric"),
        pytest.param(
            "failed_required_metric",
            "typed evidence|required benchmark metric is not a complete pass",
            id="failed_required_metric",
        ),
        pytest.param(
            "zero_denominator_required_metric",
            "typed evidence|required benchmark metric is not a complete pass",
            id="zero_denominator_required_metric",
        ),
        pytest.param(
            "incomplete_case_inventory",
            "case results|case inventory",
            id="incomplete_case_inventory",
        ),
        pytest.param("legacy_report", "schema_version", id="legacy_report"),
        pytest.param(
            "missing_schema_version",
            "schema_version",
            id="missing_schema_version",
        ),
        pytest.param(
            "coverage_counter_bypass",
            "aggregate counts|aggregate coverage|typed evidence",
            id="coverage_counter_bypass",
        ),
        pytest.param(
            "negative_contribution",
            "contribution counts",
            id="negative_contribution",
        ),
        pytest.param(
            "resource_summary_tamper",
            "resource average|runtime resource metric",
            id="resource_summary_tamper",
        ),
        pytest.param(
            "precision_evidence_tamper",
            "precision inventory",
            id="precision_evidence_tamper",
        ),
        pytest.param(
            "duplicate_confirmed_finding",
            "confirmed finding IDs must be unique and sorted",
            id="duplicate_confirmed_finding",
        ),
        pytest.param(
            "threshold_override",
            "threshold policy",
            id="threshold_override",
        ),
        pytest.param(
            "missing_runtime",
            "cost or runtime observations are incomplete",
            id="missing_runtime",
        ),
        pytest.param(
            "nonfinite_resource",
            "finite number",
            id="nonfinite_resource",
        ),
    ],
)
def test_file_backed_certificate_rejects_incomplete_report_even_after_reseal(
    tmp_path: Path,
    mutation: str,
    error_pattern: str,
) -> None:
    report_payload = _invalid_report_payload(mutation)
    build_root, inputs = _write_file_backed_components(
        tmp_path / "build",
        report_payload,
    )
    with pytest.raises(ValueError, match=error_pattern):
        build_file_backed_benchmark_certificate(
            component_root=build_root,
            inputs=inputs,
            repository_git_commit=COMMIT,
            certificate_id="invalid-synthetic-certificate",
        )

    component_root, certificate_path, original = _write_file_backed_certificate(tmp_path / "verify")
    _replace_report_and_reseal_certificate(
        component_root=component_root,
        certificate_path=certificate_path,
        certificate=original,
        report_payload=report_payload,
    )

    with pytest.raises(ValueError, match=error_pattern):
        verify_file_backed_benchmark_certificate(
            certificate_path,
            component_root=component_root,
            repository_git_commit=COMMIT,
        )


def test_file_backed_origin_requires_loaded_file_evidence() -> None:
    verification = verify_benchmark_certificate(
        _certificate(),
        repository_git_commit=COMMIT,
        bindings=_bindings(),
        benchmark_report=_report_binding(),
    )
    payload = verification.model_dump(mode="json", exclude={"verification_sha256"})
    payload["origin"] = CertificateVerificationOrigin.FILE_BACKED
    payload["verification_sha256"] = canonical_sha256(payload)

    with pytest.raises(ValidationError, match="requires exact loaded-file evidence"):
        BenchmarkCertificateVerification.model_validate(payload)


def test_certificate_rejects_component_and_envelope_tampering() -> None:
    certificate = _certificate()
    component_tamper = certificate.model_dump(mode="json")
    component_tamper["bindings"]["prompts"][0]["sha256"] = "f" * 64

    with pytest.raises(ValidationError, match="component hash"):
        BenchmarkCertificate.model_validate(component_tamper)

    envelope_tamper = certificate.model_dump(mode="json")
    envelope_tamper["benchmark_name"] = "Tampered benchmark label"
    envelope_tamper["bindings_sha256"] = canonical_sha256(
        {
            "repository_git_commit": envelope_tamper["repository_git_commit"],
            "bindings": envelope_tamper["bindings"],
            "benchmark_report": envelope_tamper["benchmark_report"],
        }
    )
    with pytest.raises(ValidationError, match="self-hash"):
        BenchmarkCertificate.model_validate(envelope_tamper)


def test_certificate_verification_reports_commit_changed_missing_and_unexpected() -> None:
    certificate = _certificate()
    observed = _bindings(configuration_value="changed")
    observed.prompts = observed.prompts[:1]
    observed.tools = sorted(
        [
            *observed.tools,
            bind_certificate_projection("tool/second", {"version": "2.0"}),
        ],
        key=lambda item: item.identifier,
    )

    result = verify_benchmark_certificate(
        certificate,
        repository_git_commit="b" * 40,
        bindings=observed,
        benchmark_report=_report_binding(),
    )

    assert result.status is CertificateVerificationStatus.STALE
    assert {(item.category, item.identifier, item.kind) for item in result.mismatches} == {
        ("configuration", "config/full", CertificateMismatchKind.CHANGED),
        ("prompts", "prompt/verification", CertificateMismatchKind.MISSING),
        ("repository", "git-commit", CertificateMismatchKind.GIT_COMMIT),
        ("tools", "tool/second", CertificateMismatchKind.UNEXPECTED),
    }
    assert result.verification_sha256

    tampered = result.model_dump(mode="json")
    tampered["status"] = "current"
    with pytest.raises(ValidationError, match="status"):
        type(result).model_validate(tampered)


def test_file_binding_and_certificate_paths_are_contained_and_non_linked(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    component = root / "config.toml"
    component.write_text('profile = "maximum-assurance"\n', encoding="utf-8")

    binding = bind_certificate_file(
        root,
        "config.toml",
        identifier="config/file",
    )

    assert binding.path == "config.toml"
    assert binding.size == component.stat().st_size
    assert binding.sha256
    with pytest.raises(ValueError, match="unsafe repository-relative path"):
        bind_certificate_file(root, "../outside", identifier="config/traversal")
    (root / ".env").write_text("SYNTHETIC=not-a-secret\n", encoding="utf-8")
    with pytest.raises(ValueError, match="sensitive"):
        bind_certificate_file(root, ".env", identifier="config/sensitive")

    linked = root / "linked.toml"
    try:
        linked.symlink_to(component)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="links"):
        bind_certificate_file(root, "linked.toml", identifier="config/link")


def test_file_binding_rejects_hardlinks_and_certificate_loader_rejects_links(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    component = root / "corpus.json"
    component.write_text("{}\n", encoding="utf-8")
    hardlink = root / "ground-truth.json"
    try:
        os.link(component, hardlink)
    except OSError:
        pytest.skip("hardlinks unavailable")

    with pytest.raises(ValueError, match="unique regular files"):
        bind_certificate_file(root, "corpus.json", identifier="corpus/file")

    certificate_path = tmp_path / "benchmark-certificate.json"
    write_benchmark_certificate(certificate_path, _certificate())
    certificate_link = tmp_path / "linked-certificate.json"
    try:
        certificate_link.symlink_to(certificate_path)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="non-link"):
        load_benchmark_certificate(certificate_link)


def test_binding_categories_are_required_sorted_and_strict() -> None:
    dumped = _bindings().model_dump(mode="json")
    dumped["prompts"] = list(reversed(dumped["prompts"]))
    with pytest.raises(ValidationError, match="unique and sorted"):
        BenchmarkCertificateBindingSet.model_validate(dumped)

    missing = _bindings().model_dump(mode="json")
    missing["ground_truth"] = []
    with pytest.raises(ValidationError):
        BenchmarkCertificateBindingSet.model_validate(missing)

    certificate = _certificate().model_dump(mode="json")
    certificate["rpc_url"] = "http://127.0.0.1:8545"
    with pytest.raises(ValidationError, match="Extra inputs"):
        BenchmarkCertificate.model_validate(certificate)


def test_published_certificate_schema_is_strict_and_bounded() -> None:
    schema_path = (
        Path(__file__).resolve().parents[2] / "schemas" / "benchmark_certificate.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    assert schema["additionalProperties"] is False
    assert schema["$defs"]["componentBinding"]["additionalProperties"] is False
    assert schema["$defs"]["bindingSet"]["additionalProperties"] is False
    assert schema["$defs"]["bindingSet"]["required"] == [
        "configuration",
        "prompts",
        "models",
        "tools",
        "compilers",
        "corpus",
        "ground_truth",
    ]
    assert schema["$defs"]["bindingSet"]["properties"]["ground_truth"] == {
        "$ref": "#/$defs/componentList"
    }
    assert schema["$defs"]["componentList"]["minItems"] == 1
    assert schema["properties"]["certificate_sha256"]["pattern"] == "^[0-9a-f]{64}$"
