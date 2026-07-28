from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from mmaudit.benchmark.engine import (
    MAXIMUM_ASSURANCE_CORE_CLAUSES,
    BenchmarkGate,
    BenchmarkMetricState,
    BenchmarkReport,
    BenchmarkReportInputStatus,
    evaluate_benchmark,
    load_manifest,
)
from mmaudit.models.schemas import (
    AnalysisState,
    AuditProfile,
    AuditQualityStatus,
    AuditReport,
    MaximumAssuranceAssessment,
    MaximumAssuranceRequirement,
    MaximumAssuranceStatus,
    RepositoryMap,
)

ROOT = Path(__file__).parents[2]

CORE_MAXIMUM_ASSURANCE_REQUIREMENTS = (
    "maximum_assurance_profile",
    "full_pipeline_mode",
    "model_family_diversity",
    "specialist_agent_configuration",
    "specialist_role_coverage",
    "hardened_dynamic_isolation",
    "requirements_traceability",
    "full_protocol_scope",
    "solidity_project_detection",
    "compilation",
    "ast_backed_index",
    "full_semantic_graphs",
    "deterministic_scanners",
    "slither_execution",
    "foundry_unit_property_invariant_execution",
    "multi_agent_review",
    "critical_model_surface_review",
    "certified_model_ensemble",
    "invariant_discovery",
    "independent_invariant_review",
    "stateful_invariant_execution",
    "protocol_economic_simulation",
    "critical_high_reproduction",
    "independent_verifier",
    "independent_falsifier",
    "independent_test_synthesis",
    "evidence_capped_judge",
    "report_quality_review",
    "coverage_report",
    "formal_adapter_inventory",
    "formal_proof_engine",
    "isolated_replay_execution",
    "production_model_qualification",
    "real_provider_session_provenance",
    "qualified_model_selection_execution",
    "real_model_execution",
    "certified_execution_isolation",
    "benchmark_regression_gate",
)


def _passing_requirement(engine: str) -> MaximumAssuranceRequirement:
    return MaximumAssuranceRequirement(
        engine=engine,
        required=True,
        passed=True,
        blocking=False,
        state=AnalysisState.DETERMINISTIC,
        detail=f"synthetic passing clause: {engine}",
    )


def _complete_assessment(engines: tuple[str, ...]) -> MaximumAssuranceAssessment:
    # Construct the object without relying on its current permissive validator. The benchmark
    # boundary must independently reject a structurally incomplete COMPLETE attestation.
    return MaximumAssuranceAssessment.model_construct(
        contract_version="1.0",
        requested=True,
        required=True,
        downgrade_allowed=False,
        downgraded=False,
        status=MaximumAssuranceStatus.COMPLETE,
        requirements=[_passing_requirement(engine) for engine in engines],
        downgrade_reasons=[],
    )


def _report(
    repository_id: str,
    assessment: MaximumAssuranceAssessment,
) -> AuditReport:
    report = AuditReport(
        schema_version="1.0",
        run_id=f"assurance-binding-{repository_id}",
        generated_at=datetime(2026, 7, 28, tzinfo=UTC),
        completed=True,
        incomplete_reasons=[],
        repository=RepositoryMap(
            root_name=repository_id,
            languages={"Solidity": 1},
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
        privacy={"code_egress_enabled": False},
        scanner_runs=[],
        usage=[],
        budget_usd=0,
        accounted_cost_usd=0,
        findings=[],
        rejected_findings=[],
        audit_profile=AuditProfile.MAXIMUM_ASSURANCE,
        quality_status=AuditQualityStatus.COMPLETED,
    )
    return report.model_copy(update={"maximum_assurance": assessment})


def _evaluate(assessment: MaximumAssuranceAssessment) -> BenchmarkReport:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    reports = {
        repository.repository_id: _report(repository.repository_id, assessment)
        for repository in manifest.repositories
    }
    return evaluate_benchmark(
        manifest,
        reports,
        profile=AuditProfile.MAXIMUM_ASSURANCE,
    )


def _maximum_complete_gate(report: BenchmarkReport) -> BenchmarkGate:
    return next(gate for gate in report.gates if gate.name == "maximum_assurance_complete")


@pytest.mark.parametrize(
    "engines",
    [
        (),
        ("synthetic_fake_clause",),
        CORE_MAXIMUM_ASSURANCE_REQUIREMENTS[:-1],
    ],
    ids=["empty", "fake-only", "missing-core-clause"],
)
def test_noncanonical_complete_assessment_fails_closed(
    engines: tuple[str, ...],
) -> None:
    result = _evaluate(_complete_assessment(engines))

    assert all(
        report_input.status is not BenchmarkReportInputStatus.USABLE and not report_input.usable
        for report_input in result.report_inputs
    )
    gate = _maximum_complete_gate(result)
    assert gate.state is not BenchmarkMetricState.PASS
    assert not gate.passed


def test_complete_assessment_with_every_core_clause_is_accepted() -> None:
    assert MAXIMUM_ASSURANCE_CORE_CLAUSES == CORE_MAXIMUM_ASSURANCE_REQUIREMENTS

    result = _evaluate(_complete_assessment(CORE_MAXIMUM_ASSURANCE_REQUIREMENTS))

    assert all(
        report_input.status is BenchmarkReportInputStatus.USABLE and report_input.usable
        for report_input in result.report_inputs
    )
    gate = _maximum_complete_gate(result)
    assert gate.state is BenchmarkMetricState.PASS
    assert gate.passed
