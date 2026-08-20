from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import timedelta
from functools import cache
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from pydantic import ValidationError

from mmaudit.constants import ANALYSIS_ROLES
from mmaudit.models.policy_selection import (
    AuditModelSelection,
    VerifiedAuditModelSelection,
)
from mmaudit.models.schemas import (
    AnalysisState,
    AuditProfile,
    AuditQualityStatus,
    AuditReport,
    AuditRunStatus,
    CompilationStatus,
    CoverageMetric,
    CoverageProvenance,
    ExecutionEvidenceKind,
    InvariantSuite,
    LanguageCapabilityFileEvidence,
    LanguageCapabilityProfile,
    MaximumAssuranceAssessment,
    MaximumAssuranceRequirement,
    MaximumAssuranceStatus,
    MinimumFloorRecoveryModelUsageBinding,
    ModelRequestValidationStatus,
    RepositoryDifferentialRunStatus,
    RepositoryFile,
    RepositoryMap,
    RepositorySuiteDifferentialRun,
    ScannerRun,
    ScannerStatus,
    SolidityCompilationResult,
    SolidityCoverage,
    SolidityProjectMetadata,
    SolidityProjectType,
    UsageRecord,
)
from mmaudit.orchestration.coverage import generic_source_coverage_metrics
from mmaudit.orchestration.run_status import (
    assess_minimum_analysis_floor,
    audit_quality_status_for_run_status,
    minimum_analysis_floor_quality_gate,
)
from tests.identity_fixtures import bind_synthetic_usage_identity, rebind_synthetic_token_plan
from tests.language_capability_support import (
    language_capability_for_files,
    matched_solidity_language_capability,
)
from tests.output_evidence_fixtures import synthetic_structured_output_routing
from tests.refresh_runtime_support import (
    SyntheticRefreshRuntime,
    bind_usage_to_refresh_pricing_runtime,
    bind_usage_to_refresh_runtime,
    synthetic_refresh_runtime,
)
from tests.unit.test_model_policy_selection import (
    BASE_TIME,
    _policy_authority,
    _policy_bundle,
    _resolve,
    _technical_qualification,
)

NOW = BASE_TIME + timedelta(hours=2)


@cache
def _report_policy_selection() -> tuple[AuditModelSelection, VerifiedAuditModelSelection]:
    """Issue one real test-only policy selection for typed report fixtures."""

    technical = _technical_qualification()
    policy = _policy_bundle(
        technical,
        excluded_ids=frozenset({technical.models[-1].exact_model_id}),
    )
    with TemporaryDirectory(prefix="mmaudit-run-status-policy-") as directory:
        authority = _policy_authority(Path(directory), policy)
    selection, _evidence_bundle, capability = _resolve(technical, policy, authority)
    return selection, capability


@cache
def _report_refresh_runtime() -> SyntheticRefreshRuntime:
    """Issue detached refresh custody for typed report fixtures."""

    with TemporaryDirectory(prefix="mmaudit-run-status-refresh-") as directory:
        return synthetic_refresh_runtime(Path(directory))


def _repository() -> RepositoryMap:
    return RepositoryMap(
        root_name="synthetic-floor-target",
        languages={"Solidity": 1},
        frameworks=["foundry"],
        manifests=["foundry.toml"],
        entry_points=["src/Safe.sol"],
        api_surfaces=[],
        auth_components=[],
        data_layers=[],
        network_clients=[],
        file_handlers=[],
        configuration_files=["foundry.toml"],
        sensitive_processing=[],
        security_tests=[],
        files=[
            RepositoryFile(
                path="src/Safe.sol",
                size=128,
                lines=8,
                sha256="1" * 64,
                language="Solidity",
            )
        ],
    )


def _compilation(
    status: CompilationStatus = CompilationStatus.SUCCESS,
) -> SolidityCompilationResult:
    successful = status is CompilationStatus.SUCCESS
    return SolidityCompilationResult(
        status=status,
        framework=SolidityProjectType.FOUNDRY,
        project_root=".",
        executable_sha256="2" * 64,
        command=["forge", "build", "--offline"],
        compiler_versions=["0.8.30"],
        contracts_compiled=["Safe"] if successful else [],
        errors=[] if successful else ["synthetic compilation failure"],
        ast_available=successful,
    )


def _coverage(*, complete: bool = True) -> dict[str, CoverageMetric]:
    return {
        "entry_points": CoverageMetric(
            numerator=1 if complete else 0,
            denominator=1 if complete else 0,
            population=1 if complete else 0,
            percentage=100.0 if complete else None,
            exclusions=[],
            not_applicable_evidence=[],
            confidence=1,
            provenance=[CoverageProvenance.SYMBOL_INDEX],
            failures=[] if complete else ["entry-point inventory did not complete"],
            state=AnalysisState.DETERMINISTIC if complete else AnalysisState.ATTEMPTED_FAILED,
            detail=(
                "synthetic entry point received qualifying analysis"
                if complete
                else "synthetic coverage inventory failed"
            ),
        )
    }


def _real_scanner() -> ScannerRun:
    run = ScannerRun(
        scanner="slither",
        status=ScannerStatus.SUCCESS,
        execution_evidence=ExecutionEvidenceKind.REAL,
        version="slither 0.11.5",
        executable_sha256="3" * 64,
        command=["slither", ".", "--json", "-"],
        started_at=NOW,
        finished_at=NOW,
        duration_seconds=0,
        raw_output_path="private/scanners/slither.json",
        raw_output_sha256="4" * 64,
        raw_output_bytes=64,
        process_exit_code=0,
        isolation_backend="sandbox-exec",
        isolation_attestation_sha256="5" * 64,
        machine_output_validated=True,
    )
    return run.model_copy(
        update={"execution_observation_sha256": run.expected_execution_observation_sha256()}
    )


def _usage(
    role: str,
    *,
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.REAL,
) -> UsageRecord:
    model = "alpha/atlas-secure"
    endpoint = "openrouter/provider-a"
    generation_id = f"generation-{role}"
    record = UsageRecord(
        request_id=f"request-{role}",
        role=role,
        execution_evidence=execution_evidence,
        requested_model=model,
        returned_model=model,
        actual_model=model,
        provider="Synthetic Provider",
        model_family="synthetic",
        timestamp=NOW,
        prompt_tokens=10,
        completion_tokens=5,
        total_tokens=15,
        reported_cost_usd=0.001,
        accounted_cost_usd=0.001,
        routing={
            "generation_id": generation_id,
            "selected_model": model,
            "canonical_model": model,
            "selected_provider_endpoint": endpoint,
            "selected_provider_name": "Synthetic Provider",
            "router_strategy": "direct",
            "router_attempt": 1,
            "router_attempt_count": 1,
            "router_pipeline": [],
            "finish_reason": "stop",
            "schema_sha256": "6" * 64,
            "router_metadata_sha256": "7" * 64,
            "provider_policy_sha256": "8" * 64,
            "provider_fallbacks_allowed": False,
            "certification_request": False,
            "endpoint_snapshot_sha256": "9" * 64,
            "endpoint_pricing_sha256": "a" * 64,
            "catalog_snapshot_sha256": "b" * 64,
            "discovery_provenance_sha256": "c" * 64,
            "discovery_evidence_sha256": "d" * 64,
            "validation_status": "valid",
            "zdr_requested": True,
            "data_collection": "deny",
            "repair_used": False,
            "repair_request": False,
            "request_started_at": NOW.isoformat(),
            "request_ended_at": NOW.isoformat(),
            "latency_ms": 0,
        },
        prompt_sha256="e" * 64,
        user_prompt_sha256="f" * 64,
        response_sha256="0" * 64,
        validated_response_sha256="1" * 64,
        request_body_sha256="2" * 64,
        schema_sha256="6" * 64,
        openrouter_generation_id=generation_id,
        configured_provider_endpoints=[endpoint],
        actual_provider_endpoint=endpoint,
        started_at=NOW,
        ended_at=NOW,
        latency_ms=0,
        finish_reason="stop",
        retry_count=0,
        validation_status=ModelRequestValidationStatus.VALID,
        status="success",
        attempts=1,
    )
    return bind_synthetic_usage_identity(record)


def _bind_report_usage_to_policy_selection(record: UsageRecord) -> UsageRecord:
    if record.execution_evidence is not ExecutionEvidenceKind.REAL:
        return record
    runtime = _report_refresh_runtime()
    selection = runtime.audit_selection_evidence.selection
    capability = runtime.audit_selection
    routes = tuple(
        route
        for route in runtime.evidence.routes
        if route.exact_model_id == record.requested_model and route.audit_selected
    )
    assert len(routes) == 1
    route = routes[0]
    assert record.request_body_sha256 is not None
    assert record.schema_sha256 is not None
    assert record.response_sha256 is not None
    assert record.validated_response_sha256 is not None
    started_at = runtime.evidence.verified_at
    routing = {
        **record.routing,
        "selected_provider_endpoint": route.approved_provider_endpoint,
        "selected_provider_name": route.approved_provider_name,
        "endpoint_snapshot_sha256": route.endpoint_snapshot_sha256,
        "output_capability_sha256": route.output_capability_sha256,
        "request_started_at": started_at.isoformat(),
        "request_ended_at": started_at.isoformat(),
        "structured_output": synthetic_structured_output_routing(
            configured_provider_endpoints=(route.approved_provider_endpoint,),
            selected_provider_endpoint=route.approved_provider_endpoint,
            endpoint_snapshot_sha256=route.endpoint_snapshot_sha256,
            output_capability_sha256=route.output_capability_sha256,
            prompt_sha256=record.prompt_sha256,
            request_body_sha256=record.request_body_sha256,
            provider_policy_sha256=str(record.routing["provider_policy_sha256"]),
            schema_sha256=record.schema_sha256,
            original_response_sha256=record.response_sha256,
            validated_response_sha256=record.validated_response_sha256,
            mode=route.structured_output_mode,
        ),
    }
    prepared = record.model_copy(
        update={
            "returned_model": route.canonical_model_slug,
            "actual_model": route.canonical_model_slug,
            "provider": route.approved_provider_name,
            "timestamp": started_at,
            "configured_provider_endpoints": [route.approved_provider_endpoint],
            "actual_provider_endpoint": route.approved_provider_endpoint,
            "started_at": started_at,
            "ended_at": started_at,
            "routing": routing,
        }
    )
    if record.status == "success":
        prepared = bind_synthetic_usage_identity(rebind_synthetic_token_plan(prepared))
    evidence = capability.routing_evidence(
        prepared.requested_model,
        now=prepared.started_at or prepared.timestamp,
        expected_audit_scope_sha256=selection.audit_scope_sha256,
        expected_source_sha256=selection.source_sha256,
        expected_audit_context_sha256=selection.audit_context_sha256,
        expected_client_constraints_sha256=selection.client_constraints_sha256,
    )
    routing = dict(prepared.routing)
    metadata = dict(evidence.request_metadata())
    routing_evidence_sha256 = metadata.pop("routing_evidence_sha256")
    routing.update(
        {
            **metadata,
            "audit_policy_routing_evidence_sha256": routing_evidence_sha256,
            "audit_selection_capability_sha256": capability.capability_sha256,
            "audit_model_routing_evidence": evidence.model_dump(mode="json"),
        }
    )
    refresh_bound = bind_usage_to_refresh_runtime(
        prepared.model_copy(update={"routing": routing}),
        runtime,
    )
    return bind_usage_to_refresh_pricing_runtime(refresh_bound, runtime)


def _assessment(
    *,
    scanner_runs: list[ScannerRun] | None = None,
    usage: list[UsageRecord] | None = None,
    compilations: list[SolidityCompilationResult] | None = None,
    coverage: dict[str, CoverageMetric] | None = None,
    static_analysis_applicable: bool = True,
    scanner_only: bool = False,
    explicit_downgrade_reason: str | None = None,
    surface_analysis_feasible: bool = True,
    orchestration_failures: tuple[str, ...] = (),
    required_model_roles: tuple[str, ...] = ("source_audit",),
    recovery_model_usage_bindings: Iterable[MinimumFloorRecoveryModelUsageBinding] = (),
):
    return assess_minimum_analysis_floor(
        repository=_repository(),
        compilations=compilations or [_compilation()],
        scanner_runs=scanner_runs or [],
        usage=usage or [],
        required_model_roles=required_model_roles,
        coverage_metrics=_coverage() if coverage is None else coverage,
        static_analysis_applicable=static_analysis_applicable,
        scanner_only=scanner_only,
        explicit_downgrade_reason=explicit_downgrade_reason,
        surface_analysis_feasible=surface_analysis_feasible,
        orchestration_failures=orchestration_failures,
        recovery_model_usage_bindings=recovery_model_usage_bindings,
    )


def test_zero_scanners_and_zero_model_roles_never_complete() -> None:
    floor = _assessment()

    assert floor.run_status is AuditRunStatus.INCOMPLETE
    assert not floor.minimum_floor_met
    assert not floor.qualifying_real_static_scanners
    assert not floor.completed_real_model_roles
    assert not minimum_analysis_floor_quality_gate(floor).passed


def test_minimum_floor_credits_recovery_usage_only_with_exact_external_binding() -> None:
    from mmaudit.models.usage import is_creditable_usage_record
    from tests.unit.test_usage import _owned_request_limit_record

    request_id = "scheduler-recovery-request-" + "a" * 64
    request_limit_scope = "scheduler-request-" + "b" * 64
    usage = _owned_request_limit_record(
        request_id,
        request_limit_scope=request_limit_scope,
        request_limit_count_before=1,
    )
    binding = MinimumFloorRecoveryModelUsageBinding.build(
        usage_record=usage,
        request_limit_scope=request_limit_scope,
        request_limit_count_before=1,
        scheduler_request_evidence_sha256="c" * 64,
    )
    assert not is_creditable_usage_record(usage, require_real=True)

    floor = _assessment(
        usage=[usage],
        static_analysis_applicable=False,
        recovery_model_usage_bindings=(binding,),
    )
    assert floor.schema_version == "1.1"
    assert floor.completed_real_model_roles == ["source_audit"]
    assert floor.run_status is AuditRunStatus.COMPLETE
    with pytest.raises(ValueError, match="differs from provider usage"):
        _assessment(
            usage=[usage],
            static_analysis_applicable=False,
            recovery_model_usage_bindings=(binding.model_copy(update={"role": "business_logic"}),),
        )
    with pytest.raises(ValueError, match=r"differ.*from provider usage"):
        _assessment(
            usage=[usage, usage],
            static_analysis_applicable=False,
            recovery_model_usage_bindings=(binding,),
        )


def test_minimum_floor_bounds_a_lying_infinite_recovery_binding_inventory() -> None:
    from tests.unit.test_usage import _owned_request_limit_record

    request_id = "scheduler-recovery-request-" + "d" * 64
    request_limit_scope = "scheduler-request-" + "e" * 64
    usage = _owned_request_limit_record(
        request_id,
        request_limit_scope=request_limit_scope,
        request_limit_count_before=1,
    )
    binding = MinimumFloorRecoveryModelUsageBinding.build(
        usage_record=usage,
        request_limit_scope=request_limit_scope,
        request_limit_count_before=1,
        scheduler_request_evidence_sha256="f" * 64,
    )

    class LyingBindings:
        def __init__(self) -> None:
            self.consumed = 0

        def __len__(self) -> int:
            return 0

        def __iter__(self) -> Iterator[MinimumFloorRecoveryModelUsageBinding]:
            while True:
                self.consumed += 1
                yield binding

    bindings = LyingBindings()
    with pytest.raises(ValueError, match="recovery usage bindings exceed their item limit"):
        _assessment(
            usage=[usage],
            static_analysis_applicable=False,
            recovery_model_usage_bindings=bindings,
        )
    assert bindings.consumed == 33


def test_mock_near_misses_earn_no_scanner_or_model_credit() -> None:
    scanner = _real_scanner().model_copy(
        update={
            "execution_evidence": ExecutionEvidenceKind.MOCK,
            "execution_observation_sha256": None,
        }
    )
    scanner = scanner.model_copy(
        update={"execution_observation_sha256": scanner.expected_execution_observation_sha256()}
    )
    floor = _assessment(
        scanner_runs=[scanner],
        usage=[_usage("source_audit", execution_evidence=ExecutionEvidenceKind.MOCK)],
    )

    assert floor.run_status is AuditRunStatus.INCOMPLETE
    assert floor.qualifying_real_static_scanners == []
    assert floor.completed_real_model_roles == []


def test_real_scanner_only_requires_explicit_downgrade() -> None:
    unauthorized = _assessment(
        scanner_runs=[_real_scanner()],
        scanner_only=True,
    )
    authorized = _assessment(
        scanner_runs=[_real_scanner()],
        scanner_only=True,
        explicit_downgrade_reason="operator authorized a scanner-only lower profile",
    )

    assert unauthorized.run_status is AuditRunStatus.INCOMPLETE
    assert authorized.run_status is AuditRunStatus.DEGRADED
    assert not authorized.minimum_floor_met
    assert (
        audit_quality_status_for_run_status(authorized.run_status)
        is AuditQualityStatus.COMPLETED_WITH_LIMITATIONS
    )


def test_real_models_only_complete_only_when_static_analysis_is_not_applicable() -> None:
    models_only = [_usage("source_audit")]

    applicable = _assessment(usage=models_only)
    not_applicable = _assessment(
        usage=models_only,
        static_analysis_applicable=False,
    )

    assert applicable.run_status is AuditRunStatus.INCOMPLETE
    assert not_applicable.run_status is AuditRunStatus.COMPLETE
    assert not_applicable.minimum_floor_met


def test_explicit_lower_profile_can_degrade_with_real_model_evidence() -> None:
    floor = _assessment(
        usage=[_usage("source_audit")],
        explicit_downgrade_reason="operator accepted the unavailable static analyzer",
    )

    assert floor.run_status is AuditRunStatus.DEGRADED
    assert not floor.static_analysis_satisfied
    assert floor.completed_real_model_roles == ["source_audit"]
    assert minimum_analysis_floor_quality_gate(floor).state is AnalysisState.MODEL_ONLY


def test_incomplete_coverage_prevents_completion() -> None:
    floor = _assessment(
        scanner_runs=[_real_scanner()],
        usage=[_usage("source_audit")],
        coverage=_coverage(complete=False),
    )

    assert floor.run_status is AuditRunStatus.INCOMPLETE
    assert not floor.coverage_denominators_valid


def test_compilation_failure_is_failed_and_prominent() -> None:
    floor = _assessment(
        scanner_runs=[_real_scanner()],
        usage=[_usage("source_audit")],
        compilations=[_compilation(CompilationStatus.FAILED)],
    )

    assert floor.run_status is AuditRunStatus.FAILED
    assert any("compilation failed" in limitation for limitation in floor.limitations)


def test_completed_floor_requires_all_qualifying_evidence() -> None:
    floor = _assessment(
        scanner_runs=[_real_scanner()],
        usage=[_usage("source_audit")],
    )
    gate = minimum_analysis_floor_quality_gate(floor)

    assert floor.run_status is AuditRunStatus.COMPLETE
    assert floor.minimum_floor_met
    assert floor.qualifying_real_static_scanners == ["slither"]
    assert floor.completed_real_model_roles == ["source_audit"]
    assert gate.passed
    assert gate.state is AnalysisState.DETERMINISTIC


def test_not_applicable_scanner_is_neutral_to_the_minimum_analysis_floor() -> None:
    not_applicable = ScannerRun(
        scanner="osv",
        status=ScannerStatus.NOT_APPLICABLE,
        execution_evidence=ExecutionEvidenceKind.REAL,
        version="osv-scanner version 2.4.0",
        executable_sha256="6" * 64,
        command=["osv-scanner", "scan", "source", "--offline", "."],
        started_at=NOW,
        finished_at=NOW,
        duration_seconds=0,
        error="no supported package sources were present in the audited scope",
        raw_output_path="private/scanners/osv.json",
        raw_output_sha256="7" * 64,
        private_stderr_path="private/scanners/osv.stderr.txt",
        private_stderr_sha256="8" * 64,
        private_stderr_bytes=25,
        process_exit_code=128,
        isolation_backend="sandbox-exec",
        isolation_attestation_sha256="9" * 64,
    )
    not_applicable = not_applicable.model_copy(
        update={
            "execution_observation_sha256": (not_applicable.expected_execution_observation_sha256())
        }
    )

    floor = _assessment(
        scanner_runs=[_real_scanner(), not_applicable],
        usage=[_usage("source_audit")],
    )

    assert floor.run_status is AuditRunStatus.COMPLETE
    assert floor.qualifying_real_static_scanners == ["slither"]
    assert floor.minimum_floor_met


@pytest.mark.parametrize(
    ("has_real_analysis", "expected"),
    [
        (False, AuditRunStatus.FAILED),
        (True, AuditRunStatus.INCOMPLETE),
    ],
)
def test_orchestration_failure_preserves_partial_real_analysis(
    has_real_analysis: bool,
    expected: AuditRunStatus,
) -> None:
    floor = _assessment(
        scanner_runs=[_real_scanner()] if has_real_analysis else [],
        orchestration_failures=("synthetic orchestration failure",),
    )

    assert floor.run_status is expected
    assert not floor.minimum_floor_met


def test_orchestration_failure_text_is_bounded_and_single_line() -> None:
    floor = _assessment(
        orchestration_failures=("provider validation failed:\n\tinvalid response" + "x" * 3_000,),
    )

    assert floor.run_status is AuditRunStatus.FAILED
    assert len(floor.orchestration_failures) == 1
    assert len(floor.orchestration_failures[0]) == 2_000
    assert "\n" not in floor.orchestration_failures[0]
    assert "\t" not in floor.orchestration_failures[0]


def _report_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "run_id": "synthetic-floor-run",
        "generated_at": NOW,
        "completed": True,
        "incomplete_reasons": [],
        "repository": _repository(),
        "configuration_hash": "3" * 64,
        "model_configuration_hash": "4" * 64,
        "privacy": {},
        "scanner_runs": [],
        "usage": [],
        "budget_usd": 0,
        "accounted_cost_usd": 0,
        "findings": [],
        "rejected_findings": [],
    }


def _typed_report_payload(
    *,
    floor,
    scanner_runs: list[ScannerRun],
    usage: list[UsageRecord],
    coverage: dict[str, CoverageMetric],
) -> dict[str, object]:
    compilation = _compilation()
    refresh_runtime = _report_refresh_runtime()
    selection = refresh_runtime.audit_selection_evidence.selection
    policy_bound_usage = [_bind_report_usage_to_policy_selection(record) for record in usage]
    project = SolidityProjectMetadata(
        project_type=SolidityProjectType.FOUNDRY,
        project_root=".",
        source_directories=["src"],
    )
    return {
        **_report_payload(),
        "schema_version": "1.2",
        "completed": floor.run_status is AuditRunStatus.COMPLETE,
        "incomplete_reasons": []
        if floor.run_status is AuditRunStatus.COMPLETE
        else floor.limitations,
        "quality_status": audit_quality_status_for_run_status(floor.run_status),
        "run_status": floor.run_status,
        "minimum_analysis_floor": floor,
        "language_capability": matched_solidity_language_capability(
            path="src/Safe.sol",
            content=b"contract Safe { function run() external {} }\n",
        ).assessment,
        "quality_gates": [minimum_analysis_floor_quality_gate(floor)],
        "scanner_runs": scanner_runs,
        "usage": policy_bound_usage,
        "audit_model_selection": selection,
        "audit_model_refresh_evidence": refresh_runtime.evidence,
        "audit_model_refresh_pricing_evidence": refresh_runtime.pricing_evidence,
        "solidity_coverage": SolidityCoverage(quality_metrics=coverage),
        "metadata": {
            "scanner_only": floor.scanner_only,
            "solidity": {
                "projects": [project.model_dump(mode="json")],
                "compilation": [compilation.model_dump(mode="json")],
            },
        },
    }


def test_legacy_report_without_typed_floor_remains_valid() -> None:
    report = AuditReport.model_validate(_report_payload())

    assert report.run_status is None
    assert report.minimum_analysis_floor is None
    assert report.completed


def test_typed_report_requires_floor_status_quality_and_completion_consistency() -> None:
    scanner = _real_scanner()
    usage = [_usage(role) for role in ANALYSIS_ROLES]
    complete_floor = _assessment(
        scanner_runs=[scanner],
        usage=usage,
        required_model_roles=ANALYSIS_ROLES,
    )
    complete_payload = _typed_report_payload(
        floor=complete_floor,
        scanner_runs=[scanner],
        usage=usage,
        coverage=_coverage(),
    )
    complete = AuditReport.model_validate(complete_payload)
    assert complete.completed
    assert AuditReport.model_validate_json(complete.model_dump_json()) == complete
    failed_required_gate = minimum_analysis_floor_quality_gate(complete_floor).model_copy(
        update={
            "gate": "synthetic_required_surface",
            "passed": False,
            "detail": "synthetic required surface was not analyzed",
        }
    )
    failed_maximum_assurance = MaximumAssuranceAssessment(
        requested=True,
        required=True,
        downgrade_allowed=False,
        downgraded=False,
        status=MaximumAssuranceStatus.FAILED,
        requirements=[
            MaximumAssuranceRequirement(
                engine="synthetic-required-engine",
                required=True,
                passed=False,
                blocking=True,
                state=AnalysisState.ATTEMPTED_FAILED,
                detail="synthetic required engine did not complete",
            )
        ],
    )

    incomplete_floor = _assessment(required_model_roles=ANALYSIS_ROLES)
    base_incomplete = _typed_report_payload(
        floor=incomplete_floor,
        scanner_runs=[],
        usage=[],
        coverage=_coverage(),
    )
    assert not AuditReport.model_validate(base_incomplete).completed

    for mutation in (
        {**base_incomplete, "completed": True},
        {**base_incomplete, "quality_status": AuditQualityStatus.COMPLETED},
        {**base_incomplete, "run_status": AuditRunStatus.FAILED},
        {**base_incomplete, "minimum_analysis_floor": None},
        {**base_incomplete, "incomplete_reasons": []},
        {key: value for key, value in complete_payload.items() if key != "run_status"},
        {key: value for key, value in complete_payload.items() if key != "language_capability"},
        {
            **complete_payload,
            "incomplete_reasons": ["synthetic missing mandatory phase"],
        },
        {
            **complete_payload,
            "quality_gates": [
                *complete_payload["quality_gates"],
                failed_required_gate,
            ],
        },
        {
            **complete_payload,
            "scanner_runs": [],
            "usage": [],
        },
        {
            **complete_payload,
            "audit_profile": AuditProfile.MAXIMUM_ASSURANCE,
            "maximum_assurance": failed_maximum_assurance,
        },
    ):
        with pytest.raises(ValidationError):
            AuditReport.model_validate(mutation)


def test_maximum_complete_report_rejects_blocking_language_inventory_omission() -> None:
    scanner = _real_scanner()
    usage = [_usage(role) for role in ANALYSIS_ROLES]
    floor = _assessment(
        scanner_runs=[scanner],
        usage=usage,
        required_model_roles=ANALYSIS_ROLES,
    )
    payload = _typed_report_payload(
        floor=floor,
        scanner_runs=[scanner],
        usage=usage,
        coverage=_coverage(),
    )
    blocked_capability = matched_solidity_language_capability(
        path="src/Safe.sol",
        content=b"contract Safe { function run() external {} }\n",
    ).assessment.model_copy(
        update={"blocking_discovery_omissions": ("repository: max_files reached",)}
    )
    maximum = MaximumAssuranceAssessment(
        requested=True,
        required=True,
        downgrade_allowed=False,
        downgraded=False,
        status=MaximumAssuranceStatus.COMPLETE,
        requirements=[
            MaximumAssuranceRequirement(
                engine="language_capability_profile",
                required=True,
                passed=True,
                blocking=False,
                state=AnalysisState.DETERMINISTIC,
                detail="Synthetic clause would pass without the blocking inventory omission.",
            )
        ],
    )

    with pytest.raises(ValidationError, match="matched Solidity/EVM capability"):
        AuditReport.model_validate(
            {
                **payload,
                "audit_profile": AuditProfile.MAXIMUM_ASSURANCE,
                "maximum_assurance": maximum,
                "language_capability": blocked_capability,
            }
        )


def test_current_python_report_cannot_claim_complete_without_language_capability() -> None:
    scanner = _real_scanner()
    usage = [_usage(role) for role in ANALYSIS_ROLES]
    floor = _assessment(
        scanner_runs=[scanner],
        usage=usage,
        required_model_roles=ANALYSIS_ROLES,
    )
    payload = _typed_report_payload(
        floor=floor,
        scanner_runs=[scanner],
        usage=usage,
        coverage=_coverage(),
    )
    payload["repository"] = RepositoryMap(
        root_name="synthetic-python-target",
        languages={"Python": 1},
        frameworks=[],
        manifests=[],
        entry_points=["app.py"],
        api_surfaces=[],
        auth_components=[],
        data_layers=[],
        network_clients=[],
        file_handlers=[],
        configuration_files=[],
        sensitive_processing=[],
        security_tests=[],
        files=[
            RepositoryFile(
                path="app.py",
                size=10,
                lines=1,
                sha256="f" * 64,
                language="Python",
            )
        ],
    )
    payload.pop("language_capability")

    with pytest.raises(ValidationError, match="typed language capability"):
        AuditReport.model_validate(payload)


def test_matched_solidity_capability_cannot_complete_without_applicable_runtime() -> None:
    usage = [_usage(role) for role in ANALYSIS_ROLES]
    floor = assess_minimum_analysis_floor(
        repository=_repository(),
        compilations=[],
        scanner_runs=[],
        usage=usage,
        required_model_roles=ANALYSIS_ROLES,
        coverage_metrics=_coverage(),
        solidity_applicable=False,
        static_analysis_applicable=False,
    )
    assert floor.run_status is AuditRunStatus.COMPLETE
    payload = _typed_report_payload(
        floor=floor,
        scanner_runs=[],
        usage=usage,
        coverage=_coverage(),
    )
    payload["metadata"] = {
        "scanner_only": False,
        "solidity": {"projects": [], "compilation": []},
    }

    with pytest.raises(ValidationError, match=r"capability conflicts.*Solidity applicability"):
        AuditReport.model_validate(payload)


def test_current_report_language_census_must_match_retained_source_inventory() -> None:
    scanner = _real_scanner()
    usage = [_usage(role) for role in ANALYSIS_ROLES]
    floor = _assessment(
        scanner_runs=[scanner],
        usage=usage,
        required_model_roles=ANALYSIS_ROLES,
    )
    payload = _typed_report_payload(
        floor=floor,
        scanner_runs=[scanner],
        usage=usage,
        coverage=_coverage(),
    )
    payload["repository"] = _repository().model_copy(update={"languages": {"Solidity": 2}})

    with pytest.raises(ValidationError, match="language census"):
        AuditReport.model_validate(payload)


def test_reduced_generic_report_rejects_substantive_solidity_portfolio_evidence() -> None:
    repository = RepositoryMap(
        root_name="synthetic-python-target",
        languages={"Python": 1},
        frameworks=[],
        manifests=[],
        entry_points=["app.py"],
        api_surfaces=[],
        auth_components=[],
        data_layers=[],
        network_clients=[],
        file_handlers=[],
        configuration_files=[],
        sensitive_processing=[],
        security_tests=[],
        files=[
            RepositoryFile(
                path="app.py",
                size=10,
                lines=1,
                sha256="f" * 64,
                language="Python",
            )
        ],
    )
    usage = [_usage(role) for role in ANALYSIS_ROLES]
    floor = assess_minimum_analysis_floor(
        repository=repository,
        compilations=[],
        scanner_runs=[],
        usage=usage,
        required_model_roles=ANALYSIS_ROLES,
        coverage_metrics=generic_source_coverage_metrics(
            repository,
            [],
            require_scanner_completion=False,
        ),
        solidity_applicable=False,
        static_analysis_applicable=False,
    )
    capability = language_capability_for_files(
        LanguageCapabilityProfile.GENERIC_SOURCE_REVIEW,
        (
            LanguageCapabilityFileEvidence(
                path="app.py",
                size=10,
                lines=1,
                sha256="f" * 64,
                language="Python",
            ),
        ),
    )
    payload = _typed_report_payload(
        floor=floor,
        scanner_runs=[],
        usage=usage,
        coverage={},
    )
    payload.update(
        {
            "repository": repository,
            "language_capability": capability.assessment,
            "solidity_coverage": SolidityCoverage(
                context_limitations=[
                    "Solidity/EVM coverage is not applicable to generic-source-review."
                ]
            ),
            "metadata": {
                "scanner_only": False,
                "solidity": {"projects": [], "compilation": []},
            },
        }
    )
    assert AuditReport.model_validate(payload).run_status is AuditRunStatus.COMPLETE

    with pytest.raises(ValidationError, match="Solidity/EVM portfolio evidence"):
        AuditReport.model_validate(
            {
                **payload,
                "solidity_coverage": SolidityCoverage(
                    projects_discovered=1,
                    context_limitations=[
                        "Solidity/EVM coverage is not applicable to generic-source-review."
                    ],
                ),
            }
        )
    with pytest.raises(ValidationError, match="Solidity/EVM portfolio evidence"):
        AuditReport.model_validate({**payload, "invariants": InvariantSuite()})
    with pytest.raises(ValidationError, match="scanner_runs:slither"):
        AuditReport.model_validate({**payload, "scanner_runs": [_real_scanner()]})
    differential = RepositorySuiteDifferentialRun.sealed(
        status=RepositoryDifferentialRunStatus.FAILED,
        configuration_sha256="f" * 64,
        requested_state_ids=("clean-local", "pinned-state"),
        required_repetitions=2,
        matrix=None,
        limitations=("Synthetic repository differential is not applicable.",),
    )
    with pytest.raises(ValidationError, match="repository_suite_differential"):
        AuditReport.model_validate({**payload, "repository_suite_differential": differential})
    contradictory_property_metadata = {
        "scanner_only": False,
        "solidity": {
            "projects": [],
            "compilation": [],
            "property_corpus_summary": {
                "properties": 1,
                "limitations": 0,
                "corpus_hash": "f" * 64,
            },
        },
    }
    with pytest.raises(ValidationError, match=r"metadata\.solidity"):
        AuditReport.model_validate({**payload, "metadata": contradictory_property_metadata})
    contradictory_metadata = {
        "scanner_only": False,
        "solidity": {
            "projects": [],
            "compilation": [],
            "invariant_summary": {"executed": 99},
            "formal_summary": {"runs": 99, "statuses": {"formal": "proved"}},
            "generated_test_specifications": 99,
            "reproduction_results": 99,
        },
    }
    with pytest.raises(ValidationError, match=r"metadata\.solidity"):
        AuditReport.model_validate({**payload, "metadata": contradictory_metadata})
