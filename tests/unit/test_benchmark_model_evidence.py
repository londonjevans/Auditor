from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mmaudit.benchmark.engine import (
    MAXIMUM_ASSURANCE_CORE_CLAUSES,
    BenchmarkMetricState,
    BenchmarkReport,
    evaluate_benchmark,
    load_manifest,
)
from mmaudit.models.schemas import (
    AnalysisState,
    AuditProfile,
    AuditReport,
    CoverageMetric,
    CoverageProvenance,
    ExecutionEvidenceKind,
    MaximumAssuranceAssessment,
    MaximumAssuranceRequirement,
    MaximumAssuranceStatus,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    ModelReviewCoverage,
    ModelReviewEvidenceReference,
    ModelReviewSurface,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewStatus,
    RepositoryMap,
    UsageRecord,
)
from tests.identity_fixtures import bind_synthetic_usage_identity

ROOT = Path(__file__).parents[2]
SURFACE_ID = "model-surface:" + ("a" * 64)
MODEL_A = "synthetic/model-a"
MODEL_B = "synthetic/model-b"
ROOT_A = "sha256:" + ("a" * 64)
ROOT_B = "sha256:" + ("b" * 64)


def _identity_sha256(*, model: str, canonical_model: str) -> str:
    return hashlib.sha256(
        json.dumps(
            {"canonical_slug": canonical_model, "id": model},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _usage(
    request_id: str,
    *,
    model: str = MODEL_A,
    root_lineage: str = ROOT_A,
    role: str = "source_audit",
) -> UsageRecord:
    started_at = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
    ended_at = started_at + timedelta(milliseconds=25)
    generation_id = f"generation-{request_id}-{model.rsplit('/', maxsplit=1)[-1]}"
    endpoint = "Synthetic"
    schema_sha256 = "1" * 64
    routing = {
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
        "schema_sha256": schema_sha256,
        "router_metadata_sha256": "2" * 64,
        "provider_policy_sha256": "3" * 64,
        "validation_status": "valid",
        "zdr_requested": True,
        "data_collection": "deny",
        "repair_used": False,
        "repair_request": False,
        "request_started_at": started_at.isoformat(),
        "request_ended_at": ended_at.isoformat(),
        "latency_ms": 25,
        "certification_request": True,
        "catalog_identity_binding_sha256": _identity_sha256(
            model=model,
            canonical_model=model,
        ),
        "provider_fallbacks_allowed": False,
        "endpoint_snapshot_sha256": "4" * 64,
        "endpoint_pricing_sha256": "5" * 64,
        "catalog_snapshot_sha256": "6" * 64,
        "discovery_provenance_sha256": "7" * 64,
        "discovery_evidence_sha256": "8" * 64,
        "qualified_exact_model_id": model,
        "qualified_canonical_model_slug": model,
        "qualified_root_lineage": root_lineage,
        "qualified_provider_endpoint": endpoint,
        "qualified_provider_name": "Synthetic Provider",
        "qualified_endpoint_snapshot_sha256": "4" * 64,
        "qualified_model_metadata_snapshot_sha256": "9" * 64,
        "qualified_pricing_snapshot_sha256": "5" * 64,
        "qualified_roles": [role],
        "qualification_verified_at": started_at.isoformat(),
        "qualification_expires_at": (started_at + timedelta(days=1)).isoformat(),
        "qualification_artifact_sha256": "a" * 64,
        "qualification_verification_sha256": "b" * 64,
        "production_selection_sha256": "c" * 64,
        "selection_verification_sha256": "d" * 64,
        "qualification_result_sha256": "e" * 64,
    }
    return bind_synthetic_usage_identity(
        UsageRecord(
            request_id=request_id,
            role=role,
            execution_evidence=ExecutionEvidenceKind.REAL,
            requested_model=model,
            returned_model=model,
            actual_model=model,
            provider="Synthetic Provider",
            model_family=model.split("/", maxsplit=1)[0],
            timestamp=started_at,
            prompt_tokens=10,
            completion_tokens=5,
            total_tokens=15,
            reported_cost_usd=0.001,
            accounted_cost_usd=0.001,
            routing=routing,
            prompt_sha256="f" * 64,
            user_prompt_sha256="0" * 64,
            response_sha256="1" * 64,
            validated_response_sha256="2" * 64,
            request_body_sha256="3" * 64,
            schema_sha256=schema_sha256,
            openrouter_generation_id=generation_id,
            configured_provider_endpoints=[endpoint],
            actual_provider_endpoint=endpoint,
            started_at=started_at,
            ended_at=ended_at,
            latency_ms=25,
            finish_reason="stop",
            retry_count=0,
            validation_status=ModelRequestValidationStatus.VALID,
            status="success",
            attempts=1,
        )
    )


def _reference(
    usage: UsageRecord,
    *,
    artifact_digit: str = "4",
    requested_model: str | None = None,
    model: str | None = None,
    role: str | None = None,
    root_lineage: str | None = None,
) -> ModelReviewEvidenceReference:
    qualified_root = usage.routing["qualified_root_lineage"]
    assert isinstance(qualified_root, str)
    return ModelReviewEvidenceReference(
        surface_id=SURFACE_ID,
        request_id=usage.request_id,
        artifact_sha256=artifact_digit * 64,
        requested_model=requested_model or usage.requested_model,
        model=model or usage.actual_model,
        review_role=role or usage.role,
        status=ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
        root_lineage=root_lineage or qualified_root,
        credited=True,
        reason="credited synthetic per-surface review",
    )


def _coverage_metric(numerator: int, denominator: int, detail: str) -> CoverageMetric:
    return CoverageMetric(
        numerator=numerator,
        denominator=denominator,
        population=denominator,
        percentage=round(numerator / denominator * 100, 4) if denominator else None,
        exclusions=[],
        not_applicable_evidence=[] if denominator else ["no surfaces of this kind"],
        confidence=1,
        provenance=[CoverageProvenance.MODEL_REVIEW],
        failures=[] if numerator == denominator else ["synthetic review evidence was not credited"],
        state=AnalysisState.MODEL_ONLY,
        detail=detail,
    )


def _coverage(
    references: list[ModelReviewEvidenceReference],
    *,
    critical: bool = False,
) -> ModelReviewCoverage:
    references = sorted(
        references,
        key=lambda item: (
            item.request_id,
            item.artifact_sha256,
            item.surface_id,
            item.review_role,
            item.status.value,
        ),
    )
    surface = ModelReviewSurface(
        surface_id=SURFACE_ID,
        kind=ModelReviewSurfaceKind.CONTRACT,
        subject_id="contract:synthetic",
        label="Synthetic contract",
        critical=critical,
        locations=[],
        evidence_references=references,
    )
    kind_metrics = {
        kind: _coverage_metric(
            1 if kind is ModelReviewSurfaceKind.CONTRACT else 0,
            1 if kind is ModelReviewSurfaceKind.CONTRACT else 0,
            f"synthetic {kind.value} review coverage",
        )
        for kind in ModelReviewSurfaceKind
    }
    critical_denominator = int(critical)
    critical_numerator = int(critical and len(surface.root_lineages) >= 2)
    return ModelReviewCoverage(
        applicable=True,
        minimum_critical_root_lineages=2,
        surfaces=[surface],
        overall=_coverage_metric(1, 1, "synthetic overall review coverage"),
        by_kind=kind_metrics,
        critical=_coverage_metric(
            critical_numerator,
            critical_denominator,
            "synthetic critical review coverage",
        ),
        critical_gate_passed=critical_numerator == critical_denominator,
        limitations=[],
    )


def _report(
    repository_id: str,
    usage: list[UsageRecord],
    references: list[ModelReviewEvidenceReference],
    *,
    critical: bool = False,
) -> AuditReport:
    return AuditReport(
        schema_version="1.1",
        run_id=f"benchmark-model-evidence-{repository_id}",
        generated_at=datetime(2026, 7, 28, 12, 1, tzinfo=UTC),
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
            configuration_files=[],
            sensitive_processing=[],
            security_tests=[],
            files=[],
        ),
        configuration_hash="a" * 64,
        model_configuration_hash="b" * 64,
        privacy={"code_egress_enabled": True},
        scanner_runs=[],
        usage=usage,
        budget_usd=1,
        accounted_cost_usd=sum(item.accounted_cost_usd for item in usage),
        findings=[],
        rejected_findings=[],
        audit_profile=AuditProfile.MAXIMUM_ASSURANCE,
        maximum_assurance=MaximumAssuranceAssessment(
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
        model_review_coverage=_coverage(references, critical=critical),
    )


def _evaluate(
    usage: list[UsageRecord],
    references: list[ModelReviewEvidenceReference],
    *,
    critical: bool = False,
    roundtrip_reports: bool = False,
    stale_reports: bool = False,
) -> BenchmarkReport:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    repository_ids = sorted(item.repository_id for item in manifest.repositories)
    reports = {
        repository_id: _report(
            repository_id,
            usage,
            references,
            critical=critical,
        )
        for repository_id in repository_ids
    }
    if stale_reports:
        reports = {
            repository_id: report.model_copy(
                update={
                    "repository": report.repository.model_copy(
                        update={"root_name": f"stale-{repository_id}"}
                    )
                }
            )
            for repository_id, report in reports.items()
        }
    if roundtrip_reports:
        reports = {
            repository_id: AuditReport.model_validate_json(report.model_dump_json())
            for repository_id, report in reports.items()
        }
    return evaluate_benchmark(
        manifest,
        reports,
        profile=AuditProfile.MAXIMUM_ASSURANCE,
    )


def test_exact_usage_reference_join_credits_valid_surface() -> None:
    usage = _usage("request-valid")

    result = _evaluate([usage], [_reference(usage)])

    assert result.metrics.model_call_success_rate.state is BenchmarkMetricState.PASS
    assert result.metrics.model_review_coverage.state is BenchmarkMetricState.PASS
    assert (
        result.metrics.model_review_coverage.numerator
        == result.metrics.model_review_coverage.denominator
        == 2
    )


def test_serialized_real_usage_without_runtime_authority_is_not_evaluable() -> None:
    first = _usage("request-serialized-a")
    second = _usage(
        "request-serialized-b",
        model=MODEL_B,
        root_lineage=ROOT_B,
    )

    result = _evaluate(
        [first, second],
        [_reference(first), _reference(second)],
        critical=True,
        roundtrip_reports=True,
    )

    for metric in (
        result.metrics.model_call_success_rate,
        result.metrics.model_review_coverage,
        result.metrics.critical_model_review_coverage,
    ):
        assert metric.denominator > 0
        assert metric.evaluated == 0
        assert metric.numerator == 0
        assert metric.state is BenchmarkMetricState.NOT_EVALUABLE


def test_stale_serialized_real_usage_remains_an_evaluated_failure() -> None:
    usage = _usage("request-stale")

    result = _evaluate(
        [usage],
        [_reference(usage)],
        critical=True,
        roundtrip_reports=True,
        stale_reports=True,
    )

    for metric in (
        result.metrics.model_call_success_rate,
        result.metrics.model_review_coverage,
        result.metrics.critical_model_review_coverage,
    ):
        assert metric.denominator > 0
        assert metric.evaluated == metric.denominator
        assert metric.numerator == 0
        assert metric.state is BenchmarkMetricState.FAIL


@pytest.mark.parametrize(
    "attempt_kind",
    ["invalid", "mock", "failed"],
)
def test_non_creditable_attempts_remain_evaluated_failures(attempt_kind: str) -> None:
    live_usage = _usage(f"request-{attempt_kind}")
    payload = live_usage.model_dump(mode="json")
    if attempt_kind == "invalid":
        routing = dict(payload["routing"])
        routing["qualified_root_lineage"] = "invalid"
        payload["routing"] = routing
    elif attempt_kind == "mock":
        payload["execution_evidence"] = ExecutionEvidenceKind.MOCK.value
    else:
        payload.update(
            {
                "identity_strength": ModelIdentityStrength.UNBOUND.value,
                "status": "failed",
                "validation_status": ModelRequestValidationStatus.INVALID_RESPONSE.value,
            }
        )
    usage = UsageRecord.model_validate(payload)

    result = _evaluate([usage], [_reference(live_usage)])

    assert result.metrics.model_call_success_rate.evaluated == (
        result.metrics.model_call_success_rate.denominator
    )
    assert result.metrics.model_call_success_rate.state is BenchmarkMetricState.FAIL
    assert result.metrics.model_review_coverage.evaluated == (
        result.metrics.model_review_coverage.denominator
    )
    assert result.metrics.model_review_coverage.state is BenchmarkMetricState.FAIL


@pytest.mark.parametrize(
    "reference_updates",
    [
        {"root_lineage": ROOT_B},
        {"role": "business_logic"},
        {"requested_model": MODEL_B},
        {"model": MODEL_B},
    ],
    ids=["root-lineage", "role", "requested-model", "actual-model"],
)
def test_relabelled_usage_identity_cannot_earn_surface_credit(
    reference_updates: dict[str, str],
) -> None:
    usage = _usage("request-relabelled")

    result = _evaluate([usage], [_reference(usage, **reference_updates)])

    assert result.metrics.model_review_coverage.numerator == 0
    assert result.metrics.model_review_coverage.state is not BenchmarkMetricState.PASS


def test_duplicate_request_ids_are_ambiguous_and_earn_no_surface_credit() -> None:
    first = _usage("request-duplicate")
    second = _usage(
        "request-duplicate",
        model=MODEL_B,
        root_lineage=ROOT_B,
    )

    result = _evaluate([first, second], [_reference(first)])

    assert result.metrics.model_call_success_rate.numerator == 0
    assert result.metrics.model_review_coverage.numerator == 0
    assert result.metrics.model_review_coverage.state is not BenchmarkMetricState.PASS


def test_one_request_cannot_inflate_critical_root_lineages() -> None:
    usage = _usage("request-one-lineage")
    references = [
        _reference(usage, artifact_digit="4", root_lineage=ROOT_A),
        _reference(usage, artifact_digit="5", root_lineage=ROOT_B),
    ]

    result = _evaluate([usage], references, critical=True)

    assert result.metrics.critical_model_review_coverage.numerator == 0


def test_missing_report_remains_in_model_call_and_surface_denominators() -> None:
    usage = _usage("request-partial-inventory")
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    repository_id = sorted(item.repository_id for item in manifest.repositories)[0]

    result = evaluate_benchmark(
        manifest,
        {
            repository_id: _report(
                repository_id,
                [usage],
                [_reference(usage)],
            )
        },
        profile=AuditProfile.MAXIMUM_ASSURANCE,
    )

    assert result.metrics.model_call_success_rate.state is BenchmarkMetricState.INCONCLUSIVE
    assert result.metrics.model_review_coverage.state is BenchmarkMetricState.INCONCLUSIVE
    assert result.metrics.model_call_success_rate.denominator == 2
    assert result.metrics.model_review_coverage.denominator == 2
    assert not next(
        gate for gate in result.gates if gate.name == "maximum_assurance_substantive_model_review"
    ).passed
    assert result.metrics.critical_model_review_coverage.state is not BenchmarkMetricState.PASS
