from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

import mmaudit.benchmark.models as benchmark_models
import mmaudit.models.openrouter as openrouter_module
from mmaudit.benchmark.model_portfolio import (
    ModelBenchmarkPortfolio,
    load_model_benchmark_portfolio,
    write_model_benchmark_portfolio,
)
from mmaudit.benchmark.models import (
    ModelBenchmarkClassification,
    ModelBenchmarkProviderResult,
    ModelBenchmarkReport,
    ModelBenchmarkResponse,
    ModelBenchmarkSuite,
    ModelBenchmarkTarget,
    load_model_benchmark_corpus,
    run_model_benchmark,
)
from mmaudit.models.candidate_benchmark import (
    CandidateBenchmarkDiagnostic,
    CandidateBenchmarkFailureStage,
    CandidateBenchmarkRunState,
)
from mmaudit.models.generation_evidence import validate_openrouter_generation_payload
from mmaudit.models.openrouter import strict_json_schema
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    CandidateModel,
    CandidateOperationalStatus,
    CandidateRegistry,
    LineageReviewStatus,
    seal_candidate_registry,
    seal_operator_lineage_review,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json
from tests.identity_fixtures import (
    bind_synthetic_usage_identity,
    synthetic_strict_zdr_privacy_routing,
    synthetic_token_plan_routing,
)
from tests.output_evidence_fixtures import (
    SYNTHETIC_OUTPUT_CAPABILITY_SHA256,
    synthetic_structured_output_routing,
)

ROOT = Path(__file__).parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
MODEL_IDS = ("author-a/model-a", "author-b/model-b")


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _candidate_registry(
    model_ids: tuple[str, ...] = MODEL_IDS,
    *,
    created_at: datetime = NOW,
    discovery_hash: str | None = None,
) -> CandidateRegistry:
    candidates = []
    for index, model_id in enumerate(model_ids):
        review = seal_operator_lineage_review(
            status=LineageReviewStatus.PENDING,
            reviewed_model_ids=(model_id,),
            rationale="Pending independent operator lineage review.",
        )
        candidates.append(
            CandidateModel(
                exact_model_id=model_id,
                canonical_model_slug=model_id,
                lineage_review=review,
                discovery_evidence_sha256=_sha(f"discovery:{model_id}"),
                approved_provider_endpoint=f"provider-{index}",
                approved_provider_name=f"Provider {index}",
                endpoint_snapshot_sha256=_sha(f"endpoint:{model_id}"),
                output_capability_sha256=SYNTHETIC_OUTPUT_CAPABILITY_SHA256,
                model_metadata_snapshot_sha256=_sha(f"metadata:{model_id}"),
                pricing_snapshot_sha256=_sha(f"pricing:{model_id}"),
                context_size=100_000,
                max_prompt_tokens=91_808,
                max_prompt_tokens_source="metadata",
                output_limit=8_192,
                output_limit_source="metadata",
                structured_output_supported=True,
                structured_output_mode=StructuredOutputMode.JSON_OBJECT,
                reasoning_supported=True,
                zdr_eligible=True,
                data_collection_deny_eligible=True,
                data_collection_deny_request_policy_enforced=True,
                data_collection_deny_evidence_source="ZDR_ENDPOINT_SNAPSHOT",
                data_collection_deny_evidence_sha256="8" * 64,
                operational_status=CandidateOperationalStatus.AVAILABLE,
                benchmark_status=CandidateBenchmarkStatus.PENDING,
            )
        )
    return seal_candidate_registry(
        created_at=created_at,
        discovery_run_sha256=discovery_hash or _sha("discovery-run-manifest"),
        candidates=tuple(candidates),
    )


class _DeterministicProvider:
    def __init__(
        self,
        *,
        suite: ModelBenchmarkSuite,
        execution_evidence: ExecutionEvidenceKind,
    ) -> None:
        self.case_ids = tuple(case.case_id for case in suite.cases)
        self.execution_evidence = execution_evidence

    async def evaluate(
        self,
        *,
        target: ModelBenchmarkTarget,
        system_prompt: str,
        user_prompt: str,
    ) -> ModelBenchmarkProviderResult:
        request = json.loads(user_prompt.split("\n", 1)[1])
        case_id = request["case_id"]
        assert isinstance(case_id, str)
        response = ModelBenchmarkResponse(
            case_id=case_id,
            classification=ModelBenchmarkClassification.INSUFFICIENT_CONTEXT,
            locations=[],
            invariant=None,
            repository_instructions_followed=False,
            assumptions=[],
            unsupported_assumptions=[],
            verifier_conclusion=None,
            falsifier_conclusion=None,
            remediation=None,
            rationale="The supplied excerpt is insufficient for this conclusion.",
        )
        return ModelBenchmarkProviderResult(
            response=response,
            usage_record=_usage_record(
                case_id=case_id,
                case_index=self.case_ids.index(case_id),
                target=target,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response=response,
                execution_evidence=self.execution_evidence,
            ),
        )


class _UnavailableProvider:
    async def evaluate(
        self,
        *,
        target: ModelBenchmarkTarget,
        system_prompt: str,
        user_prompt: str,
    ) -> ModelBenchmarkProviderResult:
        del target, system_prompt, user_prompt
        raise ValueError("synthetic provider unavailable")


def _usage_record(
    *,
    case_id: str,
    case_index: int,
    target: ModelBenchmarkTarget,
    system_prompt: str,
    user_prompt: str,
    response: ModelBenchmarkResponse,
    execution_evidence: ExecutionEvidenceKind,
) -> UsageRecord:
    model_index = MODEL_IDS.index(target.model_id) if target.model_id in MODEL_IDS else 2
    started_at = NOW + timedelta(hours=1, seconds=(model_index * 100) + case_index)
    ended_at = started_at + timedelta(milliseconds=125)
    target_slug = target.model_id.replace("/", "-")
    generation_id = f"generation-{target_slug}-{case_id}"
    endpoint = f"provider-{model_index}"
    schema_sha256 = benchmark_models._provider_payload_sha256(
        strict_json_schema(ModelBenchmarkResponse)
    )
    output_mode = StructuredOutputMode.JSON_OBJECT
    output_plan = openrouter_module._structured_output_request_plan(
        mode=output_mode,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_model=ModelBenchmarkResponse,
        schema_name="mmaudit_model_benchmark",
    )
    prompt_sha256 = openrouter_module.structured_output_prompt_sha256(
        mode=output_mode,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_model=ModelBenchmarkResponse,
        schema_name="mmaudit_model_benchmark",
    )
    response_sha256 = benchmark_models._validated_response_sha256(response)
    endpoint_snapshot_sha256 = "1" * 64
    request_body_sha256 = "c" * 64
    provider_policy_sha256 = "f" * 64
    routing = synthetic_strict_zdr_privacy_routing(
        {
            "generation_id": generation_id,
            "selected_model": target.model_id,
            "selected_provider_endpoint": endpoint,
            "router_strategy": "direct",
            "router_attempt": 1,
            "router_attempt_count": 1,
            "router_pipeline": [],
            "finish_reason": "stop",
            "schema_sha256": schema_sha256,
            "router_metadata_sha256": "e" * 64,
            "provider_policy_sha256": provider_policy_sha256,
            "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
            "output_capability_sha256": SYNTHETIC_OUTPUT_CAPABILITY_SHA256,
            "provider_fallbacks_allowed": False,
            "certification_request": False,
            "validation_status": "valid",
            "zdr_requested": True,
            "data_collection": "deny",
            "repair_used": False,
            "repair_request": False,
            "structured_output_mode": output_mode.value,
            "structured_output_request_shape_sha256": output_plan.request_shape_sha256,
            "structured_output_require_parameters": output_plan.require_parameters,
            "structured_output_required_provider_parameters": list(
                output_plan.required_provider_parameters
            ),
            "structured_output_reasoning_request_sha256": (output_plan.reasoning_request_sha256),
            "structured_output_response_format": output_plan.response_format["type"],
            "structured_output_protocol_sha256": output_plan.strict_protocol_sha256,
            "structured_output": synthetic_structured_output_routing(
                configured_provider_endpoints=(endpoint,),
                selected_provider_endpoint=endpoint,
                endpoint_snapshot_sha256=endpoint_snapshot_sha256,
                output_capability_sha256=SYNTHETIC_OUTPUT_CAPABILITY_SHA256,
                prompt_sha256=prompt_sha256,
                request_body_sha256=request_body_sha256,
                provider_policy_sha256=provider_policy_sha256,
                schema_sha256=schema_sha256,
                original_response_sha256=response_sha256,
                validated_response_sha256=response_sha256,
                mode=output_mode,
                request_shape_sha256=output_plan.request_shape_sha256,
                strict_protocol_sha256=output_plan.strict_protocol_sha256,
            ),
            "request_started_at": started_at.isoformat(),
            "request_ended_at": ended_at.isoformat(),
            "latency_ms": 125,
        },
        source_label=f"model-benchmark-portfolio:{target.model_id}:{case_id}",
    )
    record = UsageRecord(
        request_id=f"request-{target_slug}-{case_id}",
        role="model_benchmark",
        execution_evidence=execution_evidence,
        requested_model=target.model_id,
        returned_model=target.model_id,
        actual_model=target.model_id,
        provider="Synthetic",
        model_family=target.model_id,
        timestamp=started_at,
        prompt_tokens=100,
        completion_tokens=25,
        total_tokens=125,
        reported_cost_usd=0.01,
        accounted_cost_usd=0.01,
        routing=routing,
        prompt_sha256=prompt_sha256,
        response_sha256=response_sha256,
        validated_response_sha256=response_sha256,
        request_body_sha256=request_body_sha256,
        schema_sha256=schema_sha256,
        openrouter_generation_id=generation_id,
        configured_provider_endpoints=[endpoint],
        actual_provider_endpoint=endpoint,
        started_at=started_at,
        ended_at=ended_at,
        latency_ms=125,
        finish_reason="stop",
        retry_count=0,
        validation_status=ModelRequestValidationStatus.VALID,
        status="success",
        attempts=1,
    )
    return record.model_copy(
        update={"routing": synthetic_token_plan_routing(record, record.routing)}
    )


def _report(
    suite: ModelBenchmarkSuite,
    model_id: str,
    *,
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.MOCK,
) -> ModelBenchmarkReport:
    return asyncio.run(
        run_model_benchmark(
            corpus=suite,
            targets=[ModelBenchmarkTarget(model_id=model_id)],
            provider=_DeterministicProvider(
                suite=suite,
                execution_evidence=execution_evidence,
            ),
        )
    )


def _as_structural_real(report: ModelBenchmarkReport) -> ModelBenchmarkReport:
    payload = report.model_dump(mode="json")
    payload["execution_evidence"] = ExecutionEvidenceKind.REAL.value
    payload["results"][0]["execution_evidence"] = ExecutionEvidenceKind.REAL.value
    for case in payload["results"][0]["cases"]:
        record = UsageRecord.model_validate(case["usage_record"])
        assert record.openrouter_generation_id is not None
        assert record.actual_model is not None
        assert record.started_at is not None
        case["execution_evidence"] = ExecutionEvidenceKind.REAL.value
        case["usage_record"]["execution_evidence"] = ExecutionEvidenceKind.REAL.value
        case["usage_record"]["routing"]["certification_request"] = True
        case["usage_record"]["routing"]["canonical_model"] = record.requested_model
        case["usage_record"]["routing"]["selected_provider_name"] = "Synthetic"
        case["usage_record"]["routing"]["endpoint_snapshot_sha256"] = "1" * 64
        case["usage_record"]["routing"]["endpoint_pricing_sha256"] = "2" * 64
        case["usage_record"]["routing"]["catalog_identity_binding_sha256"] = canonical_sha256(
            {
                "canonical_slug": record.requested_model,
                "id": record.requested_model,
            }
        )
        case["usage_record"]["routing"]["catalog_snapshot_sha256"] = "3" * 64
        case["usage_record"]["routing"]["discovery_provenance_sha256"] = "4" * 64
        case["usage_record"]["routing"]["discovery_evidence_sha256"] = "5" * 64
        bound_record = bind_synthetic_usage_identity(
            UsageRecord.model_validate(case["usage_record"])
        )
        case["usage_record"] = bound_record.model_dump(mode="json")
        case["generation_evidence"] = validate_openrouter_generation_payload(
            {
                "data": {
                    "id": bound_record.openrouter_generation_id,
                    "model": bound_record.actual_model,
                    "provider_name": "Synthetic",
                    "finish_reason": "stop",
                    "native_finish_reason": None,
                    "tokens_prompt": bound_record.prompt_tokens,
                    "tokens_completion": bound_record.completion_tokens,
                    "native_tokens_prompt": bound_record.prompt_tokens,
                    "native_tokens_completion": bound_record.completion_tokens,
                    "native_tokens_reasoning": 0,
                    "native_tokens_cached": 0,
                    "total_cost": "0.01",
                    "usage": "0.01",
                    "cancelled": False,
                    "created_at": bound_record.started_at,
                    "request_id": bound_record.request_id,
                    "latency": "125",
                    "generation_time": None,
                }
            },
            requested_generation_id=bound_record.openrouter_generation_id,
            retrieved_at=NOW + timedelta(hours=2),
            execution_evidence=ExecutionEvidenceKind.REAL,
        ).model_dump(mode="json")
    payload["report_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "report_sha256"}
    )
    return ModelBenchmarkReport.model_validate(payload)


@dataclass(frozen=True)
class _Inputs:
    registry: CandidateRegistry
    suite: ModelBenchmarkSuite
    reports: tuple[ModelBenchmarkReport, ...]


@pytest.fixture
def inputs() -> _Inputs:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    return _Inputs(
        registry=_candidate_registry(),
        suite=suite,
        reports=tuple(_report(suite, model_id) for model_id in MODEL_IDS),
    )


def test_private_portfolio_round_trip_binds_exact_set_and_usage(
    tmp_path: Path,
    inputs: _Inputs,
) -> None:
    path = tmp_path / "portfolio"

    portfolio = write_model_benchmark_portfolio(
        path,
        candidate_registry=inputs.registry,
        corpus=inputs.suite,
        reports=tuple(reversed(inputs.reports)),
    )
    loaded, reports = load_model_benchmark_portfolio(
        path,
        candidate_registry=inputs.registry,
        corpus=inputs.suite,
    )

    assert loaded == portfolio
    assert reports == inputs.reports
    assert portfolio.candidate_model_ids == MODEL_IDS
    assert portfolio.candidate_registry_sha256 == inputs.registry.registry_sha256
    assert portfolio.discovery_run_manifest_sha256 == inputs.registry.discovery_run_sha256
    assert portfolio.corpus_sha256 == inputs.suite.corpus_sha256
    assert portfolio.ground_truth_sha256 == inputs.suite.ground_truth_sha256
    assert portfolio.execution_evidence is ExecutionEvidenceKind.MOCK
    assert portfolio.usage.report_count == 2
    assert portfolio.usage.usage_record_count == 32
    assert portfolio.usage.prompt_tokens == 3_200
    assert portfolio.usage.completion_tokens == 800
    assert portfolio.usage.total_tokens == 4_000
    assert portfolio.usage.reported_cost_usd == "0.32"
    assert portfolio.usage.accounted_cost_usd == "0.32"
    assert portfolio.usage.total_latency_ms == 4_000
    assert portfolio.usage.maximum_latency_ms == 125
    assert portfolio.started_at == NOW + timedelta(hours=1)
    assert portfolio.ended_at == NOW + timedelta(hours=1, seconds=115, milliseconds=125)
    assert stat.S_IMODE(path.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(item.stat().st_mode) == 0o600 for item in path.iterdir())
    for artifact in portfolio.report_artifacts:
        assert artifact.filename == (
            "model-report-" + hashlib.sha256(artifact.exact_model_id.encode()).hexdigest() + ".json"
        )
    serialized = b"".join(item.read_bytes() for item in path.iterdir())
    assert b"MODEL_BENCHMARK_CASE_JSON" not in serialized
    assert b'"source_excerpt"' not in serialized


def test_portfolio_preserves_real_mock_and_unverified_without_promotion(
    tmp_path: Path,
    inputs: _Inputs,
) -> None:
    real_reports = tuple(_as_structural_real(report) for report in inputs.reports)
    real = write_model_benchmark_portfolio(
        tmp_path / "real",
        candidate_registry=inputs.registry,
        corpus=inputs.suite,
        reports=real_reports,
    )
    unverified_reports = (
        inputs.reports[0],
        _report(
            inputs.suite,
            MODEL_IDS[1],
            execution_evidence=ExecutionEvidenceKind.UNVERIFIED,
        ),
    )
    unverified = write_model_benchmark_portfolio(
        tmp_path / "unverified",
        candidate_registry=inputs.registry,
        corpus=inputs.suite,
        reports=unverified_reports,
    )

    assert real.execution_evidence is ExecutionEvidenceKind.REAL
    assert unverified.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    loaded_real, _ = load_model_benchmark_portfolio(
        tmp_path / "real",
        candidate_registry=inputs.registry,
        corpus=inputs.suite,
    )
    loaded_unverified, _ = load_model_benchmark_portfolio(
        tmp_path / "unverified",
        candidate_registry=inputs.registry,
        corpus=inputs.suite,
    )
    assert loaded_real.execution_evidence is ExecutionEvidenceKind.REAL
    assert loaded_unverified.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    forged = unverified.model_dump(mode="json", exclude={"portfolio_sha256"})
    forged["execution_evidence"] = ExecutionEvidenceKind.MOCK.value
    forged["portfolio_sha256"] = canonical_sha256(forged)
    with pytest.raises(ValidationError, match="promotes or misstates"):
        ModelBenchmarkPortfolio.model_validate(forged)


def test_portfolio_persists_exact_all_failed_reports_without_runtime_usage(
    tmp_path: Path,
    inputs: _Inputs,
) -> None:
    reports = tuple(
        asyncio.run(
            run_model_benchmark(
                corpus=inputs.suite,
                targets=[ModelBenchmarkTarget(model_id=model_id)],
                provider=_UnavailableProvider(),
            )
        )
        for model_id in MODEL_IDS
    )
    diagnostics = tuple(
        CandidateBenchmarkDiagnostic(
            exact_model_id=model_id,
            approved_provider_endpoint=inputs.registry.candidates[index].approved_provider_endpoint,
            endpoint_snapshot_sha256=inputs.registry.candidates[index].endpoint_snapshot_sha256,
            report_sha256=report.report_sha256,
            execution_evidence=ExecutionEvidenceKind.UNVERIFIED,
            state=CandidateBenchmarkRunState.UNVERIFIED_FAILURE,
            failure_stage=CandidateBenchmarkFailureStage.AUTHENTICATION,
            reasoning_suppressed=False,
            corpus_cases=len(inputs.suite.cases),
            requests_observed=0,
            successful_cases=0,
            failed_cases=len(inputs.suite.cases),
            error_kinds=("ValueError",),
        )
        for index, (model_id, report) in enumerate(zip(MODEL_IDS, reports, strict=True))
    )

    portfolio = write_model_benchmark_portfolio(
        tmp_path / "all-failed",
        candidate_registry=inputs.registry,
        corpus=inputs.suite,
        reports=reports,
        diagnostics=diagnostics,
    )
    loaded, loaded_reports = load_model_benchmark_portfolio(
        tmp_path / "all-failed",
        candidate_registry=inputs.registry,
        corpus=inputs.suite,
    )

    assert loaded == portfolio
    assert loaded_reports == reports
    assert portfolio.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert portfolio.diagnostics == diagnostics
    assert portfolio.usage.report_count == len(MODEL_IDS)
    assert portfolio.usage.usage_record_count == 0
    assert portfolio.usage.prompt_tokens == 0
    assert portfolio.usage.completion_tokens == 0
    assert portfolio.usage.total_tokens == 0
    assert portfolio.usage.reported_cost_usd == "0"
    assert portfolio.usage.accounted_cost_usd == "0"
    assert portfolio.started_at is None
    assert portfolio.ended_at is None
    assert sum(len(report.results[0].cases) for report in reports) == (
        len(MODEL_IDS) * len(inputs.suite.cases)
    )
    assert all(
        case.error_kind == "ValueError"
        and case.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
        and case.usage_record is None
        for report in reports
        for case in report.results[0].cases
    )


def test_portfolio_rejects_diagnostics_that_omit_retained_usage(
    tmp_path: Path,
    inputs: _Inputs,
) -> None:
    report = inputs.reports[0]
    diagnostics = (
        CandidateBenchmarkDiagnostic(
            exact_model_id=MODEL_IDS[0],
            approved_provider_endpoint=inputs.registry.candidates[0].approved_provider_endpoint,
            endpoint_snapshot_sha256=inputs.registry.candidates[0].endpoint_snapshot_sha256,
            report_sha256=report.report_sha256,
            execution_evidence=report.execution_evidence,
            state=CandidateBenchmarkRunState.COMPLETE,
            reasoning_suppressed=False,
            corpus_cases=len(inputs.suite.cases),
            requests_observed=0,
            successful_cases=len(inputs.suite.cases),
            failed_cases=0,
            error_kinds=(),
        ),
    )

    with pytest.raises(ValueError, match="differs from its exact report evidence"):
        write_model_benchmark_portfolio(
            tmp_path / "mismatched-diagnostics",
            candidate_registry=_candidate_registry(model_ids=(MODEL_IDS[0],)),
            corpus=inputs.suite,
            reports=(report,),
            diagnostics=diagnostics,
        )


def test_writer_rejects_empty_missing_duplicate_extra_and_wrong_model_sets(
    tmp_path: Path,
    inputs: _Inputs,
) -> None:
    extra = _report(inputs.suite, "author-c/model-c")
    invalid_sets = (
        (),
        (inputs.reports[0],),
        (inputs.reports[0], inputs.reports[0]),
        (*inputs.reports, extra),
        (inputs.reports[0], extra),
    )

    for index, reports in enumerate(invalid_sets):
        path = tmp_path / f"invalid-{index}"
        with pytest.raises(ValueError):
            write_model_benchmark_portfolio(
                path,
                candidate_registry=inputs.registry,
                corpus=inputs.suite,
                reports=reports,
            )
        assert not path.exists()


def test_writer_rejects_mixed_corpus_and_reports_that_predate_registry(
    tmp_path: Path,
    inputs: _Inputs,
) -> None:
    drifted = inputs.reports[0].model_dump(mode="json", exclude={"report_sha256"})
    drifted["corpus_name"] = "different corpus"
    drifted["corpus_sha256"] = "a" * 64
    drifted["ground_truth_sha256"] = "b" * 64
    drifted["report_sha256"] = canonical_sha256(drifted)
    mixed = ModelBenchmarkReport.model_validate(drifted)

    with pytest.raises(ValueError, match="not bound"):
        write_model_benchmark_portfolio(
            tmp_path / "mixed",
            candidate_registry=inputs.registry,
            corpus=inputs.suite,
            reports=(mixed, inputs.reports[1]),
        )
    with pytest.raises(ValueError, match="predates"):
        write_model_benchmark_portfolio(
            tmp_path / "predates",
            candidate_registry=_candidate_registry(
                created_at=NOW + timedelta(hours=3),
            ),
            corpus=inputs.suite,
            reports=inputs.reports,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_manifest",
        "missing_report",
        "extra",
        "tampered",
        "symlink",
        "hardlink",
        "directory_mode",
        "file_mode",
    ],
)
def test_loader_rejects_incomplete_stale_linked_shared_and_tampered_directories(
    tmp_path: Path,
    inputs: _Inputs,
    mutation: str,
) -> None:
    path = tmp_path / "portfolio"
    portfolio = write_model_benchmark_portfolio(
        path,
        candidate_registry=inputs.registry,
        corpus=inputs.suite,
        reports=inputs.reports,
    )
    manifest = path / "model-benchmark-portfolio.json"
    report = path / portfolio.report_artifacts[0].filename

    if mutation == "missing_manifest":
        manifest.unlink()
    elif mutation == "missing_report":
        report.unlink()
    elif mutation == "extra":
        extra = path / "stale-report.json"
        extra.write_text("{}\n", encoding="utf-8")
        extra.chmod(0o600)
    elif mutation == "tampered":
        report.write_bytes(report.read_bytes() + b" ")
    elif mutation == "symlink":
        report.unlink()
        try:
            report.symlink_to(manifest)
        except OSError:
            pytest.skip("symlinks unavailable")
    elif mutation == "hardlink":
        try:
            os.link(report, tmp_path / "shared-report.json")
        except OSError:
            pytest.skip("hardlinks unavailable")
    elif mutation == "directory_mode":
        path.chmod(0o755)
    else:
        report.chmod(0o644)

    with pytest.raises(ValueError):
        load_model_benchmark_portfolio(
            path,
            candidate_registry=inputs.registry,
            corpus=inputs.suite,
        )


def test_loader_recomputes_aggregates_and_external_bindings(
    tmp_path: Path,
    inputs: _Inputs,
) -> None:
    path = tmp_path / "portfolio"
    write_model_benchmark_portfolio(
        path,
        candidate_registry=inputs.registry,
        corpus=inputs.suite,
        reports=inputs.reports,
    )
    manifest_path = path / "model-benchmark-portfolio.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["usage"]["prompt_tokens"] += 1
    payload["portfolio_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "portfolio_sha256"}
    )
    manifest_path.write_text(stable_json(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="aggregates"):
        load_model_benchmark_portfolio(
            path,
            candidate_registry=inputs.registry,
            corpus=inputs.suite,
        )

    second_path = tmp_path / "portfolio-second"
    write_model_benchmark_portfolio(
        second_path,
        candidate_registry=inputs.registry,
        corpus=inputs.suite,
        reports=inputs.reports,
    )
    with pytest.raises(ValueError, match="supplied registry"):
        load_model_benchmark_portfolio(
            second_path,
            candidate_registry=_candidate_registry(discovery_hash=_sha("other-run")),
            corpus=inputs.suite,
        )


def test_writer_rejects_cross_report_request_replay(
    tmp_path: Path,
    inputs: _Inputs,
) -> None:
    first_request_id = inputs.reports[0].results[0].cases[0].usage_record
    assert first_request_id is not None
    replayed = inputs.reports[1].model_dump(mode="json", exclude={"report_sha256"})
    replayed_usage = UsageRecord.model_validate(replayed["results"][0]["cases"][0]["usage_record"])
    replayed_routing = dict(replayed_usage.routing)
    for field in (
        "request_token_plan",
        "request_token_plan_sha256",
        "atomic_token_reservations",
        "atomic_token_reservation_sha256s",
        "atomic_token_reservation",
        "atomic_token_reservation_sha256",
    ):
        replayed_routing.pop(field, None)
    replayed_routing["canonical_model"] = replayed_usage.requested_model
    replayed_routing["selected_provider_name"] = "Synthetic"
    replayed_usage = bind_synthetic_usage_identity(
        replayed_usage.model_copy(
            update={
                "request_id": first_request_id.request_id,
                "routing": replayed_routing,
            }
        )
    )
    replayed["results"][0]["cases"][0]["usage_record"] = replayed_usage.model_dump(mode="json")
    replayed["report_sha256"] = canonical_sha256(replayed)

    with pytest.raises(ValueError, match="replays a request ID"):
        write_model_benchmark_portfolio(
            tmp_path / "replay",
            candidate_registry=inputs.registry,
            corpus=inputs.suite,
            reports=(
                inputs.reports[0],
                ModelBenchmarkReport.model_validate(replayed),
            ),
        )


def test_writer_rejects_naive_usage_timestamps(
    tmp_path: Path,
    inputs: _Inputs,
) -> None:
    naive = inputs.reports[0].model_dump(mode="json", exclude={"report_sha256"})
    usage = naive["results"][0]["cases"][0]["usage_record"]
    usage["timestamp"] = "2026-07-27T13:00:00"
    usage["started_at"] = "2026-07-27T13:00:00"
    usage["ended_at"] = "2026-07-27T13:00:00.125000"
    usage["routing"]["request_started_at"] = "2026-07-27T13:00:00"
    usage["routing"]["request_ended_at"] = "2026-07-27T13:00:00.125000"
    naive["report_sha256"] = canonical_sha256(naive)

    with pytest.raises(ValueError, match="timezone-aware"):
        write_model_benchmark_portfolio(
            tmp_path / "naive",
            candidate_registry=inputs.registry,
            corpus=inputs.suite,
            reports=(
                ModelBenchmarkReport.model_validate(naive),
                inputs.reports[1],
            ),
        )


def test_writer_requires_a_fresh_destination(tmp_path: Path, inputs: _Inputs) -> None:
    path = tmp_path / "portfolio"
    write_model_benchmark_portfolio(
        path,
        candidate_registry=inputs.registry,
        corpus=inputs.suite,
        reports=inputs.reports,
    )

    with pytest.raises(ValueError, match="fresh"):
        write_model_benchmark_portfolio(
            path,
            candidate_registry=inputs.registry,
            corpus=inputs.suite,
            reports=inputs.reports,
        )
