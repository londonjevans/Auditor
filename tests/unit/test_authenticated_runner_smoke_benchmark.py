from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

import mmaudit.benchmark.cross_lineage_adjudication as adjudication
import mmaudit.benchmark.models as benchmark_models
from mmaudit.benchmark.cross_lineage_adjudication import (
    CrossLineageAdjudicationError,
    CrossLineageAdjudicationRunKind,
    prepare_noncrediting_cross_lineage_adjudication_smoke,
)
from mmaudit.benchmark.models import (
    ModelBenchmarkCase,
    ModelBenchmarkCaseResult,
    ModelBenchmarkGroundTruthCase,
    ModelBenchmarkResponse,
    ModelBenchmarkSmokeRequestDescriptor,
    ModelBenchmarkSuite,
    ModelBenchmarkTarget,
    NoncreditingModelBenchmarkSmokeReport,
    authenticated_runner_model_benchmark_request_descriptors,
    authenticated_runner_smoke_model_benchmark_request_descriptor,
    execute_noncrediting_model_benchmark_smoke,
    load_model_benchmark_corpus,
    validate_authenticated_runner_smoke_model_benchmark_cost_preview,
    verify_noncrediting_model_benchmark_smoke_report,
)
from mmaudit.models.generation_evidence import OpenRouterGenerationEvidence
from mmaudit.models.identity import OpenRouterIdentityDiagnosticCode
from mmaudit.models.openrouter import (
    OpenRouterClient,
    OpenRouterStructuredRequestCostPreview,
    StructuredCompletion,
    strict_json_schema,
    structured_output_prompt_sha256,
)
from mmaudit.models.public_lineage_authority import resolve_verified_public_model_lineage
from mmaudit.models.qualification import CandidateModel
from mmaudit.models.schemas import UsageRecord
from mmaudit.models.usage import (
    MAX_AUTHENTICATED_RUNNER_SMOKE_RUN_INDEX,
    UsageLedger,
    _attest_owned_real_usage_record,
)
from mmaudit.orchestration.manifest import canonical_sha256
from tests.identity_fixtures import bind_synthetic_usage_identity, rebind_synthetic_token_plan
from tests.unit.test_authenticated_runner_cost_plan import _preview, _replace_preview
from tests.unit.test_model_benchmark_portfolio import (
    _as_structural_real,
    _candidate_registry,
    _report,
)

ROOT = Path(__file__).parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
SELECTION_SHA256 = "a" * 64
CANDIDATE_ID = "deepseek/deepseek-v3.2-exp"
JUDGE_ID = "google/gemma-4-26b-a4b-it"
SAME_ROOT_JUDGE_ID = "deepcogito/cogito-v2.1-671b"


def _selection(
    suite: ModelBenchmarkSuite,
) -> tuple[ModelBenchmarkCase, ModelBenchmarkGroundTruthCase]:
    case = suite.cases[0]
    return case, suite.ground_truth_case(case.case_id)


def _smoke_report(
    suite: ModelBenchmarkSuite,
    *,
    smoke_run_index: int = 1,
    run_kind: str = "PRIMARY",
    model_id: str = CANDIDATE_ID,
) -> NoncreditingModelBenchmarkSmokeReport:
    source = _as_structural_real(_report(suite, model_id))
    case, truth = _selection(suite)
    source_result = source.results[0].cases[0]
    assert source_result.usage_record is not None
    assert source_result.generation_evidence is not None
    descriptor = authenticated_runner_smoke_model_benchmark_request_descriptor(
        smoke_run_index=smoke_run_index,
        run_kind=run_kind,  # type: ignore[arg-type]
        selection_sha256=SELECTION_SHA256,
        case=case,
        target=source.results[0].target,
    )
    usage = bind_synthetic_usage_identity(
        rebind_synthetic_token_plan(
            source_result.usage_record.model_copy(
                update={"request_id": descriptor.logical_request_id},
            )
        )
    )
    usage = UsageRecord.model_validate(usage.model_dump(mode="json"))
    generation_payload = source_result.generation_evidence.model_dump(mode="json")
    generation_payload["request_id"] = descriptor.logical_request_id
    generation_payload["evidence_sha256"] = canonical_sha256(
        {key: value for key, value in generation_payload.items() if key != "evidence_sha256"}
    )
    generation = OpenRouterGenerationEvidence.model_validate(generation_payload)
    result_payload = source_result.model_dump(mode="json")
    result_payload["usage_record"] = usage.model_dump(mode="json")
    result_payload["generation_evidence"] = generation.model_dump(mode="json")
    result = ModelBenchmarkCaseResult.model_validate(result_payload)
    values = {
        "artifact_kind": "noncrediting_model_benchmark_smoke_report",
        "schema_version": "1.1",
        "disposition": "NONCREDITING_SMOKE",
        "smoke_run_index": smoke_run_index,
        "run_kind": run_kind,
        "selection_sha256": SELECTION_SHA256,
        "corpus_name": suite.name,
        "corpus_sha256": suite.corpus_sha256,
        "ground_truth_sha256": suite.ground_truth_sha256,
        "selected_case_sha256": canonical_sha256(case.model_dump(mode="json")),
        "selected_ground_truth_sha256": canonical_sha256(truth.model_dump(mode="json")),
        "target": source.results[0].target.model_dump(mode="json"),
        "result": result.model_dump(mode="json"),
        "execution_evidence": "real",
        **benchmark_models._false_smoke_authority_payload(),
    }
    return NoncreditingModelBenchmarkSmokeReport.model_validate(
        {**values, "report_sha256": canonical_sha256(values)}
    )


def _judge(model_id: str) -> CandidateModel:
    base = _candidate_registry((model_id,)).candidates[0]
    payload = base.model_dump(mode="json")
    payload.update(
        {
            "approved_provider_endpoint": "provider-judge",
            "approved_provider_name": "Synthetic Judge",
            "discovery_evidence_sha256": "5" * 64,
        }
    )
    return CandidateModel.model_validate(payload)


def _smoke_preview(
    descriptor: ModelBenchmarkSmokeRequestDescriptor,
) -> OpenRouterStructuredRequestCostPreview:
    base = _preview(0)
    return _replace_preview(
        base,
        logical_request_id=descriptor.logical_request_id,
        exact_model_id=descriptor.exact_model_id,
        prompt_sha256=structured_output_prompt_sha256(
            mode=base.structured_output_mode,
            system_prompt=descriptor.system_prompt,
            user_prompt=descriptor.user_prompt,
            response_model=descriptor.response_model,
            schema_name=descriptor.schema_name,
        ),
        user_prompt_sha256=hashlib.sha256(descriptor.user_prompt.encode("utf-8")).hexdigest(),
        response_schema_sha256=canonical_sha256(strict_json_schema(descriptor.response_model)),
    )


def test_smoke_descriptor_uses_disjoint_bounded_namespace_without_relaxing_full_inventory() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    case, _truth = _selection(suite)
    target = ModelBenchmarkTarget(model_id="fixture/model-v1")

    primary = authenticated_runner_smoke_model_benchmark_request_descriptor(
        smoke_run_index=1,
        run_kind="PRIMARY",
        selection_sha256=SELECTION_SHA256,
        case=case,
        target=target,
    )
    replay = authenticated_runner_smoke_model_benchmark_request_descriptor(
        smoke_run_index=1,
        run_kind="REPLAY",
        selection_sha256=SELECTION_SHA256,
        case=case,
        target=target,
    )
    full = authenticated_runner_model_benchmark_request_descriptors(
        run_kind="PRIMARY",
        suite=suite,
        target=target,
    )

    assert primary.logical_request_id == (
        f"authrunner.smoke.r1.candidate.primary:{SELECTION_SHA256}"
    )
    assert replay.logical_request_id == (f"authrunner.smoke.r1.candidate.replay:{SELECTION_SHA256}")
    assert len(primary.logical_request_id) <= 128
    assert len(replay.logical_request_id) <= 128
    assert len(full) == 24
    assert all(item.logical_request_id.startswith("authrunner.candidate.primary:") for item in full)
    assert {primary.logical_request_id, replay.logical_request_id}.isdisjoint(
        item.logical_request_id for item in full
    )


def test_smoke_run_index_is_deterministic_within_a_run_and_distinct_across_runs() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    case, _truth = _selection(suite)
    target = ModelBenchmarkTarget(model_id="fixture/model-v1")

    def request_id(index: int) -> str:
        return authenticated_runner_smoke_model_benchmark_request_descriptor(
            smoke_run_index=index,
            run_kind="PRIMARY",
            selection_sha256=SELECTION_SHA256,
            case=case,
            target=target,
        ).logical_request_id

    assert request_id(1) == request_id(1)
    assert request_id(1) != request_id(2)
    assert request_id(2) == f"authrunner.smoke.r2.candidate.primary:{SELECTION_SHA256}"
    maximum_request_id = request_id(MAX_AUTHENTICATED_RUNNER_SMOKE_RUN_INDEX)
    assert maximum_request_id.startswith("authrunner.smoke.r999999999.candidate.primary:")
    assert len(f"{maximum_request_id}:attempt:2") <= 128

    candidate_r1 = {
        request_id(1),
        authenticated_runner_smoke_model_benchmark_request_descriptor(
            smoke_run_index=1,
            run_kind="REPLAY",
            selection_sha256=SELECTION_SHA256,
            case=case,
            target=target,
        ).logical_request_id,
    }
    candidate_r2 = {
        request_id(2),
        authenticated_runner_smoke_model_benchmark_request_descriptor(
            smoke_run_index=2,
            run_kind="REPLAY",
            selection_sha256=SELECTION_SHA256,
            case=case,
            target=target,
        ).logical_request_id,
    }
    judge_requests = (
        SimpleNamespace(
            run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
            request_sha256="a" * 64,
        ),
        SimpleNamespace(
            run_kind=CrossLineageAdjudicationRunKind.REPLAY,
            request_sha256="b" * 64,
        ),
    )
    judge_r1 = {
        adjudication._cross_lineage_adjudication_smoke_logical_request_id(item, 1)
        for item in judge_requests
    }
    judge_r2 = {
        adjudication._cross_lineage_adjudication_smoke_logical_request_id(item, 2)
        for item in judge_requests
    }
    release = {
        f"authrunner.candidate.primary:{case.case_id}",
        f"authrunner.candidate.replay:{case.case_id}",
        *(
            adjudication._cross_lineage_adjudication_logical_request_id(item)
            for item in judge_requests
        ),
    }
    assert len(candidate_r2 | judge_r2) == 4
    assert (candidate_r2 | judge_r2).isdisjoint(candidate_r1 | judge_r1 | release)


@pytest.mark.parametrize(
    "value",
    (False, True, 0, -1, MAX_AUTHENTICATED_RUNNER_SMOKE_RUN_INDEX + 1, 1.0, "1"),
)
def test_smoke_descriptor_rejects_non_strict_or_out_of_range_run_index(value: object) -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    case, _truth = _selection(suite)
    with pytest.raises(ValueError, match="smoke run index"):
        authenticated_runner_smoke_model_benchmark_request_descriptor(
            smoke_run_index=value,  # type: ignore[arg-type]
            run_kind="PRIMARY",
            selection_sha256=SELECTION_SHA256,
            case=case,
            target=ModelBenchmarkTarget(model_id="fixture/model-v1"),
        )


@pytest.mark.parametrize(
    "value",
    (None, False, True, 0, -1, MAX_AUTHENTICATED_RUNNER_SMOKE_RUN_INDEX + 1, 1.0, "2"),
)
def test_smoke_judge_request_id_rejects_non_strict_or_out_of_range_run_index(
    value: object,
) -> None:
    request = SimpleNamespace(
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
        request_sha256="a" * 64,
    )
    with pytest.raises(CrossLineageAdjudicationError, match="smoke run index is invalid"):
        adjudication._cross_lineage_adjudication_smoke_logical_request_id(
            request,  # type: ignore[arg-type]
            value,  # type: ignore[arg-type]
        )


def test_release_judge_request_id_rejects_a_smoke_run_index() -> None:
    request = SimpleNamespace(
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
        request_sha256="a" * 64,
    )
    with pytest.raises(CrossLineageAdjudicationError, match="cannot carry a smoke run index"):
        adjudication._cross_lineage_adjudication_logical_request_id(
            request,  # type: ignore[arg-type]
            2,
        )


def test_smoke_cost_preview_binds_request_and_preserves_reasoning_plan() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    case, _truth = _selection(suite)
    target = ModelBenchmarkTarget(model_id="fixture/model-v1")
    descriptor = authenticated_runner_smoke_model_benchmark_request_descriptor(
        smoke_run_index=1,
        run_kind="PRIMARY",
        selection_sha256=SELECTION_SHA256,
        case=case,
        target=target,
    )
    base = _preview(0)
    preview = _smoke_preview(descriptor)

    validated = validate_authenticated_runner_smoke_model_benchmark_cost_preview(
        descriptor=descriptor,
        expected_request_cost_preview=preview,
    )
    assert validated == preview
    assert validated.reasoning_profile_sha256 == base.reasoning_profile_sha256
    assert validated.reasoning_plan_sha256 == base.reasoning_plan_sha256
    assert validated.reasoning_qualification_sha256 is None
    with pytest.raises(ValueError, match="exact request"):
        validate_authenticated_runner_smoke_model_benchmark_cost_preview(
            descriptor=descriptor,
            expected_request_cost_preview=_replace_preview(
                preview,
                logical_request_id=f"{descriptor.logical_request_id}:drift",
            ),
        )


def test_smoke_execute_uses_one_cost_bound_request_and_refetches_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    case, truth = _selection(suite)
    target = ModelBenchmarkTarget(model_id="fixture/model-v1")
    source = _smoke_report(suite, model_id=target.model_id)
    assert source.result.normalized_response is not None
    assert source.result.usage_record is not None
    assert source.result.generation_evidence is not None
    usage = _attest_owned_real_usage_record(source.result.usage_record)
    response = source.result.normalized_response
    generation = source.result.generation_evidence
    descriptor = authenticated_runner_smoke_model_benchmark_request_descriptor(
        smoke_run_index=1,
        run_kind="PRIMARY",
        selection_sha256=SELECTION_SHA256,
        case=case,
        target=target,
    )
    preview = _smoke_preview(descriptor)
    generation_fetches: list[str] = []

    async def complete(
        client: OpenRouterClient,
        **kwargs: Any,
    ) -> StructuredCompletion[ModelBenchmarkResponse]:
        assert kwargs["logical_request_id"] == descriptor.logical_request_id
        assert kwargs["expected_request_cost_preview"] == preview
        client.usage.add(usage)
        return StructuredCompletion(value=response, usage_record=usage)

    async def get_generation(
        _client: OpenRouterClient,
        generation_id: str,
    ) -> OpenRouterGenerationEvidence:
        generation_fetches.append(generation_id)
        return generation

    monkeypatch.setattr(OpenRouterClient, "complete_with_evidence", complete)
    monkeypatch.setattr(OpenRouterClient, "get_generation_evidence", get_generation)
    client = object.__new__(OpenRouterClient)
    object.__setattr__(client, "usage", UsageLedger())

    report = asyncio.run(
        execute_noncrediting_model_benchmark_smoke(
            smoke_run_index=1,
            suite=suite,
            selected_case=case,
            selected_ground_truth=truth,
            selection_sha256=SELECTION_SHA256,
            target=target,
            client=client,
            run_kind="PRIMARY",
            expected_request_cost_preview=preview,
        )
    )

    assert report.disposition == "NONCREDITING_SMOKE"
    assert report.result.case_id == case.case_id
    assert client.usage.records == [usage]
    assert generation_fetches == [generation.generation_id]
    assert report.benchmark_credit_authorized is False
    assert report.generation_verification_authorized is False


@pytest.mark.parametrize(
    ("usage_error", "identity_diagnostics", "case_id_mismatch", "expected_reasons"),
    (
        (
            "UsageValidationError",
            (),
            False,
            "usage_error=UsageValidationError",
        ),
        (
            None,
            (),
            True,
            "case_id_mismatch=true",
        ),
        (
            "UsageResponseBindingError",
            (),
            True,
            "usage_error=UsageResponseBindingError, case_id_mismatch=true",
        ),
        (
            "UsageValidationError",
            (
                OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_INVALID,
                OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_MISSING,
            ),
            False,
            "usage_error=UsageValidationError, "
            "identity_diagnostics=GENERATION_METADATA_INVALID|GENERATION_METADATA_MISSING",
        ),
    ),
)
def test_smoke_execute_preserves_bounded_usage_and_case_failure_reasons(
    monkeypatch: pytest.MonkeyPatch,
    usage_error: str | None,
    identity_diagnostics: tuple[OpenRouterIdentityDiagnosticCode, ...],
    case_id_mismatch: bool,
    expected_reasons: str,
) -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    case, truth = _selection(suite)
    target = ModelBenchmarkTarget(model_id="fixture/model-v1")
    source = _smoke_report(suite, model_id=target.model_id)
    assert source.result.normalized_response is not None
    assert source.result.usage_record is not None
    usage = _attest_owned_real_usage_record(source.result.usage_record)
    response = source.result.normalized_response
    if case_id_mismatch:
        response = response.model_copy(update={"case_id": suite.cases[1].case_id})
    descriptor = authenticated_runner_smoke_model_benchmark_request_descriptor(
        smoke_run_index=1,
        run_kind="PRIMARY",
        selection_sha256=SELECTION_SHA256,
        case=case,
        target=target,
    )
    preview = _smoke_preview(descriptor)

    async def complete(
        client: OpenRouterClient,
        **_kwargs: Any,
    ) -> StructuredCompletion[ModelBenchmarkResponse]:
        client.usage.add(usage)
        return StructuredCompletion(value=response, usage_record=usage)

    async def unexpected_generation_fetch(
        _client: OpenRouterClient,
        _generation_id: str,
    ) -> OpenRouterGenerationEvidence:
        raise AssertionError("generation retrieval must follow smoke completion validation")

    monkeypatch.setattr(OpenRouterClient, "complete_with_evidence", complete)
    monkeypatch.setattr(OpenRouterClient, "get_generation_evidence", unexpected_generation_fetch)
    monkeypatch.setattr(
        benchmark_models,
        "_successful_usage_error",
        lambda *_args, **_kwargs: usage_error,
    )
    monkeypatch.setattr(
        benchmark_models,
        "_successful_usage_identity_diagnostics",
        lambda *_args, **_kwargs: identity_diagnostics,
    )
    client = object.__new__(OpenRouterClient)
    object.__setattr__(client, "usage", UsageLedger())

    with pytest.raises(ValueError) as exc_info:
        asyncio.run(
            execute_noncrediting_model_benchmark_smoke(
                smoke_run_index=1,
                suite=suite,
                selected_case=case,
                selected_ground_truth=truth,
                selection_sha256=SELECTION_SHA256,
                target=target,
                client=client,
                run_kind="PRIMARY",
                expected_request_cost_preview=preview,
            )
        )

    assert str(exc_info.value) == (
        "model benchmark smoke completion is not exact successful REAL evidence "
        f"({expected_reasons})"
    )
    assert client.usage.records == [usage]


def test_smoke_report_replays_one_case_and_every_authority_field_is_false() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    case, truth = _selection(suite)
    report = _smoke_report(suite)

    verify_noncrediting_model_benchmark_smoke_report(
        report,
        suite=suite,
        selected_case=case,
        selected_ground_truth=truth,
        selection_sha256=SELECTION_SHA256,
    )
    assert report.disposition == "NONCREDITING_SMOKE"
    assert len(report.result.dimensions) < 17
    assert all(
        getattr(report, field) is False
        for field in benchmark_models._false_smoke_authority_payload()
    )

    payload = report.model_dump(mode="json")
    payload["benchmark_credit_authorized"] = True
    payload["report_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "report_sha256"}
    )
    with pytest.raises(ValidationError, match="grant no authority or credit"):
        NoncreditingModelBenchmarkSmokeReport.model_validate(payload)
    with pytest.raises(ValueError, match="selection"):
        verify_noncrediting_model_benchmark_smoke_report(
            report,
            suite=suite,
            selected_case=case,
            selected_ground_truth=truth,
            selection_sha256="b" * 64,
        )


def test_smoke_prepare_emits_one_existing_nonauthorizing_request_and_rejects_same_root() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    case, truth = _selection(suite)
    report = _smoke_report(suite)
    lineage = resolve_verified_public_model_lineage()

    prepared = prepare_noncrediting_cross_lineage_adjudication_smoke(
        public_lineage_capability=lineage,
        suite=suite,
        selected_case=case,
        selected_ground_truth=truth,
        selection_sha256=SELECTION_SHA256,
        candidate_report=report,
        judge=_judge(JUDGE_ID),
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
    )

    assert prepared.case_ids == (case.case_id,)
    assert len(prepared.requests) == 1
    assert prepared.candidate_report_sha256 == report.report_sha256
    assert prepared.requests[0].candidate_report_sha256 == report.report_sha256
    smoke_request_id = adjudication._cross_lineage_adjudication_smoke_logical_request_id(
        prepared.requests[0], 1
    )
    assert smoke_request_id == (
        f"authrunner.smoke.r1.judge.primary:{prepared.requests[0].request_sha256}"
    )
    assert len(smoke_request_id) <= 128
    assert smoke_request_id != adjudication._cross_lineage_adjudication_logical_request_id(
        prepared.requests[0]
    )
    assert prepared.serialized_authority is False
    assert prepared.adjudication_credit_authorized is False
    with pytest.raises(CrossLineageAdjudicationError, match="distinct roots"):
        prepare_noncrediting_cross_lineage_adjudication_smoke(
            public_lineage_capability=lineage,
            suite=suite,
            selected_case=case,
            selected_ground_truth=truth,
            selection_sha256=SELECTION_SHA256,
            candidate_report=report,
            judge=_judge(SAME_ROOT_JUDGE_ID),
            run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
        )
