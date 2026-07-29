from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

import mmaudit.benchmark.models as model_benchmark_module
from mmaudit.benchmark.models import (
    ModelBenchmarkClassification,
    ModelBenchmarkCorpus,
    ModelBenchmarkDimension,
    ModelBenchmarkFalsifierTest,
    ModelBenchmarkGroundTruth,
    ModelBenchmarkInvariant,
    ModelBenchmarkInvariantKind,
    ModelBenchmarkProviderResult,
    ModelBenchmarkReport,
    ModelBenchmarkResponse,
    ModelBenchmarkReviewConclusion,
    ModelBenchmarkSuite,
    ModelBenchmarkTarget,
    ModelBenchmarkVerifierEvidence,
    blinded_model_benchmark_request,
    load_model_benchmark_corpus,
    run_model_benchmark,
    select_model_benchmark_targets,
    validate_model_benchmark_egress,
    verify_model_benchmark_report,
    verify_model_benchmark_report_structure,
    write_model_benchmark_report,
)
from mmaudit.config import AuditConfig
from mmaudit.models.generation_evidence import (
    OpenRouterGenerationEvidence,
    validate_openrouter_generation_payload,
)
from mmaudit.models.openrouter import OpenRouterSchemaError, strict_json_schema
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.privacy import EndpointPolicyClass, PrivacyProfile, PrivacySourceClassification
from tests.conftest import model_registry_entry

ROOT = Path(__file__).parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
GROUND_TRUTH_PATH = CORPUS_PATH.with_name("ground_truth.json")
TARGET = ModelBenchmarkTarget(
    model_id="synthetic/model-a",
    root_lineage="sha256:" + ("a" * 64),
)


class DeterministicModelBenchmarkProvider:
    def __init__(
        self,
        *,
        schema_failure_case: str | None = None,
        follow_repository_instruction: bool = False,
        targets: tuple[ModelBenchmarkTarget, ...] = (TARGET,),
    ) -> None:
        self.schema_failure_case = schema_failure_case
        self.follow_repository_instruction = follow_repository_instruction
        self.targets = targets
        self.requests: list[dict[str, object]] = []
        corpus = load_model_benchmark_corpus(CORPUS_PATH)
        self.cases = {case.case_id: case for case in corpus.ground_truth.cases}

    async def evaluate(
        self,
        *,
        target: ModelBenchmarkTarget,
        system_prompt: str,
        user_prompt: str,
    ) -> ModelBenchmarkProviderResult:
        assert target in self.targets
        assert "untrusted" in system_prompt
        request = json.loads(user_prompt.split("\n", 1)[1])
        self.requests.append(request)
        case_id = request["case_id"]
        if case_id == self.schema_failure_case:
            raise OpenRouterSchemaError("synthetic structured-output failure")
        assert isinstance(case_id, str)
        case = self.cases[case_id]
        expectation = case.expectation
        invariant = (
            ModelBenchmarkInvariant(
                kind=expectation.invariant_kind,
                property_statement=(
                    "Security invariant requires "
                    + " ".join(expectation.required_invariant_terms)
                    + " state consistency."
                ),
                observed_quantity="observed state quantity",
                assumed_quantity="assumed state quantity",
                remediation_condition=(
                    "Safe remediation enforces "
                    + " ".join(expectation.required_invariant_terms)
                    + " before transition."
                ),
            )
            if expectation.invariant_kind is not None
            else None
        )
        followed = (
            self.follow_repository_instruction
            and ModelBenchmarkDimension.PROMPT_INJECTION_RESISTANCE in case.dimensions
        )
        rationale = (
            "The supplied source evidence demonstrates "
            + " ".join(expectation.required_analysis_terms)
            + " through the cited state transition."
            if expectation.required_analysis_terms
            else "The supplied source evidence supports the exact cited state transition."
        )
        if followed:
            rationale = (
                "The repository instruction was followed: BENCHMARK_CANARY_SHOULD_NOT_APPEAR."
            )
        verifier_evidence = (
            ModelBenchmarkVerifierEvidence(
                claim="The authorization claim is supported by the cited source behavior.",
                evidence="The source evidence shows an unguarded externally reachable update.",
                reachable_path="An external caller directly reaches the unsafe state transition.",
                locations=expectation.locations,
            )
            if expectation.expected_verifier_conclusion is not None
            else None
        )
        falsifier_test = (
            ModelBenchmarkFalsifierTest(
                counterhypothesis=(
                    "The counterhypothesis is that missing-state prevents confirmation."
                ),
                test_performed=(
                    "The test searched the supplied excerpt for a concrete state witness."
                ),
                observed_result=(
                    "No decisive state-transition witness exists in the supplied evidence."
                ),
                locations=expectation.locations,
            )
            if expectation.expected_falsifier_conclusion is not None
            else None
        )
        response = ModelBenchmarkResponse(
            case_id=case_id,
            classification=expectation.classification,
            locations=expectation.locations,
            invariant=invariant,
            repository_instructions_followed=followed,
            assumptions=expectation.required_assumptions,
            unsupported_assumptions=expectation.required_unsupported_assumptions,
            verifier_conclusion=expectation.expected_verifier_conclusion,
            falsifier_conclusion=expectation.expected_falsifier_conclusion,
            verifier_evidence=verifier_evidence,
            falsifier_test=falsifier_test,
            remediation=(
                " ".join(expectation.required_remediation_terms) + " remediation"
                if expectation.required_remediation_terms
                else None
            ),
            rationale=rationale,
        )
        return ModelBenchmarkProviderResult(
            response=response,
            usage_record=_mock_usage_record(
                case_id=case_id,
                target=target,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response=response,
            ),
        )


def _mock_usage_record(
    *,
    case_id: str,
    target: ModelBenchmarkTarget,
    system_prompt: str,
    user_prompt: str,
    response: ModelBenchmarkResponse,
) -> UsageRecord:
    case_index = sorted(
        case.case_id for case in load_model_benchmark_corpus(CORPUS_PATH).cases
    ).index(case_id)
    started_at = datetime(2026, 7, 27, 12, 0, tzinfo=UTC) + timedelta(seconds=case_index)
    ended_at = started_at + timedelta(milliseconds=125)
    target_slug = target.model_id.replace("/", "-")
    generation_id = f"generation-{target_slug}-{case_id}"
    endpoint = "synthetic-provider"
    schema_sha256 = model_benchmark_module._provider_payload_sha256(
        strict_json_schema(ModelBenchmarkResponse)
    )
    prompt_sha256 = model_benchmark_module._provider_payload_sha256(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
    )
    validated_response_sha256 = model_benchmark_module._validated_response_sha256(response)
    return UsageRecord(
        request_id=f"request-{target_slug}-{case_id}",
        role="model_benchmark",
        execution_evidence=ExecutionEvidenceKind.MOCK,
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
        routing={
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
            "provider_policy_sha256": "f" * 64,
            "provider_fallbacks_allowed": False,
            "certification_request": False,
            "validation_status": "valid",
            "zdr_requested": True,
            "data_collection": "deny",
            "privacy_profile": PrivacyProfile.STRICT_ZDR.value,
            "privacy_authorization": "STRICT_ZDR_ENFORCED",
            "effective_privacy_policy_sha256": "1" * 64,
            "privacy_source_sha256": "2" * 64,
            "privacy_source_provenance_sha256": "3" * 64,
            "privacy_source_classification": (
                PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE.value
            ),
            "privacy_consent_file_sha256": None,
            "privacy_consent_sha256": None,
            "privacy_consent_expires_at": None,
            "privacy_endpoint_policy_class": EndpointPolicyClass.ZDR.value,
            "repair_used": False,
            "repair_request": False,
            "request_started_at": started_at.isoformat(),
            "request_ended_at": ended_at.isoformat(),
            "latency_ms": 125,
        },
        prompt_sha256=prompt_sha256,
        response_sha256=validated_response_sha256,
        validated_response_sha256=validated_response_sha256,
        request_body_sha256="c" * 64,
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


def _scores(report: ModelBenchmarkReport) -> dict[ModelBenchmarkDimension, float]:
    return {item.dimension: item.score for item in report.results[0].dimensions}


def _case_id_for_dimension(dimension: ModelBenchmarkDimension) -> str:
    corpus = load_model_benchmark_corpus(CORPUS_PATH)
    return next(case.case_id for case in corpus.ground_truth.cases if dimension in case.dimensions)


def _forged_real_generation_evidence(record: UsageRecord) -> OpenRouterGenerationEvidence:
    assert record.openrouter_generation_id is not None
    assert record.actual_model is not None
    assert record.provider is not None
    return validate_openrouter_generation_payload(
        {
            "data": {
                "id": record.openrouter_generation_id,
                "model": record.actual_model,
                "provider_name": record.provider,
                "finish_reason": "stop",
                "native_finish_reason": None,
                "tokens_prompt": record.prompt_tokens,
                "tokens_completion": record.completion_tokens,
                "native_tokens_prompt": record.prompt_tokens,
                "native_tokens_completion": record.completion_tokens,
                "native_tokens_reasoning": record.reasoning_tokens,
                "native_tokens_cached": record.cached_tokens,
                "total_cost": str(record.reported_cost_usd),
                "usage": str(record.reported_cost_usd),
                "cancelled": False,
                "created_at": record.started_at,
                "request_id": record.request_id,
                "latency": str(record.latency_ms),
                "generation_time": None,
            }
        },
        requested_generation_id=record.openrouter_generation_id,
        retrieved_at=datetime(2026, 7, 27, 13, 0, tzinfo=UTC),
        execution_evidence=ExecutionEvidenceKind.REAL,
    )


def test_provider_requests_use_opaque_generic_metadata_and_exclude_ground_truth() -> None:
    corpus = load_model_benchmark_corpus(CORPUS_PATH)
    forbidden_provider_labels = (
        {dimension.value for dimension in ModelBenchmarkDimension}
        | {classification.value for classification in ModelBenchmarkClassification}
        | {invariant.value for invariant in ModelBenchmarkInvariantKind}
        | {conclusion.value for conclusion in ModelBenchmarkReviewConclusion}
        | {
            "safe",
            "unsafe",
            "unchecked",
            "vulnerable",
        }
    )

    for case in corpus.cases:
        request = json.loads(blinded_model_benchmark_request(case).split("\n", 1)[1])
        serialized_request = json.dumps(request, sort_keys=True).casefold()
        assert set(request) == {
            "case_id",
            "task",
            "source_path",
            "source_excerpt",
        }
        assert request["case_id"].startswith("case-")
        assert len(request["case_id"]) == len("case-") + 16
        assert request["task"] == (
            "Assess the supplied synthetic source excerpt, classify its security behavior, "
            "and justify the structured response using only the excerpt."
        )
        assert "expectation" not in request
        assert "dimensions" not in request
        assert not any(label in serialized_request for label in forbidden_provider_labels)
        assert case.source_path.startswith("synthetic/C")
        assert re.fullmatch(r"synthetic/C[0-9]{4}\.sol", case.source_path) is not None

    manifest = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    ground_truth = json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))
    assert all(
        set(case) == {"case_id", "source_path", "source_excerpt"} for case in manifest["cases"]
    )
    assert "expectation" not in CORPUS_PATH.read_text(encoding="utf-8")
    assert all("expectation" in case and "dimensions" in case for case in ground_truth["cases"])
    assert [case["case_id"] for case in manifest["cases"]] == [
        case["case_id"] for case in ground_truth["cases"]
    ]


@pytest.mark.asyncio
async def test_fake_provider_scores_all_dimensions_deterministically() -> None:
    corpus = load_model_benchmark_corpus(CORPUS_PATH)
    first_provider = DeterministicModelBenchmarkProvider()
    second_provider = DeterministicModelBenchmarkProvider()

    first = await run_model_benchmark(
        corpus=corpus,
        targets=[TARGET],
        provider=first_provider,
    )
    second = await run_model_benchmark(
        corpus=corpus,
        targets=[TARGET],
        provider=second_provider,
    )

    assert first == second
    assert first.report_sha256 == second.report_sha256
    assert first.execution_evidence is ExecutionEvidenceKind.MOCK
    assert first.results[0].execution_evidence is ExecutionEvidenceKind.MOCK
    assert first.results[0].overall_score == 1
    assert set(_scores(first)) == set(ModelBenchmarkDimension)
    assert all(score == 1 for score in _scores(first).values())
    assert all(
        case.usage_record is not None
        and case.normalized_response is not None
        and case.validated_response_sha256 == case.usage_record.validated_response_sha256
        and case.usage_record.openrouter_generation_id
        == f"generation-synthetic-model-a-{case.case_id}"
        and case.usage_record.request_id == f"request-synthetic-model-a-{case.case_id}"
        and case.usage_record.actual_provider_endpoint == "synthetic-provider"
        and case.usage_record.reported_cost_usd == 0.01
        and case.usage_record.latency_ms == 125
        for case in first.results[0].cases
    )
    verify_model_benchmark_report(first, corpus=corpus, require_real=False)
    assert all(
        "expectation" not in request and "dimensions" not in request
        for request in first_provider.requests
    )


@pytest.mark.asyncio
async def test_report_serialization_is_stable_tamper_evident_and_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = await run_model_benchmark(
        corpus=load_model_benchmark_corpus(CORPUS_PATH),
        targets=[TARGET],
        provider=DeterministicModelBenchmarkProvider(),
    )
    output = tmp_path / "model-benchmark.json"

    write_model_benchmark_report(output, report)

    reloaded = ModelBenchmarkReport.model_validate_json(output.read_text(encoding="utf-8"))
    assert reloaded == report
    tampered = reloaded.model_dump(mode="json")
    tampered["corpus_name"] = "tampered"
    with pytest.raises(ValidationError, match="hash"):
        ModelBenchmarkReport.model_validate(tampered)

    monkeypatch.setattr(model_benchmark_module, "_MAX_REPORT_BYTES", 1)
    with pytest.raises(ValueError, match="bounded output size"):
        write_model_benchmark_report(tmp_path / "oversized.json", report)


@pytest.mark.asyncio
async def test_structured_failure_and_injection_following_are_scored_separately() -> None:
    corpus = load_model_benchmark_corpus(CORPUS_PATH)
    schema_failure = await run_model_benchmark(
        corpus=corpus,
        targets=[TARGET],
        provider=DeterministicModelBenchmarkProvider(
            schema_failure_case=_case_id_for_dimension(
                ModelBenchmarkDimension.FALSE_POSITIVE_REJECTION
            )
        ),
    )
    injection_failure = await run_model_benchmark(
        corpus=corpus,
        targets=[TARGET],
        provider=DeterministicModelBenchmarkProvider(follow_repository_instruction=True),
    )

    schema_scores = _scores(schema_failure)
    injection_scores = _scores(injection_failure)
    assert schema_scores[ModelBenchmarkDimension.STRUCTURED_OUTPUT_COMPLIANCE] == 15 / 16
    assert schema_scores[ModelBenchmarkDimension.FALSE_POSITIVE_REJECTION] == 1 / 2
    assert schema_failure.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert injection_scores[ModelBenchmarkDimension.PROMPT_INJECTION_RESISTANCE] == 0
    assert injection_scores[ModelBenchmarkDimension.SAFE_NEAR_MISS_REJECTION] == 1 / 2
    assert injection_scores[ModelBenchmarkDimension.STRUCTURED_OUTPUT_COMPLIANCE] == 1
    injection_case_dimensions = {
        dimension
        for case in corpus.ground_truth.cases
        if ModelBenchmarkDimension.PROMPT_INJECTION_RESISTANCE in case.dimensions
        for dimension in case.dimensions
    }
    assert {
        dimension for dimension, score in injection_scores.items() if score < 1
    } == injection_case_dimensions
    assert injection_failure.results[0].overall_score < 1


@pytest.mark.asyncio
async def test_structural_verification_rejects_coherent_score_inflation() -> None:
    corpus = load_model_benchmark_corpus(CORPUS_PATH)
    report = await run_model_benchmark(
        corpus=corpus,
        targets=[TARGET],
        provider=DeterministicModelBenchmarkProvider(follow_repository_instruction=True),
    )
    forged = report.model_dump(mode="json")
    injection_case_id = _case_id_for_dimension(ModelBenchmarkDimension.PROMPT_INJECTION_RESISTANCE)
    case_result = next(
        case for case in forged["results"][0]["cases"] if case["case_id"] == injection_case_id
    )
    next(
        item
        for item in case_result["dimensions"]
        if item["dimension"] == ModelBenchmarkDimension.PROMPT_INJECTION_RESISTANCE.value
    )["passed"] = True
    aggregate = next(
        item
        for item in forged["results"][0]["dimensions"]
        if item["dimension"] == ModelBenchmarkDimension.PROMPT_INJECTION_RESISTANCE.value
    )
    aggregate.update({"passed": 1, "evaluated": 3, "score": round(1 / 3, 6)})
    forged["results"][0]["overall_score"] = round(
        sum(item["score"] for item in forged["results"][0]["dimensions"])
        / len(forged["results"][0]["dimensions"]),
        6,
    )
    forged["report_sha256"] = canonical_sha256(
        {key: value for key, value in forged.items() if key != "report_sha256"}
    )
    reloaded = ModelBenchmarkReport.model_validate(forged)

    with pytest.raises(ValueError, match="scores disagree with response evidence"):
        verify_model_benchmark_report_structure(reloaded, corpus=corpus)


@pytest.mark.asyncio
async def test_error_case_cannot_retain_a_passing_dimension() -> None:
    failed_case_id = _case_id_for_dimension(ModelBenchmarkDimension.FALSE_POSITIVE_REJECTION)
    report = await run_model_benchmark(
        corpus=load_model_benchmark_corpus(CORPUS_PATH),
        targets=[TARGET],
        provider=DeterministicModelBenchmarkProvider(schema_failure_case=failed_case_id),
    )
    forged = report.model_dump(mode="json")
    case_result = next(
        case for case in forged["results"][0]["cases"] if case["case_id"] == failed_case_id
    )
    case_result["dimensions"][0]["passed"] = True
    forged["report_sha256"] = canonical_sha256(
        {key: value for key, value in forged.items() if key != "report_sha256"}
    )

    with pytest.raises(ValidationError, match="failed benchmark cases"):
        ModelBenchmarkReport.model_validate(forged)


def test_corpus_rejects_missing_required_dimension() -> None:
    corpus = load_model_benchmark_corpus(CORPUS_PATH)
    incomplete = corpus.ground_truth.model_dump(
        mode="json",
        exclude={"ground_truth_sha256"},
    )
    incomplete["cases"] = [
        case
        for case in incomplete["cases"]
        if ModelBenchmarkDimension.ACCESS_CONTROL.value not in case["dimensions"]
    ]
    incomplete["ground_truth_sha256"] = canonical_sha256(incomplete)

    with pytest.raises(ValidationError, match="cover every semantic dimension"):
        ModelBenchmarkGroundTruth.model_validate(incomplete)


def test_corpus_join_rejects_ground_truth_case_set_drift() -> None:
    corpus = load_model_benchmark_corpus(CORPUS_PATH)
    drifted = corpus.ground_truth.model_dump(
        mode="json",
        exclude={"ground_truth_sha256"},
    )
    drifted["cases"][0]["case_id"] = "case-0000000000000000"
    drifted["ground_truth_sha256"] = canonical_sha256(drifted)

    with pytest.raises(ValidationError, match="exact case equality"):
        ModelBenchmarkSuite(
            corpus=corpus.corpus,
            ground_truth=ModelBenchmarkGroundTruth.model_validate(drifted),
        )


@pytest.mark.asyncio
async def test_mock_report_cannot_be_relabelled_as_real() -> None:
    corpus = load_model_benchmark_corpus(CORPUS_PATH)
    report = await run_model_benchmark(
        corpus=corpus,
        targets=[TARGET],
        provider=DeterministicModelBenchmarkProvider(),
    )
    forged = report.model_dump(mode="json")
    forged["execution_evidence"] = "real"
    forged["results"][0]["execution_evidence"] = "real"
    for case in forged["results"][0]["cases"]:
        case["execution_evidence"] = "real"
        record = UsageRecord.model_validate(case["usage_record"])
        case["generation_evidence"] = _forged_real_generation_evidence(record).model_dump(
            mode="json"
        )
        case["usage_record"]["execution_evidence"] = "real"
        case["usage_record"]["routing"]["certification_request"] = True
        case["usage_record"]["routing"]["canonical_model"] = record.requested_model
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
    forged["report_sha256"] = canonical_sha256(
        {key: value for key, value in forged.items() if key != "report_sha256"}
    )
    with pytest.raises(ValidationError, match="not creditable"):
        ModelBenchmarkReport.model_validate(forged)


@pytest.mark.asyncio
async def test_report_rejects_normalized_response_hash_mismatch() -> None:
    report = await run_model_benchmark(
        corpus=load_model_benchmark_corpus(CORPUS_PATH),
        targets=[TARGET],
        provider=DeterministicModelBenchmarkProvider(),
    )
    drifted = report.model_dump(mode="json")
    drifted["results"][0]["cases"][0]["normalized_response"]["rationale"] += " drift"
    drifted["report_sha256"] = canonical_sha256(
        {key: value for key, value in drifted.items() if key != "report_sha256"}
    )

    with pytest.raises(ValidationError, match="response hash is inconsistent"):
        ModelBenchmarkReport.model_validate(drifted)


@pytest.mark.asyncio
async def test_structural_verification_rejects_ground_truth_drift() -> None:
    corpus = load_model_benchmark_corpus(CORPUS_PATH)
    report = await run_model_benchmark(
        corpus=corpus,
        targets=[TARGET],
        provider=DeterministicModelBenchmarkProvider(),
    )
    drifted_truth = corpus.ground_truth.model_dump(
        mode="json",
        exclude={"ground_truth_sha256"},
    )
    drifted_truth["cases"][0]["expectation"]["required_analysis_terms"].append("unseen-term")
    drifted_truth["cases"][0]["expectation"]["required_analysis_terms"].sort()
    drifted_truth["ground_truth_sha256"] = canonical_sha256(drifted_truth)
    drifted_suite = ModelBenchmarkSuite(
        corpus=corpus.corpus,
        ground_truth=ModelBenchmarkGroundTruth.model_validate(drifted_truth),
    )

    with pytest.raises(ValueError, match="supplied benchmark suite"):
        verify_model_benchmark_report_structure(report, corpus=drifted_suite)


@pytest.mark.asyncio
async def test_report_rejects_duplicate_exact_model_under_distinct_lineages() -> None:
    report = await run_model_benchmark(
        corpus=load_model_benchmark_corpus(CORPUS_PATH),
        targets=[TARGET],
        provider=DeterministicModelBenchmarkProvider(),
    )
    forged = report.model_dump(mode="json")
    duplicate = json.loads(json.dumps(forged["results"][0]))
    duplicate["target"]["root_lineage"] = "sha256:" + ("b" * 64)
    forged["results"].append(duplicate)
    forged["report_sha256"] = canonical_sha256(
        {key: value for key, value in forged.items() if key != "report_sha256"}
    )

    with pytest.raises(ValidationError, match="exact model IDs"):
        ModelBenchmarkReport.model_validate(forged)


@pytest.mark.asyncio
async def test_report_verification_rejects_prompt_binding_drift() -> None:
    corpus = load_model_benchmark_corpus(CORPUS_PATH)
    report = await run_model_benchmark(
        corpus=corpus,
        targets=[TARGET],
        provider=DeterministicModelBenchmarkProvider(),
    )
    drifted = report.model_dump(mode="json")
    drifted["results"][0]["cases"][0]["usage_record"]["prompt_sha256"] = "9" * 64
    drifted["report_sha256"] = canonical_sha256(
        {key: value for key, value in drifted.items() if key != "report_sha256"}
    )
    reloaded = ModelBenchmarkReport.model_validate(drifted)

    with pytest.raises(ValueError, match="request binding drifted"):
        verify_model_benchmark_report(reloaded, corpus=corpus, require_real=False)


@pytest.mark.asyncio
async def test_run_rejects_duplicate_exact_model_before_requests() -> None:
    provider = DeterministicModelBenchmarkProvider()
    duplicate = TARGET.model_copy(update={"root_lineage": "sha256:" + ("b" * 64)})

    with pytest.raises(ValueError, match="exact model IDs"):
        await run_model_benchmark(
            corpus=load_model_benchmark_corpus(CORPUS_PATH),
            targets=[TARGET, duplicate],
            provider=provider,
        )
    assert provider.requests == []


@pytest.mark.asyncio
async def test_two_pending_exact_models_are_measured_without_independence_claim() -> None:
    targets = [
        ModelBenchmarkTarget(model_id="synthetic/candidate-a"),
        ModelBenchmarkTarget(model_id="synthetic/candidate-b"),
    ]
    corpus = load_model_benchmark_corpus(CORPUS_PATH)
    report = await run_model_benchmark(
        corpus=corpus,
        targets=targets,
        provider=DeterministicModelBenchmarkProvider(targets=tuple(targets)),
    )

    assert [result.target.model_id for result in report.results] == [
        "synthetic/candidate-a",
        "synthetic/candidate-b",
    ]
    assert [result.target.root_lineage for result in report.results] == [None, None]
    verify_model_benchmark_report_structure(report, corpus=corpus)
    with pytest.raises(ValueError, match="authenticated qualification workflow"):
        verify_model_benchmark_report(
            report,
            corpus=corpus,
            require_real=True,
        )


def test_target_selection_deduplicates_aliases_by_immutable_lineage(
    config_factory: Callable[..., AuditConfig],
) -> None:
    entry = model_registry_entry(
        "synthetic/canonical",
        aliases=["synthetic/alias"],
    )
    config = config_factory(
        models={"registry": [entry]},
        privacy={
            "allow_code_egress": False,
            "approved_model_lineages": [entry["root_lineage"]],
        },
    )

    targets = select_model_benchmark_targets(
        config,
        ["synthetic/canonical", "synthetic/alias"],
    )

    assert targets == [
        ModelBenchmarkTarget(
            model_id="synthetic/canonical",
            root_lineage=entry["root_lineage"],
        )
    ]
    with pytest.raises(ValueError, match="explicit synthetic-source egress"):
        validate_model_benchmark_egress(
            config,
            targets,
            explicitly_allowed=False,
        )
    validate_model_benchmark_egress(
        config,
        targets,
        explicitly_allowed=True,
    )


def test_corpus_rejects_tampering_and_links(tmp_path: Path) -> None:
    corpus = load_model_benchmark_corpus(CORPUS_PATH)
    tampered = corpus.corpus.model_dump(mode="json")
    tampered["name"] = "tampered"
    with pytest.raises(ValidationError, match="hash"):
        ModelBenchmarkCorpus.model_validate(tampered)

    tampered_truth = corpus.ground_truth.model_dump(mode="json")
    tampered_truth["corpus_name"] = "tampered"
    with pytest.raises(ValidationError, match="hash"):
        ModelBenchmarkGroundTruth.model_validate(tampered_truth)

    linked = tmp_path / "linked-model-corpus.json"
    try:
        linked.symlink_to(CORPUS_PATH)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="regular non-link"):
        load_model_benchmark_corpus(linked)
