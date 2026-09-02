from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast

import pytest

from mmaudit.agents.base import (
    RetrievalPlanningAgent,
    RetrievalPlanningResult,
    load_prompt,
)
from mmaudit.agents.source_audit import SourceAuditAgent
from mmaudit.config import AuditConfig
from mmaudit.models.openrouter import (
    OpenRouterClient,
    OpenRouterSchemaError,
    StructuredCompletion,
    StructuredRequestHashes,
)
from mmaudit.models.retrieval import (
    SolidityRetrievalIntent,
    SolidityRetrievalOperation,
    SolidityRetrievalRequestBatch,
    SolidityRetrievalRolePolicy,
    SolidityRetrievalTranscript,
)
from mmaudit.models.schemas import ContextPackage, RepositoryMap, UsageRecord
from mmaudit.models.truncation import CandidateReviewFramedDocument
from mmaudit.orchestration.context import render_context

_MODEL_ID = "bravo/borealis-secure"
_REQUEST_ID = "scheduler-request-" + "a" * 64 + ":retrieval"
_PROMPT_SHA256 = "1" * 64
_USER_PROMPT_SHA256 = "3" * 64
_SCHEMA_SHA256 = "4" * 64


def _context(
    *,
    role: str = "source_audit",
    policy: SolidityRetrievalRolePolicy | None = None,
    retrieval_bound: bool = True,
    with_transcript: bool = False,
) -> ContextPackage:
    if with_transcript and not retrieval_bound:
        raise ValueError("a retrieval transcript requires a retrieval-bound context")
    if retrieval_bound and policy is None:
        policy = SolidityRetrievalRolePolicy.build(role=role)
    corpus_sha256 = "9" * 64 if retrieval_bound else None
    transcript = (
        SolidityRetrievalTranscript.build(
            role=policy.role,
            policy_sha256=policy.policy_sha256,
            corpus_sha256=cast(str, corpus_sha256),
        )
        if with_transcript and policy is not None
        else None
    )
    package = ContextPackage(
        role=role,
        byte_budget=10_000,
        bytes_used=0,
        configured_maximum_source_tokens_per_request=200_000,
        effective_source_byte_ceiling=0,
        repository_map=RepositoryMap(
            root_name="synthetic-retrieval-planning",
            languages={"Solidity": 1},
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
            omitted_files=[],
        ),
        scanner_findings=[],
        excerpts=[],
        solidity_retrieval_policy=policy if retrieval_bound else None,
        solidity_retrieval_corpus_sha256=corpus_sha256,
        solidity_retrieval_transcript=transcript,
    )
    return package.model_copy(update={"bytes_used": len(render_context(package).encode("utf-8"))})


def _batch(*, request_count: int = 1) -> SolidityRetrievalRequestBatch:
    return SolidityRetrievalRequestBatch(
        requests=tuple(
            SolidityRetrievalIntent(
                operation=SolidityRetrievalOperation.LIST_CALLERS,
                subject_id="fn-target" if index == 0 else f"fn-target-{index}",
            )
            for index in range(request_count)
        )
    )


def _usage(
    *,
    request_id: str = _REQUEST_ID,
    role: str = "source_audit",
    model: str = _MODEL_ID,
    fallback_used: bool = False,
    batch: SolidityRetrievalRequestBatch | None = None,
) -> UsageRecord:
    if batch is None:
        batch = _batch()
    validated_response_sha256 = hashlib.sha256(
        json.dumps(
            batch.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return UsageRecord(
        request_id=request_id,
        role=role,
        requested_model=model,
        returned_model=model,
        actual_model=model,
        model_family="borealis-secure",
        timestamp=datetime(2026, 9, 2, tzinfo=UTC),
        routing={
            "host_model_fallback_used": fallback_used,
            "provider_fallback_used": False,
            "selected_model": model,
        },
        prompt_sha256=_PROMPT_SHA256,
        user_prompt_sha256=_USER_PROMPT_SHA256,
        schema_sha256=_SCHEMA_SHA256,
        validated_response_sha256=validated_response_sha256,
        fallback_used=fallback_used,
        status="success",
        attempts=1,
    )


class _CompletionClient:
    def __init__(self, completion: StructuredCompletion[SolidityRetrievalRequestBatch]) -> None:
        self.completion = completion
        self.calls: list[dict[str, Any]] = []

    async def complete_with_evidence(self, **kwargs: Any) -> StructuredCompletion[Any]:
        self.calls.append(kwargs)
        return self.completion

    def preview_structured_request_hashes(self, **_kwargs: Any) -> StructuredRequestHashes:
        return _request_hashes()


class _FailingClient:
    def __init__(self) -> None:
        self.calls = 0

    async def complete_with_evidence(self, **_kwargs: Any) -> StructuredCompletion[Any]:
        self.calls += 1
        raise OpenRouterSchemaError("synthetic invalid retrieval schema")

    def preview_structured_request_hashes(self, **_kwargs: Any) -> StructuredRequestHashes:
        return _request_hashes()


def _request_hashes() -> StructuredRequestHashes:
    return StructuredRequestHashes(
        prompt_sha256=_PROMPT_SHA256,
        system_prompt_sha256="2" * 64,
        user_prompt_sha256=_USER_PROMPT_SHA256,
        schema_sha256=_SCHEMA_SHA256,
    )


@pytest.mark.asyncio
async def test_planner_uses_exact_review_identity_and_returns_detached_noncrediting_custody(
    config_factory: Callable[..., AuditConfig],
) -> None:
    context = _context()
    batch = _batch()
    usage = _usage()
    client = _CompletionClient(StructuredCompletion(value=batch, usage_record=usage))
    agent = RetrievalPlanningAgent(
        config_factory(),
        cast(OpenRouterClient, client),
        role="source_audit",
        exact_model_id=_MODEL_ID,
    )

    result = await agent.run(context, logical_request_id=_REQUEST_ID)

    assert type(result) is RetrievalPlanningResult
    assert result.request_batch == batch
    assert result.request_batch is not batch
    assert result.planning_context == context
    assert result.planning_context is not context
    assert result.completion_usage == usage
    assert result.completion_usage is not usage
    assert set(result.request_batch.model_dump()) == {"schema_version", "requests"}
    assert "request_sha256" not in result.request_batch.model_dump_json()
    assert not hasattr(result, "findings")
    assert not hasattr(result, "surface_review_artifact")
    assert not hasattr(result, "specialist_execution")

    assert len(client.calls) == 1
    call = client.calls[0]
    assert set(call) == {
        "role",
        "models",
        "system_prompt",
        "user_prompt",
        "context_package",
        "response_model",
        "schema_name",
        "logical_request_id",
    }
    assert call["role"] == "source_audit"
    assert call["models"] == [_MODEL_ID]
    assert call["system_prompt"] == agent.request_protocol.system_prompt
    assert call["user_prompt"] == render_context(result.planning_context)
    assert call["context_package"] == result.planning_context
    assert call["context_package"] is not context
    assert call["response_model"] is SolidityRetrievalRequestBatch
    assert call["schema_name"] == "mmaudit_solidity_retrieval_request_batch"
    assert call["logical_request_id"] == _REQUEST_ID
    assert not {"tools", "tool_choice", "functions", "function_call"}.intersection(call)


def test_request_protocol_is_exact_shared_plus_dedicated_prompt(
    config_factory: Callable[..., AuditConfig],
) -> None:
    expected = "\n\n".join(
        (load_prompt("shared_security_rules.md"), load_prompt("retrieval_planning.md"))
    )
    agent = RetrievalPlanningAgent(
        config_factory(),
        cast(OpenRouterClient, _FailingClient()),
        role="source_audit",
        exact_model_id=_MODEL_ID,
    )
    protocol = agent.request_protocol

    prompt = load_prompt("retrieval_planning.md")
    assert protocol.system_prompt == expected
    assert protocol.response_model is SolidityRetrievalRequestBatch
    assert protocol.schema_name == "mmaudit_solidity_retrieval_request_batch"
    assert "zero through eight intents" in prompt
    assert "Each `(operation, subject_id)` pair must be unique." in prompt
    assert "opaque entity `subject_id`" in prompt
    assert "path, line range, glob, wildcard" in prompt
    assert "shell access, filesystem access, network access" in prompt
    assert "empty `requests` array" in prompt
    assert "terminal for retrieval" in prompt
    assert "Retrieval is not execution" in prompt
    assert "not a finding, coverage claim, completed surface review" in prompt


def test_constructor_rejects_role_or_model_identity_drift(
    config_factory: Callable[..., AuditConfig],
) -> None:
    client = cast(OpenRouterClient, _FailingClient())

    with pytest.raises(ValueError, match="not supported"):
        RetrievalPlanningAgent(
            config_factory(),
            client,
            role="judge",
            exact_model_id=_MODEL_ID,
        )
    with pytest.raises(ValueError, match="differs from the configured reviewer"):
        RetrievalPlanningAgent(
            config_factory(),
            client,
            role="source_audit",
            exact_model_id="alpha/atlas-secure",
        )


def test_constructor_accepts_configured_specialist_and_explicit_whole_protocol_identity(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory(
        models={
            "specialists": {
                "access_control": {"primary": _MODEL_ID, "fallbacks": []},
            }
        }
    )
    client = cast(OpenRouterClient, _FailingClient())

    specialist = RetrievalPlanningAgent(
        config,
        client,
        role="specialist:access_control",
        exact_model_id=_MODEL_ID,
    )
    whole_protocol = RetrievalPlanningAgent(
        config,
        client,
        role="whole_protocol_review:3",
        exact_model_id="explicit/whole-reviewer",
    )

    assert specialist.configured_models == [_MODEL_ID]
    assert whole_protocol.configured_models == ["explicit/whole-reviewer"]


@pytest.mark.parametrize(
    "usage",
    [
        _usage(request_id="different-retrieval-request"),
        _usage(role="business_logic"),
        _usage(model="alpha/atlas-secure"),
        _usage(fallback_used=True),
    ],
)
def test_bind_completed_plan_rejects_usage_identity_drift(
    config_factory: Callable[..., AuditConfig],
    usage: UsageRecord,
) -> None:
    agent = RetrievalPlanningAgent(
        config_factory(),
        cast(OpenRouterClient, _FailingClient()),
        role="source_audit",
        exact_model_id=_MODEL_ID,
    )

    with pytest.raises(OpenRouterSchemaError, match="differs from its exact request identity"):
        agent.bind_completed_plan(
            _context(),
            raw_response=_batch(),
            completion_usage=usage,
            logical_request_id=_REQUEST_ID,
        )


def test_bind_completed_plan_rejects_batch_subclass_and_context_role_drift(
    config_factory: Callable[..., AuditConfig],
) -> None:
    class BatchSubclass(SolidityRetrievalRequestBatch):
        pass

    agent = RetrievalPlanningAgent(
        config_factory(),
        cast(OpenRouterClient, _FailingClient()),
        role="source_audit",
        exact_model_id=_MODEL_ID,
    )

    with pytest.raises(OpenRouterSchemaError, match="invalid exact type"):
        agent.bind_completed_plan(
            _context(),
            raw_response=BatchSubclass(requests=()),
            completion_usage=_usage(),
            logical_request_id=_REQUEST_ID,
        )
    with pytest.raises(OpenRouterSchemaError, match="configured review role"):
        agent.bind_completed_plan(
            _context(role="business_logic"),
            raw_response=_batch(),
            completion_usage=_usage(),
            logical_request_id=_REQUEST_ID,
        )


@pytest.mark.asyncio
async def test_planner_rejects_ordinary_and_final_contexts_before_provider_dispatch(
    config_factory: Callable[..., AuditConfig],
) -> None:
    client = _FailingClient()
    agent = RetrievalPlanningAgent(
        config_factory(),
        cast(OpenRouterClient, client),
        role="source_audit",
        exact_model_id=_MODEL_ID,
    )

    with pytest.raises(OpenRouterSchemaError, match="retrieval-bound planning context"):
        await agent.run(
            _context(retrieval_bound=False),
            logical_request_id=_REQUEST_ID,
        )
    with pytest.raises(OpenRouterSchemaError, match="transcript-free planning context"):
        await agent.run(
            _context(with_transcript=True),
            logical_request_id=_REQUEST_ID,
        )

    assert client.calls == 0


@pytest.mark.asyncio
async def test_planner_rejects_exact_policy_role_drift_before_provider_dispatch(
    config_factory: Callable[..., AuditConfig],
) -> None:
    client = _FailingClient()
    agent = RetrievalPlanningAgent(
        config_factory(),
        cast(OpenRouterClient, client),
        role="whole_protocol_review:4",
        exact_model_id="explicit/whole-reviewer",
    )
    context = _context(
        role="whole_protocol_review",
        policy=SolidityRetrievalRolePolicy.build(role="whole_protocol_review:3"),
    )

    with pytest.raises(OpenRouterSchemaError, match="policy differs"):
        await agent.run(context, logical_request_id=_REQUEST_ID)

    assert client.calls == 0


@pytest.mark.parametrize(
    ("maximum_requests", "request_count"),
    ((0, 1), (1, 2)),
)
def test_bind_completed_plan_rejects_batches_exceeding_exact_policy_request_limit(
    config_factory: Callable[..., AuditConfig],
    maximum_requests: int,
    request_count: int,
) -> None:
    policy = SolidityRetrievalRolePolicy.build(
        role="source_audit",
        maximum_requests=maximum_requests,
        maximum_total_result_utf8_bytes=0 if maximum_requests == 0 else 16_384,
        maximum_total_result_tokens=0 if maximum_requests == 0 else 5_462,
    )
    agent = RetrievalPlanningAgent(
        config_factory(),
        cast(OpenRouterClient, _FailingClient()),
        role="source_audit",
        exact_model_id=_MODEL_ID,
    )

    with pytest.raises(OpenRouterSchemaError, match="exact role request limit"):
        agent.bind_completed_plan(
            _context(policy=policy),
            raw_response=_batch(request_count=request_count),
            completion_usage=_usage(),
            logical_request_id=_REQUEST_ID,
        )


def test_bind_completed_plan_accepts_empty_batch_under_zero_request_allocation(
    config_factory: Callable[..., AuditConfig],
) -> None:
    policy = SolidityRetrievalRolePolicy.build(
        role="source_audit",
        maximum_requests=0,
        maximum_total_result_utf8_bytes=0,
        maximum_total_result_tokens=0,
    )
    batch = _batch(request_count=0)
    agent = RetrievalPlanningAgent(
        config_factory(),
        cast(OpenRouterClient, _FailingClient()),
        role="source_audit",
        exact_model_id=_MODEL_ID,
    )

    result = agent.bind_completed_plan(
        _context(policy=policy),
        raw_response=batch,
        completion_usage=_usage(batch=batch),
        logical_request_id=_REQUEST_ID,
    )

    assert result.request_batch.requests == ()
    assert result.planning_context.solidity_retrieval_policy == policy


@pytest.mark.parametrize(
    "field",
    (
        "prompt_sha256",
        "user_prompt_sha256",
        "schema_sha256",
        "validated_response_sha256",
    ),
)
def test_bind_completed_plan_rejects_prompt_or_response_custody_drift(
    config_factory: Callable[..., AuditConfig],
    field: str,
) -> None:
    agent = RetrievalPlanningAgent(
        config_factory(),
        cast(OpenRouterClient, _FailingClient()),
        role="source_audit",
        exact_model_id=_MODEL_ID,
    )
    usage = _usage().model_copy(update={field: "f" * 64})

    with pytest.raises(OpenRouterSchemaError, match="exact prompt or response custody"):
        agent.bind_completed_plan(
            _context(),
            raw_response=_batch(),
            completion_usage=usage,
            logical_request_id=_REQUEST_ID,
        )


@pytest.mark.asyncio
async def test_schema_failure_is_terminal_at_agent_layer_and_finding_protocol_is_unchanged(
    config_factory: Callable[..., AuditConfig],
) -> None:
    client = _FailingClient()
    config = config_factory()
    planner = RetrievalPlanningAgent(
        config,
        cast(OpenRouterClient, client),
        role="source_audit",
        exact_model_id=_MODEL_ID,
    )

    with pytest.raises(OpenRouterSchemaError, match="synthetic invalid retrieval schema"):
        await planner.run(_context(), logical_request_id=_REQUEST_ID)

    assert client.calls == 1
    finding_protocol = SourceAuditAgent(config, cast(OpenRouterClient, client)).request_protocol
    assert finding_protocol.response_model is CandidateReviewFramedDocument
    assert finding_protocol.schema_name == "mmaudit_source_audit_findings"
