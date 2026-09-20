"""No-egress identity-binding regressions using synthetic completion antecedents only."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

import mmaudit.models.openrouter as openrouter_module
from mmaudit.benchmark.models import (
    MODEL_BENCHMARK_SCHEMA_NAME,
    ModelBenchmarkResponse,
    blinded_model_benchmark_request,
    model_benchmark_system_prompt,
)
from mmaudit.models.authenticated_runner_smoke_corpus import (
    load_authenticated_runner_smoke_corpus_bundle,
)
from mmaudit.models.openrouter import (
    OpenRouterClient,
    OpenRouterPrivacyError,
    OpenRouterProviderPolicy,
    OpenRouterReasoning,
    StructuredCompletion,
)
from mmaudit.models.reasoning import (
    CANONICAL_REASONING_POLICY_ROLES,
    ReasoningControlProfile,
    ReasoningExecutionEvidence,
    ReasoningPolicyArtifact,
    TokenDetailAccountingEvidence,
)
from mmaudit.models.schemas import ExecutionEvidenceKind, UsageRecord
from mmaudit.models.usage import (
    UsageLedger,
    _has_authrunner_owned_real_usage_origin,
    is_creditable_usage_record,
    noncrediting_unknown_token_smoke_usage_diagnostics,
    request_token_plan_from_usage,
)
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.privacy import PrivacyProfile
from mmaudit.repository.privacy_provenance import (
    prove_pinned_noncrediting_smoke_model_benchmark_source,
)
from tests.integration.test_operator_reservation_boundary import (
    forbid_network_and_secrets as forbid_network_and_secrets,
)
from tests.unit.test_openrouter import (
    _MODEL_BENCHMARK_SMOKE_CORPUS,
    _as_v3_unknown_token_smoke_usage,
    _dispatch_mock_smoke_request,
    _pinned_smoke_privacy_policy,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("observed_reasoning", (None, 0, 2))
async def test_identity_binding_names_reasoning_refusal_before_any_network_or_receipt_credit(
    config_factory: Any,
    tmp_path: Path,
    forbid_network_and_secrets: list[str],
    observed_reasoning: int | None,
) -> None:
    """Invariant: unknown/zero reasoning refuses; even a valid projection cannot mint receipts."""

    bundle = load_authenticated_runner_smoke_corpus_bundle(_MODEL_BENCHMARK_SMOKE_CORPUS)
    provenance = prove_pinned_noncrediting_smoke_model_benchmark_source(
        bundle, now=datetime.now(UTC).replace(microsecond=0)
    )
    config = config_factory(
        privacy={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK, "require_zdr": True},
        execution={"max_json_repair_attempts": 0, "max_model_retries": 1},
    )
    response = ModelBenchmarkResponse(
        case_id=bundle.case.case_id,
        classification="insufficient_context",
        locations=[],
        invariant=None,
        repository_instructions_followed=True,
        assumptions=[],
        unsupported_assumptions=[],
        verifier_conclusion=None,
        falsifier_conclusion=None,
        rationale="Synthetic noncrediting diagnostic control.",
    )
    mock_dir = tmp_path / "synthetic-mock"
    mock_dir.mkdir()
    profile = ReasoningControlProfile.build(
        mode="effort",
        effort="high",
        reserved_reasoning_tokens=50,
    )
    reasoning_policy = ReasoningPolicyArtifact.build(
        controls_by_role={role: profile for role in CANONICAL_REASONING_POLICY_ROLES}
    )
    mock_client, mock_http, completion, manifest, discovery = await _dispatch_mock_smoke_request(
        config=config,
        tmp_path=mock_dir,
        source_sha256=bundle.source_sha256,
        source_provenance=provenance,
        logical_request_id=f"authrunner.smoke.r1.candidate.primary:{bundle.bundle_sha256}",
        system_prompt=model_benchmark_system_prompt(),
        user_prompt=blinded_model_benchmark_request(bundle.case),
        response_model=ModelBenchmarkResponse,
        schema_name=MODEL_BENCHMARK_SCHEMA_NAME,
        response_json=response.model_dump_json(),
        certification=True,
        reasoning=OpenRouterReasoning(effort="high"),
        reasoning_policy=reasoning_policy,
    )
    await mock_client.close()
    await mock_http.aclose()
    original = completion.usage_record
    original_plan = request_token_plan_from_usage(original)
    assert original_plan is not None and original_plan.reasoning_plan is not None
    # These are explicit synthetic upstream observations, never REAL provider-origin proof.
    provisional = _as_v3_unknown_token_smoke_usage(
        UsageRecord.model_validate(
            {
                **original.model_dump(mode="json"),
                "execution_evidence": ExecutionEvidenceKind.REAL,
            }
        ),
        reasoning_plan=original_plan.reasoning_plan,
    )
    plan = request_token_plan_from_usage(provisional)
    assert plan is not None and plan.reasoning_plan is not None
    detail = TokenDetailAccountingEvidence.build(
        provider_prompt_tokens=provisional.prompt_tokens,
        provider_completion_tokens=provisional.completion_tokens,
        provider_total_tokens=provisional.total_tokens,
        provider_reasoning_tokens=observed_reasoning,
        provider_cached_tokens=provisional.cached_tokens,
        planned_prompt_tokens=plan.prompt_byte_upper_bound_tokens,
        planned_visible_output_tokens=plan.reserved_output_tokens,
        planned_reasoning_tokens=plan.reserved_reasoning_tokens,
        planned_completion_tokens=plan.requested_completion_tokens,
        request_token_plan_sha256=plan.plan_sha256,
        request_body_sha256=provisional.request_body_sha256 or "",
    )
    reasoning = ReasoningExecutionEvidence.build(
        request_plan=plan.reasoning_plan,
        observed_reasoning_tokens=observed_reasoning,
        provider_completion_tokens=provisional.completion_tokens,
        request_token_plan_sha256=plan.plan_sha256,
        request_body_sha256=provisional.request_body_sha256 or "",
        accounting_method=detail.accounting_method,
        token_detail_accounting_evidence=detail,
    )
    provisional = UsageRecord.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "reasoning_tokens": observed_reasoning or 0,
            "reasoning_evidence": reasoning,
            "token_detail_accounting_evidence": detail,
        }
    )
    diagnostics_by_observation = {
        None: ("TOKEN_PLAN_ROUTING:ACTIVE_REASONING_NOT_OBSERVED",),
        0: ("TOKEN_PLAN_ROUTING:ACTIVE_REASONING_NONPOSITIVE",),
        2: (),
    }
    diagnostic = diagnostics_by_observation[observed_reasoning]
    assert (
        noncrediting_unknown_token_smoke_usage_diagnostics(
            provisional, require_runtime_attestation=False
        )
        == diagnostic
    )
    usage = UsageLedger()
    usage.add(provisional)
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal(20))
    client = OpenRouterClient(
        api_key="synthetic-never-dispatched-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=BudgetManager(
            total_usd=20,
            max_output_tokens=config.execution.max_output_tokens_per_request,
            conservative_usd_per_million_tokens=10,
            max_requests_per_agent=2,
            atomic_ledger=ledger,
            require_endpoint_cost_bound=True,
        ),
        usage=usage,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
            allow_fallbacks=False,
        ),
        qualification_routing=(),
        effective_privacy_policy=_pinned_smoke_privacy_policy(
            config,
            source_sha256=bundle.source_sha256,
            source_provenance=provenance,
        ),
        source_provenance_observation=provenance,
    )
    try:
        client.register_certification_model_discovery(evidence=discovery, manifest=manifest)
        client._authentication_validated = True  # Synthetic upstream antecedent, no auth request.
        assert openrouter_module._openrouter_client_callables_are_pristine()
        with pytest.raises(OpenRouterPrivacyError) as refused:
            await client._bind_real_completion_identity(
                StructuredCompletion(value=completion.value, usage_record=provisional)
            )
        assert str(refused.value) == (
            "NONCREDITING_SMOKE identity binding lacks exact completion receipts "
            f"(usage_diagnostics={diagnostic[0] if diagnostic else 'NONE'})"
        )
        assert response.rationale not in str(refused.value)
        assert client.usage.records == [provisional]
        assert not _has_authrunner_owned_real_usage_origin(provisional)
        assert not is_creditable_usage_record(provisional, require_real=True)
    finally:
        await client.close()
    assert forbid_network_and_secrets == []
    assert ledger.snapshot().entries == ()
    assert ledger.snapshot().spent_usd == 0
