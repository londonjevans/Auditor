"""Dedicated non-finding invariant-review model role."""

from __future__ import annotations

from mmaudit.agents.base import (
    AgentRequestProtocol,
    ValidatedAgentResult,
    build_agent_request_protocol,
)
from mmaudit.agents.specialists import SPECIALIST_ROLE_REGISTRY
from mmaudit.config import AuditConfig
from mmaudit.models.openrouter import OpenRouterClient, OpenRouterSchemaError
from mmaudit.models.schemas import ContextPackage, InvariantReviewBatch
from mmaudit.orchestration.context import render_context


class InvariantReviewAgent:
    """Review source-derived invariants and propose bounded missing properties."""

    role = "invariant_review"

    def __init__(self, config: AuditConfig, client: OpenRouterClient) -> None:
        self.config = config
        self.client = client

    @property
    def request_protocol(self) -> AgentRequestProtocol:
        definition = SPECIALIST_ROLE_REGISTRY[self.role]
        return build_agent_request_protocol(
            prompt_file="invariant_review.md",
            schema_name=definition.effective_schema_name(),
            response_model=InvariantReviewBatch,
            role_contract=definition.prompt_contract(),
        )

    async def run(
        self,
        context: ContextPackage,
        *,
        logical_request_id: str | None = None,
    ) -> InvariantReviewBatch:
        return (
            await self.run_with_evidence(
                context,
                logical_request_id=logical_request_id,
            )
        ).value

    async def run_with_evidence(
        self,
        context: ContextPackage,
        *,
        logical_request_id: str | None = None,
    ) -> ValidatedAgentResult[InvariantReviewBatch]:
        configured = self.config.models.role(self.role)
        request_role = f"specialist:{self.role}"
        protocol = self.request_protocol
        completion = await self.client.complete_with_evidence(
            role=request_role,
            models=[configured.primary, *configured.fallbacks],
            system_prompt=protocol.system_prompt,
            user_prompt=render_context(context),
            context_package=context,
            response_model=protocol.response_model,
            schema_name=protocol.schema_name,
            logical_request_id=logical_request_id,
        )
        response = completion.value
        existing_ids = {
            invariant.id
            for invariant in (
                context.solidity_invariants.invariants
                if context.solidity_invariants is not None
                else []
            )
        }
        decision_ids = [decision.invariant_id for decision in response.decisions]
        if len(decision_ids) != len(set(decision_ids)):
            raise OpenRouterSchemaError("invariant reviewer returned duplicate invariant decisions")
        unknown = set(decision_ids) - existing_ids
        if unknown:
            raise OpenRouterSchemaError(
                "invariant reviewer referenced unknown source-derived invariant identifiers"
            )
        return ValidatedAgentResult(
            value=response,
            completion_usage=completion.usage_record,
            raw_response=response,
        )
