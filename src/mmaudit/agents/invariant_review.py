"""Dedicated non-finding invariant-review model role."""

from __future__ import annotations

from mmaudit.agents.base import load_prompt
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

    async def run(self, context: ContextPackage) -> InvariantReviewBatch:
        configured = self.config.models.role(self.role)
        definition = SPECIALIST_ROLE_REGISTRY[self.role]
        request_role = f"specialist:{self.role}"
        response = await self.client.complete(
            role=request_role,
            models=[configured.primary, *configured.fallbacks],
            system_prompt="\n\n".join(
                (
                    load_prompt("shared_security_rules.md"),
                    load_prompt("invariant_review.md"),
                    "<ROLE_CONTRACT_JSON>",
                    definition.prompt_contract(),
                    "</ROLE_CONTRACT_JSON>",
                )
            ),
            user_prompt=render_context(context),
            context_package=context,
            response_model=InvariantReviewBatch,
            schema_name=definition.effective_schema_name(),
        )
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
        return response
