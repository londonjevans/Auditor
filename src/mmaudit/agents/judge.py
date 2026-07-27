"""Final judge constrained to deterministic candidate groups."""

from __future__ import annotations

import json
from typing import Any

from mmaudit.agents.base import AgentBase
from mmaudit.models.openrouter import OpenRouterSchemaError
from mmaudit.models.schemas import ContextPackage, JudgeDecisionBatch, ThreatModel
from mmaudit.orchestration.context import render_context


class JudgeAgent(AgentBase):
    role = "judge"
    prompt_file = "judge.md"

    async def run(
        self,
        *,
        groups: list[dict[str, Any]],
        context: ContextPackage,
        threat_model: ThreatModel | None,
    ) -> JudgeDecisionBatch:
        payload = {
            "candidate_groups": groups,
            "threat_model": threat_model.model_dump(mode="json") if threat_model else None,
        }
        prompt = "\n".join(
            (
                "<VERIFIED_GROUPS_JSON>",
                json.dumps(payload, sort_keys=True),
                "</VERIFIED_GROUPS_JSON>",
                render_context(context),
            )
        )
        response = await self.client.complete(
            role=self.role,
            models=self.configured_models,
            system_prompt=self.system_prompt,
            user_prompt=prompt,
            response_model=JudgeDecisionBatch,
            schema_name="mmaudit_judgment",
        )
        allowed = {str(group["group_id"]) for group in groups}
        response_ids = [decision.group_id for decision in response.decisions]
        if set(response_ids) - allowed or len(response_ids) != len(set(response_ids)):
            raise OpenRouterSchemaError("judge returned unknown or duplicate candidate groups")
        return JudgeDecisionBatch(
            decisions=[decision for decision in response.decisions if decision.group_id in allowed]
        )
