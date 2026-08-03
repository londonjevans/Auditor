"""Final judge constrained to deterministic candidate groups."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from mmaudit.agents.base import AgentBase, AgentRequestProtocol, build_agent_request_protocol
from mmaudit.models.openrouter import OpenRouterSchemaError
from mmaudit.models.schemas import ContextPackage, JudgeDecisionBatch, ThreatModel
from mmaudit.orchestration.context import render_context


def _prepared_judgment_workflow(payload: object) -> tuple[str, int, str]:
    payload_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    workflow_prompt = "\n".join(
        (
            "<VERIFIED_GROUPS_JSON>",
            payload_json,
            "</VERIFIED_GROUPS_JSON>",
            "",
        )
    )
    encoded = workflow_prompt.encode("utf-8")
    return workflow_prompt, len(encoded), hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class PreparedJudgmentInput:
    """Exact judgment workflow material prepared before context allocation."""

    workflow_prompt: str
    workflow_byte_upper_bound_tokens: int
    workflow_sha256: str

    @classmethod
    def build(cls, payload: object) -> PreparedJudgmentInput:
        workflow_prompt, byte_bound, workflow_sha256 = _prepared_judgment_workflow(payload)
        return cls(
            workflow_prompt=workflow_prompt,
            workflow_byte_upper_bound_tokens=byte_bound,
            workflow_sha256=workflow_sha256,
        )

    def __post_init__(self) -> None:
        encoded = self.workflow_prompt.encode("utf-8")
        if self.workflow_byte_upper_bound_tokens != len(encoded):
            raise ValueError("prepared judgment workflow byte bound is inconsistent")
        if self.workflow_sha256 != hashlib.sha256(encoded).hexdigest():
            raise ValueError("prepared judgment workflow hash is inconsistent")
        prefix = "<VERIFIED_GROUPS_JSON>\n"
        suffix = "\n</VERIFIED_GROUPS_JSON>\n"
        if not self.workflow_prompt.startswith(prefix) or not self.workflow_prompt.endswith(suffix):
            raise ValueError("prepared judgment workflow envelope is inconsistent")
        payload_json = self.workflow_prompt[len(prefix) : -len(suffix)]
        try:
            payload = json.loads(payload_json)
            canonical_json = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("prepared judgment workflow JSON is inconsistent") from exc
        if payload_json != canonical_json:
            raise ValueError("prepared judgment workflow JSON is not canonical")


class JudgeAgent(AgentBase):
    role = "judge"
    prompt_file = "judge.md"

    @property
    def request_protocol(self) -> AgentRequestProtocol:
        return build_agent_request_protocol(
            prompt_file=self.prompt_file,
            schema_name="mmaudit_judgment",
            response_model=JudgeDecisionBatch,
        )

    @staticmethod
    def prepare_input(
        *,
        groups: list[dict[str, Any]],
        threat_model: ThreatModel | None,
    ) -> PreparedJudgmentInput:
        """Prepare the exact non-context judgment workflow."""

        return PreparedJudgmentInput.build(
            {
                "candidate_groups": groups,
                "threat_model": (threat_model.model_dump(mode="json") if threat_model else None),
            }
        )

    async def run(
        self,
        *,
        groups: list[dict[str, Any]],
        context: ContextPackage,
        threat_model: ThreatModel | None,
        prepared_input: PreparedJudgmentInput | None = None,
        logical_request_id: str | None = None,
    ) -> JudgeDecisionBatch:
        expected_input = self.prepare_input(groups=groups, threat_model=threat_model)
        if prepared_input is not None and prepared_input != expected_input:
            raise OpenRouterSchemaError(
                "prepared judgment workflow differs from submitted judgment evidence"
            )
        effective_input = prepared_input or expected_input
        protocol = self.request_protocol
        response = await self.client.complete(
            role=self.role,
            models=self.configured_models,
            system_prompt=protocol.system_prompt,
            user_prompt=effective_input.workflow_prompt + render_context(context),
            context_package=context,
            response_model=protocol.response_model,
            schema_name=protocol.schema_name,
            logical_request_id=logical_request_id,
        )
        allowed = {str(group["group_id"]) for group in groups}
        response_ids = [decision.group_id for decision in response.decisions]
        if set(response_ids) - allowed or len(response_ids) != len(set(response_ids)):
            raise OpenRouterSchemaError("judge returned unknown or duplicate candidate groups")
        return JudgeDecisionBatch(
            decisions=[decision for decision in response.decisions if decision.group_id in allowed]
        )
