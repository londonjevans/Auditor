"""Base implementation for role prompts and structured calls."""

from __future__ import annotations

import hashlib
from importlib.resources import files

from mmaudit.config import AuditConfig, model_family
from mmaudit.models.openrouter import OpenRouterClient
from mmaudit.models.schemas import (
    CandidateBatch,
    ContextPackage,
    Evidence,
    ModelVote,
    ThreatModel,
)
from mmaudit.orchestration.context import render_context


def load_prompt(name: str) -> str:
    return files("mmaudit.prompts").joinpath(name).read_text(encoding="utf-8")


class AgentBase:
    role: str
    prompt_file: str

    def __init__(self, config: AuditConfig, client: OpenRouterClient) -> None:
        self.config = config
        self.client = client

    @property
    def configured_models(self) -> list[str]:
        role = self.config.models.role(self.role)
        return [role.primary, *role.fallbacks]

    @property
    def system_prompt(self) -> str:
        return "\n\n".join(
            (
                load_prompt("shared_security_rules.md"),
                load_prompt(self.prompt_file),
            )
        )


class ThreatModelAgent(AgentBase):
    role = "threat_model"
    prompt_file = "threat_model.md"

    async def run(self, context: ContextPackage) -> ThreatModel:
        return await self.client.complete(
            role=self.role,
            models=self.configured_models,
            system_prompt=self.system_prompt,
            user_prompt=render_context(context),
            response_model=ThreatModel,
            schema_name="mmaudit_threat_model",
        )


class FindingAgent(AgentBase):
    async def run(self, context: ContextPackage) -> CandidateBatch:
        result = await self.client.complete(
            role=self.role,
            models=self.configured_models,
            system_prompt=self.system_prompt,
            user_prompt=render_context(context),
            response_model=CandidateBatch,
            schema_name=f"mmaudit_{self.role}_findings",
        )
        primary = self.config.models.role(self.role).primary
        usage = next(
            (
                record
                for record in reversed(self.client.usage.records)
                if record.role == self.role and record.status == "success"
            ),
            None,
        )
        requested = usage.requested_model if usage else primary
        returned = usage.returned_model if usage else None
        family = model_family(requested)
        trusted_scanner_fingerprints = {finding.fingerprint for finding in context.scanner_findings}
        stamped = []
        for finding in result.findings:
            stable_candidate = hashlib.sha256(
                "\0".join(
                    (
                        self.role,
                        finding.title.lower(),
                        finding.locations[0].path,
                        str(finding.locations[0].start_line),
                    )
                ).encode()
            ).hexdigest()[:16]
            vote = ModelVote(
                role=self.role,
                requested_model=requested,
                returned_model=returned,
                family=model_family(requested),
                verdict="proposed",
                rationale=finding.summary,
            )
            evidence: list[Evidence] = []
            for item in finding.evidence:
                if item.type == "scanner" and item.fingerprint in trusted_scanner_fingerprints:
                    evidence.append(item)
                else:
                    evidence.append(
                        Evidence(
                            type="model",
                            source=self.role,
                            description=item.description,
                            rule_id=None,
                            fingerprint=None,
                        )
                    )
            stamped.append(
                finding.model_copy(
                    update={
                        "candidate_id": f"cand-{stable_candidate}",
                        "role": self.role,
                        "model_family": family,
                        "model_votes": [vote],
                        "evidence": evidence,
                    }
                )
            )
        return CandidateBatch(findings=stamped)
