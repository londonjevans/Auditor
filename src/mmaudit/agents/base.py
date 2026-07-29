"""Base implementation for role prompts and structured calls."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from importlib.resources import files

from mmaudit.config import AuditConfig, model_family
from mmaudit.models.openrouter import OpenRouterClient, OpenRouterSchemaError
from mmaudit.models.schemas import (
    CandidateFinding,
    CandidateReviewBatch,
    ContextPackage,
    Evidence,
    ModelSurfaceReviewArtifact,
    ModelVote,
    ThreatModel,
)
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.model_review_evidence import (
    ModelReviewEvidenceError,
    seal_model_surface_review_artifact,
)


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


@dataclass(frozen=True, slots=True)
class FindingReviewResult:
    """Stamped candidates plus the exact response-backed surface evidence."""

    findings: tuple[CandidateFinding, ...]
    surface_review_artifact: ModelSurfaceReviewArtifact | None
    surface_review_context: ContextPackage


class ThreatModelAgent(AgentBase):
    role = "threat_model"
    prompt_file = "threat_model.md"

    async def run(self, context: ContextPackage) -> ThreatModel:
        return await self.client.complete(
            role=self.role,
            models=self.configured_models,
            system_prompt=self.system_prompt,
            user_prompt=render_context(context),
            context_package=context,
            response_model=ThreatModel,
            schema_name="mmaudit_threat_model",
        )


class FindingAgent(AgentBase):
    async def run(self, context: ContextPackage) -> FindingReviewResult:
        request_context = context.model_copy(deep=True)
        rendered_user_context = render_context(request_context)
        completion = await self.client.complete_with_evidence(
            role=self.role,
            models=self.configured_models,
            system_prompt=self.system_prompt,
            user_prompt=rendered_user_context,
            context_package=request_context,
            response_model=CandidateReviewBatch,
            schema_name=f"mmaudit_{self.role}_findings",
        )
        result = completion.value
        usage = completion.usage_record
        try:
            surface_review_artifact = seal_model_surface_review_artifact(
                context=request_context,
                completion=completion,
                rendered_user_context=rendered_user_context,
            )
        except ModelReviewEvidenceError as exc:
            raise OpenRouterSchemaError(
                f"model response did not provide valid requested-surface evidence: {exc}"
            ) from None
        requested = usage.requested_model
        returned = usage.returned_model
        family = model_family(requested)
        trusted_scanner_fingerprints = {
            finding.fingerprint for finding in request_context.scanner_findings
        }
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
        return FindingReviewResult(
            findings=tuple(stamped),
            surface_review_artifact=surface_review_artifact,
            surface_review_context=request_context,
        )
