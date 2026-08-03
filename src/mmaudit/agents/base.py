"""Base implementation for role prompts and structured calls."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib.resources import files
from typing import Any

from mmaudit.config import AuditConfig, model_family
from mmaudit.models.openrouter import (
    OpenRouterClient,
    OpenRouterSchemaError,
    StructuredCompletion,
)
from mmaudit.models.schemas import (
    CandidateFinding,
    CandidateOriginKind,
    CandidateReviewBatch,
    ContextPackage,
    Evidence,
    ModelSurfaceReviewArtifact,
    ModelVote,
    ThreatModel,
    UsageRecord,
)
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.model_review_evidence import (
    ModelReviewEvidenceError,
    seal_model_surface_review_artifact,
)


def load_prompt(name: str) -> str:
    return files("mmaudit.prompts").joinpath(name).read_text(encoding="utf-8")


@dataclass(frozen=True, slots=True)
class AgentRequestProtocol:
    """Exact structured-request protocol shared by planning and dispatch."""

    system_prompt: str
    schema_name: str
    response_model: type[Any]


def build_agent_request_protocol(
    *,
    prompt_file: str,
    schema_name: str,
    response_model: type[Any],
    role_contract: str | None = None,
) -> AgentRequestProtocol:
    """Compose one role prompt exactly once for scheduler sealing and execution."""

    parts = [load_prompt("shared_security_rules.md"), load_prompt(prompt_file)]
    if role_contract is not None:
        parts.extend(("<ROLE_CONTRACT_JSON>", role_contract, "</ROLE_CONTRACT_JSON>"))
    return AgentRequestProtocol(
        system_prompt="\n\n".join(parts),
        schema_name=schema_name,
        response_model=response_model,
    )


def _require_unique_raw_candidate_ids(
    findings: tuple[CandidateFinding, ...] | list[CandidateFinding],
) -> None:
    """Reject one provider response that reuses a raw candidate identity."""

    candidate_ids = [finding.candidate_id for finding in findings]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise OpenRouterSchemaError("model response contained duplicate raw candidate IDs")


def _model_review_origin_candidate_id(
    *,
    request_role: str,
    request_id: str,
    candidate: CandidateFinding,
) -> str:
    """Derive one stable origin ID from exact request and raw candidate evidence."""

    if not request_role or not request_id:
        raise OpenRouterSchemaError("model candidate origin identity is incomplete")
    raw_candidate = candidate.model_dump(
        mode="json",
        exclude={
            "execution_provenance",
            "model_family",
            "model_votes",
            "origin_kind",
            "role",
        },
    )
    payload = {
        "domain": "mmaudit.model-review-origin-candidate.v1",
        "request_id": request_id,
        "request_role": request_role,
        "raw_candidate": raw_candidate,
    }
    digest = hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return f"cand-{digest[:24]}"


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
    completion_usage: UsageRecord
    raw_response: CandidateReviewBatch | None = None


@dataclass(frozen=True, slots=True)
class ValidatedAgentResult[ValueT]:
    """Host-validated role result paired with its exact provider completion."""

    value: ValueT
    completion_usage: UsageRecord
    raw_response: Any | None = None


class ThreatModelAgent(AgentBase):
    role = "threat_model"
    prompt_file = "threat_model.md"

    @property
    def request_protocol(self) -> AgentRequestProtocol:
        return build_agent_request_protocol(
            prompt_file=self.prompt_file,
            schema_name="mmaudit_threat_model",
            response_model=ThreatModel,
        )

    async def run(
        self,
        context: ContextPackage,
        *,
        logical_request_id: str | None = None,
    ) -> ThreatModel:
        protocol = self.request_protocol
        return await self.client.complete(
            role=self.role,
            models=self.configured_models,
            system_prompt=protocol.system_prompt,
            user_prompt=render_context(context),
            context_package=context,
            response_model=protocol.response_model,
            schema_name=protocol.schema_name,
            logical_request_id=logical_request_id,
        )


class FindingAgent(AgentBase):
    @property
    def request_protocol(self) -> AgentRequestProtocol:
        return build_agent_request_protocol(
            prompt_file=self.prompt_file,
            schema_name=f"mmaudit_{self.role}_findings",
            response_model=CandidateReviewBatch,
        )

    async def run(
        self,
        context: ContextPackage,
        *,
        logical_request_id: str | None = None,
    ) -> FindingReviewResult:
        request_context = context.model_copy(deep=True)
        rendered_user_context = render_context(request_context)
        protocol = self.request_protocol
        completion = await self.client.complete_with_evidence(
            role=self.role,
            models=self.configured_models,
            system_prompt=protocol.system_prompt,
            user_prompt=rendered_user_context,
            context_package=request_context,
            response_model=protocol.response_model,
            schema_name=protocol.schema_name,
            logical_request_id=logical_request_id,
        )
        return self.bind_completed_review(
            request_context,
            raw_response=completion.value,
            completion_usage=completion.usage_record,
        )

    def bind_completed_review(
        self,
        context: ContextPackage,
        *,
        raw_response: CandidateReviewBatch,
        completion_usage: UsageRecord,
    ) -> FindingReviewResult:
        """Rebuild one host-validated review from exact retained completion evidence."""

        request_context = context.model_copy(deep=True)
        rendered_user_context = render_context(request_context)
        completion = StructuredCompletion(
            value=CandidateReviewBatch.model_validate(raw_response.model_dump(mode="python")),
            usage_record=UsageRecord.model_validate(completion_usage.model_dump(mode="python")),
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
        _require_unique_raw_candidate_ids(result.findings)
        stamped = []
        for finding in result.findings:
            origin_candidate_id = _model_review_origin_candidate_id(
                request_role=self.role,
                request_id=usage.request_id,
                candidate=finding,
            )
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
            stamped_candidate = finding.model_copy(
                update={
                    "candidate_id": origin_candidate_id,
                    "origin_kind": CandidateOriginKind.MODEL_REVIEW,
                    "execution_provenance": None,
                    "role": self.role,
                    "model_family": family,
                    "model_votes": [vote],
                    "evidence": evidence,
                }
            )
            stamped.append(
                CandidateFinding.model_validate(stamped_candidate.model_dump(mode="python"))
            )
        return FindingReviewResult(
            findings=tuple(stamped),
            surface_review_artifact=surface_review_artifact,
            surface_review_context=request_context,
            completion_usage=usage,
            raw_response=result,
        )


class WholeProtocolReviewAgent(FindingAgent):
    """One exact qualified whole-protocol reviewer with no model fallback."""

    prompt_file = "source_audit.md"

    def __init__(
        self,
        config: AuditConfig,
        client: OpenRouterClient,
        *,
        review_index: int,
        exact_model_id: str,
    ) -> None:
        if review_index < 0 or review_index > 9_999:
            raise ValueError("whole-protocol review index is out of bounds")
        if not exact_model_id or "/" not in exact_model_id:
            raise ValueError("whole-protocol review requires an exact model ID")
        super().__init__(config, client)
        self.role = f"whole_protocol_review:{review_index}"
        self.exact_model_id = exact_model_id

    @property
    def configured_models(self) -> list[str]:
        return [self.exact_model_id]

    @property
    def request_protocol(self) -> AgentRequestProtocol:
        return build_agent_request_protocol(
            prompt_file=self.prompt_file,
            schema_name=f"mmaudit_whole_protocol_review_{self.role.rsplit(':', 1)[1]}",
            response_model=CandidateReviewBatch,
        )
