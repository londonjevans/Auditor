"""Base implementation for role prompts and structured calls."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from typing import TYPE_CHECKING, Any

import mmaudit.models.openrouter as _openrouter_module

if TYPE_CHECKING:
    from mmaudit.models.coverage_planning import (
        ModelSurfaceGapTask,
        ModelSurfaceTaskResourcePreview,
    )
    from mmaudit.models.scheduler import SchedulerCampaignManifest, SchedulerTaskPlan

from mmaudit.config import AuditConfig
from mmaudit.models.candidate_review_stamping import (
    CandidateReviewStampingError,
    model_review_origin_candidate_id,
    require_unique_raw_candidate_ids,
    stamp_candidate_review_findings,
)
from mmaudit.models.openrouter import (
    OpenRouterCandidateReviewBoundaryError,
    OpenRouterClient,
    OpenRouterSchemaError,
    StructuredCompletion,
    trusted_complete_candidate_review_with_evidence,
)
from mmaudit.models.retrieval import (
    SolidityRetrievalRequestBatch,
    SolidityRetrievalRolePolicy,
)
from mmaudit.models.schemas import (
    CandidateFinding,
    CandidateReviewBatch,
    ContextPackage,
    ModelSurfaceReviewArtifact,
    ThreatModel,
    UsageRecord,
)
from mmaudit.models.truncation import (
    CandidateReviewFramedDocument,
    CandidateReviewNormalizationEvidence,
)
from mmaudit.models.usage import (
    _validated_usage_copy_preserving_owned_attestation,
    has_exact_nonfallback_model_identity,
)
from mmaudit.orchestration.context import (
    ContextBoundaryError,
    render_context,
    revalidate_context_package,
)
from mmaudit.orchestration.model_review_evidence import (
    ModelReviewEvidenceError,
    seal_model_surface_review_artifact,
)

_RECOVERY_ROOT_REQUEST_ID = re.compile(r"^scheduler-request-[0-9a-f]{64}$")
_RETRIEVAL_PLANNING_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_EXACT_MODEL_ID = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z"
)
_WHOLE_PROTOCOL_REVIEW_ROLE = re.compile(r"^whole_protocol_review:(?:0|[1-9][0-9]{0,3})$")
_MAX_RECOVERY_REQUEST_COUNT = 1_000_000
_TRUSTED_CANDIDATE_REVIEW_COMPLETION_DISPATCH = trusted_complete_candidate_review_with_evidence


def _require_candidate_review_recovery_coordinates(
    *,
    single_route_single_attempt: bool,
    request_limit_scope: str | None,
    request_limit_count_before: int | None,
) -> None:
    recovery_requested = request_limit_scope is not None or request_limit_count_before is not None
    if not recovery_requested:
        return
    if (
        not single_route_single_attempt
        or type(request_limit_scope) is not str
        or _RECOVERY_ROOT_REQUEST_ID.fullmatch(request_limit_scope) is None
        or type(request_limit_count_before) is not int
        or not 1 <= request_limit_count_before <= _MAX_RECOVERY_REQUEST_COUNT
    ):
        raise OpenRouterSchemaError(
            "candidate-review recovery requires exact one-route/one-attempt coordinates"
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

    try:
        require_unique_raw_candidate_ids(findings)
    except CandidateReviewStampingError as exc:
        raise OpenRouterSchemaError(str(exc)) from None


def _model_review_origin_candidate_id(
    *,
    request_role: str,
    request_id: str,
    candidate: CandidateFinding,
) -> str:
    """Derive one stable origin ID from exact request and raw candidate evidence."""

    try:
        return model_review_origin_candidate_id(
            request_role=request_role,
            request_id=request_id,
            candidate=candidate,
        )
    except CandidateReviewStampingError as exc:
        raise OpenRouterSchemaError(str(exc)) from None


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
    normalization_evidence: CandidateReviewNormalizationEvidence | None = None


@dataclass(frozen=True, slots=True)
class RetrievalPlanningResult:
    """Non-crediting retrieval intents plus their exact request custody."""

    request_batch: SolidityRetrievalRequestBatch
    planning_context: ContextPackage
    completion_usage: UsageRecord

    def __post_init__(self) -> None:
        if (
            type(self.request_batch) is not SolidityRetrievalRequestBatch
            or type(self.planning_context) is not ContextPackage
            or type(self.completion_usage) is not UsageRecord
        ):
            raise TypeError("retrieval planning result has an invalid exact custody type")
        try:
            request_batch = SolidityRetrievalRequestBatch.model_validate_json(
                self.request_batch.model_dump_json(),
                strict=True,
            )
            planning_context = revalidate_context_package(self.planning_context)
            completion_usage = _validated_usage_copy_preserving_owned_attestation(
                self.completion_usage
            )
        except (AttributeError, ContextBoundaryError, TypeError, ValueError) as exc:
            raise ValueError("retrieval planning result failed detached validation") from exc
        if (
            request_batch != self.request_batch
            or planning_context != self.planning_context
            or completion_usage != self.completion_usage
        ):
            raise ValueError("retrieval planning result changed after detached validation")
        object.__setattr__(self, "request_batch", request_batch)
        object.__setattr__(self, "planning_context", planning_context)
        object.__setattr__(self, "completion_usage", completion_usage)


@dataclass(frozen=True, slots=True)
class ValidatedAgentResult[ValueT]:
    """Host-validated role result paired with its exact provider completion."""

    value: ValueT
    completion_usage: UsageRecord
    raw_response: Any | None = None


def _retrieval_context_role_matches(*, request_role: str, context_role: str) -> bool:
    return request_role == context_role or (
        context_role == "whole_protocol_review"
        and _WHOLE_PROTOCOL_REVIEW_ROLE.fullmatch(request_role) is not None
    )


class RetrievalPlanningAgent(AgentBase):
    """Request one bounded, non-crediting retrieval-intent batch for an exact reviewer."""

    prompt_file = "retrieval_planning.md"

    def __init__(
        self,
        config: AuditConfig,
        client: OpenRouterClient,
        *,
        role: str,
        exact_model_id: str,
    ) -> None:
        super().__init__(config, client)
        if type(role) is not str:
            raise TypeError("retrieval planning role must be an exact string")
        try:
            SolidityRetrievalRolePolicy.build(role=role)
        except ValueError as exc:
            raise ValueError("retrieval planning role is not supported") from exc
        if type(exact_model_id) is not str or _EXACT_MODEL_ID.fullmatch(exact_model_id) is None:
            raise ValueError("retrieval planning requires an exact provider/model ID")

        if _WHOLE_PROTOCOL_REVIEW_ROLE.fullmatch(role) is None:
            configured_role = (
                role.removeprefix("specialist:").split(":", 1)[0]
                if role.startswith("specialist:")
                else role
            )
            try:
                configured = config.models.role(configured_role)
            except (KeyError, TypeError) as exc:
                raise ValueError(
                    "retrieval planning role has no configured model identity"
                ) from exc
            if exact_model_id not in (configured.primary, *configured.fallbacks):
                raise ValueError(
                    "retrieval planning model differs from the configured reviewer identity"
                )

        self.role = role
        self.exact_model_id = exact_model_id

    @property
    def configured_models(self) -> list[str]:
        """Expose the one exact review route shared by planning and final review."""

        return [self.exact_model_id]

    @property
    def request_protocol(self) -> AgentRequestProtocol:
        return build_agent_request_protocol(
            prompt_file=self.prompt_file,
            schema_name="mmaudit_solidity_retrieval_request_batch",
            response_model=SolidityRetrievalRequestBatch,
        )

    async def run(
        self,
        context: ContextPackage,
        *,
        logical_request_id: str,
    ) -> RetrievalPlanningResult:
        if (
            type(logical_request_id) is not str
            or _RETRIEVAL_PLANNING_REQUEST_ID.fullmatch(logical_request_id) is None
        ):
            raise OpenRouterSchemaError(
                "retrieval planning requires a separate bounded logical request ID"
            )
        request_context = self._detached_context(context)
        protocol = self.request_protocol
        completion = await self.client.complete_with_evidence(
            role=self.role,
            models=self.configured_models,
            system_prompt=protocol.system_prompt,
            user_prompt=render_context(request_context),
            context_package=request_context,
            response_model=protocol.response_model,
            schema_name=protocol.schema_name,
            logical_request_id=logical_request_id,
        )
        return self.bind_completed_plan(
            request_context,
            raw_response=completion.value,
            completion_usage=completion.usage_record,
            logical_request_id=logical_request_id,
        )

    def bind_completed_plan(
        self,
        context: ContextPackage,
        *,
        raw_response: SolidityRetrievalRequestBatch,
        completion_usage: UsageRecord,
        logical_request_id: str,
    ) -> RetrievalPlanningResult:
        """Detach and bind one retained planning completion to its exact review identity."""

        if (
            type(logical_request_id) is not str
            or _RETRIEVAL_PLANNING_REQUEST_ID.fullmatch(logical_request_id) is None
        ):
            raise OpenRouterSchemaError("retrieval planning logical request ID is invalid")
        request_context = self._detached_context(context)
        if type(raw_response) is not SolidityRetrievalRequestBatch:
            raise OpenRouterSchemaError("retrieval planning batch has an invalid exact type")
        try:
            request_batch = SolidityRetrievalRequestBatch.model_validate_json(
                raw_response.model_dump_json(),
                strict=True,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise OpenRouterSchemaError(
                "retrieval planning batch failed detached validation"
            ) from exc
        if request_batch != raw_response:
            raise OpenRouterSchemaError("retrieval planning batch changed after validation")
        policy = request_context.solidity_retrieval_policy
        if policy is None:  # Defensive: _detached_context requires this exact binding.
            raise OpenRouterSchemaError("retrieval planning context lacks its exact role policy")
        if len(request_batch.requests) > policy.maximum_requests:
            raise OpenRouterSchemaError(
                "retrieval planning batch exceeds its exact role request limit"
            )

        if type(completion_usage) is not UsageRecord:
            raise OpenRouterSchemaError("retrieval planning usage has an invalid exact type")
        try:
            usage = _validated_usage_copy_preserving_owned_attestation(completion_usage)
        except (AttributeError, TypeError, ValueError) as exc:
            raise OpenRouterSchemaError("retrieval planning usage failed exact validation") from exc
        if usage != completion_usage:
            raise OpenRouterSchemaError("retrieval planning usage changed after validation")
        if (
            usage.request_id != logical_request_id
            or usage.role != self.role
            or usage.requested_model != self.exact_model_id
            or not has_exact_nonfallback_model_identity(usage)
        ):
            raise OpenRouterSchemaError(
                "retrieval planning usage differs from its exact request identity"
            )
        protocol = self.request_protocol
        request_hashes = self.client.preview_structured_request_hashes(
            role=self.role,
            model=self.exact_model_id,
            system_prompt=protocol.system_prompt,
            user_prompt=render_context(request_context),
            response_model=protocol.response_model,
            schema_name=protocol.schema_name,
        )
        validated_response_sha256 = hashlib.sha256(
            json.dumps(
                request_batch.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        if (
            usage.prompt_sha256 != request_hashes.prompt_sha256
            or usage.user_prompt_sha256 != request_hashes.user_prompt_sha256
            or usage.schema_sha256 != request_hashes.schema_sha256
            or usage.validated_response_sha256 != validated_response_sha256
        ):
            raise OpenRouterSchemaError(
                "retrieval planning usage differs from its exact prompt or response custody"
            )
        return RetrievalPlanningResult(
            request_batch=request_batch,
            planning_context=request_context,
            completion_usage=usage,
        )

    def _detached_context(self, context: ContextPackage) -> ContextPackage:
        if type(context) is not ContextPackage:
            raise OpenRouterSchemaError("retrieval planning context has an invalid exact type")
        try:
            request_context = revalidate_context_package(context)
        except ContextBoundaryError as exc:
            raise OpenRouterSchemaError(
                "retrieval planning context failed detached validation"
            ) from exc
        if not _retrieval_context_role_matches(
            request_role=self.role,
            context_role=request_context.role,
        ):
            raise OpenRouterSchemaError(
                "retrieval planning context differs from its configured review role"
            )
        policy = request_context.solidity_retrieval_policy
        if policy is None or request_context.solidity_retrieval_corpus_sha256 is None:
            raise OpenRouterSchemaError(
                "retrieval planning requires a retrieval-bound planning context"
            )
        if policy.role != self.role:
            raise OpenRouterSchemaError(
                "retrieval planning policy differs from its configured review role"
            )
        if request_context.solidity_retrieval_transcript is not None:
            raise OpenRouterSchemaError(
                "retrieval planning requires a transcript-free planning context"
            )
        return request_context


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
            response_model=CandidateReviewFramedDocument,
        )

    async def run(
        self,
        context: ContextPackage,
        *,
        logical_request_id: str | None = None,
        single_route_single_attempt: bool = False,
        recovery_request_limit_scope: str | None = None,
        recovery_request_limit_count_before: int | None = None,
        expected_resource_preview: ModelSurfaceTaskResourcePreview | None = None,
        coverage_task: ModelSurfaceGapTask | None = None,
        scheduler_task: SchedulerTaskPlan | None = None,
        campaign_manifest: SchedulerCampaignManifest | None = None,
        resource_preview_checked_at: datetime | None = None,
    ) -> FindingReviewResult:
        _require_candidate_review_recovery_coordinates(
            single_route_single_attempt=single_route_single_attempt,
            request_limit_scope=recovery_request_limit_scope,
            request_limit_count_before=recovery_request_limit_count_before,
        )
        request_context = context.model_copy(deep=True)
        rendered_user_context = render_context(request_context)
        protocol = self.request_protocol
        if (
            trusted_complete_candidate_review_with_evidence
            is not _TRUSTED_CANDIDATE_REVIEW_COMPLETION_DISPATCH
            or _openrouter_module.trusted_complete_candidate_review_with_evidence
            is not _TRUSTED_CANDIDATE_REVIEW_COMPLETION_DISPATCH
        ):
            raise OpenRouterCandidateReviewBoundaryError(
                "candidate-review agent dispatch binding changed before provider work"
            )
        completion = await _TRUSTED_CANDIDATE_REVIEW_COMPLETION_DISPATCH(
            self.client,
            role=self.role,
            models=(
                [coverage_task.requested_model]
                if expected_resource_preview is not None and coverage_task is not None
                else self.configured_models
            ),
            system_prompt=protocol.system_prompt,
            user_prompt=rendered_user_context,
            context_package=request_context,
            schema_name=protocol.schema_name,
            logical_request_id=logical_request_id,
            single_route_single_attempt=single_route_single_attempt,
            expected_resource_preview=expected_resource_preview,
            coverage_task=coverage_task,
            scheduler_task=scheduler_task,
            campaign_manifest=campaign_manifest,
            resource_preview_checked_at=resource_preview_checked_at,
        )
        return self.bind_completed_review(
            request_context,
            raw_response=completion.value,
            completion_usage=completion.usage_record,
            normalization_evidence=completion.normalization_evidence,
            recovery_request_limit_scope=recovery_request_limit_scope,
            recovery_request_limit_count_before=recovery_request_limit_count_before,
        )

    def bind_completed_review(
        self,
        context: ContextPackage,
        *,
        raw_response: CandidateReviewBatch,
        completion_usage: UsageRecord,
        normalization_evidence: CandidateReviewNormalizationEvidence | None = None,
        recovery_request_limit_scope: str | None = None,
        recovery_request_limit_count_before: int | None = None,
    ) -> FindingReviewResult:
        """Rebuild one host-validated review from exact retained completion evidence."""

        request_context = context.model_copy(deep=True)
        rendered_user_context = render_context(request_context)
        bound_normalization_evidence = None
        if normalization_evidence is not None:
            if type(normalization_evidence) is not CandidateReviewNormalizationEvidence:
                raise OpenRouterSchemaError(
                    "candidate-review normalization custody has an invalid exact type"
                )
            bound_normalization_evidence = CandidateReviewNormalizationEvidence.model_validate_json(
                normalization_evidence.model_dump_json(),
                strict=True,
            )
        if type(completion_usage) is not UsageRecord:
            raise OpenRouterSchemaError("candidate-review usage has an invalid exact type")
        try:
            validated_usage = _validated_usage_copy_preserving_owned_attestation(completion_usage)
        except (TypeError, ValueError) as exc:
            raise OpenRouterSchemaError("candidate-review usage failed exact validation") from exc
        if validated_usage != completion_usage:
            raise OpenRouterSchemaError("candidate-review usage changed after validation")
        completion = StructuredCompletion(
            value=CandidateReviewBatch.model_validate(raw_response.model_dump(mode="python")),
            usage_record=validated_usage,
        )
        result = completion.value
        usage = completion.usage_record
        try:
            surface_review_artifact = seal_model_surface_review_artifact(
                context=request_context,
                completion=completion,
                rendered_user_context=rendered_user_context,
                normalization_evidence=bound_normalization_evidence,
                recovery_request_limit_scope=recovery_request_limit_scope,
                recovery_request_limit_count_before=recovery_request_limit_count_before,
            )
        except ModelReviewEvidenceError as exc:
            raise OpenRouterSchemaError(
                f"model response did not provide valid requested-surface evidence: {exc}"
            ) from None
        try:
            stamped = stamp_candidate_review_findings(
                request_role=self.role,
                usage_record=usage,
                trusted_scanner_fingerprints=tuple(
                    sorted({finding.fingerprint for finding in request_context.scanner_findings})
                ),
                raw_findings=result.findings,
            )
        except CandidateReviewStampingError as exc:
            raise OpenRouterSchemaError(f"candidate-review stamping failed: {exc}") from None
        return FindingReviewResult(
            findings=stamped,
            surface_review_artifact=surface_review_artifact,
            surface_review_context=request_context,
            completion_usage=usage,
            raw_response=result,
            normalization_evidence=bound_normalization_evidence,
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
            response_model=CandidateReviewFramedDocument,
        )
