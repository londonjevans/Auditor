"""Immutable contracts for the resumable seven-pass audit scheduler.

The models in this module are deliberately free of filesystem, provider, and
pipeline behavior.  They define stable identities and fail-closed joins that a
durable journal or runtime scheduler can enforce without treating a self-hash as
proof of source origin.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from functools import cache
from itertools import islice
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator
from pydantic_core import SchemaValidator

from mmaudit.constants import SEVERITY_ORDER, SPECIALIST_INVESTIGATOR_ROLES
from mmaudit.models.candidate_review_stamping import (
    CandidateReviewStampingError,
    model_review_origin_candidate_id,
    stamp_candidate_review_findings,
)
from mmaudit.models.openrouter import strict_json_schema_sha256
from mmaudit.models.retrieval import (
    SOLIDITY_RETRIEVAL_MAX_EXCHANGES,
    SolidityRetrievalRequestBatch,
    SolidityRetrievalRoleBudgetAllocation,
    SolidityRetrievalRoleBudgetPlan,
    SolidityRetrievalTranscript,
    require_solidity_retrieval_transcript_within_policy,
)
from mmaudit.models.schemas import (
    CandidateCrossExaminationDecision,
    CandidateCrossExaminationResponse,
    CandidateFinding,
    CandidateOriginKind,
    CandidateReproductionResolution,
    CandidateReviewBatch,
    ConsensusReviewArtifact,
    ContextRequestEvidence,
    ExecutionEvidenceKind,
    FalsificationBatch,
    FalsificationDecision,
    Finding,
    FindingOriginKind,
    FindingStatus,
    GeneratedFoundryTestBatch,
    GeneratedFoundryTestSpec,
    InvariantReviewBatch,
    JudgeDecision,
    JudgeDecisionBatch,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
    ReportQualityReview,
    ReproductionResult,
    Severity,
    SpecialistAcceptedOutcome,
    SpecialistAcceptedOutcomeKind,
    StrictModel,
    ThreatModel,
    UsageRecord,
    VerificationBatch,
    VerificationDecision,
)
from mmaudit.models.truncation import (
    CandidateReviewChannelState,
    CandidateReviewFramedDocument,
    CandidateReviewFramePhase,
    CandidateReviewNormalizationEvidence,
    CandidateReviewTruncatedEnvelopeEvidence,
    CandidateReviewTruncationProjection,
    candidate_review_batch_schema_sha256,
    candidate_review_frame_wire_schema_sha256,
    candidate_review_protocol_implementation_is_pristine,
    candidate_review_schema_algorithm_version,
    candidate_review_wire_schema_algorithm_version,
)
from mmaudit.models.truncation_recovery import (
    TRUNCATION_RECOVERY_MAX_CHILD_COMPLETION_TOKENS,
    TRUNCATION_RECOVERY_MAX_CHILD_PROVIDER_ATTEMPTS,
    TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    TruncationRecoveryChildPlan,
)
from mmaudit.models.truncation_recovery_journal import (
    SCHEDULER_TRUNCATION_RECOVERY_MAX_ENTRIES,
    SchedulerRecoveredCandidateOriginKind,
    SchedulerTruncationRecoveryChildActivation,
    SchedulerTruncationRecoveryChildDispatch,
    SchedulerTruncationRecoveryChildPreflightResult,
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryClosureStatus,
    SchedulerTruncationRecoveryCostDisposition,
    SchedulerTruncationRecoveryEntry,
    SchedulerTruncationRecoveryFamilyClosure,
    SchedulerTruncationRecoveryFamilyPromotion,
    SchedulerTruncationRecoveryFamilyRoot,
    SchedulerTruncationRecoveryParentKind,
    SchedulerTruncationRecoveryPromotionBinding,
    SchedulerTruncationRecoveryRequestLimitBinding,
    SchedulerTruncationRecoveryResultOrigin,
    SchedulerTruncationRecoveryTerminalStatus,
    validate_truncation_recovery_entry_chain,
)
from mmaudit.models.usage import (
    atomic_request_limit_reservations_from_usage,
    atomic_token_reservations_from_usage,
    is_structurally_accountable_usage_record,
    is_structurally_creditable_usage_record,
    usage_requires_audit_policy_evidence,
)

if TYPE_CHECKING:
    from mmaudit.models.policy_selection import (
        AuditModelRoutingEvidence,
        AuditModelSelectionEvidenceBundle,
    )
    from mmaudit.models.refresh_runtime import (
        AuditModelRefreshEvidence,
        AuditModelRefreshPricingEvidence,
    )

SchedulerAlgorithmVersion = Literal[
    "mmaudit.seven-pass-scheduler.v1",
    "mmaudit.seven-pass-scheduler.v2",
]
SCHEDULER_ALGORITHM_VERSION: SchedulerAlgorithmVersion = "mmaudit.seven-pass-scheduler.v2"
SCHEDULER_ANALYSIS_INPUT_LABELS_V1 = (
    "run_options",
    "discovery",
    "repository_map",
    "repository_execution_sha256",
    "scanner_source_sha256",
    "dependency_preparation",
    "scope_assessment",
    "projects",
    "compilations",
    "index",
    "graphs",
    "semantic_shards",
    "invariants",
    "invariant_harnesses",
    "invariant_executions",
    "property_corpus",
    "economic_simulations",
    "formal_runs",
    "scanner_runs",
    "repository_suite_differential",
    "solidity_coverage",
    "execution_candidate_build",
    "model_surface_requests",
    "model_surface_review_assignments",
)
SCHEDULER_ANALYSIS_INPUT_LABELS = (
    "actor_model_evidence",
    *SCHEDULER_ANALYSIS_INPUT_LABELS_V1,
)
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SHARD_ID_PATTERN = r"^shard-[0-9a-f]{24}$"
_MODEL_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
_PROVIDER_ENDPOINT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$"
_PROVIDER_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9 ._:/()&+-]{0,199}$"
_SAFE_KEY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_ROLE_PATTERN = r"^[a-z][a-z0-9_:.-]{0,127}$"
_MAX_TASK_OUTPUT_BYTES = 100_000_000
_MAX_PRIVACY_EVIDENCE_BYTES = 1_048_576
_MAX_SCHEDULER_MODEL_REQUESTS = 700_000
_USD_EXACT_PATTERN = r"^(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,18})?$"
_WHOLE_PROTOCOL_REVIEW_ROLE = re.compile(r"^whole_protocol_review:(?:0|[1-9][0-9]{0,3})$")
_SPECIALIST_INVESTIGATOR_REQUEST_ROLES = frozenset(
    f"specialist:{role}" for role in SPECIALIST_INVESTIGATOR_ROLES
)
_BLIND_SHARD_REVIEW_ROLES = frozenset(
    {
        "source_audit",
        "business_logic",
        "configuration",
        *_SPECIALIST_INVESTIGATOR_REQUEST_ROLES,
    }
)
_SPECIALIST_ACCEPTED_OUTCOME_ROLES = frozenset(
    {
        *(f"specialist:{role}" for role in SPECIALIST_INVESTIGATOR_ROLES),
        "specialist:invariant_review",
        "specialist:falsifier",
        "specialist:report_quality",
        "specialist:test_generation:exploit_test",
        "specialist:exploit_reproduction_planner:exploit_test",
    }
)
_SCHEDULER_RESPONSE_MODELS: tuple[type[BaseModel], ...] = (
    CandidateCrossExaminationResponse,
    CandidateReviewBatch,
    CandidateReviewFramedDocument,
    FalsificationBatch,
    GeneratedFoundryTestBatch,
    InvariantReviewBatch,
    JudgeDecisionBatch,
    ReportQualityReview,
    ThreatModel,
    VerificationBatch,
)
_SCHEDULER_AUXILIARY_RESPONSE_MODELS: tuple[type[BaseModel], ...] = (SolidityRetrievalRequestBatch,)
_SCHEDULER_V1_ACTOR_NEUTRAL_RESPONSE_SCHEMA_SHA256S: Mapping[type[BaseModel], str] = (
    MappingProxyType(
        {
            CandidateReviewBatch: (
                "29158e2c31350751f683bfa2910db39d2883d3258ef7fc41a1479d4f3133c186"
            ),
            CandidateReviewFramedDocument: (
                "478bc1d7e11e4ae1635c371ef1965025f012b5c9056af08d7a4c729425cb46a1"
            ),
            JudgeDecisionBatch: (
                "07163523897a848ac18dbed0eb64978fc0aa89381512afddc6a18d2d9b113b09"
            ),
        }
    )
)


@dataclass(frozen=True, slots=True)
class _SchedulerResponseSchemaBinding:
    """Immutable custody for one exact registered Pydantic schema generation."""

    response_model: type[BaseModel]
    validator: SchemaValidator
    core_schema: object
    schema_sha256: str

    @classmethod
    def capture(cls, response_model: type[BaseModel]) -> _SchedulerResponseSchemaBinding:
        validator = getattr(response_model, "__pydantic_validator__", None)
        core_schema = getattr(response_model, "__pydantic_core_schema__", None)
        if not isinstance(validator, SchemaValidator) or core_schema is None:
            raise ValueError("scheduler response model lacks a live Pydantic schema")
        schema_sha256 = strict_json_schema_sha256(response_model)
        if (
            getattr(response_model, "__pydantic_validator__", None) is not validator
            or getattr(response_model, "__pydantic_core_schema__", None) is not core_schema
        ):
            raise ValueError("scheduler response model changed during registry construction")
        return cls(
            response_model=response_model,
            validator=cast(SchemaValidator, validator),
            core_schema=core_schema,
            schema_sha256=schema_sha256,
        )

    def require_current(self) -> None:
        if (
            getattr(self.response_model, "__pydantic_validator__", None) is not self.validator
            or getattr(self.response_model, "__pydantic_core_schema__", None)
            is not self.core_schema
            or strict_json_schema_sha256(self.response_model) != self.schema_sha256
        ):
            raise ValueError("scheduler response model schema drifted after registry construction")


def scheduler_role_requires_specialist_accepted_outcome(role: str) -> bool:
    """Return whether ``role`` has an exact accepted-specialist evidence contract.

    Some base investigators reuse specialist-shaped ``:exploit_test`` routing labels
    to invoke the bounded reproduction planner. Those fallback labels are provider
    policy identities, not configured specialist responsibilities, and therefore
    cannot claim or require ``SpecialistAcceptedOutcome`` credit.
    """

    return role in _SPECIALIST_ACCEPTED_OUTCOME_ROLES


def scheduler_task_requires_specialist_accepted_outcome(task: SchedulerTaskPlan) -> bool:
    """Apply specialist acceptance only to substantive primary model work."""

    return (
        task.purpose is SchedulerTaskPurpose.PRIMARY
        and scheduler_role_requires_specialist_accepted_outcome(task.role)
    )


def _bounded_scheduler_items[ItemT](
    values: Iterable[ItemT],
    *,
    limit: int,
    label: str,
) -> tuple[ItemT, ...]:
    """Materialize one untrusted scheduler inventory without trusting length hints."""

    items = tuple(islice(iter(values), limit + 1))
    if len(items) > limit:
        raise ValueError(f"scheduler {label} exceeds its item limit")
    return items


def _json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    raise TypeError(f"unsupported scheduler canonical value: {type(value).__name__}")


def scheduler_canonical_sha256(value: Any) -> str:
    """Return the scheduler's canonical JSON digest."""

    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=_json_default,
        ).encode("utf-8")
    ).hexdigest()


_LEGACY_ACTOR_ANNOTATION_FIELDS = frozenset(
    {
        "actor_model_applicability",
        "actor_context",
    }
)


def _strip_legacy_actor_annotations(value: object, projection: object) -> None:
    """Remove only actor fields absent from exact scheduler-v1 typed payloads."""

    if isinstance(value, CandidateFinding | JudgeDecision):
        if value.actor_model_applicability.value != "unstated" or value.actor_context is not None:
            raise ValueError("scheduler v1 typed payload cannot carry actor annotations")
        if not isinstance(projection, dict):
            raise TypeError("scheduler typed payload projection has an invalid object shape")
        for field_name in _LEGACY_ACTOR_ANNOTATION_FIELDS:
            projection.pop(field_name, None)
    if isinstance(value, BaseModel):
        if not isinstance(projection, dict):
            raise TypeError("scheduler typed payload projection has an invalid model shape")
        for field_name in type(value).model_fields:
            if field_name in projection:
                _strip_legacy_actor_annotations(getattr(value, field_name), projection[field_name])
        return
    if isinstance(value, Mapping):
        if not isinstance(projection, dict):
            raise TypeError("scheduler typed payload projection has an invalid mapping shape")
        for key, item in value.items():
            projected_key = key.value if isinstance(key, StrEnum) else key
            if projected_key in projection:
                _strip_legacy_actor_annotations(item, projection[projected_key])
        return
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        if not isinstance(projection, list) or len(value) != len(projection):
            raise TypeError("scheduler typed payload projection has an invalid sequence shape")
        for item, projected_item in zip(value, projection, strict=True):
            _strip_legacy_actor_annotations(item, projected_item)


def scheduler_typed_payload_projection(
    value: BaseModel,
    *,
    algorithm_version: str,
) -> Any:
    """Serialize a typed payload under one exact scheduler algorithm contract.

    Version 1 predates typed actor annotations and therefore omits exactly those
    fields from candidate and judge records. Version 2 retains the current full,
    explicit wire representation, including actor-neutral default values.
    """

    if not isinstance(value, BaseModel):
        raise TypeError("scheduler typed payload projection requires a Pydantic model")
    if algorithm_version not in {
        "mmaudit.seven-pass-scheduler.v1",
        "mmaudit.seven-pass-scheduler.v2",
    }:
        raise ValueError("scheduler typed payload projection uses an unknown algorithm")
    projection = value.model_dump(mode="json")
    if algorithm_version == "mmaudit.seven-pass-scheduler.v1":
        _strip_legacy_actor_annotations(value, projection)
    return projection


def scheduler_candidate_payload_sha256(
    candidate: CandidateFinding,
    *,
    algorithm_version: str,
) -> str:
    """Hash one candidate under the exact scheduler algorithm serialization."""

    return scheduler_canonical_sha256(
        scheduler_typed_payload_projection(
            candidate,
            algorithm_version=algorithm_version,
        )
    )


def _scheduler_value_projection(value: Any, *, algorithm_version: str) -> Any:
    """Project an arbitrary scheduler hash body through typed model boundaries."""

    if isinstance(value, BaseModel):
        return scheduler_typed_payload_projection(value, algorithm_version=algorithm_version)
    if isinstance(value, Mapping):
        return {
            key: _scheduler_value_projection(item, algorithm_version=algorithm_version)
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return [
            _scheduler_value_projection(item, algorithm_version=algorithm_version) for item in value
        ]
    return value


@cache
def _scheduler_response_schema_model_registry() -> Mapping[str, _SchedulerResponseSchemaBinding]:
    """Build the closed response registry with exact validator-generation custody."""

    bindings = tuple(
        _SchedulerResponseSchemaBinding.capture(model) for model in _SCHEDULER_RESPONSE_MODELS
    )
    registry = {binding.schema_sha256: binding for binding in bindings}
    if len(registry) != len(_SCHEDULER_RESPONSE_MODELS):
        raise ValueError("scheduler response model registry contains a schema-hash collision")
    return MappingProxyType(registry)


@cache
def _scheduler_auxiliary_response_schema_model_registry() -> Mapping[
    str, _SchedulerResponseSchemaBinding
]:
    """Bind auxiliary wire schemas without changing frozen primary inventories."""

    bindings = tuple(
        _SchedulerResponseSchemaBinding.capture(model)
        for model in _SCHEDULER_AUXILIARY_RESPONSE_MODELS
    )
    registry = {binding.schema_sha256: binding for binding in bindings}
    if len(registry) != len(_SCHEDULER_AUXILIARY_RESPONSE_MODELS):
        raise ValueError("scheduler auxiliary response registry contains a schema-hash collision")
    if set(registry) & set(_scheduler_response_schema_model_registry()):
        raise ValueError("scheduler primary and auxiliary response schemas collide")
    return MappingProxyType(registry)


def _scheduler_all_response_schema_model_registry() -> Mapping[
    str, _SchedulerResponseSchemaBinding
]:
    """Return a live primary-plus-auxiliary view for exact task parsing."""

    return MappingProxyType(
        {
            **_scheduler_response_schema_model_registry(),
            **_scheduler_auxiliary_response_schema_model_registry(),
        }
    )


def scheduler_response_schema_model_registry() -> dict[str, type[BaseModel]]:
    """Return a copy only when every fixed response class still has its frozen schema."""

    registry = _scheduler_response_schema_model_registry()
    for binding in registry.values():
        binding.require_current()
    return {schema_sha256: binding.response_model for schema_sha256, binding in registry.items()}


def scheduler_auxiliary_response_schema_model_registry() -> dict[str, type[BaseModel]]:
    """Return the detached purpose-specific auxiliary response registry."""

    registry = _scheduler_auxiliary_response_schema_model_registry()
    for binding in registry.values():
        binding.require_current()
    return {schema_sha256: binding.response_model for schema_sha256, binding in registry.items()}


def scheduler_response_schema_sha256(response_model: type[Any]) -> str:
    """Return the registered strict-schema hash without regenerating its schema."""

    registry = _scheduler_all_response_schema_model_registry()
    for binding in registry.values():
        binding.require_current()
    matches = tuple(
        schema_sha256
        for schema_sha256, binding in registry.items()
        if binding.response_model is response_model
    )
    if len(matches) != 1:
        raise ValueError("scheduler response model is not registered exactly once")
    return matches[0]


def scheduler_response_schema_sha256_for_algorithm(
    response_model: type[Any],
    *,
    algorithm_version: str,
) -> str:
    """Return the exact current or actor-neutral v1 response-schema digest."""

    if algorithm_version == "mmaudit.seven-pass-scheduler.v1":
        legacy = _SCHEDULER_V1_ACTOR_NEUTRAL_RESPONSE_SCHEMA_SHA256S.get(response_model)
        if legacy is not None:
            return legacy
    elif algorithm_version != "mmaudit.seven-pass-scheduler.v2":
        raise ValueError("scheduler response schema uses an unknown algorithm")
    return scheduler_response_schema_sha256(response_model)


def scheduler_response_schema_inventory_for_algorithm(
    *,
    algorithm_version: str,
) -> tuple[dict[str, str], ...]:
    """Return the closed response-schema inventory for one scheduler algorithm."""

    registry = _scheduler_response_schema_model_registry()
    models = tuple(binding.response_model for binding in registry.values())
    if len(models) != len(set(models)):
        raise ValueError("scheduler response-schema registry contains a duplicate type")
    return tuple(
        {
            "model_type": f"{model.__module__}.{model.__qualname__}",
            "schema_sha256": scheduler_response_schema_sha256_for_algorithm(
                model,
                algorithm_version=algorithm_version,
            ),
        }
        for model in sorted(models, key=lambda item: f"{item.__module__}.{item.__qualname__}")
    )


def scheduler_response_schema_hashes_for_algorithm(
    *,
    algorithm_version: str,
) -> frozenset[str]:
    """Return the exact response-schema hashes permitted by one scheduler algorithm."""

    return frozenset(
        item["schema_sha256"]
        for item in scheduler_response_schema_inventory_for_algorithm(
            algorithm_version=algorithm_version,
        )
    )


def scheduler_response_schema_set_sha256_for_algorithm(
    *,
    algorithm_version: str,
) -> str:
    """Hash the closed response-schema inventory for one scheduler algorithm."""

    return scheduler_canonical_sha256(
        scheduler_response_schema_inventory_for_algorithm(
            algorithm_version=algorithm_version,
        )
    )


def scheduler_auxiliary_response_schema_inventory_for_algorithm(
    *,
    algorithm_version: str,
) -> tuple[dict[str, str], ...]:
    """Return purpose-scoped schemas without changing the frozen primary set."""

    if algorithm_version == "mmaudit.seven-pass-scheduler.v1":
        return ()
    if algorithm_version != "mmaudit.seven-pass-scheduler.v2":
        raise ValueError("scheduler auxiliary response schema uses an unknown algorithm")
    registry = _scheduler_auxiliary_response_schema_model_registry()
    models = tuple(binding.response_model for binding in registry.values())
    if len(models) != len(set(models)):
        raise ValueError("scheduler auxiliary response registry contains a duplicate type")
    return tuple(
        {
            "model_type": f"{model.__module__}.{model.__qualname__}",
            "schema_sha256": scheduler_response_schema_sha256_for_algorithm(
                model,
                algorithm_version=algorithm_version,
            ),
        }
        for model in sorted(models, key=lambda item: f"{item.__module__}.{item.__qualname__}")
    )


def scheduler_auxiliary_response_schema_hashes_for_algorithm(
    *,
    algorithm_version: str,
) -> frozenset[str]:
    """Return exact purpose-scoped schema hashes for one scheduler algorithm."""

    return frozenset(
        item["schema_sha256"]
        for item in scheduler_auxiliary_response_schema_inventory_for_algorithm(
            algorithm_version=algorithm_version,
        )
    )


def scheduler_auxiliary_response_schema_set_sha256_for_algorithm(
    *,
    algorithm_version: str,
) -> str:
    """Hash the detached purpose-scoped schema inventory."""

    return scheduler_canonical_sha256(
        scheduler_auxiliary_response_schema_inventory_for_algorithm(
            algorithm_version=algorithm_version,
        )
    )


def _scheduler_response_schema_binding(
    schema_sha256: str,
) -> _SchedulerResponseSchemaBinding | None:
    """Resolve a current schema or one exact actor-neutral v1 compatibility alias."""

    registry = _scheduler_all_response_schema_model_registry()
    current = registry.get(schema_sha256)
    if current is not None:
        return current
    legacy_models = tuple(
        model
        for model, legacy_sha256 in _SCHEDULER_V1_ACTOR_NEUTRAL_RESPONSE_SCHEMA_SHA256S.items()
        if legacy_sha256 == schema_sha256
    )
    if len(legacy_models) != 1:
        return None
    current_sha256 = scheduler_response_schema_sha256(legacy_models[0])
    return registry.get(current_sha256)


def _actor_sensitive_response_schema_algorithm(schema_sha256: str) -> str | None:
    """Classify only response schemas changed by actor annotations."""

    if schema_sha256 in _SCHEDULER_V1_ACTOR_NEUTRAL_RESPONSE_SCHEMA_SHA256S.values():
        return "mmaudit.seven-pass-scheduler.v1"
    current_hashes = {
        scheduler_response_schema_sha256(model)
        for model in _SCHEDULER_V1_ACTOR_NEUTRAL_RESPONSE_SCHEMA_SHA256S
    }
    if schema_sha256 in current_hashes:
        return "mmaudit.seven-pass-scheduler.v2"
    return None


def _task_uses_candidate_review_contract(task: SchedulerTaskPlan) -> bool:
    """Return whether a model task has a framed-wire/normalized-batch contract."""

    return (
        task.purpose is SchedulerTaskPurpose.PRIMARY
        and task.task_kind is SchedulerTaskKind.MODEL_REQUEST
        and (
            task.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
            or (
                task.pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
                and task.role == "business_logic"
            )
        )
    )


def _expected_response_model(task: SchedulerTaskPlan) -> type[BaseModel]:
    """Select the retained normalized response type authorized for a scheduler role."""

    if task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING:
        return SolidityRetrievalRequestBatch
    if task.pass_kind is SchedulerPassKind.ORIENTATION and task.role == "threat_model":
        return ThreatModel
    if task.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW:
        return CandidateReviewBatch
    if task.pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION:
        if task.role == "business_logic":
            return CandidateReviewBatch
        if task.role == "specialist:invariant_review":
            return InvariantReviewBatch
    if task.pass_kind is SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION:
        return CandidateCrossExaminationResponse
    if task.pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION:
        if task.role in {"verifier", "candidate_falsifier"}:
            return VerificationBatch
        if task.role in {"falsifier", "specialist:falsifier"}:
            return FalsificationBatch
        if task.role.startswith("specialist:") and task.role.endswith(":exploit_test"):
            return GeneratedFoundryTestBatch
    if task.pass_kind is SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT:
        if task.role == "judge":
            return JudgeDecisionBatch
        if task.role == "specialist:report_quality":
            return ReportQualityReview
    raise ValueError("scheduler model role lacks a registered response contract")


def _parse_retrieval_request_batch_payload(payload: Any) -> SolidityRetrievalRequestBatch:
    """Validate a strict retrieval batch through its JSON wire boundary."""

    return SolidityRetrievalRequestBatch.model_validate_json(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=_json_default,
        )
    )


def _parse_scheduler_model_payload(
    *,
    task: SchedulerTaskPlan,
    activation: SchedulerTaskActivation,
    payload: Any,
    algorithm_version: str = SCHEDULER_ALGORITHM_VERSION,
) -> BaseModel:
    registry = _scheduler_all_response_schema_model_registry()
    wire_schema_sha256 = activation.response_schema_sha256 or ""
    wire_binding = _scheduler_response_schema_binding(wire_schema_sha256)
    expected_model = _expected_response_model(task)
    candidate_review_contract = _task_uses_candidate_review_contract(task)
    permitted_wire_models = (
        (CandidateReviewBatch, CandidateReviewFramedDocument)
        if candidate_review_contract
        else (expected_model,)
    )
    if (
        wire_binding is None
        or wire_binding.response_model not in permitted_wire_models
        or wire_schema_sha256
        != scheduler_response_schema_sha256_for_algorithm(
            wire_binding.response_model,
            algorithm_version=algorithm_version,
        )
    ):
        raise ValueError(
            f"scheduler task output for role {task.role} uses the wrong response schema"
        )
    normalized_schema_sha256 = (
        scheduler_response_schema_sha256(CandidateReviewBatch)
        if candidate_review_contract
        else wire_binding.schema_sha256
    )
    binding = registry.get(normalized_schema_sha256)
    if binding is None or binding.response_model is not expected_model:
        raise ValueError("scheduler normalized output schema is not registered exactly")
    response_model = expected_model
    try:
        wire_binding.require_current()
        binding.require_current()
    except ValueError:
        raise ValueError(
            "scheduler response model schema drifted after registry construction "
            f"for task role {task.role}"
        ) from None
    schema_validator = binding.validator
    try:
        parsed = cast(
            BaseModel,
            (
                schema_validator.validate_json(
                    json.dumps(
                        payload,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                        allow_nan=False,
                    )
                )
                if response_model is SolidityRetrievalRequestBatch
                else schema_validator.validate_python(payload)
            ),
        )
    except (TypeError, ValueError):
        raise ValueError(
            f"scheduler task output for role {task.role} violates its registered response schema"
        ) from None
    if type(parsed) is not response_model:
        raise ValueError(
            f"scheduler task output for role {task.role} returned the wrong response type"
        )
    if (
        getattr(wire_binding.response_model, "__pydantic_validator__", None)
        is not wire_binding.validator
        or getattr(wire_binding.response_model, "__pydantic_core_schema__", None)
        is not wire_binding.core_schema
        or strict_json_schema_sha256(wire_binding.response_model) != wire_binding.schema_sha256
        or getattr(response_model, "__pydantic_validator__", None) is not binding.validator
        or getattr(response_model, "__pydantic_core_schema__", None) is not binding.core_schema
        or strict_json_schema_sha256(response_model) != binding.schema_sha256
    ):
        raise ValueError(
            f"scheduler task output for role {task.role} changed response schema during validation"
        )
    try:
        parsed = cast(
            BaseModel,
            schema_validator.validate_python(parsed.model_dump(mode="python", round_trip=True)),
        )
    except (TypeError, ValueError):
        raise ValueError(
            f"scheduler task output for role {task.role} failed detached revalidation"
        ) from None
    if type(parsed) is not response_model:
        raise ValueError(
            f"scheduler task output for role {task.role} returned the wrong revalidated type"
        )
    if (
        getattr(wire_binding.response_model, "__pydantic_validator__", None)
        is not wire_binding.validator
        or getattr(wire_binding.response_model, "__pydantic_core_schema__", None)
        is not wire_binding.core_schema
        or strict_json_schema_sha256(wire_binding.response_model) != wire_binding.schema_sha256
        or getattr(response_model, "__pydantic_validator__", None) is not binding.validator
        or getattr(response_model, "__pydantic_core_schema__", None) is not binding.core_schema
        or strict_json_schema_sha256(response_model) != binding.schema_sha256
    ):
        raise ValueError(
            f"scheduler task output for role {task.role} changed response schema during validation"
        )
    if isinstance(parsed, ThreatModel) and any(
        not values
        for values in (
            parsed.assets,
            parsed.trust_boundaries,
            parsed.attacker_controlled_inputs,
            parsed.identities_and_roles,
            parsed.attack_surfaces,
            parsed.review_targets,
        )
    ):
        raise ValueError("scheduler orientation output lacks substantive core threat evidence")
    return parsed


def scheduler_source_tree_sha256(sources: Iterable[SchedulerSourceDescriptor]) -> str:
    """Hash the exact source-manifest projection used by run evidence.

    The run-evidence manifest intentionally preserves Unicode source paths, so
    this one projection uses ``ensure_ascii=False`` rather than the scheduler's
    otherwise ASCII-escaped canonical encoding.
    """

    projection = [
        {"path": source.path, "sha256": source.sha256, "size": source.size}
        for source in sorted(sources, key=lambda item: item.path)
    ]
    return hashlib.sha256(
        json.dumps(
            projection,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


ABSENT_SEMANTIC_SHARD_INVENTORY_SHA256 = scheduler_canonical_sha256(
    {"domain": "mmaudit.scheduler.absent-semantic-shard-inventory.v1"}
)
ABSENT_QUALIFICATION_SHA256 = scheduler_canonical_sha256(
    {"domain": "mmaudit.scheduler.absent-production-qualification.v1"}
)
ABSENT_COST_LEDGER_BASELINE_SHA256 = scheduler_canonical_sha256(
    {"domain": "mmaudit.scheduler.absent-cost-ledger-baseline.v1"}
)
ABSENT_PRIVACY_EVIDENCE_CUSTODY_SHA256 = scheduler_canonical_sha256(
    {"domain": "mmaudit.scheduler.absent-privacy-evidence-custody.v1"}
)


def repository_pseudo_shard_id(source_sha256: str) -> str:
    """Derive the single stable pseudo-shard used for non-Solidity source."""

    if re.fullmatch(_SHA256_PATTERN, source_sha256) is None:
        raise ValueError("repository pseudo-shard requires a lowercase SHA-256 source hash")
    return (
        "shard-"
        + scheduler_canonical_sha256(
            {
                "domain": "mmaudit.scheduler.repository-pseudo-shard.v1",
                "source_sha256": source_sha256,
            }
        )[:24]
    )


def _model_sha256(
    model: BaseModel,
    *,
    exclude: set[str],
    algorithm_version: str = SCHEDULER_ALGORITHM_VERSION,
) -> str:
    projection = scheduler_typed_payload_projection(
        model,
        algorithm_version=algorithm_version,
    )
    if not isinstance(projection, dict):
        raise TypeError("scheduler model hash projection has an invalid object shape")
    for field_name in exclude:
        projection.pop(field_name, None)
    return scheduler_canonical_sha256(projection)


def _candidate_review_wire_schema_is_supported(schema_sha256: str) -> bool:
    try:
        candidate_review_wire_schema_algorithm_version(schema_sha256)
    except ValueError:
        return False
    return True


class SchedulerPassKind(StrEnum):
    """The exact closed and ordered maximum-depth audit passes."""

    ORIENTATION = "01_orientation"
    BLIND_SHARD_REVIEW = "02_blind_shard_review"
    FINDING_REDUCTION = "03_finding_reduction"
    CROSS_SHARD_INTEGRATION = "04_cross_shard_integration"
    ADVERSARIAL_CROSS_EXAMINATION = "05_adversarial_cross_examination"
    MULTI_LINEAGE_VALIDATION_FALSIFICATION = "06_multi_lineage_validation_falsification"
    EVIDENCE_CAPPED_JUDGMENT = "07_evidence_capped_judgment"


SCHEDULER_PASS_ORDER: tuple[SchedulerPassKind, ...] = tuple(SchedulerPassKind)


def _pass_index(pass_kind: SchedulerPassKind) -> int:
    return SCHEDULER_PASS_ORDER.index(pass_kind)


class SchedulerScopeKind(StrEnum):
    """Whether work concerns the whole inventory, one shard, or a shard set."""

    GLOBAL = "GLOBAL"
    SINGLE_SHARD = "SINGLE_SHARD"
    SHARD_SET = "SHARD_SET"


class SchedulerTaskKind(StrEnum):
    """The authority responsible for one planned unit of work."""

    MODEL_REQUEST = "MODEL_REQUEST"
    HOST_COMPUTATION = "HOST_COMPUTATION"
    EMPTY_COMPLETION = "EMPTY_COMPLETION"


class SchedulerTaskPurpose(StrEnum):
    """Whether a task performs substantive review or plans bounded retrieval."""

    PRIMARY = "PRIMARY"
    RETRIEVAL_PLANNING = "RETRIEVAL_PLANNING"


class SchedulerTerminalStatus(StrEnum):
    """Exact terminal outcomes; only the first two satisfy a mandatory task."""

    SUCCEEDED = "SUCCEEDED"
    EXPLICIT_EMPTY = "EXPLICIT_EMPTY"
    FAILED = "FAILED"
    TRUNCATED = "TRUNCATED"
    INVALID = "INVALID"
    UNBOUND = "UNBOUND"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNCERTAIN = "UNCERTAIN"


class SchedulerTruncationRecoveryPromotionDisposition(StrEnum):
    """How one recursive recovery request participates in an effective promotion."""

    SUCCESSFUL_LEAF = "SUCCESSFUL_LEAF"
    SUPERSEDED_TRUNCATED_BRIDGE = "SUPERSEDED_TRUNCATED_BRIDGE"


class SchedulerPassStatus(StrEnum):
    """A pass status derived from its exact terminal task inventory."""

    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    INCOMPLETE = "INCOMPLETE"


class SchedulerCampaignStatus(StrEnum):
    """A campaign status derived from its ordered mandatory pass results."""

    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    INCOMPLETE = "INCOMPLETE"


class SchedulerTaskEventKind(StrEnum):
    """Durable task transition kinds used by a journal implementation."""

    PLANNED = "PLANNED"
    ACTIVATED = "ACTIVATED"
    DISPATCHED = "DISPATCHED"
    TERMINAL = "TERMINAL"
    PREFLIGHT_TERMINAL = "PREFLIGHT_TERMINAL"
    ACTIVATED_PREFLIGHT_TERMINAL = "ACTIVATED_PREFLIGHT_TERMINAL"


class SchedulerShardKind(StrEnum):
    """Closed shard-descriptor kinds for an exact audited source inventory."""

    SOLIDITY_SEMANTIC = "SOLIDITY_SEMANTIC"
    REPOSITORY_PSEUDO = "REPOSITORY_PSEUDO"


class SchedulerAbsenceReason(StrEnum):
    """Closed predicates that may justify a conditional downstream no-op."""

    NO_HIGH_CRITICAL_CANDIDATES = "NO_HIGH_CRITICAL_CANDIDATES"
    NO_VALIDATION_CANDIDATES = "NO_VALIDATION_CANDIDATES"


class SchedulerResultOrigin(StrEnum):
    """Whether a result follows activation or a typed local preflight abort."""

    ACTIVATED = "ACTIVATED"
    LOCAL_PREFLIGHT = "LOCAL_PREFLIGHT"


class SchedulerActivationStatus(StrEnum):
    """Public activation disposition for one planned model request."""

    NOT_ACTIVATED = "NOT_ACTIVATED"
    ACTIVATED = "ACTIVATED"
    PREFLIGHT_FAILED = "PREFLIGHT_FAILED"


def _candidate_id_inventory(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"scheduler {label} inventory must be an explicit list")
    items = tuple(value)
    if any(
        not isinstance(item, str)
        or not item
        or len(item) > 500
        or item != item.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in item)
        for item in items
    ) or items != tuple(sorted(set(items))):
        raise ValueError(f"scheduler {label} inventory must be bounded, unique, and sorted")
    return items


def _candidate_reviewer_role(candidate_id: str, reviewer_index: int) -> str:
    """Return the exact host-controlled pass-five role for one candidate reviewer."""

    if reviewer_index not in {1, 2}:
        raise ValueError("scheduler candidate reviewer index must be one or two")
    candidate_sha256 = hashlib.sha256(candidate_id.encode("utf-8")).hexdigest()
    return f"candidate_falsifier:{candidate_sha256}:reviewer_{reviewer_index}"


class SchedulerCandidatePayloadBinding(StrictModel):
    """Canonical identity of one normalized candidate carried across scheduler passes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: str = Field(min_length=1, max_length=500)
    candidate_payload_sha256: str = Field(pattern=_SHA256_PATTERN)
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        candidate_id: str,
        candidate_payload_sha256: str,
    ) -> SchedulerCandidatePayloadBinding:
        _candidate_id_inventory((candidate_id,), "candidate payload")
        values: dict[str, Any] = {
            "candidate_id": candidate_id,
            "candidate_payload_sha256": candidate_payload_sha256,
        }
        return cls(**values, binding_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def candidate_payload_binding_is_exact(self) -> Self:
        _candidate_id_inventory((self.candidate_id,), "candidate payload")
        if self.binding_sha256 != _model_sha256(self, exclude={"binding_sha256"}):
            raise ValueError("scheduler candidate payload binding hash is inconsistent")
        return self


class SchedulerCandidateWorkset(StrictModel):
    """Candidate inventory deterministically projected from pass-four output."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pass_kind: SchedulerPassKind
    source_pass_kind: Literal[SchedulerPassKind.CROSS_SHARD_INTEGRATION]
    source_pass_result_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_task_id: str = Field(pattern=r"^scheduler-task-[0-9a-f]{64}$")
    source_result_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_output_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    candidate_payload_bindings: tuple[SchedulerCandidatePayloadBinding, ...] = Field(
        max_length=100_000
    )
    high_critical_candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    validation_candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    selected_candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    workset_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        pass_kind: SchedulerPassKind,
        source_pass_result: SchedulerPassResult,
        source_result: SchedulerTaskResult,
        source_output: SchedulerTaskOutput,
    ) -> SchedulerCandidateWorkset:
        if pass_kind not in {
            SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
            SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
        }:
            raise ValueError("scheduler candidate workset is only valid for passes five and six")
        if (
            source_result.pass_kind is not SchedulerPassKind.CROSS_SHARD_INTEGRATION
            or source_pass_result.plan.pass_kind is not SchedulerPassKind.CROSS_SHARD_INTEGRATION
            or source_result not in source_pass_result.task_results
            or source_pass_result.status is not SchedulerPassStatus.COMPLETE
            or source_result.terminal_status is not SchedulerTerminalStatus.SUCCEEDED
            or source_result.task_id != source_output.task_id
            or source_result.output_artifact_sha256 != source_output.output_artifact_sha256
            or source_result.output_sha256 != source_output.output_sha256
        ):
            raise ValueError("scheduler candidate workset lacks exact successful pass-four output")
        payload = source_output.payload
        if not isinstance(payload, dict):
            raise ValueError("scheduler pass-four output lacks a typed candidate inventory")
        try:
            integration = SchedulerCrossShardIntegrationOutput.model_validate(payload)
        except ValueError:
            raise ValueError(
                "scheduler pass-four output lacks a typed candidate inventory"
            ) from None
        candidate_ids = integration.candidate_ids
        raw_payload_hashes = integration.candidate_payload_sha256s
        payload_bindings = tuple(
            SchedulerCandidatePayloadBinding.build(
                candidate_id=candidate_id,
                candidate_payload_sha256=raw_payload_hashes[candidate_id],
            )
            for candidate_id in candidate_ids
        )
        high_critical = integration.high_critical_candidate_ids
        validation = integration.validation_candidate_ids
        if not set(high_critical) <= set(candidate_ids) or not set(validation) <= set(
            candidate_ids
        ):
            raise ValueError("scheduler candidate subsets exceed the exact pass-four inventory")
        selected = (
            high_critical
            if pass_kind is SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION
            else validation
        )
        values: dict[str, Any] = {
            "pass_kind": pass_kind,
            "source_pass_kind": SchedulerPassKind.CROSS_SHARD_INTEGRATION,
            "source_pass_result_sha256": source_pass_result.pass_result_sha256,
            "source_task_id": source_result.task_id,
            "source_result_sha256": source_result.result_sha256,
            "source_output_artifact_sha256": source_output.output_artifact_sha256,
            "candidate_ids": candidate_ids,
            "candidate_payload_bindings": payload_bindings,
            "high_critical_candidate_ids": high_critical,
            "validation_candidate_ids": validation,
            "selected_candidate_ids": selected,
        }
        return cls(**values, workset_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def candidate_workset_is_canonical_and_exact(self) -> Self:
        for values in (
            self.candidate_ids,
            self.high_critical_candidate_ids,
            self.validation_candidate_ids,
            self.selected_candidate_ids,
        ):
            _candidate_id_inventory(values, "candidate")
        binding_ids = tuple(item.candidate_id for item in self.candidate_payload_bindings)
        if binding_ids != self.candidate_ids:
            raise ValueError("scheduler candidate payload bindings differ from their inventory")
        if not set(self.high_critical_candidate_ids) <= set(self.candidate_ids) or not set(
            self.validation_candidate_ids
        ) <= set(self.candidate_ids):
            raise ValueError("scheduler candidate subsets exceed their exact inventory")
        expected_selected = (
            self.high_critical_candidate_ids
            if self.pass_kind is SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION
            else self.validation_candidate_ids
        )
        if self.selected_candidate_ids != expected_selected:
            raise ValueError("scheduler selected candidates differ from the pass workset")
        if self.source_pass_kind is not SchedulerPassKind.CROSS_SHARD_INTEGRATION:
            raise ValueError("scheduler candidate workset must derive from pass four")
        if self.workset_sha256 != _model_sha256(self, exclude={"workset_sha256"}):
            raise ValueError("scheduler candidate workset hash is inconsistent")
        return self

    @property
    def selected_candidate_payload_bindings(
        self,
    ) -> tuple[SchedulerCandidatePayloadBinding, ...]:
        selected = set(self.selected_candidate_ids)
        return tuple(
            binding
            for binding in self.candidate_payload_bindings
            if binding.candidate_id in selected
        )

    def candidate_payload_sha256(self, candidate_id: str) -> str:
        matches = tuple(
            binding.candidate_payload_sha256
            for binding in self.candidate_payload_bindings
            if binding.candidate_id == candidate_id
        )
        if len(matches) != 1:
            raise ValueError("scheduler candidate payload identity is absent or ambiguous")
        return matches[0]


class SchedulerSourceDescriptor(StrictModel):
    """One exact normalized source path in the audited repository."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=4_096)
    sha256: str = Field(pattern=_SHA256_PATTERN)
    size: int = Field(ge=0, le=4 * 1024**3)
    source_descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(cls, *, path: str, sha256: str, size: int) -> SchedulerSourceDescriptor:
        values = {"path": path, "sha256": sha256, "size": size}
        return cls(**values, source_descriptor_sha256=scheduler_canonical_sha256(values))

    @field_validator("path")
    @classmethod
    def path_is_normalized_relative_posix(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            "\\" in value
            or path.is_absolute()
            or path.as_posix() != value
            or value in {"", "."}
            or any(part in {"", ".", ".."} for part in path.parts)
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("scheduler source path must be normalized relative POSIX text")
        return value

    @model_validator(mode="after")
    def source_descriptor_hash_is_exact(self) -> Self:
        if self.source_descriptor_sha256 != _model_sha256(
            self, exclude={"source_descriptor_sha256"}
        ):
            raise ValueError("scheduler source descriptor hash is inconsistent")
        return self


class SchedulerShardDescriptor(StrictModel):
    """A semantic Solidity shard or the deterministic non-Solidity pseudo-shard."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    shard_id: str = Field(pattern=_SHARD_ID_PATTERN)
    kind: SchedulerShardKind
    sources: tuple[SchedulerSourceDescriptor, ...] = Field(min_length=1, max_length=100_000)
    semantic_shard_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    shard_descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def semantic(
        cls,
        *,
        shard_id: str,
        semantic_shard_sha256: str,
        sources: Iterable[SchedulerSourceDescriptor],
    ) -> SchedulerShardDescriptor:
        canonical_sources = tuple(sorted(sources, key=lambda item: item.path))
        values = {
            "shard_id": shard_id,
            "kind": SchedulerShardKind.SOLIDITY_SEMANTIC,
            "sources": canonical_sources,
            "semantic_shard_sha256": semantic_shard_sha256,
        }
        return cls(**values, shard_descriptor_sha256=scheduler_canonical_sha256(values))

    @classmethod
    def repository_pseudo(
        cls,
        *,
        sources: Iterable[SchedulerSourceDescriptor],
    ) -> SchedulerShardDescriptor:
        canonical_sources = tuple(sorted(sources, key=lambda item: item.path))
        source_sha256 = scheduler_source_tree_sha256(canonical_sources)
        values = {
            "shard_id": repository_pseudo_shard_id(source_sha256),
            "kind": SchedulerShardKind.REPOSITORY_PSEUDO,
            "sources": canonical_sources,
            "semantic_shard_sha256": None,
        }
        return cls(**values, shard_descriptor_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def descriptor_shape_and_hash_are_exact(self) -> Self:
        if self.sources != tuple(sorted(self.sources, key=lambda item: item.path)):
            raise ValueError("scheduler shard sources must be sorted by normalized path")
        paths = tuple(source.path for source in self.sources)
        if len(paths) != len(set(paths)):
            raise ValueError("scheduler shard cannot repeat a source path")
        if self.kind is SchedulerShardKind.SOLIDITY_SEMANTIC:
            if self.semantic_shard_sha256 is None or any(
                PurePosixPath(source.path).suffix.lower() != ".sol" for source in self.sources
            ):
                raise ValueError("semantic scheduler shards require only Solidity sources")
        else:
            if self.semantic_shard_sha256 is not None or any(
                PurePosixPath(source.path).suffix.lower() == ".sol" for source in self.sources
            ):
                raise ValueError("repository pseudo-shard requires only non-Solidity sources")
            expected_id = repository_pseudo_shard_id(scheduler_source_tree_sha256(self.sources))
            if self.shard_id != expected_id:
                raise ValueError("repository pseudo-shard ID differs from its exact sources")
        if self.shard_descriptor_sha256 != _model_sha256(self, exclude={"shard_descriptor_sha256"}):
            raise ValueError("scheduler shard descriptor hash is inconsistent")
        return self


class SchedulerShardInventory(StrictModel):
    """Exact source-to-shard assignment for every audited source path."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    semantic_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    shards: tuple[SchedulerShardDescriptor, ...] = Field(min_length=1, max_length=100_000)
    source_tree_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_count: int = Field(ge=1, le=100_000)
    inventory_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        semantic_inventory_sha256: str,
        shards: Iterable[SchedulerShardDescriptor],
    ) -> SchedulerShardInventory:
        canonical_shards = tuple(sorted(shards, key=lambda item: item.shard_id))
        sources = tuple(source for shard in canonical_shards for source in shard.sources)
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "evidence_authority": "comparison_required",
            "semantic_inventory_sha256": semantic_inventory_sha256,
            "shards": canonical_shards,
            "source_tree_sha256": scheduler_source_tree_sha256(sources),
            "source_count": len(sources),
        }
        return cls(**values, inventory_sha256=scheduler_canonical_sha256(values))

    @property
    def shard_ids(self) -> tuple[str, ...]:
        return tuple(shard.shard_id for shard in self.shards)

    @model_validator(mode="after")
    def inventory_is_complete_canonical_and_exact(self) -> Self:
        if self.shards != tuple(sorted(self.shards, key=lambda item: item.shard_id)):
            raise ValueError("scheduler shard descriptors must be sorted by shard ID")
        shard_ids = self.shard_ids
        if len(shard_ids) != len(set(shard_ids)):
            raise ValueError("scheduler shard inventory contains duplicate shard IDs")
        sources = tuple(source for shard in self.shards for source in shard.sources)
        paths = tuple(source.path for source in sources)
        if len(paths) != len(set(paths)) or self.source_count != len(paths):
            raise ValueError("every audited source path must occur in exactly one scheduler shard")
        pseudo_count = sum(
            shard.kind is SchedulerShardKind.REPOSITORY_PSEUDO for shard in self.shards
        )
        semantic_count = len(self.shards) - pseudo_count
        if pseudo_count > 1:
            raise ValueError("scheduler inventory permits only one repository pseudo-shard")
        if self.semantic_inventory_sha256 == ABSENT_SEMANTIC_SHARD_INVENTORY_SHA256:
            if semantic_count or pseudo_count != 1:
                raise ValueError("absent semantic inventory requires exactly one pseudo-shard")
        elif semantic_count == 0:
            raise ValueError("present semantic inventory requires at least one semantic shard")
        if self.source_tree_sha256 != scheduler_source_tree_sha256(sources):
            raise ValueError("scheduler inventory source-tree hash is inconsistent")
        if self.inventory_sha256 != _model_sha256(self, exclude={"inventory_sha256"}):
            raise ValueError("scheduler shard-inventory hash is inconsistent")
        return self


class SchedulerCostLedgerBaselineEntry(StrictModel):
    """Exact immutable identity of one ledger entry predating this campaign."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=_SAFE_KEY_PATTERN)
    ledger_entry_sha256: str = Field(pattern=_SHA256_PATTERN)
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        request_id: str,
        ledger_entry_sha256: str,
    ) -> SchedulerCostLedgerBaselineEntry:
        values = {
            "request_id": request_id,
            "ledger_entry_sha256": ledger_entry_sha256,
        }
        return cls(**values, binding_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def binding_is_exact(self) -> Self:
        if self.binding_sha256 != _model_sha256(self, exclude={"binding_sha256"}):
            raise ValueError("scheduler cost-ledger baseline entry hash is inconsistent")
        return self


class SchedulerCostLedgerBaseline(StrictModel):
    """Exact terminal ledger head frozen before any campaign provider request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    cap_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    spent_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    active_reserved_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    entries: tuple[SchedulerCostLedgerBaselineEntry, ...] = Field(max_length=1_000_000)
    ledger_identity_sha256: str = Field(pattern=_SHA256_PATTERN)
    ledger_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    baseline_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        cap_usd_exact: str,
        spent_usd_exact: str,
        active_reserved_usd_exact: str,
        entries: Iterable[SchedulerCostLedgerBaselineEntry],
        ledger_identity_sha256: str,
        ledger_snapshot_sha256: str,
    ) -> SchedulerCostLedgerBaseline:
        canonical_entries = tuple(sorted(entries, key=lambda item: item.request_id))
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "evidence_authority": "comparison_required",
            "cap_usd_exact": cap_usd_exact,
            "spent_usd_exact": spent_usd_exact,
            "active_reserved_usd_exact": active_reserved_usd_exact,
            "entries": canonical_entries,
            "ledger_identity_sha256": ledger_identity_sha256,
            "ledger_snapshot_sha256": ledger_snapshot_sha256,
        }
        return cls(**values, baseline_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def baseline_is_terminal_canonical_and_exact(self) -> Self:
        if self.entries != tuple(sorted(self.entries, key=lambda item: item.request_id)):
            raise ValueError("scheduler cost-ledger baseline entries are not sorted")
        request_ids = tuple(item.request_id for item in self.entries)
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("scheduler cost-ledger baseline repeats an entry")
        try:
            cap = Decimal(self.cap_usd_exact)
            spent = Decimal(self.spent_usd_exact)
            active = Decimal(self.active_reserved_usd_exact)
        except InvalidOperation:
            raise ValueError("scheduler cost-ledger baseline amount is invalid") from None
        if cap <= 0 or spent < 0 or spent > cap or active != 0:
            raise ValueError(
                "scheduler cost-ledger baseline must be in-cap with no active reservation"
            )
        if self.baseline_sha256 != _model_sha256(self, exclude={"baseline_sha256"}):
            raise ValueError("scheduler cost-ledger baseline hash is inconsistent")
        return self


class SchedulerAuditSelectedRouteBinding(StrictModel):
    """Minimal non-authorizing identity for one policy-selected audit route."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    exact_model_id: str = Field(pattern=_MODEL_ID_PATTERN)
    root_lineage: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    provider_name: str = Field(pattern=_PROVIDER_NAME_PATTERN)
    provider_endpoint: str = Field(pattern=_PROVIDER_ENDPOINT_PATTERN)
    policy_route_sha256: str = Field(pattern=_SHA256_PATTERN)
    selected_model_sha256: str = Field(pattern=_SHA256_PATTERN)
    route_binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        exact_model_id: str,
        root_lineage: str,
        provider_name: str,
        provider_endpoint: str,
        policy_route_sha256: str,
        selected_model_sha256: str,
    ) -> SchedulerAuditSelectedRouteBinding:
        values = {
            "exact_model_id": exact_model_id,
            "root_lineage": root_lineage,
            "provider_name": provider_name,
            "provider_endpoint": provider_endpoint,
            "policy_route_sha256": policy_route_sha256,
            "selected_model_sha256": selected_model_sha256,
        }
        return cls(**values, route_binding_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def route_binding_is_exact(self) -> Self:
        if self.route_binding_sha256 != _model_sha256(
            self,
            exclude={"route_binding_sha256"},
        ):
            raise ValueError("scheduler audit-selected route binding is inconsistent")
        return self


class SchedulerAuditModelSelectionBinding(StrictModel):
    """Hash-only campaign join to one durable audit policy-selection bundle.

    This record is comparison evidence, not runtime authority. The live opaque
    selection capability is deliberately absent.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    intended_use: Literal["PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT"] = (
        "PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT"
    )
    audit_model_selection_bundle_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_selection_sha256: str = Field(pattern=_SHA256_PATTERN)
    selected_model_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    selected_model_ids: tuple[str, ...] = Field(min_length=1, max_length=128)
    selected_routes: tuple[SchedulerAuditSelectedRouteBinding, ...] = Field(
        min_length=1,
        max_length=128,
    )
    audit_scope_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_context_sha256: str = Field(pattern=_SHA256_PATTERN)
    client_constraints_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    eligible_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_exclusion_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_production_selection_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_qualification_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_evaluation_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_authority_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_authority_statement_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_authority_envelope_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_authority_trust_anchor_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_source_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_source_commitment_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    selection_expires_at: datetime
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        audit_model_selection_bundle_sha256: str,
        audit_selection_sha256: str,
        selected_model_set_sha256: str,
        selected_routes: Iterable[SchedulerAuditSelectedRouteBinding],
        audit_scope_sha256: str,
        source_sha256: str,
        audit_context_sha256: str,
        client_constraints_sha256: str,
        technical_route_set_sha256: str,
        eligible_route_set_sha256: str,
        policy_exclusion_set_sha256: str,
        technical_production_selection_sha256: str,
        technical_qualification_capability_sha256: str,
        policy_artifact_sha256: str,
        policy_evaluation_sha256: str,
        policy_authority_receipt_sha256: str,
        policy_authority_statement_sha256: str,
        policy_authority_envelope_sha256: str,
        policy_authority_trust_anchor_sha256: str,
        policy_source_observation_sha256: str,
        policy_source_commitment_set_sha256: str,
        selection_expires_at: datetime,
    ) -> SchedulerAuditModelSelectionBinding:
        canonical_routes = tuple(sorted(selected_routes, key=lambda item: item.exact_model_id))
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "evidence_authority": "comparison_required",
            "intended_use": "PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT",
            "audit_model_selection_bundle_sha256": audit_model_selection_bundle_sha256,
            "audit_selection_sha256": audit_selection_sha256,
            "selected_model_set_sha256": selected_model_set_sha256,
            "selected_model_ids": tuple(item.exact_model_id for item in canonical_routes),
            "selected_routes": canonical_routes,
            "audit_scope_sha256": audit_scope_sha256,
            "source_sha256": source_sha256,
            "audit_context_sha256": audit_context_sha256,
            "client_constraints_sha256": client_constraints_sha256,
            "technical_route_set_sha256": technical_route_set_sha256,
            "eligible_route_set_sha256": eligible_route_set_sha256,
            "policy_exclusion_set_sha256": policy_exclusion_set_sha256,
            "technical_production_selection_sha256": technical_production_selection_sha256,
            "technical_qualification_capability_sha256": (
                technical_qualification_capability_sha256
            ),
            "policy_artifact_sha256": policy_artifact_sha256,
            "policy_evaluation_sha256": policy_evaluation_sha256,
            "policy_authority_receipt_sha256": policy_authority_receipt_sha256,
            "policy_authority_statement_sha256": policy_authority_statement_sha256,
            "policy_authority_envelope_sha256": policy_authority_envelope_sha256,
            "policy_authority_trust_anchor_sha256": policy_authority_trust_anchor_sha256,
            "policy_source_observation_sha256": policy_source_observation_sha256,
            "policy_source_commitment_set_sha256": policy_source_commitment_set_sha256,
            "selection_expires_at": selection_expires_at,
        }
        return cls(**values, binding_sha256=scheduler_canonical_sha256(values))

    @classmethod
    def from_evidence_bundle(
        cls,
        evidence_bundle: AuditModelSelectionEvidenceBundle,
    ) -> SchedulerAuditModelSelectionBinding:
        """Project a validated durable bundle without retaining opaque authority."""

        from mmaudit.models.policy_selection import AuditModelSelectionEvidenceBundle

        if type(evidence_bundle) is not AuditModelSelectionEvidenceBundle:
            raise ValueError("scheduler audit selection requires an exact evidence bundle")
        bundle = AuditModelSelectionEvidenceBundle.model_validate_json(
            evidence_bundle.model_dump_json(),
            strict=True,
        )
        selection = bundle.selection
        routes = tuple(
            SchedulerAuditSelectedRouteBinding.build(
                exact_model_id=model.exact_model_id,
                root_lineage=model.root_lineage,
                provider_name=model.approved_provider_name,
                provider_endpoint=model.approved_provider_endpoint,
                policy_route_sha256=model.policy_route_sha256,
                selected_model_sha256=model.selected_model_sha256,
            )
            for model in selection.models
        )
        return cls.build(
            audit_model_selection_bundle_sha256=bundle.bundle_sha256,
            audit_selection_sha256=selection.selection_sha256,
            selected_model_set_sha256=selection.selected_model_set_sha256,
            selected_routes=routes,
            audit_scope_sha256=selection.audit_scope_sha256,
            source_sha256=selection.source_sha256,
            audit_context_sha256=selection.audit_context_sha256,
            client_constraints_sha256=selection.client_constraints_sha256,
            technical_route_set_sha256=selection.technical_route_set_sha256,
            eligible_route_set_sha256=selection.eligible_route_set_sha256,
            policy_exclusion_set_sha256=selection.policy_exclusion_set_sha256,
            technical_production_selection_sha256=(selection.technical_production_selection_sha256),
            technical_qualification_capability_sha256=(
                selection.technical_qualification_capability_sha256
            ),
            policy_artifact_sha256=selection.policy_artifact_sha256,
            policy_evaluation_sha256=selection.policy_evaluation_sha256,
            policy_authority_receipt_sha256=selection.policy_authority_receipt_sha256,
            policy_authority_statement_sha256=selection.policy_authority_statement_sha256,
            policy_authority_envelope_sha256=selection.policy_authority_envelope_sha256,
            policy_authority_trust_anchor_sha256=(selection.policy_authority_trust_anchor_sha256),
            policy_source_observation_sha256=selection.policy_source_observation_sha256,
            policy_source_commitment_set_sha256=(selection.policy_source_commitment_set_sha256),
            selection_expires_at=selection.expires_at,
        )

    @field_validator("selection_expires_at")
    @classmethod
    def expiry_is_whole_second_utc(cls, value: datetime) -> datetime:
        if (
            type(value) is not datetime
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
            or value.microsecond != 0
        ):
            raise ValueError("scheduler audit-selection expiry must be whole-second UTC")
        return value

    def route_for(self, exact_model_id: str) -> SchedulerAuditSelectedRouteBinding:
        matches = tuple(
            item for item in self.selected_routes if item.exact_model_id == exact_model_id
        )
        if len(matches) != 1:
            raise ValueError(f"model is absent from scheduler audit selection: {exact_model_id}")
        return matches[0]

    @model_validator(mode="after")
    def binding_is_canonical_and_exact(self) -> Self:
        if self.selected_routes != tuple(
            sorted(self.selected_routes, key=lambda item: item.exact_model_id)
        ):
            raise ValueError("scheduler audit-selected routes must be sorted")
        route_ids = tuple(item.exact_model_id for item in self.selected_routes)
        if route_ids != tuple(sorted(set(route_ids))) or route_ids != self.selected_model_ids:
            raise ValueError("scheduler audit-selected model set is not exact")
        if self.binding_sha256 != _model_sha256(self, exclude={"binding_sha256"}):
            raise ValueError("scheduler audit model-selection binding is inconsistent")
        return self


class SchedulerAuditModelRefreshRouteBinding(StrictModel):
    """Exact per-model membership in the audit-selected refresh route set."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    exact_model_id: str = Field(pattern=_MODEL_ID_PATTERN)
    route_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)


class SchedulerAuditModelRefreshBinding(StrictModel):
    """Hash-only campaign join to canonical veto-only refresh evidence.

    The durable projection cannot recreate the process-local refresh guard and
    therefore cannot authorize model selection, routing, or provider access.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    authority_mode: Literal["VETO_ONLY_EXTERNAL_WORKFLOW_PIN_REQUIRED"] = (
        "VETO_ONLY_EXTERNAL_WORKFLOW_PIN_REQUIRED"
    )
    audit_model_refresh_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    guard_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    expected_workflow_status_sha256: str = Field(pattern=_SHA256_PATTERN)
    workflow_status_sha256: str = Field(pattern=_SHA256_PATTERN)
    snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    freshness_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_model_ids: tuple[str, ...] = Field(min_length=1, max_length=128)
    audit_routes: tuple[SchedulerAuditModelRefreshRouteBinding, ...] = Field(
        min_length=1,
        max_length=128,
    )
    technical_qualification_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_production_selection_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_selection_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_selection_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_scope_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_context_sha256: str = Field(pattern=_SHA256_PATTERN)
    client_constraints_sha256: str = Field(pattern=_SHA256_PATTERN)
    verified_at: datetime
    refresh_current_through: datetime
    expires_at: datetime
    runtime_authorized: Literal[False] = False
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        audit_model_refresh_evidence_sha256: str,
        guard_capability_sha256: str,
        expected_workflow_status_sha256: str,
        workflow_status_sha256: str,
        snapshot_sha256: str,
        freshness_sha256: str,
        technical_route_set_sha256: str,
        audit_route_set_sha256: str,
        audit_routes: Iterable[SchedulerAuditModelRefreshRouteBinding],
        technical_qualification_capability_sha256: str,
        technical_production_selection_sha256: str,
        audit_selection_capability_sha256: str,
        audit_selection_sha256: str,
        audit_scope_sha256: str,
        source_sha256: str,
        audit_context_sha256: str,
        client_constraints_sha256: str,
        verified_at: datetime,
        refresh_current_through: datetime,
        expires_at: datetime,
    ) -> SchedulerAuditModelRefreshBinding:
        canonical_routes = tuple(sorted(audit_routes, key=lambda item: item.exact_model_id))
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "evidence_authority": "comparison_required",
            "authority_mode": "VETO_ONLY_EXTERNAL_WORKFLOW_PIN_REQUIRED",
            "audit_model_refresh_evidence_sha256": audit_model_refresh_evidence_sha256,
            "guard_capability_sha256": guard_capability_sha256,
            "expected_workflow_status_sha256": expected_workflow_status_sha256,
            "workflow_status_sha256": workflow_status_sha256,
            "snapshot_sha256": snapshot_sha256,
            "freshness_sha256": freshness_sha256,
            "technical_route_set_sha256": technical_route_set_sha256,
            "audit_route_set_sha256": audit_route_set_sha256,
            "audit_model_ids": tuple(item.exact_model_id for item in canonical_routes),
            "audit_routes": canonical_routes,
            "technical_qualification_capability_sha256": (
                technical_qualification_capability_sha256
            ),
            "technical_production_selection_sha256": (technical_production_selection_sha256),
            "audit_selection_capability_sha256": audit_selection_capability_sha256,
            "audit_selection_sha256": audit_selection_sha256,
            "audit_scope_sha256": audit_scope_sha256,
            "source_sha256": source_sha256,
            "audit_context_sha256": audit_context_sha256,
            "client_constraints_sha256": client_constraints_sha256,
            "verified_at": verified_at,
            "refresh_current_through": refresh_current_through,
            "expires_at": expires_at,
            "runtime_authorized": False,
        }
        return cls(**values, binding_sha256=scheduler_canonical_sha256(values))

    @classmethod
    def from_evidence(
        cls,
        evidence: AuditModelRefreshEvidence,
    ) -> SchedulerAuditModelRefreshBinding:
        """Project exact durable evidence while excluding the opaque live guard."""

        from mmaudit.models.refresh_runtime import AuditModelRefreshEvidence

        if type(evidence) is not AuditModelRefreshEvidence:
            raise ValueError("scheduler refresh binding requires exact canonical evidence")
        canonical = AuditModelRefreshEvidence.model_validate_json(
            evidence.model_dump_json(),
            strict=True,
        )
        if canonical != evidence:
            raise ValueError("scheduler refresh evidence changed during canonicalization")
        guard_capability_sha256 = scheduler_canonical_sha256(
            {
                "verified_at": canonical.verified_at,
                "expires_at": canonical.expires_at,
                "refresh_current_through": canonical.refresh_current_through,
                "workflow_status_sha256": canonical.workflow_status_sha256,
                "snapshot_sha256": canonical.snapshot_sha256,
                "technical_qualification_capability_sha256": (
                    canonical.technical_qualification_capability_sha256
                ),
                "technical_production_selection_sha256": (
                    canonical.technical_production_selection_sha256
                ),
                "audit_selection_capability_sha256": (canonical.audit_selection_capability_sha256),
                "audit_selection_sha256": canonical.audit_selection_sha256,
                "evidence_sha256": canonical.evidence_sha256,
            }
        )
        return cls.build(
            audit_model_refresh_evidence_sha256=canonical.evidence_sha256,
            guard_capability_sha256=guard_capability_sha256,
            expected_workflow_status_sha256=canonical.expected_workflow_status_sha256,
            workflow_status_sha256=canonical.workflow_status_sha256,
            snapshot_sha256=canonical.snapshot_sha256,
            freshness_sha256=canonical.freshness_sha256,
            technical_route_set_sha256=canonical.technical_route_set_sha256,
            audit_route_set_sha256=canonical.audit_route_set_sha256,
            audit_routes=tuple(
                SchedulerAuditModelRefreshRouteBinding(
                    exact_model_id=route.exact_model_id,
                    route_evidence_sha256=route.route_evidence_sha256,
                )
                for route in canonical.routes
                if route.audit_selected
            ),
            technical_qualification_capability_sha256=(
                canonical.technical_qualification_capability_sha256
            ),
            technical_production_selection_sha256=(canonical.technical_production_selection_sha256),
            audit_selection_capability_sha256=canonical.audit_selection_capability_sha256,
            audit_selection_sha256=canonical.audit_selection_sha256,
            audit_scope_sha256=canonical.audit_scope_sha256,
            source_sha256=canonical.source_sha256,
            audit_context_sha256=canonical.audit_context_sha256,
            client_constraints_sha256=canonical.client_constraints_sha256,
            verified_at=canonical.verified_at,
            refresh_current_through=canonical.refresh_current_through,
            expires_at=canonical.expires_at,
        )

    @field_validator("audit_model_ids")
    @classmethod
    def model_ids_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            re.fullmatch(_MODEL_ID_PATTERN, model_id) is None for model_id in value
        ):
            raise ValueError("scheduler refresh model IDs must be exact, unique, and sorted")
        return value

    @field_validator("verified_at", "refresh_current_through", "expires_at")
    @classmethod
    def times_are_whole_second_utc(cls, value: datetime) -> datetime:
        if (
            type(value) is not datetime
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
            or value.microsecond != 0
        ):
            raise ValueError("scheduler refresh times must be whole-second UTC")
        return value

    @field_validator("runtime_authorized", mode="before")
    @classmethod
    def authority_is_literal_false(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("scheduler refresh authority flag must be a literal boolean")
        return value

    def route_for(self, exact_model_id: str) -> SchedulerAuditModelRefreshRouteBinding:
        matches = tuple(item for item in self.audit_routes if item.exact_model_id == exact_model_id)
        if len(matches) != 1:
            raise ValueError(f"model is absent from scheduler refresh binding: {exact_model_id}")
        return matches[0]

    @model_validator(mode="after")
    def refresh_binding_is_canonical_and_exact(self) -> Self:
        if self.expected_workflow_status_sha256 != self.workflow_status_sha256:
            raise ValueError("scheduler refresh differs from its external workflow pin")
        route_ids = tuple(item.exact_model_id for item in self.audit_routes)
        if (
            self.audit_routes
            != tuple(sorted(self.audit_routes, key=lambda item: item.exact_model_id))
            or route_ids != tuple(sorted(set(route_ids)))
            or route_ids != self.audit_model_ids
        ):
            raise ValueError("scheduler refresh routes differ from the exact audit model set")
        if (
            not self.verified_at < self.expires_at
            or self.expires_at > self.refresh_current_through + timedelta(seconds=1)
        ):
            raise ValueError("scheduler refresh expiry exceeds its current-freshness boundary")
        if self.binding_sha256 != _model_sha256(self, exclude={"binding_sha256"}):
            raise ValueError("scheduler audit model-refresh binding is inconsistent")
        return self


class SchedulerAuditModelRefreshPricingRouteBinding(StrictModel):
    """Hash-only scheduler join for one audit-selected refreshed-price route."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    exact_model_id: str = Field(pattern=_MODEL_ID_PATTERN)
    approved_provider_endpoint: str = Field(pattern=_PROVIDER_ENDPOINT_PATTERN)
    pricing_route_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_route_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    qualified_pricing_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    baseline_pricing_sha256: str = Field(pattern=_SHA256_PATTERN)
    current_pricing_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def baseline_is_explicit_and_qualified(self) -> Self:
        if self.qualified_pricing_snapshot_sha256 != self.baseline_pricing_sha256:
            raise ValueError("scheduler pricing route differs from its qualified baseline")
        return self


class SchedulerAuditModelRefreshPricingBinding(StrictModel):
    """Durable comparison-only projection of bounded refreshed pricing.

    The public authority hash is retained only for exact comparison with the
    process-local opaque capability. This binding cannot authorize pricing or
    provider access by itself.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    authority_mode: Literal["VETO_ONLY_EXTERNAL_PRICING_PIN_REQUIRED"] = (
        "VETO_ONLY_EXTERNAL_PRICING_PIN_REQUIRED"
    )
    audit_model_refresh_pricing_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    pricing_authority_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    expected_workflow_status_sha256: str = Field(pattern=_SHA256_PATTERN)
    workflow_status_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_guard_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    previous_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    current_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    pricing_tolerance_fraction: str = Field(min_length=1, max_length=66)
    technical_pricing_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_pricing_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_qualification_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_production_selection_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_selection_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_selection_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_scope_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_context_sha256: str = Field(pattern=_SHA256_PATTERN)
    client_constraints_sha256: str = Field(pattern=_SHA256_PATTERN)
    verified_at: datetime
    expires_at: datetime
    audit_model_ids: tuple[str, ...] = Field(min_length=1, max_length=128)
    audit_routes: tuple[SchedulerAuditModelRefreshPricingRouteBinding, ...] = Field(
        min_length=1,
        max_length=128,
    )
    runtime_authorized: Literal[False] = False
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def from_evidence(
        cls,
        evidence: AuditModelRefreshPricingEvidence,
    ) -> SchedulerAuditModelRefreshPricingBinding:
        """Project canonical pricing evidence without retaining live authority."""

        from mmaudit.models.refresh_runtime import (
            AuditModelRefreshPricingEvidence as PricingEvidence,
        )

        if type(evidence) is not PricingEvidence:
            raise ValueError("scheduler pricing binding requires exact canonical evidence")
        canonical = PricingEvidence.model_validate_json(evidence.model_dump_json(), strict=True)
        if canonical != evidence:
            raise ValueError("scheduler pricing evidence changed during canonicalization")
        authority_payload = {
            "verified_at": canonical.verified_at,
            "expires_at": canonical.expires_at,
            "workflow_status_sha256": canonical.workflow_status_sha256,
            "refresh_evidence_sha256": canonical.refresh_evidence_sha256,
            "refresh_guard_capability_sha256": canonical.refresh_guard_capability_sha256,
            "technical_qualification_capability_sha256": (
                canonical.technical_qualification_capability_sha256
            ),
            "technical_production_selection_sha256": (
                canonical.technical_production_selection_sha256
            ),
            "audit_selection_capability_sha256": (canonical.audit_selection_capability_sha256),
            "audit_selection_sha256": canonical.audit_selection_sha256,
            "pricing_evidence_sha256": canonical.evidence_sha256,
        }
        routes = tuple(
            SchedulerAuditModelRefreshPricingRouteBinding(
                exact_model_id=route.exact_model_id,
                approved_provider_endpoint=route.approved_provider_endpoint,
                pricing_route_evidence_sha256=route.route_evidence_sha256,
                refresh_route_evidence_sha256=route.refresh_route_evidence_sha256,
                qualified_pricing_snapshot_sha256=(route.qualified_pricing_snapshot_sha256),
                baseline_pricing_sha256=route.baseline_pricing_sha256,
                current_pricing_sha256=route.current_pricing_sha256,
            )
            for route in canonical.routes
            if route.audit_selected
        )
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "evidence_authority": "comparison_required",
            "authority_mode": "VETO_ONLY_EXTERNAL_PRICING_PIN_REQUIRED",
            "audit_model_refresh_pricing_evidence_sha256": canonical.evidence_sha256,
            "pricing_authority_capability_sha256": scheduler_canonical_sha256(authority_payload),
            "expected_workflow_status_sha256": canonical.expected_workflow_status_sha256,
            "workflow_status_sha256": canonical.workflow_status_sha256,
            "refresh_evidence_sha256": canonical.refresh_evidence_sha256,
            "refresh_guard_capability_sha256": canonical.refresh_guard_capability_sha256,
            "previous_snapshot_sha256": canonical.previous_snapshot_sha256,
            "current_snapshot_sha256": canonical.current_snapshot_sha256,
            "pricing_tolerance_fraction": canonical.pricing_tolerance_fraction,
            "technical_pricing_route_set_sha256": (canonical.technical_pricing_route_set_sha256),
            "audit_pricing_route_set_sha256": canonical.audit_pricing_route_set_sha256,
            "technical_qualification_capability_sha256": (
                canonical.technical_qualification_capability_sha256
            ),
            "technical_production_selection_sha256": (
                canonical.technical_production_selection_sha256
            ),
            "audit_selection_capability_sha256": (canonical.audit_selection_capability_sha256),
            "audit_selection_sha256": canonical.audit_selection_sha256,
            "audit_scope_sha256": canonical.audit_scope_sha256,
            "source_sha256": canonical.source_sha256,
            "audit_context_sha256": canonical.audit_context_sha256,
            "client_constraints_sha256": canonical.client_constraints_sha256,
            "verified_at": canonical.verified_at,
            "expires_at": canonical.expires_at,
            "audit_model_ids": canonical.audit_model_ids,
            "audit_routes": routes,
            "runtime_authorized": False,
        }
        return cls(**values, binding_sha256=scheduler_canonical_sha256(values))

    @field_validator("audit_model_ids")
    @classmethod
    def model_ids_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            re.fullmatch(_MODEL_ID_PATTERN, model_id) is None for model_id in value
        ):
            raise ValueError("scheduler pricing model IDs must be exact, unique, and sorted")
        return value

    @field_validator("verified_at", "expires_at")
    @classmethod
    def times_are_whole_second_utc(cls, value: datetime) -> datetime:
        if (
            type(value) is not datetime
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
            or value.microsecond != 0
        ):
            raise ValueError("scheduler pricing times must be whole-second UTC")
        return value

    @field_validator("runtime_authorized", mode="before")
    @classmethod
    def authority_is_literal_false(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("scheduler pricing authority flag must be a literal boolean")
        return value

    def route_for(
        self,
        exact_model_id: str,
    ) -> SchedulerAuditModelRefreshPricingRouteBinding:
        matches = tuple(item for item in self.audit_routes if item.exact_model_id == exact_model_id)
        if len(matches) != 1:
            raise ValueError(f"model is absent from scheduler pricing binding: {exact_model_id}")
        return matches[0]

    @model_validator(mode="after")
    def pricing_binding_is_canonical_and_exact(self) -> Self:
        route_ids = tuple(item.exact_model_id for item in self.audit_routes)
        if (
            self.expected_workflow_status_sha256 != self.workflow_status_sha256
            or route_ids != self.audit_model_ids
            or route_ids != tuple(sorted(set(route_ids)))
            or not self.verified_at < self.expires_at
        ):
            raise ValueError("scheduler pricing binding is not exact or current-bounded")
        if self.binding_sha256 != _model_sha256(self, exclude={"binding_sha256"}):
            raise ValueError("scheduler pricing binding hash is inconsistent")
        return self


class SchedulerBindings(StrictModel):
    """Immutable hash-only inputs that define one scheduler campaign."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    algorithm_version: Literal[
        "mmaudit.seven-pass-scheduler.v1",
        "mmaudit.seven-pass-scheduler.v2",
    ] = SCHEDULER_ALGORITHM_VERSION
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    analysis_input_sha256: str = Field(pattern=_SHA256_PATTERN)
    effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    shard_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    model_selection_sha256: str = Field(pattern=_SHA256_PATTERN)
    qualification_sha256: str = Field(pattern=_SHA256_PATTERN)
    prompt_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    schema_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    tool_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    cost_ledger_baseline_sha256: str = Field(
        default=ABSENT_COST_LEDGER_BASELINE_SHA256,
        pattern=_SHA256_PATTERN,
    )
    privacy_evidence_custody_sha256: str = Field(
        default=ABSENT_PRIVACY_EVIDENCE_CUSTODY_SHA256,
        pattern=_SHA256_PATTERN,
    )
    audit_model_selection: SchedulerAuditModelSelectionBinding | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh: SchedulerAuditModelRefreshBinding | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_pricing: SchedulerAuditModelRefreshPricingBinding | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    bindings_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        source_sha256: str,
        analysis_input_sha256: str,
        effective_config_sha256: str,
        shard_inventory_sha256: str,
        model_selection_sha256: str,
        qualification_sha256: str,
        prompt_set_sha256: str,
        schema_set_sha256: str,
        tool_policy_sha256: str,
        cost_ledger_baseline_sha256: str = ABSENT_COST_LEDGER_BASELINE_SHA256,
        privacy_evidence_custody_sha256: str = ABSENT_PRIVACY_EVIDENCE_CUSTODY_SHA256,
        audit_model_selection_evidence: AuditModelSelectionEvidenceBundle | None = None,
        audit_model_selection: SchedulerAuditModelSelectionBinding | None = None,
        audit_model_refresh_evidence: AuditModelRefreshEvidence | None = None,
        audit_model_refresh: SchedulerAuditModelRefreshBinding | None = None,
        audit_model_refresh_pricing_evidence: AuditModelRefreshPricingEvidence | None = None,
        audit_model_refresh_pricing: SchedulerAuditModelRefreshPricingBinding | None = None,
    ) -> SchedulerBindings:
        if audit_model_selection_evidence is not None and audit_model_selection is not None:
            raise ValueError("scheduler audit selection can have only one exact source")
        validated_audit_selection = (
            SchedulerAuditModelSelectionBinding.from_evidence_bundle(audit_model_selection_evidence)
            if audit_model_selection_evidence is not None
            else (
                SchedulerAuditModelSelectionBinding.model_validate(
                    audit_model_selection.model_dump(mode="python")
                )
                if audit_model_selection is not None
                else None
            )
        )
        if audit_model_refresh_evidence is not None and audit_model_refresh is not None:
            raise ValueError("scheduler model refresh can have only one exact source")
        validated_model_refresh = (
            SchedulerAuditModelRefreshBinding.from_evidence(audit_model_refresh_evidence)
            if audit_model_refresh_evidence is not None
            else (
                SchedulerAuditModelRefreshBinding.model_validate(
                    audit_model_refresh.model_dump(mode="python")
                )
                if audit_model_refresh is not None
                else None
            )
        )
        if (
            audit_model_refresh_pricing_evidence is not None
            and audit_model_refresh_pricing is not None
        ):
            raise ValueError("scheduler refresh pricing can have only one exact source")
        validated_refresh_pricing = (
            SchedulerAuditModelRefreshPricingBinding.from_evidence(
                audit_model_refresh_pricing_evidence
            )
            if audit_model_refresh_pricing_evidence is not None
            else (
                SchedulerAuditModelRefreshPricingBinding.model_validate(
                    audit_model_refresh_pricing.model_dump(mode="python")
                )
                if audit_model_refresh_pricing is not None
                else None
            )
        )
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "algorithm_version": SCHEDULER_ALGORITHM_VERSION,
            "evidence_authority": "comparison_required",
            "source_sha256": source_sha256,
            "analysis_input_sha256": analysis_input_sha256,
            "effective_config_sha256": effective_config_sha256,
            "shard_inventory_sha256": shard_inventory_sha256,
            "model_selection_sha256": model_selection_sha256,
            "qualification_sha256": qualification_sha256,
            "prompt_set_sha256": prompt_set_sha256,
            "schema_set_sha256": schema_set_sha256,
            "tool_policy_sha256": tool_policy_sha256,
            "cost_ledger_baseline_sha256": cost_ledger_baseline_sha256,
            "privacy_evidence_custody_sha256": privacy_evidence_custody_sha256,
        }
        if validated_audit_selection is not None:
            values["audit_model_selection"] = validated_audit_selection
        if validated_model_refresh is not None:
            values["audit_model_refresh"] = validated_model_refresh
        if validated_refresh_pricing is not None:
            values["audit_model_refresh_pricing"] = validated_refresh_pricing
        return cls(**values, bindings_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def bindings_hash_is_exact(self) -> Self:
        if (
            self.audit_model_selection is not None
            and self.audit_model_selection.source_sha256 != self.source_sha256
        ):
            raise ValueError("scheduler audit selection differs from campaign source")
        if self.audit_model_refresh is not None and self.audit_model_selection is None:
            raise ValueError("scheduler model refresh requires exact audit selection custody")
        if self.audit_model_refresh is not None and self.audit_model_selection is not None:
            refresh = self.audit_model_refresh
            selection = self.audit_model_selection
            if (
                refresh.source_sha256 != self.source_sha256
                or refresh.source_sha256 != selection.source_sha256
                or refresh.audit_model_ids != selection.selected_model_ids
                or refresh.technical_qualification_capability_sha256
                != selection.technical_qualification_capability_sha256
                or refresh.technical_production_selection_sha256
                != selection.technical_production_selection_sha256
                or refresh.audit_selection_sha256 != selection.audit_selection_sha256
                or refresh.audit_scope_sha256 != selection.audit_scope_sha256
                or refresh.audit_context_sha256 != selection.audit_context_sha256
                or refresh.client_constraints_sha256 != selection.client_constraints_sha256
                or refresh.expires_at > selection.selection_expires_at
            ):
                raise ValueError(
                    "scheduler model refresh differs from exact audit and technical selection"
                )
        if self.audit_model_refresh_pricing is not None:
            if self.audit_model_refresh is None or self.audit_model_selection is None:
                raise ValueError(
                    "scheduler refresh pricing requires refresh and audit selection custody"
                )
            pricing = self.audit_model_refresh_pricing
            refresh = self.audit_model_refresh
            selection = self.audit_model_selection
            refresh_routes = {
                route.exact_model_id: route.route_evidence_sha256 for route in refresh.audit_routes
            }
            if (
                pricing.source_sha256 != self.source_sha256
                or pricing.source_sha256 != selection.source_sha256
                or pricing.refresh_evidence_sha256 != refresh.audit_model_refresh_evidence_sha256
                or pricing.refresh_guard_capability_sha256 != refresh.guard_capability_sha256
                or pricing.workflow_status_sha256 != refresh.workflow_status_sha256
                or pricing.current_snapshot_sha256 != refresh.snapshot_sha256
                or pricing.technical_qualification_capability_sha256
                != selection.technical_qualification_capability_sha256
                or pricing.technical_production_selection_sha256
                != selection.technical_production_selection_sha256
                or pricing.audit_selection_capability_sha256
                != refresh.audit_selection_capability_sha256
                or pricing.audit_selection_sha256 != selection.audit_selection_sha256
                or pricing.audit_scope_sha256 != selection.audit_scope_sha256
                or pricing.audit_context_sha256 != selection.audit_context_sha256
                or pricing.client_constraints_sha256 != selection.client_constraints_sha256
                or pricing.audit_model_ids != selection.selected_model_ids
                or pricing.audit_model_ids != refresh.audit_model_ids
                or pricing.expires_at != refresh.expires_at
                or any(
                    refresh_routes.get(route.exact_model_id) != route.refresh_route_evidence_sha256
                    for route in pricing.audit_routes
                )
            ):
                raise ValueError(
                    "scheduler refresh pricing differs from exact refresh and selection custody"
                )
        if self.bindings_sha256 != _model_sha256(self, exclude={"bindings_sha256"}):
            raise ValueError("scheduler bindings hash does not match its typed fields")
        return self


class SchedulerAnalysisInputDescriptor(StrictModel):
    """Hash-only commitment to one typed deterministic pre-scheduler input."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    label: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    type_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.|\[\], ]{0,255}$")
    value_sha256: str = Field(pattern=_SHA256_PATTERN)
    descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        label: str,
        type_name: str,
        value: object,
    ) -> SchedulerAnalysisInputDescriptor:
        values = {
            "label": label,
            "type_name": type_name,
            "value_sha256": scheduler_canonical_sha256(value),
        }
        return cls(**values, descriptor_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def descriptor_hash_is_exact(self) -> Self:
        if self.descriptor_sha256 != _model_sha256(self, exclude={"descriptor_sha256"}):
            raise ValueError("scheduler analysis-input descriptor hash is inconsistent")
        return self


class SchedulerAnalysisInputInventory(StrictModel):
    """Closed complete inventory of deterministic inputs preceding scheduling."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1"] = "1.1"
    descriptors: tuple[SchedulerAnalysisInputDescriptor, ...] = Field(
        min_length=len(SCHEDULER_ANALYSIS_INPUT_LABELS_V1),
        max_length=len(SCHEDULER_ANALYSIS_INPUT_LABELS),
    )
    analysis_input_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        descriptors: Iterable[SchedulerAnalysisInputDescriptor],
    ) -> SchedulerAnalysisInputInventory:
        canonical = tuple(sorted(descriptors, key=lambda item: item.label))
        values = {
            "schema_version": "1.1",
            "descriptors": canonical,
        }
        return cls(**values, analysis_input_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def inventory_is_complete_and_exact(self) -> Self:
        labels = tuple(item.label for item in self.descriptors)
        expected_labels = (
            SCHEDULER_ANALYSIS_INPUT_LABELS_V1
            if self.schema_version == "1.0"
            else SCHEDULER_ANALYSIS_INPUT_LABELS
        )
        if labels != tuple(sorted(expected_labels)):
            raise ValueError("scheduler analysis-input inventory is incomplete or duplicated")
        if self.analysis_input_sha256 != _model_sha256(
            self,
            exclude={"analysis_input_sha256"},
        ):
            raise ValueError("scheduler analysis-input inventory hash is inconsistent")
        return self


class SchedulerScope(StrictModel):
    """Canonical shard scope included in every task and result identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: SchedulerScopeKind
    shard_ids: tuple[str, ...] = ()
    scope_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        kind: SchedulerScopeKind,
        shard_ids: Iterable[str] = (),
    ) -> SchedulerScope:
        canonical_ids = tuple(sorted(set(shard_ids)))
        values = {"kind": kind, "shard_ids": canonical_ids}
        return cls(**values, scope_sha256=scheduler_canonical_sha256(values))

    @classmethod
    def global_scope(cls) -> SchedulerScope:
        return cls.build(SchedulerScopeKind.GLOBAL)

    @classmethod
    def single_shard(cls, shard_id: str) -> SchedulerScope:
        return cls.build(SchedulerScopeKind.SINGLE_SHARD, (shard_id,))

    @classmethod
    def shard_set(cls, shard_ids: Iterable[str]) -> SchedulerScope:
        return cls.build(SchedulerScopeKind.SHARD_SET, shard_ids)

    @field_validator("shard_ids")
    @classmethod
    def shard_ids_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            re.fullmatch(_SHARD_ID_PATTERN, shard_id) is None for shard_id in value
        ):
            raise ValueError("scheduler scope shard IDs must be valid, unique, and sorted")
        return value

    @model_validator(mode="after")
    def scope_shape_and_hash_are_exact(self) -> Self:
        if self.kind is SchedulerScopeKind.GLOBAL and self.shard_ids:
            raise ValueError("global scheduler scope cannot enumerate individual shards")
        if self.kind is SchedulerScopeKind.SINGLE_SHARD and len(self.shard_ids) != 1:
            raise ValueError("single-shard scheduler scope requires exactly one shard")
        if self.kind is SchedulerScopeKind.SHARD_SET and len(self.shard_ids) < 2:
            raise ValueError("shard-set scheduler scope requires at least two shards")
        if self.scope_sha256 != _model_sha256(self, exclude={"scope_sha256"}):
            raise ValueError("scheduler scope hash does not match its typed fields")
        return self


class SchedulerPrivacyEvidenceCustody(StrictModel):
    """Exact non-secret privacy files committed before first provider dispatch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_provenance_path: Literal["privacy-source-provenance.json"] = (
        "privacy-source-provenance.json"
    )
    source_provenance_size: int = Field(ge=1, le=_MAX_PRIVACY_EVIDENCE_BYTES)
    source_provenance_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_provenance_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    effective_policy_path: Literal["privacy-policy.json"] = "privacy-policy.json"
    effective_policy_size: int = Field(ge=1, le=_MAX_PRIVACY_EVIDENCE_BYTES)
    effective_policy_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    effective_policy_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_source_provenance_sha256: str = Field(pattern=_SHA256_PATTERN)
    custody_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        source_sha256: str,
        source_provenance_size: int,
        source_provenance_artifact_sha256: str,
        source_provenance_evidence_sha256: str,
        effective_policy_size: int,
        effective_policy_artifact_sha256: str,
        effective_policy_evidence_sha256: str,
        policy_source_provenance_sha256: str,
    ) -> SchedulerPrivacyEvidenceCustody:
        values = {
            "schema_version": "1.0",
            "evidence_authority": "comparison_required",
            "source_sha256": source_sha256,
            "source_provenance_path": "privacy-source-provenance.json",
            "source_provenance_size": source_provenance_size,
            "source_provenance_artifact_sha256": source_provenance_artifact_sha256,
            "source_provenance_evidence_sha256": source_provenance_evidence_sha256,
            "effective_policy_path": "privacy-policy.json",
            "effective_policy_size": effective_policy_size,
            "effective_policy_artifact_sha256": effective_policy_artifact_sha256,
            "effective_policy_evidence_sha256": effective_policy_evidence_sha256,
            "policy_source_provenance_sha256": policy_source_provenance_sha256,
        }
        return cls(**values, custody_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def custody_is_exact(self) -> Self:
        if self.policy_source_provenance_sha256 != self.source_provenance_evidence_sha256:
            raise ValueError("scheduler privacy policy differs from source provenance")
        if self.custody_sha256 != _model_sha256(self, exclude={"custody_sha256"}):
            raise ValueError("scheduler privacy-evidence custody hash is inconsistent")
        return self


class SchedulerCampaignManifest(StrictModel):
    """Frozen campaign root from which every pass identity is derived."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1", "1.2"] = "1.0"
    algorithm_version: Literal[
        "mmaudit.seven-pass-scheduler.v1",
        "mmaudit.seven-pass-scheduler.v2",
    ] = SCHEDULER_ALGORITHM_VERSION
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    bindings: SchedulerBindings
    shard_inventory: SchedulerShardInventory
    cost_ledger_baseline: SchedulerCostLedgerBaseline | None = None
    privacy_evidence_custody: SchedulerPrivacyEvidenceCustody | None = None
    terminal_report_authority_required: bool = Field(
        default=False,
        exclude_if=lambda value: not value,
    )
    terminal_evidence_authority_required: bool = Field(
        default=False,
        exclude_if=lambda value: not value,
    )
    shard_ids: tuple[str, ...] = Field(min_length=1, max_length=100_000)
    mandatory_passes: tuple[SchedulerPassKind, ...]
    campaign_id: str = Field(pattern=r"^scheduler-campaign-[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        bindings: SchedulerBindings,
        shard_inventory: SchedulerShardInventory,
        cost_ledger_baseline: SchedulerCostLedgerBaseline | None = None,
        privacy_evidence_custody: SchedulerPrivacyEvidenceCustody | None = None,
        require_terminal_report_authority: bool = False,
    ) -> SchedulerCampaignManifest:
        validated_bindings = SchedulerBindings.model_validate(bindings.model_dump(mode="python"))
        validated_inventory = SchedulerShardInventory.model_validate(
            shard_inventory.model_dump(mode="python")
        )
        validated_baseline = (
            SchedulerCostLedgerBaseline.model_validate(
                cost_ledger_baseline.model_dump(mode="python")
            )
            if cost_ledger_baseline is not None
            else None
        )
        validated_privacy = (
            SchedulerPrivacyEvidenceCustody.model_validate(
                privacy_evidence_custody.model_dump(mode="python")
            )
            if privacy_evidence_custody is not None
            else None
        )
        values: dict[str, Any] = {
            "schema_version": "1.2" if require_terminal_report_authority else "1.0",
            "algorithm_version": SCHEDULER_ALGORITHM_VERSION,
            "evidence_authority": "comparison_required",
            "bindings": validated_bindings,
            "shard_inventory": validated_inventory,
            "cost_ledger_baseline": validated_baseline,
            "privacy_evidence_custody": validated_privacy,
            **(
                {"terminal_report_authority_required": True}
                if require_terminal_report_authority
                else {}
            ),
            **(
                {"terminal_evidence_authority_required": True}
                if require_terminal_report_authority
                else {}
            ),
            "shard_ids": validated_inventory.shard_ids,
            "mandatory_passes": SCHEDULER_PASS_ORDER,
        }
        campaign_id = "scheduler-campaign-" + scheduler_canonical_sha256(values)
        body = {**values, "campaign_id": campaign_id}
        return cls(**body, manifest_sha256=scheduler_canonical_sha256(body))

    @field_validator("shard_ids")
    @classmethod
    def manifest_shards_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            re.fullmatch(_SHARD_ID_PATTERN, shard_id) is None for shard_id in value
        ):
            raise ValueError("scheduler campaign shards must be valid, unique, and sorted")
        return value

    def pass_id(self, pass_kind: SchedulerPassKind) -> str:
        digest = scheduler_canonical_sha256(
            {
                "domain": "mmaudit.scheduler.pass-identity.v1",
                "campaign_id": self.campaign_id,
                "manifest_sha256": self.manifest_sha256,
                "pass_kind": pass_kind,
            }
        )
        return "scheduler-pass-" + digest

    @model_validator(mode="after")
    def campaign_identity_is_exact(self) -> Self:
        expected_authority_modes = {
            "1.0": (False, False),
            "1.1": (True, False),
            "1.2": (True, True),
        }[self.schema_version]
        if (
            self.terminal_report_authority_required,
            self.terminal_evidence_authority_required,
        ) != expected_authority_modes:
            raise ValueError("scheduler campaign terminal-report authority mode is inconsistent")
        if self.mandatory_passes != SCHEDULER_PASS_ORDER:
            raise ValueError("scheduler campaign must retain all seven ordered mandatory passes")
        if self.algorithm_version != self.bindings.algorithm_version:
            raise ValueError("scheduler campaign algorithm differs from its exact bindings")
        if self.shard_ids != self.shard_inventory.shard_ids:
            raise ValueError("scheduler campaign shard IDs differ from its exact inventory")
        if (
            self.bindings.source_sha256 != self.shard_inventory.source_tree_sha256
            or self.bindings.shard_inventory_sha256 != self.shard_inventory.inventory_sha256
        ):
            raise ValueError("scheduler campaign bindings differ from its exact shard inventory")
        expected_cost_baseline_sha256 = (
            self.cost_ledger_baseline.baseline_sha256
            if self.cost_ledger_baseline is not None
            else ABSENT_COST_LEDGER_BASELINE_SHA256
        )
        if self.bindings.cost_ledger_baseline_sha256 != expected_cost_baseline_sha256:
            raise ValueError("scheduler campaign differs from its exact cost-ledger baseline")
        expected_privacy_custody_sha256 = (
            self.privacy_evidence_custody.custody_sha256
            if self.privacy_evidence_custody is not None
            else ABSENT_PRIVACY_EVIDENCE_CUSTODY_SHA256
        )
        if self.bindings.privacy_evidence_custody_sha256 != expected_privacy_custody_sha256:
            raise ValueError("scheduler campaign differs from its privacy-evidence custody")
        if (
            self.privacy_evidence_custody is not None
            and self.privacy_evidence_custody.source_sha256 != self.bindings.source_sha256
        ):
            raise ValueError("scheduler privacy custody differs from its exact source binding")
        values = self.model_dump(
            mode="json",
            exclude={"campaign_id", "manifest_sha256"},
        )
        expected_id = "scheduler-campaign-" + scheduler_canonical_sha256(values)
        if self.campaign_id != expected_id:
            raise ValueError("scheduler campaign ID does not match its immutable inputs")
        if self.manifest_sha256 != _model_sha256(self, exclude={"manifest_sha256"}):
            raise ValueError("scheduler campaign manifest hash is inconsistent")
        return self


class SchedulerPassDependency(StrictModel):
    """One exact prior pass artifact required by a later pass."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pass_kind: SchedulerPassKind
    pass_id: str = Field(pattern=r"^scheduler-pass-[0-9a-f]{64}$")
    pass_result_sha256: str = Field(pattern=_SHA256_PATTERN)
    dependency_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        pass_kind: SchedulerPassKind,
        pass_id: str,
        pass_result_sha256: str,
    ) -> SchedulerPassDependency:
        values = {
            "pass_kind": pass_kind,
            "pass_id": pass_id,
            "pass_result_sha256": pass_result_sha256,
        }
        return cls(**values, dependency_sha256=scheduler_canonical_sha256(values))

    @classmethod
    def from_result(cls, result: SchedulerPassResult) -> SchedulerPassDependency:
        return cls.build(
            pass_kind=result.plan.pass_kind,
            pass_id=result.plan.pass_id,
            pass_result_sha256=result.pass_result_sha256,
        )

    @model_validator(mode="after")
    def dependency_hash_is_exact(self) -> Self:
        if self.dependency_sha256 != _model_sha256(self, exclude={"dependency_sha256"}):
            raise ValueError("scheduler pass dependency hash is inconsistent")
        return self


class SchedulerTaskPlan(StrictModel):
    """One canonical host or model work recipe within a mandatory pass.

    The request hashes are immutable recipe commitments known while the pass is
    sealed. Blind model-surface reviews may additionally commit the exact
    requested-surface manifest before dispatch. Actual rendered input, provider
    prompt, schema, and dynamic dependency-result hashes are bound immediately
    before dispatch by :class:`SchedulerTaskActivation`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    campaign_id: str = Field(pattern=r"^scheduler-campaign-[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    pass_kind: SchedulerPassKind
    pass_id: str = Field(pattern=r"^scheduler-pass-[0-9a-f]{64}$")
    scope: SchedulerScope
    task_kind: SchedulerTaskKind
    purpose: SchedulerTaskPurpose = Field(
        default=SchedulerTaskPurpose.PRIMARY,
        exclude_if=lambda value: value is SchedulerTaskPurpose.PRIMARY,
    )
    parent_task_id: str | None = Field(
        default=None,
        pattern=r"^scheduler-task-[0-9a-f]{64}$",
        exclude_if=lambda value: value is None,
    )
    task_key: str = Field(pattern=_SAFE_KEY_PATTERN)
    role: str = Field(pattern=_ROLE_PATTERN)
    requested_model: str | None = Field(default=None, pattern=_MODEL_ID_PATTERN)
    root_lineage: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    candidate_ids: tuple[str, ...] = Field(default=(), max_length=100_000)
    model_surface_review_request_manifest_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    input_sha256: str = Field(pattern=_SHA256_PATTERN)
    prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    system_prompt_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    normalizer_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    response_schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    task_id: str = Field(pattern=r"^scheduler-task-[0-9a-f]{64}$")
    logical_request_id: str = Field(pattern=r"^scheduler-request-[0-9a-f]{64}$")
    task_plan_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        manifest: SchedulerCampaignManifest,
        pass_kind: SchedulerPassKind,
        scope: SchedulerScope,
        task_kind: SchedulerTaskKind,
        task_key: str,
        role: str,
        input_sha256: str,
        prompt_sha256: str,
        response_schema_sha256: str,
        system_prompt_sha256: str | None = None,
        normalizer_sha256: str | None = None,
        requested_model: str | None = None,
        root_lineage: str | None = None,
        candidate_ids: Iterable[str] = (),
        model_surface_review_request_manifest_sha256: str | None = None,
        purpose: SchedulerTaskPurpose = SchedulerTaskPurpose.PRIMARY,
        parent_task_id: str | None = None,
    ) -> SchedulerTaskPlan:
        validated_manifest = SchedulerCampaignManifest.model_validate(
            manifest.model_dump(mode="python")
        )
        validated_scope = SchedulerScope.model_validate(scope.model_dump(mode="python"))
        if purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING and (
            validated_manifest.algorithm_version != "mmaudit.seven-pass-scheduler.v2"
            or task_kind is not SchedulerTaskKind.MODEL_REQUEST
            or pass_kind is not SchedulerPassKind.BLIND_SHARD_REVIEW
            or parent_task_id is None
            or normalizer_sha256 is not None
            or response_schema_sha256
            != scheduler_response_schema_sha256(SolidityRetrievalRequestBatch)
        ):
            raise ValueError("retrieval-planning task shape is not exact")
        if purpose is SchedulerTaskPurpose.PRIMARY and parent_task_id is not None:
            raise ValueError("primary scheduler task cannot link a parent task")
        if (
            validated_manifest.algorithm_version == "mmaudit.seven-pass-scheduler.v2"
            and task_kind is SchedulerTaskKind.MODEL_REQUEST
            and purpose is SchedulerTaskPurpose.PRIMARY
            and (
                pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
                or (
                    pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
                    and role == "business_logic"
                )
            )
            and model_surface_review_request_manifest_sha256 is None
        ):
            raise ValueError(
                "scheduler-v2 candidate-review task requires a sealed surface manifest"
            )
        audit_selection = validated_manifest.bindings.audit_model_selection
        if task_kind is SchedulerTaskKind.MODEL_REQUEST and audit_selection is not None:
            if requested_model is None or root_lineage is None:
                raise ValueError("policy-bound scheduler request lacks an exact selected model")
            selected_route = audit_selection.route_for(requested_model)
            if selected_route.root_lineage != root_lineage:
                raise ValueError("scheduler request root differs from audit-selected model")
        values: dict[str, Any] = {
            "schema_version": (
                "1.1" if purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING else "1.0"
            ),
            "evidence_authority": "comparison_required",
            "campaign_id": validated_manifest.campaign_id,
            "manifest_sha256": validated_manifest.manifest_sha256,
            "pass_kind": pass_kind,
            "pass_id": validated_manifest.pass_id(pass_kind),
            "scope": validated_scope,
            "task_kind": task_kind,
            "task_key": task_key,
            "role": role,
            "requested_model": requested_model,
            "root_lineage": root_lineage,
            "candidate_ids": _candidate_id_inventory(tuple(candidate_ids), "task candidate"),
            "input_sha256": input_sha256,
            "prompt_sha256": prompt_sha256,
            "system_prompt_sha256": system_prompt_sha256,
            "normalizer_sha256": normalizer_sha256,
            "response_schema_sha256": response_schema_sha256,
        }
        if purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING:
            values["purpose"] = purpose
            values["parent_task_id"] = parent_task_id
        if model_surface_review_request_manifest_sha256 is not None:
            values["model_surface_review_request_manifest_sha256"] = (
                model_surface_review_request_manifest_sha256
            )
        identity = scheduler_canonical_sha256(values)
        body = {
            **values,
            "task_id": "scheduler-task-" + identity,
            "logical_request_id": "scheduler-request-"
            + scheduler_canonical_sha256(
                {
                    "domain": "mmaudit.scheduler.logical-request.v1",
                    "task_identity_sha256": identity,
                }
            ),
        }
        return cls(**body, task_plan_sha256=scheduler_canonical_sha256(body))

    @model_validator(mode="after")
    def task_identity_is_exact(self) -> Self:
        model_fields_present = (
            self.requested_model is not None
            and self.root_lineage is not None
            and self.system_prompt_sha256 is not None
            and (
                self.normalizer_sha256 is not None
                or self.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
            )
        )
        if self.task_kind is SchedulerTaskKind.MODEL_REQUEST and not model_fields_present:
            raise ValueError("model scheduler task requires exact model and root lineage")
        if self.task_kind is not SchedulerTaskKind.MODEL_REQUEST and (
            self.requested_model is not None
            or self.root_lineage is not None
            or self.system_prompt_sha256 is not None
            or self.normalizer_sha256 is not None
        ):
            raise ValueError("host scheduler task cannot carry model identity")
        if self.purpose is SchedulerTaskPurpose.PRIMARY:
            if self.schema_version != "1.0" or self.parent_task_id is not None:
                raise ValueError("primary scheduler task must retain its legacy identity shape")
        elif (
            self.schema_version != "1.1"
            or self.parent_task_id is None
            or self.task_kind is not SchedulerTaskKind.MODEL_REQUEST
            or self.pass_kind is not SchedulerPassKind.BLIND_SHARD_REVIEW
            or self.normalizer_sha256 is not None
            or self.response_schema_sha256
            != scheduler_response_schema_sha256(SolidityRetrievalRequestBatch)
        ):
            raise ValueError("retrieval-planning scheduler task shape is not exact")
        _candidate_id_inventory(self.candidate_ids, "task candidate")
        if self.candidate_ids and self.task_kind is not SchedulerTaskKind.MODEL_REQUEST:
            raise ValueError("host scheduler task cannot claim model candidate review")
        if (
            self.model_surface_review_request_manifest_sha256 is not None
            and self.task_kind is not SchedulerTaskKind.MODEL_REQUEST
        ):
            raise ValueError("host scheduler task cannot claim a model-surface request manifest")
        values = self.model_dump(
            mode="json",
            exclude={"task_id", "logical_request_id", "task_plan_sha256"},
        )
        identity = scheduler_canonical_sha256(values)
        if self.task_id != "scheduler-task-" + identity:
            raise ValueError("scheduler task ID does not match its immutable work")
        expected_request_id = "scheduler-request-" + scheduler_canonical_sha256(
            {
                "domain": "mmaudit.scheduler.logical-request.v1",
                "task_identity_sha256": identity,
            }
        )
        if self.logical_request_id != expected_request_id:
            raise ValueError("scheduler logical request ID is inconsistent")
        if self.task_plan_sha256 != _model_sha256(self, exclude={"task_plan_sha256"}):
            raise ValueError("scheduler task-plan hash is inconsistent")
        return self


class SchedulerConditionalAbsence(StrictModel):
    """Typed no-work proof derived from an exact empty candidate workset."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pass_kind: SchedulerPassKind
    reason: SchedulerAbsenceReason
    candidate_workset_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_pass_result_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_output_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    absence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        reason: SchedulerAbsenceReason,
        candidate_workset: SchedulerCandidateWorkset,
    ) -> SchedulerConditionalAbsence:
        if candidate_workset.selected_candidate_ids:
            raise ValueError("scheduler conditional absence requires an empty bound workset")
        values = {
            "pass_kind": candidate_workset.pass_kind,
            "reason": reason,
            "candidate_workset_sha256": candidate_workset.workset_sha256,
            "source_pass_result_sha256": candidate_workset.source_pass_result_sha256,
            "source_output_artifact_sha256": (candidate_workset.source_output_artifact_sha256),
        }
        return cls(**values, absence_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def absence_contract_is_closed_and_exact(self) -> Self:
        expected = {
            SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION: (
                SchedulerAbsenceReason.NO_HIGH_CRITICAL_CANDIDATES,
            ),
            SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION: (
                SchedulerAbsenceReason.NO_VALIDATION_CANDIDATES,
            ),
        }.get(self.pass_kind)
        if expected != (self.reason,):
            raise ValueError("scheduler conditional absence is not permitted for this pass")
        if self.absence_sha256 != _model_sha256(self, exclude={"absence_sha256"}):
            raise ValueError("scheduler conditional-absence hash is inconsistent")
        return self


def _retrieval_role_budget_plans_for_tasks(
    tasks: tuple[SchedulerTaskPlan, ...],
) -> tuple[SolidityRetrievalRoleBudgetPlan, ...]:
    """Derive complete per-role ceilings from the exact retrieval-child inventory."""

    primary_by_id = {
        task.task_id: task for task in tasks if task.purpose is SchedulerTaskPurpose.PRIMARY
    }
    primary_ids_by_role: dict[str, list[str]] = {}
    for child in tasks:
        if child.purpose is not SchedulerTaskPurpose.RETRIEVAL_PLANNING:
            continue
        parent = primary_by_id.get(child.parent_task_id or "")
        if parent is not None:
            primary_ids_by_role.setdefault(parent.role, []).append(parent.task_id)
    return tuple(
        SolidityRetrievalRoleBudgetPlan.build(
            role=role,
            primary_task_ids=primary_ids,
        )
        for role, primary_ids in sorted(primary_ids_by_role.items())
    )


class SchedulerPassPlan(StrictModel):
    """A sealed exact task inventory for one mandatory pass."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    manifest: SchedulerCampaignManifest
    pass_kind: SchedulerPassKind
    pass_id: str = Field(pattern=r"^scheduler-pass-[0-9a-f]{64}$")
    dependencies: tuple[SchedulerPassDependency, ...]
    tasks: tuple[SchedulerTaskPlan, ...] = Field(min_length=1, max_length=100_000)
    retrieval_role_budget_plans: tuple[SolidityRetrievalRoleBudgetPlan, ...] = Field(
        default=(),
        max_length=100_000,
        exclude_if=lambda value: not value,
    )
    candidate_workset: SchedulerCandidateWorkset | None = None
    conditional_absence: SchedulerConditionalAbsence | None = None
    blind_plan_barrier_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    pass_plan_id: str = Field(pattern=r"^scheduler-plan-[0-9a-f]{64}$")
    pass_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    _tasks_by_id: dict[str, SchedulerTaskPlan] = PrivateAttr(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        """Build the immutable plan's exact task index once after validation."""

        self._tasks_by_id.update((task.task_id, task) for task in self.tasks)

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        """Copy the plan while keeping its private task index exact."""

        copied = super().model_copy(update=update, deep=deep)
        copied._tasks_by_id = {task.task_id: task for task in copied.tasks}
        return copied

    def require_exact_task(self, task: SchedulerTaskPlan) -> None:
        """Reject a task absent from this exact sealed plan in constant time."""

        if not self.has_exact_task(task):
            raise ValueError("scheduler task is not in the sealed pass plan")

    def has_exact_task(self, task: SchedulerTaskPlan) -> bool:
        """Return whether an exact task belongs to this immutable sealed plan."""

        return self._tasks_by_id.get(task.task_id) == task

    def retrieval_role_budget_plan_for_task(
        self,
        primary_task_id: str,
    ) -> SolidityRetrievalRoleBudgetPlan:
        """Return the detached role plan that contains one exact primary task."""

        matches = tuple(
            role_plan
            for role_plan in self.retrieval_role_budget_plans
            if any(
                allocation.primary_task_id == primary_task_id
                for allocation in role_plan.allocations
            )
        )
        if len(matches) != 1:
            raise KeyError("scheduler pass lacks one exact retrieval role budget for the task")
        return SolidityRetrievalRoleBudgetPlan.model_validate(matches[0].model_dump(mode="python"))

    def retrieval_role_budget_allocation_for_task(
        self,
        primary_task_id: str,
    ) -> SolidityRetrievalRoleBudgetAllocation:
        """Return the detached static allocation for one exact primary task."""

        return self.retrieval_role_budget_plan_for_task(primary_task_id).allocation_for_task(
            primary_task_id
        )

    @classmethod
    def build(
        cls,
        *,
        manifest: SchedulerCampaignManifest,
        pass_kind: SchedulerPassKind,
        dependencies: Iterable[SchedulerPassDependency],
        tasks: Iterable[SchedulerTaskPlan],
        candidate_workset: SchedulerCandidateWorkset | None = None,
        conditional_absence: SchedulerConditionalAbsence | None = None,
    ) -> SchedulerPassPlan:
        validated_manifest = SchedulerCampaignManifest.model_validate(
            manifest.model_dump(mode="python")
        )
        dependency_order = {kind: index for index, kind in enumerate(SCHEDULER_PASS_ORDER)}
        canonical_dependencies = tuple(
            sorted(
                (
                    SchedulerPassDependency.model_validate(item.model_dump(mode="python"))
                    for item in dependencies
                ),
                key=lambda item: dependency_order[item.pass_kind],
            )
        )
        canonical_tasks = tuple(
            sorted(
                (
                    SchedulerTaskPlan.model_validate(item.model_dump(mode="python"))
                    for item in tasks
                ),
                key=lambda item: item.task_id,
            )
        )
        retrieval_role_budget_plans = _retrieval_role_budget_plans_for_tasks(canonical_tasks)
        pass_id = validated_manifest.pass_id(pass_kind)
        barrier = (
            scheduler_canonical_sha256(
                {
                    "domain": "mmaudit.scheduler.blind-plan-barrier.v1",
                    "campaign_id": validated_manifest.campaign_id,
                    "pass_id": pass_id,
                    "task_plan_sha256s": [item.task_plan_sha256 for item in canonical_tasks],
                }
            )
            if pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
            else None
        )
        values: dict[str, Any] = {
            "schema_version": "1.1" if retrieval_role_budget_plans else "1.0",
            "evidence_authority": "comparison_required",
            "manifest": validated_manifest,
            "pass_kind": pass_kind,
            "pass_id": pass_id,
            "dependencies": canonical_dependencies,
            "tasks": canonical_tasks,
            "candidate_workset": candidate_workset,
            "conditional_absence": conditional_absence,
            "blind_plan_barrier_sha256": barrier,
        }
        if retrieval_role_budget_plans:
            values["retrieval_role_budget_plans"] = retrieval_role_budget_plans
        plan_id = "scheduler-plan-" + scheduler_canonical_sha256(values)
        body = {**values, "pass_plan_id": plan_id}
        return cls(**body, pass_plan_sha256=scheduler_canonical_sha256(body))

    @model_validator(mode="after")
    def plan_is_complete_canonical_and_sealed(self) -> Self:
        if self.pass_id != self.manifest.pass_id(self.pass_kind):
            raise ValueError("scheduler pass ID differs from its campaign")
        preceding_kinds = SCHEDULER_PASS_ORDER[: _pass_index(self.pass_kind)]
        observed_kinds = tuple(item.pass_kind for item in self.dependencies)
        if observed_kinds != preceding_kinds:
            raise ValueError("scheduler pass must bind every exact prior pass artifact")
        if any(
            dependency.pass_id != self.manifest.pass_id(dependency.pass_kind)
            for dependency in self.dependencies
        ):
            raise ValueError("scheduler pass dependency ID differs from its campaign")
        task_ids = tuple(item.task_id for item in self.tasks)
        if task_ids != tuple(sorted(set(task_ids))):
            raise ValueError("scheduler pass tasks must be unique and sorted")
        primary_tasks = tuple(
            task for task in self.tasks if task.purpose is SchedulerTaskPurpose.PRIMARY
        )
        retrieval_tasks = tuple(
            task for task in self.tasks if task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
        )
        if not primary_tasks:
            raise ValueError("scheduler pass requires at least one primary task")
        tasks_by_id = {task.task_id: task for task in self.tasks}
        retrieval_parent_ids: list[str] = []
        for child in retrieval_tasks:
            parent = tasks_by_id.get(child.parent_task_id or "")
            if (
                self.manifest.algorithm_version != "mmaudit.seven-pass-scheduler.v2"
                or self.pass_kind is not SchedulerPassKind.BLIND_SHARD_REVIEW
                or parent is None
                or parent.purpose is not SchedulerTaskPurpose.PRIMARY
                or child.task_id == parent.task_id
                or child.logical_request_id == parent.logical_request_id
                or child.scope != parent.scope
                or child.role != parent.role
                or child.requested_model != parent.requested_model
                or child.root_lineage != parent.root_lineage
                or child.candidate_ids != parent.candidate_ids
                or child.model_surface_review_request_manifest_sha256
                != parent.model_surface_review_request_manifest_sha256
            ):
                raise ValueError("scheduler retrieval child differs from its exact primary parent")
            retrieval_parent_ids.append(parent.task_id)
        if len(retrieval_parent_ids) != len(set(retrieval_parent_ids)):
            raise ValueError("scheduler primary task cannot have multiple retrieval children")
        expected_budget_plans = _retrieval_role_budget_plans_for_tasks(self.tasks)
        if self.retrieval_role_budget_plans != expected_budget_plans:
            raise ValueError(
                "scheduler retrieval role budgets differ from the exact child inventory"
            )
        expected_schema_version = "1.1" if expected_budget_plans else "1.0"
        if self.schema_version != expected_schema_version:
            raise ValueError("scheduler pass-plan schema differs from its retrieval budget shape")
        manifest_shards = set(self.manifest.shard_ids)
        for task in self.tasks:
            if (
                task.campaign_id != self.manifest.campaign_id
                or task.manifest_sha256 != self.manifest.manifest_sha256
                or task.pass_kind is not self.pass_kind
                or task.pass_id != self.pass_id
            ):
                raise ValueError("scheduler task differs from its pass identity")
            if not set(task.scope.shard_ids) <= manifest_shards:
                raise ValueError("scheduler task scope contains an unknown shard")
            if (
                self.manifest.algorithm_version == "mmaudit.seven-pass-scheduler.v2"
                and _task_uses_candidate_review_contract(task)
                and task.model_surface_review_request_manifest_sha256 is None
            ):
                raise ValueError(
                    "scheduler-v2 candidate-review pass lacks sealed surface authority"
                )
            audit_selection = self.manifest.bindings.audit_model_selection
            if task.task_kind is SchedulerTaskKind.MODEL_REQUEST and audit_selection is not None:
                assert task.requested_model is not None and task.root_lineage is not None
                selected_route = audit_selection.route_for(task.requested_model)
                if selected_route.root_lineage != task.root_lineage:
                    raise ValueError("scheduler task differs from its audit-selected route")
        empty_tasks = [
            item for item in primary_tasks if item.task_kind is SchedulerTaskKind.EMPTY_COMPLETION
        ]
        if empty_tasks:
            if (
                len(primary_tasks) != 1
                or len(empty_tasks) != 1
                or self.conditional_absence is None
                or empty_tasks[0].role != "host:conditional_absence"
                or empty_tasks[0].scope.kind is not SchedulerScopeKind.GLOBAL
            ):
                raise ValueError("explicit empty pass requires its sole typed absence task")
        elif self.conditional_absence is not None:
            raise ValueError("scheduler conditional absence requires an explicit empty task")
        candidate_pass = self.pass_kind in {
            SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
            SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
        }
        if candidate_pass != (self.candidate_workset is not None):
            raise ValueError("scheduler passes five and six require an exact candidate workset")
        if self.candidate_workset is not None:
            workset = self.candidate_workset
            source_dependencies = tuple(
                item
                for item in self.dependencies
                if item.pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
            )
            if (
                workset.pass_kind is not self.pass_kind
                or len(source_dependencies) != 1
                or source_dependencies[0].pass_result_sha256 != workset.source_pass_result_sha256
            ):
                raise ValueError("scheduler candidate workset lacks its exact pass-four dependency")
        if self.conditional_absence is not None:
            assert self.candidate_workset is not None
            if (
                self.conditional_absence.pass_kind is not self.pass_kind
                or self.conditional_absence.candidate_workset_sha256
                != self.candidate_workset.workset_sha256
                or self.conditional_absence.source_pass_result_sha256
                != self.candidate_workset.source_pass_result_sha256
                or self.conditional_absence.source_output_artifact_sha256
                != self.candidate_workset.source_output_artifact_sha256
                or self.candidate_workset.selected_candidate_ids
            ):
                raise ValueError("scheduler absence is not derived from its exact empty workset")
        if self.pass_kind is SchedulerPassKind.ORIENTATION and (
            len(primary_tasks) != 1
            or primary_tasks[0].scope.kind is not SchedulerScopeKind.GLOBAL
            or primary_tasks[0].task_kind is not SchedulerTaskKind.MODEL_REQUEST
            or primary_tasks[0].role != "threat_model"
        ):
            raise ValueError("orientation requires exactly one global threat-model request")
        if self.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW:
            for task in primary_tasks:
                if task.task_kind is not SchedulerTaskKind.MODEL_REQUEST:
                    raise ValueError(
                        "blind review requires only single-shard model requests or "
                        "global whole-protocol reviews"
                    )
                if _WHOLE_PROTOCOL_REVIEW_ROLE.fullmatch(task.role) is not None:
                    if task.scope.kind is not SchedulerScopeKind.GLOBAL:
                        raise ValueError("whole-protocol blind review requires global scope")
                elif (
                    task.role not in _BLIND_SHARD_REVIEW_ROLES
                    or task.scope.kind is not SchedulerScopeKind.SINGLE_SHARD
                ):
                    raise ValueError("blind review role or scope is not permitted")
            reviewed_shards = {
                task.scope.shard_ids[0] for task in primary_tasks if task.role == "source_audit"
            }
            if reviewed_shards != manifest_shards:
                raise ValueError("blind source-audit requests must cover the exact shard inventory")
            expected_barrier = scheduler_canonical_sha256(
                {
                    "domain": "mmaudit.scheduler.blind-plan-barrier.v1",
                    "campaign_id": self.manifest.campaign_id,
                    "pass_id": self.pass_id,
                    "task_plan_sha256s": [item.task_plan_sha256 for item in self.tasks],
                }
            )
            if self.blind_plan_barrier_sha256 != expected_barrier:
                raise ValueError("blind scheduler pass lacks its exact sealed-plan barrier")
        elif self.blind_plan_barrier_sha256 is not None:
            raise ValueError("only blind shard review may carry a blind-plan barrier")
        required_host_role = {
            SchedulerPassKind.FINDING_REDUCTION: "host:finding_reducer",
            SchedulerPassKind.CROSS_SHARD_INTEGRATION: "host:cross_shard_integrator",
            SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT: "host:evidence_cap_judgment",
        }.get(self.pass_kind)
        if required_host_role is not None and not any(
            task.task_kind is SchedulerTaskKind.HOST_COMPUTATION and task.role == required_host_role
            for task in primary_tasks
        ):
            raise ValueError(f"scheduler pass requires {required_host_role} host computation")
        if self.pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION:
            for task in primary_tasks:
                if task.role != "business_logic":
                    continue
                if (
                    task.task_kind is not SchedulerTaskKind.MODEL_REQUEST
                    or task.scope.kind is not SchedulerScopeKind.SHARD_SET
                    or len(task.candidate_ids) != 1
                    or re.fullmatch(r"model-surface:[0-9a-f]{64}", task.candidate_ids[0]) is None
                ):
                    raise ValueError(
                        "cross-shard business-logic task requires one exact boundary surface"
                    )
        if self.pass_kind is SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION:
            self._validate_cross_examination_portfolio()
        if self.pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION:
            self._validate_validation_falsification_portfolio()
        if self.pass_kind is SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT and any(
            task.task_kind is SchedulerTaskKind.MODEL_REQUEST
            and task.role == "judge"
            and not task.candidate_ids
            for task in primary_tasks
        ):
            raise ValueError("judge model task requires an exact non-empty candidate-group set")
        values = self.model_dump(
            mode="json",
            exclude={"pass_plan_id", "pass_plan_sha256"},
        )
        expected_id = "scheduler-plan-" + scheduler_canonical_sha256(values)
        if self.pass_plan_id != expected_id:
            raise ValueError("scheduler pass-plan ID is inconsistent")
        if self.pass_plan_sha256 != _model_sha256(self, exclude={"pass_plan_sha256"}):
            raise ValueError("scheduler pass-plan hash is inconsistent")
        return self

    def _validate_cross_examination_portfolio(self) -> None:
        assert self.candidate_workset is not None
        candidate_ids = self.candidate_workset.selected_candidate_ids
        if self.conditional_absence is not None:
            return
        if not candidate_ids:
            raise ValueError("non-empty pass-five review requires candidate work")
        expected: dict[str, dict[int, SchedulerTaskPlan]] = {
            candidate_id: {} for candidate_id in candidate_ids
        }
        for task in self.tasks:
            if task.purpose is not SchedulerTaskPurpose.PRIMARY:
                continue
            if (
                task.task_kind is not SchedulerTaskKind.MODEL_REQUEST
                or len(task.candidate_ids) != 1
                or task.candidate_ids[0] not in expected
            ):
                raise ValueError("pass five requires one exact model review candidate per task")
            candidate_id = task.candidate_ids[0]
            reviewer_index = next(
                (
                    index
                    for index in (1, 2)
                    if task.role == _candidate_reviewer_role(candidate_id, index)
                ),
                None,
            )
            if reviewer_index is None or reviewer_index in expected[candidate_id]:
                raise ValueError("pass five candidate reviewer roles must be exact and unique")
            expected[candidate_id][reviewer_index] = task
        for _candidate_id, reviewers in expected.items():
            if (
                set(reviewers) != {1, 2}
                or len({task.root_lineage for task in reviewers.values()}) != 2
            ):
                raise ValueError(
                    "pass five requires two independent root lineages per high/critical candidate"
                )

    def _validate_validation_falsification_portfolio(self) -> None:
        assert self.candidate_workset is not None
        candidate_ids = self.candidate_workset.selected_candidate_ids
        if self.conditional_absence is not None:
            return
        if not candidate_ids:
            raise ValueError("non-empty pass-six review requires candidate work")
        expected_roles = {
            "independent-verifier": "verifier",
            "candidate-falsifier-1": "candidate_falsifier",
            "candidate-falsifier-2": "candidate_falsifier",
        }
        reviewer_tasks = tuple(
            task
            for task in self.tasks
            if task.purpose is SchedulerTaskPurpose.PRIMARY
            and (
                task.task_key in expected_roles or task.role in {"verifier", "candidate_falsifier"}
            )
        )
        if (
            len(reviewer_tasks) != len(expected_roles)
            or {task.task_key for task in reviewer_tasks} != set(expected_roles)
            or any(
                task.task_kind is not SchedulerTaskKind.MODEL_REQUEST
                or task.role != expected_roles[task.task_key]
                for task in reviewer_tasks
            )
        ):
            raise ValueError(
                "pass six requires exactly one independent verifier and two candidate "
                "falsifier reviewer tasks"
            )
        if any(task.candidate_ids != candidate_ids for task in reviewer_tasks):
            raise ValueError(
                "pass six reviewer tasks must bind the exact complete validation workset"
            )
        identity_inventories = (
            tuple(task.root_lineage for task in reviewer_tasks),
            tuple(task.task_id for task in reviewer_tasks),
            tuple(task.logical_request_id for task in reviewer_tasks),
        )
        if any(
            any(identity is None for identity in inventory)
            or len(set(inventory)) != len(expected_roles)
            for inventory in identity_inventories
        ):
            raise ValueError(
                "pass six reviewer lineages, tasks, and logical requests must be pairwise distinct"
            )


def _retrieval_planning_child(
    plan: SchedulerPassPlan,
    parent: SchedulerTaskPlan,
) -> SchedulerTaskPlan | None:
    """Return the sole exact retrieval-planning child of one primary task."""

    matches = tuple(
        task
        for task in plan.tasks
        if task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
        and task.parent_task_id == parent.task_id
    )
    if len(matches) > 1:
        raise ValueError("scheduler primary task has multiple retrieval children")
    return matches[0] if matches else None


class SchedulerTaskActivation(StrictModel):
    """Exact dynamic request material committed immediately before dispatch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    campaign_id: str = Field(pattern=r"^scheduler-campaign-[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    pass_plan_id: str = Field(pattern=r"^scheduler-plan-[0-9a-f]{64}$")
    pass_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    task_id: str = Field(pattern=r"^scheduler-task-[0-9a-f]{64}$")
    task_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    logical_request_id: str = Field(pattern=r"^scheduler-request-[0-9a-f]{64}$")
    actual_input_sha256: str = Field(pattern=_SHA256_PATTERN)
    system_prompt_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    user_prompt_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    provider_prompt_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    response_schema_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    delivered_source_descriptor_sha256s: tuple[str, ...] = Field(max_length=100_000)
    prior_pass_result_sha256s: tuple[str, ...] = Field(max_length=7)
    upstream_task_result_sha256s: tuple[str, ...] = Field(max_length=100_000)
    activation_id: str = Field(pattern=r"^scheduler-activation-[0-9a-f]{64}$")
    activation_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        plan: SchedulerPassPlan,
        task: SchedulerTaskPlan,
        actual_input_sha256: str,
        system_prompt_sha256: str | None = None,
        user_prompt_sha256: str | None = None,
        provider_prompt_sha256: str | None = None,
        response_schema_sha256: str | None = None,
        delivered_source_descriptor_sha256s: Iterable[str] = (),
        upstream_task_result_sha256s: Iterable[str] = (),
        retrieval_planning_result: SchedulerTaskResult | None = None,
    ) -> SchedulerTaskActivation:
        if not plan.has_exact_task(task):
            raise ValueError("scheduler activation task is not in the sealed pass plan")
        if (
            plan.manifest.algorithm_version == "mmaudit.seven-pass-scheduler.v2"
            and _task_uses_candidate_review_contract(task)
            and task.model_surface_review_request_manifest_sha256 is None
        ):
            raise ValueError(
                "scheduler-v2 candidate-review activation lacks sealed surface authority"
            )
        upstream = tuple(sorted(set(upstream_task_result_sha256s)))
        retrieval_child = _retrieval_planning_child(plan, task)
        if retrieval_child is not None:
            if retrieval_planning_result is None or (
                retrieval_planning_result.campaign_id != plan.manifest.campaign_id
                or retrieval_planning_result.manifest_sha256 != plan.manifest.manifest_sha256
                or retrieval_planning_result.pass_kind is not plan.pass_kind
                or retrieval_planning_result.pass_id != plan.pass_id
                or retrieval_planning_result.pass_plan_id != plan.pass_plan_id
                or retrieval_planning_result.pass_plan_sha256 != plan.pass_plan_sha256
                or retrieval_planning_result.task_id != retrieval_child.task_id
                or retrieval_planning_result.task_plan_sha256 != retrieval_child.task_plan_sha256
                or retrieval_planning_result.logical_request_id
                != retrieval_child.logical_request_id
                or retrieval_planning_result.scope != retrieval_child.scope
            ):
                raise ValueError(
                    "scheduler primary activation lacks its exact retrieval-child result"
                )
            expected_upstream = (retrieval_planning_result.result_sha256,)
            if upstream and upstream != expected_upstream:
                raise ValueError("scheduler retrieval result must be the sole primary upstream")
            upstream = expected_upstream
        elif retrieval_planning_result is not None:
            raise ValueError("scheduler activation supplied an unrelated retrieval result")
        if task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING and upstream:
            raise ValueError("scheduler retrieval-planning child cannot have an upstream task")
        delivered_sources = tuple(sorted(set(delivered_source_descriptor_sha256s)))
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "evidence_authority": "comparison_required",
            "campaign_id": plan.manifest.campaign_id,
            "manifest_sha256": plan.manifest.manifest_sha256,
            "pass_plan_id": plan.pass_plan_id,
            "pass_plan_sha256": plan.pass_plan_sha256,
            "task_id": task.task_id,
            "task_plan_sha256": task.task_plan_sha256,
            "logical_request_id": task.logical_request_id,
            "actual_input_sha256": actual_input_sha256,
            "system_prompt_sha256": system_prompt_sha256,
            "user_prompt_sha256": user_prompt_sha256,
            "provider_prompt_sha256": provider_prompt_sha256,
            "response_schema_sha256": response_schema_sha256,
            "delivered_source_descriptor_sha256s": delivered_sources,
            "prior_pass_result_sha256s": tuple(
                item.pass_result_sha256 for item in plan.dependencies
            ),
            "upstream_task_result_sha256s": upstream,
        }
        activation_id = "scheduler-activation-" + scheduler_canonical_sha256(
            {
                "domain": "mmaudit.scheduler.task-activation-identity.v1",
                "pass_plan_id": plan.pass_plan_id,
                "task_id": task.task_id,
                "actual_input_sha256": actual_input_sha256,
                "system_prompt_sha256": system_prompt_sha256,
                "user_prompt_sha256": user_prompt_sha256,
                "provider_prompt_sha256": provider_prompt_sha256,
                "response_schema_sha256": response_schema_sha256,
                "delivered_source_descriptor_sha256s": delivered_sources,
                "prior_pass_result_sha256s": values["prior_pass_result_sha256s"],
                "upstream_task_result_sha256s": upstream,
            }
        )
        body = {**values, "activation_id": activation_id}
        activation = cls(**body, activation_sha256=scheduler_canonical_sha256(body))
        activation.require_exact_task(plan=plan, task=task)
        return activation

    @model_validator(mode="after")
    def activation_shape_identity_and_hash_are_exact(self) -> Self:
        provider_fields_present = (
            self.system_prompt_sha256 is not None
            and self.user_prompt_sha256 is not None
            and self.provider_prompt_sha256 is not None
            and self.response_schema_sha256 is not None
        )
        provider_fields_absent = (
            self.system_prompt_sha256 is None
            and self.user_prompt_sha256 is None
            and self.provider_prompt_sha256 is None
            and self.response_schema_sha256 is None
        )
        if not (provider_fields_present or provider_fields_absent):
            raise ValueError("scheduler activation provider hashes are all-or-none")
        if self.upstream_task_result_sha256s != tuple(
            sorted(set(self.upstream_task_result_sha256s))
        ):
            raise ValueError("scheduler activation upstream results must be unique and sorted")
        if self.delivered_source_descriptor_sha256s != tuple(
            sorted(set(self.delivered_source_descriptor_sha256s))
        ) or any(
            re.fullmatch(_SHA256_PATTERN, item) is None
            for item in self.delivered_source_descriptor_sha256s
        ):
            raise ValueError("scheduler delivered source identities must be valid and sorted")
        expected_id = "scheduler-activation-" + scheduler_canonical_sha256(
            {
                "domain": "mmaudit.scheduler.task-activation-identity.v1",
                "pass_plan_id": self.pass_plan_id,
                "task_id": self.task_id,
                "actual_input_sha256": self.actual_input_sha256,
                "system_prompt_sha256": self.system_prompt_sha256,
                "user_prompt_sha256": self.user_prompt_sha256,
                "provider_prompt_sha256": self.provider_prompt_sha256,
                "response_schema_sha256": self.response_schema_sha256,
                "delivered_source_descriptor_sha256s": (self.delivered_source_descriptor_sha256s),
                "prior_pass_result_sha256s": self.prior_pass_result_sha256s,
                "upstream_task_result_sha256s": self.upstream_task_result_sha256s,
            }
        )
        if self.activation_id != expected_id:
            raise ValueError("scheduler activation ID is inconsistent")
        if self.activation_sha256 != _model_sha256(self, exclude={"activation_sha256"}):
            raise ValueError("scheduler activation hash is inconsistent")
        return self

    def require_exact_task(self, *, plan: SchedulerPassPlan, task: SchedulerTaskPlan) -> None:
        """Reject an activation detached from its exact plan, task, or task kind."""

        expected_prior = tuple(item.pass_result_sha256 for item in plan.dependencies)
        if (
            not plan.has_exact_task(task)
            or self.campaign_id != plan.manifest.campaign_id
            or self.manifest_sha256 != plan.manifest.manifest_sha256
            or self.pass_plan_id != plan.pass_plan_id
            or self.pass_plan_sha256 != plan.pass_plan_sha256
            or self.task_id != task.task_id
            or self.task_plan_sha256 != task.task_plan_sha256
            or self.logical_request_id != task.logical_request_id
            or self.prior_pass_result_sha256s != expected_prior
        ):
            raise ValueError("scheduler activation differs from its exact planned task")
        provider_fields_present = self.user_prompt_sha256 is not None
        if (task.task_kind is SchedulerTaskKind.MODEL_REQUEST) != provider_fields_present:
            raise ValueError("scheduler activation provider hashes differ from task authority")
        if task.task_kind is SchedulerTaskKind.MODEL_REQUEST and (
            self.response_schema_sha256 != task.response_schema_sha256
            or self.system_prompt_sha256 != task.system_prompt_sha256
        ):
            raise ValueError("scheduler activation provider material differs from its plan")
        retrieval_child = _retrieval_planning_child(plan, task)
        if retrieval_child is not None and len(self.upstream_task_result_sha256s) != 1:
            raise ValueError("scheduler primary activation lacks its sole retrieval upstream")
        if (
            task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
            and self.upstream_task_result_sha256s
        ):
            raise ValueError("scheduler retrieval-planning activation cannot chain upstream")
        known_source_descriptors = {
            source.source_descriptor_sha256
            for shard in plan.manifest.shard_inventory.shards
            for source in shard.sources
        }
        if not set(self.delivered_source_descriptor_sha256s) <= known_source_descriptors:
            raise ValueError("scheduler activation claims an unknown delivered source")
        if task.task_kind is not SchedulerTaskKind.MODEL_REQUEST and (
            self.delivered_source_descriptor_sha256s
        ):
            raise ValueError("host scheduler activation cannot claim model source delivery")
        if (
            task.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
            and (
                task.role == "source_audit"
                or _WHOLE_PROTOCOL_REVIEW_ROLE.fullmatch(task.role) is not None
            )
            and set(self.delivered_source_descriptor_sha256s)
            != {source.source_descriptor_sha256 for source in _task_source_descriptors(plan, task)}
        ):
            raise ValueError("blind review activation lacks exact full-source delivery")


_SENSITIVE_USAGE_KEYS = frozenset(
    {
        "api-key",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "password",
        "proxy-authorization",
        "secret",
        "set-cookie",
    }
)


def _reject_sensitive_usage_material(value: Any) -> None:
    """Reject serialized provider evidence that carries control-plane secret fields."""

    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).strip().casefold().replace("_", "-")
            if normalized in _SENSITIVE_USAGE_KEYS:
                raise ValueError("scheduler usage evidence contains a prohibited secret field")
            _reject_sensitive_usage_material(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_sensitive_usage_material(item)


def _usage_audit_routing_evidence(
    usage_record: UsageRecord,
) -> AuditModelRoutingEvidence | None:
    """Parse an exact non-authorizing routing projection retained in usage evidence."""

    from mmaudit.models.policy_selection import AuditModelRoutingEvidence

    raw = usage_record.routing.get("audit_model_routing_evidence")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("scheduler usage has invalid typed audit policy routing evidence")
    try:
        evidence = AuditModelRoutingEvidence.model_validate_json(
            json.dumps(
                raw,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ),
            strict=True,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("scheduler usage has invalid typed audit policy routing evidence") from exc
    if evidence.model_dump(mode="json") != raw:
        raise ValueError("scheduler usage audit policy routing evidence changed on validation")
    metadata = dict(evidence.request_metadata())
    routing_sha256 = metadata.pop("routing_evidence_sha256")
    if usage_record.routing.get("audit_policy_routing_evidence_sha256") != routing_sha256 or any(
        usage_record.routing.get(key) != value for key, value in metadata.items()
    ):
        raise ValueError("scheduler usage audit policy routing projection is inconsistent")
    return evidence


def _require_usage_audit_selection(
    *,
    usage_record: UsageRecord,
    requested_model: str,
    binding: SchedulerAuditModelSelectionBinding | None,
) -> AuditModelRoutingEvidence:
    """Require one REAL paid scheduler use to match its campaign selection."""

    evidence = _usage_audit_routing_evidence(usage_record)
    if binding is None or evidence is None:
        raise ValueError("REAL scheduler model usage lacks audit policy selection evidence")
    selected_route = binding.route_for(requested_model)
    if (
        evidence.audit_model_selection_bundle_sha256 != binding.audit_model_selection_bundle_sha256
        or evidence.audit_selection_sha256 != binding.audit_selection_sha256
        or evidence.selected_model_set_sha256 != binding.selected_model_set_sha256
        or evidence.audit_scope_sha256 != binding.audit_scope_sha256
        or evidence.source_sha256 != binding.source_sha256
        or evidence.audit_context_sha256 != binding.audit_context_sha256
        or evidence.client_constraints_sha256 != binding.client_constraints_sha256
        or evidence.intended_use.value != binding.intended_use
        or evidence.technical_production_selection_sha256
        != binding.technical_production_selection_sha256
        or evidence.technical_qualification_capability_sha256
        != binding.technical_qualification_capability_sha256
        or evidence.policy_artifact_sha256 != binding.policy_artifact_sha256
        or evidence.policy_evaluation_sha256 != binding.policy_evaluation_sha256
        or evidence.policy_authority_receipt_sha256 != binding.policy_authority_receipt_sha256
        or evidence.policy_authority_statement_sha256 != binding.policy_authority_statement_sha256
        or evidence.policy_authority_envelope_sha256 != binding.policy_authority_envelope_sha256
        or evidence.policy_authority_trust_anchor_sha256
        != binding.policy_authority_trust_anchor_sha256
        or evidence.policy_source_observation_sha256 != binding.policy_source_observation_sha256
        or evidence.policy_source_commitment_set_sha256
        != binding.policy_source_commitment_set_sha256
        or evidence.expires_at != binding.selection_expires_at
        or evidence.route.exact_model_id != selected_route.exact_model_id
        or evidence.route.provider_name != selected_route.provider_name
        or evidence.route.provider_endpoint != selected_route.provider_endpoint
        or evidence.route.route_sha256 != selected_route.policy_route_sha256
        or evidence.selected_model_sha256 != selected_route.selected_model_sha256
        or usage_record.requested_model != selected_route.exact_model_id
        or tuple(usage_record.configured_provider_endpoints) != (selected_route.provider_endpoint,)
        or (
            usage_record.provider != selected_route.provider_name
            and (usage_record.status == "success" or usage_record.provider is not None)
        )
        or (
            usage_record.actual_provider_endpoint != selected_route.provider_endpoint
            and (
                usage_record.status == "success"
                or usage_record.actual_provider_endpoint is not None
            )
        )
        or usage_record.started_at is None
        or usage_record.ended_at is None
        or usage_record.started_at >= binding.selection_expires_at
        or usage_record.ended_at >= binding.selection_expires_at
    ):
        raise ValueError("REAL scheduler model usage differs from audit policy selection")
    return evidence


def _usage_audit_model_refresh_route_evidence(
    usage_record: UsageRecord,
) -> Any | None:
    """Parse one canonical non-authorizing route projection from provider usage."""

    from mmaudit.models.refresh_runtime import AuditModelRefreshRouteEvidence

    raw = usage_record.routing.get("audit_model_refresh_route_evidence")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("scheduler usage has invalid typed model-refresh route evidence")
    try:
        route = AuditModelRefreshRouteEvidence.model_validate_json(
            json.dumps(
                raw,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ),
            strict=True,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("scheduler usage has invalid typed model-refresh route evidence") from exc
    if route.model_dump(mode="json") != raw:
        raise ValueError("scheduler usage model-refresh route changed on validation")
    return route


def _require_usage_audit_model_refresh(
    *,
    usage_record: UsageRecord,
    requested_model: str,
    binding: SchedulerAuditModelRefreshBinding | None,
    audit_model_selection: SchedulerAuditModelSelectionBinding | None,
) -> Any:
    """Require one REAL scheduler use to match veto-only campaign refresh custody."""

    route = _usage_audit_model_refresh_route_evidence(usage_record)
    if binding is None or audit_model_selection is None or route is None:
        raise ValueError("REAL scheduler model usage lacks current model-refresh evidence")
    selected_route = audit_model_selection.route_for(requested_model)
    refresh_route = binding.route_for(requested_model)
    expires_at_text = binding.expires_at.isoformat()
    guard_capability_sha256 = usage_record.routing.get(
        "audit_model_refresh_guard_capability_sha256"
    )
    if (
        usage_record.routing.get("audit_model_refresh_evidence_sha256")
        != binding.audit_model_refresh_evidence_sha256
        or usage_record.routing.get("audit_model_refresh_workflow_status_sha256")
        != binding.workflow_status_sha256
        or usage_record.routing.get("audit_model_refresh_snapshot_sha256")
        != binding.snapshot_sha256
        or usage_record.routing.get("audit_model_refresh_route_evidence_sha256")
        != route.route_evidence_sha256
        or guard_capability_sha256 != binding.guard_capability_sha256
        or usage_record.routing.get("audit_model_refresh_audit_route_set_sha256")
        != binding.audit_route_set_sha256
        or usage_record.routing.get("audit_model_refresh_technical_route_set_sha256")
        != binding.technical_route_set_sha256
        or usage_record.routing.get("audit_model_refresh_expires_at") != expires_at_text
        or route.exact_model_id != requested_model
        or route.route_evidence_sha256 != refresh_route.route_evidence_sha256
        or route.exact_model_id not in binding.audit_model_ids
        or not route.audit_selected
        or route.runtime_authorized
        or route.root_lineage != selected_route.root_lineage
        or route.approved_provider_name != selected_route.provider_name
        or route.approved_provider_endpoint != selected_route.provider_endpoint
        or usage_record.requested_model != route.exact_model_id
        or tuple(usage_record.configured_provider_endpoints) != (route.approved_provider_endpoint,)
        or (
            usage_record.provider != route.approved_provider_name
            and (usage_record.status == "success" or usage_record.provider is not None)
        )
        or (
            usage_record.actual_provider_endpoint != route.approved_provider_endpoint
            and (
                usage_record.status == "success"
                or usage_record.actual_provider_endpoint is not None
            )
        )
        or usage_record.started_at is None
        or usage_record.ended_at is None
        or usage_record.started_at < binding.verified_at
        or usage_record.started_at >= binding.expires_at
        or usage_record.started_at >= route.qualification_expires_at
    ):
        raise ValueError("REAL scheduler model usage differs from current model refresh")
    return route


def _usage_audit_model_refresh_pricing_route_evidence(
    usage_record: UsageRecord,
) -> Any | None:
    """Parse one canonical non-authorizing refreshed-price route from usage."""

    from mmaudit.models.refresh_runtime import AuditModelRefreshPricingRouteEvidence

    raw = usage_record.routing.get("audit_model_refresh_pricing_route_evidence")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("scheduler usage has invalid typed refresh-pricing route")
    try:
        route = AuditModelRefreshPricingRouteEvidence.model_validate_json(
            json.dumps(
                raw,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ),
            strict=True,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("scheduler usage has invalid typed refresh-pricing route") from exc
    if route.model_dump(mode="json") != raw:
        raise ValueError("scheduler usage refresh-pricing route changed on validation")
    return route


def _require_usage_audit_model_refresh_pricing(
    *,
    usage_record: UsageRecord,
    requested_model: str,
    binding: SchedulerAuditModelRefreshPricingBinding | None,
    refresh_binding: SchedulerAuditModelRefreshBinding | None,
) -> Any:
    """Require exact pricing/cost custody for one REAL refresh-bound use."""

    route = _usage_audit_model_refresh_pricing_route_evidence(usage_record)
    if binding is None or refresh_binding is None or route is None:
        raise ValueError("REAL scheduler model usage lacks refreshed-price evidence")
    projected = binding.route_for(requested_model)
    refresh_route = refresh_binding.route_for(requested_model)
    if (
        usage_record.routing.get("audit_model_refresh_pricing_evidence_sha256")
        != binding.audit_model_refresh_pricing_evidence_sha256
        or usage_record.routing.get("audit_model_refresh_pricing_authority_capability_sha256")
        != binding.pricing_authority_capability_sha256
        or usage_record.routing.get("audit_model_refresh_pricing_route_evidence_sha256")
        != route.route_evidence_sha256
        or usage_record.routing.get("audit_model_refresh_pricing_workflow_status_sha256")
        != binding.workflow_status_sha256
        or usage_record.routing.get("audit_model_refresh_pricing_current_snapshot_sha256")
        != binding.current_snapshot_sha256
        or usage_record.routing.get("audit_model_refresh_pricing_refresh_evidence_sha256")
        != binding.refresh_evidence_sha256
        or usage_record.routing.get("audit_model_refresh_pricing_refresh_guard_capability_sha256")
        != binding.refresh_guard_capability_sha256
        or usage_record.routing.get("audit_model_refresh_pricing_technical_route_set_sha256")
        != binding.technical_pricing_route_set_sha256
        or usage_record.routing.get("audit_model_refresh_pricing_audit_route_set_sha256")
        != binding.audit_pricing_route_set_sha256
        or usage_record.routing.get("audit_model_refresh_pricing_qualified_pricing_snapshot_sha256")
        != projected.qualified_pricing_snapshot_sha256
        or usage_record.routing.get("audit_model_refresh_pricing_current_pricing_snapshot_sha256")
        != projected.current_pricing_sha256
        or usage_record.routing.get("audit_model_refresh_pricing_expires_at")
        != binding.expires_at.isoformat()
        or route.exact_model_id != requested_model
        or route.route_evidence_sha256 != projected.pricing_route_evidence_sha256
        or route.refresh_route_evidence_sha256 != refresh_route.route_evidence_sha256
        or route.qualified_pricing_snapshot_sha256 != projected.qualified_pricing_snapshot_sha256
        or route.baseline_pricing_sha256 != projected.baseline_pricing_sha256
        or route.current_pricing_sha256 != projected.current_pricing_sha256
        or route.approved_provider_endpoint != projected.approved_provider_endpoint
        or route.pricing_use_authorized
        or route.provider_access_authorized
        or route.model_selection_authorized
        or "audit_model_refresh_pricing_attempts" not in usage_record.routing
    ):
        raise ValueError("REAL scheduler model usage differs from refreshed-price custody")
    return route


class SchedulerModelCompletionEvidence(StrictModel):
    """Private redacted provider/normalization evidence for one successful model task."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1", "1.2"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    task_id: str = Field(pattern=r"^scheduler-task-[0-9a-f]{64}$")
    logical_request_id: str = Field(pattern=r"^scheduler-request-[0-9a-f]{64}$")
    activation_sha256: str = Field(pattern=_SHA256_PATTERN)
    delivered_source_descriptor_sha256s: tuple[str, ...] = Field(max_length=100_000)
    usage_record: UsageRecord
    usage_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_policy_selection_binding_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_selection_bundle_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_selection_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_selected_model_set_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_scope_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_source_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_selection_expires_at: datetime | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    audit_policy_routing_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_binding_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_guard_capability_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_workflow_status_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_snapshot_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_route_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_audit_route_set_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_technical_route_set_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_expires_at: datetime | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_pricing_binding_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_pricing_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_pricing_authority_capability_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_pricing_route_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_pricing_baseline_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_pricing_current_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_pricing_expires_at: datetime | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    context_request_evidence: ContextRequestEvidence
    context_request_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider_response_sha256: str = Field(pattern=_SHA256_PATTERN)
    validated_response_sha256: str = Field(pattern=_SHA256_PATTERN)
    response_schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    normalizer_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    normalized_output_sha256: str = Field(pattern=_SHA256_PATTERN)
    normalization_evidence: CandidateReviewNormalizationEvidence | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    completion_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        task: SchedulerTaskPlan,
        activation: SchedulerTaskActivation,
        usage_record: UsageRecord,
        privacy_evidence_custody: SchedulerPrivacyEvidenceCustody | None,
        audit_model_selection: SchedulerAuditModelSelectionBinding | None,
        audit_model_refresh: SchedulerAuditModelRefreshBinding | None,
        audit_model_refresh_pricing: SchedulerAuditModelRefreshPricingBinding | None = None,
        normalizer_sha256: str | None,
        normalized_output_sha256: str,
        normalization_evidence: CandidateReviewNormalizationEvidence | None = None,
        algorithm_version: str = SCHEDULER_ALGORITHM_VERSION,
    ) -> SchedulerModelCompletionEvidence:
        if task.task_kind is not SchedulerTaskKind.MODEL_REQUEST:
            raise ValueError("scheduler model completion evidence requires a model task")
        frozen_usage = UsageRecord.model_validate(usage_record.model_dump(mode="python"))
        _reject_sensitive_usage_material(frozen_usage.model_dump(mode="json"))
        if privacy_evidence_custody is None:
            raise ValueError("scheduler model completion lacks exact privacy custody")
        privacy_routing = {
            "privacy_source_sha256": privacy_evidence_custody.source_sha256,
            "effective_privacy_policy_sha256": (
                privacy_evidence_custody.effective_policy_evidence_sha256
            ),
            "privacy_source_provenance_sha256": (
                privacy_evidence_custody.source_provenance_evidence_sha256
            ),
        }
        privacy_keys_present = any(key in frozen_usage.routing for key in privacy_routing)
        if (
            frozen_usage.execution_evidence is ExecutionEvidenceKind.REAL or privacy_keys_present
        ) and any(frozen_usage.routing.get(key) != value for key, value in privacy_routing.items()):
            raise ValueError("scheduler model completion differs from privacy custody")
        audit_routing = _usage_audit_routing_evidence(frozen_usage)
        if (
            usage_requires_audit_policy_evidence(frozen_usage)
            or (
                frozen_usage.execution_evidence is ExecutionEvidenceKind.REAL
                and audit_model_selection is not None
            )
            or audit_routing is not None
        ):
            audit_routing = _require_usage_audit_selection(
                usage_record=frozen_usage,
                requested_model=task.requested_model or "",
                binding=audit_model_selection,
            )
        refresh_route = _usage_audit_model_refresh_route_evidence(frozen_usage)
        if (
            frozen_usage.execution_evidence is ExecutionEvidenceKind.REAL
            or refresh_route is not None
        ):
            refresh_route = _require_usage_audit_model_refresh(
                usage_record=frozen_usage,
                requested_model=task.requested_model or "",
                binding=audit_model_refresh,
                audit_model_selection=audit_model_selection,
            )
        pricing_route = _usage_audit_model_refresh_pricing_route_evidence(frozen_usage)
        if (
            (
                frozen_usage.execution_evidence is ExecutionEvidenceKind.REAL
                and audit_model_refresh is not None
            )
            or pricing_route is not None
            or audit_model_refresh_pricing is not None
        ):
            pricing_route = _require_usage_audit_model_refresh_pricing(
                usage_record=frozen_usage,
                requested_model=task.requested_model or "",
                binding=audit_model_refresh_pricing,
                refresh_binding=audit_model_refresh,
            )
        raw_context = frozen_usage.routing.get("context_request_evidence")
        if not isinstance(raw_context, dict):
            raise ValueError("scheduler model completion lacks typed context request evidence")
        context = ContextRequestEvidence.model_validate(raw_context)
        frozen_normalization: CandidateReviewNormalizationEvidence | None = None
        if normalization_evidence is not None:
            if (
                type(normalization_evidence) is not CandidateReviewNormalizationEvidence
                or not candidate_review_protocol_implementation_is_pristine()
            ):
                raise ValueError("scheduler candidate-review normalization implementation changed")
            frozen_normalization = CandidateReviewNormalizationEvidence.model_validate_json(
                normalization_evidence.model_dump_json(),
                strict=True,
            )
            if frozen_normalization != normalization_evidence:
                raise ValueError("scheduler candidate-review normalization evidence changed")
        candidate_review_contract = _task_uses_candidate_review_contract(task)
        framed_candidate_review = (
            candidate_review_contract
            and activation.response_schema_sha256
            == candidate_review_frame_wire_schema_sha256(
                algorithm_version=algorithm_version,
            )
        )
        unframed_candidate_review = (
            candidate_review_contract
            and activation.response_schema_sha256
            == candidate_review_batch_schema_sha256(
                algorithm_version=algorithm_version,
            )
        )
        if candidate_review_contract and not (framed_candidate_review or unframed_candidate_review):
            raise ValueError("scheduler candidate review uses an unknown wire schema")
        if framed_candidate_review != (frozen_normalization is not None):
            raise ValueError(
                "scheduler framed candidate review requires exact normalization evidence"
            )
        if not candidate_review_contract and frozen_normalization is not None:
            raise ValueError(
                "non-candidate scheduler completion cannot carry normalization evidence"
            )
        if task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING:
            if normalizer_sha256 is not None or frozen_normalization is not None:
                raise ValueError("retrieval-planning completion cannot claim normalization")
        elif task.normalizer_sha256 is None or normalizer_sha256 != task.normalizer_sha256:
            raise ValueError("scheduler completion normalizer differs from its sealed task")
        if frozen_normalization is not None and (
            frozen_normalization.request_id != task.logical_request_id
            or frozen_normalization.wire_schema_sha256 != activation.response_schema_sha256
            or frozen_normalization.normalized_batch_schema_sha256
            != candidate_review_batch_schema_sha256(
                algorithm_version=algorithm_version,
            )
            or frozen_normalization.wire_validated_response_sha256
            != frozen_usage.validated_response_sha256
            or frozen_normalization.normalized_batch_sha256 != normalized_output_sha256
        ):
            raise ValueError("scheduler candidate-review normalization custody is inconsistent")
        if (
            frozen_usage.request_id != task.logical_request_id
            or frozen_usage.role != task.role
            or frozen_usage.requested_model != task.requested_model
            or frozen_usage.returned_model != task.requested_model
            or frozen_usage.actual_model != task.requested_model
            or frozen_usage.status != "success"
            or frozen_usage.validation_status is not ModelRequestValidationStatus.VALID
            or frozen_usage.fallback_used
            or frozen_usage.substitution_detected
            or frozen_usage.prompt_sha256 != activation.provider_prompt_sha256
            or frozen_usage.user_prompt_sha256 != activation.user_prompt_sha256
            or frozen_usage.schema_sha256 != activation.response_schema_sha256
            or frozen_usage.response_sha256 is None
            or frozen_usage.validated_response_sha256 is None
            or context.request_id != task.logical_request_id
            or context.request_role != task.role
            or frozen_usage.routing.get("context_request_evidence_sha256")
            != context.evidence_sha256
            or (
                frozen_normalization is None
                and frozen_usage.validated_response_sha256 != normalized_output_sha256
            )
        ):
            raise ValueError("scheduler model output is not the exact provider-validated response")
        values: dict[str, Any] = {
            "schema_version": (
                "1.2"
                if task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
                else ("1.1" if frozen_normalization is not None else "1.0")
            ),
            "evidence_authority": "comparison_required",
            "task_id": task.task_id,
            "logical_request_id": task.logical_request_id,
            "activation_sha256": activation.activation_sha256,
            "delivered_source_descriptor_sha256s": (activation.delivered_source_descriptor_sha256s),
            "usage_record": frozen_usage,
            "usage_record_sha256": scheduler_canonical_sha256(frozen_usage.model_dump(mode="json")),
            **(
                {
                    "audit_policy_selection_binding_sha256": (audit_model_selection.binding_sha256),
                    "audit_model_selection_bundle_sha256": (
                        audit_routing.audit_model_selection_bundle_sha256
                    ),
                    "audit_selection_sha256": audit_routing.audit_selection_sha256,
                    "audit_selected_model_set_sha256": (audit_routing.selected_model_set_sha256),
                    "audit_scope_sha256": audit_routing.audit_scope_sha256,
                    "audit_source_sha256": audit_routing.source_sha256,
                    "audit_selection_expires_at": audit_routing.expires_at,
                    "audit_policy_routing_evidence_sha256": (audit_routing.routing_evidence_sha256),
                }
                if audit_routing is not None and audit_model_selection is not None
                else {}
            ),
            **(
                {
                    "audit_model_refresh_pricing_binding_sha256": (
                        audit_model_refresh_pricing.binding_sha256
                    ),
                    "audit_model_refresh_pricing_evidence_sha256": (
                        audit_model_refresh_pricing.audit_model_refresh_pricing_evidence_sha256
                    ),
                    "audit_model_refresh_pricing_authority_capability_sha256": (
                        audit_model_refresh_pricing.pricing_authority_capability_sha256
                    ),
                    "audit_model_refresh_pricing_route_evidence_sha256": (
                        pricing_route.route_evidence_sha256
                    ),
                    "audit_model_refresh_pricing_baseline_sha256": (
                        pricing_route.baseline_pricing_sha256
                    ),
                    "audit_model_refresh_pricing_current_sha256": (
                        pricing_route.current_pricing_sha256
                    ),
                    "audit_model_refresh_pricing_expires_at": (
                        audit_model_refresh_pricing.expires_at
                    ),
                }
                if pricing_route is not None and audit_model_refresh_pricing is not None
                else {}
            ),
            **(
                {
                    "audit_model_refresh_binding_sha256": audit_model_refresh.binding_sha256,
                    "audit_model_refresh_evidence_sha256": (
                        audit_model_refresh.audit_model_refresh_evidence_sha256
                    ),
                    "audit_model_refresh_guard_capability_sha256": (
                        audit_model_refresh.guard_capability_sha256
                    ),
                    "audit_model_refresh_workflow_status_sha256": (
                        audit_model_refresh.workflow_status_sha256
                    ),
                    "audit_model_refresh_snapshot_sha256": audit_model_refresh.snapshot_sha256,
                    "audit_model_refresh_route_evidence_sha256": (
                        refresh_route.route_evidence_sha256
                    ),
                    "audit_model_refresh_audit_route_set_sha256": (
                        audit_model_refresh.audit_route_set_sha256
                    ),
                    "audit_model_refresh_technical_route_set_sha256": (
                        audit_model_refresh.technical_route_set_sha256
                    ),
                    "audit_model_refresh_expires_at": audit_model_refresh.expires_at,
                }
                if refresh_route is not None and audit_model_refresh is not None
                else {}
            ),
            "context_request_evidence": context,
            "context_request_evidence_sha256": context.evidence_sha256,
            "provider_response_sha256": frozen_usage.response_sha256,
            "validated_response_sha256": frozen_usage.validated_response_sha256,
            "response_schema_sha256": activation.response_schema_sha256,
            "normalized_output_sha256": normalized_output_sha256,
            **({"normalizer_sha256": normalizer_sha256} if normalizer_sha256 is not None else {}),
            **(
                {"normalization_evidence": frozen_normalization}
                if frozen_normalization is not None
                else {}
            ),
        }
        return cls(
            **values,
            completion_evidence_sha256=scheduler_canonical_sha256(values),
        )

    @model_validator(mode="after")
    def completion_evidence_is_redacted_and_exact(self) -> Self:
        _reject_sensitive_usage_material(self.usage_record.model_dump(mode="json"))
        normalization_algorithm = (
            candidate_review_schema_algorithm_version(
                wire_schema_sha256=self.normalization_evidence.wire_schema_sha256,
                normalized_batch_schema_sha256=(
                    self.normalization_evidence.normalized_batch_schema_sha256
                ),
            )
            if self.normalization_evidence is not None
            else None
        )
        framed_schema = normalization_algorithm is not None and (
            self.response_schema_sha256
            == candidate_review_frame_wire_schema_sha256(
                algorithm_version=normalization_algorithm,
            )
        )
        if self.schema_version == "1.0":
            if (
                self.normalizer_sha256 is None
                or self.normalization_evidence is not None
                or framed_schema
            ):
                raise ValueError("legacy scheduler completion cannot carry framed custody")
        elif self.schema_version == "1.1" and (
            self.normalizer_sha256 is None
            or self.normalization_evidence is None
            or not framed_schema
            or not candidate_review_protocol_implementation_is_pristine()
            or type(self.normalization_evidence) is not CandidateReviewNormalizationEvidence
        ):
            raise ValueError("framed scheduler completion lacks exact normalization custody")
        elif self.schema_version == "1.2" and (
            self.normalizer_sha256 is not None or self.normalization_evidence is not None
        ):
            raise ValueError("retrieval scheduler completion cannot carry normalization")
        if self.normalization_evidence is not None and (
            self.normalization_evidence.request_id != self.logical_request_id
            or self.normalization_evidence.wire_schema_sha256 != self.response_schema_sha256
            or self.normalization_evidence.normalized_batch_schema_sha256
            != candidate_review_batch_schema_sha256(
                algorithm_version=normalization_algorithm or SCHEDULER_ALGORITHM_VERSION,
            )
            or self.normalization_evidence.wire_validated_response_sha256
            != self.validated_response_sha256
            or self.normalization_evidence.normalized_batch_sha256 != self.normalized_output_sha256
        ):
            raise ValueError("scheduler normalization hashes are inconsistent")
        audit_fields = (
            self.audit_policy_selection_binding_sha256,
            self.audit_model_selection_bundle_sha256,
            self.audit_selection_sha256,
            self.audit_selected_model_set_sha256,
            self.audit_scope_sha256,
            self.audit_source_sha256,
            self.audit_selection_expires_at,
            self.audit_policy_routing_evidence_sha256,
        )
        refresh_fields = (
            self.audit_model_refresh_binding_sha256,
            self.audit_model_refresh_evidence_sha256,
            self.audit_model_refresh_guard_capability_sha256,
            self.audit_model_refresh_workflow_status_sha256,
            self.audit_model_refresh_snapshot_sha256,
            self.audit_model_refresh_route_evidence_sha256,
            self.audit_model_refresh_audit_route_set_sha256,
            self.audit_model_refresh_technical_route_set_sha256,
            self.audit_model_refresh_expires_at,
        )
        pricing_fields = (
            self.audit_model_refresh_pricing_binding_sha256,
            self.audit_model_refresh_pricing_evidence_sha256,
            self.audit_model_refresh_pricing_authority_capability_sha256,
            self.audit_model_refresh_pricing_route_evidence_sha256,
            self.audit_model_refresh_pricing_baseline_sha256,
            self.audit_model_refresh_pricing_current_sha256,
            self.audit_model_refresh_pricing_expires_at,
        )
        if any(item is None for item in audit_fields) and any(
            item is not None for item in audit_fields
        ):
            raise ValueError("scheduler audit policy completion evidence is all-or-none")
        audit_routing = _usage_audit_routing_evidence(self.usage_record)
        if usage_requires_audit_policy_evidence(self.usage_record) and (
            audit_routing is None or any(item is None for item in audit_fields)
        ):
            raise ValueError("REAL scheduler completion lacks audit policy routing evidence")
        if audit_routing is not None and (
            self.audit_model_selection_bundle_sha256
            != audit_routing.audit_model_selection_bundle_sha256
            or self.audit_selection_sha256 != audit_routing.audit_selection_sha256
            or self.audit_selected_model_set_sha256 != audit_routing.selected_model_set_sha256
            or self.audit_scope_sha256 != audit_routing.audit_scope_sha256
            or self.audit_source_sha256 != audit_routing.source_sha256
            or self.audit_selection_expires_at != audit_routing.expires_at
            or self.audit_policy_routing_evidence_sha256 != audit_routing.routing_evidence_sha256
        ):
            raise ValueError("scheduler audit policy completion hashes are inconsistent")
        refresh_route = _usage_audit_model_refresh_route_evidence(self.usage_record)
        if any(item is None for item in refresh_fields) and any(
            item is not None for item in refresh_fields
        ):
            raise ValueError("scheduler model-refresh completion evidence is all-or-none")
        if usage_requires_audit_policy_evidence(self.usage_record) and (
            refresh_route is None or any(item is None for item in refresh_fields)
        ):
            raise ValueError("REAL scheduler completion lacks model-refresh route evidence")
        if refresh_route is not None and (
            self.audit_model_refresh_evidence_sha256
            != self.usage_record.routing.get("audit_model_refresh_evidence_sha256")
            or self.audit_model_refresh_guard_capability_sha256
            != self.usage_record.routing.get("audit_model_refresh_guard_capability_sha256")
            or self.audit_model_refresh_workflow_status_sha256
            != self.usage_record.routing.get("audit_model_refresh_workflow_status_sha256")
            or self.audit_model_refresh_snapshot_sha256
            != self.usage_record.routing.get("audit_model_refresh_snapshot_sha256")
            or self.audit_model_refresh_route_evidence_sha256 != refresh_route.route_evidence_sha256
            or self.audit_model_refresh_audit_route_set_sha256
            != self.usage_record.routing.get("audit_model_refresh_audit_route_set_sha256")
            or self.audit_model_refresh_technical_route_set_sha256
            != self.usage_record.routing.get("audit_model_refresh_technical_route_set_sha256")
            or self.audit_model_refresh_expires_at is None
            or self.audit_model_refresh_expires_at.isoformat()
            != self.usage_record.routing.get("audit_model_refresh_expires_at")
        ):
            raise ValueError("scheduler model-refresh completion hashes are inconsistent")
        pricing_route = _usage_audit_model_refresh_pricing_route_evidence(self.usage_record)
        if any(item is None for item in pricing_fields) and any(
            item is not None for item in pricing_fields
        ):
            raise ValueError("scheduler refresh-pricing completion evidence is all-or-none")
        if refresh_route is not None and (
            pricing_route is None or any(item is None for item in pricing_fields)
        ):
            raise ValueError("REAL refresh-bound completion lacks refreshed-price evidence")
        if pricing_route is not None and (
            self.audit_model_refresh_pricing_evidence_sha256
            != self.usage_record.routing.get("audit_model_refresh_pricing_evidence_sha256")
            or self.audit_model_refresh_pricing_authority_capability_sha256
            != self.usage_record.routing.get(
                "audit_model_refresh_pricing_authority_capability_sha256"
            )
            or self.audit_model_refresh_pricing_route_evidence_sha256
            != pricing_route.route_evidence_sha256
            or self.audit_model_refresh_pricing_baseline_sha256
            != pricing_route.baseline_pricing_sha256
            or self.audit_model_refresh_pricing_current_sha256
            != pricing_route.current_pricing_sha256
            or self.audit_model_refresh_pricing_expires_at is None
            or self.audit_model_refresh_pricing_expires_at.isoformat()
            != self.usage_record.routing.get("audit_model_refresh_pricing_expires_at")
        ):
            raise ValueError("scheduler refresh-pricing completion hashes are inconsistent")
        if (
            self.usage_record_sha256
            != scheduler_canonical_sha256(self.usage_record.model_dump(mode="json"))
            or self.context_request_evidence_sha256 != self.context_request_evidence.evidence_sha256
            or self.usage_record.request_id != self.logical_request_id
            or self.context_request_evidence.request_id != self.logical_request_id
            or self.delivered_source_descriptor_sha256s
            != tuple(sorted(set(self.delivered_source_descriptor_sha256s)))
            or self.usage_record.response_sha256 != self.provider_response_sha256
            or self.usage_record.validated_response_sha256 != self.validated_response_sha256
            or self.usage_record.schema_sha256 != self.response_schema_sha256
            or (
                self.normalization_evidence is None
                and self.validated_response_sha256 != self.normalized_output_sha256
            )
        ):
            raise ValueError("scheduler model completion evidence contains inconsistent hashes")
        if self.completion_evidence_sha256 != _model_sha256(
            self,
            exclude={
                "completion_evidence_sha256",
                *({"normalization_evidence"} if self.schema_version == "1.0" else set()),
            },
        ):
            raise ValueError("scheduler model completion evidence hash is inconsistent")
        return self


def _scheduler_truncated_envelope_routing(
    envelope: CandidateReviewTruncatedEnvelopeEvidence,
) -> dict[str, Any]:
    """Rebuild the complete raw-free envelope inventory retained in usage."""

    return {
        "candidate_review_truncated_envelope_evidence": envelope.model_dump(mode="json"),
        "candidate_review_truncated_envelope_sha256": envelope.evidence_sha256,
    }


def _scheduler_truncation_projection_routing(
    projection: CandidateReviewTruncationProjection,
) -> dict[str, Any]:
    """Rebuild the non-record projection inventory retained in usage."""

    return {
        "candidate_review_truncation_projection_sha256": projection.evidence_sha256,
        "candidate_review_truncation_termination": projection.termination.value,
        "candidate_review_truncation_findings_state": projection.findings_state.value,
        "candidate_review_truncation_surface_reviews_state": (
            projection.surface_reviews_state.value
        ),
        "candidate_review_truncation_summary_state": projection.summary_state.value,
        "candidate_review_truncation_stream_integrity_valid": projection.stream_integrity_valid,
        "candidate_review_truncation_document_complete": projection.document_complete,
        "candidate_review_truncation_declared_finding_count": projection.declared_finding_count,
        "candidate_review_truncation_declared_surface_review_count": (
            projection.declared_surface_review_count
        ),
        "candidate_review_truncation_observed_frame_count": projection.observed_frame_count,
        "candidate_review_truncation_observed_finding_frame_count": (
            projection.observed_finding_frame_count
        ),
        "candidate_review_truncation_observed_surface_review_frame_count": (
            projection.observed_surface_review_frame_count
        ),
        "candidate_review_truncation_accepted_frame_count": len(projection.accepted_frames),
        "candidate_review_truncation_accepted_finding_count": (projection.accepted_finding_count),
        "candidate_review_truncation_accepted_surface_review_count": (
            projection.accepted_surface_review_count
        ),
        "candidate_review_truncation_invalid_frame_count": projection.invalid_frame_count,
        "candidate_review_truncation_credit_eligible": False,
        "candidate_review_truncation_authority_eligible": False,
    }


class SchedulerProviderAttemptEvidence(StrictModel):
    """Private redacted accounting evidence for a non-creditable provider attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    task_id: str = Field(pattern=r"^scheduler-task-[0-9a-f]{64}$")
    logical_request_id: str = Field(pattern=r"^scheduler-request-[0-9a-f]{64}$")
    activation_sha256: str = Field(pattern=_SHA256_PATTERN)
    delivered_source_descriptor_sha256s: tuple[str, ...] = Field(max_length=100_000)
    usage_record: UsageRecord
    usage_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_policy_selection_binding_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_selection_bundle_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_selection_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_selected_model_set_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_scope_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_source_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_selection_expires_at: datetime | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    audit_policy_routing_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_binding_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_guard_capability_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_workflow_status_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_snapshot_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_route_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_audit_route_set_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_technical_route_set_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_expires_at: datetime | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_pricing_binding_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_pricing_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_pricing_authority_capability_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_pricing_route_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_pricing_baseline_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_pricing_current_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_refresh_pricing_expires_at: datetime | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    context_request_evidence: ContextRequestEvidence
    context_request_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider_response_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    validated_response_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    response_schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    truncated_envelope_evidence: CandidateReviewTruncatedEnvelopeEvidence | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    truncation_projection: CandidateReviewTruncationProjection | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    attempt_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("truncated_envelope_evidence", mode="before")
    @classmethod
    def typed_truncated_envelope_reconstructs_from_json(
        cls,
        value: object,
    ) -> CandidateReviewTruncatedEnvelopeEvidence | None:
        if value is None or type(value) is CandidateReviewTruncatedEnvelopeEvidence:
            return value
        if type(value) is not dict:
            raise ValueError("scheduler truncated envelope has an invalid serialized type")
        try:
            return CandidateReviewTruncatedEnvelopeEvidence.model_validate_json(
                json.dumps(
                    value,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                ),
                strict=True,
            )
        except (TypeError, ValueError):
            raise ValueError("scheduler truncated envelope failed exact reconstruction") from None

    @field_validator("truncation_projection", mode="before")
    @classmethod
    def typed_truncation_projection_reconstructs_from_json(
        cls,
        value: object,
    ) -> CandidateReviewTruncationProjection | None:
        if value is None or type(value) is CandidateReviewTruncationProjection:
            return value
        if type(value) is not dict:
            raise ValueError("scheduler truncation projection has an invalid serialized type")
        try:
            return CandidateReviewTruncationProjection.model_validate_json(
                json.dumps(
                    value,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                ),
                strict=True,
            )
        except (TypeError, ValueError):
            raise ValueError(
                "scheduler truncation projection failed exact reconstruction"
            ) from None

    @classmethod
    def build(
        cls,
        *,
        task: SchedulerTaskPlan,
        activation: SchedulerTaskActivation,
        usage_record: UsageRecord,
        audit_model_selection: SchedulerAuditModelSelectionBinding | None,
        audit_model_refresh: SchedulerAuditModelRefreshBinding | None = None,
        audit_model_refresh_pricing: SchedulerAuditModelRefreshPricingBinding | None = None,
        truncated_envelope_evidence: CandidateReviewTruncatedEnvelopeEvidence | None = None,
        truncation_projection: CandidateReviewTruncationProjection | None = None,
    ) -> SchedulerProviderAttemptEvidence:
        if task.task_kind is not SchedulerTaskKind.MODEL_REQUEST:
            raise ValueError("scheduler provider-attempt evidence requires a model task")
        frozen_usage = UsageRecord.model_validate(usage_record.model_dump(mode="python"))
        _reject_sensitive_usage_material(frozen_usage.model_dump(mode="json"))
        if (truncated_envelope_evidence is None) != (truncation_projection is None):
            raise ValueError("scheduler typed truncation custody is all-or-none")
        frozen_envelope: CandidateReviewTruncatedEnvelopeEvidence | None = None
        frozen_projection: CandidateReviewTruncationProjection | None = None
        truncation_algorithm_version: str | None = None
        if truncated_envelope_evidence is not None and truncation_projection is not None:
            try:
                truncation_algorithm_version = candidate_review_schema_algorithm_version(
                    wire_schema_sha256=truncation_projection.wire_schema_sha256,
                    normalized_batch_schema_sha256=(
                        truncation_projection.normalized_batch_schema_sha256
                    ),
                )
            except ValueError:
                raise ValueError(
                    "scheduler typed truncation custody has an invalid schema pair"
                ) from None
            if (
                type(truncated_envelope_evidence) is not CandidateReviewTruncatedEnvelopeEvidence
                or type(truncation_projection) is not CandidateReviewTruncationProjection
                or not candidate_review_protocol_implementation_is_pristine()
                or not _task_uses_candidate_review_contract(task)
                or activation.response_schema_sha256
                != candidate_review_frame_wire_schema_sha256(
                    algorithm_version=truncation_algorithm_version,
                )
                or truncated_envelope_evidence.wire_schema_sha256
                != activation.response_schema_sha256
            ):
                raise ValueError("scheduler typed truncation custody has an invalid boundary")
            frozen_envelope = CandidateReviewTruncatedEnvelopeEvidence.model_validate_json(
                truncated_envelope_evidence.model_dump_json(),
                strict=True,
            )
            frozen_projection = CandidateReviewTruncationProjection.model_validate_json(
                truncation_projection.model_dump_json(),
                strict=True,
            )
        audit_routing = _usage_audit_routing_evidence(frozen_usage)
        if (
            usage_requires_audit_policy_evidence(frozen_usage)
            or (
                frozen_usage.execution_evidence is ExecutionEvidenceKind.REAL
                and audit_model_selection is not None
            )
            or audit_routing is not None
        ):
            audit_routing = _require_usage_audit_selection(
                usage_record=frozen_usage,
                requested_model=task.requested_model or "",
                binding=audit_model_selection,
            )
        refresh_route = _usage_audit_model_refresh_route_evidence(frozen_usage)
        if (
            frozen_usage.execution_evidence is ExecutionEvidenceKind.REAL
            or refresh_route is not None
        ):
            refresh_route = _require_usage_audit_model_refresh(
                usage_record=frozen_usage,
                requested_model=task.requested_model or "",
                binding=audit_model_refresh,
                audit_model_selection=audit_model_selection,
            )
        pricing_route = _usage_audit_model_refresh_pricing_route_evidence(frozen_usage)
        if (
            (
                frozen_usage.execution_evidence is ExecutionEvidenceKind.REAL
                and audit_model_refresh is not None
            )
            or pricing_route is not None
            or audit_model_refresh_pricing is not None
        ):
            pricing_route = _require_usage_audit_model_refresh_pricing(
                usage_record=frozen_usage,
                requested_model=task.requested_model or "",
                binding=audit_model_refresh_pricing,
                refresh_binding=audit_model_refresh,
            )
        context = ContextRequestEvidence.model_validate(
            frozen_usage.routing.get("context_request_evidence")
        )
        if (
            frozen_usage.request_id != task.logical_request_id
            or frozen_usage.role != task.role
            or frozen_usage.requested_model != task.requested_model
            or frozen_usage.prompt_sha256 != activation.provider_prompt_sha256
            or frozen_usage.user_prompt_sha256 != activation.user_prompt_sha256
            or frozen_usage.schema_sha256 != activation.response_schema_sha256
            or frozen_usage.accounted_cost_usd_exact is None
            or frozen_usage.started_at is None
            or frozen_usage.ended_at is None
            or frozen_usage.latency_ms is None
            or frozen_usage.retry_count != frozen_usage.attempts - 1
            or context.request_id != task.logical_request_id
            or context.request_role != task.role
            or frozen_usage.routing.get("context_request_evidence_sha256")
            != context.evidence_sha256
        ):
            raise ValueError("scheduler provider attempt is not exact non-creditable evidence")
        values: dict[str, Any] = {
            "schema_version": "1.1" if frozen_projection is not None else "1.0",
            "evidence_authority": "comparison_required",
            "task_id": task.task_id,
            "logical_request_id": task.logical_request_id,
            "activation_sha256": activation.activation_sha256,
            "delivered_source_descriptor_sha256s": (activation.delivered_source_descriptor_sha256s),
            "usage_record": frozen_usage,
            "usage_record_sha256": scheduler_canonical_sha256(frozen_usage.model_dump(mode="json")),
            **(
                {
                    "audit_policy_selection_binding_sha256": (audit_model_selection.binding_sha256),
                    "audit_model_selection_bundle_sha256": (
                        audit_routing.audit_model_selection_bundle_sha256
                    ),
                    "audit_selection_sha256": audit_routing.audit_selection_sha256,
                    "audit_selected_model_set_sha256": (audit_routing.selected_model_set_sha256),
                    "audit_scope_sha256": audit_routing.audit_scope_sha256,
                    "audit_source_sha256": audit_routing.source_sha256,
                    "audit_selection_expires_at": audit_routing.expires_at,
                    "audit_policy_routing_evidence_sha256": (audit_routing.routing_evidence_sha256),
                }
                if audit_routing is not None and audit_model_selection is not None
                else {}
            ),
            **(
                {
                    "audit_model_refresh_pricing_binding_sha256": (
                        audit_model_refresh_pricing.binding_sha256
                    ),
                    "audit_model_refresh_pricing_evidence_sha256": (
                        audit_model_refresh_pricing.audit_model_refresh_pricing_evidence_sha256
                    ),
                    "audit_model_refresh_pricing_authority_capability_sha256": (
                        audit_model_refresh_pricing.pricing_authority_capability_sha256
                    ),
                    "audit_model_refresh_pricing_route_evidence_sha256": (
                        pricing_route.route_evidence_sha256
                    ),
                    "audit_model_refresh_pricing_baseline_sha256": (
                        pricing_route.baseline_pricing_sha256
                    ),
                    "audit_model_refresh_pricing_current_sha256": (
                        pricing_route.current_pricing_sha256
                    ),
                    "audit_model_refresh_pricing_expires_at": (
                        audit_model_refresh_pricing.expires_at
                    ),
                }
                if pricing_route is not None and audit_model_refresh_pricing is not None
                else {}
            ),
            **(
                {
                    "audit_model_refresh_binding_sha256": audit_model_refresh.binding_sha256,
                    "audit_model_refresh_evidence_sha256": (
                        audit_model_refresh.audit_model_refresh_evidence_sha256
                    ),
                    "audit_model_refresh_guard_capability_sha256": (
                        audit_model_refresh.guard_capability_sha256
                    ),
                    "audit_model_refresh_workflow_status_sha256": (
                        audit_model_refresh.workflow_status_sha256
                    ),
                    "audit_model_refresh_snapshot_sha256": audit_model_refresh.snapshot_sha256,
                    "audit_model_refresh_route_evidence_sha256": (
                        refresh_route.route_evidence_sha256
                    ),
                    "audit_model_refresh_audit_route_set_sha256": (
                        audit_model_refresh.audit_route_set_sha256
                    ),
                    "audit_model_refresh_technical_route_set_sha256": (
                        audit_model_refresh.technical_route_set_sha256
                    ),
                    "audit_model_refresh_expires_at": audit_model_refresh.expires_at,
                }
                if refresh_route is not None and audit_model_refresh is not None
                else {}
            ),
            "context_request_evidence": context,
            "context_request_evidence_sha256": context.evidence_sha256,
            "provider_response_sha256": frozen_usage.response_sha256,
            "validated_response_sha256": frozen_usage.validated_response_sha256,
            "response_schema_sha256": activation.response_schema_sha256,
            **(
                {
                    "truncated_envelope_evidence": frozen_envelope,
                    "truncation_projection": frozen_projection,
                }
                if frozen_envelope is not None and frozen_projection is not None
                else {}
            ),
        }
        hash_values = (
            _scheduler_value_projection(
                values,
                algorithm_version=truncation_algorithm_version,
            )
            if truncation_algorithm_version is not None
            else values
        )
        return cls(**values, attempt_evidence_sha256=scheduler_canonical_sha256(hash_values))

    @classmethod
    def build_truncated(
        cls,
        *,
        task: SchedulerTaskPlan,
        activation: SchedulerTaskActivation,
        usage_record: UsageRecord,
        audit_model_selection: SchedulerAuditModelSelectionBinding | None,
        truncated_envelope_evidence: CandidateReviewTruncatedEnvelopeEvidence,
        truncation_projection: CandidateReviewTruncationProjection,
        audit_model_refresh: SchedulerAuditModelRefreshBinding | None = None,
        audit_model_refresh_pricing: SchedulerAuditModelRefreshPricingBinding | None = None,
    ) -> SchedulerProviderAttemptEvidence:
        """Build one private raw-free truncation capture before terminal append."""

        return cls.build(
            task=task,
            activation=activation,
            usage_record=usage_record,
            audit_model_selection=audit_model_selection,
            audit_model_refresh=audit_model_refresh,
            audit_model_refresh_pricing=audit_model_refresh_pricing,
            truncated_envelope_evidence=truncated_envelope_evidence,
            truncation_projection=truncation_projection,
        )

    @model_validator(mode="after")
    def attempt_is_redacted_and_exact(self) -> Self:
        _reject_sensitive_usage_material(self.usage_record.model_dump(mode="json"))
        envelope = self.truncated_envelope_evidence
        projection = self.truncation_projection
        if self.schema_version == "1.0":
            if envelope is not None or projection is not None:
                raise ValueError(
                    "legacy scheduler provider attempt cannot carry truncation custody"
                )
        elif (
            envelope is None
            or projection is None
            or type(envelope) is not CandidateReviewTruncatedEnvelopeEvidence
            or type(projection) is not CandidateReviewTruncationProjection
            or not candidate_review_protocol_implementation_is_pristine()
        ):
            raise ValueError("typed scheduler provider attempt lacks truncation custody")
        if envelope is not None and projection is not None:
            usage = self.usage_record
            try:
                truncation_algorithm_version = candidate_review_schema_algorithm_version(
                    wire_schema_sha256=projection.wire_schema_sha256,
                    normalized_batch_schema_sha256=projection.normalized_batch_schema_sha256,
                )
            except ValueError:
                raise ValueError(
                    "scheduler typed provider attempt uses an invalid schema pair"
                ) from None
            envelope_routing = _scheduler_truncated_envelope_routing(envelope)
            projection_routing = _scheduler_truncation_projection_routing(projection)
            actual_envelope_keys = {
                key for key in usage.routing if key.startswith("candidate_review_truncated_")
            }
            actual_projection_keys = {
                key for key in usage.routing if key.startswith("candidate_review_truncation_")
            }
            if (
                self.response_schema_sha256
                != candidate_review_frame_wire_schema_sha256(
                    algorithm_version=truncation_algorithm_version,
                )
                or envelope.wire_schema_sha256 != self.response_schema_sha256
                or usage.validation_status is not ModelRequestValidationStatus.TRUNCATED
                or usage.identity_strength is not ModelIdentityStrength.UNBOUND
                or usage.status != "rejected_truncated_response"
                or usage.validated_response_sha256 is not None
                or self.validated_response_sha256 is not None
                or usage.request_id != envelope.logical_request_id
                or usage.requested_model != envelope.requested_model
                or usage.returned_model != envelope.returned_model
                or usage.actual_model != envelope.selected_model
                or usage.provider != envelope.selected_provider_name
                or usage.openrouter_generation_id != envelope.generation_id
                or usage.actual_provider_endpoint != envelope.selected_provider_endpoint
                or usage.response_sha256 != envelope.response_sha256
                or usage.response_sha256 != projection.original_response_sha256
                or self.provider_response_sha256 != projection.original_response_sha256
                or usage.schema_sha256 != envelope.wire_schema_sha256
                or usage.schema_sha256 != projection.wire_schema_sha256
                or usage.finish_reason != envelope.finish_reason
                or usage.finish_reason != projection.finish_reason
                or envelope.native_finish_reason != projection.native_finish_reason
                or usage.routing.get("generation_id") != envelope.generation_id
                or usage.routing.get("generation_header_id") != envelope.generation_header_id
                or usage.routing.get("provider") != envelope.selected_provider_name
                or usage.routing.get("router_metadata_sha256") != envelope.router_metadata_sha256
                or usage.routing.get("finish_reason") != envelope.finish_reason
                or usage.routing.get("native_finish_reason") != envelope.native_finish_reason
                or usage.routing.get("schema_sha256") != envelope.wire_schema_sha256
                or projection.review_credit_eligible
                or projection.coverage_credit_eligible
                or projection.summary_credit_eligible
                or projection.authority_eligible
                or actual_envelope_keys != set(envelope_routing)
                or any(usage.routing.get(key) != value for key, value in envelope_routing.items())
                or actual_projection_keys != set(projection_routing)
                or any(usage.routing.get(key) != value for key, value in projection_routing.items())
            ):
                raise ValueError(
                    "scheduler typed provider attempt differs from its truncation custody"
                )
        audit_fields = (
            self.audit_policy_selection_binding_sha256,
            self.audit_model_selection_bundle_sha256,
            self.audit_selection_sha256,
            self.audit_selected_model_set_sha256,
            self.audit_scope_sha256,
            self.audit_source_sha256,
            self.audit_selection_expires_at,
            self.audit_policy_routing_evidence_sha256,
        )
        refresh_fields = (
            self.audit_model_refresh_binding_sha256,
            self.audit_model_refresh_evidence_sha256,
            self.audit_model_refresh_guard_capability_sha256,
            self.audit_model_refresh_workflow_status_sha256,
            self.audit_model_refresh_snapshot_sha256,
            self.audit_model_refresh_route_evidence_sha256,
            self.audit_model_refresh_audit_route_set_sha256,
            self.audit_model_refresh_technical_route_set_sha256,
            self.audit_model_refresh_expires_at,
        )
        pricing_fields = (
            self.audit_model_refresh_pricing_binding_sha256,
            self.audit_model_refresh_pricing_evidence_sha256,
            self.audit_model_refresh_pricing_authority_capability_sha256,
            self.audit_model_refresh_pricing_route_evidence_sha256,
            self.audit_model_refresh_pricing_baseline_sha256,
            self.audit_model_refresh_pricing_current_sha256,
            self.audit_model_refresh_pricing_expires_at,
        )
        if any(item is None for item in audit_fields) and any(
            item is not None for item in audit_fields
        ):
            raise ValueError("scheduler audit policy provider-attempt evidence is all-or-none")
        audit_routing = _usage_audit_routing_evidence(self.usage_record)
        if (audit_routing is None) != all(item is None for item in audit_fields):
            raise ValueError("scheduler provider attempt has incomplete audit policy custody")
        if usage_requires_audit_policy_evidence(self.usage_record) and audit_routing is None:
            raise ValueError("REAL scheduler provider attempt lacks audit policy routing evidence")
        if audit_routing is not None and (
            self.audit_model_selection_bundle_sha256
            != audit_routing.audit_model_selection_bundle_sha256
            or self.audit_selection_sha256 != audit_routing.audit_selection_sha256
            or self.audit_selected_model_set_sha256 != audit_routing.selected_model_set_sha256
            or self.audit_scope_sha256 != audit_routing.audit_scope_sha256
            or self.audit_source_sha256 != audit_routing.source_sha256
            or self.audit_selection_expires_at != audit_routing.expires_at
            or self.audit_policy_routing_evidence_sha256 != audit_routing.routing_evidence_sha256
        ):
            raise ValueError("scheduler audit policy provider-attempt hashes are inconsistent")
        refresh_route = _usage_audit_model_refresh_route_evidence(self.usage_record)
        if any(item is None for item in refresh_fields) and any(
            item is not None for item in refresh_fields
        ):
            raise ValueError("scheduler model-refresh provider-attempt evidence is all-or-none")
        if usage_requires_audit_policy_evidence(self.usage_record) and (
            refresh_route is None or any(item is None for item in refresh_fields)
        ):
            raise ValueError("REAL scheduler provider attempt lacks model-refresh route evidence")
        if refresh_route is not None and (
            self.audit_model_refresh_evidence_sha256
            != self.usage_record.routing.get("audit_model_refresh_evidence_sha256")
            or self.audit_model_refresh_guard_capability_sha256
            != self.usage_record.routing.get("audit_model_refresh_guard_capability_sha256")
            or self.audit_model_refresh_workflow_status_sha256
            != self.usage_record.routing.get("audit_model_refresh_workflow_status_sha256")
            or self.audit_model_refresh_snapshot_sha256
            != self.usage_record.routing.get("audit_model_refresh_snapshot_sha256")
            or self.audit_model_refresh_route_evidence_sha256 != refresh_route.route_evidence_sha256
            or self.audit_model_refresh_audit_route_set_sha256
            != self.usage_record.routing.get("audit_model_refresh_audit_route_set_sha256")
            or self.audit_model_refresh_technical_route_set_sha256
            != self.usage_record.routing.get("audit_model_refresh_technical_route_set_sha256")
            or self.audit_model_refresh_expires_at is None
            or self.audit_model_refresh_expires_at.isoformat()
            != self.usage_record.routing.get("audit_model_refresh_expires_at")
        ):
            raise ValueError("scheduler model-refresh provider-attempt hashes are inconsistent")
        pricing_route = _usage_audit_model_refresh_pricing_route_evidence(self.usage_record)
        if any(item is None for item in pricing_fields) and any(
            item is not None for item in pricing_fields
        ):
            raise ValueError("scheduler refresh-pricing provider evidence is all-or-none")
        if refresh_route is not None and (
            pricing_route is None or any(item is None for item in pricing_fields)
        ):
            raise ValueError("REAL refresh-bound provider attempt lacks pricing evidence")
        if pricing_route is not None and (
            self.audit_model_refresh_pricing_evidence_sha256
            != self.usage_record.routing.get("audit_model_refresh_pricing_evidence_sha256")
            or self.audit_model_refresh_pricing_authority_capability_sha256
            != self.usage_record.routing.get(
                "audit_model_refresh_pricing_authority_capability_sha256"
            )
            or self.audit_model_refresh_pricing_route_evidence_sha256
            != pricing_route.route_evidence_sha256
            or self.audit_model_refresh_pricing_baseline_sha256
            != pricing_route.baseline_pricing_sha256
            or self.audit_model_refresh_pricing_current_sha256
            != pricing_route.current_pricing_sha256
            or self.audit_model_refresh_pricing_expires_at is None
            or self.audit_model_refresh_pricing_expires_at.isoformat()
            != self.usage_record.routing.get("audit_model_refresh_pricing_expires_at")
        ):
            raise ValueError("scheduler refresh-pricing provider hashes are inconsistent")
        if (
            not is_structurally_accountable_usage_record(self.usage_record)
            or self.usage_record_sha256
            != scheduler_canonical_sha256(self.usage_record.model_dump(mode="json"))
            or self.context_request_evidence_sha256 != self.context_request_evidence.evidence_sha256
            or self.usage_record.request_id != self.logical_request_id
            or self.context_request_evidence.request_id != self.logical_request_id
            or self.usage_record.response_sha256 != self.provider_response_sha256
            or self.usage_record.validated_response_sha256 != self.validated_response_sha256
            or self.usage_record.schema_sha256 != self.response_schema_sha256
            or self.attempt_evidence_sha256
            != _model_sha256(
                self,
                exclude={
                    "attempt_evidence_sha256",
                    *(
                        {"truncated_envelope_evidence", "truncation_projection"}
                        if self.schema_version == "1.0"
                        else set()
                    ),
                },
                algorithm_version=(
                    candidate_review_schema_algorithm_version(
                        wire_schema_sha256=self.truncation_projection.wire_schema_sha256,
                        normalized_batch_schema_sha256=(
                            self.truncation_projection.normalized_batch_schema_sha256
                        ),
                    )
                    if self.truncation_projection is not None
                    else SCHEDULER_ALGORITHM_VERSION
                ),
            )
        ):
            raise ValueError("scheduler provider-attempt evidence is inconsistent")
        return self


def _task_source_descriptors(
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
) -> tuple[SchedulerSourceDescriptor, ...]:
    selected_shards = (
        set(plan.manifest.shard_ids)
        if task.scope.kind is SchedulerScopeKind.GLOBAL
        else set(task.scope.shard_ids)
    )
    return tuple(
        source
        for shard in plan.manifest.shard_inventory.shards
        if shard.shard_id in selected_shards
        for source in shard.sources
    )


def _validated_model_surface_custody(
    *,
    task: SchedulerTaskPlan,
    activation: SchedulerTaskActivation,
    completion: SchedulerModelCompletionEvidence | None,
    parsed_payload: BaseModel | None,
    requests: Iterable[ModelSurfaceReviewRequest],
    artifact: ModelSurfaceReviewArtifact | None,
    algorithm_version: str,
) -> tuple[tuple[ModelSurfaceReviewRequest, ...], ModelSurfaceReviewArtifact | None]:
    frozen_requests = tuple(
        ModelSurfaceReviewRequest.model_validate(item.model_dump(mode="python"))
        for item in requests
    )
    frozen_artifact = (
        ModelSurfaceReviewArtifact.model_validate(artifact.model_dump(mode="python"))
        if artifact is not None
        else None
    )
    if not isinstance(parsed_payload, CandidateReviewBatch):
        if frozen_requests or frozen_artifact is not None:
            raise ValueError("non-review scheduler output cannot claim model-surface custody")
        return (), None
    if not frozen_requests or frozen_artifact is None or completion is None:
        raise ValueError("candidate review requires exact requested-surface artifact custody")
    surface_ids = tuple(item.surface_id for item in frozen_requests)
    if surface_ids != tuple(sorted(set(surface_ids))):
        raise ValueError("scheduler requested model surfaces must be unique and sorted")
    frozen_artifact.require_exact_requested_surface_manifest(frozen_requests)
    planned_surface_manifest_sha256 = task.model_surface_review_request_manifest_sha256
    if (
        algorithm_version == "mmaudit.seven-pass-scheduler.v2"
        and planned_surface_manifest_sha256 is None
    ):
        raise ValueError("scheduler-v2 candidate-review output lacks sealed surface authority")
    if planned_surface_manifest_sha256 is not None and (
        frozen_artifact.requested_surface_manifest_sha256 != planned_surface_manifest_sha256
        or completion.context_request_evidence.requested_surface_manifest_sha256
        != planned_surface_manifest_sha256
    ):
        raise ValueError(
            "model-surface artifact differs from its sealed pre-dispatch request manifest"
        )
    if (
        frozen_artifact.request_id != task.logical_request_id
        or frozen_artifact.review_role != task.role
        or frozen_artifact.rendered_context_sha256
        != completion.context_request_evidence.rendered_sha256
        or frozen_artifact.prompt_sha256 != activation.provider_prompt_sha256
        or frozen_artifact.response_sha256 != completion.provider_response_sha256
        or frozen_artifact.validated_response_sha256 != completion.validated_response_sha256
        or frozen_artifact.response_schema_sha256 != activation.response_schema_sha256
        or frozen_artifact.records != parsed_payload.surface_reviews
    ):
        raise ValueError("model-surface artifact differs from its exact request or completion")
    normalization = completion.normalization_evidence
    if normalization is None:
        if frozen_artifact.schema_version != "1.0":
            raise ValueError("legacy model-surface custody cannot claim framed normalization")
    elif (
        frozen_artifact.schema_version != "1.1"
        or frozen_artifact.normalization_evidence != normalization
        or frozen_artifact.normalized_response != parsed_payload
        or frozen_artifact.normalized_response_sha256 != completion.normalized_output_sha256
        or normalization.normalized_batch_sha256 != completion.normalized_output_sha256
    ):
        raise ValueError("framed model-surface artifact differs from scheduler normalization")
    request_by_id = {item.surface_id: item for item in frozen_requests}
    for record in frozen_artifact.records:
        request = request_by_id[record.surface_id]
        citation = record.citation
        location_symbol = citation.location.symbol if citation.location is not None else None
        citation_matches = bool(
            (citation.location is not None and citation.location in request.allowed_locations)
            or (citation.symbol is not None and citation.symbol in request.allowed_symbols)
            or (location_symbol is not None and location_symbol in request.allowed_symbols)
        )
        if (
            record.contract != request.contract
            or record.function_or_state_surface != request.function_or_state_surface
            or record.invariant_considered != request.invariant_considered
            or not citation_matches
        ):
            raise ValueError("model-surface record differs from its deterministic request")
    return frozen_requests, frozen_artifact


def _canonical_string_inventory(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if values != tuple(sorted(set(values))) or any(not item for item in values):
        raise ValueError(f"scheduler {label} inventory must be non-empty, unique, and sorted")
    return values


class SchedulerFindingReductionValidation(StrictModel):
    """Source-location disposition retained by deterministic finding reduction."""

    valid: bool
    content_hash: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    errors: tuple[str, ...] = Field(max_length=1_000)


class SchedulerFindingReductionCandidate(StrictModel):
    """Exact candidate hash and location disposition used by reduction."""

    candidate_id: str = Field(min_length=1, max_length=500)
    candidate_sha256: str = Field(pattern=_SHA256_PATTERN)
    location_validation: SchedulerFindingReductionValidation


class SchedulerFindingReductionGroup(StrictModel):
    """One deterministic candidate-equivalence group."""

    group_id: str = Field(min_length=1, max_length=500)
    candidate_ids: tuple[str, ...] = Field(min_length=1, max_length=100_000)
    canonical_candidate_id: str = Field(min_length=1, max_length=500)
    valid_candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    invalid_candidate_ids: tuple[str, ...] = Field(max_length=100_000)

    @model_validator(mode="after")
    def dispositions_partition_group(self) -> Self:
        candidate_ids = _canonical_string_inventory(
            self.candidate_ids,
            "finding-reduction group candidate",
        )
        valid_ids = _canonical_string_inventory(
            self.valid_candidate_ids,
            "valid finding-reduction candidate",
        )
        invalid_ids = _canonical_string_inventory(
            self.invalid_candidate_ids,
            "invalid finding-reduction candidate",
        )
        members = set(candidate_ids)
        if (
            self.canonical_candidate_id != candidate_ids[0]
            or set(valid_ids) & set(invalid_ids)
            or set(valid_ids) | set(invalid_ids) != members
        ):
            raise ValueError("scheduler finding-reduction group disposition is inconsistent")
        return self


class SchedulerFindingReductionOutput(StrictModel):
    """Closed host output for pass-three deterministic candidate reduction."""

    schema_version: Literal["1.0"] = "1.0"
    algorithm: Literal["mmaudit.deterministic-finding-reduction.v1"]
    blind_candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    execution_candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    candidate_payload_sha256s: dict[str, str] = Field(max_length=100_000)
    candidate_records: tuple[SchedulerFindingReductionCandidate, ...] = Field(max_length=100_000)
    groups: tuple[SchedulerFindingReductionGroup, ...] = Field(max_length=100_000)
    canonical_candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    reduction_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def candidate_partitions_and_hash_are_exact(self) -> Self:
        candidate_ids = _canonical_string_inventory(self.candidate_ids, "reduction candidate")
        blind = _canonical_string_inventory(self.blind_candidate_ids, "blind candidate")
        execution = _canonical_string_inventory(
            self.execution_candidate_ids,
            "execution candidate",
        )
        expected = set(candidate_ids)
        grouped = tuple(item for group in self.groups for item in group.candidate_ids)
        record_ids = tuple(item.candidate_id for item in self.candidate_records)
        group_ids = tuple(item.group_id for item in self.groups)
        canonical_ids = tuple(group.canonical_candidate_id for group in self.groups)
        if (
            set(blind) & set(execution)
            or set(blind) | set(execution) != expected
            or set(self.candidate_payload_sha256s) != expected
            or any(
                re.fullmatch(_SHA256_PATTERN, value) is None
                for value in self.candidate_payload_sha256s.values()
            )
            or record_ids != candidate_ids
            or any(
                item.candidate_sha256 != self.candidate_payload_sha256s[item.candidate_id]
                for item in self.candidate_records
            )
            or group_ids != tuple(sorted(set(group_ids)))
            or tuple(sorted(grouped)) != candidate_ids
            or len(set(grouped)) != len(grouped)
            or self.canonical_candidate_ids != tuple(sorted(set(canonical_ids)))
        ):
            raise ValueError("scheduler finding reduction does not bind an exact partition")
        if self.reduction_sha256 != _model_sha256(self, exclude={"reduction_sha256"}):
            raise ValueError("scheduler finding-reduction hash is inconsistent")
        return self


class SchedulerCrossShardRelationship(StrictModel):
    """One exact semantic relationship considered by pass four."""

    relationship_id: str = Field(min_length=1, max_length=500)
    relationship_kind: Literal["graph_boundary", "semantic_overlap"]
    source_shard_id: str = Field(pattern=_SHARD_ID_PATTERN)
    target_shard_id: str = Field(pattern=_SHARD_ID_PATTERN)
    source_path: str = Field(min_length=1, max_length=4_096)
    target_path: str = Field(min_length=1, max_length=4_096)
    resource_id: str = Field(min_length=1, max_length=1_000)
    relationship_sha256: str = Field(pattern=_SHA256_PATTERN)


class SchedulerCrossShardDecision(StrictModel):
    """Substantive model disposition joined to one semantic relationship."""

    relationship_id: str = Field(min_length=1, max_length=500)
    linked_candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    status: Literal["CANDIDATE", "REVIEWED_NO_ISSUE"]
    surface_id: str = Field(pattern=r"^model-surface:[0-9a-f]{64}$")
    review_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("linked_candidate_ids")
    @classmethod
    def linked_candidates_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_string_inventory(value, "relationship-linked candidate")


class SchedulerCrossShardIntegrationOutput(StrictModel):
    """Closed pass-four host output with one exact relationship disposition each."""

    schema_version: Literal["1.0"] = "1.0"
    algorithm: Literal["mmaudit.cross-shard-integration.v1"]
    status: Literal[
        "NOT_APPLICABLE_NO_SEMANTIC_INVENTORY",
        "REVIEWED_NO_CROSS_SHARD_RELATIONSHIPS",
        "EVALUATED",
    ]
    semantic_inventory_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    candidate_payload_sha256s: dict[str, str] = Field(max_length=100_000)
    candidate_records: tuple[SchedulerFindingReductionCandidate, ...] = Field(max_length=100_000)
    shard_ids: tuple[str, ...] = Field(max_length=100_000)
    semantic_relationship_ids: tuple[str, ...] = Field(max_length=100_000)
    boundary_review_artifact_sha256s: tuple[str, ...] = Field(max_length=100_000)
    invariant_review_present: bool
    high_critical_candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    validation_candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    relationships: tuple[SchedulerCrossShardRelationship, ...] = Field(max_length=100_000)
    decisions: tuple[SchedulerCrossShardDecision, ...] = Field(max_length=100_000)
    invariant_review_decision_ids: tuple[str, ...] = Field(max_length=100_000)
    integration_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def relationship_inventory_dispositions_and_hash_are_exact(self) -> Self:
        candidates = _canonical_string_inventory(self.candidate_ids, "integration candidate")
        _canonical_string_inventory(self.shard_ids, "integration shard")
        _canonical_string_inventory(
            self.semantic_relationship_ids,
            "semantic relationship",
        )
        _canonical_string_inventory(
            self.boundary_review_artifact_sha256s,
            "boundary review artifact",
        )
        relationship_ids = tuple(item.relationship_id for item in self.relationships)
        decision_ids = tuple(item.relationship_id for item in self.decisions)
        record_ids = tuple(item.candidate_id for item in self.candidate_records)
        valid_ids = tuple(
            item.candidate_id for item in self.candidate_records if item.location_validation.valid
        )
        expected_status = (
            "NOT_APPLICABLE_NO_SEMANTIC_INVENTORY"
            if self.semantic_inventory_sha256 is None
            else "REVIEWED_NO_CROSS_SHARD_RELATIONSHIPS"
            if not self.relationships
            else "EVALUATED"
        )
        if (
            set(self.candidate_payload_sha256s) != set(candidates)
            or any(
                re.fullmatch(_SHA256_PATTERN, value) is None
                for value in self.candidate_payload_sha256s.values()
            )
            or record_ids != candidates
            or any(
                item.candidate_sha256 != self.candidate_payload_sha256s[item.candidate_id]
                for item in self.candidate_records
            )
            or not set(self.high_critical_candidate_ids) <= set(candidates)
            or self.validation_candidate_ids != valid_ids
            or relationship_ids != tuple(sorted(set(relationship_ids)))
            or self.semantic_relationship_ids != relationship_ids
            or decision_ids != relationship_ids
            or self.boundary_review_artifact_sha256s
            != tuple(sorted(item.review_artifact_sha256 for item in self.decisions))
            or any(not set(item.linked_candidate_ids) <= set(candidates) for item in self.decisions)
            or self.status != expected_status
        ):
            raise ValueError("scheduler cross-shard integration inventory is inconsistent")
        if self.integration_sha256 != _model_sha256(self, exclude={"integration_sha256"}):
            raise ValueError("scheduler cross-shard integration hash is inconsistent")
        return self


class SchedulerReproductionHostOutput(StrictModel):
    """Closed pass-six host custody for generated tests and deterministic replays."""

    eligible_candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    generated_tests: tuple[GeneratedFoundryTestSpec, ...] | None = Field(
        default=None,
        max_length=10_000,
    )
    reproduction_results: tuple[ReproductionResult, ...] | None = Field(
        default=None,
        max_length=10_000,
    )
    generated_test_ids: tuple[str, ...] | None = Field(default=None, max_length=10_000)
    reproduction_result_ids: tuple[str, ...] | None = Field(default=None, max_length=10_000)
    falsification_decisions: int = Field(ge=0, le=100_000)

    @model_validator(mode="after")
    def representation_and_candidate_partition_are_exact(self) -> Self:
        eligible = _canonical_string_inventory(
            self.eligible_candidate_ids,
            "reproduction-eligible candidate",
        )
        full = self.generated_tests is not None and self.reproduction_results is not None
        identity_only = (
            self.generated_test_ids is not None and self.reproduction_result_ids is not None
        )
        if full == identity_only:
            raise ValueError("scheduler reproduction host output requires one exact representation")
        if full:
            assert self.generated_tests is not None
            assert self.reproduction_results is not None
            tests = tuple((item.candidate_id, item.name) for item in self.generated_tests)
            results = tuple(
                (item.candidate_id, item.test_name) for item in self.reproduction_results
            )
            if (
                tests != tuple(sorted(set(tests)))
                or results != tuple(sorted(set(results)))
                or set(tests) != set(results)
                or {candidate_id for candidate_id, _name in tests} != set(eligible)
            ):
                raise ValueError("scheduler reproduction objects are not canonical or eligible")
        else:
            assert self.generated_test_ids is not None
            assert self.reproduction_result_ids is not None
            generated_ids = _canonical_string_inventory(
                self.generated_test_ids,
                "generated-test ID",
            )
            result_ids = _canonical_string_inventory(
                self.reproduction_result_ids,
                "reproduction-result ID",
            )
            if generated_ids != result_ids or {
                candidate_id
                for candidate_id in eligible
                if any(item.startswith(f"{candidate_id}:") for item in generated_ids)
            } != set(eligible):
                raise ValueError("scheduler reproduction IDs do not cover the eligible candidates")
        return self


class SchedulerTerminalFindingState(StrEnum):
    """Exact client-facing disposition authorized by pass seven."""

    REPORTED_ACTIVE = "REPORTED_ACTIVE"
    REPORTED_REJECTED = "REPORTED_REJECTED"
    FILTERED_BELOW_THRESHOLD = "FILTERED_BELOW_THRESHOLD"


class SchedulerEvidencePayloadBinding(StrictModel):
    """Hash one complete typed payload while retaining its authoritative subject."""

    record_id: str = Field(pattern=_SHA256_PATTERN)
    subject_id: str = Field(min_length=1, max_length=500)
    payload_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        kind: Literal[
            "consensus_review",
            "judge",
            "verification",
            "cross_examination",
            "falsification",
            "reproduction",
            "reproduction_resolution",
        ],
        subject_id: str,
        payload: BaseModel,
    ) -> SchedulerEvidencePayloadBinding:
        """Bind one exact typed payload using the shared scheduler domain."""

        payload_sha256 = scheduler_canonical_sha256(payload.model_dump(mode="json"))
        return cls(
            record_id=scheduler_canonical_sha256(
                {
                    "kind": kind,
                    "subject_id": subject_id,
                    "payload_sha256": payload_sha256,
                }
            ),
            subject_id=subject_id,
            payload_sha256=payload_sha256,
        )


class SchedulerTerminalFindingBinding(StrictModel):
    """Bind one reduced group to its exact finding payload and terminal disposition."""

    group_id: str = Field(min_length=1, max_length=500)
    candidate_ids: tuple[str, ...] = Field(min_length=1, max_length=100_000)
    finding_id: str = Field(min_length=1, max_length=500)
    finding_payload_sha256: str = Field(pattern=_SHA256_PATTERN)
    state: SchedulerTerminalFindingState
    finding_status: FindingStatus
    finding_severity: Severity
    finding_origin_kind: FindingOriginKind

    @field_validator("candidate_ids")
    @classmethod
    def candidates_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_string_inventory(value, "terminal finding candidate")


class SchedulerEvidenceCapJudgmentOutput(StrictModel):
    """Closed pass-seven authority over exact terminal report evidence."""

    schema_version: Literal["2.0"] = "2.0"
    algorithm: Literal["mmaudit.evidence-cap-terminal-authority.v2"]
    severity_threshold: Severity
    critical_confirmation_requires_execution: bool
    group_ids: tuple[str, ...] = Field(max_length=100_000)
    judge_decision_ids: tuple[str, ...] = Field(max_length=100_000)
    candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    candidate_payload_sha256s: dict[str, str] = Field(max_length=100_000)
    terminal_candidate_records: tuple[SchedulerFindingReductionCandidate, ...] = Field(
        max_length=100_000
    )
    candidate_grouping_sha256: str = Field(pattern=_SHA256_PATTERN)
    terminal_findings: tuple[SchedulerTerminalFindingBinding, ...] = Field(max_length=100_000)
    final_finding_ids: tuple[str, ...] = Field(max_length=100_000)
    rejected_finding_ids: tuple[str, ...] = Field(max_length=100_000)
    filtered_finding_ids: tuple[str, ...] = Field(max_length=100_000)
    final_finding_payload_sha256s: dict[str, str] = Field(max_length=100_000)
    rejected_finding_payload_sha256s: dict[str, str] = Field(max_length=100_000)
    filtered_finding_payload_sha256s: dict[str, str] = Field(max_length=100_000)
    judge_decisions: tuple[SchedulerEvidencePayloadBinding, ...] = Field(max_length=100_000)
    consensus_review: SchedulerEvidencePayloadBinding | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    verification_decisions: tuple[SchedulerEvidencePayloadBinding, ...] = Field(max_length=100_000)
    cross_examination_decisions: tuple[SchedulerEvidencePayloadBinding, ...] = Field(
        max_length=100_000
    )
    falsification_decisions: tuple[SchedulerEvidencePayloadBinding, ...] = Field(max_length=100_000)
    reproduction_results: tuple[SchedulerEvidencePayloadBinding, ...] = Field(max_length=100_000)
    reproduction_resolutions: tuple[SchedulerEvidencePayloadBinding, ...] = Field(
        max_length=100_000
    )
    judgment_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def inventories_are_canonical_complete_and_hash_bound(self) -> Self:
        groups = _canonical_string_inventory(self.group_ids, "judgment group")
        judges = _canonical_string_inventory(self.judge_decision_ids, "judge decision")
        candidates = _canonical_string_inventory(self.candidate_ids, "judgment candidate")
        final = _canonical_string_inventory(self.final_finding_ids, "final finding")
        rejected = _canonical_string_inventory(self.rejected_finding_ids, "rejected finding")
        filtered = _canonical_string_inventory(self.filtered_finding_ids, "filtered finding")

        def require_payload_hashes(values: dict[str, str], label: str) -> tuple[str, ...]:
            keys = tuple(values)
            if keys != tuple(sorted(set(keys))) or any(
                re.fullmatch(_SHA256_PATTERN, value) is None for value in values.values()
            ):
                raise ValueError(f"scheduler {label} payload hashes are not canonical")
            return keys

        candidate_hash_ids = require_payload_hashes(
            self.candidate_payload_sha256s,
            "candidate",
        )
        terminal_candidate_ids = tuple(
            item.candidate_id for item in self.terminal_candidate_records
        )
        final_hash_ids = require_payload_hashes(
            self.final_finding_payload_sha256s,
            "final finding",
        )
        rejected_hash_ids = require_payload_hashes(
            self.rejected_finding_payload_sha256s,
            "rejected finding",
        )
        filtered_hash_ids = require_payload_hashes(
            self.filtered_finding_payload_sha256s,
            "filtered finding",
        )

        terminal_group_ids = tuple(item.group_id for item in self.terminal_findings)
        terminal_finding_ids = tuple(item.finding_id for item in self.terminal_findings)
        grouped_candidate_ids = tuple(
            candidate_id for item in self.terminal_findings for candidate_id in item.candidate_ids
        )
        expected_grouping_sha256 = scheduler_canonical_sha256(
            [
                {
                    "group_id": item.group_id,
                    "candidate_ids": list(item.candidate_ids),
                }
                for item in self.terminal_findings
            ]
        )

        evidence_inventories = (
            ("judge", self.judge_decisions),
            ("verification", self.verification_decisions),
            ("cross_examination", self.cross_examination_decisions),
            ("falsification", self.falsification_decisions),
            ("reproduction", self.reproduction_results),
            ("reproduction_resolution", self.reproduction_resolutions),
        )
        for label, inventory in evidence_inventories:
            identities = tuple((item.subject_id, item.record_id) for item in inventory)
            if identities != tuple(sorted(set(identities))) or any(
                item.record_id
                != scheduler_canonical_sha256(
                    {
                        "kind": label,
                        "subject_id": item.subject_id,
                        "payload_sha256": item.payload_sha256,
                    }
                )
                for item in inventory
            ):
                raise ValueError(f"scheduler {label} evidence inventory is not canonical")

        if self.consensus_review is not None and self.consensus_review.record_id != (
            scheduler_canonical_sha256(
                {
                    "kind": "consensus_review",
                    "subject_id": self.consensus_review.subject_id,
                    "payload_sha256": self.consensus_review.payload_sha256,
                }
            )
        ):
            raise ValueError("scheduler consensus-review evidence binding is not canonical")

        judge_subjects = tuple(item.subject_id for item in self.judge_decisions)
        candidate_evidence_inventories = (
            self.verification_decisions,
            self.cross_examination_decisions,
            self.falsification_decisions,
            self.reproduction_results,
            self.reproduction_resolutions,
        )
        candidate_subjects = set(candidates)
        partition_sets = (set(final), set(rejected), set(filtered))
        overlapping = any(
            left & right
            for index, left in enumerate(partition_sets)
            for right in partition_sets[index + 1 :]
        )
        if (
            judges != groups
            or candidate_hash_ids != candidates
            or terminal_candidate_ids != candidates
            or any(
                item.candidate_sha256 != self.candidate_payload_sha256s[item.candidate_id]
                for item in self.terminal_candidate_records
            )
            or terminal_group_ids != groups
            or tuple(sorted(grouped_candidate_ids)) != candidates
            or len(set(grouped_candidate_ids)) != len(grouped_candidate_ids)
            or len(set(terminal_finding_ids)) != len(terminal_finding_ids)
            or self.candidate_grouping_sha256 != expected_grouping_sha256
            or overlapping
            or tuple(sorted(terminal_finding_ids)) != tuple(sorted((*final, *rejected, *filtered)))
            or final_hash_ids != final
            or rejected_hash_ids != rejected
            or filtered_hash_ids != filtered
            or judge_subjects != groups
            or any(
                not {item.subject_id for item in inventory} <= candidate_subjects
                for inventory in candidate_evidence_inventories
            )
            or len({item.subject_id for item in self.reproduction_resolutions})
            != len(self.reproduction_resolutions)
        ):
            raise ValueError("scheduler evidence-cap judgment partitions are inconsistent")

        finding_hashes_by_state = {
            SchedulerTerminalFindingState.REPORTED_ACTIVE: self.final_finding_payload_sha256s,
            SchedulerTerminalFindingState.REPORTED_REJECTED: (
                self.rejected_finding_payload_sha256s
            ),
            SchedulerTerminalFindingState.FILTERED_BELOW_THRESHOLD: (
                self.filtered_finding_payload_sha256s
            ),
        }
        threshold_rank = SEVERITY_ORDER[self.severity_threshold.value]
        for item in self.terminal_findings:
            if finding_hashes_by_state[item.state].get(item.finding_id) != (
                item.finding_payload_sha256
            ):
                raise ValueError("scheduler terminal finding hash or disposition is inconsistent")
            severity_rank = SEVERITY_ORDER[item.finding_severity.value]
            if item.state is SchedulerTerminalFindingState.REPORTED_REJECTED:
                if item.finding_status is not FindingStatus.REJECTED:
                    raise ValueError("scheduler rejected disposition retains an active finding")
            elif item.finding_status is FindingStatus.REJECTED:
                raise ValueError("scheduler active or filtered disposition retains a rejection")
            elif item.state is SchedulerTerminalFindingState.FILTERED_BELOW_THRESHOLD:
                if (
                    item.finding_origin_kind is FindingOriginKind.DETERMINISTIC_EXECUTION
                    or severity_rank >= threshold_rank
                ):
                    raise ValueError("scheduler filtered disposition violates report threshold")
            elif (
                item.finding_origin_kind is not FindingOriginKind.DETERMINISTIC_EXECUTION
                and severity_rank < threshold_rank
            ):
                raise ValueError("scheduler active disposition violates report threshold")

        if self.judgment_sha256 != _model_sha256(self, exclude={"judgment_sha256"}):
            raise ValueError("scheduler evidence-cap judgment hash is inconsistent")
        return self


def _parse_scheduler_host_payload(
    *,
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
    activation: SchedulerTaskActivation,
    payload: Any,
) -> BaseModel:
    response_model: type[BaseModel]
    if task.role == "host:finding_reducer":
        response_model = SchedulerFindingReductionOutput
    elif task.role == "host:cross_shard_integrator":
        response_model = SchedulerCrossShardIntegrationOutput
    elif task.role == "host:reproduction":
        response_model = SchedulerReproductionHostOutput
    elif task.role == "host:evidence_cap_judgment":
        response_model = SchedulerEvidenceCapJudgmentOutput
    else:
        raise ValueError(f"scheduler host role {task.role} lacks a typed output contract")
    try:
        parsed = response_model.model_validate(payload)
    except ValueError:
        raise ValueError(
            f"scheduler task output for host role {task.role} violates its typed contract"
        ) from None
    if isinstance(parsed, SchedulerFindingReductionOutput):
        activation_input: dict[str, Any] = {
            "blind_candidate_ids": list(parsed.blind_candidate_ids),
            "execution_candidate_ids": list(parsed.execution_candidate_ids),
            "candidate_payload_sha256s": parsed.candidate_payload_sha256s,
        }
        if scheduler_canonical_sha256(activation_input) != activation.actual_input_sha256:
            raise ValueError("scheduler finding reduction differs from its activated inventory")
    if isinstance(parsed, SchedulerReproductionHostOutput) and plan.candidate_workset is not None:
        planned_reproduction_ids = {
            candidate_id
            for model_task in plan.tasks
            if model_task.task_kind is SchedulerTaskKind.MODEL_REQUEST
            and (
                model_task.role.endswith(":exploit_test")
                or model_task.role in {"falsifier", "specialist:falsifier"}
            )
            for candidate_id in model_task.candidate_ids
        }
        if set(
            parsed.eligible_candidate_ids
        ) != planned_reproduction_ids or not planned_reproduction_ids <= set(
            plan.candidate_workset.selected_candidate_ids
        ):
            raise ValueError(
                "scheduler reproduction output differs from its exact candidate workset"
            )
    if isinstance(parsed, SchedulerCrossShardIntegrationOutput):
        activation_input = {
            "candidate_ids": list(parsed.candidate_ids),
            "candidate_payload_sha256s": parsed.candidate_payload_sha256s,
            "candidate_records": [
                item.model_dump(mode="json") for item in parsed.candidate_records
            ],
            "high_critical_candidate_ids": list(parsed.high_critical_candidate_ids),
            "validation_candidate_ids": list(parsed.validation_candidate_ids),
            "shard_ids": list(parsed.shard_ids),
            "semantic_inventory_sha256": parsed.semantic_inventory_sha256,
            "semantic_relationship_ids": list(parsed.semantic_relationship_ids),
            "semantic_relationships": [
                item.model_dump(mode="json") for item in parsed.relationships
            ],
            "boundary_review_artifact_sha256s": list(parsed.boundary_review_artifact_sha256s),
            "invariant_review_present": parsed.invariant_review_present,
        }
        if scheduler_canonical_sha256(activation_input) != activation.actual_input_sha256:
            raise ValueError("scheduler cross-shard integration differs from its activated input")
        relationship_by_id = {item.relationship_id: item for item in parsed.relationships}
        business_tasks_by_surface = {
            model_task.candidate_ids[0]: model_task
            for model_task in plan.tasks
            if model_task.task_kind is SchedulerTaskKind.MODEL_REQUEST
            and model_task.role == "business_logic"
            and len(model_task.candidate_ids) == 1
        }
        if set(business_tasks_by_surface) != {item.surface_id for item in parsed.decisions}:
            raise ValueError("scheduler relationship decisions differ from planned review surfaces")
        for decision in parsed.decisions:
            relationship = relationship_by_id[decision.relationship_id]
            task_scope = business_tasks_by_surface[decision.surface_id].scope
            if set(task_scope.shard_ids) != {
                relationship.source_shard_id,
                relationship.target_shard_id,
            }:
                raise ValueError("scheduler relationship review surface has the wrong shard scope")
        if set(parsed.shard_ids) != set(plan.manifest.shard_ids):
            raise ValueError("scheduler cross-shard integration differs from campaign shards")
        expected_semantic_inventory_sha256 = plan.manifest.shard_inventory.semantic_inventory_sha256
        expected_output_semantic_sha256 = (
            None
            if expected_semantic_inventory_sha256 == ABSENT_SEMANTIC_SHARD_INVENTORY_SHA256
            else expected_semantic_inventory_sha256
        )
        if parsed.semantic_inventory_sha256 != expected_output_semantic_sha256:
            raise ValueError("scheduler cross-shard integration uses the wrong semantic inventory")
    if isinstance(parsed, SchedulerEvidenceCapJudgmentOutput):
        judge_groups = tuple(
            candidate_id
            for model_task in plan.tasks
            if model_task.task_kind is SchedulerTaskKind.MODEL_REQUEST
            and model_task.role == "judge"
            for candidate_id in model_task.candidate_ids
        )
        if parsed.group_ids != tuple(sorted(judge_groups)):
            raise ValueError("scheduler judgment output differs from its exact judge partition")
    if (
        isinstance(
            parsed,
            (SchedulerReproductionHostOutput, SchedulerEvidenceCapJudgmentOutput),
        )
        and scheduler_canonical_sha256(payload) != activation.actual_input_sha256
    ):
        raise ValueError("scheduler host output differs from its exact activated input")
    return parsed


def _review_projection(
    *,
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
    activation: SchedulerTaskActivation,
    payload: Any,
    completion: SchedulerModelCompletionEvidence | None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Derive only explicit source/candidate review credit from normalized output."""

    if task.task_kind is not SchedulerTaskKind.MODEL_REQUEST:
        return (), ()
    if completion is None:
        raise ValueError("scheduler model output lacks provider completion evidence")
    if task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING:
        _parse_retrieval_request_batch_payload(payload)
        return (), ()
    if task.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW and (
        task.role == "source_audit" or _WHOLE_PROTOCOL_REVIEW_ROLE.fullmatch(task.role) is not None
    ):
        batch = CandidateReviewBatch.model_validate(payload)
        scoped_by_path = {source.path: source for source in _task_source_descriptors(plan, task)}
        if set(completion.delivered_source_descriptor_sha256s) != {
            source.source_descriptor_sha256 for source in scoped_by_path.values()
        }:
            raise ValueError("blind source review lacks exact full-source delivery")
        reviewed_paths = {
            record.citation.location.path
            for record in batch.surface_reviews
            if record.status
            in {
                ModelSurfaceReviewStatus.CANDIDATE,
                ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
            }
            and record.citation.location is not None
            and record.citation.location.path in scoped_by_path
        }
        expected_paths = set(scoped_by_path)
        if reviewed_paths != expected_paths:
            raise ValueError("blind source review did not substantively cover every scoped source")
        reviewed_sources = tuple(
            sorted(scoped_by_path[path].source_descriptor_sha256 for path in reviewed_paths)
        )
        return reviewed_sources, ()
    if task.pass_kind is SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION:
        cross_examination = CandidateCrossExaminationResponse.model_validate(payload)
        candidate_refs = tuple(decision.candidate_ref for decision in cross_examination.decisions)
        if candidate_refs != ("candidate-0001",) or len(task.candidate_ids) != 1:
            raise ValueError("pass-five response omitted its sole anonymized candidate")
        return (), task.candidate_ids
    if (
        task.pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
        and task.role == "business_logic"
    ):
        boundary_batch = CandidateReviewBatch.model_validate(payload).require_exact_surface_set(
            task.candidate_ids
        )
        scoped_by_path = {source.path: source for source in _task_source_descriptors(plan, task)}
        if set(completion.delivered_source_descriptor_sha256s) != {
            source.source_descriptor_sha256 for source in scoped_by_path.values()
        }:
            raise ValueError("cross-shard boundary review lacks exact full-source delivery")
        boundary_record = boundary_batch.surface_reviews[0]
        citation = boundary_record.citation.location
        if (
            boundary_record.status
            not in {
                ModelSurfaceReviewStatus.CANDIDATE,
                ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
            }
            or citation is None
            or citation.path not in scoped_by_path
        ):
            raise ValueError("cross-shard boundary review lacks a creditable surface disposition")
        return (
            (scoped_by_path[citation.path].source_descriptor_sha256,),
            task.candidate_ids,
        )
    if task.pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION:
        if task.role in {"verifier", "candidate_falsifier"}:
            verification_batch = VerificationBatch.model_validate(payload)
            candidate_values = tuple(
                decision.candidate_id for decision in verification_batch.decisions
            )
        elif task.role in {"falsifier", "specialist:falsifier"}:
            falsification_batch = FalsificationBatch.model_validate(payload)
            candidate_values = tuple(
                decision.candidate_id for decision in falsification_batch.decisions
            )
        else:
            return (), ()
        return (), _candidate_id_inventory(
            tuple(sorted(candidate_values)),
            "validated candidate",
        )
    if task.pass_kind is SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT and task.role == "judge":
        judge_batch = JudgeDecisionBatch.model_validate(payload)
        return (), _candidate_id_inventory(
            tuple(sorted(decision.group_id for decision in judge_batch.decisions)),
            "judged candidate group",
        )
    return (), ()


def _model_review_origin_candidate_id(
    *,
    request_role: str,
    request_id: str,
    candidate: CandidateFinding,
    algorithm_version: str,
) -> str:
    """Recompute the trusted host identity for one raw model candidate."""

    # Validate the scheduler algorithm even though neutral actor defaults are
    # intentionally identity-transparent in this legacy-stable origin domain.
    scheduler_typed_payload_projection(candidate, algorithm_version=algorithm_version)
    return model_review_origin_candidate_id(
        request_role=request_role,
        request_id=request_id,
        candidate=candidate,
    )


def _accepted_candidate_projection_is_exact(
    *,
    batch: CandidateReviewBatch,
    candidates: Sequence[CandidateFinding],
    usage_record: UsageRecord,
    algorithm_version: str,
) -> bool:
    """Verify the complete deterministic host stamping of one candidate batch."""

    expected_by_id = {
        _model_review_origin_candidate_id(
            request_role=usage_record.role,
            request_id=usage_record.request_id,
            candidate=raw,
            algorithm_version=algorithm_version,
        ): raw
        for raw in batch.findings
    }
    if len(expected_by_id) != len(batch.findings) or {
        candidate.candidate_id for candidate in candidates
    } != set(expected_by_id):
        return False
    unchanged_fields = {
        "candidate_id",
        "evidence",
        "execution_provenance",
        "model_family",
        "model_votes",
        "origin_kind",
        "role",
    }
    for candidate in candidates:
        raw = expected_by_id[candidate.candidate_id]
        if (
            candidate.origin_kind is not CandidateOriginKind.MODEL_REVIEW
            or candidate.execution_provenance is not None
            or candidate.role != usage_record.role
            or candidate.model_dump(mode="json", exclude=unchanged_fields)
            != raw.model_dump(mode="json", exclude=unchanged_fields)
            or len(candidate.model_votes) != 1
        ):
            return False
        vote = candidate.model_votes[0]
        if (
            vote.role != usage_record.role
            or vote.requested_model != usage_record.requested_model
            or vote.returned_model != usage_record.returned_model
            or vote.family != candidate.model_family
            or vote.verdict != "proposed"
            or vote.rationale != raw.summary
            or len(candidate.evidence) != len(raw.evidence)
        ):
            return False
        for raw_evidence, accepted_evidence in zip(
            raw.evidence,
            candidate.evidence,
            strict=True,
        ):
            retained_scanner = (
                raw_evidence.type == "scanner"
                and raw_evidence.fingerprint is not None
                and accepted_evidence == raw_evidence
            )
            normalized_model = (
                accepted_evidence.type == "model"
                and accepted_evidence.source == usage_record.role
                and accepted_evidence.description == raw_evidence.description
                and accepted_evidence.rule_id is None
                and accepted_evidence.fingerprint is None
            )
            if not (retained_scanner or normalized_model):
                return False
    return True


class SchedulerRetrievalCustody(StrictModel):
    """Hash-only public projection of one bounded retrieval transcript."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    planner_task_id: str = Field(pattern=r"^scheduler-task-[0-9a-f]{64}$")
    planner_task_result_id: str = Field(pattern=r"^scheduler-result-[0-9a-f]{64}$")
    planner_task_result_sha256: str = Field(pattern=_SHA256_PATTERN)
    planner_output_id: str = Field(pattern=r"^scheduler-output-[0-9a-f]{64}$")
    planner_output_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    role_budget_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    role_budget_allocation_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    corpus_sha256: str = Field(pattern=_SHA256_PATTERN)
    transcript_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_sha256s: tuple[str, ...] = Field(max_length=SOLIDITY_RETRIEVAL_MAX_EXCHANGES)
    result_sha256s: tuple[str, ...] = Field(max_length=SOLIDITY_RETRIEVAL_MAX_EXCHANGES)
    exchange_sha256s: tuple[str, ...] = Field(max_length=SOLIDITY_RETRIEVAL_MAX_EXCHANGES)
    retrieval_exhausted: bool
    single_shot_fallback_required: bool
    custody_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def from_binding(cls, binding: SchedulerRetrievalBinding) -> SchedulerRetrievalCustody:
        frozen = SchedulerRetrievalBinding.model_validate(binding.model_dump(mode="python"))
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "evidence_authority": "comparison_required",
            "planner_task_id": frozen.planner_task_id,
            "planner_task_result_id": frozen.planner_task_result_id,
            "planner_task_result_sha256": frozen.planner_task_result_sha256,
            "planner_output_id": frozen.planner_output_id,
            "planner_output_artifact_sha256": frozen.planner_output_artifact_sha256,
            "role_budget_plan_sha256": frozen.role_budget_plan_sha256,
            "role_budget_allocation_sha256": frozen.role_budget_allocation_sha256,
            "policy_sha256": frozen.transcript.policy_sha256,
            "corpus_sha256": frozen.transcript.corpus_sha256,
            "transcript_sha256": frozen.transcript.transcript_sha256,
            "request_sha256s": tuple(
                exchange.request.request_sha256 for exchange in frozen.transcript.exchanges
            ),
            "result_sha256s": tuple(
                exchange.result.result_sha256 for exchange in frozen.transcript.exchanges
            ),
            "exchange_sha256s": tuple(
                exchange.exchange_sha256 for exchange in frozen.transcript.exchanges
            ),
            "retrieval_exhausted": frozen.transcript.retrieval_exhausted,
            "single_shot_fallback_required": (frozen.transcript.single_shot_fallback_required),
        }
        return cls(**values, custody_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def custody_inventory_and_hash_are_exact(self) -> Self:
        inventories = (
            self.request_sha256s,
            self.result_sha256s,
            self.exchange_sha256s,
        )
        if (
            len({len(inventory) for inventory in inventories}) != 1
            or any(len(inventory) != len(set(inventory)) for inventory in inventories)
            or any(
                re.fullmatch(_SHA256_PATTERN, value) is None
                for inventory in inventories
                for value in inventory
            )
        ):
            raise ValueError("scheduler retrieval custody hash inventories are inconsistent")
        expected_single_shot = self.retrieval_exhausted or not self.exchange_sha256s
        if self.single_shot_fallback_required is not expected_single_shot:
            raise ValueError("scheduler retrieval custody fallback state is inconsistent")
        if self.custody_sha256 != _model_sha256(self, exclude={"custody_sha256"}):
            raise ValueError("scheduler retrieval custody hash is inconsistent")
        return self


class SchedulerRetrievalBinding(StrictModel):
    """Private full transcript bound to one exact planning child lifecycle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    planner_task_id: str = Field(pattern=r"^scheduler-task-[0-9a-f]{64}$")
    planner_task_result_id: str = Field(pattern=r"^scheduler-result-[0-9a-f]{64}$")
    planner_task_result_sha256: str = Field(pattern=_SHA256_PATTERN)
    planner_output_id: str = Field(pattern=r"^scheduler-output-[0-9a-f]{64}$")
    planner_output_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    role_budget_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    role_budget_allocation_sha256: str = Field(pattern=_SHA256_PATTERN)
    transcript: SolidityRetrievalTranscript
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build_pre_activation(
        cls,
        *,
        plan: SchedulerPassPlan,
        primary_task: SchedulerTaskPlan,
        planner_task: SchedulerTaskPlan,
        planner_output: SchedulerTaskOutput,
        planner_result: SchedulerTaskResult,
        transcript: SolidityRetrievalTranscript,
    ) -> SchedulerRetrievalBinding:
        role_budget_plan = plan.retrieval_role_budget_plan_for_task(primary_task.task_id)
        role_budget_allocation = role_budget_plan.allocation_for_task(primary_task.task_id)
        planner_completion = planner_output.model_completion_evidence
        planner_context = (
            None if planner_completion is None else planner_completion.context_request_evidence
        )
        if (
            not plan.has_exact_task(primary_task)
            or not plan.has_exact_task(planner_task)
            or primary_task.purpose is not SchedulerTaskPurpose.PRIMARY
            or planner_task.purpose is not SchedulerTaskPurpose.RETRIEVAL_PLANNING
            or planner_task.parent_task_id != primary_task.task_id
            or planner_result.pass_plan_id != plan.pass_plan_id
            or planner_result.task_id != planner_task.task_id
            or planner_result.task_plan_sha256 != planner_task.task_plan_sha256
            or planner_result.logical_request_id != planner_task.logical_request_id
            or planner_result.terminal_status is not SchedulerTerminalStatus.SUCCEEDED
            or planner_result.output_sha256 != planner_output.output_sha256
            or planner_result.output_artifact_sha256 != planner_output.output_artifact_sha256
            or planner_result.activation_id != planner_output.activation_id
            or planner_result.activation_sha256 != planner_output.activation_sha256
            or planner_output.pass_plan_id != plan.pass_plan_id
            or planner_output.task_id != planner_task.task_id
            or planner_output.logical_request_id != planner_task.logical_request_id
            or planner_completion is None
            or planner_completion.schema_version != "1.2"
            or planner_context is None
            or planner_context.schema_version != "1.1"
            or planner_context.request_id != planner_task.logical_request_id
            or planner_context.request_role != planner_task.role
            or planner_context.retrieval_policy_sha256
            != role_budget_allocation.policy.policy_sha256
            or planner_context.retrieval_corpus_sha256 != transcript.corpus_sha256
            or planner_context.retrieval_transcript_sha256 is not None
            or bool(planner_context.retrieval_request_sha256s)
            or bool(planner_context.retrieval_result_sha256s)
            or bool(planner_context.retrieval_exchange_sha256s)
            or planner_context.retrieval_exhausted is not None
            or planner_context.retrieval_single_shot_fallback_required is not None
            or transcript.role != primary_task.role
            or transcript.policy_sha256 != role_budget_allocation.policy.policy_sha256
        ):
            raise ValueError("scheduler retrieval binding differs from its planner lifecycle")
        frozen_transcript = SolidityRetrievalTranscript.model_validate(
            transcript.model_dump(mode="python")
        )
        require_solidity_retrieval_transcript_within_policy(
            role_budget_allocation.policy,
            frozen_transcript,
        )
        planned_requests = _parse_retrieval_request_batch_payload(
            planner_output.payload
        ).to_host_requests()
        if planned_requests != tuple(exchange.request for exchange in frozen_transcript.exchanges):
            raise ValueError(
                "scheduler retrieval transcript differs from its planner request batch"
            )
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "evidence_authority": "comparison_required",
            "planner_task_id": planner_task.task_id,
            "planner_task_result_id": planner_result.result_id,
            "planner_task_result_sha256": planner_result.result_sha256,
            "planner_output_id": planner_output.output_id,
            "planner_output_artifact_sha256": planner_output.output_artifact_sha256,
            "role_budget_plan_sha256": role_budget_plan.plan_sha256,
            "role_budget_allocation_sha256": role_budget_allocation.allocation_sha256,
            "transcript": frozen_transcript,
        }
        return cls(**values, binding_sha256=scheduler_canonical_sha256(values))

    @classmethod
    def build(
        cls,
        *,
        plan: SchedulerPassPlan,
        primary_task: SchedulerTaskPlan,
        primary_activation: SchedulerTaskActivation,
        planner_task: SchedulerTaskPlan,
        planner_output: SchedulerTaskOutput,
        planner_result: SchedulerTaskResult,
        transcript: SolidityRetrievalTranscript,
    ) -> SchedulerRetrievalBinding:
        """Build custody and bind it to an already durable primary activation."""

        binding = cls.build_pre_activation(
            plan=plan,
            primary_task=primary_task,
            planner_task=planner_task,
            planner_output=planner_output,
            planner_result=planner_result,
            transcript=transcript,
        )
        binding.require_exact_primary(
            plan=plan,
            task=primary_task,
            activation=primary_activation,
        )
        return binding

    @model_validator(mode="after")
    def binding_hash_is_exact(self) -> Self:
        if self.binding_sha256 != _model_sha256(self, exclude={"binding_sha256"}):
            raise ValueError("scheduler retrieval binding hash is inconsistent")
        return self

    def require_exact_primary(
        self,
        *,
        plan: SchedulerPassPlan,
        task: SchedulerTaskPlan,
        activation: SchedulerTaskActivation,
    ) -> None:
        activation.require_exact_task(plan=plan, task=task)
        self.require_exact_planned_primary(plan=plan, task=task)
        if activation.upstream_task_result_sha256s != (self.planner_task_result_sha256,):
            raise ValueError("scheduler retrieval binding differs from its primary activation")

    def require_exact_planned_primary(
        self,
        *,
        plan: SchedulerPassPlan,
        task: SchedulerTaskPlan,
    ) -> None:
        """Bind pre-activation custody to one exact planned primary through its child."""

        child = _retrieval_planning_child(plan, task)
        role_budget_plan = plan.retrieval_role_budget_plan_for_task(task.task_id)
        role_budget_allocation = role_budget_plan.allocation_for_task(task.task_id)
        if (
            not plan.has_exact_task(task)
            or task.purpose is not SchedulerTaskPurpose.PRIMARY
            or child is None
            or child.task_id != self.planner_task_id
            or self.transcript.role != task.role
            or self.role_budget_plan_sha256 != role_budget_plan.plan_sha256
            or self.role_budget_allocation_sha256 != role_budget_allocation.allocation_sha256
            or self.transcript.policy_sha256 != role_budget_allocation.policy.policy_sha256
        ):
            raise ValueError("scheduler retrieval binding differs from its planned primary")


def _require_context_retrieval_projection(
    context: ContextRequestEvidence,
    custody: SchedulerRetrievalCustody,
) -> None:
    """Require the exact context branch selected by retrieval exhaustion."""

    retrieval_fields = (
        context.retrieval_policy_sha256,
        context.retrieval_corpus_sha256,
        context.retrieval_transcript_sha256,
        context.retrieval_request_sha256s,
        context.retrieval_result_sha256s,
        context.retrieval_exchange_sha256s,
        context.retrieval_exhausted,
        context.retrieval_single_shot_fallback_required,
    )
    if custody.single_shot_fallback_required:
        if context.schema_version != "1.0" or any(retrieval_fields):
            raise ValueError("scheduler exhausted retrieval requires unchanged single-shot context")
        return

    expected = {
        "retrieval_policy_sha256": custody.policy_sha256,
        "retrieval_corpus_sha256": custody.corpus_sha256,
        "retrieval_transcript_sha256": custody.transcript_sha256,
        "retrieval_request_sha256s": custody.request_sha256s,
        "retrieval_result_sha256s": custody.result_sha256s,
        "retrieval_exchange_sha256s": custody.exchange_sha256s,
        "retrieval_exhausted": custody.retrieval_exhausted,
        "retrieval_single_shot_fallback_required": (custody.single_shot_fallback_required),
    }
    if context.schema_version != "1.1" or any(
        getattr(context, field) != value for field, value in expected.items()
    ):
        raise ValueError("scheduler retrieval transcript differs from context custody")


class SchedulerTaskOutput(StrictModel):
    """Private normalized JSON output required for deterministic result recovery."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1", "1.2", "1.3"] = "1.2"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    campaign_id: str = Field(pattern=r"^scheduler-campaign-[0-9a-f]{64}$")
    pass_plan_id: str = Field(pattern=r"^scheduler-plan-[0-9a-f]{64}$")
    task_id: str = Field(pattern=r"^scheduler-task-[0-9a-f]{64}$")
    logical_request_id: str = Field(pattern=r"^scheduler-request-[0-9a-f]{64}$")
    activation_id: str = Field(pattern=r"^scheduler-activation-[0-9a-f]{64}$")
    activation_sha256: str = Field(pattern=_SHA256_PATTERN)
    model_completion_evidence: SchedulerModelCompletionEvidence | None = None
    specialist_accepted_outcome: SpecialistAcceptedOutcome | None = None
    model_surface_review_requests: tuple[ModelSurfaceReviewRequest, ...] = Field(max_length=10_000)
    model_surface_review_artifact: ModelSurfaceReviewArtifact | None = None
    reviewed_source_descriptor_sha256s: tuple[str, ...] = Field(max_length=100_000)
    reviewed_candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    accepted_candidate_payload_sha256s: dict[str, str] = Field(
        default_factory=dict,
        max_length=100_000,
    )
    accepted_candidates: tuple[CandidateFinding, ...] = Field(
        default=(),
        max_length=100_000,
    )
    retrieval_binding: SchedulerRetrievalBinding | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    payload: Any
    payload_utf8_bytes: int = Field(ge=1, le=_MAX_TASK_OUTPUT_BYTES)
    output_sha256: str = Field(pattern=_SHA256_PATTERN)
    output_id: str = Field(pattern=r"^scheduler-output-[0-9a-f]{64}$")
    output_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        plan: SchedulerPassPlan,
        task: SchedulerTaskPlan,
        activation: SchedulerTaskActivation,
        payload: Any,
        usage_record: UsageRecord | None = None,
        specialist_accepted_outcome: SpecialistAcceptedOutcome | None = None,
        model_surface_review_requests: Iterable[ModelSurfaceReviewRequest] = (),
        model_surface_review_artifact: ModelSurfaceReviewArtifact | None = None,
        accepted_candidates: Iterable[CandidateFinding] = (),
        normalizer_sha256: str | None = None,
        normalization_evidence: CandidateReviewNormalizationEvidence | None = None,
        retrieval_binding: SchedulerRetrievalBinding | None = None,
        schema_version: Literal["1.0", "1.1", "1.2", "1.3"] | None = None,
    ) -> SchedulerTaskOutput:
        activation.require_exact_task(plan=plan, task=task)
        algorithm_version = plan.manifest.algorithm_version
        effective_schema_version: Literal["1.0", "1.1", "1.2", "1.3"] = (
            "1.3"
            if schema_version is None and retrieval_binding is not None
            else (
                "1.2"
                if schema_version is None and algorithm_version == "mmaudit.seven-pass-scheduler.v2"
                else ("1.1" if schema_version is None else schema_version)
            )
        )
        if (
            algorithm_version == "mmaudit.seven-pass-scheduler.v1"
            and effective_schema_version not in {"1.0", "1.1"}
        ) or (
            algorithm_version == "mmaudit.seven-pass-scheduler.v2"
            and effective_schema_version not in {"1.2", "1.3"}
        ):
            raise ValueError("scheduler task-output schema differs from its algorithm")
        if (effective_schema_version == "1.3") != (retrieval_binding is not None):
            raise ValueError("scheduler task-output retrieval schema differs from its binding")
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=_json_default,
        ).encode("utf-8")
        if not encoded or len(encoded) > _MAX_TASK_OUTPUT_BYTES:
            raise ValueError("scheduler task output exceeds its bounded JSON envelope")
        normalized = json.loads(encoded)
        output_sha256 = hashlib.sha256(encoded).hexdigest()
        parsed_payload: BaseModel | None = None
        if task.task_kind is SchedulerTaskKind.MODEL_REQUEST:
            parsed_payload = _parse_scheduler_model_payload(
                task=task,
                activation=activation,
                payload=normalized,
                algorithm_version=algorithm_version,
            )
            if normalized != scheduler_typed_payload_projection(
                parsed_payload,
                algorithm_version=algorithm_version,
            ):
                raise ValueError(
                    "scheduler task output does not use its algorithm's typed serialization"
                )
        elif task.task_kind is SchedulerTaskKind.HOST_COMPUTATION:
            parsed_payload = _parse_scheduler_host_payload(
                plan=plan,
                task=task,
                activation=activation,
                payload=normalized,
            )
        if task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING and (
            normalizer_sha256 is not None or normalization_evidence is not None
        ):
            raise ValueError("retrieval-planning output cannot claim normalization")
        effective_normalizer_sha256 = (
            None
            if task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
            else (normalizer_sha256 or task.normalizer_sha256)
        )
        if (
            normalizer_sha256 is not None
            and task.normalizer_sha256 is not None
            and normalizer_sha256 != task.normalizer_sha256
        ):
            raise ValueError("scheduler output normalizer differs from its sealed task plan")
        completion = (
            SchedulerModelCompletionEvidence.build(
                task=task,
                activation=activation,
                usage_record=usage_record,
                privacy_evidence_custody=plan.manifest.privacy_evidence_custody,
                audit_model_selection=plan.manifest.bindings.audit_model_selection,
                audit_model_refresh=plan.manifest.bindings.audit_model_refresh,
                audit_model_refresh_pricing=(plan.manifest.bindings.audit_model_refresh_pricing),
                normalizer_sha256=effective_normalizer_sha256,
                normalized_output_sha256=output_sha256,
                normalization_evidence=normalization_evidence,
                algorithm_version=algorithm_version,
            )
            if usage_record is not None
            and (
                effective_normalizer_sha256 is not None
                or task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
            )
            else None
        )
        if task.purpose is SchedulerTaskPurpose.PRIMARY and (
            (usage_record is None) != (effective_normalizer_sha256 is None)
        ):
            raise ValueError("scheduler model normalization evidence is all-or-none")
        if normalization_evidence is not None:
            if type(parsed_payload) is not CandidateReviewBatch:
                raise ValueError("scheduler normalization evidence requires a candidate batch")
            assert isinstance(parsed_payload, CandidateReviewBatch)
            normalization_evidence.require_exact_batch(
                parsed_payload,
                request_id=task.logical_request_id,
            )
        accepted_outcome = (
            SpecialistAcceptedOutcome.model_validate(
                specialist_accepted_outcome.model_dump(mode="python")
            )
            if specialist_accepted_outcome is not None
            else None
        )
        is_specialist = scheduler_task_requires_specialist_accepted_outcome(task)
        if is_specialist != (accepted_outcome is not None):
            raise ValueError(
                "scheduler specialist success requires one exact host-accepted outcome"
            )
        if accepted_outcome is not None and (
            completion is None
            or accepted_outcome.request_id != task.logical_request_id
            or accepted_outcome.request_role != task.role
            or accepted_outcome.validated_response_sha256 != completion.validated_response_sha256
            or accepted_outcome.context_request_evidence_sha256
            != completion.context_request_evidence_sha256
        ):
            raise ValueError("scheduler specialist outcome differs from provider completion")
        frozen_surface_requests, frozen_surface_artifact = _validated_model_surface_custody(
            task=task,
            activation=activation,
            completion=completion,
            parsed_payload=parsed_payload,
            requests=model_surface_review_requests,
            artifact=model_surface_review_artifact,
            algorithm_version=algorithm_version,
        )
        if accepted_outcome is not None:
            if isinstance(parsed_payload, CandidateReviewBatch):
                expected_kind = SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW
            elif isinstance(parsed_payload, InvariantReviewBatch):
                expected_kind = SpecialistAcceptedOutcomeKind.INVARIANT_REVIEW
            elif isinstance(parsed_payload, GeneratedFoundryTestBatch):
                expected_kind = SpecialistAcceptedOutcomeKind.TEST_GENERATION
            elif isinstance(parsed_payload, FalsificationBatch):
                expected_kind = SpecialistAcceptedOutcomeKind.FALSIFICATION
            elif isinstance(parsed_payload, ReportQualityReview):
                expected_kind = SpecialistAcceptedOutcomeKind.REPORT_QUALITY
            else:
                expected_kind = None
            if expected_kind is None or accepted_outcome.outcome_kind is not expected_kind:
                raise ValueError("scheduler specialist outcome kind differs from its typed payload")
            if expected_kind is SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW and (
                frozen_surface_artifact is None
                or (
                    accepted_outcome.requested_surface_count != len(frozen_surface_requests)
                    or accepted_outcome.surface_review_artifact_sha256
                    != frozen_surface_artifact.artifact_sha256
                )
            ):
                raise ValueError("scheduler specialist outcome differs from surface-review custody")
        reviewed_sources, reviewed_candidates = _review_projection(
            plan=plan,
            task=task,
            activation=activation,
            payload=normalized,
            completion=completion,
        )
        canonical_accepted_candidates = tuple(
            sorted(accepted_candidates, key=lambda item: item.candidate_id)
        )
        accepted_candidate_ids = tuple(
            candidate.candidate_id for candidate in canonical_accepted_candidates
        )
        if len(accepted_candidate_ids) != len(set(accepted_candidate_ids)):
            raise ValueError("scheduler accepted candidate projection repeats an identity")
        if isinstance(parsed_payload, CandidateReviewBatch):
            if effective_schema_version == "1.0":
                if canonical_accepted_candidates:
                    raise ValueError("scheduler task output 1.0 cannot bind accepted candidates")
            elif completion is None or not _accepted_candidate_projection_is_exact(
                batch=parsed_payload,
                candidates=canonical_accepted_candidates,
                usage_record=completion.usage_record,
                algorithm_version=algorithm_version,
            ):
                raise ValueError(
                    "scheduler accepted candidate projection differs from the review batch"
                )
        elif canonical_accepted_candidates:
            raise ValueError("non-candidate scheduler output cannot accept candidate payloads")
        accepted_candidate_payload_sha256s = {
            candidate.candidate_id: scheduler_candidate_payload_sha256(
                candidate,
                algorithm_version=algorithm_version,
            )
            for candidate in canonical_accepted_candidates
        }
        frozen_retrieval_binding = (
            SchedulerRetrievalBinding.model_validate(retrieval_binding.model_dump(mode="python"))
            if retrieval_binding is not None
            else None
        )
        if frozen_retrieval_binding is not None:
            frozen_retrieval_binding.require_exact_primary(
                plan=plan,
                task=task,
                activation=activation,
            )
            if completion is None:
                raise ValueError("scheduler retrieval transcript requires provider completion")
            _require_context_retrieval_projection(
                completion.context_request_evidence,
                SchedulerRetrievalCustody.from_binding(frozen_retrieval_binding),
            )
        output_id = "scheduler-output-" + scheduler_canonical_sha256(
            {
                "domain": "mmaudit.scheduler.task-output-identity.v1",
                "activation_id": activation.activation_id,
                "task_id": task.task_id,
            }
        )
        values: dict[str, Any] = {
            "schema_version": effective_schema_version,
            "evidence_authority": "comparison_required",
            "campaign_id": plan.manifest.campaign_id,
            "pass_plan_id": plan.pass_plan_id,
            "task_id": task.task_id,
            "logical_request_id": task.logical_request_id,
            "activation_id": activation.activation_id,
            "activation_sha256": activation.activation_sha256,
            "model_completion_evidence": completion,
            "specialist_accepted_outcome": accepted_outcome,
            "model_surface_review_requests": frozen_surface_requests,
            "model_surface_review_artifact": frozen_surface_artifact,
            "reviewed_source_descriptor_sha256s": reviewed_sources,
            "reviewed_candidate_ids": reviewed_candidates,
            "accepted_candidate_payload_sha256s": accepted_candidate_payload_sha256s,
            "accepted_candidates": canonical_accepted_candidates,
            **(
                {"retrieval_binding": frozen_retrieval_binding}
                if frozen_retrieval_binding is not None
                else {}
            ),
            "payload": normalized,
            "payload_utf8_bytes": len(encoded),
            "output_sha256": output_sha256,
            "output_id": output_id,
        }
        hash_values = (
            values
            if effective_schema_version != "1.0"
            else {
                key: value
                for key, value in values.items()
                if key
                not in {
                    "accepted_candidate_payload_sha256s",
                    "accepted_candidates",
                }
            }
        )
        return cls(
            **values,
            output_artifact_sha256=scheduler_canonical_sha256(
                _scheduler_value_projection(
                    hash_values,
                    algorithm_version=algorithm_version,
                )
            ),
        )

    @model_validator(mode="after")
    def output_identity_payload_and_hash_are_exact(self) -> Self:
        algorithm_version = (
            "mmaudit.seven-pass-scheduler.v2"
            if self.schema_version in {"1.2", "1.3"}
            else "mmaudit.seven-pass-scheduler.v1"
        )
        encoded = json.dumps(
            self.payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded) != self.payload_utf8_bytes or hashlib.sha256(encoded).hexdigest() != (
            self.output_sha256
        ):
            raise ValueError("scheduler output hash differs from its normalized JSON payload")
        if self.reviewed_source_descriptor_sha256s != tuple(
            sorted(set(self.reviewed_source_descriptor_sha256s))
        ):
            raise ValueError("scheduler reviewed source identities must be unique and sorted")
        _candidate_id_inventory(self.reviewed_candidate_ids, "reviewed candidate")
        accepted_ids = tuple(self.accepted_candidate_payload_sha256s)
        if accepted_ids != tuple(sorted(set(accepted_ids))) or any(
            re.fullmatch(_SHA256_PATTERN, value) is None
            for value in self.accepted_candidate_payload_sha256s.values()
        ):
            raise ValueError("scheduler accepted candidate payload hashes are not canonical")
        accepted_candidate_ids = tuple(
            candidate.candidate_id for candidate in self.accepted_candidates
        )
        if accepted_candidate_ids != tuple(sorted(set(accepted_candidate_ids))):
            raise ValueError("scheduler accepted candidate projection is not canonical")
        observed_accepted_hashes = {
            candidate.candidate_id: scheduler_candidate_payload_sha256(
                candidate,
                algorithm_version=algorithm_version,
            )
            for candidate in self.accepted_candidates
        }
        if self.accepted_candidate_payload_sha256s != observed_accepted_hashes:
            raise ValueError("scheduler accepted candidate payload hashes are inconsistent")
        try:
            candidate_batch = CandidateReviewBatch.model_validate(self.payload)
        except ValueError:
            candidate_batch = None
        try:
            judge_batch = JudgeDecisionBatch.model_validate(self.payload)
        except ValueError:
            judge_batch = None
        try:
            retrieval_batch = _parse_retrieval_request_batch_payload(self.payload)
        except ValueError:
            retrieval_batch = None
        actor_typed_payload = candidate_batch if candidate_batch is not None else judge_batch
        if actor_typed_payload is not None and self.payload != scheduler_typed_payload_projection(
            actor_typed_payload,
            algorithm_version=algorithm_version,
        ):
            raise ValueError(
                "scheduler task output does not use its algorithm's typed serialization"
            )
        if self.schema_version == "1.0":
            if self.accepted_candidates or self.accepted_candidate_payload_sha256s:
                raise ValueError("scheduler task output 1.0 cannot bind accepted candidates")
        elif candidate_batch is None:
            if self.accepted_candidates:
                raise ValueError("non-candidate scheduler output claims accepted candidates")
        elif self.model_completion_evidence is None or not _accepted_candidate_projection_is_exact(
            batch=candidate_batch,
            candidates=self.accepted_candidates,
            usage_record=self.model_completion_evidence.usage_record,
            algorithm_version=algorithm_version,
        ):
            raise ValueError(
                "scheduler accepted candidate projection differs from retained provider evidence"
            )
        if self.model_completion_evidence is not None and (
            self.model_completion_evidence.task_id != self.task_id
            or self.model_completion_evidence.logical_request_id != self.logical_request_id
            or self.model_completion_evidence.activation_sha256 != self.activation_sha256
            or self.model_completion_evidence.normalized_output_sha256 != self.output_sha256
        ):
            raise ValueError("scheduler model completion evidence differs from its output")
        if self.model_completion_evidence is not None:
            completion_algorithm = _actor_sensitive_response_schema_algorithm(
                self.model_completion_evidence.response_schema_sha256
            )
            if completion_algorithm is not None and completion_algorithm != algorithm_version:
                raise ValueError("scheduler output algorithm differs from its response schema")
            normalization = self.model_completion_evidence.normalization_evidence
            if normalization is not None:
                if candidate_batch is None:
                    raise ValueError("scheduler framed completion lacks a candidate batch payload")
                normalization.require_exact_batch(
                    candidate_batch,
                    request_id=self.logical_request_id,
                )
        if retrieval_batch is not None and (
            self.retrieval_binding is not None
            or self.specialist_accepted_outcome is not None
            or self.model_surface_review_requests
            or self.model_surface_review_artifact is not None
            or self.reviewed_source_descriptor_sha256s
            or self.reviewed_candidate_ids
            or self.accepted_candidate_payload_sha256s
            or self.accepted_candidates
            or (
                self.model_completion_evidence is not None
                and (
                    self.model_completion_evidence.normalizer_sha256 is not None
                    or self.model_completion_evidence.normalization_evidence is not None
                )
            )
        ):
            raise ValueError("retrieval-planning output cannot claim substantive review credit")
        if self.specialist_accepted_outcome is not None:
            completion = self.model_completion_evidence
            if (
                completion is None
                or self.specialist_accepted_outcome.request_id != self.logical_request_id
                or self.specialist_accepted_outcome.request_role != completion.usage_record.role
                or self.specialist_accepted_outcome.validated_response_sha256
                != completion.validated_response_sha256
                or self.specialist_accepted_outcome.context_request_evidence_sha256
                != completion.context_request_evidence_sha256
            ):
                raise ValueError("scheduler specialist outcome is not bound to its completion")
        if (self.model_surface_review_artifact is None) != (not self.model_surface_review_requests):
            raise ValueError("scheduler model-surface request and artifact custody is all-or-none")
        if self.model_surface_review_artifact is not None:
            self.model_surface_review_artifact.require_exact_requested_surface_manifest(
                self.model_surface_review_requests
            )
        if (
            self.specialist_accepted_outcome is not None
            and self.specialist_accepted_outcome.outcome_kind
            is SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW
            and (
                self.model_surface_review_artifact is None
                or self.specialist_accepted_outcome.requested_surface_count
                != len(self.model_surface_review_requests)
                or self.specialist_accepted_outcome.surface_review_artifact_sha256
                != self.model_surface_review_artifact.artifact_sha256
            )
        ):
            raise ValueError("scheduler specialist outcome is not bound to its surface artifact")
        expected_id = "scheduler-output-" + scheduler_canonical_sha256(
            {
                "domain": "mmaudit.scheduler.task-output-identity.v1",
                "activation_id": self.activation_id,
                "task_id": self.task_id,
            }
        )
        if self.output_id != expected_id:
            raise ValueError("scheduler output ID is inconsistent")
        if (self.schema_version == "1.3") != (self.retrieval_binding is not None):
            raise ValueError("scheduler output retrieval schema differs from its binding")
        hash_exclusions = {"output_artifact_sha256"}
        if self.schema_version == "1.0":
            hash_exclusions.update({"accepted_candidate_payload_sha256s", "accepted_candidates"})
        hash_payload = scheduler_typed_payload_projection(
            self,
            algorithm_version=algorithm_version,
        )
        for field_name in hash_exclusions:
            hash_payload.pop(field_name, None)
        if self.output_artifact_sha256 != scheduler_canonical_sha256(hash_payload):
            raise ValueError("scheduler output artifact hash is inconsistent")
        return self

    def require_exact_activation(self, activation: SchedulerTaskActivation) -> None:
        if (
            self.campaign_id != activation.campaign_id
            or self.pass_plan_id != activation.pass_plan_id
            or self.task_id != activation.task_id
            or self.logical_request_id != activation.logical_request_id
            or self.activation_id != activation.activation_id
            or self.activation_sha256 != activation.activation_sha256
        ):
            raise ValueError("scheduler output differs from its exact task activation")


class SchedulerTaskResult(StrictModel):
    """One terminal task result bound to activation or typed local preflight failure."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    campaign_id: str = Field(pattern=r"^scheduler-campaign-[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    pass_kind: SchedulerPassKind
    pass_id: str = Field(pattern=r"^scheduler-pass-[0-9a-f]{64}$")
    pass_plan_id: str = Field(pattern=r"^scheduler-plan-[0-9a-f]{64}$")
    pass_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    task_id: str = Field(pattern=r"^scheduler-task-[0-9a-f]{64}$")
    task_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    logical_request_id: str = Field(pattern=r"^scheduler-request-[0-9a-f]{64}$")
    scope: SchedulerScope
    result_origin: SchedulerResultOrigin
    activation_id: str | None = Field(default=None, pattern=r"^scheduler-activation-[0-9a-f]{64}$")
    activation_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    terminal_status: SchedulerTerminalStatus
    output_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    output_artifact_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    model_completion_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    usage_record_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    audit_policy_selection_binding_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_selection_bundle_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_selection_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_selected_model_set_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_scope_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_source_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_selection_expires_at: datetime | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    audit_policy_routing_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    context_request_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    provider_response_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    validated_response_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    normalizer_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    specialist_accepted_outcome_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    model_surface_review_artifact_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    model_surface_review_request_manifest_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    model_surface_review_request_count: int = Field(default=0, ge=0, le=10_000)
    reviewed_source_descriptor_sha256s: tuple[str, ...] = Field(max_length=100_000)
    reviewed_candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    retrieval_custody: SchedulerRetrievalCustody | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    terminal_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    result_id: str = Field(pattern=r"^scheduler-result-[0-9a-f]{64}$")
    result_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        plan: SchedulerPassPlan,
        task: SchedulerTaskPlan,
        activation: SchedulerTaskActivation,
        terminal_status: SchedulerTerminalStatus,
        terminal_evidence_sha256: str,
        output: SchedulerTaskOutput | None = None,
        retrieval_binding: SchedulerRetrievalBinding | None = None,
    ) -> SchedulerTaskResult:
        activation.require_exact_task(plan=plan, task=task)
        if output is not None:
            output.require_exact_activation(activation)
        completion = output.model_completion_evidence if output is not None else None
        if terminal_status is SchedulerTerminalStatus.SUCCEEDED:
            if task.task_kind is SchedulerTaskKind.MODEL_REQUEST:
                if completion is None:
                    raise ValueError("successful model task lacks provider completion evidence")
                assert output is not None
                if terminal_evidence_sha256 != completion.validated_response_sha256:
                    raise ValueError(
                        "successful model terminal evidence differs from validated response"
                    )
                required_candidate_credit = (
                    task.pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
                    and task.role == "business_logic"
                ) or (
                    task.pass_kind
                    in {
                        SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
                        SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
                        SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT,
                    }
                    and (
                        task.pass_kind is SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION
                        or task.role
                        in {
                            "verifier",
                            "candidate_falsifier",
                            "falsifier",
                            "specialist:falsifier",
                        }
                        or (
                            task.pass_kind is SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT
                            and task.role == "judge"
                        )
                    )
                )
                if (
                    required_candidate_credit
                    and output.reviewed_candidate_ids != task.candidate_ids
                ):
                    raise ValueError("successful model task omitted planned candidate decisions")
            elif completion is not None:
                raise ValueError("successful host task cannot claim model completion evidence")
        return cls._build(
            plan=plan,
            task=task,
            result_origin=SchedulerResultOrigin.ACTIVATED,
            activation=activation,
            terminal_status=terminal_status,
            terminal_evidence_sha256=terminal_evidence_sha256,
            output=output,
            retrieval_binding=retrieval_binding,
        )

    @classmethod
    def build_preflight_failure(
        cls,
        *,
        plan: SchedulerPassPlan,
        task: SchedulerTaskPlan,
        terminal_status: SchedulerTerminalStatus,
        terminal_evidence_sha256: str,
        retrieval_binding: SchedulerRetrievalBinding | None = None,
    ) -> SchedulerTaskResult:
        """Create a terminal local abort when request activation never occurred."""

        if terminal_status not in {
            SchedulerTerminalStatus.FAILED,
            SchedulerTerminalStatus.INVALID,
            SchedulerTerminalStatus.UNBOUND,
            SchedulerTerminalStatus.INCONCLUSIVE,
        }:
            raise ValueError("scheduler preflight result must fail closed")
        return cls._build(
            plan=plan,
            task=task,
            result_origin=SchedulerResultOrigin.LOCAL_PREFLIGHT,
            activation=None,
            terminal_status=terminal_status,
            terminal_evidence_sha256=terminal_evidence_sha256,
            output=None,
            retrieval_binding=retrieval_binding,
        )

    @classmethod
    def _build(
        cls,
        *,
        plan: SchedulerPassPlan,
        task: SchedulerTaskPlan,
        result_origin: SchedulerResultOrigin,
        activation: SchedulerTaskActivation | None,
        terminal_status: SchedulerTerminalStatus,
        terminal_evidence_sha256: str,
        output: SchedulerTaskOutput | None,
        retrieval_binding: SchedulerRetrievalBinding | None,
    ) -> SchedulerTaskResult:
        if not plan.has_exact_task(task):
            raise ValueError("scheduler result task is not in the sealed pass plan")
        output_binding = output.retrieval_binding if output is not None else None
        frozen_retrieval_binding = (
            SchedulerRetrievalBinding.model_validate(retrieval_binding.model_dump(mode="python"))
            if retrieval_binding is not None
            else output_binding
        )
        if (
            output_binding is not None
            and frozen_retrieval_binding is not None
            and output_binding != frozen_retrieval_binding
        ):
            raise ValueError("scheduler result retrieval custody differs from its private output")
        if frozen_retrieval_binding is not None:
            frozen_retrieval_binding.require_exact_planned_primary(plan=plan, task=task)
            if activation is not None:
                frozen_retrieval_binding.require_exact_primary(
                    plan=plan,
                    task=task,
                    activation=activation,
                )
        values: dict[str, Any] = {
            "schema_version": (
                "1.1"
                if task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
                or frozen_retrieval_binding is not None
                else "1.0"
            ),
            "evidence_authority": "comparison_required",
            "campaign_id": plan.manifest.campaign_id,
            "manifest_sha256": plan.manifest.manifest_sha256,
            "pass_kind": plan.pass_kind,
            "pass_id": plan.pass_id,
            "pass_plan_id": plan.pass_plan_id,
            "pass_plan_sha256": plan.pass_plan_sha256,
            "task_id": task.task_id,
            "task_plan_sha256": task.task_plan_sha256,
            "logical_request_id": task.logical_request_id,
            "scope": task.scope,
            "result_origin": result_origin,
            "activation_id": activation.activation_id if activation is not None else None,
            "activation_sha256": activation.activation_sha256 if activation is not None else None,
            "terminal_status": terminal_status,
            "output_sha256": output.output_sha256 if output is not None else None,
            "output_artifact_sha256": (
                output.output_artifact_sha256 if output is not None else None
            ),
            "model_completion_evidence_sha256": (
                output.model_completion_evidence.completion_evidence_sha256
                if output is not None and output.model_completion_evidence is not None
                else None
            ),
            "usage_record_sha256": (
                output.model_completion_evidence.usage_record_sha256
                if output is not None and output.model_completion_evidence is not None
                else None
            ),
            **(
                {
                    "audit_policy_selection_binding_sha256": (
                        output.model_completion_evidence.audit_policy_selection_binding_sha256
                    ),
                    "audit_model_selection_bundle_sha256": (
                        output.model_completion_evidence.audit_model_selection_bundle_sha256
                    ),
                    "audit_selection_sha256": (
                        output.model_completion_evidence.audit_selection_sha256
                    ),
                    "audit_selected_model_set_sha256": (
                        output.model_completion_evidence.audit_selected_model_set_sha256
                    ),
                    "audit_scope_sha256": output.model_completion_evidence.audit_scope_sha256,
                    "audit_source_sha256": output.model_completion_evidence.audit_source_sha256,
                    "audit_selection_expires_at": (
                        output.model_completion_evidence.audit_selection_expires_at
                    ),
                    "audit_policy_routing_evidence_sha256": (
                        output.model_completion_evidence.audit_policy_routing_evidence_sha256
                    ),
                }
                if output is not None
                and output.model_completion_evidence is not None
                and output.model_completion_evidence.audit_policy_routing_evidence_sha256
                is not None
                else {}
            ),
            "context_request_evidence_sha256": (
                output.model_completion_evidence.context_request_evidence_sha256
                if output is not None and output.model_completion_evidence is not None
                else None
            ),
            "provider_response_sha256": (
                output.model_completion_evidence.provider_response_sha256
                if output is not None and output.model_completion_evidence is not None
                else None
            ),
            "validated_response_sha256": (
                output.model_completion_evidence.validated_response_sha256
                if output is not None and output.model_completion_evidence is not None
                else None
            ),
            "normalizer_sha256": (
                output.model_completion_evidence.normalizer_sha256
                if output is not None and output.model_completion_evidence is not None
                else None
            ),
            "specialist_accepted_outcome_sha256": (
                output.specialist_accepted_outcome.evidence_sha256
                if output is not None and output.specialist_accepted_outcome is not None
                else None
            ),
            "model_surface_review_artifact_sha256": (
                output.model_surface_review_artifact.artifact_sha256
                if output is not None and output.model_surface_review_artifact is not None
                else None
            ),
            "model_surface_review_request_manifest_sha256": (
                output.model_surface_review_artifact.requested_surface_manifest_sha256
                if output is not None and output.model_surface_review_artifact is not None
                else None
            ),
            "model_surface_review_request_count": (
                len(output.model_surface_review_requests) if output is not None else 0
            ),
            "reviewed_source_descriptor_sha256s": (
                output.reviewed_source_descriptor_sha256s if output is not None else ()
            ),
            "reviewed_candidate_ids": output.reviewed_candidate_ids if output is not None else (),
            **(
                {
                    "retrieval_custody": SchedulerRetrievalCustody.from_binding(
                        frozen_retrieval_binding
                    )
                }
                if frozen_retrieval_binding is not None
                else {}
            ),
            "terminal_evidence_sha256": terminal_evidence_sha256,
        }
        result_id = "scheduler-result-" + scheduler_canonical_sha256(
            {
                "domain": "mmaudit.scheduler.task-result-identity.v1",
                "pass_plan_id": plan.pass_plan_id,
                "task_id": task.task_id,
                "logical_request_id": task.logical_request_id,
            }
        )
        body = {**values, "result_id": result_id}
        return cls(**body, result_sha256=scheduler_canonical_sha256(body))

    @model_validator(mode="after")
    def result_identity_and_terminal_shape_are_exact(self) -> Self:
        if self.result_origin is SchedulerResultOrigin.ACTIVATED:
            if self.activation_id is None or self.activation_sha256 is None:
                raise ValueError("activated scheduler result requires exact activation evidence")
        elif (
            self.activation_id is not None
            or self.activation_sha256 is not None
            or self.output_sha256 is not None
            or self.output_artifact_sha256 is not None
            or self.terminal_status
            not in {
                SchedulerTerminalStatus.FAILED,
                SchedulerTerminalStatus.INVALID,
                SchedulerTerminalStatus.UNBOUND,
                SchedulerTerminalStatus.INCONCLUSIVE,
            }
        ):
            raise ValueError("local preflight scheduler result must be a no-output failure")
        if self.terminal_status is SchedulerTerminalStatus.SUCCEEDED and (
            self.output_sha256 is None or self.output_artifact_sha256 is None
        ):
            raise ValueError("successful scheduler result requires exact output evidence")
        if self.terminal_status is not SchedulerTerminalStatus.SUCCEEDED and (
            self.output_sha256 is not None or self.output_artifact_sha256 is not None
        ):
            raise ValueError("non-success scheduler result cannot claim creditable output")
        provider_hashes = (
            self.model_completion_evidence_sha256,
            self.usage_record_sha256,
            self.context_request_evidence_sha256,
            self.provider_response_sha256,
            self.validated_response_sha256,
        )
        audit_policy_hashes = (
            self.audit_policy_selection_binding_sha256,
            self.audit_model_selection_bundle_sha256,
            self.audit_selection_sha256,
            self.audit_selected_model_set_sha256,
            self.audit_scope_sha256,
            self.audit_source_sha256,
            self.audit_selection_expires_at,
            self.audit_policy_routing_evidence_sha256,
        )
        if any(item is None for item in audit_policy_hashes) and any(
            item is not None for item in audit_policy_hashes
        ):
            raise ValueError("scheduler result audit policy hashes are all-or-none")
        if any(item is not None for item in audit_policy_hashes) and (
            self.terminal_status is not SchedulerTerminalStatus.SUCCEEDED
            or any(item is None for item in provider_hashes)
        ):
            raise ValueError("scheduler result audit policy evidence requires model success")
        if self.specialist_accepted_outcome_sha256 is not None and (
            self.terminal_status is not SchedulerTerminalStatus.SUCCEEDED
            or any(item is None for item in provider_hashes)
        ):
            raise ValueError("scheduler specialist outcome requires successful provider evidence")
        surface_fields = (
            self.model_surface_review_artifact_sha256,
            self.model_surface_review_request_manifest_sha256,
        )
        if (surface_fields[0] is None) != (surface_fields[1] is None):
            raise ValueError("scheduler surface-review hashes are all-or-none")
        if (self.model_surface_review_request_count > 0) != all(
            item is not None for item in surface_fields
        ):
            raise ValueError("scheduler surface-review count differs from its hash custody")
        if self.model_surface_review_request_count > 0 and (
            self.terminal_status is not SchedulerTerminalStatus.SUCCEEDED
            or any(item is None for item in provider_hashes)
        ):
            raise ValueError("scheduler surface-review custody requires successful model evidence")
        if any(item is None for item in provider_hashes) and any(
            item is not None for item in provider_hashes
        ):
            raise ValueError("scheduler model completion hashes are all-or-none")
        if self.terminal_status is SchedulerTerminalStatus.SUCCEEDED and any(
            item is not None for item in provider_hashes
        ):
            if self.schema_version == "1.0" and self.normalizer_sha256 is None:
                raise ValueError("primary scheduler result lacks its normalizer hash")
            if self.retrieval_custody is not None and self.normalizer_sha256 is None:
                raise ValueError("retrieval-bearing primary result lacks its normalizer hash")
            if (
                self.schema_version == "1.1"
                and self.retrieval_custody is None
                and self.normalizer_sha256 is not None
            ):
                raise ValueError("retrieval-planning result cannot claim normalization")
        if self.terminal_status is not SchedulerTerminalStatus.SUCCEEDED and (
            any(item is not None for item in provider_hashes)
            or self.normalizer_sha256 is not None
            or self.reviewed_source_descriptor_sha256s
            or self.reviewed_candidate_ids
        ):
            raise ValueError("non-success scheduler result cannot claim model review credit")
        if self.schema_version == "1.0" and self.retrieval_custody is not None:
            raise ValueError("legacy scheduler task result cannot carry retrieval custody")
        if self.reviewed_source_descriptor_sha256s != tuple(
            sorted(set(self.reviewed_source_descriptor_sha256s))
        ):
            raise ValueError("scheduler reviewed source result identities are not canonical")
        _candidate_id_inventory(self.reviewed_candidate_ids, "reviewed result candidate")
        expected_id = "scheduler-result-" + scheduler_canonical_sha256(
            {
                "domain": "mmaudit.scheduler.task-result-identity.v1",
                "pass_plan_id": self.pass_plan_id,
                "task_id": self.task_id,
                "logical_request_id": self.logical_request_id,
            }
        )
        if self.result_id != expected_id:
            raise ValueError("scheduler task-result ID is inconsistent")
        if self.result_sha256 != _model_sha256(self, exclude={"result_sha256"}):
            raise ValueError("scheduler task-result hash is inconsistent")
        return self


class SchedulerModelRequestEvidence(StrictModel):
    """Public hash-only projection of one exact planned model request lifecycle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    campaign_id: str = Field(pattern=r"^scheduler-campaign-[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    pass_kind: SchedulerPassKind
    pass_id: str = Field(pattern=r"^scheduler-pass-[0-9a-f]{64}$")
    pass_plan_id: str = Field(pattern=r"^scheduler-plan-[0-9a-f]{64}$")
    pass_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    task_id: str = Field(pattern=r"^scheduler-task-[0-9a-f]{64}$")
    task_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    logical_request_id: str = Field(pattern=r"^scheduler-request-[0-9a-f]{64}$")
    scope_sha256: str = Field(pattern=_SHA256_PATTERN)
    role: str = Field(pattern=_ROLE_PATTERN)
    purpose: SchedulerTaskPurpose = Field(
        default=SchedulerTaskPurpose.PRIMARY,
        exclude_if=lambda value: value is SchedulerTaskPurpose.PRIMARY,
    )
    parent_task_id: str | None = Field(
        default=None,
        pattern=r"^scheduler-task-[0-9a-f]{64}$",
        exclude_if=lambda value: value is None,
    )
    requested_model: str = Field(pattern=_MODEL_ID_PATTERN)
    root_lineage: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    activation_status: SchedulerActivationStatus
    activation_id: str | None = Field(default=None, pattern=r"^scheduler-activation-[0-9a-f]{64}$")
    activation_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    actual_input_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    system_prompt_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    user_prompt_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    provider_prompt_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    response_schema_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    delivered_source_descriptor_sha256s: tuple[str, ...] = Field(max_length=100_000)
    terminal_status: SchedulerTerminalStatus | None = None
    result_id: str | None = Field(default=None, pattern=r"^scheduler-result-[0-9a-f]{64}$")
    result_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    terminal_evidence_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    output_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    output_artifact_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    model_completion_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    usage_record_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    audit_policy_selection_binding_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_selection_bundle_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_selection_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_selected_model_set_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_scope_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_source_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_selection_expires_at: datetime | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    audit_policy_routing_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    context_request_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    provider_response_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    validated_response_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    normalizer_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    specialist_accepted_outcome_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    model_surface_review_artifact_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    model_surface_review_request_manifest_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    model_surface_review_request_count: int = Field(default=0, ge=0, le=10_000)
    reviewed_source_descriptor_sha256s: tuple[str, ...] = Field(max_length=100_000)
    reviewed_candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    retrieval_custody: SchedulerRetrievalCustody | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    request_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        plan: SchedulerPassPlan,
        task: SchedulerTaskPlan,
        activation: SchedulerTaskActivation | None,
        result: SchedulerTaskResult | None,
    ) -> SchedulerModelRequestEvidence:
        if not plan.has_exact_task(task) or task.task_kind is not SchedulerTaskKind.MODEL_REQUEST:
            raise ValueError("scheduler model-request evidence requires an exact model task")
        if task.requested_model is None or task.root_lineage is None:
            raise ValueError("scheduler model-request evidence lacks planned model identity")
        if activation is not None:
            activation.require_exact_task(plan=plan, task=task)
        if result is not None and (
            result.pass_plan_id != plan.pass_plan_id
            or result.task_id != task.task_id
            or result.task_plan_sha256 != task.task_plan_sha256
            or result.logical_request_id != task.logical_request_id
        ):
            raise ValueError("scheduler public request result differs from its task")
        if (
            result is not None
            and result.result_origin is SchedulerResultOrigin.ACTIVATED
            and (
                activation is None
                or result.activation_id != activation.activation_id
                or result.activation_sha256 != activation.activation_sha256
            )
        ):
            raise ValueError("scheduler public request result differs from activation")
        if result is not None and result.result_origin is SchedulerResultOrigin.LOCAL_PREFLIGHT:
            if activation is not None:
                raise ValueError("scheduler preflight request evidence cannot claim activation")
            activation_status = SchedulerActivationStatus.PREFLIGHT_FAILED
        elif activation is not None:
            activation_status = SchedulerActivationStatus.ACTIVATED
        else:
            activation_status = SchedulerActivationStatus.NOT_ACTIVATED
        values: dict[str, Any] = {
            "schema_version": (
                "1.1"
                if task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
                or (result is not None and result.retrieval_custody is not None)
                else "1.0"
            ),
            "evidence_authority": "comparison_required",
            "campaign_id": plan.manifest.campaign_id,
            "manifest_sha256": plan.manifest.manifest_sha256,
            "pass_kind": plan.pass_kind,
            "pass_id": plan.pass_id,
            "pass_plan_id": plan.pass_plan_id,
            "pass_plan_sha256": plan.pass_plan_sha256,
            "task_id": task.task_id,
            "task_plan_sha256": task.task_plan_sha256,
            "logical_request_id": task.logical_request_id,
            "scope_sha256": task.scope.scope_sha256,
            "role": task.role,
            **(
                {
                    "purpose": task.purpose,
                    "parent_task_id": task.parent_task_id,
                }
                if task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
                else {}
            ),
            "requested_model": task.requested_model,
            "root_lineage": task.root_lineage,
            "activation_status": activation_status,
            "activation_id": activation.activation_id if activation is not None else None,
            "activation_sha256": activation.activation_sha256 if activation is not None else None,
            "actual_input_sha256": (
                activation.actual_input_sha256 if activation is not None else None
            ),
            "system_prompt_sha256": (
                activation.system_prompt_sha256 if activation is not None else None
            ),
            "user_prompt_sha256": (
                activation.user_prompt_sha256 if activation is not None else None
            ),
            "provider_prompt_sha256": (
                activation.provider_prompt_sha256 if activation is not None else None
            ),
            "response_schema_sha256": (
                activation.response_schema_sha256 if activation is not None else None
            ),
            "delivered_source_descriptor_sha256s": (
                activation.delivered_source_descriptor_sha256s if activation is not None else ()
            ),
            "terminal_status": result.terminal_status if result is not None else None,
            "result_id": result.result_id if result is not None else None,
            "result_sha256": result.result_sha256 if result is not None else None,
            "terminal_evidence_sha256": (
                result.terminal_evidence_sha256 if result is not None else None
            ),
            "output_sha256": result.output_sha256 if result is not None else None,
            "output_artifact_sha256": (
                result.output_artifact_sha256 if result is not None else None
            ),
            "model_completion_evidence_sha256": (
                result.model_completion_evidence_sha256 if result is not None else None
            ),
            "usage_record_sha256": result.usage_record_sha256 if result is not None else None,
            **(
                {
                    "audit_policy_selection_binding_sha256": (
                        result.audit_policy_selection_binding_sha256
                    ),
                    "audit_model_selection_bundle_sha256": (
                        result.audit_model_selection_bundle_sha256
                    ),
                    "audit_selection_sha256": result.audit_selection_sha256,
                    "audit_selected_model_set_sha256": (result.audit_selected_model_set_sha256),
                    "audit_scope_sha256": result.audit_scope_sha256,
                    "audit_source_sha256": result.audit_source_sha256,
                    "audit_selection_expires_at": result.audit_selection_expires_at,
                    "audit_policy_routing_evidence_sha256": (
                        result.audit_policy_routing_evidence_sha256
                    ),
                }
                if result is not None and result.audit_policy_routing_evidence_sha256 is not None
                else {}
            ),
            "context_request_evidence_sha256": (
                result.context_request_evidence_sha256 if result is not None else None
            ),
            "provider_response_sha256": (
                result.provider_response_sha256 if result is not None else None
            ),
            "validated_response_sha256": (
                result.validated_response_sha256 if result is not None else None
            ),
            "normalizer_sha256": result.normalizer_sha256 if result is not None else None,
            "specialist_accepted_outcome_sha256": (
                result.specialist_accepted_outcome_sha256 if result is not None else None
            ),
            "model_surface_review_artifact_sha256": (
                result.model_surface_review_artifact_sha256 if result is not None else None
            ),
            "model_surface_review_request_manifest_sha256": (
                result.model_surface_review_request_manifest_sha256 if result is not None else None
            ),
            "model_surface_review_request_count": (
                result.model_surface_review_request_count if result is not None else 0
            ),
            "reviewed_source_descriptor_sha256s": (
                result.reviewed_source_descriptor_sha256s if result is not None else ()
            ),
            "reviewed_candidate_ids": (result.reviewed_candidate_ids if result is not None else ()),
            **(
                {"retrieval_custody": result.retrieval_custody}
                if result is not None and result.retrieval_custody is not None
                else {}
            ),
        }
        return cls(**values, request_evidence_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def public_request_shape_and_hash_are_exact(self) -> Self:
        if self.purpose is SchedulerTaskPurpose.PRIMARY:
            if self.parent_task_id is not None or (self.schema_version == "1.1") != (
                self.retrieval_custody is not None
            ):
                raise ValueError("primary public model request shape is not exact")
        elif (
            self.schema_version != "1.1"
            or self.parent_task_id is None
            or self.retrieval_custody is not None
        ):
            raise ValueError("retrieval-planning public request shape is not exact")
        activation_fields = (
            self.activation_id,
            self.activation_sha256,
            self.actual_input_sha256,
            self.system_prompt_sha256,
            self.user_prompt_sha256,
            self.provider_prompt_sha256,
            self.response_schema_sha256,
        )
        result_fields = (
            self.terminal_status,
            self.result_id,
            self.result_sha256,
            self.terminal_evidence_sha256,
        )
        if self.activation_status is SchedulerActivationStatus.ACTIVATED:
            if any(item is None for item in activation_fields):
                raise ValueError("activated public model request lacks exact request hashes")
        elif any(item is not None for item in activation_fields):
            raise ValueError("unactivated public model request cannot claim request hashes")
        if self.delivered_source_descriptor_sha256s != tuple(
            sorted(set(self.delivered_source_descriptor_sha256s))
        ):
            raise ValueError("public model-request delivered source identities are not canonical")
        if (
            self.activation_status is not SchedulerActivationStatus.ACTIVATED
            and self.delivered_source_descriptor_sha256s
        ):
            raise ValueError("unactivated public request cannot claim delivered sources")
        if self.activation_status is SchedulerActivationStatus.NOT_ACTIVATED:
            if any(item is not None for item in result_fields):
                raise ValueError("not-activated public model request cannot claim a result")
        elif self.activation_status is SchedulerActivationStatus.PREFLIGHT_FAILED:
            if any(item is None for item in result_fields) or self.terminal_status not in {
                SchedulerTerminalStatus.FAILED,
                SchedulerTerminalStatus.INVALID,
                SchedulerTerminalStatus.UNBOUND,
                SchedulerTerminalStatus.INCONCLUSIVE,
            }:
                raise ValueError("preflight public request must retain a fail-closed result")
        elif any(item is None for item in result_fields) and any(
            item is not None for item in result_fields
        ):
            raise ValueError("terminal public request fields are all-or-none")
        if self.terminal_status is SchedulerTerminalStatus.EXPLICIT_EMPTY:
            raise ValueError("model request cannot use explicit-empty terminal status")
        if self.terminal_status is SchedulerTerminalStatus.SUCCEEDED:
            if self.output_sha256 is None or self.output_artifact_sha256 is None:
                raise ValueError("successful public request requires exact output hashes")
        elif self.output_sha256 is not None or self.output_artifact_sha256 is not None:
            raise ValueError("non-success public request cannot claim output hashes")
        completion_fields = (
            self.model_completion_evidence_sha256,
            self.usage_record_sha256,
            self.context_request_evidence_sha256,
            self.provider_response_sha256,
            self.validated_response_sha256,
        )
        if self.terminal_status is SchedulerTerminalStatus.SUCCEEDED:
            if any(item is None for item in completion_fields):
                raise ValueError("successful public model request lacks completion hashes")
            if self.schema_version == "1.0" and self.normalizer_sha256 is None:
                raise ValueError("successful primary request lacks its normalizer hash")
            if self.retrieval_custody is not None and self.normalizer_sha256 is None:
                raise ValueError("retrieval-bearing primary request lacks its normalizer hash")
            if (
                self.schema_version == "1.1"
                and self.retrieval_custody is None
                and self.normalizer_sha256 is not None
            ):
                raise ValueError("retrieval-planning request cannot claim normalization")
        elif any(item is not None for item in completion_fields):
            raise ValueError("non-success public model request cannot claim completion hashes")
        elif self.normalizer_sha256 is not None:
            raise ValueError("non-success public request cannot claim a normalizer hash")
        audit_policy_fields = (
            self.audit_policy_selection_binding_sha256,
            self.audit_model_selection_bundle_sha256,
            self.audit_selection_sha256,
            self.audit_selected_model_set_sha256,
            self.audit_scope_sha256,
            self.audit_source_sha256,
            self.audit_selection_expires_at,
            self.audit_policy_routing_evidence_sha256,
        )
        if any(item is None for item in audit_policy_fields) and any(
            item is not None for item in audit_policy_fields
        ):
            raise ValueError("public model-request audit policy hashes are all-or-none")
        if any(item is not None for item in audit_policy_fields) and (
            self.terminal_status is not SchedulerTerminalStatus.SUCCEEDED
            or any(item is None for item in completion_fields)
        ):
            raise ValueError("public audit policy evidence requires successful model completion")
        if self.specialist_accepted_outcome_sha256 is not None and (
            self.terminal_status is not SchedulerTerminalStatus.SUCCEEDED
            or any(item is None for item in completion_fields)
        ):
            raise ValueError("public specialist outcome requires successful completion evidence")
        surface_fields = (
            self.model_surface_review_artifact_sha256,
            self.model_surface_review_request_manifest_sha256,
        )
        if (surface_fields[0] is None) != (surface_fields[1] is None):
            raise ValueError("public surface-review hashes are all-or-none")
        if (self.model_surface_review_request_count > 0) != all(
            item is not None for item in surface_fields
        ):
            raise ValueError("public surface-review count differs from its hash custody")
        if self.model_surface_review_request_count > 0 and self.terminal_status is not (
            SchedulerTerminalStatus.SUCCEEDED
        ):
            raise ValueError("public surface-review custody requires successful completion")
        if self.terminal_status is not SchedulerTerminalStatus.SUCCEEDED and (
            self.reviewed_source_descriptor_sha256s or self.reviewed_candidate_ids
        ):
            raise ValueError("non-success public request cannot claim substantive review")
        if self.schema_version == "1.0" and self.retrieval_custody is not None:
            raise ValueError("legacy public request cannot carry retrieval custody")
        if self.request_evidence_sha256 != _model_sha256(self, exclude={"request_evidence_sha256"}):
            raise ValueError("scheduler model-request evidence hash is inconsistent")
        return self


class SchedulerTruncationRecoveryModelRequestEvidence(StrictModel):
    """Public hash-only projection of one typed recovery child usage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1", "1.2", "1.3"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    provider_dispatch_authorized: Literal[False] = False
    review_credit_authorized: Literal[False] = False
    coverage_credit_authorized: Literal[False] = False
    completion_authorized: Literal[False] = False
    release_authorized: Literal[False] = False
    campaign_id: str = Field(pattern=r"^scheduler-campaign-[0-9a-f]{64}$")
    parent_task_id: str = Field(pattern=r"^scheduler-task-[0-9a-f]{64}$")
    promotion_entry_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    promotion_disposition: SchedulerTruncationRecoveryPromotionDisposition | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    global_request_ordinal: int | None = Field(
        default=None,
        ge=1,
        le=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
        exclude_if=lambda value: value is None,
    )
    recovery_family_id: str | None = Field(
        default=None,
        pattern=r"^scheduler-recovery-family-[0-9a-f]{64}$",
        exclude_if=lambda value: value is None,
    )
    family_root_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    recovery_plan_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    family_closure_id: str | None = Field(
        default=None,
        pattern=r"^scheduler-recovery-closure-[0-9a-f]{64}$",
        exclude_if=lambda value: value is None,
    )
    family_closure_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    child_task_id: str = Field(pattern=r"^scheduler-recovery-task-[0-9a-f]{64}$")
    logical_request_id: str = Field(pattern=r"^scheduler-recovery-request-[0-9a-f]{64}$")
    child_plan_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    child_result_entry_sha256: str = Field(pattern=_SHA256_PATTERN)
    activation_id: str = Field(pattern=r"^scheduler-recovery-activation-[0-9a-f]{64}$")
    activation_entry_sha256: str = Field(pattern=_SHA256_PATTERN)
    activation_status: Literal[SchedulerActivationStatus.ACTIVATED] = (
        SchedulerActivationStatus.ACTIVATED
    )
    dispatch_id: str | None = Field(
        default=None,
        pattern=r"^scheduler-recovery-dispatch-[0-9a-f]{64}$",
        exclude_if=lambda value: value is None,
    )
    dispatch_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    role: str = Field(pattern=_ROLE_PATTERN)
    requested_model: str = Field(pattern=_MODEL_ID_PATTERN)
    root_lineage: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    actual_input_sha256: str = Field(pattern=_SHA256_PATTERN)
    system_prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    user_prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider_prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    response_schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    delivered_source_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_limit_scope: str = Field(pattern=r"^scheduler-request-[0-9a-f]{64}$")
    request_limit_count_before: int = Field(ge=1, le=2**63 - 1)
    request_limit_count_after: int = Field(ge=1, le=2**63 - 1)
    request_limit_maximum: int = Field(ge=1, le=2**63 - 1)
    request_limit_reservation_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    terminal_status: Literal[
        SchedulerTerminalStatus.SUCCEEDED,
        SchedulerTerminalStatus.TRUNCATED,
        SchedulerTerminalStatus.FAILED,
    ]
    terminal_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    result_origin: SchedulerTruncationRecoveryResultOrigin | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    released_cost_entry_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    pre_send_release_reason: (
        Literal[
            "cancelled_before_send",
            "failed_before_send",
        ]
        | None
    ) = Field(default=None, exclude_if=lambda value: value is None)
    provider_attempt_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    accounted_provider_attempts: int | None = Field(
        default=None,
        ge=1,
        le=TRUNCATION_RECOVERY_MAX_CHILD_PROVIDER_ATTEMPTS,
        exclude_if=lambda value: value is None,
    )
    accounted_completion_tokens: int | None = Field(
        default=None,
        ge=0,
        le=TRUNCATION_RECOVERY_MAX_CHILD_COMPLETION_TOKENS,
        exclude_if=lambda value: value is None,
    )
    accounted_cost_usd_exact: str | None = Field(
        default=None,
        pattern=_USD_EXACT_PATTERN,
        exclude_if=lambda value: value is None,
    )
    cost_disposition: SchedulerTruncationRecoveryCostDisposition | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    runtime_completion_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    usage_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    context_request_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider_response_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    validated_response_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    normalization_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    output_artifact_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    specialist_accepted_outcome_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_policy_selection_binding_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_model_selection_bundle_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_selection_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_selected_model_set_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_scope_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_source_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    audit_selection_expires_at: datetime | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    audit_policy_routing_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    request_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        manifest: SchedulerCampaignManifest,
        parent_request: SchedulerModelRequestEvidence,
        parent_attempt: SchedulerProviderAttemptEvidence,
        family: SchedulerTruncationRecoveryFamilyRoot,
        promotion: SchedulerTruncationRecoveryFamilyPromotion | None,
        activation: SchedulerTruncationRecoveryChildActivation,
        result: SchedulerTruncationRecoveryChildResult,
        root_family: SchedulerTruncationRecoveryFamilyRoot | None = None,
        recovery_entries: tuple[SchedulerTruncationRecoveryEntry, ...],
    ) -> SchedulerTruncationRecoveryModelRequestEvidence:
        """Derive one projection without accepting caller-selected evidence coordinates."""

        exact_manifest = SchedulerCampaignManifest.model_validate(
            manifest.model_dump(mode="python")
        )
        exact_parent = SchedulerModelRequestEvidence.model_validate(
            parent_request.model_dump(mode="python")
        )
        exact_parent_attempt = SchedulerProviderAttemptEvidence.model_validate(
            parent_attempt.model_dump(mode="python")
        )
        exact_family = SchedulerTruncationRecoveryFamilyRoot.model_validate_json(
            family.model_dump_json(),
            strict=True,
        )
        exact_root_family = SchedulerTruncationRecoveryFamilyRoot.model_validate_json(
            (root_family if root_family is not None else family).model_dump_json(),
            strict=True,
        )
        exact_promotion = (
            SchedulerTruncationRecoveryFamilyPromotion.model_validate_json(
                promotion.model_dump_json(),
                strict=True,
            )
            if promotion is not None
            else None
        )
        exact_activation = SchedulerTruncationRecoveryChildActivation.model_validate_json(
            activation.model_dump_json(),
            strict=True,
        )
        exact_result = SchedulerTruncationRecoveryChildResult.model_validate_json(
            result.model_dump_json(),
            strict=True,
        )
        if type(recovery_entries) is not tuple:
            raise TypeError("recovery public request lifecycle inventory is invalid")
        exact_recovery_entries = validate_truncation_recovery_entry_chain(recovery_entries)
        chain_families = tuple(
            item
            for item in exact_recovery_entries
            if isinstance(item, SchedulerTruncationRecoveryFamilyRoot)
        )
        chain_activations = tuple(
            item
            for item in exact_recovery_entries
            if isinstance(item, SchedulerTruncationRecoveryChildActivation)
        )
        chain_dispatches = tuple(
            item
            for item in exact_recovery_entries
            if isinstance(item, SchedulerTruncationRecoveryChildDispatch)
        )
        chain_results = tuple(
            item
            for item in exact_recovery_entries
            if isinstance(item, SchedulerTruncationRecoveryChildResult)
        )
        chain_preflight_results = tuple(
            item
            for item in exact_recovery_entries
            if isinstance(item, SchedulerTruncationRecoveryChildPreflightResult)
        )
        chain_promotions = tuple(
            item
            for item in exact_recovery_entries
            if isinstance(item, SchedulerTruncationRecoveryFamilyPromotion)
        )
        chain_closures = tuple(
            item
            for item in exact_recovery_entries
            if isinstance(item, SchedulerTruncationRecoveryFamilyClosure)
        )
        exact_root_child_results = tuple(
            item for item in chain_results if item.family_id == exact_root_family.family_id
        )
        nested_family_keys = tuple(
            (item.parent_family_id, item.recovery_plan.parent.parent_task_id)
            for item in chain_families
            if item.parent_kind is SchedulerTruncationRecoveryParentKind.RECOVERY_CHILD
        )
        terminal_child_ids = tuple(item.child_task_id for item in chain_results) + tuple(
            item.child_task_id for item in chain_preflight_results
        )
        direct_parent_task_ids = tuple(
            item.recovery_plan.parent.parent_task_id
            for item in chain_families
            if item.parent_kind is SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK
        )
        closure_family_ids = tuple(item.family_id for item in chain_closures)
        chain_shape_is_unique = (
            len({item.family_id for item in chain_families}) == len(chain_families)
            and len({item.child_task_id for item in chain_activations}) == len(chain_activations)
            and len({item.child_task_id for item in chain_dispatches}) == len(chain_dispatches)
            and len(set(terminal_child_ids)) == len(terminal_child_ids)
            and len(set(nested_family_keys)) == len(nested_family_keys)
            and len(set(direct_parent_task_ids)) == len(direct_parent_task_ids)
            and len(set(closure_family_ids)) == len(closure_family_ids)
        )
        try:
            exact_parent_reservations = atomic_request_limit_reservations_from_usage(
                exact_parent_attempt.usage_record
            )
        except ValueError:
            raise ValueError(
                "recovery public request lacks exact parent request-limit evidence"
            ) from None
        root_parent_reservation = (
            exact_root_family.request_limit_binding.parent_request_limit_reservation
        )
        root_has_nested_family = any(
            item.parent_family_id == exact_root_family.family_id for item in chain_families
        )
        root_attempt_truncation_is_exact = (
            exact_parent_attempt.schema_version == "1.1"
            and exact_parent_attempt.truncation_projection
            == exact_root_family.truncation_projection
        ) or (
            not root_has_nested_family
            and exact_parent_attempt.schema_version == "1.0"
            and exact_parent_attempt.truncation_projection is None
        )
        expected_parent_reservation_request_id = (
            exact_parent_attempt.usage_record.request_id
            if exact_parent_attempt.usage_record.attempts == 1
            else (
                f"{exact_parent_attempt.usage_record.request_id}:attempt:"
                f"{exact_parent_attempt.usage_record.attempts}"
            )
        )
        root_parent_attempt_is_exact = (
            exact_root_family.request_limit_binding.manifest_sha256
            == exact_manifest.manifest_sha256
            and exact_root_family.request_limit_binding.campaign_id == exact_manifest.campaign_id
            and exact_parent.manifest_sha256 == exact_manifest.manifest_sha256
            and exact_parent.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
            and exact_parent.activation_status is SchedulerActivationStatus.ACTIVATED
            and exact_parent.terminal_status is SchedulerTerminalStatus.TRUNCATED
            and exact_root_family.request_limit_id == exact_parent.logical_request_id
            and exact_root_family.recovery_plan.parent.parent_task_id == exact_parent.task_id
            and exact_root_family.recovery_plan.parent.parent_logical_request_id
            == exact_parent.logical_request_id
            and exact_root_family.recovery_plan.parent.pass_plan_id == exact_parent.pass_plan_id
            and exact_root_family.recovery_plan.parent.parent_task_plan_sha256
            == exact_parent.task_plan_sha256
            and exact_root_family.recovery_plan.parent.parent_activation_sha256
            == exact_parent.activation_sha256
            and exact_root_family.parent_terminal_result_sha256 == exact_parent.result_sha256
            and exact_parent.terminal_evidence_sha256
            == exact_root_family.truncation_projection.evidence_sha256
            and bool(exact_parent_reservations)
            and exact_parent_reservations[-1] == root_parent_reservation
            and root_parent_reservation.request_id == expected_parent_reservation_request_id
            and root_parent_reservation.request_limit_scope == exact_parent.logical_request_id
            and root_parent_reservation.exact_model_id == exact_parent.requested_model
            and root_parent_reservation.role == exact_parent.role
            and root_attempt_truncation_is_exact
            and exact_parent_attempt.task_id == exact_parent.task_id
            and exact_parent_attempt.logical_request_id == exact_parent.logical_request_id
            and exact_parent_attempt.activation_sha256 == exact_parent.activation_sha256
            and exact_parent_attempt.attempt_evidence_sha256
            == exact_root_family.recovery_plan.parent.provider_attempt_evidence_sha256
            and exact_parent_attempt.delivered_source_descriptor_sha256s
            == exact_parent.delivered_source_descriptor_sha256s
            and exact_parent_attempt.response_schema_sha256 == exact_parent.response_schema_sha256
            and exact_parent_attempt.usage_record.request_id == exact_parent.logical_request_id
            and exact_parent_attempt.usage_record.role == exact_parent.role
            and exact_parent_attempt.usage_record.requested_model == exact_parent.requested_model
            and exact_parent_attempt.usage_record.validation_status
            is ModelRequestValidationStatus.TRUNCATED
            and exact_parent_attempt.usage_record.status == "rejected_truncated_response"
            and exact_parent_attempt.usage_record.validated_response_sha256 is None
            and exact_parent_attempt.usage_record.response_sha256
            == exact_root_family.truncation_projection.original_response_sha256
            and exact_parent_attempt.usage_record.schema_sha256
            == exact_root_family.truncation_projection.wire_schema_sha256
        )
        usage = exact_result.runtime_usage_record
        reservation = exact_result.runtime_request_limit_reservation
        normalization = exact_result.runtime_normalization_evidence
        output_artifact = exact_result.runtime_output_artifact
        succeeded = (
            exact_result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
        )
        specialist_outcome = exact_result.runtime_specialist_accepted_outcome
        specialist_outcome_sha256 = exact_result.runtime_specialist_accepted_outcome_sha256
        requires_specialist_outcome = (
            succeeded and exact_parent.role in _SPECIALIST_INVESTIGATOR_REQUEST_ROLES
        )
        released_pre_send = exact_result.schema_version == "1.3"
        recursive_promotion = (
            exact_promotion is not None and exact_promotion.schema_version == "1.1"
        )
        promotion_disposition = (
            SchedulerTruncationRecoveryPromotionDisposition.SUPERSEDED_TRUNCATED_BRIDGE
            if recursive_promotion
            and exact_promotion is not None
            and exact_result.entry_sha256 == exact_promotion.superseded_bridge_result_sha256
            else SchedulerTruncationRecoveryPromotionDisposition.SUCCESSFUL_LEAF
            if recursive_promotion
            and exact_promotion is not None
            and exact_promotion.promoted_leaf_result_sha256s is not None
            and exact_result.entry_sha256 in exact_promotion.promoted_leaf_result_sha256s
            else None
        )
        if released_pre_send and (
            exact_result.result_origin is not SchedulerTruncationRecoveryResultOrigin.RUNTIME
            or exact_result.terminal_status is not SchedulerTruncationRecoveryTerminalStatus.FAILED
            or exact_result.runtime_activation != exact_activation
            or exact_result.activation_sha256 != exact_activation.entry_sha256
            or usage is None
            or reservation is None
            or exact_result.runtime_usage_record_sha256 is None
            or exact_result.provider_attempt_evidence_sha256 is None
            or exact_result.released_cost_entry_sha256 != exact_result.terminal_evidence_sha256
            or exact_result.pre_send_release_reason
            not in {"cancelled_before_send", "failed_before_send"}
            or exact_result.cost_disposition
            is not SchedulerTruncationRecoveryCostDisposition.RELEASED_PRE_SEND_TAIL
            or exact_result.accounted_provider_attempts != usage.attempts
            or normalization is not None
            or output_artifact is not None
            or exact_result.runtime_completion_evidence_sha256 is not None
            or exact_result.runtime_output_artifact_sha256 is not None
            or exact_result.runtime_specialist_accepted_outcome is not None
            or exact_result.runtime_specialist_accepted_outcome_sha256 is not None
            or exact_result.truncation_projection is not None
            or exact_result.completed_surface_ids
            or exact_result.retained_surface_ids
            or exact_promotion is not None
        ):
            raise ValueError("released recovery public request lacks one exact failed usage")
        if not released_pre_send and (
            exact_result.schema_version != ("1.2" if requires_specialist_outcome else "1.1")
            or exact_result.terminal_status
            not in {
                SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED,
                SchedulerTruncationRecoveryTerminalStatus.TRUNCATED,
            }
            or exact_result.runtime_activation != exact_activation
            or exact_result.activation_sha256 != exact_activation.entry_sha256
            or usage is None
            or reservation is None
            or exact_result.runtime_usage_record_sha256 is None
            or succeeded
            != (
                normalization is not None
                and output_artifact is not None
                and exact_result.runtime_completion_evidence_sha256 is not None
                and exact_result.runtime_output_artifact_sha256 is not None
                and usage.validated_response_sha256 is not None
            )
            or (
                exact_promotion is not None
                and (
                    (not recursive_promotion and not succeeded)
                    or (
                        recursive_promotion
                        and (
                            promotion_disposition is None
                            or (
                                promotion_disposition
                                is SchedulerTruncationRecoveryPromotionDisposition.SUCCESSFUL_LEAF
                            )
                            != succeeded
                        )
                    )
                )
            )
            or requires_specialist_outcome
            != (
                specialist_outcome is not None
                and specialist_outcome_sha256 == specialist_outcome.evidence_sha256
            )
            or (
                not requires_specialist_outcome
                and (specialist_outcome is not None or specialist_outcome_sha256 is not None)
            )
            or (
                exact_promotion is not None
                and (
                    exact_result.entry_sha256
                    not in (
                        exact_promotion.direct_child_result_sha256s
                        if exact_promotion.schema_version == "1.0"
                        else (
                            exact_promotion.superseded_bridge_result_sha256,
                            *(exact_promotion.promoted_leaf_result_sha256s or ()),
                        )
                    )
                )
            )
        ):
            raise ValueError("recovery public request lacks one typed runtime usage")
        assert usage is not None
        assert reservation is not None
        binding = (
            SchedulerTruncationRecoveryPromotionBinding.from_promotion(exact_promotion)
            if exact_promotion is not None
            else None
        )
        expected_source_inventory_sha256 = scheduler_canonical_sha256(
            {
                "domain": "mmaudit.scheduler.recovery-delivered-source-inventory.v1",
                "source_descriptor_sha256s": (exact_parent.delivered_source_descriptor_sha256s),
            }
        )

        def chain_lifecycle_matches(
            *,
            family_item: SchedulerTruncationRecoveryFamilyRoot,
            child: TruncationRecoveryChildPlan,
            result_item: SchedulerTruncationRecoveryChildResult,
        ) -> bool:
            preceding_reserved_attempts = sum(
                item.reserved_provider_attempts
                for item in family_item.recovery_plan.children
                if item.ordinal < child.ordinal
            )
            expected_request_limit_count_before = (
                family_item.request_limit_count_before_family + preceding_reserved_attempts
            )
            activation_matches = tuple(
                item
                for item in chain_activations
                if item.entry_sha256 == result_item.activation_sha256
                and item == result_item.runtime_activation
                and item.family_index == family_item.family_index
                and item.family_id == family_item.family_id
                and item.family_root_sha256 == family_item.entry_sha256
                and item.child_ordinal == child.ordinal
                and item.child_task_id == child.child_task_id
                and item.child_logical_request_id == child.child_logical_request_id
                and item.child_plan_sha256 == child.child_plan_sha256
                and item.child_surface_ids == child.surface_ids
                and item.global_request_ordinal
                == family_item.request_count_before_family + child.ordinal + 1
                and item.request_limit_count_before_child == expected_request_limit_count_before
                and item.request_limit_count_after_child
                == expected_request_limit_count_before + child.reserved_provider_attempts
                and item.request_limit_maximum
                == family_item.request_limit_binding.request_limit_maximum
                and item.request_limit_id == family_item.request_limit_id
                and item.request_limit_binding_sha256 == family_item.request_limit_binding_sha256
                and item.request_role
                == family_item.request_limit_binding.parent_request_limit_reservation.role
                and item.requested_model
                == family_item.request_limit_binding.parent_request_limit_reservation.exact_model_id
            )
            if len(activation_matches) != 1:
                return False
            activation_item = activation_matches[0]
            activation_dispatches = tuple(
                item
                for item in chain_dispatches
                if item.activation_id == activation_item.activation_id
                and item.activation_sha256 == activation_item.entry_sha256
                and item.child_task_id == child.child_task_id
            )
            dispatch_matches = tuple(
                item
                for item in activation_dispatches
                if item.entry_sha256 == result_item.dispatch_sha256
                and item.dispatch_id == result_item.dispatch_id
                and item.family_id == family_item.family_id
                and item.family_root_sha256 == family_item.entry_sha256
                and item.child_logical_request_id == child.child_logical_request_id
                and item.child_plan_sha256 == child.child_plan_sha256
                and item.global_request_ordinal == activation_item.global_request_ordinal
                and item.request_limit_id == activation_item.request_limit_id
                and item.request_limit_binding_sha256
                == activation_item.request_limit_binding_sha256
                and item.request_limit_count_before_child
                == activation_item.request_limit_count_before_child
                and item.request_limit_count_after_child
                == activation_item.request_limit_count_after_child
                and item.request_limit_maximum == activation_item.request_limit_maximum
            )
            dispatchless_release = (
                result_item.schema_version == "1.3"
                and result_item.dispatch_id is None
                and result_item.dispatch_sha256 is None
                and not activation_dispatches
            )
            dispatched_lifecycle_is_exact = (
                len(activation_dispatches) == 1
                and len(dispatch_matches) == 1
                and activation_item.entry_index
                < dispatch_matches[0].entry_index
                < result_item.entry_index
            )
            return (
                (dispatchless_release or dispatched_lifecycle_is_exact)
                and family_item.entry_index < activation_item.entry_index < result_item.entry_index
                and result_item.family_id == family_item.family_id
                and result_item.family_root_sha256 == family_item.entry_sha256
                and result_item.child_task_id == child.child_task_id
                and result_item.child_logical_request_id == child.child_logical_request_id
                and result_item.child_plan_sha256 == child.child_plan_sha256
                and result_item.child_surface_ids == child.surface_ids
                and result_item.global_request_ordinal == activation_item.global_request_ordinal
            )

        expected_global_request_count = 0
        expected_scope_counts: dict[str, int] = {}
        scope_bindings: dict[str, SchedulerTruncationRecoveryRequestLimitBinding] = {}
        family_sequence_is_exact = True
        for expected_family_index, family_item in enumerate(chain_families):
            prior_binding = scope_bindings.setdefault(
                family_item.request_limit_id,
                family_item.request_limit_binding,
            )
            expected_scope_count = expected_scope_counts.setdefault(
                family_item.request_limit_id,
                (
                    family_item.request_limit_binding.parent_request_limit_reservation.request_limit_count_after
                ),
            )
            if (
                family_item.family_index != expected_family_index
                or family_item.request_count_before_family != expected_global_request_count
                or family_item.request_count_after_family
                != expected_global_request_count + len(family_item.recovery_plan.children)
                or family_item.request_limit_binding != prior_binding
                or family_item.request_limit_count_before_family != expected_scope_count
                or family_item.request_limit_count_after_family
                != expected_scope_count + family_item.request_limit_attempts_reserved_for_family
            ):
                family_sequence_is_exact = False
            expected_global_request_count += len(family_item.recovery_plan.children)
            expected_scope_counts[family_item.request_limit_id] = (
                expected_scope_count + family_item.request_limit_attempts_reserved_for_family
            )

        family_by_id = {item.family_id: item for item in chain_families}
        closure_by_family_id = {item.family_id: item for item in chain_closures}
        terminal_by_child_id: dict[
            str,
            SchedulerTruncationRecoveryChildResult
            | SchedulerTruncationRecoveryChildPreflightResult,
        ] = {}
        for result_entry in chain_results:
            terminal_by_child_id[result_entry.child_task_id] = result_entry
        for preflight_entry in chain_preflight_results:
            terminal_by_child_id[preflight_entry.child_task_id] = preflight_entry
        closure_sequence_is_exact = True
        for closure_item in chain_closures:
            closed_family = family_by_id.get(closure_item.family_id)
            ordered_terminals = (
                tuple(
                    terminal_by_child_id[child.child_task_id]
                    for child in closed_family.recovery_plan.children
                )
                if closed_family is not None
                and all(
                    child.child_task_id in terminal_by_child_id
                    for child in closed_family.recovery_plan.children
                )
                else ()
            )
            nested_families = tuple(
                item for item in chain_families if item.parent_family_id == closure_item.family_id
            )
            nested_closures = tuple(
                closure_by_family_id.get(item.family_id) for item in nested_families
            )
            expected_covered: set[str] = set()
            expected_nested_closure_sha256s: list[str] = []
            all_branches_have_typed_coverage = True
            closure_is_uncertain = False
            for child, terminal_item in zip(
                closed_family.recovery_plan.children if closed_family is not None else (),
                ordered_terminals,
                strict=True,
            ):
                child_nested_families = tuple(
                    item
                    for item in nested_families
                    if item.recovery_plan.parent.parent_task_id == child.child_task_id
                )
                if (
                    isinstance(terminal_item, SchedulerTruncationRecoveryChildResult)
                    and terminal_item.schema_version in {"1.1", "1.2"}
                    and terminal_item.result_origin
                    is SchedulerTruncationRecoveryResultOrigin.RUNTIME
                    and terminal_item.terminal_status
                    is SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
                    and terminal_item.completed_surface_ids == child.surface_ids
                    and not child_nested_families
                ):
                    expected_covered.update(terminal_item.completed_surface_ids)
                    continue
                if (
                    isinstance(terminal_item, SchedulerTruncationRecoveryChildResult)
                    and terminal_item.schema_version == "1.1"
                    and terminal_item.result_origin
                    is SchedulerTruncationRecoveryResultOrigin.RUNTIME
                    and terminal_item.terminal_status
                    is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED
                    and closed_family is not None
                    and closed_family.parent_kind
                    is SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK
                    and not terminal_item.retained_surface_ids
                    and len(child_nested_families) == 1
                ):
                    nested_closure = closure_by_family_id.get(child_nested_families[0].family_id)
                    if (
                        nested_closure is not None
                        and nested_closure.schema_version == "1.1"
                        and nested_closure.closure_status
                        is SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
                        and nested_closure.covered_unfinished_surface_ids == child.surface_ids
                    ):
                        expected_covered.update(nested_closure.covered_unfinished_surface_ids)
                        expected_nested_closure_sha256s.append(nested_closure.entry_sha256)
                        continue
                all_branches_have_typed_coverage = False
                if (
                    terminal_item.terminal_status
                    is SchedulerTruncationRecoveryTerminalStatus.UNCERTAIN
                ):
                    closure_is_uncertain = True
            expected_unfinished_surfaces = (
                set(closed_family.recovery_plan.parent.unfinished_surface_ids)
                if closed_family is not None
                else set()
            )
            exact_typed_coverage = (
                all_branches_have_typed_coverage
                and expected_covered == expected_unfinished_surfaces
                and len(expected_nested_closure_sha256s) == len(nested_families)
            )
            expected_closure_status = (
                SchedulerTruncationRecoveryClosureStatus.UNCERTAIN
                if closure_is_uncertain
                else (
                    SchedulerTruncationRecoveryClosureStatus.RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING
                    if expected_nested_closure_sha256s
                    else SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
                )
                if exact_typed_coverage
                else SchedulerTruncationRecoveryClosureStatus.INCOMPLETE
            )
            expected_closure_schema = (
                "1.2"
                if expected_closure_status
                is SchedulerTruncationRecoveryClosureStatus.RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING
                else "1.1"
                if expected_closure_status
                is SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
                else "1.0"
            )
            if (
                closed_family is None
                or closure_item.schema_version != expected_closure_schema
                or closure_item.campaign_id != closed_family.campaign_id
                or closure_item.request_limit_id != closed_family.request_limit_id
                or closure_item.request_limit_binding_sha256
                != closed_family.request_limit_binding_sha256
                or closure_item.family_index != closed_family.family_index
                or closure_item.family_root_sha256 != closed_family.entry_sha256
                or closure_item.recovery_plan_sha256 != closed_family.recovery_plan.plan_sha256
                or closure_item.closure_status is not expected_closure_status
                or closure_item.covered_unfinished_surface_ids != tuple(sorted(expected_covered))
                or len(ordered_terminals) != len(closed_family.recovery_plan.children)
                or closure_item.child_result_sha256s
                != tuple(item.entry_sha256 for item in ordered_terminals)
                or not all(
                    closed_family.entry_index < item.entry_index < closure_item.entry_index
                    for item in ordered_terminals
                )
                or any(item is None for item in nested_closures)
                or closure_item.nested_family_closure_sha256s
                != tuple(expected_nested_closure_sha256s)
                or any(
                    item is None or item.entry_index >= closure_item.entry_index
                    for item in nested_closures
                )
            ):
                closure_sequence_is_exact = False
        for current_family in chain_families:
            family_closure = closure_by_family_id.get(current_family.family_id)
            parent_closure = (
                closure_by_family_id.get(current_family.parent_family_id)
                if current_family.parent_family_id is not None
                else None
            )
            family_lifecycle_indexes = (
                tuple(
                    item.entry_index
                    for item in chain_activations
                    if item.family_id == current_family.family_id
                )
                + tuple(
                    item.entry_index
                    for item in chain_dispatches
                    if item.family_id == current_family.family_id
                )
                + tuple(
                    item.entry_index
                    for item in chain_results
                    if item.family_id == current_family.family_id
                )
                + tuple(
                    item.entry_index
                    for item in chain_preflight_results
                    if item.family_id == current_family.family_id
                )
            )
            if (
                family_closure is not None
                and any(index >= family_closure.entry_index for index in family_lifecycle_indexes)
            ) or (
                parent_closure is not None
                and current_family.entry_index >= parent_closure.entry_index
            ):
                closure_sequence_is_exact = False
        for promotion_item in chain_promotions:
            promotion_closure = closure_by_family_id.get(promotion_item.family_id)
            if (
                promotion_closure is None
                or promotion_item.entry_index <= promotion_closure.entry_index
            ):
                closure_sequence_is_exact = False

        direct_family = (
            exact_family.parent_kind is SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK
            and exact_family == exact_root_family
            and exact_family.parent_family_id is None
            and exact_family.recovery_plan.parent.parent_task_id == exact_parent.task_id
            and exact_family.parent_terminal_result_sha256 == exact_parent.result_sha256
        )
        projected_children = tuple(
            child
            for child in exact_family.recovery_plan.children
            if child.child_task_id == exact_result.child_task_id
            and child.child_logical_request_id == exact_result.child_logical_request_id
            and child.child_plan_sha256 == exact_result.child_plan_sha256
            and child.surface_ids == exact_result.child_surface_ids
            and child.ordinal == exact_activation.child_ordinal
        )
        root_results_by_child = tuple(
            (
                child,
                tuple(
                    item
                    for item in exact_root_child_results
                    if item.family_id == exact_root_family.family_id
                    and item.family_root_sha256 == exact_root_family.entry_sha256
                    and item.child_task_id == child.child_task_id
                    and item.child_logical_request_id == child.child_logical_request_id
                    and item.child_plan_sha256 == child.child_plan_sha256
                    and item.child_surface_ids == child.surface_ids
                    and item.runtime_activation is not None
                    and item.runtime_activation.child_task_id == child.child_task_id
                    and item.runtime_activation.child_logical_request_id
                    == child.child_logical_request_id
                    and item.runtime_activation.child_plan_sha256 == child.child_plan_sha256
                    and item.runtime_activation.child_surface_ids == child.surface_ids
                    and item.runtime_activation.family_id == exact_root_family.family_id
                    and item.runtime_activation.family_root_sha256 == exact_root_family.entry_sha256
                    and item.runtime_activation.request_role == exact_parent.role
                    and item.runtime_activation.requested_model == exact_parent.requested_model
                    and chain_lifecycle_matches(
                        family_item=exact_root_family,
                        child=child,
                        result_item=item,
                    )
                ),
            )
            for child in exact_root_family.recovery_plan.children
        )
        exact_root_result_partition = (
            len(exact_root_family.recovery_plan.children) == 2
            and len(exact_root_child_results) == 2
            and len({item.entry_sha256 for item in exact_root_child_results}) == 2
            and all(len(matches) == 1 for _child, matches in root_results_by_child)
        )
        truncated_root_branches = tuple(
            (child, matches[0])
            for child, matches in root_results_by_child
            if len(matches) == 1
            and matches[0].schema_version == "1.1"
            and matches[0].result_origin is SchedulerTruncationRecoveryResultOrigin.RUNTIME
            and matches[0].terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED
            and matches[0].truncation_projection is not None
            and matches[0].truncation_projection.findings_state
            is CandidateReviewChannelState.COMPLETE
            and not matches[0].retained_surface_ids
            and not matches[0].truncation_projection.surface_reviews
            and matches[0].runtime_specialist_accepted_outcome is None
            and matches[0].runtime_specialist_accepted_outcome_sha256 is None
        )
        successful_root_branches = tuple(
            (child, matches[0])
            for child, matches in root_results_by_child
            if len(matches) == 1
            and matches[0].schema_version == "1.1"
            and matches[0].result_origin is SchedulerTruncationRecoveryResultOrigin.RUNTIME
            and matches[0].terminal_status is SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
            and matches[0].completed_surface_ids == child.surface_ids
            and matches[0].runtime_specialist_accepted_outcome is None
            and matches[0].runtime_specialist_accepted_outcome_sha256 is None
        )
        truncated_root_projection = (
            truncated_root_branches[0][1].truncation_projection
            if len(truncated_root_branches) == 1
            else None
        )
        ordered_root_results = (
            tuple(matches[0] for _child, matches in root_results_by_child)
            if exact_root_result_partition
            else ()
        )
        root_closure = closure_by_family_id.get(exact_root_family.family_id)
        root_nested_families = tuple(
            item for item in chain_families if item.parent_family_id == exact_root_family.family_id
        )
        recursive_nested_family = (
            root_nested_families[0] if len(root_nested_families) == 1 else None
        )
        recursive_nested_closure = (
            closure_by_family_id.get(recursive_nested_family.family_id)
            if recursive_nested_family is not None
            else None
        )
        nested_results_by_child = (
            tuple(
                (
                    child,
                    tuple(
                        item
                        for item in chain_results
                        if item.family_id == recursive_nested_family.family_id
                        and item.family_root_sha256 == recursive_nested_family.entry_sha256
                        and item.child_task_id == child.child_task_id
                        and item.child_logical_request_id == child.child_logical_request_id
                        and item.child_plan_sha256 == child.child_plan_sha256
                        and item.child_surface_ids == child.surface_ids
                        and chain_lifecycle_matches(
                            family_item=recursive_nested_family,
                            child=child,
                            result_item=item,
                        )
                    ),
                )
                for child in recursive_nested_family.recovery_plan.children
            )
            if recursive_nested_family is not None
            else ()
        )
        exact_nested_result_partition = (
            recursive_nested_family is not None
            and len(recursive_nested_family.recovery_plan.children) == 2
            and all(len(matches) == 1 for _child, matches in nested_results_by_child)
            and len(
                {
                    matches[0].entry_sha256
                    for _child, matches in nested_results_by_child
                    if len(matches) == 1
                }
            )
            == 2
        )
        ordered_nested_results = (
            tuple(matches[0] for _child, matches in nested_results_by_child)
            if exact_nested_result_partition
            else ()
        )
        successful_direct_result = (
            successful_root_branches[0][1] if len(successful_root_branches) == 1 else None
        )
        truncated_bridge_result = (
            truncated_root_branches[0][1] if len(truncated_root_branches) == 1 else None
        )
        promoted_leaf_results = (
            (successful_direct_result, *ordered_nested_results)
            if successful_direct_result is not None and len(ordered_nested_results) == 2
            else ()
        )
        promoted_leaf_ordinals = tuple(
            item.global_request_ordinal for item in promoted_leaf_results
        )
        recursive_output_bridge_is_exact = True
        if exact_promotion is not None and exact_promotion.schema_version == "1.1":
            recursive_output_bridge_is_exact = False
            bridge_usage = (
                truncated_bridge_result.runtime_usage_record
                if truncated_bridge_result is not None
                else None
            )
            bridge_projection = (
                truncated_bridge_result.truncation_projection
                if truncated_bridge_result is not None
                else None
            )
            scanner_items = exact_promotion.recovered_output.scanner_fingerprints_by_request
            scanner_projection = dict(scanner_items)
            tree_results = (*ordered_root_results, *ordered_nested_results)
            tree_usages = tuple(item.runtime_usage_record for item in tree_results)
            expected_scanner_request_ids = {exact_parent_attempt.usage_record.request_id} | {
                usage_item.request_id for usage_item in tree_usages if usage_item is not None
            }
            bridge_origins = tuple(
                origin
                for origin in exact_promotion.recovered_output.candidate_origins
                if origin.origin_kind is SchedulerRecoveredCandidateOriginKind.TRUNCATED_CHILD_FRAME
            )
            if (
                truncated_bridge_result is not None
                and bridge_usage is not None
                and bridge_projection is not None
                and truncated_bridge_result.runtime_usage_record_sha256 is not None
                and len(scanner_projection) == len(scanner_items)
                and set(scanner_projection) == expected_scanner_request_ids
                and len(tree_usages) == 4
                and all(usage_item is not None for usage_item in tree_usages)
                and len(bridge_origins) == len(bridge_projection.findings)
            ):
                raw_findings = tuple(bridge_projection.findings)
                context_sha256 = bridge_usage.routing.get("context_request_evidence_sha256")
                try:
                    stamped_findings = stamp_candidate_review_findings(
                        request_role=bridge_usage.role,
                        usage_record=bridge_usage,
                        trusted_scanner_fingerprints=scanner_projection[bridge_usage.request_id],
                        raw_findings=raw_findings,
                    )
                except (CandidateReviewStampingError, KeyError):
                    stamped_findings = ()
                stamped_pairs = (
                    tuple(zip(raw_findings, stamped_findings, strict=True))
                    if len(stamped_findings) == len(raw_findings)
                    else ()
                )
                exact_origin_count = 0
                for raw_finding, stamped_finding in stamped_pairs:
                    raw_sha256 = scheduler_candidate_payload_sha256(
                        raw_finding,
                        algorithm_version=exact_manifest.algorithm_version,
                    )
                    stamped_sha256 = scheduler_candidate_payload_sha256(
                        stamped_finding,
                        algorithm_version=exact_manifest.algorithm_version,
                    )
                    frames = tuple(
                        frame
                        for frame in bridge_projection.accepted_frames
                        if frame.phase is CandidateReviewFramePhase.FINDING
                        and frame.record_id == raw_finding.candidate_id
                        and frame.normalized_value_sha256 == raw_sha256
                    )
                    origins = tuple(
                        origin
                        for origin in bridge_origins
                        if origin.raw_candidate_id == raw_finding.candidate_id
                    )
                    if (
                        len(frames) == 1
                        and len(origins) == 1
                        and isinstance(context_sha256, str)
                        and origins[0].accepted_candidate_id == stamped_finding.candidate_id
                        and origins[0].accepted_candidate_sha256 == stamped_sha256
                        and origins[0].raw_candidate_sha256 == raw_sha256
                        and origins[0].request_id == bridge_usage.request_id
                        and origins[0].request_role == bridge_usage.role
                        and origins[0].usage_record_sha256
                        == truncated_bridge_result.runtime_usage_record_sha256
                        and origins[0].context_request_evidence_sha256 == context_sha256
                        and origins[0].truncation_projection_sha256
                        == bridge_projection.evidence_sha256
                        and origins[0].accepted_frame_sequence == frames[0].sequence
                        and origins[0].accepted_frame_sha256 == frames[0].frame_sha256
                        and origins[0].child_task_id == truncated_bridge_result.child_task_id
                        and origins[0].child_result_sha256 == truncated_bridge_result.entry_sha256
                    ):
                        exact_origin_count += 1
                recursive_output_bridge_is_exact = len(stamped_findings) == len(
                    raw_findings
                ) and exact_origin_count == len(raw_findings)
        recursive_promotion_tree_is_exact = (
            True
            if exact_promotion is None
            else (
                exact_promotion.family_id == exact_root_family.family_id
                and exact_promotion.family_root_sha256 == exact_root_family.entry_sha256
                and exact_promotion.recovery_plan_sha256
                == exact_root_family.recovery_plan.plan_sha256
                and root_closure is not None
                and exact_promotion.family_closure_id == root_closure.closure_id
                and exact_promotion.family_closure_sha256 == root_closure.entry_sha256
                and exact_promotion.direct_child_result_sha256s
                == tuple(item.entry_sha256 for item in ordered_root_results)
                and (
                    (
                        exact_promotion.schema_version == "1.0"
                        and not root_nested_families
                        and root_closure.schema_version == "1.1"
                        and root_closure.closure_status
                        is SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
                    )
                    or (
                        exact_promotion.schema_version == "1.1"
                        and recursive_nested_family is not None
                        and recursive_nested_closure is not None
                        and root_closure.schema_version == "1.2"
                        and root_closure.closure_status
                        is SchedulerTruncationRecoveryClosureStatus.RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING
                        and root_closure.nested_family_closure_sha256s
                        == (recursive_nested_closure.entry_sha256,)
                        and recursive_nested_closure.schema_version == "1.1"
                        and recursive_nested_closure.closure_status
                        is SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
                        and exact_promotion.nested_family_id == recursive_nested_family.family_id
                        and exact_promotion.nested_family_root_sha256
                        == recursive_nested_family.entry_sha256
                        and exact_promotion.nested_recovery_plan_sha256
                        == recursive_nested_family.recovery_plan.plan_sha256
                        and exact_promotion.nested_family_closure_id
                        == recursive_nested_closure.closure_id
                        and exact_promotion.nested_family_closure_sha256
                        == recursive_nested_closure.entry_sha256
                        and exact_promotion.nested_child_result_sha256s
                        == tuple(item.entry_sha256 for item in ordered_nested_results)
                        and truncated_bridge_result is not None
                        and exact_promotion.superseded_bridge_result_sha256
                        == truncated_bridge_result.entry_sha256
                        and exact_promotion.promoted_leaf_result_sha256s
                        == tuple(item.entry_sha256 for item in promoted_leaf_results)
                        and len(promoted_leaf_ordinals) == 3
                        and promoted_leaf_ordinals == tuple(sorted(promoted_leaf_ordinals))
                        and recursive_output_bridge_is_exact
                        and all(
                            item.terminal_status
                            is SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
                            for item in ordered_nested_results
                        )
                    )
                )
            )
        )
        nested_parent = exact_family.recovery_plan.parent
        family_membership_is_exact = (
            sum(item == exact_family for item in chain_families) == 1
            and sum(item == exact_root_family for item in chain_families) == 1
        )
        projected_lifecycle_is_exact = (
            len(projected_children) == 1
            and sum(item == exact_result for item in chain_results) == 1
            and chain_lifecycle_matches(
                family_item=exact_family,
                child=projected_children[0],
                result_item=exact_result,
            )
        )
        result_promotions = tuple(
            item
            for item in chain_promotions
            if exact_result.entry_sha256
            in (
                item.direct_child_result_sha256s
                if item.schema_version == "1.0"
                else (
                    item.superseded_bridge_result_sha256,
                    *(item.promoted_leaf_result_sha256s or ()),
                )
            )
        )
        promotion_membership_is_exact = (
            result_promotions == ()
            if exact_promotion is None
            else result_promotions == (exact_promotion,)
        )
        nested_family = (
            exact_family.parent_kind is SchedulerTruncationRecoveryParentKind.RECOVERY_CHILD
            and exact_family.parent_family_id == exact_root_family.family_id
            and exact_root_family.parent_kind
            is SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK
            and exact_root_family.parent_family_id is None
            and exact_root_family.recovery_plan.parent.parent_task_id == exact_parent.task_id
            and exact_root_family.parent_terminal_result_sha256 == exact_parent.result_sha256
            and exact_family.request_limit_binding == exact_root_family.request_limit_binding
            and exact_family.requested_surface_manifest
            == exact_root_family.requested_surface_manifest
            and exact_root_result_partition
            and len(truncated_root_branches) == 1
            and len(successful_root_branches) == 1
            and truncated_root_projection is not None
            and nested_parent.parent_task_id == truncated_root_branches[0][0].child_task_id
            and nested_parent.parent_logical_request_id
            == truncated_root_branches[0][0].child_logical_request_id
            and nested_parent.pass_plan_id == truncated_root_branches[0][0].pass_plan_id
            and nested_parent.parent_task_plan_sha256
            == truncated_root_branches[0][0].child_plan_sha256
            and nested_parent.parent_activation_sha256
            == truncated_root_branches[0][1].activation_sha256
            and nested_parent.provider_attempt_evidence_sha256
            == truncated_root_branches[0][1].provider_attempt_evidence_sha256
            and nested_parent.truncation_projection_sha256
            == truncated_root_projection.evidence_sha256
            and nested_parent.requested_surface_ids == truncated_root_branches[0][0].surface_ids
            and nested_parent.unfinished_surface_ids == truncated_root_branches[0][0].surface_ids
            and nested_parent.current_depth == truncated_root_branches[0][0].depth == 1
            and nested_parent.parent_path == truncated_root_branches[0][0].path
            and exact_family.parent_terminal_result_sha256
            == truncated_root_branches[0][1].entry_sha256
            and exact_family.entry_index
            > max(item.entry_index for item in exact_root_child_results)
            and exact_family.request_count_before_family
            == exact_root_family.request_count_after_family
            and exact_family.request_limit_count_before_family
            == exact_root_family.request_limit_count_after_family
            and all(child.depth == 2 for child in exact_family.recovery_plan.children)
            and exact_parent.role not in _SPECIALIST_INVESTIGATOR_REQUEST_ROLES
            and (
                exact_promotion is None
                or (exact_promotion.schema_version == "1.1" and recursive_promotion_tree_is_exact)
            )
        )
        if (
            exact_manifest.campaign_id != exact_parent.campaign_id
            or not chain_shape_is_unique
            or not root_parent_attempt_is_exact
            or not family_sequence_is_exact
            or not closure_sequence_is_exact
            or exact_family.campaign_id != exact_manifest.campaign_id
            or not family_membership_is_exact
            or not projected_lifecycle_is_exact
            or not promotion_membership_is_exact
            or not recursive_promotion_tree_is_exact
            or not (direct_family or nested_family)
            or exact_result.family_id != exact_family.family_id
            or exact_result.family_root_sha256 != exact_family.entry_sha256
            or exact_parent.terminal_status is not SchedulerTerminalStatus.TRUNCATED
            or exact_parent.response_schema_sha256
            != candidate_review_frame_wire_schema_sha256(
                algorithm_version=exact_manifest.algorithm_version,
            )
            or exact_activation.campaign_id != exact_manifest.campaign_id
            or exact_activation.child_task_id != exact_result.child_task_id
            or exact_activation.child_logical_request_id != exact_result.child_logical_request_id
            or exact_activation.request_role != exact_parent.role
            or exact_activation.requested_model != exact_parent.requested_model
            or exact_activation.response_schema_sha256 != exact_parent.response_schema_sha256
            or exact_activation.family_id != exact_family.family_id
            or exact_activation.family_root_sha256 != exact_family.entry_sha256
            or exact_activation.request_limit_id != exact_parent.logical_request_id
            or (
                exact_promotion is not None
                and (
                    exact_promotion.campaign_id != exact_manifest.campaign_id
                    or exact_promotion.parent_task_id != exact_parent.task_id
                    or exact_parent.result_sha256
                    != exact_promotion.original_truncated_result_sha256
                    or binding is None
                    or binding.delivered_source_inventory_sha256 != expected_source_inventory_sha256
                )
            )
        ):
            raise ValueError("recovery public request differs from its typed family parent")
        _reject_sensitive_usage_material(usage.model_dump(mode="json"))
        raw_context = usage.routing.get("context_request_evidence")
        if not isinstance(raw_context, dict):
            raise ValueError("recovery public request lacks typed context evidence")
        context = ContextRequestEvidence.model_validate(raw_context)
        routed_lineage = usage.routing.get("qualified_root_lineage")
        if (
            context.request_id != exact_activation.child_logical_request_id
            or context.request_role != exact_activation.request_role
            or context.rendered_sha256 != exact_activation.user_prompt_sha256
            or usage.routing.get("context_request_evidence_sha256") != context.evidence_sha256
            or (not released_pre_send and usage.response_sha256 is None)
            or (routed_lineage is not None and routed_lineage != exact_parent.root_lineage)
            or reservation.request_limit_scope != exact_activation.request_limit_id
            or reservation.request_limit_count_before
            != exact_activation.request_limit_count_before_child
            or (
                released_pre_send
                and (
                    reservation.request_limit_count_after
                    != reservation.request_limit_count_before + usage.attempts
                    or reservation.request_limit_count_after
                    != reservation.request_limit_count_before
                    + exact_result.accounted_provider_attempts
                    or reservation.request_limit_count_after
                    > exact_activation.request_limit_count_after_child
                )
            )
            or (
                not released_pre_send
                and reservation.request_limit_count_after
                != exact_activation.request_limit_count_after_child
            )
            or reservation.request_limit_maximum != exact_activation.request_limit_maximum
            or (
                specialist_outcome is not None
                and (
                    output_artifact is None
                    or usage.validated_response_sha256 is None
                    or specialist_outcome.outcome_kind
                    is not SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW
                    or specialist_outcome.request_id != exact_activation.child_logical_request_id
                    or specialist_outcome.specialist_role
                    != exact_activation.request_role.removeprefix("specialist:")
                    or specialist_outcome.request_role != exact_activation.request_role
                    or specialist_outcome.validated_response_sha256
                    != usage.validated_response_sha256
                    or specialist_outcome.context_request_evidence_sha256 != context.evidence_sha256
                    or specialist_outcome.requested_surface_count
                    != len(exact_result.child_surface_ids)
                    or specialist_outcome.surface_review_artifact_sha256
                    != output_artifact.artifact_sha256
                )
            )
        ):
            raise ValueError("recovery public request differs from typed provider evidence")

        audit_routing = _usage_audit_routing_evidence(usage)
        audit_binding = exact_manifest.bindings.audit_model_selection
        if usage_requires_audit_policy_evidence(usage) or audit_routing is not None:
            audit_routing = _require_usage_audit_selection(
                usage_record=usage,
                requested_model=exact_parent.requested_model,
                binding=audit_binding,
            )
        refresh_route = _usage_audit_model_refresh_route_evidence(usage)
        if usage.execution_evidence is ExecutionEvidenceKind.REAL or refresh_route is not None:
            _require_usage_audit_model_refresh(
                usage_record=usage,
                requested_model=exact_parent.requested_model,
                binding=exact_manifest.bindings.audit_model_refresh,
                audit_model_selection=audit_binding,
            )
        pricing_route = _usage_audit_model_refresh_pricing_route_evidence(usage)
        if (
            usage.execution_evidence is ExecutionEvidenceKind.REAL
            or pricing_route is not None
            or exact_manifest.bindings.audit_model_refresh_pricing is not None
        ):
            _require_usage_audit_model_refresh_pricing(
                usage_record=usage,
                requested_model=exact_parent.requested_model,
                binding=exact_manifest.bindings.audit_model_refresh_pricing,
                refresh_binding=exact_manifest.bindings.audit_model_refresh,
            )
        projected_family_closure = closure_by_family_id.get(exact_family.family_id)
        if recursive_promotion and projected_family_closure is None:
            raise ValueError("recursive recovery public request lacks its family closure")
        values: dict[str, Any] = {
            "schema_version": (
                "1.3"
                if released_pre_send
                else "1.2"
                if recursive_promotion
                else "1.1"
                if specialist_outcome is not None
                else "1.0"
            ),
            "evidence_authority": "comparison_required",
            "provider_dispatch_authorized": False,
            "review_credit_authorized": False,
            "coverage_credit_authorized": False,
            "completion_authorized": False,
            "release_authorized": False,
            "campaign_id": exact_manifest.campaign_id,
            "parent_task_id": exact_parent.task_id,
            **(
                {"promotion_entry_sha256": exact_promotion.entry_sha256}
                if exact_promotion is not None
                else {}
            ),
            **(
                {
                    "promotion_disposition": promotion_disposition,
                    "global_request_ordinal": exact_activation.global_request_ordinal,
                    "recovery_family_id": exact_family.family_id,
                    "family_root_sha256": exact_family.entry_sha256,
                    "recovery_plan_sha256": exact_family.recovery_plan.plan_sha256,
                    "family_closure_id": projected_family_closure.closure_id,
                    "family_closure_sha256": projected_family_closure.entry_sha256,
                }
                if recursive_promotion
                and promotion_disposition is not None
                and projected_family_closure is not None
                else {}
            ),
            **(
                {
                    "global_request_ordinal": exact_activation.global_request_ordinal,
                    "recovery_family_id": exact_family.family_id,
                    "family_root_sha256": exact_family.entry_sha256,
                    "recovery_plan_sha256": exact_family.recovery_plan.plan_sha256,
                }
                if released_pre_send
                else {}
            ),
            "child_task_id": exact_activation.child_task_id,
            "logical_request_id": exact_activation.child_logical_request_id,
            **(
                {"child_plan_sha256": exact_activation.child_plan_sha256}
                if released_pre_send
                else {}
            ),
            "child_result_entry_sha256": exact_result.entry_sha256,
            "activation_id": exact_activation.activation_id,
            "activation_entry_sha256": exact_activation.entry_sha256,
            "activation_status": SchedulerActivationStatus.ACTIVATED,
            **(
                {
                    "dispatch_id": exact_result.dispatch_id,
                    "dispatch_sha256": exact_result.dispatch_sha256,
                }
                if released_pre_send and exact_result.dispatch_id is not None
                else {}
            ),
            "role": exact_activation.request_role,
            "requested_model": exact_activation.requested_model,
            "root_lineage": exact_parent.root_lineage,
            "actual_input_sha256": exact_activation.actual_input_sha256,
            "system_prompt_sha256": exact_activation.system_prompt_sha256,
            "user_prompt_sha256": exact_activation.user_prompt_sha256,
            "provider_prompt_sha256": exact_activation.provider_prompt_sha256,
            "response_schema_sha256": exact_activation.response_schema_sha256,
            "delivered_source_inventory_sha256": expected_source_inventory_sha256,
            "request_limit_scope": reservation.request_limit_scope,
            "request_limit_count_before": reservation.request_limit_count_before,
            "request_limit_count_after": reservation.request_limit_count_after,
            "request_limit_maximum": reservation.request_limit_maximum,
            "request_limit_reservation_evidence_sha256": reservation.evidence_sha256,
            "terminal_status": (
                SchedulerTerminalStatus.SUCCEEDED
                if succeeded
                else SchedulerTerminalStatus.FAILED
                if released_pre_send
                else SchedulerTerminalStatus.TRUNCATED
            ),
            "terminal_evidence_sha256": exact_result.terminal_evidence_sha256,
            **(
                {
                    "result_origin": exact_result.result_origin,
                    "released_cost_entry_sha256": exact_result.released_cost_entry_sha256,
                    "pre_send_release_reason": exact_result.pre_send_release_reason,
                    "provider_attempt_evidence_sha256": (
                        exact_result.provider_attempt_evidence_sha256
                    ),
                    "accounted_provider_attempts": exact_result.accounted_provider_attempts,
                    "accounted_completion_tokens": exact_result.accounted_completion_tokens,
                    "accounted_cost_usd_exact": exact_result.accounted_cost_usd_exact,
                    "cost_disposition": exact_result.cost_disposition,
                }
                if released_pre_send
                else {}
            ),
            "usage_record_sha256": exact_result.runtime_usage_record_sha256,
            "context_request_evidence_sha256": context.evidence_sha256,
            **(
                {"provider_response_sha256": usage.response_sha256} if not released_pre_send else {}
            ),
            **(
                {
                    "runtime_completion_evidence_sha256": (
                        exact_result.runtime_completion_evidence_sha256
                    ),
                    "validated_response_sha256": usage.validated_response_sha256,
                    "normalization_evidence_sha256": normalization.evidence_sha256,
                    "output_artifact_sha256": output_artifact.artifact_sha256,
                    **(
                        {"specialist_accepted_outcome_sha256": (specialist_outcome.evidence_sha256)}
                        if specialist_outcome is not None
                        else {}
                    ),
                }
                if succeeded and normalization is not None and output_artifact is not None
                else {}
            ),
            **(
                {
                    "audit_policy_selection_binding_sha256": audit_binding.binding_sha256,
                    "audit_model_selection_bundle_sha256": (
                        audit_routing.audit_model_selection_bundle_sha256
                    ),
                    "audit_selection_sha256": audit_routing.audit_selection_sha256,
                    "audit_selected_model_set_sha256": (audit_routing.selected_model_set_sha256),
                    "audit_scope_sha256": audit_routing.audit_scope_sha256,
                    "audit_source_sha256": audit_routing.source_sha256,
                    "audit_selection_expires_at": audit_routing.expires_at,
                    "audit_policy_routing_evidence_sha256": (audit_routing.routing_evidence_sha256),
                }
                if audit_routing is not None and audit_binding is not None
                else {}
            ),
        }
        return cls(**values, request_evidence_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def public_recovery_request_shape_and_hash_are_exact(self) -> Self:
        audit_fields = (
            self.audit_policy_selection_binding_sha256,
            self.audit_model_selection_bundle_sha256,
            self.audit_selection_sha256,
            self.audit_selected_model_set_sha256,
            self.audit_scope_sha256,
            self.audit_source_sha256,
            self.audit_selection_expires_at,
            self.audit_policy_routing_evidence_sha256,
        )
        completion_fields = (
            self.runtime_completion_evidence_sha256,
            self.validated_response_sha256,
            self.normalization_evidence_sha256,
            self.output_artifact_sha256,
        )
        released_fields = (
            self.global_request_ordinal,
            self.recovery_family_id,
            self.family_root_sha256,
            self.recovery_plan_sha256,
            self.child_plan_sha256,
            self.result_origin,
            self.released_cost_entry_sha256,
            self.pre_send_release_reason,
            self.provider_attempt_evidence_sha256,
            self.accounted_provider_attempts,
            self.accounted_completion_tokens,
            self.accounted_cost_usd_exact,
            self.cost_disposition,
        )
        audit_fields_are_partial = any(item is None for item in audit_fields) and any(
            item is not None for item in audit_fields
        )
        if self.schema_version == "1.3":
            accounted_cost = (
                Decimal(self.accounted_cost_usd_exact)
                if self.accounted_cost_usd_exact is not None
                else None
            )
            canonical_accounted_cost = (
                format(accounted_cost, "f") if accounted_cost is not None else None
            )
            if canonical_accounted_cost is not None and "." in canonical_accounted_cost:
                canonical_accounted_cost = canonical_accounted_cost.rstrip("0").rstrip(".")
            if canonical_accounted_cost in {"", "-0"}:
                canonical_accounted_cost = "0"
            if (
                self.terminal_status is not SchedulerTerminalStatus.FAILED
                or not _candidate_review_wire_schema_is_supported(self.response_schema_sha256)
                or self.request_limit_count_after <= self.request_limit_count_before
                or self.request_limit_count_after > self.request_limit_maximum
                or self.accounted_provider_attempts is None
                or self.accounted_completion_tokens is None
                or accounted_cost is None
                or self.accounted_cost_usd_exact != canonical_accounted_cost
                or self.request_limit_count_after
                != self.request_limit_count_before + self.accounted_provider_attempts
                or (
                    self.accounted_provider_attempts == 1
                    and (self.accounted_completion_tokens != 0 or accounted_cost != 0)
                )
                or (
                    self.accounted_provider_attempts > 1
                    and (self.accounted_completion_tokens == 0 or accounted_cost <= 0)
                )
                or any(item is None for item in released_fields)
                or self.result_origin is not SchedulerTruncationRecoveryResultOrigin.RUNTIME
                or self.released_cost_entry_sha256 != self.terminal_evidence_sha256
                or self.pre_send_release_reason
                not in {"cancelled_before_send", "failed_before_send"}
                or self.cost_disposition
                is not SchedulerTruncationRecoveryCostDisposition.RELEASED_PRE_SEND_TAIL
                or (self.dispatch_id is None) != (self.dispatch_sha256 is None)
                or self.promotion_entry_sha256 is not None
                or self.promotion_disposition is not None
                or self.family_closure_id is not None
                or self.family_closure_sha256 is not None
                or any(item is not None for item in completion_fields)
                or self.provider_response_sha256 is not None
                or self.specialist_accepted_outcome_sha256 is not None
                or audit_fields_are_partial
                or self.request_evidence_sha256
                != _model_sha256(self, exclude={"request_evidence_sha256"})
            ):
                raise ValueError("scheduler released recovery request is inconsistent")
            return self
        succeeded = self.terminal_status is SchedulerTerminalStatus.SUCCEEDED
        requires_specialist_outcome = (
            succeeded and self.role in _SPECIALIST_INVESTIGATOR_REQUEST_ROLES
        )
        recursive_promotion = self.schema_version == "1.2"
        recursive_fields = (
            self.promotion_disposition,
            self.global_request_ordinal,
            self.recovery_family_id,
            self.family_root_sha256,
            self.recovery_plan_sha256,
            self.family_closure_id,
            self.family_closure_sha256,
        )
        bridge = (
            self.promotion_disposition
            is SchedulerTruncationRecoveryPromotionDisposition.SUPERSEDED_TRUNCATED_BRIDGE
        )
        if (
            self.terminal_status is SchedulerTerminalStatus.FAILED
            or self.request_limit_count_after <= self.request_limit_count_before
            or self.request_limit_count_after > self.request_limit_maximum
            or not _candidate_review_wire_schema_is_supported(self.response_schema_sha256)
            or self.provider_response_sha256 is None
            or self.child_plan_sha256 is not None
            or self.dispatch_id is not None
            or self.dispatch_sha256 is not None
            or any(item is not None for item in released_fields[5:])
            or succeeded != all(item is not None for item in completion_fields)
            or (not succeeded and any(item is not None for item in completion_fields))
            or (
                self.promotion_entry_sha256 is not None
                and not succeeded
                and not (recursive_promotion and bridge)
            )
            or recursive_promotion
            != (
                self.promotion_entry_sha256 is not None
                and all(item is not None for item in recursive_fields)
            )
            or (
                recursive_promotion
                and (bridge == succeeded or self.role in _SPECIALIST_INVESTIGATOR_REQUEST_ROLES)
            )
            or (not recursive_promotion and any(item is not None for item in recursive_fields))
            or (self.schema_version == "1.1")
            != (self.specialist_accepted_outcome_sha256 is not None)
            or requires_specialist_outcome != (self.specialist_accepted_outcome_sha256 is not None)
            or audit_fields_are_partial
            or self.request_evidence_sha256
            != _model_sha256(self, exclude={"request_evidence_sha256"})
        ):
            raise ValueError("scheduler recovery model-request evidence is inconsistent")
        return self


def build_scheduler_model_request_evidence(
    *,
    plans: Iterable[SchedulerPassPlan],
    activations: Iterable[SchedulerTaskActivation],
    task_results: Iterable[SchedulerTaskResult],
) -> tuple[SchedulerModelRequestEvidence, ...]:
    """Derive the exact bounded public projection for every planned model task."""

    exact_plans = tuple(plans)
    exact_activations = tuple(activations)
    exact_results = tuple(task_results)
    activation_by_task = {item.task_id: item for item in exact_activations}
    result_by_task = {item.task_id: item for item in exact_results}
    if len(activation_by_task) != len(exact_activations) or len(result_by_task) != len(
        exact_results
    ):
        raise ValueError("scheduler model-request projection requires unique task evidence")
    requests = tuple(
        SchedulerModelRequestEvidence.build(
            plan=plan,
            task=task,
            activation=activation_by_task.get(task.task_id),
            result=result_by_task.get(task.task_id),
        )
        for plan in exact_plans
        for task in plan.tasks
        if task.task_kind is SchedulerTaskKind.MODEL_REQUEST
    )
    if len({item.task_id for item in requests}) != len(requests):
        raise ValueError("scheduler model-request projection repeats a task identity")
    return tuple(sorted(requests, key=lambda item: item.task_id))


def build_scheduler_truncation_recovery_model_request_evidence(
    *,
    manifest: SchedulerCampaignManifest,
    model_requests: Iterable[SchedulerModelRequestEvidence],
    truncation_recovery_entries: Iterable[SchedulerTruncationRecoveryEntry],
    provider_attempts: Iterable[SchedulerProviderAttemptEvidence] = (),
) -> tuple[SchedulerTruncationRecoveryModelRequestEvidence, ...]:
    """Derive public request evidence for every typed child UsageRecord."""

    exact_manifest = SchedulerCampaignManifest.model_validate(manifest.model_dump(mode="python"))
    request_items = _bounded_scheduler_items(
        model_requests,
        limit=_MAX_SCHEDULER_MODEL_REQUESTS,
        label="model-request inventory",
    )
    exact_requests = tuple(
        SchedulerModelRequestEvidence.model_validate(item.model_dump(mode="python"))
        for item in request_items
    )
    provider_attempt_items = _bounded_scheduler_items(
        provider_attempts,
        limit=_MAX_SCHEDULER_MODEL_REQUESTS,
        label="provider-attempt inventory",
    )
    exact_provider_attempts = tuple(
        SchedulerProviderAttemptEvidence.model_validate(item.model_dump(mode="python"))
        for item in provider_attempt_items
    )
    entries = validate_truncation_recovery_entry_chain(truncation_recovery_entries)
    parent_by_task = {item.task_id: item for item in exact_requests}
    if len(parent_by_task) != len(exact_requests):
        raise ValueError("scheduler recovery public projection repeats a parent request")
    provider_attempt_by_task = {item.task_id: item for item in exact_provider_attempts}
    if len(provider_attempt_by_task) != len(exact_provider_attempts):
        raise ValueError("scheduler recovery public projection repeats a provider attempt")
    activation_items = tuple(
        entry for entry in entries if isinstance(entry, SchedulerTruncationRecoveryChildActivation)
    )
    activations_by_sha = {entry.entry_sha256: entry for entry in activation_items}
    result_items = tuple(
        entry for entry in entries if isinstance(entry, SchedulerTruncationRecoveryChildResult)
    )
    results_by_sha = {entry.entry_sha256: entry for entry in result_items}
    promotions = tuple(
        entry for entry in entries if isinstance(entry, SchedulerTruncationRecoveryFamilyPromotion)
    )
    family_items = tuple(
        entry for entry in entries if isinstance(entry, SchedulerTruncationRecoveryFamilyRoot)
    )
    families_by_id = {entry.family_id: entry for entry in family_items}
    if (
        len(activations_by_sha) != len(activation_items)
        or len(results_by_sha) != len(result_items)
        or len(families_by_id) != len(family_items)
    ):
        raise ValueError("scheduler recovery public projection repeats lifecycle evidence")

    for root_candidate in family_items:
        if root_candidate.parent_kind is not SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK:
            continue
        parent = parent_by_task.get(root_candidate.recovery_plan.parent.parent_task_id)
        attempt = provider_attempt_by_task.get(root_candidate.recovery_plan.parent.parent_task_id)
        if parent is None or attempt is None:
            raise ValueError("scheduler recovery root lacks its exact public parent attempt")
        try:
            request_limit_reservations = atomic_request_limit_reservations_from_usage(
                attempt.usage_record
            )
        except ValueError:
            raise ValueError(
                "scheduler recovery root lacks exact parent request-limit evidence"
            ) from None
        parent_reservation = root_candidate.request_limit_binding.parent_request_limit_reservation
        usage = attempt.usage_record
        root_has_nested_family = any(
            item.parent_family_id == root_candidate.family_id for item in family_items
        )
        root_attempt_truncation_is_exact = (
            attempt.schema_version == "1.1"
            and attempt.truncation_projection == root_candidate.truncation_projection
        ) or (
            not root_has_nested_family
            and attempt.schema_version == "1.0"
            and attempt.truncation_projection is None
        )
        expected_parent_request_id = (
            usage.request_id
            if usage.attempts == 1
            else f"{usage.request_id}:attempt:{usage.attempts}"
        )
        if (
            root_candidate.request_limit_binding.manifest_sha256 != exact_manifest.manifest_sha256
            or root_candidate.request_limit_binding.campaign_id != exact_manifest.campaign_id
            or not request_limit_reservations
            or request_limit_reservations[-1] != parent_reservation
            or parent_reservation.request_id != expected_parent_request_id
            or parent_reservation.request_limit_scope != parent.logical_request_id
            or parent_reservation.exact_model_id != parent.requested_model
            or parent_reservation.role != parent.role
            or root_candidate.request_limit_id != parent.logical_request_id
            or root_candidate.recovery_plan.parent.parent_logical_request_id
            != parent.logical_request_id
            or root_candidate.recovery_plan.parent.pass_plan_id != parent.pass_plan_id
            or root_candidate.recovery_plan.parent.parent_task_plan_sha256
            != parent.task_plan_sha256
            or root_candidate.recovery_plan.parent.parent_activation_sha256
            != parent.activation_sha256
            or root_candidate.recovery_plan.parent.provider_attempt_evidence_sha256
            != attempt.attempt_evidence_sha256
            or root_candidate.parent_terminal_result_sha256 != parent.result_sha256
            or parent.manifest_sha256 != exact_manifest.manifest_sha256
            or parent.pass_kind is not SchedulerPassKind.BLIND_SHARD_REVIEW
            or parent.activation_status is not SchedulerActivationStatus.ACTIVATED
            or parent.terminal_status is not SchedulerTerminalStatus.TRUNCATED
            or parent.terminal_evidence_sha256
            != root_candidate.truncation_projection.evidence_sha256
            or not root_attempt_truncation_is_exact
            or attempt.task_id != parent.task_id
            or attempt.logical_request_id != parent.logical_request_id
            or attempt.activation_sha256 != parent.activation_sha256
            or attempt.delivered_source_descriptor_sha256s
            != parent.delivered_source_descriptor_sha256s
            or attempt.response_schema_sha256 != parent.response_schema_sha256
            or usage.request_id != parent.logical_request_id
            or usage.role != parent.role
            or usage.requested_model != parent.requested_model
            or usage.validation_status is not ModelRequestValidationStatus.TRUNCATED
            or usage.status != "rejected_truncated_response"
            or usage.validated_response_sha256 is not None
            or usage.response_sha256
            != root_candidate.truncation_projection.original_response_sha256
            or usage.schema_sha256 != root_candidate.truncation_projection.wire_schema_sha256
        ):
            raise ValueError("scheduler recovery root differs from its public parent attempt")

    def root_family_for(
        family: SchedulerTruncationRecoveryFamilyRoot,
    ) -> SchedulerTruncationRecoveryFamilyRoot:
        if family.parent_kind is SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK:
            if family.parent_family_id is not None:
                raise ValueError("scheduler recovery root has an unexpected parent family")
            return family
        parent_family = (
            families_by_id.get(family.parent_family_id)
            if family.parent_family_id is not None
            else None
        )
        if (
            parent_family is None
            or parent_family.parent_kind is not SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK
            or parent_family.parent_family_id is not None
            or family.recovery_plan.parent.current_depth != 1
            or any(child.depth != 2 for child in family.recovery_plan.children)
        ):
            raise ValueError("scheduler nested recovery lacks one exact root ancestor")
        return parent_family

    parent_ids = tuple(item.parent_task_id for item in promotions)
    if len(parent_ids) != len(set(parent_ids)):
        raise ValueError("scheduler recovery public projection repeats a promoted parent")
    promotion_by_result_sha256: dict[str, SchedulerTruncationRecoveryFamilyPromotion] = {}
    for promotion in promotions:
        promoted_result_sha256s = (
            promotion.direct_child_result_sha256s
            if promotion.schema_version == "1.0"
            else (
                promotion.superseded_bridge_result_sha256,
                *(promotion.promoted_leaf_result_sha256s or ()),
            )
        )
        if any(result_sha256 is None for result_sha256 in promoted_result_sha256s):
            raise ValueError("scheduler recursive recovery promotion lacks its exact result tree")
        for result_sha256 in promoted_result_sha256s:
            assert result_sha256 is not None
            if result_sha256 in promotion_by_result_sha256:
                raise ValueError("scheduler recovery promotions repeat a typed child result")
            promotion_by_result_sha256[result_sha256] = promotion
    recovered: list[SchedulerTruncationRecoveryModelRequestEvidence] = []
    for result in results_by_sha.values():
        if result.schema_version == "1.3":
            if result.result_origin is SchedulerTruncationRecoveryResultOrigin.CRASH_RECOVERY:
                if (
                    result.runtime_usage_record is not None
                    or result.runtime_usage_record_sha256 is not None
                    or result.runtime_request_limit_reservation is not None
                    or result.provider_attempt_evidence_sha256 is not None
                ):
                    raise ValueError("crash-recovered release cannot enter public usage custody")
                continue
            if (
                result.result_origin is not SchedulerTruncationRecoveryResultOrigin.RUNTIME
                or result.runtime_usage_record is None
                or result.runtime_usage_record_sha256 is None
                or result.runtime_request_limit_reservation is None
                or result.provider_attempt_evidence_sha256 is None
            ):
                raise ValueError("released recovery result lacks one public failed usage")
        elif result.schema_version not in {"1.1", "1.2"} or (result.runtime_usage_record is None):
            continue
        family = families_by_id.get(result.family_id)
        activation = activations_by_sha.get(result.activation_sha256)
        root_family = root_family_for(family) if family is not None else None
        parent = (
            parent_by_task.get(root_family.recovery_plan.parent.parent_task_id)
            if root_family is not None
            else None
        )
        parent_attempt = (
            provider_attempt_by_task.get(root_family.recovery_plan.parent.parent_task_id)
            if root_family is not None
            else None
        )
        if (
            family is None
            or root_family is None
            or activation is None
            or parent is None
            or parent_attempt is None
        ):
            raise ValueError("scheduler typed recovery usage lacks its public parent lifecycle")
        recovered.append(
            SchedulerTruncationRecoveryModelRequestEvidence.build(
                manifest=exact_manifest,
                parent_request=parent,
                parent_attempt=parent_attempt,
                family=family,
                root_family=root_family,
                recovery_entries=entries,
                promotion=promotion_by_result_sha256.get(result.entry_sha256),
                activation=activation,
                result=result,
            )
        )
    ordered = tuple(sorted(recovered, key=lambda item: item.logical_request_id))
    request_ids = tuple(item.logical_request_id for item in ordered)
    result_sha256s = {item.child_result_entry_sha256 for item in ordered}
    if (
        len(ordered) > TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS
        or request_ids != tuple(sorted(set(request_ids)))
        or not set(promotion_by_result_sha256) <= result_sha256s
    ):
        raise ValueError("scheduler recovery public request inventory is not exact")
    return ordered


def _derived_pass_status(
    results: tuple[SchedulerTaskResult, ...],
    *,
    primary_task_ids: frozenset[str] | None = None,
    recovered_task_ids: frozenset[str] = frozenset(),
) -> SchedulerPassStatus:
    substantive_results = (
        results
        if primary_task_ids is None
        else tuple(result for result in results if result.task_id in primary_task_ids)
    )
    statuses = {
        (
            SchedulerTerminalStatus.SUCCEEDED
            if result.task_id in recovered_task_ids
            else result.terminal_status
        )
        for result in substantive_results
    }
    if not statuses:
        return SchedulerPassStatus.INCOMPLETE
    if statuses <= {
        SchedulerTerminalStatus.SUCCEEDED,
        SchedulerTerminalStatus.EXPLICIT_EMPTY,
    }:
        return SchedulerPassStatus.COMPLETE
    if statuses & {
        SchedulerTerminalStatus.FAILED,
        SchedulerTerminalStatus.INVALID,
        SchedulerTerminalStatus.UNBOUND,
    }:
        return SchedulerPassStatus.FAILED
    if SchedulerTerminalStatus.INCONCLUSIVE in statuses:
        return SchedulerPassStatus.INCONCLUSIVE
    return SchedulerPassStatus.INCOMPLETE


class SchedulerPassResult(StrictModel):
    """Exact terminal result set for one sealed mandatory pass."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    plan: SchedulerPassPlan
    task_results: tuple[SchedulerTaskResult, ...] = Field(min_length=1, max_length=100_000)
    recovery_promotion_bindings: tuple[SchedulerTruncationRecoveryPromotionBinding, ...] = Field(
        default=(),
        max_length=100_000,
        exclude_if=lambda value: not value,
    )
    status: SchedulerPassStatus
    pass_result_id: str = Field(pattern=r"^scheduler-pass-result-[0-9a-f]{64}$")
    pass_result_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        plan: SchedulerPassPlan,
        task_results: Iterable[SchedulerTaskResult],
        recovery_promotion_bindings: Iterable[SchedulerTruncationRecoveryPromotionBinding] = (),
    ) -> SchedulerPassResult:
        validated_plan = SchedulerPassPlan.model_validate(plan.model_dump(mode="python"))
        canonical_results = tuple(
            sorted(
                (
                    SchedulerTaskResult.model_validate(item.model_dump(mode="python"))
                    for item in task_results
                ),
                key=lambda item: item.task_id,
            )
        )
        raw_promotions = tuple(
            islice(iter(recovery_promotion_bindings), len(validated_plan.tasks) + 1)
        )
        if len(raw_promotions) > len(validated_plan.tasks):
            raise ValueError("scheduler pass recovery promotions exceed its exact task inventory")
        canonical_promotions = tuple(
            sorted(
                (
                    SchedulerTruncationRecoveryPromotionBinding.model_validate_json(
                        item.model_dump_json(),
                        strict=True,
                    )
                    for item in raw_promotions
                ),
                key=lambda item: item.parent_task_id,
            )
        )
        recovered_task_ids = frozenset(item.parent_task_id for item in canonical_promotions)
        values: dict[str, Any] = {
            "schema_version": "1.1" if canonical_promotions else "1.0",
            "evidence_authority": "comparison_required",
            "plan": validated_plan,
            "task_results": canonical_results,
            **(
                {"recovery_promotion_bindings": canonical_promotions}
                if canonical_promotions
                else {}
            ),
            "status": _derived_pass_status(
                canonical_results,
                primary_task_ids=frozenset(
                    task.task_id
                    for task in validated_plan.tasks
                    if task.purpose is SchedulerTaskPurpose.PRIMARY
                ),
                recovered_task_ids=recovered_task_ids,
            ),
        }
        result_id = "scheduler-pass-result-" + scheduler_canonical_sha256(
            {
                "domain": "mmaudit.scheduler.pass-result-identity.v1",
                "pass_plan_id": validated_plan.pass_plan_id,
            }
        )
        body = {**values, "pass_result_id": result_id}
        return cls(**body, pass_result_sha256=scheduler_canonical_sha256(body))

    @model_validator(mode="after")
    def exact_task_results_derive_pass_status(self) -> Self:
        planned_by_id = {task.task_id: task for task in self.plan.tasks}
        result_ids = tuple(item.task_id for item in self.task_results)
        if result_ids != tuple(sorted(set(result_ids))):
            raise ValueError("scheduler pass results must be unique and sorted")
        if set(result_ids) != set(planned_by_id):
            raise ValueError("scheduler pass result set differs from its exact task plan")
        promotion_task_ids = tuple(item.parent_task_id for item in self.recovery_promotion_bindings)
        if self.schema_version == "1.0" and self.recovery_promotion_bindings:
            raise ValueError("scheduler pass result v1.0 cannot contain recovery promotions")
        if self.schema_version == "1.1" and not self.recovery_promotion_bindings:
            raise ValueError("scheduler pass result v1.1 requires an exact recovery promotion")
        if (
            promotion_task_ids != tuple(sorted(set(promotion_task_ids)))
            or self.plan.pass_kind is not SchedulerPassKind.BLIND_SHARD_REVIEW
        ) and self.recovery_promotion_bindings:
            raise ValueError("scheduler pass recovery promotions are not canonical blind reviews")
        result_by_task = {item.task_id: item for item in self.task_results}
        for promotion in self.recovery_promotion_bindings:
            task = planned_by_id.get(promotion.parent_task_id)
            original = result_by_task.get(promotion.parent_task_id)
            expected_promotion_sources = tuple(
                sorted(
                    source.source_descriptor_sha256
                    for source in (
                        _task_source_descriptors(self.plan, task) if task is not None else ()
                    )
                )
            )
            expected_source_inventory_sha256 = scheduler_canonical_sha256(
                {
                    "domain": "mmaudit.scheduler.recovery-delivered-source-inventory.v1",
                    "source_descriptor_sha256s": expected_promotion_sources,
                }
            )
            if (
                task is None
                or original is None
                or task.purpose is not SchedulerTaskPurpose.PRIMARY
                or task.task_kind is not SchedulerTaskKind.MODEL_REQUEST
                or task.response_schema_sha256
                != candidate_review_frame_wire_schema_sha256(
                    algorithm_version=self.plan.manifest.algorithm_version,
                )
                or original.terminal_status is not SchedulerTerminalStatus.TRUNCATED
                or promotion.original_truncated_result_sha256 != original.result_sha256
                or (
                    (
                        task.role == "source_audit"
                        or _WHOLE_PROTOCOL_REVIEW_ROLE.fullmatch(task.role) is not None
                    )
                    and promotion.delivered_source_inventory_sha256
                    != expected_source_inventory_sha256
                )
            ):
                raise ValueError("scheduler recovery promotion differs from its truncated task")
        for result in self.task_results:
            task = planned_by_id[result.task_id]
            if (
                result.campaign_id != self.plan.manifest.campaign_id
                or result.manifest_sha256 != self.plan.manifest.manifest_sha256
                or result.pass_kind is not self.plan.pass_kind
                or result.pass_id != self.plan.pass_id
                or result.pass_plan_id != self.plan.pass_plan_id
                or result.pass_plan_sha256 != self.plan.pass_plan_sha256
                or result.task_plan_sha256 != task.task_plan_sha256
                or result.logical_request_id != task.logical_request_id
                or result.scope != task.scope
            ):
                raise ValueError("scheduler task result differs from its exact planned identity")
            if task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING:
                if (
                    result.schema_version != "1.1"
                    or result.retrieval_custody is not None
                    or result.normalizer_sha256 is not None
                    or result.specialist_accepted_outcome_sha256 is not None
                    or result.model_surface_review_artifact_sha256 is not None
                    or result.model_surface_review_request_manifest_sha256 is not None
                    or result.model_surface_review_request_count != 0
                    or result.reviewed_source_descriptor_sha256s
                    or result.reviewed_candidate_ids
                ):
                    raise ValueError(
                        "scheduler retrieval child result cannot claim substantive review credit"
                    )
            elif (result.schema_version == "1.1") != (result.retrieval_custody is not None):
                raise ValueError("scheduler primary result schema differs from retrieval custody")
            if (task.task_kind is SchedulerTaskKind.EMPTY_COMPLETION) != (
                result.terminal_status is SchedulerTerminalStatus.EXPLICIT_EMPTY
            ):
                raise ValueError("scheduler empty completion task/result status is inconsistent")
            if (
                task.task_kind is SchedulerTaskKind.MODEL_REQUEST
                and result.terminal_status is SchedulerTerminalStatus.SUCCEEDED
                and result.model_completion_evidence_sha256 is None
            ):
                raise ValueError("successful scheduler model result lacks provider evidence")
            if result.terminal_status is SchedulerTerminalStatus.SUCCEEDED and (
                scheduler_task_requires_specialist_accepted_outcome(task)
                != (result.specialist_accepted_outcome_sha256 is not None)
            ):
                raise ValueError(
                    "scheduler specialist result differs from its host-accepted outcome"
                )
            if (
                self.plan.pass_kind is SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION
                and task.purpose is SchedulerTaskPurpose.PRIMARY
                and task.task_kind is SchedulerTaskKind.MODEL_REQUEST
                and result.terminal_status is SchedulerTerminalStatus.SUCCEEDED
                and result.reviewed_candidate_ids != task.candidate_ids
            ):
                raise ValueError("pass-five result omitted an exact candidate review")
            if (
                self.plan.pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
                and task.purpose is SchedulerTaskPurpose.PRIMARY
                and task.role
                in {
                    "verifier",
                    "candidate_falsifier",
                    "falsifier",
                    "specialist:falsifier",
                }
                and result.terminal_status is SchedulerTerminalStatus.SUCCEEDED
                and result.reviewed_candidate_ids != task.candidate_ids
            ):
                raise ValueError("pass-six result omitted an exact candidate decision")
            if (
                self.plan.pass_kind is SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT
                and task.purpose is SchedulerTaskPurpose.PRIMARY
                and task.role == "judge"
                and result.terminal_status is SchedulerTerminalStatus.SUCCEEDED
                and result.reviewed_candidate_ids != task.candidate_ids
            ):
                raise ValueError("judge result omitted an exact candidate-group decision")
        child_result_by_parent_id = {
            task.parent_task_id: result_by_task[task.task_id]
            for task in self.plan.tasks
            if task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
        }
        for primary in (
            task for task in self.plan.tasks if task.purpose is SchedulerTaskPurpose.PRIMARY
        ):
            primary_result = result_by_task[primary.task_id]
            child_result = child_result_by_parent_id.get(primary.task_id)
            custody = primary_result.retrieval_custody
            if child_result is None:
                if custody is not None:
                    raise ValueError("scheduler primary result claims an unrelated retrieval child")
                continue
            if child_result.terminal_status is SchedulerTerminalStatus.SUCCEEDED:
                if custody is None or (
                    custody.planner_task_id != child_result.task_id
                    or custody.planner_task_result_id != child_result.result_id
                    or custody.planner_task_result_sha256 != child_result.result_sha256
                    or custody.planner_output_artifact_sha256 != child_result.output_artifact_sha256
                ):
                    raise ValueError(
                        "scheduler primary result lacks its successful retrieval-child custody"
                    )
            elif custody is not None:
                raise ValueError("scheduler retrieval custody requires a successful linked child")
        expected_status = _derived_pass_status(
            self.task_results,
            primary_task_ids=frozenset(
                task.task_id
                for task in self.plan.tasks
                if task.purpose is SchedulerTaskPurpose.PRIMARY
            ),
            recovered_task_ids=frozenset(promotion_task_ids),
        )
        if self.status is not expected_status:
            raise ValueError("scheduler pass status is not derived from terminal task evidence")
        if (
            self.status is SchedulerPassStatus.COMPLETE
            and self.plan.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
        ):
            exact_sources = {
                source.source_descriptor_sha256
                for shard in self.plan.manifest.shard_inventory.shards
                for source in shard.sources
            }
            observed_sources: set[str] = set()
            promotions_by_task = {
                item.parent_task_id: item for item in self.recovery_promotion_bindings
            }
            for result in self.task_results:
                task = planned_by_id[result.task_id]
                if task.purpose is not SchedulerTaskPurpose.PRIMARY or task.role != "source_audit":
                    continue
                expected_task_sources = {
                    source.source_descriptor_sha256
                    for source in _task_source_descriptors(self.plan, task)
                }
                task_promotion = promotions_by_task.get(result.task_id)
                reviewed_sources = (
                    tuple(sorted(expected_task_sources))
                    if task_promotion is not None
                    else result.reviewed_source_descriptor_sha256s
                )
                if set(reviewed_sources) != expected_task_sources:
                    raise ValueError(
                        "blind source-audit result lacks exact substantive source coverage"
                    )
                observed_sources.update(reviewed_sources)
            if observed_sources != exact_sources:
                raise ValueError("blind pass did not review every exact audited source")
        expected_id = "scheduler-pass-result-" + scheduler_canonical_sha256(
            {
                "domain": "mmaudit.scheduler.pass-result-identity.v1",
                "pass_plan_id": self.plan.pass_plan_id,
            }
        )
        if self.pass_result_id != expected_id:
            raise ValueError("scheduler pass-result ID is inconsistent")
        if self.pass_result_sha256 != _model_sha256(self, exclude={"pass_result_sha256"}):
            raise ValueError("scheduler pass-result hash is inconsistent")
        return self


def _derived_campaign_state(
    pass_results: tuple[SchedulerPassResult, ...],
) -> tuple[SchedulerCampaignStatus, tuple[SchedulerPassKind, ...], SchedulerPassKind | None]:
    completed = tuple(
        result.plan.pass_kind
        for result in pass_results
        if result.status is SchedulerPassStatus.COMPLETE
    )
    if any(result.status is SchedulerPassStatus.FAILED for result in pass_results):
        return SchedulerCampaignStatus.FAILED, completed, None
    if any(result.status is SchedulerPassStatus.INCONCLUSIVE for result in pass_results):
        return SchedulerCampaignStatus.INCONCLUSIVE, completed, None
    if any(result.status is SchedulerPassStatus.INCOMPLETE for result in pass_results):
        return SchedulerCampaignStatus.INCOMPLETE, completed, None
    if len(pass_results) == len(SCHEDULER_PASS_ORDER):
        return SchedulerCampaignStatus.COMPLETE, completed, None
    return SchedulerCampaignStatus.INCOMPLETE, completed, SCHEDULER_PASS_ORDER[len(pass_results)]


class SchedulerCampaignSummary(StrictModel):
    """A fail-closed derived view of a contiguous campaign result prefix."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    manifest: SchedulerCampaignManifest
    pass_results: tuple[SchedulerPassResult, ...] = Field(max_length=7)
    status: SchedulerCampaignStatus
    completed_passes: tuple[SchedulerPassKind, ...]
    next_pass: SchedulerPassKind | None
    summary_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        manifest: SchedulerCampaignManifest,
        pass_results: Iterable[SchedulerPassResult],
    ) -> SchedulerCampaignSummary:
        validated_manifest = SchedulerCampaignManifest.model_validate(
            manifest.model_dump(mode="python")
        )
        order = {kind: index for index, kind in enumerate(SCHEDULER_PASS_ORDER)}
        canonical_results = tuple(
            sorted(
                (
                    SchedulerPassResult.model_validate(item.model_dump(mode="python"))
                    for item in pass_results
                ),
                key=lambda item: order[item.plan.pass_kind],
            )
        )
        status, completed, next_pass = _derived_campaign_state(canonical_results)
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "evidence_authority": "comparison_required",
            "manifest": validated_manifest,
            "pass_results": canonical_results,
            "status": status,
            "completed_passes": completed,
            "next_pass": next_pass,
        }
        return cls(**values, summary_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def summary_is_an_exact_ordered_derivation(self) -> Self:
        observed_kinds = tuple(result.plan.pass_kind for result in self.pass_results)
        if observed_kinds != SCHEDULER_PASS_ORDER[: len(self.pass_results)]:
            raise ValueError("scheduler summary results must be an exact contiguous pass prefix")
        prior_results: list[SchedulerPassResult] = []
        for result in self.pass_results:
            if result.plan.manifest != self.manifest:
                raise ValueError("scheduler pass result belongs to a different campaign")
            expected_dependencies = tuple(
                SchedulerPassDependency.from_result(prior) for prior in prior_results
            )
            if result.plan.dependencies != expected_dependencies:
                raise ValueError("scheduler pass does not bind the exact prior result artifacts")
            if any(prior.status is not SchedulerPassStatus.COMPLETE for prior in prior_results):
                raise ValueError("scheduler cannot execute a later pass after incomplete evidence")
            prior_results.append(result)
        all_tasks = tuple(task for result in self.pass_results for task in result.plan.tasks)
        all_task_results = tuple(
            task_result for result in self.pass_results for task_result in result.task_results
        )
        for label, identifiers in (
            ("task", tuple(task.task_id for task in all_tasks)),
            ("logical request", tuple(task.logical_request_id for task in all_tasks)),
            ("task result", tuple(result.result_id for result in all_task_results)),
        ):
            if len(identifiers) != len(set(identifiers)):
                raise ValueError(f"scheduler campaign reuses a {label} identity")
        expected = _derived_campaign_state(self.pass_results)
        if (self.status, self.completed_passes, self.next_pass) != expected:
            raise ValueError("scheduler campaign state was not derived from exact pass results")
        if self.status is SchedulerCampaignStatus.COMPLETE and (
            len(self.pass_results) != len(SCHEDULER_PASS_ORDER)
            or self.completed_passes != SCHEDULER_PASS_ORDER
        ):
            raise ValueError("scheduler campaign cannot complete without all mandatory passes")
        if self.summary_sha256 != _model_sha256(self, exclude={"summary_sha256"}):
            raise ValueError("scheduler campaign summary hash is inconsistent")
        return self


class SchedulerTerminalReportAuthority(StrictModel):
    """Private write-once authority for the report's terminal evidence projection.

    The scheduler stores only canonical payload hashes here.  Source-rich findings and
    model output remain in their existing private/public artifacts, while this record
    prevents a later report-manifest reseal from changing terminal dispositions or the
    accepted candidate inventory.  The campaign summary binds the authority to the exact
    completed or incomplete pass prefix that produced it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1"] = "1.1"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    algorithm: Literal[
        "mmaudit.scheduler-terminal-report-authority.v1",
        "mmaudit.scheduler-terminal-report-authority.v2",
    ] = "mmaudit.scheduler-terminal-report-authority.v2"
    campaign_id: str = Field(pattern=r"^scheduler-campaign-[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    summary_sha256: str = Field(pattern=_SHA256_PATTERN)
    campaign_status: SchedulerCampaignStatus
    severity_threshold: Severity
    candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    candidate_payload_sha256s: dict[str, str] = Field(max_length=100_000)
    final_finding_ids: tuple[str, ...] = Field(max_length=100_000)
    rejected_finding_ids: tuple[str, ...] = Field(max_length=100_000)
    filtered_finding_ids: tuple[str, ...] = Field(max_length=100_000)
    final_finding_payload_sha256s: dict[str, str] = Field(max_length=100_000)
    rejected_finding_payload_sha256s: dict[str, str] = Field(max_length=100_000)
    filtered_finding_payload_sha256s: dict[str, str] = Field(max_length=100_000)
    report_quality_payload_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    consensus_review: SchedulerEvidencePayloadBinding | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    verification_decisions: tuple[SchedulerEvidencePayloadBinding, ...] | None = Field(
        default=None,
        max_length=100_000,
        exclude_if=lambda value: value is None,
    )
    cross_examination_decisions: tuple[SchedulerEvidencePayloadBinding, ...] | None = Field(
        default=None,
        max_length=100_000,
        exclude_if=lambda value: value is None,
    )
    falsification_decisions: tuple[SchedulerEvidencePayloadBinding, ...] | None = Field(
        default=None,
        max_length=100_000,
        exclude_if=lambda value: value is None,
    )
    reproduction_results: tuple[SchedulerEvidencePayloadBinding, ...] | None = Field(
        default=None,
        max_length=100_000,
        exclude_if=lambda value: value is None,
    )
    reproduction_resolutions: tuple[SchedulerEvidencePayloadBinding, ...] | None = Field(
        default=None,
        max_length=100_000,
        exclude_if=lambda value: value is None,
    )
    authority_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        manifest: SchedulerCampaignManifest,
        summary: SchedulerCampaignSummary,
        severity_threshold: Severity,
        candidates: Iterable[CandidateFinding],
        final_findings: Iterable[Finding],
        rejected_findings: Iterable[Finding],
        filtered_findings: Iterable[Finding],
        report_quality_review: ReportQualityReview | None,
        verification_decisions: Iterable[VerificationDecision],
        cross_examination_decisions: Iterable[CandidateCrossExaminationDecision],
        falsification_decisions: Iterable[FalsificationDecision],
        reproduction_results: Iterable[ReproductionResult],
        reproduction_resolutions: Iterable[CandidateReproductionResolution],
        consensus_review: ConsensusReviewArtifact | None = None,
    ) -> SchedulerTerminalReportAuthority:
        validated_manifest = SchedulerCampaignManifest.model_validate(
            manifest.model_dump(mode="python")
        )
        validated_summary = SchedulerCampaignSummary.model_validate(
            summary.model_dump(mode="python")
        )
        if validated_summary.manifest != validated_manifest:
            raise ValueError("scheduler terminal authority belongs to a different manifest")

        canonical_candidates = tuple(
            sorted(
                (
                    CandidateFinding.model_validate(item.model_dump(mode="python"))
                    for item in candidates
                ),
                key=lambda item: item.candidate_id,
            )
        )
        canonical_final = cls._canonical_findings(final_findings)
        canonical_rejected = cls._canonical_findings(rejected_findings)
        canonical_filtered = cls._canonical_findings(filtered_findings)
        candidate_ids = tuple(item.candidate_id for item in canonical_candidates)
        if candidate_ids != tuple(sorted(set(candidate_ids))):
            raise ValueError("scheduler terminal authority repeats a candidate identity")
        canonical_candidate_payload_sha256s = {
            item.candidate_id: scheduler_canonical_sha256(item.model_dump(mode="json"))
            for item in canonical_candidates
        }
        cls._require_valid_finding_partitions(
            severity_threshold=severity_threshold,
            final_findings=canonical_final,
            rejected_findings=canonical_rejected,
            filtered_findings=canonical_filtered,
        )
        report_quality = (
            ReportQualityReview.model_validate(report_quality_review.model_dump(mode="python"))
            if report_quality_review is not None
            else None
        )
        canonical_verifications = tuple(
            sorted(
                (VerificationDecision.model_validate(item) for item in verification_decisions),
                key=lambda item: item.candidate_id,
            )
        )
        canonical_cross_examinations = tuple(
            CandidateCrossExaminationDecision.model_validate(item)
            for item in cross_examination_decisions
        )
        canonical_falsifications = tuple(
            FalsificationDecision.model_validate(item) for item in falsification_decisions
        )
        canonical_reproductions = tuple(
            ReproductionResult.model_validate(item) for item in reproduction_results
        )
        canonical_resolutions = tuple(
            CandidateReproductionResolution.model_validate(item)
            for item in reproduction_resolutions
        )
        canonical_consensus_review = (
            ConsensusReviewArtifact.model_validate(consensus_review.model_dump(mode="python"))
            if consensus_review is not None
            else None
        )
        if canonical_consensus_review is not None and (
            canonical_consensus_review.campaign_id != validated_manifest.campaign_id
            or canonical_consensus_review.manifest_sha256 != validated_manifest.manifest_sha256
            or not set(canonical_consensus_review.candidate_ids) <= set(candidate_ids)
            or any(
                canonical_consensus_review.candidate_payload_sha256s[candidate_id]
                != canonical_candidate_payload_sha256s[candidate_id]
                for candidate_id in canonical_consensus_review.candidate_ids
            )
            or canonical_verifications
            != tuple(
                canonical_consensus_review.reviewers[0]
                .decision_for(candidate_id)
                .as_verification_decision()
                for candidate_id in canonical_consensus_review.candidate_ids
            )
        ):
            raise ValueError("scheduler consensus review differs from campaign candidate authority")
        cls._require_unique_semantic_keys(
            ((item.candidate_id,) for item in canonical_verifications),
            "verification",
        )
        cls._require_unique_semantic_keys(
            (
                (item.candidate_id, str(item.reviewer_index))
                for item in canonical_cross_examinations
            ),
            "cross-examination",
        )
        cls._require_unique_semantic_keys(
            ((item.candidate_id, item.test_name) for item in canonical_falsifications),
            "falsification",
        )
        cls._require_unique_semantic_keys(
            ((item.candidate_id, item.test_name) for item in canonical_reproductions),
            "reproduction",
        )
        cls._require_unique_semantic_keys(
            ((item.candidate_id,) for item in canonical_resolutions),
            "reproduction resolution",
        )
        values: dict[str, Any] = {
            "schema_version": "1.1",
            "evidence_authority": "comparison_required",
            "algorithm": "mmaudit.scheduler-terminal-report-authority.v2",
            "campaign_id": validated_manifest.campaign_id,
            "manifest_sha256": validated_manifest.manifest_sha256,
            "summary_sha256": validated_summary.summary_sha256,
            "campaign_status": validated_summary.status,
            "severity_threshold": severity_threshold,
            "candidate_ids": candidate_ids,
            "candidate_payload_sha256s": canonical_candidate_payload_sha256s,
            "final_finding_ids": tuple(item.id for item in canonical_final),
            "rejected_finding_ids": tuple(item.id for item in canonical_rejected),
            "filtered_finding_ids": tuple(item.id for item in canonical_filtered),
            "final_finding_payload_sha256s": cls._finding_payload_hashes(canonical_final),
            "rejected_finding_payload_sha256s": cls._finding_payload_hashes(canonical_rejected),
            "filtered_finding_payload_sha256s": cls._finding_payload_hashes(canonical_filtered),
            "report_quality_payload_sha256": (
                scheduler_canonical_sha256(report_quality.model_dump(mode="json"))
                if report_quality is not None
                else None
            ),
            "verification_decisions": cls._evidence_payload_bindings(
                "verification",
                ((item.candidate_id, item) for item in canonical_verifications),
            ),
            "cross_examination_decisions": cls._evidence_payload_bindings(
                "cross_examination",
                ((item.candidate_id, item) for item in canonical_cross_examinations),
            ),
            "falsification_decisions": cls._evidence_payload_bindings(
                "falsification",
                ((item.candidate_id, item) for item in canonical_falsifications),
            ),
            "reproduction_results": cls._evidence_payload_bindings(
                "reproduction",
                ((item.candidate_id, item) for item in canonical_reproductions),
            ),
            "reproduction_resolutions": cls._evidence_payload_bindings(
                "reproduction_resolution",
                ((item.candidate_id, item) for item in canonical_resolutions),
            ),
        }
        if canonical_consensus_review is not None:
            values["consensus_review"] = SchedulerEvidencePayloadBinding.build(
                kind="consensus_review",
                subject_id=canonical_consensus_review.campaign_id,
                payload=canonical_consensus_review,
            )
        return cls(**values, authority_sha256=scheduler_canonical_sha256(values))

    @staticmethod
    def _canonical_findings(findings: Iterable[Finding]) -> tuple[Finding, ...]:
        return tuple(
            sorted(
                (Finding.model_validate(item.model_dump(mode="python")) for item in findings),
                key=lambda item: item.id,
            )
        )

    @staticmethod
    def _finding_payload_hashes(findings: tuple[Finding, ...]) -> dict[str, str]:
        return {
            item.id: scheduler_canonical_sha256(item.model_dump(mode="json")) for item in findings
        }

    @staticmethod
    def _require_unique_semantic_keys(
        keys: Iterable[tuple[str, ...]],
        label: str,
    ) -> None:
        materialized = tuple(keys)
        if len(materialized) != len(set(materialized)):
            raise ValueError(f"scheduler terminal {label} evidence repeats a semantic identity")

    @staticmethod
    def _evidence_payload_bindings(
        kind: Literal[
            "verification",
            "cross_examination",
            "falsification",
            "reproduction",
            "reproduction_resolution",
        ],
        records: Iterable[tuple[str, BaseModel]],
    ) -> tuple[SchedulerEvidencePayloadBinding, ...]:
        bindings = tuple(
            sorted(
                (
                    SchedulerEvidencePayloadBinding.build(
                        kind=kind,
                        subject_id=subject_id,
                        payload=payload,
                    )
                    for subject_id, payload in records
                ),
                key=lambda item: (item.subject_id, item.record_id),
            )
        )
        identities = tuple((item.subject_id, item.record_id) for item in bindings)
        if len(identities) != len(set(identities)):
            raise ValueError(f"scheduler terminal {kind} evidence contains an exact duplicate")
        return bindings

    @staticmethod
    def _require_valid_finding_partitions(
        *,
        severity_threshold: Severity,
        final_findings: tuple[Finding, ...],
        rejected_findings: tuple[Finding, ...],
        filtered_findings: tuple[Finding, ...],
    ) -> None:
        inventories = (final_findings, rejected_findings, filtered_findings)
        identifiers = tuple(item.id for inventory in inventories for item in inventory)
        if identifiers and len(identifiers) != len(set(identifiers)):
            raise ValueError("scheduler terminal finding partitions overlap")
        if any(item.status is FindingStatus.REJECTED for item in final_findings):
            raise ValueError("scheduler final finding partition contains a rejection")
        if any(item.status is not FindingStatus.REJECTED for item in rejected_findings):
            raise ValueError("scheduler rejected finding partition contains an active finding")
        if any(item.status is FindingStatus.REJECTED for item in filtered_findings):
            raise ValueError("scheduler filtered finding partition contains a rejection")
        threshold_rank = SEVERITY_ORDER[severity_threshold.value]
        if any(
            item.origin_kind is not FindingOriginKind.DETERMINISTIC_EXECUTION
            and SEVERITY_ORDER[item.severity.value] < threshold_rank
            for item in final_findings
        ):
            raise ValueError("scheduler final finding partition violates its severity threshold")
        if any(
            item.origin_kind is FindingOriginKind.DETERMINISTIC_EXECUTION
            or SEVERITY_ORDER[item.severity.value] >= threshold_rank
            for item in filtered_findings
        ):
            raise ValueError("scheduler filtered finding partition violates its severity threshold")

    def require_exact_judgment(self, judgment: SchedulerEvidenceCapJudgmentOutput) -> None:
        """Require exact pass-seven terminal/candidate authority when that pass succeeded."""

        terminal_projection_differs = (
            self.severity_threshold != judgment.severity_threshold
            or self.candidate_ids != judgment.candidate_ids
            or self.candidate_payload_sha256s != judgment.candidate_payload_sha256s
            or self.final_finding_ids != judgment.final_finding_ids
            or self.rejected_finding_ids != judgment.rejected_finding_ids
            or self.filtered_finding_ids != judgment.filtered_finding_ids
            or self.final_finding_payload_sha256s != judgment.final_finding_payload_sha256s
            or self.rejected_finding_payload_sha256s != judgment.rejected_finding_payload_sha256s
            or self.filtered_finding_payload_sha256s != judgment.filtered_finding_payload_sha256s
        )
        evidence_projection_differs = self.schema_version == "1.1" and (
            self.consensus_review != judgment.consensus_review
            or self.verification_decisions != judgment.verification_decisions
            or self.cross_examination_decisions != judgment.cross_examination_decisions
            or self.falsification_decisions != judgment.falsification_decisions
            or self.reproduction_results != judgment.reproduction_results
            or self.reproduction_resolutions != judgment.reproduction_resolutions
        )
        if terminal_projection_differs or evidence_projection_differs:
            raise ValueError("scheduler terminal report authority differs from pass-seven judgment")

    @model_validator(mode="after")
    def inventories_bind_the_exact_authority_hash(self) -> Self:
        expected_algorithm = {
            "1.0": "mmaudit.scheduler-terminal-report-authority.v1",
            "1.1": "mmaudit.scheduler-terminal-report-authority.v2",
        }[self.schema_version]
        evidence_inventories = (
            ("verification", self.verification_decisions),
            ("cross_examination", self.cross_examination_decisions),
            ("falsification", self.falsification_decisions),
            ("reproduction", self.reproduction_results),
            ("reproduction_resolution", self.reproduction_resolutions),
        )
        has_complete_evidence_authority = all(
            inventory is not None for _kind, inventory in evidence_inventories
        )
        if (
            self.algorithm != expected_algorithm
            or (self.schema_version == "1.1") != has_complete_evidence_authority
        ):
            raise ValueError("scheduler terminal evidence-authority schema is inconsistent")
        if self.schema_version == "1.0" and (
            self.consensus_review is not None
            or any(inventory is not None for _kind, inventory in evidence_inventories)
        ):
            raise ValueError("legacy scheduler terminal authority cannot claim decision evidence")
        if self.consensus_review is not None and (
            self.consensus_review.subject_id != self.campaign_id
            or self.consensus_review.record_id
            != scheduler_canonical_sha256(
                {
                    "kind": "consensus_review",
                    "subject_id": self.consensus_review.subject_id,
                    "payload_sha256": self.consensus_review.payload_sha256,
                }
            )
        ):
            raise ValueError("scheduler terminal consensus-review binding is inconsistent")

        inventories = (
            (
                self.candidate_ids,
                self.candidate_payload_sha256s,
                "candidate",
            ),
            (
                self.final_finding_ids,
                self.final_finding_payload_sha256s,
                "final finding",
            ),
            (
                self.rejected_finding_ids,
                self.rejected_finding_payload_sha256s,
                "rejected finding",
            ),
            (
                self.filtered_finding_ids,
                self.filtered_finding_payload_sha256s,
                "filtered finding",
            ),
        )
        for identifiers, payload_hashes, label in inventories:
            if (
                identifiers != tuple(sorted(set(identifiers)))
                or tuple(payload_hashes) != identifiers
                or any(
                    re.fullmatch(_SHA256_PATTERN, value) is None
                    for value in payload_hashes.values()
                )
            ):
                raise ValueError(f"scheduler terminal {label} payload inventory is not canonical")
        finding_ids = (
            *self.final_finding_ids,
            *self.rejected_finding_ids,
            *self.filtered_finding_ids,
        )
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("scheduler terminal finding partitions overlap")
        candidate_subjects = set(self.candidate_ids)
        for kind, inventory in evidence_inventories:
            if inventory is None:
                continue
            identities = tuple((item.subject_id, item.record_id) for item in inventory)
            if identities != tuple(sorted(set(identities))) or any(
                item.record_id
                != scheduler_canonical_sha256(
                    {
                        "kind": kind,
                        "subject_id": item.subject_id,
                        "payload_sha256": item.payload_sha256,
                    }
                )
                for item in inventory
            ):
                raise ValueError(f"scheduler terminal {kind} evidence inventory is not canonical")
            if not {item.subject_id for item in inventory} <= candidate_subjects:
                raise ValueError(
                    f"scheduler terminal {kind} evidence references unknown candidates"
                )
        if self.reproduction_resolutions is not None and len(
            {item.subject_id for item in self.reproduction_resolutions}
        ) != len(self.reproduction_resolutions):
            raise ValueError("scheduler terminal reproduction resolutions repeat a candidate")
        if self.authority_sha256 != _model_sha256(self, exclude={"authority_sha256"}):
            raise ValueError("scheduler terminal report authority hash is inconsistent")
        return self


class SchedulerJournalEvidence(StrictModel):
    """Public exact hash-and-count projection of controller-owned journal state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1", "1.2", "1.3"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    campaign_id: str = Field(pattern=r"^scheduler-campaign-[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    summary_sha256: str = Field(pattern=_SHA256_PATTERN)
    analysis_input_sha256: str = Field(pattern=_SHA256_PATTERN)
    analysis_input_descriptor_sha256s: tuple[str, ...] = Field(
        min_length=len(SCHEDULER_ANALYSIS_INPUT_LABELS_V1),
        max_length=len(SCHEDULER_ANALYSIS_INPUT_LABELS),
    )
    analysis_input_descriptor_count: int = Field(
        ge=len(SCHEDULER_ANALYSIS_INPUT_LABELS_V1),
        le=len(SCHEDULER_ANALYSIS_INPUT_LABELS),
    )
    shard_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    pass_plan_sha256s: tuple[str, ...] = Field(max_length=7)
    task_plan_sha256s: tuple[str, ...] = Field(max_length=700_000)
    model_request_evidence_sha256s: tuple[str, ...] = Field(max_length=700_000)
    task_activation_sha256s: tuple[str, ...] = Field(max_length=700_000)
    task_output_artifact_sha256s: tuple[str, ...] = Field(max_length=700_000)
    retrieval_binding_sha256s: tuple[str, ...] = Field(
        default=(),
        max_length=700_000,
        exclude_if=lambda value: not value,
    )
    provider_attempt_evidence_sha256s: tuple[str, ...] = Field(max_length=700_000)
    task_result_sha256s: tuple[str, ...] = Field(max_length=700_000)
    result_observation_sha256s: tuple[str, ...] = Field(max_length=1_400_000)
    pass_result_sha256s: tuple[str, ...] = Field(max_length=7)
    event_sha256s: tuple[str, ...] = Field(max_length=2_800_000)
    truncation_recovery_entry_sha256s: tuple[str, ...] = Field(
        default=(),
        max_length=SCHEDULER_TRUNCATION_RECOVERY_MAX_ENTRIES,
        exclude_if=lambda value: not value,
    )
    terminal_event_chain_head_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    truncation_recovery_chain_head_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    terminal_report_authority_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    pass_plan_count: int = Field(ge=0, le=7)
    task_plan_count: int = Field(ge=0, le=700_000)
    model_request_count: int = Field(ge=0, le=700_000)
    task_activation_count: int = Field(ge=0, le=700_000)
    task_output_count: int = Field(ge=0, le=700_000)
    retrieval_binding_count: int = Field(
        default=0,
        ge=0,
        le=700_000,
        exclude_if=lambda value: value == 0,
    )
    provider_attempt_count: int = Field(ge=0, le=700_000)
    task_result_count: int = Field(ge=0, le=700_000)
    result_observation_count: int = Field(ge=0, le=1_400_000)
    preflight_failure_count: int = Field(ge=0, le=700_000)
    pass_result_count: int = Field(ge=0, le=7)
    event_count: int = Field(ge=0, le=2_800_000)
    truncation_recovery_entry_count: int = Field(
        default=0,
        ge=0,
        le=SCHEDULER_TRUNCATION_RECOVERY_MAX_ENTRIES,
        exclude_if=lambda value: value == 0,
    )
    succeeded_count: int = Field(ge=0, le=700_000)
    explicit_empty_count: int = Field(ge=0, le=7)
    failed_count: int = Field(ge=0, le=700_000)
    truncated_count: int = Field(ge=0, le=700_000)
    invalid_count: int = Field(ge=0, le=700_000)
    unbound_count: int = Field(ge=0, le=700_000)
    inconclusive_count: int = Field(ge=0, le=700_000)
    uncertain_count: int = Field(ge=0, le=700_000)
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "analysis_input_descriptor_sha256s",
        "pass_plan_sha256s",
        "task_plan_sha256s",
        "model_request_evidence_sha256s",
        "task_activation_sha256s",
        "task_output_artifact_sha256s",
        "retrieval_binding_sha256s",
        "provider_attempt_evidence_sha256s",
        "task_result_sha256s",
        "result_observation_sha256s",
        "pass_result_sha256s",
        "event_sha256s",
        "truncation_recovery_entry_sha256s",
    )
    @classmethod
    def detached_hash_inventory_is_valid_and_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(
            re.fullmatch(_SHA256_PATTERN, item) is None for item in value
        ):
            raise ValueError("scheduler journal hash inventories must be valid and unique")
        return value

    @classmethod
    def _project_validated_state(
        cls,
        *,
        manifest: SchedulerCampaignManifest,
        analysis_input_inventory: SchedulerAnalysisInputInventory,
        summary: SchedulerCampaignSummary,
        plans: tuple[SchedulerPassPlan, ...],
        model_requests: tuple[SchedulerModelRequestEvidence, ...],
        activations: tuple[SchedulerTaskActivation, ...],
        outputs: tuple[SchedulerTaskOutput, ...],
        retrieval_bindings: tuple[SchedulerRetrievalBinding, ...],
        provider_attempts: tuple[SchedulerProviderAttemptEvidence, ...],
        task_results: tuple[SchedulerTaskResult, ...],
        result_observations: tuple[SchedulerTaskResult, ...],
        events: tuple[SchedulerTaskEvent, ...],
        truncation_recovery_entries: tuple[SchedulerTruncationRecoveryEntry, ...],
        terminal_report_authority: SchedulerTerminalReportAuthority | None,
    ) -> SchedulerJournalEvidence:
        """Build the one canonical projection after its private graph is validated."""

        tasks = tuple(task for plan in plans for task in plan.tasks)
        status_counts = {
            status: sum(result.terminal_status is status for result in task_results)
            for status in SchedulerTerminalStatus
        }
        values: dict[str, Any] = {
            "schema_version": (
                "1.3"
                if terminal_report_authority is not None and truncation_recovery_entries
                else "1.2"
                if truncation_recovery_entries
                else "1.1"
                if terminal_report_authority is not None
                else "1.0"
            ),
            "evidence_authority": "comparison_required",
            "campaign_id": manifest.campaign_id,
            "manifest_sha256": manifest.manifest_sha256,
            "summary_sha256": summary.summary_sha256,
            "analysis_input_sha256": analysis_input_inventory.analysis_input_sha256,
            "analysis_input_descriptor_sha256s": tuple(
                item.descriptor_sha256 for item in analysis_input_inventory.descriptors
            ),
            "analysis_input_descriptor_count": len(analysis_input_inventory.descriptors),
            "shard_inventory_sha256": manifest.shard_inventory.inventory_sha256,
            "pass_plan_sha256s": tuple(item.pass_plan_sha256 for item in plans),
            "task_plan_sha256s": tuple(item.task_plan_sha256 for item in tasks),
            "model_request_evidence_sha256s": tuple(
                item.request_evidence_sha256 for item in model_requests
            ),
            "task_activation_sha256s": tuple(item.activation_sha256 for item in activations),
            "task_output_artifact_sha256s": tuple(item.output_artifact_sha256 for item in outputs),
            **(
                {
                    "retrieval_binding_sha256s": tuple(
                        item.binding_sha256 for item in retrieval_bindings
                    ),
                    "retrieval_binding_count": len(retrieval_bindings),
                }
                if retrieval_bindings
                else {}
            ),
            "provider_attempt_evidence_sha256s": tuple(
                item.attempt_evidence_sha256 for item in provider_attempts
            ),
            "task_result_sha256s": tuple(item.result_sha256 for item in task_results),
            "result_observation_sha256s": tuple(item.result_sha256 for item in result_observations),
            "pass_result_sha256s": tuple(item.pass_result_sha256 for item in summary.pass_results),
            "event_sha256s": tuple(item.event_sha256 for item in events),
            **(
                {
                    "truncation_recovery_entry_sha256s": tuple(
                        item.entry_sha256 for item in truncation_recovery_entries
                    ),
                    "truncation_recovery_chain_head_sha256": (
                        truncation_recovery_entries[-1].entry_sha256
                    ),
                    "truncation_recovery_entry_count": len(truncation_recovery_entries),
                }
                if truncation_recovery_entries
                else {}
            ),
            "terminal_event_chain_head_sha256": (events[-1].event_sha256 if events else None),
            **(
                {"terminal_report_authority_sha256": (terminal_report_authority.authority_sha256)}
                if terminal_report_authority is not None
                else {}
            ),
            "pass_plan_count": len(plans),
            "task_plan_count": len(tasks),
            "model_request_count": len(model_requests),
            "task_activation_count": len(activations),
            "task_output_count": len(outputs),
            "provider_attempt_count": len(provider_attempts),
            "task_result_count": len(task_results),
            "result_observation_count": len(result_observations),
            "preflight_failure_count": sum(
                item.result_origin is SchedulerResultOrigin.LOCAL_PREFLIGHT for item in task_results
            ),
            "pass_result_count": len(summary.pass_results),
            "event_count": len(events),
            "succeeded_count": status_counts[SchedulerTerminalStatus.SUCCEEDED],
            "explicit_empty_count": status_counts[SchedulerTerminalStatus.EXPLICIT_EMPTY],
            "failed_count": status_counts[SchedulerTerminalStatus.FAILED],
            "truncated_count": status_counts[SchedulerTerminalStatus.TRUNCATED],
            "invalid_count": status_counts[SchedulerTerminalStatus.INVALID],
            "unbound_count": status_counts[SchedulerTerminalStatus.UNBOUND],
            "inconclusive_count": status_counts[SchedulerTerminalStatus.INCONCLUSIVE],
            "uncertain_count": status_counts[SchedulerTerminalStatus.UNCERTAIN],
        }
        return cls(**values, evidence_sha256=scheduler_canonical_sha256(values))

    @classmethod
    def _build_from_validated_retained_state(
        cls,
        *,
        manifest: SchedulerCampaignManifest,
        analysis_input_inventory: SchedulerAnalysisInputInventory,
        summary: SchedulerCampaignSummary,
        plans: Iterable[SchedulerPassPlan],
        model_requests: Iterable[SchedulerModelRequestEvidence],
        activations: Iterable[SchedulerTaskActivation],
        outputs: Iterable[SchedulerTaskOutput],
        retrieval_bindings: Iterable[SchedulerRetrievalBinding] = (),
        provider_attempts: Iterable[SchedulerProviderAttemptEvidence] = (),
        task_results: Iterable[SchedulerTaskResult],
        result_observations: Iterable[SchedulerTaskResult],
        events: Iterable[SchedulerTaskEvent],
        truncation_recovery_entries: Iterable[SchedulerTruncationRecoveryEntry] = (),
        terminal_report_authority: SchedulerTerminalReportAuthority | None = None,
    ) -> SchedulerJournalEvidence:
        """Project frozen controller-owned state without repeating full graph validation."""

        if (
            analysis_input_inventory.analysis_input_sha256
            != manifest.bindings.analysis_input_sha256
        ):
            raise ValueError("scheduler analysis-input inventory differs from campaign bindings")
        if (
            terminal_report_authority is not None
            and not manifest.terminal_report_authority_required
        ):
            raise ValueError(
                "scheduler journal evidence differs from campaign terminal-authority mode"
            )
        return cls._project_validated_state(
            manifest=manifest,
            analysis_input_inventory=analysis_input_inventory,
            summary=summary,
            plans=tuple(sorted(plans, key=lambda item: _pass_index(item.pass_kind))),
            model_requests=tuple(sorted(model_requests, key=lambda item: item.task_id)),
            activations=tuple(sorted(activations, key=lambda item: item.task_id)),
            outputs=tuple(sorted(outputs, key=lambda item: item.task_id)),
            retrieval_bindings=tuple(
                sorted(retrieval_bindings, key=lambda item: item.planner_task_id)
            ),
            provider_attempts=tuple(sorted(provider_attempts, key=lambda item: item.task_id)),
            task_results=tuple(sorted(task_results, key=lambda item: item.task_id)),
            result_observations=tuple(
                sorted(result_observations, key=lambda item: (item.task_id, item.result_sha256))
            ),
            events=tuple(sorted(events, key=lambda item: item.event_index)),
            truncation_recovery_entries=tuple(truncation_recovery_entries),
            terminal_report_authority=terminal_report_authority,
        )

    @classmethod
    def build(
        cls,
        *,
        manifest: SchedulerCampaignManifest,
        analysis_input_inventory: SchedulerAnalysisInputInventory,
        summary: SchedulerCampaignSummary,
        plans: Iterable[SchedulerPassPlan],
        model_requests: Iterable[SchedulerModelRequestEvidence],
        activations: Iterable[SchedulerTaskActivation],
        outputs: Iterable[SchedulerTaskOutput],
        retrieval_bindings: Iterable[SchedulerRetrievalBinding] = (),
        provider_attempts: Iterable[SchedulerProviderAttemptEvidence] = (),
        task_results: Iterable[SchedulerTaskResult],
        result_observations: Iterable[SchedulerTaskResult],
        events: Iterable[SchedulerTaskEvent],
        truncation_recovery_entries: Iterable[SchedulerTruncationRecoveryEntry] = (),
        terminal_report_authority: SchedulerTerminalReportAuthority | None = None,
    ) -> SchedulerJournalEvidence:
        validated_manifest = SchedulerCampaignManifest.model_validate(
            manifest.model_dump(mode="python")
        )
        validated_analysis_inputs = SchedulerAnalysisInputInventory.model_validate(
            analysis_input_inventory.model_dump(mode="python")
        )
        if (
            validated_analysis_inputs.analysis_input_sha256
            != validated_manifest.bindings.analysis_input_sha256
        ):
            raise ValueError("scheduler analysis-input inventory differs from campaign bindings")
        validated_summary = SchedulerCampaignSummary.model_validate(
            summary.model_dump(mode="python")
        )
        canonical_plans = tuple(
            sorted(
                (
                    SchedulerPassPlan.model_validate(item.model_dump(mode="python"))
                    for item in plans
                ),
                key=lambda item: _pass_index(item.pass_kind),
            )
        )
        canonical_activations = tuple(
            sorted(
                (
                    SchedulerTaskActivation.model_validate(item.model_dump(mode="python"))
                    for item in activations
                ),
                key=lambda item: item.task_id,
            )
        )
        canonical_model_requests = tuple(
            sorted(
                (
                    SchedulerModelRequestEvidence.model_validate(item.model_dump(mode="python"))
                    for item in model_requests
                ),
                key=lambda item: item.task_id,
            )
        )
        canonical_outputs = tuple(
            sorted(
                (
                    SchedulerTaskOutput.model_validate(item.model_dump(mode="python"))
                    for item in outputs
                ),
                key=lambda item: item.task_id,
            )
        )
        canonical_retrieval_bindings = tuple(
            sorted(
                (
                    SchedulerRetrievalBinding.model_validate(item.model_dump(mode="python"))
                    for item in retrieval_bindings
                ),
                key=lambda item: item.planner_task_id,
            )
        )
        canonical_provider_attempts = tuple(
            sorted(
                (
                    SchedulerProviderAttemptEvidence.model_validate(item.model_dump(mode="python"))
                    for item in provider_attempts
                ),
                key=lambda item: item.task_id,
            )
        )
        canonical_results = tuple(
            sorted(
                (
                    SchedulerTaskResult.model_validate(item.model_dump(mode="python"))
                    for item in task_results
                ),
                key=lambda item: item.task_id,
            )
        )
        canonical_observations = tuple(
            sorted(
                (
                    SchedulerTaskResult.model_validate(item.model_dump(mode="python"))
                    for item in result_observations
                ),
                key=lambda item: (item.task_id, item.result_sha256),
            )
        )
        canonical_events = tuple(
            sorted(
                (
                    SchedulerTaskEvent.model_validate(item.model_dump(mode="python"))
                    for item in events
                ),
                key=lambda item: item.event_index,
            )
        )
        canonical_recovery_entries = validate_truncation_recovery_entry_chain(
            truncation_recovery_entries
        )
        canonical_terminal_authority = (
            SchedulerTerminalReportAuthority.model_validate(
                terminal_report_authority.model_dump(mode="python")
            )
            if terminal_report_authority is not None
            else None
        )
        # An active production journal needs a comparison-only prefix projection for
        # its local rollback checkpoint before the final authority artifact exists.
        # SchedulerArtifact still rejects that prefix for a manifest that requires
        # terminal authority, so this cannot promote the checkpoint into authority.
        if (
            canonical_terminal_authority is not None
            and not validated_manifest.terminal_report_authority_required
        ):
            raise ValueError(
                "scheduler journal evidence differs from campaign terminal-authority mode"
            )
        _validate_scheduler_journal_evidence(
            manifest=validated_manifest,
            summary=validated_summary,
            plans=canonical_plans,
            activations=canonical_activations,
            outputs=canonical_outputs,
            retrieval_bindings=canonical_retrieval_bindings,
            provider_attempts=canonical_provider_attempts,
            task_results=canonical_results,
            result_observations=canonical_observations,
            events=canonical_events,
            terminal_report_authority=canonical_terminal_authority,
        )
        if canonical_model_requests != build_scheduler_model_request_evidence(
            plans=canonical_plans,
            activations=canonical_activations,
            task_results=canonical_results,
        ):
            raise ValueError("scheduler public model requests differ from exact journal state")
        return cls._project_validated_state(
            manifest=validated_manifest,
            analysis_input_inventory=validated_analysis_inputs,
            summary=validated_summary,
            plans=canonical_plans,
            model_requests=canonical_model_requests,
            activations=canonical_activations,
            outputs=canonical_outputs,
            retrieval_bindings=canonical_retrieval_bindings,
            provider_attempts=canonical_provider_attempts,
            task_results=canonical_results,
            result_observations=canonical_observations,
            events=canonical_events,
            truncation_recovery_entries=canonical_recovery_entries,
            terminal_report_authority=canonical_terminal_authority,
        )

    @model_validator(mode="after")
    def evidence_counts_chain_and_hash_are_consistent(self) -> Self:
        expected_schema_version = (
            "1.3"
            if self.terminal_report_authority_sha256 is not None
            and self.truncation_recovery_entry_sha256s
            else "1.2"
            if self.truncation_recovery_entry_sha256s
            else "1.1"
            if self.terminal_report_authority_sha256 is not None
            else "1.0"
        )
        if self.schema_version != expected_schema_version:
            raise ValueError(
                "scheduler journal evidence authority or recovery mode is inconsistent"
            )
        pairs = (
            (
                self.analysis_input_descriptor_count,
                len(self.analysis_input_descriptor_sha256s),
            ),
            (self.pass_plan_count, len(self.pass_plan_sha256s)),
            (self.task_plan_count, len(self.task_plan_sha256s)),
            (self.model_request_count, len(self.model_request_evidence_sha256s)),
            (self.task_activation_count, len(self.task_activation_sha256s)),
            (self.task_output_count, len(self.task_output_artifact_sha256s)),
            (self.retrieval_binding_count, len(self.retrieval_binding_sha256s)),
            (
                self.provider_attempt_count,
                len(self.provider_attempt_evidence_sha256s),
            ),
            (self.task_result_count, len(self.task_result_sha256s)),
            (self.result_observation_count, len(self.result_observation_sha256s)),
            (self.pass_result_count, len(self.pass_result_sha256s)),
            (self.event_count, len(self.event_sha256s)),
            (
                self.truncation_recovery_entry_count,
                len(self.truncation_recovery_entry_sha256s),
            ),
        )
        if any(count != observed for count, observed in pairs):
            raise ValueError("scheduler journal evidence counts differ from hash inventories")
        if (self.event_count == 0) != (self.terminal_event_chain_head_sha256 is None):
            raise ValueError("scheduler event-chain head presence is inconsistent")
        if self.event_sha256s and self.terminal_event_chain_head_sha256 != self.event_sha256s[-1]:
            raise ValueError("scheduler event-chain head differs from its terminal event")
        if (self.truncation_recovery_entry_count == 0) != (
            self.truncation_recovery_chain_head_sha256 is None
        ):
            raise ValueError("scheduler recovery-chain head presence is inconsistent")
        if (
            self.truncation_recovery_entry_sha256s
            and self.truncation_recovery_chain_head_sha256
            != self.truncation_recovery_entry_sha256s[-1]
        ):
            raise ValueError("scheduler recovery-chain head differs from its terminal entry")
        status_total = (
            self.succeeded_count
            + self.explicit_empty_count
            + self.failed_count
            + self.truncated_count
            + self.invalid_count
            + self.unbound_count
            + self.inconclusive_count
            + self.uncertain_count
        )
        if status_total != self.task_result_count:
            raise ValueError("scheduler journal terminal status counts are inconsistent")
        if self.preflight_failure_count > self.task_result_count:
            raise ValueError("scheduler preflight-failure count exceeds terminal results")
        if self.result_observation_count < self.task_result_count:
            raise ValueError("scheduler journal omits credited result observations")
        if (
            self.model_request_count > self.task_plan_count
            or self.task_activation_count + self.preflight_failure_count > self.task_plan_count
            or self.task_output_count > self.task_activation_count
            or self.retrieval_binding_count > self.task_plan_count
            or self.provider_attempt_count > self.task_activation_count
            or self.task_output_count + self.provider_attempt_count > self.task_activation_count
            or self.task_result_count > self.task_plan_count
            or self.pass_result_count > self.pass_plan_count
            or self.event_count
            < self.task_plan_count + self.task_activation_count + self.task_result_count
        ):
            raise ValueError("scheduler journal lifecycle counts are structurally inconsistent")
        if self.evidence_sha256 != _model_sha256(self, exclude={"evidence_sha256"}):
            raise ValueError("scheduler journal evidence hash is inconsistent")
        return self


class SchedulerArtifact(StrictModel):
    """Public scheduler envelope requiring controller-derived journal evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1", "1.2", "1.3"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    summary: SchedulerCampaignSummary
    journal_evidence: SchedulerJournalEvidence
    model_requests: tuple[SchedulerModelRequestEvidence, ...] = Field(
        max_length=_MAX_SCHEDULER_MODEL_REQUESTS
    )
    recovery_model_requests: tuple[SchedulerTruncationRecoveryModelRequestEvidence, ...] = Field(
        default=(),
        max_length=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
        exclude_if=lambda value: not value,
    )
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        summary: SchedulerCampaignSummary,
        journal_evidence: SchedulerJournalEvidence,
        model_requests: Iterable[SchedulerModelRequestEvidence],
        recovery_model_requests: Iterable[SchedulerTruncationRecoveryModelRequestEvidence] = (),
    ) -> SchedulerArtifact:
        validated_summary = SchedulerCampaignSummary.model_validate(
            summary.model_dump(mode="python")
        )
        validated_evidence = SchedulerJournalEvidence.model_validate(
            journal_evidence.model_dump(mode="python")
        )
        request_items = _bounded_scheduler_items(
            model_requests,
            limit=_MAX_SCHEDULER_MODEL_REQUESTS,
            label="artifact model-request inventory",
        )
        recovery_request_items = _bounded_scheduler_items(
            recovery_model_requests,
            limit=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
            label="artifact recovery-model-request inventory",
        )
        validated_requests = tuple(
            sorted(
                (
                    SchedulerModelRequestEvidence.model_validate(item.model_dump(mode="python"))
                    for item in request_items
                ),
                key=lambda item: item.task_id,
            )
        )
        validated_recovery_requests = tuple(
            sorted(
                (
                    SchedulerTruncationRecoveryModelRequestEvidence.model_validate_json(
                        item.model_dump_json(),
                        strict=True,
                    )
                    for item in recovery_request_items
                ),
                key=lambda item: item.logical_request_id,
            )
        )
        values: dict[str, Any] = {
            "schema_version": validated_evidence.schema_version,
            "evidence_authority": "comparison_required",
            "summary": validated_summary,
            "journal_evidence": validated_evidence,
            "model_requests": validated_requests,
            **(
                {"recovery_model_requests": validated_recovery_requests}
                if validated_recovery_requests
                else {}
            ),
        }
        return cls(**values, artifact_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def artifact_hash_and_journal_binding_are_exact(self) -> Self:
        evidence = self.journal_evidence
        audit_selection = self.summary.manifest.bindings.audit_model_selection
        request_ids = tuple(item.task_id for item in self.model_requests)
        logical_request_ids = tuple(item.logical_request_id for item in self.model_requests)
        recovery_request_ids = tuple(
            item.logical_request_id for item in self.recovery_model_requests
        )
        recovery_result_sha256s = tuple(
            item.child_result_entry_sha256 for item in self.recovery_model_requests
        )
        recovery_promotions = tuple(
            binding
            for pass_result in self.summary.pass_results
            for binding in pass_result.recovery_promotion_bindings
        )
        recovery_promotion_entry_sha256s = tuple(
            binding.promotion_entry_sha256 for binding in recovery_promotions
        )
        promotion_by_sha256 = {item.promotion_entry_sha256: item for item in recovery_promotions}
        recovery_chain_sha256s = set(evidence.truncation_recovery_entry_sha256s)
        retrieval_preflight_failures = tuple(
            result
            for pass_result in self.summary.pass_results
            for task in pass_result.plan.tasks
            for result in pass_result.task_results
            if task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
            and result.task_id == task.task_id
            and result.result_origin is SchedulerResultOrigin.LOCAL_PREFLIGHT
        )
        expected_analysis_input_descriptor_count = (
            len(SCHEDULER_ANALYSIS_INPUT_LABELS_V1)
            if self.summary.manifest.algorithm_version == "mmaudit.seven-pass-scheduler.v1"
            else len(SCHEDULER_ANALYSIS_INPUT_LABELS)
        )
        if (
            self.schema_version != evidence.schema_version
            or (self.schema_version in {"1.1", "1.3"})
            != self.summary.manifest.terminal_report_authority_required
            or evidence.campaign_id != self.summary.manifest.campaign_id
            or evidence.manifest_sha256 != self.summary.manifest.manifest_sha256
            or evidence.summary_sha256 != self.summary.summary_sha256
            or evidence.analysis_input_sha256
            != self.summary.manifest.bindings.analysis_input_sha256
            or evidence.analysis_input_descriptor_count != expected_analysis_input_descriptor_count
            or evidence.shard_inventory_sha256
            != self.summary.manifest.shard_inventory.inventory_sha256
            or evidence.pass_result_sha256s
            != tuple(item.pass_result_sha256 for item in self.summary.pass_results)
            or request_ids != tuple(sorted(set(request_ids)))
            or len(logical_request_ids) != len(set(logical_request_ids))
            or recovery_request_ids != tuple(sorted(set(recovery_request_ids)))
            or len(recovery_result_sha256s) != len(set(recovery_result_sha256s))
            or set(logical_request_ids).intersection(recovery_request_ids)
            or evidence.model_request_count != len(self.model_requests)
            or evidence.model_request_evidence_sha256s
            != tuple(item.request_evidence_sha256 for item in self.model_requests)
            or len(recovery_promotion_entry_sha256s) != len(set(recovery_promotion_entry_sha256s))
            or len(promotion_by_sha256) != len(recovery_promotions)
            or not set(recovery_promotion_entry_sha256s)
            <= set(evidence.truncation_recovery_entry_sha256s)
            or any(
                binding.schema_version == "1.1"
                and (
                    binding.nested_family_root_sha256 not in recovery_chain_sha256s
                    or binding.nested_family_closure_sha256 not in recovery_chain_sha256s
                    or not set(binding.direct_child_result_sha256s) <= recovery_chain_sha256s
                    or binding.nested_child_result_sha256s is None
                    or not set(binding.nested_child_result_sha256s) <= recovery_chain_sha256s
                )
                for binding in recovery_promotions
            )
            or any(
                item.campaign_id != self.summary.manifest.campaign_id
                or item.manifest_sha256 != self.summary.manifest.manifest_sha256
                for item in self.model_requests
            )
            or any(
                item.campaign_id != self.summary.manifest.campaign_id
                or (
                    item.promotion_entry_sha256 is not None
                    and item.promotion_entry_sha256 not in promotion_by_sha256
                )
                or item.activation_entry_sha256 not in recovery_chain_sha256s
                or item.child_result_entry_sha256 not in recovery_chain_sha256s
                or (
                    item.schema_version in {"1.2", "1.3"}
                    and item.family_root_sha256 not in recovery_chain_sha256s
                )
                or (
                    item.schema_version == "1.2"
                    and item.family_closure_sha256 not in recovery_chain_sha256s
                )
                or (
                    item.dispatch_sha256 is not None
                    and item.dispatch_sha256 not in recovery_chain_sha256s
                )
                or (
                    item.schema_version == "1.3"
                    and item.terminal_status is not SchedulerTerminalStatus.FAILED
                )
                for item in self.recovery_model_requests
            )
        ):
            raise ValueError("scheduler public artifact differs from its journal evidence")
        parent_requests = {item.task_id: item for item in self.model_requests}
        recovery_by_promotion: dict[
            str,
            list[SchedulerTruncationRecoveryModelRequestEvidence],
        ] = {}
        for recovery_request in self.recovery_model_requests:
            parent = parent_requests.get(recovery_request.parent_task_id)
            expected_source_inventory_sha256 = (
                scheduler_canonical_sha256(
                    {
                        "domain": ("mmaudit.scheduler.recovery-delivered-source-inventory.v1"),
                        "source_descriptor_sha256s": (parent.delivered_source_descriptor_sha256s),
                    }
                )
                if parent is not None
                else None
            )
            if (
                parent is None
                or parent.terminal_status is not SchedulerTerminalStatus.TRUNCATED
                or recovery_request.role != parent.role
                or recovery_request.requested_model != parent.requested_model
                or recovery_request.root_lineage != parent.root_lineage
                or recovery_request.response_schema_sha256 != parent.response_schema_sha256
                or recovery_request.request_limit_scope != parent.logical_request_id
                or recovery_request.delivered_source_inventory_sha256
                != expected_source_inventory_sha256
            ):
                raise ValueError("scheduler recovery request differs from its truncated parent")
            if recovery_request.promotion_entry_sha256 is not None:
                recovery_by_promotion.setdefault(
                    recovery_request.promotion_entry_sha256,
                    [],
                ).append(recovery_request)
        for binding in recovery_promotions:
            children = recovery_by_promotion.get(binding.promotion_entry_sha256, [])
            parent = parent_requests.get(binding.parent_task_id)
            expected_source_inventory_sha256 = (
                scheduler_canonical_sha256(
                    {
                        "domain": ("mmaudit.scheduler.recovery-delivered-source-inventory.v1"),
                        "source_descriptor_sha256s": (parent.delivered_source_descriptor_sha256s),
                    }
                )
                if parent is not None
                else None
            )
            common_children_are_exact = parent is not None and all(
                item.parent_task_id == parent.task_id
                and item.role == parent.role
                and item.requested_model == parent.requested_model
                and item.root_lineage == parent.root_lineage
                and item.response_schema_sha256 == parent.response_schema_sha256
                and item.request_limit_scope == parent.logical_request_id
                and item.delivered_source_inventory_sha256
                == binding.delivered_source_inventory_sha256
                for item in children
            )
            if binding.schema_version == "1.0":
                exact_promoted_request_tree = (
                    len(children) == 2
                    and {item.child_result_entry_sha256 for item in children}
                    == set(binding.direct_child_result_sha256s)
                    and all(
                        item.promotion_disposition is None and item.global_request_ordinal is None
                        for item in children
                    )
                )
            else:
                bridge_hash = binding.superseded_bridge_result_sha256
                leaf_hashes = binding.promoted_leaf_result_sha256s
                nested_hashes = binding.nested_child_result_sha256s
                bridge_children = tuple(
                    item
                    for item in children
                    if item.promotion_disposition
                    is SchedulerTruncationRecoveryPromotionDisposition.SUPERSEDED_TRUNCATED_BRIDGE
                )
                leaf_children = tuple(
                    sorted(
                        (
                            item
                            for item in children
                            if item.promotion_disposition
                            is SchedulerTruncationRecoveryPromotionDisposition.SUCCESSFUL_LEAF
                        ),
                        key=lambda item: item.global_request_ordinal or 0,
                    )
                )
                root_children = (
                    (*bridge_children, leaf_children[0])
                    if len(bridge_children) == 1 and len(leaf_children) == 3
                    else ()
                )
                ordered_root_children = tuple(
                    sorted(root_children, key=lambda item: item.global_request_ordinal or 0)
                )
                ordinals = tuple(
                    sorted(
                        item.global_request_ordinal
                        for item in children
                        if item.global_request_ordinal is not None
                    )
                )
                exact_promoted_request_tree = (
                    len(children) == 4
                    and len(ordinals) == 4
                    and len(set(ordinals)) == 4
                    and ordinals == tuple(range(ordinals[0], ordinals[0] + 4))
                    and len(bridge_children) == 1
                    and bridge_hash is not None
                    and bridge_children[0].child_result_entry_sha256 == bridge_hash
                    and bridge_children[0].terminal_status is SchedulerTerminalStatus.TRUNCATED
                    and len(leaf_children) == 3
                    and leaf_hashes is not None
                    and tuple(item.child_result_entry_sha256 for item in leaf_children)
                    == leaf_hashes
                    and all(
                        item.terminal_status is SchedulerTerminalStatus.SUCCEEDED
                        for item in leaf_children
                    )
                    and tuple(item.child_result_entry_sha256 for item in ordered_root_children)
                    == binding.direct_child_result_sha256s
                    and nested_hashes is not None
                    and tuple(item.child_result_entry_sha256 for item in leaf_children[1:])
                    == nested_hashes
                    and len(
                        {
                            (
                                item.recovery_family_id,
                                item.family_root_sha256,
                                item.recovery_plan_sha256,
                                item.family_closure_id,
                                item.family_closure_sha256,
                            )
                            for item in ordered_root_children
                        }
                    )
                    == 1
                    and all(
                        item.recovery_family_id == binding.nested_family_id
                        and item.family_root_sha256 == binding.nested_family_root_sha256
                        and item.recovery_plan_sha256 == binding.nested_recovery_plan_sha256
                        and item.family_closure_id == binding.nested_family_closure_id
                        and item.family_closure_sha256 == binding.nested_family_closure_sha256
                        for item in leaf_children[1:]
                    )
                    and ordered_root_children[0].recovery_family_id != binding.nested_family_id
                    and max(item.global_request_ordinal or 0 for item in ordered_root_children)
                    < min(item.global_request_ordinal or 0 for item in leaf_children[1:])
                )
            if (
                parent is None
                or parent.terminal_status is not SchedulerTerminalStatus.TRUNCATED
                or parent.result_sha256 != binding.original_truncated_result_sha256
                or binding.delivered_source_inventory_sha256 != expected_source_inventory_sha256
                or not common_children_are_exact
                or not exact_promoted_request_tree
            ):
                raise ValueError("scheduler recovery requests differ from their promoted parent")
        for request in self.model_requests:
            audit_fields = (
                request.audit_policy_selection_binding_sha256,
                request.audit_model_selection_bundle_sha256,
                request.audit_selection_sha256,
                request.audit_selected_model_set_sha256,
                request.audit_scope_sha256,
                request.audit_source_sha256,
                request.audit_selection_expires_at,
                request.audit_policy_routing_evidence_sha256,
            )
            if audit_selection is None:
                if any(item is not None for item in audit_fields):
                    raise ValueError("scheduler request claims an unbound audit selection")
                continue
            if request.terminal_status is not SchedulerTerminalStatus.SUCCEEDED:
                continue
            selected_route = audit_selection.route_for(request.requested_model)
            if (
                request.root_lineage != selected_route.root_lineage
                or request.audit_policy_selection_binding_sha256 != audit_selection.binding_sha256
                or request.audit_model_selection_bundle_sha256
                != audit_selection.audit_model_selection_bundle_sha256
                or request.audit_selection_sha256 != audit_selection.audit_selection_sha256
                or request.audit_selected_model_set_sha256
                != audit_selection.selected_model_set_sha256
                or request.audit_scope_sha256 != audit_selection.audit_scope_sha256
                or request.audit_source_sha256 != audit_selection.source_sha256
                or request.audit_selection_expires_at != audit_selection.selection_expires_at
                or request.audit_policy_routing_evidence_sha256 is None
            ):
                raise ValueError("successful scheduler request differs from its audit selection")
        for recovery_request in self.recovery_model_requests:
            audit_fields = (
                recovery_request.audit_policy_selection_binding_sha256,
                recovery_request.audit_model_selection_bundle_sha256,
                recovery_request.audit_selection_sha256,
                recovery_request.audit_selected_model_set_sha256,
                recovery_request.audit_scope_sha256,
                recovery_request.audit_source_sha256,
                recovery_request.audit_selection_expires_at,
                recovery_request.audit_policy_routing_evidence_sha256,
            )
            if audit_selection is None:
                if any(item is not None for item in audit_fields):
                    raise ValueError("scheduler recovery request claims an audit selection")
                continue
            if recovery_request.schema_version == "1.3" and not any(
                item is not None for item in audit_fields
            ):
                continue
            selected_route = audit_selection.route_for(recovery_request.requested_model)
            if (
                recovery_request.root_lineage != selected_route.root_lineage
                or recovery_request.audit_policy_selection_binding_sha256
                != audit_selection.binding_sha256
                or recovery_request.audit_model_selection_bundle_sha256
                != audit_selection.audit_model_selection_bundle_sha256
                or recovery_request.audit_selection_sha256 != audit_selection.audit_selection_sha256
                or recovery_request.audit_selected_model_set_sha256
                != audit_selection.selected_model_set_sha256
                or recovery_request.audit_scope_sha256 != audit_selection.audit_scope_sha256
                or recovery_request.audit_source_sha256 != audit_selection.source_sha256
                or recovery_request.audit_selection_expires_at
                != audit_selection.selection_expires_at
                or recovery_request.audit_policy_routing_evidence_sha256 is None
            ):
                raise ValueError(
                    "successful scheduler recovery request differs from its audit selection"
                )
        if self.summary.status is SchedulerCampaignStatus.COMPLETE and (
            evidence.pass_plan_count != 7
            or evidence.pass_result_count != 7
            or evidence.task_plan_count != evidence.task_result_count
            or evidence.preflight_failure_count != len(retrieval_preflight_failures)
            or evidence.task_activation_count + len(retrieval_preflight_failures)
            != evidence.task_plan_count
            or evidence.task_output_count != evidence.succeeded_count
            or evidence.result_observation_count != evidence.task_result_count
            or evidence.event_count
            != (
                evidence.task_plan_count
                + evidence.task_activation_count
                + evidence.task_result_count
                + evidence.task_output_count
                + evidence.provider_attempt_count
                + evidence.explicit_empty_count
            )
        ):
            raise ValueError("complete scheduler artifact lacks full journal lifecycle evidence")
        if self.artifact_sha256 != _model_sha256(self, exclude={"artifact_sha256"}):
            raise ValueError("scheduler artifact hash is inconsistent")
        return self


class SchedulerRetainedJournalReference(StrictModel):
    """Cycle-free identity for one prior run's physical scheduler journal.

    The relative path is descriptive, not authority: detached verification must
    resolve it beneath the configured ``runs`` directory, require the referenced
    run to physically own the private journal, and reconstruct the artifact before
    accepting this exact identity projection.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    ownership_mode: Literal["physical_private_journal"] = "physical_private_journal"
    owner_run_id: str = Field(min_length=1, max_length=128)
    consumer_run_id: str = Field(min_length=1, max_length=128)
    relative_journal_path: str = Field(min_length=1, max_length=256)
    campaign_id: str = Field(pattern=r"^scheduler-campaign-[0-9a-f]{64}$")
    scheduler_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    scheduler_summary_sha256: str = Field(pattern=_SHA256_PATTERN)
    scheduler_journal_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    scheduler_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    terminal_event_chain_head_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    reference_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("owner_run_id", "consumer_run_id")
    @classmethod
    def run_id_is_one_safe_basename(cls, value: str) -> str:
        if (
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_-]{0,126}[A-Za-z0-9])?", value) is None
            or value.casefold() == "latest"
            or PurePosixPath(value).name != value
        ):
            raise ValueError("scheduler retained-journal run IDs must be safe basenames")
        return value

    @classmethod
    def from_artifact(
        cls,
        *,
        owner_run_id: str,
        consumer_run_id: str,
        artifact: SchedulerArtifact,
    ) -> SchedulerRetainedJournalReference:
        validated = SchedulerArtifact.model_validate(artifact.model_dump(mode="python"))
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "evidence_authority": "comparison_required",
            "ownership_mode": "physical_private_journal",
            "owner_run_id": owner_run_id,
            "consumer_run_id": consumer_run_id,
            "relative_journal_path": f"{owner_run_id}/private/scheduler-journal",
            "campaign_id": validated.summary.manifest.campaign_id,
            "scheduler_manifest_sha256": validated.summary.manifest.manifest_sha256,
            "scheduler_summary_sha256": validated.summary.summary_sha256,
            "scheduler_journal_evidence_sha256": validated.journal_evidence.evidence_sha256,
            "scheduler_artifact_sha256": validated.artifact_sha256,
            "terminal_event_chain_head_sha256": (
                validated.journal_evidence.terminal_event_chain_head_sha256
            ),
        }
        return cls(**values, reference_sha256=scheduler_canonical_sha256(values))

    def require_exact(
        self,
        *,
        owner_run_id: str,
        consumer_run_id: str,
        artifact: SchedulerArtifact,
    ) -> None:
        if self != type(self).from_artifact(
            owner_run_id=owner_run_id,
            consumer_run_id=consumer_run_id,
            artifact=artifact,
        ):
            raise ValueError(
                "scheduler retained-journal reference differs from its owner and artifact"
            )

    @model_validator(mode="after")
    def path_identity_and_hash_are_exact(self) -> Self:
        expected_parts = (self.owner_run_id, "private", "scheduler-journal")
        path = PurePosixPath(self.relative_journal_path)
        if self.owner_run_id == self.consumer_run_id:
            raise ValueError("scheduler retained-journal reference cannot target its own run")
        if path.is_absolute() or path.parts != expected_parts:
            raise ValueError(
                "scheduler retained-journal path must identify one prior physical journal"
            )
        if self.reference_sha256 != _model_sha256(self, exclude={"reference_sha256"}):
            raise ValueError("scheduler retained-journal reference hash is inconsistent")
        return self


class SchedulerReportBinding(StrictModel):
    """Exact public count-and-hash projection from a complete scheduler artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    campaign_id: str = Field(pattern=r"^scheduler-campaign-[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    bindings_sha256: str = Field(pattern=_SHA256_PATTERN)
    shard_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    summary_sha256: str = Field(pattern=_SHA256_PATTERN)
    journal_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    scheduler_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    event_chain_head_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    status: SchedulerCampaignStatus
    mandatory_pass_count: Literal[7] = 7
    pass_result_count: int = Field(ge=0, le=7)
    completed_pass_count: int = Field(ge=0, le=7)
    planned_task_count: int = Field(ge=0, le=700_000)
    activated_task_count: int = Field(ge=0, le=700_000)
    terminal_task_count: int = Field(ge=0, le=700_000)
    model_request_count: int = Field(
        ge=0,
        le=700_000 + TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    )
    recovery_model_request_count: int = Field(
        default=0,
        ge=0,
        le=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
        exclude_if=lambda value: value == 0,
    )
    logical_request_count: int = Field(
        ge=0,
        le=700_000 + TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    )
    task_result_count: int = Field(ge=0, le=700_000)
    result_observation_count: int = Field(ge=0, le=1_400_000)
    preflight_failure_count: int = Field(ge=0, le=700_000)
    retrieval_planning_task_count: int = Field(
        default=0,
        ge=0,
        le=700_000,
        exclude_if=lambda value: value == 0,
    )
    retrieval_planning_preflight_failure_count: int = Field(
        default=0,
        ge=0,
        le=700_000,
        exclude_if=lambda value: value == 0,
    )
    retrieval_planning_non_success_count: int = Field(
        default=0,
        ge=0,
        le=700_000,
        exclude_if=lambda value: value == 0,
    )
    task_output_count: int = Field(ge=0, le=700_000)
    request_result_mapping_count: int = Field(ge=0, le=700_000)
    event_count: int = Field(ge=0, le=2_800_000)
    succeeded_count: int = Field(ge=0, le=700_000)
    explicit_empty_count: int = Field(ge=0, le=7)
    failed_count: int = Field(ge=0, le=700_000)
    truncated_count: int = Field(ge=0, le=700_000)
    recovered_count: int = Field(
        default=0,
        ge=0,
        le=700_000,
        exclude_if=lambda value: value == 0,
    )
    invalid_count: int = Field(ge=0, le=700_000)
    unbound_count: int = Field(ge=0, le=700_000)
    inconclusive_count: int = Field(ge=0, le=700_000)
    uncertain_count: int = Field(ge=0, le=700_000)
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def from_artifact(cls, artifact: SchedulerArtifact) -> SchedulerReportBinding:
        validated = SchedulerArtifact.model_validate(artifact.model_dump(mode="python"))
        summary = validated.summary
        evidence = validated.journal_evidence
        recovery_request_count = len(validated.recovery_model_requests)
        recovered_count = sum(
            len(pass_result.recovery_promotion_bindings) for pass_result in summary.pass_results
        )
        retrieval_tasks = tuple(
            task
            for pass_result in summary.pass_results
            for task in pass_result.plan.tasks
            if task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
        )
        retrieval_task_ids = frozenset(task.task_id for task in retrieval_tasks)
        retrieval_preflight_failure_count = sum(
            result.task_id in retrieval_task_ids
            and result.result_origin is SchedulerResultOrigin.LOCAL_PREFLIGHT
            for pass_result in summary.pass_results
            for result in pass_result.task_results
        )
        retrieval_non_success_count = sum(
            result.task_id in retrieval_task_ids
            and result.terminal_status is not SchedulerTerminalStatus.SUCCEEDED
            for pass_result in summary.pass_results
            for result in pass_result.task_results
        )
        values: dict[str, Any] = {
            "schema_version": "1.1" if retrieval_tasks else "1.0",
            "evidence_authority": "comparison_required",
            "campaign_id": summary.manifest.campaign_id,
            "manifest_sha256": summary.manifest.manifest_sha256,
            "bindings_sha256": summary.manifest.bindings.bindings_sha256,
            "shard_inventory_sha256": evidence.shard_inventory_sha256,
            "summary_sha256": summary.summary_sha256,
            "journal_evidence_sha256": evidence.evidence_sha256,
            "scheduler_artifact_sha256": validated.artifact_sha256,
            "event_chain_head_sha256": evidence.terminal_event_chain_head_sha256,
            "status": summary.status,
            "mandatory_pass_count": 7,
            "pass_result_count": evidence.pass_result_count,
            "completed_pass_count": len(summary.completed_passes),
            "planned_task_count": evidence.task_plan_count,
            "activated_task_count": evidence.task_activation_count,
            "terminal_task_count": evidence.task_result_count,
            "model_request_count": evidence.model_request_count + recovery_request_count,
            **(
                {"recovery_model_request_count": recovery_request_count}
                if recovery_request_count
                else {}
            ),
            "logical_request_count": evidence.task_plan_count + recovery_request_count,
            "task_result_count": evidence.task_result_count,
            "result_observation_count": evidence.result_observation_count,
            "preflight_failure_count": evidence.preflight_failure_count,
            **({"retrieval_planning_task_count": len(retrieval_tasks)} if retrieval_tasks else {}),
            **(
                {"retrieval_planning_preflight_failure_count": (retrieval_preflight_failure_count)}
                if retrieval_preflight_failure_count
                else {}
            ),
            **(
                {"retrieval_planning_non_success_count": retrieval_non_success_count}
                if retrieval_non_success_count
                else {}
            ),
            "task_output_count": evidence.task_output_count,
            "request_result_mapping_count": evidence.task_result_count,
            "event_count": evidence.event_count,
            "succeeded_count": evidence.succeeded_count,
            "explicit_empty_count": evidence.explicit_empty_count,
            "failed_count": evidence.failed_count,
            "truncated_count": evidence.truncated_count,
            **({"recovered_count": recovered_count} if recovered_count else {}),
            "invalid_count": evidence.invalid_count,
            "unbound_count": evidence.unbound_count,
            "inconclusive_count": evidence.inconclusive_count,
            "uncertain_count": evidence.uncertain_count,
        }
        return cls(**values, binding_sha256=scheduler_canonical_sha256(values))

    def require_exact(self, artifact: SchedulerArtifact) -> None:
        if self != type(self).from_artifact(artifact):
            raise ValueError("scheduler report binding differs from its public artifact")

    @model_validator(mode="after")
    def counts_and_hash_are_structurally_consistent(self) -> Self:
        terminal_status_total = (
            self.succeeded_count
            + self.explicit_empty_count
            + self.failed_count
            + self.truncated_count
            + self.invalid_count
            + self.unbound_count
            + self.inconclusive_count
            + self.uncertain_count
        )
        if (
            (self.schema_version == "1.1") != (self.retrieval_planning_task_count > 0)
            or self.retrieval_planning_preflight_failure_count > self.retrieval_planning_task_count
            or self.retrieval_planning_non_success_count > self.retrieval_planning_task_count
            or self.retrieval_planning_preflight_failure_count
            > self.retrieval_planning_non_success_count
            or self.terminal_task_count != self.task_result_count
            or self.task_result_count != terminal_status_total
            or self.logical_request_count
            != self.planned_task_count + self.recovery_model_request_count
            or self.model_request_count < self.recovery_model_request_count
            or self.request_result_mapping_count != self.task_result_count
            or self.recovered_count > self.truncated_count
        ):
            raise ValueError("scheduler report binding counts are inconsistent")
        if self.status is SchedulerCampaignStatus.COMPLETE and (
            self.completed_pass_count != 7
            or self.pass_result_count != 7
            or self.planned_task_count != self.terminal_task_count
            or self.activated_task_count + self.retrieval_planning_preflight_failure_count
            != self.planned_task_count
            or self.preflight_failure_count != self.retrieval_planning_preflight_failure_count
            or self.task_output_count != self.succeeded_count
            or (
                self.failed_count
                + self.invalid_count
                + self.unbound_count
                + self.inconclusive_count
                + self.uncertain_count
                + self.truncated_count
                - self.recovered_count
            )
            != self.retrieval_planning_non_success_count
        ):
            raise ValueError("complete scheduler report binding contains incomplete evidence")
        if self.binding_sha256 != _model_sha256(self, exclude={"binding_sha256"}):
            raise ValueError("scheduler report binding hash is inconsistent")
        return self


class SchedulerTaskEvent(StrictModel):
    """One hash-chained lifecycle event suitable for durable journal storage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    campaign_id: str = Field(pattern=r"^scheduler-campaign-[0-9a-f]{64}$")
    pass_plan_id: str = Field(pattern=r"^scheduler-plan-[0-9a-f]{64}$")
    pass_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    task_id: str = Field(pattern=r"^scheduler-task-[0-9a-f]{64}$")
    logical_request_id: str = Field(pattern=r"^scheduler-request-[0-9a-f]{64}$")
    kind: SchedulerTaskEventKind
    event_index: int = Field(ge=0, le=10_000_000)
    task_event_index: int = Field(ge=0, le=3)
    previous_event_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    prior_task_event_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    activation_id: str | None = Field(default=None, pattern=r"^scheduler-activation-[0-9a-f]{64}$")
    activation_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    request_id: str | None = Field(
        default=None,
        pattern=r"^scheduler-request-[0-9a-f]{64}$",
    )
    task_result_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    event_id: str = Field(pattern=r"^scheduler-event-[0-9a-f]{64}$")
    event_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        plan: SchedulerPassPlan,
        task: SchedulerTaskPlan,
        kind: SchedulerTaskEventKind,
        event_index: int,
        previous_event: SchedulerTaskEvent | None = None,
        prior_task_event: SchedulerTaskEvent | None = None,
        activation: SchedulerTaskActivation | None = None,
        request_id: str | None = None,
        result: SchedulerTaskResult | None = None,
    ) -> SchedulerTaskEvent:
        if not plan.has_exact_task(task):
            raise ValueError("scheduler event task is not in the sealed pass plan")
        expected_task_index = {
            SchedulerTaskEventKind.PLANNED: 0,
            SchedulerTaskEventKind.ACTIVATED: 1,
            SchedulerTaskEventKind.DISPATCHED: 2,
            SchedulerTaskEventKind.TERMINAL: 3,
            SchedulerTaskEventKind.PREFLIGHT_TERMINAL: 1,
            SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL: 2,
        }[kind]
        if event_index == 0:
            if previous_event is not None:
                raise ValueError("first scheduler event cannot have global predecessor evidence")
        elif (
            previous_event is None
            or previous_event.event_index != event_index - 1
            or previous_event.campaign_id != plan.manifest.campaign_id
        ):
            raise ValueError("scheduler event does not extend the global event chain")
        if kind is SchedulerTaskEventKind.PLANNED:
            if (
                prior_task_event is not None
                or activation is not None
                or request_id is not None
                or result is not None
            ):
                raise ValueError(
                    "planned scheduler event cannot have activation, request, or result"
                )
        else:
            expected_prior_kind = {
                SchedulerTaskEventKind.ACTIVATED: SchedulerTaskEventKind.PLANNED,
                SchedulerTaskEventKind.DISPATCHED: SchedulerTaskEventKind.ACTIVATED,
                SchedulerTaskEventKind.TERMINAL: SchedulerTaskEventKind.DISPATCHED,
                SchedulerTaskEventKind.PREFLIGHT_TERMINAL: SchedulerTaskEventKind.PLANNED,
                SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL: (
                    SchedulerTaskEventKind.ACTIVATED
                ),
            }[kind]
            if (
                prior_task_event is None
                or prior_task_event.kind is not expected_prior_kind
                or prior_task_event.task_event_index != expected_task_index - 1
                or prior_task_event.campaign_id != plan.manifest.campaign_id
                or prior_task_event.pass_plan_id != plan.pass_plan_id
                or prior_task_event.pass_plan_sha256 != plan.pass_plan_sha256
                or prior_task_event.task_id != task.task_id
                or prior_task_event.logical_request_id != task.logical_request_id
            ):
                raise ValueError("scheduler event does not extend the exact prior task event")
            if kind is SchedulerTaskEventKind.PREFLIGHT_TERMINAL:
                if (
                    activation is not None
                    or request_id is not None
                    or result is None
                    or result.result_origin is not SchedulerResultOrigin.LOCAL_PREFLIGHT
                ):
                    raise ValueError("preflight terminal event requires an unactivated failure")
            else:
                if activation is None:
                    raise ValueError("scheduler lifecycle event requires exact activation")
                activation.require_exact_task(plan=plan, task=task)
                if kind is SchedulerTaskEventKind.ACTIVATED:
                    if request_id is not None or result is not None:
                        raise ValueError("activated scheduler event cannot dispatch or terminate")
                elif kind is SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL:
                    if (
                        request_id is not None
                        or result is None
                        or result.result_origin is not SchedulerResultOrigin.ACTIVATED
                        or result.terminal_status
                        not in {
                            SchedulerTerminalStatus.FAILED,
                            SchedulerTerminalStatus.TRUNCATED,
                            SchedulerTerminalStatus.INVALID,
                            SchedulerTerminalStatus.UNBOUND,
                            SchedulerTerminalStatus.INCONCLUSIVE,
                        }
                        or result.pass_plan_id != plan.pass_plan_id
                        or result.task_id != task.task_id
                        or result.logical_request_id != task.logical_request_id
                        or result.activation_id != activation.activation_id
                        or result.activation_sha256 != activation.activation_sha256
                    ):
                        raise ValueError(
                            "activated preflight terminal event requires its exact "
                            "undispatched failure"
                        )
                elif request_id != task.logical_request_id:
                    raise ValueError("scheduler dispatched request ID must equal stable identity")
                elif kind is SchedulerTaskEventKind.DISPATCHED and result is not None:
                    raise ValueError("dispatched scheduler event cannot contain terminal result")
                elif kind is SchedulerTaskEventKind.TERMINAL and (
                    result is None
                    or result.result_origin is not SchedulerResultOrigin.ACTIVATED
                    or result.pass_plan_id != plan.pass_plan_id
                    or result.task_id != task.task_id
                    or result.logical_request_id != task.logical_request_id
                    or result.activation_id != activation.activation_id
                    or result.activation_sha256 != activation.activation_sha256
                ):
                    raise ValueError("terminal scheduler event requires its activated task result")
            if result is not None and (
                result.pass_plan_id != plan.pass_plan_id
                or result.task_id != task.task_id
                or result.logical_request_id != task.logical_request_id
            ):
                raise ValueError("terminal scheduler event result differs from its task")
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "campaign_id": plan.manifest.campaign_id,
            "pass_plan_id": plan.pass_plan_id,
            "pass_plan_sha256": plan.pass_plan_sha256,
            "task_id": task.task_id,
            "logical_request_id": task.logical_request_id,
            "kind": kind,
            "event_index": event_index,
            "task_event_index": expected_task_index,
            "previous_event_sha256": (
                previous_event.event_sha256 if previous_event is not None else None
            ),
            "prior_task_event_sha256": (
                prior_task_event.event_sha256 if prior_task_event is not None else None
            ),
            "activation_id": activation.activation_id if activation is not None else None,
            "activation_sha256": (activation.activation_sha256 if activation is not None else None),
            "request_id": request_id,
            "task_result_sha256": result.result_sha256 if result is not None else None,
        }
        event_id = "scheduler-event-" + scheduler_canonical_sha256(
            {
                "domain": "mmaudit.scheduler.task-event-identity.v1",
                "pass_plan_id": plan.pass_plan_id,
                "task_id": task.task_id,
                "kind": kind,
            }
        )
        body = {**values, "event_id": event_id}
        return cls(**body, event_sha256=scheduler_canonical_sha256(body))

    @model_validator(mode="after")
    def event_shape_and_hash_are_exact(self) -> Self:
        expected_task_index = {
            SchedulerTaskEventKind.PLANNED: 0,
            SchedulerTaskEventKind.ACTIVATED: 1,
            SchedulerTaskEventKind.DISPATCHED: 2,
            SchedulerTaskEventKind.TERMINAL: 3,
            SchedulerTaskEventKind.PREFLIGHT_TERMINAL: 1,
            SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL: 2,
        }[self.kind]
        if self.task_event_index != expected_task_index:
            raise ValueError("scheduler per-task event index is inconsistent")
        if (self.event_index == 0) != (self.previous_event_sha256 is None):
            raise ValueError("scheduler global event predecessor shape is inconsistent")
        if self.kind is SchedulerTaskEventKind.PLANNED:
            if (
                self.prior_task_event_sha256 is not None
                or self.activation_id is not None
                or self.activation_sha256 is not None
                or self.request_id is not None
                or self.task_result_sha256 is not None
            ):
                raise ValueError("planned scheduler event has impossible evidence")
        elif self.kind is SchedulerTaskEventKind.ACTIVATED:
            if (
                self.prior_task_event_sha256 is None
                or self.activation_id is None
                or self.activation_sha256 is None
                or self.request_id is not None
                or self.task_result_sha256 is not None
            ):
                raise ValueError("activated scheduler event has impossible evidence")
        elif self.kind is SchedulerTaskEventKind.DISPATCHED:
            if (
                self.prior_task_event_sha256 is None
                or self.activation_id is None
                or self.activation_sha256 is None
                or self.request_id != self.logical_request_id
                or self.task_result_sha256 is not None
            ):
                raise ValueError("dispatched scheduler event has impossible evidence")
        elif self.kind is SchedulerTaskEventKind.TERMINAL:
            if (
                self.prior_task_event_sha256 is None
                or self.activation_id is None
                or self.activation_sha256 is None
                or self.request_id != self.logical_request_id
                or self.task_result_sha256 is None
            ):
                raise ValueError("terminal scheduler event lacks activated result evidence")
        elif self.kind is SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL:
            if (
                self.prior_task_event_sha256 is None
                or self.activation_id is None
                or self.activation_sha256 is None
                or self.request_id is not None
                or self.task_result_sha256 is None
            ):
                raise ValueError(
                    "activated preflight terminal scheduler event has impossible evidence"
                )
        elif (
            self.prior_task_event_sha256 is None
            or self.activation_id is not None
            or self.activation_sha256 is not None
            or self.request_id is not None
            or self.task_result_sha256 is None
        ):
            raise ValueError("preflight terminal scheduler event has impossible evidence")
        expected_id = "scheduler-event-" + scheduler_canonical_sha256(
            {
                "domain": "mmaudit.scheduler.task-event-identity.v1",
                "pass_plan_id": self.pass_plan_id,
                "task_id": self.task_id,
                "kind": self.kind,
            }
        )
        if self.event_id != expected_id:
            raise ValueError("scheduler task-event ID is inconsistent")
        if self.event_sha256 != _model_sha256(self, exclude={"event_sha256"}):
            raise ValueError("scheduler task-event hash is inconsistent")
        return self


def _is_exact_activated_pre_send_release_attempt(
    *,
    provider_attempt: SchedulerProviderAttemptEvidence,
    lifecycle: tuple[SchedulerTaskEventKind, ...],
    credited_result: SchedulerTaskResult | None,
) -> bool:
    """Recognize the sole noncrediting attempt allowed before durable dispatch."""

    is_live_prefix = lifecycle == (
        SchedulerTaskEventKind.PLANNED,
        SchedulerTaskEventKind.ACTIVATED,
    )
    is_failed_terminal = lifecycle == (
        SchedulerTaskEventKind.PLANNED,
        SchedulerTaskEventKind.ACTIVATED,
        SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
    )
    if not (is_live_prefix or is_failed_terminal) or is_live_prefix != (credited_result is None):
        return False
    if is_failed_terminal and (
        credited_result is None
        or credited_result.terminal_status is not SchedulerTerminalStatus.FAILED
    ):
        return False

    usage = provider_attempt.usage_record
    try:
        token_attempts = atomic_token_reservations_from_usage(usage)
        request_attempts = atomic_request_limit_reservations_from_usage(usage)
    except (TypeError, ValueError):
        return False
    return bool(
        provider_attempt.schema_version == "1.0"
        and provider_attempt.truncated_envelope_evidence is None
        and provider_attempt.truncation_projection is None
        and provider_attempt.provider_response_sha256 is None
        and provider_attempt.validated_response_sha256 is None
        and is_structurally_accountable_usage_record(usage)
        and not is_structurally_creditable_usage_record(usage)
        and usage.request_id == provider_attempt.logical_request_id
        and usage.validation_status is not ModelRequestValidationStatus.VALID
        and usage.status != "success"
        and bool(usage.provider_error_classification)
        and usage.identity_strength is ModelIdentityStrength.UNBOUND
        and usage.actual_model is None
        and usage.returned_model is None
        and usage.provider is None
        and usage.openrouter_generation_id is None
        and usage.actual_provider_endpoint is None
        and usage.finish_reason is None
        and usage.response_sha256 is None
        and usage.validated_response_sha256 is None
        and usage.reported_cost_usd is None
        and usage.reported_cost_usd_exact is None
        and usage.accounted_cost_usd == 0
        and usage.accounted_cost_usd_exact == "0"
        and usage.prompt_tokens == 0
        and usage.completion_tokens == 0
        and usage.total_tokens == 0
        and usage.cached_tokens == 0
        and usage.reasoning_tokens in {None, 0}
        and usage.reasoning_evidence is None
        and usage.token_detail_accounting_evidence is None
        and not usage.fallback_used
        and not usage.substitution_detected
        and usage.attempts == 1
        and usage.retry_count == 0
        and tuple(item.request_id for item in token_attempts)
        == (provider_attempt.logical_request_id,)
        and tuple(item.request_id for item in request_attempts)
        == (provider_attempt.logical_request_id,)
    )


def _validate_scheduler_journal_evidence(
    *,
    manifest: SchedulerCampaignManifest,
    summary: SchedulerCampaignSummary,
    plans: tuple[SchedulerPassPlan, ...],
    activations: tuple[SchedulerTaskActivation, ...],
    outputs: tuple[SchedulerTaskOutput, ...],
    retrieval_bindings: tuple[SchedulerRetrievalBinding, ...],
    provider_attempts: tuple[SchedulerProviderAttemptEvidence, ...],
    task_results: tuple[SchedulerTaskResult, ...],
    result_observations: tuple[SchedulerTaskResult, ...],
    events: tuple[SchedulerTaskEvent, ...],
    terminal_report_authority: SchedulerTerminalReportAuthority | None,
) -> None:
    """Validate full private objects before publishing their detached projection."""

    if summary.manifest != manifest:
        raise ValueError("scheduler journal summary belongs to a different manifest")
    if terminal_report_authority is not None:
        if not manifest.terminal_report_authority_required:
            raise ValueError(
                "legacy scheduler campaign cannot claim current terminal-report authority"
            )
        if (
            terminal_report_authority.campaign_id != manifest.campaign_id
            or terminal_report_authority.manifest_sha256 != manifest.manifest_sha256
            or terminal_report_authority.summary_sha256 != summary.summary_sha256
            or terminal_report_authority.campaign_status is not summary.status
        ):
            raise ValueError(
                "scheduler terminal report authority differs from its campaign summary"
            )
        if manifest.terminal_evidence_authority_required != (
            terminal_report_authority.schema_version == "1.1"
        ):
            raise ValueError(
                "scheduler terminal report authority differs from its evidence-authority mode"
            )
    observed_passes = tuple(plan.pass_kind for plan in plans)
    if observed_passes != SCHEDULER_PASS_ORDER[: len(plans)]:
        raise ValueError("scheduler journal plans must be an exact contiguous pass prefix")
    if len(plans) > len(summary.pass_results) + (summary.next_pass is not None):
        raise ValueError("scheduler journal contains an unaccounted future pass plan")
    if any(plan.manifest != manifest for plan in plans):
        raise ValueError("scheduler journal plan belongs to a different manifest")
    for index, pass_result in enumerate(summary.pass_results):
        if index >= len(plans) or pass_result.plan != plans[index]:
            raise ValueError("scheduler journal plans differ from sealed pass results")
    if len(plans) > len(summary.pass_results) and (
        summary.next_pass is None or plans[-1].pass_kind is not summary.next_pass
    ):
        raise ValueError("scheduler journal active plan differs from summary next pass")

    task_pairs = tuple((plan, task) for plan in plans for task in plan.tasks)
    task_by_id = {task.task_id: (plan, task) for plan, task in task_pairs}
    if len(task_by_id) != len(task_pairs):
        raise ValueError("scheduler journal repeats a task identity")

    activation_by_task = {item.task_id: item for item in activations}
    output_by_task = {item.task_id: item for item in outputs}
    provider_attempt_by_task = {item.task_id: item for item in provider_attempts}
    result_by_task = {item.task_id: item for item in task_results}
    for label, mapping, observed in (
        ("activation", activation_by_task, activations),
        ("output", output_by_task, outputs),
        ("provider attempt", provider_attempt_by_task, provider_attempts),
        ("result", result_by_task, task_results),
    ):
        if len(mapping) != len(observed) or not set(mapping) <= set(task_by_id):
            raise ValueError(f"scheduler journal contains duplicate or unknown {label} evidence")
    observation_hashes = tuple(item.result_sha256 for item in result_observations)
    if len(observation_hashes) != len(set(observation_hashes)) or any(
        item.task_id not in task_by_id for item in result_observations
    ):
        raise ValueError("scheduler journal contains duplicate or unknown result observations")
    if not {item.result_sha256 for item in task_results} <= set(observation_hashes):
        raise ValueError("credited scheduler results must be retained as exact observations")

    retrieval_binding_by_primary: dict[str, SchedulerRetrievalBinding] = {}
    for binding in retrieval_bindings:
        planner_pair = task_by_id.get(binding.planner_task_id)
        if planner_pair is None:
            raise ValueError("scheduler retrieval binding references an unknown planner")
        planner_plan, planner_task = planner_pair
        primary_pair = (
            task_by_id.get(planner_task.parent_task_id)
            if planner_task.parent_task_id is not None
            else None
        )
        planner_result = result_by_task.get(planner_task.task_id)
        planner_output = output_by_task.get(planner_task.task_id)
        if (
            primary_pair is None
            or primary_pair[0] != planner_plan
            or planner_result is None
            or planner_output is None
            or planner_task.purpose is not SchedulerTaskPurpose.RETRIEVAL_PLANNING
            or planner_task.parent_task_id in retrieval_binding_by_primary
        ):
            raise ValueError("scheduler retrieval binding lacks an exact primary lifecycle")
        primary_task = primary_pair[1]
        expected_binding = SchedulerRetrievalBinding.build_pre_activation(
            plan=planner_plan,
            primary_task=primary_task,
            planner_task=planner_task,
            planner_output=planner_output,
            planner_result=planner_result,
            transcript=binding.transcript,
        )
        if binding != expected_binding:
            raise ValueError("scheduler retrieval binding differs from exact planner custody")
        primary_activation = activation_by_task.get(primary_task.task_id)
        if primary_activation is not None:
            binding.require_exact_primary(
                plan=planner_plan,
                task=primary_task,
                activation=primary_activation,
            )
        primary_output = output_by_task.get(primary_task.task_id)
        if primary_output is not None and (
            primary_output.retrieval_binding is None or primary_output.retrieval_binding != binding
        ):
            raise ValueError("scheduler primary output differs from standalone retrieval custody")
        retrieval_binding_by_primary[primary_task.task_id] = binding

    if terminal_report_authority is not None:
        if len(task_results) != len(task_pairs) or len(summary.pass_results) != len(plans):
            raise ValueError(
                "scheduler terminal report authority requires a terminal planned pass prefix"
            )
        successful_outputs = {
            task_id: output_by_task[task_id]
            for task_id, result in result_by_task.items()
            if result.terminal_status is SchedulerTerminalStatus.SUCCEEDED
            and task_id in output_by_task
        }
        judgment_outputs = tuple(
            SchedulerEvidenceCapJudgmentOutput.model_validate(
                successful_outputs[task.task_id].payload
            )
            for plan, task in task_pairs
            if plan.pass_kind is SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT
            and task.role == "host:evidence_cap_judgment"
            and task.task_id in successful_outputs
        )
        if len(judgment_outputs) > 1:
            raise ValueError("scheduler terminal authority has ambiguous pass-seven judgment")
        if judgment_outputs:
            terminal_report_authority.require_exact_judgment(judgment_outputs[0])
        report_quality_outputs = tuple(
            ReportQualityReview.model_validate(successful_outputs[task.task_id].payload)
            for plan, task in task_pairs
            if plan.pass_kind is SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT
            and task.role == "specialist:report_quality"
            and task.task_id in successful_outputs
        )
        if len(report_quality_outputs) > 1:
            raise ValueError("scheduler terminal authority has ambiguous report-quality review")
        expected_quality_sha256 = (
            scheduler_canonical_sha256(report_quality_outputs[0].model_dump(mode="json"))
            if report_quality_outputs
            else None
        )
        if terminal_report_authority.report_quality_payload_sha256 != expected_quality_sha256:
            raise ValueError(
                "scheduler terminal authority differs from retained report-quality review"
            )

    for task_id, exact_activation in activation_by_task.items():
        plan, task = task_by_id[task_id]
        exact_activation.require_exact_task(plan=plan, task=task)
    for task_id, exact_output in output_by_task.items():
        observed_activation = activation_by_task.get(task_id)
        if observed_activation is None:
            raise ValueError("scheduler journal output lacks exact activation evidence")
        exact_output.require_exact_activation(observed_activation)
        _plan, task = task_by_id[task_id]
        completion = exact_output.model_completion_evidence
        if completion is not None and completion != SchedulerModelCompletionEvidence.build(
            task=task,
            activation=observed_activation,
            usage_record=completion.usage_record,
            privacy_evidence_custody=manifest.privacy_evidence_custody,
            audit_model_selection=manifest.bindings.audit_model_selection,
            audit_model_refresh=manifest.bindings.audit_model_refresh,
            audit_model_refresh_pricing=(manifest.bindings.audit_model_refresh_pricing),
            normalizer_sha256=completion.normalizer_sha256,
            normalized_output_sha256=completion.normalized_output_sha256,
            normalization_evidence=completion.normalization_evidence,
            algorithm_version=manifest.algorithm_version,
        ):
            raise ValueError("scheduler journal output differs from exact completion custody")
    if set(provider_attempt_by_task).intersection(output_by_task):
        raise ValueError("scheduler provider attempt cannot also receive review credit")
    for task_id, attempt in provider_attempt_by_task.items():
        observed_activation = activation_by_task.get(task_id)
        if observed_activation is None:
            raise ValueError("scheduler provider attempt lacks exact activation evidence")
        _plan, task = task_by_id[task_id]
        if attempt != SchedulerProviderAttemptEvidence.build(
            task=task,
            activation=observed_activation,
            usage_record=attempt.usage_record,
            audit_model_selection=manifest.bindings.audit_model_selection,
            audit_model_refresh=manifest.bindings.audit_model_refresh,
            audit_model_refresh_pricing=(manifest.bindings.audit_model_refresh_pricing),
            truncated_envelope_evidence=attempt.truncated_envelope_evidence,
            truncation_projection=attempt.truncation_projection,
        ):
            raise ValueError("scheduler provider attempt differs from exact task evidence")
    for result in result_observations:
        task_id = result.task_id
        plan, task = task_by_id[task_id]
        if (
            result.campaign_id != manifest.campaign_id
            or result.manifest_sha256 != manifest.manifest_sha256
            or result.pass_kind is not plan.pass_kind
            or result.pass_id != plan.pass_id
            or result.pass_plan_id != plan.pass_plan_id
            or result.pass_plan_sha256 != plan.pass_plan_sha256
            or result.task_plan_sha256 != task.task_plan_sha256
            or result.logical_request_id != task.logical_request_id
            or result.scope != task.scope
        ):
            raise ValueError("scheduler journal result differs from its exact task plan")
        observed_activation = activation_by_task.get(task_id)
        if result.result_origin is SchedulerResultOrigin.ACTIVATED:
            if (
                observed_activation is None
                or result.activation_id != observed_activation.activation_id
                or result.activation_sha256 != observed_activation.activation_sha256
            ):
                raise ValueError("scheduler journal result differs from its activation")
        elif observed_activation is not None:
            raise ValueError("scheduler preflight result cannot have activation evidence")
        observed_output = output_by_task.get(task_id)
        if result.terminal_status is SchedulerTerminalStatus.SUCCEEDED and (
            observed_output is None
            or result.output_sha256 != observed_output.output_sha256
            or result.output_artifact_sha256 != observed_output.output_artifact_sha256
        ):
            raise ValueError("scheduler successful result differs from its normalized output")
        standalone_binding = retrieval_binding_by_primary.get(task_id)
        output_binding = observed_output.retrieval_binding if observed_output is not None else None
        effective_binding = standalone_binding or output_binding
        expected_custody = (
            SchedulerRetrievalCustody.from_binding(effective_binding)
            if effective_binding is not None
            else None
        )
        if result.retrieval_custody != expected_custody:
            raise ValueError("scheduler result differs from private retrieval custody")
    succeeded_observation_tasks = {
        item.task_id
        for item in result_observations
        if item.terminal_status is SchedulerTerminalStatus.SUCCEEDED
    }
    if not succeeded_observation_tasks <= set(output_by_task):
        raise ValueError("scheduler successful observations lack retained normalized outputs")

    summary_results = tuple(
        item for pass_result in summary.pass_results for item in pass_result.task_results
    )
    if any(result_by_task.get(item.task_id) != item for item in summary_results):
        raise ValueError("scheduler journal omits or changes a sealed pass task result")

    if tuple(event.event_index for event in events) != tuple(range(len(events))):
        raise ValueError("scheduler journal event indices must be contiguous from zero")
    for index, event in enumerate(events):
        plan_task = task_by_id.get(event.task_id)
        if plan_task is None:
            raise ValueError("scheduler journal event references an unknown task")
        plan, task = plan_task
        if (
            event.campaign_id != manifest.campaign_id
            or event.pass_plan_id != plan.pass_plan_id
            or event.pass_plan_sha256 != plan.pass_plan_sha256
            or event.logical_request_id != task.logical_request_id
            or event.previous_event_sha256 != (events[index - 1].event_sha256 if index else None)
        ):
            raise ValueError("scheduler journal event breaks the exact global chain")

    histories: dict[str, list[SchedulerTaskEvent]] = {}
    for event in events:
        histories.setdefault(event.task_id, []).append(event)
    if set(histories) != set(task_by_id):
        raise ValueError("scheduler journal lacks a PLANNED event for an exact planned task")
    for task_id, history in histories.items():
        kinds = tuple(event.kind for event in history)
        if kinds not in {
            (SchedulerTaskEventKind.PLANNED,),
            (SchedulerTaskEventKind.PLANNED, SchedulerTaskEventKind.ACTIVATED),
            (
                SchedulerTaskEventKind.PLANNED,
                SchedulerTaskEventKind.ACTIVATED,
                SchedulerTaskEventKind.DISPATCHED,
            ),
            (
                SchedulerTaskEventKind.PLANNED,
                SchedulerTaskEventKind.ACTIVATED,
                SchedulerTaskEventKind.DISPATCHED,
                SchedulerTaskEventKind.TERMINAL,
            ),
            (SchedulerTaskEventKind.PLANNED, SchedulerTaskEventKind.PREFLIGHT_TERMINAL),
            (
                SchedulerTaskEventKind.PLANNED,
                SchedulerTaskEventKind.ACTIVATED,
                SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
            ),
        }:
            raise ValueError("scheduler journal task lifecycle is not a closed valid prefix")
        for index, event in enumerate(history):
            if event.task_event_index != index or event.prior_task_event_sha256 != (
                history[index - 1].event_sha256 if index else None
            ):
                raise ValueError("scheduler journal task lifecycle chain is inconsistent")
        observed_activation = activation_by_task.get(task_id)
        activation_events = tuple(
            event
            for event in history
            if event.kind
            in {
                SchedulerTaskEventKind.ACTIVATED,
                SchedulerTaskEventKind.DISPATCHED,
                SchedulerTaskEventKind.TERMINAL,
                SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
            }
        )
        if activation_events:
            if observed_activation is None or any(
                event.activation_id != observed_activation.activation_id
                or event.activation_sha256 != observed_activation.activation_sha256
                for event in activation_events
            ):
                raise ValueError("scheduler lifecycle events differ from exact activation")
        elif observed_activation is not None:
            raise ValueError("scheduler activation lacks its durable ACTIVATED event")
        terminal_events = tuple(
            event
            for event in history
            if event.kind
            in {
                SchedulerTaskEventKind.TERMINAL,
                SchedulerTaskEventKind.PREFLIGHT_TERMINAL,
                SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
            }
        )
        credited_result = result_by_task.get(task_id)
        if terminal_events:
            if (
                len(terminal_events) != 1
                or credited_result is None
                or (terminal_events[0].task_result_sha256 != credited_result.result_sha256)
            ):
                raise ValueError("scheduler terminal event differs from exact task result")
        elif credited_result is not None:
            raise ValueError("scheduler task result lacks its durable terminal event")
        provider_attempt = provider_attempt_by_task.get(task_id)
        if provider_attempt is not None:
            if SchedulerTaskEventKind.DISPATCHED not in kinds and not (
                _is_exact_activated_pre_send_release_attempt(
                    provider_attempt=provider_attempt,
                    lifecycle=kinds,
                    credited_result=credited_result,
                )
            ):
                raise ValueError(
                    "scheduler provider attempt lacks durable dispatch or exact pre-send release "
                    "evidence"
                )
            if credited_result is not None and credited_result.terminal_status in {
                SchedulerTerminalStatus.SUCCEEDED,
                SchedulerTerminalStatus.EXPLICIT_EMPTY,
            }:
                raise ValueError("scheduler provider attempt received impossible task credit")

    if summary.status is SchedulerCampaignStatus.COMPLETE and (
        len(plans) != len(SCHEDULER_PASS_ORDER)
        or set(result_by_task) != set(task_by_id)
        or any(
            history[-1].kind
            not in {
                SchedulerTaskEventKind.TERMINAL,
                SchedulerTaskEventKind.PREFLIGHT_TERMINAL,
                SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
            }
            for history in histories.values()
        )
    ):
        raise ValueError("complete scheduler summary lacks complete journal evidence")
