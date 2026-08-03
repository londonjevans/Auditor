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
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from functools import cache
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator
from pydantic_core import SchemaValidator

from mmaudit.constants import SEVERITY_ORDER, SPECIALIST_INVESTIGATOR_ROLES
from mmaudit.models.openrouter import strict_json_schema_sha256
from mmaudit.models.schemas import (
    CandidateCrossExaminationResponse,
    CandidateFinding,
    CandidateOriginKind,
    CandidateReviewBatch,
    ContextRequestEvidence,
    ExecutionEvidenceKind,
    FalsificationBatch,
    Finding,
    FindingOriginKind,
    FindingStatus,
    GeneratedFoundryTestBatch,
    GeneratedFoundryTestSpec,
    InvariantReviewBatch,
    JudgeDecisionBatch,
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
)
from mmaudit.models.usage import is_structurally_accountable_usage_record

SCHEDULER_ALGORITHM_VERSION = "mmaudit.seven-pass-scheduler.v1"
SCHEDULER_ANALYSIS_INPUT_LABELS = (
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
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SHARD_ID_PATTERN = r"^shard-[0-9a-f]{24}$"
_MODEL_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
_SAFE_KEY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_ROLE_PATTERN = r"^[a-z][a-z0-9_:.-]{0,127}$"
_MAX_TASK_OUTPUT_BYTES = 100_000_000
_MAX_PRIVACY_EVIDENCE_BYTES = 1_048_576
_USD_EXACT_PATTERN = r"^(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,18})?$"
_WHOLE_PROTOCOL_REVIEW_ROLE = re.compile(r"^whole_protocol_review:(?:0|[1-9][0-9]{0,3})$")
_BLIND_SHARD_REVIEW_ROLES = frozenset(
    {
        "source_audit",
        "business_logic",
        "configuration",
        *(f"specialist:{role}" for role in SPECIALIST_INVESTIGATOR_ROLES),
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
    FalsificationBatch,
    GeneratedFoundryTestBatch,
    InvariantReviewBatch,
    JudgeDecisionBatch,
    ReportQualityReview,
    ThreatModel,
    VerificationBatch,
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


def _json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, StrEnum):
        return value.value
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


def scheduler_response_schema_model_registry() -> dict[str, type[BaseModel]]:
    """Return a copy only when every fixed response class still has its frozen schema."""

    registry = _scheduler_response_schema_model_registry()
    for binding in registry.values():
        binding.require_current()
    return {schema_sha256: binding.response_model for schema_sha256, binding in registry.items()}


def scheduler_response_schema_sha256(response_model: type[Any]) -> str:
    """Return the registered strict-schema hash without regenerating its schema."""

    registry = _scheduler_response_schema_model_registry()
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


def _expected_response_model(task: SchedulerTaskPlan) -> type[BaseModel]:
    """Select the only response type authorized for a trusted scheduler role."""

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


def _parse_scheduler_model_payload(
    *,
    task: SchedulerTaskPlan,
    activation: SchedulerTaskActivation,
    payload: Any,
) -> BaseModel:
    registry = _scheduler_response_schema_model_registry()
    binding = registry.get(activation.response_schema_sha256 or "")
    expected_model = _expected_response_model(task)
    if binding is None or binding.response_model is not expected_model:
        raise ValueError(
            f"scheduler task output for role {task.role} uses the wrong response schema"
        )
    response_model = binding.response_model
    try:
        binding.require_current()
    except ValueError:
        raise ValueError(
            "scheduler response model schema drifted after registry construction "
            f"for task role {task.role}"
        ) from None
    schema_validator = binding.validator
    try:
        parsed = cast(BaseModel, schema_validator.validate_python(payload))
    except (TypeError, ValueError):
        raise ValueError(
            f"scheduler task output for role {task.role} violates its registered response schema"
        ) from None
    if type(parsed) is not response_model:
        raise ValueError(
            f"scheduler task output for role {task.role} returned the wrong response type"
        )
    if (
        getattr(response_model, "__pydantic_validator__", None) is not binding.validator
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
        getattr(response_model, "__pydantic_validator__", None) is not binding.validator
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


def _model_sha256(model: BaseModel, *, exclude: set[str]) -> str:
    return scheduler_canonical_sha256(model.model_dump(mode="json", exclude=exclude))


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
        values = {
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
        candidate_ids = _candidate_id_inventory(payload.get("candidate_ids"), "candidate")
        raw_payload_hashes = payload.get("candidate_payload_sha256s")
        if not isinstance(raw_payload_hashes, dict) or any(
            not isinstance(candidate_id, str)
            or not isinstance(candidate_sha256, str)
            or re.fullmatch(_SHA256_PATTERN, candidate_sha256) is None
            for candidate_id, candidate_sha256 in raw_payload_hashes.items()
        ):
            raise ValueError("scheduler pass-four output lacks canonical candidate payload hashes")
        if tuple(sorted(raw_payload_hashes)) != candidate_ids:
            raise ValueError("scheduler candidate payload hashes differ from pass-four inventory")
        payload_bindings = tuple(
            SchedulerCandidatePayloadBinding.build(
                candidate_id=candidate_id,
                candidate_payload_sha256=raw_payload_hashes[candidate_id],
            )
            for candidate_id in candidate_ids
        )
        high_critical = _candidate_id_inventory(
            payload.get("high_critical_candidate_ids"),
            "high/critical candidate",
        )
        validation = _candidate_id_inventory(
            payload.get("validation_candidate_ids"),
            "validation candidate",
        )
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

    schema_version: Literal["1.0"] = "1.0"
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


class SchedulerBindings(StrictModel):
    """Immutable hash-only inputs that define one scheduler campaign."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    algorithm_version: Literal["mmaudit.seven-pass-scheduler.v1"] = (
        "mmaudit.seven-pass-scheduler.v1"
    )
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
    ) -> SchedulerBindings:
        values = {
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
        return cls(**values, bindings_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def bindings_hash_is_exact(self) -> Self:
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

    schema_version: Literal["1.0"] = "1.0"
    descriptors: tuple[SchedulerAnalysisInputDescriptor, ...] = Field(
        min_length=len(SCHEDULER_ANALYSIS_INPUT_LABELS),
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
            "schema_version": "1.0",
            "descriptors": canonical,
        }
        return cls(**values, analysis_input_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def inventory_is_complete_and_exact(self) -> Self:
        labels = tuple(item.label for item in self.descriptors)
        if labels != tuple(sorted(SCHEDULER_ANALYSIS_INPUT_LABELS)):
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

    schema_version: Literal["1.0", "1.1"] = "1.0"
    algorithm_version: Literal["mmaudit.seven-pass-scheduler.v1"] = (
        "mmaudit.seven-pass-scheduler.v1"
    )
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    bindings: SchedulerBindings
    shard_inventory: SchedulerShardInventory
    cost_ledger_baseline: SchedulerCostLedgerBaseline | None = None
    privacy_evidence_custody: SchedulerPrivacyEvidenceCustody | None = None
    terminal_report_authority_required: bool = Field(
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
            "schema_version": "1.1" if require_terminal_report_authority else "1.0",
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
        if (self.schema_version == "1.1") != self.terminal_report_authority_required:
            raise ValueError("scheduler campaign terminal-report authority mode is inconsistent")
        if self.mandatory_passes != SCHEDULER_PASS_ORDER:
            raise ValueError("scheduler campaign must retain all seven ordered mandatory passes")
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

    The three request hashes are immutable recipe commitments known while the
    pass is sealed.  Actual rendered input, provider prompt, schema, and dynamic
    dependency-result hashes are bound immediately before dispatch by
    :class:`SchedulerTaskActivation`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    campaign_id: str = Field(pattern=r"^scheduler-campaign-[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    pass_kind: SchedulerPassKind
    pass_id: str = Field(pattern=r"^scheduler-pass-[0-9a-f]{64}$")
    scope: SchedulerScope
    task_kind: SchedulerTaskKind
    task_key: str = Field(pattern=_SAFE_KEY_PATTERN)
    role: str = Field(pattern=_ROLE_PATTERN)
    requested_model: str | None = Field(default=None, pattern=_MODEL_ID_PATTERN)
    root_lineage: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    candidate_ids: tuple[str, ...] = Field(default=(), max_length=100_000)
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
    ) -> SchedulerTaskPlan:
        validated_manifest = SchedulerCampaignManifest.model_validate(
            manifest.model_dump(mode="python")
        )
        validated_scope = SchedulerScope.model_validate(scope.model_dump(mode="python"))
        values: dict[str, Any] = {
            "schema_version": "1.0",
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
            and self.normalizer_sha256 is not None
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
        _candidate_id_inventory(self.candidate_ids, "task candidate")
        if self.candidate_ids and self.task_kind is not SchedulerTaskKind.MODEL_REQUEST:
            raise ValueError("host scheduler task cannot claim model candidate review")
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


class SchedulerPassPlan(StrictModel):
    """A sealed exact task inventory for one mandatory pass."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    manifest: SchedulerCampaignManifest
    pass_kind: SchedulerPassKind
    pass_id: str = Field(pattern=r"^scheduler-pass-[0-9a-f]{64}$")
    dependencies: tuple[SchedulerPassDependency, ...]
    tasks: tuple[SchedulerTaskPlan, ...] = Field(min_length=1, max_length=100_000)
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
            "schema_version": "1.0",
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
        empty_tasks = [
            item for item in self.tasks if item.task_kind is SchedulerTaskKind.EMPTY_COMPLETION
        ]
        if empty_tasks:
            if (
                len(self.tasks) != 1
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
            len(self.tasks) != 1
            or self.tasks[0].scope.kind is not SchedulerScopeKind.GLOBAL
            or self.tasks[0].task_kind is not SchedulerTaskKind.MODEL_REQUEST
            or self.tasks[0].role != "threat_model"
        ):
            raise ValueError("orientation requires exactly one global threat-model request")
        if self.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW:
            for task in self.tasks:
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
                task.scope.shard_ids[0] for task in self.tasks if task.role == "source_audit"
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
            for task in self.tasks
        ):
            raise ValueError(f"scheduler pass requires {required_host_role} host computation")
        if self.pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION:
            for task in self.tasks:
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
            for task in self.tasks
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
        allowed = set(candidate_ids)
        verifier_tasks = tuple(
            task
            for task in self.tasks
            if task.task_kind is SchedulerTaskKind.MODEL_REQUEST and task.role == "verifier"
        )
        falsifier_tasks = tuple(
            task
            for task in self.tasks
            if task.task_kind is SchedulerTaskKind.MODEL_REQUEST
            and task.role == "candidate_falsifier"
        )
        for task in (*verifier_tasks, *falsifier_tasks):
            if not task.candidate_ids or not set(task.candidate_ids) <= allowed:
                raise ValueError("pass six reviewer tasks must bind exact validation candidates")
        for candidate_id in candidate_ids:
            verifier_lineages = {
                task.root_lineage for task in verifier_tasks if candidate_id in task.candidate_ids
            }
            falsifier_lineages = {
                task.root_lineage for task in falsifier_tasks if candidate_id in task.candidate_ids
            }
            if (
                not verifier_lineages
                or len(falsifier_lineages) < 2
                or not verifier_lineages.isdisjoint(falsifier_lineages)
            ):
                raise ValueError(
                    "pass six requires a verifier and two independent falsifier lineages "
                    "per candidate"
                )


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
    ) -> SchedulerTaskActivation:
        if not plan.has_exact_task(task):
            raise ValueError("scheduler activation task is not in the sealed pass plan")
        upstream = tuple(sorted(set(upstream_task_result_sha256s)))
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


class SchedulerModelCompletionEvidence(StrictModel):
    """Private redacted provider/normalization evidence for one successful model task."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    task_id: str = Field(pattern=r"^scheduler-task-[0-9a-f]{64}$")
    logical_request_id: str = Field(pattern=r"^scheduler-request-[0-9a-f]{64}$")
    activation_sha256: str = Field(pattern=_SHA256_PATTERN)
    delivered_source_descriptor_sha256s: tuple[str, ...] = Field(max_length=100_000)
    usage_record: UsageRecord
    usage_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    context_request_evidence: ContextRequestEvidence
    context_request_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider_response_sha256: str = Field(pattern=_SHA256_PATTERN)
    validated_response_sha256: str = Field(pattern=_SHA256_PATTERN)
    response_schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    normalizer_sha256: str = Field(pattern=_SHA256_PATTERN)
    normalized_output_sha256: str = Field(pattern=_SHA256_PATTERN)
    completion_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        task: SchedulerTaskPlan,
        activation: SchedulerTaskActivation,
        usage_record: UsageRecord,
        privacy_evidence_custody: SchedulerPrivacyEvidenceCustody | None,
        normalizer_sha256: str,
        normalized_output_sha256: str,
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
        raw_context = frozen_usage.routing.get("context_request_evidence")
        if not isinstance(raw_context, dict):
            raise ValueError("scheduler model completion lacks typed context request evidence")
        context = ContextRequestEvidence.model_validate(raw_context)
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
            or frozen_usage.validated_response_sha256 != normalized_output_sha256
        ):
            raise ValueError("scheduler model output is not the exact provider-validated response")
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "evidence_authority": "comparison_required",
            "task_id": task.task_id,
            "logical_request_id": task.logical_request_id,
            "activation_sha256": activation.activation_sha256,
            "delivered_source_descriptor_sha256s": (activation.delivered_source_descriptor_sha256s),
            "usage_record": frozen_usage,
            "usage_record_sha256": scheduler_canonical_sha256(frozen_usage.model_dump(mode="json")),
            "context_request_evidence": context,
            "context_request_evidence_sha256": context.evidence_sha256,
            "provider_response_sha256": frozen_usage.response_sha256,
            "validated_response_sha256": frozen_usage.validated_response_sha256,
            "response_schema_sha256": activation.response_schema_sha256,
            "normalizer_sha256": normalizer_sha256,
            "normalized_output_sha256": normalized_output_sha256,
        }
        return cls(
            **values,
            completion_evidence_sha256=scheduler_canonical_sha256(values),
        )

    @model_validator(mode="after")
    def completion_evidence_is_redacted_and_exact(self) -> Self:
        _reject_sensitive_usage_material(self.usage_record.model_dump(mode="json"))
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
            or self.validated_response_sha256 != self.normalized_output_sha256
        ):
            raise ValueError("scheduler model completion evidence contains inconsistent hashes")
        if self.completion_evidence_sha256 != _model_sha256(
            self,
            exclude={"completion_evidence_sha256"},
        ):
            raise ValueError("scheduler model completion evidence hash is inconsistent")
        return self


class SchedulerProviderAttemptEvidence(StrictModel):
    """Private redacted accounting evidence for a non-creditable provider attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    task_id: str = Field(pattern=r"^scheduler-task-[0-9a-f]{64}$")
    logical_request_id: str = Field(pattern=r"^scheduler-request-[0-9a-f]{64}$")
    activation_sha256: str = Field(pattern=_SHA256_PATTERN)
    delivered_source_descriptor_sha256s: tuple[str, ...] = Field(max_length=100_000)
    usage_record: UsageRecord
    usage_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    context_request_evidence: ContextRequestEvidence
    context_request_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider_response_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    validated_response_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    response_schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    attempt_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        task: SchedulerTaskPlan,
        activation: SchedulerTaskActivation,
        usage_record: UsageRecord,
    ) -> SchedulerProviderAttemptEvidence:
        if task.task_kind is not SchedulerTaskKind.MODEL_REQUEST:
            raise ValueError("scheduler provider-attempt evidence requires a model task")
        frozen_usage = UsageRecord.model_validate(usage_record.model_dump(mode="python"))
        _reject_sensitive_usage_material(frozen_usage.model_dump(mode="json"))
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
            "schema_version": "1.0",
            "evidence_authority": "comparison_required",
            "task_id": task.task_id,
            "logical_request_id": task.logical_request_id,
            "activation_sha256": activation.activation_sha256,
            "delivered_source_descriptor_sha256s": (activation.delivered_source_descriptor_sha256s),
            "usage_record": frozen_usage,
            "usage_record_sha256": scheduler_canonical_sha256(frozen_usage.model_dump(mode="json")),
            "context_request_evidence": context,
            "context_request_evidence_sha256": context.evidence_sha256,
            "provider_response_sha256": frozen_usage.response_sha256,
            "validated_response_sha256": frozen_usage.validated_response_sha256,
            "response_schema_sha256": activation.response_schema_sha256,
        }
        return cls(**values, attempt_evidence_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def attempt_is_redacted_and_exact(self) -> Self:
        _reject_sensitive_usage_material(self.usage_record.model_dump(mode="json"))
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
            != _model_sha256(self, exclude={"attempt_evidence_sha256"})
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
            or not set(self.high_critical_candidate_ids) <= set(candidates)
            or not set(self.validation_candidate_ids) <= set(candidates)
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
    group_ids: tuple[str, ...] = Field(max_length=100_000)
    judge_decision_ids: tuple[str, ...] = Field(max_length=100_000)
    candidate_ids: tuple[str, ...] = Field(max_length=100_000)
    candidate_payload_sha256s: dict[str, str] = Field(max_length=100_000)
    candidate_grouping_sha256: str = Field(pattern=_SHA256_PATTERN)
    terminal_findings: tuple[SchedulerTerminalFindingBinding, ...] = Field(max_length=100_000)
    final_finding_ids: tuple[str, ...] = Field(max_length=100_000)
    rejected_finding_ids: tuple[str, ...] = Field(max_length=100_000)
    filtered_finding_ids: tuple[str, ...] = Field(max_length=100_000)
    final_finding_payload_sha256s: dict[str, str] = Field(max_length=100_000)
    rejected_finding_payload_sha256s: dict[str, str] = Field(max_length=100_000)
    filtered_finding_payload_sha256s: dict[str, str] = Field(max_length=100_000)
    judge_decisions: tuple[SchedulerEvidencePayloadBinding, ...] = Field(max_length=100_000)
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
) -> str:
    """Recompute the trusted host identity for one raw model candidate."""

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
    digest = scheduler_canonical_sha256(
        {
            "domain": "mmaudit.model-review-origin-candidate.v1",
            "request_id": request_id,
            "request_role": request_role,
            "raw_candidate": raw_candidate,
        }
    )
    return f"cand-{digest[:24]}"


def _accepted_candidate_projection_is_exact(
    *,
    batch: CandidateReviewBatch,
    candidates: Sequence[CandidateFinding],
    usage_record: UsageRecord,
) -> bool:
    """Verify the complete deterministic host stamping of one candidate batch."""

    expected_by_id = {
        _model_review_origin_candidate_id(
            request_role=usage_record.role,
            request_id=usage_record.request_id,
            candidate=raw,
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


class SchedulerTaskOutput(StrictModel):
    """Private normalized JSON output required for deterministic result recovery."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1"] = "1.1"
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
        schema_version: Literal["1.0", "1.1"] = "1.1",
    ) -> SchedulerTaskOutput:
        activation.require_exact_task(plan=plan, task=task)
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
            )
        elif task.task_kind is SchedulerTaskKind.HOST_COMPUTATION:
            parsed_payload = _parse_scheduler_host_payload(
                plan=plan,
                task=task,
                activation=activation,
                payload=normalized,
            )
        effective_normalizer_sha256 = normalizer_sha256 or task.normalizer_sha256
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
                normalizer_sha256=effective_normalizer_sha256,
                normalized_output_sha256=output_sha256,
            )
            if usage_record is not None and effective_normalizer_sha256 is not None
            else None
        )
        if (usage_record is None) != (effective_normalizer_sha256 is None):
            raise ValueError("scheduler model normalization evidence is all-or-none")
        accepted_outcome = (
            SpecialistAcceptedOutcome.model_validate(
                specialist_accepted_outcome.model_dump(mode="python")
            )
            if specialist_accepted_outcome is not None
            else None
        )
        is_specialist = scheduler_role_requires_specialist_accepted_outcome(task.role)
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
            if schema_version == "1.0":
                if canonical_accepted_candidates:
                    raise ValueError("scheduler task output 1.0 cannot bind accepted candidates")
            elif completion is None or not _accepted_candidate_projection_is_exact(
                batch=parsed_payload,
                candidates=canonical_accepted_candidates,
                usage_record=completion.usage_record,
            ):
                raise ValueError(
                    "scheduler accepted candidate projection differs from the review batch"
                )
        elif canonical_accepted_candidates:
            raise ValueError("non-candidate scheduler output cannot accept candidate payloads")
        accepted_candidate_payload_sha256s = {
            candidate.candidate_id: scheduler_canonical_sha256(candidate.model_dump(mode="json"))
            for candidate in canonical_accepted_candidates
        }
        output_id = "scheduler-output-" + scheduler_canonical_sha256(
            {
                "domain": "mmaudit.scheduler.task-output-identity.v1",
                "activation_id": activation.activation_id,
                "task_id": task.task_id,
            }
        )
        values: dict[str, Any] = {
            "schema_version": schema_version,
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
            "payload": normalized,
            "payload_utf8_bytes": len(encoded),
            "output_sha256": output_sha256,
            "output_id": output_id,
        }
        hash_values = (
            values
            if schema_version == "1.1"
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
            output_artifact_sha256=scheduler_canonical_sha256(hash_values),
        )

    @model_validator(mode="after")
    def output_identity_payload_and_hash_are_exact(self) -> Self:
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
            candidate.candidate_id: scheduler_canonical_sha256(candidate.model_dump(mode="json"))
            for candidate in self.accepted_candidates
        }
        if self.accepted_candidate_payload_sha256s != observed_accepted_hashes:
            raise ValueError("scheduler accepted candidate payload hashes are inconsistent")
        try:
            candidate_batch = CandidateReviewBatch.model_validate(self.payload)
        except ValueError:
            candidate_batch = None
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
        hash_exclusions = {"output_artifact_sha256"}
        if self.schema_version == "1.0":
            hash_exclusions.update({"accepted_candidate_payload_sha256s", "accepted_candidates"})
        if self.output_artifact_sha256 != _model_sha256(self, exclude=hash_exclusions):
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

    schema_version: Literal["1.0"] = "1.0"
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
        )

    @classmethod
    def build_preflight_failure(
        cls,
        *,
        plan: SchedulerPassPlan,
        task: SchedulerTaskPlan,
        terminal_status: SchedulerTerminalStatus,
        terminal_evidence_sha256: str,
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
    ) -> SchedulerTaskResult:
        if not plan.has_exact_task(task):
            raise ValueError("scheduler result task is not in the sealed pass plan")
        values: dict[str, Any] = {
            "schema_version": "1.0",
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
            self.normalizer_sha256,
        )
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
        if self.terminal_status is not SchedulerTerminalStatus.SUCCEEDED and (
            any(item is not None for item in provider_hashes)
            or self.reviewed_source_descriptor_sha256s
            or self.reviewed_candidate_ids
        ):
            raise ValueError("non-success scheduler result cannot claim model review credit")
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

    schema_version: Literal["1.0"] = "1.0"
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
            "schema_version": "1.0",
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
        }
        return cls(**values, request_evidence_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def public_request_shape_and_hash_are_exact(self) -> Self:
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
            self.normalizer_sha256,
        )
        if self.terminal_status is SchedulerTerminalStatus.SUCCEEDED:
            if any(item is None for item in completion_fields):
                raise ValueError("successful public model request lacks completion hashes")
        elif any(item is not None for item in completion_fields):
            raise ValueError("non-success public model request cannot claim completion hashes")
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
        if self.request_evidence_sha256 != _model_sha256(self, exclude={"request_evidence_sha256"}):
            raise ValueError("scheduler model-request evidence hash is inconsistent")
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


def _derived_pass_status(results: tuple[SchedulerTaskResult, ...]) -> SchedulerPassStatus:
    statuses = {result.terminal_status for result in results}
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

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    plan: SchedulerPassPlan
    task_results: tuple[SchedulerTaskResult, ...] = Field(min_length=1, max_length=100_000)
    status: SchedulerPassStatus
    pass_result_id: str = Field(pattern=r"^scheduler-pass-result-[0-9a-f]{64}$")
    pass_result_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        plan: SchedulerPassPlan,
        task_results: Iterable[SchedulerTaskResult],
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
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "evidence_authority": "comparison_required",
            "plan": validated_plan,
            "task_results": canonical_results,
            "status": _derived_pass_status(canonical_results),
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
                scheduler_role_requires_specialist_accepted_outcome(task.role)
                != (result.specialist_accepted_outcome_sha256 is not None)
            ):
                raise ValueError(
                    "scheduler specialist result differs from its host-accepted outcome"
                )
            if (
                self.plan.pass_kind is SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION
                and task.task_kind is SchedulerTaskKind.MODEL_REQUEST
                and result.terminal_status is SchedulerTerminalStatus.SUCCEEDED
                and result.reviewed_candidate_ids != task.candidate_ids
            ):
                raise ValueError("pass-five result omitted an exact candidate review")
            if (
                self.plan.pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
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
                and task.role == "judge"
                and result.terminal_status is SchedulerTerminalStatus.SUCCEEDED
                and result.reviewed_candidate_ids != task.candidate_ids
            ):
                raise ValueError("judge result omitted an exact candidate-group decision")
        expected_status = _derived_pass_status(self.task_results)
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
            for result in self.task_results:
                task = planned_by_id[result.task_id]
                if task.role != "source_audit":
                    continue
                expected_task_sources = {
                    source.source_descriptor_sha256
                    for source in _task_source_descriptors(self.plan, task)
                }
                if set(result.reviewed_source_descriptor_sha256s) != expected_task_sources:
                    raise ValueError(
                        "blind source-audit result lacks exact substantive source coverage"
                    )
                observed_sources.update(result.reviewed_source_descriptor_sha256s)
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

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    algorithm: Literal["mmaudit.scheduler-terminal-report-authority.v1"] = (
        "mmaudit.scheduler-terminal-report-authority.v1"
    )
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
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "evidence_authority": "comparison_required",
            "algorithm": "mmaudit.scheduler-terminal-report-authority.v1",
            "campaign_id": validated_manifest.campaign_id,
            "manifest_sha256": validated_manifest.manifest_sha256,
            "summary_sha256": validated_summary.summary_sha256,
            "campaign_status": validated_summary.status,
            "severity_threshold": severity_threshold,
            "candidate_ids": candidate_ids,
            "candidate_payload_sha256s": {
                item.candidate_id: scheduler_canonical_sha256(item.model_dump(mode="json"))
                for item in canonical_candidates
            },
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
        }
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

        if (
            self.severity_threshold != judgment.severity_threshold
            or self.candidate_ids != judgment.candidate_ids
            or self.candidate_payload_sha256s != judgment.candidate_payload_sha256s
            or self.final_finding_ids != judgment.final_finding_ids
            or self.rejected_finding_ids != judgment.rejected_finding_ids
            or self.filtered_finding_ids != judgment.filtered_finding_ids
            or self.final_finding_payload_sha256s != judgment.final_finding_payload_sha256s
            or self.rejected_finding_payload_sha256s != judgment.rejected_finding_payload_sha256s
            or self.filtered_finding_payload_sha256s != judgment.filtered_finding_payload_sha256s
        ):
            raise ValueError("scheduler terminal report authority differs from pass-seven judgment")

    @model_validator(mode="after")
    def inventories_bind_the_exact_authority_hash(self) -> Self:
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
        if self.authority_sha256 != _model_sha256(self, exclude={"authority_sha256"}):
            raise ValueError("scheduler terminal report authority hash is inconsistent")
        return self


class SchedulerJournalEvidence(StrictModel):
    """Public exact hash-and-count projection of controller-owned journal state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    campaign_id: str = Field(pattern=r"^scheduler-campaign-[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    summary_sha256: str = Field(pattern=_SHA256_PATTERN)
    analysis_input_sha256: str = Field(pattern=_SHA256_PATTERN)
    analysis_input_descriptor_sha256s: tuple[str, ...] = Field(
        min_length=len(SCHEDULER_ANALYSIS_INPUT_LABELS),
        max_length=len(SCHEDULER_ANALYSIS_INPUT_LABELS),
    )
    analysis_input_descriptor_count: int = Field(
        ge=len(SCHEDULER_ANALYSIS_INPUT_LABELS),
        le=len(SCHEDULER_ANALYSIS_INPUT_LABELS),
    )
    shard_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    pass_plan_sha256s: tuple[str, ...] = Field(max_length=7)
    task_plan_sha256s: tuple[str, ...] = Field(max_length=700_000)
    model_request_evidence_sha256s: tuple[str, ...] = Field(max_length=700_000)
    task_activation_sha256s: tuple[str, ...] = Field(max_length=700_000)
    task_output_artifact_sha256s: tuple[str, ...] = Field(max_length=700_000)
    provider_attempt_evidence_sha256s: tuple[str, ...] = Field(max_length=700_000)
    task_result_sha256s: tuple[str, ...] = Field(max_length=700_000)
    result_observation_sha256s: tuple[str, ...] = Field(max_length=1_400_000)
    pass_result_sha256s: tuple[str, ...] = Field(max_length=7)
    event_sha256s: tuple[str, ...] = Field(max_length=2_800_000)
    terminal_event_chain_head_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
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
    provider_attempt_count: int = Field(ge=0, le=700_000)
    task_result_count: int = Field(ge=0, le=700_000)
    result_observation_count: int = Field(ge=0, le=1_400_000)
    preflight_failure_count: int = Field(ge=0, le=700_000)
    pass_result_count: int = Field(ge=0, le=7)
    event_count: int = Field(ge=0, le=2_800_000)
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
        "provider_attempt_evidence_sha256s",
        "task_result_sha256s",
        "result_observation_sha256s",
        "pass_result_sha256s",
        "event_sha256s",
    )
    @classmethod
    def detached_hash_inventory_is_valid_and_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(
            re.fullmatch(_SHA256_PATTERN, item) is None for item in value
        ):
            raise ValueError("scheduler journal hash inventories must be valid and unique")
        return value

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
        provider_attempts: Iterable[SchedulerProviderAttemptEvidence] = (),
        task_results: Iterable[SchedulerTaskResult],
        result_observations: Iterable[SchedulerTaskResult],
        events: Iterable[SchedulerTaskEvent],
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
        canonical_terminal_authority = (
            SchedulerTerminalReportAuthority.model_validate(
                terminal_report_authority.model_dump(mode="python")
            )
            if terminal_report_authority is not None
            else None
        )
        if validated_manifest.terminal_report_authority_required != (
            canonical_terminal_authority is not None
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
        tasks = tuple(task for plan in canonical_plans for task in plan.tasks)
        status_counts = {
            status: sum(result.terminal_status is status for result in canonical_results)
            for status in SchedulerTerminalStatus
        }
        values: dict[str, Any] = {
            "schema_version": "1.1" if canonical_terminal_authority is not None else "1.0",
            "evidence_authority": "comparison_required",
            "campaign_id": validated_manifest.campaign_id,
            "manifest_sha256": validated_manifest.manifest_sha256,
            "summary_sha256": validated_summary.summary_sha256,
            "analysis_input_sha256": validated_analysis_inputs.analysis_input_sha256,
            "analysis_input_descriptor_sha256s": tuple(
                item.descriptor_sha256 for item in validated_analysis_inputs.descriptors
            ),
            "analysis_input_descriptor_count": len(validated_analysis_inputs.descriptors),
            "shard_inventory_sha256": validated_manifest.shard_inventory.inventory_sha256,
            "pass_plan_sha256s": tuple(item.pass_plan_sha256 for item in canonical_plans),
            "task_plan_sha256s": tuple(item.task_plan_sha256 for item in tasks),
            "model_request_evidence_sha256s": tuple(
                item.request_evidence_sha256 for item in canonical_model_requests
            ),
            "task_activation_sha256s": tuple(
                item.activation_sha256 for item in canonical_activations
            ),
            "task_output_artifact_sha256s": tuple(
                item.output_artifact_sha256 for item in canonical_outputs
            ),
            "provider_attempt_evidence_sha256s": tuple(
                item.attempt_evidence_sha256 for item in canonical_provider_attempts
            ),
            "task_result_sha256s": tuple(item.result_sha256 for item in canonical_results),
            "result_observation_sha256s": tuple(
                item.result_sha256 for item in canonical_observations
            ),
            "pass_result_sha256s": tuple(
                item.pass_result_sha256 for item in validated_summary.pass_results
            ),
            "event_sha256s": tuple(item.event_sha256 for item in canonical_events),
            "terminal_event_chain_head_sha256": (
                canonical_events[-1].event_sha256 if canonical_events else None
            ),
            **(
                {
                    "terminal_report_authority_sha256": (
                        canonical_terminal_authority.authority_sha256
                    )
                }
                if canonical_terminal_authority is not None
                else {}
            ),
            "pass_plan_count": len(canonical_plans),
            "task_plan_count": len(tasks),
            "model_request_count": len(canonical_model_requests),
            "task_activation_count": len(canonical_activations),
            "task_output_count": len(canonical_outputs),
            "provider_attempt_count": len(canonical_provider_attempts),
            "task_result_count": len(canonical_results),
            "result_observation_count": len(canonical_observations),
            "preflight_failure_count": sum(
                item.result_origin is SchedulerResultOrigin.LOCAL_PREFLIGHT
                for item in canonical_results
            ),
            "pass_result_count": len(validated_summary.pass_results),
            "event_count": len(canonical_events),
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

    @model_validator(mode="after")
    def evidence_counts_chain_and_hash_are_consistent(self) -> Self:
        if (self.schema_version == "1.1") != (self.terminal_report_authority_sha256 is not None):
            raise ValueError(
                "scheduler journal evidence terminal-report authority mode is inconsistent"
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
            (
                self.provider_attempt_count,
                len(self.provider_attempt_evidence_sha256s),
            ),
            (self.task_result_count, len(self.task_result_sha256s)),
            (self.result_observation_count, len(self.result_observation_sha256s)),
            (self.pass_result_count, len(self.pass_result_sha256s)),
            (self.event_count, len(self.event_sha256s)),
        )
        if any(count != observed for count, observed in pairs):
            raise ValueError("scheduler journal evidence counts differ from hash inventories")
        if (self.event_count == 0) != (self.terminal_event_chain_head_sha256 is None):
            raise ValueError("scheduler event-chain head presence is inconsistent")
        if self.event_sha256s and self.terminal_event_chain_head_sha256 != self.event_sha256s[-1]:
            raise ValueError("scheduler event-chain head differs from its terminal event")
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

    schema_version: Literal["1.0", "1.1"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    summary: SchedulerCampaignSummary
    journal_evidence: SchedulerJournalEvidence
    model_requests: tuple[SchedulerModelRequestEvidence, ...] = Field(max_length=700_000)
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        summary: SchedulerCampaignSummary,
        journal_evidence: SchedulerJournalEvidence,
        model_requests: Iterable[SchedulerModelRequestEvidence],
    ) -> SchedulerArtifact:
        validated_summary = SchedulerCampaignSummary.model_validate(
            summary.model_dump(mode="python")
        )
        validated_evidence = SchedulerJournalEvidence.model_validate(
            journal_evidence.model_dump(mode="python")
        )
        validated_requests = tuple(
            sorted(
                (
                    SchedulerModelRequestEvidence.model_validate(item.model_dump(mode="python"))
                    for item in model_requests
                ),
                key=lambda item: item.task_id,
            )
        )
        values: dict[str, Any] = {
            "schema_version": validated_evidence.schema_version,
            "evidence_authority": "comparison_required",
            "summary": validated_summary,
            "journal_evidence": validated_evidence,
            "model_requests": validated_requests,
        }
        return cls(**values, artifact_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def artifact_hash_and_journal_binding_are_exact(self) -> Self:
        evidence = self.journal_evidence
        request_ids = tuple(item.task_id for item in self.model_requests)
        if (
            self.schema_version != evidence.schema_version
            or (self.schema_version == "1.1")
            != self.summary.manifest.terminal_report_authority_required
            or evidence.campaign_id != self.summary.manifest.campaign_id
            or evidence.manifest_sha256 != self.summary.manifest.manifest_sha256
            or evidence.summary_sha256 != self.summary.summary_sha256
            or evidence.analysis_input_sha256
            != self.summary.manifest.bindings.analysis_input_sha256
            or evidence.analysis_input_descriptor_count != len(SCHEDULER_ANALYSIS_INPUT_LABELS)
            or evidence.shard_inventory_sha256
            != self.summary.manifest.shard_inventory.inventory_sha256
            or evidence.pass_result_sha256s
            != tuple(item.pass_result_sha256 for item in self.summary.pass_results)
            or request_ids != tuple(sorted(set(request_ids)))
            or evidence.model_request_count != len(self.model_requests)
            or evidence.model_request_evidence_sha256s
            != tuple(item.request_evidence_sha256 for item in self.model_requests)
            or any(
                item.campaign_id != self.summary.manifest.campaign_id
                or item.manifest_sha256 != self.summary.manifest.manifest_sha256
                for item in self.model_requests
            )
        ):
            raise ValueError("scheduler public artifact differs from its journal evidence")
        if self.summary.status is SchedulerCampaignStatus.COMPLETE and (
            evidence.pass_plan_count != 7
            or evidence.pass_result_count != 7
            or evidence.task_plan_count != evidence.task_result_count
            or evidence.preflight_failure_count
            or evidence.task_activation_count != evidence.task_plan_count
            or evidence.task_output_count != evidence.succeeded_count
            or evidence.result_observation_count != evidence.task_result_count
            or evidence.event_count != 4 * evidence.task_plan_count
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

    schema_version: Literal["1.0"] = "1.0"
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
    model_request_count: int = Field(ge=0, le=700_000)
    logical_request_count: int = Field(ge=0, le=700_000)
    task_result_count: int = Field(ge=0, le=700_000)
    result_observation_count: int = Field(ge=0, le=1_400_000)
    preflight_failure_count: int = Field(ge=0, le=700_000)
    task_output_count: int = Field(ge=0, le=700_000)
    request_result_mapping_count: int = Field(ge=0, le=700_000)
    event_count: int = Field(ge=0, le=2_800_000)
    succeeded_count: int = Field(ge=0, le=700_000)
    explicit_empty_count: int = Field(ge=0, le=7)
    failed_count: int = Field(ge=0, le=700_000)
    truncated_count: int = Field(ge=0, le=700_000)
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
        values: dict[str, Any] = {
            "schema_version": "1.0",
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
            "model_request_count": evidence.model_request_count,
            "logical_request_count": evidence.task_plan_count,
            "task_result_count": evidence.task_result_count,
            "result_observation_count": evidence.result_observation_count,
            "preflight_failure_count": evidence.preflight_failure_count,
            "task_output_count": evidence.task_output_count,
            "request_result_mapping_count": evidence.task_result_count,
            "event_count": evidence.event_count,
            "succeeded_count": evidence.succeeded_count,
            "explicit_empty_count": evidence.explicit_empty_count,
            "failed_count": evidence.failed_count,
            "truncated_count": evidence.truncated_count,
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
            self.terminal_task_count != self.task_result_count
            or self.task_result_count != terminal_status_total
            or self.logical_request_count != self.planned_task_count
            or self.request_result_mapping_count != self.task_result_count
        ):
            raise ValueError("scheduler report binding counts are inconsistent")
        if self.status is SchedulerCampaignStatus.COMPLETE and (
            self.completed_pass_count != 7
            or self.pass_result_count != 7
            or self.planned_task_count != self.terminal_task_count
            or self.task_output_count != self.succeeded_count
            or self.failed_count
            or self.truncated_count
            or self.invalid_count
            or self.unbound_count
            or self.inconclusive_count
            or self.uncertain_count
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


def _validate_scheduler_journal_evidence(
    *,
    manifest: SchedulerCampaignManifest,
    summary: SchedulerCampaignSummary,
    plans: tuple[SchedulerPassPlan, ...],
    activations: tuple[SchedulerTaskActivation, ...],
    outputs: tuple[SchedulerTaskOutput, ...],
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
            if SchedulerTaskEventKind.DISPATCHED not in kinds:
                raise ValueError("scheduler provider attempt lacks durable dispatch evidence")
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
