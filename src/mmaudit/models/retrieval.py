"""Dependency-light protocol models for bounded deterministic Solidity retrieval."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Sequence
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models.token_planning import UTF8_BYTES_PER_ESTIMATED_TOKEN

SOLIDITY_RETRIEVAL_MAX_BATCH_REQUESTS = 8
SOLIDITY_RETRIEVAL_MAX_EXCHANGES = SOLIDITY_RETRIEVAL_MAX_BATCH_REQUESTS
SOLIDITY_RETRIEVAL_SUBJECT_ID_MAX_LENGTH = 256
SOLIDITY_RETRIEVAL_MAX_RECORD_CONTENT = 10_000_000
SOLIDITY_RETRIEVAL_MAX_REQUESTS_PER_ROLE = 4
SOLIDITY_RETRIEVAL_MAX_RESULTS_PER_REQUEST = 16
SOLIDITY_RETRIEVAL_MAX_RESULT_UTF8_BYTES = 8_192
SOLIDITY_RETRIEVAL_MAX_TOTAL_RESULT_UTF8_BYTES = 16_384
SOLIDITY_RETRIEVAL_MAX_TOTAL_RESULT_TOKENS = 5_462
SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_UTF8_BYTES = 114_688
SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_TOKENS = (
    SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_UTF8_BYTES + UTF8_BYTES_PER_ESTIMATED_TOKEN - 1
) // UTF8_BYTES_PER_ESTIMATED_TOKEN
_OPAQUE_SUBJECT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,255}$")
_SPECIALIST_REVIEW_ROLE = re.compile(r"^specialist:[a-z][a-z0-9_]{0,63}(?::[a-z][a-z0-9_]{0,63})?$")
_WHOLE_PROTOCOL_REVIEW_ROLE = re.compile(r"^whole_protocol_review:(?:0|[1-9][0-9]{0,3})$")
_BASE_REVIEW_ROLES = frozenset({"threat_model", "source_audit", "business_logic", "configuration"})
_SCHEDULER_TASK_ID = re.compile(r"^scheduler-task-[0-9a-f]{64}$")
_MAX_ROLE_ALLOCATIONS = 100_000


def _canonical_json_bytes(value: Any, *, ensure_ascii: bool = True) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=ensure_ascii,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


class _FrozenRetrievalProtocolModel(BaseModel):
    """Strict immutable base independent of the aggregate application schemas."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _model_sha256(model: _FrozenRetrievalProtocolModel, *, hash_field: str) -> str:
    return _canonical_sha256(model.model_dump(mode="json", exclude={hash_field}))


def _sealed_model_values(
    model_type: type[_FrozenRetrievalProtocolModel],
    values: dict[str, Any],
    *,
    hash_field: str,
) -> dict[str, Any]:
    if hash_field in values:
        raise ValueError(f"{hash_field} is derived and cannot be supplied")
    provisional_values: dict[str, Any] = {**values, hash_field: "0" * 64}
    provisional = model_type.model_construct(**provisional_values)
    payload = provisional.model_dump(mode="json", exclude={hash_field})
    return {**values, hash_field: _canonical_sha256(payload)}


def _validated_bounded_text(value: str, *, label: str, maximum_length: int) -> str:
    if (
        not value
        or value != value.strip()
        or len(value) > maximum_length
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character).startswith("C") for character in value)
    ):
        raise ValueError(f"{label} is not bounded canonical text")
    return value


def validated_solidity_retrieval_subject_id(value: str) -> str:
    """Validate an opaque identifier without accepting paths, globs, or command text."""

    if _OPAQUE_SUBJECT_ID.fullmatch(value) is None:
        raise ValueError("retrieval subject ID is not an opaque bounded ASCII identifier")
    return value


def _validated_provider_entity_path(value: str) -> str:
    canonical = _validated_bounded_text(
        value,
        label="retrieval entity path",
        maximum_length=4_096,
    )
    pure = PurePosixPath(canonical)
    if (
        "\\" in canonical
        or pure.is_absolute()
        or canonical != pure.as_posix()
        or ".." in pure.parts
        or pure.suffix.lower() != ".sol"
    ):
        raise ValueError("retrieval entity path is not normalized relative Solidity source")
    return canonical


class SolidityRetrievalOperation(StrEnum):
    RESOLVE_ENTITY = "resolve_entity"
    LIST_CALLERS = "list_callers"
    LIST_STATE_WRITERS = "list_state_writers"
    FETCH_INDEXED_RANGE = "fetch_indexed_range"


class SolidityRetrievalStatus(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    REFUSED = "REFUSED"
    EXHAUSTED = "EXHAUSTED"


class SolidityRetrievalReason(StrEnum):
    UNINDEXED_SUBJECT = "UNINDEXED_SUBJECT"
    REDACTED_OR_SECRET_SUBJECT = "REDACTED_OR_SECRET_SUBJECT"
    OUT_OF_SCOPE_SUBJECT = "OUT_OF_SCOPE_SUBJECT"
    GRAPH_UNAVAILABLE = "GRAPH_UNAVAILABLE"
    UPSTREAM_GRAPH_OMISSION = "UPSTREAM_GRAPH_OMISSION"
    RELATED_UNINDEXED = "RELATED_UNINDEXED"
    RELATED_REDACTED_OR_SECRET = "RELATED_REDACTED_OR_SECRET"
    RELATED_OUT_OF_SCOPE = "RELATED_OUT_OF_SCOPE"
    RESULT_ITEM_LIMIT = "RESULT_ITEM_LIMIT"
    RESULT_UTF8_LIMIT = "RESULT_UTF8_LIMIT"
    TOTAL_RESULT_UTF8_BUDGET = "TOTAL_RESULT_UTF8_BUDGET"
    TOTAL_RESULT_TOKEN_BUDGET = "TOTAL_RESULT_TOKEN_BUDGET"
    TRANSCRIPT_UTF8_BUDGET = "TRANSCRIPT_UTF8_BUDGET"
    TRANSCRIPT_TOKEN_BUDGET = "TRANSCRIPT_TOKEN_BUDGET"
    REQUEST_COUNT_BUDGET = "REQUEST_COUNT_BUDGET"
    RETRIEVAL_ALREADY_EXHAUSTED = "RETRIEVAL_ALREADY_EXHAUSTED"


class SolidityRetrievalEntityKind(StrEnum):
    """Closed provider-visible projection of Solidity entity kinds."""

    CONTRACT = "contract"
    INTERFACE = "interface"
    LIBRARY = "library"
    FUNCTION = "function"
    CONSTRUCTOR = "constructor"
    MODIFIER = "modifier"
    EVENT = "event"
    ERROR = "error"
    STRUCT = "struct"
    ENUM = "enum"
    STATE_VARIABLE = "state_variable"
    IMMUTABLE = "immutable"
    CONSTANT = "constant"


class SolidityRetrievalRolePolicy(_FrozenRetrievalProtocolModel):
    """Fixed per-role request, result-size, and conservative token limits."""

    schema_version: Literal["1.0"] = "1.0"
    token_estimator: Literal["MMAUDIT_UTF8_BYTES_DIV3_V1"] = "MMAUDIT_UTF8_BYTES_DIV3_V1"
    role: str = Field(min_length=1, max_length=128)
    maximum_requests: int = Field(
        default=SOLIDITY_RETRIEVAL_MAX_REQUESTS_PER_ROLE,
        ge=0,
        le=SOLIDITY_RETRIEVAL_MAX_REQUESTS_PER_ROLE,
    )
    maximum_results_per_request: int = Field(
        default=SOLIDITY_RETRIEVAL_MAX_RESULTS_PER_REQUEST,
        ge=1,
        le=SOLIDITY_RETRIEVAL_MAX_RESULTS_PER_REQUEST,
    )
    maximum_result_utf8_bytes: int = Field(
        default=SOLIDITY_RETRIEVAL_MAX_RESULT_UTF8_BYTES,
        ge=1,
        le=SOLIDITY_RETRIEVAL_MAX_RESULT_UTF8_BYTES,
    )
    maximum_total_result_utf8_bytes: int = Field(
        default=SOLIDITY_RETRIEVAL_MAX_TOTAL_RESULT_UTF8_BYTES,
        ge=0,
        le=SOLIDITY_RETRIEVAL_MAX_TOTAL_RESULT_UTF8_BYTES,
    )
    maximum_total_result_tokens: int = Field(
        default=SOLIDITY_RETRIEVAL_MAX_TOTAL_RESULT_TOKENS,
        ge=0,
        le=SOLIDITY_RETRIEVAL_MAX_TOTAL_RESULT_TOKENS,
    )
    maximum_transcript_utf8_bytes: int = Field(
        default=SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_UTF8_BYTES,
        ge=SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_UTF8_BYTES,
        le=SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_UTF8_BYTES,
    )
    maximum_transcript_tokens: int = Field(
        default=SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_TOKENS,
        ge=SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_TOKENS,
        le=SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_TOKENS,
    )
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(
        cls,
        *,
        role: str,
        maximum_requests: int = SOLIDITY_RETRIEVAL_MAX_REQUESTS_PER_ROLE,
        maximum_results_per_request: int = SOLIDITY_RETRIEVAL_MAX_RESULTS_PER_REQUEST,
        maximum_result_utf8_bytes: int = SOLIDITY_RETRIEVAL_MAX_RESULT_UTF8_BYTES,
        maximum_total_result_utf8_bytes: int = (SOLIDITY_RETRIEVAL_MAX_TOTAL_RESULT_UTF8_BYTES),
        maximum_total_result_tokens: int = SOLIDITY_RETRIEVAL_MAX_TOTAL_RESULT_TOKENS,
        maximum_transcript_utf8_bytes: int = SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_UTF8_BYTES,
        maximum_transcript_tokens: int = SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_TOKENS,
    ) -> Self:
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "token_estimator": "MMAUDIT_UTF8_BYTES_DIV3_V1",
            "role": role,
            "maximum_requests": maximum_requests,
            "maximum_results_per_request": maximum_results_per_request,
            "maximum_result_utf8_bytes": maximum_result_utf8_bytes,
            "maximum_total_result_utf8_bytes": maximum_total_result_utf8_bytes,
            "maximum_total_result_tokens": maximum_total_result_tokens,
            "maximum_transcript_utf8_bytes": maximum_transcript_utf8_bytes,
            "maximum_transcript_tokens": maximum_transcript_tokens,
        }
        return cls.model_validate(_sealed_model_values(cls, values, hash_field="policy_sha256"))

    @field_validator("role")
    @classmethod
    def role_is_canonical(cls, value: str) -> str:
        canonical = _validated_bounded_text(value, label="retrieval role", maximum_length=128)
        if (
            canonical not in _BASE_REVIEW_ROLES
            and _SPECIALIST_REVIEW_ROLE.fullmatch(canonical) is None
            and _WHOLE_PROTOCOL_REVIEW_ROLE.fullmatch(canonical) is None
        ):
            raise ValueError("retrieval policy role is not a supported review role")
        return canonical

    @model_validator(mode="after")
    def zero_budget_is_an_exact_fallback_allocation(self) -> Self:
        zero_coordinates = (
            self.maximum_requests == 0,
            self.maximum_total_result_utf8_bytes == 0,
            self.maximum_total_result_tokens == 0,
        )
        if any(zero_coordinates) and not all(zero_coordinates):
            raise ValueError(
                "zero retrieval request and aggregate result budgets must be allocated together"
            )
        return self

    @model_validator(mode="after")
    def policy_hash_is_exact(self) -> Self:
        if self.policy_sha256 != _model_sha256(self, hash_field="policy_sha256"):
            raise ValueError("retrieval role policy hash is inconsistent")
        return self


def _validated_primary_task_ids(primary_task_ids: Sequence[str]) -> tuple[str, ...]:
    if isinstance(primary_task_ids, (str, bytes)):
        raise TypeError("retrieval budget task IDs must be a sequence of exact strings")
    if len(primary_task_ids) > _MAX_ROLE_ALLOCATIONS:
        raise ValueError("retrieval role allocation count exceeds its hard cap")
    validated: list[str] = []
    for task_id in primary_task_ids:
        if type(task_id) is not str:
            raise TypeError("retrieval budget task IDs must be exact strings")
        if _SCHEDULER_TASK_ID.fullmatch(task_id) is None:
            raise ValueError("retrieval budget task ID is not a canonical scheduler task ID")
        validated.append(task_id)
    if len(validated) != len(set(validated)):
        raise ValueError("retrieval role allocation task IDs must be unique")
    return tuple(sorted(validated))


def _balanced_parts(total: int, count: int) -> tuple[int, ...]:
    if count == 0:
        return ()
    quotient, remainder = divmod(total, count)
    return tuple(quotient + int(index < remainder) for index in range(count))


def _allocated_policies(
    *,
    ceiling: SolidityRetrievalRolePolicy,
    primary_task_ids: tuple[str, ...],
) -> tuple[SolidityRetrievalRolePolicy, ...]:
    active_count = min(
        len(primary_task_ids),
        ceiling.maximum_requests,
        ceiling.maximum_total_result_utf8_bytes,
        ceiling.maximum_total_result_tokens,
    )
    request_parts = _balanced_parts(ceiling.maximum_requests, active_count)
    byte_parts = _balanced_parts(ceiling.maximum_total_result_utf8_bytes, active_count)
    token_parts = _balanced_parts(ceiling.maximum_total_result_tokens, active_count)

    policies: list[SolidityRetrievalRolePolicy] = []
    for index, _task_id in enumerate(primary_task_ids):
        active = index < active_count
        allocated_bytes = byte_parts[index] if active else 0
        policies.append(
            SolidityRetrievalRolePolicy.build(
                role=ceiling.role,
                maximum_requests=request_parts[index] if active else 0,
                maximum_results_per_request=ceiling.maximum_results_per_request,
                maximum_result_utf8_bytes=(
                    min(ceiling.maximum_result_utf8_bytes, allocated_bytes)
                    if active
                    else ceiling.maximum_result_utf8_bytes
                ),
                maximum_total_result_utf8_bytes=allocated_bytes,
                maximum_total_result_tokens=token_parts[index] if active else 0,
                maximum_transcript_utf8_bytes=ceiling.maximum_transcript_utf8_bytes,
                maximum_transcript_tokens=ceiling.maximum_transcript_tokens,
            )
        )
    return tuple(policies)


class SolidityRetrievalRoleBudgetAllocation(_FrozenRetrievalProtocolModel):
    """One task's immutable share of a run-level retrieval role ceiling."""

    schema_version: Literal["1.0"] = "1.0"
    primary_task_id: str = Field(pattern=r"^scheduler-task-[0-9a-f]{64}$")
    policy: SolidityRetrievalRolePolicy
    allocation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(
        cls,
        *,
        primary_task_id: str,
        policy: SolidityRetrievalRolePolicy,
    ) -> Self:
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "primary_task_id": primary_task_id,
            "policy": SolidityRetrievalRolePolicy.model_validate(policy.model_dump(mode="python")),
        }
        return cls.model_validate(_sealed_model_values(cls, values, hash_field="allocation_sha256"))

    @model_validator(mode="after")
    def allocation_hash_is_exact(self) -> Self:
        if self.allocation_sha256 != _model_sha256(self, hash_field="allocation_sha256"):
            raise ValueError("retrieval role budget allocation hash is inconsistent")
        return self


class SolidityRetrievalRoleBudgetPlan(_FrozenRetrievalProtocolModel):
    """Self-hashed static reservations safe for concurrent shard execution."""

    schema_version: Literal["1.0"] = "1.0"
    role: str = Field(min_length=1, max_length=128)
    ceiling: SolidityRetrievalRolePolicy
    allocations: tuple[SolidityRetrievalRoleBudgetAllocation, ...] = Field(
        max_length=_MAX_ROLE_ALLOCATIONS
    )
    allocated_maximum_requests: int = Field(
        ge=0,
        le=SOLIDITY_RETRIEVAL_MAX_REQUESTS_PER_ROLE,
    )
    allocated_maximum_total_result_utf8_bytes: int = Field(
        ge=0,
        le=SOLIDITY_RETRIEVAL_MAX_TOTAL_RESULT_UTF8_BYTES,
    )
    allocated_maximum_total_result_tokens: int = Field(
        ge=0,
        le=SOLIDITY_RETRIEVAL_MAX_TOTAL_RESULT_TOKENS,
    )
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("allocations", mode="before")
    @classmethod
    def allocations_decode_from_exact_json(
        cls,
        value: object,
    ) -> object:
        """Admit JSON arrays while preserving strict Python-mode tuple custody."""

        return tuple(value) if isinstance(value, list) else value

    @classmethod
    def build(
        cls,
        *,
        role: str,
        primary_task_ids: Sequence[str],
        ceiling: SolidityRetrievalRolePolicy | None = None,
    ) -> Self:
        selected_ceiling = (
            SolidityRetrievalRolePolicy.build(role=role) if ceiling is None else ceiling
        )
        frozen_ceiling = SolidityRetrievalRolePolicy.model_validate(
            selected_ceiling.model_dump(mode="python")
        )
        if frozen_ceiling.role != role:
            raise ValueError("retrieval role budget ceiling differs from its requested role")
        canonical_ids = _validated_primary_task_ids(primary_task_ids)
        policies = _allocated_policies(ceiling=frozen_ceiling, primary_task_ids=canonical_ids)
        allocations = tuple(
            SolidityRetrievalRoleBudgetAllocation.build(
                primary_task_id=task_id,
                policy=policy,
            )
            for task_id, policy in zip(canonical_ids, policies, strict=True)
        )
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "role": role,
            "ceiling": frozen_ceiling,
            "allocations": allocations,
            "allocated_maximum_requests": sum(
                allocation.policy.maximum_requests for allocation in allocations
            ),
            "allocated_maximum_total_result_utf8_bytes": sum(
                allocation.policy.maximum_total_result_utf8_bytes for allocation in allocations
            ),
            "allocated_maximum_total_result_tokens": sum(
                allocation.policy.maximum_total_result_tokens for allocation in allocations
            ),
        }
        return cls.model_validate(_sealed_model_values(cls, values, hash_field="plan_sha256"))

    def allocation_for_task(
        self,
        primary_task_id: str,
    ) -> SolidityRetrievalRoleBudgetAllocation:
        """Return a detached exact reservation for one planned primary task."""

        if (
            type(primary_task_id) is not str
            or _SCHEDULER_TASK_ID.fullmatch(primary_task_id) is None
        ):
            raise ValueError("retrieval budget lookup requires a canonical scheduler task ID")
        for allocation in self.allocations:
            if allocation.primary_task_id == primary_task_id:
                return SolidityRetrievalRoleBudgetAllocation.model_validate(
                    allocation.model_dump(mode="python")
                )
        raise KeyError("retrieval budget plan does not contain the requested primary task")

    def policy_for_task(self, primary_task_id: str) -> SolidityRetrievalRolePolicy:
        """Return a detached exact policy for one planned primary task."""

        allocation = self.allocation_for_task(primary_task_id)
        return SolidityRetrievalRolePolicy.model_validate(
            allocation.policy.model_dump(mode="python")
        )

    @model_validator(mode="after")
    def allocation_and_plan_hashes_are_exact(self) -> Self:
        if self.ceiling.role != self.role:
            raise ValueError("retrieval role budget plan differs from its ceiling role")
        task_ids = tuple(allocation.primary_task_id for allocation in self.allocations)
        if task_ids != tuple(sorted(set(task_ids))):
            raise ValueError("retrieval role budget allocations must be unique and canonical")
        expected_policies = _allocated_policies(ceiling=self.ceiling, primary_task_ids=task_ids)
        if tuple(allocation.policy for allocation in self.allocations) != expected_policies:
            raise ValueError("retrieval role budget allocations differ from the exact static split")
        expected_totals = (
            sum(allocation.policy.maximum_requests for allocation in self.allocations),
            sum(
                allocation.policy.maximum_total_result_utf8_bytes for allocation in self.allocations
            ),
            sum(allocation.policy.maximum_total_result_tokens for allocation in self.allocations),
        )
        if expected_totals != (
            self.allocated_maximum_requests,
            self.allocated_maximum_total_result_utf8_bytes,
            self.allocated_maximum_total_result_tokens,
        ):
            raise ValueError("retrieval role budget plan totals are inconsistent")
        if (
            self.allocated_maximum_requests > self.ceiling.maximum_requests
            or self.allocated_maximum_total_result_utf8_bytes
            > self.ceiling.maximum_total_result_utf8_bytes
            or self.allocated_maximum_total_result_tokens > self.ceiling.maximum_total_result_tokens
        ):
            raise ValueError("retrieval role budget plan exceeds its run-level ceiling")
        if self.plan_sha256 != _model_sha256(self, hash_field="plan_sha256"):
            raise ValueError("retrieval role budget plan hash is inconsistent")
        return self


class SolidityRetrievalIntent(_FrozenRetrievalProtocolModel):
    """Hash-free provider wire intent over the fixed read-only vocabulary."""

    operation: SolidityRetrievalOperation
    subject_id: str = Field(min_length=1, max_length=SOLIDITY_RETRIEVAL_SUBJECT_ID_MAX_LENGTH)

    @field_validator("subject_id")
    @classmethod
    def subject_id_is_opaque(cls, value: str) -> str:
        return validated_solidity_retrieval_subject_id(value)


class SolidityRetrievalRequestBatch(_FrozenRetrievalProtocolModel):
    """Hash-free ordered provider wire batch; the host supplies all custody hashes."""

    schema_version: Literal["1.0"] = "1.0"
    requests: tuple[SolidityRetrievalIntent, ...] = Field(
        max_length=SOLIDITY_RETRIEVAL_MAX_BATCH_REQUESTS,
    )

    @model_validator(mode="after")
    def intent_identities_are_unique(self) -> Self:
        identities = tuple(
            (request.operation.value, request.subject_id) for request in self.requests
        )
        if len(identities) != len(set(identities)):
            raise ValueError("retrieval request batch identities must be unique")
        return self

    def to_host_requests(self) -> tuple[SolidityRetrievalRequest, ...]:
        """Convert validated wire intents to self-hashed host custody records."""

        return tuple(
            SolidityRetrievalRequest.build(
                operation=intent.operation,
                subject_id=intent.subject_id,
            )
            for intent in self.requests
        )


class SolidityRetrievalRequest(_FrozenRetrievalProtocolModel):
    """Host-built, self-hashed request derived from a validated wire intent."""

    schema_version: Literal["1.0"] = "1.0"
    operation: SolidityRetrievalOperation
    subject_id: str = Field(min_length=1, max_length=SOLIDITY_RETRIEVAL_SUBJECT_ID_MAX_LENGTH)
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(
        cls,
        *,
        operation: SolidityRetrievalOperation,
        subject_id: str,
    ) -> Self:
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "operation": operation,
            "subject_id": subject_id,
        }
        return cls.model_validate(_sealed_model_values(cls, values, hash_field="request_sha256"))

    @classmethod
    def from_intent(cls, intent: SolidityRetrievalIntent) -> Self:
        """Attach host custody to one already validated provider wire intent."""

        validated = SolidityRetrievalIntent.model_validate(intent.model_dump(mode="python"))
        return cls.build(operation=validated.operation, subject_id=validated.subject_id)

    @field_validator("subject_id")
    @classmethod
    def subject_id_is_opaque(cls, value: str) -> str:
        return validated_solidity_retrieval_subject_id(value)

    @model_validator(mode="after")
    def request_hash_is_exact(self) -> Self:
        if self.request_sha256 != _model_sha256(self, hash_field="request_sha256"):
            raise ValueError("retrieval request hash is inconsistent")
        return self


class SolidityRetrievalEntity(_FrozenRetrievalProtocolModel):
    """Provider-safe entity projection without docs, labels, metadata, or warnings."""

    subject_id: str = Field(min_length=1, max_length=SOLIDITY_RETRIEVAL_SUBJECT_ID_MAX_LENGTH)
    kind: SolidityRetrievalEntityKind
    name: str = Field(min_length=1, max_length=512)
    contract_name: str | None = Field(default=None, max_length=512)
    path: str = Field(min_length=1, max_length=4_096)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    visibility: str | None = Field(default=None, max_length=64)
    mutability: str | None = Field(default=None, max_length=64)
    payable: bool

    @field_validator("subject_id")
    @classmethod
    def subject_id_is_opaque(cls, value: str) -> str:
        return validated_solidity_retrieval_subject_id(value)

    @field_validator("name")
    @classmethod
    def name_is_safe(cls, value: str) -> str:
        return _validated_bounded_text(
            value,
            label="retrieval entity name",
            maximum_length=512,
        )

    @field_validator("contract_name", "visibility", "mutability")
    @classmethod
    def optional_text_is_safe(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validated_bounded_text(
            value,
            label="retrieval entity attribute",
            maximum_length=512,
        )

    @field_validator("path")
    @classmethod
    def path_is_bounded_public_text(cls, value: str) -> str:
        return _validated_provider_entity_path(value)

    @model_validator(mode="after")
    def line_range_is_ordered(self) -> Self:
        if self.end_line < self.start_line:
            raise ValueError("retrieval entity range is reversed")
        return self


class SolidityRetrievalRecord(_FrozenRetrievalProtocolModel):
    """One safe entity and, only for range fetches, its validated redacted text."""

    entity: SolidityRetrievalEntity
    content: str | None = Field(default=None, max_length=SOLIDITY_RETRIEVAL_MAX_RECORD_CONTENT)

    @model_validator(mode="after")
    def retained_content_matches_the_index_hash(self) -> Self:
        if (
            self.content is not None
            and hashlib.sha256(self.content.encode("utf-8")).hexdigest() != self.entity.source_hash
        ):
            raise ValueError("retrieval record content differs from its indexed range hash")
        return self


def solidity_retrieval_records_utf8_bytes(
    records: Sequence[SolidityRetrievalRecord],
) -> int:
    """Measure canonical provider-visible record bytes without derived hashes."""

    return sum(
        len(_canonical_json_bytes(record.model_dump(mode="json"), ensure_ascii=False))
        for record in records
    )


class SolidityRetrievalOmission(_FrozenRetrievalProtocolModel):
    """Count-only omission or refusal evidence without unsafe subject identities."""

    reason: SolidityRetrievalReason
    count: int = Field(ge=1, le=2**63 - 1)


class SolidityRetrievalResult(_FrozenRetrievalProtocolModel):
    """Typed result whose bounded provider-visible records have exact UTF-8 accounting."""

    schema_version: Literal["1.0"] = "1.0"
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation: SolidityRetrievalOperation
    subject_id: str = Field(min_length=1, max_length=SOLIDITY_RETRIEVAL_SUBJECT_ID_MAX_LENGTH)
    status: SolidityRetrievalStatus
    records: tuple[SolidityRetrievalRecord, ...] = Field(max_length=128)
    omissions: tuple[SolidityRetrievalOmission, ...] = Field(max_length=16)
    result_utf8_bytes: int = Field(ge=0, le=100_000_000)
    estimated_result_tokens: int = Field(ge=0, le=100_000_000)
    result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(
        cls,
        *,
        request: SolidityRetrievalRequest,
        status: SolidityRetrievalStatus,
        records: Sequence[SolidityRetrievalRecord] = (),
        omissions: Sequence[SolidityRetrievalOmission] = (),
    ) -> Self:
        canonical_records = tuple(records)
        canonical_omissions = tuple(sorted(omissions, key=lambda omission: omission.reason.value))
        result_utf8_bytes = solidity_retrieval_records_utf8_bytes(canonical_records)
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "request_sha256": request.request_sha256,
            "operation": request.operation,
            "subject_id": request.subject_id,
            "status": status,
            "records": canonical_records,
            "omissions": canonical_omissions,
            "result_utf8_bytes": result_utf8_bytes,
            "estimated_result_tokens": (result_utf8_bytes + UTF8_BYTES_PER_ESTIMATED_TOKEN - 1)
            // UTF8_BYTES_PER_ESTIMATED_TOKEN,
        }
        return cls.model_validate(_sealed_model_values(cls, values, hash_field="result_sha256"))

    @field_validator("subject_id")
    @classmethod
    def subject_id_is_opaque(cls, value: str) -> str:
        return validated_solidity_retrieval_subject_id(value)

    @model_validator(mode="after")
    def result_shape_accounting_and_hash_are_exact(self) -> Self:
        omission_reasons = tuple(omission.reason.value for omission in self.omissions)
        if omission_reasons != tuple(sorted(set(omission_reasons))):
            raise ValueError("retrieval result omissions must be unique and canonical")
        expected_bytes = solidity_retrieval_records_utf8_bytes(self.records)
        expected_tokens = (
            expected_bytes + UTF8_BYTES_PER_ESTIMATED_TOKEN - 1
        ) // UTF8_BYTES_PER_ESTIMATED_TOKEN
        if (
            self.result_utf8_bytes != expected_bytes
            or self.estimated_result_tokens != expected_tokens
        ):
            raise ValueError("retrieval result UTF-8/token accounting is inconsistent")
        if self.status is SolidityRetrievalStatus.COMPLETE and self.omissions:
            raise ValueError("complete retrieval result cannot carry omissions")
        if self.status is SolidityRetrievalStatus.PARTIAL and (
            not self.omissions
            or self.operation
            not in {
                SolidityRetrievalOperation.LIST_CALLERS,
                SolidityRetrievalOperation.LIST_STATE_WRITERS,
            }
        ):
            raise ValueError("partial retrieval result must be an omitted graph listing")
        if self.status in {
            SolidityRetrievalStatus.REFUSED,
            SolidityRetrievalStatus.UNAVAILABLE,
            SolidityRetrievalStatus.EXHAUSTED,
        } and (self.records or not self.omissions):
            raise ValueError("terminal retrieval result must contain only typed reasons")
        if (
            self.operation
            in {
                SolidityRetrievalOperation.RESOLVE_ENTITY,
                SolidityRetrievalOperation.FETCH_INDEXED_RANGE,
            }
            and self.status is SolidityRetrievalStatus.COMPLETE
            and (len(self.records) != 1 or self.records[0].entity.subject_id != self.subject_id)
        ):
            raise ValueError("direct retrieval result must contain its exact subject")
        if self.operation is SolidityRetrievalOperation.FETCH_INDEXED_RANGE:
            if any(record.content is None for record in self.records):
                raise ValueError("indexed-range result must contain validated redacted content")
        elif any(record.content is not None for record in self.records):
            raise ValueError("only indexed-range results may contain source text")
        if self.result_sha256 != _model_sha256(self, hash_field="result_sha256"):
            raise ValueError("retrieval result hash is inconsistent")
        return self


class SolidityRetrievalExchange(_FrozenRetrievalProtocolModel):
    """One append-only request/result exchange in a hash-linked transcript."""

    schema_version: Literal["1.0"] = "1.0"
    sequence: int = Field(ge=1, le=SOLIDITY_RETRIEVAL_MAX_EXCHANGES)
    previous_exchange_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    request: SolidityRetrievalRequest
    result: SolidityRetrievalResult
    exchange_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(
        cls,
        *,
        sequence: int,
        previous_exchange_sha256: str | None,
        request: SolidityRetrievalRequest,
        result: SolidityRetrievalResult,
    ) -> Self:
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "sequence": sequence,
            "previous_exchange_sha256": previous_exchange_sha256,
            "request": request,
            "result": result,
        }
        return cls.model_validate(_sealed_model_values(cls, values, hash_field="exchange_sha256"))

    @model_validator(mode="after")
    def exchange_bindings_and_hash_are_exact(self) -> Self:
        if (
            self.result.request_sha256 != self.request.request_sha256
            or self.result.operation is not self.request.operation
            or self.result.subject_id != self.request.subject_id
        ):
            raise ValueError("retrieval result is not bound to its exact request")
        if self.exchange_sha256 != _model_sha256(self, hash_field="exchange_sha256"):
            raise ValueError("retrieval exchange hash is inconsistent")
        return self


class SolidityRetrievalTranscript(_FrozenRetrievalProtocolModel):
    """Immutable append-only retrieval history, including typed terminal exhaustion."""

    schema_version: Literal["1.0"] = "1.0"
    role: str = Field(min_length=1, max_length=128)
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    corpus_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    exchanges: tuple[SolidityRetrievalExchange, ...] = Field(
        max_length=SOLIDITY_RETRIEVAL_MAX_EXCHANGES
    )
    accepted_request_count: int = Field(
        ge=0,
        le=SOLIDITY_RETRIEVAL_MAX_REQUESTS_PER_ROLE,
    )
    total_result_utf8_bytes: int = Field(ge=0, le=100_000_000)
    total_estimated_result_tokens: int = Field(ge=0, le=100_000_000)
    retrieval_exhausted: bool
    single_shot_fallback_required: bool
    transcript_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(
        cls,
        *,
        role: str,
        policy_sha256: str,
        corpus_sha256: str,
        exchanges: Sequence[SolidityRetrievalExchange] = (),
        accepted_request_count: int = 0,
    ) -> Self:
        canonical_exchanges = tuple(exchanges)
        retrieval_exhausted = any(
            exchange.result.status is SolidityRetrievalStatus.EXHAUSTED
            for exchange in canonical_exchanges
        )
        single_shot_fallback_required = retrieval_exhausted or not canonical_exchanges
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "role": role,
            "policy_sha256": policy_sha256,
            "corpus_sha256": corpus_sha256,
            "exchanges": canonical_exchanges,
            "accepted_request_count": accepted_request_count,
            "total_result_utf8_bytes": sum(
                exchange.result.result_utf8_bytes for exchange in canonical_exchanges
            ),
            "total_estimated_result_tokens": sum(
                exchange.result.estimated_result_tokens for exchange in canonical_exchanges
            ),
            "retrieval_exhausted": retrieval_exhausted,
            "single_shot_fallback_required": single_shot_fallback_required,
        }
        return cls.model_validate(_sealed_model_values(cls, values, hash_field="transcript_sha256"))

    @field_validator("role")
    @classmethod
    def role_is_canonical(cls, value: str) -> str:
        return _validated_bounded_text(
            value,
            label="retrieval transcript role",
            maximum_length=128,
        )

    @model_validator(mode="after")
    def transcript_chain_totals_and_hash_are_exact(self) -> Self:
        previous: str | None = None
        exhausted_positions: list[int] = []
        request_identities: list[tuple[str, str]] = []
        for sequence, exchange in enumerate(self.exchanges, start=1):
            if exchange.sequence != sequence or exchange.previous_exchange_sha256 != previous:
                raise ValueError("retrieval transcript exchange chain is inconsistent")
            request_identities.append(
                (exchange.request.operation.value, exchange.request.subject_id)
            )
            if exchange.result.status is SolidityRetrievalStatus.EXHAUSTED:
                exhausted_positions.append(sequence)
            previous = exchange.exchange_sha256
        if len(request_identities) != len(set(request_identities)):
            raise ValueError("retrieval transcript request identities must be unique")
        if exhausted_positions and exhausted_positions != list(
            range(exhausted_positions[0], len(self.exchanges) + 1)
        ):
            raise ValueError("retrieval exhaustion must form one terminal exchange suffix")
        expected_accepted = sum(
            not {
                SolidityRetrievalReason.REQUEST_COUNT_BUDGET,
                SolidityRetrievalReason.RETRIEVAL_ALREADY_EXHAUSTED,
            }
            & {omission.reason for omission in exchange.result.omissions}
            for exchange in self.exchanges
        )
        if self.accepted_request_count != expected_accepted:
            raise ValueError("retrieval accepted-request count is inconsistent")
        if self.total_result_utf8_bytes != sum(
            exchange.result.result_utf8_bytes for exchange in self.exchanges
        ) or self.total_estimated_result_tokens != sum(
            exchange.result.estimated_result_tokens for exchange in self.exchanges
        ):
            raise ValueError("retrieval transcript result totals are inconsistent")
        expected_exhausted = bool(exhausted_positions)
        expected_single_shot = expected_exhausted or not self.exchanges
        if (
            self.retrieval_exhausted is not expected_exhausted
            or self.single_shot_fallback_required is not expected_single_shot
        ):
            raise ValueError("retrieval fallback state differs from its exact exchange state")
        if self.transcript_sha256 != _model_sha256(self, hash_field="transcript_sha256"):
            raise ValueError("retrieval transcript hash is inconsistent")
        return self


def solidity_retrieval_transcript_utf8_bytes(
    transcript: SolidityRetrievalTranscript,
) -> int:
    """Measure the exact inner JSON block rendered to the final review role."""

    validated = SolidityRetrievalTranscript.model_validate(transcript.model_dump(mode="python"))
    return len(
        json.dumps(
            validated.model_dump(mode="json"),
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")
    )


def require_solidity_retrieval_transcript_within_policy(
    policy: SolidityRetrievalRolePolicy,
    transcript: SolidityRetrievalTranscript,
) -> None:
    """Reject a self-consistent transcript that exceeds its exact role allocation."""

    frozen_policy = SolidityRetrievalRolePolicy.model_validate(policy.model_dump(mode="python"))
    frozen_transcript = SolidityRetrievalTranscript.model_validate(
        transcript.model_dump(mode="python")
    )
    transcript_utf8_bytes = solidity_retrieval_transcript_utf8_bytes(frozen_transcript)
    transcript_tokens = (
        transcript_utf8_bytes + UTF8_BYTES_PER_ESTIMATED_TOKEN - 1
    ) // UTF8_BYTES_PER_ESTIMATED_TOKEN
    if (
        frozen_transcript.role != frozen_policy.role
        or frozen_transcript.policy_sha256 != frozen_policy.policy_sha256
        or frozen_transcript.accepted_request_count > frozen_policy.maximum_requests
        or frozen_transcript.total_result_utf8_bytes > frozen_policy.maximum_total_result_utf8_bytes
        or frozen_transcript.total_estimated_result_tokens
        > frozen_policy.maximum_total_result_tokens
        or transcript_utf8_bytes > frozen_policy.maximum_transcript_utf8_bytes
        or transcript_tokens > frozen_policy.maximum_transcript_tokens
        or any(
            len(exchange.result.records) > frozen_policy.maximum_results_per_request
            or exchange.result.result_utf8_bytes > frozen_policy.maximum_result_utf8_bytes
            for exchange in frozen_transcript.exchanges
        )
    ):
        raise ValueError("retrieval transcript exceeds its exact role policy")


__all__ = [
    "SOLIDITY_RETRIEVAL_MAX_BATCH_REQUESTS",
    "SOLIDITY_RETRIEVAL_MAX_EXCHANGES",
    "SOLIDITY_RETRIEVAL_MAX_REQUESTS_PER_ROLE",
    "SOLIDITY_RETRIEVAL_MAX_RESULTS_PER_REQUEST",
    "SOLIDITY_RETRIEVAL_MAX_RESULT_UTF8_BYTES",
    "SOLIDITY_RETRIEVAL_MAX_TOTAL_RESULT_TOKENS",
    "SOLIDITY_RETRIEVAL_MAX_TOTAL_RESULT_UTF8_BYTES",
    "SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_TOKENS",
    "SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_UTF8_BYTES",
    "SOLIDITY_RETRIEVAL_SUBJECT_ID_MAX_LENGTH",
    "SolidityRetrievalEntity",
    "SolidityRetrievalEntityKind",
    "SolidityRetrievalExchange",
    "SolidityRetrievalIntent",
    "SolidityRetrievalOmission",
    "SolidityRetrievalOperation",
    "SolidityRetrievalReason",
    "SolidityRetrievalRecord",
    "SolidityRetrievalRequest",
    "SolidityRetrievalRequestBatch",
    "SolidityRetrievalResult",
    "SolidityRetrievalRoleBudgetAllocation",
    "SolidityRetrievalRoleBudgetPlan",
    "SolidityRetrievalRolePolicy",
    "SolidityRetrievalStatus",
    "SolidityRetrievalTranscript",
    "require_solidity_retrieval_transcript_within_policy",
    "solidity_retrieval_records_utf8_bytes",
    "solidity_retrieval_transcript_utf8_bytes",
    "validated_solidity_retrieval_subject_id",
]
