"""Bounded diagnostic projections; never retain model prose or grant admission."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal, Self, cast, get_args

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from mmaudit.models.structured_output import StructuredOutputFailureCode

MAX_DEVELOPMENT_SCHEMA_ISSUES = 8


class DevelopmentResponseFailureReason(StrEnum):
    CONTENT_ENCODING = "CONTENT_ENCODING"
    CONTENT_LENGTH = "CONTENT_LENGTH"
    RESPONSE_SIZE = "RESPONSE_SIZE"
    RESPONSE_JSON = "RESPONSE_JSON"
    GENERATION_ID = "GENERATION_ID"
    COMPLETION_OBJECT = "COMPLETION_OBJECT"
    USAGE = "USAGE"
    TOKEN_COUNTS = "TOKEN_COUNTS"
    SERVER_TOOLS = "SERVER_TOOLS"
    CHOICES = "CHOICES"
    CHOICE_INDEX = "CHOICE_INDEX"
    MESSAGE = "MESSAGE"
    STRUCTURED_OUTPUT = "STRUCTURED_OUTPUT"
    FINDING_LINE_BOUNDS = "FINDING_LINE_BOUNDS"
    ORIGIN_FILE_SCOPE = "ORIGIN_FILE_SCOPE"
    ORIGIN_LINE_BOUNDS = "ORIGIN_LINE_BOUNDS"


class DevelopmentResponseField(StrEnum):
    RESPONSE = "response"
    SCHEMA_VERSION = "schema_version"
    SUMMARY = "summary"
    FINDINGS = "findings"
    FINDING = "finding"
    TITLE = "title"
    SEVERITY = "severity"
    LINE_START = "line_start"
    LINE_END = "line_end"
    KIND = "kind"
    VULNERABILITY_CLASS = "vulnerability_class"
    VIOLATED_INVARIANT = "violated_invariant"
    ROOT_CAUSE_REF = "root_cause_ref"
    ORIGIN_FILENAME = "root_cause_ref.filename"
    ORIGIN_LINE_START = "root_cause_ref.line_start"
    ORIGIN_LINE_END = "root_cause_ref.line_end"
    EXPLANATION = "explanation"
    RECOMMENDATION = "recommendation"


class DevelopmentSchemaConstraint(StrEnum):
    REQUIRED_FIELD = "REQUIRED_FIELD"
    EXTRA_FIELD = "EXTRA_FIELD"
    FIELD_TYPE = "FIELD_TYPE"
    ENUM_VALUE = "ENUM_VALUE"
    FIELD_BOUND = "FIELD_BOUND"
    FIELD_FORMAT = "FIELD_FORMAT"
    LINE_ORDER = "LINE_ORDER"
    ADVISORY_FIELD_MUST_BE_NULL = "ADVISORY_FIELD_MUST_BE_NULL"
    INVARIANT_FIELD_MUST_BE_SET = "INVARIANT_FIELD_MUST_BE_SET"
    SCHEMA_CONSTRAINT = "SCHEMA_CONSTRAINT"


_ROOT_FIELDS = frozenset(
    {
        DevelopmentResponseField.RESPONSE,
        DevelopmentResponseField.SCHEMA_VERSION,
        DevelopmentResponseField.SUMMARY,
        DevelopmentResponseField.FINDINGS,
    }
)
_FINDING_FIELDS = frozenset(DevelopmentResponseField) - _ROOT_FIELDS
_ORIGIN_FIELDS = {
    "filename": DevelopmentResponseField.ORIGIN_FILENAME,
    "line_start": DevelopmentResponseField.ORIGIN_LINE_START,
    "line_end": DevelopmentResponseField.ORIGIN_LINE_END,
}
_DIRECT_FINDING_FIELDS = (
    _FINDING_FIELDS - frozenset(_ORIGIN_FIELDS.values()) - {DevelopmentResponseField.FINDING}
)
_BODY_REASONS = frozenset(
    {
        DevelopmentResponseFailureReason.CONTENT_ENCODING,
        DevelopmentResponseFailureReason.CONTENT_LENGTH,
        DevelopmentResponseFailureReason.RESPONSE_SIZE,
        DevelopmentResponseFailureReason.RESPONSE_JSON,
    }
)
_SOURCE_REASONS = {
    DevelopmentResponseFailureReason.FINDING_LINE_BOUNDS: DevelopmentResponseField.LINE_END,
    DevelopmentResponseFailureReason.ORIGIN_FILE_SCOPE: DevelopmentResponseField.ORIGIN_FILENAME,
    DevelopmentResponseFailureReason.ORIGIN_LINE_BOUNDS: DevelopmentResponseField.ORIGIN_LINE_END,
}


class _DiagnosticModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, revalidate_instances="always"
    )


type _TelemetryState = Literal["REPORTED", "NOT_REPORTED", "INVALID", "UNRECOGNIZED", "AMBIGUOUS"]
type _Consistency = Literal["CONSISTENT", "INCONSISTENT", "NOT_OBSERVED"]
type _FinishReason = Literal["stop", "length", "tool_calls", "content_filter", "error"]
type _NativeFinishReason = Literal[
    "stop",
    "stop_sequence",
    "end_turn",
    "eos_token",
    "completed",
    "length",
    "max_tokens",
    "model_length",
    "tool_calls",
    "function_call",
    "content_filter",
    "error",
]
MAX_DEVELOPMENT_TELEMETRY_TOKENS = 4_000_000


class DevelopmentTelemetryCount(_DiagnosticModel):
    """One reported bounded integer; missing and invalid values are not zero."""

    state: Literal["REPORTED", "NOT_REPORTED", "INVALID"]
    value: int | None = Field(ge=0, le=MAX_DEVELOPMENT_TELEMETRY_TOKENS)

    @model_validator(mode="after")
    def count_is_coherent(self) -> Self:
        if (self.state == "REPORTED") != (self.value is not None):
            raise ValueError("development telemetry count differs from its observation state")
        return self


def _count_consistency(
    prompt: DevelopmentTelemetryCount,
    completion: DevelopmentTelemetryCount,
    total: DevelopmentTelemetryCount,
    reasoning: DevelopmentTelemetryCount,
) -> tuple[_Consistency, _Consistency]:
    summed: _Consistency = "NOT_OBSERVED"
    subset: _Consistency = "NOT_OBSERVED"
    if prompt.value is not None and completion.value is not None and total.value is not None:
        summed = "CONSISTENT" if prompt.value + completion.value == total.value else "INCONSISTENT"
    if reasoning.value is not None and completion.value is not None:
        subset = "CONSISTENT" if reasoning.value <= completion.value else "INCONSISTENT"
    return summed, subset


class DevelopmentCompletionTelemetry(_DiagnosticModel):
    """Parsed metadata only: the body hash does not authenticate provider usage or identity."""

    schema_version: Literal["1.0"] = "1.0"
    interpretation: Literal["REPORTED_METADATA_NOT_VERIFIED_USAGE"] = (
        "REPORTED_METADATA_NOT_VERIFIED_USAGE"
    )
    response_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    finish_reason: _FinishReason | None
    finish_reason_state: _TelemetryState
    native_finish_reason: _NativeFinishReason | None
    native_finish_reason_state: _TelemetryState
    prompt_tokens: DevelopmentTelemetryCount
    completion_tokens: DevelopmentTelemetryCount
    total_tokens: DevelopmentTelemetryCount
    reasoning_tokens: DevelopmentTelemetryCount
    token_sum_consistency: _Consistency
    reasoning_subset_consistency: _Consistency

    @model_validator(mode="after")
    def telemetry_is_coherent(self) -> Self:
        for value, state in (
            (self.finish_reason, self.finish_reason_state),
            (self.native_finish_reason, self.native_finish_reason_state),
        ):
            if (state == "REPORTED") != (value is not None):
                raise ValueError("development finish metadata differs from its observation state")
        expected = _count_consistency(
            self.prompt_tokens, self.completion_tokens, self.total_tokens, self.reasoning_tokens
        )
        if expected != (self.token_sum_consistency, self.reasoning_subset_consistency):
            raise ValueError("development telemetry consistency does not recompute")
        return self


def _telemetry_count(container: object, name: str) -> DevelopmentTelemetryCount:
    if container is None:
        return DevelopmentTelemetryCount(state="NOT_REPORTED", value=None)
    if type(container) is not dict:
        return DevelopmentTelemetryCount(state="INVALID", value=None)
    value = container.get(name)
    if value is None:
        return DevelopmentTelemetryCount(state="NOT_REPORTED", value=None)
    if type(value) is not int or not 0 <= value <= MAX_DEVELOPMENT_TELEMETRY_TOKENS:
        return DevelopmentTelemetryCount(state="INVALID", value=None)
    return DevelopmentTelemetryCount(state="REPORTED", value=value)


def _telemetry_finish(choices: object, *, native: bool) -> tuple[_TelemetryState, str | None]:
    if choices is None:
        return "NOT_REPORTED", None
    if type(choices) is not list:
        return "INVALID", None
    if len(choices) != 1:
        return "AMBIGUOUS", None
    choice = choices[0]
    if type(choice) is not dict or type(choice.get("index")) is not int or choice["index"] != 0:
        return "INVALID", None
    value = choice.get("native_finish_reason" if native else "finish_reason")
    if value is None:
        return "NOT_REPORTED", None
    if type(value) is not str:
        return "INVALID", None
    # Native completion spelling is normalized exactly as in the existing admission predicate.
    normalized = value.casefold() if native else value
    allowed = get_args(_NativeFinishReason.__value__ if native else _FinishReason.__value__)
    if normalized not in allowed:
        return "UNRECOGNIZED", None
    return "REPORTED", normalized


def project_development_completion_telemetry(
    payload: dict[str, Any], *, response_sha256: str
) -> DevelopmentCompletionTelemetry:
    """Project an already bounded, strictly decoded body; never infer usage or retain text."""

    if type(payload) is not dict:
        raise ValueError("development completion telemetry requires a parsed response object")
    usage = payload.get("usage")
    prompt = _telemetry_count(usage, "prompt_tokens")
    completion = _telemetry_count(usage, "completion_tokens")
    total = _telemetry_count(usage, "total_tokens")
    details = usage.get("completion_tokens_details") if type(usage) is dict else usage
    reasoning = _telemetry_count(details, "reasoning_tokens")
    finish_state, finish = _telemetry_finish(payload.get("choices"), native=False)
    native_state, native_finish = _telemetry_finish(payload.get("choices"), native=True)
    summed, subset = _count_consistency(prompt, completion, total, reasoning)
    return DevelopmentCompletionTelemetry(
        response_sha256=response_sha256,
        finish_reason=cast(_FinishReason | None, finish),
        finish_reason_state=finish_state,
        native_finish_reason=cast(_NativeFinishReason | None, native_finish),
        native_finish_reason_state=native_state,
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=total,
        reasoning_tokens=reasoning,
        token_sum_consistency=summed,
        reasoning_subset_consistency=subset,
    )


class DevelopmentSchemaIssue(_DiagnosticModel):
    """A known schema coordinate, never an input-authored key, value or error message."""

    constraint: DevelopmentSchemaConstraint
    field: DevelopmentResponseField
    finding_index: int | None = Field(ge=0, le=15)

    @model_validator(mode="after")
    def location_is_coherent(self) -> Self:
        if (self.finding_index is not None) != (self.field in _FINDING_FIELDS):
            raise ValueError("development schema coordinate lacks its bounded finding index")
        if self.constraint in {
            DevelopmentSchemaConstraint.ADVISORY_FIELD_MUST_BE_NULL,
            DevelopmentSchemaConstraint.INVARIANT_FIELD_MUST_BE_SET,
        } and self.field not in {
            DevelopmentResponseField.VULNERABILITY_CLASS,
            DevelopmentResponseField.VIOLATED_INVARIANT,
            DevelopmentResponseField.ROOT_CAUSE_REF,
        }:
            raise ValueError("development claim-kind constraint names an unrelated field")
        return self


class DevelopmentResponseRejection(_DiagnosticModel):
    """Hash-bound refusal detail, meaningful only with its incomplete parent observation."""

    schema_version: Literal["1.0"] = "1.0"
    stage: Literal["HTTP_BODY", "COMPLETION_ENVELOPE", "STRUCTURED_OUTPUT", "SOURCE_SCOPE"]
    reason: DevelopmentResponseFailureReason
    response_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    structured_failure: StructuredOutputFailureCode | None = None
    schema_issues: tuple[DevelopmentSchemaIssue, ...] = Field(
        default=(), max_length=MAX_DEVELOPMENT_SCHEMA_ISSUES
    )
    schema_issues_truncated: bool = False
    finding_index: int | None = Field(default=None, ge=0, le=15)
    field: DevelopmentResponseField | None = None

    @model_validator(mode="after")
    def detail_is_coherent(self) -> Self:
        if self.stage != development_failure_stage(self.reason):
            raise ValueError("development rejection stage differs from its reason")
        structured = self.reason is DevelopmentResponseFailureReason.STRUCTURED_OUTPUT
        if structured != (self.structured_failure is not None):
            raise ValueError("development structured rejection lacks its exact failure code")
        if (self.schema_issues or self.schema_issues_truncated) and (
            self.structured_failure is not StructuredOutputFailureCode.SCHEMA_VALIDATION_FAILED
        ):
            raise ValueError("schema details require a schema rejection")
        if (
            self.schema_issues_truncated
            and len(self.schema_issues) != MAX_DEVELOPMENT_SCHEMA_ISSUES
        ):
            raise ValueError("truncated schema projection must retain its full bounded prefix")
        expected_field = _SOURCE_REASONS.get(self.reason)
        if self.field != expected_field or (self.finding_index is not None) != (
            expected_field is not None
        ):
            raise ValueError("development source rejection has inconsistent coordinates")
        return self


def development_failure_stage(
    reason: DevelopmentResponseFailureReason,
) -> Literal["HTTP_BODY", "COMPLETION_ENVELOPE", "STRUCTURED_OUTPUT", "SOURCE_SCOPE"]:
    if reason in _BODY_REASONS:
        return "HTTP_BODY"
    if reason in _SOURCE_REASONS:
        return "SOURCE_SCOPE"
    if reason is DevelopmentResponseFailureReason.STRUCTURED_OUTPUT:
        return "STRUCTURED_OUTPUT"
    return "COMPLETION_ENVELOPE"


def _schema_location(
    location: tuple[str | int, ...],
) -> tuple[DevelopmentResponseField, int | None]:
    if len(location) == 1 and location[0] in _ROOT_FIELDS:
        return DevelopmentResponseField(str(location[0])), None
    if not location or location[0] != "findings":
        return DevelopmentResponseField.RESPONSE, None
    if len(location) < 2 or type(location[1]) is not int or not 0 <= location[1] < 16:
        return DevelopmentResponseField.FINDINGS, None
    index = location[1]
    tail = location[2:]
    if len(tail) == 2 and tail[0] == "root_cause_ref" and tail[1] in _ORIGIN_FIELDS:
        return _ORIGIN_FIELDS[str(tail[1])], index
    if len(tail) == 1 and tail[0] in _DIRECT_FINDING_FIELDS:
        return DevelopmentResponseField(str(tail[0])), index
    if tail and tail[0] == "root_cause_ref":
        return DevelopmentResponseField.ROOT_CAUSE_REF, index
    return DevelopmentResponseField.FINDING, index


def _schema_constraint(
    code: str,
) -> tuple[DevelopmentSchemaConstraint, DevelopmentResponseField | None]:
    for name in ("vulnerability_class", "violated_invariant", "root_cause_ref"):
        if code == "development_advisory_" + name:
            return (
                DevelopmentSchemaConstraint.ADVISORY_FIELD_MUST_BE_NULL,
                DevelopmentResponseField(name),
            )
        if code == "development_invariant_" + name:
            return (
                DevelopmentSchemaConstraint.INVARIANT_FIELD_MUST_BE_SET,
                DevelopmentResponseField(name),
            )
    if code in {"development_finding_line_order", "development_origin_line_order"}:
        return DevelopmentSchemaConstraint.LINE_ORDER, None
    if code == "missing":
        return DevelopmentSchemaConstraint.REQUIRED_FIELD, None
    if code == "extra_forbidden":
        return DevelopmentSchemaConstraint.EXTRA_FIELD, None
    if code in {"int_type", "string_type", "tuple_type", "model_type", "model_attributes_type"}:
        return DevelopmentSchemaConstraint.FIELD_TYPE, None
    if code in {"literal_error", "enum"}:
        return DevelopmentSchemaConstraint.ENUM_VALUE, None
    if code in {
        "greater_than_equal",
        "less_than_equal",
        "string_too_short",
        "string_too_long",
        "too_long",
        "too_short",
    }:
        return DevelopmentSchemaConstraint.FIELD_BOUND, None
    if code == "string_pattern_mismatch":
        return DevelopmentSchemaConstraint.FIELD_FORMAT, None
    return DevelopmentSchemaConstraint.SCHEMA_CONSTRAINT, None


def project_development_schema_failure(
    error: ValidationError,
) -> tuple[tuple[DevelopmentSchemaIssue, ...], bool]:
    """Project a bounded prefix through constants; never copy messages, inputs or contexts."""

    issues: list[DevelopmentSchemaIssue] = []
    for item in error.errors(include_input=False, include_context=False, include_url=False)[
        :MAX_DEVELOPMENT_SCHEMA_ISSUES
    ]:
        field, index = _schema_location(item["loc"])
        constraint, override = _schema_constraint(item["type"])
        if override is not None and index is not None:
            field = override
        issues.append(
            DevelopmentSchemaIssue(constraint=constraint, field=field, finding_index=index)
        )
    return tuple(issues), error.error_count() > MAX_DEVELOPMENT_SCHEMA_ISSUES
