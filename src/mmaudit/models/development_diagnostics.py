"""Bounded diagnostic projections; never retain rejected values or grant admission."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

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
