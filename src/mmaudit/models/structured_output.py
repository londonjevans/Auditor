"""Strict local decoding and syntax-envelope repair for model JSON responses."""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal, Never

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from pydantic_core import SchemaValidator

_SHA256_PATTERN = r"^[0-9a-f]{64}$"


class StructuredOutputFailureCode(StrEnum):
    """Non-secret classification for one rejected structured response."""

    TRUNCATED_RESPONSE = "TRUNCATED_RESPONSE"
    INVALID_JSON_SYNTAX = "INVALID_JSON_SYNTAX"
    DUPLICATE_OBJECT_KEY = "DUPLICATE_OBJECT_KEY"
    NON_FINITE_NUMBER = "NON_FINITE_NUMBER"
    SCHEMA_VALIDATION_FAILED = "SCHEMA_VALIDATION_FAILED"


class StructuredOutputRepairAlgorithm(StrEnum):
    """Allowlisted local transformations that cannot rewrite conclusions."""

    SINGLE_JSON_CODE_FENCE_V1 = "SINGLE_JSON_CODE_FENCE_V1"


class StructuredOutputRepairEvidence(BaseModel):
    """Self-hashed evidence for one deterministic syntax-envelope removal."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    algorithm: Literal[StructuredOutputRepairAlgorithm.SINGLE_JSON_CODE_FENCE_V1]
    repair_attempt: Literal[1]
    semantic_rewrite: Literal[False]
    original_response_sha256: str = Field(pattern=_SHA256_PATTERN)
    repaired_response_sha256: str = Field(pattern=_SHA256_PATTERN)
    original_response_bytes: int = Field(ge=1)
    repaired_response_bytes: int = Field(ge=1)
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def evidence_is_coherent_and_self_hashed(self) -> StructuredOutputRepairEvidence:
        if self.original_response_sha256 == self.repaired_response_sha256:
            raise ValueError("structured-output repair must change the response envelope")
        if self.repaired_response_bytes >= self.original_response_bytes:
            raise ValueError("structured-output envelope repair must reduce the byte length")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected:
            raise ValueError("structured-output repair evidence hash is inconsistent")
        return self

    def binds(self, *, original_response: str, repaired_response: str) -> bool:
        """Return whether the evidence binds an exact, otherwise unchanged payload."""

        extracted = _extract_single_json_code_fence(original_response)
        return (
            extracted == repaired_response
            and self.original_response_sha256 == _text_sha256(original_response)
            and self.repaired_response_sha256 == _text_sha256(repaired_response)
            and self.original_response_bytes == len(original_response.encode("utf-8"))
            and self.repaired_response_bytes == len(repaired_response.encode("utf-8"))
        )


@dataclass(frozen=True, slots=True)
class StructuredOutputDecodeResult[ResponseT: BaseModel]:
    """Validated value plus hash-only evidence about the provider response."""

    value: ResponseT
    original_response_sha256: str
    validated_json_sha256: str
    repair_evidence: StructuredOutputRepairEvidence | None

    @property
    def repair_used(self) -> bool:
        """Return whether validation required the one allowlisted repair."""

        return self.repair_evidence is not None


class StructuredOutputDecodeError(ValueError):
    """Safe, typed rejection that never retains raw model output."""

    def __init__(
        self,
        code: StructuredOutputFailureCode,
        *,
        repair_evidence: StructuredOutputRepairEvidence | None = None,
    ) -> None:
        self.code = code
        self.repair_evidence = repair_evidence
        super().__init__(f"structured output rejected: {code.value}")


class _DuplicateObjectKeyError(ValueError):
    """Internal sentinel that intentionally omits the duplicate key."""


class _NonFiniteNumberError(ValueError):
    """Internal sentinel that intentionally omits the rejected constant."""


class _OmittedStructuredFieldError(ValueError):
    """Internal sentinel that intentionally omits model field names and values."""


def decode_structured_output[ResponseT: BaseModel](
    content: str,
    response_model: type[ResponseT],
    *,
    max_repair_attempts: int = 0,
    truncated: bool = False,
) -> StructuredOutputDecodeResult[ResponseT]:
    """Strictly decode one complete response, optionally removing one JSON fence.

    Repair is local and syntax-envelope-only: a single response-spanning
    ``json`` code fence may be removed. The bytes inside the fence are never
    edited, and malformed or schema-invalid payloads remain rejected.
    """

    if not isinstance(content, str):
        raise TypeError("structured output content must be text")
    if not isinstance(response_model, type) or not issubclass(response_model, BaseModel):
        raise TypeError("response_model must be a Pydantic BaseModel type")
    if type(max_repair_attempts) is not int or max_repair_attempts not in {0, 1}:
        raise ValueError("max_repair_attempts must be zero or one")
    if type(truncated) is not bool:
        raise TypeError("truncated must be a boolean")

    schema_validator = getattr(response_model, "__pydantic_validator__", None)
    core_schema = getattr(response_model, "__pydantic_core_schema__", None)
    if not isinstance(schema_validator, SchemaValidator) or core_schema is None:
        raise TypeError("response_model lacks a live Pydantic schema")
    return _decode_structured_output_with_schema_generation(
        content,
        response_model,
        schema_validator=schema_validator,
        core_schema=core_schema,
        max_repair_attempts=max_repair_attempts,
        truncated=truncated,
    )


def _decode_structured_output_with_schema_generation[ResponseT: BaseModel](
    content: str,
    response_model: type[ResponseT],
    *,
    schema_validator: SchemaValidator,
    core_schema: object,
    max_repair_attempts: int = 0,
    truncated: bool = False,
) -> StructuredOutputDecodeResult[ResponseT]:
    """Decode against one exact caller-captured validator/core-schema generation."""

    if (
        getattr(response_model, "__pydantic_validator__", None) is not schema_validator
        or getattr(response_model, "__pydantic_core_schema__", None) is not core_schema
    ):
        raise StructuredOutputDecodeError(StructuredOutputFailureCode.SCHEMA_VALIDATION_FAILED)

    original_sha256 = _text_sha256(content)
    if truncated:
        raise StructuredOutputDecodeError(StructuredOutputFailureCode.TRUNCATED_RESPONSE)

    try:
        value = _decode_and_validate(
            content,
            response_model,
            schema_validator=schema_validator,
            core_schema=core_schema,
        )
    except StructuredOutputDecodeError:
        if max_repair_attempts == 0:
            raise
        repaired = _extract_single_json_code_fence(content)
        if repaired is None:
            raise
        repair_evidence = _seal_repair_evidence(
            original_response=content,
            repaired_response=repaired,
        )
        try:
            value = _decode_and_validate(
                repaired,
                response_model,
                schema_validator=schema_validator,
                core_schema=core_schema,
            )
        except StructuredOutputDecodeError as repaired_error:
            raise StructuredOutputDecodeError(
                repaired_error.code,
                repair_evidence=repair_evidence,
            ) from None
        return StructuredOutputDecodeResult(
            value=value,
            original_response_sha256=original_sha256,
            validated_json_sha256=_text_sha256(repaired),
            repair_evidence=repair_evidence,
        )

    return StructuredOutputDecodeResult(
        value=value,
        original_response_sha256=original_sha256,
        validated_json_sha256=original_sha256,
        repair_evidence=None,
    )


def _decode_and_validate[ResponseT: BaseModel](
    content: str,
    response_model: type[ResponseT],
    *,
    schema_validator: SchemaValidator,
    core_schema: object,
) -> ResponseT:
    decode_failure: StructuredOutputFailureCode | None = None
    try:
        json.loads(
            content,
            object_pairs_hook=_reject_duplicate_object_pairs,
            parse_constant=_reject_non_finite_number,
            parse_float=_validate_finite_json_float,
        )
    except _DuplicateObjectKeyError:
        decode_failure = StructuredOutputFailureCode.DUPLICATE_OBJECT_KEY
    except _NonFiniteNumberError:
        decode_failure = StructuredOutputFailureCode.NON_FINITE_NUMBER
    except (json.JSONDecodeError, UnicodeError, RecursionError):
        decode_failure = StructuredOutputFailureCode.INVALID_JSON_SYNTAX
    if decode_failure is not None:
        raise StructuredOutputDecodeError(decode_failure)

    value: ResponseT | None = None
    with contextlib.suppress(
        ValidationError,
        ValueError,
        TypeError,
        AssertionError,
    ):
        # Validate the original document in strict JSON mode after the defensive
        # preflight above. Strict Python-mode validation would reject legitimate
        # JSON representations of types such as StrEnum, while non-strict
        # Python-mode validation would permit coercions such as "2" to 2.
        candidate = schema_validator.validate_json(
            content,
            strict=True,
            extra="forbid",
        )
        if type(candidate) is not response_model:
            raise TypeError("schema validator returned the wrong response type")
        if (
            getattr(response_model, "__pydantic_validator__", None) is not schema_validator
            or getattr(response_model, "__pydantic_core_schema__", None) is not core_schema
        ):
            raise ValueError("response model changed during JSON validation")
        _ensure_all_fields_supplied(candidate)
        detached = schema_validator.validate_python(
            candidate.model_dump(mode="python", round_trip=True),
            strict=True,
            extra="forbid",
        )
        if type(detached) is not response_model:
            raise TypeError("schema validator returned the wrong detached response type")
        if (
            getattr(response_model, "__pydantic_validator__", None) is not schema_validator
            or getattr(response_model, "__pydantic_core_schema__", None) is not core_schema
        ):
            raise ValueError("response model changed during detached validation")
        _ensure_all_fields_supplied(detached)
        value = detached
    if value is None:
        raise StructuredOutputDecodeError(StructuredOutputFailureCode.SCHEMA_VALIDATION_FAILED)
    return value


def _ensure_all_fields_supplied(value: Any) -> None:
    if isinstance(value, BaseModel):
        if set(type(value).model_fields) - value.model_fields_set:
            raise _OmittedStructuredFieldError
        for name in type(value).model_fields:
            _ensure_all_fields_supplied(getattr(value, name))
        return
    if isinstance(value, Mapping):
        for item in value.values():
            _ensure_all_fields_supplied(item)
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            _ensure_all_fields_supplied(item)


def _reject_duplicate_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    for key, value in pairs:
        if key in decoded:
            raise _DuplicateObjectKeyError
        decoded[key] = value
    return decoded


def _reject_non_finite_number(_: str) -> Never:
    raise _NonFiniteNumberError


def _validate_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise _NonFiniteNumberError
    return parsed


def _extract_single_json_code_fence(content: str) -> str | None:
    opening: str | None = None
    for candidate in ("```json\n", "```json\r\n"):
        if content.startswith(candidate):
            opening = candidate
            break
    if opening is None:
        return None

    closing: str | None = None
    for candidate in ("\r\n```\r\n", "\n```\n", "\r\n```", "\n```"):
        if content.endswith(candidate):
            closing = candidate
            break
    if closing is None:
        return None

    repaired = content[len(opening) : -len(closing)]
    if not repaired or "```" in repaired:
        return None
    return repaired


def _seal_repair_evidence(
    *,
    original_response: str,
    repaired_response: str,
) -> StructuredOutputRepairEvidence:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "algorithm": StructuredOutputRepairAlgorithm.SINGLE_JSON_CODE_FENCE_V1.value,
        "repair_attempt": 1,
        "semantic_rewrite": False,
        "original_response_sha256": _text_sha256(original_response),
        "repaired_response_sha256": _text_sha256(repaired_response),
        "original_response_bytes": len(original_response.encode("utf-8")),
        "repaired_response_bytes": len(repaired_response.encode("utf-8")),
    }
    return StructuredOutputRepairEvidence.model_validate(
        {**payload, "evidence_sha256": _canonical_sha256(payload)}
    )


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
