from __future__ import annotations

import hashlib

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from mmaudit.models.schemas import (
    CandidateCrossExaminationResponse,
    CandidateCrossExaminationVerdict,
)
from mmaudit.models.structured_output import (
    StructuredOutputDecodeError,
    StructuredOutputFailureCode,
    StructuredOutputRepairEvidence,
    decode_structured_output,
)


class _NestedResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool


class _Response(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    count: int
    nested: _NestedResponse | None = None


class _OptionalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    required: str
    note: str | None = None


class _OptionalChild(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    required: bool
    note: str | None = None


class _NestedOptionalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    child: _OptionalChild
    children: list[_OptionalChild]


class _NestedNumericResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    value: float


class _LooseNestedResponse(BaseModel):
    ok: bool


class _LooseResponse(BaseModel):
    name: str
    nested: _LooseNestedResponse


class _NumericResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    value: float
    nested: _NestedNumericResponse


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_strict_decoder_accepts_one_complete_json_document() -> None:
    content = '{"name":"safe","count":2,"nested":{"ok":true}}'

    result = decode_structured_output(content, _Response)

    assert result.value == _Response(name="safe", count=2, nested=_NestedResponse(ok=True))
    assert result.original_response_sha256 == _sha256(content)
    assert result.validated_json_sha256 == _sha256(content)
    assert result.repair_evidence is None
    assert result.repair_used is False


def test_strict_decoder_ignores_mutated_model_validate_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_open_model_validate_json(
        cls: type[_Response],
        _content: str,
        **_kwargs: object,
    ) -> _Response:
        return cls.model_construct(name={"invalid": "nested"}, count="not-an-integer")

    monkeypatch.setattr(
        _Response,
        "model_validate_json",
        classmethod(fail_open_model_validate_json),
    )

    with pytest.raises(StructuredOutputDecodeError) as raised:
        decode_structured_output('{"unexpected":"payload"}', _Response)

    assert raised.value.code is StructuredOutputFailureCode.SCHEMA_VALIDATION_FAILED
    parsed = decode_structured_output('{"name":"safe","count":2,"nested":null}', _Response)
    assert type(parsed.value) is _Response
    assert parsed.value.count == 2


def test_strict_decoder_accepts_nested_production_str_enum_json() -> None:
    content = (
        '{"decisions":[{"candidate_ref":"candidate-0001","verdict":"supported",'
        '"rationale":"Source-bound support remains independently reviewable.",'
        '"contradictions":[],"missing_evidence":[]}]}'
    )

    result = decode_structured_output(content, CandidateCrossExaminationResponse)

    assert len(result.value.decisions) == 1
    assert result.value.decisions[0].verdict is CandidateCrossExaminationVerdict.SUPPORTED


@pytest.mark.parametrize("wrong_verdict", ["true", "1", "{}", "[]"])
def test_strict_decoder_rejects_wrong_json_types_for_nested_str_enum(
    wrong_verdict: str,
) -> None:
    content = (
        '{"decisions":[{"candidate_ref":"candidate-0001","verdict":'
        f"{wrong_verdict},"
        '"rationale":"Source-bound support remains independently reviewable.",'
        '"contradictions":[],"missing_evidence":[]}]}'
    )

    with pytest.raises(StructuredOutputDecodeError) as raised:
        decode_structured_output(content, CandidateCrossExaminationResponse)

    assert raised.value.code is StructuredOutputFailureCode.SCHEMA_VALIDATION_FAILED


@pytest.mark.parametrize(
    "content",
    [
        'analysis: {"name":"unsafe","count":1}',
        '{"name":"unsafe","count":1} trailing prose',
        '```json\n{"name":"unsafe","count":1}\n``` trailing prose',
        ' ```json\n{"name":"unsafe","count":1}\n```',
        '```JSON\n{"name":"unsafe","count":1}\n```',
        '```json\n{"name":"unsafe","count":1}\n```more```',
    ],
)
def test_extra_prose_and_non_allowlisted_envelopes_are_rejected(content: str) -> None:
    with pytest.raises(StructuredOutputDecodeError) as raised:
        decode_structured_output(content, _Response, max_repair_attempts=1)

    assert raised.value.code is StructuredOutputFailureCode.INVALID_JSON_SYNTAX
    assert raised.value.repair_evidence is None


def test_duplicate_keys_are_rejected_at_every_depth() -> None:
    content = '{"name":"unsafe","count":1,"nested":{"ok":true,"ok":false}}'

    with pytest.raises(StructuredOutputDecodeError) as raised:
        decode_structured_output(content, _Response)

    assert raised.value.code is StructuredOutputFailureCode.DUPLICATE_OBJECT_KEY


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_json_constants_are_rejected(constant: str) -> None:
    with pytest.raises(StructuredOutputDecodeError) as raised:
        decode_structured_output(
            f'{{"name":"unsafe","count":{constant}}}',
            _Response,
        )

    assert raised.value.code is StructuredOutputFailureCode.NON_FINITE_NUMBER


@pytest.mark.parametrize(
    "content",
    [
        '{"name":"unsafe","count":1e400,"nested":null}',
        '{"name":"unsafe","count":1,"nested":{"ok":1e400}}',
    ],
)
def test_exponent_overflow_is_rejected_at_every_depth(content: str) -> None:
    with pytest.raises(StructuredOutputDecodeError) as raised:
        decode_structured_output(content, _Response)

    assert raised.value.code is StructuredOutputFailureCode.NON_FINITE_NUMBER


def test_finite_json_floats_remain_valid_at_every_depth() -> None:
    content = '{"value":1e300,"nested":{"value":-2.5}}'

    result = decode_structured_output(content, _NumericResponse)

    assert result.value.value == 1e300
    assert result.value.nested.value == -2.5


@pytest.mark.parametrize("coercible_value", ['"2"', "true", "2.0"])
def test_coercible_json_values_are_rejected_for_integer_fields(
    coercible_value: str,
) -> None:
    content = f'{{"name":"unsafe","count":{coercible_value},"nested":null}}'

    with pytest.raises(StructuredOutputDecodeError) as raised:
        decode_structured_output(content, _Response)

    assert raised.value.code is StructuredOutputFailureCode.SCHEMA_VALIDATION_FAILED


@pytest.mark.parametrize("coercible_value", ['"true"', "1"])
def test_coercible_json_values_are_rejected_recursively_for_boolean_fields(
    coercible_value: str,
) -> None:
    content = f'{{"name":"unsafe","count":1,"nested":{{"ok":{coercible_value}}}}}'

    with pytest.raises(StructuredOutputDecodeError) as raised:
        decode_structured_output(content, _Response)

    assert raised.value.code is StructuredOutputFailureCode.SCHEMA_VALIDATION_FAILED


def test_omitted_top_level_optional_field_is_rejected() -> None:
    with pytest.raises(StructuredOutputDecodeError) as raised:
        decode_structured_output('{"required":"safe"}', _OptionalResponse)

    assert raised.value.code is StructuredOutputFailureCode.SCHEMA_VALIDATION_FAILED
    assert str(raised.value) == "structured output rejected: SCHEMA_VALIDATION_FAILED"


@pytest.mark.parametrize(
    "content",
    [
        ('{"child":{"required":true},"children":[{"required":true,"note":null}]}'),
        ('{"child":{"required":true,"note":null},"children":[{"required":true}]}'),
    ],
)
def test_omitted_nested_optional_field_is_rejected_through_models_and_lists(
    content: str,
) -> None:
    with pytest.raises(StructuredOutputDecodeError) as raised:
        decode_structured_output(content, _NestedOptionalResponse)

    assert raised.value.code is StructuredOutputFailureCode.SCHEMA_VALIDATION_FAILED
    assert str(raised.value) == "structured output rejected: SCHEMA_VALIDATION_FAILED"


def test_explicit_optional_fields_validate_recursively() -> None:
    content = (
        '{"child":{"required":true,"note":null},"children":[{"required":false,"note":"reviewed"}]}'
    )

    result = decode_structured_output(content, _NestedOptionalResponse)

    assert result.value.children[0].note == "reviewed"


@pytest.mark.parametrize(
    "content",
    [
        '{"name":"safe","nested":{"ok":true},"unexpected":"discarded"}',
        '{"name":"safe","nested":{"ok":true,"unexpected":"discarded"}}',
    ],
)
def test_unexpected_fields_are_rejected_even_for_permissive_response_models(
    content: str,
) -> None:
    with pytest.raises(StructuredOutputDecodeError) as raised:
        decode_structured_output(content, _LooseResponse)

    assert raised.value.code is StructuredOutputFailureCode.SCHEMA_VALIDATION_FAILED
    assert str(raised.value) == "structured output rejected: SCHEMA_VALIDATION_FAILED"


def test_syntax_envelope_repair_cannot_discard_unexpected_fields_from_permissive_models() -> None:
    content = '```json\n{"name":"safe","nested":{"ok":true},"unexpected":"discarded"}\n```'

    with pytest.raises(StructuredOutputDecodeError) as raised:
        decode_structured_output(
            content,
            _LooseResponse,
            max_repair_attempts=1,
        )

    assert raised.value.code is StructuredOutputFailureCode.SCHEMA_VALIDATION_FAILED
    assert raised.value.repair_evidence is not None
    assert raised.value.repair_evidence.binds(
        original_response=content,
        repaired_response='{"name":"safe","nested":{"ok":true},"unexpected":"discarded"}',
    )


@pytest.mark.parametrize(
    "content",
    [
        '```json\n{"name":"safe","count":2,"nested":null}\n```',
        '```json\r\n{"name":"safe","count":2,"nested":null}\r\n```',
        '```json\n{"name":"safe","count":2,"nested":null}\n```\n',
    ],
)
def test_one_complete_json_fence_is_removed_without_editing_payload(content: str) -> None:
    result = decode_structured_output(content, _Response, max_repair_attempts=1)
    repaired = '{"name":"safe","count":2,"nested":null}'

    assert result.value == _Response(name="safe", count=2)
    assert result.repair_used is True
    assert result.repair_evidence is not None
    assert result.repair_evidence.binds(
        original_response=content,
        repaired_response=repaired,
    )
    assert result.original_response_sha256 == _sha256(content)
    assert result.validated_json_sha256 == _sha256(repaired)


def test_repair_evidence_is_self_hashed_and_rejects_tampering() -> None:
    result = decode_structured_output(
        '```json\n{"name":"safe","count":2,"nested":null}\n```',
        _Response,
        max_repair_attempts=1,
    )
    evidence = result.repair_evidence
    assert evidence is not None

    tampered = evidence.model_dump(mode="json")
    tampered["repaired_response_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="repair evidence hash is inconsistent"):
        StructuredOutputRepairEvidence.model_validate(tampered)


def test_fence_removal_does_not_repair_invalid_json_or_retry_again() -> None:
    content = '```json\n{"name":"unsafe","count":1,}\n```'

    with pytest.raises(StructuredOutputDecodeError) as raised:
        decode_structured_output(content, _Response, max_repair_attempts=1)

    assert raised.value.code is StructuredOutputFailureCode.INVALID_JSON_SYNTAX
    assert raised.value.repair_evidence is not None
    assert raised.value.repair_evidence.binds(
        original_response=content,
        repaired_response='{"name":"unsafe","count":1,}',
    )


def test_fence_removal_does_not_repair_semantic_schema_defects() -> None:
    content = '```json\n{"name":"unsafe","unexpected":true}\n```'

    with pytest.raises(StructuredOutputDecodeError) as raised:
        decode_structured_output(content, _Response, max_repair_attempts=1)

    assert raised.value.code is StructuredOutputFailureCode.SCHEMA_VALIDATION_FAILED
    assert raised.value.repair_evidence is not None
    assert raised.value.repair_evidence.binds(
        original_response=content,
        repaired_response='{"name":"unsafe","unexpected":true}',
    )


def test_truncation_is_rejected_before_any_repair() -> None:
    content = '```json\n{"name":"unsafe","count":1}\n```'

    with pytest.raises(StructuredOutputDecodeError) as raised:
        decode_structured_output(
            content,
            _Response,
            max_repair_attempts=1,
            truncated=True,
        )

    assert raised.value.code is StructuredOutputFailureCode.TRUNCATED_RESPONSE
    assert raised.value.repair_evidence is None


@pytest.mark.parametrize("attempts", [-1, 2, True])
def test_repair_bound_accepts_only_zero_or_one(attempts: int) -> None:
    with pytest.raises(ValueError, match="zero or one"):
        decode_structured_output("{}", _Response, max_repair_attempts=attempts)


def test_rejection_does_not_retain_or_serialize_raw_response() -> None:
    canary = "SYNTHETIC_RESPONSE_CANARY_7f91"
    content = f'analysis: {{"name":"{canary}","count":1}}'

    with pytest.raises(StructuredOutputDecodeError) as raised:
        decode_structured_output(content, _Response, max_repair_attempts=1)

    assert canary not in str(raised.value)
    assert canary not in repr(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
