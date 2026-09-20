"""Bounded, hash-selected Solidity transformations for the eleven-class portfolio.

These lexical preconditions define supported source shapes, not semantic discovery,
deployment safety, property applicability, or successful mutation execution.
"""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from mmaudit.models.schemas import StrictModel
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.solidity.invariants import _mask_solidity_comments_and_strings


class SecurityMutationClass(StrEnum):
    """The eleven explicit requirements, distinct from legacy generic operators."""

    AUTHORIZATION_REMOVAL = "removed_authorization"
    NONCE_UPDATE_REMOVAL = "removed_nonce_update"
    ROUNDING_DIRECTION = "changed_rounding_direction"
    STALE_PRICE_VALIDATION_REMOVAL = "removed_stale_price_validation"
    EXTERNAL_CALL_BEFORE_STATE_UPDATE = "external_call_before_state_update"
    INITIALIZER_PROTECTION_REMOVAL = "removed_initializer_protection"
    TIMELOCK_WEAKENING = "weakened_timelock"
    STORAGE_SLOT_CHANGE = "changed_storage_slot"
    PAUSE_ENFORCEMENT_REMOVAL = "removed_pause_enforcement"
    UNCHECKED_RETURN_HANDLING = "unchecked_return_handling"
    INCORRECT_DECIMAL_SCALE = "incorrect_decimal_scale"


REQUIRED_SECURITY_MUTATION_CLASSES = tuple(SecurityMutationClass)
_LINE = Annotated[str, Field(max_length=20_000)]
_IDENTIFIER = r"[A-Za-z_$][A-Za-z0-9_$]*"
_LVAL = rf"{_IDENTIFIER}(?:\.{_IDENTIFIER}|\[[^;{{}}()\n]+\])*"
_TOKEN_CLASSES = frozenset(
    {
        SecurityMutationClass.ROUNDING_DIRECTION,
        SecurityMutationClass.TIMELOCK_WEAKENING,
        SecurityMutationClass.STORAGE_SLOT_CHANGE,
        SecurityMutationClass.INCORRECT_DECIMAL_SCALE,
    }
)


class PortfolioSourceMutationSpec(StrictModel):
    """One exact source span; arbitrary replacement source is never accepted."""

    schema_version: Literal["2.0"] = "2.0"
    id: str = Field(pattern=r"^mut-[a-z0-9][a-z0-9-]{0,75}$")
    kind: SecurityMutationClass
    path: str
    line: int = Field(ge=1, le=10_000_000)
    expected_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_lines: tuple[_LINE, ...] = Field(min_length=1, max_length=32)
    original_token: str | None = Field(default=None, min_length=1, max_length=80)
    replacement_token: str | None = Field(default=None, min_length=1, max_length=80)

    @field_validator("path")
    @classmethod
    def path_is_relative_solidity(cls, value: str) -> str:
        normalized = normalize_relative_path(value)
        if normalized in {"", "."} or PurePosixPath(normalized).suffix.lower() != ".sol":
            raise ValueError("mutation target must be a repository-relative Solidity source")
        return normalized

    @model_validator(mode="after")
    def span_and_operation_are_bounded(self) -> Self:
        if (
            sum(len(line) for line in self.expected_lines) > 40_000
            or any("\r" in line or "\n" in line for line in self.expected_lines)
            or not any(line.strip() for line in self.expected_lines)
        ):
            raise ValueError("mutation requires a bounded nonempty exact source span")
        tokens = (self.original_token, self.replacement_token)
        if self.kind in _TOKEN_CLASSES:
            if None in tokens or tokens[0] == tokens[1]:
                raise ValueError("token mutation requires two distinct explicit tokens")
        elif tokens != (None, None):
            raise ValueError("this mutation class cannot declare replacement tokens")
        transform_portfolio_span(self)
        return self

    def specification_sha256(self) -> str:
        from mmaudit.orchestration.manifest import canonical_sha256

        return canonical_sha256(self.model_dump(mode="json"))


def _guard(code: str) -> bool:
    value = code.strip()
    return (
        re.match(r"require\s*\(", value) is not None
        and value.endswith(");")
        and value.count(";") == 1
        and not any(c in value for c in "{}")
        and value.count("(") == value.count(")")
    )


def _guard_condition(code: str) -> str:
    if not _guard(code):
        return ""
    return code.split("(", 1)[1].rsplit(")", 1)[0].split(",", 1)[0].strip()


def _remove_header_modifier(source: str, code: str, modifier: str) -> tuple[str, ...]:
    if not re.match(r"\s*function\b", code) or not code.rstrip().endswith("{"):
        raise ValueError("protection removal requires a guard or complete function header")
    if code.count("{") != 1 or "}" in code or ";" in code:
        raise ValueError("protection removal cannot include the function body")
    matches = list(re.finditer(r"\b" + modifier + r"\b", code))
    if len(matches) != 1:
        raise ValueError("protection modifier must occur exactly once")
    prefix = code[: matches[0].start()]
    if ")" not in prefix or prefix.count("(") != prefix.count(")"):
        raise ValueError("protection token must be a modifier, not a function or parameter name")
    return tuple(_replace_code_token(source, code, modifier, "").split("\n"))


def _remove_span(specification: PortfolioSourceMutationSpec) -> tuple[str, ...]:
    return tuple(
        line[: len(line) - len(line.lstrip())]
        + "// mmaudit defensive mutation: "
        + specification.kind.value
        for line in specification.expected_lines
    )


def _replace_code_token(source: str, code: str, original: str, replacement: str) -> str:
    matches = list(
        re.finditer(r"(?<![A-Za-z0-9_$])" + re.escape(original) + r"(?![A-Za-z0-9_$])", code)
    )
    if len(matches) != 1:
        raise ValueError("mutation token must occur exactly once in code, not comments or strings")
    match = matches[0]
    return source[: match.start()] + replacement + source[match.end() :]


def _duration(value: str) -> int:
    match = re.fullmatch(r"(0|[1-9][0-9]{0,76})(?: +(seconds|minutes|hours|days|weeks))?", value)
    if match is None:
        raise ValueError("timelock mutation requires an explicit nonnegative duration")
    units = {None: 1, "seconds": 1, "minutes": 60, "hours": 3600, "days": 86400, "weeks": 604800}
    result = int(match[1]) * units[match[2]]
    if result >= 2**256:
        raise ValueError("timelock duration exceeds uint256")
    return result


def _scale(value: str) -> int:
    match = re.fullmatch(r"(?:1e([0-9]{1,2})|10 *\*\* *([0-9]{1,2})|1(0{0,77}))", value)
    if match is None:
        raise ValueError("decimal-scale mutation requires an explicit integer power of ten")
    exponent = int(match[1] or match[2]) if match[1] or match[2] else len(match[3])
    if exponent > 77:
        raise ValueError("decimal scale exceeds uint256")
    return exponent


def _reorder_statements(specification: PortfolioSourceMutationSpec, code: str) -> tuple[str, ...]:
    statements = code.split(";")
    if len(statements) != 3 or statements[-1].strip():
        raise ValueError("call reordering requires exactly two complete statements")
    assignment, call = statements[:2]
    if re.fullmatch(rf"\s*{_LVAL}\s*=\s*[^;{{}}()]+", assignment) is None:
        raise ValueError("reordering requires a non-declaring state assignment first")
    # No control-flow blocks or local declaration that would lose its definition before use.
    if re.fullmatch(
        rf"\s*{_IDENTIFIER}(?:\.{_IDENTIFIER})+\s*\([^;{{}}]*\)\s*", call
    ) is None or call.count("(") != call.count(")"):
        raise ValueError("reordering requires one direct member call second")
    boundary = code.index(";")
    first_line_count = code[:boundary].count("\n") + 1
    lines = code.split("\n")
    if first_line_count >= len(lines) or lines[first_line_count - 1].rsplit(";", 1)[1].strip():
        raise ValueError("reordered statements must occupy separate complete source lines")
    original = specification.expected_lines
    return (*original[first_line_count:], *original[:first_line_count])


def transform_portfolio_span(specification: PortfolioSourceMutationSpec) -> tuple[str, ...]:
    """Apply one supported lexical operation, refusing ambiguous or non-code targets."""

    source = "\n".join(specification.expected_lines)
    code = _mask_solidity_comments_and_strings(source)
    kind = specification.kind
    removable = False
    if kind is SecurityMutationClass.AUTHORIZATION_REMOVAL:
        removable = _guard(code) and re.search(r"\bmsg\.sender\b|\bhasRole\s*\(", code) is not None
    elif kind is SecurityMutationClass.NONCE_UPDATE_REMOVAL:
        removable = (
            re.search(r"\b_?(?:nonces?|used|consumed|executed|processed)[A-Za-z0-9_]*", code, re.I)
            is not None
            and re.fullmatch(
                rf"\s*{_LVAL}\s*(?:\+\+|\+=\s*1|=\s*(?:true|{_LVAL}\s*\+\s*1))\s*;\s*",
                code,
            )
            is not None
        )
    elif kind is SecurityMutationClass.STALE_PRICE_VALIDATION_REMOVAL:
        age = rf"(?:{_IDENTIFIER}|[0-9]+)"
        timestamp = _IDENTIFIER
        conditions = (
            rf"block\.timestamp\s*-\s*{timestamp}\s*<=?\s*{age}",
            rf"block\.timestamp\s*<=?\s*{timestamp}\s*\+\s*{age}",
            rf"{timestamp}\s*\+\s*{age}\s*>=?\s*block\.timestamp",
        )
        removable = _guard(code) and any(
            re.fullmatch(condition, _guard_condition(code)) for condition in conditions
        )
    elif kind is SecurityMutationClass.UNCHECKED_RETURN_HANDLING:
        removable = _guard(code) and re.search(r"\b(?:ok|success|succeeded)\b", code) is not None
    elif kind in {
        SecurityMutationClass.INITIALIZER_PROTECTION_REMOVAL,
        SecurityMutationClass.PAUSE_ENFORCEMENT_REMOVAL,
    }:
        initializer = kind is SecurityMutationClass.INITIALIZER_PROTECTION_REMOVAL
        guard_name = r"_?initialized" if initializer else r"_?paused"
        removable = (
            _guard(code)
            and re.search(rf"!\s*{guard_name}\b|\b{guard_name}\s*==\s*false\b", code) is not None
        )
        if not removable:
            modifier = "initializer" if initializer else "whenNotPaused"
            return _remove_header_modifier(source, code, modifier)
    elif kind is SecurityMutationClass.EXTERNAL_CALL_BEFORE_STATE_UPDATE:
        return _reorder_statements(specification, code)
    elif kind in _TOKEN_CLASSES:
        original, replacement = specification.original_token, specification.replacement_token
        if original is None or replacement is None:
            raise ValueError("mutation replacement tokens are missing")
        if kind is SecurityMutationClass.ROUNDING_DIRECTION:
            pairs = {"Floor": "Ceil", "Ceil": "Floor", "Down": "Up", "Up": "Down"}
            if (
                pairs.get(original) != replacement
                or re.search(r"\bRounding\s*\.\s*" + re.escape(original) + r"\b", code) is None
            ):
                raise ValueError("rounding mutation requires opposite explicit Rounding modes")
        elif kind is SecurityMutationClass.TIMELOCK_WEAKENING:
            if not 0 <= _duration(replacement) < _duration(original):
                raise ValueError("timelock mutation must strictly reduce the duration")
            if (
                re.fullmatch(
                    rf"block\.timestamp\s*>=?\s*{_IDENTIFIER}\s*\+\s*" + re.escape(original),
                    _guard_condition(code),
                )
                is None
            ):
                raise ValueError("timelock mutation requires a timestamp lower-bound guard")
        elif kind is SecurityMutationClass.STORAGE_SLOT_CHANGE:
            if any(
                re.fullmatch(r"0x[0-9a-fA-F]{64}", value) is None
                for value in (original, replacement)
            ):
                raise ValueError("storage-slot mutation requires exact bytes32 literals")
            declaration = re.fullmatch(
                rf"\s*bytes32\s+(?:(?:internal|private|public)\s+)?constant\s+({_IDENTIFIER})\s*=\s*"
                + re.escape(original)
                + r"\s*;\s*",
                code,
            )
            if (
                int(original, 16) == int(replacement, 16)
                or declaration is None
                or "slot" not in declaration[1].lower()
            ):
                raise ValueError("storage-slot mutation requires a named bytes32 slot constant")
        elif kind is SecurityMutationClass.INCORRECT_DECIMAL_SCALE:
            if _scale(original) == _scale(replacement):
                raise ValueError("decimal-scale mutation must change the numeric scale")
            without_token = _replace_code_token(code, code, original, "SCALE_VALUE")
            if (
                re.search(
                    r"[*/]|\b[A-Za-z0-9_]*(?:[Ss][Cc][Aa][Ll][Ee]|DECIMALS)[A-Za-z0-9_]*\s*=",
                    without_token,
                )
                is None
            ):
                raise ValueError(
                    "decimal-scale mutation requires scaling arithmetic or a scale constant"
                )
        return tuple(_replace_code_token(source, code, original, replacement).split("\n"))
    if not removable:
        raise ValueError("selected source does not match the required mutation class")
    return _remove_span(specification)


def _line_parts(line: str) -> tuple[str, str]:
    for ending in ("\r\n", "\n", "\r"):
        if line.endswith(ending):
            return line[: -len(ending)], ending
    return line, ""


def mutate_portfolio_source(
    original: bytes, specification: PortfolioSourceMutationSpec
) -> tuple[bytes, bytes, bytes, tuple[str, ...]]:
    """Bind lexical context to the whole original file, preserving every line ending."""

    if type(specification) is not PortfolioSourceMutationSpec:
        raise ValueError("portfolio mutation requires the exact source specification type")
    specification = PortfolioSourceMutationSpec.model_validate(
        specification.model_dump(mode="python")
    )
    if hashlib.sha256(original).hexdigest() != specification.expected_file_sha256:
        raise ValueError("portfolio mutation source hash differs")
    text = original.decode("utf-8", errors="strict")
    lines = text.splitlines(keepends=True)
    start, end = specification.line - 1, specification.line - 1 + len(specification.expected_lines)
    if end > len(lines):
        raise ValueError("portfolio mutation span exceeds the source file")
    parts = tuple(_line_parts(line) for line in lines[start:end])
    if tuple(body for body, _ in parts) != specification.expected_lines:
        raise ValueError("portfolio mutation span does not match the planned source")
    masked = _mask_solidity_comments_and_strings(text)
    offset = sum(len(line) for line in lines[:start])
    contextual = []
    for body, ending in parts:
        contextual.append(masked[offset : offset + len(body)])
        offset += len(body) + len(ending)
    if "\n".join(contextual) != _mask_solidity_comments_and_strings(
        "\n".join(specification.expected_lines)
    ):
        raise ValueError("portfolio mutation span is inside a comment or string")
    replacements = transform_portfolio_span(specification)
    if len(replacements) != len(parts):
        raise ValueError("portfolio mutation cannot change source line cardinality")
    original_span = "".join(lines[start:end]).encode()
    endings = tuple(ending for _, ending in parts)
    changed = [body + ending for body, ending in zip(replacements, endings, strict=True)]
    mutated_span = "".join(changed).encode()
    if original_span == mutated_span:
        raise ValueError("portfolio mutation did not change its source span")
    lines[start:end] = changed
    return "".join(lines).encode(), original_span, mutated_span, endings


def restore_portfolio_source(
    current: bytes,
    specification: PortfolioSourceMutationSpec,
    *,
    line_endings: tuple[str, ...],
    expected_mutated_span_sha256: str,
) -> bytes:
    """Restore only the exact applied span; the caller also checks the whole owned tree."""

    if type(specification) is not PortfolioSourceMutationSpec:
        raise ValueError("portfolio restoration requires the exact source specification type")
    specification = PortfolioSourceMutationSpec.model_validate(
        specification.model_dump(mode="python")
    )
    lines = current.decode("utf-8", errors="strict").splitlines(keepends=True)
    start, end = specification.line - 1, specification.line - 1 + len(specification.expected_lines)
    if end > len(lines) or len(line_endings) != len(specification.expected_lines):
        raise ValueError("portfolio restoration span is inconsistent")
    if any(ending not in {"", "\n", "\r", "\r\n"} for ending in line_endings):
        raise ValueError("portfolio restoration has an invalid line ending")
    if (
        hashlib.sha256("".join(lines[start:end]).encode()).hexdigest()
        != expected_mutated_span_sha256
    ):
        raise ValueError("portfolio restoration span differs from applied evidence")
    lines[start:end] = [
        body + ending
        for body, ending in zip(specification.expected_lines, line_endings, strict=True)
    ]
    restored = "".join(lines).encode()
    if hashlib.sha256(restored).hexdigest() != specification.expected_file_sha256:
        raise ValueError("portfolio restoration does not reproduce the exact original file")
    return restored
