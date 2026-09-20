"""Strict, bounded parsing of Forge's debug statement-coverage report.

``forge coverage --report debug --json`` emits one JSON result object followed by
a human-readable debug report.  This module treats that report as untrusted
process output: its grammar, paths, integers, item identities, and resource use
are validated before exact statement spans are exposed to later provenance
checks.  Nested statement spans are intentionally retained.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Literal

from mmaudit.repository.ignore import normalize_relative_path

MAX_FORGE_DEBUG_BYTES = 16_000_000
MAX_FORGE_DEBUG_RECORDS = 1_000_000
MAX_FORGE_DEBUG_ITEMS = 500_000
MAX_FORGE_DEBUG_STATEMENTS = 500_000

_MAX_LINE_BYTES = 16_384
_MAX_PATH_BYTES = 4_096
_MAX_TEXT_BYTES = 4_096
_MAX_INTEGER = 2**63 - 1
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_UNCOVERED_HEADER = re.compile(r"Uncovered for (?P<path>.+):")
_ANCHOR_HEADER = re.compile(
    r'Anchors for Contract "(?P<contract>[^"\r\n]+)" '
    r"\(solc (?P<version>[^()\r\n]+), source ID (?P<source_id>[0-9]+)\):"
)
_ANCHOR_ITEM = re.compile(r"- IC (?P<instruction>[0-9]+) -> Item (?P<item>[0-9]+)")
_LOCATION = (
    r"\(location: source ID (?P<source_id>[0-9]+), "
    r"lines (?P<start_line>[0-9]+)\.\.(?P<end_line>[0-9]+), "
    r"bytes (?P<start_byte>[0-9]+)\.\.(?P<end_byte>[0-9]+), "
    r"hits: (?P<hits>[0-9]+)\)"
)
_SIMPLE_DESCRIPTOR = re.compile(rf"(?P<kind>Line|Statement) {_LOCATION}")
_FUNCTION_DESCRIPTOR = re.compile(rf'Function "(?P<name>[^"\r\n]+)" {_LOCATION}')
_BRANCH_DESCRIPTOR = re.compile(
    rf"Branch \(branch: (?P<branch>[0-9]+), path: (?P<branch_path>[0-9]+)\) {_LOCATION}"
)
_PROGRESS_LINES = ("Analysing contracts...", "Running tests...")
_LCOV_COMPLETION_LINE = "Wrote LCOV report."


class FoundryStatementCoverageError(ValueError):
    """Raised when Forge debug output is unsafe or internally inconsistent."""


@dataclass(frozen=True, slots=True, order=True)
class ForgeDebugStatementRecord:
    """One canonical physical statement span and its observed hit count."""

    source_id: int
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int
    hits: int
    item_ids: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        _validate_location(
            source_id=self.source_id,
            start_byte=self.start_byte,
            end_byte=self.end_byte,
            start_line=self.start_line,
            end_line=self.end_line,
            hits=self.hits,
        )
        if type(self.item_ids) is not tuple or any(
            type(item_id) is not int or not 0 <= item_id <= _MAX_INTEGER
            for item_id in self.item_ids
        ):
            raise FoundryStatementCoverageError(
                "statement item IDs must be bounded canonical integers"
            )
        if self.item_ids != tuple(sorted(set(self.item_ids))):
            raise FoundryStatementCoverageError(
                "statement item IDs must be unique and canonically sorted"
            )

    @property
    def covered(self) -> bool:
        """Return whether Forge observed at least one execution hit."""

        return self.hits > 0

    @property
    def identity(self) -> tuple[int, int, int, int, int]:
        """Return the source-ID and exact half-open source-span identity."""

        return (
            self.source_id,
            self.start_byte,
            self.end_byte,
            self.start_line,
            self.end_line,
        )


@dataclass(frozen=True, slots=True, order=True)
class ForgeDebugUncoveredSource:
    """A canonical source-ID/path binding observed in an uncovered section."""

    source_id: int
    path: str

    def __post_init__(self) -> None:
        _bounded_integer(self.source_id, "source ID")
        _canonical_source_path(self.path)


@dataclass(frozen=True, slots=True)
class ForgeDebugStatementCoverage:
    """Immutable canonical statement inventory parsed from one Forge process."""

    machine_json_bytes: bytes
    statements: tuple[ForgeDebugStatementRecord, ...]
    uncovered_sources: tuple[ForgeDebugUncoveredSource, ...]
    anchored_item_count: int
    descriptor_record_count: int

    def __post_init__(self) -> None:
        _validate_machine_json_line(self.machine_json_bytes)
        if type(self.statements) is not tuple or any(
            type(statement) is not ForgeDebugStatementRecord for statement in self.statements
        ):
            raise FoundryStatementCoverageError("statements must be exact immutable records")
        statement_keys = [statement.identity for statement in self.statements]
        if statement_keys != sorted(statement_keys) or len(set(statement_keys)) != len(
            statement_keys
        ):
            raise FoundryStatementCoverageError(
                "statements must have unique, canonically sorted physical identities"
            )
        if len(self.statements) > MAX_FORGE_DEBUG_STATEMENTS:
            raise FoundryStatementCoverageError("statement count exceeds the supported limit")
        if type(self.uncovered_sources) is not tuple or any(
            type(source) is not ForgeDebugUncoveredSource for source in self.uncovered_sources
        ):
            raise FoundryStatementCoverageError("uncovered sources must be exact immutable records")
        if self.uncovered_sources != tuple(sorted(self.uncovered_sources)):
            raise FoundryStatementCoverageError("uncovered sources must be canonically sorted")
        source_ids = [source.source_id for source in self.uncovered_sources]
        source_paths = [source.path for source in self.uncovered_sources]
        if len(set(source_ids)) != len(source_ids) or len(set(source_paths)) != len(source_paths):
            raise FoundryStatementCoverageError(
                "uncovered source IDs and paths must form a one-to-one binding"
            )
        _bounded_integer(self.anchored_item_count, "anchored item count")
        _bounded_integer(self.descriptor_record_count, "descriptor record count")
        if self.anchored_item_count > MAX_FORGE_DEBUG_ITEMS:
            raise FoundryStatementCoverageError("anchored item count exceeds the supported limit")
        if self.descriptor_record_count > MAX_FORGE_DEBUG_RECORDS:
            raise FoundryStatementCoverageError(
                "descriptor record count exceeds the supported limit"
            )

    def canonical_inventory_bytes(self) -> bytes:
        """Serialize exact physical statement identities in canonical JSON."""

        payload = [
            {
                "end_byte": statement.end_byte,
                "end_line": statement.end_line,
                "source_id": statement.source_id,
                "start_byte": statement.start_byte,
                "start_line": statement.start_line,
            }
            for statement in self.statements
        ]
        return (
            json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")

    def canonical_inventory_sha256(self) -> str:
        """Hash the canonical statement identity inventory."""

        return hashlib.sha256(self.canonical_inventory_bytes()).hexdigest()

    @property
    def statement_inventory_sha256(self) -> str:
        """Expose the canonical inventory hash as a receipt-friendly field."""

        return self.canonical_inventory_sha256()


@dataclass(frozen=True, slots=True)
class _Descriptor:
    kind: str
    source_id: int
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int
    hits: int
    name: str | None = None
    branch: int | None = None
    branch_path: int | None = None

    @property
    def statement_identity(self) -> tuple[int, int, int, int, int]:
        return (
            self.source_id,
            self.start_byte,
            self.end_byte,
            self.start_line,
            self.end_line,
        )


@dataclass(slots=True)
class _StatementBuilder:
    descriptor: _Descriptor
    item_ids: set[int]


def parse_forge_debug_statement_coverage(
    raw: bytes,
    *,
    max_bytes: int = MAX_FORGE_DEBUG_BYTES,
    max_records: int = MAX_FORGE_DEBUG_RECORDS,
    max_items: int = MAX_FORGE_DEBUG_ITEMS,
    max_statements: int = MAX_FORGE_DEBUG_STATEMENTS,
) -> ForgeDebugStatementCoverage:
    """Parse bounded ``forge coverage --report debug --json`` stdout bytes.

    The statement inventory is the union of anchored items and zero-hit
    descriptors in ``Uncovered`` sections.  Forge can omit anchors for
    compiled-away or Yul-derived items, so an uncovered descriptor is not
    required to have an item ID.  Whenever the same item ID or physical
    statement is repeated, its descriptor and hit count must remain identical.
    """

    _validate_limit("max_bytes", max_bytes, MAX_FORGE_DEBUG_BYTES)
    _validate_limit("max_records", max_records, MAX_FORGE_DEBUG_RECORDS)
    _validate_limit("max_items", max_items, MAX_FORGE_DEBUG_ITEMS)
    _validate_limit("max_statements", max_statements, MAX_FORGE_DEBUG_STATEMENTS)
    if type(raw) is not bytes:
        raise FoundryStatementCoverageError("Forge debug input must be bytes")
    if not raw:
        raise FoundryStatementCoverageError("Forge debug input is empty")
    if len(raw) > max_bytes:
        raise FoundryStatementCoverageError("Forge debug input exceeds the configured byte limit")
    if b"\r" in raw:
        raise FoundryStatementCoverageError("Forge debug input must use LF line endings")
    if not raw.endswith(b"\n"):
        raise FoundryStatementCoverageError("Forge debug input must end with LF")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FoundryStatementCoverageError("Forge debug input is not UTF-8") from exc

    lines = text[:-1].split("\n")
    if len(lines) > max_records:
        raise FoundryStatementCoverageError(
            "Forge debug line count exceeds the configured record limit"
        )

    index = 0
    if lines[:2] == list(_PROGRESS_LINES):
        index = 2
    elif lines and lines[0] in _PROGRESS_LINES:
        raise _line_error(1, "Forge progress preamble is incomplete or out of order")
    if index >= len(lines):
        raise FoundryStatementCoverageError("Forge debug output is missing its JSON result")

    machine_json_text = lines[index]
    machine_json_bytes = machine_json_text.encode("utf-8")
    _validate_machine_json_line(machine_json_bytes)
    machine_json_index = index
    index += 1
    for record_index, line in enumerate(lines):
        if record_index != machine_json_index and len(line.encode("utf-8")) > _MAX_LINE_BYTES:
            raise _line_error(record_index + 1, "record exceeds the supported byte length")

    item_descriptors: dict[int, _Descriptor] = {}
    statements: dict[tuple[int, int, int, int, int], _StatementBuilder] = {}
    descriptor_hits: dict[_Descriptor, int] = {}
    source_id_to_path: dict[int, str] = {}
    path_to_source_id: dict[str, int] = {}
    uncovered_sections: set[tuple[int, str]] = set()
    uncovered_paths_seen: set[str] = set()
    anchor_sections: set[tuple[str, str, int]] = set()
    descriptor_record_count = 0
    saw_anchor_section = False
    saw_completion_line = False

    while index < len(lines):
        line = lines[index]
        line_number = index + 1
        if line == "":
            if index + 1 < len(lines) and lines[index + 1] == "":
                raise _line_error(line_number, "consecutive blank records are not canonical")
            index += 1
            continue
        if line == _LCOV_COMPLETION_LINE:
            if saw_completion_line:
                raise _line_error(line_number, "LCOV completion record is duplicate")
            saw_completion_line = True
            index += 1
            if index != len(lines):
                raise _line_error(line_number, "LCOV completion record must be final")
            continue

        uncovered_match = _UNCOVERED_HEADER.fullmatch(line)
        if uncovered_match is not None:
            if saw_anchor_section:
                raise _line_error(line_number, "uncovered sections cannot follow anchor sections")
            path = _canonical_source_path(uncovered_match.group("path"))
            if path in uncovered_paths_seen:
                raise _line_error(line_number, "uncovered source section is duplicate")
            uncovered_paths_seen.add(path)
            index += 1
            section_source_id: int | None = None
            section_record_count = 0
            while index < len(lines) and lines[index].startswith("- "):
                descriptor = _parse_descriptor(lines[index][2:], index + 1)
                descriptor_record_count += 1
                if descriptor_record_count > max_records:
                    raise _line_error(
                        index + 1, "descriptor count exceeds the configured record limit"
                    )
                if descriptor.hits != 0:
                    raise _line_error(
                        index + 1, "uncovered descriptors must have exactly zero hits"
                    )
                if section_source_id is None:
                    section_source_id = descriptor.source_id
                elif descriptor.source_id != section_source_id:
                    raise _line_error(index + 1, "uncovered section mixes multiple source IDs")
                _record_descriptor(descriptor_hits, descriptor, index + 1)
                if descriptor.kind == "Statement":
                    _record_statement(
                        statements,
                        descriptor,
                        item_id=None,
                        max_statements=max_statements,
                        line_number=index + 1,
                    )
                section_record_count += 1
                index += 1
            if section_record_count == 0:
                continue
            if section_source_id is None:  # pragma: no cover - established by the loop above
                raise _line_error(line_number, "uncovered source ID was not established")
            binding = (section_source_id, path)
            existing_path = source_id_to_path.get(section_source_id)
            existing_source_id = path_to_source_id.get(path)
            if (existing_path is not None and existing_path != path) or (
                existing_source_id is not None and existing_source_id != section_source_id
            ):
                raise _line_error(line_number, "uncovered source IDs and paths are not one-to-one")
            source_id_to_path[section_source_id] = path
            path_to_source_id[path] = section_source_id
            uncovered_sections.add(binding)
            continue

        anchor_match = _ANCHOR_HEADER.fullmatch(line)
        if anchor_match is not None:
            saw_anchor_section = True
            contract = _canonical_text(anchor_match.group("contract"), "contract name")
            version = _canonical_solc_version(anchor_match.group("version"))
            source_id = _unsigned_integer(anchor_match.group("source_id"), "source ID")
            section_key = (contract, version, source_id)
            if section_key in anchor_sections:
                raise _line_error(line_number, "anchor section is duplicate")
            anchor_sections.add(section_key)
            index += 1
            while index < len(lines) and lines[index].startswith("- IC "):
                item_line_number = index + 1
                item_match = _ANCHOR_ITEM.fullmatch(lines[index])
                if item_match is None:
                    raise _line_error(item_line_number, "anchor item record is malformed")
                _unsigned_integer(item_match.group("instruction"), "instruction counter")
                item_id = _unsigned_integer(item_match.group("item"), "item ID")
                index += 1
                if index >= len(lines) or lines[index] not in {
                    "- Runtime code",
                    "- Creation code",
                }:
                    raise _line_error(
                        min(index + 1, len(lines) + 1),
                        "anchor item is missing its exact code-mode record",
                    )
                index += 1
                prefix = "  - Refers to item: "
                if index >= len(lines) or not lines[index].startswith(prefix):
                    raise _line_error(
                        min(index + 1, len(lines) + 1),
                        "anchor item is missing its descriptor record",
                    )
                descriptor = _parse_descriptor(lines[index][len(prefix) :], index + 1)
                if descriptor.source_id != source_id:
                    raise _line_error(
                        index + 1, "anchor descriptor source ID disagrees with its section"
                    )
                descriptor_record_count += 1
                if descriptor_record_count > max_records:
                    raise _line_error(
                        index + 1, "descriptor count exceeds the configured record limit"
                    )
                prior = item_descriptors.get(item_id)
                if prior is not None and prior != descriptor:
                    raise _line_error(
                        index + 1, "reused Forge item ID has a conflicting descriptor"
                    )
                if prior is None:
                    if len(item_descriptors) >= max_items:
                        raise _line_error(
                            index + 1, "Forge item count exceeds the configured limit"
                        )
                    item_descriptors[item_id] = descriptor
                _record_descriptor(descriptor_hits, descriptor, index + 1)
                if descriptor.kind == "Statement":
                    _record_statement(
                        statements,
                        descriptor,
                        item_id=item_id,
                        max_statements=max_statements,
                        line_number=index + 1,
                    )
                index += 1
            continue

        raise _line_error(line_number, "unsupported Forge debug record")

    statement_records = tuple(
        ForgeDebugStatementRecord(
            source_id=builder.descriptor.source_id,
            start_byte=builder.descriptor.start_byte,
            end_byte=builder.descriptor.end_byte,
            start_line=builder.descriptor.start_line,
            end_line=builder.descriptor.end_line,
            hits=builder.descriptor.hits,
            item_ids=tuple(sorted(builder.item_ids)),
        )
        for _, builder in sorted(statements.items())
    )
    uncovered_sources = tuple(
        sorted(
            ForgeDebugUncoveredSource(source_id=source_id, path=path)
            for source_id, path in uncovered_sections
        )
    )
    return ForgeDebugStatementCoverage(
        machine_json_bytes=machine_json_bytes,
        statements=statement_records,
        uncovered_sources=uncovered_sources,
        anchored_item_count=len(item_descriptors),
        descriptor_record_count=descriptor_record_count,
    )


def _parse_descriptor(value: str, line_number: int) -> _Descriptor:
    match = _SIMPLE_DESCRIPTOR.fullmatch(value)
    if match is not None:
        return _descriptor_from_match(match.group("kind"), match)
    match = _FUNCTION_DESCRIPTOR.fullmatch(value)
    if match is not None:
        return _descriptor_from_match(
            "Function",
            match,
            name=_canonical_text(match.group("name"), "function name"),
        )
    match = _BRANCH_DESCRIPTOR.fullmatch(value)
    if match is not None:
        return _descriptor_from_match(
            "Branch",
            match,
            branch=_unsigned_integer(match.group("branch"), "branch ID"),
            branch_path=_unsigned_integer(match.group("branch_path"), "branch path"),
        )
    raise _line_error(line_number, "coverage descriptor is malformed or unsupported")


def _descriptor_from_match(
    kind: str,
    match: re.Match[str],
    *,
    name: str | None = None,
    branch: int | None = None,
    branch_path: int | None = None,
) -> _Descriptor:
    source_id = _unsigned_integer(match.group("source_id"), "source ID")
    start_byte = _unsigned_integer(match.group("start_byte"), "start byte")
    end_byte = _unsigned_integer(match.group("end_byte"), "end byte")
    start_line = _unsigned_integer(match.group("start_line"), "start line", positive=True)
    end_line = _unsigned_integer(match.group("end_line"), "end line", positive=True)
    hits = _unsigned_integer(match.group("hits"), "hit count")
    _validate_location(
        source_id=source_id,
        start_byte=start_byte,
        end_byte=end_byte,
        start_line=start_line,
        end_line=end_line,
        hits=hits,
    )
    return _Descriptor(
        kind=kind,
        source_id=source_id,
        start_byte=start_byte,
        end_byte=end_byte,
        start_line=start_line,
        end_line=end_line,
        hits=hits,
        name=name,
        branch=branch,
        branch_path=branch_path,
    )


def _record_descriptor(
    descriptors: dict[_Descriptor, int],
    descriptor: _Descriptor,
    line_number: int,
) -> None:
    identity = _Descriptor(
        kind=descriptor.kind,
        source_id=descriptor.source_id,
        start_byte=descriptor.start_byte,
        end_byte=descriptor.end_byte,
        start_line=descriptor.start_line,
        end_line=descriptor.end_line,
        hits=0,
        name=descriptor.name,
        branch=descriptor.branch,
        branch_path=descriptor.branch_path,
    )
    prior_hits = descriptors.get(identity)
    if prior_hits is not None and prior_hits != descriptor.hits:
        raise _line_error(line_number, "coverage descriptor has conflicting hit counts")
    descriptors[identity] = descriptor.hits


def _record_statement(
    statements: dict[tuple[int, int, int, int, int], _StatementBuilder],
    descriptor: _Descriptor,
    *,
    item_id: int | None,
    max_statements: int,
    line_number: int,
) -> None:
    identity = descriptor.statement_identity
    prior = statements.get(identity)
    if prior is not None:
        if prior.descriptor.hits != descriptor.hits:
            raise _line_error(line_number, "physical statement has conflicting hit counts")
        if item_id is not None:
            prior.item_ids.add(item_id)
        return
    if len(statements) >= max_statements:
        raise _line_error(line_number, "statement count exceeds the configured limit")
    statements[identity] = _StatementBuilder(
        descriptor=descriptor,
        item_ids=set() if item_id is None else {item_id},
    )


def _validate_machine_json_line(raw: bytes) -> None:
    if type(raw) is not bytes or not raw or b"\n" in raw or b"\r" in raw:
        raise FoundryStatementCoverageError(
            "Forge machine result must be exactly one nonempty JSON object line"
        )
    if len(raw) > MAX_FORGE_DEBUG_BYTES:
        raise FoundryStatementCoverageError(
            "Forge machine result exceeds the supported byte length"
        )
    if raw != raw.strip() or not raw.startswith(b"{") or not raw.endswith(b"}"):
        raise FoundryStatementCoverageError("Forge machine result is not a strict JSON object")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise FoundryStatementCoverageError(
            "Forge machine result is not a strict JSON object"
        ) from exc
    if type(value) is not dict:
        raise FoundryStatementCoverageError("Forge machine result must be a JSON object")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"nonstandard JSON numeric constant {value!r}")


def _validate_location(
    *,
    source_id: int,
    start_byte: int,
    end_byte: int,
    start_line: int,
    end_line: int,
    hits: int,
) -> None:
    _bounded_integer(source_id, "source ID")
    _bounded_integer(start_byte, "start byte")
    _bounded_integer(end_byte, "end byte")
    _bounded_integer(start_line, "start line", positive=True)
    _bounded_integer(end_line, "end line", positive=True)
    _bounded_integer(hits, "hit count")
    if end_byte <= start_byte:
        raise FoundryStatementCoverageError("coverage byte ranges must be nonempty and half-open")
    if end_line <= start_line:
        raise FoundryStatementCoverageError("coverage line ranges must be nonempty and half-open")


def _unsigned_integer(value: str, label: str, *, positive: bool = False) -> int:
    if (
        not value
        or not value.isascii()
        or not value.isdigit()
        or (len(value) > 1 and value.startswith("0"))
        or len(value) > 19
    ):
        raise FoundryStatementCoverageError(f"{label} is not a canonical nonnegative integer")
    parsed = int(value)
    _bounded_integer(parsed, label, positive=positive)
    return parsed


def _bounded_integer(value: int, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < 0 or value > _MAX_INTEGER or (positive and value == 0):
        qualifier = "positive" if positive else "bounded nonnegative"
        raise FoundryStatementCoverageError(f"{label} is not a {qualifier} integer")
    return value


def _canonical_source_path(value: str) -> str:
    if not value or "\\" in value or _WINDOWS_DRIVE.match(value):
        raise FoundryStatementCoverageError("coverage path is not a repository-relative POSIX path")
    try:
        normalized = normalize_relative_path(value)
    except ValueError as exc:
        raise FoundryStatementCoverageError(
            "coverage path is not a repository-relative POSIX path"
        ) from exc
    path = PurePosixPath(value)
    if (
        normalized != value
        or normalized == "."
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or value.startswith("-")
        or unicodedata.normalize("NFC", value) != value
        or len(value.encode("utf-8")) > _MAX_PATH_BYTES
        or any(
            unicodedata.category(character).startswith("C")
            or unicodedata.category(character) in {"Zl", "Zp"}
            for character in value
        )
    ):
        raise FoundryStatementCoverageError(
            "coverage path is not a canonical repository-relative POSIX path"
        )
    return value


def _canonical_text(value: str, label: str) -> str:
    if (
        not value
        or value != value.strip()
        or unicodedata.normalize("NFC", value) != value
        or len(value.encode("utf-8")) > _MAX_TEXT_BYTES
        or any(
            unicodedata.category(character).startswith("C")
            or unicodedata.category(character) in {"Zl", "Zp"}
            for character in value
        )
    ):
        raise FoundryStatementCoverageError(f"Forge {label} is not canonical printable text")
    return value


def _canonical_solc_version(value: str) -> str:
    _canonical_text(value, "solc version")
    if not value.isascii() or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", value
    ):
        raise FoundryStatementCoverageError("Forge solc version is not canonical")
    return value


def _validate_limit(label: str, value: int, maximum: int) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        raise FoundryStatementCoverageError(f"{label} must be an integer from 1 through {maximum}")


def _line_error(line_number: int, message: str) -> FoundryStatementCoverageError:
    return FoundryStatementCoverageError(f"Forge debug line {line_number}: {message}")


# These are parsing bounds, not execution, gas, cost or deployment limits.
_MAX_BYTECODE_BYTES = 16_000_000
_MAX_SOURCE_MAP_BYTES = 16_000_000
_MAX_BYTECODE_ROWS = 500_000
_ASM_ROW = re.compile(
    r"(?:\[(?P<hits>[0-9]{3,19})\]| {5}) (?P<pc>[0-9a-f]{8}): "
    r"(?P<opcode>[A-Z][A-Z0-9]*)(?: (?P<operand>0x(?:0|[1-9a-f][0-9a-f]*)))?"
    r" *(?:// (?P<location>.+))?"
)
_ASM_SOURCE = re.compile(
    r"(?P<path>.+): (?P<line1>[0-9]+):(?P<column1>[0-9]+)-"
    r"(?P<line2>[0-9]+):(?P<column2>[0-9]+) \((?P<start>[0-9]+)-(?P<end>[0-9]+)\)"
)
_ASM_GENERATED = re.compile(r"SRCID(?P<source>[0-9]+): \((?P<start>[0-9]+)-(?P<end>[0-9]+)\)")
_OPCODE_NAMES = {
    **dict(
        enumerate(
            [
                "STOP",
                "ADD",
                "MUL",
                "SUB",
                "DIV",
                "SDIV",
                "MOD",
                "SMOD",
                "ADDMOD",
                "MULMOD",
                "EXP",
                "SIGNEXTEND",
            ]
        )
    ),
    **dict(
        enumerate(
            [
                "LT",
                "GT",
                "SLT",
                "SGT",
                "EQ",
                "ISZERO",
                "AND",
                "OR",
                "XOR",
                "NOT",
                "BYTE",
                "SHL",
                "SHR",
                "SAR",
            ],
            0x10,
        )
    ),
    0x20: "KECCAK256",
    **dict(
        enumerate(
            [
                "ADDRESS",
                "BALANCE",
                "ORIGIN",
                "CALLER",
                "CALLVALUE",
                "CALLDATALOAD",
                "CALLDATASIZE",
                "CALLDATACOPY",
                "CODESIZE",
                "CODECOPY",
                "GASPRICE",
                "EXTCODESIZE",
                "EXTCODECOPY",
                "RETURNDATASIZE",
                "RETURNDATACOPY",
                "EXTCODEHASH",
            ],
            0x30,
        )
    ),
    **dict(
        enumerate(
            [
                "BLOCKHASH",
                "COINBASE",
                "TIMESTAMP",
                "NUMBER",
                "PREVRANDAO",
                "GASLIMIT",
                "CHAINID",
                "SELFBALANCE",
                "BASEFEE",
                "BLOBHASH",
                "BLOBBASEFEE",
            ],
            0x40,
        )
    ),
    **dict(
        enumerate(
            [
                "POP",
                "MLOAD",
                "MSTORE",
                "MSTORE8",
                "SLOAD",
                "SSTORE",
                "JUMP",
                "JUMPI",
                "PC",
                "MSIZE",
                "GAS",
                "JUMPDEST",
                "TLOAD",
                "TSTORE",
                "MCOPY",
                "PUSH0",
            ],
            0x50,
        )
    ),
    **{0x5F + size: f"PUSH{size}" for size in range(1, 33)},
    **{0x7F + size: f"DUP{size}" for size in range(1, 17)},
    **{0x8F + size: f"SWAP{size}" for size in range(1, 17)},
    **{0xA0 + size: f"LOG{size}" for size in range(5)},
    0xF0: "CREATE",
    0xF1: "CALL",
    0xF2: "CALLCODE",
    0xF3: "RETURN",
    0xF4: "DELEGATECALL",
    0xF5: "CREATE2",
    0xFA: "STATICCALL",
    0xFD: "REVERT",
    0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}
_OPCODE_VALUES = {name: value for value, name in _OPCODE_NAMES.items()}
_OPCODE_VALUES.update(SHA3=0x20, DIFFICULTY=0x44)
type BytecodePhase = Literal["CREATION", "RUNTIME"]


@dataclass(frozen=True, slots=True)
class SolcMappedInstruction:
    """One compiler source-map entry at an exact original bytecode instruction."""

    pc: int
    opcode: int
    push_data: bytes
    start_byte: int
    length: int
    source_id: int
    jump: str
    modifier_depth: int

    @property
    def source_identity(self) -> tuple[int, int, int] | None:
        return (
            None
            if self.source_id == -1
            else (self.source_id, self.start_byte, self.start_byte + self.length)
        )


@dataclass(frozen=True, slots=True)
class SolcBytecodeMap:
    """Complete source-map population; retain the unmapped bytecode tail separately."""

    bytecode_sha256: str
    source_map_sha256: str
    bytecode_bytes: int
    instructions: tuple[SolcMappedInstruction, ...]
    unmapped_bytecode: bytes


@dataclass(frozen=True, slots=True)
class ForgeBytecodeReportRow:
    """Untrusted reported hits, instruction bytes and source annotations; not coverage."""

    pc: int
    opcode: int
    push_data: bytes
    hits: int
    source_identity: tuple[int, int, int] | None
    reported_line_columns: tuple[int, int, int, int] | None


@dataclass(frozen=True, slots=True)
class ForgeBytecodeReportBinding:
    """Structural phase comparison only, never proof of phase-separated execution hits.

    Line/column annotations are retained but not verified against source bytes.
    Even a coherent report may combine creation/runtime hits; a consistent phase
    must not be interpreted as statement coverage or a verified execution trace.
    """

    report_sha256: str
    source_paths: tuple[tuple[int, str], ...]
    rows: tuple[ForgeBytecodeReportRow, ...]
    creation: SolcBytecodeMap
    runtime: SolcBytecodeMap
    instruction_phases: tuple[BytecodePhase, ...]
    source_map_phases: tuple[BytecodePhase, ...]

    def require_consistent_phase(self) -> BytecodePhase:
        """Refuse mixed, incomplete, unknown or ambiguous compiler/report identities."""

        phases = tuple(p for p in self.instruction_phases if p in self.source_map_phases)
        if len(phases) != 1:
            raise FoundryStatementCoverageError(
                "bytecode report lacks one consistent compiler instruction/source-map phase"
            )
        return phases[0]


def parse_solc_bytecode_source_map(bytecode: bytes, source_map: str) -> SolcBytecodeMap:
    """Expand every compressed entry and bind it to a complete original instruction.

    PUSH operands are not instructions. A bytecode suffix beyond the final map
    entry is retained, not decoded as executable coverage or silently discarded.
    Modifier depth is metadata, not evidence that a particular placeholder ran.
    """

    if type(bytecode) is not bytes or not 0 < len(bytecode) <= _MAX_BYTECODE_BYTES:
        raise FoundryStatementCoverageError("compiler bytecode must be bounded nonempty bytes")
    if (
        type(source_map) is not str
        or not source_map.isascii()
        or not 0 < len(source_map) <= _MAX_SOURCE_MAP_BYTES
        or source_map.count(";") >= _MAX_BYTECODE_ROWS
    ):
        raise FoundryStatementCoverageError("compiler source map must be bounded nonempty ASCII")
    previous = ["-1", "-1", "-1", "-", "0"]
    result: list[SolcMappedInstruction] = []
    pc = 0
    for raw in source_map.split(";"):
        fields = raw.split(":")
        if len(fields) > 5:
            raise FoundryStatementCoverageError("compiler source map has extra fields")
        previous = [
            fields[i] if i < len(fields) and fields[i] else value
            for i, value in enumerate(previous)
        ]
        if previous[3] not in {"i", "o", "-"} or any(
            re.fullmatch(r"-1|0|[1-9][0-9]{0,18}", previous[i]) is None
            or int(previous[i]) > _MAX_INTEGER
            for i in (0, 1, 2, 4)
        ):
            raise FoundryStatementCoverageError("compiler source map has invalid field values")
        start, length, source, depth = (int(previous[i]) for i in (0, 1, 2, 4))
        if depth < 0 or (source >= 0 and (start < 0 or length < 0)):
            raise FoundryStatementCoverageError("compiler source map has invalid source bounds")
        if start + length > _MAX_INTEGER or pc >= len(bytecode):
            raise FoundryStatementCoverageError("compiler source map exceeds bytecode or bounds")
        opcode = bytecode[pc]
        size = opcode - 0x5F if 0x60 <= opcode <= 0x7F else 0
        end = pc + 1 + size
        if end > len(bytecode):
            raise FoundryStatementCoverageError("compiler mapped PUSH operand is truncated")
        result.append(
            SolcMappedInstruction(
                pc,
                opcode,
                bytecode[pc + 1 : end],
                start,
                length,
                source,
                previous[3],
                depth,
            )
        )
        pc = end
    return SolcBytecodeMap(
        hashlib.sha256(bytecode).hexdigest(),
        hashlib.sha256(source_map.encode("ascii")).hexdigest(),
        len(bytecode),
        tuple(result),
        bytecode[pc:],
    )


def _bytecode_report_rows(
    raw: bytes,
    source_paths: tuple[tuple[int, str], ...],
) -> tuple[ForgeBytecodeReportRow, ...]:
    if type(source_paths) is not tuple or not 1 <= len(source_paths) <= _MAX_BYTECODE_ROWS:
        raise FoundryStatementCoverageError("compiler source paths must be a bounded tuple")
    paths: dict[str, int] = {}
    ids: set[int] = set()
    for binding in source_paths:
        if type(binding) is not tuple or len(binding) != 2:
            raise FoundryStatementCoverageError("compiler source path binding is invalid")
        source_id, path = binding
        _bounded_integer(source_id, "compiler source ID")
        _canonical_source_path(path)
        if path in paths or source_id in ids:
            raise FoundryStatementCoverageError("compiler source path bindings must be one-to-one")
        paths[path] = source_id
        ids.add(source_id)
    if source_paths != tuple(sorted(source_paths)):
        raise FoundryStatementCoverageError("compiler source path bindings must be sorted")
    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= MAX_FORGE_DEBUG_BYTES
        or b"\r" in raw
        or not raw.endswith(b"\n")
        or raw.count(b"\n") > _MAX_BYTECODE_ROWS
    ):
        raise FoundryStatementCoverageError("bytecode report must be bounded LF-terminated bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FoundryStatementCoverageError("bytecode report is not UTF-8") from exc
    rows: list[ForgeBytecodeReportRow] = []
    pc = 0
    for line in text[:-1].split("\n"):
        match = _ASM_ROW.fullmatch(line) if len(line.encode("utf-8")) <= _MAX_LINE_BYTES else None
        if match is None or match["opcode"] not in _OPCODE_VALUES:
            raise FoundryStatementCoverageError("bytecode report instruction is unsupported")
        opcode = _OPCODE_VALUES[match["opcode"]]
        size = opcode - 0x5F if 0x60 <= opcode <= 0x7F else 0
        operand = match["operand"]
        if int(match["pc"], 16) != pc or bool(operand) != bool(size):
            raise FoundryStatementCoverageError("bytecode report has an invalid PC or PUSH operand")
        if operand and (len(operand) > 66 or int(operand, 16) >= 1 << (size * 8)):
            raise FoundryStatementCoverageError("bytecode report PUSH operand exceeds its width")
        push = int(operand, 16).to_bytes(size, "big") if operand else b""
        hits = int(match["hits"] or "0")
        _bounded_integer(hits, "reported hits")
        location = match["location"]
        identity: tuple[int, int, int] | None = None
        coordinates: tuple[int, int, int, int] | None = None
        if location is not None:
            generated = _ASM_GENERATED.fullmatch(location)
            origin = _ASM_SOURCE.fullmatch(location)
            if generated is not None:
                source_id = _unsigned_integer(generated["source"], "generated source ID")
                if source_id in ids:
                    raise FoundryStatementCoverageError(
                        "bytecode report hides a supplied source path"
                    )
                start = _unsigned_integer(generated["start"], "source start")
                end = _unsigned_integer(generated["end"], "source end")
            elif origin is not None and origin["path"] in paths:
                source_id = paths[origin["path"]]
                start = _unsigned_integer(origin["start"], "source start")
                end = _unsigned_integer(origin["end"], "source end")
                coordinates = (
                    _unsigned_integer(origin["line1"], "source line", positive=True),
                    _unsigned_integer(origin["column1"], "source column", positive=True),
                    _unsigned_integer(origin["line2"], "source line", positive=True),
                    _unsigned_integer(origin["column2"], "source column", positive=True),
                )
                if coordinates[:2] > coordinates[2:]:
                    raise FoundryStatementCoverageError(
                        "bytecode report source coordinates reverse"
                    )
            else:
                raise FoundryStatementCoverageError("bytecode report source path is unknown")
            if start > end:
                raise FoundryStatementCoverageError("bytecode report source bounds reverse")
            identity = (source_id, start, end)
        rows.append(ForgeBytecodeReportRow(pc, opcode, push, hits, identity, coordinates))
        pc += 1 + size
    return tuple(rows)


def reconcile_forge_bytecode_report(
    raw: bytes,
    *,
    creation_bytecode: bytes,
    creation_source_map: str,
    runtime_bytecode: bytes,
    runtime_source_map: str,
    source_paths: tuple[tuple[int, str], ...],
) -> ForgeBytecodeReportBinding:
    """Compare original report bytes with both original compiler phases, without I/O.

    Instruction matching considers the exact prefix reported, independently of
    source-map matching, which requires the *entire* map population. This exposes
    phase mixing instead of truncating a map to manufacture an accepted join.
    Caller-owned compiler/source/process custody remains separately required.
    """

    rows = _bytecode_report_rows(raw, source_paths)
    creation = parse_solc_bytecode_source_map(creation_bytecode, creation_source_map)
    runtime = parse_solc_bytecode_source_map(runtime_bytecode, runtime_source_map)
    instruction_phases: list[BytecodePhase] = []
    source_map_phases: list[BytecodePhase] = []
    candidates: tuple[tuple[BytecodePhase, bytes, SolcBytecodeMap], ...] = (
        ("CREATION", creation_bytecode, creation),
        ("RUNTIME", runtime_bytecode, runtime),
    )
    for phase, bytecode, mapping in candidates:
        if all(
            row.pc + 1 + len(row.push_data) <= len(bytecode)
            and bytecode[row.pc] == row.opcode
            and bytecode[row.pc + 1 : row.pc + 1 + len(row.push_data)] == row.push_data
            for row in rows
        ):
            instruction_phases.append(phase)
        if len(rows) == len(mapping.instructions) and all(
            row.source_identity == entry.source_identity
            for row, entry in zip(rows, mapping.instructions, strict=True)
        ):
            source_map_phases.append(phase)
    return ForgeBytecodeReportBinding(
        hashlib.sha256(raw).hexdigest(),
        source_paths,
        rows,
        creation,
        runtime,
        tuple(instruction_phases),
        tuple(source_map_phases),
    )
