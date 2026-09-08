"""Strict, bounded parsing of LCOV v1 into line-only Foundry coverage evidence.

The parser validates common function and branch records so a malformed tracefile
cannot hide behind ignored fields. Its public result deliberately retains only
DA line hit counts. A line hit is not evidence that every source span or
statement on that line executed.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from mmaudit.repository.ignore import normalize_relative_path

MAX_LCOV_BYTES = 16_000_000
MAX_LCOV_SOURCES = 100_000
MAX_LCOV_DA_RECORDS = 1_000_000
MAX_LCOV_RECORDS = 3_000_000
MAX_LCOV_FUNCTION_RECORDS = 200_000
MAX_LCOV_BRANCH_RECORDS = 1_000_000
MAX_LCOV_RECORD_BYTES = 16_384

_MAX_LCOV_PATH_BYTES = 4_096
_MAX_LCOV_NAME_BYTES = 4_096
_MAX_LCOV_INTEGER = 2**63 - 1
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_SOURCE_RECORD_TAGS = frozenset(
    {"DA", "LF", "LH", "FN", "FNDA", "FNF", "FNH", "BRDA", "BRF", "BRH"}
)


class FoundryCoverageError(ValueError):
    """Raised when LCOV input is unsafe, unsupported, or internally inconsistent."""


@dataclass(frozen=True, slots=True, order=True)
class LcovLineRecord:
    """One LCOV DA record: a one-based source line and its execution count."""

    line: int
    hits: int

    def __post_init__(self) -> None:
        if (
            type(self.line) is not int
            or type(self.hits) is not int
            or not 1 <= self.line <= _MAX_LCOV_INTEGER
            or not 0 <= self.hits <= _MAX_LCOV_INTEGER
        ):
            raise FoundryCoverageError("LCOV line records require bounded canonical integers")


@dataclass(frozen=True, slots=True)
class LcovSourceLineCoverage:
    """Canonical line-only coverage for one repository-relative source."""

    path: str
    lines: tuple[LcovLineRecord, ...]

    def __post_init__(self) -> None:
        _canonical_source_path(self.path)
        if type(self.lines) is not tuple or any(
            type(record) is not LcovLineRecord for record in self.lines
        ):
            raise FoundryCoverageError("LCOV source lines must be exact line records")
        keys = [(record.line, record.hits) for record in self.lines]
        if keys != sorted(keys) or len({record.line for record in self.lines}) != len(self.lines):
            raise FoundryCoverageError("LCOV source lines must be unique and canonically sorted")

    @property
    def line_count(self) -> int:
        return len(self.lines)

    @property
    def hit_line_count(self) -> int:
        return sum(record.hits > 0 for record in self.lines)

    def hits_for_line(self, line: int) -> int | None:
        """Return the DA count for line without inferring source-span coverage."""

        lower = 0
        upper = len(self.lines)
        while lower < upper:
            middle = (lower + upper) // 2
            record = self.lines[middle]
            if record.line < line:
                lower = middle + 1
            else:
                upper = middle
        if lower < len(self.lines) and self.lines[lower].line == line:
            return self.lines[lower].hits
        return None


@dataclass(frozen=True, slots=True)
class LcovLineCoverage:
    """Deterministically ordered LCOV line evidence.

    Function and branch records are checked during parsing but intentionally do
    not appear here. Consequently, the canonical form is a line-evidence form,
    not a byte-for-byte canonicalization of the full input tracefile.
    """

    test_name: str | None
    sources: tuple[LcovSourceLineCoverage, ...]

    def __post_init__(self) -> None:
        if self.test_name is not None:
            _canonical_text(self.test_name, "test name", allow_empty=True)
        if (
            type(self.sources) is not tuple
            or not self.sources
            or len(self.sources) > MAX_LCOV_SOURCES
            or any(type(source) is not LcovSourceLineCoverage for source in self.sources)
        ):
            raise FoundryCoverageError("LCOV coverage requires bounded exact source records")
        paths = [source.path for source in self.sources]
        if paths != sorted(set(paths)):
            raise FoundryCoverageError("LCOV sources must be unique and canonically sorted")
        if self.da_record_count > MAX_LCOV_DA_RECORDS:
            raise FoundryCoverageError("LCOV DA record count exceeds the supported limit")

    @property
    def source_count(self) -> int:
        return len(self.sources)

    @property
    def da_record_count(self) -> int:
        return sum(source.line_count for source in self.sources)

    def canonical_bytes(self) -> bytes:
        """Serialize the normalized line evidence as deterministic LCOV bytes."""

        records: list[str] = []
        if self.test_name is not None:
            records.append(f"TN:{self.test_name}\n")
        for source in self.sources:
            records.append(f"SF:{source.path}\n")
            records.extend(f"DA:{record.line},{record.hits}\n" for record in source.lines)
            records.append(f"LF:{source.line_count}\n")
            records.append(f"LH:{source.hit_line_count}\n")
            records.append("end_of_record\n")
        return "".join(records).encode("utf-8")

    def canonical_sha256(self) -> str:
        """Hash the canonical line-only representation."""

        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(slots=True)
class _SourceBuilder:
    path: str
    lines: dict[int, int] = field(default_factory=dict)
    functions: dict[str, int] = field(default_factory=dict)
    function_hits: dict[str, int] = field(default_factory=dict)
    branches: dict[tuple[int, int, int], int | None] = field(default_factory=dict)
    line_found: int | None = None
    line_hit: int | None = None
    function_found: int | None = None
    function_hit: int | None = None
    branch_found: int | None = None
    branch_hit: int | None = None


def parse_lcov_v1(
    raw: bytes,
    *,
    max_bytes: int = MAX_LCOV_BYTES,
    max_sources: int = MAX_LCOV_SOURCES,
    max_da_records: int = MAX_LCOV_DA_RECORDS,
    max_records: int = MAX_LCOV_RECORDS,
    max_function_records: int = MAX_LCOV_FUNCTION_RECORDS,
    max_branch_records: int = MAX_LCOV_BRANCH_RECORDS,
) -> LcovLineCoverage:
    """Parse bounded LCOV v1 bytes into canonical, line-only evidence.

    Supported records are TN, SF, FN, FNDA, FNF, FNH, BRDA, BRF, BRH, DA,
    LF, LH, and end_of_record. DA checksums and newer LCOV extensions are
    rejected because this normalizer does not preserve their semantics.
    """

    _validate_limit("max_bytes", max_bytes, MAX_LCOV_BYTES)
    _validate_limit("max_sources", max_sources, MAX_LCOV_SOURCES)
    _validate_limit("max_da_records", max_da_records, MAX_LCOV_DA_RECORDS)
    _validate_limit("max_records", max_records, MAX_LCOV_RECORDS)
    _validate_limit(
        "max_function_records",
        max_function_records,
        MAX_LCOV_FUNCTION_RECORDS,
    )
    _validate_limit("max_branch_records", max_branch_records, MAX_LCOV_BRANCH_RECORDS)
    if type(raw) is not bytes:
        raise FoundryCoverageError("LCOV input must be bytes")
    if not raw:
        raise FoundryCoverageError("LCOV input is empty")
    if len(raw) > max_bytes:
        raise FoundryCoverageError("LCOV input exceeds the configured byte limit")
    if b"\r" in raw:
        raise FoundryCoverageError("LCOV input must use LF line endings")
    if not raw.endswith(b"\n"):
        raise FoundryCoverageError("LCOV input must end with LF")

    test_name: str | None = None
    saw_test_name = False
    current: _SourceBuilder | None = None
    completed: list[LcovSourceLineCoverage] = []
    source_paths: set[str] = set()
    da_record_count = 0
    function_record_count = 0
    branch_record_count = 0

    for record_number, record in _iter_lcov_records(raw, max_records=max_records):
        if record == "end_of_record":
            if current is None:
                raise _record_error(record_number, "end_of_record has no open source")
            completed.append(_finish_source(current, record_number))
            current = None
            continue

        tag, separator, value = record.partition(":")
        if not separator:
            raise _record_error(record_number, "unsupported or malformed LCOV record")

        if tag == "TN":
            if saw_test_name or current is not None or source_paths:
                raise _record_error(record_number, "TN record is duplicate or out of order")
            test_name = _canonical_text(value, "test name", allow_empty=True)
            saw_test_name = True
            continue

        if tag == "SF":
            if current is not None:
                raise _record_error(record_number, "source is missing end_of_record")
            path = _canonical_source_path(value)
            if path in source_paths:
                raise _record_error(record_number, "SF source path is duplicate")
            if len(source_paths) >= max_sources:
                raise _record_error(record_number, "LCOV source count exceeds the configured limit")
            source_paths.add(path)
            current = _SourceBuilder(path=path)
            continue

        if tag not in _SOURCE_RECORD_TAGS:
            raise _record_error(record_number, f"unsupported LCOV record type {tag!r}")
        if current is None:
            raise _record_error(record_number, f"{tag} record has no open source")

        if tag == "DA":
            line, hits = _parse_pair(value, "DA", first_positive=True)
            if line in current.lines:
                raise _record_error(record_number, "DA source line is duplicate")
            if da_record_count >= max_da_records:
                raise _record_error(
                    record_number,
                    "LCOV DA record count exceeds the configured limit",
                )
            current.lines[line] = hits
            da_record_count += 1
        elif tag == "LF":
            current.line_found = _set_summary(current.line_found, value, "LF", record_number)
        elif tag == "LH":
            current.line_hit = _set_summary(current.line_hit, value, "LH", record_number)
        elif tag == "FN":
            function_record_count += 1
            if function_record_count > max_function_records:
                raise _record_error(
                    record_number,
                    "LCOV function record count exceeds the configured limit",
                )
            line, name_text = _parse_function_definition(value, record_number)
            name = _canonical_text(name_text, "function name")
            if name in current.functions:
                raise _record_error(record_number, "FN function name is duplicate")
            current.functions[name] = line
        elif tag == "FNDA":
            function_record_count += 1
            if function_record_count > max_function_records:
                raise _record_error(
                    record_number,
                    "LCOV function record count exceeds the configured limit",
                )
            hits_text, name_text = _split_once(value, "FNDA", record_number)
            hits = _unsigned_integer(hits_text, "FNDA hits")
            name = _canonical_text(name_text, "function name")
            if name in current.function_hits:
                raise _record_error(record_number, "FNDA function name is duplicate")
            current.function_hits[name] = hits
        elif tag == "FNF":
            current.function_found = _set_summary(
                current.function_found,
                value,
                "FNF",
                record_number,
            )
        elif tag == "FNH":
            current.function_hit = _set_summary(
                current.function_hit,
                value,
                "FNH",
                record_number,
            )
        elif tag == "BRDA":
            branch_record_count += 1
            if branch_record_count > max_branch_records:
                raise _record_error(
                    record_number,
                    "LCOV branch record count exceeds the configured limit",
                )
            parts = value.split(",")
            if len(parts) != 4:
                raise _record_error(record_number, "BRDA must contain four fields")
            line = _unsigned_integer(parts[0], "BRDA line", positive=True)
            block = _unsigned_integer(parts[1], "BRDA block")
            branch = _unsigned_integer(parts[2], "BRDA branch")
            taken = None if parts[3] == "-" else _unsigned_integer(parts[3], "BRDA taken count")
            key = (line, block, branch)
            if key in current.branches:
                raise _record_error(record_number, "BRDA branch key is duplicate")
            current.branches[key] = taken
        elif tag == "BRF":
            current.branch_found = _set_summary(
                current.branch_found,
                value,
                "BRF",
                record_number,
            )
        elif tag == "BRH":
            current.branch_hit = _set_summary(
                current.branch_hit,
                value,
                "BRH",
                record_number,
            )
        else:  # pragma: no cover - exhaustively guarded by _SOURCE_RECORD_TAGS
            raise AssertionError("unreachable LCOV record dispatch")

    if current is not None:
        raise FoundryCoverageError("LCOV source is missing end_of_record")
    if not completed:
        raise FoundryCoverageError("LCOV input contains no source records")
    return LcovLineCoverage(
        test_name=test_name,
        sources=tuple(sorted(completed, key=lambda source: source.path)),
    )


def _iter_lcov_records(raw: bytes, *, max_records: int) -> Iterator[tuple[int, str]]:
    """Decode one bounded LF-delimited record at a time without eager line expansion."""

    record_number = 0
    start = 0
    while start < len(raw):
        end = raw.find(b"\n", start)
        if end < 0:  # pragma: no cover - guarded by the complete-envelope check
            raise FoundryCoverageError("LCOV input must end with LF")
        record_number += 1
        if record_number > max_records:
            raise FoundryCoverageError("LCOV record count exceeds the configured limit")
        encoded = raw[start:end]
        if not encoded:
            raise FoundryCoverageError("LCOV input contains an empty record")
        if len(encoded) > MAX_LCOV_RECORD_BYTES:
            raise FoundryCoverageError("LCOV record exceeds the supported byte limit")
        try:
            yield record_number, encoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise FoundryCoverageError("LCOV input is not valid UTF-8") from exc
        start = end + 1


def _finish_source(source: _SourceBuilder, record_number: int) -> LcovSourceLineCoverage:
    _validate_summary_pair(
        label="line",
        found=source.line_found,
        hit=source.line_hit,
        actual_found=len(source.lines),
        actual_hit=sum(hits > 0 for hits in source.lines.values()),
        record_number=record_number,
    )

    function_group_present = bool(source.functions or source.function_hits) or any(
        value is not None for value in (source.function_found, source.function_hit)
    )
    if function_group_present:
        if source.functions.keys() != source.function_hits.keys():
            raise _record_error(
                record_number,
                "FN and FNDA function identities are inconsistent",
            )
        _validate_summary_pair(
            label="function",
            found=source.function_found,
            hit=source.function_hit,
            actual_found=len(source.functions),
            actual_hit=sum(hits > 0 for hits in source.function_hits.values()),
            record_number=record_number,
        )

    branch_group_present = bool(source.branches) or any(
        value is not None for value in (source.branch_found, source.branch_hit)
    )
    if branch_group_present:
        _validate_summary_pair(
            label="branch",
            found=source.branch_found,
            hit=source.branch_hit,
            actual_found=len(source.branches),
            actual_hit=sum(hits is not None and hits > 0 for hits in source.branches.values()),
            record_number=record_number,
        )

    return LcovSourceLineCoverage(
        path=source.path,
        lines=tuple(
            LcovLineRecord(line=line, hits=hits) for line, hits in sorted(source.lines.items())
        ),
    )


def _validate_summary_pair(
    *,
    label: str,
    found: int | None,
    hit: int | None,
    actual_found: int,
    actual_hit: int,
    record_number: int,
) -> None:
    if found is None or hit is None:
        raise _record_error(record_number, f"{label} summary is incomplete")
    if found != actual_found or hit != actual_hit:
        raise _record_error(record_number, f"{label} summary is inconsistent")


def _set_summary(
    existing: int | None,
    value: str,
    tag: str,
    record_number: int,
) -> int:
    if existing is not None:
        raise _record_error(record_number, f"{tag} record is duplicate")
    return _unsigned_integer(value, f"{tag} count")


def _parse_pair(value: str, tag: str, *, first_positive: bool) -> tuple[int, int]:
    parts = value.split(",")
    if len(parts) != 2:
        raise FoundryCoverageError(f"{tag} must contain exactly two integer fields")
    return (
        _unsigned_integer(parts[0], f"{tag} first field", positive=first_positive),
        _unsigned_integer(parts[1], f"{tag} second field"),
    )


def _split_once(value: str, tag: str, record_number: int) -> tuple[str, str]:
    first, separator, remainder = value.partition(",")
    if not separator or not remainder:
        raise _record_error(record_number, f"{tag} must contain two fields")
    return first, remainder


def _parse_function_definition(value: str, record_number: int) -> tuple[int, str]:
    """Accept legacy FN start/name and optional start/end/name trace forms."""

    start_text, remainder = _split_once(value, "FN", record_number)
    start_line = _unsigned_integer(start_text, "FN start line", positive=True)
    possible_end, separator, possible_name = remainder.partition(",")
    if separator and possible_end.isascii() and possible_end.isdigit():
        end_line = _unsigned_integer(possible_end, "FN end line", positive=True)
        if end_line < start_line:
            raise _record_error(record_number, "FN end line precedes its start line")
        if not possible_name:
            raise _record_error(record_number, "FN function name is empty")
        return start_line, possible_name
    return start_line, remainder


def _unsigned_integer(value: str, label: str, *, positive: bool = False) -> int:
    if (
        not value
        or not value.isascii()
        or not value.isdigit()
        or (len(value) > 1 and value.startswith("0"))
        or len(value) > 19
    ):
        raise FoundryCoverageError(f"{label} is not a canonical nonnegative integer")
    parsed = int(value)
    if parsed > _MAX_LCOV_INTEGER or (positive and parsed == 0):
        qualifier = "positive" if positive else "bounded nonnegative"
        raise FoundryCoverageError(f"{label} is not a {qualifier} integer")
    return parsed


def _canonical_source_path(value: str) -> str:
    if not value or "\\" in value or _WINDOWS_DRIVE.match(value):
        raise FoundryCoverageError("SF path is not a repository-relative POSIX path")
    try:
        normalized = normalize_relative_path(value)
    except ValueError as exc:
        raise FoundryCoverageError("SF path is not a repository-relative POSIX path") from exc
    path = PurePosixPath(value)
    if (
        normalized != value
        or normalized == "."
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or value.startswith("-")
        or unicodedata.normalize("NFC", value) != value
        or len(value.encode("utf-8")) > _MAX_LCOV_PATH_BYTES
        or any(
            unicodedata.category(character).startswith("C")
            or unicodedata.category(character) in {"Zl", "Zp"}
            for character in value
        )
    ):
        raise FoundryCoverageError("SF path is not a canonical repository-relative POSIX path")
    return value


def _canonical_text(value: str, label: str, *, allow_empty: bool = False) -> str:
    if (
        (not value and not allow_empty)
        or value != value.strip()
        or unicodedata.normalize("NFC", value) != value
        or len(value.encode("utf-8")) > _MAX_LCOV_NAME_BYTES
        or any(
            unicodedata.category(character).startswith("C")
            or unicodedata.category(character) in {"Zl", "Zp"}
            for character in value
        )
    ):
        raise FoundryCoverageError(f"LCOV {label} is not canonical printable text")
    return value


def _validate_limit(label: str, value: int, maximum: int) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        raise FoundryCoverageError(f"{label} must be an integer from 1 through {maximum}")


def _record_error(record_number: int, message: str) -> FoundryCoverageError:
    return FoundryCoverageError(f"LCOV record {record_number}: {message}")
