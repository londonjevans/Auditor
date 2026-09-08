from __future__ import annotations

import hashlib

import pytest

from mmaudit.scanners.foundry_coverage import (
    MAX_LCOV_BYTES,
    FoundryCoverageError,
    LcovLineCoverage,
    LcovLineRecord,
    LcovSourceLineCoverage,
    parse_lcov_v1,
)


def _report(*records: str) -> bytes:
    return ("\n".join(records) + "\n").encode()


def test_lcov_v1_parser_validates_common_records_and_canonicalizes_line_evidence() -> None:
    parsed = parse_lcov_v1(
        _report(
            "TN:foundry",
            "SF:src/Z.sol",
            "FN:4,run(uint256)",
            "FNDA:2,run(uint256)",
            "FNF:1",
            "FNH:1",
            "BRDA:4,0,0,1",
            "BRDA:4,0,1,-",
            "BRF:2",
            "BRH:1",
            "DA:7,0",
            "DA:4,2",
            "LF:2",
            "LH:1",
            "end_of_record",
            "SF:src/A.sol",
            "DA:9,3",
            "LF:1",
            "LH:1",
            "end_of_record",
        )
    )

    assert isinstance(parsed, LcovLineCoverage)
    assert parsed.test_name == "foundry"
    assert parsed.source_count == 2
    assert parsed.da_record_count == 3
    assert tuple(source.path for source in parsed.sources) == ("src/A.sol", "src/Z.sol")
    assert parsed.sources[1].lines == (
        LcovLineRecord(line=4, hits=2),
        LcovLineRecord(line=7, hits=0),
    )
    expected = _report(
        "TN:foundry",
        "SF:src/A.sol",
        "DA:9,3",
        "LF:1",
        "LH:1",
        "end_of_record",
        "SF:src/Z.sol",
        "DA:4,2",
        "DA:7,0",
        "LF:2",
        "LH:1",
        "end_of_record",
    )
    assert parsed.canonical_bytes() == expected
    assert parsed.canonical_sha256() == hashlib.sha256(expected).hexdigest()


def test_lcov_v1_parser_accepts_optional_function_end_line_without_splitting_name() -> None:
    parsed = parse_lcov_v1(
        _report(
            "SF:src/A.sol",
            "FN:4,9,run(uint256,address)",
            "FNDA:2,run(uint256,address)",
            "FNF:1",
            "FNH:1",
            "LF:0",
            "LH:0",
            "end_of_record",
        )
    )

    assert parsed.sources[0].path == "src/A.sol"


def test_lcov_line_evidence_cannot_distinguish_two_source_spans_on_one_line() -> None:
    parsed = parse_lcov_v1(
        _report(
            "SF:src/TwoStatements.sol",
            "DA:8,1",
            "LF:1",
            "LH:1",
            "end_of_record",
        )
    )
    first_statement_span = (8, 4, 15)
    second_statement_span = (8, 21, 15)

    assert first_statement_span != second_statement_span
    assert parsed.sources[0].lines == (LcovLineRecord(line=8, hits=1),)
    assert parsed.sources[0].hits_for_line(first_statement_span[0]) == 1
    assert parsed.sources[0].hits_for_line(second_statement_span[0]) == 1


def test_lcov_public_value_constructors_preserve_parser_invariants() -> None:
    with pytest.raises(FoundryCoverageError, match="bounded canonical integers"):
        LcovLineRecord(line=0, hits=1)
    with pytest.raises(FoundryCoverageError, match="unique and canonically sorted"):
        LcovSourceLineCoverage(
            path="src/A.sol",
            lines=(LcovLineRecord(line=2, hits=1), LcovLineRecord(line=1, hits=1)),
        )
    with pytest.raises(FoundryCoverageError, match="SF path"):
        LcovSourceLineCoverage(path="../A.sol", lines=())
    with pytest.raises(FoundryCoverageError, match="unique and canonically sorted"):
        source = LcovSourceLineCoverage(path="src/A.sol", lines=())
        LcovLineCoverage(test_name=None, sources=(source, source))


@pytest.mark.parametrize(
    "raw, error",
    [
        (b"", "empty"),
        (b"SF:src/A.sol\r\nend_of_record\r\n", "LF line endings"),
        (b"SF:src/A.sol\nend_of_record", "end with LF"),
        (b"SF:src/A.sol\n\nend_of_record\n", "empty record"),
        (b"SF:src/\xff.sol\nend_of_record\n", "UTF-8"),
    ],
)
def test_lcov_v1_parser_rejects_invalid_byte_envelopes(raw: bytes, error: str) -> None:
    with pytest.raises(FoundryCoverageError, match=error):
        parse_lcov_v1(raw)


def test_lcov_v1_parser_enforces_byte_and_record_bounds() -> None:
    report = _report("SF:src/A.sol", "LF:0", "LH:0", "end_of_record")
    with pytest.raises(FoundryCoverageError, match="configured byte limit"):
        parse_lcov_v1(report, max_bytes=len(report) - 1)
    with pytest.raises(FoundryCoverageError, match="max_bytes"):
        parse_lcov_v1(report, max_bytes=MAX_LCOV_BYTES + 1)

    oversized_name = "a" * 16_385
    oversized = _report(
        f"TN:{oversized_name}",
        "SF:src/A.sol",
        "LF:0",
        "LH:0",
        "end_of_record",
    )
    with pytest.raises(FoundryCoverageError, match="record exceeds"):
        parse_lcov_v1(oversized)


@pytest.mark.parametrize(
    "path",
    [
        "/tmp/A.sol",
        "../A.sol",
        "src/../A.sol",
        r"src\A.sol",
        "./src/A.sol",
        "src//A.sol",
        "C:/src/A.sol",
        "C:src/A.sol",
        "-src/A.sol",
    ],
)
def test_lcov_v1_parser_rejects_unsafe_or_noncanonical_source_paths(path: str) -> None:
    with pytest.raises(FoundryCoverageError, match="SF path"):
        parse_lcov_v1(_report(f"SF:{path}", "LF:0", "LH:0", "end_of_record"))


@pytest.mark.parametrize(
    "records, error",
    [
        (
            ("SF:src/A.sol", "DA:2,0", "DA:2,1", "LF:1", "LH:1", "end_of_record"),
            "DA source line is duplicate",
        ),
        (
            (
                "SF:src/A.sol",
                "LF:0",
                "LH:0",
                "end_of_record",
                "SF:src/A.sol",
                "LF:0",
                "LH:0",
                "end_of_record",
            ),
            "SF source path is duplicate",
        ),
        (
            ("SF:src/A.sol", "LF:0", "LF:0", "LH:0", "end_of_record"),
            "LF record is duplicate",
        ),
        (
            (
                "SF:src/A.sol",
                "FN:1,run()",
                "FN:2,run()",
                "LF:0",
                "LH:0",
                "end_of_record",
            ),
            "FN function name is duplicate",
        ),
        (
            (
                "SF:src/A.sol",
                "BRDA:1,0,0,0",
                "BRDA:1,0,0,1",
                "LF:0",
                "LH:0",
                "end_of_record",
            ),
            "BRDA branch key is duplicate",
        ),
        (
            (
                "TN:first",
                "TN:second",
                "SF:src/A.sol",
                "LF:0",
                "LH:0",
                "end_of_record",
            ),
            "TN record is duplicate",
        ),
    ],
)
def test_lcov_v1_parser_rejects_duplicate_records(
    records: tuple[str, ...],
    error: str,
) -> None:
    with pytest.raises(FoundryCoverageError, match=error):
        parse_lcov_v1(_report(*records))


@pytest.mark.parametrize(
    "records, error",
    [
        (("VER:2.0",), "unsupported LCOV record type"),
        (
            ("SF:src/A.sol", "DA:1,-1", "LF:1", "LH:0", "end_of_record"),
            "DA second",
        ),
        (
            ("SF:src/A.sol", "DA:0,1", "LF:1", "LH:1", "end_of_record"),
            "positive",
        ),
        (
            ("SF:src/A.sol", "DA:1,1,checksum", "LF:1", "LH:1", "end_of_record"),
            "exactly two",
        ),
        (
            (
                "SF:src/A.sol",
                "FN:9,4,run()",
                "FNDA:1,run()",
                "FNF:1",
                "FNH:1",
                "LF:0",
                "LH:0",
                "end_of_record",
            ),
            "end line precedes",
        ),
        (("SF:src/A.sol", "LF:0", "LH:0"), "missing end_of_record"),
        (("end_of_record",), "no open source"),
        (
            ("SF:src/A.sol", "FN:1,run()", "LF:0", "LH:0", "end_of_record"),
            "FN and FNDA",
        ),
        (
            (
                "SF:src/A.sol",
                "BRDA:1,0,0,-",
                "BRF:1",
                "BRH:1",
                "LF:0",
                "LH:0",
                "end_of_record",
            ),
            "branch summary is inconsistent",
        ),
    ],
)
def test_lcov_v1_parser_rejects_malformed_or_inconsistent_records(
    records: tuple[str, ...],
    error: str,
) -> None:
    with pytest.raises(FoundryCoverageError, match=error):
        parse_lcov_v1(_report(*records))


def test_lcov_v1_parser_enforces_source_and_da_limits() -> None:
    two_sources = _report(
        "SF:src/A.sol",
        "LF:0",
        "LH:0",
        "end_of_record",
        "SF:src/B.sol",
        "LF:0",
        "LH:0",
        "end_of_record",
    )
    with pytest.raises(FoundryCoverageError, match="source count"):
        parse_lcov_v1(two_sources, max_sources=1)

    two_lines = _report(
        "SF:src/A.sol",
        "DA:1,0",
        "DA:2,0",
        "LF:2",
        "LH:0",
        "end_of_record",
    )
    with pytest.raises(FoundryCoverageError, match="DA record count"):
        parse_lcov_v1(two_lines, max_da_records=1)


def test_lcov_v1_parser_streams_under_total_function_and_branch_record_limits() -> None:
    minimal = _report("SF:src/A.sol", "LF:0", "LH:0", "end_of_record")
    with pytest.raises(FoundryCoverageError, match="record count exceeds"):
        parse_lcov_v1(minimal, max_records=3)

    functions = _report(
        "SF:src/A.sol",
        "FN:1,run()",
        "FNDA:1,run()",
        "FNF:1",
        "FNH:1",
        "LF:0",
        "LH:0",
        "end_of_record",
    )
    with pytest.raises(FoundryCoverageError, match="function record count"):
        parse_lcov_v1(functions, max_function_records=1)

    branches = _report(
        "SF:src/A.sol",
        "BRDA:1,0,0,0",
        "BRDA:1,0,1,0",
        "BRF:2",
        "BRH:0",
        "LF:0",
        "LH:0",
        "end_of_record",
    )
    with pytest.raises(FoundryCoverageError, match="branch record count"):
        parse_lcov_v1(branches, max_branch_records=1)
