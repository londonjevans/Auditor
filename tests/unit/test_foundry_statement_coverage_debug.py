from __future__ import annotations

import hashlib

import pytest

from mmaudit.scanners.foundry_statement_coverage import (
    MAX_FORGE_DEBUG_BYTES,
    ForgeDebugStatementCoverage,
    ForgeDebugStatementRecord,
    ForgeDebugUncoveredSource,
    FoundryStatementCoverageError,
    parse_forge_debug_statement_coverage,
)


def _output(*records: str) -> bytes:
    return ("\n".join(records) + "\n").encode("utf-8")


def _descriptor(
    kind: str,
    *,
    source_id: int = 1,
    start_line: int = 4,
    end_line: int = 5,
    start_byte: int = 40,
    end_byte: int = 60,
    hits: int = 0,
) -> str:
    return (
        f"{kind} (location: source ID {source_id}, "
        f"lines {start_line}..{end_line}, bytes {start_byte}..{end_byte}, hits: {hits})"
    )


def _anchor(item_id: int, descriptor: str, *, instruction: int = 5) -> tuple[str, str, str]:
    return (
        f"- IC {instruction} -> Item {item_id}",
        "- Runtime code",
        f"  - Refers to item: {descriptor}",
    )


def test_parser_unions_uncovered_and_anchored_statements_and_preserves_nested_spans() -> None:
    outer = _descriptor("Statement", start_byte=40, end_byte=80)
    inner_unanchored = _descriptor(
        "Statement", start_byte=48, end_byte=70, start_line=4, end_line=5
    )
    covered_nested = _descriptor(
        "Statement", start_byte=52, end_byte=64, start_line=4, end_line=5, hits=3
    )
    parsed = parse_forge_debug_statement_coverage(
        _output(
            "Analysing contracts...",
            "Running tests...",
            '{"test/Example.t.sol":{"ExampleTest":{"testOne()":{"status":"Success"}}}}',
            "Uncovered for src/Example.sol:",
            f"- {_descriptor('Line', start_byte=40, end_byte=80)}",
            f'- Function "run" {_descriptor("Line", start_byte=40, end_byte=80)[5:]}',
            f"- {outer}",
            f"- {inner_unanchored}",
            "- Branch (branch: 0, path: 1) "
            "(location: source ID 1, lines 4..5, bytes 40..80, hits: 0)",
            "",
            'Anchors for Contract "Example" (solc 0.8.24, source ID 1):',
            *_anchor(7, outer),
            *_anchor(8, covered_nested, instruction=10),
            "",
            'Anchors for Contract "InheritedExample" (solc 0.8.24, source ID 1):',
            *_anchor(7, outer, instruction=99),
            "",
            'Anchors for Contract "EmptyInterface" (solc 0.8.24, source ID 1):',
            "",
            "Wrote LCOV report.",
        )
    )

    assert isinstance(parsed, ForgeDebugStatementCoverage)
    assert parsed.machine_json_bytes.startswith(b'{"test/Example.t.sol"')
    assert parsed.uncovered_sources == (
        ForgeDebugUncoveredSource(source_id=1, path="src/Example.sol"),
    )
    assert parsed.anchored_item_count == 2
    assert parsed.descriptor_record_count == 8
    assert tuple(statement.identity for statement in parsed.statements) == (
        (1, 40, 80, 4, 5),
        (1, 48, 70, 4, 5),
        (1, 52, 64, 4, 5),
    )
    assert tuple(statement.hits for statement in parsed.statements) == (0, 0, 3)
    assert tuple(statement.item_ids for statement in parsed.statements) == ((7,), (), (8,))
    assert parsed.statements[2].covered is True
    expected_inventory = (
        b'[{"end_byte":80,"end_line":5,"source_id":1,"start_byte":40,"start_line":4},'
        b'{"end_byte":70,"end_line":5,"source_id":1,"start_byte":48,"start_line":4},'
        b'{"end_byte":64,"end_line":5,"source_id":1,"start_byte":52,"start_line":4}]\n'
    )
    assert parsed.canonical_inventory_bytes() == expected_inventory
    assert parsed.statement_inventory_sha256 == hashlib.sha256(expected_inventory).hexdigest()


def test_parser_accepts_json_then_anchor_without_progress_or_uncovered_sections() -> None:
    statement = _descriptor("Statement", source_id=0, hits=2)

    parsed = parse_forge_debug_statement_coverage(
        _output(
            "{}",
            'Anchors for Contract "Example" (solc 0.8.24+commit.e11b9ed9, source ID 0):',
            *_anchor(0, statement),
        )
    )

    assert parsed.machine_json_bytes == b"{}"
    assert parsed.statements == (
        ForgeDebugStatementRecord(
            source_id=0,
            start_byte=40,
            end_byte=60,
            start_line=4,
            end_line=5,
            hits=2,
            item_ids=(0,),
        ),
    )


def test_parser_accepts_empty_uncovered_section_emitted_for_fully_covered_source() -> None:
    parsed = parse_forge_debug_statement_coverage(
        _output(
            "{}",
            "Uncovered for test/Example.t.sol:",
            "",
            'Anchors for Contract "ExampleTest" (solc 0.8.24, source ID 2):',
        )
    )

    assert parsed.uncovered_sources == ()
    assert parsed.statements == ()


@pytest.mark.parametrize(
    "raw,error",
    [
        (b"", "empty"),
        (b"{}", "end with LF"),
        (b"{}\r\n", "LF line endings"),
        (b"{\xff}\n", "UTF-8"),
        (_output("Analysing contracts...", "{}"), "preamble"),
        (_output("", "{}"), "JSON object"),
    ],
)
def test_parser_rejects_invalid_byte_envelopes(raw: bytes, error: str) -> None:
    with pytest.raises(FoundryStatementCoverageError, match=error):
        parse_forge_debug_statement_coverage(raw)


@pytest.mark.parametrize(
    "machine_line",
    [
        "[]",
        "null",
        '{"duplicate":1,"duplicate":2}',
        '{"nonstandard":NaN}',
        " {}",
        "{} ",
        "{} trailing",
    ],
)
def test_parser_requires_one_strict_json_object_line(machine_line: str) -> None:
    with pytest.raises(FoundryStatementCoverageError, match="JSON object"):
        parse_forge_debug_statement_coverage(_output(machine_line))


def test_parser_allows_bounded_large_machine_json_but_not_large_debug_records() -> None:
    parsed = parse_forge_debug_statement_coverage(_output('{"log":"' + ("x" * 20_000) + '"}'))
    assert len(parsed.machine_json_bytes) > 16_384

    with pytest.raises(FoundryStatementCoverageError, match="record exceeds"):
        parse_forge_debug_statement_coverage(_output("{}", "Uncovered for " + ("x" * 20_000) + ":"))


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
def test_parser_rejects_unsafe_or_noncanonical_uncovered_paths(path: str) -> None:
    with pytest.raises(FoundryStatementCoverageError, match="coverage path"):
        parse_forge_debug_statement_coverage(
            _output(
                "{}",
                f"Uncovered for {path}:",
                f"- {_descriptor('Statement')}",
            )
        )


@pytest.mark.parametrize(
    "descriptor,error",
    [
        (_descriptor("Statement", hits=1), "exactly zero hits"),
        (
            "Statement (location: source ID 01, lines 4..5, bytes 40..60, hits: 0)",
            "canonical nonnegative integer",
        ),
        (_descriptor("Statement", start_byte=60, end_byte=60), "half-open"),
        (_descriptor("Statement", start_line=5, end_line=4), "half-open"),
        (_descriptor("Expression"), "malformed or unsupported"),
    ],
)
def test_parser_rejects_invalid_uncovered_descriptors(descriptor: str, error: str) -> None:
    with pytest.raises(FoundryStatementCoverageError, match=error):
        parse_forge_debug_statement_coverage(
            _output("{}", "Uncovered for src/A.sol:", f"- {descriptor}")
        )


def test_parser_rejects_uncovered_section_that_mixes_source_ids() -> None:
    with pytest.raises(FoundryStatementCoverageError, match="mixes multiple source IDs"):
        parse_forge_debug_statement_coverage(
            _output(
                "{}",
                "Uncovered for src/A.sol:",
                f"- {_descriptor('Statement', source_id=1)}",
                f"- {_descriptor('Statement', source_id=2, start_byte=70, end_byte=80)}",
            )
        )


def test_parser_rejects_non_one_to_one_source_path_bindings() -> None:
    with pytest.raises(FoundryStatementCoverageError, match="one-to-one"):
        parse_forge_debug_statement_coverage(
            _output(
                "{}",
                "Uncovered for src/A.sol:",
                f"- {_descriptor('Statement', source_id=1)}",
                "",
                "Uncovered for src/B.sol:",
                f"- {_descriptor('Statement', source_id=1, start_byte=70, end_byte=80)}",
            )
        )


def test_parser_rejects_anchor_source_id_mismatch_and_incomplete_triples() -> None:
    with pytest.raises(FoundryStatementCoverageError, match="source ID disagrees"):
        parse_forge_debug_statement_coverage(
            _output(
                "{}",
                'Anchors for Contract "A" (solc 0.8.24, source ID 1):',
                *_anchor(1, _descriptor("Statement", source_id=2)),
            )
        )

    with pytest.raises(FoundryStatementCoverageError, match="code-mode"):
        parse_forge_debug_statement_coverage(
            _output(
                "{}",
                'Anchors for Contract "A" (solc 0.8.24, source ID 1):',
                "- IC 1 -> Item 1",
                "  - Refers to item: " + _descriptor("Statement"),
            )
        )


def test_parser_rejects_reused_item_id_with_conflicting_descriptor() -> None:
    first = _descriptor("Statement", hits=1)
    second = _descriptor("Statement", start_byte=41, end_byte=60, hits=1)

    with pytest.raises(FoundryStatementCoverageError, match="reused Forge item ID"):
        parse_forge_debug_statement_coverage(
            _output(
                "{}",
                'Anchors for Contract "A" (solc 0.8.24, source ID 1):',
                *_anchor(7, first),
                "",
                'Anchors for Contract "B" (solc 0.8.24, source ID 1):',
                *_anchor(7, second),
            )
        )


def test_parser_rejects_conflicting_hits_for_one_physical_statement() -> None:
    with pytest.raises(FoundryStatementCoverageError, match="conflicting hit counts"):
        parse_forge_debug_statement_coverage(
            _output(
                "{}",
                'Anchors for Contract "A" (solc 0.8.24, source ID 1):',
                *_anchor(7, _descriptor("Statement", hits=1)),
                *_anchor(8, _descriptor("Statement", hits=2), instruction=6),
            )
        )


def test_parser_deduplicates_identical_physical_statements_and_collects_item_ids() -> None:
    descriptor = _descriptor("Statement", hits=2)
    parsed = parse_forge_debug_statement_coverage(
        _output(
            "{}",
            'Anchors for Contract "A" (solc 0.8.24, source ID 1):',
            *_anchor(9, descriptor),
            *_anchor(7, descriptor, instruction=6),
        )
    )

    assert len(parsed.statements) == 1
    assert parsed.statements[0].item_ids == (7, 9)
    assert parsed.anchored_item_count == 2


def test_parser_enforces_configured_byte_record_item_and_statement_bounds() -> None:
    minimal = _output("{}")
    with pytest.raises(FoundryStatementCoverageError, match="configured byte limit"):
        parse_forge_debug_statement_coverage(minimal, max_bytes=len(minimal) - 1)
    with pytest.raises(FoundryStatementCoverageError, match="max_bytes"):
        parse_forge_debug_statement_coverage(minimal, max_bytes=MAX_FORGE_DEBUG_BYTES + 1)

    anchored = _output(
        "{}",
        'Anchors for Contract "A" (solc 0.8.24, source ID 1):',
        *_anchor(1, _descriptor("Statement")),
        *_anchor(2, _descriptor("Line"), instruction=6),
    )
    with pytest.raises(FoundryStatementCoverageError, match="item count"):
        parse_forge_debug_statement_coverage(anchored, max_items=1)

    two_statements = _output(
        "{}",
        'Anchors for Contract "A" (solc 0.8.24, source ID 1):',
        *_anchor(1, _descriptor("Statement")),
        *_anchor(
            2,
            _descriptor("Statement", start_byte=70, end_byte=80),
            instruction=6,
        ),
    )
    with pytest.raises(FoundryStatementCoverageError, match="statement count"):
        parse_forge_debug_statement_coverage(two_statements, max_statements=1)


def test_public_value_constructors_preserve_parser_invariants() -> None:
    with pytest.raises(FoundryStatementCoverageError, match="half-open"):
        ForgeDebugStatementRecord(
            source_id=0,
            start_byte=4,
            end_byte=4,
            start_line=1,
            end_line=2,
            hits=0,
        )
    with pytest.raises(FoundryStatementCoverageError, match="canonically sorted"):
        ForgeDebugStatementRecord(
            source_id=0,
            start_byte=4,
            end_byte=5,
            start_line=1,
            end_line=2,
            hits=0,
            item_ids=(2, 1),
        )
    with pytest.raises(FoundryStatementCoverageError, match="coverage path"):
        ForgeDebugUncoveredSource(source_id=0, path="../A.sol")


def test_parser_rejects_noncanonical_blank_and_trailing_records() -> None:
    with pytest.raises(FoundryStatementCoverageError, match="consecutive blank"):
        parse_forge_debug_statement_coverage(_output("{}", "", "", "Wrote LCOV report."))
    with pytest.raises(FoundryStatementCoverageError, match="must be final"):
        parse_forge_debug_statement_coverage(_output("{}", "Wrote LCOV report.", "ignored"))
