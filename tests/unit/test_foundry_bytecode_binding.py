"""Synthetic compiler/report identities; no execution, source-line or audit authority."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import Any

import pytest

import mmaudit.scanners.foundry_statement_coverage as coverage
from mmaudit.scanners.foundry_statement_coverage import (
    FoundryStatementCoverageError,
    parse_solc_bytecode_source_map,
    reconcile_forge_bytecode_report,
)

CREATION = bytes.fromhex("60805000deadbeef")
RUNTIME = bytes.fromhex("5f5000aabb")
CREATION_MAP = "0:2:0:-:0;;2:3"
RUNTIME_MAP = "8:2:0:-:0;;10:3::i:1"
PATHS = ((0, "src/Control.sol"),)


def report(*, runtime: bool = False, runtime_spans: bool = False) -> bytes:
    opcode = "PUSH0" if runtime else "PUSH1 0x80"
    second, third = (1, 2) if runtime else (2, 3)
    first_span, last_span = ("8-10", "10-13") if runtime_spans else ("0-2", "2-5")
    return (
        f"[001] 00000000: {opcode} // src/Control.sol: 1:1-1:3 ({first_span})\n"
        f"[000] {second:08x}: POP // src/Control.sol: 1:1-1:3 ({first_span})\n"
        f"      {third:08x}: STOP // src/Control.sol: 1:3-1:6 ({last_span})\n"
    ).encode()


def bind(raw: bytes | None = None, **updates: Any) -> coverage.ForgeBytecodeReportBinding:
    inputs: dict[str, Any] = dict(
        creation_bytecode=CREATION,
        creation_source_map=CREATION_MAP,
        runtime_bytecode=RUNTIME,
        runtime_source_map=RUNTIME_MAP,
        source_paths=PATHS,
    )
    inputs.update(updates)
    return reconcile_forge_bytecode_report(report() if raw is None else raw, **inputs)


@pytest.mark.parametrize("runtime", [False, True])
def test_exact_compiler_phase_keeps_raw_hashes_all_rows_and_unmapped_tail(runtime: bool) -> None:
    raw = report(runtime=runtime, runtime_spans=runtime)
    bound = bind(raw)
    phase = "RUNTIME" if runtime else "CREATION"
    assert bound.require_consistent_phase() == phase
    assert bound.instruction_phases == bound.source_map_phases == (phase,)
    assert bound.report_sha256 == hashlib.sha256(raw).hexdigest()
    assert bound.source_paths == PATHS
    assert (
        len(bound.rows) == len(bound.creation.instructions) == len(bound.runtime.instructions) == 3
    )
    assert [r.hits for r in bound.rows] == [1, 0, 0]
    assert bound.creation.bytecode_sha256 == hashlib.sha256(CREATION).hexdigest()
    assert bound.creation.source_map_sha256 == hashlib.sha256(CREATION_MAP.encode()).hexdigest()
    assert bound.creation.bytecode_bytes == len(CREATION)
    assert bound.creation.unmapped_bytecode == bytes.fromhex("deadbeef")
    assert bound.runtime.unmapped_bytecode == bytes.fromhex("aabb")
    assert bound.runtime.instructions[-1].modifier_depth == 1
    assert bound.runtime.instructions[-1].jump == "i"
    # Displayed source line/columns remain raw observations, never verified lines.
    assert bound.rows[0].reported_line_columns == (1, 1, 1, 3)
    assert not hasattr(bound, "covered") and not hasattr(bound, "execution_validated")


def test_mixed_phase_cannot_gain_a_consistent_binding_from_overlapping_source_spans() -> None:
    bound = bind(report(runtime_spans=True))
    assert bound.instruction_phases == ("CREATION",)
    assert bound.source_map_phases == ("RUNTIME",)
    with pytest.raises(FoundryStatementCoverageError, match="one consistent"):
        bound.require_consistent_phase()


def test_source_map_population_is_never_truncated_to_match_report_prefix() -> None:
    bound = bind(b"\n".join(report().splitlines()[:2]) + b"\n")
    assert bound.instruction_phases == ("CREATION",)
    assert not bound.source_map_phases
    assert len(bound.creation.instructions) == 3 and len(bound.rows) == 2
    with pytest.raises(FoundryStatementCoverageError, match="one consistent"):
        bound.require_consistent_phase()


def test_identical_compiler_phases_remain_ambiguous_and_hits_do_not_resolve_them() -> None:
    bound = bind(runtime_bytecode=CREATION, runtime_source_map=CREATION_MAP)
    assert bound.instruction_phases == bound.source_map_phases == ("CREATION", "RUNTIME")
    with pytest.raises(FoundryStatementCoverageError, match="one consistent"):
        bound.require_consistent_phase()


@pytest.mark.parametrize("mutation", ["operand", "opcode", "source", "source_id"])
def test_single_changed_operand_opcode_or_source_identity_is_not_a_binding(mutation: str) -> None:
    raw = report()
    options: dict[str, Any] = {}
    if mutation == "operand":
        raw = raw.replace(b"PUSH1 0x80", b"PUSH1 0x81")
    elif mutation == "opcode":
        raw = raw.replace(b"POP", b"MLOAD")
    elif mutation == "source":
        raw = raw.replace(b"(2-5)", b"(2-6)")
    else:
        options["source_paths"] = ((1, "src/Control.sol"),)
    bound = bind(raw, **options)
    with pytest.raises(FoundryStatementCoverageError, match="one consistent"):
        bound.require_consistent_phase()


def test_source_map_inheritance_push_width_jumps_and_depth_are_exact() -> None:
    mapped = parse_solc_bytecode_source_map(
        bytes.fromhex("6100035b6050605b5000"),
        "1:2:0:i:0;:::-;3:4:::1;;::1:o:2;:::-:0",
    )
    assert [r.pc for r in mapped.instructions] == [0, 3, 4, 6, 8, 9]
    assert [r.push_data for r in mapped.instructions] == [b"\0\3", b"", b"P", b"[", b"", b""]
    assert [r.modifier_depth for r in mapped.instructions] == [0, 0, 1, 1, 2, 0]
    assert [r.jump for r in mapped.instructions] == ["i", "-", "-", "-", "o", "-"]
    assert mapped.instructions[-1].source_identity == (1, 3, 7)
    assert mapped.unmapped_bytecode == b""


def test_generated_and_unknown_source_locations_do_not_become_supplied_source_spans() -> None:
    raw = b"[001] 00000000: PUSH0 // SRCID2: (4-8)\n      00000001: STOP\n"
    bound = bind(raw, creation_bytecode=b"\x5f\x00", creation_source_map="4:4:2;-1:-1:-1")
    assert bound.require_consistent_phase() == "CREATION"
    assert bound.rows[0].source_identity == (2, 4, 8)
    assert bound.rows[1].source_identity is None
    assert bound.creation.instructions[1].source_identity is None
    assert all(r.reported_line_columns is None for r in bound.rows)


@pytest.mark.parametrize(
    "source_map",
    [
        "",
        "x",
        "0:1:0:x",
        "0:1:0:-:-1",
        "0:1:0:-:0:extra",
        "-2:1:0",
        "0:-1:0",
        "-1:1:0",
        "00:1:0",
        "+1:1:0",
        "0:1:0\n",
        "0:1:0\r",
        "0:1:0:🧪",
        "0:1:0:-:01",
        "9223372036854775808:1:0",
        "9223372036854775807:1:0",
        "0:1:0;-1:-1:-1;;",
    ],
)
def test_malformed_overflowing_or_excess_source_map_is_refused(source_map: str) -> None:
    with pytest.raises(FoundryStatementCoverageError):
        parse_solc_bytecode_source_map(b"\x00\x00\x00", source_map)


@pytest.mark.parametrize("bytecode", [b"", b"\x60", b"\x61\x01", "00", True, bytearray(b"\0")])
def test_compiler_bytecode_must_be_exact_bytes_with_complete_mapped_operands(bytecode: Any) -> None:
    with pytest.raises(FoundryStatementCoverageError):
        parse_solc_bytecode_source_map(bytecode, "0:1:0")


@pytest.mark.parametrize("source_map", [None, True, 0, b"0:1:0"])
def test_source_map_must_be_exact_text(source_map: Any) -> None:
    with pytest.raises(FoundryStatementCoverageError):
        parse_solc_bytecode_source_map(b"\0", source_map)


@pytest.mark.parametrize(
    "old,new",
    [
        (b"[001]", b"[1]"),
        (b"[001]", b"[9223372036854775808]"),
        (b"[001]", b"[-001]"),
        (b"00000002", b"00000001"),
        (b"00000003", b"00000002"),
        (b"PUSH1 0x80", b"PUSH1 0x100"),
        (b"PUSH1 0x80", b"PUSH1"),
        (b"PUSH1 0x80", b"PUSH0 0x80"),
        (b"PUSH1 0x80", b"PUSH33 0x80"),
        (b"PUSH1 0x80", b"PUSH1 0x080"),
        (b"PUSH1 0x80", b"FUTUREOP"),
        (b"POP", b"POP 0x01"),
        (b"src/Control.sol", b"src/Unselected.sol"),
        (b"src/Control.sol: 1:1-1:3", b"SRCID0:"),
        (b"1:1-1:3", b"1:0-1:3"),
        (b"1:1-1:3", b"2:1-1:3"),
        (b"(2-5)", b"(6-5)"),
        (b"(2-5)", b"(2-9223372036854775808)"),
        (b"\n", b"\r\n"),
        (b"POP", b"\xff"),
    ],
)
def test_malformed_report_records_are_refused(old: bytes, new: bytes) -> None:
    with pytest.raises(FoundryStatementCoverageError):
        bind(report().replace(old, new))


@pytest.mark.parametrize("raw", [b"", b"\n", b" ", "report", bytearray(b"report\n"), None])
def test_report_must_be_nonempty_exact_lf_bytes(raw: Any) -> None:
    with pytest.raises(FoundryStatementCoverageError):
        reconcile_forge_bytecode_report(
            raw,
            creation_bytecode=CREATION,
            creation_source_map=CREATION_MAP,
            runtime_bytecode=RUNTIME,
            runtime_source_map=RUNTIME_MAP,
            source_paths=PATHS,
        )


@pytest.mark.parametrize(
    "paths",
    [
        (),
        [],
        ((True, "src/Control.sol"),),
        ((-1, "src/Control.sol"),),
        ((0, "../Control.sol"),),
        ((0, "src/Control.sol"), (0, "other.sol")),
        ((0, "src/Control.sol"), (1, "src/Control.sol")),
        ((1, "other.sol"), (0, "src/Control.sol")),
        ((0,),),
        ([0, "src/Control.sol"],),
    ],
)
def test_source_binding_requires_canonical_unique_paths_and_ids(paths: Any) -> None:
    with pytest.raises(FoundryStatementCoverageError):
        bind(source_paths=paths)


def test_parser_limits_are_inclusive_and_cannot_allow_partial_populations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(coverage, "_MAX_BYTECODE_BYTES", len(CREATION))
    monkeypatch.setattr(coverage, "_MAX_SOURCE_MAP_BYTES", len(RUNTIME_MAP))
    monkeypatch.setattr(coverage, "_MAX_BYTECODE_ROWS", 3)
    monkeypatch.setattr(coverage, "MAX_FORGE_DEBUG_BYTES", len(report()))
    assert bind().require_consistent_phase() == "CREATION"
    for updates in (
        {"creation_bytecode": CREATION + b"\0"},
        {"runtime_source_map": RUNTIME_MAP + ";"},
    ):
        with pytest.raises(FoundryStatementCoverageError):
            bind(**updates)
    with pytest.raises(FoundryStatementCoverageError):
        bind(report() + b"\n")
    monkeypatch.setattr(coverage, "_MAX_BYTECODE_ROWS", 2)
    with pytest.raises(FoundryStatementCoverageError):
        bind()


def test_report_hits_and_line_columns_are_not_promoted_to_verified_execution() -> None:
    base = bind()
    changed = bind(report().replace(b"[001]", b"[999]").replace(b"1:1-1:3", b"9:1-9:3"))
    assert changed.report_sha256 != base.report_sha256
    assert changed.require_consistent_phase() == base.require_consistent_phase()
    assert changed.rows[0].hits == 999
    assert changed.rows[0].reported_line_columns == (9, 1, 9, 3)
    # Binding explicitly promises only instruction/source-map identity, not execution.
    assert replace(changed, rows=base.rows).report_sha256 == changed.report_sha256
