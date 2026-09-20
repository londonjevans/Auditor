"""Synthetic original/compiler byte relations; no execution or authority is inferred."""

from __future__ import annotations

import copy
import hashlib
import json
import socket
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any, NoReturn

import pytest

from mmaudit.benchmark.mutation_discovery import (
    PortfolioMutationDiscovery,
    discover_portfolio_mutations,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.scanners import foundry_inventory as inventory
from mmaudit.scanners import foundry_statement_producer as producer
from mmaudit.solidity import compiler_source as maps
from tests.property_reachability_support import SOURCE, retained_guard_fixture


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        pytest.fail("compiler source binding attempted network or process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def parser_case(*, mixed: bool = False) -> tuple[Any, dict[str, Any]]:
    original = retained_guard_fixture()
    snapshot = original.compiler_inputs[0]
    sources = []
    for source in snapshot.sources:
        # Independently supplied synthetic original bytes; raw native LF compiler
        # inputs are unchanged. Native CRLF writer custody is tested separately.
        raw = b"".join(
            line.replace(b"\n", b"\r\n") if not mixed or index % 2 == 0 else line
            for index, line in enumerate(source.content.splitlines(keepends=True))
        )
        sources.append(replace(source, content=raw, source_sha256=hashlib.sha256(raw).hexdigest()))
    return original, dict(
        build_info_jsons=snapshot.build_info_jsons,
        sources=tuple(sources),
        project_root=".",
        compiler_version=original.evidence.compiler_version,
        compiler_sha256=original.evidence.compiler_sha256,
        limits=snapshot.parser_limits,
    )


@pytest.mark.parametrize("raw", [b"", b"one\n", b"one\r\ntwo\n", "Ω\r\n𐐀".encode()])
def test_exact_identity_has_no_mapping_metadata_and_preserves_boundaries(raw: bytes) -> None:
    mapping = maps.CompilerSourceMap(raw, raw)
    assert mapping.transformation is None
    assert mapping.original_span(0, len(raw)) == mapping.compiled_span(0, len(raw)) == (0, len(raw))


@pytest.mark.parametrize("original", [b"\r\n", b"a\r\nb\n\r\nc", "Ω\r\n𐐀\nend\r\n".encode()])
def test_every_representable_boundary_round_trips_without_splitting_utf8_or_crlf(
    original: bytes,
) -> None:
    compiled = original.replace(b"\r\n", b"\n")
    mapping = maps.CompilerSourceMap(original, compiled)
    assert mapping.transformation is not None
    boundaries = [
        i for i in range(len(compiled) + 1) if i == len(compiled) or compiled[i] & 192 != 128
    ]
    represented: set[int] = set()
    for start in boundaries:
        for end in boundaries:
            if end < start:
                continue
            a, b = mapping.original_span(start, end)
            assert mapping.compiled_span(a, b) == (start, end)
            assert original[a:b].replace(b"\r\n", b"\n") == compiled[start:end]
            represented.update((a, b))
    for offset in range(len(original) + 1):
        if offset not in represented:
            with pytest.raises(ValueError, match=r"boundary|CRLF"):
                mapping.compiled_span(offset, offset)
    assert mapping.original == original and mapping.compiled == compiled


@pytest.mark.parametrize(
    ("original", "compiled"),
    [
        (b"a\r\nb\r\n", b"a\nb\r\n"),
        (b"a\nb\n", b"a\r\nb\r\n"),
        (b"a\rb", b"a\nb"),
        (b"a \r\nb", b"a\nb"),
        (b"a\r\nb", b"a\nb\n"),
        (b"a\r\nb", b"b\na"),
        (b"a\r\nb", b"a\n"),
    ],
)
def test_unknown_or_partial_source_rewrites_refuse(original: bytes, compiled: bytes) -> None:
    with pytest.raises(ValueError, match="unrecognized transformation"):
        maps.CompilerSourceMap(original, compiled)


@pytest.mark.parametrize("value", [bytearray(b"a"), "a", None, True])
def test_source_maps_require_exact_immutable_bytes(value: Any) -> None:
    with pytest.raises(ValueError, match="immutable bytes"):
        maps.CompilerSourceMap(value, b"a")


@pytest.mark.parametrize("start,end", [(-1, 1), (2, 1), (0, 9), (True, 1), (0, False), (0.0, 1)])
def test_invalid_or_coerced_offsets_refuse(start: Any, end: Any) -> None:
    mapping = maps.CompilerSourceMap(b"a\r\nb", b"a\nb")
    for method in (mapping.original_span, mapping.compiled_span):
        with pytest.raises(ValueError, match="bounds"):
            method(start, end)


@pytest.mark.parametrize("raw", [b"\xff", b"\xc3\r\n", b"\xe2\x82"])
def test_invalid_utf8_refuses_before_mapping(raw: bytes) -> None:
    with pytest.raises(UnicodeError):
        maps.CompilerSourceMap(raw, raw.replace(b"\r\n", b"\n"))


def test_map_bounds_and_deterministic_digest_without_io(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        pytest.fail("pure source map accessed a path")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(maps, "MAX_COMPILER_SOURCE_BYTES", 8)
    monkeypatch.setattr(maps, "MAX_COMPILER_SOURCE_CRLF_PAIRS", 2)
    mapped = maps.CompilerSourceMap(b"a\r\nb\r\nc", b"a\nb\nc")
    assert mapped.transformation is not None
    assert (
        mapped.transformation.boundary_map_sha256
        == hashlib.sha256(
            b"mmaudit.compiler-source-boundaries.CRLF_TO_LF_V1\x00"
            + (1).to_bytes(8, "big")
            + (3).to_bytes(8, "big")
        ).hexdigest()
    )
    with pytest.raises(ValueError, match="bounded immutable"):
        maps.CompilerSourceMap(b"a" * 9, b"a" * 9)
    with pytest.raises(ValueError, match="newline bound"):
        maps.CompilerSourceMap(b"\r\n" * 3, b"\n" * 3)


@pytest.mark.parametrize("mixed", [False, True])
def test_original_source_catalog_and_debug_compiler_spans_remain_exact(mixed: bool) -> None:
    original, kwargs = parser_case(mixed=mixed)
    catalog = inventory.parse_foundry_compiler_statement_catalog(**kwargs)
    parsed = inventory.parse_foundry_test_inventory(
        forge_list_json=original.compiler_inputs[0].forge_list_json, **kwargs
    )
    assert inventory.compiler_catalog_source_bindings(catalog) == parsed.sources
    producer._validate_catalog_structure(catalog, "synthetic mapped source")
    unit, prior = catalog.units[0], original.statement_catalogs[0].units[0]
    sources = {s.path: s for s in unit.sources}
    for source in parsed.sources:
        assert len(source.compiler_source_bindings) == 1
        binding = source.compiler_source_bindings[0]
        assert binding.transformation.original_sha256 == source.source_sha256
        assert binding.build_info_sha256 == unit.normalized_build_info_sha256
    records: tuple[inventory.FoundryCompilerEntity | inventory.FoundryCompilerStatement, ...] = (
        *unit.entities,
        *unit.statements,
    )
    previous: tuple[inventory.FoundryCompilerEntity | inventory.FoundryCompilerStatement, ...] = (
        *prior.entities,
        *prior.statements,
    )
    for item, old in zip(records, previous, strict=True):
        mapping = sources[item.path].source_mapping
        assert mapping is not None
        assert (item.compiler_start_byte, item.compiler_end_byte_exclusive) == (
            old.start_byte,
            old.end_byte_exclusive,
        )
        assert (item.start_byte, item.end_byte_exclusive) == mapping.original_span(
            old.start_byte, old.end_byte_exclusive
        )
        assert (
            item.start_line == old.start_line and item.end_line_exclusive == old.end_line_exclusive
        )
    for item, old in zip(unit.statements, prior.statements, strict=True):
        physical = producer._PhysicalStatement(".", item.path, unit, item)
        assert physical.debug_identity == (
            old.source_id,
            old.start_byte,
            old.end_byte_exclusive,
            old.start_line,
            old.end_line_exclusive,
        )
        assert physical.source_key == (
            item.path,
            item.source_sha256,
            item.start_byte,
            item.end_byte_exclusive,
        )
    for test, old in zip(parsed.tests, original.inventories[0].tests, strict=True):
        assert (test.start_line, test.end_line) == (old.start_line, old.end_line)
        assert test.source_sha256 == sources[test.declaration_path].source_sha256
    # No original raw compiler input or source population was edited.
    assert kwargs["build_info_jsons"] == original.compiler_inputs[0].build_info_jsons


@pytest.mark.parametrize("kind", ["entity", "statement"])
@pytest.mark.parametrize("change", ["omitted", "shifted", "boolean", "original-shift"])
def test_statement_consumer_refuses_mapped_span_omission_or_drift(kind: str, change: str) -> None:
    _, kwargs = parser_case()
    catalog = inventory.parse_foundry_compiler_statement_catalog(**kwargs)
    unit = catalog.units[0]
    field = "entities" if kind == "entity" else "statements"
    items = list(getattr(unit, field))
    item = items[0]
    assert item.compiler_start_byte is not None
    update = {
        "omitted": {"compiler_start_byte": None, "compiler_end_byte_exclusive": None},
        "shifted": {"compiler_start_byte": item.compiler_start_byte + 1},
        "boolean": {"compiler_start_byte": False},
        "original-shift": {"start_byte": item.start_byte + 1},
    }[change]
    items[0] = replace(item, **update)
    changes: dict[str, Any] = {field: tuple(items)}
    altered = replace(catalog, units=(replace(unit, **changes),))
    with pytest.raises(producer.FoundryStatementCoverageProductionError):
        producer._validate_catalog_structure(altered, "synthetic altered source")


def test_statement_consumer_refuses_forged_mapping_and_identity_with_mapping_spans() -> None:
    original, kwargs = parser_case()
    catalog = inventory.parse_foundry_compiler_statement_catalog(**kwargs)
    unit = catalog.units[0]
    source = unit.sources[0]
    assert source.source_mapping is not None
    mapping = copy.deepcopy(source.source_mapping)
    object.__setattr__(mapping, "_removed_compiler_offsets", ())
    altered = replace(unit, sources=(replace(source, source_mapping=mapping), *unit.sources[1:]))
    with pytest.raises(producer.FoundryStatementCoverageProductionError, match="source mapping"):
        producer._validate_catalog_structure(replace(catalog, units=(altered,)), "forged")
    prior = original.statement_catalogs[0].units[0]
    altered = replace(
        prior, entities=(replace(prior.entities[0], compiler_start_byte=0), *prior.entities[1:])
    )
    with pytest.raises(producer.FoundryStatementCoverageProductionError, match="byte spans"):
        producer._validate_catalog_structure(replace(catalog, units=(altered,)), "identity")


def test_cumulative_transformed_newline_bound_is_not_reset_per_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original, kwargs = parser_case()
    count = sum(s.content.count(b"\r\n") for s in kwargs["sources"])
    monkeypatch.setattr(inventory, "MAX_COMPILER_SOURCE_CRLF_PAIRS", count)
    inventory.parse_foundry_compiler_statement_catalog(**kwargs)
    duplicate_build = kwargs["build_info_jsons"][0] + b" "
    kwargs["build_info_jsons"] = (*kwargs["build_info_jsons"], duplicate_build)
    with pytest.raises(inventory.FoundryInventoryError, match="newline bound"):
        inventory.parse_foundry_compiler_statement_catalog(**kwargs)
    with pytest.raises(inventory.FoundryInventoryError, match="newline bound"):
        inventory.parse_foundry_test_inventory(
            forge_list_json=original.compiler_inputs[0].forge_list_json, **kwargs
        )


@pytest.mark.parametrize(
    "change", ["source-id", "foreign-build", "original-hash", "original-size", "duplicate"]
)
def test_discovery_metadata_cannot_substitute_source_or_build_identity(change: str) -> None:
    _, kwargs = parser_case(mixed=True)
    bounds = kwargs.pop("limits")
    discovery = discover_portfolio_mutations(
        **kwargs, inventory_limits=bounds, target_paths=(SOURCE,)
    )
    raw = discovery.model_dump(mode="json")
    source = next(s for s in raw["sources"] if s["path"] == SOURCE)
    binding = source["compiler_source_bindings"][0]
    if change == "source-id":
        binding["source_id"] += 10_000
    elif change == "foreign-build":
        binding["build_info_sha256"] = "a" * 64
    elif change == "original-hash":
        binding["transformation"]["original_sha256"] = "b" * 64
    elif change == "original-size":
        binding["transformation"]["original_size_bytes"] += 1
        binding["transformation"]["compiler_size_bytes"] += 1
    else:
        source["compiler_source_bindings"].append(copy.deepcopy(binding))
    raw["discovery_sha256"] = canonical_sha256(
        {k: v for k, v in raw.items() if k != "discovery_sha256"}
    )
    with pytest.raises(ValueError):
        PortfolioMutationDiscovery.model_validate(raw)


def test_identity_source_retains_original_native_inventory_digest_and_serialization() -> None:
    original = retained_guard_fixture()
    parsed = original.inventories[0]
    assert parsed.inventory_sha256 == original.evidence.projects[0].parser_inventory_sha256
    assert all(not s.compiler_source_bindings for s in parsed.sources)
    assert "compiler_source_bindings" not in parsed.model_dump_json()
    assert json.loads(parsed.model_dump_json()) == parsed.model_dump(mode="json")
