"""Static closure is earned from complete synthetic sources, never from an asserted flag."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from mmaudit.models.development_corpus import (
    freeze_development_corpus,
    render_development_corpus_sources,
)
from mmaudit.models.schemas import SolidityEntityKind, SolidityGraphKind, SolidityProvenance
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.solidity import dependency_closure as closure
from mmaudit.solidity import dependency_static_closure as static
from mmaudit.solidity.dependency_closure import DependencyGraphFact, DevelopmentDependencyClosure
from mmaudit.solidity.dependency_syntax import DependencySyntaxContext
from tests.unit.test_development_dependency_calls import call_sources, split_call_sources
from tests.unit.test_development_dependency_closure import FIXTURE, fixture_sources
from tests.unit.test_development_dependency_constructors import constructor_sources

LEGACY = Path(__file__).parents[1] / "fixtures/solidity/dependency_call_closure/legacy_replay.json"
FLAGS = {
    "include_target_context": True,
    "include_scoped_context": True,
    "include_call_context": True,
    "include_syntax_context": True,
    "include_modifier_context": True,
    "include_constructor_context": True,
    "include_static_closure": True,
}


def computed(files=None, **kwargs):
    return closure.compute_development_dependency_closure(
        source_files=fixture_sources() if files is None else files,
        **{"remapping_text": (FIXTURE / "remappings.txt").read_text(), **FLAGS, **kwargs},
    )


def changed(path, before, after):
    files = dict(fixture_sources())
    assert before.encode() in files[path]
    files[path] = files[path].replace(before.encode(), after.encode())
    return tuple(sorted(files.items()))


def reasons(witness):
    return {s.reason for s in witness.static_call_closure.shortfalls}


def resign(witness):
    proof = witness["static_call_closure"]
    proof["edges_sha256"] = canonical_sha256(proof["edges"])
    proof["proof_sha256"] = canonical_sha256(
        {k: v for k, v in proof.items() if k != "proof_sha256"}
    )
    witness["witness_sha256"] = canonical_sha256(
        {k: v for k, v in witness.items() if k != "witness_sha256"}
    )
    return json.dumps(witness)


def test_interface_closure_includes_every_supplied_implementation_and_transitive_library():
    witness = computed()
    proof = witness.static_call_closure
    assert (witness.schema_version, witness.dependency_closure) == ("1.7", "CALL_CLOSED")
    assert proof.call_closure == "CALL_CLOSED" and proof.shortfalls == ()
    primary = next(p for p in witness.primaries if p.primary == "src/Controller.sol")
    assert primary.import_members == ("src/Controller.sol", "src/IReserve.sol")
    assert primary.call_members == tuple(p for p, _ in fixture_sources())
    assert primary.call_closure == "CALL_CLOSED" and primary.call_shortfall is None
    assert len(proof.edges) == 15
    assert proof.required_graph_kinds == static.STATIC_CLOSURE_KINDS
    assert proof.minimum_original_graph_confidence == 0.9
    assert proof.original_graph_sha256 == witness.graph_sha256
    assert proof.source_inventory_sha256 == witness.source_inventory_sha256
    assert (
        not proof.runtime_authority
        and not proof.audit_complete
        and not proof.qualification_eligible
    )
    assert not witness.audit_complete and not witness.qualification_eligible
    assert not witness.call_context.complete_static_resolution
    assert not witness.syntax_context.complete_static_resolution
    assert len(proof.call_lines) == len(witness.call_context.calls) == 6
    assert proof.graph_joins == witness.graph_facts == ()
    for row in proof.call_lines:
        call = witness.call_context.calls[row.call_index]
        raw = dict(fixture_sources())[call.source]
        assert row.line_start == raw[: call.byte_start].count(b"\n") + 1
        assert row.line_end == raw[: call.byte_end - 1].count(b"\n") + 1
    assert DevelopmentDependencyClosure.model_validate_json(witness.model_dump_json()) == witness


def test_least_fixed_point_is_deterministic_and_handles_a_supplied_import_cycle():
    files = changed(
        "lib/Math.sol", "pragma solidity", 'import "../src/Controller.sol";\npragma solidity'
    )
    witness = computed(files)
    assert witness.dependency_closure == "CALL_CLOSED"
    assert computed(files).model_dump_json() == witness.model_dump_json()
    proof = witness.static_call_closure
    for primary in proof.primaries:
        expected = {primary.primary}
        while True:
            expanded = expected | {e.target for e in proof.edges if e.source in expected}
            if expanded == expected:
                break
            expected = expanded
        assert primary.members == tuple(sorted(expected))
        assert primary.edge_indices == tuple(
            i for i, e in enumerate(proof.edges) if e.source in expected
        )


@pytest.mark.parametrize("files", [call_sources, split_call_sources, constructor_sources])
def test_original_heuristic_facts_are_not_regraded_when_typed_resolution_succeeds(files):
    witness = computed(files(), remapping_text="")
    assert all(c.resolution == "STATIC_DECLARATIONS_BOUND" for c in witness.call_context.calls)
    assert witness.graph_facts and not witness.syntax_context.gaps
    assert witness.dependency_closure == "NOT_ESTABLISHED"
    assert reasons(witness) >= {
        "ORIGINAL_GRAPH_CONFIDENCE_BELOW_POLICY",
        "ORIGINAL_GRAPH_PROVENANCE_INADEQUATE",
    }
    assert len(witness.static_call_closure.graph_joins) == len(witness.graph_facts)
    for i, fact in enumerate(witness.graph_facts):
        assert fact.confidence < 0.9 and fact.resolution == "NOT_ESTABLISHED"
        join = witness.static_call_closure.graph_joins[i]
        assert join.graph_fact_index == i
        assert "ORIGINAL_GRAPH_CONFIDENCE_BELOW_POLICY" in join.shortfalls
        assert {
            s.reason
            for s in witness.static_call_closure.shortfalls
            if s.population == "GRAPH" and s.evidence_index == i
        } == set(join.shortfalls)


@pytest.mark.parametrize(
    "path,before,after,population",
    [
        ("src/Reserve.sol", "@local/Math.sol", "@missing/Math.sol", "IMPORT"),
        ("src/Controller.sol", "IReserve(reserve).value()", "IReserve(reserve).missing()", "CALL"),
        ("src/Controller.sol", "IReserve(reserve).value()", 'reserve.delegatecall("")', "CALL"),
        ("src/Controller.sol", "IReserve(reserve).value()", 'reserve.call("")', "CALL"),
        ("src/Controller.sol", "IReserve(reserve).value()", "unknown.value()", "CALL"),
        (
            "src/Controller.sol",
            "contract Controller {",
            "contract Controller { assembly {}",
            "SYNTAX",
        ),
        (
            "src/Controller.sol",
            "contract Controller {",
            "contract Controller { using Math for uint256;",
            "SYNTAX",
        ),
        (
            "src/Controller.sol",
            "contract Controller {",
            "contract Controller { mapping(address => uint256) balances;",
            "SYNTAX",
        ),
        (
            "src/Controller.sol",
            "contract Controller {",
            "contract Controller { function() external callback;",
            "SYNTAX",
        ),
        ("src/SecondReserve.sol", "function value()", "function missing()", "CALL"),
        ("src/SecondReserve.sol", "returns (uint256)", "returns (bool)", "CALL"),
        ("src/SecondReserve.sol", "external pure", "private pure", "CALL"),
        ("src/SecondReserve.sol", "{\n        return 1;\n    }", ";", "CALL"),
        ("src/Controller.sol", "pragma solidity ^0.8.20;", "/*", "PARSE"),
    ],
)
def test_unsupported_or_incomplete_source_keeps_exact_blockers(path, before, after, population):
    witness = computed(changed(path, before, after))
    assert witness.dependency_closure == "NOT_ESTABLISHED"
    assert any(s.population == population for s in witness.static_call_closure.shortfalls)
    assert reasons(witness)
    for primary in witness.static_call_closure.primaries:
        assert (primary.call_closure == "CALL_CLOSED") == (not primary.shortfall_indices)


def test_absent_implementers_are_not_an_empty_success_and_bad_remappings_are_global():
    files = tuple(
        (p, raw)
        for p, raw in fixture_sources()
        if p
        not in {
            "src/Reserve.sol",
            "src/SecondReserve.sol",
        }
    )
    witness = computed(files)
    assert witness.dependency_closure == "NOT_ESTABLISHED"
    assert "NO_SUPPLIED_IMPLEMENTER" in reasons(witness)
    bad_mapping = computed(remapping_text="unresolved-rule\n")
    assert any(
        s.population == "REMAP" and s.global_scope
        for s in bad_mapping.static_call_closure.shortfalls
    )
    assert all(p.call_closure == "NOT_ESTABLISHED" for p in bad_mapping.primaries)


@pytest.mark.parametrize(
    "field,value",
    [
        ("minimum_original_graph_confidence", 0.8),
        ("minimum_original_graph_confidence", "0.9"),
        ("policy", "WEAKENED_POLICY"),
        ("required_graph_kinds", []),
        ("runtime_authority", True),
        ("audit_complete", True),
        ("qualification_eligible", True),
        ("runtime_authority", 0),
        ("runtime_authority", "false"),
    ],
)
def test_self_rehash_cannot_change_policy_or_grant_authority(field, value):
    payload = computed().model_dump(mode="json")
    payload["static_call_closure"][field] = value
    with pytest.raises(ValueError):
        DevelopmentDependencyClosure.model_validate_json(resign(payload))


@pytest.mark.parametrize(
    "mutation", ["edge", "member", "status", "line_census", "input_hash", "graph_hash"]
)
def test_self_rehash_cannot_omit_computed_evidence_or_change_a_disposition(mutation):
    payload = computed().model_dump(mode="json")
    proof = payload["static_call_closure"]
    if mutation == "edge":
        proof["edges"].pop()
        for p in proof["primaries"]:
            p["edge_indices"] = [
                i for i, e in enumerate(proof["edges"]) if e["source"] in p["members"]
            ]
    elif mutation == "member":
        p = next(p for p in proof["primaries"] if p["primary"] == "src/Controller.sol")
        p["members"].remove("lib/Math.sol")
        p["edge_indices"] = [i for i, e in enumerate(proof["edges"]) if e["source"] in p["members"]]
        next(p for p in payload["primaries"] if p["primary"] == "src/Controller.sol")[
            "call_members"
        ].remove("lib/Math.sol")
    elif mutation == "status":
        payload["dependency_closure"] = "IMPORT_CLOSED"
    elif mutation == "line_census":
        proof["call_lines"].pop()
    else:
        proof[
            {"input_hash": "closure_inputs_sha256", "graph_hash": "original_graph_sha256"}[mutation]
        ] = "1" * 64
    with pytest.raises(ValueError):
        DevelopmentDependencyClosure.model_validate_json(resign(payload))


def test_coherently_removed_graph_shortfalls_cannot_be_promoted_by_self_hash():
    payload = computed(call_sources(), remapping_text="").model_dump(mode="json")
    proof = payload["static_call_closure"]
    proof["shortfalls"] = []
    proof["call_closure"] = payload["dependency_closure"] = "CALL_CLOSED"
    for p in proof["primaries"]:
        p["shortfall_indices"] = []
        p["call_closure"] = "CALL_CLOSED"
    for p in payload["primaries"]:
        p["call_closure"] = "CALL_CLOSED"
        p["call_shortfall"] = None
    for join in proof["graph_joins"]:
        join["shortfalls"] = []
    with pytest.raises(ValueError, match="composition"):
        DevelopmentDependencyClosure.model_validate_json(resign(payload))


@pytest.mark.parametrize("flag", [1, 0, None, "true", True])
def test_static_flag_requires_strict_boolean_and_complete_predecessor_contexts(flag):
    with pytest.raises(ValueError, match="static closure"):
        computed(include_constructor_context=False, include_static_closure=flag)


@pytest.mark.parametrize(
    "ceiling", ["MAX_STATIC_CLOSURE_WORK", "MAX_STATIC_CLOSURE_BYTES", "MAX_TARGET_RECORDS"]
)
def test_whole_proof_refuses_overflow_without_truncation(monkeypatch, ceiling):
    monkeypatch.setattr(static, ceiling, 1)
    with pytest.raises(ValueError, match="ceiling"):
        computed()


def test_static_proof_byte_ceiling_is_inclusive(monkeypatch):
    original = computed()
    size = len(original.static_call_closure.model_dump_json().encode())
    monkeypatch.setattr(static, "MAX_STATIC_CLOSURE_BYTES", size)
    assert computed() == original
    monkeypatch.setattr(static, "MAX_STATIC_CLOSURE_BYTES", size - 1)
    with pytest.raises(ValueError, match="byte ceiling"):
        computed()


@pytest.mark.parametrize(
    "case", json.loads(LEGACY.read_text())["cases"], ids=lambda c: c["schema_version"]
)
def test_all_predecessor_manifest_and_prompt_bytes_are_unchanged(case):
    files = fixture_sources()
    assert {p: hashlib.sha256(raw).hexdigest() for p, raw in files} == json.loads(
        LEGACY.read_text()
    )["source_sha256s"]
    manifest = freeze_development_corpus(
        corpus_id="synthetic-static-closure-legacy",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
        source_files=files,
        **case["options"],
    )
    assert manifest.schema_version == case["schema_version"]
    assert manifest.manifest_sha256 == case["manifest_sha256"]
    assert (
        hashlib.sha256(manifest.model_dump_json().encode()).hexdigest()
        == case["manifest_json_sha256"]
    )
    prompt = render_development_corpus_sources(manifest, files, "src/Controller.sol")
    assert hashlib.sha256(prompt.encode()).hexdigest() == case["prompt_sha256"]


def test_older_witness_cannot_claim_new_closure_or_members_without_the_proof():
    witness = computed(include_static_closure=False)
    assert witness.schema_version == "1.6" and witness.dependency_closure == "IMPORT_CLOSED"
    payload = witness.model_dump(mode="json")
    payload["dependency_closure"] = "CALL_CLOSED"
    payload["witness_sha256"] = canonical_sha256(
        {k: v for k, v in payload.items() if k != "witness_sha256"}
    )
    with pytest.raises(ValueError):
        DevelopmentDependencyClosure.model_validate_json(json.dumps(payload))


def test_manifest_call_closure_requires_a_complete_tree_receipt_not_only_selected_source_bytes():
    with pytest.raises(ValueError, match="static call closure"):
        freeze_development_corpus(
            corpus_id="synthetic-no-tree",
            source_scope="OPERATOR_SUPPLIED_PROTOCOL",
            source_files=fixture_sources(),
            dependency_remapping_text="",
            **{key.replace("include_", "dependency_"): value for key, value in FLAGS.items()},
        )


def indexed_case(monkeypatch):
    observed = {}
    build = closure.build_solidity_index

    def capture(*args, **kwargs):
        index = build(*args, **kwargs)
        observed["index"] = index
        return index

    monkeypatch.setattr(closure, "build_solidity_index", capture)
    witness = computed()
    return witness, observed["index"]


@pytest.mark.parametrize(
    "change,expected",
    [
        ("none", None),
        ("compiler", None),
        ("confidence", "ORIGINAL_GRAPH_CONFIDENCE_BELOW_POLICY"),
        ("provenance", "ORIGINAL_GRAPH_PROVENANCE_INADEQUATE"),
        ("line", "ORIGINAL_GRAPH_FACT_NOT_SOURCE_JOINED"),
        ("dispatch", "ORIGINAL_GRAPH_FACT_NOT_SOURCE_JOINED"),
        ("unknown_symbol", "ORIGINAL_GRAPH_SYMBOL_NOT_UNIQUE"),
        ("symbol_kind", "ORIGINAL_GRAPH_SYMBOL_NOT_UNIQUE"),
        ("symbol_hash", "ORIGINAL_GRAPH_SYMBOL_NOT_UNIQUE"),
        ("duplicate_symbol", "ORIGINAL_GRAPH_SYMBOL_NOT_UNIQUE"),
    ],
)
def test_original_graph_predicates_each_join_exact_source_symbols_without_regrading(
    monkeypatch, change, expected
):
    witness, index = indexed_case(monkeypatch)
    source = next(e for e in index.index.entities if e.name == "observedValue")
    dest = next(
        e for e in index.index.entities if e.name == "value" and e.contract_name == "IReserve"
    )
    # A fabricated unit-only graph fact tests the adapter's predicates, not compiler provenance.
    fact = DependencyGraphFact(
        source="src/Controller.sol",
        line_start=8,
        line_end=8,
        kind=SolidityGraphKind.EXTERNAL_CALL,
        provenance=SolidityProvenance.STATIC_TOOL,
        confidence=0.9,
        fact_sha256="1" * 64,
        source_id=source.id,
        target_id=dest.id,
    )
    changes = {
        "compiler": {"provenance": SolidityProvenance.COMPILER},
        "confidence": {"confidence": 0.899999},
        "provenance": {"provenance": SolidityProvenance.HEURISTIC},
        "line": {"line_start": 7, "line_end": 7},
        "dispatch": {"kind": SolidityGraphKind.DELEGATECALL},
        "unknown_symbol": {"target_id": "missing"},
    }
    fact = fact.model_copy(update=changes.get(change, {}))
    if change in {"symbol_kind", "symbol_hash", "duplicate_symbol"}:
        altered = dest.model_copy(
            update={"kind": SolidityEntityKind.MODIFIER}
            if change == "symbol_kind"
            else {"source_hash": "2" * 64}
        )
        entities = [altered if e.id == dest.id else e for e in index.index.entities]
        if change == "duplicate_symbol":
            entities.append(dest)
        index = replace(index, index=index.index.model_copy(update={"entities": entities}))
    altered_witness = witness.model_copy(update={"graph_facts": (fact,), "graph_sha256": "3" * 64})
    proof = static.compute_static_call_closure(
        witness=altered_witness, source_files=fixture_sources(), source_index=index
    )
    assert proof.original_graph_sha256 == "3" * 64
    assert proof.original_graph_facts_sha256 == canonical_sha256([fact.model_dump(mode="json")])
    assert (proof.call_closure == "CALL_CLOSED") == (expected is None)
    if expected is None:
        assert proof.graph_joins[0].call_indices and not proof.graph_joins[0].shortfalls
    else:
        assert expected in proof.graph_joins[0].shortfalls


@pytest.mark.parametrize("change", ["missing", "mismatched", "extra"])
def test_independent_census_omissions_mismatches_and_extra_calls_block_closure(change):
    witness = computed()
    payload = witness.syntax_context.model_dump(mode="json")
    first = payload["calls"][0]
    if change == "missing":
        payload["calls"].pop(0)
        payload["unmatched_typed_call_indices"] = [first["typed_call_index"]]
    elif change == "mismatched":
        first["byte_end"] += 1
        first["typed_match"] = "SPAN_MISMATCH"
    else:
        payload["unmatched_typed_call_indices"] = [first["typed_call_index"]]
        first["call_byte_start"] += 1
        first["typed_call_index"] = None
        first["typed_match"] = "MISSING_TYPED_CALL"
    syntax = DependencySyntaxContext.model_validate_json(json.dumps(payload))
    proof = static._compose(
        witness.model_copy(update={"syntax_context": syntax}),
        (),
        witness.static_call_closure.call_lines,
    )
    assert proof.call_closure == "NOT_ESTABLISHED"
    assert proof.shortfalls and all(s.global_scope for s in proof.shortfalls)


def test_raw_graph_warnings_and_incomplete_generation_block_every_primary():
    witness = computed()
    for fields, reason in (
        ({"graph_warnings": ("unit-only unresolved graph warning",)}, "ORIGINAL_GRAPH_WARNING"),
        ({"graph_generation_complete": False}, "ORIGINAL_GRAPH_GENERATION_INCOMPLETE"),
    ):
        proof = static._compose(
            witness.model_copy(update=fields), (), witness.static_call_closure.call_lines
        )
        assert reason in {s.reason for s in proof.shortfalls}
        assert all(p.call_closure == "NOT_ESTABLISHED" for p in proof.primaries)


def test_original_graph_omissions_are_retained_and_never_an_empty_graph_success(monkeypatch):
    monkeypatch.setattr(closure, "MAX_DEPENDENCY_GRAPH_BYTES", 8192)
    witness = computed(call_sources(), remapping_text="")
    assert witness.graph_edge_omissions or witness.graph_fact_omissions
    proof = witness.static_call_closure
    for field, population in (
        ("graph_edge_omissions", "EDGE_OMISSION"),
        ("graph_fact_omissions", "FACT_OMISSION"),
    ):
        assert [s.evidence_index for s in proof.shortfalls if s.population == population] == list(
            range(len(getattr(witness, field)))
        )
    assert all(p.call_closure == "NOT_ESTABLISHED" for p in proof.primaries)


def test_public_composer_requires_exact_source_bytes(monkeypatch):
    witness, index = indexed_case(monkeypatch)
    files = changed("lib/Math.sol", "return 0", "return 1")
    with pytest.raises(ValueError, match="source bytes"):
        static.compute_static_call_closure(witness=witness, source_files=files, source_index=index)


@pytest.mark.parametrize("newline", [b"\n", b"\r\n", b"\r"])
def test_call_line_evidence_uses_the_same_source_lines_as_the_index_and_rendering(newline):
    files = tuple((p, raw.replace(b"\n", newline)) for p, raw in fixture_sources())
    witness = computed(files)
    assert witness.dependency_closure == "CALL_CLOSED"
    assert len(witness.call_context.calls) == 6
    for row in witness.static_call_closure.call_lines:
        call = witness.call_context.calls[row.call_index]
        position = 0
        lines = {}
        for number, raw in enumerate(dict(files)[call.source].splitlines(keepends=True), 1):
            for offset in (call.byte_start, call.byte_end - 1):
                if position <= offset < position + len(raw):
                    lines[offset] = number
            position += len(raw)
        assert (row.line_start, row.line_end) == (lines[call.byte_start], lines[call.byte_end - 1])
    for record in (*witness.imports, *witness.candidate_references):
        position = 0
        expected = None
        for number, raw in enumerate(dict(files)[record.source].splitlines(keepends=True), 1):
            if position <= record.byte_start < position + len(raw):
                expected = number
                break
            position += len(raw)
        assert record.line == expected
