"""Local dependency completeness never substitutes for call semantics or audit authority."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from mmaudit.models.development_corpus import (
    DevelopmentCorpusManifest,
    DevelopmentCorpusMaterial,
    DevelopmentCorpusText,
    freeze_development_corpus,
    validate_development_corpus_sources,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.solidity import dependency_closure as closure
from mmaudit.solidity.dependency_closure import compute_development_dependency_closure

FIXTURE = Path(__file__).parents[1] / "fixtures/solidity/dependency_closure"


def fixture_sources():
    return tuple(
        (p.relative_to(FIXTURE).as_posix(), p.read_bytes()) for p in sorted(FIXTURE.rglob("*.sol"))
    )


def closed_manifest(sources=None, **kwargs):
    return freeze_development_corpus(
        corpus_id="synthetic-dependencies",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
        source_files=fixture_sources() if sources is None else sources,
        dependency_remapping_text=kwargs.pop(
            "dependency_remapping_text", (FIXTURE / "remappings.txt").read_text()
        ),
        **kwargs,
    )


@pytest.mark.parametrize(
    "directive",
    [
        'import "./B.sol";',
        'import "./B.sol" as Unit;',
        'import * as Unit from "./B.sol";',
        'import {B} from "./B.sol";',
        'import {B as Alias, C} from "./B.sol";',
        'import /* inert */ {B\n as Alias} from /* inert */ "./B.sol";',
    ],
)
def test_supported_import_grammar_is_source_bound(directive):
    source = ("// Synthetic local import control.\n" + directive + "\ncontract A {}\n").encode()
    files = (("A.sol", source), ("B.sol", b"contract B {}\ncontract C {}\n"))
    witness = compute_development_dependency_closure(source_files=files)
    assert witness.dependency_closure == "IMPORT_CLOSED"
    assert witness.primaries[0].import_members == ("A.sol", "B.sol")
    imported = witness.imports[0]
    assert imported.target == "B.sol" and imported.line == 2
    assert source[imported.byte_start : imported.byte_end].decode() == directive
    assert witness.source_inventory[0].sha256 == hashlib.sha256(source).hexdigest()
    assert all(p.call_closure == "NOT_ESTABLISHED" for p in witness.primaries)


def test_real_source_fixture_keeps_interface_and_all_supplied_implementations_distinct():
    manifest = closed_manifest()
    evidence = manifest.dependency_evidence
    assert evidence is not None and manifest.schema_version == "1.1"
    assert manifest.dependency_closure == "IMPORT_CLOSED"
    by_primary = {p.primary: p for p in evidence.primaries}
    assert by_primary["src/Controller.sol"].import_members == (
        "src/Controller.sol",
        "src/IReserve.sol",
    )
    assert by_primary["src/Reserve.sol"].import_members == (
        "lib/Math.sol",
        "src/IReserve.sol",
        "src/Reserve.sol",
    )
    assert len(by_primary) == 5 and "src/SecondReserve.sol" in by_primary
    # Generic value()/zero() calls are absent from the existing heuristic graph.
    assert not evidence.graph_facts
    assert {r.spelling for r in evidence.candidate_references} >= {"value", "zero", "is"}
    assert all(f.resolution == "NOT_ESTABLISHED" for f in evidence.graph_facts)
    assert all(p.call_closure == "NOT_ESTABLISHED" for p in by_primary.values())
    validate_development_corpus_sources(manifest, fixture_sources())


@pytest.mark.parametrize(
    "directive,reason",
    [
        ('import "./Missing.sol";', "MISSING_SUPPLIED_SOURCE"),
        ('import "../Outside.sol";', "OUTSIDE_SUPPLIED_NAMESPACE"),
        ('import "https://invalid.test/Outside.sol";', "UNSUPPORTED_IMPORT_PATH"),
        ('import "./B\\x2esol";', "UNSUPPORTED_IMPORT_PATH"),
        ('import "//Outside.sol";', "UNSUPPORTED_IMPORT_PATH"),
        ("import B;", "MALFORMED_IMPORT"),
        ('import "./B.sol"', "MALFORMED_IMPORT"),
        ('import {} from "./B.sol";', "MALFORMED_IMPORT"),
        ('import {B,} from "./B.sol";', "MALFORMED_IMPORT"),
        ('import {"B"} from "./B.sol";', "MALFORMED_IMPORT"),
        ('import "./B.sol" as "Alias";', "MALFORMED_IMPORT"),
        ('import * as "Alias" from "./B.sol";', "MALFORMED_IMPORT"),
    ],
)
def test_missing_unsupported_and_malformed_imports_are_not_a_closed_context(directive, reason):
    evidence = compute_development_dependency_closure(
        source_files=(("A.sol", directive.encode()), ("B.sol", b"contract B {}"))
    )
    assert evidence.dependency_closure == "NOT_ESTABLISHED"
    assert evidence.imports[0].shortfall == reason
    assert evidence.primaries[1].import_closure == "IMPORT_CLOSED"


@pytest.mark.parametrize(
    "content,reason",
    [
        (b"/* unfinished import", "LEXICAL_ERROR"),
        (b'"unfinished', "LEXICAL_ERROR"),
        (b"contract A {", "UNBALANCED_DELIMITER"),
        (b"contract A }", "UNBALANCED_DELIMITER"),
        (b'contract A { import "./B.sol"; }', "IMPORT_NOT_TOP_LEVEL"),
        (b'\\ import "./B.sol";', "LEXICAL_ERROR"),
    ],
)
def test_lexical_or_scope_failure_retains_the_shortfall(content, reason):
    evidence = compute_development_dependency_closure(
        source_files=(("A.sol", content), ("B.sol", b"contract B {}"))
    )
    assert evidence.dependency_closure == "NOT_ESTABLISHED"
    assert reason in {g.reason for g in evidence.parse_gaps}


def test_inert_comments_and_strings_neither_add_nor_hide_imports():
    content = b'// import "Missing.sol";\r\n/* import "Missing2.sol"; */\r\ncontract A { string constant X = "import \\"Missing3.sol\\";"; }\r\nimport "./B.sol";\r\n'
    evidence = compute_development_dependency_closure(
        source_files=(("A.sol", content), ("B.sol", b"contract B {}"))
    )
    assert evidence.dependency_closure == "IMPORT_CLOSED"
    assert len(evidence.imports) == 1 and evidence.imports[0].line == 4


def test_cycles_are_a_complete_finite_membership_not_a_recursive_failure():
    files = (
        ("A.sol", b'import "B.sol";'),
        ("B.sol", b'import "C.sol";'),
        ("C.sol", b'import "A.sol";'),
    )
    evidence = compute_development_dependency_closure(source_files=files)
    assert all(p.import_members == ("A.sol", "B.sol", "C.sol") for p in evidence.primaries)
    assert evidence.dependency_closure == "IMPORT_CLOSED"


@pytest.mark.parametrize(
    "mapping",
    ["src/:@local/=lib/", "bad", "a/=../escape/", "a/=/absolute/", "a=lib/", "a/=lib//=other/"],
)
def test_unsupported_remappings_remain_visible_and_block_import_claim(mapping):
    evidence = compute_development_dependency_closure(
        source_files=(("A.sol", b"contract A {}"),), remapping_text="# inert\n" + mapping + "\n"
    )
    assert evidence.unsupported_remapping_lines == (2,)
    assert evidence.dependency_closure == "NOT_ESTABLISHED"


def test_longest_unique_remapping_wins_and_conflicting_equal_prefixes_refuse():
    files = (("A.sol", b'import "@a/sub/B.sol";'), ("lib/B.sol", b"contract B {}"))
    good = compute_development_dependency_closure(
        source_files=files, remapping_text="@a/=other/\n@a/sub/=lib/\n"
    )
    assert good.imports[0].target == "lib/B.sol"
    bad = compute_development_dependency_closure(
        source_files=files, remapping_text="@a/sub/=lib/\n@a/sub/=other/\n"
    )
    assert bad.imports[0].shortfall == "AMBIGUOUS_REMAPPING"
    assert bad.dependency_closure == "NOT_ESTABLISHED"


def test_transitive_shortfall_propagates_to_every_dependent_primary():
    files = (
        ("A.sol", b'import "B.sol";'),
        ("B.sol", b'import "Missing.sol";'),
        ("C.sol", b"contract C {}"),
    )
    evidence = compute_development_dependency_closure(source_files=files)
    assert tuple(p.import_closure for p in evidence.primaries) == (
        "NOT_ESTABLISHED",
        "NOT_ESTABLISHED",
        "IMPORT_CLOSED",
    )


def test_legacy_manifest_dump_and_digest_are_not_retroactively_promoted():
    manifest = freeze_development_corpus(
        corpus_id="legacy",
        source_scope="OPERATOR_SUPPLIED_SYNTHETIC",
        source_files=fixture_sources(),
    )
    raw = manifest.model_dump(mode="json")
    assert "dependency_evidence" not in raw
    assert raw["schema_version"] == "1.0" and raw["dependency_closure"] == "NOT_ESTABLISHED"
    expected = raw.pop("manifest_sha256")
    assert canonical_sha256(raw) == expected
    assert (
        DevelopmentCorpusManifest.model_validate_json(manifest.model_dump_json(), strict=True)
        == manifest
    )


@pytest.mark.parametrize(
    "mutation", ["import", "member", "graph", "source", "remapping", "parse_gap"]
)
def test_resealed_forged_witness_is_refused_by_source_recomputation(mutation):
    manifest = closed_manifest()
    value = manifest.model_dump(mode="json")
    evidence = value["dependency_evidence"]
    if mutation == "import":
        evidence["imports"] = []
    elif mutation == "member":
        evidence["primaries"][-1]["import_members"] = [evidence["primaries"][-1]["primary"]]
    elif mutation == "graph":
        evidence["graph_sha256"] = "0" * 64
    elif mutation == "source":
        evidence["source_inventory"][0]["sha256"] = "0" * 64
        evidence["source_inventory_sha256"] = canonical_sha256(evidence["source_inventory"])
    elif mutation == "remapping":
        evidence["remapping_text"] += "@missing/=unused/\n"
        evidence["remapping_sha256"] = hashlib.sha256(
            evidence["remapping_text"].encode()
        ).hexdigest()
        # The changed remapping belongs to a distinct valid policy; stale identity must refuse.
        evidence["imports"][0]["line"] += 1
    else:
        evidence["parse_gaps"] = [
            {"source": "src/Controller.sol", "byte_offset": 0, "reason": "LEXICAL_ERROR"}
        ]
    evidence["witness_sha256"] = canonical_sha256(
        {k: v for k, v in evidence.items() if k != "witness_sha256"}
    )
    value["manifest_sha256"] = canonical_sha256(
        {k: v for k, v in value.items() if k != "manifest_sha256"}
    )
    with pytest.raises(ValueError):
        forged = DevelopmentCorpusManifest.model_validate_json(json.dumps(value), strict=True)
        DevelopmentCorpusMaterial(
            manifest=forged,
            sources=tuple(
                DevelopmentCorpusText(filename=p, content=b.decode()) for p, b in fixture_sources()
            ),
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("runtime_authority", True),
        ("runtime_authority", 0),
        ("audit_complete", 1),
        ("qualification_eligible", "false"),
        ("dependency_closure", "CALL_CLOSED"),
    ],
)
def test_witness_cannot_acquire_authority_by_resealing(field, value):
    evidence = closed_manifest().dependency_evidence.model_dump(mode="json")
    evidence[field] = value
    evidence["witness_sha256"] = canonical_sha256(
        {k: v for k, v in evidence.items() if k != "witness_sha256"}
    )
    with pytest.raises(ValueError):
        closure.DevelopmentDependencyClosure.model_validate_json(json.dumps(evidence), strict=True)


@pytest.mark.parametrize(
    "ceiling", ["MAX_DEPENDENCY_TOKENS", "MAX_DEPENDENCY_RECORDS", "MAX_DEPENDENCY_WITNESS_BYTES"]
)
def test_overflow_refuses_the_whole_witness_without_truncation(monkeypatch, ceiling):
    monkeypatch.setattr(closure, ceiling, 1)
    with pytest.raises(ValueError, match="ceiling"):
        closed_manifest()


def test_complete_witness_byte_bound_is_inclusive(monkeypatch):
    witness = closed_manifest().dependency_evidence
    size = len(witness.model_dump_json().encode())
    monkeypatch.setattr(closure, "MAX_DEPENDENCY_WITNESS_BYTES", size)
    assert closed_manifest().dependency_evidence == witness
    monkeypatch.setattr(closure, "MAX_DEPENDENCY_WITNESS_BYTES", size - 1)
    with pytest.raises(ValueError, match="byte ceiling"):
        closed_manifest()


def test_graph_omissions_are_retained_without_promoting_call_closure(monkeypatch):
    monkeypatch.setattr(closure, "MAX_DEPENDENCY_GRAPH_BYTES", 8192)
    witness = closed_manifest().dependency_evidence
    assert not witness.graph_generation_complete
    assert witness.graph_edge_omissions or witness.graph_fact_omissions
    assert all(p.call_closure == "NOT_ESTABLISHED" for p in witness.primaries)
    assert witness.dependency_closure == "IMPORT_CLOSED"


def test_nonrelative_dot_segments_are_not_silently_normalized_to_a_supplied_file():
    witness = compute_development_dependency_closure(
        source_files=(("A.sol", b'import "elsewhere/../B.sol";'), ("B.sol", b"contract B {}"))
    )
    assert witness.imports[0].shortfall == "UNSUPPORTED_IMPORT_PATH"
    assert witness.dependency_closure == "NOT_ESTABLISHED"


def test_generated_schema_requires_new_evidence_without_promoting_old_manifests():
    from scripts.generate_release_schemas import rendered_schema

    schema = json.loads(
        rendered_schema("development_corpus_manifest.schema.json", DevelopmentCorpusManifest)
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    manifest = closed_manifest().model_dump(mode="json")
    validator.validate(manifest)
    no_evidence = dict(manifest)
    no_evidence.pop("dependency_evidence")
    with pytest.raises(ValidationError):
        validator.validate(no_evidence)
    for bad in (
        {**manifest, "schema_version": "1.0"},
        {**no_evidence, "schema_version": "1.0"},
        {**manifest, "dependency_closure": "CALL_CLOSED"},
    ):
        with pytest.raises(ValidationError):
            validator.validate(bad)
    old = freeze_development_corpus(
        corpus_id="legacy",
        source_scope="OPERATOR_SUPPLIED_SYNTHETIC",
        source_files=fixture_sources(),
    )
    validator.validate(old.model_dump(mode="json"))
