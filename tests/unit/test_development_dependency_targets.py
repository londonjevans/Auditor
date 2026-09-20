"""Synthetic source-bound type context; no compiler, provider or audit authority."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

import mmaudit.solidity.dependency_targets as targets
from mmaudit.models.development_corpus import (
    DevelopmentCorpusManifest,
    freeze_development_corpus,
    render_development_corpus_sources,
    validate_development_corpus_sources,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.solidity.dependency_closure import compute_development_dependency_closure
from tests.unit.test_development_dependency_closure import closed_manifest, fixture_sources

FIXTURE = Path(__file__).parents[1] / "fixtures/solidity/dependency_targets"


def target_sources():
    extra = tuple(
        (p.relative_to(FIXTURE).as_posix(), p.read_bytes()) for p in sorted(FIXTURE.rglob("*.sol"))
    )
    return tuple(sorted((*fixture_sources(), *extra)))


def target_manifest(sources=None):
    return closed_manifest(
        target_sources() if sources is None else sources, dependency_target_context=True
    )


def controller_sources(directive, expression, parameters="address reserve", extra=""):
    source = (
        "// Synthetic source-only control; construction refuses deployment.\n"
        "pragma solidity ^0.8.20;\n" + directive + "\n"
        "contract Controller { constructor() { revert(); } "
        + extra
        + " function observe("
        + parameters
        + ") external view returns (uint256) { return "
        + expression
        + "; } }\n"
    ).encode()
    files = dict(fixture_sources())
    files["src/Controller.sol"] = source
    return tuple(sorted(files.items()))


def controller_call(context):
    return next(c for c in context.calls if c.source == "src/Controller.sol")


def test_explicit_calls_retain_all_transitive_implementations_and_their_imports():
    manifest = target_manifest()
    evidence = manifest.dependency_evidence
    context = evidence.target_context
    assert (manifest.schema_version, evidence.schema_version) == ("1.2", "1.1")
    assert manifest.dependency_closure == "IMPORT_CLOSED"
    by_id = {d.id: d for d in context.declarations}
    call = controller_call(context)
    assert by_id[call.receiver.target_id].name == "IReserve"
    assert {by_id[i].name for i in call.implementation_ids} == {
        "Reserve",
        "SecondReserve",
        "InheritedReserve",
    }
    assert call.shortfalls == ()
    assert context.gaps == ()
    primary = next(p for p in context.primaries if p.primary == "src/Controller.sol")
    assert set(primary.members) == {p for p, _ in target_sources()} - {"src/AliasController.sol"}
    assert "lib/Math.sol" in primary.members and "src/Intermediate.sol" in primary.members
    assert len([c for c in context.calls if c.source == "src/AliasController.sol"]) == 2
    assert not context.complete_static_resolution
    assert context.solidity_typecheck == "NOT_PERFORMED"
    assert all(c.member_dispatch == "NOT_ESTABLISHED" for c in context.calls)
    assert all(p.call_closure == "NOT_ESTABLISHED" for p in evidence.primaries)
    validate_development_corpus_sources(manifest, target_sources())


def test_declaration_and_call_spans_bind_exact_original_bytes():
    sources = dict(target_sources())
    context = target_manifest().dependency_evidence.target_context
    for declaration in context.declarations:
        raw = sources[declaration.source]
        assert declaration.source_sha256 == hashlib.sha256(raw).hexdigest()
        fragment = raw[declaration.byte_start : declaration.byte_end]
        assert fragment.startswith((declaration.kind + " " + declaration.name).encode())
        assert fragment.endswith(b"}")
    for call in context.calls:
        fragment = sources[call.source][call.byte_start : call.byte_end]
        assert call.receiver.spelling.encode() in fragment
        assert fragment.endswith(("." + call.member + "(").encode())


@pytest.mark.parametrize(
    "directive,expression",
    [
        ('import "./IReserve.sol";', "IReserve(reserve).value()"),
        ('import {IReserve as ReserveApi} from "./IReserve.sol";', "ReserveApi(reserve).value()"),
        ('import * as Protocol from "./IReserve.sol";', "Protocol.IReserve(reserve).value()"),
        ('import "./IReserve.sol" as Protocol;', "Protocol.IReserve(reserve).value()"),
    ],
)
def test_plain_named_and_namespace_imports_resolve_without_inventing_conversion_calls(
    directive, expression
):
    context = target_manifest(
        controller_sources(directive, expression)
    ).dependency_evidence.target_context
    calls = [c for c in context.calls if c.source == "src/Controller.sol"]
    assert len(calls) == 1
    assert calls[0].receiver.target_id is not None and calls[0].receiver.shortfall is None
    assert calls[0].receiver_form == "TYPE_CAST"
    assert len(calls[0].implementation_ids) == 2


@pytest.mark.parametrize("prefix", ["aaa", "zzz"])
@pytest.mark.parametrize("member", ["value", "transfer"])
def test_duplicate_names_retain_every_candidate_without_first_name_selection(prefix, member):
    alternate = prefix + "/IReserve.sol"
    files = dict(
        controller_sources(
            'import "./IReserve.sol"; import "../' + alternate + '";',
            "IReserve(reserve)." + member + "()",
        )
    )
    files[alternate] = (
        b"// Synthetic source-only interface.\ninterface IReserve { function value() external returns (uint256); }\n"
    )
    context = target_manifest(tuple(sorted(files.items()))).dependency_evidence.target_context
    call = controller_call(context)
    assert call.receiver.target_id is None
    assert call.receiver.shortfall == "AMBIGUOUS_TYPE_NAME"
    assert len(call.receiver.candidate_ids) == 2
    assert len(call.implementation_ids) == 2  # Retained possibilities, not a selected target.
    assert "AMBIGUOUS_TYPE_NAME" in call.shortfalls
    if member == "transfer":
        assert "POSSIBLE_LOW_LEVEL_TARGET" in call.shortfalls
    primary = next(p for p in context.primaries if p.primary == "src/Controller.sol")
    assert alternate in primary.members and "src/Reserve.sol" in primary.members


@pytest.mark.parametrize(
    "parameters,extra",
    [
        ("address reserve, uint256 IReserve", ""),
        ("address reserve", "uint256 private IReserve;"),
        ("address reserve", "function other(uint256 IReserve) external pure {}"),
    ],
)
def test_possible_lexical_shadowing_never_selects_a_type_by_spelling(parameters, extra):
    context = target_manifest(
        controller_sources(
            'import "./IReserve.sol";', "IReserve(reserve).value()", parameters, extra
        )
    ).dependency_evidence.target_context
    call = controller_call(context)
    assert call.receiver.target_id is None
    assert call.receiver.shortfall == "POTENTIAL_LEXICAL_SHADOWING"
    assert call.receiver.candidate_ids
    assert not context.complete_static_resolution


def test_typed_value_receiver_remains_unresolved_until_lexical_scope_types_are_proved():
    context = target_manifest(
        controller_sources('import "./IReserve.sol";', "reserve.value()", "IReserve reserve")
    ).dependency_evidence.target_context
    assert controller_call(context).receiver.shortfall == "TYPE_NAME_NOT_RESOLVED"
    assert controller_call(context).member_dispatch == "NOT_ESTABLISHED"


@pytest.mark.parametrize("member", ["call", "delegatecall", "staticcall", "transfer"])
def test_untyped_low_level_receivers_have_explicit_dynamic_shortfalls(member):
    files = controller_sources('import "./IReserve.sol";', "reserve." + member + "()")
    context = target_manifest(files).dependency_evidence.target_context
    call = controller_call(context)
    assert call.receiver.shortfall == "TYPE_NAME_NOT_RESOLVED"
    assert call.receiver.target_id is None
    assert "TYPE_NAME_NOT_RESOLVED" in call.shortfalls
    assert "POSSIBLE_LOW_LEVEL_TARGET" in call.shortfalls


def test_typed_transfer_member_is_not_misclassified_as_an_address_primitive():
    context = target_manifest(
        controller_sources('import "./IReserve.sol";', "IReserve(reserve).transfer()")
    ).dependency_evidence.target_context
    call = controller_call(context)
    assert call.receiver.target_id is not None
    assert "POSSIBLE_LOW_LEVEL_TARGET" not in call.shortfalls
    assert call.member_dispatch == "NOT_ESTABLISHED"  # No claim that this member exists.


def test_interface_without_supplied_implementation_retains_its_shortfall():
    files = tuple(
        (p, raw) for p, raw in fixture_sources() if p in {"src/Controller.sol", "src/IReserve.sol"}
    )
    context = target_manifest(files).dependency_evidence.target_context
    call = controller_call(context)
    assert call.receiver.target_id is not None
    assert call.implementation_ids == () and "NO_SUPPLIED_IMPLEMENTER" in call.shortfalls


def test_missing_named_import_symbol_blocks_the_source_namespace():
    context = target_manifest(
        controller_sources(
            'import {Missing as ReserveApi} from "./IReserve.sol";', "ReserveApi(reserve).value()"
        )
    ).dependency_evidence.target_context
    assert "IMPORT_SYMBOL_NOT_RESOLVED" in {g.reason for g in context.gaps}
    assert controller_call(context).receiver.shortfall == "UNSUPPORTED_SOURCE_NAMESPACE"


def test_unresolved_inheritance_blocks_complete_implementation_enumeration():
    files = dict(fixture_sources())
    files["src/Reserve.sol"] = files["src/Reserve.sol"].replace(b"is IReserve", b"is MissingBase")
    context = target_manifest(tuple(sorted(files.items()))).dependency_evidence.target_context
    assert "INHERITANCE_TARGET_NOT_RESOLVED" in {g.reason for g in context.gaps}
    assert "IMPLEMENTATION_SET_INCOMPLETE" in controller_call(context).shortfalls


@pytest.mark.parametrize("change", ["lexical", "delimiter", "free_function", "inheritance_cycle"])
def test_unsupported_or_incomplete_parsing_remains_visible(change):
    files = dict(fixture_sources())
    if change == "lexical":
        files["src/IReserve.sol"] += b"\n/* unfinished"
    elif change == "delimiter":
        files["src/IReserve.sol"] += b"\n}"
    elif change == "free_function":
        files["src/IReserve.sol"] += b"\nfunction outside() pure returns (uint256) { return 0; }"
    else:
        files["src/IReserve.sol"] = files["src/IReserve.sol"].replace(
            b"interface IReserve", b"interface IReserve is IReserve"
        )
    context = target_manifest(tuple(sorted(files.items()))).dependency_evidence.target_context
    assert context.gaps
    assert controller_call(context).shortfalls
    assert not context.complete_static_resolution


@pytest.mark.parametrize("value", [0, 1, "true", None])
def test_target_context_opt_in_is_explicit_and_strict(value):
    with pytest.raises(ValueError):
        closed_manifest(dependency_target_context=value)
    with pytest.raises(ValueError):
        compute_development_dependency_closure(
            source_files=fixture_sources(), include_target_context=value
        )


def test_target_context_requires_explicit_remapping_selection():
    with pytest.raises(ValueError):
        freeze_development_corpus(
            corpus_id="synthetic-targets",
            source_scope="OPERATOR_SUPPLIED_PROTOCOL",
            source_files=fixture_sources(),
            dependency_target_context=True,
        )


@pytest.mark.parametrize("value", [0, 1, True, "false"])
def test_target_context_cannot_claim_complete_static_resolution(value):
    data = target_manifest().dependency_evidence.target_context.model_dump(mode="json")
    data["complete_static_resolution"] = value
    with pytest.raises(ValueError):
        targets.DependencyTargetContext.model_validate_json(json.dumps(data))


@pytest.mark.parametrize(
    "bound,value",
    [("MAX_TARGET_RECORDS", 2), ("MAX_TARGET_WORK", 1), ("MAX_TARGET_CONTEXT_BYTES", 1024)],
)
def test_target_population_and_work_overflow_refuse_without_truncation(monkeypatch, bound, value):
    monkeypatch.setattr(targets, bound, value)
    with pytest.raises(ValueError):
        target_manifest()


def test_namespace_alias_cycle_refuses_before_unbounded_expansion():
    files = (
        ("A.sol", b'import "B.sol" as B; contract A { constructor() { revert(); } }'),
        ("B.sol", b'import "A.sol" as A; contract B { constructor() { revert(); } }'),
    )
    with pytest.raises(ValueError, match=r"ceiling|bounded"):
        target_manifest(files)


@pytest.mark.parametrize("change", ["implementers", "members", "target"])
def test_resealed_forged_target_context_refuses_actual_source_recomputation(change):
    data = target_manifest().model_dump(mode="json")
    evidence = data["dependency_evidence"]
    context = evidence["target_context"]
    call = next(c for c in context["calls"] if c["source"] == "src/Controller.sol")
    if change == "implementers":
        call["implementation_ids"] = []
    elif change == "members":
        primary = next(p for p in context["primaries"] if p["primary"] == "src/Controller.sol")
        primary["members"].remove("src/InheritedReserve.sol")
    else:
        target = next(d["id"] for d in context["declarations"] if d["name"] == "Math")
        call["receiver"].update(candidate_ids=[target], target_id=target)
    evidence["witness_sha256"] = canonical_sha256(
        {k: v for k, v in evidence.items() if k != "witness_sha256"}
    )
    data["manifest_sha256"] = canonical_sha256(
        {k: v for k, v in data.items() if k != "manifest_sha256"}
    )
    parsed = DevelopmentCorpusManifest.model_validate_json(json.dumps(data))
    with pytest.raises(ValueError, match="source recomputation"):
        validate_development_corpus_sources(parsed, target_sources())


@pytest.mark.parametrize("version", ["1.0", "1.1"])
def test_new_target_evidence_cannot_be_smuggled_into_older_manifest_versions(version):
    data = target_manifest().model_dump(mode="json")
    data["schema_version"] = version
    data["manifest_sha256"] = canonical_sha256(
        {k: v for k, v in data.items() if k != "manifest_sha256"}
    )
    with pytest.raises(ValueError):
        DevelopmentCorpusManifest.model_validate_json(json.dumps(data))


@pytest.mark.parametrize(
    "change",
    [
        "manifest_version",
        "witness_version",
        "missing_version",
        "missing_context",
        "null_context",
        "false_as_integer",
    ],
)
def test_generated_schema_enforces_target_context_version_and_false_only_scope(change):
    from scripts.generate_release_schemas import rendered_schema

    schema = json.loads(
        rendered_schema("development_corpus_manifest.schema.json", DevelopmentCorpusManifest)
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    data = target_manifest().model_dump(mode="json")
    validator.validate(data)
    if change == "manifest_version":
        data["schema_version"] = "1.1"
    elif change == "witness_version":
        data["dependency_evidence"]["schema_version"] = "1.0"
    elif change == "missing_version":
        data["dependency_evidence"].pop("schema_version")
    elif change == "missing_context":
        data["dependency_evidence"].pop("target_context")
    elif change == "null_context":
        data["dependency_evidence"]["target_context"] = None
    else:
        data["dependency_evidence"]["target_context"]["complete_static_resolution"] = 0
    with pytest.raises(ValidationError):
        validator.validate(data)


def test_pinned_predecessor_manifests_witness_and_request_bytes_replay_unchanged():
    control = json.loads((FIXTURE / "legacy_replay.json").read_text())
    assert control["predecessor_source_sha256s"] == {
        "src/mmaudit/solidity/dependency_closure.py": "a4fe34280ae9ef99a3516ac729cbf6ff2936e788094997d706145dfe4ab7fced",
        "src/mmaudit/models/development_corpus.py": "ca60d95693fc1340af278e8c42e49dc0acd55286cbc98ff4b899d6c9286d9c31",
    }
    sources = fixture_sources()
    imported = closed_manifest()
    legacy = freeze_development_corpus(
        corpus_id=imported.corpus_id, source_scope=imported.source_scope, source_files=sources
    )
    assert legacy.model_dump_json() == control["legacy_manifest_json"]
    assert imported.model_dump_json() == control["import_manifest_json"]
    assert imported.dependency_evidence.model_dump_json() == control["import_witness_json"]
    for value, name in ((legacy, "legacy"), (imported, "import")):
        parsed = DevelopmentCorpusManifest.model_validate_json(control[name + "_manifest_json"])
        validate_development_corpus_sources(parsed, sources)
        assert parsed == value
        assert (
            render_development_corpus_sources(value, sources, "src/Controller.sol")
            == control[name + "_source_prompt"]
        )
        assert "target_context" not in value.model_dump_json()


def test_unsupported_remapping_policy_never_yields_a_selected_declaration():
    manifest = closed_manifest(
        dependency_target_context=True,
        dependency_remapping_text="@local/=lib/\ncontext:@local/=elsewhere/\n",
    )
    context = manifest.dependency_evidence.target_context
    assert manifest.dependency_closure == "NOT_ESTABLISHED"
    assert "IMPORT_POLICY_NOT_ESTABLISHED" in {g.reason for g in context.gaps}
    assert controller_call(context).receiver.shortfall == "UNSUPPORTED_SOURCE_NAMESPACE"


def test_parent_import_parse_failure_propagates_to_target_bindings():
    files = dict(fixture_sources())
    files["src/Controller.sol"] = files["src/Controller.sol"].replace(
        b"contract Controller {", b'contract Controller { import "./IReserve.sol";'
    )
    manifest = target_manifest(tuple(sorted(files.items())))
    assert manifest.dependency_closure == "NOT_ESTABLISHED"
    context = manifest.dependency_evidence.target_context
    assert "IMPORT_NOT_TOP_LEVEL" in {g.reason for g in context.gaps}
    assert controller_call(context).receiver.shortfall == "UNSUPPORTED_SOURCE_NAMESPACE"
