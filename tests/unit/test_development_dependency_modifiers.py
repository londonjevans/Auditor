"""Source-only invariant: no modifier dependency disappears or earns an unproved binding."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from mmaudit.models.development_corpus import (
    DevelopmentCorpusManifest,
    freeze_development_corpus,
    render_development_corpus_sources,
    validate_development_corpus_sources,
)
from mmaudit.orchestration.manifest import canonical_sha256
from tests.unit.test_development_dependency_calls import call_sources

FIXTURE = Path(__file__).parents[1] / "fixtures/solidity/dependency_modifiers"


def modifier_sources():
    return tuple((p.name, p.read_bytes()) for p in sorted(FIXTURE.glob("*.sol")))


def changed_sources(path, before, after):
    sources = dict(modifier_sources())
    assert before.encode() in sources[path]
    sources[path] = sources[path].replace(before.encode(), after.encode())
    return tuple(sorted(sources.items()))


def modifier_manifest(files=None, **kwargs):
    return freeze_development_corpus(
        corpus_id="synthetic-modifiers",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
        source_files=modifier_sources() if files is None else files,
        **{
            "dependency_remapping_text": "",
            "dependency_target_context": True,
            "dependency_scoped_context": True,
            "dependency_call_context": True,
            "dependency_syntax_context": True,
            "dependency_modifier_context": True,
            **kwargs,
        },
    )


def modifiers(manifest):
    return [c for c in manifest.dependency_evidence.call_context.calls if "MODIFIER" in c.dispatch]


def resign(payload):
    witness = payload["dependency_evidence"]
    witness["witness_sha256"] = canonical_sha256(
        {k: v for k, v in witness.items() if k != "witness_sha256"}
    )
    payload["manifest_sha256"] = canonical_sha256(
        {k: v for k, v in payload.items() if k != "manifest_sha256"}
    )
    return payload


def test_modifier_headers_bind_arguments_all_override_bodies_and_body_dependencies():
    manifest = modifier_manifest()
    witness = manifest.dependency_evidence
    assert (manifest.schema_version, witness.schema_version) == ("1.7", "1.5")
    functions = {f.id: f for f in witness.scoped_context.functions}
    assert {c.callee for c in modifiers(manifest)} == {"open", "checked"}
    assert all(c.resolution == "STATIC_DECLARATIONS_BOUND" for c in witness.call_context.calls)
    checked = next(c for c in modifiers(manifest) if c.callee == "checked")
    assert {functions[i].source for i in checked.implementation_member_ids} == {
        "Guards.sol",
        "Child.sol",
    }
    assert (
        len(checked.implementation_ids) == 2
    )  # Controller and Child, not arbitrary unrelated types.
    assert len(checked.arguments[1].nested_call_offsets) == 1
    values = {v.id: v for v in witness.scoped_context.values}
    assert {values[i].kind for a in checked.arguments for i in a.value_ids} == {"PARAMETER"}
    assert (
        witness.scoped_context.gaps
        == witness.call_context.gaps
        == witness.syntax_context.gaps
        == ()
    )
    assert witness.syntax_context.unmatched_typed_call_indices == ()
    assert all(c.typed_match == "EXACT_SPAN" for c in witness.syntax_context.calls)
    primary = next(p for p in witness.call_context.primaries if p.primary == "Controller.sol")
    assert set(primary.members) == {p for p, _ in modifier_sources()}
    body_calls = [
        c
        for c in witness.call_context.calls
        if c.source in {"Guards.sol", "Child.sol"} and c.callee == "value"
    ]
    assert len(body_calls) == 2 and all(len(c.implementation_member_ids) == 2 for c in body_calls)
    assert not witness.scoped_context.complete_static_resolution
    assert not witness.call_context.complete_static_resolution
    assert not witness.syntax_context.complete_static_resolution
    assert all(p.call_closure == "NOT_ESTABLISHED" for p in witness.primaries)


@pytest.mark.parametrize("declaration", ["modifier open", "modifier open()"])
@pytest.mark.parametrize(
    "application", ["open", "open()", "open open()", "Guards.open", "Guards.open()"]
)
def test_implicit_explicit_repeated_and_qualified_applications_have_exact_source_anchors(
    declaration, application
):
    files = dict(modifier_sources())
    files["Guards.sol"] = files["Guards.sol"].replace(b"modifier open", declaration.encode())
    files["Controller.sol"] = files["Controller.sol"].replace(
        b"external open checked", f"external {application} checked".encode()
    )
    manifest = modifier_manifest(tuple(sorted(files.items())))
    calls = [c for c in modifiers(manifest) if c.callee == "open"]
    assert len(calls) == application.count("open")
    assert all(c.resolution == "STATIC_DECLARATIONS_BOUND" for c in calls)
    for call in calls:
        raw = files[call.source]
        span = raw[call.byte_start : call.byte_end]
        assert span.decode() in application
        if call.dispatch == "IMPLICIT_MODIFIER":
            assert call.call_byte_start == call.byte_start and not call.arguments
            assert span in {b"open", b"Guards.open"}
        else:
            assert raw[call.call_byte_start : call.call_byte_start + 1] == b"("
    assert manifest.dependency_evidence.syntax_context.gaps == ()


@pytest.mark.parametrize(
    "path,before,after,shortfall",
    [
        (
            "Controller.sol",
            "external open checked",
            "external missing checked",
            "MEMBER_DECLARATION_NOT_RESOLVED",
        ),
        (
            "Controller.sol",
            "checked(reserve, normalise(bound))",
            "checked(true, normalise(bound))",
            "NO_APPLICABLE_OVERLOAD",
        ),
        (
            "Controller.sol",
            "normalise(bound)",
            "normalise(unknown)",
            "EXPRESSION_NAME_NOT_RESOLVED",
        ),
        (
            "Controller.sol",
            "external open checked",
            "external Other.open checked",
            "QUALIFIED_MODIFIER_BASE_NOT_ESTABLISHED",
        ),
        (
            "Controller.sol",
            "external open checked",
            "external Guards() open checked",
            "BASE_CONSTRUCTOR_HEADER_UNRESOLVED",
        ),
        (
            "Guards.sol",
            "modifier open { _; }",
            "modifier open;",
            "IMPLEMENTATION_MEMBER_BODY_NOT_UNIQUE",
        ),
        (
            "Guards.sol",
            "modifier open { _; }",
            "modifier open public { _; }",
            "MODIFIER_DECLARATION_FORM_NOT_ESTABLISHED",
        ),
        (
            "Guards.sol",
            "modifier open { _; }",
            "modifier open { _; } modifier open(bool flag) { _; }",
            "MODIFIER_DECLARATION_NOT_UNIQUE",
        ),
        ("Guards.sol", ") virtual {", ") {", "MODIFIER_OVERRIDE_NOT_ESTABLISHED"),
        ("Child.sol", ") override {", ") {", "MODIFIER_OVERRIDE_NOT_ESTABLISHED"),
        ("Child.sol", "uint256 bound", "uint128 bound", "MODIFIER_OVERRIDE_NOT_ESTABLISHED"),
    ],
)
def test_unsupported_modifier_or_implementation_never_earns_binding(path, before, after, shortfall):
    manifest = modifier_manifest(changed_sources(path, before, after))
    calls = modifiers(manifest)
    assert any(shortfall in c.shortfalls for c in calls), [(c.callee, c.shortfalls) for c in calls]
    assert all(c.resolution == "NOT_ESTABLISHED" for c in calls if shortfall in c.shortfalls)


@pytest.mark.parametrize("header", ["open(,)", "open({missing: 1})", "open(normalise(unknown()))"])
def test_malformed_or_unknown_arguments_remain_visible(header):
    manifest = modifier_manifest(
        changed_sources("Controller.sol", "external open checked", f"external {header} checked")
    )
    assert (
        any(c.shortfalls for c in modifiers(manifest))
        or manifest.dependency_evidence.syntax_context.gaps
    )
    assert all(p.call_closure == "NOT_ESTABLISHED" for p in manifest.dependency_evidence.primaries)


def test_return_names_and_body_locals_are_not_visible_to_modifier_arguments():
    files = changed_sources(
        "Controller.sol",
        "checked(reserve, normalise(bound)) returns (uint256)",
        "checked(reserve, normalise(result)) returns (uint256 result)",
    )
    checked = next(c for c in modifiers(modifier_manifest(files)) if c.callee == "checked")
    assert checked.resolution == "NOT_ESTABLISHED"
    assert checked.arguments[1].value_ids == ()


def test_header_parameters_are_not_shadowed_by_unrelated_functions_or_later_body_locals():
    files = dict(modifier_sources())
    files["Controller.sol"] = files["Controller.sol"].replace(
        b"return reserve.value();", b"uint256 later = bound; return reserve.value();"
    )
    files["Guards.sol"] = files["Guards.sol"].replace(
        b"modifier open",
        b"function other(bool bound) internal pure returns (bool) { return bound; }\n    modifier open",
    )
    manifest = modifier_manifest(tuple(sorted(files.items())))
    assert all(c.resolution == "STATIC_DECLARATIONS_BOUND" for c in modifiers(manifest))


@pytest.mark.parametrize("change", ["body", "argument", "implementation", "added_implementer"])
def test_source_recomputation_refuses_modifier_and_implementation_drift(change):
    manifest = modifier_manifest()
    files = dict(modifier_sources())
    if change == "body":
        files["Guards.sol"] = files["Guards.sol"].replace(b"<= bound", b">= bound")
    elif change == "argument":
        files["Controller.sol"] = files["Controller.sol"].replace(
            b"normalise(bound)", b"normalise(0)"
        )
    elif change == "implementation":
        del files["Child.sol"]
    else:
        files["Added.sol"] = files["ReserveA.sol"].replace(b"ReserveA", b"Added")
    with pytest.raises(ValueError):
        validate_development_corpus_sources(manifest, tuple(sorted(files.items())))


def test_self_rehashed_missing_modifier_bodies_are_refused_by_source_consumer():
    payload = modifier_manifest().model_dump(mode="json")
    context = payload["dependency_evidence"]["call_context"]
    checked = next(c for c in context["calls"] if c["dispatch"] == "MODIFIER")
    checked["implementation_member_ids"] = []
    payload["dependency_evidence"]["syntax_context"]["call_context_sha256"] = canonical_sha256(
        context
    )
    forged = DevelopmentCorpusManifest.model_validate_json(json.dumps(resign(payload)))
    with pytest.raises(ValueError, match="source recomputation"):
        validate_development_corpus_sources(forged, modifier_sources())


@pytest.mark.parametrize("field", ["scoped_context", "call_context", "syntax_context"])
def test_mixed_resolution_policy_versions_are_refused_by_model_and_generated_schema(field):
    manifest = modifier_manifest()
    schema = json.loads(Path("schemas/development_corpus_manifest.schema.json").read_text())
    validator = Draft202012Validator(schema)
    validator.validate(manifest.model_dump(mode="json"))
    payload = manifest.model_dump(mode="json")
    old = modifier_manifest(dependency_modifier_context=False).model_dump(mode="json")
    payload["dependency_evidence"][field]["policy"] = old["dependency_evidence"][field]["policy"]
    with pytest.raises(ValueError, match=r"modifier|polic"):
        DevelopmentCorpusManifest.model_validate_json(json.dumps(resign(payload)))
    with pytest.raises(ValidationError):
        validator.validate(payload)


@pytest.mark.parametrize("flag", [None, 0, 1, "true", True])
def test_modifier_selection_is_strict_and_requires_syntax_context(flag):
    with pytest.raises(ValueError, match="modifier context"):
        modifier_manifest(dependency_modifier_context=flag, dependency_syntax_context=False)


def test_modifier_census_refuses_overflow_without_truncation(monkeypatch):
    from mmaudit.solidity import dependency_calls

    monkeypatch.setattr(dependency_calls, "MAX_TARGET_RECORDS", 2)
    with pytest.raises(ValueError, match="record ceiling"):
        modifier_manifest()


def test_unrelated_inheritance_branches_do_not_guess_a_modifier_linearization():
    files = dict(modifier_sources())
    files["Other.sol"] = (
        b"// Synthetic non-deployable source-only fixture.\npragma solidity ^0.8.24;\n"
        b'contract Other { constructor() { revert("NON_DEPLOYABLE_FIXTURE"); } modifier open { _; } }'
    )
    files["Controller.sol"] = files["Controller.sol"].replace(
        b"contract Controller is Guards",
        b'import "./Other.sol";\ncontract Controller is Guards, Other',
    )
    call = next(
        c for c in modifiers(modifier_manifest(tuple(sorted(files.items())))) if c.callee == "open"
    )
    assert call.resolution == "NOT_ESTABLISHED"
    assert "OVERLOAD_OR_INHERITED_MEMBER_AMBIGUITY" in call.shortfalls


@pytest.mark.parametrize("dispatch", ["MODIFIER", "IMPLICIT_MODIFIER"])
def test_independent_census_exposes_a_missing_modifier_even_without_parentheses(dispatch):
    from mmaudit.solidity.dependency_syntax import build_dependency_syntax_context

    witness = modifier_manifest().dependency_evidence
    original = witness.call_context
    dropped = next(c for c in original.calls if c.dispatch == dispatch)
    calls = tuple(c for c in original.calls if c is not dropped)
    context = build_dependency_syntax_context(
        source_files=modifier_sources(), call_context=original.model_copy(update={"calls": calls})
    )
    missing = [c for c in context.calls if c.typed_match == "MISSING_TYPED_CALL"]
    assert len(missing) == 1 and missing[0].byte_start == dropped.byte_start
    assert not context.complete_static_resolution


def test_modifier_bindings_do_not_regrade_or_hide_existing_graph_shortfalls():
    current = modifier_manifest().dependency_evidence
    previous = modifier_manifest(dependency_modifier_context=False).dependency_evidence
    for field in (
        "graph_facts",
        "graph_sha256",
        "graph_generation_complete",
        "graph_edge_omissions",
        "graph_fact_omissions",
        "graph_warnings",
        "parse_gaps",
        "primaries",
        "dependency_closure",
    ):
        assert getattr(current, field) == getattr(previous, field)


@pytest.mark.parametrize("case", json.loads((FIXTURE / "legacy_replay.json").read_text())["cases"])
def test_verified_predecessor_versions_keep_exact_artifacts_and_prompts(case):
    files = call_sources() if case["source"] == "calls" else modifier_sources()
    version = int(case["version"].split(".")[1])
    manifest = freeze_development_corpus(
        corpus_id="synthetic-modifier-legacy",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
        source_files=files,
        dependency_remapping_text="" if version else None,
        dependency_target_context=version >= 2,
        dependency_scoped_context=version >= 4,
        dependency_call_context=version >= 5,
        dependency_syntax_context=version >= 6,
    )
    assert manifest.manifest_sha256 == case["manifest_sha256"]
    assert (
        hashlib.sha256(manifest.model_dump_json().encode()).hexdigest() == case["artifact_sha256"]
    )
    prompt = render_development_corpus_sources(manifest, files, files[0][0])
    assert hashlib.sha256(prompt.encode()).hexdigest() == case["prompt_sha256"]
