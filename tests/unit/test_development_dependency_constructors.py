"""Source-only invariant: no constructor target, argument supply or ancestor is omitted."""

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
from mmaudit.solidity.dependency_syntax import build_dependency_syntax_context

FIXTURE = Path(__file__).parents[1] / "fixtures/solidity/dependency_constructors"


def constructor_sources():
    return tuple((p.name, p.read_bytes()) for p in sorted(FIXTURE.glob("*.sol")))


def changed_sources(path, before, after):
    sources = dict(constructor_sources())
    assert before.encode() in sources[path]
    sources[path] = sources[path].replace(before.encode(), after.encode())
    return tuple(sorted(sources.items()))


def constructor_manifest(files=None, **kwargs):
    return freeze_development_corpus(
        corpus_id="synthetic-constructors",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
        source_files=constructor_sources() if files is None else files,
        **{
            "dependency_remapping_text": "",
            "dependency_target_context": True,
            "dependency_scoped_context": True,
            "dependency_call_context": True,
            "dependency_syntax_context": True,
            "dependency_modifier_context": True,
            "dependency_constructor_context": True,
            **kwargs,
        },
    )


def constructions(manifest, dispatch="CREATION"):
    return [c for c in manifest.dependency_evidence.call_context.calls if c.dispatch == dispatch]


def names(witness, identities):
    return {d.name for d in witness.target_context.declarations if d.id in identities}


def resign(payload):
    witness = payload["dependency_evidence"]
    witness["witness_sha256"] = canonical_sha256(
        {k: v for k, v in witness.items() if k != "witness_sha256"}
    )
    payload["manifest_sha256"] = canonical_sha256(
        {k: v for k, v in payload.items() if k != "manifest_sha256"}
    )
    return payload


def test_creation_binds_exact_nominal_ancestors_explicit_and_implicit_constructors():
    manifest = constructor_manifest()
    witness = manifest.dependency_evidence
    assert (manifest.schema_version, witness.schema_version) == ("1.8", "1.6")
    calls = constructions(manifest)
    assert len(calls) == 6
    assert all(c.resolution == "STATIC_DECLARATIONS_BOUND" for c in witness.call_context.calls)
    expected = {
        "Product": {"Product", "Seeded", "Guard"},
        "HeaderProduct": {"HeaderProduct", "Seeded", "Guard"},
        "Implicit": {"Implicit", "Guard"},
        "DerivedProduct": {"DerivedProduct", "Product", "Seeded", "Guard"},
    }
    functions = {f.id: f for f in witness.scoped_context.functions}
    for call in calls:
        binding = call.constructor_binding
        assert names(witness, binding.required_type_ids) == expected[call.callee]
        assert names(witness, (binding.target_id,)) == {call.callee}
        assert set(call.implementation_member_ids) == set(binding.constructor_member_ids)
        assert all(functions[i].kind == "constructor" for i in binding.constructor_member_ids)
        assert {functions[i].owner_type_id for i in binding.constructor_member_ids} == (
            set(binding.required_type_ids) - set(binding.implicit_type_ids)
        )
        assert "Factory" not in names(witness, binding.required_type_ids)
        if call.callee in {"Implicit", "HeaderProduct"}:
            assert names(witness, binding.implicit_type_ids) == {call.callee}
            assert call.member_ids == () and call.candidate_member_ids == ()
        else:
            assert binding.implicit_type_ids == () and len(call.member_ids) == 1
    assert all(p.call_closure == "NOT_ESTABLISHED" for p in witness.primaries)
    assert not witness.audit_complete and not witness.qualification_eligible


def test_base_constructor_arguments_are_parameter_scoped_and_census_is_complete():
    manifest = constructor_manifest()
    witness = manifest.dependency_evidence
    files = dict(constructor_sources())
    calls = constructions(manifest, "BASE_CONSTRUCTOR")
    assert len(calls) == 3
    assert {c.callee for c in calls} == {"Base", "Product"}
    scopes = {s.id: s for s in witness.scoped_context.scopes}
    values = {v.id: v for v in witness.scoped_context.values}
    for call in calls:
        binding = call.constructor_binding
        assert binding.required_type_ids == (binding.target_id,)
        assert binding.base_argument_calls == ()
        assert call.result_types == ()
        assert files[call.source][call.call_byte_start : call.call_byte_start + 1] == b"("
        assert files[call.source][call.byte_end - 1 : call.byte_end] == b")"
        for argument in call.arguments:
            for identity in argument.value_ids:
                value = values[identity]
                assert value.kind == "PARAMETER" and value.scope_id == scopes[call.scope_id].id
    assert any(scopes[c.scope_id].kind == "CONTRACT" for c in calls)
    assert any(scopes[c.scope_id].kind == "FUNCTION" for c in calls)
    assert (
        witness.syntax_context.gaps
        == witness.scoped_context.gaps
        == witness.call_context.gaps
        == ()
    )
    assert witness.syntax_context.unmatched_typed_call_indices == ()
    assert all(c.typed_match == "EXACT_SPAN" for c in witness.syntax_context.calls)
    assert {c.kind for c in witness.syntax_context.calls} >= {
        "CREATION",
        "INHERITANCE_ARGUMENTS",
        "MODIFIER_ARGUMENTS",
    }
    assert not witness.syntax_context.complete_static_resolution


def test_initializer_nested_creation_and_returned_contract_member_dependencies_are_retained():
    manifest = constructor_manifest()
    witness = manifest.dependency_evidence
    calls = witness.call_context.calls
    observe = next(c for c in calls if c.source == "Factory.sol" and c.callee == "observe")
    assert len(observe.arguments[0].nested_call_offsets) == 1
    nested = next(
        c
        for c in calls
        if c.source == observe.source
        and c.call_byte_start == observe.arguments[0].nested_call_offsets[0]
    )
    assert nested.dispatch == "CREATION" and nested.callee == "Product"
    values = [c for c in calls if c.callee == "value" and c.receiver is not None]
    assert len(values) == 2 and all(c.member_ids for c in values)
    assert any(c.receiver.nested_call_offsets for c in values)
    primary = next(p for p in witness.call_context.primaries if p.primary == "Factory.sol")
    assert set(primary.members) == {p for p, _ in constructor_sources()}
    assert primary.unresolved_call_indices == ()
    prompt = render_development_corpus_sources(manifest, constructor_sources(), "Factory.sol")
    assert "Constructors are not inherited overloads" in prompt
    assert witness.call_context.model_dump_json() in prompt
    assert "CALL_CLOSED remains unavailable" in prompt


@pytest.mark.parametrize(
    "path,before,after,shortfall",
    [
        (
            "Factory.sol",
            "new Product(uint256(n))",
            "new Missing(uint256(n))",
            "TYPE_NAME_NOT_RESOLVED",
        ),
        (
            "Factory.sol",
            "new Product(uint256(n))",
            "new Product(true)",
            "CONSTRUCTOR_ARGUMENT_TYPE_MISMATCH",
        ),
        (
            "Factory.sol",
            "new Product(uint256(n))",
            "new Product()",
            "CONSTRUCTOR_ARGUMENT_COUNT_MISMATCH",
        ),
        (
            "Factory.sol",
            "new Implicit()",
            "new Implicit(1)",
            "IMPLICIT_CONSTRUCTOR_ARGUMENTS_NOT_EMPTY",
        ),
        (
            "Factory.sol",
            "new Product(uint256(n))",
            "new Product{value: 0}(n)",
            "CONSTRUCTOR_CALL_OPTIONS_UNRESOLVED",
        ),
        (
            "Factory.sol",
            "new Product(uint256(n))",
            "new Product({initial: n})",
            "EXPRESSION_FORM_NOT_RESOLVED",
        ),
        (
            "Products.sol",
            "contract Product is Base",
            "abstract contract Product is Base",
            "ABSTRACT_CONTRACT_CREATION",
        ),
        (
            "Products.sol",
            "contract Implicit is Guard { }",
            "interface Implicit { }",
            "CONSTRUCTOR_TARGET_NOT_CONTRACT",
        ),
        (
            "Products.sol",
            "contract Implicit is Guard { }",
            "library Implicit { }",
            "CONSTRUCTOR_TARGET_NOT_CONTRACT",
        ),
        (
            "Products.sol",
            "constructor(uint256 initial) Base(uint256(initial)) { }",
            "constructor(uint256 initial) Base(uint256(initial));",
            "CONSTRUCTOR_BODY_NOT_SUPPLIED",
        ),
        (
            "Products.sol",
            "constructor(uint256 initial) Base(uint256(initial)) { }",
            "constructor(uint256 initial) Base(uint256(initial)) { } constructor() { }",
            "CONSTRUCTOR_DECLARATION_NOT_UNIQUE",
        ),
        ("Products.sol", "Base(uint256(initial))", "", "MISSING_BASE_CONSTRUCTOR_ARGUMENTS"),
        (
            "Products.sol",
            "contract Product is Base {",
            "contract Product is Base(uint256(2)) {",
            "DUPLICATE_BASE_CONSTRUCTOR_ARGUMENTS",
        ),
        (
            "Products.sol",
            "Base(uint256(initial))",
            "Base(true)",
            "CONSTRUCTOR_ARGUMENT_TYPE_MISMATCH",
        ),
        (
            "Products.sol",
            "Base(uint256(initial))",
            "Implicit()",
            "BASE_CONSTRUCTOR_TARGET_OUTSIDE_ANCESTRY",
        ),
        (
            "Products.sol",
            "Base(uint256(initial))",
            "Base(seed)",
            "BASE_ARGUMENT_VALUE_SCOPE_UNSUPPORTED",
        ),
        ("Products.sol", "Base(uint256(7))", "Base(initial)", "EXPRESSION_NAME_NOT_RESOLVED"),
        ("Products.sol", "Base(uint256(initial))", "Base", "BASE_ARGUMENT_CALL_NOT_RESOLVED"),
        (
            "Products.sol",
            "constructor(uint256 initial)",
            "constructor(uint256 initial) public",
            "CONSTRUCTOR_DECLARATION_FORM_UNSUPPORTED",
        ),
        (
            "Products.sol",
            "constructor(uint256 initial)",
            "constructor(uint256 initial) returns(uint256)",
            "CONSTRUCTOR_DECLARATION_FORM_UNSUPPORTED",
        ),
    ],
)
def test_invalid_or_incomplete_constructor_never_earns_a_binding(path, before, after, shortfall):
    files = changed_sources(path, before, after)
    witness = constructor_manifest(files).dependency_evidence
    calls = witness.call_context.calls
    affected = [c for c in calls if shortfall in c.shortfalls]
    assert affected, [(c.callee, c.shortfalls) for c in calls]
    assert all(c.resolution == "NOT_ESTABLISHED" for c in affected)
    assert all(p.call_closure == "NOT_ESTABLISHED" for p in witness.primaries)


def test_constructor_arguments_on_an_ordinary_function_are_never_base_initialization():
    files = changed_sources(
        "Products.sol", "constructor(uint256 initial)", "function wrong(uint256 initial) public"
    )
    manifest = constructor_manifest(files)
    assert any(
        "BASE_CONSTRUCTOR_HEADER_UNRESOLVED" in c.shortfalls
        for c in manifest.dependency_evidence.call_context.calls
    )
    assert any(
        "MISSING_BASE_CONSTRUCTOR_ARGUMENTS" in c.shortfalls for c in constructions(manifest)
    )


@pytest.mark.parametrize("path", ["Guard.sol", "Bases.sol"])
def test_missing_ancestor_source_is_recorded_without_dropping_creation(path):
    files = tuple((p, raw) for p, raw in constructor_sources() if p != path)
    manifest = constructor_manifest(files)
    assert manifest.dependency_closure == "NOT_ESTABLISHED"
    assert constructions(manifest)
    assert all(c.shortfalls for c in constructions(manifest))
    assert any(
        i.shortfall == "MISSING_SUPPLIED_SOURCE" for i in manifest.dependency_evidence.imports
    )


@pytest.mark.parametrize("dispatch", ["CREATION", "BASE_CONSTRUCTOR"])
def test_independent_grammar_census_exposes_each_missing_constructor_call(dispatch):
    manifest = constructor_manifest()
    context = manifest.dependency_evidence.call_context
    removed = next(c for c in context.calls if c.dispatch == dispatch)
    changed = context.model_copy(update={"calls": tuple(c for c in context.calls if c != removed)})
    grammar = build_dependency_syntax_context(
        source_files=constructor_sources(), call_context=changed
    )
    assert any(
        c.source == removed.source
        and c.call_byte_start == removed.call_byte_start
        and c.typed_match == "MISSING_TYPED_CALL"
        for c in grammar.calls
    )
    assert not grammar.complete_static_resolution


@pytest.mark.parametrize("change", ["body", "arguments", "ancestor", "new_constructor"])
def test_exact_source_recomputation_rejects_constructor_drift(change):
    manifest = constructor_manifest()
    path, before, after = {
        "body": ("Bases.sol", "seed = initial", "seed = 0"),
        "arguments": ("Products.sol", "Base(uint256(initial))", "Base(uint256(1))"),
        "ancestor": ("Products.sol", "contract Product is Base", "contract Product is Guard"),
        "new_constructor": (
            "Products.sol",
            "contract Implicit is Guard { }",
            "contract Implicit is Guard { constructor() {} }",
        ),
    }[change]
    with pytest.raises(ValueError):
        validate_development_corpus_sources(manifest, changed_sources(path, before, after))


def test_rehashed_constructor_omission_is_not_source_evidence():
    payload = constructor_manifest().model_dump(mode="json")
    witness = payload["dependency_evidence"]
    call = next(c for c in witness["call_context"]["calls"] if c["dispatch"] == "CREATION")
    call.pop("constructor_binding")
    call["shortfalls"] = ["FORGED_UNRESOLVED_CONSTRUCTION"]
    call["resolution"] = "NOT_ESTABLISHED"
    # Source replay is mandatory even if every public context/hash is rebuilt consistently.
    for primary in witness["call_context"]["primaries"]:
        primary["unresolved_call_indices"] = [
            i
            for i, c in enumerate(witness["call_context"]["calls"])
            if c["source"] in primary["members"] and c["resolution"] == "NOT_ESTABLISHED"
        ]
    witness["syntax_context"]["call_context_sha256"] = canonical_sha256(witness["call_context"])
    forged = DevelopmentCorpusManifest.model_validate_json(json.dumps(resign(payload)))
    with pytest.raises(ValueError, match="source recomputation"):
        validate_development_corpus_sources(forged, constructor_sources())


def test_default_constructor_never_borrows_its_parameterized_ancestor_signature():
    files = changed_sources("Factory.sol", "new HeaderProduct()", "new HeaderProduct(7)")
    call = next(
        c for c in constructions(constructor_manifest(files)) if c.callee == "HeaderProduct"
    )
    assert call.member_ids == call.candidate_member_ids == ()
    assert "IMPLICIT_CONSTRUCTOR_ARGUMENTS_NOT_EMPTY" in call.shortfalls


def test_missing_abstract_member_body_blocks_concrete_creation_binding():
    files = changed_sources("Bases.sol", "{ return seed; }", ";")
    calls = constructions(constructor_manifest(files))
    assert all(
        "CONSTRUCTED_TYPE_ABSTRACTNESS_NOT_ESTABLISHED" in c.shortfalls
        for c in calls
        if c.callee != "Implicit"
    )


def test_recursive_constructor_argument_dependencies_stop_without_hiding_call_sites():
    files = changed_sources(
        "Products.sol", "Base(uint256(initial))", "Base(new Product(initial).value())"
    )
    manifest = constructor_manifest(files)
    context = manifest.dependency_evidence.call_context
    assert any("RECURSIVE_CONSTRUCTOR_DEPENDENCY" in c.shortfalls for c in context.calls)
    assert all(c.shortfalls for c in constructions(manifest) if c.callee == "Product")
    assert all(
        c.typed_match == "EXACT_SPAN" for c in manifest.dependency_evidence.syntax_context.calls
    )


def test_ambiguous_and_shadowed_creation_type_names_never_select_one_candidate():
    files = changed_sources(
        "Factory.sol", "function inspect(uint256 n)", "function inspect(uint256 n, uint256 Product)"
    )
    calls = constructions(constructor_manifest(files))
    assert any("CONSTRUCTOR_TYPE_NAME_SHADOWED" in c.shortfalls for c in calls)
    files = changed_sources(
        "Products.sol",
        "contract Implicit is Guard { }",
        "contract Implicit is Guard { } contract Implicit is Guard { }",
    )
    calls = constructions(constructor_manifest(files))
    assert all(c.shortfalls for c in calls if c.callee == "Implicit")


def test_minimum_constructor_graph_envelope_refuses_an_insufficient_bound(monkeypatch):
    from mmaudit.solidity import dependency_closure

    monkeypatch.setattr(dependency_closure, "MAX_DEPENDENCY_GRAPH_BYTES", 1024)
    with pytest.raises(ValueError, match="minimum typed semantic graph envelope"):
        constructor_manifest()


def test_constructor_context_preserves_exact_graph_omissions(monkeypatch):
    from mmaudit.solidity import dependency_closure

    monkeypatch.setattr(dependency_closure, "MAX_DEPENDENCY_GRAPH_BYTES", 8192)
    current = constructor_manifest().dependency_evidence
    previous = constructor_manifest(dependency_constructor_context=False).dependency_evidence
    assert not current.graph_generation_complete
    assert current.graph_edge_omissions or current.graph_fact_omissions
    assert current.graph_edge_omissions == previous.graph_edge_omissions
    assert current.graph_fact_omissions == previous.graph_fact_omissions
    assert current.graph_sha256 == previous.graph_sha256
    assert all(p.call_closure == "NOT_ESTABLISHED" for p in current.primaries)


@pytest.mark.parametrize(
    "path,before,after,shortfall",
    [
        (
            "Products.sol",
            "contract Implicit is Guard",
            "contract Implicit is Guard, Guard",
            "CONSTRUCTOR_DUPLICATE_DIRECT_BASE",
        ),
        (
            "Guard.sol",
            "abstract contract Guard",
            "library Guard",
            "INVALID_CONSTRUCTOR_ANCESTOR_KIND",
        ),
    ],
)
def test_constructor_ancestry_never_erases_duplicates_or_illegal_base_kinds(
    path, before, after, shortfall
):
    manifest = constructor_manifest(changed_sources(path, before, after))
    call = next(c for c in constructions(manifest) if c.callee == "Implicit")
    assert shortfall in call.shortfalls
    assert call.resolution == "NOT_ESTABLISHED"


@pytest.mark.parametrize(
    "change",
    [
        "old_manifest",
        "old_witness",
        "scoped_policy",
        "call_policy",
        "syntax_policy",
        "missing_binding",
        "wrong_dispatch",
    ],
)
def test_generated_schema_requires_exact_constructor_versions_policies_and_bound_evidence(change):
    path = Path(__file__).parents[2] / "schemas/development_corpus_manifest.schema.json"
    validator = Draft202012Validator(json.loads(path.read_text()))
    payload = constructor_manifest().model_dump(mode="json")
    validator.validate(payload)
    witness = payload["dependency_evidence"]
    if change == "old_manifest":
        payload["schema_version"] = "1.7"
    elif change == "old_witness":
        witness["schema_version"] = "1.5"
    elif change in {"scoped_policy", "call_policy", "syntax_policy"}:
        context, policy = {
            "scoped_policy": ("scoped_context", "MODERN_LEXICAL_VALUES_AND_MODIFIER_HEADERS_V2"),
            "call_policy": ("call_context", "SOURCE_CALL_AND_MODIFIER_RESOLUTION_V2"),
            "syntax_policy": ("syntax_context", "SOURCE_GRAMMAR_AND_MODIFIER_CENSUS_V2"),
        }[change]
        witness[context]["policy"] = policy
    else:
        call = next(c for c in witness["call_context"]["calls"] if c["dispatch"] == "CREATION")
        if change == "missing_binding":
            call.pop("constructor_binding")
        else:
            call["dispatch"] = "INTERNAL"
    with pytest.raises(ValidationError):
        validator.validate(payload)


@pytest.mark.parametrize("flag", [1, 0, None, "true", True])
def test_constructor_selection_is_strict_and_requires_modifier_context(flag):
    with pytest.raises(ValueError, match="constructor context"):
        constructor_manifest(dependency_constructor_context=flag, dependency_modifier_context=False)


def test_constructor_work_ceiling_refuses_without_truncating_evidence(monkeypatch):
    from mmaudit.solidity import dependency_scopes

    monkeypatch.setattr(dependency_scopes, "MAX_TARGET_WORK", 20)
    with pytest.raises(ValueError, match="work ceiling"):
        constructor_manifest()


def test_constructor_bindings_do_not_regrade_graph_or_establish_call_closure():
    current = constructor_manifest().dependency_evidence
    prior = constructor_manifest(dependency_constructor_context=False).dependency_evidence
    for field in (
        "graph_sha256",
        "graph_generation_complete",
        "graph_edge_omissions",
        "graph_fact_omissions",
        "graph_warnings",
        "graph_facts",
        "candidate_references",
        "primaries",
        "dependency_closure",
    ):
        assert getattr(current, field) == getattr(prior, field)


@pytest.mark.parametrize("case", json.loads((FIXTURE / "legacy_replay.json").read_text())["cases"])
def test_predecessor_artifacts_and_prompts_remain_byte_exact(case):
    golden = json.loads((FIXTURE / "legacy_replay.json").read_text())
    files = constructor_sources()
    assert {p: hashlib.sha256(raw).hexdigest() for p, raw in files} == golden["source_sha256s"]
    manifest = freeze_development_corpus(
        corpus_id="synthetic-constructor-legacy",
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
    assert (
        hashlib.sha256(
            render_development_corpus_sources(manifest, files, "Factory.sol").encode()
        ).hexdigest()
        == case["prompt_sha256"]
    )
