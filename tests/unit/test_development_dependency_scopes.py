"""Synthetic lexical/member evidence; no provider, compiler or deployed dispatch credit."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

import mmaudit.solidity.dependency_scopes as scopes
from mmaudit.models.development_corpus import (
    DevelopmentCorpusManifest,
    freeze_development_corpus,
    render_development_corpus_sources,
    validate_development_corpus_sources,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.solidity.dependency_closure import compute_development_dependency_closure
from mmaudit.solidity.dependency_scopes import (
    DependencyLexicalScope,
    DependencyScopedCall,
    DependencyScopedContext,
    build_dependency_scoped_context,
)
from tests.unit.test_development_dependency_closure import fixture_sources
from tests.unit.test_development_dependency_targets import controller_sources, target_manifest

FIXTURE = Path(__file__).parents[1] / "fixtures/solidity/dependency_scopes/Controller.sol"


def scoped_sources():
    files = dict(fixture_sources())
    files["src/Controller.sol"] = FIXTURE.read_bytes()
    return tuple(sorted(files.items()))


def scoped_context(source_files=None):
    files = scoped_sources() if source_files is None else source_files
    evidence = target_manifest(files).dependency_evidence
    return build_dependency_scoped_context(
        source_files=files, imports=evidence.imports, target_context=evidence.target_context
    )


def scoped_manifest(source_files=None):
    return freeze_development_corpus(
        corpus_id="synthetic-scoped-context",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
        source_files=scoped_sources() if source_files is None else source_files,
        dependency_remapping_text="@local/=lib/\n",
        dependency_target_context=True,
        dependency_scoped_context=True,
    )


def controller_calls(context):
    return [c for c in context.calls if c.source == "src/Controller.sol"]


def test_state_parameter_local_and_loop_values_bind_exact_lexical_declarations():
    context = scoped_context()
    calls = controller_calls(context)
    values = {v.id: v for v in context.values}
    assert len(calls) == 9
    assert [values[c.receiver_value_ids[0]].kind for c in calls[:-1]] == [
        "STATE",
        "PARAMETER",
        "LOCAL",
        "STATE",
        "LOCAL",
        "STATE",
        "LOCAL",
        "STATE",
    ]
    assert calls[-1].receiver_form == "TYPE_CAST"
    assert not calls[-1].receiver_value_ids  # The parameter of unrelated() is outside this scope.
    assert all(c.member_resolution == "DECLARATIONS_BOUND" for c in calls)
    assert all(
        len(c.member_declaration_ids) == 1 and len(c.implementation_member_ids) == 2 for c in calls
    )
    assert context.gaps == () and not context.complete_static_resolution
    primary = next(p for p in context.primaries if p.primary == "src/Controller.sol")
    assert primary.members == tuple(p for p, _ in scoped_sources())
    assert primary.unresolved_call_indices == ()


def test_each_record_and_member_body_has_an_exact_original_source_span():
    files = dict(scoped_sources())
    context = scoped_context()
    for record in (*context.scopes, *context.values, *context.functions):
        assert record.source_sha256 == hashlib.sha256(files[record.source]).hexdigest()
        assert record.id == canonical_sha256(record.model_dump(mode="json", exclude={"id"}))
        assert files[record.source][record.byte_start : record.byte_end]
    for value in context.values:
        assert files[value.source][value.name_byte_start :].startswith(value.name.encode())
    for function in context.functions:
        if function.body_byte_start is not None:
            body = files[function.source][function.body_byte_start : function.body_byte_end]
            assert body.startswith(b"{") and body.endswith(b"}")
    for call in context.calls:
        raw = files[call.source][call.byte_start : call.byte_end]
        assert raw.endswith(b")") and ("." + call.member).encode() in raw


@pytest.mark.parametrize(
    "directive,type_name",
    [
        ('import "./IReserve.sol";', "IReserve"),
        ('import {IReserve as API} from "./IReserve.sol";', "API"),
        ('import * as Types from "./IReserve.sol";', "Types.IReserve"),
        ('import "./IReserve.sol" as Types;', "Types.IReserve"),
    ],
)
def test_typed_parameter_import_aliases_bind_source_owned_interface_and_bodies(
    directive, type_name
):
    files = controller_sources(directive, "reserve.value()", type_name + " reserve")
    call = controller_calls(scoped_context(files))[0]
    assert call.receiver_form == "VALUE" and call.member_resolution == "DECLARATIONS_BOUND"
    assert len(call.implementation_member_ids) == 2


@pytest.mark.parametrize(
    "extra",
    [
        "function unrelated(uint256 IReserve) external pure {}",
        "function unrelated() external pure { uint256 IReserve = 1; }",
    ],
)
def test_unrelated_function_shadowing_does_not_poison_an_explicit_cast(extra):
    files = controller_sources('import "./IReserve.sol";', "IReserve(reserve).value()", extra=extra)
    call = controller_calls(scoped_context(files))[0]
    assert call.member_resolution == "DECLARATIONS_BOUND"


@pytest.mark.parametrize(
    "parameters,extra",
    [
        ("address reserve, uint256 IReserve", ""),
        ("address reserve", "uint256 private IReserve;"),
        (
            "address reserve",
            "function IReserve(address) internal pure returns (address) { return address(0); }",
        ),
    ],
)
def test_actual_visible_value_or_function_shadow_never_becomes_a_type_cast(parameters, extra):
    files = controller_sources(
        'import "./IReserve.sol";', "IReserve(reserve).value()", parameters, extra
    )
    call = controller_calls(scoped_context(files))[0]
    assert call.receiver.target_id is None
    assert "LEXICAL_TYPE_NAME_SHADOWED" in call.shortfalls
    assert call.member_resolution == "NOT_ESTABLISHED"


def test_duplicate_values_in_the_same_scope_retain_both_without_first_match_selection():
    files = controller_sources(
        'import "./IReserve.sol";', "reserve.value()", "IReserve reserve, IReserve reserve"
    )
    call = controller_calls(scoped_context(files))[0]
    assert len(call.receiver_value_ids) == 2 and call.receiver.target_id is None
    assert "AMBIGUOUS_VALUE_DECLARATION" in call.shortfalls


@pytest.mark.parametrize(
    "type_name,expression",
    [
        ("address", 'reserve.delegatecall(bytes(""))'),
        ("address payable", "reserve.transfer(0)"),
        ("IReserve[] memory", "reserve[0].value()"),
        ("function() external returns (IReserve)", "reserve().value()"),
    ],
)
def test_address_array_and_function_return_targets_do_not_invent_nominal_dispatch(
    type_name, expression
):
    files = controller_sources('import "./IReserve.sol";', expression, type_name + " reserve")
    call = controller_calls(scoped_context(files))[0]
    assert call.member_resolution == "NOT_ESTABLISHED" and call.receiver.target_id is None


@pytest.mark.parametrize("member,argument", [("missing", ""), ("value", "1"), ("transfer", "")])
def test_missing_member_or_wrong_arity_cannot_earn_a_member_binding(member, argument):
    files = controller_sources(
        'import "./IReserve.sol";', f"reserve.{member}({argument})", "IReserve reserve"
    )
    call = controller_calls(scoped_context(files))[0]
    assert "MEMBER_DECLARATION_NOT_RESOLVED" in call.shortfalls
    assert call.member_resolution == "NOT_ESTABLISHED"


def test_overloads_with_the_same_arity_are_retained_as_ambiguous_candidates():
    files = dict(
        controller_sources('import "./IReserve.sol";', "reserve.value(1)", "IReserve reserve")
    )
    files["src/IReserve.sol"] = files["src/IReserve.sol"].replace(
        b"function value()",
        b"function value(address) external returns (uint256); function value(uint256)",
    )
    call = controller_calls(scoped_context(tuple(sorted(files.items()))))[0]
    assert len(call.member_declaration_ids) == 2
    assert "OVERLOAD_OR_INHERITED_MEMBER_AMBIGUITY" in call.shortfalls


@pytest.mark.parametrize("change", ["missing", "abstract", "wrong_signature"])
def test_incomplete_implementation_bodies_are_not_treated_as_resolved(change):
    files = dict(
        controller_sources('import "./IReserve.sol";', "reserve.value()", "IReserve reserve")
    )
    if change == "missing":
        files.pop("src/Reserve.sol")
        files.pop("src/SecondReserve.sol")
    elif change == "abstract":
        files["src/Reserve.sol"] = (
            files["src/Reserve.sol"]
            .replace(b"contract Reserve", b"abstract contract Reserve")
            .replace(
                b"function value() external pure returns (uint256) {\n        return Math.zero();\n    }",
                b"function value() external pure returns (uint256);",
            )
        )
    else:
        files["src/Reserve.sol"] = files["src/Reserve.sol"].replace(
            b"function value()", b"function value(uint256)"
        )
    context = scoped_context(tuple(sorted(files.items())))
    call = controller_calls(context)[0]
    if change == "abstract":
        body = next(
            f for f in context.functions if f.source == "src/Reserve.sol" and f.name == "value"
        )
        assert body.body_byte_start is None
    assert call.member_resolution == "NOT_ESTABLISHED"
    assert set(call.shortfalls) & {
        "NO_SUPPLIED_IMPLEMENTER",
        "IMPLEMENTATION_MEMBER_BODY_NOT_UNIQUE",
    }


@pytest.mark.parametrize(
    "syntax,reason",
    [
        ("assembly { let unused := 0 }", "UNSUPPORTED_LEXICAL_REGION"),
        ("(IReserve other, uint256 amount) = unknown();", "UNSUPPORTED_TUPLE_DECLARATION"),
        ("try unknown() {} catch {}", "UNSUPPORTED_LEXICAL_REGION"),
    ],
)
def test_unparsed_lexical_regions_keep_a_shortfall_instead_of_leaking_outer_bindings(
    syntax, reason
):
    files = dict(
        controller_sources('import "./IReserve.sol";', "reserve.value()", "IReserve reserve")
    )
    files["src/Controller.sol"] = files["src/Controller.sol"].replace(
        b"return reserve.value()", syntax.encode() + b" return reserve.value()"
    )
    context = scoped_context(tuple(sorted(files.items())))
    assert reason in {g.reason for g in context.gaps}
    call = controller_calls(context)[0]
    assert call.member_resolution == "NOT_ESTABLISHED"
    assert "LEXICAL_SCOPE_NOT_ESTABLISHED" in call.shortfalls


@pytest.mark.parametrize(
    "expression,reason",
    [
        ("reserve.value{gas: 1000}()", "CALL_OPTIONS_NOT_RESOLVED"),
        ("reserve.value({amount: 1})", "CALL_ARGUMENT_FORM_UNRESOLVED"),
    ],
)
def test_unsupported_call_forms_cannot_gain_argument_or_member_precision(expression, reason):
    files = controller_sources('import "./IReserve.sol";', expression, "IReserve reserve")
    call = controller_calls(scoped_context(files))[0]
    assert reason in call.shortfalls and call.member_resolution == "NOT_ESTABLISHED"


@pytest.mark.parametrize("pragma", [b"^0.4.26", b">=0.4.26", b">=0.8.0<0.9.0", b"^0.9.0"])
def test_unproved_language_scope_policy_is_explicit(pragma):
    files = dict(
        controller_sources('import "./IReserve.sol";', "reserve.value()", "IReserve reserve")
    )
    files["src/Controller.sol"] = files["src/Controller.sol"].replace(b"^0.8.20", pragma)
    context = scoped_context(tuple(sorted(files.items())))
    assert "SCOPE_LANGUAGE_VERSION_NOT_ESTABLISHED" in {g.reason for g in context.gaps}
    assert controller_calls(context)[0].member_resolution == "NOT_ESTABLISHED"


@pytest.mark.parametrize(
    "limit",
    ["MAX_TARGET_RECORDS", "MAX_TARGET_WORK", "MAX_TARGET_CONTEXT_BYTES", "MAX_SCOPE_DEPTH"],
)
def test_complete_scoped_evidence_refuses_overflow_without_silent_truncation(monkeypatch, limit):
    monkeypatch.setattr(scopes, limit, 1)
    with pytest.raises(ValueError):
        scoped_context()


@pytest.mark.parametrize("value", [True, 0, 1, "false", None])
def test_scoped_context_cannot_claim_a_complete_typecheck(value):
    data = scoped_context().model_dump(mode="python")
    data["complete_static_resolution"] = value
    with pytest.raises(ValueError):
        DependencyScopedContext.model_validate(data)


def test_resealed_out_of_scope_parent_and_invented_member_ids_are_rejected():
    context = scoped_context()
    scope = next(s for s in context.scopes if s.kind == "FUNCTION")
    changed = scope.model_dump(mode="python", exclude={"id"})
    changed["parent_id"] = scope.id
    bad_scope = DependencyLexicalScope.create(**changed)
    data = context.model_dump(mode="python")
    data["scopes"] = tuple(bad_scope if s.id == scope.id else s for s in context.scopes)
    with pytest.raises(ValueError):
        DependencyScopedContext.model_validate(data)
    call = context.calls[0].model_dump(mode="python")
    call["member_declaration_ids"] = ("0" * 64,)
    data = context.model_dump(mode="python")
    data["calls"] = (DependencyScopedCall.model_validate(call), *context.calls[1:])
    with pytest.raises(ValueError):
        DependencyScopedContext.model_validate(data)


def test_member_claim_cannot_ignore_recorded_shortfalls():
    call = scoped_context().calls[0].model_dump(mode="python")
    call["shortfalls"] = ("UNRESOLVED",)
    with pytest.raises(ValueError):
        DependencyScopedCall.model_validate(call)


@pytest.mark.parametrize("visibility", ["internal", "private"])
def test_inherited_state_visibility_is_part_of_lexical_lookup(visibility):
    files = dict(
        controller_sources('import "./IReserve.sol"; import "./Base.sol";', "reserve.value()", "")
    )
    files["src/Controller.sol"] = files["src/Controller.sol"].replace(
        b"contract Controller {", b"contract Controller is Base {"
    )
    files["src/Base.sol"] = (
        "// Synthetic source-only scope control.\npragma solidity ^0.8.20;\n"
        'import "./IReserve.sol";\ncontract Base { constructor() { revert(); } IReserve '
        + visibility
        + " reserve; }\n"
    ).encode()
    context = scoped_context(tuple(sorted(files.items())))
    call = controller_calls(context)[0]
    if visibility == "internal":
        assert call.member_resolution == "DECLARATIONS_BOUND"
        value = next(v for v in context.values if v.id == call.receiver_value_ids[0])
        assert value.source == "src/Base.sol"
    else:
        assert not call.receiver_value_ids and call.member_resolution == "NOT_ESTABLISHED"


def test_conflicting_inherited_values_are_not_selected_by_source_or_parent_order():
    files = dict(
        controller_sources('import "./IReserve.sol"; import "./Bases.sol";', "reserve.value()", "")
    )
    files["src/Controller.sol"] = files["src/Controller.sol"].replace(
        b"contract Controller {", b"contract Controller is First, Second {"
    )
    files["src/Bases.sol"] = (
        b'// Synthetic conflicting scope control.\npragma solidity ^0.8.20;\nimport "./IReserve.sol";\n'
        b"contract First { constructor() { revert(); } IReserve internal reserve; }\n"
        b"contract Second { constructor() { revert(); } IReserve internal reserve; }\n"
    )
    call = controller_calls(scoped_context(tuple(sorted(files.items()))))[0]
    assert len(call.receiver_value_ids) == 2
    assert "AMBIGUOUS_VALUE_DECLARATION" in call.shortfalls


def test_local_type_name_shadow_does_not_bind_a_subsequent_declaration_to_the_import():
    files = dict(controller_sources('import "./IReserve.sol";', "reserve.value()", ""))
    files["src/Controller.sol"] = files["src/Controller.sol"].replace(
        b"return reserve.value()", b"uint256 IReserve = 0; IReserve reserve; return reserve.value()"
    )
    context = scoped_context(tuple(sorted(files.items())))
    call = controller_calls(context)[0]
    assert call.member_resolution == "NOT_ESTABLISHED"
    assert "LEXICAL_TYPE_NAME_SHADOWED" in call.shortfalls


def test_local_initializer_and_prior_references_see_the_outer_value_not_a_future_local():
    files = dict(
        controller_sources(
            'import "./IReserve.sol";', "reserve.value()", "", "IReserve private reserve;"
        )
    )
    files["src/Controller.sol"] = files["src/Controller.sol"].replace(
        b"return reserve.value()",
        b"reserve.value(); IReserve reserve = IReserve(address(reserve)); return reserve.value()",
    )
    context = scoped_context(tuple(sorted(files.items())))
    calls = controller_calls(context)
    values = {v.id: v for v in context.values}
    assert [values[c.receiver_value_ids[0]].kind for c in calls] == ["STATE", "LOCAL"]
    assert all(c.member_resolution == "DECLARATIONS_BOUND" for c in calls)


@pytest.mark.parametrize("branch", ["if (true)", "while (false)"])
def test_unbraced_control_statement_cannot_leak_a_local_into_the_parent(branch):
    files = dict(
        controller_sources(
            'import "./IReserve.sol";', "reserve.value()", "", "IReserve private reserve;"
        )
    )
    files["src/Controller.sol"] = files["src/Controller.sol"].replace(
        b"return reserve.value()", branch.encode() + b" IReserve reserve; return reserve.value()"
    )
    context = scoped_context(tuple(sorted(files.items())))
    call = controller_calls(context)[0]
    value = next(v for v in context.values if v.id == call.receiver_value_ids[0])
    assert value.kind == "STATE"


@pytest.mark.parametrize("change", ["private", "return_type"])
def test_nominal_implementation_member_visibility_and_return_types_are_checked(change):
    files = dict(
        controller_sources('import "./IReserve.sol";', "reserve.value()", "IReserve reserve")
    )
    if change == "private":
        files["src/Reserve.sol"] = files["src/Reserve.sol"].replace(
            b"external pure", b"private pure"
        )
    else:
        files["src/Reserve.sol"] = files["src/Reserve.sol"].replace(
            b"returns (uint256)", b"returns (address)"
        )
    call = controller_calls(scoped_context(tuple(sorted(files.items()))))[0]
    assert "IMPLEMENTATION_SIGNATURE_OR_VISIBILITY_MISMATCH" in call.shortfalls
    assert call.member_resolution == "NOT_ESTABLISHED"


def test_non_instance_contract_member_syntax_does_not_masquerade_as_an_interface_call():
    files = controller_sources('import "./IReserve.sol";', "IReserve.value()", "")
    call = controller_calls(scoped_context(files))[0]
    assert "EXPLICIT_CONTRACT_MEMBER_DISPATCH_UNRESOLVED" in call.shortfalls


def test_inherited_member_body_is_bound_to_its_actual_source_not_the_nominal_child():
    files = dict(
        controller_sources('import "./IReserve.sol";', "reserve.value()", "IReserve reserve")
    )
    files["src/Child.sol"] = (
        b'// Synthetic inherited-body control.\npragma solidity ^0.8.20;\nimport "./Reserve.sol";\n'
        b"contract Child is Reserve { constructor() { revert(); } }\n"
    )
    context = scoped_context(tuple(sorted(files.items())))
    call = controller_calls(context)[0]
    assert len(call.implementation_ids) == 3 and len(call.implementation_member_ids) == 2
    assert call.member_resolution == "DECLARATIONS_BOUND"
    assert all(
        f.source != "src/Child.sol"
        for f in context.functions
        if f.id in call.implementation_member_ids
    )


def test_ambiguous_inherited_member_bodies_remain_explicit():
    files = dict(
        controller_sources('import "./IReserve.sol";', "reserve.value()", "IReserve reserve")
    )
    files["src/Child.sol"] = (
        b"// Synthetic conflicting-body control.\npragma solidity ^0.8.20;\n"
        b'import "./Reserve.sol"; import "./SecondReserve.sol";\n'
        b"contract Child is Reserve, SecondReserve { constructor() { revert(); } }\n"
    )
    call = controller_calls(scoped_context(tuple(sorted(files.items()))))[0]
    assert "IMPLEMENTATION_MEMBER_BODY_NOT_UNIQUE" in call.shortfalls


def test_comments_and_strings_cannot_create_scopes_values_or_members():
    files = dict(scoped_sources())
    files["src/Controller.sol"] = files["src/Controller.sol"].replace(
        b"return reserve.value();",
        b'/* } IReserve fake; fake.hidden(); */ string memory note = "{ fake.hidden();"; return reserve.value();',
        1,
    )
    context = scoped_context(tuple(sorted(files.items())))
    assert len(controller_calls(context)) == 9
    assert not any(v.name == "fake" for v in context.values)
    assert all(c.member != "hidden" for c in context.calls)


def test_scoped_evidence_is_versioned_and_recomputed_from_actual_source_bytes():
    manifest = scoped_manifest()
    evidence = manifest.dependency_evidence
    assert (manifest.schema_version, evidence.schema_version) == ("1.4", "1.2")
    assert evidence.scoped_context == scoped_context()
    assert manifest.inventory_scope == "EXPLICIT_MANIFEST_ONLY"
    assert manifest.source_tree_evidence is None
    validate_development_corpus_sources(manifest, scoped_sources())
    prompt = render_development_corpus_sources(
        manifest, scoped_sources(), primary_filename="src/Controller.sol"
    )
    assert evidence.scoped_context.model_dump_json() in prompt
    assert "DECLARATIONS_BOUND identifies exact supplied member declarations" in prompt
    assert "Full static call closure remains NOT_ESTABLISHED" in prompt
    assert all(p.call_closure == "NOT_ESTABLISHED" for p in evidence.primaries)


@pytest.mark.parametrize("value", [None, 0, 1, "true"])
def test_scoped_opt_in_is_strict_and_does_not_enable_itself(value):
    with pytest.raises(ValueError):
        freeze_development_corpus(
            corpus_id="scope",
            source_scope="OPERATOR_SUPPLIED_PROTOCOL",
            source_files=fixture_sources(),
            dependency_remapping_text="",
            dependency_target_context=True,
            dependency_scoped_context=value,
        )
    with pytest.raises(ValueError):
        compute_development_dependency_closure(
            source_files=fixture_sources(),
            include_target_context=True,
            include_scoped_context=value,
        )


def test_scoped_context_cannot_skip_the_underlying_target_namespace():
    with pytest.raises(ValueError):
        compute_development_dependency_closure(
            source_files=fixture_sources(), include_scoped_context=True
        )


def test_missing_pragma_does_not_gain_an_implicit_modern_scope_claim():
    files = dict(scoped_sources())
    files["src/Controller.sol"] = files["src/Controller.sol"].replace(
        b"pragma solidity ^0.8.20;", b""
    )
    context = scoped_context(tuple(sorted(files.items())))
    assert "SCOPE_LANGUAGE_VERSION_NOT_ESTABLISHED" in {g.reason for g in context.gaps}
    assert all(c.member_resolution == "NOT_ESTABLISHED" for c in controller_calls(context))


@pytest.mark.parametrize("version", ["1.0", "1.1", "1.2", "1.3"])
def test_scoped_evidence_cannot_be_resealed_as_an_old_manifest_version(version):
    data = scoped_manifest().model_dump(mode="json")
    data["schema_version"] = version
    data["manifest_sha256"] = canonical_sha256(
        {k: v for k, v in data.items() if k != "manifest_sha256"}
    )
    with pytest.raises(ValueError):
        DevelopmentCorpusManifest.model_validate_json(json.dumps(data))


@pytest.mark.parametrize("change", ["body", "receiver", "members"])
def test_resealed_scoped_context_cannot_change_what_actual_source_resolution_computes(change):
    data = scoped_manifest().model_dump(mode="json")
    witness = data["dependency_evidence"]
    context = witness["scoped_context"]
    call = next(c for c in context["calls"] if c["source"] == "src/Controller.sol")
    if change == "body":
        call["implementation_member_ids"] = call["implementation_member_ids"][:1]
    elif change == "receiver":
        call["receiver_value_ids"] = []
    else:
        primary = next(p for p in context["primaries"] if p["primary"] == "src/Controller.sol")
        primary["members"].remove("src/SecondReserve.sol")
    witness["witness_sha256"] = canonical_sha256(
        {k: v for k, v in witness.items() if k != "witness_sha256"}
    )
    data["manifest_sha256"] = canonical_sha256(
        {k: v for k, v in data.items() if k != "manifest_sha256"}
    )
    parsed = DevelopmentCorpusManifest.model_validate_json(json.dumps(data))
    with pytest.raises(ValueError, match="source recomputation"):
        validate_development_corpus_sources(parsed, scoped_sources())


@pytest.mark.parametrize(
    "change",
    [
        "missing_scoped",
        "null_scoped",
        "old_witness",
        "missing_witness_version",
        "missing_target",
        "old_manifest",
        "unearned_tree_scope",
        "complete_resolution",
    ],
)
def test_generated_manifest_schema_enforces_scoped_versions_and_scope_boundaries(change):
    schema = json.loads(
        (Path(__file__).parents[2] / "schemas/development_corpus_manifest.schema.json").read_bytes()
    )
    validator = Draft202012Validator(schema)
    data = scoped_manifest().model_dump(mode="json")
    validator.validate(data)
    witness = data["dependency_evidence"]
    if change == "missing_scoped":
        witness.pop("scoped_context")
    elif change == "null_scoped":
        witness["scoped_context"] = None
    elif change == "old_witness":
        witness["schema_version"] = "1.1"
    elif change == "missing_witness_version":
        witness.pop("schema_version")
    elif change == "missing_target":
        witness.pop("target_context")
    elif change == "old_manifest":
        data["schema_version"] = "1.2"
    elif change == "unearned_tree_scope":
        data["inventory_scope"] = "LOCAL_TREE_SNAPSHOT_REQUIRES_ROOT_REPLAY"
    else:
        witness["scoped_context"]["complete_static_resolution"] = True
    with pytest.raises(ValidationError):
        validator.validate(data)
