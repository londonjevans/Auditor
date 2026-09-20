"""Source-only argument/return and overload resolution on non-deployable synthetic input."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

import mmaudit.solidity.dependency_calls as calls
from mmaudit.models.development_corpus import (
    DevelopmentCorpusManifest,
    freeze_development_corpus,
    render_development_corpus_sources,
    validate_development_corpus_sources,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.solidity.dependency_calls import (
    DependencyCallContext,
    DependencyExpressionType,
    build_dependency_call_context,
)

FIXTURE = Path(__file__).parents[1] / "fixtures/solidity/dependency_calls/Calls.sol"


def call_sources():
    return (("Calls.sol", FIXTURE.read_bytes()),)


def split_call_sources():
    raw = FIXTURE.read_text()
    names = ["IReserve", "IFactory", "ReserveA", "ReserveB", "Factory", "Controller"]
    markers = [
        ("interface " if name.startswith("I") else "contract ") + name + " " for name in names
    ]
    starts = [raw.index(marker) for marker in markers]
    dependencies = {
        "IReserve": [],
        "IFactory": ["IReserve"],
        "ReserveA": ["IReserve"],
        "ReserveB": ["IReserve"],
        "Factory": ["IFactory", "IReserve"],
        "Controller": ["IFactory", "IReserve"],
    }
    files = []
    for index, name in enumerate(names):
        body = raw[starts[index] : starts[index + 1] if index + 1 < len(starts) else len(raw)]
        imports = "".join(f'import "./{dependency}.sol";\n' for dependency in dependencies[name])
        files.append(
            (
                name + ".sol",
                (
                    "// Synthetic non-deployable source-only fixture.\npragma solidity ^0.8.24;\n"
                    + imports
                    + body
                ).encode(),
            )
        )
    return tuple(sorted(files))


def typed_context(files=None):
    source_files = call_sources() if files is None else files
    manifest = freeze_development_corpus(
        corpus_id="synthetic-typed-calls",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
        source_files=source_files,
        dependency_remapping_text="",
        dependency_target_context=True,
        dependency_scoped_context=True,
    )
    witness = manifest.dependency_evidence
    context = build_dependency_call_context(
        source_files=source_files,
        imports=witness.imports,
        target_context=witness.target_context,
        scoped_context=witness.scoped_context,
    )
    return context, witness


def replace_source(before, after):
    source = FIXTURE.read_bytes()
    assert before.encode() in source
    return (("Calls.sol", source.replace(before.encode(), after.encode())),)


def typed_manifest(files=None):
    return freeze_development_corpus(
        corpus_id="synthetic-typed-calls",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
        source_files=call_sources() if files is None else files,
        dependency_remapping_text="",
        dependency_target_context=True,
        dependency_scoped_context=True,
        dependency_call_context=True,
    )


def test_typed_arguments_select_different_overloads_and_all_nominal_bodies():
    context, witness = typed_context()
    functions = {f.id: f for f in witness.scoped_context.functions}
    selected = [c for c in context.calls if c.callee == "value"]
    assert len(selected) == 3
    assert all(c.resolution == "STATIC_DECLARATIONS_BOUND" for c in context.calls)
    assert [functions[c.member_ids[0]].parameters[0].spelling for c in selected] == [
        "uint256",
        "bool",
        "uint256",
    ]
    assert all(
        len(c.candidate_member_ids) == 2 and len(c.implementation_member_ids) == 2 for c in selected
    )
    assert context.gaps == () and not context.complete_static_resolution


def test_external_and_internal_return_calls_bind_their_actual_nested_source_spans():
    context, _ = typed_context()
    source = FIXTURE.read_bytes()
    selected = [c for c in context.calls if c.callee == "value"]
    assert len(selected[1].receiver.nested_call_offsets) == 1
    assert len(selected[2].receiver.nested_call_offsets) == 1
    for call in context.calls:
        assert call.source_sha256 == hashlib.sha256(source).hexdigest()
        assert source[call.call_byte_start : call.call_byte_start + 1] == b"("
        assert source[call.byte_start : call.byte_end].endswith(b")")
    assert next(c for c in context.calls if c.callee == "choose").dispatch == "INTERNAL"


def test_returned_interface_and_exact_body_membership_cross_imported_source_boundaries():
    files = dict(split_call_sources())
    files["Controller.sol"] = (
        files["Controller.sol"]
        .replace(b'import "./IReserve.sol";', b'import {IReserve as API} from "./IReserve.sol";')
        .replace(b"IReserve selected", b"API selected")
        .replace(b"returns (IReserve)", b"returns (API)")
    )
    source_files = tuple(sorted(files.items()))
    context, witness = typed_context(source_files)
    functions = {f.id: f for f in witness.scoped_context.functions}
    calls_in_controller = [c for c in context.calls if c.source == "Controller.sol"]
    assert calls_in_controller and all(
        c.resolution == "STATIC_DECLARATIONS_BOUND" for c in calls_in_controller
    )
    for call in calls_in_controller:
        if call.callee == "value":
            assert {functions[i].source for i in call.implementation_member_ids} == {
                "ReserveA.sol",
                "ReserveB.sol",
            }
            assert {functions[i].source for i in call.member_ids} == {"IReserve.sol"}
    primary = next(p for p in context.primaries if p.primary == "Controller.sol")
    assert primary.members == tuple(files)
    manifest = typed_manifest(source_files)
    validate_development_corpus_sources(manifest, source_files)
    assert context.model_dump_json() in render_development_corpus_sources(
        manifest, source_files, "Controller.sol"
    )


@pytest.mark.parametrize("expression", ["1", "uint256(1)", "amount + 1", "(amount)"])
def test_supported_integer_arguments_and_explicit_conversions_bind(expression):
    context, _ = typed_context(
        replace_source("selected.value(amount)", f"selected.value({expression})")
    )
    call = next(c for c in context.calls if c.callee == "value")
    assert call.resolution == "STATIC_DECLARATIONS_BOUND"


def test_integer_literal_does_not_pick_the_first_of_two_compatible_overloads():
    files = replace_source("value(bool choice)", "value(uint8 choice)")
    files = (("Calls.sol", files[0][1].replace(b"selected.value(amount)", b"selected.value(1)")),)
    context, _ = typed_context(files)
    call = next(c for c in context.calls if c.callee == "value")
    assert len(call.member_ids) == 2
    assert "OVERLOAD_OR_INHERITED_MEMBER_AMBIGUITY" in call.shortfalls
    assert call.resolution == "NOT_ESTABLISHED"


@pytest.mark.parametrize("expression", ["missing", "amount[0]", "factory", "uint8(300)"])
def test_unknown_or_incompatible_argument_never_becomes_unique_arity_success(expression):
    context, _ = typed_context(
        replace_source("selected.value(amount)", f"selected.value({expression})")
    )
    call = next(c for c in context.calls if c.callee == "value")
    assert call.resolution == "NOT_ESTABLISHED" and call.shortfalls


@pytest.mark.parametrize("literal", ["true", "false", "this", "(", ")"])
def test_string_contents_do_not_become_boolean_values_or_call_syntax(literal):
    context, _ = typed_context(
        replace_source("selected.value(amount)", f'selected.value("{literal}")')
    )
    call = next(c for c in context.calls if c.callee == "value")
    assert call.arguments[0].expression_type.kind == "STRING_LITERAL"
    assert call.resolution == "NOT_ESTABLISHED"
    assert len(context.calls) == len(typed_context()[0].calls)


def test_wrong_return_type_prevents_a_chained_receiver_binding():
    files = replace_source("returns (IReserve)", "returns (address)")
    context, _ = typed_context(files)
    chained = [c for c in context.calls if c.callee == "value"][-1]
    assert "CALL_RECEIVER_TYPE_NOT_ESTABLISHED" in chained.shortfalls
    assert chained.resolution == "NOT_ESTABLISHED"


def test_missing_implementation_body_is_not_fixed_by_a_return_type_declaration():
    files = replace_source(
        "function reserve() external pure returns (IReserve) { return IReserve(address(0)); }",
        "function reserve() external view returns (IReserve);",
    )
    context, _ = typed_context(files)
    factory_call = next(c for c in context.calls if c.callee == "reserve")
    assert "IMPLEMENTATION_MEMBER_BODY_NOT_UNIQUE" in factory_call.shortfalls
    assert any(c.callee == "value" and c.resolution == "NOT_ESTABLISHED" for c in context.calls)


def test_expression_depth_refuses_without_truncating_the_call_population(monkeypatch):
    monkeypatch.setattr(calls, "MAX_EXPRESSION_DEPTH", 1)
    with pytest.raises(ValueError, match="depth ceiling"):
        typed_context()


@pytest.mark.parametrize(
    "actual,expected,accepted",
    [
        ("uint8", "uint256", True),
        ("uint256", "uint8", False),
        ("uint8", "int16", True),
        ("uint8", "int8", False),
        ("int8", "uint16", False),
        ("int8", "int256", True),
        ("bytes1", "bytes32", True),
        ("bytes32", "bytes1", False),
        ("bytes1", "bytes", False),
        ("bytes", "bytes32", False),
        ("string", "bytes", False),
        ("bytes", "string", False),
        ("bool", "bool", True),
        ("bool", "uint8", False),
        ("addresspayable", "address", True),
        ("address", "addresspayable", False),
        ("uint160", "address", False),
        ("address", "uint160", False),
    ],
)
def test_supported_implicit_type_relation_preserves_every_applicable_overload(
    actual, expected, accepted
):
    _, witness = typed_context()
    builder = calls._Builder(call_sources(), witness.imports, witness.target_context)
    resolver = calls._Resolver(builder, call_sources())
    assert resolver.accepts(calls._builtin(actual), calls._builtin(expected)) is accepted


@pytest.mark.parametrize("version", ["0.5.17", "0.6.12", "0.7.6", "0.8.24"])
def test_global_address_payability_is_not_guessed_across_language_versions(version):
    files = replace_source("value(uint256 amount)", "value(address amount)")
    raw = (
        files[0][1]
        .replace(b"selected.value(amount)", b"selected.value(msg.sender)")
        .replace(b"0.8.24", version.encode())
    )
    context, _ = typed_context((("Calls.sol", raw),))
    selected = next(c for c in context.calls if c.callee == "value")
    assert selected.resolution == (
        "STATIC_DECLARATIONS_BOUND" if version.startswith("0.8.") else "NOT_ESTABLISHED"
    )
    if not version.startswith("0.8."):
        assert "GLOBAL_VALUE_LANGUAGE_VERSION_NOT_ESTABLISHED" in selected.shortfalls


@pytest.mark.parametrize(
    "type_name", ["string calldata", "string memory", "bytes calldata", "bytes memory"]
)
def test_reference_data_location_is_not_erased_to_select_an_internal_overload(type_name):
    files = replace_source("uint256 amount", type_name + " amount")
    context, _ = typed_context(files)
    selected = next(c for c in context.calls if c.callee == "value")
    assert selected.resolution == "NOT_ESTABLISHED"
    assert "REFERENCE_LOCATION_NOT_ESTABLISHED" in selected.shortfalls


@pytest.mark.parametrize("target", ["PayableBase", "PayableChild"])
@pytest.mark.parametrize("value_type", ["address", "address payable", "PayableBase"])
def test_nominal_conversion_accounts_for_inherited_payability(target, value_type):
    suffix = (
        "contract PayableBase { constructor() { revert(); } receive() external payable {} } "
        "contract PayableChild is PayableBase {} "
        "contract ConversionProbe { constructor() { revert(); } function inspect("
        + value_type
        + " supplied) external pure returns ("
        + target
        + ") { return "
        + target
        + "(supplied); } }"
    )
    files = (("Calls.sol", call_sources()[0][1] + suffix.encode()),)
    context, _ = typed_context(files)
    selected = next(c for c in context.calls if c.callee == target)
    assert selected.resolution == (
        "STATIC_DECLARATIONS_BOUND"
        if value_type in {"address payable", target}
        else "NOT_ESTABLISHED"
    )
    if value_type not in {"address payable", target}:
        assert "EXPLICIT_CONVERSION_NOT_ESTABLISHED" in selected.shortfalls


@pytest.mark.parametrize("inheritance", ["MissingBase", "UnknownChild"])
def test_nominal_conversion_never_ignores_missing_or_cyclic_ancestry(inheritance):
    suffix = (
        "contract UnknownChild is " + inheritance + " { constructor() { revert(); } } "
        "contract ConversionProbe { constructor() { revert(); } function inspect(address supplied) "
        "external pure returns (UnknownChild) { return UnknownChild(supplied); } }"
    )
    context, _ = typed_context((("Calls.sol", call_sources()[0][1] + suffix.encode()),))
    selected = next(c for c in context.calls if c.callee == "UnknownChild")
    assert "CONVERSION_NAMESPACE_OR_PARSE_GAPS" in selected.shortfalls
    assert selected.resolution == "NOT_ESTABLISHED"


@pytest.mark.parametrize("argument", ["uint8(1)", "amount"])
def test_fixed_width_overload_matching_does_not_collapse_implicit_widening(argument):
    files = replace_source("value(bool choice)", "value(uint8 choice)")
    files = (
        (
            "Calls.sol",
            files[0][1].replace(b"selected.value(amount)", f"selected.value({argument})".encode()),
        ),
    )
    context, _ = typed_context(files)
    selected = next(c for c in context.calls if c.callee == "value")
    assert len(selected.member_ids) == (2 if argument == "uint8(1)" else 1)
    assert selected.resolution == (
        "NOT_ESTABLISHED" if argument == "uint8(1)" else "STATIC_DECLARATIONS_BOUND"
    )


@pytest.mark.parametrize(
    "expression,reason",
    [
        ("selected.value{gas: 1}(amount)", "CALL_OPTIONS_NOT_RESOLVED"),
        ("selected.value({amount: amount})", "EXPRESSION_FORM_NOT_RESOLVED"),
        ("selected.value(amount,)", "EMPTY_ARGUMENT_EXPRESSION"),
        ("selected.value(unknown(amount))", "DEPENDENT_CALL_RESULT_NOT_ESTABLISHED"),
        ("selected.value(amount > 0 ? 1 : 2)", "BINARY_EXPRESSION_TYPE_UNRESOLVED"),
    ],
)
def test_unsupported_argument_forms_keep_exact_shortfalls_and_nested_call_census(
    expression, reason
):
    context, _ = typed_context(replace_source("selected.value(amount)", expression))
    selected = next(c for c in context.calls if c.callee == "value")
    assert reason in selected.shortfalls and selected.resolution == "NOT_ESTABLISHED"
    if "unknown(" in expression:
        assert any(c.callee == "unknown" for c in context.calls)


@pytest.mark.parametrize(
    "syntax",
    [
        "assembly { let x := 0 }",
        "do { amount++; } while (amount == 0);",
        "try factory.reserve() {} catch {}",
    ],
)
def test_unsupported_scopes_prevent_an_otherwise_unique_typed_call_from_earning_resolution(syntax):
    files = replace_source(
        "IReserve selected = factory.reserve();", syntax + " IReserve selected = factory.reserve();"
    )
    context, _ = typed_context(files)
    selected = next(c for c in context.calls if c.callee == "value")
    assert "LEXICAL_SCOPE_NOT_ESTABLISHED" in selected.shortfalls


@pytest.mark.parametrize("flag", [1, 0, None, "true"])
def test_typed_mode_is_strict_and_requires_the_earlier_scoped_context(flag):
    with pytest.raises(ValueError, match="typed call context"):
        freeze_development_corpus(
            corpus_id="synthetic-typed",
            source_scope="OPERATOR_SUPPLIED_PROTOCOL",
            source_files=call_sources(),
            dependency_call_context=flag,
        )
    with pytest.raises(ValueError, match="typed call context"):
        freeze_development_corpus(
            corpus_id="synthetic-typed",
            source_scope="OPERATOR_SUPPLIED_PROTOCOL",
            source_files=call_sources(),
            dependency_call_context=True,
        )


def test_versioned_source_recomputation_and_rendering_carry_exact_typed_evidence():
    manifest = typed_manifest()
    witness = manifest.dependency_evidence
    assert (manifest.schema_version, witness.schema_version) == ("1.5", "1.3")
    assert witness.call_context == typed_context()[0]
    validate_development_corpus_sources(manifest, call_sources())
    prompt = render_development_corpus_sources(manifest, call_sources(), "Calls.sol")
    assert witness.call_context.model_dump_json() in prompt
    assert "not compiler validity or deployed dispatch" in prompt
    assert manifest.dependency_closure == "IMPORT_CLOSED"
    assert witness.primaries[0].call_closure == "NOT_ESTABLISHED"


@pytest.mark.parametrize("mutation", ["drop_call", "drop_body", "replace_argument", "promote_call"])
def test_resealed_false_typed_evidence_is_refused_by_actual_source_recomputation(mutation):
    files = call_sources()
    if mutation == "promote_call":
        files = replace_source("selected.value(amount)", "selected.value(unknown)")
    data = typed_manifest(files).model_dump(mode="json")
    witness = data["dependency_evidence"]
    context = witness["call_context"]
    if mutation == "drop_call":
        # Drop an unnested intrinsic, preserving the remaining structural source joins.
        context["calls"] = [c for c in context["calls"] if c["callee"] != "require"]
    else:
        selected = next(c for c in context["calls"] if c["callee"] == "value")
        if mutation == "drop_body":
            selected["implementation_member_ids"] = []
        elif mutation == "replace_argument":
            selected["arguments"][0]["expression_type"]["spelling"] = "bool"
        else:
            selected["arguments"][0]["expression_type"] = calls._builtin("uint256").model_dump(
                mode="json"
            )
            selected["arguments"][0]["shortfalls"] = []
            selected["member_ids"] = selected["member_ids"][:1]
            selected["shortfalls"] = []
            selected["resolution"] = "STATIC_DECLARATIONS_BOUND"
    for primary in context["primaries"]:
        primary["unresolved_call_indices"] = [
            i
            for i, c in enumerate(context["calls"])
            if c["source"] in primary["members"] and c["resolution"] == "NOT_ESTABLISHED"
        ]
    witness["witness_sha256"] = canonical_sha256(
        {k: v for k, v in witness.items() if k != "witness_sha256"}
    )
    data["manifest_sha256"] = canonical_sha256(
        {k: v for k, v in data.items() if k != "manifest_sha256"}
    )
    forged = DevelopmentCorpusManifest.model_validate_json(json.dumps(data), strict=True)
    with pytest.raises(ValueError, match="exact source recomputation"):
        validate_development_corpus_sources(forged, files)


@pytest.mark.parametrize("value", [True, 0, 1, "false", None])
def test_no_serialized_flag_can_promote_partial_argument_analysis_to_complete_resolution(value):
    data = typed_context()[0].model_dump(mode="python")
    data["complete_static_resolution"] = value
    with pytest.raises(ValueError):
        DependencyCallContext.model_validate(data)


@pytest.mark.parametrize("bound", ["MAX_TARGET_CONTEXT_BYTES", "MAX_TARGET_RECORDS"])
def test_typed_context_bounds_refuse_instead_of_dropping_evidence(monkeypatch, bound):
    monkeypatch.setattr(calls, bound, 1)
    with pytest.raises(ValueError, match="ceiling"):
        typed_context()


@pytest.mark.parametrize(
    "kind,fields",
    [
        ("BUILTIN", {"spelling": "uint7"}),
        ("BUILTIN", {"spelling": "uint"}),
        ("NOMINAL", {"spelling": "IReserve"}),
        ("INTEGER_LITERAL", {"spelling": "integer_literal", "integer_value": str(2**256)}),
        ("UNKNOWN", {"spelling": "UNKNOWN"}),
    ],
)
def test_expression_type_shape_cannot_invent_a_valid_primitive_or_nominal_identity(kind, fields):
    with pytest.raises(ValueError):
        DependencyExpressionType.model_validate({"kind": kind, **fields})


@pytest.mark.parametrize(
    "mutation",
    [
        "drop_context",
        "null_context",
        "old_witness",
        "old_manifest",
        "missing_scopes",
        "complete_flag",
    ],
)
def test_generated_schema_requires_versioned_typed_evidence(mutation):
    schema = json.loads(Path("schemas/development_corpus_manifest.schema.json").read_bytes())
    data = typed_manifest().model_dump(mode="json")
    Draft202012Validator(schema).validate(data)
    evidence = data["dependency_evidence"]
    if mutation == "drop_context":
        del evidence["call_context"]
    elif mutation == "null_context":
        evidence["call_context"] = None
    elif mutation == "old_witness":
        evidence["schema_version"] = "1.2"
    elif mutation == "old_manifest":
        data["schema_version"] = "1.4"
    elif mutation == "missing_scopes":
        evidence["scoped_context"] = None
    else:
        evidence["call_context"]["complete_static_resolution"] = True
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(data)


@pytest.mark.parametrize("label", ["1.0", "1.1", "1.2", "1.3", "1.4-selected", "1.4-tree"])
def test_all_pre_argument_versions_replay_exact_verified_predecessor_bytes(label):
    from tests.unit.test_development_corpus_tree_models import tree_receipt

    golden = json.loads(FIXTURE.with_name("legacy_replay.json").read_bytes())
    files = call_sources()
    assert {name: hashlib.sha256(raw).hexdigest() for name, raw in files} == golden[
        "source_sha256s"
    ]
    base = dict(
        corpus_id=golden["corpus_id"], source_scope=golden["source_scope"], source_files=files
    )
    receipt = tree_receipt(freeze_development_corpus(**base))
    version = label.split("-")[0]
    options = {}
    if version != "1.0":
        options["dependency_remapping_text"] = ""
    if version in {"1.2", "1.3", "1.4"}:
        options["dependency_target_context"] = True
    if version == "1.3" or label == "1.4-tree":
        options["source_tree_evidence"] = receipt
    if version == "1.4":
        options["dependency_scoped_context"] = True
    manifest = freeze_development_corpus(**base, **options)
    expected = golden["artifacts"][label]
    assert manifest.schema_version == version
    assert (
        hashlib.sha256(manifest.model_dump_json().encode()).hexdigest()
        == expected["manifest_sha256"]
    )
    if manifest.dependency_evidence is not None:
        assert manifest.dependency_evidence.call_context is None
        assert "call_context" not in manifest.dependency_evidence.model_dump(mode="json")
        assert (
            hashlib.sha256(manifest.dependency_evidence.model_dump_json().encode()).hexdigest()
            == expected["witness_sha256"]
        )
    else:
        assert expected["witness_sha256"] is None
    assert {
        name: hashlib.sha256(
            render_development_corpus_sources(manifest, files, name).encode()
        ).hexdigest()
        for name, _ in files
    } == expected["prompt_sha256s"]
