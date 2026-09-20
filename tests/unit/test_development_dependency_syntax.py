"""Source-only grammar and call-census regressions; no compilation or external execution."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

import mmaudit.solidity.dependency_syntax as syntax
from mmaudit.models.development_corpus import (
    DevelopmentCorpusManifest,
    freeze_development_corpus,
    render_development_corpus_sources,
    validate_development_corpus_sources,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.solidity.dependency_syntax import (
    DependencySyntaxContext,
    build_dependency_syntax_context,
)
from tests.unit.test_development_dependency_calls import (
    call_sources,
    split_call_sources,
    typed_manifest,
)


def syntax_manifest(files=None):
    return freeze_development_corpus(
        corpus_id="synthetic-syntax-context",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
        source_files=call_sources() if files is None else files,
        dependency_remapping_text="",
        dependency_target_context=True,
        dependency_scoped_context=True,
        dependency_call_context=True,
        dependency_syntax_context=True,
    )


def body_sources(body, extra=""):
    return (
        (
            "Syntax.sol",
            (
                "// Synthetic source-only, deliberately non-deployable.\npragma solidity ^0.8.24;\n"
                'contract Syntax { constructor() { revert("NON_DEPLOYABLE_FIXTURE"); } '
                + extra
                + " function probe(uint256 value) external returns (uint256) { "
                + body
                + " } function check(uint256 n) internal pure returns(uint256) { return n; } }"
            ).encode(),
        ),
    )


def context_for(files):
    return syntax_manifest(files).dependency_evidence.syntax_context


@pytest.mark.parametrize("split", [False, True])
def test_complete_supported_sources_join_every_typed_call_without_closure_promotion(split):
    files = split_call_sources() if split else call_sources()
    manifest = syntax_manifest(files)
    witness = manifest.dependency_evidence
    context = witness.syntax_context
    assert manifest.schema_version == "1.6" and witness.schema_version == "1.4"
    assert context.gaps == () and context.unmatched_typed_call_indices == ()
    assert all(s.syntax_coverage == "SUPPORTED_GRAMMAR_ACCOUNTED" for s in context.sources)
    assert len(context.calls) == len(witness.call_context.calls)
    assert all(c.typed_match == "EXACT_SPAN" for c in context.calls)
    assert not context.complete_static_resolution
    assert all(p.call_closure == "NOT_ESTABLISHED" for p in witness.primaries)
    validate_development_corpus_sources(manifest, files)
    assert context.model_dump_json() in render_development_corpus_sources(
        manifest, files, files[0][0]
    )


@pytest.mark.parametrize(
    "body, expected",
    [
        ("return check(value);", ["check"]),
        ("uint256 result = check(value); return result;", ["check"]),
        ("{ uint256 result = check(value); value = result; } return value;", ["check"]),
        ("if (check(value) > 0) return check(1); else return check(2);", ["check"] * 3),
        ("while (check(value) > 0) { value--; } return value;", ["check"]),
        ("do { value = check(value); } while(check(value) > 0); return value;", ["check"] * 2),
        (
            "for (uint256 i = check(0); i < check(value); i = check(i)) { continue; } return value;",
            ["check"] * 3,
        ),
        ("for (;;) { break; } return check(value);", ["check"]),
        ("unchecked { value += check(value); } return value;", ["check"]),
        ("return check(value) > 0 ? check(1) : check(2);", ["check"] * 3),
        ("return check(check(value));", ["check"] * 2),
        ("return -check(value);", ["check"]),
        ("return (check(value));", ["check"]),
        ("return [check(value), check(1)][0];", ["check"] * 2),
        ("value = check({n: check(value)}); return value;", ["check"] * 2),
        (
            "return target.send{value: check(value), gas: check(100)}(check(0));",
            ["check"] * 3 + ["target.send"],
        ),
        (
            "return new Other(check(value)).observe(check(value));",
            ["Other", "check", "new Other(check(value)).observe", "check"],
        ),
        ("(value, ) = (check(value), check(1)); return value;", ["check"] * 2),
        ("delete values[check(value)]; return value;", ["check"]),
    ],
)
def test_statement_and_expression_calls_are_accounted_to_eof(body, expected):
    files = body_sources(body)
    context = context_for(files)
    assert context.gaps == ()
    source = files[0][1]
    found = [c for c in context.calls if source[c.byte_start : c.call_byte_start] != b"revert"]
    assert len(found) == len(expected)
    body_start = source.index(body.encode())
    openings = {
        body_start + match.end() - 1 for match in re.finditer(r"(?:check|Other|observe)\(", body)
    }
    if "target.send{" in body:
        openings.add(body_start + body.index("}(") + 1)
    assert {c.call_byte_start for c in found} == openings
    assert all(source[c.call_byte_start : c.call_byte_start + 1] == b"(" for c in found)
    assert all(source[c.byte_end - 1 : c.byte_end] == b")" for c in found)


def test_inheritance_constructor_and_modifier_header_calls_expose_missing_typed_evidence():
    files = (
        (
            "Header.sol",
            b'pragma solidity ^0.8.24; contract Base { constructor(uint256 n) { revert("NON_DEPLOYABLE_FIXTURE"); } } contract Child is Base(seed(1)) { function seed(uint256 n) internal pure returns(uint256) { return n; } modifier guarded(uint256 n) { _; } function probe() external guarded(seed(2)) { } }',
        ),
    )
    manifest = syntax_manifest(files)
    context = manifest.dependency_evidence.syntax_context
    assert context.gaps == ()
    source = files[0][1]
    missing = [c for c in context.calls if c.typed_match == "MISSING_TYPED_CALL"]
    assert {source[c.byte_start : c.byte_end].decode() for c in missing} == {
        "Base(seed(1))",
        "seed(1)",
        "guarded(seed(2))",
        "seed(2)",
    }
    assert {c.kind for c in missing} == {
        "INHERITANCE_ARGUMENTS",
        "MODIFIER_ARGUMENTS",
        "EXPRESSION",
    }
    assert not context.complete_static_resolution


def test_state_initializer_and_array_dimension_calls_are_not_silently_excluded():
    files = body_sources(
        "return value;", extra="uint256 initial = check(1); uint256[check(2)] values;"
    )
    context = context_for(files)
    assert context.gaps == ()
    source = files[0][1]
    assert {source[c.byte_start : c.byte_end] for c in context.calls} >= {b"check(1)", b"check(2)"}


def test_supported_syntax_does_not_waive_low_confidence_graph_facts():
    evidence = syntax_manifest(split_call_sources()).dependency_evidence
    assert evidence.syntax_context.gaps == ()
    assert any(f.confidence == 0.4 for f in evidence.graph_facts)
    assert not evidence.syntax_context.complete_static_resolution
    assert all(p.call_closure == "NOT_ESTABLISHED" for p in evidence.primaries)


def test_unsupported_suffix_retains_extra_typed_calls_instead_of_discarding_them():
    files = body_sources("assembly {} return check(1);")
    manifest = syntax_manifest(files)
    context = manifest.dependency_evidence.syntax_context
    assert context.gaps and context.unmatched_typed_call_indices
    assert any(
        manifest.dependency_evidence.call_context.calls[i].callee == "check"
        for i in context.unmatched_typed_call_indices
    )


def test_disagreeing_call_span_is_retained_as_a_mismatch():
    files = call_sources()
    original = typed_manifest(files).dependency_evidence.call_context
    value = original.model_dump(mode="python")
    value["calls"][0]["byte_start"] += 1
    changed = type(original).model_validate(value)
    context = build_dependency_syntax_context(source_files=files, call_context=changed)
    assert context.calls[0].typed_match == "SPAN_MISMATCH"
    assert context.calls[0].typed_call_index == 0
    assert not context.complete_static_resolution


@pytest.mark.parametrize(
    "body",
    [
        "assembly { let n := call(0,0,0,0,0,0,0) } return check(1);",
        "try this.probe(1) returns(uint256 n) { return n; } catch { return 0; }",
        "uint256 n = ; return check(1);",
        "return check(value) + ;",
        "return check(value)",
        "return check(value); garbage",
        "if (true) return ; else",
        "return check({n:1,n:2});",
        "return check(value) ? 1;",
        "return value = = check(1);",
        "pragma uint256 hidden; return 1;",
        "mapping(address => uint256) storage xs; return value;",
    ],
)
def test_unsupported_or_malformed_statement_retains_unparsed_suffix(body):
    files = body_sources(body)
    context = context_for(files)
    assert context.sources[0].syntax_coverage == "NOT_ESTABLISHED"
    assert len(context.gaps) == 1
    gap = context.gaps[0]
    assert gap.byte_start <= gap.failure_byte_offset <= gap.byte_end == len(files[0][1])
    assert context.sources[0].parsed_token_count < context.sources[0].token_count


@pytest.mark.parametrize(
    "literal", ['"true"', '"("', '"call(42)"', '"\\n"', 'unicode"λ"', 'hex"aabb"', '"ab" "cd"']
)
def test_string_contents_cannot_invent_calls_or_keywords(literal):
    files = body_sources(f"require(true, {literal}); return value;")
    context = context_for(files)
    assert context.gaps == ()
    assert len(context.calls) == 2


@pytest.mark.parametrize("literal", ['"\\q"', '"\\x1"', '"\\uQQQQ"', '"λ"', 'hex"abc"'])
def test_unsupported_string_lexemes_never_establish_syntax_coverage(literal):
    context = context_for(body_sources(f"require(true, {literal}); return value;"))
    assert context.gaps[0].reason == "INVALID_STRING_LITERAL"


@pytest.mark.parametrize("value", ["1", "0xff", "1_000", "1.5", ".25", "2e10", "1.0e-2", "1 ether"])
def test_supported_numeric_lexemes_are_accounted_without_inventing_type_correctness(value):
    context = context_for(body_sources(f"return check({value});"))
    assert context.gaps == () and not context.complete_static_resolution


@pytest.mark.parametrize("suffix", [b" /* unterminated", b' "unterminated', b" \\", b" \x00"])
def test_lexical_failure_after_valid_declarations_is_a_gap(suffix):
    path, raw = body_sources("return 1;")[0]
    if suffix == b" \x00":
        with pytest.raises(ValueError, match="ambiguous text"):
            context_for(((path, raw + suffix),))
        return
    context = context_for(((path, raw + suffix),))
    assert context.gaps and context.sources[0].syntax_coverage == "NOT_ESTABLISHED"


@pytest.mark.parametrize(
    "field,value",
    [
        ("MAX_SYNTAX_DEPTH", 2),
        ("MAX_SYNTAX_WORK", 4),
        ("MAX_TARGET_RECORDS", 1),
        ("MAX_TARGET_CONTEXT_BYTES", 32),
    ],
)
def test_complete_context_refuses_work_depth_record_or_byte_omissions(monkeypatch, field, value):
    monkeypatch.setattr(syntax, field, value)
    with pytest.raises(ValueError, match=r"ceiling|bound"):
        context_for(call_sources())


def test_join_validator_rejects_dropped_or_relabelled_typed_identity():
    manifest = syntax_manifest()
    context = manifest.dependency_evidence.syntax_context
    values = context.model_dump(mode="python")
    values["calls"] = values["calls"][1:]
    forged = DependencySyntaxContext.model_validate(values)
    with pytest.raises(ValueError, match="unmatched"):
        forged.validate_call_context(manifest.dependency_evidence.call_context)


def test_resealed_forged_syntax_census_refuses_at_actual_source_consumer():
    files = call_sources()
    manifest = syntax_manifest(files)
    value = manifest.model_dump(mode="json")
    evidence = value["dependency_evidence"]
    context = evidence["syntax_context"]
    dropped = context["calls"].pop()
    context["unmatched_typed_call_indices"].append(dropped["typed_call_index"])
    evidence["witness_sha256"] = canonical_sha256(
        {k: v for k, v in evidence.items() if k != "witness_sha256"}
    )
    value["manifest_sha256"] = canonical_sha256(
        {k: v for k, v in value.items() if k != "manifest_sha256"}
    )
    forged = DevelopmentCorpusManifest.model_validate_json(json.dumps(value))
    with pytest.raises(ValueError, match="recomputation"):
        validate_development_corpus_sources(forged, files)


@pytest.mark.parametrize("value", [True, 1, "true"])
def test_syntax_evidence_never_claims_complete_static_resolution(value):
    context = context_for(call_sources()).model_dump(mode="python")
    context["complete_static_resolution"] = value
    with pytest.raises(ValueError, match="complete static"):
        DependencySyntaxContext.model_validate(context)


def test_typed_only_legacy_artifacts_omit_new_evidence_and_prompt():
    files = call_sources()
    manifest = typed_manifest(files)
    assert manifest.schema_version == "1.5"
    assert "syntax_context" not in manifest.model_dump_json()
    assert "Computed source grammar" not in render_development_corpus_sources(
        manifest, files, files[0][0]
    )


@pytest.mark.parametrize(
    "mutation", ["source_bytes", "source_order", "mutable_pair", "mutable_sources"]
)
def test_exact_source_inputs_cannot_differ_from_the_typed_inventory(mutation):
    files = split_call_sources()
    context = typed_manifest(files).dependency_evidence.call_context
    if mutation == "source_bytes":
        files = ((files[0][0], files[0][1] + b" "), *files[1:])
    elif mutation == "source_order":
        files = tuple(reversed(files))
    elif mutation == "mutable_pair":
        files = (list(files[0]), *files[1:])
    else:
        files = list(files)
    with pytest.raises(ValueError):
        build_dependency_syntax_context(source_files=files, call_context=context)


@pytest.mark.parametrize(
    "mutation", ["drop", "null", "old_witness", "old_manifest", "missing_calls", "complete_flag"]
)
def test_generated_schema_requires_exact_versioned_syntax_context(mutation):
    schema = json.loads(Path("schemas/development_corpus_manifest.schema.json").read_bytes())
    value = syntax_manifest().model_dump(mode="json")
    validator = Draft202012Validator(schema)
    validator.validate(value)
    evidence = value["dependency_evidence"]
    if mutation == "drop":
        del evidence["syntax_context"]
    elif mutation == "null":
        evidence["syntax_context"] = None
    elif mutation == "old_witness":
        evidence["schema_version"] = "1.3"
    elif mutation == "old_manifest":
        value["schema_version"] = "1.5"
    elif mutation == "missing_calls":
        evidence["call_context"] = None
    else:
        evidence["syntax_context"]["complete_static_resolution"] = True
    with pytest.raises(ValidationError):
        validator.validate(value)


@pytest.mark.parametrize(
    "label", ["1.0", "1.1", "1.2", "1.3", "1.4-selected", "1.4-tree", "1.5-selected", "1.5-tree"]
)
def test_every_pre_syntax_version_replays_verified_predecessor_artifact_and_prompt_bytes(label):
    from tests.unit.test_development_corpus_tree_models import tree_receipt

    golden = json.loads(
        (
            Path(__file__).parents[1] / "fixtures/solidity/dependency_syntax/legacy_replay.json"
        ).read_bytes()
    )
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
    if version in {"1.2", "1.3", "1.4", "1.5"}:
        options["dependency_target_context"] = True
    if version == "1.3" or label.endswith("-tree"):
        options["source_tree_evidence"] = receipt
    if version in {"1.4", "1.5"}:
        options["dependency_scoped_context"] = True
    if version == "1.5":
        options["dependency_call_context"] = True
    manifest = freeze_development_corpus(**base, **options)
    expected = golden["artifacts"][label]
    assert manifest.schema_version == version
    assert (
        hashlib.sha256(manifest.model_dump_json().encode()).hexdigest()
        == expected["manifest_sha256"]
    )
    assert "syntax_context" not in manifest.model_dump_json()
    if manifest.dependency_evidence is not None:
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
