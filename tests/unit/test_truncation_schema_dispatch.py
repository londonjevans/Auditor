"""Fresh direct dispatch must preserve reference behavior, not cache schema authority."""

from __future__ import annotations

import copy
import cProfile
import json
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import BaseModel
from pydantic._internal import _core_utils, _schema_generation_shared
from pydantic.errors import PydanticInvalidForJsonSchema
from pydantic.json_schema import CoreRef, GenerateJsonSchema, JsonSchemaMode, models_json_schema

import mmaudit.models.truncation as protocol
from tests.unit.test_truncation_schema_inventory import MODEL_NAMES

CASES = json.loads(
    (Path(__file__).parents[1] / "fixtures/schema_dispatch/reference_cases.json").read_text()
)["cases"]


def _calls(profile: cProfile.Profile, function: Any) -> int:
    return sum(row.callcount for row in profile.getstats() if row.code is function.__code__)


def _generator_state(generator: GenerateJsonSchema) -> dict[str, Any]:
    return {
        "definitions": generator.definitions,
        "core_to_defs": generator.core_to_defs_refs,
        "core_to_json": generator.core_to_json_refs,
        "defs_to_core": generator.defs_to_core_refs,
        "json_to_defs": generator.json_to_defs_refs,
        "invalid": {
            key: str(value) for key, value in generator._core_defs_invalid_for_json_schema.items()
        },
    }


@pytest.mark.parametrize("case", CASES, ids=lambda item: item["id"])
@pytest.mark.parametrize("mode", ("validation", "serialization"))
def test_synthetic_nodes_match_reference_output_state_and_input_identity(
    case: dict[str, Any], mode: Any
) -> None:
    schema = copy.deepcopy(case["schema"])
    selected = protocol._candidate_review_direct_schema_dispatch(schema)
    assert (selected is not None) is case["direct"]
    reference = GenerateJsonSchema()
    optimized = protocol._CandidateReviewJsonSchemaGenerator()
    reference._mode = optimized._mode = mode
    expected = reference.generate_inner(copy.deepcopy(schema))
    observed = optimized.generate_inner(schema)
    assert observed == expected
    assert _generator_state(optimized) == _generator_state(reference)
    assert schema == case["schema"]


@pytest.mark.parametrize("mode", ("validation", "serialization"))
@pytest.mark.parametrize("by_alias", (False, True))
def test_all_protocol_roots_share_exact_fresh_reference_definitions(
    mode: Any, by_alias: bool
) -> None:
    inputs = [(getattr(protocol, name), mode) for name in MODEL_NAMES]
    assert models_json_schema(
        inputs, by_alias=by_alias, schema_generator=protocol._CandidateReviewJsonSchemaGenerator
    ) == models_json_schema(inputs, by_alias=by_alias)
    assert protocol.candidate_review_protocol_implementation_is_pristine()


def test_direct_nodes_reduce_reference_handlers_without_skipping_fresh_inventories() -> None:
    inputs: list[tuple[type[BaseModel], JsonSchemaMode]] = [
        (getattr(protocol, name), "validation") for name in MODEL_NAMES
    ]
    reference, optimized = cProfile.Profile(), cProfile.Profile()
    expected = reference.runcall(models_json_schema, inputs)
    observed = optimized.runcall(
        models_json_schema, inputs, schema_generator=protocol._CandidateReviewJsonSchemaGenerator
    )
    assert observed == expected
    assert (
        0
        < _calls(optimized, GenerateJsonSchema.generate_inner)
        < _calls(reference, GenerateJsonSchema.generate_inner)
    )
    assert _calls(optimized, protocol._CandidateReviewJsonSchemaGenerator.generate_inner) == _calls(
        reference, GenerateJsonSchema.generate_inner
    )
    fresh = cProfile.Profile()
    for _ in range(3):
        assert fresh.runcall(protocol.candidate_review_protocol_implementation_is_pristine)
    for function in (
        GenerateJsonSchema.generate_definitions,
        protocol._candidate_review_schema_inventory_sha256,
        protocol._candidate_review_schema_input_guard,
    ):
        assert _calls(fresh, function) == 3


class _UntouchableDict(dict[str, Any]):
    def __iter__(self) -> Any:
        raise AssertionError("direct selector must not traverse a custom container")

    def get(self, *_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("direct selector must not inspect a custom container")


class _UntouchableString(str):
    __hash__ = str.__hash__

    def __eq__(self, _other: object) -> bool:
        raise AssertionError("direct selector must not compare a custom key or type")


@pytest.mark.parametrize(
    "schema",
    (
        _UntouchableDict(type="int"),
        {_UntouchableString("type"): "int"},
        {"type": _UntouchableString("int")},
        {"type": "int", "metadata": _UntouchableDict()},
        {"type": "int", "metadata": {_UntouchableString("pydantic_js_updates"): {}}},
        {"type": "int", "metadata": {"pydantic_js_updates": _UntouchableDict()}},
        {"type": "int", "metadata": {"pydantic_js_updates": {_UntouchableString("x"): 1}}},
        {"type": "int", "metadata": None},
        {"type": "int", "metadata": {"pydantic_js_updates": None}},
        {"type": "int", "metadata": {"pydantic_js_functions": []}},
        {"type": "int", "metadata": {"pydantic_js_annotation_functions": []}},
        {"type": "int", "metadata": {"pydantic_js_extra": {}}},
        {"type": "int", "ref": None},
        {"type": "int", "serialization": None},
        [],
        None,
    ),
    ids=[f"unsupported-{index}" for index in range(16)],
)
def test_selector_falls_back_without_executing_custom_container_behavior(schema: Any) -> None:
    assert protocol._candidate_review_direct_schema_dispatch(schema) is None


@pytest.mark.parametrize("target", ("node", "updates"))
@pytest.mark.parametrize("over", (False, True))
def test_exact_bounds_select_reference_without_becoming_schema_admission_limits(
    target: str, over: bool
) -> None:
    count = protocol._SCHEMA_DISPATCH_MAX_KEYS + int(over)
    schema: Any = {"type": "int"}
    if target == "node":
        schema.update({f"synthetic_{index}": index for index in range(count - 1)})
    else:
        schema["metadata"] = {
            "pydantic_js_updates": {f"synthetic_{index}": index for index in range(count)}
        }
    assert (protocol._candidate_review_direct_schema_dispatch(schema) is None) is over
    reference, optimized = GenerateJsonSchema(), protocol._CandidateReviewJsonSchemaGenerator()
    profile = cProfile.Profile()
    assert profile.runcall(optimized.generate_inner, schema) == reference.generate_inner(schema)
    assert _calls(profile, GenerateJsonSchema.generate_inner) == int(over)


@pytest.mark.parametrize(
    "schema",
    (
        {},
        {"type": "synthetic-unknown"},
        {"type": "int", "metadata": None},
        {"type": "int", "metadata": {"pydantic_js_updates": [1]}},
        {"type": "int", "serialization": None},
    ),
)
def test_unsupported_error_type_and_message_match_reference(schema: Any) -> None:
    results: list[tuple[object, Any]] = []
    for generator_type in (GenerateJsonSchema, protocol._CandidateReviewJsonSchemaGenerator):
        generator = generator_type()
        generator._mode = "serialization"
        try:
            results.append(("result", generator.generate_inner(copy.deepcopy(schema))))
        except Exception as error:
            results.append((type(error), str(error)))
    assert results[0] == results[1]
    assert results[0][0] != "result"


@pytest.mark.parametrize("initially_nonempty", (False, True))
@pytest.mark.parametrize("mutation", ("populate", "clear", "replace", "late_hooks"))
def test_update_wrapper_timing_matches_reference_across_child_callbacks(
    initially_nonempty: bool, mutation: str
) -> None:
    def exercise(generator_type: type[GenerateJsonSchema]) -> tuple[Any, dict[str, Any]]:
        events: list[str] = []
        updates = {"title": "initial"} if initially_nonempty else {}
        metadata: dict[str, Any] = {"pydantic_js_updates": updates}
        outer: Any = {"type": "nullable", "metadata": metadata}

        def child_callback(child: Any, handler: Any) -> Any:
            events.append("child")
            updates.clear()
            if mutation != "clear":
                updates["description"] = "original dictionary, current contents"
            if mutation == "replace":
                metadata["pydantic_js_updates"] = {"title": "replacement must be ignored"}
            if mutation == "late_hooks":

                def too_late(_schema: Any) -> None:
                    events.append("must not execute newly inserted extra")

                metadata["pydantic_js_extra"] = too_late
                metadata["pydantic_js_functions"] = [too_late]
                outer["serialization"] = {"type": "to-string"}
            return handler(child)

        outer["schema"] = {
            "type": "int",
            "metadata": {"pydantic_js_annotation_functions": [child_callback]},
        }
        generator = generator_type()
        generator._mode = "serialization"
        observed = generator.generate_inner(outer)
        assert events == ["child"]
        assert ("description" in observed) is (initially_nonempty and mutation != "clear")
        assert "title" not in observed
        return observed, _generator_state(generator)

    assert exercise(GenerateJsonSchema) == exercise(protocol._CandidateReviewJsonSchemaGenerator)


@pytest.mark.parametrize("mutation", ("add_ref", "become_field", "remove_type"))
def test_final_classification_reads_live_node_after_child_callback(mutation: str) -> None:
    def exercise(generator_type: type[GenerateJsonSchema]) -> tuple[Any, dict[str, Any]] | None:
        outer: Any = {"type": "nullable"}

        def child_callback(child: Any, handler: Any) -> Any:
            if mutation == "remove_type":
                outer.pop("type")
            else:
                outer["ref"] = "synthetic.Late:1"
                if mutation == "become_field":
                    outer["type"] = "model-field"
            return handler(child)

        outer["schema"] = {
            "type": "int",
            "metadata": {"pydantic_js_annotation_functions": [child_callback]},
        }
        generator = generator_type()
        if mutation == "remove_type":
            with pytest.raises(KeyError, match="type"):
                generator.generate_inner(outer)
            return None
        value = generator.generate_inner(outer)
        assert ("$ref" in value) is (mutation == "add_ref")
        return value, _generator_state(generator)

    assert exercise(GenerateJsonSchema) == exercise(protocol._CandidateReviewJsonSchemaGenerator)


@pytest.mark.parametrize("self_reference", (False, True))
def test_late_reference_preserves_self_ref_rule_invalid_cleanup_and_custom_get_arguments(
    self_reference: bool,
) -> None:
    def exercise(generator_type: type[GenerateJsonSchema]) -> tuple[Any, dict[str, Any]]:
        generator = generator_type()
        defs_ref, ref_schema = generator.get_cache_defs_ref_schema(CoreRef("synthetic.Late:1"))
        marker = PydanticInvalidForJsonSchema("synthetic")
        generator._core_defs_invalid_for_json_schema[defs_ref] = marker
        get_calls: list[Any] = []

        class Result(dict[str, Any]):
            def get(self, key: Any, *args: Any) -> Any:
                get_calls.append((key, args))
                return super().get(key, *args)

        def render(schema: Any) -> Any:
            schema["ref"] = "synthetic.Late:1"
            return Result(ref_schema if self_reference else {"type": "integer"})

        generator._schema_type_to_method["int"] = render
        observed = generator.generate_inner({"type": "int"})
        assert observed == ref_schema
        assert get_calls == [("$ref", (None,))]
        assert (defs_ref in generator.definitions) is not self_reference
        assert (defs_ref in generator._core_defs_invalid_for_json_schema) is self_reference
        return observed, _generator_state(generator)

    assert exercise(GenerateJsonSchema) == exercise(protocol._CandidateReviewJsonSchemaGenerator)


def test_caller_subclasses_keep_reference_property_and_dispatch_behavior() -> None:
    class ReferenceObserver(GenerateJsonSchema):
        mode_reads = 0

        @property
        def mode(self) -> JsonSchemaMode:
            self.mode_reads += 1
            return self._mode

    class OptimizedObserver(protocol._CandidateReviewJsonSchemaGenerator):
        mode_reads = 0

        @property
        def mode(self) -> JsonSchemaMode:
            self.mode_reads += 1
            return self._mode

    results = []
    for generator in (ReferenceObserver(), OptimizedObserver()):
        profile = cProfile.Profile()
        observed = profile.runcall(
            generator.generate_inner, {"type": "nullable", "schema": {"type": "int"}}
        )
        assert _calls(profile, protocol._candidate_review_direct_schema_dispatch) == 0
        assert generator.mode_reads > 0
        results.append((observed, generator.mode_reads))
    assert results[0] == results[1]


_FUNCTION_TARGETS = {
    "selector": protocol._candidate_review_direct_schema_dispatch,
    "dispatcher": protocol._CandidateReviewJsonSchemaGenerator.generate_inner,
    "reference": GenerateJsonSchema.generate_inner,
    "register_ref": GenerateJsonSchema.get_cache_defs_ref_schema,
    "classify_core": _core_utils.is_core_schema,
    "classify_field": _core_utils.is_core_schema_field,
    "mode": vars(GenerateJsonSchema)["mode"].fget,
    "handler_init": _schema_generation_shared.GenerateJsonSchemaHandler.__init__,
    "handler_call": _schema_generation_shared.GenerateJsonSchemaHandler.__call__,
    "cast": cast,
}


@pytest.mark.parametrize("target", _FUNCTION_TARGETS)
@pytest.mark.parametrize("attribute", ("__code__", "__defaults__", "__kwdefaults__"))
def test_new_and_bypassed_callable_state_cannot_replace_fresh_integrity(
    monkeypatch: pytest.MonkeyPatch, target: str, attribute: str
) -> None:
    def replacement(*_args: Any, **_kwargs: Any) -> None:
        return None

    values = {"__code__": replacement.__code__, "__defaults__": (None,), "__kwdefaults__": {"x": 0}}
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    with monkeypatch.context() as patch:
        patch.setattr(_FUNCTION_TARGETS[target], attribute, values[attribute])
        assert not protocol.candidate_review_protocol_implementation_is_pristine()
    assert protocol.candidate_review_protocol_implementation_is_pristine()


@pytest.mark.parametrize("mutation", ("same_size", "extra", "custom_value", "replacement"))
def test_mutable_field_classification_is_bound_by_identity_and_contents(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    module = _core_utils
    original = module._CORE_SCHEMA_FIELD_TYPES
    contents = set(original)
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    try:
        with monkeypatch.context() as patch:
            if mutation == "replacement":
                patch.setattr(module, "_CORE_SCHEMA_FIELD_TYPES", set(contents))
            else:
                if mutation != "extra":
                    original.remove("model-field")
                original.add(
                    _UntouchableString("synthetic-custom")
                    if mutation == "custom_value"
                    else "synthetic-other"
                )
            assert not protocol.candidate_review_protocol_implementation_is_pristine()
    finally:
        original.clear()
        original.update(contents)
    assert protocol.candidate_review_protocol_implementation_is_pristine()


@pytest.mark.parametrize(
    "target", ("selector", "dispatcher", "reference", "handler", "mode", "limit", "core_ref")
)
def test_semantically_identical_dependency_replacement_mid_generation_is_refused(
    monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    selector = protocol._candidate_review_direct_schema_dispatch
    reference = GenerateJsonSchema.generate_inner
    handler = _schema_generation_shared.GenerateJsonSchemaHandler
    handler_call = handler.__call__
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    with monkeypatch.context() as patch:

        def mutate(_schema: dict[str, Any]) -> None:
            if target == "selector":
                patch.setattr(protocol, "_candidate_review_direct_schema_dispatch", selector_clone)
            elif target == "dispatcher":
                patch.setattr(
                    protocol._CandidateReviewJsonSchemaGenerator, "generate_inner", reference
                )
            elif target == "reference":
                patch.setattr(GenerateJsonSchema, "generate_inner", reference_clone)
            elif target == "handler":
                patch.setattr(handler, "__call__", handler_clone)
            elif target == "mode":
                patch.setattr(
                    GenerateJsonSchema, "mode", property(vars(GenerateJsonSchema)["mode"].fget)
                )
            elif target == "limit":
                patch.setattr(protocol, "_SCHEMA_DISPATCH_MAX_KEYS", 63)
            else:
                patch.setattr(protocol, "CoreRef", lambda value: value)

        def selector_clone(schema: Any) -> Any:
            return selector(schema)

        def reference_clone(generator: Any, schema: Any) -> Any:
            return reference(generator, schema)

        def handler_clone(current: Any, schema: Any) -> Any:
            return handler_call(current, schema)

        patch.setitem(protocol.CandidateReviewEndFrame.model_config, "json_schema_extra", mutate)
        assert not protocol.candidate_review_protocol_implementation_is_pristine()
    assert protocol.candidate_review_protocol_implementation_is_pristine()
