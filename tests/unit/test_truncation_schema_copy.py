"""Hash-only copying preserves reference schema meaning and original input custody."""

from __future__ import annotations

import copy
import cProfile
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, Field
from pydantic import json_schema as json_schema_module
from pydantic.json_schema import GenerateJsonSchema, models_json_schema

import mmaudit.models.truncation as protocol
from tests.unit.test_truncation_schema_inventory import MODEL_NAMES

FIXTURE = json.loads(
    (Path(__file__).parents[1] / "fixtures/schema_copy/reference_cases.json").read_text()
)
assert FIXTURE["scope"] == "SYNTHETIC_SCHEMA_COPY_ISOLATION_NO_PROVIDER"


def _normal_form(value: Any) -> Any:
    result = copy.deepcopy(value)
    pending = [result]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            node.pop("default", None)
            properties = node.get("properties")
            if isinstance(properties, dict):
                node["required"] = list(properties)
                node["additionalProperties"] = False
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    return result


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _reference_inventory(models: tuple[type[BaseModel], ...]) -> str:
    roots, definitions = models_json_schema([(model, "validation") for model in models])
    value = {
        "roots": [roots[(model, "validation")] for model in models],
        "definitions": definitions,
    }
    return hashlib.sha256(_canonical(_normal_form(value))).hexdigest()


@pytest.fixture
def selected_schema_generator(monkeypatch: pytest.MonkeyPatch) -> type[GenerateJsonSchema]:
    """Observe the existing hash consumer's selection, without assuming a future implementation."""
    observed: list[type[GenerateJsonSchema]] = []

    def observe(*args: Any, **kwargs: Any) -> Any:
        observed.append(kwargs["schema_generator"])
        return models_json_schema(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(json_schema_module, "models_json_schema", observe)
        protocol._candidate_review_schema_inventory_sha256((protocol.CandidateReviewBeginFrame,))
    assert len(observed) == 1
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    return observed[0]


def _assert_fresh_containers(source: Any, result: Any) -> None:
    """Every container occurrence is copied, including repeated references to one input."""
    pending = [(source, result)]
    source_ids: set[int] = set()
    result_ids: set[int] = set()
    while pending:
        original, copied = pending.pop()
        if type(original) is dict:
            assert type(copied) is dict and original.keys() == copied.keys()
            assert id(copied) not in result_ids
            source_ids.add(id(original))
            result_ids.add(id(copied))
            if isinstance(original.get("properties"), dict):
                assert list(copied["properties"]) == list(original["properties"])
            pending.extend((child, copied[key]) for key, child in original.items())
        elif type(original) is list:
            assert type(copied) is list and len(original) == len(copied)
            assert id(copied) not in result_ids
            source_ids.add(id(original))
            result_ids.add(id(copied))
            pending.extend(zip(original, copied, strict=True))
        else:
            assert copied is original
    assert source_ids.isdisjoint(result_ids)


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=lambda case: case["id"])
@pytest.mark.parametrize("parent_key", (None, "properties", "default"))
def test_hash_sort_preserves_meaning_property_order_and_fresh_containers(
    selected_schema_generator: type[GenerateJsonSchema],
    case: dict[str, Any],
    parent_key: str | None,
) -> None:
    source = copy.deepcopy(case["schema"])
    before = copy.deepcopy(source)
    expected = GenerateJsonSchema().sort(source, parent_key=parent_key)
    actual = selected_schema_generator().sort(source, parent_key=parent_key)
    assert source == before and actual == expected
    if parent_key in ("properties", "default"):
        assert list(actual) == list(source)
    assert _canonical(_normal_form(actual)) == _canonical(_normal_form(expected))
    _assert_fresh_containers(source, actual)


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=lambda case: case["id"])
def test_normalization_of_one_copy_cannot_mutate_source_or_another_copy(
    selected_schema_generator: type[GenerateJsonSchema], case: dict[str, Any]
) -> None:
    source = copy.deepcopy(case["schema"])
    before = copy.deepcopy(source)
    first = selected_schema_generator().sort(source)
    second = selected_schema_generator().sort(source)
    expected = copy.deepcopy(second)
    pending = [first]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            node.pop("default", None)
            if isinstance(node.get("properties"), dict):
                node["required"] = list(node["properties"])
                node["additionalProperties"] = False
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    first.clear()
    assert source == before and second == expected
    _assert_fresh_containers(source, second)


def test_shared_container_occurrences_are_copied_independently(
    selected_schema_generator: type[GenerateJsonSchema],
) -> None:
    shared = {"properties": {"z": {"default": 1}, "a": {"type": "integer"}}}
    source = {"z": shared, "a": [shared, shared]}
    actual = selected_schema_generator().sort(source)
    assert actual == GenerateJsonSchema().sort(source)
    _assert_fresh_containers(source, actual)
    actual["z"]["properties"].clear()
    assert actual["a"][0] == shared and actual["a"][1] == shared


def test_large_integer_default_is_copied_before_normalization_without_serializing_it(
    selected_schema_generator: type[GenerateJsonSchema],
) -> None:
    value = {"default": 10**5000, "type": "integer"}
    actual = selected_schema_generator().sort(value)
    _assert_fresh_containers(value, actual)
    assert _canonical(_normal_form(actual)) == b'{"type":"integer"}'


@pytest.mark.parametrize("value", (float("inf"), float("nan")))
def test_nonfinite_callback_values_keep_reference_hash_refusal(value: float) -> None:
    class SyntheticNonfinite(BaseModel):
        field: int

    SyntheticNonfinite.model_config["json_schema_extra"] = {"x_synthetic_nonfinite": value}
    with pytest.raises(ValueError):
        _reference_inventory((SyntheticNonfinite,))
    with pytest.raises(ValueError):
        protocol._candidate_review_schema_inventory_sha256((SyntheticNonfinite,))


def _unsupported_graph(kind: str, trace: list[str]) -> dict[str, Any]:
    class CustomDict(dict[str, Any]):
        def keys(self) -> Any:
            trace.append("keys")
            return super().keys()

        def __getitem__(self, key: str) -> Any:
            trace.append("get:" + key)
            return super().__getitem__(key)

    class CustomList(list[Any]):
        def __iter__(self) -> Any:
            trace.append("iterate")
            return super().__iter__()

    class CustomString(str):
        pass

    class CustomInt(int):
        pass

    if kind == "dict_subclass":
        return {"z": CustomDict(z=1, a=2)}
    if kind == "list_subclass":
        return {"z": CustomList([{"z": 1, "a": 2}])}
    if kind == "str_subclass":
        return {"z": CustomString("synthetic")}
    if kind == "int_subclass":
        return {"z": CustomInt(2)}
    if kind == "nonfinite":
        return {"z": float("inf")}
    if kind == "opaque":
        return {"z": object()}
    if kind == "nonstring_key":
        return {"z": {"a": 1, 2: 3}}
    if kind == "node_bound":
        return {"z": [0] * protocol._SCHEMA_REMAPPING_MAX_NODES}
    if kind == "depth_bound":
        node: dict[str, Any] = {}
        for _ in range(protocol._SCHEMA_REMAPPING_MAX_DEPTH + 1):
            node = {"z": node}
        return node
    if kind == "alias_expansion_bound":
        shared = [0] * 1024
        return {"z": [shared] * 50}
    if kind == "tuple":
        return {"z": ({"z": 1, "a": 2},)}
    if kind == "cycle":
        cycle: dict[str, Any] = {}
        cycle["z"] = cycle
        return cycle
    raise AssertionError("unknown synthetic unsupported graph")


@pytest.mark.parametrize(
    "kind",
    (
        "dict_subclass",
        "list_subclass",
        "str_subclass",
        "int_subclass",
        "nonfinite",
        "opaque",
        "nonstring_key",
        "node_bound",
        "depth_bound",
        "alias_expansion_bound",
        "tuple",
        "cycle",
    ),
)
def test_unsupported_or_excessive_graph_keeps_reference_behavior(
    selected_schema_generator: type[GenerateJsonSchema], kind: str
) -> None:
    trace: list[str] = []
    value = _unsupported_graph(kind, trace)
    expected_error: type[Exception] | None = None
    expected: Any = None
    try:
        expected = GenerateJsonSchema().sort(value)
    except (TypeError, RecursionError) as error:
        expected_error = type(error)
    reference_trace = tuple(trace)
    trace.clear()
    profile = cProfile.Profile()
    if expected_error is not None:
        with pytest.raises(expected_error):
            profile.runcall(selected_schema_generator().sort, value)
    else:
        actual = profile.runcall(selected_schema_generator().sort, value)
        assert actual == expected
        assert _canonical(list(actual)) == _canonical(list(expected))
    assert tuple(trace) == reference_trace
    assert (
        sum(
            row.callcount
            for row in profile.getstats()
            if row.code is GenerateJsonSchema.sort.__code__
        )
        == 1
    )


@pytest.mark.parametrize("name", MODEL_NAMES)
def test_every_protocol_root_hash_matches_independent_reference(name: str) -> None:
    models = (getattr(protocol, name),)
    assert protocol._candidate_review_schema_inventory_sha256(models) == _reference_inventory(
        models
    )


@pytest.mark.parametrize("order", ("forward", "reverse", "rotate"))
def test_complete_root_order_is_not_replaced_by_dictionary_sort_order(order: str) -> None:
    models = tuple(getattr(protocol, name) for name in MODEL_NAMES)
    ordered = (
        models
        if order == "forward"
        else models[::-1]
        if order == "reverse"
        else models[1:] + models[:1]
    )
    assert protocol._candidate_review_schema_inventory_sha256(ordered) == _reference_inventory(
        ordered
    )
    if order != "forward":
        assert _reference_inventory(ordered) != _reference_inventory(models)


def test_recursive_alias_union_and_default_properties_keep_reference_hash() -> None:
    class SyntheticNode(BaseModel):
        z_value: int | str = Field(alias="z_alias")
        a_children: list[SyntheticNode] = Field(default_factory=list, alias="a_alias")

    models = (SyntheticNode,)
    assert protocol._candidate_review_schema_inventory_sha256(models) == _reference_inventory(
        models
    )


def test_callback_owned_nested_schema_is_not_normalized_in_place() -> None:
    owned = {"properties": {"z": {"default": 1}, "a": {"type": "integer"}}, "default": 2}
    before = copy.deepcopy(owned)
    calls: list[str] = []

    class SyntheticCallback(BaseModel):
        value: int

    def decorate(schema: dict[str, Any]) -> None:
        calls.append("called")
        schema["x_synthetic_owned"] = owned

    SyntheticCallback.model_config["json_schema_extra"] = decorate
    expected = _reference_inventory((SyntheticCallback,))
    reference_calls = len(calls)
    assert owned == before and reference_calls > 0
    calls.clear()
    assert protocol._candidate_review_schema_inventory_sha256((SyntheticCallback,)) == expected
    assert len(calls) == reference_calls and owned == before


@pytest.mark.parametrize("kind", ("ordinary_generator", "caller_subclass"))
def test_ordinary_rendering_and_caller_subclass_keep_reference_sorting(
    selected_schema_generator: type[GenerateJsonSchema], kind: str
) -> None:
    caller = type("SyntheticCaller", (selected_schema_generator,), {})

    selected = (
        protocol._CandidateReviewJsonSchemaGenerator if kind == "ordinary_generator" else caller
    )
    value = {"z": {"z": 1, "a": 2}, "a": [3, 1, 2]}
    expected = GenerateJsonSchema().sort(value)
    profile = cProfile.Profile()
    observed = profile.runcall(selected().sort, value)
    assert json.dumps(observed) == json.dumps(expected)
    assert (
        sum(
            row.callcount
            for row in profile.getstats()
            if row.code is GenerateJsonSchema.sort.__code__
        )
        == 1
    )


def _mutate_selected_sort(
    patch: pytest.MonkeyPatch, generator: type[GenerateJsonSchema], mutation: str
) -> None:
    original = generator.sort
    if mutation == "rebind":

        def equivalent(self: GenerateJsonSchema, value: Any, parent_key: str | None = None) -> Any:
            return original(self, value, parent_key=parent_key)

        patch.setattr(generator, "sort", equivalent)
    elif mutation == "code":
        patch.setattr(
            original, "__code__", original.__code__.replace(co_filename="<synthetic-copy-change>")
        )
    else:
        raise AssertionError("unknown synthetic dependency mutation")


@pytest.mark.parametrize("mutation", ("rebind", "code"))
def test_hash_generator_sort_drift_during_callback_is_rechecked(
    selected_schema_generator: type[GenerateJsonSchema],
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    calls: list[str] = []
    with monkeypatch.context() as patch:

        def change(_schema: dict[str, Any]) -> None:
            calls.append("called")
            _mutate_selected_sort(patch, selected_schema_generator, mutation)

        patch.setitem(protocol.CandidateReviewEndFrame.model_config, "json_schema_extra", change)
        pristine = protocol.candidate_review_protocol_implementation_is_pristine()
        assert calls and not pristine
    assert protocol.candidate_review_protocol_implementation_is_pristine()


@pytest.mark.parametrize("target", ("copy_helper", "hash_sort"))
@pytest.mark.parametrize("mutation", ("rebind", "code", "defaults", "keyword_defaults"))
def test_new_hash_copy_dependencies_are_required_and_bound(
    monkeypatch: pytest.MonkeyPatch, target: str, mutation: str
) -> None:
    generator = getattr(protocol, "_CandidateReviewHashJsonSchemaGenerator", None)
    helper = getattr(protocol, "_copy_plain_schema_for_hash", None)
    assert generator is not None and helper is not None
    owner, name = (
        (protocol, "_copy_plain_schema_for_hash")
        if target == "copy_helper"
        else (generator, "sort")
    )
    original = getattr(owner, name)
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    with monkeypatch.context() as patch:
        if mutation == "rebind":

            def equivalent(*args: Any, **kwargs: Any) -> Any:
                return original(*args, **kwargs)

            patch.setattr(owner, name, equivalent)
        elif mutation == "code":
            patch.setattr(
                original,
                "__code__",
                original.__code__.replace(co_filename="<synthetic-copy-change>"),
            )
        elif mutation == "defaults":
            defaults = original.__defaults__
            replacement = () if defaults is None else tuple(value for value in defaults)
            assert replacement is not defaults
            patch.setattr(original, "__defaults__", replacement)
        else:
            assert original.__kwdefaults__ is None
            patch.setattr(original, "__kwdefaults__", {})
        assert not protocol.candidate_review_protocol_implementation_is_pristine()
    assert protocol.candidate_review_protocol_implementation_is_pristine()


@pytest.mark.parametrize("mutation", ("attributes", "bases"))
def test_new_hash_generator_class_custody_is_required_and_bound(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    generator = getattr(protocol, "_CandidateReviewHashJsonSchemaGenerator", None)
    assert generator is not None
    if mutation == "attributes":
        with monkeypatch.context() as patch:
            patch.setattr(generator, "_synthetic_copy_attribute", None, raising=False)
            assert not protocol.candidate_review_protocol_implementation_is_pristine()
    else:
        original_bases = generator.__bases__
        bases = tuple(base for base in original_bases)
        assert bases is not original_bases
        try:
            # __bases__ is a type descriptor, not an entry that pytest can delete on undo.
            generator.__bases__ = bases
            assert not protocol.candidate_review_protocol_implementation_is_pristine()
        finally:
            generator.__bases__ = original_bases
    assert protocol.candidate_review_protocol_implementation_is_pristine()


def test_inventory_selects_bounded_copy_without_reference_sort(
    selected_schema_generator: type[GenerateJsonSchema],
) -> None:
    expected = getattr(protocol, "_CandidateReviewHashJsonSchemaGenerator", None)
    assert expected is not None and selected_schema_generator is expected
    value = {"z": {"z": 1, "a": 2}, "a": [3, 1, 2]}
    profile = cProfile.Profile()
    copied = profile.runcall(selected_schema_generator().sort, value)
    assert copied == GenerateJsonSchema().sort(value)
    assert list(copied) == list(value)
    _assert_fresh_containers(value, copied)
    assert not any(row.code is GenerateJsonSchema.sort.__code__ for row in profile.getstats())


@pytest.mark.parametrize("kind", ("str_subclass", "object"))
def test_nonplain_parent_key_retains_reference_comparisons_and_sorting(
    selected_schema_generator: type[GenerateJsonSchema], kind: str
) -> None:
    trace: list[str] = []

    class CustomString(str):
        def __eq__(self, other: object) -> bool:
            trace.append(type(other).__name__)
            return False

    class CustomObject:
        def __eq__(self, other: object) -> bool:
            trace.append(type(other).__name__)
            return False

    parent: Any = CustomString("synthetic-parent") if kind == "str_subclass" else CustomObject()
    value = {"z": {"z": 1, "a": 2}, "a": [3, 1, 2]}
    expected = GenerateJsonSchema().sort(value, parent_key=parent)
    expected_trace = tuple(trace)
    assert expected_trace
    trace.clear()
    profile = cProfile.Profile()
    actual = profile.runcall(selected_schema_generator().sort, value, parent_key=parent)
    assert json.dumps(actual) == json.dumps(expected)
    assert tuple(trace) == expected_trace
    assert (
        sum(
            row.callcount
            for row in profile.getstats()
            if row.code is GenerateJsonSchema.sort.__code__
        )
        == 1
    )
