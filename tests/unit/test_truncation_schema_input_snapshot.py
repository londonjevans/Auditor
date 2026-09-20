"""Fresh input snapshots retain exact edges, not equality or cached authorization."""

from __future__ import annotations

import json
from collections import UserDict, UserList
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import BaseModel

import mmaudit.models.truncation as protocol

FIXTURE = json.loads(
    (Path(__file__).parents[1] / "fixtures/schema_input_snapshot/cases.json").read_text()
)
assert FIXTURE["scope"] == "SYNTHETIC_INPUT_EDGE_IDENTITIES_NO_PROVIDER"


class _NoValueOperations:
    def __eq__(self, _other: object) -> bool:
        raise AssertionError("snapshot comparisons must use identity, not user equality")

    def __bool__(self) -> bool:
        raise AssertionError("snapshot traversal must not inspect a value's truthiness")


def _model(payload: Any) -> type[BaseModel]:
    class SyntheticSnapshotModel(BaseModel):
        value: int

    SyntheticSnapshotModel.model_config["json_schema_extra"] = {"payload": payload}
    return SyntheticSnapshotModel


def _key(suffix: str) -> str:
    return ("synthetic-snapshot-key-" + suffix).encode().decode()


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=lambda case: case["id"])
def test_snapshot_preserves_original_edge_identity_order_and_aliases(case: dict[str, Any]) -> None:
    marker = _NoValueOperations()
    first, second = _key("first"), _key("second")
    nested = [marker]
    mapping = {first: marker, second: nested}
    sequence: list[Any] = [marker, nested]
    sequence.append(sequence)
    payload = {"mapping": mapping, "sequence": sequence, "alias": sequence, "tuple": (nested,)}
    model = _model(payload)
    guard = protocol._candidate_review_schema_input_guard((model,))
    assert guard is not None and guard()
    mutation = case["mutation"]
    if mutation == "unchanged":
        pass
    elif mutation == "mapping_value":
        mapping[first] = _NoValueOperations()
    elif mutation == "mapping_key":
        replacement = _key("first")
        assert replacement == first and replacement is not first
        mapping.clear()
        mapping.update(((replacement, marker), (second, nested)))
    elif mutation == "mapping_order":
        mapping[first] = mapping.pop(first)
    elif mutation == "mapping_size":
        mapping[_key("extra")] = marker
    elif mutation == "sequence_value":
        sequence[0] = _NoValueOperations()
    elif mutation == "sequence_size":
        sequence.append(marker)
    elif mutation == "tuple_child":
        nested[0] = _NoValueOperations()
    elif mutation == "detached_mapping":
        payload["mapping"] = mapping.copy()
    elif mutation == "detached_alias":
        payload["alias"] = list(sequence)
    elif mutation == "same_objects":
        original = tuple(mapping.items())
        mapping.clear()
        mapping.update(original)
    elif mutation == "restored":
        sequence[0] = _NoValueOperations()
        assert not guard()
        sequence[0] = marker
    else:
        raise AssertionError("unknown synthetic mutation")
    assert guard() is case["accepted"]


def test_each_snapshot_has_its_own_original_edges_without_cross_call_authority() -> None:
    original, replacement = _NoValueOperations(), _NoValueOperations()
    payload = {"edge": original}
    model = _model(payload)
    first = protocol._candidate_review_schema_input_guard((model,))
    assert first is not None and first()
    payload["edge"] = replacement
    assert not first()
    second = protocol._candidate_review_schema_input_guard((model,))
    assert second is not None and second()
    payload["edge"] = original
    assert first() and not second()


def test_traversal_uses_the_captured_pairs_not_later_dictionary_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    visited: list[str] = []
    root: dict[str, Any] = {}

    class TrackedMetadata(type):
        def __getattribute__(cls, name: str) -> Any:
            if name == "__pydantic_core_schema__":
                visited.append("original" if cls is OriginalChild else "replacement")
                root["child"] = OriginalChild
            return super().__getattribute__(name)

    class OriginalChild(metaclass=TrackedMetadata):
        __pydantic_core_schema__ = None
        model_config = None

    class ReplacementChild(metaclass=TrackedMetadata):
        __pydantic_core_schema__ = None
        model_config = None

    root["child"] = OriginalChild
    model = _minimal_graph_model([])
    model.__pydantic_core_schema__ = cast(Any, root)
    original_tuple = tuple
    items_type: type[Any] = type({}.items())

    def capture_then_change(iterable: Any) -> tuple[Any, ...]:
        captured = original_tuple(iterable)
        if isinstance(iterable, items_type) and captured == (("child", OriginalChild),):
            root["child"] = ReplacementChild
        return captured

    # This direct helper fixture injects drift immediately after pair capture.
    # Neither the deliberately invalid core nor the instrumented builtin is used
    # for schema generation, custody issuance or provider work.
    with monkeypatch.context() as patch:
        patch.setattr(protocol, "tuple", capture_then_change, raising=False)
        guard = protocol._candidate_review_schema_input_guard((model,))
    assert guard is not None
    assert visited == ["original"]
    assert root["child"] is OriginalChild and guard()


@pytest.mark.parametrize(
    "attribute",
    (
        "__name__",
        "__qualname__",
        "__module__",
        "__doc__",
        "__pydantic_core_schema__",
        "model_config",
    ),
)
def test_snapshot_retains_all_six_class_metadata_edges(attribute: str) -> None:
    model = _model({"nested": []})
    guard = protocol._candidate_review_schema_input_guard((model,))
    assert guard is not None and guard()
    original = getattr(model, attribute)
    replacement: Any = {} if isinstance(original, dict) else "ChangedSyntheticMetadata"
    setattr(model, attribute, replacement)
    assert not guard()
    setattr(model, attribute, original)
    assert guard()


def test_equivalent_exact_metadata_strings_do_not_call_subclass_equality() -> None:
    class NoEqualityString(str):
        def __eq__(self, _other: object) -> bool:
            raise AssertionError("metadata subclass equality is not trusted")

    model = _model(None)
    model.__doc__ = _key("documentation")
    guard = protocol._candidate_review_schema_input_guard((model,))
    assert guard is not None and guard()
    original = model.__doc__
    assert original is not None
    model.__doc__ = original.encode().decode()
    assert model.__doc__ is not original and guard()
    model.__doc__ = NoEqualityString(original)
    assert not guard()


def _minimal_graph_model(values: list[Any]) -> type[BaseModel]:
    # Isolate the traversal budget only. This deliberately invalid synthetic core
    # is never used to generate schemas, create custody or dispatch model work.
    model = _model(None)
    model.model_config = {}
    model.__pydantic_core_schema__ = cast(Any, values)
    return model


@pytest.mark.parametrize("excess", (-1, 0, 1))
def test_repeated_edges_retain_the_exact_fifty_thousand_edge_bound(excess: int) -> None:
    values: list[Any] = [None] * (50_000 - 6 + excess)
    model = _minimal_graph_model(values)
    guard = protocol._candidate_review_schema_input_guard((model,))
    assert (guard is not None) is (excess <= 0)
    if guard is not None:
        assert guard()
        values.append(None)
        assert not guard()


@pytest.mark.parametrize("excess", (-1, 0, 1))
def test_distinct_nodes_retain_the_exact_fifty_thousand_node_bound(excess: int) -> None:
    values: list[Any] = []
    model = _minimal_graph_model(values)
    attributes = tuple(
        getattr(model, name)
        for name in (
            "__name__",
            "__qualname__",
            "__module__",
            "__doc__",
            "__pydantic_core_schema__",
            "model_config",
        )
    )
    fixed_nodes = len({id(model), *(id(value) for value in attributes)})
    assert fixed_nodes == 7
    values.extend(object() for _ in range(50_000 - fixed_nodes + excess))
    guard = protocol._candidate_review_schema_input_guard((model,))
    assert (guard is not None) is (excess <= 0)
    if guard is not None:
        assert guard()
        values[0] = object()
        assert not guard()


class _UnwalkableDict(dict[str, Any]):
    def items(self) -> Any:
        raise AssertionError("custom dictionary must be refused without traversal")

    def values(self) -> Any:
        raise AssertionError("custom dictionary must not supply fresh traversal values")


class _UnwalkableList(list[Any]):
    def __iter__(self) -> Any:
        raise AssertionError("custom list must be refused without traversal")


@pytest.mark.parametrize("kind", ("dict", "list", "user_dict", "user_list"))
def test_custom_mutable_containers_still_refuse_before_traversal(kind: str) -> None:
    factories: dict[str, Callable[[], Any]] = {
        "dict": lambda: _UnwalkableDict(edge=1),
        "list": lambda: _UnwalkableList([1]),
        "user_dict": lambda: UserDict(edge=1),
        "user_list": lambda: UserList([1]),
    }
    value = factories[kind]()
    assert protocol._candidate_review_schema_input_guard((_model(value),)) is None


@pytest.mark.parametrize("dependency", ("Mapping", "Sequence", "itemgetter"))
def test_every_consumed_snapshot_dependency_is_bound(
    dependency: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    consumed = dependency in protocol._candidate_review_schema_input_guard.__code__.co_names
    # The reference does not consume itemgetter; the proposed traversal will.
    # This same control therefore stays meaningful on both fixed-harness sides.
    assert consumed or dependency == "itemgetter"
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    with monkeypatch.context() as patch:
        patch.setattr(protocol, dependency, object(), raising=False)
        assert protocol.candidate_review_protocol_implementation_is_pristine() is not consumed
    assert protocol.candidate_review_protocol_implementation_is_pristine()
