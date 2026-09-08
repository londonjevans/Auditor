from __future__ import annotations

import copy
import gc
import pickle
from decimal import Decimal
from typing import Any

import pytest

import mmaudit.models.price_lexemes as price_lexemes_module
from mmaudit.models.endpoint_snapshots import (
    EndpointSnapshotValidationError,
    canonicalize_openrouter_pricing,
)
from mmaudit.models.price_lexemes import (
    MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
    CapturedOpenRouterJSONNumber,
    captured_openrouter_json_number_raw,
    decode_openrouter_price_metadata_json,
    detach_captured_openrouter_json_number,
    price_lexeme_callables_are_pristine,
)


def _materialized_pricing(raw_pricing: str) -> dict[str, Any]:
    decoded = decode_openrouter_price_metadata_json(
        (
            '{"data":{"id":"alpha/atlas-secure","endpoints":['
            '{"status":0,"pricing":'
            f"{raw_pricing}"
            "}]}}"
        ).encode(),
        layout=MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
    )
    data = decoded["data"]
    assert type(data) is dict
    endpoints = data["endpoints"]
    assert type(endpoints) is list
    endpoint = endpoints[0]
    assert type(endpoint) is dict
    assert type(endpoint["status"]) is int
    pricing = endpoint["pricing"]
    assert type(pricing) is dict
    return pricing


def _canonicalize_materialized_pricing(pricing: dict[str, Any]) -> dict[str, str]:
    return canonicalize_openrouter_pricing(
        pricing,
        price_lexeme_layout=MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
        price_lexeme_parent_path=("data", "endpoints", 0, "pricing"),
    )


def test_captured_canonical_decimal_and_integer_prices_are_admitted_losslessly() -> None:
    pricing = _materialized_pricing('{"prompt":0.000003,"completion":0}')

    assert captured_openrouter_json_number_raw(pricing["prompt"]) == "0.000003"
    assert captured_openrouter_json_number_raw(pricing["completion"]) == "0"
    assert _canonicalize_materialized_pricing(pricing) == {
        "completion": "0",
        "prompt": "0.000003",
    }


def test_captured_price_cannot_move_between_pricing_fields() -> None:
    pricing = _materialized_pricing('{"prompt":0.000003,"completion":0}')
    moved = {
        "completion": pricing["prompt"],
        "prompt": pricing["completion"],
    }

    with pytest.raises(
        EndpointSnapshotValidationError,
        match="captured numeric price full-path binding changed",
    ):
        _canonicalize_materialized_pricing(moved)

    assert captured_openrouter_json_number_raw(pricing["prompt"]) is None
    assert captured_openrouter_json_number_raw(pricing["completion"]) == "0"

    pricing = _materialized_pricing('{"prompt":0.000003,"completion":0}')
    moved_to_nonbillable = {
        "completion": "0",
        "discount": pricing["prompt"],
        "prompt": "0.000003",
    }
    with pytest.raises(
        EndpointSnapshotValidationError,
        match="captured numeric price full-path binding changed",
    ):
        _canonicalize_materialized_pricing(moved_to_nonbillable)


@pytest.mark.parametrize(
    ("layout", "parent_path", "message"),
    [
        pytest.param(
            MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
            None,
            "layout and full-path context must be supplied together",
            id="layout-only",
        ),
        pytest.param(
            None,
            ("data", "endpoints", 0, "pricing"),
            "layout and full-path context must be supplied together",
            id="path-only",
        ),
        pytest.param(
            MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
            ("data", "endpoints", -1, "pricing"),
            "full-path context is invalid",
            id="invalid-original-index",
        ),
    ],
)
def test_invalid_price_path_context_revokes_every_captured_value_monotonically(
    layout: str | None,
    parent_path: tuple[str | int, ...] | None,
    message: str,
) -> None:
    pricing = _materialized_pricing('{"prompt":0.000003,"completion":0}')
    prompt = pricing["prompt"]
    completion = pricing["completion"]

    with pytest.raises(EndpointSnapshotValidationError, match=message):
        canonicalize_openrouter_pricing(
            pricing,
            price_lexeme_layout=layout,
            price_lexeme_parent_path=parent_path,
        )

    assert captured_openrouter_json_number_raw(prompt) is None
    assert captured_openrouter_json_number_raw(completion) is None
    with pytest.raises(
        EndpointSnapshotValidationError,
        match=r"^endpoint prices must be exact decimal strings$",
    ):
        _canonicalize_materialized_pricing(pricing)


def test_price_decoder_rejects_duplicate_keys_and_nonfinite_constants() -> None:
    for raw in (
        b'{"data":{"endpoints":[{"pricing":{"prompt":1,"prompt":2}}]}}',
        b'{"data":{"endpoints":[{"pricing":{"prompt":NaN}}]}}',
    ):
        with pytest.raises(ValueError):
            decode_openrouter_price_metadata_json(
                raw,
                layout=MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
            )


def test_price_decoder_bounds_parse_phase_numeric_tokens_without_leaking_custody() -> None:
    token_limit = price_lexemes_module._MAX_JSON_NUMBER_TOKENS
    assert 0 < token_limit < price_lexemes_module._MAX_JSON_NODES

    survivor = _materialized_pricing('{"prompt":0.000003,"completion":0}')["prompt"]
    gc.collect()
    registered_before = {
        id(value)
        for value in gc.get_objects()
        if type(value) is CapturedOpenRouterJSONNumber
        and captured_openrouter_json_number_raw(value) is not None
    }
    dense_off_path_numbers = (b"0," * token_limit) + b"0"
    payload = b'{"data":{"endpoints":[],"off_path_numbers":[' + dense_off_path_numbers + b"]}}"

    with pytest.raises(
        ValueError,
        match="provider price-lexeme JSON exceeds its numeric token bound",
    ):
        decode_openrouter_price_metadata_json(
            payload,
            layout=MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
        )

    gc.collect()
    registered_after = {
        id(value)
        for value in gc.get_objects()
        if type(value) is CapturedOpenRouterJSONNumber
        and captured_openrouter_json_number_raw(value) is not None
    }
    assert registered_after <= registered_before
    assert captured_openrouter_json_number_raw(survivor) == "0.000003"

    recovered = _materialized_pricing('{"prompt":0.000004,"completion":0}')
    assert captured_openrouter_json_number_raw(recovered["prompt"]) == "0.000004"
    assert _canonicalize_materialized_pricing(recovered) == {
        "completion": "0",
        "prompt": "0.000004",
    }


def test_price_decoder_normalizes_parser_recursion_failure_to_structural_refusal() -> None:
    nested = (b"[" * 2_000) + b"0" + (b"]" * 2_000)

    with pytest.raises(
        ValueError,
        match="provider price-lexeme JSON exceeds its structural bound",
    ):
        decode_openrouter_price_metadata_json(
            b'{"off_path":' + nested + b"}",
            layout=MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
        )


@pytest.mark.parametrize(
    "uncaptured_price",
    [
        pytest.param(0.000003, id="float"),
        pytest.param(0, id="integer"),
        pytest.param(Decimal("0.000003"), id="decimal"),
        pytest.param(True, id="boolean"),
    ],
)
def test_uncaptured_numeric_price_types_keep_exact_string_refusal(
    uncaptured_price: object,
) -> None:
    with pytest.raises(
        EndpointSnapshotValidationError,
        match=r"^endpoint prices must be exact decimal strings$",
    ):
        canonicalize_openrouter_pricing({"prompt": uncaptured_price, "completion": "0"})


@pytest.mark.parametrize(
    ("raw_price", "message"),
    [
        pytest.param("1e-6", "bounded decimal string", id="exponent"),
        pytest.param("0.0000030", "not canonically encoded", id="trailing-zero"),
        pytest.param("-0.000003", "bounded decimal string", id="negative"),
        pytest.param("1000000000000", "bounded decimal string", id="integer-bound"),
        pytest.param(
            "0.1234567890123456789012345678901234567",
            "bounded decimal string",
            id="fraction-bound",
        ),
    ],
)
def test_noncanonical_or_over_bound_captured_prices_are_rejected(
    raw_price: str,
    message: str,
) -> None:
    pricing = _materialized_pricing(f'{{"prompt":{raw_price},"completion":0}}')

    with pytest.raises(EndpointSnapshotValidationError, match=message):
        _canonicalize_materialized_pricing(pricing)


@pytest.mark.parametrize("raw_discount", ["0", "0.125"])
def test_captured_nonbillable_discount_is_validated_but_not_retained(
    raw_discount: str,
) -> None:
    pricing = _materialized_pricing(
        f'{{"prompt":0.000003,"completion":0,"discount":{raw_discount}}}'
    )

    assert captured_openrouter_json_number_raw(pricing["discount"]) == raw_discount
    assert _canonicalize_materialized_pricing(pricing) == {
        "completion": "0",
        "prompt": "0.000003",
    }


@pytest.mark.parametrize("raw_discount", ["-0.01", "1"])
def test_captured_nonbillable_discount_still_requires_a_bounded_fraction(
    raw_discount: str,
) -> None:
    pricing = _materialized_pricing(
        f'{{"prompt":0.000003,"completion":0,"discount":{raw_discount}}}'
    )

    with pytest.raises(
        EndpointSnapshotValidationError,
        match="endpoint discount metadata must be a finite nonnegative fraction",
    ):
        _canonicalize_materialized_pricing(pricing)


def test_decoder_retains_only_exact_paths_before_intermediate_graph_can_escape() -> None:
    decoded = decode_openrouter_price_metadata_json(
        (
            b'{"data":{"endpoints":[{"pricing":{"completion":0,"prompt":0.000003},'
            b'"shadow":{"completion":0,"prompt":0.000003},'
            b'"metadata":{"pricing":{"completion":0,"prompt":0.000003}}}]}}'
        ),
        layout=MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
    )
    endpoint = decoded["data"]["endpoints"][0]
    assert captured_openrouter_json_number_raw(endpoint["pricing"]["prompt"]) == "0.000003"
    assert type(endpoint["shadow"]["prompt"]) is float
    assert type(endpoint["shadow"]["completion"]) is int
    assert type(endpoint["metadata"]["pricing"]["prompt"]) is float


def test_unregistered_or_instance_modified_number_marker_is_never_admitted() -> None:
    assert not hasattr(price_lexemes_module, "_register_captured_openrouter_json_number")
    assert not hasattr(price_lexemes_module, "_LEXEME_ISSUER")
    assert not hasattr(price_lexemes_module, "capture_openrouter_json_decimal")
    assert not hasattr(price_lexemes_module, "capture_openrouter_json_integer")
    assert not hasattr(price_lexemes_module, "materialize_openrouter_price_lexemes")

    with pytest.raises(TypeError, match="bounded JSON decoding"):
        CapturedOpenRouterJSONNumber()

    unregistered = object.__new__(CapturedOpenRouterJSONNumber)
    with pytest.raises(AttributeError):
        object.__setattr__(unregistered, "_raw", "0.000009")

    assert captured_openrouter_json_number_raw(unregistered) is None
    assert (
        detach_captured_openrouter_json_number(
            unregistered,
            layout=MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
            path=("data", "endpoints", 0, "pricing", "prompt"),
        )
        is None
    )
    with pytest.raises(
        EndpointSnapshotValidationError,
        match=r"^endpoint prices must be exact decimal strings$",
    ):
        canonicalize_openrouter_pricing({"prompt": unregistered, "completion": "0"})

    slotless = _materialized_pricing('{"prompt":0.000004,"completion":0}')["prompt"]
    with pytest.raises(AttributeError):
        object.__setattr__(slotless, "_raw", "0.000009")
    assert captured_openrouter_json_number_raw(slotless) == "0.000004"

    captured = _materialized_pricing('{"prompt":0.000003,"completion":0}')["prompt"]
    original_raw = captured_openrouter_json_number_raw(captured)
    assert original_raw == "0.000003"
    with pytest.raises(AttributeError, match="immutable"):
        captured._raw = "0.000009"

    assert captured_openrouter_json_number_raw(captured) is None
    assert (
        detach_captured_openrouter_json_number(
            captured,
            layout=MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
            path=("data", "endpoints", 0, "pricing", "prompt"),
        )
        is None
    )
    with pytest.raises(AttributeError, match="immutable"):
        captured._raw = original_raw
    assert captured_openrouter_json_number_raw(captured) is None
    with pytest.raises(
        EndpointSnapshotValidationError,
        match=r"^endpoint prices must be exact decimal strings$",
    ):
        canonicalize_openrouter_pricing({"prompt": captured, "completion": "0"})


def test_observed_class_swap_cannot_restore_captured_authority() -> None:
    class SameLayout:
        __slots__ = ("__weakref__",)

    class HostileHashSameLayout:
        __slots__ = ("__weakref__",)

        def __hash__(self) -> int:
            raise AssertionError("a swapped-class hash hook must not run")

        def __eq__(self, _other: object) -> bool:
            raise AssertionError("a swapped-class equality hook must not run")

    for swapped_type in (SameLayout, HostileHashSameLayout):
        captured = _materialized_pricing('{"prompt":0.000003,"completion":0}')["prompt"]
        object.__setattr__(captured, "__class__", swapped_type)
        assert captured_openrouter_json_number_raw(captured) is None
        object.__setattr__(captured, "__class__", CapturedOpenRouterJSONNumber)

        assert captured_openrouter_json_number_raw(captured) is None
        with pytest.raises(
            EndpointSnapshotValidationError,
            match=r"^endpoint prices must be exact decimal strings$",
        ):
            canonicalize_openrouter_pricing({"prompt": captured, "completion": "0"})


def test_captured_number_copy_is_identity_preserving_and_does_not_mutate_class() -> None:
    captured = _materialized_pricing('{"prompt":0.000003,"completion":0}')["prompt"]

    assert copy.copy(captured) is captured
    assert copy.deepcopy(captured) is captured
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(captured)
    assert "__slotnames__" not in vars(CapturedOpenRouterJSONNumber)
    assert price_lexeme_callables_are_pristine()


def test_price_lexeme_integrity_guard_detects_helper_and_descriptor_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert price_lexeme_callables_are_pristine()

    with monkeypatch.context() as context:
        context.setattr(
            price_lexemes_module,
            "openrouter_json_number_is_price_path",
            lambda _path, *, layout: layout == MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
        )
        assert not price_lexeme_callables_are_pristine()

    with monkeypatch.context() as context:
        context.setattr(
            CapturedOpenRouterJSONNumber,
            "raw",
            property(lambda _value: "0"),
        )
        assert not price_lexeme_callables_are_pristine()

    with monkeypatch.context() as context:
        context.setattr(
            price_lexemes_module.weakref,
            "ref",
            lambda _value, _callback=None: None,
        )
        assert not price_lexeme_callables_are_pristine()

    raw_property = vars(CapturedOpenRouterJSONNumber)["raw"]
    assert type(raw_property) is property
    raw_getter = raw_property.fget
    assert raw_getter is not None
    original_code = raw_getter.__code__

    def substituted_raw_getter(_value: object) -> str:
        return "0"

    raw_getter.__code__ = substituted_raw_getter.__code__
    try:
        assert not price_lexeme_callables_are_pristine()
    finally:
        raw_getter.__code__ = original_code

    assert price_lexeme_callables_are_pristine()
