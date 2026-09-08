"""Lossless, bounded custody for numeric provider-price JSON lexemes."""

from __future__ import annotations

import json
import math
import re
import weakref
from collections.abc import Callable
from decimal import Decimal, InvalidOperation
from types import FunctionType
from typing import Final, Literal, NoReturn, SupportsIndex, cast

type OpenRouterPriceLexemeLayout = Literal["model_endpoints", "zdr_endpoints"]
type OpenRouterJSONNumberKind = Literal["decimal", "integer"]
type OpenRouterJSONPath = tuple[str | int, ...]

MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT: Final[OpenRouterPriceLexemeLayout] = "model_endpoints"
ZDR_ENDPOINT_PRICE_LEXEME_LAYOUT: Final[OpenRouterPriceLexemeLayout] = "zdr_endpoints"

_JSON_NUMBER_PATTERN = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z")
_MAX_JSON_CONTENT_BYTES = 20_000_000
_MAX_JSON_NUMBER_LEXEME_LENGTH = 128
_MAX_JSON_NUMBER_TOKENS = 100_000
_MAX_JSON_DEPTH = 256
_MAX_JSON_NODES = 2_000_000

type _CapturedOpenRouterJSONNumberState = tuple[
    str,
    OpenRouterJSONNumberKind,
    Decimal,
    OpenRouterPriceLexemeLayout,
    OpenRouterJSONPath,
]
type _OpenRouterJSONNumberRegistryState = tuple[
    str,
    OpenRouterJSONNumberKind,
    Decimal,
    OpenRouterPriceLexemeLayout,
    OpenRouterJSONPath,
]


class CapturedOpenRouterJSONNumber:
    """One registry-only JSON number issued by the endpoint metadata decoder."""

    __slots__ = ("__weakref__",)

    def __new__(cls) -> CapturedOpenRouterJSONNumber:
        raise TypeError(
            "captured provider-price numbers require trusted decoder custody through "
            "bounded JSON decoding"
        )

    def __init__(self) -> None:
        raise TypeError(
            "captured provider-price numbers require trusted decoder custody through "
            "bounded JSON decoding"
        )

    def __setattr__(self, _name: str, _value: object) -> NoReturn:
        _revoke_captured_openrouter_json_number(self)
        raise AttributeError("captured provider-price numbers are immutable")

    def __delattr__(self, _name: str) -> NoReturn:
        _revoke_captured_openrouter_json_number(self)
        raise AttributeError("captured provider-price numbers are immutable")

    def __copy__(self) -> CapturedOpenRouterJSONNumber:
        if _registered_captured_openrouter_json_number_state(self) is None:
            raise ValueError("provider price-lexeme token lost decoder custody")
        return self

    def __deepcopy__(self, _memo: dict[int, object]) -> CapturedOpenRouterJSONNumber:
        if _registered_captured_openrouter_json_number_state(self) is None:
            raise ValueError("provider price-lexeme token lost decoder custody")
        return self

    def __reduce__(self) -> NoReturn:
        raise TypeError("captured provider-price numbers cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("captured provider-price numbers cannot be serialized")

    @property
    def raw(self) -> str:
        state = _registered_captured_openrouter_json_number_state(self)
        if state is None:
            raise ValueError("provider price-lexeme token lost decoder custody")
        return state[0]

    @property
    def kind(self) -> OpenRouterJSONNumberKind:
        state = _registered_captured_openrouter_json_number_state(self)
        if state is None:
            raise ValueError("provider price-lexeme token lost decoder custody")
        return state[1]

    @property
    def decimal(self) -> Decimal:
        state = _registered_captured_openrouter_json_number_state(self)
        if state is None:
            raise ValueError("provider price-lexeme token lost decoder custody")
        return state[2]


type _OpenRouterJSONNumberRegistryEntry = tuple[
    weakref.ReferenceType[CapturedOpenRouterJSONNumber],
    _OpenRouterJSONNumberRegistryState,
]


def openrouter_json_number_is_price_path(
    path: OpenRouterJSONPath,
    *,
    layout: OpenRouterPriceLexemeLayout,
) -> bool:
    """Return whether a path is one direct price value in a fixed provider envelope."""

    if type(layout) is not str or layout not in {
        MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
        ZDR_ENDPOINT_PRICE_LEXEME_LAYOUT,
    }:
        raise ValueError("provider price-lexeme layout is invalid")
    if type(path) is not tuple:
        return False
    if layout == MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT:
        return (
            len(path) == 5
            and type(path[0]) is str
            and path[0] == "data"
            and type(path[1]) is str
            and path[1] == "endpoints"
            and type(path[2]) is int
            and path[2] >= 0
            and type(path[3]) is str
            and path[3] == "pricing"
            and type(path[4]) is str
        )
    return (
        len(path) == 4
        and type(path[0]) is str
        and path[0] == "data"
        and type(path[1]) is int
        and path[1] >= 0
        and type(path[2]) is str
        and path[2] == "pricing"
        and type(path[3]) is str
    )


def _build_openrouter_price_metadata_decoder() -> tuple[
    Callable[
        [bytes, OpenRouterPriceLexemeLayout],
        dict[str, object],
    ],
    Callable[[object], _CapturedOpenRouterJSONNumberState | None],
    Callable[[object], None],
]:
    captured_type = CapturedOpenRouterJSONNumber
    trusted_decimal = Decimal
    trusted_invalid_operation = InvalidOperation
    trusted_json_loads = json.loads
    trusted_math_isfinite = math.isfinite
    trusted_number_pattern = _JSON_NUMBER_PATTERN
    trusted_object_new = object.__new__
    trusted_recursion_error = RecursionError
    trusted_is_price_path = openrouter_json_number_is_price_path
    trusted_weakref_ref = weakref.ref
    model_layout = MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT
    zdr_layout = ZDR_ENDPOINT_PRICE_LEXEME_LAYOUT
    pending_number_marker = object()
    registry: dict[int, _OpenRouterJSONNumberRegistryEntry] = {}

    def pop_exact_entry(
        identity: int,
        reference: weakref.ReferenceType[CapturedOpenRouterJSONNumber],
    ) -> None:
        current = registry.get(identity)
        if current is not None and current[0] is reference:
            registry.pop(identity, None)

    def exact_registry_entry(value: object) -> _OpenRouterJSONNumberRegistryEntry | None:
        identity = id(value)
        entry = registry.get(identity)
        if entry is None:
            return None
        reference, _state = entry
        if reference() is not value or type(value) is not captured_type:
            pop_exact_entry(identity, reference)
            return None
        return entry

    def registered_state(value: object) -> _CapturedOpenRouterJSONNumberState | None:
        entry = exact_registry_entry(value)
        if entry is None:
            return None
        reference, state = entry
        raw, kind, decimal, layout, path = state
        if (
            type(raw) is not str
            or not 1 <= len(raw) <= _MAX_JSON_NUMBER_LEXEME_LENGTH
            or trusted_number_pattern.fullmatch(raw) is None
            or kind not in {"decimal", "integer"}
            or (kind == "integer" and any(marker in raw for marker in ".eE"))
            or (kind == "decimal" and all(marker not in raw for marker in ".eE"))
            or type(decimal) is not trusted_decimal
            or not decimal.is_finite()
            or decimal != trusted_decimal(raw)
            or type(layout) is not str
            or layout not in {model_layout, zdr_layout}
            or not trusted_is_price_path(path, layout=layout)
        ):
            pop_exact_entry(id(value), reference)
            return None
        return raw, kind, decimal, layout, path

    def revoke(value: object) -> None:
        identity = id(value)
        entry = registry.get(identity)
        if entry is None:
            return
        reference, _state = entry
        referenced_value = reference()
        if referenced_value is value or referenced_value is None:
            pop_exact_entry(identity, reference)

    def decode(
        content: bytes,
        layout: OpenRouterPriceLexemeLayout,
    ) -> dict[str, object]:
        if type(content) is not bytes or not 1 <= len(content) <= _MAX_JSON_CONTENT_BYTES:
            raise ValueError("provider price metadata is not a bounded byte payload")
        if type(layout) is not str or layout not in {model_layout, zdr_layout}:
            raise ValueError("provider price-lexeme layout is invalid")

        numeric_tokens = 0

        def capture_pending(
            raw: str,
            kind: OpenRouterJSONNumberKind,
        ) -> tuple[object, str, OpenRouterJSONNumberKind]:
            nonlocal numeric_tokens
            numeric_tokens += 1
            if numeric_tokens > _MAX_JSON_NUMBER_TOKENS:
                raise ValueError("provider price-lexeme JSON exceeds its numeric token bound")
            if (
                type(raw) is not str
                or not 1 <= len(raw) <= _MAX_JSON_NUMBER_LEXEME_LENGTH
                or trusted_number_pattern.fullmatch(raw) is None
                or kind not in {"decimal", "integer"}
                or (kind == "integer" and any(marker in raw for marker in ".eE"))
                or (kind == "decimal" and all(marker not in raw for marker in ".eE"))
            ):
                raise ValueError("provider metadata contains an invalid numeric lexeme")
            return pending_number_marker, raw, kind

        def issue(
            raw: str,
            kind: OpenRouterJSONNumberKind,
            path: OpenRouterJSONPath,
        ) -> CapturedOpenRouterJSONNumber:
            try:
                parsed = trusted_decimal(raw)
            except trusted_invalid_operation as exc:
                raise ValueError("provider metadata contains an invalid numeric lexeme") from exc
            if not parsed.is_finite():
                raise ValueError("provider metadata contains a non-finite numeric lexeme")
            value = cast(CapturedOpenRouterJSONNumber, trusted_object_new(captured_type))
            identity = id(value)
            previous = registry.get(identity)
            if previous is not None:
                previous_reference, _previous_state = previous
                if previous_reference() is not None:
                    raise RuntimeError("provider price-lexeme registry identity collision")
                pop_exact_entry(identity, previous_reference)

            def cleanup(
                reference: weakref.ReferenceType[CapturedOpenRouterJSONNumber],
            ) -> None:
                pop_exact_entry(identity, reference)

            reference = trusted_weakref_ref(value, cleanup)
            registry[identity] = (reference, (raw, kind, parsed, layout, path))
            return value

        def capture_decimal(
            raw: str,
        ) -> tuple[object, str, OpenRouterJSONNumberKind]:
            return capture_pending(raw, "decimal")

        def capture_integer(
            raw: str,
        ) -> tuple[object, str, OpenRouterJSONNumberKind]:
            return capture_pending(raw, "integer")

        def reject_nonfinite(_raw: str) -> NoReturn:
            raise ValueError("provider metadata contains a non-finite JSON number")

        def unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if type(key) is not str or key in result:
                    raise ValueError("provider metadata contains a duplicate or invalid object key")
                result[key] = value
            return result

        try:
            decoded: object = trusted_json_loads(
                content,
                parse_float=capture_decimal,
                parse_int=capture_integer,
                parse_constant=reject_nonfinite,
                object_pairs_hook=unique_json_object,
            )
        except trusted_recursion_error as exc:
            raise ValueError("provider price-lexeme JSON exceeds its structural bound") from exc
        if type(decoded) is not dict:
            raise ValueError("provider price metadata response is not a JSON object")

        nodes = 0

        def materialize(
            current: object,
            *,
            path: OpenRouterJSONPath,
            depth: int,
        ) -> object:
            nonlocal nodes
            nodes += 1
            if depth > _MAX_JSON_DEPTH or nodes > _MAX_JSON_NODES:
                raise ValueError("provider price-lexeme JSON exceeds its structural bound")
            if (
                type(current) is tuple
                and len(current) == 3
                and current[0] is pending_number_marker
                and type(current[1]) is str
                and current[2] in {"decimal", "integer"}
            ):
                raw = cast(str, current[1])
                kind = cast(OpenRouterJSONNumberKind, current[2])
                if trusted_is_price_path(path, layout=layout):
                    return issue(raw, kind, path)
                if kind == "integer":
                    return int(raw)
                native_float = float(raw)
                if not trusted_math_isfinite(native_float):
                    raise ValueError("provider metadata contains a non-finite decoded JSON number")
                return native_float
            if type(current) is dict:
                if any(type(key) is not str for key in current):
                    raise ValueError("provider price-lexeme JSON contains a non-string object key")
                return {
                    key: materialize(value, path=(*path, key), depth=depth + 1)
                    for key, value in dict.items(current)
                }
            if type(current) is list:
                return [
                    materialize(value, path=(*path, index), depth=depth + 1)
                    for index, value in enumerate(list.__iter__(current))
                ]
            return current

        materialized = materialize(decoded, path=(), depth=0)
        if type(materialized) is not dict:
            raise ValueError("provider price metadata response is not a JSON object")
        return cast(dict[str, object], materialized)

    return decode, registered_state, revoke


(
    _decode_openrouter_price_metadata_json,
    _registered_captured_openrouter_json_number_state,
    _revoke_captured_openrouter_json_number,
) = _build_openrouter_price_metadata_decoder()
del _build_openrouter_price_metadata_decoder


def decode_openrouter_price_metadata_json(
    content: bytes,
    *,
    layout: OpenRouterPriceLexemeLayout,
) -> dict[str, object]:
    """Decode one bounded object and retain exact numbers only at fixed price paths."""

    return _decode_openrouter_price_metadata_json(content, layout)


def captured_openrouter_json_number_raw(value: object) -> str | None:
    """Return a decoder-issued raw lexeme, rejecting bare Decimal and subclasses."""

    state = _registered_captured_openrouter_json_number_state(value)
    return None if state is None else state[0]


def captured_openrouter_json_number_decimal(value: object) -> Decimal | None:
    """Return the exact decoded decimal value for a genuine captured token."""

    state = _registered_captured_openrouter_json_number_state(value)
    return None if state is None else state[2]


def revoke_captured_openrouter_json_number(value: object) -> None:
    """Permanently remove any decoder custody associated with this identity."""

    _revoke_captured_openrouter_json_number(value)


def captured_openrouter_json_number_matches_path(
    value: object,
    *,
    layout: OpenRouterPriceLexemeLayout,
    path: OpenRouterJSONPath,
) -> bool:
    """Match exact decoder custody, revoking a token after any observed relocation."""

    state = _registered_captured_openrouter_json_number_state(value)
    if state is None:
        return False
    try:
        matches = (
            openrouter_json_number_is_price_path(path, layout=layout)
            and state[3] == layout
            and state[4] == path
        )
    except ValueError:
        matches = False
    if not matches:
        _revoke_captured_openrouter_json_number(value)
    return matches


def detach_captured_openrouter_json_number(
    value: object,
    *,
    layout: OpenRouterPriceLexemeLayout,
    path: OpenRouterJSONPath,
) -> CapturedOpenRouterJSONNumber | None:
    """Preserve one genuine token identity after an exact decoder-origin path match."""

    if not captured_openrouter_json_number_matches_path(value, layout=layout, path=path):
        return None
    return cast(CapturedOpenRouterJSONNumber, value)


def openrouter_json_number_digest_channels(
    value: object,
) -> tuple[object, tuple[dict[str, object], ...]] | None:
    """Separate path-bound tokens from ordinary JSON for domain-prefixed hashing."""

    lexemes: list[dict[str, object]] = []
    nodes = 0

    def project(current: object, *, path: OpenRouterJSONPath, depth: int) -> object:
        nonlocal nodes
        nodes += 1
        if depth > _MAX_JSON_DEPTH or nodes > _MAX_JSON_NODES:
            raise ValueError("provider price-lexeme JSON exceeds its structural bound")
        if type(current) is CapturedOpenRouterJSONNumber:
            state = _registered_captured_openrouter_json_number_state(current)
            if state is None:
                raise ValueError("provider price-lexeme token lost decoder custody")
            raw, kind, _decimal, layout, bound_path = state
            if path != bound_path or not openrouter_json_number_is_price_path(path, layout=layout):
                _revoke_captured_openrouter_json_number(current)
                raise ValueError("provider price-lexeme token moved from its decoder-bound path")
            lexemes.append(
                {
                    "path": [
                        {"key": segment} if type(segment) is str else {"index": segment}
                        for segment in path
                    ],
                    "kind": kind,
                    "raw": raw,
                }
            )
            return None
        if type(current) is dict:
            if any(type(key) is not str for key in current):
                raise ValueError("provider price-lexeme JSON contains a non-string object key")
            keys = list(dict.keys(current))
            keys.sort()
            return {
                key: project(
                    dict.__getitem__(current, key),
                    path=(*path, key),
                    depth=depth + 1,
                )
                for key in keys
            }
        if type(current) is list:
            return [
                project(item, path=(*path, index), depth=depth + 1)
                for index, item in enumerate(list.__iter__(current))
            ]
        if type(current) is tuple:
            return [
                project(item, path=(*path, index), depth=depth + 1)
                for index, item in enumerate(tuple.__iter__(current))
            ]
        return current

    projected = project(value, path=(), depth=0)
    if not lexemes:
        return None
    return projected, tuple(lexemes)


def _install_price_lexeme_integrity_guard() -> Callable[[], bool]:
    """Seal the complete helper graph used by trusted endpoint-number custody."""

    module_globals = globals()
    captured_type = CapturedOpenRouterJSONNumber
    trusted_decimal = Decimal
    trusted_invalid_operation = InvalidOperation
    trusted_json = json
    trusted_json_loads = json.loads
    trusted_weakref = weakref
    trusted_weakref_ref = weakref.ref
    trusted_weakref_reference_type = weakref.ReferenceType
    trusted_math = math
    trusted_math_isfinite = math.isfinite
    trusted_pattern = _JSON_NUMBER_PATTERN
    trusted_decimal_layout = MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT
    trusted_zdr_layout = ZDR_ENDPOINT_PRICE_LEXEME_LAYOUT
    trusted_max_content_bytes = _MAX_JSON_CONTENT_BYTES
    trusted_max_length = _MAX_JSON_NUMBER_LEXEME_LENGTH
    trusted_max_number_tokens = _MAX_JSON_NUMBER_TOKENS
    trusted_max_depth = _MAX_JSON_DEPTH
    trusted_max_nodes = _MAX_JSON_NODES
    module_function_bindings = (
        (
            "_decode_openrouter_price_metadata_json",
            _decode_openrouter_price_metadata_json,
        ),
        (
            "_registered_captured_openrouter_json_number_state",
            _registered_captured_openrouter_json_number_state,
        ),
        (
            "_revoke_captured_openrouter_json_number",
            _revoke_captured_openrouter_json_number,
        ),
        ("decode_openrouter_price_metadata_json", decode_openrouter_price_metadata_json),
        ("captured_openrouter_json_number_raw", captured_openrouter_json_number_raw),
        ("captured_openrouter_json_number_decimal", captured_openrouter_json_number_decimal),
        ("revoke_captured_openrouter_json_number", revoke_captured_openrouter_json_number),
        (
            "captured_openrouter_json_number_matches_path",
            captured_openrouter_json_number_matches_path,
        ),
        ("detach_captured_openrouter_json_number", detach_captured_openrouter_json_number),
        ("openrouter_json_number_digest_channels", openrouter_json_number_digest_channels),
        ("openrouter_json_number_is_price_path", openrouter_json_number_is_price_path),
    )
    module_functions = tuple(
        cast(FunctionType, function) for _name, function in module_function_bindings
    )
    class_functions = (
        cast(FunctionType, captured_type.__new__),
        cast(FunctionType, captured_type.__init__),
        cast(FunctionType, captured_type.__setattr__),
        cast(FunctionType, captured_type.__delattr__),
        cast(FunctionType, captured_type.__copy__),
        cast(FunctionType, captured_type.__deepcopy__),
        cast(FunctionType, captured_type.__reduce__),
        cast(FunctionType, captured_type.__reduce_ex__),
        cast(FunctionType, cast(property, vars(captured_type)["raw"]).fget),
        cast(FunctionType, cast(property, vars(captured_type)["kind"]).fget),
        cast(FunctionType, cast(property, vars(captured_type)["decimal"]).fget),
    )
    functions = (*module_functions, *class_functions)

    def function_state(function: FunctionType) -> tuple[object, ...]:
        kwdefaults = function.__kwdefaults__
        attributes = function.__dict__
        closure = function.__closure__
        closure_state = tuple((cell, cell.cell_contents) for cell in closure or ())
        return (
            function,
            function.__code__,
            function.__defaults__,
            kwdefaults,
            tuple(sorted((kwdefaults or {}).items())),
            function.__globals__,
            attributes,
            tuple(sorted(attributes.items())),
            closure,
            closure_state,
        )

    states = tuple(function_state(function) for function in functions)
    class_items = tuple(sorted(vars(captured_type).items()))

    def pristine() -> bool:
        try:
            if (
                module_globals.get("price_lexeme_callables_are_pristine") is not pristine
                or module_globals.get("CapturedOpenRouterJSONNumber") is not captured_type
                or module_globals.get("Decimal") is not trusted_decimal
                or module_globals.get("InvalidOperation") is not trusted_invalid_operation
                or module_globals.get("json") is not trusted_json
                or trusted_json.loads is not trusted_json_loads
                or module_globals.get("weakref") is not trusted_weakref
                or trusted_weakref.ref is not trusted_weakref_ref
                or trusted_weakref.ReferenceType is not trusted_weakref_reference_type
                or module_globals.get("math") is not trusted_math
                or trusted_math.isfinite is not trusted_math_isfinite
                or module_globals.get("_JSON_NUMBER_PATTERN") is not trusted_pattern
                or module_globals.get("MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT")
                is not trusted_decimal_layout
                or module_globals.get("ZDR_ENDPOINT_PRICE_LEXEME_LAYOUT") is not trusted_zdr_layout
                or module_globals.get("_MAX_JSON_CONTENT_BYTES") != trusted_max_content_bytes
                or module_globals.get("_MAX_JSON_NUMBER_LEXEME_LENGTH") != trusted_max_length
                or module_globals.get("_MAX_JSON_NUMBER_TOKENS") != trusted_max_number_tokens
                or module_globals.get("_MAX_JSON_DEPTH") != trusted_max_depth
                or module_globals.get("_MAX_JSON_NODES") != trusted_max_nodes
                or tuple(module_globals.get(name) for name, _function in module_function_bindings)
                != module_functions
            ):
                return False
            current_class_items = vars(captured_type)
            if len(current_class_items) != len(class_items) or any(
                current_class_items.get(name) is not value for name, value in class_items
            ):
                return False
            for state in states:
                function = state[0]
                if type(function) is not FunctionType:
                    return False
                kwdefaults = function.__kwdefaults__
                attributes = function.__dict__
                closure = function.__closure__
                expected_closure_state = cast(
                    tuple[tuple[object, object], ...],
                    state[9],
                )
                if (
                    function.__code__ is not state[1]
                    or function.__defaults__ is not state[2]
                    or kwdefaults is not state[3]
                    or tuple(sorted((kwdefaults or {}).items())) != state[4]
                    or function.__globals__ is not state[5]
                    or attributes is not state[6]
                    or tuple(sorted(attributes.items())) != state[7]
                    or closure is not state[8]
                    or len(closure or ()) != len(expected_closure_state)
                    or any(
                        cell is not expected_cell or cell.cell_contents is not expected_value
                        for cell, (expected_cell, expected_value) in zip(
                            closure or (),
                            expected_closure_state,
                            strict=True,
                        )
                    )
                ):
                    return False
            return True
        except BaseException:
            return False

    return pristine


price_lexeme_callables_are_pristine = _install_price_lexeme_integrity_guard()
del _install_price_lexeme_integrity_guard
if not price_lexeme_callables_are_pristine():
    raise RuntimeError("provider price-lexeme custody failed its initial integrity check")
