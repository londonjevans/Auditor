"""Fresh collision-free schema names must match the reference without retaining authority."""

from __future__ import annotations

import copy
import cProfile
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, Field, create_model
from pydantic.json_schema import GenerateJsonSchema, models_json_schema

import mmaudit.models.truncation as protocol
from tests.unit.test_truncation_schema_inventory import MODEL_NAMES

FIXTURES = json.loads(
    (Path(__file__).parents[1] / "fixtures/schema_remapping/reference_cases.json").read_text()
)["cases"]


def _profile_calls(profiler: cProfile.Profile, function: Any) -> int:
    return sum(row.callcount for row in profiler.getstats() if row.code is function.__code__)


@pytest.mark.parametrize("case", FIXTURES, ids=lambda item: item["id"])
def test_reference_maps_and_all_aliases_match_without_mutating_inputs(case: dict[str, Any]) -> None:
    original = GenerateJsonSchema(ref_template=case["ref_template"])
    optimized = protocol._CandidateReviewJsonSchemaGenerator(ref_template=case["ref_template"])
    for generator in (original, optimized):
        generator.definitions = copy.deepcopy(case["definitions"])
        generator._prioritized_defsref_choices = copy.deepcopy(case["choices"])
    expected = original._build_definitions_remapping()
    profile = cProfile.Profile()
    observed = profile.runcall(optimized._build_definitions_remapping)
    assert observed == expected
    for generator in (original, optimized):
        assert generator.definitions == case["definitions"]
        assert generator._prioritized_defsref_choices == case["choices"]
    before = {"$defs": copy.deepcopy(case["definitions"])}
    assert observed.remap_json_schema(copy.deepcopy(before)) == expected.remap_json_schema(before)
    assert _profile_calls(profile, GenerateJsonSchema._build_definitions_remapping) == (
        0 if case["fast_path"] else 1
    )
    assert _profile_calls(profile, protocol._collision_free_schema_remapping) == 1


@pytest.mark.parametrize("name", MODEL_NAMES)
def test_every_protocol_root_matches_fresh_reference_schema(name: str) -> None:
    model = getattr(protocol, name)
    before = model.__pydantic_validator__, model.__pydantic_core_schema__
    for mode in ("validation", "serialization"):
        for by_alias in (False, True):
            inputs = [(model, mode)]
            assert models_json_schema(
                inputs,
                by_alias=by_alias,
                schema_generator=protocol._CandidateReviewJsonSchemaGenerator,
            ) == models_json_schema(inputs, by_alias=by_alias)
    assert (model.__pydantic_validator__, model.__pydantic_core_schema__) == before
    assert protocol.candidate_review_protocol_implementation_is_pristine()


def test_protocol_batch_keeps_fresh_generation_without_reference_deduplication() -> None:
    profile = cProfile.Profile()
    for _ in range(3):
        assert profile.runcall(protocol.candidate_review_protocol_implementation_is_pristine)
    assert _profile_calls(profile, GenerateJsonSchema.generate_definitions) == 3
    assert _profile_calls(profile, protocol._collision_free_schema_remapping) == 3
    assert _profile_calls(profile, protocol._plain_schema_definitions) == 3
    assert _profile_calls(profile, GenerateJsonSchema._build_definitions_remapping) == 0
    assert _profile_calls(profile, protocol._DefinitionsRemapping.from_prioritized_choices) == 0


def test_normalized_protocol_inventory_digest_matches_the_reference() -> None:
    models = tuple(getattr(protocol, name) for name in MODEL_NAMES)
    roots, definitions = models_json_schema([(model, "validation") for model in models])
    inventory = {
        "roots": [roots[(model, "validation")] for model in models],
        "definitions": definitions,
    }

    def normalize(value: Any) -> None:
        if isinstance(value, dict):
            value.pop("default", None)
            if isinstance(value.get("properties"), dict):
                value["required"] = list(value["properties"])
                value["additionalProperties"] = False
            for child in value.values():
                normalize(child)
        elif isinstance(value, list):
            for child in value:
                normalize(child)

    normalize(inventory)
    assert protocol._candidate_review_schema_inventory_sha256(models) == protocol._canonical_sha256(
        inventory
    )


@pytest.mark.parametrize("same_fields", (False, True))
def test_real_colliding_models_retain_reference_fallback(same_fields: bool) -> None:
    one = create_model("Shared", value=(int, ...), __module__="synthetic.one")
    two = create_model(
        "Shared", value=(int if same_fields else str, ...), __module__="synthetic.two"
    )
    inputs = [(one, "validation"), (two, "validation")]
    expected = models_json_schema(inputs)
    profile = cProfile.Profile()
    actual = profile.runcall(
        models_json_schema, inputs, schema_generator=protocol._CandidateReviewJsonSchemaGenerator
    )
    assert actual == expected
    assert _profile_calls(profile, GenerateJsonSchema._build_definitions_remapping) == 1


def test_recursive_alias_and_union_schemas_match_reference() -> None:
    class SyntheticNode(BaseModel):
        value: int | str = Field(alias="label")
        children: list[SyntheticNode] = Field(default_factory=list)

    for mode in ("validation", "serialization"):
        inputs = [(SyntheticNode, mode)]
        assert models_json_schema(
            inputs, schema_generator=protocol._CandidateReviewJsonSchemaGenerator
        ) == models_json_schema(inputs)


class _CustomDict(dict[str, Any]):
    def __iter__(self) -> Any:
        raise AssertionError("unsupported container must not be traversed by the fast path")


class _CustomList(list[Any]):
    def __iter__(self) -> Any:
        raise AssertionError("unsupported container must not be traversed by the fast path")


class _CustomString(str):
    pass


class _CustomInt(int):
    pass


@pytest.mark.parametrize(
    "kind",
    (
        "choice_container",
        "definition_container",
        "choice_key",
        "definition_key",
        "alternative_container",
        "alternative_tuple",
        "alias_type",
        "empty_alternatives",
        "empty_alias",
        "missing_original_alias",
        "missing_group",
        "extra_group",
        "long_alias",
        "template_type",
        "template_value",
    ),
)
def test_unsupported_metadata_retains_reference_path(kind: str) -> None:
    choices: Any = {"synthetic_A": ["A", "synthetic_A"]}
    definitions: Any = {"synthetic_A": {"type": "string"}}
    template: Any = "#/$defs/{model}"
    if kind == "choice_container":
        choices = _CustomDict(choices)
    elif kind == "definition_container":
        definitions = _CustomDict(definitions)
    elif kind == "choice_key":
        choices = {_CustomString("synthetic_A"): choices["synthetic_A"]}
    elif kind == "definition_key":
        definitions = {_CustomString("synthetic_A"): definitions["synthetic_A"]}
    elif kind == "alternative_container":
        choices["synthetic_A"] = _CustomList(choices["synthetic_A"])
    elif kind == "alternative_tuple":
        choices["synthetic_A"] = tuple(choices["synthetic_A"])
    elif kind == "alias_type":
        choices["synthetic_A"][0] = _CustomString("A")
    elif kind == "empty_alternatives":
        choices["synthetic_A"] = []
    elif kind == "empty_alias":
        choices["synthetic_A"][0] = ""
    elif kind == "missing_original_alias":
        choices["synthetic_A"] = ["A"]
    elif kind == "missing_group":
        choices = {"missing": ["missing"]}
    elif kind == "extra_group":
        choices["extra"] = ["extra"]
    elif kind == "long_alias":
        choices["synthetic_A"][0] = "x" * (protocol._SCHEMA_REMAPPING_MAX_NAME_LENGTH + 1)
    elif kind == "template_type":
        template = _CustomString(template)
    else:
        template = "constant-ref-with-collisions"
    assert protocol._collision_free_schema_remapping(choices, definitions, template) is None


@pytest.mark.parametrize(
    "value",
    (
        _CustomDict(value=1),
        _CustomList([1]),
        _CustomString("text"),
        _CustomInt(1),
        float("nan"),
        float("inf"),
        float("-inf"),
        {1: "value"},
        (1, 2),
        object(),
    ),
)
def test_non_plain_json_uses_reference_without_fast_path_coercion(value: Any) -> None:
    assert (
        protocol._collision_free_schema_remapping(
            {"A": ["A"]}, {"A": {"x-synthetic": value}}, "#/$defs/{model}"
        )
        is None
    )


@pytest.mark.parametrize("bound", ("definitions", "aliases", "nodes", "depth", "name_length"))
def test_exact_fast_path_bounds_fall_back_only_after_the_limit(bound: str) -> None:
    for excess in (0, 1):
        choices: Any = {"A": ["A"]}
        definitions: Any = {"A": {"type": "string"}}
        if bound == "definitions":
            count = protocol._SCHEMA_REMAPPING_MAX_DEFINITIONS + excess
            choices = {f"A{i}": [f"A{i}"] for i in range(count)}
            definitions = {key: {} for key in choices}
        elif bound == "aliases":
            count = protocol._SCHEMA_REMAPPING_MAX_ALIASES + excess
            choices["A"] = ["A", *(f"alternative-{i}" for i in range(count - 1))]
        elif bound == "nodes":
            definitions = {"A": {"enum": [0] * (protocol._SCHEMA_REMAPPING_MAX_NODES - 3 + excess)}}
        elif bound == "depth":
            nested: Any = 0
            for _ in range(protocol._SCHEMA_REMAPPING_MAX_DEPTH - 1 + excess):
                nested = {"value": nested}
            definitions = {"A": nested}
        else:
            choices["A"] = ["A", "x" * (protocol._SCHEMA_REMAPPING_MAX_NAME_LENGTH + excess)]
        result = protocol._collision_free_schema_remapping(choices, definitions, "#/$defs/{model}")
        assert (result is not None) is (excess == 0)


def test_cycles_are_bounded_and_do_not_produce_a_fast_mapping() -> None:
    cycle: list[Any] = []
    cycle.append(cycle)
    assert (
        protocol._collision_free_schema_remapping(
            {"A": ["A"]}, {"A": {"x-synthetic": cycle}}, "#/$defs/{model}"
        )
        is None
    )


def test_unknown_types_do_not_invoke_custom_metaclass_equality() -> None:
    class NoEquality(type):
        def __eq__(cls, _other: object) -> bool:
            raise AssertionError("schema fast path must use identity checks for unknown types")

    class SyntheticOpaque(metaclass=NoEquality):
        pass

    assert (
        protocol._collision_free_schema_remapping(
            {"A": ["A"]}, {"A": {"x-synthetic": SyntheticOpaque()}}, "#/$defs/{model}"
        )
        is None
    )


def test_each_generation_gets_fresh_maps_and_preserves_shared_json_values() -> None:
    shared = {"type": "string"}
    choices: Any = {"A": ["A"], "B": ["B"]}
    definitions: Any = {"A": shared, "B": shared}
    first = protocol._collision_free_schema_remapping(choices, definitions, "#/$defs/{model}")
    second = protocol._collision_free_schema_remapping(choices, definitions, "#/$defs/{model}")
    assert first is not None and second is not None and first is not second
    assert first == second and first.defs_remapping is not second.defs_remapping
    assert first.json_remapping is not second.json_remapping
    assert definitions["A"] is definitions["B"] is shared
    assert shared == {"type": "string"}


@pytest.mark.parametrize(
    "target",
    (
        "helper_binding",
        "plain_binding",
        "generator_binding",
        "generator_override",
        "generator_constructor",
        "helper_code",
        "helper_defaults",
        "helper_keywords",
        "generator_code",
        "reference_binding",
        "reference_code",
        "remap_constructor",
        "remap_method",
        "limit",
        "template",
    ),
)
def test_new_dispatch_and_function_state_cannot_replace_fresh_integrity(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    def changed(*_args: Any, **_kwargs: Any) -> None:
        return None

    assert protocol.candidate_review_protocol_implementation_is_pristine()
    with monkeypatch.context() as patch:
        generator = protocol._CandidateReviewJsonSchemaGenerator
        helper = protocol._collision_free_schema_remapping
        if target == "helper_binding":
            patch.setattr(protocol, "_collision_free_schema_remapping", changed)
        elif target == "plain_binding":
            patch.setattr(protocol, "_plain_schema_definitions", changed)
        elif target == "generator_binding":
            patch.setattr(protocol, "_CandidateReviewJsonSchemaGenerator", GenerateJsonSchema)
        elif target == "generator_override":
            patch.setattr(
                generator, "generate_definitions", GenerateJsonSchema.generate_definitions
            )
        elif target == "generator_constructor":
            patch.setattr(generator, "__init__", GenerateJsonSchema.__init__)
        elif target == "helper_code":
            patch.setattr(helper, "__code__", changed.__code__)
        elif target == "helper_defaults":
            patch.setattr(helper, "__defaults__", (None,))
        elif target == "helper_keywords":
            patch.setattr(helper, "__kwdefaults__", {"unused": None})
        elif target == "generator_code":
            patch.setattr(generator._build_definitions_remapping, "__code__", changed.__code__)
        elif target == "reference_binding":
            patch.setattr(GenerateJsonSchema, "_build_definitions_remapping", changed)
        elif target == "reference_code":
            patch.setattr(
                GenerateJsonSchema._build_definitions_remapping, "__code__", changed.__code__
            )
        elif target == "remap_constructor":
            patch.setattr(protocol._DefinitionsRemapping, "__init__", changed)
        elif target == "remap_method":
            patch.setattr(protocol._DefinitionsRemapping, "remap_json_schema", changed)
        elif target == "limit":
            patch.setattr(protocol, "_SCHEMA_REMAPPING_MAX_DEFINITIONS", 255)
        else:
            patch.setattr(protocol, "_SCHEMA_REMAPPING_REF_TEMPLATE", "/changed/{model}")
        assert not protocol.candidate_review_protocol_implementation_is_pristine()
    assert protocol.candidate_review_protocol_implementation_is_pristine()


@pytest.mark.parametrize("target", ("helper_code", "generator_method", "limit", "reference"))
def test_schema_callbacks_cannot_change_remapping_implementation_mid_generation(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    def fallback(*_args: Any, **_kwargs: Any) -> None:
        return None

    assert protocol.candidate_review_protocol_implementation_is_pristine()
    with monkeypatch.context() as patch:

        def mutate(_schema: dict[str, Any]) -> None:
            if target == "helper_code":
                patch.setattr(
                    protocol._collision_free_schema_remapping, "__code__", fallback.__code__
                )
            elif target == "generator_method":
                patch.setattr(
                    protocol._CandidateReviewJsonSchemaGenerator,
                    "_build_definitions_remapping",
                    GenerateJsonSchema._build_definitions_remapping,
                )
            elif target == "limit":
                patch.setattr(protocol, "_SCHEMA_REMAPPING_MAX_DEFINITIONS", 255)
            else:
                patch.setattr(GenerateJsonSchema, "_build_definitions_remapping", fallback)

        patch.setitem(protocol.CandidateReviewEndFrame.model_config, "json_schema_extra", mutate)
        assert not protocol.candidate_review_protocol_implementation_is_pristine()
    assert protocol.candidate_review_protocol_implementation_is_pristine()
