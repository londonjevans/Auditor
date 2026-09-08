"""Fresh schema inventory checks must stay bounded without retaining stale authority."""

from __future__ import annotations

import cProfile
from typing import Any

import pydantic.main
import pytest
from pydantic import BaseModel
from pydantic.json_schema import GenerateJsonSchema

import mmaudit.models.truncation as protocol
from mmaudit.models.schemas import Location

MODEL_NAMES = (
    "CandidateFinding",
    "CandidateReviewBatch",
    "ModelSurfaceReviewRecord",
    "CandidateReviewBeginFrame",
    "CandidateReviewFindingFrame",
    "CandidateReviewFindingsEndFrame",
    "CandidateReviewSurfaceReviewFrame",
    "CandidateReviewSurfaceReviewsEndFrame",
    "CandidateReviewSummaryFrame",
    "CandidateReviewEndFrame",
    "CandidateReviewFramedDocument",
    "CandidateReviewAcceptedFrame",
    "CandidateReviewTruncationProjection",
    "CandidateReviewNormalizationEvidence",
    "CandidateReviewTruncatedEnvelopeEvidence",
)


def test_pristine_guard_generates_one_fresh_inventory_per_call() -> None:
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    profiler = cProfile.Profile()
    for _ in range(3):
        assert profiler.runcall(protocol.candidate_review_protocol_implementation_is_pristine)

    calls = {entry.code: entry.callcount for entry in profiler.getstats()}
    assert calls.get(GenerateJsonSchema.generate_definitions.__code__, 0) == 3
    assert calls.get(GenerateJsonSchema.generate.__code__, 0) == 0


@pytest.mark.parametrize("name", MODEL_NAMES)
def test_each_schema_is_regenerated_after_in_place_configuration_drift(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    model = getattr(protocol, name)
    validator, core_schema = model.__pydantic_validator__, model.__pydantic_core_schema__
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    with monkeypatch.context() as patch:
        patch.setitem(model.model_config, "title", "Synthetic changed schema title")
        assert model.__pydantic_validator__ is validator
        assert model.__pydantic_core_schema__ is core_schema
        assert not protocol.candidate_review_protocol_implementation_is_pristine()
    assert protocol.candidate_review_protocol_implementation_is_pristine()


def test_transitive_schema_drift_is_not_hidden_by_shared_definitions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    with monkeypatch.context() as patch:
        patch.setitem(Location.model_config, "title", "Synthetic changed nested location")
        assert not protocol.candidate_review_protocol_implementation_is_pristine()
    assert protocol.candidate_review_protocol_implementation_is_pristine()


def test_in_place_core_field_constraints_are_checked_without_rebuild(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = protocol.CandidateReviewBeginFrame
    core = model.__pydantic_core_schema__
    before = protocol._strict_schema_sha256(model)
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    with monkeypatch.context() as patch:
        patch.setitem(core["schema"]["fields"]["finding_count"]["schema"], "ge", 99)
        assert model.__pydantic_core_schema__ is core
        assert protocol._strict_schema_sha256(model) != before
        assert not protocol.candidate_review_protocol_implementation_is_pristine()
    assert protocol.candidate_review_protocol_implementation_is_pristine()


def test_forced_rebuild_with_unchanged_schema_still_loses_generation_custody(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = protocol.CandidateReviewBeginFrame
    before = model.model_json_schema()
    with monkeypatch.context() as patch:
        for name in (
            "__pydantic_core_schema__",
            "__pydantic_validator__",
            "__pydantic_serializer__",
            "__pydantic_complete__",
        ):
            patch.setattr(model, name, getattr(model, name))
        assert model.model_rebuild(force=True) is True
        assert model.model_json_schema() == before
        assert not protocol.candidate_review_protocol_implementation_is_pristine()
    assert protocol.candidate_review_protocol_implementation_is_pristine()


@pytest.mark.parametrize(
    "target", ("base_method", "module_renderer", "single_generator", "batch_generator")
)
def test_single_model_rendering_dispatch_drift_is_rejected(
    monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    def changed(*_args: Any, **_kwargs: Any) -> dict[str, str]:
        return {"title": "Synthetic changed rendering dispatch"}

    assert protocol.candidate_review_protocol_implementation_is_pristine()
    with monkeypatch.context() as patch:
        if target == "base_method":
            patch.setattr(BaseModel, "model_json_schema", classmethod(changed))
        elif target == "module_renderer":
            patch.setattr(pydantic.main, "model_json_schema", changed)
        elif target == "single_generator":
            patch.setattr(GenerateJsonSchema, "generate", changed)
        else:
            patch.setattr(GenerateJsonSchema, "generate_definitions", changed)
        assert not protocol.candidate_review_protocol_implementation_is_pristine()
    assert protocol.candidate_review_protocol_implementation_is_pristine()


def test_renderer_code_mutation_cannot_reuse_an_inventory_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def changed(self: Any, schema: Any, mode: str = "validation") -> dict[str, str]:
        return {"title": "Synthetic altered renderer implementation"}

    assert protocol.candidate_review_protocol_implementation_is_pristine()
    with monkeypatch.context() as patch:
        patch.setattr(GenerateJsonSchema.generate, "__code__", changed.__code__)
        assert not protocol.candidate_review_protocol_implementation_is_pristine()
    assert protocol.candidate_review_protocol_implementation_is_pristine()


def test_generation_custody_is_rechecked_after_schema_callbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    with monkeypatch.context() as patch:

        def mutate_earlier_generation(_schema: dict[str, Any]) -> None:
            patch.setattr(protocol.CandidateReviewBeginFrame, "__pydantic_validator__", object())

        patch.setitem(
            protocol.CandidateReviewEndFrame.model_config,
            "json_schema_extra",
            mutate_earlier_generation,
        )
        assert not protocol.candidate_review_protocol_implementation_is_pristine()
    assert protocol.candidate_review_protocol_implementation_is_pristine()


@pytest.mark.parametrize("mutation", ("configuration", "core_constraint"))
def test_in_place_input_drift_after_an_earlier_shared_definition_is_rejected(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    with monkeypatch.context() as patch:

        def mutate_earlier_schema(_schema: dict[str, Any]) -> None:
            if mutation == "configuration":
                patch.setitem(
                    protocol.CandidateFinding.model_config, "title", "Changed during render"
                )
            else:
                core = protocol.CandidateReviewBeginFrame.__pydantic_core_schema__
                patch.setitem(core["schema"]["fields"]["finding_count"]["schema"], "ge", 99)

        patch.setitem(
            protocol.CandidateReviewEndFrame.model_config,
            "json_schema_extra",
            mutate_earlier_schema,
        )
        assert not protocol.candidate_review_protocol_implementation_is_pristine()
    assert protocol.candidate_review_protocol_implementation_is_pristine()


@pytest.mark.parametrize("mutation", ("mapping_value", "mapping_size", "list_value", "list_size"))
def test_input_snapshot_compares_mutable_edges_without_user_equality(mutation: str) -> None:
    class SyntheticSchema(BaseModel):
        value: int

    nested: dict[str, Any] = {"values": [1, 2]}
    SyntheticSchema.model_config["json_schema_extra"] = nested
    guard = protocol._candidate_review_schema_input_guard((SyntheticSchema,))
    assert guard is not None and guard()
    if mutation == "mapping_value":
        nested["values"] = [1, 2]
    elif mutation == "mapping_size":
        nested["extra"] = 1
    elif mutation == "list_value":
        nested["values"][0] = 2
    else:
        nested["values"].append(3)
    assert not guard()


def test_input_snapshot_cycles_are_bounded_and_still_observe_mutation() -> None:
    class SyntheticSchema(BaseModel):
        value: int

    cycle: list[Any] = []
    cycle.append(cycle)
    SyntheticSchema.model_config["json_schema_extra"] = {"cycle": cycle}
    guard = protocol._candidate_review_schema_input_guard((SyntheticSchema,))
    assert guard is not None and guard()
    cycle.append(1)
    assert not guard()


@pytest.mark.parametrize(
    "kind", ("node_limit", "repeated_edge_limit", "mapping_subclass", "list_subclass")
)
def test_input_snapshot_refuses_excessive_or_custom_mutable_graphs(kind: str) -> None:
    class SyntheticSchema(BaseModel):
        value: int

    class CustomMapping(dict[str, Any]):
        pass

    class CustomList(list[int]):
        pass

    value = (
        list(range(50_001))
        if kind == "node_limit"
        else [0] * 50_001
        if kind == "repeated_edge_limit"
        else CustomMapping(values=[1])
        if kind == "mapping_subclass"
        else CustomList([1])
    )
    SyntheticSchema.model_config["json_schema_extra"] = {"value": value}
    assert protocol._candidate_review_schema_input_guard((SyntheticSchema,)) is None


@pytest.mark.parametrize("mutation", ("positional_defaults", "keyword_defaults"))
def test_renderer_default_mutation_cannot_change_the_bound_schema_contract(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    renderer = BaseModel.model_json_schema.__func__
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    with monkeypatch.context() as patch:
        if mutation == "positional_defaults":
            patch.setattr(renderer, "__defaults__", (False, *renderer.__defaults__[1:]))
        else:
            patch.setitem(renderer.__kwdefaults__, "union_format", "primitive_type_array")
        assert not protocol.candidate_review_protocol_implementation_is_pristine()
    assert protocol.candidate_review_protocol_implementation_is_pristine()
