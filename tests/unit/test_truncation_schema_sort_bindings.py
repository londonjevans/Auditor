"""Equivalent sorting behavior cannot substitute a changed implementation dependency."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic.json_schema import GenerateJsonSchema

import mmaudit.models.truncation as protocol

FIXTURE = json.loads(
    (Path(__file__).parents[1] / "fixtures/schema_sort_bindings/mutations.json").read_text()
)
assert FIXTURE["scope"] == "SYNTHETIC_SORT_DEPENDENCY_IDENTITIES_NO_PROVIDER"


def _mutate_sort_dependency(patch: pytest.MonkeyPatch, method_name: str, mutation: str) -> None:
    original = getattr(GenerateJsonSchema, method_name)
    if mutation == "rebind":

        def equivalent(self: GenerateJsonSchema, value: Any, parent_key: str | None = None) -> Any:
            return original(self, value, parent_key=parent_key)

        patch.setattr(GenerateJsonSchema, method_name, equivalent)
    elif mutation == "code":
        patch.setattr(
            original,
            "__code__",
            original.__code__.replace(co_filename="<synthetic-sort-dependency-change>"),
        )
    elif mutation == "defaults":
        defaults = original.__defaults__
        assert type(defaults) is tuple and defaults
        replacement = tuple(value for value in defaults)
        assert replacement == defaults and replacement is not defaults
        patch.setattr(original, "__defaults__", replacement)
    elif mutation == "keyword_defaults":
        assert original.__kwdefaults__ is None
        patch.setattr(original, "__kwdefaults__", {})
    else:
        raise AssertionError("unknown synthetic sort-dependency mutation")


@pytest.mark.parametrize("method_name", FIXTURE["methods"])
@pytest.mark.parametrize("mutation", FIXTURE["mutations"])
def test_equal_sort_output_does_not_authorize_a_changed_dependency(
    monkeypatch: pytest.MonkeyPatch, method_name: str, mutation: str
) -> None:
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    original = getattr(GenerateJsonSchema, method_name)
    expected = original(GenerateJsonSchema(), copy.deepcopy(FIXTURE["probe_schema"]))
    with monkeypatch.context() as patch:
        _mutate_sort_dependency(patch, method_name, mutation)
        observed = getattr(GenerateJsonSchema, method_name)(
            GenerateJsonSchema(), copy.deepcopy(FIXTURE["probe_schema"])
        )
        # The named invariant binds implementation custody, not merely equal output.
        assert observed == expected
        assert not protocol.candidate_review_protocol_implementation_is_pristine()
    assert protocol.candidate_review_protocol_implementation_is_pristine()


@pytest.mark.parametrize("method_name", FIXTURE["methods"])
@pytest.mark.parametrize("mutation", FIXTURE["during_generation_mutations"])
def test_generation_rechecks_sort_dependencies_after_schema_callbacks(
    monkeypatch: pytest.MonkeyPatch, method_name: str, mutation: str
) -> None:
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    invoked: list[str] = []
    with monkeypatch.context() as patch:

        def mutate_during_generation(_schema: dict[str, Any]) -> None:
            invoked.append(method_name)
            _mutate_sort_dependency(patch, method_name, mutation)

        patch.setitem(
            protocol.CandidateReviewEndFrame.model_config,
            "json_schema_extra",
            mutate_during_generation,
        )
        # A valid pre-generation check cannot authorize post-callback dependency drift.
        pristine = protocol.candidate_review_protocol_implementation_is_pristine()
        assert invoked
        assert not pristine
    assert protocol.candidate_review_protocol_implementation_is_pristine()
