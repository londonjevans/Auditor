"""Worst-case reviewer claims are size-only supersets, not fabricated candidate evidence."""

from __future__ import annotations

import copy
import json

import pytest

from mmaudit.models import development_tree_request_bounds as module


@pytest.mark.parametrize(
    "character", ["\x00", "\x01", "\n", "\r", "\t", '"', "\\", "a", "é", "界", "😀"]
)
def test_nested_json_string_bound_covers_control_escaping_and_utf8(character):
    bound = module._maximum_value({"type": "string", "maxLength": 2000}, {})
    assert module._quoted_bytes(character * 2000) <= module._quoted_bytes(bound)


def test_review_superset_preserves_all_sixteen_claim_slots_and_deterministic_schema_pin():
    content, pin = module.development_tree_review_claims_bound()
    assert (content, pin) == module.development_tree_review_claims_bound()
    claims = json.loads(content)
    assert len(claims) == 16
    assert claims[0]["claim_id"] == "file-0256:01"
    assert claims[-1]["claim_id"] == "file-0256:16"
    assert len(claims[-1]["finding"]["explanation"]) == 2000
    assert len(json.dumps(content, ensure_ascii=False).encode()) > 500_000
    assert len(pin) == 64


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "string"},
        {"type": "number"},
        {"type": "integer", "minimum": 0},
        {"type": "object", "properties": {}},
        {"$ref": "https://invalid.example/schema"},
        {"$ref": "#/$defs/Missing"},
        {"type": "array"},
    ],
)
def test_unbounded_or_unsupported_schema_cannot_be_assumed_small(schema):
    with pytest.raises(ValueError):
        module._maximum_value(schema, {})


def test_recursive_schema_is_bounded():
    schema = {"$ref": "#/$defs/Recursive"}
    with pytest.raises(ValueError, match="recursive or too deep"):
        module._maximum_value(schema, {"Recursive": schema})


def test_changed_outer_claim_layout_cannot_silently_omit_new_fields(monkeypatch):
    schema = copy.deepcopy(module.DevelopmentCorpusJudgmentClaim.model_json_schema())
    schema["properties"]["extra_context"] = {"type": "string", "maxLength": 10000}
    monkeypatch.setattr(module.DevelopmentCorpusJudgmentClaim, "model_json_schema", lambda: schema)
    with pytest.raises(ValueError, match=r"claim.*grammar changed"):
        module.development_tree_review_claims_bound()
