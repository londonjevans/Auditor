from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.qualification import ModelQualificationArtifact
from tests.unit import test_model_qualification as qualification_fixtures

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "schemas" / "model_qualification.schema.json"
SCHEMA_URI = "https://mmaudit.local/schemas/model_qualification.schema.json"


def _published_schema() -> dict[str, Any]:
    loaded = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _generated_schema() -> dict[str, Any]:
    schema = ModelQualificationArtifact.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = SCHEMA_URI
    schema["title"] = "mmaudit model qualification artifact"
    return schema


def _valid_payload() -> dict[str, Any]:
    return qualification_fixtures._bundle().artifact.model_dump(mode="json")


def test_published_qualification_schema_matches_the_typed_contract() -> None:
    schema = _published_schema()

    assert schema == _generated_schema()
    assert schema["additionalProperties"] is False
    assert schema["properties"]["results"]["minItems"] == 1
    assert schema["$defs"]["ModelQualificationResult"]["additionalProperties"] is False
    assert schema["$defs"]["QualificationBindings"]["additionalProperties"] is False
    assert schema["$defs"]["QualificationDimensionResult"]["additionalProperties"] is False


def test_published_qualification_schema_accepts_a_sealed_artifact() -> None:
    assert _published_schema() == _generated_schema()
    payload = _valid_payload()

    assert ModelQualificationArtifact.model_validate(payload).model_dump(mode="json") == payload


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("unexpected", True),
        ("results", []),
    ),
)
def test_published_qualification_schema_rejects_extra_properties_and_zero_results(
    field: str,
    value: object,
) -> None:
    assert _published_schema() == _generated_schema()
    payload = deepcopy(_valid_payload())
    payload[field] = value

    with pytest.raises(ValidationError):
        ModelQualificationArtifact.model_validate(payload)
