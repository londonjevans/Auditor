from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.endpoint_inventory import (
    OpenRouterEndpointInventoryDiagnostic,
    OpenRouterEndpointInventoryEntry,
    build_openrouter_endpoint_inventory_diagnostic,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "schemas" / "openrouter_endpoint_inventory_diagnostic.schema.json"
SCHEMA_URI = "https://mmaudit.local/schemas/openrouter_endpoint_inventory_diagnostic.schema.json"


def _published_schema() -> dict[str, Any]:
    loaded = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _generated_schema() -> dict[str, Any]:
    schema = OpenRouterEndpointInventoryDiagnostic.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = SCHEMA_URI
    schema["title"] = "mmaudit non-authorizing OpenRouter endpoint inventory diagnostic"
    return schema


def _valid_payload() -> dict[str, Any]:
    endpoint = {
        "tag": "provider-alpha/fp8",
        "slug": "provider-alpha",
        "provider_name": "Provider Alpha",
        "status": 0,
        "supported_parameters": [
            "max_tokens",
            "reasoning",
            "response_format",
            "structured_outputs",
        ],
        "reasoning": {"supported_efforts": ["medium", "high"]},
    }
    diagnostic = build_openrouter_endpoint_inventory_diagnostic(
        exact_model_id="alpha/atlas-secure",
        retrieved_at=datetime(2026, 8, 30, 18, 0, tzinfo=UTC),
        catalog_payload={
            "data": [
                {
                    "id": "alpha/atlas-secure",
                    "supported_parameters": [
                        "max_tokens",
                        "reasoning",
                        "response_format",
                        "structured_outputs",
                        "temperature",
                    ],
                    "reasoning": {"supported_efforts": ["medium", "high"]},
                }
            ]
        },
        endpoint_records=[endpoint],
        zdr_payload={"data": [{**endpoint, "model_id": "alpha/atlas-secure"}]},
    )
    return diagnostic.model_dump(mode="json")


def test_published_endpoint_inventory_schema_matches_strict_typed_contract() -> None:
    schema = _published_schema()

    assert schema == _generated_schema()
    assert schema["additionalProperties"] is False
    entry_schema = schema["$defs"]["OpenRouterEndpointInventoryEntry"]
    assert entry_schema["additionalProperties"] is False
    assert set(schema["required"]) == set(OpenRouterEndpointInventoryDiagnostic.model_fields)
    assert set(entry_schema["required"]) == set(OpenRouterEndpointInventoryEntry.model_fields)
    assert schema["properties"]["schema_version"]["const"] == "1.1"
    assert entry_schema["properties"]["schema_version"]["const"] == "1.1"
    assert set(
        entry_schema["properties"]["effective_reasoning_effort_inventory_source"]["enum"]
    ) == {"ENDPOINT", "MODEL", "UNAVAILABLE"}
    assert set(
        entry_schema["properties"]["effective_reasoning_effort_inventory_state"]["enum"]
    ) == {"UNAVAILABLE", "EMPTY", "PUBLISHED", "CONTRADICTORY"}
    for field in ("authenticated_control_plane_metadata", "metadata_only"):
        assert schema["properties"][field]["const"] is True
    for field in (
        "completion_requested",
        "cost_ledger_opened",
        "cost_ledger_mutated",
        "secret_persisted",
        "provider_authority",
        "runner_authority",
        "qualification_authority",
        "selection_authority",
        "egress_authority",
        "completion_authority",
        "release_authority",
    ):
        assert schema["properties"][field]["const"] is False


def test_published_endpoint_inventory_schema_accepts_the_self_bound_diagnostic() -> None:
    assert _published_schema() == _generated_schema()
    payload = _valid_payload()

    assert (
        OpenRouterEndpointInventoryDiagnostic.model_validate_json(
            json.dumps(payload, sort_keys=True)
        ).model_dump(mode="json")
        == payload
    )


def test_endpoint_inventory_contract_rejects_authority_or_extra_fields() -> None:
    assert _published_schema() == _generated_schema()
    payload = _valid_payload()
    payload["selection_authority"] = True
    with pytest.raises(ValidationError):
        OpenRouterEndpointInventoryDiagnostic.model_validate_json(json.dumps(payload))

    extra = deepcopy(_valid_payload())
    extra["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        OpenRouterEndpointInventoryDiagnostic.model_validate_json(json.dumps(extra))


def test_endpoint_inventory_contract_rejects_omitted_canonical_fields() -> None:
    assert _published_schema() == _generated_schema()
    payload = _valid_payload()

    for field in OpenRouterEndpointInventoryDiagnostic.model_fields:
        missing = deepcopy(payload)
        del missing[field]
        with pytest.raises(ValidationError, match="Field required"):
            OpenRouterEndpointInventoryDiagnostic.model_validate_json(json.dumps(missing))

    for field in OpenRouterEndpointInventoryEntry.model_fields:
        missing = deepcopy(payload)
        del missing["endpoints"][0][field]
        with pytest.raises(ValidationError, match="Field required"):
            OpenRouterEndpointInventoryDiagnostic.model_validate_json(json.dumps(missing))
