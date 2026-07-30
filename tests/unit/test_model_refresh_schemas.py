from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from mmaudit.models.refresh import (
    ModelRefreshAttempt,
    ModelRefreshDiff,
    ModelRefreshFreshness,
    ModelRefreshSnapshot,
    ModelRefreshSourceEvidence,
)
from mmaudit.models.refresh_staging import ModelRefreshWorkflowStatus
from scripts.generate_release_schemas import rendered_schema

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "schemas"

REFRESH_SCHEMAS: tuple[tuple[str, type[BaseModel]], ...] = (
    ("model_refresh_attempt.schema.json", ModelRefreshAttempt),
    ("model_refresh_diff.schema.json", ModelRefreshDiff),
    ("model_refresh_freshness.schema.json", ModelRefreshFreshness),
    ("model_refresh_snapshot.schema.json", ModelRefreshSnapshot),
    ("model_refresh_source_evidence.schema.json", ModelRefreshSourceEvidence),
    ("model_refresh_workflow_status.schema.json", ModelRefreshWorkflowStatus),
)


def _published(filename: str) -> dict[str, Any]:
    loaded = json.loads((SCHEMA_ROOT / filename).read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


@pytest.mark.parametrize(("filename", "model"), REFRESH_SCHEMAS)
def test_refresh_schema_is_canonical_strict_and_complete(
    filename: str,
    model: type[BaseModel],
) -> None:
    observed_text = (SCHEMA_ROOT / filename).read_text(encoding="utf-8")
    schema = _published(filename)

    assert observed_text == rendered_schema(filename, model)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == f"https://mmaudit.local/schemas/{filename}"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {
        name for name, field in model.model_fields.items() if field.is_required()
    }
    assert all(
        definition["additionalProperties"] is False
        for definition in schema.get("$defs", {}).values()
        if definition.get("type") == "object"
    )


def test_refresh_snapshot_and_diff_schema_preserve_evidence_bounds() -> None:
    snapshot = _published("model_refresh_snapshot.schema.json")
    diff = _published("model_refresh_diff.schema.json")

    assert snapshot["properties"]["schema_version"]["const"] == "2.0"
    assert (
        snapshot["$defs"]["LiveCatalogModelState"]["properties"]["schema_version"]["const"] == "2.0"
    )
    assert (
        snapshot["$defs"]["LiveProviderRouteState"]["properties"]["schema_version"]["const"]
        == "2.0"
    )
    assert diff["properties"]["schema_version"]["const"] == "2.0"
    assert diff["$defs"]["CatalogModelState"]["properties"]["schema_version"]["const"] == "2.0"
    assert diff["$defs"]["ProviderRouteState"]["properties"]["schema_version"]["const"] == "2.0"
    assert snapshot["properties"]["models"]["minItems"] == 1
    assert snapshot["properties"]["models"]["maxItems"] == 10_000
    assert snapshot["properties"]["excluded_routed_model_ids"]["maxItems"] == 10_000
    assert snapshot["$defs"]["LiveCatalogModelState"]["properties"]["routes"]["maxItems"] == 256
    assert (
        snapshot["$defs"]["LiveProviderRouteState"]["properties"]["supported_parameters"][
            "maxItems"
        ]
        == 256
    )
    route = snapshot["$defs"]["LiveProviderRouteState"]["properties"]
    model = snapshot["$defs"]["LiveCatalogModelState"]["properties"]
    assert route["max_prompt_tokens"] == {
        "maximum": 2**31 - 1,
        "minimum": 1,
        "title": "Max Prompt Tokens",
        "type": "integer",
    }
    assert route["max_prompt_tokens_source"]["enum"] == [
        "metadata",
        "context_limit",
    ]
    assert route["output_limit_source"]["enum"] == [
        "metadata",
        "context_limit",
    ]
    assert route["pricing_observation"]["const"] == "EXACT"
    assert "max_prompt_tokens" in snapshot["$defs"]["LiveProviderRouteState"]["required"]
    assert "max_prompt_tokens_source" in snapshot["$defs"]["LiveProviderRouteState"]["required"]
    assert "output_limit_source" in snapshot["$defs"]["LiveProviderRouteState"]["required"]
    assert "structured_output_mode" in snapshot["$defs"]["LiveProviderRouteState"]["required"]
    assert "pricing" in snapshot["$defs"]["LiveProviderRouteState"]["required"]
    assert route["supported_output_modes"]["minItems"] == 1
    assert route["supported_output_modes"]["maxItems"] == 3
    assert model["catalog_context_limit"]["minimum"] == 1
    assert model["context_limit_source"]["enum"] == [
        "metadata",
        "catalog_context",
    ]
    assert model["output_limit_source"]["enum"] == [
        "metadata",
        "provider_context",
    ]
    assert snapshot["$defs"]["StructuredOutputMode"]["enum"] == [
        "NATIVE_JSON_SCHEMA",
        "JSON_OBJECT",
        "VALIDATED_TEXT_JSON",
    ]
    assert diff["$defs"]["ModelDriftRecord"]["properties"]["change_kinds"]["minItems"] == 1
    assert diff["$defs"]["ModelDriftRecord"]["properties"]["before"]["anyOf"][0] == {
        "$ref": "#/$defs/CatalogModelState"
    }
    assert diff["$defs"]["ModelDriftRecord"]["properties"]["after"]["anyOf"][0] == {
        "$ref": "#/$defs/LiveCatalogModelState"
    }
    assert diff["$defs"]["ModelDriftKind"]["enum"] == [
        "NEW_ELIGIBLE_MODEL",
        "WITHDRAWN_MODEL",
        "MODEL_IDENTITY_CHANGED",
        "PRICING_CHANGED",
        "CONTEXT_LIMIT_CHANGED",
        "OUTPUT_LIMIT_CHANGED",
        "STRUCTURED_OUTPUT_SUPPORT_CHANGED",
        "REASONING_SUPPORT_CHANGED",
        "ZDR_ELIGIBILITY_CHANGED",
        "ENDPOINT_AVAILABILITY_CHANGED",
        "ENDPOINT_IDENTITY_CHANGED",
        "ENDPOINT_IDENTITY_UNVERIFIED",
        "LINEAGE_REVIEW_REQUIRED",
    ]


def test_refresh_terminal_and_freshness_states_are_explicit() -> None:
    attempt = _published("model_refresh_attempt.schema.json")
    freshness = _published("model_refresh_freshness.schema.json")

    assert attempt["$defs"]["ModelRefreshAttemptStatus"]["enum"] == [
        "UNCHANGED",
        "CHANGED",
        "PRODUCTION_BLOCKED",
        "FAILED",
    ]
    assert attempt["$defs"]["ModelRefreshFailureCode"]["enum"] == [
        "AUTHENTICATION",
        "NETWORK_TIMEOUT",
        "RATE_LIMIT",
        "PROVIDER_UNAVAILABLE",
        "MALFORMED_METADATA",
        "LOCAL_PERSISTENCE",
        "SECRET_PREREQUISITE",
    ]
    assert freshness["$defs"]["ModelRefreshFreshnessState"]["enum"] == [
        "CURRENT",
        "STALE",
        "HARD_EXPIRED",
        "NO_SUCCESS",
    ]
    assert freshness["properties"]["soft_max_age_hours"] == {
        "maximum": 720,
        "minimum": 1,
        "title": "Soft Max Age Hours",
        "type": "integer",
    }
    assert freshness["properties"]["hard_max_age_hours"] == {
        "maximum": 2160,
        "minimum": 2,
        "title": "Hard Max Age Hours",
        "type": "integer",
    }


def test_refresh_source_schema_is_bounded_and_allowlisted() -> None:
    source = _published("model_refresh_source_evidence.schema.json")
    endpoint = source["$defs"]["ModelRefreshEndpointSource"]["properties"]

    assert source["properties"]["schema_version"]["const"] == "1.0"
    assert source["properties"]["source_api_identity"]["const"] == ("https://openrouter.ai/api/v1")
    assert source["properties"]["authenticated_metadata"]["const"] is True
    assert source["properties"]["catalog_models"]["minItems"] == 1
    assert source["properties"]["catalog_models"]["maxItems"] == 10_000
    assert source["properties"]["zdr_endpoints"]["maxItems"] == 40_000
    assert source["properties"]["candidate_endpoint_sets"]["maxItems"] == 10_000
    assert endpoint["provider_name"]["maxLength"] == 128
    assert endpoint["supported_parameters"]["maxItems"] == 256
    assert endpoint["supported_parameters"]["items"]["maxLength"] == 100
    assert endpoint["pricing"]["maxProperties"] == 64
    assert endpoint["pricing"]["additionalProperties"]["maxLength"] == 128
    assert source["properties"]["excluded_routed_model_ids"]["items"]["pattern"]
    assert (
        source["$defs"]["ExcludedZdrRoutedModelSource"]["properties"]["model_id"]["pattern"]
        == source["properties"]["excluded_routed_model_ids"]["items"]["pattern"]
    )


def test_refresh_workflow_status_schema_binds_disposition_inventory_and_identity() -> None:
    status = _published("model_refresh_workflow_status.schema.json")
    artifact = status["$defs"]["StagedModelRefreshArtifact"]

    assert status["properties"]["schema_version"]["const"] == "2.0"
    assert status["properties"]["validated_at"]["format"] == "date-time"
    assert status["$defs"]["ModelRefreshWorkflowDisposition"]["enum"] == [
        "COMPLETED",
        "PRODUCTION_BLOCKED",
        "FAILED",
        "PREREQUISITE_MISSING",
    ]
    assert artifact["additionalProperties"] is False
    assert artifact["properties"]["filename"]["enum"] == [
        "model-refresh-source-evidence.json",
        "model-refresh-snapshot.json",
        "model-refresh-diff.json",
        "model-refresh-attempt.json",
        "model-refresh-freshness.json",
    ]
    assert set(artifact["required"]) == {
        "filename",
        "content_sha256",
        "artifact_sha256",
        "byte_count",
    }
    assert artifact["properties"]["byte_count"]["minimum"] == 1
    assert artifact["properties"]["byte_count"]["maximum"] == 20_000_000
    assert status["properties"]["source_commit"]["pattern"] == (r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    assert status["properties"]["candidate_registry_sha256"]["pattern"] == r"^[0-9a-f]{64}$"
    assert status["properties"]["workflow_status_sha256"]["pattern"] == r"^[0-9a-f]{64}$"
    assert status["properties"]["workflow_run_id"]["pattern"] == r"^[1-9][0-9]{0,19}$"
    assert status["properties"]["workflow_run_attempt"]["pattern"] == r"^[1-9][0-9]{0,19}$"
