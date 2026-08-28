from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from mmaudit.models.prepurchase_quote import (
    AcceptedPrepurchaseQuote,
    PrepurchaseQuote,
    PrepurchaseQuoteInconclusiveReason,
    PrepurchaseQuoteReconciliation,
    PrepurchaseQuoteReconciliationStatus,
    PrepurchaseQuoteRuntimeRoleKind,
    PrepurchaseQuoteTaskClass,
)
from scripts.generate_release_schemas import MODELS, rendered_schema

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_BASE = "https://mmaudit.local/schemas"
CANONICAL_MONEY_PATTERN = r"^(?:0|[1-9][0-9]{0,29})(?:\.[0-9]{1,30})?$"
AUTHORITY_FIELDS = (
    "authorizes_dispatch",
    "grants_review_credit",
    "grants_completion_credit",
    "grants_release_authority",
)
SCHEMA_MODELS: tuple[tuple[str, type[BaseModel], str], ...] = (
    (
        "prepurchase_quote.schema.json",
        PrepurchaseQuote,
        "mmaudit deterministic non-authorizing whole-run pre-purchase quote",
    ),
    (
        "accepted_prepurchase_quote.schema.json",
        AcceptedPrepurchaseQuote,
        "mmaudit non-authorizing accepted pre-purchase quote constraint",
    ),
    (
        "prepurchase_quote_reconciliation.schema.json",
        PrepurchaseQuoteReconciliation,
        "mmaudit terminal actual-versus-quote cost reconciliation",
    ),
)


def _published_schema(filename: str) -> dict[str, Any]:
    loaded = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _object_schemas(schema: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    definitions = tuple(
        value for value in schema.get("$defs", {}).values() if value.get("type") == "object"
    )
    return (schema, *definitions)


def _string_option(property_schema: dict[str, Any]) -> dict[str, Any]:
    if property_schema.get("type") == "string":
        return property_schema
    raw_options = property_schema.get("anyOf")
    assert isinstance(raw_options, list)
    options: list[dict[str, Any]] = []
    for option in raw_options:
        assert isinstance(option, dict)
        if option.get("type") == "string":
            options.append(option)
    assert len(options) == 1
    return options[0]


@pytest.mark.parametrize(("filename", "model", "title"), SCHEMA_MODELS)
def test_published_quote_schema_matches_the_canonical_typed_contract(
    filename: str,
    model: type[BaseModel],
    title: str,
) -> None:
    schema = _published_schema(filename)

    assert MODELS[filename] is model
    assert schema == json.loads(rendered_schema(filename, model))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == f"{SCHEMA_BASE}/{filename}"
    assert schema["title"] == title
    assert all(item["additionalProperties"] is False for item in _object_schemas(schema))


@pytest.mark.parametrize(("filename", "model", "_title"), SCHEMA_MODELS)
def test_quote_schemas_preserve_canonical_money_and_nonauthorizing_fields(
    filename: str,
    model: type[BaseModel],
    _title: str,
) -> None:
    schema = _published_schema(filename)
    assert schema == json.loads(rendered_schema(filename, model))

    for object_schema in _object_schemas(schema):
        properties = object_schema["properties"]
        for field_name in AUTHORITY_FIELDS:
            if field_name in properties:
                assert properties[field_name]["const"] is False
        for field_name, property_schema in properties.items():
            if field_name.endswith("_usd_exact"):
                assert _string_option(property_schema)["pattern"] == CANONICAL_MONEY_PATTERN


def test_quote_schema_closes_every_paid_task_class_and_finite_ceiling() -> None:
    schema = _published_schema("prepurchase_quote.schema.json")
    classes = schema["$defs"]["PrepurchaseQuoteTaskClass"]["enum"]
    covered = schema["properties"]["covered_task_classes"]
    ceilings = schema["properties"]["task_ceilings"]
    task_ceiling = schema["$defs"]["PrepurchaseQuoteTaskCeiling"]["properties"]

    assert classes == [item.value for item in PrepurchaseQuoteTaskClass]
    assert covered["minItems"] == covered["maxItems"] == len(PrepurchaseQuoteTaskClass)
    assert covered["uniqueItems"] is True
    assert ceilings["minItems"] == len(PrepurchaseQuoteTaskClass)
    assert ceilings["maxItems"] == 10_000
    assert ceilings["uniqueItems"] is True
    assert task_ceiling["maximum_task_count"]["maximum"] == 1_000_000
    assert task_ceiling["maximum_attempts_per_task"]["maximum"] == 64
    assert schema["properties"]["maximum_request_count"]["minimum"] == 1
    assert schema["properties"]["completion_within_hard_ceiling_guaranteed"]["const"] is False


def test_quote_schema_binds_dynamic_roles_selected_models_campaign_and_cost_semantics() -> None:
    schema = _published_schema("prepurchase_quote.schema.json")
    target = schema["$defs"]["PrepurchaseQuoteTargetBinding"]["properties"]
    ceiling = schema["$defs"]["PrepurchaseQuoteTaskCeiling"]["properties"]
    cost_range = schema["$defs"]["PrepurchaseQuoteCostRange"]["properties"]
    properties = schema["properties"]

    assert schema["$defs"]["PrepurchaseQuoteRuntimeRoleKind"]["enum"] == [
        item.value for item in PrepurchaseQuoteRuntimeRoleKind
    ]
    assert ceiling["maximum_distinct_runtime_roles"] == {
        "maximum": 1_000_000,
        "minimum": 0,
        "title": "Maximum Distinct Runtime Roles",
        "type": "integer",
    }
    assert target["scheduler_campaign_id"]["pattern"] == (r"^scheduler-campaign-[0-9a-f]{64}$")
    assert target["audit_selected_model_set_sha256"]["anyOf"][0]["pattern"] == (r"^[0-9a-f]{64}$")
    assert "Accepted hard spend ceiling" in cost_range["worst_case_usd_exact"]["description"]
    assert (
        "Complete-work worst-case cost"
        in (properties["unconstrained_workflow_worst_usd_exact"]["description"])
    )
    assert "cannot cover the complete workflow" in properties["hard_budget_limited"]["description"]


def test_reconciliation_schema_keeps_terminal_status_and_actuals_explicit() -> None:
    schema = _published_schema("prepurchase_quote_reconciliation.schema.json")
    properties = schema["properties"]

    assert schema["$defs"]["PrepurchaseQuoteReconciliationStatus"]["enum"] == [
        item.value for item in PrepurchaseQuoteReconciliationStatus
    ]
    assert schema["$defs"]["PrepurchaseQuoteInconclusiveReason"]["enum"] == [
        item.value for item in PrepurchaseQuoteInconclusiveReason
    ]
    assert properties["ledger_evidence_canonical_json"]["maxLength"] == 100_000_000
    assert {option["type"] for option in properties["actual_cost_usd_exact"]["anyOf"]} == {
        "null",
        "string",
    }
    assert {option["type"] for option in properties["within_worst_case"]["anyOf"]} == {
        "boolean",
        "null",
    }


@pytest.mark.parametrize(("_filename", "model", "_title"), SCHEMA_MODELS)
def test_quote_models_reject_unknown_top_level_fields(
    _filename: str,
    model: type[BaseModel],
    _title: str,
) -> None:
    with pytest.raises(ValidationError) as raised:
        model.model_validate({"unexpected": True})

    assert any(
        error["type"] == "extra_forbidden" and error["loc"] == ("unexpected",)
        for error in raised.value.errors()
    )
