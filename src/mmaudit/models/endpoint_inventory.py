"""Bounded nonauthorizing projection of current OpenRouter endpoint metadata.

The projection is diagnostic only. It identifies route selectors and the exact
metadata facts needed before constrained discovery, but it cannot select a route,
authorize execution, or substitute for empirical route validation.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from mmaudit.models.discovery import (
    ModelDiscoveryValidationError,
    canonicalize_openrouter_catalog_supported_parameters,
)
from mmaudit.models.endpoint_snapshots import (
    EndpointSnapshotValidationError,
    canonicalize_openrouter_endpoint_identity,
    canonicalize_openrouter_supported_parameters,
)
from mmaudit.models.identifiers import (
    EXACT_MODEL_ID_PATTERN,
    is_openrouter_catalog_model_id,
    require_exact_openrouter_model_id,
)
from mmaudit.models.output_modes import StructuredOutputMode, supported_output_modes
from mmaudit.models.reasoning import (
    REASONING_EFFORT_ORDER,
    EffectiveReasoningEffortInventorySource,
    EffectiveReasoningEffortInventoryState,
    ReasoningEffort,
)
from mmaudit.models.reasoning import (
    resolve_effective_reasoning_effort_inventory as _resolve_effective_reasoning_inventory,
)

_ENDPOINT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_ENDPOINTS = 2_048
_MAX_CATALOG_MODELS = 10_000
_MAX_SELECTION_ARGUMENTS = 2
_OPERATIONAL_TEXT = frozenset({"active", "available", "healthy", "online", "operational"})

ReasoningEffortInventoryState = Literal["UNAVAILABLE", "EMPTY", "PUBLISHED"]
EndpointOperationalStatus = (
    Annotated[StrictInt, Field(ge=-(2**31 - 1), le=2**31 - 1)]
    | Annotated[StrictStr, Field(min_length=1, max_length=32)]
)


class EndpointInventoryValidationError(ValueError):
    """Raised when endpoint metadata cannot form a bounded diagnostic projection."""


class _FrozenInventoryModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


class OpenRouterEndpointInventoryEntry(_FrozenInventoryModel):
    """One current exact-model endpoint and its nonauthorizing selection hints."""

    schema_version: Literal["1.1"]
    exact_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    endpoint_tag: str | None = Field(pattern=_ENDPOINT_PATTERN)
    endpoint_slug: str | None = Field(pattern=_ENDPOINT_PATTERN)
    provider_name: str = Field(min_length=1, max_length=128)
    provider_name_occurrences: int = Field(ge=1, le=_MAX_ENDPOINTS)
    routing_identity_unambiguous: bool
    operational: bool
    operational_status: EndpointOperationalStatus
    zdr_eligible: bool
    supported_parameters: tuple[str, ...] = Field(max_length=256)
    supported_output_modes: tuple[StructuredOutputMode, ...] = Field(min_length=1, max_length=3)
    native_structured_output_supported: bool
    structured_outputs_marker_present: bool
    reasoning_effort_inventory_state: ReasoningEffortInventoryState
    reasoning_effort_inventory_present: bool
    supported_reasoning_efforts: tuple[ReasoningEffort, ...] | None = Field(
        max_length=len(REASONING_EFFORT_ORDER),
    )
    high_reasoning_effort_supported: bool | None
    effective_reasoning_effort_inventory_source: EffectiveReasoningEffortInventorySource
    effective_reasoning_effort_inventory_state: EffectiveReasoningEffortInventoryState
    effective_supported_reasoning_efforts: tuple[ReasoningEffort, ...] | None = Field(
        max_length=len(REASONING_EFFORT_ORDER),
    )
    effective_high_reasoning_effort_supported: bool | None
    selection_arguments: tuple[str, ...] = Field(max_length=_MAX_SELECTION_ARGUMENTS)
    route_addressable: bool
    endpoint_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @field_validator("provider_name")
    @classmethod
    def provider_name_is_safe(cls, value: str) -> str:
        if value != value.strip() or any(not character.isprintable() for character in value):
            raise ValueError("endpoint inventory provider name is invalid")
        return value

    @field_validator("supported_reasoning_efforts", "effective_supported_reasoning_efforts")
    @classmethod
    def reasoning_efforts_are_canonical(
        cls,
        value: tuple[ReasoningEffort, ...] | None,
    ) -> tuple[ReasoningEffort, ...] | None:
        return _canonical_reasoning_efforts(value, label="endpoint inventory")

    @model_validator(mode="after")
    def entry_is_canonical_and_self_bound(self) -> Self:
        if self.endpoint_tag is None and self.endpoint_slug is None:
            raise ValueError("endpoint inventory entry requires a tag or slug")
        if self.supported_parameters != tuple(sorted(set(self.supported_parameters))):
            raise ValueError("endpoint inventory parameters must be unique and sorted")
        expected_modes = supported_output_modes(self.supported_parameters)
        if self.supported_output_modes != expected_modes:
            raise ValueError("endpoint inventory output modes are inconsistent")
        expected_native = StructuredOutputMode.NATIVE_JSON_SCHEMA in expected_modes
        if self.native_structured_output_supported is not expected_native:
            raise ValueError("endpoint inventory native structured-output status is inconsistent")
        if self.structured_outputs_marker_present is not (
            "structured_outputs" in self.supported_parameters
        ):
            raise ValueError("endpoint inventory structured_outputs marker is inconsistent")
        expected_operational, canonical_status = _operational_status(self.operational_status)
        if (
            canonical_status != self.operational_status
            or self.operational is not expected_operational
        ):
            raise ValueError("endpoint inventory operational status is inconsistent")
        if (
            self.supported_reasoning_efforts is not None
            and "reasoning" not in self.supported_parameters
        ):
            raise ValueError("endpoint inventory reasoning efforts lack exact parameter support")
        if self.reasoning_effort_inventory_state == "UNAVAILABLE":
            if (
                self.reasoning_effort_inventory_present
                or self.supported_reasoning_efforts is not None
                or self.high_reasoning_effort_supported is not None
            ):
                raise ValueError("unavailable reasoning inventory retains a support claim")
        elif self.reasoning_effort_inventory_state == "EMPTY":
            if (
                not self.reasoning_effort_inventory_present
                or self.supported_reasoning_efforts != ()
                or self.high_reasoning_effort_supported is not False
            ):
                raise ValueError("empty reasoning inventory has an inconsistent support claim")
        else:
            if not self.reasoning_effort_inventory_present or not self.supported_reasoning_efforts:
                raise ValueError("published reasoning inventory must contain an effort")
            if self.high_reasoning_effort_supported is not (
                "high" in self.supported_reasoning_efforts
            ):
                raise ValueError("published reasoning high-effort status is inconsistent")
        effective_efforts = self.effective_supported_reasoning_efforts
        expected_effective_high = None if effective_efforts is None else "high" in effective_efforts
        if self.effective_high_reasoning_effort_supported is not expected_effective_high:
            raise ValueError("effective reasoning high-effort status is inconsistent")
        if self.effective_reasoning_effort_inventory_source == "UNAVAILABLE":
            if (
                self.supported_reasoning_efforts is not None
                or self.effective_reasoning_effort_inventory_state != "UNAVAILABLE"
                or effective_efforts is not None
            ):
                raise ValueError("unavailable effective reasoning inventory is inconsistent")
        elif self.effective_reasoning_effort_inventory_source == "MODEL":
            if (
                self.supported_reasoning_efforts is not None
                or effective_efforts is None
                or self.effective_reasoning_effort_inventory_state not in {"EMPTY", "PUBLISHED"}
            ):
                raise ValueError("model effective reasoning inventory is inconsistent")
        elif (
            self.supported_reasoning_efforts is None
            or effective_efforts != self.supported_reasoning_efforts
            or self.effective_reasoning_effort_inventory_state == "UNAVAILABLE"
        ):
            raise ValueError("endpoint effective reasoning inventory is inconsistent")
        if self.effective_reasoning_effort_inventory_state == "EMPTY":
            if effective_efforts != ():
                raise ValueError("empty effective reasoning inventory is inconsistent")
        elif self.effective_reasoning_effort_inventory_state in {
            "PUBLISHED",
            "CONTRADICTORY",
        }:
            if not effective_efforts:
                raise ValueError("published effective reasoning inventory must contain an effort")
            if (
                self.effective_reasoning_effort_inventory_state == "CONTRADICTORY"
                and self.effective_reasoning_effort_inventory_source != "ENDPOINT"
            ):
                raise ValueError("contradictory reasoning inventory must be endpoint-sourced")
        if self.selection_arguments != tuple(sorted(set(self.selection_arguments))):
            raise ValueError("endpoint inventory selection arguments must be unique and sorted")
        expected_prefix = f"{self.exact_model_id}="
        aliases = {value for value in (self.endpoint_tag, self.endpoint_slug) if value is not None}
        if any(
            not argument.startswith(expected_prefix)
            or argument.removeprefix(expected_prefix) not in aliases
            for argument in self.selection_arguments
        ):
            raise ValueError("endpoint inventory selection argument is inconsistent")
        if self.route_addressable is not bool(self.selection_arguments):
            raise ValueError("endpoint inventory addressability is inconsistent")
        expected_hash = _canonical_sha256(self.model_dump(mode="json", exclude={"endpoint_sha256"}))
        if self.endpoint_sha256 != expected_hash:
            raise ValueError("endpoint inventory entry self-hash is inconsistent")
        return self


class OpenRouterEndpointInventoryDiagnostic(_FrozenInventoryModel):
    """Authenticated metadata diagnostic that grants no execution authority."""

    schema_version: Literal["1.1"]
    exact_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    retrieved_at: datetime
    source_api_identity: Literal["https://openrouter.ai/api/v1"]
    authenticated_control_plane_metadata: Literal[True]
    metadata_only: Literal[True]
    completion_requested: Literal[False]
    cost_ledger_opened: Literal[False]
    cost_ledger_mutated: Literal[False]
    secret_persisted: Literal[False]
    provider_authority: Literal[False]
    runner_authority: Literal[False]
    qualification_authority: Literal[False]
    selection_authority: Literal[False]
    egress_authority: Literal[False]
    completion_authority: Literal[False]
    release_authority: Literal[False]
    model_supported_parameters: tuple[str, ...] = Field(max_length=256)
    model_supported_output_modes: tuple[StructuredOutputMode, ...] = Field(
        min_length=1,
        max_length=3,
    )
    model_native_structured_output_supported: bool
    model_structured_outputs_marker_present: bool
    model_reasoning_effort_inventory_state: ReasoningEffortInventoryState
    model_reasoning_effort_inventory_present: bool
    model_supported_reasoning_efforts: tuple[ReasoningEffort, ...] | None = Field(
        max_length=len(REASONING_EFFORT_ORDER),
    )
    model_high_reasoning_effort_supported: bool | None
    endpoint_count: int = Field(ge=1, le=_MAX_ENDPOINTS)
    endpoints: tuple[OpenRouterEndpointInventoryEntry, ...] = Field(
        min_length=1,
        max_length=_MAX_ENDPOINTS,
    )
    diagnostic_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @field_validator("retrieved_at")
    @classmethod
    def retrieval_time_is_whole_second_utc(cls, value: datetime) -> datetime:
        offset = value.utcoffset() if value.tzinfo is not None else None
        if offset is None or offset.total_seconds() != 0 or value.microsecond:
            raise ValueError("endpoint inventory retrieval time must be whole-second UTC")
        return value.astimezone(UTC)

    @field_validator("model_supported_reasoning_efforts")
    @classmethod
    def model_reasoning_efforts_are_canonical(
        cls,
        value: tuple[ReasoningEffort, ...] | None,
    ) -> tuple[ReasoningEffort, ...] | None:
        return _canonical_reasoning_efforts(value, label="model")

    @model_validator(mode="after")
    def diagnostic_is_canonical_and_self_bound(self) -> Self:
        try:
            canonical_model_parameters = canonicalize_openrouter_catalog_supported_parameters(
                list(self.model_supported_parameters)
            )
        except ModelDiscoveryValidationError as exc:
            raise ValueError("model inventory parameters are invalid") from exc
        if self.model_supported_parameters != canonical_model_parameters:
            raise ValueError("model inventory parameters must be canonical")
        expected_model_modes = supported_output_modes(self.model_supported_parameters)
        if self.model_supported_output_modes != expected_model_modes:
            raise ValueError("model inventory output modes are inconsistent")
        if self.model_native_structured_output_supported is not (
            StructuredOutputMode.NATIVE_JSON_SCHEMA in expected_model_modes
        ):
            raise ValueError("model inventory native structured-output status is inconsistent")
        if self.model_structured_outputs_marker_present is not (
            "structured_outputs" in self.model_supported_parameters
        ):
            raise ValueError("model inventory structured_outputs marker is inconsistent")
        if (
            self.model_supported_reasoning_efforts is not None
            and "reasoning" not in self.model_supported_parameters
        ):
            raise ValueError("model reasoning efforts lack exact parameter support")
        _require_reasoning_inventory_projection(
            state=self.model_reasoning_effort_inventory_state,
            present=self.model_reasoning_effort_inventory_present,
            efforts=self.model_supported_reasoning_efforts,
            high_supported=self.model_high_reasoning_effort_supported,
            label="model",
        )
        if self.endpoint_count != len(self.endpoints):
            raise ValueError("endpoint inventory count is inconsistent")
        if any(endpoint.exact_model_id != self.exact_model_id for endpoint in self.endpoints):
            raise ValueError("endpoint inventory changes exact model identity")
        keys = tuple(_entry_sort_key(endpoint) for endpoint in self.endpoints)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("endpoint inventory entries must be unique and sorted")
        provider_counts: dict[str, int] = {}
        alias_counts: dict[str, int] = {}
        for endpoint in self.endpoints:
            key = endpoint.provider_name.casefold()
            provider_counts[key] = provider_counts.get(key, 0) + 1
            aliases = {
                alias
                for alias in (endpoint.endpoint_tag, endpoint.endpoint_slug)
                if alias is not None
            }
            for alias in aliases:
                alias_counts[alias] = alias_counts.get(alias, 0) + 1
        if any(
            endpoint.provider_name_occurrences != provider_counts[endpoint.provider_name.casefold()]
            or endpoint.routing_identity_unambiguous
            is not (provider_counts[endpoint.provider_name.casefold()] == 1)
            for endpoint in self.endpoints
        ):
            raise ValueError("endpoint inventory provider-name injectivity is inconsistent")
        for endpoint in self.endpoints:
            aliases = {
                alias
                for alias in (endpoint.endpoint_tag, endpoint.endpoint_slug)
                if alias is not None
            }
            expected_arguments = tuple(
                sorted(
                    f"{self.exact_model_id}={alias}"
                    for alias in aliases
                    if alias_counts[alias] == 1
                )
            )
            if (
                endpoint.selection_arguments != expected_arguments
                or endpoint.route_addressable is not bool(expected_arguments)
            ):
                raise ValueError("endpoint inventory global selection arguments are inconsistent")
            (
                expected_source,
                expected_state,
                expected_efforts,
                expected_high,
            ) = _resolve_effective_reasoning_inventory(
                endpoint_efforts=endpoint.supported_reasoning_efforts,
                model_efforts=self.model_supported_reasoning_efforts,
            )
            if (
                endpoint.effective_reasoning_effort_inventory_source != expected_source
                or endpoint.effective_reasoning_effort_inventory_state != expected_state
                or endpoint.effective_supported_reasoning_efforts != expected_efforts
                or endpoint.effective_high_reasoning_effort_supported is not expected_high
            ):
                raise ValueError("endpoint effective reasoning inventory differs from model facts")
        expected_hash = _canonical_sha256(
            self.model_dump(mode="json", exclude={"diagnostic_sha256"})
        )
        if self.diagnostic_sha256 != expected_hash:
            raise ValueError("endpoint inventory diagnostic self-hash is inconsistent")
        return self


def build_openrouter_endpoint_inventory_diagnostic(
    *,
    exact_model_id: str,
    retrieved_at: datetime,
    catalog_payload: Mapping[str, Any],
    endpoint_records: Sequence[Mapping[str, Any]],
    zdr_payload: Mapping[str, Any],
) -> OpenRouterEndpointInventoryDiagnostic:
    """Build a bounded diagnostic from already-fetched authenticated metadata."""

    exact_model_id = require_exact_openrouter_model_id(value=exact_model_id)
    retrieved_at = _whole_second_utc(retrieved_at)
    model_facts = _normalize_catalog_model_record(
        exact_model_id=exact_model_id,
        catalog_payload=catalog_payload,
    )
    if (
        type(endpoint_records) not in {list, tuple}
        or not 1 <= len(endpoint_records) <= _MAX_ENDPOINTS
        or any(not isinstance(record, Mapping) for record in endpoint_records)
    ):
        raise EndpointInventoryValidationError(
            "endpoint inventory requires a nonempty bounded endpoint sequence"
        )
    raw_zdr = zdr_payload.get("data")
    if (
        not isinstance(raw_zdr, list)
        or len(raw_zdr) > _MAX_ENDPOINTS * 4
        or any(not isinstance(record, Mapping) for record in raw_zdr)
    ):
        raise EndpointInventoryValidationError("ZDR endpoint inventory is invalid")

    normalized = tuple(
        _normalize_endpoint_record(exact_model_id=exact_model_id, raw=record)
        for record in endpoint_records
    )
    identities = tuple(item["identity_key"] for item in normalized)
    if len(identities) != len(set(identities)):
        raise EndpointInventoryValidationError("endpoint inventory contains duplicate exact routes")

    alias_counts: dict[str, int] = {}
    provider_counts: dict[str, int] = {}
    for item in normalized:
        for alias in item["aliases"]:
            alias_counts[alias] = alias_counts.get(alias, 0) + 1
        provider_name = item["provider_name"]
        assert isinstance(provider_name, str)
        provider_key = provider_name.casefold()
        provider_counts[provider_key] = provider_counts.get(provider_key, 0) + 1

    for record in raw_zdr:
        if not is_openrouter_catalog_model_id(record.get("model_id")):
            raise EndpointInventoryValidationError(
                "ZDR endpoint inventory omits an exact model binding"
            )
    normalized_zdr = tuple(
        _normalize_endpoint_record(exact_model_id=exact_model_id, raw=record)
        for record in raw_zdr
        if record["model_id"] == exact_model_id
    )
    zdr_identities = tuple(item["identity_key"] for item in normalized_zdr)
    if len(zdr_identities) != len(set(zdr_identities)):
        raise EndpointInventoryValidationError("ZDR inventory contains duplicate exact routes")
    zdr_by_identity = {item["identity_key"]: item for item in normalized_zdr}

    entries: list[OpenRouterEndpointInventoryEntry] = []
    for item in sorted(normalized, key=lambda value: value["identity_key"]):
        aliases = item["aliases"]
        assert isinstance(aliases, tuple)
        zdr_match = zdr_by_identity.get(item["identity_key"])
        if zdr_match is not None:
            _require_zdr_fact_consistency(item, zdr_match)
        unique_aliases = tuple(sorted(alias for alias in aliases if alias_counts[alias] == 1))
        selection_arguments = tuple(f"{exact_model_id}={alias}" for alias in unique_aliases)
        efforts = item["supported_reasoning_efforts"]
        assert efforts is None or isinstance(efforts, tuple)
        reasoning_state: ReasoningEffortInventoryState = (
            "UNAVAILABLE" if efforts is None else ("EMPTY" if not efforts else "PUBLISHED")
        )
        (
            effective_source,
            effective_state,
            effective_efforts,
            effective_high,
        ) = _resolve_effective_reasoning_inventory(
            endpoint_efforts=efforts,
            model_efforts=model_facts["supported_reasoning_efforts"],
        )
        provider_name = item["provider_name"]
        assert isinstance(provider_name, str)
        values: dict[str, Any] = {
            "schema_version": "1.1",
            "exact_model_id": exact_model_id,
            "endpoint_tag": item["endpoint_tag"],
            "endpoint_slug": item["endpoint_slug"],
            "provider_name": provider_name,
            "provider_name_occurrences": provider_counts[provider_name.casefold()],
            "routing_identity_unambiguous": provider_counts[provider_name.casefold()] == 1,
            "operational": item["operational"],
            "operational_status": item["operational_status"],
            "zdr_eligible": zdr_match is not None,
            "supported_parameters": item["supported_parameters"],
            "supported_output_modes": item["supported_output_modes"],
            "native_structured_output_supported": (
                StructuredOutputMode.NATIVE_JSON_SCHEMA in item["supported_output_modes"]
            ),
            "structured_outputs_marker_present": (
                "structured_outputs" in item["supported_parameters"]
            ),
            "reasoning_effort_inventory_state": reasoning_state,
            "reasoning_effort_inventory_present": efforts is not None,
            "supported_reasoning_efforts": efforts,
            "high_reasoning_effort_supported": None if efforts is None else "high" in efforts,
            "effective_reasoning_effort_inventory_source": effective_source,
            "effective_reasoning_effort_inventory_state": effective_state,
            "effective_supported_reasoning_efforts": effective_efforts,
            "effective_high_reasoning_effort_supported": effective_high,
            "selection_arguments": selection_arguments,
            "route_addressable": bool(selection_arguments),
        }
        values["endpoint_sha256"] = _canonical_sha256(values)
        try:
            entries.append(OpenRouterEndpointInventoryEntry.model_validate(values))
        except ValueError as exc:
            raise EndpointInventoryValidationError(
                "endpoint inventory entry projection is invalid"
            ) from exc

    ordered_entries = tuple(sorted(entries, key=_entry_sort_key))
    diagnostic_values: dict[str, Any] = {
        "schema_version": "1.1",
        "exact_model_id": exact_model_id,
        "retrieved_at": retrieved_at,
        "source_api_identity": "https://openrouter.ai/api/v1",
        "authenticated_control_plane_metadata": True,
        "metadata_only": True,
        "completion_requested": False,
        "cost_ledger_opened": False,
        "cost_ledger_mutated": False,
        "secret_persisted": False,
        "provider_authority": False,
        "runner_authority": False,
        "qualification_authority": False,
        "selection_authority": False,
        "egress_authority": False,
        "completion_authority": False,
        "release_authority": False,
        "model_supported_parameters": model_facts["supported_parameters"],
        "model_supported_output_modes": model_facts["supported_output_modes"],
        "model_native_structured_output_supported": (
            StructuredOutputMode.NATIVE_JSON_SCHEMA in model_facts["supported_output_modes"]
        ),
        "model_structured_outputs_marker_present": (
            "structured_outputs" in model_facts["supported_parameters"]
        ),
        "model_reasoning_effort_inventory_state": model_facts["reasoning_effort_inventory_state"],
        "model_reasoning_effort_inventory_present": (
            model_facts["supported_reasoning_efforts"] is not None
        ),
        "model_supported_reasoning_efforts": model_facts["supported_reasoning_efforts"],
        "model_high_reasoning_effort_supported": (
            None
            if model_facts["supported_reasoning_efforts"] is None
            else "high" in model_facts["supported_reasoning_efforts"]
        ),
        "endpoint_count": len(ordered_entries),
        "endpoints": ordered_entries,
    }
    hash_values = {
        **diagnostic_values,
        "endpoints": [entry.model_dump(mode="json") for entry in ordered_entries],
    }
    diagnostic_values["diagnostic_sha256"] = _canonical_sha256(_json_projection(hash_values))
    try:
        return OpenRouterEndpointInventoryDiagnostic.model_validate(diagnostic_values)
    except ValueError as exc:
        raise EndpointInventoryValidationError("endpoint inventory diagnostic is invalid") from exc


def _normalize_catalog_model_record(
    *,
    exact_model_id: str,
    catalog_payload: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(catalog_payload, Mapping):
        raise EndpointInventoryValidationError("model catalog is invalid")
    raw_models = catalog_payload.get("data")
    if (
        not isinstance(raw_models, list)
        or not 1 <= len(raw_models) <= _MAX_CATALOG_MODELS
        or any(not isinstance(record, Mapping) for record in raw_models)
    ):
        raise EndpointInventoryValidationError(
            "model catalog requires a nonempty bounded model sequence"
        )
    for record in raw_models:
        if not is_openrouter_catalog_model_id(record.get("id")):
            raise EndpointInventoryValidationError(
                "model catalog contains an invalid model identity"
            )
    selected = [record for record in raw_models if record.get("id") == exact_model_id]
    if len(selected) != 1:
        raise EndpointInventoryValidationError(
            "model catalog must contain exactly one requested model"
        )
    try:
        parameters = canonicalize_openrouter_catalog_supported_parameters(
            selected[0].get("supported_parameters")
        )
        efforts = _reasoning_efforts(selected[0], label="model")
        if efforts is not None and "reasoning" not in parameters:
            raise EndpointSnapshotValidationError(
                "model reasoning efforts lack exact parameter support"
            )
    except (EndpointSnapshotValidationError, ModelDiscoveryValidationError) as exc:
        raise EndpointInventoryValidationError("model catalog record is invalid") from exc
    reasoning_state: ReasoningEffortInventoryState = (
        "UNAVAILABLE" if efforts is None else ("EMPTY" if not efforts else "PUBLISHED")
    )
    return {
        "supported_parameters": parameters,
        "supported_output_modes": supported_output_modes(parameters),
        "reasoning_effort_inventory_state": reasoning_state,
        "supported_reasoning_efforts": efforts,
    }


def _normalize_endpoint_record(
    *,
    exact_model_id: str,
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    item_model_id = raw.get("model_id")
    if item_model_id is not None and item_model_id != exact_model_id:
        raise EndpointInventoryValidationError(
            "endpoint inventory record changes the exact requested model"
        )
    try:
        identity = canonicalize_openrouter_endpoint_identity(raw)
        parameters = canonicalize_openrouter_supported_parameters(raw.get("supported_parameters"))
        efforts = _reasoning_efforts(raw, label="endpoint")
        if efforts is not None and "reasoning" not in parameters:
            raise EndpointSnapshotValidationError(
                "endpoint reasoning efforts lack exact parameter support"
            )
        operational, status = _operational_status(raw.get("status"))
    except EndpointSnapshotValidationError as exc:
        raise EndpointInventoryValidationError("endpoint inventory record is invalid") from exc
    aliases = tuple(
        dict.fromkeys(
            value for value in (identity["tag"], identity["slug"]) if isinstance(value, str)
        )
    )
    if not aliases:
        raise EndpointInventoryValidationError("endpoint inventory record has no route selector")
    return {
        "identity_key": (identity["tag"] or "", identity["slug"] or ""),
        "aliases": aliases,
        "endpoint_tag": identity["tag"],
        "endpoint_slug": identity["slug"],
        "provider_name": identity["provider_name"],
        "operational": operational,
        "operational_status": status,
        "supported_parameters": parameters,
        "supported_output_modes": supported_output_modes(parameters),
        "supported_reasoning_efforts": efforts,
    }


def _reasoning_efforts(
    raw: Mapping[str, Any],
    *,
    label: str,
) -> tuple[ReasoningEffort, ...] | None:
    reasoning = raw.get("reasoning")
    if reasoning is None:
        return None
    if not isinstance(reasoning, Mapping) or len(reasoning) > 16:
        raise EndpointSnapshotValidationError(f"{label} reasoning metadata is invalid")
    value = reasoning.get("supported_efforts")
    if value is None:
        return None
    if (
        not isinstance(value, list)
        or len(value) > len(REASONING_EFFORT_ORDER)
        or any(not isinstance(item, str) or item not in REASONING_EFFORT_ORDER for item in value)
        or len(value) != len(set(value))
    ):
        raise EndpointSnapshotValidationError(f"{label} supported reasoning efforts are invalid")
    selected = frozenset(value)
    return tuple(effort for effort in REASONING_EFFORT_ORDER if effort in selected)


def _canonical_reasoning_efforts(
    value: tuple[ReasoningEffort, ...] | None,
    *,
    label: str,
) -> tuple[ReasoningEffort, ...] | None:
    if value is None:
        return None
    selected = frozenset(value)
    if len(value) != len(selected) or value != tuple(
        effort for effort in REASONING_EFFORT_ORDER if effort in selected
    ):
        raise ValueError(f"{label} reasoning efforts are not canonical")
    return value


def _require_reasoning_inventory_projection(
    *,
    state: ReasoningEffortInventoryState,
    present: bool,
    efforts: tuple[ReasoningEffort, ...] | None,
    high_supported: bool | None,
    label: str,
) -> None:
    expected_state: ReasoningEffortInventoryState = (
        "UNAVAILABLE" if efforts is None else ("EMPTY" if not efforts else "PUBLISHED")
    )
    expected_high = None if efforts is None else "high" in efforts
    if (
        state != expected_state
        or present is not (efforts is not None)
        or high_supported is not expected_high
    ):
        raise ValueError(f"{label} reasoning inventory projection is inconsistent")


def _operational_status(value: Any) -> tuple[bool, EndpointOperationalStatus]:
    if isinstance(value, bool):
        raise EndpointSnapshotValidationError("endpoint operational status is invalid")
    if isinstance(value, int):
        if not -(2**31 - 1) <= value <= 2**31 - 1:
            raise EndpointSnapshotValidationError("endpoint operational status is invalid")
        return value == 0, value
    if (
        isinstance(value, str)
        and value
        and value == value.strip()
        and len(value) <= 32
        and all(character.isprintable() for character in value)
    ):
        normalized = value.casefold()
        return normalized in _OPERATIONAL_TEXT, normalized
    raise EndpointSnapshotValidationError("endpoint operational status is invalid")


def _require_zdr_fact_consistency(
    endpoint: Mapping[str, Any],
    zdr_endpoint: Mapping[str, Any],
) -> None:
    fields = (
        "provider_name",
        "operational",
        "operational_status",
        "supported_parameters",
        "supported_output_modes",
        "supported_reasoning_efforts",
    )
    if any(endpoint[field] != zdr_endpoint[field] for field in fields):
        raise EndpointInventoryValidationError(
            "per-model and ZDR endpoint diagnostic facts are inconsistent"
        )


def _entry_sort_key(entry: OpenRouterEndpointInventoryEntry) -> tuple[str, str]:
    return (entry.endpoint_tag or "", entry.endpoint_slug or "")


def _whole_second_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise EndpointInventoryValidationError(
            "endpoint inventory retrieval time must be whole-second UTC"
        )
    normalized = value.astimezone(UTC)
    if normalized.microsecond:
        raise EndpointInventoryValidationError(
            "endpoint inventory retrieval time must be whole-second UTC"
        )
    return normalized


def _json_projection(value: Mapping[str, Any]) -> dict[str, Any]:
    projected = dict(value)
    retrieved_at = projected.get("retrieved_at")
    if isinstance(retrieved_at, datetime):
        projected["retrieved_at"] = retrieved_at.isoformat().replace("+00:00", "Z")
    return projected


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


__all__ = [
    "EndpointInventoryValidationError",
    "OpenRouterEndpointInventoryDiagnostic",
    "OpenRouterEndpointInventoryEntry",
    "build_openrouter_endpoint_inventory_diagnostic",
]
