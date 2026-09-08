"""Bounded routing observations; only supplied metadata can establish model equivalence."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models.discovery import (
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryPayload,
)
from mmaudit.models.endpoint_snapshots import OpenRouterEndpointSnapshotEvidence
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.repository.redaction import detect_secrets

DEVELOPMENT_GENERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA = r"^[0-9a-f]{64}$"
_ABSENT = object()
_MAX_CANDIDATES = 128
_MAX_COUNT = 1_000_000
type ByokObservation = Literal["ABSENT", "FALSE", "TRUE", "INVALID"]


class _RoutingModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, allow_inf_nan=False, revalidate_instances="always"
    )


class DevelopmentRoutingFailure(StrEnum):
    RETURNED_MODEL = "RETURNED_MODEL"
    RESPONSE_PROVIDER = "RESPONSE_PROVIDER"
    ROUTER_METADATA = "ROUTER_METADATA"
    REQUESTED_MODEL = "REQUESTED_MODEL"
    STRATEGY = "STRATEGY"
    ROUTER_ATTEMPT = "ROUTER_ATTEMPT"
    BYOK_EVIDENCE_MISSING = "BYOK_EVIDENCE_MISSING"
    BYOK_REPORTED = "BYOK_REPORTED"
    BYOK_INVALID = "BYOK_INVALID"
    PIPELINE = "PIPELINE"
    ENDPOINT_SHAPE = "ENDPOINT_SHAPE"
    SELECTION_COUNT = "SELECTION_COUNT"
    SELECTED_MODEL = "SELECTED_MODEL"
    SELECTED_PROVIDER = "SELECTED_PROVIDER"
    ATTEMPT_SHAPE = "ATTEMPT_SHAPE"
    ATTEMPT_MODEL = "ATTEMPT_MODEL"
    ATTEMPT_PROVIDER = "ATTEMPT_PROVIDER"
    ATTEMPT_STATUS = "ATTEMPT_STATUS"
    GENERATION_HEADER = "GENERATION_HEADER"
    GENERATION_REUSE = "GENERATION_REUSE"


class DevelopmentRoutingContext(_RoutingModel):
    """Supplied request/discovery binding, not independently authenticated provider evidence."""

    exact_model_id: str = Field(min_length=1, max_length=256)
    provider_endpoint: str = Field(min_length=1, max_length=128)
    provider_name: str = Field(min_length=1, max_length=128)
    endpoint_snapshot_sha256: str = Field(pattern=_SHA)
    identity_basis: Literal["REQUEST_ID_ONLY", "SUPPLIED_DISCOVERY_BOUND"]
    canonical_model_id: str | None = Field(default=None, min_length=1, max_length=256)
    catalog_identity_binding_sha256: str | None = Field(default=None, pattern=_SHA)
    model_metadata_snapshot_sha256: str | None = Field(default=None, pattern=_SHA)

    @model_validator(mode="after")
    def identity_binding_is_consistent(self) -> Self:
        if self.identity_basis == "REQUEST_ID_ONLY":
            if any(
                value is not None
                for value in (
                    self.canonical_model_id,
                    self.catalog_identity_binding_sha256,
                    self.model_metadata_snapshot_sha256,
                )
            ):
                raise ValueError("endpoint-only routing cannot invent canonical identity")
        elif (
            self.canonical_model_id is None
            or self.model_metadata_snapshot_sha256 is None
            or self.canonical_model_id.split("/", 1)[0] != self.exact_model_id.split("/", 1)[0]
            or self.catalog_identity_binding_sha256
            != canonical_sha256(
                {"id": self.exact_model_id, "canonical_slug": self.canonical_model_id}
            )
        ):
            raise ValueError("development canonical identity differs from its supplied binding")
        for value in (
            self.exact_model_id,
            self.provider_endpoint,
            self.provider_name,
            self.canonical_model_id,
        ):
            if value is not None and (
                detect_secrets(value)
                or value.strip() != value
                or any(ord(c) < 32 or ord(c) == 127 for c in value)
            ):
                raise ValueError("development routing identity is unsafe to observe")
        return self

    @classmethod
    def from_metadata(
        cls,
        snapshot: OpenRouterEndpointSnapshotEvidence,
        discovery: OpenRouterModelDiscoveryPayload | None,
    ) -> DevelopmentRoutingContext:
        """Revalidate exact supplied metadata before any reservation, never response aliases."""

        if type(snapshot) is not OpenRouterEndpointSnapshotEvidence:
            raise ValueError("development routing requires an exact endpoint snapshot")
        snapshot = OpenRouterEndpointSnapshotEvidence.model_validate_json(
            snapshot.model_dump_json(), strict=True
        )
        if len(snapshot.endpoints) != 1:
            raise ValueError("development routing requires one exact endpoint")
        if discovery is not None:
            if type(discovery) not in {
                OpenRouterModelDiscoveryPayload,
                OpenRouterModelDiscoveryEvidence,
            }:
                raise ValueError("development routing requires exact supplied discovery")
            discovery = type(discovery).model_validate_json(
                discovery.model_dump_json(), strict=True
            )
            if (
                discovery.endpoint_snapshot != snapshot
                or discovery.exact_model_id != snapshot.exact_model_id
            ):
                raise ValueError("development discovery differs from its selected endpoint")
        endpoint = snapshot.endpoints[0]
        return cls(
            exact_model_id=snapshot.exact_model_id,
            provider_endpoint=endpoint.provider_endpoint,
            provider_name=endpoint.provider_name,
            endpoint_snapshot_sha256=snapshot.snapshot_sha256,
            identity_basis="REQUEST_ID_ONLY" if discovery is None else "SUPPLIED_DISCOVERY_BOUND",
            canonical_model_id=None if discovery is None else discovery.canonical_slug,
            catalog_identity_binding_sha256=None
            if discovery is None
            else discovery.catalog_identity_binding_sha256,
            model_metadata_snapshot_sha256=None
            if discovery is None
            else discovery.model_metadata_snapshot_sha256,
        )


class DevelopmentRoutingIdentity(_RoutingModel):
    """Unknown response strings are suppressed completely, not heuristically echoed."""

    status: Literal[
        "REQUESTED", "CANONICAL", "PROVIDER", "UNBOUND", "ABSENT", "INVALID", "REDACTED"
    ]
    value: str | None = Field(default=None, min_length=1, max_length=256)

    @model_validator(mode="after")
    def only_recognized_values_can_be_retained(self) -> Self:
        recognized = self.status in {"REQUESTED", "CANONICAL", "PROVIDER"}
        if recognized != (self.value is not None) or (
            self.value is not None and detect_secrets(self.value)
        ):
            raise ValueError("development diagnostic cannot retain an unbound or secret-like value")
        return self


class DevelopmentRoutingEndpoint(_RoutingModel):
    model: DevelopmentRoutingIdentity
    provider: DevelopmentRoutingIdentity
    http_status: int | None = Field(default=None, ge=100, le=599)


class DevelopmentRoutingEvidence(_RoutingModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_routing_observation"] = "development_routing_observation"
    evidence_class: Literal["BOUNDED_UNTRUSTED_PROVIDER_OBSERVATION"] = (
        "BOUNDED_UNTRUSTED_PROVIDER_OBSERVATION"
    )
    runtime_authority: Literal[False] = False
    context: DevelopmentRoutingContext
    returned_model: DevelopmentRoutingIdentity
    response_provider: DevelopmentRoutingIdentity
    requested_model: DevelopmentRoutingIdentity
    metadata_shape: Literal["ABSENT", "OBJECT", "INVALID"]
    strategy: Literal["ABSENT", "DIRECT", "OTHER", "INVALID"]
    router_attempt: int | None = Field(ge=0, le=_MAX_COUNT)
    router_byok: ByokObservation
    usage_byok: ByokObservation
    endpoint_total: int | None = Field(ge=0, le=_MAX_COUNT)
    available_count: int | None = Field(ge=0, le=_MAX_COUNT)
    selected_endpoints: tuple[DevelopmentRoutingEndpoint, ...] = Field(max_length=_MAX_CANDIDATES)
    attempt_count: int | None = Field(ge=0, le=_MAX_COUNT)
    attempts: tuple[DevelopmentRoutingEndpoint, ...] = Field(max_length=_MAX_CANDIDATES)
    pipeline_count: int | None = Field(ge=0, le=_MAX_COUNT)
    failure_codes: tuple[DevelopmentRoutingFailure, ...] = Field(
        max_length=len(DevelopmentRoutingFailure)
    )

    @field_validator("runtime_authority", mode="before")
    @classmethod
    def never_authority(cls, value: Any) -> bool:
        if value is not False:
            raise ValueError("development routing observations cannot confer authority")
        return False

    @model_validator(mode="after")
    def diagnostic_values_remain_bound(self) -> Self:
        if len(set(self.failure_codes)) != len(self.failure_codes):
            raise ValueError("development routing failure codes must be unique")
        model_values = [self.returned_model, self.requested_model]
        provider_values = [self.response_provider]
        for endpoint in (*self.selected_endpoints, *self.attempts):
            model_values.append(endpoint.model)
            provider_values.append(endpoint.provider)
        for value in model_values:
            if (
                (value.status == "REQUESTED" and value.value != self.context.exact_model_id)
                or (value.status == "CANONICAL" and value.value != self.context.canonical_model_id)
                or value.status == "PROVIDER"
            ):
                raise ValueError("development routing retained a model outside supplied identity")
        for value in provider_values:
            if value.status in {"REQUESTED", "CANONICAL"} or (
                value.status == "PROVIDER"
                and value.value not in {self.context.provider_endpoint, self.context.provider_name}
            ):
                raise ValueError("development routing retained an unbound provider")
        if not self.failure_codes and (
            self.returned_model.status not in {"REQUESTED", "CANONICAL"}
            or self.response_provider.status not in {"ABSENT", "PROVIDER"}
            or self.requested_model.status != "REQUESTED"
            or self.metadata_shape != "OBJECT"
            or self.strategy != "DIRECT"
            or self.router_attempt != 1
            or not {self.router_byok, self.usage_byok}.issubset({"ABSENT", "FALSE"})
            or "FALSE" not in {self.router_byok, self.usage_byok}
            or self.pipeline_count != 0
            or self.endpoint_total is None
            or self.available_count is None
            or not 1 <= self.available_count <= _MAX_CANDIDATES
            or self.endpoint_total < self.available_count
            or len(self.selected_endpoints) != 1
            or any(
                row.model.status not in {"REQUESTED", "CANONICAL"}
                or row.provider.status != "PROVIDER"
                for row in (*self.selected_endpoints, *self.attempts)
            )
            or (self.attempt_count is None and self.attempts != ())
            or (
                self.attempt_count is not None
                and (
                    self.attempt_count != 1
                    or len(self.attempts) != 1
                    or self.attempts[0].http_status != 200
                )
            )
        ):
            raise ValueError("development routing cannot erase a visible refusal")
        return self


def _identity(
    value: Any, context: DevelopmentRoutingContext, api_key: str, *, provider: bool = False
) -> DevelopmentRoutingIdentity:
    if value is _ABSENT or value is None:
        return DevelopmentRoutingIdentity(status="ABSENT")
    if type(value) is not str:
        return DevelopmentRoutingIdentity(status="INVALID")
    if len(value) > 256:
        return DevelopmentRoutingIdentity(status="UNBOUND")
    if (api_key and api_key in value) or detect_secrets(value):
        return DevelopmentRoutingIdentity(status="REDACTED")
    if provider:
        if value in {context.provider_endpoint, context.provider_name}:
            return DevelopmentRoutingIdentity(status="PROVIDER", value=value)
    elif value == context.exact_model_id:
        return DevelopmentRoutingIdentity(status="REQUESTED", value=value)
    elif value == context.canonical_model_id:
        return DevelopmentRoutingIdentity(status="CANONICAL", value=value)
    return DevelopmentRoutingIdentity(status="UNBOUND")


def _integer(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= _MAX_COUNT else None


def _byok(value: Any) -> ByokObservation:
    if value is _ABSENT:
        return "ABSENT"
    if value is False:
        return "FALSE"
    if value is True:
        return "TRUE"
    return "INVALID"


def observe_development_routing(
    payload: dict[str, Any],
    *,
    context: DevelopmentRoutingContext,
    api_key: str,
    generation_header_ids: tuple[str, ...] = (),
) -> DevelopmentRoutingEvidence:
    """Inspect a bounded decoded response without retaining arbitrary response text.

    Explicit false in either documented BYOK location is required; true or malformed
    evidence in either location refuses. Missing is never converted to false.
    """

    if type(payload) is not dict or type(context) is not DevelopmentRoutingContext:
        raise ValueError("development routing requires exact input shapes")
    context = DevelopmentRoutingContext.model_validate(context)
    failures: list[DevelopmentRoutingFailure] = []
    F = DevelopmentRoutingFailure
    returned = _identity(payload.get("model", _ABSENT), context, api_key)
    provider = _identity(payload.get("provider", _ABSENT), context, api_key, provider=True)
    if returned.status not in {"REQUESTED", "CANONICAL"}:
        failures.append(F.RETURNED_MODEL)
    if provider.status not in {"ABSENT", "PROVIDER"}:
        failures.append(F.RESPONSE_PROVIDER)
    raw_router = payload.get("openrouter_metadata", _ABSENT)
    router = raw_router if type(raw_router) is dict else {}
    metadata_shape: Literal["ABSENT", "OBJECT", "INVALID"] = (
        "OBJECT" if type(raw_router) is dict else "ABSENT" if raw_router is _ABSENT else "INVALID"
    )
    requested = _identity(router.get("requested", _ABSENT), context, api_key)
    strategy_value = router.get("strategy", _ABSENT)
    strategy: Literal["ABSENT", "DIRECT", "OTHER", "INVALID"] = (
        "ABSENT"
        if strategy_value is _ABSENT
        else "INVALID"
        if type(strategy_value) is not str
        else "DIRECT"
        if strategy_value == "direct"
        else "OTHER"
    )
    attempt = _integer(router.get("attempt"))
    router_byok = _byok(router.get("is_byok", _ABSENT))
    usage = payload.get("usage")
    usage_byok = _byok(usage.get("is_byok", _ABSENT) if type(usage) is dict else _ABSENT)
    raw_pipeline = router.get("pipeline", [])
    pipeline_count = _integer(len(raw_pipeline)) if type(raw_pipeline) is list else None
    endpoint_data = router.get("endpoints")
    endpoints = endpoint_data if type(endpoint_data) is dict else {}
    available = endpoints.get("available")
    available_count = _integer(len(available)) if type(available) is list else None
    endpoint_total = _integer(endpoints.get("total"))
    selected_rows: list[dict[str, Any]] = []
    attempted_rows: list[dict[str, Any]] = []
    raw_attempts = router.get("attempts")
    attempt_count = _integer(len(raw_attempts)) if type(raw_attempts) is list else None
    if metadata_shape != "OBJECT":
        failures.append(F.ROUTER_METADATA)
    else:
        if requested.status != "REQUESTED":
            failures.append(F.REQUESTED_MODEL)
        if strategy != "DIRECT":
            failures.append(F.STRATEGY)
        if attempt != 1:
            failures.append(F.ROUTER_ATTEMPT)
        if "INVALID" in {router_byok, usage_byok}:
            failures.append(F.BYOK_INVALID)
        if "TRUE" in {router_byok, usage_byok}:
            failures.append(F.BYOK_REPORTED)
        if router_byok == usage_byok == "ABSENT":
            failures.append(F.BYOK_EVIDENCE_MISSING)
        if pipeline_count != 0:
            failures.append(F.PIPELINE)
        if (
            type(available) is not list
            or not 1 <= len(available) <= _MAX_CANDIDATES
            or endpoint_total is None
            or endpoint_total < len(available)
            or any(
                type(row) is not dict or type(row.get("selected")) is not bool for row in available
            )
        ):
            failures.append(F.ENDPOINT_SHAPE)
        else:
            selected_rows = [row for row in available if row["selected"] is True]
            if len(selected_rows) != 1:
                failures.append(F.SELECTION_COUNT)
            if any(
                _identity(row.get("model"), context, api_key).status
                not in {"REQUESTED", "CANONICAL"}
                for row in selected_rows
            ):
                failures.append(F.SELECTED_MODEL)
            if any(
                _identity(row.get("provider"), context, api_key, provider=True).status != "PROVIDER"
                for row in selected_rows
            ):
                failures.append(F.SELECTED_PROVIDER)
        if raw_attempts is not None:
            if (
                type(raw_attempts) is not list
                or len(raw_attempts) != 1
                or type(raw_attempts[0]) is not dict
            ):
                failures.append(F.ATTEMPT_SHAPE)
            else:
                attempted_rows = raw_attempts
                if _identity(raw_attempts[0].get("model"), context, api_key).status not in {
                    "REQUESTED",
                    "CANONICAL",
                }:
                    failures.append(F.ATTEMPT_MODEL)
                if (
                    _identity(
                        raw_attempts[0].get("provider"), context, api_key, provider=True
                    ).status
                    != "PROVIDER"
                ):
                    failures.append(F.ATTEMPT_PROVIDER)
                if (
                    type(raw_attempts[0].get("status")) is not int
                    or raw_attempts[0]["status"] != 200
                ):
                    failures.append(F.ATTEMPT_STATUS)
    generation_id = payload.get("id")
    if (
        type(generation_id) is str
        and DEVELOPMENT_GENERATION_ID.fullmatch(generation_id) is not None
        and generation_header_ids
        and generation_header_ids != (generation_id,)
    ):
        failures.append(F.GENERATION_HEADER)

    def row_observation(
        row: dict[str, Any], *, attempted: bool = False
    ) -> DevelopmentRoutingEndpoint:
        status = row.get("status")
        return DevelopmentRoutingEndpoint(
            model=_identity(row.get("model", _ABSENT), context, api_key),
            provider=_identity(row.get("provider", _ABSENT), context, api_key, provider=True),
            http_status=status
            if attempted and type(status) is int and 100 <= status <= 599
            else None,
        )

    return DevelopmentRoutingEvidence(
        context=context,
        returned_model=returned,
        response_provider=provider,
        requested_model=requested,
        metadata_shape=metadata_shape,
        strategy=strategy,
        router_attempt=attempt,
        router_byok=router_byok,
        usage_byok=usage_byok,
        endpoint_total=endpoint_total,
        available_count=available_count,
        selected_endpoints=tuple(row_observation(row) for row in selected_rows),
        attempt_count=attempt_count,
        attempts=tuple(row_observation(row, attempted=True) for row in attempted_rows),
        pipeline_count=pipeline_count,
        failure_codes=tuple(failures),
    )
