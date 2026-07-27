"""Bounded, fail-closed evidence for public OpenRouter model discovery.

This module never performs network access. Callers supply already-fetched public
catalog metadata together with separately validated exact-endpoint evidence. Only
the allowlisted metadata needed to bind a production candidate is retained.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Mapping
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models.endpoint_snapshots import OpenRouterEndpointSnapshotEvidence
from mmaudit.models.identifiers import (
    EXACT_MODEL_ID_PATTERN,
    is_exact_openrouter_model_id,
)
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.secrets import is_sensitive_workspace_name

_MODEL_ID_PATTERN = EXACT_MODEL_ID_PATTERN
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_CATALOG_MODELS = 10_000
_MAX_PARAMETERS = 256
_MAX_ARTIFACT_BYTES = 2_000_000
_SCHEMA_VERSION = "1.0"
_RUN_SCHEMA_VERSION = "1.0"
_MAX_DISCOVERY_CANDIDATES = 64
_RUN_MANIFEST_NAME = "model-discovery-manifest.json"
OPENROUTER_API_IDENTITY = "https://openrouter.ai/api/v1"
OPENROUTER_CATALOG_QUERY = "/models?zdr=true&supported_parameters=response_format"
OPENROUTER_ZDR_QUERY = "/endpoints/zdr"
_STRUCTURED_OUTPUT_PARAMETERS = frozenset(
    {
        "json_schema",
        "response_format",
        "structured_outputs",
    }
)
_REASONING_PARAMETERS = frozenset(
    {
        "include_reasoning",
        "reasoning",
        "reasoning_effort",
    }
)
_REQUIRED_CATALOG_PARAMETERS = frozenset(
    {
        "max_tokens",
        "response_format",
        "temperature",
    }
)
_TRUSTED_OPENROUTER_DISCOVERY_ISSUER = object()


class ModelDiscoveryValidationError(ValueError):
    """Raised when public metadata cannot prove an exact production candidate."""


class DiscoveryCandidateRoute(BaseModel):
    """One exact requested model/provider route in a discovery run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    exact_model_id: str = Field(pattern=_MODEL_ID_PATTERN)
    approved_provider_endpoint: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")

    @model_validator(mode="after")
    def route_is_exact(self) -> DiscoveryCandidateRoute:
        _validate_non_alias_model_id(self.exact_model_id, "candidate model")
        return self


class DiscoveryEndpointMetadataBinding(BaseModel):
    """Hash binding for one exact per-model endpoint metadata response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    exact_model_id: str = Field(pattern=_MODEL_ID_PATTERN)
    api_query: str = Field(
        pattern=r"^/models/[a-z0-9][a-z0-9._-]{0,127}/"
        r"[a-z0-9][a-z0-9._:%-]{0,767}/endpoints$"
    )
    response_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def endpoint_query_is_exact(self) -> DiscoveryEndpointMetadataBinding:
        _validate_non_alias_model_id(self.exact_model_id, "endpoint metadata model")
        if self.api_query != openrouter_endpoint_query(self.exact_model_id):
            raise ValueError("endpoint metadata query is not bound to the exact model")
        return self


class OpenRouterDiscoveryRunProvenance(BaseModel):
    """Trusted, self-hashed provenance shared by one atomic discovery run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    retrieved_at: datetime
    execution_evidence: Literal[ExecutionEvidenceKind.REAL]
    authenticated_metadata: Literal[True]
    source_api_identity: Literal["https://openrouter.ai/api/v1"]
    catalog_api_query: Literal["/models?zdr=true&supported_parameters=response_format"]
    zdr_api_query: Literal["/endpoints/zdr"]
    client_fingerprint_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider_fingerprint_sha256: str = Field(pattern=_SHA256_PATTERN)
    catalog_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    zdr_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_routes: tuple[DiscoveryCandidateRoute, ...] = Field(
        min_length=1,
        max_length=_MAX_DISCOVERY_CANDIDATES,
    )
    candidate_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    endpoint_metadata_bindings: tuple[DiscoveryEndpointMetadataBinding, ...] = Field(
        min_length=1,
        max_length=_MAX_DISCOVERY_CANDIDATES,
    )
    provenance_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("retrieved_at")
    @classmethod
    def retrieved_at_is_whole_second_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond != 0:
            raise ValueError("discovery retrieval time must be a whole-second UTC timestamp")
        return value

    @model_validator(mode="after")
    def provenance_is_complete_and_self_bound(self) -> OpenRouterDiscoveryRunProvenance:
        route_keys = tuple(
            (route.exact_model_id, route.approved_provider_endpoint)
            for route in self.candidate_routes
        )
        if route_keys != tuple(sorted(set(route_keys))):
            raise ValueError("discovery candidate routes must be unique and sorted")
        if self.candidate_set_sha256 != _canonical_sha256(
            [route.model_dump(mode="json") for route in self.candidate_routes]
        ):
            raise ValueError("discovery candidate-set hash is inconsistent")
        binding_ids = tuple(binding.exact_model_id for binding in self.endpoint_metadata_bindings)
        expected_ids = tuple(route.exact_model_id for route in self.candidate_routes)
        if binding_ids != expected_ids:
            raise ValueError("endpoint metadata bindings do not exactly cover the candidate set")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"provenance_sha256"}))
        if self.provenance_sha256 != expected:
            raise ValueError("discovery provenance hash is inconsistent")
        return self


class OpenRouterModelDiscoveryPayload(BaseModel):
    """Canonical allowlisted model and endpoint discovery facts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    exact_model_id: str = Field(pattern=_MODEL_ID_PATTERN)
    canonical_slug: str = Field(pattern=_MODEL_ID_PATTERN)
    catalog_identity_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    model_metadata_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    catalog_context_size: int = Field(gt=0, le=2**31 - 1)
    catalog_provider_context_size: int = Field(gt=0, le=2**31 - 1)
    catalog_provider_context_size_source: Literal["metadata", "catalog_context"]
    catalog_output_limit: int = Field(gt=0, le=2**31 - 1)
    catalog_output_limit_source: Literal["metadata", "provider_context"]
    model_supported_parameters: tuple[str, ...] = Field(max_length=_MAX_PARAMETERS)
    structured_output_parameters: tuple[str, ...] = Field(min_length=1, max_length=3)
    reasoning_parameters: tuple[str, ...] = Field(max_length=3)
    structured_output_supported: Literal[True]
    reasoning_supported: bool
    approved_provider_endpoint: str = Field(min_length=1, max_length=128)
    provider_name: str = Field(min_length=1, max_length=128)
    endpoint_tag: str | None
    endpoint_slug: str | None
    operational: Literal[True]
    operational_status: str = Field(min_length=1, max_length=32)
    zdr_eligible: Literal[True]
    data_collection_deny_eligible: Literal[True]
    context_size: int = Field(gt=0, le=2**31 - 1)
    output_limit: int = Field(gt=0, le=2**31 - 1)
    endpoint_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    endpoint_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    pricing_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    endpoint_snapshot: OpenRouterEndpointSnapshotEvidence

    @model_validator(mode="after")
    def facts_are_canonical_and_endpoint_bound(self) -> OpenRouterModelDiscoveryPayload:
        _validate_non_alias_model_id(self.exact_model_id, "requested model")
        _validate_non_alias_model_id(self.canonical_slug, "canonical model slug")
        expected_identity_binding = _canonical_sha256(
            {
                "canonical_slug": self.canonical_slug,
                "id": self.exact_model_id,
            }
        )
        if self.catalog_identity_binding_sha256 != expected_identity_binding:
            raise ValueError("catalog identity binding hash is inconsistent")
        if self.model_supported_parameters != tuple(sorted(set(self.model_supported_parameters))):
            raise ValueError("catalog supported parameters must be sorted and unique")
        if not _REQUIRED_CATALOG_PARAMETERS.issubset(self.model_supported_parameters):
            raise ValueError("catalog metadata omits the required request parameters")
        if (
            self.catalog_provider_context_size_source == "catalog_context"
            and self.catalog_provider_context_size != self.catalog_context_size
        ):
            raise ValueError("derived catalog provider context is inconsistent")
        if self.catalog_output_limit > self.catalog_provider_context_size:
            raise ValueError("catalog output limit exceeds the catalog provider context")
        if (
            self.catalog_output_limit_source == "provider_context"
            and self.catalog_output_limit != self.catalog_provider_context_size
        ):
            raise ValueError("derived catalog output limit is inconsistent")

        endpoints = self.endpoint_snapshot.endpoints
        if len(endpoints) != 1:
            raise ValueError("model discovery requires exactly one approved provider endpoint")
        endpoint = endpoints[0]
        if self.endpoint_snapshot.exact_model_id != self.exact_model_id:
            raise ValueError("endpoint snapshot is bound to a different model")
        if self.endpoint_snapshot.configured_provider_endpoints != (
            self.approved_provider_endpoint,
        ):
            raise ValueError("endpoint policy is not bound to the approved provider endpoint")
        if endpoint.provider_endpoint != self.approved_provider_endpoint:
            raise ValueError("endpoint record is not bound to the approved provider endpoint")
        if (
            self.provider_name,
            self.endpoint_tag,
            self.endpoint_slug,
            self.operational,
            self.operational_status,
            self.zdr_eligible,
            self.context_size,
            self.output_limit,
            self.endpoint_record_sha256,
            self.pricing_snapshot_sha256,
        ) != (
            endpoint.provider_name,
            endpoint.endpoint_tag,
            endpoint.endpoint_slug,
            endpoint.operational,
            endpoint.operational_status,
            endpoint.zdr_eligible,
            endpoint.context_length,
            endpoint.max_completion_tokens,
            endpoint.endpoint_snapshot_sha256,
            endpoint.pricing_sha256,
        ):
            raise ValueError("inherited endpoint discovery facts are inconsistent")
        if self.endpoint_snapshot_sha256 != self.endpoint_snapshot.snapshot_sha256:
            raise ValueError("endpoint policy hash is inconsistent")
        if self.zdr_eligible is not True or self.endpoint_snapshot.require_zdr is not True:
            raise ValueError("production discovery requires exact ZDR endpoint evidence")
        if self.data_collection_deny_eligible is not True:
            raise ValueError("production discovery requires data-collection denial eligibility")
        if self.context_size > max(
            self.catalog_context_size,
            self.catalog_provider_context_size,
        ):
            raise ValueError("endpoint context exceeds every published catalog context")
        if self.output_limit > self.context_size:
            raise ValueError("endpoint output limit exceeds the endpoint context")

        common_parameters = set(self.model_supported_parameters).intersection(
            endpoint.supported_parameters
        )
        expected_structured = tuple(sorted(_STRUCTURED_OUTPUT_PARAMETERS & common_parameters))
        if self.structured_output_parameters != expected_structured:
            raise ValueError("structured-output capability evidence is inconsistent")
        expected_reasoning = tuple(sorted(_REASONING_PARAMETERS & common_parameters))
        if self.reasoning_parameters != expected_reasoning:
            raise ValueError("reasoning capability evidence is inconsistent")
        if self.reasoning_supported is not bool(expected_reasoning):
            raise ValueError("reasoning support status is inconsistent")
        if self.structured_output_supported is not bool(expected_structured):
            raise ValueError("structured-output support status is inconsistent")
        if not set(endpoint.required_request_parameters).issubset(self.model_supported_parameters):
            raise ValueError("catalog metadata omits a parameter required by the exact endpoint")

        expected_metadata_hash = _canonical_sha256(_model_metadata_projection(self))
        if self.model_metadata_snapshot_sha256 != expected_metadata_hash:
            raise ValueError("model metadata projection hash is inconsistent")
        return self


class OpenRouterModelDiscoveryEvidence(OpenRouterModelDiscoveryPayload):
    """REAL, provenance-bound discovery evidence for one exact model endpoint."""

    provenance: OpenRouterDiscoveryRunProvenance
    discovery_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def discovery_provenance_and_hash_match(self) -> OpenRouterModelDiscoveryEvidence:
        matching_routes = [
            route
            for route in self.provenance.candidate_routes
            if route.exact_model_id == self.exact_model_id
        ]
        if len(matching_routes) != 1 or (
            matching_routes[0].approved_provider_endpoint != self.approved_provider_endpoint
        ):
            raise ValueError("discovery provenance does not bind the exact candidate route")
        matching_endpoints = [
            binding
            for binding in self.provenance.endpoint_metadata_bindings
            if binding.exact_model_id == self.exact_model_id
        ]
        if len(matching_endpoints) != 1:
            raise ValueError(
                "discovery provenance does not bind the exact endpoint metadata response"
            )
        expected = _canonical_sha256(
            self.model_dump(mode="json", exclude={"discovery_evidence_sha256"})
        )
        if self.discovery_evidence_sha256 != expected:
            raise ValueError("model discovery evidence hash is inconsistent")
        return self


class ModelDiscoveryArtifactBinding(BaseModel):
    """Exact on-disk binding for one discovery evidence record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    exact_model_id: str = Field(pattern=_MODEL_ID_PATTERN)
    approved_provider_endpoint: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
    filename: str = Field(pattern=r"^candidate-[0-9a-f]{64}\.json$")
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def filename_is_model_bound(self) -> ModelDiscoveryArtifactBinding:
        _validate_non_alias_model_id(self.exact_model_id, "artifact model")
        expected = f"candidate-{hashlib.sha256(self.exact_model_id.encode()).hexdigest()}.json"
        if self.filename != expected:
            raise ValueError("discovery artifact filename is not bound to the exact model")
        return self


class OpenRouterModelDiscoveryRunManifest(BaseModel):
    """Self-hashed exact-set manifest for one atomic discovery directory."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    run_provenance: OpenRouterDiscoveryRunProvenance
    candidate_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifacts: tuple[ModelDiscoveryArtifactBinding, ...] = Field(
        min_length=1,
        max_length=_MAX_DISCOVERY_CANDIDATES,
    )
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def manifest_is_exact_complete_and_self_bound(
        self,
    ) -> OpenRouterModelDiscoveryRunManifest:
        if self.candidate_set_sha256 != self.run_provenance.candidate_set_sha256:
            raise ValueError("discovery manifest candidate-set hash is inconsistent")
        artifact_keys = tuple(
            (artifact.exact_model_id, artifact.approved_provider_endpoint)
            for artifact in self.artifacts
        )
        route_keys = tuple(
            (route.exact_model_id, route.approved_provider_endpoint)
            for route in self.run_provenance.candidate_routes
        )
        if artifact_keys != route_keys:
            raise ValueError("discovery manifest does not exactly cover its candidate set")
        filenames = tuple(artifact.filename for artifact in self.artifacts)
        if len(filenames) != len(set(filenames)):
            raise ValueError("discovery manifest artifact filenames must be unique")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"manifest_sha256"}))
        if self.manifest_sha256 != expected:
            raise ValueError("discovery run manifest hash is inconsistent")
        return self


def validate_openrouter_model_discovery(
    *,
    exact_model_id: str,
    models_payload: Any,
    endpoint_snapshot: OpenRouterEndpointSnapshotEvidence,
) -> OpenRouterModelDiscoveryPayload:
    """Validate untrusted metadata without claiming provider execution provenance."""

    _validate_non_alias_model_id(exact_model_id, "requested model")
    envelope = _required_mapping(models_payload, "model catalog")
    items = _required_model_list(envelope.get("data"))
    indexed: dict[str, Mapping[str, Any]] = {}
    for item in items:
        model_id = item.get("id")
        if not isinstance(model_id, str) or re.fullmatch(_MODEL_ID_PATTERN, model_id) is None:
            raise ModelDiscoveryValidationError(
                "model catalog contains a missing or invalid exact model identifier"
            )
        if not is_exact_openrouter_model_id(model_id):
            # OpenRouter's public catalog includes routed aliases. They remain
            # visible provider metadata but can never enter an exact candidate set.
            continue
        if model_id in indexed:
            raise ModelDiscoveryValidationError(
                f"model catalog contains a duplicate exact model identifier: {model_id}"
            )
        indexed[model_id] = item
    selected = indexed.get(exact_model_id)
    if selected is None:
        raise ModelDiscoveryValidationError(
            "requested exact model is unavailable in the public model catalog"
        )

    canonical_slug = _required_model_id(selected.get("canonical_slug"), "canonical model slug")
    _validate_non_alias_model_id(canonical_slug, "canonical model slug")
    requested_author, _requested_model = exact_model_id.split("/", 1)
    canonical_author, _canonical_model = canonical_slug.split("/", 1)
    if canonical_author != requested_author:
        raise ModelDiscoveryValidationError(
            "catalog canonical model changes the requested model author"
        )
    catalog_identity_binding_sha256 = _canonical_sha256(
        {
            "canonical_slug": canonical_slug,
            "id": exact_model_id,
        }
    )
    catalog_context_size = _positive_integer(
        selected.get("context_length"),
        "catalog model context",
    )
    top_provider = _required_mapping(selected.get("top_provider"), "catalog top provider")
    catalog_provider_context_size, provider_context_source = _effective_limit(
        top_provider.get("context_length"),
        fallback=catalog_context_size,
        label="catalog provider context",
    )
    catalog_output_limit, output_limit_source = _effective_limit(
        top_provider.get("max_completion_tokens"),
        fallback=catalog_provider_context_size,
        fallback_source="provider_context",
        label="catalog output limit",
    )
    model_supported_parameters = _supported_parameters(selected.get("supported_parameters"))

    if len(endpoint_snapshot.endpoints) != 1:
        raise ModelDiscoveryValidationError(
            "model discovery requires exactly one approved provider endpoint"
        )
    endpoint = endpoint_snapshot.endpoints[0]
    common_parameters = set(model_supported_parameters).intersection(endpoint.supported_parameters)
    structured_output_parameters = tuple(sorted(_STRUCTURED_OUTPUT_PARAMETERS & common_parameters))
    if not structured_output_parameters:
        raise ModelDiscoveryValidationError(
            "catalog and approved endpoint lack common structured-output support"
        )
    reasoning_parameters = tuple(sorted(_REASONING_PARAMETERS & common_parameters))

    metadata_values: dict[str, Any] = {
        "schema_version": _SCHEMA_VERSION,
        "exact_model_id": exact_model_id,
        "canonical_slug": canonical_slug,
        "catalog_identity_binding_sha256": catalog_identity_binding_sha256,
        "model_metadata_snapshot_sha256": "0" * 64,
        "catalog_context_size": catalog_context_size,
        "catalog_provider_context_size": catalog_provider_context_size,
        "catalog_provider_context_size_source": provider_context_source,
        "catalog_output_limit": catalog_output_limit,
        "catalog_output_limit_source": output_limit_source,
        "model_supported_parameters": model_supported_parameters,
        "structured_output_parameters": structured_output_parameters,
        "reasoning_parameters": reasoning_parameters,
        "structured_output_supported": True,
        "reasoning_supported": bool(reasoning_parameters),
        "approved_provider_endpoint": endpoint.provider_endpoint,
        "provider_name": endpoint.provider_name,
        "endpoint_tag": endpoint.endpoint_tag,
        "endpoint_slug": endpoint.endpoint_slug,
        "operational": endpoint.operational,
        "operational_status": endpoint.operational_status,
        "zdr_eligible": endpoint.zdr_eligible,
        # An exact ZDR endpoint is strictly eligible for a data_collection=deny route.
        "data_collection_deny_eligible": endpoint.zdr_eligible is True,
        "context_size": endpoint.context_length,
        "output_limit": endpoint.max_completion_tokens,
        "endpoint_record_sha256": endpoint.endpoint_snapshot_sha256,
        "endpoint_snapshot_sha256": endpoint_snapshot.snapshot_sha256,
        "pricing_snapshot_sha256": endpoint.pricing_sha256,
        "endpoint_snapshot": endpoint_snapshot,
    }
    provisional = OpenRouterModelDiscoveryPayload.model_construct(**metadata_values)
    metadata_values["model_metadata_snapshot_sha256"] = _canonical_sha256(
        _model_metadata_projection(provisional)
    )
    return OpenRouterModelDiscoveryPayload.model_validate(metadata_values)


def _seal_real_model_discovery_evidence(
    payload: OpenRouterModelDiscoveryPayload,
    provenance: OpenRouterDiscoveryRunProvenance,
    *,
    issuer: object,
) -> OpenRouterModelDiscoveryEvidence:
    """Attach REAL runtime provenance; callable only by the trusted client path."""

    if issuer is not _TRUSTED_OPENROUTER_DISCOVERY_ISSUER:
        raise ModelDiscoveryValidationError(
            "only the trusted OpenRouter client may seal REAL discovery evidence"
        )
    serialized = {
        **payload.model_dump(mode="json"),
        "provenance": provenance.model_dump(mode="json"),
    }
    return OpenRouterModelDiscoveryEvidence.model_validate(
        {
            **serialized,
            "discovery_evidence_sha256": _canonical_sha256(serialized),
        }
    )


def _issue_real_openrouter_discovery_run(
    *,
    run_id: str,
    retrieved_at: datetime,
    client_fingerprint_sha256: str,
    provider_fingerprint_sha256: str,
    catalog_snapshot_sha256: str,
    zdr_snapshot_sha256: str,
    candidate_routes: tuple[DiscoveryCandidateRoute, ...],
    endpoint_metadata_bindings: tuple[DiscoveryEndpointMetadataBinding, ...],
    payloads: tuple[OpenRouterModelDiscoveryPayload, ...],
    issuer: object,
) -> tuple[
    OpenRouterDiscoveryRunProvenance,
    tuple[OpenRouterModelDiscoveryEvidence, ...],
]:
    """Issue one exact REAL run after trusted transport observations are verified."""

    if issuer is not _TRUSTED_OPENROUTER_DISCOVERY_ISSUER:
        raise ModelDiscoveryValidationError(
            "only the trusted OpenRouter client may issue REAL discovery provenance"
        )
    ordered_routes = tuple(
        sorted(
            candidate_routes,
            key=lambda item: (
                item.exact_model_id,
                item.approved_provider_endpoint,
            ),
        )
    )
    ordered_bindings = tuple(
        sorted(endpoint_metadata_bindings, key=lambda item: item.exact_model_id)
    )
    payload_by_model = {payload.exact_model_id: payload for payload in payloads}
    if len(payload_by_model) != len(payloads):
        raise ModelDiscoveryValidationError("discovery payload model IDs must be unique")
    if tuple(payload_by_model) != tuple(sorted(payload_by_model)):
        payload_by_model = dict(sorted(payload_by_model.items()))
    route_ids = tuple(route.exact_model_id for route in ordered_routes)
    if tuple(payload_by_model) != route_ids:
        raise ModelDiscoveryValidationError(
            "validated discovery payloads do not exactly cover the candidate set"
        )
    for route in ordered_routes:
        payload = payload_by_model[route.exact_model_id]
        if payload.approved_provider_endpoint != route.approved_provider_endpoint:
            raise ModelDiscoveryValidationError(
                "validated discovery payload changes its candidate endpoint"
            )
    provenance_values: dict[str, Any] = {
        "schema_version": _RUN_SCHEMA_VERSION,
        "run_id": run_id,
        "retrieved_at": retrieved_at.isoformat().replace("+00:00", "Z"),
        "execution_evidence": ExecutionEvidenceKind.REAL.value,
        "authenticated_metadata": True,
        "source_api_identity": OPENROUTER_API_IDENTITY,
        "catalog_api_query": OPENROUTER_CATALOG_QUERY,
        "zdr_api_query": OPENROUTER_ZDR_QUERY,
        "client_fingerprint_sha256": client_fingerprint_sha256,
        "provider_fingerprint_sha256": provider_fingerprint_sha256,
        "catalog_snapshot_sha256": catalog_snapshot_sha256,
        "zdr_snapshot_sha256": zdr_snapshot_sha256,
        "candidate_routes": [route.model_dump(mode="json") for route in ordered_routes],
        "candidate_set_sha256": _canonical_sha256(
            [route.model_dump(mode="json") for route in ordered_routes]
        ),
        "endpoint_metadata_bindings": [
            binding.model_dump(mode="json") for binding in ordered_bindings
        ],
    }
    provenance = OpenRouterDiscoveryRunProvenance.model_validate(
        {
            **provenance_values,
            "provenance_sha256": _canonical_sha256(provenance_values),
        }
    )
    evidence = tuple(
        _seal_real_model_discovery_evidence(
            payload_by_model[route.exact_model_id],
            provenance,
            issuer=issuer,
        )
        for route in ordered_routes
    )
    return provenance, evidence


def seal_model_discovery_run_manifest(
    *,
    provenance: OpenRouterDiscoveryRunProvenance,
    artifacts: tuple[ModelDiscoveryArtifactBinding, ...],
) -> OpenRouterModelDiscoveryRunManifest:
    """Seal an exact-set manifest after every evidence file has been written."""

    ordered_artifacts = tuple(sorted(artifacts, key=lambda item: item.exact_model_id))
    values: dict[str, Any] = {
        "schema_version": _RUN_SCHEMA_VERSION,
        "run_provenance": provenance.model_dump(mode="json"),
        "candidate_set_sha256": provenance.candidate_set_sha256,
        "artifacts": [artifact.model_dump(mode="json") for artifact in ordered_artifacts],
    }
    return OpenRouterModelDiscoveryRunManifest.model_validate(
        {
            **values,
            "manifest_sha256": _canonical_sha256(values),
        }
    )


def load_model_discovery_evidence(path: Path) -> OpenRouterModelDiscoveryEvidence:
    """Load bounded evidence without following symlinks or accepting hardlinks."""

    _validate_artifact_leaf(path)
    _reject_linked_components(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError("model discovery evidence must be a regular non-link file") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > _MAX_ARTIFACT_BYTES
        ):
            raise ValueError("model discovery evidence must be bounded and unshared")
        chunks: list[bytes] = []
        remaining = _MAX_ARTIFACT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(raw) > _MAX_ARTIFACT_BYTES
            or len(raw) != metadata.st_size
            or (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_nlink)
            != (after.st_dev, after.st_ino, after.st_size, after.st_nlink)
        ):
            raise ValueError("model discovery evidence changed while being read")
    finally:
        os.close(descriptor)
    return OpenRouterModelDiscoveryEvidence.model_validate_json(raw)


def write_model_discovery_evidence(
    path: Path,
    evidence: OpenRouterModelDiscoveryEvidence,
) -> None:
    """Atomically write deterministic evidence without following filesystem links."""

    _validate_artifact_leaf(path)
    serialized = stable_json(evidence).encode("utf-8")
    if len(serialized) > _MAX_ARTIFACT_BYTES:
        raise ValueError("model discovery evidence exceeds its output bound")
    _reject_linked_components(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_linked_components(path)
    if path.is_symlink() or path.is_junction():
        raise ValueError("model discovery destination may not be a link")
    if path.exists():
        metadata = path.stat()
        if not path.is_file() or metadata.st_nlink != 1 or metadata.st_size > _MAX_ARTIFACT_BYTES:
            raise ValueError("model discovery destination must be a bounded unshared file")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(serialized)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("failed to make progress writing model discovery evidence")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if temporary_path.stat().st_nlink != 1:
            raise ValueError("temporary discovery artifact unexpectedly became shared")
        os.replace(temporary_path, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)


def write_model_discovery_run(
    path: Path,
    evidence: tuple[OpenRouterModelDiscoveryEvidence, ...],
) -> OpenRouterModelDiscoveryRunManifest:
    """Atomically publish a fresh exact-set discovery directory or publish nothing."""

    if not 1 <= len(evidence) <= _MAX_DISCOVERY_CANDIDATES:
        raise ValueError("discovery run requires a bounded non-empty evidence set")
    ordered = tuple(sorted(evidence, key=lambda item: item.exact_model_id))
    identifiers = tuple(item.exact_model_id for item in ordered)
    if identifiers != tuple(sorted(set(identifiers))):
        raise ValueError("discovery run evidence models must be unique")
    provenance = ordered[0].provenance
    if any(item.provenance != provenance for item in ordered):
        raise ValueError("discovery run evidence must share one exact provenance record")
    expected_ids = tuple(route.exact_model_id for route in provenance.candidate_routes)
    if identifiers != expected_ids:
        raise ValueError("discovery run evidence does not exactly cover its candidate set")

    absolute = Path(os.path.abspath(path))
    _validate_artifact_leaf(absolute)
    if absolute.exists() or absolute.is_symlink() or absolute.is_junction():
        raise ValueError("model discovery run destination must be fresh")
    _reject_linked_components(absolute.parent)
    absolute.parent.mkdir(parents=True, exist_ok=True)
    _reject_linked_components(absolute.parent)
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{absolute.name}.",
            suffix=".tmp",
            dir=absolute.parent,
        )
    )
    os.chmod(temporary, 0o700)
    published = False
    try:
        bindings: list[ModelDiscoveryArtifactBinding] = []
        for item in ordered:
            filename = f"candidate-{hashlib.sha256(item.exact_model_id.encode()).hexdigest()}.json"
            destination = temporary / filename
            write_model_discovery_evidence(destination, item)
            artifact_bytes = destination.read_bytes()
            bindings.append(
                ModelDiscoveryArtifactBinding(
                    exact_model_id=item.exact_model_id,
                    approved_provider_endpoint=item.approved_provider_endpoint,
                    filename=filename,
                    artifact_sha256=hashlib.sha256(artifact_bytes).hexdigest(),
                    discovery_evidence_sha256=item.discovery_evidence_sha256,
                )
            )
        manifest = seal_model_discovery_run_manifest(
            provenance=provenance,
            artifacts=tuple(bindings),
        )
        _write_private_bytes(
            temporary / _RUN_MANIFEST_NAME,
            stable_json(manifest).encode("utf-8"),
        )
        directory_descriptor = os.open(temporary, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        if absolute.exists() or absolute.is_symlink() or absolute.is_junction():
            raise ValueError("model discovery run destination was reused during publication")
        os.rename(temporary, absolute)
        published = True
        return manifest
    finally:
        if not published:
            shutil.rmtree(temporary, ignore_errors=True)


def load_model_discovery_run(
    path: Path,
) -> tuple[
    OpenRouterModelDiscoveryRunManifest,
    tuple[OpenRouterModelDiscoveryEvidence, ...],
]:
    """Load a complete exact-set run while rejecting stale or unmanifested files."""

    absolute = Path(os.path.abspath(path))
    _reject_linked_components(absolute)
    if not absolute.is_dir():
        raise ValueError("model discovery run must be a regular non-link directory")
    manifest_raw = _read_bounded_unshared_file(absolute / _RUN_MANIFEST_NAME)
    manifest = OpenRouterModelDiscoveryRunManifest.model_validate_json(manifest_raw)
    expected_names = {
        _RUN_MANIFEST_NAME,
        *(binding.filename for binding in manifest.artifacts),
    }
    observed_names = {item.name for item in absolute.iterdir()}
    if observed_names != expected_names:
        raise ValueError("model discovery run contains stale or unmanifested artifacts")
    evidence: list[OpenRouterModelDiscoveryEvidence] = []
    for binding in manifest.artifacts:
        artifact_path = absolute / binding.filename
        artifact_raw = _read_bounded_unshared_file(artifact_path)
        if hashlib.sha256(artifact_raw).hexdigest() != binding.artifact_sha256:
            raise ValueError("model discovery artifact hash does not match its manifest")
        item = OpenRouterModelDiscoveryEvidence.model_validate_json(artifact_raw)
        if (
            item.provenance != manifest.run_provenance
            or item.exact_model_id != binding.exact_model_id
            or item.approved_provider_endpoint != binding.approved_provider_endpoint
            or item.discovery_evidence_sha256 != binding.discovery_evidence_sha256
        ):
            raise ValueError("model discovery artifact is inconsistent with its manifest")
        evidence.append(item)
    return manifest, tuple(evidence)


def _write_private_bytes(path: Path, value: bytes) -> None:
    if not value or len(value) > _MAX_ARTIFACT_BYTES:
        raise ValueError("model discovery artifact bytes are invalid")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("failed to make progress writing model discovery artifact")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_bounded_unshared_file(path: Path) -> bytes:
    _reject_linked_components(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= _MAX_ARTIFACT_BYTES
        ):
            raise ValueError("model discovery artifact must be bounded and unshared")
        chunks: list[bytes] = []
        remaining = _MAX_ARTIFACT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(raw) != metadata.st_size or (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_nlink,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_nlink):
            raise ValueError("model discovery artifact changed while being read")
        return raw
    finally:
        os.close(descriptor)


def _model_metadata_projection(
    evidence: OpenRouterModelDiscoveryPayload,
) -> dict[str, Any]:
    return {
        "canonical_slug": evidence.canonical_slug,
        "context_length": evidence.catalog_context_size,
        "id": evidence.exact_model_id,
        "supported_parameters": list(evidence.model_supported_parameters),
        "top_provider": {
            "context_length": evidence.catalog_provider_context_size,
            "context_length_source": evidence.catalog_provider_context_size_source,
            "max_completion_tokens": evidence.catalog_output_limit,
            "max_completion_tokens_source": evidence.catalog_output_limit_source,
        },
    }


def _validate_non_alias_model_id(value: str, label: str) -> None:
    if not is_exact_openrouter_model_id(value):
        raise ModelDiscoveryValidationError(
            f"{label} must be an exact non-routed author/model identifier"
        )


def _required_model_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not is_exact_openrouter_model_id(value):
        raise ModelDiscoveryValidationError(f"{label} is missing or invalid")
    return value


def openrouter_endpoint_query(exact_model_id: str) -> str:
    """Return the fixed authenticated endpoint-metadata query for one exact model."""

    _validate_non_alias_model_id(exact_model_id, "endpoint metadata model")
    author, slug = exact_model_id.split("/", 1)
    return f"/models/{quote(author, safe='')}/{quote(slug, safe=':._-')}/endpoints"


def _required_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ModelDiscoveryValidationError(f"{label} must be an object")
    return value


def _required_model_list(value: Any) -> list[Mapping[str, Any]]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > _MAX_CATALOG_MODELS
        or any(not isinstance(item, dict) for item in value)
    ):
        raise ModelDiscoveryValidationError(
            "model catalog must contain a bounded non-empty data list"
        )
    return value


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= 2**31 - 1:
        raise ModelDiscoveryValidationError(f"{label} is invalid")
    return int(value)


def _effective_limit(
    value: Any,
    *,
    fallback: int,
    fallback_source: Literal["catalog_context", "provider_context"] = "catalog_context",
    label: str,
) -> tuple[int, Literal["metadata", "catalog_context", "provider_context"]]:
    if value is None:
        return fallback, fallback_source
    return _positive_integer(value, label), "metadata"


def _supported_parameters(value: Any) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or len(value) > _MAX_PARAMETERS
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > 100
            or item != item.casefold()
            or re.fullmatch(r"[a-z][a-z0-9_]{0,99}", item) is None
            for item in value
        )
    ):
        raise ModelDiscoveryValidationError("catalog supported parameters are invalid")
    if len(value) != len(set(value)):
        raise ModelDiscoveryValidationError("catalog supported parameters are duplicated")
    normalized = tuple(sorted(value))
    if not _REQUIRED_CATALOG_PARAMETERS.issubset(normalized):
        raise ModelDiscoveryValidationError(
            "catalog metadata omits the required request parameters"
        )
    return normalized


def _validate_artifact_leaf(path: Path) -> None:
    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing a sensitive model discovery artifact filename")


def _reject_linked_components(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    candidates = (absolute, *absolute.parents)
    for candidate in candidates:
        if candidate.is_symlink() or candidate.is_junction():
            raise ValueError("model discovery artifact path may not traverse links")


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
