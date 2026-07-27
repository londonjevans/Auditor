"""Bounded asynchronous OpenRouter client with structured-output validation."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import math
import random
import re
import time
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal, TypeVar
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ValidationError

from mmaudit.config import ExecutionConfig, PrivacyConfig, model_family
from mmaudit.constants import OPENROUTER_DEFAULT_BASE_URL
from mmaudit.models.endpoint_snapshots import OpenRouterEndpointSnapshotEvidence
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.models.usage import UsageLedger
from mmaudit.orchestration.budgets import (
    BudgetExhaustedError,
    BudgetManager,
    EndpointRequestCostBound,
    Reservation,
    UnprovenCostBoundError,
)

ResponseT = TypeVar("ResponseT", bound=BaseModel)

_NORMALIZED_OPENROUTER_BASE_URL = OPENROUTER_DEFAULT_BASE_URL.rstrip("/") + "/"
_EXACT_MODEL_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
)
_PROVIDER_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,127}$")
_NON_DIRECT_ROUTING_STRATEGIES = {
    "alias",
    "auto",
    "bodybuilder",
    "fallback",
    "free",
    "fusion",
    "latest",
    "pareto",
}
_TRUNCATED_FINISH_REASONS = {
    "content_filter",
    "error",
    "length",
    "max_tokens",
    "max_tokens_exceeded",
    "token_limit_exceeded",
}
_SUPPORTED_TEXT_PRICING_FIELDS = frozenset(
    {
        "completion",
        "image",
        "input_cache_read",
        "input_cache_write",
        "internal_reasoning",
        "prompt",
        "request",
        "web_search",
    }
)
_ROUTER_MAX_PRICE_FIELDS = frozenset({"completion", "image", "prompt", "request"})
_PER_MILLION_ROUTER_PRICE_FIELDS = frozenset({"completion", "prompt"})
_UNENFORCEABLE_VARIABLE_PRICING_FIELDS = frozenset(
    {
        "input_cache_read",
        "input_cache_write",
        "internal_reasoning",
    }
)
_TRUSTED_ASYNC_CLIENT_SEND = httpx.AsyncClient.send
_TRUSTED_ASYNC_CLIENT_REQUEST = httpx.AsyncClient.request
_TRUSTED_ASYNC_CLIENT_STREAM = httpx.AsyncClient.stream
_TRUSTED_ASYNC_HTTP_TRANSPORT_REQUEST = httpx.AsyncHTTPTransport.handle_async_request


@dataclass(frozen=True)
class OpenRouterProviderPolicy:
    """Explicit provider routing policy for one exact OpenRouter model."""

    certification: bool = False
    only: tuple[str, ...] = ()
    order: tuple[str, ...] = ()
    allow_fallbacks: bool = False

    def __post_init__(self) -> None:
        if self.only and self.order:
            raise ValueError("provider routing must use either only or order, not both")
        for label, providers in (("only", self.only), ("order", self.order)):
            if len(providers) != len(set(providers)):
                raise ValueError(f"provider.{label} must contain unique endpoints")
            if any(not _PROVIDER_ID_PATTERN.fullmatch(provider) for provider in providers):
                raise ValueError(f"provider.{label} contains an invalid endpoint identifier")
        if self.certification and not (self.only or self.order):
            raise ValueError("certification requires an explicit provider endpoint allowlist")
        if self.certification and len(self.configured_endpoints) != 1:
            raise ValueError("certification requires exactly one provider endpoint")
        if self.certification and self.allow_fallbacks:
            raise ValueError("certification cannot allow provider fallbacks")

    @property
    def configured_endpoints(self) -> tuple[str, ...]:
        return self.only or self.order

    def as_request_payload(self, *, require_zdr: bool) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "allow_fallbacks": self.allow_fallbacks,
            "require_parameters": True,
            "data_collection": "deny",
        }
        if require_zdr:
            payload["zdr"] = True
        if self.only:
            payload["only"] = list(self.only)
        elif self.order:
            payload["order"] = list(self.order)
        return payload


@dataclass(frozen=True)
class OpenRouterReasoning:
    """Bounded reasoning controls supported by OpenRouter."""

    effort: Literal["minimal", "low", "medium", "high", "xhigh"] | None = None
    max_tokens: int | None = None
    exclude: bool = False

    def __post_init__(self) -> None:
        if self.effort is not None and self.max_tokens is not None:
            raise ValueError("reasoning effort and max_tokens are mutually exclusive")
        if self.max_tokens is not None and not 1 <= self.max_tokens <= 65_536:
            raise ValueError("reasoning max_tokens must be between 1 and 65536")

    def as_request_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"exclude": self.exclude}
        if self.effort is not None:
            payload["effort"] = self.effort
        if self.max_tokens is not None:
            payload["max_tokens"] = self.max_tokens
        return payload


@dataclass(frozen=True)
class CompletionEnvelope:
    generation_id: str
    returned_model: str
    provider: str
    finish_reason: str
    native_finish_reason: str | None
    content: str
    usage: dict[str, Any]
    router_metadata: dict[str, Any]
    selected_provider: str
    selected_provider_name: str
    router_attempt: int
    router_attempt_count: int
    router_attempts_observed: bool
    pipeline: tuple[dict[str, str], ...]


@dataclass(frozen=True)
class _RegisteredEndpointPricing:
    provider_endpoint: str
    provider_identities: tuple[str, ...]
    pricing: tuple[tuple[str, str], ...]
    pricing_sha256: str
    snapshot_sha256: str
    max_prompt_tokens: int
    max_completion_tokens: int


@dataclass(frozen=True)
class _RegisteredEndpointPolicy:
    snapshot_sha256: str
    policy_pricing_sha256: str
    routing_max_price: tuple[tuple[str, float], ...]
    endpoints: tuple[_RegisteredEndpointPricing, ...]

    def endpoint(self, provider_identity: str) -> _RegisteredEndpointPricing | None:
        normalized = provider_identity.casefold()
        matches = [
            endpoint
            for endpoint in self.endpoints
            if normalized in {identity.casefold() for identity in endpoint.provider_identities}
        ]
        return matches[0] if len(matches) == 1 else None


class OpenRouterError(RuntimeError):
    """Base provider error containing no source excerpts."""


class OpenRouterAuthenticationError(OpenRouterError):
    pass


class OpenRouterTransientError(OpenRouterError):
    pass


class OpenRouterTimeoutError(OpenRouterTransientError):
    pass


class OpenRouterRateLimitError(OpenRouterTransientError):
    pass


class OpenRouterProviderUnavailableError(OpenRouterTransientError):
    pass


class OpenRouterSchemaError(OpenRouterError):
    pass


class OpenRouterTruncatedResponseError(OpenRouterSchemaError):
    pass


class OpenRouterPrivacyError(OpenRouterError):
    pass


class OpenRouterModelError(OpenRouterError):
    pass


class OpenRouterProviderPolicyError(OpenRouterModelError):
    pass


class OpenRouterRequestLimitError(OpenRouterError):
    pass


class OpenRouterCostControlError(OpenRouterError):
    pass


def is_retryable_status(status_code: int) -> bool:
    return status_code in {408, 409, 425, 429} or 500 <= status_code <= 599


def safe_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return headers safe for diagnostics."""

    return {
        key: (
            "[REDACTED]"
            if key.lower() in {"authorization", "proxy-authorization", "x-api-key"}
            else value
        )
        for key, value in headers.items()
    }


def strict_json_schema(response_model: type[BaseModel]) -> dict[str, Any]:
    """Normalize Pydantic JSON Schema for strict structured-output providers."""

    schema = copy.deepcopy(response_model.model_json_schema())

    def normalize(node: Any) -> None:
        if isinstance(node, dict):
            node.pop("default", None)
            properties = node.get("properties")
            if isinstance(properties, dict):
                node["required"] = list(properties)
                node["additionalProperties"] = False
            for value in node.values():
                normalize(value)
        elif isinstance(node, list):
            for value in node:
                normalize(value)

    normalize(schema)
    return schema


class OpenRouterClient:
    """Minimal client that never enables tools, web access, or random model routing."""

    def __init__(
        self,
        *,
        api_key: str,
        execution: ExecutionConfig,
        privacy: PrivacyConfig,
        budget: BudgetManager,
        usage: UsageLedger,
        base_url: str = OPENROUTER_DEFAULT_BASE_URL,
        http_client: httpx.AsyncClient | None = None,
        run_dir: Path | None = None,
        logger: logging.Logger | None = None,
        random_seed: int = 0,
        provider_policy: OpenRouterProviderPolicy | None = None,
        reasoning: OpenRouterReasoning | None = None,
    ) -> None:
        if (
            not api_key
            or len(api_key.encode("utf-8")) > 4_096
            or not api_key.isascii()
            or any(not 33 <= ord(character) <= 126 for character in api_key)
        ):
            raise OpenRouterAuthenticationError("operator API credential is missing or invalid")
        self.execution = execution
        self.privacy = privacy
        self.budget = budget
        self.usage = usage
        self.run_dir = run_dir
        self.logger = logger or logging.getLogger("mmaudit.openrouter")
        self._random = random.Random(random_seed)
        self.provider_policy = provider_policy or OpenRouterProviderPolicy()
        self.reasoning = reasoning
        self._endpoint_pricing: dict[str, _RegisteredEndpointPolicy] = {}
        if self.provider_policy.certification and not self.privacy.require_zdr:
            raise OpenRouterPrivacyError("certification requires zero-data-retention routing")
        if self.execution.max_json_repair_attempts:
            raise OpenRouterSchemaError(
                "model-output repair is disabled because repaired output cannot count as a review"
            )
        self._owns_client = http_client is None
        closed_mock_transport = _uses_closed_httpx_mock_transport(http_client)
        normalized_base_url = base_url.rstrip("/") + "/"
        effective_base_url = (
            normalized_base_url
            if http_client is None
            else str(http_client.base_url).rstrip("/") + "/"
        )
        if not closed_mock_transport and effective_base_url != _NORMALIZED_OPENROUTER_BASE_URL:
            raise OpenRouterPrivacyError(
                "operator credentials may only use the canonical OpenRouter API endpoint"
            )
        self.execution_evidence = (
            ExecutionEvidenceKind.MOCK
            if closed_mock_transport
            else (
                ExecutionEvidenceKind.REAL
                if self._owns_client
                else ExecutionEvidenceKind.UNVERIFIED
            )
        )
        self._requires_paid_controls = (
            not closed_mock_transport or self.budget.atomic_ledger is not None
        )
        self._credential = bytearray(api_key.encode("utf-8"))
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/mmaudit/mmaudit",
            "X-OpenRouter-Title": "mmaudit",
            "X-OpenRouter-Metadata": "enabled",
        }
        self._client = http_client or httpx.AsyncClient(
            base_url=normalized_base_url,
            timeout=httpx.Timeout(execution.request_timeout_seconds),
            headers=self._headers,
            trust_env=False,
        )
        self._client_identity = self._client
        self._transport_identity = getattr(self._client, "_transport", None)
        self._owned_client_identity = self._client if self._owns_client else None
        self._owned_transport_identity = (
            getattr(self._client, "_transport", None) if self._owns_client else None
        )
        if self._owns_client and not _owned_httpx_callables_are_pristine(
            self._client,
            self._owned_transport_identity,
        ):
            raise OpenRouterPrivacyError("owned provider callable provenance is invalid")

    async def __aenter__(self) -> OpenRouterClient:
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.close()

    async def close(self) -> None:
        self.clear_credentials()
        if self._owned_client_identity is not None:
            await self._owned_client_identity.aclose()

    def clear_credentials(self) -> None:
        """Drop retained authorization values without serializing them."""

        authorization = self._headers.get("Authorization")
        self._credential[:] = b"\x00" * len(self._credential)
        self._credential.clear()
        self._headers.clear()
        if (
            self._owned_client_identity is not None
            and self._owned_client_identity.headers.get("Authorization") == authorization
        ):
            self._owned_client_identity.headers.pop("Authorization", None)

    async def validate_authentication(self) -> None:
        """Validate the current bearer credential without returning key metadata."""

        payload = await self._request_metadata("/key")
        if not isinstance(payload.get("data"), dict):
            raise OpenRouterAuthenticationError(
                "OpenRouter key validation returned an invalid response"
            )

    async def list_models(self) -> list[dict[str, Any]]:
        response = await self._request_metadata("/models")
        data = response.get("data")
        if (
            not isinstance(data, list)
            or not data
            or any(not isinstance(item, dict) for item in data)
        ):
            raise OpenRouterModelError("OpenRouter returned an invalid models response")
        result = list(data)
        for item in result:
            model_id = item.get("id")
            if not isinstance(model_id, str) or not _is_model_slug(model_id):
                raise OpenRouterModelError("OpenRouter returned invalid model metadata")
        return result

    async def get_model_endpoint_metadata(self, model: str) -> dict[str, Any]:
        """Return the exact-model endpoint response envelope after basic validation."""

        _require_exact_model_id(model)
        author, slug = model.split("/", 1)
        response = await self._request_metadata(
            f"/models/{quote(author, safe='')}/{quote(slug, safe=':._-')}/endpoints"
        )
        data = response.get("data")
        if not isinstance(data, dict):
            raise OpenRouterModelError("OpenRouter returned invalid endpoint metadata")
        if data.get("id") != model:
            raise OpenRouterModelError(
                "OpenRouter endpoint metadata does not bind the exact requested model"
            )
        endpoints = data.get("endpoints")
        if (
            not isinstance(endpoints, list)
            or not endpoints
            or any(not isinstance(endpoint, dict) for endpoint in endpoints)
        ):
            raise OpenRouterModelError("OpenRouter returned invalid endpoint metadata")
        return response

    async def list_model_endpoints(self, model: str) -> list[dict[str, Any]]:
        """Return endpoint records for one exact author/model slug."""

        response = await self.get_model_endpoint_metadata(model)
        data = response["data"]
        assert isinstance(data, dict)
        endpoints = data["endpoints"]
        assert isinstance(endpoints, list)
        return list(endpoints)

    async def list_zdr_endpoints(self) -> dict[str, Any]:
        response = await self._request_metadata("/endpoints/zdr")
        data = response.get("data")
        if (
            not isinstance(data, list)
            or not data
            or any(not isinstance(endpoint, dict) for endpoint in data)
        ):
            raise OpenRouterPrivacyError("OpenRouter returned invalid ZDR endpoint metadata")
        return response

    def register_certification_endpoint_snapshot(
        self,
        *,
        evidence: OpenRouterEndpointSnapshotEvidence,
    ) -> None:
        """Bind one exact validated endpoint/pricing snapshot before a paid request."""

        if not self.provider_policy.certification:
            raise OpenRouterCostControlError(
                "endpoint pricing may only be registered for one certification endpoint"
            )
        self.register_endpoint_snapshot(evidence=evidence)

    def register_endpoint_snapshot(
        self,
        *,
        evidence: OpenRouterEndpointSnapshotEvidence,
    ) -> None:
        """Bind all validated exact endpoints needed to prove a paid request ceiling."""

        if not isinstance(evidence, OpenRouterEndpointSnapshotEvidence):
            raise OpenRouterCostControlError("endpoint pricing evidence has an invalid type")
        _require_exact_model_id(evidence.exact_model_id)
        configured = self.provider_policy.configured_endpoints
        if not configured:
            raise OpenRouterCostControlError(
                "endpoint pricing requires an explicit provider endpoint policy"
            )
        if (
            evidence.configured_provider_endpoints != configured
            or evidence.provider_policy_mode != ("only" if self.provider_policy.only else "order")
        ):
            raise OpenRouterProviderPolicyError(
                "endpoint pricing does not match the exact configured provider policy"
            )
        if not evidence.require_zdr or not self.privacy.require_zdr:
            raise OpenRouterPrivacyError(
                "paid endpoint pricing requires current ZDR eligibility evidence"
            )
        registered: list[_RegisteredEndpointPricing] = []
        pricing_hashes: dict[str, str] = {}
        identity_owners: dict[str, str] = {}
        for configured_endpoint in configured:
            endpoint = evidence.endpoint(configured_endpoint)
            pricing = endpoint.pricing
            if (
                not pricing
                or not {"prompt", "completion"}.issubset(pricing)
                or not set(pricing).issubset(_SUPPORTED_TEXT_PRICING_FIELDS)
            ):
                raise OpenRouterCostControlError(
                    "endpoint pricing is incomplete or unsupported for bounded text requests"
                )
            provider_identities = tuple(
                sorted(
                    {
                        identity
                        for identity in (
                            endpoint.provider_endpoint,
                            endpoint.endpoint_tag,
                            endpoint.endpoint_slug,
                            endpoint.provider_name,
                        )
                        if identity is not None
                    },
                    key=str.casefold,
                )
            )
            for identity in provider_identities:
                normalized_identity = identity.casefold()
                existing_owner = identity_owners.get(normalized_identity)
                if existing_owner is not None and existing_owner != endpoint.provider_endpoint:
                    raise OpenRouterProviderPolicyError(
                        "configured endpoints have ambiguous provider response identities"
                    )
                identity_owners[normalized_identity] = endpoint.provider_endpoint
            registered.append(
                _RegisteredEndpointPricing(
                    provider_endpoint=endpoint.provider_endpoint,
                    provider_identities=provider_identities,
                    pricing=tuple(pricing.items()),
                    pricing_sha256=endpoint.pricing_sha256,
                    snapshot_sha256=evidence.snapshot_sha256,
                    max_prompt_tokens=endpoint.max_prompt_tokens,
                    max_completion_tokens=endpoint.max_completion_tokens,
                )
            )
            pricing_hashes[endpoint.provider_endpoint] = endpoint.pricing_sha256
        routing_max_price = _routing_max_price(tuple(registered))
        self._endpoint_pricing[evidence.exact_model_id] = _RegisteredEndpointPolicy(
            snapshot_sha256=evidence.snapshot_sha256,
            policy_pricing_sha256=_canonical_sha256(pricing_hashes),
            routing_max_price=tuple(routing_max_price.items()),
            endpoints=tuple(registered),
        )

    async def _request_metadata(self, path: str) -> dict[str, Any]:
        attempts = 0
        while True:
            attempts += 1
            try:
                response = await self._bounded_request(
                    "GET",
                    path,
                    max_bytes=20_000_000,
                )
            except (httpx.TimeoutException, httpx.NetworkError):
                if attempts >= self.execution.max_model_retries + 1:
                    raise OpenRouterTimeoutError("OpenRouter metadata request failed") from None
                await self._backoff(attempts, None)
                continue
            except httpx.HTTPError:
                raise OpenRouterModelError(
                    "OpenRouter metadata transport response was invalid"
                ) from None
            if response.status_code in {401, 403}:
                raise OpenRouterAuthenticationError("OpenRouter rejected the API credentials")
            if is_retryable_status(response.status_code):
                if attempts >= self.execution.max_model_retries + 1:
                    if response.status_code == 429:
                        raise OpenRouterRateLimitError(
                            "OpenRouter metadata rate limit exhausted the retry policy"
                        )
                    if response.status_code in {408, 425}:
                        raise OpenRouterTimeoutError(
                            f"transient metadata failure (HTTP {response.status_code})"
                        )
                    raise OpenRouterProviderUnavailableError(
                        f"metadata provider unavailable (HTTP {response.status_code})"
                    )
                await self._backoff(attempts, response.headers.get("Retry-After"))
                continue
            if response.status_code >= 400:
                raise OpenRouterModelError(
                    f"OpenRouter metadata request failed with HTTP {response.status_code}"
                )
            break
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if not isinstance(payload, dict):
            raise OpenRouterModelError("OpenRouter metadata response was not a valid object")
        self._ensure_no_credential_in_value(payload)
        return payload

    async def _bounded_request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        max_bytes: int,
    ) -> httpx.Response:
        self._validate_transport_provenance()
        chunks: list[bytes] = []
        total = 0
        relative_path = path.lstrip("/")
        try:
            async with self._client.stream(
                method,
                relative_path,
                json=json_body,
                headers=self._headers,
                timeout=httpx.Timeout(self.execution.request_timeout_seconds),
            ) as response:
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise OpenRouterSchemaError(
                            "provider response exceeded the configured safety limit"
                        )
                    chunks.append(chunk)
                safe_request = httpx.Request(method, response.request.url)
                return httpx.Response(
                    status_code=response.status_code,
                    headers=_decoded_response_headers(response.headers),
                    content=b"".join(chunks),
                    request=safe_request,
                )
        except OpenRouterError:
            raise
        except httpx.HTTPError as exc:
            if exc.request is not None:
                exc.request = httpx.Request(method, self._client.base_url.join(relative_path))
            raise
        except Exception:
            pass
        raise OpenRouterSchemaError("model transport failed safely")

    def _validate_transport_provenance(self) -> None:
        if (
            self._client is not self._client_identity
            or getattr(self._client, "_transport", None) is not self._transport_identity
        ):
            raise OpenRouterPrivacyError("provider transport provenance changed after validation")
        if self.execution_evidence is ExecutionEvidenceKind.UNVERIFIED:
            raise OpenRouterPrivacyError(
                "network-capable injected provider clients are not permitted"
            )
        if self._owns_client and (
            self._client is not self._owned_client_identity
            or getattr(self._client, "_transport", None) is not self._owned_transport_identity
            or not _owned_httpx_callables_are_pristine(
                self._client,
                self._owned_transport_identity,
            )
        ):
            raise OpenRouterPrivacyError("owned provider callable provenance is invalid")

    def build_request(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
        response_model: type[BaseModel],
        schema_name: str,
        request_metadata: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        _require_exact_model_id(model)
        body: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0,
            "max_tokens": self.execution.max_output_tokens_per_request,
            "stream": False,
            "provider": self.provider_policy.as_request_payload(
                require_zdr=self.privacy.require_zdr
            ),
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": schema_name,
                    "strict": True,
                    "schema": strict_json_schema(response_model),
                },
            },
        }
        endpoint_policy = self._endpoint_pricing.get(model)
        if endpoint_policy is not None:
            provider = body["provider"]
            assert isinstance(provider, dict)
            provider["max_price"] = dict(endpoint_policy.routing_max_price)
        if self.reasoning is not None:
            body["reasoning"] = self.reasoning.as_request_payload()
        if request_metadata:
            body["metadata"] = {
                key: value
                for key, value in request_metadata.items()
                if _is_safe_metadata_pair(key, value)
            }
            if len(body["metadata"]) != len(request_metadata):
                raise OpenRouterRequestLimitError("request metadata is invalid")
        return body

    async def complete(
        self,
        *,
        role: str,
        models: list[str],
        system_prompt: str,
        user_prompt: str,
        response_model: type[ResponseT],
        schema_name: str,
    ) -> ResponseT:
        """Call only the explicitly supplied models, in order."""

        if not models:
            raise OpenRouterModelError(f"no model configured for role {role}")
        if self.execution_evidence is ExecutionEvidenceKind.UNVERIFIED:
            raise OpenRouterPrivacyError(
                "network-capable injected provider clients are not permitted"
            )
        if self._requires_paid_controls and self.budget.atomic_ledger is None:
            raise OpenRouterCostControlError(
                "real provider completions require a durable atomic cost ledger"
            )
        if self._requires_paid_controls and not self.budget.require_endpoint_cost_bound:
            raise OpenRouterCostControlError(
                "real provider completions require endpoint-bound maximum cost proof"
            )
        if self._requires_paid_controls and not self.privacy.require_zdr:
            raise OpenRouterPrivacyError(
                "real provider completions require zero-data-retention routing"
            )
        if self._requires_paid_controls and not self.provider_policy.configured_endpoints:
            raise OpenRouterProviderPolicyError(
                "real provider completions require an explicit provider endpoint allowlist"
            )
        for model in models:
            _require_exact_model_id(model)
        if self._requires_paid_controls:
            unbound_models = [model for model in models if model not in self._endpoint_pricing]
            if unbound_models:
                raise OpenRouterCostControlError(
                    "real provider completion lacks validated endpoint pricing"
                )
        if self.provider_policy.certification and len(models) != 1:
            raise OpenRouterModelError(
                "certification requires exactly one explicitly qualified model"
            )
        last_error: OpenRouterError | None = None
        for index, model in enumerate(models):
            try:
                return await self._complete_one(
                    role=role,
                    model=model,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_model=response_model,
                    schema_name=schema_name,
                    fallback_used=index > 0,
                )
            except (
                OpenRouterTransientError,
                OpenRouterModelError,
                OpenRouterSchemaError,
            ) as exc:
                last_error = exc
                self.logger.warning(
                    "Configured model failed; considering the next explicit fallback",
                    extra={"role": role, "status": "fallback"},
                )
        assert last_error is not None
        raise last_error

    async def _complete_one(
        self,
        *,
        role: str,
        model: str,
        system_prompt: str,
        user_prompt: str,
        response_model: type[ResponseT],
        schema_name: str,
        fallback_used: bool,
    ) -> ResponseT:
        request_id = str(uuid.uuid4())
        prompt_hash = _canonical_sha256(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]
        )
        schema = strict_json_schema(response_model)
        schema_hash = _canonical_sha256(schema)
        request_metadata = {
            "mmaudit_request_id": request_id,
            "mmaudit_role": role,
            "mmaudit_prompt_sha256": prompt_hash,
            "mmaudit_schema_sha256": schema_hash,
        }
        endpoint_policy = self._endpoint_pricing.get(model)
        if endpoint_policy is not None:
            request_metadata["mmaudit_endpoint_snapshot_sha256"] = endpoint_policy.snapshot_sha256
            request_metadata["mmaudit_endpoint_pricing_sha256"] = (
                endpoint_policy.policy_pricing_sha256
            )
        body = self.build_request(
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            schema_name=schema_name,
            request_metadata=request_metadata,
        )
        self._ensure_request_size(body)
        request_body_hash = _canonical_sha256(body)
        request_material = json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        endpoint_cost_bound = self._endpoint_request_cost_bound(
            model=model,
            request_material=request_material,
        )
        if self.privacy.store_raw_prompts:
            self._store_debug(request_id, "prompt.json", body)
        attempts = 0
        usage_recorded = False
        accounted_cost_usd = 0.0
        active_reservation: Reservation | None = None
        active_network_attempted = False
        active_actual_cost: Decimal | None = None
        started_at = datetime.now(UTC)
        started_clock = time.perf_counter()
        initial_usage: dict[str, Any] = {}
        initial_cost: Decimal | None = None
        response_hash: str | None = None
        raw_payload: dict[str, Any] | None = None
        response_headers: Mapping[str, str] = {}

        async def finalize_active(actual_cost: Decimal | None) -> None:
            nonlocal accounted_cost_usd, active_reservation
            if active_reservation is None:
                return
            reservation = active_reservation
            active_reservation = None
            try:
                accounted_cost_usd += await self.budget.reconcile(
                    reservation,
                    actual_cost,
                )
            except Exception:
                accounted_cost_usd += (
                    reservation.estimated_cost_usd
                    if actual_cost is None
                    else max(0.0, float(actual_cost))
                )
                raise

        async def release_active() -> None:
            nonlocal active_reservation
            if active_reservation is None:
                return
            reservation = active_reservation
            active_reservation = None
            await self.budget.release(reservation)

        try:
            while True:
                attempts += 1
                active_reservation = await self.budget.reserve(
                    f"{request_id}:attempt:{attempts}",
                    role,
                    request_material,
                    endpoint_cost_bound=endpoint_cost_bound,
                )
                active_network_attempted = False
                active_actual_cost = None
                self.logger.info(
                    "Sending bounded structured model request",
                    extra={
                        "request_id": request_id,
                        "role": role,
                        "status": "started",
                    },
                )
                try:
                    active_network_attempted = True
                    response = await self._bounded_request(
                        "POST",
                        "/chat/completions",
                        json_body=body,
                        max_bytes=max(
                            1_000_000,
                            self.execution.max_output_tokens_per_request * 32,
                        ),
                    )
                except (httpx.TimeoutException, httpx.NetworkError):
                    await finalize_active(None)
                    if attempts >= self.execution.max_model_retries + 1:
                        raise OpenRouterTimeoutError("model request timed out") from None
                    await self._backoff(attempts, None)
                    continue
                except httpx.HTTPError:
                    await finalize_active(None)
                    raise OpenRouterSchemaError("model transport response was invalid") from None
                response_headers = response.headers
                try:
                    response_value = json.loads(
                        response.content,
                        parse_float=Decimal,
                    )
                except (UnicodeDecodeError, ValueError):
                    response_value = None
                if isinstance(response_value, dict):
                    self._ensure_no_credential_in_value(response_value)
                    raw_payload = response_value
                if response.status_code in {401, 403}:
                    await finalize_active(None)
                    raise OpenRouterAuthenticationError("OpenRouter rejected the API credentials")
                if response.status_code == 402:
                    await finalize_active(None)
                    raise BudgetExhaustedError("OpenRouter account budget rejected the request")
                if response.status_code == 404:
                    await finalize_active(None)
                    raise OpenRouterModelError(f"configured model is unavailable: {model}")
                if is_retryable_status(response.status_code):
                    await finalize_active(None)
                    if attempts >= self.execution.max_model_retries + 1:
                        if response.status_code == 429:
                            raise OpenRouterRateLimitError(
                                "OpenRouter rate limit exhausted the retry policy"
                            )
                        if response.status_code in {408, 425}:
                            raise OpenRouterTimeoutError(
                                f"transient model failure (HTTP {response.status_code})"
                            )
                        raise OpenRouterProviderUnavailableError(
                            f"provider unavailable after retries (HTTP {response.status_code})"
                        )
                    await self._backoff(attempts, response.headers.get("Retry-After"))
                    continue
                if response.status_code >= 400:
                    await finalize_active(None)
                    raise OpenRouterModelError(
                        f"model request rejected with HTTP {response.status_code}"
                    )
                break

            payload = response_value
            if not isinstance(payload, dict):
                raise OpenRouterSchemaError("model provider returned invalid JSON data")
            _raise_provider_payload_error(payload, requested_model=model)
            raw_content = _response_content_if_string(payload)
            if raw_content is not None:
                response_hash = hashlib.sha256(raw_content.encode()).hexdigest()
            envelope = _validate_completion_envelope(
                payload,
                response.headers,
                requested_model=model,
                provider_policy=self.provider_policy,
                endpoint_policy=endpoint_policy,
            )
            initial_usage = envelope.usage
            initial_cost = _optional_cost_decimal(initial_usage.get("cost"))
            assert initial_cost is not None
            active_actual_cost = initial_cost
            response_hash = hashlib.sha256(envelope.content.encode()).hexdigest()
            if self.privacy.store_raw_responses:
                self._store_debug(request_id, "response.json", payload)
            content = envelope.content
            parsed: ResponseT
            try:
                parsed = response_model.model_validate_json(content)
                _ensure_all_fields_supplied(parsed)
            except (ValidationError, ValueError):
                raise OpenRouterSchemaError("model returned invalid structured data") from None
            await finalize_active(active_actual_cost)
            ended_at = datetime.now(UTC)
            latency_ms = max(0, round((time.perf_counter() - started_clock) * 1_000))
            routing = self._routing_evidence(
                envelope=envelope,
                schema_hash=schema_hash,
                started_at=started_at,
                ended_at=ended_at,
                latency_ms=latency_ms,
                validation_status="valid",
                repair_used=False,
            )
            self.usage.add(
                UsageRecord(
                    request_id=request_id,
                    role=role,
                    execution_evidence=self.execution_evidence,
                    requested_model=model,
                    returned_model=envelope.returned_model,
                    provider=envelope.provider,
                    model_family=model_family(model),
                    timestamp=started_at,
                    prompt_tokens=_nonnegative_int(initial_usage.get("prompt_tokens")),
                    completion_tokens=_nonnegative_int(initial_usage.get("completion_tokens")),
                    total_tokens=_nonnegative_int(initial_usage.get("total_tokens")),
                    reported_cost_usd=float(initial_cost),
                    accounted_cost_usd=accounted_cost_usd,
                    routing=routing,
                    prompt_sha256=prompt_hash,
                    response_sha256=response_hash,
                    request_body_sha256=request_body_hash,
                    schema_sha256=schema_hash,
                    openrouter_generation_id=envelope.generation_id,
                    configured_provider_endpoints=list(self.provider_policy.configured_endpoints),
                    actual_provider_endpoint=envelope.selected_provider,
                    started_at=started_at,
                    ended_at=ended_at,
                    latency_ms=latency_ms,
                    finish_reason=envelope.finish_reason,
                    reasoning_tokens=_reasoning_tokens(initial_usage),
                    cached_tokens=_cached_tokens(initial_usage),
                    retry_count=attempts - 1,
                    validation_status=ModelRequestValidationStatus.VALID,
                    fallback_used=fallback_used
                    or envelope.router_attempt > 1
                    or envelope.router_attempt_count > 1,
                    substitution_detected=False,
                    status="success",
                    attempts=attempts,
                )
            )
            usage_recorded = True
            self.logger.info(
                "Structured model request completed",
                extra={
                    "request_id": request_id,
                    "role": role,
                    "status": "success",
                },
            )
            return parsed
        except Exception as exc:
            terminal_error = exc
            if active_reservation is not None:
                try:
                    if active_network_attempted:
                        await finalize_active(active_actual_cost)
                    else:
                        await release_active()
                except Exception as budget_error:
                    terminal_error = budget_error
            if not usage_recorded:
                ended_at = datetime.now(UTC)
                latency_ms = max(0, round((time.perf_counter() - started_clock) * 1_000))
                returned_model = (
                    _optional_string(raw_payload.get("model")) if raw_payload is not None else None
                )
                actual_provider = (
                    _optional_string(raw_payload.get("provider"))
                    if raw_payload is not None
                    else None
                )
                self.usage.add(
                    UsageRecord(
                        request_id=request_id,
                        role=role,
                        execution_evidence=self.execution_evidence,
                        requested_model=model,
                        returned_model=returned_model,
                        provider=actual_provider,
                        model_family=model_family(model),
                        timestamp=started_at,
                        prompt_tokens=_nonnegative_int(initial_usage.get("prompt_tokens")),
                        completion_tokens=_nonnegative_int(initial_usage.get("completion_tokens")),
                        total_tokens=_nonnegative_int(initial_usage.get("total_tokens")),
                        reported_cost_usd=(
                            float(initial_cost) if initial_cost is not None else None
                        ),
                        accounted_cost_usd=accounted_cost_usd,
                        routing=self._failure_routing_evidence(
                            payload=raw_payload,
                            response_headers=response_headers,
                            schema_hash=schema_hash,
                            started_at=started_at,
                            ended_at=ended_at,
                            latency_ms=latency_ms,
                            error=terminal_error,
                        ),
                        prompt_sha256=prompt_hash,
                        response_sha256=response_hash,
                        request_body_sha256=request_body_hash,
                        schema_sha256=schema_hash,
                        openrouter_generation_id=_response_generation_id(
                            raw_payload, response_headers
                        ),
                        configured_provider_endpoints=list(
                            self.provider_policy.configured_endpoints
                        ),
                        actual_provider_endpoint=actual_provider,
                        started_at=started_at,
                        ended_at=ended_at,
                        latency_ms=latency_ms,
                        finish_reason=_optional_finish_reason(raw_payload),
                        reasoning_tokens=_reasoning_tokens(initial_usage),
                        cached_tokens=_cached_tokens(initial_usage),
                        retry_count=max(0, attempts - 1),
                        provider_error_classification=_provider_error_classification(
                            terminal_error
                        ),
                        validation_status=_failure_validation_status(terminal_error),
                        fallback_used=fallback_used,
                        substitution_detected=(
                            returned_model is not None and returned_model != model
                        ),
                        status=_failure_status(terminal_error, model, raw_payload),
                        attempts=max(1, attempts),
                    )
                )
            self.logger.warning(
                "Structured model request failed",
                extra={
                    "request_id": request_id,
                    "role": role,
                    "status": type(terminal_error).__name__,
                },
            )
            if terminal_error is exc:
                raise
            raise terminal_error from exc

    def _endpoint_request_cost_bound(
        self,
        *,
        model: str,
        request_material: str,
    ) -> EndpointRequestCostBound | None:
        if not self.budget.require_endpoint_cost_bound:
            return None
        registered_policy = self._endpoint_pricing.get(model)
        if registered_policy is None:
            raise UnprovenCostBoundError("paid request lacks validated endpoint pricing")
        request_bytes = max(1, len(request_material.encode("utf-8")))
        output_tokens = self.execution.max_output_tokens_per_request
        reasoning_tokens = (
            self.reasoning.max_tokens
            if self.reasoning is not None and self.reasoning.max_tokens is not None
            else output_tokens
        )
        ceilings = {
            "completion": output_tokens,
            "image": 0,
            "input_cache_read": request_bytes,
            "input_cache_write": request_bytes,
            "internal_reasoning": max(output_tokens, reasoning_tokens),
            "prompt": request_bytes,
            "request": 1,
            "web_search": 0,
        }
        policy_prices: dict[str, str] = {}
        for field, price in registered_policy.routing_max_price:
            normalized = Decimal(str(price))
            if field in _PER_MILLION_ROUTER_PRICE_FIELDS:
                normalized /= Decimal(1_000_000)
            policy_prices[field] = format(normalized, "f")
        bounds: list[EndpointRequestCostBound] = []
        for registered in registered_policy.endpoints:
            if request_bytes > registered.max_prompt_tokens:
                raise UnprovenCostBoundError(
                    "serialized request byte ceiling exceeds an endpoint prompt-token limit"
                )
            if output_tokens > registered.max_completion_tokens:
                raise UnprovenCostBoundError(
                    "configured output ceiling exceeds an endpoint completion-token limit"
                )
            bounded_pricing = {**dict(registered.pricing), **policy_prices}
            bounds.append(
                EndpointRequestCostBound.from_endpoint_pricing(
                    exact_model_id=model,
                    provider_endpoint=registered.provider_endpoint,
                    request_material=request_material,
                    pricing=bounded_pricing,
                    maximum_units={field: ceilings[field] for field in bounded_pricing},
                )
            )
        return max(
            bounds,
            key=lambda bound: (bound.maximum_cost_usd, bound.provider_endpoint),
        )

    def _routing_evidence(
        self,
        *,
        envelope: CompletionEnvelope,
        schema_hash: str,
        started_at: datetime,
        ended_at: datetime,
        latency_ms: float,
        validation_status: str,
        repair_used: bool,
        repair_request: bool = False,
    ) -> dict[str, Any]:
        usage = envelope.usage
        endpoint_policy = self._endpoint_pricing.get(envelope.returned_model)
        endpoint_pricing = (
            endpoint_policy.endpoint(envelope.selected_provider)
            if endpoint_policy is not None
            else None
        )
        return {
            "generation_id": envelope.generation_id,
            "provider": envelope.provider,
            "selected_provider_endpoint": envelope.selected_provider,
            "selected_provider_name": envelope.selected_provider_name,
            "router_strategy": envelope.router_metadata["strategy"],
            "router_attempt": envelope.router_attempt,
            "router_attempt_count": envelope.router_attempt_count,
            "router_attempts_observed": envelope.router_attempts_observed,
            "router_metadata_sha256": _canonical_sha256(envelope.router_metadata),
            "router_pipeline": [dict(stage) for stage in envelope.pipeline],
            "finish_reason": envelope.finish_reason,
            "native_finish_reason": envelope.native_finish_reason,
            "reasoning_tokens": _reasoning_tokens(usage),
            "cached_tokens": _cached_tokens(usage),
            "schema_sha256": schema_hash,
            "provider_policy_sha256": _canonical_sha256(
                self.provider_policy.as_request_payload(require_zdr=self.privacy.require_zdr)
            ),
            "endpoint_snapshot_sha256": (
                endpoint_policy.snapshot_sha256 if endpoint_policy is not None else None
            ),
            "endpoint_pricing_sha256": (
                endpoint_pricing.pricing_sha256 if endpoint_pricing is not None else None
            ),
            "configured_provider_only": list(self.provider_policy.only),
            "configured_provider_order": list(self.provider_policy.order),
            "provider_fallbacks_allowed": self.provider_policy.allow_fallbacks,
            "certification_request": self.provider_policy.certification,
            "zdr_requested": self.privacy.require_zdr,
            "data_collection": "deny",
            "request_started_at": started_at.isoformat(),
            "request_ended_at": ended_at.isoformat(),
            "latency_ms": round(latency_ms, 3),
            "validation_status": validation_status,
            "repair_used": repair_used,
            "repair_request": repair_request,
        }

    def _failure_routing_evidence(
        self,
        *,
        payload: dict[str, Any] | None,
        response_headers: Mapping[str, str],
        schema_hash: str,
        started_at: datetime,
        ended_at: datetime,
        latency_ms: float,
        error: Exception,
    ) -> dict[str, Any]:
        router_metadata = payload.get("openrouter_metadata") if isinstance(payload, dict) else None
        finish_reason = _optional_finish_reason(payload)
        return {
            "generation_id": (_optional_string(payload.get("id")) if payload is not None else None),
            "generation_header_id": _header_value(response_headers, "x-generation-id"),
            "provider": (
                _optional_string(payload.get("provider")) if payload is not None else None
            ),
            "router_metadata_sha256": (
                _canonical_sha256(router_metadata) if isinstance(router_metadata, dict) else None
            ),
            "finish_reason": finish_reason,
            "schema_sha256": schema_hash,
            "provider_policy_sha256": _canonical_sha256(
                self.provider_policy.as_request_payload(require_zdr=self.privacy.require_zdr)
            ),
            "configured_provider_only": list(self.provider_policy.only),
            "configured_provider_order": list(self.provider_policy.order),
            "provider_fallbacks_allowed": self.provider_policy.allow_fallbacks,
            "certification_request": self.provider_policy.certification,
            "zdr_requested": self.privacy.require_zdr,
            "data_collection": "deny",
            "request_started_at": started_at.isoformat(),
            "request_ended_at": ended_at.isoformat(),
            "latency_ms": round(latency_ms, 3),
            "validation_status": "rejected",
            "provider_error_classification": _provider_error_classification(error),
        }

    async def _backoff(self, attempt: int, retry_after: str | None) -> None:
        delay: float
        try:
            delay = min(30.0, max(0.0, float(retry_after))) if retry_after else 0.0
        except ValueError:
            delay = 0.0
        if delay == 0:
            delay = min(30.0, (2 ** (attempt - 1)) + self._random.uniform(0, 0.5))
        await asyncio.sleep(delay)

    def _store_debug(self, request_id: str, filename: str, value: Any) -> None:
        if self.run_dir is None:
            raise OpenRouterPrivacyError("debug storage requested without a private run directory")
        self._ensure_no_credential_in_value(value)
        debug_dir = self.run_dir / "debug" / request_id
        debug_dir.mkdir(parents=True, exist_ok=True)
        path = debug_dir / filename
        path.write_text(
            json.dumps(
                value,
                sort_keys=True,
                indent=2,
                default=_debug_json_default,
            ),
            encoding="utf-8",
        )

    def _ensure_request_size(self, body: dict[str, Any]) -> None:
        self._ensure_no_credential_in_value(body)
        serialized = json.dumps(body, sort_keys=True, ensure_ascii=True)
        size = len(serialized.encode("utf-8"))
        if size > self.execution.max_request_bytes:
            raise OpenRouterRequestLimitError(
                f"serialized model request exceeds {self.execution.max_request_bytes} byte limit"
            )

    def _ensure_no_credential_in_value(self, value: Any) -> None:
        credential = bytes(self._credential).decode("utf-8")
        if credential and any(credential in item for item in _nested_string_values(value)):
            raise OpenRouterPrivacyError("operator credential appeared in provider data")


def _uses_closed_httpx_mock_transport(client: httpx.AsyncClient | None) -> bool:
    """Recognize only httpx's exact in-memory test transport as mock execution."""

    if client is None:
        return False
    return type(getattr(client, "_transport", None)) is httpx.MockTransport


def _owned_httpx_callables_are_pristine(
    client: httpx.AsyncClient,
    transport: object,
) -> bool:
    """Reject class or instance mutation of callables that can fabricate a response."""

    if type(client) is not httpx.AsyncClient or type(transport) is not httpx.AsyncHTTPTransport:
        return False
    try:
        client_values = vars(client)
        transport_values = vars(transport)
    except TypeError:
        return False
    return (
        "send" not in client_values
        and "request" not in client_values
        and "stream" not in client_values
        and "handle_async_request" not in transport_values
        and httpx.AsyncClient.send is _TRUSTED_ASYNC_CLIENT_SEND
        and httpx.AsyncClient.request is _TRUSTED_ASYNC_CLIENT_REQUEST
        and httpx.AsyncClient.stream is _TRUSTED_ASYNC_CLIENT_STREAM
        and (httpx.AsyncHTTPTransport.handle_async_request is _TRUSTED_ASYNC_HTTP_TRANSPORT_REQUEST)
    )


def _debug_json_default(value: Any) -> str:
    if isinstance(value, Decimal):
        return format(value, "f")
    raise TypeError("unsupported debug JSON value")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _routing_max_price(
    endpoints: tuple[_RegisteredEndpointPricing, ...],
) -> dict[str, float]:
    """Return provider-side price ceilings that cannot round below snapshot prices."""

    if not endpoints:
        raise OpenRouterCostControlError("endpoint pricing policy is empty")
    maxima: dict[str, Decimal] = {}
    for endpoint in endpoints:
        for field, raw_price in endpoint.pricing:
            if field in _UNENFORCEABLE_VARIABLE_PRICING_FIELDS:
                raise OpenRouterCostControlError(
                    "variable endpoint pricing component cannot be provider-capped"
                )
            if field not in _ROUTER_MAX_PRICE_FIELDS:
                if Decimal(raw_price) != 0:
                    raise OpenRouterCostControlError(
                        "nonzero endpoint pricing component cannot be provider-capped"
                    )
                continue
            price = Decimal(raw_price)
            maxima[field] = max(maxima.get(field, Decimal(0)), price)
    if not {"prompt", "completion"}.issubset(maxima):
        raise OpenRouterCostControlError(
            "endpoint pricing cannot produce provider-side prompt and completion caps"
        )
    result: dict[str, float] = {}
    for field in sorted(maxima):
        ceiling = maxima[field]
        if field in _PER_MILLION_ROUTER_PRICE_FIELDS:
            ceiling *= Decimal(1_000_000)
        candidate = float(ceiling)
        if not math.isfinite(candidate) or candidate < 0:
            raise OpenRouterCostControlError("endpoint price cannot be represented safely")
        while Decimal(str(candidate)) < ceiling:
            candidate = math.nextafter(candidate, math.inf)
        result[field] = candidate
    return result


def _is_model_slug(model: str) -> bool:
    return bool(_EXACT_MODEL_ID_PATTERN.fullmatch(model))


def _is_exact_model_id(model: str) -> bool:
    if not _is_model_slug(model):
        return False
    author, slug = model.casefold().split("/", 1)
    alias_parts = {part for part in re.split(r"[-_:.]", slug) if part}
    if author == "openrouter" and alias_parts & {"auto", "free", "random", "router"}:
        return False
    return not bool(alias_parts & {"auto", "latest", "random"})


def _require_exact_model_id(model: str) -> None:
    if not _is_exact_model_id(model):
        raise OpenRouterModelError(
            "model must be an exact author/model slug without auto, random, or latest routing"
        )


def _is_safe_metadata_pair(key: str, value: str) -> bool:
    return bool(
        isinstance(key, str)
        and isinstance(value, str)
        and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", key)
        and 0 < len(value.encode("utf-8")) <= 500
        and all(ord(character) >= 32 and ord(character) != 127 for character in value)
    )


def _header_value(headers: Mapping[str, str], name: str) -> str | None:
    lowered = name.casefold()
    for key, value in headers.items():
        if key.casefold() == lowered:
            return value
    return None


def _required_safe_string(value: Any, *, field: str, max_length: int = 500) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise OpenRouterSchemaError(f"model response has an invalid {field}")
    return value


def _response_content_if_string(payload: dict[str, Any]) -> str | None:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return None
    message = choices[0].get("message")
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    return content if isinstance(content, str) else None


def _raise_provider_payload_error(
    payload: dict[str, Any],
    *,
    requested_model: str,
) -> None:
    """Raise a closed typed error without retaining provider-controlled text."""

    value = payload.get("error")
    if value is None:
        return
    if not isinstance(value, dict):
        raise OpenRouterSchemaError("model provider returned malformed error data")
    code = value.get("code")
    normalized = (
        str(code).casefold() if isinstance(code, (int, str)) and not isinstance(code, bool) else ""
    )
    if normalized in {"401", "403", "authentication", "authentication_error", "unauthorized"}:
        raise OpenRouterAuthenticationError("OpenRouter rejected the API credentials")
    if normalized in {"402", "insufficient_credits", "payment_required"}:
        raise BudgetExhaustedError("OpenRouter account budget rejected the request")
    if normalized in {"404", "model_not_found", "not_found"}:
        raise OpenRouterModelError(f"configured model is unavailable: {requested_model}")
    if normalized in {"408", "425", "request_timeout", "timeout"}:
        raise OpenRouterTimeoutError("OpenRouter reported a provider timeout")
    if normalized in {"429", "rate_limit", "rate_limit_exceeded"}:
        raise OpenRouterRateLimitError("OpenRouter reported a provider rate limit")
    if normalized in {
        "500",
        "502",
        "503",
        "504",
        "provider_error",
        "provider_unavailable",
        "server_error",
        "service_unavailable",
    }:
        raise OpenRouterProviderUnavailableError(
            "OpenRouter reported that the approved provider was unavailable"
        )
    raise OpenRouterModelError("OpenRouter returned a rejected provider response")


def _validate_completion_envelope(
    payload: dict[str, Any],
    headers: Mapping[str, str],
    *,
    requested_model: str,
    provider_policy: OpenRouterProviderPolicy,
    endpoint_policy: _RegisteredEndpointPolicy | None,
) -> CompletionEnvelope:
    generation_id = _required_safe_string(payload.get("id"), field="generation ID")
    raw_header_generation_id = _header_value(headers, "x-generation-id")
    if raw_header_generation_id is not None:
        header_generation_id = _required_safe_string(
            raw_header_generation_id,
            field="X-Generation-Id header",
        )
        if generation_id != header_generation_id:
            raise OpenRouterSchemaError(
                "generation header does not match the response generation ID"
            )

    returned_model = _required_safe_string(payload.get("model"), field="returned model")
    if returned_model != requested_model:
        raise OpenRouterModelError(
            "provider returned an unrelated model or alias instead of the exact configured model"
        )
    response_provider = _optional_string(payload.get("provider"))
    if response_provider is not None:
        response_provider = _required_safe_string(
            response_provider,
            field="provider endpoint",
        )

    choices = payload.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise OpenRouterSchemaError("model response must contain exactly one choice")
    choice = choices[0]
    if choice.get("index") != 0:
        raise OpenRouterSchemaError("model response choice index is invalid")
    finish_reason = _required_safe_string(
        choice.get("finish_reason"),
        field="finish reason",
        max_length=100,
    )
    if finish_reason != "stop":
        if finish_reason.casefold() in _TRUNCATED_FINISH_REASONS:
            raise OpenRouterTruncatedResponseError("model response was incomplete or truncated")
        raise OpenRouterSchemaError("model response did not finish normally")
    native_finish_reason = _optional_string(choice.get("native_finish_reason"))

    message = choice.get("message")
    if not isinstance(message, dict) or message.get("role") != "assistant":
        raise OpenRouterSchemaError("model response omitted the assistant message role")
    if message.get("tool_calls") or message.get("function_call"):
        raise OpenRouterSchemaError("model response unexpectedly requested a tool")
    refusal = message.get("refusal")
    if refusal not in (None, ""):
        raise OpenRouterSchemaError("model response refused the structured request")
    content = message.get("content")
    if not isinstance(content, str):
        raise OpenRouterSchemaError("model response omitted structured text content")

    usage = _validate_usage(payload.get("usage"))
    (
        router_metadata,
        selected_provider,
        selected_provider_name,
        router_attempt,
        router_attempt_count,
        router_attempts_observed,
        pipeline,
    ) = _validate_router_metadata(
        payload.get("openrouter_metadata"),
        requested_model=requested_model,
        response_provider=response_provider,
        provider_policy=provider_policy,
        endpoint_policy=endpoint_policy,
    )
    provider = response_provider or selected_provider_name
    return CompletionEnvelope(
        generation_id=generation_id,
        returned_model=returned_model,
        provider=provider,
        finish_reason=finish_reason,
        native_finish_reason=native_finish_reason,
        content=content,
        usage=usage,
        router_metadata=router_metadata,
        selected_provider=selected_provider,
        selected_provider_name=selected_provider_name,
        router_attempt=router_attempt,
        router_attempt_count=router_attempt_count,
        router_attempts_observed=router_attempts_observed,
        pipeline=pipeline,
    )


def _validate_usage(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OpenRouterSchemaError("model response omitted usage accounting")
    fields: dict[str, int] = {}
    for field in ("prompt_tokens", "completion_tokens", "total_tokens"):
        item = value.get(field)
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            raise OpenRouterSchemaError("model response has invalid usage accounting")
        fields[field] = item
    if fields["total_tokens"] != fields["prompt_tokens"] + fields["completion_tokens"]:
        raise OpenRouterSchemaError("model response usage totals are inconsistent")
    if _optional_cost_decimal(value.get("cost")) is None:
        raise OpenRouterSchemaError("model response has invalid cost accounting")
    for detail_field, token_field in (
        ("completion_tokens_details", "reasoning_tokens"),
        ("prompt_tokens_details", "cached_tokens"),
    ):
        details = value.get(detail_field)
        if details is None:
            continue
        if not isinstance(details, dict):
            raise OpenRouterSchemaError("model response token details are invalid")
        token_count = details.get(token_field)
        if token_count is not None and (
            not isinstance(token_count, int) or isinstance(token_count, bool) or token_count < 0
        ):
            raise OpenRouterSchemaError("model response token details are invalid")
    reasoning_tokens = _reasoning_tokens(value)
    cached_tokens = _cached_tokens(value)
    if reasoning_tokens > fields["completion_tokens"] or cached_tokens > fields["prompt_tokens"]:
        raise OpenRouterSchemaError("model response token details are inconsistent")
    return value


def _validate_router_metadata(
    value: Any,
    *,
    requested_model: str,
    response_provider: str | None,
    provider_policy: OpenRouterProviderPolicy,
    endpoint_policy: _RegisteredEndpointPolicy | None,
) -> tuple[
    dict[str, Any],
    str,
    str,
    int,
    int,
    bool,
    tuple[dict[str, str], ...],
]:
    if not isinstance(value, dict):
        raise OpenRouterSchemaError("model response omitted OpenRouter routing metadata")
    if value.get("requested") != requested_model:
        raise OpenRouterModelError("router metadata does not bind the exact configured model")
    strategy = _required_safe_string(value.get("strategy"), field="router strategy")
    permitted_strategies = {"direct"}
    if provider_policy.allow_fallbacks:
        permitted_strategies.add("fallback")
    if strategy in _NON_DIRECT_ROUTING_STRATEGIES and strategy not in permitted_strategies:
        raise OpenRouterModelError("router used an unapproved model or fallback strategy")
    if strategy not in permitted_strategies:
        raise OpenRouterModelError("router used an unknown or unapproved routing strategy")
    router_attempt = value.get("attempt")
    if (
        not isinstance(router_attempt, int)
        or isinstance(router_attempt, bool)
        or router_attempt < 1
    ):
        raise OpenRouterSchemaError("router metadata has an invalid attempt number")
    if not provider_policy.allow_fallbacks and router_attempt != 1:
        raise OpenRouterProviderPolicyError("router attempted an unapproved provider fallback")

    endpoints = value.get("endpoints")
    if not isinstance(endpoints, dict):
        raise OpenRouterSchemaError("router metadata omitted endpoint evidence")
    available = endpoints.get("available")
    total = endpoints.get("total")
    if (
        not isinstance(available, list)
        or not available
        or any(not isinstance(item, dict) for item in available)
        or not isinstance(total, int)
        or isinstance(total, bool)
        or total < len(available)
    ):
        raise OpenRouterSchemaError("router metadata has invalid endpoint evidence")
    selected = [item for item in available if item.get("selected") is True]
    if len(selected) != 1:
        raise OpenRouterProviderPolicyError(
            "router metadata does not identify exactly one selected provider"
        )
    selected_model = _required_safe_string(selected[0].get("model"), field="selected model")
    selected_provider_name = _required_safe_string(
        selected[0].get("provider"),
        field="selected provider",
    )
    if selected_model != requested_model:
        raise OpenRouterModelError("selected provider used a different exact model")
    selected_provider = _resolve_provider_endpoint(
        selected_provider_name,
        provider_policy=provider_policy,
        endpoint_policy=endpoint_policy,
    )
    if response_provider is not None:
        response_provider_endpoint = _resolve_provider_endpoint(
            response_provider,
            provider_policy=provider_policy,
            endpoint_policy=endpoint_policy,
        )
        if response_provider_endpoint != selected_provider:
            raise OpenRouterProviderPolicyError(
                "selected provider does not match the response provider"
            )

    attempts = value.get("attempts")
    attempts_observed = attempts is not None
    if attempts is None:
        if router_attempt != 1:
            raise OpenRouterSchemaError(
                "router omitted provider-attempt evidence after multiple attempts"
            )
        if endpoint_policy is None:
            raise OpenRouterSchemaError(
                "router omitted provider-attempt evidence without an exact endpoint binding"
            )
        attempt_count = 1
    else:
        if (
            not isinstance(attempts, list)
            or len(attempts) != router_attempt
            or any(not isinstance(item, dict) for item in attempts)
        ):
            raise OpenRouterSchemaError("router metadata has invalid provider-attempt evidence")
        for index, attempt in enumerate(attempts):
            attempt_model = _required_safe_string(attempt.get("model"), field="attempt model")
            attempt_provider_name = _required_safe_string(
                attempt.get("provider"),
                field="attempt provider",
            )
            status = attempt.get("status")
            if (
                attempt_model != requested_model
                or not isinstance(status, int)
                or isinstance(status, bool)
                or not 100 <= status <= 599
            ):
                raise OpenRouterSchemaError("router metadata provider attempt is invalid")
            attempt_provider = _resolve_provider_endpoint(
                attempt_provider_name,
                provider_policy=provider_policy,
                endpoint_policy=endpoint_policy,
            )
            if index == len(attempts) - 1 and (
                status != 200 or attempt_provider != selected_provider
            ):
                raise OpenRouterSchemaError(
                    "router success attempt does not match selected provider"
                )
        if not provider_policy.allow_fallbacks and len(attempts) != 1:
            raise OpenRouterProviderPolicyError("router performed an unapproved provider fallback")
        attempt_count = len(attempts)

    raw_pipeline = value.get("pipeline", [])
    if not isinstance(raw_pipeline, list) or any(
        not isinstance(stage, dict) for stage in raw_pipeline
    ):
        raise OpenRouterSchemaError("router metadata pipeline is invalid")
    pipeline: list[dict[str, str]] = []
    for stage in raw_pipeline:
        stage_type = _required_safe_string(stage.get("type"), field="pipeline stage type")
        stage_name = _required_safe_string(stage.get("name"), field="pipeline stage name")
        pipeline.append({"type": stage_type, "name": stage_name})
    if provider_policy.certification and pipeline:
        raise OpenRouterProviderPolicyError(
            "certification forbids provider-side pipeline transformations"
        )
    return (
        value,
        selected_provider,
        selected_provider_name,
        router_attempt,
        attempt_count,
        attempts_observed,
        tuple(pipeline),
    )


def _resolve_provider_endpoint(
    provider_identity: str,
    *,
    provider_policy: OpenRouterProviderPolicy,
    endpoint_policy: _RegisteredEndpointPolicy | None,
) -> str:
    if endpoint_policy is not None:
        endpoint = endpoint_policy.endpoint(provider_identity)
        if endpoint is None:
            raise OpenRouterProviderPolicyError(
                "provider response identity is outside or ambiguous under the endpoint snapshot"
            )
        return endpoint.provider_endpoint
    configured = {
        provider.casefold(): provider for provider in provider_policy.configured_endpoints
    }
    if configured:
        configured_endpoint = configured.get(provider_identity.casefold())
        if configured_endpoint is None:
            raise OpenRouterProviderPolicyError(
                "selected provider is outside the configured endpoint policy"
            )
        return configured_endpoint
    return provider_identity


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _decoded_response_headers(headers: httpx.Headers) -> dict[str, str]:
    removed = {"content-encoding", "content-length", "transfer-encoding"}
    return {
        name: value
        for name, value in safe_headers(dict(headers)).items()
        if name.lower() not in removed
    }


def _nested_string_values(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str):
                yield key
            yield from _nested_string_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _nested_string_values(child)


def _optional_cost_decimal(value: Any) -> Decimal | None:
    if isinstance(value, bool) or not isinstance(value, (Decimal, int, float)):
        return None
    try:
        normalized = value if isinstance(value, Decimal) else Decimal(str(value))
    except (ArithmeticError, ValueError):
        return None
    if normalized.is_finite() and normalized >= 0:
        return normalized
    return None


def _nonnegative_int(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return 0


def _reasoning_tokens(usage: Mapping[str, Any]) -> int:
    direct = usage.get("reasoning_tokens")
    if isinstance(direct, int) and not isinstance(direct, bool) and direct >= 0:
        return direct
    details = usage.get("completion_tokens_details")
    if isinstance(details, dict):
        nested = details.get("reasoning_tokens")
        if isinstance(nested, int) and not isinstance(nested, bool) and nested >= 0:
            return nested
    return 0


def _cached_tokens(usage: Mapping[str, Any]) -> int:
    direct = usage.get("cached_tokens")
    if isinstance(direct, int) and not isinstance(direct, bool) and direct >= 0:
        return direct
    details = usage.get("prompt_tokens_details")
    if isinstance(details, dict):
        nested = details.get("cached_tokens")
        if isinstance(nested, int) and not isinstance(nested, bool) and nested >= 0:
            return nested
    return 0


def _usage_dict(payload: dict[str, Any]) -> dict[str, Any]:
    usage = payload.get("usage", {})
    return usage if isinstance(usage, dict) else {}


def _optional_finish_reason(payload: dict[str, Any] | None) -> str | None:
    if payload is None:
        return None
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return None
    return _optional_string(choices[0].get("finish_reason"))


def _response_generation_id(
    payload: dict[str, Any] | None,
    headers: Mapping[str, str],
) -> str | None:
    body_id = _optional_string(payload.get("id")) if payload is not None else None
    return body_id or _header_value(headers, "x-generation-id")


def _provider_error_classification(error: Exception) -> str:
    if isinstance(error, OpenRouterAuthenticationError):
        return "authentication"
    if isinstance(error, BudgetExhaustedError):
        return "budget"
    if isinstance(error, OpenRouterCostControlError):
        return "cost_control"
    if isinstance(error, OpenRouterTimeoutError):
        return "timeout"
    if isinstance(error, OpenRouterRateLimitError):
        return "rate_limit"
    if isinstance(error, OpenRouterProviderUnavailableError):
        return "provider_unavailable"
    if isinstance(error, OpenRouterProviderPolicyError):
        return "provider_policy"
    if isinstance(error, OpenRouterModelError):
        return "model"
    if isinstance(error, OpenRouterTruncatedResponseError):
        return "truncated_response"
    if isinstance(error, OpenRouterSchemaError):
        return "invalid_response"
    if isinstance(error, OpenRouterPrivacyError):
        return "privacy"
    if isinstance(error, OpenRouterRequestLimitError):
        return "request_limit"
    return "internal"


def _failure_validation_status(error: Exception) -> ModelRequestValidationStatus:
    if isinstance(error, OpenRouterTruncatedResponseError):
        return ModelRequestValidationStatus.TRUNCATED
    if isinstance(error, OpenRouterProviderPolicyError):
        return ModelRequestValidationStatus.PROVIDER_MISMATCH
    if isinstance(error, OpenRouterModelError):
        return ModelRequestValidationStatus.MODEL_MISMATCH
    if isinstance(error, OpenRouterSchemaError):
        return ModelRequestValidationStatus.INVALID_RESPONSE
    return ModelRequestValidationStatus.PROVIDER_ERROR


def _failure_status(
    error: Exception,
    requested_model: str,
    payload: dict[str, Any] | None,
) -> str:
    returned_model = _optional_string(payload.get("model")) if payload is not None else None
    if returned_model is not None and returned_model != requested_model:
        return "rejected_model_substitution"
    if isinstance(error, OpenRouterProviderPolicyError):
        return "rejected_provider_substitution"
    if isinstance(error, OpenRouterTruncatedResponseError):
        return "rejected_truncated_response"
    return f"failed:{type(error).__name__}"


def _ensure_all_fields_supplied(value: Any, path: str = "response") -> None:
    if isinstance(value, BaseModel):
        missing = sorted(set(type(value).model_fields) - value.model_fields_set)
        if missing:
            raise ValueError(f"{path} omitted required field(s): {', '.join(missing)}")
        for name in type(value).model_fields:
            _ensure_all_fields_supplied(getattr(value, name), f"{path}.{name}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _ensure_all_fields_supplied(item, f"{path}[{index}]")
