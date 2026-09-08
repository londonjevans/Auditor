"""Development-only cost estimates; never provider-enforced cost proofs.

These calculations use a supplied metadata snapshot, not a live price guarantee.
No result from this module authorizes transport, qualification, or release.
"""

from __future__ import annotations

import hashlib
import json
import re
from decimal import ROUND_CEILING, Decimal, localcontext
from typing import Annotated, Any, Final, Literal, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from mmaudit.models.endpoint_snapshots import OpenRouterEndpointSnapshotEvidence
from mmaudit.models.route_constraints import (
    ExactRoutePricingSchedule,
    normalize_exact_route_pricing,
)

ESTIMATE_WARNING: Final = (
    "DEVELOPMENT ONLY: estimated costs may exceed reservations and the budget target. "
    "This is not a provider-enforced ceiling or qualification/release evidence."
)
MAX_DEVELOPMENT_REQUEST_BYTES = 4_000_000
_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_USD_QUANTUM = Decimal("0.000000000000000001")
_MINIMUM_ESTIMATE = Decimal("0.000001")
_DECIMAL_STRING_PATTERN = r"(?:0|[1-9][0-9]{0,3})(?:\.[0-9]{1,18})?"
_TEXT_FIELDS = frozenset(
    {
        "prompt",
        "completion",
        "input_cache_read",
        "input_cache_write",
        "request",
        "image",
        "web_search",
    }
)
_REQUEST_FIELDS = frozenset(
    {
        "model",
        "messages",
        "max_tokens",
        "temperature",
        "response_format",
        "reasoning",
        "provider",
        "stream",
    }
)


class DevelopmentCostError(ValueError):
    """A development estimate or its explicit opt-in is invalid."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, allow_inf_nan=False, revalidate_instances="always"
    )


class DevelopmentCostPolicy(_StrictModel):
    """Explicit target budgets, not hard guarantees; defaults keep retries off."""

    purpose: Literal["DEVELOPMENT_ONLY_ESTIMATED"] = "DEVELOPMENT_ONLY_ESTIMATED"
    overspend_risk_accepted: Literal[True]
    total_budget_usd: Decimal = Field(gt=0, le=250)
    per_attempt_budget_usd: Decimal = Field(gt=0, le=250)
    safety_multiplier: Decimal = Field(default=Decimal("2"), ge=2, le=10)
    maximum_attempts: int = Field(default=1, ge=1, le=32)
    uncertain_cost_policy: Literal["STOP", "CARRY_RESERVED_ESTIMATE"] = "STOP"

    @model_serializer(mode="wrap")
    def omit_default_uncertainty_policy(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, Any]:
        """Keep legacy bytes exact; a selected carry mode is always retained."""

        result: dict[str, Any] = handler(self)
        if self.uncertain_cost_policy == "STOP":
            result.pop("uncertain_cost_policy", None)
        return result

    @field_validator("overspend_risk_accepted", mode="before")
    @classmethod
    def explicit_boolean_acknowledgement(cls, value: Any) -> bool:
        if value is not True:
            raise ValueError(
                "development cost estimates require explicit overspend acknowledgement"
            )
        return True

    @field_validator(
        "total_budget_usd",
        "per_attempt_budget_usd",
        "safety_multiplier",
        mode="before",
        json_schema_input_type=Annotated[str, Field(pattern=f"^{_DECIMAL_STRING_PATTERN}$")],
    )
    @classmethod
    def exact_decimals_only(cls, value: Any) -> Decimal:
        if type(value) is Decimal:
            exponent = value.as_tuple().exponent
            if not value.is_finite() or type(exponent) is not int or exponent < -18:
                raise ValueError(
                    "development money requires finite values with at most 18 decimal places"
                )
            return value
        if type(value) is not str or not re.fullmatch(_DECIMAL_STRING_PATTERN, value):
            raise ValueError("development money and multiplier require exact decimal strings")
        return Decimal(value)

    @model_validator(mode="after")
    def attempt_target_fits_total(self) -> DevelopmentCostPolicy:
        if self.per_attempt_budget_usd > self.total_budget_usd:
            raise ValueError("per-attempt target exceeds total development budget target")
        return self


type DevelopmentPriceField = Literal[
    "prompt",
    "completion",
    "input_cache_read",
    "input_cache_write",
    "request",
    "image",
    "web_search",
]


class DevelopmentCostComponent(_StrictModel):
    """One observed rate and the deliberately conservative estimation allowance."""

    component: DevelopmentPriceField
    observed_unit_price_usd: Decimal = Field(ge=0, lt=Decimal("1000000000000"))
    estimated_unit_price_usd: Decimal = Field(ge=0, lt=Decimal("1000000000000"))
    estimated_units: int = Field(ge=0, le=MAX_DEVELOPMENT_REQUEST_BYTES)


class DevelopmentCostEstimate(_StrictModel):
    """Non-qualifying explanatory output, not an admission or execution capability."""

    artifact_kind: Literal["development_cost_estimate"] = "development_cost_estimate"
    policy: DevelopmentCostPolicy
    warning: Literal[
        "DEVELOPMENT ONLY: estimated costs may exceed reservations and the budget target. "
        "This is not a provider-enforced ceiling or qualification/release evidence."
    ] = ESTIMATE_WARNING
    request_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    endpoint_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_model_id: str
    provider_endpoint: str
    request_bytes: int = Field(gt=0, le=MAX_DEVELOPMENT_REQUEST_BYTES)
    maximum_completion_tokens: int = Field(gt=0, le=65_536)
    components: tuple[DevelopmentCostComponent, ...] = Field(min_length=2, max_length=7)
    estimated_cost_per_attempt_usd: Decimal = Field(gt=0)
    estimated_cost_all_attempts_usd: Decimal = Field(gt=0)
    within_estimated_budget: bool
    provider_enforced_ceiling: Literal[False] = False
    qualification_eligible: Literal[False] = False
    release_eligible: Literal[False] = False

    @field_validator(
        "provider_enforced_ceiling", "qualification_eligible", "release_eligible", mode="before"
    )
    @classmethod
    def no_authority(cls, value: Any) -> bool:
        if value is not False:
            raise ValueError("development estimates cannot acquire assurance authority")
        return False

    @model_validator(mode="after")
    def totals_are_consistent(self) -> DevelopmentCostEstimate:
        names = tuple(component.component for component in self.components)
        if names != tuple(sorted(set(names))) or not {"prompt", "completion"}.issubset(names):
            raise ValueError("development price components must be complete, unique and sorted")
        prompt = next(
            item.observed_unit_price_usd for item in self.components if item.component == "prompt"
        )
        for item in self.components:
            units = (
                1
                if item.component == "request"
                else 0
                if item.component in {"image", "web_search"}
                else self.maximum_completion_tokens
                if item.component == "completion"
                else self.request_bytes
            )
            rate = (
                max(item.observed_unit_price_usd, prompt)
                if item.component == "input_cache_write"
                else item.observed_unit_price_usd
            )
            if item.estimated_units != units or item.estimated_unit_price_usd != rate:
                raise ValueError(
                    "development estimate component differs from its conservative allowance"
                )
        per_attempt, all_attempts, within = _totals(self.components, self.policy)
        if (
            self.estimated_cost_per_attempt_usd,
            self.estimated_cost_all_attempts_usd,
            self.within_estimated_budget,
        ) != (per_attempt, all_attempts, within):
            raise ValueError("development estimate totals do not match their components and policy")
        return self


def _totals(
    components: tuple[DevelopmentCostComponent, ...], policy: DevelopmentCostPolicy
) -> tuple[Decimal, Decimal, bool]:
    with localcontext() as context:
        context.prec = 160
        observed = sum(
            (item.estimated_unit_price_usd * item.estimated_units for item in components),
            start=Decimal(0),
        )
        per_attempt = max(
            _MINIMUM_ESTIMATE,
            (observed * policy.safety_multiplier).quantize(_USD_QUANTUM, rounding=ROUND_CEILING),
        )
        all_attempts = per_attempt * policy.maximum_attempts
        within = (
            per_attempt <= policy.per_attempt_budget_usd and all_attempts <= policy.total_budget_usd
        )
        return per_attempt, all_attempts, within


def estimate_development_request(
    *,
    policy: DevelopmentCostPolicy,
    endpoint_snapshot: OpenRouterEndpointSnapshotEvidence,
    request_id: str,
    request_body: dict[str, Any],
) -> DevelopmentCostEstimate:
    """Estimate a pinned, text-only request without weakening strict pricing projection.

    Full serialized UTF-8 bytes stand in for input tokens. Every input/cache price is
    counted at that population; cache writes reserve at least the prompt rate even
    when metadata quotes zero. Maximum rates across all retained tiers are used.
    Completion tokens include reasoning. Repricing and unreported fees can still
    exceed this estimate, despite its safety multiplier.
    """

    if (
        type(policy) is not DevelopmentCostPolicy
        or type(endpoint_snapshot) is not OpenRouterEndpointSnapshotEvidence
    ):
        raise DevelopmentCostError(
            "development estimation requires exact policy and snapshot types"
        )
    policy = DevelopmentCostPolicy.model_validate_json(policy.model_dump_json())
    snapshot = OpenRouterEndpointSnapshotEvidence.model_validate_json(
        endpoint_snapshot.model_dump_json()
    )
    if type(request_id) is not str or not _REQUEST_ID.fullmatch(request_id):
        raise DevelopmentCostError("development request identifier is invalid")
    if len(snapshot.endpoints) != 1 or snapshot.provider_policy_mode != "only":
        raise DevelopmentCostError("development estimates require one exact provider endpoint")
    endpoint = snapshot.endpoints[0]
    if endpoint.operational is not True or endpoint.zdr_eligible is not True:
        raise DevelopmentCostError("development estimates retain operational and ZDR requirements")
    if type(request_body) is not dict:
        raise DevelopmentCostError("development request must be a JSON object")
    try:
        material = json.dumps(
            request_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
        if len(material) > MAX_DEVELOPMENT_REQUEST_BYTES:
            raise DevelopmentCostError("development request exceeds its byte limit")
        # Validate exactly the detached bytes whose size and digest are estimated.
        request_body = json.loads(material)
    except (ValueError, TypeError, UnicodeError, RecursionError, RuntimeError) as exc:
        raise DevelopmentCostError("development request is not bounded finite JSON") from exc
    if not set(request_body).issubset(_REQUEST_FIELDS):
        raise DevelopmentCostError(
            "development estimates allow only bounded text requests without tools or search"
        )
    expected_provider = {
        "only": [endpoint.provider_endpoint],
        "allow_fallbacks": False,
        "require_parameters": True,
        "data_collection": "deny",
        "zdr": True,
    }
    provider = request_body.get("provider")
    if (
        type(provider) is not dict
        or provider != expected_provider
        or any(
            type(provider.get(key)) is not bool
            for key in ("allow_fallbacks", "require_parameters", "zdr")
        )
    ):
        raise DevelopmentCostError(
            "development request must pin its exact route and retain privacy controls"
        )
    if request_body.get("model") != snapshot.exact_model_id or ":online" in snapshot.exact_model_id:
        raise DevelopmentCostError(
            "development request model differs from the exact text-only snapshot"
        )
    if request_body.get("stream", False) is not False:
        raise DevelopmentCostError("development estimate does not support streaming")
    output_tokens = request_body.get("max_tokens")
    if type(output_tokens) is not int or not 1 <= output_tokens <= min(
        65_536, endpoint.max_completion_tokens
    ):
        raise DevelopmentCostError(
            "development completion limit is missing or exceeds the endpoint limit"
        )
    messages = request_body.get("messages")
    if (
        type(messages) is not list
        or not 1 <= len(messages) <= 128
        or any(
            type(message) is not dict
            or set(message) != {"role", "content"}
            or message["role"] not in ("system", "user", "assistant")
            or type(message["content"]) is not str
            or not message["content"]
            for message in messages
        )
    ):
        raise DevelopmentCostError("development request requires bounded text-only messages")
    if not 0 < len(material) <= min(MAX_DEVELOPMENT_REQUEST_BYTES, endpoint.max_prompt_tokens):
        raise DevelopmentCostError("development request exceeds its conservative byte/input limit")
    if len(material) + output_tokens > endpoint.context_length:
        raise DevelopmentCostError("development request exceeds its conservative context limit")
    pricing = normalize_exact_route_pricing(endpoint.pricing)
    schedule = endpoint.tiered_pricing_cost_projection
    if schedule == "unavailable":
        raise DevelopmentCostError("development price schedule is unavailable")
    if isinstance(schedule, ExactRoutePricingSchedule):
        pricing = schedule.maximum_pricing
    rates = {item.component.value: Decimal(item.unit_price) for item in pricing}
    if not set(rates).issubset(_TEXT_FIELDS):
        raise DevelopmentCostError("development pricing contains an unsupported charging unit")
    components = tuple(
        DevelopmentCostComponent(
            component=cast(DevelopmentPriceField, name),
            observed_unit_price_usd=price,
            estimated_unit_price_usd=max(price, rates["prompt"])
            if name == "input_cache_write"
            else price,
            estimated_units=(
                1
                if name == "request"
                else 0
                if name in {"image", "web_search"}
                else output_tokens
                if name == "completion"
                else len(material)
            ),
        )
        for name, price in sorted(rates.items())
    )
    per_attempt, all_attempts, within = _totals(components, policy)
    return DevelopmentCostEstimate(
        policy=policy,
        request_id=request_id,
        request_sha256=hashlib.sha256(material).hexdigest(),
        endpoint_snapshot_sha256=snapshot.snapshot_sha256,
        exact_model_id=snapshot.exact_model_id,
        provider_endpoint=endpoint.provider_endpoint,
        request_bytes=len(material),
        maximum_completion_tokens=output_tokens,
        components=components,
        estimated_cost_per_attempt_usd=per_attempt,
        estimated_cost_all_attempts_usd=all_attempts,
        within_estimated_budget=within,
    )
