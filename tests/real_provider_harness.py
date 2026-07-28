"""Fail-closed environment gate for explicitly paid provider tests."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models.schemas import ModelIdentityStrength
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release_io import read_file_evidence, write_json_evidence
from mmaudit.reporting.json_report import stable_json

REAL_PROVIDER_OPT_IN = "MMAUDIT_RUN_REAL_PROVIDER_TESTS"
REAL_PROVIDER_SECRET_FILE = "MMAUDIT_SECRETS_ENV_FILE"
REAL_PROVIDER_COST_CAP = "MMAUDIT_REAL_PROVIDER_COST_CAP_USD"
REAL_PROVIDER_COST_LEDGER = "MMAUDIT_OPENROUTER_COST_LEDGER"
REAL_PROVIDER_MODEL = "MMAUDIT_REAL_PROVIDER_MODEL_ID"
REAL_PROVIDER_MODEL_ALLOWLIST = "MMAUDIT_REAL_PROVIDER_MODEL_ALLOWLIST"
REAL_PROVIDER_ENDPOINT_ALLOWLIST = "MMAUDIT_REAL_PROVIDER_ENDPOINT_ALLOWLIST"
REAL_PROVIDER_EVIDENCE_OUTPUT = "MMAUDIT_REAL_PROVIDER_EVIDENCE_OUTPUT"

_MAX_REMEDIATION_BUDGET_USD = Decimal("250.00")
_MONEY_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?\Z")
_MODEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_PROVIDER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_NON_EXACT_MODEL_NAMES = frozenset({"auto", "free", "latest", "random"})
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SAFE_REQUEST_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_SAFE_GENERATION_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$"
SMOKE_FIXTURE_PATH = "tests/fixtures/solidity/provider_smoke/src/ProviderSmoke.sol"
SMOKE_FIXTURE_SHA256 = "bbb0127919f734caedffb6f9143a634b6925ff4451985d1410a47e1637f1517b"
_PLACEHOLDER_TOKENS = frozenset(
    {"alpha", "dummy", "example", "fake", "placeholder", "synthetic", "test", "vendor"}
)


class RealProviderTestConfigurationError(ValueError):
    """Raised before secret loading or network access when opt-in is incomplete."""


@dataclass(frozen=True)
class RealProviderTestSettings:
    """Validated, non-secret settings for one exact paid provider smoke request."""

    secret_file: Path
    cost_ledger: Path
    cost_cap_usd: Decimal
    model_id: str
    model_allowlist: tuple[str, ...]
    provider_endpoint_allowlist: tuple[str, ...]
    evidence_output: Path


class SyntheticProviderSmokeResponse(BaseModel):
    """Strict minimal response used only for synthetic provider transport validation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["OK"]
    marker: Literal["mmaudit-synthetic-provider-smoke-v1"]


def real_provider_smoke_verification_subject_sha256(
    *,
    fixture_sha256: str,
    internal_request_id: str,
    openrouter_generation_id: str,
    requested_model_id: str,
    canonical_model_id: str,
    validated_response_sha256: str,
    prompt_sha256: str,
    schema_sha256: str,
    endpoint_snapshot_sha256: str,
    discovery_evidence_sha256: str,
) -> str:
    """Bind generation verification to the exact non-secret smoke result."""

    hash_values = (
        fixture_sha256,
        validated_response_sha256,
        prompt_sha256,
        schema_sha256,
        endpoint_snapshot_sha256,
        discovery_evidence_sha256,
    )
    if any(re.fullmatch(_SHA256_PATTERN, value) is None for value in hash_values):
        raise ValueError("smoke verification subject requires complete SHA-256 bindings")
    if re.fullmatch(_SAFE_REQUEST_ID_PATTERN, internal_request_id) is None:
        raise ValueError("smoke verification subject request ID is invalid")
    if re.fullmatch(_SAFE_GENERATION_ID_PATTERN, openrouter_generation_id) is None:
        raise ValueError("smoke verification subject generation ID is invalid")
    if any(
        _MODEL_PATTERN.fullmatch(value) is None
        for value in (requested_model_id, canonical_model_id)
    ):
        raise ValueError("smoke verification subject model ID is invalid")
    return canonical_sha256(
        {
            "schema_version": "1.0",
            "ticket_id": "V3-SMOKE-001",
            "fixture_sha256": fixture_sha256,
            "internal_request_id": internal_request_id,
            "openrouter_generation_id": openrouter_generation_id,
            "requested_model_id": requested_model_id,
            "canonical_model_id": canonical_model_id,
            "validated_response_sha256": validated_response_sha256,
            "prompt_sha256": prompt_sha256,
            "schema_sha256": schema_sha256,
            "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
            "discovery_evidence_sha256": discovery_evidence_sha256,
        }
    )


class _RealProviderSmokeEvidenceBody(BaseModel):
    """Bounded non-secret facts required to credit the real synthetic smoke."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    ticket_id: Literal["V3-SMOKE-001"]
    evidence_kind: Literal["real_openrouter_synthetic_smoke"]
    status: Literal["SUCCESS"]
    execution_evidence: Literal["real"]
    fixture_path: Literal["tests/fixtures/solidity/provider_smoke/src/ProviderSmoke.sol"]
    fixture_sha256: str = Field(pattern=_SHA256_PATTERN)
    internal_request_id: str = Field(pattern=_SAFE_REQUEST_ID_PATTERN)
    openrouter_generation_id: str = Field(pattern=_SAFE_GENERATION_ID_PATTERN)
    requested_model_id: str
    canonical_model_id: str
    returned_model_id: str
    generation_model_id: str
    approved_provider_endpoint: str
    actual_provider_endpoint: str
    actual_provider_name: str = Field(min_length=1, max_length=128)
    provider_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    endpoint_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    model_metadata_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_provenance_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    identity_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    generation_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    verification_subject_sha256: str = Field(pattern=_SHA256_PATTERN)
    prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    user_prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_body_sha256: str = Field(pattern=_SHA256_PATTERN)
    response_sha256: str = Field(pattern=_SHA256_PATTERN)
    validated_response_sha256: str = Field(pattern=_SHA256_PATTERN)
    started_at: datetime
    ended_at: datetime
    latency_ms: int = Field(ge=0)
    finish_reason: Literal["stop"]
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    reasoning_tokens: int = Field(ge=0)
    cached_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    actual_cost_usd: str
    accounted_cost_usd: str
    ledger_cap_usd: str
    ledger_spent_before_usd: str
    ledger_spent_usd: str
    smoke_spend_delta_usd: str
    ledger_active_reserved_usd: Literal["0"]
    ledger_remaining_usd: str
    validation_status: Literal["valid"]
    identity_strength: ModelIdentityStrength
    privacy_profile: Literal["STRICT_ZDR"]
    require_zdr: Literal[True]
    data_collection: Literal["deny"]
    allow_fallbacks: Literal[False]
    fallback_used: Literal[False]
    substitution_detected: Literal[False]
    raw_prompts_stored: Literal[False]
    raw_responses_stored: Literal[False]
    validated_output: SyntheticProviderSmokeResponse

    @field_validator(
        "requested_model_id",
        "canonical_model_id",
        "returned_model_id",
        "generation_model_id",
    )
    @classmethod
    def model_ids_are_exact(cls, value: str) -> str:
        if _MODEL_PATTERN.fullmatch(value) is None:
            raise ValueError("smoke evidence model ID must be exact")
        return value

    @field_validator("approved_provider_endpoint", "actual_provider_endpoint")
    @classmethod
    def provider_endpoints_are_safe(cls, value: str) -> str:
        if _PROVIDER_PATTERN.fullmatch(value) is None:
            raise ValueError("smoke evidence provider endpoint is invalid")
        return value

    @field_validator("actual_provider_name")
    @classmethod
    def provider_name_is_canonical(cls, value: str) -> str:
        if value != value.strip() or any(not character.isprintable() for character in value):
            raise ValueError("smoke evidence provider name is invalid")
        return value

    @field_validator(
        "actual_cost_usd",
        "accounted_cost_usd",
        "ledger_cap_usd",
        "ledger_spent_before_usd",
        "ledger_spent_usd",
        "smoke_spend_delta_usd",
        "ledger_active_reserved_usd",
        "ledger_remaining_usd",
    )
    @classmethod
    def money_is_canonical(cls, value: str) -> str:
        if _canonical_nonnegative_decimal(value) != value:
            raise ValueError("smoke evidence cost must be a canonical non-negative decimal")
        return value

    @model_validator(mode="after")
    def evidence_is_coherent(self) -> Self:
        if self.fixture_sha256 != SMOKE_FIXTURE_SHA256:
            raise ValueError("smoke fixture hash differs from the committed pinned fixture")
        aliases = {self.requested_model_id, self.canonical_model_id}
        if self.requested_model_id.split("/", 1)[0] != self.canonical_model_id.split("/", 1)[0]:
            raise ValueError("requested and canonical smoke models have different authors")
        if self.returned_model_id not in aliases:
            raise ValueError("returned smoke model is outside the frozen alias pair")
        if self.generation_model_id not in aliases:
            raise ValueError("generation model is outside the frozen alias pair")
        if self.actual_provider_endpoint != self.approved_provider_endpoint:
            raise ValueError("actual provider endpoint differs from the approved route")
        if self.identity_strength not in {
            ModelIdentityStrength.IMMUTABLE_VERSION_BOUND,
            ModelIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND,
        }:
            raise ValueError("identity_strength must be bound before smoke credit")
        expected_subject = real_provider_smoke_verification_subject_sha256(
            fixture_sha256=self.fixture_sha256,
            internal_request_id=self.internal_request_id,
            openrouter_generation_id=self.openrouter_generation_id,
            requested_model_id=self.requested_model_id,
            canonical_model_id=self.canonical_model_id,
            validated_response_sha256=self.validated_response_sha256,
            prompt_sha256=self.prompt_sha256,
            schema_sha256=self.schema_sha256,
            endpoint_snapshot_sha256=self.endpoint_snapshot_sha256,
            discovery_evidence_sha256=self.discovery_evidence_sha256,
        )
        if self.verification_subject_sha256 != expected_subject:
            raise ValueError("smoke verification subject hash is inconsistent")
        if self.ended_at < self.started_at:
            raise ValueError("smoke request ended before it started")
        if self.reasoning_tokens > self.completion_tokens:
            raise ValueError("smoke reasoning tokens exceed completion tokens")
        if self.cached_tokens > self.prompt_tokens:
            raise ValueError("smoke cached tokens exceed prompt tokens")
        if self.total_tokens != self.prompt_tokens + self.completion_tokens:
            raise ValueError("smoke total tokens do not reconcile")
        actual = Decimal(self.actual_cost_usd)
        accounted = Decimal(self.accounted_cost_usd)
        cap = Decimal(self.ledger_cap_usd)
        spent_before = Decimal(self.ledger_spent_before_usd)
        spent = Decimal(self.ledger_spent_usd)
        spend_delta = Decimal(self.smoke_spend_delta_usd)
        remaining = Decimal(self.ledger_remaining_usd)
        if accounted < actual:
            raise ValueError("smoke accounted cost is below actual cost")
        if spent < accounted:
            raise ValueError("ledger spent total is below the smoke accounted cost")
        if spent_before + spend_delta != spent or spend_delta != accounted:
            raise ValueError("smoke ledger spend delta does not reconcile")
        if spend_delta > Decimal("5"):
            raise ValueError("smoke spend exceeded its stage cap")
        if spent + remaining != cap:
            raise ValueError("smoke ledger totals do not reconcile")
        return self


class RealProviderSmokeEvidence(_RealProviderSmokeEvidenceBody):
    """Self-hashed successful real-provider smoke artifact."""

    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def evidence_is_self_hashed(self) -> Self:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected:
            raise ValueError("smoke evidence self-hash is inconsistent")
        return self


def real_provider_tests_enabled(environ: Mapping[str, str]) -> bool:
    """Require the exact opt-in sentinel; truthy alternatives are rejected."""

    return environ.get(REAL_PROVIDER_OPT_IN) == "1"


def load_pinned_synthetic_smoke_fixture(repository_root: Path) -> tuple[str, str]:
    """Read the exact committed smoke fixture without following or sharing links."""

    observed = read_file_evidence(
        evidence_root=repository_root,
        relative_path=SMOKE_FIXTURE_PATH,
        max_bytes=20_000,
    )
    if observed.binding.sha256 != SMOKE_FIXTURE_SHA256:
        raise ValueError("the synthetic provider fixture differs from its pinned hash")
    try:
        source = observed.content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("the synthetic provider fixture is not strict UTF-8") from exc
    if not source or "\x00" in source:
        raise ValueError("the synthetic provider fixture is empty or invalid")
    return source, observed.binding.sha256


def load_real_provider_test_settings(
    environ: Mapping[str, str],
) -> RealProviderTestSettings:
    """Validate every non-secret prerequisite before the secret file is opened."""

    if not real_provider_tests_enabled(environ):
        raise RealProviderTestConfigurationError(
            f"paid provider tests require {REAL_PROVIDER_OPT_IN}=1"
        )

    secret_file_text = _required_value(environ, REAL_PROVIDER_SECRET_FILE)
    secret_file = Path(secret_file_text)
    if not secret_file.is_absolute():
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_SECRET_FILE} must be an absolute operator-controlled path"
        )

    cost_text = _required_value(environ, REAL_PROVIDER_COST_CAP)
    if not _MONEY_PATTERN.fullmatch(cost_text):
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_COST_CAP} must be a plain positive decimal"
        )
    try:
        cost_cap = Decimal(cost_text)
    except InvalidOperation:
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_COST_CAP} must be a plain positive decimal"
        ) from None
    if cost_cap <= 0 or cost_cap > _MAX_REMEDIATION_BUDGET_USD:
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_COST_CAP} must be greater than zero and at most 250.00"
        )
    cost_ledger = Path(_required_value(environ, REAL_PROVIDER_COST_LEDGER))
    if not cost_ledger.is_absolute():
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_COST_LEDGER} must be an absolute operator-controlled path"
        )

    model_allowlist = _parse_allowlist(
        environ,
        REAL_PROVIDER_MODEL_ALLOWLIST,
        validator=_is_exact_non_placeholder_model,
        item_label="exact non-placeholder model ID",
    )
    model_id = _required_value(environ, REAL_PROVIDER_MODEL)
    if not _is_exact_non_placeholder_model(model_id):
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_MODEL} must be an exact non-placeholder author/model ID"
        )
    if model_id not in model_allowlist:
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_MODEL} must appear in {REAL_PROVIDER_MODEL_ALLOWLIST}"
        )

    provider_allowlist = _parse_allowlist(
        environ,
        REAL_PROVIDER_ENDPOINT_ALLOWLIST,
        validator=_is_exact_non_placeholder_provider,
        item_label="exact non-placeholder provider endpoint",
    )
    if len(provider_allowlist) != 1:
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_ENDPOINT_ALLOWLIST} must select exactly one provider endpoint"
        )
    evidence_output = Path(_required_value(environ, REAL_PROVIDER_EVIDENCE_OUTPUT))
    if not evidence_output.is_absolute():
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_EVIDENCE_OUTPUT} must be an absolute output path"
        )
    return RealProviderTestSettings(
        secret_file=secret_file,
        cost_ledger=cost_ledger,
        cost_cap_usd=cost_cap,
        model_id=model_id,
        model_allowlist=model_allowlist,
        provider_endpoint_allowlist=provider_allowlist,
        evidence_output=evidence_output,
    )


def seal_real_provider_smoke_evidence(
    value: Mapping[str, Any],
) -> RealProviderSmokeEvidence:
    """Validate smoke facts and bind their exact canonical public projection."""

    if "evidence_sha256" in value:
        raise ValueError("smoke evidence must be sealed exactly once")
    body = _RealProviderSmokeEvidenceBody.model_validate(dict(value))
    payload = body.model_dump(mode="json")
    return RealProviderSmokeEvidence.model_validate(
        {
            **payload,
            "evidence_sha256": canonical_sha256(payload),
        }
    )


def preflight_real_provider_smoke_output(
    *,
    output_path: Path,
    forbidden_paths: tuple[Path, ...],
) -> None:
    """Reject unsafe or colliding evidence destinations before provider spend."""

    if not output_path.is_absolute():
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_EVIDENCE_OUTPUT} must be an absolute fresh JSON file"
        )
    if (
        output_path.suffix != ".json"
        or output_path.name.startswith(("-", "."))
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json", output_path.name) is None
    ):
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_EVIDENCE_OUTPUT} must name a bounded JSON artifact"
        )
    normalized_output = Path(os.path.abspath(output_path))
    normalized_forbidden = {Path(os.path.abspath(path)) for path in forbidden_paths}
    if normalized_output in normalized_forbidden:
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_EVIDENCE_OUTPUT} collides with a protected input"
        )
    current = Path(normalized_output.anchor)
    try:
        for part in normalized_output.parent.parts[1:]:
            current /= part
            metadata = current.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or current.is_junction()
                or not stat.S_ISDIR(metadata.st_mode)
            ):
                raise RealProviderTestConfigurationError(
                    f"{REAL_PROVIDER_EVIDENCE_OUTPUT} traverses an unsafe parent"
                )
    except OSError as exc:
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_EVIDENCE_OUTPUT} parent is unavailable"
        ) from exc
    try:
        normalized_output.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_EVIDENCE_OUTPUT} could not be checked safely"
        ) from exc
    raise RealProviderTestConfigurationError(
        f"{REAL_PROVIDER_EVIDENCE_OUTPUT} must be a fresh destination"
    )


def write_real_provider_smoke_evidence(
    *,
    output_path: Path,
    evidence: RealProviderSmokeEvidence,
    forbidden_values: tuple[str, ...],
) -> ManifestFileBinding:
    """Write one fresh private artifact after a final secret-content scan."""

    preflight_real_provider_smoke_output(
        output_path=output_path,
        forbidden_paths=(),
    )
    serialized = stable_json(evidence)
    lowered = serialized.casefold()
    if "authorization" in lowered or "bearer " in lowered:
        raise ValueError("smoke evidence contains a forbidden authorization surface")
    if any(value and value in serialized for value in forbidden_values):
        raise ValueError("smoke evidence contains a forbidden value")
    return write_json_evidence(
        evidence_root=output_path.parent,
        relative_path=output_path.name,
        value=evidence,
        max_bytes=64_000,
    )


def _required_value(environ: Mapping[str, str], name: str) -> str:
    value = environ.get(name)
    if value is None or not value or value != value.strip():
        raise RealProviderTestConfigurationError(f"{name} is required and must be canonical")
    return value


def _parse_allowlist(
    environ: Mapping[str, str],
    name: str,
    *,
    validator: Callable[[str], bool],
    item_label: str,
) -> tuple[str, ...]:
    raw = _required_value(environ, name)
    values = tuple(item.strip() for item in raw.split(","))
    if (
        not values
        or any(not value for value in values)
        or len(values) != len(set(values))
        or any(not validator(value) for value in values)
    ):
        raise RealProviderTestConfigurationError(
            f"{name} must contain unique comma-separated {item_label}s"
        )
    return values


def _is_exact_non_placeholder_model(value: str) -> bool:
    if not _MODEL_PATTERN.fullmatch(value):
        return False
    author, model = value.split("/", 1)
    normalized_model = model.casefold()
    if normalized_model in _NON_EXACT_MODEL_NAMES or normalized_model.endswith(":latest"):
        return False
    return not _contains_placeholder_token(author) and not _contains_placeholder_token(model)


def _is_exact_non_placeholder_provider(value: str) -> bool:
    return bool(_PROVIDER_PATTERN.fullmatch(value)) and not _contains_placeholder_token(value)


def _contains_placeholder_token(value: str) -> bool:
    tokens = re.split(r"[^a-z0-9]+", value.casefold())
    return any(token in _PLACEHOLDER_TOKENS for token in tokens)


def _canonical_nonnegative_decimal(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", value) is None:
        raise ValueError("cost is not a canonical decimal")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError("cost is not a canonical decimal") from exc
    if not parsed.is_finite() or parsed < 0:
        raise ValueError("cost is not a canonical non-negative decimal")
    normalized = format(parsed, "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    return normalized or "0"
