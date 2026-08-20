from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict

import mmaudit.models.openrouter as openrouter_module
import mmaudit.models.provider_smoke as provider_smoke_module
from mmaudit.models.openrouter import OpenRouterClient
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.provider_smoke import (
    REAL_PROVIDER_SMOKE_REPOSITORY_SOURCE_PATH,
    REAL_PROVIDER_SMOKE_ROLE,
    REAL_PROVIDER_SMOKE_SCHEMA_NAME,
    SyntheticProviderSmokeResponse,
    build_provider_smoke_user_prompt,
    provider_smoke_system_prompt,
)
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.privacy import (
    PrivacyProfile,
    PrivacySourceClassification,
    resolve_effective_privacy_policy,
)
from mmaudit.repository.discovery import DiscoveredFile, DiscoveryResult
from mmaudit.repository.privacy_provenance import prove_privacy_source_classification

_ROOT = Path(__file__).parents[2]
_TARGET = _ROOT / "tests/fixtures/solidity/provider_smoke"
_SOURCE = _TARGET / "src/ProviderSmoke.sol"
_NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)


class _WrongResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    answer: str


def _discovery() -> tuple[DiscoveryResult, str, str]:
    source_bytes = _SOURCE.read_bytes()
    source_text = source_bytes.decode("utf-8", errors="strict")
    fixture_sha256 = hashlib.sha256(source_bytes).hexdigest()
    discovery = DiscoveryResult(
        root=_TARGET.resolve(strict=True),
        files=(
            DiscoveredFile(
                absolute_path=_SOURCE.resolve(strict=True),
                relative_path="src/ProviderSmoke.sol",
                content=source_text,
                size=len(source_bytes),
                lines=source_bytes.count(b"\n"),
                sha256=fixture_sha256,
                language="Solidity",
                categories=("smart_contract",),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    source_sha256 = canonical_sha256(
        [
            {
                "path": discovery.files[0].relative_path,
                "sha256": discovery.files[0].sha256,
                "size": discovery.files[0].size,
            }
        ]
    )
    return discovery, source_sha256, source_text


def _client_context(
    *,
    classification: PrivacySourceClassification = PrivacySourceClassification.SYNTHETIC_COMMITTED,
) -> tuple[OpenRouterClient, dict[str, Any]]:
    discovery, source_sha256, source_text = _discovery()
    observation = prove_privacy_source_classification(
        discovery,
        requested_classification=classification,
        source_sha256=source_sha256,
        now=_NOW,
    )
    policy = resolve_effective_privacy_policy(
        profile=(
            PrivacyProfile.SYNTHETIC_BENCHMARK
            if classification is PrivacySourceClassification.SYNTHETIC_COMMITTED
            else PrivacyProfile.STRICT_ZDR
        ),
        require_zdr=True,
        consent_observation=None,
        source_sha256=source_sha256,
        source_classification=classification,
        source_provenance_observation=observation,
        configured_model_ids=("qwen/qwen3.6-35b-a3b",),
        configured_provider_endpoints=("akashml/fp8",),
        requested_budget_usd=Decimal("5.00"),
        now=_NOW,
    )
    client = object.__new__(OpenRouterClient)
    client.effective_privacy_policy = policy
    client._privacy_source_provenance_observation = observation
    shape: dict[str, Any] = {
        "system_prompt": provider_smoke_system_prompt(),
        "user_prompt": build_provider_smoke_user_prompt(
            fixture_path=REAL_PROVIDER_SMOKE_REPOSITORY_SOURCE_PATH,
            fixture_sha256=discovery.files[0].sha256,
            fixture_source=source_text,
        ),
        "response_model": SyntheticProviderSmokeResponse,
        "schema_name": REAL_PROVIDER_SMOKE_SCHEMA_NAME,
        "structured_output_mode": StructuredOutputMode.NATIVE_JSON_SCHEMA,
        "context_package": None,
    }
    return client, shape


def test_committed_smoke_authority_accepts_only_the_exact_closed_request_shape() -> None:
    client, shape = _client_context()

    assert client._is_trusted_prequalification_request(REAL_PROVIDER_SMOKE_ROLE, **shape)

    invalid_shapes = (
        {**shape, "user_prompt": f"{shape['user_prompt']}\nprivate operator text"},
        {**shape, "system_prompt": "different system"},
        {**shape, "response_model": _WrongResponse},
        {**shape, "schema_name": "different_schema"},
        {**shape, "structured_output_mode": StructuredOutputMode.JSON_OBJECT},
        {**shape, "context_package": object()},
    )
    for invalid_shape in invalid_shapes:
        assert not client._is_trusted_prequalification_request(
            REAL_PROVIDER_SMOKE_ROLE,
            **invalid_shape,
        )
    assert not client._is_trusted_prequalification_request("source_audit", **shape)


def test_private_source_cannot_authorize_the_exact_smoke_request() -> None:
    client, shape = _client_context(
        classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE
    )

    assert not client._is_trusted_prequalification_request(REAL_PROVIDER_SMOKE_ROLE, **shape)


def test_provider_smoke_module_reassignment_cannot_bless_an_appended_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        provider_smoke_module,
        "provider_smoke_request_commitment",
        lambda **_kwargs: "0" * 64,
    )
    monkeypatch.setattr(
        provider_smoke_module,
        "build_provider_smoke_user_prompt",
        lambda **_kwargs: "arbitrary private prompt",
    )
    monkeypatch.setattr(
        provider_smoke_module,
        "SyntheticProviderSmokeResponse",
        _WrongResponse,
    )
    client, shape = _client_context()

    assert client._is_trusted_prequalification_request(REAL_PROVIDER_SMOKE_ROLE, **shape)
    assert not client._is_trusted_prequalification_request(
        REAL_PROVIDER_SMOKE_ROLE,
        **{**shape, "user_prompt": f"{shape['user_prompt']}\nprivate operator text"},
    )


def test_normal_audit_roles_still_require_postqualification_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, shape = _client_context()
    monkeypatch.setattr(
        openrouter_module,
        "trusted_openrouter_execution_evidence",
        lambda _client: ExecutionEvidenceKind.REAL,
    )

    assert not client._requires_real_audit_policy_selection(
        REAL_PROVIDER_SMOKE_ROLE,
        **shape,
    )
    assert client._requires_real_audit_policy_selection("source_audit", **shape)


def test_smoke_prompt_builder_rejects_path_or_byte_drift() -> None:
    discovery, _source_sha256, source_text = _discovery()
    fixture_sha256 = discovery.files[0].sha256

    with pytest.raises(ValueError, match="exact committed source path"):
        build_provider_smoke_user_prompt(
            fixture_path="private/operator/source.sol",
            fixture_sha256=fixture_sha256,
            fixture_source=source_text,
        )
    with pytest.raises(ValueError, match="differs from its SHA-256"):
        build_provider_smoke_user_prompt(
            fixture_path=REAL_PROVIDER_SMOKE_REPOSITORY_SOURCE_PATH,
            fixture_sha256=fixture_sha256,
            fixture_source=f"{source_text}\nprivate operator text",
        )
