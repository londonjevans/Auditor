"""Exact provider-visible request shape for the committed synthetic smoke."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.orchestration.manifest import canonical_sha256

REAL_PROVIDER_SMOKE_ROLE = "real_provider_smoke"
REAL_PROVIDER_SMOKE_SCHEMA_NAME = "mmaudit_real_provider_smoke_v1"
REAL_PROVIDER_SMOKE_MARKER = "mmaudit-synthetic-provider-smoke-v1"
REAL_PROVIDER_SMOKE_RELATIVE_SOURCE_PATH = "src/ProviderSmoke.sol"
REAL_PROVIDER_SMOKE_REPOSITORY_SOURCE_PATH = (
    "tests/fixtures/solidity/provider_smoke/src/ProviderSmoke.sol"
)
REAL_PROVIDER_SMOKE_PACKAGE_SOURCE_PATH = (
    "src/mmaudit/resources/synthetic/provider_smoke/src/ProviderSmoke.sol"
)
REAL_PROVIDER_SMOKE_SOURCE_PATHS = frozenset(
    {
        REAL_PROVIDER_SMOKE_REPOSITORY_SOURCE_PATH,
        REAL_PROVIDER_SMOKE_PACKAGE_SOURCE_PATH,
    }
)
REAL_PROVIDER_SMOKE_RESPONSE_SCHEMA_SHA256 = (
    "5a60f25d52b29595e9ae16639e5ecef52b653154136758b9cb6bcbdd9e2e9f44"
)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SYSTEM_PROMPT = (
    "This is a synthetic transport validation with no repository or target data. "
    "Return only the strict response schema and do not use tools or external data."
)


class SyntheticProviderSmokeResponse(BaseModel):
    """Strict minimal response used only for synthetic provider transport validation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["OK"]
    marker: Literal["mmaudit-synthetic-provider-smoke-v1"]


def _build_provider_smoke_system_prompt(system_prompt: str) -> Callable[[], str]:
    def system_prompt_value() -> str:
        """Return the fixed system prompt for the committed synthetic smoke."""

        return system_prompt

    return system_prompt_value


provider_smoke_system_prompt = _build_provider_smoke_system_prompt(_SYSTEM_PROMPT)
del _build_provider_smoke_system_prompt


def _build_provider_smoke_user_prompt_builder(
    *,
    allowed_paths: frozenset[str],
    sha256: Callable[[bytes], Any],
) -> Callable[..., str]:
    def build(
        *,
        fixture_path: str,
        fixture_sha256: str,
        fixture_source: str,
    ) -> str:
        """Build the sole provider-visible prompt authorized for smoke egress."""

        if type(fixture_path) is not str or fixture_path not in allowed_paths:
            raise ValueError("provider smoke fixture path is not the exact committed source path")
        if type(fixture_sha256) is not str or _SHA256_PATTERN.fullmatch(fixture_sha256) is None:
            raise ValueError("provider smoke fixture SHA-256 is invalid")
        if type(fixture_source) is not str or not fixture_source:
            raise ValueError("provider smoke fixture source must be non-empty text")
        try:
            source_bytes = fixture_source.encode("utf-8", errors="strict")
        except UnicodeError:
            raise ValueError("provider smoke fixture source is not canonical UTF-8") from None
        if sha256(source_bytes).hexdigest() != fixture_sha256:
            raise ValueError("provider smoke fixture source differs from its SHA-256")
        return (
            "Set status to OK and marker to mmaudit-synthetic-provider-smoke-v1 after "
            "reading this committed synthetic Solidity transport fixture. Do not report "
            "findings.\n"
            f'<synthetic_source path="{fixture_path}" sha256="{fixture_sha256}">\n'
            f"{fixture_source}\n"
            "</synthetic_source>"
        )

    return build


build_provider_smoke_user_prompt = _build_provider_smoke_user_prompt_builder(
    allowed_paths=REAL_PROVIDER_SMOKE_SOURCE_PATHS,
    sha256=hashlib.sha256,
)
del _build_provider_smoke_user_prompt_builder


def _build_provider_smoke_request_commitment(
    *,
    trusted_role: str,
    trusted_system_prompt: str,
    trusted_response_model: type[BaseModel],
    trusted_schema_name: str,
    trusted_mode: StructuredOutputMode,
    trusted_response_schema_sha256: str,
    sha256: Callable[[bytes], Any],
    canonical_hash: Callable[[object], str],
) -> Callable[..., str]:
    def require_exact(
        *,
        request_role: str,
        system_prompt: str,
        user_prompt: str,
        response_model: type[BaseModel],
        schema_name: str,
        structured_output_mode: StructuredOutputMode,
        context_package: object | None,
    ) -> str:
        """Validate and commit the complete closed synthetic-smoke request shape."""

        if type(request_role) is not str or request_role != trusted_role:
            raise ValueError("provider smoke request role differs from the committed shape")
        if type(system_prompt) is not str or system_prompt != trusted_system_prompt:
            raise ValueError("provider smoke system prompt differs from the committed shape")
        if type(user_prompt) is not str:
            raise ValueError("provider smoke user prompt must be text")
        if response_model is not trusted_response_model:
            raise ValueError("provider smoke response model differs from the committed shape")
        if schema_name != trusted_schema_name:
            raise ValueError("provider smoke schema name differs from the committed shape")
        if structured_output_mode is not trusted_mode:
            raise ValueError(
                "provider smoke structured-output mode differs from the committed shape"
            )
        if context_package is not None:
            raise ValueError("provider smoke cannot carry repository context")

        system_digest = sha256(trusted_system_prompt.encode("utf-8"))
        user_digest = sha256(user_prompt.encode("utf-8"))
        provider_visible_prompt_sha256 = canonical_hash(
            [
                {"role": "system", "content": trusted_system_prompt},
                {"role": "user", "content": user_prompt},
            ]
        )
        return canonical_hash(
            {
                "schema_version": "1.0",
                "request_role": trusted_role,
                "system_prompt_sha256": system_digest.hexdigest(),
                "user_prompt_sha256": user_digest.hexdigest(),
                "response_schema_sha256": trusted_response_schema_sha256,
                "schema_name": trusted_schema_name,
                "structured_output_mode": trusted_mode.value,
                "provider_visible_prompt_sha256": provider_visible_prompt_sha256,
                "context_package": None,
            }
        )

    return require_exact


provider_smoke_request_commitment = _build_provider_smoke_request_commitment(
    trusted_role=REAL_PROVIDER_SMOKE_ROLE,
    trusted_system_prompt=_SYSTEM_PROMPT,
    trusted_response_model=SyntheticProviderSmokeResponse,
    trusted_schema_name=REAL_PROVIDER_SMOKE_SCHEMA_NAME,
    trusted_mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
    trusted_response_schema_sha256=REAL_PROVIDER_SMOKE_RESPONSE_SCHEMA_SHA256,
    sha256=hashlib.sha256,
    canonical_hash=canonical_sha256,
)
del _build_provider_smoke_request_commitment
