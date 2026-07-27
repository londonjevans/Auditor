"""Fail-closed environment gate for explicitly paid provider tests."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path

REAL_PROVIDER_OPT_IN = "MMAUDIT_RUN_REAL_PROVIDER_TESTS"
REAL_PROVIDER_SECRET_FILE = "MMAUDIT_SECRETS_ENV_FILE"
REAL_PROVIDER_COST_CAP = "MMAUDIT_REAL_PROVIDER_COST_CAP_USD"
REAL_PROVIDER_COST_LEDGER = "MMAUDIT_OPENROUTER_COST_LEDGER"
REAL_PROVIDER_MODEL = "MMAUDIT_REAL_PROVIDER_MODEL_ID"
REAL_PROVIDER_MODEL_ALLOWLIST = "MMAUDIT_REAL_PROVIDER_MODEL_ALLOWLIST"
REAL_PROVIDER_ENDPOINT_ALLOWLIST = "MMAUDIT_REAL_PROVIDER_ENDPOINT_ALLOWLIST"

_MAX_REMEDIATION_BUDGET_USD = Decimal("250.00")
_MONEY_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?\Z")
_MODEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_PROVIDER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_NON_EXACT_MODEL_NAMES = frozenset({"auto", "free", "latest", "random"})
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


def real_provider_tests_enabled(environ: Mapping[str, str]) -> bool:
    """Require the exact opt-in sentinel; truthy alternatives are rejected."""

    return environ.get(REAL_PROVIDER_OPT_IN) == "1"


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
    return RealProviderTestSettings(
        secret_file=secret_file,
        cost_ledger=cost_ledger,
        cost_cap_usd=cost_cap,
        model_id=model_id,
        model_allowlist=model_allowlist,
        provider_endpoint_allowlist=provider_allowlist,
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
