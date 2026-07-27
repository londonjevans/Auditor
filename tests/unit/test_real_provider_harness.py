from __future__ import annotations

from collections.abc import Iterator, Mapping
from pathlib import Path

import pytest

from tests.real_provider_harness import (
    REAL_PROVIDER_COST_CAP,
    REAL_PROVIDER_COST_LEDGER,
    REAL_PROVIDER_ENDPOINT_ALLOWLIST,
    REAL_PROVIDER_MODEL,
    REAL_PROVIDER_MODEL_ALLOWLIST,
    REAL_PROVIDER_OPT_IN,
    REAL_PROVIDER_SECRET_FILE,
    RealProviderTestConfigurationError,
    load_real_provider_test_settings,
    real_provider_tests_enabled,
)


def _valid_environment() -> dict[str, str]:
    return {
        REAL_PROVIDER_OPT_IN: "1",
        REAL_PROVIDER_SECRET_FILE: "/operator/control/openrouter.env",
        REAL_PROVIDER_COST_CAP: "1.25",
        REAL_PROVIDER_COST_LEDGER: "/operator/control/openrouter-cost-ledger.json",
        REAL_PROVIDER_MODEL: "acme/secure-reasoner-v1",
        REAL_PROVIDER_MODEL_ALLOWLIST: (
            "acme/secure-reasoner-v1,second-author/security-reviewer-v2"
        ),
        REAL_PROVIDER_ENDPOINT_ALLOWLIST: "approved-provider",
    }


class _OptInOnlyEnvironment(Mapping[str, str]):
    """Raise if the guard examines any prerequisite before the opt-in."""

    def __getitem__(self, key: str) -> str:
        if key == REAL_PROVIDER_OPT_IN:
            return "0"
        raise AssertionError("non-opt-in environment value was accessed")

    def __iter__(self) -> Iterator[str]:
        return iter((REAL_PROVIDER_OPT_IN,))

    def __len__(self) -> int:
        return 1


@pytest.mark.parametrize("value", [None, "", "0", "true", "TRUE", " 1", "1 "])
def test_real_provider_opt_in_requires_exact_sentinel(value: str | None) -> None:
    environment = {} if value is None else {REAL_PROVIDER_OPT_IN: value}
    assert not real_provider_tests_enabled(environment)


def test_disabled_gate_stops_before_other_environment_access() -> None:
    with pytest.raises(RealProviderTestConfigurationError, match="require"):
        load_real_provider_test_settings(_OptInOnlyEnvironment())


@pytest.mark.parametrize("cost", ["", "0", "-1", "nan", "1e2", "250.01", "251"])
def test_real_provider_cost_cap_is_plain_bounded_decimal(cost: str) -> None:
    environment = _valid_environment()
    environment[REAL_PROVIDER_COST_CAP] = cost
    with pytest.raises(RealProviderTestConfigurationError, match="COST_CAP"):
        load_real_provider_test_settings(environment)


@pytest.mark.parametrize(
    "model",
    [
        "openrouter/auto",
        "openrouter/random",
        "acme/example-model",
        "acme/reasoner:latest",
        "missing-author",
    ],
)
def test_real_provider_model_must_be_exact_and_non_placeholder(model: str) -> None:
    environment = _valid_environment()
    environment[REAL_PROVIDER_MODEL] = model
    environment[REAL_PROVIDER_MODEL_ALLOWLIST] = model
    with pytest.raises(RealProviderTestConfigurationError, match="MODEL"):
        load_real_provider_test_settings(environment)


def test_selected_real_provider_model_must_be_allowlisted() -> None:
    environment = _valid_environment()
    environment[REAL_PROVIDER_MODEL] = "third-author/qualified-security-model"
    with pytest.raises(RealProviderTestConfigurationError, match="appear"):
        load_real_provider_test_settings(environment)


@pytest.mark.parametrize("path", ["", "relative-ledger.json"])
def test_real_provider_cost_ledger_must_be_explicit_and_absolute(path: str) -> None:
    environment = _valid_environment()
    environment[REAL_PROVIDER_COST_LEDGER] = path
    with pytest.raises(RealProviderTestConfigurationError, match="COST_LEDGER"):
        load_real_provider_test_settings(environment)


@pytest.mark.parametrize(
    "providers",
    ["", "Approved Provider,", "fake/provider", "One,One", "Provider-A,Provider-B"],
)
def test_real_provider_endpoint_allowlist_is_nonempty_exact_and_unique(
    providers: str,
) -> None:
    environment = _valid_environment()
    environment[REAL_PROVIDER_ENDPOINT_ALLOWLIST] = providers
    with pytest.raises(RealProviderTestConfigurationError, match="ENDPOINT_ALLOWLIST"):
        load_real_provider_test_settings(environment)


def test_real_provider_gate_returns_only_non_secret_settings() -> None:
    settings = load_real_provider_test_settings(_valid_environment())
    assert settings.cost_cap_usd.as_tuple().exponent == -2
    assert settings.cost_ledger == Path("/operator/control/openrouter-cost-ledger.json")
    assert settings.model_id == "acme/secure-reasoner-v1"
    assert settings.model_id in settings.model_allowlist
    assert settings.provider_endpoint_allowlist == ("approved-provider",)
    assert "API_KEY" not in repr(settings)
