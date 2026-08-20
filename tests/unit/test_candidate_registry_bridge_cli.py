from __future__ import annotations

import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import mmaudit.cli as cli_module
from mmaudit.config import AuditConfig
from mmaudit.constants import ExitCode
from mmaudit.models.candidate_registry_bridge import write_candidate_registry_json
from mmaudit.models.discovery import (
    OpenRouterDiscoveryRunProvenance,
    OpenRouterModelDiscoveryEvidence,
    load_model_discovery_run,
)
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    load_candidate_registry,
    validate_candidate_registry_discovery,
)
from mmaudit.privacy import PrivacyProfile
from tests.unit import test_candidate_benchmark as fixtures

ROOT = Path(__file__).parents[2]
RUNNER = CliRunner()
MODEL_ID = "alpha/atlas-secure"
PROVIDER_ENDPOINT = "provider-alpha"
CANARY = "synthetic-registry-bridge-canary"


def _config(config_factory: Callable[..., AuditConfig]) -> AuditConfig:
    return config_factory(privacy={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK})


@pytest.mark.parametrize(
    "option",
    ("--candidate-registry-template", "--candidate-registry-output"),
)
def test_discover_registry_bridge_requires_paired_options_before_secret_access(
    option: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            f"{MODEL_ID}={PROVIDER_ENDPOINT}",
            option,
            str(tmp_path / "registry.json"),
            "--output-dir",
            str(tmp_path / "discovery"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "must be supplied together" in result.output
    assert not secret_accessed


def test_discover_registry_bridge_rejects_template_endpoint_drift_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            "deepcogito/cogito-v2.1-671b=provider-drift",
            "--candidate-registry-template",
            str(ROOT / "config" / "models.candidates.toml"),
            "--candidate-registry-output",
            str(tmp_path / "fresh-registry.json"),
            "--output-dir",
            str(tmp_path / "discovery"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "operator-approved template endpoint" in result.output
    assert not secret_accessed
    assert not (tmp_path / "fresh-registry.json").exists()


def test_discover_registry_bridge_rejects_output_inside_discovery_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    discovery = tmp_path / "discovery"
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            f"{MODEL_ID}={PROVIDER_ENDPOINT}",
            "--candidate-registry-template",
            str(tmp_path / "missing-template.json"),
            "--candidate-registry-output",
            str(discovery / "fresh-registry.json"),
            "--output-dir",
            str(discovery),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "outside the discovery directory" in " ".join(result.output.split())
    assert not secret_accessed
    assert not discovery.exists()


def test_discover_registry_bridge_publishes_exact_selected_registry_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    spec = fixtures._CandidateSpec(
        model_id=MODEL_ID,
        provider_endpoint=PROVIDER_ENDPOINT,
        provider_name="Provider Alpha",
    )
    _fixture_manifest, sealed_evidence, template = fixtures._discovery_and_registry(
        tmp_path=tmp_path / "fixture-discovery",
        config=config,
        specs=(spec,),
    )
    template_path = tmp_path / "template" / "candidate-template.json"
    write_candidate_registry_json(template_path, template)
    secret_file = tmp_path / "synthetic-secrets.env"
    secret_file.write_text(f"OPENROUTER_API_KEY={CANARY}\n", encoding="utf-8")
    secret_file.chmod(0o600)

    endpoint = fixtures._endpoint(spec)
    catalog_payload = {"data": [fixtures._catalog_model(spec)]}
    endpoint_payload = {
        "data": {
            "id": MODEL_ID,
            "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
        }
    }

    class ProviderFreeDiscoveryClient:
        def __init__(self, *, api_key: str, **_kwargs: object) -> None:
            assert api_key == CANARY

        async def validate_authentication(self) -> None:
            return None

        async def get_certification_model_metadata(self) -> dict[str, Any]:
            return catalog_payload

        async def list_zdr_endpoints(self) -> dict[str, Any]:
            return {"data": [endpoint]}

        async def get_model_metadata(self, model_id: str) -> dict[str, Any]:
            assert model_id == MODEL_ID
            return {"data": fixtures._catalog_model(spec)}

        async def get_model_endpoint_metadata(self, model_id: str) -> dict[str, Any]:
            assert model_id == MODEL_ID
            return endpoint_payload

        def seal_real_model_discovery_run(
            self,
            **kwargs: Any,
        ) -> tuple[
            OpenRouterDiscoveryRunProvenance,
            tuple[OpenRouterModelDiscoveryEvidence, ...],
        ]:
            assert tuple(item.exact_model_id for item in kwargs["payloads"]) == (MODEL_ID,)
            return sealed_evidence[0].provenance, sealed_evidence

        async def close(self) -> None:
            return None

    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(cli_module, "OpenRouterClient", ProviderFreeDiscoveryClient)
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_CLIENT_TYPE",
        ProviderFreeDiscoveryClient,
    )
    discovery_output = tmp_path / "private" / "fresh-discovery"
    registry_output = tmp_path / "private" / "fresh-registry.json"
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            f"{MODEL_ID}={PROVIDER_ENDPOINT}",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--secrets-env-file",
            str(secret_file),
            "--output-dir",
            str(discovery_output),
            "--candidate-registry-template",
            str(template_path),
            "--candidate-registry-output",
            str(registry_output),
            "--no-color",
        ],
    )

    assert result.exit_code == 0, result.output
    manifest, evidence = load_model_discovery_run(discovery_output)
    registry = load_candidate_registry(registry_output)
    validate_candidate_registry_discovery(
        registry=registry,
        run_manifest=manifest,
        evidence=evidence,
    )
    assert tuple(candidate.exact_model_id for candidate in registry.candidates) == (MODEL_ID,)
    assert registry.candidates[0].benchmark_status is CandidateBenchmarkStatus.PENDING
    assert stat.S_IMODE(registry_output.stat().st_mode) == 0o600
    assert CANARY not in result.output
