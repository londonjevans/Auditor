from __future__ import annotations

import json
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

import pytest
from typer.testing import CliRunner

import mmaudit.cli as cli_module
from mmaudit.config import AuditConfig
from mmaudit.models.endpoint_inventory import OpenRouterEndpointInventoryDiagnostic
from mmaudit.models.openrouter import OpenRouterModelError
from mmaudit.models.schemas import ExecutionEvidenceKind

RUNNER = CliRunner()
MODEL_ID = "alpha/atlas-secure"
ENDPOINT = "provider-alpha/fp8"
CANARY = "synthetic-endpoint-inventory-secret-canary"


def _endpoint(
    *,
    provider_name: str = "Provider Alpha",
    include_reasoning: bool = True,
) -> dict[str, Any]:
    endpoint: dict[str, Any] = {
        "tag": ENDPOINT,
        "slug": "provider-alpha",
        "provider_name": provider_name,
        "status": 0,
        "supported_parameters": [
            "max_tokens",
            "reasoning",
            "response_format",
            "structured_outputs",
            "temperature",
        ],
    }
    if include_reasoning:
        endpoint["reasoning"] = {"supported_efforts": ["medium", "high"]}
    return endpoint


def _catalog_payload() -> dict[str, Any]:
    return {
        "data": [
            {
                "id": MODEL_ID,
                "supported_parameters": [
                    "max_tokens",
                    "reasoning",
                    "response_format",
                    "structured_outputs",
                    "temperature",
                ],
                "reasoning": {"supported_efforts": ["low", "medium", "high"]},
            }
        ]
    }


def _secret_file(tmp_path: Path) -> Path:
    path = tmp_path / "operator-secrets.env"
    path.write_text(f"OPENROUTER_API_KEY={CANARY}\n", encoding="utf-8")
    path.chmod(0o600)
    return path


class _RecordedMetadataClient:
    instances: ClassVar[list[_RecordedMetadataClient]] = []
    provider_name = "Provider Alpha"
    authentication_error: Exception | None = None
    endpoint_error: Exception | None = None
    catalog_error: Exception | None = None
    zdr_error: Exception | None = None
    catalog_payload: dict[str, Any] | None = None
    include_endpoint_reasoning = True
    empty_endpoints = False
    empty_zdr = False

    def __init__(self, *, api_key: str, **kwargs: Any) -> None:
        assert api_key == CANARY
        self.kwargs = dict(kwargs)
        self.budget = kwargs["budget"]
        self.usage = kwargs["usage"]
        self.calls: list[str] = []
        self.closed = False
        type(self).instances.append(self)

    async def _request_metadata(self, _path: str) -> dict[str, Any]:
        raise AssertionError("recorded client does not use a private transport")

    async def validate_authentication(self) -> None:
        self.calls.append("authenticate")
        if self.authentication_error is not None:
            raise self.authentication_error

    async def list_model_endpoint_inventory(self, model_id: str) -> list[dict[str, Any]]:
        self.calls.append(f"endpoints:{model_id}")
        if self.endpoint_error is not None:
            raise self.endpoint_error
        return (
            []
            if self.empty_endpoints
            else [
                _endpoint(
                    provider_name=self.provider_name,
                    include_reasoning=self.include_endpoint_reasoning,
                )
            ]
        )

    async def get_certification_model_metadata(self) -> dict[str, Any]:
        self.calls.append("catalog")
        if self.catalog_error is not None:
            raise self.catalog_error
        return self.catalog_payload or _catalog_payload()

    async def get_zdr_endpoint_metadata(self) -> dict[str, Any]:
        self.calls.append("zdr")
        if self.zdr_error is not None:
            raise self.zdr_error
        if self.empty_zdr:
            return {"data": []}
        return {
            "data": [
                {
                    **_endpoint(
                        provider_name=self.provider_name,
                        include_reasoning=self.include_endpoint_reasoning,
                    ),
                    "model_id": MODEL_ID,
                }
            ]
        }

    async def close(self) -> None:
        self.calls.append("close")
        self.closed = True

    def clear_credentials(self) -> None:
        return None


@pytest.fixture(autouse=True)
def _reset_client_state() -> None:
    _RecordedMetadataClient.instances = []
    _RecordedMetadataClient.provider_name = "Provider Alpha"
    _RecordedMetadataClient.authentication_error = None
    _RecordedMetadataClient.endpoint_error = None
    _RecordedMetadataClient.catalog_error = None
    _RecordedMetadataClient.zdr_error = None
    _RecordedMetadataClient.catalog_payload = None
    _RecordedMetadataClient.include_endpoint_reasoning = True
    _RecordedMetadataClient.empty_endpoints = False
    _RecordedMetadataClient.empty_zdr = False


def _install_recorded_client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    config: AuditConfig,
) -> None:
    def trusted_execution_evidence(_client: object) -> ExecutionEvidenceKind:
        return ExecutionEvidenceKind.REAL

    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(cli_module, "OpenRouterClient", _RecordedMetadataClient)
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_CLIENT_TYPE",
        _RecordedMetadataClient,
    )
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_INIT_METHOD",
        _RecordedMetadataClient.__init__,
    )
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_INIT_METHOD_CODE",
        _RecordedMetadataClient.__init__.__code__,
    )
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_REQUEST_METADATA_METHOD",
        _RecordedMetadataClient._request_metadata,
    )
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_REQUEST_METADATA_METHOD_CODE",
        _RecordedMetadataClient._request_metadata.__code__,
    )
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_CLOSE_METHOD",
        _RecordedMetadataClient.close,
    )
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_CLOSE_METHOD_CODE",
        _RecordedMetadataClient.close.__code__,
    )
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_CLEAR_CREDENTIALS_METHOD",
        _RecordedMetadataClient.clear_credentials,
    )
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_CLEAR_CREDENTIALS_METHOD_CODE",
        _RecordedMetadataClient.clear_credentials.__code__,
    )
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_AUTHENTICATION_METHOD",
        _RecordedMetadataClient.validate_authentication,
    )
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_AUTHENTICATION_METHOD_CODE",
        _RecordedMetadataClient.validate_authentication.__code__,
    )
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_ENDPOINT_INVENTORY_METHOD",
        _RecordedMetadataClient.list_model_endpoint_inventory,
    )
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_ENDPOINT_INVENTORY_METHOD_CODE",
        _RecordedMetadataClient.list_model_endpoint_inventory.__code__,
    )
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_CERTIFICATION_MODEL_METADATA_METHOD",
        _RecordedMetadataClient.get_certification_model_metadata,
    )
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_CERTIFICATION_MODEL_METADATA_METHOD_CODE",
        _RecordedMetadataClient.get_certification_model_metadata.__code__,
    )
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_ZDR_METADATA_METHOD",
        _RecordedMetadataClient.get_zdr_endpoint_metadata,
    )
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_ZDR_METADATA_METHOD_CODE",
        _RecordedMetadataClient.get_zdr_endpoint_metadata.__code__,
    )
    monkeypatch.setattr(
        cli_module,
        "trusted_openrouter_execution_evidence",
        trusted_execution_evidence,
    )
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_EXECUTION_EVIDENCE",
        trusted_execution_evidence,
    )
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_EXECUTION_EVIDENCE_CODE",
        trusted_execution_evidence.__code__,
    )


def test_list_endpoints_emits_nonauthorizing_json_without_ledger_or_secret_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    ledger_path = tmp_path / "operator-cost-ledger.json"
    ledger_bytes = b'{"cap_usd":"250","entries":{},"schema_version":1}\n'
    ledger_path.write_bytes(ledger_bytes)
    config = config_factory(execution={"cost_ledger_path": str(ledger_path)})
    _install_recorded_client(monkeypatch, config=config)
    secret_file = _secret_file(tmp_path)

    def forbidden_ledger_open(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("endpoint enumeration opened the configured cost ledger")

    monkeypatch.setattr(
        cli_module.AtomicCostLedger,
        "open_existing",
        forbidden_ledger_open,
    )

    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "list-endpoints",
            "--model",
            MODEL_ID,
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--secrets-env-file",
            str(secret_file),
            "--json",
            "--no-color",
        ],
        terminal_width=240,
    )

    assert result.exit_code == 0, result.output
    json.loads(result.output)
    diagnostic = OpenRouterEndpointInventoryDiagnostic.model_validate_json(result.output)
    route = diagnostic.endpoints[0]
    assert route.selection_arguments == (
        f"{MODEL_ID}=provider-alpha",
        f"{MODEL_ID}={ENDPOINT}",
    )
    assert route.zdr_eligible is True
    assert route.structured_outputs_marker_present is True
    assert route.high_reasoning_effort_supported is True
    assert diagnostic.model_supported_reasoning_efforts == ("low", "medium", "high")
    assert route.effective_reasoning_effort_inventory_source == "ENDPOINT"
    assert route.effective_supported_reasoning_efforts == ("medium", "high")
    assert diagnostic.completion_requested is False
    assert diagnostic.cost_ledger_opened is False
    assert diagnostic.cost_ledger_mutated is False
    assert diagnostic.selection_authority is False
    assert CANARY not in result.output
    assert ledger_path.read_bytes() == ledger_bytes
    assert stat.S_IMODE(secret_file.stat().st_mode) == 0o600
    assert len(_RecordedMetadataClient.instances) == 1
    client = _RecordedMetadataClient.instances[0]
    assert client.calls == [
        "authenticate",
        f"endpoints:{MODEL_ID}",
        "catalog",
        "zdr",
        "close",
    ]
    assert client.closed is True
    assert client.budget.atomic_ledger is None
    assert client.usage.records == []


def test_list_endpoints_table_contains_direct_successor_argument(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    _install_recorded_client(monkeypatch, config=config_factory())
    secret_file = _secret_file(tmp_path)

    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "list-endpoints",
            "--model",
            MODEL_ID,
            "--secrets-env-file",
            str(secret_file),
            "--no-color",
        ],
        terminal_width=240,
    )

    assert result.exit_code == 0, result.output
    assert f"{MODEL_ID}={ENDPOINT}" in result.output
    assert "endpoint_structured_outputs=yes" in result.output
    assert "model_structured_outputs=yes" in result.output
    assert "effective_reasoning_effort_source=ENDPOINT" in result.output
    assert "completion_requested=false" in result.output
    assert "cost_ledger_opened=false" in result.output
    assert "selection_authority=false" in result.output
    assert CANARY not in result.output


def test_list_endpoints_reports_catalog_fallback_when_endpoint_inventory_is_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    _RecordedMetadataClient.include_endpoint_reasoning = False
    _install_recorded_client(monkeypatch, config=config_factory())

    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "list-endpoints",
            "--model",
            MODEL_ID,
            "--secrets-env-file",
            str(_secret_file(tmp_path)),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    diagnostic = OpenRouterEndpointInventoryDiagnostic.model_validate_json(result.output)
    route = diagnostic.endpoints[0]
    assert route.reasoning_effort_inventory_state == "UNAVAILABLE"
    assert diagnostic.model_reasoning_effort_inventory_state == "PUBLISHED"
    assert route.effective_reasoning_effort_inventory_source == "MODEL"
    assert route.effective_supported_reasoning_efforts == ("low", "medium", "high")
    assert route.effective_high_reasoning_effort_supported is True


def test_list_endpoints_retains_authenticated_empty_zdr_as_ineligible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    _RecordedMetadataClient.empty_zdr = True
    _install_recorded_client(monkeypatch, config=config_factory())

    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "list-endpoints",
            "--model",
            MODEL_ID,
            "--secrets-env-file",
            str(_secret_file(tmp_path)),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    diagnostic = OpenRouterEndpointInventoryDiagnostic.model_validate_json(result.output)
    assert diagnostic.endpoints[0].zdr_eligible is False


def test_list_endpoints_is_independent_of_execution_route_cardinality(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory(
        models={
            "provider_policy": {
                "only": ["provider-alpha", "provider-beta"],
                "order": [],
                "allow_fallbacks": True,
            }
        }
    )
    _install_recorded_client(monkeypatch, config=config)

    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "list-endpoints",
            "--model",
            MODEL_ID,
            "--secrets-env-file",
            str(_secret_file(tmp_path)),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    OpenRouterEndpointInventoryDiagnostic.model_validate_json(result.output)
    client = _RecordedMetadataClient.instances[0]
    assert client.calls == [
        "authenticate",
        f"endpoints:{MODEL_ID}",
        "catalog",
        "zdr",
        "close",
    ]
    assert "provider_policy" not in client.kwargs
    assert "reasoning_policy" not in client.kwargs
    assert client.usage.records == []


@pytest.mark.parametrize("empty_endpoints", (False, True))
def test_list_endpoints_unknown_or_empty_model_fails_closed_and_closes_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    empty_endpoints: bool,
) -> None:
    _RecordedMetadataClient.empty_endpoints = empty_endpoints
    if not empty_endpoints:
        _RecordedMetadataClient.endpoint_error = OpenRouterModelError(
            "requested exact model is unavailable"
        )
    _install_recorded_client(monkeypatch, config=config_factory())

    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "list-endpoints",
            "--model",
            MODEL_ID,
            "--secrets-env-file",
            str(_secret_file(tmp_path)),
        ],
    )

    assert result.exit_code != 0
    assert CANARY not in result.output
    client = _RecordedMetadataClient.instances[0]
    assert client.closed is True
    assert client.calls[-1] == "close"
    assert "zdr" not in client.calls


@pytest.mark.parametrize("failure_stage", ("authentication", "catalog", "zdr"))
def test_list_endpoints_closes_client_on_control_plane_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    failure_stage: str,
) -> None:
    error = OpenRouterModelError(f"synthetic {failure_stage} failure")
    if failure_stage == "authentication":
        _RecordedMetadataClient.authentication_error = error
    elif failure_stage == "catalog":
        _RecordedMetadataClient.catalog_error = error
    else:
        _RecordedMetadataClient.zdr_error = error
    _install_recorded_client(monkeypatch, config=config_factory())

    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "list-endpoints",
            "--model",
            MODEL_ID,
            "--secrets-env-file",
            str(_secret_file(tmp_path)),
            "--json",
        ],
    )

    assert result.exit_code != 0
    assert CANARY not in result.output
    client = _RecordedMetadataClient.instances[0]
    assert client.closed is True
    assert client.calls[-1] == "close"
    assert client.calls.count("close") == 1
    assert client.usage.records == []


@pytest.mark.parametrize(
    "invalid_model_id",
    (
        "Alpha/atlas-secure",
        "alpha-atlas-secure",
        "~alpha/atlas-secure",
        "auto/router",
        "alpha/atlas-secure:free",
        "alpha/atlas-secure:latest",
    ),
)
def test_list_endpoints_rejects_alias_before_config_secret_or_client_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalid_model_id: str,
) -> None:
    accesses: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> None:
        accesses.append("accessed")
        raise AssertionError("invalid model reached downstream state")

    monkeypatch.setattr(cli_module, "load_config", forbidden)
    monkeypatch.setattr(cli_module, "build_openrouter_runtime_controls", forbidden)
    monkeypatch.setattr(cli_module, "_budget_and_usage", forbidden)
    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden)
    monkeypatch.setattr(cli_module, "OpenRouterClient", forbidden)

    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "list-endpoints",
            "--model",
            invalid_model_id,
            "--secrets-env-file",
            str(tmp_path / "absent.env"),
        ],
    )

    assert result.exit_code != 0
    assert accesses == []
    assert "exact non-routed" in result.output


def test_list_endpoints_rejects_secret_reflection_before_rendering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    _RecordedMetadataClient.provider_name = f"Provider {CANARY}"
    _install_recorded_client(monkeypatch, config=config_factory())

    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "list-endpoints",
            "--model",
            MODEL_ID,
            "--secrets-env-file",
            str(_secret_file(tmp_path)),
        ],
    )

    assert result.exit_code != 0
    assert "reflected an operator credential" in result.output
    assert CANARY not in result.output
    assert _RecordedMetadataClient.instances[0].closed is True


def test_list_endpoints_rejects_catalog_secret_reflection_before_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    payload = _catalog_payload()
    payload["data"][0]["description"] = CANARY
    _RecordedMetadataClient.catalog_payload = payload
    _install_recorded_client(monkeypatch, config=config_factory())

    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "list-endpoints",
            "--model",
            MODEL_ID,
            "--secrets-env-file",
            str(_secret_file(tmp_path)),
            "--json",
        ],
    )

    assert result.exit_code != 0
    assert "reflected an operator credential" in result.output
    assert CANARY not in result.output
    assert _RecordedMetadataClient.instances[0].closed is True


@pytest.mark.parametrize(
    "method_name",
    (
        "__init__",
        "_request_metadata",
        "close",
        "clear_credentials",
        "validate_authentication",
        "list_model_endpoint_inventory",
        "get_certification_model_metadata",
        "get_zdr_endpoint_metadata",
    ),
)
def test_list_endpoints_rejects_same_identity_metadata_method_code_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    method_name: str,
) -> None:
    _install_recorded_client(monkeypatch, config=config_factory())
    method = getattr(_RecordedMetadataClient, method_name)
    original_code = method.__code__

    if method_name in {"__init__", "clear_credentials"}:

        def forged(*_args: object, **_kwargs: object) -> None:
            return None

    else:

        async def forged(*_args: object, **_kwargs: object) -> None:
            return None

    try:
        method.__code__ = forged.__code__
        result = RUNNER.invoke(
            cli_module.app,
            [
                "models",
                "list-endpoints",
                "--model",
                MODEL_ID,
                "--secrets-env-file",
                str(tmp_path / "absent.env"),
            ],
        )
    finally:
        method.__code__ = original_code

    assert result.exit_code != 0
    assert "endpoint enumeration requires" in result.output
    assert _RecordedMetadataClient.instances == []


def test_list_endpoints_help_documents_the_diagnostic_surface() -> None:
    result = RUNNER.invoke(cli_module.app, ["models", "list-endpoints", "--help"])

    assert result.exit_code == 0, result.output
    assert "--model" in result.output
    assert "--json" in result.output
    assert "completion" in result.output
