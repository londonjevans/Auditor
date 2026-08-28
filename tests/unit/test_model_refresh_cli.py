from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import mmaudit.cli as cli_module
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.openrouter import OpenRouterAuthenticationError
from mmaudit.models.policy_eligibility import (
    PolicyReviewReason,
    build_model_policy_eligibility_artifact,
    build_policy_eligibility_route,
)
from mmaudit.models.policy_eligibility_authority import (
    build_policy_eligibility_source_observation,
)
from mmaudit.models.policy_eligibility_refresh import (
    POLICY_ELIGIBILITY_REFRESH_FILENAME,
    PolicyEligibilityRefreshRouteDisposition,
    load_model_policy_eligibility_refresh_artifact,
)
from mmaudit.models.qualification import (
    CandidateRegistry,
    load_candidate_registry,
    seal_candidate_registry,
)
from mmaudit.models.refresh import (
    ATTEMPT_FILENAME,
    DIFF_FILENAME,
    FRESHNESS_FILENAME,
    SNAPSHOT_FILENAME,
    SOURCE_EVIDENCE_FILENAME,
    ModelRefreshAttemptStatus,
    ModelRefreshFailureCode,
    load_model_refresh_attempt,
    load_model_refresh_diff,
    load_model_refresh_snapshot,
    load_model_refresh_source_evidence,
)
from mmaudit.reporting.json_report import stable_json
from tests.unit import test_model_refresh as refresh_fixtures

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "config" / "models.candidates.toml"
runner = CliRunner()


def _secret_file(tmp_path: Path, canary: str) -> Path:
    path = tmp_path / "operator.env"
    path.write_text(f"OPENROUTER_API_KEY={canary}\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _model(candidate: Any) -> dict[str, Any]:
    return {
        "id": candidate.exact_model_id,
        "canonical_slug": candidate.canonical_model_slug,
        "context_length": candidate.context_size,
        "top_provider": {
            "context_length": candidate.context_size,
            "max_completion_tokens": candidate.output_limit,
        },
        "supported_parameters": [
            "max_tokens",
            "reasoning",
            "response_format",
            "temperature",
        ],
    }


def _endpoint(candidate: Any) -> dict[str, Any]:
    return {
        "model_id": candidate.exact_model_id,
        "slug": candidate.approved_provider_endpoint,
        "provider_name": candidate.approved_provider_name,
        "status": 0,
        "context_length": candidate.context_size,
        "max_prompt_tokens": candidate.context_size,
        "max_completion_tokens": candidate.output_limit,
        "supported_parameters": [
            "max_tokens",
            "reasoning",
            "response_format",
            "temperature",
        ],
        "pricing": {
            "completion": "0.000002",
            "prompt": "0.000001",
        },
    }


def _install_fake_client(
    monkeypatch: pytest.MonkeyPatch,
    registry: CandidateRegistry,
    *,
    fail_authentication: bool = False,
    malformed_catalog: bool = False,
    malformed_endpoint_limits: bool = False,
    reflect_secret: bool = False,
    reflect_secret_in_ignored_field: bool = False,
    empty_zdr: bool = False,
) -> tuple[type[Any], list[str], list[Any]]:
    calls: list[str] = []
    usages: list[Any] = []

    class FakeMetadataClient:
        def __init__(self, *, api_key: str, usage: Any, **_kwargs: object) -> None:
            assert api_key == "synthetic-refresh-canary"
            usages.append(usage)
            self.closed = False

        async def validate_authentication(self) -> None:
            calls.append("authenticate")
            if fail_authentication:
                raise OpenRouterAuthenticationError("synthetic value-free authentication failure")

        async def get_certification_model_metadata(self) -> dict[str, Any]:
            calls.append("catalog")
            models = [_model(candidate) for candidate in registry.candidates]
            if malformed_catalog:
                models.append(dict(models[0]))
            if reflect_secret_in_ignored_field:
                models[0]["description"] = "synthetic-refresh-canary"
            return {"data": models}

        async def get_zdr_endpoint_metadata(self) -> dict[str, Any]:
            calls.append("zdr")
            return {
                "data": (
                    [] if empty_zdr else [_endpoint(candidate) for candidate in registry.candidates]
                )
            }

        async def get_refresh_model_endpoint_metadata(
            self,
            model_id: str,
        ) -> dict[str, Any]:
            calls.append(f"endpoint:{model_id}")
            candidate = next(
                item for item in registry.candidates if item.exact_model_id == model_id
            )
            endpoint = _endpoint(candidate)
            if malformed_endpoint_limits:
                endpoint["max_completion_tokens"] = candidate.context_size + 1
            if reflect_secret:
                endpoint["provider_name"] = "synthetic-refresh-canary"
            return {
                "data": {
                    "id": model_id,
                    "endpoints": [
                        {key: value for key, value in endpoint.items() if key != "model_id"}
                    ],
                }
            }

        async def close(self) -> None:
            calls.append("close")
            self.closed = True

    monkeypatch.setattr(cli_module, "OpenRouterClient", FakeMetadataClient)
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_CLIENT_TYPE",
        FakeMetadataClient,
    )
    return FakeMetadataClient, calls, usages


def _arguments(tmp_path: Path, secret: Path) -> list[str]:
    return [
        "models",
        "refresh",
        "--candidate-registry",
        str(REGISTRY_PATH),
        "--secrets-env-file",
        str(secret),
        "--output-dir",
        str(tmp_path / "refresh-output"),
        "--soft-max-age-hours",
        "30",
        "--hard-max-age-hours",
        "72",
        "--pricing-tolerance-fraction",
        "0.05",
        "--no-color",
    ]


def _missing_policy_inputs(tmp_path: Path, registry: CandidateRegistry) -> tuple[list[str], str]:
    observed_at = datetime.now(UTC).replace(microsecond=0)
    candidate = registry.candidates[0]
    route = build_policy_eligibility_route(
        exact_model_id=candidate.exact_model_id,
        provider_name=candidate.approved_provider_name,
        provider_endpoint=candidate.approved_provider_endpoint,
    )
    artifact = build_model_policy_eligibility_artifact(
        created_at=observed_at - timedelta(hours=1),
        official_evidence=(),
        determinations=(),
    )
    observation = build_policy_eligibility_source_observation(
        artifact=artifact,
        observed_at=observed_at,
        expires_at=observed_at + timedelta(hours=12),
        source_commitments=(),
    )
    artifact_path = tmp_path / "policy-artifact.json"
    observation_path = tmp_path / "policy-source-observation.json"
    routes_path = tmp_path / "policy-checked-routes.json"
    for path, value in (
        (artifact_path, artifact),
        (observation_path, observation),
        (routes_path, [route.model_dump(mode="json")]),
    ):
        path.write_text(stable_json(value), encoding="utf-8")
        path.chmod(0o600)
    return (
        [
            "--policy-eligibility-artifact",
            str(artifact_path),
            "--policy-source-observation",
            str(observation_path),
            "--policy-checked-routes",
            str(routes_path),
        ],
        route.route_sha256,
    )


def test_models_refresh_help_exposes_only_metadata_and_evidence_controls() -> None:
    result = runner.invoke(app, ["models", "refresh", "--help"], env={"COLUMNS": "240"})

    assert result.exit_code == ExitCode.SUCCESS
    for option in (
        "--candidate-registry",
        "--previous-candidate-registry",
        "--previous-snapshot",
        "--previous-source-evidence",
        "--selected-route",
        "--secrets-env-file",
        "--output-dir",
        "--soft-max-age-hours",
        "--hard-max-age-hours",
        "--pricing-tolerance-fraction",
        "--policy-eligibility-artifact",
        "--policy-source-observation",
        "--policy-checked-routes",
    ):
        assert option in result.stdout
    assert "--benchmark" not in result.stdout
    assert "--qualify" not in result.stdout


def test_models_refresh_rejects_reused_output_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    result = runner.invoke(
        app,
        [
            "models",
            "refresh",
            "--candidate-registry",
            str(REGISTRY_PATH),
            "--output-dir",
            str(output),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "must be fresh" in result.stdout
    assert not secret_accessed


@pytest.mark.parametrize(
    "policy_arguments",
    [
        ["--pricing-tolerance-fraction", "0.050"],
        ["--pricing-tolerance-fraction", "1e-1000000000"],
        ["--pricing-tolerance-fraction", "-0.1"],
        ["--pricing-tolerance-fraction", "2"],
        ["--soft-max-age-hours", "72", "--hard-max-age-hours", "72"],
        ["--soft-max-age-hours", "73", "--hard-max-age-hours", "72"],
    ],
)
def test_models_refresh_rejects_invalid_policy_before_secret_or_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    policy_arguments: list[str],
) -> None:
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    result = runner.invoke(
        app,
        [
            "models",
            "refresh",
            "--candidate-registry",
            str(REGISTRY_PATH),
            *policy_arguments,
            "--output-dir",
            str(tmp_path / "output"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "refresh policy is invalid" in " ".join(result.stdout.split())
    assert not secret_accessed


def test_models_refresh_rejects_future_registry_before_secret_or_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = load_candidate_registry(REGISTRY_PATH)
    future_registry = seal_candidate_registry(
        created_at=datetime.now(UTC).replace(microsecond=0) + timedelta(days=1),
        discovery_run_sha256=registry.discovery_run_sha256,
        candidates=registry.candidates,
    )
    registry_path = tmp_path / "future-candidate-registry.json"
    registry_path.write_text(stable_json(future_registry), encoding="utf-8")
    registry_path.chmod(0o600)
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    result = runner.invoke(
        app,
        [
            "models",
            "refresh",
            "--candidate-registry",
            str(registry_path),
            "--output-dir",
            str(tmp_path / "output"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "candidate registry is future-dated" in " ".join(result.stdout.split())
    assert not secret_accessed


def test_models_refresh_rejects_revoked_registry_before_secret_or_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_id = "deepseek/deepseek-v4-pro-0813"
    base = refresh_fixtures._registry(
        model_ids=(model_id,),
        created_at=datetime.now(UTC).replace(microsecond=0),
    )
    model = base.candidates[0].model_copy(
        update={
            "canonical_model_slug": "deepseek/deepseek-v4-pro-20260813",
            "approved_provider_endpoint": "parasail/fp8",
        }
    )
    registry = seal_candidate_registry(
        created_at=base.created_at,
        discovery_run_sha256=base.discovery_run_sha256,
        candidates=(model,),
    )
    registry_path = tmp_path / "revoked-candidate-registry.json"
    registry_path.write_text(stable_json(registry), encoding="utf-8")
    registry_path.chmod(0o600)
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    result = runner.invoke(
        app,
        [
            "models",
            "refresh",
            "--candidate-registry",
            str(registry_path),
            "--selected-route",
            f"{model_id}=parasail/fp8",
            "--output-dir",
            str(tmp_path / "output"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "candidate assignment is ineligible" in " ".join(result.stdout.split())
    assert not secret_accessed
    assert not (tmp_path / "output").exists()


def test_models_refresh_rejects_untrusted_client_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_accessed = False

    class FakeClient:
        pass

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr(cli_module, "OpenRouterClient", FakeClient)
    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    result = runner.invoke(
        app,
        [
            "models",
            "refresh",
            "--candidate-registry",
            str(REGISTRY_PATH),
            "--output-dir",
            str(tmp_path / "output"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "trusted concrete OpenRouter" in result.stdout
    assert not secret_accessed


@pytest.mark.parametrize(
    "previous_arguments",
    [
        ["--previous-candidate-registry", str(REGISTRY_PATH)],
        ["--previous-snapshot", "previous-snapshot.json"],
        ["--previous-source-evidence", "previous-source.json"],
        [
            "--previous-candidate-registry",
            str(REGISTRY_PATH),
            "--previous-snapshot",
            "previous-snapshot.json",
        ],
        [
            "--previous-candidate-registry",
            str(REGISTRY_PATH),
            "--previous-source-evidence",
            "previous-source.json",
        ],
        [
            "--previous-snapshot",
            "previous-snapshot.json",
            "--previous-source-evidence",
            "previous-source.json",
        ],
    ],
)
def test_models_refresh_requires_exact_previous_triple_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    previous_arguments: list[str],
) -> None:
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    result = runner.invoke(
        app,
        [
            "models",
            "refresh",
            "--candidate-registry",
            str(REGISTRY_PATH),
            *previous_arguments,
            "--output-dir",
            str(tmp_path / "output"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "must" in result.stdout and "be supplied together" in result.stdout
    assert not secret_accessed


def test_models_refresh_executes_get_only_path_and_emits_private_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "synthetic-refresh-canary"
    secret = _secret_file(tmp_path, canary)
    registry = load_candidate_registry(REGISTRY_PATH)
    _client, calls, usages = _install_fake_client(monkeypatch, registry)
    output = tmp_path / "refresh-output"

    result = runner.invoke(app, _arguments(tmp_path, secret), env={"COLUMNS": "500"})

    assert result.exit_code == ExitCode.SUCCESS, result.stdout
    assert calls[0:3] == ["authenticate", "catalog", "zdr"]
    assert calls[-1] == "close"
    assert {call.removeprefix("endpoint:") for call in calls if call.startswith("endpoint:")} == {
        candidate.exact_model_id for candidate in registry.candidates
    }
    assert all(usage.records == [] for usage in usages)
    assert {path.name for path in output.iterdir()} == {
        SOURCE_EVIDENCE_FILENAME,
        SNAPSHOT_FILENAME,
        DIFF_FILENAME,
        ATTEMPT_FILENAME,
        FRESHNESS_FILENAME,
    }
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in output.iterdir())
    assert load_model_refresh_attempt(output / ATTEMPT_FILENAME).status in {
        ModelRefreshAttemptStatus.CHANGED,
        ModelRefreshAttemptStatus.UNCHANGED,
    }
    assert (
        load_model_refresh_source_evidence(
            output / SOURCE_EVIDENCE_FILENAME
        ).candidate_registry_sha256
        == registry.registry_sha256
    )
    serialized = "".join(path.read_text(encoding="utf-8") for path in output.iterdir())
    assert canary not in result.stdout
    assert canary not in serialized
    assert str(secret) not in serialized


def test_models_refresh_explicit_policy_inputs_emit_bound_missing_review_signal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "synthetic-refresh-canary"
    secret = _secret_file(tmp_path, canary)
    registry = load_candidate_registry(REGISTRY_PATH)
    _client, calls, usages = _install_fake_client(monkeypatch, registry)
    policy_arguments, checked_route_sha256 = _missing_policy_inputs(tmp_path, registry)
    output = tmp_path / "refresh-output"

    result = runner.invoke(
        app,
        [*_arguments(tmp_path, secret), *policy_arguments],
        env={"COLUMNS": "500"},
    )

    assert result.exit_code == ExitCode.SUCCESS, result.stdout
    assert calls[0:3] == ["authenticate", "catalog", "zdr"]
    assert calls[-1] == "close"
    assert all(usage.records == [] for usage in usages)
    projection = load_model_policy_eligibility_refresh_artifact(
        output / POLICY_ELIGIBILITY_REFRESH_FILENAME
    )
    snapshot = load_model_refresh_snapshot(output / SNAPSHOT_FILENAME)
    assert projection.refresh_snapshot_sha256 == snapshot.snapshot_sha256
    assert projection.refresh_source_evidence_sha256 == snapshot.source_evidence_sha256
    assert projection.observed_at == snapshot.retrieved_at
    assert projection.checked_routes[0].route_sha256 == checked_route_sha256
    assert projection.route_records[0].disposition is (
        PolicyEligibilityRefreshRouteDisposition.REDETERMINATION_REQUIRED
    )
    assert projection.route_records[0].review_reasons == (PolicyReviewReason.MISSING,)
    assert projection.redetermination_required is True
    assert projection.automated_eligibility_inference is False
    assert projection.policy_selection_authorized is False
    assert projection.qualification_authorized is False
    assert projection.source_egress_authorized is False
    assert projection.production_selection_authorized is False
    assert canary not in (output / POLICY_ELIGIBILITY_REFRESH_FILENAME).read_text(encoding="utf-8")


def test_models_refresh_requires_all_policy_inputs_before_secret_or_provider_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    class ForbiddenClient:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError("provider client must not be constructed")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    monkeypatch.setattr(cli_module, "OpenRouterClient", ForbiddenClient)
    monkeypatch.setattr(cli_module, "_TRUSTED_OPENROUTER_CLIENT_TYPE", ForbiddenClient)
    result = runner.invoke(
        app,
        [
            "models",
            "refresh",
            "--candidate-registry",
            str(REGISTRY_PATH),
            "--policy-eligibility-artifact",
            str(tmp_path / "policy-artifact.json"),
            "--output-dir",
            str(tmp_path / "output"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "must be supplied together" in " ".join(result.stdout.split())
    assert not secret_accessed


def test_models_refresh_rejects_unapproved_policy_route_before_provider_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = load_candidate_registry(REGISTRY_PATH)
    policy_arguments, _route_sha256 = _missing_policy_inputs(tmp_path, registry)
    candidate = registry.candidates[0]
    unapproved = build_policy_eligibility_route(
        exact_model_id=candidate.exact_model_id,
        provider_name=candidate.approved_provider_name,
        provider_endpoint="unapproved-provider/route",
    )
    routes_path = Path(policy_arguments[policy_arguments.index("--policy-checked-routes") + 1])
    routes_path.write_text(
        stable_json([unapproved.model_dump(mode="json")]),
        encoding="utf-8",
    )
    routes_path.chmod(0o600)
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    class ForbiddenClient:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError("provider client must not be constructed")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    monkeypatch.setattr(cli_module, "OpenRouterClient", ForbiddenClient)
    monkeypatch.setattr(cli_module, "_TRUSTED_OPENROUTER_CLIENT_TYPE", ForbiddenClient)
    result = runner.invoke(
        app,
        [
            "models",
            "refresh",
            "--candidate-registry",
            str(REGISTRY_PATH),
            *policy_arguments,
            "--output-dir",
            str(tmp_path / "output"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "checked policy route" in " ".join(result.stdout.split())
    assert not secret_accessed


def test_models_refresh_replays_an_exact_previous_triple_before_provider_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = _secret_file(tmp_path, "synthetic-refresh-canary")
    registry = load_candidate_registry(REGISTRY_PATH)
    _install_fake_client(monkeypatch, registry)
    first_output = tmp_path / "refresh-output"
    first = runner.invoke(app, _arguments(tmp_path, secret), env={"COLUMNS": "500"})
    assert first.exit_code == ExitCode.SUCCESS, first.stdout

    second_output = tmp_path / "second-output"
    arguments = _arguments(tmp_path, secret)
    arguments[arguments.index("--output-dir") + 1] = str(second_output)
    arguments.extend(
        [
            "--previous-candidate-registry",
            str(REGISTRY_PATH),
            "--previous-snapshot",
            str(first_output / SNAPSHOT_FILENAME),
            "--previous-source-evidence",
            str(first_output / SOURCE_EVIDENCE_FILENAME),
        ]
    )
    second = runner.invoke(app, arguments, env={"COLUMNS": "500"})

    assert second.exit_code == ExitCode.SUCCESS, second.stdout
    assert {path.name for path in second_output.iterdir()} == {
        SOURCE_EVIDENCE_FILENAME,
        SNAPSHOT_FILENAME,
        DIFF_FILENAME,
        ATTEMPT_FILENAME,
        FRESHNESS_FILENAME,
    }


def test_models_refresh_replays_history_across_an_exact_registry_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = _secret_file(tmp_path, "synthetic-refresh-canary")
    current_registry = load_candidate_registry(REGISTRY_PATH)
    previous_registry = seal_candidate_registry(
        created_at=current_registry.created_at - timedelta(days=1),
        discovery_run_sha256="d" * 64,
        candidates=current_registry.candidates,
    )
    previous_registry_path = tmp_path / "previous-candidate-registry.json"
    previous_registry_path.write_text(stable_json(previous_registry), encoding="utf-8")
    previous_registry_path.chmod(0o600)

    _install_fake_client(monkeypatch, previous_registry)
    previous_output = tmp_path / "previous-output"
    previous_arguments = _arguments(tmp_path, secret)
    previous_arguments[previous_arguments.index("--candidate-registry") + 1] = str(
        previous_registry_path
    )
    previous_arguments[previous_arguments.index("--output-dir") + 1] = str(previous_output)
    first = runner.invoke(app, previous_arguments, env={"COLUMNS": "500"})
    assert first.exit_code == ExitCode.SUCCESS, first.stdout

    _install_fake_client(monkeypatch, current_registry)
    current_output = tmp_path / "current-output"
    current_arguments = _arguments(tmp_path, secret)
    current_arguments[current_arguments.index("--output-dir") + 1] = str(current_output)
    current_arguments.extend(
        [
            "--previous-candidate-registry",
            str(previous_registry_path),
            "--previous-snapshot",
            str(previous_output / SNAPSHOT_FILENAME),
            "--previous-source-evidence",
            str(previous_output / SOURCE_EVIDENCE_FILENAME),
        ]
    )
    second = runner.invoke(app, current_arguments, env={"COLUMNS": "500"})

    assert second.exit_code == ExitCode.SUCCESS, second.stdout
    diff = load_model_refresh_diff(current_output / DIFF_FILENAME)
    assert diff.baseline_candidate_registry_sha256 == previous_registry.registry_sha256
    assert diff.current_candidate_registry_sha256 == current_registry.registry_sha256


def test_models_refresh_rejects_a_previous_snapshot_newer_than_current_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = _secret_file(tmp_path, "synthetic-refresh-canary")
    registry = load_candidate_registry(REGISTRY_PATH)
    _client, calls, _usages = _install_fake_client(monkeypatch, registry)
    base_time = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)

    class FutureDatetime(datetime):
        @classmethod
        def now(cls, tz: object | None = None) -> datetime:
            del tz
            return base_time + timedelta(hours=1)

    monkeypatch.setattr(cli_module, "datetime", FutureDatetime)
    first_output = tmp_path / "future-output"
    first_arguments = _arguments(tmp_path, secret)
    first_arguments[first_arguments.index("--output-dir") + 1] = str(first_output)
    first = runner.invoke(app, first_arguments, env={"COLUMNS": "500"})
    assert first.exit_code == ExitCode.SUCCESS, first.stdout
    calls.clear()

    class CurrentDatetime(datetime):
        @classmethod
        def now(cls, tz: object | None = None) -> datetime:
            del tz
            return base_time

    monkeypatch.setattr(cli_module, "datetime", CurrentDatetime)
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    second_output = tmp_path / "current-output"
    second_arguments = _arguments(tmp_path, secret)
    second_arguments[second_arguments.index("--output-dir") + 1] = str(second_output)
    second_arguments.extend(
        [
            "--previous-candidate-registry",
            str(REGISTRY_PATH),
            "--previous-snapshot",
            str(first_output / SNAPSHOT_FILENAME),
            "--previous-source-evidence",
            str(first_output / SOURCE_EVIDENCE_FILENAME),
        ]
    )
    second = runner.invoke(app, second_arguments, env={"COLUMNS": "500"})

    assert second.exit_code == ExitCode.CONFIGURATION
    assert "future-dated" in second.stdout
    assert not secret_accessed
    assert calls == []
    assert not second_output.exists()


def test_models_refresh_authentication_failure_emits_only_typed_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = _secret_file(tmp_path, "synthetic-refresh-canary")
    registry = load_candidate_registry(REGISTRY_PATH)
    _client, calls, usages = _install_fake_client(
        monkeypatch,
        registry,
        fail_authentication=True,
    )
    output = tmp_path / "refresh-output"

    result = runner.invoke(app, _arguments(tmp_path, secret), env={"COLUMNS": "500"})

    assert result.exit_code == ExitCode.MODEL_FAILURE
    assert calls == ["authenticate", "close"]
    assert all(usage.records == [] for usage in usages)
    assert [path.name for path in output.iterdir()] == [ATTEMPT_FILENAME]
    attempt = load_model_refresh_attempt(output / ATTEMPT_FILENAME)
    assert attempt.status is ModelRefreshAttemptStatus.FAILED
    assert attempt.failure_code is ModelRefreshFailureCode.AUTHENTICATION
    assert "AUTHENTICATION" in result.stdout
    assert "synthetic-refresh-canary" not in result.stdout


def test_models_refresh_malformed_catalogue_is_failed_not_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = _secret_file(tmp_path, "synthetic-refresh-canary")
    registry = load_candidate_registry(REGISTRY_PATH)
    _client, _calls, _usages = _install_fake_client(
        monkeypatch,
        registry,
        malformed_catalog=True,
    )
    output = tmp_path / "refresh-output"

    result = runner.invoke(app, _arguments(tmp_path, secret), env={"COLUMNS": "500"})

    assert result.exit_code == ExitCode.MODEL_FAILURE
    assert [path.name for path in output.iterdir()] == [ATTEMPT_FILENAME]
    attempt = load_model_refresh_attempt(output / ATTEMPT_FILENAME)
    assert attempt.status is ModelRefreshAttemptStatus.FAILED
    assert attempt.failure_code is ModelRefreshFailureCode.MALFORMED_METADATA
    assert "UNCHANGED" not in result.stdout


def test_models_refresh_nested_validation_failure_emits_typed_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = _secret_file(tmp_path, "synthetic-refresh-canary")
    registry = load_candidate_registry(REGISTRY_PATH)
    _client, _calls, _usages = _install_fake_client(
        monkeypatch,
        registry,
        malformed_endpoint_limits=True,
    )
    output = tmp_path / "refresh-output"

    result = runner.invoke(app, _arguments(tmp_path, secret), env={"COLUMNS": "500"})

    assert result.exit_code == ExitCode.MODEL_FAILURE
    assert [path.name for path in output.iterdir()] == [ATTEMPT_FILENAME]
    attempt = load_model_refresh_attempt(output / ATTEMPT_FILENAME)
    assert attempt.status is ModelRefreshAttemptStatus.FAILED
    assert attempt.failure_code is ModelRefreshFailureCode.MALFORMED_METADATA


def test_models_refresh_rejects_reflected_secret_before_hash_or_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "synthetic-refresh-canary"
    secret = _secret_file(tmp_path, canary)
    registry = load_candidate_registry(REGISTRY_PATH)
    _client, _calls, _usages = _install_fake_client(
        monkeypatch,
        registry,
        reflect_secret=True,
    )
    output = tmp_path / "refresh-output"

    result = runner.invoke(app, _arguments(tmp_path, secret), env={"COLUMNS": "500"})

    assert result.exit_code == ExitCode.MODEL_FAILURE
    assert [path.name for path in output.iterdir()] == [ATTEMPT_FILENAME]
    attempt = load_model_refresh_attempt(output / ATTEMPT_FILENAME)
    assert attempt.failure_code is ModelRefreshFailureCode.MALFORMED_METADATA
    assert canary not in result.stdout
    assert canary not in (output / ATTEMPT_FILENAME).read_text(encoding="utf-8")


def test_models_refresh_rejects_secret_reflected_only_in_an_ignored_field(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "synthetic-refresh-canary"
    secret = _secret_file(tmp_path, canary)
    registry = load_candidate_registry(REGISTRY_PATH)
    _client, _calls, _usages = _install_fake_client(
        monkeypatch,
        registry,
        reflect_secret_in_ignored_field=True,
    )
    output = tmp_path / "refresh-output"

    result = runner.invoke(app, _arguments(tmp_path, secret), env={"COLUMNS": "500"})

    assert result.exit_code == ExitCode.MODEL_FAILURE
    assert [path.name for path in output.iterdir()] == [ATTEMPT_FILENAME]
    attempt = load_model_refresh_attempt(output / ATTEMPT_FILENAME)
    assert attempt.failure_code is ModelRefreshFailureCode.MALFORMED_METADATA
    assert canary not in result.stdout
    assert canary not in (output / ATTEMPT_FILENAME).read_text(encoding="utf-8")


def test_models_refresh_selected_route_loss_emits_evidence_and_incomplete_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = _secret_file(tmp_path, "synthetic-refresh-canary")
    registry = load_candidate_registry(REGISTRY_PATH)
    _client, _calls, _usages = _install_fake_client(
        monkeypatch,
        registry,
        empty_zdr=True,
    )
    selected = registry.candidates[0]
    output = tmp_path / "refresh-output"

    result = runner.invoke(
        app,
        [
            *_arguments(tmp_path, secret),
            "--selected-route",
            f"{selected.exact_model_id}={selected.approved_provider_endpoint}",
        ],
        env={"COLUMNS": "500"},
    )

    assert result.exit_code == ExitCode.INCOMPLETE
    assert {path.name for path in output.iterdir()} == {
        SOURCE_EVIDENCE_FILENAME,
        SNAPSHOT_FILENAME,
        DIFF_FILENAME,
        ATTEMPT_FILENAME,
        FRESHNESS_FILENAME,
    }
    assert (
        load_model_refresh_attempt(output / ATTEMPT_FILENAME).status
        is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    )


def test_models_refresh_missing_explicit_secret_is_typed_and_ambient_key_is_ignored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MMAUDIT_SECRETS_ENV_FILE", raising=False)
    output = tmp_path / "refresh-output"
    result = runner.invoke(
        app,
        [
            "models",
            "refresh",
            "--candidate-registry",
            str(REGISTRY_PATH),
            "--output-dir",
            str(output),
            "--no-color",
        ],
        env={"OPENROUTER_API_KEY": "ambient-key-must-be-ignored", "COLUMNS": "500"},
    )

    assert result.exit_code == ExitCode.MODEL_FAILURE
    attempt = load_model_refresh_attempt(output / ATTEMPT_FILENAME)
    assert attempt.failure_code is ModelRefreshFailureCode.SECRET_PREREQUISITE
    assert "ambient-key-must-be-ignored" not in result.stdout
    assert "ambient-key-must-be-ignored" not in (output / ATTEMPT_FILENAME).read_text(
        encoding="utf-8"
    )


def test_models_refresh_invalid_selected_route_fails_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    result = runner.invoke(
        app,
        [
            "models",
            "refresh",
            "--candidate-registry",
            str(REGISTRY_PATH),
            "--selected-route",
            "openrouter/auto=provider/fp8",
            "--output-dir",
            str(tmp_path / "output"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "exact non-alias" in result.stdout
    assert not secret_accessed


def test_models_refresh_unapproved_exact_route_fails_before_secret_or_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    class ForbiddenClient:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError("provider client must not be constructed")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    monkeypatch.setattr(cli_module, "OpenRouterClient", ForbiddenClient)
    monkeypatch.setattr(cli_module, "_TRUSTED_OPENROUTER_CLIENT_TYPE", ForbiddenClient)
    result = runner.invoke(
        app,
        [
            "models",
            "refresh",
            "--candidate-registry",
            str(REGISTRY_PATH),
            "--selected-route",
            "deepseek/deepseek-v3.2-exp=unapproved-provider/fp8",
            "--output-dir",
            str(tmp_path / "output"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "frozen candidate registry" in " ".join(result.stdout.split())
    assert not secret_accessed
