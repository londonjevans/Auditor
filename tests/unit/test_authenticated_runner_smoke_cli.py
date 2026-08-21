from __future__ import annotations

import json
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

import mmaudit.cli as cli_module
from mmaudit.config import ConfigError
from mmaudit.constants import ExitCode
from mmaudit.models.authenticated_runner_smoke import AuthenticatedRunnerSmokeEvidenceBundle
from scripts.generate_release_schemas import MODELS, rendered_schema

RUNNER = CliRunner()
ROOT = Path(__file__).resolve().parents[2]
SCHEMA_NAME = "authenticated_runner_smoke_evidence_bundle.schema.json"


class _SecretPresenceOnly:
    def __init__(self) -> None:
        self.cleared = False

    @property
    def openrouter_api_key_present(self) -> bool:
        return not self.cleared

    def __enter__(self) -> _SecretPresenceOnly:
        return self

    def __exit__(self, *_args: object) -> None:
        self.clear()

    def clear(self) -> None:
        self.cleared = True


def _required_arguments(
    tmp_path: Path,
    *,
    allow_egress: bool = True,
    preflight_only: bool = False,
    live_route_preflight_only: bool = False,
    include_secret: bool = True,
) -> list[str]:
    arguments = [
        "models",
        "authenticated-runner-smoke",
        "--candidate-registry",
        str(tmp_path / "candidate-registry.json"),
        "--candidate-discovery-run",
        str(tmp_path / "candidate-discovery"),
        "--primary-judge-registry",
        str(tmp_path / "primary-judge-registry.json"),
        "--primary-judge-discovery-run",
        str(tmp_path / "primary-judge-discovery"),
        "--replay-judge-registry",
        str(tmp_path / "replay-judge-registry.json"),
        "--replay-judge-discovery-run",
        str(tmp_path / "replay-judge-discovery"),
        "--smoke-corpus",
        str(tmp_path / "smoke-corpus"),
        "--output",
        str(tmp_path / "smoke-evidence.json"),
        "--candidate-cost-cap-usd-per-attempt",
        "1.00",
        "--primary-judge-cost-cap-usd-per-attempt",
        "1.00",
        "--replay-judge-cost-cap-usd-per-attempt",
        "1.00",
        "--config",
        str(tmp_path / "mmaudit.toml"),
        "--corpus",
        str(tmp_path / "parent-manifest.json"),
        "--cost-ledger",
        str(tmp_path / "cost-ledger.json"),
        "--no-color",
    ]
    if include_secret:
        arguments.extend(("--secrets-env-file", str(tmp_path / "operator-secrets.env")))
    if allow_egress:
        arguments.append(
            "--allow-metadata-egress" if live_route_preflight_only else "--allow-code-egress"
        )
    if preflight_only:
        arguments.append("--preflight-only")
    if live_route_preflight_only:
        arguments.append("--live-route-preflight-only")
    return arguments


def _inventory() -> SimpleNamespace:
    return SimpleNamespace(
        run_count=2,
        case_count=1,
        logical_request_count=4,
        maximum_attempts_per_logical_request=2,
        maximum_provider_attempt_count=8,
        generation_refetch_count=4,
        effective_config_sha256="a" * 64,
        initial_spent_usd="0",
        operator_interval_tripwire_usd="8.00",
        operator_final_spent_tripwire_usd="8.00",
        candidate_cost_plans=(
            SimpleNamespace(plan_sha256="b" * 64),
            SimpleNamespace(plan_sha256="c" * 64),
        ),
        candidate_derived_interval_cost_cap_usd="0.22",
        candidate_derived_final_spent_cap_usd="0.22",
        judge_cost_admission_status="PENDING_REAL_CANDIDATE_OUTPUTS",
    )


def _patch_launch_inputs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> SimpleNamespace:
    config = SimpleNamespace(execution=SimpleNamespace(cost_ledger_path=None))
    ledger = SimpleNamespace(
        path=tmp_path / "cost-ledger.json",
        lock_path=tmp_path / ".cost-ledger.json.lock",
    )
    budget = SimpleNamespace(atomic_ledger=ledger)
    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(cli_module, "load_model_benchmark_corpus", lambda _path: object())
    monkeypatch.setattr(
        cli_module,
        "load_authenticated_runner_smoke_corpus_bundle",
        lambda _path: object(),
    )
    monkeypatch.setattr(cli_module, "resolve_verified_public_model_lineage", lambda: object())
    monkeypatch.setattr(cli_module, "load_candidate_registry", lambda _path: object())
    monkeypatch.setattr(
        cli_module,
        "load_model_discovery_run",
        lambda _path: (object(), (object(),)),
    )
    monkeypatch.setattr(
        cli_module,
        "_budget_and_usage",
        lambda *_args, **_kwargs: (budget, object()),
    )
    return ledger


def test_authenticated_runner_smoke_help_is_isolated_from_crediting_inputs() -> None:
    result = RUNNER.invoke(
        cli_module.app,
        ["models", "authenticated-runner-smoke", "--help"],
        env={"COLUMNS": "180"},
    )

    assert result.exit_code == 0
    for option in (
        "--candidate-registry",
        "--candidate-discovery-run",
        "--primary-judge-registry",
        "--primary-judge-discovery-run",
        "--replay-judge-registry",
        "--replay-judge-discovery-run",
        "--smoke-corpus",
        "--corpus",
        "--cost-ledger",
        "--secrets-env-file",
        "--allow-code-egress",
        "--allow-metadata-egress",
        "--preflight-only",
        "--live-route-preflight-only",
    ):
        assert option in result.stdout
    for forbidden in (
        "--qualification-policy",
        "--ground-truth-provenance",
        "--campaign-journal",
        "--portfolio",
        "--resume",
    ):
        assert forbidden not in result.stdout
    assert "non-resumable" in result.stdout
    assert "without benchmark credit" in result.stdout


def test_authenticated_runner_smoke_requires_egress_opt_in_before_loading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_module,
        "load_config",
        lambda _path: (_ for _ in ()).throw(AssertionError("must not load configuration")),
    )

    result = RUNNER.invoke(
        cli_module.app,
        _required_arguments(tmp_path, allow_egress=False),
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "requires explicit --allow-code-egress" in " ".join(result.stdout.split())


def test_authenticated_runner_smoke_preflight_is_provider_free_and_does_not_mutate_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    _patch_launch_inputs(monkeypatch, tmp_path)
    monkeypatch.setattr(
        cli_module,
        "preflight_authenticated_runner_smoke_openrouter_launch",
        lambda _launch: _inventory(),
    )

    def forbidden(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("preflight must not select secrets, execute, or publish")

    for name in (
        "select_operator_secret_file",
        "load_operator_secrets",
        "execute_authenticated_runner_smoke_openrouter",
        "execute_authenticated_openrouter_runner",
        "_preflight_authenticated_runner_output",
        "_write_authenticated_runner_smoke_output_fresh",
    ):
        monkeypatch.setattr(cli_module, name, forbidden)

    output = tmp_path / "smoke-evidence.json"
    before = tuple(tmp_path.iterdir())
    result = RUNNER.invoke(
        cli_module.app,
        _required_arguments(
            tmp_path,
            preflight_only=True,
            include_secret=False,
        ),
    )

    assert result.exit_code == 0, result.stdout
    assert tuple(tmp_path.iterdir()) == before
    assert not output.exists()
    normalized = " ".join(result.stdout.split())
    assert "VALID / NONCREDITING / NONAUTHORIZING / NO PROVIDER EGRESS" in normalized
    assert "runs=2; cases=1; logical_requests=4" in normalized
    assert "maximum_provider_attempts=8; generation_refetches=4" in normalized
    assert "full_smoke_cost_bound=UNAVAILABLE_BEFORE_REAL_CANDIDATE_OUTPUTS" in normalized


def test_authenticated_runner_smoke_preflight_modes_are_mutually_exclusive_before_loading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_module,
        "load_config",
        lambda _path: (_ for _ in ()).throw(AssertionError("must not load configuration")),
    )

    result = RUNNER.invoke(
        cli_module.app,
        _required_arguments(
            tmp_path,
            preflight_only=True,
            live_route_preflight_only=True,
        ),
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "mutually exclusive" in " ".join(result.stdout.split())


def test_authenticated_runner_smoke_live_route_rejects_code_egress_authority_before_loading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_module,
        "load_config",
        lambda _path: (_ for _ in ()).throw(AssertionError("must not load configuration")),
    )
    arguments = _required_arguments(tmp_path, live_route_preflight_only=True)
    arguments.append("--allow-code-egress")

    result = RUNNER.invoke(cli_module.app, arguments)

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "rejects broader --allow-code-egress" in " ".join(result.stdout.split())


def test_authenticated_runner_smoke_live_route_requires_explicit_metadata_egress_before_loading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_module,
        "load_config",
        lambda _path: (_ for _ in ()).throw(AssertionError("must not load configuration")),
    )

    result = RUNNER.invoke(
        cli_module.app,
        _required_arguments(
            tmp_path,
            allow_egress=False,
            live_route_preflight_only=True,
        ),
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "requires explicit --allow-metadata-egress" in " ".join(result.stdout.split())


def test_authenticated_runner_smoke_metadata_egress_cannot_authorize_another_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_module,
        "load_config",
        lambda _path: (_ for _ in ()).throw(AssertionError("must not load configuration")),
    )
    arguments = _required_arguments(tmp_path, allow_egress=False)
    arguments.append("--allow-metadata-egress")

    result = RUNNER.invoke(cli_module.app, arguments)

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "requires --live-route-preflight-only" in " ".join(result.stdout.split())


def test_authenticated_runner_smoke_live_route_uses_metadata_egress_and_never_publishes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    _patch_launch_inputs(monkeypatch, tmp_path)
    calls: list[str] = []
    inventory = _inventory()
    live_result = SimpleNamespace(
        inventory=inventory,
        exact_model_ids=("candidate/model", "primary/judge", "replay/judge"),
        logical_metadata_get_count=15,
        maximum_metadata_provider_attempt_count=30,
    )
    secret_holder = _SecretPresenceOnly()

    def preflight(_launch: object) -> SimpleNamespace:
        calls.append("metadata-preflight")
        return inventory

    def select(path: Path | None) -> Path:
        calls.append("select-secret")
        assert path is not None
        return path

    async def live_probe(**kwargs: object) -> SimpleNamespace:
        calls.append("live-route-probe")
        assert not secret_holder.cleared
        assert kwargs["explicitly_allow_metadata_egress"] is True
        secret_holder.clear()
        return live_result

    def forbidden(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("live-route preflight must not complete or publish")

    monkeypatch.setattr(
        cli_module,
        "preflight_authenticated_runner_smoke_live_route_launch",
        preflight,
    )
    monkeypatch.setattr(cli_module, "select_operator_secret_file", select)
    monkeypatch.setattr(
        cli_module,
        "load_operator_secrets",
        lambda *_args, **_kwargs: secret_holder,
    )
    monkeypatch.setattr(
        cli_module,
        "preflight_authenticated_runner_smoke_live_routes",
        live_probe,
    )
    for name in (
        "execute_authenticated_runner_smoke_openrouter",
        "execute_authenticated_openrouter_runner",
        "_preflight_authenticated_runner_output",
        "_write_authenticated_runner_smoke_output_fresh",
    ):
        monkeypatch.setattr(cli_module, name, forbidden)

    output = tmp_path / "smoke-evidence.json"
    before = tuple(tmp_path.iterdir())
    result = RUNNER.invoke(
        cli_module.app,
        _required_arguments(tmp_path, live_route_preflight_only=True),
    )

    assert result.exit_code == 0, result.stdout
    assert calls == ["metadata-preflight", "select-secret", "live-route-probe"]
    assert secret_holder.cleared
    assert tuple(tmp_path.iterdir()) == before
    assert not output.exists()
    normalized = " ".join(result.stdout.split())
    assert "METADATA EGRESS ONLY / NO MODEL COMPLETION" in normalized
    assert "candidate=candidate/model" in normalized
    assert "primary_judge=primary/judge" in normalized
    assert "replay_judge=replay/judge" in normalized
    assert "logical_gets=15; maximum_provider_attempts=30" in normalized
    assert (
        "usage_records=0; budget=UNCHANGED; atomic_cost_ledger=UNCHANGED; output=NOT_PUBLISHED"
    ) in normalized


def test_authenticated_runner_smoke_real_path_preflights_before_secret_and_publishes_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    _patch_launch_inputs(monkeypatch, tmp_path)
    calls: list[str] = []
    inventory = _inventory()
    ledger_evidence = SimpleNamespace(entries=(object(),) * 4, final_spent_usd="0.18")
    bundle = SimpleNamespace(
        bundle_sha256="d" * 64,
        closed_ledger_evidence=ledger_evidence,
    )

    def preflight(_launch: object) -> SimpleNamespace:
        calls.append("preflight")
        return inventory

    def select(path: Path | None) -> Path:
        calls.append("select-secret")
        assert path is not None
        return path

    async def execute(**_kwargs: object) -> SimpleNamespace:
        calls.append("execute")
        return SimpleNamespace(bundle=bundle)

    def write(path: Path, value: object) -> int:
        calls.append("write")
        assert path == tmp_path / "smoke-evidence.json"
        assert value is bundle
        return 1

    monkeypatch.setattr(
        cli_module,
        "preflight_authenticated_runner_smoke_openrouter_launch",
        preflight,
    )
    monkeypatch.setattr(cli_module, "select_operator_secret_file", select)
    monkeypatch.setattr(
        cli_module, "load_operator_secrets", lambda *_a, **_k: _SecretPresenceOnly()
    )
    monkeypatch.setattr(cli_module, "execute_authenticated_runner_smoke_openrouter", execute)
    monkeypatch.setattr(cli_module, "_write_authenticated_runner_smoke_output_fresh", write)
    monkeypatch.setattr(cli_module, "_preflight_authenticated_runner_output", lambda _path: None)

    result = RUNNER.invoke(cli_module.app, _required_arguments(tmp_path))

    assert result.exit_code == 0, result.stdout
    assert calls == ["preflight", "select-secret", "execute", "write"]
    assert "COMPLETE / NONCREDITING / NONAUTHORIZING" in result.stdout
    assert f"Bundle SHA-256: {bundle.bundle_sha256}" in result.stdout
    assert "Closed ledger: entries=4; final_spent_usd=0.18" in result.stdout


def test_verify_authenticated_runner_smoke_help_requires_all_offline_pins() -> None:
    result = RUNNER.invoke(
        cli_module.app,
        ["models", "verify-authenticated-runner-smoke", "--help"],
        env={"COLUMNS": "160"},
    )

    assert result.exit_code == 0
    for option in ("--bundle", "--smoke-corpus", "--corpus", "--config"):
        assert option in result.stdout
    for forbidden in ("--secrets-env-file", "--cost-ledger", "--allow-code-egress"):
        assert forbidden not in result.stdout


def test_verify_authenticated_runner_smoke_replays_exact_corpus_parent_and_config_offline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = SimpleNamespace(case_id="case-df79ea132113b863")
    truth = SimpleNamespace(case_id="case-df79ea132113b863")
    smoke = SimpleNamespace(
        bundle_sha256="a" * 64,
        case=case,
        ground_truth_case=truth,
    )
    parent = SimpleNamespace(
        cases=(case,),
        ground_truth=SimpleNamespace(cases=(truth,)),
        corpus_sha256="b" * 64,
        ground_truth_sha256="c" * 64,
    )
    config = SimpleNamespace(stable_hash=lambda: "d" * 64)
    bundle = SimpleNamespace(
        smoke_corpus_bundle_sha256=smoke.bundle_sha256,
        parent_corpus_sha256=parent.corpus_sha256,
        parent_ground_truth_sha256=parent.ground_truth_sha256,
        effective_config_sha256="d" * 64,
        selected_case_id=case.case_id,
        bundle_sha256="e" * 64,
        run_count=2,
        logical_request_count=4,
        closed_ledger_evidence=SimpleNamespace(entries=(object(),) * 4, final_spent_usd="0.2"),
    )
    observed: list[tuple[str, Path]] = []

    def load_bundle(path: Path) -> SimpleNamespace:
        observed.append(("bundle", path))
        return bundle

    def load_smoke(path: Path) -> SimpleNamespace:
        observed.append(("smoke", path))
        return smoke

    def load_parent(path: Path) -> SimpleNamespace:
        observed.append(("parent", path))
        return parent

    def load_configuration(path: Path) -> SimpleNamespace:
        observed.append(("config", path))
        return config

    monkeypatch.setattr(
        cli_module,
        "_load_authenticated_runner_smoke_evidence_bundle",
        load_bundle,
    )
    monkeypatch.setattr(
        cli_module,
        "load_authenticated_runner_smoke_corpus_bundle",
        load_smoke,
    )
    monkeypatch.setattr(
        cli_module,
        "load_model_benchmark_corpus",
        load_parent,
    )
    monkeypatch.setattr(
        cli_module,
        "load_config",
        load_configuration,
    )

    def external_state_forbidden(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("offline smoke replay must not access live state")

    for name in (
        "load_operator_secrets",
        "_budget_and_usage",
        "execute_authenticated_runner_smoke_openrouter",
        "execute_authenticated_openrouter_runner",
    ):
        monkeypatch.setattr(cli_module, name, external_state_forbidden)
    bundle_path = tmp_path / "bundle.json"
    smoke_path = tmp_path / "smoke"
    corpus_path = tmp_path / "manifest.json"
    config_path = tmp_path / "mmaudit.toml"
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "verify-authenticated-runner-smoke",
            "--bundle",
            str(bundle_path),
            "--smoke-corpus",
            str(smoke_path),
            "--corpus",
            str(corpus_path),
            "--config",
            str(config_path),
            "--no-color",
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert observed == [
        ("bundle", bundle_path),
        ("smoke", smoke_path),
        ("parent", corpus_path),
        ("config", config_path),
    ]
    assert "VALID / NONCREDITING / NONAUTHORIZING" in result.stdout
    assert "runs=2; logical_requests=4" in result.stdout


@pytest.mark.parametrize(
    "field",
    (
        "smoke_corpus_bundle_sha256",
        "parent_corpus_sha256",
        "parent_ground_truth_sha256",
        "effective_config_sha256",
        "selected_case_id",
    ),
)
def test_verify_authenticated_runner_smoke_rejects_detached_pin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    case = SimpleNamespace(case_id="case-df79ea132113b863")
    truth = SimpleNamespace(case_id=case.case_id)
    smoke = SimpleNamespace(bundle_sha256="a" * 64, case=case, ground_truth_case=truth)
    parent = SimpleNamespace(
        cases=(case,),
        ground_truth=SimpleNamespace(cases=(truth,)),
        corpus_sha256="b" * 64,
        ground_truth_sha256="c" * 64,
    )
    values = {
        "smoke_corpus_bundle_sha256": smoke.bundle_sha256,
        "parent_corpus_sha256": parent.corpus_sha256,
        "parent_ground_truth_sha256": parent.ground_truth_sha256,
        "effective_config_sha256": "d" * 64,
        "selected_case_id": case.case_id,
        "bundle_sha256": "e" * 64,
        "run_count": 2,
        "logical_request_count": 4,
        "closed_ledger_evidence": SimpleNamespace(entries=(), final_spent_usd="0"),
    }
    values[field] = "f" * 64
    bundle = SimpleNamespace(**values)
    monkeypatch.setattr(
        cli_module,
        "_load_authenticated_runner_smoke_evidence_bundle",
        lambda _path: bundle,
    )
    monkeypatch.setattr(
        cli_module,
        "load_authenticated_runner_smoke_corpus_bundle",
        lambda _path: smoke,
    )
    monkeypatch.setattr(cli_module, "load_model_benchmark_corpus", lambda _path: parent)
    monkeypatch.setattr(
        cli_module,
        "load_config",
        lambda _path: SimpleNamespace(stable_hash=lambda: "d" * 64),
    )

    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "verify-authenticated-runner-smoke",
            "--bundle",
            str(tmp_path / "bundle.json"),
            "--smoke-corpus",
            str(tmp_path / "smoke"),
            "--corpus",
            str(tmp_path / "manifest.json"),
            "--config",
            str(tmp_path / "mmaudit.toml"),
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "differs from its tracked corpus" in " ".join(result.stdout.split())
    assert "VALID / NONCREDITING" not in result.stdout


def test_smoke_private_loader_is_bounded_canonical_and_rejects_unsafe_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    path = private / "bundle.json"
    raw = b'{"synthetic":"smoke"}\n'
    path.write_bytes(raw)
    path.chmod(0o600)
    smoke_model: Any = AuthenticatedRunnerSmokeEvidenceBundle
    expected: AuthenticatedRunnerSmokeEvidenceBundle = smoke_model.model_construct()
    observed: list[bytes] = []

    def revalidate(value: bytes) -> AuthenticatedRunnerSmokeEvidenceBundle:
        observed.append(value)
        return expected

    monkeypatch.setattr(
        cli_module,
        "revalidate_authenticated_runner_smoke_evidence_bytes",
        revalidate,
    )

    assert cli_module._load_authenticated_runner_smoke_evidence_bundle(path) is expected
    assert observed == [raw]

    path.chmod(0o644)
    with pytest.raises(ConfigError, match="owned, private, regular, and unshared"):
        cli_module._load_authenticated_runner_smoke_evidence_bundle(path)


def test_smoke_output_publication_is_fresh_private_and_atomic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    output = private / "bundle.json"
    payload = b'{"synthetic":"smoke"}\n'
    smoke_model: Any = AuthenticatedRunnerSmokeEvidenceBundle
    bundle = smoke_model.model_construct()
    monkeypatch.setattr(
        cli_module,
        "authenticated_runner_smoke_evidence_bytes",
        lambda _bundle: payload,
    )

    assert cli_module._write_authenticated_runner_smoke_output_fresh(output, bundle) == len(payload)
    assert output.read_bytes() == payload
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert output.stat().st_nlink == 1
    with pytest.raises(ConfigError, match="must be fresh"):
        cli_module._write_authenticated_runner_smoke_output_fresh(output, bundle)


def test_smoke_evidence_schema_is_generated_closed_and_non_authorizing() -> None:
    assert MODELS[SCHEMA_NAME] is AuthenticatedRunnerSmokeEvidenceBundle
    path = ROOT / "schemas" / SCHEMA_NAME
    assert path.read_text(encoding="utf-8") == rendered_schema(
        SCHEMA_NAME,
        AuthenticatedRunnerSmokeEvidenceBundle,
    )
    schema = json.loads(path.read_text(encoding="utf-8"))
    assert schema["additionalProperties"] is False
    assert schema["properties"]["purpose"]["const"] == "NONCREDITING_SMOKE"
    assert schema["properties"]["selected_case_count"]["const"] == 1
    assert schema["properties"]["parent_case_count"]["const"] == 24
    assert schema["properties"]["run_count"]["const"] == 2
    assert schema["properties"]["logical_request_count"]["const"] == 4
    assert schema["properties"]["maximum_provider_attempt_count"]["const"] == 8
    sequence = schema["properties"]["execution_sequence_request_ids"]
    assert sequence["minItems"] == 4
    assert sequence["maxItems"] == 4
    assert len(sequence["prefixItems"]) == 4
    for field in (
        "benchmark_authorized",
        "benchmark_scoring_authorized",
        "grants_review_credit",
        "grants_completion_credit",
        "model_qualification_authorized",
        "calibration_authorized",
        "runner_custody_authorized",
        "runner_authority_authorized",
        "authseal_comparison_authorized",
        "seal_publication_authorized",
        "authority_issuance_authorized",
        "release_authorized",
    ):
        assert schema["properties"][field]["const"] is False
