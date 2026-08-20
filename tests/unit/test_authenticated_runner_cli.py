from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import typer
from typer.testing import CliRunner

import mmaudit.cli as cli_module
from mmaudit.config import ConfigError
from mmaudit.constants import ExitCode
from mmaudit.models.authenticated_runner import AuthenticatedCrossLineageRunnerEvidence
from mmaudit.models.authenticated_runner_durable_bundle import (
    AuthenticatedRunnerDurableBundleError,
    AuthenticatedRunnerDurableEvidenceBundle,
    authenticated_runner_durable_bundle_bytes,
)
from mmaudit.models.authenticated_runner_execution import AuthenticatedRunnerExecutionInventory
from mmaudit.models.evidence_seal_authority import (
    EvidenceSealCollisionMap,
    EvidenceSealDecisionProjection,
)
from mmaudit.orchestration.authenticated_runner_openrouter import (
    AuthenticatedRunnerOpenRouterExecutionSnapshot,
    AuthenticatedRunnerOpenRouterLaunch,
    AuthenticatedRunnerOpenRouterResult,
    AuthenticatedRunnerOpenRouterRunSnapshot,
)
from tests.unit.test_authenticated_runner_durable_bundle import _rejected_bundle

RUNNER = CliRunner()


class _SecretPresenceOnly:
    """Context holder with no credential value or credential-value property."""

    openrouter_api_key_present = True

    def __enter__(self) -> _SecretPresenceOnly:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def _required_arguments(
    tmp_path: Path,
    *,
    allow_egress: bool = True,
    include_secret_file: bool = True,
    preflight_only: bool = False,
) -> list[str]:
    arguments = [
        "models",
        "authenticated-runner",
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
        "--qualification-policy",
        str(tmp_path / "qualification-policy.json"),
        "--primary-campaign-journal",
        str(tmp_path / "primary-campaign"),
        "--primary-portfolio",
        str(tmp_path / "primary-portfolio"),
        "--replay-campaign-journal",
        str(tmp_path / "replay-campaign"),
        "--replay-portfolio",
        str(tmp_path / "replay-portfolio"),
        "--output",
        str(tmp_path / "runner-evidence.json"),
        "--candidate-cost-cap-usd-per-attempt",
        "0.01",
        "--primary-judge-cost-cap-usd-per-attempt",
        "0.02",
        "--replay-judge-cost-cap-usd-per-attempt",
        "0.03",
        "--config",
        str(tmp_path / "mmaudit.toml"),
        "--corpus",
        str(tmp_path / "manifest.json"),
        "--ground-truth-provenance",
        str(tmp_path / "provenance.json"),
        "--cost-ledger",
        str(tmp_path / "cost-ledger.json"),
    ]
    if include_secret_file:
        arguments.extend(("--secrets-env-file", str(tmp_path / "operator-secrets.env")))
    arguments.append("--no-color")
    if allow_egress:
        arguments.append("--allow-code-egress")
    if preflight_only:
        arguments.append("--preflight-only")
    return arguments


def _result() -> AuthenticatedRunnerOpenRouterResult:
    evidence = AuthenticatedCrossLineageRunnerEvidence.model_construct(
        evidence_sha256="a" * 64,
        serialized_authority=False,
        runner_custody_authorized=False,
    )
    collision_map = EvidenceSealCollisionMap.model_construct(collision_map_sha256="b" * 64)
    projections = tuple(
        EvidenceSealDecisionProjection.model_construct(
            projection_sha256=digest,
            model_qualification_authorized=False,
            production_selection_authorized=False,
        )
        for digest in ("c" * 64, "d" * 64)
    )
    runs = tuple(
        AuthenticatedRunnerOpenRouterRunSnapshot(
            candidate_report=cast(Any, f"candidate-report-{index}"),
            prepared_adjudication=cast(Any, f"prepared-{index}"),
            adjudication_report=cast(Any, f"adjudication-report-{index}"),
        )
        for index in range(2)
    )
    execution = AuthenticatedRunnerOpenRouterExecutionSnapshot(
        inventory=cast(Any, object()),
        runs=runs,
    )
    return AuthenticatedRunnerOpenRouterResult(
        execution=execution,
        runner_evidence=evidence,
        authseal_collision_map=collision_map,
        authseal_decision_projections=projections,
        authseal_rejection_kind=None,
    )


def _durable_bundle() -> AuthenticatedRunnerDurableEvidenceBundle:
    return AuthenticatedRunnerDurableEvidenceBundle.model_construct(
        schema_version="1.0",
        runner_evidence_sha256="f" * 64,
        closed_ledger_evidence=SimpleNamespace(
            entries=(object(), object()),
            final_spent_usd="0.125",
        ),
        authseal_comparison=SimpleNamespace(status="REJECTED"),
        serialized_authority=False,
        provider_call_authorized=False,
        source_egress_authorized=False,
        runner_custody_authorized=False,
        authority_issuance_authorized=False,
        benchmark_authorized=False,
        model_qualification_authorized=False,
        production_selection_authorized=False,
        seal_publication_authorized=False,
        release_authorized=False,
        bundle_sha256="e" * 64,
    )


def test_verify_authenticated_runner_help_exposes_offline_bundle_input() -> None:
    result = RUNNER.invoke(
        cli_module.app,
        ["models", "verify-authenticated-runner", "--help"],
        env={"COLUMNS": "120"},
    )

    assert result.exit_code == 0
    assert "--bundle" in result.stdout
    assert "nonauthorizing" in result.stdout.lower()


def test_verify_authenticated_runner_is_offline_and_nonauthorizing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _durable_bundle()
    observed: list[Path] = []

    def load(path: Path) -> AuthenticatedRunnerDurableEvidenceBundle:
        observed.append(path)
        return bundle

    def external_state_forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("offline verification must not access external state")

    monkeypatch.setattr(cli_module, "load_authenticated_runner_durable_bundle", load)
    for name in ("load_config", "load_operator_secrets", "_budget_and_usage"):
        monkeypatch.setattr(cli_module, name, external_state_forbidden)

    path = tmp_path / "runner-evidence.json"
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "verify-authenticated-runner",
            "--bundle",
            str(path),
            "--no-color",
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert observed == [path]
    assert "VALID / NONAUTHORIZING" in result.stdout
    assert f"Bundle SHA-256: {bundle.bundle_sha256}" in result.stdout
    assert f"Runner SHA-256: {bundle.runner_evidence_sha256}" in result.stdout
    assert "entries=2; final_spent_usd=0.125" in result.stdout
    assert "AUTHSEAL comparison: REJECTED" in result.stdout


def test_verify_authenticated_runner_replays_real_private_file(tmp_path: Path) -> None:
    bundle = _rejected_bundle()
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    path = parent / "runner-evidence.json"
    path.write_bytes(authenticated_runner_durable_bundle_bytes(bundle))
    path.chmod(0o600)

    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "verify-authenticated-runner",
            "--bundle",
            str(path),
            "--no-color",
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert f"Bundle SHA-256: {bundle.bundle_sha256}" in result.stdout
    assert f"Runner SHA-256: {bundle.runner_evidence_sha256}" in result.stdout
    assert "AUTHSEAL comparison: REJECTED" in result.stdout


def test_verify_authenticated_runner_rejects_invalid_bundle_without_external_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def external_state_forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("offline verification must not access external state")

    monkeypatch.setattr(
        cli_module,
        "load_authenticated_runner_durable_bundle",
        lambda _path: (_ for _ in ()).throw(
            AuthenticatedRunnerDurableBundleError("synthetic invalid durable evidence")
        ),
    )
    for name in ("load_config", "load_operator_secrets", "_budget_and_usage"):
        monkeypatch.setattr(cli_module, name, external_state_forbidden)

    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "verify-authenticated-runner",
            "--bundle",
            str(tmp_path / "invalid.json"),
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "synthetic invalid durable evidence" in " ".join(result.stdout.split())


def _rejected_result() -> AuthenticatedRunnerOpenRouterResult:
    successful = _result()
    return AuthenticatedRunnerOpenRouterResult(
        execution=successful.execution,
        runner_evidence=successful.runner_evidence,
        authseal_collision_map=None,
        authseal_decision_projections=(),
        authseal_rejection_kind="EvidenceSealAuthorityError",
    )


def test_authenticated_runner_help_exposes_explicit_operator_inputs() -> None:
    result = RUNNER.invoke(
        cli_module.app,
        ["models", "authenticated-runner", "--help"],
        env={"COLUMNS": "160"},
    )

    assert result.exit_code == 0
    for option in (
        "--secrets-env-file",
        "--candidate-discovery-run",
        "--primary-judge-discovery-run",
        "--replay-judge-discovery-run",
        "--ground-truth-provenance",
        "--cost-ledger",
        "--allow-code-egress",
        "--preflight-only",
    ):
        assert option in result.stdout


def test_authenticated_runner_requires_opt_in_before_loading_or_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_module,
        "load_config",
        lambda _path: (_ for _ in ()).throw(AssertionError("config must not be loaded")),
    )
    monkeypatch.setattr(
        cli_module,
        "load_operator_secrets",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("secret file must not be accessed")
        ),
    )

    result = RUNNER.invoke(
        cli_module.app,
        _required_arguments(tmp_path, allow_egress=False),
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "requires explicit --allow-code-egress" in " ".join(result.stdout.split())


def test_authenticated_runner_preflight_only_never_selects_secrets_or_mutates_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SimpleNamespace(execution=SimpleNamespace(cost_ledger_path=None))
    ledger = SimpleNamespace(
        path=tmp_path / "cost-ledger.json",
        lock_path=tmp_path / "cost-ledger.json.lock",
    )
    budget = SimpleNamespace(atomic_ledger=ledger)
    captured: dict[str, object] = {}

    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(cli_module, "load_model_benchmark_corpus", lambda _path: object())
    monkeypatch.setattr(
        cli_module,
        "load_frozen_ground_truth_provenance",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        cli_module,
        "resolve_verified_frozen_ground_truth",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        cli_module,
        "resolve_verified_public_model_lineage",
        lambda: object(),
    )
    monkeypatch.setattr(cli_module, "load_candidate_registry", lambda _path: object())
    monkeypatch.setattr(
        cli_module,
        "load_model_discovery_run",
        lambda _path: (object(), (object(),)),
    )
    monkeypatch.setattr(cli_module, "load_qualification_policy", lambda _path: object())
    monkeypatch.setattr(cli_module, "_require_qualification_release_pins", lambda **_kw: None)
    monkeypatch.setattr(
        cli_module,
        "_budget_and_usage",
        lambda *_args, **_kwargs: (budget, object()),
    )

    def paths(**kwargs: object) -> None:
        captured["source_paths"] = kwargs["source_paths"]

    monkeypatch.setattr(cli_module, "_preflight_authenticated_runner_cli_paths", paths)
    monkeypatch.setattr(cli_module, "_preflight_authenticated_runner_output", lambda _path: None)
    inventory = AuthenticatedRunnerExecutionInventory(
        run_count=2,
        case_count=24,
        candidate_logical_request_count=48,
        judge_logical_request_count=48,
        logical_request_count=96,
        maximum_attempts_per_logical_request=2,
        maximum_provider_attempt_count=192,
        generation_refetch_count=96,
        effective_config_sha256="a" * 64,
        initial_spent_usd=Decimal("0.0034764325"),
        declared_interval_cost_cap_usd=Decimal("192.00"),
        declared_final_spent_cap_usd=Decimal("192.0034764325"),
    )
    monkeypatch.setattr(
        cli_module,
        "preflight_authenticated_openrouter_launch",
        lambda _launch: inventory,
    )

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("preflight-only must not select secrets, execute, or publish")

    for name in (
        "select_operator_secret_file",
        "load_operator_secrets",
        "execute_authenticated_openrouter_runner",
        "build_authenticated_runner_durable_bundle",
        "_write_authenticated_runner_output_fresh",
    ):
        monkeypatch.setattr(cli_module, name, forbidden)

    result = RUNNER.invoke(
        cli_module.app,
        _required_arguments(tmp_path, preflight_only=True),
        env={"MMAUDIT_SECRETS_ENV_FILE": str(tmp_path / "different-secret.env")},
    )

    assert result.exit_code == 0, result.stdout
    assert "VALID / NONAUTHORIZING / NO PROVIDER EGRESS" in result.stdout
    assert "logical_requests=96" in result.stdout
    assert "maximum_provider_attempts=192" in result.stdout
    assert "declared_interval_cap_usd=192.00" in result.stdout
    assert "declared_final_spent_cap_usd=192.0034764325" in result.stdout
    source_paths = cast(tuple[Path, ...], captured["source_paths"])
    assert tmp_path / "operator-secrets.env" not in source_paths
    assert tmp_path / "different-secret.env" not in source_paths
    for name in (
        "primary-campaign",
        "primary-portfolio",
        "replay-campaign",
        "replay-portfolio",
        "runner-evidence.json",
    ):
        assert not (tmp_path / name).exists()


@pytest.mark.parametrize("explicit_secret", (True, False))
@pytest.mark.parametrize("authseal_reject", (False, True))
def test_authenticated_runner_preflights_before_secret_and_writes_only_durable_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    explicit_secret: bool,
    authseal_reject: bool,
) -> None:
    events: list[str] = []
    config = SimpleNamespace(execution=SimpleNamespace(cost_ledger_path=None))
    suite = object()
    provenance = object()
    ground_truth = object()
    public_lineage = object()
    policy = object()
    candidate_registry = object()
    primary_registry = object()
    replay_registry = object()
    candidate_manifest = object()
    primary_manifest = object()
    replay_manifest = object()
    candidate_evidence = (object(),)
    primary_evidence = (object(),)
    replay_evidence = (object(),)
    ledger = SimpleNamespace(
        path=tmp_path / "cost-ledger.json",
        lock_path=tmp_path / "cost-ledger.json.lock",
    )
    budget = SimpleNamespace(atomic_ledger=ledger)
    usage = object()
    captured: dict[str, Any] = {}

    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(cli_module, "load_model_benchmark_corpus", lambda _path: suite)
    monkeypatch.setattr(
        cli_module,
        "load_frozen_ground_truth_provenance",
        lambda _path: provenance,
    )
    monkeypatch.setattr(
        cli_module,
        "resolve_verified_frozen_ground_truth",
        lambda **_kwargs: ground_truth,
    )
    monkeypatch.setattr(
        cli_module,
        "resolve_verified_public_model_lineage",
        lambda: public_lineage,
    )

    def load_registry(path: Path) -> object:
        if "primary" in path.name:
            return primary_registry
        if "replay" in path.name:
            return replay_registry
        return candidate_registry

    def load_discovery(path: Path) -> tuple[object, tuple[object, ...]]:
        if "primary" in path.name:
            return primary_manifest, primary_evidence
        if "replay" in path.name:
            return replay_manifest, replay_evidence
        return candidate_manifest, candidate_evidence

    monkeypatch.setattr(cli_module, "load_candidate_registry", load_registry)
    monkeypatch.setattr(cli_module, "load_model_discovery_run", load_discovery)
    monkeypatch.setattr(cli_module, "load_qualification_policy", lambda _path: policy)
    monkeypatch.setattr(cli_module, "_require_qualification_release_pins", lambda **_kw: None)
    monkeypatch.setattr(
        cli_module,
        "_budget_and_usage",
        lambda *_args, **_kwargs: (budget, usage),
    )

    def preflight_paths(**kwargs: object) -> None:
        events.append("paths")
        captured["source_paths"] = kwargs["source_paths"]

    monkeypatch.setattr(
        cli_module,
        "_preflight_authenticated_runner_cli_paths",
        preflight_paths,
    )
    monkeypatch.setattr(
        cli_module,
        "_preflight_authenticated_runner_output",
        lambda _path: events.append("output-preflight"),
    )

    def preflight(launch: AuthenticatedRunnerOpenRouterLaunch) -> object:
        events.append("launch-preflight")
        captured["launch"] = launch
        return object()

    monkeypatch.setattr(cli_module, "preflight_authenticated_openrouter_launch", preflight)

    def load_secrets(path: Path | None, *, required: bool) -> _SecretPresenceOnly:
        events.append("secret")
        assert path == tmp_path / "operator-secrets.env"
        assert required is True
        return _SecretPresenceOnly()

    monkeypatch.setattr(cli_module, "load_operator_secrets", load_secrets)

    async def execute_runner(**kwargs: object) -> AuthenticatedRunnerOpenRouterResult:
        events.append("execute")
        captured.update(kwargs)
        return _rejected_result() if authseal_reject else _result()

    monkeypatch.setattr(cli_module, "execute_authenticated_openrouter_runner", execute_runner)

    durable_bundle = _durable_bundle()

    def build_bundle(**kwargs: object) -> AuthenticatedRunnerDurableEvidenceBundle:
        events.append("bundle")
        captured["bundle_inputs"] = kwargs
        return durable_bundle

    monkeypatch.setattr(cli_module, "build_authenticated_runner_durable_bundle", build_bundle)

    def write_output(path: Path, value: AuthenticatedRunnerDurableEvidenceBundle) -> int:
        events.append("write")
        captured["output_path"] = path
        captured["output"] = value
        return 1

    monkeypatch.setattr(cli_module, "_write_authenticated_runner_output_fresh", write_output)

    result = RUNNER.invoke(
        cli_module.app,
        _required_arguments(tmp_path, include_secret_file=explicit_secret),
        env=(
            {"MMAUDIT_SECRETS_ENV_FILE": ""}
            if explicit_secret
            else {"MMAUDIT_SECRETS_ENV_FILE": str(tmp_path / "operator-secrets.env")}
        ),
    )

    if authseal_reject:
        assert result.exit_code == ExitCode.CONFIGURATION
        assert "nonauthorizing runner evidence was retained" in " ".join(result.stdout.split())
    else:
        assert result.exit_code == 0, result.stdout
    assert events == [
        "paths",
        "output-preflight",
        "launch-preflight",
        "secret",
        "execute",
        "bundle",
        "output-preflight",
        "write",
    ]
    launch = cast(AuthenticatedRunnerOpenRouterLaunch, captured["launch"])
    assert launch.explicitly_allow_synthetic_egress is True
    assert launch.run_plans[0].candidate_declared_cost_cap_usd_per_attempt.as_tuple().exponent == -2
    assert launch.run_plans[1].judge_declared_cost_cap_usd_per_attempt.as_tuple().exponent == -2
    assert captured["operator_secrets"].openrouter_api_key_present is True
    assert tmp_path / "operator-secrets.env" in captured["source_paths"]
    assert captured["output"] is durable_bundle
    bundle_inputs = cast(dict[str, object], captured["bundle_inputs"])
    assert set(bundle_inputs) == {
        "runner_evidence",
        "candidate_reports",
        "prepared_runs",
        "adjudication_reports",
        "authseal_collision_map",
        "authseal_decision_projections",
        "authseal_rejection_kind",
    }
    assert "EXECUTION-CAPABILITY-CANARY" not in repr(bundle_inputs)


def test_authenticated_runner_cli_path_preflight_rejects_output_inside_source() -> None:
    root = Path("/private/tmp/mmaudit-authrunner-cli-path-test")
    source = root / "candidate-discovery"

    with pytest.raises(ConfigError, match="overlaps immutable input"):
        cli_module._preflight_authenticated_runner_cli_paths(
            mutable_outputs=(
                source / "campaign",
                root / "primary-portfolio",
                root / "replay-campaign",
                root / "replay-portfolio",
                root / "runner-evidence.json",
            ),
            source_paths=(source,),
        )


def test_authenticated_runner_output_preflight_requires_fresh_private_leaf(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    output = private / "runner-evidence.json"

    cli_module._preflight_authenticated_runner_output(output)
    output.write_text("occupied\n", encoding="utf-8")
    output.chmod(0o600)
    with pytest.raises(ConfigError, match="must be fresh"):
        cli_module._preflight_authenticated_runner_output(output)


def test_authenticated_runner_output_preflight_exercises_hard_link_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    output = private / "runner-evidence.json"

    def reject_link(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("synthetic hard-link rejection")

    monkeypatch.setattr(cli_module.os, "link", reject_link)
    monkeypatch.setattr(
        cli_module.os,
        "supports_dir_fd",
        cli_module.os.supports_dir_fd | {reject_link},
    )
    monkeypatch.setattr(
        cli_module.os,
        "supports_follow_symlinks",
        cli_module.os.supports_follow_symlinks | {reject_link},
    )

    with pytest.raises(ConfigError, match="unavailable, linked, or not writable"):
        cli_module._preflight_authenticated_runner_output(output)

    assert not output.exists()


def test_authenticated_runner_output_publication_is_fresh_private_and_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    output = private / "runner-evidence.json"
    bundle = _durable_bundle()
    payload = b'{"bundle_sha256":"' + (b"e" * 64) + b'","serialized_authority":false}'
    monkeypatch.setattr(
        cli_module,
        "authenticated_runner_durable_bundle_bytes",
        lambda value: payload if value is bundle else b"wrong",
    )

    written = cli_module._write_authenticated_runner_output_fresh(output, bundle)

    assert written == output.stat().st_size
    assert output.stat().st_mode & 0o777 == 0o600
    assert output.read_bytes() == payload


def test_authenticated_runner_output_publication_never_clobbers_intervening_leaf(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    output = private / "runner-evidence.json"
    original_preflight = cli_module._preflight_authenticated_runner_output
    bundle = _durable_bundle()
    monkeypatch.setattr(
        cli_module,
        "authenticated_runner_durable_bundle_bytes",
        lambda value: b"{}" if value is bundle else b"wrong",
    )

    def racing_preflight(path: Path) -> None:
        original_preflight(path)
        output.write_text("operator-owned\n", encoding="utf-8")
        output.chmod(0o600)

    monkeypatch.setattr(
        cli_module,
        "_preflight_authenticated_runner_output",
        racing_preflight,
    )

    with pytest.raises(ConfigError, match="must remain fresh"):
        cli_module._write_authenticated_runner_output_fresh(
            output,
            bundle,
        )

    assert output.read_text(encoding="utf-8") == "operator-owned\n"


def test_authenticated_runner_output_publication_rejects_parent_namespace_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    moved = tmp_path / "moved-private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    output = private / "runner-evidence.json"
    bundle = _durable_bundle()
    real_link = cli_module.os.link

    monkeypatch.setattr(
        cli_module,
        "authenticated_runner_durable_bundle_bytes",
        lambda value: b"{}" if value is bundle else b"wrong",
    )
    monkeypatch.setattr(cli_module, "_preflight_authenticated_runner_output", lambda _path: None)

    def move_parent_after_link(*args: object, **kwargs: object) -> None:
        real_link(*args, **kwargs)
        private.rename(moved)

    monkeypatch.setattr(cli_module.os, "link", move_parent_after_link)
    monkeypatch.setattr(
        cli_module.os,
        "supports_dir_fd",
        cli_module.os.supports_dir_fd | {move_parent_after_link},
    )
    monkeypatch.setattr(
        cli_module.os,
        "supports_follow_symlinks",
        cli_module.os.supports_follow_symlinks | {move_parent_after_link},
    )

    with pytest.raises(ConfigError, match="publication failed safely"):
        cli_module._write_authenticated_runner_output_fresh(output, bundle)

    assert not output.exists()
    assert (moved / output.name).read_bytes() == b"{}"


def test_authenticated_runner_output_rollback_never_deletes_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    moved = tmp_path / "moved-private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    output = private / "runner-evidence.json"
    bundle = _durable_bundle()
    real_link = cli_module.os.link

    monkeypatch.setattr(
        cli_module,
        "authenticated_runner_durable_bundle_bytes",
        lambda value: b"{}" if value is bundle else b"wrong",
    )
    monkeypatch.setattr(cli_module, "_preflight_authenticated_runner_output", lambda _path: None)

    def replace_after_parent_move(*args: object, **kwargs: object) -> None:
        real_link(*args, **kwargs)
        private.rename(moved)
        replacement = moved / output.name
        replacement.unlink()
        replacement.write_text("operator-owned\n", encoding="utf-8")
        replacement.chmod(0o600)

    monkeypatch.setattr(cli_module.os, "link", replace_after_parent_move)
    monkeypatch.setattr(
        cli_module.os,
        "supports_dir_fd",
        cli_module.os.supports_dir_fd | {replace_after_parent_move},
    )
    monkeypatch.setattr(
        cli_module.os,
        "supports_follow_symlinks",
        cli_module.os.supports_follow_symlinks | {replace_after_parent_move},
    )

    with pytest.raises(ConfigError, match="publication failed safely"):
        cli_module._write_authenticated_runner_output_fresh(output, bundle)

    assert not output.exists()
    assert (moved / output.name).read_text(encoding="utf-8") == "operator-owned\n"


def test_authenticated_runner_cost_ledger_override_must_match_configured_path(
    tmp_path: Path,
) -> None:
    configured = (tmp_path / "configured-ledger.json").resolve()
    override = (tmp_path / "other-ledger.json").resolve()
    config = SimpleNamespace(
        execution=SimpleNamespace(cost_ledger_path=str(configured)),
    )

    with pytest.raises(ConfigError, match="differs from configured ledger"):
        cli_module._selected_cost_ledger_path(cast(Any, config), override)


def test_async_cli_preserves_bracketed_rejection_text_verbatim(
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def reject() -> None:
        raise ConfigError("[bold]endpoint[/bold]")

    with pytest.raises(typer.Exit):
        cli_module._run_async_cli(reject)

    assert "[bold]endpoint[/bold]" in capsys.readouterr().out


@pytest.mark.parametrize("rejected", [False, True], ids=["complete", "rejected"])
def test_authenticated_runner_durable_output_delegates_exact_retained_runs(
    monkeypatch: pytest.MonkeyPatch,
    rejected: bool,
) -> None:
    result = _rejected_result() if rejected else _result()
    expected = _durable_bundle()
    observed: dict[str, object] = {}

    def build(**kwargs: object) -> AuthenticatedRunnerDurableEvidenceBundle:
        observed.update(kwargs)
        return expected

    monkeypatch.setattr(cli_module, "build_authenticated_runner_durable_bundle", build)

    output = cli_module._authenticated_runner_durable_output(result)

    assert output is expected
    assert observed["runner_evidence"] is result.runner_evidence
    assert observed["candidate_reports"] == (
        "candidate-report-0",
        "candidate-report-1",
    )
    assert observed["prepared_runs"] == ("prepared-0", "prepared-1")
    assert observed["adjudication_reports"] == (
        "adjudication-report-0",
        "adjudication-report-1",
    )
    assert observed["authseal_collision_map"] is result.authseal_collision_map
    assert observed["authseal_decision_projections"] == result.authseal_decision_projections
    assert observed["authseal_rejection_kind"] == result.authseal_rejection_kind
    assert "EXECUTION-CAPABILITY-CANARY" not in repr(observed)
