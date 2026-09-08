from __future__ import annotations

import stat
from collections.abc import Callable
from decimal import Decimal
from pathlib import Path

import pytest
from typer.testing import CliRunner

import mmaudit.cli as cli_module
from mmaudit.config import AuditConfig
from mmaudit.constants import ExitCode
from mmaudit.isolation.dependency_snapshot import build_managed_dependency_snapshot
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.managed_provisioning import (
    ManagedProvisioningAction,
    ManagedProvisioningObservationStatus,
    ManagedProvisioningRefusalCode,
    ManagedProvisioningState,
    parse_managed_provisioning_receipt,
)
from tests.dependency_snapshot_support import setup_snapshot_inputs

RUNNER = CliRunner()


def test_automatic_cli_reports_missing_material_as_incomplete_without_creating_it(
    tmp_path, config_factory, monkeypatch
):
    repository, archives, advisories, digest = setup_snapshot_inputs(tmp_path)
    output = _private_directory(tmp_path / "receipts")
    _patch_config(monkeypatch, config_factory())
    args = [
        *_arguments(repository, output, verify_only=True),
        "--archive-root",
        str(archives),
        "--advisory-path",
        str(advisories),
        "--advisory-sha256",
        digest,
    ]
    result = RUNNER.invoke(cli_module.app, args)
    assert result.exit_code == ExitCode.INCOMPLETE, result.output
    assert "no authority granted" in result.output
    assert list(output.iterdir()) == []
    assert not (repository / ".mmaudit").exists()


@pytest.mark.parametrize("mask", range(1, 7))
def test_automatic_cli_refuses_partial_local_source_selection_before_config_load(
    tmp_path, monkeypatch, mask
):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("partial source selection must fail before configuration or writes")

    monkeypatch.setattr(cli_module, "load_config", forbidden)
    args = _arguments(tmp_path / "repo", tmp_path / "receipts")
    options = [
        ("--archive-root", str(tmp_path / "archives")),
        ("--advisory-path", str(tmp_path / "advisories.json")),
        ("--advisory-sha256", "a" * 64),
    ]
    for index, pair in enumerate(options):
        if mask & (1 << index):
            args.extend(pair)
    result = RUNNER.invoke(cli_module.app, args)
    assert result.exit_code == ExitCode.CONFIGURATION, result.output
    assert not (tmp_path / "receipts").exists()


def test_cli_consumes_configured_dependency_material_but_still_exits_incomplete(
    tmp_path, config_factory, monkeypatch
):
    repository, archives, advisories, digest = setup_snapshot_inputs(tmp_path)
    built = build_managed_dependency_snapshot(
        repository=repository,
        archive_root=archives,
        advisory_path=advisories,
        advisory_sha256=digest,
    )
    output = _private_directory(tmp_path / "receipts")
    config = config_factory(dependency_preparation=built.config.model_dump())
    seen = _patch_config(monkeypatch, config)
    result = RUNNER.invoke(
        app=cli_module.app, args=_arguments(repository, output, verify_only=True)
    )
    assert result.exit_code == ExitCode.INCOMPLETE, result.output
    assert seen == [{}]
    receipt = parse_managed_provisioning_receipt(next(output.iterdir()).read_bytes())
    assert receipt.state.verified_requirement_ids == ("dependency-snapshot",)
    assert receipt.managed_run_ready is False


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _config(
    config_factory: Callable[..., AuditConfig],
    ledger_path: Path,
    *,
    budget_usd: float = 20.0,
) -> AuditConfig:
    return config_factory(
        execution={
            "cost_ledger_path": str(ledger_path),
            "budget_usd": budget_usd,
        }
    )


def _arguments(repository: Path, output_dir: Path, *, verify_only: bool = False) -> list[str]:
    arguments = [
        "managed",
        "provision",
        "--output-dir",
        str(output_dir),
        "--repo",
        str(repository),
        "--config",
        str(repository / "unused.toml"),
        "--no-color",
    ]
    if verify_only:
        arguments.append("--verify-only")
    return arguments


def _patch_config(
    monkeypatch: pytest.MonkeyPatch,
    config: AuditConfig,
) -> list[dict[str, str]]:
    observed_environments: list[dict[str, str]] = []

    def load_config(_path: Path, *, environ: dict[str, str]) -> AuditConfig:
        observed_environments.append(environ)
        return config

    monkeypatch.setattr(cli_module, "load_config", load_config)

    def forbidden_secret(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("managed provisioning must not access operator secrets")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret)
    monkeypatch.setattr(cli_module, "select_operator_secret_file", forbidden_secret)
    return observed_environments


def _states(output_dir: Path) -> list[ManagedProvisioningState]:
    return [
        parse_managed_provisioning_receipt(path.read_bytes()).state
        for path in sorted(output_dir.glob("managed-provisioning-receipt-*.json"))
    ]


def test_managed_provision_creates_then_reopens_exact_ledger_idempotently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    ledger_parent = _private_directory(tmp_path / "ledger")
    output_dir = _private_directory(tmp_path / "receipts")
    repository = _private_directory(tmp_path / "repo")
    ledger_path = ledger_parent / "costs.json"
    environments = _patch_config(monkeypatch, _config(config_factory, ledger_path))
    arguments = _arguments(repository, output_dir)

    first = RUNNER.invoke(cli_module.app, arguments)
    retained_ledger = ledger_path.read_bytes()
    retained_lock = (ledger_parent / ".costs.json.lock").stat()
    second = RUNNER.invoke(cli_module.app, arguments)
    third = RUNNER.invoke(cli_module.app, arguments)

    assert first.exit_code == ExitCode.INCOMPLETE
    assert second.exit_code == ExitCode.INCOMPLETE
    assert third.exit_code == ExitCode.INCOMPLETE
    assert environments == [{}, {}, {}]
    assert ledger_path.read_bytes() == retained_ledger
    current_lock = (ledger_parent / ".costs.json.lock").stat()
    assert (current_lock.st_dev, current_lock.st_ino, stat.S_IMODE(current_lock.st_mode)) == (
        retained_lock.st_dev,
        retained_lock.st_ino,
        0o600,
    )
    states = _states(output_dir)
    assert len(states) == 2
    assert {state.observations.cost_ledger.action for state in states} == {
        ManagedProvisioningAction.CREATED,
        ManagedProvisioningAction.VERIFIED_EXISTING,
    }
    assert all(state.runtime_authority is False for state in states)
    assert all(state.managed_run_ready is False for state in states)
    assert "receipt=" in first.stdout
    assert str(ledger_path) not in first.stdout


def test_managed_provision_verify_only_refuses_missing_ledger_without_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    ledger_parent = _private_directory(tmp_path / "ledger")
    output_dir = _private_directory(tmp_path / "receipts")
    repository = _private_directory(tmp_path / "repo")
    ledger_path = ledger_parent / "costs.json"
    _patch_config(monkeypatch, _config(config_factory, ledger_path))

    result = RUNNER.invoke(
        cli_module.app,
        _arguments(repository, output_dir, verify_only=True),
    )

    assert result.exit_code == ExitCode.INCOMPLETE
    assert not ledger_path.exists()
    assert not (ledger_parent / ".costs.json.lock").exists()
    state = _states(output_dir)[0]
    assert state.observations.cost_ledger.status is ManagedProvisioningObservationStatus.REFUSED
    assert (
        state.observations.cost_ledger.refusal_code
        is ManagedProvisioningRefusalCode.INVALID_LOCAL_STATE
    )


def test_managed_provision_refuses_cap_mismatch_without_mutating_existing_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    ledger_parent = _private_directory(tmp_path / "ledger")
    output_dir = _private_directory(tmp_path / "receipts")
    repository = _private_directory(tmp_path / "repo")
    ledger_path = ledger_parent / "costs.json"
    ledger = AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("1"))
    retained_bytes = ledger_path.read_bytes()
    retained_state = ledger_path.stat()
    retained_lock = ledger.lock_path.stat()
    _patch_config(monkeypatch, _config(config_factory, ledger_path, budget_usd=2.0))

    result = RUNNER.invoke(cli_module.app, _arguments(repository, output_dir))

    assert result.exit_code == ExitCode.INCOMPLETE
    assert ledger_path.read_bytes() == retained_bytes
    current_state = ledger_path.stat()
    current_lock = ledger.lock_path.stat()
    assert (current_state.st_dev, current_state.st_ino, current_state.st_mode) == (
        retained_state.st_dev,
        retained_state.st_ino,
        retained_state.st_mode,
    )
    assert (current_lock.st_dev, current_lock.st_ino, current_lock.st_mode) == (
        retained_lock.st_dev,
        retained_lock.st_ino,
        retained_lock.st_mode,
    )
    state = _states(output_dir)[0]
    assert (
        state.observations.cost_ledger.refusal_code
        is ManagedProvisioningRefusalCode.INVALID_LOCAL_STATE
    )


def test_managed_provision_refuses_unprivate_output_before_ledger_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    ledger_parent = _private_directory(tmp_path / "ledger")
    output_dir = _private_directory(tmp_path / "receipts")
    repository = _private_directory(tmp_path / "repo")
    output_dir.chmod(0o755)
    ledger_path = ledger_parent / "costs.json"
    _patch_config(monkeypatch, _config(config_factory, ledger_path))

    result = RUNNER.invoke(cli_module.app, _arguments(repository, output_dir))

    assert result.exit_code == ExitCode.CONFIGURATION
    assert not ledger_path.exists()
    assert not (ledger_parent / ".costs.json.lock").exists()
    assert str(output_dir) not in result.stdout


def test_managed_provision_help_exposes_only_local_nonauthorizing_inputs() -> None:
    result = RUNNER.invoke(
        cli_module.app,
        ["managed", "provision", "--help"],
        env={"COLUMNS": "180"},
    )

    assert result.exit_code == ExitCode.SUCCESS
    for option in ("--output-dir", "--repo", "--config", "--verify-only", "--no-color"):
        assert option in result.stdout
    for forbidden in ("secret", "provider", "egress", "api-key", "rpc"):
        assert forbidden not in result.stdout.lower()
