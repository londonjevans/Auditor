from __future__ import annotations

import stat
from collections.abc import Callable
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import mmaudit.cli as cli_module
from mmaudit.benchmark.model_portfolio import (
    TrustedCandidateBenchmarkCampaignVerification,
)
from mmaudit.config import AuditConfig, ConfigError
from mmaudit.constants import ExitCode
from mmaudit.models.calibration import (
    ModelCalibrationArtifact,
    load_model_calibration_artifact,
)
from mmaudit.models.candidate_benchmark import (
    CandidateBenchmarkExecutionResult,
    run_candidate_registry_benchmarks,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.unit import test_candidate_benchmark as candidate_fixtures
from tests.unit import test_candidate_benchmark_cli as cli_fixtures

runner = CliRunner()


def _open_ledger(tmp_path: Path, config: AuditConfig) -> AtomicCostLedger:
    return AtomicCostLedger.open_existing(
        cli_fixtures._ledger(tmp_path, config),
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )


def test_calibration_output_requires_candidate_registry_mode_before_config_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_module,
        "load_config",
        lambda _path: (_ for _ in ()).throw(AssertionError("configuration must not be loaded")),
    )

    result = runner.invoke(
        cli_module.app,
        [
            "models",
            "benchmark",
            "--calibration-output",
            str(tmp_path / "calibration.json"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "candidate campaign options require candidate-registry mode" in " ".join(
        result.output.split()
    )


def test_calibration_output_rejects_resumed_campaign_before_config_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_module,
        "load_config",
        lambda _path: (_ for _ in ()).throw(AssertionError("configuration must not be loaded")),
    )

    result = runner.invoke(
        cli_module.app,
        [
            "models",
            "benchmark",
            "--candidate-registry",
            str(tmp_path / "candidates.toml"),
            "--discovery-run",
            str(tmp_path / "discovery"),
            "--campaign-journal",
            str(tmp_path / "campaign"),
            "--qualification-policy",
            str(tmp_path / "policy.toml"),
            "--calibration-output",
            str(tmp_path / "calibration.json"),
            "--resume-campaign",
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "calibration requires one fresh same-process candidate campaign" in " ".join(
        result.output.split()
    )


def test_calibration_preflight_rejects_existing_output(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = cli_fixtures._pending_config(config_factory)
    ledger = _open_ledger(tmp_path, config)
    output = tmp_path / "calibration.json"
    output.touch()

    with pytest.raises(ConfigError, match="fresh file"):
        cli_module._preflight_model_calibration_output(
            output,
            ledger=ledger,
            portfolio_output=tmp_path / "portfolio",
            campaign_journal=tmp_path / "campaign",
        )


@pytest.mark.parametrize("protected_name", ["portfolio", "campaign"])
def test_calibration_preflight_rejects_protected_path_collision(
    protected_name: str,
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = cli_fixtures._pending_config(config_factory)
    ledger = _open_ledger(tmp_path, config)
    protected = tmp_path / protected_name

    with pytest.raises(ConfigError, match="must be distinct"):
        cli_module._preflight_model_calibration_output(
            protected,
            ledger=ledger,
            portfolio_output=tmp_path / "portfolio",
            campaign_journal=tmp_path / "campaign",
        )


def test_calibration_preflight_rejects_nested_protected_path(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = cli_fixtures._pending_config(config_factory)
    ledger = _open_ledger(tmp_path, config)

    with pytest.raises(ConfigError, match="must be distinct"):
        cli_module._preflight_model_calibration_output(
            tmp_path / "portfolio" / "calibration.json",
            ledger=ledger,
            portfolio_output=tmp_path / "portfolio",
            campaign_journal=tmp_path / "campaign",
        )


def test_calibration_preflight_rejects_symlink_traversal(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = cli_fixtures._pending_config(config_factory)
    ledger = _open_ledger(tmp_path, config)
    actual = tmp_path / "actual"
    actual.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)

    with pytest.raises(ConfigError, match="may not traverse"):
        cli_module._preflight_model_calibration_output(
            linked / "calibration.json",
            ledger=ledger,
            portfolio_output=tmp_path / "portfolio",
            campaign_journal=tmp_path / "campaign",
        )


def test_candidate_campaign_emits_calibration_from_live_trusted_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    tmp_path.chmod(0o700)
    config = cli_fixtures._pending_config(config_factory)
    manifest, evidence, registry, suite = cli_fixtures._inputs(
        tmp_path=tmp_path / "inputs",
        config=config,
    )
    cli_fixtures._patch_inputs(
        monkeypatch,
        config=config,
        manifest=manifest,
        evidence=evidence,
        registry=registry,
        suite=suite,
    )
    factory = candidate_fixtures._MockClientFactory()

    async def dispatch(**kwargs: Any) -> CandidateBenchmarkExecutionResult:
        return await run_candidate_registry_benchmarks(
            **kwargs,
            client_factory=factory,
        )

    monkeypatch.setattr(cli_module, "run_candidate_registry_benchmarks", dispatch)
    actual_issue = cli_module.issue_trusted_candidate_benchmark_campaign_verification
    actual_build = cli_module.build_model_calibration_artifact
    captured: dict[str, object] = {}

    def issue_capability(**kwargs: Any) -> TrustedCandidateBenchmarkCampaignVerification:
        capability = actual_issue(**kwargs)
        captured["capability"] = capability
        return capability

    def build_calibration(**kwargs: Any) -> ModelCalibrationArtifact:
        assert kwargs["trusted_campaign_verification"] is captured["capability"]
        artifact = actual_build(**kwargs)
        captured["artifact"] = artifact
        return artifact

    monkeypatch.setattr(
        cli_module,
        "issue_trusted_candidate_benchmark_campaign_verification",
        issue_capability,
    )
    monkeypatch.setattr(
        cli_module,
        "build_model_calibration_artifact",
        build_calibration,
    )
    calibration_output = tmp_path / "calibration.json"
    arguments = cli_fixtures._candidate_args(
        tmp_path=tmp_path,
        output=tmp_path / "portfolio",
        ledger=cli_fixtures._ledger(tmp_path, config),
        secret_file=cli_fixtures._secret_file(tmp_path),
        allow_egress=True,
    )
    arguments.extend(("--calibration-output", str(calibration_output)))

    result = runner.invoke(
        cli_module.app,
        arguments,
        env={"MMAUDIT_SECRETS_ENV_FILE": ""},
    )

    artifact = load_model_calibration_artifact(calibration_output)
    assert result.exit_code == ExitCode.MODEL_FAILURE
    assert isinstance(
        captured["capability"],
        TrustedCandidateBenchmarkCampaignVerification,
    )
    assert artifact == captured["artifact"]
    assert not artifact.candidates[0].included_in_distribution
    assert stat.S_IMODE(calibration_output.stat().st_mode) == 0o600
    assert "Calibration:" in result.output
    assert cli_fixtures.CANARY not in result.output
    assert cli_fixtures.CANARY.encode() not in calibration_output.read_bytes()
