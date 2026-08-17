from __future__ import annotations

import stat
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

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
    TrustedModelCalibrationVerification,
    load_calibrated_qualification_policy,
    load_model_calibration_artifact,
)
from mmaudit.models.candidate_benchmark import (
    CandidateBenchmarkExecutionResult,
    run_candidate_registry_benchmarks,
)
from mmaudit.models.lineage_authority import write_model_lineage_authority_envelope
from mmaudit.models.refresh import (
    build_model_refresh_snapshot_from_source,
    build_model_refresh_source_evidence,
    evaluate_model_refresh_freshness,
)
from mmaudit.release_io import write_json_evidence
from tests.unit import test_candidate_benchmark as candidate_fixtures
from tests.unit import test_candidate_benchmark_cli as cli_fixtures
from tests.unit import test_model_lineage_authority as lineage_authority_fixtures
from tests.unit import test_model_lineage_review as lineage_fixtures
from tests.unit import test_qualification_policy_calibration as policy_fixtures

runner = CliRunner()


class _RecordingLineageCapability:
    def __init__(self, events: list[str], *, reject_join: bool = False) -> None:
        self.events = events
        self.reject_join = reject_join
        self.join_arguments: dict[str, object] | None = None

    def require_for(self, **kwargs: object) -> object:
        self.events.append("lineage_join")
        self.join_arguments = kwargs
        if self.reject_join:
            raise ValueError("synthetic lineage exact join rejected")
        return object()


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


@pytest.mark.parametrize(
    "selected_options",
    [
        ("--calibration-output",),
        ("--lineage-review-bundle",),
        ("--lineage-trust-anchor",),
        ("--calibration-output", "--lineage-review-bundle"),
        ("--calibration-output", "--lineage-trust-anchor"),
        ("--lineage-review-bundle", "--lineage-trust-anchor"),
    ],
)
def test_calibration_lineage_inputs_must_be_supplied_exactly_together_before_config_load(
    selected_options: tuple[str, ...],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_module,
        "load_config",
        lambda _path: (_ for _ in ()).throw(AssertionError("configuration must not be loaded")),
    )
    arguments = [
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
    ]
    for option in selected_options:
        arguments.extend((option, str(tmp_path / option.removeprefix("--"))))
    arguments.append("--no-color")

    result = runner.invoke(cli_module.app, arguments)

    assert result.exit_code == ExitCode.CONFIGURATION
    assert (
        "--calibration-output, --lineage-review-bundle, and --lineage-trust-anchor "
        "must be supplied together"
    ) in " ".join(result.output.split())


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
            "--lineage-review-bundle",
            str(tmp_path / "lineage-review"),
            "--lineage-trust-anchor",
            str(tmp_path / "lineage-trust-anchor.json"),
            "--resume-campaign",
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "calibration requires one fresh same-process candidate campaign" in " ".join(
        result.output.split()
    )


def test_calibrated_policy_output_requires_same_campaign_calibration_before_config_load(
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
            "--calibrated-policy-output",
            str(tmp_path / "calibrated-policy.json"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "requires --calibration-output from the same campaign" in " ".join(result.output.split())


@pytest.mark.parametrize(
    "protected_name",
    ["ledger.json", ".ledger.json.lock", "portfolio", "campaign", "calibration.json"],
)
def test_calibrated_policy_preflight_rejects_every_protected_path(
    protected_name: str,
    tmp_path: Path,
) -> None:
    with pytest.raises(ConfigError, match="must be distinct"):
        cli_module._preflight_calibrated_policy_output(
            tmp_path / protected_name,
            cost_ledger_path=tmp_path / "ledger.json",
            portfolio_output=tmp_path / "portfolio",
            campaign_journal=tmp_path / "campaign",
            calibration_output=tmp_path / "calibration.json",
        )


def test_calibrated_policy_preflight_rejects_existing_output(
    tmp_path: Path,
) -> None:
    output = tmp_path / "calibrated-policy.json"
    output.touch()

    with pytest.raises(ConfigError, match="fresh file"):
        cli_module._preflight_calibrated_policy_output(
            output,
            cost_ledger_path=tmp_path / "ledger.json",
            portfolio_output=tmp_path / "portfolio",
            campaign_journal=tmp_path / "campaign",
            calibration_output=tmp_path / "calibration.json",
        )


def test_calibrated_policy_preflight_fails_before_ledger_secrets_or_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
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
    policy_output = tmp_path / "calibrated-policy.json"
    policy_output.touch()

    def forbidden(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("ledger, secrets, and provider work must remain untouched")

    monkeypatch.setattr(cli_module, "_budget_and_usage", forbidden)
    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden)
    monkeypatch.setattr(cli_module, "run_candidate_registry_benchmarks", forbidden)
    ledger_path = tmp_path / "must-not-open-ledger.json"
    arguments = cli_fixtures._candidate_args(
        tmp_path=tmp_path,
        output=tmp_path / "portfolio",
        ledger=ledger_path,
        secret_file=tmp_path / "must-not-read-secrets.env",
        allow_egress=True,
    )
    arguments.extend(
        (
            "--calibration-output",
            str(tmp_path / "calibration.json"),
            "--calibrated-policy-output",
            str(policy_output),
            "--lineage-review-bundle",
            str(tmp_path / "lineage-review"),
            "--lineage-trust-anchor",
            str(tmp_path / "lineage-trust-anchor.json"),
        )
    )

    result = runner.invoke(cli_module.app, arguments)

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "calibrated policy output must be a fresh file" in " ".join(result.output.split())
    assert not ledger_path.exists()


def test_calibration_preflight_rejects_existing_output(
    tmp_path: Path,
) -> None:
    output = tmp_path / "calibration.json"
    output.touch()

    with pytest.raises(ConfigError, match="fresh file"):
        cli_module._preflight_model_calibration_output(
            output,
            cost_ledger_path=tmp_path / "ledger.json",
            portfolio_output=tmp_path / "portfolio",
            campaign_journal=tmp_path / "campaign",
        )


@pytest.mark.parametrize("protected_name", ["portfolio", "campaign"])
def test_calibration_preflight_rejects_protected_path_collision(
    protected_name: str,
    tmp_path: Path,
) -> None:
    protected = tmp_path / protected_name

    with pytest.raises(ConfigError, match="must be distinct"):
        cli_module._preflight_model_calibration_output(
            protected,
            cost_ledger_path=tmp_path / "ledger.json",
            portfolio_output=tmp_path / "portfolio",
            campaign_journal=tmp_path / "campaign",
        )


def test_calibration_preflight_rejects_nested_protected_path(
    tmp_path: Path,
) -> None:
    with pytest.raises(ConfigError, match="must be distinct"):
        cli_module._preflight_model_calibration_output(
            tmp_path / "portfolio" / "calibration.json",
            cost_ledger_path=tmp_path / "ledger.json",
            portfolio_output=tmp_path / "portfolio",
            campaign_journal=tmp_path / "campaign",
        )


def test_calibration_preflight_rejects_symlink_traversal(
    tmp_path: Path,
) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)

    with pytest.raises(ConfigError, match="may not traverse"):
        cli_module._preflight_model_calibration_output(
            linked / "calibration.json",
            cost_ledger_path=tmp_path / "ledger.json",
            portfolio_output=tmp_path / "portfolio",
            campaign_journal=tmp_path / "campaign",
        )


def test_calibration_preflight_fails_before_ledger_secrets_or_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
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
    calibration_output = tmp_path / "calibration.json"
    calibration_output.touch()

    def forbidden(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("ledger, secrets, and provider work must remain untouched")

    monkeypatch.setattr(cli_module, "_budget_and_usage", forbidden)
    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden)
    monkeypatch.setattr(cli_module, "run_candidate_registry_benchmarks", forbidden)
    ledger_path = tmp_path / "must-not-open-ledger.json"
    arguments = cli_fixtures._candidate_args(
        tmp_path=tmp_path,
        output=tmp_path / "portfolio",
        ledger=ledger_path,
        secret_file=tmp_path / "must-not-read-secrets.env",
        allow_egress=True,
    )
    arguments.extend(
        (
            "--calibration-output",
            str(calibration_output),
            "--lineage-review-bundle",
            str(tmp_path / "lineage-review"),
            "--lineage-trust-anchor",
            str(tmp_path / "lineage-trust-anchor.json"),
        )
    )

    result = runner.invoke(cli_module.app, arguments)

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "model calibration output must be a fresh file" in " ".join(result.output.split())
    assert not ledger_path.exists()


@pytest.mark.parametrize(
    "failure_stage",
    ["missing_bundle", "missing_anchor", "signature", "exact_join"],
)
def test_missing_or_untrusted_lineage_fails_before_ledger_secrets_or_provider_dispatch(
    failure_stage: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
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
    events: list[str] = []
    lineage_artifact = object()
    authority_envelope = object()
    trust_anchor = object()
    capability = _RecordingLineageCapability(
        events,
        reject_join=failure_stage == "exact_join",
    )

    def load_bundle(_path: Path) -> tuple[object, object]:
        events.append("lineage_bundle_load")
        if failure_stage == "missing_bundle":
            raise FileNotFoundError("synthetic lineage review bundle is missing")
        return lineage_artifact, authority_envelope

    def load_anchor(_path: Path) -> object:
        events.append("lineage_anchor_load")
        if failure_stage == "missing_anchor":
            raise FileNotFoundError("synthetic lineage trust anchor is missing")
        return trust_anchor

    monkeypatch.setattr(
        cli_module,
        "load_model_lineage_authority_bundle",
        load_bundle,
    )
    monkeypatch.setattr(
        cli_module,
        "load_model_lineage_trust_anchor",
        load_anchor,
    )

    def verify_lineage(**kwargs: object) -> object:
        events.append("lineage_verify")
        assert kwargs["artifact"] is lineage_artifact
        assert kwargs["envelope"] is authority_envelope
        assert kwargs["trust_anchor"] is trust_anchor
        if failure_stage == "signature":
            raise ValueError("synthetic lineage signature is not trusted")
        return capability

    monkeypatch.setattr(
        cli_module,
        "verify_operator_model_lineage_authority",
        verify_lineage,
    )

    def forbidden(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("ledger, secrets, and provider work must remain untouched")

    monkeypatch.setattr(cli_module, "_budget_and_usage", forbidden)
    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden)
    monkeypatch.setattr(cli_module, "run_candidate_registry_benchmarks", forbidden)
    arguments = cli_fixtures._candidate_args(
        tmp_path=tmp_path,
        output=tmp_path / "portfolio",
        ledger=tmp_path / "must-not-open-ledger.json",
        secret_file=tmp_path / "must-not-read-secrets.env",
        allow_egress=True,
    )
    arguments.extend(
        (
            "--calibration-output",
            str(tmp_path / "calibration.json"),
            "--lineage-review-bundle",
            str(tmp_path / "lineage-review"),
            "--lineage-trust-anchor",
            str(tmp_path / "lineage-trust-anchor.json"),
        )
    )

    result = runner.invoke(cli_module.app, arguments)

    assert result.exit_code == ExitCode.CONFIGURATION
    expected_events = {
        "missing_bundle": ["lineage_bundle_load"],
        "missing_anchor": ["lineage_bundle_load", "lineage_anchor_load"],
        "signature": ["lineage_bundle_load", "lineage_anchor_load", "lineage_verify"],
        "exact_join": [
            "lineage_bundle_load",
            "lineage_anchor_load",
            "lineage_verify",
            "lineage_join",
        ],
    }
    assert events == expected_events[failure_stage]
    assert not (tmp_path / "must-not-open-ledger.json").exists()
    assert not (tmp_path / "campaign-journal").exists()
    assert "lineage" in result.output


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
    events: list[str] = []
    lineage_artifact = object()
    authority_envelope = object()
    trust_anchor = object()
    lineage_capability = _RecordingLineageCapability(events)
    monkeypatch.setattr(
        cli_module,
        "load_model_lineage_authority_bundle",
        lambda _path: (lineage_artifact, authority_envelope),
    )
    monkeypatch.setattr(
        cli_module,
        "load_model_lineage_trust_anchor",
        lambda _path: trust_anchor,
    )

    def verify_lineage(**kwargs: object) -> object:
        events.append("lineage_verify")
        assert kwargs["artifact"] is lineage_artifact
        assert kwargs["envelope"] is authority_envelope
        assert kwargs["trust_anchor"] is trust_anchor
        return lineage_capability

    monkeypatch.setattr(
        cli_module,
        "verify_operator_model_lineage_authority",
        verify_lineage,
    )

    async def dispatch(**kwargs: Any) -> CandidateBenchmarkExecutionResult:
        events.append("provider_dispatch")
        return await run_candidate_registry_benchmarks(
            **kwargs,
            client_factory=factory,
        )

    monkeypatch.setattr(cli_module, "run_candidate_registry_benchmarks", dispatch)
    actual_issue = cli_module.issue_trusted_candidate_benchmark_campaign_verification
    captured: dict[str, object] = {}

    def issue_capability(**kwargs: Any) -> TrustedCandidateBenchmarkCampaignVerification:
        capability = actual_issue(**kwargs)
        captured["capability"] = capability
        return capability

    def build_calibration(**kwargs: Any) -> Any:
        events.append("calibration_build")
        assert kwargs["trusted_campaign_verification"] is captured["capability"]
        assert kwargs["lineage_review_artifact"] is lineage_artifact
        assert kwargs["trusted_lineage_verification"] is lineage_capability
        artifact = SimpleNamespace(
            artifact_sha256="c" * 64,
            candidates=(SimpleNamespace(included_in_distribution=False),),
        )
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

    def write_calibration(path: Path, artifact: object) -> None:
        assert artifact is captured["artifact"]
        path.write_text('{"artifact_sha256":"' + "c" * 64 + '"}\n', encoding="utf-8")
        path.chmod(0o600)

    monkeypatch.setattr(
        cli_module,
        "write_model_calibration_artifact",
        write_calibration,
    )
    calibration_output = tmp_path / "calibration.json"
    arguments = cli_fixtures._candidate_args(
        tmp_path=tmp_path,
        output=tmp_path / "portfolio",
        ledger=cli_fixtures._ledger(tmp_path, config),
        secret_file=cli_fixtures._secret_file(tmp_path),
        allow_egress=True,
    )
    arguments.extend(
        (
            "--calibration-output",
            str(calibration_output),
            "--lineage-review-bundle",
            str(tmp_path / "lineage-review"),
            "--lineage-trust-anchor",
            str(tmp_path / "lineage-trust-anchor.json"),
        )
    )

    result = runner.invoke(
        cli_module.app,
        arguments,
        env={"MMAUDIT_SECRETS_ENV_FILE": ""},
    )

    assert result.exit_code == ExitCode.MODEL_FAILURE
    assert isinstance(
        captured["capability"],
        TrustedCandidateBenchmarkCampaignVerification,
    )
    assert lineage_capability.join_arguments is not None
    assert lineage_capability.join_arguments["candidate_registry"] == registry
    assert lineage_capability.join_arguments["discovery_manifest"] == manifest
    assert events[:3] == ["lineage_verify", "lineage_join", "provider_dispatch"]
    assert stat.S_IMODE(calibration_output.stat().st_mode) == 0o600
    assert "Calibration:" in result.output
    assert cli_fixtures.CANARY not in result.output
    assert cli_fixtures.CANARY.encode() not in calibration_output.read_bytes()


@pytest.mark.parametrize("derivation_succeeds", [True, False])
def test_candidate_campaign_persists_calibration_before_p2_derivation(
    derivation_succeeds: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    tmp_path.chmod(0o700)
    observed_at = datetime.now(UTC).replace(microsecond=0)

    class _CampaignClock(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> datetime:
            value = observed_at + timedelta(seconds=10)
            return value if tz is not None else value.replace(tzinfo=None)

    monkeypatch.setattr(cli_module, "datetime", _CampaignClock)
    discovered_at = observed_at - timedelta(hours=3)
    refreshed_at = observed_at - timedelta(hours=2)
    created_at = observed_at - timedelta(hours=1)
    expires_at = observed_at + timedelta(days=7)
    config = cli_fixtures._pending_config(config_factory)
    candidate_spec = candidate_fixtures._CandidateSpec(
        model_id=cli_fixtures.MODEL_ID,
        provider_endpoint=cli_fixtures.PROVIDER_ENDPOINT,
        provider_name="Provider Alpha",
    )
    monkeypatch.setattr(candidate_fixtures, "_NOW", discovered_at)
    manifest, discovery_evidence, registry = candidate_fixtures._discovery_and_registry(
        tmp_path=tmp_path / "inputs",
        config=config,
        specs=(candidate_spec,),
    )
    catalog = candidate_fixtures._catalog_model(candidate_spec)
    endpoint = candidate_fixtures._endpoint(candidate_spec)
    source = build_model_refresh_source_evidence(
        retrieved_at=refreshed_at,
        catalog_payload={"data": [catalog]},
        zdr_payload={"data": [endpoint]},
        candidate_registry=registry,
        candidate_endpoint_payloads={
            candidate_spec.model_id: {
                "data": {
                    "id": candidate_spec.model_id,
                    "endpoints": [
                        {key: value for key, value in endpoint.items() if key != "model_id"}
                    ],
                }
            }
        },
        authenticated_metadata=True,
    )
    snapshot = build_model_refresh_snapshot_from_source(
        source_evidence=source,
        candidate_registry=registry,
    )
    freshness = evaluate_model_refresh_freshness(
        observed_at=created_at,
        snapshot=snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=False,
    )
    lineage_bundle = lineage_fixtures._Bundle(
        registry=registry,
        manifest=manifest,
        discovery_evidence=discovery_evidence,
        source=source,
        snapshot=snapshot,
        freshness=freshness,
        catalogs=(catalog,),
        endpoints=(endpoint,),
    )
    with patch.multiple(
        lineage_fixtures,
        CREATED_AT=created_at,
        EXPIRES_AT=expires_at,
    ):
        review = lineage_fixtures._review(
            (cli_fixtures.MODEL_ID,),
            label="cli-p2",
            reviewed_at=created_at,
        )
        lineage_artifact = lineage_fixtures._artifact(lineage_bundle, (review,))

    signing_root = tmp_path / "lineage-signing"
    signing_root.mkdir(mode=0o700)
    anchor, envelope, _lineage_capability = lineage_authority_fixtures._signed_authority(
        root=signing_root,
        artifact=lineage_artifact,
        signed_at=created_at + timedelta(minutes=15),
        expires_at=observed_at + timedelta(days=1),
    )
    lineage_root = tmp_path / "lineage-review"
    lineage_root.mkdir(mode=0o700)
    lineage_fixtures.write_model_lineage_review_artifact(lineage_root, lineage_artifact)
    write_model_lineage_authority_envelope(lineage_root, envelope)
    trust_path = tmp_path / "lineage-trust-anchor.json"
    write_json_evidence(
        evidence_root=tmp_path,
        relative_path=trust_path.name,
        value=anchor,
    )

    suite = cli_fixtures.load_model_benchmark_corpus(cli_fixtures.CORPUS_PATH)
    monkeypatch.setattr(candidate_fixtures, "_NOW", observed_at)
    cli_fixtures._patch_inputs(
        monkeypatch,
        config=config,
        manifest=lineage_bundle.manifest,
        evidence=lineage_bundle.discovery_evidence,
        registry=lineage_bundle.registry,
        suite=suite,
    )
    factory = candidate_fixtures._MockClientFactory()
    events: list[str] = []

    async def dispatch(**kwargs: Any) -> CandidateBenchmarkExecutionResult:
        events.append("provider_dispatch")
        return await run_candidate_registry_benchmarks(
            **kwargs,
            client_factory=factory,
        )

    monkeypatch.setattr(cli_module, "run_candidate_registry_benchmarks", dispatch)
    actual_issue = cli_module.issue_trusted_model_calibration_verification

    def issue(**kwargs: Any) -> TrustedModelCalibrationVerification:
        authority = actual_issue(**kwargs)
        events.append("calibration_verification_issue")
        return authority

    monkeypatch.setattr(cli_module, "issue_trusted_model_calibration_verification", issue)
    successor = policy_fixtures._seal_structural_v2()
    actual_derive = cli_module.derive_calibrated_qualification_policy

    def derive(
        *,
        calibration: ModelCalibrationArtifact,
        trusted_calibration_verification: TrustedModelCalibrationVerification,
    ) -> Any:
        events.append("p2_derivation")
        if derivation_succeeds:
            trusted_calibration_verification.require_for(calibration)
            return successor
        return actual_derive(
            calibration=calibration,
            trusted_calibration_verification=trusted_calibration_verification,
        )

    monkeypatch.setattr(cli_module, "derive_calibrated_qualification_policy", derive)
    actual_write_calibration = cli_module.write_model_calibration_artifact
    actual_write_policy = cli_module.write_calibrated_qualification_policy

    def write_calibration(path: Path, artifact: ModelCalibrationArtifact) -> None:
        events.append("calibration_write")
        actual_write_calibration(path, artifact)

    def write_policy(path: Path, policy: Any) -> None:
        events.append("p2_write")
        actual_write_policy(path, policy)

    monkeypatch.setattr(cli_module, "write_model_calibration_artifact", write_calibration)
    monkeypatch.setattr(cli_module, "write_calibrated_qualification_policy", write_policy)

    calibration_output = tmp_path / "calibration.json"
    policy_output = tmp_path / "calibrated-policy.json"
    arguments = cli_fixtures._candidate_args(
        tmp_path=tmp_path,
        output=tmp_path / "portfolio",
        ledger=cli_fixtures._ledger(tmp_path, config),
        secret_file=cli_fixtures._secret_file(tmp_path),
        allow_egress=True,
    )
    arguments.extend(
        (
            "--calibration-output",
            str(calibration_output),
            "--calibrated-policy-output",
            str(policy_output),
            "--lineage-review-bundle",
            str(lineage_root),
            "--lineage-trust-anchor",
            str(trust_path),
        )
    )

    result = runner.invoke(
        cli_module.app,
        arguments,
        env={"MMAUDIT_SECRETS_ENV_FILE": ""},
    )

    assert result.exit_code == (
        ExitCode.MODEL_FAILURE if derivation_succeeds else ExitCode.CONFIGURATION
    ), result.output
    expected_tail = [
        "calibration_write",
        "calibration_verification_issue",
        "p2_derivation",
    ]
    if derivation_succeeds:
        expected_tail.append("p2_write")
    assert events[-len(expected_tail) :] == expected_tail
    assert load_model_calibration_artifact(calibration_output).schema_version == "2.0"
    rendered = " ".join(result.output.split())
    if derivation_succeeds:
        assert load_calibrated_qualification_policy(policy_output) == successor
        assert stat.S_IMODE(policy_output.stat().st_mode) == 0o600
        assert "P2 successor candidate:" in rendered
        assert "review, commit, and release-pin it before J2 qualification" in rendered
    else:
        assert not policy_output.exists()
        assert "calibration distribution has no exact denominator" in rendered
    assert cli_fixtures.CANARY not in result.output
    if policy_output.exists():
        assert cli_fixtures.CANARY.encode() not in policy_output.read_bytes()
