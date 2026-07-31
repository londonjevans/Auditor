from __future__ import annotations

import stat
from collections.abc import Callable
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import mmaudit.cli as cli_module
from mmaudit.benchmark.model_portfolio import load_model_benchmark_portfolio
from mmaudit.benchmark.models import ModelBenchmarkSuite, load_model_benchmark_corpus
from mmaudit.config import AuditConfig, ConfigError
from mmaudit.constants import ExitCode
from mmaudit.models.candidate_benchmark import (
    CandidateBenchmarkExecutionResult,
    CandidateBenchmarkRunState,
    run_candidate_registry_benchmarks,
)
from mmaudit.models.discovery import (
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
)
from mmaudit.models.qualification import (
    CandidateRegistry,
    LineageReviewStatus,
    QualificationDimensionThreshold,
    load_qualification_policy,
    seal_qualification_policy,
)
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.unit import test_candidate_benchmark as candidate_fixtures

runner = CliRunner()
ROOT = Path(__file__).parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
POLICY_PATH = ROOT / "config" / "models.maximum-assurance.toml"
MODEL_ID = "alpha/atlas-secure"
PROVIDER_ENDPOINT = "provider-alpha"
CANARY = "SYNTHETIC_CANDIDATE_CLI_SECRET_CANARY"


def _pending_config(config_factory: Callable[..., AuditConfig]) -> AuditConfig:
    return config_factory(
        execution={"max_requests_per_agent": 512},
        privacy={"approved_model_lineages": []},
        models={
            "registry": [],
            "reasoning": {"effort": "high", "reserved_tokens": 4_096},
        },
    )


def _inputs(
    *,
    tmp_path: Path,
    config: AuditConfig,
) -> tuple[
    OpenRouterModelDiscoveryRunManifest,
    tuple[OpenRouterModelDiscoveryEvidence, ...],
    CandidateRegistry,
    ModelBenchmarkSuite,
]:
    manifest, evidence, registry = candidate_fixtures._discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=(
            candidate_fixtures._CandidateSpec(
                model_id=MODEL_ID,
                provider_endpoint=PROVIDER_ENDPOINT,
                provider_name="Provider Alpha",
            ),
        ),
    )
    return manifest, evidence, registry, load_model_benchmark_corpus(CORPUS_PATH)


def _patch_inputs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    config: AuditConfig,
    manifest: OpenRouterModelDiscoveryRunManifest,
    evidence: tuple[OpenRouterModelDiscoveryEvidence, ...],
    registry: CandidateRegistry,
    suite: ModelBenchmarkSuite,
) -> None:
    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(
        cli_module,
        "load_model_benchmark_corpus",
        lambda _path: suite,
    )
    monkeypatch.setattr(
        cli_module,
        "load_candidate_registry",
        lambda _path: registry,
    )
    monkeypatch.setattr(
        cli_module,
        "load_model_discovery_run",
        lambda _path: (manifest, evidence),
    )
    monkeypatch.setattr(
        cli_module,
        "load_qualification_policy",
        lambda _path: load_qualification_policy(POLICY_PATH),
    )


def _secret_file(tmp_path: Path) -> Path:
    path = tmp_path / "operator-secrets.env"
    path.write_text(f"OPENROUTER_API_KEY={CANARY}\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _ledger(tmp_path: Path, config: AuditConfig) -> Path:
    path = tmp_path / "candidate-cost-ledger.json"
    AtomicCostLedger.initialize(
        path,
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    return path


def test_candidate_qualification_rejects_alternate_self_hashed_policy(config_factory) -> None:
    config = _pending_config(config_factory)
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    policy = load_qualification_policy(POLICY_PATH)
    lenient = seal_qualification_policy(
        created_at=policy.created_at,
        thresholds=tuple(
            threshold.model_copy(update={"minimum_score": 0.5}) for threshold in policy.thresholds
        ),
        tier_a_minimum_overall_score=0.5,
        maximum_validity_days=policy.maximum_validity_days,
        maximum_benchmark_evidence_age_days=policy.maximum_benchmark_evidence_age_days,
    )

    cli_module._require_qualification_release_pins(
        config=config,
        policy=policy,
        benchmark_suite=suite,
    )
    with pytest.raises(ConfigError, match="release pins"):
        cli_module._require_qualification_release_pins(
            config=config,
            policy=lenient,
            benchmark_suite=suite,
        )


def _candidate_args(
    *,
    tmp_path: Path,
    output: Path,
    ledger: Path | None,
    secret_file: Path | None,
    allow_egress: bool,
) -> list[str]:
    arguments = [
        "models",
        "benchmark",
        "--config",
        str(tmp_path / "synthetic.toml"),
        "--corpus",
        str(CORPUS_PATH),
        "--candidate-registry",
        str(tmp_path / "candidates.toml"),
        "--discovery-run",
        str(tmp_path / "discovery"),
        "--output",
        str(output),
        "--campaign-journal",
        str(tmp_path / "campaign-journal"),
        "--qualification-policy",
        str(POLICY_PATH),
        "--no-color",
    ]
    if ledger is not None:
        arguments.extend(("--cost-ledger", str(ledger)))
    if secret_file is not None:
        arguments.extend(("--secrets-env-file", str(secret_file)))
    if allow_egress:
        arguments.append("--allow-code-egress")
    return arguments


@pytest.mark.parametrize(
    "extra_arguments",
    [
        ("--candidate-registry", "candidates.toml"),
        ("--discovery-run", "discovery"),
        (
            "--candidate-registry",
            "candidates.toml",
            "--discovery-run",
            "discovery",
            "--model",
            MODEL_ID,
        ),
    ],
)
def test_candidate_mode_rejects_incomplete_or_conflicting_options_before_loading(
    extra_arguments: tuple[str, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_module,
        "load_config",
        lambda _path: (_ for _ in ()).throw(AssertionError("configuration must not be loaded")),
    )

    result = runner.invoke(
        cli_module.app,
        ["models", "benchmark", *extra_arguments, "--no-color"],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    output = " ".join(result.output.split())
    assert "must be supplied together" in output or "cannot be combined" in output


def test_candidate_mode_requires_policy_before_loading(
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
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "--qualification-policy" in " ".join(result.output.split())


def test_candidate_mode_rejects_underfilled_policy_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _pending_config(config_factory)
    manifest, evidence, registry, suite = _inputs(
        tmp_path=tmp_path / "inputs",
        config=config,
    )
    _patch_inputs(
        monkeypatch,
        config=config,
        manifest=manifest,
        evidence=evidence,
        registry=registry,
        suite=suite,
    )
    policy = load_qualification_policy(POLICY_PATH)
    underfilled = seal_qualification_policy(
        created_at=policy.created_at,
        thresholds=tuple(
            QualificationDimensionThreshold(
                dimension=item.dimension,
                minimum_cases=(
                    item.minimum_cases + 1
                    if item.dimension.value == "access_control"
                    else item.minimum_cases
                ),
                minimum_score=item.minimum_score,
            )
            for item in policy.thresholds
        ),
        tier_a_minimum_overall_score=policy.tier_a_minimum_overall_score,
        maximum_validity_days=policy.maximum_validity_days,
    )
    monkeypatch.setattr(cli_module, "load_qualification_policy", lambda _path: underfilled)
    monkeypatch.setattr(
        cli_module,
        "_require_qualification_release_pins",
        lambda **_kwargs: None,
    )
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    result = runner.invoke(
        cli_module.app,
        _candidate_args(
            tmp_path=tmp_path,
            output=tmp_path / "portfolio",
            ledger=None,
            secret_file=None,
            allow_egress=True,
        ),
        env={
            "MMAUDIT_COST_LEDGER_PATH": "",
            "MMAUDIT_SECRETS_ENV_FILE": "",
        },
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "underfills" in " ".join(result.output.split())
    assert not secret_accessed
    assert not (tmp_path / "campaign-journal").exists()


@pytest.mark.parametrize(
    ("allow_egress", "with_ledger", "expected"),
    [
        (False, False, "explicit synthetic-source egress"),
        (True, False, "existing --cost-ledger"),
    ],
)
def test_candidate_mode_rejects_missing_controls_before_secret_access(
    allow_egress: bool,
    with_ledger: bool,
    expected: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    tmp_path.chmod(0o700)
    config = _pending_config(config_factory)
    manifest, evidence, registry, suite = _inputs(
        tmp_path=tmp_path / "inputs",
        config=config,
    )
    _patch_inputs(
        monkeypatch,
        config=config,
        manifest=manifest,
        evidence=evidence,
        registry=registry,
        suite=suite,
    )
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    ledger = _ledger(tmp_path, config) if with_ledger else None
    result = runner.invoke(
        cli_module.app,
        _candidate_args(
            tmp_path=tmp_path,
            output=tmp_path / "portfolio",
            ledger=ledger,
            secret_file=None,
            allow_egress=allow_egress,
        ),
        env={
            "MMAUDIT_COST_LEDGER_PATH": "",
            "MMAUDIT_SECRETS_ENV_FILE": "",
        },
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert expected in " ".join(result.output.split())
    assert not secret_accessed
    assert not (tmp_path / "portfolio").exists()


def test_pending_lineage_mock_dispatch_persists_atomic_portfolio_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    tmp_path.chmod(0o700)
    config = _pending_config(config_factory)
    manifest, evidence, registry, suite = _inputs(
        tmp_path=tmp_path / "inputs",
        config=config,
    )
    _patch_inputs(
        monkeypatch,
        config=config,
        manifest=manifest,
        evidence=evidence,
        registry=registry,
        suite=suite,
    )
    captured: dict[str, Any] = {}
    factory = candidate_fixtures._MockClientFactory()

    async def dispatch(**kwargs: Any) -> CandidateBenchmarkExecutionResult:
        captured.update(kwargs)
        return await run_candidate_registry_benchmarks(
            **kwargs,
            client_factory=factory,
        )

    monkeypatch.setattr(cli_module, "run_candidate_registry_benchmarks", dispatch)
    ledger = _ledger(tmp_path, config)
    secret_file = _secret_file(tmp_path)
    output = tmp_path / "portfolio"
    result = runner.invoke(
        cli_module.app,
        _candidate_args(
            tmp_path=tmp_path,
            output=output,
            ledger=ledger,
            secret_file=secret_file,
            allow_egress=True,
        ),
        env={"MMAUDIT_SECRETS_ENV_FILE": ""},
    )

    portfolio, reports = load_model_benchmark_portfolio(
        output,
        candidate_registry=registry,
        corpus=suite,
    )
    assert result.exit_code == ExitCode.MODEL_FAILURE
    assert captured["candidate_registry"] == registry
    assert captured["discovery_manifest"] == manifest
    assert captured["discovery_evidence"] == evidence
    assert captured["operator_api_key"] == CANARY
    assert captured["explicitly_allow_synthetic_egress"] is True
    assert registry.candidates[0].lineage_review.status is LineageReviewStatus.PENDING
    assert reports[0].results[0].target.root_lineage is None
    assert portfolio.execution_evidence is ExecutionEvidenceKind.MOCK
    assert portfolio.diagnostics[0].state is CandidateBenchmarkRunState.COMPLETE_WITH_FAILURES
    assert portfolio.usage.usage_record_count == len(suite.cases)
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(item.stat().st_mode) == 0o600 for item in output.iterdir())
    assert CANARY not in result.output
    assert CANARY.encode() not in b"".join(item.read_bytes() for item in output.iterdir())


def test_all_authentication_failures_persist_unverified_zero_usage_portfolio(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    tmp_path.chmod(0o700)
    config = _pending_config(config_factory)
    manifest, evidence, registry, suite = _inputs(
        tmp_path=tmp_path / "inputs",
        config=config,
    )
    _patch_inputs(
        monkeypatch,
        config=config,
        manifest=manifest,
        evidence=evidence,
        registry=registry,
        suite=suite,
    )

    factory = candidate_fixtures._MockClientFactory(authentication_failure_models={MODEL_ID})

    async def dispatch(**kwargs: Any) -> CandidateBenchmarkExecutionResult:
        return await run_candidate_registry_benchmarks(
            **kwargs,
            client_factory=factory,
        )

    monkeypatch.setattr(cli_module, "run_candidate_registry_benchmarks", dispatch)
    output = tmp_path / "portfolio"
    result = runner.invoke(
        cli_module.app,
        _candidate_args(
            tmp_path=tmp_path,
            output=output,
            ledger=_ledger(tmp_path, config),
            secret_file=_secret_file(tmp_path),
            allow_egress=True,
        ),
        env={"MMAUDIT_SECRETS_ENV_FILE": ""},
    )

    portfolio, reports = load_model_benchmark_portfolio(
        output,
        candidate_registry=registry,
        corpus=suite,
    )
    assert result.exit_code == ExitCode.MODEL_FAILURE
    assert portfolio.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert portfolio.usage.usage_record_count == 0
    assert portfolio.started_at is None
    assert portfolio.ended_at is None
    assert portfolio.diagnostics[0].state is CandidateBenchmarkRunState.UNVERIFIED_FAILURE
    assert all(
        case.error_kind is not None and case.usage_record is None
        for case in reports[0].results[0].cases
    )
    assert "evidence=unverified" in result.output
    assert CANARY not in result.output
