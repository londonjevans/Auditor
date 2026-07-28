from __future__ import annotations

import asyncio
import json
import shutil
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from mmaudit.benchmark.certificate import (
    BenchmarkCertificatePayload,
    CertificateVerificationStatus,
    load_benchmark_certificate,
    observe_file_backed_certificate,
    seal_benchmark_certificate,
    write_benchmark_certificate,
)
from mmaudit.benchmark.claims import (
    ComparativeMetricEvidence,
    HumanComparisonEvidencePayload,
    ProportionSample,
    SuperiorityClaimStatus,
    seal_human_comparison_evidence,
)
from mmaudit.benchmark.engine import (
    BenchmarkMetricState,
    BenchmarkReport,
    BenchmarkStatus,
)
from mmaudit.benchmark.mutations import (
    MutationKind,
    MutationPropertyOutcome,
    MutationTestOutcome,
    score_mutation_outcomes,
)
from mmaudit.cli import _audit_config_overrides, _load_audit_production_qualification, app
from mmaudit.config import (
    AuditConfig,
    AuditConfigOverrides,
    ConfigError,
    LoadedAuditConfig,
    configured_model_ids,
)
from mmaudit.constants import ALL_MODEL_ROLES, ExitCode
from mmaudit.models.qualification_workflow import seal_qualification_release_bindings
from mmaudit.models.schemas import AuditProfile
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.manifest import canonical_sha256
from tests.conftest import base_config_data, model_registry_entry
from tests.qualification_support import synthetic_release_observation
from tests.unit import test_benchmark as benchmark_fixtures
from tests.unit import test_benchmark_certificate as certificate_fixtures
from tests.unit import test_model_qualification as qualification_fixtures

ROOT = Path(__file__).parents[2]
runner = CliRunner()
CERTIFICATE_COMMIT = "a" * 40


def _patch_loaded_audit_config(
    monkeypatch: pytest.MonkeyPatch,
    config: AuditConfig,
) -> None:
    loaded = LoadedAuditConfig(
        file_config=config,
        environment_overrides=AuditConfigOverrides(),
        effective_config=config.effective(),
    )
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    monkeypatch.setattr(
        "mmaudit.cli.load_config_with_provenance",
        lambda _path, **_kwargs: loaded,
    )


def _derived_production_config() -> AuditConfig:
    qualification = qualification_fixtures._bundle()
    results = qualification.artifact.results
    registry = []
    for result in results:
        assert result.root_lineage is not None
        entry = model_registry_entry(
            result.exact_model_id,
            root_lineage=result.root_lineage,
            measured_quality_score=result.overall_score,
            measured_quality_tier="highest",
        )
        entry["quality_measurement"] = f"sha256:{result.quality_measurement_sha256}"
        registry.append(entry)
    data = base_config_data()
    data["privacy"]["approved_model_lineages"] = sorted(
        {result.root_lineage for result in results if result.root_lineage is not None}
    )
    data["models"].update(
        {
            "provider_policy": {
                "only": sorted({result.approved_provider_endpoint for result in results}),
                "allow_fallbacks": False,
            },
            "registry": registry,
            **{
                role: {"primary": results[index].exact_model_id, "fallbacks": []}
                for index, role in enumerate(ALL_MODEL_ROLES)
            },
            "specialists": {
                "access_control": {
                    "primary": results[6].exact_model_id,
                    "fallbacks": [],
                },
                "report_quality": {
                    "primary": results[7].exact_model_id,
                    "fallbacks": [],
                },
            },
        }
    )
    return AuditConfig.model_validate(data)


def test_help_lists_required_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in (
        "init",
        "doctor",
        "models",
        "snapshot",
        "scan",
        "run",
        "explain",
        "benchmark",
        "verify-certificate",
        "verify-run",
        "replay",
    ):
        assert command in result.stdout


def test_run_help_lists_fork_aliases() -> None:
    result = runner.invoke(app, ["run", "--help"], env={"COLUMNS": "300"})
    assert result.exit_code == 0
    assert "--allow-fork" in result.stdout
    assert "--scope" in result.stdout
    assert "--cost-ledger" in result.stdout
    assert "--model-qualification-bundle" in result.stdout
    assert "--model-qualification-policy" in result.stdout
    assert "--model-qualification-release-bindings" in result.stdout
    assert "--model-qualification-release-source-root" in result.stdout
    assert "--model-qualification-corpus" in result.stdout
    assert "--model-qualification-ground-truth" in result.stdout


def test_explicit_cost_ledger_is_recorded_as_canonical_cli_provenance(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "campaign-ledger.json"

    overrides = _audit_config_overrides(
        budget_usd=None,
        cost_ledger=ledger_path,
        max_files=None,
        max_file_bytes=None,
        max_context_bytes=None,
        concurrency=None,
        require_zdr=False,
    )

    assert [entry.model_dump(mode="json") for entry in overrides.entries] == [
        {
            "path": "execution.cost_ledger_path",
            "value": str(ledger_path.resolve()),
        }
    ]
    assert "secret" not in overrides.model_dump_json().lower()


def test_models_help_lists_release_observation_command() -> None:
    result = runner.invoke(app, ["models", "--help"], env={"COLUMNS": "300"})

    assert result.exit_code == 0
    assert "observe-release-bindings" in result.stdout


def test_run_requires_complete_production_qualification_input_set(
    tmp_path: Path,
    monkeypatch,
    config_factory,
) -> None:
    _patch_loaded_audit_config(monkeypatch, config_factory())

    result = runner.invoke(
        app,
        [
            "run",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--model-qualification-bundle",
            str(tmp_path / "bundle.json"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    normalized = " ".join(result.stdout.split())
    assert "production qualification requires" in normalized
    assert "--model-qualification-bundle" in normalized
    assert "cost-ledger" not in result.stdout


def test_scanner_only_rejects_model_qualification_inputs(
    tmp_path: Path,
    monkeypatch,
    config_factory,
) -> None:
    _patch_loaded_audit_config(monkeypatch, config_factory())

    result = runner.invoke(
        app,
        [
            "run",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--scanner-only",
            "--model-qualification-bundle",
            str(tmp_path / "bundle.json"),
            "--model-qualification-policy",
            str(tmp_path / "policy.toml"),
            "--model-qualification-release-bindings",
            str(tmp_path / "bindings.json"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "model qualification inputs are not accepted for a scanner-only run" in (
        " ".join(result.stdout.split())
    )


def test_audit_qualification_loader_rejects_disk_only_content_provenance_before_provider(
    tmp_path: Path,
    monkeypatch,
    config_factory,
) -> None:
    config = config_factory()
    pins = config.maximum_assurance.qualification
    production_hash = config.stable_hash()
    benchmark_hash = canonical_sha256(config.model_dump(mode="json"))
    assert production_hash != benchmark_hash
    policy = SimpleNamespace(policy_sha256=pins.policy_sha256)
    benchmark_suite = SimpleNamespace(
        corpus=SimpleNamespace(schema_version=pins.corpus_version),
        corpus_sha256=pins.corpus_sha256,
        ground_truth=SimpleNamespace(schema_version=pins.ground_truth_version),
        ground_truth_sha256=pins.ground_truth_sha256,
    )
    provider_called = False

    def inputs(effective_config_sha256: str) -> tuple[SimpleNamespace, SimpleNamespace]:
        release = SimpleNamespace(
            source_commit="1" * 40,
            source_tree_sha256="2" * 64,
            effective_config_sha256=effective_config_sha256,
            prompt_sha256="3" * 64,
            response_schema_sha256="4" * 64,
            toolchain_sha256="5" * 64,
            isolation_sha256="6" * 64,
            benchmark_corpus_version=pins.corpus_version,
            benchmark_ground_truth_version=pins.ground_truth_version,
        )
        bundle = SimpleNamespace(
            policy_sha256=policy.policy_sha256,
            release_bindings=release,
            qualification_artifact=SimpleNamespace(bindings=release),
            updated_registry=object(),
            benchmark_reports=(),
            trusted_benchmark_evidence=(),
        )
        return bundle, release

    bundle, release = inputs(benchmark_hash)
    monkeypatch.setattr(
        "mmaudit.cli.load_qualification_workflow_bundle",
        lambda _path: bundle,
    )
    monkeypatch.setattr("mmaudit.cli.load_qualification_policy", lambda _path: policy)
    monkeypatch.setattr(
        "mmaudit.cli.load_qualification_release_bindings",
        lambda _path: release,
    )
    monkeypatch.setattr(
        "mmaudit.cli.load_model_benchmark_corpus",
        lambda _path, *, ground_truth_path: benchmark_suite,
    )

    async def refetch(**_kwargs):
        nonlocal provider_called
        provider_called = True
        return object()

    monkeypatch.setattr("mmaudit.cli._refetch_qualification_generations", refetch)
    monkeypatch.setattr(
        "mmaudit.cli._observe_qualification_release",
        lambda **_kwargs: SimpleNamespace(
            observed_at=qualification_fixtures._NOW + timedelta(hours=3)
        ),
    )
    paths = {
        "bundle_path": tmp_path / "bundle.json",
        "policy_path": tmp_path / "policy.toml",
        "release_bindings_path": tmp_path / "release-bindings.json",
        "release_source_root": tmp_path,
        "corpus_path": tmp_path / "corpus.json",
        "ground_truth_path": tmp_path / "ground-truth.json",
        "secrets_env_file": None,
    }

    with pytest.raises(ValueError, match="live response-content campaign provenance"):
        asyncio.run(
            _load_audit_production_qualification(
                config=config,
                scanner_only=False,
                **paths,
            )
        )

    assert release.effective_config_sha256 == benchmark_hash
    assert production_hash != benchmark_hash
    assert not provider_called


def test_audit_qualification_loader_rejects_alternate_policy_before_provider_work(
    tmp_path: Path,
    monkeypatch,
    config_factory,
) -> None:
    config = config_factory()
    pins = config.maximum_assurance.qualification
    alternate = qualification_fixtures._bundle().policy
    benchmark_suite = SimpleNamespace(
        corpus=SimpleNamespace(schema_version=pins.corpus_version),
        corpus_sha256=pins.corpus_sha256,
        ground_truth=SimpleNamespace(schema_version=pins.ground_truth_version),
        ground_truth_sha256=pins.ground_truth_sha256,
    )
    provider_called = False

    monkeypatch.setattr(
        "mmaudit.cli.load_qualification_workflow_bundle",
        lambda _path: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "mmaudit.cli.load_qualification_policy",
        lambda _path: alternate,
    )
    monkeypatch.setattr(
        "mmaudit.cli.load_qualification_release_bindings",
        lambda _path: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "mmaudit.cli.load_model_benchmark_corpus",
        lambda _path, *, ground_truth_path: benchmark_suite,
    )

    async def forbidden_refetch(**_kwargs):
        nonlocal provider_called
        provider_called = True
        return object()

    monkeypatch.setattr(
        "mmaudit.cli._refetch_qualification_generations",
        forbidden_refetch,
    )

    with pytest.raises(ConfigError, match="release pins"):
        asyncio.run(
            _load_audit_production_qualification(
                config=config,
                scanner_only=False,
                bundle_path=tmp_path / "bundle.json",
                policy_path=tmp_path / "policy.toml",
                release_bindings_path=tmp_path / "bindings.json",
                release_source_root=tmp_path,
                corpus_path=tmp_path / "corpus.json",
                ground_truth_path=tmp_path / "ground-truth.json",
                secrets_env_file=None,
            )
        )
    assert not provider_called


def test_audit_qualification_loader_resolves_derived_production_config_without_resealing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = _derived_production_config()
    qualification = qualification_fixtures._bundle()
    artifact = qualification.artifact
    bindings = artifact.bindings
    release_bindings = seal_qualification_release_bindings(
        source_commit=bindings.source_commit,
        source_tree_sha256=bindings.source_tree_sha256,
        effective_config_sha256=bindings.effective_config_sha256,
        prompt_sha256=bindings.prompt_sha256,
        response_schema_sha256=bindings.response_schema_sha256,
        toolchain_sha256=bindings.toolchain_sha256,
        isolation_sha256=bindings.isolation_sha256,
        benchmark_corpus_version=bindings.benchmark_corpus_version,
        benchmark_ground_truth_version=bindings.benchmark_ground_truth_version,
    )
    workflow = SimpleNamespace(
        policy_sha256=qualification.policy.policy_sha256,
        release_bindings=release_bindings,
        qualification_artifact=artifact,
        updated_registry=qualification.registry,
        benchmark_reports=(),
        trusted_benchmark_evidence=qualification.benchmark_evidence,
    )

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            value = qualification_fixtures._NOW + timedelta(hours=3)
            return value if tz is None else value.astimezone(tz)

    monkeypatch.setattr("mmaudit.cli.datetime", FrozenDatetime)
    monkeypatch.setattr(
        "mmaudit.cli.load_qualification_workflow_bundle",
        lambda _path: workflow,
    )
    monkeypatch.setattr(
        "mmaudit.cli.load_qualification_policy",
        lambda _path: qualification.policy,
    )
    monkeypatch.setattr(
        "mmaudit.cli.load_qualification_release_bindings",
        lambda _path: release_bindings,
    )
    monkeypatch.setattr(
        "mmaudit.cli.load_model_benchmark_corpus",
        lambda _path, *, ground_truth_path: SimpleNamespace(ground_truth_path=ground_truth_path),
    )
    monkeypatch.setattr(
        "mmaudit.cli._require_qualification_release_pins",
        lambda **_kwargs: None,
    )

    provider_called = False

    async def refetch(**_kwargs):
        nonlocal provider_called
        provider_called = True
        return object()

    monkeypatch.setattr("mmaudit.cli._refetch_qualification_generations", refetch)
    monkeypatch.setattr(
        "mmaudit.cli._observe_qualification_release",
        lambda **_kwargs: synthetic_release_observation(
            bindings,
            observed_at=qualification_fixtures._NOW + timedelta(hours=3),
        ),
    )
    monkeypatch.setattr(
        "mmaudit.models.qualification._freshly_reverify_production_benchmarks",
        lambda **_kwargs: qualification.benchmark_evidence,
    )

    with pytest.raises(ValueError, match="live response-content campaign provenance"):
        asyncio.run(
            _load_audit_production_qualification(
                config=config,
                scanner_only=False,
                bundle_path=tmp_path / "bundle.json",
                policy_path=tmp_path / "policy.toml",
                release_bindings_path=tmp_path / "bindings.json",
                release_source_root=tmp_path,
                corpus_path=tmp_path / "corpus.json",
                ground_truth_path=tmp_path / "ground-truth.json",
                secrets_env_file=None,
            )
        )

    assert artifact.bindings.effective_config_sha256 != config.stable_hash()
    assert not provider_called


def test_models_benchmark_help_lists_blinded_corpus_and_egress_controls() -> None:
    result = runner.invoke(app, ["models", "benchmark", "--help"])
    assert result.exit_code == 0
    assert "--corpus" in result.stdout
    assert "--model" in result.stdout
    assert "--candidate-registry" in result.stdout
    assert "--discovery-run" in result.stdout
    assert "--allow-code-egress" in result.stdout
    assert "--cost-ledger" in result.stdout


def test_models_discover_help_lists_exact_route_and_private_output_controls() -> None:
    result = runner.invoke(app, ["models", "discover", "--help"])
    assert result.exit_code == 0
    assert "--candidate" in result.stdout
    assert "--output-dir" in result.stdout
    assert "--secrets-env-file" in result.stdout


@pytest.mark.parametrize(
    "arguments",
    [
        ["doctor", "--help"],
        ["models", "list", "--help"],
        ["models", "discover", "--help"],
        ["models", "check", "--help"],
        ["models", "benchmark", "--help"],
        ["scan", "--help"],
        ["run", "--help"],
    ],
)
def test_provider_commands_expose_explicit_secret_file_option(arguments: list[str]) -> None:
    result = runner.invoke(app, arguments, env={"COLUMNS": "240"})
    assert result.exit_code == 0
    assert "--secrets-env-file" in result.stdout


def test_models_benchmark_requires_explicit_egress_before_provider_access(
    tmp_path: Path,
    monkeypatch,
    config_factory,
) -> None:
    config = config_factory(privacy={"allow_code_egress": False})
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    monkeypatch.delenv("MMAUDIT_SECRETS_ENV_FILE", raising=False)
    model_id = config.models.threat_model.primary
    arguments = [
        "models",
        "benchmark",
        "--config",
        str(tmp_path / "synthetic.toml"),
        "--corpus",
        str(ROOT / "benchmarks" / "model_corpus" / "manifest.json"),
        "--model",
        model_id,
        "--output",
        str(tmp_path / "model-benchmark.json"),
        "--no-color",
    ]

    without_approval = runner.invoke(app, arguments)
    with_approval = runner.invoke(app, [*arguments, "--allow-code-egress"])

    assert without_approval.exit_code == ExitCode.CONFIGURATION
    assert "explicit synthetic-source egress" in without_approval.stdout
    assert "approval" in without_approval.stdout
    assert with_approval.exit_code == ExitCode.CONFIGURATION
    assert "--cost-ledger" in with_approval.stdout
    assert not (tmp_path / "model-benchmark.json").exists()


def test_models_discover_rejects_alias_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr("mmaudit.cli.load_operator_secrets", forbidden_secret_access)
    result = runner.invoke(
        app,
        [
            "models",
            "discover",
            "--candidate",
            "openrouter/auto=approved-provider/fp8",
            "--config",
            str(tmp_path / "missing.toml"),
            "--output-dir",
            str(tmp_path / "private"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "exact non-alias" in result.stdout
    assert not secret_accessed


def test_models_discover_rejects_synthetic_client_without_real_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
) -> None:
    model_id = "alpha/atlas-secure"
    provider_endpoint = "approved-provider/fp8"
    canary = "synthetic-provider-canary"
    config = config_factory()
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    secret_file = tmp_path / "operator-secrets.env"
    secret_file.write_text(f"OPENROUTER_API_KEY={canary}\n", encoding="utf-8")
    secret_file.chmod(0o600)

    class SyntheticMetadataClient:
        def __init__(self, *, api_key: str, **_kwargs: object) -> None:
            assert api_key == canary

    monkeypatch.setattr("mmaudit.cli.OpenRouterClient", SyntheticMetadataClient)
    output = tmp_path / "private" / "discovery"
    result = runner.invoke(
        app,
        [
            "models",
            "discover",
            "--candidate",
            f"{model_id}={provider_endpoint}",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--secrets-env-file",
            str(secret_file),
            "--output-dir",
            str(output),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "trusted concrete OpenRouter" in result.stdout
    assert not output.exists()
    assert canary not in result.stdout


def test_models_discover_rejects_reused_output_before_secret_access(
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

    monkeypatch.setattr("mmaudit.cli.load_operator_secrets", forbidden_secret_access)
    result = runner.invoke(
        app,
        [
            "models",
            "discover",
            "--candidate",
            "alpha/atlas-secure=approved-provider/fp8",
            "--config",
            str(tmp_path / "missing.toml"),
            "--output-dir",
            str(output),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "must be fresh" in result.stdout
    assert not secret_accessed


def test_models_cost_ledger_initialization_is_explicit_and_one_time(
    tmp_path: Path,
    monkeypatch,
    config_factory,
) -> None:
    tmp_path.chmod(0o700)
    config = config_factory(execution={"budget_usd": 250.0})
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    ledger = tmp_path / "provider-cost-ledger.json"
    arguments = [
        "models",
        "init-cost-ledger",
        "--config",
        str(tmp_path / "synthetic.toml"),
        "--cost-ledger",
        str(ledger),
        "--no-color",
    ]

    first = runner.invoke(app, arguments)
    second = runner.invoke(app, arguments)

    assert first.exit_code == 0, first.stdout
    assert ledger.is_file()
    assert second.exit_code == ExitCode.CONFIGURATION
    assert "one-time" in second.stdout


def test_provider_run_missing_ledger_fails_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
) -> None:
    config = config_factory()
    _patch_loaded_audit_config(monkeypatch, config)
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr("mmaudit.cli.load_operator_secrets", forbidden_secret_access)
    result = runner.invoke(
        app,
        [
            "run",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--repo",
            str(tmp_path),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "requires an existing --cost-ledger" in result.stdout
    assert not secret_accessed


def test_provider_run_deleted_ledger_fails_without_recreating_budget_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
) -> None:
    tmp_path.chmod(0o700)
    config = config_factory()
    _patch_loaded_audit_config(monkeypatch, config)
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr("mmaudit.cli.load_operator_secrets", forbidden_secret_access)
    ledger_path = tmp_path / "deleted-campaign-ledger.json"
    result = runner.invoke(
        app,
        [
            "run",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--repo",
            str(tmp_path),
            "--cost-ledger",
            str(ledger_path),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "existing cost ledger lock" in result.stdout
    assert not secret_accessed
    assert not ledger_path.exists()
    assert not ledger_path.with_name(f".{ledger_path.name}.lock").exists()


def test_provider_run_cap_mismatch_fails_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
) -> None:
    tmp_path.chmod(0o700)
    config = config_factory(execution={"budget_usd": 20.0})
    _patch_loaded_audit_config(monkeypatch, config)
    ledger_path = tmp_path / "different-cap-ledger.json"
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("19.0"))
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr("mmaudit.cli.load_operator_secrets", forbidden_secret_access)
    result = runner.invoke(
        app,
        [
            "run",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--repo",
            str(tmp_path),
            "--cost-ledger",
            str(ledger_path),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "cost cap does not match" in result.stdout
    assert not secret_accessed


def test_provider_run_uses_existing_configured_campaign_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
) -> None:
    tmp_path.chmod(0o700)
    ledger_path = tmp_path / "campaign-cost-ledger.json"
    config = config_factory(
        execution={"cost_ledger_path": str(ledger_path)},
    )
    AtomicCostLedger.initialize(
        ledger_path,
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    secret_file = tmp_path / "operator-secrets.env"
    secret_file.write_text("OPENROUTER_API_KEY=synthetic-provider-canary\n", encoding="utf-8")
    secret_file.chmod(0o600)
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "app.py").write_text("value = 1\n", encoding="utf-8")
    observed_ledgers: list[AtomicCostLedger] = []

    class SyntheticPipelineResult:
        run_dir = tmp_path / "synthetic-run"

        def exit_for_findings(self, _fail_on: object) -> ExitCode:
            return ExitCode.SUCCESS

    class SyntheticPipeline:
        def __init__(self, _config: object, **kwargs: object) -> None:
            ledger = kwargs["cost_ledger"]
            assert isinstance(ledger, AtomicCostLedger)
            self.ledger = ledger
            observed_ledgers.append(ledger)

        async def run(self, **_kwargs: object) -> SyntheticPipelineResult:
            index = len(observed_ledgers)
            reservation = self.ledger.reserve(
                f"synthetic-provider-run-{index}",
                Decimal("1.0"),
            )
            self.ledger.reconcile(reservation, Decimal("0.25"))
            return SyntheticPipelineResult()

        def clear_credentials(self) -> None:
            return None

    _patch_loaded_audit_config(monkeypatch, config)
    monkeypatch.setattr("mmaudit.cli.AuditPipeline", SyntheticPipeline)
    for index in range(2):
        output = tmp_path / f"output-{index}"
        result = runner.invoke(
            app,
            [
                "run",
                "--config",
                str(tmp_path / "synthetic.toml"),
                "--secrets-env-file",
                str(secret_file),
                "--repo",
                str(repository),
                "--output",
                str(output),
                "--no-color",
            ],
        )
        assert result.exit_code == ExitCode.SUCCESS, result.stdout
        assert not list(output.rglob("model-cost-ledger.json"))

    assert [ledger.path for ledger in observed_ledgers] == [ledger_path, ledger_path]
    snapshot = observed_ledgers[-1].snapshot()
    assert snapshot.spent_usd == Decimal("0.5")
    assert len(snapshot.entries) == 2


def test_models_benchmark_missing_ledger_fails_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
) -> None:
    tmp_path.chmod(0o700)
    config = config_factory()
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr("mmaudit.cli.load_operator_secrets", forbidden_secret_access)
    output = tmp_path / "benchmark.json"
    result = runner.invoke(
        app,
        [
            "models",
            "benchmark",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--corpus",
            str(ROOT / "benchmarks" / "model_corpus" / "manifest.json"),
            "--model",
            config.models.threat_model.primary,
            "--output",
            str(output),
            "--cost-ledger",
            str(tmp_path / "missing-cost-ledger.json"),
            "--allow-code-egress",
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "existing cost ledger lock" in result.stdout
    assert not secret_accessed
    assert not output.exists()
    assert not (tmp_path / "missing-cost-ledger.json").exists()
    assert not (tmp_path / ".missing-cost-ledger.json.lock").exists()


def test_models_benchmark_output_path_does_not_select_or_create_budget_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
) -> None:
    tmp_path.chmod(0o700)
    config = config_factory()
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    ledger_path = tmp_path / "campaign-cost-ledger.json"
    AtomicCostLedger.initialize(
        ledger_path,
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    secret_calls = 0

    def stop_at_secret_boundary(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_calls
        secret_calls += 1
        raise ConfigError("synthetic secret boundary reached")

    monkeypatch.setattr("mmaudit.cli.load_operator_secrets", stop_at_secret_boundary)
    outputs = (tmp_path / "first-report.json", tmp_path / "second-report.json")
    for output in outputs:
        result = runner.invoke(
            app,
            [
                "models",
                "benchmark",
                "--config",
                str(tmp_path / "synthetic.toml"),
                "--corpus",
                str(ROOT / "benchmarks" / "model_corpus" / "manifest.json"),
                "--model",
                config.models.threat_model.primary,
                "--output",
                str(output),
                "--cost-ledger",
                str(ledger_path),
                "--allow-code-egress",
                "--no-color",
            ],
        )
        assert result.exit_code == ExitCode.CONFIGURATION
        assert "synthetic secret boundary reached" in result.stdout
        assert not output.exists()

    assert secret_calls == 2
    snapshot = AtomicCostLedger.open_existing(
        ledger_path,
        cap_usd=Decimal(str(config.execution.budget_usd)),
    ).snapshot()
    assert snapshot.entries == ()
    for output in outputs:
        derived = output.with_name(f"{output.stem}-cost-ledger.json")
        assert not derived.exists()
        assert not derived.with_name(f".{derived.name}.lock").exists()


@pytest.mark.parametrize("protected_name", ["ledger", "lock"])
def test_models_benchmark_rejects_output_that_aliases_cost_state_before_secret_access(
    protected_name: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
) -> None:
    tmp_path.chmod(0o700)
    config = config_factory()
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    ledger_path = tmp_path / "campaign-cost-ledger.json"
    ledger = AtomicCostLedger.initialize(
        ledger_path,
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr("mmaudit.cli.load_operator_secrets", forbidden_secret_access)
    output = ledger.path if protected_name == "ledger" else ledger.lock_path
    result = runner.invoke(
        app,
        [
            "models",
            "benchmark",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--corpus",
            str(ROOT / "benchmarks" / "model_corpus" / "manifest.json"),
            "--model",
            config.models.threat_model.primary,
            "--output",
            str(output),
            "--cost-ledger",
            str(ledger_path),
            "--allow-code-egress",
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "distinct from cost-ledger" in result.stdout
    assert "state" in result.stdout
    assert (
        AtomicCostLedger.open_existing(
            ledger_path,
            cap_usd=Decimal(str(config.execution.budget_usd)),
        )
        .snapshot()
        .entries
        == ()
    )


def test_benchmark_without_reports_is_explicitly_incomplete(tmp_path: Path) -> None:
    output = tmp_path / "benchmark.json"
    result = runner.invoke(
        app,
        [
            "benchmark",
            "--corpus",
            str(ROOT / "benchmarks" / "corpus" / "manifest.json"),
            "--ground-truth-root",
            str(ROOT),
            "--profile",
            AuditProfile.MAXIMUM_ASSURANCE.value,
            "--output-json",
            str(output),
            "--no-color",
        ],
    )
    assert result.exit_code == ExitCode.INCOMPLETE
    assert "incomplete" in result.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "3.0"
    assert payload["profile"] == AuditProfile.MAXIMUM_ASSURANCE.value
    assert payload["status"] == BenchmarkStatus.INCOMPLETE.value
    assert (
        payload["reports_expected"],
        payload["reports_attempted"],
        payload["reports_parsed"],
        payload["reports_loaded"],
    ) == (2, 0, 0, 0)
    assert {
        item["repository_id"]: (
            item["status"],
            item["attempted"],
            item["parsed"],
            item["usable"],
        )
        for item in payload["report_inputs"]
    } == {
        "economic_erc4626": ("MISSING", False, False, False),
        "maximum_assurance_protocol": ("MISSING", False, False, False),
    }
    assert {
        name for name, metric in payload["metrics"].items() if metric["state"] != "NOT_EVALUABLE"
    } == set()
    critical_recall = payload["metrics"]["critical_recall"]
    assert {name: critical_recall[name] for name in critical_recall if name != "detail"} == {
        "direction": "minimum",
        "evaluated": 0,
        "numerator": 0,
        "denominator": 4,
        "state": "NOT_EVALUABLE",
        "threshold": 1.0,
        "value": None,
    }
    assert critical_recall["detail"]
    assert payload["metrics"]["safe_near_miss_rejection_rate"]["denominator"] == 15
    assert payload["metrics"]["exact_location_accuracy"]["denominator"] == 13
    assert payload["metrics"]["reproduction_success_rate"]["denominator"] == 13
    assert all(gate["state"] == "NOT_EVALUABLE" and not gate["passed"] for gate in payload["gates"])
    assert {gate["name"] for gate in payload["gates"]} >= {
        "safe_control_false_confirmations",
        "evidence_caps",
        "maximum_assurance_semantic_coverage",
        "maximum_assurance_real_model_calls",
        "maximum_assurance_substantive_model_review",
    }


@pytest.mark.parametrize(
    ("report_state", "expected_status", "expected_parsed"),
    [
        ("malformed", "MALFORMED", False),
        ("stale", "STALE", True),
        ("failed", "FAILED", True),
    ],
)
def test_benchmark_keeps_unusable_reports_in_failure_accounting(
    tmp_path: Path,
    report_state: str,
    expected_status: str,
    expected_parsed: bool,
) -> None:
    repository_id = "economic_erc4626"
    reports = tmp_path / "reports"
    reports.mkdir()
    report_path = reports / f"{repository_id}.json"
    if report_state == "malformed":
        report_path.write_text("{", encoding="utf-8")
    else:
        report = benchmark_fixtures._report([], root_name=repository_id)
        if report_state == "stale":
            report = report.model_copy(
                update={
                    "repository": report.repository.model_copy(
                        update={"root_name": "different_repository"}
                    )
                }
            )
        else:
            report = report.model_copy(
                update={
                    "completed": False,
                    "incomplete_reasons": ["synthetic failed analysis"],
                }
            )
        report_path.write_text(report.model_dump_json(), encoding="utf-8")

    output = tmp_path / "benchmark.json"
    result = runner.invoke(
        app,
        [
            "benchmark",
            "--corpus",
            str(ROOT / "benchmarks" / "corpus" / "manifest.json"),
            "--reports",
            str(reports),
            "--ground-truth-root",
            str(ROOT),
            "--output-json",
            str(output),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.INCOMPLETE
    payload = json.loads(output.read_text(encoding="utf-8"))
    inputs = {item["repository_id"]: item for item in payload["report_inputs"]}
    assert payload["reports_expected"] == 2
    assert payload["reports_attempted"] == 1
    assert payload["reports_parsed"] == int(expected_parsed)
    assert payload["reports_loaded"] == 0
    assert inputs[repository_id]["status"] == expected_status
    assert inputs[repository_id]["attempted"]
    assert inputs[repository_id]["parsed"] is expected_parsed
    assert not inputs[repository_id]["usable"]
    assert inputs["maximum_assurance_protocol"]["status"] == "MISSING"
    assert payload["metrics"]["critical_recall"]["denominator"] == 4
    assert payload["metrics"]["critical_recall"]["evaluated"] == 0
    assert payload["metrics"]["critical_recall"]["state"] == "NOT_EVALUABLE"
    assert all(not result["evaluated"] for result in payload["case_results"])


def test_benchmark_loads_typed_mutation_scorecard(tmp_path: Path) -> None:
    scorecard = score_mutation_outcomes(
        property_corpus_hash="a" * 64,
        expected_property_ids=["prop-" + ("b" * 24)],
        property_repositories={
            "prop-" + ("b" * 24): "maximum_assurance_protocol",
        },
        outcomes=[
            MutationPropertyOutcome(
                mutation_id="mut-cli-fixture",
                mutation_kind=MutationKind.BOUNDARY_CHECK_WEAKENING,
                property_id="prop-" + ("b" * 24),
                outcome=MutationTestOutcome.KILLED,
                evidence_sha256="c" * 64,
            )
        ],
        minimum_property_kill_score=1,
    )
    scorecard_path = tmp_path / "mutation-scorecard.json"
    scorecard_path.write_text(scorecard.model_dump_json(), encoding="utf-8")
    output = tmp_path / "benchmark.json"

    result = runner.invoke(
        app,
        [
            "benchmark",
            "--corpus",
            str(ROOT / "benchmarks" / "corpus" / "manifest.json"),
            "--ground-truth-root",
            str(ROOT),
            "--mutation-scorecard",
            str(scorecard_path),
            "--output-json",
            str(output),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.INCOMPLETE
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["mutation_scorecard"]["gate_passed"] is True


def test_benchmark_refuses_symlinked_mutation_scorecard(tmp_path: Path) -> None:
    target = tmp_path / "scorecard.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "linked-scorecard.json"
    try:
        link.symlink_to(target)
    except OSError:
        return

    result = runner.invoke(
        app,
        [
            "benchmark",
            "--corpus",
            str(ROOT / "benchmarks" / "corpus" / "manifest.json"),
            "--ground-truth-root",
            str(ROOT),
            "--mutation-scorecard",
            str(link),
            "--output-json",
            str(tmp_path / "benchmark.json"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "regular non-symlink" in result.stdout


def test_benchmark_serializes_demonstrated_human_comparison_claim(
    tmp_path: Path,
) -> None:
    corpus_sha256 = "186534e1d0d263920d42041e39b05fd6fb4acc57f5e7e4c9c1321a403756845b"
    metric = ComparativeMetricEvidence(
        mmaudit=ProportionSample(successes=95, trials=100),
        human=ProportionSample(successes=70, trials=100),
    )
    evidence = seal_human_comparison_evidence(
        HumanComparisonEvidencePayload(
            comparison_id="cli-synthetic-comparison",
            corpus_sha256=corpus_sha256,
            benchmark_report_sha256="b" * 64,
            reports_generated_blind=True,
            ground_truth_withheld_from_humans=True,
            ground_truth_withheld_from_mmaudit=True,
            blinding_protocol_sha256="c" * 64,
            same_corpus=True,
            same_scope=True,
            same_time_budget=True,
            same_evidence_access=True,
            review_protocol_sha256="d" * 64,
            human_reviewer_count=3,
            adjudicators_independent=True,
            adjudicator_count=2,
            adjudication_sha256="e" * 64,
            precision=metric,
            recall=metric,
        )
    )
    evidence_path = tmp_path / "human-comparison.json"
    evidence_path.write_text(evidence.model_dump_json(), encoding="utf-8")
    output = tmp_path / "benchmark.json"

    result = runner.invoke(
        app,
        [
            "benchmark",
            "--corpus",
            str(ROOT / "benchmarks" / "corpus" / "manifest.json"),
            "--ground-truth-root",
            str(ROOT),
            "--human-comparison",
            str(evidence_path),
            "--output-json",
            str(output),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.INCOMPLETE
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["superiority_claim"]["status"] == SuperiorityClaimStatus.DEMONSTRATED
    assert all(item["passed"] for item in payload["superiority_claim"]["preconditions"])
    assert payload["superiority_claim"]["benchmark_report_sha256"] == "b" * 64

    wrong_payload = evidence.model_dump(mode="json", exclude={"evidence_sha256"})
    wrong_payload["corpus_sha256"] = "f" * 64
    wrong_evidence = seal_human_comparison_evidence(
        HumanComparisonEvidencePayload.model_validate(wrong_payload)
    )
    wrong_path = tmp_path / "wrong-corpus-comparison.json"
    wrong_path.write_text(wrong_evidence.model_dump_json(), encoding="utf-8")
    wrong_output = tmp_path / "wrong-benchmark.json"
    wrong_result = runner.invoke(
        app,
        [
            "benchmark",
            "--corpus",
            str(ROOT / "benchmarks" / "corpus" / "manifest.json"),
            "--ground-truth-root",
            str(ROOT),
            "--human-comparison",
            str(wrong_path),
            "--output-json",
            str(wrong_output),
            "--no-color",
        ],
    )
    assert wrong_result.exit_code == ExitCode.CONFIGURATION
    assert "evaluated benchmark corpus" in wrong_result.stdout
    assert not wrong_output.exists()


def _failed_benchmark_report(report: BenchmarkReport) -> BenchmarkReport:
    payload = report.model_dump(mode="json")
    payload["status"] = BenchmarkStatus.FAILED.value
    payload["metrics"]["model_review_coverage"] = {
        "numerator": 0,
        "denominator": 1,
        "evaluated": 1,
        "value": 0,
        "state": BenchmarkMetricState.FAIL.value,
        "threshold": 1,
        "direction": "minimum",
        "detail": "Synthetic substantive review did not meet its threshold.",
    }
    substantive_gate = next(
        gate
        for gate in payload["gates"]
        if gate["name"] == "maximum_assurance_substantive_model_review"
    )
    substantive_gate["state"] = BenchmarkMetricState.FAIL.value
    substantive_gate["passed"] = False
    return BenchmarkReport.model_validate(payload)


def _write_certificate_components(
    tmp_path: Path,
    *,
    status: BenchmarkStatus = BenchmarkStatus.PASSED,
) -> tuple[Path, Path]:
    component_root = tmp_path / "components"
    (component_root / "prompts").mkdir(parents=True)
    component_contents = {
        "mmaudit.toml": 'profile = "maximum-assurance"\n',
        "prompts/discovery.md": "Synthetic defensive prompt.\n",
        "models.json": '{"lineage":"synthetic-a"}\n',
        "tools.json": '{"scanner":"synthetic","version":"1"}\n',
        "compilers.json": '{"compiler":"solc","version":"0.8.30"}\n',
        "corpus.json": certificate_fixtures._benchmark_manifest().model_dump_json() + "\n",
        "ground-truth.json": '{"case_hashes":["aaaaaaaa"]}\n',
    }
    for relative_path, contents in component_contents.items():
        (component_root / relative_path).write_text(contents, encoding="utf-8")
    report = certificate_fixtures._benchmark_report()
    if status is BenchmarkStatus.FAILED:
        report = _failed_benchmark_report(report)
    assert report.status is status
    (component_root / "benchmark-results.json").write_text(
        report.model_dump_json(),
        encoding="utf-8",
    )
    inputs = {
        "configuration": ["mmaudit.toml"],
        "prompts": ["prompts/discovery.md"],
        "models": ["models.json"],
        "tools": ["tools.json"],
        "compilers": ["compilers.json"],
        "corpus": ["corpus.json"],
        "ground_truth": ["ground-truth.json"],
        "benchmark_report": "benchmark-results.json",
    }
    inputs_path = tmp_path / "certificate-inputs.json"
    inputs_path.write_text(json.dumps(inputs), encoding="utf-8")
    return component_root, inputs_path


def _certify(
    tmp_path: Path,
    component_root: Path,
    inputs_path: Path,
) -> tuple[Path, object]:
    certificate_path = tmp_path / "benchmark-certificate.json"
    result = runner.invoke(
        app,
        [
            "benchmark",
            "certify",
            "--component-root",
            str(component_root),
            "--inputs",
            str(inputs_path),
            "--repository-commit",
            CERTIFICATE_COMMIT,
            "--output",
            str(certificate_path),
            "--no-color",
        ],
    )
    return certificate_path, result


def test_benchmark_certificate_cli_success_and_current_verification(
    tmp_path: Path,
) -> None:
    component_root, inputs_path = _write_certificate_components(tmp_path)
    certificate_path, certify_result = _certify(
        tmp_path,
        component_root,
        inputs_path,
    )
    verification_path = tmp_path / "verification.json"

    verify_result = runner.invoke(
        app,
        [
            "verify-certificate",
            "--certificate",
            str(certificate_path),
            "--component-root",
            str(component_root),
            "--repository-commit",
            CERTIFICATE_COMMIT,
            "--output",
            str(verification_path),
            "--no-color",
        ],
    )

    assert certify_result.exit_code == ExitCode.SUCCESS
    assert load_benchmark_certificate(certificate_path).benchmark_name == (
        "Synthetic file-backed benchmark"
    )
    assert verify_result.exit_code == ExitCode.SUCCESS
    assert json.loads(verification_path.read_text(encoding="utf-8"))["status"] == ("current")


def test_benchmark_certificate_cli_rejects_resealed_semantic_counter_bypass(
    tmp_path: Path,
) -> None:
    component_root, inputs_path = _write_certificate_components(tmp_path)
    report_path = component_root / "benchmark-results.json"
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    payload["coverage_metrics"] = {}
    payload["reports_missing_coverage"] = 1
    payload["evidence_cap_bypasses"] = 1
    report_path.write_text(json.dumps(payload), encoding="utf-8")

    certificate_path, result = _certify(
        tmp_path,
        component_root,
        inputs_path,
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "failed safely" in result.stdout
    assert not certificate_path.exists()


def test_verify_certificate_cli_rejects_stale_component_binding(
    tmp_path: Path,
) -> None:
    component_root, inputs_path = _write_certificate_components(tmp_path)
    certificate_path, certify_result = _certify(
        tmp_path,
        component_root,
        inputs_path,
    )
    assert certify_result.exit_code == ExitCode.SUCCESS
    (component_root / "mmaudit.toml").write_text(
        'profile = "changed"\n',
        encoding="utf-8",
    )
    verification_path = tmp_path / "stale-verification.json"

    result = runner.invoke(
        app,
        [
            "verify-certificate",
            "--certificate",
            str(certificate_path),
            "--component-root",
            str(component_root),
            "--repository-commit",
            CERTIFICATE_COMMIT,
            "--output",
            str(verification_path),
            "--no-color",
        ],
    )

    payload = json.loads(verification_path.read_text(encoding="utf-8"))
    assert result.exit_code == ExitCode.INCOMPLETE
    assert payload["status"] == "stale"
    assert payload["mismatches"][0]["identifier"] == "configuration/00000"


def test_verify_certificate_cli_rejects_tampered_certificate(
    tmp_path: Path,
) -> None:
    component_root, inputs_path = _write_certificate_components(tmp_path)
    certificate_path, certify_result = _certify(
        tmp_path,
        component_root,
        inputs_path,
    )
    assert certify_result.exit_code == ExitCode.SUCCESS
    tampered = json.loads(certificate_path.read_text(encoding="utf-8"))
    tampered["benchmark_name"] = "Tampered"
    certificate_path.write_text(json.dumps(tampered), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "verify-certificate",
            "--certificate",
            str(certificate_path),
            "--component-root",
            str(component_root),
            "--repository-commit",
            CERTIFICATE_COMMIT,
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "self-hash" in result.stdout


def test_benchmark_certify_cli_requires_passed_gates(tmp_path: Path) -> None:
    component_root, inputs_path = _write_certificate_components(
        tmp_path,
        status=BenchmarkStatus.FAILED,
    )
    certificate_path, result = _certify(tmp_path, component_root, inputs_path)

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "benchmark report is not certifiable" in result.stdout
    assert "benchmark status is failed, not passed" in result.stdout
    assert "required benchmark gates" in result.stdout
    assert not certificate_path.exists()


def _run_gate_arguments(
    *,
    tmp_path: Path,
    repository: Path,
    certificate_path: Path | None = None,
    component_root: Path | None = None,
) -> list[str]:
    arguments = [
        "run",
        "--config",
        str(ROOT / "mmaudit.example.toml"),
        "--repo",
        str(repository),
        "--output",
        str(tmp_path / "audit-output"),
        "--scanner-only",
        "--skip-codeql",
        "--benchmark-gate",
        "--no-color",
    ]
    if certificate_path is not None:
        arguments.extend(["--benchmark-certificate", str(certificate_path)])
    if component_root is not None:
        arguments.extend(["--benchmark-component-root", str(component_root)])
    if certificate_path is not None and component_root is not None:
        arguments.extend(["--benchmark-repository-commit", CERTIFICATE_COMMIT])
    return arguments


def _synthetic_run_repository(tmp_path: Path) -> Path:
    repository = tmp_path / "audit-repository"
    repository.mkdir()
    (repository / "app.py").write_text("value = 1\n", encoding="utf-8")
    return repository


def test_run_benchmark_gate_passes_typed_verification_to_pipeline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    component_root, inputs_path = _write_certificate_components(tmp_path)
    certificate_path, certify_result = _certify(
        tmp_path,
        component_root,
        inputs_path,
    )
    assert certify_result.exit_code == ExitCode.SUCCESS
    repository = _synthetic_run_repository(tmp_path)
    captured: dict[str, object] = {}

    class SyntheticPipelineResult:
        run_dir = tmp_path / "synthetic-run"

        def exit_for_findings(self, fail_on) -> ExitCode:
            del fail_on
            return ExitCode.SUCCESS

    class SyntheticPipeline:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs
            captured["constructed"] = True

        async def run(self, **kwargs):
            captured.update(kwargs)
            return SyntheticPipelineResult()

    monkeypatch.setattr("mmaudit.cli.AuditPipeline", SyntheticPipeline)

    result = runner.invoke(
        app,
        _run_gate_arguments(
            tmp_path=tmp_path,
            repository=repository,
            certificate_path=certificate_path,
            component_root=component_root,
        ),
    )

    assert result.exit_code == ExitCode.SUCCESS
    verification = captured["benchmark_verification"]
    assert verification.status is CertificateVerificationStatus.CURRENT


def test_run_benchmark_gate_rejects_absent_certificate_before_pipeline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository = _synthetic_run_repository(tmp_path)
    constructed = False

    class ForbiddenPipeline:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs
            nonlocal constructed
            constructed = True

    monkeypatch.setattr("mmaudit.cli.AuditPipeline", ForbiddenPipeline)

    result = runner.invoke(
        app,
        _run_gate_arguments(tmp_path=tmp_path, repository=repository),
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "benchmark gate requires" in result.stdout
    assert not constructed


def test_run_benchmark_gate_allows_wholly_missing_inputs_with_explicit_downgrade(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository = _synthetic_run_repository(tmp_path)
    captured: dict[str, object] = {}

    class SyntheticPipelineResult:
        run_dir = tmp_path / "synthetic-run"

        def exit_for_findings(self, fail_on) -> ExitCode:
            del fail_on
            return ExitCode.SUCCESS

    class SyntheticPipeline:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs

        async def run(self, **kwargs):
            captured.update(kwargs)
            return SyntheticPipelineResult()

    monkeypatch.setattr("mmaudit.cli.AuditPipeline", SyntheticPipeline)
    arguments = [
        *_run_gate_arguments(tmp_path=tmp_path, repository=repository),
        "--profile",
        "maximum-assurance",
        "--allow-maximum-assurance-downgrade",
    ]

    result = runner.invoke(app, arguments)

    assert result.exit_code == ExitCode.SUCCESS
    assert captured["benchmark_verification"] is None
    assert captured["require_maximum_assurance"] is None
    assert captured["allow_maximum_assurance_downgrade"] is None


def test_run_benchmark_gate_preserves_configured_downgrade_when_flag_is_absent(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository = _synthetic_run_repository(tmp_path)
    config_path = tmp_path / "maximum-downgrade.toml"
    config_contents = (ROOT / "mmaudit.example.toml").read_text(encoding="utf-8")
    config_contents = config_contents.replace(
        'profile = "standard"',
        'profile = "maximum-assurance"',
        1,
    ).replace(
        "allow_downgrade = false",
        "allow_downgrade = true",
        1,
    )
    config_path.write_text(config_contents, encoding="utf-8")
    captured: dict[str, object] = {}

    class SyntheticPipelineResult:
        run_dir = tmp_path / "synthetic-run"

        def exit_for_findings(self, fail_on) -> ExitCode:
            del fail_on
            return ExitCode.SUCCESS

    class SyntheticPipeline:
        def __init__(self, config, *args, **kwargs) -> None:
            del args, kwargs
            captured["config"] = config

        async def run(self, **kwargs):
            captured.update(kwargs)
            return SyntheticPipelineResult()

    monkeypatch.setattr("mmaudit.cli.AuditPipeline", SyntheticPipeline)
    arguments = _run_gate_arguments(tmp_path=tmp_path, repository=repository)
    arguments[arguments.index("--config") + 1] = str(config_path)

    result = runner.invoke(app, arguments)

    assert result.exit_code == ExitCode.SUCCESS
    config = captured["config"]
    assert config.maximum_assurance.allow_downgrade is True
    assert captured["benchmark_verification"] is None
    assert captured["require_maximum_assurance"] is None
    assert captured["allow_maximum_assurance_downgrade"] is None


def test_run_preserves_configured_maximum_requirement_when_flag_is_absent(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository = _synthetic_run_repository(tmp_path)
    config_path = tmp_path / "required-maximum.toml"
    config_contents = (ROOT / "mmaudit.example.toml").read_text(encoding="utf-8")
    config_path.write_text(
        config_contents.replace("require = false", "require = true", 1),
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    class SyntheticPipelineResult:
        run_dir = tmp_path / "synthetic-run"

        def exit_for_findings(self, fail_on) -> ExitCode:
            del fail_on
            return ExitCode.SUCCESS

    class SyntheticPipeline:
        def __init__(self, config, *args, **kwargs) -> None:
            del args, kwargs
            captured["config"] = config

        async def run(self, **kwargs):
            captured.update(kwargs)
            return SyntheticPipelineResult()

    monkeypatch.setattr("mmaudit.cli.AuditPipeline", SyntheticPipeline)

    result = runner.invoke(
        app,
        [
            "run",
            "--config",
            str(config_path),
            "--repo",
            str(repository),
            "--output",
            str(tmp_path / "audit-output"),
            "--scanner-only",
            "--skip-codeql",
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.SUCCESS
    config = captured["config"]
    assert config.maximum_assurance.require is True
    assert captured["require_maximum_assurance"] is None
    assert captured["allow_maximum_assurance_downgrade"] is None


def test_run_benchmark_gate_rejects_partial_inputs_even_with_downgrade(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository = _synthetic_run_repository(tmp_path)
    constructed = False

    class ForbiddenPipeline:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs
            nonlocal constructed
            constructed = True

    monkeypatch.setattr("mmaudit.cli.AuditPipeline", ForbiddenPipeline)
    arguments = [
        *_run_gate_arguments(
            tmp_path=tmp_path,
            repository=repository,
            certificate_path=tmp_path / "partial-certificate.json",
        ),
        "--profile",
        "maximum-assurance",
        "--allow-maximum-assurance-downgrade",
    ]

    result = runner.invoke(app, arguments)

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "benchmark gate requires" in result.stdout
    assert not constructed


def test_run_benchmark_gate_rejects_stale_binding_before_pipeline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    component_root, inputs_path = _write_certificate_components(tmp_path)
    certificate_path, certify_result = _certify(
        tmp_path,
        component_root,
        inputs_path,
    )
    assert certify_result.exit_code == ExitCode.SUCCESS
    (component_root / "tools.json").write_text(
        '{"scanner":"changed"}\n',
        encoding="utf-8",
    )
    repository = _synthetic_run_repository(tmp_path)
    constructed = False

    class ForbiddenPipeline:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs
            nonlocal constructed
            constructed = True

    monkeypatch.setattr("mmaudit.cli.AuditPipeline", ForbiddenPipeline)

    result = runner.invoke(
        app,
        _run_gate_arguments(
            tmp_path=tmp_path,
            repository=repository,
            certificate_path=certificate_path,
            component_root=component_root,
        ),
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "certificate is stale" in result.stdout
    assert not constructed


def test_run_benchmark_gate_allows_stale_binding_with_explicit_downgrade(
    tmp_path: Path,
    monkeypatch,
) -> None:
    component_root, inputs_path = _write_certificate_components(tmp_path)
    certificate_path, certify_result = _certify(
        tmp_path,
        component_root,
        inputs_path,
    )
    assert certify_result.exit_code == ExitCode.SUCCESS
    (component_root / "tools.json").write_text(
        '{"scanner":"changed"}\n',
        encoding="utf-8",
    )
    repository = _synthetic_run_repository(tmp_path)
    captured: dict[str, object] = {}

    class SyntheticPipelineResult:
        run_dir = tmp_path / "synthetic-run"

        def exit_for_findings(self, fail_on) -> ExitCode:
            del fail_on
            return ExitCode.SUCCESS

    class SyntheticPipeline:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs

        async def run(self, **kwargs):
            captured.update(kwargs)
            return SyntheticPipelineResult()

    monkeypatch.setattr("mmaudit.cli.AuditPipeline", SyntheticPipeline)
    arguments = [
        *_run_gate_arguments(
            tmp_path=tmp_path,
            repository=repository,
            certificate_path=certificate_path,
            component_root=component_root,
        ),
        "--profile",
        "maximum-assurance",
        "--allow-maximum-assurance-downgrade",
    ]

    result = runner.invoke(app, arguments)

    assert result.exit_code == ExitCode.SUCCESS
    verification = captured["benchmark_verification"]
    assert verification.status is CertificateVerificationStatus.STALE
    assert captured["allow_maximum_assurance_downgrade"] is None


def test_run_benchmark_gate_rejects_current_failed_corpus_before_pipeline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    component_root, inputs_path = _write_certificate_components(tmp_path)
    certificate_path, certify_result = _certify(
        tmp_path,
        component_root,
        inputs_path,
    )
    assert certify_result.exit_code == ExitCode.SUCCESS
    report_path = component_root / "benchmark-results.json"
    failed_report = _failed_benchmark_report(
        BenchmarkReport.model_validate_json(report_path.read_text(encoding="utf-8"))
    )
    report_path.write_text(failed_report.model_dump_json(), encoding="utf-8")
    original = load_benchmark_certificate(certificate_path)
    observed_bindings, observed_report = observe_file_backed_certificate(
        original,
        component_root=component_root,
    )
    manually_resealed = seal_benchmark_certificate(
        BenchmarkCertificatePayload(
            certificate_id=original.certificate_id,
            benchmark_name=original.benchmark_name,
            profile=original.profile,
            repository_git_commit=original.repository_git_commit,
            bindings=observed_bindings,
            benchmark_report=observed_report,
        )
    )
    write_benchmark_certificate(certificate_path, manually_resealed)
    repository = _synthetic_run_repository(tmp_path)
    constructed = False

    class ForbiddenPipeline:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs
            nonlocal constructed
            constructed = True

    monkeypatch.setattr("mmaudit.cli.AuditPipeline", ForbiddenPipeline)

    result = runner.invoke(
        app,
        _run_gate_arguments(
            tmp_path=tmp_path,
            repository=repository,
            certificate_path=certificate_path,
            component_root=component_root,
        ),
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "benchmark report is not certifiable" in result.stdout
    assert "failed, not passed" in result.stdout
    assert "required benchmark gates did not pass" in result.stdout
    assert not constructed


def test_snapshot_import_requires_explicit_opt_in_before_plan_or_network_access(
    tmp_path: Path,
) -> None:
    result = runner.invoke(
        app,
        [
            "snapshot",
            "import",
            "--plan",
            str(tmp_path / "missing.json"),
            "--rpc-url",
            "http://127.0.0.1:8545",
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "--allow-read-only-import" in result.stdout


def test_init_does_not_overwrite_without_force(tmp_path: Path) -> None:
    first = runner.invoke(app, ["init", "--directory", str(tmp_path)])
    assert first.exit_code == 0
    config = tmp_path / "mmaudit.toml"
    config.write_text("sentinel", encoding="utf-8")
    second = runner.invoke(app, ["init", "--directory", str(tmp_path)])
    assert second.exit_code == ExitCode.CONFIGURATION
    assert config.read_text(encoding="utf-8") == "sentinel"
    forced = runner.invoke(app, ["init", "--directory", str(tmp_path), "--force"])
    assert forced.exit_code == 0
    assert "version = 1" in config.read_text(encoding="utf-8")


def test_init_refuses_symlink_even_with_force(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_text("sentinel", encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    try:
        (target / "mmaudit.toml").symlink_to(outside)
    except OSError:
        return
    result = runner.invoke(
        app,
        ["init", "--directory", str(target), "--force"],
    )
    assert result.exit_code == ExitCode.CONFIGURATION
    assert outside.read_text(encoding="utf-8") == "sentinel"


def test_init_force_does_not_write_through_hardlink(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_text("sentinel", encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    try:
        (target / "mmaudit.toml").hardlink_to(outside)
    except OSError:
        return
    result = runner.invoke(
        app,
        ["init", "--directory", str(target), "--force"],
    )
    assert result.exit_code == 0
    assert outside.read_text(encoding="utf-8") == "sentinel"
    assert "version = 1" in (target / "mmaudit.toml").read_text(encoding="utf-8")


def test_doctor_without_credentials_fails_safely(tmp_path: Path, monkeypatch) -> None:
    canary = "sk-or-v1-ambient-value-must-be-ignored"
    monkeypatch.setenv("OPENROUTER_API_KEY", canary)
    monkeypatch.delenv("MMAUDIT_SECRETS_ENV_FILE", raising=False)
    config = tmp_path / "mmaudit.toml"
    shutil.copy2(ROOT / "mmaudit.example.toml", config)
    result = runner.invoke(
        app,
        [
            "doctor",
            "--config",
            str(config),
            "--repo",
            str(tmp_path),
            "--output",
            str(tmp_path / "output"),
            "--no-color",
        ],
    )
    assert result.exit_code == ExitCode.CONFIGURATION
    assert "Operator secret file" in result.stdout
    assert "rejected" in result.stdout
    assert "missing" in result.stdout
    assert "invalid" in result.stdout
    assert canary not in result.stdout
    assert "replace-with-an-openrouter-key" not in result.stdout


@pytest.mark.parametrize(("authenticated", "status"), [(True, "valid"), (False, "invalid")])
def test_doctor_reports_only_secret_and_authentication_state(
    tmp_path: Path,
    monkeypatch,
    authenticated: bool,
    status: str,
) -> None:
    canary = "sk-or-v1-synthetic-doctor-canary"
    secret_file = tmp_path / "operator.env"
    secret_file.write_text(f"OPENROUTER_API_KEY={canary}\n", encoding="utf-8")
    secret_file.chmod(0o600)
    config = tmp_path / "mmaudit.toml"
    shutil.copy2(ROOT / "mmaudit.example.toml", config)
    observed: list[str] = []

    def validate(_config, api_key: str) -> bool:
        observed.append(api_key)
        return authenticated

    monkeypatch.setattr("mmaudit.cli._openrouter_authentication_valid", validate)
    result = runner.invoke(
        app,
        [
            "doctor",
            "--config",
            str(config),
            "--secrets-env-file",
            str(secret_file),
            "--repo",
            str(tmp_path),
            "--output",
            str(tmp_path / "output"),
            "--no-color",
        ],
    )

    assert observed == [canary]
    assert "Operator secret file" in result.stdout
    assert "accepted" in result.stdout
    assert "present" in result.stdout
    assert status in result.stdout
    assert canary not in result.stdout
    assert str(secret_file) not in result.stdout


def test_scanner_only_cli_never_requires_api_key(
    tmp_path: Path, vulnerable_repo: Path, monkeypatch
) -> None:
    canary = "sk-or-v1-scanner-only-artifact-canary"
    secret_file = tmp_path / "operator.env"
    secret_file.write_text(f"OPENROUTER_API_KEY={canary}\n", encoding="utf-8")
    secret_file.chmod(0o600)
    monkeypatch.setenv("OPENROUTER_API_KEY", canary)
    monkeypatch.setenv("MMAUDIT_SECRETS_ENV_FILE", str(secret_file))
    config = tmp_path / "mmaudit.toml"
    shutil.copy2(ROOT / "mmaudit.example.toml", config)
    output = tmp_path / "reports"
    result = runner.invoke(
        app,
        [
            "scan",
            "--config",
            str(config),
            "--secrets-env-file",
            str(secret_file),
            "--repo",
            str(vulnerable_repo),
            "--output",
            str(output),
            "--skip-codeql",
            "--allow-fork",
            "--no-color",
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert (output / "latest" / "scanner-results.json").is_file()
    assert (output / "latest" / "audit-results.sarif").is_file()
    serialized = result.stdout + result.stderr
    serialized += "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in output.rglob("*")
        if path.is_file()
    )
    assert canary not in serialized


def test_models_check_requires_operator_secret_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "ambient-value-must-be-ignored")
    monkeypatch.delenv("MMAUDIT_SECRETS_ENV_FILE", raising=False)
    config = tmp_path / "mmaudit.toml"
    shutil.copy2(ROOT / "mmaudit.example.toml", config)
    result = runner.invoke(app, ["models", "check", "--config", str(config)])
    assert result.exit_code == ExitCode.CONFIGURATION
    assert "operator secret file is not selected" in result.stdout


def test_models_check_rejects_empty_provider_endpoint_policy_before_network(
    tmp_path: Path,
    monkeypatch,
    config_factory,
) -> None:
    secret_file = tmp_path / "operator.env"
    secret_file.write_text("OPENROUTER_API_KEY=synthetic-check-key\n", encoding="utf-8")
    secret_file.chmod(0o600)
    config = config_factory(
        models={
            "provider_policy": {
                "only": [],
                "order": [],
                "allow_fallbacks": False,
            }
        }
    )
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)

    class UnexpectedClient:
        def __init__(self, **_kwargs: object) -> None:
            raise AssertionError("models check reached the network client")

    monkeypatch.setattr("mmaudit.cli.OpenRouterClient", UnexpectedClient)
    result = runner.invoke(
        app,
        [
            "models",
            "check",
            "--config",
            str(tmp_path / "mmaudit.toml"),
            "--secrets-env-file",
            str(secret_file),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "explicit provider endpoint" in result.stdout
    assert "allowlist" in result.stdout


def test_models_check_rejects_unavailable_exact_provider_endpoint(
    tmp_path: Path,
    monkeypatch,
    config_factory,
) -> None:
    canary = "sk-or-v1-synthetic-model-check-canary"
    secret_file = tmp_path / "operator.env"
    secret_file.write_text(f"OPENROUTER_API_KEY={canary}\n", encoding="utf-8")
    secret_file.chmod(0o600)
    config = config_factory()
    model_ids = tuple(sorted(set(configured_model_ids(config, include_fallbacks=True))))
    observed_models: list[str] = []
    observed_keys: list[str] = []
    closed = False

    def endpoint_record(model_id: str, endpoint: str) -> dict[str, object]:
        return {
            "model_id": model_id,
            "tag": endpoint,
            "provider_name": "Synthetic Provider",
            "status": 0,
            "context_length": 200_000,
            "max_prompt_tokens": 180_000,
            "max_completion_tokens": 20_000,
            "supported_parameters": ["max_tokens", "response_format", "temperature"],
            "pricing": {
                "prompt": "0.000001",
                "completion": "0.00001",
                "request": "0",
            },
        }

    class EndpointMismatchClient:
        def __init__(self, *, api_key: str, **_kwargs: object) -> None:
            observed_keys.append(api_key)

        async def list_models(self) -> list[dict[str, object]]:
            return [
                {
                    "id": model_id,
                    "supported_parameters": ["response_format"],
                }
                for model_id in model_ids
            ]

        async def list_zdr_endpoints(self) -> dict[str, object]:
            return {
                "data": [endpoint_record(model_id, "synthetic-provider") for model_id in model_ids]
            }

        async def get_model_endpoint_metadata(self, model_id: str) -> dict[str, object]:
            observed_models.append(model_id)
            return {
                "data": {
                    "id": model_id,
                    "endpoints": [endpoint_record(model_id, "unapproved-provider")],
                }
            }

        async def close(self) -> None:
            nonlocal closed
            closed = True

    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    monkeypatch.setattr("mmaudit.cli.OpenRouterClient", EndpointMismatchClient)

    result = runner.invoke(
        app,
        [
            "models",
            "check",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--secrets-env-file",
            str(secret_file),
            "--refresh",
            "--no-color",
        ],
        env={"COLUMNS": "500"},
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert observed_keys == [canary]
    assert observed_models == list(model_ids)
    assert closed is True
    assert "exact provider endpoint validation failed" in result.stdout
    assert "configured endpoint tag or slug is unavailable: synthetic-provider" in result.stdout
    assert "Validated" not in result.stdout
    assert canary not in result.stdout
    assert str(secret_file) not in result.stdout
