"""Typer command-line interface for mmaudit."""

from __future__ import annotations

import asyncio
import os
import re
import stat
import sys
import tempfile
import uuid
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from importlib.resources import files
from pathlib import Path
from typing import Annotated, Any, Literal

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from mmaudit.artifact_limits import MAX_JSON_ARTIFACT_BYTES
from mmaudit.benchmark.certificate import (
    CertificateVerificationStatus,
    build_file_backed_benchmark_certificate,
    load_benchmark_certificate_file_inputs,
    verify_file_backed_benchmark_certificate,
    write_benchmark_certificate,
    write_benchmark_certificate_verification,
)
from mmaudit.benchmark.claims import load_human_comparison_evidence
from mmaudit.benchmark.cross_lineage_adjudication import CrossLineageAdjudicationRunKind
from mmaudit.benchmark.engine import (
    BenchmarkMetricState,
    BenchmarkStatus,
    evaluate_benchmark,
    load_manifest,
    load_reports,
    validate_benchmark_ground_truth,
    write_benchmark_report,
)
from mmaudit.benchmark.model_portfolio import (
    CandidateBenchmarkCampaignJournal,
    ModelBenchmarkPortfolio,
    create_candidate_benchmark_campaign,
    issue_trusted_candidate_benchmark_campaign_verification,
    load_model_benchmark_portfolio,
    resume_candidate_benchmark_campaign,
    seal_model_benchmark_portfolio_from_campaign,
    verify_model_benchmark_portfolio_campaign,
)
from mmaudit.benchmark.models import (
    ModelBenchmarkReport,
    ModelBenchmarkSuite,
    OpenRouterModelBenchmarkProvider,
    load_model_benchmark_corpus,
    run_model_benchmark,
    select_model_benchmark_targets,
    validate_model_benchmark_egress,
    write_model_benchmark_report,
)
from mmaudit.benchmark.mutations import load_mutation_scorecard
from mmaudit.config import (
    AuditConfig,
    AuditConfigOverrides,
    ConfigError,
    ExecutionConfig,
    PrivacyConfig,
    audit_config_overrides,
    configured_model_ids,
    load_config,
    load_config_with_provenance,
    require_maximum_assurance_qualification_pins,
    validate_model_independence,
)
from mmaudit.constants import DEFAULT_CONFIG_NAME, VERSION, ExitCode
from mmaudit.forensic_export import (
    export_complete_forensic_bundle,
    verify_complete_forensic_bundle,
)
from mmaudit.logging import configure_logging
from mmaudit.models.authenticated_runner_durable_bundle import (
    AuthenticatedRunnerDurableBundleError,
    AuthenticatedRunnerDurableEvidenceBundle,
    authenticated_runner_durable_bundle_bytes,
    build_authenticated_runner_durable_bundle,
    load_authenticated_runner_durable_bundle,
)
from mmaudit.models.authenticated_runner_execution import (
    AuthenticatedRunnerRunPlan,
)
from mmaudit.models.authenticated_runner_smoke import (
    MAX_AUTHENTICATED_RUNNER_SMOKE_BUNDLE_BYTES,
    AuthenticatedRunnerSmokeError,
    AuthenticatedRunnerSmokeEvidenceBundle,
    authenticated_runner_smoke_evidence_bytes,
    revalidate_authenticated_runner_smoke_evidence_bytes,
)
from mmaudit.models.authenticated_runner_smoke_corpus import (
    load_authenticated_runner_smoke_corpus_bundle,
)
from mmaudit.models.calibration import (
    build_model_calibration_artifact,
    derive_calibrated_qualification_policy,
    issue_trusted_model_calibration_verification,
    write_calibrated_qualification_policy,
    write_model_calibration_artifact,
)
from mmaudit.models.candidate_benchmark import (
    CandidateBenchmarkExecutionResult,
    CandidateBenchmarkRunState,
    run_candidate_registry_benchmarks,
    validate_candidate_benchmark_egress,
    validate_candidate_benchmark_policy_capacity,
)
from mmaudit.models.candidate_registry_bridge import (
    derive_candidate_registry_from_discovery,
    preflight_candidate_registry_output,
    validate_candidate_registry_template_selection,
    write_candidate_registry_json,
)
from mmaudit.models.candidate_selection import (
    CandidateSelectionPlan,
    derive_pending_candidate_registry_from_selection_plan,
    load_candidate_selection_plan,
    read_candidate_selection_source,
    validate_candidate_selection_discovery_capability,
    validate_candidate_selection_plan_sources,
    validate_candidate_selection_routes,
)
from mmaudit.models.discovery import (
    DiscoveryCandidateRoute,
    load_model_discovery_run,
    openrouter_catalog_canonical_slug,
    validate_openrouter_model_discovery,
    write_model_discovery_run,
)
from mmaudit.models.endpoint_snapshots import (
    EndpointSnapshotValidationError,
    validate_openrouter_endpoint_snapshot,
)
from mmaudit.models.generation_evidence import TrustedGenerationVerification
from mmaudit.models.ground_truth_authority import (
    load_frozen_ground_truth_provenance,
    resolve_verified_frozen_ground_truth,
)
from mmaudit.models.identifiers import is_exact_openrouter_model_id
from mmaudit.models.lineage_authority import (
    TrustedModelLineageReviewVerification,
    load_model_lineage_authority_bundle,
    load_model_lineage_trust_anchor,
    verify_operator_model_lineage_authority,
)
from mmaudit.models.lineage_review import ModelLineageReviewArtifact
from mmaudit.models.openrouter import (
    OpenRouterAuthenticationError,
    OpenRouterClient,
    OpenRouterError,
    OpenRouterProviderUnavailableError,
    OpenRouterRateLimitError,
    OpenRouterTimeoutError,
)
from mmaudit.models.output_modes import supported_output_modes
from mmaudit.models.policy_eligibility_refresh import (
    ModelPolicyEligibilityRefreshError,
    build_model_policy_eligibility_refresh_artifact,
    load_model_policy_eligibility_artifact,
    load_policy_eligibility_checked_routes,
    load_policy_eligibility_source_observation,
    validate_model_policy_eligibility_refresh_inputs,
)
from mmaudit.models.public_lineage_authority import resolve_verified_public_model_lineage
from mmaudit.models.qualification import (
    CandidateRegistry,
    QualificationPolicy,
    VerifiedProductionQualification,
    load_candidate_registry,
    load_qualification_policy,
    validate_candidate_registry_discovery,
    verify_model_qualification,
)
from mmaudit.models.qualification_workflow import (
    QualificationWorkflowBundle,
    load_qualification_release_bindings,
    load_qualification_workflow_bundle,
    refetch_trusted_benchmark_generations,
    run_qualification_workflow,
    seal_qualification_release_bindings,
    validate_qualification_portfolio_readiness,
    write_qualification_workflow_bundle,
)
from mmaudit.models.refresh import (
    ModelRefreshFailureCode,
    ModelRefreshValidationError,
    SelectedModelRoute,
    build_model_refresh_snapshot_from_source,
    build_model_refresh_source_evidence,
    diff_model_refresh,
    evaluate_model_refresh_freshness,
    load_model_refresh_snapshot,
    load_model_refresh_source_evidence,
    reject_model_refresh_secret_reflection,
    seal_model_refresh_attempt,
    validate_model_refresh_controls,
    write_model_refresh_failure,
    write_model_refresh_success,
)
from mmaudit.models.registry import ModelRegistry, extract_zdr_model_ids
from mmaudit.models.release_attestation import (
    TrustedReleaseBindingObservation,
    measure_qualification_release_environment,
    observe_and_verify_qualification_release,
    write_observed_qualification_release_bindings,
)
from mmaudit.models.runtime import build_openrouter_runtime_controls
from mmaudit.models.schemas import (
    AuditProfile,
    AuditReport,
    AuditScope,
    ExecutionEvidenceKind,
    Finding,
    LanguageCapabilityProfile,
    MaximumAssuranceStatus,
    Severity,
)
from mmaudit.models.usage import UsageLedger
from mmaudit.operator_secrets import (
    OperatorSecretError,
    OperatorSecrets,
    load_operator_secrets,
    select_operator_secret_file,
)
from mmaudit.orchestration.authenticated_runner_openrouter import (
    AuthenticatedRunnerOpenRouterExecutionSnapshot,
    AuthenticatedRunnerOpenRouterLaunch,
    AuthenticatedRunnerOpenRouterResult,
    AuthenticatedRunnerOpenRouterRunSnapshot,
    execute_authenticated_openrouter_runner,
    preflight_authenticated_openrouter_launch,
)
from mmaudit.orchestration.authenticated_runner_smoke_openrouter import (
    AuthenticatedRunnerSmokeOpenRouterLaunch,
    AuthenticatedRunnerSmokeRunPlan,
    execute_authenticated_runner_smoke_openrouter,
    preflight_authenticated_runner_smoke_live_route_launch,
    preflight_authenticated_runner_smoke_live_routes,
    preflight_authenticated_runner_smoke_openrouter_launch,
)
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.certification import (
    certify_maximum_assurance_run,
    write_maximum_assurance_certification,
)
from mmaudit.orchestration.ci import LoadedCIBaseline, load_ci_baseline_bundle
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostLedgerError
from mmaudit.orchestration.manifest import (
    RunEvidenceManifest,
    canonical_sha256,
    load_run_evidence_manifest,
)
from mmaudit.orchestration.pipeline import AuditPipeline, resolve_safe_output_root
from mmaudit.orchestration.replay import (
    OfflineReplayOrchestrator,
    OfflineReplayStatus,
    write_offline_replay,
)
from mmaudit.orchestration.verification import (
    RunVerificationStatus,
    verify_run_evidence,
    write_run_verification,
)
from mmaudit.privacy import (
    PrivacyProfile,
    PrivacyRetentionConsentObservation,
    PrivacySourceClassification,
    load_privacy_retention_consent,
    resolve_effective_privacy_policy,
)
from mmaudit.repository.discovery import RepositorySafetyError, safe_repository_root
from mmaudit.repository.privacy_provenance import (
    prove_release_pinned_model_benchmark_source,
)
from mmaudit.repository.secrets import is_sensitive_workspace_name
from mmaudit.scanners.diagnostics import ScannerExecutablePreflight, ScannerExecutableState
from mmaudit.scanners.runner import (
    configured_scanner_adapters,
    preflight_configured_scanner_tools,
)
from mmaudit.snapshots.importer import (
    ReadOnlySnapshotImporter,
    load_snapshot_import_plan,
)
from mmaudit.snapshots.schema import write_deployment_snapshot
from mmaudit.solidity.reproduction import default_isolation_backend

app = typer.Typer(
    name="mmaudit",
    help=("Solidity/EVM security auditor with an explicit reduced generic source-review mode."),
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
models_app = typer.Typer(help="Inspect and validate explicit OpenRouter model IDs.")
app.add_typer(models_app, name="models")
benchmark_app = typer.Typer(
    help="Evaluate and certify deterministic benchmark evidence.",
    invoke_without_command=True,
    no_args_is_help=False,
)
app.add_typer(benchmark_app, name="benchmark")
snapshot_app = typer.Typer(help="Validate and import offline deployment snapshots.")
app.add_typer(snapshot_app, name="snapshot")
console = Console()
_TRUSTED_OPENROUTER_CLIENT_TYPE = OpenRouterClient

ConfigOption = Annotated[
    Path,
    typer.Option("--config", help="Path to mmaudit TOML configuration."),
]
SecretsEnvFileOption = Annotated[
    Path | None,
    typer.Option(
        "--secrets-env-file",
        help="Explicit operator control-plane dotenv file; never target input.",
    ),
]
DEFAULT_BENCHMARK_MANIFEST = (
    Path(__file__).resolve().parents[2] / "benchmarks" / "corpus" / "manifest.json"
)
DEFAULT_MODEL_BENCHMARK_CORPUS = (
    Path(__file__).resolve().parents[2] / "benchmarks" / "model_corpus" / "manifest.json"
)
DEFAULT_MODEL_BENCHMARK_PROVENANCE = DEFAULT_MODEL_BENCHMARK_CORPUS.with_name("provenance.json")


def _version(value: bool) -> None:
    if value:
        typer.echo(f"mmaudit {VERSION}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Run Solidity/EVM assurance or an explicitly reduced generic source review."""


@app.command("init")
def init_command(
    directory: Annotated[
        Path,
        typer.Option("--directory", "-d", help="Directory in which to create files."),
    ] = Path("."),
    force: Annotated[
        bool,
        typer.Option("--force", help="Replace existing init files."),
    ] = False,
) -> None:
    """Create mmaudit.toml and .mmauditignore without implicit overwrites."""

    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    try:
        safe_repository_root(directory)
    except RepositorySafetyError as exc:
        console.print(f"[red]Unsafe init directory:[/red] {exc}")
        raise typer.Exit(ExitCode.CONFIGURATION) from exc
    resources = {
        directory / DEFAULT_CONFIG_NAME: files("mmaudit.templates")
        .joinpath("mmaudit.example.toml")
        .read_text(encoding="utf-8"),
        directory / ".mmauditignore": files("mmaudit.templates")
        .joinpath("mmauditignore")
        .read_text(encoding="utf-8"),
    }
    existing = [str(path) for path in resources if path.exists()]
    symlinks = [str(path) for path in resources if path.is_symlink()]
    nonfiles = [str(path) for path in resources if path.exists() and not path.is_file()]
    if symlinks:
        console.print(
            "[red]Refusing to write through symlinked init files:[/red] " + ", ".join(symlinks)
        )
        raise typer.Exit(ExitCode.CONFIGURATION)
    if nonfiles:
        console.print("[red]Refusing non-file init destinations:[/red] " + ", ".join(nonfiles))
        raise typer.Exit(ExitCode.CONFIGURATION)
    if existing and not force:
        console.print("[red]Refusing to overwrite existing files:[/red] " + ", ".join(existing))
        raise typer.Exit(ExitCode.CONFIGURATION)
    for path, content in resources.items():
        if path.exists():
            path.unlink()
        path.write_text(content, encoding="utf-8")
        console.print(f"Created {path}")


@app.command("doctor")
def doctor_command(
    config_path: ConfigOption = Path(DEFAULT_CONFIG_NAME),
    secrets_env_file: SecretsEnvFileOption = None,
    repo: Annotated[
        Path | None,
        typer.Option("--repo", help="Repository root override."),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Output directory override."),
    ] = None,
    allow_code_egress: Annotated[
        bool,
        typer.Option(
            "--allow-code-egress",
            help="Acknowledge source egress for this diagnostic invocation.",
        ),
    ] = False,
    allow_fork_probing: Annotated[
        bool,
        typer.Option(
            "--allow-fork-probing",
            "--allow-fork",
            help="Acknowledge fork-only Foundry probing for this diagnostic invocation.",
        ),
    ] = False,
    fork_rpc_url_env: Annotated[
        str | None,
        typer.Option(
            "--fork-rpc-url-env",
            help="Environment variable name containing the fork RPC URL. The value is never printed.",
        ),
    ] = None,
    profile: Annotated[
        AuditProfile | None,
        typer.Option(
            "--profile",
            help=("Assurance-depth override; maximum-assurance is valid only with solidity-evm."),
        ),
    ] = None,
    language_profile: Annotated[
        LanguageCapabilityProfile | None,
        typer.Option(
            "--language-profile",
            "--capability-profile",
            help=(
                "solidity-evm enables the EVM portfolio; generic-source-review is reduced "
                "and cannot claim EVM maximum assurance."
            ),
        ),
    ] = None,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Check local safety, credentials, scanners, and model independence."""

    local_console = Console(no_color=no_color)
    try:
        config = load_config(config_path)
        config = _audit_config_overrides(
            budget_usd=None,
            max_files=None,
            max_file_bytes=None,
            max_context_bytes=None,
            concurrency=None,
            require_zdr=False,
            profile=profile,
            language_profile=language_profile,
            fork_rpc_url_env=fork_rpc_url_env,
        ).apply(config)
    except ConfigError as exc:
        local_console.print(f"[red]Configuration invalid:[/red] {exc}")
        raise typer.Exit(ExitCode.CONFIGURATION) from exc
    repo_path = _repo_path(config, config_path, repo)
    try:
        output_path = resolve_safe_output_root(output or (repo_path / ".mmaudit"))
    except ValueError as exc:
        local_console.print(f"[red]Output directory invalid:[/red] {exc}")
        raise typer.Exit(ExitCode.CONFIGURATION) from exc
    operator_secrets = OperatorSecrets()
    try:
        try:
            operator_secrets = load_operator_secrets(secrets_env_file, required=True)
            secret_file_accepted = True
        except OperatorSecretError:
            secret_file_accepted = False
        key_present = operator_secrets.openrouter_api_key_present
        authentication_valid = (
            _openrouter_authentication_valid(config, operator_secrets.openrouter_api_key)
            if key_present
            else False
        )
    finally:
        operator_secrets.clear()

    checks: list[tuple[str, bool, str, bool]] = []
    checks.append(
        (
            "Python version",
            sys.version_info >= (3, 12),
            platform_python(),
            True,
        )
    )
    try:
        safe_repository_root(repo_path)
        repository_ok = True
        checks.append(("Repository", True, str(repo_path), True))
    except RepositorySafetyError as exc:
        repository_ok = False
        checks.append(("Repository", False, str(exc), True))
    checks.append(("Configuration", True, str(config_path.resolve()), True))
    checks.append(
        (
            "Operator secret file",
            secret_file_accepted,
            "accepted" if secret_file_accepted else "rejected",
            True,
        )
    )
    checks.append(
        ("OPENROUTER_API_KEY", key_present, "present" if key_present else "missing", True)
    )
    checks.append(
        (
            "OpenRouter authentication",
            authentication_valid,
            "valid" if authentication_valid else "invalid",
            True,
        )
    )
    output_check = (
        _writable_output_check(output_path)
        if repository_ok
        else ("Output directory", False, "not checked because repository scope is invalid", True)
    )
    checks.append(output_check)
    checks.append(
        (
            "Output separation",
            output_path != repo_path.resolve(),
            (
                "separate from repository root"
                if output_path != repo_path.resolve()
                else "output cannot be the repository root"
            ),
            True,
        )
    )
    isolation_backend = default_isolation_backend(
        config.reproduction.isolation_backend,
        rootless_container_image=config.reproduction.rootless_container_image,
        rootless_container_runtime=config.reproduction.rootless_container_runtime,
    )
    isolation_required = (
        config.profile is AuditProfile.MAXIMUM_ASSURANCE
        or config.smart_contracts.compile
        or config.reproduction.require_hardened_isolation
        or any(
            getattr(config.scanners, scanner).enabled and getattr(config.scanners, scanner).required
            for scanner in (
                "semgrep",
                "gitleaks",
                "trivy",
                "osv",
                "codeql",
                "slither",
                "foundry_fork",
            )
        )
    )
    checks.append(
        (
            "Hardened execution isolation",
            isolation_backend is not None,
            (
                f"available ({isolation_backend.name})"
                if isolation_backend is not None
                else "unavailable; dynamic tools will fail closed"
            ),
            isolation_required,
        )
    )
    fork_isolation_available = isolation_backend is not None and bool(
        getattr(isolation_backend, "supports_local_fork_rpc", True)
    )
    fork_isolation_required = (
        config.profile is AuditProfile.MAXIMUM_ASSURANCE
        or config.scanners.foundry_fork.required
        or config.invariants.execute_generated
    )
    checks.append(
        (
            "Local-fork execution isolation",
            fork_isolation_available,
            (
                f"available ({isolation_backend.name})"
                if fork_isolation_available and isolation_backend is not None
                else (
                    f"{isolation_backend.name} safely supports non-networked tools but "
                    "cannot reach a host loopback fork"
                    if isolation_backend is not None
                    else "unavailable"
                )
            ),
            fork_isolation_required,
        )
    )
    scanner_adapters = configured_scanner_adapters(config)
    scanner_preflights: dict[str, ScannerExecutablePreflight] = {}
    scanner_preflight_error: str | None = None
    if repository_ok and output_check[1]:
        try:
            scanner_preflights = preflight_configured_scanner_tools(
                scanner_adapters,
                backend=isolation_backend,
                repository_root=repo_path,
                trusted_output_root=output_path,
                private_dir=(output_path / "private" / "doctor-tool-preflight" / uuid.uuid4().hex),
                timeout_seconds=5.0,
            )
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as exc:
            scanner_preflight_error = type(exc).__name__
    else:
        scanner_preflight_error = "repository or private output is unavailable"
    for name in scanner_adapters:
        enabled = getattr(config.scanners, name).enabled
        required = getattr(config.scanners, name).required
        preflight = scanner_preflights.get(name)
        release_ready = (
            preflight is not None
            and preflight.state is ScannerExecutableState.PRESENT_EXECUTABLE
            and preflight.version is not None
            and preflight.failure_kind is None
        )
        checks.append(
            (
                f"Scanner: {name}",
                release_ready or (not enabled and not required),
                (
                    _scanner_preflight_detail(preflight, enabled=enabled)
                    if preflight is not None
                    else f"preflight failed closed: {scanner_preflight_error or 'unknown error'}"
                ),
                required,
            )
        )
    model_errors = validate_model_independence(config)
    checks.append(
        (
            "Configured model roles",
            not model_errors,
            "; ".join(model_errors) if model_errors else "six explicit roles configured",
            True,
        )
    )
    privacy_ok = (
        config.privacy.redact_secrets
        and config.privacy.fail_on_detected_secret
        and not config.privacy.store_raw_prompts
        and not config.privacy.store_raw_responses
    )
    checks.append(
        (
            "Privacy safeguards",
            privacy_ok,
            "safe defaults enabled" if privacy_ok else "review unsafe privacy overrides",
            True,
        )
    )
    checks.append(
        (
            "Source-egress acknowledgement",
            config.privacy.allow_code_egress or allow_code_egress,
            "acknowledged in config"
            if config.privacy.allow_code_egress
            else (
                "acknowledged for this invocation"
                if allow_code_egress
                else "disabled; pass --allow-code-egress at run time or acknowledge in config"
            ),
            True,
        )
    )
    checks.append(
        (
            "Privacy profile",
            True,
            config.privacy.profile.value,
            True,
        )
    )
    zdr_control_consistent = (
        config.privacy.profile is PrivacyProfile.STRICT_ZDR
        and config.privacy.require_zdr
        and config.privacy.maximum_model_retention == "zero"
    ) or (
        config.privacy.profile is not PrivacyProfile.STRICT_ZDR
        and (config.privacy.require_zdr == (config.privacy.maximum_model_retention == "zero"))
    )
    checks.append(
        (
            "Request-level Zero Data Retention",
            zdr_control_consistent,
            (
                "enforced; no request-level downgrade is permitted"
                if config.privacy.require_zdr
                else "omitted only for an explicitly consent-bound non-ZDR run"
            ),
            True,
        )
    )
    checks.append(
        (
            "Retention-consent boundary",
            True,
            (
                "not applicable; STRICT_ZDR rejects retention consent"
                if config.privacy.profile is PrivacyProfile.STRICT_ZDR
                else (
                    (
                        "not applicable; ZDR-enforced synthetic runs require committed "
                        "source provenance instead of retention consent"
                    )
                    if (
                        config.privacy.profile is PrivacyProfile.SYNTHETIC_BENCHMARK
                        and config.privacy.require_zdr
                    )
                    else (
                        "configuration is non-authorizing; each provider run requires an "
                        "explicit matching --privacy-profile and external consent artifact"
                    )
                )
            ),
            True,
        )
    )
    checks.append(
        (
            "Account/guardrail ZDR compatibility",
            False,
            (
                (
                    "not observable from API-key metadata; a ZDR claim requires a "
                    "successful exact-route ZDR runtime preflight"
                )
                if config.privacy.require_zdr
                else (
                    "not observable from API-key metadata; account or guardrail ZDR can "
                    "block the consented non-ZDR endpoint, so a frontier claim requires "
                    "a successful exact-route consented runtime preflight"
                )
            ),
            False,
        )
    )
    fork_acknowledged = config.smart_contracts.allow_fork_probing or allow_fork_probing
    checks.append(
        (
            "Smart-contract fork mode",
            config.smart_contracts.enabled and config.smart_contracts.fork_only,
            "enabled; fork-only probing enforced"
            if config.smart_contracts.enabled and config.smart_contracts.fork_only
            else "disabled",
            False,
        )
    )
    checks.append(
        (
            "Fork-probing acknowledgement",
            fork_acknowledged or not config.scanners.foundry_fork.required,
            "acknowledged"
            if fork_acknowledged
            else "disabled; pass --allow-fork or set smart_contracts.allow_fork_probing",
            config.scanners.foundry_fork.required,
        )
    )
    checks.append(
        (
            "Fork RPC URL",
            bool(os.environ.get(config.smart_contracts.fork_rpc_url_env))
            or not fork_acknowledged
            or not config.scanners.foundry_fork.required,
            f"{config.smart_contracts.fork_rpc_url_env}=present (value never printed)"
            if os.environ.get(config.smart_contracts.fork_rpc_url_env)
            else f"{config.smart_contracts.fork_rpc_url_env}=missing (value never printed)",
            config.scanners.foundry_fork.required and fork_acknowledged,
        )
    )
    table = Table(title="mmaudit doctor")
    table.add_column("Check")
    table.add_column("Result")
    table.add_column("Detail")
    for name, ok, detail, _required in checks:
        table.add_row(
            Text(_terminal_text(name)),
            "[green]PASS[/green]" if ok else "[red]FAIL[/red]",
            Text(_terminal_text(detail)),
        )
    local_console.print(table)
    if any(not ok and required for _name, ok, _detail, required in checks):
        raise typer.Exit(ExitCode.CONFIGURATION)


@models_app.command("list")
def models_list(
    config_path: ConfigOption = Path(DEFAULT_CONFIG_NAME),
    secrets_env_file: SecretsEnvFileOption = None,
    refresh: Annotated[bool, typer.Option("--refresh", help="Ignore cached metadata.")] = False,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """List current OpenRouter model IDs and structured-output capabilities."""

    async def execute() -> None:
        config = load_config(config_path)
        with load_operator_secrets(secrets_env_file, required=True) as operator_secrets:
            metadata = await _model_metadata(
                config,
                config_path,
                api_key=operator_secrets.openrouter_api_key,
                refresh=refresh,
            )
        table = Table(title="OpenRouter models", show_lines=False)
        table.add_column("ID")
        table.add_column("Name")
        table.add_column("Context", justify="right")
        table.add_column("Catalog output mode")
        for item in metadata:
            parameters = {str(value).lower() for value in item.get("supported_parameters", [])}
            output_mode = supported_output_modes(parameters)[0]
            table.add_row(
                Text(_terminal_text(str(item.get("id", "")))),
                Text(_terminal_text(str(item.get("name", "")))),
                Text(_terminal_text(str(item.get("context_length", "")))),
                Text(output_mode.value),
            )
        Console(no_color=no_color).print(table)

    _run_async_cli(execute)


@models_app.command("discover")
def models_discover(
    candidate: Annotated[
        list[str],
        typer.Option(
            "--candidate",
            help="Exact MODEL_ID=PROVIDER_ENDPOINT pair; repeat for each candidate.",
        ),
    ],
    config_path: ConfigOption = Path(DEFAULT_CONFIG_NAME),
    secrets_env_file: SecretsEnvFileOption = None,
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output-dir",
            help="Private directory for self-hashed discovery evidence.",
        ),
    ] = Path(".mmaudit/private/model-discovery"),
    candidate_registry_template: Annotated[
        Path | None,
        typer.Option(
            "--candidate-registry-template",
            help="Existing registry supplying only selected lineage-review and role policy.",
        ),
    ] = None,
    candidate_selection_plan: Annotated[
        Path | None,
        typer.Option(
            "--candidate-selection-plan",
            help="Nonauthorizing exact-ID/endpoint allowlist for fresh registry bootstrap.",
        ),
    ] = None,
    candidate_selection_ranking_source: Annotated[
        Path | None,
        typer.Option(
            "--candidate-selection-ranking-source",
            help="Exact operator-staged ranking implementation bytes bound by the plan.",
        ),
    ] = None,
    candidate_selection_lineage_review_source: Annotated[
        Path | None,
        typer.Option(
            "--candidate-selection-lineage-review-source",
            help="Exact operator-staged lineage-review bytes bound by the plan.",
        ),
    ] = None,
    candidate_registry_output: Annotated[
        Path | None,
        typer.Option(
            "--candidate-registry-output",
            help="Fresh private JSON registry bound to this exact discovery run.",
        ),
    ] = None,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Freeze exact public model and endpoint metadata without making a completion call."""

    async def execute() -> None:
        plan_inputs = (
            candidate_selection_plan,
            candidate_selection_ranking_source,
            candidate_selection_lineage_review_source,
        )
        plan_mode = any(value is not None for value in plan_inputs)
        if plan_mode and not all(value is not None for value in plan_inputs):
            raise ConfigError(
                "--candidate-selection-plan, --candidate-selection-ranking-source, and "
                "--candidate-selection-lineage-review-source must be supplied together"
            )
        if candidate_registry_template is not None and plan_mode:
            raise ConfigError(
                "candidate registry template and candidate selection plan are mutually exclusive"
            )
        if candidate_registry_template is not None and candidate_registry_output is None:
            raise ConfigError(
                "--candidate-registry-template and --candidate-registry-output "
                "must be supplied together"
            )
        if plan_mode and candidate_registry_output is None:
            raise ConfigError("candidate selection plan requires --candidate-registry-output")
        if (
            candidate_registry_output is not None
            and candidate_registry_template is None
            and not plan_mode
        ):
            raise ConfigError(
                "--candidate-registry-output must be supplied together with a registry "
                "template or selection plan"
            )
        candidates = _parse_model_discovery_candidates(candidate)
        candidate_routes = tuple(
            DiscoveryCandidateRoute(
                exact_model_id=model_id,
                approved_provider_endpoint=provider_endpoint,
            )
            for model_id, provider_endpoint in candidates
        )
        template_registry: CandidateRegistry | None = None
        selection_plan: CandidateSelectionPlan | None = None
        registry_output_path: Path | None = None
        if candidate_registry_output is not None:
            discovery_path = Path(os.path.abspath(output_dir))
            requested_registry_output = Path(os.path.abspath(candidate_registry_output))
            bridge_inputs = tuple(
                Path(os.path.abspath(value))
                for value in (
                    candidate_registry_template,
                    candidate_selection_plan,
                    candidate_selection_ranking_source,
                    candidate_selection_lineage_review_source,
                )
                if value is not None
            )
            if requested_registry_output in bridge_inputs:
                raise ConfigError("candidate registry output must differ from every bridge input")
            if (
                requested_registry_output == discovery_path
                or requested_registry_output.is_relative_to(discovery_path)
                or discovery_path.is_relative_to(requested_registry_output)
            ):
                raise ConfigError(
                    "candidate registry output must remain outside the discovery directory"
                )
        if candidate_registry_template is not None and candidate_registry_output is not None:
            try:
                template_registry = load_candidate_registry(candidate_registry_template)
                validate_candidate_registry_template_selection(
                    template=template_registry,
                    routes=candidate_routes,
                )
                registry_output_path = preflight_candidate_registry_output(
                    candidate_registry_output
                )
            except ValueError as exc:
                raise ConfigError(f"candidate registry bridge is invalid: {exc}") from exc
        elif plan_mode and candidate_registry_output is not None:
            if (
                candidate_selection_plan is None
                or candidate_selection_ranking_source is None
                or candidate_selection_lineage_review_source is None
            ):
                raise ConfigError("candidate selection plan inputs are incomplete")
            try:
                selection_plan = load_candidate_selection_plan(candidate_selection_plan)
                source_names = {
                    binding.kind: binding.filename for binding in selection_plan.source_bindings
                }
                if (
                    candidate_selection_ranking_source.name
                    != source_names["MODEL_RANKING_IMPLEMENTATION"]
                    or candidate_selection_lineage_review_source.name
                    != source_names["OPERATOR_LINEAGE_REVIEW"]
                ):
                    raise ValueError("candidate selection source filename differs from its binding")
                input_paths = {
                    Path(os.path.abspath(candidate_selection_plan)),
                    Path(os.path.abspath(candidate_selection_ranking_source)),
                    Path(os.path.abspath(candidate_selection_lineage_review_source)),
                }
                if len(input_paths) != 3:
                    raise ValueError("candidate selection inputs must be distinct paths")
                ranking_source_bytes = read_candidate_selection_source(
                    candidate_selection_ranking_source
                )
                lineage_review_source_bytes = read_candidate_selection_source(
                    candidate_selection_lineage_review_source
                )
                validate_candidate_selection_plan_sources(
                    selection_plan,
                    ranking_source_bytes=ranking_source_bytes,
                    lineage_review_source_bytes=lineage_review_source_bytes,
                )
                validate_candidate_selection_routes(selection_plan, routes=candidate_routes)
                registry_output_path = preflight_candidate_registry_output(
                    candidate_registry_output
                )
            except ValueError as exc:
                raise ConfigError(f"candidate selection bridge is invalid: {exc}") from exc
        _preflight_model_discovery_output_dir(output_dir)
        config = load_config(config_path)
        budget, usage = _budget_and_usage(config)
        with load_operator_secrets(secrets_env_file, required=True) as operator_secrets:
            if not operator_secrets.openrouter_api_key_present:
                raise ConfigError("OPENROUTER_API_KEY is missing from the operator secret file")
            client = OpenRouterClient(
                api_key=operator_secrets.openrouter_api_key,
                execution=config.execution,
                privacy=config.privacy,
                budget=budget,
                usage=usage,
            )
            if type(client) is not _TRUSTED_OPENROUTER_CLIENT_TYPE:
                raise ConfigError("models discover requires the trusted concrete OpenRouter client")
            try:
                await client.validate_authentication()
                models_payload = await client.get_certification_model_metadata()
                zdr_payload = await client.list_zdr_endpoints()
                single_model_payloads: dict[str, dict[str, Any]] = {}
                endpoint_payloads: dict[str, dict[str, Any]] = {}
                structural_payloads = []
                for model_id, provider_endpoint in candidates:
                    openrouter_catalog_canonical_slug(
                        exact_model_id=model_id,
                        models_payload=models_payload,
                    )
                    single_model_payload = await client.get_model_metadata(model_id)
                    single_model_payloads[model_id] = single_model_payload
                    endpoint_payload = await client.get_model_endpoint_metadata(model_id)
                    endpoint_payloads[model_id] = endpoint_payload
                    endpoint_snapshot = validate_openrouter_endpoint_snapshot(
                        exact_model_id=model_id,
                        configured_provider_endpoints=(provider_endpoint,),
                        provider_policy_mode="only",
                        endpoint_payload=endpoint_payload,
                        require_zdr=config.privacy.require_zdr,
                        zdr_payload=zdr_payload,
                        structured_output_required=False,
                    )
                    structural_payload = validate_openrouter_model_discovery(
                        exact_model_id=model_id,
                        models_payload=models_payload,
                        single_model_payload=single_model_payload,
                        endpoint_snapshot=endpoint_snapshot,
                    )
                    if selection_plan is not None:
                        validate_candidate_selection_discovery_capability(
                            selection_plan,
                            evidence=structural_payload,
                        )
                    structural_payloads.append(structural_payload)
                retrieved_at = datetime.now(UTC).replace(microsecond=0)
                provenance, evidence = client.seal_real_model_discovery_run(
                    run_id=uuid.uuid4().hex,
                    retrieved_at=retrieved_at,
                    models_payload=models_payload,
                    zdr_payload=zdr_payload,
                    single_model_payloads=single_model_payloads,
                    endpoint_payloads=endpoint_payloads,
                    candidate_routes=candidate_routes,
                    payloads=tuple(structural_payloads),
                )
            finally:
                await client.close()

        manifest = write_model_discovery_run(output_dir, evidence)
        registry: CandidateRegistry | None = None
        if template_registry is not None and registry_output_path is not None:
            try:
                registry = derive_candidate_registry_from_discovery(
                    template=template_registry,
                    run_manifest=manifest,
                    evidence=evidence,
                )
                write_candidate_registry_json(registry_output_path, registry)
            except ValueError as exc:
                raise ConfigError(
                    f"fresh candidate registry could not be published: {exc}"
                ) from exc
        elif selection_plan is not None and registry_output_path is not None:
            try:
                registry = derive_pending_candidate_registry_from_selection_plan(
                    plan=selection_plan,
                    run_manifest=manifest,
                    evidence=evidence,
                )
                write_candidate_registry_json(registry_output_path, registry)
            except ValueError as exc:
                raise ConfigError(
                    f"fresh pending candidate registry could not be published: {exc}"
                ) from exc
        local_console = Console(no_color=no_color)
        for item in evidence:
            local_console.print(f"{item.exact_model_id}: {item.discovery_evidence_sha256}")
        local_console.print(
            f"[green]Frozen {len(evidence)} exact REAL discovery records in "
            f"{output_dir.resolve()}; run {provenance.run_id}; manifest "
            f"{manifest.manifest_sha256}; no model completion was requested.[/green]"
        )
        if registry is not None and registry_output_path is not None:
            local_console.print(
                f"[green]Frozen exact pending candidate registry {registry.registry_sha256} "
                f"at {registry_output_path}; stale discovery fields were not copied.[/green]"
            )

    _run_async_cli(execute)


@models_app.command("refresh")
def models_refresh(
    candidate_registry: Annotated[
        Path,
        typer.Option(
            "--candidate-registry",
            help="Frozen candidate registry used only as the comparison baseline.",
        ),
    ] = Path("config/models.candidates.toml"),
    previous_candidate_registry: Annotated[
        Path | None,
        typer.Option(
            "--previous-candidate-registry",
            help="Exact prior candidate registry paired with the prior source and snapshot.",
        ),
    ] = None,
    previous_snapshot: Annotated[
        Path | None,
        typer.Option(
            "--previous-snapshot",
            help="Optional prior canonical refresh snapshot with exact historical pricing.",
        ),
    ] = None,
    previous_source_evidence: Annotated[
        Path | None,
        typer.Option(
            "--previous-source-evidence",
            help="Canonical source evidence paired with --previous-snapshot.",
        ),
    ] = None,
    selected_route: Annotated[
        list[str] | None,
        typer.Option(
            "--selected-route",
            help="Current production MODEL_ID=PROVIDER_ENDPOINT route; repeat as needed.",
        ),
    ] = None,
    secrets_env_file: SecretsEnvFileOption = None,
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output-dir",
            help="Fresh private directory for exact refresh evidence.",
        ),
    ] = Path(".mmaudit/private/model-refresh"),
    soft_max_age_hours: Annotated[
        int,
        typer.Option("--soft-max-age-hours", min=1, max=24 * 30),
    ] = 30,
    hard_max_age_hours: Annotated[
        int,
        typer.Option("--hard-max-age-hours", min=2, max=24 * 90),
    ] = 72,
    pricing_tolerance_fraction: Annotated[
        str,
        typer.Option(
            "--pricing-tolerance-fraction",
            help="Canonical Decimal fraction; exact increases beyond it block selected routes.",
        ),
    ] = "0.05",
    policy_eligibility_artifact: Annotated[
        Path | None,
        typer.Option(
            "--policy-eligibility-artifact",
            help="Explicit canonical operator/legal policy artifact; never fetched automatically.",
        ),
    ] = None,
    policy_source_observation: Annotated[
        Path | None,
        typer.Option(
            "--policy-source-observation",
            help="Explicit current-source observation paired with the policy artifact.",
        ),
    ] = None,
    policy_checked_routes: Annotated[
        Path | None,
        typer.Option(
            "--policy-checked-routes",
            help="Explicit canonical JSON array of exact policy routes to classify.",
        ),
    ] = None,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Refresh authenticated metadata without completions, qualification, or promotion."""

    local_console = Console(no_color=no_color)

    async def execute() -> None:
        preflight_observed_at = datetime.now(UTC).replace(microsecond=0)
        try:
            validate_model_refresh_controls(
                pricing_tolerance_fraction=pricing_tolerance_fraction,
                soft_max_age_hours=soft_max_age_hours,
                hard_max_age_hours=hard_max_age_hours,
            )
        except ModelRefreshValidationError as exc:
            raise ConfigError("models refresh policy is invalid") from exc
        registry = load_candidate_registry(candidate_registry)
        if registry.created_at > preflight_observed_at:
            raise ConfigError("candidate registry is future-dated")
        policy_paths = (
            policy_eligibility_artifact,
            policy_source_observation,
            policy_checked_routes,
        )
        if any(path is not None for path in policy_paths) and not all(
            path is not None for path in policy_paths
        ):
            raise ConfigError(
                "--policy-eligibility-artifact, --policy-source-observation, and "
                "--policy-checked-routes must be supplied together"
            )
        policy_inputs = None
        if all(path is not None for path in policy_paths):
            assert policy_eligibility_artifact is not None
            assert policy_source_observation is not None
            assert policy_checked_routes is not None
            try:
                policy_inputs = (
                    load_model_policy_eligibility_artifact(policy_eligibility_artifact),
                    load_policy_eligibility_source_observation(policy_source_observation),
                    load_policy_eligibility_checked_routes(policy_checked_routes),
                )
                validate_model_policy_eligibility_refresh_inputs(
                    policy_artifact=policy_inputs[0],
                    source_observation=policy_inputs[1],
                    checked_routes=policy_inputs[2],
                    refresh_retrieved_at=datetime.now(UTC).replace(microsecond=0),
                )
            except ModelPolicyEligibilityRefreshError as exc:
                raise ConfigError("models refresh policy evidence is invalid") from exc
        previous_paths = (
            previous_candidate_registry,
            previous_snapshot,
            previous_source_evidence,
        )
        if any(path is not None for path in previous_paths) and not all(
            path is not None for path in previous_paths
        ):
            raise ConfigError(
                "--previous-candidate-registry, --previous-snapshot, and "
                "--previous-source-evidence must be supplied together"
            )
        previous_registry = (
            load_candidate_registry(previous_candidate_registry)
            if previous_candidate_registry is not None
            else None
        )
        previous = (
            load_model_refresh_snapshot(previous_snapshot)
            if previous_snapshot is not None
            else None
        )
        previous_source = (
            load_model_refresh_source_evidence(previous_source_evidence)
            if previous_source_evidence is not None
            else None
        )
        if previous_registry is not None and previous is not None and previous_source is not None:
            try:
                reproduced_previous = build_model_refresh_snapshot_from_source(
                    source_evidence=previous_source,
                    candidate_registry=previous_registry,
                )
            except ModelRefreshValidationError as exc:
                raise ConfigError("previous refresh evidence is invalid") from exc
            if previous != reproduced_previous:
                raise ConfigError(
                    "previous refresh snapshot differs from its paired source evidence"
                )
            if previous.retrieved_at > preflight_observed_at:
                raise ConfigError("previous refresh snapshot is future-dated")
            if previous_registry.created_at > registry.created_at:
                raise ConfigError(
                    "previous candidate registry is newer than the current candidate registry"
                )
        selected = _parse_model_refresh_selected_routes(selected_route or [])
        approved_routes = {
            (candidate.exact_model_id, candidate.approved_provider_endpoint)
            for candidate in registry.candidates
        }
        if any(
            (route.exact_model_id, route.provider_endpoint) not in approved_routes
            for route in selected
        ):
            raise ConfigError(
                "models refresh selected route is absent from the frozen candidate registry"
            )
        approved_policy_routes = {
            (
                candidate.exact_model_id,
                candidate.approved_provider_name,
                candidate.approved_provider_endpoint,
            )
            for candidate in registry.candidates
        }
        if policy_inputs is not None and any(
            route.identity not in approved_policy_routes for route in policy_inputs[2]
        ):
            raise ConfigError(
                "models refresh checked policy route is absent from the frozen candidate registry"
            )
        if OpenRouterClient is not _TRUSTED_OPENROUTER_CLIENT_TYPE:
            raise ConfigError("models refresh requires the trusted concrete OpenRouter client")
        _preflight_model_discovery_output_dir(output_dir)
        attempted_at = datetime.now(UTC).replace(microsecond=0)
        execution = ExecutionConfig(max_model_retries=1)
        privacy = PrivacyConfig()
        usage = UsageLedger()
        budget = BudgetManager(
            total_usd=execution.budget_usd,
            max_output_tokens=execution.max_output_tokens_per_request,
            conservative_usd_per_million_tokens=(execution.conservative_usd_per_million_tokens),
            max_requests_per_agent=execution.max_requests_per_agent,
        )
        client: OpenRouterClient | None = None
        try:
            with load_operator_secrets(
                secrets_env_file,
                required=True,
            ) as operator_secrets:
                if not operator_secrets.openrouter_api_key_present:
                    raise OperatorSecretError(
                        "OPENROUTER_API_KEY is missing from the operator secret file"
                    )
                client = OpenRouterClient(
                    api_key=operator_secrets.openrouter_api_key,
                    execution=execution,
                    privacy=privacy,
                    budget=budget,
                    usage=usage,
                )
                if type(client) is not _TRUSTED_OPENROUTER_CLIENT_TYPE:
                    raise ConfigError(
                        "models refresh requires the trusted concrete OpenRouter client"
                    )
                await client.validate_authentication()
                catalog_payload = await client.get_certification_model_metadata()
                zdr_payload = await client.get_zdr_endpoint_metadata()
                endpoint_payloads = {
                    candidate.exact_model_id: (
                        await client.get_refresh_model_endpoint_metadata(candidate.exact_model_id)
                    )
                    for candidate in registry.candidates
                }
                reject_model_refresh_secret_reflection(
                    catalog_payload,
                    zdr_payload,
                    endpoint_payloads,
                    forbidden_values=(operator_secrets.openrouter_api_key,),
                )
        except (OperatorSecretError, OpenRouterError, ModelRefreshValidationError) as exc:
            failure_code = _model_refresh_failure_code(exc)
            failure = seal_model_refresh_attempt(
                attempted_at=attempted_at,
                candidate_registry_sha256=registry.registry_sha256,
                failure_code=failure_code,
            )
            try:
                write_model_refresh_failure(output_dir, attempt=failure)
            except (OSError, ValueError):
                local_console.print(
                    "[red]mmaudit failed safely: refresh failure evidence "
                    "could not be persisted.[/red]"
                )
                raise typer.Exit(ExitCode.CONFIGURATION) from None
            local_console.print(
                f"[red]Model metadata refresh failed safely: {failure_code.value}.[/red]"
            )
            raise typer.Exit(ExitCode.MODEL_FAILURE) from None
        finally:
            if client is not None:
                await client.close()

        if usage.records:
            raise ConfigError("metadata refresh unexpectedly created model usage records")
        retrieved_at = datetime.now(UTC).replace(microsecond=0)
        try:
            source_evidence = build_model_refresh_source_evidence(
                retrieved_at=retrieved_at,
                catalog_payload=catalog_payload,
                zdr_payload=zdr_payload,
                candidate_registry=registry,
                candidate_endpoint_payloads=endpoint_payloads,
                authenticated_metadata=True,
            )
            snapshot = build_model_refresh_snapshot_from_source(
                source_evidence=source_evidence,
                candidate_registry=registry,
            )
            diff = diff_model_refresh(
                current=snapshot,
                previous=previous,
                previous_source_evidence=previous_source,
                previous_candidate_registry=previous_registry,
                candidate_registry=registry,
                pricing_tolerance_fraction=pricing_tolerance_fraction,
                compared_at=retrieved_at,
                selected_routes=selected,
            )
            attempt = seal_model_refresh_attempt(
                attempted_at=attempted_at,
                candidate_registry_sha256=registry.registry_sha256,
                snapshot=snapshot,
                diff=diff,
            )
            freshness = evaluate_model_refresh_freshness(
                observed_at=retrieved_at,
                snapshot=snapshot,
                soft_max_age_hours=soft_max_age_hours,
                hard_max_age_hours=hard_max_age_hours,
                production_selection_present=bool(selected),
            )
            policy_refresh = (
                None
                if policy_inputs is None
                else build_model_policy_eligibility_refresh_artifact(
                    refresh_snapshot=snapshot,
                    policy_artifact=policy_inputs[0],
                    source_observation=policy_inputs[1],
                    checked_routes=policy_inputs[2],
                )
            )
        except ValueError:
            failure = seal_model_refresh_attempt(
                attempted_at=attempted_at,
                candidate_registry_sha256=registry.registry_sha256,
                failure_code=ModelRefreshFailureCode.MALFORMED_METADATA,
            )
            try:
                write_model_refresh_failure(output_dir, attempt=failure)
            except (OSError, ValueError):
                local_console.print(
                    "[red]mmaudit failed safely: malformed-metadata evidence "
                    "could not be persisted.[/red]"
                )
                raise typer.Exit(ExitCode.CONFIGURATION) from None
            local_console.print(
                "[red]Model metadata refresh failed safely: MALFORMED_METADATA.[/red]"
            )
            raise typer.Exit(ExitCode.MODEL_FAILURE) from None
        try:
            write_model_refresh_success(
                output_dir,
                source_evidence=source_evidence,
                snapshot=snapshot,
                diff=diff,
                attempt=attempt,
                freshness=freshness,
                policy_eligibility_refresh=policy_refresh,
            )
        except (OSError, ValueError):
            local_console.print(
                "[red]mmaudit failed safely: refresh success evidence could not be persisted.[/red]"
            )
            raise typer.Exit(ExitCode.CONFIGURATION) from None
        local_console.print(
            f"[green]Model metadata refresh {attempt.status.value}; "
            f"{len(snapshot.models)} exact catalogue models, "
            f"{len(diff.changes)} drift records; no completion was requested.[/green]"
        )
        if attempt.status.value == "PRODUCTION_BLOCKED":
            raise typer.Exit(ExitCode.INCOMPLETE)

    _run_async_cli(execute)


@models_app.command("check")
def models_check(
    config_path: ConfigOption = Path(DEFAULT_CONFIG_NAME),
    secrets_env_file: SecretsEnvFileOption = None,
    refresh: Annotated[bool, typer.Option("--refresh", help="Ignore cached metadata.")] = False,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Verify exact models, endpoint capabilities, ZDR, duplicates, and independence."""

    async def execute() -> None:
        config = load_config(config_path)
        errors = validate_model_independence(config)
        with load_operator_secrets(secrets_env_file, required=True) as operator_secrets:
            if not operator_secrets.openrouter_api_key_present:
                raise ConfigError("OPENROUTER_API_KEY is missing from the operator secret file")
            budget, usage = _budget_and_usage(config)
            controls = build_openrouter_runtime_controls(
                config,
                certification=False,
            )
            if not controls.provider_policy.configured_endpoints:
                raise ConfigError("models check requires an explicit provider endpoint allowlist")
            client = OpenRouterClient(
                api_key=operator_secrets.openrouter_api_key,
                execution=config.execution,
                privacy=config.privacy,
                budget=budget,
                usage=usage,
                provider_policy=controls.provider_policy,
                reasoning_policy=controls.reasoning_policy,
            )
            try:
                registry = ModelRegistry(_cache_path(config_path))
                metadata = None if refresh else registry.load_cache()
                if metadata is None:
                    metadata = await client.list_models()
                    registry.save_cache(metadata)
                zdr_payload = await client.list_zdr_endpoints()
                zdr_ids = extract_zdr_model_ids(zdr_payload)
                if config.privacy.require_zdr and not zdr_ids:
                    errors.append("ZDR endpoint eligibility could not be verified")
                errors.extend(
                    registry.validate(
                        config,
                        metadata,
                        require_verified_qualification=False,
                        zdr_model_ids=zdr_ids,
                        source_egress_requested=True,
                    )
                )
                provider_policy = controls.provider_policy
                endpoint_snapshots = []
                if provider_policy.configured_endpoints:
                    policy_mode: Literal["only", "order"] = (
                        "only" if provider_policy.only else "order"
                    )
                    for model_id in sorted(
                        set(configured_model_ids(config, include_fallbacks=True))
                    ):
                        endpoint_payload = await client.get_model_endpoint_metadata(model_id)
                        try:
                            endpoint_snapshots.append(
                                validate_openrouter_endpoint_snapshot(
                                    exact_model_id=model_id,
                                    configured_provider_endpoints=(
                                        provider_policy.configured_endpoints
                                    ),
                                    provider_policy_mode=policy_mode,
                                    endpoint_payload=endpoint_payload,
                                    require_zdr=config.privacy.require_zdr,
                                    zdr_payload=zdr_payload,
                                    reasoning_requested=False,
                                    structured_output_required=False,
                                )
                            )
                        except EndpointSnapshotValidationError as exc:
                            errors.append(
                                f"exact provider endpoint validation failed for {model_id}: {exc}"
                            )
            finally:
                await client.close()
        if errors:
            raise ConfigError("; ".join(errors))
        Console(no_color=no_color).print(
            f"[green]Validated {len(configured_model_ids(config, include_fallbacks=True))} "
            f"configured model IDs and {len(endpoint_snapshots)} exact endpoint "
            "snapshots.[/green]"
        )

    _run_async_cli(execute)


@models_app.command("benchmark")
def models_benchmark(
    config_path: ConfigOption = Path(DEFAULT_CONFIG_NAME),
    secrets_env_file: SecretsEnvFileOption = None,
    corpus: Annotated[
        Path,
        typer.Option("--corpus", help="Self-hashed blinded model benchmark corpus."),
    ] = DEFAULT_MODEL_BENCHMARK_CORPUS,
    model: Annotated[
        list[str] | None,
        typer.Option(
            "--model",
            help="Configured model ID to include; repeat as needed.",
        ),
    ] = None,
    candidate_registry: Annotated[
        Path | None,
        typer.Option(
            "--candidate-registry",
            help="Frozen self-hashed candidate registry for exact-set benchmarking.",
        ),
    ] = None,
    discovery_run: Annotated[
        Path | None,
        typer.Option(
            "--discovery-run",
            help="Frozen atomic discovery directory bound to the candidate registry.",
        ),
    ] = None,
    qualification_policy: Annotated[
        Path | None,
        typer.Option(
            "--qualification-policy",
            help="Frozen self-hashed model qualification policy for candidate mode.",
        ),
    ] = None,
    campaign_journal: Annotated[
        Path | None,
        typer.Option(
            "--campaign-journal",
            help="Explicit private candidate campaign journal directory.",
        ),
    ] = None,
    calibration_output: Annotated[
        Path | None,
        typer.Option(
            "--calibration-output",
            help=(
                "Fresh private non-dispositive calibration artifact; candidate-registry mode only."
            ),
        ),
    ] = None,
    calibrated_policy_output: Annotated[
        Path | None,
        typer.Option(
            "--calibrated-policy-output",
            help=(
                "Fresh private P2 successor candidate derived from --calibration-output; "
                "requires review, commit, and release pinning before qualification."
            ),
        ),
    ] = None,
    lineage_review_bundle: Annotated[
        Path | None,
        typer.Option(
            "--lineage-review-bundle",
            help="Signed operator lineage-review bundle required for calibration.",
        ),
    ] = None,
    lineage_trust_anchor: Annotated[
        Path | None,
        typer.Option(
            "--lineage-trust-anchor",
            help="Pinned operator lineage trust-anchor JSON required for calibration.",
        ),
    ] = None,
    resume_campaign: Annotated[
        bool,
        typer.Option(
            "--resume-campaign",
            help="Resume only the exact bound existing candidate campaign journal.",
        ),
    ] = False,
    output: Annotated[
        Path,
        typer.Option("--output", help="Destination for the model benchmark report."),
    ] = Path("model-benchmark-results.json"),
    cost_ledger: Annotated[
        Path | None,
        typer.Option(
            "--cost-ledger",
            help="Existing operator-controlled cumulative paid-provider ledger.",
        ),
    ] = None,
    allow_code_egress: Annotated[
        bool,
        typer.Option(
            "--allow-code-egress",
            help="Explicitly permit the synthetic benchmark excerpts to reach the provider.",
        ),
    ] = False,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Score configured root lineages on the blinded synthetic quality corpus."""

    async def execute() -> None:
        candidate_mode = candidate_registry is not None or discovery_run is not None
        if (candidate_registry is None) != (discovery_run is None):
            raise ConfigError("--candidate-registry and --discovery-run must be supplied together")
        if candidate_mode and model:
            raise ConfigError("--model cannot be combined with candidate-registry mode")
        if candidate_mode and (campaign_journal is None or qualification_policy is None):
            raise ConfigError(
                "candidate-registry mode requires explicit --campaign-journal "
                "and --qualification-policy"
            )
        if not candidate_mode and (
            campaign_journal is not None
            or qualification_policy is not None
            or resume_campaign
            or calibration_output is not None
            or calibrated_policy_output is not None
            or lineage_review_bundle is not None
            or lineage_trust_anchor is not None
        ):
            raise ConfigError("candidate campaign options require candidate-registry mode")
        if calibrated_policy_output is not None and calibration_output is None:
            raise ConfigError(
                "--calibrated-policy-output requires --calibration-output from the same campaign"
            )
        calibration_inputs = (
            calibration_output,
            lineage_review_bundle,
            lineage_trust_anchor,
        )
        if any(value is not None for value in calibration_inputs) and not all(
            value is not None for value in calibration_inputs
        ):
            raise ConfigError(
                "--calibration-output, --lineage-review-bundle, and "
                "--lineage-trust-anchor must be supplied together"
            )
        if calibration_output is not None and resume_campaign:
            raise ConfigError("calibration requires one fresh same-process candidate campaign")
        config = load_config(config_path)
        benchmark_corpus = load_model_benchmark_corpus(corpus)
        if candidate_mode:
            assert candidate_registry is not None
            assert discovery_run is not None
            assert campaign_journal is not None
            assert qualification_policy is not None
            await _execute_candidate_registry_benchmark(
                config=config,
                benchmark_corpus=benchmark_corpus,
                candidate_registry_path=candidate_registry,
                discovery_run_path=discovery_run,
                secrets_env_file=secrets_env_file,
                output=output,
                campaign_journal_path=campaign_journal,
                resume_campaign=resume_campaign,
                qualification_policy_path=qualification_policy,
                calibration_output=calibration_output,
                calibrated_policy_output=calibrated_policy_output,
                lineage_review_bundle=lineage_review_bundle,
                lineage_trust_anchor=lineage_trust_anchor,
                cost_ledger=cost_ledger,
                allow_code_egress=allow_code_egress,
                no_color=no_color,
            )
            return
        privacy_observed_at = datetime.now(UTC).replace(microsecond=0)
        source_provenance_observation = prove_release_pinned_model_benchmark_source(
            benchmark_corpus,
            now=privacy_observed_at,
        )
        targets = select_model_benchmark_targets(config, model)
        validate_model_benchmark_egress(
            config,
            targets,
            explicitly_allowed=allow_code_egress,
        )
        ledger_path = _selected_cost_ledger_path(config, cost_ledger)
        if ledger_path is None:
            raise ConfigError(
                "models benchmark requires an existing --cost-ledger initialized "
                "with models init-cost-ledger or execution.cost_ledger_path"
            )
        budget, usage = _budget_and_usage(
            config,
            ledger_path=ledger_path,
            require_endpoint_cost_bound=True,
        )
        assert budget.atomic_ledger is not None
        _preflight_model_benchmark_output(output, budget.atomic_ledger)
        controls = build_openrouter_runtime_controls(
            config,
            certification=True,
        )
        effective_privacy_policy = resolve_effective_privacy_policy(
            profile=config.privacy.profile,
            require_zdr=config.privacy.require_zdr,
            consent_observation=None,
            source_sha256=benchmark_corpus.corpus_sha256,
            source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
            source_provenance_observation=source_provenance_observation,
            configured_model_ids=tuple(target.model_id for target in targets),
            configured_provider_endpoints=(controls.provider_policy.configured_endpoints),
            requested_budget_usd=Decimal(str(config.execution.budget_usd)),
            now=privacy_observed_at,
        )
        with load_operator_secrets(secrets_env_file, required=True) as operator_secrets:
            if not operator_secrets.openrouter_api_key_present:
                raise ConfigError("OPENROUTER_API_KEY is missing from the operator secret file")
            client = OpenRouterClient(
                api_key=operator_secrets.openrouter_api_key,
                execution=config.execution,
                privacy=config.privacy,
                budget=budget,
                usage=usage,
                provider_policy=controls.provider_policy,
                reasoning_policy=controls.reasoning_policy,
                effective_privacy_policy=effective_privacy_policy,
                source_provenance_observation=source_provenance_observation,
            )
            try:
                await client.validate_authentication()
                models_payload = await client.get_certification_model_metadata()
                zdr_payload = await client.list_zdr_endpoints()
                policy_mode: Literal["only", "order"] = (
                    "only" if controls.provider_policy.only else "order"
                )
                single_model_payloads: dict[str, dict[str, Any]] = {}
                endpoint_payloads: dict[str, dict[str, Any]] = {}
                discovery_payloads = []
                for target in targets:
                    openrouter_catalog_canonical_slug(
                        exact_model_id=target.model_id,
                        models_payload=models_payload,
                    )
                    single_model_payload = await client.get_model_metadata(target.model_id)
                    single_model_payloads[target.model_id] = single_model_payload
                    endpoint_payload = await client.get_model_endpoint_metadata(target.model_id)
                    endpoint_payloads[target.model_id] = endpoint_payload
                    endpoint_snapshot = validate_openrouter_endpoint_snapshot(
                        exact_model_id=target.model_id,
                        configured_provider_endpoints=(
                            controls.provider_policy.configured_endpoints
                        ),
                        provider_policy_mode=policy_mode,
                        endpoint_payload=endpoint_payload,
                        require_zdr=True,
                        zdr_payload=zdr_payload,
                        reasoning_requested=False,
                        structured_output_required=False,
                    )
                    discovery_payloads.append(
                        validate_openrouter_model_discovery(
                            exact_model_id=target.model_id,
                            models_payload=models_payload,
                            single_model_payload=single_model_payload,
                            endpoint_snapshot=endpoint_snapshot,
                        )
                    )
                _provenance, discovery_evidence = client.seal_real_model_discovery_run(
                    run_id=uuid.uuid4().hex,
                    retrieved_at=datetime.now(UTC).replace(microsecond=0),
                    models_payload=models_payload,
                    zdr_payload=zdr_payload,
                    single_model_payloads=single_model_payloads,
                    endpoint_payloads=endpoint_payloads,
                    candidate_routes=tuple(
                        DiscoveryCandidateRoute(
                            exact_model_id=target.model_id,
                            approved_provider_endpoint=(
                                controls.provider_policy.configured_endpoints[0]
                            ),
                        )
                        for target in sorted(targets, key=lambda item: item.model_id)
                    ),
                    payloads=tuple(
                        sorted(
                            discovery_payloads,
                            key=lambda item: item.exact_model_id,
                        )
                    ),
                )
                for evidence in discovery_evidence:
                    client.register_certification_model_discovery(evidence=evidence)
                report = await run_model_benchmark(
                    corpus=benchmark_corpus,
                    targets=targets,
                    provider=OpenRouterModelBenchmarkProvider(client),
                )
            finally:
                await client.close()
        write_model_benchmark_report(output, report)
        local_console = Console(no_color=no_color)
        for result in report.results:
            local_console.print(
                f"{result.target.model_id} ({result.target.root_lineage}): "
                f"{result.overall_score:.1%}"
            )
        local_console.print(f"Result: {output.resolve()}")

    _run_async_cli(execute)


@models_app.command("authenticated-runner")
def models_authenticated_runner(
    candidate_registry: Annotated[
        Path,
        typer.Option(
            "--candidate-registry",
            help="Fresh-discovery-bound singleton candidate registry.",
        ),
    ],
    candidate_discovery_run: Annotated[
        Path,
        typer.Option(
            "--candidate-discovery-run",
            help="Fresh atomic discovery directory for the singleton candidate.",
        ),
    ],
    primary_judge_registry: Annotated[
        Path,
        typer.Option(
            "--primary-judge-registry",
            help="Fresh-discovery-bound singleton PRIMARY judge registry.",
        ),
    ],
    primary_judge_discovery_run: Annotated[
        Path,
        typer.Option(
            "--primary-judge-discovery-run",
            help="Fresh atomic discovery directory for the PRIMARY judge.",
        ),
    ],
    replay_judge_registry: Annotated[
        Path,
        typer.Option(
            "--replay-judge-registry",
            help="Fresh-discovery-bound singleton REPLAY judge registry.",
        ),
    ],
    replay_judge_discovery_run: Annotated[
        Path,
        typer.Option(
            "--replay-judge-discovery-run",
            help="Fresh atomic discovery directory for the REPLAY judge.",
        ),
    ],
    qualification_policy: Annotated[
        Path,
        typer.Option(
            "--qualification-policy",
            help="Frozen release-pinned candidate qualification policy.",
        ),
    ],
    primary_campaign_journal: Annotated[
        Path,
        typer.Option(
            "--primary-campaign-journal",
            help="Fresh absolute private PRIMARY campaign directory.",
        ),
    ],
    primary_portfolio: Annotated[
        Path,
        typer.Option(
            "--primary-portfolio",
            help="Fresh absolute private PRIMARY portfolio directory.",
        ),
    ],
    replay_campaign_journal: Annotated[
        Path,
        typer.Option(
            "--replay-campaign-journal",
            help="Fresh absolute private REPLAY campaign directory.",
        ),
    ],
    replay_portfolio: Annotated[
        Path,
        typer.Option(
            "--replay-portfolio",
            help="Fresh absolute private REPLAY portfolio directory.",
        ),
    ],
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            help="Fresh absolute private nonauthorizing runner/AUTHSEAL JSON output.",
        ),
    ],
    candidate_declared_cost_cap_usd_per_attempt: Annotated[
        str,
        typer.Option(
            "--candidate-cost-cap-usd-per-attempt",
            help="Exact positive candidate per-attempt cost tripwire (decimal USD).",
        ),
    ],
    primary_judge_declared_cost_cap_usd_per_attempt: Annotated[
        str,
        typer.Option(
            "--primary-judge-cost-cap-usd-per-attempt",
            help="Exact positive PRIMARY judge per-attempt cost tripwire (decimal USD).",
        ),
    ],
    replay_judge_declared_cost_cap_usd_per_attempt: Annotated[
        str,
        typer.Option(
            "--replay-judge-cost-cap-usd-per-attempt",
            help="Exact positive REPLAY judge per-attempt cost tripwire (decimal USD).",
        ),
    ],
    config_path: ConfigOption = Path(DEFAULT_CONFIG_NAME),
    secrets_env_file: SecretsEnvFileOption = None,
    corpus: Annotated[
        Path,
        typer.Option("--corpus", help="Exact frozen synthetic/public benchmark corpus."),
    ] = DEFAULT_MODEL_BENCHMARK_CORPUS,
    ground_truth_provenance: Annotated[
        Path,
        typer.Option(
            "--ground-truth-provenance",
            help="Compiled-pin-bound frozen ground-truth provenance.",
        ),
    ] = DEFAULT_MODEL_BENCHMARK_PROVENANCE,
    cost_ledger: Annotated[
        Path | None,
        typer.Option(
            "--cost-ledger",
            help="Existing absolute exact-250-USD cumulative provider cost ledger.",
        ),
    ] = None,
    allow_code_egress: Annotated[
        bool,
        typer.Option(
            "--allow-code-egress",
            help="Explicitly permit only the frozen synthetic/public corpus to reach providers.",
        ),
    ] = False,
    preflight_only: Annotated[
        bool,
        typer.Option(
            "--preflight-only",
            help=(
                "Validate the complete launch without selecting secrets, provider access, "
                "ledger mutation, or output publication."
            ),
        ),
    ] = False,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Run one exact two-pass authenticated synthetic benchmark in a single process."""

    async def execute() -> None:
        if not allow_code_egress:
            raise ConfigError("models authenticated-runner requires explicit --allow-code-egress")
        candidate_cost_cap = _parse_authenticated_runner_cost_cap(
            candidate_declared_cost_cap_usd_per_attempt,
            label="candidate",
        )
        primary_judge_cost_cap = _parse_authenticated_runner_cost_cap(
            primary_judge_declared_cost_cap_usd_per_attempt,
            label="PRIMARY judge",
        )
        replay_judge_cost_cap = _parse_authenticated_runner_cost_cap(
            replay_judge_declared_cost_cap_usd_per_attempt,
            label="REPLAY judge",
        )

        config = load_config(config_path)
        benchmark_suite = load_model_benchmark_corpus(corpus)
        provenance = load_frozen_ground_truth_provenance(ground_truth_provenance)
        ground_truth_capability = resolve_verified_frozen_ground_truth(
            provenance=provenance,
            benchmark_suite=benchmark_suite,
        )
        public_lineage_capability = resolve_verified_public_model_lineage()
        candidate = load_candidate_registry(candidate_registry)
        candidate_manifest, candidate_evidence = load_model_discovery_run(candidate_discovery_run)
        primary_judge = load_candidate_registry(primary_judge_registry)
        primary_judge_manifest, primary_judge_evidence = load_model_discovery_run(
            primary_judge_discovery_run
        )
        replay_judge = load_candidate_registry(replay_judge_registry)
        replay_judge_manifest, replay_judge_evidence = load_model_discovery_run(
            replay_judge_discovery_run
        )
        policy = load_qualification_policy(qualification_policy)
        _require_qualification_release_pins(
            config=config,
            policy=policy,
            benchmark_suite=benchmark_suite,
        )
        ledger_path = _selected_cost_ledger_path(config, cost_ledger)
        if ledger_path is None:
            raise ConfigError(
                "models authenticated-runner requires an existing --cost-ledger initialized "
                "with models init-cost-ledger or execution.cost_ledger_path"
            )
        budget, usage = _budget_and_usage(
            config,
            ledger_path=ledger_path,
            require_endpoint_cost_bound=True,
        )
        ledger = budget.atomic_ledger
        if ledger is None:
            raise ConfigError("authenticated runner cost ledger failed to open")

        plans = (
            AuthenticatedRunnerRunPlan(
                run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
                campaign_path=primary_campaign_journal,
                portfolio_path=primary_portfolio,
                judge_discovery_manifest=primary_judge_manifest,
                judge_discovery_evidence=primary_judge_evidence,
                judge_registry=primary_judge,
                candidate_declared_cost_cap_usd_per_attempt=candidate_cost_cap,
                judge_declared_cost_cap_usd_per_attempt=primary_judge_cost_cap,
            ),
            AuthenticatedRunnerRunPlan(
                run_kind=CrossLineageAdjudicationRunKind.REPLAY,
                campaign_path=replay_campaign_journal,
                portfolio_path=replay_portfolio,
                judge_discovery_manifest=replay_judge_manifest,
                judge_discovery_evidence=replay_judge_evidence,
                judge_registry=replay_judge,
                candidate_declared_cost_cap_usd_per_attempt=candidate_cost_cap,
                judge_declared_cost_cap_usd_per_attempt=replay_judge_cost_cap,
            ),
        )
        launch = AuthenticatedRunnerOpenRouterLaunch(
            config=config,
            explicitly_allow_synthetic_egress=allow_code_egress,
            public_lineage_capability=public_lineage_capability,
            ground_truth_capability=ground_truth_capability,
            benchmark_suite=benchmark_suite,
            candidate_discovery_manifest=candidate_manifest,
            candidate_discovery_evidence=candidate_evidence,
            candidate_registry=candidate,
            qualification_policy=policy,
            budget=budget,
            usage=usage,
            run_plans=plans,
        )
        mutable_outputs = (
            primary_campaign_journal,
            primary_portfolio,
            replay_campaign_journal,
            replay_portfolio,
            output,
        )
        source_paths: tuple[Path, ...] = (
            config_path,
            corpus,
            ground_truth_provenance,
            candidate_registry,
            candidate_discovery_run,
            primary_judge_registry,
            primary_judge_discovery_run,
            replay_judge_registry,
            replay_judge_discovery_run,
            qualification_policy,
            ledger.path,
            ledger.lock_path,
        )
        _preflight_authenticated_runner_cli_paths(
            mutable_outputs=mutable_outputs,
            source_paths=source_paths,
        )
        _preflight_authenticated_runner_output(output)
        inventory = preflight_authenticated_openrouter_launch(launch)
        selected_secret_file: Path | None = None
        if not preflight_only:
            selected_secret_file = select_operator_secret_file(secrets_env_file)
            if selected_secret_file is None:
                raise ConfigError(
                    "models authenticated-runner requires --secrets-env-file or "
                    "MMAUDIT_SECRETS_ENV_FILE"
                )
            source_paths = (*source_paths, selected_secret_file)
            _preflight_authenticated_runner_cli_paths(
                mutable_outputs=mutable_outputs,
                source_paths=source_paths,
            )

        if preflight_only:
            local_console = Console(no_color=no_color)
            local_console.print(
                "AUTHRUNNER preflight: VALID / NONAUTHORIZING / NO PROVIDER EGRESS",
                markup=False,
            )
            local_console.print(
                f"Inventory: runs={inventory.run_count}; cases={inventory.case_count}; "
                f"candidate_logical_requests={inventory.candidate_logical_request_count}; "
                f"judge_logical_requests={inventory.judge_logical_request_count}; "
                f"logical_requests={inventory.logical_request_count}",
                markup=False,
            )
            local_console.print(
                "Attempts: "
                f"maximum_per_logical_request={inventory.maximum_attempts_per_logical_request}; "
                f"maximum_provider_attempts={inventory.maximum_provider_attempt_count}; "
                f"generation_refetches={inventory.generation_refetch_count}",
                markup=False,
            )
            local_console.print(
                f"Operator cost tripwires: initial_spent_usd={inventory.initial_spent_usd}; "
                f"operator_interval_cap_usd={inventory.declared_interval_cost_cap_usd}; "
                f"operator_final_spent_cap_usd={inventory.declared_final_spent_cap_usd}",
                markup=False,
            )
            local_console.print(
                "Candidate exact admission: "
                f"plan_sha256s={','.join(inventory.candidate_stage_plan_sha256s)}; "
                "derived_interval_cap_usd="
                f"{inventory.candidate_derived_interval_cost_cap_usd}; "
                "derived_final_spent_cap_usd="
                f"{inventory.candidate_derived_final_spent_cap_usd}",
                markup=False,
            )
            local_console.print(
                "Judge exact admission: "
                f"status={inventory.judge_cost_admission_status}; "
                "full_campaign_cost_bound=UNAVAILABLE_BEFORE_REAL_CANDIDATE_OUTPUTS",
                markup=False,
            )
            local_console.print(
                f"Effective config SHA-256: {inventory.effective_config_sha256}",
                markup=False,
            )
            return

        if selected_secret_file is None:
            raise ConfigError("authenticated runner secret selection was not retained")

        with load_operator_secrets(selected_secret_file, required=True) as operator_secrets:
            if not operator_secrets.openrouter_api_key_present:
                raise ConfigError("OPENROUTER_API_KEY is missing from the operator secret file")
            result = await execute_authenticated_openrouter_runner(
                launch=launch,
                operator_secrets=operator_secrets,
            )

        durable_output = _authenticated_runner_durable_output(result)
        _preflight_authenticated_runner_output(output)
        _write_authenticated_runner_output_fresh(output, durable_output)
        local_console = Console(no_color=no_color)
        if result.authseal_rejection_kind is not None:
            raise ConfigError(
                "AUTHSEAL comparison rejected after AUTHRUNNER completion "
                f"({result.authseal_rejection_kind}); nonauthorizing runner evidence "
                f"was retained at {output}"
            )
        assert result.authseal_collision_map is not None
        local_console.print(
            f"Runner evidence: {result.runner_evidence.evidence_sha256}; "
            f"AUTHSEAL collision map: "
            f"{result.authseal_collision_map.collision_map_sha256}",
            markup=False,
        )
        local_console.print(f"Result: {output}", markup=False)

    _run_async_cli(execute)


@models_app.command("verify-authenticated-runner")
def models_verify_authenticated_runner(
    bundle_path: Annotated[
        Path,
        typer.Option(
            "--bundle",
            help="Absolute private mode-0600 nonauthorizing AUTHRUNNER evidence bundle.",
        ),
    ],
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Replay one durable AUTHRUNNER bundle offline without issuing authority."""

    async def execute() -> None:
        bundle = load_authenticated_runner_durable_bundle(bundle_path)
        if bundle.schema_version != "1.1":
            raise ConfigError(
                "authenticated runner durable evidence is legacy and lacks exact staged "
                "request-cost admission"
            )
        ledger = bundle.closed_ledger_evidence
        local_console = Console(no_color=no_color)
        local_console.print(
            "AUTHRUNNER durable evidence: VALID / NONAUTHORIZING",
            markup=False,
        )
        local_console.print(f"Bundle SHA-256: {bundle.bundle_sha256}", markup=False)
        local_console.print(
            f"Runner SHA-256: {bundle.runner_evidence_sha256}",
            markup=False,
        )
        local_console.print(
            f"Closed ledger: entries={len(ledger.entries)}; "
            f"final_spent_usd={ledger.final_spent_usd}",
            markup=False,
        )
        local_console.print(
            f"AUTHSEAL comparison: {bundle.authseal_comparison.status}",
            markup=False,
        )

    _run_async_cli(execute)


@models_app.command("authenticated-runner-smoke")
def models_authenticated_runner_smoke(
    candidate_registry: Annotated[
        Path,
        typer.Option(
            "--candidate-registry",
            help="Fresh-discovery-bound singleton smoke candidate registry.",
        ),
    ],
    candidate_discovery_run: Annotated[
        Path,
        typer.Option(
            "--candidate-discovery-run",
            help="Fresh atomic discovery directory for the singleton smoke candidate.",
        ),
    ],
    primary_judge_registry: Annotated[
        Path,
        typer.Option(
            "--primary-judge-registry",
            help="Fresh-discovery-bound singleton PRIMARY smoke judge registry.",
        ),
    ],
    primary_judge_discovery_run: Annotated[
        Path,
        typer.Option(
            "--primary-judge-discovery-run",
            help="Fresh atomic discovery directory for the PRIMARY smoke judge.",
        ),
    ],
    replay_judge_registry: Annotated[
        Path,
        typer.Option(
            "--replay-judge-registry",
            help="Fresh-discovery-bound singleton REPLAY smoke judge registry.",
        ),
    ],
    replay_judge_discovery_run: Annotated[
        Path,
        typer.Option(
            "--replay-judge-discovery-run",
            help="Fresh atomic discovery directory for the REPLAY smoke judge.",
        ),
    ],
    smoke_corpus: Annotated[
        Path,
        typer.Option(
            "--smoke-corpus",
            help="Exact four-file NONCREDITING smoke corpus directory.",
        ),
    ],
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            help="Fresh absolute private NONCREDITING smoke evidence JSON.",
        ),
    ],
    candidate_cost_tripwire_usd_per_attempt: Annotated[
        str,
        typer.Option(
            "--candidate-cost-cap-usd-per-attempt",
            help="Positive candidate per-attempt smoke cost tripwire (decimal USD).",
        ),
    ],
    primary_judge_cost_tripwire_usd_per_attempt: Annotated[
        str,
        typer.Option(
            "--primary-judge-cost-cap-usd-per-attempt",
            help="Positive PRIMARY judge per-attempt smoke cost tripwire (decimal USD).",
        ),
    ],
    replay_judge_cost_tripwire_usd_per_attempt: Annotated[
        str,
        typer.Option(
            "--replay-judge-cost-cap-usd-per-attempt",
            help="Positive REPLAY judge per-attempt smoke cost tripwire (decimal USD).",
        ),
    ],
    config_path: ConfigOption = Path(DEFAULT_CONFIG_NAME),
    secrets_env_file: SecretsEnvFileOption = None,
    corpus: Annotated[
        Path,
        typer.Option("--corpus", help="Exact frozen 24-case parent benchmark corpus."),
    ] = DEFAULT_MODEL_BENCHMARK_CORPUS,
    cost_ledger: Annotated[
        Path | None,
        typer.Option(
            "--cost-ledger",
            help="Existing absolute exact-250-USD cumulative provider cost ledger.",
        ),
    ] = None,
    allow_code_egress: Annotated[
        bool,
        typer.Option(
            "--allow-code-egress",
            help="Explicitly permit only the frozen synthetic smoke case to reach providers.",
        ),
    ] = False,
    allow_metadata_egress: Annotated[
        bool,
        typer.Option(
            "--allow-metadata-egress",
            help=(
                "Explicitly permit only authentication and public model-route metadata GETs "
                "for --live-route-preflight-only."
            ),
        ),
    ] = False,
    preflight_only: Annotated[
        bool,
        typer.Option(
            "--preflight-only",
            help=(
                "Validate the smoke launch without selecting secrets, provider access, "
                "ledger mutation, or output publication."
            ),
        ),
    ] = False,
    live_route_preflight_only: Annotated[
        bool,
        typer.Option(
            "--live-route-preflight-only",
            help=(
                "Authenticate and refresh the exact candidate and judge metadata routes, "
                "then stop without completions, ledger mutation, or output publication."
            ),
        ),
    ] = False,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Run one non-resumable, one-case REAL transport smoke without benchmark credit."""

    async def execute() -> None:
        if preflight_only and live_route_preflight_only:
            raise ConfigError(
                "--preflight-only and --live-route-preflight-only are mutually exclusive"
            )
        if live_route_preflight_only:
            if allow_code_egress:
                raise ConfigError(
                    "--live-route-preflight-only rejects broader --allow-code-egress authority"
                )
            if not allow_metadata_egress:
                raise ConfigError(
                    "--live-route-preflight-only requires explicit --allow-metadata-egress"
                )
        else:
            if allow_metadata_egress:
                raise ConfigError("--allow-metadata-egress requires --live-route-preflight-only")
            if not allow_code_egress:
                raise ConfigError(
                    "models authenticated-runner-smoke requires explicit --allow-code-egress"
                )
        candidate_tripwire = _parse_authenticated_runner_cost_cap(
            candidate_cost_tripwire_usd_per_attempt,
            label="smoke candidate",
        )
        primary_judge_tripwire = _parse_authenticated_runner_cost_cap(
            primary_judge_cost_tripwire_usd_per_attempt,
            label="smoke PRIMARY judge",
        )
        replay_judge_tripwire = _parse_authenticated_runner_cost_cap(
            replay_judge_cost_tripwire_usd_per_attempt,
            label="smoke REPLAY judge",
        )

        config = load_config(config_path)
        benchmark_suite = load_model_benchmark_corpus(corpus)
        smoke_bundle = load_authenticated_runner_smoke_corpus_bundle(smoke_corpus)
        public_lineage_capability = resolve_verified_public_model_lineage()
        candidate = load_candidate_registry(candidate_registry)
        candidate_manifest, candidate_evidence = load_model_discovery_run(candidate_discovery_run)
        primary_judge = load_candidate_registry(primary_judge_registry)
        primary_manifest, primary_evidence = load_model_discovery_run(primary_judge_discovery_run)
        replay_judge = load_candidate_registry(replay_judge_registry)
        replay_manifest, replay_evidence = load_model_discovery_run(replay_judge_discovery_run)
        ledger_path = _selected_cost_ledger_path(config, cost_ledger)
        if ledger_path is None:
            raise ConfigError(
                "models authenticated-runner-smoke requires an existing --cost-ledger "
                "initialized with models init-cost-ledger or execution.cost_ledger_path"
            )
        budget, usage = _budget_and_usage(
            config,
            ledger_path=ledger_path,
            require_endpoint_cost_bound=True,
        )
        ledger = budget.atomic_ledger
        if ledger is None:
            raise ConfigError("authenticated runner smoke cost ledger failed to open")

        launch = AuthenticatedRunnerSmokeOpenRouterLaunch(
            config=config,
            explicitly_allow_synthetic_egress=(
                False if live_route_preflight_only else allow_code_egress
            ),
            public_lineage_capability=public_lineage_capability,
            benchmark_suite=benchmark_suite,
            smoke_corpus=smoke_bundle,
            candidate_discovery_manifest=candidate_manifest,
            candidate_discovery_evidence=candidate_evidence,
            candidate_registry=candidate,
            budget=budget,
            usage=usage,
            run_plans=(
                AuthenticatedRunnerSmokeRunPlan(
                    run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
                    judge_discovery_manifest=primary_manifest,
                    judge_discovery_evidence=primary_evidence,
                    judge_registry=primary_judge,
                    candidate_cost_tripwire_usd_per_attempt=candidate_tripwire,
                    judge_cost_tripwire_usd_per_attempt=primary_judge_tripwire,
                ),
                AuthenticatedRunnerSmokeRunPlan(
                    run_kind=CrossLineageAdjudicationRunKind.REPLAY,
                    judge_discovery_manifest=replay_manifest,
                    judge_discovery_evidence=replay_evidence,
                    judge_registry=replay_judge,
                    candidate_cost_tripwire_usd_per_attempt=candidate_tripwire,
                    judge_cost_tripwire_usd_per_attempt=replay_judge_tripwire,
                ),
            ),
        )
        source_paths: tuple[Path, ...] = (
            config_path,
            corpus,
            smoke_corpus,
            candidate_registry,
            candidate_discovery_run,
            primary_judge_registry,
            primary_judge_discovery_run,
            replay_judge_registry,
            replay_judge_discovery_run,
            ledger.path,
            ledger.lock_path,
        )
        _preflight_authenticated_runner_smoke_cli_paths(
            output=output,
            source_paths=source_paths,
        )
        if preflight_only or live_route_preflight_only:
            _preflight_authenticated_runner_smoke_output_readonly(output)
        else:
            _preflight_authenticated_runner_output(output)
        inventory = (
            preflight_authenticated_runner_smoke_live_route_launch(launch)
            if live_route_preflight_only
            else preflight_authenticated_runner_smoke_openrouter_launch(launch)
        )

        if preflight_only:
            local_console = Console(no_color=no_color)
            local_console.print(
                "AUTHRUNNER smoke preflight: VALID / NONCREDITING / NONAUTHORIZING / "
                "NO PROVIDER EGRESS",
                markup=False,
            )
            local_console.print(
                f"Inventory: runs={inventory.run_count}; cases={inventory.case_count}; "
                f"logical_requests={inventory.logical_request_count}; "
                f"maximum_provider_attempts={inventory.maximum_provider_attempt_count}; "
                f"generation_refetches={inventory.generation_refetch_count}",
                markup=False,
            )
            local_console.print(
                "Operator cost tripwires: "
                f"initial_spent_usd={inventory.initial_spent_usd}; "
                f"operator_interval_cap_usd={inventory.operator_interval_tripwire_usd}; "
                f"operator_final_spent_cap_usd={inventory.operator_final_spent_tripwire_usd}",
                markup=False,
            )
            local_console.print(
                "Candidate exact admission: "
                f"plan_sha256s={','.join(item.plan_sha256 for item in inventory.candidate_cost_plans)}; "
                "derived_interval_cap_usd="
                f"{inventory.candidate_derived_interval_cost_cap_usd}; "
                "derived_final_spent_cap_usd="
                f"{inventory.candidate_derived_final_spent_cap_usd}",
                markup=False,
            )
            local_console.print(
                "Judge exact admission: "
                f"status={inventory.judge_cost_admission_status}; "
                "full_smoke_cost_bound=UNAVAILABLE_BEFORE_REAL_CANDIDATE_OUTPUTS",
                markup=False,
            )
            local_console.print(
                f"Effective config SHA-256: {inventory.effective_config_sha256}",
                markup=False,
            )
            return

        selected_secret_file = select_operator_secret_file(secrets_env_file)
        if selected_secret_file is None:
            raise ConfigError(
                "models authenticated-runner-smoke requires --secrets-env-file or "
                "MMAUDIT_SECRETS_ENV_FILE"
            )
        _preflight_authenticated_runner_smoke_cli_paths(
            output=output,
            source_paths=(*source_paths, selected_secret_file),
        )
        with load_operator_secrets(selected_secret_file, required=True) as operator_secrets:
            if not operator_secrets.openrouter_api_key_present:
                raise ConfigError("OPENROUTER_API_KEY is missing from the operator secret file")
            if live_route_preflight_only:
                live_route_result = await preflight_authenticated_runner_smoke_live_routes(
                    launch=launch,
                    operator_secrets=operator_secrets,
                    explicitly_allow_metadata_egress=allow_metadata_egress,
                )
            else:
                result = await execute_authenticated_runner_smoke_openrouter(
                    launch=launch,
                    operator_secrets=operator_secrets,
                )

        if live_route_preflight_only:
            if live_route_result.inventory != inventory:
                raise ConfigError(
                    "authenticated runner smoke live-route inventory changed after secret selection"
                )
            local_console = Console(no_color=no_color)
            local_console.print(
                "AUTHRUNNER smoke live-route preflight: VALID / NONCREDITING / "
                "NONAUTHORIZING / METADATA EGRESS ONLY / NO MODEL COMPLETION",
                markup=False,
            )
            local_console.print(
                "Validated exact routes: "
                f"candidate={live_route_result.exact_model_ids[0]}; "
                f"primary_judge={live_route_result.exact_model_ids[1]}; "
                f"replay_judge={live_route_result.exact_model_ids[2]}",
                markup=False,
            )
            local_console.print(
                "Metadata request inventory: "
                f"logical_gets={live_route_result.logical_metadata_get_count}; "
                "maximum_provider_attempts="
                f"{live_route_result.maximum_metadata_provider_attempt_count}",
                markup=False,
            )
            local_console.print(
                "Runtime state: usage_records=0; budget=UNCHANGED; "
                "atomic_cost_ledger=UNCHANGED; "
                "output=NOT_PUBLISHED",
                markup=False,
            )
            local_console.print(
                f"Effective config SHA-256: {inventory.effective_config_sha256}",
                markup=False,
            )
            return

        _preflight_authenticated_runner_output(output)
        _write_authenticated_runner_smoke_output_fresh(output, result.bundle)
        local_console = Console(no_color=no_color)
        local_console.print(
            "AUTHRUNNER smoke: COMPLETE / NONCREDITING / NONAUTHORIZING",
            markup=False,
        )
        local_console.print(f"Bundle SHA-256: {result.bundle.bundle_sha256}", markup=False)
        local_console.print(
            f"Closed ledger: entries={len(result.bundle.closed_ledger_evidence.entries)}; "
            f"final_spent_usd={result.bundle.closed_ledger_evidence.final_spent_usd}",
            markup=False,
        )
        local_console.print(f"Result: {output}", markup=False)

    _run_async_cli(execute)


@models_app.command("verify-authenticated-runner-smoke")
def models_verify_authenticated_runner_smoke(
    bundle_path: Annotated[
        Path,
        typer.Option(
            "--bundle",
            help="Absolute private mode-0600 NONCREDITING smoke evidence bundle.",
        ),
    ],
    smoke_corpus: Annotated[
        Path,
        typer.Option(
            "--smoke-corpus",
            help="Exact tracked four-file NONCREDITING smoke corpus directory.",
        ),
    ],
    config_path: ConfigOption = Path(DEFAULT_CONFIG_NAME),
    corpus: Annotated[
        Path,
        typer.Option("--corpus", help="Exact frozen 24-case parent benchmark corpus."),
    ] = DEFAULT_MODEL_BENCHMARK_CORPUS,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Strictly replay one smoke bundle offline without recreating live authority."""

    async def execute() -> None:
        bundle = _load_authenticated_runner_smoke_evidence_bundle(bundle_path)
        smoke = load_authenticated_runner_smoke_corpus_bundle(smoke_corpus)
        parent = load_model_benchmark_corpus(corpus)
        config = load_config(config_path)
        parent_case = {item.case_id: item for item in parent.cases}.get(bundle.selected_case_id)
        parent_truth = {item.case_id: item for item in parent.ground_truth.cases}.get(
            bundle.selected_case_id
        )
        if (
            bundle.smoke_corpus_bundle_sha256 != smoke.bundle_sha256
            or bundle.parent_corpus_sha256 != parent.corpus_sha256
            or bundle.parent_ground_truth_sha256 != parent.ground_truth_sha256
            or bundle.effective_config_sha256 != config.stable_hash()
            or bundle.selected_case_id != smoke.case.case_id
            or parent_case != smoke.case
            or parent_truth != smoke.ground_truth_case
        ):
            raise ConfigError(
                "authenticated runner smoke evidence differs from its tracked corpus, "
                "parent, or effective configuration"
            )
        local_console = Console(no_color=no_color)
        local_console.print(
            "AUTHRUNNER smoke evidence: VALID / NONCREDITING / NONAUTHORIZING",
            markup=False,
        )
        local_console.print(f"Bundle SHA-256: {bundle.bundle_sha256}", markup=False)
        local_console.print(
            f"Inventory: case={bundle.selected_case_id}; runs={bundle.run_count}; "
            f"logical_requests={bundle.logical_request_count}",
            markup=False,
        )
        local_console.print(
            f"Closed ledger: entries={len(bundle.closed_ledger_evidence.entries)}; "
            f"final_spent_usd={bundle.closed_ledger_evidence.final_spent_usd}",
            markup=False,
        )

    _run_async_cli(execute)


async def _execute_candidate_registry_benchmark(
    *,
    config: AuditConfig,
    benchmark_corpus: ModelBenchmarkSuite,
    candidate_registry_path: Path,
    discovery_run_path: Path,
    secrets_env_file: Path | None,
    output: Path,
    campaign_journal_path: Path,
    resume_campaign: bool,
    qualification_policy_path: Path,
    calibration_output: Path | None,
    calibrated_policy_output: Path | None,
    lineage_review_bundle: Path | None,
    lineage_trust_anchor: Path | None,
    cost_ledger: Path | None,
    allow_code_egress: bool,
    no_color: bool,
) -> None:
    """Validate, execute, and atomically publish one frozen candidate benchmark set."""

    registry = load_candidate_registry(candidate_registry_path)
    qualification_policy = load_qualification_policy(qualification_policy_path)
    _require_qualification_release_pins(
        config=config,
        policy=qualification_policy,
        benchmark_suite=benchmark_corpus,
    )
    discovery_manifest, discovery_evidence = load_model_discovery_run(discovery_run_path)
    validate_candidate_registry_discovery(
        registry=registry,
        run_manifest=discovery_manifest,
        evidence=discovery_evidence,
    )
    validate_candidate_benchmark_egress(
        config=config,
        benchmark_suite=benchmark_corpus,
        explicitly_allowed=allow_code_egress,
    )
    validate_candidate_benchmark_policy_capacity(
        benchmark_suite=benchmark_corpus,
        qualification_policy=qualification_policy,
    )
    ledger_path = _selected_cost_ledger_path(config, cost_ledger)
    if ledger_path is None:
        raise ConfigError(
            "candidate benchmark requires an existing --cost-ledger initialized "
            "with models init-cost-ledger or execution.cost_ledger_path"
        )
    if calibration_output is not None:
        _preflight_model_calibration_output(
            calibration_output,
            cost_ledger_path=ledger_path,
            portfolio_output=output,
            campaign_journal=campaign_journal_path,
        )
    if calibrated_policy_output is not None:
        assert calibration_output is not None
        _preflight_calibrated_policy_output(
            calibrated_policy_output,
            cost_ledger_path=ledger_path,
            portfolio_output=output,
            campaign_journal=campaign_journal_path,
            calibration_output=calibration_output,
        )
    lineage_review_artifact: ModelLineageReviewArtifact | None = None
    trusted_lineage_verification: TrustedModelLineageReviewVerification | None = None
    if calibration_output is not None:
        assert lineage_review_bundle is not None
        assert lineage_trust_anchor is not None
        lineage_review_artifact, authority_envelope = load_model_lineage_authority_bundle(
            lineage_review_bundle
        )
        trust_anchor = load_model_lineage_trust_anchor(lineage_trust_anchor)
        lineage_observed_at = datetime.now(UTC).replace(microsecond=0)
        trusted_lineage_verification = verify_operator_model_lineage_authority(
            artifact=lineage_review_artifact,
            envelope=authority_envelope,
            trust_anchor=trust_anchor,
            observed_at=lineage_observed_at,
        )
        trusted_lineage_verification.require_for(
            candidate_registry=registry,
            discovery_manifest=discovery_manifest,
            campaign_started_at=lineage_observed_at,
            observed_at=lineage_observed_at,
        )
    budget, usage = _budget_and_usage(
        config,
        ledger_path=ledger_path,
        require_endpoint_cost_bound=True,
    )
    assert budget.atomic_ledger is not None
    _preflight_model_benchmark_portfolio_output(output, budget.atomic_ledger)
    if Path(os.path.abspath(output)) == Path(os.path.abspath(campaign_journal_path)):
        raise ConfigError("candidate campaign journal and final portfolio must be distinct")
    effective_config_sha256 = config.stable_hash()
    campaign: CandidateBenchmarkCampaignJournal
    if resume_campaign:
        campaign = resume_candidate_benchmark_campaign(
            campaign_journal_path,
            candidate_registry=registry,
            corpus=benchmark_corpus,
            effective_config_sha256=effective_config_sha256,
            qualification_policy_sha256=qualification_policy.policy_sha256,
            cost_ledger=budget.atomic_ledger,
        )
    else:
        campaign = create_candidate_benchmark_campaign(
            campaign_journal_path,
            candidate_registry=registry,
            corpus=benchmark_corpus,
            effective_config_sha256=effective_config_sha256,
            qualification_policy_sha256=qualification_policy.policy_sha256,
            cost_ledger=budget.atomic_ledger,
        )

    with load_operator_secrets(secrets_env_file, required=True) as operator_secrets:
        if not operator_secrets.openrouter_api_key_present:
            raise ConfigError("OPENROUTER_API_KEY is missing from the operator secret file")
        execution = await run_candidate_registry_benchmarks(
            config=config,
            discovery_manifest=discovery_manifest,
            discovery_evidence=discovery_evidence,
            candidate_registry=registry,
            benchmark_suite=benchmark_corpus,
            budget=budget,
            usage=usage,
            operator_api_key=operator_secrets.openrouter_api_key,
            explicitly_allow_synthetic_egress=True,
            evidence_sink=campaign,
            qualification_policy=qualification_policy,
        )

    local_console = Console(no_color=no_color)
    portfolio = seal_model_benchmark_portfolio_from_campaign(
        output,
        campaign=campaign,
    )
    if calibration_output is not None:
        assert lineage_review_artifact is not None
        assert trusted_lineage_verification is not None
        trusted_campaign = issue_trusted_candidate_benchmark_campaign_verification(
            campaign=campaign,
            portfolio=portfolio,
            reports=execution.reports,
        )
        campaign_anchor = portfolio.ended_at or registry.created_at
        calibration_created_at = max(
            datetime.now(UTC).replace(microsecond=0),
            campaign_anchor.replace(microsecond=0),
        )
        calibration = build_model_calibration_artifact(
            created_at=calibration_created_at,
            candidate_registry=registry,
            discovery_run_manifest=discovery_manifest,
            benchmark_suite=benchmark_corpus,
            benchmark_portfolio=portfolio,
            benchmark_reports=execution.reports,
            benchmark_policy_sha256=qualification_policy.policy_sha256,
            effective_config_sha256=effective_config_sha256,
            trusted_campaign_verification=trusted_campaign,
            lineage_review_artifact=lineage_review_artifact,
            trusted_lineage_verification=trusted_lineage_verification,
        )
        write_model_calibration_artifact(calibration_output, calibration)
        calibrated_policy: QualificationPolicy | None = None
        if calibrated_policy_output is not None:
            trusted_calibration = issue_trusted_model_calibration_verification(
                artifact=calibration,
                candidate_registry=registry,
                discovery_run_manifest=discovery_manifest,
                benchmark_suite=benchmark_corpus,
                benchmark_portfolio=portfolio,
                benchmark_reports=execution.reports,
                benchmark_policy_sha256=qualification_policy.policy_sha256,
                effective_config_sha256=effective_config_sha256,
                trusted_campaign_verification=trusted_campaign,
                lineage_review_artifact=lineage_review_artifact,
                trusted_lineage_verification=trusted_lineage_verification,
            )
            calibrated_policy = derive_calibrated_qualification_policy(
                calibration=calibration,
                trusted_calibration_verification=trusted_calibration,
            )
        if calibrated_policy is not None:
            assert calibrated_policy_output is not None
            write_calibrated_qualification_policy(
                calibrated_policy_output,
                calibrated_policy,
            )
        local_console.print(
            f"Calibration: {calibration.artifact_sha256}; "
            f"included_models="
            f"{sum(item.included_in_distribution for item in calibration.candidates)}",
            markup=False,
        )
        if calibrated_policy is not None:
            local_console.print(
                f"P2 successor candidate: {calibrated_policy.policy_sha256}; "
                "review, commit, and release-pin it before J2 qualification.",
                markup=False,
            )
    _print_candidate_benchmark_diagnostics(execution, target=local_console)
    local_console.print(
        f"Portfolio: {portfolio.portfolio_sha256}; "
        f"evidence={portfolio.execution_evidence.value}; "
        f"accounted_cost_usd={portfolio.usage.accounted_cost_usd}",
        markup=False,
    )
    if portfolio.execution_evidence is not ExecutionEvidenceKind.REAL or any(
        diagnostic.state is not CandidateBenchmarkRunState.COMPLETE
        for diagnostic in execution.diagnostics
    ):
        raise typer.Exit(ExitCode.MODEL_FAILURE)


@models_app.command("observe-release-bindings")
def models_observe_release_bindings(
    config_path: ConfigOption,
    candidate_registry: Annotated[
        Path,
        typer.Option("--candidate-registry", help="Self-hashed candidate-registry TOML."),
    ],
    corpus: Annotated[
        Path,
        typer.Option("--corpus", help="Self-hashed blinded benchmark corpus."),
    ],
    ground_truth: Annotated[
        Path,
        typer.Option("--ground-truth", help="Separately sealed private benchmark truth."),
    ],
    portfolio: Annotated[
        Path,
        typer.Option("--portfolio", help="Atomic private model-benchmark portfolio."),
    ],
    release_source_root: Annotated[
        Path,
        typer.Option(
            "--release-source-root",
            help="Clean Git root containing the exact executing mmaudit release.",
        ),
    ],
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            help="Fresh mode-0600 bindings path outside the release source tree.",
        ),
    ],
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Measure and publish exact non-secret qualification release bindings."""

    config = load_config(config_path)
    registry = load_candidate_registry(candidate_registry)
    benchmark_suite = load_model_benchmark_corpus(
        corpus,
        ground_truth_path=ground_truth,
    )
    _benchmark_portfolio, reports = load_model_benchmark_portfolio(
        portfolio,
        candidate_registry=registry,
        corpus=benchmark_suite,
    )
    prompt_sha256, response_schema_sha256 = _benchmark_request_binding_hashes(reports)
    backend = default_isolation_backend(
        config.reproduction.isolation_backend,
        rootless_container_image=config.reproduction.rootless_container_image,
        rootless_container_runtime=config.reproduction.rootless_container_runtime,
    )
    measurement = measure_qualification_release_environment(
        source_root=release_source_root,
        isolation_backend=backend,
    )
    source_root = release_source_root.resolve(strict=True)
    output_absolute = Path(os.path.abspath(output))
    try:
        output_absolute.relative_to(source_root)
    except ValueError:
        pass
    else:
        raise ConfigError("release binding output must be outside the release source tree")
    bindings = seal_qualification_release_bindings(
        source_commit=measurement.source_commit,
        source_tree_sha256=measurement.source_tree_sha256,
        effective_config_sha256=config.stable_hash(),
        prompt_sha256=prompt_sha256,
        response_schema_sha256=response_schema_sha256,
        toolchain_sha256=measurement.toolchain_sha256,
        isolation_sha256=measurement.isolation_sha256,
        benchmark_corpus_version=benchmark_suite.corpus.schema_version,
        benchmark_ground_truth_version=benchmark_suite.ground_truth.schema_version,
    )
    write_observed_qualification_release_bindings(output_absolute, bindings)
    Console(no_color=no_color).print(
        f"bindings_sha256={bindings.bindings_sha256} "
        f"source_commit={bindings.source_commit} "
        f"source_tree_sha256={bindings.source_tree_sha256} "
        f"toolchain_sha256={bindings.toolchain_sha256} "
        f"isolation_sha256={bindings.isolation_sha256}",
        markup=False,
    )


@models_app.command("qualify")
def models_qualify(
    config_path: ConfigOption,
    candidate_registry: Annotated[
        Path,
        typer.Option(
            "--candidate-registry",
            help="Self-hashed candidate-registry TOML.",
        ),
    ],
    discovery_run: Annotated[
        Path,
        typer.Option(
            "--discovery-run",
            help="Complete private REAL discovery-run directory.",
        ),
    ],
    policy: Annotated[
        Path,
        typer.Option("--policy", help="Self-hashed qualification-policy TOML."),
    ],
    corpus: Annotated[
        Path,
        typer.Option("--corpus", help="Self-hashed blinded benchmark corpus."),
    ],
    ground_truth: Annotated[
        Path,
        typer.Option(
            "--ground-truth",
            help="Separately sealed private benchmark ground truth.",
        ),
    ],
    portfolio: Annotated[
        Path,
        typer.Option(
            "--portfolio",
            help="Atomic private model-benchmark portfolio directory.",
        ),
    ],
    campaign_journal: Annotated[
        Path,
        typer.Option(
            "--campaign-journal",
            help="Complete private candidate-benchmark campaign journal.",
        ),
    ],
    release_bindings: Annotated[
        Path,
        typer.Option(
            "--release-bindings",
            help="Self-hashed non-secret release bindings JSON.",
        ),
    ],
    release_source_root: Annotated[
        Path,
        typer.Option(
            "--release-source-root",
            help="Clean Git root containing the exact executing mmaudit release.",
        ),
    ],
    qualification_expires_at: Annotated[
        str,
        typer.Option(
            "--qualification-expires-at",
            help="Whole-second UTC qualification expiry.",
        ),
    ],
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            help="Fresh private mode-0600 qualification bundle.",
        ),
    ],
    cost_ledger: Annotated[
        Path | None,
        typer.Option(
            "--cost-ledger",
            help="Existing atomic cost ledger bound to the campaign.",
        ),
    ] = None,
    secrets_env_file: SecretsEnvFileOption = None,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Qualify exact models after a fresh authenticated metadata re-fetch."""

    async def execute() -> None:
        local_console = Console(no_color=no_color)
        config = load_config(config_path)
        registry = load_candidate_registry(candidate_registry)
        discovery_manifest, discovery_evidence = load_model_discovery_run(discovery_run)
        qualification_policy = load_qualification_policy(policy)
        benchmark_suite = load_model_benchmark_corpus(
            corpus,
            ground_truth_path=ground_truth,
        )
        _require_qualification_release_pins(
            config=config,
            policy=qualification_policy,
            benchmark_suite=benchmark_suite,
        )
        benchmark_portfolio, reports = load_model_benchmark_portfolio(
            portfolio,
            candidate_registry=registry,
            corpus=benchmark_suite,
        )
        _require_real_qualification_portfolio(
            benchmark_portfolio,
            policy=qualification_policy,
        )
        bindings = load_qualification_release_bindings(release_bindings)
        _verify_qualification_campaign(
            config=config,
            campaign_journal=campaign_journal,
            cost_ledger=cost_ledger,
            portfolio=benchmark_portfolio,
            reports=reports,
            registry=registry,
            benchmark_suite=benchmark_suite,
            qualification_policy=qualification_policy,
        )
        trusted_campaign_verification = None
        expiry = _parse_qualification_timestamp(qualification_expires_at)
        # Persisted campaign JSON can be checked structurally, but cannot
        # recreate the process-local authority over original provider content.
        trusted_generation_verification = (
            await _refetch_qualification_generations(
                config=config,
                secrets_env_file=secrets_env_file,
                registry=registry,
                reports=reports,
            )
            if trusted_campaign_verification is not None
            else None
        )
        trusted_release_observation = _observe_qualification_release(
            config=config,
            release_bindings=bindings,
            release_source_root=release_source_root,
        )
        evaluated_at = trusted_release_observation.observed_at
        bundle = run_qualification_workflow(
            candidate_registry=registry,
            discovery_run_manifest=discovery_manifest,
            discovery_evidence=discovery_evidence,
            policy=qualification_policy,
            benchmark_suite=benchmark_suite,
            benchmark_portfolio=benchmark_portfolio,
            benchmark_reports=reports,
            release_bindings=bindings,
            trusted_campaign_verification=trusted_campaign_verification,
            trusted_generation_verification=trusted_generation_verification,
            trusted_release_observation=trusted_release_observation,
            evaluated_at=evaluated_at,
            qualification_expires_at=expiry,
        )
        write_qualification_workflow_bundle(output, bundle)
        _print_qualification_summary(bundle, local_console)
        if not bundle.qualification_verification.production_selection_ready:
            raise typer.Exit(ExitCode.INCOMPLETE)

    _run_async_cli(execute)


@models_app.command("verify-qualification")
def models_verify_qualification(
    config_path: ConfigOption,
    bundle_path: Annotated[
        Path,
        typer.Option("--bundle", help="Private mode-0600 qualification bundle."),
    ],
    candidate_registry: Annotated[
        Path,
        typer.Option(
            "--candidate-registry",
            help="Original self-hashed candidate-registry TOML.",
        ),
    ],
    discovery_run: Annotated[
        Path,
        typer.Option(
            "--discovery-run",
            help="Original complete private REAL discovery-run directory.",
        ),
    ],
    policy: Annotated[
        Path,
        typer.Option("--policy", help="Original qualification-policy TOML."),
    ],
    corpus: Annotated[
        Path,
        typer.Option("--corpus", help="Original blinded benchmark corpus."),
    ],
    ground_truth: Annotated[
        Path,
        typer.Option(
            "--ground-truth",
            help="Original separately sealed private benchmark ground truth.",
        ),
    ],
    portfolio: Annotated[
        Path,
        typer.Option(
            "--portfolio",
            help="Original atomic private model-benchmark portfolio directory.",
        ),
    ],
    campaign_journal: Annotated[
        Path,
        typer.Option(
            "--campaign-journal",
            help="Original complete private candidate-benchmark campaign journal.",
        ),
    ],
    release_bindings: Annotated[
        Path,
        typer.Option(
            "--release-bindings",
            help="Original self-hashed release bindings JSON.",
        ),
    ],
    release_source_root: Annotated[
        Path,
        typer.Option(
            "--release-source-root",
            help="Clean Git root containing the exact executing mmaudit release.",
        ),
    ],
    cost_ledger: Annotated[
        Path | None,
        typer.Option(
            "--cost-ledger",
            help="Existing atomic cost ledger bound to the campaign.",
        ),
    ] = None,
    secrets_env_file: SecretsEnvFileOption = None,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Re-fetch provider evidence and reproduce the frozen qualification bundle."""

    async def execute() -> None:
        local_console = Console(no_color=no_color)
        config = load_config(config_path)
        frozen = load_qualification_workflow_bundle(bundle_path)
        registry = load_candidate_registry(candidate_registry)
        discovery_manifest, discovery_evidence = load_model_discovery_run(discovery_run)
        qualification_policy = load_qualification_policy(policy)
        benchmark_suite = load_model_benchmark_corpus(
            corpus,
            ground_truth_path=ground_truth,
        )
        _require_qualification_release_pins(
            config=config,
            policy=qualification_policy,
            benchmark_suite=benchmark_suite,
        )
        benchmark_portfolio, reports = load_model_benchmark_portfolio(
            portfolio,
            candidate_registry=registry,
            corpus=benchmark_suite,
        )
        _require_real_qualification_portfolio(
            benchmark_portfolio,
            policy=qualification_policy,
        )
        bindings = load_qualification_release_bindings(release_bindings)
        _verify_qualification_campaign(
            config=config,
            campaign_journal=campaign_journal,
            cost_ledger=cost_ledger,
            portfolio=benchmark_portfolio,
            reports=reports,
            registry=registry,
            benchmark_suite=benchmark_suite,
            qualification_policy=qualification_policy,
        )
        trusted_campaign_verification = None
        trusted_generation_verification = (
            await _refetch_qualification_generations(
                config=config,
                secrets_env_file=secrets_env_file,
                registry=registry,
                reports=reports,
            )
            if trusted_campaign_verification is not None
            else None
        )
        trusted_release_observation = _observe_qualification_release(
            config=config,
            release_bindings=bindings,
            release_source_root=release_source_root,
        )
        recomputed = run_qualification_workflow(
            candidate_registry=registry,
            discovery_run_manifest=discovery_manifest,
            discovery_evidence=discovery_evidence,
            policy=qualification_policy,
            benchmark_suite=benchmark_suite,
            benchmark_portfolio=benchmark_portfolio,
            benchmark_reports=reports,
            release_bindings=bindings,
            trusted_campaign_verification=trusted_campaign_verification,
            trusted_generation_verification=trusted_generation_verification,
            trusted_release_observation=trusted_release_observation,
            evaluated_at=trusted_release_observation.observed_at,
            qualification_expires_at=frozen.qualification_expires_at,
        )
        if _qualification_semantic_view(recomputed) != _qualification_semantic_view(frozen):
            raise ValueError(
                "qualification bundle differs from authenticated semantic recomputation"
            )
        verified_at = trusted_release_observation.observed_at
        current = verify_model_qualification(
            artifact=frozen.qualification_artifact,
            registry=frozen.updated_registry,
            policy=qualification_policy,
            expected_bindings=recomputed.qualification_artifact.bindings,
            trusted_benchmark_evidence=frozen.trusted_benchmark_evidence,
            now=verified_at,
        )
        if frozen.qualification_expires_at <= verified_at:
            raise ValueError("qualification bundle is stale")
        _print_qualification_summary(frozen, local_console)
        if not current.production_selection_ready:
            raise typer.Exit(ExitCode.INCOMPLETE)

    _run_async_cli(execute)


@models_app.command("init-cost-ledger")
def models_init_cost_ledger(
    cost_ledger: Annotated[
        Path,
        typer.Option(
            "--cost-ledger",
            help="New absolute path for the cumulative paid-provider cost ledger.",
        ),
    ],
    config_path: ConfigOption = Path(DEFAULT_CONFIG_NAME),
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Initialize one cumulative paid-provider ledger exactly once."""

    try:
        config = load_config(config_path)
        AtomicCostLedger.initialize(
            cost_ledger,
            cap_usd=Decimal(str(config.execution.budget_usd)),
        )
    except (ConfigError, CostLedgerError, OSError, ValueError) as exc:
        Console(no_color=no_color).print(f"[red]mmaudit failed safely:[/red] {exc}")
        raise typer.Exit(ExitCode.CONFIGURATION) from exc
    Console(no_color=no_color).print(
        "[green]Initialized cumulative paid-provider cost ledger.[/green]"
    )


@app.command("scan")
def scan_command(
    config_path: ConfigOption = Path(DEFAULT_CONFIG_NAME),
    secrets_env_file: SecretsEnvFileOption = None,
    repo: Annotated[Path | None, typer.Option("--repo")] = None,
    output: Annotated[Path | None, typer.Option("--output")] = None,
    skip_codeql: Annotated[bool, typer.Option("--skip-codeql")] = False,
    fail_on: Annotated[Severity | None, typer.Option("--fail-on")] = None,
    changed_since: Annotated[str | None, typer.Option("--changed-since")] = None,
    profile: Annotated[
        AuditProfile | None,
        typer.Option(
            "--profile",
            help=("Assurance-depth override; maximum-assurance is valid only with solidity-evm."),
        ),
    ] = None,
    language_profile: Annotated[
        LanguageCapabilityProfile | None,
        typer.Option(
            "--language-profile",
            "--capability-profile",
            help=(
                "solidity-evm enables the EVM portfolio; generic-source-review is reduced "
                "and cannot claim EVM maximum assurance."
            ),
        ),
    ] = None,
    scope: Annotated[
        AuditScope | None,
        typer.Option("--scope", help="Requested audit scope override."),
    ] = None,
    require_complete_scope: Annotated[
        bool | None,
        typer.Option("--require-complete-scope/--allow-incomplete-scope"),
    ] = None,
    require_maximum_assurance: Annotated[
        bool,
        typer.Option(
            "--require-maximum-assurance",
            help=(
                "Require every Solidity/EVM maximum-assurance clause; incompatible with "
                "generic-source-review."
            ),
        ),
    ] = False,
    allow_maximum_assurance_downgrade: Annotated[
        bool,
        typer.Option(
            "--allow-maximum-assurance-downgrade",
            help="Continue with a visibly DOWNGRADED result when maximum gates cannot pass.",
        ),
    ] = False,
    min_model_families: Annotated[
        int | None,
        typer.Option("--min-model-families", min=3, max=32),
    ] = None,
    min_specialist_agents: Annotated[
        int | None,
        typer.Option("--min-specialist-agents", min=1, max=64),
    ] = None,
    require_reproduction_for_critical: Annotated[
        bool | None,
        typer.Option("--require-reproduction-for-critical/--no-require-reproduction-for-critical"),
    ] = None,
    require_formal_or_reproduction_for_confirmed_critical: Annotated[
        bool | None,
        typer.Option(
            "--require-formal-or-reproduction-for-confirmed-critical/"
            "--no-require-formal-or-reproduction-for-confirmed-critical"
        ),
    ] = None,
    benchmark_gate: Annotated[
        bool,
        typer.Option(
            "--benchmark-gate",
            help="Require a current component-bound benchmark certificate.",
        ),
    ] = False,
    benchmark_certificate: Annotated[
        Path | None,
        typer.Option("--benchmark-certificate", help="Sealed benchmark certificate."),
    ] = None,
    benchmark_component_root: Annotated[
        Path | None,
        typer.Option(
            "--benchmark-component-root",
            help="Local root containing the certificate-bound component files.",
        ),
    ] = None,
    benchmark_repository_commit: Annotated[
        str | None,
        typer.Option(
            "--benchmark-repository-commit",
            help="Currently observed full lowercase Git commit.",
        ),
    ] = None,
    solidity: Annotated[
        bool | None,
        typer.Option(
            "--solidity/--no-solidity",
            help=(
                "Control Solidity discovery within the selected capability; this does not "
                "authorize generic review."
            ),
        ),
    ] = None,
    compile_solidity: Annotated[
        bool | None,
        typer.Option(
            "--compile/--no-compile", help="Opt in or out of isolated Solidity compilation."
        ),
    ] = None,
    run_slither: Annotated[
        bool,
        typer.Option(
            "--run-slither",
            help="Run isolated Slither with the configured hash-pinned Solidity compiler.",
        ),
    ] = False,
    allow_network: Annotated[
        bool,
        typer.Option(
            "--allow-network", help="Permit network access for Solidity compilation tools."
        ),
    ] = False,
    framework: Annotated[
        Literal["auto", "foundry", "hardhat", "mixed", "plain"] | None,
        typer.Option("--framework", help="Solidity framework override."),
    ] = None,
    project_root: Annotated[
        str | None,
        typer.Option("--project-root", help="Repository-relative Solidity project root."),
    ] = None,
    allow_fork_probing: Annotated[
        bool,
        typer.Option("--allow-fork-probing", "--allow-fork"),
    ] = False,
    fork_rpc_url_env: Annotated[
        str | None,
        typer.Option(
            "--fork-rpc-url-env",
            help="Environment variable name containing the fork RPC URL.",
        ),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose")] = False,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Run applicable deterministic scanners under an explicit capability profile."""

    _execute_audit(
        config_path=config_path,
        secrets_env_file=secrets_env_file,
        repo=repo,
        output=output,
        budget_usd=None,
        cost_ledger=None,
        model_qualification_bundle=None,
        model_qualification_policy=None,
        model_qualification_release_bindings=None,
        model_qualification_release_source_root=None,
        model_qualification_corpus=None,
        model_qualification_ground_truth=None,
        max_files=None,
        max_file_bytes=None,
        max_context_bytes=None,
        concurrency=None,
        severity_threshold=Severity.INFORMATIONAL,
        fail_on=fail_on,
        scanner_only=True,
        skip_codeql=skip_codeql,
        allow_code_egress=False,
        require_zdr=False,
        privacy_profile=None,
        retention_consent=None,
        privacy_source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        profile=profile,
        language_profile=language_profile,
        scope=scope,
        require_complete_scope=require_complete_scope,
        require_maximum_assurance=require_maximum_assurance,
        allow_maximum_assurance_downgrade=allow_maximum_assurance_downgrade,
        min_model_families=min_model_families,
        min_specialist_agents=min_specialist_agents,
        require_reproduction_for_critical=require_reproduction_for_critical,
        require_formal_or_reproduction_for_confirmed_critical=(
            require_formal_or_reproduction_for_confirmed_critical
        ),
        benchmark_gate=benchmark_gate,
        benchmark_certificate=benchmark_certificate,
        benchmark_component_root=benchmark_component_root,
        benchmark_repository_commit=benchmark_repository_commit,
        solidity=solidity,
        compile_solidity=compile_solidity,
        run_slither=run_slither,
        allow_network=allow_network,
        framework=framework,
        project_root=project_root,
        changed_since=changed_since,
        allow_fork_probing=allow_fork_probing,
        fork_rpc_url_env=fork_rpc_url_env,
        verbose=verbose,
        no_color=no_color,
    )


@app.command("ci")
def ci_command(
    config_path: ConfigOption = Path(DEFAULT_CONFIG_NAME),
    repo: Annotated[Path | None, typer.Option("--repo")] = None,
    output: Annotated[Path | None, typer.Option("--output")] = None,
    changed_since: Annotated[
        str | None,
        typer.Option(
            "--changed-since",
            help="Exact trusted comparison revision used only for prioritization.",
        ),
    ] = None,
    baseline_run: Annotated[
        Path | None,
        typer.Option(
            "--baseline-run",
            help="Absolute manifest-bound three-file CI baseline bundle for comparison.",
        ),
    ] = None,
    skip_codeql: Annotated[bool, typer.Option("--skip-codeql")] = False,
    fail_on: Annotated[Severity | None, typer.Option("--fail-on")] = Severity.HIGH,
    verbose: Annotated[bool, typer.Option("--verbose")] = False,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Run provider-free deterministic pull-request analysis with fail-closed suites."""

    if changed_since is None:
        Console(no_color=no_color).print(
            "[red]mmaudit failed safely:[/red] CI requires --changed-since."
        )
        raise typer.Exit(ExitCode.CONFIGURATION)
    _execute_audit(
        config_path=config_path,
        secrets_env_file=None,
        repo=repo,
        output=output,
        budget_usd=None,
        cost_ledger=None,
        model_qualification_bundle=None,
        model_qualification_policy=None,
        model_qualification_release_bindings=None,
        model_qualification_release_source_root=None,
        model_qualification_corpus=None,
        model_qualification_ground_truth=None,
        max_files=None,
        max_file_bytes=None,
        max_context_bytes=None,
        concurrency=None,
        severity_threshold=Severity.INFORMATIONAL,
        fail_on=fail_on,
        scanner_only=True,
        skip_codeql=skip_codeql,
        allow_code_egress=False,
        require_zdr=False,
        privacy_profile=None,
        retention_consent=None,
        privacy_source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        profile=None,
        language_profile=LanguageCapabilityProfile.SOLIDITY_EVM,
        scope=None,
        require_complete_scope=None,
        require_maximum_assurance=False,
        allow_maximum_assurance_downgrade=False,
        min_model_families=None,
        min_specialist_agents=None,
        require_reproduction_for_critical=None,
        require_formal_or_reproduction_for_confirmed_critical=None,
        benchmark_gate=False,
        benchmark_certificate=None,
        benchmark_component_root=None,
        benchmark_repository_commit=None,
        solidity=True,
        compile_solidity=True,
        run_slither=True,
        allow_network=False,
        framework=None,
        project_root=None,
        allow_fork_probing=True,
        fork_rpc_url_env=None,
        changed_since=changed_since,
        verbose=verbose,
        no_color=no_color,
        ci_mode=True,
        ci_baseline_run=baseline_run,
    )


@app.command("run")
def run_command(
    config_path: ConfigOption = Path(DEFAULT_CONFIG_NAME),
    secrets_env_file: SecretsEnvFileOption = None,
    repo: Annotated[Path | None, typer.Option("--repo")] = None,
    output: Annotated[Path | None, typer.Option("--output")] = None,
    budget_usd: Annotated[float | None, typer.Option("--budget-usd", min=0.01)] = None,
    cost_ledger: Annotated[
        Path | None,
        typer.Option(
            "--cost-ledger",
            help="Existing operator-controlled cumulative paid-provider ledger.",
        ),
    ] = None,
    model_qualification_bundle: Annotated[
        Path | None,
        typer.Option(
            "--model-qualification-bundle",
            help="Private verified model-qualification workflow bundle.",
        ),
    ] = None,
    model_qualification_policy: Annotated[
        Path | None,
        typer.Option(
            "--model-qualification-policy",
            help="Original self-hashed production qualification policy.",
        ),
    ] = None,
    model_qualification_release_bindings: Annotated[
        Path | None,
        typer.Option(
            "--model-qualification-release-bindings",
            help="Current self-hashed qualification release bindings.",
        ),
    ] = None,
    model_qualification_release_source_root: Annotated[
        Path | None,
        typer.Option(
            "--model-qualification-release-source-root",
            help="Clean Git root containing the exact executing mmaudit release.",
        ),
    ] = None,
    model_qualification_corpus: Annotated[
        Path | None,
        typer.Option(
            "--model-qualification-corpus",
            help="Original provider-visible model qualification corpus.",
        ),
    ] = None,
    model_qualification_ground_truth: Annotated[
        Path | None,
        typer.Option(
            "--model-qualification-ground-truth",
            help="Original separately sealed model qualification ground truth.",
        ),
    ] = None,
    max_files: Annotated[int | None, typer.Option("--max-files", min=1)] = None,
    max_file_bytes: Annotated[int | None, typer.Option("--max-file-bytes", min=1)] = None,
    max_context_bytes: Annotated[int | None, typer.Option("--max-context-bytes", min=1)] = None,
    concurrency: Annotated[int | None, typer.Option("--concurrency", min=1, max=16)] = None,
    severity_threshold: Annotated[
        Severity, typer.Option("--severity-threshold")
    ] = Severity.INFORMATIONAL,
    fail_on: Annotated[Severity | None, typer.Option("--fail-on")] = None,
    scanner_only: Annotated[bool, typer.Option("--scanner-only")] = False,
    skip_codeql: Annotated[bool, typer.Option("--skip-codeql")] = False,
    allow_code_egress: Annotated[bool, typer.Option("--allow-code-egress")] = False,
    require_zdr: Annotated[bool, typer.Option("--require-zdr")] = False,
    privacy_profile: Annotated[
        PrivacyProfile | None,
        typer.Option(
            "--privacy-profile",
            help="Explicit privacy profile for this invocation.",
        ),
    ] = None,
    retention_consent: Annotated[
        Path | None,
        typer.Option(
            "--retention-consent",
            help="Operator-authored privacy consent outside the audited repository.",
        ),
    ] = None,
    privacy_source_classification: Annotated[
        PrivacySourceClassification,
        typer.Option(
            "--privacy-source-classification",
            help="Operator-declared source class bound into privacy authorization.",
        ),
    ] = PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
    profile: Annotated[
        AuditProfile | None,
        typer.Option(
            "--profile",
            help=("Assurance-depth override; maximum-assurance is valid only with solidity-evm."),
        ),
    ] = None,
    language_profile: Annotated[
        LanguageCapabilityProfile | None,
        typer.Option(
            "--language-profile",
            "--capability-profile",
            help=(
                "solidity-evm enables the EVM portfolio; generic-source-review is reduced "
                "and cannot claim EVM maximum assurance."
            ),
        ),
    ] = None,
    scope: Annotated[
        AuditScope | None,
        typer.Option("--scope", help="Requested audit scope override."),
    ] = None,
    require_complete_scope: Annotated[
        bool | None,
        typer.Option("--require-complete-scope/--allow-incomplete-scope"),
    ] = None,
    require_maximum_assurance: Annotated[
        bool,
        typer.Option(
            "--require-maximum-assurance",
            help=(
                "Require every Solidity/EVM maximum-assurance clause; incompatible with "
                "generic-source-review."
            ),
        ),
    ] = False,
    allow_maximum_assurance_downgrade: Annotated[
        bool,
        typer.Option(
            "--allow-maximum-assurance-downgrade",
            help="Continue with a visibly DOWNGRADED result when maximum gates cannot pass.",
        ),
    ] = False,
    min_model_families: Annotated[
        int | None,
        typer.Option("--min-model-families", min=3, max=32),
    ] = None,
    min_specialist_agents: Annotated[
        int | None,
        typer.Option("--min-specialist-agents", min=1, max=64),
    ] = None,
    require_reproduction_for_critical: Annotated[
        bool | None,
        typer.Option("--require-reproduction-for-critical/--no-require-reproduction-for-critical"),
    ] = None,
    require_formal_or_reproduction_for_confirmed_critical: Annotated[
        bool | None,
        typer.Option(
            "--require-formal-or-reproduction-for-confirmed-critical/"
            "--no-require-formal-or-reproduction-for-confirmed-critical"
        ),
    ] = None,
    benchmark_gate: Annotated[
        bool,
        typer.Option(
            "--benchmark-gate",
            help="Require a current component-bound benchmark certificate.",
        ),
    ] = False,
    benchmark_certificate: Annotated[
        Path | None,
        typer.Option("--benchmark-certificate", help="Sealed benchmark certificate."),
    ] = None,
    benchmark_component_root: Annotated[
        Path | None,
        typer.Option(
            "--benchmark-component-root",
            help="Local root containing the certificate-bound component files.",
        ),
    ] = None,
    benchmark_repository_commit: Annotated[
        str | None,
        typer.Option(
            "--benchmark-repository-commit",
            help="Currently observed full lowercase Git commit.",
        ),
    ] = None,
    solidity: Annotated[
        bool | None,
        typer.Option(
            "--solidity/--no-solidity",
            help=(
                "Control Solidity discovery within the selected capability; this does not "
                "authorize generic review."
            ),
        ),
    ] = None,
    compile_solidity: Annotated[
        bool | None,
        typer.Option(
            "--compile/--no-compile", help="Opt in or out of isolated Solidity compilation."
        ),
    ] = None,
    run_slither: Annotated[
        bool,
        typer.Option(
            "--run-slither",
            help="Run isolated Slither with the configured hash-pinned Solidity compiler.",
        ),
    ] = False,
    allow_network: Annotated[
        bool,
        typer.Option(
            "--allow-network", help="Permit network access for Solidity compilation tools."
        ),
    ] = False,
    framework: Annotated[
        Literal["auto", "foundry", "hardhat", "mixed", "plain"] | None,
        typer.Option("--framework", help="Solidity framework override."),
    ] = None,
    project_root: Annotated[
        str | None,
        typer.Option("--project-root", help="Repository-relative Solidity project root."),
    ] = None,
    allow_fork_probing: Annotated[
        bool,
        typer.Option("--allow-fork-probing", "--allow-fork"),
    ] = False,
    fork_rpc_url_env: Annotated[
        str | None,
        typer.Option(
            "--fork-rpc-url-env",
            help="Environment variable name containing the fork RPC URL.",
        ),
    ] = None,
    changed_since: Annotated[str | None, typer.Option("--changed-since")] = None,
    verbose: Annotated[bool, typer.Option("--verbose")] = False,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Run Solidity/EVM assurance or explicitly reduced generic source review."""

    _execute_audit(
        config_path=config_path,
        secrets_env_file=secrets_env_file,
        repo=repo,
        output=output,
        budget_usd=budget_usd,
        cost_ledger=cost_ledger,
        model_qualification_bundle=model_qualification_bundle,
        model_qualification_policy=model_qualification_policy,
        model_qualification_release_bindings=model_qualification_release_bindings,
        model_qualification_release_source_root=model_qualification_release_source_root,
        model_qualification_corpus=model_qualification_corpus,
        model_qualification_ground_truth=model_qualification_ground_truth,
        max_files=max_files,
        max_file_bytes=max_file_bytes,
        max_context_bytes=max_context_bytes,
        concurrency=concurrency,
        severity_threshold=severity_threshold,
        fail_on=fail_on,
        scanner_only=scanner_only,
        skip_codeql=skip_codeql,
        allow_code_egress=allow_code_egress,
        require_zdr=require_zdr,
        privacy_profile=privacy_profile,
        retention_consent=retention_consent,
        privacy_source_classification=privacy_source_classification,
        profile=profile,
        language_profile=language_profile,
        scope=scope,
        require_complete_scope=require_complete_scope,
        require_maximum_assurance=require_maximum_assurance,
        allow_maximum_assurance_downgrade=allow_maximum_assurance_downgrade,
        min_model_families=min_model_families,
        min_specialist_agents=min_specialist_agents,
        require_reproduction_for_critical=require_reproduction_for_critical,
        require_formal_or_reproduction_for_confirmed_critical=(
            require_formal_or_reproduction_for_confirmed_critical
        ),
        benchmark_gate=benchmark_gate,
        benchmark_certificate=benchmark_certificate,
        benchmark_component_root=benchmark_component_root,
        benchmark_repository_commit=benchmark_repository_commit,
        solidity=solidity,
        compile_solidity=compile_solidity,
        run_slither=run_slither,
        allow_network=allow_network,
        framework=framework,
        project_root=project_root,
        allow_fork_probing=allow_fork_probing,
        fork_rpc_url_env=fork_rpc_url_env,
        changed_since=changed_since,
        verbose=verbose,
        no_color=no_color,
    )


@app.command("explain")
def explain_command(
    finding_id: Annotated[str, typer.Argument(help="Stable finding ID.")],
    output: Annotated[
        Path,
        typer.Option("--output", help="mmaudit output root."),
    ] = Path(".mmaudit"),
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Display evidence, votes, validation, and rejection rationale."""

    report_path = output.resolve() / "latest" / "final-findings.json"
    try:
        report_path.resolve(strict=True).relative_to(output.resolve(strict=True))
    except (OSError, ValueError) as exc:
        Console(no_color=no_color).print(
            "[red]Latest report path escaped the output directory.[/red]"
        )
        raise typer.Exit(ExitCode.CONFIGURATION) from exc
    try:
        report = AuditReport.model_validate_json(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        Console(no_color=no_color).print(f"[red]Cannot read latest report:[/red] {exc}")
        raise typer.Exit(ExitCode.CONFIGURATION) from exc
    finding = next(
        (item for item in [*report.findings, *report.rejected_findings] if item.id == finding_id),
        None,
    )
    if finding is None:
        Console(no_color=no_color).print(f"[red]Finding not found:[/red] {finding_id}")
        raise typer.Exit(ExitCode.CONFIGURATION)
    _print_finding(finding, Console(no_color=no_color))


def _format_optional_rate(value: float | None) -> str:
    return f"{value:.1%}" if value is not None else BenchmarkMetricState.NOT_EVALUABLE.value


@benchmark_app.callback(invoke_without_command=True)
def benchmark_command(
    ctx: typer.Context,
    corpus: Annotated[
        Path,
        typer.Option(
            "--corpus",
            help="Benchmark manifest JSON.",
        ),
    ] = DEFAULT_BENCHMARK_MANIFEST,
    reports: Annotated[
        Path | None,
        typer.Option(
            "--reports",
            help=(
                "Directory containing <repository-id>/final-findings.json or "
                "<repository-id>.json reports."
            ),
        ),
    ] = None,
    ground_truth_root: Annotated[
        Path,
        typer.Option(
            "--ground-truth-root",
            help="Local root used to verify corpus-bound synthetic fixture sources.",
        ),
    ] = Path("."),
    profile: Annotated[
        AuditProfile,
        typer.Option("--profile", help="Profile whose reports are being evaluated."),
    ] = AuditProfile.STANDARD,
    mutation_scorecard: Annotated[
        Path | None,
        typer.Option(
            "--mutation-scorecard",
            help="Typed per-property mutation scorecard JSON.",
        ),
    ] = None,
    human_comparison: Annotated[
        Path | None,
        typer.Option(
            "--human-comparison",
            help="Self-hashed blinded human-comparison evidence for the claim gate.",
        ),
    ] = None,
    output_json: Annotated[
        Path,
        typer.Option("--output-json", help="Machine-readable benchmark result."),
    ] = Path("benchmark-results.json"),
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Evaluate actual audit reports against the explicit benchmark corpus."""

    if ctx.invoked_subcommand is not None:
        return
    local_console = Console(no_color=no_color)
    try:
        manifest = load_manifest(corpus.resolve())
        ground_truth_bindings = validate_benchmark_ground_truth(
            manifest,
            workspace_root=ground_truth_root,
        )
        repository_ids = {case.repository_id for case in manifest.cases}
        if reports is None:
            loaded: dict[str, AuditReport] = {}
            report_inputs = None
            limitations = [
                "no audit-report directory supplied; corpus validated but no audit quality "
                "measurement was performed"
            ]
        else:
            loaded, report_inputs, limitations = load_reports(
                reports,
                repository_ids,
                profile=profile,
            )
        benchmark = evaluate_benchmark(
            manifest,
            loaded,
            profile=profile,
            report_inputs=report_inputs,
            initial_limitations=limitations,
            mutation_scorecard=(
                load_mutation_scorecard(mutation_scorecard)
                if mutation_scorecard is not None
                else None
            ),
            superiority_evidence=(
                load_human_comparison_evidence(human_comparison)
                if human_comparison is not None
                else None
            ),
        )
        if output_json.is_symlink():
            raise ValueError("benchmark output may not be a symlink")
        write_benchmark_report(output_json.resolve(), benchmark)
    except (OSError, ValueError) as exc:
        local_console.print(f"[red]Benchmark failed safely:[/red] {exc}")
        raise typer.Exit(ExitCode.CONFIGURATION) from exc
    local_console.print(
        f"Benchmark {benchmark.status.value}: "
        f"recall={_format_optional_rate(benchmark.recall)}, "
        f"critical_recall={_format_optional_rate(benchmark.critical_recall)}, "
        f"safe_false_confirmations={benchmark.safe_high_critical_confirmations}"
    )
    local_console.print(f"Ground truth: {len(ground_truth_bindings)} source binding(s) verified")
    local_console.print(f"Superiority claim: {benchmark.superiority_claim.status.value}")
    local_console.print(f"Result: {output_json.resolve()}")
    if benchmark.status is BenchmarkStatus.INCOMPLETE:
        raise typer.Exit(ExitCode.INCOMPLETE)
    if benchmark.status is BenchmarkStatus.FAILED:
        raise typer.Exit(ExitCode.FINDINGS)


@benchmark_app.command("certify")
def benchmark_certify_command(
    component_root: Annotated[
        Path,
        typer.Option(
            "--component-root",
            help="Non-link local root containing every certificate input file.",
        ),
    ],
    inputs: Annotated[
        Path,
        typer.Option(
            "--inputs",
            help="Typed sorted relative-path manifest for all binding categories.",
        ),
    ],
    repository_commit: Annotated[
        str,
        typer.Option(
            "--repository-commit",
            help="Full lowercase Git commit being certified.",
        ),
    ],
    certificate_id: Annotated[
        str,
        typer.Option("--certificate-id", help="Stable certificate identifier."),
    ] = "benchmark-certificate",
    output: Annotated[
        Path,
        typer.Option("--output", help="Destination for the sealed certificate."),
    ] = Path("benchmark-certificate.json"),
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Seal a passed benchmark report and every declared local component file."""

    local_console = Console(no_color=no_color)
    try:
        file_inputs = load_benchmark_certificate_file_inputs(inputs)
        certificate = build_file_backed_benchmark_certificate(
            component_root=component_root,
            inputs=file_inputs,
            repository_git_commit=repository_commit,
            certificate_id=certificate_id,
        )
        write_benchmark_certificate(output, certificate)
    except (OSError, ValueError) as exc:
        local_console.print(f"[red]Benchmark certification failed safely:[/red] {exc}")
        raise typer.Exit(ExitCode.CONFIGURATION) from exc
    local_console.print(f"Benchmark certificate created: {certificate.certificate_sha256}")
    local_console.print(f"Result: {output.resolve()}")


@app.command("verify-certificate")
def verify_certificate_command(
    certificate_path: Annotated[
        Path,
        typer.Option("--certificate", help="Sealed benchmark certificate."),
    ],
    component_root: Annotated[
        Path,
        typer.Option(
            "--component-root",
            help="Non-link local root containing the currently observed component files.",
        ),
    ],
    repository_commit: Annotated[
        str,
        typer.Option(
            "--repository-commit",
            help="Currently observed full lowercase Git commit.",
        ),
    ],
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            help="Destination for sanitized certificate-verification evidence.",
        ),
    ] = Path("benchmark-certificate-verification.json"),
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Re-hash local files and reject any certificate whose bindings are stale."""

    local_console = Console(no_color=no_color)
    try:
        verification = verify_file_backed_benchmark_certificate(
            certificate_path,
            component_root=component_root,
            repository_git_commit=repository_commit,
        )
        write_benchmark_certificate_verification(output, verification)
    except (OSError, ValueError) as exc:
        local_console.print(f"[red]Benchmark certificate verification failed safely:[/red] {exc}")
        raise typer.Exit(ExitCode.CONFIGURATION) from exc
    local_console.print(
        f"Benchmark certificate {verification.status.value}: "
        f"{len(verification.mismatches)} mismatch(es)"
    )
    local_console.print(f"Result: {output.resolve()}")
    if verification.status is CertificateVerificationStatus.STALE:
        raise typer.Exit(ExitCode.INCOMPLETE)


@app.command("verify-run")
def verify_run_command(
    manifest: Annotated[
        Path,
        typer.Option("--manifest", help="Self-hashed run evidence manifest."),
    ],
    run_dir: Annotated[
        Path,
        typer.Option("--run-dir", help="Local completed run directory to verify."),
    ],
    repository: Annotated[
        Path,
        typer.Option("--repo", help="Local source repository bound by the run."),
    ] = Path("."),
    config_path: Annotated[
        Path | None,
        typer.Option(
            "--config",
            help="Optional current base config; recorded safe overrides are replayed.",
        ),
    ] = None,
    output: Annotated[
        Path,
        typer.Option("--output", help="Destination for normalized verification evidence."),
    ] = Path("run-verification.json"),
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Verify run sources, projections, artifacts, and certificates without execution."""

    local_console = Console(no_color=no_color)
    try:
        sealed_manifest = load_run_evidence_manifest(manifest)
        legacy_config, current_file_config = _verification_config_inputs(
            sealed_manifest=sealed_manifest,
            config_path=config_path,
        )
        verification = verify_run_evidence(
            manifest_path=manifest,
            run_dir=run_dir,
            repository_root=repository,
            config=legacy_config,
            file_config=current_file_config,
        )
        write_run_verification(output, verification)
    except (OSError, ValueError) as exc:
        local_console.print(f"[red]Run verification failed safely:[/red] {exc}")
        raise typer.Exit(ExitCode.CONFIGURATION) from exc
    local_console.print(
        f"Run verification {verification.status.value}: {len(verification.mismatches)} mismatch(es)"
    )
    local_console.print(f"Result: {output.resolve()}")
    if verification.status is RunVerificationStatus.STALE:
        raise typer.Exit(ExitCode.INCOMPLETE)


@app.command("export-forensic")
def export_forensic_command(
    run_dir: Annotated[
        Path,
        typer.Option("--run-dir", help="Exact local manifest-bound run directory."),
    ],
    destination: Annotated[
        Path,
        typer.Option(
            "--destination",
            help="Fresh wrapper directory; its parent must already exist.",
        ),
    ],
    acknowledge_sensitive_evidence: Annotated[
        bool,
        typer.Option(
            "--acknowledge-sensitive-evidence",
            help="Acknowledge that private and log evidence will be copied exactly.",
        ),
    ] = False,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Export a complete local forensic run without executing or sanitizing its evidence."""

    local_console = Console(no_color=no_color)
    try:
        descriptor = export_complete_forensic_bundle(
            source_run=run_dir,
            destination=destination,
            acknowledge_sensitive_evidence=acknowledge_sensitive_evidence,
        )
    except (OSError, ValueError) as exc:
        local_console.print(f"[red]Forensic export failed safely:[/red] {exc}")
        raise typer.Exit(ExitCode.CONFIGURATION) from exc
    local_console.print(
        "Complete forensic bundle exported: "
        f"{descriptor.artifact_count} file(s), {descriptor.artifact_total_bytes} byte(s)"
    )
    local_console.print(f"Result: {destination.resolve()}")


@app.command("verify-forensic-export")
def verify_forensic_export_command(
    bundle: Annotated[
        Path,
        typer.Option("--bundle", help="Complete forensic wrapper directory to verify."),
    ],
    acknowledge_sensitive_evidence: Annotated[
        bool,
        typer.Option(
            "--acknowledge-sensitive-evidence",
            help="Acknowledge that private and log evidence will be read for hashing.",
        ),
    ] = False,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Verify a complete forensic wrapper independently of its original run."""

    local_console = Console(no_color=no_color)
    try:
        descriptor = verify_complete_forensic_bundle(
            delivery_root=bundle,
            acknowledge_sensitive_evidence=acknowledge_sensitive_evidence,
        )
    except (OSError, ValueError) as exc:
        local_console.print(f"[red]Forensic verification failed safely:[/red] {exc}")
        raise typer.Exit(ExitCode.CONFIGURATION) from exc
    local_console.print(
        "Complete forensic bundle verified: "
        f"{descriptor.artifact_count} file(s), {descriptor.artifact_total_bytes} byte(s)"
    )
    local_console.print(f"Result: {bundle.resolve()}")


@app.command("replay")
def replay_command(
    manifest: Annotated[
        Path,
        typer.Option("--manifest", help="Self-hashed run evidence manifest."),
    ],
    run_dir: Annotated[
        Path,
        typer.Option("--run-dir", help="Local completed run directory to replay."),
    ],
    repository: Annotated[
        Path,
        typer.Option("--repo", help="Local source repository bound by the run."),
    ] = Path("."),
    config_path: Annotated[
        Path | None,
        typer.Option(
            "--config",
            help="Optional current base config; recorded safe overrides are replayed.",
        ),
    ] = None,
    output: Annotated[
        Path,
        typer.Option("--output", help="Destination for normalized offline replay evidence."),
    ] = Path("offline-replay.json"),
    work_dir: Annotated[
        Path,
        typer.Option("--work-dir", help="Parent for disposable isolated replay workspaces."),
    ] = Path(".mmaudit/replay-work"),
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Replay sealed scanners, saved tests, and counterexamples without model contact."""

    local_console = Console(no_color=no_color)
    try:
        sealed_manifest = load_run_evidence_manifest(manifest)
        legacy_config, current_file_config = _verification_config_inputs(
            sealed_manifest=sealed_manifest,
            config_path=config_path,
        )
        replay = asyncio.run(
            OfflineReplayOrchestrator(
                legacy_config,
                file_config=current_file_config,
            ).replay(
                manifest_path=manifest,
                run_dir=run_dir,
                repository_root=repository,
                work_dir=work_dir,
            )
        )
        write_offline_replay(output, replay)
    except (OSError, RuntimeError, ValueError) as exc:
        local_console.print(f"[red]Offline replay failed safely:[/red] {exc}")
        raise typer.Exit(ExitCode.CONFIGURATION) from exc
    local_console.print(
        f"Offline replay {replay.status.value}: {len(replay.components)} component(s)"
    )
    local_console.print(f"Result: {output.resolve()}")
    if replay.status is not OfflineReplayStatus.REPLAYED:
        raise typer.Exit(ExitCode.INCOMPLETE)


@app.command("certify-run")
def certify_run_command(
    manifest: Annotated[
        Path,
        typer.Option("--manifest", help="Self-hashed run evidence manifest."),
    ],
    run_dir: Annotated[
        Path,
        typer.Option("--run-dir", help="Local completed maximum-assurance run directory."),
    ],
    replay: Annotated[
        Path,
        typer.Option("--replay", help="Manifest-bound offline replay evidence."),
    ],
    repository: Annotated[
        Path,
        typer.Option("--repo", help="Local source repository bound by the run."),
    ] = Path("."),
    config_path: Annotated[
        Path | None,
        typer.Option(
            "--config",
            help="Optional current base config; recorded safe overrides are replayed.",
        ),
    ] = None,
    output: Annotated[
        Path,
        typer.Option("--output", help="Destination for post-run certification evidence."),
    ] = Path("maximum-assurance-certification.json"),
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Certify a verified immutable run after its required offline replay."""

    local_console = Console(no_color=no_color)
    try:
        sealed_manifest = load_run_evidence_manifest(manifest)
        legacy_config, current_file_config = _verification_config_inputs(
            sealed_manifest=sealed_manifest,
            config_path=config_path,
        )
        certification = certify_maximum_assurance_run(
            manifest_path=manifest,
            run_dir=run_dir,
            repository_root=repository,
            replay_path=replay,
            config=legacy_config,
            file_config=current_file_config,
        )
        write_maximum_assurance_certification(output, certification)
    except (OSError, ValueError) as exc:
        local_console.print(f"[red]Maximum-assurance certification failed safely:[/red] {exc}")
        raise typer.Exit(ExitCode.CONFIGURATION) from exc
    local_console.print(
        f"Maximum assurance {certification.assessment.status.value}: "
        f"{len(certification.assessment.requirements)} clause(s)"
    )
    local_console.print(f"Result: {output.resolve()}")
    if certification.assessment.status is not MaximumAssuranceStatus.COMPLETE:
        raise typer.Exit(ExitCode.INCOMPLETE)


def _verification_config_inputs(
    *,
    sealed_manifest: RunEvidenceManifest,
    config_path: Path | None,
) -> tuple[AuditConfig | None, AuditConfig | None]:
    """Load only the configuration input appropriate for the manifest generation."""

    if config_path is None:
        return None, None
    if sealed_manifest.run_configuration is None:
        return load_config(config_path), None
    return None, load_config_with_provenance(config_path, environ={}).file_config


@snapshot_app.command("import")
def snapshot_import_command(
    plan: Annotated[
        Path,
        typer.Option("--plan", help="Hash-linked read-only snapshot import plan."),
    ],
    rpc_url: Annotated[
        str,
        typer.Option("--rpc-url", help="Plain HTTP loopback development-chain endpoint."),
    ],
    output: Annotated[
        Path,
        typer.Option("--output", help="Destination for the sanitized offline snapshot."),
    ] = Path("deployment-snapshot.json"),
    allow_read_only_import: Annotated[
        bool,
        typer.Option(
            "--allow-read-only-import",
            help="Explicitly authorize allowlisted read-only observation calls.",
        ),
    ] = False,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Import a deterministic snapshot using only the fixed read-only RPC vocabulary."""

    local_console = Console(no_color=no_color)
    if not allow_read_only_import:
        local_console.print("[red]Snapshot import requires --allow-read-only-import.[/red]")
        raise typer.Exit(ExitCode.CONFIGURATION)
    importer: ReadOnlySnapshotImporter | None = None
    try:
        import_plan = load_snapshot_import_plan(plan)
        importer = ReadOnlySnapshotImporter(rpc_url)
        snapshot = importer.import_snapshot(
            import_plan,
            explicitly_enabled=allow_read_only_import,
        )
        write_deployment_snapshot(output, snapshot)
    except (OSError, ValueError) as exc:
        local_console.print(f"[red]Snapshot import failed safely:[/red] {exc}")
        raise typer.Exit(ExitCode.CONFIGURATION) from exc
    finally:
        if importer is not None:
            importer.close()
    local_console.print(
        f"Snapshot imported at chain {snapshot.chain.chain_id} block "
        f"{snapshot.chain.block_number}: {output.resolve()}"
    )


def _execute_audit(
    *,
    config_path: Path,
    secrets_env_file: Path | None,
    repo: Path | None,
    output: Path | None,
    budget_usd: float | None,
    cost_ledger: Path | None,
    model_qualification_bundle: Path | None,
    model_qualification_policy: Path | None,
    model_qualification_release_bindings: Path | None,
    model_qualification_release_source_root: Path | None,
    model_qualification_corpus: Path | None,
    model_qualification_ground_truth: Path | None,
    max_files: int | None,
    max_file_bytes: int | None,
    max_context_bytes: int | None,
    concurrency: int | None,
    severity_threshold: Severity,
    fail_on: Severity | None,
    scanner_only: bool,
    skip_codeql: bool,
    allow_code_egress: bool,
    require_zdr: bool,
    privacy_profile: PrivacyProfile | None,
    retention_consent: Path | None,
    privacy_source_classification: PrivacySourceClassification,
    profile: AuditProfile | None,
    language_profile: LanguageCapabilityProfile | None,
    scope: AuditScope | None,
    require_complete_scope: bool | None,
    require_maximum_assurance: bool,
    allow_maximum_assurance_downgrade: bool,
    min_model_families: int | None,
    min_specialist_agents: int | None,
    require_reproduction_for_critical: bool | None,
    require_formal_or_reproduction_for_confirmed_critical: bool | None,
    benchmark_gate: bool,
    benchmark_certificate: Path | None,
    benchmark_component_root: Path | None,
    benchmark_repository_commit: str | None,
    solidity: bool | None,
    compile_solidity: bool | None,
    run_slither: bool,
    allow_network: bool,
    framework: Literal["auto", "foundry", "hardhat", "mixed", "plain"] | None,
    project_root: str | None,
    allow_fork_probing: bool,
    fork_rpc_url_env: str | None,
    changed_since: str | None,
    verbose: bool,
    no_color: bool,
    ci_mode: bool = False,
    ci_baseline_run: Path | None = None,
) -> None:
    operator_secrets = OperatorSecrets()
    pipeline: AuditPipeline | None = None
    try:
        if ci_mode and (
            not scanner_only
            or secrets_env_file is not None
            or budget_usd is not None
            or cost_ledger is not None
            or model_qualification_bundle is not None
            or model_qualification_policy is not None
            or model_qualification_release_bindings is not None
            or model_qualification_release_source_root is not None
            or model_qualification_corpus is not None
            or model_qualification_ground_truth is not None
            or allow_code_egress
            or retention_consent is not None
            or allow_network
        ):
            raise ConfigError("CI mode rejects provider, secret, egress, and network controls")
        if ci_mode and changed_since is None:
            raise ConfigError("CI mode requires --changed-since")
        if ci_baseline_run is not None and not ci_mode:
            raise ConfigError("--baseline-run is accepted only by CI mode")
        loaded_config = load_config_with_provenance(config_path)
        resolved_cost_ledger = cost_ledger.resolve() if cost_ledger is not None else None
        cli_overrides = _audit_config_overrides(
            budget_usd=budget_usd,
            cost_ledger=resolved_cost_ledger,
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_context_bytes=max_context_bytes,
            concurrency=concurrency,
            require_zdr=require_zdr,
            privacy_profile=privacy_profile,
            profile=profile,
            language_profile=language_profile,
            scope=scope,
            require_complete_scope=require_complete_scope,
            require_maximum_assurance=require_maximum_assurance,
            allow_maximum_assurance_downgrade=allow_maximum_assurance_downgrade,
            min_model_families=min_model_families,
            min_specialist_agents=min_specialist_agents,
            require_reproduction_for_critical=require_reproduction_for_critical,
            require_formal_or_reproduction_for_confirmed_critical=(
                require_formal_or_reproduction_for_confirmed_critical
            ),
            benchmark_gate=benchmark_gate,
            solidity=solidity,
            compile_solidity=compile_solidity,
            run_slither=run_slither,
            allow_network=allow_network,
            framework=framework,
            project_root=project_root,
            fork_rpc_url_env=fork_rpc_url_env,
            ci_mode=ci_mode,
        )
        config = cli_overrides.apply(loaded_config.effective_config)
        qualification_inputs_supplied = _validate_audit_production_qualification_inputs(
            scanner_only=scanner_only,
            bundle_path=model_qualification_bundle,
            policy_path=model_qualification_policy,
            release_bindings_path=model_qualification_release_bindings,
            release_source_root=model_qualification_release_source_root,
            corpus_path=model_qualification_corpus,
            ground_truth_path=model_qualification_ground_truth,
        )
        production_qualification: VerifiedProductionQualification | None = None
        campaign_ledger: AtomicCostLedger | None = None
        if not scanner_only:
            ledger_path = _selected_cost_ledger_path(config, resolved_cost_ledger)
            if ledger_path is None:
                raise ConfigError(
                    "provider audit requires an existing --cost-ledger initialized "
                    "with models init-cost-ledger"
                )
            campaign_ledger = AtomicCostLedger.open_existing(
                ledger_path,
                cap_usd=Decimal(str(config.execution.budget_usd)),
            )
            operator_secrets = load_operator_secrets(secrets_env_file, required=True)
        if qualification_inputs_supplied:
            production_qualification = asyncio.run(
                _load_audit_production_qualification(
                    config=config,
                    scanner_only=scanner_only,
                    bundle_path=model_qualification_bundle,
                    policy_path=model_qualification_policy,
                    release_bindings_path=model_qualification_release_bindings,
                    release_source_root=model_qualification_release_source_root,
                    corpus_path=model_qualification_corpus,
                    ground_truth_path=model_qualification_ground_truth,
                    secrets_env_file=secrets_env_file,
                )
            )
        benchmark_required = (
            config.maximum_assurance.benchmark_gate or config.maximum_assurance.ci_mode
        )
        benchmark_inputs = (
            benchmark_certificate,
            benchmark_component_root,
            benchmark_repository_commit,
        )
        supplied_benchmark_inputs = sum(value is not None for value in benchmark_inputs)
        downgrade_allowed = config.maximum_assurance.allow_downgrade
        benchmark_verification = None
        if benchmark_required:
            if supplied_benchmark_inputs not in {0, len(benchmark_inputs)}:
                raise ConfigError(
                    "benchmark gate requires --benchmark-certificate, "
                    "--benchmark-component-root, and --benchmark-repository-commit"
                )
            if supplied_benchmark_inputs == 0:
                if not downgrade_allowed:
                    raise ConfigError(
                        "benchmark gate requires --benchmark-certificate, "
                        "--benchmark-component-root, and --benchmark-repository-commit"
                    )
            else:
                assert benchmark_certificate is not None
                assert benchmark_component_root is not None
                assert benchmark_repository_commit is not None
                benchmark_verification = verify_file_backed_benchmark_certificate(
                    benchmark_certificate,
                    component_root=benchmark_component_root,
                    repository_git_commit=benchmark_repository_commit,
                )
                if (
                    benchmark_verification.status is not CertificateVerificationStatus.CURRENT
                    and not downgrade_allowed
                ):
                    raise ConfigError("benchmark certificate is stale")
        elif supplied_benchmark_inputs:
            raise ConfigError(
                "benchmark certificate inputs require --benchmark-gate or a configured gate"
            )
        repo_path = _repo_path(config, config_path, repo)
        ci_baseline: LoadedCIBaseline | None = None
        if ci_baseline_run is not None:
            assert changed_since is not None
            ci_baseline = load_ci_baseline_bundle(
                ci_baseline_run,
                expected_repository_git_commit=changed_since,
            )
        if scanner_only:
            if retention_consent is not None:
                raise ConfigError(
                    "scanner-only execution does not accept a provider-retention consent artifact"
                )
            consent_observation = None
        else:
            consent_observation = _load_audit_privacy_consent(
                config=config,
                explicit_profile=privacy_profile,
                retention_consent=retention_consent,
                target_root=repo_path,
            )
        output_path = resolve_safe_output_root(output or (repo_path / ".mmaudit"))
        if config.privacy.store_raw_prompts or config.privacy.store_raw_responses:
            Console(no_color=no_color).print(
                "[yellow]Warning: debug storage is enabled; source code may be written "
                "to the private run directory.[/yellow]"
            )
        logger = configure_logging(verbose=verbose, no_color=no_color)
        pipeline = AuditPipeline(
            config,
            repo=repo_path,
            output=output_path,
            configuration_root=config_path.resolve().parent,
            file_config=loaded_config.file_config,
            environment_overrides=loaded_config.environment_overrides,
            cli_overrides=cli_overrides,
            cost_ledger=campaign_ledger,
            api_key=operator_secrets.openrouter_api_key,
            logger=logger,
            production_qualification=production_qualification,
            privacy_consent_observation=consent_observation,
            privacy_source_classification=privacy_source_classification,
        )
        result = asyncio.run(
            pipeline.run(
                scanner_only=scanner_only,
                allow_code_egress=allow_code_egress,
                skip_codeql=skip_codeql,
                changed_since=changed_since,
                severity_threshold=severity_threshold,
                fail_on=fail_on,
                allow_fork_probing=allow_fork_probing,
                require_maximum_assurance=None,
                allow_maximum_assurance_downgrade=None,
                benchmark_verification=benchmark_verification,
                benchmark_repository_git_commit=benchmark_repository_commit,
                ci_mode=ci_mode,
                ci_baseline=ci_baseline,
            )
        )
        local_console = Console(no_color=no_color)
        local_console.print(f"Reports: {result.run_dir}")
        if ci_mode:
            ci_state = result.ci_state
            if ci_state is None:
                local_console.print("[red]CI status: ANALYSIS_FAILED; state artifact missing[/red]")
            else:
                comparison = ci_state.comparison
                local_console.print(
                    "CI status: "
                    f"{ci_state.job_status.value}; "
                    f"new={len(comparison.new_finding_ids) if comparison else len(ci_state.evidence.findings)}; "
                    f"unchanged={len(comparison.unchanged_finding_ids) if comparison else 0}; "
                    f"coverage_regressions="
                    f"{len(comparison.coverage_regressions) if comparison else 0}"
                )
            raise typer.Exit(result.exit_for_ci(fail_on))
        raise typer.Exit(result.exit_for_findings(fail_on))
    except typer.Exit:
        raise
    except SecretlessErrors as exc:
        Console(no_color=no_color).print(f"[red]mmaudit failed safely:[/red] {exc}")
        raise typer.Exit(ExitCode.CONFIGURATION) from exc
    finally:
        if pipeline is not None:
            clear_credentials = getattr(pipeline, "clear_credentials", None)
            if callable(clear_credentials):
                clear_credentials()
        operator_secrets.clear()


SecretlessErrors = (
    ConfigError,
    CostLedgerError,
    RepositorySafetyError,
    OpenRouterError,
    OSError,
    ValueError,
)


def _load_audit_privacy_consent(
    *,
    config: AuditConfig,
    explicit_profile: PrivacyProfile | None,
    retention_consent: Path | None,
    target_root: Path,
) -> PrivacyRetentionConsentObservation | None:
    """Load only explicit operator consent; configuration alone cannot authorize retention."""

    if config.privacy.profile is PrivacyProfile.STRICT_ZDR:
        if retention_consent is not None:
            raise ConfigError("STRICT_ZDR does not accept a retention-consent artifact")
        return None
    if explicit_profile is not config.privacy.profile:
        raise ConfigError("non-strict privacy requires an explicit matching --privacy-profile")
    if config.privacy.profile is PrivacyProfile.SYNTHETIC_BENCHMARK and config.privacy.require_zdr:
        if retention_consent is not None:
            raise ConfigError(
                "ZDR-enforced synthetic benchmark execution does not accept retention consent"
            )
        return None
    if retention_consent is None:
        raise ConfigError("non-strict privacy requires an explicit --retention-consent artifact")
    return load_privacy_retention_consent(
        retention_consent,
        target_root=target_root,
    )


def _audit_config_overrides(
    *,
    budget_usd: float | None,
    cost_ledger: Path | None = None,
    max_files: int | None,
    max_file_bytes: int | None,
    max_context_bytes: int | None,
    concurrency: int | None,
    require_zdr: bool,
    privacy_profile: PrivacyProfile | None = None,
    profile: AuditProfile | None = None,
    language_profile: LanguageCapabilityProfile | None = None,
    scope: AuditScope | None = None,
    require_complete_scope: bool | None = None,
    require_maximum_assurance: bool = False,
    allow_maximum_assurance_downgrade: bool = False,
    min_model_families: int | None = None,
    min_specialist_agents: int | None = None,
    require_reproduction_for_critical: bool | None = None,
    require_formal_or_reproduction_for_confirmed_critical: bool | None = None,
    benchmark_gate: bool = False,
    solidity: bool | None = None,
    compile_solidity: bool | None = None,
    run_slither: bool = False,
    allow_network: bool = False,
    framework: Literal["auto", "foundry", "hardhat", "mixed", "plain"] | None = None,
    project_root: str | None = None,
    fork_rpc_url_env: str | None = None,
    ci_mode: bool = False,
) -> AuditConfigOverrides:
    if require_maximum_assurance and allow_maximum_assurance_downgrade:
        raise ConfigError(
            "--require-maximum-assurance and --allow-maximum-assurance-downgrade "
            "cannot be used together"
        )
    privacy_profile_override: str | None = None
    if require_zdr:
        privacy_profile_override = PrivacyProfile.STRICT_ZDR.value
    elif privacy_profile is not None:
        privacy_profile_override = privacy_profile.value
    values: dict[str, bool | int | float | str | None] = {
        "execution.budget_usd": budget_usd,
        "execution.cost_ledger_path": (
            str(cost_ledger.resolve()) if cost_ledger is not None else None
        ),
        "execution.concurrency": concurrency,
        "repository.max_files": max_files,
        "repository.max_file_bytes": max_file_bytes,
        "repository.max_total_context_bytes": max_context_bytes,
        "privacy.profile": privacy_profile_override,
        "privacy.require_zdr": (
            True
            if require_zdr or privacy_profile is PrivacyProfile.STRICT_ZDR
            else (
                False
                if privacy_profile is PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT
                else None
            )
        ),
        "privacy.maximum_model_retention": (
            "zero" if require_zdr or privacy_profile is PrivacyProfile.STRICT_ZDR else None
        ),
        "profile": profile.value if profile is not None else None,
        "language_profile": (language_profile.value if language_profile is not None else None),
        "scope.mode": scope.value if scope is not None else None,
        "scope.require_complete": require_complete_scope,
        "maximum_assurance.minimum_model_families": min_model_families,
        "maximum_assurance.minimum_specialist_agents": min_specialist_agents,
        "maximum_assurance.require_reproduction_for_critical": (require_reproduction_for_critical),
        "maximum_assurance.require_formal_or_reproduction_for_confirmed_critical": (
            require_formal_or_reproduction_for_confirmed_critical
        ),
        "maximum_assurance.benchmark_gate": True if benchmark_gate else None,
        "models.minimum_distinct_families": min_model_families,
        "smart_contracts.enabled": True if ci_mode else solidity,
        "smart_contracts.compile": True if ci_mode else compile_solidity,
        "smart_contracts.allow_network": False if ci_mode else (True if allow_network else None),
        "smart_contracts.require_local_fork_rpc": True if ci_mode else None,
        "smart_contracts.framework": framework,
        "smart_contracts.project_root": project_root,
        "smart_contracts.fork_rpc_url_env": fork_rpc_url_env,
        "scanners.slither.enabled": True if run_slither else None,
        "scanners.foundry_fork.enabled": True if ci_mode else None,
        "scanners.hardhat_fork.enabled": True if ci_mode else None,
        "reproduction.require_hardened_isolation": True if ci_mode else None,
    }
    if require_maximum_assurance:
        values["maximum_assurance.require"] = True
        values["maximum_assurance.allow_downgrade"] = False
    elif allow_maximum_assurance_downgrade:
        values["maximum_assurance.require"] = False
        values["maximum_assurance.allow_downgrade"] = True
    return audit_config_overrides(values)


def _repo_path(config: AuditConfig, config_path: Path, override: Path | None) -> Path:
    if override is not None:
        return override.resolve()
    root = Path(config.repository.root)
    return (root if root.is_absolute() else config_path.resolve().parent / root).resolve()


def _writable_output_check(path: Path) -> tuple[str, bool, str, bool]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path, prefix=".mmaudit-doctor-", delete=True):
            pass
        return ("Output directory", True, str(path), True)
    except OSError as exc:
        return ("Output directory", False, type(exc).__name__, True)


def _scanner_preflight_detail(
    preflight: ScannerExecutablePreflight,
    *,
    enabled: bool,
) -> str:
    state_detail = {
        ScannerExecutableState.ABSENT: "absent from PATH",
        ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE: (
            "resolved but not executable under isolation"
        ),
        ScannerExecutableState.PRESENT_EXECUTABLE: "resolved and executable under isolation",
    }[preflight.state]
    details = [state_detail]
    if preflight.resolved_path is not None:
        details.append(f"resolved absolute path: {preflight.resolved_path}")
    if preflight.version is not None:
        details.append(f"version: {preflight.version}")
    if preflight.failure_kind is not None:
        details.append(f"failure: {preflight.failure_kind.value}")
    if preflight.diagnostic is not None:
        details.append(preflight.diagnostic)
    if not enabled:
        details.insert(0, "disabled by configuration")
    return "; ".join(details)


def platform_python() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def _parse_authenticated_runner_cost_cap(value: str, *, label: str) -> Decimal:
    """Parse one exact finite decimal without a binary-float round trip."""

    if type(value) is not str or not value or value != value.strip():
        raise ConfigError(f"authenticated runner {label} cost cap must be an exact decimal")
    try:
        parsed = Decimal(value)
    except ArithmeticError:
        raise ConfigError(
            f"authenticated runner {label} cost cap must be an exact decimal"
        ) from None
    if not parsed.is_finite() or parsed <= 0:
        raise ConfigError(f"authenticated runner {label} cost cap must be finite and positive")
    return parsed


def _preflight_authenticated_runner_cli_paths(
    *,
    mutable_outputs: tuple[Path, ...],
    source_paths: tuple[Path, ...],
) -> None:
    """Reject output/source aliasing before the operator secret file is opened."""

    path_type = type(Path("/"))
    if (
        type(mutable_outputs) is not tuple
        or len(mutable_outputs) != 5
        or type(source_paths) is not tuple
        or not source_paths
    ):
        raise ConfigError("authenticated runner path inventory is incomplete")

    normalized_mutable: list[Path] = []
    for path in mutable_outputs:
        if type(path) is not path_type or not path.is_absolute():
            raise ConfigError("authenticated runner output paths must be exact absolute paths")
        normalized = Path(os.path.abspath(path))
        if normalized != path or not normalized.name or normalized.name in {".", ".."}:
            raise ConfigError("authenticated runner output paths must be canonical leaves")
        if is_sensitive_workspace_name(normalized.name):
            raise ConfigError("refusing a sensitive authenticated runner output path")
        normalized_mutable.append(normalized)

    if len(set(normalized_mutable)) != len(normalized_mutable):
        raise ConfigError("authenticated runner outputs must be distinct")
    for index, left in enumerate(normalized_mutable):
        for right in normalized_mutable[index + 1 :]:
            if _paths_overlap(left, right):
                raise ConfigError("authenticated runner output paths may not overlap")

    for source in source_paths:
        if type(source) is not path_type:
            raise ConfigError("authenticated runner source paths must use concrete paths")
        normalized_source = Path(os.path.abspath(source))
        if any(_paths_overlap(output, normalized_source) for output in normalized_mutable):
            raise ConfigError(
                "authenticated runner output overlaps immutable input or ledger state"
            )


def _preflight_authenticated_runner_smoke_cli_paths(
    *,
    output: Path,
    source_paths: tuple[Path, ...],
) -> None:
    """Reject smoke output/source aliasing before an operator secret is opened."""

    path_type = type(Path("/"))
    if type(output) is not path_type or type(source_paths) is not tuple or not source_paths:
        raise ConfigError("authenticated runner smoke path inventory is incomplete")
    if not output.is_absolute():
        raise ConfigError("authenticated runner smoke output must be an exact absolute path")
    normalized_output = Path(os.path.abspath(output))
    if (
        normalized_output != output
        or not normalized_output.name
        or normalized_output.name in {".", ".."}
    ):
        raise ConfigError("authenticated runner smoke output must be a canonical leaf")
    if is_sensitive_workspace_name(normalized_output.name):
        raise ConfigError("refusing a sensitive authenticated runner smoke output path")
    for source in source_paths:
        if type(source) is not path_type:
            raise ConfigError("authenticated runner smoke sources must use concrete paths")
        normalized_source = Path(os.path.abspath(source))
        if _paths_overlap(normalized_output, normalized_source):
            raise ConfigError(
                "authenticated runner smoke output overlaps immutable input or ledger state"
            )


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _preflight_authenticated_runner_smoke_output_readonly(output: Path) -> None:
    """Validate one fresh private smoke leaf without creating a probe or publishing output."""

    path_type = type(Path("/"))
    if type(output) is not path_type or not output.is_absolute():
        raise ConfigError("authenticated runner smoke output must be an exact absolute path")
    absolute = Path(os.path.abspath(output))
    if absolute != output or not absolute.name or absolute.name in {".", ".."}:
        raise ConfigError("authenticated runner smoke output must be a canonical leaf")
    if is_sensitive_workspace_name(absolute.name):
        raise ConfigError("refusing a sensitive authenticated runner smoke output filename")

    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if (
        no_follow <= 0
        or directory <= 0
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise ConfigError(
            "authenticated runner smoke output preflight requires descriptor-relative "
            "no-follow support"
        )
    descriptor = -1
    directory_flags = os.O_RDONLY | no_follow | directory | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(absolute.anchor, directory_flags)
        for component in absolute.parts[1:-1]:
            child = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        parent = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_IMODE(parent.st_mode) != 0o700
            or parent.st_uid != os.geteuid()
        ):
            raise ConfigError(
                "authenticated runner smoke output parent must be an owned mode-0700 directory"
            )
        parent_identity = (parent.st_dev, parent.st_ino, parent.st_mode, parent.st_uid)
        if _authenticated_runner_output_parent_identity(absolute, directory_flags) != (
            parent_identity
        ):
            raise ConfigError("authenticated runner smoke output parent changed during preflight")
        try:
            os.stat(absolute.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ConfigError("authenticated runner smoke final output must be fresh")
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
        ) != parent_identity or _authenticated_runner_output_parent_identity(
            absolute, directory_flags
        ) != parent_identity:
            raise ConfigError("authenticated runner smoke output parent changed during preflight")
    except ConfigError:
        raise
    except OSError as exc:
        raise ConfigError(
            "authenticated runner smoke output parent is unavailable or linked"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _preflight_authenticated_runner_output(output: Path) -> None:
    """Prove the final bundle can be atomically published to a fresh private leaf."""

    path_type = type(Path("/"))
    if type(output) is not path_type or not output.is_absolute():
        raise ConfigError("authenticated runner final output must be an exact absolute path")
    absolute = Path(os.path.abspath(output))
    if absolute != output or not absolute.name or absolute.name in {".", ".."}:
        raise ConfigError("authenticated runner final output must be a canonical leaf")
    if is_sensitive_workspace_name(absolute.name):
        raise ConfigError("refusing a sensitive authenticated runner output filename")

    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if (
        no_follow <= 0
        or directory <= 0
        or os.open not in os.supports_dir_fd
        or os.link not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.unlink not in os.supports_dir_fd
        or os.link not in os.supports_follow_symlinks
        or os.stat not in os.supports_follow_symlinks
    ):
        raise ConfigError(
            "authenticated runner output preflight requires descriptor-relative no-follow support"
        )

    descriptor = -1
    probe_name: str | None = None
    linked_probe_name: str | None = None
    directory_flags = os.O_RDONLY | no_follow | directory | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(absolute.anchor, directory_flags)
        for component in absolute.parts[1:-1]:
            child = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        parent = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_IMODE(parent.st_mode) != 0o700
            or parent.st_uid != os.geteuid()
        ):
            raise ConfigError(
                "authenticated runner output parent must be an owned mode-0700 directory"
            )
        parent_identity = (parent.st_dev, parent.st_ino, parent.st_mode, parent.st_uid)
        if _authenticated_runner_output_parent_identity(absolute, directory_flags) != (
            parent_identity
        ):
            raise ConfigError("authenticated runner output parent changed during preflight")
        try:
            os.stat(absolute.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ConfigError("authenticated runner final output must be fresh")

        probe_name = f".mmaudit-authrunner-output-{uuid.uuid4().hex}"
        probe_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow | getattr(os, "O_CLOEXEC", 0)
        probe = os.open(probe_name, probe_flags, 0o600, dir_fd=descriptor)
        try:
            os.fchmod(probe, 0o600)
            metadata = os.fstat(probe)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise ConfigError(
                    "authenticated runner output parent cannot create private artifacts"
                )
            os.fsync(probe)
        finally:
            os.close(probe)
        linked_probe_name = f"{probe_name}.link"
        os.link(
            probe_name,
            linked_probe_name,
            src_dir_fd=descriptor,
            dst_dir_fd=descriptor,
            follow_symlinks=False,
        )
        linked_probe = os.stat(linked_probe_name, dir_fd=descriptor, follow_symlinks=False)
        original_probe = os.stat(probe_name, dir_fd=descriptor, follow_symlinks=False)
        if (
            linked_probe.st_dev != original_probe.st_dev
            or linked_probe.st_ino != original_probe.st_ino
            or linked_probe.st_nlink != 2
            or original_probe.st_nlink != 2
        ):
            raise ConfigError(
                "authenticated runner output parent cannot publish exact private artifacts"
            )
        os.unlink(linked_probe_name, dir_fd=descriptor)
        linked_probe_name = None
        os.fsync(descriptor)
        os.unlink(probe_name, dir_fd=descriptor)
        probe_name = None
        os.fsync(descriptor)
        current_parent = os.fstat(descriptor)
        if (
            current_parent.st_dev,
            current_parent.st_ino,
            current_parent.st_mode,
            current_parent.st_uid,
        ) != (
            parent.st_dev,
            parent.st_ino,
            parent.st_mode,
            parent.st_uid,
        ):
            raise ConfigError("authenticated runner output parent changed during preflight")
        if _authenticated_runner_output_parent_identity(absolute, directory_flags) != (
            parent_identity
        ):
            raise ConfigError("authenticated runner output parent changed during preflight")
    except ConfigError:
        raise
    except OSError as exc:
        raise ConfigError(
            "authenticated runner output parent is unavailable, linked, or not writable"
        ) from exc
    finally:
        if descriptor >= 0:
            if linked_probe_name is not None:
                with suppress(OSError):
                    os.unlink(linked_probe_name, dir_fd=descriptor)
            if probe_name is not None:
                with suppress(OSError):
                    os.unlink(probe_name, dir_fd=descriptor)
            os.close(descriptor)


def _authenticated_runner_output_parent_identity(
    output: Path,
    directory_flags: int,
) -> tuple[int, int, int, int]:
    """Resolve the requested parent afresh and return its exact inode identity."""

    descriptor = -1
    try:
        descriptor = os.open(output.anchor, directory_flags)
        for component in output.parts[1:-1]:
            child = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        parent = os.fstat(descriptor)
        return (parent.st_dev, parent.st_ino, parent.st_mode, parent.st_uid)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_authenticated_runner_output_fresh(
    output: Path,
    value: AuthenticatedRunnerDurableEvidenceBundle,
    *,
    max_bytes: int = MAX_JSON_ARTIFACT_BYTES,
) -> int:
    """Publish one bounded private bundle without replacing an intervening leaf.

    The provider-free preflight is intentionally repeated here.  Publication uses
    a descriptor-relative exclusive temporary file followed by an exclusive hard
    link, so an output created after preflight is never overwritten. Once the final
    name becomes visible, rollback never unlinks it: there is no portable atomic
    unlink-if-inode-matches operation, and deleting by name could remove a concurrent
    operator replacement.
    """

    if (
        type(value) is not AuthenticatedRunnerDurableEvidenceBundle
        or type(max_bytes) is not int
        or max_bytes <= 0
    ):
        raise ConfigError("authenticated runner final output payload is invalid")
    try:
        serialized = authenticated_runner_durable_bundle_bytes(value)
    except AuthenticatedRunnerDurableBundleError:
        raise ConfigError("authenticated runner final output payload is invalid") from None
    if len(serialized) > max_bytes:
        raise ConfigError(f"authenticated runner final output exceeds {max_bytes} byte limit")
    _preflight_authenticated_runner_output(output)

    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if (
        no_follow <= 0
        or directory <= 0
        or os.open not in os.supports_dir_fd
        or os.link not in os.supports_dir_fd
        or os.unlink not in os.supports_dir_fd
        or os.link not in os.supports_follow_symlinks
    ):
        raise ConfigError(
            "authenticated runner output publication requires descriptor-relative support"
        )

    descriptor = -1
    temporary_name: str | None = None
    published = False
    directory_flags = os.O_RDONLY | no_follow | directory | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(output.anchor, directory_flags)
        for component in output.parts[1:-1]:
            child = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        parent = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_IMODE(parent.st_mode) != 0o700
            or parent.st_uid != os.geteuid()
        ):
            raise ConfigError(
                "authenticated runner output parent must be an owned mode-0700 directory"
            )
        parent_identity = (parent.st_dev, parent.st_ino, parent.st_mode, parent.st_uid)
        if _authenticated_runner_output_parent_identity(output, directory_flags) != (
            parent_identity
        ):
            raise ConfigError("authenticated runner output parent changed before publication")

        temporary_name = f".mmaudit-authrunner-output-{uuid.uuid4().hex}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow | getattr(os, "O_CLOEXEC", 0)
        temporary = os.open(temporary_name, flags, 0o600, dir_fd=descriptor)
        try:
            remaining = memoryview(serialized)
            while remaining:
                written = os.write(temporary, remaining)
                if written <= 0:
                    raise OSError("authenticated runner output write made no progress")
                remaining = remaining[written:]
            os.fsync(temporary)
            metadata = os.fstat(temporary)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size != len(serialized)
            ):
                raise ConfigError("authenticated runner temporary output is not exact and private")
        finally:
            os.close(temporary)

        if _authenticated_runner_output_parent_identity(output, directory_flags) != (
            parent_identity
        ):
            raise ConfigError("authenticated runner output parent changed before publication")
        os.link(
            temporary_name,
            output.name,
            src_dir_fd=descriptor,
            dst_dir_fd=descriptor,
            follow_symlinks=False,
        )
        if _authenticated_runner_output_parent_identity(output, directory_flags) != (
            parent_identity
        ):
            raise ConfigError("authenticated runner output parent changed during publication")
        os.unlink(temporary_name, dir_fd=descriptor)
        temporary_name = None
        os.fsync(descriptor)
        final = os.stat(output.name, dir_fd=descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(final.st_mode)
            or final.st_nlink != 1
            or stat.S_IMODE(final.st_mode) != 0o600
            or final.st_size != len(serialized)
        ):
            raise ConfigError("authenticated runner final output is not exact and private")
        if _authenticated_runner_output_parent_identity(output, directory_flags) != (
            parent_identity
        ):
            raise ConfigError("authenticated runner output parent changed during publication")
        published = True
    except FileExistsError:
        raise ConfigError("authenticated runner final output must remain fresh") from None
    except ConfigError:
        raise
    except OSError as exc:
        raise ConfigError("authenticated runner final output publication failed safely") from exc
    finally:
        if descriptor >= 0:
            if temporary_name is not None:
                with suppress(OSError):
                    os.unlink(temporary_name, dir_fd=descriptor)
            os.close(descriptor)
    if not published:
        raise ConfigError("authenticated runner final output was not published")
    return len(serialized)


def _write_authenticated_runner_smoke_output_fresh(
    output: Path,
    value: AuthenticatedRunnerSmokeEvidenceBundle,
) -> int:
    """Atomically publish one fresh, bounded, private NONCREDITING smoke bundle."""

    if type(value) is not AuthenticatedRunnerSmokeEvidenceBundle:
        raise ConfigError("authenticated runner smoke final output payload is invalid")
    try:
        serialized = authenticated_runner_smoke_evidence_bytes(value)
    except AuthenticatedRunnerSmokeError:
        raise ConfigError("authenticated runner smoke final output payload is invalid") from None
    if (
        type(serialized) is not bytes
        or not serialized
        or len(serialized) > MAX_AUTHENTICATED_RUNNER_SMOKE_BUNDLE_BYTES
    ):
        raise ConfigError("authenticated runner smoke final output is invalid or exceeds its bound")
    _preflight_authenticated_runner_output(output)

    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if (
        no_follow <= 0
        or directory <= 0
        or os.open not in os.supports_dir_fd
        or os.link not in os.supports_dir_fd
        or os.unlink not in os.supports_dir_fd
        or os.link not in os.supports_follow_symlinks
    ):
        raise ConfigError(
            "authenticated runner smoke publication requires descriptor-relative support"
        )

    descriptor = -1
    temporary_name: str | None = None
    published = False
    directory_flags = os.O_RDONLY | no_follow | directory | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(output.anchor, directory_flags)
        for component in output.parts[1:-1]:
            child = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        parent = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_IMODE(parent.st_mode) != 0o700
            or parent.st_uid != os.geteuid()
        ):
            raise ConfigError(
                "authenticated runner smoke output parent must be an owned mode-0700 directory"
            )
        parent_identity = (parent.st_dev, parent.st_ino, parent.st_mode, parent.st_uid)
        if _authenticated_runner_output_parent_identity(output, directory_flags) != (
            parent_identity
        ):
            raise ConfigError("authenticated runner smoke output parent changed before publication")

        temporary_name = f".mmaudit-authrunner-smoke-output-{uuid.uuid4().hex}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow | getattr(os, "O_CLOEXEC", 0)
        temporary = os.open(temporary_name, flags, 0o600, dir_fd=descriptor)
        try:
            remaining = memoryview(serialized)
            while remaining:
                written = os.write(temporary, remaining)
                if written <= 0:
                    raise OSError("authenticated runner smoke output write made no progress")
                remaining = remaining[written:]
            os.fsync(temporary)
            metadata = os.fstat(temporary)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size != len(serialized)
            ):
                raise ConfigError(
                    "authenticated runner smoke temporary output is not exact and private"
                )
        finally:
            os.close(temporary)

        if _authenticated_runner_output_parent_identity(output, directory_flags) != (
            parent_identity
        ):
            raise ConfigError("authenticated runner smoke output parent changed before publication")
        os.link(
            temporary_name,
            output.name,
            src_dir_fd=descriptor,
            dst_dir_fd=descriptor,
            follow_symlinks=False,
        )
        if _authenticated_runner_output_parent_identity(output, directory_flags) != (
            parent_identity
        ):
            raise ConfigError("authenticated runner smoke output parent changed during publication")
        os.unlink(temporary_name, dir_fd=descriptor)
        temporary_name = None
        os.fsync(descriptor)
        final = os.stat(output.name, dir_fd=descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(final.st_mode)
            or final.st_nlink != 1
            or stat.S_IMODE(final.st_mode) != 0o600
            or final.st_size != len(serialized)
        ):
            raise ConfigError("authenticated runner smoke final output is not exact and private")
        if _authenticated_runner_output_parent_identity(output, directory_flags) != (
            parent_identity
        ):
            raise ConfigError("authenticated runner smoke output parent changed during publication")
        published = True
    except FileExistsError:
        raise ConfigError("authenticated runner smoke final output must remain fresh") from None
    except ConfigError:
        raise
    except OSError as exc:
        raise ConfigError("authenticated runner smoke output publication failed safely") from exc
    finally:
        if descriptor >= 0:
            if temporary_name is not None:
                with suppress(OSError):
                    os.unlink(temporary_name, dir_fd=descriptor)
            os.close(descriptor)
    if not published:
        raise ConfigError("authenticated runner smoke final output was not published")
    return len(serialized)


def _load_authenticated_runner_smoke_evidence_bundle(
    path: Path,
) -> AuthenticatedRunnerSmokeEvidenceBundle:
    """Read one canonical private smoke file without following any path component."""

    path_type = type(Path("/"))
    if type(path) is not path_type or not path.is_absolute() or not path.name:
        raise ConfigError("authenticated runner smoke bundle path must be one absolute file")
    absolute = Path(os.path.abspath(path))
    if absolute != path or is_sensitive_workspace_name(absolute.name):
        raise ConfigError("authenticated runner smoke bundle path is unsafe")

    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if (
        no_follow <= 0
        or directory <= 0
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise ConfigError(
            "authenticated runner smoke replay requires descriptor-relative no-follow support"
        )
    directory_descriptor = -1
    file_descriptor = -1
    directory_flags = os.O_RDONLY | no_follow | directory | getattr(os, "O_CLOEXEC", 0)
    try:
        directory_descriptor = os.open(absolute.anchor, directory_flags)
        for component in absolute.parts[1:-1]:
            child = os.open(component, directory_flags, dir_fd=directory_descriptor)
            os.close(directory_descriptor)
            directory_descriptor = child
        parent_before = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(parent_before.st_mode)
            or stat.S_IMODE(parent_before.st_mode) != 0o700
            or parent_before.st_uid != os.geteuid()
        ):
            raise ConfigError(
                "authenticated runner smoke bundle parent must be owned and mode-0700"
            )
        file_descriptor = os.open(
            absolute.name,
            os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_descriptor,
        )
        file_before = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(file_before.st_mode)
            or stat.S_IMODE(file_before.st_mode) != 0o600
            or file_before.st_uid != os.geteuid()
            or file_before.st_nlink != 1
            or not 0 < file_before.st_size <= MAX_AUTHENTICATED_RUNNER_SMOKE_BUNDLE_BYTES
        ):
            raise ConfigError(
                "authenticated runner smoke bundle must be owned, private, regular, and unshared"
            )
        chunks: list[bytes] = []
        remaining = file_before.st_size
        while remaining:
            chunk = os.read(file_descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ConfigError("authenticated runner smoke bundle was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(file_descriptor, 1):
            raise ConfigError("authenticated runner smoke bundle grew while reading")
        raw = b"".join(chunks)
        file_after = os.fstat(file_descriptor)
        path_after = os.stat(
            absolute.name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        parent_after = os.fstat(directory_descriptor)
        if (
            _authenticated_runner_smoke_file_identity(file_before)
            != _authenticated_runner_smoke_file_identity(file_after)
            or _authenticated_runner_smoke_file_identity(file_before)
            != _authenticated_runner_smoke_file_identity(path_after)
            or _authenticated_runner_smoke_directory_identity(parent_before)
            != _authenticated_runner_smoke_directory_identity(parent_after)
            or _authenticated_runner_output_parent_identity(absolute, directory_flags)
            != (
                parent_before.st_dev,
                parent_before.st_ino,
                parent_before.st_mode,
                parent_before.st_uid,
            )
        ):
            raise ConfigError("authenticated runner smoke bundle changed during replay")
    except ConfigError:
        raise
    except OSError as exc:
        raise ConfigError(
            "authenticated runner smoke bundle is absent, unsafe, or changed"
        ) from exc
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        if directory_descriptor >= 0:
            os.close(directory_descriptor)
    try:
        return revalidate_authenticated_runner_smoke_evidence_bytes(raw)
    except AuthenticatedRunnerSmokeError:
        raise ConfigError("authenticated runner smoke bundle failed canonical replay") from None


def _authenticated_runner_smoke_file_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _authenticated_runner_smoke_directory_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _authenticated_runner_durable_output(
    result: AuthenticatedRunnerOpenRouterResult,
) -> AuthenticatedRunnerDurableEvidenceBundle:
    """Build the strict durable bundle without serializing PID-local authority."""

    if (
        type(result) is not AuthenticatedRunnerOpenRouterResult
        or type(result.execution) is not AuthenticatedRunnerOpenRouterExecutionSnapshot
        or type(result.execution.runs) is not tuple
        or any(
            type(item) is not AuthenticatedRunnerOpenRouterRunSnapshot
            for item in result.execution.runs
        )
    ):
        raise ConfigError("authenticated runner returned the wrong exact result type")
    try:
        return build_authenticated_runner_durable_bundle(
            runner_evidence=result.runner_evidence,
            candidate_cost_plans=tuple(item.candidate_cost_plan for item in result.execution.runs),
            judge_cost_plans=tuple(item.judge_cost_plan for item in result.execution.runs),
            candidate_reports=tuple(item.candidate_report for item in result.execution.runs),
            prepared_runs=tuple(item.prepared_adjudication for item in result.execution.runs),
            adjudication_reports=tuple(item.adjudication_report for item in result.execution.runs),
            authseal_collision_map=result.authseal_collision_map,
            authseal_decision_projections=result.authseal_decision_projections,
            authseal_rejection_kind=result.authseal_rejection_kind,
        )
    except (AttributeError, AuthenticatedRunnerDurableBundleError):
        raise ConfigError("authenticated runner durable output is invalid") from None


def _budget_and_usage(
    config: AuditConfig,
    *,
    ledger_path: Path | None = None,
    require_endpoint_cost_bound: bool = False,
) -> tuple[BudgetManager, UsageLedger]:
    return (
        BudgetManager(
            total_usd=config.execution.budget_usd,
            max_output_tokens=config.execution.max_output_tokens_per_request,
            conservative_usd_per_million_tokens=(
                config.execution.conservative_usd_per_million_tokens
            ),
            max_requests_per_agent=config.execution.max_requests_per_agent,
            atomic_ledger=(
                AtomicCostLedger.open_existing(
                    ledger_path,
                    cap_usd=Decimal(str(config.execution.budget_usd)),
                )
                if ledger_path is not None
                else None
            ),
            require_endpoint_cost_bound=require_endpoint_cost_bound,
            global_input_token_budget=config.token_budgets.global_input_token_budget,
            global_output_token_budget=config.token_budgets.global_output_token_budget,
            per_model_usd_caps={
                model: str(cap)
                for model, cap in config.token_budgets.per_model_cost_budget_usd.items()
            },
            per_role_usd_caps={
                role: str(cap)
                for role, cap in config.token_budgets.per_role_cost_budget_usd.items()
            },
        ),
        UsageLedger(),
    )


def _selected_cost_ledger_path(
    config: AuditConfig,
    override: Path | None,
) -> Path | None:
    configured = config.execution.cost_ledger_path
    if override is not None:
        if not override.is_absolute():
            raise ConfigError("authenticated runner cost ledger override must be absolute")
        if configured is not None and override != Path(configured):
            raise ConfigError(
                "authenticated runner cost ledger override differs from configured ledger"
            )
        return override
    return Path(configured) if configured is not None else None


def _parse_model_discovery_candidates(values: list[str]) -> tuple[tuple[str, str], ...]:
    """Parse exact candidate routes before secret loading or provider access."""

    if not 1 <= len(values) <= 64:
        raise ConfigError("models discover requires between 1 and 64 --candidate values")
    parsed: list[tuple[str, str]] = []
    endpoint_pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
    for value in values:
        if value != value.strip() or value.count("=") != 1:
            raise ConfigError(
                "models discover candidates must use canonical MODEL_ID=PROVIDER_ENDPOINT form"
            )
        model_id, provider_endpoint = value.split("=", 1)
        if (
            not is_exact_openrouter_model_id(model_id)
            or endpoint_pattern.fullmatch(provider_endpoint) is None
        ):
            raise ConfigError("models discover requires exact non-alias model and endpoint IDs")
        parsed.append((model_id, provider_endpoint))
    if len({model_id for model_id, _endpoint in parsed}) != len(parsed):
        raise ConfigError("models discover candidate model IDs must be unique")
    return tuple(sorted(parsed))


def _parse_model_refresh_selected_routes(
    values: list[str],
) -> tuple[SelectedModelRoute, ...]:
    """Parse optional production routes before secret or provider access."""

    if len(values) > 128:
        raise ConfigError("models refresh accepts at most 128 selected routes")
    parsed: list[SelectedModelRoute] = []
    endpoint_pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}\Z")
    for value in values:
        if value != value.strip() or value.count("=") != 1:
            raise ConfigError(
                "models refresh routes must use canonical MODEL_ID=PROVIDER_ENDPOINT form"
            )
        model_id, provider_endpoint = value.split("=", 1)
        if (
            not is_exact_openrouter_model_id(model_id)
            or endpoint_pattern.fullmatch(provider_endpoint) is None
        ):
            raise ConfigError("models refresh requires exact non-alias model and endpoint IDs")
        parsed.append(
            SelectedModelRoute(
                exact_model_id=model_id,
                provider_endpoint=provider_endpoint,
            )
        )
    ordered = tuple(
        sorted(
            parsed,
            key=lambda route: (route.exact_model_id, route.provider_endpoint),
        )
    )
    if len(ordered) != len({(route.exact_model_id, route.provider_endpoint) for route in ordered}):
        raise ConfigError("models refresh selected routes must be unique")
    return ordered


def _model_refresh_failure_code(
    error: Exception,
) -> ModelRefreshFailureCode:
    if isinstance(error, OperatorSecretError):
        return ModelRefreshFailureCode.SECRET_PREREQUISITE
    if isinstance(error, OpenRouterAuthenticationError):
        return ModelRefreshFailureCode.AUTHENTICATION
    if isinstance(error, OpenRouterTimeoutError):
        return ModelRefreshFailureCode.NETWORK_TIMEOUT
    if isinstance(error, OpenRouterRateLimitError):
        return ModelRefreshFailureCode.RATE_LIMIT
    if isinstance(error, OpenRouterProviderUnavailableError):
        return ModelRefreshFailureCode.PROVIDER_UNAVAILABLE
    return ModelRefreshFailureCode.MALFORMED_METADATA


def _require_real_qualification_portfolio(
    portfolio: ModelBenchmarkPortfolio,
    *,
    policy: QualificationPolicy,
) -> None:
    validate_qualification_portfolio_readiness(portfolio=portfolio, policy=policy)


def _require_qualification_release_pins(
    *,
    config: AuditConfig,
    policy: QualificationPolicy,
    benchmark_suite: ModelBenchmarkSuite,
) -> None:
    """Bind every production qualification path to release-owned quality inputs."""

    require_maximum_assurance_qualification_pins(
        config,
        policy_sha256=policy.policy_sha256,
        corpus_version=benchmark_suite.corpus.schema_version,
        corpus_sha256=benchmark_suite.corpus_sha256,
        ground_truth_version=benchmark_suite.ground_truth.schema_version,
        ground_truth_sha256=benchmark_suite.ground_truth_sha256,
    )


def _benchmark_request_binding_hashes(
    reports: tuple[ModelBenchmarkReport, ...],
) -> tuple[str, str]:
    """Derive the prompt-set and response-schema hashes from complete report usage."""

    prompt_sets: set[str] = set()
    schema_hashes: set[str] = set()
    if not reports:
        raise ValueError("release binding observation requires non-empty benchmark reports")
    for report in reports:
        if len(report.results) != 1 or not report.results[0].cases:
            raise ValueError("release binding observation requires exact one-model reports")
        records = tuple(
            case.usage_record for case in report.results[0].cases if case.usage_record is not None
        )
        if len(records) != len(report.results[0].cases):
            raise ValueError("release binding observation requires complete benchmark usage")
        prompt_sets.add(canonical_sha256(sorted(record.prompt_sha256 for record in records)))
        schema_hashes.update(
            record.schema_sha256 for record in records if record.schema_sha256 is not None
        )
        if any(record.schema_sha256 is None for record in records):
            raise ValueError("release binding observation requires response-schema hashes")
    if len(prompt_sets) != 1 or len(schema_hashes) != 1:
        raise ValueError("benchmark request bindings differ across qualification reports")
    return prompt_sets.pop(), schema_hashes.pop()


def _observe_qualification_release(
    *,
    config: AuditConfig,
    release_bindings: object,
    release_source_root: Path,
) -> TrustedReleaseBindingObservation:
    """Reconcile release declarations against executing code and sealed isolation."""

    backend = default_isolation_backend(
        config.reproduction.isolation_backend,
        rootless_container_image=config.reproduction.rootless_container_image,
        rootless_container_runtime=config.reproduction.rootless_container_runtime,
    )
    return observe_and_verify_qualification_release(
        release_bindings=release_bindings,
        source_root=release_source_root,
        isolation_backend=backend,
    )


def _validate_audit_production_qualification_inputs(
    *,
    scanner_only: bool,
    bundle_path: Path | None,
    policy_path: Path | None,
    release_bindings_path: Path | None,
    release_source_root: Path | None,
    corpus_path: Path | None,
    ground_truth_path: Path | None,
) -> bool:
    paths = (
        bundle_path,
        policy_path,
        release_bindings_path,
        release_source_root,
        corpus_path,
        ground_truth_path,
    )
    supplied = sum(path is not None for path in paths)
    if scanner_only:
        if supplied:
            raise ConfigError("model qualification inputs are not accepted for a scanner-only run")
        return False
    if supplied not in {0, len(paths)}:
        raise ConfigError(
            "production qualification requires --model-qualification-bundle, "
            "--model-qualification-policy, and "
            "--model-qualification-release-bindings, "
            "--model-qualification-release-source-root, --model-qualification-corpus, "
            "and --model-qualification-ground-truth together"
        )
    return bool(supplied)


async def _load_audit_production_qualification(
    *,
    config: AuditConfig,
    scanner_only: bool,
    bundle_path: Path | None,
    policy_path: Path | None,
    release_bindings_path: Path | None,
    release_source_root: Path | None,
    corpus_path: Path | None,
    ground_truth_path: Path | None,
    secrets_env_file: Path | None,
) -> VerifiedProductionQualification | None:
    supplied = _validate_audit_production_qualification_inputs(
        scanner_only=scanner_only,
        bundle_path=bundle_path,
        policy_path=policy_path,
        release_bindings_path=release_bindings_path,
        release_source_root=release_source_root,
        corpus_path=corpus_path,
        ground_truth_path=ground_truth_path,
    )
    if not supplied:
        return None

    assert bundle_path is not None
    assert policy_path is not None
    assert release_bindings_path is not None
    assert release_source_root is not None
    assert corpus_path is not None
    assert ground_truth_path is not None
    bundle = load_qualification_workflow_bundle(bundle_path)
    policy = load_qualification_policy(policy_path)
    release_bindings = load_qualification_release_bindings(release_bindings_path)
    benchmark_corpus = load_model_benchmark_corpus(
        corpus_path,
        ground_truth_path=ground_truth_path,
    )
    _require_qualification_release_pins(
        config=config,
        policy=policy,
        benchmark_suite=benchmark_corpus,
    )
    if bundle.policy_sha256 != policy.policy_sha256:
        raise ValueError("qualification bundle binds a different production policy")
    if bundle.release_bindings != release_bindings:
        raise ValueError("qualification bundle binds different release inputs")

    artifact_bindings = bundle.qualification_artifact.bindings
    release_projection = {
        "source_commit": release_bindings.source_commit,
        "source_tree_sha256": release_bindings.source_tree_sha256,
        "effective_config_sha256": release_bindings.effective_config_sha256,
        "prompt_sha256": release_bindings.prompt_sha256,
        "response_schema_sha256": release_bindings.response_schema_sha256,
        "toolchain_sha256": release_bindings.toolchain_sha256,
        "isolation_sha256": release_bindings.isolation_sha256,
        "benchmark_corpus_version": release_bindings.benchmark_corpus_version,
        "benchmark_ground_truth_version": (release_bindings.benchmark_ground_truth_version),
    }
    artifact_projection = {key: getattr(artifact_bindings, key) for key in release_projection}
    if artifact_projection != release_projection:
        raise ValueError("qualification artifact differs from current release bindings")
    raise ValueError(
        "persisted qualification artifacts cannot establish live response-content "
        "campaign provenance; a same-process trusted qualification path is required"
    )


def _verify_qualification_campaign(
    *,
    config: AuditConfig,
    campaign_journal: Path,
    cost_ledger: Path | None,
    portfolio: ModelBenchmarkPortfolio,
    reports: tuple[ModelBenchmarkReport, ...],
    registry: CandidateRegistry,
    benchmark_suite: ModelBenchmarkSuite,
    qualification_policy: QualificationPolicy,
) -> None:
    ledger_path = _selected_cost_ledger_path(config, cost_ledger)
    if ledger_path is None:
        raise ConfigError(
            "model qualification requires the existing cost ledger bound to its campaign"
        )
    ledger = AtomicCostLedger.open_existing(
        ledger_path,
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    verify_model_benchmark_portfolio_campaign(
        campaign_journal,
        portfolio=portfolio,
        reports=reports,
        candidate_registry=registry,
        corpus=benchmark_suite,
        effective_config_sha256=config.stable_hash(),
        qualification_policy_sha256=qualification_policy.policy_sha256,
        cost_ledger=ledger,
    )


async def _refetch_qualification_generations(
    *,
    config: AuditConfig,
    secrets_env_file: Path | None,
    registry: CandidateRegistry,
    reports: tuple[ModelBenchmarkReport, ...],
) -> TrustedGenerationVerification:
    """Use only an owned client to authenticate and re-fetch generation metadata."""

    if (
        not config.privacy.require_zdr
        or config.privacy.store_raw_prompts
        or config.privacy.store_raw_responses
        or config.execution.max_json_repair_attempts
        or config.models.provider_policy.allow_fallbacks
    ):
        raise ConfigError(
            "qualification metadata verification requires ZDR, no raw retention, "
            "no output repair, and no provider fallbacks"
        )
    controls = build_openrouter_runtime_controls(config, certification=False)
    budget, usage = _budget_and_usage(config)
    with load_operator_secrets(secrets_env_file, required=True) as operator_secrets:
        if not operator_secrets.openrouter_api_key_present:
            raise ConfigError("OPENROUTER_API_KEY is missing from the operator secret file")
        client = OpenRouterClient(
            api_key=operator_secrets.openrouter_api_key,
            execution=config.execution,
            privacy=config.privacy,
            budget=budget,
            usage=usage,
            provider_policy=controls.provider_policy,
            reasoning_policy=controls.reasoning_policy,
        )
        try:
            return await refetch_trusted_benchmark_generations(
                client=client,
                registry=registry,
                benchmark_reports=reports,
            )
        finally:
            await client.close()


def _parse_qualification_timestamp(value: str) -> datetime:
    if not value or value != value.strip():
        raise ValueError("qualification expiry must be one whole-second UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("qualification expiry must be one whole-second UTC timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0) or parsed.microsecond:
        raise ValueError("qualification expiry must be one whole-second UTC timestamp")
    return parsed.astimezone(UTC)


def _print_qualification_summary(
    bundle: QualificationWorkflowBundle,
    target: Console,
) -> None:
    for result in bundle.qualification_artifact.results:
        target.print(
            f"model={result.exact_model_id} disposition={result.disposition.value} "
            f"report_sha256={result.benchmark_report_sha256}",
            markup=False,
        )
    verification = bundle.qualification_verification
    target.print(
        f"workflow_sha256={bundle.workflow_sha256} "
        f"artifact_sha256={bundle.qualification_artifact.artifact_sha256} "
        f"verification_valid={str(verification.valid).lower()} "
        f"production_selection_ready="
        f"{str(verification.production_selection_ready).lower()} "
        f"eligible_models={len(verification.eligible_tier_a_model_ids)}",
        markup=False,
    )


def _qualification_semantic_view(
    bundle: QualificationWorkflowBundle,
) -> dict[str, Any]:
    """Remove only fresh-refetch timestamps and their transitive self-hashes."""

    payload = bundle.model_dump(mode="json")
    payload.pop("workflow_sha256", None)
    payload.pop("evaluated_at", None)
    evidence_items = payload.get("trusted_benchmark_evidence", [])
    if isinstance(evidence_items, list):
        for evidence in evidence_items:
            if not isinstance(evidence, dict):
                continue
            evidence.pop("generation_evidence_sha256", None)
            evidence.pop("verification_sha256", None)
            attestations = evidence.get("generation_attestations", [])
            if isinstance(attestations, list):
                for attestation in attestations:
                    if isinstance(attestation, dict):
                        attestation.pop("retrieved_at", None)
                        attestation.pop("evidence_sha256", None)
    artifact = payload.get("qualification_artifact")
    if isinstance(artifact, dict):
        artifact.pop("artifact_sha256", None)
        artifact.pop("created_at", None)
        results = artifact.get("results", [])
        if isinstance(results, list):
            for result in results:
                if isinstance(result, dict):
                    result.pop("benchmark_verification_sha256", None)
                    result.pop("evaluated_at", None)
                    result.pop("result_sha256", None)
    verification = payload.get("qualification_verification")
    if isinstance(verification, dict):
        verification.pop("artifact_sha256", None)
        verification.pop("verified_at", None)
        verification.pop("verification_sha256", None)
    return payload


def _preflight_model_discovery_output_dir(path: Path) -> None:
    absolute = path.absolute()
    if is_sensitive_workspace_name(absolute.name):
        raise ConfigError("refusing a sensitive model discovery output directory")
    if any(
        candidate.is_symlink() or candidate.is_junction()
        for candidate in (absolute, *absolute.parents)
    ):
        raise ConfigError("model discovery output may not traverse filesystem links")
    if absolute.exists():
        raise ConfigError("model discovery output directory must be fresh")
    absolute.parent.mkdir(parents=True, exist_ok=True)
    if absolute.parent.is_symlink() or absolute.parent.is_junction():
        raise ConfigError("model discovery output parent must be a regular non-link directory")
    try:
        with tempfile.NamedTemporaryFile(
            dir=absolute.parent,
            prefix=".mmaudit-model-discovery-preflight-",
            delete=True,
        ):
            pass
    except OSError as exc:
        raise ConfigError("model discovery output directory is not writable") from exc


def _preflight_model_benchmark_output(
    output: Path,
    ledger: AtomicCostLedger,
) -> None:
    """Prove a paid benchmark can persist its report without touching budget state."""

    output_parent = output.absolute().parent
    output_parent.mkdir(parents=True, exist_ok=True)
    if is_sensitive_workspace_name(output.name):
        raise ConfigError("refusing a sensitive model benchmark output filename")
    candidate = output.absolute().resolve(strict=False)
    protected = {
        ledger.path.resolve(strict=True),
        ledger.lock_path.resolve(strict=True),
    }
    if candidate in protected:
        raise ConfigError("model benchmark output must be distinct from cost-ledger state")
    if output.exists():
        if output.is_symlink() or output.is_junction():
            raise ConfigError("model benchmark output may not be a link")
        metadata = output.stat()
        if not output.is_file() or metadata.st_nlink != 1:
            raise ConfigError("model benchmark output must be an unshared regular file")
        if any(output.samefile(path) for path in protected):
            raise ConfigError("model benchmark output must be distinct from cost-ledger state")
    try:
        with tempfile.NamedTemporaryFile(
            dir=output_parent,
            prefix=".mmaudit-model-benchmark-preflight-",
            delete=True,
        ):
            pass
    except OSError as exc:
        raise ConfigError("model benchmark output directory is not writable") from exc


def _preflight_model_benchmark_portfolio_output(
    output: Path,
    ledger: AtomicCostLedger,
) -> None:
    """Require a fresh non-link directory target distinct from paid budget state."""

    absolute = Path(os.path.abspath(output))
    if is_sensitive_workspace_name(absolute.name):
        raise ConfigError("refusing a sensitive model benchmark portfolio directory")
    if any(
        candidate.is_symlink() or candidate.is_junction()
        for candidate in (absolute, *absolute.parents)
    ):
        raise ConfigError("model benchmark portfolio path may not traverse links")
    if absolute.exists():
        raise ConfigError("model benchmark portfolio destination must be fresh")
    protected = {
        ledger.path.resolve(strict=True),
        ledger.lock_path.resolve(strict=True),
    }
    if absolute.resolve(strict=False) in protected:
        raise ConfigError("model benchmark output must be distinct from cost-ledger state")
    absolute.parent.mkdir(parents=True, exist_ok=True)
    if absolute.parent.is_symlink() or absolute.parent.is_junction():
        raise ConfigError("model benchmark portfolio parent must be a regular directory")
    try:
        with tempfile.NamedTemporaryFile(
            dir=absolute.parent,
            prefix=".mmaudit-model-portfolio-preflight-",
            delete=True,
        ):
            pass
    except OSError as exc:
        raise ConfigError("model benchmark portfolio directory is not writable") from exc


def _preflight_model_calibration_output(
    output: Path,
    *,
    cost_ledger_path: Path,
    portfolio_output: Path,
    campaign_journal: Path,
) -> None:
    """Prove the fresh private calibration file can be published before ledger access."""

    absolute = Path(os.path.abspath(output))
    if is_sensitive_workspace_name(absolute.name):
        raise ConfigError("refusing a sensitive model calibration output filename")
    if any(
        candidate.is_symlink() or candidate.is_junction()
        for candidate in (absolute, *absolute.parents)
    ):
        raise ConfigError("model calibration output may not traverse filesystem links")
    if os.path.lexists(absolute):
        raise ConfigError("model calibration output must be a fresh file")
    ledger = Path(os.path.abspath(cost_ledger_path))
    protected = (
        ledger,
        ledger.parent / f".{ledger.name}.lock",
        Path(os.path.abspath(portfolio_output)),
        Path(os.path.abspath(campaign_journal)),
    )
    if any(
        absolute == candidate
        or absolute.is_relative_to(candidate)
        or candidate.is_relative_to(absolute)
        for candidate in protected
    ):
        raise ConfigError(
            "model calibration output must be distinct from campaign, portfolio, and ledger state"
        )
    absolute.parent.mkdir(parents=True, exist_ok=True)
    if absolute.parent.is_symlink() or absolute.parent.is_junction():
        raise ConfigError("model calibration output parent must be a regular directory")
    try:
        with tempfile.NamedTemporaryFile(
            dir=absolute.parent,
            prefix=".mmaudit-model-calibration-preflight-",
            delete=True,
        ):
            pass
    except OSError as exc:
        raise ConfigError("model calibration output directory is not writable") from exc


def _preflight_calibrated_policy_output(
    output: Path,
    *,
    cost_ledger_path: Path,
    portfolio_output: Path,
    campaign_journal: Path,
    calibration_output: Path,
) -> None:
    """Reject an unsafe P2 destination before opening paid ledger or secret state."""

    absolute = Path(os.path.abspath(output))
    if is_sensitive_workspace_name(absolute.name):
        raise ConfigError("refusing a sensitive calibrated policy output filename")
    if any(
        candidate.is_symlink() or candidate.is_junction()
        for candidate in (absolute, *absolute.parents)
    ):
        raise ConfigError("calibrated policy output may not traverse filesystem links")
    if os.path.lexists(absolute):
        raise ConfigError("calibrated policy output must be a fresh file")

    ledger = Path(os.path.abspath(cost_ledger_path))
    ledger_lock = ledger.parent / f".{ledger.name}.lock"
    protected = (
        ledger,
        ledger_lock,
        Path(os.path.abspath(portfolio_output)),
        Path(os.path.abspath(campaign_journal)),
        Path(os.path.abspath(calibration_output)),
    )
    if any(
        absolute == candidate
        or absolute.is_relative_to(candidate)
        or candidate.is_relative_to(absolute)
        for candidate in protected
    ):
        raise ConfigError(
            "calibrated policy output must be distinct from calibration, campaign, "
            "portfolio, and ledger state"
        )
    absolute.parent.mkdir(parents=True, exist_ok=True)
    if absolute.parent.is_symlink() or absolute.parent.is_junction():
        raise ConfigError("calibrated policy output parent must be a regular directory")
    try:
        with tempfile.NamedTemporaryFile(
            dir=absolute.parent,
            prefix=".mmaudit-calibrated-policy-preflight-",
            delete=True,
        ):
            pass
    except OSError as exc:
        raise ConfigError("calibrated policy output directory is not writable") from exc


def _print_candidate_benchmark_diagnostics(
    execution: CandidateBenchmarkExecutionResult,
    *,
    target: Console,
) -> None:
    reports = {report.results[0].target.model_id: report for report in execution.reports}
    for diagnostic in execution.diagnostics:
        report = reports[diagnostic.exact_model_id]
        target.print(
            f"{diagnostic.exact_model_id}: status={diagnostic.state.value}; "
            f"evidence={diagnostic.execution_evidence.value}; "
            f"report={diagnostic.report_sha256}; "
            f"accounted_cost_usd={_model_benchmark_report_cost(report)}",
            markup=False,
        )


def _model_benchmark_report_cost(report: ModelBenchmarkReport) -> str:
    total = sum(
        (
            Decimal(str(case.usage_record.accounted_cost_usd))
            for result in report.results
            for case in result.cases
            if case.usage_record is not None
        ),
        Decimal(0),
    )
    rendered = format(total, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered if rendered not in {"", "-0"} else "0"


def _cache_path(config_path: Path) -> Path:
    return config_path.resolve().parent / ".mmaudit" / "cache" / "openrouter-models.json"


async def _model_metadata(
    config: AuditConfig,
    config_path: Path,
    *,
    api_key: str,
    refresh: bool,
) -> list[dict[str, Any]]:
    if not api_key:
        raise ConfigError("OPENROUTER_API_KEY is missing from the operator secret file")
    registry = ModelRegistry(_cache_path(config_path))
    cached = None if refresh else registry.load_cache()
    if cached is not None:
        return cached
    budget, usage = _budget_and_usage(config)
    controls = build_openrouter_runtime_controls(
        config,
        certification=False,
    )
    client = OpenRouterClient(
        api_key=api_key,
        execution=config.execution,
        privacy=config.privacy,
        budget=budget,
        usage=usage,
        provider_policy=controls.provider_policy,
        reasoning_policy=controls.reasoning_policy,
    )
    try:
        metadata = await client.list_models()
    finally:
        await client.close()
    registry.save_cache(metadata)
    return metadata


def _openrouter_authentication_valid(config: AuditConfig, api_key: str) -> bool:
    async def validate() -> bool:
        budget, usage = _budget_and_usage(config)
        controls = build_openrouter_runtime_controls(
            config,
            certification=False,
        )
        client = OpenRouterClient(
            api_key=api_key,
            execution=config.execution,
            privacy=config.privacy,
            budget=budget,
            usage=usage,
            provider_policy=controls.provider_policy,
            reasoning_policy=controls.reasoning_policy,
        )
        try:
            await client.validate_authentication()
            return True
        except OpenRouterError:
            return False
        finally:
            await client.close()

    try:
        return asyncio.run(validate())
    except (OSError, ValueError):
        return False


def _run_async_cli(function: Any) -> None:
    try:
        asyncio.run(function())
    except (ConfigError, CostLedgerError, OpenRouterError, OSError, ValueError) as exc:
        console.print(f"mmaudit failed safely: {exc}", style="red", markup=False)
        raise typer.Exit(ExitCode.CONFIGURATION) from exc


def _print_finding(finding: Finding, target: Console) -> None:
    target.rule(Text(f"{_terminal_text(finding.id)}: {_terminal_text(finding.title)}"))
    target.print(
        f"Status: {finding.status.value}  Severity: {finding.severity.value}  "
        f"Confidence: {finding.confidence:.2f}",
        markup=False,
    )
    target.print(f"Summary: {_terminal_text(finding.summary)}", markup=False)
    target.print(f"Impact: {_terminal_text(finding.impact)}", markup=False)
    target.print("Preconditions:", markup=False)
    for precondition in finding.preconditions:
        target.print(f"  {_terminal_text(precondition)}", markup=False)
    target.print("Attack path:", markup=False)
    for index, step in enumerate(finding.attack_path, start=1):
        target.print(f"  {index}. {_terminal_text(step)}", markup=False)
    target.print("Locations:", markup=False)
    for location in finding.locations:
        target.print(
            f"  {_terminal_text(location.path)}:{location.start_line}-{location.end_line}"
            + (f" ({_terminal_text(location.symbol)})" if location.symbol else ""),
            markup=False,
        )
    target.print("Evidence:", markup=False)
    for evidence in finding.evidence:
        target.print(
            f"  [{evidence.type}] {_terminal_text(evidence.source)}"
            + (f"/{_terminal_text(evidence.rule_id)}" if evidence.rule_id else "")
            + f": {_terminal_text(evidence.description)}",
            markup=False,
        )
    target.print("Model opinions:", markup=False)
    for vote in finding.model_votes:
        target.print(
            f"  {_terminal_text(vote.role)} ({_terminal_text(vote.requested_model)}; "
            f"family {_terminal_text(vote.family)}): {_terminal_text(vote.verdict)} — "
            f"{_terminal_text(vote.rationale)}",
            markup=False,
        )
    target.print(
        f"Location validation: {'valid' if finding.location_validation.valid else 'invalid'}",
        markup=False,
    )
    for error in finding.location_validation.errors:
        target.print(f"  {_terminal_text(error)}", markup=False)
    if finding.disagreement:
        target.print(
            f"Verifier/judge reasoning: {_terminal_text(finding.disagreement)}",
            markup=False,
        )
    if finding.compensating_controls:
        target.print("Compensating controls:", markup=False)
        for control in finding.compensating_controls:
            target.print(f"  {_terminal_text(control)}", markup=False)
    target.print("False-positive conditions:", markup=False)
    for condition in finding.false_positive_conditions:
        target.print(f"  {_terminal_text(condition)}", markup=False)
    target.print(f"Recommendation: {_terminal_text(finding.recommendation)}", markup=False)
    if finding.verification_test is not None:
        target.print(
            f"Safe local verification: "
            f"{_terminal_text(finding.verification_test.description)} "
            f"(safe={finding.verification_test.safe})",
            markup=False,
        )


def _terminal_text(value: str) -> str:
    """Strip terminal control characters from untrusted report fields."""

    sanitized = "".join(
        character if ord(character) >= 32 and ord(character) != 127 else " " for character in value
    )
    return " ".join(sanitized.split())
