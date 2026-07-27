"""Typer command-line interface for mmaudit."""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from importlib.resources import files
from pathlib import Path
from typing import Annotated, Any, Literal

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from mmaudit.benchmark.certificate import (
    CertificateVerificationStatus,
    build_file_backed_benchmark_certificate,
    load_benchmark_certificate_file_inputs,
    verify_file_backed_benchmark_certificate,
    write_benchmark_certificate,
    write_benchmark_certificate_verification,
)
from mmaudit.benchmark.claims import load_human_comparison_evidence
from mmaudit.benchmark.engine import (
    BenchmarkStatus,
    evaluate_benchmark,
    load_manifest,
    load_reports,
    validate_benchmark_ground_truth,
    write_benchmark_report,
)
from mmaudit.benchmark.models import (
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
    ConfigError,
    configured_model_ids,
    load_config,
    validate_model_independence,
)
from mmaudit.constants import DEFAULT_CONFIG_NAME, VERSION, ExitCode
from mmaudit.logging import configure_logging
from mmaudit.models.openrouter import OpenRouterClient, OpenRouterError
from mmaudit.models.registry import ModelRegistry, extract_zdr_model_ids
from mmaudit.models.schemas import AuditProfile, AuditReport, AuditScope, Finding, Severity
from mmaudit.models.usage import UsageLedger
from mmaudit.operator_secrets import (
    OperatorSecretError,
    OperatorSecrets,
    load_operator_secrets,
)
from mmaudit.orchestration.budgets import BudgetManager
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
from mmaudit.repository.discovery import RepositorySafetyError, safe_repository_root
from mmaudit.scanners.runner import ScannerRunner
from mmaudit.snapshots.importer import (
    ReadOnlySnapshotImporter,
    load_snapshot_import_plan,
)
from mmaudit.snapshots.schema import write_deployment_snapshot
from mmaudit.solidity.reproduction import default_isolation_backend

app = typer.Typer(
    name="mmaudit",
    help="Defensive repository-aware multi-model security auditor.",
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
    """Run bounded scanners and independently configured model review roles."""


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
        typer.Option("--profile", help="Audit profile override for diagnostics."),
    ] = None,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Check local safety, credentials, scanners, and model independence."""

    local_console = Console(no_color=no_color)
    try:
        config = load_config(config_path)
        config = _apply_overrides(
            config,
            budget_usd=None,
            max_files=None,
            max_file_bytes=None,
            max_context_bytes=None,
            concurrency=None,
            require_zdr=False,
            profile=profile,
            fork_rpc_url_env=fork_rpc_url_env,
        )
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
    checks.append(
        _writable_output_check(output_path)
        if repository_ok
        else ("Output directory", False, "not checked because repository scope is invalid", True)
    )
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
    for name, adapter in ScannerRunner(config).adapters.items():
        enabled = getattr(config.scanners, name).enabled
        required = getattr(config.scanners, name).required
        available = adapter.available()
        checks.append(
            (
                f"Scanner: {name}",
                available or not enabled or not required,
                "available" if available else ("disabled" if not enabled else "unavailable"),
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
            "Zero Data Retention",
            config.privacy.require_zdr,
            "required" if config.privacy.require_zdr else "not required",
            True,
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
        table.add_row(name, "[green]PASS[/green]" if ok else "[red]FAIL[/red]", detail)
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
        table.add_column("Structured JSON")
        for item in metadata:
            parameters = {str(value).lower() for value in item.get("supported_parameters", [])}
            structured = bool({"response_format", "structured_outputs", "json_schema"} & parameters)
            table.add_row(
                Text(_terminal_text(str(item.get("id", "")))),
                Text(_terminal_text(str(item.get("name", "")))),
                Text(_terminal_text(str(item.get("context_length", "")))),
                Text("yes" if structured else "no"),
            )
        Console(no_color=no_color).print(table)

    _run_async_cli(execute)


@models_app.command("check")
def models_check(
    config_path: ConfigOption = Path(DEFAULT_CONFIG_NAME),
    secrets_env_file: SecretsEnvFileOption = None,
    refresh: Annotated[bool, typer.Option("--refresh", help="Ignore cached metadata.")] = False,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Verify existence, structured JSON, ZDR, duplicates, and independence."""

    async def execute() -> None:
        config = load_config(config_path)
        errors = validate_model_independence(config)
        with load_operator_secrets(secrets_env_file, required=True) as operator_secrets:
            if not operator_secrets.openrouter_api_key_present:
                raise ConfigError("OPENROUTER_API_KEY is missing from the operator secret file")
            budget, usage = _budget_and_usage(config)
            client = OpenRouterClient(
                api_key=operator_secrets.openrouter_api_key,
                execution=config.execution,
                privacy=config.privacy,
                budget=budget,
                usage=usage,
            )
            try:
                registry = ModelRegistry(_cache_path(config_path))
                metadata = None if refresh else registry.load_cache()
                if metadata is None:
                    metadata = await client.list_models()
                    registry.save_cache(metadata)
                zdr_ids = None
                if config.privacy.require_zdr:
                    zdr_ids = extract_zdr_model_ids(await client.list_zdr_endpoints())
                    if not zdr_ids:
                        errors.append("ZDR endpoint eligibility could not be verified")
                errors.extend(
                    registry.validate(
                        config,
                        metadata,
                        zdr_model_ids=zdr_ids,
                        source_egress_requested=True,
                    )
                )
            finally:
                await client.close()
        if errors:
            raise ConfigError("; ".join(errors))
        Console(no_color=no_color).print(
            f"[green]Validated {len(configured_model_ids(config, include_fallbacks=True))} "
            "configured model IDs.[/green]"
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
    output: Annotated[
        Path,
        typer.Option("--output", help="Destination for the model benchmark report."),
    ] = Path("model-benchmark-results.json"),
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
        config = load_config(config_path)
        benchmark_corpus = load_model_benchmark_corpus(corpus)
        targets = select_model_benchmark_targets(config, model)
        validate_model_benchmark_egress(
            config,
            targets,
            explicitly_allowed=allow_code_egress,
        )
        with load_operator_secrets(secrets_env_file, required=True) as operator_secrets:
            if not operator_secrets.openrouter_api_key_present:
                raise ConfigError("OPENROUTER_API_KEY is missing from the operator secret file")
            budget, usage = _budget_and_usage(config)
            client = OpenRouterClient(
                api_key=operator_secrets.openrouter_api_key,
                execution=config.execution,
                privacy=config.privacy,
                budget=budget,
                usage=usage,
            )
            try:
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
        typer.Option("--profile", help="Audit profile override."),
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
            help="Fail unless every maximum-assurance contract clause passes.",
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
        typer.Option("--solidity/--no-solidity", help="Enable or disable Solidity discovery."),
    ] = None,
    compile_solidity: Annotated[
        bool | None,
        typer.Option(
            "--compile/--no-compile", help="Opt in or out of isolated Solidity compilation."
        ),
    ] = None,
    run_slither: Annotated[
        bool,
        typer.Option("--run-slither", help="Run Slither when installed."),
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
    """Run deterministic scanners only and emit JSON plus SARIF."""

    _execute_audit(
        config_path=config_path,
        secrets_env_file=secrets_env_file,
        repo=repo,
        output=output,
        budget_usd=None,
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
        profile=profile,
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


@app.command("run")
def run_command(
    config_path: ConfigOption = Path(DEFAULT_CONFIG_NAME),
    secrets_env_file: SecretsEnvFileOption = None,
    repo: Annotated[Path | None, typer.Option("--repo")] = None,
    output: Annotated[Path | None, typer.Option("--output")] = None,
    budget_usd: Annotated[float | None, typer.Option("--budget-usd", min=0.01)] = None,
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
    profile: Annotated[
        AuditProfile | None,
        typer.Option("--profile", help="Audit profile override."),
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
            help="Fail unless every maximum-assurance contract clause passes.",
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
        typer.Option("--solidity/--no-solidity", help="Enable or disable Solidity discovery."),
    ] = None,
    compile_solidity: Annotated[
        bool | None,
        typer.Option(
            "--compile/--no-compile", help="Opt in or out of isolated Solidity compilation."
        ),
    ] = None,
    run_slither: Annotated[
        bool,
        typer.Option("--run-slither", help="Run Slither when installed."),
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
    """Run scanners, configured independent roles, verification, and evidence-capped judgment."""

    _execute_audit(
        config_path=config_path,
        secrets_env_file=secrets_env_file,
        repo=repo,
        output=output,
        budget_usd=budget_usd,
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
        profile=profile,
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
            limitations = [
                "no audit-report directory supplied; corpus validated but no audit quality "
                "measurement was performed"
            ]
        else:
            loaded, limitations = load_reports(reports, repository_ids)
        benchmark = evaluate_benchmark(
            manifest,
            loaded,
            profile=profile,
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
        f"recall={benchmark.recall:.1%}, "
        f"critical_recall={benchmark.critical_recall:.1%}, "
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
    config_path: ConfigOption = Path(DEFAULT_CONFIG_NAME),
    output: Annotated[
        Path,
        typer.Option("--output", help="Destination for normalized verification evidence."),
    ] = Path("run-verification.json"),
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Verify run sources, projections, artifacts, and certificates without execution."""

    local_console = Console(no_color=no_color)
    try:
        verification = verify_run_evidence(
            manifest_path=manifest,
            run_dir=run_dir,
            repository_root=repository,
            config=load_config(config_path),
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
    config_path: ConfigOption = Path(DEFAULT_CONFIG_NAME),
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
        replay = asyncio.run(
            OfflineReplayOrchestrator(load_config(config_path)).replay(
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
    profile: AuditProfile | None,
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
) -> None:
    operator_secrets = OperatorSecrets()
    pipeline: AuditPipeline | None = None
    try:
        if not scanner_only:
            operator_secrets = load_operator_secrets(secrets_env_file, required=True)
        config = load_config(config_path)
        config = _apply_overrides(
            config,
            budget_usd=budget_usd,
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_context_bytes=max_context_bytes,
            concurrency=concurrency,
            require_zdr=require_zdr,
            profile=profile,
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
        )
        benchmark_required = (
            config.maximum_assurance.benchmark_gate or config.maximum_assurance.ci_mode
        )
        benchmark_inputs = (
            benchmark_certificate,
            benchmark_component_root,
            benchmark_repository_commit,
        )
        benchmark_verification = None
        if benchmark_required:
            if any(value is None for value in benchmark_inputs):
                raise ConfigError(
                    "benchmark gate requires --benchmark-certificate, "
                    "--benchmark-component-root, and --benchmark-repository-commit"
                )
            assert benchmark_certificate is not None
            assert benchmark_component_root is not None
            assert benchmark_repository_commit is not None
            benchmark_verification = verify_file_backed_benchmark_certificate(
                benchmark_certificate,
                component_root=benchmark_component_root,
                repository_git_commit=benchmark_repository_commit,
            )
            if benchmark_verification.status is not CertificateVerificationStatus.CURRENT:
                raise ConfigError("benchmark certificate is stale")
        elif any(value is not None for value in benchmark_inputs):
            raise ConfigError(
                "benchmark certificate inputs require --benchmark-gate or a configured gate"
            )
        repo_path = _repo_path(config, config_path, repo)
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
            api_key=operator_secrets.openrouter_api_key,
            logger=logger,
        )
        result = asyncio.run(
            pipeline.run(
                scanner_only=scanner_only,
                allow_code_egress=allow_code_egress,
                skip_codeql=skip_codeql,
                changed_since=changed_since,
                severity_threshold=severity_threshold,
                allow_fork_probing=allow_fork_probing,
                require_maximum_assurance=require_maximum_assurance,
                allow_maximum_assurance_downgrade=allow_maximum_assurance_downgrade,
                benchmark_verification=benchmark_verification,
            )
        )
        Console(no_color=no_color).print(f"Reports: {result.run_dir}")
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


SecretlessErrors = (ConfigError, RepositorySafetyError, OpenRouterError, OSError, ValueError)


def _apply_overrides(
    config: AuditConfig,
    *,
    budget_usd: float | None,
    max_files: int | None,
    max_file_bytes: int | None,
    max_context_bytes: int | None,
    concurrency: int | None,
    require_zdr: bool,
    profile: AuditProfile | None = None,
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
) -> AuditConfig:
    execution_updates = {
        key: value
        for key, value in {
            "budget_usd": budget_usd,
            "concurrency": concurrency,
        }.items()
        if value is not None
    }
    repository_updates = {
        key: value
        for key, value in {
            "max_files": max_files,
            "max_file_bytes": max_file_bytes,
            "max_total_context_bytes": max_context_bytes,
        }.items()
        if value is not None
    }
    privacy_updates = {"require_zdr": True} if require_zdr else {}
    top_level_updates = {"profile": profile} if profile is not None else {}
    scope_updates = {
        key: value
        for key, value in {
            "mode": scope,
            "require_complete": require_complete_scope,
        }.items()
        if value is not None
    }
    if require_maximum_assurance and allow_maximum_assurance_downgrade:
        raise ConfigError(
            "--require-maximum-assurance and --allow-maximum-assurance-downgrade "
            "cannot be used together"
        )
    maximum_assurance_updates = {
        key: value
        for key, value in {
            "require": True if require_maximum_assurance else None,
            "allow_downgrade": (True if allow_maximum_assurance_downgrade else None),
            "minimum_model_families": min_model_families,
            "minimum_specialist_agents": min_specialist_agents,
            "require_reproduction_for_critical": require_reproduction_for_critical,
            "require_formal_or_reproduction_for_confirmed_critical": (
                require_formal_or_reproduction_for_confirmed_critical
            ),
            "benchmark_gate": True if benchmark_gate else None,
        }.items()
        if value is not None
    }
    model_updates = (
        {"minimum_distinct_families": min_model_families} if min_model_families is not None else {}
    )
    smart_contract_updates = {
        key: value
        for key, value in {
            "enabled": solidity,
            "compile": compile_solidity,
            "allow_network": True if allow_network else None,
            "framework": framework,
            "project_root": project_root,
            "fork_rpc_url_env": fork_rpc_url_env,
        }.items()
        if value is not None
    }
    scanner_updates = {}
    if run_slither:
        scanner_updates["slither"] = config.scanners.slither.model_copy(update={"enabled": True})
    return config.model_copy(
        update={
            **top_level_updates,
            "scope": config.scope.model_copy(update=scope_updates),
            "execution": config.execution.model_copy(update=execution_updates),
            "repository": config.repository.model_copy(update=repository_updates),
            "privacy": config.privacy.model_copy(update=privacy_updates),
            "maximum_assurance": config.maximum_assurance.model_copy(
                update=maximum_assurance_updates
            ),
            "models": config.models.model_copy(update=model_updates),
            "smart_contracts": config.smart_contracts.model_copy(update=smart_contract_updates),
            "scanners": config.scanners.model_copy(update=scanner_updates),
        }
    ).effective()


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


def platform_python() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def _budget_and_usage(config: AuditConfig) -> tuple[BudgetManager, UsageLedger]:
    return (
        BudgetManager(
            total_usd=config.execution.budget_usd,
            max_output_tokens=config.execution.max_output_tokens_per_request,
            conservative_usd_per_million_tokens=(
                config.execution.conservative_usd_per_million_tokens
            ),
            max_requests_per_agent=config.execution.max_requests_per_agent,
        ),
        UsageLedger(),
    )


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
    client = OpenRouterClient(
        api_key=api_key,
        execution=config.execution,
        privacy=config.privacy,
        budget=budget,
        usage=usage,
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
        client = OpenRouterClient(
            api_key=api_key,
            execution=config.execution,
            privacy=config.privacy,
            budget=budget,
            usage=usage,
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
    except (ConfigError, OpenRouterError, OSError, ValueError) as exc:
        console.print(f"[red]mmaudit failed safely:[/red] {exc}")
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
