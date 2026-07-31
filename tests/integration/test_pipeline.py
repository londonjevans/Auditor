from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from mmaudit.agents.specialists import build_specialist_execution_records
from mmaudit.benchmark.certificate import (
    BenchmarkCertificateVerification,
    CertificateVerificationOrigin,
    CertificateVerificationStatus,
    FileBackedBenchmarkVerificationEvidence,
)
from mmaudit.config import (
    AuditConfig,
    AuditConfigOverrides,
    canonical_audit_config_json,
    configured_model_ids,
)
from mmaudit.constants import ALL_SPECIALIST_ROLES, ExitCode
from mmaudit.isolation.dependencies import dependency_tree_sha256
from mmaudit.models.openrouter import OpenRouterClient, OpenRouterRequestLimitError
from mmaudit.models.runtime import build_openrouter_runtime_controls
from mmaudit.models.schemas import (
    AnalysisState,
    AuditProfile,
    AuditQualityStatus,
    AuditReport,
    AuditRunStatus,
    AuditScope,
    AuditScopeAssessment,
    CandidateFinding,
    CandidateFindingArtifact,
    CandidateOriginKind,
    CompilationStatus,
    ContextPackage,
    DependencyPreparationResult,
    DependencyPreparationStatus,
    DependencySbom,
    EconomicSimulationKind,
    ExecutionEvidenceKind,
    FindingOriginKind,
    FindingStatus,
    FormalToolRun,
    FormalToolStatus,
    GeneratedFoundryTestSpec,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    LocalInvariantDeployment,
    LocalInvariantDeploymentArgument,
    Location,
    MaximumAssuranceStatus,
    ModelReviewCoverage,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewArtifact,
    PriorAuditComparison,
    PriorAuditDiscoveryStatus,
    PriorAuditRemediationStatus,
    PropertyCorpus,
    RepositoryDifferentialRunStatus,
    RepositorySuiteDifferentialRun,
    ReproductionAttemptEvidence,
    ReproductionMinimizationEvidence,
    ReproductionResolutionKind,
    ReproductionResult,
    ReproductionState,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
    Severity,
    SolidityCompilationResult,
    SolidityProjectMetadata,
    TransactionOrderingCapability,
    UsageRecord,
)
from mmaudit.models.usage import UsageLedger
from mmaudit.operator_secrets import load_operator_secrets
from mmaudit.orchestration import ci as ci_module
from mmaudit.orchestration.assurance import AssuranceRuntime, MaximumAssuranceContract
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.ci import (
    CIJobStatus,
    CIRunState,
    load_ci_baseline,
    load_ci_baseline_bundle,
)
from mmaudit.orchestration.context_manifest import (
    context_manifest_report_binding,
    load_context_manifest,
    validate_context_manifest_against_usage,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.manifest import (
    RunEvidenceManifest,
    canonical_sha256,
    validate_manifest_artifacts,
    validate_report_privacy_consistency,
    write_run_evidence_manifest,
)
from mmaudit.orchestration.pipeline import AuditPipeline
from mmaudit.orchestration.prior_audit import build_prior_audit_comparison
from mmaudit.orchestration.replay import OfflineReplayOrchestrator
from mmaudit.orchestration.verification import (
    RunVerificationStatus,
    verify_run_evidence,
)
from mmaudit.privacy import (
    REQUIRED_PROHIBITED_CONTENT,
    EndpointPolicyClass,
    EndpointPrivacyDisclosure,
    PrivacyProfile,
    PrivacyRetentionConsent,
    PrivacyRetentionConsentObservation,
    PrivacySourceClassification,
    load_privacy_retention_consent,
)
from mmaudit.reporting.json_report import write_json
from mmaudit.scanners.base import (
    ScannerSourceIntegrityError,
    scanner_fingerprint,
    scanner_workspace_sha256,
)
from mmaudit.scanners.fork_matrix import repository_fork_matrix_timeout_budget_seconds
from mmaudit.solidity.compile import CompilationRun
from mmaudit.solidity.invariant_execution import FoundryInvariantRunner
from mmaudit.solidity.reproduction import translate_foundry_test
from mmaudit.solidity.reproduction_integrity import reproduction_repository_sha256
from mmaudit.traceability import (
    MaximumAssuranceTraceability,
    validate_traceability_evidence,
)
from tests.conftest import FIXTURES, model_registry_entry
from tests.fake_openrouter import FakeOpenRouter, _request_schema_name
from tests.qualification_support import synthetic_production_qualification
from tests.unit.test_execution_candidates import _inputs as _execution_origin_inputs


class StaticScannerRunner:
    def __init__(
        self,
        *,
        status: ScannerStatus = ScannerStatus.SUCCESS,
        required: bool = False,
        finding_path: str = "app.py",
        finding_line: int = 13,
        scanner_name: str = "semgrep",
        before_return: Callable[[], None] | None = None,
        source_integrity_error: bool = False,
    ) -> None:
        self.status = status
        self.required = required
        self.finding_path = finding_path
        self.finding_line = finding_line
        self.scanner_name = scanner_name
        self.before_return = before_return
        self.source_integrity_error = source_integrity_error
        self.expected_repository_sha256: str | None = None
        self.repository_exclusion_root: Path | None = None
        self.audited_relative_paths: tuple[str, ...] = ()
        self.calls = 0

    async def run_all(
        self,
        root: Path,
        private_dir: Path,
        *,
        audited_relative_paths: Sequence[str],
        skip_codeql: bool = False,
        allow_fork_probing: bool = False,
        projects: Sequence[SolidityProjectMetadata] = (),
        expected_repository_sha256: str | None = None,
        repository_exclusion_root: Path | None = None,
        allow_custom_repository_exclusion: bool = False,
    ) -> list[ScannerRun]:
        del root, private_dir, skip_codeql, allow_fork_probing, projects
        self.calls += 1
        self.audited_relative_paths = tuple(audited_relative_paths)
        self.expected_repository_sha256 = expected_repository_sha256
        self.repository_exclusion_root = repository_exclusion_root
        del allow_custom_repository_exclusion
        now = datetime.now(UTC)
        findings = []
        if self.status is ScannerStatus.SUCCESS:
            findings = [
                ScannerFinding(
                    scanner=self.scanner_name,
                    rule_id="synthetic-sql-injection",
                    title="Synthetic SQL injection",
                    severity=Severity.HIGH,
                    message="Formatted SQL query",
                    locations=[
                        Location(
                            path=self.finding_path,
                            start_line=self.finding_line,
                            end_line=self.finding_line,
                        )
                    ],
                    cwe=["CWE-89"],
                    fingerprint=scanner_fingerprint(
                        self.scanner_name,
                        "synthetic-sql-injection",
                        self.finding_path,
                        self.finding_line,
                        "Formatted SQL query",
                    ),
                )
            ]
        if self.before_return is not None:
            self.before_return()
        if self.source_integrity_error:
            raise ScannerSourceIntegrityError("synthetic scanner source custody failure")
        return [
            ScannerRun(
                scanner=self.scanner_name,
                status=self.status,
                version="synthetic-1.0",
                started_at=now,
                finished_at=now,
                duration_seconds=0,
                findings=findings,
                error=None if self.status is ScannerStatus.SUCCESS else "synthetic failure",
            )
        ]

    def required_failures(self, runs: list[ScannerRun]) -> list[str]:
        if self.required and runs[0].status is not ScannerStatus.SUCCESS:
            return [f"semgrep: {runs[0].status.value}"]
        return []


class SyntheticValidatedScannerRunner(StaticScannerRunner):
    """Emit schema-valid synthetic runtime evidence for CI artifact integration tests."""

    async def run_all(self, *args: Any, **kwargs: Any) -> list[ScannerRun]:
        runs = await super().run_all(*args, **kwargs)
        run = runs[0].model_copy(
            update={
                "execution_evidence": ExecutionEvidenceKind.REAL,
                "command": ["/trusted/synthetic-scanner", "--machine-output"],
                "executable_sha256": "1" * 64,
                "raw_output_path": "synthetic-scanner/output.json",
                "raw_output_sha256": hashlib.sha256(b"{}").hexdigest(),
                "raw_output_bytes": 2,
                "process_exit_code": 0,
                "isolation_backend": "bubblewrap",
                "isolation_attestation_sha256": "2" * 64,
                "machine_output_validated": True,
            }
        )
        return [
            ScannerRun.model_validate(
                {
                    **run.model_dump(mode="json"),
                    "execution_observation_sha256": (run.expected_execution_observation_sha256()),
                }
            )
        ]


class SyntheticTwoValidatedScannerRunner(SyntheticValidatedScannerRunner):
    """Emit a second successful deterministic scanner for coverage-baseline tests."""

    async def run_all(self, *args: Any, **kwargs: Any) -> list[ScannerRun]:
        runs = await super().run_all(*args, **kwargs)
        second = runs[0].model_copy(
            update={
                "scanner": "gitleaks",
                "findings": [],
                "command": ["/trusted/synthetic-gitleaks", "--machine-output"],
                "executable_sha256": "3" * 64,
                "raw_output_path": "synthetic-gitleaks/output.json",
                "execution_observation_sha256": None,
            }
        )
        second = ScannerRun.model_validate(
            {
                **second.model_dump(mode="json"),
                "execution_observation_sha256": (second.expected_execution_observation_sha256()),
            }
        )
        return [*runs, second]


def _commit_synthetic_repository(repository: Path) -> str:
    """Create one local commit without consulting host Git configuration."""

    executable = shutil.which("git")
    if executable is None:
        pytest.fail("Git is required for the CI baseline integration regression")
    environment = {
        "PATH": str(Path(executable).resolve(strict=True).parent),
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }

    def run_git(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [executable, "-C", str(repository), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            env=environment,
        )

    run_git("init", "--quiet")
    run_git("add", "--all")
    run_git(
        "-c",
        "user.name=Corrovera CI Test",
        "-c",
        "user.email=ci-test@invalid.example",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "-m",
        "Synthetic CI baseline",
    )
    return run_git("rev-parse", "HEAD").stdout.strip()


def _replace_manifest_bound_report(run_dir: Path, report: AuditReport) -> None:
    """Replace the public report and reseal only its manifest file binding."""

    report_path = run_dir / "final-findings.json"
    write_json(report_path, report)
    manifest_path = run_dir / "run-evidence-manifest.json"
    manifest = RunEvidenceManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    payload = manifest.model_dump(mode="json")
    report_bytes = report_path.read_bytes()
    report_binding = next(
        binding for binding in payload["artifacts"] if binding["path"] == report_path.name
    )
    report_binding["sha256"] = hashlib.sha256(report_bytes).hexdigest()
    report_binding["size"] = len(report_bytes)
    payload["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "manifest_sha256"}
    )
    write_run_evidence_manifest(
        manifest_path,
        RunEvidenceManifest.model_validate(payload),
    )


def _copy_ci_public_bundle(run_dir: Path, destination: Path) -> Path:
    destination.mkdir()
    for name in (
        "ci-state.json",
        "final-findings.json",
        "run-evidence-manifest.json",
    ):
        shutil.copyfile(run_dir / name, destination / name)
    return destination.resolve(strict=True)


def _write_resealed_ci_manifest(path: Path, payload: dict[str, Any]) -> None:
    payload["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "manifest_sha256"}
    )
    write_run_evidence_manifest(
        path,
        RunEvidenceManifest.model_validate(payload),
    )


class StaticRepositoryForkMatrixRunner:
    """Capture the pipeline seam without executing a chain or repository code."""

    def __init__(
        self,
        *,
        configuration_sha256: str,
        before_return: Callable[[], None] | None = None,
    ) -> None:
        self.configuration_sha256 = configuration_sha256
        self.before_return = before_return
        self.calls: list[dict[str, Any]] = []

    def run(
        self,
        root: Path,
        private_root: Path,
        *,
        projects: Sequence[SolidityProjectMetadata],
        repository_sha256: str,
        repository_exclusion_root: Path,
        backend: Any,
        baseline_run: ScannerRun,
        absolute_deadline: float,
    ) -> RepositorySuiteDifferentialRun:
        self.calls.append(
            {
                "root": root,
                "private_root": private_root,
                "projects": tuple(projects),
                "repository_sha256": repository_sha256,
                "repository_exclusion_root": repository_exclusion_root,
                "backend": backend,
                "baseline_run": baseline_run,
                "absolute_deadline": absolute_deadline,
            }
        )
        if self.before_return is not None:
            self.before_return()
        return RepositorySuiteDifferentialRun.sealed(
            status=RepositoryDifferentialRunStatus.FAILED,
            configuration_sha256=self.configuration_sha256,
            requested_state_ids=("clean-local", "pinned-local"),
            required_repetitions=2,
            matrix=None,
            limitations=("Synthetic differential dependency remained unavailable.",),
        )


def _repository_fork_matrix_config_override() -> dict[str, Any]:
    return {
        "repository_suite": {
            "fork_matrix_states": [
                {
                    "state_id": "clean-local",
                    "kind": "clean_local",
                    "expected_chain_id": 31_337,
                    "anvil_executable_env": "MMAUDIT_ANVIL_EXECUTABLE",
                    "anvil_version": "anvil Version: 1.3.2-stable",
                    "anvil_sha256": "a" * 64,
                    "hardfork": "cancun",
                    "genesis_timestamp": 1,
                    "startup_timeout_seconds": 5,
                    "shutdown_timeout_seconds": 5,
                },
                {
                    "state_id": "pinned-local",
                    "kind": "pinned_fork",
                    "rpc_url_env": "MMAUDIT_PINNED_FORK_RPC_URL",
                    "expected_chain_id": 1,
                    "pinned_block_number": 20_000_000,
                    "state_source_sha256": "b" * 64,
                },
            ],
            "fork_matrix_repetitions": 2,
        }
    }


class EvidenceMismatchingUsageLedger(UsageLedger):
    """Test-only ledger that attempts to relabel MOCK provider usage as REAL."""

    def add(self, record: UsageRecord) -> None:
        super().add(
            record.model_copy(
                update={"execution_evidence": ExecutionEvidenceKind.REAL},
            )
        )


@pytest.mark.asyncio
async def test_provider_pipeline_requires_existing_cumulative_ledger_before_output(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    output = tmp_path / "provider-output"
    pipeline = AuditPipeline(
        config_factory(),
        repo=vulnerable_repo,
        output=output,
        api_key="synthetic-provider-canary",
        scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match="existing cumulative cost ledger"):
        await pipeline.run(allow_code_egress=True)

    assert not (output / "runs").exists()


@pytest.mark.asyncio
async def test_maximum_assurance_missing_qualification_fails_before_model_transport(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = config_factory(
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        privacy={"fail_on_detected_secret": False},
        maximum_assurance={"allow_downgrade": True},
    ).effective()
    fake = FakeOpenRouter()

    result = await _run(config, vulnerable_repo, tmp_path, fake)

    assert fake.requests == []
    payload = json.loads(
        (result.run_dir / "model-qualification-runtime.json").read_text(encoding="utf-8")
    )
    assert payload["required"]
    assert not payload["valid"]
    assert payload["qualified_model_ids"] == []
    assert any(
        "configured quality hashes are not authorization" in error for error in payload["errors"]
    )
    assert result.report.maximum_assurance is not None
    gate = next(
        requirement
        for requirement in result.report.maximum_assurance.requirements
        if requirement.engine == "production_model_qualification"
    )
    assert not gate.passed
    assert result.report.maximum_assurance.status.value != "COMPLETE"


@pytest.mark.asyncio
async def test_real_injected_client_cannot_establish_provider_session(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = config_factory()
    ledger = AtomicCostLedger.initialize(
        tmp_path / "client-only-ledger.json",
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    client = OpenRouterClient(
        api_key="synthetic-provider-canary",
        execution=config.execution,
        privacy=config.privacy,
        budget=BudgetManager(
            total_usd=config.execution.budget_usd,
            max_output_tokens=config.execution.max_output_tokens_per_request,
            conservative_usd_per_million_tokens=(
                config.execution.conservative_usd_per_million_tokens
            ),
            max_requests_per_agent=config.execution.max_requests_per_agent,
            atomic_ledger=ledger,
            require_endpoint_cost_bound=True,
        ),
        usage=UsageLedger(),
    )
    output = tmp_path / "provider-output"
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=output,
        client=client,
        scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
    )
    try:
        with pytest.raises(
            ValueError,
            match="injected provider clients cannot establish REAL execution provenance",
        ):
            await pipeline.run(allow_code_egress=True)
    finally:
        await client.close()

    assert not (output / "runs").exists()


@pytest.mark.asyncio
async def test_real_injected_client_is_rejected_even_with_selected_ledger(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = config_factory()
    ledger = AtomicCostLedger.initialize(
        tmp_path / "campaign-ledger.json",
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    client = OpenRouterClient(
        api_key="synthetic-provider-canary",
        execution=config.execution,
        privacy=config.privacy,
        budget=BudgetManager(
            total_usd=config.execution.budget_usd,
            max_output_tokens=config.execution.max_output_tokens_per_request,
            conservative_usd_per_million_tokens=(
                config.execution.conservative_usd_per_million_tokens
            ),
            max_requests_per_agent=config.execution.max_requests_per_agent,
            atomic_ledger=ledger,
            require_endpoint_cost_bound=True,
        ),
        usage=UsageLedger(),
    )
    output = tmp_path / "provider-output"
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=output,
        client=client,
        cost_ledger=ledger,
        scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
    )
    try:
        with pytest.raises(
            ValueError,
            match="injected provider clients cannot establish REAL execution provenance",
        ):
            await pipeline.run(allow_code_egress=True)
    finally:
        await client.close()

    assert not (output / "runs").exists()


@pytest.mark.asyncio
async def test_injected_provider_client_rejects_stale_usage_before_work(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    stale_usage = UsageLedger()
    stale_usage.add(
        UsageRecord(
            request_id="stale-before-run",
            role="source_audit",
            execution_evidence=ExecutionEvidenceKind.MOCK,
            requested_model="bravo/borealis-secure",
            model_family="bravo/borealis-secure",
            timestamp=datetime(2025, 1, 1, tzinfo=UTC),
            accounted_cost_usd=1.25,
            prompt_sha256="a" * 64,
            status="failed",
            attempts=1,
        )
    )
    fake = FakeOpenRouter()
    client, http_client = _provider(config, fake, usage=stale_usage)
    output = tmp_path / "provider-output"
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=output,
        client=client,
        scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
    )
    try:
        with pytest.raises(ValueError, match="fresh empty client usage ledger"):
            await pipeline.run(allow_code_egress=True)
    finally:
        await http_client.aclose()

    assert fake.requests == []
    assert not (output / "runs").exists()
    assert [record.request_id for record in stale_usage.records] == ["stale-before-run"]


@pytest.mark.asyncio
async def test_reused_provider_client_cannot_carry_usage_into_another_provider_run(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    fake = FakeOpenRouter()
    client, http_client = _provider(config, fake)
    output = tmp_path / "provider-output"
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=output,
        client=client,
        scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
    )
    try:
        first = await pipeline.run(allow_code_egress=True)
        request_count = len(fake.requests)
        run_directories = tuple((output / "runs").iterdir())
        with pytest.raises(ValueError, match="fresh empty client usage ledger"):
            await pipeline.run(allow_code_egress=True)
    finally:
        await http_client.aclose()

    assert first.exit_code is ExitCode.INCOMPLETE
    assert not first.report.completed
    assert first.report.run_status is AuditRunStatus.INCOMPLETE
    assert request_count > 0
    assert len(fake.requests) == request_count
    assert tuple((output / "runs").iterdir()) == run_directories


@pytest.mark.asyncio
async def test_mock_provider_session_rejects_usage_relabelled_as_real(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = config_factory()
    fake = FakeOpenRouter()
    usage = EvidenceMismatchingUsageLedger()
    client, http_client = _provider(config, fake, usage=usage)
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path / "provider-output",
        client=client,
        scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
    )
    try:
        result = await pipeline.run(allow_code_egress=True)
    finally:
        await http_client.aclose()

    assert result.exit_code is ExitCode.MODEL_FAILURE
    assert any(
        "provider usage execution evidence differs from the established session" in reason
        for reason in result.report.incomplete_reasons
    )
    assert result.report.model_review_coverage is not None
    assert result.report.model_review_coverage.overall.numerator == 0
    assert result.report.maximum_assurance is not None
    assert result.report.maximum_assurance.status is MaximumAssuranceStatus.NOT_REQUESTED


def _current_benchmark_verification() -> BenchmarkCertificateVerification:
    payload = {
        "schema_version": "1.0",
        "certificate_sha256": "a" * 64,
        "status": CertificateVerificationStatus.CURRENT,
        "observed_repository_git_commit": "b" * 40,
        "observed_bindings_sha256": "c" * 64,
        "mismatches": [],
        "origin": CertificateVerificationOrigin.FILE_BACKED,
        "file_backed_evidence": FileBackedBenchmarkVerificationEvidence(
            certificate_loaded=True,
            certificate_file_sha256="d" * 64,
            benchmark_report_loaded=True,
            benchmark_report_file_sha256="e" * 64,
            benchmark_name="Synthetic standard benchmark",
            benchmark_profile=AuditProfile.STANDARD,
            benchmark_report_status="passed",
            benchmark_report_gate_count=1,
            benchmark_reports_expected=1,
            benchmark_reports_loaded=1,
        ).model_dump(mode="json"),
    }
    payload["verification_sha256"] = canonical_sha256(payload)
    return BenchmarkCertificateVerification.model_validate(payload)


def _provider(
    config,
    fake: FakeOpenRouter,
    *,
    api_key: str = "synthetic-test-key",
    usage: UsageLedger | None = None,
) -> tuple[OpenRouterClient, httpx.AsyncClient]:
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(fake.handler),
        base_url="https://fake.openrouter.test",
    )
    usage = usage or UsageLedger()
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
        per_model_usd_caps={
            model: str(cap) for model, cap in config.token_budgets.per_model_cost_budget_usd.items()
        },
        per_role_usd_caps={
            role: str(cap) for role, cap in config.token_budgets.per_role_cost_budget_usd.items()
        },
    )
    controls = build_openrouter_runtime_controls(config, certification=False)
    return (
        OpenRouterClient(
            api_key=api_key,
            execution=config.execution,
            privacy=config.privacy,
            budget=budget,
            usage=usage,
            http_client=http_client,
            provider_policy=controls.provider_policy,
            reasoning_policy=controls.reasoning_policy,
            token_budgets=config.token_budgets,
        ),
        http_client,
    )


async def _run(
    config,
    vulnerable_repo: Path,
    tmp_path: Path,
    fake: FakeOpenRouter,
    *,
    scanner_runner: StaticScannerRunner | None = None,
    reproduction_runner: Any | None = None,
    invariant_runner: Any | None = None,
    formal_runner: Any | None = None,
    allow_fork_probing: bool = False,
    production_qualification=None,
):
    client, http_client = _provider(config, fake)
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path / "output",
        client=client,
        scanner_runner=scanner_runner or StaticScannerRunner(),  # type: ignore[arg-type]
        reproduction_runner=reproduction_runner,
        invariant_runner=invariant_runner,
        formal_runner=formal_runner,
        production_qualification=production_qualification,
    )
    try:
        result = await pipeline.run(
            allow_code_egress=True,
            allow_fork_probing=allow_fork_probing,
        )
    finally:
        await http_client.aclose()
    return result


def _privacy_consent_observation(
    *,
    config,
    target_root: Path,
    control_root: Path,
    profile: PrivacyProfile,
    source_classification: PrivacySourceClassification,
    source_sha256: str,
) -> PrivacyRetentionConsentObservation:
    models = tuple(sorted(set(configured_model_ids(config, include_fallbacks=True))))
    providers = tuple(
        sorted(set(config.models.provider_policy.only) | set(config.models.provider_policy.order))
    )
    disclosures = tuple(
        EndpointPrivacyDisclosure(
            provider_endpoint=provider,
            policy_class=EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED,
            disclosed_retention="Synthetic operator-reviewed temporary retention terms.",
            privacy_policy_reference=f"https://privacy.example.test/provider/{index}",
            privacy_policy_sha256=f"{index + 1:064x}",
        )
        for index, provider in enumerate(providers)
    )
    now = datetime.now(UTC).replace(microsecond=0)
    provisional = PrivacyRetentionConsent.model_construct(
        schema_version="1.0",
        selected_privacy_profile=profile,
        source_classification=source_classification,
        permitted_source_sha256=source_sha256,
        permitted_model_ids=models,
        permitted_provider_endpoints=providers,
        permitted_endpoint_policy_classes=(EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED,),
        endpoint_disclosures=disclosures,
        issued_at=now - timedelta(minutes=5),
        expires_at=now + timedelta(hours=1),
        operator_identity_reference="operator-record:privacy-regression",
        signature_reference=None,
        maximum_cost_usd="250",
        prohibited_content=REQUIRED_PROHIBITED_CONTENT,
        acknowledges_zdr_not_in_force=True,
        consent_sha256="0" * 64,
    )
    payload = provisional.model_dump(mode="json", exclude={"consent_sha256"})
    consent = PrivacyRetentionConsent.model_validate(
        {
            **payload,
            "consent_sha256": canonical_sha256(payload),
        }
    )
    control_root.mkdir(parents=True)
    consent_path = control_root / "privacy-consent.json"
    consent_path.write_text(
        json.dumps(consent.model_dump(mode="json"), sort_keys=True),
        encoding="utf-8",
    )
    consent_path.chmod(0o600)
    return load_privacy_retention_consent(
        consent_path,
        target_root=target_root,
    )


class SyntheticForkReproductionRunner:
    """Integration-test runner that exercises pipeline semantics without forge."""

    def run(
        self,
        *,
        repository_root: Path,
        project: SolidityProjectMetadata,
        candidate: CandidateFinding,
        specification: GeneratedFoundryTestSpec,
        private_dir: Path,
    ) -> ReproductionResult:
        del private_dir
        source = (repository_root / "src" / "Vault.sol").read_text(encoding="utf-8")
        patched = "function withdraw(uint256 amount) external onlyOwner" in source
        return _synthetic_reproduction_result(
            repository_root=repository_root,
            project=project,
            candidate=candidate,
            specification=specification,
            targets={"Vault": "0x2000000000000000000000000000000000000002"},
            reproduced=not patched,
            attempts=2,
            limitation=("patched access control blocked reproduction" if patched else None),
        )


class SyntheticMaximumReproductionRunner:
    """Deterministic integration double; real sandbox behavior is tested separately."""

    isolation_available = True
    backend = None

    def run(
        self,
        *,
        repository_root: Path,
        project: SolidityProjectMetadata,
        candidate: CandidateFinding,
        specification: GeneratedFoundryTestSpec,
        private_dir: Path,
    ) -> ReproductionResult:
        del private_dir
        safe_control = any(
            location.path == "src/SafeControls.sol" for location in candidate.locations
        )
        return _synthetic_reproduction_result(
            repository_root=repository_root,
            project=project,
            candidate=candidate,
            specification=specification,
            targets=SYNTHETIC_MAXIMUM_TARGETS,
            reproduced=not safe_control,
            attempts=3,
            limitation=(
                "synthetic safe control blocked the claimed transition" if safe_control else None
            ),
        )


SYNTHETIC_MAXIMUM_TARGETS = {
    "AccessVault": "0x2000000000000000000000000000000000000002",
    "ReentrantBank": "0x2000000000000000000000000000000000000003",
    "SafeControls": "0x2000000000000000000000000000000000000004",
    "SpotOracleLender": "0x2000000000000000000000000000000000000005",
    "UnsafeUUPS": "0x2000000000000000000000000000000000000006",
}


def _synthetic_reproduction_result(
    *,
    repository_root: Path,
    project: SolidityProjectMetadata,
    candidate: CandidateFinding,
    specification: GeneratedFoundryTestSpec,
    targets: dict[str, str],
    reproduced: bool,
    attempts: int,
    limitation: str | None,
) -> ReproductionResult:
    """Build explicit mocked replay evidence for pipeline-only integration tests."""

    repository_sha256 = reproduction_repository_sha256(repository_root, project)
    generated_source = translate_foundry_test(
        specification,
        targets=targets,
        expected_chain_id=specification.expected_chain_id,
    )
    generated_sha256 = hashlib.sha256(generated_source.encode()).hexdigest()
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    attempt_state = ReproductionState.REPRODUCED if reproduced else ReproductionState.NOT_REPRODUCED
    step_ids = [step.step_id for step in specification.attack_calls]
    minimized = reproduced and len(step_ids) == 1
    return ReproductionResult(
        candidate_id=candidate.candidate_id,
        test_name=specification.name,
        state=(
            ReproductionState.REPRODUCED_AND_MINIMIZED
            if minimized
            else (ReproductionState.REPRODUCED if reproduced else ReproductionState.NOT_REPRODUCED)
        ),
        specification_sha256=hashlib.sha256(specification.model_dump_json().encode()).hexdigest(),
        generated_test_sha256=generated_sha256,
        generated_test_path="private/synthetic/generated.t.sol",
        regression_test_path="private/synthetic/regression.t.sol",
        command=["[MOCK_FORGE]", "test", "--fork-url", "[REDACTED_LOCAL_FORK_RPC]"],
        attempts=attempts,
        successful_attempts=attempts if reproduced else 0,
        original_steps=len(step_ids),
        minimized_steps=len(step_ids),
        duration_seconds=0.01,
        required_block_number=specification.required_block_number,
        expected_chain_id=specification.expected_chain_id,
        assumptions=specification.assumptions,
        limitations=[limitation] if limitation else [],
        isolation_backend="synthetic-integration-isolation",
        repository_sha256=repository_sha256,
        attempt_evidence=[
            ReproductionAttemptEvidence(
                attempt=attempt,
                state=attempt_state,
                repository_sha256=repository_sha256,
                generated_test_sha256=generated_sha256,
                fresh_workspace=True,
                stdout_sha256=empty_sha256,
                stderr_sha256=empty_sha256,
            )
            for attempt in range(1, attempts + 1)
        ],
        minimization_evidence=ReproductionMinimizationEvidence(
            original_step_ids=step_ids,
            retained_step_ids=step_ids,
            removal_trials=[],
            strategy="single_step_trivial" if minimized else "not_attempted",
            proven_minimal=minimized,
        ),
    )


class SyntheticInvariantRunner:
    isolation_available = True

    def run(self, **kwargs: Any) -> Any:
        raise AssertionError(f"unexpected unconfigured invariant harness: {sorted(kwargs)}")


class LocalOnlyInvariantIsolationBackend:
    """Test-only no-network wrapper for generated source-local Forge execution."""

    name = "synthetic-local-only-isolation"
    supports_local_fork_rpc = False

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del workspace, private_dir
        assert rpc_port == 0
        assert "--fork-url" not in command
        return command


class SyntheticFormalRunner:
    def run(self, **kwargs: Any) -> list[FormalToolRun]:
        del kwargs
        return [
            FormalToolRun(
                tool="solc-smtchecker",
                version=None,
                status=FormalToolStatus.UNAVAILABLE,
                failure_reason="synthetic integration environment has no solver",
            )
        ]


def _synthetic_compiler(
    repository_root: Path,
    projects: list[SolidityProjectMetadata],
    config: Any,
    private_dir: Path,
    *,
    backend: Any = None,
) -> CompilationRun:
    del repository_root, config, private_dir, backend
    return CompilationRun(
        results=[
            SolidityCompilationResult(
                status=CompilationStatus.SUCCESS,
                framework=project.project_type,
                project_root=project.project_root,
                command=project.build_command,
                contracts_compiled=["SyntheticMaximumProtocol"],
                warnings=["synthetic integration compiler; no AST artifact emitted"],
            )
            for project in projects
        ],
        artifact_roots=[],
    )


def _maximum_specialists() -> dict[str, dict[str, Any]]:
    return {
        role: {
            "primary": f"specialist-{index % 8}/security-model-{index}",
            "fallbacks": [],
            "quality_tier": "high",
            "capabilities": ["structured_json", "security_reasoning", "solidity"],
        }
        for index, role in enumerate(ALL_SPECIALIST_ROLES)
    }


def _foundry_repo(tmp_path: Path, *, patched: bool) -> Path:
    target = tmp_path / ("foundry_patched" if patched else "foundry_vulnerable")
    shutil.copytree(FIXTURES / "solidity" / "foundry", target)
    if not patched:
        vault = target / "src" / "Vault.sol"
        vault.write_text(
            vault.read_text(encoding="utf-8").replace(
                "function withdraw(uint256 amount) external onlyOwner",
                "function withdraw(uint256 amount) external",
            ),
            encoding="utf-8",
        )
    return target


def _dependency_repo(tmp_path: Path) -> tuple[Path, str]:
    target = tmp_path / "dependency_project"
    shutil.copytree(FIXTURES / "dependency_preparation" / "safe_project", target)
    snapshot_dir = target / ".mmaudit-dependencies"
    package_root = snapshot_dir / "packages" / "safe-dep"
    lockfile = target / "package-lock.json"
    snapshot = {
        "schema_version": "1.0",
        "projects": [
            {
                "project_root": ".",
                "lockfile": "package-lock.json",
                "lockfile_sha256": hashlib.sha256(lockfile.read_bytes()).hexdigest(),
                "packages": [
                    {
                        "lock_path": "node_modules/safe-dep",
                        "name": "safe-dep",
                        "version": "1.0.0",
                        "source": "packages/safe-dep",
                        "tree_sha256": dependency_tree_sha256(package_root),
                    }
                ],
            }
        ],
        "advisories": [],
    }
    snapshot_path = snapshot_dir / "snapshot.json"
    snapshot_path.write_text(
        json.dumps(snapshot, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return target, hashlib.sha256(snapshot_path.read_bytes()).hexdigest()


def _solidity_reproduction_config(config_factory):
    return config_factory(
        privacy={"fail_on_detected_secret": False},
        smart_contracts={
            "enabled": True,
            "compile": False,
            "allow_fork_probing": True,
            "fork_rpc_url_env": "MMAUDIT_FORK_RPC_URL",
        },
        reproduction={
            "enabled": True,
            "required_for_solidity": True,
            "require_hardened_isolation": False,
            "pinned_block_number": 123456,
            "expected_chain_id": 31337,
            "targets": {"Vault": "0x2000000000000000000000000000000000000002"},
        },
    )


@pytest.mark.asyncio
async def test_mock_multi_agent_audit_preserves_artifacts_without_false_completion(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    before = {
        path.relative_to(vulnerable_repo): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in vulnerable_repo.rglob("*")
        if path.is_file()
    }
    fake = FakeOpenRouter()
    result = await _run(config, vulnerable_repo, tmp_path, fake)
    after = {
        path.relative_to(vulnerable_repo): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in vulnerable_repo.rglob("*")
        if path.is_file()
    }
    assert result.exit_code is ExitCode.INCOMPLETE
    assert not result.report.completed
    assert result.report.run_status is AuditRunStatus.INCOMPLETE
    assert any(finding.status == "confirmed" for finding in result.report.findings)
    assert before == after
    assert fake.chat_calls == 6
    assert {record.role for record in result.report.usage} >= {
        "threat_model",
        "source_audit",
        "business_logic",
        "configuration",
        "verifier",
        "judge",
    }
    for name in (
        "metadata.json",
        "repository-map.json",
        "scanner-results.json",
        "candidate-findings.json",
        "verification-results.json",
        "property-corpus.json",
        "scope-assessment.json",
        "final-findings.json",
        "audit-report.md",
        "audit-results.sarif",
        "context-manifest.json",
        "maximum_assurance_traceability.json",
        "run-evidence-manifest.json",
    ):
        assert (result.run_dir / name).is_file()
        assert (tmp_path / "output" / "latest" / name).is_file()
    AuditReport.model_validate_json(
        (result.run_dir / "final-findings.json").read_text(encoding="utf-8")
    )
    sarif = json.loads((result.run_dir / "audit-results.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    traceability = MaximumAssuranceTraceability.model_validate_json(
        (result.run_dir / "maximum_assurance_traceability.json").read_text(encoding="utf-8")
    )
    validate_traceability_evidence(
        traceability,
        repository_root=Path(__file__).resolve().parents[2],
        runtime_artifacts={path.name for path in result.run_dir.iterdir() if path.is_file()},
    )
    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    validate_manifest_artifacts(manifest, result.run_dir)
    context_manifest = load_context_manifest(result.run_dir / "context-manifest.json")
    validate_context_manifest_against_usage(
        context_manifest,
        run_id=result.report.run_id,
        usage_records=result.report.usage,
    )
    expected_context_binding = context_manifest_report_binding(context_manifest)
    context_coverage_binding = next(
        binding
        for binding in manifest.bindings.coverage
        if binding.identifier == "context-manifest/artifact"
    )
    assert context_manifest.run_id == result.report.run_id
    assert context_manifest.totals.request_count == len(result.report.usage)
    assert context_manifest.totals.mock_reported_request_count == len(result.report.usage)
    assert context_manifest.totals.provider_reported_request_count == 0
    assert context_manifest.totals.planned_prompt_tokens > 0
    assert context_manifest.totals.reserved_output_tokens > 0
    assert result.report.metadata["context_manifest"] == expected_context_binding.model_dump(
        mode="json"
    )
    assert context_coverage_binding.sha256 == context_manifest.manifest_sha256
    assert (tmp_path / "output" / "latest" / "context-manifest.json").read_bytes() == (
        result.run_dir / "context-manifest.json"
    ).read_bytes()
    assert manifest.run_id == result.report.run_id
    assert manifest.source_tree_sha256
    assert all(
        getattr(manifest.bindings, category)
        for category in manifest.bindings.__class__.model_fields
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("secondary_role", ["verifier", "judge"])
async def test_candidate_falsifier_context_preview_uses_exact_selected_models(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    secondary_role: str,
) -> None:
    base = config_factory()
    falsifier_model = "golf/gale-secure"
    falsifier_registry = model_registry_entry(falsifier_model)
    registry: list[dict[str, Any]] = []
    for entry in base.models.registry:
        payload = entry.model_dump(mode="json")
        if secondary_role == "judge" and entry.canonical_model_id == base.models.verifier.primary:
            payload["root_lineage"] = falsifier_registry["root_lineage"]
        registry.append(payload)
    registry.append(falsifier_registry)
    config = config_factory(
        profile=AuditProfile.DEEP,
        privacy={
            "fail_on_detected_secret": False,
            "approved_model_lineages": sorted({str(entry["root_lineage"]) for entry in registry}),
        },
        models={
            "specialists": {
                "falsifier": {
                    "primary": falsifier_model,
                    "fallbacks": [],
                    "quality_tier": "high",
                    "capabilities": ["structured_json", "security_reasoning"],
                }
            },
            "registry": registry,
        },
    ).effective()
    expected_models = (
        falsifier_model,
        config.models.role(secondary_role).primary,
    )
    observed_previews: list[tuple[str, ...]] = []
    observed_workflow_previews: list[tuple[tuple[str, ...], int | None, str | None, int]] = []
    original_preview = OpenRouterClient.context_package_byte_budget

    def record_preview(
        client: OpenRouterClient,
        models: list[str] | tuple[str, ...],
        *,
        role: str | None = None,
        workflow_byte_upper_bound_tokens: int | None = None,
        workflow_prompt: str | None = None,
        context_json_escape_overhead_tokens: int = 0,
    ) -> int:
        observed_previews.append(tuple(models))
        observed_workflow_previews.append(
            (
                tuple(models),
                workflow_byte_upper_bound_tokens,
                workflow_prompt,
                context_json_escape_overhead_tokens,
            )
        )
        return original_preview(
            client,
            models,
            role=role,
            workflow_byte_upper_bound_tokens=workflow_byte_upper_bound_tokens,
            workflow_prompt=workflow_prompt,
            context_json_escape_overhead_tokens=context_json_escape_overhead_tokens,
        )

    monkeypatch.setattr(OpenRouterClient, "context_package_byte_budget", record_preview)
    fake = FakeOpenRouter(extra_model_ids=[falsifier_model])

    result = await _run(config, vulnerable_repo, tmp_path, fake)

    actual_cross_exam_models = {
        str(request["model"])
        for request in fake.requests
        if _request_schema_name(request).startswith("mmaudit_candidate_cross_examination_")
    }
    assert result.report.cross_examination_decisions
    assert actual_cross_exam_models == set(expected_models)
    assert expected_models in observed_previews
    assert any(
        models == expected_models
        and prompt is not None
        and bound == len(prompt.encode("utf-8"))
        and context_escape_overhead > 0
        for models, bound, prompt, context_escape_overhead in observed_workflow_previews
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_role", ["verifier", "judge"])
async def test_context_preview_failure_preserves_fail_closed_pipeline_artifacts(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_role: str,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False}).effective()
    failed_role_config = config.models.role(failed_role)
    failed_models = (
        failed_role_config.primary,
        *failed_role_config.fallbacks,
    )
    original_preview = OpenRouterClient.context_package_byte_budget

    def fail_selected_preview(
        client: OpenRouterClient,
        models: list[str] | tuple[str, ...],
        *,
        role: str | None = None,
        workflow_byte_upper_bound_tokens: int | None = None,
        workflow_prompt: str | None = None,
        context_json_escape_overhead_tokens: int = 0,
    ) -> int:
        if tuple(models) == failed_models:
            raise OpenRouterRequestLimitError(f"synthetic {failed_role} context preview refusal")
        return original_preview(
            client,
            models,
            role=role,
            workflow_byte_upper_bound_tokens=workflow_byte_upper_bound_tokens,
            workflow_prompt=workflow_prompt,
            context_json_escape_overhead_tokens=context_json_escape_overhead_tokens,
        )

    monkeypatch.setattr(OpenRouterClient, "context_package_byte_budget", fail_selected_preview)
    fake = FakeOpenRouter()

    result = await _run(config, vulnerable_repo, tmp_path, fake)

    assert result.exit_code is ExitCode.MODEL_FAILURE
    assert not result.report.completed
    assert any(
        f"{failed_role}: synthetic {failed_role} context preview refusal" in reason
        for reason in result.report.incomplete_reasons
    )
    assert not any(
        _request_schema_name(request)
        == f"mmaudit_{'judgment' if failed_role == 'judge' else 'verification'}"
        for request in fake.requests
    )
    for artifact in (
        "specialist-execution.json",
        "context-manifest.json",
        "final-findings.json",
        "audit-report.md",
        "run-evidence-manifest.json",
    ):
        assert (result.run_dir / artifact).is_file()
    specialist_execution = json.loads(
        (result.run_dir / "specialist-execution.json").read_text(encoding="utf-8")
    )
    assert isinstance(specialist_execution["records"], list)


@pytest.mark.asyncio
async def test_strict_default_links_effective_privacy_evidence_to_report_and_manifest(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    fake = FakeOpenRouter()

    result = await _run(config, vulnerable_repo, tmp_path, fake)

    assert result.exit_code is ExitCode.INCOMPLETE
    assert not result.report.completed
    assert result.report.run_status is AuditRunStatus.INCOMPLETE
    effective = result.report.privacy["effective_policy"]
    assert isinstance(effective, dict)
    assert effective["privacy_profile"] == PrivacyProfile.STRICT_ZDR
    assert effective["require_zdr"] is True
    assert effective["source_classification"] == (
        PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE
    )
    assert effective["consent_sha256"] is None
    source_provenance = result.report.privacy["source_provenance"]
    assert isinstance(source_provenance, dict)
    assert source_provenance["proof_kind"] == "PRIVATE_DEFAULT"
    assert source_provenance["source_sha256"] == effective["source_sha256"]
    persisted = json.loads((result.run_dir / "privacy-policy.json").read_text(encoding="utf-8"))
    persisted_provenance = json.loads(
        (result.run_dir / "privacy-source-provenance.json").read_text(encoding="utf-8")
    )
    metadata = json.loads((result.run_dir / "metadata.json").read_text(encoding="utf-8"))
    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    privacy_binding = next(
        artifact for artifact in manifest.artifacts if artifact.path == "privacy-policy.json"
    )
    provenance_binding = next(
        artifact
        for artifact in manifest.artifacts
        if artifact.path == "privacy-source-provenance.json"
    )
    privacy_bytes = (result.run_dir / "privacy-policy.json").read_bytes()
    provenance_bytes = (result.run_dir / "privacy-source-provenance.json").read_bytes()
    markdown = (result.run_dir / "audit-report.md").read_text(encoding="utf-8")

    assert persisted == effective
    assert persisted_provenance == source_provenance
    assert (
        json.loads(
            (tmp_path / "output" / "latest" / "privacy-policy.json").read_text(encoding="utf-8")
        )
        == effective
    )
    assert (
        json.loads(
            (tmp_path / "output" / "latest" / "privacy-source-provenance.json").read_text(
                encoding="utf-8"
            )
        )
        == source_provenance
    )
    assert metadata["privacy"]["effective_policy"] == effective
    assert metadata["privacy"]["source_provenance"] == source_provenance
    assert manifest.source_tree_sha256 == effective["source_sha256"]
    assert privacy_binding.sha256 == hashlib.sha256(privacy_bytes).hexdigest()
    assert provenance_binding.sha256 == hashlib.sha256(provenance_bytes).hexdigest()
    assert effective["evidence_sha256"] in markdown
    assert effective["source_sha256"] in markdown
    assert "Privacy-permitted exact model routes:" in markdown
    assert "Privacy-permitted exact provider endpoints:" in markdown
    assert "Retention consent: not applicable under STRICT_ZDR" in markdown
    validate_manifest_artifacts(manifest, result.run_dir)


@pytest.mark.asyncio
async def test_unicode_source_inventory_has_one_privacy_and_manifest_hash(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "unicode-repository"
    shutil.copytree(vulnerable_repo, repository)
    (repository / "café.sol").write_text(
        "contract UnicodePrivacyFixture {}\n",
        encoding="utf-8",
    )
    config = config_factory(privacy={"fail_on_detected_secret": False})

    result = await _run(config, repository, tmp_path, FakeOpenRouter())

    effective = result.report.privacy["effective_policy"]
    provenance = result.report.privacy["source_provenance"]
    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    assert effective["source_sha256"] == provenance["source_sha256"]
    assert effective["source_sha256"] == manifest.source_tree_sha256
    assert effective["source_provenance_sha256"] == provenance["evidence_sha256"]
    validate_manifest_artifacts(manifest, result.run_dir)


@pytest.mark.asyncio
async def test_privacy_semantic_validation_rejects_source_and_usage_disagreement(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    result = await _run(config, vulnerable_repo, tmp_path, FakeOpenRouter())
    effective = result.report.privacy["effective_policy"]
    assert isinstance(effective, dict)

    with pytest.raises(ValueError, match="manifest source tree"):
        validate_report_privacy_consistency(
            result.report,
            source_tree_sha256="f" * 64,
            expected_source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        )

    usage = result.report.usage[0]
    mismatched_usage = usage.model_copy(
        update={
            "routing": {
                **usage.routing,
                "privacy_source_provenance_sha256": "e" * 64,
            }
        }
    )
    mismatched_report = result.report.model_copy(update={"usage": [mismatched_usage]})
    with pytest.raises(ValueError, match="usage privacy routing"):
        validate_report_privacy_consistency(
            mismatched_report,
            source_tree_sha256=effective["source_sha256"],
            expected_source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        )

    missing_privacy_routing = usage.model_copy(
        update={
            "routing": {
                key: value
                for key, value in usage.routing.items()
                if key
                not in {
                    "privacy_profile",
                    "effective_privacy_policy_sha256",
                    "privacy_source_sha256",
                    "privacy_source_provenance_sha256",
                }
            }
        }
    )
    missing_privacy_report = result.report.model_copy(update={"usage": [missing_privacy_routing]})
    with pytest.raises(ValueError, match="usage privacy routing"):
        validate_report_privacy_consistency(
            missing_privacy_report,
            source_tree_sha256=effective["source_sha256"],
            expected_source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        )

    no_policy_report = result.report.model_copy(
        update={
            "privacy": {
                **result.report.privacy,
                "effective_policy": None,
                "source_provenance": None,
            },
            "usage": [missing_privacy_routing],
        }
    )
    with pytest.raises(ValueError, match="lacks effective privacy and provenance"):
        validate_report_privacy_consistency(
            no_policy_report,
            source_tree_sha256=effective["source_sha256"],
            expected_source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        )

    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    missing_policy_payload = manifest.model_dump(mode="json", exclude={"manifest_sha256"})
    missing_policy_payload["artifacts"] = [
        artifact
        for artifact in missing_policy_payload["artifacts"]
        if artifact["path"] != "privacy-policy.json"
    ]
    missing_policy_manifest = RunEvidenceManifest.model_validate(
        {
            **missing_policy_payload,
            "manifest_sha256": canonical_sha256(missing_policy_payload),
        }
    )
    (result.run_dir / "privacy-policy.json").unlink()
    with pytest.raises(ValueError, match=r"privacy-policy\.json presence"):
        validate_manifest_artifacts(missing_policy_manifest, result.run_dir)


@pytest.mark.parametrize("consent_state", ["missing", "source_mismatch"])
@pytest.mark.asyncio
async def test_frontier_privacy_refuses_before_model_request_without_exact_consent(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
    consent_state: str,
) -> None:
    config = config_factory(
        privacy={
            "profile": PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT,
            "require_zdr": False,
            "maximum_model_retention": "temporary",
            "fail_on_detected_secret": False,
        }
    )
    observation = (
        None
        if consent_state == "missing"
        else _privacy_consent_observation(
            config=config,
            target_root=vulnerable_repo,
            control_root=tmp_path / "operator-control",
            profile=PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT,
            source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
            source_sha256="f" * 64,
        )
    )
    fake = FakeOpenRouter()
    client, http_client = _provider(config, fake)
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path / "frontier-output",
        client=client,
        scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
        privacy_consent_observation=observation,
        privacy_source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
    )
    try:
        result = await pipeline.run(allow_code_egress=True)
    finally:
        await http_client.aclose()

    assert result.exit_code is ExitCode.PRIVACY_REFUSAL
    assert fake.chat_calls == 0
    assert fake.requests == []
    assert result.report.privacy["effective_policy"] is None
    assert not (result.run_dir / "privacy-policy.json").exists()
    assert pipeline.privacy_authorization is None
    assert pipeline.privacy_consent_observation is None
    expected = (
        "descriptor-safe consent evidence"
        if consent_state == "missing"
        else "different source hash"
    )
    assert any(expected in reason for reason in result.report.incomplete_reasons)


@pytest.mark.asyncio
async def test_synthetic_benchmark_profile_cannot_authorize_private_operator_source(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = config_factory(
        privacy={
            "profile": PrivacyProfile.SYNTHETIC_BENCHMARK,
            "require_zdr": False,
            "maximum_model_retention": "temporary",
            "fail_on_detected_secret": False,
        }
    )
    observation = _privacy_consent_observation(
        config=config,
        target_root=vulnerable_repo,
        control_root=tmp_path / "operator-control",
        profile=PrivacyProfile.SYNTHETIC_BENCHMARK,
        source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
        source_sha256="e" * 64,
    )
    fake = FakeOpenRouter()
    client, http_client = _provider(config, fake)
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path / "synthetic-output",
        client=client,
        scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
        privacy_consent_observation=observation,
        privacy_source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
    )
    try:
        result = await pipeline.run(allow_code_egress=True)
    finally:
        await http_client.aclose()

    assert result.exit_code is ExitCode.PRIVACY_REFUSAL
    assert fake.chat_calls == 0
    assert fake.requests == []
    assert result.report.privacy["effective_policy"] is None
    assert any(
        "different source classification" in reason for reason in result.report.incomplete_reasons
    )


@pytest.mark.asyncio
async def test_synthetic_benchmark_enum_cannot_bypass_committed_source_provenance(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = config_factory(
        privacy={
            "profile": PrivacyProfile.SYNTHETIC_BENCHMARK,
            "require_zdr": True,
            "maximum_model_retention": "zero",
            "fail_on_detected_secret": False,
        }
    )
    fake = FakeOpenRouter()
    client, http_client = _provider(config, fake)
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path / "synthetic-provenance-output",
        client=client,
        scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
        privacy_source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
    )
    try:
        result = await pipeline.run(allow_code_egress=True)
    finally:
        await http_client.aclose()

    assert result.exit_code is ExitCode.PRIVACY_REFUSAL
    assert fake.chat_calls == 0
    assert fake.requests == []
    assert result.report.privacy["effective_policy"] is None
    assert result.report.privacy["source_provenance"] is None
    assert any(
        "distribution-owned fixture or benchmark scope" in reason
        for reason in result.report.incomplete_reasons
    )


@pytest.mark.asyncio
async def test_loaded_operator_credential_is_absent_from_emitted_audit_artifacts(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    canary = "sk-or-v1-loaded-artifact-canary"
    secret_file = tmp_path / "operator-control.env"
    secret_file.write_text(f"OPENROUTER_API_KEY={canary}\n", encoding="utf-8")
    secret_file.chmod(0o600)
    config = config_factory(privacy={"fail_on_detected_secret": False})
    fake = FakeOpenRouter()

    with load_operator_secrets(secret_file, environ={}) as secrets:
        client, http_client = _provider(
            config,
            fake,
            api_key=secrets.openrouter_api_key,
        )
        pipeline = AuditPipeline(
            config,
            repo=vulnerable_repo,
            output=tmp_path / "output",
            client=client,
            scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
        )
        try:
            result = await pipeline.run(allow_code_egress=True)
        finally:
            await http_client.aclose()

    required_artifacts = {
        "audit-report.md",
        "audit-results.sarif",
        "final-findings.json",
        "maximum_assurance_traceability.json",
        "run-evidence-manifest.json",
    }
    emitted = {path.name for path in result.run_dir.iterdir() if path.is_file()}
    assert required_artifacts <= emitted
    assert fake.chat_calls > 0
    for path in result.run_dir.rglob("*"):
        if path.is_file():
            assert canary.encode() not in path.read_bytes()
            assert str(secret_file).encode() not in path.read_bytes()
    captured = capsys.readouterr()
    assert canary not in captured.out
    assert canary not in captured.err
    assert canary not in caplog.text
    assert client._credential == bytearray()
    assert secrets.cleared


@pytest.mark.asyncio
async def test_prior_audit_is_loaded_only_after_blind_model_discovery(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prior_path = vulnerable_repo / "audit" / "prior.json"
    prior_path.parent.mkdir()
    source_lines = (
        (vulnerable_repo / "app.py").read_text(encoding="utf-8").splitlines(keepends=True)
    )
    historical_hash = hashlib.sha256("".join(source_lines[10:14]).encode()).hexdigest()
    canary = "BLIND-PRIOR-FINDING-CANARY"
    prior_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "findings": [
                    {
                        "prior_id": "PRIOR-PIPELINE-001",
                        "title": canary,
                        "severity": "high",
                        "cwe": ["CWE-89"],
                        "previous_state": "open",
                        "locations": [
                            {
                                "path": "app.py",
                                "start_line": 11,
                                "end_line": 14,
                                "historical_content_sha256": historical_hash,
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    config = config_factory(
        privacy={"fail_on_detected_secret": False},
        prior_audit={"path": "audit/prior.json"},
    )
    fake = FakeOpenRouter()
    load_observations: list[int] = []

    def observe_post_discovery_load(**kwargs: Any) -> PriorAuditComparison:
        load_observations.append(fake.chat_calls)
        assert fake.chat_calls == 6
        prompts = json.dumps(fake.requests)
        assert canary not in prompts
        assert "audit/prior.json" not in prompts
        return build_prior_audit_comparison(**kwargs)

    monkeypatch.setattr(
        "mmaudit.orchestration.pipeline.build_prior_audit_comparison",
        observe_post_discovery_load,
    )

    result = await _run(config, vulnerable_repo, tmp_path, fake)

    assert result.exit_code is ExitCode.INCOMPLETE
    assert not result.report.completed
    assert result.report.run_status is AuditRunStatus.INCOMPLETE
    assert load_observations == [6]
    assert "audit/prior.json" not in {file.path for file in result.report.repository.files}
    assert all(
        "audit/prior.json" not in omission for omission in result.report.repository.omitted_files
    )
    comparison = result.report.prior_audit_comparison
    assert comparison is not None
    assert comparison.loaded
    assert comparison.model_request_count_before_load == len(result.report.usage) == 6
    assert comparison.items[0].discovery_status is PriorAuditDiscoveryStatus.REDISCOVERED
    assert comparison.items[0].remediation_status is PriorAuditRemediationStatus.UNRESOLVED
    artifact = json.loads(
        (result.run_dir / "prior-audit-comparison.json").read_text(encoding="utf-8")
    )
    assert PriorAuditComparison.model_validate(artifact["comparison"]) == comparison
    assert (tmp_path / "output" / "latest" / "prior-audit-comparison.json").is_file()
    markdown = (result.run_dir / "audit-report.md").read_text(encoding="utf-8")
    assert "Blind-first prior-audit comparison" in markdown
    assert "| rediscovered | unresolved |" in markdown


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("patched", "expect_confirmed"),
    [(False, True), (True, False)],
)
async def test_generated_foundry_reproduction_caps_solidity_classification(
    config_factory,
    tmp_path: Path,
    patched: bool,
    expect_confirmed: bool,
) -> None:
    repo = _foundry_repo(tmp_path, patched=patched)
    before = {
        path.relative_to(repo): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in repo.rglob("*")
        if path.is_file()
    }
    result = await _run(
        _solidity_reproduction_config(config_factory),
        repo,
        tmp_path,
        FakeOpenRouter(mode="solidity_reproduction"),
        scanner_runner=StaticScannerRunner(status=ScannerStatus.UNAVAILABLE),
        reproduction_runner=SyntheticForkReproductionRunner(),
        allow_fork_probing=True,
    )
    after = {
        path.relative_to(repo): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in repo.rglob("*")
        if path.is_file()
    }
    assert before == after
    assert result.exit_code is ExitCode.INCOMPLETE
    assert not result.report.completed
    assert result.report.run_status is AuditRunStatus.INCOMPLETE
    reproduction_artifact = json.loads(
        (result.run_dir / "reproduction-results.json").read_text(encoding="utf-8")
    )
    serialized_results = [
        ReproductionResult.model_validate(item) for item in reproduction_artifact["results"]
    ]
    assert serialized_results == result.report.reproductions
    assert all(
        reproduction.integrity is not None and reproduction.integrity.status.value == "verified"
        for reproduction in serialized_results
    )
    markdown = (result.run_dir / "audit-report.md").read_text(encoding="utf-8")
    assert "Executable verification" in markdown
    assert "| verified |" in markdown
    if expect_confirmed:
        assert any(
            finding.status is FindingStatus.CONFIRMED
            and finding.reproduction_state is ReproductionState.REPRODUCED_AND_MINIMIZED
            for finding in result.report.findings
        )
    else:
        assert not any(
            finding.status is FindingStatus.CONFIRMED for finding in result.report.findings
        )
        assert any(
            finding.status is FindingStatus.REJECTED for finding in result.report.rejected_findings
        )


@pytest.mark.asyncio
async def test_maximum_assurance_e2e_is_evidence_rich_but_never_false_complete(
    config_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "maximum_assurance_protocol"
    shutil.copytree(FIXTURES / "solidity" / "maximum_assurance_protocol", repo)
    specialists = _maximum_specialists()
    base_registry = [entry.model_dump(mode="json") for entry in config_factory().models.registry]
    specialist_registry = [model_registry_entry(slot["primary"]) for slot in specialists.values()]
    registry = [*base_registry, *specialist_registry]
    config = config_factory(
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        privacy={
            "fail_on_detected_secret": False,
            "approved_model_lineages": [entry["root_lineage"] for entry in registry],
        },
        repository={"max_total_context_bytes": 5_000_000},
        maximum_assurance={"allow_downgrade": True},
        models={"specialists": specialists, "registry": registry},
        smart_contracts={
            "allow_fork_probing": True,
            "compile": True,
        },
        reproduction={
            "targets": SYNTHETIC_MAXIMUM_TARGETS,
            "pinned_block_number": 123456,
            "expected_chain_id": 31337,
        },
    ).effective()
    fake = FakeOpenRouter(
        mode="maximum_assurance",
        extra_model_ids=[slot.primary for slot in config.models.specialists.values()],
        context_length=300_000,
        max_prompt_tokens=280_000,
        max_completion_tokens=65_536,
    )
    execution_contexts: list[ContextPackage] = []

    def capture_execution_contexts(
        execution_config: Any,
        *,
        usage_records: list[UsageRecord],
        contexts: list[ContextPackage],
        accepted_outcomes: Any = (),
    ) -> Any:
        execution_contexts.extend(contexts)
        return build_specialist_execution_records(
            execution_config,
            usage_records=usage_records,
            contexts=contexts,
            accepted_outcomes=accepted_outcomes,
        )

    monkeypatch.setattr(
        "mmaudit.orchestration.pipeline.compile_solidity_projects",
        _synthetic_compiler,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.pipeline.build_specialist_execution_records",
        capture_execution_contexts,
    )
    before = {
        path.relative_to(repo): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in repo.rglob("*")
        if path.is_file()
    }

    result = await _run(
        config,
        repo,
        tmp_path,
        fake,
        scanner_runner=StaticScannerRunner(
            scanner_name="slither",
            finding_path="src/AccessVault.sol",
            finding_line=12,
        ),
        reproduction_runner=SyntheticMaximumReproductionRunner(),
        invariant_runner=SyntheticInvariantRunner(),
        formal_runner=SyntheticFormalRunner(),
        allow_fork_probing=True,
        production_qualification=synthetic_production_qualification(
            config,
            datetime.now(UTC).replace(microsecond=0),
            provider_endpoint="synthetic-provider",
        ),
    )

    after = {
        path.relative_to(repo): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in repo.rglob("*")
        if path.is_file()
    }
    assert before == after
    assert result.exit_code is ExitCode.INCOMPLETE
    assert not result.report.completed
    assert result.report.run_status is AuditRunStatus.INCOMPLETE
    assert result.report.maximum_assurance is not None
    assert result.report.maximum_assurance.status.value == "DOWNGRADED"
    assert result.report.maximum_assurance.status.value != "COMPLETE"
    failed_assurance_engines = {
        requirement.engine
        for requirement in result.report.maximum_assurance.requirements
        if requirement.required and not requirement.passed
    }
    assert "traceability:ma-economic-portfolio" not in failed_assurance_engines
    assert "protocol_economic_simulation" in failed_assurance_engines
    assert "traceability:ma-formal-portfolio" in failed_assurance_engines
    assert "critical_model_surface_review" in failed_assurance_engines
    assert "full_protocol_scope" in failed_assurance_engines
    assert {
        "src/AccessVault.sol",
        "src/ReentrantBank.sol",
        "src/SpotOracleLender.sol",
        "src/UnsafeUUPS.sol",
    } <= {location.path for finding in result.report.findings for location in finding.locations}
    confirmed_paths = {
        location.path
        for finding in result.report.findings
        if finding.status is FindingStatus.CONFIRMED
        for location in finding.locations
    }
    assert {"src/ReentrantBank.sol", "src/UnsafeUUPS.sol"} <= confirmed_paths
    assert not any(
        finding.status is FindingStatus.CONFIRMED
        and any(location.path == "src/SafeControls.sol" for location in finding.locations)
        for finding in result.report.findings
    )
    assert any(
        any(location.path == "src/SafeControls.sol" for location in finding.locations)
        for finding in result.report.rejected_findings
    )
    for artifact in (
        "solidity-graphs.json",
        "solidity-invariants.json",
        "invariant-review.json",
        "property-corpus.json",
        "formal-results.json",
        "reproduction-results.json",
        "cross-examination.json",
        "specialist-execution.json",
        "model-review-coverage.json",
        "model-qualification-runtime.json",
        "solidity-coverage.json",
        "final-findings.json",
        "audit-report.md",
        "audit-results.sarif",
    ):
        assert (result.run_dir / artifact).is_file()
    reproduction_payload = json.loads(
        (result.run_dir / "reproduction-results.json").read_text(encoding="utf-8")
    )
    resolutions = {
        item["candidate_id"]: item["kind"] for item in reproduction_payload["candidate_resolutions"]
    }
    assert resolutions
    rejected_safe_control_ids = {
        candidate_id
        for finding in result.report.rejected_findings
        if any(location.path == "src/SafeControls.sol" for location in finding.locations)
        for candidate_id in finding.contributing_candidate_ids
    }
    assert rejected_safe_control_ids
    assert rejected_safe_control_ids <= resolutions.keys()
    assert all(
        resolutions[candidate_id] == "inconclusive" for candidate_id in rejected_safe_control_ids
    )
    for reproduction in reproduction_payload["results"]:
        if reproduction["state"] in {"reproduced", "reproduced_and_minimized"}:
            assert resolutions[reproduction["candidate_id"]] == "reproduced"
        elif reproduction["state"] == "not_reproduced":
            assert resolutions[reproduction["candidate_id"]] == "inconclusive"
    property_payload = json.loads(
        (result.run_dir / "property-corpus.json").read_text(encoding="utf-8")
    )
    property_corpus = PropertyCorpus.model_validate(property_payload["corpus"])
    assert all(
        property_spec.source_evidence
        and property_spec.covered_entity_ids
        and property_spec.campaign.seed >= 0
        for property_spec in property_corpus.properties
    )
    assert (
        result.report.metadata["solidity"]["property_corpus_summary"]["corpus_hash"]
        == property_corpus.corpus_hash
    )
    assert result.report.metadata["solidity"]["property_corpus_summary"]["properties"] == len(
        property_corpus.properties
    )
    specialist_execution = json.loads(
        (result.run_dir / "specialist-execution.json").read_text(encoding="utf-8")
    )
    specialist_records = {record["role"]: record for record in specialist_execution["records"]}
    reproduction_falsifier_contexts = [
        context for context in execution_contexts if context.role == "specialist:falsifier"
    ]
    assert len(reproduction_falsifier_contexts) == 1
    assert any(context.role == "candidate_cross_examination" for context in execution_contexts)
    assert specialist_records["falsifier"]["context_budget_bytes"] == (
        reproduction_falsifier_contexts[0].byte_budget
    )
    assert specialist_records["falsifier"]["context_bytes_used"] == (
        reproduction_falsifier_contexts[0].bytes_used
    )
    assert set(specialist_records) == set(ALL_SPECIALIST_ROLES)
    assert all(record["configured"] for record in specialist_records.values())
    assert all(
        record["status"] == "completed"
        and record["context_bytes_used"]
        <= record["context_budget_bytes"]
        <= record["context_limit_bytes"]
        for record in specialist_records.values()
    )
    assert len({record["schema_name"] for record in specialist_records.values()}) == len(
        ALL_SPECIALIST_ROLES
    )
    model_coverage_payload = json.loads(
        (result.run_dir / "model-review-coverage.json").read_text(encoding="utf-8")
    )
    model_coverage = ModelReviewCoverage.model_validate(model_coverage_payload["coverage"])
    assert result.report.model_review_coverage == model_coverage
    assert {surface.kind for surface in model_coverage.surfaces} == set(ModelReviewSurfaceKind)
    assert model_coverage.overall.numerator == 0
    assert model_coverage.overall.denominator > 0
    assert "mock model usage was excluded from substantive model-review coverage" in (
        model_coverage.limitations
    )
    assert not model_coverage.critical_gate_passed
    assert all(
        surface.reviewed == bool(surface.reviewer_roles and surface.root_lineages)
        for surface in model_coverage.surfaces
    )
    private_review_payload = json.loads(
        (result.run_dir / "private/model-review-artifacts.json").read_text(encoding="utf-8")
    )
    review_artifacts = [
        ModelSurfaceReviewArtifact.model_validate(item)
        for item in private_review_payload["artifacts"]
    ]
    assert review_artifacts
    sealed_hashes = {artifact.artifact_sha256 for artifact in review_artifacts}
    assert {
        reference.artifact_sha256
        for surface in model_coverage.surfaces
        for reference in surface.evidence_references
    } <= sealed_hashes
    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    sealed_file = next(
        artifact
        for artifact in manifest.artifacts
        if artifact.path == "private/model-review-artifacts.json"
    )
    assert (
        sealed_file.sha256
        == hashlib.sha256((result.run_dir / sealed_file.path).read_bytes()).hexdigest()
    )
    assert not (result.run_dir.parent.parent / "latest/private").exists()
    critical_gate = next(
        gate for gate in result.report.quality_gates if gate.gate == "critical_model_surface_review"
    )
    assert not critical_gate.passed
    assert critical_gate.artifacts == ["model-review-coverage.json"]
    assert result.report.verification_decisions
    assert result.report.cross_examination_decisions
    assert {decision.verdict.value for decision in result.report.cross_examination_decisions} == {
        "supported",
        "disputed",
    }
    assert (
        len({decision.root_lineage for decision in result.report.cross_examination_decisions}) == 2
    )
    cross_examination_candidate_ids = {
        decision.candidate_id for decision in result.report.cross_examination_decisions
    }
    for candidate_id in cross_examination_candidate_ids:
        candidate_decisions = [
            decision
            for decision in result.report.cross_examination_decisions
            if decision.candidate_id == candidate_id
        ]
        assert len(candidate_decisions) == 2
        assert len({decision.root_lineage for decision in candidate_decisions}) == 2
        assert len({decision.request_id for decision in candidate_decisions}) == 2
    assert {decision.request_id for decision in result.report.cross_examination_decisions} <= {
        record.request_id
        for record in result.report.usage
        if record.role.startswith("candidate_falsifier:")
    }
    cross_examination_requests = [
        request
        for request in fake.requests
        if _request_schema_name(request).startswith("mmaudit_candidate_cross_examination_")
    ]
    assert len(cross_examination_requests) == 2 * len(cross_examination_candidate_ids)
    for request in cross_examination_requests:
        user_prompt = request["messages"][1]["content"]
        anonymized = json.loads(
            user_prompt.split("<ANONYMIZED_CANDIDATES_JSON>\n", 1)[1].split(
                "\n</ANONYMIZED_CANDIDATES_JSON>",
                1,
            )[0]
        )
        assert len(anonymized) == 1
        assert anonymized
        assert all(
            {
                "candidate_id",
                "role",
                "model_family",
                "model_votes",
            }.isdisjoint(candidate)
            for candidate in anonymized
        )
    assert result.report.falsification_decisions
    assert result.report.invariant_review is not None
    assert len(result.report.invariant_review.accepted_proposals) == 1
    assert result.report.invariant_review.accepted_proposals[0].confidence == 0.65
    assert all(
        finding.title != result.report.invariant_review.accepted_proposals[0].title
        for finding in [*result.report.findings, *result.report.rejected_findings]
    )
    quality_metrics = result.report.metadata["solidity"]["coverage"]["quality_metrics"]
    assert result.report.solidity_coverage is not None
    assert (
        result.report.solidity_coverage.model_dump(mode="json")
        == result.report.metadata["solidity"]["coverage"]
    )
    assert quality_metrics
    required_coverage_fields = {
        "numerator",
        "denominator",
        "population",
        "percentage",
        "exclusions",
        "not_applicable_evidence",
        "confidence",
        "provenance",
        "failures",
        "state",
        "detail",
    }
    assert all(required_coverage_fields <= set(metric) for metric in quality_metrics.values())
    assert all(
        metric["population"] == metric["denominator"] + len(metric["exclusions"])
        for metric in quality_metrics.values()
    )
    assert quality_metrics["model_invariant_proposal_validation"]["numerator"] == 1
    assert quality_metrics["model_invariant_proposal_validation"]["denominator"] == 1
    assert (
        quality_metrics["model_role_completion"]["numerator"]
        == quality_metrics["model_role_completion"]["denominator"]
    )
    quality_gate_names = {gate.gate for gate in result.report.quality_gates}
    assert {
        "compiler_contract_index_coverage",
        "public_external_entry_point_review_coverage",
        "privileged_entry_point_review_coverage",
        "state_writing_function_review_coverage",
        "high_value_path_review_coverage",
        "external_call_classification_coverage",
        "asset_flow_classification_coverage",
        "storage_layout_coverage",
        "invariant_execution_coverage",
        "deterministic_scanner_completion",
        "configured_model_role_completion",
        "economic_template_execution_coverage",
        "dependency_resolution_coverage",
    } <= quality_gate_names
    markdown = (result.run_dir / "audit-report.md").read_text(encoding="utf-8")
    assert "DOWNGRADED" in markdown
    assert "Coverage scorecard" in markdown
    assert (
        "| Exclusions | Population | Percent | N/A evidence | Confidence | Provenance | Failures |"
        in markdown
    )
    assert "Anonymized adversarial cross-examination" in markdown


@pytest.mark.asyncio
async def test_erc4626_generated_harness_executes_locally_and_is_counted_separately(
    config_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forge = shutil.which("forge")
    if forge is None:
        pytest.skip("forge is not installed")
    solc_candidates = (
        Path.home() / "Library" / "Application Support" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".local" / "share" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".svm" / "0.8.30" / "solc-0.8.30",
    )
    solc = next(
        (candidate for candidate in solc_candidates if candidate.is_file()),
        None,
    )
    if solc is None:
        pytest.skip("external Foundry-managed solc 0.8.30 is not installed")
    repository = tmp_path / "economic_erc4626"
    shutil.copytree(FIXTURES / "solidity" / "economic_erc4626", repository)
    targets = {
        "VulnerableInflationVault": "0x2000000000000000000000000000000000000002",
        "VulnerableInflationVaultAsset": "0x3000000000000000000000000000000000000002",
        "PatchedInflationVault": "0x2000000000000000000000000000000000000003",
        "PatchedInflationVaultAsset": "0x3000000000000000000000000000000000000003",
    }
    source_path = "src/EconomicVaults.sol"
    local_deployments = [
        LocalInvariantDeployment(
            target_alias="VulnerableInflationVaultAsset",
            contract_name="SimpleToken",
            source_path=source_path,
            token_seed_function_signature="mint(address,uint256)",
        ),
        LocalInvariantDeployment(
            target_alias="VulnerableInflationVault",
            contract_name="VulnerableInflationVault",
            source_path=source_path,
            constructor_arguments=[
                LocalInvariantDeploymentArgument(
                    target_alias="VulnerableInflationVaultAsset",
                    cast_contract="SimpleToken",
                )
            ],
        ),
        LocalInvariantDeployment(
            target_alias="PatchedInflationVaultAsset",
            contract_name="SimpleToken",
            source_path=source_path,
            token_seed_function_signature="mint(address,uint256)",
        ),
        LocalInvariantDeployment(
            target_alias="PatchedInflationVault",
            contract_name="PatchedInflationVault",
            source_path=source_path,
            constructor_arguments=[
                LocalInvariantDeploymentArgument(
                    target_alias="PatchedInflationVaultAsset",
                    cast_contract="SimpleToken",
                )
            ],
        ),
    ]
    config = config_factory(
        privacy={"fail_on_detected_secret": False},
        smart_contracts={"enabled": True, "compile": True},
        reproduction={
            "enabled": False,
            "required_for_solidity": False,
            "require_hardened_isolation": False,
            "expected_chain_id": 31337,
            "targets": targets,
            "repetitions": 2,
        },
        invariants={
            "execute_generated": True,
            "local_deployments": [
                deployment.model_dump(mode="json") for deployment in local_deployments
            ],
        },
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.pipeline.compile_solidity_projects",
        _synthetic_compiler,
    )
    invariant_runner = FoundryInvariantRunner(
        config.reproduction,
        config.smart_contracts,
        backend=LocalOnlyInvariantIsolationBackend(),
        forge_executable=Path(forge),
        solc_executable=solc,
    )
    pipeline = AuditPipeline(
        config,
        repo=repository,
        output=tmp_path / "erc4626-output",
        scanner_runner=StaticScannerRunner(status=ScannerStatus.UNAVAILABLE),  # type: ignore[arg-type]
        invariant_runner=invariant_runner,
    )

    result = await pipeline.run(scanner_only=True)

    payload = json.loads(
        (result.run_dir / "invariant-execution-results.json").read_text(encoding="utf-8")
    )
    executions = [
        InvariantExecutionResult.model_validate(item)
        for item in payload["results"]
        if item["economic_template"] == "erc4626_donation_inflation"
    ]
    assert len(executions) == 2
    assert {execution.status for execution in executions} == {
        InvariantExecutionStatus.COUNTEREXAMPLE,
        InvariantExecutionStatus.PASSED,
    }
    assert all(
        execution.replay_confirmed
        and execution.attempts == 2
        and execution.successful_attempts == 2
        and all(attempt.fresh_workspace for attempt in execution.attempt_evidence)
        for execution in executions
    )
    counterexample = next(
        execution
        for execution in executions
        if execution.status is InvariantExecutionStatus.COUNTEREXAMPLE
    )
    assert counterexample.minimization_evidence is not None
    assert counterexample.minimization_evidence.proven_minimal
    assert all(
        execution.isolation_backend == "synthetic-local-only-isolation" for execution in executions
    )
    assert all("--fork-url" not in execution.command for execution in executions)
    compiler_sha256 = hashlib.sha256(solc.read_bytes()).hexdigest()
    assert all(execution.compiler_sha256 == compiler_sha256 for execution in executions)
    assert all("[PINNED_SOLC]" in execution.command for execution in executions)
    assert all(str(solc) not in execution.command for execution in executions)
    coverage = result.report.metadata["solidity"]["coverage"]
    assert coverage["economic_simulations_executed"] >= 1
    template_coverage = coverage["economic_template_execution"]["erc4626_donation_inflation"]
    assert template_coverage == {
        "kind": "erc4626_donation_inflation",
        "applicable": True,
        "execution_required": True,
        "typed_harness_available": True,
        "harnesses_generated": 2,
        "harnesses_compiled": 2,
        "harnesses_executed": 2,
        "harnesses_replayed": 2,
        "counterexamples": 1,
        "counterexamples_minimized": 1,
        "statuses": {"counterexample": 1, "passed": 1},
        "source_sha256s": sorted(execution.source_sha256 for execution in executions),
        "compiler_sha256s": [compiler_sha256],
        "limitations": [
            "Execution requires pinned local fork targets and operator-validated market assumptions"
        ],
    }
    metric_prefix = "economic_erc4626_donation_inflation"
    expected_metrics = {
        "generated": (1, 1),
        "compiled": (2, 2),
        "executed": (2, 2),
        "replayed": (2, 2),
        "counterexamples_minimized": (1, 1),
    }
    for suffix, expected_counts in expected_metrics.items():
        metric = coverage["quality_metrics"][f"{metric_prefix}_{suffix}"]
        assert (metric["numerator"], metric["denominator"]) == expected_counts
        assert metric["percentage"] == 100
    summary = result.report.metadata["solidity"]["economic_simulation_summary"]
    assert summary["replayed"] >= 1
    assert summary["counterexamples_minimized"] == 1
    assert summary["by_template"]["erc4626_donation_inflation"] == template_coverage
    serialized_report = AuditReport.model_validate_json(
        (result.run_dir / "final-findings.json").read_text(encoding="utf-8")
    )
    assert (
        serialized_report.metadata["solidity"]["coverage"]["economic_template_execution"][
            "erc4626_donation_inflation"
        ]
        == template_coverage
    )
    markdown = (result.run_dir / "audit-report.md").read_text(encoding="utf-8")
    assert (
        "| Template | Applicable | Typed harness | Generated | Execution | Replayed |" in markdown
    )
    assert "1 counterexample, 1 passed" in markdown
    assert "| 2 | 1 counterexample, 1 passed | 2 | 1 |" in markdown


@pytest.mark.asyncio
async def test_mocked_runtime_post_judge_severity_fails_closed_across_pipeline_artifacts(
    config_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, suite, harness, corpus, execution = _execution_origin_inputs(
        tmp_path / "execution-origin-inputs"
    )
    config = config_factory(
        privacy={"fail_on_detected_secret": False},
        smart_contracts={
            "enabled": True,
            "compile": False,
        },
        reproduction={
            "enabled": False,
            "required_for_solidity": False,
            "require_hardened_isolation": False,
            "expected_chain_id": 31_337,
            "repetitions": 2,
        },
        invariants={
            "execute_generated": True,
            "generate_foundry_templates": False,
            "harnesses": [harness.model_dump(mode="json")],
        },
    )
    captured_assurance_runtime: list[AssuranceRuntime] = []
    original_assurance_evaluate = MaximumAssuranceContract.evaluate

    def capture_assurance_runtime(
        contract: MaximumAssuranceContract,
        runtime: AssuranceRuntime,
    ) -> Any:
        captured_assurance_runtime.append(runtime)
        return original_assurance_evaluate(contract, runtime)

    async def mocked_execution_results(*_args: Any, **_kwargs: Any) -> list[Any]:
        return [execution]

    monkeypatch.setattr(
        "mmaudit.orchestration.pipeline.discover_invariants",
        lambda *_args, **_kwargs: suite,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.pipeline.build_property_corpus",
        lambda *_args, **_kwargs: corpus,
    )
    monkeypatch.setattr(
        AuditPipeline,
        "_execute_invariant_harnesses",
        mocked_execution_results,
    )
    monkeypatch.setattr(
        MaximumAssuranceContract,
        "evaluate",
        capture_assurance_runtime,
    )
    result = await _run(
        config,
        repository,
        tmp_path,
        FakeOpenRouter(mode="execution_origin_post_judge"),
        scanner_runner=StaticScannerRunner(status=ScannerStatus.UNAVAILABLE),
        invariant_runner=SyntheticInvariantRunner(),
    )

    assert result.exit_code is ExitCode.INCOMPLETE
    # The mocked wiring intentionally has neither real compilation nor a real
    # scanner, so the evidence-derived run status can be stricter than the
    # post-judge INCOMPLETE terminal code. It must never become COMPLETE.
    assert result.report.run_status in {
        AuditRunStatus.INCOMPLETE,
        AuditRunStatus.FAILED,
    }
    execution_findings = [
        finding
        for finding in result.report.findings
        if finding.origin_kind is FindingOriginKind.DETERMINISTIC_EXECUTION
    ]
    assert len(execution_findings) == 1
    finding = execution_findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.status is FindingStatus.NEEDS_REVIEW
    assert "did not receive candidate-specific cross-examination" in finding.disagreement

    candidates = CandidateFindingArtifact.model_validate_json(
        (result.run_dir / "candidate-findings.json").read_text(encoding="utf-8")
    )
    execution_candidates = [
        candidate
        for candidate in candidates.findings
        if candidate.origin_kind is CandidateOriginKind.DETERMINISTIC_EXECUTION
    ]
    assert len(execution_candidates) == 1
    candidate = execution_candidates[0]
    assert candidate.severity is Severity.INFORMATIONAL
    assert candidate.candidate_id in finding.contributing_candidate_ids

    reproduction_payload = json.loads(
        (result.run_dir / "reproduction-results.json").read_text(encoding="utf-8")
    )
    resolutions = reproduction_payload["candidate_resolutions"]
    assert len(resolutions) == 1
    assert resolutions[0]["candidate_id"] == candidate.candidate_id
    assert resolutions[0]["kind"] == ReproductionResolutionKind.INCONCLUSIVE.value
    assert not resolutions[0]["evidence_refs"]

    quality_gates = {gate.gate: gate for gate in result.report.quality_gates}
    assert not quality_gates["reproduction_integrity"].passed
    assert candidate.candidate_id in quality_gates["reproduction_integrity"].detail
    assert len(captured_assurance_runtime) == 1
    assurance_runtime = captured_assurance_runtime[0]
    assert assurance_runtime.eligible_high_critical_ids == {candidate.candidate_id}
    fail_closed_assessment = original_assurance_evaluate(
        MaximumAssuranceContract(config, require=True),
        assurance_runtime,
    )
    requirements = {
        requirement.engine: requirement for requirement in fail_closed_assessment.requirements
    }
    assert not requirements["critical_high_reproduction"].passed
    assert not requirements["independent_falsifier"].passed
    assert "1 candidate(s)" in requirements["independent_falsifier"].detail

    manifest_path = result.run_dir / "run-evidence-manifest.json"
    manifest = RunEvidenceManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    validate_manifest_artifacts(manifest, result.run_dir)
    verification = verify_run_evidence(
        manifest_path=manifest_path,
        run_dir=result.run_dir,
        repository_root=repository,
        config=config,
    )
    assert verification.status is RunVerificationStatus.CURRENT

    reproduction_path = result.run_dir / "reproduction-results.json"
    reproduction_payload["candidate_resolutions"] = []
    write_json(reproduction_path, reproduction_payload)

    resealed_payload = manifest.model_dump(mode="json")
    reproduction_binding = next(
        binding
        for binding in resealed_payload["artifacts"]
        if binding["path"] == reproduction_path.name
    )
    reproduction_bytes = reproduction_path.read_bytes()
    reproduction_binding["sha256"] = hashlib.sha256(reproduction_bytes).hexdigest()
    reproduction_binding["size"] = len(reproduction_bytes)
    resealed_payload["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in resealed_payload.items() if key != "manifest_sha256"}
    )
    write_run_evidence_manifest(
        manifest_path,
        RunEvidenceManifest.model_validate(resealed_payload),
    )

    verification = verify_run_evidence(
        manifest_path=manifest_path,
        run_dir=result.run_dir,
        repository_root=repository,
        config=config,
    )
    assert verification.status is RunVerificationStatus.STALE
    assert any(
        mismatch.identifier == "bindings/recalculation" for mismatch in verification.mismatches
    ), [
        (mismatch.category.value, mismatch.identifier, mismatch.kind.value)
        for mismatch in verification.mismatches
    ]

    with pytest.raises(ValueError, match="offline replay refused stale run evidence"):
        await OfflineReplayOrchestrator(config).replay(
            manifest_path=manifest_path,
            run_dir=result.run_dir,
            repository_root=repository,
            work_dir=tmp_path / "tampered-replay",
        )


@pytest.mark.asyncio
async def test_temporary_liquidity_harness_replays_settled_unsafe_and_safe_variants(
    config_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forge = shutil.which("forge")
    if forge is None:
        pytest.skip("forge is not installed")
    solc_candidates = (
        Path.home() / "Library" / "Application Support" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".local" / "share" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".svm" / "0.8.30" / "solc-0.8.30",
    )
    solc = next(
        (candidate for candidate in solc_candidates if candidate.is_file()),
        None,
    )
    if solc is None:
        pytest.skip("external Foundry-managed solc 0.8.30 is not installed")
    repository = tmp_path / "economic_temporary_liquidity"
    shutil.copytree(
        FIXTURES / "solidity" / "economic_temporary_liquidity_oracle",
        repository,
    )
    contract_names = (
        "UnsafeTemporaryLiquidityOracle",
        "SafeTemporaryLiquidityOracle",
    )
    targets = {
        **{name: f"0x{index + 2:040x}" for index, name in enumerate(contract_names)},
        **{f"{name}Asset": f"0x{index + 12:040x}" for index, name in enumerate(contract_names)},
    }
    source_path = "src/TemporaryLiquidityOracle.sol"
    local_deployments: list[LocalInvariantDeployment] = []
    for name in contract_names:
        asset_alias = f"{name}Asset"
        local_deployments.extend(
            (
                LocalInvariantDeployment(
                    target_alias=asset_alias,
                    contract_name="SyntheticLiquidityAsset",
                    source_path=source_path,
                    token_seed_function_signature="mint(address,uint256)",
                ),
                LocalInvariantDeployment(
                    target_alias=name,
                    contract_name=name,
                    source_path=source_path,
                    constructor_arguments=[
                        LocalInvariantDeploymentArgument(
                            target_alias=asset_alias,
                            cast_contract="SyntheticLiquidityAsset",
                        )
                    ],
                ),
            )
        )
    config = config_factory(
        privacy={"fail_on_detected_secret": False},
        smart_contracts={"enabled": True, "compile": True},
        reproduction={
            "enabled": False,
            "required_for_solidity": False,
            "require_hardened_isolation": False,
            "expected_chain_id": 31337,
            "targets": targets,
            "repetitions": 2,
            "max_flash_liquidity_wei": 1_000,
            "allowed_oracle_influence": "fixture_configured",
        },
        invariants={
            "execute_generated": True,
            "local_deployments": [
                deployment.model_dump(mode="json") for deployment in local_deployments
            ],
        },
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.pipeline.compile_solidity_projects",
        _synthetic_compiler,
    )
    invariant_runner = FoundryInvariantRunner(
        config.reproduction,
        config.smart_contracts,
        backend=LocalOnlyInvariantIsolationBackend(),
        forge_executable=Path(forge),
        solc_executable=solc,
    )
    pipeline = AuditPipeline(
        config,
        repo=repository,
        output=tmp_path / "temporary-liquidity-output",
        scanner_runner=StaticScannerRunner(status=ScannerStatus.UNAVAILABLE),  # type: ignore[arg-type]
        invariant_runner=invariant_runner,
    )

    result = await pipeline.run(scanner_only=True)

    payload = json.loads(
        (result.run_dir / "invariant-execution-results.json").read_text(encoding="utf-8")
    )
    executions = [
        InvariantExecutionResult.model_validate(item)
        for item in payload["results"]
        if item["economic_template"] == "flash_loan_oracle_manipulation"
    ]
    assert len(executions) == 2
    assert {execution.status for execution in executions} == {
        InvariantExecutionStatus.COUNTEREXAMPLE,
        InvariantExecutionStatus.PASSED,
    }
    assert all(
        execution.replay_confirmed
        and execution.attempts == 2
        and execution.successful_attempts == 2
        and execution.economic_metrics is not None
        and execution.economic_metrics.financial_settlement is not None
        for execution in executions
    )
    unsafe = next(
        execution
        for execution in executions
        if execution.status is InvariantExecutionStatus.COUNTEREXAMPLE
    )
    safe = next(
        execution for execution in executions if execution.status is InvariantExecutionStatus.PASSED
    )
    assert unsafe.economic_metrics is not None
    assert safe.economic_metrics is not None
    unsafe_settlement = unsafe.economic_metrics.financial_settlement
    safe_settlement = safe.economic_metrics.financial_settlement
    assert unsafe_settlement is not None
    assert safe_settlement is not None
    assert (
        unsafe_settlement.starting_assets,
        unsafe_settlement.borrowed_assets,
        unsafe_settlement.repaid_assets,
        unsafe_settlement.gross_assets_received,
        unsafe_settlement.fees_paid,
        unsafe_settlement.slippage_loss,
        unsafe_settlement.ending_assets,
        unsafe_settlement.net_impact,
    ) == (100, 1_000, 1_000, 35, 10, 5, 120, 20)
    assert (
        safe_settlement.starting_assets,
        safe_settlement.borrowed_assets,
        safe_settlement.repaid_assets,
        safe_settlement.gross_assets_received,
        safe_settlement.fees_paid,
        safe_settlement.slippage_loss,
        safe_settlement.ending_assets,
        safe_settlement.net_impact,
    ) == (100, 1_000, 1_000, 15, 10, 5, 100, 0)
    assert unsafe.minimization_evidence is not None
    assert unsafe.minimization_evidence.proven_minimal
    assert all(
        execution.isolation_backend == "synthetic-local-only-isolation"
        and "--fork-url" not in execution.command
        for execution in executions
    )
    compiler_sha256 = hashlib.sha256(solc.read_bytes()).hexdigest()
    assert all(execution.compiler_sha256 == compiler_sha256 for execution in executions)
    coverage = result.report.metadata["solidity"]["coverage"]
    template_coverage = coverage["economic_template_execution"]["flash_loan_oracle_manipulation"]
    assert template_coverage["harnesses_generated"] == 2
    assert template_coverage["harnesses_compiled"] == 2
    assert template_coverage["harnesses_executed"] == 2
    assert template_coverage["harnesses_replayed"] == 2
    assert template_coverage["counterexamples"] == 1
    assert template_coverage["counterexamples_minimized"] == 1
    assert template_coverage["statuses"] == {"counterexample": 1, "passed": 1}
    serialized_report = AuditReport.model_validate_json(
        (result.run_dir / "final-findings.json").read_text(encoding="utf-8")
    )
    serialized_executions = [
        execution
        for execution in serialized_report.invariant_executions
        if execution.economic_template is EconomicSimulationKind.FLASH_ORACLE
    ]
    assert len(serialized_executions) == 2
    assert all(
        execution.economic_metrics is not None
        and execution.economic_metrics.financial_settlement is not None
        for execution in serialized_executions
    )
    markdown = (result.run_dir / "audit-report.md").read_text(encoding="utf-8")
    assert "repaid 1000 base units" in markdown
    assert "fees 10 base units" in markdown
    assert "slippage 5 base units" in markdown
    assert "ending 120 base units" in markdown
    assert "ending 100 base units" in markdown


@pytest.mark.asyncio
async def test_amm_reserve_harness_replays_unsafe_spot_and_safe_protected_pricing(
    config_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forge = shutil.which("forge")
    if forge is None:
        pytest.skip("forge is not installed")
    solc_candidates = (
        Path.home() / "Library" / "Application Support" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".local" / "share" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".svm" / "0.8.30" / "solc-0.8.30",
    )
    solc = next(
        (candidate for candidate in solc_candidates if candidate.is_file()),
        None,
    )
    if solc is None:
        pytest.skip("external Foundry-managed solc 0.8.30 is not installed")
    repository = tmp_path / "economic_amm_reserves"
    shutil.copytree(FIXTURES / "solidity" / "economic_amm_reserves", repository)
    contract_names = (
        "UnsafeSpotReservePricing",
        "SafeProtectedReservePricing",
    )
    targets = {
        **{name: f"0x{index + 2:040x}" for index, name in enumerate(contract_names)},
        **{f"{name}Asset": f"0x{index + 12:040x}" for index, name in enumerate(contract_names)},
    }
    source_path = "src/ReservePricing.sol"
    local_deployments: list[LocalInvariantDeployment] = []
    for name in contract_names:
        asset_alias = f"{name}Asset"
        local_deployments.extend(
            (
                LocalInvariantDeployment(
                    target_alias=asset_alias,
                    contract_name="SyntheticSettlementAsset",
                    source_path=source_path,
                    token_seed_function_signature="mint(address,uint256)",
                ),
                LocalInvariantDeployment(
                    target_alias=name,
                    contract_name=name,
                    source_path=source_path,
                    constructor_arguments=[
                        LocalInvariantDeploymentArgument(
                            target_alias=asset_alias,
                            cast_contract="SyntheticSettlementAsset",
                        )
                    ],
                ),
            )
        )
    config = config_factory(
        privacy={"fail_on_detected_secret": False},
        smart_contracts={"enabled": True, "compile": True},
        reproduction={
            "enabled": False,
            "required_for_solidity": False,
            "require_hardened_isolation": False,
            "expected_chain_id": 31337,
            "targets": targets,
            "repetitions": 2,
            "allowed_oracle_influence": "fixture_configured",
        },
        invariants={
            "execute_generated": True,
            "local_deployments": [
                deployment.model_dump(mode="json") for deployment in local_deployments
            ],
        },
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.pipeline.compile_solidity_projects",
        _synthetic_compiler,
    )
    invariant_runner = FoundryInvariantRunner(
        config.reproduction,
        config.smart_contracts,
        backend=LocalOnlyInvariantIsolationBackend(),
        forge_executable=Path(forge),
        solc_executable=solc,
    )
    pipeline = AuditPipeline(
        config,
        repo=repository,
        output=tmp_path / "amm-reserve-output",
        scanner_runner=StaticScannerRunner(status=ScannerStatus.UNAVAILABLE),  # type: ignore[arg-type]
        invariant_runner=invariant_runner,
    )

    result = await pipeline.run(scanner_only=True)

    payload = json.loads(
        (result.run_dir / "invariant-execution-results.json").read_text(encoding="utf-8")
    )
    executions = [
        InvariantExecutionResult.model_validate(item)
        for item in payload["results"]
        if item["economic_template"] == "amm_reserve_manipulation"
    ]
    assert len(executions) == 2
    assert {execution.status for execution in executions} == {
        InvariantExecutionStatus.COUNTEREXAMPLE,
        InvariantExecutionStatus.PASSED,
    }
    assert all(
        execution.replay_confirmed
        and execution.attempts == 2
        and execution.successful_attempts == 2
        and execution.economic_metrics is not None
        and execution.economic_metrics.financial_settlement is not None
        for execution in executions
    )
    unsafe = next(
        execution
        for execution in executions
        if execution.status is InvariantExecutionStatus.COUNTEREXAMPLE
    )
    safe = next(
        execution for execution in executions if execution.status is InvariantExecutionStatus.PASSED
    )
    assert unsafe.economic_metrics is not None
    assert safe.economic_metrics is not None
    unsafe_settlement = unsafe.economic_metrics.financial_settlement
    safe_settlement = safe.economic_metrics.financial_settlement
    assert unsafe_settlement is not None
    assert safe_settlement is not None
    assert (
        unsafe_settlement.starting_assets,
        unsafe_settlement.borrowed_assets,
        unsafe_settlement.repaid_assets,
        unsafe_settlement.gross_assets_received,
        unsafe_settlement.fees_paid,
        unsafe_settlement.ending_assets,
        unsafe_settlement.net_impact,
    ) == (100, 0, 0, 40, 10, 130, 30)
    assert (
        safe_settlement.starting_assets,
        safe_settlement.borrowed_assets,
        safe_settlement.repaid_assets,
        safe_settlement.gross_assets_received,
        safe_settlement.fees_paid,
        safe_settlement.ending_assets,
        safe_settlement.net_impact,
    ) == (100, 0, 0, 10, 10, 100, 0)
    assert unsafe.minimization_evidence is not None
    assert unsafe.minimization_evidence.proven_minimal
    assert "constant-product reserve movement" in (unsafe.counterexample_summary or "")
    assert all(
        execution.isolation_backend == "synthetic-local-only-isolation"
        and "--fork-url" not in execution.command
        for execution in executions
    )
    compiler_sha256 = hashlib.sha256(solc.read_bytes()).hexdigest()
    assert all(execution.compiler_sha256 == compiler_sha256 for execution in executions)
    coverage = result.report.metadata["solidity"]["coverage"]
    template_coverage = coverage["economic_template_execution"]["amm_reserve_manipulation"]
    assert template_coverage["harnesses_generated"] == 2
    assert template_coverage["harnesses_compiled"] == 2
    assert template_coverage["harnesses_executed"] == 2
    assert template_coverage["harnesses_replayed"] == 2
    assert template_coverage["counterexamples"] == 1
    assert template_coverage["counterexamples_minimized"] == 1
    assert template_coverage["statuses"] == {"counterexample": 1, "passed": 1}
    serialized_report = AuditReport.model_validate_json(
        (result.run_dir / "final-findings.json").read_text(encoding="utf-8")
    )
    serialized_executions = [
        execution
        for execution in serialized_report.invariant_executions
        if execution.economic_template is EconomicSimulationKind.AMM_RESERVES
    ]
    assert len(serialized_executions) == 2
    assert all(
        execution.economic_metrics is not None
        and execution.economic_metrics.financial_settlement is not None
        for execution in serialized_executions
    )
    markdown = (result.run_dir / "audit-report.md").read_text(encoding="utf-8")
    assert "borrowed 0 base units" in markdown
    assert "fees 10 base units" in markdown
    assert "ending 130 base units" in markdown
    assert "ending 100 base units" in markdown


@pytest.mark.asyncio
async def test_liquidation_harness_replays_unsafe_health_boundary_and_safe_guard(
    config_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forge = shutil.which("forge")
    if forge is None:
        pytest.skip("forge is not installed")
    solc_candidates = (
        Path.home() / "Library" / "Application Support" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".local" / "share" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".svm" / "0.8.30" / "solc-0.8.30",
    )
    solc = next(
        (candidate for candidate in solc_candidates if candidate.is_file()),
        None,
    )
    if solc is None:
        pytest.skip("external Foundry-managed solc 0.8.30 is not installed")
    repository = tmp_path / "economic_liquidation"
    shutil.copytree(FIXTURES / "solidity" / "economic_liquidation", repository)
    contract_names = (
        "UnsafeHealthyPositionLiquidation",
        "SafeHealthyPositionLiquidation",
    )
    targets = {
        **{name: f"0x{index + 2:040x}" for index, name in enumerate(contract_names)},
        **{f"{name}Asset": f"0x{index + 12:040x}" for index, name in enumerate(contract_names)},
    }
    source_path = "src/LiquidationBoundary.sol"
    local_deployments: list[LocalInvariantDeployment] = []
    for name in contract_names:
        asset_alias = f"{name}Asset"
        local_deployments.extend(
            (
                LocalInvariantDeployment(
                    target_alias=asset_alias,
                    contract_name="SyntheticLiquidationAsset",
                    source_path=source_path,
                    token_seed_function_signature="mint(address,uint256)",
                ),
                LocalInvariantDeployment(
                    target_alias=name,
                    contract_name=name,
                    source_path=source_path,
                    constructor_arguments=[
                        LocalInvariantDeploymentArgument(
                            target_alias=asset_alias,
                            cast_contract="SyntheticLiquidationAsset",
                        )
                    ],
                ),
            )
        )
    config = config_factory(
        privacy={"fail_on_detected_secret": False},
        smart_contracts={"enabled": True, "compile": True},
        reproduction={
            "enabled": False,
            "required_for_solidity": False,
            "require_hardened_isolation": False,
            "expected_chain_id": 31337,
            "targets": targets,
            "repetitions": 2,
        },
        invariants={
            "execute_generated": True,
            "local_deployments": [
                deployment.model_dump(mode="json") for deployment in local_deployments
            ],
        },
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.pipeline.compile_solidity_projects",
        _synthetic_compiler,
    )
    invariant_runner = FoundryInvariantRunner(
        config.reproduction,
        config.smart_contracts,
        backend=LocalOnlyInvariantIsolationBackend(),
        forge_executable=Path(forge),
        solc_executable=solc,
    )
    pipeline = AuditPipeline(
        config,
        repo=repository,
        output=tmp_path / "liquidation-output",
        scanner_runner=StaticScannerRunner(status=ScannerStatus.UNAVAILABLE),  # type: ignore[arg-type]
        invariant_runner=invariant_runner,
    )

    result = await pipeline.run(scanner_only=True)

    payload = json.loads(
        (result.run_dir / "invariant-execution-results.json").read_text(encoding="utf-8")
    )
    executions = [
        InvariantExecutionResult.model_validate(item)
        for item in payload["results"]
        if item["economic_template"] == "liquidation_edge_cases"
    ]
    assert len(executions) == 2
    assert {execution.status for execution in executions} == {
        InvariantExecutionStatus.COUNTEREXAMPLE,
        InvariantExecutionStatus.PASSED,
    }
    assert all(
        execution.replay_confirmed
        and execution.attempts == 2
        and execution.successful_attempts == 2
        and execution.economic_metrics is not None
        and execution.economic_metrics.financial_settlement is not None
        and execution.economic_metrics.lending_boundary is not None
        for execution in executions
    )
    unsafe = next(
        execution
        for execution in executions
        if execution.status is InvariantExecutionStatus.COUNTEREXAMPLE
    )
    safe = next(
        execution for execution in executions if execution.status is InvariantExecutionStatus.PASSED
    )
    assert unsafe.economic_metrics is not None
    assert safe.economic_metrics is not None
    unsafe_settlement = unsafe.economic_metrics.financial_settlement
    safe_settlement = safe.economic_metrics.financial_settlement
    unsafe_boundary = unsafe.economic_metrics.lending_boundary
    safe_boundary = safe.economic_metrics.lending_boundary
    assert unsafe_settlement is not None
    assert safe_settlement is not None
    assert unsafe_boundary is not None
    assert safe_boundary is not None
    assert (
        unsafe_settlement.starting_assets,
        unsafe_settlement.borrowed_assets,
        unsafe_settlement.repaid_assets,
        unsafe_settlement.gross_assets_received,
        unsafe_settlement.ending_assets,
        unsafe_settlement.net_impact,
    ) == (10, 0, 0, 150, 160, 150)
    assert (
        safe_settlement.starting_assets,
        safe_settlement.borrowed_assets,
        safe_settlement.repaid_assets,
        safe_settlement.gross_assets_received,
        safe_settlement.ending_assets,
        safe_settlement.net_impact,
    ) == (10, 0, 0, 0, 10, 0)
    assert (
        unsafe_boundary.debt_before,
        unsafe_boundary.collateral_before,
        unsafe_boundary.debt_after,
        unsafe_boundary.collateral_after,
        unsafe_boundary.collateral_seized,
        unsafe_boundary.bad_debt_after,
    ) == (100, 150, 100, 0, 150, 100)
    assert (
        safe_boundary.debt_before,
        safe_boundary.collateral_before,
        safe_boundary.debt_after,
        safe_boundary.collateral_after,
        safe_boundary.collateral_seized,
        safe_boundary.bad_debt_after,
    ) == (100, 150, 100, 150, 0, 0)
    assert unsafe.minimization_evidence is not None
    assert unsafe.minimization_evidence.proven_minimal
    assert "debt 100 and collateral 150" in (unsafe.counterexample_summary or "")
    assert all(
        execution.isolation_backend == "synthetic-local-only-isolation"
        and "--fork-url" not in execution.command
        for execution in executions
    )
    compiler_sha256 = hashlib.sha256(solc.read_bytes()).hexdigest()
    assert all(execution.compiler_sha256 == compiler_sha256 for execution in executions)
    coverage = result.report.metadata["solidity"]["coverage"]
    template_coverage = coverage["economic_template_execution"]["liquidation_edge_cases"]
    assert template_coverage["harnesses_generated"] == 2
    assert template_coverage["harnesses_compiled"] == 2
    assert template_coverage["harnesses_executed"] == 2
    assert template_coverage["harnesses_replayed"] == 2
    assert template_coverage["counterexamples"] == 1
    assert template_coverage["counterexamples_minimized"] == 1
    assert template_coverage["statuses"] == {"counterexample": 1, "passed": 1}
    serialized_report = AuditReport.model_validate_json(
        (result.run_dir / "final-findings.json").read_text(encoding="utf-8")
    )
    serialized_executions = [
        execution
        for execution in serialized_report.invariant_executions
        if execution.economic_template is EconomicSimulationKind.LIQUIDATION
    ]
    assert len(serialized_executions) == 2
    assert all(
        execution.economic_metrics is not None
        and execution.economic_metrics.financial_settlement is not None
        and execution.economic_metrics.lending_boundary is not None
        for execution in serialized_executions
    )
    markdown = (result.run_dir / "audit-report.md").read_text(encoding="utf-8")
    assert "debt 100-&gt;100 base units" in markdown
    assert "collateral 150-&gt;0 base units" in markdown
    assert "collateral 150-&gt;150 base units" in markdown
    assert "bad debt 100 base units" in markdown
    assert "bad debt 0 base units" in markdown


@pytest.mark.asyncio
async def test_share_price_harness_replays_reported_asset_excess_and_observed_asset_rate(
    config_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forge = shutil.which("forge")
    if forge is None:
        pytest.skip("forge is not installed")
    solc_candidates = (
        Path.home() / "Library" / "Application Support" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".local" / "share" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".svm" / "0.8.30" / "solc-0.8.30",
    )
    solc = next(
        (candidate for candidate in solc_candidates if candidate.is_file()),
        None,
    )
    if solc is None:
        pytest.skip("external Foundry-managed solc 0.8.30 is not installed")
    repository = tmp_path / "economic_share_price"
    shutil.copytree(FIXTURES / "solidity" / "economic_share_price", repository)
    contract_names = (
        "UnsafeReportedAssetRateVault",
        "SafeObservedAssetRateVault",
    )
    targets = {
        **{name: f"0x{index + 2:040x}" for index, name in enumerate(contract_names)},
        **{f"{name}Asset": f"0x{index + 12:040x}" for index, name in enumerate(contract_names)},
    }
    source_path = "src/SharePriceBoundary.sol"
    local_deployments: list[LocalInvariantDeployment] = []
    for name in contract_names:
        asset_alias = f"{name}Asset"
        local_deployments.extend(
            (
                LocalInvariantDeployment(
                    target_alias=asset_alias,
                    contract_name="SyntheticRateAsset",
                    source_path=source_path,
                    token_seed_function_signature="mint(address,uint256)",
                ),
                LocalInvariantDeployment(
                    target_alias=name,
                    contract_name=name,
                    source_path=source_path,
                    constructor_arguments=[
                        LocalInvariantDeploymentArgument(
                            target_alias=asset_alias,
                            cast_contract="SyntheticRateAsset",
                        )
                    ],
                ),
            )
        )
    config = config_factory(
        privacy={"fail_on_detected_secret": False},
        smart_contracts={"enabled": True, "compile": True},
        reproduction={
            "enabled": False,
            "required_for_solidity": False,
            "require_hardened_isolation": False,
            "expected_chain_id": 31337,
            "targets": targets,
            "repetitions": 2,
        },
        invariants={
            "execute_generated": True,
            "local_deployments": [
                deployment.model_dump(mode="json") for deployment in local_deployments
            ],
        },
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.pipeline.compile_solidity_projects",
        _synthetic_compiler,
    )
    invariant_runner = FoundryInvariantRunner(
        config.reproduction,
        config.smart_contracts,
        backend=LocalOnlyInvariantIsolationBackend(),
        forge_executable=Path(forge),
        solc_executable=solc,
    )
    pipeline = AuditPipeline(
        config,
        repo=repository,
        output=tmp_path / "share-price-output",
        scanner_runner=StaticScannerRunner(status=ScannerStatus.UNAVAILABLE),  # type: ignore[arg-type]
        invariant_runner=invariant_runner,
    )

    result = await pipeline.run(scanner_only=True)

    payload = json.loads(
        (result.run_dir / "invariant-execution-results.json").read_text(encoding="utf-8")
    )
    executions = [
        InvariantExecutionResult.model_validate(item)
        for item in payload["results"]
        if item["economic_template"] == "share_price_exchange_rate"
    ]
    assert len(executions) == 2
    assert {execution.status for execution in executions} == {
        InvariantExecutionStatus.COUNTEREXAMPLE,
        InvariantExecutionStatus.PASSED,
    }
    assert all(
        execution.replay_confirmed
        and execution.attempts == 2
        and execution.successful_attempts == 2
        and execution.economic_metrics is not None
        and execution.economic_metrics.financial_settlement is not None
        and execution.economic_metrics.share_price_boundary is not None
        for execution in executions
    )
    unsafe = next(
        execution
        for execution in executions
        if execution.status is InvariantExecutionStatus.COUNTEREXAMPLE
    )
    safe = next(
        execution for execution in executions if execution.status is InvariantExecutionStatus.PASSED
    )
    assert unsafe.economic_metrics is not None
    assert safe.economic_metrics is not None
    unsafe_settlement = unsafe.economic_metrics.financial_settlement
    safe_settlement = safe.economic_metrics.financial_settlement
    unsafe_boundary = unsafe.economic_metrics.share_price_boundary
    safe_boundary = safe.economic_metrics.share_price_boundary
    assert unsafe_settlement is not None
    assert safe_settlement is not None
    assert unsafe_boundary is not None
    assert safe_boundary is not None
    assert (
        unsafe_settlement.starting_assets,
        unsafe_settlement.borrowed_assets,
        unsafe_settlement.repaid_assets,
        unsafe_settlement.gross_assets_received,
        unsafe_settlement.ending_assets,
        unsafe_settlement.net_impact,
    ) == (100, 0, 0, 150, 250, 150)
    assert (
        safe_settlement.starting_assets,
        safe_settlement.borrowed_assets,
        safe_settlement.repaid_assets,
        safe_settlement.gross_assets_received,
        safe_settlement.ending_assets,
        safe_settlement.net_impact,
    ) == (100, 0, 0, 110, 210, 110)
    assert (
        unsafe_boundary.total_assets_before,
        unsafe_boundary.total_shares_before,
        unsafe_boundary.legitimate_yield,
        unsafe_boundary.expected_rate_after_yield,
        unsafe_boundary.observed_rate_after,
        unsafe_boundary.shares_redeemed,
        unsafe_boundary.assets_redeemed,
        unsafe_boundary.excess_assets,
    ) == (1_000, 1_000, 100, 1_100, 1_500, 100, 150, 40)
    assert (
        safe_boundary.total_assets_before,
        safe_boundary.total_shares_before,
        safe_boundary.legitimate_yield,
        safe_boundary.expected_rate_after_yield,
        safe_boundary.observed_rate_after,
        safe_boundary.shares_redeemed,
        safe_boundary.assets_redeemed,
        safe_boundary.excess_assets,
    ) == (1_000, 1_000, 100, 1_100, 1_100, 100, 110, 0)
    assert unsafe.minimization_evidence is not None
    assert unsafe.minimization_evidence.proven_minimal
    assert "legitimate yield 100" in (unsafe.counterexample_summary or "")
    assert "excess assets 40" in (unsafe.counterexample_summary or "")
    assert all(
        execution.isolation_backend == "synthetic-local-only-isolation"
        and "--fork-url" not in execution.command
        for execution in executions
    )
    compiler_sha256 = hashlib.sha256(solc.read_bytes()).hexdigest()
    assert all(execution.compiler_sha256 == compiler_sha256 for execution in executions)
    coverage = result.report.metadata["solidity"]["coverage"]
    template_coverage = coverage["economic_template_execution"]["share_price_exchange_rate"]
    assert template_coverage["harnesses_generated"] == 2
    assert template_coverage["harnesses_compiled"] == 2
    assert template_coverage["harnesses_executed"] == 2
    assert template_coverage["harnesses_replayed"] == 2
    assert template_coverage["counterexamples"] == 1
    assert template_coverage["counterexamples_minimized"] == 1
    assert template_coverage["statuses"] == {"counterexample": 1, "passed": 1}
    serialized_report = AuditReport.model_validate_json(
        (result.run_dir / "final-findings.json").read_text(encoding="utf-8")
    )
    serialized_executions = [
        execution
        for execution in serialized_report.invariant_executions
        if execution.economic_template is EconomicSimulationKind.SHARE_PRICE
    ]
    assert len(serialized_executions) == 2
    assert all(
        execution.economic_metrics is not None
        and execution.economic_metrics.financial_settlement is not None
        and execution.economic_metrics.share_price_boundary is not None
        for execution in serialized_executions
    )
    markdown = (result.run_dir / "audit-report.md").read_text(encoding="utf-8")
    assert "share rate 1100-&gt;1500 per 1000" in markdown
    assert "share rate 1100-&gt;1100 per 1000" in markdown
    assert "assets redeemed 150 base units" in markdown
    assert "assets redeemed 110 base units" in markdown
    assert "excess assets 40 base units" in markdown
    assert "excess assets 0 base units" in markdown


@pytest.mark.asyncio
async def test_state_ordering_harness_persists_seed_sequence_and_removal_trials(
    config_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forge = shutil.which("forge")
    if forge is None:
        pytest.skip("forge is not installed")
    solc_candidates = (
        Path.home() / "Library" / "Application Support" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".local" / "share" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".svm" / "0.8.30" / "solc-0.8.30",
    )
    solc = next(
        (candidate for candidate in solc_candidates if candidate.is_file()),
        None,
    )
    if solc is None:
        pytest.skip("external Foundry-managed solc 0.8.30 is not installed")
    repository = tmp_path / "economic-state-ordering"
    shutil.copytree(FIXTURES / "solidity" / "economic_state_ordering", repository)
    contract_names = (
        "UnsafePreparedStateMachine",
        "SafePreparedStateMachine",
    )
    targets = {name: f"0x{index + 2:040x}" for index, name in enumerate(contract_names)}
    source_path = "src/StateOrdering.sol"
    config = config_factory(
        privacy={"fail_on_detected_secret": False},
        smart_contracts={"enabled": True, "compile": True},
        reproduction={
            "enabled": False,
            "required_for_solidity": False,
            "require_hardened_isolation": False,
            "expected_chain_id": 31337,
            "targets": targets,
            "repetitions": 2,
            "allowed_transaction_ordering": "multi_transaction",
        },
        invariants={
            "execute_generated": True,
            "local_deployments": [
                LocalInvariantDeployment(
                    target_alias=name,
                    contract_name=name,
                    source_path=source_path,
                ).model_dump(mode="json")
                for name in contract_names
            ],
        },
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.pipeline.compile_solidity_projects",
        _synthetic_compiler,
    )
    invariant_runner = FoundryInvariantRunner(
        config.reproduction,
        config.smart_contracts,
        backend=LocalOnlyInvariantIsolationBackend(),
        forge_executable=Path(forge),
        solc_executable=solc,
    )
    pipeline = AuditPipeline(
        config,
        repo=repository,
        output=tmp_path / "state-ordering-output",
        scanner_runner=StaticScannerRunner(status=ScannerStatus.UNAVAILABLE),  # type: ignore[arg-type]
        invariant_runner=invariant_runner,
    )

    result = await pipeline.run(scanner_only=True)

    payload = json.loads(
        (result.run_dir / "invariant-execution-results.json").read_text(encoding="utf-8")
    )
    executions = [
        InvariantExecutionResult.model_validate(item)
        for item in payload["results"]
        if item["economic_template"] == "multi_transaction_state_ordering"
    ]
    assert len(executions) == 2
    assert {execution.status for execution in executions} == {
        InvariantExecutionStatus.COUNTEREXAMPLE,
        InvariantExecutionStatus.PASSED,
    }
    assert all(
        execution.replay_confirmed
        and execution.attempts == 2
        and execution.successful_attempts == 2
        and execution.seed == 18
        and execution.runs == 32
        and execution.depth == 2
        and execution.required_transaction_ordering
        is TransactionOrderingCapability.MULTI_TRANSACTION
        and execution.capability_policy is not None
        and execution.capability_policy.transaction_ordering
        is TransactionOrderingCapability.MULTI_TRANSACTION
        for execution in executions
    )
    unsafe = next(
        execution
        for execution in executions
        if execution.status is InvariantExecutionStatus.COUNTEREXAMPLE
    )
    safe = next(
        execution for execution in executions if execution.status is InvariantExecutionStatus.PASSED
    )
    unsafe_campaign = unsafe.campaign_coverage
    safe_campaign = safe.campaign_coverage
    assert unsafe_campaign is not None
    assert safe_campaign is not None
    for campaign in (unsafe_campaign, safe_campaign):
        assert campaign.declared_action_functions == [
            "commitPreset()",
            "preparePreset()",
        ]
        assert campaign.observed_action_functions == [
            "commitPreset()",
            "preparePreset()",
        ]
        assert campaign.declared_state_properties == ["PreparedStateConsumedBeforeFinalization"]
        assert campaign.observed_state_properties == ["PreparedStateConsumedBeforeFinalization"]
        assert campaign.sequence_depth_bound == 2
        assert campaign.attempts_consistent
    assert unsafe_campaign.observed_sequence_lengths == [2]
    assert unsafe_campaign.minimized_sequence_action_ids == [
        "PrepareState",
        "CommitState",
    ]
    assert safe_campaign.observed_sequence_lengths == []
    assert safe_campaign.minimized_sequence_action_ids == []
    minimization = unsafe.minimization_evidence
    assert minimization is not None
    assert minimization.proven_minimal
    assert minimization.strategy == "bounded_action_removal"
    assert minimization.original_action_ids == ["PrepareState", "CommitState"]
    assert minimization.retained_action_ids == ["PrepareState", "CommitState"]
    assert minimization.foundry_original_sequence_length == 2
    assert minimization.foundry_shrunk_sequence_length == 2
    assert len(minimization.removal_trials) == 2
    assert all(
        trial.status is InvariantExecutionStatus.PASSED
        and trial.replay_confirmed
        and trial.seed == 18
        for trial in minimization.removal_trials
    )
    assert safe.minimization_evidence is None
    assert "seed 18" in (unsafe.counterexample_summary or "")
    assert "PrepareState then CommitState" in (unsafe.counterexample_summary or "")
    assert unsafe.economic_metrics is not None
    assert unsafe.economic_metrics.bounded_actions == 2
    assert all(
        execution.isolation_backend == "synthetic-local-only-isolation"
        and "--fork-url" not in execution.command
        for execution in executions
    )
    compiler_sha256 = hashlib.sha256(solc.read_bytes()).hexdigest()
    assert all(execution.compiler_sha256 == compiler_sha256 for execution in executions)
    coverage = result.report.metadata["solidity"]["coverage"]
    template_coverage = coverage["economic_template_execution"]["multi_transaction_state_ordering"]
    assert template_coverage["harnesses_generated"] == 2
    assert template_coverage["harnesses_compiled"] == 2
    assert template_coverage["harnesses_executed"] == 2
    assert template_coverage["harnesses_replayed"] == 2
    assert template_coverage["counterexamples"] == 1
    assert template_coverage["counterexamples_minimized"] == 1
    assert template_coverage["statuses"] == {"counterexample": 1, "passed": 1}
    assert coverage["invariant_campaign_functions_declared"] == 4
    assert coverage["invariant_campaign_functions_observed"] == 4
    assert coverage["invariant_campaign_state_properties_declared"] == 2
    assert coverage["invariant_campaign_state_properties_observed"] == 2
    assert coverage["invariant_counterexample_sequences_observed"] == 1
    assert coverage["invariant_counterexample_sequences_minimized"] == 1
    quality_metrics = coverage["quality_metrics"]
    assert (
        quality_metrics["invariant_campaign_function_coverage"]["numerator"],
        quality_metrics["invariant_campaign_function_coverage"]["denominator"],
    ) == (4, 4)
    assert (
        quality_metrics["invariant_campaign_state_coverage"]["numerator"],
        quality_metrics["invariant_campaign_state_coverage"]["denominator"],
    ) == (2, 2)
    assert (
        quality_metrics["invariant_campaign_sequence_coverage"]["numerator"],
        quality_metrics["invariant_campaign_sequence_coverage"]["denominator"],
    ) == (1, 1)
    harness_payload = json.loads(
        (result.run_dir / "invariant-harness-plan.json").read_text(encoding="utf-8")
    )
    sequence_harnesses = [
        item
        for item in harness_payload["harnesses"]
        if item["economic_template"] == "multi_transaction_state_ordering"
    ]
    assert len(sequence_harnesses) == 2
    assert all(
        item["required_action_sequence"] == ["PrepareState", "CommitState"] and item["seed"] == 18
        for item in sequence_harnesses
    )
    property_payload = json.loads(
        (result.run_dir / "property-corpus.json").read_text(encoding="utf-8")
    )
    property_corpus = PropertyCorpus.model_validate(property_payload["corpus"])
    assert property_corpus.corpus_hash
    assert len(property_corpus.properties) == 2
    assert {property_spec.campaign.seed for property_spec in property_corpus.properties} == {18}
    assert {property_spec.campaign.depth for property_spec in property_corpus.properties} == {2}
    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    assert any(binding.details.get("value") == "18" for binding in manifest.bindings.seeds)
    assert {binding.identifier for binding in manifest.bindings.corpora} == {
        "property-corpus/artifact",
        "property-corpus/content",
    }
    corpus_binding = next(
        binding
        for binding in manifest.bindings.corpora
        if binding.identifier == "property-corpus/content"
    )
    assert corpus_binding.sha256 == property_corpus.corpus_hash
    assert corpus_binding.details == {"properties": "2"}
    serialized_report = AuditReport.model_validate_json(
        (result.run_dir / "final-findings.json").read_text(encoding="utf-8")
    )
    serialized_executions = [
        execution
        for execution in serialized_report.invariant_executions
        if execution.economic_template is EconomicSimulationKind.STATE_ORDERING
    ]
    assert len(serialized_executions) == 2
    serialized_unsafe = next(
        execution
        for execution in serialized_executions
        if execution.status is InvariantExecutionStatus.COUNTEREXAMPLE
    )
    assert serialized_unsafe.minimization_evidence == minimization
    markdown = (result.run_dir / "audit-report.md").read_text(encoding="utf-8")
    assert "PrepareState -&gt; CommitState" in markdown
    assert "| 32 | 2 | 18 | multi\\_transaction |" in markdown
    assert "- Foundry action functions observed/declared: 4/4" in markdown
    assert "- Foundry state properties observed/declared: 2/2" in markdown
    assert "- Foundry counterexample sequences minimized/observed: 1/1" in markdown


@pytest.mark.asyncio
async def test_one_model_timeout_preserves_partial_report(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    fake = FakeOpenRouter(mode="timeout", role="source_audit")
    result = await _run(config, vulnerable_repo, tmp_path, fake)
    assert result.exit_code is ExitCode.MODEL_FAILURE
    assert not result.report.completed
    assert any("source_audit" in reason for reason in result.report.incomplete_reasons)
    assert (result.run_dir / "final-findings.json").is_file()
    assert result.report.findings


@pytest.mark.asyncio
async def test_invalid_model_json_fails_without_repair_or_credit(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    fake = FakeOpenRouter(mode="invalid_json", role="source_audit")
    result = await _run(config, vulnerable_repo, tmp_path, fake)
    assert result.exit_code is ExitCode.MODEL_FAILURE
    assert not result.report.completed
    assert not any(record.role == "source_audit:json_repair" for record in result.report.usage)
    assert not any(
        record.role == "source_audit" and record.status == "success"
        for record in result.report.usage
    )


@pytest.mark.asyncio
async def test_authentication_failure_is_partial(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    result = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        FakeOpenRouter(mode="authentication_failure"),
    )
    assert result.exit_code is ExitCode.MODEL_FAILURE
    assert not result.report.completed
    assert (result.run_dir / "audit-report.md").is_file()


@pytest.mark.asyncio
async def test_budget_exhaustion_halts_model_calls(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    config = config_factory(
        privacy={"fail_on_detected_secret": False},
        execution={
            "budget_usd": 0.000001,
            "conservative_usd_per_million_tokens": 1_000,
        },
    )
    fake = FakeOpenRouter()
    result = await _run(config, vulnerable_repo, tmp_path, fake)
    assert result.exit_code is ExitCode.INCOMPLETE
    assert fake.chat_calls == 0
    assert any("could cost" in reason for reason in result.report.incomplete_reasons)


@pytest.mark.asyncio
async def test_secret_detection_blocks_all_model_calls(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    synthetic = "AKIA" + ("Z" * 16)
    (vulnerable_repo / "credentials.py").write_text(
        f"SYNTHETIC = '{synthetic}'\n", encoding="utf-8"
    )
    fake = FakeOpenRouter()
    result = await _run(config_factory(), vulnerable_repo, tmp_path, fake)
    assert result.exit_code is ExitCode.PRIVACY_REFUSAL
    assert fake.chat_calls == 0
    assert "egress blocked" in " ".join(result.report.incomplete_reasons)


@pytest.mark.asyncio
async def test_zdr_eligibility_failure_is_closed(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    fake = FakeOpenRouter(mode="zdr_failure")
    result = await _run(config, vulnerable_repo, tmp_path, fake)
    assert result.exit_code is ExitCode.MODEL_FAILURE
    assert fake.chat_calls == 0
    assert any("ZDR" in reason for reason in result.report.incomplete_reasons)


@pytest.mark.asyncio
async def test_invalid_file_location_is_rejected(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    result = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        FakeOpenRouter(mode="invalid_location"),
    )
    assert result.report.rejected_findings
    assert any(not finding.location_validation.valid for finding in result.report.rejected_findings)
    candidates = CandidateFindingArtifact.model_validate_json(
        (result.run_dir / "candidate-findings.json").read_text(encoding="utf-8")
    )
    required_resolution_ids = {
        candidate.candidate_id
        for candidate in candidates.findings
        if candidate.severity in {Severity.HIGH, Severity.CRITICAL}
    }
    reproduction_payload = json.loads(
        (result.run_dir / "reproduction-results.json").read_text(encoding="utf-8")
    )
    assert required_resolution_ids <= {
        resolution["candidate_id"] for resolution in reproduction_payload["candidate_resolutions"]
    }


@pytest.mark.asyncio
async def test_invalid_threat_model_location_is_removed_and_recorded(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    result = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        FakeOpenRouter(mode="invalid_threat_location"),
    )
    verification = json.loads(
        (result.run_dir / "verification-results.json").read_text(encoding="utf-8")
    )
    assert verification["threat_model"]["trust_boundaries"][0]["locations"] == []
    assert "missing.py:1-1" in verification["threat_model_location_rejections"][0]
    assert result.report.metadata["threat_model_location_rejections"] == 1


@pytest.mark.asyncio
async def test_verifier_rejection_survives_for_explanation(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    result = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        FakeOpenRouter(mode="verifier_rejection"),
    )
    assert result.report.findings == []
    assert result.report.rejected_findings
    assert all(finding.status == "rejected" for finding in result.report.rejected_findings)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["verifier_omission", "judge_omission"])
async def test_omitted_role_decision_marks_partial_report(
    config_factory, vulnerable_repo: Path, tmp_path: Path, mode: str
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    result = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        FakeOpenRouter(mode=mode),
    )
    assert result.exit_code is ExitCode.MODEL_FAILURE
    assert not result.report.completed
    assert result.report.findings or result.report.rejected_findings
    assert any(
        "omitted" in reason or "incomplete" in reason for reason in result.report.incomplete_reasons
    )


@pytest.mark.asyncio
async def test_duplicate_candidates_merge_and_ids_are_deterministic(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    first = await _run(config, vulnerable_repo, tmp_path / "one", FakeOpenRouter())
    second = await _run(config, vulnerable_repo, tmp_path / "two", FakeOpenRouter())
    first_ids = sorted(finding.id for finding in first.report.findings)
    second_ids = sorted(finding.id for finding in second.report.findings)
    assert first_ids == second_ids
    sql = next(finding for finding in first.report.findings if "SQL" in finding.title)
    assert len(sql.contributing_candidate_ids) == 2


@pytest.mark.asyncio
async def test_required_scanner_timeout_stops_before_models(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    fake = FakeOpenRouter()
    result = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        fake,
        scanner_runner=StaticScannerRunner(
            status=ScannerStatus.TIMED_OUT,
            required=True,
        ),
    )
    assert result.exit_code is ExitCode.SCANNER_FAILURE
    assert fake.chat_calls == 0
    assert result.report.scanner_runs[0].status is ScannerStatus.TIMED_OUT


@pytest.mark.asyncio
async def test_zero_completed_analysis_fails_closed(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    config = config_factory()
    fake = FakeOpenRouter()
    client, http_client = _provider(config, fake)
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path / "output",
        client=client,
        scanner_runner=StaticScannerRunner(  # type: ignore[arg-type]
            status=ScannerStatus.UNAVAILABLE,
            required=False,
        ),
    )
    try:
        result = await pipeline.run(scanner_only=True)
    finally:
        await http_client.aclose()
    assert result.exit_code is ExitCode.INCOMPLETE
    assert result.exit_for_findings(None) is ExitCode.INCOMPLETE
    assert result.exit_for_findings(Severity.CRITICAL) is ExitCode.INCOMPLETE
    assert not result.report.completed
    assert result.report.quality_status is AuditQualityStatus.INCOMPLETE
    assert result.report.run_status is AuditRunStatus.INCOMPLETE
    assert result.report.minimum_analysis_floor is not None
    assert not result.report.minimum_analysis_floor.minimum_floor_met
    assert not result.report.findings
    assert not result.report.rejected_findings
    assert not result.report.usage
    assert not any(run.status is ScannerStatus.SUCCESS for run in result.report.scanner_runs)
    floor_gate = next(
        gate for gate in result.report.quality_gates if gate.gate == "minimum_analysis_floor"
    )
    assert floor_gate.required
    assert not floor_gate.passed
    assert floor_gate.state is AnalysisState.NOT_ANALYZED
    assert any(
        "minimum_analysis_floor" in reason and "real scanner" in reason and "real model" in reason
        for reason in result.report.incomplete_reasons
    )
    assert fake.chat_calls == 0
    context_manifest = load_context_manifest(result.run_dir / "context-manifest.json")
    assert context_manifest.run_id == result.report.run_id
    assert context_manifest.requests == ()
    assert result.report.metadata["context_manifest"] == context_manifest_report_binding(
        context_manifest
    ).model_dump(mode="json")
    assert (tmp_path / "output" / "latest" / "context-manifest.json").read_bytes() == (
        result.run_dir / "context-manifest.json"
    ).read_bytes()
    serialized_report = AuditReport.model_validate_json(
        (result.run_dir / "final-findings.json").read_text(encoding="utf-8")
    )
    assert not serialized_report.completed
    assert serialized_report.quality_status is AuditQualityStatus.INCOMPLETE
    assert serialized_report.run_status is AuditRunStatus.INCOMPLETE
    metadata = json.loads((result.run_dir / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["completed"] is False
    assert metadata["quality_status"] == AuditQualityStatus.INCOMPLETE.value
    assert metadata["run_status"] == AuditRunStatus.INCOMPLETE.value
    markdown = (result.run_dir / "audit-report.md").read_text(encoding="utf-8")
    assert (
        "No reportable findings were identified by the analyses that completed. "
        "This run is incomplete and does not support a conclusion about repository safety."
        in markdown
    )


@pytest.mark.asyncio
async def test_dependency_preparation_emits_validated_artifacts_without_discovery_leakage(
    config_factory,
    tmp_path: Path,
) -> None:
    repository, snapshot_sha256 = _dependency_repo(tmp_path)
    config = config_factory(
        privacy={"fail_on_detected_secret": False},
        dependency_preparation={
            "enabled": True,
            "required": True,
            "offline_snapshot_path": ".mmaudit-dependencies/snapshot.json",
            "offline_snapshot_sha256": snapshot_sha256,
        },
    )
    pipeline = AuditPipeline(
        config,
        repo=repository,
        output=tmp_path / "dependency-output",
        scanner_runner=StaticScannerRunner(  # type: ignore[arg-type]
            status=ScannerStatus.UNAVAILABLE,
        ),
    )

    result = await pipeline.run(scanner_only=True)

    assert result.exit_code is ExitCode.INCOMPLETE
    assert not result.report.completed
    assert result.report.run_status is AuditRunStatus.INCOMPLETE
    preparation_payload = json.loads(
        (result.run_dir / "dependency-preparation.json").read_text(encoding="utf-8")
    )
    preparation = DependencyPreparationResult.model_validate(preparation_payload["results"][0])
    assert preparation.status is DependencyPreparationStatus.PREPARED
    assert preparation.snapshot_sha256 == snapshot_sha256
    sbom_payload = json.loads((result.run_dir / "dependency-sbom.json").read_text(encoding="utf-8"))
    sbom = DependencySbom.model_validate(sbom_payload["documents"][0])
    assert [component.name for component in sbom.components] == ["safe-dep"]
    repository_map = (result.run_dir / "repository-map.json").read_text(encoding="utf-8")
    assert ".mmaudit-dependencies" not in repository_map
    assert "not-required" not in repository_map
    assert (result.run_dir / "audit-report.md").read_text(encoding="utf-8").count(
        "## Dependency preparation"
    ) == 1
    for artifact in ("dependency-preparation.json", "dependency-sbom.json"):
        assert (tmp_path / "dependency-output" / "latest" / artifact).is_file()


@pytest.mark.asyncio
async def test_required_deployment_scope_is_incomplete_when_evidence_is_missing(
    config_factory,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "contracts_without_deployment"
    (repo / "src").mkdir(parents=True)
    (repo / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\n',
        encoding="utf-8",
    )
    (repo / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.24;\ncontract Vault {}\n",
        encoding="utf-8",
    )
    config = config_factory(
        scope={
            "mode": AuditScope.CONTRACTS_AND_DEPLOYMENT,
            "require_complete": True,
        },
        privacy={"fail_on_detected_secret": False},
    )
    pipeline = AuditPipeline(
        config,
        repo=repo,
        output=tmp_path / "scope-output",
        scanner_runner=StaticScannerRunner(  # type: ignore[arg-type]
            status=ScannerStatus.UNAVAILABLE,
        ),
    )

    result = await pipeline.run(scanner_only=True)

    assert result.exit_code is ExitCode.INCOMPLETE
    assert not result.report.completed
    assert result.report.scope_assessment is not None
    assert result.report.scope_assessment.requested is AuditScope.CONTRACTS_AND_DEPLOYMENT
    assert result.report.scope_assessment.achieved is AuditScope.CONTRACTS_ONLY
    scope_gate = next(
        gate for gate in result.report.quality_gates if gate.gate == "requested_audit_scope"
    )
    assert scope_gate.required
    assert not scope_gate.passed
    payload = json.loads((result.run_dir / "scope-assessment.json").read_text(encoding="utf-8"))
    assert (
        AuditScopeAssessment.model_validate(payload["assessment"]) == result.report.scope_assessment
    )
    assert "Requested and achieved scope" in (result.run_dir / "audit-report.md").read_text(
        encoding="utf-8"
    )


@pytest.mark.asyncio
async def test_required_infeasible_scope_blocks_provider_spend(
    config_factory,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "contracts_without_required_deployment"
    (repo / "src").mkdir(parents=True)
    (repo / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\n',
        encoding="utf-8",
    )
    (repo / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.24;\ncontract Vault {}\n",
        encoding="utf-8",
    )
    config = config_factory(
        scope={
            "mode": AuditScope.CONTRACTS_AND_DEPLOYMENT,
            "require_complete": True,
        },
        privacy={"fail_on_detected_secret": False},
    )
    fake = FakeOpenRouter()
    client, http_client = _provider(config, fake)
    pipeline = AuditPipeline(
        config,
        repo=repo,
        output=tmp_path / "scope-preflight-output",
        client=client,
        scanner_runner=StaticScannerRunner(  # type: ignore[arg-type]
            status=ScannerStatus.UNAVAILABLE,
        ),
    )
    try:
        result = await pipeline.run(allow_code_egress=True)
    finally:
        await http_client.aclose()

    assert result.exit_code is ExitCode.INCOMPLETE
    assert not result.report.completed
    assert fake.requests == []
    assert any(
        "quality gate failed before provider spend: requested_audit_scope" in reason
        for reason in result.report.incomplete_reasons
    )


@pytest.mark.asyncio
async def test_infeasible_model_surface_assignments_block_provider_spend(
    config_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _foundry_repo(tmp_path, patched=True)
    config = config_factory(
        privacy={"fail_on_detected_secret": False},
        smart_contracts={"compile": False},
        reproduction={"required_for_solidity": False},
    )
    fake = FakeOpenRouter()
    monkeypatch.setattr(
        "mmaudit.orchestration.pipeline.plan_model_surface_review_assignments",
        lambda *_args, **_kwargs: {},
    )

    result = await _run(
        config,
        repository,
        tmp_path,
        fake,
        scanner_runner=StaticScannerRunner(status=ScannerStatus.UNAVAILABLE),
    )

    assert result.exit_code is ExitCode.INCOMPLETE
    assert result.report.run_status is AuditRunStatus.FAILED
    assert fake.requests == []
    gate = next(
        item
        for item in result.report.quality_gates
        if item.gate == "model_surface_assignment_feasibility"
    )
    assert gate.required
    assert not gate.passed
    assert any(
        "quality gate failed before provider spend: model_surface_assignment_feasibility" in reason
        for reason in result.report.incomplete_reasons
    )


@pytest.mark.asyncio
async def test_formal_adapter_failure_prevents_complete_and_provider_spend(
    config_factory,
    tmp_path: Path,
) -> None:
    class FailingFormalRunner:
        def run(self, **_kwargs: Any) -> list[Any]:
            raise RuntimeError("synthetic formal adapter failure")

    repository = _foundry_repo(tmp_path, patched=True)
    config = config_factory(
        privacy={"fail_on_detected_secret": False},
        smart_contracts={"compile": False},
        reproduction={"required_for_solidity": False},
        formal={"enabled": True},
    )
    fake = FakeOpenRouter()

    result = await _run(
        config,
        repository,
        tmp_path,
        fake,
        scanner_runner=StaticScannerRunner(status=ScannerStatus.UNAVAILABLE),
        formal_runner=FailingFormalRunner(),
    )

    assert result.exit_code is ExitCode.INCOMPLETE
    assert result.report.run_status is AuditRunStatus.FAILED
    assert fake.requests == []
    assert any(
        reason == "formal adapter layer failed safely: RuntimeError"
        for reason in result.report.incomplete_reasons
    )


@pytest.mark.asyncio
async def test_scanner_only_findings_are_needs_review_and_in_sarif(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    config = config_factory()
    fake = FakeOpenRouter()
    client, http_client = _provider(config, fake)
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path / "output",
        client=client,
        scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
    )
    try:
        result = await pipeline.run(scanner_only=True)
    finally:
        await http_client.aclose()
    assert [finding.status.value for finding in result.report.findings] == ["needs_review"]
    assert result.exit_for_findings(Severity.HIGH) is ExitCode.INCOMPLETE
    assert not result.report.completed
    assert result.report.run_status is AuditRunStatus.INCOMPLETE
    sarif = json.loads((result.run_dir / "audit-results.sarif").read_text(encoding="utf-8"))
    assert len(sarif["runs"][0]["results"]) == 1


@pytest.mark.asyncio
async def test_scanner_only_prior_match_satisfies_required_missed_finding_gate(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    prior_path = vulnerable_repo / "audit" / "prior.json"
    prior_path.parent.mkdir()
    source_lines = (
        (vulnerable_repo / "app.py").read_text(encoding="utf-8").splitlines(keepends=True)
    )
    prior_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "findings": [
                    {
                        "prior_id": "SCANNER-PRIOR-001",
                        "title": "Synthetic scanner finding",
                        "severity": "high",
                        "cwe": ["CWE-89"],
                        "previous_state": "open",
                        "locations": [
                            {
                                "path": "app.py",
                                "start_line": 13,
                                "end_line": 13,
                                "historical_content_sha256": hashlib.sha256(
                                    source_lines[12].encode()
                                ).hexdigest(),
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    config = config_factory(
        prior_audit={
            "path": "audit/prior.json",
            "required": True,
            "fail_on_missed": True,
        }
    )
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path / "scanner-prior-output",
        scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
    )

    result = await pipeline.run(scanner_only=True)

    assert result.exit_code is ExitCode.INCOMPLETE
    assert not result.report.completed
    assert result.report.run_status is AuditRunStatus.INCOMPLETE
    comparison = result.report.prior_audit_comparison
    assert comparison is not None
    assert comparison.model_request_count_before_load == 0
    assert comparison.items[0].matched_candidate_ids == []
    assert comparison.items[0].matched_finding_ids
    assert comparison.items[0].discovery_status is PriorAuditDiscoveryStatus.REDISCOVERED
    gate = next(
        gate for gate in result.report.quality_gates if gate.gate == "prior_audit_comparison"
    )
    assert gate.required
    assert gate.passed


@pytest.mark.asyncio
async def test_required_missed_prior_finding_makes_run_incomplete(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    prior_path = vulnerable_repo / "audit" / "prior.json"
    prior_path.parent.mkdir()
    source_lines = (
        (vulnerable_repo / "app.py").read_text(encoding="utf-8").splitlines(keepends=True)
    )
    prior_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "findings": [
                    {
                        "prior_id": "MISSED-PRIOR-001",
                        "title": "Source-valid prior finding",
                        "severity": "high",
                        "cwe": ["CWE-89"],
                        "previous_state": "open",
                        "locations": [
                            {
                                "path": "app.py",
                                "start_line": 13,
                                "end_line": 13,
                                "historical_content_sha256": hashlib.sha256(
                                    source_lines[12].encode()
                                ).hexdigest(),
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    config = config_factory(
        prior_audit={
            "path": "audit/prior.json",
            "fail_on_missed": True,
        }
    )
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path / "missed-prior-output",
        scanner_runner=StaticScannerRunner(  # type: ignore[arg-type]
            status=ScannerStatus.UNAVAILABLE,
        ),
    )

    result = await pipeline.run(scanner_only=True)

    assert result.exit_code is ExitCode.INCOMPLETE
    comparison = result.report.prior_audit_comparison
    assert comparison is not None
    assert comparison.items[0].discovery_status is PriorAuditDiscoveryStatus.MISSED
    assert comparison.items[0].remediation_status is PriorAuditRemediationStatus.UNRESOLVED
    gate = next(
        gate for gate in result.report.quality_gates if gate.gate == "prior_audit_comparison"
    )
    assert gate.required
    assert not gate.passed
    assert "missed=1" in gate.detail


@pytest.mark.asyncio
async def test_ignored_lockfile_scanner_finding_stays_local_and_reported(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    (vulnerable_repo / "requirements.lock").write_text(
        "synthetic-package==0.0\n",
        encoding="utf-8",
    )
    config = config_factory()
    fake = FakeOpenRouter()
    client, http_client = _provider(config, fake)
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path / "output",
        client=client,
        scanner_runner=StaticScannerRunner(  # type: ignore[arg-type]
            finding_path="requirements.lock",
            finding_line=1,
        ),
    )
    try:
        result = await pipeline.run(scanner_only=True)
    finally:
        await http_client.aclose()
    assert result.report.repository.files
    assert "requirements.lock" not in {file.path for file in result.report.repository.files}
    assert result.report.scanner_runs[0].findings[0].locations[0].path == "requirements.lock"
    assert result.report.findings[0].status is FindingStatus.NEEDS_REVIEW
    assert fake.chat_calls == 0


@pytest.mark.asyncio
async def test_code_egress_defaults_to_refusal(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    config = config_factory(
        privacy={
            "allow_code_egress": False,
            "fail_on_detected_secret": False,
        }
    )
    fake = FakeOpenRouter()
    client, http_client = _provider(config, fake)
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path / "output",
        client=client,
        scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
    )
    try:
        result = await pipeline.run(allow_code_egress=False)
    finally:
        await http_client.aclose()
    assert result.exit_code is ExitCode.PRIVACY_REFUSAL
    assert result.report.privacy["code_egress_enabled"] is False
    assert fake.chat_calls == 0


@pytest.mark.asyncio
async def test_first_pass_contexts_exclude_peer_model_findings(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    specialist_models = {
        "access_control": {
            "primary": "specialist-alpha/access-review",
            "fallbacks": [],
        },
        "reentrancy_control_flow": {
            "primary": "specialist-bravo/control-flow-review",
            "fallbacks": [],
        },
    }
    base_registry = [entry.model_dump(mode="json") for entry in config_factory().models.registry]
    specialist_registry = [
        model_registry_entry(slot["primary"]) for slot in specialist_models.values()
    ]
    registry = [*base_registry, *specialist_registry]
    config = config_factory(
        profile=AuditProfile.DEEP,
        privacy={
            "fail_on_detected_secret": False,
            "approved_model_lineages": [entry["root_lineage"] for entry in registry],
        },
        models={
            "specialists": specialist_models,
            "registry": registry,
        },
    )
    canary = "MODEL_OUTPUT_CANARY_7F31C2"
    fake = FakeOpenRouter(
        first_pass_canary=canary,
        extra_model_ids=[slot["primary"] for slot in specialist_models.values()],
    )

    result = await _run(config, vulnerable_repo, tmp_path, fake)

    assert result.exit_code is ExitCode.INCOMPLETE
    assert not result.report.completed
    assert result.report.run_status is AuditRunStatus.INCOMPLETE
    first_pass_schemas = {
        "mmaudit_source_audit_findings",
        "mmaudit_business_logic_findings",
        "mmaudit_configuration_findings",
        "mmaudit_specialist_access_control",
        "mmaudit_specialist_reentrancy_control_flow",
    }
    first_pass_requests = [
        request for request in fake.requests if _request_schema_name(request) in first_pass_schemas
    ]
    assert {_request_schema_name(request) for request in first_pass_requests} == first_pass_schemas
    assert all(canary not in request["messages"][1]["content"] for request in first_pass_requests)
    verifier_request = next(
        request
        for request in fake.requests
        if _request_schema_name(request) == "mmaudit_verification"
    )
    assert canary in verifier_request["messages"][1]["content"]


def test_pipeline_refuses_symlinked_output_root(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    output_link = tmp_path / "reports"
    try:
        output_link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="symlinked output"):
        AuditPipeline(
            config_factory(),
            repo=vulnerable_repo,
            output=output_link,
            scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_pipeline_excludes_custom_in_repository_output_from_frozen_scanner_source(
    config_factory,
    vulnerable_repo: Path,
) -> None:
    output = vulnerable_repo / "custom-audit-output"
    nested_same_name = vulnerable_repo / "src" / "custom-audit-output" / "keep.py"
    nested_same_name.parent.mkdir(parents=True)
    nested_same_name.write_text("VALUE = 1\n", encoding="utf-8")
    scanner_runner = StaticScannerRunner()
    config = config_factory()
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=output,
        scanner_runner=scanner_runner,  # type: ignore[arg-type]
    )

    result = await pipeline.run(scanner_only=True)

    assert scanner_runner.repository_exclusion_root == output.resolve(strict=True)
    assert scanner_runner.expected_repository_sha256 == scanner_workspace_sha256(
        vulnerable_repo,
        output,
        allow_custom_private_exclusion=True,
    )
    repository_map = json.loads(
        (result.run_dir / "repository-map.json").read_text(encoding="utf-8")
    )
    discovered_paths = {item["path"] for item in repository_map["files"]}
    assert "src/custom-audit-output/keep.py" in discovered_paths
    assert not any(path.startswith("custom-audit-output/") for path in discovered_paths)


@pytest.mark.asyncio
async def test_pipeline_rejects_preexisting_custom_output_as_a_source_exclusion(
    config_factory,
    vulnerable_repo: Path,
) -> None:
    output = vulnerable_repo / "custom-audit-output"
    output.mkdir()
    (output / "PotentialSource.sol").write_text(
        "contract PotentialSource {}\n",
        encoding="utf-8",
    )
    scanner_runner = StaticScannerRunner()
    pipeline = AuditPipeline(
        config_factory(
            scanners={"foundry_fork": {"enabled": True, "required": False}},
        ),
        repo=vulnerable_repo,
        output=output,
        scanner_runner=scanner_runner,  # type: ignore[arg-type]
    )

    result = await pipeline.run(scanner_only=True)

    assert scanner_runner.calls == 0
    assert result.exit_code is ExitCode.INCOMPLETE
    assert any(
        "repository execution source identity could not be frozen before discovery" in limitation
        for limitation in result.report.incomplete_reasons
    )
    assert any(
        "audited source inventory is incompatible with scanner execution workspaces" in limitation
        for limitation in result.report.incomplete_reasons
    )


@pytest.mark.asyncio
async def test_pipeline_external_output_ancestor_does_not_exclude_repository_source(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    scanner_runner = StaticScannerRunner()
    expected_source = scanner_workspace_sha256(vulnerable_repo)
    config = config_factory(
        scanners={"foundry_fork": {"enabled": True, "required": False}},
    )
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path,
        scanner_runner=scanner_runner,  # type: ignore[arg-type]
    )

    await pipeline.run(scanner_only=True)

    assert scanner_runner.expected_repository_sha256 == expected_source
    assert scanner_runner.repository_exclusion_root == (
        vulnerable_repo.resolve(strict=True) / ".mmaudit"
    )


@pytest.mark.asyncio
async def test_pipeline_blocks_scanners_when_discovery_reincludes_excluded_source(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    explicitly_audited = vulnerable_repo / "vendor" / "ExplicitlyAudited.sol"
    explicitly_audited.parent.mkdir()
    explicitly_audited.write_text("contract ExplicitlyAudited {}\n", encoding="utf-8")
    (vulnerable_repo / ".mmauditignore").write_text("!vendor/**\n", encoding="utf-8")
    scanner_runner = StaticScannerRunner()
    pipeline = AuditPipeline(
        config_factory(),
        repo=vulnerable_repo,
        output=tmp_path / "output",
        scanner_runner=scanner_runner,  # type: ignore[arg-type]
    )

    result = await pipeline.run(scanner_only=True)

    repository_map = json.loads(
        (result.run_dir / "repository-map.json").read_text(encoding="utf-8")
    )
    assert "vendor/ExplicitlyAudited.sol" in {item["path"] for item in repository_map["files"]}
    assert scanner_runner.calls == 0
    assert result.exit_code is ExitCode.INCOMPLETE
    assert any(
        "audited source inventory is incompatible with scanner execution workspaces" in limitation
        for limitation in result.report.incomplete_reasons
    )


@pytest.mark.asyncio
async def test_pipeline_freezes_scanner_source_before_discovery(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mmaudit.orchestration import pipeline as pipeline_module

    output = tmp_path / "frozen-source-output"
    expected_before_discovery = scanner_workspace_sha256(vulnerable_repo, output)
    scanner_runner = StaticScannerRunner()
    original_discover = pipeline_module.discover_repository

    def discover_then_add_source(*args: Any, **kwargs: Any):
        discovery = original_discover(*args, **kwargs)
        (vulnerable_repo / "late-added.sol").write_text(
            "contract LateAdded {}\n",
            encoding="utf-8",
        )
        return discovery

    monkeypatch.setattr(pipeline_module, "discover_repository", discover_then_add_source)
    config = config_factory(
        scanners={"foundry_fork": {"enabled": True, "required": False}},
    )
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=output,
        scanner_runner=scanner_runner,  # type: ignore[arg-type]
    )

    result = await pipeline.run(scanner_only=True)

    assert result.exit_code is ExitCode.INCOMPLETE
    assert scanner_runner.calls == 0
    assert scanner_runner.expected_repository_sha256 is None
    assert scanner_runner.repository_exclusion_root is None
    assert scanner_workspace_sha256(vulnerable_repo, output) != expected_before_discovery
    assert any(
        "repository execution source changed during discovery" in limitation
        for limitation in result.report.incomplete_reasons
    )


@pytest.mark.asyncio
async def test_pipeline_revalidates_frozen_source_after_scanner_execution(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    output = tmp_path / "post-scanner-source-output"
    expected_source = scanner_workspace_sha256(vulnerable_repo, output)

    def add_source_during_scanner() -> None:
        (vulnerable_repo / "scanner-added.sol").write_text(
            "contract ScannerAdded {}\n",
            encoding="utf-8",
        )

    scanner_runner = StaticScannerRunner(before_return=add_source_during_scanner)
    config = config_factory()
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=output,
        scanner_runner=scanner_runner,  # type: ignore[arg-type]
    )

    result = await pipeline.run(scanner_only=True)

    assert result.exit_code is ExitCode.INCOMPLETE
    assert scanner_runner.expected_repository_sha256 == expected_source
    assert scanner_workspace_sha256(vulnerable_repo, output) != expected_source
    assert any(
        "audited source changed during scanner execution" in limitation
        for limitation in result.report.incomplete_reasons
    )


@pytest.mark.asyncio
async def test_pipeline_converts_scanner_source_custody_failure_to_incomplete(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    expected_source = scanner_workspace_sha256(vulnerable_repo)
    scanner_runner = StaticScannerRunner(source_integrity_error=True)
    pipeline = AuditPipeline(
        config_factory(),
        repo=vulnerable_repo,
        output=tmp_path / "scanner-custody-failure-output",
        scanner_runner=scanner_runner,  # type: ignore[arg-type]
    )

    result = await pipeline.run(scanner_only=True)

    assert result.exit_code is ExitCode.INCOMPLETE
    assert scanner_runner.expected_repository_sha256 == expected_source
    assert any(
        "audited source identity could not be preserved through scanner execution" in limitation
        for limitation in result.report.incomplete_reasons
    )
    assert result.report.scanner_runs == []


@pytest.mark.asyncio
async def test_pipeline_persists_configured_repository_fork_matrix_failure(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = config_factory(
        scanners={"foundry_fork": {"enabled": True, "required": False}},
        smart_contracts=_repository_fork_matrix_config_override(),
    )
    matrix_runner = StaticRepositoryForkMatrixRunner(
        configuration_sha256=config.smart_contracts.repository_suite.stable_hash()
    )
    scanner_runner = StaticScannerRunner(scanner_name="foundry_fork")
    scanner_runner.backend = object()  # type: ignore[attr-defined]
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path / "matrix-output",
        scanner_runner=scanner_runner,  # type: ignore[arg-type]
        repository_fork_matrix_runner=matrix_runner,  # type: ignore[arg-type]
    )

    deadline_window_start = time.monotonic()
    result = await pipeline.run(scanner_only=True)
    deadline_window_end = time.monotonic()

    assert result.exit_code is ExitCode.INCOMPLETE
    assert len(matrix_runner.calls) == 1
    call = matrix_runner.calls[0]
    assert call["root"] == vulnerable_repo.resolve(strict=True)
    assert call["baseline_run"].scanner == "foundry_fork"
    assert call["repository_sha256"] == scanner_runner.expected_repository_sha256
    assert call["repository_exclusion_root"] == scanner_runner.repository_exclusion_root
    timeout_budget = repository_fork_matrix_timeout_budget_seconds(
        config.smart_contracts.repository_suite
    )
    assert deadline_window_start + timeout_budget <= call["absolute_deadline"]
    assert call["absolute_deadline"] <= deadline_window_end + timeout_budget
    differential = result.report.repository_suite_differential
    assert differential is not None
    assert differential.status is RepositoryDifferentialRunStatus.FAILED
    assert result.report.privacy["fork_rpc_egress"]["status"] == "unverified"
    assert json.loads(
        (result.run_dir / "repository-suite-differential.json").read_text(encoding="utf-8")
    ) == differential.model_dump(mode="json")
    fork_privacy = (result.run_dir / "privacy-fork-rpc-egress.json").read_text(encoding="utf-8")
    assert "http://" not in fork_privacy
    assert "127.0.0.1" not in fork_privacy
    scanner_artifact = json.loads(
        (result.run_dir / "scanner-results.json").read_text(encoding="utf-8")
    )
    assert [run["scanner"] for run in scanner_artifact["runs"]] == ["foundry_fork"]
    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    validate_manifest_artifacts(manifest, result.run_dir)


@pytest.mark.asyncio
async def test_pipeline_revalidates_frozen_source_after_repository_fork_matrix(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = config_factory(
        scanners={"foundry_fork": {"enabled": True, "required": False}},
        smart_contracts=_repository_fork_matrix_config_override(),
    )

    def mutate_repository() -> None:
        (vulnerable_repo / "matrix-added.sol").write_text(
            "contract MatrixAdded {}\n",
            encoding="utf-8",
        )

    matrix_runner = StaticRepositoryForkMatrixRunner(
        configuration_sha256=config.smart_contracts.repository_suite.stable_hash(),
        before_return=mutate_repository,
    )
    scanner_runner = StaticScannerRunner(scanner_name="foundry_fork")
    scanner_runner.backend = object()  # type: ignore[attr-defined]
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path / "matrix-mutation-output",
        scanner_runner=scanner_runner,  # type: ignore[arg-type]
        repository_fork_matrix_runner=matrix_runner,  # type: ignore[arg-type]
    )

    result = await pipeline.run(scanner_only=True)

    assert len(matrix_runner.calls) == 1
    assert result.exit_code is ExitCode.INCOMPLETE
    assert any(
        "audited source changed during scanner execution" in reason
        for reason in result.report.incomplete_reasons
    )
    assert (
        scanner_workspace_sha256(
            vulnerable_repo,
            scanner_runner.repository_exclusion_root,
        )
        != matrix_runner.calls[0]["repository_sha256"]
    )


@pytest.mark.asyncio
async def test_pipeline_benchmark_gate_fails_before_run_without_verification(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    output = tmp_path / "benchmark-required-output"
    config = config_factory(
        maximum_assurance={"benchmark_gate": True},
    )
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=output,
        scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match="requires current certificate verification"):
        await pipeline.run(scanner_only=True)

    assert not (output / "runs").exists()


@pytest.mark.asyncio
async def test_pipeline_persists_current_benchmark_verification(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = config_factory(
        maximum_assurance={"benchmark_gate": True},
    )
    verification = _current_benchmark_verification()
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path / "benchmark-current-output",
        scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
    )

    result = await pipeline.run(
        scanner_only=True,
        benchmark_verification=verification,
        benchmark_repository_git_commit=verification.observed_repository_git_commit,
    )

    persisted = BenchmarkCertificateVerification.model_validate_json(
        (result.run_dir / "benchmark-certificate-verification.json").read_text(encoding="utf-8")
    )
    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    assert persisted == verification
    assert "benchmark-certificate-verification.json" in {
        artifact.path for artifact in manifest.artifacts
    }


@pytest.mark.asyncio
async def test_maximum_pipeline_rejects_standard_profile_benchmark_before_run(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    pipeline = AuditPipeline(
        config_factory(profile=AuditProfile.MAXIMUM_ASSURANCE),
        repo=vulnerable_repo,
        output=tmp_path / "benchmark-wrong-profile-output",
        scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match="requires current certificate verification"):
        await pipeline.run(
            scanner_only=True,
            benchmark_verification=_current_benchmark_verification(),
        )


@pytest.mark.asyncio
async def test_latest_report_refresh_does_not_follow_hardlink(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    output = tmp_path / "output"
    latest = output / "latest"
    latest.mkdir(parents=True)
    outside = tmp_path / "outside-report.md"
    outside.write_text("sentinel\n", encoding="utf-8")
    try:
        (latest / "audit-report.md").hardlink_to(outside)
    except OSError:
        pytest.skip("hardlinks unavailable")
    pipeline = AuditPipeline(
        config_factory(),
        repo=vulnerable_repo,
        output=output,
        scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
    )
    result = await pipeline.run(scanner_only=True)
    assert result.exit_code is ExitCode.INCOMPLETE
    assert not result.report.completed
    assert result.report.run_status is AuditRunStatus.INCOMPLETE
    assert outside.read_text(encoding="utf-8") == "sentinel\n"
    assert (
        (latest / "audit-report.md")
        .read_text(encoding="utf-8")
        .startswith("# Corrovera Security Assurance Report")
    )


@pytest.mark.asyncio
async def test_scanner_only_latest_refresh_removes_stale_provider_privacy_artifacts(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    latest = output / "latest"
    latest.mkdir(parents=True)
    stale_names = (
        "privacy-source-provenance.json",
        "privacy-policy.json",
    )
    for name in stale_names:
        (latest / name).write_text('{"stale":true}\n', encoding="utf-8")

    pipeline = AuditPipeline(
        config_factory(),
        repo=vulnerable_repo,
        output=output,
        scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
    )
    result = await pipeline.run(scanner_only=True)

    assert result.exit_code is ExitCode.INCOMPLETE
    assert not result.report.completed
    assert result.report.run_status is AuditRunStatus.INCOMPLETE
    for name in stale_names:
        assert not (result.run_dir / name).exists()
        assert not (latest / name).exists()


@pytest.mark.asyncio
async def test_reused_pipeline_does_not_leak_provider_privacy_state_into_scanner_run(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    fake = FakeOpenRouter()
    client, http_client = _provider(config, fake)
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path / "reused-output",
        client=client,
        scanner_runner=StaticScannerRunner(),  # type: ignore[arg-type]
    )
    try:
        provider_result = await pipeline.run(allow_code_egress=True)
        scanner_result = await pipeline.run(scanner_only=True)
    finally:
        await http_client.aclose()

    assert provider_result.report.privacy["effective_policy"] is not None
    assert provider_result.report.privacy["source_provenance"] is not None
    assert scanner_result.report.privacy["effective_policy"] is None
    assert scanner_result.report.privacy["source_provenance"] is None
    assert pipeline.effective_privacy_policy is None
    assert pipeline.privacy_source_provenance is None
    assert pipeline.privacy_authorization is None
    assert not (scanner_result.run_dir / "privacy-policy.json").exists()
    assert not (scanner_result.run_dir / "privacy-source-provenance.json").exists()
    scanner_metadata = json.loads(
        (scanner_result.run_dir / "metadata.json").read_text(encoding="utf-8")
    )
    assert scanner_metadata["privacy"]["effective_policy"] is None
    assert scanner_metadata["privacy"]["source_provenance"] is None


@pytest.mark.asyncio
async def test_ci_pipeline_emits_manifest_bound_state_that_round_trips(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    commit = _commit_synthetic_repository(vulnerable_repo)
    output = tmp_path / "ci-output"
    pipeline = AuditPipeline(
        config_factory(scanners={"semgrep": {"enabled": True, "required": True}}),
        repo=vulnerable_repo,
        output=output,
        scanner_runner=SyntheticValidatedScannerRunner(),  # type: ignore[arg-type]
    )

    result = await pipeline.run(
        scanner_only=True,
        changed_since=commit,
        ci_mode=True,
    )

    assert result.ci_state is not None
    assert result.ci_state.job_status is CIJobStatus.NEW_FINDINGS
    persisted = CIRunState.model_validate_json(
        (result.run_dir / "ci-state.json").read_text(encoding="utf-8")
    )
    assert persisted == result.ci_state
    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    validate_manifest_artifacts(manifest, result.run_dir)
    state_binding = next(
        artifact for artifact in manifest.artifacts if artifact.path == "ci-state.json"
    )
    state_bytes = (result.run_dir / "ci-state.json").read_bytes()
    assert state_binding.sha256 == hashlib.sha256(state_bytes).hexdigest()
    assert state_binding.size == len(state_bytes)

    loaded = load_ci_baseline(
        result.run_dir.resolve(strict=True),
        expected_repository_git_commit=commit,
    )
    assert loaded.state == persisted
    assert loaded.manifest == manifest
    assert loaded.report == result.report


@pytest.mark.asyncio
async def test_ci_public_baseline_bundle_is_exact_and_excludes_private_artifacts(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    commit = _commit_synthetic_repository(vulnerable_repo)
    result = await AuditPipeline(
        config_factory(scanners={"semgrep": {"enabled": True, "required": True}}),
        repo=vulnerable_repo,
        output=tmp_path / "ci-public-bundle-output",
        scanner_runner=SyntheticValidatedScannerRunner(),  # type: ignore[arg-type]
    ).run(
        scanner_only=True,
        changed_since=commit,
        ci_mode=True,
    )
    bundle = tmp_path / "ci-public-bundle"
    bundle.mkdir()
    names = (
        "ci-state.json",
        "final-findings.json",
        "run-evidence-manifest.json",
    )
    for name in names:
        shutil.copyfile(result.run_dir / name, bundle / name)

    loaded = load_ci_baseline_bundle(
        bundle.resolve(strict=True),
        expected_repository_git_commit=commit,
    )

    assert loaded.state == result.ci_state
    assert tuple(sorted(path.name for path in bundle.iterdir())) == names
    assert not (bundle / "private").exists()

    (bundle / "unexpected.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected or unsafe member"):
        load_ci_baseline_bundle(
            bundle.resolve(strict=True),
            expected_repository_git_commit=commit,
        )


@pytest.mark.parametrize(
    ("variant", "error"),
    [
        ("effective_configuration", "effective configuration differs"),
        ("repository_root", "repository root identity differs"),
        ("configuration_binding", "configuration bindings differ"),
        ("tool_binding", "tool bindings differ"),
    ],
)
@pytest.mark.asyncio
async def test_ci_public_bundle_rejects_resealed_manifest_projection_mismatch(
    variant: str,
    error: str,
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    commit = _commit_synthetic_repository(vulnerable_repo)
    result = await AuditPipeline(
        config_factory(scanners={"semgrep": {"enabled": True, "required": True}}),
        repo=vulnerable_repo,
        output=tmp_path / f"ci-manifest-{variant}-output",
        scanner_runner=SyntheticValidatedScannerRunner(),  # type: ignore[arg-type]
    ).run(
        scanner_only=True,
        changed_since=commit,
        ci_mode=True,
    )
    bundle = _copy_ci_public_bundle(
        result.run_dir,
        tmp_path / f"ci-manifest-{variant}-bundle",
    )
    manifest_path = bundle / "run-evidence-manifest.json"
    manifest = RunEvidenceManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    payload = manifest.model_dump(mode="json")

    if variant == "effective_configuration":
        run_configuration = payload["run_configuration"]
        assert isinstance(run_configuration, dict)
        file_payload = json.loads(run_configuration["file_configuration_json"])
        file_payload["reporting"]["markdown"] = not file_payload["reporting"]["markdown"]
        file_config = AuditConfig.model_validate(file_payload)
        environment_overrides = AuditConfigOverrides.model_validate(
            run_configuration["environment_overrides"]
        )
        cli_overrides = AuditConfigOverrides.model_validate(run_configuration["cli_overrides"])
        effective = cli_overrides.apply(environment_overrides.apply(file_config))
        run_configuration["file_configuration_json"] = canonical_audit_config_json(file_config)
        run_configuration["file_config_sha256"] = file_config.stable_hash()
        run_configuration["effective_configuration_json"] = canonical_audit_config_json(effective)
        run_configuration["effective_config_sha256"] = effective.stable_hash()
        run_configuration["model_config_sha256"] = effective.model_hash()
        run_configuration["invocation_sha256"] = canonical_sha256(
            {
                "environment_overrides_sha256": run_configuration["environment_overrides_sha256"],
                "cli_overrides_sha256": run_configuration["cli_overrides_sha256"],
                "run_options_sha256": run_configuration["run_options_sha256"],
                "effective_config_sha256": run_configuration["effective_config_sha256"],
                "requested_profile": run_configuration["requested_profile"],
                "achieved_profile": run_configuration["achieved_profile"],
            }
        )
    elif variant == "repository_root":
        payload["repository_root_name"] = "forged-root-name"
    elif variant == "configuration_binding":
        payload["bindings"]["configuration"][0]["sha256"] = "f" * 64
    else:
        scanner_binding = next(
            binding
            for binding in payload["bindings"]["tools"]
            if binding["identifier"].startswith("scanner/")
        )
        scanner_binding["sha256"] = "f" * 64

    _write_resealed_ci_manifest(manifest_path, payload)

    with pytest.raises(ValueError, match=error):
        load_ci_baseline_bundle(
            bundle,
            expected_repository_git_commit=commit,
        )


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("changed_since", "forged-base", "changed-since metadata differs"),
        ("model_configuration_hash", "f" * 64, "model configuration differs"),
    ],
)
@pytest.mark.asyncio
async def test_ci_public_bundle_rejects_resealed_report_manifest_projection_mismatch(
    field: str,
    value: str,
    error: str,
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    commit = _commit_synthetic_repository(vulnerable_repo)
    result = await AuditPipeline(
        config_factory(scanners={"semgrep": {"enabled": True, "required": True}}),
        repo=vulnerable_repo,
        output=tmp_path / f"ci-report-{field}-output",
        scanner_runner=SyntheticValidatedScannerRunner(),  # type: ignore[arg-type]
    ).run(
        scanner_only=True,
        changed_since=commit,
        ci_mode=True,
    )
    bundle = _copy_ci_public_bundle(
        result.run_dir,
        tmp_path / f"ci-report-{field}-bundle",
    )
    report_payload = result.report.model_dump(mode="python")
    if field == "changed_since":
        report_payload["repository"] = result.report.repository.model_copy(
            update={"changed_since": value}
        )
    else:
        report_payload[field] = value
    tampered_report = AuditReport.model_validate(report_payload)
    _replace_manifest_bound_report(bundle, tampered_report)

    with pytest.raises(ValueError, match=error):
        load_ci_baseline_bundle(
            bundle,
            expected_repository_git_commit=commit,
        )


@pytest.mark.asyncio
async def test_ci_public_bundle_rejects_root_replacement_during_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    commit = _commit_synthetic_repository(vulnerable_repo)
    result = await AuditPipeline(
        config_factory(scanners={"semgrep": {"enabled": True, "required": True}}),
        repo=vulnerable_repo,
        output=tmp_path / "ci-root-swap-output",
        scanner_runner=SyntheticValidatedScannerRunner(),  # type: ignore[arg-type]
    ).run(
        scanner_only=True,
        changed_since=commit,
        ci_mode=True,
    )
    bundle = _copy_ci_public_bundle(result.run_dir, tmp_path / "ci-root-swap-bundle")
    retired = tmp_path / "ci-root-swap-retired"
    original_read = ci_module._read_ci_bundle_member_at
    replaced = False

    def read_and_replace(
        root_descriptor: int,
        name: str,
        *,
        max_bytes: int,
    ) -> ci_module._CIBundleMemberObservation:
        nonlocal replaced
        observation = original_read(
            root_descriptor,
            name,
            max_bytes=max_bytes,
        )
        if not replaced:
            replaced = True
            bundle.rename(retired)
            shutil.copytree(retired, bundle)
        return observation

    monkeypatch.setattr(ci_module, "_read_ci_bundle_member_at", read_and_replace)

    with pytest.raises(ValueError, match="bundle root changed"):
        load_ci_baseline_bundle(
            bundle,
            expected_repository_git_commit=commit,
        )


@pytest.mark.asyncio
async def test_ci_public_bundle_rejects_member_replacement_during_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    commit = _commit_synthetic_repository(vulnerable_repo)
    result = await AuditPipeline(
        config_factory(scanners={"semgrep": {"enabled": True, "required": True}}),
        repo=vulnerable_repo,
        output=tmp_path / "ci-member-swap-output",
        scanner_runner=SyntheticValidatedScannerRunner(),  # type: ignore[arg-type]
    ).run(
        scanner_only=True,
        changed_since=commit,
        ci_mode=True,
    )
    bundle = _copy_ci_public_bundle(result.run_dir, tmp_path / "ci-member-swap-bundle")
    replacement = tmp_path / "replacement-ci-state.json"
    original_read = ci_module._read_ci_bundle_member_at
    replaced = False

    def read_and_replace(
        root_descriptor: int,
        name: str,
        *,
        max_bytes: int,
    ) -> ci_module._CIBundleMemberObservation:
        nonlocal replaced
        observation = original_read(
            root_descriptor,
            name,
            max_bytes=max_bytes,
        )
        if name == "ci-state.json" and not replaced:
            replaced = True
            replacement.write_bytes(observation.data)
            replacement.replace(bundle / name)
        return observation

    monkeypatch.setattr(ci_module, "_read_ci_bundle_member_at", read_and_replace)

    with pytest.raises(ValueError, match=r"bundle (?:root|member) changed"):
        load_ci_baseline_bundle(
            bundle,
            expected_repository_git_commit=commit,
        )


@pytest.mark.parametrize(
    ("field", "forged_value"),
    [
        ("schema_version", "9.9"),
        ("enabled", False),
        ("scanner_workspace_sha256", "c" * 64),
        ("producer_sha256", "d" * 64),
        ("deterministic_policy_sha256", "e" * 64),
        ("job_status", "CLEAN"),
        ("analysis_failures", ["forged analysis success projection"]),
        ("new_findings", 999),
        ("unchanged_findings", 999),
        ("resolved_findings", 999),
        ("coverage_regressions", 999),
        ("whole_run_reuse_eligible", True),
        ("baseline_state_sha256", "a" * 64),
        ("baseline_manifest_sha256", "b" * 64),
        ("historical_evidence_use", "forged_current_execution_credit"),
        ("forged_extra_projection", "not_emitted_by_the_ci_pipeline"),
    ],
)
@pytest.mark.asyncio
async def test_ci_report_or_baseline_rejects_resealed_state_projection_mismatch(
    field: str,
    forged_value: object,
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    commit = _commit_synthetic_repository(vulnerable_repo)
    pipeline = AuditPipeline(
        config_factory(scanners={"semgrep": {"enabled": True, "required": True}}),
        repo=vulnerable_repo,
        output=tmp_path / "ci-projection-output",
        scanner_runner=SyntheticValidatedScannerRunner(),  # type: ignore[arg-type]
    )
    result = await pipeline.run(
        scanner_only=True,
        changed_since=commit,
        ci_mode=True,
    )
    metadata = dict(result.report.metadata)
    ci_metadata = dict(metadata["ci"])
    ci_metadata[field] = forged_value
    metadata["ci"] = ci_metadata
    report_payload = {
        **result.report.model_dump(mode="python"),
        "metadata": metadata,
    }
    if field == "enabled":
        with pytest.raises(
            ValidationError,
            match="minimum-floor coverage claims conflict",
        ):
            AuditReport.model_validate(report_payload)
        return
    tampered_report = AuditReport.model_validate(report_payload)
    _replace_manifest_bound_report(result.run_dir, tampered_report)
    resealed_manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    validate_manifest_artifacts(resealed_manifest, result.run_dir)

    with pytest.raises(
        ValueError,
        match="CI baseline scanner workspace identity is absent from the report",
    ):
        load_ci_baseline(
            result.run_dir.resolve(strict=True),
            expected_repository_git_commit=commit,
        )


@pytest.mark.asyncio
async def test_ci_baseline_rejects_resealed_report_source_inventory_mismatch(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    commit = _commit_synthetic_repository(vulnerable_repo)
    result = await AuditPipeline(
        config_factory(scanners={"semgrep": {"enabled": True, "required": True}}),
        repo=vulnerable_repo,
        output=tmp_path / "ci-source-inventory-output",
        scanner_runner=SyntheticValidatedScannerRunner(),  # type: ignore[arg-type]
    ).run(
        scanner_only=True,
        changed_since=commit,
        ci_mode=True,
    )
    repository_files = list(result.report.repository.files)
    repository_files[0] = repository_files[0].model_copy(
        update={"size": repository_files[0].size + 1}
    )
    tampered_report = AuditReport.model_validate(
        {
            **result.report.model_dump(mode="python"),
            "repository": result.report.repository.model_copy(update={"files": repository_files}),
        }
    )
    _replace_manifest_bound_report(result.run_dir, tampered_report)

    with pytest.raises(ValueError, match="sources differ from the final report"):
        load_ci_baseline(
            result.run_dir.resolve(strict=True),
            expected_repository_git_commit=commit,
        )


@pytest.mark.asyncio
async def test_ci_baseline_rejects_shared_manifest_inode(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    commit = _commit_synthetic_repository(vulnerable_repo)
    result = await AuditPipeline(
        config_factory(scanners={"semgrep": {"enabled": True, "required": True}}),
        repo=vulnerable_repo,
        output=tmp_path / "ci-shared-manifest-output",
        scanner_runner=SyntheticValidatedScannerRunner(),  # type: ignore[arg-type]
    ).run(
        scanner_only=True,
        changed_since=commit,
        ci_mode=True,
    )
    os.link(
        result.run_dir / "run-evidence-manifest.json",
        result.run_dir / "shared-manifest-copy.json",
    )

    with pytest.raises(ValueError, match="bounded unshared regular file"):
        load_ci_baseline(
            result.run_dir.resolve(strict=True),
            expected_repository_git_commit=commit,
        )


@pytest.mark.asyncio
async def test_ci_baseline_rejects_exact_commit_mismatch(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    commit = _commit_synthetic_repository(vulnerable_repo)
    pipeline = AuditPipeline(
        config_factory(scanners={"semgrep": {"enabled": True, "required": True}}),
        repo=vulnerable_repo,
        output=tmp_path / "ci-commit-output",
        scanner_runner=SyntheticValidatedScannerRunner(),  # type: ignore[arg-type]
    )
    result = await pipeline.run(
        scanner_only=True,
        changed_since=commit,
        ci_mode=True,
    )

    with pytest.raises(
        ValueError,
        match="repository commit differs from changed-since",
    ):
        load_ci_baseline(
            result.run_dir.resolve(strict=True),
            expected_repository_git_commit="0" * 40,
        )


@pytest.mark.asyncio
async def test_ci_coverage_regression_is_not_admissible_as_next_baseline(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    commit = _commit_synthetic_repository(vulnerable_repo)
    config = config_factory(
        scanners={
            "semgrep": {"enabled": True, "required": True},
            "gitleaks": {"enabled": True, "required": False},
        }
    )
    baseline_result = await AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path / "ci-coverage-baseline",
        scanner_runner=SyntheticTwoValidatedScannerRunner(),  # type: ignore[arg-type]
    ).run(
        scanner_only=True,
        changed_since=commit,
        ci_mode=True,
    )
    baseline = load_ci_baseline(
        baseline_result.run_dir.resolve(strict=True),
        expected_repository_git_commit=commit,
    )
    current = await AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path / "ci-coverage-current",
        scanner_runner=SyntheticValidatedScannerRunner(),  # type: ignore[arg-type]
    ).run(
        scanner_only=True,
        changed_since=commit,
        ci_mode=True,
        ci_baseline=baseline,
    )

    assert current.ci_state is not None
    assert current.ci_state.job_status is CIJobStatus.COVERAGE_REGRESSION
    assert current.exit_for_ci(None) is ExitCode.INCOMPLETE
    with pytest.raises(ValueError, match="unresolved coverage regression"):
        load_ci_baseline(
            current.run_dir.resolve(strict=True),
            expected_repository_git_commit=commit,
        )


@pytest.mark.asyncio
async def test_ci_pipeline_fails_closed_when_applicable_repository_suite_is_unavailable(
    config_factory,
    tmp_path: Path,
) -> None:
    repository = _foundry_repo(tmp_path, patched=True)
    commit = _commit_synthetic_repository(repository)
    runner = SyntheticValidatedScannerRunner(
        finding_path="src/Vault.sol",
        finding_line=20,
    )
    pipeline = AuditPipeline(
        config_factory(
            scanners={
                "semgrep": {"enabled": True, "required": True},
                "foundry_fork": {"enabled": True, "required": False},
            },
        ),
        repo=repository,
        output=tmp_path / "ci-suite-output",
        scanner_runner=runner,  # type: ignore[arg-type]
    )

    result = await pipeline.run(
        scanner_only=True,
        changed_since=commit,
        allow_fork_probing=True,
        ci_mode=True,
    )

    assert result.ci_state is not None
    assert result.ci_state.job_status is CIJobStatus.ANALYSIS_FAILED
    assert any(
        failure.startswith("foundry_fork:missing:") for failure in result.ci_state.analysis_failures
    )
    assert result.exit_for_ci(None) is not ExitCode.SUCCESS
    assert result.report.run_status in {
        AuditRunStatus.INCOMPLETE,
        AuditRunStatus.FAILED,
    }
    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    validate_manifest_artifacts(manifest, result.run_dir)


@pytest.mark.asyncio
async def test_non_ci_pipeline_emits_no_ci_state(
    config_factory,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    output = tmp_path / "ordinary-output"
    pipeline = AuditPipeline(
        config_factory(scanners={"semgrep": {"enabled": True, "required": True}}),
        repo=vulnerable_repo,
        output=output,
        scanner_runner=SyntheticValidatedScannerRunner(),  # type: ignore[arg-type]
    )

    result = await pipeline.run(scanner_only=True)

    assert result.ci_state is None
    assert not (result.run_dir / "ci-state.json").exists()
    assert not (output / "latest" / "ci-state.json").exists()
    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    assert "ci-state.json" not in {artifact.path for artifact in manifest.artifacts}
