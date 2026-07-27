from __future__ import annotations

import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from mmaudit.benchmark.certificate import (
    BenchmarkCertificateVerification,
    CertificateVerificationStatus,
)
from mmaudit.constants import ALL_SPECIALIST_ROLES, ExitCode
from mmaudit.isolation.dependencies import dependency_tree_sha256
from mmaudit.models.openrouter import OpenRouterClient
from mmaudit.models.schemas import (
    AuditProfile,
    AuditReport,
    AuditScope,
    AuditScopeAssessment,
    CandidateFinding,
    CompilationStatus,
    DependencyPreparationResult,
    DependencyPreparationStatus,
    DependencySbom,
    EconomicSimulationKind,
    FindingStatus,
    FormalToolRun,
    FormalToolStatus,
    GeneratedFoundryTestSpec,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    LocalInvariantDeployment,
    LocalInvariantDeploymentArgument,
    Location,
    ModelReviewCoverage,
    ModelReviewSurfaceKind,
    PriorAuditComparison,
    PriorAuditDiscoveryStatus,
    PriorAuditRemediationStatus,
    PropertyCorpus,
    ReproductionAttemptEvidence,
    ReproductionMinimizationEvidence,
    ReproductionResult,
    ReproductionState,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
    Severity,
    SolidityCompilationResult,
    SolidityProjectMetadata,
    TransactionOrderingCapability,
)
from mmaudit.models.usage import UsageLedger
from mmaudit.operator_secrets import load_operator_secrets
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.manifest import (
    RunEvidenceManifest,
    canonical_sha256,
    validate_manifest_artifacts,
)
from mmaudit.orchestration.pipeline import AuditPipeline
from mmaudit.orchestration.prior_audit import build_prior_audit_comparison
from mmaudit.scanners.base import scanner_fingerprint
from mmaudit.solidity.compile import CompilationRun
from mmaudit.solidity.invariant_execution import FoundryInvariantRunner
from mmaudit.solidity.reproduction import translate_foundry_test
from mmaudit.solidity.reproduction_integrity import reproduction_repository_sha256
from mmaudit.traceability import (
    MaximumAssuranceTraceability,
    validate_traceability_evidence,
)
from tests.conftest import FIXTURES, model_registry_entry
from tests.fake_openrouter import FakeOpenRouter


class StaticScannerRunner:
    def __init__(
        self,
        *,
        status: ScannerStatus = ScannerStatus.SUCCESS,
        required: bool = False,
        finding_path: str = "app.py",
        finding_line: int = 13,
        scanner_name: str = "semgrep",
    ) -> None:
        self.status = status
        self.required = required
        self.finding_path = finding_path
        self.finding_line = finding_line
        self.scanner_name = scanner_name

    async def run_all(
        self,
        root: Path,
        private_dir: Path,
        *,
        skip_codeql: bool = False,
        allow_fork_probing: bool = False,
    ) -> list[ScannerRun]:
        del root, private_dir, skip_codeql, allow_fork_probing
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


def _current_benchmark_verification() -> BenchmarkCertificateVerification:
    payload = {
        "schema_version": "1.0",
        "certificate_sha256": "a" * 64,
        "status": CertificateVerificationStatus.CURRENT,
        "observed_repository_git_commit": "b" * 40,
        "observed_bindings_sha256": "c" * 64,
        "mismatches": [],
    }
    payload["verification_sha256"] = canonical_sha256(payload)
    return BenchmarkCertificateVerification.model_validate(payload)


def _provider(
    config,
    fake: FakeOpenRouter,
    *,
    api_key: str = "synthetic-test-key",
) -> tuple[OpenRouterClient, httpx.AsyncClient]:
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(fake.handler),
        base_url="https://fake.openrouter.test",
    )
    usage = UsageLedger()
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
    )
    return (
        OpenRouterClient(
            api_key=api_key,
            execution=config.execution,
            privacy=config.privacy,
            budget=budget,
            usage=usage,
            http_client=http_client,
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
    )
    try:
        result = await pipeline.run(
            allow_code_egress=True,
            allow_fork_probing=allow_fork_probing,
        )
    finally:
        await http_client.aclose()
    return result


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
async def test_successful_multi_agent_audit(
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
    assert result.exit_code is ExitCode.SUCCESS
    assert result.report.completed
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
    assert manifest.run_id == result.report.run_id
    assert manifest.source_tree_sha256
    assert all(
        getattr(manifest.bindings, category)
        for category in manifest.bindings.__class__.model_fields
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

    assert result.exit_code is ExitCode.SUCCESS
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
    assert result.report.completed
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
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.pipeline.compile_solidity_projects",
        _synthetic_compiler,
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
    )

    after = {
        path.relative_to(repo): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in repo.rglob("*")
        if path.is_file()
    }
    assert before == after
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
    assert 0 < model_coverage.overall.numerator < model_coverage.overall.denominator
    assert not model_coverage.critical_gate_passed
    assert all(
        surface.reviewed == bool(surface.reviewer_roles and surface.root_lineages)
        for surface in model_coverage.surfaces
    )
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
    cross_examination_requests = [
        request
        for request in fake.requests
        if request["response_format"]["json_schema"]["name"].startswith(
            "mmaudit_candidate_cross_examination_"
        )
    ]
    assert len(cross_examination_requests) == 2
    for request in cross_examination_requests:
        user_prompt = request["messages"][1]["content"]
        anonymized = json.loads(
            user_prompt.split("<ANONYMIZED_CANDIDATES_JSON>\n", 1)[1].split(
                "\n</ANONYMIZED_CANDIDATES_JSON>",
                1,
            )[0]
        )
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
async def test_invalid_model_json_gets_one_repair(
    config_factory, vulnerable_repo: Path, tmp_path: Path
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    fake = FakeOpenRouter(mode="invalid_json", role="source_audit")
    result = await _run(config, vulnerable_repo, tmp_path, fake)
    assert result.exit_code is ExitCode.SUCCESS
    assert fake.repaired_roles == ["source_audit"]
    assert any(record.role == "source_audit:json_repair" for record in result.report.usage)


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
async def test_optional_unavailable_scanner_only_completes(
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
    assert result.exit_code is ExitCode.SUCCESS
    assert result.report.completed
    assert fake.chat_calls == 0


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

    assert result.exit_code is ExitCode.SUCCESS
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
    assert result.exit_for_findings(Severity.HIGH) is ExitCode.FINDINGS
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

    assert result.exit_code is ExitCode.SUCCESS
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

    assert result.exit_code is ExitCode.SUCCESS
    first_pass_schemas = {
        "mmaudit_source_audit_findings",
        "mmaudit_business_logic_findings",
        "mmaudit_configuration_findings",
        "mmaudit_specialist_access_control",
        "mmaudit_specialist_reentrancy_control_flow",
    }
    first_pass_requests = [
        request
        for request in fake.requests
        if request["response_format"]["json_schema"]["name"] in first_pass_schemas
    ]
    assert {
        request["response_format"]["json_schema"]["name"] for request in first_pass_requests
    } == first_pass_schemas
    assert all(canary not in request["messages"][1]["content"] for request in first_pass_requests)
    verifier_request = next(
        request
        for request in fake.requests
        if request["response_format"]["json_schema"]["name"] == "mmaudit_verification"
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
    assert result.exit_code is ExitCode.SUCCESS
    assert outside.read_text(encoding="utf-8") == "sentinel\n"
    assert (
        (latest / "audit-report.md")
        .read_text(encoding="utf-8")
        .startswith("# Corrovera Security Assurance Report")
    )
