from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import struct
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.config import ReproductionConfig, SmartContractsConfig
from mmaudit.models.openrouter import safe_headers
from mmaudit.models.schemas import (
    AnalysisState,
    AttackerCapability,
    AttackerCapabilityPolicy,
    AuditedSuiteAssertionStatus,
    AuditedSuiteCoverage,
    AuditedSuiteCoverageGap,
    AuditedSuiteCoverageGapKind,
    AuditedSuiteStatementCoverageEvidence,
    AuditedSuiteStatementStatus,
    AuditedSuiteSurfaceCoverage,
    AuditQualityStatus,
    AuditReport,
    AuditRunStatus,
    CoverageMetric,
    CoverageProvenance,
    CrossChainMessageCapability,
    EconomicMetrics,
    EconomicSimulationKind,
    EconomicSimulationPlan,
    EvidenceStrength,
    ExecutionEvidenceKind,
    FinancialAssetKind,
    FinancialSettlementEvidence,
    Finding,
    FindingStatus,
    FormalDependencyProvenance,
    FormalToolRun,
    HardhatReporterExecution,
    HardhatReporterInventory,
    InvariantExecutionCandidateProvenance,
    InvariantExecutionMinimizationEvidence,
    InvariantExecutionRemovalTrial,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    LendingBoundaryEvidence,
    Location,
    LocationValidation,
    MinimumAnalysisFloor,
    ModelReviewCoverage,
    ModelReviewSurfaceKind,
    RepositoryCleanStateAttestationEvidence,
    RepositoryCodeExecutionState,
    RepositoryFile,
    RepositoryMap,
    RepositorySuiteExecutionPolicy,
    RepositorySuiteFramework,
    RepositorySuiteInventoryEvidence,
    RepositorySuiteTestDescriptor,
    RepositoryTestExecution,
    RepositoryTestExecutionStatus,
    ReproductionResult,
    ReproductionState,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
    Severity,
    SharePriceBoundaryEvidence,
    SolidityCompilationResult,
    SolidityCoverage,
    SolidityEntityKind,
    TransactionOrderingCapability,
    VerificationTest,
)
from mmaudit.orchestration.pipeline import (
    _annotate_scanner_locations,
    _scanner_findings_for_report,
)
from mmaudit.orchestration.run_status import minimum_analysis_floor_quality_gate
from mmaudit.privacy import (
    EffectivePrivacyPolicyEvidence,
    EndpointPolicyClass,
    PrivacyProfile,
    PrivacySourceClassification,
)
from mmaudit.reporting.json_report import stable_json, write_json
from mmaudit.reporting.markdown import render_markdown
from mmaudit.reporting.sarif import generate_sarif
from mmaudit.scanners.base import (
    ScannerAdapter,
    _darwin_current_uid_process_count,
    _darwin_nproc_ceiling_from_uid_listing,
    _darwin_process_group_rss_bytes,
    isolated_executable_version,
    isolated_executable_version_probe,
    preflight_scanner_executable,
    sanitized_scanner_environment,
    scanner_trust_pin_error,
    scanner_workspace_sha256,
)
from mmaudit.scanners.codeql import CodeQLScanner
from mmaudit.scanners.diagnostics import (
    ExecutableVersionProbeStatus,
    ScannerExecutableState,
)
from mmaudit.scanners.fork_rpc import PinnedForkObservation
from mmaudit.scanners.foundry import (
    FoundryForkScanner,
    _foundry_execution_summary,
    _foundry_machine_result_precondition,
    _parse_exact_foundry_test,
    _reject_unsafe_foundry_configuration,
)
from mmaudit.scanners.gitleaks import GitleaksScanner
from mmaudit.scanners.osv import OsvScanner
from mmaudit.scanners.semgrep import SemgrepScanner
from mmaudit.scanners.slither import SlitherScanner
from mmaudit.scanners.trivy import TrivyScanner
from mmaudit.solidity.reproduction import MacOSToolchainResolutionError

FIXTURES = Path(__file__).parents[1] / "fixtures"


class _SyntheticProcessScanner(ScannerAdapter):
    name = "synthetic"
    executable = sys.executable

    def __init__(self, code: str, *, output_limit: int = 50_000_000) -> None:
        self.code = code
        self.max_stdout_bytes = output_limit

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        del root, private_dir
        return [self.executable, "-c", self.code]

    def parse(self, root: Path, stdout: str, private_dir: Path):
        del root, stdout, private_dir
        return []


class _PassthroughIsolation:
    name = "test-isolation"
    supports_local_fork_rpc = True

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del workspace, private_dir, rpc_port
        return command


class _NoLocalForkIsolation(_PassthroughIsolation):
    supports_local_fork_rpc = False


class _NoNetworkOnlyIsolation(_PassthroughIsolation):
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del command, workspace, private_dir, rpc_port
        pytest.fail("static scanners must not request a network-capable wrapper")

    def wrap_without_network(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del workspace, private_dir
        assert rpc_port == 0
        self.commands.append(command.copy())
        return command


class _DeletingScannerOutputIsolation(_PassthroughIsolation):
    def __init__(self, pid_path: Path) -> None:
        self.pid_path = pid_path

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del workspace, rpc_port
        if command[-1] == "--version":
            return command
        raw_path = private_dir / "synthetic.json"
        code = (
            "import os, pathlib, time; "
            f"pathlib.Path({str(self.pid_path)!r}).write_text(str(os.getpid())); "
            f"pathlib.Path({str(raw_path)!r}).unlink(); "
            "time.sleep(10)"
        )
        return [sys.executable, "-c", code]


class _ToolchainResolutionFailureIsolation(_PassthroughIsolation):
    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del command, workspace, private_dir, rpc_port
        raise MacOSToolchainResolutionError(
            "synthetic private path /Users/SYNTHETIC-OPERATOR/toolchain"
        )


class _UndeclaredForkIsolation:
    name = "undeclared-fork-isolation"

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del workspace, private_dir, rpc_port
        return command


class _SelfAssertedRealIsolation(_PassthroughIsolation):
    """Adversarial injected backend that must not mint real provenance."""

    name = "sandbox-exec"
    execution_evidence = ExecutionEvidenceKind.REAL


class _MockRepositoryJavaScriptIsolation(_PassthroughIsolation):
    """Mock an off-host scanner boundary without importing repository configuration."""

    name = "mocked-off-host-container"

    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.cleanup_calls = 0

    def wrap_repository_javascript(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del rpc_port
        workspace.resolve(strict=True).relative_to(private_dir.resolve(strict=True))
        self.commands.append(command.copy())
        output = (
            "print('synthetic slither 1.0')"
            if command[-1] == "--version"
            else 'print(\'{"success":true,"results":{"detectors":[]}}\')'
        )
        return [sys.executable, "-c", output]

    def cleanup(self, private_dir: Path) -> None:
        private_dir.resolve(strict=True)
        self.cleanup_calls += 1


def test_semgrep_normalization(vulnerable_repo: Path, tmp_path: Path) -> None:
    raw = (FIXTURES / "scanner_outputs/semgrep.json").read_text(encoding="utf-8")
    findings = SemgrepScanner().parse(vulnerable_repo, raw, tmp_path)
    assert len(findings) == 1
    assert findings[0].locations[0].path == "app.py"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].cwe == ["CWE-89"]


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"results": {}},
        {"results": [None]},
        {"results": [{}]},
        {
            "results": [
                {
                    "check_id": "synthetic.rule",
                    "path": "../outside.py",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {"message": "synthetic", "severity": "WARNING"},
                }
            ]
        },
        {
            "results": [
                {
                    "check_id": "synthetic.rule",
                    "path": "Synthetic.sol",
                    "start": {"line": 2},
                    "end": {"line": 1},
                    "extra": {"message": "synthetic", "severity": "WARNING"},
                }
            ]
        },
    ],
)
def test_semgrep_rejects_malformed_machine_envelopes(tmp_path: Path, payload: object) -> None:
    with pytest.raises(ValueError, match="Semgrep"):
        SemgrepScanner().parse(tmp_path, json.dumps(payload), tmp_path)


def test_gitleaks_normalization_never_preserves_value(
    vulnerable_repo: Path, tmp_path: Path
) -> None:
    raw = (FIXTURES / "scanner_outputs/gitleaks.json").read_text(encoding="utf-8")
    findings = GitleaksScanner().parse(vulnerable_repo, raw, tmp_path)
    serialized = stable_json([finding.model_dump(mode="json") for finding in findings])
    assert "REDACTED" not in serialized
    assert findings[0].metadata["redacted"] is True


@pytest.mark.parametrize(
    "payload",
    [
        {},
        [None],
        [{"RuleID": "generic-api-key", "File": "config.py", "StartLine": 1}],
        [
            {
                "RuleID": "generic-api-key",
                "File": "config.py",
                "StartLine": True,
                "EndLine": 1,
            }
        ],
        [
            {
                "RuleID": "generic-api-key",
                "File": "../outside.py",
                "StartLine": 1,
                "EndLine": 1,
            }
        ],
        [
            {
                "RuleID": "generic-api-key",
                "File": "Synthetic.sol",
                "StartLine": 2,
                "EndLine": 1,
            }
        ],
    ],
)
def test_gitleaks_rejects_malformed_machine_envelopes(tmp_path: Path, payload: object) -> None:
    with pytest.raises(ValueError, match="Gitleaks"):
        GitleaksScanner().parse(tmp_path, json.dumps(payload), tmp_path)


def test_trivy_normalizes_vulnerability_and_misconfiguration(
    vulnerable_repo: Path, tmp_path: Path
) -> None:
    raw = (FIXTURES / "scanner_outputs/trivy.json").read_text(encoding="utf-8")
    findings = TrivyScanner().parse(vulnerable_repo, raw, tmp_path)
    assert {finding.rule_id for finding in findings} == {
        "CVE-SYNTHETIC-0001",
        "CFG-SYNTHETIC-1",
    }
    assert all(
        location.path in {"requirements.txt", "config.py"}
        for finding in findings
        for location in finding.locations
    )


def test_osv_normalization(vulnerable_repo: Path, tmp_path: Path) -> None:
    raw = (FIXTURES / "scanner_outputs/osv.json").read_text(encoding="utf-8")
    findings = OsvScanner().parse(vulnerable_repo, raw, tmp_path)
    assert findings[0].rule_id == "GHSA-SYNTHETIC-0001"
    assert findings[0].metadata["package"] == "Flask"


def test_codeql_sarif_normalization(vulnerable_repo: Path, tmp_path: Path) -> None:
    payload = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "py/sql-injection",
                                "name": "SQL query built from user input",
                                "properties": {"tags": ["external/cwe/cwe-089"]},
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "level": "error",
                        "message": {"text": "Synthetic query"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {"startLine": 13, "endLine": 14},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    (tmp_path / "codeql.sarif").write_text(json.dumps(payload), encoding="utf-8")
    findings = CodeQLScanner("db", "security-extended").parse(vulnerable_repo, "", tmp_path)
    assert findings[0].rule_id == "py/sql-injection"
    assert findings[0].cwe == ["CWE-089"]


def test_codeql_database_cannot_escape_repository(vulnerable_repo: Path, tmp_path: Path) -> None:
    scanner = CodeQLScanner("../outside", "security-extended")
    with pytest.raises(ValueError, match="inside the repository"):
        scanner.build_command(vulnerable_repo, tmp_path)


def test_foundry_execution_summary_records_observed_portfolio_evidence() -> None:
    stdout = json.dumps(
        {
            "test/audit/Portfolio.t.sol:PortfolioTest": {
                "test_results": {
                    "testOwnerCanWithdraw()": {
                        "status": "Success",
                        "kind": {"Unit": {"gas": 12_345}},
                    },
                    "testFuzz_Deposit(uint256)": {
                        "status": "Success",
                        "kind": {"Fuzz": {"runs": 256, "mean_gas": 456}},
                    },
                    "invariant_TotalAssets()": {
                        "status": "Failure",
                        "kind": {
                            "Invariant": {
                                "runs": 128,
                                "calls": 4_096,
                                "reverts": 0,
                            }
                        },
                    },
                    "testProperty_Rounding(uint256)": {
                        "status": "Skipped",
                        "kind": {"Fuzz": {"runs": 32}},
                    },
                }
            }
        }
    )

    summary = _foundry_execution_summary(stdout)

    assert summary is not None
    assert summary.unit_tests == 1
    assert summary.fuzz_tests == 2
    assert summary.invariant_tests == 1
    assert summary.passed_tests == 2
    assert summary.failed_tests == 1
    assert summary.skipped_tests == 1
    assert summary.fuzz_cases == 288
    assert summary.invariant_runs == 128
    assert summary.invariant_calls == 4096

    now = datetime.now(UTC)
    run = ScannerRun(
        scanner="foundry_fork",
        status=ScannerStatus.SUCCESS,
        version="1.3.2",
        command=["forge", "test"],
        started_at=now,
        finished_at=now,
        duration_seconds=0,
        foundry_summary=summary,
    )
    restored = ScannerRun.model_validate_json(run.model_dump_json())
    assert restored.foundry_summary == summary


def test_foundry_execution_summary_requires_structured_test_results() -> None:
    stdout = json.dumps(
        {
            "test/audit/Portfolio.t.sol:PortfolioTest": {
                "test_results": {},
            }
        }
    )

    assert _foundry_execution_summary(stdout) is None
    with pytest.raises(ValueError, match="one JSON document"):
        _foundry_execution_summary(
            "[PASS] testFuzz_Spoofed(uint256) (runs: 100000)\n"
            "[PASS] invariant_Spoofed() (runs: 100000, calls: 100000)"
        )


def test_foundry_execution_summary_ignores_spoofed_repository_log_text() -> None:
    stdout = json.dumps(
        {
            "test/audit/Portfolio.t.sol:PortfolioTest": {
                "test_results": {
                    "testUnit()": {
                        "status": "Success",
                        "kind": {"Unit": {"gas": 123}},
                        "logs": [
                            "[PASS] testFuzz_Spoofed(uint256) (runs: 100000)",
                            "[PASS] invariant_Spoofed() (runs: 100000, calls: 100000)",
                        ],
                    }
                }
            }
        }
    )

    summary = _foundry_execution_summary(stdout)

    assert summary is not None
    assert summary.unit_tests == 1
    assert summary.fuzz_tests == 0
    assert summary.invariant_tests == 0
    assert summary.fuzz_cases == 0
    assert summary.invariant_runs == 0
    assert summary.invariant_calls == 0


def test_foundry_execution_summary_rejects_ambiguous_or_unknown_metadata() -> None:
    duplicate_status = (
        '{"test/audit/Portfolio.t.sol:PortfolioTest":{"test_results":'
        '{"testUnit()":{"status":"Success","status":"Failure",'
        '"kind":{"Unit":{"gas":1}}}}}}'
    )
    unsupported_kind = json.dumps(
        {
            "test/audit/Portfolio.t.sol:PortfolioTest": {
                "test_results": {
                    "testUnit()": {
                        "status": "Success",
                        "kind": {"Unknown": {}},
                    }
                }
            }
        }
    )

    with pytest.raises(ValueError, match="duplicate object key"):
        _foundry_execution_summary(duplicate_status)
    with pytest.raises(ValueError, match="unsupported test kind"):
        _foundry_execution_summary(unsupported_kind)


def test_foundry_repository_suite_rejects_nonempty_fs_permissions(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "foundry.toml").write_text(
        "\n".join(
            (
                "[profile.default]",
                'fs_permissions = [{ access = "read-write", path = "./" }]',
                "",
            )
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="fs_permissions"):
        _reject_unsafe_foundry_configuration(root)


def test_foundry_repository_suite_rejects_repository_selected_compiler_path(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "foundry.toml").write_text(
        '[profile.default]\nsolc = "./toolchain/solc"\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="executable compiler path"):
        _reject_unsafe_foundry_configuration(root)


def test_foundry_repository_suite_rejects_backend_without_local_rpc_before_tool_lookup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repository"
    test_dir = root / "test" / "audit"
    test_dir.mkdir(parents=True)
    (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (test_dir / "Portfolio.t.sol").write_text(
        "contract PortfolioTest { function testUnit() public {} }\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "mmaudit.scanners.foundry.shutil.which",
        lambda _executable: pytest.fail("tool lookup must follow isolation capability preflight"),
    )

    result = FoundryForkScanner(SmartContractsConfig(allow_fork_probing=True)).run(
        root,
        tmp_path / "private-no-local-rpc",
        5,
        backend=_NoLocalForkIsolation(),
    )

    assert result.status is ScannerStatus.UNAVAILABLE
    assert "loopback" in (result.error or "")


def test_foundry_repository_suite_rejects_undeclared_local_rpc_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repository"
    test_dir = root / "test" / "audit"
    test_dir.mkdir(parents=True)
    (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (test_dir / "Portfolio.t.sol").write_text(
        "contract PortfolioTest { function testUnit() public {} }\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "mmaudit.scanners.foundry.shutil.which",
        lambda _executable: pytest.fail("undeclared capability must stop before tool lookup"),
    )

    result = FoundryForkScanner(SmartContractsConfig(allow_fork_probing=True)).run(
        root,
        tmp_path / "private-undeclared-local-rpc",
        5,
        backend=_UndeclaredForkIsolation(),
    )

    assert result.status is ScannerStatus.UNAVAILABLE
    assert "explicit configured loopback" in (result.error or "")


def test_foundry_repository_suite_missing_rpc_is_unavailable_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repository"
    test_dir = root / "test" / "audit"
    test_dir.mkdir(parents=True)
    (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (test_dir / "Portfolio.t.sol").write_text(
        "contract PortfolioTest { function testUnit() public {} }\n",
        encoding="utf-8",
    )
    fake_forge = tmp_path / "forge"
    fake_forge.write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
    fake_forge.chmod(0o755)
    monkeypatch.setattr(
        "mmaudit.scanners.foundry.shutil.which",
        lambda executable: str(fake_forge) if executable == "forge" else None,
    )
    monkeypatch.delenv("MMAUDIT_FORK_RPC_URL", raising=False)
    monkeypatch.setattr(
        "mmaudit.scanners.foundry.isolation_execution_evidence",
        lambda _backend: ExecutionEvidenceKind.REAL,
    )
    monkeypatch.setattr(
        "mmaudit.scanners.foundry.isolation_attestation_sha256",
        lambda _backend: "a" * 64,
    )

    result = FoundryForkScanner(
        SmartContractsConfig(allow_fork_probing=True),
        reproduction=ReproductionConfig(
            expected_chain_id=31_337,
            pinned_block_number=42,
        ),
    ).run(
        root,
        tmp_path / "private-missing-rpc",
        5,
        backend=_PassthroughIsolation(),
    )

    assert result.status is ScannerStatus.UNAVAILABLE
    assert "MMAUDIT_FORK_RPC_URL" in (result.error or "")


def test_foundry_scanner_uses_explicit_in_memory_rpc_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    scanner = FoundryForkScanner(
        SmartContractsConfig(),
        fork_rpc_url_override="http://127.0.0.1:9545",
    )

    command = scanner.build_command(tmp_path, tmp_path / "private")

    assert command[command.index("--fork-url") + 1] == "http://127.0.0.1:9545"
    assert "http://127.0.0.1:8545" not in command
    assert all("9545" not in token for token in scanner.display_command())


def test_foundry_repository_suite_rejects_source_changed_after_pipeline_freeze(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repository"
    test_dir = root / "test" / "audit"
    test_dir.mkdir(parents=True)
    (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (test_dir / "Portfolio.t.sol").write_text(
        "contract PortfolioTest { function testUnit() public {} }\n",
        encoding="utf-8",
    )
    output = root / ".mmaudit"
    frozen_sha256 = scanner_workspace_sha256(root, output)
    (root / "src").mkdir()
    (root / "src" / "Late.sol").write_text("contract Late {}\n", encoding="utf-8")
    monkeypatch.setattr(
        "mmaudit.scanners.foundry.shutil.which",
        lambda _executable: pytest.fail("source mismatch must stop before tool lookup"),
    )

    result = FoundryForkScanner(
        SmartContractsConfig(allow_fork_probing=True),
        expected_repository_sha256=frozen_sha256,
        repository_exclusion_root=output,
    ).run(
        root,
        tmp_path / "private-source-mismatch",
        5,
        backend=_PassthroughIsolation(),
    )

    assert result.status is ScannerStatus.FAILED
    assert "pipeline-frozen identity" in (result.error or "")
    assert result.repository_suite_selection is None
    assert not result.repository_test_executions


def test_foundry_repository_suite_missing_forge_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repository"
    test_dir = root / "test" / "audit"
    test_dir.mkdir(parents=True)
    (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (test_dir / "Portfolio.t.sol").write_text(
        "contract PortfolioTest { function testUnit() public {} }\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    monkeypatch.setattr("mmaudit.scanners.foundry.shutil.which", lambda _executable: None)
    monkeypatch.setattr(
        "mmaudit.scanners.foundry.isolation_execution_evidence",
        lambda _backend: ExecutionEvidenceKind.REAL,
    )
    monkeypatch.setattr(
        "mmaudit.scanners.foundry.isolation_attestation_sha256",
        lambda _backend: "a" * 64,
    )

    result = FoundryForkScanner(
        SmartContractsConfig(allow_fork_probing=True),
        reproduction=ReproductionConfig(
            expected_chain_id=31_337,
            pinned_block_number=42,
        ),
    ).run(
        root,
        tmp_path / "private-missing-forge",
        5,
        backend=_PassthroughIsolation(),
    )

    assert result.status is ScannerStatus.UNAVAILABLE
    assert result.error == "forge is not installed"
    assert len(result.repository_test_executions) == 1
    execution = result.repository_test_executions[0]
    assert execution.status is RepositoryTestExecutionStatus.UNAVAILABLE
    assert execution.command_sha256 is None
    assert execution.output_sha256 is None
    assert execution.repository_code_execution is RepositoryCodeExecutionState.BLOCKED
    assert not result.findings


def test_foundry_repository_suite_missing_pinned_solc_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repository"
    test_dir = root / "test" / "audit"
    test_dir.mkdir(parents=True)
    (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (test_dir / "Portfolio.t.sol").write_text(
        "contract PortfolioTest { function testUnit() public {} }\n",
        encoding="utf-8",
    )
    fake_forge = tmp_path / "forge"
    fake_forge.write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
    fake_forge.chmod(0o755)
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    monkeypatch.delenv("MMAUDIT_SOLC_EXECUTABLE", raising=False)
    monkeypatch.setattr(
        "mmaudit.scanners.foundry.shutil.which",
        lambda executable: str(fake_forge) if executable == "forge" else None,
    )
    monkeypatch.setattr(
        "mmaudit.scanners.foundry.isolation_execution_evidence",
        lambda _backend: ExecutionEvidenceKind.REAL,
    )
    monkeypatch.setattr(
        "mmaudit.scanners.foundry.isolation_attestation_sha256",
        lambda _backend: "a" * 64,
    )

    result = FoundryForkScanner(
        SmartContractsConfig(
            allow_fork_probing=True,
            solc_version="0.8.30",
            solc_sha256="b" * 64,
        ),
        reproduction=ReproductionConfig(
            expected_chain_id=31_337,
            pinned_block_number=42,
        ),
    ).run(
        root,
        tmp_path / "private-missing-solc",
        5,
        backend=_PassthroughIsolation(),
    )

    assert result.status is ScannerStatus.UNAVAILABLE
    assert result.error == "MMAUDIT_SOLC_EXECUTABLE is not set"
    assert len(result.repository_test_executions) == 1
    execution = result.repository_test_executions[0]
    assert execution.status is RepositoryTestExecutionStatus.UNAVAILABLE
    assert execution.command_sha256 is None
    assert execution.output_sha256 is None
    assert execution.repository_code_execution is RepositoryCodeExecutionState.BLOCKED
    assert not result.findings


@pytest.mark.parametrize(
    ("return_code", "stdout", "expected"),
    [
        (-6, "", "terminated before emitting"),
        (134, '{"suite":{}}', "terminated before emitting"),
        (0, "", "no machine JSON"),
        (1, " \n\t", "no machine JSON"),
        (0, '{"suite":{}}', None),
        (1, '{"suite":{}}', None),
    ],
)
def test_foundry_machine_result_precondition_rejects_crash_and_empty_output(
    return_code: int,
    stdout: str,
    expected: str | None,
) -> None:
    result = _foundry_machine_result_precondition(
        return_code=return_code,
        stdout=stdout,
    )

    if expected is None:
        assert result is None
    else:
        assert expected in (result or "")


@pytest.mark.parametrize(
    ("reason", "expected_status"),
    [
        ("assertion failed", RepositoryTestExecutionStatus.ASSERTION_FAILED),
        ("EvmError: Revert", RepositoryTestExecutionStatus.REVERTED),
        ("synthetic machine failure", RepositoryTestExecutionStatus.FAILED),
    ],
)
def test_foundry_machine_result_classifies_failure_kinds(
    reason: str,
    expected_status: RepositoryTestExecutionStatus,
) -> None:
    descriptor = RepositorySuiteTestDescriptor.sealed(
        framework=RepositorySuiteFramework.FOUNDRY,
        project_root=".",
        path="test/audit/Portfolio.t.sol",
        suite_name="PortfolioTest",
        test_name="testFailure",
        source_sha256="a" * 64,
        start_line=1,
        end_line=1,
    )
    stdout = json.dumps(
        {
            "test/audit/Portfolio.t.sol:PortfolioTest": {
                "test_results": {
                    "testFailure()": {
                        "status": "Failure",
                        "reason": reason,
                        "kind": {"Unit": {"gas": 123}},
                    }
                }
            }
        },
        separators=(",", ":"),
    )

    status, detail, summary, result_sha256 = _parse_exact_foundry_test(
        stdout,
        descriptor=descriptor,
        return_code=1,
    )

    assert status is expected_status
    assert detail == reason
    assert summary.failed_tests == 1
    assert len(result_sha256) == 64


def test_real_repository_suite_scanner_strength_survives_report_conversion(
    tmp_path: Path,
) -> None:
    source = tmp_path / "Vault.t.sol"
    source.write_text(
        "contract VaultTest { function testInvariant() public {} }\n",
        encoding="utf-8",
    )
    scanner = ScannerFinding(
        scanner="foundry_fork",
        rule_id="repository-fork-test-failure",
        title="Synthetic repository test failure",
        severity=Severity.HIGH,
        message="A real isolated repository test observed an incorrect state transition.",
        locations=[Location(path=source.name, start_line=1, end_line=1)],
        metadata={"repository_test_execution_sha256": "a" * 64},
        evidence_strength=EvidenceStrength.DETERMINISTIC_ANALYZER,
        fingerprint="b" * 64,
    )

    findings = _scanner_findings_for_report(tmp_path, [scanner])

    assert len(findings) == 1
    assert findings[0].status is FindingStatus.NEEDS_REVIEW
    assert findings[0].evidence_strength is EvidenceStrength.DETERMINISTIC_ANALYZER


def test_scanner_location_annotation_reseals_execution_observation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "Vault.t.sol").write_text(
        "contract VaultTest { function testInvariant() public {} }\n",
        encoding="utf-8",
    )
    now = datetime.now(UTC)
    unsealed = ScannerRun(
        scanner="foundry_fork",
        status=ScannerStatus.SUCCESS,
        execution_evidence=ExecutionEvidenceKind.REAL,
        version="forge 1.3.2",
        executable_sha256="1" * 64,
        command=["forge", "test"],
        started_at=now,
        finished_at=now,
        duration_seconds=0,
        findings=[
            ScannerFinding(
                scanner="foundry_fork",
                rule_id="repository-test-failure",
                title="Synthetic repository test failure",
                severity=Severity.MEDIUM,
                message="Synthetic local assertion failed.",
                locations=[Location(path="Vault.t.sol", start_line=1, end_line=1)],
                fingerprint="2" * 64,
            )
        ],
        raw_output_path="private/scanners/foundry.json",
        raw_output_sha256="3" * 64,
        raw_output_bytes=1,
        process_exit_code=1,
        isolation_backend="sandbox-exec",
        isolation_attestation_sha256="4" * 64,
        machine_output_validated=True,
    )
    run = unsealed.model_copy(
        update={"execution_observation_sha256": (unsealed.expected_execution_observation_sha256())}
    )

    annotated = _annotate_scanner_locations(root, run)

    assert annotated.findings[0].metadata["location_validation"][0]["valid"] is True
    assert (
        annotated.execution_observation_sha256 == annotated.expected_execution_observation_sha256()
    )
    assert ScannerRun.model_validate_json(annotated.model_dump_json()) == annotated


def test_foundry_scanner_rejects_self_asserted_real_inventory_provenance(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "repository"
    test_dir = root / "test" / "audit"
    test_dir.mkdir(parents=True)
    (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (test_dir / "Portfolio.t.sol").write_text(
        "contract PortfolioTest { function testUnit() public {} }\n",
        encoding="utf-8",
    )
    payload = json.dumps(
        {
            "test/audit/Portfolio.t.sol:PortfolioTest": {
                "test_results": {
                    "testUnit()": {
                        "status": "Success",
                        "kind": {"Unit": {"gas": 123}},
                    }
                }
            }
        },
        separators=(",", ":"),
    )
    fake_forge = tmp_path / "forge"
    fake_forge.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import os",
                "import sys",
                'if "--version" in sys.argv:',
                '    print("forge 1.3.2")',
                "    raise SystemExit(0)",
                'if os.environ.get("FOUNDRY_INVARIANT_RUNS") != "4":',
                "    raise SystemExit(19)",
                f"sys.stdout.write({payload!r})",
                "",
            )
        ),
        encoding="utf-8",
    )
    fake_forge.chmod(0o755)
    fake_solc = tmp_path / "solc-0.8.30"
    fake_solc.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                'print("solc, Version: 0.8.30")',
                "",
            )
        ),
        encoding="utf-8",
    )
    fake_solc.chmod(0o755)
    fake_solc_sha256 = hashlib.sha256(fake_solc.read_bytes()).hexdigest()
    monkeypatch.setattr(
        "mmaudit.scanners.foundry.shutil.which",
        lambda executable: str(fake_forge) if executable == "forge" else None,
    )
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    monkeypatch.setenv("MMAUDIT_SOLC_EXECUTABLE", str(fake_solc))
    monkeypatch.setattr(
        "mmaudit.scanners.foundry.isolation_execution_evidence",
        lambda _backend: ExecutionEvidenceKind.REAL,
    )
    monkeypatch.setattr(
        "mmaudit.scanners.foundry.isolation_attestation_sha256",
        lambda _backend: "a" * 64,
    )
    monkeypatch.setattr(
        "mmaudit.scanners.foundry.observe_pinned_fork_rpc",
        lambda *_args, **_kwargs: PinnedForkObservation(
            chain_id=31_337,
            block_number=42,
            block_hash="0x" + "b" * 64,
        ),
    )
    scanner = FoundryForkScanner(
        SmartContractsConfig(
            allow_fork_probing=True,
            solc_version="0.8.30",
            solc_sha256=fake_solc_sha256,
            foundry_fuzz_runs=8,
            foundry_invariant_runs=4,
        ),
        reproduction=ReproductionConfig(
            expected_chain_id=31_337,
            pinned_block_number=42,
        ),
    )

    run = scanner.run(
        root,
        tmp_path / "private",
        5,
        backend=_SelfAssertedRealIsolation(),
    )

    assert run.status is ScannerStatus.UNAVAILABLE
    assert run.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert run.isolation_backend == "sandbox-exec"
    assert run.error is not None
    assert "inventory isolation lacks current attested execution evidence" in run.error
    assert run.foundry_summary is None
    assert run.repository_suite_selection is not None
    assert run.repository_suite_selection.selected_test_count == 1
    assert len(run.repository_test_executions) == 1
    execution = run.repository_test_executions[0]
    assert execution.status is RepositoryTestExecutionStatus.UNAVAILABLE
    assert execution.chain_id == 31_337
    assert execution.block_number == 42
    assert execution.block_hash == "0x" + ("b" * 64)
    assert execution.test_kind is None
    assert execution.compiler_sha256 == fake_solc_sha256
    assert execution.execution_policy_sha256 is None
    assert execution.safety_claim is False
    assert not run.findings
    assert not run.command
    assert run.execution_observation_sha256 == run.expected_execution_observation_sha256()
    payload_with_tampered_output = run.model_dump(mode="json")
    payload_with_tampered_output["raw_output_bytes"] = run.raw_output_bytes + 1
    with pytest.raises(ValueError, match="execution observation hash"):
        ScannerRun.model_validate(payload_with_tampered_output)


def test_scanner_commands_are_fixed_argument_arrays(tmp_path: Path) -> None:
    adapters = [SemgrepScanner(), GitleaksScanner(), TrivyScanner(), OsvScanner(), SlitherScanner()]
    for adapter in adapters:
        command = adapter.build_command(tmp_path, tmp_path / adapter.name)
        assert isinstance(command, list)
        assert command[0] == adapter.executable
        assert not any(token in command for token in ("curl", "wget", "ssh"))


def test_semgrep_stages_exact_bundled_rules_inside_private_directory(tmp_path: Path) -> None:
    private = tmp_path / "private"

    command = SemgrepScanner().build_command(tmp_path, private)

    config_index = command.index("--config") + 1
    staged = Path(command[config_index]).resolve(strict=True)
    staged.relative_to(private.resolve(strict=True))
    bundled = Path(__file__).parents[2] / "src/mmaudit/scanners/rules/security.yml"
    assert staged.read_bytes() == bundled.read_bytes()
    assert staged.stat().st_mode & 0o777 == 0o600
    assert str(bundled.resolve(strict=True)) not in command


def test_gitleaks_stages_exact_bundled_rules_inside_private_directory(tmp_path: Path) -> None:
    private = tmp_path / "private"

    command = GitleaksScanner().build_command(tmp_path, private)

    config_index = command.index("--config") + 1
    staged = Path(command[config_index]).resolve(strict=True)
    staged.relative_to(private.resolve(strict=True))
    bundled = Path(__file__).parents[2] / "src/mmaudit/scanners/rules/gitleaks.toml"
    assert staged.read_bytes() == bundled.read_bytes()
    assert staged.stat().st_mode & 0o777 == 0o600
    assert str(bundled.resolve(strict=True)) not in command
    assert command[command.index("--report-path") + 1] == "-"


def test_gitleaks_refuses_to_replace_existing_staged_rules(tmp_path: Path) -> None:
    private = tmp_path / "private"
    scanner = GitleaksScanner()
    scanner.build_command(tmp_path, private)

    with pytest.raises(FileExistsError):
        scanner.build_command(tmp_path, private)


@pytest.mark.parametrize(
    ("scanner", "destination"),
    [
        (SemgrepScanner(), "semgrep-security.yml"),
        (GitleaksScanner(), "gitleaks.toml"),
    ],
)
def test_scanner_revalidates_staged_rule_bytes_before_execution(
    tmp_path: Path,
    scanner: SemgrepScanner | GitleaksScanner,
    destination: str,
) -> None:
    private = tmp_path / "private"
    scanner.build_command(tmp_path, private)
    staged = private / "trusted-inputs" / destination
    staged.write_bytes(b"tampered\n")

    with pytest.raises(ValueError, match="exact-byte verification"):
        scanner.validate_pre_execution_inputs(tmp_path, private)


@pytest.mark.parametrize(
    ("scanner", "destination"),
    [
        (SemgrepScanner(), "semgrep-security.yml"),
        (GitleaksScanner(), "gitleaks.toml"),
    ],
)
def test_scanner_rejects_hardlinked_staged_rule_before_execution(
    tmp_path: Path,
    scanner: SemgrepScanner | GitleaksScanner,
    destination: str,
) -> None:
    private = tmp_path / "private"
    scanner.build_command(tmp_path, private)
    staged = private / "trusted-inputs" / destination
    os.link(staged, tmp_path / f"{destination}.alias")

    with pytest.raises(ValueError, match="private-file validation"):
        scanner.validate_pre_execution_inputs(tmp_path, private)


def test_gitleaks_run_attests_the_strict_stdout_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "Synthetic.sol").write_text("contract Synthetic {}\n", encoding="utf-8")
    trusted_bin = tmp_path / "trusted-bin"
    trusted_bin.mkdir()
    executable = trusted_bin / "gitleaks"
    executable.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import sys",
                "print('gitleaks 8.30.1' if '--version' in sys.argv else '[]')",
                "",
            )
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(trusted_bin))
    private = tmp_path / "private"

    run = GitleaksScanner().run(target, private, 5, backend=_PassthroughIsolation())

    assert run.status is ScannerStatus.SUCCESS
    assert run.machine_output_validated
    assert run.raw_output_bytes == len(b"[]\n")
    assert (private / "gitleaks.json").read_bytes() == b"[]\n"
    assert run.command[run.command.index("--report-path") + 1] == "-"
    staged = Path(run.command[run.command.index("--config") + 1]).resolve(strict=True)
    staged.relative_to(private.resolve(strict=True))


def test_semgrep_run_credits_only_a_validated_stdout_envelope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "Synthetic.sol").write_text("contract Synthetic {}\n", encoding="utf-8")
    trusted_bin = tmp_path / "trusted-bin"
    trusted_bin.mkdir()
    executable = trusted_bin / "semgrep"
    executable.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import sys",
                "print('semgrep 1.172.0' if '--version' in sys.argv "
                'else \'{"results":[],"errors":[]}\')',
                "",
            )
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(trusted_bin))
    private = tmp_path / "private"

    run = SemgrepScanner().run(target, private, 5, backend=_PassthroughIsolation())

    assert run.status is ScannerStatus.SUCCESS
    assert run.machine_output_validated
    assert run.raw_output_bytes > 0
    assert json.loads((private / "semgrep.json").read_bytes()) == {"errors": [], "results": []}


def test_semgrep_refuses_to_replace_existing_staged_rules(tmp_path: Path) -> None:
    private = tmp_path / "private"
    scanner = SemgrepScanner()
    scanner.build_command(tmp_path, private)

    with pytest.raises(FileExistsError):
        scanner.build_command(tmp_path, private)


def test_semgrep_rejects_oversized_bundled_rules_before_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "synthetic-package"
    rules = package / "rules"
    rules.mkdir(parents=True)
    (rules / "security.yml").write_bytes(b"x" * 1_000_001)
    monkeypatch.setattr("mmaudit.scanners.trusted_inputs.files", lambda _package: package)

    with pytest.raises(ValueError, match="exceeds its fixed bound"):
        SemgrepScanner().build_command(tmp_path, tmp_path / "private")

    assert not (tmp_path / "private").exists()


def test_semgrep_rejects_non_private_staging_directory(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o755)

    with pytest.raises(ValueError, match="mode 0700"):
        SemgrepScanner().build_command(tmp_path, private)


@pytest.mark.parametrize(
    "payload",
    [
        {"success": False, "results": {"detectors": []}},
        {"success": True, "results": []},
        {"success": True, "results": {"detectors": [None]}},
        {"success": True, "error": "compilation failed", "results": {"detectors": []}},
    ],
)
def test_slither_rejects_invalid_machine_envelopes(
    tmp_path: Path,
    payload: object,
) -> None:
    with pytest.raises(ValueError, match="Slither"):
        SlitherScanner().parse(tmp_path, json.dumps(payload), tmp_path / "private")


def test_exit_zero_slither_success_false_is_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "target"
    root.mkdir()
    (root / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
    trusted_bin = tmp_path / "trusted-bin"
    trusted_bin.mkdir()
    executable = trusted_bin / "slither"
    executable.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import sys",
                'print("slither 0.11.5" if "--version" in sys.argv else '
                '\'{"success":false,"results":{"detectors":[]}}\')',
                "",
            )
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(trusted_bin))

    run = SlitherScanner().run(
        root,
        tmp_path / "private-slither-false",
        2,
        backend=_PassthroughIsolation(),
    )

    assert run.status is ScannerStatus.FAILED
    assert run.process_exit_code == 0
    assert not run.machine_output_validated
    assert run.execution_observation_sha256 == run.expected_execution_observation_sha256()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", ScannerStatus.FAILED),
        ("version", "slither 0.11.4"),
        ("execution_evidence", ExecutionEvidenceKind.MOCK),
        ("isolation_backend", "rootless-container"),
        ("repository_code_execution", RepositoryCodeExecutionState.ISOLATED),
    ],
)
def test_scanner_observation_binds_assurance_provenance(
    field: str,
    value: object,
) -> None:
    now = datetime.now(UTC)
    run = ScannerRun(
        scanner="slither",
        status=ScannerStatus.SUCCESS,
        execution_evidence=ExecutionEvidenceKind.REAL,
        version="slither 0.11.5",
        executable_sha256="1" * 64,
        command=["slither", ".", "--json", "-"],
        started_at=now,
        finished_at=now,
        duration_seconds=0,
        raw_output_path="private/slither.json",
        raw_output_sha256="2" * 64,
        raw_output_bytes=2,
        process_exit_code=0,
        isolation_backend="sandbox-exec",
        machine_output_validated=True,
    )
    sealed = ScannerRun.model_validate(
        {
            **run.model_dump(mode="json"),
            "execution_observation_sha256": run.expected_execution_observation_sha256(),
        }
    )
    payload = sealed.model_dump(mode="json")
    payload[field] = value

    with pytest.raises(ValueError, match="execution observation hash"):
        ScannerRun.model_validate(payload)


def test_scanner_environment_drops_unrelated_secrets(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "should-not-propagate")
    monkeypatch.setenv("MMAUDIT_SECRETS_ENV_FILE", "/synthetic/operator.env")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "should-not-propagate")
    monkeypatch.setenv("SSL_CERT_FILE", "/Users/synthetic-operator/private-ca.pem")
    monkeypatch.setenv("SEMGREP_SEND_METRICS", "on")
    monkeypatch.setenv("SEMGREP_ENABLE_VERSION_CHECK", "1")
    monkeypatch.setattr(
        "mmaudit.scanners.base._fixed_darwin_scanner_ca_bundle",
        lambda: Path("/etc/ssl/cert.pem"),
    )
    environment = sanitized_scanner_environment(tmp_path)
    assert "OPENROUTER_API_KEY" not in environment
    assert "MMAUDIT_SECRETS_ENV_FILE" not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert environment["SSL_CERT_FILE"] == "/etc/ssl/cert.pem"
    assert environment["SEMGREP_SEND_METRICS"] == "off"
    assert environment["SEMGREP_ENABLE_VERSION_CHECK"] == "0"
    assert environment["HOME"].startswith(str(tmp_path))


def test_scanner_preflight_probes_exact_absolute_executable_without_path_lookup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "synthetic-tool"
    executable.write_text(
        f"#!{sys.executable}\nprint('synthetic-tool 1.2.3')\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    private = tmp_path / "private-preflight"
    environment = sanitized_scanner_environment(private)
    monkeypatch.setattr(
        "mmaudit.scanners.base.shutil.which",
        lambda _name: pytest.fail("an absolute executable must not be resolved again through PATH"),
    )

    result = preflight_scanner_executable(
        executable,
        environment,
        _PassthroughIsolation(),
        tmp_path,
        private,
    )

    assert result.state is ScannerExecutableState.PRESENT_EXECUTABLE
    assert result.resolved_path == executable.resolve(strict=True)
    assert result.version == "synthetic-tool 1.2.3"
    assert result.failure_kind is None
    assert result.diagnostic is None


def test_scanner_preflight_selects_multiline_solc_version_line(tmp_path: Path) -> None:
    executable = tmp_path / "solc"
    executable.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "print('solc, the solidity compiler commandline interface')",
                "print('Version: 0.8.30+commit.synthetic.Darwin.appleclang')",
                "",
            )
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    private = tmp_path / "private-solc-version"
    environment = sanitized_scanner_environment(private)

    result = preflight_scanner_executable(
        executable,
        environment,
        _PassthroughIsolation(),
        tmp_path,
        private,
    )

    assert result.state is ScannerExecutableState.PRESENT_EXECUTABLE
    assert result.version == "Version: 0.8.30+commit.synthetic.Darwin.appleclang"
    raw_stdout = next(private.glob("version-probe-*/stdout.txt")).read_text(encoding="utf-8")
    assert raw_stdout.startswith("solc, the solidity compiler commandline interface\nVersion:")


def test_legacy_version_projection_returns_only_validated_public_line(tmp_path: Path) -> None:
    executable = tmp_path / "legacy-version-tool"
    executable.write_text(
        f"#!{sys.executable}\nprint('tool 4.5.6')\nprint('private build metadata')\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    private = tmp_path / "private-legacy-version"
    environment = sanitized_scanner_environment(private)

    version = isolated_executable_version(
        executable,
        environment,
        _PassthroughIsolation(),
        tmp_path,
        private,
    )

    assert version == "tool 4.5.6"


@pytest.mark.parametrize("kind", ["permissive", "symlink"])
def test_scanner_preflight_refuses_non_private_probe_root(tmp_path: Path, kind: str) -> None:
    executable = tmp_path / "synthetic-private-root-tool"
    executable.write_text(f"#!{sys.executable}\nprint('tool 1.0')\n", encoding="utf-8")
    executable.chmod(0o755)
    outside = tmp_path / "outside-private-root"
    outside.mkdir(mode=0o700)
    private = tmp_path / "probe-root"
    if kind == "permissive":
        private.mkdir(mode=0o700)
        private.chmod(0o755)
    else:
        private.symlink_to(outside, target_is_directory=True)
    environment = {
        "PATH": "",
        "HOME": str(tmp_path),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }

    result = preflight_scanner_executable(
        executable,
        environment,
        _PassthroughIsolation(),
        tmp_path,
        private,
    )

    assert result.state is ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE
    assert result.failure_kind is ExecutableVersionProbeStatus.ISOLATION_FAILURE
    assert result.diagnostic == "private tool-probe evidence could not be retained safely"
    assert list(outside.iterdir()) == []


def test_scanner_preflight_distinguishes_absent_from_isolation_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private-preflight-states"
    environment = sanitized_scanner_environment(private)
    monkeypatch.setattr("mmaudit.scanners.base.shutil.which", lambda _name: None)

    absent = preflight_scanner_executable(
        "synthetic-missing-tool",
        environment,
        _PassthroughIsolation(),
        tmp_path,
        private,
    )

    assert absent.state is ScannerExecutableState.ABSENT
    assert absent.resolved_path is None
    assert absent.failure_kind is None

    executable = tmp_path / "synthetic-failing-tool"
    executable.write_text(f"#!{sys.executable}\nraise SystemExit(7)\n", encoding="utf-8")
    executable.chmod(0o755)
    failed = preflight_scanner_executable(
        executable,
        environment,
        _PassthroughIsolation(),
        tmp_path,
        private,
    )

    assert failed.state is ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE
    assert failed.resolved_path == executable.resolve(strict=True)
    assert failed.version is None
    assert failed.failure_kind is ExecutableVersionProbeStatus.ISOLATION_FAILURE
    assert failed.diagnostic is not None
    assert str(tmp_path) not in failed.diagnostic


def test_toolchain_resolution_failure_is_typed_and_path_free(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repository-toolchain-resolution"
    root.mkdir()
    executable = tmp_path / "synthetic-toolchain-resolution-tool"
    executable.write_text(f"#!{sys.executable}\nprint('tool 1.0')\n", encoding="utf-8")
    executable.chmod(0o755)
    backend = _ToolchainResolutionFailureIsolation()
    preflight_private = tmp_path / "private-toolchain-preflight"

    preflight = preflight_scanner_executable(
        executable,
        sanitized_scanner_environment(preflight_private),
        backend,
        root,
        preflight_private,
    )
    scanner = _SyntheticProcessScanner("print('{}')")
    scanner.executable = str(executable)
    run = scanner.run(
        root,
        tmp_path / "private-toolchain-scanner",
        2,
        backend=backend,
    )

    assert preflight.state is ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE
    assert preflight.failure_kind is ExecutableVersionProbeStatus.INTERPRETER_OR_LOADER_FAILURE
    assert preflight.diagnostic is not None
    assert "self-contained tool distribution" in preflight.diagnostic
    assert run.status is ScannerStatus.INTERPRETER_OR_LOADER_FAILURE
    for public_diagnostic in (preflight.diagnostic, run.error or ""):
        assert "SYNTHETIC-OPERATOR" not in public_diagnostic
        assert "/Users/" not in public_diagnostic


def test_darwin_process_ceiling_is_relative_bounded_and_fail_closed() -> None:
    listing = "501\n0\n501\n502\n501\n"

    assert (
        _darwin_nproc_ceiling_from_uid_listing(
            listing,
            current_uid=501,
            allowance=16,
            inherited_hard_limit=1_000,
        )
        == 19
    )
    assert (
        _darwin_nproc_ceiling_from_uid_listing(
            listing,
            current_uid=501,
            allowance=16,
            inherited_hard_limit=10,
        )
        == 10
    )
    with pytest.raises(OSError, match="no safe child allowance"):
        _darwin_nproc_ceiling_from_uid_listing(
            listing,
            current_uid=501,
            allowance=16,
            inherited_hard_limit=3,
        )
    with pytest.raises(OSError, match="malformed"):
        _darwin_nproc_ceiling_from_uid_listing(
            "501\nnot-a-uid\n",
            current_uid=501,
            allowance=16,
            inherited_hard_limit=1_000,
        )


def test_darwin_process_inventory_uses_real_uid_kernel_filter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int]] = []
    raw = struct.pack("=3i", os.getpid(), 123, 456)

    class FakeListPids:
        argtypes: object = None
        restype: object = None

        def __call__(
            self,
            mode: int,
            typeinfo: int,
            buffer: object,
            capacity: int,
        ) -> int:
            calls.append((mode, typeinfo))
            if buffer is None:
                return len(raw)
            assert capacity >= len(raw)
            import ctypes

            ctypes.memmove(buffer, raw, len(raw))
            return len(raw)

    class FakeLibproc:
        proc_listpids = FakeListPids()

    monkeypatch.setattr(
        "mmaudit.scanners.base.ctypes.CDLL", lambda *_args, **_kwargs: FakeLibproc()
    )

    assert _darwin_current_uid_process_count() == 3
    assert calls == [(5, os.getuid()), (5, os.getuid())]


def test_darwin_memory_monitor_sums_one_bounded_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_pid = 123
    pids = (root_pid, 456)
    raw_pids = struct.pack("=2i", *pids)
    resident_by_pid = {root_pid: 4_096, 456: 8_192}
    list_calls: list[tuple[int, int]] = []
    info_calls: list[int] = []

    class FakeListPids:
        argtypes: object = None
        restype: object = None

        def __call__(
            self,
            mode: int,
            typeinfo: int,
            buffer: object,
            capacity: int,
        ) -> int:
            list_calls.append((mode, typeinfo))
            if buffer is None:
                return len(raw_pids)
            assert capacity >= len(raw_pids)
            import ctypes

            ctypes.memmove(buffer, raw_pids, len(raw_pids))
            return len(raw_pids)

    class FakePidInfo:
        argtypes: object = None
        restype: object = None

        def __call__(
            self,
            pid: int,
            flavor: int,
            argument: int,
            buffer: object,
            capacity: int,
        ) -> int:
            del argument
            assert flavor == 4
            assert capacity >= 16
            info_calls.append(pid)
            import ctypes

            task_info = struct.pack("=QQ", 1_000_000, resident_by_pid[pid])
            ctypes.memmove(buffer, task_info, len(task_info))
            return len(task_info)

    class FakeLibproc:
        proc_listpids = FakeListPids()
        proc_pidinfo = FakePidInfo()

    monkeypatch.setattr("mmaudit.scanners.base.sys.platform", "darwin")
    monkeypatch.setattr(
        "mmaudit.scanners.base.ctypes.CDLL", lambda *_args, **_kwargs: FakeLibproc()
    )

    assert _darwin_process_group_rss_bytes(root_pid) == 12_288
    assert list_calls == [(2, root_pid), (2, root_pid)]
    assert sorted(info_calls) == sorted(pids)


@pytest.mark.parametrize(
    ("task_info_errno", "expected_resident_bytes"),
    [
        (errno.ESRCH, 4_096),
        (0, None),
        (errno.EPERM, None),
        (errno.EINVAL, None),
    ],
)
def test_darwin_memory_monitor_only_tolerates_stale_esrch_pids(
    monkeypatch: pytest.MonkeyPatch,
    task_info_errno: int,
    expected_resident_bytes: int | None,
) -> None:
    root_pid = 123
    stale_pid = 456
    raw_pids = struct.pack("=2i", root_pid, stale_pid)

    class FakeListPids:
        argtypes: object = None
        restype: object = None

        def __call__(
            self,
            mode: int,
            typeinfo: int,
            buffer: object,
            capacity: int,
        ) -> int:
            assert (mode, typeinfo) == (2, root_pid)
            if buffer is None:
                return len(raw_pids)
            assert capacity >= len(raw_pids)
            import ctypes

            ctypes.memmove(buffer, raw_pids, len(raw_pids))
            return len(raw_pids)

    class FakePidInfo:
        argtypes: object = None
        restype: object = None

        def __call__(
            self,
            pid: int,
            flavor: int,
            argument: int,
            buffer: object,
            capacity: int,
        ) -> int:
            del argument
            assert flavor == 4
            assert capacity >= 16
            import ctypes

            if pid == root_pid:
                task_info = struct.pack("=QQ", 1_000_000, 4_096)
                ctypes.memmove(buffer, task_info, len(task_info))
                return len(task_info)
            assert pid == stale_pid
            ctypes.set_errno(task_info_errno)
            return 0

    class FakeLibproc:
        proc_listpids = FakeListPids()
        proc_pidinfo = FakePidInfo()

    monkeypatch.setattr("mmaudit.scanners.base.sys.platform", "darwin")
    monkeypatch.setattr(
        "mmaudit.scanners.base.ctypes.CDLL", lambda *_args, **_kwargs: FakeLibproc()
    )

    if expected_resident_bytes is None:
        with pytest.raises(OSError, match="could not be established"):
            _darwin_process_group_rss_bytes(root_pid)
    else:
        assert _darwin_process_group_rss_bytes(root_pid) == expected_resident_bytes


def test_version_probe_memory_limit_stops_before_target_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "target-ran-after-version-memory-limit"
    root = tmp_path / "repository-version-memory"
    root.mkdir()
    executable = tmp_path / "synthetic-memory-probe-tool"
    executable.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import pathlib",
                "import sys",
                "import time",
                'if "--version" in sys.argv:',
                "    print('synthetic tool 1.0', flush=True)",
                "    time.sleep(1)",
                "else:",
                f"    pathlib.Path({str(marker)!r}).write_text('executed')",
                "",
            )
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    scanner = _SyntheticProcessScanner("print('{}')")
    scanner.executable = str(executable)
    monkeypatch.setattr(
        "mmaudit.scanners.base._darwin_process_group_rss_bytes",
        lambda _pid: 1024**3 + 1,
    )

    result = scanner.run(
        root,
        tmp_path / ".mmaudit" / "private-version-memory-bound",
        2,
        backend=_PassthroughIsolation(),
    )

    assert result.status is ScannerStatus.UNAVAILABLE
    assert result.error == "tool version command exceeded the private memory limit"
    assert result.command == []
    assert result.process_exit_code is None
    assert not marker.exists()


def test_oversized_version_output_is_invalid_not_an_execution_failure(tmp_path: Path) -> None:
    executable = tmp_path / "oversized-version-tool"
    executable.write_text(
        f"#!{sys.executable}\nimport sys\nsys.stdout.write('1' * (70 * 1024))\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    private = tmp_path / "private-oversized-version"
    environment = sanitized_scanner_environment(private)

    result = isolated_executable_version_probe(
        executable,
        environment,
        _PassthroughIsolation(),
        tmp_path,
        private,
    )

    assert result.status is ExecutableVersionProbeStatus.INVALID_VERSION
    assert result.version is None
    assert result.diagnostic is not None
    assert "bounded path-free single-line" in result.diagnostic
    assert next(private.glob("version-probe-*/stdout.txt")).stat().st_size <= 64 * 1024


def test_scanner_process_group_memory_limit_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repository-target-memory"
    root.mkdir()
    executable = tmp_path / "synthetic-target-memory-tool"
    executable.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import sys",
                "import time",
                'if "--version" in sys.argv:',
                "    print('synthetic tool 1.0', flush=True)",
                "    time.sleep(0.1)",
                "else:",
                "    time.sleep(5)",
                "",
            )
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    scanner = _SyntheticProcessScanner("print('{}')")
    scanner.executable = str(executable)
    version_pid: int | None = None

    def resident_bytes(pid: int) -> int:
        nonlocal version_pid
        if version_pid is None:
            version_pid = pid
        return 0 if pid == version_pid else 4 * 1024**3 + 1

    monkeypatch.setattr(
        "mmaudit.scanners.base._darwin_process_group_rss_bytes",
        resident_bytes,
    )

    result = scanner.run(
        root,
        tmp_path / ".mmaudit" / "private-target-memory-bound",
        2,
        backend=_PassthroughIsolation(),
    )

    assert result.status is ScannerStatus.FAILED
    assert result.error == "scanner exceeded the private memory limit"
    assert result.command
    assert result.process_exit_code is not None


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group attestation")
def test_version_probe_rejects_descendant_that_outlives_process_group_leader(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "synthetic-version-descendant-tool"
    child_code = "import time; time.sleep(10)"
    executable.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import subprocess",
                "import sys",
                f"subprocess.Popen([sys.executable, '-c', {child_code!r}])",
                "print('synthetic tool 1.0')",
                "",
            )
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    private = tmp_path / "private-version-descendant"

    result = isolated_executable_version_probe(
        executable,
        sanitized_scanner_environment(private),
        _PassthroughIsolation(),
        tmp_path,
        private,
    )

    assert result.status is ExecutableVersionProbeStatus.ISOLATION_FAILURE
    assert result.version is None
    assert result.diagnostic == (
        "tool version command left a descendant process after its leader exited"
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group attestation")
def test_scanner_rejects_descendant_that_outlives_process_group_leader(tmp_path: Path) -> None:
    root = tmp_path / "repository-target-descendant"
    root.mkdir()
    executable = tmp_path / "synthetic-target-descendant-tool"
    child_code = "import time; time.sleep(10)"
    executable.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import subprocess",
                "import sys",
                'if "--version" in sys.argv:',
                "    print('synthetic tool 1.0')",
                "else:",
                f"    subprocess.Popen([sys.executable, '-c', {child_code!r}])",
                "    print('{}')",
                "",
            )
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    scanner = _SyntheticProcessScanner("print('{}')")
    scanner.executable = str(executable)

    result = scanner.run(
        root,
        tmp_path / ".mmaudit" / "private-target-descendant",
        2,
        backend=_PassthroughIsolation(),
    )

    assert result.status is ScannerStatus.FAILED
    assert result.error == "scanner left a descendant process after its leader exited"
    assert result.command


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group attestation")
def test_post_launch_output_observation_failure_stops_scanner_process(tmp_path: Path) -> None:
    root = tmp_path / "repository-output-observation"
    root.mkdir()
    pid_path = tmp_path / "scanner.pid"
    backend = _DeletingScannerOutputIsolation(pid_path)
    scanner = _SyntheticProcessScanner("print('{}')")

    result = scanner.run(
        root,
        tmp_path / ".mmaudit" / "private-output-observation",
        2,
        backend=backend,
    )

    assert result.status is ScannerStatus.FAILED
    assert result.error == "private scanner output identity changed and was rejected"
    assert result.raw_output_path is None
    process_id = int(pid_path.read_text(encoding="utf-8"))
    with pytest.raises(ProcessLookupError):
        os.kill(process_id, 0)


def test_missing_process_bound_evidence_stops_before_version_or_target_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "target-ran-without-process-bound"
    scanner = _SyntheticProcessScanner(
        f"from pathlib import Path; Path({str(marker)!r}).write_text('executed')"
    )
    monkeypatch.setattr(
        "mmaudit.scanners.base._darwin_uid_process_ceiling",
        lambda _allowance: (_ for _ in ()).throw(OSError("synthetic unavailable count")),
    )

    result = scanner.run(
        tmp_path,
        tmp_path / ".mmaudit" / "private-process-bound",
        2,
        backend=_PassthroughIsolation(),
    )

    assert result.status is ScannerStatus.UNAVAILABLE
    assert result.version is None
    assert result.command == []
    assert result.process_exit_code is None
    assert not marker.exists()


@pytest.mark.skipif(os.name == "nt", reason="Windows does not expose POSIX preexec resource limits")
def test_resource_limit_application_failure_stops_before_target_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "target-ran-without-resource-bounds"
    scanner = _SyntheticProcessScanner(
        f"from pathlib import Path; Path({str(marker)!r}).write_text('executed')"
    )

    def fail_limits(*, nproc_ceiling: int | None) -> None:
        del nproc_ceiling
        raise RuntimeError("synthetic setrlimit failure")

    monkeypatch.setattr("mmaudit.scanners.base._limit_version_probe_process", fail_limits)

    result = scanner.run(
        tmp_path,
        tmp_path / ".mmaudit" / "private-resource-bound",
        2,
        backend=_PassthroughIsolation(),
    )

    assert result.status is ScannerStatus.UNAVAILABLE
    assert result.version is None
    assert result.command == []
    assert result.process_exit_code is None
    assert not marker.exists()


@pytest.mark.skipif(os.name == "nt", reason="Windows does not expose POSIX preexec resource limits")
def test_target_resource_limit_failure_is_not_silently_ignored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "target-ran-after-resource-limit-failure"
    scanner = _SyntheticProcessScanner(
        f"from pathlib import Path; Path({str(marker)!r}).write_text('executed')"
    )

    def fail_limits(*, nproc_ceiling: int | None) -> None:
        del nproc_ceiling
        raise RuntimeError("synthetic scanner setrlimit failure")

    monkeypatch.setattr("mmaudit.scanners.base._limit_scanner_process", fail_limits)

    result = scanner.run(
        tmp_path,
        tmp_path / ".mmaudit" / "private-target-resource-bound",
        2,
        backend=_PassthroughIsolation(),
    )

    assert result.status is ScannerStatus.FAILED
    assert "SubprocessError" in (result.error or "")
    assert result.process_exit_code is None
    assert not marker.exists()


def test_static_scanner_and_version_probe_use_no_network_wrapper(tmp_path: Path) -> None:
    backend = _NoNetworkOnlyIsolation()
    scanner = _SyntheticProcessScanner("print('{}')")

    result = scanner.run(
        tmp_path,
        tmp_path / ".mmaudit" / "private-no-network",
        2,
        backend=backend,
    )

    assert result.status is ScannerStatus.SUCCESS
    assert len(backend.commands) == 2
    assert backend.commands[0][0] == str(Path(sys.executable).resolve(strict=True))
    assert backend.commands[1] == [str(Path(sys.executable).resolve(strict=True)), "--version"]


def test_invalid_path_bearing_version_is_unavailable_and_private(tmp_path: Path) -> None:
    root = tmp_path / "repository-invalid-version"
    root.mkdir()
    executable = tmp_path / "path-bearing-version-tool"
    raw_version = "tool 1.2.3 from /Users/SYNTHETIC-OPERATOR/private/tool"
    executable.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import sys",
                'if "--version" in sys.argv:',
                f"    print({raw_version!r})",
                "else:",
                "    print('{}')",
                "",
            )
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    scanner = _SyntheticProcessScanner("print('{}')")
    scanner.executable = str(executable)
    preflight_private = tmp_path / "private-invalid-version-preflight"
    preflight = preflight_scanner_executable(
        executable,
        sanitized_scanner_environment(preflight_private),
        _PassthroughIsolation(),
        root,
        preflight_private,
    )
    private = tmp_path / "private-invalid-version"

    result = scanner.run(root, private, 2, backend=_PassthroughIsolation())

    assert preflight.state is ScannerExecutableState.PRESENT_EXECUTABLE
    assert preflight.version is None
    assert preflight.failure_kind is ExecutableVersionProbeStatus.INVALID_VERSION
    assert result.status is ScannerStatus.UNAVAILABLE
    assert result.version is None
    assert result.error is not None
    assert "bounded path-free single-line" in result.error
    assert result.command == []
    assert result.process_exit_code is None
    assert raw_version not in result.model_dump_json()
    assert (
        next(private.glob("version-probe-*/stdout.txt")).read_text(encoding="utf-8").strip()
        == raw_version
    )


def test_version_probe_rejects_scrubbed_environment_value_echo(tmp_path: Path) -> None:
    executable = tmp_path / "environment-echo-version-tool"
    environment_canary = "SYNTHETIC_SCRUBBED_ENVIRONMENT_CANARY_987"
    raw_version = f"tool 1.2.3 {environment_canary}"
    executable.write_text(
        f"#!{sys.executable}\nprint({raw_version!r})\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    private = tmp_path / "private-environment-echo-version"
    environment = sanitized_scanner_environment(private)
    environment["SYNTHETIC_TEST_CANARY"] = environment_canary

    result = preflight_scanner_executable(
        executable,
        environment,
        _PassthroughIsolation(),
        tmp_path,
        private,
    )

    assert result.state is ScannerExecutableState.PRESENT_EXECUTABLE
    assert result.version is None
    assert result.failure_kind is ExecutableVersionProbeStatus.INVALID_VERSION
    assert environment_canary not in (result.diagnostic or "")
    assert (
        next(private.glob("version-probe-*/stdout.txt")).read_text(encoding="utf-8").strip()
        == raw_version
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX no-follow private-artifact attestation")
def test_version_probe_rejects_symlink_replacement_without_reading_host_canary(
    tmp_path: Path,
) -> None:
    host_canary = tmp_path / "host-version-canary.txt"
    canary_text = "SYNTHETIC_HOST_VERSION_CANARY_9.9.9"
    host_canary.write_text(canary_text, encoding="utf-8")
    private = tmp_path / "private-version-symlink"
    executable = tmp_path / "symlink-replacing-version-tool"
    executable.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "from pathlib import Path",
                f"probe = next(Path({str(private)!r}).glob('version-probe-*'))",
                "stdout_path = probe / 'stdout.txt'",
                "stdout_path.unlink()",
                f"stdout_path.symlink_to(Path({str(host_canary)!r}))",
                "",
            )
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)

    result = preflight_scanner_executable(
        executable,
        sanitized_scanner_environment(private),
        _PassthroughIsolation(),
        tmp_path,
        private,
    )

    assert result.state is ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE
    assert result.failure_kind is ExecutableVersionProbeStatus.ISOLATION_FAILURE
    assert result.version is None
    assert result.diagnostic == ("private tool-version evidence identity changed and was rejected")
    assert canary_text not in (result.diagnostic or "")
    replaced_path = next(private.glob("version-probe-*/stdout.txt"))
    assert replaced_path.is_symlink()
    assert os.readlink(replaced_path) == str(host_canary)
    assert host_canary.read_text(encoding="utf-8") == canary_text


@pytest.mark.parametrize(
    "version",
    [
        "tool 1.2.3\nprivate prefix",
        "tool 1.2.3\x00",
        "tool 1.2.3 at /Users/synthetic-operator/anaconda3/bin/python",
        "tool 1.2.3 built-from-/Users/synthetic-operator/anaconda3/bin/python",
        "tool 1.2.3,-/Users/synthetic-operator/anaconda3/bin/python",
        "tool 1.2.3 at C:\\Users\\synthetic-operator\\python.exe",
        "tool 1.2.3 environment=SYNTHETIC_ENVIRONMENT_VALUE_CANARY",
        "tool 1.2.3/",
        "tool 1.2.3=",
        "x" * 257,
    ],
)
def test_scanner_run_schema_rejects_unsafe_public_versions(version: str) -> None:
    now = datetime.now(UTC)

    with pytest.raises(ValueError, match="bounded path-free single-line"):
        ScannerRun(
            scanner="synthetic",
            status=ScannerStatus.UNAVAILABLE,
            version=version,
            started_at=now,
            finished_at=now,
            duration_seconds=0,
        )


@pytest.mark.parametrize(
    ("model", "payload", "field"),
    [
        (InvariantExecutionCandidateProvenance, {"compiler_version": "unsafe"}, "compiler_version"),
        (RepositorySuiteInventoryEvidence, {"tool_version": "unsafe"}, "tool_version"),
        (
            RepositorySuiteInventoryEvidence,
            {"compiler_version": "unsafe"},
            "compiler_version",
        ),
        (HardhatReporterInventory, {"reporter_version": "unsafe"}, "reporter_version"),
        (HardhatReporterExecution, {"reporter_version": "unsafe"}, "reporter_version"),
        (RepositorySuiteExecutionPolicy, {"tool_version": "unsafe"}, "tool_version"),
        (
            RepositorySuiteExecutionPolicy,
            {"compiler_version": "unsafe"},
            "compiler_version",
        ),
        (RepositoryTestExecution, {"compiler_version": "unsafe"}, "compiler_version"),
        (
            RepositoryCleanStateAttestationEvidence,
            {"configured_tool_version": "unsafe"},
            "configured_tool_version",
        ),
        (
            RepositoryCleanStateAttestationEvidence,
            {"observed_tool_version": "unsafe"},
            "observed_tool_version",
        ),
        (ScannerRun, {"version": "unsafe"}, "version"),
        (SolidityCompilationResult, {"tool_versions": {"forge": "unsafe"}}, "tool_versions"),
        (InvariantExecutionResult, {"compiler_version": "unsafe"}, "compiler_version"),
        (FormalDependencyProvenance, {"version": "unsafe"}, "version"),
        (FormalToolRun, {"version": "unsafe"}, "version"),
        (
            AuditedSuiteStatementCoverageEvidence,
            {"producer_version": "unsafe"},
            "producer_version",
        ),
        (
            AuditedSuiteStatementCoverageEvidence,
            {"tool_version": "unsafe"},
            "tool_version",
        ),
    ],
)
def test_all_runtime_tool_version_evidence_schemas_reject_host_paths(
    model,
    payload: dict[str, object],
    field: str,
) -> None:
    unsafe_version = "tool 1.2.3 at /Users/SYNTHETIC-OPERATOR/private/tool"
    invalid_payload = {
        key: (
            {name: unsafe_version for name in value} if isinstance(value, dict) else unsafe_version
        )
        for key, value in payload.items()
    }

    with pytest.raises(ValidationError) as exc_info:
        model.model_validate(invalid_payload)

    assert any(
        error["loc"] == (field,) and "bounded path-free single-line" in str(error["msg"])
        for error in exc_info.value.errors()
    )


def test_scanner_fails_closed_without_hardened_isolation(tmp_path: Path) -> None:
    scanner = _SyntheticProcessScanner("print('{}')")
    result = scanner.run(tmp_path, tmp_path / "private-no-isolation", 2)
    assert result.status is ScannerStatus.UNAVAILABLE
    assert "isolation" in (result.error or "")


def test_scanner_trust_pin_mismatch_blocks_target_execution(tmp_path: Path) -> None:
    marker = tmp_path / "target-executed"
    scanner = _SyntheticProcessScanner(
        f"from pathlib import Path; Path({str(marker)!r}).write_text('executed')"
    )

    result = scanner.run(
        tmp_path,
        tmp_path / ".mmaudit" / "private-trust-mismatch",
        2,
        backend=_PassthroughIsolation(),
        expected_version="0.0.0",
        expected_sha256="0" * 64,
    )

    assert result.status is ScannerStatus.FAILED
    assert "trust pin" in (result.error or "")
    assert not marker.exists()


def test_scanner_trust_pin_selects_one_version_line_from_private_multiline_output() -> None:
    version = "forge Version: 1.3.2-stable\nCommit SHA: synthetic\nBuild Timestamp: synthetic"
    expected = version

    assert (
        scanner_trust_pin_error(
            version=version,
            executable_sha256="a" * 64,
            expected_version=expected,
            expected_sha256="a" * 64,
        )
        is None
    )


def test_injected_scanner_backend_cannot_self_assert_real(tmp_path: Path) -> None:
    scanner = _SyntheticProcessScanner("print('{}')")

    result = scanner.run(
        tmp_path,
        tmp_path / ".mmaudit" / "private-self-asserted",
        2,
        backend=_SelfAssertedRealIsolation(),
    )

    assert result.status is ScannerStatus.SUCCESS
    assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert result.isolation_backend == "sandbox-exec"


def test_slither_on_hardhat_blocks_before_host_tool_or_repository_code_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "hardhat-isolation"
    shutil.copytree(FIXTURES / "solidity" / "hardhat_isolation", root)
    scanner = SlitherScanner()
    monkeypatch.setattr(
        scanner,
        "available",
        lambda: pytest.fail("host Slither must not be resolved for a Hardhat repository"),
    )
    monkeypatch.setattr(
        "mmaudit.scanners.base.subprocess.Popen",
        lambda *args, **kwargs: pytest.fail("repository configuration must not execute"),
    )

    result = scanner.run(
        root,
        tmp_path / "private-slither-blocked",
        2,
        backend=_PassthroughIsolation(),
    )

    assert result.status is ScannerStatus.UNAVAILABLE
    assert result.repository_code_execution is RepositoryCodeExecutionState.BLOCKED
    assert result.isolation_backend == "test-isolation"
    assert "off-host" in (result.error or "")
    assert not (root / "repository-config-executed.marker").exists()
    restored = ScannerRun.model_validate_json(result.model_dump_json())
    assert restored.repository_code_execution is RepositoryCodeExecutionState.BLOCKED


def test_slither_on_hardhat_uses_mocked_off_host_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "hardhat-isolation"
    shutil.copytree(FIXTURES / "solidity" / "hardhat_isolation", root)
    scanner = SlitherScanner()
    monkeypatch.setattr(
        scanner,
        "available",
        lambda: pytest.fail("host Slither must not be resolved for a Hardhat repository"),
    )
    backend = _MockRepositoryJavaScriptIsolation()

    result = scanner.run(
        root,
        tmp_path / "private-slither-isolated",
        2,
        backend=backend,
    )

    assert result.status is ScannerStatus.SUCCESS
    assert result.repository_code_execution is RepositoryCodeExecutionState.ISOLATED
    assert result.isolation_backend == backend.name
    assert result.version == "synthetic slither 1.0"
    assert backend.commands[0][0] == "slither"
    assert backend.commands[1] == ["slither", "--version"]
    assert backend.cleanup_calls == 2
    assert not (root / "repository-config-executed.marker").exists()
    restored = ScannerRun.model_validate_json(result.model_dump_json())
    assert restored.repository_code_execution is RepositoryCodeExecutionState.ISOLATED


def test_scanner_rejects_repository_local_binary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    executable = fake_bin / "fake-scanner"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    scanner = _SyntheticProcessScanner("print('{}')")
    scanner.executable = "fake-scanner"

    result = scanner.run(
        tmp_path,
        tmp_path / "private-local-binary",
        2,
        backend=_PassthroughIsolation(),
    )

    assert result.status is ScannerStatus.FAILED
    assert "inside audited repository" in (result.error or "")


def test_scanner_rejects_included_symlink_before_execution(
    tmp_path: Path,
) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.sol"
    outside.write_text("contract Outside {}", encoding="utf-8")
    (tmp_path / "Escape.sol").symlink_to(outside)

    result = _SyntheticProcessScanner("print('{}')").run(
        tmp_path,
        tmp_path / "private-symlink",
        2,
        backend=_PassthroughIsolation(),
    )

    assert result.status is ScannerStatus.FAILED
    assert "workspace" in (result.error or "")


def test_scanner_workspace_withholds_environment_files(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("PRIVATE_KEY=synthetic\n", encoding="utf-8")
    (tmp_path / "id_rsa").write_text("synthetic ssh key\n", encoding="utf-8")
    (tmp_path / "mnemonic.txt").write_text("synthetic seed phrase\n", encoding="utf-8")
    (tmp_path / "wallet.json").write_text("synthetic wallet\n", encoding="utf-8")
    (tmp_path / ".ENV.PROD").write_text("PRIVATE_KEY=synthetic\n", encoding="utf-8")
    (tmp_path / "WALLET.PEM").write_text("synthetic pem\n", encoding="utf-8")
    (tmp_path / "ID_ED25519").write_text("synthetic ssh key\n", encoding="utf-8")
    scanner = _SyntheticProcessScanner(
        "import pathlib; "
        "print(any(pathlib.Path(name).exists() for name in "
        "('.env', 'id_rsa', 'mnemonic.txt', 'wallet.json', "
        "'.ENV.PROD', 'WALLET.PEM', 'ID_ED25519')))"
    )
    private = tmp_path / ".mmaudit" / "private-env"

    result = scanner.run(
        tmp_path,
        private,
        2,
        backend=_PassthroughIsolation(),
    )

    assert result.status is ScannerStatus.SUCCESS
    assert (
        result.executable_sha256
        == hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest()
    )
    assert (private / "synthetic.json").read_text(encoding="utf-8").strip() == "False"


def test_real_subprocess_timeout_is_bounded(tmp_path: Path) -> None:
    scanner = _SyntheticProcessScanner("import time; time.sleep(2)")
    result = scanner.run(
        tmp_path,
        tmp_path / ".mmaudit" / "private-timeout",
        0.05,
        backend=_PassthroughIsolation(),
    )
    assert result.status is ScannerStatus.TIMED_OUT


def test_real_subprocess_output_is_bounded(tmp_path: Path) -> None:
    scanner = _SyntheticProcessScanner("print('x' * 10000)", output_limit=100)
    result = scanner.run(
        tmp_path,
        tmp_path / ".mmaudit" / "private-output",
        2,
        backend=_PassthroughIsolation(),
    )
    assert result.status is ScannerStatus.FAILED
    assert "output" in (result.error or "")


def test_poisoned_scanner_shape_becomes_failed_result(tmp_path: Path, monkeypatch) -> None:
    scanner = _SyntheticProcessScanner("print('[]')")

    def invalid_parse(root: Path, stdout: str, private_dir: Path):
        del root, stdout, private_dir
        raise AttributeError("synthetic poisoned shape")

    monkeypatch.setattr(scanner, "parse", invalid_parse)
    result = scanner.run(
        tmp_path,
        tmp_path / ".mmaudit" / "private-invalid",
        2,
        backend=_PassthroughIsolation(),
    )
    assert result.status is ScannerStatus.FAILED
    assert result.error == "invalid scanner output: AttributeError"


def test_authorization_header_redaction() -> None:
    result = safe_headers(
        {
            "Authorization": "Bearer secret",
            "X-Api-Key": "secret",
            "Content-Type": "application/json",
        }
    )
    assert result["Authorization"] == "[REDACTED]"
    assert result["X-Api-Key"] == "[REDACTED]"
    assert result["Content-Type"] == "application/json"


def _finding(status: FindingStatus = FindingStatus.CONFIRMED) -> Finding:
    return Finding(
        id="MMA-ABCDEF123456",
        title="Synthetic <script>alert(1)</script> SQL injection",
        status=status,
        severity=Severity.HIGH,
        confidence=0.91,
        cwe=["CWE-89"],
        owasp=["A03:2021"],
        summary="Synthetic query interpolation.",
        impact="Synthetic records could be read.",
        preconditions=["Can invoke local fixture"],
        locations=[
            Location(
                path="app.py",
                start_line=11,
                end_line=14,
                symbol="search_users",
            )
        ],
        attack_path=["Submit metacharacters", "Reach local fake query"],
        evidence=[]
        if status is FindingStatus.REJECTED
        else [
            {
                "type": "scanner",
                "source": "semgrep",
                "description": "formatted query",
                "rule_id": "sql-injection",
            }
        ],
        false_positive_conditions=["Driver neutralizes syntax"],
        recommendation="Use parameters.",
        verification_test=VerificationTest(
            description="Run against an in-memory synthetic database"
        ),
        location_validation=LocationValidation(
            valid=True,
            content_hash="abc123",
        ),
    )


def _report(findings: list[Finding]) -> AuditReport:
    now = datetime.now(UTC)
    return AuditReport(
        schema_version="1.0",
        run_id="run-test",
        generated_at=now,
        completed=True,
        incomplete_reasons=[],
        repository=RepositoryMap(
            root_name="fixture",
            languages={"Python": 1},
            frameworks=[],
            manifests=[],
            entry_points=[],
            api_surfaces=["app.py"],
            auth_components=[],
            data_layers=[],
            network_clients=[],
            file_handlers=[],
            configuration_files=[],
            sensitive_processing=[],
            security_tests=[],
            files=[],
        ),
        configuration_hash="config-hash",
        model_configuration_hash="model-hash",
        privacy={
            "code_egress_enabled": True,
            "require_zdr": True,
            "redact_secrets": True,
            "store_raw_prompts": False,
            "store_raw_responses": False,
        },
        scanner_runs=[
            ScannerRun(
                scanner="semgrep",
                status=ScannerStatus.SUCCESS,
                version="1.0",
                started_at=now,
                finished_at=now,
                duration_seconds=0,
            )
        ],
        usage=[],
        budget_usd=20,
        accounted_cost_usd=0,
        findings=findings,
        rejected_findings=[],
        metadata={"configured_models": {}},
    )


def test_anaconda_interpreter_failure_is_typed_private_and_absent_from_public_artifacts(
    tmp_path: Path,
) -> None:
    host_path_canary = "/Users/SYNTHETIC-OPERATOR/anaconda3/bin/python3.11"
    environment_canary = "SYNTHETIC_ENVIRONMENT_VALUE_CANARY"
    raw_failure = "\n".join(
        (
            "Could not find platform independent libraries <prefix>",
            "Python path configuration:",
            "  PYTHONHOME = (not set)",
            f"  sys._base_executable = '{host_path_canary}'",
            "  sys.base_prefix = '/Users/SYNTHETIC-OPERATOR/anaconda3'",
            "  sys.path = ['/Users/SYNTHETIC-OPERATOR/anaconda3/lib/python3.11']",
            f"  environment canary = '{environment_canary}'",
            "Fatal Python error: init_fs_encoding: failed to get the Python codec",
            "",
        )
    )
    root = tmp_path / "repository"
    root.mkdir()
    (root / "contract.sol").write_text("contract Synthetic {}\n", encoding="utf-8")
    executable = tmp_path / "trusted-bin" / "synthetic-scanner"
    executable.parent.mkdir()
    marker = tmp_path / "target-command-ran"
    executable.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import pathlib",
                "import sys",
                'if "--version" in sys.argv:',
                f"    sys.stderr.write({raw_failure!r})",
                "    raise SystemExit(1)",
                f"pathlib.Path({str(marker)!r}).write_text('executed')",
                "print('{}')",
                "",
            )
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    scanner = _SyntheticProcessScanner("print('{}')")
    scanner.executable = str(executable)
    private = tmp_path / "private-anaconda-failure"

    run = scanner.run(root, private, 2, backend=_PassthroughIsolation())

    assert run.status is ScannerStatus.INTERPRETER_OR_LOADER_FAILURE
    assert run.version is None
    assert run.error is not None
    assert "self-contained tool distribution" in run.error
    assert "pipx or Homebrew" in run.error
    assert run.command == []
    assert run.process_exit_code is None
    assert run.raw_output_path is None
    assert not marker.exists()
    probe_directories = list(private.glob("version-probe-*"))
    assert len(probe_directories) == 1
    assert probe_directories[0].stat().st_mode & 0o777 == 0o700
    private_stderr = probe_directories[0] / "stderr.txt"
    assert private_stderr.stat().st_mode & 0o777 == 0o600
    assert private_stderr.read_text(encoding="utf-8") == raw_failure

    report = _report([]).model_copy(update={"scanner_runs": [run]})
    scanner_results = stable_json({"schema_version": "1.2", "runs": [run.model_dump(mode="json")]})
    final_report = stable_json(report)
    markdown = render_markdown(report)
    sarif = stable_json(
        generate_sarif(
            report.findings,
            run_status=AuditRunStatus.INCOMPLETE,
            quality_status=AuditQualityStatus.INCOMPLETE,
            completed=False,
            incomplete_reasons=[run.error],
        )
    )
    for public_artifact in (scanner_results, final_report, markdown, sarif):
        assert raw_failure not in public_artifact
        assert host_path_canary not in public_artifact
        assert "/Users/SYNTHETIC-OPERATOR/anaconda3" not in public_artifact
        assert "PYTHONHOME" not in public_artifact
        assert "sys.path" not in public_artifact
        assert environment_canary not in public_artifact


def test_markdown_exposes_model_coverage_applicability_classification_and_limitations() -> None:
    missing = CoverageMetric(
        numerator=0,
        denominator=0,
        population=0,
        percentage=None,
        exclusions=[],
        not_applicable_evidence=[],
        confidence=1,
        provenance=[CoverageProvenance.MODEL_REVIEW],
        failures=["critical classification evidence was incomplete"],
        state=AnalysisState.NOT_ANALYZED,
        detail="Synthetic fail-closed model-review coverage.",
    )
    model_coverage = ModelReviewCoverage(
        applicable=False,
        critical_classification_complete=False,
        surfaces=[],
        overall=missing,
        by_kind={kind: missing for kind in ModelReviewSurfaceKind},
        critical=missing,
        critical_gate_passed=False,
        limitations=[
            "audited-suite critical classification was incomplete",
        ],
    )
    report = _report([]).model_copy(update={"model_review_coverage": model_coverage})

    rendered = render_markdown(report)

    assert "- Coverage applicable: False" in rendered
    assert "- Critical-surface classification complete: False" in rendered
    assert "Model-review coverage limitations:" in rendered
    assert "audited-suite critical classification was incomplete" in rendered


def test_markdown_distinguishes_status_and_escapes_html() -> None:
    confirmed = _finding()
    needs_review = _finding(FindingStatus.NEEDS_REVIEW).model_copy(
        update={"id": "MMA-REVIEW000001"}
    )
    rendered = render_markdown(_report([confirmed, needs_review]))
    assert "Confirmed finding" in rendered
    assert "Needs human review — not established as fact" in rendered
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered


def test_markdown_uses_corrovera_report_identity() -> None:
    rendered = render_markdown(_report([_finding()]))
    assert rendered.startswith("# Corrovera Security Assurance Report")
    assert "*Independent minds. Corroborated truth.*" in rendered
    assert "Generated by `mmaudit` · `corrovera.ai`" in rendered


@pytest.mark.parametrize(
    ("run_status", "quality_status"),
    [
        (AuditRunStatus.INCOMPLETE, AuditQualityStatus.INCOMPLETE),
        (AuditRunStatus.FAILED, AuditQualityStatus.FAILED),
    ],
)
def test_markdown_does_not_present_incomplete_empty_run_as_safe(
    run_status: AuditRunStatus,
    quality_status: AuditQualityStatus,
) -> None:
    source_ingestion_succeeded = run_status is not AuditRunStatus.FAILED
    minimum_floor = MinimumAnalysisFloor(
        run_status=run_status,
        source_files_ingested=int(source_ingestion_succeeded),
        source_ingestion_succeeded=source_ingestion_succeeded,
        solidity_applicable=False,
        compilation_satisfied=True,
        qualifying_compilations=0,
        static_analysis_applicable=True,
        static_analysis_satisfied=False,
        model_review_required=False,
        scanner_only=True,
        model_review_satisfied=True,
        coverage_metric_ids=[],
        coverage_denominators_valid=False,
        surface_analysis_feasible=True,
        minimum_floor_met=False,
        limitations=["no real scanner or model review completed"],
    )
    payload = _report([]).model_dump(mode="python")
    payload.update(
        {
            "schema_version": "1.2",
            "run_status": run_status,
            "minimum_analysis_floor": minimum_floor,
            "quality_gates": [minimum_analysis_floor_quality_gate(minimum_floor)],
            "quality_status": quality_status,
            "completed": False,
            "incomplete_reasons": ["no real scanner or model review completed"],
            "repository": _report([]).repository.model_copy(
                update={
                    "files": (
                        [
                            RepositoryFile(
                                path="app.py",
                                size=20,
                                lines=1,
                                sha256="a" * 64,
                                language="Python",
                            )
                        ]
                        if source_ingestion_succeeded
                        else []
                    )
                }
            ),
            "metadata": {
                "scanner_only": True,
                "solidity": {"projects": [], "compilation": []},
            },
        }
    )
    report = AuditReport.model_validate(payload)

    rendered = render_markdown(report)
    executive_summary = rendered.split("## Status semantics", maxsplit=1)[0]
    required_summary = (
        "No reportable findings were identified by the analyses that completed. "
        "This run is incomplete and does not support a conclusion about repository safety."
    )

    assert f"## Executive summary\n\n{required_summary}\n\n" in executive_summary
    assert f"> **RUN STATUS: {run_status.value}**" in executive_summary
    assert "The audit produced **0 surviving finding(s)**" not in executive_summary


def test_markdown_does_not_present_degraded_empty_run_as_safe() -> None:
    report = _report([]).model_copy(
        update={
            "quality_status": AuditQualityStatus.COMPLETED_WITH_LIMITATIONS,
            "incomplete_reasons": ["operator authorized a reduced analysis profile"],
        }
    )

    rendered = render_markdown(report)
    executive_summary = rendered.split("## Status semantics", maxsplit=1)[0]

    assert "> **RUN STATUS: DEGRADED**" in executive_summary
    assert (
        "This run is incomplete and does not support a conclusion about repository safety."
        in executive_summary
    )
    assert "The audit produced **0 surviving finding(s)**" not in executive_summary


def test_markdown_labels_consent_free_synthetic_zdr_policy_accurately() -> None:
    policy_payload = {
        "schema_version": "1.0",
        "privacy_profile": PrivacyProfile.SYNTHETIC_BENCHMARK,
        "source_classification": PrivacySourceClassification.SYNTHETIC_COMMITTED,
        "source_sha256": "b" * 64,
        "source_provenance_sha256": "c" * 64,
        "source_proof_kind": "PACKAGE_PINNED_SYNTHETIC",
        "source_distribution_commit": None,
        "source_distribution_scope": "tests/fixtures/synthetic",
        "source_synthetic_declaration_sha256": "d" * 64,
        "source_synthetic_declaration_entry_sha256": "e" * 64,
        "require_zdr": True,
        "data_collection": "deny",
        "permitted_model_ids": ("example/model",),
        "permitted_provider_endpoints": ("example-provider",),
        "endpoint_policy_classes": (EndpointPolicyClass.ZDR,),
        "endpoint_disclosures": (),
        "consent_file_sha256": None,
        "consent_file_size": None,
        "consent_sha256": None,
        "consent_issued_at": None,
        "consent_expires_at": None,
        "operator_reference_sha256": None,
        "consent_maximum_cost_usd": None,
        "requested_budget_usd": "1",
        "limitations": (
            "Synthetic or public benchmark source uses ZDR without retention consent.",
        ),
    }
    policy = EffectivePrivacyPolicyEvidence.model_validate(
        {
            **policy_payload,
            "evidence_sha256": hashlib.sha256(
                json.dumps(
                    policy_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest(),
        }
    )
    report_payload = _report([_finding()]).model_dump(mode="python")
    report_payload["privacy"] = {
        **report_payload["privacy"],
        "profile": PrivacyProfile.SYNTHETIC_BENCHMARK.value,
        "effective_policy": policy.model_dump(mode="json"),
    }
    report = AuditReport.model_validate(report_payload)

    rendered = render_markdown(report)

    assert (
        "Retention consent: not applicable to ZDR-enforced synthetic benchmark source" in rendered
    )
    assert "Retention consent: not applicable under STRICT_ZDR" not in rendered


def test_audit_report_rejects_conflicting_typed_and_legacy_solidity_coverage() -> None:
    payload = _report([]).model_dump(mode="python")
    payload["solidity_coverage"] = SolidityCoverage(projects_discovered=2)
    payload["metadata"] = {
        "solidity": {
            "coverage": {
                "projects_discovered": 1,
            }
        }
    }

    with pytest.raises(
        ValueError,
        match=r"typed solidity_coverage conflicts with legacy metadata\.solidity\.coverage",
    ):
        AuditReport.model_validate(payload)


def test_markdown_prefers_typed_solidity_coverage_when_legacy_copy_matches() -> None:
    typed_coverage = SolidityCoverage(projects_discovered=7, contracts_indexed=5)
    payload = _report([]).model_dump(mode="python")
    payload["solidity_coverage"] = typed_coverage
    payload["metadata"] = {
        "solidity": {
            "coverage": {
                "projects_discovered": 7,
                "contracts_indexed": 5,
            }
        }
    }
    report = AuditReport.model_validate(payload)

    assert report.effective_solidity_coverage() is report.solidity_coverage
    assert "- Projects discovered: 7" in render_markdown(report)


def test_markdown_bounds_exact_audited_suite_gaps_and_keeps_them_out_of_sarif(
    tmp_path: Path,
) -> None:
    surfaces: list[AuditedSuiteSurfaceCoverage] = []
    gaps: list[AuditedSuiteCoverageGap] = []
    for index in range(21):
        entity_id = f"function:Vault{index:03d}.withdraw"
        location = Location(
            path=f"src/Vault{index:03d}.sol",
            start_line=10 + index,
            end_line=11 + index,
            symbol="withdraw(uint256)",
            content_hash=hashlib.sha256(entity_id.encode()).hexdigest(),
        )
        surfaces.append(
            AuditedSuiteSurfaceCoverage(
                entity_id=entity_id,
                entity_kind=SolidityEntityKind.FUNCTION,
                contract_name=f"Vault{index:03d}",
                location=location,
                critical=True,
                statement_status=AuditedSuiteStatementStatus.NOT_ANALYZED,
                assertion_status=AuditedSuiteAssertionStatus.NOT_ANALYZED,
            )
        )
        kind = AuditedSuiteCoverageGapKind.ASSERTION_NOT_ANALYZED
        gaps.append(
            AuditedSuiteCoverageGap(
                gap_id=AuditedSuiteCoverageGap.calculate_gap_id(entity_id, kind),
                entity_id=entity_id,
                entity_kind=SolidityEntityKind.FUNCTION,
                location=location,
                kind=kind,
                assertion_status=AuditedSuiteAssertionStatus.NOT_ANALYZED,
                detail="No repository-owned assertion-strength result covers this exact surface.",
            )
        )
    gap_metric = CoverageMetric(
        numerator=0,
        denominator=len(surfaces),
        population=len(surfaces),
        percentage=0,
        exclusions=[],
        not_applicable_evidence=[],
        confidence=1,
        provenance=[CoverageProvenance.RUNTIME],
        failures=["critical audited-source surfaces lack assertion evidence"],
        state=AnalysisState.NOT_ANALYZED,
        detail="Synthetic bounded-report audited-suite metric.",
    )
    contract_metric = CoverageMetric(
        numerator=0,
        denominator=0,
        population=0,
        percentage=None,
        exclusions=[],
        not_applicable_evidence=["no contract surface is in this focused report fixture"],
        confidence=1,
        provenance=[CoverageProvenance.RUNTIME],
        failures=[],
        state=AnalysisState.NOT_ANALYZED,
        detail="Synthetic empty contract metric.",
    )
    audited_suite = AuditedSuiteCoverage(
        contract_statement_coverage=contract_metric,
        function_statement_coverage=gap_metric,
        critical_function_assertion_coverage=gap_metric,
        surfaces=surfaces,
        gaps=gaps,
        repository_tests_selected=5,
        repository_tests_executed=4,
        repository_tests_failed=1,
        source_classification_complete=True,
        critical_classification_complete=True,
    )
    coverage = SolidityCoverage(
        tests_executed=4,
        tests_failed=1,
        audited_suite_coverage=audited_suite,
        quality_metrics={
            "audited_suite_contract_statement_coverage": contract_metric,
            "audited_suite_function_statement_coverage": gap_metric,
            "audited_suite_critical_function_assertion_coverage": gap_metric,
        },
    )
    report = _report([]).model_copy(update={"solidity_coverage": coverage})

    rendered = render_markdown(report)
    rendered_gaps = sorted(gaps, key=lambda gap: gap.gap_id)[:20]
    omitted_gap = sorted(gaps, key=lambda gap: gap.gap_id)[20]
    first = rendered_gaps[0]

    assert "Audited-suite coverage gaps — not vulnerability findings" in rendered
    assert "never populate finding or SARIF results" in rendered
    assert rendered.count("audited-suite-gap:") == 20
    assert (
        f"`{first.location.path}`:{first.location.start_line}-{first.location.end_line}" in rendered
    )
    assert f"`{first.location.symbol}`" in rendered
    assert f"`{first.location.content_hash}`" in rendered
    assert omitted_gap.gap_id not in rendered
    assert "1 additional audited-suite coverage gap record(s)" in rendered
    assert report.findings == []
    sarif = generate_sarif(report.findings)
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
    assert sarif["runs"][0]["results"] == []

    assert report.solidity_coverage is not None
    assert report.solidity_coverage.audited_suite_coverage is not None
    tampered_gap = report.solidity_coverage.audited_suite_coverage.gaps[0]
    object.__setattr__(
        tampered_gap,
        "location",
        tampered_gap.location.model_copy(update={"content_hash": "f" * 64}),
    )
    with pytest.raises(ValueError, match="gap identity differs"):
        render_markdown(report)
    with pytest.raises(ValueError, match="gap identity differs"):
        stable_json(report)
    invalid_json = tmp_path / "invalid-final-findings.json"
    with pytest.raises(ValueError, match="gap identity differs"):
        write_json(invalid_json, report)
    assert not invalid_json.exists()


def test_markdown_falls_back_to_valid_legacy_solidity_coverage() -> None:
    payload = _report([]).model_dump(mode="python")
    payload["metadata"] = {
        "solidity": {
            "coverage": {
                "projects_discovered": 3,
                "contracts_indexed": 2,
            }
        }
    }
    report = AuditReport.model_validate(payload)

    assert report.solidity_coverage is None
    assert report.effective_solidity_coverage() == SolidityCoverage(
        projects_discovered=3,
        contracts_indexed=2,
    )
    assert "- Projects discovered: 3" in render_markdown(report)


def test_markdown_always_explains_all_status_categories() -> None:
    rendered = render_markdown(_report([_finding()]))
    for status in ("Confirmed:", "High-confidence:", "Needs review:", "Rejected:"):
        assert status in rendered


def test_markdown_serializes_repository_code_isolation_evidence() -> None:
    base_report = _report([])
    report = base_report.model_copy(
        update={
            "scanner_runs": [
                base_report.scanner_runs[0].model_copy(
                    update={
                        "isolation_backend": "rootless-container",
                        "repository_code_execution": RepositoryCodeExecutionState.ISOLATED,
                    }
                )
            ],
            "metadata": {
                "configured_models": {},
                "solidity": {
                    "compilation": [
                        {
                            "project_root": ".",
                            "framework": "hardhat",
                            "status": "success",
                            "repository_code_execution": "isolated",
                            "isolation_backend": "rootless-container",
                        }
                    ]
                },
            },
        }
    )

    rendered = render_markdown(report)

    assert "## Solidity compilation isolation" in rendered
    assert "| `.` | hardhat | success | isolated | rootless-container |" in rendered
    assert "| semgrep | success | 1.0 | isolated | rootless-container | 0 |" in rendered


def test_markdown_neutralizes_untrusted_links_and_headings() -> None:
    finding = _finding().model_copy(
        update={"summary": "[load external](https://invalid.example/pixel)\n# injected heading"}
    )
    rendered = render_markdown(_report([finding]))
    assert "](https://invalid.example" not in rendered
    assert "\n# injected heading" not in rendered
    assert "\\[load external\\]\\(https://invalid.example/pixel\\)" in rendered


def test_markdown_reports_invariant_economic_metrics() -> None:
    report = _report([]).model_copy(
        update={
            "invariant_executions": [
                InvariantExecutionResult(
                    invariant_id="inv-erc4626",
                    harness_name="DonationInflation",
                    status=InvariantExecutionStatus.COUNTEREXAMPLE,
                    runs=1,
                    depth=1,
                    economic_template=EconomicSimulationKind.ERC4626_DONATION,
                    economic_metrics=EconomicMetrics(
                        required_initial_capital=2 * 10**18,
                        borrowed_capital=0,
                        maximum_victim_loss=10**18,
                    ),
                )
            ]
        }
    )
    rendered = render_markdown(report)
    assert "Economic metrics" in rendered
    assert "initial capital 2000000000000000000 wei" in rendered
    assert "victim at risk 1000000000000000000 wei" in rendered


def test_markdown_and_json_report_settled_financial_impact() -> None:
    settlement = FinancialSettlementEvidence(
        actor="attacker",
        asset_kind=FinancialAssetKind.NATIVE,
        starting_assets=100,
        borrowed_assets=50,
        repaid_assets=50,
        gross_assets_received=30,
        fees_paid=5,
        slippage_loss=2,
        ending_assets=123,
        net_impact=23,
    )
    reproduction = ReproductionResult(
        candidate_id="candidate-financial",
        test_name="FinancialSettlement",
        state=ReproductionState.REPRODUCED,
        specification_sha256="a" * 64,
        attempts=1,
        successful_attempts=1,
        financial_settlement=settlement,
        financial_settlement_verified=True,
    )
    report = _report([]).model_copy(update={"reproductions": [reproduction]})

    rendered = render_markdown(report)
    assert "Settled financial impact (single-asset base units)" in rendered
    assert (
        "| `candidate-financial` | attacker | native | 100 | 50 | 50 | 30 | 5 | 2 | 123 | 23 | True |"
        in rendered
    )
    encoded = json.loads(stable_json(report))
    serialized = encoded["reproductions"][0]
    assert serialized["financial_settlement_verified"] is True
    assert serialized["financial_settlement"]["net_impact"] == 23


def test_invariant_economic_metrics_report_full_temporary_liquidity_settlement() -> None:
    settlement = FinancialSettlementEvidence(
        actor="attacker",
        asset_kind=FinancialAssetKind.ERC20,
        asset_target="SyntheticAsset",
        starting_assets=100,
        borrowed_assets=1_000,
        repaid_assets=1_000,
        gross_assets_received=35,
        fees_paid=10,
        slippage_loss=5,
        ending_assets=120,
        net_impact=20,
    )
    execution = InvariantExecutionResult(
        invariant_id="inv-temporary-liquidity",
        harness_name="TemporaryLiquiditySettlement",
        status=InvariantExecutionStatus.PASSED,
        runs=8,
        depth=1,
        economic_template=EconomicSimulationKind.FLASH_ORACLE,
        economic_metrics=EconomicMetrics(
            required_initial_capital=100,
            borrowed_capital=1_000,
            gross_extraction=35,
            fees=10,
            net_profit_or_loss=20,
            financial_settlement=settlement,
        ),
    )
    report = _report([]).model_copy(update={"invariant_executions": [execution]})

    rendered = render_markdown(report)
    assert "initial capital 100 base units" in rendered
    assert "borrowed 1000 base units" in rendered
    assert "repaid 1000 base units" in rendered
    assert "fees 10 base units" in rendered
    assert "slippage 5 base units" in rendered
    assert "ending 120 base units" in rendered
    encoded = json.loads(stable_json(report))
    metrics = encoded["invariant_executions"][0]["economic_metrics"]
    assert metrics["financial_settlement"]["repaid_assets"] == 1_000
    assert metrics["financial_settlement"]["net_impact"] == 20


def test_invariant_report_serializes_liquidation_boundary_and_settlement() -> None:
    settlement = FinancialSettlementEvidence(
        actor="attacker",
        asset_kind=FinancialAssetKind.ERC20,
        asset_target="SyntheticCollateral",
        starting_assets=10,
        borrowed_assets=0,
        repaid_assets=0,
        gross_assets_received=150,
        fees_paid=0,
        slippage_loss=0,
        ending_assets=160,
        net_impact=150,
    )
    boundary = LendingBoundaryEvidence(
        debt_before=100,
        collateral_before=150,
        debt_after=100,
        collateral_after=0,
        collateral_seized=150,
        bad_debt_after=100,
    )
    execution = InvariantExecutionResult(
        invariant_id="inv-liquidation",
        harness_name="HealthyLiquidationBoundary",
        status=InvariantExecutionStatus.COUNTEREXAMPLE,
        runs=8,
        depth=1,
        economic_template=EconomicSimulationKind.LIQUIDATION,
        economic_metrics=EconomicMetrics(
            required_initial_capital=10,
            borrowed_capital=0,
            gross_extraction=150,
            net_profit_or_loss=150,
            maximum_victim_loss=150,
            protocol_insolvency=100,
            financial_settlement=settlement,
            lending_boundary=boundary,
        ),
    )
    report = _report([]).model_copy(update={"invariant_executions": [execution]})

    rendered = render_markdown(report)
    assert "debt 100-&gt;100 base units" in rendered
    assert "collateral 150-&gt;0 base units" in rendered
    assert "collateral seized 150 base units" in rendered
    assert "bad debt 100 base units" in rendered
    encoded = json.loads(stable_json(report))
    metrics = encoded["invariant_executions"][0]["economic_metrics"]
    assert metrics["lending_boundary"]["debt_before"] == 100
    assert metrics["lending_boundary"]["collateral_before"] == 150
    assert metrics["lending_boundary"]["bad_debt_after"] == 100
    assert metrics["financial_settlement"]["net_impact"] == 150


def test_invariant_report_serializes_share_rate_boundary_and_settlement() -> None:
    settlement = FinancialSettlementEvidence(
        actor="attacker",
        asset_kind=FinancialAssetKind.ERC20,
        asset_target="SyntheticAsset",
        starting_assets=100,
        borrowed_assets=0,
        repaid_assets=0,
        gross_assets_received=150,
        fees_paid=0,
        slippage_loss=0,
        ending_assets=250,
        net_impact=150,
    )
    boundary = SharePriceBoundaryEvidence(
        rate_scale=1_000,
        total_assets_before=1_000,
        total_shares_before=1_000,
        legitimate_yield=100,
        expected_rate_after_yield=1_100,
        observed_rate_after=1_500,
        shares_redeemed=100,
        assets_redeemed=150,
        excess_assets=40,
    )
    execution = InvariantExecutionResult(
        invariant_id="inv-share-rate",
        harness_name="YieldAdjustedShareRate",
        status=InvariantExecutionStatus.COUNTEREXAMPLE,
        runs=8,
        depth=1,
        economic_template=EconomicSimulationKind.SHARE_PRICE,
        economic_metrics=EconomicMetrics(
            required_initial_capital=100,
            borrowed_capital=0,
            gross_extraction=150,
            net_profit_or_loss=150,
            maximum_victim_loss=40,
            financial_settlement=settlement,
            share_price_boundary=boundary,
        ),
    )
    report = _report([]).model_copy(update={"invariant_executions": [execution]})

    rendered = render_markdown(report)
    assert "legitimate yield 100 base units" in rendered
    assert "share rate 1100-&gt;1500 per 1000" in rendered
    assert "shares redeemed 100" in rendered
    assert "assets redeemed 150 base units" in rendered
    assert "excess assets 40 base units" in rendered
    encoded = json.loads(stable_json(report))
    metrics = encoded["invariant_executions"][0]["economic_metrics"]
    assert metrics["share_price_boundary"]["legitimate_yield"] == 100
    assert metrics["share_price_boundary"]["expected_rate_after_yield"] == 1_100
    assert metrics["share_price_boundary"]["observed_rate_after"] == 1_500
    assert metrics["share_price_boundary"]["excess_assets"] == 40
    assert metrics["financial_settlement"]["net_impact"] == 150


def test_invariant_report_serializes_seed_and_minimized_state_sequence() -> None:
    policy = AttackerCapabilityPolicy(
        attacker_controlled_actors=["attacker"],
        transaction_ordering=TransactionOrderingCapability.MULTI_TRANSACTION,
        capability_justifications={
            AttackerCapability.TRANSACTION_ORDERING: (
                "Two ordered synthetic local transactions validate the state transition"
            )
        },
    )
    minimization = InvariantExecutionMinimizationEvidence(
        original_action_ids=["PrepareState", "CommitState"],
        retained_action_ids=["PrepareState", "CommitState"],
        strategy="bounded_action_removal",
        proven_minimal=True,
        foundry_original_sequence_length=2,
        foundry_shrunk_sequence_length=2,
        removal_trials=[
            InvariantExecutionRemovalTrial(
                removed_action_id="PrepareState",
                retained_action_ids=["CommitState"],
                status=InvariantExecutionStatus.PASSED,
                replay_confirmed=True,
                seed=18,
            ),
            InvariantExecutionRemovalTrial(
                removed_action_id="CommitState",
                retained_action_ids=["PrepareState"],
                status=InvariantExecutionStatus.PASSED,
                replay_confirmed=True,
                seed=18,
            ),
        ],
    )
    execution = InvariantExecutionResult(
        invariant_id="inv-state-ordering",
        harness_name="PreparedStateConsumedSequence",
        status=InvariantExecutionStatus.COUNTEREXAMPLE,
        runs=32,
        depth=2,
        seed=18,
        economic_template=EconomicSimulationKind.STATE_ORDERING,
        required_transaction_ordering=TransactionOrderingCapability.MULTI_TRANSACTION,
        capability_policy=policy,
        minimization_evidence=minimization,
    )
    report = _report([]).model_copy(update={"invariant_executions": [execution]})

    rendered = render_markdown(report)
    assert "PrepareState -&gt; CommitState" in rendered
    assert "| 32 | 2 | 18 | multi\\_transaction |" in rendered
    encoded = json.loads(stable_json(report))
    serialized = encoded["invariant_executions"][0]
    assert serialized["seed"] == 18
    assert serialized["economic_template"] == "multi_transaction_state_ordering"
    assert serialized["minimization_evidence"]["retained_action_ids"] == [
        "PrepareState",
        "CommitState",
    ]
    assert len(serialized["minimization_evidence"]["removal_trials"]) == 2


def test_markdown_reports_separate_asset_flow_operations_and_endpoints() -> None:
    report = _report([]).model_copy(
        update={
            "metadata": {
                "configured_models": {},
                "solidity": {
                    "coverage": {
                        "projects_discovered": 1,
                        "asset_flow_operation_counts": {
                            "balance_observation": 2,
                            "claim": 1,
                            "mint": 1,
                        },
                        "asset_flow_direction_counts": {
                            "observation": 2,
                            "sink": 1,
                            "source": 1,
                        },
                        "control_resolution_counts": {
                            "resolved": 3,
                            "unknown": 1,
                        },
                        "governance_stage_counts": {
                            "execute": 2,
                            "queue": 1,
                        },
                        "dependency_resolution_counts": {
                            "source_reference_only": 2,
                        },
                        "oracle_freshness_counts": {
                            "present": 1,
                            "unknown": 1,
                        },
                    }
                },
            }
        }
    )

    rendered = render_markdown(report)
    assert "Asset-flow operations:" in rendered
    assert "balance\\_observation=2" in rendered
    assert "claim=1" in rendered
    assert "mint=1" in rendered
    assert "Asset-flow endpoints:" in rendered
    assert "observation=2" in rendered
    assert "sink=1" in rendered
    assert "source=1" in rendered
    assert "Control resolution: resolved=3, unknown=1" in rendered
    assert "Governance stages: execute=2, queue=1" in rendered
    assert "Dependency references: source\\_reference\\_only=2" in rendered
    assert "Oracle freshness validation: present=1, unknown=1" in rendered


def test_markdown_reports_economic_template_harness_availability() -> None:
    report = _report([]).model_copy(
        update={
            "economic_simulations": [
                EconomicSimulationPlan(
                    kind=EconomicSimulationKind.ERC4626_DONATION,
                    applicable=True,
                    rationale="Synthetic typed template.",
                    typed_harness_available=True,
                    execution_required=True,
                    limitations=["requires pinned local fork targets"],
                ),
                EconomicSimulationPlan(
                    kind=EconomicSimulationKind.FLASH_ORACLE,
                    applicable=True,
                    rationale="Synthetic planning-only template.",
                    typed_harness_available=False,
                    execution_required=True,
                    limitations=["No deterministic typed Foundry harness is implemented"],
                ),
            ]
        }
    )
    rendered = render_markdown(report)
    assert "Typed harness" in rendered
    assert (
        "| erc4626\\_donation\\_inflation | True | True | 0 | not\\_executed | 0 | 0 |" in rendered
    )
    assert (
        "| flash\\_loan\\_oracle\\_manipulation | True | False | 0 | not\\_executed | 0 | 0 |"
    ) in rendered


def test_non_standard_token_counterexample_serializes_as_executed_evidence() -> None:
    plan = EconomicSimulationPlan(
        kind=EconomicSimulationKind.NON_STANDARD_TOKEN,
        applicable=True,
        rationale="Observed-versus-assumed accounting is source-linked.",
        typed_harness_available=True,
        execution_required=True,
    )
    execution = InvariantExecutionResult(
        invariant_id="inv-observed-assets",
        harness_name="ObservedAssetsCoverClaims",
        status=InvariantExecutionStatus.COUNTEREXAMPLE,
        runs=1,
        depth=1,
        seed=1,
        economic_template=EconomicSimulationKind.NON_STANDARD_TOKEN,
        counterexample_summary="A bounded local invariant failed.",
    )
    report = _report([]).model_copy(
        update={
            "economic_simulations": [plan],
            "invariant_executions": [execution],
        }
    )
    rendered = render_markdown(report)
    assert "fee\\_on\\_transfer\\_rebasing\\_accounting" in rendered
    assert "| True | True | 1 | 1 counterexample | 0 | 0 |" in rendered
    encoded = json.loads(stable_json(report))
    assert encoded["invariant_executions"][0]["status"] == "counterexample"
    assert (
        encoded["invariant_executions"][0]["economic_template"]
        == "fee_on_transfer_rebasing_accounting"
    )


def test_rounding_counterexample_and_safe_loss_metrics_serialize() -> None:
    plan = EconomicSimulationPlan(
        kind=EconomicSimulationKind.ROUNDING,
        applicable=True,
        rationale="A bounded round-trip transition contains source-linked integer division.",
        typed_harness_available=True,
        execution_required=True,
    )
    execution = InvariantExecutionResult(
        invariant_id="inv-rounding",
        harness_name="NoRoundTripValueCreation",
        status=InvariantExecutionStatus.COUNTEREXAMPLE,
        runs=16,
        depth=8,
        seed=1,
        economic_template=EconomicSimulationKind.ROUNDING,
        economic_metrics=EconomicMetrics(
            required_initial_capital=1,
            borrowed_capital=0,
            required_privileges=["unprivileged account holder"],
            market_assumptions=["bounded downward-rounding loss is permitted"],
        ),
        counterexample_summary="A bounded local invariant failed.",
    )
    report = _report([]).model_copy(
        update={
            "economic_simulations": [plan],
            "invariant_executions": [execution],
        }
    )

    rendered = render_markdown(report)
    assert "rounding\\_exploitation" in rendered
    assert "| True | True | 1 | 1 counterexample | 0 | 0 |" in rendered
    assert "initial capital 1 wei" in rendered
    encoded = json.loads(stable_json(report))
    assert encoded["invariant_executions"][0]["economic_template"] == "rounding_exploitation"
    assert encoded["invariant_executions"][0]["economic_metrics"]["required_initial_capital"] == 1


def test_oracle_guard_counterexample_and_synthetic_metrics_serialize() -> None:
    plan = EconomicSimulationPlan(
        kind=EconomicSimulationKind.ORACLE_GUARDS,
        applicable=True,
        rationale="A configured source-linked feed transition omits required validation.",
        typed_harness_available=True,
        execution_required=True,
    )
    execution = InvariantExecutionResult(
        invariant_id="inv-oracle-guards",
        harness_name="InvalidFeedIsRejected",
        status=InvariantExecutionStatus.COUNTEREXAMPLE,
        runs=8,
        depth=1,
        seed=1,
        economic_template=EconomicSimulationKind.ORACLE_GUARDS,
        economic_metrics=EconomicMetrics(
            required_initial_capital=0,
            borrowed_capital=0,
            required_privileges=["unprivileged oracle consumer caller"],
            market_assumptions=["feed values are deterministic synthetic presets"],
        ),
        counterexample_summary="A bounded invalid feed preset was accepted.",
    )
    report = _report([]).model_copy(
        update={
            "economic_simulations": [plan],
            "invariant_executions": [execution],
        }
    )

    rendered = render_markdown(report)
    assert "oracle\\_freshness\\_scale\\_availability" in rendered
    assert "| True | True | 1 | 1 counterexample | 0 | 0 |" in rendered
    encoded = json.loads(stable_json(report))
    assert (
        encoded["invariant_executions"][0]["economic_template"]
        == "oracle_freshness_scale_availability"
    )
    assert encoded["invariant_executions"][0]["economic_metrics"]["required_initial_capital"] == 0


def test_governance_counterexample_serializes_declared_rights_and_time_bound() -> None:
    policy = AttackerCapabilityPolicy(
        attacker_controlled_actors=["governor"],
        max_time_shift_seconds=3_600,
        governance_rights=True,
        capability_justifications={
            AttackerCapability.TIMING: "One bounded pre-delay time move.",
            AttackerCapability.GOVERNANCE_RIGHTS: "Synthetic declared governance rights.",
        },
    )
    plan = EconomicSimulationPlan(
        kind=EconomicSimulationKind.GOVERNANCE_RACE,
        applicable=True,
        rationale="A rights-guarded lifecycle omits its execution-delay guard.",
        typed_harness_available=True,
        execution_required=True,
    )
    execution = InvariantExecutionResult(
        invariant_id="inv-governance",
        harness_name="NoExecutionBeforeConfiguredDelay",
        status=InvariantExecutionStatus.COUNTEREXAMPLE,
        runs=8,
        depth=1,
        seed=1,
        economic_template=EconomicSimulationKind.GOVERNANCE_RACE,
        capability_policy=policy,
        economic_metrics=EconomicMetrics(
            required_initial_capital=0,
            borrowed_capital=0,
            required_privileges=["declared governance proposer and voter rights"],
            market_assumptions=["time movement is bounded to 3600 seconds"],
        ),
        counterexample_summary="A bounded early execution changed governance state.",
    )
    report = _report([]).model_copy(
        update={
            "economic_simulations": [plan],
            "invariant_executions": [execution],
        }
    )

    rendered = render_markdown(report)
    assert "governance\\_timelock\\_race" in rendered
    assert "governance\\_rights" in rendered
    assert "time\\_shift&lt;=3600s" in rendered
    encoded = json.loads(stable_json(report))
    encoded_policy = encoded["invariant_executions"][0]["capability_policy"]
    assert encoded_policy["governance_rights"] is True
    assert encoded_policy["max_time_shift_seconds"] == 3_600


def test_upgrade_counterexample_serializes_legitimate_proxy_call_scope() -> None:
    plan = EconomicSimulationPlan(
        kind=EconomicSimulationKind.UPGRADE_INITIALIZER,
        applicable=True,
        rationale="Linked proxy authorization and initializer guards are missing.",
        typed_harness_available=True,
        execution_required=True,
    )
    execution = InvariantExecutionResult(
        invariant_id="inv-upgrade",
        harness_name="OnlyLegitimateProxyTransitions",
        status=InvariantExecutionStatus.COUNTEREXAMPLE,
        runs=8,
        depth=1,
        seed=1,
        economic_template=EconomicSimulationKind.UPGRADE_INITIALIZER,
        economic_metrics=EconomicMetrics(
            required_initial_capital=0,
            borrowed_capital=0,
            required_privileges=["unprivileged proxy caller for negative transitions"],
            market_assumptions=[
                "all transitions use declared proxy ABI calls without direct mutation"
            ],
        ),
        counterexample_summary="A bounded invalid proxy transition was accepted.",
    )
    report = _report([]).model_copy(
        update={
            "economic_simulations": [plan],
            "invariant_executions": [execution],
        }
    )

    rendered = render_markdown(report)
    assert "upgrade\\_initializer\\_misuse" in rendered
    assert "| True | True | 1 | 1 counterexample | 0 | 0 |" in rendered
    encoded = json.loads(stable_json(report))
    assert encoded["invariant_executions"][0]["economic_template"] == "upgrade_initializer_misuse"
    assert (
        "direct mutation"
        in encoded["invariant_executions"][0]["economic_metrics"]["market_assumptions"][0]
    )


def test_cross_chain_counterexample_serializes_offline_message_capability() -> None:
    policy = AttackerCapabilityPolicy(
        attacker_controlled_actors=["messenger"],
        cross_chain_messages=CrossChainMessageCapability.REORDER_VALID_MESSAGES,
        capability_justifications={
            AttackerCapability.CROSS_CHAIN_MESSAGE: (
                "Only fixed fixture-confined offline messages are reordered."
            )
        },
    )
    plan = EconomicSimulationPlan(
        kind=EconomicSimulationKind.CROSS_CHAIN_REPLAY,
        applicable=True,
        rationale="An inbound transition omits replay and ordering guards.",
        typed_harness_available=True,
        execution_required=True,
    )
    execution = InvariantExecutionResult(
        invariant_id="inv-cross-chain",
        harness_name="OnlyNextUnconsumedMessageChangesState",
        status=InvariantExecutionStatus.COUNTEREXAMPLE,
        runs=8,
        depth=1,
        seed=1,
        economic_template=EconomicSimulationKind.CROSS_CHAIN_REPLAY,
        capability_policy=policy,
        economic_metrics=EconomicMetrics(
            required_initial_capital=0,
            borrowed_capital=0,
            required_privileges=["declared synthetic local messenger"],
            market_assumptions=["message values are offline fixture values"],
        ),
        counterexample_summary="A bounded invalid offline message changed state.",
    )
    report = _report([]).model_copy(
        update={
            "economic_simulations": [plan],
            "invariant_executions": [execution],
        }
    )

    rendered = render_markdown(report)
    assert "cross\\_chain\\_duplicate\\_ordering" in rendered
    assert "cross\\_chain=reorder\\_valid\\_messages" in rendered
    encoded = json.loads(stable_json(report))
    encoded_policy = encoded["invariant_executions"][0]["capability_policy"]
    assert encoded_policy["cross_chain_messages"] == "reorder_valid_messages"
    assert encoded["invariant_executions"][0]["economic_metrics"]["borrowed_capital"] == 0


def test_callback_counterexample_serializes_receiver_and_affected_state() -> None:
    policy = AttackerCapabilityPolicy(
        attacker_controlled_actors=["attacker"],
        attacker_controlled_contracts=["CallbackReceiver"],
    )
    plan = EconomicSimulationPlan(
        kind=EconomicSimulationKind.CALLBACK_REENTRANCY,
        applicable=True,
        rationale="A public receiver hook precedes its affected accounting write.",
        typed_harness_available=True,
        execution_required=True,
    )
    execution = InvariantExecutionResult(
        invariant_id="inv-callback",
        harness_name="ReachableCallbackPreservesAvailableCredit",
        status=InvariantExecutionStatus.COUNTEREXAMPLE,
        runs=8,
        depth=1,
        seed=1,
        economic_template=EconomicSimulationKind.CALLBACK_REENTRANCY,
        capability_policy=policy,
        economic_metrics=EconomicMetrics(
            required_initial_capital=0,
            borrowed_capital=0,
            required_privileges=["one declared synthetic callback receiver"],
            market_assumptions=[
                "receiver.onCreditReceived() is the source-linked reachable callback",
                "availableCredit is the affected accounting state",
            ],
        ),
        counterexample_summary=(
            "The reachable receiver.onCreditReceived() callback reused affected "
            "state availableCredit."
        ),
    )
    report = _report([]).model_copy(
        update={
            "economic_simulations": [plan],
            "invariant_executions": [execution],
        }
    )

    rendered = render_markdown(report)
    assert "callback\\_receiver\\_reentrancy" in rendered
    assert "controlled\\_contracts=CallbackReceiver" in rendered
    encoded = json.loads(stable_json(report))
    encoded_execution = encoded["invariant_executions"][0]
    assert encoded_execution["capability_policy"]["attacker_controlled_contracts"] == [
        "CallbackReceiver"
    ]
    assert "receiver.onCreditReceived()" in encoded_execution["counterexample_summary"]
    assert "availableCredit" in encoded_execution["counterexample_summary"]
    assert encoded_execution["economic_metrics"]["required_initial_capital"] == 0


def test_state_growth_counterexample_serializes_resource_threshold() -> None:
    plan = EconomicSimulationPlan(
        kind=EconomicSimulationKind.BOUNDED_STATE_GROWTH,
        applicable=True,
        rationale="A public array append omits a resolved length guard.",
        typed_harness_available=True,
        execution_required=True,
    )
    execution = InvariantExecutionResult(
        invariant_id="inv-state-growth",
        harness_name="EntryCountWithinGrowthThreshold",
        status=InvariantExecutionStatus.COUNTEREXAMPLE,
        runs=8,
        depth=1,
        seed=1,
        economic_template=EconomicSimulationKind.BOUNDED_STATE_GROWTH,
        economic_metrics=EconomicMetrics(
            required_initial_capital=0,
            borrowed_capital=0,
            resource_threshold=4,
            bounded_actions=5,
            required_privileges=["unprivileged bounded append caller"],
            market_assumptions=["no unbounded loop is executed"],
        ),
        counterexample_summary=("entryCount exceeded growthThreshold after one bounded append."),
    )
    report = _report([]).model_copy(
        update={
            "economic_simulations": [plan],
            "invariant_executions": [execution],
        }
    )

    rendered = render_markdown(report)
    assert "bounded\\_state\\_growth" in rendered
    assert "resource threshold 4" in rendered
    assert "bounded actions 5" in rendered
    encoded = json.loads(stable_json(report))
    encoded_metrics = encoded["invariant_executions"][0]["economic_metrics"]
    assert encoded_metrics["resource_threshold"] == 4
    assert encoded_metrics["bounded_actions"] == 5
    assert "growthThreshold" in encoded["invariant_executions"][0]["counterexample_summary"]


def test_signature_replay_counterexample_serializes_without_key_material() -> None:
    plan = EconomicSimulationPlan(
        kind=EconomicSimulationKind.SIGNATURE_REPLAY,
        applicable=True,
        rationale="A source-linked signature primitive authorizes the transition.",
        typed_harness_available=True,
        execution_required=True,
    )
    execution = InvariantExecutionResult(
        invariant_id="inv-signature",
        harness_name="AuthorizationConsumedOnce",
        status=InvariantExecutionStatus.COUNTEREXAMPLE,
        runs=8,
        depth=2,
        seed=1,
        economic_template=EconomicSimulationKind.SIGNATURE_REPLAY,
        economic_metrics=EconomicMetrics(
            required_initial_capital=0,
            borrowed_capital=0,
            required_privileges=["holder of one fixture-authorized signature"],
            market_assumptions=["signature material is synthetic and local-only"],
        ),
        counterexample_summary="A bounded local invariant failed.",
    )
    report = _report([]).model_copy(
        update={
            "economic_simulations": [plan],
            "invariant_executions": [execution],
        }
    )

    rendered = render_markdown(report)
    assert "signature\\_nonce\\_domain\\_replay" in rendered
    assert "| True | True | 1 | 1 counterexample | 0 | 0 |" in rendered
    encoded_text = stable_json(report)
    assert "private_key" not in encoded_text
    assert "privateKey" not in encoded_text
    encoded = json.loads(encoded_text)
    assert (
        encoded["invariant_executions"][0]["economic_template"] == "signature_nonce_domain_replay"
    )


def test_ordering_counterexample_serializes_declared_same_block_capability() -> None:
    plan = EconomicSimulationPlan(
        kind=EconomicSimulationKind.SANDWICH,
        applicable=True,
        rationale="A staged value bound and reorder transition are source-linked.",
        typed_harness_available=True,
        execution_required=True,
        required_transaction_ordering=TransactionOrderingCapability.SAME_BLOCK,
    )
    execution = InvariantExecutionResult(
        invariant_id="inv-ordering",
        harness_name="StagedValueBoundPreserved",
        status=InvariantExecutionStatus.COUNTEREXAMPLE,
        runs=8,
        depth=1,
        seed=1,
        economic_template=EconomicSimulationKind.SANDWICH,
        required_transaction_ordering=TransactionOrderingCapability.SAME_BLOCK,
        economic_metrics=EconomicMetrics(
            required_initial_capital=0,
            borrowed_capital=0,
            required_privileges=["declared same-block transaction ordering"],
            market_assumptions=["no time or block movement occurs"],
        ),
        counterexample_summary="A bounded local invariant failed.",
    )
    report = _report([]).model_copy(
        update={
            "economic_simulations": [plan],
            "invariant_executions": [execution],
        }
    )

    rendered = render_markdown(report)
    assert "sandwich\\_sensitive\\_flow" in rendered
    assert "same\\_block" in rendered
    encoded = json.loads(stable_json(report))
    assert encoded["economic_simulations"][0]["required_transaction_ordering"] == "same_block"
    assert encoded["invariant_executions"][0]["required_transaction_ordering"] == "same_block"


def test_stable_json_is_sorted_and_versioned() -> None:
    report = _report([_finding()])
    encoded = stable_json(report)
    assert encoded.endswith("\n")
    assert json.loads(encoded)["schema_version"] == "1.0"
    assert encoded.index('"completed"') < encoded.index('"schema_version"')


def test_sarif_21_shape_and_fingerprints() -> None:
    sarif = generate_sarif([_finding()])
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["rules"][0]["id"] == "MMA-ABCDEF123456"
    result = run["results"][0]
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
    assert result["partialFingerprints"]["mmaudit/v1"] == "abc123"


def test_sarif_encodes_incomplete_run_as_unsuccessful_with_reasons() -> None:
    reason = "no real scanner or model review completed"
    sarif = generate_sarif(
        [],
        run_status=AuditRunStatus.INCOMPLETE,
        quality_status=AuditQualityStatus.INCOMPLETE,
        completed=False,
        incomplete_reasons=[reason],
    )

    run = sarif["runs"][0]
    assert run["properties"]["runStatus"] == "INCOMPLETE"
    assert run["properties"]["qualityStatus"] == "incomplete"
    assert run["properties"]["completed"] is False
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["properties"]["runStatus"] == "INCOMPLETE"
    assert invocation["toolExecutionNotifications"] == [
        {
            "level": "error",
            "message": {"text": reason},
        }
    ]


def test_sarif_marks_only_complete_run_status_successful() -> None:
    complete = generate_sarif(
        [],
        run_status=AuditRunStatus.COMPLETE,
        quality_status=AuditQualityStatus.COMPLETED,
        completed=True,
    )
    degraded = generate_sarif(
        [],
        run_status=AuditRunStatus.DEGRADED,
        quality_status=AuditQualityStatus.COMPLETED_WITH_LIMITATIONS,
        completed=False,
        incomplete_reasons=["operator authorized a reduced analysis profile"],
    )
    quality_only = generate_sarif(
        [],
        quality_status=AuditQualityStatus.INCOMPLETE,
        completed=False,
    )

    assert complete["runs"][0]["invocations"][0]["executionSuccessful"] is True
    assert degraded["runs"][0]["invocations"][0]["executionSuccessful"] is False
    assert quality_only["runs"][0]["invocations"][0]["executionSuccessful"] is False
    assert generate_sarif([])["runs"][0]["invocations"] == []


@pytest.mark.parametrize(
    ("run_status", "quality_status", "completed"),
    [
        (AuditRunStatus.DEGRADED, AuditQualityStatus.COMPLETED_WITH_LIMITATIONS, True),
        (AuditRunStatus.INCOMPLETE, AuditQualityStatus.COMPLETED, False),
        (AuditRunStatus.COMPLETE, AuditQualityStatus.COMPLETED, False),
    ],
)
def test_sarif_rejects_contradictory_run_evidence(
    run_status: AuditRunStatus,
    quality_status: AuditQualityStatus,
    completed: bool,
) -> None:
    with pytest.raises(ValueError, match="SARIF"):
        generate_sarif(
            [],
            run_status=run_status,
            quality_status=quality_status,
            completed=completed,
            incomplete_reasons=(
                [] if run_status is AuditRunStatus.COMPLETE else ["synthetic incomplete reason"]
            ),
        )


def test_sarif_excludes_rejected_findings() -> None:
    assert generate_sarif([_finding(FindingStatus.REJECTED)])["runs"][0]["results"] == []


def test_sarif_excludes_findings_with_invalid_locations() -> None:
    finding = _finding().model_copy(
        update={
            "location_validation": LocationValidation(
                valid=False,
                errors=["line range no longer exists"],
            )
        }
    )
    sarif = generate_sarif([finding])
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_needs_review_is_not_presented_as_an_error() -> None:
    result = generate_sarif([_finding(FindingStatus.NEEDS_REVIEW)])["runs"][0]["results"][0]
    assert result["level"] == "note"
    assert result["properties"]["status"] == "needs_review"


def test_sarif_encodes_uri_shaped_repository_filename() -> None:
    finding = _finding().model_copy(
        update={
            "locations": [Location(path="https:/invalid.example/file.py", start_line=1, end_line=1)]
        }
    )
    uri = generate_sarif([finding])["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == "https%3A/invalid.example/file.py"
