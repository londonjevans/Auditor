from __future__ import annotations

import hashlib
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mmaudit.models.openrouter import safe_headers
from mmaudit.models.schemas import (
    AttackerCapability,
    AttackerCapabilityPolicy,
    AuditReport,
    CrossChainMessageCapability,
    EconomicMetrics,
    EconomicSimulationKind,
    EconomicSimulationPlan,
    FinancialAssetKind,
    FinancialSettlementEvidence,
    Finding,
    FindingStatus,
    InvariantExecutionMinimizationEvidence,
    InvariantExecutionRemovalTrial,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    LendingBoundaryEvidence,
    Location,
    LocationValidation,
    RepositoryCodeExecutionState,
    RepositoryMap,
    ReproductionResult,
    ReproductionState,
    ScannerRun,
    ScannerStatus,
    Severity,
    SharePriceBoundaryEvidence,
    TransactionOrderingCapability,
    VerificationTest,
)
from mmaudit.reporting.json_report import stable_json
from mmaudit.reporting.markdown import render_markdown
from mmaudit.reporting.sarif import generate_sarif
from mmaudit.scanners.base import ScannerAdapter, sanitized_scanner_environment
from mmaudit.scanners.codeql import CodeQLScanner
from mmaudit.scanners.gitleaks import GitleaksScanner
from mmaudit.scanners.osv import OsvScanner
from mmaudit.scanners.semgrep import SemgrepScanner
from mmaudit.scanners.slither import SlitherScanner
from mmaudit.scanners.trivy import TrivyScanner

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


def test_gitleaks_normalization_never_preserves_value(
    vulnerable_repo: Path, tmp_path: Path
) -> None:
    private = tmp_path / "gitleaks"
    private.mkdir()
    (private / "gitleaks-report.json").write_text(
        (FIXTURES / "scanner_outputs/gitleaks.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    findings = GitleaksScanner().parse(vulnerable_repo, "", private)
    serialized = stable_json([finding.model_dump(mode="json") for finding in findings])
    assert "REDACTED" not in serialized
    assert findings[0].metadata["redacted"] is True


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


def test_scanner_commands_are_fixed_argument_arrays(tmp_path: Path) -> None:
    adapters = [SemgrepScanner(), GitleaksScanner(), TrivyScanner(), OsvScanner(), SlitherScanner()]
    for adapter in adapters:
        command = adapter.build_command(tmp_path, tmp_path / adapter.name)
        assert isinstance(command, list)
        assert command[0] == adapter.executable
        assert not any(token in command for token in ("curl", "wget", "ssh"))


def test_scanner_environment_drops_unrelated_secrets(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "should-not-propagate")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "should-not-propagate")
    environment = sanitized_scanner_environment(tmp_path)
    assert "OPENROUTER_API_KEY" not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert environment["HOME"].startswith(str(tmp_path))


def test_scanner_fails_closed_without_hardened_isolation(tmp_path: Path) -> None:
    scanner = _SyntheticProcessScanner("print('{}')")
    result = scanner.run(tmp_path, tmp_path / "private-no-isolation", 2)
    assert result.status is ScannerStatus.UNAVAILABLE
    assert "isolation" in (result.error or "")


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
    private = tmp_path / "private-env"

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
        tmp_path / "private-timeout",
        0.05,
        backend=_PassthroughIsolation(),
    )
    assert result.status is ScannerStatus.TIMED_OUT


def test_real_subprocess_output_is_bounded(tmp_path: Path) -> None:
    scanner = _SyntheticProcessScanner("print('x' * 10000)", output_limit=100)
    result = scanner.run(
        tmp_path,
        tmp_path / "private-output",
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
        tmp_path / "private-invalid",
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
