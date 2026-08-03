from __future__ import annotations

import hashlib
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    AnalysisState,
    AuditedSuiteCoverage,
    CoverageExclusion,
    CoverageMetric,
    CoverageProvenance,
    EconomicSimulationKind,
    EconomicTemplateExecutionCoverage,
    ExecutionEvidenceKind,
    InvariantCategory,
    InvariantExecutionStatus,
    InvariantTemplate,
    RepositoryCodeExecutionState,
    ReproductionResult,
    ReproductionState,
    ScannerRun,
    ScannerStatus,
    SolidityCompilationResult,
    SolidityCoverage,
    SolidityGraphKind,
    SolidityGraphNodeKind,
    SolidityGraphSet,
    SolidityProvenance,
    SoliditySymbolIndex,
)
from mmaudit.orchestration.context import ContextBuilder, render_context
from mmaudit.orchestration.pipeline import (
    _coverage_quality_gate,
    _record_reproduction_attempts,
)
from mmaudit.repository.chunking import line_range_hash
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.repository.mapping import build_repository_map
from mmaudit.scanners.slither import SlitherScanner
from mmaudit.solidity.compile import _artifact_summary, compile_solidity_projects
from mmaudit.solidity.coverage import build_solidity_coverage
from mmaudit.solidity.graphs import _line_range, build_solidity_graphs
from mmaudit.solidity.index import build_solidity_index
from mmaudit.solidity.invariants import discover_invariants
from mmaudit.solidity.projects import discover_solidity_projects
from mmaudit.solidity.retrieval import compact_solidity_graphs

FIXTURES = Path(__file__).parents[1] / "fixtures" / "solidity"


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
    """Mock the off-host adapter without loading repository JavaScript in the test process."""

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
        if command[-1] == "--version":
            return [sys.executable, "-c", "print('synthetic hardhat 1.0')"]
        artifact = json.dumps(
            {
                "contractName": "Contained",
                "sourceName": "contracts/Contained.sol",
                "abi": [],
            }
        )
        code = (
            "from pathlib import Path; "
            "target = Path('artifacts/contracts/Contained.sol'); "
            "target.mkdir(parents=True, exist_ok=True); "
            f"(target / 'Contained.json').write_text({artifact!r}, encoding='utf-8')"
        )
        return [sys.executable, "-c", code]

    def cleanup(self, private_dir: Path) -> None:
        private_dir.resolve(strict=True)
        self.cleanup_calls += 1


def _copy_fixture(tmp_path: Path, name: str) -> Path:
    target = tmp_path / name
    shutil.copytree(FIXTURES / name, target)
    return target


def test_detects_foundry_project_metadata(tmp_path: Path, config_factory) -> None:
    root = _copy_fixture(tmp_path, "foundry")
    discovery = discover_repository(root, config_factory().repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config_factory().smart_contracts)
    assert len(projects) == 1
    project = projects[0]
    assert project.project_type == "foundry"
    assert project.project_root == "."
    assert "src" in project.source_directories
    assert "test" in project.test_directories
    assert "0.8.20" in project.compiler_versions
    assert project.optimizer_enabled is True
    assert project.optimizer_runs == 200
    assert project.evm_version == "paris"
    assert project.build_command[:2] == ["forge", "build"]


def test_candidate_reproduction_preserves_audited_repository_suite_counts() -> None:
    def not_analyzed_metric(detail: str) -> CoverageMetric:
        return CoverageMetric(
            numerator=0,
            denominator=0,
            population=0,
            percentage=None,
            exclusions=[],
            not_applicable_evidence=[],
            confidence=0,
            provenance=[CoverageProvenance.RUNTIME],
            failures=["audited source inventory was not available"],
            state=AnalysisState.NOT_ANALYZED,
            detail=detail,
        )

    contract_metric = not_analyzed_metric("No audited contract statements were analyzed.")
    function_metric = not_analyzed_metric("No audited function statements were analyzed.")
    assertion_metric = not_analyzed_metric("No critical function assertions were analyzed.")
    audited_suite = AuditedSuiteCoverage(
        contract_statement_coverage=contract_metric,
        function_statement_coverage=function_metric,
        critical_function_assertion_coverage=assertion_metric,
        repository_tests_selected=9,
        repository_tests_executed=7,
        repository_tests_failed=2,
        source_classification_complete=True,
        critical_classification_complete=True,
    )
    coverage = SolidityCoverage(
        tests_executed=7,
        tests_failed=2,
        audited_suite_coverage=audited_suite,
        quality_metrics={
            "audited_suite_contract_statement_coverage": contract_metric,
            "audited_suite_function_statement_coverage": function_metric,
            "audited_suite_critical_function_assertion_coverage": assertion_metric,
        },
    )
    reproduction = ReproductionResult(
        candidate_id="candidate-reproduction-accounting",
        test_name="SyntheticCandidateReplay",
        state=ReproductionState.NOT_REPRODUCED,
        specification_sha256="a" * 64,
        attempts=3,
    )

    updated = _record_reproduction_attempts(coverage, [reproduction])

    assert updated.reproduction_attempts == 1
    assert updated.tests_executed == audited_suite.repository_tests_executed == 7
    assert updated.tests_failed == audited_suite.repository_tests_failed == 2
    assert updated.audited_suite_coverage == audited_suite


def test_candidate_reproduction_revalidates_audited_suite_count_binding() -> None:
    def not_analyzed_metric(detail: str) -> CoverageMetric:
        return CoverageMetric(
            numerator=0,
            denominator=0,
            population=0,
            percentage=None,
            exclusions=[],
            not_applicable_evidence=[],
            confidence=0,
            provenance=[CoverageProvenance.RUNTIME],
            failures=["audited source inventory was not available"],
            state=AnalysisState.NOT_ANALYZED,
            detail=detail,
        )

    metric = not_analyzed_metric("No audited source surface was analyzed.")
    nested = AuditedSuiteCoverage(
        contract_statement_coverage=metric,
        function_statement_coverage=metric,
        critical_function_assertion_coverage=metric,
        repository_tests_selected=9,
        repository_tests_executed=7,
        repository_tests_failed=2,
        source_classification_complete=True,
        critical_classification_complete=True,
    )
    coverage = SolidityCoverage(
        tests_executed=7,
        tests_failed=2,
        audited_suite_coverage=nested,
        quality_metrics={
            "audited_suite_contract_statement_coverage": metric,
            "audited_suite_function_statement_coverage": metric,
            "audited_suite_critical_function_assertion_coverage": metric,
        },
    )
    bypassed = coverage.model_copy(
        update={
            "audited_suite_coverage": nested.model_copy(update={"repository_tests_executed": 6})
        }
    )

    with pytest.raises(ValidationError, match="top-level Solidity test counts"):
        _record_reproduction_attempts(bypassed, [])


def test_detects_hardhat_project_metadata(tmp_path: Path, config_factory) -> None:
    root = _copy_fixture(tmp_path, "hardhat")
    discovery = discover_repository(root, config_factory().repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config_factory().smart_contracts)
    assert len(projects) == 1
    project = projects[0]
    assert project.project_type == "hardhat"
    assert "contracts" in project.source_directories
    assert "hardhat.config.ts" in project.framework_config_files
    assert "0.8.20" in project.compiler_versions
    assert project.optimizer_runs == 300


def test_detects_mixed_and_plain_layouts(tmp_path: Path, config_factory) -> None:
    mixed = tmp_path / "mixed"
    (mixed / "contracts").mkdir(parents=True)
    (mixed / "contracts" / "A.sol").write_text(
        "pragma solidity ^0.8.20; contract A {}", encoding="utf-8"
    )
    (mixed / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (mixed / "hardhat.config.js").write_text(
        'module.exports = { solidity: "0.8.20" };\n', encoding="utf-8"
    )
    discovery = discover_repository(mixed, config_factory().repository, IgnoreMatcher())
    assert (
        discover_solidity_projects(discovery, config_factory().smart_contracts)[0].project_type
        == "mixed"
    )

    plain = tmp_path / "plain"
    (plain / "contracts").mkdir(parents=True)
    (plain / "contracts" / "B.sol").write_text(
        "pragma solidity ^0.8.20; contract B {}", encoding="utf-8"
    )
    discovery = discover_repository(plain, config_factory().repository, IgnoreMatcher())
    assert (
        discover_solidity_projects(discovery, config_factory().smart_contracts)[0].project_type
        == "plain"
    )


def test_detects_monorepo_project_roots(tmp_path: Path, config_factory) -> None:
    for package in ("packages/one", "packages/two"):
        root = tmp_path / package
        (root / "src").mkdir(parents=True)
        (root / "src" / "C.sol").write_text(
            "pragma solidity ^0.8.20; contract C {}", encoding="utf-8"
        )
        (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    discovery = discover_repository(tmp_path, config_factory().repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config_factory().smart_contracts)
    assert {project.project_root for project in projects} == {"packages/one", "packages/two"}
    assert all("monorepo" in " ".join(project.discovery_warnings) for project in projects)


def test_solidity_index_and_graphs_from_foundry_artifact(tmp_path: Path, config_factory) -> None:
    root = _copy_fixture(tmp_path, "foundry")
    discovery = discover_repository(root, config_factory().repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config_factory().smart_contracts)
    compilation = compile_solidity_projects(
        root, projects, config_factory().smart_contracts, tmp_path / "private"
    )
    build = build_solidity_index(discovery, projects, compilation.artifact_roots)
    assert "src/Vault.sol" in build.index.ast_sources
    names = {entity.name for entity in build.index.entities}
    assert {"Vault", "withdraw", "_withdraw", "onlyOwner"} <= names
    graphs = build_solidity_graphs(discovery, build)
    labels = {edge.label for edge in graphs.edges}
    assert "Vault inherits Owned" in labels
    assert "applies onlyOwner" in labels
    assert "calls _withdraw" in labels


def test_solidity_index_rejects_ast_byte_spans_outside_current_source_inventory(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "foundry")
    source = root / "src" / "Vault.sol"
    source.write_text(
        source.read_text(encoding="utf-8").replace(" external onlyOwner", " external"),
        encoding="utf-8",
    )
    discovery = discover_repository(root, config_factory().repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config_factory().smart_contracts)
    compilation = compile_solidity_projects(
        root, projects, config_factory().smart_contracts, tmp_path / "private-stale-ast"
    )

    build = build_solidity_index(discovery, projects, compilation.artifact_roots)

    assert build.index.ast_sources == []
    assert "src/Vault.sol" in build.index.fallback_sources
    assert any(
        "AST byte spans did not match current source" in item for item in build.index.warnings
    )


def test_ast_line_range_treats_the_compiler_byte_span_as_half_open() -> None:
    content = "contract Synthetic {\n    function check() external {}\n}\n"

    assert _line_range(content, f"0:{len(content.encode())}:0") == (1, 3)


@pytest.mark.parametrize(
    "source_range",
    (
        "malformed",
        "-1:1:0",
        "0:-1:0",
        "999:1:0",
        "0:999:0",
        "0:1:-1",
        "0:1:",
        "0:1:not-an-int",
        "0:1:0:extra",
    ),
)
def test_ast_line_range_rejects_invalid_or_stale_compiler_byte_spans(
    source_range: str,
) -> None:
    with pytest.raises(ValueError, match="compiler source range"):
        _line_range("a\nb\n", source_range)


def test_ast_line_range_accepts_a_bounded_zero_length_compiler_point() -> None:
    assert _line_range("a\nb\n", "2:0:0") == (2, 2)


def test_hardhat_build_info_ast_is_indexed(tmp_path: Path, config_factory) -> None:
    root = _copy_fixture(tmp_path, "hardhat")
    discovery = discover_repository(root, config_factory().repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config_factory().smart_contracts)
    compilation = compile_solidity_projects(
        root, projects, config_factory().smart_contracts, tmp_path / "private"
    )
    build = build_solidity_index(discovery, projects, compilation.artifact_roots)
    assert "contracts/Token.sol" in build.index.ast_sources
    assert {"Token", "mint", "_mint", "onlyMinter"} <= {
        entity.name for entity in build.index.entities
    }


def test_compilation_fails_closed_without_hardened_isolation(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_fixture(tmp_path, "foundry")
    config = config_factory(smart_contracts={"compile": True})
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    monkeypatch.setattr(
        "mmaudit.solidity.compile.default_isolation_backend",
        lambda configured: None,
    )

    compilation = compile_solidity_projects(
        root,
        projects,
        config.smart_contracts,
        tmp_path / "private-no-isolation",
    )

    assert compilation.results[0].status == "unavailable"
    assert "isolation" in compilation.results[0].errors[0]


def test_hardhat_compilation_blocks_before_repository_javascript_or_host_tool_resolution(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_fixture(tmp_path, "hardhat_isolation")
    config = config_factory(smart_contracts={"compile": True})
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    monkeypatch.setattr(
        "mmaudit.solidity.compile.subprocess.Popen",
        lambda *args, **kwargs: pytest.fail("repository JavaScript must not execute"),
    )
    monkeypatch.setattr(
        "mmaudit.solidity.compile.shutil.which",
        lambda _: pytest.fail("host Hardhat must not be resolved"),
    )

    compilation = compile_solidity_projects(
        root,
        projects,
        config.smart_contracts,
        tmp_path / "private-hardhat-blocked",
        backend=_PassthroughIsolation(),
    )

    result = compilation.results[0]
    assert result.status == "unavailable"
    assert result.repository_code_execution is RepositoryCodeExecutionState.BLOCKED
    assert result.isolation_backend == "test-isolation"
    assert "off-host" in result.errors[0]
    assert not (root / "repository-config-executed.marker").exists()
    restored = SolidityCompilationResult.model_validate_json(result.model_dump_json())
    assert restored.repository_code_execution is RepositoryCodeExecutionState.BLOCKED


def test_hardhat_compilation_uses_mocked_off_host_adapter_and_serializes_evidence(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_fixture(tmp_path, "hardhat_isolation")
    config = config_factory(smart_contracts={"compile": True})
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    monkeypatch.setattr(
        "mmaudit.solidity.compile.shutil.which",
        lambda _: pytest.fail("host Hardhat must not be resolved"),
    )
    backend = _MockRepositoryJavaScriptIsolation()

    compilation = compile_solidity_projects(
        root,
        projects,
        config.smart_contracts,
        tmp_path / "private-hardhat-isolated",
        backend=backend,
    )

    result = compilation.results[0]
    assert result.status == "success"
    assert result.repository_code_execution is RepositoryCodeExecutionState.ISOLATED
    assert result.isolation_backend == backend.name
    assert result.contracts_compiled == ["Contained"]
    assert result.tool_versions == {"hardhat": "synthetic hardhat 1.0"}
    assert backend.commands == [["hardhat", "compile"], ["hardhat", "--version"]]
    assert backend.cleanup_calls == 2
    assert not (root / "repository-config-executed.marker").exists()
    restored = SolidityCompilationResult.model_validate_json(result.model_dump_json())
    assert restored.repository_code_execution is RepositoryCodeExecutionState.ISOLATED


def test_artifact_summary_recognizes_current_foundry_compilation_target(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "out" / "Vault.sol"
    artifact_root.mkdir(parents=True)
    (artifact_root / "Vault.json").write_text(
        json.dumps(
            {
                "abi": [],
                "ast": {"nodeType": "SourceUnit"},
                "bytecode": {"object": "00", "sourceMap": "1:2:3"},
                "metadata": {
                    "settings": {
                        "compilationTarget": {
                            "src/Vault.sol": "Vault",
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    summary = _artifact_summary([tmp_path / "out"])

    assert summary == {
        "contracts": ["Vault"],
        "ast_available": True,
        "source_maps_available": True,
    }


def test_artifact_summary_does_not_credit_null_or_declared_only_ast(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "out" / "Vault.sol"
    artifact_root.mkdir(parents=True)
    (artifact_root / "Vault.json").write_text(
        json.dumps(
            {
                "ast": None,
                "metadata": {
                    "settings": {
                        "compilationTarget": {
                            "src/Vault.sol": "Vault",
                        }
                    }
                },
                "output": {
                    "sources": {
                        "src/Vault.sol": {
                            "id": 0,
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    summary = _artifact_summary([tmp_path / "out"])

    assert summary["contracts"] == ["Vault"]
    assert not summary["ast_available"]


def test_compilation_rejects_repository_local_build_tool(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_fixture(tmp_path, "foundry")
    fake_bin = root / "bin"
    fake_bin.mkdir()
    fake_forge = fake_bin / "forge"
    fake_forge.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_forge.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    config = config_factory(smart_contracts={"compile": True})
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)

    compilation = compile_solidity_projects(
        root,
        projects,
        config.smart_contracts,
        tmp_path / "private-local-tool",
        backend=_PassthroughIsolation(),
    )

    assert compilation.results[0].status == "unavailable"
    assert "inside audited repository" in compilation.results[0].errors[0]


def test_compilation_workspace_excludes_secret_files(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_fixture(tmp_path, "foundry")
    (root / ".env").write_text("PRIVATE_KEY=synthetic\n", encoding="utf-8")
    (root / "wallet.pem").write_text("synthetic pem\n", encoding="utf-8")
    (root / "signing.key").write_text("synthetic key\n", encoding="utf-8")
    (root / "id_rsa").write_text("synthetic ssh key\n", encoding="utf-8")
    (root / "mnemonic.txt").write_text("synthetic seed phrase\n", encoding="utf-8")
    (root / "wallet.json").write_text("synthetic wallet\n", encoding="utf-8")
    (root / ".ENV.PROD").write_text("PRIVATE_KEY=synthetic\n", encoding="utf-8")
    (root / "WALLET.PEM").write_text("synthetic pem\n", encoding="utf-8")
    (root / "ID_ED25519").write_text("synthetic ssh key\n", encoding="utf-8")
    tools = tmp_path / "tools"
    tools.mkdir()
    fake_forge = tools / "forge"
    fake_forge.write_text(
        '#!/bin/sh\nif [ "$1" = "--version" ]; then echo "forge fake"; exit 0; fi\n'
        'test ! -e ".env"\n'
        'test ! -e "wallet.pem"\n'
        'test ! -e "signing.key"\n'
        'test ! -e "id_rsa"\n'
        'test ! -e "mnemonic.txt"\n'
        'test ! -e "wallet.json"\n'
        'test ! -e ".ENV.PROD"\n'
        'test ! -e "WALLET.PEM"\n'
        'test ! -e "ID_ED25519"\n',
        encoding="utf-8",
    )
    fake_forge.chmod(0o755)
    monkeypatch.setenv("PATH", str(tools))
    config = config_factory(smart_contracts={"compile": True})
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)

    compilation = compile_solidity_projects(
        root,
        projects,
        config.smart_contracts,
        tmp_path / "private-no-env",
        backend=_PassthroughIsolation(),
    )

    assert compilation.results[0].status == "success"
    assert (
        compilation.results[0].executable_sha256
        == hashlib.sha256(fake_forge.read_bytes()).hexdigest()
    )


def test_compilation_rejects_symlink_before_execution(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_fixture(tmp_path, "foundry")
    outside = tmp_path / "outside.sol"
    outside.write_text("contract Outside {}", encoding="utf-8")
    (root / "src" / "Escape.sol").symlink_to(outside)
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "forge").symlink_to(Path(sys.executable))
    monkeypatch.setenv("PATH", str(tools))
    monkeypatch.setattr(
        "mmaudit.solidity.compile.subprocess.Popen",
        lambda *args, **kwargs: pytest.fail("compiler must not execute"),
    )
    config = config_factory(smart_contracts={"compile": True})
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)

    compilation = compile_solidity_projects(
        root,
        projects,
        config.smart_contracts,
        tmp_path / "private-symlink",
        backend=_PassthroughIsolation(),
    )

    assert compilation.results[0].status == "failed"
    assert "isolated compilation workspace" in compilation.results[0].errors[0]


def test_fallback_index_for_plain_solidity(tmp_path: Path, config_factory) -> None:
    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts" / "Fallback.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract Fallback { uint256 total; function inc() public { total += 1; } }\n",
        encoding="utf-8",
    )
    discovery = discover_repository(tmp_path, config_factory().repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config_factory().smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    assert build.index.fallback_sources == ["contracts/Fallback.sol"]
    assert {"Fallback", "inc"} <= {entity.name for entity in build.index.entities}
    inc = next(entity for entity in build.index.entities if entity.name == "inc")
    assert inc.signature == "inc()"
    assert inc.visibility == "public"


def test_fallback_index_records_supported_function_abi_signatures(
    tmp_path: Path,
    config_factory,
) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Signatures.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "contract Signatures {\n"
        "function act(uint amount, address payable receiver, bytes32 id) external payable {}\n"
        "}\n",
        encoding="utf-8",
    )
    config = config_factory()
    discovery = discover_repository(tmp_path, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    action = next(entity for entity in build.index.entities if entity.name == "act")
    assert action.signature == "act(uint256,address,bytes32)"
    assert action.visibility == "external"
    assert action.payable


def test_compiler_ast_records_canonical_signature_and_selector(
    tmp_path: Path,
    config_factory,
) -> None:
    source = (
        "pragma solidity ^0.8.20;\n"
        "contract Token {\n"
        "function transfer(address to, uint256 amount) external returns (bool) { return true; }\n"
        "}\n"
    )
    (tmp_path / "src").mkdir()
    source_path = tmp_path / "src" / "Token.sol"
    source_path.write_text(source, encoding="utf-8")
    function_start = source.index("function transfer")
    contract_start = source.index("contract Token")
    artifact_root = tmp_path / "compiler-artifacts"
    artifact_root.mkdir()
    (artifact_root / "Token.json").write_text(
        json.dumps(
            {
                "sourceName": "src/Token.sol",
                "ast": {
                    "nodeType": "SourceUnit",
                    "nodes": [
                        {
                            "id": 1,
                            "nodeType": "ContractDefinition",
                            "contractKind": "contract",
                            "name": "Token",
                            "src": f"{contract_start}:{len(source) - contract_start}:0",
                            "nodes": [
                                {
                                    "id": 2,
                                    "nodeType": "FunctionDefinition",
                                    "kind": "function",
                                    "name": "transfer",
                                    "visibility": "external",
                                    "stateMutability": "nonpayable",
                                    "functionSelector": "a9059cbb",
                                    "src": (
                                        f"{function_start}:"
                                        f"{source.index('}', function_start) - function_start + 1}:0"
                                    ),
                                    "parameters": {
                                        "parameters": [
                                            {"typeDescriptions": {"typeString": "address"}},
                                            {"typeDescriptions": {"typeString": "uint256"}},
                                        ]
                                    },
                                }
                            ],
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    config = config_factory()
    discovery = discover_repository(tmp_path, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [artifact_root])
    transfer = next(entity for entity in build.index.entities if entity.name == "transfer")
    assert transfer.signature == "transfer(address,uint256)"
    assert transfer.selector == "a9059cbb"
    assert transfer.provenance is SolidityProvenance.COMPILER


def test_compiler_semantic_provenance_survives_serialization(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "foundry")
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    graphs = build_solidity_graphs(discovery, build)
    files = {item.relative_path: item for item in discovery.files}

    restored_index = SoliditySymbolIndex.model_validate_json(build.index.model_dump_json())
    restored_graphs = SolidityGraphSet.model_validate_json(graphs.model_dump_json())
    assert restored_index == build.index
    assert restored_graphs == graphs

    compiler_entities = [
        entity
        for entity in restored_index.entities
        if entity.provenance is SolidityProvenance.COMPILER
    ]
    fallback_entities = [
        entity
        for entity in restored_index.entities
        if entity.provenance is SolidityProvenance.FALLBACK
    ]
    assert compiler_entities
    assert fallback_entities
    assert max(entity.confidence for entity in fallback_entities) < min(
        entity.confidence for entity in compiler_entities
    )
    for entity in restored_index.entities:
        file = files[entity.path]
        assert 0 <= entity.byte_start <= entity.byte_end <= len(file.content.encode())
        assert entity.source_hash == line_range_hash(
            file.content, entity.start_line, entity.end_line
        )
        assert entity.transformation
    for node in restored_graphs.nodes:
        assert node.source_hash == line_range_hash(
            files[node.path].content, node.start_line, node.end_line
        )
        assert node.transformation
    for edge in restored_graphs.edges:
        assert edge.source_hash == line_range_hash(
            files[edge.path].content, edge.start_line, edge.end_line
        )
        assert edge.transformation


def test_malformed_source_uses_lower_confidence_serializable_fallback_provenance(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "semantic_malformed")
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    source = next(item for item in discovery.files if item.language == "Solidity")

    assert build.index.ast_sources == []
    assert build.index.fallback_sources == ["src/MalformedAccounting.sol"]
    assert build.index.entities
    assert all(
        entity.provenance is SolidityProvenance.FALLBACK
        and entity.confidence < 0.8
        and entity.transformation.startswith("bounded_source_")
        and entity.source_hash
        == line_range_hash(source.content, entity.start_line, entity.end_line)
        for entity in build.index.entities
    )
    assert graphs.edges
    assert all(
        edge.provenance is SolidityProvenance.HEURISTIC
        and edge.confidence < min(entity.confidence for entity in build.index.entities)
        and edge.transformation
        and edge.source_hash == line_range_hash(source.content, edge.start_line, edge.end_line)
        for edge in graphs.edges
    )
    assert SoliditySymbolIndex.model_validate_json(build.index.model_dump_json()) == build.index
    assert SolidityGraphSet.model_validate_json(graphs.model_dump_json()) == graphs

    invalid_entity = build.index.entities[0].model_dump()
    invalid_entity["confidence"] = 0.9
    with pytest.raises(ValidationError, match="fallback entity confidence"):
        type(build.index.entities[0]).model_validate(invalid_entity)
    invalid_edge = graphs.edges[0].model_dump()
    invalid_edge["transformation"] = ""
    with pytest.raises(ValidationError, match="at least 1 character"):
        type(graphs.edges[0]).model_validate(invalid_edge)


def _write_call_control_ast(source_path: Path, artifact_root: Path) -> None:
    source = source_path.read_text(encoding="utf-8")

    def block_span(marker: str) -> tuple[int, int]:
        start = source.index(marker)
        opening = source.index("{", start)
        depth = 0
        for position in range(opening, len(source)):
            if source[position] == "{":
                depth += 1
            elif source[position] == "}":
                depth -= 1
                if depth == 0:
                    return start, position + 1
        raise AssertionError(f"synthetic block is not closed: {marker}")

    def src(start: int, end: int) -> str:
        return f"{start}:{end - start}:0"

    def fragment_span(marker: str, fragment: str) -> tuple[int, int]:
        start, end = block_span(marker)
        fragment_start = source.index(fragment, start, end)
        return fragment_start, fragment_start + len(fragment)

    function_ids = {
        "_book": 10,
        "callInternal": 11,
        "callExternal": 12,
        "callLowLevel": 13,
        "callDelegate": 14,
        "unsafeWithdraw": 15,
        "guardedWithdraw": 16,
        "effectsFirst": 17,
    }

    def internal_call(function: str, fragment: str) -> dict[str, Any]:
        start, end = fragment_span(f"function {function}", fragment)
        return {
            "nodeType": "FunctionCall",
            "src": src(start, end),
            "expression": {
                "nodeType": "Identifier",
                "name": "_book",
                "referencedDeclaration": function_ids["_book"],
                "src": src(start, start + len("_book")),
            },
        }

    def member_call(function: str, fragment: str, target: str, member: str) -> dict[str, Any]:
        start, end = fragment_span(f"function {function}", fragment)
        member_start = source.index(f"{target}.{member}", start, end)
        return {
            "nodeType": "FunctionCall",
            "src": src(start, end),
            "expression": {
                "nodeType": "MemberAccess",
                "memberName": member,
                "src": src(member_start, member_start + len(f"{target}.{member}")),
                "expression": {
                    "nodeType": "Identifier",
                    "name": target,
                    "src": src(member_start, member_start + len(target)),
                },
            },
        }

    def balance_write(function: str) -> dict[str, Any]:
        fragment = "balances[msg.sender] -= amount"
        start, end = fragment_span(f"function {function}", fragment)
        target_end = start + len("balances[msg.sender]")
        return {
            "nodeType": "Assignment",
            "operator": "-=",
            "src": src(start, end),
            "leftHandSide": {
                "nodeType": "IndexAccess",
                "referencedDeclaration": 2,
                "src": src(start, target_end),
            },
        }

    function_bodies: dict[str, list[dict[str, Any]]] = {
        "_book": [],
        "callInternal": [internal_call("callInternal", "_book(amount)")],
        "callExternal": [member_call("callExternal", "target.ping()", "target", "ping")],
        "callLowLevel": [member_call("callLowLevel", 'target.call("")', "target", "call")],
        "callDelegate": [
            member_call(
                "callDelegate",
                "target.delegatecall(data)",
                "target",
                "delegatecall",
            )
        ],
        "unsafeWithdraw": [
            member_call("unsafeWithdraw", 'receiver.call("")', "receiver", "call"),
            balance_write("unsafeWithdraw"),
        ],
        "guardedWithdraw": [
            member_call("guardedWithdraw", 'receiver.call("")', "receiver", "call"),
            balance_write("guardedWithdraw"),
        ],
        "effectsFirst": [
            balance_write("effectsFirst"),
            member_call("effectsFirst", 'receiver.call("")', "receiver", "call"),
        ],
    }

    functions: list[dict[str, Any]] = []
    for name, identifier in function_ids.items():
        start, end = block_span(f"function {name}")
        modifiers: list[dict[str, Any]] = []
        if name == "guardedWithdraw":
            guard_start = source.index("nonReentrant", start, source.index("{", start))
            modifiers.append(
                {
                    "nodeType": "ModifierInvocation",
                    "src": src(guard_start, guard_start + len("nonReentrant")),
                    "modifierName": {
                        "nodeType": "IdentifierPath",
                        "name": "nonReentrant",
                        "namePath": "nonReentrant",
                    },
                }
            )
        functions.append(
            {
                "id": identifier,
                "nodeType": "FunctionDefinition",
                "kind": "function",
                "name": name,
                "visibility": "internal" if name == "_book" else "external",
                "stateMutability": "nonpayable",
                "src": src(start, end),
                "modifiers": modifiers,
                "body": {
                    "nodeType": "Block",
                    "src": src(source.index("{", start), end),
                    "statements": function_bodies[name],
                },
            }
        )

    contract_start, contract_end = block_span("contract CallControl")
    modifier_start, modifier_end = block_span("modifier nonReentrant")
    balance_start = source.index("mapping(address => uint256) public balances;")
    artifact_root.mkdir()
    (artifact_root / "CallControl.json").write_text(
        json.dumps(
            {
                "sourceName": "src/CallControl.sol",
                "ast": {
                    "nodeType": "SourceUnit",
                    "src": src(0, len(source)),
                    "nodes": [
                        {
                            "id": 1,
                            "nodeType": "ContractDefinition",
                            "contractKind": "contract",
                            "name": "CallControl",
                            "src": src(contract_start, contract_end),
                            "baseContracts": [],
                            "nodes": [
                                {
                                    "id": 2,
                                    "nodeType": "VariableDeclaration",
                                    "name": "balances",
                                    "stateVariable": True,
                                    "visibility": "public",
                                    "mutability": "mutable",
                                    "src": src(
                                        balance_start,
                                        balance_start
                                        + len("mapping(address => uint256) public balances;"),
                                    ),
                                },
                                {
                                    "id": 3,
                                    "nodeType": "ModifierDefinition",
                                    "name": "nonReentrant",
                                    "src": src(modifier_start, modifier_end),
                                },
                                *functions,
                            ],
                        }
                    ],
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_ast_call_and_reentrancy_graphs_distinguish_guarded_near_miss(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "semantic_calls")
    artifact_root = tmp_path / "call-control-ast"
    _write_call_control_ast(root / "src" / "CallControl.sol", artifact_root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [artifact_root])
    graphs = build_solidity_graphs(discovery, build)
    entities = {entity.name: entity for entity in build.index.entities}
    files = {item.relative_path: item for item in discovery.files}
    compiler_edges = [
        edge for edge in graphs.edges if edge.provenance is SolidityProvenance.COMPILER
    ]

    internal = next(
        edge
        for edge in compiler_edges
        if edge.graph is SolidityGraphKind.INTERNAL_CALL
        and edge.source_id == entities["callInternal"].id
    )
    assert internal.target_id == entities["_book"].id
    assert internal.metadata["resolution"] == "referenced_declaration"
    assert any(
        edge.graph is SolidityGraphKind.EXTERNAL_CALL
        and edge.source_id == entities["callExternal"].id
        and edge.metadata["call_kind"] == "external_call"
        for edge in compiler_edges
    )
    assert any(
        edge.graph is SolidityGraphKind.LOW_LEVEL_CALL
        and edge.source_id == entities["callLowLevel"].id
        and edge.metadata["call_kind"] == "low_level_call"
        for edge in compiler_edges
    )
    assert any(
        edge.graph is SolidityGraphKind.DELEGATECALL
        and edge.source_id == entities["callDelegate"].id
        and edge.metadata["call_kind"] == "delegatecall"
        for edge in compiler_edges
    )
    compiler_dependencies = [
        edge for edge in compiler_edges if edge.graph is SolidityGraphKind.DEPENDENCY
    ]
    assert {edge.metadata.get("dependency_resolution") for edge in compiler_dependencies} == {
        "compiler_expression_reference"
    }
    assert {
        entities["callExternal"].id,
        entities["callLowLevel"].id,
        entities["callDelegate"].id,
    } <= {edge.source_id for edge in compiler_dependencies}

    reentrancy_edges = [
        edge for edge in compiler_edges if edge.graph is SolidityGraphKind.REENTRANCY
    ]
    by_function = {edge.metadata["function_id"]: edge for edge in reentrancy_edges}
    unsafe = by_function[entities["unsafeWithdraw"].id]
    guarded = by_function[entities["guardedWithdraw"].id]
    assert unsafe.metadata["control_classification"] == "no_named_reentrancy_guard"
    assert unsafe.metadata["unsafe_transition_candidate"] is True
    assert unsafe.metadata["guard_candidates"] == []
    assert guarded.metadata["control_classification"] == "named_reentrancy_guard_present"
    assert guarded.metadata["unsafe_transition_candidate"] is False
    assert guarded.metadata["guard_candidates"] == ["nonReentrant"]
    assert entities["effectsFirst"].id not in by_function
    for edge in [internal, unsafe, guarded]:
        file = files[edge.path]
        assert edge.source_hash == line_range_hash(file.content, edge.start_line, edge.end_line)
        assert edge.start_line <= edge.end_line

    specialist_projection = compact_solidity_graphs(
        graphs,
        role="specialist:reentrancy_control_flow",
        max_edges=4,
    )
    assert specialist_projection is not None
    projected_controls = {
        edge.metadata.get("control_classification")
        for edge in specialist_projection.edges
        if edge.graph is SolidityGraphKind.REENTRANCY
        and edge.provenance is SolidityProvenance.COMPILER
    }
    assert projected_controls == {
        "no_named_reentrancy_guard",
        "named_reentrancy_guard_present",
    }
    verifier_projection = compact_solidity_graphs(
        graphs,
        role="verifier",
        max_edges=5,
        preferred_paths={"src/CallControl.sol"},
    )
    assert verifier_projection is not None
    assert verifier_projection.edges
    assert all(edge.path == "src/CallControl.sol" for edge in verifier_projection.edges)
    serialized_projection = verifier_projection.model_dump_json()
    assert "unsafe_transition_candidate" in serialized_projection
    assert "source_order_external_call_before_state_write" in serialized_projection

    context_builder = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
        solidity_projects=projects,
        solidity_index=build.index,
        solidity_graphs=graphs,
        planned_packages=2,
    )
    specialist_context = context_builder.build(
        "specialist:reentrancy_control_flow",
        requested_budget=250_000,
    )
    verifier_context = context_builder.build(
        "verifier",
        requested_budget=250_000,
        preferred_paths={"src/CallControl.sol"},
    )
    for rendered in (render_context(specialist_context), render_context(verifier_context)):
        assert '"control_classification": "no_named_reentrancy_guard"' in rendered
        assert '"control_classification": "named_reentrancy_guard_present"' in rendered
        assert "source_order_external_call_before_state_write" in rendered


def test_accounting_graphs_separate_state_access_asset_operations_and_endpoints(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "semantic_accounting")
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)

    def function_id(contract: str, name: str) -> str:
        return next(
            entity.id
            for entity in build.index.entities
            if entity.contract_name == contract
            and entity.name == name
            and entity.kind.value == "function"
        )

    unsafe_deposit = function_id("UnsafeNominalLedger", "deposit")
    safe_deposit = function_id("SafeObservedLedger", "deposit")
    unsafe_withdraw = function_id("UnsafeNominalLedger", "withdraw")
    safe_withdraw = function_id("SafeObservedLedger", "withdraw")
    unsafe_credit = next(
        entity.id
        for entity in build.index.entities
        if entity.contract_name == "UnsafeNominalLedger"
        and entity.name == "credit"
        and entity.kind.value == "state_variable"
    )
    asset_edges = [edge for edge in graphs.edges if edge.graph is SolidityGraphKind.ASSET_FLOW]

    unsafe_deposit_operations = {
        edge.metadata.get("operation") for edge in asset_edges if edge.source_id == unsafe_deposit
    }
    safe_deposit_operations = {
        edge.metadata.get("operation") for edge in asset_edges if edge.source_id == safe_deposit
    }
    assert unsafe_deposit_operations == {"deposit", "transfer"}
    assert safe_deposit_operations == {
        "balance_observation",
        "deposit",
        "transfer",
    }
    assert (
        sum(
            edge.metadata.get("operation") == "balance_observation"
            and edge.source_id == safe_deposit
            for edge in asset_edges
        )
        >= 2
    )

    lifecycle_operations = {
        edge.metadata.get("operation")
        for edge in asset_edges
        if edge.metadata.get("classification") == "function_name"
        and edge.metadata.get("target") == "LifecycleLedger"
    }
    assert lifecycle_operations == {
        "mint",
        "burn",
        "deposit",
        "withdraw",
        "reward",
        "claim",
        "liquidation",
    }
    directions_by_operation = {
        str(edge.metadata["operation"]): edge.metadata["flow_direction"]
        for edge in asset_edges
        if edge.metadata.get("classification") == "function_name"
    }
    assert directions_by_operation["mint"] == "source"
    assert directions_by_operation["deposit"] == "source"
    assert directions_by_operation["reward"] == "source"
    assert directions_by_operation["burn"] == "sink"
    assert directions_by_operation["withdraw"] == "sink"
    assert directions_by_operation["claim"] == "sink"
    assert directions_by_operation["liquidation"] == "sink"

    unsafe_credit_edges = [
        edge
        for edge in graphs.edges
        if edge.source_id == unsafe_deposit
        and edge.target_id == unsafe_credit
        and edge.graph
        in {
            SolidityGraphKind.STATE_READ,
            SolidityGraphKind.STATE_WRITE,
        }
    ]
    assert {edge.graph for edge in unsafe_credit_edges} == {
        SolidityGraphKind.STATE_READ,
        SolidityGraphKind.STATE_WRITE,
    }
    ordering_edges = [edge for edge in graphs.edges if edge.graph is SolidityGraphKind.REENTRANCY]
    assert any(
        edge.metadata.get("function_id") == unsafe_withdraw
        and edge.metadata.get("unsafe_transition_candidate") is True
        for edge in ordering_edges
    )
    assert all(edge.metadata.get("function_id") != safe_withdraw for edge in ordering_edges)

    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[],
    )
    assert coverage.asset_flow_operation_counts["balance_observation"] >= 2
    assert coverage.asset_flow_operation_counts["liquidation"] == 1
    assert coverage.asset_flow_direction_counts["source"] >= 3
    assert coverage.asset_flow_direction_counts["sink"] >= 4
    assert coverage.quality_metrics["asset_flows_classified"].percentage == 100

    projected = compact_solidity_graphs(
        graphs,
        role="specialist:accounting_invariant",
        max_edges=12,
        preferred_paths={"src/AccountingFlows.sol"},
    )
    assert projected is not None
    projected_operations = {
        edge.metadata.get("operation")
        for edge in projected.edges
        if edge.graph is SolidityGraphKind.ASSET_FLOW
    }
    assert {"deposit", "balance_observation"} <= projected_operations
    assert all(
        edge.source_hash
        == line_range_hash(
            next(item for item in discovery.files if item.relative_path == edge.path).content,
            edge.start_line,
            edge.end_line,
        )
        for edge in projected.edges
    )


def test_control_dependency_graphs_preserve_resolved_and_unknown_evidence(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "semantic_controls")
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)

    def function_id(contract: str, name: str) -> str:
        return next(
            entity.id
            for entity in build.index.entities
            if entity.contract_name == contract
            and entity.name == name
            and entity.kind.value == "function"
        )

    unsafe_drain = function_id("UnsafeRoleDrain", "drain")
    safe_rescue = function_id("SafeRoleDrain", "rescue")
    delayed_execute = function_id("TimelockedGovernor", "execute")
    immediate_execute = function_id("ImmediateGovernor", "execute")
    unsafe_quote = function_id("UnsafeOracleConsumer", "quote")
    safe_quote = function_id("SafeOracleConsumer", "quote")

    privilege_edges = [edge for edge in graphs.edges if edge.graph is SolidityGraphKind.PRIVILEGE]
    unsafe_control = next(edge for edge in privilege_edges if edge.source_id == unsafe_drain)
    assert unsafe_control.metadata["control_resolution"] == "unknown"
    assert unsafe_control.metadata["control_kind"] == "unresolved_sensitive_surface"
    assert (
        next(node for node in graphs.nodes if node.id == unsafe_control.target_id).kind
        is SolidityGraphNodeKind.UNKNOWN
    )
    safe_controls = [edge for edge in privilege_edges if edge.source_id == safe_rescue]
    assert safe_controls
    assert {edge.metadata.get("control_resolution") for edge in safe_controls} == {"resolved"}

    governance_edges = [edge for edge in graphs.edges if edge.graph is SolidityGraphKind.GOVERNANCE]
    assert {
        edge.metadata.get("stage")
        for edge in governance_edges
        if edge.source_id
        in {
            function_id("TimelockedGovernor", "queue"),
            delayed_execute,
        }
    } == {"queue", "execute"}
    delayed_control = next(edge for edge in governance_edges if edge.source_id == delayed_execute)
    immediate_control = next(
        edge for edge in governance_edges if edge.source_id == immediate_execute
    )
    assert delayed_control.metadata["authorization_control"] == "present"
    assert delayed_control.metadata["delay_control"] == "present"
    assert immediate_control.metadata["authorization_control"] == "present"
    assert immediate_control.metadata["delay_control"] == "unknown"

    oracle_edges = [
        edge for edge in graphs.edges if edge.graph is SolidityGraphKind.ORACLE_DEPENDENCY
    ]
    unsafe_oracle = next(edge for edge in oracle_edges if edge.source_id == unsafe_quote)
    safe_oracle = next(edge for edge in oracle_edges if edge.source_id == safe_quote)
    assert unsafe_oracle.metadata["freshness_validation"] == "unknown"
    assert safe_oracle.metadata["freshness_validation"] == "present"
    assert {
        unsafe_oracle.metadata["dependency_resolution"],
        safe_oracle.metadata["dependency_resolution"],
    } == {"source_reference_only"}
    dependency_edges = [edge for edge in graphs.edges if edge.graph is SolidityGraphKind.DEPENDENCY]
    assert {unsafe_quote, safe_quote} <= {edge.source_id for edge in dependency_edges}

    fixture_file = next(
        item for item in discovery.files if item.relative_path == "src/ControlDependencies.sol"
    )
    for edge in [*privilege_edges, *governance_edges, *oracle_edges, *dependency_edges]:
        assert edge.source_hash == line_range_hash(
            fixture_file.content,
            edge.start_line,
            edge.end_line,
        )
        assert edge.transformation

    access_projection = compact_solidity_graphs(
        graphs,
        role="specialist:access_control",
        max_edges=1,
    )
    governance_projection = compact_solidity_graphs(
        graphs,
        role="specialist:governance_timelock",
        max_edges=8,
    )
    oracle_projection = compact_solidity_graphs(
        graphs,
        role="specialist:oracle_price_manipulation",
        max_edges=4,
    )
    dependency_projection = compact_solidity_graphs(
        graphs,
        role="specialist:dependency_supply_chain",
        max_edges=12,
    )
    assert access_projection is not None
    assert access_projection.edges[0].metadata.get("control_resolution") == "unknown"
    assert governance_projection is not None
    assert any(
        edge.graph is SolidityGraphKind.GOVERNANCE
        and edge.metadata.get("delay_control") == "unknown"
        for edge in governance_projection.edges
    )
    assert oracle_projection is not None
    assert {
        edge.metadata.get("freshness_validation")
        for edge in oracle_projection.edges
        if edge.graph is SolidityGraphKind.ORACLE_DEPENDENCY
    } == {"present", "unknown"}
    assert dependency_projection is not None
    assert any(edge.graph is SolidityGraphKind.DEPENDENCY for edge in dependency_projection.edges)

    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[],
    )
    assert coverage.control_resolution_counts["unknown"] >= 1
    assert coverage.control_resolution_counts["resolved"] >= 1
    assert coverage.governance_stage_counts == {"execute": 2, "queue": 1}
    assert coverage.dependency_resolution_counts["source_reference_only"] >= 2
    assert coverage.oracle_freshness_counts == {"present": 1, "unknown": 1}
    serialized = coverage.model_dump_json()
    assert '"control_resolution_counts"' in serialized
    assert '"oracle_freshness_counts"' in serialized


def _write_upgrade_layout_artifacts(artifact_root: Path) -> None:
    artifact_root.mkdir()
    types = {
        "t_address": {"label": "address", "numberOfBytes": "20"},
        "t_uint128": {"label": "uint128", "numberOfBytes": "16"},
        "t_uint256": {"label": "uint256", "numberOfBytes": "32"},
        "t_gap48": {"label": "uint256[48]", "numberOfBytes": str(48 * 32)},
        "t_gap47": {"label": "uint256[47]", "numberOfBytes": str(47 * 32)},
    }
    layouts = {
        "BaseAccessStorage": [
            ("owner", "0", 0, "t_address"),
        ],
        "LayoutV1": [
            ("owner", "0", 0, "t_address"),
            ("fee", "1", 0, "t_uint128"),
            ("limit", "1", 16, "t_uint128"),
            ("__gap", "2", 0, "t_gap48"),
        ],
        "LayoutV2Safe": [
            ("owner", "0", 0, "t_address"),
            ("fee", "1", 0, "t_uint128"),
            ("limit", "1", 16, "t_uint128"),
            ("newValue", "2", 0, "t_uint256"),
            ("__gap", "3", 0, "t_gap47"),
        ],
        "LayoutV2Unsafe": [
            ("owner", "0", 0, "t_address"),
            ("newValue", "1", 0, "t_uint256"),
            ("fee", "2", 0, "t_uint128"),
            ("limit", "2", 16, "t_uint128"),
            ("__gap", "3", 0, "t_gap47"),
        ],
    }
    source_name = "src/UpgradeLayouts.sol"
    for contract_name, entries in layouts.items():
        payload = {
            "contractName": contract_name,
            "sourceName": source_name,
            "storageLayout": {
                "storage": [
                    {
                        "astId": position + 1,
                        "contract": f"{source_name}:{contract_name}",
                        "label": label,
                        "offset": offset,
                        "slot": slot,
                        "type": type_id,
                    }
                    for position, (label, slot, offset, type_id) in enumerate(entries)
                ],
                "types": types,
            },
        }
        (artifact_root / f"{contract_name}.json").write_text(
            json.dumps(payload, sort_keys=True),
            encoding="utf-8",
        )


def test_proxy_initializer_and_versioned_storage_layout_evidence_is_exact(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "semantic_upgrade_layout")
    artifact_root = tmp_path / "storage-layout-artifacts"
    _write_upgrade_layout_artifacts(artifact_root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [artifact_root])
    graphs = build_solidity_graphs(discovery, build)
    source = next(
        item for item in discovery.files if item.relative_path == "src/UpgradeLayouts.sol"
    )

    compiler_layout = [
        entry for entry in graphs.storage_layout if entry.provenance is SolidityProvenance.COMPILER
    ]
    assert len(compiler_layout) == 15
    inherited_owner_entries = [
        entry
        for entry in compiler_layout
        if entry.variable_name == "owner" and entry.contract_name != "BaseAccessStorage"
    ]
    assert {entry.contract_name for entry in inherited_owner_entries} == {
        "LayoutV1",
        "LayoutV2Safe",
        "LayoutV2Unsafe",
    }
    assert {entry.declaring_contract_name for entry in inherited_owner_entries} == {
        "BaseAccessStorage"
    }
    assert all(entry.ast_id is not None for entry in compiler_layout)
    assert all(
        entry.source_hash == line_range_hash(source.content, entry.start_line, entry.end_line)
        for entry in compiler_layout
    )

    compatibility_edges = [
        edge for edge in graphs.edges if edge.graph is SolidityGraphKind.UPGRADE_COMPATIBILITY
    ]
    packed = next(
        edge
        for edge in compatibility_edges
        if edge.metadata.get("comparison") is None
        and edge.metadata.get("left_type") == "uint128"
        and edge.metadata.get("right_type") == "uint128"
        and edge.metadata.get("packed") is True
    )
    assert packed.provenance is SolidityProvenance.COMPILER
    assert packed.metadata["collision"] is False
    assert packed.metadata["layout_resolution"] == "compiler"

    version_edges = [
        edge
        for edge in compatibility_edges
        if edge.metadata.get("comparison") == "versioned_layout"
    ]
    safe_edges = [
        edge for edge in version_edges if edge.metadata.get("to_contract") == "LayoutV2Safe"
    ]
    unsafe_edges = [
        edge for edge in version_edges if edge.metadata.get("to_contract") == "LayoutV2Unsafe"
    ]
    assert safe_edges
    assert {edge.metadata.get("compatibility") for edge in safe_edges} == {"compatible"}
    assert any(
        edge.metadata.get("change_kind") == "new_variable"
        and edge.metadata.get("storage_gap_consumption") is True
        for edge in safe_edges
    )
    assert any(
        edge.metadata.get("variable") == "__gap"
        and edge.metadata.get("compatibility") == "compatible"
        for edge in safe_edges
    )
    assert {
        edge.metadata.get("variable")
        for edge in unsafe_edges
        if edge.metadata.get("compatibility") == "incompatible"
    } >= {"fee", "limit", "newValue"}
    assert all(
        edge.provenance is SolidityProvenance.COMPILER
        and edge.transformation == "compiler_storage_layout_version_comparison"
        and edge.source_hash == line_range_hash(source.content, edge.start_line, edge.end_line)
        for edge in version_edges
    )

    slot_edges = [
        edge
        for edge in graphs.edges
        if edge.graph is SolidityGraphKind.STORAGE_LAYOUT and edge.metadata.get("slot_kind")
    ]
    assert {edge.metadata["slot_kind"] for edge in slot_edges} == {
        "admin",
        "implementation",
    }
    initializer_edges = [
        edge for edge in graphs.edges if edge.graph is SolidityGraphKind.INITIALIZER
    ]
    guard_by_contract = {
        next(
            entity.contract_name for entity in build.index.entities if entity.id == edge.source_id
        ): edge.metadata["guard_resolution"]
        for edge in initializer_edges
    }
    assert guard_by_contract == {
        "LayoutV1": "unknown",
        "LayoutV2Safe": "named_guard",
        "LayoutV2Unsafe": "unknown",
    }

    projection = compact_solidity_graphs(
        graphs,
        role="specialist:upgradeability_storage",
        max_edges=60,
        preferred_paths={"src/UpgradeLayouts.sol"},
    )
    assert projection is not None
    assert {
        SolidityGraphKind.INITIALIZER,
        SolidityGraphKind.STORAGE_LAYOUT,
        SolidityGraphKind.UPGRADE_COMPATIBILITY,
    } <= {edge.graph for edge in projection.edges}
    assert "versioned_layout" in projection.model_dump_json()

    fallback_build = build_solidity_index(discovery, projects, [])
    fallback_graphs = build_solidity_graphs(discovery, fallback_build)
    fallback_layout = [
        entry for entry in fallback_graphs.storage_layout if entry.contract_name == "LayoutV1"
    ]
    assert fallback_layout
    assert all(
        entry.provenance is SolidityProvenance.HEURISTIC
        and entry.confidence < min(item.confidence for item in compiler_layout)
        for entry in fallback_layout
    )
    assert all(
        edge.metadata.get("layout_resolution") == "unknown_estimate"
        and edge.metadata.get("compatibility") == "unknown"
        for edge in fallback_graphs.edges
        if edge.graph is SolidityGraphKind.UPGRADE_COMPATIBILITY
        and edge.source_id in {entry.id for entry in fallback_layout}
    )


def test_bridge_event_and_offchain_dependencies_keep_heuristic_assumptions_explicit(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "semantic_bridge")
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    source = next(item for item in discovery.files if item.relative_path == "src/BridgeRelayer.sol")

    def function_id(contract: str, name: str) -> str:
        return next(
            entity.id
            for entity in build.index.entities
            if entity.contract_name == contract
            and entity.name == name
            and entity.kind.value == "function"
        )

    unsafe_receive = function_id("UnsafeBridgeEndpoint", "receiveMessage")
    safe_receive = function_id("SafeBridgeEndpoint", "receiveMessage")
    unsafe_dispatch = function_id("UnsafeBridgeEndpoint", "dispatch")
    safe_dispatch = function_id("SafeBridgeEndpoint", "dispatch")
    fulfill_price = function_id("RelayedOracleRequest", "fulfillPrice")

    message_edges = [edge for edge in graphs.edges if edge.graph is SolidityGraphKind.CROSS_CHAIN]
    assert message_edges
    assert all(
        edge.provenance is SolidityProvenance.HEURISTIC
        and edge.confidence < 0.8
        and edge.metadata.get("classification") == "heuristic_source_pattern"
        and edge.metadata.get("deterministic_fact") is False
        for edge in message_edges
    )
    inbound_by_function = {
        edge.source_id: edge
        for edge in message_edges
        if edge.metadata.get("direction") == "inbound"
    }
    unsafe_inbound = inbound_by_function[unsafe_receive]
    safe_inbound = inbound_by_function[safe_receive]
    for field_name in (
        "authentication_evidence",
        "replay_protection_evidence",
        "finality_evidence",
    ):
        assert unsafe_inbound.metadata[field_name] == "unknown"
        assert safe_inbound.metadata[field_name] == "present"
    assert {unsafe_dispatch, safe_dispatch} <= {
        edge.source_id for edge in message_edges if edge.metadata.get("direction") == "outbound"
    }

    event_edges = [edge for edge in graphs.edges if edge.graph is SolidityGraphKind.EVENT_FLOW]
    assert event_edges
    assert {
        edge.metadata.get("event")
        for edge in event_edges
        if edge.source_id in {unsafe_receive, safe_receive}
    } == {"MessageProcessed"}
    assert all(
        edge.provenance is SolidityProvenance.HEURISTIC
        and edge.metadata.get("event_resolution") == "indexed_source_declaration"
        for edge in event_edges
    )

    offchain_edges = [
        edge for edge in graphs.edges if edge.graph is SolidityGraphKind.OFFCHAIN_DEPENDENCY
    ]
    assert offchain_edges
    assert all(
        edge.provenance is SolidityProvenance.HEURISTIC
        and edge.metadata.get("deterministic_fact") is False
        for edge in offchain_edges
        if "deterministic_fact" in edge.metadata
    )
    event_dependencies = [
        edge
        for edge in offchain_edges
        if edge.metadata.get("classification") == "heuristic_event_name"
    ]
    assert event_dependencies
    assert all(
        edge.metadata.get("delivery_assumption") == "unknown"
        and edge.metadata.get("ordering_assumption") == "unknown"
        and edge.metadata.get("consumer_resolution") == "unknown"
        for edge in event_dependencies
    )
    callback = next(edge for edge in offchain_edges if edge.source_id == fulfill_price)
    assert callback.metadata["authentication_resolution"] == "present"
    assert callback.metadata["delivery_assumption"] == "unknown"

    for edge in [*message_edges, *event_edges, *offchain_edges]:
        assert edge.source_hash == line_range_hash(
            source.content,
            edge.start_line,
            edge.end_line,
        )
        assert edge.transformation

    projection = compact_solidity_graphs(
        graphs,
        role="specialist:cross_chain_bridge",
        max_edges=30,
        preferred_paths={"src/BridgeRelayer.sol"},
    )
    assert projection is not None
    assert {
        SolidityGraphKind.CROSS_CHAIN,
        SolidityGraphKind.EVENT_FLOW,
        SolidityGraphKind.OFFCHAIN_DEPENDENCY,
    } <= {edge.graph for edge in projection.edges}
    serialized = SolidityGraphSet.model_validate_json(graphs.model_dump_json()).model_dump_json()
    assert '"deterministic_fact":false' in serialized
    assert '"finality_evidence":"unknown"' in serialized


def test_full_semantic_graphs_are_built_with_explicit_fallback_provenance(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "semantic")
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)

    assert set(graphs.analyzed_graphs) == set(SolidityGraphKind)
    populated = {edge.graph for edge in graphs.edges}
    assert {
        SolidityGraphKind.DELEGATECALL,
        SolidityGraphKind.LOW_LEVEL_CALL,
        SolidityGraphKind.STATE_WRITE,
        SolidityGraphKind.ASSET_FLOW,
        SolidityGraphKind.PRIVILEGE,
        SolidityGraphKind.PROXY,
        SolidityGraphKind.ORACLE_DEPENDENCY,
        SolidityGraphKind.EVENT_STATE,
        SolidityGraphKind.SIGNATURE_REPLAY,
        SolidityGraphKind.REENTRANCY,
        SolidityGraphKind.STORAGE_LAYOUT,
    } <= populated
    assert all(edge.source_hash for edge in graphs.edges if edge.path)
    assert all(edge.transformation for edge in graphs.edges)
    assert any(
        edge.graph is SolidityGraphKind.DELEGATECALL
        and edge.provenance is SolidityProvenance.HEURISTIC
        and edge.confidence < 0.6
        for edge in graphs.edges
    )
    asset_edges = [edge for edge in graphs.edges if edge.graph is SolidityGraphKind.ASSET_FLOW]
    assert any(
        edge.metadata.get("member") == "transfer"
        and edge.metadata.get("asset_standard") == "erc20_like"
        and edge.metadata.get("flow_direction") == "transfer"
        for edge in asset_edges
    )
    compact_token_graphs = compact_solidity_graphs(
        graphs,
        role="specialist:token_standard",
        max_edges=1,
    )
    assert compact_token_graphs is not None
    assert compact_token_graphs.edges[0].graph is SolidityGraphKind.ASSET_FLOW
    deposited = next(
        entity
        for entity in build.index.entities
        if entity.kind.value == "event" and entity.name == "Deposited"
    )
    total_assets = next(
        entity
        for entity in build.index.entities
        if entity.kind.value == "state_variable" and entity.name == "totalAssets"
    )
    permit_deposit = next(
        entity
        for entity in build.index.entities
        if entity.kind.value == "function" and entity.name == "permitDeposit"
    )
    assert any(
        edge.graph is SolidityGraphKind.EVENT_STATE
        and edge.source_id == deposited.id
        and edge.target_id == total_assets.id
        and edge.provenance is SolidityProvenance.HEURISTIC
        for edge in graphs.edges
    )
    assert any(
        edge.graph is SolidityGraphKind.EVENT_FLOW
        and edge.target_id == deposited.id
        and edge.provenance is SolidityProvenance.HEURISTIC
        and edge.metadata.get("event_resolution") == "indexed_source_declaration"
        for edge in graphs.edges
    )
    signature_edges = [
        edge
        for edge in graphs.edges
        if edge.graph is SolidityGraphKind.SIGNATURE_REPLAY and edge.source_id == permit_deposit.id
    ]
    assert signature_edges
    assert {edge.metadata.get("aspect") for edge in signature_edges} >= {
        "signature_primitive",
        "chain_id",
        "contract_domain",
        "nonce_or_deadline",
    }


def test_compiler_ast_builds_event_state_and_signature_replay_edges(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "ast-graphs"
    source_dir = root / "src"
    source_dir.mkdir(parents=True)
    source = """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
contract SignedLedger {
    event Deposited(address account, uint256 amount);
    mapping(address => uint256) public nonces;
    uint256 public totalAssets;
    function permitDeposit(uint256 amount, bytes32 digest, uint8 v, bytes32 r, bytes32 s) external {
        totalAssets += amount;
        nonces[msg.sender] += 1;
        require(ecrecover(digest, v, r, s) != address(0));
        uint256 domainChain = block.chainid;
        emit Deposited(msg.sender, amount);
    }
}
"""
    source_path = source_dir / "SignedLedger.sol"
    source_path.write_text(source, encoding="utf-8")

    def src(fragment: str) -> str:
        start = source.index(fragment)
        return f"{start}:{len(fragment)}:0"

    function_source = source[
        source.index("    function permitDeposit") : source.rindex("    }") + 5
    ]
    assignment_source = "totalAssets += amount"
    nonce_source = "nonces[msg.sender] += 1"
    recover_source = "ecrecover(digest, v, r, s)"
    chain_source = "block.chainid"
    emit_source = "emit Deposited(msg.sender, amount);"
    artifact_root = tmp_path / "compiler-artifacts"
    artifact_root.mkdir()
    (artifact_root / "SignedLedger.json").write_text(
        json.dumps(
            {
                "sourceName": "src/SignedLedger.sol",
                "ast": {
                    "nodeType": "SourceUnit",
                    "nodes": [
                        {
                            "id": 1,
                            "nodeType": "ContractDefinition",
                            "contractKind": "contract",
                            "name": "SignedLedger",
                            "src": src(source[source.index("contract SignedLedger") :]),
                            "nodes": [
                                {
                                    "id": 2,
                                    "nodeType": "EventDefinition",
                                    "name": "Deposited",
                                    "src": src("event Deposited(address account, uint256 amount);"),
                                },
                                {
                                    "id": 3,
                                    "nodeType": "VariableDeclaration",
                                    "name": "nonces",
                                    "stateVariable": True,
                                    "visibility": "public",
                                    "src": src("mapping(address => uint256) public nonces;"),
                                },
                                {
                                    "id": 4,
                                    "nodeType": "VariableDeclaration",
                                    "name": "totalAssets",
                                    "stateVariable": True,
                                    "visibility": "public",
                                    "src": src("uint256 public totalAssets;"),
                                },
                                {
                                    "id": 5,
                                    "nodeType": "FunctionDefinition",
                                    "kind": "function",
                                    "name": "permitDeposit",
                                    "visibility": "external",
                                    "stateMutability": "nonpayable",
                                    "src": src(function_source),
                                    "modifiers": [],
                                    "body": {
                                        "nodeType": "Block",
                                        "statements": [
                                            {
                                                "nodeType": "ExpressionStatement",
                                                "expression": {
                                                    "nodeType": "Assignment",
                                                    "operator": "+=",
                                                    "src": src(assignment_source),
                                                    "leftHandSide": {
                                                        "nodeType": "Identifier",
                                                        "name": "totalAssets",
                                                        "referencedDeclaration": 4,
                                                        "src": src("totalAssets"),
                                                    },
                                                },
                                            },
                                            {
                                                "nodeType": "ExpressionStatement",
                                                "expression": {
                                                    "nodeType": "Assignment",
                                                    "operator": "+=",
                                                    "src": src(nonce_source),
                                                    "leftHandSide": {
                                                        "nodeType": "IndexAccess",
                                                        "referencedDeclaration": 3,
                                                        "src": src("nonces[msg.sender]"),
                                                    },
                                                },
                                            },
                                            {
                                                "nodeType": "ExpressionStatement",
                                                "expression": {
                                                    "nodeType": "FunctionCall",
                                                    "src": src(recover_source),
                                                    "expression": {
                                                        "nodeType": "Identifier",
                                                        "name": "ecrecover",
                                                    },
                                                },
                                            },
                                            {
                                                "nodeType": "MemberAccess",
                                                "memberName": "chainid",
                                                "src": src(chain_source),
                                                "expression": {
                                                    "nodeType": "Identifier",
                                                    "name": "block",
                                                },
                                            },
                                            {
                                                "nodeType": "EmitStatement",
                                                "src": src(emit_source),
                                                "eventCall": {
                                                    "nodeType": "FunctionCall",
                                                    "src": src("Deposited(msg.sender, amount)"),
                                                    "expression": {
                                                        "nodeType": "Identifier",
                                                        "name": "Deposited",
                                                        "referencedDeclaration": 2,
                                                    },
                                                },
                                            },
                                        ],
                                    },
                                },
                            ],
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [artifact_root])
    graphs = build_solidity_graphs(discovery, build)
    event = next(entity for entity in build.index.entities if entity.name == "Deposited")
    total = next(entity for entity in build.index.entities if entity.name == "totalAssets")
    nonces = next(entity for entity in build.index.entities if entity.name == "nonces")
    function = next(entity for entity in build.index.entities if entity.name == "permitDeposit")

    compiler_state_access = [
        edge
        for edge in graphs.edges
        if edge.source_id == function.id
        and edge.target_id in {total.id, nonces.id}
        and edge.graph
        in {
            SolidityGraphKind.STATE_READ,
            SolidityGraphKind.STATE_WRITE,
        }
        and edge.provenance is SolidityProvenance.COMPILER
    ]
    assert {(edge.target_id, edge.graph) for edge in compiler_state_access} == {
        (total.id, SolidityGraphKind.STATE_READ),
        (total.id, SolidityGraphKind.STATE_WRITE),
        (nonces.id, SolidityGraphKind.STATE_READ),
        (nonces.id, SolidityGraphKind.STATE_WRITE),
    }
    assert all(
        edge.metadata.get("read_modify_write") is True
        for edge in compiler_state_access
        if edge.graph is SolidityGraphKind.STATE_READ
    )
    assert all(
        edge.metadata.get("write_semantics") == "read_modify_write"
        for edge in compiler_state_access
        if edge.graph is SolidityGraphKind.STATE_WRITE
    )
    assert any(
        edge.graph is SolidityGraphKind.EVENT_STATE
        and edge.source_id == event.id
        and edge.target_id == total.id
        and edge.provenance is SolidityProvenance.COMPILER
        for edge in graphs.edges
    )
    assert any(
        edge.graph is SolidityGraphKind.EVENT_FLOW
        and edge.source_id == function.id
        and edge.target_id == event.id
        and edge.provenance is SolidityProvenance.COMPILER
        and edge.metadata.get("event_resolution") == "referenced_declaration"
        for edge in graphs.edges
    )
    compiler_signature_edges = [
        edge
        for edge in graphs.edges
        if edge.graph is SolidityGraphKind.SIGNATURE_REPLAY
        and edge.source_id == function.id
        and edge.provenance is SolidityProvenance.COMPILER
    ]
    assert {edge.metadata.get("aspect") for edge in compiler_signature_edges} >= {
        "signature_primitive",
        "chain_id",
        "nonces",
    }


def test_invariant_discovery_is_source_linked_and_never_claims_protocol_intent(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "semantic")
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    suite = discover_invariants(discovery, build.index, graphs, config.invariants)

    assert "erc4626_vault" in suite.protocol_profiles
    assert {invariant.category for invariant in suite.invariants} >= {
        InvariantCategory.ACCOUNTING,
        InvariantCategory.AUTHORIZATION,
        InvariantCategory.STATE_MACHINE,
        InvariantCategory.ECONOMIC,
    }
    assert {invariant.template for invariant in suite.invariants} >= {
        InvariantTemplate.ERC4626_CONVERSION_SANITY,
        InvariantTemplate.AUTHORIZED_UPGRADE,
        InvariantTemplate.INITIALIZE_ONCE,
        InvariantTemplate.ORACLE_MANIPULATION_RESISTANCE,
        InvariantTemplate.PERMIT_REPLAY_PROTECTION,
    }
    assert all(invariant.locations for invariant in suite.invariants)
    assert all(
        location.content_hash for invariant in suite.invariants for location in invariant.locations
    )
    assert all(
        invariant.provenance is SolidityProvenance.HEURISTIC for invariant in suite.invariants
    )
    assert any("not verified protocol intent" in warning for warning in suite.warnings)


def test_minimal_erc4626_like_vault_discovers_donation_inflation_invariant(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "economic_erc4626")
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    suite = discover_invariants(discovery, build.index, graphs, config.invariants)

    assert "erc4626_vault" in suite.protocol_profiles
    donation = [
        invariant
        for invariant in suite.invariants
        if invariant.template is InvariantTemplate.DONATION_INFLATION_RESISTANCE
    ]
    assert donation
    assert any(
        location.path == "src/EconomicVaults.sol"
        for invariant in donation
        for location in invariant.locations
    )
    assert all(invariant.provenance is SolidityProvenance.HEURISTIC for invariant in donation)


def test_fallback_indexed_public_vault_state_still_binds_donation_invariant(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "maximum_assurance_protocol")
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    suite = discover_invariants(discovery, build.index, graphs, config.invariants)

    donation = [
        invariant
        for invariant in suite.invariants
        if invariant.template is InvariantTemplate.DONATION_INFLATION_RESISTANCE
    ]

    assert donation
    assert any(
        location.path == "src/InflationVault.sol"
        for invariant in donation
        for location in invariant.locations
    )


def test_slither_normalization(vulnerable_repo: Path, tmp_path: Path) -> None:
    raw = {
        "success": True,
        "results": {
            "detectors": [
                {
                    "check": "reentrancy-eth",
                    "impact": "High",
                    "confidence": "Medium",
                    "description": "Synthetic reentrancy issue",
                    "elements": [
                        {
                            "type": "function",
                            "name": "withdraw",
                            "source_mapping": {
                                "filename_relative": "app.py",
                                "lines": [11, 12],
                            },
                        }
                    ],
                }
            ]
        },
    }
    findings = SlitherScanner().parse(vulnerable_repo, json.dumps(raw), tmp_path)
    assert len(findings) == 1
    assert findings[0].scanner == "slither"
    assert findings[0].rule_id == "reentrancy-eth"
    assert findings[0].locations[0].path == "app.py"


@pytest.mark.parametrize(
    "scanner_status",
    [
        ScannerStatus.UNAVAILABLE,
        ScannerStatus.INTERPRETER_OR_LOADER_FAILURE,
    ],
)
def test_coverage_reports_denominators(
    tmp_path: Path,
    config_factory,
    scanner_status: ScannerStatus,
) -> None:
    root = _copy_fixture(tmp_path, "foundry")
    discovery = discover_repository(root, config_factory().repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config_factory().smart_contracts)
    compilation = compile_solidity_projects(
        root, projects, config_factory().smart_contracts, tmp_path / "private"
    )
    build = build_solidity_index(discovery, projects, compilation.artifact_roots)
    graphs = build_solidity_graphs(discovery, build)
    run = ScannerRun(
        scanner="slither",
        status=scanner_status,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        duration_seconds=0,
    )
    skipped = ScannerRun(
        scanner="codeql",
        status=ScannerStatus.SKIPPED,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        duration_seconds=0,
        error="disabled by synthetic test configuration",
    )
    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=compilation.results,
        index=build.index,
        graphs=graphs,
        scanner_runs=[run, skipped],
    )
    assert coverage.projects_discovered == 1
    assert coverage.files_discovered >= 2
    assert coverage.contracts_indexed >= 2
    assert coverage.functions_indexed >= 3
    assert coverage.tools_unavailable == ["slither"]
    indexed = coverage.quality_metrics["solidity_files_indexed"]
    assert indexed.denominator == coverage.files_discovered
    assert indexed.percentage is not None
    scanner_completion = coverage.quality_metrics["scanner_completion"]
    assert scanner_completion.numerator == 0
    assert scanner_completion.denominator == 1
    assert scanner_completion.population == 2
    assert [exclusion.subject for exclusion in scanner_completion.exclusions] == ["codeql[1]"]
    assert scanner_completion.failures == [f"slither: scanner status {scanner_status.value}"]
    compiler_contracts = coverage.quality_metrics["compiler_contracts_indexed"]
    assert compiler_contracts.denominator >= coverage.contracts_indexed
    assert compiler_contracts.population == compiler_contracts.denominator
    assert compiler_contracts.failures
    dependencies = coverage.quality_metrics["dependency_resolution"]
    assert dependencies.denominator == 1
    assert dependencies.numerator == 0
    asset_flows = coverage.quality_metrics["asset_flows_classified"]
    assert asset_flows.denominator >= 1
    assert asset_flows.numerator == asset_flows.denominator
    for metric in coverage.quality_metrics.values():
        assert metric.population == metric.denominator + len(metric.exclusions)
        assert metric.provenance
        assert 0 <= metric.confidence <= 1
        if metric.denominator == 0:
            assert bool(metric.not_applicable_evidence) != bool(metric.failures)


def test_scanner_completion_excludes_not_applicable_and_retains_typed_failures(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "foundry")
    discovery = discover_repository(root, config_factory().repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config_factory().smart_contracts)
    compilation = compile_solidity_projects(
        root, projects, config_factory().smart_contracts, tmp_path / "private"
    )
    build = build_solidity_index(discovery, projects, compilation.artifact_roots)
    graphs = build_solidity_graphs(discovery, build)
    now = datetime.now(UTC)

    def typed_exit(
        scanner: str,
        status: ScannerStatus,
        *,
        preparation: str | None = None,
    ) -> ScannerRun:
        return ScannerRun(
            scanner=scanner,
            status=status,
            command=[scanner, "scan"],
            started_at=now,
            finished_at=now,
            duration_seconds=0,
            error=f"synthetic {status.value} diagnostic",
            raw_output_path=f"{scanner}/{scanner}.json",
            raw_output_sha256="1" * 64,
            private_stderr_path=f"{scanner}/{scanner}.stderr.txt",
            private_stderr_sha256="2" * 64,
            private_stderr_bytes=1,
            operator_preparation_step=preparation,
            process_exit_code=1,
        )

    not_applicable = typed_exit("osv", ScannerStatus.NOT_APPLICABLE)
    unmet = typed_exit(
        "trivy",
        ScannerStatus.UNMET_PREREQUISITE,
        preparation="prepare_trivy_offline_vulnerability_database",
    )
    silent = typed_exit("slither", ScannerStatus.SILENT_FAILURE)
    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=compilation.results,
        index=build.index,
        graphs=graphs,
        scanner_runs=[not_applicable, unmet, silent],
    )

    scanner_completion = coverage.quality_metrics["scanner_completion"]
    assert scanner_completion.numerator == 0
    assert scanner_completion.denominator == 2
    assert scanner_completion.population == 3
    assert [exclusion.subject for exclusion in scanner_completion.exclusions] == ["osv[0]"]
    assert scanner_completion.exclusions[0].provenance is CoverageProvenance.DISCOVERY
    assert scanner_completion.failures == [
        "trivy: scanner status unmet_prerequisite",
        "slither: scanner status silent_failure",
    ]
    assert coverage.tools_failed == ["slither"]

    not_applicable_only = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=compilation.results,
        index=build.index,
        graphs=graphs,
        scanner_runs=[not_applicable],
    ).quality_metrics["scanner_completion"]
    assert not_applicable_only.denominator == 0
    assert not_applicable_only.population == 1
    assert len(not_applicable_only.exclusions) == 1
    assert not not_applicable_only.failures
    assert not_applicable_only.not_applicable_evidence == [
        "all inventoried scanners were explicitly skipped or not applicable"
    ]

    def success_run(
        scanner: str,
        *,
        evidence: ExecutionEvidenceKind,
        machine_output_validated: bool,
    ) -> ScannerRun:
        run = ScannerRun(
            scanner=scanner,
            status=ScannerStatus.SUCCESS,
            execution_evidence=evidence,
            version="1.0.0",
            executable_sha256="3" * 64,
            command=[scanner, "scan"],
            started_at=now,
            finished_at=now,
            duration_seconds=0,
            raw_output_path=f"{scanner}/{scanner}.json",
            raw_output_sha256="4" * 64,
            raw_output_bytes=2,
            process_exit_code=0,
            isolation_backend="sandbox-exec",
            isolation_attestation_sha256="5" * 64,
            machine_output_validated=machine_output_validated,
        )
        return ScannerRun.model_validate(
            {
                **run.model_dump(mode="json"),
                "execution_observation_sha256": run.expected_execution_observation_sha256(),
            }
        )

    mock_success = success_run(
        "semgrep",
        evidence=ExecutionEvidenceKind.MOCK,
        machine_output_validated=True,
    )
    unvalidated_success = success_run(
        "trivy",
        evidence=ExecutionEvidenceKind.REAL,
        machine_output_validated=False,
    )
    unqualified_successes = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=compilation.results,
        index=build.index,
        graphs=graphs,
        scanner_runs=[mock_success, unvalidated_success],
    ).quality_metrics["scanner_completion"]
    assert unqualified_successes.numerator == 0
    assert unqualified_successes.denominator == 2
    assert unqualified_successes.failures == [
        "semgrep: execution evidence is mock, not real",
        "trivy: machine output was not strictly validated",
    ]


def test_coverage_metric_rejects_denominator_shrinking() -> None:
    with pytest.raises(
        ValidationError,
        match="population must equal denominator plus explicit exclusions",
    ):
        CoverageMetric(
            numerator=1,
            denominator=1,
            population=3,
            percentage=100,
            exclusions=[
                CoverageExclusion(
                    subject="explicitly-excluded",
                    reason="synthetic exclusion evidence",
                    provenance=CoverageProvenance.CONFIGURATION,
                )
            ],
            not_applicable_evidence=[],
            confidence=1,
            provenance=[CoverageProvenance.DISCOVERY],
            failures=[],
            state=AnalysisState.DETERMINISTIC,
            detail="Synthetic denominator consistency check.",
        )


def test_economic_template_coverage_rejects_inconsistent_lifecycle_counts() -> None:
    with pytest.raises(
        ValidationError,
        match="status counts must match generated harnesses",
    ):
        EconomicTemplateExecutionCoverage(
            kind=EconomicSimulationKind.ERC4626_DONATION,
            applicable=True,
            execution_required=True,
            typed_harness_available=True,
            harnesses_generated=2,
            harnesses_compiled=2,
            harnesses_executed=2,
            harnesses_replayed=2,
            counterexamples=1,
            counterexamples_minimized=1,
            statuses={InvariantExecutionStatus.PASSED: 1},
        )


def test_independent_coverage_gate_prevents_aggregate_masking() -> None:
    complete = CoverageMetric(
        numerator=9,
        denominator=9,
        population=9,
        percentage=100,
        exclusions=[],
        not_applicable_evidence=[],
        confidence=1,
        provenance=[CoverageProvenance.SYMBOL_INDEX],
        failures=[],
        state=AnalysisState.DETERMINISTIC,
        detail="Synthetic complete dimension.",
    )
    uncovered = CoverageMetric(
        numerator=0,
        denominator=1,
        population=1,
        percentage=0,
        exclusions=[],
        not_applicable_evidence=[],
        confidence=1,
        provenance=[CoverageProvenance.SEMANTIC_GRAPH],
        failures=["one required semantic edge was not classified"],
        state=AnalysisState.ATTEMPTED_FAILED,
        detail="Synthetic incomplete dimension.",
    )
    failed_empty = CoverageMetric(
        numerator=0,
        denominator=0,
        population=0,
        percentage=None,
        exclusions=[],
        not_applicable_evidence=[],
        confidence=1,
        provenance=[CoverageProvenance.RUNTIME],
        failures=["required runtime inventory was not produced"],
        state=AnalysisState.ATTEMPTED_FAILED,
        detail="Synthetic failed empty dimension.",
    )
    complete_with_inventory_failure = complete.model_copy(
        update={
            "failures": ["one upstream population source failed"],
            "state": AnalysisState.ATTEMPTED_FAILED,
        }
    )
    coverage = SolidityCoverage(
        quality_metrics={
            "complete_dimension": complete,
            "uncovered_dimension": uncovered,
            "failed_empty_dimension": failed_empty,
            "complete_with_inventory_failure": complete_with_inventory_failure,
        }
    )
    assert CoverageMetric.model_validate_json(complete.model_dump_json()) == complete

    complete_gate = _coverage_quality_gate(
        coverage,
        metric_name="complete_dimension",
        gate="complete_dimension",
        threshold=0.8,
        required=True,
    )
    uncovered_gate = _coverage_quality_gate(
        coverage,
        metric_name="uncovered_dimension",
        gate="uncovered_dimension",
        threshold=0.8,
        required=True,
    )
    failed_empty_gate = _coverage_quality_gate(
        coverage,
        metric_name="failed_empty_dimension",
        gate="failed_empty_dimension",
        threshold=0.8,
        required=True,
    )
    inventory_failure_gate = _coverage_quality_gate(
        coverage,
        metric_name="complete_with_inventory_failure",
        gate="complete_with_inventory_failure",
        threshold=0.8,
        required=True,
    )

    assert complete_gate.passed
    assert not uncovered_gate.passed
    assert "failures=1" in uncovered_gate.detail
    assert not failed_empty_gate.passed
    assert "failure evidence" in failed_empty_gate.detail
    assert not inventory_failure_gate.passed
    assert "denominator_integrity_failed=True" in inventory_failure_gate.detail
