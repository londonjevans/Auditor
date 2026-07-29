from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

import httpx
import pytest

from mmaudit.config import ReproductionConfig, SmartContractsConfig
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    RepositoryCodeExecutionState,
    RepositorySuiteExecutionPolicy,
    RepositorySuiteSelection,
    RepositoryTestExecution,
    RepositoryTestExecutionStatus,
    ScannerRun,
    ScannerStatus,
)
from mmaudit.orchestration.replay import _scanner_projection
from mmaudit.scanners.foundry import FoundryForkScanner
from mmaudit.solidity.reproduction import default_isolation_backend


def _unused_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_for_anvil(endpoint: str) -> None:
    with httpx.Client(timeout=0.5, trust_env=False) as client:
        for attempt in range(100):
            try:
                response = client.post(
                    endpoint,
                    json={
                        "jsonrpc": "2.0",
                        "id": attempt + 1,
                        "method": "eth_chainId",
                        "params": [],
                    },
                )
                if response.status_code == 200:
                    return
            except httpx.RequestError:
                pass
            time.sleep(0.05)
    raise AssertionError("disposable local Anvil did not become ready")


def _pinned_solidity_compiler() -> tuple[Path, str, str]:
    raw_solc = os.environ.get("MMAUDIT_TEST_SOLC_EXECUTABLE", "")
    if not raw_solc:
        pytest.skip("explicit pinned integration-test Solidity compiler is unavailable")
    solc = Path(raw_solc)
    if (
        not solc.is_absolute()
        or solc.is_symlink()
        or not solc.is_file()
        or solc.resolve(strict=True) != solc
    ):
        pytest.skip("integration-test Solidity compiler path is not canonical and regular")
    result = subprocess.run(
        [str(solc), "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            "HOME": os.devnull,
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "PATH": "/usr/bin:/bin",
        },
        shell=False,
    )
    match = re.search(r"\bVersion:\s*([0-9]+\.[0-9]+\.[0-9]+)\b", result.stdout)
    if result.returncode != 0 or match is None:
        pytest.skip("integration-test Solidity compiler version could not be attested")
    return solc, match.group(1), hashlib.sha256(solc.read_bytes()).hexdigest()


def test_real_foundry_repository_suite_classifies_pinned_local_fork_portfolio(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forge = shutil.which("forge")
    anvil = shutil.which("anvil")
    if forge is None or anvil is None:
        pytest.skip("Foundry toolchain is unavailable")
    solc, solc_version, solc_sha256 = _pinned_solidity_compiler()
    backend = default_isolation_backend("sandbox-exec")
    if backend is None:
        pytest.skip("process-attested sandbox-exec isolation is unavailable")

    root = tmp_path / "synthetic-repository"
    (root / "src").mkdir(parents=True)
    (root / "test" / "audit").mkdir(parents=True)
    (root / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\ntest = "test"\n',
        encoding="utf-8",
    )
    (root / "src" / "Placeholder.sol").write_text(
        "pragma solidity >=0.8.0 <0.9.0; contract Placeholder {}\n",
        encoding="utf-8",
    )
    (root / "test" / "audit" / "RepositorySuite.t.sol").write_text(
        "\n".join(
            (
                "pragma solidity >=0.8.0 <0.9.0;",
                "contract SyntheticInvariantState {",
                "    uint256 public value;",
                "    function setValue(uint256 next) external { value = next; }",
                "}",
                "contract RepositorySuiteTest {",
                "    SyntheticInvariantState internal state;",
                "    function setUp() public { state = new SyntheticInvariantState(); }",
                "    function touch(uint256 next) public { state.setValue(next); }",
                "    function testPinnedForkPasses() public view {",
                "        assert(block.chainid == 31337);",
                "    }",
                "    function testFuzzPinnedFork(uint256) public view {",
                "        assert(block.chainid == 31337);",
                "    }",
                "    function invariantPinnedForkState() public view {",
                "        assert(address(state) != address(0));",
                "    }",
                "    function testPinnedForkAssertionFailure() public view {",
                "        assert(block.chainid == 1);",
                "    }",
                "}",
                "",
            )
        ),
        encoding="utf-8",
    )

    port = _unused_loopback_port()
    endpoint = f"http://127.0.0.1:{port}"
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path / "anvil-home"),
        "TMPDIR": str(tmp_path / "anvil-tmp"),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
    }
    Path(environment["HOME"]).mkdir()
    Path(environment["TMPDIR"]).mkdir()
    process = subprocess.Popen(
        [
            anvil,
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--chain-id",
            "31337",
            "--silent",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
        shell=False,
        start_new_session=True,
    )
    try:
        _wait_for_anvil(endpoint)
        monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", endpoint)
        monkeypatch.setenv("MMAUDIT_SOLC_EXECUTABLE", str(solc))
        scanner = FoundryForkScanner(
            SmartContractsConfig(
                allow_fork_probing=True,
                solc_version=solc_version,
                solc_sha256=solc_sha256,
                foundry_fuzz_runs=4,
                foundry_invariant_runs=2,
            ),
            reproduction=ReproductionConfig(
                expected_chain_id=31_337,
                pinned_block_number=0,
            ),
        )
        runs = [
            scanner.run(
                root,
                tmp_path / private_name,
                120,
                backend=backend,
            )
            for private_name in ("private-first", "private-replay")
        ]
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    run, replay_run = runs
    assert run.status is ScannerStatus.SUCCESS, run.error
    assert replay_run.status is ScannerStatus.SUCCESS, replay_run.error
    assert _scanner_projection(run) == _scanner_projection(replay_run)
    assert ScannerRun.model_validate_json(run.model_dump_json()) == run
    assert run.execution_evidence is ExecutionEvidenceKind.REAL
    assert run.repository_code_execution is RepositoryCodeExecutionState.ISOLATED
    assert run.repository_suite_selection is not None
    assert run.repository_suite_selection.selected_test_count == 4
    assert len(run.repository_test_executions) == 4
    executions = {execution.test_name: execution for execution in run.repository_test_executions}
    assert executions["testPinnedForkPasses"].status is RepositoryTestExecutionStatus.PASSED
    assert executions["testFuzzPinnedFork"].status is RepositoryTestExecutionStatus.PASSED
    assert executions["invariantPinnedForkState"].status is RepositoryTestExecutionStatus.PASSED
    failure = executions["testPinnedForkAssertionFailure"]
    assert failure.status is RepositoryTestExecutionStatus.ASSERTION_FAILED
    assert all(execution.chain_id == 31_337 for execution in executions.values())
    assert all(execution.block_number == 0 for execution in executions.values())
    assert all(execution.compiler_sha256 == solc_sha256 for execution in executions.values())
    assert all(execution.machine_output_validated for execution in executions.values())
    assert all(execution.safety_claim is False for execution in executions.values())
    assert run.foundry_summary is not None
    assert run.foundry_summary.unit_tests == 2
    assert run.foundry_summary.fuzz_tests == 1
    assert run.foundry_summary.invariant_tests == 1
    assert run.foundry_summary.passed_tests == 3
    assert run.foundry_summary.failed_tests == 1
    assert run.foundry_summary.fuzz_cases >= 4
    assert run.foundry_summary.invariant_runs >= 2
    assert run.foundry_summary.invariant_calls > 0
    assert all(execution.block_hash.startswith("0x") for execution in executions.values())
    observed_compiler_versions = {execution.compiler_version for execution in executions.values()}
    assert len(observed_compiler_versions) == 1
    assert solc_version in next(iter(observed_compiler_versions))
    assert all(execution.execution_policy_sha256 is not None for execution in executions.values())
    assert len(run.findings) == 1
    finding = run.findings[0]
    assert finding.rule_id == "repository-fork-test-failure"
    assert finding.metadata["repository_test_execution_sha256"] == failure.execution_sha256

    manifest_path = tmp_path / "private-first" / "repository-suite-execution.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    assert run.raw_output_sha256 == hashlib.sha256(manifest_bytes).hexdigest()
    assert run.raw_output_bytes == len(manifest_bytes)
    serialized_selection = RepositorySuiteSelection.model_validate(manifest["selection"])
    serialized_policy = RepositorySuiteExecutionPolicy.model_validate(manifest["execution_policy"])
    serialized_executions = [
        RepositoryTestExecution.model_validate(item) for item in manifest["executions"]
    ]
    assert serialized_selection == run.repository_suite_selection
    assert serialized_policy == run.repository_suite_execution_policy
    assert serialized_executions == run.repository_test_executions
    assert manifest["safety_claim"] is False
