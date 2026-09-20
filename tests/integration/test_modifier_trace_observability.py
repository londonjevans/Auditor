"""Original compiler/trace modifier controls; observations never confer coverage authority."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import TypedDict
from urllib.parse import urlsplit

import pytest

from mmaudit.config import RepositoryForkSuiteConfig, SmartContractsConfig
from mmaudit.isolation.provenance import isolation_execution_evidence
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    RepositorySuiteInventoryPhase,
    SolidityProjectMetadata,
    SolidityProjectType,
)
from mmaudit.scanners.base import scanner_workspace_sha256
from mmaudit.scanners.fork_rpc import observe_pinned_fork_rpc
from mmaudit.scanners.foundry import _execute_foundry_debugger_trace
from mmaudit.scanners.foundry_inventory_runner import run_foundry_test_inventory
from mmaudit.scanners.read_only_rpc import ReadOnlyRpcBridge
from mmaudit.scanners.repository_suite import select_foundry_repository_suite_from_inventory
from mmaudit.solidity.reproduction import default_isolation_backend
from tests.integration.test_mutation_compilation import _solc_0_8_30
from tests.integration.test_repository_foundry_fork_suite import (
    _unused_loopback_port,
    _wait_for_anvil,
)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/modifier_witness"
CASES = (
    "single_allowed",
    "single_blocked",
    "nested",
    "repeated",
    "conditional_left",
    "conditional_right",
    "early_return",
    "empty",
    "internal",
)


class _ScopeBoundary(TypedDict):
    attempt_binding_sha256: str
    selection_sha256: str
    descriptor_sha256: str
    sequence_index: int


@pytest.mark.parametrize("case", CASES)
def test_original_modifier_trace_retains_full_compiler_and_local_invariant(
    tmp_path: Path, case: str
) -> None:
    forge, anvil = Path.home() / ".foundry/bin/forge", Path.home() / ".foundry/bin/anvil"
    solc = _solc_0_8_30()
    if (
        not forge.is_file()
        or not anvil.is_file()
        or solc is None
        or not Path("/usr/bin/sandbox-exec").is_file()
    ):
        pytest.skip(
            "Requires existing external Forge/Anvil/solc and macOS sandbox; no provisioning"
        )
    forge, anvil, solc = (p.resolve(strict=True) for p in (forge, anvil, solc))
    assert all(not p.is_relative_to(FIXTURE.parents[2]) for p in (forge, anvil, solc))
    forge_pin, solc_pin = (hashlib.sha256(p.read_bytes()).hexdigest() for p in (forge, solc))
    assert forge_pin == "d59ceec9d2075b1792e552289c2a4d8ac8b19195d9a6c6a76c066586a7f32757"
    assert solc_pin == "738dcdc6afddeb505ee4e4ef24f1c1fdba2b8c924e614cbbf5801a5b062dd683"
    backend = default_isolation_backend("sandbox-exec")
    assert backend is not None
    assert isolation_execution_evidence(backend) is ExecutionEvidenceKind.REAL
    private, environment = (
        tmp_path / "private",
        {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    workspace = private / "workspace"
    shutil.copytree(FIXTURE, workspace)
    source_pin = scanner_workspace_sha256(workspace)
    copied_solc = private / "solc"
    shutil.copyfile(solc, copied_solc)
    copied_solc.chmod(0o500)
    version = (
        subprocess.run(
            [str(forge), "--version"],
            capture_output=True,
            timeout=5,
            check=True,
            shell=False,
            env=environment,
        )
        .stdout.decode()
        .splitlines()[0]
    )
    config = SmartContractsConfig(
        repository_suite=RepositoryForkSuiteConfig(
            profile="explicit",
            foundry_include_paths=("test/ModifierWitness.t.sol",),
            foundry_include_tests=(f"test_{case}",),
            hardhat_include_paths=(),
            hardhat_include_tests=(),
        )
    )
    inventory = run_foundry_test_inventory(
        workspace=workspace,
        private_dir=private,
        projects=(
            SolidityProjectMetadata(project_root=".", project_type=SolidityProjectType.FOUNDRY),
        ),
        phase=RepositorySuiteInventoryPhase.PRE_EXECUTION,
        forge_executable=forge,
        copied_solc=copied_solc,
        repository_sha256=source_pin,
        configuration_sha256=config.repository_suite.stable_hash(),
        tool_version=version,
        tool_sha256=forge_pin,
        compiler_version="0.8.30",
        compiler_sha256=solc_pin,
        backend=backend,
        timeout_seconds=30,
    )
    (tmp_path / "original-inventory.json").write_text(inventory.evidence.model_dump_json())
    selection = select_foundry_repository_suite_from_inventory(
        inventory.evidence.projects[0].records,
        config,
        repository_sha256=source_pin,
        repository_exclusion_path=".mmaudit",
        inventory_sha256=inventory.evidence.normalized_inventory_sha256,
    )
    assert len(selection.tests) == 1
    port = _unused_loopback_port()
    endpoint = f"http://127.0.0.1:{port}"
    node = subprocess.Popen(
        [str(anvil), "--host", "127.0.0.1", "--port", str(port), "--chain-id", "31337", "--silent"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
        shell=False,
        start_new_session=True,
    )
    try:
        _wait_for_anvil(endpoint)
        fork = observe_pinned_fork_rpc(endpoint, expected_chain_id=31337, pinned_block_number=0)
        with ReadOnlyRpcBridge(
            endpoint,
            expected_chain_id=31337,
            pinned_block_number=0,
            pinned_block_hash=fork.block_hash,
            timeout_seconds=3,
        ) as bridge:
            rpc_port = urlsplit(bridge.endpoint).port
            assert rpc_port is not None
            boundary = _ScopeBoundary(
                attempt_binding_sha256=hashlib.sha256(b"synthetic-modifier-trace").hexdigest(),
                selection_sha256=selection.selection_sha256,
                descriptor_sha256=selection.tests[0].descriptor_sha256,
                sequence_index=1,
            )
            bridge.begin_selected_test_scope(**boundary)
            deadline = time.monotonic() + 30
            try:
                process, usage = _execute_foundry_debugger_trace(
                    descriptor=selection.tests[0],
                    workspace=workspace,
                    private_dir=private,
                    output_index=0,
                    executable_path=forge,
                    executable_sha256=forge_pin,
                    compiler_path=copied_solc,
                    compiler_sha256=solc_pin,
                    compiler_inputs=inventory.compiler_inputs,
                    rpc_url=bridge.endpoint,
                    rpc_port=rpc_port,
                    fork=fork,
                    fuzz_seed="0x" + "0" * 63 + "1",
                    fuzz_runs=8,
                    invariant_runs=2,
                    deadline=deadline,
                    max_output_bytes=8_000_000,
                    max_output_entries=200,
                    backend=backend,
                    base_environment=environment,
                )
            finally:
                scope = bridge.end_selected_test_scope(**boundary)
            assert scope.verify() and scope.status == "validated"
            retained = process.retained_payload(max_bytes=16_000_000, deadline=deadline)
            (tmp_path / "retained-debugger.json").write_text(json.dumps(retained, sort_keys=True))
        observation = process.result.observation
        observation.require_code_bound_steps()
        assert observation.test_status == "Success"
        assert observation.execution_scope == "ONE_DEBUGGER_TRACE_NOT_FULL_TEST_OR_FUZZ_POPULATION"
        assert retained["runtime_authority"] is retained["coverage_complete"] is False
        assert usage.bytes == process.private_artifact_bytes < 8_000_000
        assert scanner_workspace_sha256(workspace) == source_pin
        selected = [s for s in observation.steps if s.source_path == "src/ModifierWitness.sol"]
        (tmp_path / "original-depth-observations.json").write_text(
            json.dumps(
                {
                    "case": case,
                    "runtime_authority": False,
                    "coverage_complete": False,
                    "source_sha256": source_pin,
                    "steps": len(observation.steps),
                    "frames": len(observation.frames),
                    "selected_source_steps": [
                        {
                            "ordinal": s.ordinal,
                            "pc": s.pc,
                            "span": s.original_span,
                            "depth": s.modifier_depth,
                            "phase": s.phase,
                        }
                        for s in selected
                    ],
                },
                sort_keys=True,
            )
        )
    finally:
        node.terminate()
        try:
            node.wait(timeout=3)
        except subprocess.TimeoutExpired:
            node.kill()
            node.wait(timeout=3)
    assert node.poll() is not None
