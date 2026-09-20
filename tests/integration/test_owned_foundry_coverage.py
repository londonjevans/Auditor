"""Original coverage-owner handoff on disposable synthetic local forks; no audit authority."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest

import mmaudit.scanners.foundry_inventory_runner as inventory_runner
from mmaudit.config import RepositoryForkSuiteConfig, SmartContractsConfig
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    RepositorySuiteInventoryPhase,
    SolidityProjectMetadata,
    SolidityProjectType,
)
from mmaudit.scanners.base import scanner_workspace_sha256
from mmaudit.scanners.fork_rpc import observe_pinned_fork_rpc
from mmaudit.scanners.foundry import (
    _execute_foundry_debugger_trace,
    _execute_foundry_statement_coverage,
)
from mmaudit.scanners.repository_suite import select_foundry_repository_suite_from_inventory
from mmaudit.solidity.reproduction import MacOSSandboxBackend
from tests.integration.test_foundry_coverage_custody import FIXTURE
from tests.integration.test_mutation_compilation import _solc_0_8_30
from tests.integration.test_mutation_pipeline_execution import NativeLocalMutationBackend
from tests.integration.test_repository_foundry_fork_suite import (
    _unused_loopback_port,
    _wait_for_anvil,
)
from tests.property_reachability_support import inventory_snapshot


@pytest.mark.parametrize("project_root,style", [(".", "lf"), ("packages/local", "crlf")])
@pytest.mark.parametrize("transition", ["blocked", "permitted", "fuzz"])
def test_original_coverage_owner_retains_native_compilation_in_existing_sandbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, project_root: str, style: str, transition: str
) -> None:
    forge, anvil = Path.home() / ".foundry/bin/forge", Path.home() / ".foundry/bin/anvil"
    solc, sandbox = _solc_0_8_30(), Path("/usr/bin/sandbox-exec")
    if not forge.is_file() or not anvil.is_file() or solc is None or not sandbox.is_file():
        pytest.skip(
            "Requires existing external Forge/Anvil/solc and macOS sandbox; no provisioning"
        )
    forge, anvil, solc = (p.resolve(strict=True) for p in (forge, anvil, solc))
    repository = FIXTURE.parents[2]
    assert all(not p.is_relative_to(repository) for p in (forge, anvil, solc))
    private = tmp_path / "private"
    workspace = private / "workspace"
    project = workspace / project_root
    shutil.copytree(FIXTURE, project)
    if transition == "fuzz":
        shutil.copyfile(
            FIXTURE.parent / "coverage_trace_population/PopulationControl.t.sol",
            project / "test/PopulationControl.t.sol",
        )
    if style == "crlf":
        for path in project.rglob("*.sol"):
            path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    source_pin = scanner_workspace_sha256(workspace)
    copied_solc = private / "solc"
    shutil.copyfile(solc, copied_solc)
    copied_solc.chmod(0o500)
    forge_pin = hashlib.sha256(forge.read_bytes()).hexdigest()
    solc_pin = hashlib.sha256(solc.read_bytes()).hexdigest()
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
    version = (
        subprocess.run(
            [str(forge), "--version"],
            env=environment,
            capture_output=True,
            timeout=5,
            shell=False,
            check=True,
        )
        .stdout.decode()
        .splitlines()[0]
    )
    # Only test-local MOCK inventory custody. No runtime attestation is manufactured.
    monkeypatch.setattr(inventory_runner, "isolation_attestation_sha256", lambda _: "a" * 64)
    inventory = inventory_runner.run_foundry_test_inventory(
        workspace=workspace,
        private_dir=private,
        projects=(
            SolidityProjectMetadata(
                project_root=project_root,
                project_type=SolidityProjectType.FOUNDRY,
            ),
        ),
        phase=RepositorySuiteInventoryPhase.PRE_EXECUTION,
        forge_executable=forge,
        copied_solc=copied_solc,
        repository_sha256=source_pin,
        configuration_sha256="b" * 64,
        tool_version=version,
        tool_sha256=forge_pin,
        compiler_version="0.8.30",
        compiler_sha256=solc_pin,
        backend=NativeLocalMutationBackend(),
        timeout_seconds=30,
    )
    assert inventory.evidence.execution_evidence is ExecutionEvidenceKind.MOCK
    (tmp_path / "original-inventory.json").write_text(json.dumps(inventory_snapshot(inventory)))
    test_name = (
        "test_invariant_blocked_transition_preserves_counter"
        if transition == "blocked"
        else "test_invariant_permitted_transition_increments_once"
    )
    selected_test_path = "test/ModifierControl.t.sol"
    if transition == "fuzz":
        test_name = "testFuzz_invariant_transition_matches_permission"
        selected_test_path = "test/PopulationControl.t.sol"
    selection = select_foundry_repository_suite_from_inventory(
        inventory.evidence.projects[0].records,
        SmartContractsConfig(
            repository_suite=RepositoryForkSuiteConfig(
                profile="explicit",
                foundry_include_paths=((Path(project_root) / selected_test_path).as_posix(),),
                foundry_include_tests=(test_name,),
                hardhat_include_paths=(),
                hardhat_include_tests=(),
            )
        ),
        repository_sha256=source_pin,
        repository_exclusion_path=".mmaudit",
        inventory_sha256=inventory.evidence.normalized_inventory_sha256,
    )
    assert len(selection.tests) == 1
    port = _unused_loopback_port()
    endpoint = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [str(anvil), "--host", "127.0.0.1", "--port", str(port), "--chain-id", "31337", "--silent"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
        shell=False,
        start_new_session=True,
    )
    try:
        _wait_for_anvil(endpoint)
        fork = observe_pinned_fork_rpc(endpoint, expected_chain_id=31337, pinned_block_number=0)
        deadline = time.monotonic() + 30
        observation, usage = _execute_foundry_statement_coverage(
            descriptor=selection.tests[0],
            workspace=workspace,
            private_dir=private,
            output_index=0,
            executable_path=forge,
            executable_sha256=forge_pin,
            compiler_path=copied_solc,
            compiler_sha256=solc_pin,
            compiler_inputs=inventory.compiler_inputs,
            rpc_url=endpoint,
            rpc_port=port,
            fork=fork,
            fuzz_seed="0x" + "0" * 63 + "1",
            fuzz_runs=8,
            invariant_runs=2,
            deadline=deadline,
            max_output_bytes=8_000_000,
            max_output_entries=200,
            backend=MacOSSandboxBackend(str(sandbox)),
            base_environment=environment,
        )
        # The exact original inventory descriptor is shared, not an execution
        # receipt. Keep coverage output untouched and launch a separate debugger.
        coverage_receipt = private / observation.private_artifact_path / "launch-receipt.json"
        coverage_receipt_raw = coverage_receipt.read_bytes()
        debugger_process, debugger_usage = _execute_foundry_debugger_trace(
            descriptor=selection.tests[0],
            workspace=workspace,
            private_dir=private,
            output_index=0,
            executable_path=forge,
            executable_sha256=forge_pin,
            compiler_path=copied_solc,
            compiler_sha256=solc_pin,
            compiler_inputs=inventory.compiler_inputs,
            rpc_url=endpoint,
            rpc_port=port,
            fork=fork,
            fuzz_seed="0x" + "0" * 63 + "1",
            fuzz_runs=8,
            invariant_runs=2,
            deadline=deadline,
            max_output_bytes=8_000_000 - usage.bytes,
            max_output_entries=200 - usage.entries,
            backend=MacOSSandboxBackend(str(sandbox)),
            base_environment=environment,
        )
        assert usage.bytes + debugger_usage.bytes < 8_000_000
        assert usage.entries + debugger_usage.entries < 200
        debug_result = debugger_process.result
        retained = debugger_process.retained_payload(
            max_bytes=8_000_000 - usage.bytes - debugger_usage.bytes,
            deadline=deadline,
        )
        (tmp_path / "retained-debugger.json").write_text(json.dumps(retained, sort_keys=True))
        debug_result.observation.require_code_bound_steps()
        assert len(debug_result.observation.steps) > (100 if transition == "fuzz" else 500)
        assert len(debug_result.observation.frames) == 5
        assert len([c for c in debug_result.compiler_transcripts if c.stdin]) == 2
        assert debug_result.observation.descriptor_sha256 == observation.descriptor_sha256
        assert (
            debug_result.launch_receipt_sha256 != hashlib.sha256(coverage_receipt_raw).hexdigest()
        )
        assert coverage_receipt.read_bytes() == coverage_receipt_raw
        coverage_machine = json.loads(observation.debug_coverage.machine_json_bytes)
        coverage_result = next(iter(next(iter(coverage_machine.values()))["test_results"].values()))
        debugger_machine = json.loads(debug_result.stdout)
        debugger_result = next(iter(next(iter(debugger_machine.values()))["test_results"].values()))
        if transition == "fuzz":
            assert coverage_result["kind"]["Fuzz"]["runs"] == 8
        assert (
            debug_result.observation.execution_scope
            == "ONE_DEBUGGER_TRACE_NOT_FULL_TEST_OR_FUZZ_POPULATION"
        )
        (tmp_path / "original-debugger-observation.json").write_text(
            json.dumps(
                {
                    "scope": "SYNTHETIC_ORIGINAL_DEBUGGER_OWNER_NO_COVERAGE_OR_RUNTIME_AUTHORITY",
                    "descriptor_sha256": observation.descriptor_sha256,
                    "launch_plan_sha256": debug_result.launch_plan_sha256,
                    "launch_receipt_sha256": debug_result.launch_receipt_sha256,
                    "separate_coverage_receipt_sha256": hashlib.sha256(
                        coverage_receipt_raw
                    ).hexdigest(),
                    "machine_stdout_sha256": debug_result.observation.machine_stdout_sha256,
                    "debugger_dump_sha256": debug_result.observation.debugger_dump_sha256,
                    "compiler_transcript_sha256s": [
                        c.transcript_sha256 for c in debug_result.compiler_transcripts
                    ],
                    "steps": len(debug_result.observation.steps),
                    "frames": len(debug_result.observation.frames),
                    "original_coverage_kind": coverage_result["kind"],
                    "separate_debugger_kind": debugger_result["kind"],
                    "coverage_complete": False,
                    "execution_validated": False,
                },
                sort_keys=True,
            )
        )
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    assert process.poll() is not None
    assert scanner_workspace_sha256(workspace) == source_pin
    assert observation.process_exit_code == 0 and observation.machine_output_validated
    assert observation.private_artifact_sha256 == usage.artifact_sha256
    assert observation.private_artifact_bytes == usage.bytes < 8_000_000
    transcripts = observation.compiler_transcripts
    compilations = [r for r in transcripts if "--standard-json" in r.received_argv]
    assert len(compilations) == 1
    assert all(r.evidence_authority == "UNATTESTED_COMPILER_TRANSCRIPT" for r in transcripts)
    supplied = json.loads(compilations[0].stdin)["sources"]
    assert set(supplied) == {s.path for s in inventory.compiler_inputs[0].sources}
    assert all(
        supplied[s.path]["content"].encode() == s.content.replace(b"\r\n", b"\n")
        for s in inventory.compiler_inputs[0].sources
    )
    assert "--no-import-callback" in compilations[0].compiler_argv
    execution = private / observation.private_artifact_path
    receipt = json.loads((execution / "launch-receipt.json").read_bytes())
    assert receipt["runtime"]["transitive_native_dependency_closure_verified"] is False
    assert receipt["runtime"]["flags"] == {
        "isolated": 1,
        "ignore_environment": 1,
        "no_site": 1,
        "dont_write_bytecode": 1,
    }
    assert all(value for value in receipt["runtime"]["files"].values())
    profile = (private / "sandbox.sb").read_text()
    assert '(deny file-write* (subpath "' + str(private / "trusted-inputs") in profile
    assert f'(remote tcp "localhost:{port}")' in profile
    assert "(allow network-outbound)" not in profile
    (tmp_path / "owner-observation.json").write_text(
        json.dumps(
            {
                "scope": "SYNTHETIC_LOCAL_OWNER_HANDOFF_NO_AUDIT_OR_QUALIFICATION_AUTHORITY",
                "project_root": project_root,
                "line_style": style,
                "transition": transition,
                "source_sha256": source_pin,
                "forge_sha256": forge_pin,
                "solc_sha256": solc_pin,
                "artifact_sha256": usage.artifact_sha256,
                "artifact_bytes": usage.bytes,
                "compiler_transcript_sha256s": [r.transcript_sha256 for r in transcripts],
                "execution_validated": False,
                "coverage_complete": False,
                "qualification_eligible": False,
            },
            sort_keys=True,
        )
    )
