"""Original automatic suite on synthetic local source with genuine sandbox/RPC custody."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from mmaudit.config import RepositoryForkSuiteConfig, ReproductionConfig, SmartContractsConfig
from mmaudit.isolation.provenance import isolation_attestation_sha256, isolation_execution_evidence
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    RepositorySuiteInventoryPhase,
    RepositoryTestExecutionStatus,
    ScannerStatus,
    SolidityProjectMetadata,
    SolidityProjectType,
)
from mmaudit.repository.discovery import DiscoveredFile, DiscoveryResult
from mmaudit.scanners.base import scanner_workspace_sha256
from mmaudit.scanners.fork_rpc import observe_pinned_fork_rpc
from mmaudit.scanners.foundry import FoundryForkScanner
from mmaudit.scanners.foundry_inventory_runner import run_foundry_test_inventory
from mmaudit.scanners.foundry_statement_coverage import parse_forge_debug_statement_coverage
from mmaudit.scanners.foundry_statement_producer import FoundryStatementCoverageGaps
from mmaudit.scanners.read_only_rpc import ReadOnlyRpcBridge
from mmaudit.solidity.coverage import build_audited_suite_entity_catalog
from mmaudit.solidity.index import build_solidity_index
from mmaudit.solidity.reproduction import default_isolation_backend
from tests.integration.test_mutation_compilation import _solc_0_8_30
from tests.integration.test_repository_foundry_fork_suite import (
    _unused_loopback_port,
    _wait_for_anvil,
)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/coverage_compilation"


@pytest.mark.parametrize("control", ["inline", "modifier", "double_increment"])
def test_original_configured_suite_dispatches_primary_coverage_and_debugger(
    tmp_path: Path, control: str
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
    forge, anvil, solc = (path.resolve(strict=True) for path in (forge, anvil, solc))
    assert not any(path.is_relative_to(FIXTURE.parents[2]) for path in (forge, anvil, solc))
    forge_pin = hashlib.sha256(forge.read_bytes()).hexdigest()
    solc_pin = hashlib.sha256(solc.read_bytes()).hexdigest()
    assert forge_pin == "d59ceec9d2075b1792e552289c2a4d8ac8b19195d9a6c6a76c066586a7f32757"
    assert solc_pin == "738dcdc6afddeb505ee4e4ef24f1c1fdba2b8c924e614cbbf5801a5b062dd683"

    # Real built-in preflight: synthetic canaries and a disposable loopback listener.
    # No admission, inventory, execution result or scope predicate is monkeypatched.
    backend = default_isolation_backend("sandbox-exec")
    assert backend is not None, "genuine built-in sandbox preflight is unavailable"
    assert isolation_execution_evidence(backend) is ExecutionEvidenceKind.REAL
    assert isolation_attestation_sha256(backend) is not None

    source = tmp_path / "synthetic-source"
    shutil.copytree(FIXTURE, source)
    if control != "modifier":
        shutil.copyfile(
            FIXTURE.parent
            / "coverage_configured_suite"
            / ("InlineControl.sol" if control == "inline" else "DoubleIncrementControl.sol"),
            source / "src/ModifierControl.sol",
        )
    shutil.copyfile(
        FIXTURE.parent / "coverage_trace_population/PopulationControl.t.sol",
        source / "test/PopulationControl.t.sol",
    )
    source_pin = scanner_workspace_sha256(source)
    project = SolidityProjectMetadata(
        project_root=".",
        project_type=SolidityProjectType.FOUNDRY,
        source_directories=["src"],
        test_directories=["test"],
    )
    config = SmartContractsConfig(
        allow_fork_probing=True,
        solc_version="0.8.30",
        solc_sha256=solc_pin,
        foundry_fuzz_runs=8,
        foundry_invariant_runs=2,
        max_fork_probe_seconds=120,
        repository_suite=RepositoryForkSuiteConfig(
            profile="explicit",
            foundry_include_paths=("test/*.t.sol",),
            foundry_include_tests=("testFuzz_*", "test_*"),
            hardhat_include_paths=(),
            hardhat_include_tests=(),
            per_test_timeout_seconds=30,
            total_timeout_seconds=120,
            max_output_bytes_per_test=8_000_000,
            max_total_output_bytes=32_000_000,
        ),
    )
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
    version = (
        subprocess.run(
            [str(forge), "--version"],
            env=environment,
            check=True,
            capture_output=True,
            timeout=5,
            shell=False,
        )
        .stdout.decode()
        .splitlines()[0]
    )

    # Produce the catalog from original compiler output before the suite's own inventories.
    index_private = tmp_path / "index-private"
    index_workspace = index_private / "workspace"
    shutil.copytree(source, index_workspace)
    copied_solc = index_private / "solc"
    shutil.copyfile(solc, copied_solc)
    copied_solc.chmod(0o500)
    original_inventory = run_foundry_test_inventory(
        workspace=index_workspace,
        private_dir=index_private,
        projects=(project,),
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
    (tmp_path / "original-index-inventory.json").write_text(
        original_inventory.evidence.model_dump_json()
    )
    artifacts = tmp_path / "index-artifacts"
    artifacts.mkdir()
    for number, raw in enumerate(original_inventory.compiler_inputs[0].build_info_jsons):
        (artifacts / f"build-{number:03d}.json").write_bytes(raw)
    sources = original_inventory.compiler_inputs[0].sources
    discovery = DiscoveryResult(
        root=source,
        files=tuple(
            DiscoveredFile(
                absolute_path=source / item.path,
                relative_path=item.path,
                content=item.content.decode(),
                size=len(item.content),
                lines=len(item.content.splitlines()),
                sha256=item.source_sha256,
                language="Solidity",
                categories=(),
            )
            for item in sources
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    built = build_solidity_index(discovery, [project], [artifacts])
    assert not built.index.fallback_sources
    catalog = build_audited_suite_entity_catalog(
        index=built.index,
        projects=[project],
        repository_sha256=source_pin,
        source_file_sha256s={item.path: item.source_sha256 for item in sources},
    )
    assert catalog.classification_complete and catalog.bindings
    (tmp_path / "original-source-catalog.json").write_text(catalog.model_dump_json())

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
        bridge = ReadOnlyRpcBridge(
            endpoint,
            expected_chain_id=fork.chain_id,
            pinned_block_number=fork.block_number,
            pinned_block_hash=fork.block_hash,
            timeout_seconds=3,
        )
        with bridge:
            scanner = FoundryForkScanner(
                config,
                reproduction=ReproductionConfig(expected_chain_id=31337, pinned_block_number=0),
                projects=(project,),
                allow_fork_probing=True,
                expected_repository_sha256=source_pin,
                fork_rpc_url_override=bridge.endpoint,
                fork_rpc_scope_recorder=bridge,
                attempt_binding_sha256=hashlib.sha256(
                    b"synthetic-configured-suite-attempt"
                ).hexdigest(),
                audited_suite_entity_catalog=catalog,
                executable_path=forge,
                solc_path=solc,
            )
            run = scanner.run(
                source,
                tmp_path / "suite",
                120,
                backend=backend,
                expected_version=version,
                expected_sha256=forge_pin,
            )
        (tmp_path / "original-suite-result.json").write_text(run.model_dump_json())
        assert scanner_workspace_sha256(source) == source_pin
        assert len(run.repository_test_executions) == 4
        assert len(run.repository_test_fork_rpc_scopes) == (
            3 if control == "double_increment" else 4
        )
        assert bridge.snapshot().verify()
        if control == "modifier":
            assert run.status is ScannerStatus.FAILED
            assert run.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
            assert run.error is not None and "evidence finalization failed" in run.error
            assert "FoundryStatementCoverageProductionError" in run.error
            assert not run.machine_output_validated
            assert not run.repository_statement_coverage_evidence
            manifest_path = tmp_path / "suite/repository-suite-execution.json"
            raw_manifest = manifest_path.read_bytes()
            assert run.raw_output_path is not None
            assert run.raw_output_bytes == len(raw_manifest)
            assert run.raw_output_sha256 == hashlib.sha256(raw_manifest).hexdigest()
            manifest = json.loads(raw_manifest)
            assert manifest["schema_version"] == "1.4" and manifest["safety_claim"] is False
            assert "repository_statement_coverage_receipt" not in manifest
            assert "repository_statement_coverage_evidence" not in manifest
            assert "repository_statement_entity_catalog" not in manifest
            assert (
                manifest["unvalidated_statement_entity_catalog"]["catalog_sha256"]
                == catalog.catalog_sha256
            )
            gaps = FoundryStatementCoverageGaps.model_validate_json(
                json.dumps(manifest["repository_statement_observation_gaps"])
            )
            assert len(gaps.statements) == len(gaps.processes) == 4
            assert gaps.repository_sha256 == source_pin
            assert not any(
                (
                    gaps.coverage_complete,
                    gaps.runtime_authority,
                    gaps.qualification_eligible,
                    gaps.safety_claim,
                )
            )
            traces = manifest["repository_debugger_observations"]
            assert len(traces["observed"]) == 4 and not traces["unproduced_descriptors"]
            assert traces["runtime_authority"] is traces["coverage_complete"] is False
            # Every original coverage report omits the same compiler-owned placeholder.
            # The independent debugger trace cannot substitute for these missing spans.
            placeholders = [
                item
                for unit in original_inventory.statement_catalogs[0].units
                for item in unit.statements
                if item.node_type == "PlaceholderStatement"
            ]
            assert len(placeholders) == 1
            missing = placeholders[0]
            gap_statement = next(
                s for s in gaps.statements if s.node_type == "PlaceholderStatement"
            )
            assert gap_statement.compiler_ast_id == missing.compiler_ast_id
            assert gap_statement.start_byte == missing.start_byte
            assert gap_statement.end_byte_exclusive == missing.end_byte_exclusive
            identity = (
                missing.source_id,
                missing.start_byte,
                missing.end_byte_exclusive,
                missing.start_line,
                missing.end_line_exclusive,
            )
            for index in range(4):
                stage = tmp_path / f"suite/repository-suite/coverage/{index:05d}"
                coverage = parse_forge_debug_statement_coverage((stage / "stdout.txt").read_bytes())
                assert identity not in {item.identity for item in coverage.statements}
                gap_process = gaps.processes[index]
                assert gap_process.missing_statement_ids == (gap_statement.physical_statement_id,)
                assert len(gap_process.mapped_statement_ids) == 3
                assert (
                    gap_process.stdout_sha256
                    == hashlib.sha256((stage / "stdout.txt").read_bytes()).hexdigest()
                )
                assert (
                    gap_process.debug_statement_inventory_sha256
                    == coverage.statement_inventory_sha256
                )
                assert (
                    gap_process.fork_rpc_scope_sha256
                    == run.repository_test_fork_rpc_scopes[index].evidence_sha256
                )
                assert (tmp_path / f"suite/repository-suite/debugger/{index:05d}").is_dir()
            assert all(
                item.status is RepositoryTestExecutionStatus.PASSED
                for item in run.repository_test_executions
            )
            return
        if control == "double_increment":
            assert run.status is ScannerStatus.FAILED
            assert run.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
            outcomes = run.repository_test_executions
            assert [item.status for item in outcomes] == [
                RepositoryTestExecutionStatus.PASSED,
                RepositoryTestExecutionStatus.FAILED,
                RepositoryTestExecutionStatus.INVALID_OUTPUT,
                RepositoryTestExecutionStatus.UNAVAILABLE,
            ]
            assert outcomes[2].fuzz_cases == 0 and not outcomes[2].machine_output_validated
            assert outcomes[2].machine_result_sha256 is None
            assert not run.repository_statement_coverage_evidence
            failed_fuzz = json.loads(
                (tmp_path / "suite/repository-suite/tests/00002/stdout.json").read_bytes()
            )
            result = next(iter(next(iter(failed_fuzz.values()))["test_results"].values()))
            assert result["status"] == "Failure" and result["kind"]["Fuzz"]["runs"] == 0
            assert result["counterexample"] is not None
            assert not (tmp_path / "suite/repository-suite/tests/00003").exists()
            manifest = json.loads((tmp_path / "suite/repository-suite-execution.json").read_bytes())
            traces = manifest["repository_debugger_observations"]
            assert len(traces["observed"]) == 1 and len(traces["unproduced_descriptors"]) == 3
            assert traces["runtime_authority"] is traces["coverage_complete"] is False
            return
        assert run.status is ScannerStatus.SUCCESS, run.error
        assert run.machine_output_validated and run.execution_evidence is ExecutionEvidenceKind.REAL
        assert all(
            item.status is RepositoryTestExecutionStatus.PASSED
            for item in run.repository_test_executions
        )
        payload = json.loads((tmp_path / "suite/repository-suite-execution.json").read_bytes())
        assert payload["schema_version"] == "1.3" and payload["safety_claim"] is False
        traces = payload["repository_debugger_observations"]
        assert len(traces["observed"]) == 4 and traces["unproduced_descriptors"] == []
        assert traces["runtime_authority"] is traces["coverage_complete"] is False
        assert len(payload["repository_statement_coverage_evidence"]) == len(catalog.bindings)
    finally:
        node.terminate()
        node.wait(timeout=5)
