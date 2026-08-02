from __future__ import annotations

import hashlib
import shutil
import stat
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from mmaudit.config import RepositoryForkSuiteConfig, SmartContractsConfig
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    RepositorySuiteFramework,
    RepositorySuiteSelection,
    RepositorySuiteTestDescriptor,
)
from mmaudit.scanners.base import scanner_workspace_sha256
from mmaudit.scanners.hardhat import (
    HARDHAT_REPORTER_SHA256,
    HARDHAT_REPORTER_SOURCE_PATH,
    HARDHAT_REPORTER_VERSION,
    parse_hardhat_execution_report,
    parse_hardhat_inventory_report,
    select_hardhat_repository_suite,
    verified_hardhat_reporter_source,
)
from mmaudit.scanners.hardhat_protocol import (
    HardhatProtocolBindingError,
    seal_hardhat_inventory_phase_request,
    seal_hardhat_test_phase_request,
    validate_hardhat_two_phase_bindings,
)
from mmaudit.scanners.hardhat_source import bind_hardhat_inventory_to_source

_REPOSITORY_SHA256 = "e" * 64
_BLOCK_HASH = "0x" + ("f" * 64)
_SEED = "0x" + ("0" * 63) + "1"
_NODE_HARNESS = r"""
const EventEmitter = require("node:events");
const path = require("node:path");
const Reporter = require(process.argv[1]);
const phase = process.argv[2];
const outputPath = process.argv[3];
const repositoryRoot = process.argv[4];
const reporterSha256 = process.argv[5];
const repositorySha256 = process.argv[6];
const requestSha256 = process.argv[7];
const descriptorSha256 = process.argv[8];
const selectionSha256 = process.argv[9];
const root = { title: "", parent: null };
const suite = { title: "Vault", parent: root };
const test = {
  file: path.join(repositoryRoot, "test/audit/Vault.ts"),
  title: "preserves accounting",
  parent: suite,
  duration: 250,
};
const options = {
  reporterOptions: {
    schemaVersion: "1.0",
    phase,
    outputPath,
    reporterSha256,
    repositorySha256,
    requestSha256,
    repositoryRoot,
    projectRoot: ".",
  },
};
if (phase === "test") {
  Object.assign(options.reporterOptions, {
    selectedTests: [{
      projectRoot: ".",
      path: "test/audit/Vault.ts",
      suiteName: "Vault",
      testName: "preserves accounting",
      descriptorSha256,
    }],
    selectionSha256,
    chainId: 31337,
    blockNumber: 0,
    blockHash: "0x" + "f".repeat(64),
    fuzzSeed: "0x" + "0".repeat(63) + "1",
  });
}
const runner = new EventEmitter();
new Reporter(runner, options);
if (phase === "inventory") {
  runner.emit("test", test);
  runner.emit("pending", test);
} else {
  runner.emit("pass", test);
  runner.emit("test end", test);
}
runner.emit("end");
"""


class _StubbedReporterProcessBoundary:
    """Local protocol double: real Node reporter process, no container/runtime credit."""

    execution_evidence = ExecutionEvidenceKind.MOCK

    def run(
        self,
        root: Path,
        output: Path,
        *,
        phase: str,
        request_sha256: str,
        selection: RepositorySuiteSelection,
        repository_sha256: str,
    ) -> subprocess.CompletedProcess[bytes]:
        return _run_reporter(
            root,
            output,
            phase=phase,
            request_sha256=request_sha256,
            selection=selection,
            repository_sha256=repository_sha256,
        )


def _node() -> str:
    executable = shutil.which("node")
    if executable is None:
        pytest.skip("Node.js is unavailable for the reference-reporter process-boundary test")
    return executable


def _selection() -> RepositorySuiteSelection:
    descriptor = RepositorySuiteTestDescriptor.sealed(
        framework=RepositorySuiteFramework.HARDHAT,
        project_root=".",
        path="test/audit/Vault.ts",
        suite_name="Vault",
        test_name="preserves accounting",
        source_sha256="1" * 64,
        start_line=3,
        end_line=3,
    )
    config = RepositoryForkSuiteConfig(
        profile="explicit",
        foundry_include_paths=(),
        foundry_include_tests=(),
        hardhat_include_paths=("test/audit/*.ts",),
        hardhat_include_tests=("*",),
    )
    return RepositorySuiteSelection.sealed(
        profile=config.profile,
        repository_sha256=_REPOSITORY_SHA256,
        repository_exclusion_path=".mmaudit",
        configuration_sha256=config.stable_hash(),
        candidate_file_count=1,
        candidate_test_count=1,
        selected_file_count=1,
        selected_test_count=1,
        omitted_file_count=0,
        omitted_test_count=0,
        limit_reached=False,
        tests=(descriptor,),
        safety_claim=False,
    )


def _run_reporter(
    root: Path,
    output: Path,
    *,
    phase: str,
    request_sha256: str,
    selection: RepositorySuiteSelection,
    repository_sha256: str = _REPOSITORY_SHA256,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            _node(),
            "-e",
            _NODE_HARNESS,
            str(HARDHAT_REPORTER_SOURCE_PATH.resolve(strict=True)),
            phase,
            str(output.resolve()),
            str(root.resolve(strict=True)),
            HARDHAT_REPORTER_SHA256,
            repository_sha256,
            request_sha256,
            selection.tests[0].descriptor_sha256,
            selection.selection_sha256,
        ],
        cwd=root,
        env={"PATH": str(Path(_node()).parent)},
        check=False,
        capture_output=True,
        timeout=10,
    )


def test_reference_reporter_two_phase_output_remains_observation_only(tmp_path: Path) -> None:
    assert verified_hardhat_reporter_source()
    root = tmp_path / "synthetic-repository"
    test_path = root / "test" / "audit" / "Vault.ts"
    test_path.parent.mkdir(parents=True)
    test_path.write_text(
        'describe("Vault", () => {\n  it("preserves accounting", () => {});\n});\n',
        encoding="utf-8",
    )
    repository_sha256 = scanner_workspace_sha256(root)
    placeholder_selection = _selection()
    config = SmartContractsConfig(
        repository_suite=RepositoryForkSuiteConfig(
            profile="explicit",
            foundry_include_paths=(),
            foundry_include_tests=(),
            hardhat_include_paths=("test/audit/*.ts",),
            hardhat_include_tests=("*",),
        )
    )
    schema_root = Path(__file__).parents[2] / "schemas"
    inventory_schema_sha256 = hashlib.sha256(
        (schema_root / "hardhat_reporter_inventory.schema.json").read_bytes()
    ).hexdigest()
    test_schema_sha256 = hashlib.sha256(
        (schema_root / "hardhat_reporter_test.schema.json").read_bytes()
    ).hexdigest()
    inventory_request = seal_hardhat_inventory_phase_request(
        attempt_sha256="7" * 64,
        repository_sha256=repository_sha256,
        repository_exclusion_path=".mmaudit",
        configuration_sha256=config.repository_suite.stable_hash(),
        image="registry.example/mmaudit-hardhat@sha256:" + "a" * 64,
        container_executable_sha256="b" * 64,
        isolation_capability_sha256="c" * 64,
        bridge_policy_sha256="d" * 64,
        reporter_version=HARDHAT_REPORTER_VERSION,
        reporter_sha256=HARDHAT_REPORTER_SHA256,
        reporter_schema_sha256=inventory_schema_sha256,
        chain_id=31_337,
        block_number=0,
        block_hash=_BLOCK_HASH,
        fuzz_seed=_SEED,
        timeout_seconds=10,
        maximum_output_bytes=100_000,
    )
    boundary = _StubbedReporterProcessBoundary()

    inventory_path = tmp_path / "inventory.json"
    inventory_process = boundary.run(
        root,
        inventory_path,
        phase="inventory",
        request_sha256=inventory_request.request_sha256,
        selection=placeholder_selection,
        repository_sha256=repository_sha256,
    )
    assert inventory_process.returncode == 0, inventory_process.stderr.decode("utf-8", "replace")
    assert inventory_process.stdout == b""
    assert inventory_process.stderr == b""
    inventory = parse_hardhat_inventory_report(
        inventory_path.read_bytes(),
        expected_request_sha256=inventory_request.request_sha256,
        expected_repository_sha256=repository_sha256,
        maximum_bytes=100_000,
    )
    assert inventory.reporter_version == HARDHAT_REPORTER_VERSION
    assert inventory.authorship_claim is False
    assert inventory.execution_credit is False
    assert stat.S_IMODE(inventory_path.stat().st_mode) == 0o600
    authority = bind_hardhat_inventory_to_source(
        root,
        inventory,
        config,
        expected_repository_sha256=repository_sha256,
    )
    selection = select_hardhat_repository_suite(
        inventory,
        config,
        repository_exclusion_path=".mmaudit",
        authority=authority,
    )
    stale_inventory_request = deepcopy(inventory_request)
    stale_inventory_request.image = "registry.example/mmaudit-hardhat@sha256:" + "9" * 64
    with pytest.raises(HardhatProtocolBindingError, match="structurally invalid"):
        seal_hardhat_test_phase_request(
            stale_inventory_request,
            inventory,
            authority,
            selection,
            reporter_schema_sha256=test_schema_sha256,
            per_test_timeout_seconds=1,
            maximum_output_bytes_per_test=100_000,
        )

    stale_selection = deepcopy(selection)
    stale_selection.selection_sha256 = "0" * 64
    with pytest.raises(HardhatProtocolBindingError, match="structurally invalid"):
        seal_hardhat_test_phase_request(
            inventory_request,
            inventory,
            authority,
            stale_selection,
            reporter_schema_sha256=test_schema_sha256,
            per_test_timeout_seconds=1,
            maximum_output_bytes_per_test=100_000,
        )

    altered_values = selection.model_dump(mode="python", exclude={"selection_sha256"})
    altered_values["tests"] = selection.tests
    altered_values["inventory_kind"] = selection.inventory_kind
    altered_values["candidate_file_count"] = selection.candidate_file_count + 1
    altered_values["omitted_file_count"] = selection.omitted_file_count + 1
    altered_accounting = RepositorySuiteSelection.sealed(**altered_values)
    with pytest.raises(HardhatProtocolBindingError, match="does not exactly join"):
        seal_hardhat_test_phase_request(
            inventory_request,
            inventory,
            authority,
            altered_accounting,
            reporter_schema_sha256=test_schema_sha256,
            per_test_timeout_seconds=1,
            maximum_output_bytes_per_test=100_000,
        )

    test_request = seal_hardhat_test_phase_request(
        inventory_request,
        inventory,
        authority,
        selection,
        reporter_schema_sha256=test_schema_sha256,
        per_test_timeout_seconds=1,
        maximum_output_bytes_per_test=100_000,
    )
    validate_hardhat_two_phase_bindings(
        inventory_request,
        inventory,
        authority,
        selection,
        test_request,
    )

    execution_path = tmp_path / "execution.json"
    execution_process = boundary.run(
        root,
        execution_path,
        phase="test",
        request_sha256=test_request.request_sha256,
        selection=selection,
        repository_sha256=repository_sha256,
    )
    assert execution_process.returncode == 0, execution_process.stderr.decode("utf-8", "replace")
    assert execution_process.stdout == b""
    assert execution_process.stderr == b""
    execution = parse_hardhat_execution_report(
        execution_path.read_bytes(),
        selection=selection,
        expected_request_sha256=test_request.request_sha256,
        expected_chain_id=31_337,
        expected_block_number=0,
        expected_block_hash=_BLOCK_HASH,
        expected_fuzz_seed=_SEED,
        per_test_timeout_seconds=1,
        maximum_bytes=100_000,
    )
    assert inventory_request.execution_credit is False
    assert test_request.execution_credit is False
    assert boundary.execution_evidence is ExecutionEvidenceKind.MOCK
    assert execution.authorship_claim is False
    assert execution.execution_credit is False
    assert execution.results[0].descriptor_sha256 == selection.tests[0].descriptor_sha256
    assert stat.S_IMODE(execution_path.stat().st_mode) == 0o600


def test_reference_reporter_refuses_to_replace_existing_output(tmp_path: Path) -> None:
    root = tmp_path / "synthetic-repository"
    test_path = root / "test" / "audit" / "Vault.ts"
    test_path.parent.mkdir(parents=True)
    test_path.write_text("// inert synthetic source identity\n", encoding="utf-8")
    output = tmp_path / "preexisting.json"
    canary = b"SYNTHETIC_PREEXISTING_OUTPUT_CANARY"
    output.write_bytes(canary)

    process = _run_reporter(
        root,
        output,
        phase="inventory",
        request_sha256="8" * 64,
        selection=_selection(),
    )

    assert process.returncode != 0
    assert output.read_bytes() == canary
    assert process.stdout == b""
    assert canary not in process.stderr
