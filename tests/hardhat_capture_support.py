"""Synthetic protocol-only controls; no engine, subprocess, model or network access."""

from __future__ import annotations

from pathlib import Path

from mmaudit.config import RepositoryForkSuiteConfig, SmartContractsConfig
from mmaudit.models.schemas import (
    HardhatInventoryPhaseRequest,
    HardhatReporterExecution,
    HardhatReporterInventory,
    HardhatReporterObservedTest,
    HardhatReporterTestResult,
    RepositoryTestExecutionStatus,
)
from mmaudit.scanners.base import scanner_workspace_sha256
from mmaudit.scanners.hardhat import HARDHAT_REPORTER_SHA256, HARDHAT_REPORTER_VERSION
from mmaudit.scanners.hardhat_protocol import (
    HARDHAT_INVENTORY_SCHEMA_SHA256,
    HardhatPreparedTestPhase,
    seal_hardhat_inventory_phase_request,
)
from mmaudit.scanners.hardhat_supervision import HardhatCaptureOutcome, HardhatPhaseCapture

SOURCE = Path(__file__).parent / "fixtures/hardhat_supervision/Vault.ts"


def inputs(
    tmp_path: Path,
) -> tuple[Path, SmartContractsConfig, HardhatInventoryPhaseRequest, HardhatPhaseCapture]:
    root = tmp_path / "source"
    target = root / "test/audit/Vault.ts"
    target.parent.mkdir(parents=True)
    target.write_bytes(SOURCE.read_bytes())
    config = SmartContractsConfig(
        repository_suite=RepositoryForkSuiteConfig(
            profile="explicit",
            foundry_include_paths=(),
            foundry_include_tests=(),
            hardhat_include_paths=("test/audit/*.ts",),
            hardhat_include_tests=("*",),
            total_timeout_seconds=10,
            per_test_timeout_seconds=1,
            max_total_output_bytes=100_000,
            max_output_bytes_per_test=10_000,
        )
    )
    request = seal_hardhat_inventory_phase_request(
        attempt_sha256="1" * 64,
        repository_sha256=scanner_workspace_sha256(root),
        repository_exclusion_path=".mmaudit",
        configuration_sha256=config.repository_suite.stable_hash(),
        image="registry.example/mmaudit-hardhat@sha256:" + "4" * 64,
        container_executable_sha256="5" * 64,
        isolation_capability_sha256="6" * 64,
        bridge_policy_sha256="7" * 64,
        reporter_version=HARDHAT_REPORTER_VERSION,
        reporter_sha256=HARDHAT_REPORTER_SHA256,
        reporter_schema_sha256=HARDHAT_INVENTORY_SCHEMA_SHA256,
        chain_id=31_337,
        block_number=0,
        block_hash="0x" + "f" * 64,
        fuzz_seed=config.repository_suite.fuzz_seed,
        timeout_seconds=config.repository_suite.total_timeout_seconds,
        maximum_output_bytes=config.repository_suite.max_total_output_bytes,
    )
    inventory = HardhatReporterInventory.sealed(
        reporter_version=HARDHAT_REPORTER_VERSION,
        reporter_sha256=HARDHAT_REPORTER_SHA256,
        request_sha256=request.request_sha256,
        repository_sha256=request.repository_sha256,
        tests=(
            HardhatReporterObservedTest.sealed(
                project_root=".",
                path="test/audit/Vault.ts",
                suite_name="Vault",
                test_name="preserves accounting",
            ),
        ),
    )
    capture = HardhatPhaseCapture(
        request_sha256=request.request_sha256,
        phase="inventory",
        outcome=HardhatCaptureOutcome.EXITED,
        process_exit_code=0,
        duration_seconds=0.1,
        stdout=b"",
        stderr=b"",
        report=inventory.model_dump_json().encode(),
    )
    return root, config, request, capture


def execution_capture(
    prepared: HardhatPreparedTestPhase,
    *,
    status: RepositoryTestExecutionStatus = RepositoryTestExecutionStatus.PASSED,
    exit_code: int = 0,
) -> HardhatPhaseCapture:
    request, selection = prepared.test_request, prepared.selection
    descriptor = selection.tests[0]
    failure = status in {
        RepositoryTestExecutionStatus.FAILED,
        RepositoryTestExecutionStatus.ASSERTION_FAILED,
        RepositoryTestExecutionStatus.REVERTED,
    }
    result = HardhatReporterTestResult.sealed(
        descriptor_sha256=descriptor.descriptor_sha256,
        path=descriptor.path,
        suite_name=descriptor.suite_name,
        test_name=descriptor.test_name,
        status=status,
        terminal_detail="synthetic invariant observation" if failure else None,
        duration_seconds=0,
    )
    report = HardhatReporterExecution.sealed(
        reporter_version=request.reporter_version,
        reporter_sha256=request.reporter_sha256,
        request_sha256=request.request_sha256,
        repository_sha256=request.repository_sha256,
        selection_sha256=selection.selection_sha256,
        chain_id=request.chain_id,
        block_number=request.block_number,
        block_hash=request.block_hash,
        fuzz_seed=request.fuzz_seed,
        results=(result,),
    )
    return HardhatPhaseCapture(
        request_sha256=request.request_sha256,
        phase="test",
        outcome=HardhatCaptureOutcome.EXITED,
        process_exit_code=exit_code,
        duration_seconds=0.1,
        stdout=b"",
        stderr=b"",
        report=report.model_dump_json().encode(),
    )
