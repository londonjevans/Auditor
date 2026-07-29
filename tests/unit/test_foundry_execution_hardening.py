from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

import mmaudit.scanners.foundry as foundry_module
from mmaudit.config import SmartContractsConfig
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    FoundryTestExecutionSummary,
    RepositorySuiteExecutionPolicy,
    RepositorySuiteFramework,
    RepositorySuiteSelection,
    RepositorySuiteTestDescriptor,
    RepositoryTestExecutionStatus,
    ScannerRun,
    ScannerStatus,
)
from mmaudit.scanners.base import (
    ScannerWorkspaceCopyCustody,
    copy_scanner_workspace_with_custody,
)
from mmaudit.scanners.fork_rpc import PinnedForkObservation
from mmaudit.scanners.foundry import (
    FoundryForkScanner,
    _bounded_stream_artifact_usage,
    _display_foundry_test_command,
    _execute_foundry_test,
    _execute_foundry_test_with_scope,
    _finalize_foundry_repository_suite,
    _foundry_inventory_limits,
    _FoundrySuiteDeadlineExpired,
    _FoundryTestObservation,
    _parse_exact_foundry_test_with_deadline,
    _private_artifact_usage,
    _PrivateArtifactUsage,
    _remaining_deadline_seconds,
    _selection_sources_unchanged,
    _SuiteArtifactBudget,
    _write_repository_suite_manifest,
)
from mmaudit.scanners.foundry_inventory_runner import (
    FoundryInventoryInvalidError,
    FoundryInventoryOverflowError,
    FoundryInventoryUnavailableError,
)
from mmaudit.scanners.read_only_rpc import ReadOnlyRpcTestScopeSnapshot

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
SEED = "0x" + ("0" * 63) + "1"


def _descriptor() -> RepositorySuiteTestDescriptor:
    return RepositorySuiteTestDescriptor.sealed(
        framework=RepositorySuiteFramework.FOUNDRY,
        project_root=".",
        path="test/audit/ExactSuite.t.sol",
        suite_name="ExactSuiteTest",
        test_name="testExact",
        source_sha256=HASH_A,
        start_line=1,
        end_line=3,
    )


def _selection(
    descriptors: tuple[RepositorySuiteTestDescriptor, ...] | None = None,
    *,
    repository_sha256: str = HASH_B,
) -> RepositorySuiteSelection:
    selected = descriptors or (_descriptor(),)
    return RepositorySuiteSelection.sealed(
        profile="explicit",
        repository_sha256=repository_sha256,
        repository_exclusion_path=".mmaudit",
        configuration_sha256=HASH_C,
        candidate_file_count=len({descriptor.path for descriptor in selected}),
        candidate_test_count=len(selected),
        selected_file_count=len({descriptor.path for descriptor in selected}),
        selected_test_count=len(selected),
        omitted_file_count=0,
        omitted_test_count=0,
        limit_reached=False,
        tests=selected,
    )


class _ScopeRecorder:
    def __init__(
        self,
        *,
        fail_begin: bool = False,
        fail_end: bool = False,
        policy_sha256: str = HASH_B,
    ) -> None:
        self.fail_begin = fail_begin
        self.fail_end = fail_end
        self.policy_sha256 = policy_sha256
        self.events: list[tuple[str, str, int]] = []

    def begin_selected_test_scope(
        self,
        *,
        attempt_binding_sha256: str,
        selection_sha256: str,
        descriptor_sha256: str,
        sequence_index: int,
    ) -> None:
        assert attempt_binding_sha256 == HASH_A
        assert selection_sha256
        self.events.append(("begin", descriptor_sha256, sequence_index))
        if self.fail_begin:
            raise RuntimeError("synthetic begin failure")

    def end_selected_test_scope(
        self,
        *,
        attempt_binding_sha256: str,
        selection_sha256: str,
        descriptor_sha256: str,
        sequence_index: int,
    ) -> ReadOnlyRpcTestScopeSnapshot:
        assert attempt_binding_sha256 == HASH_A
        assert selection_sha256
        self.events.append(("end", descriptor_sha256, sequence_index))
        if self.fail_end:
            raise RuntimeError("synthetic end failure")
        payload: dict[str, object] = {
            "schema_version": "1.0",
            "attempt_binding_sha256": attempt_binding_sha256,
            "selection_sha256": selection_sha256,
            "descriptor_sha256": descriptor_sha256,
            "sequence_index": sequence_index,
            "policy_sha256": self.policy_sha256,
            "expected_chain_id": 31_337,
            "pinned_block_number": 0,
            "pinned_block_hash": "0x" + HASH_C,
            "status": "validated",
            "http_request_count": 1,
            "permitted_rpc_call_count": 1,
            "origin_attempted_rpc_call_count": 1,
            "origin_validated_rpc_call_count": 1,
            "synthetic_rpc_call_count": 0,
            "denied_request_count": 0,
            "malformed_request_count": 0,
            "limit_exceeded_request_count": 0,
            "upstream_error_request_count": 0,
            "allowed_method_counts": [{"method": "eth_getCode", "count": 1}],
            "method_log_sha256": HASH_C,
            "boundary_drained": True,
        }
        snapshot_sha256 = hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode()
        ).hexdigest()
        return ReadOnlyRpcTestScopeSnapshot(
            schema_version="1.0",
            attempt_binding_sha256=attempt_binding_sha256,
            selection_sha256=selection_sha256,
            descriptor_sha256=descriptor_sha256,
            sequence_index=sequence_index,
            policy_sha256=self.policy_sha256,
            expected_chain_id=31_337,
            pinned_block_number=0,
            pinned_block_hash="0x" + HASH_C,
            status="validated",
            http_request_count=1,
            permitted_rpc_call_count=1,
            origin_attempted_rpc_call_count=1,
            origin_validated_rpc_call_count=1,
            synthetic_rpc_call_count=0,
            denied_request_count=0,
            malformed_request_count=0,
            limit_exceeded_request_count=0,
            upstream_error_request_count=0,
            allowed_method_counts=(("eth_getCode", 1),),
            method_log_sha256=HASH_C,
            boundary_drained=True,
            snapshot_sha256=snapshot_sha256,
        )


def _test_observation(
    descriptor: RepositorySuiteTestDescriptor,
    *,
    status: RepositoryTestExecutionStatus = RepositoryTestExecutionStatus.PASSED,
) -> _FoundryTestObservation:
    return _FoundryTestObservation(
        descriptor=descriptor,
        status=status,
        terminal_detail=None,
        duration_seconds=0.1,
        command_sha256=HASH_A,
        output_sha256=HASH_B,
        output_bytes=1,
        process_exit_code=0,
        machine_output_validated=True,
        machine_result_sha256=HASH_C,
    )


def _test_usage() -> _PrivateArtifactUsage:
    return _PrivateArtifactUsage(entries=0, bytes=0, artifact_sha256=HASH_A)


def test_workspace_copy_custody_proves_stable_copy_without_claiming_removal(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "src").mkdir()
    (repository / "src" / "Example.sol").write_text(
        "contract Example {}\n",
        encoding="utf-8",
    )
    private_dir = tmp_path / "private"
    private_dir.mkdir()
    workspace = private_dir / "workspace"

    custody = copy_scanner_workspace_with_custody(
        repository,
        workspace,
        private_dir,
    )
    observation = custody.finalize()

    assert custody.closed
    assert observation.workspace_created_exclusively
    assert observation.workspace_direct_child
    assert observation.audited_inventory_symlink_free
    assert observation.source_descriptor_custody_validated
    assert observation.workspace_descriptor_custody_validated
    assert observation.workspace_parent_descriptor_custody_validated
    assert observation.copy_matches_source
    assert observation.source_identity_stable
    assert observation.workspace_identity_stable
    assert not observation.workspace_removed
    assert observation.source_inventory_sha256_before == observation.source_inventory_sha256_after
    assert (
        observation.source_inventory_sha256_before
        == observation.workspace_inventory_sha256_after_copy
        == observation.workspace_inventory_sha256_after_execution
    )
    assert observation.source_root_device_before == observation.source_root_device_after
    assert observation.source_root_inode_before == observation.source_root_inode_after
    assert observation.workspace_root_device_before == observation.workspace_root_device_after
    assert observation.workspace_root_inode_before == observation.workspace_root_inode_after
    parent_stat = private_dir.stat()
    assert observation.workspace_parent_device == parent_stat.st_dev
    assert observation.workspace_parent_inode == parent_stat.st_ino
    assert workspace.is_dir()


def test_workspace_copy_custody_requires_exclusive_direct_child(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "Example.sol").write_text("contract Example {}\n", encoding="utf-8")
    private_dir = tmp_path / "private"
    private_dir.mkdir()
    workspace = private_dir / "workspace"
    workspace.mkdir()

    with pytest.raises(OSError, match="already exists"):
        copy_scanner_workspace_with_custody(repository, workspace, private_dir)


def test_workspace_copy_custody_removes_only_its_empty_root_when_open_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "Example.sol").write_text("contract Example {}\n", encoding="utf-8")
    private_dir = tmp_path / "private"
    private_dir.mkdir()
    workspace = private_dir / "workspace"
    real_open = os.open

    def fail_workspace_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == "workspace" and dir_fd is not None:
            raise OSError("synthetic workspace open failure")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", fail_workspace_open)

    with pytest.raises(OSError, match="synthetic workspace open failure"):
        copy_scanner_workspace_with_custody(repository, workspace, private_dir)

    assert not workspace.exists()


@pytest.mark.parametrize("replaced_root", ["source", "workspace"])
def test_workspace_copy_custody_detects_root_replacement_and_closes_descriptors(
    tmp_path: Path,
    replaced_root: str,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "Example.sol").write_text("contract Example {}\n", encoding="utf-8")
    private_dir = tmp_path / "private"
    private_dir.mkdir()
    workspace = private_dir / "workspace"
    custody = copy_scanner_workspace_with_custody(repository, workspace, private_dir)

    target = repository if replaced_root == "source" else workspace
    retained = target.with_name(f"{target.name}-retained")
    target.rename(retained)
    target.mkdir()
    (target / "Example.sol").write_text("contract Example {}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="root identity changed"):
        custody.finalize()

    assert custody.closed


@pytest.mark.parametrize("drifted_root", ["source", "workspace"])
def test_workspace_copy_custody_detects_inventory_drift_and_closes_descriptors(
    tmp_path: Path,
    drifted_root: str,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "Example.sol").write_text("contract Example {}\n", encoding="utf-8")
    private_dir = tmp_path / "private"
    private_dir.mkdir()
    workspace = private_dir / "workspace"
    custody = copy_scanner_workspace_with_custody(repository, workspace, private_dir)

    drifted = repository if drifted_root == "source" else workspace
    (drifted / "Example.sol").write_text(
        "contract Example { uint256 changed; }\n", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="inventory changed"):
        custody.finalize()

    assert custody.closed


def test_workspace_copy_custody_closes_all_descriptors_when_one_close_reports_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "Example.sol").write_text("contract Example {}\n", encoding="utf-8")
    private_dir = tmp_path / "private"
    private_dir.mkdir()
    custody = copy_scanner_workspace_with_custody(
        repository,
        private_dir / "workspace",
        private_dir,
    )
    source_fd = custody._source_fd
    workspace_fd = custody._workspace_fd
    workspace_parent_fd = custody._workspace_parent_fd
    real_close = os.close

    def close_then_report_error(descriptor: int) -> None:
        real_close(descriptor)
        if descriptor == workspace_fd:
            raise OSError("synthetic close error")

    monkeypatch.setattr(os, "close", close_then_report_error)

    with pytest.raises(OSError, match="synthetic close error"):
        custody.close()

    assert custody.closed
    with pytest.raises(OSError):
        os.fstat(source_fd)
    with pytest.raises(OSError):
        os.fstat(workspace_fd)
    with pytest.raises(OSError):
        os.fstat(workspace_parent_fd)


def test_foundry_run_closes_workspace_custody_after_unexpected_base_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "Example.sol").write_text("contract Example {}\n", encoding="utf-8")
    private_dir = tmp_path / "private"
    captured_descriptors: list[int] = []
    scanner = FoundryForkScanner(SmartContractsConfig())

    def interrupt_after_copy(
        root: Path,
        supplied_private_dir: Path,
        timeout_seconds: float,
        *,
        backend: object,
        expected_version: str | None,
        expected_sha256: str | None,
        workspace_custody_guard: list[ScannerWorkspaceCopyCustody],
    ) -> ScannerRun:
        del timeout_seconds, backend, expected_version, expected_sha256
        supplied_private_dir.mkdir()
        custody = copy_scanner_workspace_with_custody(
            root,
            supplied_private_dir / "workspace",
            supplied_private_dir,
        )
        captured_descriptors.extend(
            (
                custody._source_fd,
                custody._workspace_fd,
                custody._workspace_parent_fd,
            )
        )
        workspace_custody_guard.append(custody)
        raise KeyboardInterrupt

    monkeypatch.setattr(scanner, "_run_repository_suite", interrupt_after_copy)

    with pytest.raises(KeyboardInterrupt):
        scanner.run(repository, private_dir, 10.0)

    assert len(captured_descriptors) == 3
    for descriptor in captured_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_foundry_scope_context_is_all_or_none_and_runtime_context_preserves_it() -> None:
    recorder = _ScopeRecorder()

    with pytest.raises(ValueError, match="all-or-none"):
        FoundryForkScanner(
            SmartContractsConfig(),
            fork_rpc_scope_recorder=recorder,
        )
    with pytest.raises(ValueError, match="all-or-none"):
        FoundryForkScanner(
            SmartContractsConfig(),
            attempt_binding_sha256=HASH_A,
        )

    scanner = FoundryForkScanner(
        SmartContractsConfig(),
        fork_rpc_scope_recorder=recorder,
        attempt_binding_sha256=HASH_A,
    )
    runtime = scanner.with_runtime_context(allow_fork_probing=True, projects=())

    assert runtime.fork_rpc_scope_recorder is recorder
    assert runtime.attempt_binding_sha256 == HASH_A
    with pytest.raises(ValueError, match="all-or-none"):
        scanner.with_runtime_context(
            allow_fork_probing=True,
            projects=(),
            fork_rpc_scope_recorder=recorder,
        )
    with pytest.raises(ValueError, match="all-or-none"):
        scanner.with_runtime_context(
            allow_fork_probing=True,
            projects=(),
            attempt_binding_sha256=HASH_B,
        )


def test_foundry_scope_wrapper_preserves_descriptor_order_and_exact_binding() -> None:
    first = _descriptor()
    second = RepositorySuiteTestDescriptor.sealed(
        framework=RepositorySuiteFramework.FOUNDRY,
        project_root=".",
        path="test/audit/ExactSuite.t.sol",
        suite_name="ExactSuiteTest",
        test_name="testSecond",
        source_sha256=HASH_A,
        start_line=4,
        end_line=6,
    )
    selection = _selection((first, second))
    recorder = _ScopeRecorder()
    outcomes = []

    for index, descriptor in enumerate(selection.tests, start=1):
        outcomes.append(
            _execute_foundry_test_with_scope(
                recorder=recorder,
                attempt_binding_sha256=HASH_A,
                selection=selection,
                descriptor=descriptor,
                sequence_index=index,
                execute=lambda descriptor=descriptor, index=index: (
                    recorder.events.append(("execute", descriptor.descriptor_sha256, index))
                    or (_test_observation(descriptor), _test_usage())
                ),
            )
        )

    assert [event[0] for event in recorder.events] == [
        "begin",
        "execute",
        "end",
        "begin",
        "execute",
        "end",
    ]
    assert all(outcome.error is None for outcome in outcomes)
    assert [outcome.scope.descriptor_sha256 for outcome in outcomes if outcome.scope] == [
        first.descriptor_sha256,
        second.descriptor_sha256,
    ]
    assert [outcome.scope.sequence_index for outcome in outcomes if outcome.scope] == [1, 2]


def test_foundry_scope_wrapper_without_recorder_is_compatible() -> None:
    descriptor = _descriptor()
    called = False

    def execute() -> tuple[_FoundryTestObservation, _PrivateArtifactUsage]:
        nonlocal called
        called = True
        return _test_observation(descriptor), _test_usage()

    outcome = _execute_foundry_test_with_scope(
        recorder=None,
        attempt_binding_sha256=None,
        selection=_selection(),
        descriptor=descriptor,
        sequence_index=1,
        execute=execute,
    )

    assert called
    assert outcome.error is None
    assert outcome.scope is None
    assert outcome.result is not None


@pytest.mark.parametrize(
    ("failure", "expected_events"),
    [("begin", ["begin"]), ("end", ["begin", "end"])],
)
def test_foundry_scope_boundary_failure_is_explicit(
    failure: str,
    expected_events: list[str],
) -> None:
    recorder = _ScopeRecorder(fail_begin=failure == "begin", fail_end=failure == "end")
    executed = False

    def execute() -> tuple[_FoundryTestObservation, _PrivateArtifactUsage]:
        nonlocal executed
        executed = True
        return _test_observation(_descriptor()), _test_usage()

    outcome = _execute_foundry_test_with_scope(
        recorder=recorder,
        attempt_binding_sha256=HASH_A,
        selection=_selection(),
        descriptor=_descriptor(),
        sequence_index=1,
        execute=execute,
    )

    assert [event[0] for event in recorder.events] == expected_events
    assert executed is (failure == "end")
    assert outcome.error is not None
    assert "scope boundary" in str(outcome.error)
    assert outcome.scope is None


def test_foundry_scope_end_runs_after_execution_exception_and_timeout() -> None:
    descriptor = _descriptor()
    selection = _selection()
    exception_recorder = _ScopeRecorder()
    execution_error = RuntimeError("synthetic execution failure")

    def fail_execution() -> tuple[_FoundryTestObservation, _PrivateArtifactUsage]:
        exception_recorder.events.append(("execute", descriptor.descriptor_sha256, 1))
        raise execution_error

    failed = _execute_foundry_test_with_scope(
        recorder=exception_recorder,
        attempt_binding_sha256=HASH_A,
        selection=selection,
        descriptor=descriptor,
        sequence_index=1,
        execute=fail_execution,
    )

    timeout_recorder = _ScopeRecorder()
    timed_out = _execute_foundry_test_with_scope(
        recorder=timeout_recorder,
        attempt_binding_sha256=HASH_A,
        selection=selection,
        descriptor=descriptor,
        sequence_index=1,
        execute=lambda: (
            _test_observation(
                descriptor,
                status=RepositoryTestExecutionStatus.TIMED_OUT,
            ),
            _test_usage(),
        ),
    )

    assert [event[0] for event in exception_recorder.events] == ["begin", "execute", "end"]
    assert failed.error is execution_error
    assert failed.scope is not None
    assert timed_out.error is None
    assert timed_out.result is not None
    assert timed_out.result[0].status is RepositoryTestExecutionStatus.TIMED_OUT
    assert [event[0] for event in timeout_recorder.events] == ["begin", "end"]


def test_inventory_limits_bind_all_output_to_remaining_suite_budget() -> None:
    config = SmartContractsConfig(
        repository_suite={
            "max_output_bytes_per_test": 2_048,
            "max_total_output_bytes": 4_096,
        }
    )

    limits = _foundry_inventory_limits(config, remaining_total_bytes=3_072)

    assert limits.max_stdout_bytes_per_project == 2_048
    assert limits.max_stderr_bytes_per_project == 2_048
    assert limits.max_total_stream_bytes == 3_072
    assert limits.max_generated_file_bytes == 3_072
    assert limits.max_generated_bytes_per_project == 3_072
    assert limits.max_total_generated_bytes == 3_072
    assert limits.max_combined_output_bytes == 3_072

    with pytest.raises(
        FoundryInventoryOverflowError,
        match="insufficient output budget",
    ):
        _foundry_inventory_limits(config, remaining_total_bytes=1_023)


def test_foundry_command_uses_exact_literal_path_and_anchored_test_name() -> None:
    descriptor = _descriptor()
    command = _display_foundry_test_command(
        descriptor=descriptor,
        fork=PinnedForkObservation(
            chain_id=31_337,
            block_number=0,
            block_hash="0x" + ("b" * 64),
        ),
        fuzz_seed=SEED,
        fuzz_runs=16,
        compiler_sha256="c" * 64,
    )

    path_pattern = command[command.index("--match-path") + 1]
    test_pattern = command[command.index("--match-test") + 1]
    assert path_pattern == descriptor.path
    assert command[command.index("--gas-price") + 1] == "1000000000"
    assert re.fullmatch(test_pattern, f"{descriptor.test_name}()")
    assert re.fullmatch(test_pattern, f"{descriptor.test_name}Neighbor()") is None

    bypassed_validation = descriptor.model_copy(update={"path": "test/audit/[ExactSuite].t.sol"})
    with pytest.raises(ValueError, match="exact literal path"):
        _display_foundry_test_command(
            descriptor=bypassed_validation,
            fork=PinnedForkObservation(
                chain_id=31_337,
                block_number=0,
                block_hash="0x" + ("b" * 64),
            ),
            fuzz_seed=SEED,
            fuzz_runs=16,
            compiler_sha256="c" * 64,
        )


def test_private_artifact_usage_enumerates_stream_cache_and_out_files(
    tmp_path: Path,
) -> None:
    root = tmp_path / "execution"
    (root / "cache" / "nested").mkdir(parents=True)
    (root / "out").mkdir()
    (root / "stdout.json").write_bytes(b"stdout")
    (root / "stderr.txt").write_bytes(b"err")
    (root / "cache" / "nested" / "cache.bin").write_bytes(b"cache")
    (root / "out" / "artifact.json").write_bytes(b"artifact")

    usage = _private_artifact_usage(root)

    assert usage.entries == 7
    assert usage.bytes == len(b"stdouterrcacheartifact")
    first_hash = usage.artifact_sha256
    (root / "out" / "artifact.json").write_bytes(b"changed!")
    assert _private_artifact_usage(root).artifact_sha256 != first_hash


@pytest.mark.parametrize(
    ("purpose", "hash_contents"),
    (
        (foundry_module._PrivateArtifactTraversalPurpose.STRICT_SNAPSHOT, True),
        (foundry_module._PrivateArtifactTraversalPurpose.LIVE_LIMIT_MONITOR, False),
    ),
)
def test_private_artifact_usage_uses_no_follow_cloexec_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    purpose: foundry_module._PrivateArtifactTraversalPurpose,
    hash_contents: bool,
) -> None:
    root = tmp_path / "execution"
    root.mkdir()
    (root / "artifact.json").write_bytes(b'{"ok":true}')
    observed_flags: list[int] = []
    real_open = os.open

    def recording_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        observed_flags.append(flags)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", recording_open)

    usage = _private_artifact_usage(
        root,
        hash_contents=hash_contents,
        purpose=purpose,
    )

    assert usage.bytes == len(b'{"ok":true}')
    assert len(observed_flags) == 2
    assert all(flags & os.O_NOFOLLOW for flags in observed_flags)
    if hasattr(os, "O_CLOEXEC"):
        assert all(flags & os.O_CLOEXEC for flags in observed_flags)
    assert sum(bool(flags & os.O_DIRECTORY) for flags in observed_flags) == 1


def test_live_private_artifact_monitor_tolerates_directory_entry_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "execution"
    cache = root / "cache"
    cache.mkdir(parents=True)
    (cache / "initial.bin").write_bytes(b"initial")
    real_scandir = os.scandir
    scan_count = 0

    def create_during_scan(
        path: int | str | bytes | os.PathLike[str] | os.PathLike[bytes],
    ):
        nonlocal scan_count
        scan_count += 1
        if scan_count == 2:
            (cache / "created.bin").write_bytes(b"created")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", create_during_scan)

    usage = _private_artifact_usage(
        root,
        hash_contents=False,
        purpose=foundry_module._PrivateArtifactTraversalPurpose.LIVE_LIMIT_MONITOR,
    )

    assert usage.entries == 3
    assert usage.bytes == len(b"initialcreated")


def test_strict_private_artifact_snapshot_rejects_directory_entry_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "execution"
    cache = root / "cache"
    cache.mkdir(parents=True)
    (cache / "initial.bin").write_bytes(b"initial")
    real_scandir = os.scandir
    scan_count = 0

    def create_during_scan(
        path: int | str | bytes | os.PathLike[str] | os.PathLike[bytes],
    ):
        nonlocal scan_count
        scan_count += 1
        if scan_count == 2:
            (cache / "created.bin").write_bytes(b"created")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", create_during_scan)

    with pytest.raises(
        FoundryInventoryInvalidError,
        match="directory changed while it was traversed",
    ):
        _private_artifact_usage(root)


def test_private_artifact_usage_fails_closed_without_no_follow_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "execution"
    root.mkdir()
    (root / "artifact.json").write_bytes(b'{"ok":true}')
    monkeypatch.delattr(os, "O_NOFOLLOW")

    with pytest.raises(
        FoundryInventoryUnavailableError,
        match="no no-follow open flag is available",
    ):
        _private_artifact_usage(root)


def test_private_artifact_usage_rejects_path_replacement_during_descriptor_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "execution"
    root.mkdir()
    artifact = root / "artifact.json"
    moved_artifact = root / "opened-artifact.json"
    artifact.write_bytes(b"trusted")
    replacement = b"changed"
    real_read = os.read
    replaced = False

    def replacing_read(descriptor: int, maximum_bytes: int) -> bytes:
        nonlocal replaced
        if not replaced:
            artifact.rename(moved_artifact)
            artifact.write_bytes(replacement)
            replaced = True
        return real_read(descriptor, maximum_bytes)

    monkeypatch.setattr(os, "read", replacing_read)

    with pytest.raises(
        FoundryInventoryInvalidError,
        match="changed while it was hashed",
    ):
        _private_artifact_usage(root)

    assert replaced is True
    assert moved_artifact.read_bytes() == b"trusted"
    assert artifact.read_bytes() == replacement


def test_live_private_artifact_monitor_rejects_file_name_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "execution"
    root.mkdir()
    artifact = root / "artifact.json"
    moved_artifact = root / "opened-artifact.json"
    artifact.write_bytes(b"trusted")
    real_open = os.open
    replaced = False

    def replace_after_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replaced
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == "artifact.json" and dir_fd is not None and not replaced:
            artifact.rename(moved_artifact)
            artifact.write_bytes(b"replacement")
            replaced = True
        return descriptor

    monkeypatch.setattr(os, "open", replace_after_open)

    with pytest.raises(
        FoundryInventoryInvalidError,
        match="changed while it was monitored",
    ):
        _private_artifact_usage(
            root,
            hash_contents=False,
            purpose=foundry_module._PrivateArtifactTraversalPurpose.LIVE_LIMIT_MONITOR,
        )

    assert replaced is True
    assert moved_artifact.read_bytes() == b"trusted"


@pytest.mark.parametrize(
    ("purpose", "hash_contents"),
    (
        (foundry_module._PrivateArtifactTraversalPurpose.STRICT_SNAPSHOT, True),
        (foundry_module._PrivateArtifactTraversalPurpose.LIVE_LIMIT_MONITOR, False),
    ),
)
def test_private_artifact_usage_does_not_follow_replaced_queued_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    purpose: foundry_module._PrivateArtifactTraversalPurpose,
    hash_contents: bool,
) -> None:
    root = tmp_path / "execution"
    queued = root / "queued"
    moved_queued = root / "opened-queued"
    external = tmp_path / "external"
    queued.mkdir(parents=True)
    external.mkdir()
    (queued / "trusted.bin").write_bytes(b"trusted")
    (external / "outside.bin").write_bytes(b"outside")
    real_scandir = os.scandir
    scan_count = 0
    replaced = False

    def replacing_scandir(path: int | str | bytes | os.PathLike[str] | os.PathLike[bytes]):
        nonlocal replaced, scan_count
        scan_count += 1
        if scan_count == 2 and not replaced:
            queued.rename(moved_queued)
            try:
                queued.symlink_to(external, target_is_directory=True)
            except OSError:
                pytest.skip("directory symlinks are unavailable")
            replaced = True
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", replacing_scandir)

    with pytest.raises(
        FoundryInventoryInvalidError,
        match="directory changed while it was traversed",
    ):
        _private_artifact_usage(
            root,
            hash_contents=hash_contents,
            purpose=purpose,
        )

    assert replaced is True
    assert (moved_queued / "trusted.bin").read_bytes() == b"trusted"
    assert (queued / "outside.bin").read_bytes() == b"outside"


def test_private_artifact_usage_rejects_symlinked_intermediate_directory(
    tmp_path: Path,
) -> None:
    trusted_root = tmp_path / "private"
    outside = tmp_path / "outside"
    (outside / "execution").mkdir(parents=True)
    trusted_root.mkdir()
    (outside / "execution" / "outside.bin").write_bytes(b"outside")
    try:
        (trusted_root / "redirect").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")

    with pytest.raises(
        FoundryInventoryInvalidError,
        match="directory",
    ):
        _private_artifact_usage(
            trusted_root / "redirect" / "execution",
            trusted_root=trusted_root,
        )


def test_exact_result_is_parsed_from_the_hash_bound_stdout_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = _descriptor()
    workspace = tmp_path / "private" / "workspace"
    selected_source = workspace / descriptor.path
    selected_source.parent.mkdir(parents=True)
    selected_source.write_text("contract ExactSuiteTest {}\n", encoding="utf-8")
    private_dir = workspace.parent
    fake_forge = tmp_path / "forge"
    original_stdout = json.dumps(
        {
            f"{descriptor.path}:{descriptor.suite_name}": {
                "test_results": {
                    f"{descriptor.test_name}()": {
                        "status": "Success",
                        "kind": {"Unit": {"gas": 1}},
                    }
                }
            }
        },
        separators=(",", ":"),
    )
    replacement_stdout = json.dumps(
        {
            f"{descriptor.path}:{descriptor.suite_name}": {
                "test_results": {
                    "testDifferent()": {
                        "status": "Success",
                        "kind": {"Unit": {"gas": 1}},
                    }
                }
            }
        },
        separators=(",", ":"),
    )
    fake_forge.write_text(
        f"#!{sys.executable}\nimport time\ntime.sleep(0.1)\nprint({original_stdout!r})\n",
        encoding="utf-8",
    )
    fake_forge.chmod(0o700)
    compiler = tmp_path / "solc"
    compiler.write_bytes(b"compiler")
    selection = RepositorySuiteSelection.sealed(
        profile="explicit",
        repository_sha256="b" * 64,
        repository_exclusion_path=".mmaudit",
        configuration_sha256="c" * 64,
        candidate_file_count=1,
        candidate_test_count=1,
        selected_file_count=1,
        selected_test_count=1,
        omitted_file_count=0,
        omitted_test_count=0,
        limit_reached=False,
        tests=(descriptor,),
    )

    class _Backend:
        name = "sandbox-exec"

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

    original_usage = foundry_module._private_artifact_usage
    replaced = False
    usage_calls: list[tuple[bool, foundry_module._PrivateArtifactTraversalPurpose]] = []

    def replace_after_hash(
        root: Path,
        **kwargs: object,
    ) -> _PrivateArtifactUsage:
        nonlocal replaced
        purpose = kwargs.get(
            "purpose",
            foundry_module._PrivateArtifactTraversalPurpose.STRICT_SNAPSHOT,
        )
        assert isinstance(purpose, foundry_module._PrivateArtifactTraversalPurpose)
        usage_calls.append(
            (
                bool(kwargs.get("hash_contents", True)),
                purpose,
            )
        )
        usage = original_usage(root, **kwargs)
        if kwargs.get("hash_contents", True) and root.name == "00000" and not replaced:
            (root / "stdout.json").write_text(replacement_stdout, encoding="utf-8")
            replaced = True
        return usage

    monkeypatch.setattr(foundry_module, "_private_artifact_usage", replace_after_hash)
    observation, _usage = _execute_foundry_test(
        descriptor=descriptor,
        selection=selection,
        workspace=workspace,
        private_dir=private_dir,
        output_index=0,
        executable_path=fake_forge,
        compiler_path=compiler,
        compiler_sha256=hashlib.sha256(compiler.read_bytes()).hexdigest(),
        rpc_url="http://127.0.0.1:8545",
        rpc_port=8545,
        fork=PinnedForkObservation(
            chain_id=31_337,
            block_number=0,
            block_hash="0x" + ("b" * 64),
        ),
        fuzz_seed=SEED,
        fuzz_runs=16,
        invariant_runs=8,
        deadline=time.monotonic() + 5,
        max_output_bytes=1_000_000,
        backend=_Backend(),
        base_environment={"PATH": os.environ.get("PATH", "")},
    )

    assert replaced
    assert (
        False,
        foundry_module._PrivateArtifactTraversalPurpose.LIVE_LIMIT_MONITOR,
    ) in usage_calls
    assert (
        True,
        foundry_module._PrivateArtifactTraversalPurpose.STRICT_SNAPSHOT,
    ) in usage_calls
    assert observation.status is RepositoryTestExecutionStatus.PASSED
    assert observation.machine_output_validated


def test_foundry_process_limits_attempt_every_limit_then_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    def failing_setrlimit(kind: int, value: tuple[int, int]) -> None:
        del value
        calls.append(kind)
        if kind == 1:
            raise ValueError("synthetic limit failure")

    fake_resource = SimpleNamespace(
        RLIMIT_CPU=1,
        RLIMIT_FSIZE=2,
        RLIMIT_NOFILE=3,
        RLIMIT_NPROC=4,
        RLIMIT_AS=5,
        setrlimit=failing_setrlimit,
    )
    monkeypatch.setitem(sys.modules, "resource", fake_resource)
    monkeypatch.setattr(sys, "platform", "linux")

    with pytest.raises(RuntimeError, match="resource limit setup failed"):
        foundry_module._limit_process()

    assert calls == [1, 2, 3, 4, 5]


def test_exact_foundry_subprocess_receives_no_inherited_credentials(
    tmp_path: Path,
) -> None:
    descriptor = _descriptor()
    workspace = tmp_path / "private" / "workspace"
    selected_source = workspace / descriptor.path
    selected_source.parent.mkdir(parents=True)
    selected_source.write_text("contract ExactSuiteTest {}\n", encoding="utf-8")
    private_dir = workspace.parent
    rpc_url = "http://127.0.0.1:8545"
    fake_forge = tmp_path / "forge"
    exact_stdout = json.dumps(
        {
            f"{descriptor.path}:{descriptor.suite_name}": {
                "test_results": {
                    f"{descriptor.test_name}()": {
                        "status": "Success",
                        "kind": {"Unit": {"gas": 1}},
                    }
                }
            }
        },
        separators=(",", ":"),
    )
    forbidden_names = (
        "ALCHEMY_API_KEY",
        "INFURA_API_KEY",
        "MMAUDIT_FORK_RPC_URL",
        "MNEMONIC",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "PRIVATE_KEY",
        "WALLET_PRIVATE_KEY",
    )
    fake_forge.write_text(
        (
            f"#!{sys.executable}\n"
            "import os\n"
            f"for name in {forbidden_names!r}:\n"
            "    if name in os.environ:\n"
            "        raise SystemExit(91)\n"
            f"if os.environ.get('ETH_RPC_URL') != {rpc_url!r}:\n"
            "    raise SystemExit(92)\n"
            f"print({exact_stdout!r})\n"
        ),
        encoding="utf-8",
    )
    fake_forge.chmod(0o700)
    compiler = tmp_path / "solc"
    compiler.write_bytes(b"compiler")
    selection = RepositorySuiteSelection.sealed(
        profile="explicit",
        repository_sha256="b" * 64,
        repository_exclusion_path=".mmaudit",
        configuration_sha256="c" * 64,
        candidate_file_count=1,
        candidate_test_count=1,
        selected_file_count=1,
        selected_test_count=1,
        omitted_file_count=0,
        omitted_test_count=0,
        limit_reached=False,
        tests=(descriptor,),
    )

    class _CredentialInjectingBackend:
        name = "sandbox-exec"

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

        def host_environment(self, supplied_private_dir: Path) -> dict[str, str]:
            environment = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": str(supplied_private_dir / "host-home"),
            }
            environment.update({name: f"{name.casefold()}-canary" for name in forbidden_names})
            environment["ETH_RPC_URL"] = "https://credentialed.invalid"
            return environment

    observation, _usage = _execute_foundry_test(
        descriptor=descriptor,
        selection=selection,
        workspace=workspace,
        private_dir=private_dir,
        output_index=0,
        executable_path=fake_forge,
        compiler_path=compiler,
        compiler_sha256=hashlib.sha256(compiler.read_bytes()).hexdigest(),
        rpc_url=rpc_url,
        rpc_port=8545,
        fork=PinnedForkObservation(
            chain_id=31_337,
            block_number=0,
            block_hash="0x" + ("b" * 64),
        ),
        fuzz_seed=SEED,
        fuzz_runs=16,
        invariant_runs=8,
        deadline=time.monotonic() + 5,
        max_output_bytes=1_000_000,
        backend=_CredentialInjectingBackend(),
        base_environment={"PATH": os.environ.get("PATH", "")},
    )

    assert observation.status is RepositoryTestExecutionStatus.PASSED
    assert observation.machine_output_validated


def test_bounded_stream_usage_rejects_path_replacement_without_retaining_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout_path = tmp_path / "stdout.json"
    stderr_path = tmp_path / "stderr.txt"
    moved_stdout = tmp_path / "opened-stdout.json"
    stdout_path.write_bytes(b"trusted")
    stderr_path.write_bytes(b"stderr")
    replacement = b"changed"
    real_read = os.read
    replaced = False

    def replacing_read(descriptor: int, maximum_bytes: int) -> bytes:
        nonlocal replaced
        if not replaced:
            stdout_path.rename(moved_stdout)
            stdout_path.write_bytes(replacement)
            replaced = True
        return real_read(descriptor, maximum_bytes)

    monkeypatch.setattr(os, "read", replacing_read)

    usage = _bounded_stream_artifact_usage(stdout_path, stderr_path)

    assert usage.entries == 1
    assert usage.bytes == 0
    assert replaced is True
    assert moved_stdout.read_bytes() == b"trusted"
    assert stdout_path.read_bytes() == replacement


def test_bounded_stream_usage_fails_closed_without_no_follow_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout_path = tmp_path / "stdout.json"
    stderr_path = tmp_path / "stderr.txt"
    stdout_path.write_bytes(b"stdout")
    stderr_path.write_bytes(b"stderr")
    monkeypatch.delattr(os, "O_NOFOLLOW")

    usage = _bounded_stream_artifact_usage(stdout_path, stderr_path)

    assert usage.entries == 1
    assert usage.bytes == 0


def test_suite_artifact_budget_charges_inventory_before_per_test_outputs() -> None:
    budget = _SuiteArtifactBudget(
        max_bytes_per_test=6,
        max_total_bytes=10,
        max_entries_per_test=4,
        max_total_entries=8,
    )
    inventory = _PrivateArtifactUsage(
        entries=3,
        bytes=6,
        artifact_sha256=hashlib.sha256(b"inventory").hexdigest(),
    )
    test_output = _PrivateArtifactUsage(
        entries=2,
        bytes=5,
        artifact_sha256=hashlib.sha256(b"test").hexdigest(),
    )

    budget.charge(inventory, label="inventory", per_test=False)
    with pytest.raises(FoundryInventoryOverflowError, match="suite total"):
        budget.charge(test_output, label="test", per_test=True)

    per_test_overflow = _SuiteArtifactBudget(
        max_bytes_per_test=4,
        max_total_bytes=20,
        max_entries_per_test=4,
        max_total_entries=8,
    )
    with pytest.raises(FoundryInventoryOverflowError, match="per-test"):
        per_test_overflow.charge(test_output, label="test", per_test=True)


def test_deadline_allowance_never_exceeds_single_remaining_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("mmaudit.scanners.foundry.time.monotonic", lambda: 10.0)
    assert _remaining_deadline_seconds(13.0, maximum=20.0) == 3.0
    assert _remaining_deadline_seconds(13.0, maximum=2.0) == 2.0

    monkeypatch.setattr("mmaudit.scanners.foundry.time.monotonic", lambda: 13.0)
    with pytest.raises(_FoundrySuiteDeadlineExpired):
        _remaining_deadline_seconds(13.0, maximum=20.0)


def test_source_revalidation_fails_when_total_deadline_expires_after_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = _descriptor()
    source = tmp_path / descriptor.path
    source.parent.mkdir(parents=True)
    source.write_bytes(b"contract ExactSuiteTest {}")
    descriptor = RepositorySuiteTestDescriptor.sealed(
        **{
            **descriptor.model_dump(mode="python", exclude={"descriptor_sha256"}),
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        }
    )
    selection = RepositorySuiteSelection.sealed(
        profile="explicit",
        repository_sha256="b" * 64,
        repository_exclusion_path=".mmaudit",
        configuration_sha256="c" * 64,
        candidate_file_count=1,
        candidate_test_count=1,
        selected_file_count=1,
        selected_test_count=1,
        omitted_file_count=0,
        omitted_test_count=0,
        limit_reached=False,
        tests=(descriptor,),
    )
    observations = iter((10.0, 12.0))
    monkeypatch.setattr(
        "mmaudit.scanners.foundry.time.monotonic",
        lambda: next(observations),
    )

    with pytest.raises(_FoundrySuiteDeadlineExpired):
        _selection_sources_unchanged(tmp_path, selection, deadline=11.0)


def test_exact_foundry_parsing_cannot_outlive_per_test_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout = json.dumps(
        {
            "test/audit/ExactSuite.t.sol:ExactSuiteTest": {
                "test_results": {
                    "testExact()": {
                        "status": "Success",
                        "kind": {"Unit": {"gas": 1}},
                    }
                }
            }
        },
        separators=(",", ":"),
    )
    observations = iter((10.0, 12.0))
    monkeypatch.setattr(
        foundry_module.time,
        "monotonic",
        lambda: next(observations),
    )

    with pytest.raises(_FoundrySuiteDeadlineExpired):
        _parse_exact_foundry_test_with_deadline(
            stdout,
            descriptor=_descriptor(),
            return_code=0,
            deadline=11.0,
        )


def test_manifest_write_cannot_outlive_total_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection = RepositorySuiteSelection.sealed(
        profile="explicit",
        repository_sha256="b" * 64,
        repository_exclusion_path=".mmaudit",
        configuration_sha256="c" * 64,
        candidate_file_count=1,
        candidate_test_count=1,
        selected_file_count=1,
        selected_test_count=1,
        omitted_file_count=0,
        omitted_test_count=0,
        limit_reached=False,
        tests=(_descriptor(),),
    )
    expired = False
    real_write_text = Path.write_text

    def delayed_write_text(
        path: Path,
        data: str,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> int:
        nonlocal expired
        written = real_write_text(
            path,
            data,
            encoding=encoding,
            errors=errors,
            newline=newline,
        )
        expired = True
        return written

    monkeypatch.setattr(Path, "write_text", delayed_write_text)
    monkeypatch.setattr(
        foundry_module.time,
        "monotonic",
        lambda: 12.0 if expired else 10.0,
    )

    with pytest.raises(_FoundrySuiteDeadlineExpired):
        _write_repository_suite_manifest(
            tmp_path,
            selection,
            None,
            None,
            None,
            [],
            deadline=11.0,
        )


def test_manifest_serializes_bound_per_test_rpc_scope(tmp_path: Path) -> None:
    selection = _selection()
    baseline_dir = tmp_path / "baseline"
    baseline_dir.mkdir()
    baseline_path = _write_repository_suite_manifest(
        baseline_dir,
        selection,
        None,
        None,
        None,
        [],
        deadline=time.monotonic() + 10.0,
    )
    baseline_payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert "repository_test_fork_rpc_scopes" not in baseline_payload

    recorder = _ScopeRecorder()
    outcome = _execute_foundry_test_with_scope(
        recorder=recorder,
        attempt_binding_sha256=HASH_A,
        selection=selection,
        descriptor=selection.tests[0],
        sequence_index=1,
        execute=lambda: (_test_observation(selection.tests[0]), _test_usage()),
    )
    assert outcome.scope is not None

    path = _write_repository_suite_manifest(
        tmp_path,
        selection,
        None,
        None,
        None,
        [],
        [outcome.scope],
        deadline=time.monotonic() + 10.0,
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    scopes = payload["repository_test_fork_rpc_scopes"]
    assert len(scopes) == 1
    assert scopes[0]["attempt_binding_sha256"] == HASH_A
    assert scopes[0]["selection_sha256"] == selection.selection_sha256
    assert scopes[0]["descriptor_sha256"] == selection.tests[0].descriptor_sha256
    assert scopes[0]["sequence_index"] == 1
    serialized_scopes = json.dumps(scopes, sort_keys=True)
    assert "http://" not in serialized_scopes
    assert "https://" not in serialized_scopes


def test_finalizer_attaches_copy_evidence_only_to_successful_matrix_scoped_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "Example.sol").write_text("contract Example {}\n", encoding="utf-8")
    matrix_private = tmp_path / "matrix-private"
    matrix_private.mkdir()
    custody = copy_scanner_workspace_with_custody(
        repository,
        matrix_private / "workspace",
        matrix_private,
    )
    selection = _selection(repository_sha256=custody.source_inventory_sha256_before)
    policy = RepositorySuiteExecutionPolicy.sealed(
        selection_sha256=selection.selection_sha256,
        selection_configuration_sha256=selection.configuration_sha256,
        chain_id=31_337,
        block_number=0,
        block_hash="0x" + HASH_C,
        tool_version="forge 1.3.2",
        tool_sha256=HASH_A,
        compiler_version="solc 0.8.30",
        compiler_sha256=HASH_B,
        isolation_backend="synthetic-isolation",
        isolation_attestation_sha256=HASH_C,
        fuzz_seed=SEED,
        fuzz_runs=256,
        invariant_runs=64,
        per_test_timeout_seconds=10.0,
        total_timeout_seconds=60.0,
        max_output_bytes_per_test=1_024,
        max_total_output_bytes=10_240,
    )
    summary = FoundryTestExecutionSummary(
        unit_tests=1,
        fuzz_tests=0,
        invariant_tests=0,
        passed_tests=1,
        failed_tests=0,
        skipped_tests=0,
        fuzz_cases=0,
        invariant_runs=0,
        invariant_calls=0,
    )
    observation = _FoundryTestObservation(
        descriptor=selection.tests[0],
        status=RepositoryTestExecutionStatus.PASSED,
        terminal_detail=None,
        duration_seconds=0.1,
        command_sha256=HASH_A,
        output_sha256=HASH_B,
        output_bytes=1,
        process_exit_code=0,
        machine_output_validated=True,
        machine_result_sha256=HASH_C,
        summary=summary,
    )
    recorder = _ScopeRecorder()
    scoped = _execute_foundry_test_with_scope(
        recorder=recorder,
        attempt_binding_sha256=HASH_A,
        selection=selection,
        descriptor=selection.tests[0],
        sequence_index=1,
        execute=lambda: (observation, _test_usage()),
    )
    assert scoped.scope is not None
    backend = SimpleNamespace(name="synthetic-isolation")
    monkeypatch.setattr(foundry_module, "_cleanup_error", lambda *_args: None)
    monkeypatch.setattr(
        foundry_module,
        "isolation_attestation_sha256",
        lambda _backend: HASH_C,
    )

    matrix_run = _finalize_foundry_repository_suite(
        root=repository,
        private_dir=matrix_private,
        backend=backend,
        start=datetime.now(UTC),
        monotonic_start=time.monotonic(),
        deadline=time.monotonic() + 10.0,
        total_timeout_seconds=10.0,
        status=ScannerStatus.SUCCESS,
        error=None,
        selection=selection,
        observations=[observation],
        fork=PinnedForkObservation(
            chain_id=31_337,
            block_number=0,
            block_hash="0x" + HASH_C,
        ),
        executable_sha256=HASH_A,
        version="forge 1.3.2",
        compiler_version="solc 0.8.30",
        compiler_sha256=HASH_B,
        execution_policy=policy,
        inventory=None,
        post_inventory=None,
        fuzz_seed=SEED,
        repository_test_fork_rpc_scopes=[scoped.scope],
        repository_suite_workspace_custody=custody,
    )

    assert matrix_run.status is ScannerStatus.SUCCESS
    copy_evidence = matrix_run.repository_suite_workspace_copy
    assert copy_evidence is not None
    assert copy_evidence.copy_evidence_sha256 == copy_evidence.expected_copy_evidence_sha256()
    assert copy_evidence.attempt_binding_sha256 == HASH_A
    assert copy_evidence.selection_sha256 == selection.selection_sha256
    assert copy_evidence.repository_sha256 == selection.repository_sha256
    assert matrix_run.execution_observation_sha256_is_valid()

    legacy_private = tmp_path / "legacy-private"
    legacy_private.mkdir()
    legacy_run = _finalize_foundry_repository_suite(
        root=repository,
        private_dir=legacy_private,
        backend=backend,
        start=datetime.now(UTC),
        monotonic_start=time.monotonic(),
        deadline=time.monotonic() + 10.0,
        total_timeout_seconds=10.0,
        status=ScannerStatus.SUCCESS,
        error=None,
        selection=selection,
        observations=[observation],
        fork=PinnedForkObservation(
            chain_id=31_337,
            block_number=0,
            block_hash="0x" + HASH_C,
        ),
        executable_sha256=HASH_A,
        version="forge 1.3.2",
        compiler_version="solc 0.8.30",
        compiler_sha256=HASH_B,
        execution_policy=policy,
        inventory=None,
        post_inventory=None,
        fuzz_seed=SEED,
        repository_suite_workspace_copy=copy_evidence,
    )

    assert legacy_run.status is ScannerStatus.SUCCESS
    assert legacy_run.repository_suite_workspace_copy is None
    assert "repository_suite_workspace_copy" not in legacy_run.model_dump(mode="json")
    assert legacy_run.execution_observation_sha256_is_valid()


@pytest.mark.parametrize(
    "status",
    [ScannerStatus.FAILED, ScannerStatus.TIMED_OUT, ScannerStatus.UNAVAILABLE],
)
def test_finalizer_retains_scope_in_unverified_interrupted_run_and_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: ScannerStatus,
) -> None:
    selection = _selection()
    policy = RepositorySuiteExecutionPolicy.sealed(
        selection_sha256=selection.selection_sha256,
        selection_configuration_sha256=selection.configuration_sha256,
        chain_id=31_337,
        block_number=0,
        block_hash="0x" + HASH_C,
        tool_version="forge 1.3.2",
        tool_sha256=HASH_A,
        compiler_version="solc 0.8.30",
        compiler_sha256=HASH_B,
        isolation_backend="synthetic-isolation",
        isolation_attestation_sha256=HASH_C,
        fuzz_seed=SEED,
        fuzz_runs=256,
        invariant_runs=64,
        per_test_timeout_seconds=10.0,
        total_timeout_seconds=60.0,
        max_output_bytes_per_test=1_024,
        max_total_output_bytes=10_240,
    )
    recorder = _ScopeRecorder(policy_sha256=HASH_B)
    assert recorder.policy_sha256 != policy.policy_sha256
    scoped = _execute_foundry_test_with_scope(
        recorder=recorder,
        attempt_binding_sha256=HASH_A,
        selection=selection,
        descriptor=selection.tests[0],
        sequence_index=1,
        execute=lambda: (_test_observation(selection.tests[0]), _test_usage()),
    )
    assert scoped.scope is not None
    private_dir = tmp_path / "private"
    private_dir.mkdir()
    backend = SimpleNamespace(name="synthetic-isolation")
    monkeypatch.setattr(foundry_module, "_cleanup_error", lambda *_args: None)
    monkeypatch.setattr(
        foundry_module,
        "isolation_attestation_sha256",
        lambda _backend: HASH_C,
    )

    run = _finalize_foundry_repository_suite(
        root=tmp_path,
        private_dir=private_dir,
        backend=backend,
        start=datetime.now(UTC),
        monotonic_start=time.monotonic(),
        deadline=time.monotonic() + 10.0,
        total_timeout_seconds=10.0,
        status=status,
        error="synthetic scope-interrupted execution",
        selection=selection,
        observations=[],
        fork=PinnedForkObservation(
            chain_id=31_337,
            block_number=0,
            block_hash="0x" + HASH_C,
        ),
        executable_sha256=HASH_A,
        version="forge 1.3.2",
        compiler_version="solc 0.8.30",
        compiler_sha256=HASH_B,
        execution_policy=policy,
        inventory=None,
        post_inventory=None,
        fuzz_seed=SEED,
        repository_test_fork_rpc_scopes=[scoped.scope],
    )

    assert run.status is status
    assert run.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert run.repository_test_fork_rpc_scopes == [scoped.scope]
    assert run.raw_output_path is not None
    manifest = json.loads(
        (private_dir / "repository-suite-execution.json").read_text(encoding="utf-8")
    )
    assert manifest["repository_test_fork_rpc_scopes"] == [scoped.scope.model_dump(mode="json")]


def test_finalizer_downgrades_when_cleanup_crosses_total_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expired = False

    def delayed_cleanup(backend: object, private_dir: Path) -> None:
        nonlocal expired
        del backend, private_dir
        expired = True
        return None

    monkeypatch.setattr(foundry_module, "_cleanup_error", delayed_cleanup)
    monkeypatch.setattr(
        foundry_module.time,
        "monotonic",
        lambda: 12.0 if expired else 10.0,
    )

    run = _finalize_foundry_repository_suite(
        root=tmp_path,
        private_dir=tmp_path / "private",
        backend=None,
        start=datetime.now(UTC),
        monotonic_start=10.0,
        deadline=11.0,
        total_timeout_seconds=1.0,
        status=ScannerStatus.SUCCESS,
        error=None,
        selection=None,
        observations=[],
        fork=None,
        executable_sha256=None,
        version=None,
        compiler_version=None,
        compiler_sha256=None,
        execution_policy=None,
        inventory=None,
        post_inventory=None,
        fuzz_seed=SEED,
    )

    assert run.status is ScannerStatus.TIMED_OUT
    assert run.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert run.machine_output_validated is False
    assert run.duration_seconds >= 2.0


def test_finalizer_downgrades_when_model_validation_crosses_total_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expired = False
    real_model_validate = ScannerRun.model_validate

    def delayed_model_validate(
        cls: type[ScannerRun],
        payload: object,
    ) -> ScannerRun:
        nonlocal expired
        del cls
        validated = real_model_validate(payload)
        expired = True
        return validated

    monkeypatch.setattr(
        ScannerRun,
        "model_validate",
        classmethod(delayed_model_validate),
    )
    monkeypatch.setattr(
        foundry_module.time,
        "monotonic",
        lambda: 12.0 if expired else 10.0,
    )

    run = _finalize_foundry_repository_suite(
        root=tmp_path,
        private_dir=tmp_path / "private",
        backend=None,
        start=datetime.now(UTC),
        monotonic_start=10.0,
        deadline=11.0,
        total_timeout_seconds=1.0,
        status=ScannerStatus.FAILED,
        error="synthetic pre-finalization failure",
        selection=None,
        observations=[],
        fork=None,
        executable_sha256=None,
        version=None,
        compiler_version=None,
        compiler_sha256=None,
        execution_policy=None,
        inventory=None,
        post_inventory=None,
        fuzz_seed=SEED,
    )

    assert run.status is ScannerStatus.TIMED_OUT
    assert run.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert run.error == "repository fork suite exceeded 1s total timeout"
    assert run.duration_seconds >= 2.0
