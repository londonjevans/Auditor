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
    RepositorySuiteFramework,
    RepositorySuiteSelection,
    RepositorySuiteTestDescriptor,
    RepositoryTestExecutionStatus,
    ScannerRun,
    ScannerStatus,
)
from mmaudit.scanners.fork_rpc import PinnedForkObservation
from mmaudit.scanners.foundry import (
    _bounded_stream_artifact_usage,
    _display_foundry_test_command,
    _execute_foundry_test,
    _finalize_foundry_repository_suite,
    _foundry_inventory_limits,
    _FoundrySuiteDeadlineExpired,
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

HASH_A = "a" * 64
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
