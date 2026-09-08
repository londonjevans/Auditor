"""No-probe/no-scan invariants for synthetic local executable identities."""

from __future__ import annotations

import hashlib
import os
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from mmaudit.models.schemas import ExecutionEvidenceKind, ScannerFinding, ScannerStatus
from mmaudit.scanners import base
from mmaudit.scanners.diagnostics import ExecutableVersionProbe, ExecutableVersionProbeStatus

FIXTURE = Path(__file__).parents[1] / "fixtures" / "scanners" / "identity-inert.txt"


class _InertScanner(base.ScannerAdapter):
    name = "synthetic-identity"

    def __init__(self, executable: Path, prepare: Callable[[], None] = lambda: None) -> None:
        self.executable = str(executable)
        self.prepare = prepare

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        return [self.executable]

    def validate_pre_execution_inputs(self, workspace: Path, private_dir: Path) -> None:
        self.prepare()

    def parse(self, root: Path, stdout: str, private_dir: Path) -> list[ScannerFinding]:
        return []


class _NoExecutionBackend:
    name = "synthetic-identity-test"
    supports_local_fork_rpc = False

    def __init__(self, prepare: Callable[[], None] = lambda: None) -> None:
        self.prepare = prepare

    def wrap(
        self, command: list[str], *, workspace: Path, private_dir: Path, rpc_port: int
    ) -> list[str]:
        self.prepare()
        return command


@pytest.fixture
def inert_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "Safe.sol").write_text("contract Safe {}\n", encoding="utf-8")
    executable = tmp_path / "inert-tool"
    shutil.copyfile(FIXTURE, executable)
    executable.chmod(0o700)

    def forbidden_process(*args: object, **kwargs: object) -> Any:
        pytest.fail("invariant: inert tool must never be executed")

    monkeypatch.setattr(base.subprocess, "Popen", forbidden_process)
    return repository, executable, hashlib.sha256(executable.read_bytes()).hexdigest()


@pytest.mark.parametrize("pin_case", ["wrong-digest", "version-only", "digest-only"])
@pytest.mark.parametrize("source_bound", [False, True])
def test_rejected_pin_never_copies_or_probes(
    inert_inputs: tuple[Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
    pin_case: str,
    source_bound: bool,
) -> None:
    repository, executable, digest = inert_inputs
    private = repository.parent / "private"

    def forbidden_preparation(*args: object, **kwargs: object) -> Any:
        pytest.fail("invariant: rejected executable pin must stop before copying or probing")

    monkeypatch.setattr(base, "copy_scanner_workspace_with_custody", forbidden_preparation)
    monkeypatch.setattr(base, "isolated_executable_version_probe", forbidden_preparation)
    scanner = _InertScanner(executable)
    options = dict(
        backend=_NoExecutionBackend(),
        expected_version=None if pin_case == "digest-only" else "1.2.3",
        expected_sha256=(
            None
            if pin_case == "version-only"
            else ("0" * 64 if pin_case == "wrong-digest" else digest)
        ),
    )
    if source_bound:
        result = scanner.run_source_bound(
            repository,
            private,
            1,
            expected_repository_sha256=base.scanner_workspace_sha256(repository),
            audited_relative_paths=("Safe.sol",),
            **options,
        )
    else:
        result = scanner.run(repository, private, 1, **options)

    assert result.status is ScannerStatus.FAILED
    assert "pin" in (result.error or "")
    assert result.version is None
    assert result.command == []
    assert result.executable_sha256 == digest
    assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert not (private / "workspace").exists()


@pytest.mark.parametrize("stage", ["before-probe", "during-probe", "before-scan"])
@pytest.mark.parametrize("pinned", [False, True])
def test_changed_executable_never_reaches_next_invocation(
    inert_inputs: tuple[Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    pinned: bool,
) -> None:
    repository, executable, digest = inert_inputs
    probes: list[str] = []

    def change() -> None:
        executable.write_bytes(b"Different inert synthetic identity; never execute.\n")

    def probe(*args: object, **kwargs: object) -> ExecutableVersionProbe:
        assert stage != "before-probe", "changed material must not be version-probed"
        probes.append("version")
        if stage == "during-probe":
            change()
        return ExecutableVersionProbe(
            status=ExecutableVersionProbeStatus.SUCCESS,
            version="tool 1.2.3",
            diagnostic=None,
            return_code=0,
        )

    monkeypatch.setattr(base, "isolated_executable_version_probe", probe)
    scanner = _InertScanner(executable, change if stage == "before-scan" else lambda: None)
    result = scanner.run(
        repository,
        repository.parent / "private",
        1,
        backend=_NoExecutionBackend(change if stage == "before-probe" else lambda: None),
        expected_version="1.2.3" if pinned else None,
        expected_sha256=digest if pinned else None,
    )

    assert result.status is ScannerStatus.FAILED
    assert "executable" in (result.error or "")
    assert probes == ([] if stage == "before-probe" else ["version"])
    assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert result.raw_output_path is None


@pytest.mark.parametrize("mutation", ["same-bytes-new-inode", "changed-then-restored", "unlink"])
def test_observed_identity_drift_is_not_hidden_by_equal_content(
    inert_inputs: tuple[Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    repository, executable, digest = inert_inputs
    original = executable.read_bytes()

    def change() -> None:
        if mutation == "same-bytes-new-inode":
            replacement = executable.with_name("replacement")
            replacement.write_bytes(original)
            replacement.chmod(0o700)
            os.replace(replacement, executable)
        elif mutation == "changed-then-restored":
            executable.write_bytes(b"Different inert bytes.\n")
            executable.write_bytes(original)
        else:
            executable.unlink()

    def forbidden_probe(*args: object, **kwargs: object) -> Any:
        pytest.fail("invariant: changed executable identity must not be probed")

    monkeypatch.setattr(base, "isolated_executable_version_probe", forbidden_probe)
    result = _InertScanner(executable).run(
        repository,
        repository.parent / "private",
        1,
        backend=_NoExecutionBackend(change),
        expected_version="1.2.3",
        expected_sha256=digest,
    )

    assert result.status is ScannerStatus.FAILED
    assert "executable" in (result.error or "")
    assert result.version is None
    assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED


def test_unchanged_observation_is_repeatable_and_content_bound(
    inert_inputs: tuple[Path, Path, str],
) -> None:
    _, executable, digest = inert_inputs
    observed = base._observe_scanner_executable(executable)
    assert observed.sha256 == digest
    assert base._observe_scanner_executable(executable) == observed
    assert base._scanner_executable_recheck_error(executable, observed, boundary="test") is None


@pytest.mark.parametrize("material", ["empty", "oversize", "not-executable", "hardlink", "symlink"])
def test_invalid_initial_material_is_refused_before_reading(
    inert_inputs: tuple[Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
    material: str,
) -> None:
    _, executable, _ = inert_inputs
    if material == "empty":
        executable.write_bytes(b"")
    elif material == "oversize":
        monkeypatch.setattr(base, "_MAX_SCANNER_EXECUTABLE_BYTES", 1)
    elif material == "not-executable":
        executable.chmod(0o600)
    elif material == "hardlink":
        os.link(executable, executable.with_name("shared-inert"))
    else:
        target = executable.with_name("other-inert")
        executable.rename(target)
        executable.symlink_to(target)

    def forbidden_read(*args: object, **kwargs: object) -> Any:
        pytest.fail("invariant: invalid executable material must not be read")

    monkeypatch.setattr(base.os, "read", forbidden_read)
    with pytest.raises(ValueError, match="scanner executable"):
        base._observe_scanner_executable(executable)


@pytest.mark.parametrize("material", ["fifo", "symlink", "hardlink", "new-inode"])
def test_swap_between_stat_and_open_is_refused_without_content_read(
    inert_inputs: tuple[Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
    material: str,
) -> None:
    _, executable, _ = inert_inputs
    if material == "fifo" and not hasattr(os, "mkfifo"):
        pytest.skip("FIFOs unavailable")
    original = executable.read_bytes()
    real_open = os.open
    swapped = False

    def swap(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        nonlocal swapped
        if path == executable and not swapped:
            assert flags & os.O_NONBLOCK and flags & os.O_NOFOLLOW
            swapped = True
            target = executable.with_name("saved-inert")
            executable.rename(target)
            if material == "fifo":
                os.mkfifo(executable, mode=0o700)
            elif material == "symlink":
                executable.symlink_to(target)
            elif material == "hardlink":
                os.link(target, executable)
            else:
                executable.write_bytes(original)
                executable.chmod(0o700)
        return real_open(path, flags, *args, **kwargs)

    def forbidden_read(*args: object, **kwargs: object) -> Any:
        pytest.fail("invariant: swapped executable material must not be read")

    monkeypatch.setattr(base.os, "open", swap)
    monkeypatch.setattr(base.os, "read", forbidden_read)
    with pytest.raises((OSError, ValueError)):
        base._observe_scanner_executable(executable)
    assert swapped


@pytest.mark.parametrize("mutation", ["growth", "same-bytes-new-inode", "restore"])
def test_changes_during_hashing_do_not_produce_an_observation(
    inert_inputs: tuple[Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    _, executable, _ = inert_inputs
    original = executable.read_bytes()
    real_read = os.read
    changed = False
    read_bytes = 0

    def changing_read(descriptor: int, count: int) -> bytes:
        nonlocal changed, read_bytes
        if not changed:
            changed = True
            if mutation == "growth":
                executable.write_bytes(original * 20)
            elif mutation == "same-bytes-new-inode":
                replacement = executable.with_name("replacement-inert")
                replacement.write_bytes(original)
                replacement.chmod(0o700)
                os.replace(replacement, executable)
            else:
                executable.write_bytes(b"Changed inert material.\n")
                executable.write_bytes(original)
        content = real_read(descriptor, count)
        read_bytes += len(content)
        return content

    monkeypatch.setattr(base.os, "read", changing_read)
    with pytest.raises(ValueError, match="scanner executable"):
        base._observe_scanner_executable(executable)
    assert changed
    assert read_bytes <= len(original) + 1


@pytest.mark.parametrize("flag", ["O_NOFOLLOW", "O_NONBLOCK"])
def test_observation_refuses_when_safe_open_primitive_is_unavailable(
    inert_inputs: tuple[Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
    flag: str,
) -> None:
    _, executable, _ = inert_inputs
    monkeypatch.setattr(base.os, flag, 0)
    with pytest.raises(ValueError, match="safe observation is unavailable"):
        base._observe_scanner_executable(executable)


@pytest.mark.parametrize("boundary", ["initial", "before-probe", "before-scan"])
def test_unreadable_executable_becomes_a_closed_failure(
    inert_inputs: tuple[Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    repository, executable, digest = inert_inputs
    real_observe = base._observe_scanner_executable
    observed = 0
    probes = 0
    fail_on = {"initial": 1, "before-probe": 2, "before-scan": 3}[boundary]

    def observe(path: Path) -> base._ScannerExecutableObservation:
        nonlocal observed
        observed += 1
        if observed == fail_on:
            raise OSError("synthetic unavailable executable")
        return real_observe(path)

    def probe(*args: object, **kwargs: object) -> ExecutableVersionProbe:
        nonlocal probes
        probes += 1
        return ExecutableVersionProbe(ExecutableVersionProbeStatus.SUCCESS, "tool 1.2.3", None, 0)

    monkeypatch.setattr(base, "_observe_scanner_executable", observe)
    monkeypatch.setattr(base, "isolated_executable_version_probe", probe)
    result = _InertScanner(executable).run(
        repository,
        repository.parent / "private",
        1,
        backend=_NoExecutionBackend(),
        expected_version="1.2.3",
        expected_sha256=digest,
    )
    assert result.status is ScannerStatus.FAILED
    assert "executable" in (result.error or "")
    assert probes == (1 if boundary == "before-scan" else 0)
    assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED


def test_repository_javascript_pin_cannot_be_satisfied_by_a_host_observation(
    inert_inputs: tuple[Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, executable, digest = inert_inputs

    class ImageBackend(_NoExecutionBackend):
        def wrap_repository_javascript(
            self, command: list[str], *, workspace: Path, private_dir: Path, rpc_port: int
        ) -> list[str]:
            pytest.fail("invariant: absent image-side identity must stop before image probing")

    def forbidden_host(*args: object, **kwargs: object) -> Any:
        pytest.fail("invariant: host identity must not stand in for image-side identity")

    scanner = _InertScanner(executable)
    scanner.may_execute_repository_code = True
    monkeypatch.setattr(base, "contains_hardhat_repository_code", lambda _: True)
    monkeypatch.setattr(base, "_observe_scanner_executable", forbidden_host)
    monkeypatch.setattr(base, "isolated_executable_version_probe", forbidden_host)
    result = scanner.run(
        repository,
        repository.parent / "private",
        1,
        backend=ImageBackend(),
        expected_version="1.2.3",
        expected_sha256=digest,
    )
    assert result.status is ScannerStatus.FAILED
    assert "SHA-256" in (result.error or "")
    assert result.executable_sha256 is None
    assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED


@pytest.mark.parametrize("stage", ["wrapper", "environment", "stream"])
@pytest.mark.parametrize("pinned", [False, True])
def test_version_probe_rechecks_after_its_own_preparation(
    inert_inputs: tuple[Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    pinned: bool,
) -> None:
    repository, executable, digest = inert_inputs
    cleanup_calls: list[Path] = []

    def change() -> None:
        executable.write_bytes(b"Different inert material prepared before version launch.\n")

    class PreparingBackend(_NoExecutionBackend):
        def wrap(
            self, command: list[str], *, workspace: Path, private_dir: Path, rpc_port: int
        ) -> list[str]:
            if stage == "wrapper" and command[-1] == "--version":
                change()
            return command

        def host_environment(self, private_dir: Path) -> dict[str, str]:
            if stage == "environment":
                change()
            return {}

        def cleanup(self, private_dir: Path) -> None:
            cleanup_calls.append(private_dir)

    real_identity = base._private_probe_stream_identity

    def identify_stream(handle: Any) -> base._PrivateProbeStreamIdentity:
        identity = real_identity(handle)
        if stage == "stream":
            change()
        return identity

    monkeypatch.setattr(base, "_private_probe_stream_identity", identify_stream)
    result = _InertScanner(executable).run(
        repository,
        repository.parent / "private",
        1,
        backend=PreparingBackend(),
        expected_version="1.2.3" if pinned else None,
        expected_sha256=digest if pinned else None,
    )
    assert result.status is ScannerStatus.FAILED
    assert "executable" in (result.error or "")
    assert result.version is None
    assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert cleanup_calls == [repository.parent / "private"]
