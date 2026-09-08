"""Synthetic CID and mocked CLI observations confer no runtime or image authority."""

from __future__ import annotations

import io
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from mmaudit.isolation import container_cleanup as cleanup
from tests.unit.test_isolation import _backend

CID = "a" * 64


@pytest.fixture
def selected(tmp_path, monkeypatch):
    private = tmp_path / "private"
    runtime = private / "container-runtime"
    runtime.mkdir(mode=0o700, parents=True)
    cidfile = runtime / "container.cid"
    cidfile.write_text(CID, encoding="ascii")
    backend = _backend(executable=str(Path(sys.executable).resolve(strict=True)))
    monkeypatch.setattr(cleanup, "_runtime_identity", lambda *_: "fixed mock observation")

    def forbid(*args, **kwargs):
        pytest.fail("unit test attempted an actual process")

    monkeypatch.setattr(cleanup, "_run_control_command", forbid)
    return backend, private, cidfile


def mock_controls(monkeypatch, outputs):
    iterator = iter(outputs)
    calls = []

    def control(command, **kwargs):
        calls.append((command, kwargs))
        value = next(iterator)
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(cleanup, "_run_control_command", control)
    return calls


@pytest.mark.parametrize("status", ["absent", "removed", "newline"])
def test_exact_query_and_removal_observations_are_noncrediting(selected, monkeypatch, status):
    backend, private, cidfile = selected
    if status == "newline":
        cidfile.write_text(CID + "\n", encoding="ascii")
    outputs = [b""] if status == "absent" else [CID.encode(), b"", b""]
    calls = mock_controls(monkeypatch, outputs)
    result = cleanup.cleanup_rootless_container(backend, private)
    assert result.status is (
        cleanup.ContainerCleanupStatus.ALREADY_ABSENT
        if status == "absent"
        else cleanup.ContainerCleanupStatus.REMOVED
    )
    assert result.absence_verified and result.container_id == CID
    assert result.execution_credit is result.runtime_authority is False
    assert CID not in repr(result) and not cidfile.exists()
    query = (
        backend.executable,
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--quiet",
        "--filter",
        "id=" + CID,
    )
    assert calls[0][0] == query
    if status != "absent":
        assert calls[1][0] == (backend.executable, "rm", "--force", CID)
        assert calls[2][0] == query


@pytest.mark.parametrize("missing", ["cid", "runtime"])
def test_missing_identifier_is_not_verified_absence_or_a_runtime_probe(selected, missing):
    backend, private, cidfile = selected
    cidfile.unlink()
    if missing == "runtime":
        cidfile.parent.rmdir()
    result = cleanup.cleanup_rootless_container(backend, private)
    assert result.status is cleanup.ContainerCleanupStatus.NO_IDENTIFIER
    assert result.container_id is None and not result.absence_verified
    assert result.execution_credit is result.runtime_authority is False


@pytest.mark.parametrize("value", [True, False, 0, -1, 30.1, float("inf"), float("nan"), "2"])
def test_cleanup_budget_is_finite_positive_and_cannot_widen(selected, value):
    backend, private, cidfile = selected
    with pytest.raises(cleanup.ContainerCleanupError):
        cleanup.cleanup_rootless_container(backend, private, timeout_seconds=value)
    assert cidfile.exists()


@pytest.mark.parametrize(
    "content",
    [
        b"a" * 12,
        b"A" * 64,
        b"a" * 63,
        b"a" * 66,
        b" " + b"a" * 64,
        b"a" * 64 + b"\r\n",
        b"\xff" * 64,
    ],
)
def test_only_one_full_lowercase_identifier_is_accepted(selected, content):
    backend, private, cidfile = selected
    cidfile.write_bytes(content)
    with pytest.raises(cleanup.ContainerCleanupError):
        cleanup.cleanup_rootless_container(backend, private)
    assert cidfile.read_bytes() == content


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "directory", "writable"])
def test_unsafe_identifier_file_is_retained_without_process(selected, kind):
    backend, private, cidfile = selected
    target = private / "synthetic-original.cid"
    if kind == "writable":
        cidfile.chmod(0o666)
    else:
        cidfile.rename(target)
        if kind == "symlink":
            cidfile.symlink_to(target)
        elif kind == "hardlink":
            os.link(target, cidfile)
        elif kind == "fifo":
            os.mkfifo(cidfile, 0o600)
        else:
            cidfile.mkdir()
    with pytest.raises(cleanup.ContainerCleanupError):
        cleanup.cleanup_rootless_container(backend, private)
    assert cidfile.lstat()


@pytest.mark.parametrize(
    "output",
    [
        b"\n",
        b"b" * 64,
        b"a" * 12,
        b"a" * 64 + b"\n\n",
        b"a" * 64 + b"\r\n",
        b"a" * 64 + b"\nb" * 64,
        b"\xff",
    ],
)
def test_ambiguous_scoped_response_is_not_absence(selected, monkeypatch, output):
    backend, private, cidfile = selected
    calls = mock_controls(monkeypatch, [output])
    with pytest.raises(cleanup.ContainerCleanupError, match="ambiguous"):
        cleanup.cleanup_rootless_container(backend, private)
    assert len(calls) == 1 and cidfile.read_text() == CID


@pytest.mark.parametrize("failed_step", [0, 1, 2])
def test_query_or_removal_failure_retains_identifier(selected, monkeypatch, failed_step):
    backend, private, cidfile = selected
    error = cleanup.ContainerCleanupError("synthetic control failed")
    outputs = [CID.encode(), b"", b""]
    outputs[failed_step] = error
    calls = mock_controls(monkeypatch, outputs)
    with pytest.raises(cleanup.ContainerCleanupError) as caught:
        cleanup.cleanup_rootless_container(backend, private)
    assert caught.value is error and len(calls) == failed_step + 1
    assert cidfile.read_text() == CID


def test_successful_removal_exit_without_absence_is_refused(selected, monkeypatch):
    backend, private, cidfile = selected
    mock_controls(monkeypatch, [CID.encode(), b"", CID.encode()])
    with pytest.raises(cleanup.ContainerCleanupError, match="verify removal"):
        cleanup.cleanup_rootless_container(backend, private)
    assert cidfile.exists()


@pytest.mark.parametrize(
    "drift", ["cid_content", "cid_identity", "runtime", "home", "backend", "executable", "deadline"]
)
def test_changed_custody_or_expiry_after_query_cannot_delete_evidence(selected, monkeypatch, drift):
    backend, private, cidfile = selected
    clock = [100.0]
    monkeypatch.setattr(cleanup.time, "monotonic", lambda: clock[0])

    def changed(command, **kwargs):
        if drift == "cid_content":
            cidfile.write_text("b" * 64)
        elif drift == "cid_identity":
            cidfile.rename(cidfile.with_suffix(".retained"))
            cidfile.write_text(CID)
        elif drift == "runtime":
            cidfile.parent.chmod(0o755)
        elif drift == "home":
            (cidfile.parent / "runtime-home").chmod(0o755)
        elif drift == "backend":
            object.__setattr__(backend, "host_uid", 1001)
        elif drift == "executable":
            monkeypatch.setattr(cleanup, "_runtime_identity", lambda *_: "changed")
        else:
            clock[0] = 131.0
        return b""

    monkeypatch.setattr(cleanup, "_run_control_command", changed)
    with pytest.raises(cleanup.ContainerCleanupError):
        cleanup.cleanup_rootless_container(backend, private)
    assert cidfile.exists()


def test_cleanup_commands_share_one_narrowing_deadline_and_scrubbed_environment(
    selected, monkeypatch
):
    backend, private, cidfile = selected
    clock = [100.0]
    monkeypatch.setattr(cleanup.time, "monotonic", lambda: clock[0])
    monkeypatch.setenv("OPENROUTER_API_KEY", "synthetic-not-a-secret")
    monkeypatch.setenv("PATH", ".:/synthetic-source")
    outputs = iter([CID.encode(), b"", b""])
    deadlines = []

    def control(command, **kwargs):
        deadlines.append(kwargs["deadline"])
        environment = kwargs["environment"]
        assert environment["HOME"] == str(cidfile.parent / "runtime-home")
        assert "OPENROUTER_API_KEY" not in environment
        assert "injected" not in environment
        assert environment["PATH"] == str(Path(backend.executable).parent) + ":/usr/bin:/bin"
        environment["injected"] = "mock mutation must not reach next command"
        clock[0] += 2
        return next(outputs)

    monkeypatch.setattr(cleanup, "_run_control_command", control)
    result = cleanup.cleanup_rootless_container(backend, private, timeout_seconds=9)
    assert result.absence_verified and deadlines == [109.0, 109.0, 109.0]


def test_backend_subclass_cannot_override_cleanup_controls(selected):
    backend, private, cidfile = selected

    class UntrustedBackend(type(backend)):
        pass

    untrusted = UntrustedBackend(
        **{key: getattr(backend, key) for key in backend.__dataclass_fields__}
    )
    with pytest.raises(cleanup.ContainerCleanupError):
        cleanup.cleanup_rootless_container(untrusted, private)
    assert cidfile.exists()


def test_runtime_file_observation_rejects_repository_private_or_alias_paths(tmp_path):
    private = tmp_path / "private"
    private.mkdir()
    for executable in (private / "podman", Path.cwd() / "podman"):
        with pytest.raises(cleanup.ContainerCleanupError):
            cleanup._runtime_identity(executable, private)
    alias = tmp_path / "podman-alias"
    alias.symlink_to(Path(sys.executable).resolve(strict=True))
    with pytest.raises(ValueError):
        cleanup._runtime_identity(alias, private)


def test_private_root_alias_is_refused(selected):
    backend, private, cidfile = selected
    alias = private.parent / "private-alias"
    alias.symlink_to(private, target_is_directory=True)
    with pytest.raises(cleanup.ContainerCleanupError):
        cleanup.cleanup_rootless_container(replace(backend), alias)
    assert cidfile.exists()


@pytest.mark.parametrize("error", [RuntimeError("primary"), KeyboardInterrupt(), SystemExit(7)])
def test_control_primary_exception_survives_cleanup_error(tmp_path, monkeypatch, error):
    class Process:
        stdout = io.BytesIO()
        stderr = io.BytesIO()

    process = Process()
    monkeypatch.setattr(cleanup.subprocess, "Popen", lambda *args, **kwargs: process)

    def fail_capture(*args, **kwargs):
        raise error

    def fail_cleanup(*args, **kwargs):
        raise RuntimeError("secondary cleanup failure")

    monkeypatch.setattr(cleanup, "_capture_pipes", fail_capture)
    monkeypatch.setattr(cleanup, "_cleanup_child", fail_cleanup)
    with pytest.raises(type(error)) as caught:
        cleanup._run_control_command(
            (str(Path(sys.executable).resolve(strict=True)),),
            runtime_dir=tmp_path,
            environment={},
            deadline=cleanup.time.monotonic() + 10,
        )
    assert caught.value is error
    assert process.stdout.closed and process.stderr.closed


@pytest.mark.parametrize("target", ["runtime", "home"])
def test_private_runtime_or_home_alias_is_rejected_without_process(selected, target):
    backend, private, cidfile = selected
    if target == "runtime":
        retained = private / "retained-runtime"
        cidfile.parent.rename(retained)
        cidfile.parent.symlink_to(retained, target_is_directory=True)
    else:
        retained = private / "retained-home"
        retained.mkdir(mode=0o700)
        (cidfile.parent / "runtime-home").symlink_to(retained, target_is_directory=True)
    with pytest.raises(cleanup.ContainerCleanupError):
        cleanup.cleanup_rootless_container(backend, private)
    assert cidfile.read_text() == CID


def test_late_evidence_finalization_cannot_return_a_successful_observation(selected, monkeypatch):
    backend, private, cidfile = selected
    clock = [100.0]
    monkeypatch.setattr(cleanup.time, "monotonic", lambda: clock[0])
    mock_controls(monkeypatch, [b""])
    original = os.unlink

    def late_unlink(path, *, dir_fd):
        assert path == "container.cid"
        original(path, dir_fd=dir_fd)
        clock[0] = 131.0

    monkeypatch.setattr(cleanup.os, "unlink", late_unlink)
    with pytest.raises(cleanup.ContainerCleanupError, match="finalization exceeded"):
        cleanup.cleanup_rootless_container(backend, private)
    # Confirmed absence preceded unlink. A late failure cannot roll back evidence removal;
    # a subsequent NO_IDENTIFIER must never be used as a substitute for successful finalization.
    assert not cidfile.exists()
