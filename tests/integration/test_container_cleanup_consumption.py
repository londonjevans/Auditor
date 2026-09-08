"""Actual bounded Python control processes, MOCK runtime replies and no real containers."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from mmaudit.isolation import container_cleanup as cleanup
from tests.integration.test_hardhat_supervision_consumption import no_network as no_network
from tests.unit.test_isolation import _backend

CONTROL = Path(__file__).parents[1] / "fixtures/container_cleanup/control.py"
CID = "a" * 64


@pytest.fixture
def selected_controls(tmp_path, monkeypatch):
    executable = str(Path(sys.executable).resolve(strict=True))
    private = tmp_path / "private"
    runtime = private / "container-runtime"
    runtime.mkdir(mode=0o700, parents=True)
    cidfile = runtime / "container.cid"
    cidfile.write_text(CID, encoding="ascii")
    original = subprocess.Popen
    processes, calls, modes = [], [], []

    def launch(command, **kwargs):
        assert command in {
            (
                executable,
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--quiet",
                "--filter",
                "id=" + CID,
            ),
            (executable, "rm", "--force", CID),
        }
        assert kwargs["cwd"] == runtime
        assert kwargs["shell"] is False and kwargs["close_fds"] is True
        assert kwargs["start_new_session"] is True
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["stdout"] == kwargs["stderr"] == subprocess.PIPE
        assert kwargs["env"]["HOME"] == str(runtime / "runtime-home")
        assert "OPENROUTER_API_KEY" not in kwargs["env"]
        calls.append(command)
        # No runtime argv is executed: select only this committed, fixed finite control.
        process = original((executable, "-I", str(CONTROL), modes.pop(0)), **kwargs)
        processes.append(process)
        return process

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: cleanup integration cannot run an actual container runtime")

    monkeypatch.setattr(subprocess, "Popen", launch)
    monkeypatch.setattr(subprocess, "run", forbidden)
    yield _backend(executable=executable), private, cidfile, calls, modes, processes
    for process in processes:
        alive = process.poll() is None
        if alive:
            process.kill()
            process.wait(timeout=2)
        assert not alive, "owned cleanup child required test-fixture intervention"
        assert process.stdout.closed and process.stderr.closed


@pytest.mark.parametrize("removed", [False, True])
def test_actual_fixed_controls_require_successful_exact_absence(selected_controls, removed):
    backend, private, cidfile, calls, modes, _ = selected_controls
    modes.extend(["present", "present", "absent"] if removed else ["absent"])
    result = cleanup.cleanup_rootless_container(backend, private)
    assert result.status is (
        cleanup.ContainerCleanupStatus.REMOVED
        if removed
        else cleanup.ContainerCleanupStatus.ALREADY_ABSENT
    )
    assert result.absence_verified and not cidfile.exists()
    assert result.execution_credit is result.runtime_authority is False
    assert len(calls) == (3 if removed else 1) and not modes


@pytest.mark.parametrize(
    "mode",
    ["error", "warning", "ambiguous", "stdout_limit", "stderr_limit", "timeout", "descendant"],
)
def test_actual_failed_or_unbounded_response_is_not_absence(selected_controls, mode):
    backend, private, cidfile, calls, modes, _ = selected_controls
    modes.append(mode)
    started = time.monotonic()
    with pytest.raises(cleanup.ContainerCleanupError):
        cleanup.cleanup_rootless_container(
            backend, private, timeout_seconds=0.2 if mode == "timeout" else 10.0
        )
    assert cidfile.read_text(encoding="ascii") == CID and len(calls) == 1
    if mode in {"stdout_limit", "stderr_limit", "timeout"}:
        assert time.monotonic() - started < 1.5


@pytest.mark.parametrize(
    "sequence",
    [["present", "error"], ["present", "present", "error"], ["present", "present", "present"]],
)
def test_actual_failed_removal_or_post_query_retains_exact_cid(selected_controls, sequence):
    backend, private, cidfile, calls, modes, _ = selected_controls
    modes.extend(sequence)
    with pytest.raises(cleanup.ContainerCleanupError):
        cleanup.cleanup_rootless_container(backend, private)
    assert cidfile.read_text(encoding="ascii") == CID and len(calls) == len(sequence)


def test_missing_cid_is_not_absence_and_never_launches_a_control(selected_controls):
    backend, private, cidfile, calls, modes, _ = selected_controls
    cidfile.unlink()
    result = cleanup.cleanup_rootless_container(backend, private)
    assert result.status is cleanup.ContainerCleanupStatus.NO_IDENTIFIER
    assert not result.absence_verified and not calls and not modes


def test_control_spawn_failure_retains_identifier(selected_controls, monkeypatch):
    backend, private, cidfile, calls, modes, _ = selected_controls

    def unavailable(*args, **kwargs):
        raise OSError("synthetic failed spawn")

    monkeypatch.setattr(subprocess, "Popen", unavailable)
    with pytest.raises(cleanup.ContainerCleanupError):
        cleanup.cleanup_rootless_container(backend, private)
    assert cidfile.read_text() == CID and not calls and not modes
