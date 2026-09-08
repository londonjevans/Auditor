"""Inert launcher admission fixtures; mocked probes never establish real isolation."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from mmaudit.isolation import provenance
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.solidity.reproduction import BubblewrapBackend, MacOSSandboxBackend

Backend = BubblewrapBackend | MacOSSandboxBackend
_PROBES = provenance._IsolationProbeResults(True, True, True, True, True, True)


@pytest.fixture(autouse=True)
def forbid_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> Any:
        pytest.fail("invariant: inert admission fixtures must never execute or use a socket")

    monkeypatch.setattr(provenance.subprocess, "run", forbidden)
    monkeypatch.setattr(provenance.subprocess, "Popen", forbidden)
    monkeypatch.setattr(provenance.socket, "socket", forbidden)
    monkeypatch.setattr(provenance, "_current_policy_sha256", lambda _backend: "a" * 64)


@pytest.fixture(params=[BubblewrapBackend, MacOSSandboxBackend])
def backend(request: pytest.FixtureRequest, tmp_path: Path) -> Backend:
    executable = tmp_path / "inert-launcher"
    executable.write_bytes(b"synthetic non-executed launcher fixture\n")
    executable.chmod(0o700)
    return request.param(executable=str(executable))


def _mutate(executable: Path, kind: str) -> None:
    original = executable.read_bytes()
    if kind == "bytes":
        executable.write_bytes(b"different non-executed fixture\n")
    elif kind == "restored-bytes":
        executable.write_bytes(b"temporary non-executed fixture\n")
        executable.write_bytes(original)
    elif kind == "replacement":
        replacement = executable.with_name("replacement")
        replacement.write_bytes(original)
        replacement.chmod(0o700)
        replacement.replace(executable)
    elif kind == "permissions":
        executable.chmod(0o500)
    elif kind == "missing":
        executable.unlink()
    elif kind == "symlink":
        target = executable.with_name("link-target")
        executable.rename(target)
        executable.symlink_to(target)
    else:
        raise AssertionError(kind)


@pytest.mark.parametrize(
    "kind", ["missing", "directory", "symlink", "hardlink", "no-execute", "empty", "large", "fifo"]
)
def test_invalid_launcher_is_refused_before_policy_or_probes(
    backend: Backend, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = Path(backend.executable)
    if kind == "missing":
        executable.unlink()
    elif kind == "directory":
        executable.unlink()
        executable.mkdir()
    elif kind == "symlink":
        _mutate(executable, kind)
    elif kind == "hardlink":
        os.link(executable, executable.with_name("second-link"))
    elif kind == "no-execute":
        executable.chmod(0o600)
    elif kind == "empty":
        executable.write_bytes(b"")
    elif kind == "large":
        monkeypatch.setattr("mmaudit.scanners.base._MAX_SCANNER_EXECUTABLE_BYTES", 16)
    elif kind == "fifo":
        executable.unlink()
        os.mkfifo(executable)

    def forbidden(*args: object, **kwargs: object) -> Any:
        pytest.fail("invariant: invalid launcher must be refused before preflight work")

    monkeypatch.setattr(provenance, "_run_builtin_preflight", forbidden)
    monkeypatch.setattr(provenance, "_current_policy_sha256", forbidden)
    with pytest.raises(ValueError, match="isolation"):
        provenance._seal_builtin_isolation_backend(backend)
    assert provenance.isolation_execution_evidence(backend) is ExecutionEvidenceKind.UNVERIFIED


@pytest.mark.parametrize(
    "kind", ["bytes", "restored-bytes", "replacement", "permissions", "missing", "symlink"]
)
def test_preflight_cannot_credit_a_different_launcher_identity(
    backend: Backend, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def probes(*args: object, **kwargs: object) -> provenance._IsolationProbeResults:
        _mutate(Path(backend.executable), kind)
        return _PROBES

    monkeypatch.setattr(provenance, "_run_builtin_preflight", probes)
    with pytest.raises(ValueError, match="isolation"):
        provenance._seal_builtin_isolation_backend(backend)
    assert provenance.isolation_execution_evidence(backend) is ExecutionEvidenceKind.UNVERIFIED
    assert provenance.isolation_attestation_sha256(backend) is None


@pytest.mark.parametrize("policy_boundary", [1, 2])
def test_policy_construction_cannot_change_launcher_identity(
    backend: Backend, policy_boundary: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    policies = 0
    probes = 0

    def policy(_backend: object) -> str:
        nonlocal policies
        policies += 1
        if policies == policy_boundary:
            _mutate(Path(backend.executable), "replacement")
        return "a" * 64

    def preflight(*args: object, **kwargs: object) -> provenance._IsolationProbeResults:
        nonlocal probes
        probes += 1
        return _PROBES

    monkeypatch.setattr(provenance, "_current_policy_sha256", policy)
    monkeypatch.setattr(provenance, "_run_builtin_preflight", preflight)
    with pytest.raises(ValueError, match="isolation"):
        provenance._seal_builtin_isolation_backend(backend)
    assert probes == policy_boundary - 1


def test_policy_must_match_before_and_after_preflight(
    backend: Backend, monkeypatch: pytest.MonkeyPatch
) -> None:
    policies = iter(["a" * 64, "b" * 64])
    monkeypatch.setattr(provenance, "_current_policy_sha256", lambda _backend: next(policies))
    monkeypatch.setattr(provenance, "_run_builtin_preflight", lambda *_a, **_k: _PROBES)
    with pytest.raises(ValueError, match="isolation"):
        provenance._seal_builtin_isolation_backend(backend)


@pytest.mark.parametrize("kind", ["restored-bytes", "replacement", "permissions"])
def test_old_seal_cannot_reactivate_without_fresh_preflight(
    backend: Backend, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(provenance, "_run_builtin_preflight", lambda *_a, **_k: _PROBES)
    provenance._seal_builtin_isolation_backend(backend)
    assert provenance.isolation_execution_evidence(backend) is ExecutionEvidenceKind.REAL
    _mutate(Path(backend.executable), kind)
    assert provenance.isolation_execution_evidence(backend) is ExecutionEvidenceKind.UNVERIFIED
    assert provenance.isolation_attestation_sha256(backend) is None
    provenance._seal_builtin_isolation_backend(backend)
    assert provenance.isolation_execution_evidence(backend) is ExecutionEvidenceKind.REAL


@pytest.mark.parametrize("failure", ["probes", "backend-name", "executable-type"])
def test_failed_reseal_revokes_previous_process_local_evidence(
    backend: Backend, failure: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(provenance, "_run_builtin_preflight", lambda *_a, **_k: _PROBES)
    provenance._seal_builtin_isolation_backend(backend)
    name, executable = backend.name, backend.executable
    if failure == "backend-name":
        object.__setattr__(backend, "name", "unselected-backend")
    elif failure == "executable-type":
        object.__setattr__(backend, "executable", Path(executable))
    monkeypatch.setattr(
        provenance,
        "_run_builtin_preflight",
        lambda *_a, **_k: replace(_PROBES, network_denied=False),
    )
    with pytest.raises(ValueError, match="isolation"):
        provenance._seal_builtin_isolation_backend(backend)
    object.__setattr__(backend, "name", name)
    object.__setattr__(backend, "executable", executable)
    assert provenance.isolation_execution_evidence(backend) is ExecutionEvidenceKind.UNVERIFIED


@pytest.mark.parametrize("boundary", ["before-wrap", "during-wrap", "after-process", "argv"])
def test_probe_refusal_is_never_a_successful_negative_observation(
    backend: Backend, boundary: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    admission = provenance._admit_isolation_executable(backend)
    invocations: list[list[str]] = []
    workspace = tmp_path / "private" / "workspace"
    workspace.mkdir(parents=True)

    def wrap(self: Backend, command: list[str], **kwargs: object) -> list[str]:
        if boundary == "during-wrap":
            _mutate(Path(self.executable), "replacement")
        launcher = str(tmp_path / "unselected-launcher") if boundary == "argv" else self.executable
        return [launcher, *command]

    def run(command: list[str], **kwargs: object) -> Any:
        invocations.append(command)
        if boundary == "after-process":
            _mutate(Path(backend.executable), "replacement")
        return provenance.subprocess.CompletedProcess(command, 1)

    monkeypatch.setattr(type(backend), "wrap", wrap)
    monkeypatch.setattr(provenance.subprocess, "run", run)
    if boundary == "before-wrap":
        _mutate(Path(backend.executable), "replacement")
    result = provenance._execute_probe(
        backend,
        ["fixed-inert-control"],
        workspace=workspace,
        private_dir=workspace.parent,
        rpc_port=0,
        environment={},
        admission=admission,
    )
    assert result is None
    assert len(invocations) == (1 if boundary == "after-process" else 0)
    assert provenance.isolation_execution_evidence(backend) is ExecutionEvidenceKind.UNVERIFIED
