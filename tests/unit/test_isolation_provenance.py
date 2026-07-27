from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from mmaudit.isolation.provenance import (
    _IsolationProbeResults,
    _network_probe_denied,
    _probe_environment,
    _run_builtin_preflight,
    _seal_builtin_isolation_backend,
    isolation_attestation_sha256,
    isolation_execution_evidence,
)
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.solidity.reproduction import MacOSSandboxBackend


def _passing_probes() -> _IsolationProbeResults:
    return _IsolationProbeResults(
        benign_execution=True,
        workspace_write_allowed=True,
        network_denied=True,
        host_home_read_denied=True,
        secret_environment_denied=True,
        outside_write_denied=True,
    )


def _executable(tmp_path: Path) -> Path:
    executable = tmp_path / "sandbox-exec"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    return executable


def test_probe_environment_excludes_control_plane_secret_names(tmp_path: Path) -> None:
    environment = _probe_environment(tmp_path / "private")

    assert "OPENROUTER_API_KEY" not in environment
    assert "MMAUDIT_SECRETS_ENV_FILE" not in environment
    assert environment["HOME"].startswith(str(tmp_path))


@pytest.mark.parametrize(
    "failed_probe",
    [
        "benign_execution",
        "workspace_write_allowed",
        "network_denied",
        "host_home_read_denied",
        "secret_environment_denied",
        "outside_write_denied",
    ],
)
def test_every_adversarial_preflight_probe_is_mandatory(
    failed_probe: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probes = replace(_passing_probes(), **{failed_probe: False})
    monkeypatch.setattr(
        "mmaudit.isolation.provenance._run_builtin_preflight",
        lambda _backend: probes,
    )
    backend = MacOSSandboxBackend(executable=str(_executable(tmp_path)))

    with pytest.raises(ValueError, match="mandatory adversarial preflight"):
        _seal_builtin_isolation_backend(backend)

    assert isolation_execution_evidence(backend) is ExecutionEvidenceKind.UNVERIFIED


def test_preflight_records_each_boundary_observation_without_secret_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_environments: list[dict[str, str]] = []

    def execute(
        _backend: object,
        command: list[str],
        **kwargs: object,
    ) -> int:
        environment = kwargs["environment"]
        assert isinstance(environment, dict)
        observed_environments.append(environment)
        rendered = " ".join(command)
        if "workspace-ok" in rendered:
            Path(command[-1]).write_text("workspace-ok", encoding="utf-8")
            return 0
        if "host-canary" in rendered or "boundary-failed" in rendered:
            return 1
        return 0

    monkeypatch.setattr("mmaudit.isolation.provenance._execute_probe", execute)
    monkeypatch.setattr(
        "mmaudit.isolation.provenance._network_probe_denied",
        lambda *_args, **_kwargs: True,
    )
    backend = MacOSSandboxBackend(executable=str(_executable(tmp_path)))

    probes = _run_builtin_preflight(backend)

    assert probes == _passing_probes()
    assert observed_environments
    assert all("OPENROUTER_API_KEY" not in item for item in observed_environments)
    assert all("MMAUDIT_SECRETS_ENV_FILE" not in item for item in observed_environments)


def test_network_probe_requires_failed_connection_and_no_boundary_crossing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Listener:
        accepted = 0

        def __enter__(self) -> Listener:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def setsockopt(self, *_args: object) -> None:
            return None

        def bind(self, _address: object) -> None:
            return None

        def listen(self, _backlog: int) -> None:
            return None

        def settimeout(self, _timeout: float) -> None:
            return None

        def getsockname(self) -> tuple[str, int]:
            return ("127.0.0.1", 43_210)

        def accept(self) -> tuple[object, object]:
            self.accepted += 1
            if self.accepted == 1:
                return Connection(), ("127.0.0.1", 43_210)
            raise TimeoutError

    class Connection:
        def close(self) -> None:
            return None

    private_dir = tmp_path / "private"
    workspace = private_dir / "workspace"
    workspace.mkdir(parents=True)
    backend = MacOSSandboxBackend(executable=str(_executable(tmp_path)))
    monkeypatch.setattr(
        "mmaudit.isolation.provenance.socket.socket",
        lambda *_args, **_kwargs: Listener(),
    )
    monkeypatch.setattr(
        "mmaudit.isolation.provenance.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(args=[], returncode=0),
    )
    monkeypatch.setattr("mmaudit.isolation.provenance._execute_probe", lambda *_a, **_k: 1)

    assert _network_probe_denied(
        backend,
        Path("/usr/bin/nc"),
        workspace=workspace,
        private_dir=private_dir,
        environment={},
    )

    monkeypatch.setattr("mmaudit.isolation.provenance._execute_probe", lambda *_a, **_k: 0)
    assert not _network_probe_denied(
        backend,
        Path("/usr/bin/nc"),
        workspace=workspace,
        private_dir=private_dir,
        environment={},
    )

    monkeypatch.setattr("mmaudit.isolation.provenance._execute_probe", lambda *_a, **_k: 1)
    monkeypatch.setattr(
        "mmaudit.isolation.provenance.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(args=[], returncode=1),
    )
    assert not _network_probe_denied(
        backend,
        Path("/usr/bin/nc"),
        workspace=workspace,
        private_dir=private_dir,
        environment={},
    )


def test_network_probe_fails_closed_when_listener_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_dir = tmp_path / "private"
    workspace = private_dir / "workspace"
    workspace.mkdir(parents=True)
    backend = MacOSSandboxBackend(executable=str(_executable(tmp_path)))

    def unavailable(*_args: object, **_kwargs: object) -> object:
        raise PermissionError("local socket unavailable")

    monkeypatch.setattr("mmaudit.isolation.provenance.socket.socket", unavailable)

    assert not _network_probe_denied(
        backend,
        Path("/usr/bin/nc"),
        workspace=workspace,
        private_dir=private_dir,
        environment={},
    )


def test_seal_rejects_reconstructed_altered_executable_and_altered_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = _executable(tmp_path)
    monkeypatch.setattr(
        "mmaudit.isolation.provenance._run_builtin_preflight",
        lambda _backend: _passing_probes(),
    )
    backend = MacOSSandboxBackend(executable=str(executable))
    _seal_builtin_isolation_backend(backend)

    assert isolation_execution_evidence(backend) is ExecutionEvidenceKind.REAL
    assert isolation_attestation_sha256(backend) is not None
    reconstructed = MacOSSandboxBackend(executable=str(executable))
    assert isolation_execution_evidence(reconstructed) is ExecutionEvidenceKind.UNVERIFIED
    assert isolation_attestation_sha256(reconstructed) is None

    executable.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    assert isolation_execution_evidence(backend) is ExecutionEvidenceKind.UNVERIFIED
    assert isolation_attestation_sha256(backend) is None
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    assert isolation_execution_evidence(backend) is ExecutionEvidenceKind.REAL

    original_wrap = MacOSSandboxBackend.wrap

    def altered_wrap(
        self: MacOSSandboxBackend,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        wrapped = original_wrap(
            self,
            command,
            workspace=workspace,
            private_dir=private_dir,
            rpc_port=rpc_port,
        )
        return [*wrapped, "--altered-policy"]

    monkeypatch.setattr(MacOSSandboxBackend, "wrap", altered_wrap)
    assert isolation_execution_evidence(backend) is ExecutionEvidenceKind.UNVERIFIED
    assert isolation_attestation_sha256(backend) is None
