"""Fixed trusted local probe controls; only the explicit OS test can attest isolation."""

from __future__ import annotations

import hashlib
import platform
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from mmaudit.isolation import provenance
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.solidity.reproduction import MacOSSandboxBackend


@dataclass
class _TrustedLocalControl:
    """Test-only fixed command wrapper, deliberately not a built-in isolation type."""

    executable: str
    expected_command: list[str]
    mutate_during_wrap: bool = False
    name: str = "unverified-local-admission-control"

    def wrap(
        self, command: list[str], *, workspace: Path, private_dir: Path, rpc_port: int
    ) -> list[str]:
        assert command == self.expected_command
        assert rpc_port == 0 and workspace.is_relative_to(private_dir)
        if self.mutate_during_wrap:
            Path(self.executable).chmod(0o500)
        return [self.executable, *command]


@pytest.mark.parametrize("returncode", [0, 1])
@pytest.mark.parametrize(
    "boundary", ["unchanged", "before-wrap", "during-wrap", "after-launch", "restored"]
)
def test_only_unchanged_launcher_can_supply_a_local_probe_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, returncode: int, boundary: str
) -> None:
    trusted = Path(sys.executable).resolve(strict=True)
    assert not trusted.is_relative_to(Path(__file__).resolve().parents[2])
    digest = hashlib.sha256(trusted.read_bytes()).hexdigest()
    executable = tmp_path / "trusted-python-control"
    shutil.copyfile(trusted, executable)
    executable.chmod(0o700)
    command = ["-I", "-c", f"raise SystemExit({returncode})"]
    backend = _TrustedLocalControl(str(executable), command, boundary == "during-wrap")
    admission = provenance._admit_isolation_executable(backend)
    assert admission.observation.sha256 == digest
    private_dir = tmp_path / "private"
    workspace = private_dir / "workspace"
    workspace.mkdir(parents=True)
    environment = provenance._probe_environment(private_dir)
    assert "OPENROUTER_API_KEY" not in environment
    assert "MMAUDIT_SECRETS_ENV_FILE" not in environment
    if boundary in {"before-wrap", "restored"}:
        executable.chmod(0o500)
        if boundary == "restored":
            executable.chmod(0o700)
    invocations: list[list[str]] = []
    real_popen = provenance.subprocess.Popen

    def popen(argv: list[str], *args: Any, **kwargs: Any) -> Any:
        assert argv == [str(executable), *command]
        assert hashlib.sha256(executable.read_bytes()).hexdigest() == digest
        assert kwargs["shell"] is False and kwargs["env"] == environment
        invocations.append(argv.copy())
        process = real_popen(argv, *args, **kwargs)
        if boundary == "after-launch":
            executable.chmod(0o500)
        return process

    def forbidden(*args: object, **kwargs: object) -> Any:
        pytest.fail(
            "invariant: the fixed local admission control must not discover tools or network"
        )

    monkeypatch.setattr(provenance.subprocess, "Popen", popen)
    monkeypatch.setattr(provenance.socket, "socket", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    result = provenance._execute_probe(
        backend,
        command,
        workspace=workspace,
        private_dir=private_dir,
        rpc_port=0,
        environment=environment,
        admission=admission,
    )
    assert result == (returncode if boundary == "unchanged" else None)
    assert len(invocations) == (1 if boundary in {"unchanged", "after-launch"} else 0)
    assert provenance.isolation_execution_evidence(backend) is ExecutionEvidenceKind.UNVERIFIED
    assert provenance.isolation_attestation_sha256(backend) is None


@pytest.mark.skipif(platform.system() != "Darwin", reason="requires the fixed macOS system sandbox")
def test_system_sandbox_requires_all_six_real_local_boundary_observations() -> None:
    executable = Path("/usr/bin/sandbox-exec")
    if not executable.is_file():
        pytest.skip("INCONCLUSIVE: fixed macOS system sandbox is unavailable")
    backend = MacOSSandboxBackend(executable=str(executable.resolve(strict=True)))
    try:
        provenance._seal_builtin_isolation_backend(backend)
    except ValueError as exc:
        if "mandatory adversarial preflight" not in str(exc):
            raise
        assert provenance.isolation_execution_evidence(backend) is ExecutionEvidenceKind.UNVERIFIED
        assert provenance.isolation_attestation_sha256(backend) is None
        pytest.skip("INCONCLUSIVE: host cannot satisfy all six real local isolation probes")
    assert provenance.isolation_execution_evidence(backend) is ExecutionEvidenceKind.REAL
    assert provenance.isolation_attestation_sha256(backend) is not None
