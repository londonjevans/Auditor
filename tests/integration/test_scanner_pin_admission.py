"""Trusted-Python local pin admission; not real isolation attestation."""

from __future__ import annotations

import hashlib
import shutil
import socket
import sys
from pathlib import Path
from typing import Any

import pytest

from mmaudit.models.schemas import ExecutionEvidenceKind, ScannerFinding, ScannerStatus
from mmaudit.scanners import base

_SAFE_CODE = "print('{}')"
_FIXTURE = (
    Path(__file__).parents[1] / "fixtures" / "solidity" / "development_review" / "ControlB.sol"
)


class _TrustedPythonScanner(base.ScannerAdapter):
    name = "synthetic-pin-integration"
    executable = sys.executable

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        return [self.executable, "-c", _SAFE_CODE]

    def parse(self, root: Path, stdout: str, private_dir: Path) -> list[ScannerFinding]:
        assert stdout.strip() == "{}"
        return []


class _SyntheticLocalBackend:
    """Only a fixed harmless Python command may run; no isolation authority claimed."""

    name = "synthetic-local-pin-test"
    supports_local_fork_rpc = False

    def wrap(
        self, command: list[str], *, workspace: Path, private_dir: Path, rpc_port: int
    ) -> list[str]:
        assert rpc_port == 0
        assert command in (
            [str(Path(sys.executable).resolve(strict=True)), "--version"],
            [str(Path(sys.executable).resolve(strict=True)), "-c", _SAFE_CODE],
        )
        return command


@pytest.mark.parametrize("source_bound", [False, True])
@pytest.mark.parametrize("pin_case", ["match", "wrong-digest", "version-only", "wrong-version"])
def test_local_consumer_enforces_pin_before_any_tool_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_bound: bool,
    pin_case: str,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    shutil.copyfile(_FIXTURE, repository / "ControlB.sol")
    private = tmp_path / "private"
    executable = Path(sys.executable).resolve(strict=True)
    assert not executable.is_relative_to(repository)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    commands: list[list[str]] = []
    real_popen = base.subprocess.Popen

    def record_popen(command: list[str], *args: Any, **kwargs: Any) -> Any:
        assert command in (
            [str(executable), "--version"],
            [str(executable), "-c", _SAFE_CODE],
        )
        assert kwargs["shell"] is False
        commands.append(command.copy())
        return real_popen(command, *args, **kwargs)

    def forbidden_network(*args: object, **kwargs: object) -> Any:
        pytest.fail("invariant: pin-admission integration must remain local")

    monkeypatch.setattr(base.subprocess, "Popen", record_popen)
    monkeypatch.setattr(socket, "socket", forbidden_network)
    expected_version = (
        "0.0.0"
        if pin_case == "wrong-version"
        else ".".join(str(value) for value in sys.version_info[:3])
    )
    options = dict(
        backend=_SyntheticLocalBackend(),
        expected_version=expected_version,
        expected_sha256=(
            None
            if pin_case == "version-only"
            else ("0" * 64 if pin_case == "wrong-digest" else digest)
        ),
    )
    scanner = _TrustedPythonScanner()
    if source_bound:
        result = scanner.run_source_bound(
            repository,
            private,
            3,
            expected_repository_sha256=base.scanner_workspace_sha256(repository),
            audited_relative_paths=("ControlB.sol",),
            **options,
        )
    else:
        result = scanner.run(repository, private, 3, **options)

    expected_commands = []
    if pin_case in {"match", "wrong-version"}:
        expected_commands.append([str(executable), "--version"])
    if pin_case == "match":
        expected_commands.append([str(executable), "-c", _SAFE_CODE])
    assert commands == expected_commands
    assert result.status is (ScannerStatus.SUCCESS if pin_case == "match" else ScannerStatus.FAILED)
    assert result.executable_sha256 == digest
    assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert (result.raw_output_path is not None) is (pin_case == "match")
    if pin_case in {"wrong-digest", "version-only"}:
        assert result.version is None
        assert not (private / "workspace").exists()
