"""Actual offline solc input closure; synthetic abstract source and no runtime authority."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, NoReturn

import pytest

from mmaudit.scanners.foundry_inventory import FoundrySourceInput
from mmaudit.scanners.solc_capture import prepare_solc_capture
from tests.integration.test_mutation_compilation import _solc_0_8_30

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/compiler_capture"


@pytest.mark.parametrize("complete_inputs", [False, True])
def test_native_compiler_uses_only_declared_literals_and_retains_exact_process_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, complete_inputs: bool
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        pytest.fail("compiler input-closure control attempted network access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    solc = _solc_0_8_30()
    if solc is None:
        pytest.skip("Requires existing external solc0.8.30; no provisioning")
    solc = solc.resolve(strict=True)
    assert not solc.is_relative_to(FIXTURE.parents[2])
    workspace = tmp_path / "source"
    shutil.copytree(FIXTURE, workspace)
    original = {p.name: p.read_bytes() for p in workspace.iterdir() if p.is_file()}
    paths = ("Dependency.sol", "MissingImport.sol") if complete_inputs else ("MissingImport.sol",)
    sources = tuple(
        FoundrySourceInput(name, original[name], hashlib.sha256(original[name]).hexdigest())
        for name in paths
    )
    session = prepare_solc_capture(
        root=tmp_path / "transcript",
        workspace=workspace,
        compiler=solc,
        compiler_sha256=hashlib.sha256(solc.read_bytes()).hexdigest(),
        sources=sources,
        deadline_monotonic=time.monotonic() + 15,
    )
    request = json.dumps(
        {
            "language": "Solidity",
            "sources": {name: {"content": original[name].decode()} for name in paths},
            "settings": {"outputSelection": {"*": {"": ["ast"]}}},
        }
    ).encode()
    command = [
        str(session.launcher),
        "--standard-json",
        "--allow-paths",
        str(workspace),
        "--base-path",
        str(workspace),
    ]
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    result = subprocess.run(
        command,
        input=request,
        capture_output=True,
        timeout=15,
        env=environment,
        shell=False,
        check=False,
    )
    (tmp_path / "stdout.txt").write_bytes(result.stdout)
    (tmp_path / "stderr.txt").write_bytes(result.stderr)
    (tmp_path / "returncode.txt").write_text(str(result.returncode))
    call = session.root / "calls/0000"
    assert (call / "stdin.bin").read_bytes() == request
    assert (call / "stdout.bin").read_bytes() == result.stdout
    assert json.loads((call / "process.json").read_bytes()) == {
        "process_started": True,
        "compiler_exit_code": 0,
    }
    assert all((workspace / name).read_bytes() == raw for name, raw in original.items())
    session.require_inputs_unchanged()
    if complete_inputs:
        assert result.returncode == 0
        records = session.collect()
        assert len(records) == 1 and records[0].stdin == request
        assert records[0].evidence_authority == "UNATTESTED_COMPILER_TRANSCRIPT"
    else:
        assert result.returncode == 125
        errors = json.loads(result.stdout)["errors"]
        assert any(
            error["severity"] == "error" and "callback" in error["message"] for error in errors
        )
        assert (call / "failed.json").is_file() and not (call / "complete.json").exists()
        with pytest.raises(ValueError):
            session.collect()
        refusal = subprocess.run(
            [str(session.launcher), "--version"],
            capture_output=True,
            timeout=15,
            env=environment,
            shell=False,
            check=False,
        )
        assert refusal.returncode == 125
        assert [p.name for p in (session.root / "calls").iterdir()] == ["0000"]
