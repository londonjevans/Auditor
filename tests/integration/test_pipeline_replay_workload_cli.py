"""Real local CLI preparation/refusal; no full performance workload or provider dispatch."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.pipeline_replay_workload import load_replay_declaration, require_current_replay_inputs
from tests.scheduler_scaling_support import ROOT


def _command(*arguments: str, optimize: bool = False) -> subprocess.CompletedProcess[str]:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": "src",
        "PYTHONDONTWRITEBYTECODE": "1",
        "MMAUDIT_RUN_REAL_PROVIDER_TESTS": "0",
        "MMAUDIT_SECRETS_ENV_FILE": "",
    }
    return subprocess.run(
        [
            sys.executable,
            *(["-O"] if optimize else []),
            "-m",
            "scripts.measure_pipeline_replay_scaling",
            *arguments,
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_cli_predeclaration_runs_no_workload_and_cannot_clobber_prior_selection(
    tmp_path: Path,
) -> None:
    path = tmp_path / "declaration.json"
    result = _command("--predeclare", str(path))
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["workloads_executed"] == report["real_provider_calls"] == 0
    declaration = load_replay_declaration(path, report["declaration_sha256"])
    assert declaration.workload_sha256 == report["workload_sha256"]
    require_current_replay_inputs(declaration)
    raw = path.read_bytes()
    repeated = _command("--predeclare", str(path))
    assert repeated.returncode != 0 and path.read_bytes() == raw
    assert "FileExistsError" in repeated.stderr
    assert set(tmp_path.iterdir()) == {path}


@pytest.mark.parametrize(
    "arguments",
    (
        (),
        ("--workspace", "unused", "--declaration", "missing.json"),
        ("--workspace", "unused", "--declaration-sha256", "a" * 64),
        ("--predeclare", "unused.json", "--workspace", "unused"),
        (
            "--workspace",
            "unused",
            "--declaration",
            "missing.json",
            "--declaration-sha256",
            "a" * 64,
            "--case",
            "generic-open",
        ),
    ),
)
def test_cli_incomplete_or_reduced_declaration_refuses_before_measurement(
    arguments: tuple[str, ...],
) -> None:
    result = _command(*arguments)
    assert result.returncode == 2
    assert not result.stdout and "phase_started" not in result.stderr


def test_cli_wrong_pin_refuses_before_creating_a_measurement_workspace(tmp_path: Path) -> None:
    path = tmp_path / "synthetic-invalid-declaration.json"
    path.write_text('{"schema_version":"1.0","synthetic":true}\n')
    workspace = tmp_path / "not-created"
    result = _command(
        "--workspace", str(workspace), "--declaration", str(path), "--declaration-sha256", "a" * 64
    )
    assert result.returncode != 0 and "caller pin" in result.stderr
    assert not result.stdout and not workspace.exists()


def test_cli_cannot_prepare_measurement_with_original_assertions_disabled(tmp_path: Path) -> None:
    path = tmp_path / "not-created.json"
    result = _command("--predeclare", str(path), optimize=True)
    assert result.returncode != 0 and "enabled original assertions" in result.stderr
    assert not path.exists() and not result.stdout
