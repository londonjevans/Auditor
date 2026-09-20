"""Real offline verifier CLI against explicitly fabricated parser fixtures, never audit evidence."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.scheduler_scaling_support import ROOT
from tests.unit.test_pipeline_replay_capture import synthetic_side


def _command(
    before: dict[str, Any], after: dict[str, Any], *, optimize: bool = False
) -> subprocess.CompletedProcess[str]:
    arguments: list[str] = []
    for side, selected in (("before", before), ("after", after)):
        for key, value in selected.items():
            arguments.extend((f"--{side}-{key.replace('_', '-')}", str(value)))
    return subprocess.run(
        [
            sys.executable,
            *(["-O"] if optimize else []),
            "-m",
            "scripts.verify_pipeline_replay",
            *arguments,
        ],
        cwd=ROOT,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": "src",
            "PYTHONDONTWRITEBYTECODE": "1",
            "MMAUDIT_RUN_REAL_PROVIDER_TESTS": "0",
            "MMAUDIT_SECRETS_ENV_FILE": "",
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


@pytest.mark.parametrize(
    "invalid", (None, "native_failure", "missing_file", "wrong_pin", "optimized")
)
def test_real_cli_verifies_or_rejects_both_synthetic_inputs_without_running_or_mutating_them(
    tmp_path: Path, invalid: str | None
) -> None:
    before, after = synthetic_side(tmp_path / "before", 0), synthetic_side(tmp_path / "after", 1)
    if invalid == "native_failure":
        value = json.loads(after["capture"].read_bytes())
        value["results"][-1]["exit_code"] = 1
        after["capture"].write_text(json.dumps(value))
        after["capture_sha256"] = hashlib.sha256(after["capture"].read_bytes()).hexdigest()
    elif invalid == "missing_file":
        (after["workspace"] / "generic-open/synthetic-ledger.json").unlink()
    elif invalid == "wrong_pin":
        after["capture_sha256"] = "f" * 64
    snapshot = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    result = _command(before, after, optimize=invalid == "optimized")
    assert result.returncode == (0 if invalid is None else 1), result.stderr
    report = json.loads(result.stdout)
    assert report["accepted"] is (invalid is None)
    assert report["new_workloads_executed"] == report["real_provider_calls"] == 0
    assert not report["execution_attested"] and not report["qualification_or_release_authority"]
    assert not result.stderr
    assert snapshot == {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
