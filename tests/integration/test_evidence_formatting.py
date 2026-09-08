"""Real formatter/make checks operate only on synthetic disposable local files."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_PATH = "docs/remediation/v3/operator_results.md"
OWNED_PATH = "docs/remediation/v3/owned.py"
UNFORMATTED_SOURCE = "def measured( value:int)->int:\n return value+1\n"
FORMATTED_SOURCE = "def measured(value: int) -> int:\n    return value + 1\n"


@pytest.fixture
def formatter_workspace(tmp_path: Path) -> tuple[Path, bytes]:
    for name in ("pyproject.toml", "Makefile"):
        (tmp_path / name).write_bytes((ROOT / name).read_bytes())
    evidence = (ROOT / "tests/fixtures/governance/operator_formatting_input.txt").read_bytes()
    destination = tmp_path / EVIDENCE_PATH
    destination.parent.mkdir(parents=True)
    destination.write_bytes(evidence)
    return tmp_path, evidence


def _run(workspace: Path, command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=workspace,
        env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def _make(workspace: Path, target: str) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("make", path=os.defpath)
    assert executable is not None, "the repository's documented make tool is required"
    return _run(workspace, [executable, target, f"PYTHON={sys.executable}"])


def test_make_format_preserves_external_bytes_and_formats_adjacent_owned_code(
    formatter_workspace: tuple[Path, bytes],
) -> None:
    workspace, evidence = formatter_workspace
    owned = workspace / OWNED_PATH
    owned.write_text(UNFORMATTED_SOURCE)

    result = _make(workspace, "format")

    assert result.returncode == 0, result.stdout + result.stderr
    assert (workspace / EVIDENCE_PATH).read_bytes() == evidence
    assert owned.read_text() == FORMATTED_SOURCE
    checked = _make(workspace, "lint")
    assert checked.returncode == 0, checked.stdout + checked.stderr
    assert (workspace / EVIDENCE_PATH).read_bytes() == evidence


@pytest.mark.parametrize(
    ("source", "expected_diagnostic"),
    [(UNFORMATTED_SOURCE, "owned.py"), ("import os\n\nVALUE = 1\n", "F401")],
    ids=["formatting-still-fails", "lint-still-fails"],
)
def test_make_lint_rejects_owned_defects_without_reformatting_external_evidence(
    formatter_workspace: tuple[Path, bytes], source: str, expected_diagnostic: str
) -> None:
    workspace, evidence = formatter_workspace
    (workspace / OWNED_PATH).write_text(source)

    result = _make(workspace, "lint")

    assert result.returncode != 0
    assert expected_diagnostic in result.stdout + result.stderr
    assert EVIDENCE_PATH not in result.stdout + result.stderr
    assert (workspace / EVIDENCE_PATH).read_bytes() == evidence
    assert (workspace / OWNED_PATH).read_text() == source


def test_explicit_force_exclude_retains_external_bytes(
    formatter_workspace: tuple[Path, bytes],
) -> None:
    workspace, evidence = formatter_workspace

    result = _run(
        workspace,
        [sys.executable, "-m", "ruff", "format", "--check", "--force-exclude", EVIDENCE_PATH],
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert (workspace / EVIDENCE_PATH).read_bytes() == evidence
