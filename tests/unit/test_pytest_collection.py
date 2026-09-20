"""The normal local/CI command must collect both same-named test modules."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_default_pytest_import_mode_keeps_directory_specific_modules(
    pytestconfig: pytest.Config,
) -> None:
    assert pytestconfig.getoption("importmode") == "importlib"
    assert pytestconfig.getini("testpaths") == ["tests"]


def test_default_configuration_executes_both_same_named_modules(tmp_path: Path) -> None:
    modules = []
    for group in ("unit", "integration"):
        directory = tmp_path / group
        directory.mkdir()
        module = directory / "test_shared_name.py"
        module.write_text(
            f"GROUP = {group!r}\n\ndef test_group_is_not_the_other_module():\n"
            f"    assert GROUP == {group!r}\n",
            encoding="utf-8",
        )
        modules.append(module)
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-c",
            str(ROOT / "pyproject.toml"),
            "--rootdir",
            str(tmp_path),
            "--confcutdir",
            str(tmp_path),
            "-p",
            "no:cacheprovider",
            "-p",
            "pytest_asyncio.plugin",
            "-q",
            *(str(module) for module in modules),
        ],
        cwd=tmp_path,
        env={
            "PATH": os.defpath,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "2 passed" in completed.stdout
