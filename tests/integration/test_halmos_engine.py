from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from mmaudit.config import FormalConfig
from mmaudit.models.schemas import FormalResultKind, FormalToolStatus
from mmaudit.solidity.formal import FormalRunner, HalmosAdapter
from mmaudit.solidity.reproduction import default_isolation_backend
from tests.unit.test_echidna import FIXTURE, _inputs

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _semantic_version(output: str) -> str:
    match = re.search(r"(?<![0-9.])([0-9]+\.[0-9]+\.[0-9]+)(?![0-9.])", output)
    if match is None:
        raise ValueError("tool version output does not contain a semantic version")
    return match.group(1)


def _explicit_test_tool(environment_name: str, label: str) -> Path:
    raw = os.environ.get(environment_name, "")
    if not raw:
        pytest.skip(f"real {label} integration requires {environment_name}")
    executable = Path(raw)
    try:
        metadata = executable.lstat()
        resolved = executable.resolve(strict=True)
    except OSError:
        pytest.skip(f"the explicit {label} integration executable is unavailable")
    if (
        not executable.is_absolute()
        or resolved != executable
        or executable.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        or resolved.is_relative_to(REPOSITORY_ROOT)
    ):
        pytest.skip(f"the explicit {label} integration executable is not trusted")
    return executable


def test_real_halmos_translated_fixture_captures_bounded_counterexample(
    tmp_path: Path,
    config_factory,
) -> None:
    executable = _explicit_test_tool("MMAUDIT_TEST_HALMOS_EXECUTABLE", "Halmos")
    solver = _explicit_test_tool("MMAUDIT_TEST_Z3_EXECUTABLE", "Z3")
    backend = default_isolation_backend("auto")
    if backend is None:
        pytest.skip("no hardened isolation backend is available")

    halmos_version = _semantic_version(
        subprocess.run(
            [str(executable), "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
    )
    solver_version = _semantic_version(
        subprocess.run(
            [str(solver), "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
    )
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    projects, index, suite, corpus = _inputs(root, config_factory())
    adapter = HalmosAdapter()
    adapter.available = lambda repository_root: executable  # type: ignore[method-assign]
    runner = FormalRunner(
        FormalConfig(
            enabled=True,
            timeout_seconds=60,
            halmos_version=halmos_version,
            halmos_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            halmos_solver_version=solver_version,
            halmos_solver_sha256=hashlib.sha256(solver.read_bytes()).hexdigest(),
        ),
        backend=backend,
        adapters=[adapter],
    )

    run = runner.run(
        repository_root=root,
        projects=projects,
        index=index,
        invariants=suite,
        property_corpus=corpus,
        private_dir=tmp_path / "private",
    )[0]

    assert run.status is FormalToolStatus.INCONCLUSIVE
    assert len(run.evidence) == 1
    assert run.evidence[0].result_kind is FormalResultKind.COUNTEREXAMPLE
    assert run.evidence[0].property_id == corpus.properties[0].id
    assert run.evidence[0].counterexample["models"]
    assert run.property_corpus_hash == corpus.corpus_hash
    assert run.executable_sha256 == hashlib.sha256(executable.read_bytes()).hexdigest()
    assert run.dependencies[0].executable_sha256 == hashlib.sha256(solver.read_bytes()).hexdigest()
    assert not (root / "cache").exists()
    assert not (root / "out").exists()
