from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from mmaudit.config import FormalConfig
from mmaudit.models.schemas import FormalResultKind, FormalToolStatus
from mmaudit.solidity.formal import FormalRunner, HalmosAdapter
from mmaudit.solidity.reproduction import default_isolation_backend
from tests.unit.test_echidna import FIXTURE, _inputs


def _semantic_version(output: str) -> str:
    match = re.search(r"(?<![0-9.])([0-9]+\.[0-9]+\.[0-9]+)(?![0-9.])", output)
    if match is None:
        raise ValueError("tool version output does not contain a semantic version")
    return match.group(1)


def test_real_halmos_translated_fixture_captures_bounded_counterexample(
    tmp_path: Path,
    config_factory,
) -> None:
    raw_executable = shutil.which("halmos")
    raw_solver = shutil.which("z3")
    if raw_executable is None:
        pytest.skip("halmos is not installed")
    if raw_solver is None:
        pytest.skip("the fixed local Z3 dependency is not installed")
    backend = default_isolation_backend("auto")
    if backend is None:
        pytest.skip("no hardened isolation backend is available")

    executable = Path(raw_executable).resolve(strict=True)
    solver = Path(raw_solver).resolve(strict=True)
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
