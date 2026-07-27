from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

import pytest

from mmaudit.config import FormalConfig
from mmaudit.models.schemas import FormalResultKind, FormalToolStatus
from mmaudit.solidity.formal import EchidnaAdapter, FormalRunner
from mmaudit.solidity.reproduction import default_isolation_backend
from tests.unit.test_echidna import FIXTURE, _inputs


def test_real_echidna_translated_fixture_replays_in_hardened_isolation(
    tmp_path: Path,
    config_factory,
) -> None:
    raw_executable = shutil.which("echidna")
    if raw_executable is None:
        pytest.skip("echidna is not installed")
    expected_version = os.environ.get("MMAUDIT_TEST_ECHIDNA_VERSION")
    if expected_version is None:
        pytest.skip("MMAUDIT_TEST_ECHIDNA_VERSION is not configured")
    backend = default_isolation_backend("auto")
    if backend is None:
        pytest.skip("no hardened isolation backend is available")

    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    projects, index, suite, corpus = _inputs(root, config_factory())
    executable = Path(raw_executable).resolve(strict=True)
    executable_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
    adapter = EchidnaAdapter()
    adapter.available = lambda repository_root: executable  # type: ignore[method-assign]
    runner = FormalRunner(
        FormalConfig(
            enabled=True,
            timeout_seconds=30,
            echidna_version=expected_version,
            echidna_sha256=executable_hash,
        ),
        backend=backend,
        adapters=[adapter],
    )

    first = runner.run(
        repository_root=root,
        projects=projects,
        index=index,
        invariants=suite,
        property_corpus=corpus,
        private_dir=tmp_path / "first",
    )[0]
    second = runner.run(
        repository_root=root,
        projects=projects,
        index=index,
        invariants=suite,
        property_corpus=corpus,
        private_dir=tmp_path / "second",
    )[0]

    assert first.status in {FormalToolStatus.SUCCESS, FormalToolStatus.INCONCLUSIVE}
    assert second.status in {FormalToolStatus.SUCCESS, FormalToolStatus.INCONCLUSIVE}
    assert first.evidence and second.evidence
    assert first.evidence[0].result_kind is FormalResultKind.COUNTEREXAMPLE
    assert second.evidence[0].result_kind is FormalResultKind.COUNTEREXAMPLE
    assert first.evidence[0].property_id == second.evidence[0].property_id
    assert (
        first.evidence[0].counterexample["sequence"]
        == (second.evidence[0].counterexample["sequence"])
    )
    assert first.property_corpus_hash == corpus.corpus_hash
    assert first.executable_sha256 == executable_hash
    assert not (root / "cache").exists()
    assert not (root / "out").exists()
