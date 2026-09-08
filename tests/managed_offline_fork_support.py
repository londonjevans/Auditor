"""Inert prepared tools and hash-addressed synthetic fork reads for local handoff tests."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from mmaudit.orchestration.managed_fork_archives import ManagedForkArchiveSource
from tests.unit.test_managed_fork_matrix import prepared_matrix


def prepared_archives(tmp_path, config_factory, *, primary=False, matrix=True):
    archive_root = tmp_path / "fork-archives"
    archive_root.mkdir(mode=0o700)
    fixture = Path(__file__).parent / "fixtures/offline_fork_rpc/reads.json"
    digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
    archive = archive_root / f"{digest}.json"
    shutil.copyfile(fixture, archive)

    def selected_config(**kwargs):
        suite = kwargs["smart_contracts"]["repository_suite"]
        suite.update(total_timeout_seconds=1, per_test_timeout_seconds=1)
        for state in suite["fork_matrix_states"]:
            if state["kind"] == "pinned_fork":
                state["state_source_sha256"] = digest
        if not matrix:
            suite["fork_matrix_states"] = []
        if primary:
            kwargs["reproduction"].update(expected_chain_id=31337, pinned_block_number=7)
            kwargs.setdefault("execution", {})["scanner_timeout_seconds"] = 1
        return config_factory(**kwargs)

    repository, material, private, _ = prepared_matrix(tmp_path, selected_config)
    source = ManagedForkArchiveSource(
        archive_root=archive_root.resolve(strict=True),
        **({"primary_archive_sha256": digest} if primary else {}),
    )
    return repository, material, private, source, archive
