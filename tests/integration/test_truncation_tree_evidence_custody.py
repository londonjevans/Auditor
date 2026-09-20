"""Disposable local file/process regressions for original full-tree verification custody."""

from __future__ import annotations

import multiprocessing
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import mmaudit.orchestration.scheduler as scheduler_module
import mmaudit.orchestration.truncation_tree_evidence as tree_module
from mmaudit.models.scheduler import SchedulerPassKind, SchedulerPassStatus
from mmaudit.orchestration.truncation_tree_evidence import (
    require_verified_truncation_recovery_full_tree,
    verify_truncation_recovery_full_tree,
)
from tests.unit.test_truncation_tree_evidence import LiveTreeFixture, build_live_tree


@pytest.fixture
def local_tree(tmp_path: Path) -> Iterator[tuple[LiveTreeFixture, Any, Path]]:
    path = tmp_path / "original-journal"
    fixture = build_live_tree(path, source_count=4, truncated_paths=frozenset())
    try:
        token, artifact = verify_truncation_recovery_full_tree(**fixture.arguments())
        assert artifact.accounting.provider_request_count == 3
        yield fixture, token, path
    finally:
        fixture.journal.close()


@pytest.mark.parametrize("change", ["content", "inode", "symlink"])
def test_original_tree_refuses_changed_durable_custody(
    local_tree: tuple[Any, Any, Path], change: str
) -> None:
    fixture, token, path = local_tree
    root = fixture.journal.truncation_recovery_families[0]
    target = path / scheduler_module._truncation_recovery_entry_path(root)
    original = target.read_bytes()
    if change == "content":
        target.write_bytes(original + b"\n")
    elif change == "inode":
        replacement = target.with_name("synthetic-same-content-replacement")
        replacement.write_bytes(original)
        replacement.chmod(0o600)
        os.replace(replacement, target)
    else:
        retained = target.with_name("synthetic-symlink-source")
        target.rename(retained)
        target.symlink_to(retained.name)
    # Invariant: unchanged decoded content is not unchanged original durable custody.
    with pytest.raises(ValueError):
        require_verified_truncation_recovery_full_tree(token)


def test_closed_original_owner_cannot_be_replaced_by_its_data(
    local_tree: tuple[Any, Any, Path],
) -> None:
    fixture, token, _ = local_tree
    fixture.journal.close()
    with pytest.raises(ValueError):
        require_verified_truncation_recovery_full_tree(token)
    with pytest.raises(ValueError):
        verify_truncation_recovery_full_tree(**fixture.arguments())


def test_append_only_pass_checkpoint_preserves_verification_without_promotion(
    tmp_path: Path,
) -> None:
    fixture = build_live_tree(
        tmp_path / "unpromoted-generic-tree",
        source_count=5,
        truncated_paths=frozenset({"0", "1"}),
    )
    try:
        token, artifact = verify_truncation_recovery_full_tree(**fixture.arguments())
        assert artifact.recovery_prefix[-1].schema_version == "1.3"
        before = require_verified_truncation_recovery_full_tree(token)
        result = fixture.journal.seal_pass_result(SchedulerPassKind.BLIND_SHARD_REVIEW)
        assert result.status is not SchedulerPassStatus.COMPLETE
        after = require_verified_truncation_recovery_full_tree(token)
        assert after.artifact == before.artifact
        assert after.model_review_bindings == before.model_review_bindings
    finally:
        fixture.journal.close()


def test_mutated_original_live_usage_cannot_retain_verified_tree_custody(
    local_tree: tuple[Any, Any, Path],
) -> None:
    fixture, token, _ = local_tree
    fixture.parent_usage.routing["synthetic_post_verification_mutation"] = True
    with pytest.raises(ValueError):
        require_verified_truncation_recovery_full_tree(token)


def _fork_require(token: Any, connection: Any) -> None:
    try:
        require_verified_truncation_recovery_full_tree(token)
    except ValueError as exc:
        connection.send(str(exc))
    else:
        connection.send("unexpected-success")
    finally:
        connection.close()


@pytest.mark.skipif(
    "fork" not in multiprocessing.get_all_start_methods(), reason="fork unavailable"
)
def test_forked_tree_token_cannot_inherit_parent_authority(
    local_tree: tuple[Any, Any, Path],
) -> None:
    _, token, _ = local_tree
    context = multiprocessing.get_context("fork")
    receiving, sending = context.Pipe(duplex=False)
    child = context.Process(target=_fork_require, args=(token, sending))
    child.start()
    sending.close()
    try:
        assert receiving.poll(20), "bounded local child did not return a verification result"
        assert "process fork" in receiving.recv()
        child.join(timeout=10)
        assert child.exitcode == 0
        assert require_verified_truncation_recovery_full_tree(token).artifact is not None
    finally:
        if child.is_alive():
            child.terminate()
            child.join(timeout=10)
        receiving.close()


def test_public_helper_rebinding_cannot_replace_original_reader(
    local_tree: tuple[Any, Any, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, token, path = local_tree
    projection = require_verified_truncation_recovery_full_tree(token)
    monkeypatch.setattr(tree_module, "_verify_live_tree_material", lambda **_: projection)
    monkeypatch.setattr(
        scheduler_module, "_read_live_recovery_tree_journal_snapshot", lambda **_: None
    )
    monkeypatch.setattr(fixture.journal, "_validate_state", lambda: ())
    target = path / scheduler_module._truncation_recovery_entry_path(
        fixture.journal.truncation_recovery_families[0]
    )
    target.write_bytes(target.read_bytes() + b"\n")
    with pytest.raises(ValueError):
        require_verified_truncation_recovery_full_tree(token)
