"""Disposable local file/process custody for private full-tree promotion."""

from __future__ import annotations

import multiprocessing
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import mmaudit.orchestration.scheduler as scheduler_module
import mmaudit.orchestration.truncation_tree_promotion as promotion_module
from mmaudit.orchestration.truncation_tree_evidence import verify_truncation_recovery_full_tree
from mmaudit.orchestration.truncation_tree_promotion import (
    promote_truncation_recovery_full_tree,
    require_journal_promoted_truncation_recovery_tree,
)
from tests.unit.test_truncation_tree_evidence import LiveTreeFixture, build_live_tree


@pytest.fixture
def local_promotion(tmp_path: Path) -> Iterator[tuple[LiveTreeFixture, Any, Any, Path]]:
    path = tmp_path / "original"
    fixture = build_live_tree(path, source_count=5, truncated_paths=frozenset({"0", "1"}))
    try:
        source, _artifact = verify_truncation_recovery_full_tree(**fixture.arguments())
        token, promotion = promote_truncation_recovery_full_tree(
            journal=fixture.journal, capability=source
        )
        yield fixture, token, promotion, path
    finally:
        fixture.journal.close()


@pytest.mark.parametrize("change", ("bytes", "inode", "symlink"))
def test_changed_original_promotion_file_revokes_live_custody(
    local_promotion: tuple[Any, Any, Any, Path],
    change: str,
) -> None:
    _fixture, token, promotion, path = local_promotion
    target = path / scheduler_module._truncation_recovery_entry_path(promotion)
    original = target.read_bytes()
    if change == "bytes":
        target.write_bytes(original + b"\n")
    elif change == "inode":
        replacement = target.with_name("same-content-local-replacement")
        replacement.write_bytes(original)
        replacement.chmod(0o600)
        os.replace(replacement, target)
    else:
        retained = target.with_name("local-symlink-source")
        target.rename(retained)
        target.symlink_to(retained.name)
    # Invariant: decoded equality cannot replace the original append's file custody.
    with pytest.raises(ValueError):
        require_journal_promoted_truncation_recovery_tree(token)


def test_closed_original_journal_cannot_keep_promotion_authority(
    local_promotion: tuple[Any, Any, Any, Path],
) -> None:
    fixture, token, _promotion, _path = local_promotion
    fixture.journal.close()
    with pytest.raises(ValueError):
        require_journal_promoted_truncation_recovery_tree(token)


def test_original_live_usage_mutation_revokes_private_promotion(
    local_promotion: tuple[Any, Any, Any, Path],
) -> None:
    fixture, token, _promotion, _path = local_promotion
    fixture.usages[-1].routing["synthetic-post-promotion-mutation"] = True
    with pytest.raises(ValueError):
        require_journal_promoted_truncation_recovery_tree(token)


def _require_in_fork(token: Any, connection: Any) -> None:
    try:
        require_journal_promoted_truncation_recovery_tree(token)
    except ValueError as exc:
        connection.send(str(exc))
    else:
        connection.send("unexpected-success")
    finally:
        connection.close()


@pytest.mark.skipif(
    "fork" not in multiprocessing.get_all_start_methods(), reason="fork unavailable"
)
def test_child_process_cannot_inherit_original_promotion(
    local_promotion: tuple[Any, Any, Any, Path],
) -> None:
    _fixture, token, _promotion, _path = local_promotion
    context = multiprocessing.get_context("fork")
    receiving, sending = context.Pipe(duplex=False)
    child = context.Process(target=_require_in_fork, args=(token, sending))
    child.start()
    sending.close()
    try:
        assert receiving.poll(20), "bounded local child did not return"
        assert "process fork" in receiving.recv()
        child.join(timeout=10)
        assert child.exitcode == 0
        assert require_journal_promoted_truncation_recovery_tree(token).promotion is not None
    finally:
        if child.is_alive():
            child.terminate()
            child.join(timeout=10)
        receiving.close()


def test_rebound_helpers_cannot_replace_original_promotion_verification(
    local_promotion: tuple[Any, Any, Any, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fixture, token, promotion, _path = local_promotion

    def replacement(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("substituted public helper must not supply authority")

    monkeypatch.setattr(
        promotion_module, "require_verified_truncation_recovery_full_tree", replacement
    )
    monkeypatch.setattr(
        scheduler_module.SchedulerJournal,
        "_require_current_promoted_truncation_recovery_family",
        replacement,
    )
    assert require_journal_promoted_truncation_recovery_tree(token).promotion == promotion


def test_foreign_owner_is_refused_before_any_append(tmp_path: Path) -> None:
    fixture = build_live_tree(
        tmp_path / "source", source_count=5, truncated_paths=frozenset({"0", "1"})
    )
    try:
        source, _artifact = verify_truncation_recovery_full_tree(**fixture.arguments())
        before = tuple(fixture.journal._truncation_recovery_entries)
        with pytest.raises(ValueError, match="original journal"):
            promote_truncation_recovery_full_tree(journal=object(), capability=source)  # type: ignore[arg-type]
        assert tuple(fixture.journal._truncation_recovery_entries) == before
    finally:
        fixture.journal.close()
