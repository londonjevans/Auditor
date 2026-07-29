"""Regression coverage for scanner workspace source binding."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from mmaudit.scanners import base as scanner_base
from mmaudit.scanners.base import (
    copy_scanner_workspace,
    scanner_workspace_exclusion_path,
    scanner_workspace_sha256,
)


def test_excluded_output_is_pruned_without_opening_or_enumerating_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    source = repository / "src"
    output = repository / "custom-output"
    source.mkdir(parents=True)
    output.mkdir()
    (source / "Safe.sol").write_text("contract Safe {}\n", encoding="utf-8")
    (output / "large-result.json").write_text('{"ignored":true}\n', encoding="utf-8")
    output_identity = output.stat()
    real_open = os.open
    real_scandir = os.scandir

    def guarded_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        metadata = os.fstat(descriptor)
        if metadata.st_dev == output_identity.st_dev and metadata.st_ino == output_identity.st_ino:
            os.close(descriptor)
            pytest.fail("excluded output directory was opened")
        return descriptor

    def guarded_scandir(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes] | int,
    ) -> Any:
        if isinstance(path, int):
            metadata = os.fstat(path)
            if (
                metadata.st_dev == output_identity.st_dev
                and metadata.st_ino == output_identity.st_ino
            ):
                pytest.fail("excluded output directory was enumerated")
        return real_scandir(path)

    monkeypatch.setattr(os, "open", guarded_open)
    monkeypatch.setattr(os, "scandir", guarded_scandir)

    expected = scanner_workspace_sha256(repository, output)
    copied = tmp_path / "copied"
    copy_scanner_workspace(repository, copied, output)

    assert scanner_workspace_sha256(copied) == expected
    assert (copied / "src" / "Safe.sol").is_file()
    assert not (copied / "custom-output").exists()
    (output / "large-result.json").write_text('{"ignored":false}\n', encoding="utf-8")
    assert scanner_workspace_sha256(repository, output) == expected


def test_symlinked_prior_output_name_is_excluded_without_following_it(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    outside = tmp_path / "outside"
    repository.mkdir()
    outside.mkdir()
    (repository / "Safe.sol").write_text("contract Safe {}\n", encoding="utf-8")
    (outside / "prior-report.json").write_text('{"ignored":true}\n', encoding="utf-8")
    output = repository / "custom-output"
    try:
        output.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")

    expected = scanner_workspace_sha256(repository, output)

    assert scanner_workspace_exclusion_path(repository, output) == "custom-output"
    (outside / "prior-report.json").write_text('{"ignored":false}\n', encoding="utf-8")
    assert scanner_workspace_sha256(repository, output) == expected


def test_copy_rejects_symlink_replacement_after_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "Safe.sol"
    source.write_text("contract Safe {}\n", encoding="utf-8")
    outside = tmp_path / "outside.sol"
    outside.write_text("contract Outside {}\n", encoding="utf-8")
    original_copy = scanner_base._copy_scanner_workspace_inventory

    def replace_then_copy(
        inventory: scanner_base._ScannerWorkspaceInventory,
        workspace: Path,
    ) -> None:
        source.unlink()
        source.symlink_to(outside)
        original_copy(inventory, workspace)

    monkeypatch.setattr(
        scanner_base,
        "_copy_scanner_workspace_inventory",
        replace_then_copy,
    )

    with pytest.raises((OSError, ValueError)):
        copy_scanner_workspace(repository, tmp_path / "copied", tmp_path / "private")
    assert not (tmp_path / "copied" / "Safe.sol").exists()


def test_hash_rejects_regular_file_replacement_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "Safe.sol"
    source.write_bytes(b"a" * 4096)
    source_identity = source.stat()
    replacement = tmp_path / "replacement.sol"
    replacement.write_bytes(b"b" * 4096)
    real_read = os.read
    replaced = False

    def racing_read(descriptor: int, count: int) -> bytes:
        nonlocal replaced
        value = real_read(descriptor, count)
        metadata = os.fstat(descriptor)
        if (
            not replaced
            and metadata.st_dev == source_identity.st_dev
            and metadata.st_ino == source_identity.st_ino
        ):
            os.replace(replacement, source)
            replaced = True
        return value

    monkeypatch.setattr(os, "read", racing_read)

    with pytest.raises(ValueError, match="identity changed"):
        scanner_workspace_sha256(repository)
    assert replaced
