"""Fail-closed tests for descriptor-observed scanner source text."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from mmaudit.scanners import base as scanner_base
from mmaudit.scanners.base import (
    observe_scanner_workspace_texts,
    scanner_workspace_sha256,
)


def _source_repository(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "repository"
    source = repository / "requirements.lock"
    repository.mkdir()
    source.write_text("package-a==1.0\npackage-b==2.0\n", encoding="utf-8")
    nested = repository / "src" / "δοκιμή.txt"
    nested.parent.mkdir()
    nested.write_text("first\nsecond", encoding="utf-8")
    return repository, source


def test_observer_returns_sorted_raw_bound_strict_utf8_records(tmp_path: Path) -> None:
    repository, source = _source_repository(tmp_path)
    nested = repository / "src" / "δοκιμή.txt"
    expected_inventory_sha256 = scanner_workspace_sha256(repository)

    records = observe_scanner_workspace_texts(
        repository,
        ("src/δοκιμή.txt", Path("requirements.lock")),
        expected_inventory_sha256=expected_inventory_sha256,
        maximum_file_bytes=1_000,
        maximum_total_bytes=2_000,
    )

    assert tuple(record.relative_path for record in records) == (
        "requirements.lock",
        "src/δοκιμή.txt",
    )
    assert records[0].raw_sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert records[0].size == len(source.read_bytes())
    assert records[0].content == "package-a==1.0\npackage-b==2.0\n"
    assert records[0].lines == 2
    assert records[1].raw_sha256 == hashlib.sha256(nested.read_bytes()).hexdigest()
    assert records[1].content == "first\nsecond"
    assert records[1].lines == 2


def test_observer_requires_exact_frozen_inventory_and_requested_file(
    tmp_path: Path,
) -> None:
    repository, _ = _source_repository(tmp_path)
    expected_inventory_sha256 = scanner_workspace_sha256(repository)

    with pytest.raises(ValueError, match="differs from the expected hash"):
        observe_scanner_workspace_texts(
            repository,
            ("requirements.lock",),
            expected_inventory_sha256="0" * 64,
        )
    with pytest.raises(ValueError, match="absent from the execution inventory"):
        observe_scanner_workspace_texts(
            repository,
            ("missing.lock",),
            expected_inventory_sha256=expected_inventory_sha256,
        )


def test_observer_enforces_per_file_and_aggregate_byte_bounds(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "a.txt").write_bytes(b"aaaa")
    (repository / "b.txt").write_bytes(b"bbbb")
    expected_inventory_sha256 = scanner_workspace_sha256(repository)

    with pytest.raises(ValueError, match="per-file byte bound"):
        observe_scanner_workspace_texts(
            repository,
            ("a.txt",),
            expected_inventory_sha256=expected_inventory_sha256,
            maximum_file_bytes=3,
            maximum_total_bytes=8,
        )
    with pytest.raises(ValueError, match="total byte bound"):
        observe_scanner_workspace_texts(
            repository,
            ("a.txt", "b.txt"),
            expected_inventory_sha256=expected_inventory_sha256,
            maximum_file_bytes=4,
            maximum_total_bytes=7,
        )


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b"not-utf8-\xff\n", "not strict UTF-8"),
        (b"text\x00payload\n", "is binary"),
        (b"text\x01\x02\x03\x04\n", "is binary"),
    ],
)
def test_observer_rejects_non_utf8_and_binary_sources(
    tmp_path: Path,
    raw: bytes,
    message: str,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "source.dat").write_bytes(raw)
    expected_inventory_sha256 = scanner_workspace_sha256(repository)

    with pytest.raises(ValueError, match=message):
        observe_scanner_workspace_texts(
            repository,
            ("source.dat",),
            expected_inventory_sha256=expected_inventory_sha256,
        )


def test_observer_rejects_sensitive_and_linked_requested_paths(tmp_path: Path) -> None:
    sensitive_repository = tmp_path / "sensitive"
    sensitive_repository.mkdir()
    (sensitive_repository / ".env").write_text("SYNTHETIC=canary\n", encoding="utf-8")
    sensitive_hash = scanner_workspace_sha256(sensitive_repository)
    with pytest.raises(ValueError, match="excluded from execution workspaces"):
        observe_scanner_workspace_texts(
            sensitive_repository,
            (".env",),
            expected_inventory_sha256=sensitive_hash,
        )

    linked_repository = tmp_path / "linked"
    linked_repository.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    try:
        (linked_repository / "linked.txt").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="unique regular files only"):
        observe_scanner_workspace_texts(
            linked_repository,
            ("linked.txt",),
            expected_inventory_sha256="0" * 64,
        )


def test_observer_rejects_hardlinked_and_special_workspace_entries(tmp_path: Path) -> None:
    hardlinked_repository = tmp_path / "hardlinked"
    hardlinked_repository.mkdir()
    original = hardlinked_repository / "original.txt"
    original.write_text("synthetic\n", encoding="utf-8")
    try:
        os.link(original, hardlinked_repository / "alias.txt")
    except OSError:
        pytest.skip("hardlinks unavailable")
    with pytest.raises(ValueError, match="unique regular files only"):
        observe_scanner_workspace_texts(
            hardlinked_repository,
            ("original.txt",),
            expected_inventory_sha256="0" * 64,
        )

    if not hasattr(os, "mkfifo"):
        return
    special_repository = tmp_path / "special"
    special_repository.mkdir()
    os.mkfifo(special_repository / "channel")
    with pytest.raises(ValueError, match="unique regular files only"):
        observe_scanner_workspace_texts(
            special_repository,
            ("channel",),
            expected_inventory_sha256="0" * 64,
        )


def test_observer_uses_descriptor_relative_no_follow_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = _source_repository(tmp_path)
    expected_inventory_sha256 = scanner_workspace_sha256(repository)
    real_open = os.open
    observed_flags: list[int] = []

    def recording_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == "requirements.lock" and dir_fd is not None:
            observed_flags.append(flags)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", recording_open)

    observe_scanner_workspace_texts(
        repository,
        ("requirements.lock",),
        expected_inventory_sha256=expected_inventory_sha256,
    )

    assert len(observed_flags) >= 3
    assert all(flags & os.O_NOFOLLOW for flags in observed_flags)


def test_observer_rejects_source_mutation_after_the_custodied_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, source = _source_repository(tmp_path)
    expected_inventory_sha256 = scanner_workspace_sha256(repository)
    real_read = scanner_base._read_scanner_workspace_file_bytes
    mutated = False

    def read_then_mutate(
        root_fd: int,
        item: scanner_base._WorkspaceFile,
        directory_identities: dict[str, scanner_base._WorkspaceIdentity],
    ) -> bytes:
        nonlocal mutated
        raw = real_read(root_fd, item, directory_identities)
        source.write_text("package-x==9.9\npackage-y==8.8\n", encoding="utf-8")
        mutated = True
        return raw

    monkeypatch.setattr(scanner_base, "_read_scanner_workspace_file_bytes", read_then_mutate)

    with pytest.raises(ValueError, match="changed during text observation"):
        observe_scanner_workspace_texts(
            repository,
            ("requirements.lock",),
            expected_inventory_sha256=expected_inventory_sha256,
        )
    assert mutated
