"""Bounded staging for trusted scanner resources used inside isolation."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from importlib.resources import files
from pathlib import Path

_MAX_BUNDLED_RESOURCE_BYTES = 1_000_000
_SAFE_RESOURCE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def stage_bundled_scanner_resource(
    private_dir: Path,
    *,
    resource_relative_path: str,
    destination_name: str,
    scanner_label: str,
) -> Path:
    """Stage one exact package resource inside an operator-private scanner directory."""

    if _SAFE_RESOURCE_COMPONENT.fullmatch(destination_name) is None:
        raise ValueError("bundled scanner destination name is invalid")
    resource_bytes = _bundled_resource_bytes(
        resource_relative_path=resource_relative_path,
        scanner_label=scanner_label,
    )
    source_sha256 = hashlib.sha256(resource_bytes).hexdigest()

    resolved_private, current_uid = _validated_private_directory(private_dir, scanner_label)
    staged_root = resolved_private / "trusted-inputs"
    staged_root.mkdir(mode=0o700)
    _validate_directory(staged_root, mode=0o700, uid=current_uid, scanner_label=scanner_label)

    destination = staged_root / destination_name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(destination, flags, 0o600)
    try:
        remaining = memoryview(resource_bytes)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("staged scanner resource write made no progress")
            remaining = remaining[written:]
    finally:
        os.close(descriptor)
    validate_staged_bundled_scanner_resource(
        private_dir,
        resource_relative_path=resource_relative_path,
        destination_name=destination_name,
        scanner_label=scanner_label,
        expected_sha256=source_sha256,
    )
    return destination


def validate_staged_bundled_scanner_resource(
    private_dir: Path,
    *,
    resource_relative_path: str,
    destination_name: str,
    scanner_label: str,
    expected_sha256: str | None = None,
) -> Path:
    """Revalidate exact staged rule bytes and inode identity immediately before execution."""

    if _SAFE_RESOURCE_COMPONENT.fullmatch(destination_name) is None:
        raise ValueError("bundled scanner destination name is invalid")
    resource_bytes = _bundled_resource_bytes(
        resource_relative_path=resource_relative_path,
        scanner_label=scanner_label,
    )
    source_sha256 = hashlib.sha256(resource_bytes).hexdigest()
    if expected_sha256 is not None and source_sha256 != expected_sha256:
        raise ValueError(f"bundled {scanner_label} rule resource identity changed")
    resolved_private, current_uid = _validated_private_directory(private_dir, scanner_label)
    staged_root = resolved_private / "trusted-inputs"
    _validate_directory(staged_root, mode=0o700, uid=current_uid, scanner_label=scanner_label)
    destination = staged_root / destination_name
    staged_bytes = _read_attested_staged_file(
        destination,
        uid=current_uid,
        scanner_label=scanner_label,
    )
    if staged_bytes != resource_bytes or hashlib.sha256(staged_bytes).hexdigest() != source_sha256:
        raise ValueError(f"staged {scanner_label} rule resource failed exact-byte verification")
    return destination


def _bundled_resource_bytes(*, resource_relative_path: str, scanner_label: str) -> bytes:
    resource_parts = resource_relative_path.split("/")
    if not resource_parts or any(
        _SAFE_RESOURCE_COMPONENT.fullmatch(part) is None for part in resource_parts
    ):
        raise ValueError("bundled scanner resource path is invalid")
    resource = files("mmaudit.scanners").joinpath(*resource_parts)
    if not resource.is_file():
        raise ValueError(f"bundled {scanner_label} rule resource is unavailable")
    with resource.open("rb") as handle:
        resource_bytes = handle.read(_MAX_BUNDLED_RESOURCE_BYTES + 1)
    if not resource_bytes or len(resource_bytes) > _MAX_BUNDLED_RESOURCE_BYTES:
        raise ValueError(
            f"bundled {scanner_label} rule resource is empty or exceeds its fixed bound"
        )
    return resource_bytes


def _validated_private_directory(private_dir: Path, scanner_label: str) -> tuple[Path, int]:
    if _SAFE_RESOURCE_COMPONENT.fullmatch(scanner_label) is None:
        raise ValueError("bundled scanner label is invalid")

    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if private_dir.is_symlink() or private_dir.is_junction():
        raise ValueError(f"{scanner_label} private directory may not be a link")
    resolved_private = private_dir.resolve(strict=True)
    private_metadata = resolved_private.stat()
    current_uid = int(getattr(os, "getuid", lambda: private_metadata.st_uid)())
    if (
        not stat.S_ISDIR(private_metadata.st_mode)
        or stat.S_IMODE(private_metadata.st_mode) != 0o700
        or private_metadata.st_uid != current_uid
    ):
        raise ValueError(f"{scanner_label} private directory must be operator-owned with mode 0700")
    return resolved_private, current_uid


def _validate_directory(path: Path, *, mode: int, uid: int, scanner_label: str) -> None:
    if path.is_symlink() or path.is_junction():
        raise ValueError(f"{scanner_label} staged-input directory may not be a link")
    staged_metadata = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(staged_metadata.st_mode)
        or stat.S_IMODE(staged_metadata.st_mode) != mode
        or staged_metadata.st_uid != uid
    ):
        raise ValueError(f"{scanner_label} staged-input directory failed private-mode validation")


def _read_attested_staged_file(path: Path, *, uid: int, scanner_label: str) -> bytes:
    if _SAFE_RESOURCE_COMPONENT.fullmatch(path.name) is None:
        raise ValueError("bundled scanner destination name is invalid")
    if path.is_symlink() or path.is_junction():
        raise ValueError(f"staged {scanner_label} rule resource may not be a link")
    flags = os.O_RDONLY
    flags |= int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != uid
            or before.st_nlink != 1
            or not 0 < before.st_size <= _MAX_BUNDLED_RESOURCE_BYTES
        ):
            raise ValueError(f"staged {scanner_label} rule resource failed private-file validation")
        chunks: list[bytes] = []
        remaining = _MAX_BUNDLED_RESOURCE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_nlink, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_size,
        ) or after.st_nlink != 1:
            raise ValueError(f"staged {scanner_label} rule resource identity changed")
        payload = b"".join(chunks)
        if len(payload) != before.st_size:
            raise ValueError(f"staged {scanner_label} rule resource length changed")
        return payload
    finally:
        os.close(descriptor)
