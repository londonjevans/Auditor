"""Build inert local archives from non-deployable synthetic fixture material."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import shutil
import tarfile
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures/dependency_snapshot"


def archive_bytes(members: dict[str, bytes], *, mode: int = 0o644) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = mode
            archive.addfile(info, io.BytesIO(content))
    return gzip.compress(stream.getvalue(), mtime=0)


def setup_snapshot_inputs(
    tmp_path: Path, *, members: dict[str, bytes] | None = None
) -> tuple[Path, Path, Path, str]:
    repository = tmp_path / "repository"
    shutil.copytree(FIXTURE / "project", repository)
    archives = tmp_path / "archives"
    archives.mkdir()
    if members is None:
        members = {
            f"package/{path.name}": path.read_bytes()
            for path in sorted((FIXTURE / "package").iterdir())
        }
    replace_archive(repository, archives, archive_bytes(members))
    advisories = tmp_path / "advisories.json"
    advisories.write_bytes(b'{"schema_version":"1.0","advisories":[]}\n')
    return repository, archives, advisories, hashlib.sha256(advisories.read_bytes()).hexdigest()


def replace_archive(repository: Path, archives: Path, content: bytes) -> Path:
    digest = hashlib.sha512(content).digest()
    archive = archives / f"{digest.hex()}.tgz"
    archive.write_bytes(content)
    lock = {
        "name": "mmaudit-synthetic-snapshot",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "mmaudit-synthetic-snapshot", "version": "0.0.0"},
            "node_modules/safe-dep": {
                "version": "1.0.0",
                "integrity": "sha512-" + base64.b64encode(digest).decode("ascii"),
            },
        },
    }
    (repository / "package-lock.json").write_text(json.dumps(lock) + "\n")
    return archive
