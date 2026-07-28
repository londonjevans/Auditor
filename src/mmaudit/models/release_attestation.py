"""Process-local attestation of qualification release bindings.

Self-hashed release-binding documents are declarations. This module independently
observes the executing mmaudit source surface, qualification runtime toolchain, and
already-sealed isolation backend before those declarations can authorize production
model selection.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import ssl
import stat
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from importlib import metadata
from pathlib import Path
from typing import Literal, Never, SupportsIndex

from pydantic import Field, field_validator, model_validator

import mmaudit
from mmaudit.isolation.provenance import (
    isolation_attestation_sha256,
    isolation_execution_evidence,
)
from mmaudit.models.schemas import ExecutionEvidenceKind, StrictModel
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.secrets import is_sensitive_workspace_path

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_COMMIT_PATTERN = r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$"
_MAX_SOURCE_FILES = 100_000
_MAX_SOURCE_BYTES = 4 * 1024**3
_MAX_TOOLCHAIN_FILES = 20_000
_MAX_TOOLCHAIN_BYTES = 2 * 1024**3
_RELEASE_SOURCE_PATHS = (
    "schemas/model_qualification.schema.json",
    "src/mmaudit",
)
_QUALIFICATION_DISTRIBUTIONS = (
    "anyio",
    "certifi",
    "httpcore",
    "httpx",
    "mmaudit",
    "pydantic",
    "pydantic-core",
    "python-dotenv",
    "rich",
    "typer",
)
_TRUSTED_RELEASE_OBSERVATION_ISSUER = object()


class ReleaseEnvironmentMeasurement(StrictModel):
    """Safe, non-secret projection of independently measured release state."""

    schema_version: Literal["1.0"] = "1.0"
    source_commit: str = Field(pattern=_COMMIT_PATTERN)
    source_tree_sha256: str = Field(pattern=_SHA256_PATTERN)
    toolchain_sha256: str = Field(pattern=_SHA256_PATTERN)
    isolation_sha256: str = Field(pattern=_SHA256_PATTERN)
    observed_at: datetime
    measurement_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
            raise ValueError("release observation time must be a whole-second UTC timestamp")
        return value

    @model_validator(mode="after")
    def measurement_hash_is_consistent(self) -> ReleaseEnvironmentMeasurement:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"measurement_sha256"}))
        if self.measurement_sha256 != expected:
            raise ValueError("release environment measurement hash is inconsistent")
        return self


class TrustedReleaseBindingObservation:
    """Opaque proof that release declarations matched fresh local observations."""

    __slots__ = (
        "__bindings_sha256",
        "__isolation_sha256",
        "__issuer",
        "__measurement_sha256",
        "__observed_at",
        "__source_commit",
        "__source_tree_sha256",
        "__toolchain_sha256",
    )

    def __init__(
        self,
        *,
        bindings_sha256: str,
        measurement: ReleaseEnvironmentMeasurement,
        issuer: object,
    ) -> None:
        if issuer is not _TRUSTED_RELEASE_OBSERVATION_ISSUER:
            raise TypeError("trusted release observation cannot be constructed directly")
        self.__bindings_sha256 = bindings_sha256
        self.__measurement_sha256 = measurement.measurement_sha256
        self.__observed_at = measurement.observed_at
        self.__source_commit = measurement.source_commit
        self.__source_tree_sha256 = measurement.source_tree_sha256
        self.__toolchain_sha256 = measurement.toolchain_sha256
        self.__isolation_sha256 = measurement.isolation_sha256
        self.__issuer = issuer

    @property
    def measurement_sha256(self) -> str:
        """Return the non-secret digest retained in runtime evidence."""

        self.__require_integrity()
        return self.__measurement_sha256

    @property
    def observed_at(self) -> datetime:
        """Return when the process-local release measurements completed."""

        self.__require_integrity()
        return self.__observed_at

    def require_for(self, bindings: object) -> None:
        """Reject any reconstructed capability or release-binding drift."""

        from mmaudit.models.qualification import QualificationBindings
        from mmaudit.models.qualification_workflow import QualificationReleaseBindings

        self.__require_integrity()
        if type(bindings) is QualificationReleaseBindings:
            bindings_sha256 = bindings.bindings_sha256
        elif type(bindings) is QualificationBindings:
            bindings_sha256 = canonical_sha256(
                {
                    "schema_version": "1.0",
                    "source_commit": bindings.source_commit,
                    "source_tree_sha256": bindings.source_tree_sha256,
                    "effective_config_sha256": bindings.effective_config_sha256,
                    "prompt_sha256": bindings.prompt_sha256,
                    "response_schema_sha256": bindings.response_schema_sha256,
                    "toolchain_sha256": bindings.toolchain_sha256,
                    "isolation_sha256": bindings.isolation_sha256,
                    "benchmark_corpus_version": bindings.benchmark_corpus_version,
                    "benchmark_ground_truth_version": bindings.benchmark_ground_truth_version,
                }
            )
        else:
            raise ValueError("release observation requires exact typed qualification bindings")
        if (
            self.__bindings_sha256 != bindings_sha256
            or self.__source_commit != bindings.source_commit
            or self.__source_tree_sha256 != bindings.source_tree_sha256
            or self.__toolchain_sha256 != bindings.toolchain_sha256
            or self.__isolation_sha256 != bindings.isolation_sha256
        ):
            raise ValueError("trusted release observation differs from qualification bindings")

    def __require_integrity(self) -> None:
        """Revalidate every retained measurement field before granting authority."""

        if (
            type(self) is not TrustedReleaseBindingObservation
            or getattr(self, "_TrustedReleaseBindingObservation__issuer", None)
            is not _TRUSTED_RELEASE_OBSERVATION_ISSUER
        ):
            raise ValueError("release observation capability is not trusted")
        try:
            measurement = ReleaseEnvironmentMeasurement.model_validate(
                {
                    "schema_version": "1.0",
                    "source_commit": self.__source_commit,
                    "source_tree_sha256": self.__source_tree_sha256,
                    "toolchain_sha256": self.__toolchain_sha256,
                    "isolation_sha256": self.__isolation_sha256,
                    "observed_at": self.__observed_at,
                    "measurement_sha256": self.__measurement_sha256,
                }
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("release observation capability integrity check failed") from exc
        if (
            measurement.source_commit != self.__source_commit
            or measurement.source_tree_sha256 != self.__source_tree_sha256
            or measurement.toolchain_sha256 != self.__toolchain_sha256
            or measurement.isolation_sha256 != self.__isolation_sha256
            or measurement.observed_at != self.__observed_at
            or measurement.measurement_sha256 != self.__measurement_sha256
            or re.fullmatch(_SHA256_PATTERN, self.__bindings_sha256) is None
        ):
            raise ValueError("release observation capability integrity check failed")

    def __copy__(self) -> Never:
        raise TypeError("trusted release observation cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("trusted release observation cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("trusted release observation cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("trusted release observation cannot be serialized")


def measure_qualification_release_environment(
    *,
    source_root: Path,
    isolation_backend: object | None,
) -> ReleaseEnvironmentMeasurement:
    """Measure the exact executing release surface, tools, and sealed isolation."""

    root = _require_executing_release_root(source_root)
    git = _trusted_git_executable()
    source_commit, source_tree_sha256 = _measure_release_source(root, git=git)
    toolchain_sha256 = _measure_qualification_toolchain(root=root, git=git)
    if isolation_execution_evidence(isolation_backend) is not ExecutionEvidenceKind.REAL:
        raise ValueError("qualification release requires freshly sealed REAL isolation")
    isolation_sha256 = isolation_attestation_sha256(isolation_backend)
    if isolation_sha256 is None or re.fullmatch(_SHA256_PATTERN, isolation_sha256) is None:
        raise ValueError("qualification release isolation attestation is unavailable")
    timestamp = _utc_now()
    payload = {
        "schema_version": "1.0",
        "source_commit": source_commit,
        "source_tree_sha256": source_tree_sha256,
        "toolchain_sha256": toolchain_sha256,
        "isolation_sha256": isolation_sha256,
        "observed_at": timestamp.isoformat().replace("+00:00", "Z"),
    }
    payload["measurement_sha256"] = canonical_sha256(payload)
    return ReleaseEnvironmentMeasurement.model_validate(payload)


def observe_and_verify_qualification_release(
    *,
    release_bindings: object,
    source_root: Path,
    isolation_backend: object | None,
) -> TrustedReleaseBindingObservation:
    """Issue process-local authority only when every measured release field matches."""

    from mmaudit.models.qualification_workflow import QualificationReleaseBindings

    if type(release_bindings) is not QualificationReleaseBindings:
        raise ValueError("release observation requires exact typed release bindings")
    started_at = _utc_now()
    measurement = measure_qualification_release_environment(
        source_root=source_root,
        isolation_backend=isolation_backend,
    )
    completed_at = _utc_now()
    if measurement.observed_at < started_at or measurement.observed_at > completed_at:
        raise ValueError("release environment measurement time is not freshly observed")
    expected = (
        release_bindings.source_commit,
        release_bindings.source_tree_sha256,
        release_bindings.toolchain_sha256,
        release_bindings.isolation_sha256,
    )
    actual = (
        measurement.source_commit,
        measurement.source_tree_sha256,
        measurement.toolchain_sha256,
        measurement.isolation_sha256,
    )
    if actual != expected:
        raise ValueError("measured release environment differs from declared bindings")
    return TrustedReleaseBindingObservation(
        bindings_sha256=release_bindings.bindings_sha256,
        measurement=measurement,
        issuer=_TRUSTED_RELEASE_OBSERVATION_ISSUER,
    )


def _utc_now() -> datetime:
    """Sample a whole-second UTC wall clock for freshness-bound authority."""

    return datetime.now(UTC).replace(microsecond=0)


def write_observed_qualification_release_bindings(path: Path, bindings: object) -> None:
    """Atomically publish canonical non-secret bindings outside the source tree."""

    from mmaudit.models.qualification_workflow import QualificationReleaseBindings

    if type(bindings) is not QualificationReleaseBindings:
        raise ValueError("release binding output requires exact typed bindings")
    serialized = stable_json(bindings).encode("utf-8")
    if not serialized or len(serialized) > 1_000_000:
        raise ValueError("qualification release bindings exceed their byte limit")
    absolute = Path(os.path.abspath(path))
    parent = absolute.parent
    if parent.is_symlink() or parent.is_junction() or not parent.is_dir():
        raise ValueError("qualification release binding parent must be a non-link directory")
    if os.path.lexists(absolute):
        raise ValueError("qualification release binding output must be fresh")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{absolute.name}.",
        suffix=".tmp",
        dir=parent,
    )
    temporary = Path(temporary_name)
    published = False
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(serialized)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("qualification release binding output made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if os.path.lexists(absolute):
            raise ValueError("qualification release binding output appeared during publication")
        os.link(temporary, absolute, follow_symlinks=False)
        temporary.unlink()
        published = True
        metadata_result = absolute.stat()
        if (
            not stat.S_ISREG(metadata_result.st_mode)
            or metadata_result.st_nlink != 1
            or stat.S_IMODE(metadata_result.st_mode) != 0o600
        ):
            raise ValueError("qualification release binding output is not private and unshared")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not published:
            temporary.unlink(missing_ok=True)


def _require_executing_release_root(source_root: Path) -> Path:
    absolute = Path(os.path.abspath(source_root))
    if absolute.is_symlink() or absolute.is_junction():
        raise ValueError("qualification release source root may not be a link")
    try:
        root = absolute.resolve(strict=True)
        imported_package = Path(mmaudit.__file__).parent.resolve(strict=True)
        source_package = (root / "src" / "mmaudit").resolve(strict=True)
    except OSError as exc:
        raise ValueError("qualification release source root is unavailable") from exc
    if not root.is_dir() or source_package != imported_package:
        raise ValueError(
            "qualification release root does not contain the executing mmaudit package"
        )
    return root


def _trusted_git_executable() -> Path:
    for candidate in (Path("/usr/bin/git"), Path("/bin/git")):
        try:
            metadata_result = candidate.lstat()
            resolved = candidate.resolve(strict=True)
            resolved_metadata = resolved.stat()
        except OSError:
            continue
        if (
            stat.S_ISLNK(metadata_result.st_mode)
            or not stat.S_ISREG(resolved_metadata.st_mode)
            or resolved_metadata.st_nlink != 1
        ):
            continue
        return resolved
    raise ValueError("fixed trusted Git executable is unavailable")


def _git_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _run_git(git: Path, root: Path, arguments: tuple[str, ...], *, timeout: int = 30) -> bytes:
    try:
        result = subprocess.run(
            [str(git), "-C", str(root), *arguments],
            check=False,
            capture_output=True,
            timeout=timeout,
            env=_git_environment(),
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("trusted Git source observation failed") from exc
    if result.returncode != 0:
        raise ValueError("trusted Git source observation was rejected")
    return result.stdout


def _measure_release_source(root: Path, *, git: Path) -> tuple[str, str]:
    top_level = (
        _run_git(git, root, ("rev-parse", "--show-toplevel"))
        .decode("utf-8", errors="strict")
        .strip()
    )
    if Path(top_level).resolve(strict=True) != root:
        raise ValueError("qualification release root is not the exact Git worktree")
    source_arguments = ("--", *_RELEASE_SOURCE_PATHS)
    status_before = _run_git(
        git,
        root,
        ("status", "--porcelain=v1", "-z", "--untracked-files=all", *source_arguments),
    )
    if status_before:
        raise ValueError("qualification release code surface is not clean")
    commit = (
        _run_git(git, root, ("rev-parse", "--verify", "HEAD"))
        .decode("ascii", errors="strict")
        .strip()
    )
    if re.fullmatch(_COMMIT_PATTERN, commit) is None:
        raise ValueError("qualification release commit is unavailable")
    object_format = (
        _run_git(git, root, ("rev-parse", "--show-object-format"))
        .decode("ascii", errors="strict")
        .strip()
    )
    if object_format not in {"sha1", "sha256"}:
        raise ValueError("qualification release Git object format is unsupported")
    listed = _run_git(
        git,
        root,
        ("ls-tree", "-r", "-z", "--full-tree", commit, *source_arguments),
    )
    raw_entries = tuple(part for part in listed.split(b"\0") if part)
    if not raw_entries or len(raw_entries) > _MAX_SOURCE_FILES:
        raise ValueError("qualification release source inventory is empty or excessive")
    entries: list[tuple[str, str, str]] = []
    for raw_entry in raw_entries:
        try:
            header, raw_path = raw_entry.split(b"\t", 1)
            mode, object_type, object_id = header.decode("ascii", errors="strict").split(" ")
            relative = raw_path.decode("utf-8", errors="strict")
        except (UnicodeError, ValueError):
            raise ValueError("qualification release Git inventory is malformed") from None
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise ValueError("qualification release source inventory contains an unsafe entry")
        expected_length = 40 if object_format == "sha1" else 64
        if re.fullmatch(rf"[0-9a-f]{{{expected_length}}}", object_id) is None:
            raise ValueError("qualification release Git object identity is malformed")
        entries.append((relative, mode, object_id))
    paths = tuple(relative for relative, _mode, _object_id in entries)
    if paths != tuple(sorted(set(paths))):
        raise ValueError("qualification release source inventory is not canonical")
    records: list[dict[str, str | int]] = []
    total_bytes = 0
    for relative, committed_mode, expected_object_id in entries:
        if (
            relative.startswith(("/", "-"))
            or any(part in {"", ".", ".."} for part in relative.split("/"))
            or is_sensitive_workspace_path(relative)
        ):
            raise ValueError("qualification release source inventory contains an unsafe path")
        candidate = root / relative
        try:
            candidate.relative_to(root)
            item_metadata = candidate.lstat()
        except (OSError, ValueError) as exc:
            raise ValueError("qualification release source inventory is unavailable") from exc
        if not stat.S_ISREG(item_metadata.st_mode) or item_metadata.st_nlink != 1:
            raise ValueError("qualification release source inventory contains a linked file")
        digest, observed_object_id = _file_and_git_blob_sha256(
            candidate,
            size=item_metadata.st_size,
            git_object_format=object_format,
        )
        observed_mode = "100755" if item_metadata.st_mode & stat.S_IXUSR else "100644"
        if observed_object_id != expected_object_id or observed_mode != committed_mode:
            raise ValueError("qualification release bytes differ from the committed Git object")
        total_bytes += item_metadata.st_size
        if total_bytes > _MAX_SOURCE_BYTES:
            raise ValueError("qualification release source inventory exceeds its byte limit")
        records.append(
            {
                "path": relative,
                "sha256": digest,
                "size": item_metadata.st_size,
                "mode": committed_mode,
            }
        )
    status_after = _run_git(
        git,
        root,
        ("status", "--porcelain=v1", "-z", "--untracked-files=all", *source_arguments),
    )
    commit_after = (
        _run_git(git, root, ("rev-parse", "--verify", "HEAD"))
        .decode("ascii", errors="strict")
        .strip()
    )
    if status_after or commit_after != commit:
        raise ValueError("qualification release code surface changed during observation")
    return commit, canonical_sha256(records)


def _measure_qualification_toolchain(*, root: Path, git: Path) -> str:
    executable = Path(sys.executable).resolve(strict=True)
    executable_metadata = executable.stat()
    try:
        executable.relative_to(root)
    except ValueError:
        pass
    else:
        raise ValueError("qualification Python executable may not be repository-controlled")
    if not stat.S_ISREG(executable_metadata.st_mode) or executable_metadata.st_nlink != 1:
        raise ValueError("qualification Python executable must be an unshared regular file")
    git_metadata = git.stat()
    if not stat.S_ISREG(git_metadata.st_mode) or git_metadata.st_nlink != 1:
        raise ValueError("trusted Git executable must be an unshared regular file")
    git_version = _run_git(git, root, ("--version",)).decode("utf-8", errors="strict").strip()
    if not re.fullmatch(r"git version [0-9][A-Za-z0-9.() +_-]{0,100}", git_version):
        raise ValueError("trusted Git version output is malformed")

    distributions: list[dict[str, object]] = []
    file_count = 0
    total_bytes = 0
    for name in _QUALIFICATION_DISTRIBUTIONS:
        try:
            distribution = metadata.distribution(name)
        except metadata.PackageNotFoundError as exc:
            raise ValueError("qualification runtime dependency is unavailable") from exc
        files = tuple(sorted(distribution.files or (), key=str))
        if not files:
            raise ValueError("qualification runtime dependency has no file inventory")
        inventory: list[dict[str, str | int]] = []
        for package_path in files:
            file_count += 1
            if file_count > _MAX_TOOLCHAIN_FILES:
                raise ValueError("qualification toolchain file inventory is excessive")
            located = Path(str(distribution.locate_file(package_path)))
            try:
                located_metadata = located.lstat()
            except OSError as exc:
                raise ValueError("qualification toolchain dependency file is unavailable") from exc
            if not stat.S_ISREG(located_metadata.st_mode) or located_metadata.st_nlink != 1:
                raise ValueError("qualification toolchain dependency contains a linked file")
            total_bytes += located_metadata.st_size
            if total_bytes > _MAX_TOOLCHAIN_BYTES:
                raise ValueError("qualification toolchain exceeds its byte limit")
            inventory.append(
                {
                    "path": str(package_path).replace("\\", "/"),
                    "sha256": _file_sha256(located),
                    "size": located_metadata.st_size,
                }
            )
        distributions.append(
            {
                "name": name,
                "version": distribution.version,
                "files_sha256": canonical_sha256(inventory),
                "file_count": len(inventory),
            }
        )
    material = {
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "cache_tag": sys.implementation.cache_tag,
            "executable_sha256": _file_sha256(executable),
            "openssl_version": ssl.OPENSSL_VERSION,
        },
        "git": {
            "version": git_version,
            "executable_sha256": _file_sha256(git),
        },
        "distributions": distributions,
    }
    return canonical_sha256(material)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _file_and_git_blob_sha256(
    path: Path,
    *,
    size: int,
    git_object_format: str,
) -> tuple[str, str]:
    content_digest = hashlib.sha256()
    git_digest = hashlib.new(git_object_format)
    git_digest.update(f"blob {size}\0".encode("ascii"))
    observed = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            observed += len(chunk)
            content_digest.update(chunk)
            git_digest.update(chunk)
    if observed != size:
        raise ValueError("qualification release source changed while being hashed")
    return content_digest.hexdigest(), git_digest.hexdigest()
