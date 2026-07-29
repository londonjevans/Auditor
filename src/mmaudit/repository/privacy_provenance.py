"""Fail-closed provenance for source classifications that permit benchmark egress."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import threading
import weakref
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

import mmaudit
from mmaudit.repository.discovery import DiscoveryResult
from mmaudit.repository.ignore import normalize_relative_path

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_GIT_OBJECT_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")
_MAX_GIT_OUTPUT_BYTES = 16 * 1024 * 1024
_MAX_PROVENANCE_FILE_BYTES = 8 * 1024 * 1024
_MAX_PROVENANCE_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_PROVENANCE_FILES = 20_000
_SYNTHETIC_DECLARATION_RELATIVE_PATH = "src/mmaudit/resources/privacy-synthetic-sources.json"
_PACKAGE_SYNTHETIC_DECLARATION_RELATIVE_PATH = "resources/privacy-synthetic-sources.json"
_TRUSTED_SYNTHETIC_DECLARATION_SHA256 = (
    "7bca2ce44d14f9844f61a8434277f88b443c0992a8df5d811db6794513a9fb6b"
)
_TRUSTED_PROVENANCE_ISSUER = object()
_PROVENANCE_LOCK = threading.Lock()

PrivacySourceClassificationValue = Literal[
    "PRIVATE_OPERATOR_SOURCE",
    "SYNTHETIC_COMMITTED",
    "PUBLIC_BENCHMARK",
]


class _SyntheticDeclarationFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=1_024)
    sha256: str = Field(pattern=_SHA256_PATTERN)
    size: int = Field(ge=0, le=_MAX_PROVENANCE_FILE_BYTES)

    @field_validator("path")
    @classmethod
    def path_is_normalized(cls, value: str) -> str:
        normalized = normalize_relative_path(value)
        if normalized != value or normalized in {"", "."}:
            raise ValueError("synthetic declaration file path must be normalized")
        return value


class _SyntheticDeclarationEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: str = Field(min_length=1, max_length=1_024)
    purpose: str = Field(min_length=1, max_length=1_000)
    files: tuple[_SyntheticDeclarationFile, ...] = Field(
        min_length=1,
        max_length=_MAX_PROVENANCE_FILES,
    )

    @field_validator("scope")
    @classmethod
    def scope_is_normalized(cls, value: str) -> str:
        normalized = normalize_relative_path(value)
        if normalized != value or normalized in {"", "."}:
            raise ValueError("synthetic declaration scope must be normalized")
        return value

    @field_validator("purpose")
    @classmethod
    def purpose_is_bounded_printable_text(cls, value: str) -> str:
        if value != value.strip() or any(not character.isprintable() for character in value):
            raise ValueError("synthetic declaration purpose must be canonical printable text")
        return value

    @field_validator("files")
    @classmethod
    def files_are_sorted_and_unique(
        cls,
        value: tuple[_SyntheticDeclarationFile, ...],
    ) -> tuple[_SyntheticDeclarationFile, ...]:
        paths = tuple(item.path for item in value)
        if paths != tuple(sorted(set(paths))):
            raise ValueError("synthetic declaration files must be unique and sorted")
        return value


class _SyntheticSourceDeclaration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    entries: tuple[_SyntheticDeclarationEntry, ...] = Field(min_length=1, max_length=1_000)

    @field_validator("entries")
    @classmethod
    def entries_are_sorted_and_unique(
        cls,
        value: tuple[_SyntheticDeclarationEntry, ...],
    ) -> tuple[_SyntheticDeclarationEntry, ...]:
        scopes = tuple(item.scope for item in value)
        if scopes != tuple(sorted(set(scopes))):
            raise ValueError("synthetic declaration entries must be unique and sorted")
        return value


class PrivacySourceProvenanceEvidence(BaseModel):
    """Self-hashed evidence supporting the effective source classification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    source_classification: PrivacySourceClassificationValue
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    proof_kind: Literal[
        "PRIVATE_DEFAULT",
        "DISTRIBUTION_COMMITTED_SYNTHETIC",
        "PACKAGE_PINNED_SYNTHETIC",
    ]
    distribution_commit: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{40,64}$",
    )
    distribution_scope: str | None = Field(default=None, min_length=1, max_length=1_024)
    committed_file_count: int = Field(ge=0, le=_MAX_PROVENANCE_FILES)
    committed_file_inventory_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    synthetic_declaration_path: str | None = Field(
        default=None,
        min_length=1,
        max_length=1_024,
    )
    synthetic_declaration_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    synthetic_declaration_entry_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    observed_at: datetime
    limitations: tuple[str, ...] = Field(min_length=1, max_length=8)
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_whole_second_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
            raise ValueError("source provenance time must be whole-second UTC")
        return value

    @model_validator(mode="after")
    def evidence_is_coherent_and_self_hashed(self) -> Self:
        synthetic = self.proof_kind in {
            "DISTRIBUTION_COMMITTED_SYNTHETIC",
            "PACKAGE_PINNED_SYNTHETIC",
        }
        synthetic_values = (
            self.distribution_scope,
            self.committed_file_inventory_sha256,
            self.synthetic_declaration_path,
            self.synthetic_declaration_sha256,
            self.synthetic_declaration_entry_sha256,
        )
        if synthetic:
            if (
                self.source_classification != "SYNTHETIC_COMMITTED"
                or any(value is None for value in synthetic_values)
                or self.committed_file_count < 1
            ):
                raise ValueError("synthetic source provenance is incomplete")
            if (
                self.proof_kind == "DISTRIBUTION_COMMITTED_SYNTHETIC"
                and self.distribution_commit is None
            ):
                raise ValueError("committed synthetic provenance requires a commit")
            if (
                self.proof_kind == "PACKAGE_PINNED_SYNTHETIC"
                and self.distribution_commit is not None
            ):
                raise ValueError("package-pinned synthetic provenance cannot claim a commit")
        elif (
            self.source_classification != "PRIVATE_OPERATOR_SOURCE"
            or self.distribution_commit is not None
            or any(value is not None for value in synthetic_values)
            or self.committed_file_count
        ):
            raise ValueError("private source provenance cannot claim committed benchmark proof")
        if self.limitations != tuple(sorted(set(self.limitations))):
            raise ValueError("source provenance limitations must be unique and sorted")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected:
            raise ValueError("source provenance hash is inconsistent")
        return self


@dataclass(frozen=True, slots=True)
class _ProvenanceBinding:
    evidence: PrivacySourceProvenanceEvidence = field(repr=False, compare=False)
    evidence_sha256: str
    evidence_content_sha256: str


@dataclass(frozen=True, slots=True, init=False, eq=False, weakref_slot=True)
class PrivacySourceProvenanceObservation:
    """Opaque live observation issued only by the trusted provenance prover."""

    evidence: PrivacySourceProvenanceEvidence
    _issuer: object = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        evidence: PrivacySourceProvenanceEvidence,
        _issuer: object | None = None,
    ) -> None:
        if _issuer is not _TRUSTED_PROVENANCE_ISSUER:
            raise TypeError("source provenance observations are issued only by the trusted prover")
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "_issuer", _issuer)

    def __copy__(self) -> PrivacySourceProvenanceObservation:
        raise TypeError("source provenance observations cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> PrivacySourceProvenanceObservation:
        del memo
        raise TypeError("source provenance observations cannot be copied")

    def __reduce__(self) -> Any:
        raise TypeError("source provenance observations cannot be serialized")


_LIVE_PROVENANCE_OBSERVATIONS: weakref.WeakKeyDictionary[
    PrivacySourceProvenanceObservation,
    _ProvenanceBinding,
] = weakref.WeakKeyDictionary()


def prove_privacy_source_classification(
    discovery: DiscoveryResult,
    *,
    requested_classification: str,
    source_sha256: str,
    now: datetime,
) -> PrivacySourceProvenanceObservation:
    """Prove a safe effective classification for the exact provider-visible scope."""

    classification = _classification_value(requested_classification)
    if type(discovery) is not DiscoveryResult:
        raise ValueError("privacy source discovery must be typed")
    if classification is None:
        raise ValueError("privacy source classification must be typed")
    if re.fullmatch(_SHA256_PATTERN, source_sha256) is None:
        raise ValueError("privacy source inventory hash is invalid")
    observed_at = _whole_second_utc(now)
    expected_source_sha256 = _canonical_sha256(
        [
            {
                "path": item.relative_path,
                "sha256": item.sha256,
                "size": item.size,
            }
            for item in sorted(discovery.files, key=lambda candidate: candidate.relative_path)
        ]
    )
    if expected_source_sha256 != source_sha256:
        raise ValueError("privacy source provenance binds a different source inventory")

    if classification == "PRIVATE_OPERATOR_SOURCE":
        return _issue_observation(
            _seal(
                {
                    "schema_version": "1.0",
                    "source_classification": classification,
                    "source_sha256": source_sha256,
                    "proof_kind": "PRIVATE_DEFAULT",
                    "distribution_commit": None,
                    "distribution_scope": None,
                    "committed_file_count": 0,
                    "committed_file_inventory_sha256": None,
                    "synthetic_declaration_path": None,
                    "synthetic_declaration_sha256": None,
                    "synthetic_declaration_entry_sha256": None,
                    "observed_at": observed_at,
                    "limitations": (
                        "Private is the fail-closed default; no public or synthetic provenance is claimed.",
                    ),
                }
            )
        )
    if classification == "PUBLIC_BENCHMARK":
        raise ValueError(
            "PUBLIC_BENCHMARK requires independent publication provenance, which is unavailable"
        )
    if not discovery.files:
        raise ValueError("synthetic benchmark provenance requires a non-empty source scope")

    distribution_root = _distribution_root()
    target_root = discovery.root.resolve(strict=True)
    package_mode = _is_packaged_distribution(distribution_root)
    allowed_candidates = (
        (distribution_root / "resources" / "synthetic",)
        if package_mode
        else (
            distribution_root / "tests" / "fixtures",
            distribution_root / "benchmarks",
            distribution_root / "src" / "mmaudit" / "resources" / "synthetic",
        )
    )
    allowed_roots = tuple(
        candidate.resolve(strict=True)
        for candidate in allowed_candidates
        if candidate.is_dir() and not candidate.is_symlink()
    )
    if not any(target_root == root or target_root.is_relative_to(root) for root in allowed_roots):
        raise ValueError(
            "SYNTHETIC_COMMITTED requires a distribution-owned fixture or benchmark scope"
        )
    physical_scope = normalize_relative_path(target_root.relative_to(distribution_root))
    scope = f"src/mmaudit/{physical_scope}" if package_mode else physical_scope
    declaration_relative_path = (
        _PACKAGE_SYNTHETIC_DECLARATION_RELATIVE_PATH
        if package_mode
        else _SYNTHETIC_DECLARATION_RELATIVE_PATH
    )
    declaration_bytes = _read_bound_regular_file(
        distribution_root,
        declaration_relative_path,
        max_bytes=262_144,
    )
    declaration_sha256 = hashlib.sha256(declaration_bytes).hexdigest()
    if declaration_sha256 != _TRUSTED_SYNTHETIC_DECLARATION_SHA256:
        raise ValueError("trusted synthetic source declaration differs from its code-pinned hash")

    git: Path | None = None
    commit: str | None = None
    tree: dict[str, str] = {}
    if not package_mode:
        git = _trusted_git_executable()
        observed_top = Path(
            _decode_line(
                _run_git(git, distribution_root, ("rev-parse", "--show-toplevel")),
                label="Git worktree root",
            )
        ).resolve(strict=True)
        if observed_top != distribution_root:
            raise ValueError("synthetic benchmark provenance is not distribution-root bound")
        commit = _decode_line(
            _run_git(git, distribution_root, ("rev-parse", "--verify", "HEAD^{commit}")),
            label="Git commit",
        )
        if _GIT_OBJECT_PATTERN.fullmatch(commit) is None:
            raise ValueError("synthetic benchmark commit identity is malformed")
        if _run_git(
            git,
            distribution_root,
            (
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=all",
                "--",
                scope,
                _SYNTHETIC_DECLARATION_RELATIVE_PATH,
            ),
        ):
            raise ValueError("synthetic benchmark scope or declaration differs from committed HEAD")
        tree = _parse_tree(
            _run_git(
                git,
                distribution_root,
                (
                    "ls-tree",
                    "-r",
                    "-z",
                    "--full-tree",
                    commit,
                    "--",
                    scope,
                    _SYNTHETIC_DECLARATION_RELATIVE_PATH,
                ),
            )
        )
        declaration_object = tree.get(_SYNTHETIC_DECLARATION_RELATIVE_PATH)
        if declaration_object is None:
            raise ValueError("trusted synthetic source declaration is not committed")
        if (
            _read_git_blob(
                git,
                distribution_root,
                declaration_object,
                max_bytes=262_144,
            )
            != declaration_bytes
        ):
            raise ValueError("trusted synthetic source declaration differs from committed HEAD")
    try:
        declaration = _SyntheticSourceDeclaration.model_validate_json(
            declaration_bytes,
            strict=True,
        )
    except Exception:
        raise ValueError("trusted synthetic source declaration is invalid") from None
    declared_entry = next((entry for entry in declaration.entries if entry.scope == scope), None)
    if declared_entry is None:
        raise ValueError("synthetic benchmark scope is not explicitly approved")
    declared_by_path = {item.path: item for item in declared_entry.files}
    discovered_paths = tuple(
        sorted(normalize_relative_path(item.relative_path) for item in discovery.files)
    )
    if discovered_paths != tuple(declared_by_path):
        raise ValueError("provider-visible synthetic source differs from its approved declaration")

    records: list[dict[str, str | int]] = []
    observed_total_bytes = 0
    for item in sorted(discovery.files, key=lambda candidate: candidate.relative_path):
        relative_path = normalize_relative_path(item.relative_path)
        if relative_path != item.relative_path or relative_path in {"", "."}:
            raise ValueError("provider-visible synthetic source path is not canonical")
        expected_absolute_path = target_root / relative_path
        if Path(os.path.abspath(item.absolute_path)) != expected_absolute_path:
            raise ValueError("provider-visible synthetic source path binding is inconsistent")
        data = _read_bound_regular_file(
            target_root,
            relative_path,
            max_bytes=_MAX_PROVENANCE_FILE_BYTES,
        )
        observed_total_bytes += len(data)
        if observed_total_bytes > _MAX_PROVENANCE_TOTAL_BYTES:
            raise ValueError("synthetic benchmark source exceeds its aggregate byte bound")
        current_sha256 = hashlib.sha256(data).hexdigest()
        expected_content = data.decode("utf-8", errors="replace")
        if (
            item.size != len(data)
            or item.sha256 != current_sha256
            or item.content != expected_content
        ):
            raise ValueError("provider-visible synthetic source inventory is inconsistent")
        declared_file = declared_by_path[relative_path]
        if declared_file.size != len(data) or declared_file.sha256 != current_sha256:
            raise ValueError("provider-visible synthetic source violates its approved declaration")
        distribution_path = normalize_relative_path(
            expected_absolute_path.relative_to(distribution_root)
        )
        logical_distribution_path = (
            f"src/mmaudit/{distribution_path}" if package_mode else distribution_path
        )
        if git is None:
            expected_object = f"package-sha256:{current_sha256}"
        else:
            tree_object = tree.get(distribution_path)
            if tree_object is None:
                raise ValueError("provider-visible synthetic source is not committed")
            expected_object = tree_object
            committed_data = _read_git_blob(
                git,
                distribution_root,
                expected_object,
                max_bytes=_MAX_PROVENANCE_FILE_BYTES,
            )
            if committed_data != data:
                raise ValueError("provider-visible synthetic source differs from committed HEAD")
        records.append(
            {
                "path": logical_distribution_path,
                "sha256": current_sha256,
                "size": len(data),
                "git_object": expected_object,
            }
        )
    proof_kind = "PACKAGE_PINNED_SYNTHETIC" if package_mode else "DISTRIBUTION_COMMITTED_SYNTHETIC"
    limitations = (
        (
            "Package-pinned provenance proves exact reviewed bytes, but no runtime Git commit is available."
        )
        if package_mode
        else "Committed distribution provenance proves fixture custody, not real-world publication."
    )
    return _issue_observation(
        _seal(
            {
                "schema_version": "1.0",
                "source_classification": classification,
                "source_sha256": source_sha256,
                "proof_kind": proof_kind,
                "distribution_commit": commit,
                "distribution_scope": scope,
                "committed_file_count": len(records),
                "committed_file_inventory_sha256": _canonical_sha256(records),
                "synthetic_declaration_path": _SYNTHETIC_DECLARATION_RELATIVE_PATH,
                "synthetic_declaration_sha256": declaration_sha256,
                "synthetic_declaration_entry_sha256": _canonical_sha256(
                    declared_entry.model_dump(mode="json")
                ),
                "observed_at": observed_at,
                "limitations": (limitations,),
            }
        )
    )


def validate_privacy_source_provenance_observation(
    observation: PrivacySourceProvenanceObservation,
    *,
    source_sha256: str,
    source_classification: str,
) -> PrivacySourceProvenanceEvidence:
    """Return a fresh evidence snapshot only for a live exact provenance observation."""

    classification = _classification_value(source_classification)
    if classification is None:
        raise ValueError("privacy source classification must be typed")
    if re.fullmatch(_SHA256_PATTERN, source_sha256) is None:
        raise ValueError("privacy source inventory hash is invalid")
    if type(observation) is not PrivacySourceProvenanceObservation:
        raise ValueError("privacy source provenance observation is not trusted")
    with _PROVENANCE_LOCK:
        binding = _LIVE_PROVENANCE_OBSERVATIONS.get(observation)
    if (
        binding is None
        or observation._issuer is not _TRUSTED_PROVENANCE_ISSUER
        or observation.evidence is not binding.evidence
    ):
        raise ValueError("privacy source provenance observation was not issued in this process")
    try:
        validated = PrivacySourceProvenanceEvidence.model_validate(
            observation.evidence.model_dump(mode="python"),
            strict=True,
        )
    except Exception:
        raise ValueError("privacy source provenance observation binding is inconsistent") from None
    if (
        validated.evidence_sha256 != binding.evidence_sha256
        or _model_content_sha256(validated) != binding.evidence_content_sha256
        or validated.source_sha256 != source_sha256
        or validated.source_classification != classification
    ):
        raise ValueError("privacy source provenance observation binding is inconsistent")
    return validated


def _issue_observation(
    evidence: PrivacySourceProvenanceEvidence,
) -> PrivacySourceProvenanceObservation:
    observation = PrivacySourceProvenanceObservation(
        evidence=evidence,
        _issuer=_TRUSTED_PROVENANCE_ISSUER,
    )
    with _PROVENANCE_LOCK:
        _LIVE_PROVENANCE_OBSERVATIONS[observation] = _ProvenanceBinding(
            evidence=evidence,
            evidence_sha256=evidence.evidence_sha256,
            evidence_content_sha256=_model_content_sha256(evidence),
        )
    return observation


def _classification_value(value: object) -> PrivacySourceClassificationValue | None:
    from mmaudit.privacy import PrivacySourceClassification

    if type(value) is not PrivacySourceClassification:
        return None
    normalized = value.value
    if normalized not in {
        "PRIVATE_OPERATOR_SOURCE",
        "SYNTHETIC_COMMITTED",
        "PUBLIC_BENCHMARK",
    }:
        return None
    return cast(PrivacySourceClassificationValue, normalized)


def _read_bound_regular_file(root: Path, relative_path: str, *, max_bytes: int) -> bytes:
    """Read a regular single-link file beneath root without following links."""

    normalized = normalize_relative_path(relative_path)
    if normalized != relative_path or normalized in {"", "."}:
        raise ValueError("source provenance file path is not canonical")
    parts = Path(normalized).parts
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    opened_directories: list[int] = []
    try:
        descriptor = os.open(root, directory_flags | nofollow)
        opened_directories.append(descriptor)
        for part in parts[:-1]:
            descriptor = os.open(part, directory_flags | nofollow, dir_fd=descriptor)
            opened_directories.append(descriptor)
        file_descriptor = os.open(
            parts[-1],
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow,
            dir_fd=descriptor,
        )
    except (OSError, ValueError):
        for opened in reversed(opened_directories):
            os.close(opened)
        raise ValueError("source provenance file could not be opened safely") from None
    try:
        before = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > max_bytes
        ):
            raise ValueError("source provenance file metadata is unsafe")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(file_descriptor, min(remaining, 65_536))
            if not chunk:
                raise ValueError("source provenance file changed while it was read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(file_descriptor, 1):
            raise ValueError("source provenance file exceeds its declared byte size")
        after = os.fstat(file_descriptor)
        if _stat_identity(before) != _stat_identity(after):
            raise ValueError("source provenance file changed while it was read")
        return b"".join(chunks)
    except OSError:
        raise ValueError("source provenance file could not be read safely") from None
    finally:
        os.close(file_descriptor)
        for opened in reversed(opened_directories):
            os.close(opened)


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _distribution_root() -> Path:
    package_path = mmaudit.__file__
    if package_path is None:
        raise ValueError("executing mmaudit distribution is unavailable")
    try:
        package_root = Path(package_path).resolve(strict=True).parent
    except (IndexError, OSError):
        raise ValueError("executing mmaudit distribution is unavailable") from None
    source_root = package_root.parents[1] if len(package_root.parents) >= 2 else None
    source_package = source_root / "src" / "mmaudit" if source_root is not None else None
    root = (
        source_root
        if source_root is not None
        and source_package is not None
        and source_package.is_dir()
        and source_package.resolve(strict=True) == package_root
        and (source_root / ".git").exists()
        else package_root
    )
    if root.is_symlink() or not root.is_dir():
        raise ValueError("executing mmaudit distribution root is unsafe")
    return root


def _is_packaged_distribution(root: Path) -> bool:
    return (root / "resources").is_dir() and not (root / "src" / "mmaudit").is_dir()


def _trusted_git_executable() -> Path:
    for candidate in (Path("/usr/bin/git"), Path("/bin/git")):
        try:
            declared = candidate.lstat()
            resolved = candidate.resolve(strict=True)
            observed = resolved.stat()
        except OSError:
            continue
        if (
            not stat.S_ISLNK(declared.st_mode)
            and stat.S_ISREG(observed.st_mode)
            and observed.st_uid == 0
            and not stat.S_IMODE(observed.st_mode) & 0o022
        ):
            return resolved
    raise ValueError("fixed trusted Git executable is unavailable")


def _run_git(git: Path, root: Path, arguments: tuple[str, ...]) -> bytes:
    try:
        result = subprocess.run(
            [
                str(git),
                "--no-replace-objects",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "protocol.allow=never",
                "-c",
                "submodule.recurse=false",
                "-C",
                str(root),
                *arguments,
            ],
            check=False,
            capture_output=True,
            timeout=30,
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "TMPDIR": "/tmp",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
            },
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("trusted Git source provenance observation failed") from None
    if (
        result.returncode
        or result.stderr
        or len(result.stdout) > _MAX_GIT_OUTPUT_BYTES
        or len(result.stderr) > _MAX_GIT_OUTPUT_BYTES
    ):
        raise ValueError("trusted Git source provenance observation was rejected")
    return result.stdout


def _read_git_blob(
    git: Path,
    root: Path,
    object_id: str,
    *,
    max_bytes: int,
) -> bytes:
    if _GIT_OBJECT_PATTERN.fullmatch(object_id) is None:
        raise ValueError("trusted Git blob identity is malformed")
    raw_size = _decode_line(
        _run_git(git, root, ("cat-file", "-s", object_id)),
        label="Git blob size",
    )
    try:
        size = int(raw_size)
    except ValueError:
        raise ValueError("trusted Git blob size is malformed") from None
    if size < 0 or size > max_bytes:
        raise ValueError("trusted Git blob exceeds its byte bound")
    content = _run_git(git, root, ("cat-file", "blob", object_id))
    if len(content) != size:
        raise ValueError("trusted Git blob size is inconsistent")
    return content


def _parse_tree(value: bytes) -> dict[str, str]:
    if not value or not value.endswith(b"\0") or b"\0\0" in value:
        raise ValueError("synthetic benchmark Git tree is empty or malformed")
    records = value[:-1].split(b"\0")
    if len(records) > _MAX_PROVENANCE_FILES:
        raise ValueError("synthetic benchmark Git tree exceeds its file bound")
    result: dict[str, str] = {}
    for record in records:
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, kind, object_id = header.decode("ascii", errors="strict").split(" ")
            path = raw_path.decode("utf-8", errors="strict")
        except (UnicodeError, ValueError):
            raise ValueError("synthetic benchmark Git tree is malformed") from None
        normalized = normalize_relative_path(path)
        if (
            kind != "blob"
            or mode not in {"100644", "100755"}
            or _GIT_OBJECT_PATTERN.fullmatch(object_id) is None
            or normalized != path
            or path in result
        ):
            raise ValueError("synthetic benchmark Git tree contains an unsafe entry")
        result[path] = object_id
    return result


def _decode_line(value: bytes, *, label: str) -> str:
    try:
        decoded = value.decode("ascii", errors="strict")
    except UnicodeError:
        raise ValueError(f"{label} output is malformed") from None
    if not decoded.endswith("\n") or decoded.count("\n") != 1:
        raise ValueError(f"{label} output is malformed")
    return decoded[:-1]


def _whole_second_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
        raise ValueError("source provenance time must be whole-second UTC")
    return value


def _seal(payload: dict[str, object]) -> PrivacySourceProvenanceEvidence:
    return PrivacySourceProvenanceEvidence.model_validate(
        {**payload, "evidence_sha256": _canonical_sha256(payload)}
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=_json_default,
        ).encode("utf-8")
    ).hexdigest()


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def _model_content_sha256(value: BaseModel) -> str:
    return _canonical_sha256(value.model_dump(mode="json"))
