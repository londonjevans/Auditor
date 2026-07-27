"""Checksum-bound offline dependency preparation for isolated JavaScript builds."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import shutil
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from mmaudit.config import DependencyPreparationConfig
from mmaudit.models.schemas import (
    DependencyAdvisoryFinding,
    DependencyPackageEvidence,
    DependencyPreparationResult,
    DependencyPreparationStatus,
    DependencySbom,
    DependencySbomComponent,
    DependencyScanStatus,
    Severity,
    SolidityProjectMetadata,
    SolidityProjectType,
)
from mmaudit.repository.secrets import is_sensitive_workspace_path

_LIFECYCLE_SCRIPTS = frozenset(
    {
        "install",
        "postinstall",
        "postpack",
        "preinstall",
        "prepack",
        "prepare",
        "prepublish",
        "prepublishonly",
    }
)
_UNSAFE_BINARY_SUFFIXES = frozenset(
    {
        ".dll",
        ".dylib",
        ".exe",
        ".node",
        ".so",
        ".tar",
        ".tgz",
        ".zip",
    }
)
_PRIVATE_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_INTEGRITY = re.compile(r"^sha512-([A-Za-z0-9+/]+={0,2})$")
_MAX_PACKAGE_JSON_BYTES = 1_000_000


class _SnapshotModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _SnapshotPackage(_SnapshotModel):
    lock_path: str
    name: str
    version: str
    source: str
    tree_sha256: str

    @field_validator("lock_path")
    @classmethod
    def lock_path_is_a_node_modules_entry(cls, value: str) -> str:
        normalized = _safe_relative(value)
        if not normalized.startswith("node_modules/"):
            raise ValueError("snapshot lock path must identify a node_modules entry")
        _npm_name_from_lock_path(normalized)
        return normalized

    @field_validator("source")
    @classmethod
    def source_is_a_dedicated_package_directory(cls, value: str) -> str:
        normalized = _safe_relative(value)
        if not normalized.startswith("packages/"):
            raise ValueError("snapshot package source must remain below packages/")
        return normalized.rstrip("/")

    @field_validator("name")
    @classmethod
    def name_is_a_safe_npm_identifier(cls, value: str) -> str:
        if not _NPM_NAME.fullmatch(value):
            raise ValueError("snapshot package name is not a safe npm identifier")
        return value

    @field_validator("version")
    @classmethod
    def version_is_bounded(cls, value: str) -> str:
        if not _VERSION.fullmatch(value):
            raise ValueError("snapshot package version is not a bounded exact value")
        return value

    @field_validator("tree_sha256")
    @classmethod
    def tree_hash_is_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("snapshot package tree hash must be lowercase sha256")
        return value


class _SnapshotProject(_SnapshotModel):
    project_root: str
    lockfile: Literal["package-lock.json"]
    lockfile_sha256: str
    packages: list[_SnapshotPackage] = Field(min_length=1, max_length=10_000)

    @field_validator("project_root")
    @classmethod
    def project_root_is_safe(cls, value: str) -> str:
        return "." if value in {"", "."} else _safe_relative(value).rstrip("/")

    @field_validator("lockfile_sha256")
    @classmethod
    def lock_hash_is_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("snapshot lockfile hash must be lowercase sha256")
        return value

    @model_validator(mode="after")
    def packages_are_unique(self) -> _SnapshotProject:
        lock_paths = [package.lock_path for package in self.packages]
        sources = [package.source for package in self.packages]
        if lock_paths != sorted(set(lock_paths)):
            raise ValueError("snapshot package lock paths must be unique and sorted")
        if len(sources) != len(set(sources)):
            raise ValueError("snapshot package source paths must be unique")
        return self


class _SnapshotAdvisory(_SnapshotModel):
    advisory_id: str = Field(min_length=1, max_length=200)
    package_name: str
    versions: list[str] = Field(min_length=1, max_length=1_000)
    severity: Severity
    summary: str = Field(min_length=1, max_length=2_000)

    @field_validator("package_name")
    @classmethod
    def package_name_is_safe(cls, value: str) -> str:
        if not _NPM_NAME.fullmatch(value):
            raise ValueError("advisory package name is not a safe npm identifier")
        return value

    @field_validator("versions")
    @classmethod
    def versions_are_exact_and_unique(cls, values: list[str]) -> list[str]:
        if values != sorted(set(values)) or any(not _VERSION.fullmatch(value) for value in values):
            raise ValueError("advisory versions must be unique sorted exact values")
        return values


class _DependencySnapshot(_SnapshotModel):
    schema_version: Literal["1.0"]
    projects: list[_SnapshotProject] = Field(min_length=1, max_length=200)
    advisories: list[_SnapshotAdvisory] = Field(default_factory=list, max_length=20_000)

    @model_validator(mode="after")
    def projects_and_advisories_are_unique(self) -> _DependencySnapshot:
        roots = [project.project_root for project in self.projects]
        if roots != sorted(set(roots)):
            raise ValueError("snapshot project roots must be unique and sorted")
        advisory_ids = [advisory.advisory_id for advisory in self.advisories]
        if advisory_ids != sorted(set(advisory_ids)):
            raise ValueError("snapshot advisory IDs must be unique and sorted")
        return self


@dataclass(frozen=True)
class _InventoryFile:
    relative_path: str
    source_path: Path
    sha256: str
    size: int


@dataclass(frozen=True)
class _ValidatedPackage:
    evidence: DependencyPackageEvidence
    files: tuple[_InventoryFile, ...]


@dataclass(frozen=True)
class DependencyPreparationRun:
    """Serializable results plus private roots consumable by isolated compilers."""

    results: list[DependencyPreparationResult]
    sboms: list[DependencySbom]
    prepared_roots: dict[str, Path]


class _PreparationRejected(ValueError):
    def __init__(
        self,
        message: str,
        *,
        checks: dict[str, bool] | None = None,
        scan_status: DependencyScanStatus = DependencyScanStatus.NOT_RUN,
    ) -> None:
        super().__init__(message)
        self.safe_message = message
        self.checks = checks or {}
        self.scan_status = scan_status


def prepare_dependencies(
    repository_root: Path,
    projects: list[SolidityProjectMetadata],
    config: DependencyPreparationConfig,
    private_dir: Path,
) -> DependencyPreparationRun:
    """Prepare checksum-bound npm dependencies without network or package execution."""

    targets = sorted(
        (project for project in projects if _project_uses_hardhat(project)),
        key=lambda project: project.project_root,
    )
    if not config.enabled:
        return DependencyPreparationRun(
            results=[
                DependencyPreparationResult(
                    status=DependencyPreparationStatus.DISABLED,
                    project_root=project.project_root,
                    errors=["dependency preparation disabled by configuration"],
                )
                for project in targets
            ],
            sboms=[],
            prepared_roots={},
        )
    if not targets:
        return DependencyPreparationRun(
            results=[
                DependencyPreparationResult(
                    status=DependencyPreparationStatus.NOT_APPLICABLE,
                    project_root=".",
                    errors=["no Hardhat project requires npm dependency preparation"],
                )
            ],
            sboms=[],
            prepared_roots={},
        )
    if len(targets) > config.max_projects:
        return _batch_rejected(
            targets,
            "dependency project count exceeds the configured limit",
        )
    try:
        snapshot_path, snapshot, snapshot_sha256 = _load_snapshot(
            repository_root,
            config,
        )
    except _PreparationRejected as exc:
        return _batch_rejected(targets, exc.safe_message, checks=exc.checks)
    except (OSError, UnicodeError, ValidationError, json.JSONDecodeError, ValueError) as exc:
        return _batch_failed(
            targets,
            f"offline dependency snapshot could not be loaded: {type(exc).__name__}",
        )

    target_roots = [project.project_root for project in targets]
    snapshot_roots = [project.project_root for project in snapshot.projects]
    if snapshot_roots != target_roots:
        return _batch_rejected(
            targets,
            "offline dependency snapshot project set does not match detected Hardhat projects",
            checks={"snapshot_sha256": True, "project_set": False},
            snapshot_sha256=snapshot_sha256,
        )

    private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if private_dir.is_symlink() or private_dir.is_junction():
        return _batch_failed(targets, "dependency preparation directory may not be a link")
    private_root = private_dir.resolve(strict=True)
    results: list[DependencyPreparationResult] = []
    sboms: list[DependencySbom] = []
    prepared_roots: dict[str, Path] = {}
    snapshot_by_root = {project.project_root: project for project in snapshot.projects}
    for project in targets:
        try:
            result, sbom, prepared_root = _prepare_project(
                repository_root=repository_root,
                project=project,
                snapshot_project=snapshot_by_root[project.project_root],
                advisories=snapshot.advisories,
                snapshot_path=snapshot_path,
                snapshot_sha256=snapshot_sha256,
                private_root=private_root,
                config=config,
            )
        except _PreparationRejected as exc:
            result = DependencyPreparationResult(
                status=DependencyPreparationStatus.REJECTED,
                project_root=project.project_root,
                snapshot_sha256=snapshot_sha256,
                scan_status=exc.scan_status,
                checks=exc.checks,
                errors=[exc.safe_message],
            )
            sbom = None
            prepared_root = None
        except (OSError, UnicodeError, ValidationError, json.JSONDecodeError, ValueError) as exc:
            result = DependencyPreparationResult(
                status=DependencyPreparationStatus.FAILED,
                project_root=project.project_root,
                snapshot_sha256=snapshot_sha256,
                errors=[f"dependency preparation failed safely: {type(exc).__name__}"],
            )
            sbom = None
            prepared_root = None
        results.append(result)
        if sbom is not None:
            sboms.append(sbom)
        if prepared_root is not None:
            prepared_roots[project.project_root] = prepared_root
    return DependencyPreparationRun(
        results=results,
        sboms=sboms,
        prepared_roots=prepared_roots,
    )


def dependency_tree_sha256(
    package_root: Path,
    *,
    max_files: int = 100_000,
    max_file_bytes: int = 10_000_000,
    max_total_bytes: int = 1_000_000_000,
) -> str:
    """Return the canonical digest used to bind one unpacked offline package."""

    files = _inventory_dependency_tree(
        package_root,
        max_files=max_files,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
    )
    return _inventory_hash(files)


def _project_uses_hardhat(project: SolidityProjectMetadata) -> bool:
    return project.project_type is SolidityProjectType.HARDHAT or any(
        PurePosixPath(path).name.lower()
        in {
            "hardhat.config.cjs",
            "hardhat.config.js",
            "hardhat.config.mjs",
            "hardhat.config.ts",
        }
        for path in project.framework_config_files
    )


def _load_snapshot(
    repository_root: Path,
    config: DependencyPreparationConfig,
) -> tuple[Path, _DependencySnapshot, str]:
    configured = config.offline_snapshot_path
    expected_sha256 = config.offline_snapshot_sha256
    if configured is None or expected_sha256 is None:
        raise _PreparationRejected(
            "dependency preparation requires a checksum-pinned offline snapshot",
            checks={"snapshot_sha256": False},
        )
    root = repository_root.resolve(strict=True)
    relative = PurePosixPath(_safe_relative(configured))
    candidate = root
    for part in relative.parts:
        candidate = candidate / part
        if candidate.is_symlink() or candidate.is_junction():
            raise _PreparationRejected(
                "offline dependency snapshot path may not traverse links",
                checks={"snapshot_sha256": False},
            )
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(root)
    if not resolved.is_file() or resolved.stat().st_nlink != 1:
        raise _PreparationRejected(
            "offline dependency snapshot must be a unique regular file",
            checks={"snapshot_sha256": False},
        )
    if resolved.stat().st_size > config.max_snapshot_bytes:
        raise _PreparationRejected(
            "offline dependency snapshot exceeds the configured byte limit",
            checks={"snapshot_sha256": False},
        )
    raw = resolved.read_bytes()
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != expected_sha256:
        raise _PreparationRejected(
            "offline dependency snapshot SHA-256 does not match configuration",
            checks={"snapshot_sha256": False},
        )
    payload = json.loads(raw.decode("utf-8"))
    return resolved, _DependencySnapshot.model_validate(payload), actual_sha256


def _prepare_project(
    *,
    repository_root: Path,
    project: SolidityProjectMetadata,
    snapshot_project: _SnapshotProject,
    advisories: list[_SnapshotAdvisory],
    snapshot_path: Path,
    snapshot_sha256: str,
    private_root: Path,
    config: DependencyPreparationConfig,
) -> tuple[DependencyPreparationResult, DependencySbom | None, Path | None]:
    checks = {
        "snapshot_sha256": True,
        "project_set": True,
        "lockfile_sha256": False,
        "lockfile_integrity": False,
        "package_tree_sha256": False,
        "lifecycle_scripts_disabled": False,
        "offline_advisory_scan": False,
        "bounded_copy": False,
    }
    repository = repository_root.resolve(strict=True)
    project_root = (
        repository
        if project.project_root == "."
        else _resolve_contained_directory(repository, project.project_root)
    )
    _reject_lifecycle_scripts(
        _read_package_json(project_root / "package.json"),
        checks=checks,
    )
    lockfile = _resolve_unique_file(project_root, snapshot_project.lockfile)
    if lockfile.stat().st_size > config.max_snapshot_bytes:
        raise _PreparationRejected(
            "package lockfile exceeds the configured byte limit",
            checks=checks,
        )
    lock_bytes = lockfile.read_bytes()
    lockfile_sha256 = hashlib.sha256(lock_bytes).hexdigest()
    if lockfile_sha256 != snapshot_project.lockfile_sha256:
        raise _PreparationRejected(
            "package lockfile SHA-256 does not match the offline snapshot",
            checks=checks,
        )
    checks["lockfile_sha256"] = True
    lock_packages = _load_lock_packages(lock_bytes, config.max_packages)
    snapshot_packages = {package.lock_path: package for package in snapshot_project.packages}
    if set(lock_packages) != set(snapshot_packages):
        raise _PreparationRejected(
            "offline snapshot package set does not match package-lock.json",
            checks=checks,
        )
    if len(snapshot_packages) > config.max_packages:
        raise _PreparationRejected(
            "dependency package count exceeds the configured limit",
            checks=checks,
        )

    validated: list[_ValidatedPackage] = []
    total_files = 0
    total_bytes = 0
    for lock_path in sorted(snapshot_packages):
        package = snapshot_packages[lock_path]
        lock_entry = lock_packages[lock_path]
        integrity = _lock_integrity(lock_entry)
        lock_version = lock_entry.get("version")
        if (
            not isinstance(lock_version, str)
            or lock_version != package.version
            or _npm_name_from_lock_path(lock_path) != package.name
        ):
            raise _PreparationRejected(
                "offline package identity does not match package-lock.json",
                checks=checks,
            )
        source = _resolve_contained_directory(snapshot_path.parent, package.source)
        files = _inventory_dependency_tree(
            source,
            max_files=config.max_files,
            max_file_bytes=config.max_file_bytes,
            max_total_bytes=config.max_total_bytes,
        )
        total_files += len(files)
        total_bytes += sum(item.size for item in files)
        if total_files > config.max_files or total_bytes > config.max_total_bytes:
            raise _PreparationRejected(
                "dependency snapshot exceeds aggregate copy limits",
                checks=checks,
            )
        package_json = _read_inventory_package_json(files)
        if (
            package_json.get("name") != package.name
            or package_json.get("version") != package.version
        ):
            raise _PreparationRejected(
                "offline package manifest identity does not match its snapshot entry",
                checks=checks,
            )
        _reject_lifecycle_scripts(package_json, checks=checks)
        actual_tree_hash = _inventory_hash(files)
        if actual_tree_hash != package.tree_sha256:
            raise _PreparationRejected(
                "offline package tree SHA-256 does not match its snapshot entry",
                checks=checks,
            )
        purl = _npm_purl(package.name, package.version)
        validated.append(
            _ValidatedPackage(
                evidence=DependencyPackageEvidence(
                    name=package.name,
                    version=package.version,
                    lock_path=package.lock_path,
                    integrity=integrity,
                    tree_sha256=actual_tree_hash,
                    purl=purl,
                    file_count=len(files),
                    total_bytes=sum(item.size for item in files),
                ),
                files=files,
            )
        )
    checks["lockfile_integrity"] = True
    checks["package_tree_sha256"] = True
    checks["lifecycle_scripts_disabled"] = True
    findings = _scan_advisories(validated, advisories)
    sbom = _build_sbom(
        project_root=project.project_root,
        lockfile_sha256=lockfile_sha256,
        snapshot_sha256=snapshot_sha256,
        packages=validated,
    )
    if findings:
        checks["offline_advisory_scan"] = False
        return (
            DependencyPreparationResult(
                status=DependencyPreparationStatus.REJECTED,
                project_root=project.project_root,
                lockfile_path=_repository_relative(repository, lockfile),
                lockfile_sha256=lockfile_sha256,
                snapshot_sha256=snapshot_sha256,
                packages=[package.evidence for package in validated],
                scan_status=DependencyScanStatus.FAILED,
                scan_findings=findings,
                checks=checks,
                errors=["offline dependency advisory scan rejected the prepared package set"],
            ),
            sbom,
            None,
        )
    checks["offline_advisory_scan"] = True
    prepared_root = _copy_validated_packages(
        validated,
        private_root=private_root,
        project_root=project.project_root,
    )
    checks["bounded_copy"] = True
    copied_files = sum(package.evidence.file_count for package in validated)
    copied_bytes = sum(package.evidence.total_bytes for package in validated)
    return (
        DependencyPreparationResult(
            status=DependencyPreparationStatus.PREPARED,
            project_root=project.project_root,
            lockfile_path=_repository_relative(repository, lockfile),
            lockfile_sha256=lockfile_sha256,
            snapshot_sha256=snapshot_sha256,
            packages=[package.evidence for package in validated],
            scan_status=DependencyScanStatus.PASSED,
            checks=checks,
            copied_files=copied_files,
            copied_bytes=copied_bytes,
            prepared_path=prepared_root.relative_to(private_root.parent).as_posix(),
        ),
        sbom,
        prepared_root,
    )


def _load_lock_packages(raw: bytes, max_packages: int) -> dict[str, dict[str, object]]:
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or payload.get("lockfileVersion") not in {2, 3}:
        raise _PreparationRejected("only npm package-lock schema versions 2 and 3 are supported")
    packages = payload.get("packages")
    if not isinstance(packages, dict):
        raise _PreparationRejected("package-lock.json lacks a packages map")
    result: dict[str, dict[str, object]] = {}
    for raw_path, raw_entry in packages.items():
        if raw_path == "":
            continue
        if not isinstance(raw_path, str) or not isinstance(raw_entry, dict):
            raise _PreparationRejected("package-lock.json contains an invalid package entry")
        lock_path = _safe_relative(raw_path)
        if not lock_path.startswith("node_modules/") or raw_entry.get("link") is True:
            raise _PreparationRejected(
                "package-lock.json contains an unsupported linked or non-package entry"
            )
        _npm_name_from_lock_path(lock_path)
        result[lock_path] = raw_entry
        if len(result) > max_packages:
            raise _PreparationRejected("package-lock.json exceeds the configured package limit")
    if not result:
        raise _PreparationRejected("package-lock.json contains no prepared dependencies")
    return result


def _lock_integrity(entry: dict[str, object]) -> str:
    integrity = entry.get("integrity")
    if not isinstance(integrity, str):
        raise _PreparationRejected("every locked package requires sha512 integrity")
    match = _INTEGRITY.fullmatch(integrity)
    if match is None:
        raise _PreparationRejected("every locked package requires sha512 integrity")
    try:
        decoded = base64.b64decode(match.group(1), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _PreparationRejected("package-lock integrity is not valid base64") from exc
    if len(decoded) != 64:
        raise _PreparationRejected("package-lock integrity must contain a sha512 digest")
    return integrity


def _inventory_dependency_tree(
    package_root: Path,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> tuple[_InventoryFile, ...]:
    root = package_root.resolve(strict=True)
    if not root.is_dir() or root.is_symlink() or root.is_junction():
        raise _PreparationRejected("offline package source must be a regular directory")
    inventory: list[_InventoryFile] = []
    total_bytes = 0
    try:
        candidates = sorted(root.rglob("*"), key=lambda path: path.as_posix())
    except OSError as exc:
        raise _PreparationRejected("offline package source could not be enumerated") from exc
    for candidate in candidates:
        if candidate.is_symlink() or candidate.is_junction():
            raise _PreparationRejected("offline package source may not contain links")
        if candidate.is_dir():
            continue
        if not candidate.is_file() or candidate.stat().st_nlink != 1:
            raise _PreparationRejected(
                "offline package source must contain unique regular files only"
            )
        relative = candidate.relative_to(root)
        if is_sensitive_workspace_path(relative):
            raise _PreparationRejected("offline package source contains a sensitive filename")
        size = candidate.stat().st_size
        if size > max_file_bytes:
            raise _PreparationRejected("offline package file exceeds the configured byte limit")
        total_bytes += size
        if len(inventory) + 1 > max_files or total_bytes > max_total_bytes:
            raise _PreparationRejected("offline package tree exceeds configured copy limits")
        data = candidate.read_bytes()
        _reject_unsafe_dependency_file(candidate, data)
        inventory.append(
            _InventoryFile(
                relative_path=relative.as_posix(),
                source_path=candidate,
                sha256=hashlib.sha256(data).hexdigest(),
                size=size,
            )
        )
    if not inventory or not any(item.relative_path == "package.json" for item in inventory):
        raise _PreparationRejected("offline package source lacks package.json")
    return tuple(inventory)


def _reject_unsafe_dependency_file(path: Path, data: bytes) -> None:
    mode = path.stat().st_mode
    if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise _PreparationRejected("offline dependency contains an executable file")
    lower_name = path.name.lower()
    if (
        any(lower_name.endswith(suffix) for suffix in _UNSAFE_BINARY_SUFFIXES)
        or data.startswith((b"\x7fELF", b"MZ"))
        or any(marker in data for marker in _PRIVATE_KEY_MARKERS)
    ):
        raise _PreparationRejected(
            "offline dependency contains a binary, archive, or private-key payload"
        )


def _inventory_hash(files: tuple[_InventoryFile, ...]) -> str:
    digest = hashlib.sha256(b"mmaudit-dependency-tree-v1\0")
    for item in files:
        digest.update(item.relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(item.sha256))
        digest.update(b"\0")
    return digest.hexdigest()


def _read_inventory_package_json(files: tuple[_InventoryFile, ...]) -> dict[str, object]:
    package_file = next(item for item in files if item.relative_path == "package.json")
    if package_file.size > _MAX_PACKAGE_JSON_BYTES:
        raise _PreparationRejected("offline dependency package.json exceeds its byte limit")
    payload = json.loads(package_file.source_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise _PreparationRejected("offline dependency package.json must be an object")
    return payload


def _read_package_json(path: Path) -> dict[str, object]:
    resolved = _resolve_unique_file(path.parent.resolve(strict=True), path.name)
    if resolved.stat().st_size > _MAX_PACKAGE_JSON_BYTES:
        raise _PreparationRejected("project package.json exceeds its byte limit")
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise _PreparationRejected("project package.json must be an object")
    return payload


def _reject_lifecycle_scripts(
    package_json: dict[str, object],
    *,
    checks: dict[str, bool],
) -> None:
    scripts = package_json.get("scripts", {})
    if scripts is None:
        return
    if not isinstance(scripts, dict):
        raise _PreparationRejected(
            "package scripts must be an object",
            checks=checks,
            scan_status=DependencyScanStatus.FAILED,
        )
    if _LIFECYCLE_SCRIPTS & {str(name).casefold() for name in scripts}:
        checks["lifecycle_scripts_disabled"] = False
        raise _PreparationRejected(
            "dependency lifecycle scripts are prohibited during preparation",
            checks=checks,
            scan_status=DependencyScanStatus.FAILED,
        )


def _scan_advisories(
    packages: list[_ValidatedPackage],
    advisories: list[_SnapshotAdvisory],
) -> list[DependencyAdvisoryFinding]:
    affected = {
        (advisory.package_name, version): advisory
        for advisory in advisories
        for version in advisory.versions
    }
    findings = []
    for package in packages:
        advisory = affected.get((package.evidence.name, package.evidence.version))
        if advisory is None:
            continue
        findings.append(
            DependencyAdvisoryFinding(
                advisory_id=advisory.advisory_id,
                package_name=package.evidence.name,
                version=package.evidence.version,
                severity=advisory.severity,
                summary=advisory.summary,
            )
        )
    return sorted(findings, key=lambda finding: finding.advisory_id)


def _copy_validated_packages(
    packages: list[_ValidatedPackage],
    *,
    private_root: Path,
    project_root: str,
) -> Path:
    digest = hashlib.sha256(project_root.encode("utf-8")).hexdigest()[:12]
    project_private = private_root / digest
    staging = project_private / "node_modules.staging"
    destination = project_private / "node_modules"
    if staging.exists() or destination.exists():
        raise _PreparationRejected("dependency preparation destination already exists")
    staging.mkdir(mode=0o700, parents=True)
    try:
        for package in packages:
            relative_package = PurePosixPath(package.evidence.lock_path).relative_to("node_modules")
            package_destination = staging.joinpath(*relative_package.parts)
            package_destination.mkdir(mode=0o700, parents=True, exist_ok=True)
            for item in package.files:
                data = item.source_path.read_bytes()
                if len(data) != item.size or hashlib.sha256(data).hexdigest() != item.sha256:
                    raise _PreparationRejected(
                        "offline dependency changed after checksum validation"
                    )
                relative_file = PurePosixPath(item.relative_path)
                output = package_destination.joinpath(*relative_file.parts)
                output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with output.open("xb") as handle:
                    handle.write(data)
                output.chmod(0o600)
        staging.rename(destination)
    except (OSError, _PreparationRejected):
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return destination


def _build_sbom(
    *,
    project_root: str,
    lockfile_sha256: str,
    snapshot_sha256: str,
    packages: list[_ValidatedPackage],
) -> DependencySbom:
    components = sorted(
        (
            DependencySbomComponent(
                bom_ref=(f"{package.evidence.purl}#{quote(package.evidence.lock_path, safe='')}"),
                name=package.evidence.name,
                version=package.evidence.version,
                purl=package.evidence.purl,
                sha256=package.evidence.tree_sha256,
                integrity=package.evidence.integrity,
            )
            for package in packages
        ),
        key=lambda component: component.bom_ref,
    )
    serial_seed = hashlib.sha256(
        f"{project_root}\0{lockfile_sha256}\0{snapshot_sha256}".encode()
    ).hexdigest()
    serial = uuid.UUID(hex=serial_seed[:32])
    return DependencySbom(
        serial_number=f"urn:uuid:{serial}",
        project_root=project_root,
        lockfile_sha256=lockfile_sha256,
        snapshot_sha256=snapshot_sha256,
        components=components,
    )


def _batch_rejected(
    projects: list[SolidityProjectMetadata],
    error: str,
    *,
    checks: dict[str, bool] | None = None,
    snapshot_sha256: str | None = None,
) -> DependencyPreparationRun:
    return DependencyPreparationRun(
        results=[
            DependencyPreparationResult(
                status=DependencyPreparationStatus.REJECTED,
                project_root=project.project_root,
                snapshot_sha256=snapshot_sha256,
                checks=checks or {},
                errors=[error],
            )
            for project in projects
        ],
        sboms=[],
        prepared_roots={},
    )


def _batch_failed(
    projects: list[SolidityProjectMetadata],
    error: str,
) -> DependencyPreparationRun:
    return DependencyPreparationRun(
        results=[
            DependencyPreparationResult(
                status=DependencyPreparationStatus.FAILED,
                project_root=project.project_root,
                errors=[error],
            )
            for project in projects
        ],
        sboms=[],
        prepared_roots={},
    )


def _resolve_contained_directory(root: Path, relative: str) -> Path:
    resolved_root = root.resolve(strict=True)
    candidate = resolved_root
    for part in PurePosixPath(_safe_relative(relative)).parts:
        candidate = candidate / part
        if candidate.is_symlink() or candidate.is_junction():
            raise _PreparationRejected("dependency path may not traverse links")
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(resolved_root)
    if not resolved.is_dir():
        raise _PreparationRejected("dependency path must identify a directory")
    return resolved


def _resolve_unique_file(root: Path, relative: str) -> Path:
    resolved_root = root.resolve(strict=True)
    candidate = resolved_root
    for part in PurePosixPath(_safe_relative(relative)).parts:
        candidate = candidate / part
        if candidate.is_symlink() or candidate.is_junction():
            raise _PreparationRejected("dependency file path may not traverse links")
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(resolved_root)
    if not resolved.is_file() or resolved.stat().st_nlink != 1:
        raise _PreparationRejected("dependency input must be a unique regular file")
    return resolved


def _safe_relative(value: str) -> str:
    if (
        not value
        or "\\" in value
        or value.startswith(("/", "-"))
        or re.match(r"^[A-Za-z]:", value)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("dependency path is not a safe relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("dependency path is not a safe relative path")
    return path.as_posix()


def _npm_name_from_lock_path(lock_path: str) -> str:
    parts = PurePosixPath(lock_path).parts
    indices = [index for index, part in enumerate(parts) if part == "node_modules"]
    if not indices:
        raise ValueError("lock path is not below node_modules")
    tail = parts[indices[-1] + 1 :]
    if len(tail) == 1:
        name = tail[0]
    elif len(tail) == 2 and tail[0].startswith("@"):
        name = f"{tail[0]}/{tail[1]}"
    else:
        raise ValueError("lock path does not identify exactly one npm package")
    if not _NPM_NAME.fullmatch(name):
        raise ValueError("lock path contains an unsafe npm package name")
    return name


def _npm_purl(name: str, version: str) -> str:
    return f"pkg:npm/{quote(name, safe='/')}@{quote(version, safe='')}"


def _repository_relative(repository_root: Path, path: Path) -> str:
    return path.resolve(strict=True).relative_to(repository_root).as_posix()
