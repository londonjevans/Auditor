"""Offline materialization of declared host files; never installed-closure authority."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.config import AuditConfig, canonical_audit_config_json, parse_canonical_audit_config
from mmaudit.orchestration.managed_toolchain import (
    MANAGED_TOOLCHAIN_ROLE_SPECS,
    ManagedToolchainBundle,
    ManagedToolchainDisposition,
    ManagedToolchainMember,
    ManagedToolchainMemberKind,
    ManagedToolchainRole,
    derive_managed_toolchain_config,
    preflight_managed_toolchain_config,
)
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release_io import copy_file_evidence, read_json_evidence, write_json_evidence
from mmaudit.reporting.json_report import stable_json
from mmaudit.scanners import base as scanner_base

_SHA256 = r"^[0-9a-f]{64}$"
_MANIFEST_NAME = "host-tool-material.json"
_MAX_MANIFEST_BYTES = 1_000_000
_ROLE_SPECS = {spec.role: spec for spec in MANAGED_TOOLCHAIN_ROLE_SPECS}
_AUTHORITY_FIELDS = (
    "independently_trusted",
    "installed_members_verified",
    "architecture_verified",
    "transitive_dependency_closure_verified",
    "image_side_attestation_verified",
    "execution_evidence_verified",
    "runtime_authority",
    "managed_run_ready",
)


class ManagedHostToolError(ValueError):
    """Local tool material was refused; any partial output must not be consumed."""


class _FrozenHostModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        del deep
        values = self.model_dump(mode="python")
        if update is not None:
            values.update(update)
        return type(self).model_validate(values, strict=True)


class ManagedHostToolLimits(_FrozenHostModel):
    """Bound disk material independently of model or subprocess budgets."""

    max_file_bytes: int = Field(default=512 * 1024**2, ge=1, le=4 * 1024**3)
    max_total_bytes: int = Field(default=4 * 1024**3, ge=1, le=8 * 1024**3)


class ManagedHostToolSource(_FrozenHostModel):
    """An explicit local blob store; no PATH, URL, package manager or script resolution."""

    blob_root: Path | None = None
    limits: ManagedHostToolLimits = Field(default_factory=ManagedHostToolLimits)

    @field_validator("blob_root")
    @classmethod
    def root_is_absolute(cls, value: Path | None) -> Path | None:
        if value is not None and (not value.is_absolute() or ".." in value.parts):
            raise ValueError("host-tool blob root must be an absolute direct local path")
        return value


def _host_file_schema(schema: dict[str, Any]) -> None:
    """Keep exported JSON validation aligned with the closed host-role/locator join."""

    schema["oneOf"] = [
        {
            "properties": {
                "role": {"const": spec.role.value},
                "locator": {"enum": list(spec.allowed_locators)},
            },
            "required": ["role", "locator"],
        }
        for spec in MANAGED_TOOLCHAIN_ROLE_SPECS
        if spec.kind is ManagedToolchainMemberKind.HOST_EXECUTABLE
    ]


class ManagedHostToolFile(_FrozenHostModel):
    """One declared direct host file; its version string is not a probe result."""

    model_config = ConfigDict(json_schema_extra=_host_file_schema)

    role: ManagedToolchainRole
    locator: str = Field(min_length=1, max_length=100)
    version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/ -]{0,199}$")
    sha256: str = Field(pattern=_SHA256)
    size: int = Field(ge=1, le=4 * 1024**3)

    @model_validator(mode="after")
    def file_is_a_catalog_host_role(self) -> Self:
        spec = _ROLE_SPECS[self.role]
        if (
            spec.kind is not ManagedToolchainMemberKind.HOST_EXECUTABLE
            or self.locator not in spec.allowed_locators
            or Path(self.locator).name != self.locator
            or self.sha256 == "0" * 64
        ):
            raise ValueError("material file must match a declared host-executable catalog role")
        return self


class ManagedHostToolManifest(_FrozenHostModel):
    """Self-consistent direct-file material inventory, never installed-toolchain trust."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["managed-host-tool-material"] = "managed-host-tool-material"
    status: Literal["DIRECT_HOST_FILES_PREPARED_NONAUTHORIZING"] = (
        "DIRECT_HOST_FILES_PREPARED_NONAUTHORIZING"
    )
    source_bundle_sha256: str = Field(pattern=_SHA256)
    effective_config_sha256: str = Field(pattern=_SHA256)
    required_roles: tuple[ManagedToolchainRole, ...] = Field(min_length=1, max_length=28)
    files: tuple[ManagedHostToolFile, ...] = Field(min_length=1, max_length=21)
    independently_trusted: Literal[False] = False
    installed_members_verified: Literal[False] = False
    architecture_verified: Literal[False] = False
    transitive_dependency_closure_verified: Literal[False] = False
    image_side_attestation_verified: Literal[False] = False
    execution_evidence_verified: Literal[False] = False
    runtime_authority: Literal[False] = False
    managed_run_ready: Literal[False] = False
    manifest_sha256: str = Field(pattern=_SHA256)

    @field_validator(*_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def authority_is_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("host-file material cannot grant trust or execution authority")
        return value

    @model_validator(mode="after")
    def required_files_and_hash_are_exact(self) -> Self:
        if self.required_roles != tuple(sorted(set(self.required_roles), key=str)):
            raise ValueError("required material roles must be sorted and unique")
        host_roles = tuple(
            role
            for role in self.required_roles
            if _ROLE_SPECS[role].kind is ManagedToolchainMemberKind.HOST_EXECUTABLE
        )
        if tuple(item.role for item in self.files) != host_roles:
            raise ValueError("material must contain exactly every required direct host role")
        if len({item.locator for item in self.files}) != len(self.files):
            raise ValueError("host material executable locators must be unique")
        if sum(item.size for item in self.files) > 8 * 1024**3:
            raise ValueError("host material exceeds its aggregate hard bound")
        if any(
            value == "0" * 64 for value in (self.source_bundle_sha256, self.effective_config_sha256)
        ):
            raise ValueError("material bindings cannot use sentinel hashes")
        payload = self.model_dump(mode="json", exclude={"manifest_sha256"})
        if canonical_sha256(payload) != self.manifest_sha256:
            raise ValueError("host material manifest hash differs from its payload")
        return self


@dataclass(frozen=True, slots=True)
class ManagedHostToolMaterialization:
    """Exact local paths/config, reverified on use; not a runnable closure attestation."""

    action: Literal["CREATED", "VERIFIED_EXISTING"]
    directory: Path
    _manifest_json: str = field(repr=False)
    _bundle_json: str = field(repr=False)
    _config_json: str = field(repr=False)
    _limits_json: str = field(repr=False)
    runtime_authority: Literal[False] = field(default=False, init=False)
    managed_run_ready: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        if self.action not in {"CREATED", "VERIFIED_EXISTING"}:
            raise ManagedHostToolError("unsupported host material action")
        self.verify()

    @property
    def manifest(self) -> ManagedHostToolManifest:
        """Detach the retained declaration from callers and mutable model internals."""

        return ManagedHostToolManifest.model_validate_json(self._manifest_json, strict=True)

    @property
    def config(self) -> AuditConfig:
        """Return the exact derived consumer configuration without mutating the input."""

        return parse_canonical_audit_config(self._config_json)

    @property
    def bundle(self) -> ManagedToolchainBundle:
        """Return a detached declaration; platform labels are not architecture evidence."""

        return ManagedToolchainBundle.model_validate_json(self._bundle_json, strict=True)

    def verify(self) -> None:
        """Recheck every exact material file; failure never authorizes an invocation."""

        manifest = self.manifest
        limits = ManagedHostToolLimits.model_validate_json(self._limits_json, strict=True)
        bundle = self.bundle
        bundle, config, required = preflight_managed_toolchain_config(
            bundle, self.config, allow_unresolved=True
        )
        by_role = {member.role: member for member in bundle.members}
        _require_selection(
            manifest,
            bundle,
            config,
            required,
            tuple(
                by_role[role]
                for role in required
                if by_role[role].kind is ManagedToolchainMemberKind.HOST_EXECUTABLE
            ),
        )
        if derive_managed_toolchain_config(bundle, config, allow_unresolved=True) != config:
            raise ManagedHostToolError("host material config is missing its derived pins")
        if self.directory.name != _material_directory_name(
            manifest.source_bundle_sha256, manifest.effective_config_sha256
        ):
            raise ManagedHostToolError("host material directory differs from its selection")
        try:
            _verify_material_directory(self.directory, manifest, limits)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ManagedHostToolError("host material changed or cannot be verified") from exc

    def executable_for(self, role: ManagedToolchainRole) -> Path:
        """Return only a reverified selected host path for an existing pinned consumer."""

        if type(role) is not ManagedToolchainRole:
            raise ManagedHostToolError("host material lookup requires an exact role")
        self.verify()
        for item in self.manifest.files:
            if item.role is role:
                return self.directory / item.locator
        raise ManagedHostToolError("requested role has no selected direct host material")


def preflight_managed_host_tool_source(
    bundle: ManagedToolchainBundle, config: AuditConfig, source: ManagedHostToolSource
) -> ManagedHostToolSource:
    """Detach exact local selection and reject unpinned host roles before setup writes."""

    if type(source) is not ManagedHostToolSource:
        raise ManagedHostToolError("host material source has the wrong type")
    validated = ManagedHostToolSource.model_validate(source.model_dump(), strict=True)
    bundle, _, required = preflight_managed_toolchain_config(bundle, config, allow_unresolved=True)
    _selected_host_members(bundle, required)
    return validated


def _selected_host_members(
    bundle: ManagedToolchainBundle, required: tuple[ManagedToolchainRole, ...]
) -> tuple[ManagedToolchainMember, ...]:
    by_role = {member.role: member for member in bundle.members}
    members = tuple(
        by_role[role]
        for role in required
        if by_role[role].kind is ManagedToolchainMemberKind.HOST_EXECUTABLE
    )
    if not members or any(
        member.disposition is not ManagedToolchainDisposition.PINNED for member in members
    ):
        raise ManagedHostToolError("every required host role must have a declared exact pin")
    return members


def materialize_managed_host_tools(
    *,
    bundle: ManagedToolchainBundle,
    config: AuditConfig,
    repository: Path,
    output_root: Path,
    source: ManagedHostToolSource,
    verify_only: bool = False,
) -> ManagedHostToolMaterialization:
    """Copy exact local ``<sha256>.blob`` files, or verify a complete existing set.

    All selected host roles must already be pinned. Non-host roles are never
    materialized by this function. Output is private and outside audited source;
    partial output is preserved, not reset, overwritten or returned for consumption.
    An absent source store is allowed only when verifying already complete material.
    """

    try:
        if type(source) is not ManagedHostToolSource or type(verify_only) is not bool:
            raise ValueError("host material requires exact source and verify-only types")
        source = preflight_managed_host_tool_source(bundle, config, source)
        bundle, effective, required = preflight_managed_toolchain_config(
            bundle, config, allow_unresolved=True
        )
        effective = derive_managed_toolchain_config(bundle, effective, allow_unresolved=True)
        members = _selected_host_members(bundle, required)
        repository = _canonical_directory(repository)
        output_root = _canonical_directory(output_root)
        _require_disjoint(repository, output_root)
        if source.blob_root is not None:
            _canonical_directory(source.blob_root)
            _require_disjoint(repository, source.blob_root)
            _require_disjoint(output_root, source.blob_root)
        name = _material_directory_name(bundle.bundle_sha256, effective.stable_hash())
        output_fd = _open_private_directory(output_root)
        try:
            _require_directory_identity(output_root, output_fd)
            directory = output_root / name
            created = False
            try:
                os.stat(name, dir_fd=output_fd, follow_symlinks=False)
            except FileNotFoundError:
                if verify_only or source.blob_root is None:
                    raise ValueError(
                        "host material is absent and cannot be created in this mode"
                    ) from None
                files = _files_from_store(members, source.blob_root, source.limits)
                manifest = _seal_manifest(bundle, effective, required, files)
                os.mkdir(name, 0o700, dir_fd=output_fd)
                created = True
            else:
                manifest = _read_manifest(directory)
                _require_selection(manifest, bundle, effective, required, members)
            if created:
                assert source.blob_root is not None
                directory_fd = _open_private_directory(directory)
                try:
                    for item in manifest.files:
                        _require_directory_identity(output_root, output_fd)
                        _require_directory_identity(directory, directory_fd)
                        source_name = f"{item.sha256}.blob"
                        copy_file_evidence(
                            source_root=source.blob_root,
                            source_relative_path=source_name,
                            destination_root=directory,
                            destination_relative_path=item.locator,
                            expected_binding=ManifestFileBinding(
                                path=source_name, sha256=item.sha256, size=item.size
                            ),
                        )
                        _make_private_executable(directory_fd, item)
                    observed = _verify_tool_files(directory, directory_fd, manifest, source.limits)
                    write_json_evidence(
                        evidence_root=directory,
                        relative_path=_MANIFEST_NAME,
                        value=manifest,
                        max_bytes=_MAX_MANIFEST_BYTES,
                        require_private_parent=True,
                        validate_content=lambda _: _require_unchanged_tools(directory, observed),
                    )
                    _require_unchanged_tools(directory, observed)
                    _require_directory_identity(directory, directory_fd)
                    os.fsync(directory_fd)
                    os.fsync(output_fd)
                finally:
                    os.close(directory_fd)
            _verify_material_directory(directory, manifest, source.limits)
            _require_directory_identity(output_root, output_fd)
            return ManagedHostToolMaterialization(
                action="CREATED" if created else "VERIFIED_EXISTING",
                directory=directory,
                _manifest_json=stable_json(manifest),
                _bundle_json=bundle.model_dump_json(),
                _config_json=canonical_audit_config_json(effective),
                _limits_json=source.limits.model_dump_json(),
            )
        finally:
            os.close(output_fd)
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        raise ManagedHostToolError(
            "Local host material refused; no authority granted. "
            "Partial output is preserved and must not be consumed."
        ) from exc


def _files_from_store(
    members: tuple[ManagedToolchainMember, ...],
    blob_root: Path,
    limits: ManagedHostToolLimits,
) -> tuple[ManagedHostToolFile, ...]:
    files: list[ManagedHostToolFile] = []
    total = 0
    for member in members:
        assert (
            member.sha256 is not None and member.locator is not None and member.version is not None
        )
        metadata = (blob_root / f"{member.sha256}.blob").lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= limits.max_file_bytes
        ):
            raise ValueError("source blob must be a bounded unshared regular file")
        total += metadata.st_size
        if total > limits.max_total_bytes:
            raise ValueError("selected host files exceed the total material bound")
        files.append(
            ManagedHostToolFile(
                role=member.role,
                locator=member.locator,
                version=member.version,
                sha256=member.sha256,
                size=metadata.st_size,
            )
        )
    return tuple(files)


def _seal_manifest(
    bundle: ManagedToolchainBundle,
    config: AuditConfig,
    required: tuple[ManagedToolchainRole, ...],
    files: tuple[ManagedHostToolFile, ...],
) -> ManagedHostToolManifest:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "artifact_kind": "managed-host-tool-material",
        "status": "DIRECT_HOST_FILES_PREPARED_NONAUTHORIZING",
        "source_bundle_sha256": bundle.bundle_sha256,
        "effective_config_sha256": config.stable_hash(),
        "required_roles": list(required),
        "files": [item.model_dump(mode="json") for item in files],
        **dict.fromkeys(_AUTHORITY_FIELDS, False),
    }
    payload["manifest_sha256"] = canonical_sha256(payload)
    return ManagedHostToolManifest.model_validate_json(json.dumps(payload), strict=True)


def _require_selection(
    manifest: ManagedHostToolManifest,
    bundle: ManagedToolchainBundle,
    config: AuditConfig,
    required: tuple[ManagedToolchainRole, ...],
    members: tuple[ManagedToolchainMember, ...],
) -> None:
    if (
        manifest.source_bundle_sha256 != bundle.bundle_sha256
        or manifest.effective_config_sha256 != config.stable_hash()
        or manifest.required_roles != required
        or tuple((item.role, item.locator, item.version, item.sha256) for item in manifest.files)
        != tuple((item.role, item.locator, item.version, item.sha256) for item in members)
    ):
        raise ValueError("existing host material differs from its exact bundle/config selection")


def _read_manifest(directory: Path) -> ManagedHostToolManifest:
    descriptor = _open_private_directory(directory)
    try:
        before = (directory / _MANIFEST_NAME).lstat()
        _require_private_file(before, mode=0o600)
        observed = read_json_evidence(
            evidence_root=directory,
            relative_path=_MANIFEST_NAME,
            max_bytes=_MAX_MANIFEST_BYTES,
        )
        manifest = ManagedHostToolManifest.model_validate_json(observed.content, strict=True)
        if observed.content != stable_json(manifest).encode("utf-8"):
            raise ValueError("material manifest bytes are not canonical")
        if _file_identity(before) != _file_identity((directory / _MANIFEST_NAME).lstat()):
            raise ValueError("material manifest identity changed")
        _require_directory_identity(directory, descriptor)
        return manifest
    finally:
        os.close(descriptor)


def _verify_material_directory(
    directory: Path, manifest: ManagedHostToolManifest, limits: ManagedHostToolLimits
) -> None:
    descriptor = _open_private_directory(directory)
    try:
        if _read_manifest(directory) != manifest:
            raise ValueError("retained and published host manifests differ")
        expected = {_MANIFEST_NAME, *(item.locator for item in manifest.files)}
        seen: set[str] = set()
        with os.scandir(descriptor) as entries:
            for item in entries:
                if item.name not in expected or item.name in seen:
                    raise ValueError("unexpected entry in private host material")
                seen.add(item.name)
        if seen != expected:
            raise ValueError("private host material is incomplete")
        observed = _verify_tool_files(directory, descriptor, manifest, limits)
        if _read_manifest(directory) != manifest:
            raise ValueError("host material manifest changed during verification")
        _require_unchanged_tools(directory, observed)
        _require_directory_identity(directory, descriptor)
    finally:
        os.close(descriptor)


def _verify_tool_files(
    directory: Path,
    descriptor: int,
    manifest: ManagedHostToolManifest,
    limits: ManagedHostToolLimits,
) -> dict[str, scanner_base._ScannerExecutableObservation]:
    if sum(item.size for item in manifest.files) > limits.max_total_bytes:
        raise ValueError("host material exceeds the selected total limit")
    observed: dict[str, scanner_base._ScannerExecutableObservation] = {}
    for item in manifest.files:
        if item.size > limits.max_file_bytes:
            raise ValueError("host material exceeds the selected per-file limit")
        path = directory / item.locator
        before = path.lstat()
        _require_private_file(before, mode=0o500)
        identity = scanner_base._observe_scanner_executable(path)
        if (
            before.st_size != item.size
            or identity.sha256 != item.sha256
            or identity.identity != scanner_base._scanner_executable_identity(before)
        ):
            raise ValueError("host executable material differs from its declared identity")
        observed[item.locator] = identity
    _require_unchanged_tools(directory, observed)
    _require_directory_identity(directory, descriptor)
    return observed


def _require_unchanged_tools(
    directory: Path, observed: dict[str, scanner_base._ScannerExecutableObservation]
) -> None:
    for name, observation in observed.items():
        metadata = (directory / name).lstat()
        _require_private_file(metadata, mode=0o500)
        if scanner_base._scanner_executable_identity(metadata) != observation.identity:
            raise ValueError("earlier material identity changed during verification")


def _make_private_executable(descriptor: int, item: ManagedHostToolFile) -> None:
    file_descriptor = os.open(
        item.locator,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
        dir_fd=descriptor,
    )
    try:
        before = os.fstat(file_descriptor)
        _require_private_file(before, mode=0o600)
        if before.st_size != item.size:
            raise ValueError("copied host material size changed")
        os.fchmod(file_descriptor, 0o500)
        os.fsync(file_descriptor)
        after = os.stat(item.locator, dir_fd=descriptor, follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError("copied host material was replaced while setting its private mode")
        _require_private_file(after, mode=0o500)
    finally:
        os.close(file_descriptor)


def _canonical_directory(path: Path) -> Path:
    if not path.is_absolute() or path != path.resolve(strict=True) or not path.is_dir():
        raise ValueError("host material roots must be absolute unlinked directories")
    return path


def _require_disjoint(first: Path, second: Path) -> None:
    if first == second or first in second.parents or second in first.parents:
        raise ValueError("host material roots must not overlap")


def _open_private_directory(path: Path) -> int:
    _canonical_directory(path)
    if not all(getattr(os, name, 0) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")):
        raise ValueError("descriptor-safe host material is unavailable")
    descriptor = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        _require_directory_identity(path, descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _require_directory_identity(path: Path, descriptor: int) -> None:
    _canonical_directory(path)
    opened = os.fstat(descriptor)
    named = path.lstat()
    for metadata in (opened, named):
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != os.geteuid()
        ):
            raise ValueError("host output directories must be private and owned")
    if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
        raise ValueError("host output directory identity changed")


def _require_private_file(metadata: os.stat_result, *, mode: int) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise ValueError("host material files must be private, owned and unshared")


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _material_directory_name(bundle_sha256: str, config_sha256: str) -> str:
    digest = canonical_sha256(
        {"schema_version": "1.0", "bundle_sha256": bundle_sha256, "config_sha256": config_sha256}
    )
    return f"managed-host-tools-{digest}"
