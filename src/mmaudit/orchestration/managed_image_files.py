"""Join fixed managed file pins to a bounded, in-memory local OCI filesystem view.

No extraction, provisioning or runtime admission. Supported hardlinks refer only
to an already materialized regular file in the same layer. Writes through symbolic
parents, special entries and ambiguous replacement semantics refuse explicitly.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mmaudit.isolation.oci_layer import (
    OciLayerChangeset,
    OciLayerEntry,
    OciLayerLimits,
    read_oci_layer,
    require_oci_deadline,
)
from mmaudit.orchestration.managed_image_layers import (
    ManagedImageLayerLimits,
    ManagedImageLayersObservation,
    _inspect_managed_image_layers,
)
from mmaudit.orchestration.managed_toolchain import (
    MANAGED_HARDHAT_REPORTER_IMAGE_PATH,
    ManagedToolchainBundle,
    ManagedToolchainDisposition,
    ManagedToolchainRole,
)
from mmaudit.scanners.hardhat import HARDHAT_REPORTER_SHA256, HARDHAT_REPORTER_VERSION

_ROLES = (
    ManagedToolchainRole.HARDHAT_IMAGE_HARDHAT,
    ManagedToolchainRole.HARDHAT_IMAGE_NODE,
    ManagedToolchainRole.HARDHAT_IMAGE_LOOPBACK,
    ManagedToolchainRole.HARDHAT_REPORTER,
)


class ManagedImageFileError(ValueError):
    """Current layer contents do not establish the selected static file membership."""


class ManagedImageFileLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    layers: ManagedImageLayerLimits = Field(default_factory=ManagedImageLayerLimits)
    tar: OciLayerLimits = Field(default_factory=OciLayerLimits)
    max_total_headers: int = Field(default=250_000, ge=1, le=500_000)
    max_total_metadata_bytes: int = Field(default=32 * 1024**2, ge=1, le=64 * 1024**2)
    max_live_nodes: int = Field(default=100_000, ge=1, le=250_000)
    max_live_path_bytes: int = Field(default=32 * 1024**2, ge=1, le=64 * 1024**2)
    max_symlink_hops: int = Field(default=40, ge=1, le=40)


@dataclass(frozen=True, slots=True)
class ManagedImageFileMembership:
    """A static path/content join; version and ownership remain archive declarations."""

    role: ManagedToolchainRole
    image_path: str
    resolved_image_path: str
    sha256: str
    size: int
    mode: int
    uid: int
    gid: int
    content_layer_index: int
    declared_version: str
    symlink_paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ManagedImageFilesObservation:
    layers: ManagedImageLayersObservation = field(repr=False)
    files: tuple[ManagedImageFileMembership, ...]
    total_headers: int
    total_metadata_bytes: int
    live_nodes: int
    independently_trusted: Literal[False] = field(default=False, init=False)
    image_side_attestation_verified: Literal[False] = field(default=False, init=False)
    transitive_dependency_closure_verified: Literal[False] = field(default=False, init=False)
    execution_evidence_verified: Literal[False] = field(default=False, init=False)
    runtime_authority: Literal[False] = field(default=False, init=False)
    managed_run_ready: Literal[False] = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class _Node:
    entry: OciLayerEntry
    content_layer: int


def _parent(path: str) -> str:
    return path.rpartition("/")[0]


class _Filesystem:
    def __init__(self, limits: ManagedImageFileLimits) -> None:
        self.limits = limits
        self.nodes = {"": _Node(OciLayerEntry("", "directory", 0, None, None, 0, 0, 0), -1)}
        self.children: dict[str, set[str]] = {"": set()}
        self.path_bytes = 0
        self.headers = self.metadata_bytes = 0
        self.deadline = 0.0

    def consume(self, index: int, deadline: float, chunks: Iterator[bytes]) -> None:
        self.deadline = deadline
        layer = read_oci_layer(chunks, limits=self.limits.tar, absolute_deadline=deadline)
        self.headers += layer.headers
        self.metadata_bytes += layer.metadata_bytes
        if (
            self.headers > self.limits.max_total_headers
            or self.metadata_bytes > self.limits.max_total_metadata_bytes
        ):
            raise ValueError("image exceeds its cumulative tar metadata allowance")
        self._apply(layer, index)
        require_oci_deadline(deadline)

    def _apply(self, layer: OciLayerChangeset, index: int) -> None:
        non_directories = {
            entry.path for entry in layer.entries if entry.kind in {"file", "symlink", "hardlink"}
        }
        for entry in layer.entries:
            require_oci_deadline(self.deadline)
            parent = _parent(entry.path)
            while parent:
                if parent in non_directories:
                    raise ValueError("same-layer non-directory ancestor is ambiguous")
                parent = _parent(parent)
            if entry.kind in {"whiteout", "opaque"}:
                self._existing_directory(_parent(entry.path))
        # OCI whiteouts affect only lower layers, regardless of archive order.
        for entry in layer.entries:
            require_oci_deadline(self.deadline)
            if entry.kind not in {"whiteout", "opaque"}:
                continue
            parent = _parent(entry.path)
            if not self._existing_directory(parent):
                continue
            if entry.kind == "opaque":
                for child in tuple(self.children[parent]):
                    self._remove(child)
            else:
                name = entry.path.rsplit("/", 1)[-1][4:]
                self._remove(parent + "/" + name if parent else name)
        current_files: set[str] = set()
        for entry in layer.entries:
            require_oci_deadline(self.deadline)
            if entry.kind in {"whiteout", "opaque"}:
                continue
            self._parents(entry.path)
            node = _Node(entry, index)
            if entry.kind == "hardlink":
                target = entry.link_target
                if target not in current_files:
                    raise ValueError("hardlink target must be an earlier same-layer regular file")
                assert target is not None
                node = self.nodes[target]
                if (entry.mode, entry.uid, entry.gid) != (
                    node.entry.mode,
                    node.entry.uid,
                    node.entry.gid,
                ):
                    raise ValueError("hardlink metadata would change shared inode attributes")
            previous = self.nodes.get(entry.path)
            if not (
                previous is not None
                and previous.entry.kind == "directory"
                and entry.kind == "directory"
            ):
                self._remove(entry.path)
            self._put(entry.path, node)
            if node.entry.kind == "file":
                current_files.add(entry.path)

    def _existing_directory(self, path: str) -> bool:
        current = ""
        for part in path.split("/") if path else ():
            current = current + "/" + part if current else part
            node = self.nodes.get(current)
            if node is None:
                return False
            if node.entry.kind != "directory":
                raise ValueError("OCI layer write through a non-directory parent is unsupported")
        return True

    def _parents(self, path: str) -> None:
        current = ""
        for part in path.split("/")[:-1]:
            require_oci_deadline(self.deadline)
            current = current + "/" + part if current else part
            if current not in self.nodes:
                self._put(
                    current, _Node(OciLayerEntry(current, "directory", 0, None, None, 0, 0, 0), -1)
                )
            elif self.nodes[current].entry.kind != "directory":
                raise ValueError("OCI layer write through a non-directory parent is unsupported")

    def _put(self, path: str, node: _Node) -> None:
        if path not in self.nodes:
            projected = self.path_bytes + len(path.encode("utf-8"))
            if (
                len(self.nodes) >= self.limits.max_live_nodes
                or projected > self.limits.max_live_path_bytes
            ):
                raise ValueError("image exceeds its live filesystem metadata allowance")
            self.path_bytes = projected
            self.children[_parent(path)].add(path)
        self.nodes[path] = node
        self.children.setdefault(path, set())

    def _remove(self, path: str) -> None:
        if path not in self.nodes:
            return
        if not path:
            raise ValueError("replacing the image root is unsupported")
        pending = [path]
        self.children[_parent(path)].discard(path)
        while pending:
            require_oci_deadline(self.deadline)
            current = pending.pop()
            pending.extend(self.children.pop(current))
            self.nodes.pop(current)
            self.path_bytes -= len(current.encode("utf-8"))

    def resolve(self, path: str) -> tuple[str, _Node, tuple[str, ...]]:
        pending = deque(path.removeprefix("/").split("/"))
        resolved: list[str] = []
        links: list[str] = []
        while pending:
            require_oci_deadline(self.deadline)
            part = pending.popleft()
            if part == ".":
                continue
            if part == "..":
                if not resolved:
                    raise ValueError("symlink escapes the image root")
                resolved.pop()
                continue
            if not part:
                raise ValueError("ambiguous empty symlink path component")
            current = "/".join([*resolved, part])
            node = self.nodes.get(current)
            if node is None:
                raise ValueError("selected image file or link target is missing")
            if node.entry.kind == "symlink":
                links.append("/" + current)
                if len(links) > self.limits.max_symlink_hops:
                    raise ValueError("image symlink hop allowance is exhausted")
                target = node.entry.link_target
                assert target is not None
                if target.startswith("/"):
                    resolved.clear()
                    target = target[1:]
                components = target.split("/")
                if components[-1] == "":
                    components[-1] = "."
                pending.extendleft(reversed(components))
            else:
                resolved.append(part)
                if pending and node.entry.kind != "directory":
                    raise ValueError("image path traverses a non-directory")
            if (
                len(resolved) + len(pending) > self.limits.tar.max_path_depth
                or len("/".join([*resolved, *pending]).encode("utf-8"))
                > self.limits.tar.max_path_bytes
            ):
                raise ValueError("resolved image path exceeds its allowance")
        final = "/".join(resolved)
        node = self.nodes[final]
        if node.entry.kind != "file":
            raise ValueError("selected image path is not a regular file")
        return "/" + final, node, tuple(links)


def verify_managed_image_files(
    bundle: ManagedToolchainBundle,
    *,
    blob_root: Path,
    limits: ManagedImageFileLimits | None = None,
) -> ManagedImageFilesObservation:
    """Hash the effective selected files; never accept serialized observations as authority."""

    if type(bundle) is not ManagedToolchainBundle:
        raise ManagedImageFileError("file verification requires the exact managed bundle type")
    if limits is None:
        limits = ManagedImageFileLimits()
    if type(limits) is not ManagedImageFileLimits:
        raise ManagedImageFileError("file verification requires the exact limits type")
    try:
        selected = ManagedImageFileLimits.model_validate_json(limits.model_dump_json(), strict=True)
        pinned = ManagedToolchainBundle.model_validate_json(bundle.model_dump_json(), strict=True)
        members = {member.role: member for member in pinned.members}
        for role in _ROLES:
            if members[role].disposition != ManagedToolchainDisposition.PINNED:
                raise ValueError("every selected image file requires an exact available pin")
        reporter = members[ManagedToolchainRole.HARDHAT_REPORTER]
        if (reporter.sha256, reporter.version) != (
            HARDHAT_REPORTER_SHA256,
            HARDHAT_REPORTER_VERSION,
        ):
            raise ValueError("reporter pin does not match the compiled package contract")
        filesystem = _Filesystem(selected)
        observation = _inspect_managed_image_layers(
            bundle, blob_root=blob_root, limits=selected.layers, consume_layer=filesystem.consume
        )
        if observation.metadata.source_bundle_sha256 != pinned.bundle_sha256:
            raise ValueError("managed file pins changed during layer consumption")
        files: list[ManagedImageFileMembership] = []
        for role in _ROLES:
            member = members[role]
            path = MANAGED_HARDHAT_REPORTER_IMAGE_PATH if role == reporter.role else member.locator
            assert path is not None and member.version is not None
            resolved, node, links = filesystem.resolve(path)
            entry = node.entry
            if entry.sha256 != member.sha256:
                raise ValueError("effective image file differs from its selected content pin")
            if entry.mode & 0o7022 or (role != reporter.role and not entry.mode & 0o111):
                raise ValueError("selected image file has unsupported archive permission bits")
            if role == reporter.role and not entry.mode & 0o444:
                raise ValueError("selected reporter lacks readable archive permission bits")
            assert entry.sha256 is not None
            files.append(
                ManagedImageFileMembership(
                    role,
                    path,
                    resolved,
                    entry.sha256,
                    entry.size,
                    entry.mode,
                    entry.uid,
                    entry.gid,
                    node.content_layer,
                    member.version,
                    links,
                )
            )
        if (
            ManagedToolchainBundle.model_validate_json(bundle.model_dump_json(), strict=True)
            != pinned
        ):
            raise ValueError("managed bundle changed during file membership inspection")
        require_oci_deadline(filesystem.deadline)
        return ManagedImageFilesObservation(
            observation,
            tuple(files),
            filesystem.headers,
            filesystem.metadata_bytes,
            len(filesystem.nodes),
        )
    except (OSError, ValueError) as exc:
        if isinstance(exc, ManagedImageFileError):
            raise
        raise ManagedImageFileError("managed image file membership was refused") from exc
