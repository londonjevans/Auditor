"""Deterministic host-material isolation composition, not installed-closure authority."""

from __future__ import annotations

import platform
from pathlib import Path
from typing import TYPE_CHECKING

from mmaudit.isolation.provenance import (
    _admit_isolation_executable,
    _seal_builtin_isolation_backend,
)
from mmaudit.orchestration.managed_host_tools import ManagedHostToolMaterialization
from mmaudit.orchestration.managed_toolchain import ManagedToolchainRole

if TYPE_CHECKING:
    from mmaudit.solidity.reproduction import BubblewrapBackend


class ManagedIsolationError(ValueError):
    """Selected managed isolation is unavailable; no ambient fallback is permitted."""


def _verified_bubblewrap_selection(
    host_tools: ManagedHostToolMaterialization,
) -> tuple[Path, str]:
    """Join exact local material, selected backend and declared host platform."""

    if type(host_tools) is not ManagedHostToolMaterialization:
        raise ManagedIsolationError("managed isolation requires exact prepared host material")
    host_tools.verify()
    if host_tools.config.reproduction.isolation_backend != "bubblewrap":
        raise ManagedIsolationError("managed isolation currently requires explicit bubblewrap")
    machine = platform.machine()
    host_platform = {
        "x86_64": "linux-amd64",
        "AMD64": "linux-amd64",
        "aarch64": "linux-arm64",
        "arm64": "linux-arm64",
    }.get(machine)
    if platform.system() != "Linux" or host_platform != host_tools.bundle.target_platform:
        raise ManagedIsolationError("managed isolation platform does not match its declared bundle")
    # This host-platform join does not verify ELF architecture or dependency closure.
    for item in host_tools.manifest.files:
        if item.role is ManagedToolchainRole.BUBBLEWRAP:
            return host_tools.directory / item.locator, item.sha256
    raise ManagedIsolationError("managed isolation has no selected bubblewrap host material")


def managed_isolation_backend(host_tools: ManagedHostToolMaterialization) -> BubblewrapBackend:
    """Preflight the selected pinned launcher without PATH or cross-platform fallback."""

    from mmaudit.solidity.reproduction import BubblewrapBackend

    try:
        executable, expected_sha256 = _verified_bubblewrap_selection(host_tools)
        backend = BubblewrapBackend(executable=str(executable), host_tools=host_tools)
        admission = _admit_isolation_executable(backend)
        if admission.observation.sha256 != expected_sha256:
            raise ManagedIsolationError("managed isolation launcher differs from its selected pin")
        host_tools.verify()
        backend = _seal_builtin_isolation_backend(backend, admission=admission)
        if _verified_bubblewrap_selection(host_tools) != (executable, expected_sha256):
            raise ManagedIsolationError("managed isolation selection changed during preflight")
        return backend
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ManagedIsolationError(
            "managed Linux isolation refused; selected material and every boundary probe are required"
        ) from exc


def _managed_tool_read_directory(
    host_tools: ManagedHostToolMaterialization, *, executable: str, private_dir: Path
) -> Path:
    """Reverify a closed tool tree and prohibit overlap with any writable private mount."""

    selected, _ = _verified_bubblewrap_selection(host_tools)
    if executable != str(selected):
        raise ManagedIsolationError("managed isolation wrapper has a different selected launcher")
    directory = host_tools.directory
    if directory.is_relative_to(private_dir) or private_dir.is_relative_to(directory):
        raise ManagedIsolationError("managed tool material must not overlap writable private state")
    return directory
