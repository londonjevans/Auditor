"""Hardened execution backends for untrusted dynamic tooling."""

from mmaudit.isolation.container import (
    RepositoryJavaScriptIsolationBackend,
    RootlessContainerBackend,
    RootlessContainerLimits,
    cleanup_isolation_backend,
    discover_rootless_container_backend,
    isolation_host_environment,
)
from mmaudit.isolation.dependencies import (
    DependencyPreparationRun,
    dependency_tree_sha256,
    prepare_dependencies,
)

__all__ = [
    "DependencyPreparationRun",
    "RepositoryJavaScriptIsolationBackend",
    "RootlessContainerBackend",
    "RootlessContainerLimits",
    "cleanup_isolation_backend",
    "dependency_tree_sha256",
    "discover_rootless_container_backend",
    "isolation_host_environment",
    "prepare_dependencies",
]
