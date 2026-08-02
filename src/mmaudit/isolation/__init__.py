"""Hardened execution backends for untrusted dynamic tooling."""

from mmaudit.isolation.container import (
    HARDHAT_READ_ONLY_RPC_METHODS,
    HardhatReadOnlyRpcBridgeBinding,
    RepositoryJavaScriptIsolationBackend,
    RootlessContainerBackend,
    RootlessContainerLimits,
    SingleLoopbackHardhatBackend,
    bind_hardhat_read_only_rpc_bridge,
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
    "HARDHAT_READ_ONLY_RPC_METHODS",
    "DependencyPreparationRun",
    "HardhatReadOnlyRpcBridgeBinding",
    "RepositoryJavaScriptIsolationBackend",
    "RootlessContainerBackend",
    "RootlessContainerLimits",
    "SingleLoopbackHardhatBackend",
    "bind_hardhat_read_only_rpc_bridge",
    "cleanup_isolation_backend",
    "dependency_tree_sha256",
    "discover_rootless_container_backend",
    "isolation_host_environment",
    "prepare_dependencies",
]
