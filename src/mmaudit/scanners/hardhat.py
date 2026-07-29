"""Fail-closed boundary for repository-supplied Hardhat fork suites."""

from __future__ import annotations

import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mmaudit.config import ScannerConfig, SmartContractsConfig
from mmaudit.isolation.container import RootlessContainerBackend
from mmaudit.isolation.provenance import (
    isolation_attestation_sha256,
    isolation_execution_evidence,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    RepositoryCodeExecutionState,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
)
from mmaudit.scanners.base import ScannerAdapter, ScannerIsolationBackend

_HARDHAT_CONFIG_NAMES = (
    "hardhat.config.cjs",
    "hardhat.config.js",
    "hardhat.config.mjs",
    "hardhat.config.ts",
)
_DIGEST_PINNED_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
_MAX_CONFIGURATION_BYTES = 1_000_000
_UNSAFE_CONFIGURATION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bnetworks?\s*[:=]", re.IGNORECASE), "repository-defined network settings"),
    (
        re.compile(
            r"\b(?:child_process|node:child_process|execSync|spawnSync|"
            r"execFile|spawn|shelljs|execa)\b",
            re.IGNORECASE,
        ),
        "process or shell execution",
    ),
    (
        re.compile(r"\b(?:task|subtask)\s*\(", re.IGNORECASE),
        "repository-defined task hooks",
    ),
    (
        re.compile(
            r"\b(?:process\.env|dotenv|mnemonic|private[_-]?key|wallet)\b",
            re.IGNORECASE,
        ),
        "wallet, private-key, or environment credential material",
    ),
    (
        re.compile(r"(?:https?|wss?)://", re.IGNORECASE),
        "repository-defined network endpoint",
    ),
)
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
_UNSAFE_PACKAGE_SCRIPT = re.compile(
    r"(?:[;&|`$<>]|\r|\n|\b(?:bash|curl|wget|ssh|nc|netcat|powershell)\b|"
    r"\bnode\s+-e\b|\bhardhat\s+(?:node|run)\b|--network\b|--config\b)",
    re.IGNORECASE,
)
_SENSITIVE_PACKAGE_KEY = re.compile(
    r"(?:mnemonic|private[_-]?key|wallet)",
    re.IGNORECASE,
)
_UNSAFE_DEPENDENCY = re.compile(
    r"(?:^|/)(?:ffi-napi|node-ffi|shelljs|execa|zx)$",
    re.IGNORECASE,
)


class HardhatForkScanner(ScannerAdapter):
    """Refuse Hardhat execution until its exact rootless fork boundary is attested."""

    name = "hardhat_fork"
    executable = "hardhat"
    may_execute_repository_code = True
    strict_machine_output = True

    def __init__(
        self,
        smart_contracts: SmartContractsConfig,
        scanner_config: ScannerConfig,
    ) -> None:
        self.smart_contracts = smart_contracts
        self.scanner_config = scanner_config

    def with_runtime_allowance(self, allow_fork_probing: bool) -> HardhatForkScanner:
        """Return an immutable runtime view of the explicit CLI/config acknowledgement."""

        return HardhatForkScanner(
            self.smart_contracts.model_copy(
                update={
                    "allow_fork_probing": (
                        self.smart_contracts.allow_fork_probing or allow_fork_probing
                    )
                }
            ),
            self.scanner_config,
        )

    def available(self) -> bool:
        """Host PATH discovery cannot prove an in-container Hardhat toolchain."""

        return False

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        """Return the future fixed command shape without executing package scripts."""

        del root, private_dir
        return [self.executable, "test", "--network", "hardhat", "--no-compile"]

    def parse(self, root: Path, stdout: str, private_dir: Path) -> list[ScannerFinding]:
        """Reject output until a trusted machine-readable reporter is implemented."""

        del root, stdout, private_dir
        raise ValueError("trusted machine-readable Hardhat fork output is unavailable")

    def run(
        self,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: ScannerIsolationBackend | None = None,
        expected_version: str | None = None,
        expected_sha256: str | None = None,
    ) -> ScannerRun:
        """Perform only fail-closed preflight; never execute target JavaScript here."""

        del timeout_seconds
        start = datetime.now(UTC)
        monotonic_start = time.monotonic()

        def finish(status: ScannerStatus, error: str) -> ScannerRun:
            run = ScannerRun(
                scanner=self.name,
                status=status,
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error=error,
                isolation_backend=(
                    str(getattr(backend, "name", "")) or None if backend is not None else None
                ),
                isolation_attestation_sha256=isolation_attestation_sha256(backend),
                repository_code_execution=RepositoryCodeExecutionState.BLOCKED,
            )
            return ScannerRun.model_validate(
                {
                    **run.model_dump(mode="json"),
                    "execution_observation_sha256": (run.expected_execution_observation_sha256()),
                }
            )

        if not self.scanner_config.enabled:
            return finish(ScannerStatus.SKIPPED, "Hardhat fork-suite scanner is disabled")
        if not self.smart_contracts.enabled:
            return finish(ScannerStatus.SKIPPED, "smart-contract analysis is disabled")
        if not self.smart_contracts.allow_fork_probing:
            return finish(
                ScannerStatus.SKIPPED,
                "Hardhat fork probing requires explicit operator acknowledgement",
            )

        backend_error = _rootless_backend_error(backend)
        if backend_error is not None:
            return finish(ScannerStatus.UNAVAILABLE, backend_error)

        if expected_version is None:
            expected_version = self.scanner_config.version
        if expected_sha256 is None:
            expected_sha256 = self.scanner_config.sha256
        if expected_version is None or expected_sha256 is None:
            return finish(
                ScannerStatus.UNAVAILABLE,
                "Hardhat fork execution requires paired in-container toolchain trust pins",
            )

        rpc_value = _fork_rpc_value(self.smart_contracts)
        if rpc_value is None:
            return finish(
                ScannerStatus.UNAVAILABLE,
                f"{self.smart_contracts.fork_rpc_url_env} is not set",
            )
        try:
            rpc_port = _loopback_rpc_port(rpc_value)
        except ValueError:
            return finish(
                ScannerStatus.FAILED,
                "Hardhat fork RPC must be one credential-free plain HTTP loopback endpoint",
            )

        assert type(backend) is RootlessContainerBackend
        approved_port = getattr(backend, "approved_loopback_rpc_port", None)
        if (
            not isinstance(approved_port, int)
            or isinstance(approved_port, bool)
            or approved_port != rpc_port
        ):
            return finish(
                ScannerStatus.UNAVAILABLE,
                "rootless isolation has no attested single-port loopback RPC capability",
            )

        try:
            configuration_error = _target_configuration_error(root)
        except (OSError, UnicodeError, ValueError):
            return finish(
                ScannerStatus.FAILED,
                "Hardhat repository configuration could not be validated safely",
            )
        if configuration_error is not None:
            return finish(ScannerStatus.FAILED, configuration_error)

        return finish(
            ScannerStatus.UNAVAILABLE,
            "trusted machine-readable Hardhat fork-suite execution is not implemented",
        )


def _rootless_backend_error(backend: object | None) -> str | None:
    if type(backend) is not RootlessContainerBackend:
        return "Hardhat fork suites require the exact digest-pinned rootless container backend"
    assert isinstance(backend, RootlessContainerBackend)
    if not backend.rootless_verified or _DIGEST_PINNED_IMAGE.fullmatch(backend.image) is None:
        return "Hardhat fork suites require a verified digest-pinned rootless container"
    if isolation_execution_evidence(backend) is not ExecutionEvidenceKind.REAL:
        return "rootless Hardhat isolation lacks process-attested REAL provenance"
    if isolation_attestation_sha256(backend) is None:
        return "rootless Hardhat isolation lacks a current process attestation"
    if not backend.supports_local_fork_rpc:
        return "rootless Hardhat isolation cannot reach one approved loopback fork RPC"
    for method in (
        "wrap_repository_javascript",
        "writable_path",
        "cleanup",
        "host_environment",
    ):
        if not callable(getattr(backend, method, None)):
            return "rootless Hardhat isolation lacks a disposable execution boundary"
    return None


def _fork_rpc_value(config: SmartContractsConfig) -> str | None:
    """Read only the operator-selected fork variable, never target dotenv files."""

    import os

    value = os.environ.get(config.fork_rpc_url_env)
    return value if value else None


def _loopback_rpc_port(value: str) -> int:
    parsed = urlparse(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.port is None
        or parsed.path not in {"", "/"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid loopback RPC")
    return parsed.port


def _target_configuration_error(root: Path) -> str | None:
    if root.is_symlink() or root.is_junction():
        raise ValueError("repository root may not be a link")
    repository_root = root.resolve(strict=True)
    if not repository_root.is_dir():
        raise ValueError("repository root must be a directory")

    config_paths = [repository_root / name for name in _HARDHAT_CONFIG_NAMES]
    present_configs = [path for path in config_paths if path.exists()]
    if not present_configs:
        return "no repository-root Hardhat configuration was found"
    for path in present_configs:
        content = _bounded_regular_text(path)
        for pattern, label in _UNSAFE_CONFIGURATION_PATTERNS:
            if pattern.search(content):
                return f"Hardhat configuration contains prohibited {label}"

    package_path = repository_root / "package.json"
    if package_path.exists():
        payload = _strict_json_object(_bounded_regular_text(package_path))
        package_error = _package_configuration_error(payload)
        if package_error is not None:
            return package_error
    return None


def _bounded_regular_text(path: Path) -> str:
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError("Hardhat configuration must be a regular non-link file")
    stat = path.stat()
    if stat.st_nlink != 1 or stat.st_size > _MAX_CONFIGURATION_BYTES:
        raise ValueError("Hardhat configuration file is not safely bounded")
    return path.read_text(encoding="utf-8")


def _strict_json_object(content: str) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("package.json contains duplicate keys")
            result[key] = value
        return result

    payload = json.loads(content, object_pairs_hook=unique_object)
    if not isinstance(payload, dict):
        raise ValueError("package.json must be an object")
    return payload


def _package_configuration_error(payload: dict[str, Any]) -> str | None:
    if _contains_sensitive_package_key(payload):
        return "Hardhat package configuration contains wallet or private-key material"

    scripts = payload.get("scripts", {})
    if not isinstance(scripts, dict):
        return "Hardhat package scripts must be an object"
    for raw_name, raw_command in scripts.items():
        if not isinstance(raw_name, str) or not isinstance(raw_command, str):
            return "Hardhat package scripts must contain string commands"
        name = raw_name.casefold()
        if name in _LIFECYCLE_SCRIPTS or name.startswith(("pre", "post")):
            return "Hardhat package configuration contains prohibited lifecycle hooks"
        if _UNSAFE_PACKAGE_SCRIPT.search(raw_command):
            return "Hardhat package configuration contains prohibited shell or network hooks"

    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        dependencies = payload.get(field, {})
        if not isinstance(dependencies, dict):
            return f"Hardhat {field} must be an object"
        if any(isinstance(name, str) and _UNSAFE_DEPENDENCY.search(name) for name in dependencies):
            return "Hardhat package configuration contains a prohibited execution dependency"
    return None


def _contains_sensitive_package_key(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            _SENSITIVE_PACKAGE_KEY.search(str(key)) is not None
            or _contains_sensitive_package_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_sensitive_package_key(item) for item in value)
    return False
