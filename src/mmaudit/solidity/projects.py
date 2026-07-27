"""Solidity project discovery without executing repository code."""

from __future__ import annotations

import json
import re
import tomllib
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import Any

from mmaudit.config import SmartContractsConfig
from mmaudit.models.schemas import SolidityProjectMetadata, SolidityProjectType
from mmaudit.repository.discovery import DiscoveryResult
from mmaudit.repository.ignore import normalize_relative_path

_HARDHAT_CONFIGS = {
    "hardhat.config.cjs",
    "hardhat.config.js",
    "hardhat.config.mjs",
    "hardhat.config.ts",
}
_DEP_FILES = {
    "foundry.toml",
    "remappings.txt",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
}
_SOURCE_DIRS = ("src", "contracts")
_TEST_DIRS = ("test", "tests")
_SCRIPT_DIRS = ("script", "scripts")
_DEPLOYMENT_DIRS = ("deploy", "deployments", "broadcast")
_ARTIFACT_DIRS = ("out", "artifacts")
_EXCLUDED_DIRS = ("cache", "out", "artifacts", "node_modules", ".git", ".mmaudit")
_PRAGMA = re.compile(r"pragma\s+solidity\s+([^;]+);")


def discover_solidity_projects(
    discovery: DiscoveryResult,
    config: SmartContractsConfig,
) -> list[SolidityProjectMetadata]:
    """Return normalized Solidity project metadata for all detected package roots."""

    if not config.enabled:
        return []
    root = discovery.root
    solidity_paths = [item.relative_path for item in discovery.files if item.language == "Solidity"]
    if not solidity_paths:
        return []

    configured_root = _configured_root(config)
    if configured_root is not None:
        return [_metadata_for_root(root, configured_root, discovery, config, solidity_paths)]

    candidates: set[str] = set()
    for item in discovery.files:
        name = PurePosixPath(item.relative_path).name
        if (
            name == "foundry.toml"
            or name in _HARDHAT_CONFIGS
            or (name == "package.json" and _package_has_hardhat(item.content))
        ):
            candidates.add(PurePosixPath(item.relative_path).parent.as_posix())

    if not candidates:
        candidates.add(_plain_project_root(solidity_paths))

    normalized = sorted("." if candidate in {"", "."} else candidate for candidate in candidates)
    projects = [
        _metadata_for_root(root, project_root, discovery, config, solidity_paths)
        for project_root in normalized
    ]
    if len(projects) > 1:
        projects = [
            project.model_copy(
                update={
                    "discovery_warnings": [
                        *project.discovery_warnings,
                        "monorepo: multiple Solidity project roots detected",
                    ]
                }
            )
            for project in projects
        ]
    return projects


def _configured_root(config: SmartContractsConfig) -> str | None:
    if config.project_root is None:
        return None
    return normalize_relative_path(config.project_root) or "."


def _metadata_for_root(
    repository_root: Path,
    project_root: str,
    discovery: DiscoveryResult,
    config: SmartContractsConfig,
    all_solidity_paths: list[str],
) -> SolidityProjectMetadata:
    project_root = "." if project_root in {"", "."} else project_root.rstrip("/")
    project_path = repository_root if project_root == "." else repository_root / project_root
    path_set = {item.relative_path for item in discovery.files}
    content_by_path = {item.relative_path: item.content for item in discovery.files}
    project_files = [
        item.relative_path
        for item in discovery.files
        if _inside_project(item.relative_path, project_root)
    ]
    solidity_paths = [path for path in all_solidity_paths if _inside_project(path, project_root)]
    foundry_config = _join(project_root, "foundry.toml")
    hardhat_configs = [_join(project_root, value) for value in _HARDHAT_CONFIGS]
    package_json = _join(project_root, "package.json")
    has_foundry = foundry_config in path_set
    has_hardhat = any(path in path_set for path in hardhat_configs) or _package_has_hardhat(
        content_by_path.get(package_json, "")
    )
    if config.framework != "auto":
        project_type = SolidityProjectType(config.framework)
    elif has_foundry and has_hardhat:
        project_type = SolidityProjectType.MIXED
    elif has_foundry:
        project_type = SolidityProjectType.FOUNDRY
    elif has_hardhat:
        project_type = SolidityProjectType.HARDHAT
    else:
        project_type = SolidityProjectType.PLAIN

    source_dirs = _existing_dirs(project_path, project_root, _SOURCE_DIRS, require_solidity=True)
    if not source_dirs:
        source_dirs = _fallback_source_dirs(solidity_paths)
    dependency_files = sorted(
        path
        for path in project_files
        if PurePosixPath(path).name in _DEP_FILES or path.endswith("/remappings.txt")
    )
    foundry_settings = _foundry_settings(content_by_path.get(foundry_config, ""))
    hardhat_settings = _hardhat_settings(
        "\n".join(content_by_path.get(path, "") for path in hardhat_configs)
    )
    compiler_versions = sorted(
        {
            *foundry_settings["compiler_versions"],
            *hardhat_settings["compiler_versions"],
            *[
                version
                for path in solidity_paths
                for version in _pragma_versions(content_by_path.get(path, ""))
            ],
        }
    )
    warnings = []
    if project_type is SolidityProjectType.PLAIN:
        warnings.append("plain Solidity project: no Foundry or Hardhat configuration detected")
    if not compiler_versions:
        warnings.append("no Solidity compiler version detected")
    if project_root not in {".", ""} and not project_path.exists():
        warnings.append("configured Solidity project root does not exist")
    return SolidityProjectMetadata(
        project_type=project_type,
        project_root=project_root,
        source_directories=source_dirs,
        test_directories=_existing_dirs(project_path, project_root, _TEST_DIRS),
        script_directories=_existing_dirs(project_path, project_root, _SCRIPT_DIRS),
        deployment_directories=_existing_dirs(project_path, project_root, _DEPLOYMENT_DIRS),
        dependency_files=dependency_files,
        compiler_versions=compiler_versions,
        optimizer_enabled=foundry_settings["optimizer_enabled"]
        if foundry_settings["optimizer_enabled"] is not None
        else hardhat_settings["optimizer_enabled"],
        optimizer_runs=foundry_settings["optimizer_runs"] or hardhat_settings["optimizer_runs"],
        evm_version=foundry_settings["evm_version"] or hardhat_settings["evm_version"],
        remappings=_remappings(content_by_path.get(_join(project_root, "remappings.txt"), ""))
        + foundry_settings["remappings"],
        build_command=_build_command(project_type, config.allow_network),
        test_command=_test_command(project_type),
        framework_config_files=sorted(
            path for path in [foundry_config, *hardhat_configs, package_json] if path in path_set
        ),
        artifact_paths=[
            path
            for path in _existing_dirs(project_path, project_root, _ARTIFACT_DIRS)
            if Path(repository_root / path).exists()
        ],
        excluded_paths=_existing_dirs(project_path, project_root, _EXCLUDED_DIRS),
        discovery_warnings=warnings,
    )


def _inside_project(path: str, project_root: str) -> bool:
    if project_root in {"", "."}:
        return True
    return path == project_root or path.startswith(project_root.rstrip("/") + "/")


def _join(project_root: str, child: str) -> str:
    return child if project_root in {"", "."} else f"{project_root.rstrip('/')}/{child}"


def _existing_dirs(
    project_path: Path,
    project_root: str,
    names: tuple[str, ...],
    *,
    require_solidity: bool = False,
) -> list[str]:
    result: list[str] = []
    for name in names:
        path = project_path / name
        if not path.is_dir():
            continue
        if require_solidity and not any(path.glob("**/*.sol")):
            continue
        result.append(_join(project_root, name))
    return sorted(result)


def _fallback_source_dirs(solidity_paths: list[str]) -> list[str]:
    directories = {
        PurePosixPath(path).parent.as_posix()
        for path in solidity_paths
        if PurePosixPath(path).parent.as_posix() not in {"", "."}
    }
    return sorted(directories or {"."})[:20]


def _plain_project_root(solidity_paths: list[str]) -> str:
    first_parts = {PurePosixPath(path).parts[0] for path in solidity_paths if "/" in path}
    if len(first_parts) == 1 and next(iter(first_parts)) not in {
        "src",
        "contracts",
        "test",
        "tests",
    }:
        return next(iter(first_parts))
    return "."


def _package_has_hardhat(content: str) -> bool:
    if not content.strip():
        return False
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return "hardhat" in content.lower()
    dependencies: dict[str, Any] = {}
    for field in ("dependencies", "devDependencies"):
        value = payload.get(field, {})
        if isinstance(value, dict):
            dependencies.update(value)
    scripts = payload.get("scripts", {})
    script_values = (
        " ".join(str(value) for value in scripts.values()) if isinstance(scripts, dict) else ""
    )
    return "hardhat" in dependencies or "hardhat" in script_values.lower()


def _foundry_settings(content: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "compiler_versions": [],
        "optimizer_enabled": None,
        "optimizer_runs": None,
        "evm_version": None,
        "remappings": [],
    }
    if not content.strip():
        return result
    try:
        payload = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return result
    default = payload.get("profile", {}).get("default", {}) if isinstance(payload, dict) else {}
    if not isinstance(default, dict):
        return result
    for key in ("solc_version", "solc"):
        if value := default.get(key):
            result["compiler_versions"].append(str(value))
    if "optimizer" in default:
        result["optimizer_enabled"] = bool(default["optimizer"])
    if "optimizer_runs" in default:
        with suppress(TypeError, ValueError):
            result["optimizer_runs"] = int(default["optimizer_runs"])
    if value := default.get("evm_version"):
        result["evm_version"] = str(value)
    remappings = default.get("remappings", [])
    if isinstance(remappings, list):
        result["remappings"] = [str(value) for value in remappings]
    return result


def _hardhat_settings(content: str) -> dict[str, Any]:
    versions = re.findall(r"version\s*:\s*['\"]([^'\"]+)['\"]", content)
    versions.extend(re.findall(r"solidity\s*:\s*['\"]([^'\"]+)['\"]", content))
    optimizer_enabled = None
    enabled_match = re.search(r"optimizer\s*:\s*\{[^}]*enabled\s*:\s*(true|false)", content, re.S)
    if enabled_match:
        optimizer_enabled = enabled_match.group(1) == "true"
    runs = None
    runs_match = re.search(r"optimizer\s*:\s*\{[^}]*runs\s*:\s*(\d+)", content, re.S)
    if runs_match:
        runs = int(runs_match.group(1))
    evm_version = None
    evm_match = re.search(r"evmVersion\s*:\s*['\"]([^'\"]+)['\"]", content)
    if evm_match:
        evm_version = evm_match.group(1)
    return {
        "compiler_versions": versions,
        "optimizer_enabled": optimizer_enabled,
        "optimizer_runs": runs,
        "evm_version": evm_version,
    }


def _pragma_versions(content: str) -> list[str]:
    return [match.group(1).strip() for match in _PRAGMA.finditer(content)]


def _remappings(content: str) -> list[str]:
    return [
        line.strip()
        for line in content.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _build_command(project_type: SolidityProjectType, allow_network: bool) -> list[str]:
    if project_type in {SolidityProjectType.FOUNDRY, SolidityProjectType.MIXED}:
        command = ["forge", "build", "--ast", "--build-info", "--build-info-path", "build-info"]
        if not allow_network:
            command.append("--offline")
        return command
    if project_type is SolidityProjectType.HARDHAT:
        return ["hardhat", "compile"]
    return []


def _test_command(project_type: SolidityProjectType) -> list[str]:
    if project_type in {SolidityProjectType.FOUNDRY, SolidityProjectType.MIXED}:
        return ["forge", "test"]
    if project_type is SolidityProjectType.HARDHAT:
        return ["hardhat", "test"]
    return []
