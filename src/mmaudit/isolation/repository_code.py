"""Static detection of repository configuration that may execute JavaScript."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_HARDHAT_CONFIG_NAMES = frozenset(
    {
        "hardhat.config.cjs",
        "hardhat.config.js",
        "hardhat.config.mjs",
        "hardhat.config.ts",
    }
)
_MAX_PACKAGE_FILES = 2_000
_MAX_PACKAGE_BYTES = 1_000_000
_MAX_INSPECTED_ENTRIES = 200_000


def contains_hardhat_repository_code(root: Path) -> bool:
    """Conservatively identify Hardhat configuration without importing or executing it."""

    repository_root = root.resolve(strict=True)
    package_count = 0
    inspected_entries = 0
    try:
        for candidate in repository_root.rglob("*"):
            inspected_entries += 1
            if inspected_entries > _MAX_INSPECTED_ENTRIES:
                return True
            if candidate.is_symlink() or candidate.is_junction():
                continue
            if not candidate.is_file():
                continue
            name = candidate.name.lower()
            if name in _HARDHAT_CONFIG_NAMES:
                return True
            if name != "package.json":
                continue
            package_count += 1
            if package_count > _MAX_PACKAGE_FILES:
                return True
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(repository_root)
            if resolved.stat().st_size > _MAX_PACKAGE_BYTES:
                return True
            content = resolved.read_text(encoding="utf-8")
            if _package_may_invoke_hardhat(content):
                return True
    except (OSError, UnicodeError, ValueError):
        return True
    return False


def _package_may_invoke_hardhat(content: str) -> bool:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return "hardhat" in content.casefold()
    if not isinstance(payload, dict):
        return False
    dependency_names: set[str] = set()
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        dependencies = payload.get(field)
        if isinstance(dependencies, dict):
            dependency_names.update(str(name).casefold() for name in dependencies)
    if any("hardhat" in name for name in dependency_names):
        return True
    scripts: Any = payload.get("scripts")
    return isinstance(scripts, dict) and any(
        "hardhat" in str(command).casefold() for command in scripts.values()
    )
