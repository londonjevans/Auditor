"""Read-only, bounded repository file discovery."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from mmaudit.config import RepositoryConfig
from mmaudit.repository.ignore import IgnoreMatcher, normalize_relative_path


class RepositorySafetyError(RuntimeError):
    """Raised for traversal, inaccessible roots, or unsafe git input."""


@dataclass(frozen=True)
class DiscoveredFile:
    absolute_path: Path
    relative_path: str
    content: str
    size: int
    lines: int
    sha256: str
    language: str
    categories: tuple[str, ...]


@dataclass(frozen=True)
class DiscoveryResult:
    root: Path
    files: tuple[DiscoveredFile, ...]
    omitted: tuple[str, ...]
    changed_paths: frozenset[str]
    git_commit: str | None


_LANGUAGES = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".c": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".h": "C/C++ Header",
    ".hpp": "C++ Header",
    ".sol": "Solidity",
    ".sh": "Shell",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".json": "JSON",
    ".toml": "TOML",
    ".xml": "XML",
    ".tf": "Terraform",
    ".sql": "SQL",
    ".html": "HTML",
    ".jinja": "Template",
    ".j2": "Template",
    ".md": "Markdown",
}

_MANIFESTS = {
    "pyproject.toml",
    "requirements.txt",
    "package.json",
    "foundry.toml",
    "remappings.txt",
    "hardhat.config.js",
    "hardhat.config.cjs",
    "hardhat.config.mjs",
    "hardhat.config.ts",
    "brownie-config.yaml",
    "go.mod",
    "cargo.toml",
    "gemfile",
    "pom.xml",
    "build.gradle",
    "composer.json",
}


def _contained(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _is_linklike(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def safe_repository_root(path: Path) -> Path:
    try:
        root = path.resolve(strict=True)
    except OSError as exc:
        raise RepositorySafetyError(f"repository is inaccessible: {path}") from exc
    if not root.is_dir():
        raise RepositorySafetyError(f"repository path is not a directory: {path}")
    filesystem_root = Path(root.anchor)
    if root == filesystem_root:
        raise RepositorySafetyError("filesystem root cannot be audited as a repository")
    try:
        home = Path.home().resolve(strict=True)
    except OSError:
        home = None
    if home is not None and (root == home or root in home.parents):
        raise RepositorySafetyError(
            "home directory or an ancestor of it cannot be audited as a repository"
        )
    return root


def is_binary(data: bytes) -> bool:
    if b"\x00" in data:
        return True
    sample = data[:8_192]
    if not sample:
        return False
    control = sum(byte < 9 or 13 < byte < 32 for byte in sample)
    return control / len(sample) > 0.15


def _categories(path: str, content: str, changed: bool) -> tuple[str, ...]:
    lower_path = path.lower()
    lower = content[:100_000].lower()
    categories: set[str] = set()
    basename = PureName(path).lower
    if basename in _MANIFESTS or lower_path.endswith((".lock", "dockerfile")):
        categories.add("dependency")
    if any(
        token in lower_path for token in ("config", ".github/", "docker", "deploy", "terraform")
    ):
        categories.add("configuration")
    if any(token in lower_path for token in ("route", "controller", "handler", "api/", "views")):
        categories.add("api")
    if any(token in lower_path for token in ("auth", "permission", "policy", "middleware")):
        categories.add("auth")
    if any(token in lower_path for token in ("model", "repository", "database", "db/", "query")):
        categories.add("data")
    if any(token in lower_path for token in ("upload", "file", "storage")):
        categories.add("file")
    if any(token in lower_path for token in ("test", "spec")):
        categories.add("test")
    if lower_path.endswith(".sol"):
        categories.add("smart_contract")
        if (
            lower_path.endswith(".t.sol")
            or "/test/" in lower_path
            or lower_path.startswith("test/")
        ):
            categories.update({"test", "evm_test"})
        evm_keyword_groups = {
            "evm_auth": (
                "onlyowner",
                "accesscontrol",
                "hasrole",
                "msg.sender",
                "owner()",
                "initializer",
            ),
            "evm_external_call": (
                ".call{",
                ".call(",
                ".delegatecall",
                ".staticcall",
                ".send(",
                ".transfer(",
            ),
            "evm_upgrade": (
                "uups",
                "upgradeable",
                "upgradeto",
                "proxy",
                "delegatecall",
                "initializer",
                "reinitializer",
            ),
            "evm_value": ("payable", "msg.value", ".balance", "withdraw", "deposit"),
            "evm_signature": ("ecrecover", "eip712", "permit(", "nonces", "signature"),
            "evm_oracle": ("oracle", "chainlink", "latestrounddata", "pricefeed"),
            "evm_token": (
                "erc20",
                "erc721",
                "erc1155",
                "transferfrom",
                "allowance",
                "mint",
                "burn",
            ),
            "evm_storage": ("mapping(", "mapping (", "struct ", "storage "),
        }
        for category, keywords in evm_keyword_groups.items():
            if any(keyword in lower for keyword in keywords):
                categories.add(category)
        if any(
            keyword in lower
            for keyword in (
                "claim",
                "redeem",
                "stake",
                "unstake",
                "reward",
                "auction",
                "refund",
                "vote",
                "governance",
                "borrow",
                "repay",
                "liquidat",
            )
        ):
            categories.add("business_logic")
    keyword_groups = {
        "network": ("httpx", "requests.", "fetch(", "axios", "urlopen", "net/http"),
        "sensitive": ("password", "token", "secret", "credit_card", "ssn", "personal"),
        "serialization": ("pickle", "yaml.load", "deserialize", "marshal", "json.loads"),
        "command": ("subprocess", "os.system", "exec(", "child_process"),
        "business_logic": ("payment", "refund", "invite", "approve", "quota", "idempot"),
    }
    for category, keywords in keyword_groups.items():
        if any(keyword in lower for keyword in keywords):
            categories.add(category)
    if changed:
        categories.add("changed")
    if not categories:
        categories.add("source")
    return tuple(sorted(categories))


class PureName:
    """Tiny helper that avoids platform-specific case handling in discovery."""

    def __init__(self, path: str) -> None:
        self.lower = path.rsplit("/", 1)[-1].lower()


def _changed_paths(root: Path, git_ref: str | None) -> frozenset[str]:
    if git_ref is None:
        return frozenset()
    if (
        len(git_ref) > 256
        or git_ref.startswith("-")
        or not re.fullmatch(r"[A-Za-z0-9_./~^{}-]+", git_ref)
    ):
        raise RepositorySafetyError("changed-since is not a safe git ref")
    executable = _git_executable(root)
    if executable is None:
        raise RepositorySafetyError("git is unavailable or resolved from inside the repository")
    command = [
        executable,
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-C",
        str(root),
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--name-only",
        "-z",
        "--diff-filter=ACMRT",
        f"{git_ref}...HEAD",
        "--",
    ]
    environment = _git_environment()
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RepositorySafetyError("unable to calculate changed files") from exc
    if result.returncode != 0:
        raise RepositorySafetyError("git rejected the changed-since reference")
    return frozenset(
        normalize_relative_path(value)
        for value in result.stdout.decode("utf-8", errors="replace").split("\0")
        if value
    )


def _git_commit(root: Path) -> str | None:
    executable = _git_executable(root)
    if executable is None:
        return None
    try:
        result = subprocess.run(
            [executable, "-C", str(root), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=_git_environment(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = result.stdout.strip()
    return value if result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40,64}", value) else None


def _git_executable(root: Path) -> str | None:
    executable = shutil.which("git")
    if executable is None:
        return None
    try:
        resolved = Path(executable).resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except ValueError:
        return str(resolved)
    except OSError:
        return None
    return None


def _git_environment() -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }
    if os.name == "nt":
        for key in ("SYSTEMROOT", "WINDIR", "PATHEXT"):
            if key in os.environ:
                environment[key] = os.environ[key]
    return environment


def discover_repository(
    root_path: Path,
    config: RepositoryConfig,
    matcher: IgnoreMatcher,
    *,
    changed_since: str | None = None,
) -> DiscoveryResult:
    """Discover bounded UTF-8-ish text files without following unsafe links."""

    root = safe_repository_root(root_path)
    changed = _changed_paths(root, changed_since)
    files: list[DiscoveredFile] = []
    omitted: list[str] = []
    retained_content_bytes = 0
    walked_entries = 0
    visited_directories = {root}
    for directory, directory_names, filenames in os.walk(
        root, topdown=True, followlinks=config.follow_symlinks
    ):
        walked_entries += len(directory_names) + len(filenames)
        if walked_entries > config.max_walk_entries:
            omitted.append("repository: max_walk_entries reached")
            return DiscoveryResult(
                root=root,
                files=tuple(files),
                omitted=tuple(omitted),
                changed_paths=changed,
                git_commit=_git_commit(root),
            )
        current = Path(directory)
        retained_dirs: list[str] = []
        for name in sorted(directory_names):
            candidate = current / name
            try:
                relative = normalize_relative_path(candidate.relative_to(root))
            except (UnicodeError, ValueError):
                omitted.append("repository directory omitted: unsupported path")
                continue
            if matcher.ignored(
                relative,
                is_dir=True,
            ) and not matcher.may_include_descendant(relative):
                continue
            if _is_linklike(candidate):
                try:
                    resolved = candidate.resolve(strict=True)
                except OSError:
                    omitted.append(f"{relative}: broken symlink")
                    continue
                if not config.follow_symlinks or not _contained(root, resolved):
                    omitted.append(f"{relative}: symlink excluded")
                    continue
                if resolved in visited_directories:
                    omitted.append(f"{relative}: symlink cycle or duplicate directory excluded")
                    continue
                visited_directories.add(resolved)
            retained_dirs.append(name)
        directory_names[:] = retained_dirs

        for filename in sorted(filenames):
            candidate = current / filename
            try:
                relative = normalize_relative_path(candidate.relative_to(root))
            except (UnicodeError, ValueError):
                omitted.append("repository file omitted: unsupported path")
                continue
            if matcher.ignored(relative):
                continue
            if _is_linklike(candidate):
                try:
                    resolved = candidate.resolve(strict=True)
                except OSError:
                    omitted.append(f"{relative}: broken symlink")
                    continue
                if not config.follow_symlinks or not _contained(root, resolved):
                    omitted.append(f"{relative}: symlink excluded")
                    continue
            else:
                resolved = candidate.resolve()
            if not _contained(root, resolved):
                omitted.append(f"{relative}: escaped repository")
                continue
            try:
                file_stat = candidate.stat()
            except OSError:
                omitted.append(f"{relative}: unreadable")
                continue
            if file_stat.st_nlink > 1:
                omitted.append(f"{relative}: hardlink excluded")
                continue
            size = file_stat.st_size
            if size > config.max_file_bytes:
                omitted.append(f"{relative}: exceeds max_file_bytes")
                continue
            try:
                data = candidate.read_bytes()
            except OSError:
                omitted.append(f"{relative}: unreadable")
                continue
            if is_binary(data):
                omitted.append(f"{relative}: binary")
                continue
            content = data.decode("utf-8", errors="replace")
            lower_relative = relative.lower()
            if not config.include_tests and any(
                part in {"test", "tests", "spec", "specs"} for part in lower_relative.split("/")
            ):
                continue
            if not config.include_docs and lower_relative.endswith(
                (".md", ".rst", ".adoc", ".txt")
            ):
                continue
            retained_content = content
            if retained_content_bytes + len(data) > config.max_discovery_bytes:
                retained_content = ""
                omitted.append(f"{relative}: mapped without content after max_discovery_bytes")
            else:
                retained_content_bytes += len(data)
            files.append(
                DiscoveredFile(
                    absolute_path=resolved,
                    relative_path=relative,
                    content=retained_content,
                    size=len(data),
                    lines=len(content.splitlines()),
                    sha256=hashlib.sha256(data).hexdigest(),
                    language=_LANGUAGES.get(candidate.suffix.lower(), "Text"),
                    categories=_categories(relative, content, relative in changed),
                )
            )
            if len(files) >= config.max_files:
                omitted.append("repository: max_files reached")
                return DiscoveryResult(
                    root=root,
                    files=tuple(files),
                    omitted=tuple(omitted),
                    changed_paths=changed,
                    git_commit=_git_commit(root),
                )
    return DiscoveryResult(
        root=root,
        files=tuple(files),
        omitted=tuple(omitted),
        changed_paths=changed,
        git_commit=_git_commit(root),
    )
