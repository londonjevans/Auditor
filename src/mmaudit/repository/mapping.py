"""Compact deterministic repository map construction."""

from __future__ import annotations

from collections import Counter
from pathlib import PurePosixPath

from mmaudit.models.schemas import RepositoryFile, RepositoryMap
from mmaudit.repository.discovery import DiscoveryResult


def _paths_with_category(discovery: DiscoveryResult, category: str) -> list[str]:
    return [item.relative_path for item in discovery.files if category in item.categories][:100]


def _detect_frameworks(discovery: DiscoveryResult) -> list[str]:
    names = {PurePosixPath(item.relative_path).name.lower() for item in discovery.files}
    combined = "\n".join(
        item.content[:50_000]
        for item in discovery.files
        if PurePosixPath(item.relative_path).name.lower()
        in {
            "pyproject.toml",
            "requirements.txt",
            "package.json",
            "go.mod",
            "cargo.toml",
            "foundry.toml",
            "remappings.txt",
            "hardhat.config.js",
            "hardhat.config.cjs",
            "hardhat.config.mjs",
            "hardhat.config.ts",
        }
    ).lower()
    signatures = {
        "Django": ("django",),
        "Flask": ("flask",),
        "FastAPI": ("fastapi",),
        "Express": ("express",),
        "Next.js": ("next", "package.json"),
        "React": ("react",),
        "Rails": ("rails",),
        "Spring": ("spring-boot",),
        "Gin": ("github.com/gin-gonic/gin",),
        "Actix": ("actix-web",),
        "Foundry": ("foundry", "foundry.toml"),
        "Hardhat": ("hardhat", "package.json"),
        "OpenZeppelin Contracts": ("openzeppelin",),
        "Chainlink": ("chainlink",),
    }
    frameworks: list[str] = []
    for framework, tokens in signatures.items():
        if tokens[0] in combined and (len(tokens) == 1 or tokens[1] in names):
            frameworks.append(framework)
    if "foundry.toml" in names and "Foundry" not in frameworks:
        frameworks.append("Foundry")
    if {
        "hardhat.config.cjs",
        "hardhat.config.js",
        "hardhat.config.mjs",
        "hardhat.config.ts",
    } & names and "Hardhat" not in frameworks:
        frameworks.append("Hardhat")
    return sorted(frameworks)


def build_repository_map(
    discovery: DiscoveryResult,
    *,
    changed_since: str | None = None,
) -> RepositoryMap:
    language_counts = Counter(item.language for item in discovery.files)
    manifests = [item.relative_path for item in discovery.files if "dependency" in item.categories]
    entry_names = {
        "main.py",
        "app.py",
        "manage.py",
        "server.py",
        "index.js",
        "index.ts",
        "main.go",
        "main.rs",
    }
    entry_points = [
        item.relative_path
        for item in discovery.files
        if PurePosixPath(item.relative_path).name.lower() in entry_names
        or item.relative_path.startswith(("cmd/", "src/main"))
    ]
    return RepositoryMap(
        root_name=discovery.root.name,
        git_commit=discovery.git_commit,
        changed_since=changed_since,
        languages=dict(sorted(language_counts.items())),
        frameworks=_detect_frameworks(discovery),
        manifests=manifests[:100],
        entry_points=entry_points[:100],
        api_surfaces=[
            *_paths_with_category(discovery, "api"),
            *_paths_with_category(discovery, "smart_contract"),
        ][:100],
        auth_components=[
            *_paths_with_category(discovery, "auth"),
            *_paths_with_category(discovery, "evm_auth"),
        ][:100],
        data_layers=[
            *_paths_with_category(discovery, "data"),
            *_paths_with_category(discovery, "evm_storage"),
        ][:100],
        network_clients=[
            *_paths_with_category(discovery, "network"),
            *_paths_with_category(discovery, "evm_external_call"),
            *_paths_with_category(discovery, "evm_oracle"),
        ][:100],
        file_handlers=_paths_with_category(discovery, "file"),
        configuration_files=_paths_with_category(discovery, "configuration"),
        sensitive_processing=[
            *_paths_with_category(discovery, "sensitive"),
            *_paths_with_category(discovery, "evm_value"),
            *_paths_with_category(discovery, "evm_signature"),
        ][:100],
        security_tests=[
            path
            for path in _paths_with_category(discovery, "test")
            if any(
                token in path.lower()
                for token in (
                    "security",
                    "auth",
                    "permission",
                    "tenant",
                    "audit",
                    ".t.sol",
                )
            )
        ],
        files=[
            RepositoryFile(
                path=item.relative_path,
                size=item.size,
                lines=item.lines,
                sha256=item.sha256,
                language=item.language,
                categories=list(item.categories),
            )
            for item in discovery.files
        ],
        omitted_files=list(discovery.omitted),
    )
