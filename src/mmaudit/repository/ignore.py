"""Small, deterministic gitignore-style matcher."""

from __future__ import annotations

import fnmatch
import re
import unicodedata
from pathlib import Path, PurePosixPath

from mmaudit.constants import DEFAULT_EXCLUSIONS, PERMANENT_EXCLUSIONS


def normalize_relative_path(path: str | Path) -> str:
    value = str(path).replace("\\", "/")
    if len(value.encode("utf-8", errors="surrogatepass")) > 4_096 or any(
        ord(character) == 127 or unicodedata.category(character) in {"Cc", "Cf", "Cs"}
        for character in value
    ):
        raise ValueError("repository paths containing control characters are not supported")
    if re.match(r"^[A-Za-z]:/", value):
        raise ValueError(f"absolute drive path rejected: {value}")
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"unsafe repository-relative path: {value}")
    if any(len(part.encode("utf-8", errors="surrogatepass")) > 255 for part in pure.parts):
        raise ValueError("repository path component exceeds the supported byte length")
    normalized = pure.as_posix()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _matches(path: str, pattern: str, *, is_dir: bool) -> bool:
    rooted = pattern.startswith("/")
    pattern = pattern.lstrip("/")
    directory_pattern = pattern.endswith("/")
    pattern = pattern.rstrip("/")
    if not pattern:
        return False
    path_parts = PurePosixPath(path).parts

    if directory_pattern:
        if "/" in pattern or rooted:
            return path == pattern or path.startswith(pattern + "/")
        return pattern in path_parts[:-1] or (is_dir and pattern in path_parts)

    if "/" not in pattern:
        return fnmatch.fnmatch(PurePosixPath(path).name, pattern) or any(
            fnmatch.fnmatch(part, pattern) for part in path_parts
        )
    return fnmatch.fnmatch(path, pattern) or PurePosixPath(path).match(pattern)


class IgnoreMatcher:
    """Evaluate defaults followed by user rules; safety exclusions are final."""

    def __init__(self, rules: list[str] | None = None) -> None:
        self.rules = [*DEFAULT_EXCLUSIONS, *(rules or [])]

    @classmethod
    def from_file(cls, path: Path | None) -> IgnoreMatcher:
        if path is None or not path.is_file():
            return cls()
        rules: list[str] = []
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if line and not line.startswith("#"):
                rules.append(line)
        return cls(rules)

    def ignored(self, path: str | Path, *, is_dir: bool = False) -> bool:
        normalized = normalize_relative_path(path)
        ignored = False
        for raw_rule in self.rules:
            negated = raw_rule.startswith("!")
            rule = raw_rule[1:] if negated else raw_rule
            if _matches(normalized, rule, is_dir=is_dir):
                ignored = not negated
        if any(_matches(normalized, pattern, is_dir=is_dir) for pattern in PERMANENT_EXCLUSIONS):
            return True
        return ignored

    def may_include_descendant(self, path: str | Path) -> bool:
        """Return whether a negation could re-include something below a directory."""

        directory = normalize_relative_path(path).rstrip("/")
        if any(_matches(directory, pattern, is_dir=True) for pattern in PERMANENT_EXCLUSIONS):
            return False
        normalized = directory + "/"
        for raw_rule in self.rules:
            if not raw_rule.startswith("!"):
                continue
            rule = raw_rule[1:].lstrip("/").rstrip("/")
            metacharacters = [
                index for character in ("*", "?", "[") if (index := rule.find(character)) >= 0
            ]
            literal_prefix = rule[: min(metacharacters)] if metacharacters else rule
            wildcard_may_reach = bool(metacharacters) and (
                not literal_prefix or normalized.startswith(literal_prefix)
            )
            if (
                rule.startswith(normalized)
                or literal_prefix.startswith(normalized)
                or wildcard_may_reach
            ):
                return True
        return False


def safe_ignore_file(root: Path, configured_path: str) -> Path:
    """Resolve an optional ignore file without permitting repository escape."""

    relative = normalize_relative_path(configured_path)
    repository_root = root.resolve(strict=True)
    candidate = repository_root.joinpath(*PurePosixPath(relative).parts)
    try:
        resolved = candidate.resolve(strict=candidate.exists())
        resolved.relative_to(repository_root)
    except (OSError, ValueError) as exc:
        raise ValueError("ignore file must remain inside the repository") from exc
    return resolved
