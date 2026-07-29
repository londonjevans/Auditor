"""Deterministic, read-only selection of repository-owned Foundry tests."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from mmaudit.config import SmartContractsConfig
from mmaudit.models.schemas import (
    RepositorySuiteFramework,
    RepositorySuiteSelection,
    RepositorySuiteTestDescriptor,
    SolidityProjectMetadata,
    SolidityProjectType,
)
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.scanners.base import scanner_workspace_sha256

_FOUNDRY_PROJECT_TYPES = frozenset(
    {
        SolidityProjectType.FOUNDRY,
        SolidityProjectType.MIXED,
    }
)
_FUNCTION_DECLARATION = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CONTRACT_DECLARATION = re.compile(
    r"\b(?P<abstract>abstract\s+)?contract\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_SAFE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MAX_WALKED_ENTRIES = 100_000
_MAX_SOURCE_BYTES = 10_000_000
_MAX_FUNCTION_DECLARATIONS = 10_000
_GLOB_MAGIC = frozenset("*?[")


class RepositorySuiteSelectionError(ValueError):
    """Raised before execution when suite selection is unsafe or ambiguous."""


@dataclass(frozen=True)
class _ContractScope:
    name: str
    start: int
    end: int
    abstract: bool
    bases: tuple[str, ...]


@dataclass(frozen=True)
class _ParsedFoundryTest:
    suite_name: str
    test_name: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class _CandidateFile:
    project_root: str
    path: str
    absolute_path: Path
    source: bytes
    source_sha256: str


def select_foundry_repository_suite(
    repository_root: Path,
    projects: Sequence[SolidityProjectMetadata],
    smart_contracts: SmartContractsConfig,
    *,
    private_dir: Path | None = None,
) -> RepositorySuiteSelection:
    """Select an exact bounded Foundry test inventory without executing repository code."""

    suite_config = smart_contracts.repository_suite
    if not suite_config.foundry_include_paths or not suite_config.foundry_include_tests:
        raise RepositorySuiteSelectionError("Foundry repository-suite selection is disabled")

    root = _validated_repository_root(repository_root)
    candidates = _discover_candidate_files(root, projects)
    try:
        repository_sha256 = scanner_workspace_sha256(root, private_dir)
    except (OSError, ValueError) as exc:
        raise RepositorySuiteSelectionError(
            "repository suite could not bind the complete scanner workspace"
        ) from exc
    parsed_inventory = tuple(
        (candidate, _parse_foundry_tests(candidate.source)) for candidate in candidates
    )
    candidate_files = {
        (candidate.project_root, candidate.path)
        for candidate, parsed_tests in parsed_inventory
        if parsed_tests
    }
    candidate_test_count = sum(len(parsed_tests) for _, parsed_tests in parsed_inventory)
    descriptors: list[RepositorySuiteTestDescriptor] = []
    exact_bare_matches: dict[str, set[tuple[str, str, str]]] = {
        pattern: set()
        for pattern in suite_config.foundry_include_tests
        if not _has_glob_magic(pattern)
    }

    for candidate, parsed_tests in parsed_inventory:
        include_paths = _include_paths_for_project(
            profile=suite_config.profile,
            configured=suite_config.foundry_include_paths,
            project_root=candidate.project_root,
        )
        if not _matches_any_path(candidate.path, include_paths) or _matches_any_path(
            candidate.path,
            suite_config.foundry_exclude_paths,
        ):
            continue
        seen_file_keys: set[tuple[str, str]] = set()
        selected_in_file = 0
        for parsed in parsed_tests:
            stable_id = _stable_test_id(
                candidate.path,
                parsed.suite_name,
                parsed.test_name,
            )
            if not _matches_test(
                parsed.test_name,
                stable_id,
                suite_config.foundry_include_tests,
            ):
                continue
            if _matches_test(
                parsed.test_name,
                stable_id,
                suite_config.foundry_exclude_tests,
            ):
                continue
            key = (parsed.suite_name, parsed.test_name)
            if key in seen_file_keys:
                raise RepositorySuiteSelectionError(
                    f"ambiguous duplicate Foundry test identity: {stable_id}"
                )
            seen_file_keys.add(key)
            selected_in_file += 1
            if selected_in_file > suite_config.max_tests_per_file:
                raise RepositorySuiteSelectionError(
                    f"selected Foundry tests exceed per-file ceiling for {candidate.path}"
                )
            for exact_name in exact_bare_matches:
                if parsed.test_name == exact_name:
                    exact_bare_matches[exact_name].add(
                        (candidate.path, parsed.suite_name, parsed.test_name)
                    )
            descriptors.append(
                RepositorySuiteTestDescriptor.sealed(
                    framework=RepositorySuiteFramework.FOUNDRY,
                    project_root=candidate.project_root,
                    path=candidate.path,
                    suite_name=parsed.suite_name,
                    test_name=parsed.test_name,
                    source_sha256=candidate.source_sha256,
                    start_line=parsed.start_line,
                    end_line=parsed.end_line,
                )
            )

    for exact_name, matches in exact_bare_matches.items():
        if len(matches) > 1:
            raise RepositorySuiteSelectionError(
                f"exact bare test selector is ambiguous: {exact_name}"
            )

    descriptors.sort(key=lambda item: item.canonical_key)
    canonical_keys = [descriptor.canonical_key for descriptor in descriptors]
    if len(canonical_keys) != len(set(canonical_keys)):
        raise RepositorySuiteSelectionError("selected Foundry test identities are duplicated")
    if not descriptors:
        raise RepositorySuiteSelectionError("Foundry repository-suite selection matched zero tests")

    selected_files = {(descriptor.project_root, descriptor.path) for descriptor in descriptors}
    if len(selected_files) > suite_config.max_selected_files:
        raise RepositorySuiteSelectionError("selected Foundry files exceed configured ceiling")
    if len(descriptors) > suite_config.max_total_tests:
        raise RepositorySuiteSelectionError(
            "selected Foundry tests exceed configured total ceiling"
        )

    return RepositorySuiteSelection.sealed(
        profile=suite_config.profile,
        repository_sha256=repository_sha256,
        configuration_sha256=suite_config.stable_hash(),
        candidate_file_count=len(candidate_files),
        candidate_test_count=candidate_test_count,
        selected_file_count=len(selected_files),
        selected_test_count=len(descriptors),
        omitted_file_count=len(candidate_files - selected_files),
        omitted_test_count=candidate_test_count - len(descriptors),
        limit_reached=False,
        tests=tuple(descriptors),
        safety_claim=False,
    )


def _validated_repository_root(repository_root: Path) -> Path:
    try:
        if repository_root.is_symlink() or repository_root.is_junction():
            raise RepositorySuiteSelectionError("repository suite root cannot be a link")
        root = repository_root.resolve(strict=True)
    except OSError as exc:
        raise RepositorySuiteSelectionError("repository suite root is inaccessible") from exc
    if not root.is_dir():
        raise RepositorySuiteSelectionError("repository suite root is not a directory")
    return root


def _discover_candidate_files(
    repository_root: Path,
    projects: Sequence[SolidityProjectMetadata],
) -> tuple[_CandidateFile, ...]:
    project_roots: set[str] = set()
    owners: dict[str, tuple[str, str]] = {}
    candidates: list[_CandidateFile] = []
    walked_entries = 0

    for project in sorted(projects, key=lambda item: (item.project_root, item.project_type.value)):
        if project.project_type not in _FOUNDRY_PROJECT_TYPES:
            continue
        project_root = _normalized_project_root(project.project_root)
        if project_root in project_roots:
            raise RepositorySuiteSelectionError(
                f"ambiguous duplicate Foundry project root: {project_root}"
            )
        project_roots.add(project_root)
        project_path = _validated_directory(
            repository_root,
            project_root,
            description="Foundry project root",
        )
        test_directories = tuple(sorted(project.test_directories))
        if len(test_directories) != len(set(test_directories)):
            raise RepositorySuiteSelectionError(
                f"duplicate Foundry test directory metadata for {project_root}"
            )
        for configured_test_directory in test_directories:
            test_directory = _normalized_file_path(configured_test_directory)
            if not _path_is_within_project(test_directory, project_root):
                raise RepositorySuiteSelectionError(
                    f"Foundry test directory escapes its project root: {test_directory}"
                )
            test_path = _validated_directory(
                repository_root,
                test_directory,
                description="Foundry test directory",
            )
            try:
                test_path.relative_to(project_path)
            except ValueError as exc:
                raise RepositorySuiteSelectionError(
                    f"Foundry test directory escapes its project root: {test_directory}"
                ) from exc
            for absolute_path in _walk_regular_files(test_path):
                walked_entries += 1
                if walked_entries > _MAX_WALKED_ENTRIES:
                    raise RepositorySuiteSelectionError(
                        "Foundry test discovery exceeds the bounded entry ceiling"
                    )
                if not absolute_path.name.endswith(".t.sol"):
                    continue
                raw_relative_path = absolute_path.relative_to(repository_root).as_posix()
                try:
                    relative_path = normalize_relative_path(raw_relative_path)
                except ValueError as exc:
                    raise RepositorySuiteSelectionError(
                        "Foundry test candidate path is unsafe"
                    ) from exc
                if relative_path != raw_relative_path:
                    raise RepositorySuiteSelectionError(
                        "Foundry test candidate path is not canonical"
                    )
                prior_owner = owners.get(relative_path)
                owner = (project_root, test_directory)
                if prior_owner is not None:
                    raise RepositorySuiteSelectionError(
                        f"Foundry test file has ambiguous project ownership: {relative_path}"
                    )
                owners[relative_path] = owner
                source = _read_regular_source(repository_root, absolute_path)
                candidates.append(
                    _CandidateFile(
                        project_root=project_root,
                        path=relative_path,
                        absolute_path=absolute_path,
                        source=source,
                        source_sha256=hashlib.sha256(source).hexdigest(),
                    )
                )

    return tuple(sorted(candidates, key=lambda item: (item.project_root, item.path)))


def _walk_regular_files(directory: Path) -> tuple[Path, ...]:
    result: list[Path] = []
    pending = [directory]
    seen_entries = 0
    while pending:
        current = pending.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda item: item.name)
        except OSError as exc:
            raise RepositorySuiteSelectionError(
                "Foundry test directory cannot be enumerated safely"
            ) from exc
        directories: list[Path] = []
        for entry in entries:
            seen_entries += 1
            if seen_entries > _MAX_WALKED_ENTRIES:
                raise RepositorySuiteSelectionError(
                    "Foundry test discovery exceeds the bounded entry ceiling"
                )
            path = Path(entry.path)
            if entry.is_symlink() or path.is_junction():
                raise RepositorySuiteSelectionError(
                    f"Foundry test directory contains a link: {path.name}"
                )
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise RepositorySuiteSelectionError(
                    "Foundry test entry cannot be inspected safely"
                ) from exc
            if stat.S_ISDIR(entry_stat.st_mode):
                directories.append(path)
            elif stat.S_ISREG(entry_stat.st_mode):
                result.append(path)
            elif path.name.endswith(".t.sol"):
                raise RepositorySuiteSelectionError("Foundry test candidate is not a regular file")
        pending.extend(reversed(directories))
    return tuple(sorted(result))


def _read_regular_source(repository_root: Path, path: Path) -> bytes:
    try:
        relative = path.relative_to(repository_root)
        _reject_link_components(repository_root, relative)
        before = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise RepositorySuiteSelectionError("Foundry test candidate is not a regular file")
        if before.st_nlink != 1:
            raise RepositorySuiteSelectionError("Foundry test candidate cannot be hard-linked")
        if before.st_size > _MAX_SOURCE_BYTES:
            raise RepositorySuiteSelectionError("Foundry test source exceeds the byte ceiling")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or opened.st_nlink != 1
            ):
                raise RepositorySuiteSelectionError(
                    "Foundry test candidate changed during selection"
                )
            source = os.read(descriptor, _MAX_SOURCE_BYTES + 1)
            if os.read(descriptor, 1):
                source += b"x"
        finally:
            os.close(descriptor)
    except RepositorySuiteSelectionError:
        raise
    except OSError as exc:
        raise RepositorySuiteSelectionError("Foundry test candidate cannot be read safely") from exc
    if len(source) > _MAX_SOURCE_BYTES:
        raise RepositorySuiteSelectionError("Foundry test source exceeds the byte ceiling")
    try:
        source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RepositorySuiteSelectionError("Foundry test source is not valid UTF-8") from exc
    return source


def _parse_foundry_tests(source: bytes) -> tuple[_ParsedFoundryTest, ...]:
    text = source.decode("utf-8")
    masked = _mask_non_code(text)
    scopes = _contract_scopes(masked)
    if any(not scope.abstract and scope.bases for scope in scopes):
        raise RepositorySuiteSelectionError(
            "Foundry test inheritance requires isolated inventory reconciliation"
        )
    declarations = list(_FUNCTION_DECLARATION.finditer(masked))
    if len(declarations) > _MAX_FUNCTION_DECLARATIONS:
        raise RepositorySuiteSelectionError(
            "Foundry test source exceeds the function declaration ceiling"
        )
    parsed: list[_ParsedFoundryTest] = []
    for declaration in declarations:
        test_name = declaration.group(1)
        if not (test_name.startswith("test") or test_name.startswith("invariant")):
            continue
        if _SAFE_NAME.fullmatch(test_name) is None:
            raise RepositorySuiteSelectionError("Foundry test name is invalid")
        suite = _containing_contract(scopes, declaration.start())
        if suite is None or suite.abstract:
            continue
        opening_parenthesis = declaration.end() - 1
        closing_parenthesis = _matching_delimiter(
            masked,
            opening_parenthesis,
            opening="(",
            closing=")",
        )
        body_start = _function_body_start(masked, closing_parenthesis + 1)
        if body_start is None:
            continue
        header = masked[closing_parenthesis + 1 : body_start]
        if not {"public", "external"}.intersection(_top_level_header_words(header)):
            continue
        if (
            test_name.startswith("invariant")
            and masked[opening_parenthesis + 1 : closing_parenthesis].strip()
        ):
            raise RepositorySuiteSelectionError(
                f"Foundry invariant must not accept parameters: {test_name}"
            )
        body_end = _matching_delimiter(masked, body_start, opening="{", closing="}")
        start_line = _line_number(masked, declaration.start())
        end_line = _line_number(masked, body_end)
        if end_line < start_line:
            raise RepositorySuiteSelectionError("Foundry test source range is invalid")
        parsed.append(
            _ParsedFoundryTest(
                suite_name=suite.name,
                test_name=test_name,
                start_line=start_line,
                end_line=end_line,
            )
        )
    return tuple(
        sorted(
            parsed,
            key=lambda item: (
                item.suite_name,
                item.test_name,
                item.start_line,
                item.end_line,
            ),
        )
    )


def _contract_scopes(masked: str) -> tuple[_ContractScope, ...]:
    scopes: list[_ContractScope] = []
    names: set[str] = set()
    for declaration in _CONTRACT_DECLARATION.finditer(masked):
        name = declaration.group("name")
        if name in names:
            raise RepositorySuiteSelectionError(f"duplicate Foundry contract name: {name}")
        body_start = _declaration_body_start(masked, declaration.end())
        if body_start is None:
            continue
        body_end = _matching_delimiter(masked, body_start, opening="{", closing="}")
        bases = _contract_base_names(masked[declaration.end() : body_start])
        names.add(name)
        scopes.append(
            _ContractScope(
                name=name,
                start=body_start,
                end=body_end,
                abstract=declaration.group("abstract") is not None,
                bases=bases,
            )
        )
    return tuple(sorted(scopes, key=lambda item: (item.start, item.end, item.name)))


def _contract_base_names(header: str) -> tuple[str, ...]:
    """Parse bounded inheritance names only to prevent silent inherited-test omission."""

    words = list(re.finditer(r"[A-Za-z_][A-Za-z0-9_]*", header))
    inheritance = next((match for match in words if match.group(0) == "is"), None)
    if inheritance is None:
        return ()
    suffix = header[inheritance.end() :]
    bases: list[str] = []
    start = 0
    parenthesis_depth = 0
    segments: list[str] = []
    for index, character in enumerate(suffix):
        if character == "(":
            parenthesis_depth += 1
        elif character == ")":
            parenthesis_depth -= 1
            if parenthesis_depth < 0:
                raise RepositorySuiteSelectionError("unbalanced Solidity inheritance")
        elif character == "," and parenthesis_depth == 0:
            segments.append(suffix[start:index])
            start = index + 1
    if parenthesis_depth:
        raise RepositorySuiteSelectionError("unbalanced Solidity inheritance")
    segments.append(suffix[start:])
    for segment in segments:
        name = segment.partition("(")[0].strip()
        if not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*",
            name,
        ):
            raise RepositorySuiteSelectionError("Foundry contract inheritance is ambiguous")
        bases.append(name)
    return tuple(bases)


def _declaration_body_start(masked: str, start: int) -> int | None:
    parenthesis_depth = 0
    for index in range(start, len(masked)):
        character = masked[index]
        if character == "(":
            parenthesis_depth += 1
        elif character == ")":
            parenthesis_depth -= 1
            if parenthesis_depth < 0:
                raise RepositorySuiteSelectionError("unbalanced Solidity declaration")
        elif character == ";" and parenthesis_depth == 0:
            return None
        elif character == "{" and parenthesis_depth == 0:
            return index
    raise RepositorySuiteSelectionError("unterminated Solidity contract declaration")


def _function_body_start(masked: str, start: int) -> int | None:
    parenthesis_depth = 0
    bracket_depth = 0
    for index in range(start, len(masked)):
        character = masked[index]
        if character == "(":
            parenthesis_depth += 1
        elif character == ")":
            parenthesis_depth -= 1
        elif character == "[":
            bracket_depth += 1
        elif character == "]":
            bracket_depth -= 1
        elif character == ";" and parenthesis_depth == 0 and bracket_depth == 0:
            return None
        elif character == "{" and parenthesis_depth == 0 and bracket_depth == 0:
            return index
        if parenthesis_depth < 0 or bracket_depth < 0:
            raise RepositorySuiteSelectionError("unbalanced Solidity function declaration")
    raise RepositorySuiteSelectionError("unterminated Solidity function declaration")


def _top_level_header_words(header: str) -> frozenset[str]:
    top_level = list(header)
    parenthesis_depth = 0
    bracket_depth = 0
    for index, character in enumerate(header):
        if character == "(":
            parenthesis_depth += 1
        elif character == ")":
            parenthesis_depth -= 1
        elif character == "[":
            bracket_depth += 1
        elif character == "]":
            bracket_depth -= 1
        elif parenthesis_depth or bracket_depth:
            top_level[index] = " "
        if parenthesis_depth < 0 or bracket_depth < 0:
            raise RepositorySuiteSelectionError("unbalanced Solidity function declaration")
    if parenthesis_depth or bracket_depth:
        raise RepositorySuiteSelectionError("unbalanced Solidity function declaration")
    return frozenset(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", "".join(top_level)))


def _matching_delimiter(
    masked: str,
    start: int,
    *,
    opening: str,
    closing: str,
) -> int:
    if start >= len(masked) or masked[start] != opening:
        raise RepositorySuiteSelectionError("Solidity delimiter start is invalid")
    depth = 0
    for index in range(start, len(masked)):
        character = masked[index]
        if character == opening:
            depth += 1
        elif character == closing:
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                break
    raise RepositorySuiteSelectionError("unbalanced Solidity delimiters")


def _mask_non_code(source: str) -> str:
    masked = list(source)
    state = "code"
    index = 0
    while index < len(source):
        character = source[index]
        next_character = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if character == "/" and next_character == "/":
                masked[index] = masked[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if character == "/" and next_character == "*":
                masked[index] = masked[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if character in {'"', "'"}:
                masked[index] = " "
                state = character
                index += 1
                continue
        elif state == "line_comment":
            if character == "\n":
                state = "code"
            else:
                masked[index] = " "
        elif state == "block_comment":
            if character == "*" and next_character == "/":
                masked[index] = masked[index + 1] = " "
                state = "code"
                index += 2
                continue
            if character != "\n":
                masked[index] = " "
        else:
            if character == "\\":
                masked[index] = " "
                if index + 1 < len(source):
                    if source[index + 1] != "\n":
                        masked[index + 1] = " "
                    index += 2
                    continue
            elif character == state:
                masked[index] = " "
                state = "code"
                index += 1
                continue
            elif character != "\n":
                masked[index] = " "
        index += 1
    if state in {"block_comment", '"', "'"}:
        raise RepositorySuiteSelectionError("unterminated Solidity comment or string")
    return "".join(masked)


def _containing_contract(
    scopes: tuple[_ContractScope, ...],
    offset: int,
) -> _ContractScope | None:
    matches = [scope for scope in scopes if scope.start < offset < scope.end]
    if not matches:
        return None
    return min(matches, key=lambda item: item.end - item.start)


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _validated_directory(repository_root: Path, relative: str, *, description: str) -> Path:
    pure = PurePosixPath(relative)
    candidate = repository_root.joinpath(*(() if relative == "." else pure.parts))
    try:
        _reject_link_components(repository_root, pure)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(repository_root)
    except (OSError, ValueError) as exc:
        raise RepositorySuiteSelectionError(
            f"{description} is missing or escapes the repository"
        ) from exc
    if not resolved.is_dir():
        raise RepositorySuiteSelectionError(f"{description} is not a directory")
    return resolved


def _reject_link_components(
    repository_root: Path,
    relative: Path | PurePosixPath,
) -> None:
    cursor = repository_root
    for part in relative.parts:
        if part == ".":
            continue
        cursor /= part
        if cursor.is_symlink() or cursor.is_junction():
            raise RepositorySuiteSelectionError("repository suite path traverses a link")


def _normalized_project_root(value: str) -> str:
    try:
        normalized = normalize_relative_path(value)
    except ValueError as exc:
        raise RepositorySuiteSelectionError("Foundry project root is unsafe") from exc
    return "." if normalized in {"", "."} else normalized.rstrip("/")


def _normalized_file_path(value: str) -> str:
    try:
        normalized = normalize_relative_path(value)
    except ValueError as exc:
        raise RepositorySuiteSelectionError("Foundry test directory is unsafe") from exc
    if normalized in {"", "."}:
        raise RepositorySuiteSelectionError("Foundry test directory cannot be repository root")
    return normalized.rstrip("/")


def _path_is_within_project(path: str, project_root: str) -> bool:
    return project_root == "." or path == project_root or path.startswith(f"{project_root}/")


def _include_paths_for_project(
    *,
    profile: str,
    configured: tuple[str, ...],
    project_root: str,
) -> tuple[str, ...]:
    if profile == "explicit":
        return configured
    return tuple(_join_project_path(project_root, pattern) for pattern in configured)


def _join_project_path(project_root: str, path: str) -> str:
    return path if project_root == "." else f"{project_root}/{path}"


def _matches_any_path(path: str, patterns: tuple[str, ...]) -> bool:
    return any(_path_glob_matches(path, pattern) for pattern in patterns)


def _path_glob_matches(path: str, pattern: str) -> bool:
    path_parts = PurePosixPath(path).parts
    pattern_parts = PurePosixPath(pattern).parts
    memo: dict[tuple[int, int], bool] = {}

    def match(path_index: int, pattern_index: int) -> bool:
        key = (path_index, pattern_index)
        if key in memo:
            return memo[key]
        if pattern_index == len(pattern_parts):
            result = path_index == len(path_parts)
        elif pattern_parts[pattern_index] == "**":
            result = match(path_index, pattern_index + 1) or (
                path_index < len(path_parts) and match(path_index + 1, pattern_index)
            )
        else:
            result = (
                path_index < len(path_parts)
                and fnmatch.fnmatchcase(
                    path_parts[path_index],
                    pattern_parts[pattern_index],
                )
                and match(path_index + 1, pattern_index + 1)
            )
        memo[key] = result
        return result

    return match(0, 0)


def _matches_test(
    test_name: str,
    stable_id: str,
    patterns: tuple[str, ...],
) -> bool:
    return any(
        fnmatch.fnmatchcase(test_name, pattern) or fnmatch.fnmatchcase(stable_id, pattern)
        for pattern in patterns
    )


def _stable_test_id(path: str, suite_name: str, test_name: str) -> str:
    return f"{path}:{suite_name}:{test_name}"


def _has_glob_magic(pattern: str) -> bool:
    return any(character in pattern for character in _GLOB_MAGIC)
