"""Conservative host-side source binding for untrusted Hardhat observations."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import stat
import weakref
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from mmaudit.config import SmartContractsConfig
from mmaudit.models.schemas import (
    HardhatReporterInventory,
    RepositorySuiteFramework,
    RepositorySuiteSelection,
    RepositorySuiteTestDescriptor,
)
from mmaudit.scanners.base import (
    scanner_workspace_exclusion_path,
    scanner_workspace_file_records,
    scanner_workspace_sha256,
)

_MAX_SOURCE_BYTES = 5_000_000
_MAX_TOKENS = 500_000
_MAX_SUITE_TEST_RELATIONSHIPS = 1_000_000
_SUPPORTED_TEST_SUFFIXES = frozenset({".cjs", ".js", ".mjs", ".ts"})
_SUITE_IDENTIFIERS = frozenset({"context", "describe", "suite"})
_TEST_IDENTIFIERS = frozenset({"it", "specify", "test"})
_TEST_MODIFIERS = frozenset({"only", "skip"})
_IDENTIFIER_START = re.compile(r"[A-Za-z_$]")
_IDENTIFIER_CONTINUE = re.compile(r"[A-Za-z0-9_$]")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MOCHA_CALL_TEXT = re.compile(
    r"\b(?:context|describe|it|specify|suite|test)\s*"
    r"(?:\.\s*(?:only|skip)\s*)?\("
)


class HardhatSourceBindingError(ValueError):
    """Untrusted Hardhat observations could not be bound to exact source."""


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str
    value: str
    line: int


@dataclass(frozen=True, slots=True)
class _StaticDefinition:
    suite_name: str
    test_name: str
    start_line: int
    end_line: int


@dataclass(frozen=True, slots=True)
class _MochaCall:
    name: str
    call_open: int
    call_close: int
    body_open: int | None
    body_close: int | None


@dataclass(frozen=True, slots=True, weakref_slot=True, eq=False)
class HardhatSourceInventoryAuthority:
    """Process-local seal for one independently source-bound selection snapshot.

    Constructing a lookalike object is insufficient. Only the exact instance retained
    in the module-local seal registry verifies, so serialization cannot recreate
    selection authority. The seal retains no root descriptor and never grants runtime,
    reporter-output, execution, or coverage credit.
    """

    inventory_sha256: str
    request_sha256: str
    repository_sha256: str
    repository_exclusion_path: str
    configuration_sha256: str
    profile: Literal["legacy_audit", "explicit"]
    source_bundle_sha256: str
    candidate_file_count: int
    candidate_test_count: int
    selected_file_count: int
    selected_test_count: int
    omitted_file_count: int
    omitted_test_count: int
    descriptors: tuple[RepositorySuiteTestDescriptor, ...]
    authority_sha256: str


@dataclass(frozen=True, slots=True)
class _AuthoritySeal:
    reference: weakref.ReferenceType[HardhatSourceInventoryAuthority]
    authority_sha256: str


_SOURCE_AUTHORITIES: dict[int, _AuthoritySeal] = {}


def bind_hardhat_inventory_to_source(
    root: Path,
    inventory: HardhatReporterInventory,
    smart_contracts: SmartContractsConfig,
    *,
    expected_repository_sha256: str,
    repository_exclusion_root: Path | None = None,
) -> HardhatSourceInventoryAuthority:
    """Bind an exact reporter inventory to independently selected literal source tests.

    The same-process reporter remains untrusted. This function independently
    inventories eligible files, verifies complete observation coverage, reads each
    source through no-follow descriptors, and accepts only literal Mocha
    declarations. Dynamic names, aliases, duplicate identities, and unsupported
    syntax receive no selection authority.
    """

    suite_config = smart_contracts.repository_suite
    if not suite_config.hardhat_include_paths or not suite_config.hardhat_include_tests:
        raise HardhatSourceBindingError("Hardhat repository-suite selection is disabled")
    if (
        _SHA256.fullmatch(expected_repository_sha256) is None
        or expected_repository_sha256 == "0" * 64
    ):
        raise HardhatSourceBindingError("Hardhat source binding requires a nonzero repository hash")
    if inventory.repository_sha256 != expected_repository_sha256:
        raise HardhatSourceBindingError("Hardhat inventory differs from the frozen repository")
    if inventory.inventory_sha256 != inventory.expected_inventory_sha256() or any(
        observation.observation_sha256 != observation.expected_observation_sha256()
        for observation in inventory.tests
    ):
        raise HardhatSourceBindingError("Hardhat inventory or observation hash is stale")
    try:
        observed_repository_sha256 = scanner_workspace_sha256(
            root,
            repository_exclusion_root,
        )
    except (OSError, TypeError, UnicodeError, ValueError) as exc:
        raise HardhatSourceBindingError(
            "Hardhat source binding could not retain the repository inventory"
        ) from exc
    if observed_repository_sha256 != expected_repository_sha256:
        raise HardhatSourceBindingError("Hardhat source changed before observation binding")

    try:
        repository_exclusion_path = scanner_workspace_exclusion_path(
            root, repository_exclusion_root
        )
        file_records = scanner_workspace_file_records(root, repository_exclusion_root)
    except (OSError, TypeError, UnicodeError, ValueError) as exc:
        raise HardhatSourceBindingError(
            "Hardhat source binding could not retain the repository file inventory"
        ) from exc
    candidate_records = tuple(
        record
        for record in file_records
        if PurePosixPath(record.relative_path).suffix.casefold() in _SUPPORTED_TEST_SUFFIXES
        and _matches_any_path(record.relative_path, suite_config.hardhat_include_paths)
        and not _matches_any_path(record.relative_path, suite_config.hardhat_exclude_paths)
    )
    if not candidate_records:
        raise HardhatSourceBindingError("Hardhat source selection matched zero candidate files")

    source_hashes = {record.relative_path: record.sha256 for record in candidate_records}
    all_descriptors: list[RepositorySuiteTestDescriptor] = []
    selected_descriptors: list[RepositorySuiteTestDescriptor] = []
    candidate_files: set[str] = set()
    selected_per_file: dict[str, int] = {}
    exact_bare_matches: dict[str, set[tuple[str, str, str]]] = {
        pattern: set()
        for pattern in suite_config.hardhat_include_tests
        if not _has_glob_magic(pattern)
    }
    for record in candidate_records:
        raw = _read_repository_source(root, record.relative_path)
        if hashlib.sha256(raw).hexdigest() != record.sha256:
            raise HardhatSourceBindingError(
                "Hardhat test source differs from its retained inventory"
            )
        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HardhatSourceBindingError("Hardhat test source is not valid UTF-8") from exc
        definitions = _static_mocha_definitions(source)
        if definitions:
            candidate_files.add(record.relative_path)
        for (suite_name, test_name), matches in definitions.items():
            if len(matches) != 1:
                raise HardhatSourceBindingError(
                    "Hardhat source contains an ambiguous duplicate test identity"
                )
            definition = matches[0]
            descriptor = RepositorySuiteTestDescriptor.sealed(
                framework=RepositorySuiteFramework.HARDHAT,
                project_root=".",
                path=record.relative_path,
                suite_name=suite_name,
                test_name=test_name,
                source_sha256=record.sha256,
                start_line=definition.start_line,
                end_line=definition.end_line,
            )
            all_descriptors.append(descriptor)
            stable_id = _stable_test_id(record.relative_path, suite_name, test_name)
            if not _matches_test(
                test_name, stable_id, suite_config.hardhat_include_tests
            ) or _matches_test(test_name, stable_id, suite_config.hardhat_exclude_tests):
                continue
            selected_per_file[record.relative_path] = (
                selected_per_file.get(record.relative_path, 0) + 1
            )
            if selected_per_file[record.relative_path] > suite_config.max_tests_per_file:
                raise HardhatSourceBindingError(
                    "selected Hardhat tests exceed the configured per-file ceiling"
                )
            for exact_name in exact_bare_matches:
                if test_name == exact_name:
                    exact_bare_matches[exact_name].add(
                        (record.relative_path, suite_name, test_name)
                    )
            selected_descriptors.append(descriptor)

    for exact_name, exact_matches in exact_bare_matches.items():
        if len(exact_matches) > 1:
            raise HardhatSourceBindingError(
                f"exact bare Hardhat test selector is ambiguous: {exact_name}"
            )
    all_ordered = tuple(sorted(all_descriptors, key=lambda item: item.canonical_key))
    observed_keys = tuple(test.canonical_key for test in inventory.tests)
    source_keys = tuple(
        (descriptor.project_root, descriptor.path, descriptor.suite_name, descriptor.test_name)
        for descriptor in all_ordered
    )
    if observed_keys != source_keys:
        raise HardhatSourceBindingError(
            "Hardhat observations do not exactly cover the literal source inventory"
        )
    ordered = tuple(sorted(selected_descriptors, key=lambda item: item.canonical_key))
    if not ordered:
        raise HardhatSourceBindingError("Hardhat repository-suite selection matched zero tests")
    selected_files = {descriptor.path for descriptor in ordered}
    if len(selected_files) > suite_config.max_selected_files:
        raise HardhatSourceBindingError("selected Hardhat files exceed the configured ceiling")
    if len(ordered) > suite_config.max_total_tests:
        raise HardhatSourceBindingError(
            "selected Hardhat tests exceed the configured total ceiling"
        )
    try:
        final_records = scanner_workspace_file_records(root, repository_exclusion_root)
        final_repository_sha256 = scanner_workspace_sha256(root, repository_exclusion_root)
    except (OSError, TypeError, UnicodeError, ValueError) as exc:
        raise HardhatSourceBindingError(
            "Hardhat source binding could not revalidate the repository inventory"
        ) from exc
    if final_records != file_records or final_repository_sha256 != expected_repository_sha256:
        raise HardhatSourceBindingError("Hardhat source changed during observation binding")

    source_bundle_sha256 = _canonical_sha256(
        [
            {
                "path": path,
                "source_sha256": source_hashes[path],
            }
            for path in sorted(source_hashes)
        ]
    )
    candidate_file_count = len(candidate_files)
    candidate_test_count = len(all_ordered)
    selected_file_count = len(selected_files)
    selected_test_count = len(ordered)
    material = {
        "version": "MMAUDIT_HARDHAT_SOURCE_AUTHORITY_V1",
        "inventory_sha256": inventory.inventory_sha256,
        "request_sha256": inventory.request_sha256,
        "repository_sha256": expected_repository_sha256,
        "repository_exclusion_path": repository_exclusion_path,
        "configuration_sha256": suite_config.stable_hash(),
        "profile": suite_config.profile,
        "source_bundle_sha256": source_bundle_sha256,
        "candidate_file_count": candidate_file_count,
        "candidate_test_count": candidate_test_count,
        "selected_file_count": selected_file_count,
        "selected_test_count": selected_test_count,
        "omitted_file_count": candidate_file_count - selected_file_count,
        "omitted_test_count": candidate_test_count - selected_test_count,
        "descriptor_sha256s": [descriptor.descriptor_sha256 for descriptor in ordered],
    }
    authority = HardhatSourceInventoryAuthority(
        inventory_sha256=inventory.inventory_sha256,
        request_sha256=inventory.request_sha256,
        repository_sha256=expected_repository_sha256,
        repository_exclusion_path=repository_exclusion_path,
        configuration_sha256=suite_config.stable_hash(),
        profile=suite_config.profile,
        source_bundle_sha256=source_bundle_sha256,
        candidate_file_count=candidate_file_count,
        candidate_test_count=candidate_test_count,
        selected_file_count=selected_file_count,
        selected_test_count=selected_test_count,
        omitted_file_count=candidate_file_count - selected_file_count,
        omitted_test_count=candidate_test_count - selected_test_count,
        descriptors=ordered,
        authority_sha256=_canonical_sha256(material),
    )
    _seal_source_authority(authority)
    return authority


def verify_hardhat_source_inventory_authority(
    authority: object,
    *,
    inventory: HardhatReporterInventory | None = None,
) -> bool:
    """Verify one unchanged exact process-local source-snapshot seal instance."""

    if type(authority) is not HardhatSourceInventoryAuthority:
        return False
    seal = _SOURCE_AUTHORITIES.get(id(authority))
    if seal is None or seal.reference() is not authority:
        return False
    descriptor_hashes = [descriptor.descriptor_sha256 for descriptor in authority.descriptors]
    material = {
        "version": "MMAUDIT_HARDHAT_SOURCE_AUTHORITY_V1",
        "inventory_sha256": authority.inventory_sha256,
        "request_sha256": authority.request_sha256,
        "repository_sha256": authority.repository_sha256,
        "repository_exclusion_path": authority.repository_exclusion_path,
        "configuration_sha256": authority.configuration_sha256,
        "profile": authority.profile,
        "source_bundle_sha256": authority.source_bundle_sha256,
        "candidate_file_count": authority.candidate_file_count,
        "candidate_test_count": authority.candidate_test_count,
        "selected_file_count": authority.selected_file_count,
        "selected_test_count": authority.selected_test_count,
        "omitted_file_count": authority.omitted_file_count,
        "omitted_test_count": authority.omitted_test_count,
        "descriptor_sha256s": descriptor_hashes,
    }
    if (
        not authority.descriptors
        or tuple(authority.descriptors)
        != tuple(sorted(authority.descriptors, key=lambda item: item.canonical_key))
        or len(descriptor_hashes) != len(set(descriptor_hashes))
        or any(
            descriptor.descriptor_sha256 != descriptor.expected_descriptor_sha256()
            for descriptor in authority.descriptors
        )
        or authority.selected_test_count != len(authority.descriptors)
        or authority.profile not in {"legacy_audit", "explicit"}
        or authority.selected_file_count
        != len({descriptor.path for descriptor in authority.descriptors})
        or authority.candidate_file_count
        != authority.selected_file_count + authority.omitted_file_count
        or authority.candidate_test_count
        != authority.selected_test_count + authority.omitted_test_count
        or authority.authority_sha256 != _canonical_sha256(material)
        or authority.authority_sha256 != seal.authority_sha256
    ):
        return False
    return inventory is None or (
        inventory.inventory_sha256 == inventory.expected_inventory_sha256()
        and all(
            observation.observation_sha256 == observation.expected_observation_sha256()
            for observation in inventory.tests
        )
        and authority.inventory_sha256 == inventory.inventory_sha256
        and authority.request_sha256 == inventory.request_sha256
        and authority.repository_sha256 == inventory.repository_sha256
    )


def hardhat_selection_from_source_authority(
    inventory: HardhatReporterInventory,
    smart_contracts: SmartContractsConfig,
    *,
    repository_exclusion_path: str,
    authority: object,
) -> RepositorySuiteSelection:
    """Construct a bounded selection only from the exact process-local source snapshot."""

    if not verify_hardhat_source_inventory_authority(authority, inventory=inventory):
        raise HardhatSourceBindingError("Hardhat source inventory authority is unavailable")
    assert isinstance(authority, HardhatSourceInventoryAuthority)
    suite_config = smart_contracts.repository_suite
    if authority.configuration_sha256 != suite_config.stable_hash():
        raise HardhatSourceBindingError("Hardhat source authority differs from selection policy")
    if authority.repository_exclusion_path != repository_exclusion_path:
        raise HardhatSourceBindingError(
            "Hardhat source authority differs from repository exclusion"
        )
    return RepositorySuiteSelection.sealed(
        profile=authority.profile,
        repository_sha256=authority.repository_sha256,
        repository_exclusion_path=authority.repository_exclusion_path,
        configuration_sha256=authority.configuration_sha256,
        candidate_file_count=authority.candidate_file_count,
        candidate_test_count=authority.candidate_test_count,
        selected_file_count=authority.selected_file_count,
        selected_test_count=authority.selected_test_count,
        omitted_file_count=authority.omitted_file_count,
        omitted_test_count=authority.omitted_test_count,
        limit_reached=False,
        tests=authority.descriptors,
        safety_claim=False,
    )


def _seal_source_authority(authority: HardhatSourceInventoryAuthority) -> None:
    identity = id(authority)

    def discard(reference: weakref.ReferenceType[HardhatSourceInventoryAuthority]) -> None:
        current = _SOURCE_AUTHORITIES.get(identity)
        if current is not None and current.reference is reference:
            _SOURCE_AUTHORITIES.pop(identity, None)

    reference = weakref.ref(authority, discard)
    _SOURCE_AUTHORITIES[identity] = _AuthoritySeal(
        reference=reference,
        authority_sha256=authority.authority_sha256,
    )


def _read_repository_source(root: Path, relative_path: str) -> bytes:
    path = PurePosixPath(relative_path)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.suffix.casefold() not in _SUPPORTED_TEST_SUFFIXES
        or any(
            part.casefold() in {".env", ".git", ".mmaudit", "node_modules"} for part in path.parts
        )
    ):
        raise HardhatSourceBindingError("Hardhat observation source path is unsupported")
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if no_follow == 0 or directory_flag == 0:
        raise HardhatSourceBindingError("no-follow source custody is unavailable")
    root_path = root.absolute()
    try:
        root_before = root_path.lstat()
    except OSError as exc:
        raise HardhatSourceBindingError("Hardhat repository root is unavailable") from exc
    if not stat.S_ISDIR(root_before.st_mode) or stat.S_ISLNK(root_before.st_mode):
        raise HardhatSourceBindingError("Hardhat repository root must be a non-link directory")
    root_fd = -1
    current_fd = -1
    try:
        root_fd = os.open(
            root_path,
            os.O_RDONLY | directory_flag | no_follow | getattr(os, "O_CLOEXEC", 0),
        )
        current_fd = os.dup(root_fd)
        if _identity(os.fstat(root_fd)) != _identity(root_before):
            raise HardhatSourceBindingError("Hardhat repository root identity changed")
        for component in path.parts[:-1]:
            before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                raise HardhatSourceBindingError(
                    "Hardhat source parent must be a non-link directory"
                )
            child_fd = os.open(
                component,
                os.O_RDONLY | directory_flag | no_follow | getattr(os, "O_CLOEXEC", 0),
                dir_fd=current_fd,
            )
            if _identity(os.fstat(child_fd)) != _identity(before):
                os.close(child_fd)
                raise HardhatSourceBindingError("Hardhat source parent identity changed")
            os.close(current_fd)
            current_fd = child_fd
        name = path.parts[-1]
        named_before = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(named_before.st_mode)
            or stat.S_ISLNK(named_before.st_mode)
            or named_before.st_nlink != 1
            or not 0 < named_before.st_size <= _MAX_SOURCE_BYTES
        ):
            raise HardhatSourceBindingError(
                "Hardhat source must be one bounded unique regular file"
            )
        file_fd = os.open(
            name,
            os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0),
            dir_fd=current_fd,
        )
        try:
            if _identity(os.fstat(file_fd)) != _identity(named_before):
                raise HardhatSourceBindingError("Hardhat source identity changed before read")
            chunks: list[bytes] = []
            remaining = named_before.st_size
            while remaining:
                chunk = os.read(file_fd, min(64 * 1024, remaining))
                if not chunk:
                    raise HardhatSourceBindingError("Hardhat source changed while read")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(file_fd, 1):
                raise HardhatSourceBindingError("Hardhat source exceeds its retained size")
            named_after = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
            if (
                _identity(os.fstat(file_fd)) != _identity(named_before)
                or _identity(named_after) != _identity(named_before)
                or _identity(os.fstat(root_fd)) != _identity(root_before)
            ):
                raise HardhatSourceBindingError("Hardhat source identity changed during read")
            return b"".join(chunks)
        finally:
            os.close(file_fd)
    except (OSError, UnicodeError) as exc:
        raise HardhatSourceBindingError("Hardhat source could not be read safely") from exc
    finally:
        if current_fd >= 0:
            os.close(current_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _static_mocha_definitions(
    source: str,
) -> dict[tuple[str, str], tuple[_StaticDefinition, ...]]:
    source = (
        source.replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("\u2028", "\n")
        .replace("\u2029", "\n")
    )
    tokens = _tokenize_javascript(source)
    pairs = _delimiter_pairs(tokens)
    suites: list[tuple[int, int, str]] = []
    tests: list[tuple[int, int, str]] = []
    for index, token in enumerate(tokens):
        if token.kind != "identifier":
            continue
        kind = (
            "suite"
            if token.value in _SUITE_IDENTIFIERS
            else ("test" if token.value in _TEST_IDENTIFIERS else None)
        )
        if kind is None:
            continue
        if index and tokens[index - 1].value == ".":
            continue
        call = _literal_mocha_call(tokens, pairs, index, kind=kind)
        if call is None:
            raise HardhatSourceBindingError(
                "Hardhat source uses an unsupported direct Mocha identifier reference"
            )
        if kind == "suite":
            if call.body_open is None or call.body_close is None:
                raise HardhatSourceBindingError(
                    "Hardhat suite declaration requires one literal block callback"
                )
            suites.append((call.body_open, call.body_close, call.name))
        else:
            tests.append((index, call.body_close or call.call_close, call.name))

    if len(suites) * len(tests) > _MAX_SUITE_TEST_RELATIONSHIPS:
        raise HardhatSourceBindingError("Hardhat suite ancestry work exceeds its fixed bound")
    definitions: dict[tuple[str, str], list[_StaticDefinition]] = {}
    for test_index, body_close, test_name in tests:
        parents = sorted(
            (
                (suite_open, suite_name)
                for suite_open, suite_close, suite_name in suites
                if suite_open < test_index < suite_close
            ),
            key=lambda item: item[0],
        )
        if not parents:
            continue
        suite_name = " ".join(name for _index, name in parents)
        definition = _StaticDefinition(
            suite_name=suite_name,
            test_name=test_name,
            start_line=tokens[test_index].line,
            end_line=tokens[body_close].line,
        )
        definitions.setdefault((suite_name, test_name), []).append(definition)
    return {
        key: tuple(sorted(values, key=lambda item: (item.start_line, item.end_line)))
        for key, values in definitions.items()
    }


def _literal_mocha_call(
    tokens: tuple[_Token, ...],
    pairs: dict[int, int],
    index: int,
    *,
    kind: str,
) -> _MochaCall | None:
    cursor = index + 1
    if (
        cursor + 1 < len(tokens)
        and tokens[cursor].value == "."
        and tokens[cursor + 1].kind == "identifier"
        and tokens[cursor + 1].value in _TEST_MODIFIERS
    ):
        cursor += 2
    if cursor >= len(tokens) or tokens[cursor].value != "(":
        return None
    call_close = pairs.get(cursor)
    if call_close is None:
        raise HardhatSourceBindingError("Hardhat test source has an incomplete Mocha call")
    if call_close + 1 < len(tokens) and tokens[call_close + 1].value == "{":
        return None
    if cursor + 2 >= call_close:
        raise HardhatSourceBindingError("Hardhat test source has an incomplete Mocha call")
    literal = tokens[cursor + 1]
    if literal.kind != "string" or tokens[cursor + 2].value != ",":
        raise HardhatSourceBindingError(
            "Hardhat suite and test names must be unescaped literal strings"
        )
    callback = cursor + 3
    if callback < call_close and tokens[callback].value == "async":
        callback += 1
    body_open: int | None = None
    if callback < call_close and tokens[callback].value == "function":
        callback += 1
        if callback < call_close and tokens[callback].kind == "identifier":
            callback += 1
        if callback >= call_close or tokens[callback].value != "(":
            raise HardhatSourceBindingError("Hardhat callback function is ambiguous")
        parameters_close = pairs.get(callback)
        if parameters_close is None or parameters_close + 1 >= call_close:
            raise HardhatSourceBindingError("Hardhat callback function is incomplete")
        body_open = parameters_close + 1
        if tokens[body_open].value != "{":
            raise HardhatSourceBindingError("Hardhat callback function lacks a literal body")
    else:
        if callback < call_close and tokens[callback].value == "(":
            parameters_close = pairs.get(callback)
            if parameters_close is None:
                raise HardhatSourceBindingError("Hardhat callback parameters are incomplete")
            callback = parameters_close + 1
        elif callback < call_close and tokens[callback].kind == "identifier":
            callback += 1
        if callback >= call_close or tokens[callback].value != "=>":
            raise HardhatSourceBindingError("Hardhat callback must be one literal function")
        callback += 1
        if callback < call_close and tokens[callback].value == "{":
            body_open = callback
    body_close = pairs.get(body_open) if body_open is not None else None
    if body_open is not None and (body_close is None or body_close > call_close):
        raise HardhatSourceBindingError("Hardhat callback body is incomplete")
    if kind == "suite" and body_open is None:
        raise HardhatSourceBindingError("Hardhat suite callback must have a literal block body")
    return _MochaCall(
        name=literal.value,
        call_open=cursor,
        call_close=call_close,
        body_open=body_open,
        body_close=body_close,
    )


def _delimiter_pairs(tokens: tuple[_Token, ...]) -> dict[int, int]:
    pairs: dict[int, int] = {}
    stacks: dict[str, list[int]] = {"(": [], "[": [], "{": []}
    closes = {")": "(", "]": "[", "}": "{"}
    for index, token in enumerate(tokens):
        if token.value in stacks:
            stacks[token.value].append(index)
        elif token.value in closes:
            opening = closes[token.value]
            if not stacks[opening]:
                raise HardhatSourceBindingError("Hardhat test source has unmatched delimiters")
            start = stacks[opening].pop()
            pairs[start] = index
    if any(stack for stack in stacks.values()):
        raise HardhatSourceBindingError("Hardhat test source has unmatched delimiters")
    return pairs


def _tokenize_javascript(source: str) -> tuple[_Token, ...]:
    tokens: list[_Token] = []
    index = 0
    line = 1
    length = len(source)

    def append(kind: str, value: str, token_line: int) -> None:
        tokens.append(_Token(kind=kind, value=value, line=token_line))
        if len(tokens) > _MAX_TOKENS:
            raise HardhatSourceBindingError("Hardhat test source token limit exceeded")

    while index < length:
        character = source[index]
        if index == 0 and source.startswith("#!", index):
            raise HardhatSourceBindingError("Hardhat test source uses an unsupported hashbang")
        if source.startswith("<!--", index) or source.startswith("-->", index):
            raise HardhatSourceBindingError(
                "Hardhat test source uses an unsupported legacy HTML comment"
            )
        if character in " \t\r\f\v":
            index += 1
            continue
        if character == "\n":
            line += 1
            index += 1
            continue
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = length if newline < 0 else newline
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise HardhatSourceBindingError("Hardhat test source has an unterminated comment")
            line += source.count("\n", index, end + 2)
            index = end + 2
            continue
        if character == "/" and _ambiguous_slash_contains_mocha_call(source, index):
            raise HardhatSourceBindingError(
                "Hardhat test source contains an ambiguous regular-expression test token"
            )
        if character == "/" and _slash_starts_regular_expression(tokens):
            index, line = _skip_javascript_regular_expression(source, index, line)
            append("regular_expression", "/…/", line)
            continue
        if character in {"'", '"', "`"}:
            quote = character
            token_line = line
            index += 1
            value: list[str] = []
            literal = True
            while index < length:
                current = source[index]
                if current == quote:
                    index += 1
                    append("string" if literal else "dynamic_string", "".join(value), token_line)
                    break
                if current == "\\":
                    literal = False
                    if index + 1 < length and source[index + 1] == "\n":
                        line += 1
                    index += 2
                    continue
                if quote == "`" and source.startswith("${", index):
                    raise HardhatSourceBindingError(
                        "Hardhat test source uses unsupported template interpolation"
                    )
                if current == "\n":
                    if quote != "`":
                        raise HardhatSourceBindingError(
                            "Hardhat test source has an unterminated string"
                        )
                    line += 1
                value.append(current)
                index += 1
            else:
                raise HardhatSourceBindingError("Hardhat test source has an unterminated string")
            continue
        if character == "\\":
            raise HardhatSourceBindingError(
                "Hardhat test source uses an unsupported escaped identifier"
            )
        if _IDENTIFIER_START.fullmatch(character):
            token_line = line
            end = index + 1
            while end < length and _IDENTIFIER_CONTINUE.fullmatch(source[end]):
                end += 1
            append("identifier", source[index:end], token_line)
            index = end
            continue
        operator = next(
            (
                candidate
                for candidate in ("=>", "&&", "||", "??")
                if source.startswith(candidate, index)
            ),
            None,
        )
        if operator is not None:
            append("punctuation", operator, line)
            index += 2
            continue
        append("punctuation", character, line)
        index += 1
    return tuple(tokens)


def _slash_starts_regular_expression(tokens: list[_Token]) -> bool:
    if not tokens:
        return True
    previous = tokens[-1]
    return previous.value in {
        "(",
        "[",
        "{",
        ",",
        ";",
        ":",
        "=",
        "!",
        "?",
        "&&",
        "||",
        "=>",
    } or (previous.kind == "identifier" and previous.value in {"case", "return", "throw"})


def _skip_javascript_regular_expression(source: str, index: int, line: int) -> tuple[int, int]:
    cursor = index + 1
    escaped = False
    character_class = False
    while cursor < len(source):
        character = source[cursor]
        if character == "\n":
            raise HardhatSourceBindingError(
                "Hardhat test source has an unterminated regular expression"
            )
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "[":
            character_class = True
        elif character == "]":
            character_class = False
        elif character == "/" and not character_class:
            cursor += 1
            while cursor < len(source) and _IDENTIFIER_CONTINUE.fullmatch(source[cursor]):
                cursor += 1
            return cursor, line
        cursor += 1
    raise HardhatSourceBindingError("Hardhat test source has an unterminated regular expression")


def _ambiguous_slash_contains_mocha_call(source: str, index: int) -> bool:
    cursor = index + 1
    escaped = False
    character_class = False
    while cursor < len(source):
        character = source[cursor]
        if character == "\n":
            return False
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "[":
            character_class = True
        elif character == "]":
            character_class = False
        elif character == "/" and not character_class:
            return _MOCHA_CALL_TEXT.search(source, index + 1, cursor) is not None
        cursor += 1
    return False


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
                and fnmatch.fnmatchcase(path_parts[path_index], pattern_parts[pattern_index])
                and match(path_index + 1, pattern_index + 1)
            )
        memo[key] = result
        return result

    return match(0, 0)


def _matches_test(test_name: str, stable_id: str, patterns: tuple[str, ...]) -> bool:
    return any(
        fnmatch.fnmatchcase(test_name, pattern) or fnmatch.fnmatchcase(stable_id, pattern)
        for pattern in patterns
    )


def _stable_test_id(path: str, suite_name: str, test_name: str) -> str:
    return f"{path}:{suite_name}:{test_name}"


def _has_glob_magic(pattern: str) -> bool:
    return any(character in pattern for character in "*?[")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
