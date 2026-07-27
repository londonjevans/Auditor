"""Typed source-local mutations for defensive benchmark validation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.models.schemas import StrictModel
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_path
from mmaudit.repository.workspace import validate_copyable_workspace

_EXCLUDED_WORKSPACE_NAMES = frozenset(
    {
        ".git",
        ".mmaudit",
        "artifacts",
        "broadcast",
        "cache",
        "node_modules",
        "out",
    }
)
_MAX_MUTATION_FILES = 100_000
_MAX_MUTATION_BYTES = 2 * 1024**3


class MutationKind(StrEnum):
    """Required source-local classes used to challenge defensive properties."""

    ACCESS_CONTROL_GUARD_REMOVAL = "access_control_guard_removal"
    REPLAY_STATE_UPDATE_REMOVAL = "replay_state_update_removal"
    BOUNDARY_CHECK_WEAKENING = "boundary_check_weakening"
    ACCOUNTING_OPERATOR_REPLACEMENT = "accounting_operator_replacement"
    EXTERNAL_CALL_RESULT_CHECK_REMOVAL = "external_call_result_check_removal"


REQUIRED_MUTATION_KINDS: tuple[MutationKind, ...] = tuple(MutationKind)

MutationOperator = Literal["<", "<=", ">", ">=", "+", "-", "*", "/"]


class SourceMutationSpec(StrictModel):
    """One hash-pinned mutation of exactly one source line."""

    id: str = Field(pattern=r"^mut-[a-z0-9][a-z0-9-]{0,75}$")
    kind: MutationKind
    path: str
    line: int = Field(ge=1, le=10_000_000)
    expected_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_line: str = Field(min_length=1, max_length=20_000)
    original_operator: MutationOperator | None = None
    replacement_operator: MutationOperator | None = None

    @field_validator("path")
    @classmethod
    def path_is_normalized_solidity_source(cls, value: str) -> str:
        normalized = normalize_relative_path(value)
        if normalized in {"", "."} or PurePosixPath(normalized).suffix.lower() != ".sol":
            raise ValueError("mutation target must be a repository-relative Solidity source")
        return normalized

    @field_validator("expected_line")
    @classmethod
    def target_is_one_line(cls, value: str) -> str:
        if "\n" in value or "\r" in value:
            raise ValueError("mutation target must contain exactly one source line")
        return value

    @model_validator(mode="after")
    def mutation_shape_matches_kind(self) -> SourceMutationSpec:
        line = self.expected_line.strip()
        removal_kinds = {
            MutationKind.ACCESS_CONTROL_GUARD_REMOVAL,
            MutationKind.REPLAY_STATE_UPDATE_REMOVAL,
            MutationKind.EXTERNAL_CALL_RESULT_CHECK_REMOVAL,
        }
        if self.kind in removal_kinds:
            if self.original_operator is not None or self.replacement_operator is not None:
                raise ValueError("line-removal mutations cannot declare operators")
        elif self.original_operator is None or self.replacement_operator is None:
            raise ValueError("operator mutations require an original and replacement operator")

        if self.kind is MutationKind.ACCESS_CONTROL_GUARD_REMOVAL:
            if not re.search(r"\brequire\s*\(", line) or not re.search(
                r"\bmsg\.sender\b|\bhasRole\s*\(",
                line,
            ):
                raise ValueError("access-control mutation requires an explicit caller guard")
        elif self.kind is MutationKind.REPLAY_STATE_UPDATE_REMOVAL:
            if (
                not line.endswith(";")
                or re.search(r"(?<![=!<>])=(?!=)", line) is None
                or re.search(
                    r"\b(?:used|consumed|executed|processed)[A-Za-z0-9_]*",
                    line,
                )
                is None
            ):
                raise ValueError("replay mutation requires an explicit consumed-state assignment")
        elif self.kind is MutationKind.EXTERNAL_CALL_RESULT_CHECK_REMOVAL:
            if (
                not re.search(r"\brequire\s*\(", line)
                or re.search(
                    r"\b(?:ok|success|succeeded)\b",
                    line,
                )
                is None
            ):
                raise ValueError("call-result mutation requires an explicit success check")
        elif self.kind is MutationKind.BOUNDARY_CHECK_WEAKENING:
            expected_pair = {"<": "<=", ">": ">="}.get(self.original_operator or "")
            if (
                expected_pair != self.replacement_operator
                or not re.search(r"\brequire\s*\(", line)
                or line.count(self.original_operator or "") != 1
            ):
                raise ValueError("boundary mutation must expand exactly one strict comparison")
        elif self.kind is MutationKind.ACCOUNTING_OPERATOR_REPLACEMENT:
            allowed_pairs = {
                ("+", "-"),
                ("-", "+"),
                ("*", "/"),
                ("/", "*"),
            }
            if (
                (self.original_operator, self.replacement_operator) not in allowed_pairs
                or re.search(r"(?<![=!<>])=(?!=)|\breturn\b", line) is None
                or line.count(self.original_operator or "") != 1
            ):
                raise ValueError(
                    "accounting mutation requires one approved arithmetic operator replacement"
                )
        return self


class MutationTestOutcome(StrEnum):
    """Normalized result of challenging one property with one applicable mutation."""

    KILLED = "killed"
    SURVIVED = "survived"
    INCONCLUSIVE = "inconclusive"


class MutationPropertyOutcome(StrictModel):
    """Hash-linked outcome for one property/mutation pair."""

    mutation_id: str = Field(pattern=r"^mut-[a-z0-9][a-z0-9-]{0,75}$")
    mutation_kind: MutationKind
    property_id: str = Field(pattern=r"^prop-[0-9a-f]{24}$")
    outcome: MutationTestOutcome
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class PropertyMutationScore(StrictModel):
    """Explicit kill score for one expected invariant/property."""

    property_id: str = Field(pattern=r"^prop-[0-9a-f]{24}$")
    applicable_mutations: int = Field(ge=0, le=100_000)
    killed: int = Field(ge=0, le=100_000)
    survived: int = Field(ge=0, le=100_000)
    inconclusive: int = Field(ge=0, le=100_000)
    kill_score: float | None = Field(default=None, ge=0, le=1)
    minimum_required: float = Field(ge=0, le=1)
    gate_passed: bool

    @model_validator(mode="after")
    def score_is_arithmetically_consistent(self) -> PropertyMutationScore:
        total = self.killed + self.survived + self.inconclusive
        expected_score = _kill_score(self.killed, total)
        expected_passed = (
            total > 0
            and self.inconclusive == 0
            and expected_score is not None
            and expected_score >= self.minimum_required
        )
        if self.applicable_mutations != total:
            raise ValueError("property mutation counts do not match the applicable total")
        if self.kill_score != expected_score:
            raise ValueError("property mutation kill score is inconsistent")
        if self.gate_passed != expected_passed:
            raise ValueError("property mutation gate result is inconsistent")
        return self


class MutationScorecard(StrictModel):
    """Per-property mutation quality evidence; aggregate scores cannot hide weak properties."""

    schema_version: Literal["1.0"] = "1.0"
    property_corpus_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    minimum_property_kill_score: float = Field(ge=0, le=1)
    expected_property_ids: list[str] = Field(min_length=1, max_length=10_000)
    property_repositories: dict[str, str] = Field(min_length=1, max_length=10_000)
    mutation_count: int = Field(ge=0, le=100_000)
    outcomes: list[MutationPropertyOutcome] = Field(default_factory=list, max_length=100_000)
    property_scores: list[PropertyMutationScore] = Field(
        min_length=1,
        max_length=10_000,
    )
    overall_kill_score: float | None = Field(default=None, ge=0, le=1)
    gate_passed: bool

    @model_validator(mode="after")
    def scorecard_is_complete_and_consistent(self) -> MutationScorecard:
        if self.expected_property_ids != sorted(set(self.expected_property_ids)):
            raise ValueError("expected mutation property IDs must be unique and sorted")
        if list(self.property_repositories) != sorted(self.property_repositories):
            raise ValueError("mutation property repository bindings must be sorted")
        if set(self.property_repositories) != set(self.expected_property_ids):
            raise ValueError("every expected mutation property requires a repository binding")
        if any(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", repository_id) is None
            for repository_id in self.property_repositories.values()
        ):
            raise ValueError("mutation property repository bindings are invalid")
        expected_outcomes = sorted(
            self.outcomes,
            key=lambda item: (item.property_id, item.mutation_id),
        )
        if self.outcomes != expected_outcomes:
            raise ValueError("mutation outcomes must be sorted by property and mutation ID")
        pairs = [(item.property_id, item.mutation_id) for item in self.outcomes]
        if len(pairs) != len(set(pairs)):
            raise ValueError("mutation property/outcome pairs must be unique")
        expected_ids = set(self.expected_property_ids)
        if any(item.property_id not in expected_ids for item in self.outcomes):
            raise ValueError("mutation outcome references an unexpected property")
        kinds_by_mutation: dict[str, MutationKind] = {}
        for item in self.outcomes:
            previous = kinds_by_mutation.setdefault(item.mutation_id, item.mutation_kind)
            if previous is not item.mutation_kind:
                raise ValueError("one mutation ID cannot represent multiple mutation kinds")
        if self.mutation_count != len(kinds_by_mutation):
            raise ValueError("mutation count does not match unique mutation IDs")
        expected_scores = _property_mutation_scores(
            self.expected_property_ids,
            self.outcomes,
            minimum_required=self.minimum_property_kill_score,
        )
        if self.property_scores != expected_scores:
            raise ValueError("per-property mutation scores are inconsistent")
        expected_overall = _kill_score(
            sum(item.outcome is MutationTestOutcome.KILLED for item in self.outcomes),
            len(self.outcomes),
        )
        if self.overall_kill_score != expected_overall:
            raise ValueError("aggregate mutation kill score is inconsistent")
        if self.gate_passed != all(score.gate_passed for score in expected_scores):
            raise ValueError("mutation scorecard gate must require every property gate")
        return self


def score_mutation_outcomes(
    *,
    property_corpus_hash: str,
    expected_property_ids: list[str],
    property_repositories: dict[str, str],
    outcomes: list[MutationPropertyOutcome],
    minimum_property_kill_score: float,
) -> MutationScorecard:
    """Build a deterministic scorecard whose gate is the conjunction of property gates."""

    ordered_property_ids = sorted(set(expected_property_ids))
    if set(property_repositories) != set(ordered_property_ids):
        raise ValueError("every expected mutation property requires one repository binding")
    ordered_property_repositories = {
        property_id: property_repositories[property_id] for property_id in ordered_property_ids
    }
    ordered_outcomes = sorted(
        outcomes,
        key=lambda item: (item.property_id, item.mutation_id),
    )
    property_scores = _property_mutation_scores(
        ordered_property_ids,
        ordered_outcomes,
        minimum_required=minimum_property_kill_score,
    )
    return MutationScorecard(
        property_corpus_hash=property_corpus_hash,
        minimum_property_kill_score=minimum_property_kill_score,
        expected_property_ids=ordered_property_ids,
        property_repositories=ordered_property_repositories,
        mutation_count=len({item.mutation_id for item in ordered_outcomes}),
        outcomes=ordered_outcomes,
        property_scores=property_scores,
        overall_kill_score=_kill_score(
            sum(item.outcome is MutationTestOutcome.KILLED for item in ordered_outcomes),
            len(ordered_outcomes),
        ),
        gate_passed=all(score.gate_passed for score in property_scores),
    )


def load_mutation_scorecard(path: Path) -> MutationScorecard:
    """Load a bounded regular mutation scorecard for benchmark evaluation."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("mutation scorecard must be a regular non-symlink file")
    if path.stat().st_size > 20_000_000:
        raise ValueError("mutation scorecard exceeds the 20 MB limit")
    return MutationScorecard.model_validate_json(path.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class AppliedSourceMutation:
    """Integrity evidence for one mutation in a disposable copied workspace."""

    specification: SourceMutationSpec
    source_repository: Path
    workspace: Path
    source_repository_sha256: str
    pristine_workspace_sha256: str
    mutated_workspace_sha256: str
    original_file_sha256: str
    mutated_file_sha256: str
    original_line_sha256: str
    mutated_line_sha256: str
    line_ending: str


@dataclass(frozen=True)
class RevertedSourceMutation:
    """Evidence that a disposable mutation workspace was restored exactly."""

    specification: SourceMutationSpec
    workspace: Path
    source_repository_sha256: str
    restored_workspace_sha256: str
    restored_file_sha256: str

    @property
    def exact_restoration(self) -> bool:
        return self.source_repository_sha256 == self.restored_workspace_sha256


def _property_mutation_scores(
    expected_property_ids: list[str],
    outcomes: list[MutationPropertyOutcome],
    *,
    minimum_required: float,
) -> list[PropertyMutationScore]:
    scores: list[PropertyMutationScore] = []
    for property_id in expected_property_ids:
        property_outcomes = [item.outcome for item in outcomes if item.property_id == property_id]
        killed = sum(item is MutationTestOutcome.KILLED for item in property_outcomes)
        survived = sum(item is MutationTestOutcome.SURVIVED for item in property_outcomes)
        inconclusive = sum(item is MutationTestOutcome.INCONCLUSIVE for item in property_outcomes)
        total = len(property_outcomes)
        kill_score = _kill_score(killed, total)
        scores.append(
            PropertyMutationScore(
                property_id=property_id,
                applicable_mutations=total,
                killed=killed,
                survived=survived,
                inconclusive=inconclusive,
                kill_score=kill_score,
                minimum_required=minimum_required,
                gate_passed=(
                    total > 0
                    and inconclusive == 0
                    and kill_score is not None
                    and kill_score >= minimum_required
                ),
            )
        )
    return scores


def _kill_score(killed: int, total: int) -> float | None:
    return round(killed / total, 6) if total else None


def mutation_repository_sha256(repository: Path) -> str:
    """Hash the exact bounded tree eligible for a mutation workspace copy."""

    root = repository.resolve(strict=True)
    validate_copyable_workspace(
        root,
        excluded=lambda path: _workspace_path_excluded(path, root),
        max_files=_MAX_MUTATION_FILES,
        max_total_bytes=_MAX_MUTATION_BYTES,
    )
    bindings: list[dict[str, int | str]] = []
    total_bytes = 0
    for directory, directory_names, filenames in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        current = Path(directory)
        directory_names[:] = [
            name
            for name in sorted(directory_names)
            if not _workspace_path_excluded(current / name, root)
        ]
        for name in sorted(filenames):
            candidate = current / name
            if _workspace_path_excluded(candidate, root):
                continue
            metadata = candidate.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("mutation tree hash requires unique regular files")
            total_bytes += metadata.st_size
            if len(bindings) + 1 > _MAX_MUTATION_FILES or total_bytes > _MAX_MUTATION_BYTES:
                raise ValueError("mutation tree hash bounds were exceeded")
            bindings.append(
                {
                    "path": normalize_relative_path(candidate.relative_to(root)),
                    "size": metadata.st_size,
                    "sha256": _sha256(candidate.read_bytes()),
                }
            )
    return _sha256(
        json.dumps(
            bindings,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )


def apply_source_mutation(
    *,
    source_repository: Path,
    workspace: Path,
    specification: SourceMutationSpec,
) -> AppliedSourceMutation:
    """Copy a bounded repository and apply one hash-pinned defensive mutation."""

    source = source_repository.resolve(strict=True)
    target = _source_target(source, specification)
    original_bytes = target.read_bytes()
    original_file_sha256 = _sha256(original_bytes)
    if original_file_sha256 != specification.expected_file_sha256:
        raise ValueError("mutation source hash does not match the planned source")
    mutated_bytes, original_line, mutated_line, line_ending = _mutated_source(
        original_bytes,
        specification,
    )
    source_tree_sha256 = mutation_repository_sha256(source)
    destination = _validate_disposable_destination(source, workspace)
    shutil.copytree(
        source,
        destination,
        ignore=lambda directory, names: _copy_ignored_names(
            Path(directory),
            names,
            source,
        ),
    )
    pristine_workspace_sha256 = mutation_repository_sha256(destination)
    if pristine_workspace_sha256 != source_tree_sha256:
        raise ValueError("disposable mutation copy does not match the source tree")

    workspace_target = _source_target(destination, specification)
    workspace_target.write_bytes(mutated_bytes)
    mutated_file_sha256 = _sha256(mutated_bytes)
    mutated_workspace_sha256 = mutation_repository_sha256(destination)
    if mutated_workspace_sha256 == pristine_workspace_sha256:
        raise ValueError("mutation did not change the disposable workspace")
    if mutation_repository_sha256(source) != source_tree_sha256:
        raise ValueError("source repository changed while applying a disposable mutation")
    return AppliedSourceMutation(
        specification=specification,
        source_repository=source,
        workspace=destination,
        source_repository_sha256=source_tree_sha256,
        pristine_workspace_sha256=pristine_workspace_sha256,
        mutated_workspace_sha256=mutated_workspace_sha256,
        original_file_sha256=original_file_sha256,
        mutated_file_sha256=mutated_file_sha256,
        original_line_sha256=_sha256(original_line.encode()),
        mutated_line_sha256=_sha256(mutated_line.encode()),
        line_ending=line_ending,
    )


def revert_source_mutation(application: AppliedSourceMutation) -> RevertedSourceMutation:
    """Restore one mutation workspace and prove byte-identical tree recovery."""

    if mutation_repository_sha256(application.source_repository) != (
        application.source_repository_sha256
    ):
        raise ValueError("source repository changed before mutation restoration")
    if mutation_repository_sha256(application.workspace) != application.mutated_workspace_sha256:
        raise ValueError("mutation workspace changed before restoration")
    target = _source_target(application.workspace, application.specification)
    if _sha256(target.read_bytes()) != application.mutated_file_sha256:
        raise ValueError("mutated source file changed before restoration")

    current = target.read_bytes()
    restored, _, _, _ = _replace_target_line(
        current,
        application.specification.line,
        application.specification.expected_line,
        expected_current_hash=application.mutated_line_sha256,
        replacement=application.specification.expected_line,
        replacement_line_ending=application.line_ending,
    )
    target.write_bytes(restored)
    restored_file_sha256 = _sha256(restored)
    restored_workspace_sha256 = mutation_repository_sha256(application.workspace)
    if (
        restored_file_sha256 != application.original_file_sha256
        or restored_workspace_sha256 != application.pristine_workspace_sha256
        or restored_workspace_sha256 != application.source_repository_sha256
    ):
        raise ValueError("mutation workspace did not restore to its exact source state")
    return RevertedSourceMutation(
        specification=application.specification,
        workspace=application.workspace,
        source_repository_sha256=application.source_repository_sha256,
        restored_workspace_sha256=restored_workspace_sha256,
        restored_file_sha256=restored_file_sha256,
    )


def _mutated_source(
    original: bytes,
    specification: SourceMutationSpec,
) -> tuple[bytes, str, str, str]:
    lines = _decode_lines(original)
    if specification.line > len(lines):
        raise ValueError("mutation line exceeds the source file")
    current_body, line_ending = _split_line_ending(lines[specification.line - 1])
    if current_body != specification.expected_line:
        raise ValueError("mutation target line does not match the planned source")
    if specification.kind in {
        MutationKind.ACCESS_CONTROL_GUARD_REMOVAL,
        MutationKind.REPLAY_STATE_UPDATE_REMOVAL,
        MutationKind.EXTERNAL_CALL_RESULT_CHECK_REMOVAL,
    }:
        indentation = current_body[: len(current_body) - len(current_body.lstrip())]
        replacement = f"{indentation}// mmaudit defensive mutation: {specification.kind.value}"
    else:
        assert specification.original_operator is not None
        assert specification.replacement_operator is not None
        if current_body.count(specification.original_operator) != 1:
            raise ValueError("mutation operator is not unique on the target line")
        replacement = current_body.replace(
            specification.original_operator,
            specification.replacement_operator,
            1,
        )
    lines[specification.line - 1] = replacement + line_ending
    return "".join(lines).encode(), current_body, replacement, line_ending


def _replace_target_line(
    current: bytes,
    line_number: int,
    expected_original: str,
    *,
    expected_current_hash: str,
    replacement: str,
    replacement_line_ending: str,
) -> tuple[bytes, str, str, str]:
    lines = _decode_lines(current)
    if line_number > len(lines):
        raise ValueError("mutation restoration line exceeds the source file")
    current_body, current_line_ending = _split_line_ending(lines[line_number - 1])
    if _sha256(current_body.encode()) != expected_current_hash:
        raise ValueError("mutation restoration target does not match applied evidence")
    if current_line_ending != replacement_line_ending:
        raise ValueError("mutation target line ending changed before restoration")
    lines[line_number - 1] = expected_original + replacement_line_ending
    return (
        "".join(lines).encode(),
        current_body,
        replacement,
        replacement_line_ending,
    )


def _decode_lines(content: bytes) -> list[str]:
    try:
        return content.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as exc:
        raise ValueError("mutation source must be valid UTF-8") from exc


def _split_line_ending(line: str) -> tuple[str, str]:
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n") or line.endswith("\r"):
        return line[:-1], line[-1]
    return line, ""


def _source_target(root: Path, specification: SourceMutationSpec) -> Path:
    target = root.joinpath(*PurePosixPath(specification.path).parts)
    try:
        resolved = target.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise ValueError("mutation target must remain inside the copied repository") from exc
    if not resolved.is_file() or resolved.is_symlink() or resolved.stat().st_nlink != 1:
        raise ValueError("mutation target must be a unique regular source file")
    if _workspace_path_excluded(resolved, root):
        raise ValueError("mutation target is excluded from disposable workspaces")
    return resolved


def _validate_disposable_destination(source: Path, workspace: Path) -> Path:
    if workspace.exists():
        raise ValueError("mutation workspace must not already exist")
    parent = workspace.parent.resolve(strict=True)
    if not parent.is_dir() or workspace.parent.is_symlink():
        raise ValueError("mutation workspace parent must be a regular directory")
    destination = (parent / workspace.name).resolve(strict=False)
    try:
        destination.relative_to(source)
    except ValueError:
        pass
    else:
        raise ValueError("mutation workspace must remain outside the source repository")
    if not destination.name or destination.name in {".", ".."}:
        raise ValueError("mutation workspace name is invalid")
    return destination


def _copy_ignored_names(directory: Path, names: list[str], source: Path) -> set[str]:
    return {name for name in names if _workspace_path_excluded(directory / name, source)}


def _workspace_path_excluded(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    return any(
        part.lower() in _EXCLUDED_WORKSPACE_NAMES for part in relative.parts
    ) or is_sensitive_workspace_path(relative, is_dir=path.is_dir())


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()
