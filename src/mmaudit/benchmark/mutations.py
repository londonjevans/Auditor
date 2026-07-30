"""Typed source-local mutations for defensive benchmark validation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Protocol

from pydantic import Field, field_validator, model_validator

from mmaudit.models.schemas import ExecutionEvidenceKind, StrictModel
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.workspace import (
    DEFAULT_MAX_WORKSPACE_DEPTH,
    audited_workspace_relative_excluded,
)
from mmaudit.scanners.base import (
    copy_scanner_workspace_with_custody,
    retain_scanner_workspace_source_custody,
    scanner_workspace_file_sha256,
    scanner_workspace_sha256,
)

_MAX_MUTATION_FILES = 100_000
_MAX_MUTATION_REMOVAL_DEPTH = DEFAULT_MAX_WORKSPACE_DEPTH + 2
_MAX_MUTATION_REMOVAL_ENTRIES = (2 * _MAX_MUTATION_FILES) + 10_000


class MutationKind(StrEnum):
    """Implemented source-local classes used to challenge defensive properties."""

    ACCESS_CONTROL_GUARD_REMOVAL = "access_control_guard_removal"
    REPLAY_STATE_UPDATE_REMOVAL = "replay_state_update_removal"
    BOUNDARY_CHECK_WEAKENING = "boundary_check_weakening"
    ACCOUNTING_OPERATOR_REPLACEMENT = "accounting_operator_replacement"
    EXTERNAL_CALL_RESULT_CHECK_REMOVAL = "external_call_result_check_removal"


IMPLEMENTED_MUTATION_KINDS: tuple[MutationKind, ...] = tuple(MutationKind)
# Backward-compatible component-suite name; this is not the full assurance portfolio.
REQUIRED_MUTATION_KINDS: tuple[MutationKind, ...] = IMPLEMENTED_MUTATION_KINDS

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

    def specification_sha256(self) -> str:
        """Hash every typed source-selection and transformation field."""

        return _canonical_sha256(self.model_dump(mode="json"))

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


class MutationApplicabilityBinding(StrictModel):
    """One independently declared property/mutation denominator member."""

    property_id: str = Field(pattern=r"^prop-[0-9a-f]{24}$")
    mutation_id: str = Field(pattern=r"^mut-[a-z0-9][a-z0-9-]{0,75}$")
    test_ids: list[str] = Field(min_length=1, max_length=10_000)

    @field_validator("test_ids")
    @classmethod
    def tests_are_nonempty_unique_and_sorted(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("applicable mutation test IDs must be unique and sorted")
        if any(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}", test_id) is None
            for test_id in value
        ):
            raise ValueError("applicable mutation test IDs are invalid")
        return value


class MutationNonApplicabilityReason(StrEnum):
    """Typed reason that a declared candidate does not challenge one property."""

    PROPERTY_SCOPE_MISMATCH = "property_scope_mismatch"
    NO_EXECUTABLE_ASSERTION = "no_executable_assertion"
    UNSUPPORTED_PROPERTY_MAPPING = "unsupported_property_mapping"


class MutationNonApplicabilityRecord(StrictModel):
    """Explicitly exclude one considered candidate/property pair from the denominator."""

    property_id: str = Field(pattern=r"^prop-[0-9a-f]{24}$")
    mutation_id: str = Field(pattern=r"^mut-[a-z0-9][a-z0-9-]{0,75}$")
    reason: MutationNonApplicabilityReason
    rationale: str = Field(min_length=1, max_length=500)

    @field_validator("rationale")
    @classmethod
    def rationale_is_single_line(cls, value: str) -> str:
        if "\n" in value or "\r" in value:
            raise ValueError("mutation non-applicability rationale must be one line")
        return value


class MutationKindInventoryStatus(StrEnum):
    """Whether this implemented mutation kind has source candidates in the plan."""

    CANDIDATES_DECLARED = "candidates_declared"
    NO_CANDIDATE_DECLARED = "no_candidate_declared"


class MutationKindAccounting(StrictModel):
    """Exact candidate accounting for one implemented mutation kind."""

    kind: MutationKind
    status: MutationKindInventoryStatus
    candidate_count: int = Field(ge=0, le=100_000)
    candidate_ids: list[str] = Field(default_factory=list, max_length=100_000)
    limitation: str | None = Field(default=None, min_length=1, max_length=500)

    @field_validator("candidate_ids")
    @classmethod
    def candidate_ids_are_unique_and_sorted(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("mutation kind candidate IDs must be unique and sorted")
        if any(re.fullmatch(r"^mut-[a-z0-9][a-z0-9-]{0,75}$", item) is None for item in value):
            raise ValueError("mutation kind candidate ID is invalid")
        return value

    @model_validator(mode="after")
    def status_matches_candidates(self) -> MutationKindAccounting:
        if self.candidate_count != len(self.candidate_ids):
            raise ValueError("mutation kind candidate count is inconsistent")
        expected_status = (
            MutationKindInventoryStatus.CANDIDATES_DECLARED
            if self.candidate_ids
            else MutationKindInventoryStatus.NO_CANDIDATE_DECLARED
        )
        if self.status is not expected_status:
            raise ValueError("mutation kind inventory status is inconsistent")
        if self.candidate_ids and self.limitation is not None:
            raise ValueError("declared mutation candidates cannot carry a missing-kind limitation")
        if not self.candidate_ids and self.limitation is None:
            raise ValueError("missing mutation candidates require an explicit limitation")
        if self.limitation is not None and ("\n" in self.limitation or "\r" in self.limitation):
            raise ValueError("mutation kind limitation must be one line")
        return self


class MutationApplicabilityPlan(StrictModel):
    """Hash-bound source mutations and property pairs that define the score denominator."""

    schema_version: Literal["1.1"] = "1.1"
    portfolio_scope: Literal["implemented_five_class_subset"] = "implemented_five_class_subset"
    property_corpus_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_repository_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    approved_executor_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    approved_isolation_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    property_repositories: dict[str, str] = Field(min_length=1, max_length=10_000)
    specifications: list[SourceMutationSpec] = Field(min_length=1, max_length=100_000)
    bindings: list[MutationApplicabilityBinding] = Field(min_length=1, max_length=100_000)
    non_applicability: list[MutationNonApplicabilityRecord] = Field(
        default_factory=list,
        max_length=100_000,
    )
    kind_accounting: list[MutationKindAccounting] = Field(
        min_length=len(IMPLEMENTED_MUTATION_KINDS),
        max_length=len(IMPLEMENTED_MUTATION_KINDS),
    )
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> MutationApplicabilityPlan:
        """Construct a plan whose hash is derived from its complete typed denominator."""

        if "plan_sha256" in values:
            raise ValueError("plan_sha256 is derived and cannot be supplied")
        provisional = cls.model_construct(**values, plan_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"plan_sha256"})
        return cls.model_validate(
            {
                **payload,
                "plan_sha256": _canonical_sha256(payload),
            }
        )

    @model_validator(mode="after")
    def denominator_is_complete_and_hash_bound(self) -> MutationApplicabilityPlan:
        property_ids = sorted(self.property_repositories)
        if list(self.property_repositories) != sorted(self.property_repositories):
            raise ValueError("mutation plan repository bindings must be sorted")
        if any(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", repository_id) is None
            for repository_id in self.property_repositories.values()
        ):
            raise ValueError("mutation plan repository bindings are invalid")
        specification_ids = [item.id for item in self.specifications]
        if specification_ids != sorted(set(specification_ids)):
            raise ValueError("mutation plan specifications must be unique and sorted by ID")
        binding_pairs = [(item.property_id, item.mutation_id) for item in self.bindings]
        if binding_pairs != sorted(set(binding_pairs)):
            raise ValueError("mutation applicability pairs must be unique and sorted")
        non_applicable_pairs = [
            (item.property_id, item.mutation_id) for item in self.non_applicability
        ]
        if non_applicable_pairs != sorted(set(non_applicable_pairs)):
            raise ValueError("mutation non-applicability pairs must be unique and sorted")
        if set(binding_pairs) & set(non_applicable_pairs):
            raise ValueError("one candidate/property pair cannot have conflicting applicability")
        inventory_size = len(property_ids) * len(specification_ids)
        if inventory_size > 100_000:
            raise ValueError("mutation candidate/applicability inventory exceeds its limit")
        expected_inventory = {
            (property_id, mutation_id)
            for property_id in property_ids
            for mutation_id in specification_ids
        }
        observed_inventory = set(binding_pairs) | set(non_applicable_pairs)
        if observed_inventory != expected_inventory:
            raise ValueError(
                "every declared candidate/property pair requires explicit applicability"
            )
        accounting_kinds = [item.kind for item in self.kind_accounting]
        expected_kinds = sorted(IMPLEMENTED_MUTATION_KINDS, key=lambda item: item.value)
        if accounting_kinds != expected_kinds:
            raise ValueError("mutation kind accounting must cover the implemented subset exactly")
        specifications_by_kind = {
            kind: sorted(item.id for item in self.specifications if item.kind is kind)
            for kind in IMPLEMENTED_MUTATION_KINDS
        }
        for accounting in self.kind_accounting:
            if accounting.candidate_ids != specifications_by_kind[accounting.kind]:
                raise ValueError("mutation kind accounting differs from declared candidates")
        payload = self.model_dump(mode="json", exclude={"plan_sha256"})
        if self.plan_sha256 != _canonical_sha256(payload):
            raise ValueError("mutation applicability plan hash does not match its contents")
        return self


class MutationSuiteTestStatus(StrEnum):
    """Bounded suite status used to derive, never declare, mutation credit."""

    PASSED = "passed"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    TIMED_OUT = "timed_out"
    INVALID_OUTPUT = "invalid_output"


class MutationSuiteTestObservation(StrictModel):
    """One path-free baseline or mutant test observation."""

    test_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}$")
    status: MutationSuiteTestStatus


class MutationSuiteObservation(StrictModel):
    """Typed same-selection baseline/mutant execution evidence from one executor."""

    schema_version: Literal["1.0"] = "1.0"
    mutation_id: str = Field(pattern=r"^mut-[a-z0-9][a-z0-9-]{0,75}$")
    baseline_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    mutant_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    suite_selection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    executor_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    isolation_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_execution_evidence: ExecutionEvidenceKind
    mutant_execution_evidence: ExecutionEvidenceKind
    baseline_isolation_attestation_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    mutant_isolation_attestation_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    baseline_compilation_succeeded: bool
    mutant_compilation_succeeded: bool
    baseline_tests: list[MutationSuiteTestObservation] = Field(
        min_length=1,
        max_length=10_000,
    )
    mutant_tests: list[MutationSuiteTestObservation] = Field(
        min_length=1,
        max_length=10_000,
    )
    observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @staticmethod
    def calculate_selection_sha256(test_ids: list[str]) -> str:
        """Bind one canonical nonempty test inventory independently from outcomes."""

        if not test_ids or test_ids != sorted(set(test_ids)):
            raise ValueError("mutation suite selection requires unique sorted test IDs")
        return _canonical_sha256({"test_ids": test_ids})

    @classmethod
    def sealed(cls, **values: Any) -> MutationSuiteObservation:
        """Construct a self-hashed execution observation."""

        if "observation_sha256" in values:
            raise ValueError("observation_sha256 is derived and cannot be supplied")
        provisional = cls.model_construct(**values, observation_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"observation_sha256"})
        return cls.model_validate(
            {
                **payload,
                "observation_sha256": _canonical_sha256(payload),
            }
        )

    @model_validator(mode="after")
    def observation_is_ordered_and_hash_bound(self) -> MutationSuiteObservation:
        observed_test_ids: list[list[str]] = []
        for observations, label in (
            (self.baseline_tests, "baseline"),
            (self.mutant_tests, "mutant"),
        ):
            test_ids = [item.test_id for item in observations]
            if test_ids != sorted(set(test_ids)):
                raise ValueError(f"{label} mutation test observations must be unique and sorted")
            observed_test_ids.append(test_ids)
        if observed_test_ids[0] != observed_test_ids[1]:
            raise ValueError("baseline and mutant must execute the same exact nonempty suite")
        if self.suite_selection_sha256 != self.calculate_selection_sha256(observed_test_ids[0]):
            raise ValueError("mutation suite selection hash does not match its test inventory")
        payload = self.model_dump(mode="json", exclude={"observation_sha256"})
        if self.observation_sha256 != _canonical_sha256(payload):
            raise ValueError("mutation suite observation hash does not match its contents")
        return self


class MutationCampaignEvidence(StrictModel):
    """Path-free source, execution, restoration, and disposal evidence for one mutant."""

    schema_version: Literal["1.0"] = "1.0"
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    mutation_id: str = Field(pattern=r"^mut-[a-z0-9][a-z0-9-]{0,75}$")
    mutation_specification_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_repository_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    pristine_workspace_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    mutated_workspace_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    restored_workspace_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    executor_observation: MutationSuiteObservation | None = None
    restoration_verified: bool
    workspace_disposed: bool
    source_preserved: bool
    disposal_entry_count: int = Field(ge=0, le=_MAX_MUTATION_REMOVAL_ENTRIES)
    failure_kind: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_]{0,99}$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> MutationCampaignEvidence:
        """Construct self-hashed path-free campaign evidence."""

        if "evidence_sha256" in values:
            raise ValueError("evidence_sha256 is derived and cannot be supplied")
        provisional = cls.model_construct(**values, evidence_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"evidence_sha256"})
        return cls.model_validate(
            {
                **payload,
                "evidence_sha256": _canonical_sha256(payload),
            }
        )

    @model_validator(mode="after")
    def campaign_is_hash_bound(self) -> MutationCampaignEvidence:
        if self.restoration_verified and (
            self.restored_workspace_sha256 != self.source_repository_sha256
        ):
            raise ValueError("mutation restoration claim does not match its source hash")
        payload = self.model_dump(mode="json", exclude={"evidence_sha256"})
        if self.evidence_sha256 != _canonical_sha256(payload):
            raise ValueError("mutation campaign evidence hash does not match its contents")
        return self


class MutationCampaignExecutor(Protocol):
    """Trusted adapter boundary for a baseline/mutant suite comparison."""

    def execute(
        self,
        *,
        baseline_workspace: Path,
        mutant_workspace: Path,
        specification: SourceMutationSpec,
    ) -> MutationSuiteObservation:
        """Execute a fixed typed suite and return path-free normalized evidence."""

        ...


class MutationTestOutcome(StrEnum):
    """Normalized result of challenging one property with one applicable mutation."""

    KILLED = "killed"
    SURVIVED = "survived"
    INCONCLUSIVE = "inconclusive"


class MutationScorecardEvidenceOrigin(StrEnum):
    """Trust origin of mutation outcomes; neither member is runtime attestation."""

    DECLARATIVE = "declarative"
    PLANNED_UNATTESTED = "planned_unattested"


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
    evidence_origin: MutationScorecardEvidenceOrigin = MutationScorecardEvidenceOrigin.DECLARATIVE
    applicability_plan_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
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
        if (
            self.evidence_origin is MutationScorecardEvidenceOrigin.DECLARATIVE
            and self.applicability_plan_sha256 is not None
        ):
            raise ValueError("declarative mutation evidence cannot claim an applicability plan")
        if (
            self.evidence_origin is MutationScorecardEvidenceOrigin.PLANNED_UNATTESTED
            and self.applicability_plan_sha256 is None
        ):
            raise ValueError("planned mutation evidence requires its applicability plan hash")
        if self.evidence_origin is MutationScorecardEvidenceOrigin.PLANNED_UNATTESTED and (
            any(item.outcome is not MutationTestOutcome.INCONCLUSIVE for item in self.outcomes)
            or self.gate_passed
        ):
            raise ValueError("unattested planned mutation evidence cannot award decisive credit")
        return self

    def require_planned_campaign_origin(self) -> None:
        """Reject legacy declarative scorecards at audited-suite boundaries."""

        validated = MutationScorecard.model_validate(self.model_dump(mode="python"))
        if validated.evidence_origin is not MutationScorecardEvidenceOrigin.PLANNED_UNATTESTED:
            raise ValueError("audited-suite mutation evidence requires planned campaign origin")


def score_mutation_outcomes(
    *,
    property_corpus_hash: str,
    expected_property_ids: list[str],
    property_repositories: dict[str, str],
    outcomes: list[MutationPropertyOutcome],
    minimum_property_kill_score: float,
) -> MutationScorecard:
    """Build a legacy declarative scorecard that is never audited-suite runtime evidence."""

    return _score_mutation_outcomes(
        property_corpus_hash=property_corpus_hash,
        expected_property_ids=expected_property_ids,
        property_repositories=property_repositories,
        outcomes=outcomes,
        minimum_property_kill_score=minimum_property_kill_score,
        evidence_origin=MutationScorecardEvidenceOrigin.DECLARATIVE,
        applicability_plan_sha256=None,
    )


def _score_mutation_outcomes(
    *,
    property_corpus_hash: str,
    expected_property_ids: list[str],
    property_repositories: dict[str, str],
    outcomes: list[MutationPropertyOutcome],
    minimum_property_kill_score: float,
    evidence_origin: MutationScorecardEvidenceOrigin,
    applicability_plan_sha256: str | None,
) -> MutationScorecard:
    """Build one scorecard while keeping evidence-origin selection private."""

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
        evidence_origin=evidence_origin,
        applicability_plan_sha256=applicability_plan_sha256,
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


def score_planned_mutation_campaigns(
    *,
    plan: MutationApplicabilityPlan,
    campaigns: list[MutationCampaignEvidence],
    minimum_property_kill_score: float,
) -> MutationScorecard:
    """Record every planned pair without awarding unavailable production-runtime credit."""

    plan = MutationApplicabilityPlan.model_validate(plan.model_dump(mode="python"))
    campaigns = [
        MutationCampaignEvidence.model_validate(campaign.model_dump(mode="python"))
        for campaign in campaigns
    ]
    campaign_by_mutation: dict[str, MutationCampaignEvidence] = {}
    for campaign_record in campaigns:
        if campaign_record.plan_sha256 != plan.plan_sha256:
            raise ValueError("mutation campaign does not bind the applicability plan")
        if campaign_record.mutation_id in campaign_by_mutation:
            raise ValueError("mutation campaigns must be unique by mutation ID")
        campaign_by_mutation[campaign_record.mutation_id] = campaign_record
    specifications = {item.id: item for item in plan.specifications}
    unexpected = sorted(set(campaign_by_mutation) - set(specifications))
    if unexpected:
        raise ValueError("mutation campaign references an unexpected source mutation")

    outcomes: list[MutationPropertyOutcome] = []
    for binding in plan.bindings:
        specification = specifications[binding.mutation_id]
        matched_campaign = campaign_by_mutation.get(binding.mutation_id)
        if matched_campaign is None:
            outcome = MutationTestOutcome.INCONCLUSIVE
            evidence_sha256 = _canonical_sha256(
                {
                    "plan_sha256": plan.plan_sha256,
                    "property_id": binding.property_id,
                    "mutation_id": binding.mutation_id,
                    "status": "missing",
                }
            )
        else:
            if (
                matched_campaign.mutation_specification_sha256
                != specification.specification_sha256()
            ):
                raise ValueError("mutation campaign source specification binding is invalid")
            if matched_campaign.source_repository_sha256 != plan.source_repository_sha256:
                raise ValueError("mutation campaign source repository binding is invalid")
            outcome = MutationTestOutcome.INCONCLUSIVE
            evidence_sha256 = matched_campaign.evidence_sha256
        outcomes.append(
            MutationPropertyOutcome(
                mutation_id=binding.mutation_id,
                mutation_kind=specification.kind,
                property_id=binding.property_id,
                outcome=outcome,
                evidence_sha256=evidence_sha256,
            )
        )

    return _score_mutation_outcomes(
        property_corpus_hash=plan.property_corpus_hash,
        expected_property_ids=sorted(plan.property_repositories),
        property_repositories=plan.property_repositories,
        outcomes=outcomes,
        minimum_property_kill_score=minimum_property_kill_score,
        evidence_origin=MutationScorecardEvidenceOrigin.PLANNED_UNATTESTED,
        applicability_plan_sha256=plan.plan_sha256,
    )


def _derive_mutation_suite_outcome(
    binding: MutationApplicabilityBinding,
    observation: MutationSuiteObservation,
) -> MutationTestOutcome:
    """Pure non-crediting classifier reserved for component tests and future attestation."""

    baseline = {item.test_id: item.status for item in observation.baseline_tests}
    mutant = {item.test_id: item.status for item in observation.mutant_tests}
    if not baseline or set(baseline) != set(mutant):
        return MutationTestOutcome.INCONCLUSIVE
    applicable = set(binding.test_ids)
    if not applicable <= set(baseline):
        return MutationTestOutcome.INCONCLUSIVE
    if any(status is not MutationSuiteTestStatus.PASSED for status in baseline.values()):
        return MutationTestOutcome.INCONCLUSIVE
    if any(
        status
        not in {
            MutationSuiteTestStatus.PASSED,
            MutationSuiteTestStatus.FAILED,
        }
        for status in mutant.values()
    ):
        return MutationTestOutcome.INCONCLUSIVE
    mutant_statuses = [mutant[test_id] for test_id in applicable]
    if any(status is MutationSuiteTestStatus.FAILED for status in mutant_statuses):
        return MutationTestOutcome.KILLED
    return MutationTestOutcome.SURVIVED


def load_mutation_scorecard(path: Path) -> MutationScorecard:
    """Load only legacy declarative scorecards; planned evidence is process-local."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("mutation scorecard must be a regular non-symlink file")
    if path.stat().st_size > 20_000_000:
        raise ValueError("mutation scorecard exceeds the 20 MB limit")
    scorecard = MutationScorecard.model_validate_json(path.read_text(encoding="utf-8"))
    if scorecard.evidence_origin is not MutationScorecardEvidenceOrigin.DECLARATIVE:
        raise ValueError("persisted mutation scorecards must have declarative evidence origin")
    return scorecard


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


@dataclass
class _MutationRemovalBudget:
    """Bound the exact number and depth of descriptor-relative removals."""

    removed_entries: int = 0

    def consume(self, depth: int) -> None:
        if depth < 0 or depth > _MAX_MUTATION_REMOVAL_DEPTH:
            raise ValueError("mutation workspace cleanup exceeded its depth limit")
        self.removed_entries += 1
        if self.removed_entries > _MAX_MUTATION_REMOVAL_ENTRIES:
            raise ValueError("mutation workspace cleanup exceeded its entry limit")


@dataclass
class _OwnedMutationRoot:
    """Retain no-follow custody of an owner-only campaign namespace."""

    path: Path
    descriptor: int
    device: int
    inode: int
    closed: bool = False

    def assert_descriptor_stable(self) -> None:
        if self.closed:
            raise ValueError("mutation private-root custody is closed")
        descriptor_stat = os.fstat(self.descriptor)
        if (
            not stat.S_ISDIR(descriptor_stat.st_mode)
            or descriptor_stat.st_uid != os.geteuid()
            or stat.S_IMODE(descriptor_stat.st_mode) != 0o700
            or (descriptor_stat.st_dev, descriptor_stat.st_ino) != (self.device, self.inode)
        ):
            raise ValueError("mutation private-root descriptor identity changed")

    def assert_stable(self) -> None:
        self.assert_descriptor_stable()
        named_stat = self.path.lstat()
        if (
            not stat.S_ISDIR(named_stat.st_mode)
            or stat.S_ISLNK(named_stat.st_mode)
            or (named_stat.st_dev, named_stat.st_ino) != (self.device, self.inode)
        ):
            raise ValueError("mutation private-root identity changed")

    def capture_child(self, name: str) -> _OwnedMutationWorkspace:
        """Capture one already-created direct child without following its name."""

        if not name or name in {".", ".."} or "/" in name:
            raise ValueError("mutation workspace child name is invalid")
        self.assert_stable()
        named_stat = os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)
        if (
            not stat.S_ISDIR(named_stat.st_mode)
            or named_stat.st_uid != os.geteuid()
            or named_stat.st_dev != self.device
        ):
            raise ValueError("mutation workspace child is not an owned local directory")
        descriptor = os.open(name, _mutation_directory_open_flags(), dir_fd=self.descriptor)
        try:
            descriptor_stat = os.fstat(descriptor)
            if not _same_file_identity(named_stat, descriptor_stat):
                raise ValueError("mutation workspace child changed while custody opened it")
            return _OwnedMutationWorkspace(
                parent=self,
                name=name,
                descriptor=descriptor,
                device=descriptor_stat.st_dev,
                inode=descriptor_stat.st_ino,
            )
        except BaseException:
            os.close(descriptor)
            raise

    def create_child(self, name: str) -> _OwnedMutationWorkspace:
        """Exclusively create and capture one direct private child."""

        if not name or name in {".", ".."} or "/" in name:
            raise ValueError("mutation workspace child name is invalid")
        self.assert_stable()
        custody: _OwnedMutationWorkspace | None = None
        descriptor: int | None = None
        try:
            os.mkdir(name, mode=0o700, dir_fd=self.descriptor)
            descriptor = os.open(name, _mutation_directory_open_flags(), dir_fd=self.descriptor)
            descriptor_stat = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(descriptor_stat.st_mode)
                or descriptor_stat.st_uid != os.geteuid()
                or descriptor_stat.st_dev != self.device
            ):
                raise ValueError("created mutation workspace is not an owned local directory")
            custody = _OwnedMutationWorkspace(
                parent=self,
                name=name,
                descriptor=descriptor,
                device=descriptor_stat.st_dev,
                inode=descriptor_stat.st_ino,
            )
            descriptor = None
            named_stat = os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)
            if not _same_file_identity(named_stat, descriptor_stat):
                raise ValueError("created mutation workspace name changed during capture")
            return custody
        except BaseException:
            if custody is not None:
                try:
                    custody.dispose(_MutationRemovalBudget())
                except (OSError, ValueError):
                    custody.close()
            elif descriptor is not None:
                os.close(descriptor)
            # A child whose directory descriptor was never captured has no
            # trustworthy identity. Leave that failed-setup residue in the
            # private root and fail closed; deleting by its current name could
            # remove an unrelated replacement after a rename race.
            raise

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        os.close(self.descriptor)


@dataclass
class _OwnedMutationWorkspace:
    """Descriptor custody for one exact disposable child."""

    parent: _OwnedMutationRoot
    name: str
    descriptor: int
    device: int
    inode: int
    closed: bool = False

    def assert_descriptor_stable(self) -> None:
        if self.closed:
            raise ValueError("mutation workspace custody is closed")
        self.parent.assert_descriptor_stable()
        descriptor_stat = os.fstat(self.descriptor)
        if not stat.S_ISDIR(descriptor_stat.st_mode) or (
            descriptor_stat.st_dev,
            descriptor_stat.st_ino,
        ) != (self.device, self.inode):
            raise ValueError("mutation workspace descriptor identity changed")

    def dispose(self, budget: _MutationRemovalBudget) -> bool:
        """Remove the observed owned child within its retained owner-only namespace.

        POSIX exposes descriptor-relative ``rmdir`` but no portable operation that
        atomically predicates directory removal on an already-open inode. The
        surrounding 0700 parent is therefore a required capability boundary; a
        same-UID actor that can mutate that namespace remains outside this
        function's portable safety guarantee.
        """

        try:
            self.assert_descriptor_stable()
            _remove_owned_mutation_contents(
                self.descriptor,
                root_device=self.device,
                depth=0,
                budget=budget,
            )
            self.assert_descriptor_stable()
            owned_name = _find_owned_mutation_child_name(
                self.parent.descriptor,
                device=self.device,
                inode=self.inode,
            )
            if owned_name is None:
                raise ValueError("descriptor-held mutation workspace is no longer a direct child")
            named_stat = _directory_identity_without_following(
                self.parent.descriptor,
                owned_name,
            )
            if named_stat is None or (named_stat.st_dev, named_stat.st_ino) != (
                self.device,
                self.inode,
            ):
                raise ValueError("mutation workspace name changed before removal")
            budget.consume(0)
            os.rmdir(owned_name, dir_fd=self.parent.descriptor)
            self.assert_descriptor_stable()
            remaining_path = _find_owned_mutation_descendant_path(
                self.parent.descriptor,
                device=self.device,
                inode=self.inode,
            )
            if remaining_path is not None:
                raise ValueError("removed mutation workspace identity remains linked")
            return True
        finally:
            self.close()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        os.close(self.descriptor)


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

    return scanner_workspace_sha256(repository)


def run_owned_mutation_campaign(
    *,
    source_repository: Path,
    private_root: Path,
    plan: MutationApplicabilityPlan,
    mutation_id: str,
    executor: MutationCampaignExecutor,
) -> MutationCampaignEvidence:
    """Run one typed comparison inside one exclusively owned, always-disposed child."""

    plan = MutationApplicabilityPlan.model_validate(plan.model_dump(mode="python"))
    source = source_repository.resolve(strict=True)
    source_sha256 = mutation_repository_sha256(source)
    if source_sha256 != plan.source_repository_sha256:
        raise ValueError("mutation campaign source does not match the applicability plan")
    specifications = {item.id: item for item in plan.specifications}
    try:
        specification = specifications[mutation_id]
    except KeyError as exc:
        raise ValueError("mutation campaign ID is not present in the applicability plan") from exc

    root = _open_owned_mutation_root(private_root)
    try:
        source_custody = retain_scanner_workspace_source_custody(source)
    except BaseException:
        root.close()
        raise
    try:
        if source_custody.source_inventory_sha256_before != source_sha256:
            raise ValueError("mutation campaign source changed before custody")
    except BaseException:
        source_custody.close()
        root.close()
        raise
    campaign_name = f"mmaudit-campaign-{mutation_id}"
    campaign_custody: _OwnedMutationWorkspace | None = None
    application: AppliedSourceMutation | None = None
    setup_complete = False
    executor_observation: MutationSuiteObservation | None = None
    failure_kind: str | None = None
    restored_workspace_sha256: str | None = None
    restoration_verified = False
    workspace_disposed = False
    source_preserved = False
    removal_budget = _MutationRemovalBudget()
    try:
        campaign_custody = root.create_child(campaign_name)
        campaign_root = root.path / campaign_name
        baseline_workspace = campaign_root / "baseline"
        mutant_workspace = campaign_root / "mutant"
        _copy_pristine_mutation_workspace(source, baseline_workspace)
        application = apply_source_mutation(
            source_repository=source,
            workspace=mutant_workspace,
            specification=specification,
        )
        if application.source_repository_sha256 != source_sha256:
            raise ValueError("mutation application source differs from the campaign plan")
        setup_complete = True
        try:
            supplied_observation = executor.execute(
                baseline_workspace=baseline_workspace,
                mutant_workspace=mutant_workspace,
                specification=specification,
            )
            executor_observation = MutationSuiteObservation.model_validate(
                supplied_observation.model_dump(mode="python")
            )
        except Exception as exc:
            failure_kind = type(exc).__name__

        baseline_restored = False
        try:
            baseline_restored = mutation_repository_sha256(baseline_workspace) == source_sha256
        except (OSError, ValueError):
            failure_kind = failure_kind or "BaselineIntegrityError"
        try:
            restoration = revert_source_mutation(application)
            restored_workspace_sha256 = restoration.restored_workspace_sha256
        except (OSError, ValueError):
            failure_kind = failure_kind or "RestorationIntegrityError"
        restoration_verified = bool(
            baseline_restored and restored_workspace_sha256 == source_sha256
        )
    finally:
        try:
            if campaign_custody is not None:
                try:
                    workspace_disposed = campaign_custody.dispose(removal_budget)
                except (OSError, ValueError):
                    campaign_custody.close()
                    workspace_disposed = False
        finally:
            try:
                root.close()
            finally:
                try:
                    source_preserved = source_custody.finalize() == source_sha256
                except (OSError, ValueError):
                    source_preserved = False
        if not setup_complete and (not workspace_disposed or not source_preserved):
            raise ValueError(
                "mutation campaign setup failed without verified cleanup and source preservation"
            )

    if application is None:
        raise ValueError("mutation campaign workspace setup failed")
    if not workspace_disposed:
        failure_kind = failure_kind or "WorkspaceDisposalError"
    if not source_preserved:
        failure_kind = failure_kind or "SourceIntegrityError"

    return MutationCampaignEvidence.sealed(
        plan_sha256=plan.plan_sha256,
        mutation_id=mutation_id,
        mutation_specification_sha256=specification.specification_sha256(),
        source_repository_sha256=source_sha256,
        pristine_workspace_sha256=application.pristine_workspace_sha256,
        mutated_workspace_sha256=application.mutated_workspace_sha256,
        restored_workspace_sha256=restored_workspace_sha256,
        executor_observation=executor_observation,
        restoration_verified=restoration_verified,
        workspace_disposed=workspace_disposed,
        source_preserved=source_preserved,
        disposal_entry_count=removal_budget.removed_entries,
        failure_kind=failure_kind,
    )


def apply_source_mutation(
    *,
    source_repository: Path,
    workspace: Path,
    specification: SourceMutationSpec,
) -> AppliedSourceMutation:
    """Copy a bounded repository and apply one hash-pinned defensive mutation."""

    source = source_repository.resolve(strict=True)
    if scanner_workspace_file_sha256(source, specification.path) != (
        specification.expected_file_sha256
    ):
        raise ValueError("mutation source hash does not match the planned source")
    destination = _validate_disposable_destination(source, workspace)
    copy_custody = copy_scanner_workspace_with_custody(
        source,
        destination,
        source / ".mmaudit",
        audited_relative_paths=(specification.path,),
    )
    copy_observation = copy_custody.finalize()
    source_tree_sha256 = copy_observation.source_inventory_sha256_before
    pristine_workspace_sha256 = copy_observation.workspace_inventory_sha256_after_copy
    if (
        copy_observation.source_inventory_sha256_after != source_tree_sha256
        or pristine_workspace_sha256 != source_tree_sha256
    ):
        raise ValueError("disposable mutation copy does not match the source tree")

    workspace_target = _source_target(destination, specification)
    original_bytes = workspace_target.read_bytes()
    original_file_sha256 = _sha256(original_bytes)
    if original_file_sha256 != specification.expected_file_sha256:
        raise ValueError("copied mutation source hash does not match the planned source")
    mutated_bytes, original_line, mutated_line, line_ending = _mutated_source(
        original_bytes,
        specification,
    )
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


def _copy_pristine_mutation_workspace(source: Path, workspace: Path) -> None:
    """Create one exact unmutated sibling using the mutation copy policy."""

    destination = _validate_disposable_destination(source, workspace)
    copy_custody = copy_scanner_workspace_with_custody(
        source,
        destination,
        source / ".mmaudit",
    )
    observation = copy_custody.finalize()
    if (
        observation.source_inventory_sha256_before != observation.source_inventory_sha256_after
        or observation.workspace_inventory_sha256_after_copy
        != observation.source_inventory_sha256_before
    ):
        raise ValueError("baseline mutation workspace does not match the source tree")


def _open_owned_mutation_root(private_root: Path) -> _OwnedMutationRoot:
    """Open a canonical 0700 root with required no-follow descriptor support."""

    required_dir_fd = (os.open, os.stat, os.mkdir, os.rmdir, os.unlink)
    if any(function not in os.supports_dir_fd for function in required_dir_fd):
        raise ValueError("descriptor-relative mutation workspace operations are unavailable")
    if os.scandir not in os.supports_fd:
        raise ValueError("descriptor-relative mutation workspace enumeration is unavailable")
    requested = Path(os.path.abspath(private_root))
    try:
        named_stat = requested.lstat()
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise ValueError("mutation private root is unavailable") from exc
    if (
        requested != resolved
        or stat.S_ISLNK(named_stat.st_mode)
        or not stat.S_ISDIR(named_stat.st_mode)
        or named_stat.st_uid != os.geteuid()
        or stat.S_IMODE(named_stat.st_mode) != 0o700
    ):
        raise ValueError("mutation private root must be canonical, mode 0700, and operator-owned")
    descriptor = os.open(resolved, _mutation_directory_open_flags())
    try:
        descriptor_stat = os.fstat(descriptor)
        if not _same_file_identity(named_stat, descriptor_stat):
            raise ValueError("mutation private root changed while custody opened it")
        return _OwnedMutationRoot(
            path=resolved,
            descriptor=descriptor,
            device=descriptor_stat.st_dev,
            inode=descriptor_stat.st_ino,
        )
    except BaseException:
        os.close(descriptor)
        raise


def _mutation_directory_open_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", None)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(directory, int) or directory == 0:
        raise ValueError("directory-only mutation workspace custody is unavailable")
    if not isinstance(no_follow, int) or no_follow == 0:
        raise ValueError("no-follow mutation workspace custody is unavailable")
    return os.O_RDONLY | directory | no_follow | int(getattr(os, "O_CLOEXEC", 0))


def _remove_owned_mutation_contents(
    directory_descriptor: int,
    *,
    root_device: int,
    depth: int,
    budget: _MutationRemovalBudget,
) -> None:
    """Boundedly remove descriptor-relative entries without following links."""

    if depth > _MAX_MUTATION_REMOVAL_DEPTH:
        raise ValueError("mutation workspace cleanup exceeded its depth limit")
    remaining_entries = _MAX_MUTATION_REMOVAL_ENTRIES - budget.removed_entries
    names = _bounded_directory_entry_names(
        directory_descriptor,
        maximum_entries=remaining_entries,
        bound_error="mutation workspace cleanup exceeded its entry limit",
    )
    for name in names:
        budget.consume(depth + 1)
        before = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if before.st_dev != root_device:
            raise ValueError("mutation workspace entry crossed its owned filesystem")
        if stat.S_ISDIR(before.st_mode):
            child_descriptor = os.open(
                name,
                _mutation_directory_open_flags(),
                dir_fd=directory_descriptor,
            )
            try:
                if not _same_file_identity(before, os.fstat(child_descriptor)):
                    raise ValueError("mutation workspace directory changed while opened")
                _remove_owned_mutation_contents(
                    child_descriptor,
                    root_device=root_device,
                    depth=depth + 1,
                    budget=budget,
                )
                named_after = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                if not _same_file_identity(before, os.fstat(child_descriptor)) or not (
                    _same_file_identity(before, named_after)
                ):
                    raise ValueError("mutation workspace directory changed before removal")
                os.rmdir(name, dir_fd=directory_descriptor)
            finally:
                os.close(child_descriptor)
            continue
        current = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if not _same_file_identity(before, current):
            raise ValueError("mutation workspace leaf changed before removal")
        os.unlink(name, dir_fd=directory_descriptor)


def _find_owned_mutation_child_name(
    parent_descriptor: int,
    *,
    device: int,
    inode: int,
) -> str | None:
    """Find one retained direct child by identity without following replaced names."""

    names = _bounded_directory_entry_names(
        parent_descriptor,
        maximum_entries=_MAX_MUTATION_REMOVAL_ENTRIES,
        bound_error="mutation workspace parent enumeration exceeded its entry limit",
    )
    matched_name: str | None = None
    for name in names:
        metadata = _directory_identity_without_following(parent_descriptor, name)
        if metadata is None:
            continue
        if (metadata.st_dev, metadata.st_ino) == (device, inode):
            if matched_name is not None:
                raise ValueError("mutation workspace identity has multiple direct-child names")
            matched_name = name
    return matched_name


def _find_owned_mutation_descendant_path(
    parent_descriptor: int,
    *,
    device: int,
    inode: int,
) -> str | None:
    """Boundedly prove that an owned inode is absent anywhere below its private root."""

    inspected_entries = [0]

    def search(directory_descriptor: int, prefix: PurePosixPath, depth: int) -> str | None:
        if depth > _MAX_MUTATION_REMOVAL_DEPTH:
            raise ValueError("mutation workspace identity search exceeded its depth limit")
        remaining = _MAX_MUTATION_REMOVAL_ENTRIES - inspected_entries[0]
        names = _bounded_directory_entry_names(
            directory_descriptor,
            maximum_entries=remaining,
            bound_error="mutation workspace identity search exceeded its entry limit",
        )
        for name in names:
            inspected_entries[0] += 1
            if inspected_entries[0] > _MAX_MUTATION_REMOVAL_ENTRIES:
                raise ValueError("mutation workspace identity search exceeded its entry limit")
            before = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
            relative = prefix / name
            if (before.st_dev, before.st_ino) == (device, inode):
                return relative.as_posix()
            if not stat.S_ISDIR(before.st_mode):
                continue
            if before.st_dev != device:
                raise ValueError("mutation workspace identity search crossed its filesystem")
            child_descriptor = os.open(
                name,
                _mutation_directory_open_flags(),
                dir_fd=directory_descriptor,
            )
            try:
                if not _same_file_identity(before, os.fstat(child_descriptor)):
                    raise ValueError(
                        "mutation workspace identity search directory changed while opened"
                    )
                matched = search(child_descriptor, relative, depth + 1)
                if matched is not None:
                    return matched
            finally:
                os.close(child_descriptor)
        return None

    return search(parent_descriptor, PurePosixPath("."), 0)


def _directory_identity_without_following(
    parent_descriptor: int,
    name: str,
) -> os.stat_result | None:
    """Observe one child directory through a transient no-follow descriptor."""

    try:
        descriptor = os.open(name, _mutation_directory_open_flags(), dir_fd=parent_descriptor)
    except OSError:
        return None
    try:
        metadata = os.fstat(descriptor)
        return metadata if stat.S_ISDIR(metadata.st_mode) else None
    finally:
        os.close(descriptor)


def _bounded_directory_entry_names(
    directory_descriptor: int,
    *,
    maximum_entries: int,
    bound_error: str,
) -> list[str]:
    """Enumerate at most the declared count plus one unstored sentinel."""

    if maximum_entries < 0:
        raise ValueError(bound_error)
    names: list[str] = []
    with os.scandir(directory_descriptor) as iterator:
        for entry in iterator:
            if len(names) >= maximum_entries:
                raise ValueError(bound_error)
            names.append(entry.name)
    names.sort()
    return names


def _same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _validate_disposable_destination(source: Path, workspace: Path) -> Path:
    requested = workspace.absolute()
    try:
        requested.lstat()
    except FileNotFoundError:
        pass
    else:
        raise ValueError("mutation workspace must not already exist")
    requested_parent = requested.parent
    parent = requested_parent.resolve(strict=True)
    if (
        requested_parent != parent
        or not parent.is_dir()
        or requested_parent.is_symlink()
        or requested_parent.is_junction()
    ):
        raise ValueError("mutation workspace parent must be a regular directory")
    destination = parent / requested.name
    try:
        destination.relative_to(source)
    except ValueError:
        pass
    else:
        raise ValueError("mutation workspace must remain outside the source repository")
    if not destination.name or destination.name in {".", ".."}:
        raise ValueError("mutation workspace name is invalid")
    return destination


def _workspace_path_excluded(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    return audited_workspace_relative_excluded(relative, is_dir=path.is_dir())


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_sha256(payload: object) -> str:
    return _sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
