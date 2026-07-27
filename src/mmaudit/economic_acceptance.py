"""Typed evidence for the synthetic economic-protocol acceptance portfolio."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.models.schemas import EconomicSimulationKind, StrictModel
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_name, is_sensitive_workspace_path

_MAX_MANIFEST_BYTES = 2_000_000
_MAX_FIXTURE_FILE_BYTES = 10_000_000
_MAX_REPORT_BYTES = 10_000_000
_REQUIRED_TICKETS = {f"ECO-{index:03d}" for index in range(1, 19)}
_CONTRACT_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,99}$")


class EconomicAcceptanceStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"


class EconomicAcceptanceCase(StrictModel):
    """One source-bound unsafe/safe fixture pair in the acceptance portfolio."""

    ticket_id: str = Field(pattern=r"^ECO-[0-9]{3}$")
    template: EconomicSimulationKind
    fixture_path: str = Field(min_length=1, max_length=500)
    config_path: Literal["foundry.toml"] = "foundry.toml"
    config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_path: str = Field(min_length=1, max_length=500)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    test_path: str = Field(min_length=1, max_length=500)
    test_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    unsafe_contracts: list[str] = Field(min_length=1, max_length=20)
    safe_contracts: list[str] = Field(min_length=1, max_length=20)

    @field_validator("fixture_path")
    @classmethod
    def fixture_is_synthetic_and_repository_relative(cls, value: str) -> str:
        normalized = normalize_relative_path(value)
        if not normalized.startswith("tests/fixtures/solidity/economic_"):
            raise ValueError("economic acceptance fixtures must use the synthetic fixture tree")
        if is_sensitive_workspace_path(normalized, is_dir=True):
            raise ValueError("economic acceptance fixture path is sensitive")
        return normalized

    @field_validator("source_path", "test_path")
    @classmethod
    def fixture_files_are_relative_solidity(cls, value: str) -> str:
        normalized = normalize_relative_path(value)
        if (
            normalized == "."
            or not normalized.endswith(".sol")
            or is_sensitive_workspace_path(normalized)
        ):
            raise ValueError("economic acceptance fixture file must be relative Solidity")
        return normalized

    @field_validator("unsafe_contracts", "safe_contracts")
    @classmethod
    def contract_names_are_safe_sorted_and_unique(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("economic acceptance contract names must be unique and sorted")
        if any(_CONTRACT_IDENTIFIER.fullmatch(name) is None for name in value):
            raise ValueError("economic acceptance contract names must be safe identifiers")
        return value

    @model_validator(mode="after")
    def unsafe_and_safe_contracts_are_disjoint(self) -> EconomicAcceptanceCase:
        if set(self.unsafe_contracts) & set(self.safe_contracts):
            raise ValueError("unsafe and safe acceptance contracts must be disjoint")
        return self


class EconomicAcceptanceManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    generated_by: Literal["mmaudit"] = "mmaudit"
    cases: list[EconomicAcceptanceCase] = Field(min_length=18, max_length=18)
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def portfolio_is_complete_and_hash_linked(self) -> EconomicAcceptanceManifest:
        tickets = [item.ticket_id for item in self.cases]
        fixtures = [item.fixture_path for item in self.cases]
        if tickets != sorted(_REQUIRED_TICKETS):
            raise ValueError("economic acceptance manifest must cover ECO-001 through ECO-018")
        if len(fixtures) != len(set(fixtures)):
            raise ValueError("economic acceptance fixtures must be unique")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"manifest_sha256"}))
        if self.manifest_sha256 != expected:
            raise ValueError("economic acceptance manifest hash is inconsistent")
        return self


class EconomicAcceptanceObservation(StrictModel):
    """Normalized contract outcomes from two unsafe and one safe local campaign."""

    ticket_id: str = Field(pattern=r"^ECO-[0-9]{3}$")
    first_unsafe_contracts_executed: list[str] = Field(max_length=20)
    first_unsafe_counterexamples: list[str] = Field(max_length=20)
    second_unsafe_contracts_executed: list[str] = Field(max_length=20)
    second_unsafe_counterexamples: list[str] = Field(max_length=20)
    safe_contracts_executed: list[str] = Field(max_length=20)
    safe_contracts_passed: list[str] = Field(max_length=20)

    @field_validator(
        "first_unsafe_contracts_executed",
        "first_unsafe_counterexamples",
        "second_unsafe_contracts_executed",
        "second_unsafe_counterexamples",
        "safe_contracts_executed",
        "safe_contracts_passed",
    )
    @classmethod
    def observations_are_sorted_and_unique(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("economic acceptance observations must be unique and sorted")
        return value


class EconomicAcceptanceOutcome(StrictModel):
    ticket_id: str = Field(pattern=r"^ECO-[0-9]{3}$")
    template: EconomicSimulationKind
    fixture_path: str
    config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    test_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    applicable_harnesses: int = Field(ge=2, le=40)
    executed_harnesses: int = Field(ge=0, le=40)
    planted_unsafe_contracts: list[str] = Field(min_length=1, max_length=20)
    executed_unsafe_contracts: list[str] = Field(max_length=20)
    reproduced_unsafe_contracts: list[str] = Field(max_length=20)
    safe_near_miss_contracts: list[str] = Field(min_length=1, max_length=20)
    executed_safe_contracts: list[str] = Field(max_length=20)
    unconfirmed_safe_near_misses: list[str] = Field(max_length=20)
    all_applicable_harnesses_executed: bool
    replay_confirmed: bool
    safe_near_misses_remain_unconfirmed: bool
    passed: bool

    @model_validator(mode="after")
    def outcome_counts_and_status_are_consistent(self) -> EconomicAcceptanceOutcome:
        for values in (
            self.planted_unsafe_contracts,
            self.executed_unsafe_contracts,
            self.reproduced_unsafe_contracts,
            self.safe_near_miss_contracts,
            self.executed_safe_contracts,
            self.unconfirmed_safe_near_misses,
        ):
            if values != sorted(set(values)):
                raise ValueError("economic acceptance outcome contracts must be unique and sorted")
        expected_applicable = len(self.planted_unsafe_contracts) + len(
            self.safe_near_miss_contracts
        )
        if self.applicable_harnesses != expected_applicable:
            raise ValueError("economic acceptance applicability count is inconsistent")
        if not set(self.executed_unsafe_contracts) <= set(self.planted_unsafe_contracts):
            raise ValueError("executed unsafe contracts must be planted")
        if not set(self.reproduced_unsafe_contracts) <= set(self.executed_unsafe_contracts):
            raise ValueError("reproduced unsafe contracts must have executed")
        if not set(self.executed_safe_contracts) <= set(self.safe_near_miss_contracts):
            raise ValueError("executed safe contracts must be declared near-misses")
        if not set(self.unconfirmed_safe_near_misses) <= set(self.executed_safe_contracts):
            raise ValueError("unconfirmed near-misses must have executed")
        expected_executed = len(self.executed_unsafe_contracts) + len(self.executed_safe_contracts)
        if self.executed_harnesses != expected_executed:
            raise ValueError("economic acceptance execution count is inconsistent")
        expected_all_executed = (
            self.executed_unsafe_contracts == self.planted_unsafe_contracts
            and self.executed_safe_contracts == self.safe_near_miss_contracts
        )
        expected_replay = self.reproduced_unsafe_contracts == self.planted_unsafe_contracts
        expected_safe = self.unconfirmed_safe_near_misses == self.safe_near_miss_contracts
        if self.all_applicable_harnesses_executed is not expected_all_executed:
            raise ValueError("economic acceptance execution status is inconsistent")
        if self.replay_confirmed is not expected_replay:
            raise ValueError("economic acceptance replay status is inconsistent")
        if self.safe_near_misses_remain_unconfirmed is not expected_safe:
            raise ValueError("economic acceptance safe-control status is inconsistent")
        if self.passed is not (expected_all_executed and expected_replay and expected_safe):
            raise ValueError("economic acceptance outcome status is inconsistent")
        return self


class EconomicAcceptanceReportPayload(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    generated_by: Literal["mmaudit"] = "mmaudit"
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: EconomicAcceptanceStatus
    total_cases: int = Field(ge=18, le=18)
    applicable_harnesses: int = Field(ge=36, le=720)
    executed_harnesses: int = Field(ge=0, le=720)
    planted_issues: int = Field(ge=18, le=360)
    reproduced_issues: int = Field(ge=0, le=360)
    safe_near_misses: int = Field(ge=18, le=360)
    unconfirmed_safe_near_misses: int = Field(ge=0, le=360)
    outcomes: list[EconomicAcceptanceOutcome] = Field(min_length=18, max_length=18)

    @model_validator(mode="after")
    def totals_and_status_are_consistent(self) -> EconomicAcceptanceReportPayload:
        tickets = [item.ticket_id for item in self.outcomes]
        if tickets != sorted(_REQUIRED_TICKETS):
            raise ValueError("economic acceptance outcomes must cover every economic ticket")
        totals = {
            "total_cases": len(self.outcomes),
            "applicable_harnesses": sum(item.applicable_harnesses for item in self.outcomes),
            "executed_harnesses": sum(item.executed_harnesses for item in self.outcomes),
            "planted_issues": sum(len(item.planted_unsafe_contracts) for item in self.outcomes),
            "reproduced_issues": sum(
                len(item.reproduced_unsafe_contracts) for item in self.outcomes
            ),
            "safe_near_misses": sum(len(item.safe_near_miss_contracts) for item in self.outcomes),
            "unconfirmed_safe_near_misses": sum(
                len(item.unconfirmed_safe_near_misses) for item in self.outcomes
            ),
        }
        if any(getattr(self, name) != value for name, value in totals.items()):
            raise ValueError("economic acceptance report totals are inconsistent")
        expected = (
            EconomicAcceptanceStatus.PASSED
            if all(item.passed for item in self.outcomes)
            else EconomicAcceptanceStatus.FAILED
        )
        if self.status is not expected:
            raise ValueError("economic acceptance report status is inconsistent")
        return self


class EconomicAcceptanceReport(EconomicAcceptanceReportPayload):
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def report_hash_matches(self) -> EconomicAcceptanceReport:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"report_sha256"}))
        if self.report_sha256 != expected:
            raise ValueError("economic acceptance report hash is inconsistent")
        return self


def load_economic_acceptance_manifest(
    path: Path,
    *,
    repository_root: Path,
) -> EconomicAcceptanceManifest:
    """Load a self-hashed manifest and verify every local fixture binding."""

    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError("economic acceptance manifest must be a regular non-link file")
    metadata = path.stat()
    if metadata.st_nlink != 1 or metadata.st_size > _MAX_MANIFEST_BYTES:
        raise ValueError("economic acceptance manifest must be a bounded unshared file")
    manifest = EconomicAcceptanceManifest.model_validate_json(path.read_text(encoding="utf-8"))
    if repository_root.is_symlink() or repository_root.is_junction():
        raise ValueError("economic acceptance repository root may not be a link")
    root = repository_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("economic acceptance repository root must be a directory")
    for case in manifest.cases:
        fixture_root = _resolve_safe_path(root, case.fixture_path, directory=True)
        _validate_fixture_inventory(fixture_root, case)
        config = _resolve_safe_path(fixture_root, case.config_path, directory=False)
        source = _resolve_safe_path(fixture_root, case.source_path, directory=False)
        test = _resolve_safe_path(fixture_root, case.test_path, directory=False)
        if _file_sha256(config) != case.config_sha256:
            raise ValueError(f"{case.ticket_id} economic config hash mismatch")
        if _file_sha256(source) != case.source_sha256:
            raise ValueError(f"{case.ticket_id} economic source hash mismatch")
        if _file_sha256(test) != case.test_sha256:
            raise ValueError(f"{case.ticket_id} economic test hash mismatch")
    return manifest


def build_economic_acceptance_report(
    manifest: EconomicAcceptanceManifest,
    observations: list[EconomicAcceptanceObservation],
) -> EconomicAcceptanceReport:
    """Reconcile exact unsafe replay and safe-control results."""

    by_ticket = {item.ticket_id: item for item in observations}
    if len(by_ticket) != len(observations):
        raise ValueError("economic acceptance observations must have unique tickets")
    if set(by_ticket) != _REQUIRED_TICKETS:
        raise ValueError("economic acceptance observations must cover ECO-001 through ECO-018")
    outcomes: list[EconomicAcceptanceOutcome] = []
    for case in manifest.cases:
        observation = by_ticket[case.ticket_id]
        expected_unsafe = set(case.unsafe_contracts)
        expected_safe = set(case.safe_contracts)
        for values, expected, label in (
            (
                observation.first_unsafe_contracts_executed,
                expected_unsafe,
                "first unsafe execution",
            ),
            (
                observation.first_unsafe_counterexamples,
                expected_unsafe,
                "first unsafe replay",
            ),
            (
                observation.second_unsafe_contracts_executed,
                expected_unsafe,
                "second unsafe execution",
            ),
            (
                observation.second_unsafe_counterexamples,
                expected_unsafe,
                "second unsafe replay",
            ),
            (observation.safe_contracts_executed, expected_safe, "safe execution"),
            (observation.safe_contracts_passed, expected_safe, "safe near-miss"),
        ):
            if not set(values) <= expected:
                raise ValueError(f"{case.ticket_id} {label} contains an unknown contract")
        if not set(observation.first_unsafe_counterexamples) <= set(
            observation.first_unsafe_contracts_executed
        ):
            raise ValueError(f"{case.ticket_id} first unsafe replay did not execute its contract")
        if not set(observation.second_unsafe_counterexamples) <= set(
            observation.second_unsafe_contracts_executed
        ):
            raise ValueError(f"{case.ticket_id} second unsafe replay did not execute its contract")
        if not set(observation.safe_contracts_passed) <= set(observation.safe_contracts_executed):
            raise ValueError(f"{case.ticket_id} safe near-miss did not execute")
        executed_unsafe = sorted(
            set(observation.first_unsafe_contracts_executed)
            & set(observation.second_unsafe_contracts_executed)
        )
        executed_safe = sorted(observation.safe_contracts_executed)
        reproduced = sorted(
            set(observation.first_unsafe_counterexamples)
            & set(observation.second_unsafe_counterexamples)
        )
        unconfirmed_safe = sorted(observation.safe_contracts_passed)
        outcomes.append(
            EconomicAcceptanceOutcome(
                ticket_id=case.ticket_id,
                template=case.template,
                fixture_path=case.fixture_path,
                config_sha256=case.config_sha256,
                source_sha256=case.source_sha256,
                test_sha256=case.test_sha256,
                applicable_harnesses=len(case.unsafe_contracts) + len(case.safe_contracts),
                executed_harnesses=len(executed_unsafe) + len(executed_safe),
                planted_unsafe_contracts=case.unsafe_contracts,
                executed_unsafe_contracts=executed_unsafe,
                reproduced_unsafe_contracts=reproduced,
                safe_near_miss_contracts=case.safe_contracts,
                executed_safe_contracts=executed_safe,
                unconfirmed_safe_near_misses=unconfirmed_safe,
                all_applicable_harnesses_executed=(
                    executed_unsafe == case.unsafe_contracts
                    and executed_safe == case.safe_contracts
                ),
                replay_confirmed=reproduced == case.unsafe_contracts,
                safe_near_misses_remain_unconfirmed=(unconfirmed_safe == case.safe_contracts),
                passed=(
                    executed_unsafe == case.unsafe_contracts
                    and executed_safe == case.safe_contracts
                    and reproduced == case.unsafe_contracts
                    and unconfirmed_safe == case.safe_contracts
                ),
            )
        )
    payload = EconomicAcceptanceReportPayload(
        manifest_sha256=manifest.manifest_sha256,
        status=(
            EconomicAcceptanceStatus.PASSED
            if all(item.passed for item in outcomes)
            else EconomicAcceptanceStatus.FAILED
        ),
        total_cases=len(outcomes),
        applicable_harnesses=sum(item.applicable_harnesses for item in outcomes),
        executed_harnesses=sum(item.executed_harnesses for item in outcomes),
        planted_issues=sum(len(item.planted_unsafe_contracts) for item in outcomes),
        reproduced_issues=sum(len(item.reproduced_unsafe_contracts) for item in outcomes),
        safe_near_misses=sum(len(item.safe_near_miss_contracts) for item in outcomes),
        unconfirmed_safe_near_misses=sum(
            len(item.unconfirmed_safe_near_misses) for item in outcomes
        ),
        outcomes=outcomes,
    )
    serialized = payload.model_dump(mode="json")
    return EconomicAcceptanceReport.model_validate(
        {
            **serialized,
            "report_sha256": canonical_sha256(serialized),
        }
    )


def write_economic_acceptance_report(
    path: Path,
    report: EconomicAcceptanceReport,
) -> None:
    """Write a bounded normalized acceptance report without following links."""

    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to write a sensitive economic acceptance filename")
    if path.is_symlink() or path.is_junction():
        raise ValueError("economic acceptance report destination may not be a link")
    if path.exists() and (
        not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > _MAX_REPORT_BYTES
    ):
        raise ValueError("economic acceptance report destination must be unshared")
    serialized = stable_json(report)
    if len(serialized.encode("utf-8")) > _MAX_REPORT_BYTES:
        raise ValueError("economic acceptance report exceeds its output bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialized, encoding="utf-8")


def _resolve_safe_path(root: Path, relative: str, *, directory: bool) -> Path:
    normalized = normalize_relative_path(relative)
    candidate = root
    for part in PurePosixPath(normalized).parts:
        candidate = candidate / part
        if candidate.is_symlink() or candidate.is_junction():
            raise ValueError("economic acceptance fixture paths may not traverse links")
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(root)
    if directory:
        if not resolved.is_dir():
            raise ValueError("economic acceptance fixture root must be a directory")
    else:
        metadata = resolved.stat()
        if (
            not resolved.is_file()
            or metadata.st_nlink != 1
            or metadata.st_size > _MAX_FIXTURE_FILE_BYTES
        ):
            raise ValueError("economic acceptance fixture must be a bounded unshared file")
    return resolved


def _validate_fixture_inventory(
    fixture_root: Path,
    case: EconomicAcceptanceCase,
) -> None:
    expected_files = {case.config_path, case.source_path, case.test_path}
    expected_directories = {
        parent.as_posix()
        for path in expected_files
        for parent in PurePosixPath(path).parents
        if parent.as_posix() != "."
    }
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    for entry in fixture_root.rglob("*"):
        if entry.is_symlink() or entry.is_junction():
            raise ValueError("economic acceptance fixture inventory may not contain links")
        relative = entry.relative_to(fixture_root).as_posix()
        if entry.is_dir():
            observed_directories.add(relative)
        elif entry.is_file():
            observed_files.add(relative)
        else:
            raise ValueError("economic acceptance fixture inventory contains a special file")
    if observed_files != expected_files or observed_directories != expected_directories:
        raise ValueError(f"{case.ticket_id} economic fixture inventory mismatch")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
