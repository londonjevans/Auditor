"""Typed, self-hashed evidence for the maximum-assurance release gate."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.models.schemas import StrictModel
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.secrets import is_sensitive_workspace_name

_MAX_REPORT_BYTES = 2_000_000


class ReleaseGateId(StrEnum):
    ARTIFACTS = "artifacts"
    BENCHMARK_CERTIFICATE = "benchmark_certificate"
    DOCTOR = "doctor"
    MANIFESTS = "manifests"
    MAXIMUM_ASSURANCE_RUN = "maximum_assurance_run"
    MODEL_BENCHMARK = "model_benchmark"
    MYPY = "mypy"
    PYTEST = "pytest"
    REPLAY = "replay"
    RUFF_CHECK = "ruff_check"
    RUFF_FORMAT = "ruff_format"
    SCHEMAS = "schemas"


class ReleaseGateStatus(StrEnum):
    PASSED = "passed"
    BLOCKED_TECHNICAL = "blocked_technical"
    FAILED = "failed"


class ReleaseStatus(StrEnum):
    COMPLETE = "complete"
    BLOCKED_TECHNICAL = "blocked_technical"
    FAILED = "failed"


_REAL_INTEGRATION_GATES = {
    ReleaseGateId.DOCTOR,
    ReleaseGateId.MAXIMUM_ASSURANCE_RUN,
    ReleaseGateId.MODEL_BENCHMARK,
    ReleaseGateId.REPLAY,
}
_SAFE_LOCAL_GATES = {
    ReleaseGateId.ARTIFACTS,
    ReleaseGateId.BENCHMARK_CERTIFICATE,
    ReleaseGateId.MANIFESTS,
    ReleaseGateId.MYPY,
    ReleaseGateId.PYTEST,
    ReleaseGateId.RUFF_CHECK,
    ReleaseGateId.RUFF_FORMAT,
    ReleaseGateId.SCHEMAS,
}


class ReleaseGateObservation(StrictModel):
    gate_id: ReleaseGateId
    status: ReleaseGateStatus
    command: str = Field(min_length=1, max_length=4_000)
    exit_code: int | None = Field(default=None, ge=0, le=255)
    result: str = Field(min_length=1, max_length=2_000)
    mocked: bool = False
    blocker: str | None = Field(default=None, min_length=1, max_length=1_000)
    evidence: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("command", "result", "blocker")
    @classmethod
    def text_is_single_line_and_bounded(cls, value: str | None) -> str | None:
        if value is not None and any(ord(character) < 32 for character in value):
            raise ValueError("release evidence text must not contain control characters")
        return value

    @field_validator("evidence")
    @classmethod
    def evidence_is_sorted_unique_and_bounded(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("release gate evidence must be unique and sorted")
        if any(
            not item or len(item) > 500 or any(ord(character) < 32 for character in item)
            for item in value
        ):
            raise ValueError("release gate evidence must be bounded single-line text")
        return value

    @model_validator(mode="after")
    def status_evidence_is_consistent(self) -> ReleaseGateObservation:
        if self.status is ReleaseGateStatus.PASSED:
            if self.exit_code != 0 or self.blocker is not None:
                raise ValueError("passed release gates require exit zero and no blocker")
            if self.mocked and self.gate_id in _REAL_INTEGRATION_GATES:
                raise ValueError("mocked evidence cannot pass a real release integration gate")
        elif self.status is ReleaseGateStatus.BLOCKED_TECHNICAL:
            if self.blocker is None or self.exit_code == 0:
                raise ValueError("blocked release gates require a blocker and no successful exit")
        elif self.exit_code in {None, 0}:
            raise ValueError("failed release gates require a nonzero exit")
        return self


class ReleaseGateReportPayload(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    generated_by: Literal["mmaudit"] = "mmaudit"
    release_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    repository_state: str = Field(min_length=1, max_length=200)
    status: ReleaseStatus
    total_gates: int = Field(ge=12, le=12)
    passed_gates: int = Field(ge=0, le=12)
    blocked_gates: list[ReleaseGateId] = Field(max_length=12)
    failed_gates: list[ReleaseGateId] = Field(max_length=12)
    safe_local_gates_complete: bool
    all_required_gates_passed: bool
    gates: list[ReleaseGateObservation] = Field(min_length=12, max_length=12)
    limitations: list[str] = Field(max_length=100)

    @field_validator("limitations")
    @classmethod
    def limitations_are_sorted_unique_and_bounded(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("release limitations must be unique and sorted")
        if any(not item or len(item) > 1_000 for item in value):
            raise ValueError("release limitations must be bounded")
        return value

    @model_validator(mode="after")
    def counts_and_status_are_consistent(self) -> ReleaseGateReportPayload:
        gate_ids = [item.gate_id for item in self.gates]
        if gate_ids != sorted(ReleaseGateId, key=lambda item: item.value):
            raise ValueError("release report must cover every required gate exactly once")
        blocked = [
            item.gate_id
            for item in self.gates
            if item.status is ReleaseGateStatus.BLOCKED_TECHNICAL
        ]
        failed = [item.gate_id for item in self.gates if item.status is ReleaseGateStatus.FAILED]
        if self.blocked_gates != blocked or self.failed_gates != failed:
            raise ValueError("release blocked/failed gate accounting is inconsistent")
        if self.total_gates != len(self.gates):
            raise ValueError("release total-gate accounting is inconsistent")
        if self.passed_gates != sum(item.status is ReleaseGateStatus.PASSED for item in self.gates):
            raise ValueError("release passed-gate accounting is inconsistent")
        safe_complete = all(
            item.status is ReleaseGateStatus.PASSED
            for item in self.gates
            if item.gate_id in _SAFE_LOCAL_GATES
        )
        if self.safe_local_gates_complete is not safe_complete:
            raise ValueError("safe local release-gate status is inconsistent")
        all_passed = all(item.status is ReleaseGateStatus.PASSED for item in self.gates)
        if self.all_required_gates_passed is not all_passed:
            raise ValueError("required release-gate status is inconsistent")
        expected_status = (
            ReleaseStatus.FAILED
            if failed
            else (ReleaseStatus.BLOCKED_TECHNICAL if blocked else ReleaseStatus.COMPLETE)
        )
        if self.status is not expected_status:
            raise ValueError("release status is inconsistent")
        return self


class ReleaseGateReport(ReleaseGateReportPayload):
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def report_hash_matches(self) -> ReleaseGateReport:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"report_sha256"}))
        if self.report_sha256 != expected:
            raise ValueError("release report hash is inconsistent")
        return self


def build_release_gate_report(
    *,
    release_id: str,
    repository_state: str,
    observations: list[ReleaseGateObservation],
    limitations: list[str],
) -> ReleaseGateReport:
    """Build normalized release evidence without promoting mocked integrations."""

    by_gate = {item.gate_id: item for item in observations}
    if len(by_gate) != len(observations) or set(by_gate) != set(ReleaseGateId):
        raise ValueError("release observations must uniquely cover every required gate")
    gates = sorted(observations, key=lambda item: item.gate_id.value)
    blocked = [item.gate_id for item in gates if item.status is ReleaseGateStatus.BLOCKED_TECHNICAL]
    failed = [item.gate_id for item in gates if item.status is ReleaseGateStatus.FAILED]
    all_passed = not blocked and not failed
    safe_complete = all(
        item.status is ReleaseGateStatus.PASSED
        for item in gates
        if item.gate_id in _SAFE_LOCAL_GATES
    )
    payload = ReleaseGateReportPayload(
        release_id=release_id,
        repository_state=repository_state,
        status=(
            ReleaseStatus.FAILED
            if failed
            else (ReleaseStatus.BLOCKED_TECHNICAL if blocked else ReleaseStatus.COMPLETE)
        ),
        total_gates=len(gates),
        passed_gates=sum(item.status is ReleaseGateStatus.PASSED for item in gates),
        blocked_gates=blocked,
        failed_gates=failed,
        safe_local_gates_complete=safe_complete,
        all_required_gates_passed=all_passed,
        gates=gates,
        limitations=sorted(set(limitations)),
    )
    serialized = payload.model_dump(mode="json")
    return ReleaseGateReport.model_validate(
        {
            **serialized,
            "report_sha256": canonical_sha256(serialized),
        }
    )


def load_release_gate_report(path: Path) -> ReleaseGateReport:
    """Load one bounded release report without following links."""

    if (
        path.is_symlink()
        or path.is_junction()
        or not path.is_file()
        or path.stat().st_nlink != 1
        or path.stat().st_size > _MAX_REPORT_BYTES
        or is_sensitive_workspace_name(path.name)
    ):
        raise ValueError("release report must be a bounded unshared non-link file")
    return ReleaseGateReport.model_validate_json(path.read_text(encoding="utf-8"))


def write_release_gate_report(path: Path, report: ReleaseGateReport) -> None:
    """Write normalized release evidence to a bounded non-link file."""

    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to write a sensitive release report filename")
    if path.is_symlink() or path.is_junction():
        raise ValueError("release report destination may not be a link")
    if path.exists() and (
        not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > _MAX_REPORT_BYTES
    ):
        raise ValueError("release report destination must be an unshared file")
    serialized = stable_json(report)
    if len(serialized.encode("utf-8")) > _MAX_REPORT_BYTES:
        raise ValueError("release report exceeds its output bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialized, encoding="utf-8")
