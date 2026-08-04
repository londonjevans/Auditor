"""Commit- and evidence-bound maximum-assurance release report."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.models.schemas import (
    AuditProfile,
    ExecutionEvidenceKind,
    LanguageCapabilityProfile,
    LanguageCapabilityStatus,
    StrictModel,
)
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release import ReleaseGateId, ReleaseGateStatus, ReleaseStatus
from mmaudit.release_candidate import ReleaseCandidateObservation
from mmaudit.release_gates import (
    ReleaseGateEvidenceBundle,
    ReleaseGatePrerequisiteBlocker,
    ReleaseGateReceipt,
    ReleaseGateResultSummary,
)
from mmaudit.release_run import ReleaseRunBinding
from mmaudit.release_static import StaticReleaseEvidence
from mmaudit.release_verification import ReleaseRunVerificationBinding

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REQUIRED_GATE_COUNT = 12
_MAX_INPUT_BYTES = 100_000_000
_MAX_EVIDENCE_AGE = timedelta(hours=24)
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


class ReleaseReportInputRole(StrEnum):
    """Fixed typed inputs from which a release report is derived."""

    CANDIDATE = "candidate"
    GATE_EVIDENCE = "gate_evidence"
    RUN = "run"
    RUN_VERIFICATION = "run_verification"
    STATIC_EVIDENCE = "static_evidence"


_INPUT_PATHS = {
    ReleaseReportInputRole.CANDIDATE: "candidate-observation.json",
    ReleaseReportInputRole.GATE_EVIDENCE: "gate-evidence.json",
    ReleaseReportInputRole.RUN: "run-binding.json",
    ReleaseReportInputRole.RUN_VERIFICATION: "run-verification-binding.json",
    ReleaseReportInputRole.STATIC_EVIDENCE: "static-evidence.json",
}


class ReleaseReportInputBinding(StrictModel):
    """Exact file and inner-evidence identity for one fixed report input."""

    role: ReleaseReportInputRole
    path: str = Field(min_length=1, max_length=200)
    file_sha256: str = Field(pattern=_SHA256_PATTERN)
    file_size: int = Field(ge=1, le=_MAX_INPUT_BYTES)
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def path_matches_fixed_role(self) -> ReleaseReportInputBinding:
        parsed = PurePosixPath(self.path)
        if (
            self.path != _INPUT_PATHS[self.role]
            or parsed.is_absolute()
            or len(parsed.parts) != 1
            or parsed.name != self.path
        ):
            raise ValueError("release report input path does not match its fixed role")
        return self


class ReleaseGateReportObservation(StrictModel):
    """Lossless public projection of one validated runtime gate receipt."""

    gate_id: ReleaseGateId
    status: ReleaseGateStatus
    receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    run_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    fixed_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    started_at: datetime
    ended_at: datetime
    argv_sha256: str = Field(pattern=_SHA256_PATTERN)
    tool_name: str = Field(min_length=1, max_length=200)
    tool_version: str | None = Field(default=None, min_length=1, max_length=500)
    tool_executable_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    tool_distribution_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    execution_evidence: ExecutionEvidenceKind
    exit_code: int | None = Field(default=None, ge=-255, le=255)
    timed_out: bool
    stdout_size: int = Field(ge=0)
    stdout_sha256: str = Field(pattern=_SHA256_PATTERN)
    stderr_size: int = Field(ge=0)
    stderr_sha256: str = Field(pattern=_SHA256_PATTERN)
    result_summary: ReleaseGateResultSummary
    prerequisite_blocker: ReleaseGatePrerequisiteBlocker | None
    artifact_bindings: tuple[ManifestFileBinding, ...] = Field(max_length=1_000)
    artifact_count: int = Field(ge=0, le=1_000)
    artifact_bytes: int = Field(ge=0, le=1_000_000_000)
    artifact_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("started_at", "ended_at")
    @classmethod
    def timestamps_are_whole_second_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
            raise ValueError("release report gate timestamps must be whole-second UTC")
        return value

    @model_validator(mode="after")
    def observation_is_status_consistent(self) -> ReleaseGateReportObservation:
        if self.ended_at < self.started_at:
            raise ValueError("release report gate end precedes its start")
        paths = tuple(binding.path for binding in self.artifact_bindings)
        if paths != tuple(sorted(set(paths))):
            raise ValueError("release report gate artifacts must be unique and sorted")
        if (
            self.artifact_count != len(self.artifact_bindings)
            or self.artifact_bytes != sum(binding.size for binding in self.artifact_bindings)
            or self.artifact_inventory_sha256
            != canonical_sha256(
                [binding.model_dump(mode="json") for binding in self.artifact_bindings]
            )
        ):
            raise ValueError("release report gate artifact accounting is inconsistent")
        if self.status is ReleaseGateStatus.PASSED and (
            self.execution_evidence is not ExecutionEvidenceKind.REAL
            or self.exit_code != 0
            or self.timed_out
            or self.prerequisite_blocker is not None
            or self.artifact_count == 0
        ):
            raise ValueError("release report pass lacks qualifying real evidence")
        if self.status is ReleaseGateStatus.BLOCKED_TECHNICAL and (
            self.prerequisite_blocker is None or self.exit_code is not None or self.timed_out
        ):
            raise ValueError("release report blocker is inconsistent")
        if self.status is ReleaseGateStatus.FAILED and (
            self.prerequisite_blocker is not None
            or (not self.timed_out and self.exit_code in {None, 0})
        ):
            raise ValueError("release report failure is inconsistent")
        return self


class ReleaseGateReportPayload(StrictModel):
    """Canonical report payload derived from five exact evidence inputs."""

    schema_version: Literal["2.0"]
    generated_by: Literal["mmaudit"]
    release_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    generated_at: datetime
    candidate: ReleaseCandidateObservation
    run: ReleaseRunBinding
    run_verification: ReleaseRunVerificationBinding
    static_evidence: StaticReleaseEvidence
    gate_evidence_bundle_sha256: str = Field(pattern=_SHA256_PATTERN)
    gate_receipt_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    input_files: tuple[ReleaseReportInputBinding, ...] = Field(min_length=5, max_length=5)
    input_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    gate_observations_sha256: str = Field(pattern=_SHA256_PATTERN)
    status: ReleaseStatus
    total_gates: int = Field(ge=_REQUIRED_GATE_COUNT, le=_REQUIRED_GATE_COUNT)
    passed_gates: int = Field(ge=0, le=_REQUIRED_GATE_COUNT)
    blocked_gates: tuple[ReleaseGateId, ...] = Field(max_length=_REQUIRED_GATE_COUNT)
    failed_gates: tuple[ReleaseGateId, ...] = Field(max_length=_REQUIRED_GATE_COUNT)
    safe_local_gates_complete: bool
    all_required_gates_passed: bool
    gates: tuple[ReleaseGateReportObservation, ...] = Field(
        min_length=_REQUIRED_GATE_COUNT,
        max_length=_REQUIRED_GATE_COUNT,
    )
    limitations: tuple[str, ...] = Field(max_length=100)

    @field_validator("generated_at")
    @classmethod
    def generated_at_is_whole_second_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
            raise ValueError("release report generation time must be whole-second UTC")
        return value

    @field_validator("limitations")
    @classmethod
    def limitations_are_sorted_unique_and_bounded(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("release report limitations must be unique and sorted")
        if any(
            not item.strip()
            or len(item) > 1_000
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
            for item in value
        ):
            raise ValueError("release report limitations must be bounded single-line text")
        return value

    @model_validator(mode="after")
    def identities_counts_and_status_reconcile(self) -> ReleaseGateReportPayload:
        if (
            self.run_verification.run_binding_sha256 != self.run.binding_sha256
            or self.run_verification.run_id != self.run.run_id
            or self.run_verification.manifest_sha256 != self.run.manifest_sha256
            or self.run_verification.manifest_file_sha256 != self.run.manifest_file_sha256
            or self.run_verification.target_source_tree_sha256 != self.run.target_source_tree_sha256
            or self.run_verification.effective_config_sha256 != self.run.effective_config_sha256
        ):
            raise ValueError("release report run verification is not bound to its exact run")
        if (
            self.static_evidence.candidate_commit != self.candidate.candidate_commit
            or self.static_evidence.candidate_observation_sha256
            != self.candidate.observation_sha256
        ):
            raise ValueError("release static evidence is not bound to the exact candidate")

        expected_roles = tuple(sorted(ReleaseReportInputRole, key=lambda role: role.value))
        roles = tuple(binding.role for binding in self.input_files)
        if roles != expected_roles:
            raise ValueError("release report must bind every fixed input exactly once and sorted")
        expected_inner_hashes = {
            ReleaseReportInputRole.CANDIDATE: self.candidate.observation_sha256,
            ReleaseReportInputRole.GATE_EVIDENCE: self.gate_evidence_bundle_sha256,
            ReleaseReportInputRole.RUN: self.run.binding_sha256,
            ReleaseReportInputRole.RUN_VERIFICATION: self.run_verification.binding_sha256,
            ReleaseReportInputRole.STATIC_EVIDENCE: self.static_evidence.evidence_sha256,
        }
        if any(
            binding.evidence_sha256 != expected_inner_hashes[binding.role]
            for binding in self.input_files
        ):
            raise ValueError("release report input inner hash is inconsistent")
        expected_input_hash = canonical_sha256(
            [binding.model_dump(mode="json") for binding in self.input_files]
        )
        if self.input_inventory_sha256 != expected_input_hash:
            raise ValueError("release report input inventory hash is inconsistent")

        expected_gate_ids = tuple(sorted(ReleaseGateId, key=lambda gate_id: gate_id.value))
        gate_ids = tuple(gate.gate_id for gate in self.gates)
        if gate_ids != expected_gate_ids:
            raise ValueError("release report must cover every required gate exactly once")
        expected_gate_hash = canonical_sha256([gate.model_dump(mode="json") for gate in self.gates])
        if self.gate_observations_sha256 != expected_gate_hash:
            raise ValueError("release report gate-observation hash is inconsistent")
        if any(
            gate.candidate_observation_sha256 != self.candidate.observation_sha256
            or gate.run_binding_sha256 != self.run.binding_sha256
            for gate in self.gates
        ):
            raise ValueError("release report gate receipts are rebound or replayed")
        blocked = tuple(
            gate.gate_id
            for gate in self.gates
            if gate.status is ReleaseGateStatus.BLOCKED_TECHNICAL
        )
        failed = tuple(
            gate.gate_id for gate in self.gates if gate.status is ReleaseGateStatus.FAILED
        )
        if self.blocked_gates != blocked or self.failed_gates != failed:
            raise ValueError("release report blocked/failed gate accounting is inconsistent")
        if self.total_gates != len(self.gates):
            raise ValueError("release report total-gate accounting is inconsistent")
        if self.passed_gates != sum(gate.status is ReleaseGateStatus.PASSED for gate in self.gates):
            raise ValueError("release report passed-gate accounting is inconsistent")
        expected_safe = all(
            gate.status is ReleaseGateStatus.PASSED
            for gate in self.gates
            if gate.gate_id in _SAFE_LOCAL_GATES
        )
        if self.safe_local_gates_complete is not expected_safe:
            raise ValueError("release report safe-local status is inconsistent")
        expected_all = all(gate.status is ReleaseGateStatus.PASSED for gate in self.gates)
        if self.all_required_gates_passed is not expected_all:
            raise ValueError("release report complete-gate status is inconsistent")
        expected_status = (
            ReleaseStatus.FAILED
            if failed
            else (ReleaseStatus.BLOCKED_TECHNICAL if blocked else ReleaseStatus.COMPLETE)
        )
        if self.status is not expected_status:
            raise ValueError("release report status is inconsistent")
        maximum_gate = next(
            gate for gate in self.gates if gate.gate_id is ReleaseGateId.MAXIMUM_ASSURANCE_RUN
        )
        if maximum_gate.status is ReleaseGateStatus.PASSED and (
            self.run.requested_profile is not AuditProfile.MAXIMUM_ASSURANCE
            or self.run.achieved_profile is not AuditProfile.MAXIMUM_ASSURANCE
        ):
            raise ValueError("non-maximum run cannot pass the maximum-assurance release gate")
        if maximum_gate.status is ReleaseGateStatus.PASSED and (
            self.run.requested_language_profile is not LanguageCapabilityProfile.SOLIDITY_EVM
            or self.run.achieved_language_profile
            is not LanguageCapabilityProfile.SOLIDITY_EVM
            or self.run.capability_status is not LanguageCapabilityStatus.MATCHED
            or self.run.reduced_language_capability
        ):
            raise ValueError(
                "maximum-assurance release gate requires matched Solidity/EVM capability"
            )

        blocker_summaries = {
            gate.prerequisite_blocker.summary
            for gate in self.gates
            if gate.prerequisite_blocker is not None
        }
        if not blocker_summaries.issubset(set(self.limitations)):
            raise ValueError("release report limitations omit a technical blocker")
        if self.status is ReleaseStatus.COMPLETE and self.limitations:
            raise ValueError("complete release report cannot retain unresolved limitations")
        latest_evidence_time = max(
            self.candidate.observed_at,
            self.run.observed_at,
            self.run_verification.observed_at,
            self.static_evidence.observed_at,
            *(gate.ended_at for gate in self.gates),
        )
        if self.generated_at < latest_evidence_time:
            raise ValueError("release report predates its bound evidence")
        earliest_evidence_time = min(
            self.candidate.observed_at,
            self.run.observed_at,
            self.run_verification.observed_at,
            self.static_evidence.observed_at,
            *(gate.started_at for gate in self.gates),
        )
        if self.generated_at - earliest_evidence_time > _MAX_EVIDENCE_AGE:
            raise ValueError("release report evidence exceeds its freshness window")
        if any(
            gate.started_at < self.candidate.observed_at or gate.started_at < self.run.observed_at
            for gate in self.gates
        ):
            raise ValueError("release gate receipt predates its candidate or run binding")
        return self


class ReleaseGateReport(ReleaseGateReportPayload):
    """Self-hashed release report that cannot outlive its exact candidate."""

    report_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def report_hash_is_consistent(self) -> ReleaseGateReport:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"report_sha256"}))
        if self.report_sha256 != expected:
            raise ValueError("release report hash is inconsistent")
        return self


def _assemble_release_gate_report(
    *,
    release_id: str,
    generated_at: datetime,
    candidate: ReleaseCandidateObservation,
    run: ReleaseRunBinding,
    run_verification: ReleaseRunVerificationBinding,
    static_evidence: StaticReleaseEvidence,
    gate_evidence: ReleaseGateEvidenceBundle,
    input_files: list[ReleaseReportInputBinding],
    limitations: list[str],
) -> ReleaseGateReport:
    """Assemble integrity-linked bytes; only authoritative validation proves provenance."""

    validated_candidate = ReleaseCandidateObservation.model_validate(
        candidate.model_dump(mode="json")
    )
    validated_run = ReleaseRunBinding.model_validate(run.model_dump(mode="json"))
    validated_verification = ReleaseRunVerificationBinding.model_validate(
        run_verification.model_dump(mode="json")
    )
    validated_static = StaticReleaseEvidence.model_validate(static_evidence.model_dump(mode="json"))
    validated_gates = ReleaseGateEvidenceBundle.model_validate(
        gate_evidence.model_dump(mode="json")
    )
    if (
        validated_gates.candidate_observation_sha256 != validated_candidate.observation_sha256
        or validated_gates.run_binding_sha256 != validated_run.binding_sha256
    ):
        raise ValueError("release gate evidence is not bound to the candidate and run")
    if (
        validated_verification.run_binding_sha256 != validated_run.binding_sha256
        or validated_verification.run_id != validated_run.run_id
    ):
        raise ValueError("release verification is not bound to the exact run")
    if generated_at > datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=5):
        raise ValueError("release report generation time is unreasonably in the future")

    inputs = tuple(
        sorted(
            (
                ReleaseReportInputBinding.model_validate(binding.model_dump(mode="json"))
                for binding in input_files
            ),
            key=lambda binding: binding.role.value,
        )
    )
    gates = tuple(_project_gate_receipt(receipt) for receipt in validated_gates.receipts)
    blocked = tuple(
        gate.gate_id for gate in gates if gate.status is ReleaseGateStatus.BLOCKED_TECHNICAL
    )
    failed = tuple(gate.gate_id for gate in gates if gate.status is ReleaseGateStatus.FAILED)
    all_passed = not blocked and not failed
    safe_complete = all(
        gate.status is ReleaseGateStatus.PASSED
        for gate in gates
        if gate.gate_id in _SAFE_LOCAL_GATES
    )
    blocker_summaries = {
        gate.prerequisite_blocker.summary for gate in gates if gate.prerequisite_blocker is not None
    }
    normalized_limitations = tuple(sorted({*limitations, *blocker_summaries}))
    payload = ReleaseGateReportPayload(
        schema_version="2.0",
        generated_by="mmaudit",
        release_id=release_id,
        generated_at=generated_at,
        candidate=validated_candidate,
        run=validated_run,
        run_verification=validated_verification,
        static_evidence=validated_static,
        gate_evidence_bundle_sha256=validated_gates.bundle_sha256,
        gate_receipt_set_sha256=validated_gates.receipt_set_sha256,
        input_files=inputs,
        input_inventory_sha256=canonical_sha256(
            [binding.model_dump(mode="json") for binding in inputs]
        ),
        gate_observations_sha256=canonical_sha256([gate.model_dump(mode="json") for gate in gates]),
        status=(
            ReleaseStatus.FAILED
            if failed
            else (ReleaseStatus.BLOCKED_TECHNICAL if blocked else ReleaseStatus.COMPLETE)
        ),
        total_gates=len(gates),
        passed_gates=sum(gate.status is ReleaseGateStatus.PASSED for gate in gates),
        blocked_gates=blocked,
        failed_gates=failed,
        safe_local_gates_complete=safe_complete,
        all_required_gates_passed=all_passed,
        gates=gates,
        limitations=normalized_limitations,
    )
    serialized = payload.model_dump(mode="json")
    return ReleaseGateReport.model_validate(
        {
            **serialized,
            "report_sha256": canonical_sha256(serialized),
        }
    )


def _project_gate_receipt(receipt: ReleaseGateReceipt) -> ReleaseGateReportObservation:
    artifact_payload = [binding.model_dump(mode="json") for binding in receipt.artifact_bindings]
    return ReleaseGateReportObservation(
        gate_id=receipt.gate_id,
        status=receipt.status,
        receipt_sha256=receipt.receipt_sha256,
        candidate_observation_sha256=receipt.candidate_observation_sha256,
        run_binding_sha256=receipt.run_binding_sha256,
        fixed_plan_sha256=receipt.fixed_plan_sha256,
        started_at=receipt.started_at,
        ended_at=receipt.ended_at,
        argv_sha256=receipt.argv_sha256,
        tool_name=receipt.tool_name,
        tool_version=receipt.tool_version,
        tool_executable_sha256=receipt.tool_executable_sha256,
        tool_distribution_sha256=receipt.tool_distribution_sha256,
        execution_evidence=receipt.execution_evidence,
        exit_code=receipt.exit_code,
        timed_out=receipt.timed_out,
        stdout_size=receipt.stdout_size,
        stdout_sha256=receipt.stdout_sha256,
        stderr_size=receipt.stderr_size,
        stderr_sha256=receipt.stderr_sha256,
        result_summary=receipt.result_summary,
        prerequisite_blocker=receipt.prerequisite_blocker,
        artifact_bindings=tuple(receipt.artifact_bindings),
        artifact_count=len(receipt.artifact_bindings),
        artifact_bytes=sum(binding.size for binding in receipt.artifact_bindings),
        artifact_inventory_sha256=canonical_sha256(artifact_payload),
    )
