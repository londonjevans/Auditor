"""Typed semantic evidence for fixed non-command release gates."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

import mmaudit
from mmaudit.models.schemas import AuditProfile, ExecutionEvidenceKind, StrictModel
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release import ReleaseGateId, ReleaseGateStatus
from mmaudit.release_candidate import ReleaseCandidateObservation
from mmaudit.release_gates import (
    ReleaseGateEvidenceBundle,
    ReleaseGateFixedPlan,
    ReleaseGatePlanExecutor,
    ReleaseGatePrerequisiteBlocker,
    ReleaseGateReceipt,
    build_release_gate_receipt,
    get_release_gate_fixed_plan,
)
from mmaudit.release_io import (
    read_json_evidence,
    revalidate_evidence_file_binding,
    write_json_evidence,
)
from mmaudit.release_report import ReleaseReportInputBinding, ReleaseReportInputRole
from mmaudit.release_run import ReleaseRunBinding
from mmaudit.release_static import StaticReleaseEvidence
from mmaudit.release_verification import ReleaseRunVerificationBinding

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_PYTHON_BYTES = 256 * 1024 * 1024
_BOUND_GATE_IDS = frozenset(
    {
        ReleaseGateId.ARTIFACTS,
        ReleaseGateId.BENCHMARK_CERTIFICATE,
        ReleaseGateId.DOCTOR,
        ReleaseGateId.MANIFESTS,
        ReleaseGateId.MAXIMUM_ASSURANCE_RUN,
        ReleaseGateId.MODEL_BENCHMARK,
        ReleaseGateId.REPLAY,
        ReleaseGateId.SCHEMAS,
    }
)
_PASSING_GATE_IDS = frozenset(
    {
        ReleaseGateId.ARTIFACTS,
        ReleaseGateId.MANIFESTS,
        ReleaseGateId.SCHEMAS,
    }
)
_PRE_BUNDLE_ROLES = frozenset(
    {
        ReleaseReportInputRole.CANDIDATE,
        ReleaseReportInputRole.RUN,
        ReleaseReportInputRole.RUN_VERIFICATION,
        ReleaseReportInputRole.STATIC_EVIDENCE,
    }
)


class BoundReleaseSubjectKind(StrEnum):
    """Closed semantic subject families for bound release observations."""

    ARTIFACT_SET = "artifact_set"
    MANIFEST_SET = "manifest_set"
    PREREQUISITE_BLOCKER = "prerequisite_blocker"
    SCHEMA_SET = "schema_set"


class ArtifactSetSubject(StrictModel):
    """Exact emitted artifact-set identity used by the artifacts gate."""

    kind: Literal[BoundReleaseSubjectKind.ARTIFACT_SET]
    run_id: str
    artifact_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifact_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifact_count: int = Field(ge=1)
    manifest_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    traceability_sha256: str = Field(pattern=_SHA256_PATTERN)


class ManifestSetSubject(StrictModel):
    """Reconstructable manifest/configuration and CURRENT verification identity."""

    kind: Literal[BoundReleaseSubjectKind.MANIFEST_SET]
    run_id: str
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    manifest_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    run_configuration_sha256: str = Field(pattern=_SHA256_PATTERN)
    effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    requested_profile: AuditProfile
    achieved_profile: AuditProfile | None
    verification_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    verification_sha256: str = Field(pattern=_SHA256_PATTERN)
    verification_status: Literal["current"]


class SchemaSetSubject(StrictModel):
    """Nonempty static schema/corpus evidence bound to the candidate."""

    kind: Literal[BoundReleaseSubjectKind.SCHEMA_SET]
    candidate_commit: str
    static_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    schema_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    schema_count: int = Field(ge=1)
    benchmark_source_bindings: int = Field(ge=1)
    model_cases: int = Field(ge=1)
    economic_cases: int = Field(ge=1)
    adversarial_cases: int = Field(ge=1)
    full_protocol_files: int = Field(ge=1)


class PrerequisiteBlockerSubject(StrictModel):
    """Explicit absence of one dedicated real runtime prerequisite."""

    kind: Literal[BoundReleaseSubjectKind.PREREQUISITE_BLOCKER]
    gate_id: ReleaseGateId
    code: str = Field(min_length=1, max_length=100, pattern=r"^[a-z][a-z0-9_]{0,99}$")
    summary: str = Field(min_length=1, max_length=1_000)

    @field_validator("summary")
    @classmethod
    def summary_is_bounded_single_line(cls, value: str) -> str:
        if not value.strip() or any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise ValueError("bound release blocker summary must be bounded single-line text")
        return value


type BoundReleaseGateSubject = Annotated[
    ArtifactSetSubject | ManifestSetSubject | SchemaSetSubject | PrerequisiteBlockerSubject,
    Field(discriminator="kind"),
]


class BoundReleaseGateResultPayload(StrictModel):
    """Canonical result of one fixed candidate/run-bound semantic observation."""

    schema_version: Literal["1.0"]
    generated_by: Literal["mmaudit"]
    gate_id: ReleaseGateId
    candidate_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    run_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    plan: ReleaseGateFixedPlan
    status: ReleaseGateStatus
    started_at: datetime
    ended_at: datetime
    argv: tuple[str, str]
    argv_sha256: str = Field(pattern=_SHA256_PATTERN)
    tool_name: Literal["mmaudit.release_observations"]
    tool_version: str = Field(min_length=1, max_length=200)
    python_executable_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_distribution_sha256: str = Field(pattern=_SHA256_PATTERN)
    execution_evidence: Literal[ExecutionEvidenceKind.REAL]
    source_input_bindings: tuple[ReleaseReportInputBinding, ...] = Field(
        min_length=1,
        max_length=4,
    )
    source_input_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    subject: BoundReleaseGateSubject
    subject_sha256: str = Field(pattern=_SHA256_PATTERN)
    prerequisite_blocker: ReleaseGatePrerequisiteBlocker | None

    @field_validator("started_at", "ended_at")
    @classmethod
    def timestamps_are_whole_second_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
            raise ValueError("bound release observation time must be whole-second UTC")
        return value

    @model_validator(mode="after")
    def semantics_are_consistent(self) -> BoundReleaseGateResultPayload:
        if self.gate_id not in _BOUND_GATE_IDS:
            raise ValueError("bound release result uses a local-command gate")
        if (
            self.plan != get_release_gate_fixed_plan(self.gate_id)
            or self.plan.executor is not ReleaseGatePlanExecutor.BOUND_RUNTIME_OBSERVATION
        ):
            raise ValueError("bound release result does not use its canonical observation plan")
        if self.ended_at < self.started_at:
            raise ValueError("bound release observation end precedes its start")
        expected_argv = ("mmaudit-release-observer", self.gate_id.value)
        if self.argv != expected_argv or self.argv_sha256 != canonical_sha256(list(expected_argv)):
            raise ValueError("bound release observer identity is inconsistent")
        roles = tuple(binding.role for binding in self.source_input_bindings)
        if roles != tuple(sorted(set(roles), key=lambda role: role.value)):
            raise ValueError("bound release source inputs must be unique and sorted")
        if self.source_input_inventory_sha256 != canonical_sha256(
            [binding.model_dump(mode="json") for binding in self.source_input_bindings]
        ):
            raise ValueError("bound release source-input inventory hash is inconsistent")
        if self.subject_sha256 != canonical_sha256(self.subject.model_dump(mode="json")):
            raise ValueError("bound release subject hash is inconsistent")
        expected_roles = _required_roles(self.gate_id)
        if set(roles) != expected_roles:
            raise ValueError("bound release result uses the wrong semantic source inputs")
        if self.gate_id in _PASSING_GATE_IDS:
            if (
                self.status is not ReleaseGateStatus.PASSED
                or self.prerequisite_blocker is not None
                or not _subject_matches_passing_gate(self.gate_id, self.subject)
            ):
                raise ValueError("passing bound release evidence is semantically incomplete")
        elif (
            self.status is not ReleaseGateStatus.BLOCKED_TECHNICAL
            or self.prerequisite_blocker is None
            or not isinstance(self.subject, PrerequisiteBlockerSubject)
            or self.subject.gate_id is not self.gate_id
            or self.subject.code != self.prerequisite_blocker.code
            or self.subject.summary != self.prerequisite_blocker.summary
        ):
            raise ValueError("unimplemented bound release gate must remain explicitly blocked")
        return self


class BoundReleaseGateResult(BoundReleaseGateResultPayload):
    """Self-hashed bound release observation artifact."""

    result_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def result_hash_is_consistent(self) -> BoundReleaseGateResult:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"result_sha256"}))
        if self.result_sha256 != expected:
            raise ValueError("bound release result hash is inconsistent")
        return self


def collect_bound_release_gate_receipt(
    *,
    gate_id: ReleaseGateId,
    evidence_root: Path,
    candidate: ReleaseCandidateObservation,
    run: ReleaseRunBinding,
    run_verification: ReleaseRunVerificationBinding,
    static_evidence: StaticReleaseEvidence,
    input_bindings: Sequence[ReleaseReportInputBinding],
) -> ReleaseGateReceipt:
    """Collect one fixed semantic observation without promoting absent integrations."""

    if gate_id not in _BOUND_GATE_IDS:
        raise ValueError("local-command release gates require the fixed command executor")
    validated_inputs = _validate_inputs(
        evidence_root=evidence_root,
        input_bindings=input_bindings,
        candidate=candidate,
        run=run,
        run_verification=run_verification,
        static_evidence=static_evidence,
        include_gate_evidence=None,
    )
    selected_inputs = tuple(
        validated_inputs[role]
        for role in sorted(_required_roles(gate_id), key=lambda role: role.value)
    )
    plan = get_release_gate_fixed_plan(gate_id)
    result_path = plan.result_artifact_path
    started_at = _utc_now()
    if started_at < candidate.observed_at or started_at < run.observed_at:
        raise ValueError("bound release observer clock predates its candidate or run")
    subject, blocker = _subject_for_gate(
        gate_id,
        candidate=candidate,
        run=run,
        run_verification=run_verification,
        static_evidence=static_evidence,
    )
    status = (
        ReleaseGateStatus.BLOCKED_TECHNICAL if blocker is not None else ReleaseGateStatus.PASSED
    )
    ended_at = _utc_now()
    argv = ("mmaudit-release-observer", gate_id.value)
    python_sha256 = _python_executable_sha256()
    payload = BoundReleaseGateResultPayload(
        schema_version="1.0",
        generated_by="mmaudit",
        gate_id=gate_id,
        candidate_observation_sha256=candidate.observation_sha256,
        run_binding_sha256=run.binding_sha256,
        plan=plan,
        status=status,
        started_at=started_at,
        ended_at=ended_at,
        argv=argv,
        argv_sha256=canonical_sha256(list(argv)),
        tool_name="mmaudit.release_observations",
        tool_version=mmaudit.VERSION,
        python_executable_sha256=python_sha256,
        candidate_distribution_sha256=candidate.tracked_source_inventory_sha256,
        execution_evidence=ExecutionEvidenceKind.REAL,
        source_input_bindings=selected_inputs,
        source_input_inventory_sha256=canonical_sha256(
            [binding.model_dump(mode="json") for binding in selected_inputs]
        ),
        subject=subject,
        subject_sha256=canonical_sha256(subject.model_dump(mode="json")),
        prerequisite_blocker=blocker,
    )
    serialized = payload.model_dump(mode="json")
    result = BoundReleaseGateResult.model_validate(
        {
            **serialized,
            "result_sha256": canonical_sha256(serialized),
        }
    )
    result_binding = write_json_evidence(
        evidence_root=evidence_root,
        relative_path=result_path,
        value=result,
    )
    return build_release_gate_receipt(
        gate_id=gate_id,
        candidate_observation_sha256=candidate.observation_sha256,
        run_binding_sha256=run.binding_sha256,
        fixed_plan_sha256=plan.fixed_plan_sha256,
        started_at=started_at,
        ended_at=ended_at,
        argv=argv,
        tool_name="mmaudit.release_observations",
        tool_version=mmaudit.VERSION,
        tool_executable_sha256=python_sha256,
        tool_distribution_sha256=candidate.tracked_source_inventory_sha256,
        execution_evidence=ExecutionEvidenceKind.REAL,
        exit_code=None if blocker is not None else 0,
        timed_out=False,
        stdout=b"",
        stderr=b"",
        summary=_summary_for_gate(gate_id, blocker=blocker),
        prerequisite_blocker=blocker,
        artifact_bindings=(result_binding,),
    )


def validate_bound_release_gate_receipts(
    *,
    bundle: ReleaseGateEvidenceBundle,
    evidence_root: Path,
    candidate: ReleaseCandidateObservation,
    run: ReleaseRunBinding,
    run_verification: ReleaseRunVerificationBinding,
    static_evidence: StaticReleaseEvidence,
    input_bindings: Sequence[ReleaseReportInputBinding],
) -> tuple[BoundReleaseGateResult, ...]:
    """Recompute and reconcile every non-command gate result and receipt."""

    validated_bundle = ReleaseGateEvidenceBundle.model_validate(bundle.model_dump(mode="json"))
    if (
        validated_bundle.candidate_observation_sha256 != candidate.observation_sha256
        or validated_bundle.run_binding_sha256 != run.binding_sha256
    ):
        raise ValueError("bound release bundle differs from its candidate or run")
    validated_inputs = _validate_inputs(
        evidence_root=evidence_root,
        input_bindings=input_bindings,
        candidate=candidate,
        run=run,
        run_verification=run_verification,
        static_evidence=static_evidence,
        include_gate_evidence=validated_bundle,
    )
    receipts = {receipt.gate_id: receipt for receipt in validated_bundle.receipts}
    current_python_sha256 = _python_executable_sha256()
    results = []
    for gate_id in sorted(_BOUND_GATE_IDS, key=lambda item: item.value):
        receipt = receipts[gate_id]
        plan = get_release_gate_fixed_plan(gate_id)
        binding = _only_result_binding(receipt, expected_path=plan.result_artifact_path)
        observation = read_json_evidence(
            evidence_root=evidence_root,
            relative_path=binding.path,
        )
        if observation.binding != binding:
            raise ValueError("bound release result differs from its receipt binding")
        result = BoundReleaseGateResult.model_validate_json(
            observation.content,
            strict=True,
        )
        expected_subject, expected_blocker = _subject_for_gate(
            gate_id,
            candidate=candidate,
            run=run,
            run_verification=run_verification,
            static_evidence=static_evidence,
        )
        expected_inputs = tuple(
            validated_inputs[role]
            for role in sorted(_required_roles(gate_id), key=lambda role: role.value)
        )
        expected_status = (
            ReleaseGateStatus.BLOCKED_TECHNICAL
            if expected_blocker is not None
            else ReleaseGateStatus.PASSED
        )
        expected_exit_code = None if expected_blocker is not None else 0
        if (
            result.gate_id is not gate_id
            or result.candidate_observation_sha256 != candidate.observation_sha256
            or result.run_binding_sha256 != run.binding_sha256
            or result.plan != plan
            or result.status is not expected_status
            or result.subject != expected_subject
            or result.prerequisite_blocker != expected_blocker
            or result.source_input_bindings != expected_inputs
            or result.tool_version != mmaudit.VERSION
            or result.python_executable_sha256 != current_python_sha256
            or result.candidate_distribution_sha256 != candidate.tracked_source_inventory_sha256
            or receipt.candidate_observation_sha256 != candidate.observation_sha256
            or receipt.run_binding_sha256 != run.binding_sha256
            or receipt.fixed_plan_sha256 != plan.fixed_plan_sha256
            or receipt.status is not expected_status
            or receipt.started_at != result.started_at
            or receipt.ended_at != result.ended_at
            or receipt.argv != result.argv
            or receipt.argv_sha256 != result.argv_sha256
            or receipt.tool_name != result.tool_name
            or receipt.tool_version != result.tool_version
            or receipt.tool_executable_sha256 != result.python_executable_sha256
            or receipt.tool_distribution_sha256 != result.candidate_distribution_sha256
            or receipt.execution_evidence is not ExecutionEvidenceKind.REAL
            or receipt.exit_code != expected_exit_code
            or receipt.timed_out
            or receipt.stdout_size != 0
            or receipt.stdout_sha256 != hashlib.sha256(b"").hexdigest()
            or receipt.stderr_size != 0
            or receipt.stderr_sha256 != hashlib.sha256(b"").hexdigest()
            or receipt.prerequisite_blocker != expected_blocker
            or receipt.result_summary.summary
            != _summary_for_gate(gate_id, blocker=expected_blocker)
        ):
            raise ValueError("bound release result differs from its semantic receipt")
        expected_checks = (0, 0, 0) if expected_blocker is not None else (1, 1, 0)
        observed_checks = (
            receipt.result_summary.checks_total,
            receipt.result_summary.checks_passed,
            receipt.result_summary.checks_failed,
        )
        if observed_checks != expected_checks:
            raise ValueError("bound release receipt check accounting is inconsistent")
        revalidate_evidence_file_binding(
            evidence_root=evidence_root,
            binding=binding,
        )
        results.append(result)
    return tuple(results)


def _validate_inputs(
    *,
    evidence_root: Path,
    input_bindings: Sequence[ReleaseReportInputBinding],
    candidate: ReleaseCandidateObservation,
    run: ReleaseRunBinding,
    run_verification: ReleaseRunVerificationBinding,
    static_evidence: StaticReleaseEvidence,
    include_gate_evidence: ReleaseGateEvidenceBundle | None,
) -> dict[ReleaseReportInputRole, ReleaseReportInputBinding]:
    normalized = [
        ReleaseReportInputBinding.model_validate_json(
            binding.model_dump_json(),
            strict=True,
        )
        for binding in input_bindings
    ]
    by_role = {binding.role: binding for binding in normalized}
    expected_roles = set(_PRE_BUNDLE_ROLES)
    if include_gate_evidence is not None:
        expected_roles.add(ReleaseReportInputRole.GATE_EVIDENCE)
    if len(by_role) != len(normalized) or set(by_role) != expected_roles:
        raise ValueError("bound release observations require the exact fixed input set")
    expected_values: dict[ReleaseReportInputRole, tuple[type[StrictModel], StrictModel, str]] = {
        ReleaseReportInputRole.CANDIDATE: (
            ReleaseCandidateObservation,
            candidate,
            candidate.observation_sha256,
        ),
        ReleaseReportInputRole.RUN: (
            ReleaseRunBinding,
            run,
            run.binding_sha256,
        ),
        ReleaseReportInputRole.RUN_VERIFICATION: (
            ReleaseRunVerificationBinding,
            run_verification,
            run_verification.binding_sha256,
        ),
        ReleaseReportInputRole.STATIC_EVIDENCE: (
            StaticReleaseEvidence,
            static_evidence,
            static_evidence.evidence_sha256,
        ),
    }
    if include_gate_evidence is not None:
        expected_values[ReleaseReportInputRole.GATE_EVIDENCE] = (
            ReleaseGateEvidenceBundle,
            include_gate_evidence,
            include_gate_evidence.bundle_sha256,
        )
    for role, (model, expected, inner_sha256) in expected_values.items():
        binding = by_role[role]
        file_binding = ManifestFileBinding(
            path=binding.path,
            sha256=binding.file_sha256,
            size=binding.file_size,
        )
        observed_binding = revalidate_evidence_file_binding(
            evidence_root=evidence_root,
            binding=file_binding,
        )
        observation = read_json_evidence(
            evidence_root=evidence_root,
            relative_path=binding.path,
        )
        try:
            parsed = model.model_validate_json(
                observation.content,
                strict=True,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("bound release source input failed typed validation") from exc
        if (
            observation.binding != observed_binding
            or parsed != expected
            or binding.evidence_sha256 != inner_sha256
        ):
            raise ValueError("bound release source input differs from its declared evidence")
    return by_role


def _subject_for_gate(
    gate_id: ReleaseGateId,
    *,
    candidate: ReleaseCandidateObservation,
    run: ReleaseRunBinding,
    run_verification: ReleaseRunVerificationBinding,
    static_evidence: StaticReleaseEvidence,
) -> tuple[BoundReleaseGateSubject, ReleaseGatePrerequisiteBlocker | None]:
    if gate_id is ReleaseGateId.ARTIFACTS:
        return (
            ArtifactSetSubject(
                kind=BoundReleaseSubjectKind.ARTIFACT_SET,
                run_id=run.run_id,
                artifact_evidence_sha256=run.artifact_evidence_sha256,
                artifact_inventory_sha256=run.artifact_inventory_sha256,
                artifact_count=run.artifact_count,
                manifest_file_sha256=run.manifest_file_sha256,
                traceability_sha256=run.traceability_sha256,
            ),
            None,
        )
    if gate_id is ReleaseGateId.MANIFESTS:
        return (
            ManifestSetSubject(
                kind=BoundReleaseSubjectKind.MANIFEST_SET,
                run_id=run.run_id,
                manifest_sha256=run.manifest_sha256,
                manifest_file_sha256=run.manifest_file_sha256,
                run_configuration_sha256=run.run_configuration_sha256,
                effective_config_sha256=run.effective_config_sha256,
                requested_profile=run.requested_profile,
                achieved_profile=run.achieved_profile,
                verification_binding_sha256=run_verification.binding_sha256,
                verification_sha256=run_verification.verification_sha256,
                verification_status="current",
            ),
            None,
        )
    if gate_id is ReleaseGateId.SCHEMAS:
        return (
            SchemaSetSubject(
                kind=BoundReleaseSubjectKind.SCHEMA_SET,
                candidate_commit=candidate.candidate_commit,
                static_evidence_sha256=static_evidence.evidence_sha256,
                schema_inventory_sha256=static_evidence.schema_inventory_sha256,
                schema_count=len(static_evidence.schemas),
                benchmark_source_bindings=static_evidence.benchmark_source_bindings,
                model_cases=static_evidence.model_cases,
                economic_cases=static_evidence.economic_cases,
                adversarial_cases=static_evidence.adversarial_cases,
                full_protocol_files=static_evidence.full_protocol_files,
            ),
            None,
        )
    blocker = _blocker_for_gate(gate_id, run=run)
    return (
        PrerequisiteBlockerSubject(
            kind=BoundReleaseSubjectKind.PREREQUISITE_BLOCKER,
            gate_id=gate_id,
            code=blocker.code,
            summary=blocker.summary,
        ),
        blocker,
    )


def _blocker_for_gate(
    gate_id: ReleaseGateId,
    *,
    run: ReleaseRunBinding,
) -> ReleaseGatePrerequisiteBlocker:
    if gate_id is ReleaseGateId.BENCHMARK_CERTIFICATE:
        code = "current_benchmark_certificate_unavailable"
        summary = "current commit-bound nonempty benchmark certificate is unavailable"
    elif gate_id is ReleaseGateId.DOCTOR:
        code = "certified_doctor_evidence_unavailable"
        summary = "certified real prerequisite doctor evidence is unavailable"
    elif gate_id is ReleaseGateId.MAXIMUM_ASSURANCE_RUN:
        if (
            run.requested_profile is AuditProfile.MAXIMUM_ASSURANCE
            and run.achieved_profile is AuditProfile.MAXIMUM_ASSURANCE
        ):
            code = "maximum_assurance_clause_evidence_unavailable"
            summary = "dedicated maximum-assurance clause validation evidence is unavailable"
        else:
            code = "maximum_assurance_not_achieved"
            summary = "the bound audit run did not achieve maximum assurance"
    elif gate_id is ReleaseGateId.MODEL_BENCHMARK:
        code = "qualified_model_benchmark_unavailable"
        summary = "real exact-model qualification benchmark evidence is unavailable"
    elif gate_id is ReleaseGateId.REPLAY:
        code = "isolated_replay_evidence_unavailable"
        summary = "real isolated deterministic replay evidence is unavailable"
    else:
        raise ValueError("passing bound gate cannot be converted to a prerequisite blocker")
    return ReleaseGatePrerequisiteBlocker(code=code, summary=summary)


def _required_roles(gate_id: ReleaseGateId) -> set[ReleaseReportInputRole]:
    roles = {
        ReleaseGateId.ARTIFACTS: {ReleaseReportInputRole.RUN},
        ReleaseGateId.BENCHMARK_CERTIFICATE: {
            ReleaseReportInputRole.CANDIDATE,
            ReleaseReportInputRole.STATIC_EVIDENCE,
        },
        ReleaseGateId.DOCTOR: {ReleaseReportInputRole.CANDIDATE},
        ReleaseGateId.MANIFESTS: {
            ReleaseReportInputRole.RUN,
            ReleaseReportInputRole.RUN_VERIFICATION,
        },
        ReleaseGateId.MAXIMUM_ASSURANCE_RUN: {
            ReleaseReportInputRole.RUN,
            ReleaseReportInputRole.RUN_VERIFICATION,
        },
        ReleaseGateId.MODEL_BENCHMARK: {ReleaseReportInputRole.STATIC_EVIDENCE},
        ReleaseGateId.REPLAY: {ReleaseReportInputRole.RUN},
        ReleaseGateId.SCHEMAS: {ReleaseReportInputRole.STATIC_EVIDENCE},
    }
    try:
        return set(roles[gate_id])
    except KeyError as exc:
        raise ValueError("local-command release gate has no bound source roles") from exc


def _subject_matches_passing_gate(
    gate_id: ReleaseGateId,
    subject: BoundReleaseGateSubject,
) -> bool:
    return (
        (gate_id is ReleaseGateId.ARTIFACTS and isinstance(subject, ArtifactSetSubject))
        or (gate_id is ReleaseGateId.MANIFESTS and isinstance(subject, ManifestSetSubject))
        or (gate_id is ReleaseGateId.SCHEMAS and isinstance(subject, SchemaSetSubject))
    )


def _only_result_binding(
    receipt: ReleaseGateReceipt,
    *,
    expected_path: str,
) -> ManifestFileBinding:
    if len(receipt.artifact_bindings) != 1:
        raise ValueError("bound release receipt must carry exactly one typed result artifact")
    binding = receipt.artifact_bindings[0]
    if binding.path != expected_path:
        raise ValueError("bound release receipt result path differs from its fixed plan")
    return binding


def _summary_for_gate(
    gate_id: ReleaseGateId,
    *,
    blocker: ReleaseGatePrerequisiteBlocker | None,
) -> str:
    if blocker is not None:
        return blocker.summary
    return {
        ReleaseGateId.ARTIFACTS: "exact emitted artifact set and traceability validated",
        ReleaseGateId.MANIFESTS: (
            "reconstructable manifest, effective configuration, and CURRENT verification validated"
        ),
        ReleaseGateId.SCHEMAS: (
            "published schemas and nonempty static release denominators validated"
        ),
    }[gate_id]


def _python_executable_sha256() -> str:
    if not sys.executable:
        raise ValueError("bound release Python executable is unavailable")
    declared = Path(sys.executable)
    try:
        resolved = declared.resolve(strict=True)
        base = Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)
        before = resolved.lstat()
    except OSError as exc:
        raise ValueError("bound release Python executable identity is unavailable") from exc
    if resolved != base:
        raise ValueError("bound release Python executable differs from the running interpreter")
    flags = os.O_RDONLY | _required_flag("O_NOFOLLOW") | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise ValueError("bound release Python executable could not be opened") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size <= 0
            or opened.st_size > _MAX_PYTHON_BYTES
            or stat.S_IMODE(opened.st_mode) & 0o022
        ):
            raise ValueError("bound release Python executable is not a bounded trusted file")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > _MAX_PYTHON_BYTES:
                raise ValueError("bound release Python executable exceeds its size bound")
            digest.update(chunk)
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after = resolved.lstat()
    except OSError as exc:
        raise ValueError("bound release Python executable changed while measured") from exc
    if (
        size != opened.st_size
        or _stat_identity(before) != _stat_identity(opened)
        or _stat_identity(opened) != _stat_identity(finished)
        or _stat_identity(finished) != _stat_identity(after)
    ):
        raise ValueError("bound release Python executable changed while measured")
    return digest.hexdigest()


def _required_flag(name: str) -> int:
    value = getattr(os, name, 0)
    if value == 0:
        raise ValueError(f"required bound release filesystem flag is unavailable: {name}")
    return int(value)


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)
