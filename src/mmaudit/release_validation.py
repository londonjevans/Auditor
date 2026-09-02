"""Authoritative, provider-free validation of a v2 release report."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from mmaudit.models.schemas import (
    AuditProfile,
    ExecutionEvidenceKind,
    LanguageCapabilityProfile,
    LanguageCapabilityStatus,
)
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release import ReleaseGateStatus, ReleaseStatus
from mmaudit.release_candidate import (
    ReleaseCandidateObservation,
    observe_release_candidate,
)
from mmaudit.release_gates import (
    ReleaseGateEvidenceBundle,
    validate_release_gate_evidence_bundle,
)
from mmaudit.release_io import (
    JsonEvidenceObservation,
    read_json_evidence,
    revalidate_evidence_file_binding,
)
from mmaudit.release_observations import validate_bound_release_gate_receipts
from mmaudit.release_report import (
    ReleaseGateReport,
    ReleaseReportInputBinding,
    ReleaseReportInputRole,
    _assemble_release_gate_report,
)
from mmaudit.release_run import ReleaseRunBinding, observe_release_run_binding
from mmaudit.release_runtime import validate_local_release_gate_receipts
from mmaudit.release_static import StaticReleaseEvidence, collect_static_release_evidence
from mmaudit.release_verification import (
    ReleaseConfigurationInputObservation,
    ReleaseRunVerificationBinding,
    observe_release_configuration_input_from_run,
    observe_release_run_verification,
)
from mmaudit.repository.directory_custody import (
    DirectoryCustodyObservation,
    observe_unlinked_directory,
    require_unchanged_unlinked_directory,
)
from mmaudit.repository.file_custody import (
    RegularFileCustodyObservation,
    observe_regular_file_custody,
    require_regular_file_custody_unchanged,
)

MAX_REPORT_CLOCK_SKEW = timedelta(minutes=5)
MAX_REPORT_AGE = timedelta(hours=24)
MAX_AUXILIARY_EVIDENCE_BYTES = 100_000_000


@dataclass(frozen=True, slots=True)
class _FileObservation:
    path: Path
    identity: tuple[int, int, int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class _ValidationRoots:
    report: DirectoryCustodyObservation
    evidence: DirectoryCustodyObservation
    release_repository: DirectoryCustodyObservation
    run: DirectoryCustodyObservation
    target_repository: DirectoryCustodyObservation
    configuration: ReleaseConfigurationInputObservation
    artifact_evidence: _FileObservation
    run_verification_evidence: _FileObservation


@dataclass(frozen=True, slots=True)
class _ValidationFileAuthorities:
    report: RegularFileCustodyObservation
    evidence: tuple[RegularFileCustodyObservation, ...]


@dataclass(frozen=True, slots=True)
class ReleaseSnapshotFileBinding:
    """Immutable primitive binding for one file in a validated release snapshot."""

    namespace: Literal["report", "evidence"]
    path: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        validated = ManifestFileBinding(path=self.path, sha256=self.sha256, size=self.size)
        if validated.path != self.path:
            raise ValueError("validated release snapshot file path is not normalized")

    def manifest_binding(self) -> ManifestFileBinding:
        """Return a fresh typed binding without exposing mutable snapshot state."""

        return ManifestFileBinding(path=self.path, sha256=self.sha256, size=self.size)


@dataclass(frozen=True, slots=True)
class ValidatedReleaseReportSnapshot:
    """Cryptographically bound report bytes and evidence-file identities validated together.

    The snapshot is the returned authority. It deliberately makes no claim that mutable
    filesystem paths remain unchanged after any individual observation or after return.
    Downstream consumers must revalidate published paths against these bindings.
    """

    report_content: bytes
    report_file: ReleaseSnapshotFileBinding
    evidence_files: tuple[ReleaseSnapshotFileBinding, ...]
    snapshot_sha256: str

    def __post_init__(self) -> None:
        if self.report_file.namespace != "report":
            raise ValueError("validated release snapshot report binding has the wrong namespace")
        if any(binding.namespace != "evidence" for binding in self.evidence_files):
            raise ValueError("validated release snapshot evidence binding has the wrong namespace")
        if tuple(sorted(self.evidence_files, key=lambda item: item.path)) != self.evidence_files:
            raise ValueError("validated release snapshot evidence bindings are not ordered")
        paths = [binding.path for binding in self.evidence_files]
        if len(paths) != len(set(paths)):
            raise ValueError("validated release snapshot evidence bindings are not unique")
        if (
            len(self.report_content) != self.report_file.size
            or hashlib.sha256(self.report_content).hexdigest() != self.report_file.sha256
        ):
            raise ValueError("validated release snapshot report bytes differ from their binding")
        # Strict parsing here keeps the immutable bytes, rather than a mutable nested model,
        # as the snapshot's source of truth.
        report = ReleaseGateReport.model_validate_json(self.report_content, strict=True)
        expected_evidence: dict[str, tuple[str, int]] = {}
        for input_binding in report.input_files:
            expected_evidence[input_binding.path] = (
                input_binding.file_sha256,
                input_binding.file_size,
            )
        for gate in report.gates:
            for artifact_binding in gate.artifact_bindings:
                expected = (artifact_binding.sha256, artifact_binding.size)
                prior = expected_evidence.get(artifact_binding.path)
                if prior is not None and prior != expected:
                    raise ValueError("validated release snapshot evidence bindings conflict")
                expected_evidence[artifact_binding.path] = expected
        observed_evidence = {
            binding.path: (binding.sha256, binding.size) for binding in self.evidence_files
        }
        if observed_evidence != expected_evidence:
            raise ValueError("validated release snapshot evidence inventory is incomplete")
        if self.snapshot_sha256 != _release_snapshot_sha256(
            report_file=self.report_file,
            evidence_files=self.evidence_files,
        ):
            raise ValueError("validated release snapshot hash is inconsistent")

    @property
    def report(self) -> ReleaseGateReport:
        """Return a fresh strict model projection of the immutable report bytes."""

        return ReleaseGateReport.model_validate_json(self.report_content, strict=True)


def validate_release_report(
    *,
    report_root: Path,
    report_relative_path: str | Path,
    evidence_root: Path,
    release_repository_root: Path,
    emitted_run_dir: Path,
    target_repository_root: Path,
    configuration_root: Path,
    artifact_evidence_path: Path,
    run_verification_path: Path,
    require_complete: bool = False,
) -> ReleaseGateReport:
    """Return the report projection of a snapshot, optionally enforcing completion policy.

    This compatibility API returns a fresh model derived from immutable snapshot bytes. It does
    not promise that the source paths remain unchanged after their individual observations.
    """

    if type(require_complete) is not bool:
        raise ValueError("release completion policy must be an explicit boolean")
    snapshot = validate_release_report_integrity(
        report_root=report_root,
        report_relative_path=report_relative_path,
        evidence_root=evidence_root,
        release_repository_root=release_repository_root,
        emitted_run_dir=emitted_run_dir,
        target_repository_root=target_repository_root,
        configuration_root=configuration_root,
        artifact_evidence_path=artifact_evidence_path,
        run_verification_path=run_verification_path,
    )
    report = snapshot.report
    return require_complete_release_report(report) if require_complete else report


def validate_release_report_integrity(
    *,
    report_root: Path,
    report_relative_path: str | Path,
    evidence_root: Path,
    release_repository_root: Path,
    emitted_run_dir: Path,
    target_repository_root: Path,
    configuration_root: Path,
    artifact_evidence_path: Path,
    run_verification_path: Path,
) -> ValidatedReleaseReportSnapshot:
    """Return a coherent cryptographic snapshot after recomputing every report input.

    Validation detects observed custody violations, but does not promise that mutable paths
    remain unchanged after they have been observed. The returned snapshot binds the exact report
    bytes and every evidence-file digest used by the authoritative reconstruction.
    """

    initial_roots = _observe_validation_roots(
        report_root=report_root,
        evidence_root=evidence_root,
        release_repository_root=release_repository_root,
        emitted_run_dir=emitted_run_dir,
        target_repository_root=target_repository_root,
        configuration_root=configuration_root,
        artifact_evidence_path=artifact_evidence_path,
        run_verification_path=run_verification_path,
    )
    report_observation = read_json_evidence(
        evidence_root=initial_roots.report.path,
        relative_path=report_relative_path,
    )
    report = _parse_model(ReleaseGateReport, report_observation, label="release report")
    _validate_report_time(report)
    if report.status is ReleaseStatus.COMPLETE and (
        report.run.requested_profile is not AuditProfile.MAXIMUM_ASSURANCE
        or report.run.achieved_profile is not AuditProfile.MAXIMUM_ASSURANCE
        or report.run.requested_language_profile is not LanguageCapabilityProfile.SOLIDITY_EVM
        or report.run.achieved_language_profile is not LanguageCapabilityProfile.SOLIDITY_EVM
        or report.run.capability_status is not LanguageCapabilityStatus.MATCHED
        or report.run.reduced_language_capability
        or bool(report.run.blocking_discovery_omissions)
        or report.limitations
    ):
        raise ValueError("complete release report has not achieved unqualified maximum assurance")

    candidate_before = observe_release_candidate(initial_roots.release_repository.path)

    declared_inputs = {binding.role: binding for binding in report.input_files}
    expected_input_roles = set(ReleaseReportInputRole)
    if (
        len(declared_inputs) != len(report.input_files)
        or set(declared_inputs) != expected_input_roles
    ):
        raise ValueError("release report must declare every exact input role once")
    candidate_observation = _read_bound_input(
        model=ReleaseCandidateObservation,
        role=ReleaseReportInputRole.CANDIDATE,
        declared=declared_inputs[ReleaseReportInputRole.CANDIDATE],
        evidence_root=initial_roots.evidence.path,
    )
    gate_observation = _read_bound_input(
        model=ReleaseGateEvidenceBundle,
        role=ReleaseReportInputRole.GATE_EVIDENCE,
        declared=declared_inputs[ReleaseReportInputRole.GATE_EVIDENCE],
        evidence_root=initial_roots.evidence.path,
    )
    run_observation = _read_bound_input(
        model=ReleaseRunBinding,
        role=ReleaseReportInputRole.RUN,
        declared=declared_inputs[ReleaseReportInputRole.RUN],
        evidence_root=initial_roots.evidence.path,
    )
    verification_observation = _read_bound_input(
        model=ReleaseRunVerificationBinding,
        role=ReleaseReportInputRole.RUN_VERIFICATION,
        declared=declared_inputs[ReleaseReportInputRole.RUN_VERIFICATION],
        evidence_root=initial_roots.evidence.path,
    )
    static_observation = _read_bound_input(
        model=StaticReleaseEvidence,
        role=ReleaseReportInputRole.STATIC_EVIDENCE,
        declared=declared_inputs[ReleaseReportInputRole.STATIC_EVIDENCE],
        evidence_root=initial_roots.evidence.path,
    )

    candidate = candidate_observation[0]
    gate_evidence = gate_observation[0]
    run = run_observation[0]
    run_verification = verification_observation[0]
    static_evidence = static_observation[0]
    initial_inputs = {
        ReleaseReportInputRole.CANDIDATE: candidate_observation[1],
        ReleaseReportInputRole.GATE_EVIDENCE: gate_observation[1],
        ReleaseReportInputRole.RUN: run_observation[1],
        ReleaseReportInputRole.RUN_VERIFICATION: verification_observation[1],
        ReleaseReportInputRole.STATIC_EVIDENCE: static_observation[1],
    }
    if (
        candidate != report.candidate
        or run != report.run
        or run_verification != report.run_verification
        or static_evidence != report.static_evidence
    ):
        raise ValueError("release report projections differ from their exact input files")
    if (
        run_verification.run_binding_sha256 != run.binding_sha256
        or run_verification.manifest_sha256 != run.manifest_sha256
        or run_verification.manifest_file_sha256 != run.manifest_file_sha256
        or run_verification.target_source_tree_sha256 != run.target_source_tree_sha256
        or run_verification.effective_config_sha256 != run.effective_config_sha256
    ):
        raise ValueError("release report verification projection differs from its exact run")
    _require_validation_directories_unchanged(initial_roots)

    validated_gates = validate_release_gate_evidence_bundle(
        gate_evidence,
        evidence_root=initial_roots.evidence.path,
    )
    if validated_gates != gate_evidence:
        raise ValueError("release gate evidence changed during validation")
    validate_local_release_gate_receipts(
        bundle=validated_gates,
        evidence_root=initial_roots.evidence.path,
    )
    file_authorities = _observe_validation_file_authorities(
        report_root=initial_roots.report.path,
        report_observation=report_observation,
        evidence_root=initial_roots.evidence.path,
        input_observations=initial_inputs,
        gate_evidence=gate_evidence,
    )
    snapshot = _build_validated_release_snapshot(
        report_observation=report_observation,
        file_authorities=file_authorities,
    )

    fresh_run = observe_release_run_binding(
        initial_roots.run.path,
        initial_roots.release_repository.path,
        artifact_evidence_path,
    )
    if _run_state(fresh_run) != _run_state(run):
        raise ValueError("release report run binding is stale")

    fresh_verification = observe_release_run_verification(
        run_dir=initial_roots.run.path,
        target_repository_root=initial_roots.target_repository.path,
        configuration_root=initial_roots.configuration.root,
        release_repository_root=initial_roots.release_repository.path,
        artifact_evidence_path=artifact_evidence_path,
        verification_path=run_verification_path,
        run_binding=run,
    )
    if _verification_state(fresh_verification) != _verification_state(run_verification):
        raise ValueError("release report run verification is stale")

    fresh_static = collect_static_release_evidence(
        initial_roots.release_repository.path,
        candidate=candidate,
    )
    if _static_state(fresh_static) != _static_state(static_evidence):
        raise ValueError("release report static evidence is stale")

    if (
        _candidate_state(candidate_before) != _candidate_state(candidate)
        or gate_evidence.candidate_observation_sha256 != candidate.observation_sha256
        or gate_evidence.run_binding_sha256 != run.binding_sha256
    ):
        raise ValueError("release report candidate or gate bindings are stale")

    exact_input_bindings = [
        _report_input_binding(
            role=role,
            observation=observation,
            evidence_sha256=inner_hash,
        )
        for role, observation, inner_hash in (
            (
                ReleaseReportInputRole.CANDIDATE,
                candidate_observation[1],
                candidate.observation_sha256,
            ),
            (
                ReleaseReportInputRole.GATE_EVIDENCE,
                gate_observation[1],
                gate_evidence.bundle_sha256,
            ),
            (
                ReleaseReportInputRole.RUN,
                run_observation[1],
                run.binding_sha256,
            ),
            (
                ReleaseReportInputRole.RUN_VERIFICATION,
                verification_observation[1],
                run_verification.binding_sha256,
            ),
            (
                ReleaseReportInputRole.STATIC_EVIDENCE,
                static_observation[1],
                static_evidence.evidence_sha256,
            ),
        )
    ]
    validate_bound_release_gate_receipts(
        bundle=validated_gates,
        evidence_root=initial_roots.evidence.path,
        candidate=candidate,
        run=run,
        run_verification=run_verification,
        static_evidence=static_evidence,
        input_bindings=exact_input_bindings,
    )
    rebuilt = _assemble_release_gate_report(
        release_id=report.release_id,
        generated_at=report.generated_at,
        candidate=candidate,
        run=run,
        run_verification=run_verification,
        static_evidence=static_evidence,
        gate_evidence=gate_evidence,
        input_files=exact_input_bindings,
        limitations=list(report.limitations),
    )
    if rebuilt != report:
        raise ValueError("release report differs from its authoritative reconstruction")

    for role, initial in initial_inputs.items():
        final = read_json_evidence(
            evidence_root=initial_roots.evidence.path,
            relative_path=declared_inputs[role].path,
        )
        if final != initial:
            raise ValueError("release report input changed during validation")
        revalidate_evidence_file_binding(
            evidence_root=initial_roots.evidence.path,
            binding=initial.binding,
        )

    final_gates = validate_release_gate_evidence_bundle(
        gate_evidence,
        evidence_root=initial_roots.evidence.path,
    )
    if final_gates != validated_gates:
        raise ValueError("release gate evidence changed during validation")
    validate_local_release_gate_receipts(
        bundle=final_gates,
        evidence_root=initial_roots.evidence.path,
    )
    validate_bound_release_gate_receipts(
        bundle=final_gates,
        evidence_root=initial_roots.evidence.path,
        candidate=candidate,
        run=run,
        run_verification=run_verification,
        static_evidence=static_evidence,
        input_bindings=exact_input_bindings,
    )

    final_report = read_json_evidence(
        evidence_root=initial_roots.report.path,
        relative_path=report_relative_path,
    )
    if final_report != report_observation:
        raise ValueError("release report changed during validation")

    final_run = observe_release_run_binding(
        initial_roots.run.path,
        initial_roots.release_repository.path,
        artifact_evidence_path,
    )
    if _run_state(final_run) != _run_state(fresh_run) or _run_state(final_run) != _run_state(run):
        raise ValueError("release report run binding changed during validation")

    final_verification = observe_release_run_verification(
        run_dir=initial_roots.run.path,
        target_repository_root=initial_roots.target_repository.path,
        configuration_root=initial_roots.configuration.root,
        release_repository_root=initial_roots.release_repository.path,
        artifact_evidence_path=artifact_evidence_path,
        verification_path=run_verification_path,
        run_binding=run,
    )
    if _verification_state(final_verification) != _verification_state(
        fresh_verification
    ) or _verification_state(final_verification) != _verification_state(run_verification):
        raise ValueError("release report run verification changed during validation")

    final_static = collect_static_release_evidence(
        initial_roots.release_repository.path,
        candidate=candidate,
    )
    if _static_state(final_static) != _static_state(fresh_static) or _static_state(
        final_static
    ) != _static_state(static_evidence):
        raise ValueError("release report static evidence changed during validation")

    candidate_after = observe_release_candidate(initial_roots.release_repository.path)
    if _candidate_state(candidate_after) != _candidate_state(candidate_before) or _candidate_state(
        candidate_after
    ) != _candidate_state(candidate):
        raise ValueError("release candidate changed during report validation")
    _require_validation_directories_unchanged(initial_roots)
    final_roots = _observe_validation_roots(
        report_root=report_root,
        evidence_root=evidence_root,
        release_repository_root=release_repository_root,
        emitted_run_dir=emitted_run_dir,
        target_repository_root=target_repository_root,
        configuration_root=configuration_root,
        artifact_evidence_path=artifact_evidence_path,
        run_verification_path=run_verification_path,
    )
    if final_roots != initial_roots:
        raise ValueError("release validation roots changed during validation")
    _validate_report_time(report)
    _require_validation_file_authorities_unchanged(file_authorities)
    return snapshot


def require_complete_release_report(report: ReleaseGateReport) -> ReleaseGateReport:
    """Apply strict completion policy to a report already validated for integrity."""

    validated = ReleaseGateReport.model_validate(report.model_dump(mode="json"))
    if (
        validated.status is not ReleaseStatus.COMPLETE
        or not validated.all_required_gates_passed
        or not validated.safe_local_gates_complete
        or validated.total_gates != 12
        or validated.passed_gates != 12
        or validated.blocked_gates
        or validated.failed_gates
        or validated.run.requested_profile is not AuditProfile.MAXIMUM_ASSURANCE
        or validated.run.achieved_profile is not AuditProfile.MAXIMUM_ASSURANCE
        or validated.run.requested_language_profile is not LanguageCapabilityProfile.SOLIDITY_EVM
        or validated.run.achieved_language_profile is not LanguageCapabilityProfile.SOLIDITY_EVM
        or validated.run.capability_status is not LanguageCapabilityStatus.MATCHED
        or validated.run.reduced_language_capability
        or bool(validated.run.blocking_discovery_omissions)
        or validated.limitations
        or any(
            gate.status is not ReleaseGateStatus.PASSED
            or gate.execution_evidence is not ExecutionEvidenceKind.REAL
            or gate.exit_code != 0
            or gate.timed_out
            or gate.prerequisite_blocker is not None
            or gate.artifact_count == 0
            for gate in validated.gates
        )
    ):
        raise ValueError("release does not satisfy the complete maximum-assurance policy")
    return validated


def _read_bound_input[ModelT: BaseModel](
    *,
    model: type[ModelT],
    role: ReleaseReportInputRole,
    declared: ReleaseReportInputBinding,
    evidence_root: Path,
) -> tuple[ModelT, JsonEvidenceObservation]:
    if declared.role is not role:
        raise ValueError("release report input role is inconsistent")
    observation = read_json_evidence(
        evidence_root=evidence_root,
        relative_path=declared.path,
    )
    expected = ManifestFileBinding(
        path=declared.path,
        sha256=declared.file_sha256,
        size=declared.file_size,
    )
    if observation.binding != expected:
        raise ValueError("release report input file binding is stale")
    revalidate_evidence_file_binding(
        evidence_root=evidence_root,
        binding=expected,
    )
    parsed = _parse_model(model, observation, label="release report input")
    inner_hash = _inner_evidence_hash(role, parsed)
    if declared.evidence_sha256 != inner_hash:
        raise ValueError("release report input inner-evidence hash is stale")
    return parsed, observation


def _parse_model[ModelT: BaseModel](
    model: type[ModelT],
    observation: JsonEvidenceObservation,
    *,
    label: str,
) -> ModelT:
    try:
        return model.model_validate_json(observation.content, strict=True)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} failed strict typed validation") from exc


def _inner_evidence_hash(role: ReleaseReportInputRole, value: BaseModel) -> str:
    attributes = {
        ReleaseReportInputRole.CANDIDATE: "observation_sha256",
        ReleaseReportInputRole.GATE_EVIDENCE: "bundle_sha256",
        ReleaseReportInputRole.RUN: "binding_sha256",
        ReleaseReportInputRole.RUN_VERIFICATION: "binding_sha256",
        ReleaseReportInputRole.STATIC_EVIDENCE: "evidence_sha256",
    }
    inner = getattr(value, attributes[role], None)
    if not isinstance(inner, str):
        raise ValueError("release report input has no typed inner-evidence hash")
    return inner


def _report_input_binding(
    *,
    role: ReleaseReportInputRole,
    observation: JsonEvidenceObservation,
    evidence_sha256: str,
) -> ReleaseReportInputBinding:
    return ReleaseReportInputBinding(
        role=role,
        path=observation.binding.path,
        file_sha256=observation.binding.sha256,
        file_size=observation.binding.size,
        evidence_sha256=evidence_sha256,
    )


def _observe_validation_file_authorities(
    *,
    report_root: Path,
    report_observation: JsonEvidenceObservation,
    evidence_root: Path,
    input_observations: dict[ReleaseReportInputRole, JsonEvidenceObservation],
    gate_evidence: ReleaseGateEvidenceBundle,
) -> _ValidationFileAuthorities:
    report = observe_regular_file_custody(
        root=report_root,
        relative_path=report_observation.binding.path,
        expected_binding=report_observation.binding,
        label="release validation report file",
    )
    evidence_bindings = {
        observation.binding.path: observation.binding for observation in input_observations.values()
    }
    for receipt in gate_evidence.receipts:
        for binding in receipt.artifact_bindings:
            prior = evidence_bindings.get(binding.path)
            if prior is not None and prior != binding:
                raise ValueError("release validation evidence bindings conflict")
            evidence_bindings[binding.path] = binding
    evidence = tuple(
        observe_regular_file_custody(
            root=evidence_root,
            relative_path=binding.path,
            expected_binding=binding,
            label=f"release validation evidence file {binding.path}",
        )
        for binding in sorted(evidence_bindings.values(), key=lambda item: item.path)
    )
    return _ValidationFileAuthorities(report=report, evidence=evidence)


def _require_validation_file_authorities_unchanged(
    authorities: _ValidationFileAuthorities,
) -> None:
    """Best-effort churn detection; the returned snapshot remains the authority.

    These checks are intentionally not described as an atomic filesystem observation: a later
    check cannot prove that an earlier mutable path stayed unchanged. Their value is detecting
    races that overlap an individual observation and inode/ancestor changes that occurred before
    the corresponding recheck.
    """

    require_regular_file_custody_unchanged(
        authorities.report,
        label="release validation report file",
    )
    for authority in authorities.evidence:
        require_regular_file_custody_unchanged(
            authority,
            label=f"release validation evidence file {authority.binding.path}",
        )


def _build_validated_release_snapshot(
    *,
    report_observation: JsonEvidenceObservation,
    file_authorities: _ValidationFileAuthorities,
) -> ValidatedReleaseReportSnapshot:
    if file_authorities.report.binding != report_observation.binding:
        raise ValueError("validated release snapshot report authority is inconsistent")
    report_file = _snapshot_file_binding(
        namespace="report",
        binding=file_authorities.report.binding,
    )
    evidence_files = tuple(
        _snapshot_file_binding(namespace="evidence", binding=authority.binding)
        for authority in file_authorities.evidence
    )
    return ValidatedReleaseReportSnapshot(
        report_content=report_observation.content,
        report_file=report_file,
        evidence_files=evidence_files,
        snapshot_sha256=_release_snapshot_sha256(
            report_file=report_file,
            evidence_files=evidence_files,
        ),
    )


def _snapshot_file_binding(
    *,
    namespace: Literal["report", "evidence"],
    binding: ManifestFileBinding,
) -> ReleaseSnapshotFileBinding:
    return ReleaseSnapshotFileBinding(
        namespace=namespace,
        path=binding.path,
        sha256=binding.sha256,
        size=binding.size,
    )


def _release_snapshot_sha256(
    *,
    report_file: ReleaseSnapshotFileBinding,
    evidence_files: tuple[ReleaseSnapshotFileBinding, ...],
) -> str:
    return canonical_sha256(
        {
            "schema_version": "1.0",
            "report_file": {
                "namespace": report_file.namespace,
                "path": report_file.path,
                "sha256": report_file.sha256,
                "size": report_file.size,
            },
            "evidence_files": [
                {
                    "namespace": binding.namespace,
                    "path": binding.path,
                    "sha256": binding.sha256,
                    "size": binding.size,
                }
                for binding in evidence_files
            ],
        }
    )


def _candidate_state(candidate: ReleaseCandidateObservation) -> dict[str, object]:
    return candidate.model_dump(
        mode="json",
        exclude={"observed_at", "observation_sha256"},
    )


def _verification_state(
    verification: ReleaseRunVerificationBinding,
) -> dict[str, object]:
    return verification.model_dump(
        mode="json",
        exclude={"observed_at", "binding_sha256"},
    )


def _run_state(run: ReleaseRunBinding) -> dict[str, object]:
    return run.model_dump(
        mode="json",
        exclude={"observed_at", "binding_sha256"},
    )


def _static_state(evidence: StaticReleaseEvidence) -> dict[str, object]:
    return evidence.model_dump(
        mode="json",
        exclude={"observed_at", "evidence_sha256"},
    )


def _observe_validation_roots(
    *,
    report_root: Path,
    evidence_root: Path,
    release_repository_root: Path,
    emitted_run_dir: Path,
    target_repository_root: Path,
    configuration_root: Path,
    artifact_evidence_path: Path,
    run_verification_path: Path,
) -> _ValidationRoots:
    run = observe_unlinked_directory(emitted_run_dir, label="release validation run")
    observed = _ValidationRoots(
        report=observe_unlinked_directory(report_root, label="release validation report"),
        evidence=observe_unlinked_directory(evidence_root, label="release validation evidence"),
        release_repository=observe_unlinked_directory(
            release_repository_root,
            label="release validation repository",
        ),
        run=run,
        target_repository=observe_unlinked_directory(
            target_repository_root,
            label="release validation target repository",
        ),
        configuration=observe_release_configuration_input_from_run(
            run_dir=run.path,
            configuration_root=configuration_root,
        ),
        artifact_evidence=_observe_unlinked_regular_file(artifact_evidence_path),
        run_verification_evidence=_observe_unlinked_regular_file(run_verification_path),
    )
    if os.path.samestat(observed.report.path.stat(), observed.evidence.path.stat()):
        raise ValueError("release report and evidence roots must be distinct")
    for candidate in (observed.report.path, observed.evidence.path):
        for source in (
            observed.release_repository.path,
            observed.run.path,
            observed.target_repository.path,
            observed.configuration.root,
        ):
            if _directory_is_within(candidate, source) or _directory_is_within(
                source,
                candidate,
            ):
                raise ValueError(
                    "release report and evidence roots must be disjoint from source roots"
                )
    return observed


def _require_validation_directories_unchanged(roots: _ValidationRoots) -> None:
    for observation, label in (
        (roots.report, "release validation report"),
        (roots.evidence, "release validation evidence"),
        (roots.release_repository, "release validation repository"),
        (roots.run, "release validation run"),
        (roots.target_repository, "release validation target repository"),
    ):
        require_unchanged_unlinked_directory(observation, label=label)


def _observe_unlinked_regular_file(path: Path) -> _FileObservation:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    observed_components: list[tuple[Path, tuple[int, int, int, int, int, int, int]]] = []
    try:
        anchor_metadata = current.lstat()
        if (
            stat.S_ISLNK(anchor_metadata.st_mode)
            or current.is_junction()
            or not stat.S_ISDIR(anchor_metadata.st_mode)
        ):
            raise ValueError("release validation evidence anchor must be an unlinked directory")
        observed_components.append((current, _file_identity(anchor_metadata)))
        for index, part in enumerate(absolute.parts[1:]):
            current /= part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or current.is_junction():
                raise ValueError("release validation evidence path may not traverse a link")
            is_leaf = index == len(absolute.parts[1:]) - 1
            if not is_leaf and not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("release validation evidence parents must be directories")
            observed_components.append((current, _file_identity(metadata)))
        resolved = absolute.resolve(strict=True)
        if resolved != absolute:
            raise ValueError("release validation evidence path may not traverse a link")
        for index, (component, expected_identity) in enumerate(observed_components):
            metadata = component.lstat()
            is_leaf = index == len(observed_components) - 1
            if (
                stat.S_ISLNK(metadata.st_mode)
                or component.is_junction()
                or (not is_leaf and not stat.S_ISDIR(metadata.st_mode))
                or _file_identity(metadata)[:4] != expected_identity[:4]
            ):
                raise ValueError("release validation evidence path changed while being resolved")
    except OSError as exc:
        raise ValueError("release validation evidence file is unavailable") from exc
    metadata = absolute.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > MAX_AUXILIARY_EVIDENCE_BYTES
    ):
        raise ValueError("release validation evidence must be a bounded unshared regular file")
    return _FileObservation(
        path=absolute,
        identity=_file_identity(metadata),
    )


def _directory_is_within(candidate: Path, directory: Path) -> bool:
    try:
        expected = directory.stat()
        current = candidate
        while True:
            if os.path.samestat(current.stat(), expected):
                return True
            parent = current.parent
            if parent == current:
                return False
            current = parent
    except OSError as exc:
        raise ValueError("release validation root containment is unavailable") from exc


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_report_time(report: ReleaseGateReport) -> None:
    validation_time = _utc_now()
    if report.generated_at > validation_time + MAX_REPORT_CLOCK_SKEW:
        raise ValueError("release report generation time exceeds the allowed clock skew")
    if validation_time - report.generated_at > MAX_REPORT_AGE:
        raise ValueError("release report is stale")


def _utc_now() -> datetime:
    return datetime.now(UTC)
