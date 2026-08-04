from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    AuditProfile,
    ExecutionEvidenceKind,
    LanguageCapabilityProfile,
    LanguageCapabilityStatus,
)
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release import ReleaseGateId, ReleaseGateStatus, ReleaseStatus
from mmaudit.release_candidate import ReleaseCandidateObservation
from mmaudit.release_gates import (
    ReleaseGateEvidenceBundle,
    ReleaseGatePrerequisiteBlocker,
    build_release_gate_evidence_bundle,
    build_release_gate_receipt,
    release_gate_fixed_plan_sha256,
)
from mmaudit.release_report import (
    ReleaseGateReport,
    ReleaseReportInputBinding,
    ReleaseReportInputRole,
    _assemble_release_gate_report,
)
from mmaudit.release_run import ReleaseRunBinding, ReleaseRunBindingPayload
from mmaudit.release_static import StaticReleaseEvidence, StaticReleaseEvidencePayload
from mmaudit.release_verification import (
    ReleaseRunVerificationBinding,
    ReleaseRunVerificationBindingPayload,
)

START = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=2)
TOOL_SHA256 = "f" * 64


def _candidate() -> ReleaseCandidateObservation:
    payload = {
        "schema_version": "1.0",
        "generated_by": "mmaudit",
        "candidate_commit": "1" * 40,
        "git_object_format": "sha1",
        "candidate_tree_object": "2" * 40,
        "tracked_source_inventory_sha256": "3" * 64,
        "tracked_file_count": 100,
        "tracked_file_bytes": 10_000,
        "worktree_clean": True,
        "worktree_status_sha256": canonical_sha256([]),
        "observed_at": START.isoformat().replace("+00:00", "Z"),
    }
    return ReleaseCandidateObservation.model_validate(
        {
            **payload,
            "observation_sha256": canonical_sha256(payload),
        }
    )


def _run(
    profile: AuditProfile = AuditProfile.MAXIMUM_ASSURANCE,
) -> ReleaseRunBinding:
    payload = ReleaseRunBindingPayload(
        schema_version="1.0",
        generated_by="mmaudit",
        run_id="release-run",
        target_repository_name="synthetic-target",
        target_git_commit="4" * 40,
        target_source_tree_sha256="5" * 64,
        manifest_path="run-evidence-manifest.json",
        manifest_file_sha256="6" * 64,
        manifest_sha256="7" * 64,
        run_configuration_sha256="8" * 64,
        file_config_sha256="9" * 64,
        environment_overrides_sha256="a" * 64,
        cli_overrides_sha256="b" * 64,
        run_options_sha256="c" * 64,
        effective_config_sha256="d" * 64,
        model_config_sha256="e" * 64,
        invocation_sha256="f" * 64,
        requested_profile=profile,
        achieved_profile=profile,
        requested_language_profile=LanguageCapabilityProfile.SOLIDITY_EVM,
        achieved_language_profile=LanguageCapabilityProfile.SOLIDITY_EVM,
        capability_status=LanguageCapabilityStatus.MATCHED,
        reduced_language_capability=False,
        language_capability_sha256="4" * 64,
        artifact_evidence_file_sha256="0" * 64,
        artifact_evidence_file_size=1_000,
        artifact_evidence_sha256="1" * 64,
        artifact_inventory_sha256="2" * 64,
        artifact_count=31,
        traceability_sha256="3" * 64,
        observed_at=START + timedelta(seconds=5),
    )
    serialized = payload.model_dump(mode="json")
    return ReleaseRunBinding.model_validate(
        {
            **serialized,
            "binding_sha256": canonical_sha256(serialized),
        }
    )


def _verification(run: ReleaseRunBinding) -> ReleaseRunVerificationBinding:
    payload = ReleaseRunVerificationBindingPayload(
        schema_version="1.0",
        generated_by="mmaudit",
        run_id=run.run_id,
        run_binding_sha256=run.binding_sha256,
        manifest_sha256=run.manifest_sha256,
        manifest_file_sha256=run.manifest_file_sha256,
        target_source_tree_sha256=run.target_source_tree_sha256,
        effective_config_sha256=run.effective_config_sha256,
        status="current",
        mismatches=0,
        verification_file_sha256="4" * 64,
        verification_file_size=500,
        verification_sha256="5" * 64,
        observed_at=START + timedelta(seconds=10),
    )
    serialized = payload.model_dump(mode="json")
    return ReleaseRunVerificationBinding.model_validate(
        {
            **serialized,
            "binding_sha256": canonical_sha256(serialized),
        }
    )


def _static(candidate: ReleaseCandidateObservation) -> StaticReleaseEvidence:
    schema = ManifestFileBinding(
        path="schemas/synthetic.schema.json",
        sha256="6" * 64,
        size=100,
    )
    payload = StaticReleaseEvidencePayload(
        schema_version="1.0",
        generated_by="mmaudit",
        candidate_commit=candidate.candidate_commit,
        candidate_observation_sha256=candidate.observation_sha256,
        observed_at=START + timedelta(seconds=15),
        schemas=[schema],
        schema_inventory_sha256=canonical_sha256([schema.model_dump(mode="json")]),
        benchmark_source_bindings=1,
        benchmark_evidence_sha256="7" * 64,
        model_cases=1,
        model_corpus_sha256="8" * 64,
        economic_cases=1,
        economic_manifest_sha256="9" * 64,
        adversarial_cases=1,
        adversarial_manifest_sha256="a" * 64,
        full_protocol_files=1,
        full_protocol_manifest_sha256="b" * 64,
        snapshot_comparison_sha256="c" * 64,
        foundry_ast_sha256="d" * 64,
    )
    serialized = payload.model_dump(mode="json")
    return StaticReleaseEvidence.model_validate(
        {
            **serialized,
            "evidence_sha256": canonical_sha256(serialized),
        }
    )


def _gates(
    candidate: ReleaseCandidateObservation,
    run: ReleaseRunBinding,
    *,
    blocked: set[ReleaseGateId] | None = None,
    failed: set[ReleaseGateId] | None = None,
) -> ReleaseGateEvidenceBundle:
    blocked = blocked or set()
    failed = failed or set()
    receipts = []
    for index, gate_id in enumerate(ReleaseGateId):
        timestamp = START + timedelta(seconds=20 + index)
        if gate_id in blocked:
            receipt = build_release_gate_receipt(
                gate_id=gate_id,
                candidate_observation_sha256=candidate.observation_sha256,
                run_binding_sha256=run.binding_sha256,
                fixed_plan_sha256=release_gate_fixed_plan_sha256(gate_id),
                started_at=timestamp,
                ended_at=timestamp,
                argv=("mmaudit-release", gate_id.value),
                tool_name="mmaudit-release",
                tool_version=None,
                tool_executable_sha256=None,
                execution_evidence=ExecutionEvidenceKind.UNVERIFIED,
                exit_code=None,
                timed_out=False,
                stdout=b"",
                stderr=b"",
                summary="required real prerequisite is unavailable",
                prerequisite_blocker=ReleaseGatePrerequisiteBlocker(
                    code=f"{gate_id.value}_unavailable",
                    summary=f"{gate_id.value} real prerequisite is unavailable",
                ),
                artifact_bindings=(),
            )
        elif gate_id in failed:
            receipt = build_release_gate_receipt(
                gate_id=gate_id,
                candidate_observation_sha256=candidate.observation_sha256,
                run_binding_sha256=run.binding_sha256,
                fixed_plan_sha256=release_gate_fixed_plan_sha256(gate_id),
                started_at=timestamp,
                ended_at=timestamp,
                argv=("mmaudit-release", gate_id.value),
                tool_name="mmaudit-release",
                tool_version="1.0",
                tool_executable_sha256=TOOL_SHA256,
                execution_evidence=ExecutionEvidenceKind.REAL,
                exit_code=1,
                timed_out=False,
                stdout=b"",
                stderr=b"synthetic failure",
                summary="release gate failed",
                prerequisite_blocker=None,
                artifact_bindings=(),
            )
        else:
            artifact = ManifestFileBinding(
                path=f"gate-artifacts/{gate_id.value}.json",
                sha256=f"{index:x}" * 64,
                size=100 + index,
            )
            receipt = build_release_gate_receipt(
                gate_id=gate_id,
                candidate_observation_sha256=candidate.observation_sha256,
                run_binding_sha256=run.binding_sha256,
                fixed_plan_sha256=release_gate_fixed_plan_sha256(gate_id),
                started_at=timestamp,
                ended_at=timestamp,
                argv=("mmaudit-release", gate_id.value),
                tool_name="mmaudit-release",
                tool_version="1.0",
                tool_executable_sha256=TOOL_SHA256,
                execution_evidence=ExecutionEvidenceKind.REAL,
                exit_code=0,
                timed_out=False,
                stdout=b"passed",
                stderr=b"",
                summary="release gate passed with runtime evidence",
                prerequisite_blocker=None,
                artifact_bindings=(artifact,),
            )
        receipts.append(receipt)
    return build_release_gate_evidence_bundle(
        candidate_observation_sha256=candidate.observation_sha256,
        run_binding_sha256=run.binding_sha256,
        receipts=receipts,
    )


def _inputs(
    candidate: ReleaseCandidateObservation,
    run: ReleaseRunBinding,
    verification: ReleaseRunVerificationBinding,
    static: StaticReleaseEvidence,
    gates: ReleaseGateEvidenceBundle,
) -> list[ReleaseReportInputBinding]:
    inner_hashes = {
        ReleaseReportInputRole.CANDIDATE: candidate.observation_sha256,
        ReleaseReportInputRole.GATE_EVIDENCE: gates.bundle_sha256,
        ReleaseReportInputRole.RUN: run.binding_sha256,
        ReleaseReportInputRole.RUN_VERIFICATION: verification.binding_sha256,
        ReleaseReportInputRole.STATIC_EVIDENCE: static.evidence_sha256,
    }
    paths = {
        ReleaseReportInputRole.CANDIDATE: "candidate-observation.json",
        ReleaseReportInputRole.GATE_EVIDENCE: "gate-evidence.json",
        ReleaseReportInputRole.RUN: "run-binding.json",
        ReleaseReportInputRole.RUN_VERIFICATION: "run-verification-binding.json",
        ReleaseReportInputRole.STATIC_EVIDENCE: "static-evidence.json",
    }
    return [
        ReleaseReportInputBinding(
            role=role,
            path=paths[role],
            file_sha256=f"{index + 6:x}" * 64,
            file_size=1_000 + index,
            evidence_sha256=inner_hashes[role],
        )
        for index, role in enumerate(ReleaseReportInputRole)
    ]


def _report(
    *,
    blocked: set[ReleaseGateId] | None = None,
    failed: set[ReleaseGateId] | None = None,
) -> ReleaseGateReport:
    candidate = _candidate()
    run = _run()
    verification = _verification(run)
    static = _static(candidate)
    gates = _gates(candidate, run, blocked=blocked, failed=failed)
    return _assemble_release_gate_report(
        release_id="release-candidate-test",
        generated_at=START + timedelta(minutes=1),
        candidate=candidate,
        run=run,
        run_verification=verification,
        static_evidence=static,
        gate_evidence=gates,
        input_files=_inputs(candidate, run, verification, static, gates),
        limitations=[],
    )


def test_complete_report_is_bound_to_exact_candidate_run_inputs_and_real_receipts() -> None:
    report = _report()

    assert report.status is ReleaseStatus.COMPLETE
    assert report.candidate.candidate_commit == "1" * 40
    assert report.run.effective_config_sha256 == "d" * 64
    assert report.run_verification.run_binding_sha256 == report.run.binding_sha256
    assert report.total_gates == report.passed_gates == 12
    assert report.safe_local_gates_complete
    assert report.all_required_gates_passed
    assert all(
        gate.execution_evidence is ExecutionEvidenceKind.REAL
        and gate.status is ReleaseGateStatus.PASSED
        for gate in report.gates
    )
    assert report.report_sha256 == canonical_sha256(
        report.model_dump(mode="json", exclude={"report_sha256"})
    )


def test_blockers_and_failures_are_preserved_without_false_completion() -> None:
    blocked = {
        ReleaseGateId.BENCHMARK_CERTIFICATE,
        ReleaseGateId.DOCTOR,
        ReleaseGateId.MAXIMUM_ASSURANCE_RUN,
        ReleaseGateId.MODEL_BENCHMARK,
        ReleaseGateId.REPLAY,
    }
    report = _report(blocked=blocked)
    assert report.status is ReleaseStatus.BLOCKED_TECHNICAL
    assert set(report.blocked_gates) == blocked
    assert report.passed_gates == 7
    assert not report.safe_local_gates_complete
    assert not report.all_required_gates_passed
    assert len(report.limitations) == len(blocked)

    failed = _report(
        blocked={ReleaseGateId.DOCTOR},
        failed={ReleaseGateId.PYTEST},
    )
    assert failed.status is ReleaseStatus.FAILED
    assert failed.failed_gates == (ReleaseGateId.PYTEST,)
    assert not failed.safe_local_gates_complete


def test_non_maximum_run_cannot_produce_a_complete_release() -> None:
    candidate = _candidate()
    run = _run(AuditProfile.STANDARD)
    verification = _verification(run)
    static = _static(candidate)
    gates = _gates(candidate, run)

    with pytest.raises(ValidationError, match="non-maximum"):
        _assemble_release_gate_report(
            release_id="standard-is-not-maximum",
            generated_at=START + timedelta(minutes=1),
            candidate=candidate,
            run=run,
            run_verification=verification,
            static_evidence=static,
            gate_evidence=gates,
            input_files=_inputs(candidate, run, verification, static, gates),
            limitations=[],
        )


def test_reduced_release_capability_requires_achieved_generic_review() -> None:
    payload = _run().model_dump(mode="json", exclude={"binding_sha256"})
    payload.update(
        {
            "requested_language_profile": "generic-source-review",
            "achieved_language_profile": None,
            "capability_status": "REDUCED",
            "reduced_language_capability": False,
        }
    )

    with pytest.raises(ValidationError, match="achieved generic source review"):
        ReleaseRunBindingPayload.model_validate(payload)


def test_structurally_self_hashed_legacy_report_cannot_validate_as_current() -> None:
    legacy = {
        "schema_version": "1.0",
        "generated_by": "mmaudit",
        "release_id": "stale",
        "repository_state": "claimed-clean",
        "status": "complete",
        "total_gates": 12,
        "passed_gates": 12,
        "blocked_gates": [],
        "failed_gates": [],
        "safe_local_gates_complete": True,
        "all_required_gates_passed": True,
        "gates": [],
        "limitations": [],
    }
    legacy["report_sha256"] = canonical_sha256(legacy)
    with pytest.raises(ValidationError, match=r"schema_version|Extra inputs"):
        ReleaseGateReport.model_validate(legacy)


def test_report_rejects_cross_candidate_gate_bundle_and_invalid_run_verification() -> None:
    candidate = _candidate()
    run = _run()
    verification = _verification(run)
    static = _static(candidate)
    gates = _gates(candidate, run)
    gate_payload = gates.model_dump(mode="json")
    gate_payload["candidate_observation_sha256"] = "0" * 64
    gate_payload["bundle_sha256"] = canonical_sha256(
        {key: value for key, value in gate_payload.items() if key != "bundle_sha256"}
    )
    with pytest.raises(ValidationError, match="not bound"):
        ReleaseGateEvidenceBundle.model_validate(gate_payload)

    mutated = verification.model_copy(update={"run_id": "different-run"})
    with pytest.raises(ValidationError):
        _assemble_release_gate_report(
            release_id="invalid-verification",
            generated_at=START + timedelta(minutes=1),
            candidate=candidate,
            run=run,
            run_verification=mutated,
            static_evidence=static,
            gate_evidence=gates,
            input_files=_inputs(candidate, run, verification, static, gates),
            limitations=[],
        )


def test_report_rejects_input_tampering_stale_time_and_self_hash_changes() -> None:
    candidate = _candidate()
    run = _run()
    verification = _verification(run)
    static = _static(candidate)
    gates = _gates(candidate, run)
    inputs = _inputs(candidate, run, verification, static, gates)
    wrong_inputs = [
        binding.model_copy(update={"evidence_sha256": "0" * 64})
        if binding.role is ReleaseReportInputRole.RUN
        else binding
        for binding in inputs
    ]
    with pytest.raises(ValidationError, match="inner hash"):
        _assemble_release_gate_report(
            release_id="bad-input",
            generated_at=START + timedelta(minutes=1),
            candidate=candidate,
            run=run,
            run_verification=verification,
            static_evidence=static,
            gate_evidence=gates,
            input_files=wrong_inputs,
            limitations=[],
        )
    with pytest.raises(ValidationError, match="predates"):
        _assemble_release_gate_report(
            release_id="stale-time",
            generated_at=START,
            candidate=candidate,
            run=run,
            run_verification=verification,
            static_evidence=static,
            gate_evidence=gates,
            input_files=inputs,
            limitations=[],
        )

    report = _report()
    payload = report.model_dump(mode="json")
    payload["candidate"]["candidate_commit"] = "0" * 40
    with pytest.raises(ValidationError):
        ReleaseGateReport.model_validate(payload)
