from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mmaudit.models.schemas import AuditProfile, ExecutionEvidenceKind
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release import ReleaseGateId, ReleaseGateStatus
from mmaudit.release_candidate import ReleaseCandidateObservation
from mmaudit.release_gates import (
    ReleaseGatePrerequisiteBlocker,
    build_release_gate_evidence_bundle,
    build_release_gate_receipt,
    release_gate_fixed_plan_sha256,
)
from mmaudit.release_io import write_json_evidence
from mmaudit.release_observations import (
    BoundReleaseGateResult,
    collect_bound_release_gate_receipt,
    validate_bound_release_gate_receipts,
)
from mmaudit.release_report import ReleaseReportInputBinding, ReleaseReportInputRole
from mmaudit.release_run import ReleaseRunBinding, ReleaseRunBindingPayload
from mmaudit.release_static import StaticReleaseEvidence, StaticReleaseEvidencePayload
from mmaudit.release_verification import (
    ReleaseRunVerificationBinding,
    ReleaseRunVerificationBindingPayload,
)

NOW = datetime.now(UTC).replace(microsecond=0)


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
        "observed_at": (NOW - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
    }
    return ReleaseCandidateObservation.model_validate(
        {
            **payload,
            "observation_sha256": canonical_sha256(payload),
        }
    )


def _run() -> ReleaseRunBinding:
    payload = ReleaseRunBindingPayload(
        schema_version="1.0",
        generated_by="mmaudit",
        run_id="bound-observation-run",
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
        requested_profile=AuditProfile.MAXIMUM_ASSURANCE,
        achieved_profile=None,
        artifact_evidence_file_sha256="0" * 64,
        artifact_evidence_file_size=1_000,
        artifact_evidence_sha256="1" * 64,
        artifact_inventory_sha256="2" * 64,
        artifact_count=31,
        traceability_sha256="3" * 64,
        observed_at=NOW - timedelta(minutes=4),
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
        observed_at=NOW - timedelta(minutes=3),
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
        observed_at=NOW - timedelta(minutes=2),
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


def _write_input(
    root: Path,
    *,
    role: ReleaseReportInputRole,
    value,
    evidence_sha256: str,
) -> ReleaseReportInputBinding:
    paths = {
        ReleaseReportInputRole.CANDIDATE: "candidate-observation.json",
        ReleaseReportInputRole.GATE_EVIDENCE: "gate-evidence.json",
        ReleaseReportInputRole.RUN: "run-binding.json",
        ReleaseReportInputRole.RUN_VERIFICATION: "run-verification-binding.json",
        ReleaseReportInputRole.STATIC_EVIDENCE: "static-evidence.json",
    }
    binding = write_json_evidence(
        evidence_root=root,
        relative_path=paths[role],
        value=value,
    )
    return ReleaseReportInputBinding(
        role=role,
        path=binding.path,
        file_sha256=binding.sha256,
        file_size=binding.size,
        evidence_sha256=evidence_sha256,
    )


def _workspace(tmp_path: Path):
    root = tmp_path / "evidence"
    root.mkdir(mode=0o700)
    candidate = _candidate()
    run = _run()
    verification = _verification(run)
    static = _static(candidate)
    inputs = [
        _write_input(
            root,
            role=ReleaseReportInputRole.CANDIDATE,
            value=candidate,
            evidence_sha256=candidate.observation_sha256,
        ),
        _write_input(
            root,
            role=ReleaseReportInputRole.RUN,
            value=run,
            evidence_sha256=run.binding_sha256,
        ),
        _write_input(
            root,
            role=ReleaseReportInputRole.RUN_VERIFICATION,
            value=verification,
            evidence_sha256=verification.binding_sha256,
        ),
        _write_input(
            root,
            role=ReleaseReportInputRole.STATIC_EVIDENCE,
            value=static,
            evidence_sha256=static.evidence_sha256,
        ),
    ]
    receipts = []
    for gate_id in ReleaseGateId:
        if gate_id in {
            ReleaseGateId.MYPY,
            ReleaseGateId.PYTEST,
            ReleaseGateId.RUFF_CHECK,
            ReleaseGateId.RUFF_FORMAT,
        }:
            blocker = ReleaseGatePrerequisiteBlocker(
                code=f"{gate_id.value}_not_run",
                summary=f"{gate_id.value} local command was not run in this unit fixture",
            )
            receipts.append(
                build_release_gate_receipt(
                    gate_id=gate_id,
                    candidate_observation_sha256=candidate.observation_sha256,
                    run_binding_sha256=run.binding_sha256,
                    fixed_plan_sha256=release_gate_fixed_plan_sha256(gate_id),
                    started_at=NOW,
                    ended_at=NOW,
                    argv=("mmaudit-release", gate_id.value),
                    tool_name="mmaudit-release",
                    tool_version=None,
                    tool_executable_sha256=None,
                    execution_evidence=ExecutionEvidenceKind.UNVERIFIED,
                    exit_code=None,
                    timed_out=False,
                    stdout=b"",
                    stderr=b"",
                    summary=blocker.summary,
                    prerequisite_blocker=blocker,
                    artifact_bindings=(),
                )
            )
        else:
            receipts.append(
                collect_bound_release_gate_receipt(
                    gate_id=gate_id,
                    evidence_root=root,
                    candidate=candidate,
                    run=run,
                    run_verification=verification,
                    static_evidence=static,
                    input_bindings=inputs,
                )
            )
    bundle = build_release_gate_evidence_bundle(
        candidate_observation_sha256=candidate.observation_sha256,
        run_binding_sha256=run.binding_sha256,
        receipts=receipts,
    )
    inputs.append(
        _write_input(
            root,
            role=ReleaseReportInputRole.GATE_EVIDENCE,
            value=bundle,
            evidence_sha256=bundle.bundle_sha256,
        )
    )
    return root, candidate, run, verification, static, inputs, bundle


def test_bound_observations_pass_only_static_local_facts_and_preserve_blockers(
    tmp_path: Path,
) -> None:
    root, candidate, run, verification, static, inputs, bundle = _workspace(tmp_path)

    results = validate_bound_release_gate_receipts(
        bundle=bundle,
        evidence_root=root,
        candidate=candidate,
        run=run,
        run_verification=verification,
        static_evidence=static,
        input_bindings=inputs,
    )

    assert len(results) == 8
    statuses = {result.gate_id: result.status for result in results}
    assert {
        gate_id for gate_id, status in statuses.items() if status is ReleaseGateStatus.PASSED
    } == {
        ReleaseGateId.ARTIFACTS,
        ReleaseGateId.MANIFESTS,
        ReleaseGateId.SCHEMAS,
    }
    assert {
        gate_id
        for gate_id, status in statuses.items()
        if status is ReleaseGateStatus.BLOCKED_TECHNICAL
    } == {
        ReleaseGateId.BENCHMARK_CERTIFICATE,
        ReleaseGateId.DOCTOR,
        ReleaseGateId.MAXIMUM_ASSURANCE_RUN,
        ReleaseGateId.MODEL_BENCHMARK,
        ReleaseGateId.REPLAY,
    }


def test_bound_validator_rejects_laundering_a_blocker_into_a_pass(
    tmp_path: Path,
) -> None:
    root, candidate, run, verification, static, inputs, bundle = _workspace(tmp_path)
    receipts = list(bundle.receipts)
    index = next(
        index
        for index, receipt in enumerate(receipts)
        if receipt.gate_id is ReleaseGateId.BENCHMARK_CERTIFICATE
    )
    blocked = receipts[index]
    receipts[index] = build_release_gate_receipt(
        gate_id=blocked.gate_id,
        candidate_observation_sha256=candidate.observation_sha256,
        run_binding_sha256=run.binding_sha256,
        fixed_plan_sha256=blocked.fixed_plan_sha256,
        started_at=blocked.started_at,
        ended_at=blocked.ended_at,
        argv=blocked.argv,
        tool_name=blocked.tool_name,
        tool_version=blocked.tool_version,
        tool_executable_sha256=blocked.tool_executable_sha256,
        tool_distribution_sha256=blocked.tool_distribution_sha256,
        execution_evidence=ExecutionEvidenceKind.REAL,
        exit_code=0,
        timed_out=False,
        stdout=b"",
        stderr=b"",
        summary="fabricated benchmark pass",
        prerequisite_blocker=None,
        artifact_bindings=blocked.artifact_bindings,
    )
    laundered = build_release_gate_evidence_bundle(
        candidate_observation_sha256=candidate.observation_sha256,
        run_binding_sha256=run.binding_sha256,
        receipts=receipts,
    )
    gate_input = next(
        binding for binding in inputs if binding.role is ReleaseReportInputRole.GATE_EVIDENCE
    )
    inputs = [
        binding for binding in inputs if binding.role is not ReleaseReportInputRole.GATE_EVIDENCE
    ]
    (root / gate_input.path).unlink()
    inputs.append(
        _write_input(
            root,
            role=ReleaseReportInputRole.GATE_EVIDENCE,
            value=laundered,
            evidence_sha256=laundered.bundle_sha256,
        )
    )

    with pytest.raises(ValueError, match="semantic receipt"):
        validate_bound_release_gate_receipts(
            bundle=laundered,
            evidence_root=root,
            candidate=candidate,
            run=run,
            run_verification=verification,
            static_evidence=static,
            input_bindings=inputs,
        )


def test_bound_result_artifact_cannot_be_rebound_to_another_candidate(
    tmp_path: Path,
) -> None:
    root, candidate, _, _, _, _, bundle = _workspace(tmp_path)
    receipt = next(
        receipt for receipt in bundle.receipts if receipt.gate_id is ReleaseGateId.ARTIFACTS
    )
    result = BoundReleaseGateResult.model_validate_json(
        (root / receipt.artifact_bindings[0].path).read_bytes()
    )
    assert result.candidate_observation_sha256 == candidate.observation_sha256

    payload = result.model_dump(mode="json")
    payload["candidate_observation_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="hash is inconsistent"):
        BoundReleaseGateResult.model_validate(payload)
