from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, call

import pytest

import mmaudit.release_validation as validation_module
from mmaudit.models.schemas import AuditProfile, ExecutionEvidenceKind
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release import ReleaseGateId, ReleaseStatus
from mmaudit.release_candidate import ReleaseCandidateObservation
from mmaudit.release_gates import (
    ReleaseGateEvidenceBundle,
    ReleaseGatePrerequisiteBlocker,
    build_release_gate_evidence_bundle,
    build_release_gate_receipt,
    release_gate_fixed_plan_sha256,
)
from mmaudit.release_io import write_json_evidence
from mmaudit.release_report import (
    ReleaseGateReport,
    ReleaseReportInputBinding,
    ReleaseReportInputRole,
    _assemble_release_gate_report,
)
from mmaudit.release_run import ReleaseRunBinding, ReleaseRunBindingPayload
from mmaudit.release_static import StaticReleaseEvidence, StaticReleaseEvidencePayload
from mmaudit.release_validation import (
    MAX_REPORT_AGE,
    require_complete_release_report,
    validate_release_report,
    validate_release_report_integrity,
)
from mmaudit.release_verification import (
    ReleaseRunVerificationBinding,
    ReleaseRunVerificationBindingPayload,
)
from mmaudit.reporting.json_report import stable_json

NOW = datetime.now(UTC).replace(microsecond=0)
TOOL_SHA256 = "f" * 64


@dataclass(frozen=True, slots=True)
class _Workspace:
    report_root: Path
    evidence_root: Path
    release_repository_root: Path
    run_dir: Path
    target_repository_root: Path
    artifact_evidence_path: Path
    run_verification_path: Path
    report: ReleaseGateReport
    candidate: ReleaseCandidateObservation
    run: ReleaseRunBinding
    verification: ReleaseRunVerificationBinding
    static: StaticReleaseEvidence
    gates: ReleaseGateEvidenceBundle


def _candidate(
    *,
    observed_at: datetime,
    commit: str = "1" * 40,
) -> ReleaseCandidateObservation:
    payload = {
        "schema_version": "1.0",
        "generated_by": "mmaudit",
        "candidate_commit": commit,
        "git_object_format": "sha1",
        "candidate_tree_object": "2" * 40,
        "tracked_source_inventory_sha256": "3" * 64,
        "tracked_file_count": 100,
        "tracked_file_bytes": 10_000,
        "worktree_clean": True,
        "worktree_status_sha256": canonical_sha256([]),
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
    }
    return ReleaseCandidateObservation.model_validate(
        {
            **payload,
            "observation_sha256": canonical_sha256(payload),
        }
    )


def _run(
    *,
    effective_config_sha256: str = "d" * 64,
    achieved_profile: AuditProfile | None = AuditProfile.MAXIMUM_ASSURANCE,
    observed_at: datetime = NOW - timedelta(minutes=3, seconds=30),
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
        effective_config_sha256=effective_config_sha256,
        model_config_sha256="e" * 64,
        invocation_sha256="f" * 64,
        requested_profile=AuditProfile.MAXIMUM_ASSURANCE,
        achieved_profile=achieved_profile,
        artifact_evidence_file_sha256="0" * 64,
        artifact_evidence_file_size=1_000,
        artifact_evidence_sha256="1" * 64,
        artifact_inventory_sha256="2" * 64,
        artifact_count=31,
        traceability_sha256="3" * 64,
        observed_at=observed_at,
    )
    serialized = payload.model_dump(mode="json")
    return ReleaseRunBinding.model_validate(
        {
            **serialized,
            "binding_sha256": canonical_sha256(serialized),
        }
    )


def _verification(
    run: ReleaseRunBinding,
    *,
    observed_at: datetime,
    manifest_file_sha256: str | None = None,
) -> ReleaseRunVerificationBinding:
    payload = ReleaseRunVerificationBindingPayload(
        schema_version="1.0",
        generated_by="mmaudit",
        run_id=run.run_id,
        run_binding_sha256=run.binding_sha256,
        manifest_sha256=run.manifest_sha256,
        manifest_file_sha256=manifest_file_sha256 or run.manifest_file_sha256,
        target_source_tree_sha256=run.target_source_tree_sha256,
        effective_config_sha256=run.effective_config_sha256,
        status="current",
        mismatches=0,
        verification_file_sha256="4" * 64,
        verification_file_size=500,
        verification_sha256="5" * 64,
        observed_at=observed_at,
    )
    serialized = payload.model_dump(mode="json")
    return ReleaseRunVerificationBinding.model_validate(
        {
            **serialized,
            "binding_sha256": canonical_sha256(serialized),
        }
    )


def _static(
    candidate: ReleaseCandidateObservation,
    *,
    observed_at: datetime,
    benchmark_hash: str = "7" * 64,
) -> StaticReleaseEvidence:
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
        observed_at=observed_at,
        schemas=[schema],
        schema_inventory_sha256=canonical_sha256([schema.model_dump(mode="json")]),
        benchmark_source_bindings=1,
        benchmark_evidence_sha256=benchmark_hash,
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
    evidence_root: Path,
    candidate: ReleaseCandidateObservation,
    run: ReleaseRunBinding,
    *,
    blocked: set[ReleaseGateId],
) -> ReleaseGateEvidenceBundle:
    artifact_root = evidence_root / "gate-artifacts"
    artifact_root.mkdir()
    receipts = []
    for index, gate_id in enumerate(ReleaseGateId):
        timestamp = NOW - timedelta(minutes=2) + timedelta(seconds=index)
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
        else:
            content = (
                json.dumps({"gate": gate_id.value, "result": "passed"}, sort_keys=True) + "\n"
            ).encode()
            relative = f"gate-artifacts/{gate_id.value}.json"
            (evidence_root / relative).write_bytes(content)
            artifact = ManifestFileBinding(
                path=relative,
                sha256=hashlib.sha256(content).hexdigest(),
                size=len(content),
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


def _write_input(
    evidence_root: Path,
    *,
    role: ReleaseReportInputRole,
    value,
    inner_hash: str,
) -> ReleaseReportInputBinding:
    paths = {
        ReleaseReportInputRole.CANDIDATE: "candidate-observation.json",
        ReleaseReportInputRole.GATE_EVIDENCE: "gate-evidence.json",
        ReleaseReportInputRole.RUN: "run-binding.json",
        ReleaseReportInputRole.RUN_VERIFICATION: "run-verification-binding.json",
        ReleaseReportInputRole.STATIC_EVIDENCE: "static-evidence.json",
    }
    binding = write_json_evidence(
        evidence_root=evidence_root,
        relative_path=paths[role],
        value=value,
    )
    return ReleaseReportInputBinding(
        role=role,
        path=binding.path,
        file_sha256=binding.sha256,
        file_size=binding.size,
        evidence_sha256=inner_hash,
    )


def _workspace(
    tmp_path: Path,
    *,
    blocked: set[ReleaseGateId] | None = None,
    generated_at: datetime | None = None,
) -> _Workspace:
    tmp_path.mkdir(parents=True, exist_ok=True)
    blocked = blocked or set()
    report_root = tmp_path / "reports"
    evidence_root = tmp_path / "evidence"
    release_repository_root = tmp_path / "candidate"
    run_dir = tmp_path / "run"
    target_repository_root = tmp_path / "target"
    for path in (
        report_root,
        evidence_root,
        release_repository_root,
        run_dir,
        target_repository_root,
    ):
        path.mkdir()
    candidate = _candidate(observed_at=NOW - timedelta(minutes=4))
    run = _run()
    verification = _verification(run, observed_at=NOW - timedelta(minutes=3))
    static = _static(
        candidate,
        observed_at=NOW - timedelta(minutes=2, seconds=30),
    )
    gates = _gates(evidence_root, candidate, run, blocked=blocked)
    inputs = [
        _write_input(
            evidence_root,
            role=ReleaseReportInputRole.CANDIDATE,
            value=candidate,
            inner_hash=candidate.observation_sha256,
        ),
        _write_input(
            evidence_root,
            role=ReleaseReportInputRole.GATE_EVIDENCE,
            value=gates,
            inner_hash=gates.bundle_sha256,
        ),
        _write_input(
            evidence_root,
            role=ReleaseReportInputRole.RUN,
            value=run,
            inner_hash=run.binding_sha256,
        ),
        _write_input(
            evidence_root,
            role=ReleaseReportInputRole.RUN_VERIFICATION,
            value=verification,
            inner_hash=verification.binding_sha256,
        ),
        _write_input(
            evidence_root,
            role=ReleaseReportInputRole.STATIC_EVIDENCE,
            value=static,
            inner_hash=static.evidence_sha256,
        ),
    ]
    report = _assemble_release_gate_report(
        release_id="authoritative-release",
        generated_at=generated_at or NOW - timedelta(minutes=1),
        candidate=candidate,
        run=run,
        run_verification=verification,
        static_evidence=static,
        gate_evidence=gates,
        input_files=inputs,
        limitations=[],
    )
    write_json_evidence(
        evidence_root=report_root,
        relative_path="release-report.json",
        value=report,
    )
    artifact_evidence_path = evidence_root / "raw-artifact-evidence.json"
    artifact_evidence_path.write_text('{"synthetic":true}\n', encoding="utf-8")
    run_verification_path = evidence_root / "raw-run-verification.json"
    run_verification_path.write_text('{"synthetic":true}\n', encoding="utf-8")
    return _Workspace(
        report_root=report_root,
        evidence_root=evidence_root,
        release_repository_root=release_repository_root,
        run_dir=run_dir,
        target_repository_root=target_repository_root,
        artifact_evidence_path=artifact_evidence_path,
        run_verification_path=run_verification_path,
        report=report,
        candidate=candidate,
        run=run,
        verification=verification,
        static=static,
        gates=gates,
    )


def _install_fresh_observers(
    workspace: _Workspace,
    monkeypatch,
    *,
    candidate: ReleaseCandidateObservation | None = None,
    run: ReleaseRunBinding | None = None,
    verification: ReleaseRunVerificationBinding | None = None,
    static: StaticReleaseEvidence | None = None,
) -> tuple[Mock, Mock, Mock, Mock, Mock, Mock]:
    fresh_candidate = candidate or _candidate(observed_at=NOW)
    fresh_run = run or _run(observed_at=NOW)
    fresh_verification = verification or _verification(workspace.run, observed_at=NOW)
    fresh_static = static or _static(workspace.candidate, observed_at=NOW)
    candidate_observer = Mock(return_value=fresh_candidate)
    run_observer = Mock(return_value=fresh_run)
    verification_observer = Mock(return_value=fresh_verification)
    static_observer = Mock(return_value=fresh_static)
    local_gate_validator = Mock(return_value=())
    bound_gate_validator = Mock(return_value=())
    monkeypatch.setattr(validation_module, "observe_release_candidate", candidate_observer)
    monkeypatch.setattr(validation_module, "observe_release_run_binding", run_observer)
    monkeypatch.setattr(
        validation_module,
        "observe_release_run_verification",
        verification_observer,
    )
    monkeypatch.setattr(
        validation_module,
        "collect_static_release_evidence",
        static_observer,
    )
    monkeypatch.setattr(
        validation_module,
        "validate_local_release_gate_receipts",
        local_gate_validator,
    )
    monkeypatch.setattr(
        validation_module,
        "validate_bound_release_gate_receipts",
        bound_gate_validator,
    )
    monkeypatch.setattr(validation_module, "_utc_now", lambda: NOW)
    return (
        candidate_observer,
        run_observer,
        verification_observer,
        static_observer,
        local_gate_validator,
        bound_gate_validator,
    )


def _validate(workspace: _Workspace, *, require_complete: bool = False) -> ReleaseGateReport:
    return validate_release_report(
        report_root=workspace.report_root,
        report_relative_path="release-report.json",
        evidence_root=workspace.evidence_root,
        release_repository_root=workspace.release_repository_root,
        emitted_run_dir=workspace.run_dir,
        target_repository_root=workspace.target_repository_root,
        artifact_evidence_path=workspace.artifact_evidence_path,
        run_verification_path=workspace.run_verification_path,
        require_complete=require_complete,
    )


def test_integrity_validation_accepts_coherent_blocked_release_and_uses_explicit_roots(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = _workspace(tmp_path, blocked={ReleaseGateId.DOCTOR})
    (
        candidate_observer,
        run_observer,
        verification_observer,
        static_observer,
        local_gate_validator,
        bound_gate_validator,
    ) = _install_fresh_observers(workspace, monkeypatch)

    validated = _validate(workspace)

    assert validated == workspace.report
    assert validated.status is ReleaseStatus.BLOCKED_TECHNICAL
    assert candidate_observer.call_count == 2
    assert run_observer.call_args_list == [
        call(
            workspace.run_dir,
            workspace.release_repository_root,
            workspace.artifact_evidence_path,
        ),
        call(
            workspace.run_dir,
            workspace.release_repository_root,
            workspace.artifact_evidence_path,
        ),
    ]
    assert verification_observer.call_args_list == [
        call(
            run_dir=workspace.run_dir,
            target_repository_root=workspace.target_repository_root,
            release_repository_root=workspace.release_repository_root,
            artifact_evidence_path=workspace.artifact_evidence_path,
            verification_path=workspace.run_verification_path,
            run_binding=workspace.run,
        ),
        call(
            run_dir=workspace.run_dir,
            target_repository_root=workspace.target_repository_root,
            release_repository_root=workspace.release_repository_root,
            artifact_evidence_path=workspace.artifact_evidence_path,
            verification_path=workspace.run_verification_path,
            run_binding=workspace.run,
        ),
    ]
    assert static_observer.call_args_list == [
        call(
            workspace.release_repository_root,
            candidate=workspace.candidate,
        ),
        call(
            workspace.release_repository_root,
            candidate=workspace.candidate,
        ),
    ]
    assert local_gate_validator.call_args_list == [
        call(
            bundle=workspace.gates,
            evidence_root=workspace.evidence_root,
        ),
        call(
            bundle=workspace.gates,
            evidence_root=workspace.evidence_root,
        ),
    ]
    expected_bound_call = call(
        bundle=workspace.gates,
        evidence_root=workspace.evidence_root,
        candidate=workspace.candidate,
        run=workspace.run,
        run_verification=workspace.verification,
        static_evidence=workspace.static,
        input_bindings=list(workspace.report.input_files),
    )
    assert bound_gate_validator.call_args_list == [
        expected_bound_call,
        expected_bound_call,
    ]


def test_complete_policy_requires_all_real_gates_and_achieved_maximum_assurance(
    tmp_path: Path,
    monkeypatch,
) -> None:
    complete = _workspace(tmp_path / "complete")
    _install_fresh_observers(complete, monkeypatch)
    assert _validate(complete, require_complete=True).status is ReleaseStatus.COMPLETE
    assert require_complete_release_report(complete.report) == complete.report

    blocked = _workspace(
        tmp_path / "blocked",
        blocked={ReleaseGateId.MODEL_BENCHMARK},
    )
    _install_fresh_observers(blocked, monkeypatch)
    assert _validate(blocked).status is ReleaseStatus.BLOCKED_TECHNICAL
    with pytest.raises(ValueError, match="complete maximum-assurance"):
        _validate(blocked, require_complete=True)
    with pytest.raises(ValueError, match="complete maximum-assurance"):
        require_complete_release_report(blocked.report)


def test_validator_rejects_legacy_v1_report_without_fallback(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = _workspace(tmp_path)
    _install_fresh_observers(workspace, monkeypatch)
    report_path = workspace.report_root / "release-report.json"
    payload = workspace.report.model_dump(mode="json")
    payload["schema_version"] = "1.0"
    payload["report_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "report_sha256"}
    )
    report_path.write_text(stable_json(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="strict typed validation"):
        _validate(workspace)


def test_validator_rejects_coercible_json_types_even_when_normalized_hash_matches(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = _workspace(tmp_path)
    _install_fresh_observers(workspace, monkeypatch)
    payload = workspace.report.model_dump(mode="json")
    payload["total_gates"] = str(payload["total_gates"])
    (workspace.report_root / "release-report.json").write_text(
        stable_json(payload),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="strict typed validation"):
        _validate(workspace)


def test_validator_rejects_future_report_beyond_explicit_skew(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = _workspace(
        tmp_path,
        generated_at=NOW + timedelta(minutes=4),
    )
    _install_fresh_observers(workspace, monkeypatch)
    monkeypatch.setattr(validation_module, "_utc_now", lambda: NOW - timedelta(minutes=2))

    with pytest.raises(ValueError, match="clock skew"):
        _validate(workspace)


def test_validator_accepts_exact_age_boundary_and_rejects_older_report(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = _workspace(tmp_path)
    _install_fresh_observers(workspace, monkeypatch)
    monkeypatch.setattr(
        validation_module,
        "_utc_now",
        lambda: workspace.report.generated_at + MAX_REPORT_AGE,
    )
    assert _validate(workspace) == workspace.report

    monkeypatch.setattr(
        validation_module,
        "_utc_now",
        lambda: workspace.report.generated_at + MAX_REPORT_AGE + timedelta(seconds=1),
    )
    with pytest.raises(ValueError, match="stale"):
        _validate(workspace)


def test_validator_rejects_report_that_expires_during_validation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = _workspace(tmp_path)
    _install_fresh_observers(workspace, monkeypatch)
    times = iter(
        (
            workspace.report.generated_at + MAX_REPORT_AGE,
            workspace.report.generated_at + MAX_REPORT_AGE + timedelta(seconds=1),
        )
    )
    monkeypatch.setattr(validation_module, "_utc_now", lambda: next(times))

    with pytest.raises(ValueError, match="stale"):
        _validate(workspace)


@pytest.mark.parametrize("kind", ["report_symlink", "input_hardlink", "input_symlink"])
def test_validator_rejects_linked_or_shared_report_inputs(
    tmp_path: Path,
    monkeypatch,
    kind: str,
) -> None:
    workspace = _workspace(tmp_path)
    _install_fresh_observers(workspace, monkeypatch)
    if kind == "report_symlink":
        report_path = workspace.report_root / "release-report.json"
        outside = tmp_path / "outside-report.json"
        report_path.rename(outside)
        report_path.symlink_to(outside)
    else:
        input_path = workspace.evidence_root / "run-binding.json"
        outside = tmp_path / "outside-input.json"
        if kind == "input_hardlink":
            os.link(input_path, outside)
        else:
            input_path.rename(outside)
            input_path.symlink_to(outside)

    with pytest.raises(ValueError, match=r"unshared|regular file"):
        _validate(workspace)


@pytest.mark.parametrize("root_kind", ["report", "evidence"])
def test_validator_rejects_linked_control_plane_root(
    tmp_path: Path,
    monkeypatch,
    root_kind: str,
) -> None:
    workspace = _workspace(tmp_path)
    _install_fresh_observers(workspace, monkeypatch)
    target = workspace.report_root if root_kind == "report" else workspace.evidence_root
    linked_root = tmp_path / f"{root_kind}-root-link"
    linked_root.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="root may not traverse a link"):
        validate_release_report_integrity(
            report_root=linked_root if root_kind == "report" else workspace.report_root,
            report_relative_path="release-report.json",
            evidence_root=linked_root if root_kind == "evidence" else workspace.evidence_root,
            release_repository_root=workspace.release_repository_root,
            emitted_run_dir=workspace.run_dir,
            target_repository_root=workspace.target_repository_root,
            artifact_evidence_path=workspace.artifact_evidence_path,
            run_verification_path=workspace.run_verification_path,
        )


@pytest.mark.parametrize("kind", ["artifact_symlink", "verification_hardlink"])
def test_validator_rejects_linked_or_shared_auxiliary_evidence(
    tmp_path: Path,
    monkeypatch,
    kind: str,
) -> None:
    workspace = _workspace(tmp_path)
    _install_fresh_observers(workspace, monkeypatch)
    if kind == "artifact_symlink":
        target = workspace.artifact_evidence_path
        outside = tmp_path / "outside-artifact-evidence.json"
        target.rename(outside)
        target.symlink_to(outside)
    else:
        target = workspace.run_verification_path
        os.link(target, tmp_path / "shared-run-verification.json")

    with pytest.raises(ValueError, match=r"may not traverse a link|bounded unshared"):
        _validate(workspace)


@pytest.mark.parametrize("inside", ["candidate", "run", "target"])
@pytest.mark.parametrize("root_kind", ["report", "evidence"])
def test_validator_rejects_control_plane_roots_inside_candidate_run_or_target(
    tmp_path: Path,
    monkeypatch,
    inside: str,
    root_kind: str,
) -> None:
    workspace = _workspace(tmp_path)
    _install_fresh_observers(workspace, monkeypatch)
    forbidden = {
        "candidate": workspace.release_repository_root,
        "run": workspace.run_dir,
        "target": workspace.target_repository_root,
    }[inside]

    with pytest.raises(
        ValueError,
        match="disjoint from source roots",
    ):
        validate_release_report_integrity(
            report_root=forbidden if root_kind == "report" else workspace.report_root,
            report_relative_path="release-report.json",
            evidence_root=forbidden if root_kind == "evidence" else workspace.evidence_root,
            release_repository_root=workspace.release_repository_root,
            emitted_run_dir=workspace.run_dir,
            target_repository_root=workspace.target_repository_root,
            artifact_evidence_path=workspace.artifact_evidence_path,
            run_verification_path=workspace.run_verification_path,
        )


@pytest.mark.parametrize("root_kind", ["report", "evidence"])
def test_validator_rejects_control_plane_root_that_contains_source_roots(
    tmp_path: Path,
    monkeypatch,
    root_kind: str,
) -> None:
    workspace = _workspace(tmp_path)
    _install_fresh_observers(workspace, monkeypatch)

    with pytest.raises(ValueError, match="disjoint from source roots"):
        validate_release_report_integrity(
            report_root=tmp_path if root_kind == "report" else workspace.report_root,
            report_relative_path="release-report.json",
            evidence_root=tmp_path if root_kind == "evidence" else workspace.evidence_root,
            release_repository_root=workspace.release_repository_root,
            emitted_run_dir=workspace.run_dir,
            target_repository_root=workspace.target_repository_root,
            artifact_evidence_path=workspace.artifact_evidence_path,
            run_verification_path=workspace.run_verification_path,
        )


def test_validator_requires_distinct_report_and_evidence_roots(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = _workspace(tmp_path)
    _install_fresh_observers(workspace, monkeypatch)

    with pytest.raises(ValueError, match="must be distinct"):
        validate_release_report_integrity(
            report_root=workspace.evidence_root,
            report_relative_path="release-report.json",
            evidence_root=workspace.evidence_root,
            release_repository_root=workspace.release_repository_root,
            emitted_run_dir=workspace.run_dir,
            target_repository_root=workspace.target_repository_root,
            artifact_evidence_path=workspace.artifact_evidence_path,
            run_verification_path=workspace.run_verification_path,
        )


def test_validator_rejects_stale_candidate_run_verification_and_static_state(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = _workspace(tmp_path)
    stale_candidate = _candidate(observed_at=NOW, commit="9" * 40)
    _install_fresh_observers(workspace, monkeypatch, candidate=stale_candidate)
    with pytest.raises(ValueError, match="candidate"):
        _validate(workspace)

    workspace = _workspace(tmp_path / "run-stale")
    stale_run = _run(effective_config_sha256="0" * 64)
    _install_fresh_observers(workspace, monkeypatch, run=stale_run)
    with pytest.raises(ValueError, match="run binding is stale"):
        _validate(workspace)

    workspace = _workspace(tmp_path / "verification-stale")
    stale_verification = _verification(
        workspace.run,
        observed_at=NOW,
        manifest_file_sha256="0" * 64,
    )
    _install_fresh_observers(
        workspace,
        monkeypatch,
        verification=stale_verification,
    )
    with pytest.raises(ValueError, match="run verification is stale"):
        _validate(workspace)

    workspace = _workspace(tmp_path / "static-stale")
    stale_static = _static(
        workspace.candidate,
        observed_at=NOW,
        benchmark_hash="0" * 64,
    )
    _install_fresh_observers(workspace, monkeypatch, static=stale_static)
    with pytest.raises(ValueError, match="static evidence is stale"):
        _validate(workspace)


@pytest.mark.parametrize("source", ["run", "verification", "static"])
def test_validator_rejects_source_state_that_changes_after_initial_observation(
    tmp_path: Path,
    monkeypatch,
    source: str,
) -> None:
    workspace = _workspace(tmp_path)
    (
        _candidate_observer,
        run_observer,
        verification_observer,
        static_observer,
        _local_gate_validator,
        _bound_gate_validator,
    ) = _install_fresh_observers(workspace, monkeypatch)
    if source == "run":
        run_observer.side_effect = (
            _run(observed_at=NOW),
            _run(effective_config_sha256="0" * 64, observed_at=NOW),
        )
    elif source == "verification":
        verification_observer.side_effect = (
            _verification(workspace.run, observed_at=NOW),
            _verification(
                workspace.run,
                observed_at=NOW,
                manifest_file_sha256="0" * 64,
            ),
        )
    else:
        static_observer.side_effect = (
            _static(workspace.candidate, observed_at=NOW),
            _static(
                workspace.candidate,
                observed_at=NOW,
                benchmark_hash="0" * 64,
            ),
        )

    with pytest.raises(ValueError, match="changed during validation"):
        _validate(workspace)


@pytest.mark.parametrize("evidence_kind", ["artifact", "verification"])
def test_validator_rejects_auxiliary_evidence_file_race(
    tmp_path: Path,
    monkeypatch,
    evidence_kind: str,
) -> None:
    workspace = _workspace(tmp_path)
    (
        _candidate_observer,
        run_observer,
        verification_observer,
        _static_observer,
        _local_gate_validator,
        _bound_gate_validator,
    ) = _install_fresh_observers(workspace, monkeypatch)
    target = (
        workspace.artifact_evidence_path
        if evidence_kind == "artifact"
        else workspace.run_verification_path
    )
    observer = run_observer if evidence_kind == "artifact" else verification_observer
    result = observer.return_value
    mutations = 0

    def mutate_auxiliary_evidence(*_args, **_kwargs):
        nonlocal mutations
        mutations += 1
        target.write_text(f'{{"mutation":{mutations}}}\n', encoding="utf-8")
        return result

    observer.side_effect = mutate_auxiliary_evidence

    with pytest.raises(ValueError, match="roots changed during validation"):
        _validate(workspace)


def test_validator_rejects_tampered_gate_artifact_and_input_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    gate_workspace = _workspace(tmp_path / "gate")
    _install_fresh_observers(gate_workspace, monkeypatch)
    gate_path = gate_workspace.evidence_root / "gate-artifacts" / "doctor.json"
    gate_path.write_text('{"tampered":true}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="artifact hash mismatch"):
        _validate(gate_workspace)

    input_workspace = _workspace(tmp_path / "input")
    _install_fresh_observers(input_workspace, monkeypatch)
    input_path = input_workspace.evidence_root / "candidate-observation.json"
    input_path.write_bytes(input_path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="input file binding is stale"):
        _validate(input_workspace)


def test_validator_propagates_local_gate_semantic_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = _workspace(tmp_path)
    *_, local_gate_validator, _bound_gate_validator = _install_fresh_observers(
        workspace,
        monkeypatch,
    )
    local_gate_validator.side_effect = ValueError("local release result is inconsistent")

    with pytest.raises(ValueError, match="local release result"):
        _validate(workspace)


def test_validator_propagates_bound_gate_semantic_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = _workspace(tmp_path)
    *_, bound_gate_validator = _install_fresh_observers(workspace, monkeypatch)
    bound_gate_validator.side_effect = ValueError("bound release result is inconsistent")

    with pytest.raises(ValueError, match="bound release result"):
        _validate(workspace)


def test_validator_detects_input_race_across_authoritative_reconstruction(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = _workspace(tmp_path)
    _install_fresh_observers(workspace, monkeypatch)
    real_run_observer = validation_module.observe_release_run_binding

    def mutate_after_run_observation(*args, **kwargs):
        result = real_run_observer(*args, **kwargs)
        candidate_path = workspace.evidence_root / "candidate-observation.json"
        candidate_path.write_bytes(candidate_path.read_bytes() + b"\n")
        return result

    monkeypatch.setattr(
        validation_module,
        "observe_release_run_binding",
        mutate_after_run_observation,
    )

    with pytest.raises(ValueError, match="input changed during validation"):
        _validate(workspace)


def test_validator_detects_gate_artifact_race_after_initial_validation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = _workspace(tmp_path)
    _install_fresh_observers(workspace, monkeypatch)
    real_run_observer = validation_module.observe_release_run_binding

    def mutate_gate_after_run_observation(*args, **kwargs):
        result = real_run_observer(*args, **kwargs)
        gate_path = workspace.evidence_root / "gate-artifacts" / "doctor.json"
        gate_path.write_text('{"changed_during_validation":true}\n', encoding="utf-8")
        return result

    monkeypatch.setattr(
        validation_module,
        "observe_release_run_binding",
        mutate_gate_after_run_observation,
    )

    with pytest.raises(ValueError, match="artifact hash mismatch"):
        _validate(workspace)


def test_validator_rejects_resealed_non_authoritative_report_projection(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = _workspace(tmp_path)
    _install_fresh_observers(workspace, monkeypatch)
    payload = workspace.report.model_dump(mode="json")
    payload["gates"][0]["tool_name"] = "fabricated-tool"
    payload["gate_observations_sha256"] = canonical_sha256(payload["gates"])
    payload["report_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "report_sha256"}
    )
    (workspace.report_root / "release-report.json").write_text(
        stable_json(payload),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="authoritative reconstruction"):
        _validate(workspace)


def test_validator_rejects_report_path_traversal(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = _workspace(tmp_path)
    _install_fresh_observers(workspace, monkeypatch)

    with pytest.raises(ValueError, match="safe relative path"):
        validate_release_report_integrity(
            report_root=workspace.report_root,
            report_relative_path="../release-report.json",
            evidence_root=workspace.evidence_root,
            release_repository_root=workspace.release_repository_root,
            emitted_run_dir=workspace.run_dir,
            target_repository_root=workspace.target_repository_root,
            artifact_evidence_path=workspace.artifact_evidence_path,
            run_verification_path=workspace.run_verification_path,
        )


def test_validator_requires_explicit_existing_report_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = _workspace(tmp_path)
    _install_fresh_observers(workspace, monkeypatch)

    with pytest.raises(ValueError, match="missing"):
        validate_release_report_integrity(
            report_root=workspace.report_root,
            report_relative_path="not-the-report.json",
            evidence_root=workspace.evidence_root,
            release_repository_root=workspace.release_repository_root,
            emitted_run_dir=workspace.run_dir,
            target_repository_root=workspace.target_repository_root,
            artifact_evidence_path=workspace.artifact_evidence_path,
            run_verification_path=workspace.run_verification_path,
        )
