from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

import mmaudit.release_gates as release_module
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release import ReleaseGateId, ReleaseGateStatus
from mmaudit.release_gates import (
    ReleaseGateEvidenceBundle,
    ReleaseGateFixedPlan,
    ReleaseGatePrerequisiteBlocker,
    ReleaseGateReceipt,
    ReleaseGateResultKind,
    ReleaseGateResultSummary,
    build_release_gate_evidence_bundle,
    build_release_gate_receipt,
    get_release_gate_fixed_plan,
    release_gate_fixed_plan_sha256,
    validate_release_gate_evidence_bundle,
)

START = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
END = datetime(2026, 7, 28, 12, 1, tzinfo=UTC)
TOOL_SHA256 = hashlib.sha256(b"synthetic-tool").hexdigest()
CANDIDATE_SHA256 = "a" * 64
RUN_BINDING_SHA256 = "b" * 64


def _write_binding(root: Path, name: str, content: bytes) -> ManifestFileBinding:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return ManifestFileBinding(
        path=name,
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
    )


def _passed_receipt(
    gate_id: ReleaseGateId,
    binding: ManifestFileBinding,
) -> ReleaseGateReceipt:
    return _passed_receipt_with_bindings(gate_id, (binding,))


def _passed_receipt_with_bindings(
    gate_id: ReleaseGateId,
    bindings: tuple[ManifestFileBinding, ...],
) -> ReleaseGateReceipt:
    return build_release_gate_receipt(
        gate_id=gate_id,
        candidate_observation_sha256=CANDIDATE_SHA256,
        run_binding_sha256=RUN_BINDING_SHA256,
        fixed_plan_sha256=release_gate_fixed_plan_sha256(gate_id),
        started_at=START,
        ended_at=END,
        argv=("mmaudit-release", gate_id.value),
        tool_name="mmaudit-release",
        tool_version="1.0",
        tool_executable_sha256=TOOL_SHA256,
        execution_evidence=ExecutionEvidenceKind.REAL,
        exit_code=0,
        timed_out=False,
        stdout=b"bounded synthetic stdout",
        stderr=b"",
        summary="gate completed with runtime evidence",
        prerequisite_blocker=None,
        artifact_bindings=bindings,
    )


def _complete_bundle(root: Path) -> ReleaseGateEvidenceBundle:
    receipts = []
    for gate_id in ReleaseGateId:
        binding = _write_binding(
            root,
            f"gate-evidence/{gate_id.value}.json",
            f'{{"gate":"{gate_id.value}"}}\n'.encode(),
        )
        receipts.append(_passed_receipt(gate_id, binding))
    return build_release_gate_evidence_bundle(
        candidate_observation_sha256=CANDIDATE_SHA256,
        run_binding_sha256=RUN_BINDING_SHA256,
        receipts=list(reversed(receipts)),
    )


def test_receipt_derives_status_and_hashes_without_retaining_raw_output(tmp_path: Path) -> None:
    binding = _write_binding(tmp_path, "evidence/result.json", b'{"ok":true}\n')
    receipt = _passed_receipt(ReleaseGateId.PYTEST, binding)

    assert receipt.status is ReleaseGateStatus.PASSED
    assert receipt.argv == ("mmaudit-release", "pytest")
    assert receipt.argv_sha256 == canonical_sha256(list(receipt.argv))
    assert receipt.stdout_sha256 == hashlib.sha256(b"bounded synthetic stdout").hexdigest()
    assert receipt.stderr_sha256 == hashlib.sha256(b"").hexdigest()
    assert receipt.result_summary.kind is ReleaseGateResultKind.PASSED
    assert receipt.result_summary.checks_total == receipt.result_summary.checks_passed == 1
    serialized = receipt.model_dump_json()
    assert "bounded synthetic stdout" not in serialized
    assert '"stdout":' not in serialized
    assert receipt.receipt_sha256 == canonical_sha256(
        receipt.model_dump(mode="json", exclude={"receipt_sha256"})
    )


def test_every_gate_has_one_canonical_self_hashed_semantic_plan() -> None:
    plans = [get_release_gate_fixed_plan(gate_id) for gate_id in ReleaseGateId]

    assert [plan.gate_id for plan in plans] == list(ReleaseGateId)
    assert len({plan.fixed_plan_sha256 for plan in plans}) == len(ReleaseGateId)
    for plan in plans:
        assert plan.schema_version == "1.0"
        assert plan.generated_by == "mmaudit"
        assert plan.fixed_plan_sha256 == canonical_sha256(
            plan.model_dump(mode="json", exclude={"fixed_plan_sha256"})
        )
        assert release_gate_fixed_plan_sha256(plan.gate_id) == plan.fixed_plan_sha256
    assert get_release_gate_fixed_plan(ReleaseGateId.RUFF_FORMAT).arguments == (
        "format",
        "--check",
        ".",
    )
    assert get_release_gate_fixed_plan(ReleaseGateId.RUFF_CHECK).arguments == ("check", ".")
    assert get_release_gate_fixed_plan(ReleaseGateId.MYPY).arguments == ()
    assert get_release_gate_fixed_plan(ReleaseGateId.PYTEST).arguments == (
        "-q",
        "--junitxml",
        "{evidence_root}/release-gate-pytest-junit.xml",
    )


@pytest.mark.parametrize(
    "execution_evidence",
    (ExecutionEvidenceKind.MOCK, ExecutionEvidenceKind.UNVERIFIED),
)
def test_mock_and_unverified_success_can_never_pass(
    tmp_path: Path,
    execution_evidence: ExecutionEvidenceKind,
) -> None:
    binding = _write_binding(tmp_path, "result.json", b"result\n")
    with pytest.raises(ValueError, match="cannot pass"):
        build_release_gate_receipt(
            gate_id=ReleaseGateId.MODEL_BENCHMARK,
            candidate_observation_sha256=CANDIDATE_SHA256,
            run_binding_sha256=RUN_BINDING_SHA256,
            fixed_plan_sha256=release_gate_fixed_plan_sha256(ReleaseGateId.MODEL_BENCHMARK),
            started_at=START,
            ended_at=END,
            argv=("mmaudit", "models", "benchmark"),
            tool_name="mmaudit",
            tool_version="1.0",
            tool_executable_sha256=TOOL_SHA256,
            execution_evidence=execution_evidence,
            exit_code=0,
            timed_out=False,
            stdout=b"",
            stderr=b"",
            summary="non-real execution completed",
            prerequisite_blocker=None,
            artifact_bindings=(binding,),
        )


def test_failed_timed_out_and_blocked_statuses_are_derived() -> None:
    failed = build_release_gate_receipt(
        gate_id=ReleaseGateId.PYTEST,
        candidate_observation_sha256=CANDIDATE_SHA256,
        run_binding_sha256=RUN_BINDING_SHA256,
        fixed_plan_sha256=release_gate_fixed_plan_sha256(ReleaseGateId.PYTEST),
        started_at=START,
        ended_at=END,
        argv=("pytest", "-q"),
        tool_name="pytest",
        tool_version="9.0",
        tool_executable_sha256=TOOL_SHA256,
        execution_evidence=ExecutionEvidenceKind.REAL,
        exit_code=1,
        timed_out=False,
        stdout=b"",
        stderr=b"failure",
        summary="tests failed",
        prerequisite_blocker=None,
        artifact_bindings=(),
    )
    timed_out = build_release_gate_receipt(
        gate_id=ReleaseGateId.REPLAY,
        candidate_observation_sha256=CANDIDATE_SHA256,
        run_binding_sha256=RUN_BINDING_SHA256,
        fixed_plan_sha256=release_gate_fixed_plan_sha256(ReleaseGateId.REPLAY),
        started_at=START,
        ended_at=END,
        argv=("mmaudit", "replay"),
        tool_name="mmaudit",
        tool_version="1.0",
        tool_executable_sha256=TOOL_SHA256,
        execution_evidence=ExecutionEvidenceKind.REAL,
        exit_code=None,
        timed_out=True,
        stdout=b"",
        stderr=b"",
        summary="replay timed out",
        prerequisite_blocker=None,
        artifact_bindings=(),
    )
    blocked = build_release_gate_receipt(
        gate_id=ReleaseGateId.DOCTOR,
        candidate_observation_sha256=CANDIDATE_SHA256,
        run_binding_sha256=RUN_BINDING_SHA256,
        fixed_plan_sha256=release_gate_fixed_plan_sha256(ReleaseGateId.DOCTOR),
        started_at=START,
        ended_at=END,
        argv=("mmaudit", "doctor"),
        tool_name="mmaudit",
        tool_version=None,
        tool_executable_sha256=None,
        execution_evidence=ExecutionEvidenceKind.UNVERIFIED,
        exit_code=None,
        timed_out=False,
        stdout=b"",
        stderr=b"",
        summary="required credential is unavailable",
        prerequisite_blocker=ReleaseGatePrerequisiteBlocker(
            code="credential_unavailable",
            summary="explicit provider credential was not supplied",
        ),
        artifact_bindings=(),
    )

    assert failed.status is ReleaseGateStatus.FAILED
    assert failed.result_summary.kind is ReleaseGateResultKind.FAILED
    assert timed_out.status is ReleaseGateStatus.FAILED
    assert timed_out.result_summary.kind is ReleaseGateResultKind.TIMED_OUT
    assert blocked.status is ReleaseGateStatus.BLOCKED_TECHNICAL
    assert blocked.result_summary.kind is ReleaseGateResultKind.BLOCKED_TECHNICAL


@pytest.mark.parametrize(
    ("exit_code", "timed_out"),
    ((1, False), (None, True)),
)
def test_terminal_failure_cannot_be_laundered_as_a_prerequisite_blocker(
    exit_code: int | None,
    timed_out: bool,
) -> None:
    with pytest.raises(ValidationError, match="cannot claim a prerequisite blocker"):
        build_release_gate_receipt(
            gate_id=ReleaseGateId.REPLAY,
            candidate_observation_sha256=CANDIDATE_SHA256,
            run_binding_sha256=RUN_BINDING_SHA256,
            fixed_plan_sha256=release_gate_fixed_plan_sha256(ReleaseGateId.REPLAY),
            started_at=START,
            ended_at=END,
            argv=("mmaudit", "replay"),
            tool_name="mmaudit",
            tool_version="1.0",
            tool_executable_sha256=TOOL_SHA256,
            execution_evidence=ExecutionEvidenceKind.REAL,
            exit_code=exit_code,
            timed_out=timed_out,
            stdout=b"",
            stderr=b"terminal failure",
            summary="terminal execution failed",
            prerequisite_blocker=ReleaseGatePrerequisiteBlocker(
                code="dependency_unavailable",
                summary="a prerequisite was reported unavailable",
            ),
            artifact_bindings=(),
        )


def test_receipt_rejects_missing_artifacts_tool_identity_and_inconsistent_payload(
    tmp_path: Path,
) -> None:
    binding = _write_binding(tmp_path, "result.json", b"result\n")
    common = {
        "gate_id": ReleaseGateId.PYTEST,
        "candidate_observation_sha256": CANDIDATE_SHA256,
        "run_binding_sha256": RUN_BINDING_SHA256,
        "fixed_plan_sha256": release_gate_fixed_plan_sha256(ReleaseGateId.PYTEST),
        "started_at": START,
        "ended_at": END,
        "argv": ("pytest", "-q"),
        "tool_name": "pytest",
        "tool_version": "9.0",
        "tool_executable_sha256": TOOL_SHA256,
        "execution_evidence": ExecutionEvidenceKind.REAL,
        "exit_code": 0,
        "timed_out": False,
        "stdout": b"",
        "stderr": b"",
        "summary": "tests passed",
        "prerequisite_blocker": None,
        "artifact_bindings": (binding,),
    }
    with pytest.raises(ValueError, match="artifact evidence"):
        build_release_gate_receipt(**{**common, "artifact_bindings": ()})
    with pytest.raises(ValidationError, match="tool identity"):
        build_release_gate_receipt(
            **{
                **common,
                "tool_version": None,
                "tool_executable_sha256": None,
            }
        )

    receipt = build_release_gate_receipt(**common)
    payload = receipt.model_dump(mode="json")
    payload["argv"].append("--changed")
    with pytest.raises(ValidationError, match="argv hash"):
        ReleaseGateReceipt.model_validate(payload)
    payload = receipt.model_dump(mode="json")
    payload["receipt_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="receipt hash"):
        ReleaseGateReceipt.model_validate(payload)


def test_receipt_rejects_fractional_time_raw_output_overflow_and_partial_counts(
    tmp_path: Path,
) -> None:
    binding = _write_binding(tmp_path, "result.json", b"result\n")
    common = {
        "gate_id": ReleaseGateId.PYTEST,
        "candidate_observation_sha256": CANDIDATE_SHA256,
        "run_binding_sha256": RUN_BINDING_SHA256,
        "fixed_plan_sha256": release_gate_fixed_plan_sha256(ReleaseGateId.PYTEST),
        "started_at": START,
        "ended_at": END,
        "argv": ("pytest", "-q"),
        "tool_name": "pytest",
        "tool_version": "9.0",
        "tool_executable_sha256": TOOL_SHA256,
        "execution_evidence": ExecutionEvidenceKind.REAL,
        "exit_code": 0,
        "timed_out": False,
        "stdout": b"",
        "stderr": b"",
        "summary": "tests passed",
        "prerequisite_blocker": None,
        "artifact_bindings": (binding,),
    }
    with pytest.raises(ValidationError, match="whole seconds"):
        build_release_gate_receipt(**{**common, "started_at": START.replace(microsecond=1)})
    with pytest.raises(ValueError, match="captured output"):
        build_release_gate_receipt(**{**common, "stdout": b"x" * (4 * 1024 * 1024 + 1)})
    with pytest.raises(ValueError, match="supplied together"):
        build_release_gate_receipt(**common, checks_total=1)


def test_result_summary_is_typed_strict_and_nonvacuous() -> None:
    with pytest.raises(ValidationError, match="non-empty"):
        ReleaseGateResultSummary(
            kind=ReleaseGateResultKind.PASSED,
            summary="vacuous pass",
            checks_total=0,
            checks_passed=0,
            checks_failed=0,
        )
    with pytest.raises(ValidationError, match="Extra inputs"):
        ReleaseGateResultSummary.model_validate(
            {
                "kind": "failed",
                "summary": "failed",
                "checks_total": 1,
                "checks_passed": 0,
                "checks_failed": 1,
                "raw_output": "must not be retained",
            }
        )
    with pytest.raises(ValidationError, match="cannot claim completed checks"):
        ReleaseGateResultSummary(
            kind=ReleaseGateResultKind.BLOCKED_TECHNICAL,
            summary="prerequisite unavailable",
            checks_total=1,
            checks_passed=1,
            checks_failed=0,
        )


def test_bundle_is_exact_sorted_self_hashed_and_resolves_real_files(tmp_path: Path) -> None:
    bundle = _complete_bundle(tmp_path)

    assert [receipt.gate_id for receipt in bundle.receipts] == sorted(
        ReleaseGateId,
        key=lambda gate_id: gate_id.value,
    )
    assert bundle.receipt_set_sha256 == canonical_sha256(
        [
            {
                "gate_id": receipt.gate_id.value,
                "receipt_sha256": receipt.receipt_sha256,
            }
            for receipt in bundle.receipts
        ]
    )
    assert bundle.bundle_sha256 == canonical_sha256(
        bundle.model_dump(mode="json", exclude={"bundle_sha256"})
    )
    assert bundle.generated_by == "mmaudit"
    assert all(receipt.generated_by == "mmaudit" for receipt in bundle.receipts)
    assert validate_release_gate_evidence_bundle(bundle, evidence_root=tmp_path) == bundle


def test_gate_artifacts_require_explicit_schema_and_generator_fields(tmp_path: Path) -> None:
    bundle = _complete_bundle(tmp_path)
    artifacts = (
        (ReleaseGateFixedPlan, get_release_gate_fixed_plan(ReleaseGateId.RUFF_CHECK)),
        (ReleaseGateReceipt, bundle.receipts[0]),
        (ReleaseGateEvidenceBundle, bundle),
    )

    for model, artifact in artifacts:
        for required_field in ("schema_version", "generated_by"):
            payload = artifact.model_dump(mode="json")
            del payload[required_field]
            with pytest.raises(ValidationError, match=required_field):
                model.model_validate(payload)


def test_bundle_rejects_missing_duplicate_out_of_order_and_tampered_receipts(
    tmp_path: Path,
) -> None:
    bundle = _complete_bundle(tmp_path)
    with pytest.raises(ValidationError, match="at least 12"):
        build_release_gate_evidence_bundle(
            candidate_observation_sha256=CANDIDATE_SHA256,
            run_binding_sha256=RUN_BINDING_SHA256,
            receipts=bundle.receipts[:-1],
        )
    with pytest.raises(ValidationError, match="every gate exactly once"):
        build_release_gate_evidence_bundle(
            candidate_observation_sha256=CANDIDATE_SHA256,
            run_binding_sha256=RUN_BINDING_SHA256,
            receipts=(*bundle.receipts[:-1], bundle.receipts[0]),
        )

    payload = bundle.model_dump(mode="json")
    payload["receipts"] = list(reversed(payload["receipts"]))
    with pytest.raises(ValidationError, match="every gate exactly once and sorted"):
        ReleaseGateEvidenceBundle.model_validate(payload)
    payload = bundle.model_dump(mode="json")
    payload["receipt_set_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="receipt-set hash"):
        ReleaseGateEvidenceBundle.model_validate(payload)
    payload = bundle.model_dump(mode="json")
    payload["bundle_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="bundle hash"):
        ReleaseGateEvidenceBundle.model_validate(payload)


def test_receipts_cannot_be_rebound_to_another_candidate_run_or_plan(tmp_path: Path) -> None:
    bundle = _complete_bundle(tmp_path)
    original = bundle.receipts[0]

    rebound_payload = original.model_dump(mode="json", exclude={"receipt_sha256"})
    rebound_payload["candidate_observation_sha256"] = "c" * 64
    rebound = ReleaseGateReceipt.model_validate(
        {
            **rebound_payload,
            "receipt_sha256": canonical_sha256(rebound_payload),
        }
    )
    with pytest.raises(ValidationError, match="not bound to the bundle"):
        build_release_gate_evidence_bundle(
            candidate_observation_sha256=CANDIDATE_SHA256,
            run_binding_sha256=RUN_BINDING_SHA256,
            receipts=(rebound, *bundle.receipts[1:]),
        )

    plan_payload = original.model_dump(mode="json", exclude={"receipt_sha256"})
    plan_payload["fixed_plan_sha256"] = "d" * 64
    plan_payload["receipt_sha256"] = canonical_sha256(plan_payload)
    with pytest.raises(ValidationError, match="canonical fixed plan"):
        ReleaseGateReceipt.model_validate(plan_payload)


def test_bundle_rejects_excessive_unique_artifact_count_and_aggregate_bytes() -> None:
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    unique_bindings = tuple(
        ManifestFileBinding(
            path=f"many/{index:05d}.json",
            sha256=empty_sha256,
            size=0,
        )
        for index in range(4_097)
    )
    receipts: list[ReleaseGateReceipt] = []
    cursor = 0
    for gate_id in ReleaseGateId:
        selected = unique_bindings[cursor : cursor + 1_000]
        cursor += len(selected)
        if not selected:
            selected = (unique_bindings[0],)
        receipts.append(_passed_receipt_with_bindings(gate_id, selected))
    with pytest.raises(ValidationError, match="unique-artifact bound"):
        build_release_gate_evidence_bundle(
            candidate_observation_sha256=CANDIDATE_SHA256,
            run_binding_sha256=RUN_BINDING_SHA256,
            receipts=receipts,
        )

    large_receipts = []
    for index, gate_id in enumerate(ReleaseGateId):
        large_receipts.append(
            _passed_receipt_with_bindings(
                gate_id,
                (
                    ManifestFileBinding(
                        path=f"large/{index:02d}.bin",
                        sha256=empty_sha256,
                        size=100_000_000,
                    ),
                ),
            )
        )
    with pytest.raises(ValidationError, match="aggregate artifact-byte bound"):
        build_release_gate_evidence_bundle(
            candidate_observation_sha256=CANDIDATE_SHA256,
            run_binding_sha256=RUN_BINDING_SHA256,
            receipts=large_receipts,
        )


def test_validator_rejects_missing_linked_hardlinked_and_hash_mismatched_artifacts(
    tmp_path: Path,
) -> None:
    missing_root = tmp_path / "missing"
    missing_root.mkdir()
    missing_bundle = _complete_bundle(missing_root)
    missing_path = missing_root / missing_bundle.receipts[0].artifact_bindings[0].path
    missing_path.unlink()
    with pytest.raises(ValueError, match="missing"):
        validate_release_gate_evidence_bundle(missing_bundle, evidence_root=missing_root)

    linked_root = tmp_path / "linked"
    linked_root.mkdir()
    linked_bundle = _complete_bundle(linked_root)
    linked_path = linked_root / linked_bundle.receipts[0].artifact_bindings[0].path
    linked_path.unlink()
    outside = tmp_path / "outside.json"
    outside.write_text('{"outside":true}\n', encoding="utf-8")
    linked_path.symlink_to(outside)
    with pytest.raises(ValueError, match="may not traverse a link"):
        validate_release_gate_evidence_bundle(linked_bundle, evidence_root=linked_root)

    hardlink_root = tmp_path / "hardlink"
    hardlink_root.mkdir()
    hardlink_bundle = _complete_bundle(hardlink_root)
    hardlink_path = hardlink_root / hardlink_bundle.receipts[0].artifact_bindings[0].path
    original = hardlink_path.read_bytes()
    hardlink_path.unlink()
    hardlink_source = tmp_path / "hardlink-source.json"
    hardlink_source.write_bytes(original)
    try:
        os.link(hardlink_source, hardlink_path)
    except OSError:
        pytest.skip("hardlinks unavailable")
    with pytest.raises(ValueError, match="unshared regular file"):
        validate_release_gate_evidence_bundle(hardlink_bundle, evidence_root=hardlink_root)

    mismatch_root = tmp_path / "mismatch"
    mismatch_root.mkdir()
    mismatch_bundle = _complete_bundle(mismatch_root)
    mismatch_path = mismatch_root / mismatch_bundle.receipts[0].artifact_bindings[0].path
    mismatch_path.write_text('{"changed":true}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        validate_release_gate_evidence_bundle(mismatch_bundle, evidence_root=mismatch_root)


def test_validator_rejects_linked_evidence_root_and_linked_parent(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    bundle = _complete_bundle(root)
    linked_root = tmp_path / "evidence-link"
    linked_root.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError, match="root may not traverse a link"):
        validate_release_gate_evidence_bundle(bundle, evidence_root=linked_root)

    parent_target = tmp_path / "parent-target"
    parent_target.mkdir()
    nested_root = parent_target / "nested"
    nested_root.mkdir()
    nested_bundle = _complete_bundle(nested_root)
    parent_link = tmp_path / "parent-link"
    parent_link.symlink_to(parent_target, target_is_directory=True)
    with pytest.raises(ValueError, match="root may not traverse a link"):
        validate_release_gate_evidence_bundle(
            nested_bundle,
            evidence_root=parent_link / "nested",
        )


def test_descriptor_relative_validation_fails_closed_on_parent_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    bundle = _complete_bundle(root)
    relative = bundle.receipts[0].artifact_bindings[0].path
    parent = root / Path(relative).parent
    backup = root / "gate-evidence-held"
    outside = tmp_path / "outside-race"
    outside.mkdir()
    (outside / Path(relative).name).write_text("redirected bytes\n", encoding="utf-8")

    original_open = release_module.os.open
    swapped = False

    def racing_open(
        path: str | bytes | int,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if path == Path(relative).name and dir_fd is not None and not swapped:
            swapped = True
            parent.rename(backup)
            parent.symlink_to(outside, target_is_directory=True)
            try:
                return original_open(path, flags, mode, dir_fd=dir_fd)
            finally:
                parent.unlink()
                backup.rename(parent)
        if dir_fd is None:
            return original_open(path, flags, mode)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(release_module.os, "open", racing_open)
    with pytest.raises(ValueError, match="root changed"):
        validate_release_gate_evidence_bundle(bundle, evidence_root=root)
    assert swapped
