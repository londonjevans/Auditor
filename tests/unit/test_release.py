from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.release import (
    ReleaseGateId,
    ReleaseGateObservation,
    ReleaseGateReport,
    ReleaseGateStatus,
    ReleaseStatus,
    build_release_gate_report,
    load_release_gate_report,
    write_release_gate_report,
)

ROOT = Path(__file__).resolve().parents[2]


def _observations(
    *,
    blocked: set[ReleaseGateId] | None = None,
    failed: set[ReleaseGateId] | None = None,
) -> list[ReleaseGateObservation]:
    blocked = blocked or set()
    failed = failed or set()
    observations: list[ReleaseGateObservation] = []
    for gate_id in ReleaseGateId:
        if gate_id in blocked:
            observations.append(
                ReleaseGateObservation(
                    gate_id=gate_id,
                    status=ReleaseGateStatus.BLOCKED_TECHNICAL,
                    command=f"mmaudit-release {gate_id.value}",
                    result="required real integration unavailable",
                    blocker="synthetic technical blocker",
                    evidence=["mocked coverage passed"],
                    mocked=True,
                )
            )
        elif gate_id in failed:
            observations.append(
                ReleaseGateObservation(
                    gate_id=gate_id,
                    status=ReleaseGateStatus.FAILED,
                    command=f"mmaudit-release {gate_id.value}",
                    exit_code=1,
                    result="gate failed",
                )
            )
        else:
            observations.append(
                ReleaseGateObservation(
                    gate_id=gate_id,
                    status=ReleaseGateStatus.PASSED,
                    command=f"mmaudit-release {gate_id.value}",
                    exit_code=0,
                    result="gate passed",
                )
            )
    return observations


def test_complete_release_requires_every_real_gate_to_pass() -> None:
    report = build_release_gate_report(
        release_id="release-test",
        repository_state="synthetic-commit",
        observations=_observations(),
        limitations=[],
    )

    assert report.status is ReleaseStatus.COMPLETE
    assert report.passed_gates == report.total_gates == 12
    assert report.blocked_gates == []
    assert report.failed_gates == []
    assert report.safe_local_gates_complete
    assert report.all_required_gates_passed


def test_technical_blockers_preserve_safe_local_completion_without_release_claim() -> None:
    blocked = {
        ReleaseGateId.DOCTOR,
        ReleaseGateId.MAXIMUM_ASSURANCE_RUN,
        ReleaseGateId.MODEL_BENCHMARK,
        ReleaseGateId.REPLAY,
    }
    report = build_release_gate_report(
        release_id="release-blocked",
        repository_state="uncommitted-worktree",
        observations=_observations(blocked=blocked),
        limitations=["real integrations remain unavailable"],
    )

    assert report.status is ReleaseStatus.BLOCKED_TECHNICAL
    assert report.blocked_gates == sorted(blocked, key=lambda item: item.value)
    assert report.failed_gates == []
    assert report.safe_local_gates_complete
    assert not report.all_required_gates_passed


def test_failure_takes_precedence_over_technical_blockers() -> None:
    report = build_release_gate_report(
        release_id="release-failed",
        repository_state="synthetic-commit",
        observations=_observations(
            blocked={ReleaseGateId.MODEL_BENCHMARK},
            failed={ReleaseGateId.PYTEST},
        ),
        limitations=[],
    )

    assert report.status is ReleaseStatus.FAILED
    assert report.failed_gates == [ReleaseGateId.PYTEST]
    assert not report.safe_local_gates_complete


def test_mocked_real_integration_cannot_be_recorded_as_passed() -> None:
    with pytest.raises(ValidationError, match="mocked evidence cannot pass"):
        ReleaseGateObservation(
            gate_id=ReleaseGateId.MODEL_BENCHMARK,
            status=ReleaseGateStatus.PASSED,
            command="pytest mocked-model-benchmark",
            exit_code=0,
            result="mocked benchmark passed",
            mocked=True,
        )
    with pytest.raises(ValidationError, match="blocker"):
        ReleaseGateObservation(
            gate_id=ReleaseGateId.REPLAY,
            status=ReleaseGateStatus.BLOCKED_TECHNICAL,
            command="mmaudit replay",
            result="not executed",
        )


def test_missing_duplicate_and_tampered_gate_evidence_is_rejected() -> None:
    observations = _observations()
    with pytest.raises(ValueError, match="uniquely cover"):
        build_release_gate_report(
            release_id="missing",
            repository_state="synthetic",
            observations=observations[:-1],
            limitations=[],
        )
    with pytest.raises(ValueError, match="uniquely cover"):
        build_release_gate_report(
            release_id="duplicate",
            repository_state="synthetic",
            observations=[*observations, observations[0]],
            limitations=[],
        )

    report = build_release_gate_report(
        release_id="tampered",
        repository_state="synthetic",
        observations=observations,
        limitations=[],
    )
    payload = report.model_dump(mode="json")
    payload["passed_gates"] = 0
    with pytest.raises(ValidationError, match="passed-gate"):
        ReleaseGateReport.model_validate(payload)


def test_report_round_trip_loader_and_link_rejection(tmp_path: Path) -> None:
    report = build_release_gate_report(
        release_id="round-trip",
        repository_state="synthetic",
        observations=_observations(blocked={ReleaseGateId.REPLAY}),
        limitations=["real replay unavailable"],
    )
    output = tmp_path / "release-gate-report.json"
    write_release_gate_report(output, report)

    assert load_release_gate_report(output) == report
    target = tmp_path / "target.json"
    target.write_text("{}\n", encoding="utf-8")
    linked = tmp_path / "linked.json"
    linked.symlink_to(target)
    with pytest.raises(ValueError, match="non-link"):
        load_release_gate_report(linked)
    with pytest.raises(ValueError, match="may not be a link"):
        write_release_gate_report(linked, report)


def test_published_release_schema_is_strict_and_complete() -> None:
    schema = json.loads(
        (ROOT / "schemas/release_gate_report.schema.json").read_text(encoding="utf-8")
    )

    assert schema["additionalProperties"] is False
    assert schema["$defs"]["gate"]["additionalProperties"] is False
    assert set(schema["required"]) == set(ReleaseGateReport.model_fields)
    assert set(schema["$defs"]["gateId"]["enum"]) == {item.value for item in ReleaseGateId}
