from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.models.scheduler import scheduler_canonical_sha256
from mmaudit.models.schemas import ExecutionEvidenceKind, UsageRecord
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntryStatus,
    CostReservationOverrunError,
    ReleaseReason,
)
from mmaudit.orchestration.scheduler_runtime import build_scheduler_cost_ledger_baseline
from mmaudit.reporting.bundle import (
    CostLedgerAbsenceEvidence,
    ModelExecutionArtifact,
    RunCostLedgerEvidence,
    build_model_execution_artifact,
    build_run_cost_ledger_evidence,
)
from tests.unit.test_client_forensic_reporting import _report

LOGICAL_REQUEST_ID = "scheduler-request-" + "a" * 64


def _usage(*, attempts: int = 1, cost: str = "0.1") -> UsageRecord:
    return UsageRecord(
        request_id=LOGICAL_REQUEST_ID,
        role="source_audit",
        execution_evidence=ExecutionEvidenceKind.MOCK,
        requested_model="synthetic/model",
        returned_model="synthetic/model",
        actual_model="synthetic/model",
        model_family="synthetic",
        timestamp=datetime(2026, 8, 3, 12, 0, tzinfo=UTC),
        accounted_cost_usd=float(Decimal(cost)),
        accounted_cost_usd_exact=cost,
        prompt_sha256="b" * 64,
        status="success",
        attempts=attempts,
    )


def _closed_campaign(
    tmp_path: Path,
) -> tuple[AtomicCostLedger, RunCostLedgerEvidence, UsageRecord]:
    ledger = AtomicCostLedger.initialize(
        tmp_path / "operator-ledger.json",
        cap_usd=Decimal("250"),
    )
    prior = ledger.reserve("prior-global-canary-history", Decimal("0.5"))
    ledger.reconcile(prior, Decimal("0.25"))
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    charged = ledger.reserve(LOGICAL_REQUEST_ID, Decimal("0.4"))
    ledger.reconcile(charged, Decimal("0.1"))
    released = ledger.reserve(f"{LOGICAL_REQUEST_ID}:attempt:2", Decimal("0.3"))
    ledger.release(released, reason=ReleaseReason.FAILED_BEFORE_SEND)
    usage = _usage(attempts=2)
    evidence = build_run_cost_ledger_evidence(
        baseline=baseline,
        final_snapshot=ledger.snapshot(),
        campaign_logical_request_ids=(LOGICAL_REQUEST_ID,),
        usage_records=(usage,),
    )
    return ledger, evidence, usage


def test_run_cost_custody_closes_usage_and_excludes_global_history(tmp_path: Path) -> None:
    ledger, evidence, usage = _closed_campaign(tmp_path)
    report = _report().model_copy(
        update={"usage": [usage], "accounted_cost_usd": usage.accounted_cost_usd}
    )

    artifact = build_model_execution_artifact(report, cost_ledger_evidence=evidence)
    serialized = artifact.model_dump_json()

    assert artifact.schema_version == "1.1"
    assert evidence.run_entry_count == 2
    assert evidence.run_reserved_usd_exact == "0.7"
    assert evidence.run_accounted_cost_usd_exact == "0.1"
    assert evidence.run_released_usd_exact == "0.6"
    assert [attempt.status for attempt in evidence.attempts] == [
        CostEntryStatus.RECONCILED,
        CostEntryStatus.RELEASED,
    ]
    assert evidence.attempts[1].release_reason is ReleaseReason.FAILED_BEFORE_SEND
    assert all(attempt.usage_record_sha256 is not None for attempt in evidence.attempts)
    assert "prior-global-canary-history" not in serialized
    assert str(ledger.path) not in serialized
    assert ledger.identity_sha256 not in serialized
    assert "prompt.json" not in serialized
    assert "RAW-RESPONSE-CANARY" not in serialized


def test_cost_custody_rejects_rehashed_usage_join_tamper(tmp_path: Path) -> None:
    _ledger, evidence, usage = _closed_campaign(tmp_path)
    report = _report().model_copy(
        update={"usage": [usage], "accounted_cost_usd": usage.accounted_cost_usd}
    )
    payload = build_model_execution_artifact(
        report,
        cost_ledger_evidence=evidence,
    ).model_dump(mode="json")
    ledger_payload = payload["cost_ledger"]
    assert isinstance(ledger_payload, dict)
    attempts = ledger_payload["attempts"]
    assert isinstance(attempts, list)
    attempts[0]["usage_record_sha256"] = "f" * 64
    ledger_payload["evidence_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in ledger_payload.items() if key != "evidence_sha256"}
    )

    with pytest.raises(ValidationError, match="emitted usage record"):
        ModelExecutionArtifact.model_validate(payload)


def test_cost_custody_rejects_non_campaign_delta_and_open_reservation(
    tmp_path: Path,
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "ledger.json", cap_usd=Decimal("10"))
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    foreign = ledger.reserve("unrelated-global-request", Decimal("0.2"))
    ledger.reconcile(foreign, Decimal("0.1"))

    with pytest.raises(ValueError, match="non-campaign"):
        build_run_cost_ledger_evidence(
            baseline=baseline,
            final_snapshot=ledger.snapshot(),
            campaign_logical_request_ids=(LOGICAL_REQUEST_ID,),
            usage_records=(),
        )

    second = AtomicCostLedger.initialize(tmp_path / "active.json", cap_usd=Decimal("10"))
    second_baseline = build_scheduler_cost_ledger_baseline(second)
    second.reserve(LOGICAL_REQUEST_ID, Decimal("0.2"))
    with pytest.raises(ValidationError, match="must be terminal"):
        build_run_cost_ledger_evidence(
            baseline=second_baseline,
            final_snapshot=second.snapshot(),
            campaign_logical_request_ids=(LOGICAL_REQUEST_ID,),
            usage_records=(),
        )


def test_current_model_execution_fails_without_nonempty_cost_closure() -> None:
    usage = _usage()
    report = _report().model_copy(
        update={"usage": [usage], "accounted_cost_usd": usage.accounted_cost_usd}
    )

    with pytest.raises(ValueError, match="run-scoped cost-ledger closure"):
        build_model_execution_artifact(report)

    legacy = build_model_execution_artifact(report, legacy_schema_1_0=True)
    assert legacy.schema_version == "1.0"
    assert legacy.cost_ledger is None


def test_zero_usage_absence_never_invents_ledger_snapshots() -> None:
    absent = build_model_execution_artifact(_report())
    unestablished = build_model_execution_artifact(
        _report(),
        persistent_ledger_configured=True,
    )

    assert isinstance(absent.cost_ledger, CostLedgerAbsenceEvidence)
    assert absent.cost_ledger.state == "ABSENT_ZERO"
    assert absent.cost_ledger.status == "NOT_APPLICABLE"
    assert isinstance(unestablished.cost_ledger, CostLedgerAbsenceEvidence)
    assert unestablished.cost_ledger.state == "UNESTABLISHED_ZERO"
    assert unestablished.cost_ledger.status == "INCONCLUSIVE"
    for artifact in (absent, unestablished):
        serialized = json.loads(artifact.model_dump_json())["cost_ledger"]
        assert "baseline_snapshot_sha256" not in serialized
        assert "final_snapshot_sha256" not in serialized


def test_preexisting_reservation_overrun_remains_explicit_in_zero_delta(
    tmp_path: Path,
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "overrun.json", cap_usd=Decimal("10"))
    reservation = ledger.reserve("prior-overrun", Decimal("0.6"))
    with pytest.raises(CostReservationOverrunError):
        ledger.reconcile(reservation, Decimal("0.7"))
    baseline = build_scheduler_cost_ledger_baseline(ledger)

    evidence = build_run_cost_ledger_evidence(
        baseline=baseline,
        final_snapshot=ledger.snapshot(),
        campaign_logical_request_ids=(),
        usage_records=(),
    )

    assert evidence.baseline_has_reservation_overrun
    assert evidence.final_has_reservation_overrun
    assert evidence.run_entry_count == 0


def test_two_charged_attempts_join_one_exact_usage_record(tmp_path: Path) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "retry.json", cap_usd=Decimal("250"))
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    first = ledger.reserve(LOGICAL_REQUEST_ID, Decimal("0.4"))
    ledger.reconcile(first, Decimal("0.1"))
    second = ledger.reserve(f"{LOGICAL_REQUEST_ID}:attempt:2", Decimal("0.5"))
    ledger.reconcile(second, Decimal("0.2"))
    usage = _usage(attempts=2, cost="0.3")

    evidence = build_run_cost_ledger_evidence(
        baseline=baseline,
        final_snapshot=ledger.snapshot(),
        campaign_logical_request_ids=(LOGICAL_REQUEST_ID,),
        usage_records=(usage,),
    )
    artifact = build_model_execution_artifact(
        _report().model_copy(update={"usage": [usage], "accounted_cost_usd": 0.3}),
        cost_ledger_evidence=evidence,
    )

    assert [attempt.attempt_index for attempt in evidence.attempts] == [1, 2]
    assert evidence.run_accounted_cost_usd_exact == "0.3"
    assert len({attempt.usage_record_sha256 for attempt in evidence.attempts}) == 1
    assert artifact.accounted_cost_usd_exact == "0.3"


def test_release_only_attempt_joins_zero_cost_logical_usage(tmp_path: Path) -> None:
    ledger = AtomicCostLedger.initialize(
        tmp_path / "release-only.json",
        cap_usd=Decimal("250"),
    )
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    reservation = ledger.reserve(LOGICAL_REQUEST_ID, Decimal("0.4"))
    ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)
    usage = _usage(cost="0")

    evidence = build_run_cost_ledger_evidence(
        baseline=baseline,
        final_snapshot=ledger.snapshot(),
        campaign_logical_request_ids=(LOGICAL_REQUEST_ID,),
        usage_records=(usage,),
    )
    artifact = build_model_execution_artifact(
        _report().model_copy(update={"usage": [usage]}),
        cost_ledger_evidence=evidence,
    )

    assert evidence.attempts[0].status is CostEntryStatus.RELEASED
    assert evidence.attempts[0].usage_record_sha256 is not None
    assert evidence.run_accounted_cost_usd_exact == "0"
    assert artifact.accounted_cost_usd_exact == "0"


def test_recovered_uncertain_cost_is_retained_without_usage(tmp_path: Path) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "uncertain.json", cap_usd=Decimal("250"))
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    reservation = ledger.reserve(LOGICAL_REQUEST_ID, Decimal("0.4"))
    ledger.reconcile(reservation, None)

    evidence = build_run_cost_ledger_evidence(
        baseline=baseline,
        final_snapshot=ledger.snapshot(),
        campaign_logical_request_ids=(LOGICAL_REQUEST_ID,),
        usage_records=(),
    )
    artifact = build_model_execution_artifact(
        _report().model_copy(update={"accounted_cost_usd": 0.4}),
        cost_ledger_evidence=evidence,
    )

    assert evidence.attempts[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert evidence.attempts[0].usage_record_sha256 is None
    assert evidence.run_accounted_cost_usd_exact == "0.4"
    assert artifact.accounted_cost_usd_exact == "0.4"


def test_baseline_prefix_rejects_changed_or_reordered_final_entries(tmp_path: Path) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "prefix.json", cap_usd=Decimal("10"))
    prior = ledger.reserve("z-prior-global", Decimal("0.4"))
    ledger.reconcile(prior, Decimal("0.2"))
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    current = ledger.reserve(LOGICAL_REQUEST_ID, Decimal("0.3"))
    ledger.reconcile(current, Decimal("0.1"))
    usage = _usage(cost="0.1")
    snapshot = ledger.snapshot()

    interleaved = build_run_cost_ledger_evidence(
        baseline=baseline,
        final_snapshot=snapshot,
        campaign_logical_request_ids=(LOGICAL_REQUEST_ID,),
        usage_records=(usage,),
    )
    assert interleaved.baseline_entry_count == 1
    assert snapshot.entries[0].request_id == LOGICAL_REQUEST_ID

    reordered = replace(snapshot, entries=tuple(reversed(snapshot.entries)))
    with pytest.raises(ValueError, match="canonically ordered"):
        build_run_cost_ledger_evidence(
            baseline=baseline,
            final_snapshot=reordered,
            campaign_logical_request_ids=(LOGICAL_REQUEST_ID,),
            usage_records=(usage,),
        )

    prior_entry = next(entry for entry in snapshot.entries if entry.request_id == "z-prior-global")
    changed_entry = replace(prior_entry, accounted_cost_usd=Decimal("0.21"))
    changed_entries = tuple(
        changed_entry if entry.request_id == changed_entry.request_id else entry
        for entry in snapshot.entries
    )
    changed = replace(snapshot, entries=changed_entries)
    with pytest.raises(ValueError, match="baseline entry changed"):
        build_run_cost_ledger_evidence(
            baseline=baseline,
            final_snapshot=changed,
            campaign_logical_request_ids=(LOGICAL_REQUEST_ID,),
            usage_records=(usage,),
        )
