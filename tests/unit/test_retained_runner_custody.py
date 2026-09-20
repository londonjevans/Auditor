"""Retained ledger authority with isolated runner registration and explicit fake origins.

All semantic/source/child/ledger replay is original code. Only the two REAL-origin
predicates and the runner registry are isolated; no production runner is issued.
"""

from __future__ import annotations

import inspect
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

import mmaudit.models.authenticated_runner as runner
import mmaudit.models.authenticated_runner_ledger as ledger_authority
import mmaudit.orchestration.authenticated_calibration_accounting as accounting
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostReservationOverrunError
from tests.unit import test_authenticated_runner as fixtures
from tests.unit.test_calibration_ledger_accounting import closed_interval
from tests.unit.test_runner_custody_transfer import assert_children_disposed, isolated_function


@dataclass
class RetainedRunnerHarness:
    ledger: AtomicCostLedger
    owner: Any
    registry: Any
    original: Any
    evidence: Any
    live: Any
    require: Any
    retain: Any
    transfer: Any
    revoke: Any


@contextmanager
def build_retained_runner(
    tmp_path: Path,
    *,
    ledger: AtomicCostLedger | None = None,
    owner: Any = None,
    live: Any = None,
) -> Iterator[RetainedRunnerHarness]:
    """Construct only isolated registration; optionally use an already-owned test ledger."""

    live = fixtures.live_inputs.__wrapped__() if live is None else live
    ledger = ledger or AtomicCostLedger.initialize(
        tmp_path / "synthetic.json", cap_usd=Decimal("250")
    )
    owns_accounting = owner is None
    owner = accounting.begin_calibration_ledger_accounting(ledger) if owner is None else owner
    opened = runner.begin_cross_lineage_ledger_interval(ledger)
    request_ids = []
    for usage in fixtures._usage_records(live.runs):
        cost = Decimal(usage.accounted_cost_usd_exact)
        reservation = ledger.reserve(usage.request_id, cost)
        ledger.reconcile(reservation, cost)
        request_ids.append(usage.request_id)
    interval = runner.close_cross_lineage_ledger_interval(opened, expected_request_ids=request_ids)
    registry = runner._PidLocalOneWayLeaseRegistry(
        capability_type=runner.VerifiedCrossLineageRunnerCustody, getpid=os.getpid
    )
    build = inspect.getclosurevars(runner.issue_verified_cross_lineage_runner_custody).nonlocals[
        "build_evidence"
    ]
    replay = inspect.getclosurevars(build).nonlocals["replay_run"]
    attestation = inspect.getclosurevars(replay).nonlocals["require_generation_attestation"]

    def synthetic_origin(*_args: Any, **_kwargs: Any) -> None:
        """Explicit test stand-in; no production callable or origin registry is changed."""

    replay = isolated_function(
        replay,
        require_usage_origin=synthetic_origin,
        require_generation_attestation=isolated_function(
            attestation, require_generation_origin=synthetic_origin
        ),
    )
    build = isolated_function(build, replay_run=replay)
    issue = isolated_function(
        runner.issue_verified_cross_lineage_runner_custody, registry=registry, build_evidence=build
    )
    original, evidence = issue(
        public_lineage_capability=live.public_lineage,
        ground_truth_capability=live.ground_truth,
        benchmark_suite=live.suite,
        runs=live.runs,
        closed_ledger_interval=interval,
    )
    require = isolated_function(
        runner.require_verified_cross_lineage_runner_custody,
        registry=registry,
        build_evidence=build,
    )
    transfer = isolated_function(
        runner.transfer_verified_cross_lineage_runner_custody, registry=registry, require=require
    )
    retain = isolated_function(
        runner.retain_verified_cross_lineage_runner_custody,
        registry=registry,
        require=require,
        transfer=transfer,
    )
    revoke = isolated_function(
        runner.revoke_verified_cross_lineage_runner_custody, registry=registry
    )
    try:
        yield RetainedRunnerHarness(
            ledger, owner, registry, original, evidence, live, require, retain, transfer, revoke
        )
    finally:
        # Test-only disposal of isolated registrations, even after a failed assertion.
        for entry in tuple(registry._entries.values()):
            capability = entry[0]()
            if capability is not None:
                revoke(capability)
        try:
            accounting.observe_calibration_ledger_accounting(owner)
        except ValueError as exc:
            assert "absent or revoked" in str(exc)
        else:
            if owns_accounting:
                accounting.close_calibration_ledger_accounting(owner)


@pytest.fixture
def retained_runner(tmp_path: Path) -> Iterator[RetainedRunnerHarness]:
    with build_retained_runner(tmp_path) as subject:
        yield subject


def retain(subject: RetainedRunnerHarness) -> tuple[Any, Any]:
    return subject.retain(subject.original, evidence=subject.evidence, accounting=subject.owner)


def assert_original_absent(subject: RetainedRunnerHarness) -> None:
    with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
        subject.require(subject.original, evidence=subject.evidence)


def test_retained_original_semantics_survive_accounted_sequential_intervals(
    retained_runner: RetainedRunnerHarness,
) -> None:
    subject = retained_runner
    expected = subject.require(subject.original, evidence=subject.evidence)
    original_state = subject.registry.snapshot(subject.original).state
    successor, runs = retain(subject)
    state = subject.registry.snapshot(successor).state
    assert_original_absent(subject)
    assert runs is state.runs
    assert subject.require(successor, evidence=subject.evidence) == expected
    assert_children_disposed(original_state)
    assert state.retained_ledger_view.capability is original_state.closed_ledger_interval
    assert state.retained_ledger_view.ledger is subject.ledger

    for index in range(2):
        later = closed_interval(subject.ledger, f"synthetic-next-{index}")
        with pytest.raises(ValueError, match="ledger changed after closure"):
            runner._require_closed_cross_lineage_ledger_interval(state.closed_ledger_interval)
        with pytest.raises(ValueError, match="unassigned or unsafe work"):
            subject.require(successor, evidence=subject.evidence)
        accounting.retain_calibration_ledger_interval(subject.owner, interval=later)
        raw = subject.ledger.path.read_bytes()
        assert subject.require(successor, evidence=subject.evidence) == expected
        assert subject.ledger.path.read_bytes() == raw
    observed = accounting.require_calibration_accounting_ready(subject.owner)
    assert observed.retained_interval_count == 3
    assert state.evidence is subject.evidence
    assert not state.evidence.runner_custody_authorized


@pytest.mark.parametrize("kind", ("revoked-owner", "unknown", "reserved", "overrun", "ceiling"))
def test_retained_security_proof_never_ignores_current_cost_liabilities(
    retained_runner: RetainedRunnerHarness, kind: str
) -> None:
    subject = retained_runner
    successor, _runs = retain(subject)
    if kind == "revoked-owner":
        accounting.close_calibration_ledger_accounting(subject.owner)
    else:
        amount = (
            Decimal("250") - subject.ledger.snapshot().spent_usd
            if kind == "ceiling"
            else Decimal("1")
        )
        reservation = subject.ledger.reserve("synthetic-unsafe-later", amount)
        if kind == "unknown":
            subject.ledger.commit_for_transport(reservation)
            subject.ledger.reconcile(reservation, None)
        elif kind == "overrun":
            with pytest.raises(CostReservationOverrunError):
                subject.ledger.reconcile(reservation, Decimal("2"))
        elif kind == "ceiling":
            subject.ledger.reconcile(reservation, amount)
    raw = subject.ledger.path.read_bytes()
    with pytest.raises(ValueError, match="retained runner ledger custody is unavailable"):
        subject.require(successor, evidence=subject.evidence)
    subject.revoke(successor)
    assert subject.ledger.path.read_bytes() == raw


def test_later_retention_does_not_stop_original_security_input_replay(
    retained_runner: RetainedRunnerHarness,
) -> None:
    subject = retained_runner
    successor, runs = retain(subject)
    later = closed_interval(subject.ledger, "synthetic-later")
    accounting.retain_calibration_ledger_interval(subject.owner, interval=later)
    assert subject.require(successor, evidence=subject.evidence)
    report = runs[0].candidate_report
    original_hash = report.report_sha256
    try:
        object.__setattr__(report, "report_sha256", "f" * 64)
        with pytest.raises(ValueError, match="structurally invalid"):
            subject.require(successor, evidence=subject.evidence)
    finally:
        object.__setattr__(report, "report_sha256", original_hash)


@pytest.mark.parametrize("field", ("retained_ledger_prefix", "retained_ledger_view"))
def test_partial_or_caller_reconstructed_retention_never_replaces_custody(
    retained_runner: RetainedRunnerHarness, field: str
) -> None:
    subject = retained_runner
    successor, _runs = retain(subject)
    original = subject.registry.snapshot(successor)
    altered = replace(original.state, **{field: None})
    subject.registry.replace_state(successor, original, altered)
    with pytest.raises(ValueError, match="custody is incomplete"):
        subject.require(successor, evidence=subject.evidence)


def test_ledger_view_from_a_different_interval_cannot_be_substituted(
    retained_runner: RetainedRunnerHarness,
) -> None:
    subject = retained_runner
    successor, _runs = retain(subject)
    later = closed_interval(subject.ledger, "synthetic-later")
    view = runner._require_closed_cross_lineage_ledger_interval(later)
    accounting.retain_calibration_ledger_interval(subject.owner, interval=later)
    lease = subject.registry.snapshot(successor)
    subject.registry.replace_state(
        successor, lease, replace(lease.state, retained_ledger_view=view)
    )
    with pytest.raises(ValueError, match="differs from its original closed ledger"):
        subject.require(successor, evidence=subject.evidence)


def test_retention_cannot_be_rebound_to_a_later_prefix(
    retained_runner: RetainedRunnerHarness,
) -> None:
    subject = retained_runner
    successor, _runs = retain(subject)
    with pytest.raises(ValueError, match="already retained"):
        subject.retain(successor, evidence=subject.evidence, accounting=subject.owner)
    moved, _runs = subject.transfer(successor, evidence=subject.evidence)
    assert subject.require(moved, evidence=subject.evidence)
    assert subject.registry.snapshot(moved).state.retained_ledger_prefix is not None


def test_wrong_accounting_owner_refuses_before_consuming_source(
    retained_runner: RetainedRunnerHarness, tmp_path: Path
) -> None:
    subject = retained_runner
    other = AtomicCostLedger.initialize(tmp_path / "other.json", cap_usd=Decimal("250"))
    with (
        accounting.calibration_ledger_accounting_scope(other) as owner,
        pytest.raises(ValueError, match="overlaps or skips"),
    ):
        subject.retain(subject.original, evidence=subject.evidence, accounting=owner)
    assert subject.require(subject.original, evidence=subject.evidence)
    assert (
        accounting.observe_calibration_ledger_accounting(subject.owner).retained_interval_count == 0
    )


@pytest.mark.parametrize("kind", (ValueError, RuntimeError, KeyboardInterrupt))
def test_failure_after_prefix_binding_disposes_successor_but_preserves_cost_history(
    retained_runner: RetainedRunnerHarness, kind: type[BaseException]
) -> None:
    subject = retained_runner
    states: list[Any] = []

    def require(capability: Any, **kwargs: Any) -> Any:
        value = subject.require(capability, **kwargs)
        state = subject.registry.snapshot(capability).state
        if state.retained_ledger_prefix is not None:
            states.append(state)
            raise kind("synthetic retained replay refusal")
        return value

    operation = isolated_function(subject.retain, require=require)
    raw = subject.ledger.path.read_bytes()
    with pytest.raises(kind, match="retained replay refusal"):
        operation(subject.original, evidence=subject.evidence, accounting=subject.owner)
    assert_original_absent(subject)
    assert subject.registry._entries == {}
    assert_children_disposed(states[0])
    assert subject.ledger.path.read_bytes() == raw
    assert (
        accounting.require_calibration_accounting_ready(subject.owner).retained_interval_count == 1
    )


def test_accounting_owner_is_rechecked_after_security_replay(
    retained_runner: RetainedRunnerHarness,
) -> None:
    subject = retained_runner
    successor, _runs = retain(subject)
    build = inspect.getclosurevars(subject.require).nonlocals["build_evidence"]

    def revoke_after_replay(**kwargs: Any) -> Any:
        evidence = build(**kwargs)
        accounting.close_calibration_ledger_accounting(subject.owner)
        return evidence

    require = isolated_function(subject.require, build_evidence=revoke_after_replay)
    with pytest.raises(ValueError, match="custody is unavailable"):
        require(successor, evidence=subject.evidence)


@pytest.mark.parametrize("attribute", ("__defaults__", "__kwdefaults__"))
def test_retained_prefix_verifier_callable_drift_is_refused(
    retained_runner: RetainedRunnerHarness, monkeypatch: pytest.MonkeyPatch, attribute: str
) -> None:
    subject = retained_runner
    successor, _runs = retain(subject)
    value = ("synthetic",) if attribute == "__defaults__" else {"synthetic": True}
    with monkeypatch.context() as patch:
        patch.setattr(accounting.require_calibration_ledger_prefix, attribute, value)
        with pytest.raises(ValueError, match="runtime is not pristine"):
            subject.require(successor, evidence=subject.evidence)


def test_original_ledger_exports_share_one_exact_authority() -> None:
    for name in (
        "AuthenticatedCrossLineageRunnerError",
        "AuthenticatedCrossLineageLedgerIntervalEvidence",
        "ClosedCrossLineageLedgerInterval",
        "OpenCrossLineageLedgerInterval",
        "begin_cross_lineage_ledger_interval",
        "close_cross_lineage_ledger_interval",
        "_require_closed_cross_lineage_ledger_interval",
    ):
        assert getattr(runner, name) is getattr(ledger_authority, name)


def test_atomic_state_replacement_invalidates_inflight_lease_and_cannot_revive_revoked() -> None:
    registry = runner._PidLocalOneWayLeaseRegistry(
        capability_type=fixtures._LeaseCapability, getpid=os.getpid
    )
    capability = fixtures._LeaseCapability()
    registry.register(capability, "original")
    first = registry.snapshot(capability)
    second = registry.replace_state(capability, first, "retained")
    assert second.state == "retained" and first.nonce is not second.nonce
    with pytest.raises(ValueError, match="changed or was revoked"):
        registry.recheck(capability, first)
    with pytest.raises(ValueError, match="changed or was revoked"):
        registry.replace_state(capability, first, "stale")
    registry.revoke(capability)
    with pytest.raises(ValueError, match="changed or was revoked"):
        registry.replace_state(capability, second, "revived")
