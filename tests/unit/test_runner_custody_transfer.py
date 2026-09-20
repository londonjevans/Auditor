"""Coordinated moves in an isolated registry, never positive REAL-runner authority."""

from __future__ import annotations

import inspect
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, fields
from pathlib import Path
from types import CellType, FunctionType
from typing import Any

import pytest

import mmaudit.models.authenticated_runner as runner
from mmaudit.models.generation_evidence import TrustedGenerationVerification
from tests.unit import test_authenticated_runner as fixtures
from tests.unit import test_authenticated_runner_durable_bundle as durable


def isolated_function(function: Any, **bindings: Any) -> Any:
    """Clone code with explicit test-only dependencies; never modify production cells."""

    original = inspect.getclosurevars(function).nonlocals
    assert set(bindings) <= set(original)
    values = {**original, **bindings}
    cloned = FunctionType(
        function.__code__,
        function.__globals__,
        function.__name__,
        function.__defaults__,
        tuple(CellType(values[name]) for name in function.__code__.co_freevars),
    )
    cloned.__kwdefaults__ = function.__kwdefaults__
    return cloned


@dataclass
class IsolatedRunner:
    live: Any
    ledger: Any
    registry: Any
    original: Any
    evidence: Any
    state: Any
    transfer: Any
    require: Any
    revoke: Any
    events: list[Any]


def require_children(runs: Any) -> None:
    request_builder = inspect.getclosurevars(
        runner.transfer_verified_cross_lineage_runner_custody
    ).nonlocals["generation_transfer_requests"]
    for run in runs:
        run.candidate_campaign_verification.require_for(
            portfolio_sha256=run.candidate_portfolio.portfolio_sha256,
            reports=run.candidate_campaign_reports,
            policy_sha256=run.candidate_campaign_policy_sha256,
            effective_config_sha256=run.candidate_campaign_effective_config_sha256,
        )
        for candidate, capability in (
            (True, run.candidate_generation_verification),
            (False, run.judge_generation_verification),
        ):
            for request in request_builder(run, candidate=candidate):
                capability.attestation_for(
                    **{field.name: getattr(request, field.name) for field in fields(request)}
                )


@pytest.fixture
def isolated_runner(tmp_path: Path) -> IsolatedRunner:
    live = fixtures.live_inputs.__wrapped__()
    ledger, interval = fixtures._closed_runner_interval(tmp_path / "synthetic.json", live.runs)
    evidence = durable._runner_evidence(live)
    state_type = inspect.getclosurevars(
        runner.issue_verified_cross_lineage_runner_custody
    ).nonlocals["RunnerState"]
    state = state_type(
        process_id=os.getpid(),
        run_count=len(live.runs),
        public_lineage_capability=live.public_lineage,
        ground_truth_capability=live.ground_truth,
        benchmark_suite=live.suite,
        runs=live.runs,
        campaign_capabilities=tuple(run.candidate_campaign_verification for run in live.runs),
        generation_capabilities=tuple(
            capability
            for run in live.runs
            for capability in (
                run.candidate_generation_verification,
                run.judge_generation_verification,
            )
        ),
        closed_ledger_interval=interval,
        evidence=evidence,
    )
    registry = runner._PidLocalOneWayLeaseRegistry(
        capability_type=runner.VerifiedCrossLineageRunnerCustody, getpid=os.getpid
    )
    original = object.__new__(runner.VerifiedCrossLineageRunnerCustody)
    registry.register(original, state)
    events: list[Any] = []
    projection = object()

    def require(capability: Any, *, evidence: Any) -> Any:
        # This explicitly replaces REAL-source replay in the cloned transaction.
        # Child proofs and the exact local ledger verifier below are production.
        lease = registry.snapshot(capability)
        assert evidence is state.evidence
        require_children(lease.state.runs)
        runner._require_closed_cross_lineage_ledger_interval(lease.state.closed_ledger_interval)
        registry.recheck(capability, lease)
        events.append(capability)
        return projection

    return IsolatedRunner(
        live,
        ledger,
        registry,
        original,
        evidence,
        state,
        isolated_function(
            runner.transfer_verified_cross_lineage_runner_custody,
            registry=registry,
            require=require,
        ),
        require,
        isolated_function(runner.revoke_verified_cross_lineage_runner_custody, registry=registry),
        events,
    )


def assert_source_consumed(subject: IsolatedRunner) -> None:
    with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
        subject.registry.snapshot(subject.original)


def assert_children_disposed(state: Any) -> None:
    for run in state.runs:
        with pytest.raises(ValueError):
            run.candidate_campaign_verification.require_for(
                portfolio_sha256=run.candidate_portfolio.portfolio_sha256,
                reports=run.candidate_campaign_reports,
                policy_sha256=run.candidate_campaign_policy_sha256,
                effective_config_sha256=run.candidate_campaign_effective_config_sha256,
            )
    for capability in state.generation_capabilities:
        with pytest.raises(ValueError, match="generation verification capability is not trusted"):
            # Snapshot checks registry identity without manufacturing an attestation.
            from mmaudit.models.generation_evidence import _snapshot_trusted_generation_capability

            _snapshot_trusted_generation_capability(capability)


def test_isolated_transaction_moves_every_child_and_preserves_all_other_state(
    isolated_runner: IsolatedRunner,
) -> None:
    subject = isolated_runner
    raw = subject.ledger.path.read_bytes()
    successor, runs = subject.transfer(subject.original, evidence=subject.evidence)
    assert successor is not subject.original
    assert_source_consumed(subject)
    moved = subject.registry.snapshot(successor).state
    assert moved.runs is runs
    for field in fields(subject.state):
        if field.name not in {"runs", "campaign_capabilities", "generation_capabilities"}:
            assert getattr(moved, field.name) is getattr(subject.state, field.name)
    for original, current in zip(subject.state.runs, runs, strict=True):
        for field in fields(original):
            before, after = getattr(original, field.name), getattr(current, field.name)
            if field.name.endswith("_verification"):
                assert before is not after
            else:
                assert before is after
    assert subject.events == [subject.original, successor]
    assert subject.require(successor, evidence=subject.evidence)
    assert_children_disposed(subject.state)
    assert subject.ledger.path.read_bytes() == raw
    subject.revoke(successor)
    assert_children_disposed(moved)
    with pytest.raises(ValueError, match="revoked"):
        subject.require(successor, evidence=subject.evidence)


def test_original_native_verifier_and_transfer_reject_isolated_registration(
    isolated_runner: IsolatedRunner,
) -> None:
    subject = isolated_runner
    for function in (
        runner.require_verified_cross_lineage_runner_custody,
        runner.transfer_verified_cross_lineage_runner_custody,
    ):
        with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
            function(subject.original, evidence=subject.evidence)
    require_children(subject.state.runs)


@pytest.mark.parametrize("kind", (ValueError, RuntimeError, KeyboardInterrupt))
def test_failure_before_consumption_preserves_original_and_every_child(
    isolated_runner: IsolatedRunner, kind: type[BaseException]
) -> None:
    subject = isolated_runner

    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise kind("synthetic source replay refusal")

    move = isolated_function(subject.transfer, require=refuse)
    with pytest.raises(kind, match="source replay refusal"):
        move(subject.original, evidence=subject.evidence)
    assert subject.require(subject.original, evidence=subject.evidence)


@pytest.mark.parametrize("failure_index", range(6))
def test_failure_at_any_child_move_disposes_moved_and_unmoved_inventory(
    isolated_runner: IsolatedRunner, failure_index: int
) -> None:
    subject = isolated_runner
    bindings = inspect.getclosurevars(subject.transfer).nonlocals
    calls: list[Any] = []
    moved: list[Any] = []

    def wrapped(function: Any) -> Any:
        def call(capability: Any, **kwargs: Any) -> Any:
            index = len(calls)
            calls.append(capability)
            if index == failure_index:
                raise RuntimeError("synthetic child move failure")
            result = function(capability, **kwargs)
            moved.append(result)
            return result

        return call

    move = isolated_function(
        subject.transfer,
        transfer_campaign=wrapped(bindings["transfer_campaign"]),
        transfer_generation=wrapped(bindings["transfer_generation"]),
    )
    with pytest.raises(RuntimeError, match="child move failure"):
        move(subject.original, evidence=subject.evidence)
    assert_source_consumed(subject)
    assert_children_disposed(subject.state)
    assert subject.registry._entries == {}
    for capability in moved:
        if type(capability) is TrustedGenerationVerification:
            from mmaudit.models.generation_evidence import _snapshot_trusted_generation_capability

            with pytest.raises(ValueError):
                _snapshot_trusted_generation_capability(capability)
        else:
            # A moved campaign is consumed by the captured inventory revoker.
            from mmaudit.benchmark.model_portfolio import (
                revoke_trusted_candidate_benchmark_campaign_verification,
            )

            with pytest.raises(ValueError):
                revoke_trusted_candidate_benchmark_campaign_verification(capability)


@pytest.mark.parametrize("kind", (ValueError, RuntimeError, KeyboardInterrupt))
def test_successor_replay_failure_never_revives_parent_or_children(
    isolated_runner: IsolatedRunner, kind: type[BaseException]
) -> None:
    subject = isolated_runner
    moved: list[Any] = []

    def require(capability: Any, **kwargs: Any) -> Any:
        result = subject.require(capability, **kwargs)
        if capability is not subject.original:
            moved.append(subject.registry.snapshot(capability).state)
            raise kind("synthetic successor replay refusal")
        return result

    move = isolated_function(subject.transfer, require=require)
    with pytest.raises(kind, match="successor replay refusal"):
        move(subject.original, evidence=subject.evidence)
    assert_source_consumed(subject)
    assert subject.registry._entries == {}
    assert_children_disposed(moved[0])


def test_registration_failure_after_insertion_cannot_leave_a_live_successor(
    isolated_runner: IsolatedRunner,
) -> None:
    subject = isolated_runner
    retained: list[Any] = []

    def register(registry: Any, capability: Any, state: Any) -> None:
        retained.append((capability, state))
        registry.register(capability, state)
        raise RuntimeError("synthetic post-registration failure")

    move = isolated_function(subject.transfer, trusted_lease_register=register)
    with pytest.raises(RuntimeError, match="post-registration failure"):
        move(subject.original, evidence=subject.evidence)
    assert_source_consumed(subject)
    assert subject.registry._entries == {}
    assert_children_disposed(retained[0][1])


def test_competing_transactions_have_at_most_one_successor(isolated_runner: IsolatedRunner) -> None:
    subject = isolated_runner
    barrier = threading.Barrier(2)

    def require(capability: Any, **kwargs: Any) -> Any:
        result = subject.require(capability, **kwargs)
        if capability is subject.original:
            barrier.wait(timeout=10)
        return result

    move = isolated_function(subject.transfer, require=require)

    def attempt() -> Any:
        try:
            return move(subject.original, evidence=subject.evidence)
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(attempt) for _ in range(2)]
        results = [future.result(timeout=30) for future in futures]
    successful = [result for result in results if result is not None]
    assert len(successful) == 1
    successor, _runs = successful[0]
    assert_source_consumed(subject)
    subject.require(successor, evidence=subject.evidence)
    subject.revoke(successor)


@pytest.mark.parametrize(
    "binding",
    (
        "replace",
        "GenerationVerificationRequest",
        "transfer_trusted_generation_verification",
        "transfer_trusted_candidate_benchmark_campaign_verification",
    ),
)
def test_production_binding_retarget_refuses_before_source_consumption(
    isolated_runner: IsolatedRunner, monkeypatch: pytest.MonkeyPatch, binding: str
) -> None:
    subject = isolated_runner
    with monkeypatch.context() as patch:
        patch.setattr(runner, binding, object())
        with pytest.raises(ValueError, match="runtime is not pristine"):
            subject.transfer(subject.original, evidence=subject.evidence)
    assert subject.require(subject.original, evidence=subject.evidence)


@pytest.mark.parametrize("attribute", ("__defaults__", "__kwdefaults__"))
def test_child_callable_state_drift_refuses_before_consumption(
    isolated_runner: IsolatedRunner, monkeypatch: pytest.MonkeyPatch, attribute: str
) -> None:
    subject = isolated_runner
    value = ("synthetic",) if attribute == "__defaults__" else {"synthetic": True}
    with monkeypatch.context() as patch:
        patch.setattr(runner.transfer_trusted_generation_verification, attribute, value)
        with pytest.raises(ValueError, match="runtime is not pristine"):
            subject.transfer(subject.original, evidence=subject.evidence)
    assert subject.require(subject.original, evidence=subject.evidence)


def test_successor_can_move_again_but_old_aliases_stay_consumed(
    isolated_runner: IsolatedRunner,
) -> None:
    subject = isolated_runner
    first, _runs = subject.transfer(subject.original, evidence=subject.evidence)
    second, _runs = subject.transfer(first, evidence=subject.evidence)
    for old in (subject.original, first):
        with pytest.raises(ValueError, match="revoked"):
            subject.transfer(old, evidence=subject.evidence)
    assert subject.require(second, evidence=subject.evidence)
    subject.revoke(second)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires a POSIX process boundary")
def test_actual_child_process_cannot_transfer_parent_custody(
    isolated_runner: IsolatedRunner,
) -> None:
    subject = isolated_runner
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            try:
                subject.transfer(subject.original, evidence=subject.evidence)
            except ValueError as exc:
                os.write(write_fd, b"refused" if "not pristine" in str(exc) else b"wrong refusal")
            else:
                os.write(write_fd, b"unexpected success")
        finally:
            os.close(write_fd)
            os._exit(0)
    os.close(write_fd)
    try:
        observed = os.read(read_fd, 64)
    finally:
        os.close(read_fd)
    waited, status = os.waitpid(pid, 0)
    assert waited == pid and os.waitstatus_to_exitcode(status) == 0
    assert observed == b"refused"
    assert subject.require(subject.original, evidence=subject.evidence)
