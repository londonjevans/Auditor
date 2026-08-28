from __future__ import annotations

import asyncio
import copy
import os
import pickle
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from decimal import Decimal
from pathlib import Path
from typing import cast

import pytest

import mmaudit.benchmark.cross_lineage_adjudication as adjudication_module
import mmaudit.models.authenticated_runner as authenticated_runner_module
import mmaudit.models.generation_evidence as generation_evidence_module
import mmaudit.models.openrouter as openrouter_module
import mmaudit.orchestration.cost_ledger as cost_ledger_module
from mmaudit.benchmark.cross_lineage_adjudication import (
    CrossLineageAdjudicationDisposition,
    CrossLineageAdjudicationPreparedRun,
    CrossLineageAdjudicationReport,
    CrossLineageAdjudicationRunKind,
    adjudication_generation_verification_requests,
    build_cross_lineage_adjudication_case_result,
    build_cross_lineage_adjudication_report,
    build_cross_lineage_adjudication_response,
    prepare_cross_lineage_adjudication,
)
from mmaudit.benchmark.models import (
    ModelBenchmarkReport,
    ModelBenchmarkSuite,
    ModelBenchmarkTarget,
    load_model_benchmark_corpus,
)
from mmaudit.models.authenticated_runner import (
    AuthenticatedCrossLineageRunnerError,
    AuthenticatedCrossLineageRunnerEvidence,
    ClosedCrossLineageLedgerInterval,
    CrossLineageRunnerRunCustody,
    OpenCrossLineageLedgerInterval,
    VerifiedCrossLineageRunnerCustody,
    _PidLocalOneWayLeaseRegistry,
    _revoke_runner_child_capability_inventory,
    begin_cross_lineage_ledger_interval,
    close_cross_lineage_ledger_interval,
    issue_verified_cross_lineage_runner_custody,
    revoke_verified_cross_lineage_runner_custody,
)
from mmaudit.models.generation_evidence import (
    GenerationEvidenceValidationError,
    TrustedGenerationVerification,
    _attest_authrunner_generation_origin,
    _has_authrunner_generation_origin,
)
from mmaudit.models.ground_truth_authority import (
    VerifiedFrozenGroundTruth,
    load_frozen_ground_truth_provenance,
    resolve_verified_frozen_ground_truth,
)
from mmaudit.models.public_lineage_authority import (
    VerifiedPublicModelLineage,
    resolve_verified_public_model_lineage,
)
from mmaudit.models.qualification import CandidateModel, QualificationPolicy
from mmaudit.models.qualification_workflow import candidate_generation_verification_requests
from mmaudit.models.schemas import UsageRecord
from mmaudit.models.usage import (
    _attest_authrunner_owned_real_usage_origin,
    _authrunner_usage_origin_process_is_current,
    _has_authrunner_owned_real_usage_origin,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.manifest import canonical_sha256
from tests.identity_fixtures import bind_synthetic_usage_identity, rebind_synthetic_token_plan
from tests.unit import test_model_benchmark as benchmark_fixtures
from tests.unit import test_qualification_workflow as qualification_fixtures
from tests.unit.test_cross_lineage_adjudication import _judge_usage_and_generation
from tests.unit.test_model_benchmark_portfolio import _candidate_registry

ROOT = Path(__file__).resolve().parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
PROVENANCE_PATH = ROOT / "benchmarks" / "model_corpus" / "provenance.json"
CANDIDATE_ID = "deepseek/deepseek-v3.2-exp"
PRIMARY_JUDGE_ID = "google/gemma-4-26b-a4b-it"
REPLAY_JUDGE_ID = "meta-llama/llama-4-maverick"


@dataclass(frozen=True, slots=True)
class _LiveInputs:
    suite: ModelBenchmarkSuite
    public_lineage: VerifiedPublicModelLineage
    ground_truth: VerifiedFrozenGroundTruth
    runs: tuple[CrossLineageRunnerRunCustody, ...]


class _LeaseCapability:
    """Non-authorizing token used only to assay the shared lease primitive."""

    __slots__ = ("__weakref__",)


@dataclass(frozen=True, slots=True)
class _LeaseState:
    marker: str


def _reseal_report(payload: dict[str, object]) -> ModelBenchmarkReport:
    payload["report_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "report_sha256"}
    )
    return ModelBenchmarkReport.model_validate(payload)


def _candidate_reports(candidate: CandidateModel) -> tuple[ModelBenchmarkReport, ...]:
    primary = qualification_fixtures._as_real_report(
        asyncio.run(
            qualification_fixtures._mock_report(target=ModelBenchmarkTarget(model_id=CANDIDATE_ID))
        ),
        candidate=candidate,
    )
    replay = qualification_fixtures._as_real_report(
        asyncio.run(
            qualification_fixtures._mock_report(
                target=ModelBenchmarkTarget(
                    model_id=CANDIDATE_ID,
                    request_role="model_benchmark:falsifier:verifier",
                )
            )
        ),
        candidate=candidate,
    )
    payload = replay.model_dump(mode="json")
    result = payload["results"][0]
    result["target"]["request_role"] = "model_benchmark"
    for case in result["cases"]:
        usage_payload = dict(case["usage_record"])
        usage_payload["role"] = "model_benchmark"
        routing = dict(usage_payload["routing"])
        for key in (
            "request_token_plan",
            "request_token_plan_sha256",
            "atomic_token_reservation",
            "atomic_token_reservation_sha256",
            "atomic_token_reservations",
            "atomic_token_reservation_sha256s",
        ):
            routing.pop(key, None)
        usage_payload["routing"] = routing
        usage = bind_synthetic_usage_identity(
            rebind_synthetic_token_plan(UsageRecord.model_validate(usage_payload))
        )
        case["usage_record"] = usage.model_dump(mode="json")
        case["generation_evidence"] = benchmark_fixtures._forged_real_generation_evidence(
            usage
        ).model_dump(mode="json")
    return primary, _reseal_report(payload)


def _judge(model_id: str, *, index: int) -> CandidateModel:
    payload = _candidate_registry((model_id,)).candidates[0].model_dump(mode="json")
    payload.update(
        {
            "approved_provider_endpoint": f"provider-judge-{index}",
            "approved_provider_name": f"Synthetic Judge {index}",
            "discovery_evidence_sha256": f"{5 + index}" * 64,
        }
    )
    return CandidateModel.model_validate(payload)


def _adjudication_report(
    *,
    public_lineage: VerifiedPublicModelLineage,
    suite: ModelBenchmarkSuite,
    candidate_report: ModelBenchmarkReport,
    judge: CandidateModel,
    run_kind: CrossLineageAdjudicationRunKind,
    request_offset: int,
) -> tuple[CrossLineageAdjudicationPreparedRun, CrossLineageAdjudicationReport]:
    prepared = prepare_cross_lineage_adjudication(
        public_lineage_capability=public_lineage,
        suite=suite,
        candidate_report=candidate_report,
        judge=judge,
        run_kind=run_kind,
    )
    results = []
    for index, request in enumerate(prepared.requests):
        response = build_cross_lineage_adjudication_response(
            request=request,
            dimension_outcomes=request.expected_dimension_outcomes,
            disposition=CrossLineageAdjudicationDisposition.CONFIRMED,
            rationale="Synthetic independent adjudication agrees with frozen expectations.",
        )
        usage, generation = _judge_usage_and_generation(
            case_index=request_offset + index,
            request=request,
            response=response,
            judge=judge,
        )
        results.append(
            build_cross_lineage_adjudication_case_result(
                request=request,
                response=response,
                usage_record=usage,
                generation_evidence=generation,
            )
        )
    return prepared, build_cross_lineage_adjudication_report(prepared=prepared, results=results)


def _judge_generation_capability(
    report: CrossLineageAdjudicationReport,
    judge: CandidateModel,
) -> TrustedGenerationVerification:
    attestations = tuple(case.generation_evidence for case in report.cases)
    return generation_evidence_module._issue_trusted_generation_verification(
        requests=adjudication_generation_verification_requests(report=report, judge=judge),
        attestations=attestations,
        verification_started_at=min(item.retrieved_at for item in attestations),
    )


@pytest.fixture(scope="module")
def live_inputs() -> _LiveInputs:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    public_lineage = resolve_verified_public_model_lineage()
    ground_truth = resolve_verified_frozen_ground_truth(
        provenance=load_frozen_ground_truth_provenance(PROVENANCE_PATH),
        benchmark_suite=suite,
    )
    registry = _candidate_registry((CANDIDATE_ID,))
    candidate = registry.candidates[0]
    reports = _candidate_reports(candidate)
    policy = cast(Callable[[], QualificationPolicy], qualification_fixtures._policy)()
    judges = (
        _judge(PRIMARY_JUDGE_ID, index=1),
        _judge(REPLAY_JUDGE_ID, index=2),
    )
    kinds = (
        CrossLineageAdjudicationRunKind.PRIMARY,
        CrossLineageAdjudicationRunKind.REPLAY,
    )
    runs = []
    for index, (report, judge, run_kind) in enumerate(zip(reports, judges, kinds, strict=True)):
        portfolio, campaign = qualification_fixtures._portfolio_evidence(
            registry=registry,
            report=report,
            policy=policy,
        )
        prepared, adjudication = _adjudication_report(
            public_lineage=public_lineage,
            suite=suite,
            candidate_report=report,
            judge=judge,
            run_kind=run_kind,
            request_offset=index * 1_000,
        )
        runs.append(
            CrossLineageRunnerRunCustody(
                run_kind=run_kind,
                candidate_report=report,
                candidate_campaign_verification=campaign,
                candidate_portfolio=portfolio,
                candidate_campaign_reports=(report,),
                candidate_campaign_policy_sha256=policy.policy_sha256,
                candidate_campaign_effective_config_sha256="3" * 64,
                candidate_generation_verification=(
                    qualification_fixtures._trusted_generation_authority(
                        registry=registry,
                        primary=report,
                    )
                ),
                judge=judge,
                prepared_adjudication=prepared,
                adjudication_report=adjudication,
                judge_generation_verification=_judge_generation_capability(
                    adjudication,
                    judge,
                ),
            )
        )
    return _LiveInputs(
        suite=suite,
        public_lineage=public_lineage,
        ground_truth=ground_truth,
        runs=tuple(runs),
    )


def _usage_records(runs: tuple[CrossLineageRunnerRunCustody, ...]) -> tuple[UsageRecord, ...]:
    records: list[UsageRecord] = []
    for run in runs:
        records.extend(
            case.usage_record
            for case in run.candidate_report.results[0].cases
            if case.usage_record is not None
        )
        records.extend(case.usage_record for case in run.adjudication_report.cases)
    return tuple(records)


def _closed_runner_interval(
    path: Path,
    runs: tuple[CrossLineageRunnerRunCustody, ...],
    *,
    actual_cost: Decimal | None = None,
) -> tuple[AtomicCostLedger, ClosedCrossLineageLedgerInterval]:
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("250"))
    interval = begin_cross_lineage_ledger_interval(ledger)
    request_ids: list[str] = []
    for record in _usage_records(runs):
        assert record.attempts == 1
        request_ids.append(record.request_id)
        accounted_cost = record.accounted_cost_usd_exact
        assert accounted_cost is not None
        cost = actual_cost if actual_cost is not None else Decimal(accounted_cost)
        reservation = ledger.reserve(record.request_id, cost)
        ledger.reconcile(reservation, cost)
    return ledger, close_cross_lineage_ledger_interval(
        interval,
        expected_request_ids=request_ids,
    )


def _issue(
    live_inputs: _LiveInputs,
    interval: ClosedCrossLineageLedgerInterval,
    *,
    runs: tuple[CrossLineageRunnerRunCustody, ...] | None = None,
) -> tuple[VerifiedCrossLineageRunnerCustody, AuthenticatedCrossLineageRunnerEvidence]:
    return issue_verified_cross_lineage_runner_custody(
        public_lineage_capability=live_inputs.public_lineage,
        ground_truth_capability=live_inputs.ground_truth,
        benchmark_suite=live_inputs.suite,
        runs=live_inputs.runs if runs is None else runs,
        closed_ledger_interval=interval,
    )


def test_provider_free_fixture_cannot_issue_runner_projection(
    tmp_path: Path,
    live_inputs: _LiveInputs,
) -> None:
    _ledger, interval = _closed_runner_interval(tmp_path / "runner.json", live_inputs.runs)
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="owned REAL transport origin"):
        _issue(live_inputs, interval)


def test_runner_rejects_mixed_campaign_effective_configuration_before_origin_replay(
    tmp_path: Path,
    live_inputs: _LiveInputs,
) -> None:
    runs = (
        live_inputs.runs[0],
        replace(
            live_inputs.runs[1],
            candidate_campaign_effective_config_sha256="4" * 64,
        ),
    )
    _ledger, interval = _closed_runner_interval(tmp_path / "mixed-config.json", runs)

    with pytest.raises(
        AuthenticatedCrossLineageRunnerError,
        match="do not share one effective configuration",
    ):
        _issue(live_inputs, interval, runs=runs)


def test_structural_attesters_do_not_mint_authrunner_transport_origin(
    live_inputs: _LiveInputs,
) -> None:
    assert all(
        not _has_authrunner_owned_real_usage_origin(record)
        for record in _usage_records(live_inputs.runs)
    )
    assert all(
        not _has_authrunner_generation_origin(capability)
        for run in live_inputs.runs
        for capability in (
            run.candidate_generation_verification,
            run.judge_generation_verification,
        )
    )
    structurally_reconciled = _usage_records(live_inputs.runs)[0]
    with pytest.raises(ValueError, match="pristine bound-success path"):
        _attest_authrunner_owned_real_usage_origin(structurally_reconciled)
    assert not _has_authrunner_owned_real_usage_origin(structurally_reconciled)
    raw_generation_capability = live_inputs.runs[0].candidate_generation_verification
    with pytest.raises(ValueError, match="pristine refetch path"):
        _attest_authrunner_generation_origin(raw_generation_capability, ())
    assert not _has_authrunner_generation_origin(raw_generation_capability)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires a POSIX process boundary")
def test_authrunner_usage_origin_process_boundary_rejects_parent_pid_after_fork() -> None:
    parent_pid = os.getpid()
    assert _authrunner_usage_origin_process_is_current(parent_pid)
    read_fd, write_fd = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:
        os.close(read_fd)
        try:
            observed = _authrunner_usage_origin_process_is_current(parent_pid)
            os.write(write_fd, b"1" if observed else b"0")
        finally:
            os.close(write_fd)
            os._exit(0)
    os.close(write_fd)
    try:
        observed = os.read(read_fd, 1)
    finally:
        os.close(read_fd)
    waited_pid, status = os.waitpid(child_pid, 0)
    assert waited_pid == child_pid
    assert os.waitstatus_to_exitcode(status) == 0
    assert observed == b"0"


def test_transport_origin_rejects_descriptor_retarget_before_forged_invocation(
    live_inputs: _LiveInputs,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = _usage_records(live_inputs.runs)[0]
    invocations: list[str] = []

    async def forged_completion(*_args: object, **_kwargs: object) -> object:
        invocations.append("completion")
        raise AssertionError("forged completion descriptor was invoked")

    with monkeypatch.context() as context:
        context.setattr(
            openrouter_module.OpenRouterClient,
            "complete_with_evidence",
            forged_completion,
        )
        with pytest.raises(ValueError, match="pristine bound-success path"):
            _attest_authrunner_owned_real_usage_origin(record)

    assert invocations == []
    assert not _has_authrunner_owned_real_usage_origin(record)


def test_capabilities_are_nonconstructible_noncopyable_and_nonserializable(
    tmp_path: Path,
    live_inputs: _LiveInputs,
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "opaque-ledger.json", cap_usd=Decimal("250"))
    open_interval = begin_cross_lineage_ledger_interval(ledger)
    with pytest.raises(TypeError):
        OpenCrossLineageLedgerInterval()
    with pytest.raises(TypeError):
        copy.copy(open_interval)
    with pytest.raises(TypeError):
        pickle.dumps(open_interval)
    reservation = ledger.reserve("opaque-request", Decimal("0.01"))
    ledger.reconcile(reservation, Decimal("0.01"))
    closed = close_cross_lineage_ledger_interval(
        open_interval,
        expected_request_ids=("opaque-request",),
    )
    with pytest.raises(TypeError):
        ClosedCrossLineageLedgerInterval()
    with pytest.raises(TypeError):
        copy.deepcopy(closed)
    with pytest.raises(TypeError):
        pickle.dumps(closed)

    _runner_ledger, runner_interval = _closed_runner_interval(
        tmp_path / "opaque-runner.json",
        live_inputs.runs,
    )
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="owned REAL transport origin"):
        _issue(live_inputs, runner_interval)
    with pytest.raises(TypeError):
        VerifiedCrossLineageRunnerCustody()
    forged = object.__new__(VerifiedCrossLineageRunnerCustody)
    with pytest.raises(TypeError):
        copy.copy(forged)
    with pytest.raises(TypeError):
        copy.deepcopy(forged)
    with pytest.raises(TypeError):
        pickle.dumps(forged)


def test_runner_lease_registry_revocation_is_exact_one_way_and_returns_nothing() -> None:
    observed_pid = [101]
    registry: _PidLocalOneWayLeaseRegistry[_LeaseCapability, _LeaseState] = (
        _PidLocalOneWayLeaseRegistry(
            capability_type=_LeaseCapability,
            getpid=lambda: observed_pid[0],
        )
    )
    capability = _LeaseCapability()
    state = _LeaseState(marker="non-authorizing-lease-state")
    registry.register(capability, state)
    snapshot = registry.snapshot(capability)

    assert snapshot.state is state
    revoke = cast(Callable[[_LeaseCapability], object], registry.revoke)
    assert revoke(capability) is None
    with pytest.raises(
        AuthenticatedCrossLineageRunnerError,
        match="absent, mismatched, or revoked",
    ):
        registry.snapshot(capability)
    with pytest.raises(
        AuthenticatedCrossLineageRunnerError,
        match="absent, mismatched, or revoked",
    ):
        registry.revoke(capability)
    with pytest.raises(
        AuthenticatedCrossLineageRunnerError,
        match="absent, mismatched, or revoked",
    ):
        registry.revoke(_LeaseCapability())
    with pytest.raises(
        AuthenticatedCrossLineageRunnerError,
        match="absent, mismatched, or revoked",
    ):
        registry.revoke(cast(_LeaseCapability, object()))


def test_runner_lease_registry_rejects_cross_process_revocation() -> None:
    observed_pid = [201]
    registry: _PidLocalOneWayLeaseRegistry[_LeaseCapability, _LeaseState] = (
        _PidLocalOneWayLeaseRegistry(
            capability_type=_LeaseCapability,
            getpid=lambda: observed_pid[0],
        )
    )
    capability = _LeaseCapability()
    registry.register(capability, _LeaseState(marker="parent"))

    observed_pid[0] = 202
    with pytest.raises(
        AuthenticatedCrossLineageRunnerError,
        match="belongs to another process",
    ):
        registry.snapshot(capability)
    with pytest.raises(
        AuthenticatedCrossLineageRunnerError,
        match="belongs to another process",
    ):
        registry.revoke(capability)

    observed_pid[0] = 201
    revoke = cast(Callable[[_LeaseCapability], object], registry.revoke)
    assert revoke(capability) is None


def test_runner_lease_registry_recheck_detects_concurrent_revocation() -> None:
    registry: _PidLocalOneWayLeaseRegistry[_LeaseCapability, _LeaseState] = (
        _PidLocalOneWayLeaseRegistry(
            capability_type=_LeaseCapability,
            getpid=lambda: 301,
        )
    )
    capability = _LeaseCapability()
    registry.register(capability, _LeaseState(marker="replay"))
    snapshot = registry.snapshot(capability)
    replay_started = threading.Event()
    continue_replay = threading.Event()
    failures: list[str] = []

    def finish_replay() -> None:
        replay_started.set()
        if not continue_replay.wait(timeout=5):
            failures.append("replay test timed out")
            return
        try:
            registry.recheck(capability, snapshot)
        except AuthenticatedCrossLineageRunnerError as exc:
            failures.append(str(exc))

    replay = threading.Thread(target=finish_replay)
    replay.start()
    assert replay_started.wait(timeout=5)
    revoke = cast(Callable[[_LeaseCapability], object], registry.revoke)
    assert revoke(capability) is None
    continue_replay.set()
    replay.join(timeout=5)

    assert not replay.is_alive()
    assert failures == [
        "verified cross-lineage runner custody changed or was revoked during replay"
    ]


def test_public_runner_revocation_rejects_forged_or_absent_custody() -> None:
    forged = object.__new__(VerifiedCrossLineageRunnerCustody)
    with pytest.raises(
        AuthenticatedCrossLineageRunnerError,
        match="absent, mismatched, or revoked",
    ):
        revoke_verified_cross_lineage_runner_custody(forged)
    with pytest.raises(
        AuthenticatedCrossLineageRunnerError,
        match="absent, mismatched, or revoked",
    ):
        revoke_verified_cross_lineage_runner_custody(
            cast(VerifiedCrossLineageRunnerCustody, object())
        )


def test_public_runner_revocation_attempts_disposal_before_reporting_binding_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forged_calls: list[str] = []

    def forged_revoke(_capability: VerifiedCrossLineageRunnerCustody) -> None:
        forged_calls.append("forged")

    monkeypatch.setattr(
        authenticated_runner_module,
        "revoke_verified_cross_lineage_runner_custody",
        forged_revoke,
    )
    forged = object.__new__(VerifiedCrossLineageRunnerCustody)

    with pytest.raises(
        AuthenticatedCrossLineageRunnerError,
        match="absent, mismatched, or revoked",
    ):
        revoke_verified_cross_lineage_runner_custody(forged)

    assert forged_calls == []


def test_runner_child_inventory_revocation_invalidates_every_retained_consumer(
    live_inputs: _LiveInputs,
) -> None:
    registry = _candidate_registry((CANDIDATE_ID,))
    policy = cast(Callable[[], QualificationPolicy], qualification_fixtures._policy)()
    campaign_bindings = []
    generation_bindings = []

    for run in (*live_inputs.runs, live_inputs.runs[0]):
        portfolio, campaign = qualification_fixtures._portfolio_evidence(
            registry=registry,
            report=run.candidate_report,
            policy=policy,
        )
        campaign_bindings.append((campaign, portfolio, run.candidate_report))

        candidate_requests = candidate_generation_verification_requests(
            registry=registry,
            benchmark_reports=(run.candidate_report,),
        )
        candidate_generation = qualification_fixtures._trusted_generation_authority(
            registry=registry,
            primary=run.candidate_report,
        )
        generation_bindings.append((candidate_generation, candidate_requests[0]))

        judge_requests = adjudication_generation_verification_requests(
            report=run.adjudication_report,
            judge=run.judge,
        )
        judge_generation = _judge_generation_capability(run.adjudication_report, run.judge)
        generation_bindings.append((judge_generation, judge_requests[0]))

    campaigns = tuple(item[0] for item in campaign_bindings)
    generations = tuple(item[0] for item in generation_bindings)
    assert len(campaigns) == 3
    assert len(generations) == 6

    _revoke_runner_child_capability_inventory(
        campaigns=campaigns,
        generations=generations,
        expected_campaign_count=3,
    )

    for capability, portfolio, report in campaign_bindings:
        with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
            capability.require_for(
                portfolio_sha256=portfolio.portfolio_sha256,
                reports=(report,),
                policy_sha256=policy.policy_sha256,
                effective_config_sha256="3" * 64,
            )
    for capability, request in generation_bindings:
        with pytest.raises(GenerationEvidenceValidationError, match="not trusted"):
            capability.attestation_for(
                benchmark_report_sha256=request.benchmark_report_sha256,
                case_id=request.case_id,
                exact_model_id=request.exact_model_id,
                canonical_model_id=request.canonical_model_id,
                catalog_identity_binding_sha256=request.catalog_identity_binding_sha256,
                discovery_evidence_sha256=request.discovery_evidence_sha256,
                usage_record=request.usage_record,
                expected_provider_name=request.expected_provider_name,
            )


def test_ledger_closure_rejects_nonexact_or_uncertain_intervals(tmp_path: Path) -> None:
    wrong_cap = AtomicCostLedger.initialize(tmp_path / "wrong-cap.json", cap_usd=Decimal("10"))
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="250 USD"):
        begin_cross_lineage_ledger_interval(wrong_cap)

    exact = AtomicCostLedger.initialize(tmp_path / "exact.json", cap_usd=Decimal("250"))
    exact_interval = begin_cross_lineage_ledger_interval(exact)
    reservation = exact.reserve("exact-request", Decimal("0.01"))
    exact.reconcile(reservation, Decimal("0.01"))
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="exact expected"):
        close_cross_lineage_ledger_interval(
            exact_interval,
            expected_request_ids=("different-request",),
        )
    close_cross_lineage_ledger_interval(
        exact_interval,
        expected_request_ids=(item for item in ("exact-request",)),
    )

    uncertain = AtomicCostLedger.initialize(tmp_path / "uncertain.json", cap_usd=Decimal("250"))
    uncertain_interval = begin_cross_lineage_ledger_interval(uncertain)
    uncertain_reservation = uncertain.reserve("uncertain-request", Decimal("0.01"))
    uncertain.reconcile(uncertain_reservation, None)
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="non-reconciled"):
        close_cross_lineage_ledger_interval(
            uncertain_interval,
            expected_request_ids=("uncertain-request",),
        )

    historical = AtomicCostLedger.initialize(
        tmp_path / "historical-uncertain.json",
        cap_usd=Decimal("250"),
    )
    historical_reservation = historical.reserve("historical-request", Decimal("0.01"))
    historical.reconcile(historical_reservation, None)
    historical_interval = begin_cross_lineage_ledger_interval(historical)
    exact_reservation = historical.reserve("new-exact-request", Decimal("0.02"))
    historical.reconcile(exact_reservation, Decimal("0.015"))
    close_cross_lineage_ledger_interval(
        historical_interval,
        expected_request_ids=("new-exact-request",),
    )

    exhausted = AtomicCostLedger.initialize(tmp_path / "exhausted.json", cap_usd=Decimal("250"))
    exhausted_interval = begin_cross_lineage_ledger_interval(exhausted)
    exhausted_reservation = exhausted.reserve("exhausted-request", Decimal("250"))
    exhausted.reconcile(exhausted_reservation, Decimal("250"))
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="terminal non-overrun"):
        close_cross_lineage_ledger_interval(
            exhausted_interval,
            expected_request_ids=("exhausted-request",),
        )


def test_origin_precondition_precedes_cost_and_capability_checks(
    tmp_path: Path,
    live_inputs: _LiveInputs,
) -> None:
    _ledger, cost_interval = _closed_runner_interval(
        tmp_path / "cost-mismatch.json",
        live_inputs.runs,
        actual_cost=Decimal("0.02"),
    )
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="owned REAL transport origin"):
        _issue(live_inputs, cost_interval)

    reused = replace(
        live_inputs.runs[1],
        candidate_campaign_verification=(live_inputs.runs[0].candidate_campaign_verification),
    )
    _ledger, capability_interval = _closed_runner_interval(
        tmp_path / "reused-capability.json",
        live_inputs.runs,
    )
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="separate reports"):
        _issue(live_inputs, capability_interval, runs=(live_inputs.runs[0], reused))


def test_forged_live_generation_capability_and_candidate_root_fail(
    tmp_path: Path,
    live_inputs: _LiveInputs,
) -> None:
    forged_generation = object.__new__(TrustedGenerationVerification)
    forged_run = replace(
        live_inputs.runs[0],
        candidate_generation_verification=forged_generation,
    )
    _ledger, forged_interval = _closed_runner_interval(
        tmp_path / "forged-generation.json",
        live_inputs.runs,
    )
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="owned REAL transport origin"):
        _issue(live_inputs, forged_interval, runs=(forged_run, live_inputs.runs[1]))

    report_payload = live_inputs.runs[0].candidate_report.model_dump(mode="json")
    report_payload["results"][0]["target"]["root_lineage"] = "sha256:" + ("f" * 64)
    mismatched_report = _reseal_report(report_payload)
    mismatched_run = replace(
        live_inputs.runs[0],
        candidate_report=mismatched_report,
        candidate_campaign_reports=(mismatched_report,),
    )
    _ledger, root_interval = _closed_runner_interval(
        tmp_path / "root-mismatch.json",
        (mismatched_run, live_inputs.runs[1]),
    )
    with pytest.raises(
        AuthenticatedCrossLineageRunnerError,
        match="prepared adjudication cannot be rebuilt from frozen authority",
    ):
        _issue(live_inputs, root_interval, runs=(mismatched_run, live_inputs.runs[1]))


def test_runner_rejects_report_resealed_over_nonprepared_ground_truth(
    tmp_path: Path,
    live_inputs: _LiveInputs,
) -> None:
    run = live_inputs.runs[0]
    prepared = run.prepared_adjudication
    wrong_request = adjudication_module._build_case_request(
        target=prepared.target,
        suite=live_inputs.suite,
        candidate_report=run.candidate_report,
        case=live_inputs.suite.cases[0],
        truth=live_inputs.suite.ground_truth.cases[1],
        result=run.candidate_report.results[0].cases[0],
    )
    wrong_response = build_cross_lineage_adjudication_response(
        request=wrong_request,
        dimension_outcomes=wrong_request.expected_dimension_outcomes,
        disposition=CrossLineageAdjudicationDisposition.CONFIRMED,
        rationale="Synthetic resealed result uses the wrong frozen truth case.",
    )
    wrong_usage, wrong_generation = _judge_usage_and_generation(
        case_index=99_999,
        request=wrong_request,
        response=wrong_response,
        judge=run.judge,
    )
    wrong_result = build_cross_lineage_adjudication_case_result(
        request=wrong_request,
        response=wrong_response,
        usage_record=wrong_usage,
        generation_evidence=wrong_generation,
    )
    cases = (wrong_result, *run.adjudication_report.cases[1:])
    original = run.adjudication_report
    provisional = original.model_copy(
        update={
            "cases": cases,
            "report_sha256": "0" * 64,
        }
    )
    tampered_report = CrossLineageAdjudicationReport(
        **provisional.model_dump(mode="python", exclude={"report_sha256"}),
        report_sha256=canonical_sha256(adjudication_module._report_hash_payload(provisional)),
    )
    assert tampered_report.prepared_run_sha256 == prepared.prepared_run_sha256
    assert tuple(item.request for item in tampered_report.cases) != prepared.requests

    tampered_run = replace(run, adjudication_report=tampered_report)
    runs = (tampered_run, live_inputs.runs[1])
    _ledger, interval = _closed_runner_interval(tmp_path / "wrong-truth.json", runs)
    with pytest.raises(
        AuthenticatedCrossLineageRunnerError,
        match="prepared adjudication differs from frozen truth or retained report",
    ):
        _issue(live_inputs, interval, runs=runs)


def test_module_and_class_retargeting_fail_before_forged_invocation(
    tmp_path: Path,
    live_inputs: _LiveInputs,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _ledger, interval = _closed_runner_interval(tmp_path / "retarget.json", live_inputs.runs)
    invocations: list[str] = []

    def forged_public_lineage(*_args: object, **_kwargs: object) -> object:
        invocations.append("public")
        raise AssertionError("forged public-lineage callable was invoked")

    with monkeypatch.context() as context:
        context.setattr(
            authenticated_runner_module,
            "require_independent_public_model_lineage",
            forged_public_lineage,
        )
        with pytest.raises(AuthenticatedCrossLineageRunnerError, match="not pristine"):
            _issue(live_inputs, interval)

    def forged_attestation(
        _self: object,
        *_args: object,
        **_kwargs: object,
    ) -> object:
        invocations.append("generation")
        raise AssertionError("forged generation callable was invoked")

    with monkeypatch.context() as context:
        context.setattr(TrustedGenerationVerification, "attestation_for", forged_attestation)
        with pytest.raises(AuthenticatedCrossLineageRunnerError, match="not pristine"):
            _issue(live_inputs, interval)

    def forged_snapshot(*_args: object, **_kwargs: object) -> object:
        invocations.append("ledger")
        raise AssertionError("forged ledger callable was invoked")

    with monkeypatch.context() as context:
        context.setattr(cost_ledger_module, "_snapshot", forged_snapshot)
        with pytest.raises(AuthenticatedCrossLineageRunnerError, match="not pristine"):
            _issue(live_inputs, interval)

    original_case_getattribute = (
        adjudication_module.CrossLineageAdjudicationCaseResult.__getattribute__
    )

    def forged_case_getattribute(self: object, name: str) -> object:
        invocations.append("case-result")
        return original_case_getattribute(self, name)

    with monkeypatch.context() as context:
        context.setattr(
            adjudication_module.CrossLineageAdjudicationCaseResult,
            "__getattribute__",
            forged_case_getattribute,
        )
        with pytest.raises(AuthenticatedCrossLineageRunnerError, match="not pristine"):
            _issue(live_inputs, interval)

    def forged_case_request(*_args: object, **_kwargs: object) -> object:
        invocations.append("case-request")
        raise AssertionError("forged adjudication request builder was invoked")

    with monkeypatch.context() as context:
        context.setattr(adjudication_module, "_build_case_request", forged_case_request)
        with pytest.raises(
            AuthenticatedCrossLineageRunnerError,
            match="prepared adjudication cannot be rebuilt",
        ):
            _issue(live_inputs, interval)

    def forged_runner_revoke(*_args: object, **_kwargs: object) -> None:
        invocations.append("runner-revoke")
        raise AssertionError("forged runner revocation callable was invoked")

    with monkeypatch.context() as context:
        context.setattr(
            authenticated_runner_module,
            "revoke_verified_cross_lineage_runner_custody",
            forged_runner_revoke,
        )
        with pytest.raises(AuthenticatedCrossLineageRunnerError, match="not pristine"):
            _issue(live_inputs, interval)

    def forged_child_revoke(*_args: object, **_kwargs: object) -> None:
        invocations.append("child-revoke")
        raise AssertionError("forged child revocation callable was invoked")

    with monkeypatch.context() as context:
        context.setattr(
            authenticated_runner_module,
            "_revoke_runner_child_capability_inventory",
            forged_child_revoke,
        )
        with pytest.raises(AuthenticatedCrossLineageRunnerError, match="not pristine"):
            _issue(live_inputs, interval)

    def forged_child_slot(_self: object) -> object:
        invocations.append("child-slot")
        raise AssertionError("forged runner child slot was invoked")

    with monkeypatch.context() as context:
        context.setattr(
            CrossLineageRunnerRunCustody,
            "candidate_generation_verification",
            property(forged_child_slot),
        )
        with pytest.raises(AuthenticatedCrossLineageRunnerError, match="not pristine"):
            _issue(live_inputs, interval)

    def forged_lease_recheck(*_args: object, **_kwargs: object) -> None:
        invocations.append("lease-recheck")
        raise AssertionError("forged lease recheck callable was invoked")

    with monkeypatch.context() as context:
        context.setattr(
            authenticated_runner_module._PidLocalOneWayLeaseRegistry,
            "recheck",
            forged_lease_recheck,
        )
        with pytest.raises(AuthenticatedCrossLineageRunnerError, match="not pristine"):
            _issue(live_inputs, interval)

    assert invocations == []
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="owned REAL transport origin"):
        _issue(live_inputs, interval)


def test_closed_ledger_cannot_bootstrap_provider_free_runner_custody(
    tmp_path: Path,
    live_inputs: _LiveInputs,
) -> None:
    ledger, interval = _closed_runner_interval(tmp_path / "drift.json", live_inputs.runs)
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="owned REAL transport origin"):
        _issue(live_inputs, interval)
    reservation = ledger.reserve("post-closure-request", Decimal("0.01"))
    ledger.reconcile(reservation, Decimal("0.01"))
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="changed after closure"):
        _issue(live_inputs, interval)
