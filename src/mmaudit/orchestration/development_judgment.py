"""Durable source-bound candidate reviews through the non-qualifying development boundary."""

from __future__ import annotations

import asyncio
import math
import time
from pathlib import Path
from typing import Literal

import httpx

from mmaudit.benchmark.development import (
    DevelopmentBenchmarkTruth,
    bind_development_benchmark,
    score_development_judgment,
)
from mmaudit.models.development_audit import (
    DevelopmentAuditAccountingEntry,
    development_ledger_request_id,
)
from mmaudit.models.development_judgment import (
    DevelopmentJudgmentObservation,
    DevelopmentJudgmentPlan,
    DevelopmentJudgmentShardObservation,
    PreparedDevelopmentJudgment,
    PreparedDevelopmentJudgmentShard,
    _money_sum,
    prepare_development_judgment,
    validate_development_candidate_accounting,
)
from mmaudit.models.development_review import DevelopmentReviewDiagnostic
from mmaudit.models.development_routing import DevelopmentRoutingEvidence, DevelopmentRoutingFailure
from mmaudit.models.development_transport import review_development_judgment_shard
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.development_audit import MAX_DEVELOPMENT_AUDIT_ARTIFACT_BYTES, _write
from mmaudit.orchestration.development_budget import development_uncertain_reservations
from mmaudit.release_io import revalidate_evidence_file_binding
from mmaudit.repository.directory_custody import (
    observe_unlinked_directory,
    require_same_unlinked_directory_objects,
)


class DevelopmentJudgmentError(ValueError):
    """Controlled local refusal without model prose, paths, credentials or provider detail."""


def _rebuild(prepared: PreparedDevelopmentJudgment) -> PreparedDevelopmentJudgment:
    if (
        type(prepared) is not PreparedDevelopmentJudgment
        or type(prepared.plan) is not DevelopmentJudgmentPlan
        or type(prepared.shards) is not tuple
        or any(type(item) is not PreparedDevelopmentJudgmentShard for item in prepared.shards)
    ):
        raise DevelopmentJudgmentError("development judgment requires exact prepared types")
    plan = DevelopmentJudgmentPlan.model_validate_json(prepared.plan.model_dump_json(), strict=True)
    rebuilt = prepare_development_judgment(
        candidate=plan.candidate,
        policy=plan.policy,
        endpoint_snapshot=prepared.endpoint_snapshot,
        source_files=prepared.source_files,
        run_id=plan.run_id,
        maximum_completion_tokens=plan.maximum_completion_tokens,
    )
    if rebuilt != prepared:
        raise DevelopmentJudgmentError(
            "development judgment source, claims, metadata or requests changed"
        )
    return rebuilt


def _report(
    prepared: PreparedDevelopmentJudgment,
    ledger: AtomicCostLedger,
    observations: list[DevelopmentJudgmentShardObservation],
    transport: Literal["MOCK_HTTP", "HTTP_OBSERVATION"],
    reason: Literal["JUDGMENT_INCOMPLETE", "LOCAL_FAILURE", "INTERRUPTED"] | None,
    elapsed: float,
) -> DevelopmentJudgmentObservation:
    snapshot = ledger.snapshot()
    validate_development_candidate_accounting(prepared.plan.candidate, snapshot)
    entries = {entry.request_id: entry for entry in snapshot.entries}
    accounting: list[DevelopmentAuditAccountingEntry] = []
    for shard in prepared.plan.shards:
        entry = entries.get(development_ledger_request_id(shard.estimate.request_id))
        if entry is not None:
            accounting.append(
                DevelopmentAuditAccountingEntry(
                    shard_id=shard.shard_id,
                    ledger_request_id=entry.request_id,
                    reservation_id=entry.reservation_id,
                    status=entry.status,
                    reserved_usd=entry.reserved_usd,
                    actual_cost_usd=entry.actual_cost_usd,
                    accounted_cost_usd=entry.accounted_cost_usd,
                )
            )
    reviewed = {
        claim.claim_id
        for observation in observations
        if observation.status == "OBSERVED"
        for claim in observation.claims
    }
    gaps = tuple(
        claim.claim_id
        for shard in prepared.plan.shards
        for claim in shard.claims
        if claim.claim_id not in reviewed
    )
    cost = _money_sum(item.accounted_cost_usd for item in accounting)
    return DevelopmentJudgmentObservation(
        plan=prepared.plan,
        transport=transport,
        status="INCOMPLETE"
        if gaps or reason is not None
        else ("OBSERVED_ALL_JUDGMENTS" if prepared.plan.shards else "NO_CANDIDATES"),
        stop_reason=reason,
        observations=tuple(observations),
        accounting=tuple(accounting),
        unreviewed_claim_ids=gaps,
        completed_judgment_count=len(reviewed),
        judgment_accounted_cost_usd=cost,
        combined_accounted_cost_usd=_money_sum(
            (cost, prepared.plan.candidate.total_accounted_cost_usd)
        ),
        active_reserved_usd=_money_sum(
            item.reserved_usd for item in accounting if item.status is CostEntryStatus.RESERVED
        ),
        elapsed_seconds=elapsed,
        summed_stage_elapsed_seconds=elapsed + prepared.plan.candidate.elapsed_seconds,
    )


async def run_development_judgment(
    *,
    prepared: PreparedDevelopmentJudgment,
    ledger: AtomicCostLedger,
    operator_secrets: OperatorSecrets,
    output_dir: Path,
    allow_code_egress: bool = False,
    maximum_run_seconds: float = 600.0,
    mock_transport: httpx.MockTransport | None = None,
    benchmark_truth: DevelopmentBenchmarkTruth | None = None,
) -> DevelopmentJudgmentObservation:
    """Review every nonempty candidate shard once, retaining original costs and failures.

    The input audit remains unchanged. No request means NO_CANDIDATES, not a completed
    judgment. Cancellation retains durable accounting and owned artifacts, then propagates.
    Supplied metadata can reject identity collisions, never prove root-lineage independence.
    """

    if allow_code_egress is not True:
        raise DevelopmentJudgmentError(
            "development judgment requires explicit source egress consent"
        )
    if (
        type(ledger) is not AtomicCostLedger
        or type(operator_secrets) is not OperatorSecrets
        or not operator_secrets.openrouter_api_key_present
    ):
        raise DevelopmentJudgmentError(
            "development judgment requires exact ledger and credential handles"
        )
    if mock_transport is not None and type(mock_transport) is not httpx.MockTransport:
        raise DevelopmentJudgmentError(
            "development judgment test transport must be an exact MockTransport"
        )
    if (
        type(maximum_run_seconds) not in {int, float}
        or not math.isfinite(maximum_run_seconds)
        or not 0 < maximum_run_seconds <= 1800
    ):
        raise DevelopmentJudgmentError("development judgment requires a bounded run deadline")
    prepared = _rebuild(prepared)
    transport: Literal["MOCK_HTTP", "HTTP_OBSERVATION"] = (
        "MOCK_HTTP" if mock_transport is not None else "HTTP_OBSERVATION"
    )
    if prepared.plan.candidate.transport != transport:
        raise DevelopmentJudgmentError("development judgment cannot mix mock and HTTP observations")
    if operator_secrets.openrouter_api_key in prepared.plan.model_dump_json():
        raise DevelopmentJudgmentError(
            "development credential overlaps retained candidate or plan data"
        )
    binding = (
        bind_development_benchmark(plan=prepared.plan.candidate.plan, truth=benchmark_truth)
        if benchmark_truth is not None
        else None
    )
    state = ledger.snapshot()
    validate_development_candidate_accounting(prepared.plan.candidate, state)
    carried = {
        entry.request_id
        for entry in development_uncertain_reservations(policy=prepared.plan.policy, snapshot=state)
    }
    request_ids = {
        development_ledger_request_id(item.estimate.request_id) for item in prepared.plan.shards
    }
    if (
        state.over_cap
        or state.has_reservation_overrun
        or state.active_reserved_usd != 0
        or any(
            entry.request_id in request_ids
            or (
                entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
                and entry.request_id not in carried
            )
            for entry in state.entries
        )
        or prepared.plan.estimated_total_cost_usd > state.remaining_usd
    ):
        raise DevelopmentJudgmentError(
            "development judgment preflight refuses cumulative accounting"
        )
    if not output_dir.is_absolute() or ".." in output_dir.parts:
        raise DevelopmentJudgmentError(
            "development judgment output must be an absolute normalized path"
        )
    parent = observe_unlinked_directory(
        output_dir.parent, label="development judgment output parent"
    )
    output_dir.mkdir(mode=0o700)
    require_same_unlinked_directory_objects(parent, label="development judgment output parent")
    custody = observe_unlinked_directory(output_dir, label="development judgment output")
    bindings = [_write(output_dir, "plan.json", prepared.plan)]
    if binding is not None:
        bindings.append(_write(output_dir, "benchmark-plan.json", binding))

    def require_outputs() -> None:
        require_same_unlinked_directory_objects(custody, label="development judgment output")
        for item in bindings:
            revalidate_evidence_file_binding(
                evidence_root=output_dir,
                binding=item,
                max_bytes=MAX_DEVELOPMENT_AUDIT_ARTIFACT_BYTES,
            )

    start = time.monotonic()
    deadline = start + maximum_run_seconds
    observations: list[DevelopmentJudgmentShardObservation] = []
    reason: Literal["JUDGMENT_INCOMPLETE", "LOCAL_FAILURE", "INTERRUPTED"] | None = None
    interruption: BaseException | None = None
    generations = {item.generation_id for item in prepared.plan.candidate.observations}
    try:
        async with asyncio.timeout(maximum_run_seconds):
            for shard in prepared.shards:
                require_outputs()
                if time.monotonic() >= deadline:
                    raise TimeoutError("development judgment deadline exceeded before dispatch")
                observation = await review_development_judgment_shard(
                    prepared=shard,
                    ledger=ledger,
                    operator_secrets=operator_secrets,
                    allow_code_egress=allow_code_egress,
                    mock_transport=mock_transport,
                )
                if observation.status == "OBSERVED" and observation.generation_id in generations:
                    routing = observation.routing_evidence
                    if routing is not None:
                        routing = DevelopmentRoutingEvidence.model_validate(
                            {
                                **routing.model_dump(),
                                "failure_codes": (DevelopmentRoutingFailure.GENERATION_REUSE,),
                            }
                        )
                    observation = DevelopmentJudgmentShardObservation.model_validate(
                        {
                            **observation.model_dump(),
                            "status": "INCOMPLETE",
                            "response": None,
                            "diagnostics": (DevelopmentReviewDiagnostic.IDENTITY_MISMATCH,),
                            "routing_evidence": routing,
                        }
                    )
                generations.add(observation.generation_id)
                observations.append(observation)
                require_outputs()
                bindings.append(_write(output_dir, shard.shard_id + ".json", observation))
                if time.monotonic() >= deadline:
                    raise TimeoutError("development judgment deadline exceeded after observation")
                if observation.status != "OBSERVED":
                    reason = "JUDGMENT_INCOMPLETE"
                    break
    except (asyncio.CancelledError, KeyboardInterrupt, SystemExit) as exc:
        interruption = exc
        reason = "INTERRUPTED"
    except Exception:
        reason = "LOCAL_FAILURE"
    try:
        result = _report(
            prepared, ledger, observations, transport, reason, time.monotonic() - start
        )
        require_outputs()
        bindings.append(_write(output_dir, "result.json", result))
        require_outputs()
        if binding is not None:
            score = score_development_judgment(binding=binding, observation=result)
            bindings.append(_write(output_dir, "score.json", score))
            require_outputs()
    except Exception:
        if interruption is not None:
            raise interruption from None
        raise DevelopmentJudgmentError(
            "development judgment output/accounting could not be finalized"
        ) from None
    if interruption is not None:
        raise interruption
    return result
