"""Owned candidate-to-dual-review execution with one ledger and whole-run deadline."""

from __future__ import annotations

import asyncio
import time
from decimal import Decimal
from pathlib import Path
from typing import Literal

import httpx
from pydantic import BaseModel

from mmaudit.benchmark.development import DevelopmentBenchmarkTruth, bind_development_benchmark
from mmaudit.models.development_audit import (
    DevelopmentAuditAccountingEntry,
    DevelopmentAuditObservation,
    DevelopmentAuditPlan,
    PreparedDevelopmentAudit,
    PreparedDevelopmentAuditShard,
    development_ledger_request_id,
)
from mmaudit.models.development_ensemble import (
    DEVELOPMENT_ENSEMBLE_STAGES,
    MAX_DEVELOPMENT_ENSEMBLE_ARTIFACT_BYTES,
    DevelopmentEnsembleAccountingEntry,
    DevelopmentEnsembleObservation,
    DevelopmentEnsemblePlan,
    DevelopmentEnsembleStageId,
    PreparedDevelopmentEnsemble,
    development_ensemble_claims,
    prepare_development_ensemble,
)
from mmaudit.models.development_judgment import (
    DevelopmentJudgmentObservation,
    DevelopmentJudgmentPlan,
    _money_sum,
    prepare_development_judgment,
)
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.development_audit import (
    MAX_DEVELOPMENT_AUDIT_ARTIFACT_BYTES,
    _write,
    run_development_audit,
)
from mmaudit.orchestration.development_budget import development_uncertain_reservations
from mmaudit.orchestration.development_judgment import run_development_judgment
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release_io import read_json_evidence, revalidate_evidence_file_binding
from mmaudit.repository.directory_custody import (
    DirectoryCustodyObservation,
    observe_unlinked_directory,
    require_same_unlinked_directory_objects,
)

type _StopReason = Literal[
    "CANDIDATE_INCOMPLETE", "REVIEW_INCOMPLETE", "LOCAL_FAILURE", "INTERRUPTED"
]


class DevelopmentEnsembleError(ValueError):
    """Controlled local refusal; never include response text, credentials or private paths."""


def _rebuild(prepared: PreparedDevelopmentEnsemble) -> PreparedDevelopmentEnsemble:
    if (
        type(prepared) is not PreparedDevelopmentEnsemble
        or type(prepared.plan) is not DevelopmentEnsemblePlan
        or type(prepared.candidate) is not PreparedDevelopmentAudit
        or type(prepared.candidate.shards) is not tuple
        or len(prepared.candidate.shards) != 3
        or any(
            type(shard) is not PreparedDevelopmentAuditShard for shard in prepared.candidate.shards
        )
    ):
        raise DevelopmentEnsembleError("development ensemble requires exact prepared stage types")
    plan = DevelopmentEnsemblePlan.model_validate_json(prepared.plan.model_dump_json(), strict=True)
    first = prepared.candidate.shards[0]
    rebuilt = prepare_development_ensemble(
        policy=plan.policy,
        candidate_metadata=first.discovery or first.endpoint_snapshot,
        reviewer_metadata=prepared.reviewer_metadata,
        corpus_id=plan.candidate.corpus_id,
        source_files=first.source_files,
        run_id=plan.run_id,
        candidate_maximum_completion_tokens=plan.candidate.shards[
            0
        ].estimate.maximum_completion_tokens,
        reviewer_maximum_completion_tokens=(
            plan.reviewers[0].maximum_completion_tokens,
            plan.reviewers[1].maximum_completion_tokens,
        ),
        maximum_run_seconds=plan.maximum_run_seconds,
    )
    if rebuilt != prepared:
        raise DevelopmentEnsembleError("development ensemble selection or requests changed")
    return rebuilt


def _report(
    prepared: PreparedDevelopmentEnsemble,
    ledger: AtomicCostLedger,
    candidate: DevelopmentAuditObservation | None,
    plans: list[DevelopmentJudgmentPlan],
    judgments: list[DevelopmentJudgmentObservation],
    transport: Literal["MOCK_HTTP", "HTTP_OBSERVATION"],
    reason: _StopReason | None,
    elapsed: float,
) -> DevelopmentEnsembleObservation:
    snapshot = ledger.snapshot()
    entries = {entry.request_id: entry for entry in snapshot.entries}
    accounting: list[DevelopmentEnsembleAccountingEntry] = []
    stages: list[
        tuple[DevelopmentEnsembleStageId, DevelopmentAuditPlan | DevelopmentJudgmentPlan]
    ] = [
        ("candidate", prepared.plan.candidate),
        *((prepared.plan.reviewers[i].stage_id, plan) for i, plan in enumerate(plans)),
    ]
    for stage_id, stage_plan in stages:
        for shard in stage_plan.shards:
            entry = entries.get(development_ledger_request_id(shard.estimate.request_id))
            if entry is not None:
                accounting.append(
                    DevelopmentEnsembleAccountingEntry(
                        stage_id=stage_id,
                        entry=DevelopmentAuditAccountingEntry(
                            shard_id=shard.shard_id,
                            ledger_request_id=entry.request_id,
                            reservation_id=entry.reservation_id,
                            status=entry.status,
                            reserved_usd=entry.reserved_usd,
                            actual_cost_usd=entry.actual_cost_usd,
                            accounted_cost_usd=entry.accounted_cost_usd,
                        ),
                    )
                )
    claims = development_ensemble_claims(candidate, tuple(judgments))
    completed = (
        candidate is not None and candidate.status == "OBSERVED_ALL_SHARDS",
        *(i < len(judgments) and judgments[i].status == "OBSERVED_ALL_JUDGMENTS" for i in range(2)),
    )
    gaps = tuple(
        stage
        for stage, done in zip(DEVELOPMENT_ENSEMBLE_STAGES, completed, strict=True)
        if not done
    )
    status = (
        "INCOMPLETE"
        if reason is not None or not completed[0] or (gaps and claims)
        else "NO_CANDIDATES"
        if not claims
        else "OBSERVED_ALL_STAGES"
    )
    return DevelopmentEnsembleObservation.model_validate(
        dict(
            plan=prepared.plan,
            transport=transport,
            status=status,
            stop_reason=reason,
            candidate=candidate,
            judgment_plans=tuple(plans),
            judgments=tuple(judgments),
            accounting=tuple(accounting),
            claims=claims,
            unobserved_stage_ids=gaps,
            completed_stage_count=sum(completed),
            completed_judgment_count=sum(op is not None for row in claims for op in row.opinions),
            total_accounted_cost_usd=_money_sum(row.entry.accounted_cost_usd for row in accounting),
            reported_actual_cost_usd=_money_sum(
                row.entry.actual_cost_usd or Decimal(0) for row in accounting
            ),
            uncertain_accounted_cost_usd=_money_sum(
                row.entry.accounted_cost_usd
                for row in accounting
                if row.entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
            ),
            active_reserved_usd=_money_sum(
                row.entry.reserved_usd
                for row in accounting
                if row.entry.status is CostEntryStatus.RESERVED
            ),
            elapsed_seconds=elapsed,
            observed_stage_elapsed_seconds=(
                candidate.elapsed_seconds if candidate is not None else 0
            )
            + sum(j.elapsed_seconds for j in judgments),
        )
    )


def _bind_stage_outputs(
    root: Path,
    stage_id: DevelopmentEnsembleStageId,
    observation: DevelopmentAuditObservation | DevelopmentJudgmentObservation,
) -> list[ManifestFileBinding]:
    expected: dict[str, BaseModel] = {"plan.json": observation.plan, "result.json": observation}
    expected.update({shard.shard_id + ".json": shard for shard in observation.observations})
    bindings: list[ManifestFileBinding] = []
    for filename, model in expected.items():
        observed = read_json_evidence(
            evidence_root=root,
            relative_path=stage_id + "/" + filename,
            max_bytes=MAX_DEVELOPMENT_AUDIT_ARTIFACT_BYTES,
        )
        if observed.value != model.model_dump(mode="json"):
            raise DevelopmentEnsembleError(
                "development ensemble child output differs from returned observation"
            )
        bindings.append(observed.binding)
    return bindings


async def run_development_ensemble(
    *,
    prepared: PreparedDevelopmentEnsemble,
    ledger: AtomicCostLedger,
    operator_secrets: OperatorSecrets,
    output_dir: Path,
    allow_code_egress: bool = False,
    mock_transport: httpx.MockTransport | None = None,
    benchmark_truth: DevelopmentBenchmarkTruth | None = None,
) -> DevelopmentEnsembleObservation:
    """Execute candidate then two isolated opinions; a failed stage never silently continues.

    Headroom is a preflight estimate, not a portfolio reservation or provider hard cap.
    Child artifacts survive failures. A child that never returns earns no observation credit,
    while every known request liability remains in the parent accounting and missing scope.
    """

    if allow_code_egress is not True:
        raise DevelopmentEnsembleError(
            "development ensemble requires explicit source egress consent"
        )
    if (
        type(ledger) is not AtomicCostLedger
        or type(operator_secrets) is not OperatorSecrets
        or not operator_secrets.openrouter_api_key_present
        or (mock_transport is not None and type(mock_transport) is not httpx.MockTransport)
    ):
        raise DevelopmentEnsembleError(
            "development ensemble requires exact ledger and credential handles"
        )
    prepared = _rebuild(prepared)
    if operator_secrets.openrouter_api_key in prepared.plan.model_dump_json():
        raise DevelopmentEnsembleError("development credential overlaps the ensemble plan")
    benchmark_binding = (
        bind_development_benchmark(plan=prepared.plan.candidate, truth=benchmark_truth)
        if benchmark_truth is not None
        else None
    )
    state = ledger.snapshot()
    carried_ids = {
        entry.request_id
        for entry in development_uncertain_reservations(policy=prepared.plan.policy, snapshot=state)
    }
    request_ids = {
        development_ledger_request_id(shard.estimate.request_id)
        for shard in prepared.plan.candidate.shards
    }
    if (
        state.cap_usd != prepared.plan.policy.total_budget_usd
        or state.over_cap
        or state.has_reservation_overrun
        or state.active_reserved_usd != 0
        or any(
            entry.request_id in request_ids
            or (
                entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
                and entry.request_id not in carried_ids
            )
            for entry in state.entries
        )
        or prepared.plan.estimated_headroom_usd > state.remaining_usd
    ):
        raise DevelopmentEnsembleError(
            "development ensemble preflight refuses cumulative accounting or headroom"
        )
    if not output_dir.is_absolute() or ".." in output_dir.parts:
        raise DevelopmentEnsembleError(
            "development ensemble output must be absolute and normalized"
        )
    parent = observe_unlinked_directory(
        output_dir.parent, label="development ensemble output parent"
    )
    output_dir.mkdir(mode=0o700)
    require_same_unlinked_directory_objects(parent, label="development ensemble output parent")
    custody = observe_unlinked_directory(output_dir, label="development ensemble output")
    bindings = [_write(output_dir, "plan.json", prepared.plan)]
    if benchmark_binding is not None:
        bindings.append(_write(output_dir, "benchmark-plan.json", benchmark_binding))
    child_custody: list[DirectoryCustodyObservation] = []

    def require_outputs() -> None:
        require_same_unlinked_directory_objects(custody, label="development ensemble output")
        for child in child_custody:
            require_same_unlinked_directory_objects(
                child, label="development ensemble child output"
            )
        for binding in bindings:
            revalidate_evidence_file_binding(
                evidence_root=output_dir,
                binding=binding,
                max_bytes=MAX_DEVELOPMENT_ENSEMBLE_ARTIFACT_BYTES,
            )

    started = time.monotonic()
    deadline = started + prepared.plan.maximum_run_seconds

    def remaining() -> float:
        require_outputs()
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("development ensemble whole-run deadline exhausted")
        return min(value, 1800.0)

    candidate: DevelopmentAuditObservation | None = None
    plans: list[DevelopmentJudgmentPlan] = []
    judgments: list[DevelopmentJudgmentObservation] = []
    reason: _StopReason | None = None
    interruption: BaseException | None = None
    try:
        async with asyncio.timeout(prepared.plan.maximum_run_seconds):
            candidate = await run_development_audit(
                prepared=prepared.candidate,
                ledger=ledger,
                operator_secrets=operator_secrets,
                output_dir=output_dir / "candidate",
                allow_code_egress=allow_code_egress,
                maximum_run_seconds=remaining(),
                mock_transport=mock_transport,
            )
            require_outputs()
            child_custody.append(
                observe_unlinked_directory(
                    output_dir / "candidate", label="development ensemble child output"
                )
            )
            bindings.extend(_bind_stage_outputs(output_dir, "candidate", candidate))
            if candidate.status != "OBSERVED_ALL_SHARDS":
                reason = "CANDIDATE_INCOMPLETE"
            elif development_ensemble_claims(candidate, ()):
                for role, metadata in zip(
                    prepared.plan.reviewers, prepared.reviewer_metadata, strict=True
                ):
                    remaining()
                    review = prepare_development_judgment(
                        candidate=candidate,
                        policy=prepared.plan.policy,
                        endpoint_snapshot=metadata,
                        source_files=prepared.candidate.shards[0].source_files,
                        run_id=role.run_id,
                        maximum_completion_tokens=role.maximum_completion_tokens,
                    )
                    plans.append(review.plan)
                    bindings.append(_write(output_dir, role.stage_id + "-plan.json", review.plan))
                    excluded = tuple(
                        shard.generation_id
                        for judgment in judgments
                        for shard in judgment.observations
                        if shard.generation_id is not None
                    )
                    judgment = await run_development_judgment(
                        prepared=review,
                        ledger=ledger,
                        operator_secrets=operator_secrets,
                        output_dir=output_dir / role.stage_id,
                        allow_code_egress=allow_code_egress,
                        maximum_run_seconds=remaining(),
                        mock_transport=mock_transport,
                        excluded_generation_ids=excluded,
                    )
                    judgments.append(judgment)
                    require_outputs()
                    child_custody.append(
                        observe_unlinked_directory(
                            output_dir / role.stage_id, label="development ensemble child output"
                        )
                    )
                    bindings.extend(_bind_stage_outputs(output_dir, role.stage_id, judgment))
                    if judgment.status != "OBSERVED_ALL_JUDGMENTS":
                        reason = "REVIEW_INCOMPLETE"
                        break
            remaining()
    except (asyncio.CancelledError, KeyboardInterrupt, SystemExit) as exc:
        interruption = exc
        reason = "INTERRUPTED"
    except Exception:
        reason = "LOCAL_FAILURE"
    try:
        observation = _report(
            prepared,
            ledger,
            candidate,
            plans,
            judgments,
            "MOCK_HTTP" if mock_transport is not None else "HTTP_OBSERVATION",
            reason,
            time.monotonic() - started,
        )
        require_outputs()
        bindings.append(
            _write(
                output_dir,
                "result.json",
                observation,
                max_bytes=MAX_DEVELOPMENT_ENSEMBLE_ARTIFACT_BYTES,
            )
        )
        require_outputs()
        if benchmark_binding is not None:
            from mmaudit.benchmark.development_ensemble import score_development_ensemble

            score = score_development_ensemble(binding=benchmark_binding, observation=observation)
            bindings.append(
                _write(
                    output_dir,
                    "score.json",
                    score,
                    max_bytes=MAX_DEVELOPMENT_ENSEMBLE_ARTIFACT_BYTES,
                )
            )
            require_outputs()
    except Exception:
        if interruption is not None:
            raise interruption from None
        raise DevelopmentEnsembleError(
            "development ensemble output/accounting could not be finalized"
        ) from None
    if interruption is not None:
        raise interruption
    return observation
