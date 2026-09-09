"""Constructed local continuation controls, not executed provider or audit evidence."""

from __future__ import annotations

import hashlib
from decimal import Decimal

from mmaudit.models.development_audit import development_ledger_request_id
from mmaudit.models.development_corpus import (
    DevelopmentCorpusAccountingEntry,
    DevelopmentCorpusMaterial,
    DevelopmentCorpusShardObservation,
    DevelopmentCorpusText,
)
from mmaudit.models.development_corpus_resume import (
    DevelopmentCorpusResumeAttempt,
    freeze_development_corpus_resume_history,
    prepare_development_corpus_resume,
)
from mmaudit.models.development_review import DevelopmentReviewDiagnostic
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from tests.development_corpus_judgment_support import pure_candidate


def resume_case(*, count=4, observed_count=2, claims=1, policy=None, endpoint_snapshot=None):
    prepared, original = pure_candidate(
        count=count,
        observed_count=observed_count,
        claims=claims,
        policy=policy,
        endpoint_snapshot=endpoint_snapshot,
    )
    material = DevelopmentCorpusMaterial(
        manifest=prepared.plan.manifest,
        sources=tuple(
            DevelopmentCorpusText(filename=name, content=raw.decode())
            for name, raw in prepared.shards[0].source_files
        ),
    )
    metadata = prepared.shards[0].discovery or prepared.shards[0].endpoint_snapshot
    return freeze_development_corpus_resume_history(original=original, material=material), metadata


def selected_resume(history, metadata, *, run_id=None):
    return prepare_development_corpus_resume(
        history=history,
        endpoint_snapshot=metadata,
        run_id=run_id or f"synthetic-continuation-{len(history.continuations) + 1}",
    )


def pure_attempt(prepared, *, observed_count=None, claims=1, unknown=False):
    plan = prepared.plan
    selected = [s for s in prepared.candidate.shards if s.shard_id in plan.selected_shard_ids]
    observed_count = len(selected) if observed_count is None else observed_count
    _, template = pure_candidate(
        source_files=prepared.history.material.source_files,
        claims=claims,
        policy=prepared.history.original.plan.policy,
        endpoint_snapshot=selected[0].discovery or selected[0].endpoint_snapshot,
    )
    templates = {s.shard_id: s for s in template.observations}
    observations, entries = [], []
    for index, shard in enumerate(selected[: observed_count + int(unknown)]):
        failed = unknown and index == observed_count
        charge = shard.estimate.estimated_cost_per_attempt_usd if failed else Decimal("0.01")
        status = CostEntryStatus.UNCERTAIN_ACCOUNTED if failed else CostEntryStatus.RECONCILED
        data = templates[shard.shard_id].model_dump()
        data.update(
            run_id=plan.candidate.run_id,
            estimate=shard.estimate,
            generation_id=None
            if failed
            else f"gen-synthetic-resume-{plan.continuation_index}-{shard.shard_id}",
            accounted_cost_usd=charge,
            accounting_status=status,
            reported_cost_usd=None if failed else charge,
        )
        if failed:
            data.update(
                status="INCOMPLETE",
                response=None,
                diagnostics=(DevelopmentReviewDiagnostic.UNKNOWN_COST,),
                http_status=429,
            )
        observations.append(DevelopmentCorpusShardObservation.model_validate(data))
        entries.append(
            DevelopmentCorpusAccountingEntry(
                shard_id=shard.shard_id,
                ledger_request_id=development_ledger_request_id(shard.estimate.request_id),
                reservation_id=hashlib.sha256(
                    (plan.candidate.run_id + "-" + shard.shard_id).encode()
                ).hexdigest()[:32],
                status=status,
                reserved_usd=shard.estimate.estimated_cost_per_attempt_usd,
                actual_cost_usd=None if failed else charge,
                accounted_cost_usd=charge,
            )
        )
    complete = observed_count == len(selected) and not unknown
    return DevelopmentCorpusResumeAttempt(
        plan=plan,
        transport=prepared.history.original.transport,
        status="OBSERVED_ALL_SELECTED_SHARDS" if complete else "INCOMPLETE",
        stop_reason=None if complete else "SHARD_INCOMPLETE" if unknown else "LOCAL_FAILURE",
        observations=tuple(observations),
        accounting=tuple(entries),
        elapsed_seconds=1.0,
    )


def append_attempt(history, attempt):
    return freeze_development_corpus_resume_history(
        original=history.original,
        material=history.material,
        original_score=history.original_score,
        continuations=(*history.continuations, attempt),
    )
