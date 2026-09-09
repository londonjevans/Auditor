"""Local paired sources and fake role metadata; no real provider or root-lineage evidence."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from mmaudit.models.development_corpus import freeze_development_corpus
from mmaudit.models.development_corpus_ensemble import (
    DevelopmentCorpusEnsembleAccountingEntry,
    DevelopmentCorpusEnsembleObservation,
    development_corpus_ensemble_claims,
    prepare_development_corpus_ensemble,
)
from mmaudit.models.development_ensemble import DEVELOPMENT_ENSEMBLE_STAGES
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from tests.development_corpus_benchmark_support import paired_payload, paired_sources
from tests.development_corpus_judgment_support import manifest_judgment_payload, selected_policy
from tests.development_corpus_support import supplied_sources
from tests.development_ensemble_support import ENSEMBLE_MODELS
from tests.development_judgment_support import judgment_metadata


def manifest_ensemble_case(*, source_files=None, **changes: Any):
    sources = paired_sources() if source_files is None else source_files
    values = dict(
        policy=selected_policy(),
        candidate_metadata=judgment_metadata(model_id=ENSEMBLE_MODELS[0]),
        reviewer_metadata=tuple(judgment_metadata(model_id=m) for m in ENSEMBLE_MODELS[1:]),
        manifest=freeze_development_corpus(
            corpus_id="synthetic-paired-manifest-ensemble",
            source_scope="OPERATOR_SUPPLIED_SYNTHETIC",
            source_files=sources,
        ),
        source_files=sources,
        run_id="synthetic-manifest-ensemble",
    )
    values.update(changes)
    return prepare_development_corpus_ensemble(**values)


def manifest_ensemble_payload(role, ordinal, *, count=1, verdict="SUPPORTED", filename=None):
    if role == 0:
        payload = paired_payload(ordinal, count=count)
    else:
        payload = manifest_judgment_payload(
            ordinal,
            count=count,
            verdict=verdict,
            filename=paired_sources()[ordinal - 1][0] if filename is None else filename,
        )
    payload["id"] = f"gen-synthetic-manifest-ensemble-{role}-{ordinal}"
    payload["model"] = ENSEMBLE_MODELS[role]
    routing = payload["openrouter_metadata"]
    routing["requested"] = payload["model"]
    routing["endpoints"]["available"][0]["model"] = payload["model"]
    routing["attempts"][0]["model"] = payload["model"]
    return payload


def maximum_manifest_sources():
    """64 structural file slots within the unchanged synthetic metadata/budget limits."""

    raw = next(raw for name, raw in supplied_sources() if name == "src/ReplayInitializer.sol")
    return tuple((f"src/control-{i:04d}/Source.sol", raw) for i in range(1, 65))


def composed_observation(plan, candidate=None, judgments=(), *, judgment_plans=None):
    """Construct aggregate model-test evidence, not an executed whole-run orchestration result."""

    judgments = tuple(judgments)
    plans = tuple(j.plan for j in judgments) if judgment_plans is None else judgment_plans
    rows = development_corpus_ensemble_claims(candidate, judgments)
    complete = (
        candidate is not None and candidate.status == "OBSERVED_ALL_SHARDS",
        *(i < len(judgments) and judgments[i].status == "OBSERVED_ALL_JUDGMENTS" for i in range(2)),
    )
    reason = (
        "CANDIDATE_INCOMPLETE"
        if not complete[0]
        else "REVIEW_INCOMPLETE"
        if rows and not all(complete)
        else None
    )
    accounting = tuple(
        DevelopmentCorpusEnsembleAccountingEntry(stage_id=stage, entry=entry)
        for stage, child in zip(DEVELOPMENT_ENSEMBLE_STAGES, (candidate, *judgments), strict=False)
        if child is not None
        for entry in child.accounting
    )
    elapsed = (candidate.elapsed_seconds if candidate is not None else 0) + sum(
        j.elapsed_seconds for j in judgments
    )
    return DevelopmentCorpusEnsembleObservation(
        plan=plan,
        candidate=candidate,
        transport="MOCK_HTTP",
        status="INCOMPLETE" if reason else "OBSERVED_ALL_STAGES" if rows else "NO_CANDIDATES",
        stop_reason=reason,
        judgment_plans=plans,
        judgments=judgments,
        accounting=accounting,
        claims=rows,
        unobserved_candidate_shard_ids=tuple(s.shard_id for s in plan.candidate.shards)
        if candidate is None
        else candidate.unobserved_shard_ids,
        unobserved_stage_ids=tuple(
            s for s, done in zip(DEVELOPMENT_ENSEMBLE_STAGES, complete, strict=True) if not done
        ),
        completed_stage_count=sum(complete),
        completed_judgment_count=sum(op is not None for r in rows for op in r.opinions),
        available_claim_reviews_complete=bool(rows) and all(None not in r.opinions for r in rows),
        total_accounted_cost_usd=sum((r.entry.accounted_cost_usd for r in accounting), Decimal(0)),
        reported_actual_cost_usd=sum(
            (r.entry.actual_cost_usd or Decimal(0) for r in accounting), Decimal(0)
        ),
        uncertain_accounted_cost_usd=sum(
            (
                r.entry.accounted_cost_usd
                for r in accounting
                if r.entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
            ),
            Decimal(0),
        ),
        active_reserved_usd=sum(
            (
                r.entry.reserved_usd
                for r in accounting
                if r.entry.status is CostEntryStatus.RESERVED
            ),
            Decimal(0),
        ),
        elapsed_seconds=elapsed + 1,
        observed_stage_elapsed_seconds=elapsed,
    )
