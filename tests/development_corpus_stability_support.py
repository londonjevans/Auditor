"""Re-key only synthetic fixture observations to exercise disjoint retained-run evidence."""

from __future__ import annotations

import hashlib
import json

from mmaudit.benchmark.development_corpus import (
    bind_development_corpus_benchmark,
    score_development_corpus,
)
from mmaudit.benchmark.development_corpus_control_measurement import (
    measure_development_corpus_controls,
)
from mmaudit.benchmark.development_corpus_resume import score_development_corpus_resume
from mmaudit.models.development_audit import development_ledger_request_id
from mmaudit.models.development_corpus import (
    DevelopmentCorpusPlan,
    development_corpus_request_id,
)
from mmaudit.models.development_corpus_resume import (
    DevelopmentCorpusResumeAttempt,
    DevelopmentCorpusResumePlan,
    freeze_development_corpus_resume_history,
)
from mmaudit.orchestration.manifest import canonical_sha256
from tests.development_corpus_control_measurement_support import retained_score


def rekey_plan(plan, run_id):
    data = plan.model_dump(mode="json")
    data["run_id"] = run_id
    for shard in data["shards"]:
        shard["estimate"]["request_id"] = development_corpus_request_id(
            run_id, plan.manifest, shard["primary_filename"]
        )
    data["plan_sha256"] = canonical_sha256({k: v for k, v in data.items() if k != "plan_sha256"})
    return DevelopmentCorpusPlan.model_validate_json(json.dumps(data), strict=True)


def rekey_stage(stage, plan, *, keep_generations=False, keep_reservations=False):
    data = stage.model_dump()
    candidate = plan if isinstance(plan, DevelopmentCorpusPlan) else plan.candidate
    data["plan"] = plan
    shards = {s.shard_id: s for s in candidate.shards}
    for observed in data["observations"]:
        observed["run_id"] = candidate.run_id
        observed["estimate"] = shards[observed["shard_id"]].estimate
        if observed["generation_id"] is not None and not keep_generations:
            observed["generation_id"] = "gen-" + candidate.run_id + "-" + observed["shard_id"]
    for account in data["accounting"]:
        request_id = shards[account["shard_id"]].estimate.request_id
        account["ledger_request_id"] = development_ledger_request_id(request_id)
        if not keep_reservations:
            account["reservation_id"] = hashlib.sha256(request_id.encode()).hexdigest()[:32]
    return type(stage).model_validate(data)


def rekey_score(score, run_id, *, keep_generations=False, keep_reservations=False):
    cumulative = score.artifact_kind == "development_corpus_resume_benchmark_score"
    original = score.history.original if cumulative else score.observation
    original_score = score.history.original_score if cumulative else score
    plan = rekey_plan(original.plan, run_id)
    candidate = rekey_stage(
        original, plan, keep_generations=keep_generations, keep_reservations=keep_reservations
    )
    labels = original_score.binding
    binding = bind_development_corpus_benchmark(
        plan=plan,
        truth_content=labels.truth_file_content.encode(),
        expected_truth_sha256=labels.truth_file_sha256,
    )
    result = score_development_corpus(binding=binding, observation=candidate)
    if not cumulative:
        return result
    history = freeze_development_corpus_resume_history(
        original=candidate, original_score=result, material=score.history.material
    )
    for index, old in enumerate(score.history.continuations, 1):
        data = old.plan.model_dump(mode="json")
        data.update(
            candidate=rekey_plan(old.plan.candidate, run_id + "-stage-" + str(index)).model_dump(
                mode="json"
            ),
            prior_history_sha256=history.history_sha256,
            original_candidate_sha256=canonical_sha256(candidate.model_dump(mode="json")),
        )
        data["plan_sha256"] = canonical_sha256(
            {k: v for k, v in data.items() if k != "plan_sha256"}
        )
        next_plan = DevelopmentCorpusResumePlan.model_validate_json(json.dumps(data), strict=True)
        attempt = rekey_stage(
            old, next_plan, keep_generations=keep_generations, keep_reservations=keep_reservations
        )
        assert isinstance(attempt, DevelopmentCorpusResumeAttempt)
        history = freeze_development_corpus_resume_history(
            original=candidate,
            original_score=result,
            material=history.material,
            continuations=(*history.continuations, attempt),
        )
    return score_development_corpus_resume(history=history)


def trial(run_id, *, score=None, keep_generations=False, keep_reservations=False, **changes):
    score = retained_score(**changes) if score is None else score
    return measure_development_corpus_controls(
        score=rekey_score(
            score, run_id, keep_generations=keep_generations, keep_reservations=keep_reservations
        )
    )
