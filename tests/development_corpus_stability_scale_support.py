"""Maximum synthetic retained inputs; repeated source lines are not independent semantic truth."""

from __future__ import annotations

import hashlib
import json

from mmaudit.benchmark.development_corpus import (
    bind_development_corpus_benchmark,
    score_development_corpus,
)
from mmaudit.benchmark.development_corpus_resume import score_development_corpus_resume
from mmaudit.models.development_corpus import (
    DevelopmentCorpusMaterial,
    DevelopmentCorpusObservation,
    DevelopmentCorpusResponse,
    DevelopmentCorpusText,
)
from mmaudit.models.development_corpus_resume import freeze_development_corpus_resume_history
from tests.development_corpus_judgment_support import pure_candidate
from tests.development_corpus_resume_score_support import maximum_scoring_case
from tests.development_corpus_resume_support import append_attempt, pure_attempt, selected_resume


def maximum_stability_score(*, complete=True, cumulative=False, request_timeout_seconds=None):
    prepared, labels, responses = maximum_scoring_case()
    policy = prepared.plan.policy.model_copy(
        update={"request_timeout_seconds": request_timeout_seconds}
    )
    sources = prepared.shards[0].source_files
    observed_count = 0 if cumulative else 64 if complete else 63
    _, original = pure_candidate(
        source_files=sources, policy=policy, observed_count=observed_count, claims=16
    )
    data = original.model_dump()
    for observed, response in zip(data["observations"], responses, strict=False):
        raw = json.dumps(response).encode()
        observed["response"] = DevelopmentCorpusResponse.model_validate_json(raw, strict=True)
        observed["response_sha256"] = hashlib.sha256(raw).hexdigest()
    original = DevelopmentCorpusObservation.model_validate(data)
    binding = bind_development_corpus_benchmark(
        plan=original.plan,
        truth_content=labels.truth_file_content.encode(),
        expected_truth_sha256=labels.truth_file_sha256,
    )
    score = score_development_corpus(binding=binding, observation=original)
    if not cumulative:
        return score
    history = freeze_development_corpus_resume_history(
        original=original,
        original_score=score,
        material=DevelopmentCorpusMaterial(
            manifest=original.plan.manifest,
            sources=tuple(
                DevelopmentCorpusText(filename=n, content=b.decode()) for n, b in sources
            ),
        ),
    )
    metadata = prepared.shards[0].discovery or prepared.shards[0].endpoint_snapshot
    for _ in range(8):
        attempt = pure_attempt(selected_resume(history, metadata), observed_count=0, unknown=True)
        history = append_attempt(history, attempt)
    return score_development_corpus_resume(history=history)
