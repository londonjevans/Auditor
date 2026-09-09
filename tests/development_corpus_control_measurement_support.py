"""Synthetic retained-score controls built only from existing local paired fixtures."""

from __future__ import annotations

from mmaudit.benchmark.development_corpus import score_development_corpus
from mmaudit.benchmark.development_corpus_resume import score_development_corpus_resume
from tests.development_corpus_benchmark_support import paired_observation, paired_response
from tests.development_corpus_resume_score_support import extend_labelled, labelled_history


def original_score(**changes):
    binding, observation = paired_observation(**changes)
    return score_development_corpus(binding=binding, observation=observation)


def direct_responses(*, advisory=False, severity="high"):
    responses = [
        paired_response(i, count=int(i in {1, 4}), guarded_empty=False, advisory=advisory)
        for i in range(1, 7)
    ]
    for response in responses:
        for finding in response["findings"]:
            finding["severity"] = severity
    return responses


def retained_score(*, cumulative=False, complete=True, responses=None):
    if not cumulative:
        return original_score(observed_count=6 if complete else 1, responses=responses)
    history, metadata = labelled_history(responses=responses)
    history = extend_labelled(
        history,
        metadata,
        responses=responses,
        observed_count=None if complete else 0,
        unknown=not complete,
    )
    return score_development_corpus_resume(history=history)
