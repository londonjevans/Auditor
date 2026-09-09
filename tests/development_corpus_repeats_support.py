"""Repeat only existing paired synthetic source/labels; no external truth or provider execution."""

from mmaudit.models.development_corpus_repeats import prepare_development_corpus_repeats
from tests.development_corpus_benchmark_support import paired_case, paired_payload, truth_binding


def repeat_case(**changes):
    candidate = paired_case()
    binding = truth_binding(candidate)
    first = candidate.shards[0]
    values = dict(
        policy=candidate.plan.policy,
        endpoint_snapshot=first.discovery or first.endpoint_snapshot,
        manifest=candidate.plan.manifest,
        source_files=first.source_files,
        run_id="synthetic-repeat-series",
        trial_count=2,
        truth_content=binding.truth_file_content.encode(),
        expected_truth_sha256=binding.truth_file_sha256,
    )
    values.update(changes)
    return prepare_development_corpus_repeats(**values)


def repeat_payload(ordinal, primary_index=None):
    payload = paired_payload(primary_index or (ordinal - 1) % 6 + 1)
    payload["id"] = f"gen-synthetic-repeat-{ordinal}"
    return payload
