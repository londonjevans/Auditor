"""Constructed paired-source scoring histories; no executed provider evidence or external truth."""

from __future__ import annotations

import hashlib
import json

from mmaudit.benchmark.development_corpus import (
    DevelopmentCorpusBenchmarkTruth,
    score_development_corpus,
)
from mmaudit.models.development_corpus import (
    DevelopmentCorpusMaterial,
    DevelopmentCorpusResponse,
    DevelopmentCorpusShardObservation,
    DevelopmentCorpusText,
)
from mmaudit.models.development_corpus_resume import (
    DevelopmentCorpusResumeAttempt,
    freeze_development_corpus_resume_history,
)
from tests.development_corpus_benchmark_support import (
    labelled_truth,
    paired_case,
    paired_observation,
    paired_response,
    paired_sources,
    truth_binding,
)
from tests.development_corpus_judgment_support import selected_policy
from tests.development_corpus_resume_support import append_attempt, pure_attempt, selected_resume
from tests.development_corpus_support import CORPUS_MODEL, corpus_case
from tests.development_judgment_support import judgment_metadata


def labelled_history(*, observed_count=1, responses=None, both_planted=False):
    binding, original = paired_observation(
        observed_count=observed_count,
        responses=responses,
        both_planted=both_planted,
        policy=selected_policy(carry=True),
    )
    history = freeze_development_corpus_resume_history(
        original=original,
        material=DevelopmentCorpusMaterial(
            manifest=original.plan.manifest,
            sources=tuple(
                DevelopmentCorpusText(filename=n, content=b.decode()) for n, b in paired_sources()
            ),
        ),
        original_score=score_development_corpus(binding=binding, observation=original),
    )
    return history, judgment_metadata(model_id=CORPUS_MODEL)


def extend_labelled(history, metadata, *, observed_count=None, unknown=False, responses=None):
    prepared = selected_resume(history, metadata)
    attempt = pure_attempt(prepared, observed_count=observed_count, unknown=unknown)
    responses = tuple(paired_response(i) for i in range(1, 7)) if responses is None else responses
    retained = []
    for shard in attempt.observations:
        if shard.status != "OBSERVED":
            retained.append(shard)
            continue
        response = responses[int(shard.shard_id[-4:]) - 1]
        retained.append(
            DevelopmentCorpusShardObservation.model_validate(
                {
                    **shard.model_dump(),
                    "response": DevelopmentCorpusResponse.model_validate_json(json.dumps(response)),
                    "response_sha256": hashlib.sha256(json.dumps(response).encode()).hexdigest(),
                }
            )
        )
    attempt = DevelopmentCorpusResumeAttempt.model_validate(
        {**attempt.model_dump(), "observations": tuple(retained)}
    )
    return append_attempt(history, attempt)


def maximum_scoring_case():
    """Repeated existing safe source with line labels tests scale, not independent semantic roots."""

    raw = paired_sources()[0][1]
    sources = tuple((f"src/control-{i:04d}/Source.sol", raw) for i in range(1, 65))
    prepared = corpus_case(
        source_files=sources, policy=selected_policy(carry=True, total="250", per_attempt="5")
    )
    seed = labelled_truth(paired_case()).controls[0].model_dump(mode="json")
    controls, responses = [], []
    for index, (filename, _) in enumerate(sources, 1):
        response = paired_response(1)
        template = response["findings"][0]
        findings = []
        for line in range(1, 17):
            ref = {"filename": filename, "line_start": line, "line_end": line}
            controls.append(
                {
                    **seed,
                    "control_id": f"control-{index:04d}-{line:02d}",
                    "severity": "critical",
                    "origin": ref,
                    "required_origin_line": line,
                    "claim_sites": [ref],
                }
            )
            findings.append(
                {
                    **template,
                    "line_start": line,
                    "line_end": line,
                    "severity": "critical",
                    "vulnerability_class": seed["vulnerability_class"],
                    "root_cause_ref": ref,
                }
            )
        response["findings"] = findings
        responses.append(response)
    truth = DevelopmentCorpusBenchmarkTruth.model_validate_json(
        json.dumps(
            {
                "truth_id": "synthetic-maximum-continuation-structural-labels",
                "provenance": "AGENT_CONSTRUCTED_DEVELOPMENT_CONTROLS",
                "manifest": prepared.plan.manifest.model_dump(mode="json"),
                "controls": controls,
            }
        ),
        strict=True,
    )
    return prepared, truth_binding(prepared, truth), tuple(responses)
