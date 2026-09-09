"""Explicit agent-constructed label projections of existing safe paired fixtures, not external truth."""

from __future__ import annotations

import hashlib
import json

from mmaudit.benchmark.development_corpus import (
    DevelopmentCorpusBenchmarkTruth,
    bind_development_corpus_benchmark,
)
from mmaudit.models.development_corpus import (
    DevelopmentCorpusObservation,
    DevelopmentCorpusResponse,
)
from tests.development_audit_support import corpus_sources
from tests.development_benchmark_support import (
    benchmark_truth,
    scored_file_response,
    scored_payload,
)
from tests.development_corpus_judgment_support import pure_candidate
from tests.development_corpus_support import CORPUS_MODEL, corpus_case


def paired_sources():
    return tuple(
        (f"src/{variant}/{name}", content)
        for variant in ("a", "b")
        for name, content in corpus_sources(variant)
    )


def labelled_truth(prepared, *, both_planted=False):
    controls = []
    for variant in ("a", "b"):
        control = benchmark_truth(variant).controls[0].model_dump(mode="json")
        control["control_id"] = variant + "-" + control["control_id"]
        if both_planted:
            control["expected"] = "PLANTED"
        for ref in (control["origin"], *control["claim_sites"]):
            ref["filename"] = f"src/{variant}/" + ref["filename"]
        controls.append(control)
    # The optional both_planted value is an intentionally incorrect-label negative control.
    return DevelopmentCorpusBenchmarkTruth.model_validate_json(
        json.dumps(
            dict(
                truth_id="synthetic-paired-nested-labels",
                provenance="AGENT_CONSTRUCTED_DEVELOPMENT_CONTROLS",
                manifest=prepared.plan.manifest.model_dump(mode="json"),
                controls=controls,
            )
        ),
        strict=True,
    )


def truth_binding(prepared, truth=None):
    truth = labelled_truth(prepared) if truth is None else truth
    content = truth.model_dump_json(indent=2).encode()
    return bind_development_corpus_benchmark(
        plan=prepared.plan,
        truth_content=content,
        expected_truth_sha256=hashlib.sha256(content).hexdigest(),
    )


def paired_response(ordinal, *, count=1, guarded_empty=True, advisory=False):
    variant = "a" if ordinal <= 3 else "b"
    response = scored_file_response((ordinal - 1) % 3 + 1, advisory=advisory)
    response["schema_version"] = "3.0"
    for finding in response["findings"]:
        if finding["root_cause_ref"] is not None:
            finding["root_cause_ref"]["filename"] = (
                f"src/{variant}/" + finding["root_cause_ref"]["filename"]
            )
    response["findings"] = response["findings"] * (0 if guarded_empty and variant == "b" else count)
    return response


def paired_payload(ordinal, **changes):
    payload = scored_payload(1, response=paired_response(ordinal, **changes))
    payload["id"] = f"gen-synthetic-corpus-{ordinal}"
    payload["model"] = CORPUS_MODEL
    routing = payload["openrouter_metadata"]
    routing["requested"] = CORPUS_MODEL
    routing["endpoints"]["available"][0]["model"] = CORPUS_MODEL
    routing["attempts"][0]["model"] = CORPUS_MODEL
    return payload


def paired_case(**changes):
    return corpus_case(source_files=paired_sources(), **changes)


def paired_observation(*, observed_count=6, responses=None, both_planted=False):
    responses = tuple(paired_response(i) for i in range(1, 7)) if responses is None else responses
    prepared, candidate = pure_candidate(
        source_files=paired_sources(),
        observed_count=observed_count,
        claims=tuple(len(r["findings"]) for r in responses),
    )
    data = candidate.model_dump()
    shards = []
    for shard, response in zip(candidate.observations, responses, strict=False):
        fields = shard.model_dump()
        fields["response"] = DevelopmentCorpusResponse.model_validate_json(json.dumps(response))
        fields["response_sha256"] = hashlib.sha256(json.dumps(response).encode()).hexdigest()
        shards.append(fields)
    data["observations"] = tuple(shards)
    observation = DevelopmentCorpusObservation.model_validate(data)
    return truth_binding(prepared, labelled_truth(prepared, both_planted=both_planted)), observation
