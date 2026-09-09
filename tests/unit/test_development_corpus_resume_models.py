"""Pure bounded history/plan controls; no provider execution or semantic audit credit."""

from __future__ import annotations

import json
import socket
import subprocess
from decimal import Decimal

import pytest

from mmaudit.benchmark.development_corpus import score_development_corpus
from mmaudit.models.development_corpus import DevelopmentCorpusMaterial, DevelopmentCorpusText
from mmaudit.models.development_corpus_resume import (
    DevelopmentCorpusResumeAttempt,
    DevelopmentCorpusResumeHistory,
    DevelopmentCorpusResumePlan,
    freeze_development_corpus_resume_history,
    prepare_development_corpus_resume,
)
from mmaudit.orchestration.manifest import canonical_sha256
from tests.development_corpus_benchmark_support import paired_observation, paired_sources
from tests.development_corpus_judgment_support import selected_policy
from tests.development_corpus_resume_support import (
    append_attempt,
    pure_attempt,
    resume_case,
    selected_resume,
)
from tests.development_corpus_support import CORPUS_MODEL
from tests.development_judgment_support import judgment_metadata


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("pure continuation contract attempted real network or process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def reseal(data, field):
    data[field] = canonical_sha256({k: v for k, v in data.items() if k != field})
    return data


@pytest.mark.parametrize("claims", [0, 1, 16])
@pytest.mark.parametrize("observed_count", [0, 1, 3])
def test_continuation_selects_only_gaps_and_preserves_the_complete_request_context(
    claims, observed_count
):
    history, metadata = resume_case(claims=claims, observed_count=observed_count)
    original_bytes = history.original.model_dump_json()
    prepared = selected_resume(history, metadata)
    assert prepared.plan.selected_shard_ids == history.original.unobserved_shard_ids
    assert len(prepared.plan.reused_observed_shard_ids) == observed_count
    for old, new in zip(history.original.plan.shards, prepared.candidate.shards, strict=True):
        assert old.estimate.request_sha256 == new.estimate.request_sha256
        assert old.estimate.request_id != new.estimate.request_id
        assert new.source_files == history.material.source_files
    completed = append_attempt(history, pure_attempt(prepared, claims=claims))
    assert completed.original.model_dump_json() == original_bytes
    assert completed.summary.original_first_attempt_status == "INCOMPLETE"
    assert completed.summary.original_first_attempt_completed_shard_count == observed_count
    assert completed.summary.cumulative_completed_shard_count == 4
    assert completed.summary.candidate_claim_count == 4 * claims
    assert completed.summary.total_accounted_cost_usd == Decimal("0.04")
    assert completed.summary.sum_run_elapsed_seconds == 2
    assert completed.summary.between_run_wait_seconds is None
    assert completed.summary.status == "OBSERVED_ALL_SOURCES_ACROSS_RECORDED_ATTEMPTS"
    assert completed.summary.accounted_request_count == 4 and not completed.audit_complete
    assert (
        DevelopmentCorpusResumeHistory.model_validate_json(completed.model_dump_json()) == completed
    )


def test_multiple_flat_stages_preserve_unknown_costs_and_never_replay_observed_sources():
    history, metadata = resume_case(policy=selected_policy(carry=True))
    first = selected_resume(history, metadata)
    incomplete = append_attempt(history, pure_attempt(first, observed_count=1, unknown=True))
    second = selected_resume(incomplete, metadata)
    assert second.plan.selected_shard_ids == ("file-0004",)
    completed = append_attempt(incomplete, pure_attempt(second))
    retained_unknown = incomplete.continuations[0].accounting[-1].accounted_cost_usd
    assert completed.summary.total_accounted_cost_usd == Decimal("0.04") + retained_unknown
    assert completed.summary.uncertain_accounted_cost_usd == retained_unknown
    assert completed.summary.reported_actual_cost_usd == Decimal("0.04")
    assert completed.summary.accounted_request_count == 5
    assert completed.continuations[0] == incomplete.continuations[0]
    assert (
        completed.summary.continuation_count == 2 and completed.summary.sum_run_elapsed_seconds == 3
    )


def test_original_score_and_raw_declared_labels_never_become_a_merged_first_attempt_score():
    binding, original = paired_observation(observed_count=3)
    score = score_development_corpus(binding=binding, observation=original)
    material = DevelopmentCorpusMaterial(
        manifest=original.plan.manifest,
        sources=tuple(
            DevelopmentCorpusText(filename=n, content=b.decode()) for n, b in paired_sources()
        ),
    )
    history = freeze_development_corpus_resume_history(
        original=original, material=material, original_score=score
    )
    prepared = selected_resume(history, judgment_metadata(model_id=CORPUS_MODEL))
    complete = append_attempt(history, pure_attempt(prepared))
    assert complete.original_score.model_dump_json() == score.model_dump_json()
    assert complete.original_score.summary.quality_scope == "INCOMPLETE_OBSERVATIONS"
    assert complete.original_score.binding.truth_file_content == binding.truth_file_content
    assert complete.summary.cumulative_completed_shard_count == 6
    assert complete.original.completed_shard_count == 3 and not complete.qualification_eligible


@pytest.mark.parametrize("kind", ["complete", "same_run", "changed_model", "wrong_type", "limit"])
def test_preparation_refuses_no_work_replay_selection_drift_and_unbounded_history(kind):
    history, metadata = resume_case(observed_count=4 if kind == "complete" else 2)
    if kind == "limit":
        for _ in range(8):
            prepared = selected_resume(history, metadata)
            history = append_attempt(history, pure_attempt(prepared, observed_count=0))
    if kind == "wrong_type":
        history = history.model_dump()
    with pytest.raises(ValueError):
        prepare_development_corpus_resume(
            history=history,
            endpoint_snapshot=judgment_metadata(model_id="synthetic/different-model")
            if kind == "changed_model"
            else metadata,
            run_id="synthetic-corpus" if kind == "same_run" else "synthetic-next-stage",
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("prior_history_sha256", "0" * 64),
        ("original_candidate_sha256", "0" * 64),
        ("continuation_index", 2),
        ("selected_shard_ids", ("file-0002", "file-0003", "file-0004")),
        ("reused_observed_shard_ids", ("file-0001",)),
        ("estimated_continuation_cost_usd", Decimal("0.01")),
    ],
)
def test_self_rehashed_plan_changes_do_not_create_valid_ancestry(field, value):
    history, metadata = resume_case()
    prepared = selected_resume(history, metadata)
    data = prepared.plan.model_dump(mode="json")
    data[field] = value if not isinstance(value, Decimal) else str(value)
    with pytest.raises(ValueError):
        changed = DevelopmentCorpusResumePlan.model_validate_json(
            json.dumps(reseal(data, "plan_sha256")), strict=True
        )
        attempt = pure_attempt(prepared).model_copy(update={"plan": changed})
        append_attempt(history, attempt)


@pytest.mark.parametrize(
    "kind",
    [
        "generation",
        "reservation",
        "missing_account",
        "account_cost",
        "reordered",
        "status",
        "elapsed",
        "transport",
        "original",
        "source",
        "summary",
        "authority",
        "digest",
    ],
)
def test_nested_tampering_cannot_reseal_cumulative_scope_or_history(kind):
    history, metadata = resume_case()
    completed = append_attempt(history, pure_attempt(selected_resume(history, metadata)))
    data = completed.model_dump(mode="json")
    current = data["continuations"][0]
    if kind == "generation":
        current["observations"][0]["generation_id"] = data["original"]["observations"][0][
            "generation_id"
        ]
    elif kind == "reservation":
        current["accounting"][0]["reservation_id"] = data["original"]["accounting"][0][
            "reservation_id"
        ]
    elif kind == "missing_account":
        current["accounting"].pop()
    elif kind == "account_cost":
        current["accounting"][0]["accounted_cost_usd"] = "0"
    elif kind == "reordered":
        current["observations"].reverse()
    elif kind == "status":
        current.update(status="INCOMPLETE", stop_reason=None)
    elif kind == "elapsed":
        current["elapsed_seconds"] = 0.0
    elif kind == "transport":
        current["transport"] = "HTTP_OBSERVATION"
    elif kind == "original":
        data["original"]["elapsed_seconds"] = 1.5
    elif kind == "source":
        data["material"]["sources"][0]["content"] += "\n"
    elif kind == "summary":
        data["summary"]["original_first_attempt_completed_shard_count"] = 4
    elif kind == "authority":
        data["audit_complete"] = True
    if kind != "digest":
        reseal(data, "history_sha256")
    else:
        data["history_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        DevelopmentCorpusResumeHistory.model_validate_json(json.dumps(data), strict=True)


def test_flat_ancestry_cannot_drop_or_reorder_an_earlier_continuation():
    history, metadata = resume_case()
    first = append_attempt(
        history, pure_attempt(selected_resume(history, metadata), observed_count=1)
    )
    second = append_attempt(first, pure_attempt(selected_resume(first, metadata)))
    for attempts in (second.continuations[1:], tuple(reversed(second.continuations))):
        with pytest.raises(ValueError):
            freeze_development_corpus_resume_history(
                original=history.original, material=history.material, continuations=attempts
            )


def test_attempt_cannot_keep_dispatching_after_an_unknown_response():
    history, metadata = resume_case(policy=selected_policy(carry=True), observed_count=0)
    prepared = selected_resume(history, metadata)
    failed = pure_attempt(prepared, observed_count=1, unknown=True)
    complete = pure_attempt(prepared)
    with pytest.raises(ValueError):
        DevelopmentCorpusResumeAttempt.model_validate(
            {
                **failed.model_dump(),
                "observations": (*failed.observations, complete.observations[2]),
                "accounting": (*failed.accounting, complete.accounting[2]),
            }
        )


def test_maximum_manifest_claims_remain_originally_scoped_across_continuation():
    history, metadata = resume_case(
        count=64, observed_count=1, claims=16, policy=selected_policy(total="250", per_attempt="4")
    )
    prepared = selected_resume(history, metadata)
    completed = append_attempt(history, pure_attempt(prepared, claims=16))
    assert len(prepared.plan.selected_shard_ids) == 63
    assert completed.summary.candidate_claim_count == 1024
    assert completed.summary.cumulative_completed_shard_count == 64
    assert completed.summary.accounted_request_count == 64
    assert completed.original.completed_shard_count == 1
    assert completed.material == history.material and not completed.audit_complete


@pytest.mark.parametrize(
    "field,value",
    [
        ("selected_shard_ids", []),
        ("selected_shard_ids", ["file-0004", "file-0003"]),
        ("selected_shard_ids", ["file-0003", "file-0003", "file-0004"]),
        ("selected_shard_ids", ["file-0003", "file-9999"]),
        ("reused_observed_shard_ids", ["file-0001", "file-0001", "file-0002"]),
        ("reused_observed_shard_ids", ["file-0001", "file-0002", "file-0003"]),
        ("continuation_index", 0),
        ("continuation_index", 9),
        ("continuation_index", True),
    ],
)
def test_plan_partition_and_stage_bounds_are_not_digest_only(field, value):
    history, metadata = resume_case()
    data = selected_resume(history, metadata).plan.model_dump(mode="json")
    data[field] = value
    with pytest.raises(ValueError):
        DevelopmentCorpusResumePlan.model_validate_json(json.dumps(reseal(data, "plan_sha256")))


def test_nonfinite_summed_child_duration_is_a_controlled_validation_refusal():
    history, metadata = resume_case()
    attempt = pure_attempt(selected_resume(history, metadata))
    data = attempt.model_dump(mode="json")
    data["elapsed_seconds"] = 1e308
    for observation in data["observations"]:
        observation["elapsed_seconds"] = 1e308
    with pytest.raises(ValueError):
        DevelopmentCorpusResumeAttempt.model_validate_json(json.dumps(data), strict=True)
