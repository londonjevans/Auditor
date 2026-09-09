"""Synthetic retained-label measurements, never external ground truth or real execution evidence."""

from __future__ import annotations

import json
import socket
import subprocess
from decimal import Decimal

import pytest

import mmaudit.benchmark.development_corpus_resume as scoring
from mmaudit.benchmark.development_corpus import score_development_corpus
from mmaudit.benchmark.development_corpus_resume import (
    read_development_corpus_resume_score,
    score_development_corpus_resume,
)
from mmaudit.models.development_audit import development_ledger_request_id
from mmaudit.models.development_corpus import (
    DevelopmentCorpusAccountingEntry,
    DevelopmentCorpusObservation,
)
from mmaudit.models.development_corpus_resume import (
    DevelopmentCorpusResumeAttempt,
    freeze_development_corpus_resume_history,
)
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from mmaudit.orchestration.manifest import canonical_sha256
from tests.development_corpus_benchmark_support import paired_response
from tests.development_corpus_resume_score_support import extend_labelled, labelled_history
from tests.development_corpus_resume_support import append_attempt, pure_attempt, selected_resume


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("cumulative score attempted network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def reseal(data):
    data["score_sha256"] = canonical_sha256(
        {key: value for key, value in data.items() if key != "score_sha256"}
    )
    return data


@pytest.mark.parametrize("observed_count", range(7))
def test_cumulative_score_preserves_original_measurements_labels_and_each_attempt(observed_count):
    original, metadata = labelled_history(observed_count=observed_count)
    history = extend_labelled(original, metadata) if observed_count < 6 else original
    raw = history.model_dump_json()
    score = score_development_corpus_resume(history=history)
    assert history.model_dump_json() == raw == score.history.model_dump_json()
    assert score.first_attempt_summary == original.original_score.summary
    assert score.first_attempt_summary.first_attempt_shard_completion.numerator == observed_count
    assert score.history.original_score.binding == original.original_score.binding
    assert score.cumulative_quality.unique_root_recall.value == 1.0
    assert score.cumulative_quality.total_claim_count == 3
    assert score.cumulative_quality.duplicate_claim_count == 2
    assert score.cumulative_quality.all_claim_unique_root_fraction.value == 0.333333
    assert [c.claim_id for c in score.claims] == [f"file-{i:04d}:01" for i in range(1, 4)]
    assert [c.stage_index for c in score.claims] == [int(i > observed_count) for i in range(1, 4)]
    assert score.cumulative_shard_completion.numerator == 6
    assert score.cumulative_summary == history.summary
    assert score.cumulative_summary.total_accounted_cost_usd == Decimal("0.06")
    assert len(score.requests) == 12 - observed_count
    assert len(score.missing_accounting_request_ids) == 6 - observed_count
    assert score.missing_shard_runtime_request_ids == score.missing_accounting_request_ids
    assert not score.unknown_actual_cost_request_ids
    for request in score.requests:
        stage = history.original if request.stage_index == 0 else history.continuations[0]
        if request.accounting_index is None:
            assert request.actual_cost_state == "MISSING_ACCOUNTING"
            assert request.accounting_status is None and request.elapsed_seconds is None
        else:
            assert stage.accounting[request.accounting_index].shard_id == request.shard_id
            assert request.accounting_status is CostEntryStatus.RECONCILED
    assert read_development_corpus_resume_score(score.model_dump_json().encode()) == score
    assert not score.audit_complete and not score.findings_validated
    assert not score.qualification_eligible and not score.release_eligible


@pytest.mark.parametrize("observed_count", range(6))
def test_incomplete_history_keeps_full_denominators_and_null_quality(observed_count):
    history, _ = labelled_history(observed_count=observed_count, both_planted=True)
    score = score_development_corpus_resume(history=history)
    quality = score.cumulative_quality
    assert quality.quality_scope == "INCOMPLETE_OBSERVATIONS"
    for name in (
        "unique_root_recall",
        "severity_weighted_root_recall",
        "all_claim_unique_root_fraction",
        "severity_weighted_structural_precision",
    ):
        assert getattr(quality, name).state == "INCOMPLETE_SCOPE"
        assert getattr(quality, name).value is None
    assert quality.unique_root_recall.denominator == 2
    assert score.cumulative_shard_completion.denominator == 6
    assert score.cumulative_shard_completion.numerator == observed_count
    assert score.cumulative_summary.selected_primary_line_count == (
        history.original.selected_primary_line_count
    )
    assert score.cumulative_summary.between_run_wait_seconds is None
    assert score.runtime_scope == "SUM_RECORDED_RUN_DURATIONS_NOT_END_TO_END"


def test_completed_history_preserves_every_failed_unknown_cost_and_original_gap():
    original, metadata = labelled_history(observed_count=1)
    partial = extend_labelled(original, metadata, observed_count=1, unknown=True)
    history = extend_labelled(partial, metadata)
    score = score_development_corpus_resume(history=history)
    failed = partial.continuations[0].accounting[-1]
    failed_id = partial.continuations[0].observations[-1].estimate.request_id
    assert score.unknown_actual_cost_request_ids == (failed_id,)
    assert (
        score.cumulative_summary.total_accounted_cost_usd == Decimal("0.06") + failed.reserved_usd
    )
    assert score.cumulative_summary.uncertain_accounted_cost_usd == failed.reserved_usd
    assert score.cumulative_summary.reported_actual_cost_usd == Decimal("0.06")
    assert score.cumulative_summary.accounted_request_count == 7
    assert len(score.requests) == 6 + 5 + 4
    assert len(score.missing_accounting_request_ids) == 5 + 3
    assert [c.stage_index for c in score.claims] == [0, 1, 2]
    assert score.cumulative_quality.duplicate_claim_count == 2
    assert score.cumulative_quality.unique_root_recall.value == 1.0
    assert score.first_attempt_summary.unique_root_recall.value is None
    assert score.history.continuations[0] == partial.continuations[0]
    assert score.actual_cost_scope == "SUM_REPORTED_ACTUAL_NOT_TOTAL_BILL"


@pytest.mark.parametrize("kind", ["advisory", "guarded", "class_mismatch", "anchor_mismatch"])
def test_cumulative_matching_never_relabels_or_drops_inconvenient_claims(kind):
    responses = [paired_response(i, guarded_empty=False) for i in range(1, 7)]
    if kind == "advisory":
        responses = [paired_response(i, guarded_empty=False, advisory=True) for i in range(1, 7)]
    elif kind == "class_mismatch":
        for response in responses:
            response["findings"][0]["vulnerability_class"] = "other"
    elif kind == "anchor_mismatch":
        for response in responses:
            response["findings"][0]["root_cause_ref"]["line_start"] = 1
            response["findings"][0]["root_cause_ref"]["line_end"] = 1
    history, metadata = labelled_history(observed_count=0)
    history = extend_labelled(history, metadata, responses=tuple(responses))
    score = score_development_corpus_resume(history=history)
    assert score.cumulative_quality.total_claim_count == 6
    assert score.cumulative_quality.unique_root_recall.denominator == 1
    if kind == "guarded":
        assert score.cumulative_quality.guarded_control_claim_count == 3
        assert score.cumulative_quality.duplicate_claim_count == 2
        assert score.cumulative_quality.all_claim_unique_root_fraction.value == 0.166667
    elif kind == "advisory":
        assert score.cumulative_quality.advisory_claim_count == 6
        assert score.cumulative_quality.advisories_at_planted_sites_count == 3
        assert score.cumulative_quality.unique_root_recall.value == 0.0
    else:
        assert score.cumulative_quality.unmatched_invariant_claim_count == 6
        assert score.cumulative_quality.unique_root_recall.value == 0.0


@pytest.mark.parametrize("kind", ["missing", "mapping", "subclass", "tampered"])
def test_scoring_requires_exact_validated_history_with_the_original_binding(kind):
    history, _ = labelled_history()
    if kind == "missing":
        history = freeze_development_corpus_resume_history(
            original=history.original, material=history.material
        )
    elif kind == "mapping":
        history = history.model_dump()
    elif kind == "subclass":
        subtype = type("SyntheticUnselectedHistory", (type(history),), {})
        history = subtype.model_validate_json(history.model_dump_json(), strict=True)
    else:
        history = history.model_copy(update={"history_sha256": "0" * 64})
    with pytest.raises(ValueError):
        score_development_corpus_resume(history=history)


@pytest.mark.parametrize(
    "kind",
    [
        "claim",
        "origin",
        "request",
        "accounting",
        "first_attempt",
        "quality",
        "scope",
        "runtime",
        "unknown",
        "missing",
        "history",
        "original_hash",
        "score_hash",
        "authority",
    ],
)
def test_rehashing_cannot_hide_changed_measurements_provenance_costs_or_authority(kind):
    original, metadata = labelled_history()
    score = score_development_corpus_resume(history=extend_labelled(original, metadata))
    data = score.model_dump(mode="json")
    if kind == "claim":
        data["claims"].pop()
    elif kind == "origin":
        data["claims"][-1]["stage_index"] = 0
    elif kind == "request":
        data["requests"][-1]["request_id"] = data["requests"][0]["request_id"]
    elif kind == "accounting":
        data["requests"][-1]["accounting_index"] = 0
    elif kind == "first_attempt":
        data["first_attempt_summary"]["total_claim_count"] = 0
    elif kind == "quality":
        data["cumulative_quality"]["matched_root_ids"] = []
    elif kind == "scope":
        data["cumulative_summary"]["selected_primary_line_count"] = 1
    elif kind == "runtime":
        data["requests"][-1]["elapsed_seconds"] = None
    elif kind == "unknown":
        data["unknown_actual_cost_request_ids"] = [data["requests"][0]["request_id"]]
    elif kind == "missing":
        data["missing_accounting_request_ids"] = []
    elif kind == "history":
        data["history_sha256"] = "0" * 64
    elif kind == "original_hash":
        data["original_score_sha256"] = "0" * 64
    elif kind == "authority":
        data["qualification_eligible"] = True
    reseal(data)
    if kind == "score_hash":
        data["score_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        read_development_corpus_resume_score(json.dumps(data).encode())


@pytest.mark.parametrize(
    "content", [b"", b"[]", b"null", b"{", b"\xff", b'{"a":NaN}', b'{"a":1,"a":2}', "{}", None]
)
def test_score_reader_rejects_noncanonical_or_nonbyte_input(content):
    with pytest.raises((ValueError, UnicodeError)):
        read_development_corpus_resume_score(content)


@pytest.mark.parametrize("target", ["history", "score", "secret"])
def test_typed_scoring_enforces_separate_fixed_bounds_and_secret_refusal(monkeypatch, target):
    history, _ = labelled_history()
    if target == "secret":
        monkeypatch.setattr(scoring, "detect_secrets", lambda _: True)
    else:
        name = (
            "MAX_DEVELOPMENT_CORPUS_RESUME_BYTES"
            if target == "history"
            else ("MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES")
        )
        monkeypatch.setattr(scoring, name, 1)
    with pytest.raises(ValueError):
        score_development_corpus_resume(history=history)


def test_eight_empty_stages_remain_incomplete_and_retain_every_selected_planned_request():
    history, metadata = labelled_history(observed_count=0)
    for _ in range(8):
        history = append_attempt(
            history, pure_attempt(selected_resume(history, metadata), observed_count=0)
        )
    score = score_development_corpus_resume(history=history)
    assert len(score.requests) == 54
    assert len(score.missing_accounting_request_ids) == 54
    assert not score.claims and not score.unknown_actual_cost_request_ids
    assert score.cumulative_quality.unique_root_recall.value is None
    assert score.cumulative_summary.continuation_count == 8
    assert score.cumulative_summary.sum_run_elapsed_seconds == 9


@pytest.mark.parametrize("status", list(CostEntryStatus))
def test_charge_without_response_keeps_its_exact_state_and_missing_runtime(status):
    history, metadata = labelled_history()
    selected = selected_resume(history, metadata)
    attempt = pure_attempt(selected, observed_count=0)
    shard = next(
        s for s in selected.plan.candidate.shards if s.shard_id in selected.plan.selected_shard_ids
    )
    actual = (
        shard.estimate.estimated_cost_per_attempt_usd + Decimal("0.03")
        if status is CostEntryStatus.RESERVATION_OVERRUN
        else Decimal("0.03")
        if status is CostEntryStatus.RECONCILED
        else None
    )
    entry = DevelopmentCorpusAccountingEntry(
        shard_id=shard.shard_id,
        ledger_request_id=development_ledger_request_id(shard.estimate.request_id),
        reservation_id="a" * 32,
        status=status,
        reserved_usd=shard.estimate.estimated_cost_per_attempt_usd,
        actual_cost_usd=actual,
        accounted_cost_usd=shard.estimate.estimated_cost_per_attempt_usd
        if status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        else actual or Decimal("0"),
    )
    attempt = DevelopmentCorpusResumeAttempt.model_validate(
        {**attempt.model_dump(), "accounting": (entry,)}
    )
    score = score_development_corpus_resume(history=append_attempt(history, attempt))
    request = next(r for r in score.requests if r.request_id == shard.estimate.request_id)
    assert request.observation_status == "MISSING" and request.elapsed_seconds is None
    assert request.accounting_status is status and request.accounting_index == 0
    assert request.request_id not in score.missing_accounting_request_ids
    assert request.request_id in score.missing_shard_runtime_request_ids
    assert (request.request_id in score.unknown_actual_cost_request_ids) == (
        status in {CostEntryStatus.RESERVED, CostEntryStatus.UNCERTAIN_ACCOUNTED}
    )
    assert score.history.continuations[0].accounting == (entry,)
    assert score.cumulative_summary.active_reserved_usd == (
        entry.reserved_usd if status is CostEntryStatus.RESERVED else 0
    )
    assert score.cumulative_quality.unique_root_recall.value is None


@pytest.mark.parametrize("where", ["original", "continuation"])
def test_all_responses_with_late_failure_do_not_receive_complete_quality(where):
    history, metadata = labelled_history(observed_count=6 if where == "original" else 1)
    if where == "original":
        original = DevelopmentCorpusObservation.model_validate(
            {
                **history.original.model_dump(),
                "status": "INCOMPLETE",
                "stop_reason": "LOCAL_FAILURE",
            }
        )
        history = freeze_development_corpus_resume_history(
            original=original,
            material=history.material,
            original_score=score_development_corpus(
                binding=history.original_score.binding, observation=original
            ),
        )
    else:
        complete = extend_labelled(history, metadata)
        last = DevelopmentCorpusResumeAttempt.model_validate(
            {
                **complete.continuations[-1].model_dump(),
                "status": "INCOMPLETE",
                "stop_reason": "LOCAL_FAILURE",
            }
        )
        history = append_attempt(history, last)
    score = score_development_corpus_resume(history=history)
    assert score.cumulative_shard_completion.value == 1.0
    assert score.cumulative_summary.status == "INCOMPLETE"
    assert score.cumulative_quality.unique_root_recall.value is None
    assert score.cumulative_quality.quality_scope == "INCOMPLETE_OBSERVATIONS"
    assert not score.audit_complete


def test_empty_responses_keep_missed_roots_and_empty_claim_denominator_separate():
    responses = tuple(paired_response(i, count=0) for i in range(1, 7))
    history, metadata = labelled_history(observed_count=1, responses=responses)
    score = score_development_corpus_resume(
        history=extend_labelled(history, metadata, responses=responses)
    )
    assert score.cumulative_quality.unique_root_recall.value == 0.0
    assert (
        score.cumulative_quality.observed_missed_root_ids
        == score.cumulative_quality.expected_root_ids
    )
    assert not score.cumulative_quality.unobserved_root_ids
    assert score.cumulative_quality.all_claim_unique_root_fraction.state == "EMPTY_DENOMINATOR"
    assert score.cumulative_quality.all_claim_unique_root_fraction.value is None
    assert not score.claims and score.cumulative_summary.accounted_request_count == 6
