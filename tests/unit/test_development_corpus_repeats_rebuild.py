"""Remove duplicate preparation, never child validation or exact cross-trial input equality."""

import socket
import subprocess
from dataclasses import replace
from decimal import Decimal

import pytest

import mmaudit.models.development_corpus_repeats as plans
import mmaudit.orchestration.development_corpus as corpus
import mmaudit.orchestration.development_corpus_repeats as repeats
from mmaudit.models.development_corpus_repeats import (
    DevelopmentCorpusRepeatsPlan,
    PreparedDevelopmentCorpusRepeats,
    prepare_development_corpus_repeats,
    read_development_corpus_repeats_plan,
)
from mmaudit.models.development_costs import DevelopmentCostPolicy
from tests.development_corpus_repeats_support import repeat_case
from tests.unit.test_development_corpus_resume_metadata import metadata_case


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("repeat preparation attempted network or process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def selected_case(**changes):
    return repeat_case(
        policy=DevelopmentCostPolicy(
            overspend_risk_accepted=True,
            total_budget_usd=Decimal("250"),
            per_attempt_budget_usd=Decimal("5"),
        ),
        **changes,
    )


def legacy_rebuild(prepared):
    """Reference the previous two-pass composition, using the unchanged real child rebuilder."""

    if (
        type(prepared) is not PreparedDevelopmentCorpusRepeats
        or type(prepared.plan) is not DevelopmentCorpusRepeatsPlan
        or type(prepared.trials) is not tuple
        or not 2 <= len(prepared.trials) <= 8
    ):
        raise ValueError("candidate repeats require exact prepared trials")
    plan = read_development_corpus_repeats_plan(prepared.plan.model_dump_json().encode())
    children = tuple(corpus._rebuild(t) for t in prepared.trials)
    first = children[0].shards[0]
    rebuilt = prepare_development_corpus_repeats(
        policy=plan.policy,
        endpoint_snapshot=first.discovery or first.endpoint_snapshot,
        manifest=plan.trials[0].manifest,
        source_files=first.source_files,
        run_id=plan.run_id,
        trial_count=plan.trial_count,
        truth_content=plan.benchmark.truth_file_content.encode(),
        expected_truth_sha256=plan.benchmark.truth_file_sha256,
        maximum_completion_tokens=first.estimate.maximum_completion_tokens,
        maximum_trial_seconds=plan.trials[0].maximum_run_seconds,
        maximum_run_seconds=plan.maximum_run_seconds,
    )
    if rebuilt != prepared:
        raise ValueError("candidate repeat source, labels or requests changed")
    return rebuilt


@pytest.mark.parametrize("count", [2, 8])
def test_rebuild_prepares_every_selected_child_exactly_once(monkeypatch, count):
    prepared = selected_case(trial_count=count)
    calls = []
    original = corpus.prepare_development_corpus

    def tracked(**kwargs):
        calls.append(kwargs["run_id"])
        return original(**kwargs)

    monkeypatch.setattr(corpus, "prepare_development_corpus", tracked)
    monkeypatch.setattr(plans, "prepare_development_corpus", tracked)
    rebuilt = repeats._rebuild(prepared)
    assert rebuilt == prepared and rebuilt is not prepared
    assert all(a is not b for a, b in zip(rebuilt.trials, prepared.trials, strict=True))
    assert calls == [t.plan.run_id for t in prepared.trials]


@pytest.mark.parametrize("form", ["endpoint", "discovery_payload", "discovery_file"])
@pytest.mark.parametrize("count", [2, 8])
def test_rebuild_matches_previous_complete_prepared_bytes(form, count):
    prepared = selected_case(trial_count=count, endpoint_snapshot=metadata_case(form))
    expected = legacy_rebuild(prepared)
    rebuilt = repeats._rebuild(prepared)
    assert rebuilt == expected == prepared
    assert rebuilt.plan.model_dump_json() == expected.plan.model_dump_json()
    for actual, previous in zip(rebuilt.trials, expected.trials, strict=True):
        assert actual.plan.model_dump_json() == previous.plan.model_dump_json()
        assert actual.shards == previous.shards


@pytest.mark.parametrize("index", [0, 1, 2])
@pytest.mark.parametrize(
    "mutation",
    [
        "child_type",
        "plan_type",
        "shards_type",
        "shard_type",
        "no_shards",
        "source_bytes",
        "source_tuple",
        "source_content",
        "source_order",
        "request",
        "endpoint",
        "estimate",
        "run_id",
        "manifest",
        "late_request",
        "late_metadata",
        "valid_different_deadline",
        "valid_different_identity",
    ],
)
def test_changed_first_middle_or_last_child_preserves_legacy_refusal(index, mutation):
    prepared = selected_case(trial_count=3)
    child = prepared.trials[index]
    first = child.shards[0]
    if mutation == "child_type":
        child = object()
    elif mutation == "plan_type":
        child = replace(child, plan=object())
    elif mutation == "shards_type":
        child = replace(child, shards=list(child.shards))
    elif mutation == "shard_type":
        child = replace(child, shards=(object(), *child.shards[1:]))
    elif mutation == "no_shards":
        child = replace(child, shards=())
    elif mutation.startswith("valid_different"):
        child = corpus.prepare_development_corpus(
            policy=child.plan.policy,
            endpoint_snapshot=first.discovery or first.endpoint_snapshot,
            manifest=child.plan.manifest,
            source_files=first.source_files,
            run_id="synthetic-other-child" if mutation.endswith("identity") else child.plan.run_id,
            maximum_completion_tokens=first.estimate.maximum_completion_tokens,
            maximum_run_seconds=601.0 if mutation.endswith("deadline") else 600.0,
        )
        assert corpus._rebuild(child) == child
    else:
        shard_index = -1 if mutation.startswith("late_") else 0
        shard = child.shards[shard_index]
        if mutation == "source_bytes":
            name, raw = shard.source_files[0]
            shard = replace(shard, source_files=((name, raw + b"\n"), *shard.source_files[1:]))
        elif mutation == "source_tuple":
            shard = replace(shard, source_files=list(shard.source_files))
        elif mutation == "source_order":
            shard = replace(shard, source_files=tuple(reversed(shard.source_files)))
        elif mutation == "source_content":
            shard = replace(shard, source_content=b"// changed synthetic source")
        elif mutation in {"request", "late_request"}:
            shard = replace(shard, request_content=b"changed synthetic request")
        elif mutation in {"endpoint", "late_metadata"}:
            shard = replace(
                shard,
                endpoint_snapshot=shard.endpoint_snapshot.model_copy(
                    update={"snapshot_sha256": "0" * 64}
                ),
            )
        elif mutation == "estimate":
            shard = replace(
                shard, estimate=shard.estimate.model_copy(update={"maximum_completion_tokens": 1})
            )
        elif mutation == "run_id":
            shard = replace(shard, run_id="synthetic-substituted-child")
        elif mutation == "manifest":
            shard = replace(
                shard, manifest=shard.manifest.model_copy(update={"corpus_id": "synthetic-changed"})
            )
        else:
            raise AssertionError("unhandled synthetic mutation")
        shards = list(child.shards)
        shards[shard_index] = shard
        child = replace(child, shards=tuple(shards))
    children = list(prepared.trials)
    children[index] = child
    changed = replace(prepared, trials=tuple(children))
    for rebuild in (legacy_rebuild, repeats._rebuild):
        with pytest.raises(ValueError):
            rebuild(changed)
