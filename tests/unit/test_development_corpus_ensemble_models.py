"""Frozen manifest roles and purely descriptive opinions; no source execution or authority."""

from __future__ import annotations

import json
from itertools import product

import pytest

from mmaudit.models.development_corpus_ensemble import (
    DevelopmentCorpusEnsembleClaim,
    DevelopmentCorpusEnsemblePlan,
    manifest_refutation_scope,
)
from mmaudit.models.development_corpus_judgment import development_corpus_judgment_claims
from mmaudit.models.development_ensemble import development_ensemble_stage_run_id
from tests.development_corpus_ensemble_support import (
    composed_observation,
    manifest_ensemble_case,
    maximum_manifest_sources,
)
from tests.development_corpus_judgment_support import (
    pure_candidate,
    selected_policy,
)
from tests.development_ensemble_support import ENSEMBLE_MODELS, high_allowance_metadata
from tests.development_judgment_support import judgment_metadata


def test_manifest_ensemble_freezes_six_sources_and_separately_selected_role_allowances():
    prepared = manifest_ensemble_case(
        candidate_maximum_completion_tokens=1024,
        reviewer_maximum_completion_tokens=(2048, 3072),
        maximum_run_seconds=420.0,
    )
    plan = prepared.plan
    assert len(plan.candidate.shards) == 6
    assert plan.candidate.maximum_run_seconds == plan.maximum_run_seconds == 420
    assert plan.candidate.run_id == development_ensemble_stage_run_id(plan.run_id, "candidate")
    assert plan.candidate.shards[0].estimate.maximum_completion_tokens == 1024
    assert tuple(r.maximum_completion_tokens for r in plan.reviewers) == (2048, 3072)
    assert plan.estimated_headroom_usd == plan.candidate.estimated_total_cost_usd + 12
    assert len({plan.candidate.run_id, *(r.run_id for r in plan.reviewers)}) == 3
    assert plan.lineage_independence == "NOT_ESTABLISHED"
    assert plan.findings_validated is plan.audit_complete is plan.qualification_eligible is False
    assert DevelopmentCorpusEnsemblePlan.model_validate_json(plan.model_dump_json()) == plan


@pytest.mark.parametrize("tokens", [(False, 4096), (0, 4096), (4096, 65537), (4096,), [4096, 4096]])
def test_invalid_role_allowances_refuse(tokens):
    with pytest.raises(ValueError):
        manifest_ensemble_case(reviewer_maximum_completion_tokens=tokens)


@pytest.mark.parametrize(
    "kind",
    ["same_candidate", "same_reviewers", "missing", "extra", "headroom", "deadline", "policy_type"],
)
def test_invalid_roles_policy_or_whole_run_shape_refuse(kind):
    metadata = tuple(judgment_metadata(model_id=m) for m in ENSEMBLE_MODELS[1:])
    changes = {}
    if kind == "same_candidate":
        changes["reviewer_metadata"] = (judgment_metadata(model_id=ENSEMBLE_MODELS[0]), metadata[1])
    elif kind == "same_reviewers":
        changes["reviewer_metadata"] = (metadata[0], metadata[0])
    elif kind == "missing":
        changes["reviewer_metadata"] = metadata[:1]
    elif kind == "extra":
        changes["reviewer_metadata"] = (*metadata, metadata[0])
    elif kind == "headroom":
        changes["policy"] = selected_policy(per_attempt="5")
    elif kind == "deadline":
        changes["maximum_run_seconds"] = True
    else:
        changes["policy"] = selected_policy().model_dump()
    with pytest.raises(ValueError):
        manifest_ensemble_case(**changes)


@pytest.mark.parametrize(
    "field",
    [
        "source",
        "candidate_run",
        "reviewer_run",
        "order",
        "tokens",
        "headroom",
        "deadline",
        "digest",
        "authority",
    ],
)
def test_serialized_plan_cannot_change_selected_source_roles_or_authority(field):
    data = manifest_ensemble_case().plan.model_dump(mode="json")
    if field == "source":
        data["candidate"]["manifest"]["sources"][0]["sha256"] = "a" * 64
    elif field == "candidate_run":
        data["candidate"]["run_id"] = "changed"
    elif field == "reviewer_run":
        data["reviewers"][0]["run_id"] = "changed"
    elif field == "order":
        data["reviewers"].reverse()
    elif field == "tokens":
        data["reviewers"][1]["maximum_completion_tokens"] = 2048
    elif field == "headroom":
        data["estimated_headroom_usd"] = "0.01"
    elif field == "deadline":
        data["maximum_run_seconds"] = 1800
    elif field == "digest":
        data["plan_sha256"] = "b" * 64
    else:
        data["release_eligible"] = True
    with pytest.raises(ValueError):
        DevelopmentCorpusEnsemblePlan.model_validate_json(json.dumps(data), strict=True)


@pytest.mark.parametrize(
    "opinions", list(product(("SUPPORTED", "REFUTED", "INCONCLUSIVE", None), repeat=2))
)
def test_every_opinion_pair_retains_original_claim_and_one_versus_two_refutations(opinions):
    _, candidate = pure_candidate(count=1)
    claim = development_corpus_judgment_claims(candidate, "file-0001")[0]
    consensus = (
        "UNREVIEWED"
        if None in opinions
        else opinions[0]
        if opinions[0] == opinions[1]
        else "INCONCLUSIVE"
    )
    row = DevelopmentCorpusEnsembleClaim(
        candidate_claim=claim,
        opinions=opinions,
        consensus=consensus,
        refutation_scope=manifest_refutation_scope(opinions),
    )
    assert row.candidate_claim == claim and row.opinions == opinions
    assert row.refutation_scope == (
        "REFUTED_BY_BOTH"
        if opinions.count("REFUTED") == 2
        else "REFUTED_BY_ONE"
        if "REFUTED" in opinions
        else "NO_REFUTATION_OBSERVED"
    )
    data = row.model_dump(mode="json")
    data["refutation_scope"] = (
        "REFUTED_BY_BOTH" if row.refutation_scope != "REFUTED_BY_BOTH" else "NO_REFUTATION_OBSERVED"
    )
    with pytest.raises(ValueError):
        DevelopmentCorpusEnsembleClaim.model_validate_json(json.dumps(data), strict=True)


def test_maximum_manifest_retains_all_128_future_review_allowances():
    prepared = manifest_ensemble_case(
        source_files=maximum_manifest_sources(), policy=selected_policy(total="250")
    )
    assert len(prepared.candidate.shards) == 64
    assert (
        prepared.plan.estimated_headroom_usd
        == prepared.plan.candidate.estimated_total_cost_usd + 128
    )


def test_large_reviewer_allowance_does_not_change_candidate_allowance_or_request_bytes():
    baseline = manifest_ensemble_case()
    changed = manifest_ensemble_case(
        reviewer_metadata=tuple(high_allowance_metadata(m) for m in ENSEMBLE_MODELS[1:]),
        reviewer_maximum_completion_tokens=(16384, 32768),
    )
    assert changed.candidate == baseline.candidate
    assert changed.plan.plan_sha256 != baseline.plan.plan_sha256


def test_missing_candidate_keeps_every_selected_source_and_stage_unobserved():
    plan = manifest_ensemble_case().plan
    result = composed_observation(plan)
    assert result.status == "INCOMPLETE" and result.stop_reason == "CANDIDATE_INCOMPLETE"
    assert len(result.unobserved_candidate_shard_ids) == 6
    assert result.unobserved_stage_ids == ("candidate", "review-01", "review-02")
    assert result.completed_stage_count == result.completed_judgment_count == 0
    assert not result.claims and not result.available_claim_reviews_complete
    assert result.total_accounted_cost_usd == 0
