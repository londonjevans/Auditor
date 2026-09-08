"""Exact manifest review partitions and schemas, never ground-truth or lineage qualification."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator

from mmaudit.models.development_corpus_judgment import (
    DevelopmentCorpusJudgmentPlan,
    DevelopmentCorpusJudgmentResponse,
    development_corpus_judgment_request_id,
    prepare_development_corpus_judgment,
    require_development_corpus_judgment_candidate,
    validate_development_corpus_judgment_response,
)
from mmaudit.models.development_judgment import require_development_judgment_candidate
from mmaudit.models.development_review import DevelopmentJudgmentResponse
from mmaudit.orchestration.manifest import canonical_sha256
from tests.development_benchmark_support import scored_observation
from tests.development_corpus_judgment_support import (
    manifest_judgment_response,
    pure_candidate,
    review_case,
    selected_policy,
)
from tests.development_judgment_support import judgment_metadata


def test_review_uses_exact_nested_sources_original_claims_and_separate_wire_schema():
    prepared = review_case(policy=selected_policy(timeout=360), maximum_completion_tokens=8192)
    plan = prepared.plan
    assert len(plan.shards) == 4 and not plan.empty_candidate_shard_ids
    assert plan.policy.request_timeout_seconds == 360
    assert plan.maximum_completion_tokens == 8192
    assert not plan.unobserved_candidate_shard_ids
    assert (
        DevelopmentCorpusJudgmentPlan.model_validate_json(plan.model_dump_json(), strict=True)
        == plan
    )
    for shard in prepared.shards:
        body = json.loads(shard.request_content)
        prompt = body["messages"][1]["content"]
        assert all("Source file: " + name in prompt for name, _ in prepared.source_files)
        assert all(
            c.finding.model_dump(mode="json") == original.model_dump(mode="json")
            for c, original in zip(
                shard.claims,
                next(
                    s for s in plan.candidate.observations if s.shard_id == shard.shard_id
                ).response.findings,
                strict=True,
            )
        )
        assert (
            body["response_format"]["json_schema"]["schema"]["properties"]["schema_version"][
                "const"
            ]
            == "2.0"
        )
        assert plan.candidate.plan.routing.exact_model_id not in prompt
        assert "request_timeout_seconds" not in shard.request_content.decode()
    assert plan.lineage_independence == "NOT_ESTABLISHED"
    assert not plan.audit_complete and not plan.qualification_eligible and not plan.release_eligible


@pytest.mark.parametrize("observed", [0, 1, 3, 4])
@pytest.mark.parametrize("claims", [0, 1, 16])
def test_observed_empty_and_unobserved_candidate_scope_stay_distinct(observed, claims):
    prepared = review_case(observed_count=observed, claims=claims)
    assert len(prepared.shards) == (observed if claims else 0)
    assert len(prepared.plan.empty_candidate_shard_ids) == (0 if claims else observed)
    assert len(prepared.plan.unobserved_candidate_shard_ids) == 4 - observed
    assert prepared.plan.candidate.candidate_claim_count == observed * claims
    assert prepared.plan.candidate.status == (
        "OBSERVED_ALL_SHARDS" if observed == 4 else "INCOMPLETE"
    )


@pytest.mark.parametrize("verdict", ["SUPPORTED", "REFUTED", "INCONCLUSIVE"])
@pytest.mark.parametrize("references", [0, 1])
def test_runtime_and_public_schema_agree_on_conclusive_reference_requirement(verdict, references):
    response = manifest_judgment_response(verdict=verdict)
    if not references:
        response["decisions"][0]["source_refs"] = []
    valid = references == 1 or verdict == "INCONCLUSIVE"
    assert (
        Draft202012Validator(DevelopmentCorpusJudgmentResponse.model_json_schema()).is_valid(
            response
        )
        == valid
    )
    if valid:
        assert DevelopmentCorpusJudgmentResponse.model_validate_json(
            json.dumps(response), strict=True
        )
    else:
        with pytest.raises(ValueError):
            DevelopmentCorpusJudgmentResponse.model_validate_json(json.dumps(response), strict=True)


@pytest.mark.parametrize(
    "identity",
    ["file-0000:01", "file-0065:01", "file-9999:01", "file-0001:00", "file-0001:17", "file-01:01"],
)
def test_manifest_response_rejects_wrong_or_out_of_bound_claim_namespace(identity):
    response = manifest_judgment_response()
    response["decisions"][0]["claim_id"] = identity
    with pytest.raises(ValueError):
        DevelopmentCorpusJudgmentResponse.model_validate_json(json.dumps(response), strict=True)


@pytest.mark.parametrize("kind", ["omitted", "reordered", "unselected_source", "outside_lines"])
def test_manifest_response_requires_every_original_claim_and_in_snapshot_references(kind):
    prepared = review_case(claims=2)
    data = manifest_judgment_response(count=2)
    if kind == "omitted":
        data["decisions"].pop()
    elif kind == "reordered":
        data["decisions"].reverse()
    elif kind == "unselected_source":
        data["decisions"][0]["source_refs"][0]["filename"] = "src/Unknown.sol"
    else:
        data["decisions"][0]["source_refs"][0]["line_end"] = 10000
    response = DevelopmentCorpusJudgmentResponse.model_validate_json(json.dumps(data), strict=True)
    with pytest.raises(ValueError):
        validate_development_corpus_judgment_response(
            response,
            manifest=prepared.plan.candidate.plan.manifest,
            claims=prepared.shards[0].claims,
        )


def test_legacy_candidates_and_responses_remain_separate_exact_contracts():
    _, candidate = pure_candidate()
    with pytest.raises(ValueError):
        require_development_judgment_candidate(candidate)
    with pytest.raises(ValueError):
        require_development_corpus_judgment_candidate(scored_observation())
    with pytest.raises(ValueError):
        DevelopmentJudgmentResponse.model_validate_json(
            json.dumps(manifest_judgment_response()), strict=True
        )


@pytest.mark.parametrize("identity", ["file-0001:01", "file-0064:16"])
def test_manifest_response_accepts_the_exact_first_and_last_bounded_claim_ids(identity):
    response = manifest_judgment_response()
    response["decisions"][0]["claim_id"] = identity
    parsed = DevelopmentCorpusJudgmentResponse.model_validate_json(
        json.dumps(response), strict=True
    )
    assert parsed.decisions[0].claim_id == identity


@pytest.mark.parametrize("value", [True, False, 0, -1, 1801, float("inf"), float("nan"), "600"])
def test_whole_run_deadline_is_frozen_exact_and_bounded(value):
    with pytest.raises(ValueError):
        review_case(maximum_run_seconds=value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_id", ""),
        ("candidate_sha256", "not-a-hash"),
        ("shard_id", "file-0065"),
        ("shard_id", True),
    ],
)
def test_request_identity_is_bounded_and_not_interchangeable(field, value):
    values = dict(run_id="synthetic", candidate_sha256="a" * 64, shard_id="file-0001")
    values[field] = value
    with pytest.raises(ValueError):
        development_corpus_judgment_request_id(**values)


@pytest.mark.parametrize("kind", ["source", "producer", "candidate_digest", "budget"])
def test_prepare_rejects_source_identity_digest_or_budget_substitution(kind):
    original, candidate = pure_candidate()
    sources = original.shards[0].source_files
    metadata = judgment_metadata()
    policy = selected_policy()
    if kind == "source":
        sources = ((sources[0][0], sources[0][1] + b"\n"), *sources[1:])
    elif kind == "producer":
        metadata = judgment_metadata(model_id=candidate.plan.routing.exact_model_id)
    elif kind == "candidate_digest":
        candidate = candidate.model_copy(update={"candidate_claim_count": 0})
    else:
        policy = policy.model_copy(update={"total_budget_usd": policy.total_budget_usd + 1})
    with pytest.raises(ValueError):
        prepare_development_corpus_judgment(
            candidate=candidate,
            policy=policy,
            endpoint_snapshot=metadata,
            source_files=sources,
            run_id="synthetic",
        )


@pytest.mark.parametrize("alias_side", ["candidate", "reviewer"])
def test_every_retained_known_alias_excludes_a_matching_reviewer_even_without_optional_response_routing(
    alias_side,
):
    candidate_id = "synthetic/corpus-review"
    reviewer_id = "synthetic/development-reviewer"
    original, candidate = pure_candidate(
        endpoint_snapshot=judgment_metadata(
            model_id=candidate_id,
            canonical=reviewer_id if alias_side == "candidate" else None,
        )
    )
    metadata = judgment_metadata(
        model_id=reviewer_id, canonical=candidate_id if alias_side == "reviewer" else None
    )
    with pytest.raises(ValueError, match=r"producer|alias"):
        prepare_development_corpus_judgment(
            candidate=candidate,
            policy=selected_policy(),
            endpoint_snapshot=metadata,
            source_files=original.shards[0].source_files,
            run_id="synthetic-alias-collision",
        )


@pytest.mark.parametrize(
    "kind",
    [
        "claims",
        "reordered",
        "omitted",
        "empty_scope",
        "unobserved_scope",
        "tokens",
        "attempts",
        "timeout",
        "source",
        "total",
        "candidate_digest",
    ],
)
def test_rehashed_plan_still_rejects_semantic_claim_scope_or_policy_drift(kind):
    plan = review_case(claims=(1, 0, 1, 1), observed_count=3).plan
    data = plan.model_dump(mode="json")
    if kind == "claims":
        data["shards"][0]["claims"][0]["finding"]["explanation"] = "Changed original hypothesis."
    elif kind == "reordered":
        data["shards"].reverse()
    elif kind == "omitted":
        data["shards"].pop()
    elif kind == "empty_scope":
        data["empty_candidate_shard_ids"] = []
    elif kind == "unobserved_scope":
        data["unobserved_candidate_shard_ids"] = []
    elif kind == "tokens":
        data["maximum_completion_tokens"] = 8192
    elif kind == "attempts":
        data["policy"]["maximum_attempts"] = 2
    elif kind == "timeout":
        data["policy"]["request_timeout_seconds"] = 360
    elif kind == "source":
        data["shards"][0]["primary_filename"] = "src/Unknown.sol"
    elif kind == "total":
        data["estimated_total_cost_usd"] = "0"
    else:
        data["candidate_sha256"] = "0" * 64
    data["plan_sha256"] = canonical_sha256({k: v for k, v in data.items() if k != "plan_sha256"})
    with pytest.raises(ValueError):
        DevelopmentCorpusJudgmentPlan.model_validate_json(json.dumps(data), strict=True)


def test_manifest_candidate_input_bound_is_enforced_before_any_preparation(monkeypatch):
    import mmaudit.models.development_corpus_judgment as module

    _, candidate = pure_candidate()
    monkeypatch.setattr(module, "MAX_DEVELOPMENT_CORPUS_RESULT_BYTES", 1)
    with pytest.raises(ValueError, match="bound"):
        require_development_corpus_judgment_candidate(candidate)
