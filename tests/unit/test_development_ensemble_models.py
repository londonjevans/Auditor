"""Exact frozen stage selection and opinion-only consensus on synthetic inputs."""

from __future__ import annotations

import json
from decimal import Decimal
from itertools import product

import pytest
from pydantic import BaseModel

from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.models.development_ensemble import (
    DevelopmentEnsembleClaim,
    DevelopmentEnsemblePlan,
    development_ensemble_stage_run_id,
)
from mmaudit.models.development_judgment import development_judgment_claims
from mmaudit.orchestration.development_audit import _write
from mmaudit.orchestration.manifest import canonical_sha256
from tests.development_benchmark_support import scored_observation
from tests.development_ensemble_support import (
    ENSEMBLE_MODELS,
    ensemble_case,
    high_allowance_metadata,
)
from tests.development_judgment_support import judgment_metadata


@pytest.mark.parametrize("variant", ["a", "b"])
def test_plan_pins_all_roles_source_stage_ids_and_estimated_headroom(variant):
    prepared = ensemble_case(variant=variant)
    plan = prepared.plan
    assert plan.candidate == prepared.candidate.plan
    assert plan.candidate.schema_version == "2.0"
    assert plan.candidate.run_id == development_ensemble_stage_run_id(plan.run_id, "candidate")
    assert plan.estimated_headroom_usd == plan.candidate.estimated_total_cost_usd + Decimal("6")
    assert [r.routing.exact_model_id for r in plan.reviewers] == list(ENSEMBLE_MODELS[1:])
    assert len({plan.candidate.run_id, *(r.run_id for r in plan.reviewers)}) == 3
    assert plan.lineage_independence == "NOT_ESTABLISHED"
    assert (
        plan.findings_validated
        is plan.audit_complete
        is plan.qualification_eligible
        is plan.release_eligible
        is False
    )
    assert DevelopmentEnsemblePlan.model_validate_json(plan.model_dump_json(), strict=True) == plan


@pytest.mark.parametrize(
    "candidate_tokens,review_tokens", [(65536, (4096, 16384)), (4096, (16384, 4096))]
)
def test_candidate_and_both_review_allowances_remain_independent(candidate_tokens, review_tokens):
    prepared = ensemble_case(
        candidate_metadata=high_allowance_metadata(ENSEMBLE_MODELS[0]),
        candidate_maximum_completion_tokens=candidate_tokens,
        reviewer_maximum_completion_tokens=review_tokens,
        policy=DevelopmentCostPolicy(
            overspend_risk_accepted=True,
            total_budget_usd=Decimal("40"),
            per_attempt_budget_usd=Decimal("5"),
        ),
    )
    assert prepared.plan.candidate.shards[0].estimate.maximum_completion_tokens == candidate_tokens
    assert tuple(r.maximum_completion_tokens for r in prepared.plan.reviewers) == review_tokens


@pytest.mark.parametrize("kind", ["candidate", "reviewer", "candidate_alias", "reviewer_alias"])
def test_all_three_roles_reject_identical_or_known_alias_identities(kind):
    first = judgment_metadata(model_id=ENSEMBLE_MODELS[1])
    second = judgment_metadata(model_id=ENSEMBLE_MODELS[2])
    if kind == "candidate":
        first = judgment_metadata(model_id=ENSEMBLE_MODELS[0])
    elif kind == "reviewer":
        second = first
    elif kind == "candidate_alias":
        first = judgment_metadata(model_id=ENSEMBLE_MODELS[1], canonical=ENSEMBLE_MODELS[0])
    else:
        second = judgment_metadata(model_id=ENSEMBLE_MODELS[2], canonical=ENSEMBLE_MODELS[1])
    with pytest.raises(ValueError, match="alias"):
        ensemble_case(reviewer_metadata=(first, second))


@pytest.mark.parametrize("tokens", [(True, 4096), (0, 4096), (65536, 4096), (4096,), [4096, 4096]])
def test_known_bad_reviewer_allowances_refuse_before_candidate_dispatch(tokens):
    with pytest.raises(ValueError):
        ensemble_case(reviewer_maximum_completion_tokens=tokens)


@pytest.mark.parametrize("deadline", [True, 0, -1, 1801, float("inf"), float("nan"), "60"])
def test_whole_run_deadline_is_explicit_finite_and_bounded(deadline):
    with pytest.raises(ValueError):
        ensemble_case(maximum_run_seconds=deadline)


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_id", "changed"),
        ("estimated_headroom_usd", "0.001"),
        ("plan_sha256", "a" * 64),
        ("lineage_independence", "VERIFIED"),
        ("findings_validated", True),
        ("audit_complete", True),
        ("qualification_eligible", True),
        ("release_eligible", True),
    ],
)
def test_plan_roundtrip_rejects_tamper_or_authority(field, value):
    data = ensemble_case().plan.model_dump(mode="json")
    data[field] = value
    if field != "plan_sha256":
        data["plan_sha256"] = canonical_sha256(
            {k: v for k, v in data.items() if k != "plan_sha256"}
        )
    with pytest.raises(ValueError):
        DevelopmentEnsemblePlan.model_validate_json(json.dumps(data), strict=True)


def test_insufficient_future_review_headroom_refuses_even_when_candidate_fits():
    with pytest.raises(ValueError, match="headroom"):
        ensemble_case(
            policy=DevelopmentCostPolicy(
                overspend_risk_accepted=True,
                total_budget_usd=Decimal("5"),
                per_attempt_budget_usd=Decimal("1"),
            )
        )


@pytest.mark.parametrize(
    "pair", list(product(("SUPPORTED", "REFUTED", "INCONCLUSIVE", None), repeat=2))
)
def test_every_pair_of_review_opinions_preserves_disagreement_and_missing_scope(pair):
    expected = "UNREVIEWED" if None in pair else pair[0] if pair[0] == pair[1] else "INCONCLUSIVE"
    claim = development_judgment_claims(scored_observation(), "file-01")[0]
    result = DevelopmentEnsembleClaim(candidate_claim=claim, opinions=pair, consensus=expected)
    assert result.opinions == pair and result.candidate_claim == claim
    for wrong in {"SUPPORTED", "REFUTED", "INCONCLUSIVE", "UNREVIEWED"} - {expected}:
        with pytest.raises(ValueError):
            DevelopmentEnsembleClaim(candidate_claim=claim, opinions=pair, consensus=wrong)


@pytest.mark.parametrize(
    "run_id,stage",
    [
        ("", "candidate"),
        ("bad/child", "candidate"),
        ("x" * 65, "candidate"),
        ("valid", "review-03"),
        (True, "candidate"),
    ],
)
def test_stage_identity_cannot_expand_scope_or_create_an_implicit_retry(run_id, stage):
    with pytest.raises(ValueError):
        development_ensemble_stage_run_id(run_id, stage)


@pytest.mark.parametrize("bound", [True, 0, -1, 16_000_001, "2000000"])
def test_composed_writer_rejects_invalid_bounds_before_creating_an_artifact(tmp_path, bound):
    with pytest.raises(ValueError, match="byte bound"):
        _write(tmp_path, "result.json", ensemble_case().plan, max_bytes=bound)
    assert not (tmp_path / "result.json").exists()


def test_larger_composed_envelope_requires_explicit_bound_and_keeps_private_custody(tmp_path):
    class SyntheticEnvelope(BaseModel):
        content: str

    output = tmp_path / "private"
    output.mkdir(mode=0o700)
    model = SyntheticEnvelope(content="x" * 2_000_001)
    with pytest.raises(ValueError):
        _write(output, "too-large.json", model)
    assert not (output / "too-large.json").exists()
    binding = _write(output, "composed.json", model, max_bytes=16_000_000)
    assert binding.size > 2_000_000
    assert (output / "composed.json").stat().st_mode & 0o777 == 0o600
    assert SyntheticEnvelope.model_validate_json((output / "composed.json").read_bytes()) == model
