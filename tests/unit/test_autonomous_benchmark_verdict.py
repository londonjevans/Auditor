from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.benchmark.models import ModelBenchmarkDimension
from mmaudit.models.autonomous_benchmark_verdict import (
    AUTONOMOUS_BENCHMARK_QUALIFICATION_POLICY_FILE_SHA256,
    AUTONOMOUS_BENCHMARK_VERDICT_POLICY_FILE_SHA256,
    EvidenceSealBaselineDisposition,
    EvidenceSealBudgetProjection,
    EvidenceSealBudgetScope,
    EvidenceSealCaseDimensionOutcome,
    EvidenceSealDimensionVerdict,
    EvidenceSealPairedOutcomeRelation,
    EvidenceSealPolicyDisposition,
    EvidenceSealRequirementState,
    EvidenceSealVerdictPolicy,
    EvidenceSealVerdictProjection,
    EvidenceSealVerdictReason,
    compare_evidence_seal_case_dimension_outcomes,
    compiled_evidence_seal_verdict_policy,
    load_evidence_seal_verdict_policy,
)
from mmaudit.models.evidence_seal_authority import (
    EvidenceSealDecisionProjection,
    build_evidence_authority_subject,
    build_evidence_seal_verdict_projection,
)
from mmaudit.models.ground_truth_authority import GroundTruthOriginKind
from mmaudit.models.qualification import load_qualification_policy
from mmaudit.orchestration.manifest import canonical_sha256
from tests.unit.test_evidence_seal_authority import _Fixture as _AuthorityFixture
from tests.unit.test_evidence_seal_authority import (
    authority_fixture as _shared_authority_fixture,
)

ROOT = Path(__file__).resolve().parents[2]
VERDICT_POLICY_PATH = ROOT / "benchmarks" / "model_corpus" / "verdict_policy.json"
QUALIFICATION_POLICY_PATH = ROOT / "config" / "models.maximum-assurance.toml"

_VERDICT_AUTHORITY_FLAGS = (
    "durable_authority",
    "authority_issuance_authorized",
    "model_qualification_authorized",
    "production_selection_authorized",
    "provider_access_authorized",
    "source_egress_authorized",
)
_CASE_A = "case-0000000000000001"
_CASE_B = "case-0000000000000002"


@pytest.fixture(scope="module")
def autonomous_verdict_fixture() -> _AuthorityFixture:
    factory = _shared_authority_fixture.__wrapped__
    return factory()


def _reseal(payload: dict[str, object], *, hash_field: str) -> dict[str, object]:
    payload.pop(hash_field, None)
    payload[hash_field] = canonical_sha256(payload)
    return payload


def _reseal_decision_output(payload: dict[str, object]) -> None:
    candidate = payload["candidate"]
    case_hashes = payload["case_outcome_sha256s"]
    dimension_hashes = payload["dimension_score_sha256s"]
    assert isinstance(candidate, dict)
    assert isinstance(case_hashes, list)
    assert isinstance(dimension_hashes, list)
    payload["deterministic_output_sha256"] = canonical_sha256(
        {
            "candidate_model_id": candidate["exact_model_id"],
            "candidate_root_lineage": candidate["root_lineage"],
            "benchmark_corpus_sha256": payload["benchmark_corpus_sha256"],
            "benchmark_ground_truth_sha256": payload["benchmark_ground_truth_sha256"],
            "case_outcome_sha256s": case_hashes,
            "case_dimension_outcome_set_sha256": payload["case_dimension_outcome_set_sha256"],
            "dimension_score_sha256s": dimension_hashes,
            "overall_score_micros": payload["overall_score_micros"],
            "execution_evidence": payload["execution_evidence"],
        }
    )
    _reseal(payload, hash_field="projection_sha256")


def _refresh_verdict_disposition(payload: dict[str, object]) -> None:
    dimensions = payload["dimensions"]
    budget = payload["budget"]
    assert isinstance(dimensions, list)
    assert isinstance(budget, dict)
    states = [
        *(item["state"] for item in dimensions),
        payload["overall_state"],
        payload["case_execution_state"],
        payload["execution_evidence_state"],
        payload["replay_state"],
        payload["lineage_state"],
        payload["freshness_state"],
        budget["state"],
    ]
    if EvidenceSealRequirementState.FAIL.value in states:
        disposition = EvidenceSealPolicyDisposition.NOT_SATISFIED
    elif EvidenceSealRequirementState.UNEVALUABLE.value in states:
        disposition = EvidenceSealPolicyDisposition.UNEVALUABLE
    else:
        disposition = EvidenceSealPolicyDisposition.STRUCTURALLY_SATISFIED
    payload["policy_disposition"] = disposition.value


def _budget_projection(
    *,
    campaign_cost_usd_exact: str,
    state: EvidenceSealRequirementState,
) -> EvidenceSealBudgetProjection:
    payload: dict[str, object] = {
        "scope": EvidenceSealBudgetScope.CLOSED_CANDIDATE_PRIMARY_AND_REPLAY_LEDGER_CHAIN.value,
        "report_usage_cost_usd_exact": "0",
        "campaign_cost_usd_exact": campaign_cost_usd_exact,
        "maximum_campaign_cost_usd_exact": "250",
        "portfolio_sha256s": ["1" * 64, "2" * 64],
        "initial_ledger_snapshot_sha256": "3" * 64,
        "final_ledger_snapshot_sha256": "4" * 64,
        "unresolved_cost_count": 0,
        "state": state.value,
    }
    _reseal(payload, hash_field="projection_sha256")
    return EvidenceSealBudgetProjection.model_validate_json(
        json.dumps(payload, sort_keys=True),
        strict=True,
    )


def test_raw_policy_equals_the_verifier_compiled_policy() -> None:
    compiled = compiled_evidence_seal_verdict_policy()
    loaded = load_evidence_seal_verdict_policy(VERDICT_POLICY_PATH)

    assert loaded == compiled
    assert loaded.model_dump(mode="json") == compiled.model_dump(mode="json")
    assert hashlib.sha256(VERDICT_POLICY_PATH.read_bytes()).hexdigest() == (
        AUTONOMOUS_BENCHMARK_VERDICT_POLICY_FILE_SHA256
    )


def test_wrapped_qualification_policy_equals_its_raw_source_pin() -> None:
    compiled = compiled_evidence_seal_verdict_policy()

    assert hashlib.sha256(QUALIFICATION_POLICY_PATH.read_bytes()).hexdigest() == (
        AUTONOMOUS_BENCHMARK_QUALIFICATION_POLICY_FILE_SHA256
    )
    assert load_qualification_policy(QUALIFICATION_POLICY_PATH) == (compiled.qualification_policy)


def test_lowered_and_resealed_policy_is_rejected() -> None:
    raw = compiled_evidence_seal_verdict_policy().model_dump(mode="json")
    dimension_floors = raw["dimension_floors"]
    assert isinstance(dimension_floors, list)
    dimension_floors[0]["minimum_score_micros"] = 999_999
    _reseal(raw, hash_field="policy_sha256")

    with pytest.raises(ValidationError, match="differs from verifier-compiled inputs"):
        EvidenceSealVerdictPolicy.model_validate_json(
            json.dumps(raw, sort_keys=True),
            strict=True,
        )


def test_dimension_score_equality_passes_and_one_micro_below_fails() -> None:
    at_floor = EvidenceSealDimensionVerdict(
        dimension=ModelBenchmarkDimension.ACCESS_CONTROL,
        passed=3,
        evaluated=4,
        score_micros=750_000,
        minimum_score_micros=750_000,
        state=EvidenceSealRequirementState.PASS,
    )
    one_below = EvidenceSealDimensionVerdict(
        dimension=ModelBenchmarkDimension.ACCESS_CONTROL,
        passed=3,
        evaluated=4,
        score_micros=750_000,
        minimum_score_micros=750_001,
        state=EvidenceSealRequirementState.FAIL,
    )

    assert at_floor.state is EvidenceSealRequirementState.PASS
    assert one_below.state is EvidenceSealRequirementState.FAIL

    raw = one_below.model_dump(mode="json")
    raw["state"] = EvidenceSealRequirementState.PASS.value
    with pytest.raises(ValidationError, match="dimension arithmetic is inconsistent"):
        EvidenceSealDimensionVerdict.model_validate_json(
            json.dumps(raw, sort_keys=True),
            strict=True,
        )


def test_paired_outcome_relation_reports_exact_equality() -> None:
    outcomes = (
        EvidenceSealCaseDimensionOutcome(
            case_id=_CASE_A,
            dimension=ModelBenchmarkDimension.ACCESS_CONTROL,
            passed=True,
        ),
        EvidenceSealCaseDimensionOutcome(
            case_id=_CASE_B,
            dimension=ModelBenchmarkDimension.REPORT_QUALITY,
            passed=False,
        ),
    )

    assert (
        compare_evidence_seal_case_dimension_outcomes(
            candidate=outcomes,
            baseline=outcomes,
        )
        is EvidenceSealPairedOutcomeRelation.EQUAL
    )


def test_paired_outcome_relation_reports_strict_dominance_without_regression() -> None:
    candidate = (
        EvidenceSealCaseDimensionOutcome(
            case_id=_CASE_A,
            dimension=ModelBenchmarkDimension.ACCESS_CONTROL,
            passed=True,
        ),
        EvidenceSealCaseDimensionOutcome(
            case_id=_CASE_B,
            dimension=ModelBenchmarkDimension.REPORT_QUALITY,
            passed=True,
        ),
    )
    baseline = (
        candidate[0],
        candidate[1].model_copy(update={"passed": False}),
    )

    assert (
        compare_evidence_seal_case_dimension_outcomes(
            candidate=candidate,
            baseline=baseline,
        )
        is EvidenceSealPairedOutcomeRelation.STRICTLY_DOMINATES
    )


def test_paired_outcome_relation_reports_mixed_gain_and_regression() -> None:
    candidate = (
        EvidenceSealCaseDimensionOutcome(
            case_id=_CASE_A,
            dimension=ModelBenchmarkDimension.ACCESS_CONTROL,
            passed=True,
        ),
        EvidenceSealCaseDimensionOutcome(
            case_id=_CASE_B,
            dimension=ModelBenchmarkDimension.REPORT_QUALITY,
            passed=False,
        ),
    )
    baseline = (
        candidate[0].model_copy(update={"passed": False}),
        candidate[1].model_copy(update={"passed": True}),
    )

    assert (
        compare_evidence_seal_case_dimension_outcomes(
            candidate=candidate,
            baseline=baseline,
        )
        is EvidenceSealPairedOutcomeRelation.REGRESSES_OR_MIXED
    )


def test_paired_outcome_relation_reports_mismatched_inventory() -> None:
    candidate = (
        EvidenceSealCaseDimensionOutcome(
            case_id=_CASE_A,
            dimension=ModelBenchmarkDimension.ACCESS_CONTROL,
            passed=True,
        ),
    )
    baseline = (
        EvidenceSealCaseDimensionOutcome(
            case_id=_CASE_B,
            dimension=ModelBenchmarkDimension.ACCESS_CONTROL,
            passed=True,
        ),
    )

    assert (
        compare_evidence_seal_case_dimension_outcomes(
            candidate=candidate,
            baseline=baseline,
        )
        is EvidenceSealPairedOutcomeRelation.INCOMPARABLE
    )


def test_paired_baseline_duplicate_outcome_keys_fail_closed() -> None:
    outcome = EvidenceSealCaseDimensionOutcome(
        case_id=_CASE_A,
        dimension=ModelBenchmarkDimension.ACCESS_CONTROL,
        passed=True,
    )

    with pytest.raises(ValueError, match="candidate outcome inventory repeats a key"):
        compare_evidence_seal_case_dimension_outcomes(
            candidate=(outcome, outcome),
            baseline=(outcome,),
        )


def test_budget_ceiling_is_strictly_less_than_250_usd() -> None:
    below = _budget_projection(
        campaign_cost_usd_exact="249.999999999999999999",
        state=EvidenceSealRequirementState.PASS,
    )
    equal = _budget_projection(
        campaign_cost_usd_exact="250",
        state=EvidenceSealRequirementState.FAIL,
    )

    assert below.state is EvidenceSealRequirementState.PASS
    assert equal.state is EvidenceSealRequirementState.FAIL


def test_missing_budget_closure_is_unevaluable(
    autonomous_verdict_fixture: _AuthorityFixture,
) -> None:
    verdict = autonomous_verdict_fixture.verdict

    assert verdict.budget.scope is EvidenceSealBudgetScope.REPORT_USAGE_LOWER_BOUND
    assert verdict.budget.state is EvidenceSealRequirementState.UNEVALUABLE
    assert EvidenceSealVerdictReason.BUDGET_CLOSURE_MISSING in verdict.reason_codes

    raw = verdict.budget.model_dump(mode="json")
    raw["state"] = EvidenceSealRequirementState.PASS.value
    _reseal(raw, hash_field="projection_sha256")
    with pytest.raises(ValidationError, match="budget state is inconsistent"):
        EvidenceSealBudgetProjection.model_validate_json(
            json.dumps(raw, sort_keys=True),
            strict=True,
        )


def test_mock_fixture_is_nonpositive_and_baseline_is_explicitly_unevaluable(
    autonomous_verdict_fixture: _AuthorityFixture,
) -> None:
    verdict = autonomous_verdict_fixture.verdict

    assert verdict.execution_evidence_state is EvidenceSealRequirementState.UNEVALUABLE
    assert verdict.policy_disposition is EvidenceSealPolicyDisposition.NOT_SATISFIED
    assert verdict.baseline_disposition is EvidenceSealBaselineDisposition.UNEVALUABLE
    assert EvidenceSealVerdictReason.EXECUTION_NOT_REAL in verdict.reason_codes
    assert EvidenceSealVerdictReason.BASELINE_NOT_FROZEN in verdict.reason_codes

    raw = verdict.model_dump(mode="json")
    raw["baseline_disposition"] = EvidenceSealBaselineDisposition.DOES_NOT_OUTPERFORM.value
    _reseal(raw, hash_field="verdict_sha256")
    with pytest.raises(ValidationError):
        EvidenceSealVerdictProjection.model_validate_json(
            json.dumps(raw, sort_keys=True),
            strict=True,
        )


@pytest.mark.parametrize("field", _VERDICT_AUTHORITY_FLAGS)
def test_durable_verdict_flags_cannot_be_resealed_true(
    autonomous_verdict_fixture: _AuthorityFixture,
    field: str,
) -> None:
    verdict = autonomous_verdict_fixture.verdict
    assert getattr(verdict, field) is False

    raw = verdict.model_dump(mode="json")
    raw[field] = True
    _reseal(raw, hash_field="verdict_sha256")
    with pytest.raises(ValidationError, match="literal false"):
        EvidenceSealVerdictProjection.model_validate_json(
            json.dumps(raw, sort_keys=True),
            strict=True,
        )


def test_verdict_is_identical_when_builder_inputs_are_reordered(
    autonomous_verdict_fixture: _AuthorityFixture,
) -> None:
    fixture = autonomous_verdict_fixture
    reordered = build_evidence_seal_verdict_projection(
        benchmark_suite=fixture.suite,
        ground_truth_projection=fixture.ground_projection,
        policy=fixture.verdict_policy,
        collision_map=fixture.collision_map,
        decision_projections=tuple(reversed(fixture.projections)),
        benchmark_reports=(fixture.replay_report, fixture.primary_report),
    )

    assert reordered == fixture.verdict
    assert reordered.model_dump_json() == fixture.verdict.model_dump_json()
    assert reordered.verdict_sha256 == fixture.verdict.verdict_sha256


def test_resealed_decision_case_hashes_cannot_detach_from_reports(
    autonomous_verdict_fixture: _AuthorityFixture,
) -> None:
    fixture = autonomous_verdict_fixture
    detached_projections: list[EvidenceSealDecisionProjection] = []
    for projection in fixture.projections:
        raw = projection.model_dump(mode="json")
        case_hashes = raw["case_outcome_sha256s"]
        assert isinstance(case_hashes, list)
        case_hashes[0] = "f" * 64
        _reseal_decision_output(raw)
        detached_projections.append(
            EvidenceSealDecisionProjection.model_validate_json(
                json.dumps(raw, sort_keys=True),
                strict=True,
            )
        )

    assert len({item.deterministic_output_sha256 for item in detached_projections}) == 1
    with pytest.raises(ValueError, match="decision projection differs from its report"):
        build_evidence_seal_verdict_projection(
            benchmark_suite=fixture.suite,
            ground_truth_projection=fixture.ground_projection,
            policy=fixture.verdict_policy,
            collision_map=fixture.collision_map,
            decision_projections=tuple(detached_projections),
            benchmark_reports=(fixture.primary_report, fixture.replay_report),
        )


@pytest.mark.parametrize("attack", ["mock-as-real", "perfect-scores"])
def test_resealed_detached_verdict_cannot_relabel_or_rewrite_report_evidence(
    autonomous_verdict_fixture: _AuthorityFixture,
    attack: str,
) -> None:
    fixture = autonomous_verdict_fixture
    raw = fixture.verdict.model_dump(mode="json")
    reason_codes = raw["reason_codes"]
    assert isinstance(reason_codes, list)

    if attack == "mock-as-real":
        bindings = raw["report_bindings"]
        assert isinstance(bindings, list)
        for binding in bindings:
            binding["execution_evidence"] = "real"
            _reseal(binding, hash_field="binding_sha256")
        raw["report_binding_set_sha256"] = canonical_sha256(bindings)
        raw["execution_evidence_state"] = EvidenceSealRequirementState.PASS.value
        raw["reason_codes"] = [
            reason
            for reason in reason_codes
            if reason != EvidenceSealVerdictReason.EXECUTION_NOT_REAL.value
        ]
    else:
        outcomes = raw["case_dimension_outcomes"]
        dimensions = raw["dimensions"]
        assert isinstance(outcomes, list)
        assert isinstance(dimensions, list)
        for outcome in outcomes:
            outcome["passed"] = True
        raw["case_dimension_outcome_set_sha256"] = canonical_sha256(outcomes)
        for dimension in dimensions:
            dimension["passed"] = dimension["evaluated"]
            dimension["score_micros"] = 1_000_000
            dimension["state"] = EvidenceSealRequirementState.PASS.value
        raw["overall_score_micros"] = 1_000_000
        raw["overall_state"] = EvidenceSealRequirementState.PASS.value
        raw["reason_codes"] = [
            reason
            for reason in reason_codes
            if reason
            not in {
                EvidenceSealVerdictReason.DIMENSION_FLOOR_NOT_MET.value,
                EvidenceSealVerdictReason.OVERALL_FLOOR_NOT_MET.value,
            }
        ]

    _refresh_verdict_disposition(raw)
    _reseal(raw, hash_field="verdict_sha256")
    detached = EvidenceSealVerdictProjection.model_validate_json(
        json.dumps(raw, sort_keys=True),
        strict=True,
    )

    with pytest.raises(ValidationError, match="verdict differs from its authority subject"):
        build_evidence_authority_subject(
            benchmark_suite=fixture.suite,
            ground_truth_projection=fixture.ground_projection,
            collision_map=fixture.collision_map,
            decision_projections=fixture.projections,
            benchmark_reports=(fixture.primary_report, fixture.replay_report),
            verdict_projection=detached,
        )


@pytest.mark.parametrize("attack", ["replay-identities", "fabricated-budget-closure"])
def test_subject_rebuilds_detached_report_and_budget_claims(
    autonomous_verdict_fixture: _AuthorityFixture,
    attack: str,
) -> None:
    fixture = autonomous_verdict_fixture
    raw = fixture.verdict.model_dump(mode="json")
    reason_codes = raw["reason_codes"]
    assert isinstance(reason_codes, list)
    if attack == "replay-identities":
        bindings = raw["report_bindings"]
        assert isinstance(bindings, list)
        replay = bindings[1]
        request_ids = sorted(
            f"detached-request-{index}" for index in range(replay["usage_record_count"])
        )
        generation_ids = sorted(
            f"detached-generation-{index}" for index in range(replay["usage_record_count"])
        )
        replay["request_ids"] = request_ids
        replay["request_id_set_sha256"] = canonical_sha256(request_ids)
        replay["generation_ids"] = generation_ids
        replay["generation_id_set_sha256"] = canonical_sha256(generation_ids)
        _reseal(replay, hash_field="binding_sha256")
        raw["report_binding_set_sha256"] = canonical_sha256(bindings)
        raw["replay_state"] = EvidenceSealRequirementState.PASS.value
        raw["reason_codes"] = [
            reason
            for reason in reason_codes
            if reason != EvidenceSealVerdictReason.REPLAY_IDENTITY_REUSED.value
        ]
    else:
        raw["budget"] = _budget_projection(
            campaign_cost_usd_exact="1",
            state=EvidenceSealRequirementState.PASS,
        ).model_dump(mode="json")
        raw["reason_codes"] = [
            reason
            for reason in reason_codes
            if reason != EvidenceSealVerdictReason.BUDGET_CLOSURE_MISSING.value
        ]
    _refresh_verdict_disposition(raw)
    _reseal(raw, hash_field="verdict_sha256")
    detached = EvidenceSealVerdictProjection.model_validate_json(
        json.dumps(raw, sort_keys=True),
        strict=True,
    )

    with pytest.raises(ValueError, match="differs from its exact benchmark inputs"):
        build_evidence_authority_subject(
            benchmark_suite=fixture.suite,
            ground_truth_projection=fixture.ground_projection,
            collision_map=fixture.collision_map,
            decision_projections=fixture.projections,
            benchmark_reports=(fixture.primary_report, fixture.replay_report),
            verdict_projection=detached,
        )


def test_malformed_resealed_verdict_is_rejected(
    autonomous_verdict_fixture: _AuthorityFixture,
) -> None:
    raw = autonomous_verdict_fixture.verdict.model_dump(mode="json")
    dimensions = raw["dimensions"]
    assert isinstance(dimensions, list)
    dimensions[0]["score_micros"] += 1
    _reseal(raw, hash_field="verdict_sha256")

    with pytest.raises(ValidationError, match="dimension arithmetic is inconsistent"):
        EvidenceSealVerdictProjection.model_validate_json(
            json.dumps(raw, sort_keys=True),
            strict=True,
        )


def test_coherent_resealed_overall_state_detached_from_dimensions_is_rejected(
    autonomous_verdict_fixture: _AuthorityFixture,
) -> None:
    raw = autonomous_verdict_fixture.verdict.model_dump(mode="json")
    assert raw["overall_score_micros"] != 1_000_000
    raw["overall_score_micros"] = 1_000_000
    raw["overall_state"] = EvidenceSealRequirementState.PASS.value
    reason_codes = raw["reason_codes"]
    assert isinstance(reason_codes, list)
    raw["reason_codes"] = [
        reason
        for reason in reason_codes
        if reason != EvidenceSealVerdictReason.OVERALL_FLOOR_NOT_MET.value
    ]
    _reseal(raw, hash_field="verdict_sha256")

    with pytest.raises(ValidationError, match="overall score is inconsistent"):
        EvidenceSealVerdictProjection.model_validate_json(
            json.dumps(raw, sort_keys=True),
            strict=True,
        )


def test_verdict_builder_rejects_ground_truth_projection_with_wrong_origin_kind(
    autonomous_verdict_fixture: _AuthorityFixture,
) -> None:
    fixture = autonomous_verdict_fixture
    wrong_origin = replace(
        fixture.ground_projection,
        origin_kinds=(GroundTruthOriginKind.PUBLIC_ESTABLISHED,),
    )

    with pytest.raises(ValueError, match="ground-truth projection differs from compiled pins"):
        build_evidence_seal_verdict_projection(
            benchmark_suite=fixture.suite,
            ground_truth_projection=wrong_origin,
            policy=fixture.verdict_policy,
            collision_map=fixture.collision_map,
            decision_projections=fixture.projections,
            benchmark_reports=(fixture.primary_report, fixture.replay_report),
        )


def test_structurally_valid_resealed_detached_verdict_is_rejected_by_subject(
    autonomous_verdict_fixture: _AuthorityFixture,
) -> None:
    fixture = autonomous_verdict_fixture
    raw = fixture.verdict.model_dump(mode="json")
    raw["candidate_binding_sha256"] = "f" * 64
    _reseal(raw, hash_field="verdict_sha256")
    detached = EvidenceSealVerdictProjection.model_validate_json(
        json.dumps(raw, sort_keys=True),
        strict=True,
    )

    with pytest.raises(ValidationError, match="verdict differs from its authority subject"):
        build_evidence_authority_subject(
            benchmark_suite=fixture.suite,
            ground_truth_projection=fixture.ground_projection,
            collision_map=fixture.collision_map,
            decision_projections=fixture.projections,
            benchmark_reports=(fixture.primary_report, fixture.replay_report),
            verdict_projection=detached,
        )
