from __future__ import annotations

from pathlib import Path

import pytest

from mmaudit.benchmark.models import (
    ModelBenchmarkClassification,
    ModelBenchmarkDimension,
    ModelBenchmarkFalsifierTest,
    ModelBenchmarkGroundTruthCase,
    ModelBenchmarkInvariant,
    ModelBenchmarkLocation,
    ModelBenchmarkResponse,
    ModelBenchmarkVerifierEvidence,
    _score_semantic_dimension,
    load_model_benchmark_corpus,
)

ROOT = Path(__file__).parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"


def _case_for(
    dimension: ModelBenchmarkDimension,
) -> ModelBenchmarkGroundTruthCase:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    return next(case for case in suite.ground_truth.cases if dimension in case.dimensions)


def _response_for(case: ModelBenchmarkGroundTruthCase) -> ModelBenchmarkResponse:
    expectation = case.expectation
    rationale = (
        "The supplied source evidence demonstrates "
        + " ".join(expectation.required_analysis_terms)
        + " through the cited state transition."
        if expectation.required_analysis_terms
        else "The supplied source evidence supports the exact cited state transition."
    )
    invariant = (
        ModelBenchmarkInvariant(
            kind=expectation.invariant_kind,
            property_statement=(
                "The security property requires "
                + " ".join(expectation.required_invariant_terms)
                + " throughout the state transition."
            ),
            observed_quantity="The observed post-transition quantity",
            assumed_quantity="The assumed pre-transition quantity",
            remediation_condition=(
                "The safe implementation enforces "
                + " ".join(expectation.required_invariant_terms)
                + " before crediting state."
            ),
        )
        if expectation.invariant_kind is not None
        else None
    )
    verifier_evidence = (
        ModelBenchmarkVerifierEvidence(
            claim="The authorization claim is supported by the cited source behavior.",
            evidence="The source evidence shows an unguarded externally reachable update.",
            reachable_path="An external caller directly reaches the unsafe state transition.",
            locations=expectation.locations,
        )
        if expectation.expected_verifier_conclusion is not None
        else None
    )
    falsifier_test = (
        ModelBenchmarkFalsifierTest(
            counterhypothesis="The counterhypothesis is that missing-state prevents confirmation.",
            test_performed="The test searched the supplied excerpt for a concrete state witness.",
            observed_result="No decisive state-transition witness exists in the supplied evidence.",
            locations=expectation.locations,
        )
        if expectation.expected_falsifier_conclusion is not None
        else None
    )
    return ModelBenchmarkResponse(
        case_id=case.case_id,
        classification=expectation.classification,
        locations=expectation.locations,
        invariant=invariant,
        repository_instructions_followed=False,
        assumptions=expectation.required_assumptions,
        unsupported_assumptions=expectation.required_unsupported_assumptions,
        verifier_conclusion=expectation.expected_verifier_conclusion,
        falsifier_conclusion=expectation.expected_falsifier_conclusion,
        verifier_evidence=verifier_evidence,
        falsifier_test=falsifier_test,
        remediation=(
            "The safe remediation adds "
            + " ".join(expectation.required_remediation_terms)
            + " before the state transition."
            if expectation.required_remediation_terms
            else None
        ),
        rationale=rationale,
    )


def _replace(
    response: ModelBenchmarkResponse,
    **updates: object,
) -> ModelBenchmarkResponse:
    payload = response.model_dump(mode="json")
    payload.update(updates)
    return ModelBenchmarkResponse.model_validate(payload)


@pytest.mark.parametrize(
    "dimension",
    tuple(
        dimension
        for dimension in ModelBenchmarkDimension
        if dimension is not ModelBenchmarkDimension.STRUCTURED_OUTPUT_COMPLIANCE
    ),
)
def test_every_semantic_dimension_requires_exact_classification_and_locations(
    dimension: ModelBenchmarkDimension,
) -> None:
    case = _case_for(dimension)
    response = _response_for(case)
    passed, _detail = _score_semantic_dimension(dimension, case, response)
    assert passed

    if case.expectation.classification is ModelBenchmarkClassification.VULNERABILITY:
        wrong_locations: list[ModelBenchmarkLocation] = []
    else:
        wrong_locations = [
            ModelBenchmarkLocation(
                path=f"synthetic/{case.case_id}.sol",
                start_line=999,
                end_line=999,
            )
        ]
    wrong = _replace(
        response,
        locations=[item.model_dump(mode="json") for item in wrong_locations],
    )
    passed, detail = _score_semantic_dimension(dimension, case, wrong)
    assert not passed
    assert detail == "classification or exact expected source locations differed"


def test_extra_source_location_fails_even_with_correct_security_reasoning() -> None:
    dimension = ModelBenchmarkDimension.ACCESS_CONTROL
    case = _case_for(dimension)
    response = _response_for(case)
    extra = ModelBenchmarkLocation(
        path=case.expectation.locations[0].path,
        start_line=999,
        end_line=999,
    )
    wrong = _replace(
        response,
        locations=[
            *[item.model_dump(mode="json") for item in response.locations],
            extra.model_dump(mode="json"),
        ],
    )

    passed, detail = _score_semantic_dimension(dimension, case, wrong)

    assert not passed
    assert detail == "classification or exact expected source locations differed"


def test_analysis_keywords_in_wrong_fields_do_not_satisfy_reasoning() -> None:
    dimension = ModelBenchmarkDimension.CROSS_CONTRACT_BUSINESS_LOGIC
    case = _case_for(dimension)
    response = _response_for(case)
    keyword_salad = _replace(
        response,
        rationale=(
            "The supplied excerpt contains a state transition, but this sentence does "
            "not identify its relevant security concepts."
        ),
        remediation="cross-contract policy stale",
        assumptions=["cross-contract", "policy", "stale"],
    )

    passed, _detail = _score_semantic_dimension(dimension, case, keyword_salad)

    assert not passed


@pytest.mark.parametrize(
    ("dimension", "field"),
    (
        (ModelBenchmarkDimension.VERIFIER_QUALITY, "verifier_evidence"),
        (ModelBenchmarkDimension.FALSIFIER_QUALITY, "falsifier_test"),
    ),
)
def test_review_conclusion_without_structured_support_fails(
    dimension: ModelBenchmarkDimension,
    field: str,
) -> None:
    case = _case_for(dimension)
    response = _replace(_response_for(case), **{field: None})

    passed, _detail = _score_semantic_dimension(dimension, case, response)

    assert not passed


def test_verifier_keywords_require_distinct_structured_evidence() -> None:
    dimension = ModelBenchmarkDimension.VERIFIER_QUALITY
    case = _case_for(dimension)
    response = _response_for(case)
    repeated = "Authorization evidence shows a reachable external transition."
    unsupported = _replace(
        response,
        verifier_evidence={
            "claim": repeated,
            "evidence": repeated,
            "reachable_path": repeated,
            "locations": [
                location.model_dump(mode="json") for location in case.expectation.locations
            ],
        },
    )

    passed, _detail = _score_semantic_dimension(dimension, case, unsupported)

    assert not passed


def test_contradictory_rationale_fails_despite_keywords_and_exact_location() -> None:
    dimension = ModelBenchmarkDimension.ACCESS_CONTROL
    case = _case_for(dimension)
    response = _replace(
        _response_for(case),
        rationale=(
            "Authorization caller owner concepts appear here, but no vulnerability "
            "exists and this is a safe implementation."
        ),
    )

    passed, detail = _score_semantic_dimension(dimension, case, response)

    assert not passed
    assert detail == "rationale contradicted the structured classification"
