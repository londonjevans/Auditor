from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.policy_eligibility import (
    ClientConstraintMode,
    ClientPolicyConstraints,
    ModelPolicyEligibilityArtifact,
    ModelPolicyEligibilityDetermination,
    OfficialPolicyEvidenceReference,
    PolicyAuditContext,
    PolicyCriterionAssessment,
    PolicyCriterionDisposition,
    PolicyEligibilityDecision,
    PolicyEligibilityEvaluation,
    PolicyEligibilityRoute,
    PolicyEvidenceKind,
    PolicyExclusionReason,
    PolicyLegalCriterion,
    PolicyReviewReason,
    PolicyUsePurpose,
    build_client_policy_constraints,
    build_model_policy_eligibility_artifact,
    build_model_policy_eligibility_determination,
    build_official_policy_evidence_reference,
    build_policy_audit_context,
    build_policy_criterion_assessment,
    build_policy_eligibility_route,
    build_policy_eligibility_source_reference_observation,
    evaluate_model_policy_eligibility,
    policy_eligibility_candidate_routes_sha256,
    policy_review_signal,
)
from mmaudit.privacy import PrivacySourceClassification

RETRIEVED_AT = datetime(2026, 8, 17, 8, 0, tzinfo=UTC)
REVIEWED_AT = datetime(2026, 8, 17, 9, 0, tzinfo=UTC)
EFFECTIVE_AT = datetime(2026, 8, 17, 9, 0, tzinfo=UTC)
OBSERVED_AT = datetime(2026, 8, 17, 10, 0, tzinfo=UTC)
EXPIRES_AT = datetime(2026, 8, 24, 9, 0, tzinfo=UTC)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _route(
    model_id: str = "alpha/atlas-1",
    provider: str = "Provider Alpha",
    endpoint: str = "provider-alpha/exact-1",
) -> PolicyEligibilityRoute:
    return build_policy_eligibility_route(
        exact_model_id=model_id,
        provider_name=provider,
        provider_endpoint=endpoint,
    )


def _evidence(label: str = "terms") -> OfficialPolicyEvidenceReference:
    return build_official_policy_evidence_reference(
        kind=PolicyEvidenceKind.MODEL_PROVIDER_TERMS,
        publisher="Provider Alpha",
        official_source_url=f"https://policy.example/{label}",
        source_version="2026-08",
        retrieved_at=RETRIEVED_AT,
        content_sha256=_sha(f"content:{label}"),
        byte_count=512,
    )


def _assessments(
    evidence_sha256: str,
    *,
    disposition: PolicyCriterionDisposition = PolicyCriterionDisposition.PERMITTED,
    override: dict[PolicyLegalCriterion, PolicyCriterionDisposition] | None = None,
) -> tuple[PolicyCriterionAssessment, ...]:
    override = override or {}
    return tuple(
        build_policy_criterion_assessment(
            criterion=criterion,
            disposition=override.get(criterion, disposition),
            evidence_reference_sha256s=(evidence_sha256,),
            assessment_record_sha256=_sha(f"assessment:{criterion.value}"),
        )
        for criterion in sorted(PolicyLegalCriterion, key=lambda item: item.value)
    )


def _determination(
    route: PolicyEligibilityRoute,
    evidence_sha256: str,
    *,
    decision: PolicyEligibilityDecision = PolicyEligibilityDecision.ELIGIBLE,
    dispositions: dict[PolicyLegalCriterion, PolicyCriterionDisposition] | None = None,
    intended_use: PolicyUsePurpose = (PolicyUsePurpose.PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT),
    applicable_client_entity_sha256s: tuple[str, ...] = (_sha("client-entity"),),
    applicable_client_jurisdictions: tuple[str, ...] = ("GB",),
    applicable_operator_entity_sha256s: tuple[str, ...] = (_sha("operator-entity"),),
    applicable_operator_jurisdictions: tuple[str, ...] = ("GB",),
    reviewed_at: datetime = REVIEWED_AT,
    effective_at: datetime = EFFECTIVE_AT,
    expires_at: datetime = EXPIRES_AT,
) -> ModelPolicyEligibilityDetermination:
    return build_model_policy_eligibility_determination(
        route=route,
        decision=decision,
        intended_use=intended_use,
        applicable_client_entity_sha256s=applicable_client_entity_sha256s,
        applicable_client_jurisdictions=applicable_client_jurisdictions,
        applicable_operator_entity_sha256s=applicable_operator_entity_sha256s,
        applicable_operator_jurisdictions=applicable_operator_jurisdictions,
        assessments=_assessments(evidence_sha256, override=dispositions),
        reviewed_by="legal-reviewer@example.test",
        reviewed_at=reviewed_at,
        effective_at=effective_at,
        expires_at=expires_at,
        review_record_sha256=_sha(f"review:{route.route_sha256}:{decision.value}"),
    )


def _context(**overrides: Any) -> PolicyAuditContext:
    values: dict[str, Any] = {
        "audit_scope_sha256": _sha("audit-scope"),
        "source_sha256": _sha("source"),
        "source_classification": PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        "intended_use": PolicyUsePurpose.PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT,
        "client_entity_sha256": _sha("client-entity"),
        "client_jurisdiction": "GB",
        "operator_entity_sha256": _sha("operator-entity"),
        "operator_jurisdiction": "GB",
    }
    values.update(overrides)
    return build_policy_audit_context(**values)


def _constraints(
    context: PolicyAuditContext | None = None, **overrides: Any
) -> ClientPolicyConstraints:
    values: dict[str, Any] = {
        "audit_context": context or _context(),
        "mode": ClientConstraintMode.DENY_ONLY,
        "provider_names": (),
        "exact_model_ids": (),
        "exact_routes": (),
        "reviewed_by": "client-policy-reviewer@example.test",
        "reviewed_at": REVIEWED_AT,
        "effective_at": EFFECTIVE_AT,
        "expires_at": EXPIRES_AT,
        "constraint_basis_sha256": _sha("client-constraint-basis"),
    }
    values.update(overrides)
    return build_client_policy_constraints(**values)


def _artifact(
    routes: tuple[PolicyEligibilityRoute, ...] = (_route(),),
    *,
    decisions: tuple[PolicyEligibilityDecision, ...] | None = None,
    dispositions: tuple[dict[PolicyLegalCriterion, PolicyCriterionDisposition] | None, ...]
    | None = None,
    reviewed_at: datetime = REVIEWED_AT,
    effective_at: datetime = EFFECTIVE_AT,
    expires_at: datetime = EXPIRES_AT,
) -> ModelPolicyEligibilityArtifact:
    evidence = _evidence()
    decisions = decisions or tuple(PolicyEligibilityDecision.ELIGIBLE for _ in routes)
    dispositions = dispositions or tuple(None for _ in routes)
    determinations = tuple(
        _determination(
            route,
            evidence.reference_sha256,
            decision=decision,
            dispositions=route_dispositions,
            reviewed_at=reviewed_at,
            effective_at=effective_at,
            expires_at=expires_at,
        )
        for route, decision, route_dispositions in zip(routes, decisions, dispositions, strict=True)
    )
    return build_model_policy_eligibility_artifact(
        created_at=max(REVIEWED_AT, reviewed_at),
        official_evidence=(evidence,),
        determinations=determinations,
    )


def _reason_set(evaluation: PolicyEligibilityEvaluation) -> set[PolicyExclusionReason]:
    assert len(evaluation.exclusions) == 1
    return set(evaluation.exclusions[0].reasons)


def test_structural_evaluation_is_exact_current_and_explicitly_non_authorizing() -> None:
    route = _route()
    context = _context()
    artifact = _artifact((route,))
    constraints = _constraints(context)

    evaluation = evaluate_model_policy_eligibility(
        artifact=artifact,
        client_constraints=constraints,
        audit_context=context,
        technical_routes=(route,),
        observed_at=OBSERVED_AT,
    )

    assert evaluation.eligible_routes == (route,)
    assert evaluation.eligible_model_ids == (route.exact_model_id,)
    assert evaluation.exclusions == ()
    assert evaluation.expires_at == EXPIRES_AT
    assert evaluation.technical_route_set_sha256 == policy_eligibility_candidate_routes_sha256(
        (route,)
    )
    assert evaluation.operator_decision_authenticity == "NOT_INDEPENDENTLY_PROVEN"
    assert evaluation.automated_eligibility_inference is False
    assert evaluation.production_selection_authorized is False
    assert artifact.operator_decision_authenticity == "NOT_INDEPENDENTLY_PROVEN"
    assert artifact.automated_eligibility_inference is False
    assert artifact.production_selection_authorized is False


@pytest.mark.parametrize(
    ("decision", "override", "match"),
    [
        (
            PolicyEligibilityDecision.ELIGIBLE,
            {PolicyLegalCriterion.SOURCE_CODE_ANALYSIS: (PolicyCriterionDisposition.AMBIGUOUS)},
            "every criterion",
        ),
        (PolicyEligibilityDecision.INELIGIBLE, {}, "prohibited criterion"),
        (PolicyEligibilityDecision.REVIEW_REQUIRED, {}, "requires ambiguity"),
        (
            PolicyEligibilityDecision.REVIEW_REQUIRED,
            {PolicyLegalCriterion.SOURCE_CODE_ANALYSIS: (PolicyCriterionDisposition.PROHIBITED)},
            "without a prohibition",
        ),
    ],
)
def test_decision_must_match_the_complete_fixed_criterion_set(
    decision: PolicyEligibilityDecision,
    override: dict[PolicyLegalCriterion, PolicyCriterionDisposition],
    match: str,
) -> None:
    route = _route()
    evidence = _evidence()
    with pytest.raises(ValidationError, match=match):
        _determination(
            route,
            evidence.reference_sha256,
            decision=decision,
            dispositions=override,
        )


def test_client_entity_and_jurisdiction_is_an_explicit_evidence_bound_criterion() -> None:
    route = _route()
    evidence = _evidence()
    assessments = tuple(
        item
        for item in _assessments(evidence.reference_sha256)
        if item.criterion is not PolicyLegalCriterion.CLIENT_ENTITY_AND_JURISDICTION
    )
    duplicate = build_policy_criterion_assessment(
        criterion=PolicyLegalCriterion.SOURCE_CODE_ANALYSIS,
        disposition=PolicyCriterionDisposition.PERMITTED,
        evidence_reference_sha256s=(evidence.reference_sha256,),
        assessment_record_sha256=_sha("duplicate-client-jurisdiction-assessment"),
    )
    invalid = tuple(sorted((*assessments, duplicate), key=lambda item: item.criterion.value))

    with pytest.raises(ValidationError, match="exact, unique, and sorted"):
        build_model_policy_eligibility_determination(
            route=route,
            decision=PolicyEligibilityDecision.ELIGIBLE,
            intended_use=PolicyUsePurpose.PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT,
            applicable_client_entity_sha256s=(_sha("client-entity"),),
            applicable_client_jurisdictions=("GB",),
            applicable_operator_entity_sha256s=(_sha("operator-entity"),),
            applicable_operator_jurisdictions=("GB",),
            assessments=invalid,
            reviewed_by="legal-reviewer@example.test",
            reviewed_at=REVIEWED_AT,
            effective_at=EFFECTIVE_AT,
            expires_at=EXPIRES_AT,
            review_record_sha256=_sha("review:missing-client-jurisdiction"),
        )


def test_missing_and_route_mismatch_are_distinct_from_technical_unavailability() -> None:
    reviewed = _route()
    wrong_route = _route(endpoint="provider-alpha/exact-2")
    missing_model = _route(
        model_id="beta/borealis-2",
        provider="Provider Beta",
        endpoint="provider-beta/exact-2",
    )
    context = _context()
    evaluation = evaluate_model_policy_eligibility(
        artifact=_artifact((reviewed,)),
        client_constraints=_constraints(context),
        audit_context=context,
        technical_routes=(wrong_route, missing_model),
        observed_at=OBSERVED_AT,
    )

    reasons = {item.route.exact_model_id: set(item.reasons) for item in evaluation.exclusions}
    assert reasons[missing_model.exact_model_id] == {PolicyExclusionReason.MISSING_DETERMINATION}
    assert reasons[wrong_route.exact_model_id] == {PolicyExclusionReason.ROUTE_MISMATCH}


@pytest.mark.parametrize(
    ("artifact", "expected"),
    [
        (
            _artifact(expires_at=OBSERVED_AT),
            PolicyExclusionReason.DETERMINATION_EXPIRED,
        ),
        (
            _artifact(
                reviewed_at=OBSERVED_AT + timedelta(hours=1),
                effective_at=OBSERVED_AT + timedelta(hours=1),
                expires_at=OBSERVED_AT + timedelta(days=2),
            ),
            PolicyExclusionReason.DETERMINATION_FUTURE,
        ),
        (
            _artifact(
                decisions=(PolicyEligibilityDecision.INELIGIBLE,),
                dispositions=(
                    {
                        PolicyLegalCriterion.SOURCE_CODE_ANALYSIS: (
                            PolicyCriterionDisposition.PROHIBITED
                        )
                    },
                ),
            ),
            PolicyExclusionReason.DECISION_INELIGIBLE,
        ),
        (
            _artifact(
                decisions=(PolicyEligibilityDecision.REVIEW_REQUIRED,),
                dispositions=(
                    {
                        PolicyLegalCriterion.SOURCE_CODE_ANALYSIS: (
                            PolicyCriterionDisposition.AMBIGUOUS
                        )
                    },
                ),
            ),
            PolicyExclusionReason.DECISION_REVIEW_REQUIRED,
        ),
    ],
)
def test_stale_future_and_noneligible_decisions_fail_closed(
    artifact: ModelPolicyEligibilityArtifact,
    expected: PolicyExclusionReason,
) -> None:
    route = artifact.determinations[0].route
    context = _context()
    evaluation = evaluate_model_policy_eligibility(
        artifact=artifact,
        client_constraints=_constraints(context),
        audit_context=context,
        technical_routes=(route,),
        observed_at=OBSERVED_AT,
    )
    assert expected in _reason_set(evaluation)
    assert evaluation.eligible_model_ids == ()
    assert evaluation.expires_at is None


@pytest.mark.parametrize(
    ("context_override", "expected"),
    [
        ({"audit_scope_sha256": _sha("other-audit")}, PolicyExclusionReason.AUDIT_SCOPE_RESTRICTED),
        ({"source_sha256": _sha("other-source")}, PolicyExclusionReason.SOURCE_RESTRICTED),
        (
            {"client_entity_sha256": _sha("other-client")},
            PolicyExclusionReason.CLIENT_ENTITY_RESTRICTED,
        ),
        ({"client_jurisdiction": "US-CA"}, PolicyExclusionReason.CLIENT_JURISDICTION_RESTRICTED),
        (
            {"operator_entity_sha256": _sha("other-operator")},
            PolicyExclusionReason.OPERATOR_ENTITY_RESTRICTED,
        ),
        (
            {"operator_jurisdiction": "US-NY"},
            PolicyExclusionReason.OPERATOR_JURISDICTION_RESTRICTED,
        ),
    ],
)
def test_per_audit_source_client_and_operator_bindings_are_exact(
    context_override: dict[str, Any],
    expected: PolicyExclusionReason,
) -> None:
    route = _route()
    expected_context = _context()
    observed_context = _context(**context_override)
    evaluation = evaluate_model_policy_eligibility(
        artifact=_artifact((route,)),
        client_constraints=_constraints(expected_context),
        audit_context=observed_context,
        technical_routes=(route,),
        observed_at=OBSERVED_AT,
    )
    assert expected in _reason_set(evaluation)


@pytest.mark.parametrize(
    ("context_override", "expected"),
    [
        (
            {
                "intended_use": PolicyUsePurpose.PUBLIC_OR_SYNTHETIC_DEFENSIVE_EVALUATION,
            },
            PolicyExclusionReason.USE_PURPOSE_RESTRICTED,
        ),
        (
            {"client_entity_sha256": _sha("other-client")},
            PolicyExclusionReason.CLIENT_ENTITY_RESTRICTED,
        ),
        (
            {"client_jurisdiction": "US-CA"},
            PolicyExclusionReason.CLIENT_JURISDICTION_RESTRICTED,
        ),
        (
            {"operator_entity_sha256": _sha("other-operator")},
            PolicyExclusionReason.OPERATOR_ENTITY_RESTRICTED,
        ),
        (
            {"operator_jurisdiction": "US-NY"},
            PolicyExclusionReason.OPERATOR_JURISDICTION_RESTRICTED,
        ),
    ],
)
def test_determination_applicability_is_independent_of_matching_client_constraints(
    context_override: dict[str, Any],
    expected: PolicyExclusionReason,
) -> None:
    route = _route()
    observed_context = _context(**context_override)
    evaluation = evaluate_model_policy_eligibility(
        artifact=_artifact((route,)),
        client_constraints=_constraints(observed_context),
        audit_context=observed_context,
        technical_routes=(route,),
        observed_at=OBSERVED_AT,
    )
    assert expected in _reason_set(evaluation)
    assert evaluation.eligible_routes == ()


@pytest.mark.parametrize(
    ("constraint_overrides", "expected"),
    [
        (
            {"mode": ClientConstraintMode.ALLOW_ONLY, "provider_names": ("Other Provider",)},
            PolicyExclusionReason.CLIENT_PROVIDER_RESTRICTED,
        ),
        (
            {"mode": ClientConstraintMode.ALLOW_ONLY, "exact_model_ids": ("beta/borealis-2",)},
            PolicyExclusionReason.CLIENT_MODEL_RESTRICTED,
        ),
        (
            {
                "mode": ClientConstraintMode.ALLOW_ONLY,
                "exact_routes": (_route(endpoint="provider-alpha/exact-2"),),
            },
            PolicyExclusionReason.CLIENT_ENDPOINT_RESTRICTED,
        ),
        (
            {"mode": ClientConstraintMode.DENY_ONLY, "provider_names": ("Provider Alpha",)},
            PolicyExclusionReason.CLIENT_PROVIDER_RESTRICTED,
        ),
        (
            {"mode": ClientConstraintMode.DENY_ONLY, "exact_model_ids": ("alpha/atlas-1",)},
            PolicyExclusionReason.CLIENT_MODEL_RESTRICTED,
        ),
        (
            {"mode": ClientConstraintMode.DENY_ONLY, "exact_routes": (_route(),)},
            PolicyExclusionReason.CLIENT_ENDPOINT_RESTRICTED,
        ),
    ],
)
def test_allow_only_and_deny_only_route_constraints_have_distinct_reasons(
    constraint_overrides: dict[str, Any],
    expected: PolicyExclusionReason,
) -> None:
    route = _route()
    context = _context()
    evaluation = evaluate_model_policy_eligibility(
        artifact=_artifact((route,)),
        client_constraints=_constraints(context, **constraint_overrides),
        audit_context=context,
        technical_routes=(route,),
        observed_at=OBSERVED_AT,
    )
    assert expected in _reason_set(evaluation)


@pytest.mark.parametrize(
    ("constraint_overrides", "expected"),
    [
        (
            {
                "reviewed_at": OBSERVED_AT + timedelta(hours=1),
                "effective_at": OBSERVED_AT + timedelta(hours=1),
                "expires_at": OBSERVED_AT + timedelta(days=2),
            },
            PolicyExclusionReason.CLIENT_CONSTRAINTS_FUTURE,
        ),
        ({"expires_at": OBSERVED_AT}, PolicyExclusionReason.CLIENT_CONSTRAINTS_EXPIRED),
    ],
)
def test_client_constraint_time_is_checked_at_evaluation(
    constraint_overrides: dict[str, Any],
    expected: PolicyExclusionReason,
) -> None:
    route = _route()
    context = _context()
    evaluation = evaluate_model_policy_eligibility(
        artifact=_artifact((route,)),
        client_constraints=_constraints(context, **constraint_overrides),
        audit_context=context,
        technical_routes=(route,),
        observed_at=OBSERVED_AT,
    )
    assert expected in _reason_set(evaluation)


def test_review_helper_only_reports_fail_closed_refresh_states() -> None:
    route = _route()
    artifact = _artifact((route,))
    reference = artifact.official_evidence[0]
    expected_source = (
        build_policy_eligibility_source_reference_observation(
            reference=reference,
            current_content_sha256=reference.content_sha256,
        ),
    )

    assert (
        policy_review_signal(
            artifact=artifact,
            route=route,
            observed_at=OBSERVED_AT,
            source_reference_observations=expected_source,
        )
        is None
    )

    changed = policy_review_signal(
        artifact=artifact,
        route=route,
        observed_at=OBSERVED_AT,
        source_reference_observations=(
            build_policy_eligibility_source_reference_observation(
                reference=reference,
                current_content_sha256=_sha("changed-policy"),
            ),
        ),
    )
    assert changed is not None
    assert changed.reasons == (PolicyReviewReason.SOURCE_CHANGED,)
    assert changed.automated_eligibility_inference is False
    assert changed.production_selection_authorized is False

    missing = policy_review_signal(
        artifact=artifact,
        route=_route(model_id="beta/borealis-2"),
        observed_at=OBSERVED_AT,
    )
    assert missing is not None
    assert missing.reasons == (PolicyReviewReason.MISSING,)
    assert "ELIGIBLE" not in {reason.value for reason in PolicyReviewReason}


def test_review_helper_reports_expiry_and_operator_review_required() -> None:
    expired_artifact = _artifact(expires_at=OBSERVED_AT)
    expired = policy_review_signal(
        artifact=expired_artifact,
        route=expired_artifact.determinations[0].route,
        observed_at=OBSERVED_AT,
    )
    assert expired is not None
    assert PolicyReviewReason.EXPIRED in expired.reasons

    review_artifact = _artifact(
        decisions=(PolicyEligibilityDecision.REVIEW_REQUIRED,),
        dispositions=(
            {PolicyLegalCriterion.SOURCE_CODE_ANALYSIS: PolicyCriterionDisposition.AMBIGUOUS},
        ),
    )
    review = policy_review_signal(
        artifact=review_artifact,
        route=review_artifact.determinations[0].route,
        observed_at=OBSERVED_AT,
    )
    assert review is not None
    assert PolicyReviewReason.REVIEW_REQUIRED in review.reasons


def test_self_hash_extra_fields_coercion_and_authority_tampering_are_rejected() -> None:
    artifact = _artifact()
    payload = artifact.model_dump(mode="json")
    payload["production_selection_authorized"] = True
    with pytest.raises(ValidationError):
        ModelPolicyEligibilityArtifact.model_validate_json(json.dumps(payload), strict=True)

    payload = artifact.model_dump(mode="json")
    payload["automated_eligibility_inference"] = 0
    with pytest.raises(ValidationError):
        ModelPolicyEligibilityArtifact.model_validate_json(json.dumps(payload), strict=True)

    payload = artifact.model_dump(mode="json")
    payload["unexpected"] = "catalogue-says-eligible"
    with pytest.raises(ValidationError):
        ModelPolicyEligibilityArtifact.model_validate_json(json.dumps(payload), strict=True)

    payload = artifact.model_dump(mode="json")
    payload["determinations"][0]["decision"] = "INELIGIBLE"
    with pytest.raises(ValidationError, match=r"self-hash|prohibited criterion"):
        ModelPolicyEligibilityArtifact.model_validate_json(json.dumps(payload), strict=True)


def test_official_urls_timestamps_exact_ids_and_canonical_order_fail_closed() -> None:
    with pytest.raises(ValidationError, match="HTTPS URL"):
        build_official_policy_evidence_reference(
            kind=PolicyEvidenceKind.MODEL_PROVIDER_TERMS,
            publisher="Provider Alpha",
            official_source_url="http://policy.example/terms?token=secret",
            retrieved_at=RETRIEVED_AT,
            content_sha256=_sha("content"),
            byte_count=10,
        )
    with pytest.raises(ValidationError, match="whole-second UTC"):
        build_official_policy_evidence_reference(
            kind=PolicyEvidenceKind.MODEL_PROVIDER_TERMS,
            publisher="Provider Alpha",
            official_source_url="https://policy.example/terms",
            retrieved_at=RETRIEVED_AT.replace(microsecond=1),
            content_sha256=_sha("content"),
            byte_count=10,
        )
    with pytest.raises(ValidationError, match="exact non-routed"):
        _route(model_id="alpha/atlas-latest")

    alpha = _route()
    beta = _route(
        model_id="beta/borealis-2",
        provider="Provider Beta",
        endpoint="provider-beta/exact-2",
    )
    with pytest.raises(ValueError, match="unique and sorted"):
        policy_eligibility_candidate_routes_sha256((beta, alpha))
    with pytest.raises(ValidationError, match="allow-only"):
        _constraints(mode=ClientConstraintMode.ALLOW_ONLY)


def test_artifact_requires_exact_used_evidence_and_canonical_determinations() -> None:
    route = _route()
    evidence = _evidence()
    other = _evidence("regional")
    determination = _determination(route, evidence.reference_sha256)
    with pytest.raises(ValidationError, match="used exactly"):
        build_model_policy_eligibility_artifact(
            created_at=REVIEWED_AT,
            official_evidence=tuple(
                sorted((evidence, other), key=lambda item: item.reference_sha256)
            ),
            determinations=(determination,),
        )
    with pytest.raises(ValidationError, match="unique and sorted"):
        build_model_policy_eligibility_artifact(
            created_at=REVIEWED_AT,
            official_evidence=(evidence,),
            determinations=(determination, determination),
        )


def test_old_official_evidence_cannot_support_a_fresh_or_long_lived_determination() -> None:
    route = _route()
    stale_evidence = build_official_policy_evidence_reference(
        kind=PolicyEvidenceKind.MODEL_PROVIDER_TERMS,
        publisher="Provider Alpha",
        official_source_url="https://policy.example/stale-terms",
        retrieved_at=REVIEWED_AT - timedelta(days=32),
        content_sha256=_sha("stale-policy-content"),
        byte_count=512,
    )
    stale_determination = _determination(route, stale_evidence.reference_sha256)
    with pytest.raises(ValidationError, match="too old"):
        build_model_policy_eligibility_artifact(
            created_at=REVIEWED_AT,
            official_evidence=(stale_evidence,),
            determinations=(stale_determination,),
        )

    aging_evidence = build_official_policy_evidence_reference(
        kind=PolicyEvidenceKind.MODEL_PROVIDER_TERMS,
        publisher="Provider Alpha",
        official_source_url="https://policy.example/aging-terms",
        retrieved_at=REVIEWED_AT - timedelta(days=30),
        content_sha256=_sha("aging-policy-content"),
        byte_count=512,
    )
    outliving_determination = _determination(
        route,
        aging_evidence.reference_sha256,
        expires_at=REVIEWED_AT + timedelta(days=7),
    )
    with pytest.raises(ValidationError, match="outlives"):
        build_model_policy_eligibility_artifact(
            created_at=REVIEWED_AT,
            official_evidence=(aging_evidence,),
            determinations=(outliving_determination,),
        )


def test_determination_applicability_sets_are_nonempty_canonical_and_self_hashed() -> None:
    route = _route()
    evidence = _evidence()
    with pytest.raises(ValidationError):
        _determination(
            route,
            evidence.reference_sha256,
            applicable_client_entity_sha256s=(),
        )
    with pytest.raises(ValidationError, match="unique and sorted"):
        _determination(
            route,
            evidence.reference_sha256,
            applicable_client_jurisdictions=("US-CA", "GB"),
        )


def test_strict_frozen_models_reject_assignment() -> None:
    route = _route()
    with pytest.raises(ValidationError):
        route.provider_name = "Other"  # type: ignore[misc]
    assert ClientPolicyConstraints.model_config["strict"] is True
    assert PolicyEligibilityRoute.model_config["frozen"] is True
