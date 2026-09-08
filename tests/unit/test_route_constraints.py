from __future__ import annotations

import gc
import hashlib
import math
from decimal import Decimal
from typing import Any

import pytest
from pydantic import ValidationError

import mmaudit.models.route_constraints as route_constraints_module
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.reasoning import ReasoningEffort
from mmaudit.models.route_constraints import (
    ROUTE_PREDICATE_IDS,
    ExactRouteConstraint,
    ExactRoutePrice,
    ExactRoutePriceTier,
    ExactRoutePricingSchedule,
    ExactRouteRole,
    NormalizedRouteFacts,
    ProviderMaxPriceComponent,
    ProviderPriceCap,
    ProviderPriceCapAlgorithm,
    RouteConstraintError,
    RouteConstraintPurpose,
    RoutePredicateDisposition,
    RoutePredicateId,
    RoutePredicateProfile,
    RoutePredicateReason,
    RoutePredicateReport,
    RoutePredicateRequirementError,
    RoutePredicateResult,
    RoutePriceComponent,
    RoutePriceComponentUnitEnvelope,
    bind_live_route_facts,
    bind_registry_route_facts,
    bind_runtime_route_facts,
    evaluate_route_predicates,
    normalize_exact_route_pricing,
    project_provider_price_cap,
    project_route_emitted_request_parameters,
    prove_provider_price_cap,
    require_route_predicates,
    route_constraint_callables_are_pristine,
)

MODEL = "acme/model-v1"
OTHER_MODEL = "other/model-v2"
ENDPOINT = "provider/fp8"
OTHER_ENDPOINT = "provider/other"
PLAN_SHA256 = "1" * 64
POLICY_SHA256 = "2" * 64
ROLE_PROFILE_SHA256 = "3" * 64
ROLE_BINDING_SHA256 = "4" * 64
CONTROL_SHA256 = "5" * 64
OTHER_SHA256 = "f" * 64
PARAMETERS = (
    "max_tokens",
    "reasoning",
    "response_format",
    "structured_outputs",
    "temperature",
)
HIGH_EFFORTS: tuple[ReasoningEffort, ...] = ("high",)
EXACT_ROUTE_CONSTRAINT_PURPOSES: tuple[RouteConstraintPurpose, ...] = (
    RouteConstraintPurpose.DISCOVERY_PUBLICATION,
    RouteConstraintPurpose.REGISTRY_PUBLICATION,
    RouteConstraintPurpose.NONCREDITING_SMOKE_ADMISSION,
    RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION,
)


def _pricing() -> tuple[ExactRoutePrice, ...]:
    return (
        ExactRoutePrice(
            component=RoutePriceComponent.COMPLETION,
            unit_price="0.0000009",
        ),
        ExactRoutePrice(
            component=RoutePriceComponent.INPUT_CACHE_READ,
            unit_price="0.0000005",
        ),
        ExactRoutePrice(
            component=RoutePriceComponent.PROMPT,
            unit_price="0.000001234567890123456789",
        ),
        ExactRoutePrice(component=RoutePriceComponent.REQUEST, unit_price="0"),
        ExactRoutePrice(component=RoutePriceComponent.WEB_SEARCH, unit_price="0"),
    )


def test_exact_route_pricing_normalization_is_canonical_and_closed() -> None:
    assert normalize_exact_route_pricing(
        {
            "prompt": "0.000001",
            "completion": "0.000002",
            "request": "0",
        }
    ) == (
        ExactRoutePrice(component=RoutePriceComponent.COMPLETION, unit_price="0.000002"),
        ExactRoutePrice(component=RoutePriceComponent.PROMPT, unit_price="0.000001"),
        ExactRoutePrice(component=RoutePriceComponent.REQUEST, unit_price="0"),
    )
    with pytest.raises(RouteConstraintError, match="pricing mapping"):
        normalize_exact_route_pricing({"prompt": "0.000001", "unsupported": "0.000002"})


def _profile() -> RoutePredicateProfile:
    return RoutePredicateProfile.build(
        reasoning_policy_sha256=POLICY_SHA256,
        reasoning_role_profile_sha256=ROLE_PROFILE_SHA256,
        reasoning_role_binding_sha256=ROLE_BINDING_SHA256,
        reasoning_control_profile_sha256=CONTROL_SHA256,
        reserved_reasoning_tokens=4_096,
        minimum_prompt_tokens=8_192,
        required_output_tokens=4_096,
        minimum_context_tokens=16_384,
    )


def _component_envelope_profile() -> RoutePredicateProfile:
    return RoutePredicateProfile.build(
        reasoning_policy_sha256=POLICY_SHA256,
        reasoning_role_profile_sha256=ROLE_PROFILE_SHA256,
        reasoning_role_binding_sha256=ROLE_BINDING_SHA256,
        reasoning_control_profile_sha256=CONTROL_SHA256,
        reserved_reasoning_tokens=4_096,
        minimum_prompt_tokens=8_192,
        required_output_tokens=4_096,
        minimum_context_tokens=16_384,
        price_cap_algorithm=(ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2),
    )


def _cache_write_dominance_profile() -> RoutePredicateProfile:
    return RoutePredicateProfile.build(
        reasoning_policy_sha256=POLICY_SHA256,
        reasoning_role_profile_sha256=ROLE_PROFILE_SHA256,
        reasoning_role_binding_sha256=ROLE_BINDING_SHA256,
        reasoning_control_profile_sha256=CONTROL_SHA256,
        reserved_reasoning_tokens=4_096,
        minimum_prompt_tokens=8_192,
        required_output_tokens=4_096,
        minimum_context_tokens=16_384,
        price_cap_algorithm=(
            ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_PROMPT_DOMINATED_CACHE_WRITE_V3
        ),
    )


def _constraint(profile: RoutePredicateProfile | None = None) -> ExactRouteConstraint:
    selected = _profile() if profile is None else profile
    return ExactRouteConstraint.build(
        role=ExactRouteRole.CANDIDATE,
        exact_model_id=MODEL,
        provider_endpoint=ENDPOINT,
        profile=selected,
    )


def _fact_values(
    profile: RoutePredicateProfile,
    constraint: ExactRouteConstraint,
) -> dict[str, Any]:
    pricing = _pricing()
    return {
        "observed_model_id": MODEL,
        "observed_provider_endpoint": ENDPOINT,
        "selected_provider_display_name": "Provider A",
        "provider_display_names": ("Provider A", "Provider B"),
        "provider_identity_inventory_complete": True,
        "operational_status": "0",
        "zdr_eligible": True,
        "emitted_request_parameters": (
            "max_tokens",
            "reasoning",
            "response_format",
            "temperature",
        ),
        "model_supported_parameters": PARAMETERS,
        "endpoint_supported_parameters": PARAMETERS,
        "structured_output_mode": StructuredOutputMode.NATIVE_JSON_SCHEMA,
        "configured_provider_endpoints": (ENDPOINT,),
        "provider_policy_mode": "only",
        "automatic_fallbacks_allowed": False,
        "reasoning_policy_sha256": profile.reasoning_policy_sha256,
        "reasoning_role_profile_sha256": profile.reasoning_role_profile_sha256,
        "reasoning_role_binding_sha256": profile.reasoning_role_binding_sha256,
        "reasoning_control_profile_sha256": profile.reasoning_control_profile_sha256,
        "reasoning_mode": "effort",
        "reasoning_effort": "high",
        "reasoning_max_tokens": None,
        "reasoning_exclude": False,
        "reserved_reasoning_tokens": 4_096,
        "endpoint_supported_reasoning_efforts": HIGH_EFFORTS,
        "model_supported_reasoning_efforts": HIGH_EFFORTS,
        "max_prompt_tokens": 16_384,
        "max_completion_tokens": 16_384,
        "max_completion_tokens_source": "metadata",
        "context_tokens": 32_768,
        "exact_pricing": pricing,
        "configured_provider_max_price": project_provider_price_cap(pricing),
        "frozen_live_equivalent": True,
        "expected_selection_plan_sha256": PLAN_SHA256,
        "registry_selection_plan_sha256": PLAN_SHA256,
        "registry_profile_sha256": profile.profile_sha256,
        "registry_constraint_sha256": constraint.constraint_sha256,
    }


def _facts(
    *,
    profile: RoutePredicateProfile | None = None,
    constraint: ExactRouteConstraint | None = None,
    **updates: Any,
) -> NormalizedRouteFacts:
    selected_profile = _profile() if profile is None else profile
    selected_constraint = _constraint(selected_profile) if constraint is None else constraint
    values = _fact_values(selected_profile, selected_constraint)
    values.update(updates)
    return NormalizedRouteFacts.build(**values)


def _report(
    *,
    facts: NormalizedRouteFacts | None = None,
) -> RoutePredicateReport:
    profile = _profile()
    constraint = _constraint(profile)
    selected_facts = _facts(profile=profile, constraint=constraint) if facts is None else facts
    return evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=selected_facts,
    )


def _result(
    report: RoutePredicateReport,
    predicate: RoutePredicateId,
) -> tuple[RoutePredicateDisposition, RoutePredicateReason]:
    result = next(item for item in report.results if item.predicate_id is predicate)
    return result.disposition, result.reason


@pytest.mark.parametrize(
    "policy_name",
    ("_FAILURE_REASONS_BY_PREDICATE", "_PURPOSE_REQUIRED"),
)
def test_route_predicate_policy_containers_are_immutable(policy_name: str) -> None:
    policy: Any = getattr(route_constraints_module, policy_name)
    key = next(iter(policy))

    with pytest.raises(TypeError):
        policy[key] = policy[key]

    assert route_constraint_callables_are_pristine() is True


def test_route_purpose_policy_alias_replacement_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _report()

    with monkeypatch.context() as context:
        context.setattr(route_constraints_module, "_PURPOSE_REQUIRED", {})
        assert route_constraint_callables_are_pristine() is False
        with pytest.raises(RouteConstraintError, match="callable boundary changed"):
            require_route_predicates(
                report,
                purpose=RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION,
            )

    assert route_constraint_callables_are_pristine() is True


def test_route_pricing_policy_alias_replacement_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as context:
        context.setattr(
            route_constraints_module,
            "_UNENFORCEABLE_VARIABLE_PRICE_FIELDS",
            frozenset(),
        )
        assert route_constraint_callables_are_pristine() is False
        with pytest.raises(RouteConstraintError, match="callable boundary changed"):
            project_provider_price_cap(_pricing())

    assert route_constraint_callables_are_pristine() is True


def test_route_constraint_guard_alias_replacement_revokes_captured_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as context:
        context.setattr(
            route_constraints_module,
            "route_constraint_callables_are_pristine",
            lambda: True,
        )
        assert route_constraint_callables_are_pristine() is False

    assert route_constraint_callables_are_pristine() is True


def test_runtime_transition_rejects_retargeted_registered_consumer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mmaudit.models.route_runtime_evidence as runtime_evidence_module

    called = False

    def retargeted_consumer(*_args: object, **_kwargs: object) -> tuple[None, None]:
        nonlocal called
        called = True
        return None, None

    profile = _profile()
    constraint = _constraint(profile)
    facts = _facts(profile=profile, constraint=constraint)
    report = evaluate_route_predicates(profile=profile, constraint=constraint, facts=facts)
    assert route_constraint_callables_are_pristine() is True

    with monkeypatch.context() as context:
        context.setattr(
            runtime_evidence_module,
            "runtime_predicate_transition_reasons",
            retargeted_consumer,
        )
        assert route_constraint_callables_are_pristine() is False
        with pytest.raises(RouteConstraintError, match="callable boundary changed"):
            route_constraints_module.transition_full_campaign_runtime_predicates(
                report,
                runtime_evidence=object(),
                qualification_policy=object(),
                role=ExactRouteRole.CANDIDATE,
                model=object(),
                discovery_manifest=object(),
                discovery_evidence=object(),
                facts=facts,
            )

    assert called is False
    assert route_constraint_callables_are_pristine() is True


def test_route_purpose_enum_decode_table_mutation_fails_closed() -> None:
    purpose = RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION
    value_map = RouteConstraintPurpose._value2member_map_
    original = value_map[purpose.value]

    value_map[purpose.value] = RouteConstraintPurpose.DISCOVERY_PUBLICATION
    try:
        assert route_constraint_callables_are_pristine() is False
        with pytest.raises(RouteConstraintError, match="callable boundary changed"):
            require_route_predicates(_report(), purpose=purpose)
    finally:
        value_map[purpose.value] = original

    assert RouteConstraintPurpose(purpose.value) is purpose
    assert route_constraint_callables_are_pristine() is True


def test_route_purpose_policy_backing_mutation_fails_closed() -> None:
    report = _report()
    policy: Any = route_constraints_module._PURPOSE_REQUIRED
    referents = tuple(item for item in gc.get_referents(policy) if type(item) is dict)
    assert len(referents) == 1
    backing: dict[object, object] = referents[0]
    purpose = RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION
    original = backing[purpose]

    backing[purpose] = frozenset()
    try:
        assert route_constraint_callables_are_pristine() is False
        with pytest.raises(RouteConstraintError, match="callable boundary changed"):
            require_route_predicates(report, purpose=purpose)
    finally:
        backing[purpose] = original

    assert route_constraint_callables_are_pristine() is True


@pytest.mark.parametrize(
    "helper_name",
    ("_detached", "_predicate_result", "_rebuild_route_facts", "_reasoning_effort_result"),
)
def test_route_predicate_helper_code_mutation_fails_closed(helper_name: str) -> None:
    helper = getattr(route_constraints_module, helper_name)
    original_code = helper.__code__

    def changed(*_args: object, **_kwargs: object) -> None:
        return None

    helper.__code__ = changed.__code__.replace(co_freevars=original_code.co_freevars)
    try:
        assert route_constraint_callables_are_pristine() is False
        with pytest.raises(RouteConstraintError, match="callable boundary changed"):
            evaluate_route_predicates(
                profile=_profile(),
                constraint=_constraint(),
                facts=_facts(),
            )
    finally:
        helper.__code__ = original_code

    assert route_constraint_callables_are_pristine() is True


@pytest.mark.parametrize(
    "helper_name",
    (
        "output_mode_request_parameters",
        "require_exact_openrouter_model_id",
        "resolve_effective_reasoning_effort_inventory",
    ),
)
def test_imported_route_helper_code_mutation_fails_closed(helper_name: str) -> None:
    helper = getattr(route_constraints_module, helper_name)
    original_code = helper.__code__

    def changed(*_args: object, **_kwargs: object) -> None:
        return None

    helper.__code__ = changed.__code__.replace(co_freevars=original_code.co_freevars)
    try:
        assert route_constraint_callables_are_pristine() is False
    finally:
        helper.__code__ = original_code

    assert route_constraint_callables_are_pristine() is True


@pytest.mark.parametrize(
    ("model_type", "validator_name"),
    (
        (RoutePredicateProfile, "profile_is_exact_complete_and_self_hashed"),
        (ExactRouteConstraint, "constraint_is_self_hashed"),
        (NormalizedRouteFacts, "facts_are_canonical_and_self_hashed"),
        (RoutePredicateResult, "reason_matches_predicate_and_disposition"),
        (RoutePredicateReport, "report_is_complete_and_self_hashed"),
    ),
)
def test_route_model_validator_code_mutation_fails_closed(
    model_type: type[object],
    validator_name: str,
) -> None:
    validator: Any = vars(model_type)[validator_name]
    original_code = validator.__code__

    def changed(*_args: object, **_kwargs: object) -> None:
        return None

    validator.__code__ = changed.__code__.replace(co_freevars=original_code.co_freevars)
    try:
        assert route_constraint_callables_are_pristine() is False
    finally:
        validator.__code__ = original_code

    assert route_constraint_callables_are_pristine() is True


def test_unavailable_result_code_mutation_cannot_promote_full_admission() -> None:
    report = _report()
    helper = route_constraints_module._unavailable_result
    original_code = helper.__code__

    def forged(
        predicate: RoutePredicateId,
        _reason: RoutePredicateReason,
    ) -> RoutePredicateResult:
        return RoutePredicateResult(
            predicate_id=predicate,
            disposition=RoutePredicateDisposition.SATISFIED,
            reason=RoutePredicateReason.SATISFIED,
        )

    helper.__code__ = forged.__code__
    try:
        assert route_constraint_callables_are_pristine() is False
        with pytest.raises(RouteConstraintError, match="callable boundary changed"):
            evaluate_route_predicates(
                profile=_profile(),
                constraint=_constraint(),
                facts=_facts(),
            )
        with pytest.raises(RouteConstraintError, match="callable boundary changed"):
            require_route_predicates(
                report,
                purpose=RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION,
            )
    finally:
        helper.__code__ = original_code

    assert route_constraint_callables_are_pristine() is True


def test_profile_constraint_facts_and_report_are_deterministic_and_self_hashed() -> None:
    profile = _profile()
    constraint = _constraint(profile)
    facts = _facts(profile=profile, constraint=constraint)
    report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=facts,
    )

    assert profile == _profile()
    assert constraint == _constraint(profile)
    assert facts == _facts(profile=profile, constraint=constraint)
    assert report == evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=facts,
    )
    assert tuple(item.predicate_id for item in report.results) == ROUTE_PREDICATE_IDS
    assert len(report.results) == len(RoutePredicateId) == 29
    assert all(
        item.disposition is RoutePredicateDisposition.SATISFIED for item in report.results[:-2]
    )
    assert tuple(item.disposition for item in report.results[-2:]) == (
        RoutePredicateDisposition.UNAVAILABLE,
        RoutePredicateDisposition.UNAVAILABLE,
    )


def test_default_route_artifact_bytes_remain_pinned_without_runtime_evidence() -> None:
    profile = _profile()
    constraint = _constraint(profile)
    facts = _facts(profile=profile, constraint=constraint)
    report = evaluate_route_predicates(profile=profile, constraint=constraint, facts=facts)

    expected = (
        (
            profile,
            2_092,
            "3a10acd74a520acaeb034e76219cced83ed67414b3f2aa03570ec7deeb469b13",
        ),
        (
            constraint,
            282,
            "778e27473f955952c763f757d0450daaf52f7053303d4169f3b9242e5e6f5bf2",
        ),
        (
            facts,
            2_483,
            "98ee35edeb8d2df320ba8518d18e8d39f257ae387c7e3815d510156f0eeac04c",
        ),
        (
            report,
            3_079,
            "5b8a7bbcd24c8ce0e23f698c8e6c2428b8df6e85c88b11f2b8caf52b9e92a5c0",
        ),
    )
    for artifact, expected_bytes, expected_sha256 in expected:
        raw = artifact.model_dump_json().encode("utf-8")
        assert len(raw) == expected_bytes
        assert hashlib.sha256(raw).hexdigest() == expected_sha256


@pytest.mark.parametrize(
    ("mode", "reasoning_emitted", "expected"),
    (
        (
            StructuredOutputMode.NATIVE_JSON_SCHEMA,
            True,
            ("max_tokens", "reasoning", "response_format", "temperature"),
        ),
        (
            StructuredOutputMode.JSON_OBJECT,
            False,
            ("max_tokens", "response_format", "temperature"),
        ),
        (
            StructuredOutputMode.VALIDATED_TEXT_JSON,
            False,
            ("max_tokens", "temperature"),
        ),
    ),
)
def test_emitted_request_parameter_projection_is_finite_and_shared(
    mode: StructuredOutputMode,
    reasoning_emitted: bool,
    expected: tuple[str, ...],
) -> None:
    assert (
        project_route_emitted_request_parameters(
            structured_output_mode=mode,
            reasoning_emitted=reasoning_emitted,
        )
        == expected
    )


@pytest.mark.parametrize(
    ("factory", "hash_field", "changed_field", "changed_value"),
    (
        (_profile, "profile_sha256", "minimum_prompt_tokens", 8_191),
        (
            lambda: _constraint(_profile()),
            "constraint_sha256",
            "provider_endpoint",
            OTHER_ENDPOINT,
        ),
        (
            lambda: _facts(profile=_profile(), constraint=_constraint(_profile())),
            "facts_sha256",
            "operational_status",
            "active",
        ),
        (_report, "report_sha256", "facts_sha256", OTHER_SHA256),
    ),
)
def test_self_hashed_artifacts_reject_tampering(
    factory: Any,
    hash_field: str,
    changed_field: str,
    changed_value: Any,
) -> None:
    artifact = factory()
    payload = artifact.model_dump(mode="python")
    original_hash = payload[hash_field]
    payload[changed_field] = changed_value
    assert payload[hash_field] == original_hash

    with pytest.raises(ValidationError, match=hash_field):
        type(artifact).model_validate(payload)


def test_profile_and_report_reject_missing_predicate_inventory() -> None:
    profile_payload = _profile().model_dump(mode="python")
    profile_payload["predicate_ids"] = profile_payload["predicate_ids"][:-1]
    with pytest.raises(ValidationError, match=r"predicate_ids|predicate profile inventory"):
        RoutePredicateProfile.model_validate(profile_payload)

    report_payload = _report().model_dump(mode="python")
    report_payload["results"] = report_payload["results"][:-1]
    with pytest.raises(ValidationError, match=r"results|report inventory"):
        RoutePredicateReport.model_validate(report_payload)


def test_constraint_has_no_final_plan_hash_back_edge() -> None:
    constraint = _constraint()

    assert "selection_plan_sha256" not in type(constraint).model_fields
    assert constraint.model_dump(mode="json") == {
        "schema_version": "1.0",
        "role": "candidate",
        "exact_model_id": MODEL,
        "provider_endpoint": ENDPOINT,
        "profile_sha256": constraint.profile_sha256,
        "constraint_sha256": constraint.constraint_sha256,
    }


def test_route_facts_advance_once_through_registry_and_live_custody() -> None:
    profile = _profile()
    constraint = _constraint(profile)
    discovery = _facts(
        profile=profile,
        constraint=constraint,
        registry_selection_plan_sha256=None,
        registry_profile_sha256=None,
        registry_constraint_sha256=None,
        frozen_live_equivalent=None,
    )
    registry = bind_registry_route_facts(
        discovery,
        registry_selection_plan_sha256=PLAN_SHA256,
        profile=profile,
        constraint=constraint,
    )
    registry_report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=registry,
    )
    assert discovery.registry_selection_plan_sha256 is None
    assert registry.registry_selection_plan_sha256 == PLAN_SHA256
    assert (
        require_route_predicates(
            registry_report,
            purpose=RouteConstraintPurpose.REGISTRY_PUBLICATION,
        )
        == registry_report
    )

    live = bind_live_route_facts(registry, frozen_live_equivalent=True)
    runtime = bind_runtime_route_facts(
        live,
        required_output_tokens=profile.required_output_tokens,
    )
    live_report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=runtime,
    )
    assert registry.frozen_live_equivalent is None
    assert live.frozen_live_equivalent is True
    assert runtime.runtime_required_output_tokens == profile.required_output_tokens
    assert (
        require_route_predicates(
            live_report,
            purpose=RouteConstraintPurpose.NONCREDITING_SMOKE_ADMISSION,
        )
        == live_report
    )

    with pytest.raises(RouteConstraintError, match="already carry registry"):
        bind_registry_route_facts(
            registry,
            registry_selection_plan_sha256=PLAN_SHA256,
            profile=profile,
            constraint=constraint,
        )
    with pytest.raises(RouteConstraintError, match="already carry a live"):
        bind_live_route_facts(live, frozen_live_equivalent=True)
    with pytest.raises(RouteConstraintError, match="already carry a runtime"):
        bind_runtime_route_facts(
            runtime,
            required_output_tokens=profile.required_output_tokens,
        )


def test_live_route_facts_require_registry_custody_and_preserve_mismatch() -> None:
    profile = _profile()
    constraint = _constraint(profile)
    discovery = _facts(
        profile=profile,
        constraint=constraint,
        registry_selection_plan_sha256=None,
        registry_profile_sha256=None,
        registry_constraint_sha256=None,
        frozen_live_equivalent=None,
    )
    with pytest.raises(RouteConstraintError, match="complete registry custody"):
        bind_live_route_facts(discovery, frozen_live_equivalent=True)
    with pytest.raises(RouteConstraintError, match="complete registry custody"):
        bind_runtime_route_facts(
            discovery,
            required_output_tokens=profile.required_output_tokens,
        )

    registry = bind_registry_route_facts(
        discovery,
        registry_selection_plan_sha256=PLAN_SHA256,
        profile=profile,
        constraint=constraint,
    )
    live = bind_live_route_facts(registry, frozen_live_equivalent=False)
    report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=live,
    )
    assert _result(report, RoutePredicateId.FROZEN_LIVE_EQUIVALENCE) == (
        RoutePredicateDisposition.REJECTED,
        RoutePredicateReason.LIVE_EQUIVALENCE_MISMATCH,
    )
    with pytest.raises(RoutePredicateRequirementError):
        require_route_predicates(
            report,
            purpose=RouteConstraintPurpose.NONCREDITING_SMOKE_ADMISSION,
        )


@pytest.mark.parametrize("delta", (-256, 256))
def test_runtime_output_envelope_must_equal_the_profile(delta: int) -> None:
    profile = _profile()
    constraint = _constraint(profile)
    facts = bind_runtime_route_facts(
        _facts(profile=profile, constraint=constraint),
        required_output_tokens=profile.required_output_tokens + delta,
    )
    report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=facts,
    )

    assert _result(report, RoutePredicateId.OUTPUT_CAPACITY_ENVELOPE) == (
        RoutePredicateDisposition.REJECTED,
        RoutePredicateReason.RUNTIME_OUTPUT_TOKENS_MISMATCH,
    )
    with pytest.raises(RoutePredicateRequirementError) as captured:
        require_route_predicates(
            report,
            purpose=RouteConstraintPurpose.NONCREDITING_SMOKE_ADMISSION,
        )
    assert any(
        item.predicate_id is RoutePredicateId.OUTPUT_CAPACITY_ENVELOPE
        and item.reason is RoutePredicateReason.RUNTIME_OUTPUT_TOKENS_MISMATCH
        for item in captured.value.failures
    )


def test_exact_configured_slug_identity_is_accepted_without_a_raw_tag() -> None:
    profile = _profile()
    slug = "provider/slug-v1"
    constraint = ExactRouteConstraint.build(
        role=ExactRouteRole.CANDIDATE,
        exact_model_id=MODEL,
        provider_endpoint=slug,
        profile=profile,
    )
    facts = _facts(
        profile=profile,
        constraint=constraint,
        observed_provider_endpoint=slug,
        configured_provider_endpoints=(slug,),
    )
    report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=facts,
    )

    assert _result(report, RoutePredicateId.EXACT_PROVIDER_ENDPOINT) == (
        RoutePredicateDisposition.SATISFIED,
        RoutePredicateReason.SATISFIED,
    )
    assert _result(report, RoutePredicateId.SINGLETON_EXACT_ROUTE) == (
        RoutePredicateDisposition.SATISFIED,
        RoutePredicateReason.SATISFIED,
    )


@pytest.mark.parametrize(
    ("case", "predicate", "reason"),
    (
        (
            "model",
            RoutePredicateId.EXACT_MODEL_IDENTITY,
            RoutePredicateReason.MODEL_IDENTITY_MISMATCH,
        ),
        (
            "endpoint",
            RoutePredicateId.EXACT_PROVIDER_ENDPOINT,
            RoutePredicateReason.PROVIDER_ENDPOINT_MISMATCH,
        ),
        (
            "display_incomplete",
            RoutePredicateId.PROVIDER_DISPLAY_NAME_INJECTIVITY,
            RoutePredicateReason.DISPLAY_INVENTORY_INCOMPLETE,
        ),
        (
            "display_ambiguous",
            RoutePredicateId.PROVIDER_DISPLAY_NAME_INJECTIVITY,
            RoutePredicateReason.DISPLAY_NAME_NOT_INJECTIVE,
        ),
        (
            "operational",
            RoutePredicateId.OPERATIONAL_STATUS,
            RoutePredicateReason.OPERATIONAL_STATUS_NOT_ACCEPTED,
        ),
        (
            "zdr",
            RoutePredicateId.ZDR_ELIGIBILITY,
            RoutePredicateReason.ZDR_NOT_ELIGIBLE,
        ),
        (
            "max_tokens",
            RoutePredicateId.EMITS_MAX_TOKENS,
            RoutePredicateReason.MAX_TOKENS_NOT_EMITTED,
        ),
        (
            "temperature",
            RoutePredicateId.EMITS_TEMPERATURE,
            RoutePredicateReason.TEMPERATURE_NOT_EMITTED,
        ),
        (
            "response_format",
            RoutePredicateId.EMITS_RESPONSE_FORMAT,
            RoutePredicateReason.RESPONSE_FORMAT_NOT_EMITTED,
        ),
        (
            "reasoning_parameter",
            RoutePredicateId.EMITS_REASONING,
            RoutePredicateReason.REASONING_NOT_EMITTED,
        ),
        (
            "model_marker",
            RoutePredicateId.MODEL_STRUCTURED_OUTPUT_MARKER,
            RoutePredicateReason.MODEL_NATIVE_MARKER_MISSING,
        ),
        (
            "endpoint_marker",
            RoutePredicateId.ENDPOINT_STRUCTURED_OUTPUT_MARKER,
            RoutePredicateReason.ENDPOINT_NATIVE_MARKER_MISSING,
        ),
        (
            "output_mode",
            RoutePredicateId.NATIVE_STRUCTURED_OUTPUT_MODE,
            RoutePredicateReason.NATIVE_OUTPUT_MODE_MISSING,
        ),
        (
            "singleton",
            RoutePredicateId.SINGLETON_EXACT_ROUTE,
            RoutePredicateReason.ROUTE_NOT_SINGLETON,
        ),
        (
            "fallback",
            RoutePredicateId.AUTOMATIC_FALLBACK_DISABLED,
            RoutePredicateReason.AUTOMATIC_FALLBACK_ENABLED,
        ),
        (
            "policy_hash",
            RoutePredicateId.REASONING_POLICY_BINDING,
            RoutePredicateReason.REASONING_POLICY_HASH_MISMATCH,
        ),
        (
            "control_hash",
            RoutePredicateId.REASONING_CONTROL_BINDING,
            RoutePredicateReason.REASONING_CONTROL_HASH_MISMATCH,
        ),
        (
            "control_values",
            RoutePredicateId.REASONING_CONTROL_VALUES,
            RoutePredicateReason.REASONING_CONTROL_MISMATCH,
        ),
        (
            "effort",
            RoutePredicateId.REASONING_EFFORT_SUPPORT,
            RoutePredicateReason.REASONING_EFFORT_UNSUPPORTED,
        ),
        (
            "prompt_capacity",
            RoutePredicateId.PROMPT_CAPACITY_ENVELOPE,
            RoutePredicateReason.PROMPT_CAPACITY_INSUFFICIENT,
        ),
        (
            "output_capacity",
            RoutePredicateId.OUTPUT_CAPACITY_ENVELOPE,
            RoutePredicateReason.OUTPUT_CAPACITY_INSUFFICIENT,
        ),
        (
            "context_capacity",
            RoutePredicateId.CONTEXT_CAPACITY_ENVELOPE,
            RoutePredicateReason.CONTEXT_CAPACITY_INSUFFICIENT,
        ),
        (
            "completion_source",
            RoutePredicateId.METADATA_COMPLETION_CAPACITY,
            RoutePredicateReason.COMPLETION_CAPACITY_NOT_METADATA,
        ),
        (
            "price_expression",
            RoutePredicateId.PRICE_CAP_EXPRESSIBILITY,
            RoutePredicateReason.PRICE_CAP_NOT_EXPRESSIBLE,
        ),
        (
            "price_missing",
            RoutePredicateId.PRICE_CAP_NO_WEAKER,
            RoutePredicateReason.PRICE_CAP_MISSING,
        ),
        (
            "price_weaker",
            RoutePredicateId.PRICE_CAP_NO_WEAKER,
            RoutePredicateReason.PRICE_CAP_WEAKER_THAN_ROUTE,
        ),
        (
            "live",
            RoutePredicateId.FROZEN_LIVE_EQUIVALENCE,
            RoutePredicateReason.LIVE_EQUIVALENCE_MISMATCH,
        ),
        (
            "registry_selection",
            RoutePredicateId.REGISTRY_SELECTION_HASH_CUSTODY,
            RoutePredicateReason.REGISTRY_SELECTION_CUSTODY_MISMATCH,
        ),
        (
            "registry_constraint",
            RoutePredicateId.REGISTRY_CONSTRAINT_HASH_CUSTODY,
            RoutePredicateReason.REGISTRY_CONSTRAINT_CUSTODY_MISMATCH,
        ),
    ),
)
def test_route_reason_sweep_is_closed_and_value_free(
    case: str,
    predicate: RoutePredicateId,
    reason: RoutePredicateReason,
) -> None:
    profile = _profile()
    constraint = _constraint(profile)
    updates = _failure_update(case, profile)
    facts = _facts(profile=profile, constraint=constraint, **updates)
    report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=facts,
    )

    assert _result(report, predicate) == (RoutePredicateDisposition.REJECTED, reason)
    assert MODEL not in reason.value
    assert ENDPOINT not in reason.value


def _failure_update(case: str, profile: RoutePredicateProfile) -> dict[str, Any]:
    emitted = ("max_tokens", "reasoning", "response_format", "temperature")
    by_case: dict[str, dict[str, Any]] = {
        "model": {"observed_model_id": OTHER_MODEL},
        "endpoint": {"observed_provider_endpoint": OTHER_ENDPOINT},
        "display_incomplete": {"provider_identity_inventory_complete": False},
        "display_ambiguous": {"provider_display_names": ("Provider A", "provider a")},
        "operational": {"operational_status": "active"},
        "zdr": {"zdr_eligible": False},
        "max_tokens": {
            "emitted_request_parameters": tuple(item for item in emitted if item != "max_tokens")
        },
        "temperature": {
            "emitted_request_parameters": tuple(item for item in emitted if item != "temperature")
        },
        "response_format": {
            "emitted_request_parameters": tuple(
                item for item in emitted if item != "response_format"
            )
        },
        "reasoning_parameter": {
            "emitted_request_parameters": tuple(item for item in emitted if item != "reasoning")
        },
        "model_marker": {
            "model_supported_parameters": tuple(
                item for item in PARAMETERS if item != "structured_outputs"
            )
        },
        "endpoint_marker": {
            "endpoint_supported_parameters": tuple(
                item for item in PARAMETERS if item != "structured_outputs"
            )
        },
        "output_mode": {"structured_output_mode": StructuredOutputMode.JSON_OBJECT},
        "singleton": {"configured_provider_endpoints": (ENDPOINT, OTHER_ENDPOINT)},
        "fallback": {"automatic_fallbacks_allowed": True},
        "policy_hash": {"reasoning_policy_sha256": OTHER_SHA256},
        "control_hash": {"reasoning_control_profile_sha256": OTHER_SHA256},
        "control_values": {"reserved_reasoning_tokens": 2_048},
        "effort": {
            "endpoint_supported_reasoning_efforts": ("medium",),
            "model_supported_reasoning_efforts": ("medium",),
        },
        "prompt_capacity": {"max_prompt_tokens": 8_191},
        "output_capacity": {"max_completion_tokens": 4_095},
        "context_capacity": {
            "max_prompt_tokens": 8_192,
            "max_completion_tokens": 8_192,
            "context_tokens": 8_192,
        },
        "completion_source": {"max_completion_tokens_source": "context_limit"},
        "price_expression": {
            "exact_pricing": (
                *_pricing()[:2],
                ExactRoutePrice(
                    component=RoutePriceComponent.INTERNAL_REASONING,
                    unit_price="0",
                ),
                *_pricing()[2:],
            )
        },
        "price_missing": {"configured_provider_max_price": None},
        "price_weaker": {"configured_provider_max_price": _weaker_prompt_cap()},
        "live": {"frozen_live_equivalent": False},
        "registry_selection": {"registry_selection_plan_sha256": OTHER_SHA256},
        "registry_constraint": {"registry_constraint_sha256": OTHER_SHA256},
    }
    assert profile.price_cap_algorithm is (
        ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1
    )
    return by_case[case]


def _weaker_prompt_cap() -> tuple[ProviderPriceCap, ...]:
    caps = list(project_provider_price_cap(_pricing()))
    return tuple(
        ProviderPriceCap(component=item.component, value=1.0)
        if item.component is ProviderMaxPriceComponent.PROMPT
        else item
        for item in caps
    )


def test_reasoning_effort_is_endpoint_first_with_only_absence_fallback() -> None:
    profile = _profile()
    constraint = _constraint(profile)

    fallback = _facts(
        profile=profile,
        constraint=constraint,
        endpoint_supported_reasoning_efforts=None,
        model_supported_reasoning_efforts=HIGH_EFFORTS,
    )
    explicit_empty = _facts(
        profile=profile,
        constraint=constraint,
        endpoint_supported_reasoning_efforts=(),
        model_supported_reasoning_efforts=HIGH_EFFORTS,
    )
    contradictory = _facts(
        profile=profile,
        constraint=constraint,
        endpoint_supported_reasoning_efforts=HIGH_EFFORTS,
        model_supported_reasoning_efforts=("medium",),
    )
    unavailable = _facts(
        profile=profile,
        constraint=constraint,
        endpoint_supported_reasoning_efforts=None,
        model_supported_reasoning_efforts=None,
    )

    reports = tuple(
        evaluate_route_predicates(profile=profile, constraint=constraint, facts=item)
        for item in (fallback, explicit_empty, contradictory, unavailable)
    )
    assert tuple(
        _result(report, RoutePredicateId.REASONING_EFFORT_SUPPORT) for report in reports
    ) == (
        (RoutePredicateDisposition.SATISFIED, RoutePredicateReason.SATISFIED),
        (
            RoutePredicateDisposition.REJECTED,
            RoutePredicateReason.REASONING_EFFORT_INVENTORY_EMPTY,
        ),
        (
            RoutePredicateDisposition.REJECTED,
            RoutePredicateReason.REASONING_EFFORT_INVENTORY_CONTRADICTORY,
        ),
        (
            RoutePredicateDisposition.UNAVAILABLE,
            RoutePredicateReason.REASONING_EFFORT_INVENTORY_UNAVAILABLE,
        ),
    )


def test_route_constraint_purpose_inventory_is_exact() -> None:
    assert tuple(RouteConstraintPurpose) == EXACT_ROUTE_CONSTRAINT_PURPOSES


@pytest.mark.parametrize("purpose", EXACT_ROUTE_CONSTRAINT_PURPOSES)
def test_candidate_reasoning_effort_inventory_is_required_for_every_purpose(
    purpose: RouteConstraintPurpose,
) -> None:
    profile = _profile()
    constraint = _constraint(profile)
    assert constraint.role is ExactRouteRole.CANDIDATE
    report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=_facts(
            profile=profile,
            constraint=constraint,
            endpoint_supported_reasoning_efforts=None,
            model_supported_reasoning_efforts=None,
        ),
    )

    with pytest.raises(RoutePredicateRequirementError) as error:
        require_route_predicates(report, purpose=purpose)

    reasoning_failures = tuple(
        failure
        for failure in error.value.failures
        if failure.predicate_id is RoutePredicateId.REASONING_EFFORT_SUPPORT
    )
    assert len(reasoning_failures) == 1
    assert reasoning_failures[0].disposition is RoutePredicateDisposition.UNAVAILABLE
    assert (
        reasoning_failures[0].reason is RoutePredicateReason.REASONING_EFFORT_INVENTORY_UNAVAILABLE
    )


def test_emitted_parameter_inventory_rejects_unrepresented_runtime_field() -> None:
    profile = _profile()
    constraint = _constraint(profile)
    report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=_facts(
            profile=profile,
            constraint=constraint,
            emitted_request_parameters=(
                "max_tokens",
                "reasoning",
                "response_format",
                "temperature",
                "unrepresented_runtime_field",
            ),
        ),
    )

    for predicate in (
        RoutePredicateId.EMITS_MAX_TOKENS,
        RoutePredicateId.EMITS_TEMPERATURE,
        RoutePredicateId.EMITS_RESPONSE_FORMAT,
        RoutePredicateId.EMITS_REASONING,
    ):
        assert _result(report, predicate) == (
            RoutePredicateDisposition.REJECTED,
            RoutePredicateReason.EMITTED_PARAMETER_INVENTORY_MISMATCH,
        )


@pytest.mark.parametrize(
    "support_field",
    ("model_supported_parameters", "endpoint_supported_parameters"),
)
def test_emitted_parameter_inventory_requires_model_and_endpoint_support(
    support_field: str,
) -> None:
    profile = _profile()
    constraint = _constraint(profile)
    report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=_facts(
            profile=profile,
            constraint=constraint,
            **{
                support_field: tuple(
                    parameter for parameter in PARAMETERS if parameter != "reasoning"
                )
            },
        ),
    )

    assert _result(report, RoutePredicateId.EMITS_REASONING) == (
        RoutePredicateDisposition.REJECTED,
        RoutePredicateReason.EMITTED_PARAMETER_SUPPORT_MISMATCH,
    )


def test_provider_display_injectivity_requires_only_the_selected_name_to_be_unique() -> None:
    profile = _profile()
    constraint = _constraint(profile)
    report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=_facts(
            profile=profile,
            constraint=constraint,
            provider_display_names=(
                "Provider A",
                "Repeated Other Provider",
                "repeated other provider",
            ),
        ),
    )

    assert _result(report, RoutePredicateId.PROVIDER_DISPLAY_NAME_INJECTIVITY) == (
        RoutePredicateDisposition.SATISFIED,
        RoutePredicateReason.SATISFIED,
    )


def test_price_projection_rounds_up_and_proof_rejects_weaker_cap() -> None:
    pricing = (
        ExactRoutePrice(
            component=RoutePriceComponent.COMPLETION,
            unit_price="0.000000100000000000000000000000000001",
        ),
        ExactRoutePrice(
            component=RoutePriceComponent.PROMPT,
            unit_price="0.000000200000000000000000000000000001",
        ),
    )
    projected = project_provider_price_cap(pricing)
    by_component = {item.component: item.value for item in projected}

    assert Decimal(str(by_component[ProviderMaxPriceComponent.COMPLETION])) >= (
        Decimal(pricing[0].unit_price) * Decimal(1_000_000)
    )
    assert Decimal(str(by_component[ProviderMaxPriceComponent.PROMPT])) >= (
        Decimal(pricing[1].unit_price) * Decimal(1_000_000)
    )
    proof = prove_provider_price_cap(
        pricing=pricing,
        configured_cap=projected,
        algorithm=ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1,
    )
    assert proof.expressible is True
    assert proof.no_weaker is True

    weaker = tuple(
        ProviderPriceCap(
            component=item.component,
            value=(
                math.nextafter(item.value, 0)
                if item.component is ProviderMaxPriceComponent.PROMPT
                else item.value
            ),
        )
        for item in projected
    )
    with pytest.raises(RouteConstraintError, match="weaker"):
        prove_provider_price_cap(
            pricing=pricing,
            configured_cap=weaker,
            algorithm=ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1,
        )

    looser = tuple(
        ProviderPriceCap(
            component=item.component,
            value=(
                math.nextafter(item.value, math.inf)
                if item.component is ProviderMaxPriceComponent.PROMPT
                else item.value
            ),
        )
        for item in projected
    )
    with pytest.raises(RouteConstraintError, match="weaker"):
        prove_provider_price_cap(
            pricing=pricing,
            configured_cap=looser,
            algorithm=ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1,
        )


def test_zero_unit_component_proof_accepts_web_search_without_emitting_router_cap() -> None:
    profile = _component_envelope_profile()
    envelopes = profile.price_component_unit_envelopes
    assert profile.schema_version == "1.1"
    assert envelopes is not None
    assert type(envelopes[0]) is RoutePriceComponentUnitEnvelope
    pricing = normalize_exact_route_pricing(
        {
            "completion": "0.0000066",
            "prompt": "0.0000022",
            "request": "0",
            "web_search": "0.01",
        }
    )

    with pytest.raises(RouteConstraintError, match="provider cap") as exc_info:
        project_provider_price_cap(pricing)
    assert str(exc_info.value).endswith("exact zero-unit envelope: web_search")

    cap = project_provider_price_cap(
        pricing,
        algorithm=profile.price_cap_algorithm,
        price_component_unit_envelopes=envelopes,
    )
    assert {item.component for item in cap} == {
        ProviderMaxPriceComponent.COMPLETION,
        ProviderMaxPriceComponent.PROMPT,
        ProviderMaxPriceComponent.REQUEST,
    }
    assert all(item.component.value != "web_search" for item in cap)
    proof = prove_provider_price_cap(
        pricing=pricing,
        configured_cap=cap,
        algorithm=profile.price_cap_algorithm,
        price_component_unit_envelopes=envelopes,
    )
    assert proof.schema_version == "1.1"
    assert proof.price_component_unit_envelopes == envelopes
    assert envelopes[0].maximum_units == 0
    assert envelopes[0].maximum_cost_usd_exact == "0"


def test_cache_write_dominance_v3_retains_exact_v2_web_search_envelope_and_bytes() -> None:
    v2_profile = _component_envelope_profile()
    v3_profile = _cache_write_dominance_profile()

    assert v2_profile.schema_version == "1.1"
    assert v3_profile.schema_version == "1.2"
    assert v3_profile.price_component_unit_envelopes == (v2_profile.price_component_unit_envelopes)
    assert v2_profile.profile_sha256 == (
        "558deab9e5abd748918e6e4ff5cfd865b02c8ef6889ce3058fd49b86716e7a4d"
    )
    assert len(v2_profile.model_dump_json().encode("utf-8")) == 2_561
    assert hashlib.sha256(v2_profile.model_dump_json().encode("utf-8")).hexdigest() == (
        "369e5a488377605490c26be067312bc23286310ad9eb5b42e6ad32f07fa2723b"
    )

    pricing = normalize_exact_route_pricing(
        {
            "completion": "0.0000066",
            "prompt": "0.0000022",
            "request": "0",
            "web_search": "0.01",
        }
    )
    v2_envelopes = v2_profile.price_component_unit_envelopes or ()
    v2_cap = project_provider_price_cap(
        pricing,
        algorithm=v2_profile.price_cap_algorithm,
        price_component_unit_envelopes=v2_envelopes,
    )
    v2_proof = prove_provider_price_cap(
        pricing=pricing,
        configured_cap=v2_cap,
        algorithm=v2_profile.price_cap_algorithm,
        price_component_unit_envelopes=v2_envelopes,
    )

    assert v2_proof.schema_version == "1.1"
    assert v2_proof.proof_sha256 == (
        "fefb6efddcbef3bace699e11309000e576fd91eea62c316101e21020b71a91c8"
    )
    assert len(v2_proof.model_dump_json().encode("utf-8")) == 1_128
    assert hashlib.sha256(v2_proof.model_dump_json().encode("utf-8")).hexdigest() == (
        "ae4d7f6d8d100f8fe0f9c67e7e7c862cba5dd2228738b8a227b24afa3cd93eef"
    )


@pytest.mark.parametrize("cache_write_price", ("0", "0.05", "0.1"))
def test_cache_write_snapshot_dominance_never_substitutes_for_provider_cap(
    cache_write_price: str,
) -> None:
    pricing = normalize_exact_route_pricing(
        {
            "completion": "0.2",
            "input_cache_write": cache_write_price,
            "prompt": "0.1",
            "web_search": "0.01",
        }
    )
    v2_profile = _component_envelope_profile()
    for algorithm, envelopes in (
        (ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1, ()),
        (
            v2_profile.price_cap_algorithm,
            v2_profile.price_component_unit_envelopes or (),
        ),
    ):
        with pytest.raises(RouteConstraintError, match="variable price") as exc_info:
            project_provider_price_cap(
                pricing,
                algorithm=algorithm,
                price_component_unit_envelopes=envelopes,
            )
        assert str(exc_info.value).endswith("without a provider cap: input_cache_write")

    v3_profile = _cache_write_dominance_profile()
    v3_envelopes = v3_profile.price_component_unit_envelopes or ()
    with pytest.raises(RouteConstraintError, match="cannot be bound by the provider max_price"):
        project_provider_price_cap(
            pricing,
            algorithm=v3_profile.price_cap_algorithm,
            price_component_unit_envelopes=v3_envelopes,
        )


def test_cache_write_dominance_v3_rejects_flat_and_inherited_tier_assumptions() -> None:
    profile = _cache_write_dominance_profile()
    envelopes = profile.price_component_unit_envelopes or ()
    excessive_flat = normalize_exact_route_pricing(
        {
            "completion": "0.2",
            "input_cache_write": "0.100000000000000000000000000000000001",
            "prompt": "0.1",
        }
    )
    with pytest.raises(RouteConstraintError, match="cannot be bound by the provider max_price"):
        project_provider_price_cap(
            excessive_flat,
            algorithm=profile.price_cap_algorithm,
            price_component_unit_envelopes=envelopes,
        )

    base = normalize_exact_route_pricing(
        {
            "completion": "0.2",
            "input_cache_write": "0.09",
            "prompt": "0.1",
        }
    )
    schedule = ExactRoutePricingSchedule.build(
        base_pricing=base,
        tiers=(
            ExactRoutePriceTier.build(
                min_prompt_tokens=100,
                pricing={"prompt": "0.05"},
            ),
            ExactRoutePriceTier.build(
                min_prompt_tokens=200,
                pricing={"prompt": "0.2"},
            ),
        ),
    )
    maximum = {item.component: item.unit_price for item in schedule.maximum_pricing}
    assert Decimal(maximum[RoutePriceComponent.INPUT_CACHE_WRITE]) <= Decimal(
        maximum[RoutePriceComponent.PROMPT]
    )
    with pytest.raises(RouteConstraintError, match="cannot be bound by the provider max_price"):
        project_provider_price_cap(
            base,
            schedule=schedule,
            algorithm=profile.price_cap_algorithm,
            price_component_unit_envelopes=envelopes,
        )


@pytest.mark.parametrize("reasoning_price", ("0", "0.01"))
def test_cache_write_dominance_v3_is_unconditionally_non_admissible(
    reasoning_price: str,
) -> None:
    profile = _cache_write_dominance_profile()
    pricing = normalize_exact_route_pricing(
        {
            "completion": "0.2",
            "internal_reasoning": reasoning_price,
            "prompt": "0.1",
        }
    )

    with pytest.raises(RouteConstraintError, match="cannot be bound by the provider max_price"):
        project_provider_price_cap(
            pricing,
            algorithm=profile.price_cap_algorithm,
            price_component_unit_envelopes=(profile.price_component_unit_envelopes or ()),
        )


def test_cache_write_dominance_v3_profile_schema_and_projection_fail_closed() -> None:
    profile = _cache_write_dominance_profile()
    profile_payload = profile.model_dump(mode="python")
    profile_payload["schema_version"] = "1.1"
    with pytest.raises(ValidationError, match="schema differs"):
        RoutePredicateProfile.model_validate(profile_payload)

    pricing = normalize_exact_route_pricing(
        {"completion": "0.2", "input_cache_write": "0.05", "prompt": "0.1"}
    )
    envelopes = profile.price_component_unit_envelopes or ()
    with pytest.raises(RouteConstraintError, match="cannot be bound by the provider max_price"):
        project_provider_price_cap(
            pricing,
            algorithm=profile.price_cap_algorithm,
            price_component_unit_envelopes=envelopes,
        )


@pytest.mark.parametrize(
    "component",
    (RoutePriceComponent.INPUT_CACHE_WRITE, RoutePriceComponent.INTERNAL_REASONING),
)
@pytest.mark.parametrize("price", ("0", "0.01"))
def test_zero_unit_component_policy_never_exempts_variable_prices(
    component: RoutePriceComponent,
    price: str,
) -> None:
    profile = _component_envelope_profile()
    pricing = normalize_exact_route_pricing(
        {
            "completion": "0.2",
            component.value: price,
            "prompt": "0.1",
        }
    )

    with pytest.raises(RouteConstraintError, match="variable price"):
        project_provider_price_cap(
            pricing,
            algorithm=profile.price_cap_algorithm,
            price_component_unit_envelopes=(profile.price_component_unit_envelopes or ()),
        )


def test_component_unit_envelope_inventory_rejects_missing_duplicate_and_tamper() -> None:
    profile = _component_envelope_profile()
    envelope = (profile.price_component_unit_envelopes or ())[0]
    pricing = normalize_exact_route_pricing(
        {"completion": "0.2", "prompt": "0.1", "web_search": "0.01"}
    )

    invalid_inventories = (
        (),
        (envelope, envelope),
        (envelope.model_copy(update={"maximum_units": 1}),),
        (envelope.model_copy(update={"component": RoutePriceComponent.PROMPT}),),
        (
            envelope.model_copy(
                update={
                    "prohibited_request_fields": tuple(reversed(envelope.prohibited_request_fields))
                }
            ),
        ),
    )
    for inventory in invalid_inventories:
        with pytest.raises(RouteConstraintError, match="unit-envelope inventory"):
            project_provider_price_cap(
                pricing,
                algorithm=profile.price_cap_algorithm,
                price_component_unit_envelopes=inventory,
            )

    with pytest.raises(RouteConstraintError, match="legacy"):
        project_provider_price_cap(
            pricing,
            price_component_unit_envelopes=(envelope,),
        )


def test_zero_unit_component_proof_applies_to_every_tier_effective_vector() -> None:
    profile = _component_envelope_profile()
    envelopes = profile.price_component_unit_envelopes or ()
    base = normalize_exact_route_pricing(
        {"completion": "0.2", "prompt": "0.1", "web_search": "0.01"}
    )
    schedule = ExactRoutePricingSchedule.build(
        base_pricing=base,
        tiers=(
            ExactRoutePriceTier.build(
                min_prompt_tokens=100,
                pricing={"prompt": "0.2", "web_search": "0.02"},
            ),
        ),
    )

    cap = project_provider_price_cap(
        base,
        schedule=schedule,
        algorithm=profile.price_cap_algorithm,
        price_component_unit_envelopes=envelopes,
    )
    assert {item.component: item.value for item in cap} == {
        ProviderMaxPriceComponent.COMPLETION: 200000.0,
        ProviderMaxPriceComponent.PROMPT: 200000.0,
    }
    proof = prove_provider_price_cap(
        pricing=base,
        schedule=schedule,
        configured_cap=cap,
        algorithm=profile.price_cap_algorithm,
        price_component_unit_envelopes=envelopes,
    )
    assert proof.pricing_schedule == schedule


def test_tiered_price_schedule_derives_exact_inherited_maximum_and_binds_proof() -> None:
    base = normalize_exact_route_pricing(
        {
            "completion": "0.0000066",
            "input_cache_read": "0.00000055",
            "prompt": "0.0000022",
            "request": "0",
            "web_search": "0",
        }
    )
    schedule = ExactRoutePricingSchedule.build(
        base_pricing=base,
        tiers=(
            ExactRoutePriceTier.build(
                min_prompt_tokens=100_000,
                pricing={"prompt": "0.0000044"},
            ),
            ExactRoutePriceTier.build(
                min_prompt_tokens=200_000,
                pricing={
                    "completion": "0.0000132",
                    "prompt": "0.0000033",
                },
            ),
        ),
    )

    assert {item.component: item.unit_price for item in schedule.maximum_pricing} == {
        RoutePriceComponent.COMPLETION: "0.0000132",
        RoutePriceComponent.INPUT_CACHE_READ: "0.00000055",
        RoutePriceComponent.PROMPT: "0.0000044",
        RoutePriceComponent.REQUEST: "0",
        RoutePriceComponent.WEB_SEARCH: "0",
    }
    assert schedule.projection_method == "MMAUDIT_TIERED_MAXIMUM_RATE_V1"
    assert schedule.conservative_for_sub_threshold_prompts is True
    cap = project_provider_price_cap(base, schedule=schedule)
    by_component = {item.component: item.value for item in cap}
    assert Decimal(str(by_component[ProviderMaxPriceComponent.PROMPT])) == Decimal("4.4")
    assert Decimal(str(by_component[ProviderMaxPriceComponent.COMPLETION])) == Decimal("13.2")

    proof = prove_provider_price_cap(
        pricing=base,
        schedule=schedule,
        configured_cap=cap,
        algorithm=ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1,
    )
    assert proof.pricing_schedule == schedule
    assert proof.projected_cap == cap
    assert len(proof.proof_sha256) == 64

    with pytest.raises(RouteConstraintError, match="weaker"):
        prove_provider_price_cap(
            pricing=base,
            schedule=schedule,
            configured_cap=project_provider_price_cap(base),
            algorithm=ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1,
        )


def test_tiered_schedule_digest_matches_endpoint_schedule_domain() -> None:
    base = normalize_exact_route_pricing(
        {
            "completion": "0.0000066",
            "input_cache_read": "0.00000055",
            "prompt": "0.0000022",
            "request": "0",
            "web_search": "0",
        }
    )
    schedule = ExactRoutePricingSchedule.build(
        base_pricing=base,
        tiers=(
            ExactRoutePriceTier.build(
                min_prompt_tokens=200_000,
                pricing={
                    "completion": "0.0000132",
                    "input_cache_read": "0.0000011",
                    "prompt": "0.0000044",
                },
            ),
        ),
    )

    assert schedule.pricing_schedule_sha256 == (
        "b84e33a72274317fe7c8bc25c59dfcce6b82d7bc3edbe4664530aef29f9d5936"
    )
    assert len(schedule.evidence_sha256) == 64

    payload = schedule.model_dump(mode="python")
    payload["maximum_pricing"] = (
        ExactRoutePrice(
            component=RoutePriceComponent.COMPLETION,
            unit_price="0.0000133",
        ),
        *payload["maximum_pricing"][1:],
    )
    with pytest.raises(ValidationError, match="schedule maximum is inconsistent"):
        ExactRoutePricingSchedule.model_validate(payload)


def test_tiered_cap_checks_cache_dominance_in_every_effective_state() -> None:
    base = normalize_exact_route_pricing(
        {
            "completion": "0.2",
            "input_cache_read": "0.09",
            "prompt": "0.1",
        }
    )
    schedule = ExactRoutePricingSchedule.build(
        base_pricing=base,
        tiers=(
            ExactRoutePriceTier.build(
                min_prompt_tokens=100,
                pricing={"prompt": "0.05"},
            ),
            ExactRoutePriceTier.build(
                min_prompt_tokens=200,
                pricing={"prompt": "0.2"},
            ),
        ),
    )
    maximum = {item.component: item.unit_price for item in schedule.maximum_pricing}
    assert Decimal(maximum[RoutePriceComponent.INPUT_CACHE_READ]) <= Decimal(
        maximum[RoutePriceComponent.PROMPT]
    )

    with pytest.raises(RouteConstraintError, match="cache-read pricing is not prompt dominated"):
        project_provider_price_cap(base, schedule=schedule)


def test_tiered_schedule_rejects_missing_base_component_and_preserves_uncappable_policy() -> None:
    base = normalize_exact_route_pricing({"completion": "0.2", "prompt": "0.1"})
    with pytest.raises(RouteConstraintError, match="component absent from base"):
        ExactRoutePricingSchedule.build(
            base_pricing=base,
            tiers=(
                ExactRoutePriceTier.build(
                    min_prompt_tokens=100,
                    pricing={"request": "0"},
                ),
            ),
        )

    uncappable_base = normalize_exact_route_pricing(
        {
            "completion": "0.2",
            "input_cache_write": "0",
            "prompt": "0.1",
        }
    )
    uncappable_schedule = ExactRoutePricingSchedule.build(
        base_pricing=uncappable_base,
        tiers=(
            ExactRoutePriceTier.build(
                min_prompt_tokens=100,
                pricing={"prompt": "0.2"},
            ),
        ),
    )
    with pytest.raises(RouteConstraintError, match="variable price without a provider cap"):
        project_provider_price_cap(uncappable_base, schedule=uncappable_schedule)


def test_optional_schedule_keeps_flat_facts_and_proof_byte_identity() -> None:
    profile = _profile()
    constraint = _constraint(profile)
    facts = _facts(profile=profile, constraint=constraint)
    proof = prove_provider_price_cap(
        pricing=_pricing(),
        configured_cap=project_provider_price_cap(_pricing()),
        algorithm=ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1,
    )

    assert "pricing_schedule" not in facts.model_dump(mode="json")
    assert facts.facts_sha256 == (
        "1103d18abae1742e7b445e6d60b131d44d1b1c00f0c21f4ed86cbfd3a1760714"
    )
    assert "pricing_schedule" not in proof.model_dump(mode="json")
    assert proof.proof_sha256 == (
        "92fd05157c7a2f5a16c5906eecf35bcb9692b6348205d8f392e8a817341f1ddd"
    )

    tiered_base = normalize_exact_route_pricing(
        {"completion": "0.000002", "prompt": "0.000001", "request": "0"}
    )
    schedule = ExactRoutePricingSchedule.build(
        base_pricing=tiered_base,
        tiers=(
            ExactRoutePriceTier.build(
                min_prompt_tokens=100,
                pricing={"completion": "0.000004", "prompt": "0.000003"},
            ),
        ),
    )
    tiered_facts = _facts(
        profile=profile,
        constraint=constraint,
        exact_pricing=tiered_base,
        pricing_schedule=schedule,
        configured_provider_max_price=project_provider_price_cap(
            tiered_base,
            schedule=schedule,
        ),
    )
    tiered_report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=tiered_facts,
    )

    assert tiered_facts.pricing_schedule == schedule
    assert (
        tiered_facts.model_dump(mode="json")["pricing_schedule"]["pricing_schedule_sha256"]
        == schedule.pricing_schedule_sha256
    )
    assert _result(tiered_report, RoutePredicateId.PRICE_CAP_EXPRESSIBILITY) == (
        RoutePredicateDisposition.SATISFIED,
        RoutePredicateReason.SATISFIED,
    )
    assert _result(tiered_report, RoutePredicateId.PRICE_CAP_NO_WEAKER) == (
        RoutePredicateDisposition.SATISFIED,
        RoutePredicateReason.SATISFIED,
    )


def test_unavailable_pricing_schedule_fails_closed_before_flat_cap_projection() -> None:
    profile = _profile()
    constraint = _constraint(profile)
    facts = _facts(
        profile=profile,
        constraint=constraint,
        pricing_schedule="unavailable",
        configured_provider_max_price=None,
    )

    report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=facts,
    )

    assert facts.model_dump(mode="json")["pricing_schedule"] == "unavailable"
    assert _result(report, RoutePredicateId.PRICE_CAP_EXPRESSIBILITY) == (
        RoutePredicateDisposition.REJECTED,
        RoutePredicateReason.PRICE_CAP_NOT_EXPRESSIBLE,
    )
    assert _result(report, RoutePredicateId.PRICE_CAP_NO_WEAKER) == (
        RoutePredicateDisposition.UNAVAILABLE,
        RoutePredicateReason.PRICE_CAP_PROOF_UNAVAILABLE,
    )
    with pytest.raises(ValueError, match="cannot retain a provider price cap"):
        _facts(
            profile=profile,
            constraint=constraint,
            pricing_schedule="unavailable",
        )


@pytest.mark.parametrize(
    "pricing",
    (
        (
            ExactRoutePrice(
                component=RoutePriceComponent.COMPLETION,
                unit_price="0.1",
            ),
            ExactRoutePrice(
                component=RoutePriceComponent.INTERNAL_REASONING,
                unit_price="0",
            ),
            ExactRoutePrice(component=RoutePriceComponent.PROMPT, unit_price="0.1"),
        ),
        (
            ExactRoutePrice(
                component=RoutePriceComponent.COMPLETION,
                unit_price="0.1",
            ),
            ExactRoutePrice(
                component=RoutePriceComponent.INPUT_CACHE_READ,
                unit_price="0.2",
            ),
            ExactRoutePrice(component=RoutePriceComponent.PROMPT, unit_price="0.1"),
        ),
        (
            ExactRoutePrice(
                component=RoutePriceComponent.COMPLETION,
                unit_price="0.1",
            ),
            ExactRoutePrice(component=RoutePriceComponent.PROMPT, unit_price="0.1"),
            ExactRoutePrice(
                component=RoutePriceComponent.WEB_SEARCH,
                unit_price="0.1",
            ),
        ),
    ),
)
def test_price_projection_rejects_unexpressible_components(
    pricing: tuple[ExactRoutePrice, ...],
) -> None:
    with pytest.raises(RouteConstraintError):
        project_provider_price_cap(pricing)


@pytest.mark.parametrize("unit_price", ("0.10", "01", "1e-6", "-1", "nan"))
def test_exact_price_rejects_noncanonical_values(unit_price: str) -> None:
    with pytest.raises(ValidationError):
        ExactRoutePrice(
            component=RoutePriceComponent.PROMPT,
            unit_price=unit_price,
        )


def test_purpose_rules_stage_unavailable_facts_without_weakening() -> None:
    profile = _profile()
    constraint = _constraint(profile)
    discovery_facts = _facts(
        profile=profile,
        constraint=constraint,
        frozen_live_equivalent=None,
        registry_selection_plan_sha256=None,
        registry_profile_sha256=None,
        registry_constraint_sha256=None,
    )
    discovery_report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=discovery_facts,
    )
    full_report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=_facts(profile=profile, constraint=constraint),
    )

    assert (
        require_route_predicates(
            discovery_report,
            purpose=RouteConstraintPurpose.DISCOVERY_PUBLICATION,
        )
        == discovery_report
    )
    with pytest.raises(RoutePredicateRequirementError) as registry_error:
        require_route_predicates(
            discovery_report,
            purpose=RouteConstraintPurpose.REGISTRY_PUBLICATION,
        )
    assert {item.predicate_id for item in registry_error.value.failures} == {
        RoutePredicateId.REGISTRY_SELECTION_HASH_CUSTODY,
        RoutePredicateId.REGISTRY_CONSTRAINT_HASH_CUSTODY,
    }
    assert (
        require_route_predicates(
            full_report,
            purpose=RouteConstraintPurpose.REGISTRY_PUBLICATION,
        )
        == full_report
    )
    assert (
        require_route_predicates(
            full_report,
            purpose=RouteConstraintPurpose.NONCREDITING_SMOKE_ADMISSION,
        )
        == full_report
    )

    with pytest.raises(RoutePredicateRequirementError) as campaign_error:
        require_route_predicates(
            full_report,
            purpose=RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION,
        )
    assert tuple(item.predicate_id for item in campaign_error.value.failures) == (
        RoutePredicateId.EMPIRICAL_SCHEMA_CONFORMANCE,
        RoutePredicateId.TOKEN_DETAIL_REPORTING_CONVENTION,
    )
    assert tuple(item.reason for item in campaign_error.value.failures) == (
        RoutePredicateReason.EMPIRICAL_SCHEMA_EVIDENCE_UNAVAILABLE,
        RoutePredicateReason.TOKEN_DETAIL_CONVENTION_UNAVAILABLE,
    )
    assert str(campaign_error.value) == (
        "route predicate report does not satisfy its closed purpose: "
        "purpose=FULL_CAMPAIGN_ADMISSION; "
        "failures=EMPIRICAL_SCHEMA_CONFORMANCE=EMPIRICAL_SCHEMA_EVIDENCE_UNAVAILABLE,"
        "TOKEN_DETAIL_REPORTING_CONVENTION=TOKEN_DETAIL_CONVENTION_UNAVAILABLE"
    )

    static_full_facts = _facts(
        profile=profile,
        constraint=constraint,
        frozen_live_equivalent=None,
    )
    static_full_report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=static_full_facts,
    )
    with pytest.raises(RoutePredicateRequirementError) as static_campaign_error:
        require_route_predicates(
            static_full_report,
            purpose=RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION,
        )
    assert tuple(item.predicate_id for item in static_campaign_error.value.failures) == (
        RoutePredicateId.EMPIRICAL_SCHEMA_CONFORMANCE,
        RoutePredicateId.TOKEN_DETAIL_REPORTING_CONVENTION,
    )

    mismatched_live_report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=_facts(
            profile=profile,
            constraint=constraint,
            frozen_live_equivalent=False,
        ),
    )
    with pytest.raises(RoutePredicateRequirementError) as mismatch_error:
        require_route_predicates(
            mismatched_live_report,
            purpose=RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION,
        )
    assert RoutePredicateId.FROZEN_LIVE_EQUIVALENCE in {
        item.predicate_id for item in mismatch_error.value.failures
    }


def test_registry_selection_custody_compares_expected_and_observed_final_plan_hashes() -> None:
    profile = _profile()
    constraint = _constraint(profile)
    matching = _facts(profile=profile, constraint=constraint)
    mismatching = _facts(
        profile=profile,
        constraint=constraint,
        expected_selection_plan_sha256=OTHER_SHA256,
    )

    assert _result(
        evaluate_route_predicates(
            profile=profile,
            constraint=constraint,
            facts=matching,
        ),
        RoutePredicateId.REGISTRY_SELECTION_HASH_CUSTODY,
    ) == (RoutePredicateDisposition.SATISFIED, RoutePredicateReason.SATISFIED)
    assert _result(
        evaluate_route_predicates(
            profile=profile,
            constraint=constraint,
            facts=mismatching,
        ),
        RoutePredicateId.REGISTRY_SELECTION_HASH_CUSTODY,
    ) == (
        RoutePredicateDisposition.REJECTED,
        RoutePredicateReason.REGISTRY_SELECTION_CUSTODY_MISMATCH,
    )


def test_empirical_schema_and_token_detail_cannot_be_promoted_by_metadata() -> None:
    report = _report()

    assert _result(report, RoutePredicateId.EMPIRICAL_SCHEMA_CONFORMANCE) == (
        RoutePredicateDisposition.UNAVAILABLE,
        RoutePredicateReason.EMPIRICAL_SCHEMA_EVIDENCE_UNAVAILABLE,
    )
    assert _result(report, RoutePredicateId.TOKEN_DETAIL_REPORTING_CONVENTION) == (
        RoutePredicateDisposition.UNAVAILABLE,
        RoutePredicateReason.TOKEN_DETAIL_CONVENTION_UNAVAILABLE,
    )


def test_constraint_rejects_mutable_model_alias() -> None:
    profile = _profile()
    with pytest.raises(ValidationError, match="exact"):
        ExactRouteConstraint.build(
            role=ExactRouteRole.CANDIDATE,
            exact_model_id="acme/model-latest",
            provider_endpoint=ENDPOINT,
            profile=profile,
        )


def test_facts_reject_partial_registry_custody() -> None:
    profile = _profile()
    constraint = _constraint(profile)

    with pytest.raises(ValidationError, match="all present or absent"):
        _facts(
            profile=profile,
            constraint=constraint,
            registry_selection_plan_sha256=None,
        )
