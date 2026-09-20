"""Synthetic truth-table regressions; copied post-decode states grant no runtime authority."""

from __future__ import annotations

import json
from typing import Any, get_args

import pytest

import mmaudit.models.usage as usage_module
from mmaudit.models.reasoning import ReasoningExecutionEvidence, TokenDetailAccountingEvidence
from mmaudit.models.schemas import UsageRecord
from mmaudit.models.token_planning import RequestTokenPlan
from mmaudit.orchestration.manifest import canonical_sha256
from tests.unit.test_usage import _creditable_record, _reasoning_token_bound_creditable_record

_CANARY = "synthetic-private-evidence-must-not-be-disclosed"


def _fixture(version: str) -> tuple[UsageRecord, RequestTokenPlan]:
    record = _reasoning_token_bound_creditable_record(3)
    plan = usage_module.request_token_plan_from_usage(record)
    assert plan is not None
    if version == "2.0":
        return record, plan
    payload = plan.model_dump(mode="json")
    payload.update(
        schema_version="3.0",
        token_detail_accounting_method="MMAUDIT_INDEPENDENT_REASONING_COMPONENT_ENVELOPE_V1",
        wire_max_tokens=plan.reserved_output_tokens,
    )
    payload["plan_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "plan_sha256"}
    )
    plan = RequestTokenPlan.model_validate_json(json.dumps(payload), strict=True)
    assert plan.reasoning_plan is not None
    detail = TokenDetailAccountingEvidence.build(
        provider_prompt_tokens=record.prompt_tokens,
        provider_completion_tokens=record.completion_tokens,
        provider_total_tokens=record.total_tokens,
        provider_reasoning_tokens=record.reasoning_tokens,
        provider_cached_tokens=record.cached_tokens,
        planned_prompt_tokens=plan.prompt_byte_upper_bound_tokens,
        planned_visible_output_tokens=plan.reserved_output_tokens,
        planned_reasoning_tokens=plan.reserved_reasoning_tokens,
        planned_completion_tokens=plan.requested_completion_tokens,
        request_token_plan_sha256=plan.plan_sha256,
        request_body_sha256=record.request_body_sha256 or "",
    )
    reasoning = ReasoningExecutionEvidence.build(
        request_plan=plan.reasoning_plan,
        observed_reasoning_tokens=record.reasoning_tokens,
        provider_completion_tokens=record.completion_tokens,
        request_token_plan_sha256=plan.plan_sha256,
        request_body_sha256=record.request_body_sha256 or "",
        accounting_method=detail.accounting_method,
        token_detail_accounting_evidence=detail,
    )
    atomic = dict(record.routing["atomic_token_reservation"])
    atomic["request_token_plan_sha256"] = plan.plan_sha256
    atomic["evidence_sha256"] = canonical_sha256(
        {key: value for key, value in atomic.items() if key != "evidence_sha256"}
    )
    record = UsageRecord.model_validate(
        {
            **record.model_dump(mode="json"),
            "reasoning_evidence": reasoning,
            "token_detail_accounting_evidence": detail,
            "routing": {
                **record.routing,
                "request_token_plan": plan.model_dump(mode="json"),
                "request_token_plan_sha256": plan.plan_sha256,
                "atomic_token_reservation": atomic,
                "atomic_token_reservation_sha256": atomic["evidence_sha256"],
                "atomic_token_reservations": [atomic],
                "atomic_token_reservation_sha256s": [atomic["evidence_sha256"]],
            },
        }
    )
    assert usage_module.request_token_plan_from_usage(record) == plan
    return record, plan


def _replace(model: Any, path: str, value: Any) -> Any:
    """Mutate a detached post-decode field for differential testing only."""

    head, _, tail = path.partition(".")
    return model.model_copy(
        update={head: _replace(getattr(model, head), tail, value) if tail else value}
    )


def test_token_routing_vocabulary_is_closed_unique_and_value_free() -> None:
    expected = (
        "TOKEN_PLAN_ROUTING:PLAN_MISSING",
        "TOKEN_PLAN_ROUTING:RECOVERY_SCOPE",
        "TOKEN_PLAN_ROUTING:PLAN_OR_RESERVATION_PROJECTION",
        "TOKEN_PLAN_ROUTING:PLAN_UNAVAILABLE",
        "TOKEN_PLAN_ROUTING:V3_SCOPE_REQUIRED",
        "TOKEN_PLAN_ROUTING:PLAN_SCHEMA",
        "TOKEN_PLAN_ROUTING:REASONING_PRESENCE",
        "TOKEN_PLAN_ROUTING:REASONING_REQUEST_PLAN",
        "TOKEN_PLAN_ROUTING:REASONING_PLAN_SHA256",
        "TOKEN_PLAN_ROUTING:REASONING_REQUEST_BODY_SHA256",
        "TOKEN_PLAN_ROUTING:REASONING_COMPLETION_TOKENS",
        "TOKEN_PLAN_ROUTING:REASONING_OBSERVATION_MISMATCH",
        "TOKEN_PLAN_ROUTING:UNOBSERVED_REASONING_NONZERO",
        "TOKEN_PLAN_ROUTING:ACTIVE_REASONING_NOT_OBSERVED",
        "TOKEN_PLAN_ROUTING:ACTIVE_REASONING_NONPOSITIVE",
        "TOKEN_PLAN_ROUTING:PROMPT_BYTE_BOUND",
        "TOKEN_PLAN_ROUTING:PROMPT_ROUTE_LIMIT",
        "TOKEN_PLAN_ROUTING:COMPLETION_REQUEST_LIMIT",
        "TOKEN_PLAN_ROUTING:COMPLETION_ROUTE_LIMIT",
        "TOKEN_PLAN_ROUTING:CONTEXT_LIMIT",
        "TOKEN_PLAN_ROUTING:REASONING_WITHIN_COMPLETION",
        "TOKEN_PLAN_ROUTING:REASONING_RESERVATION",
        "TOKEN_PLAN_ROUTING:VISIBLE_OUTPUT_RESERVATION",
        "TOKEN_PLAN_ROUTING:SELECTED_PROVIDER_ENDPOINT",
        "TOKEN_PLAN_ROUTING:V3_PLAN_SCHEMA",
        "TOKEN_PLAN_ROUTING:V3_ACCOUNTING_METHOD",
        "TOKEN_PLAN_ROUTING:V3_WIRE_MAX_TOKENS",
        "TOKEN_PLAN_ROUTING:TOKEN_DETAIL_MISSING",
        "TOKEN_PLAN_ROUTING:TOKEN_DETAIL_ACCOUNTING_METHOD",
        "TOKEN_PLAN_ROUTING:TOKEN_DETAIL_PLAN_SHA256",
        "TOKEN_PLAN_ROUTING:TOKEN_DETAIL_REQUEST_BODY_SHA256",
        "TOKEN_PLAN_ROUTING:REASONING_PLAN_MISSING",
        "TOKEN_PLAN_ROUTING:REASONING_EVIDENCE_MISSING",
        "TOKEN_PLAN_ROUTING:V3_REASONING_SCHEMA",
        "TOKEN_PLAN_ROUTING:REASONING_TOKEN_DETAIL_OBSERVATION",
        "TOKEN_PLAN_ROUTING:REASONING_TOKEN_DETAIL_SHA256",
        "TOKEN_PLAN_ROUTING:REASONING_OBSERVATION_MISSING",
        "TOKEN_PLAN_ROUTING:ACCOUNTED_PROMPT_RESERVATION",
        "TOKEN_PLAN_ROUTING:ACCOUNTED_VISIBLE_OUTPUT_RESERVATION",
        "TOKEN_PLAN_ROUTING:ACCOUNTED_REASONING_RESERVATION",
        "TOKEN_PLAN_ROUTING:ACCOUNTED_COMPLETION_RESERVATION",
        "TOKEN_PLAN_ROUTING:ACCOUNTED_TOTAL_RESERVATION",
        "TOKEN_PLAN_ROUTING:RECORD_PROMPT_TOKENS",
        "TOKEN_PLAN_ROUTING:RECORD_COMPLETION_TOKENS",
        "TOKEN_PLAN_ROUTING:RECORD_REASONING_TOKENS",
        "TOKEN_PLAN_ROUTING:RECORD_TOTAL_TOKENS",
        "TOKEN_PLAN_ROUTING:RECORD_CACHED_TOKENS",
    )
    assert expected == usage_module.TOKEN_PLAN_ROUTING_FAILURE_CODES
    assert get_args(usage_module.TokenPlanRoutingFailureCode) == expected
    assert len(set(expected)) == len(expected)
    assert set(expected).issubset(usage_module.STRICT_USAGE_FAILURE_CODES)
    assert max(map(len, expected)) <= 64
    assert "TOKEN_PLAN_ROUTING" not in usage_module.STRICT_USAGE_FAILURE_CODES


@pytest.mark.parametrize("version", ("2.0", "3.0"))
def test_valid_token_plan_truth_table_preserves_acceptance_and_v3_scope(version: str) -> None:
    record, _plan = _fixture(version)
    for allow in (False, True):
        expected = version == "2.0" or allow
        assert _legacy(record, allow_noncrediting_unknown_token_accounting=allow) is expected
        assert (
            usage_module._has_valid_token_plan_routing(
                record, allow_noncrediting_unknown_token_accounting=allow
            )
            is expected
        )
        code = usage_module._token_plan_routing_failure_code(
            record, allow_noncrediting_unknown_token_accounting=allow
        )
        assert code == (None if expected else "TOKEN_PLAN_ROUTING:V3_SCOPE_REQUIRED")
    if version == "3.0":
        assert not usage_module.is_creditable_usage_record(record)


@pytest.mark.parametrize(
    ("code", "changes"),
    (
        ("REASONING_PRESENCE", (("record.reasoning_evidence", None),)),
        ("REASONING_REQUEST_PLAN", (("record.reasoning_evidence.request_plan", None),)),
        (
            "REASONING_PLAN_SHA256",
            (("record.reasoning_evidence.request_token_plan_sha256", _CANARY),),
        ),
        (
            "REASONING_REQUEST_BODY_SHA256",
            (("record.reasoning_evidence.request_body_sha256", _CANARY),),
        ),
        (
            "REASONING_COMPLETION_TOKENS",
            (("record.reasoning_evidence.provider_completion_tokens", 1),),
        ),
        (
            "REASONING_OBSERVATION_MISMATCH",
            (("record.reasoning_evidence.observed_reasoning_tokens", 2),),
        ),
        (
            "UNOBSERVED_REASONING_NONZERO",
            (("record.reasoning_evidence.observation_available", False),),
        ),
        (
            "ACTIVE_REASONING_NOT_OBSERVED",
            (("record.reasoning_evidence.state", "active_unobserved"),),
        ),
        (
            "ACTIVE_REASONING_NONPOSITIVE",
            (
                ("record.reasoning_tokens", 0),
                ("record.reasoning_evidence.observed_reasoning_tokens", 0),
            ),
        ),
        ("PROMPT_BYTE_BOUND", (("plan.prompt_byte_upper_bound_tokens", 99),)),
        ("PROMPT_ROUTE_LIMIT", (("plan.route_intersection.max_prompt_tokens", 99),)),
        ("COMPLETION_REQUEST_LIMIT", (("plan.requested_completion_tokens", 24),)),
        ("COMPLETION_ROUTE_LIMIT", (("plan.route_intersection.max_completion_tokens", 24),)),
        ("CONTEXT_LIMIT", (("plan.route_intersection.context_tokens", 124),)),
        (
            "REASONING_WITHIN_COMPLETION",
            (
                ("record.reasoning_tokens", 30),
                ("record.reasoning_evidence.observed_reasoning_tokens", 30),
            ),
        ),
        ("REASONING_RESERVATION", (("plan.reserved_reasoning_tokens", 2),)),
        ("VISIBLE_OUTPUT_RESERVATION", (("plan.reserved_output_tokens", 21),)),
        ("SELECTED_PROVIDER_ENDPOINT", (("record.actual_provider_endpoint", _CANARY),)),
        ("PLAN_SCHEMA", (("plan.schema_version", "1.0"),)),
    ),
)
def test_v2_exact_first_failure_matches_frozen_acceptance(
    monkeypatch: pytest.MonkeyPatch, code: str, changes: tuple[tuple[str, Any], ...]
) -> None:
    record, plan = _fixture("2.0")
    for path, value in changes:
        root, _, field = path.partition(".")
        if root == "record":
            record = _replace(record, field, value)
        else:
            plan = _replace(plan, field, value)
    # Isolate already-parsed field predicates. Real projection refusals are tested separately.
    monkeypatch.setattr(usage_module, "request_token_plan_from_usage", lambda _record: plan)
    assert _legacy(record) is False
    assert usage_module._has_valid_token_plan_routing(record) is False
    observed = usage_module._token_plan_routing_failure_code(record)
    assert observed == "TOKEN_PLAN_ROUTING:" + code
    assert _CANARY not in observed


@pytest.mark.parametrize(
    ("code", "changes"),
    (
        ("V3_PLAN_SCHEMA", (("plan.schema_version", "2.0"),)),
        ("V3_ACCOUNTING_METHOD", (("plan.token_detail_accounting_method", _CANARY),)),
        ("V3_WIRE_MAX_TOKENS", (("plan.wire_max_tokens", 1),)),
        ("TOKEN_DETAIL_MISSING", (("record.token_detail_accounting_evidence", None),)),
        ("TOKEN_DETAIL_ACCOUNTING_METHOD", (("detail.accounting_method", _CANARY),)),
        ("TOKEN_DETAIL_PLAN_SHA256", (("detail.request_token_plan_sha256", _CANARY),)),
        ("TOKEN_DETAIL_REQUEST_BODY_SHA256", (("detail.request_body_sha256", _CANARY),)),
        ("REASONING_PLAN_MISSING", (("plan.reasoning_plan", None),)),
        ("REASONING_EVIDENCE_MISSING", (("record.reasoning_evidence", None),)),
        ("V3_REASONING_SCHEMA", (("reasoning.schema_version", "1.0"),)),
        ("REASONING_REQUEST_PLAN", (("reasoning.request_plan", None),)),
        ("REASONING_PLAN_SHA256", (("reasoning.request_token_plan_sha256", _CANARY),)),
        ("REASONING_REQUEST_BODY_SHA256", (("reasoning.request_body_sha256", _CANARY),)),
        ("REASONING_COMPLETION_TOKENS", (("reasoning.provider_completion_tokens", 1),)),
        ("REASONING_TOKEN_DETAIL_OBSERVATION", (("reasoning.observed_reasoning_tokens", 1),)),
        (
            "REASONING_TOKEN_DETAIL_SHA256",
            (("reasoning.token_detail_accounting_evidence_sha256", _CANARY),),
        ),
        ("ACTIVE_REASONING_NOT_OBSERVED", (("reasoning.state", "active_unobserved"),)),
        (
            "ACTIVE_REASONING_NONPOSITIVE",
            (
                ("detail.provider_reasoning_tokens", 0),
                ("reasoning.observed_reasoning_tokens", 0),
            ),
        ),
        (
            "REASONING_OBSERVATION_MISSING",
            (
                ("detail.provider_reasoning_tokens", None),
                ("reasoning.observed_reasoning_tokens", None),
                ("plan.reasoning_plan.control_profile.mode", "disabled"),
                ("reasoning.request_plan.control_profile.mode", "disabled"),
            ),
        ),
        ("PROMPT_BYTE_BOUND", (("detail.provider_prompt_tokens", 99999),)),
        ("PROMPT_ROUTE_LIMIT", (("plan.route_intersection.max_prompt_tokens", 99),)),
        (
            "VISIBLE_OUTPUT_RESERVATION",
            (
                ("detail.provider_completion_tokens", 99999),
                ("reasoning.provider_completion_tokens", 99999),
            ),
        ),
        (
            "REASONING_RESERVATION",
            (
                ("detail.provider_reasoning_tokens", 99999),
                ("reasoning.observed_reasoning_tokens", 99999),
            ),
        ),
        ("ACCOUNTED_PROMPT_RESERVATION", (("detail.accounted_prompt_tokens", 1),)),
        ("ACCOUNTED_VISIBLE_OUTPUT_RESERVATION", (("detail.accounted_visible_output_tokens", 1),)),
        ("ACCOUNTED_REASONING_RESERVATION", (("detail.accounted_reasoning_tokens", 1),)),
        ("ACCOUNTED_COMPLETION_RESERVATION", (("detail.accounted_completion_tokens", 1),)),
        ("ACCOUNTED_TOTAL_RESERVATION", (("detail.accounted_total_tokens", 1),)),
        ("RECORD_PROMPT_TOKENS", (("record.prompt_tokens", 1),)),
        ("RECORD_COMPLETION_TOKENS", (("record.completion_tokens", 1),)),
        ("RECORD_REASONING_TOKENS", (("record.reasoning_tokens", 1),)),
        ("RECORD_TOTAL_TOKENS", (("record.total_tokens", 1),)),
        ("RECORD_CACHED_TOKENS", (("record.cached_tokens", 1),)),
        ("SELECTED_PROVIDER_ENDPOINT", (("record.actual_provider_endpoint", _CANARY),)),
    ),
)
def test_v3_exact_first_failure_matches_frozen_acceptance(
    code: str, changes: tuple[tuple[str, Any], ...]
) -> None:
    record, plan = _fixture("3.0")
    for path, value in changes:
        root, _, field = path.partition(".")
        if root == "plan":
            plan = _replace(plan, field, value)
        else:
            prefix = {
                "detail": "token_detail_accounting_evidence.",
                "reasoning": "reasoning_evidence.",
            }.get(root, "")
            record = _replace(record, prefix + field, value)
    assert _legacy_v3(record, plan) is False
    assert usage_module._has_valid_noncrediting_unknown_token_plan_routing(record, plan) is False
    observed = usage_module._noncrediting_unknown_token_plan_routing_failure_code(record, plan)
    assert observed == "TOKEN_PLAN_ROUTING:" + code
    assert _CANARY not in observed


@pytest.mark.parametrize(
    ("routing_changes", "code"),
    (
        ({"request_token_plan": _CANARY}, "PLAN_OR_RESERVATION_PROJECTION"),
        ({"request_token_plan_sha256": _CANARY}, "PLAN_OR_RESERVATION_PROJECTION"),
        ({"atomic_token_reservation": _CANARY}, "PLAN_OR_RESERVATION_PROJECTION"),
        ({"atomic_token_reservation_sha256s": [_CANARY]}, "PLAN_OR_RESERVATION_PROJECTION"),
        ({"request_token_plan": None, "request_token_plan_sha256": None}, "PLAN_UNAVAILABLE"),
    ),
)
def test_invalid_plan_and_reservation_projection_preserves_refusal_without_values(
    routing_changes: dict[str, Any], code: str
) -> None:
    record, _plan = _fixture("2.0")
    record = record.model_copy(update={"routing": {**record.routing, **routing_changes}})
    assert _legacy(record) is False
    assert usage_module._token_plan_routing_failure_code(record) == "TOKEN_PLAN_ROUTING:" + code


def test_missing_plan_and_partial_recovery_coordinates_remain_refused() -> None:
    record, _plan = _fixture("2.0")
    for options in (
        {"recovery_request_limit_scope": "synthetic-scope"},
        {"recovery_request_limit_count_before": 0},
    ):
        assert _legacy(record, **options) is False
        assert (
            usage_module._token_plan_routing_failure_code(record, **options)
            == "TOKEN_PLAN_ROUTING:RECOVERY_SCOPE"
        )
    missing = record.model_copy(
        update={
            "routing": {
                key: value for key, value in record.routing.items() if key != "request_token_plan"
            }
        }
    )
    assert _legacy(missing) is False
    assert (
        usage_module._token_plan_routing_failure_code(missing) == "TOKEN_PLAN_ROUTING:PLAN_MISSING"
    )


@pytest.mark.parametrize("version", ("2.0", "3.0"))
@pytest.mark.parametrize(
    "field",
    ("prompt_tokens", "completion_tokens", "reasoning_tokens", "total_tokens", "cached_tokens"),
)
@pytest.mark.parametrize("value", (0, 1, 25, 100, 99999, float("nan")))
def test_numeric_truth_table_including_nan_preserves_exact_original_comparisons(
    version: str, field: str, value: int | float
) -> None:
    record, plan = _fixture(version)
    record = record.model_copy(update={field: value})
    expected = _legacy(record, allow_noncrediting_unknown_token_accounting=True)
    assert (
        usage_module._has_valid_token_plan_routing(
            record, allow_noncrediting_unknown_token_accounting=True
        )
        is expected
    )
    if version == "3.0":
        assert usage_module._has_valid_noncrediting_unknown_token_plan_routing(
            record, plan
        ) is _legacy_v3(record, plan)


@pytest.mark.parametrize(
    "helper_name",
    (
        "_token_plan_routing_failure_code",
        "_noncrediting_unknown_token_plan_routing_failure_code",
    ),
)
def test_new_diagnostic_helper_retarget_never_grants_strict_credit(
    monkeypatch: pytest.MonkeyPatch, helper_name: str
) -> None:
    record = _creditable_record()
    assert usage_module.is_creditable_usage_record(record)
    monkeypatch.setattr(usage_module, helper_name, lambda *_args, **_kwargs: None)
    assert not usage_module.is_creditable_usage_record(record)
    assert usage_module.noncrediting_unknown_token_smoke_usage_diagnostics(
        record, require_runtime_attestation=False
    ) == ("REQUIRED_FIELDS",)


@pytest.mark.parametrize(
    "helper_name",
    (
        "_token_plan_routing_failure_code",
        "_noncrediting_unknown_token_plan_routing_failure_code",
    ),
)
def test_in_place_token_helper_retarget_is_caught_by_owned_transport(helper_name: str) -> None:
    import mmaudit.models.openrouter as openrouter_module

    helper = getattr(usage_module, helper_name)
    original = helper.__code__

    def changed(*_args: Any, **_kwargs: Any) -> None:
        return None

    assert openrouter_module._openrouter_client_callables_are_pristine()
    helper.__code__ = changed.__code__.replace(co_freevars=original.co_freevars)
    try:
        assert not openrouter_module._openrouter_client_callables_are_pristine()
    finally:
        helper.__code__ = original
    assert openrouter_module._openrouter_client_callables_are_pristine()


@pytest.mark.parametrize(
    "path",
    (
        "token_detail_accounting_evidence.accounted_prompt_tokens",
        "token_detail_accounting_evidence.accounted_visible_output_tokens",
        "token_detail_accounting_evidence.accounted_reasoning_tokens",
        "token_detail_accounting_evidence.accounted_completion_tokens",
        "token_detail_accounting_evidence.accounted_total_tokens",
        "prompt_tokens",
        "completion_tokens",
        "reasoning_tokens",
        "total_tokens",
        "cached_tokens",
    ),
)
def test_equality_refusal_does_not_invoke_overridden_inequality(path: str) -> None:
    class InconsistentComparison(int):
        def __eq__(self, other: object) -> bool:
            return False

        def __ne__(self, other: object) -> bool:
            raise AssertionError("the original predicate never called inequality here")

    record, plan = _fixture("3.0")
    record = _replace(record, path, InconsistentComparison(1))
    assert _legacy_v3(record, plan) is False
    assert usage_module._has_valid_noncrediting_unknown_token_plan_routing(record, plan) is False


@pytest.mark.parametrize("version", ("2.0", "3.0"))
@pytest.mark.parametrize("count_before", (6, 7, 8))
def test_recovery_truth_table_keeps_external_exact_request_count(
    version: str, count_before: int
) -> None:
    from tests.unit.test_usage import _with_request_limit_inventory

    record, _plan = _fixture(version)
    record = _with_request_limit_inventory(
        record,
        request_limit_scope="synthetic-recovery",
        request_limit_count_before=7,
    )
    options = {
        "recovery_request_limit_scope": "synthetic-recovery",
        "recovery_request_limit_count_before": count_before,
        "allow_noncrediting_unknown_token_accounting": True,
    }
    expected = count_before == 7
    assert _legacy(record, **options) is expected
    assert usage_module._has_valid_token_plan_routing(record, **options) is expected
    assert usage_module._token_plan_routing_failure_code(record, **options) == (
        None if expected else "TOKEN_PLAN_ROUTING:PLAN_OR_RESERVATION_PROJECTION"
    )


# Frozen pre-change predicates, deliberately independent of the new diagnostic evaluators.


def _legacy(
    record: UsageRecord,
    *,
    recovery_request_limit_scope: str | None = None,
    recovery_request_limit_count_before: int | None = None,
    allow_noncrediting_unknown_token_accounting: bool = False,
) -> bool:
    if "request_token_plan" not in record.routing:
        return False
    recovery_mode = recovery_request_limit_scope is not None
    if recovery_mode != (recovery_request_limit_count_before is not None):
        return False
    try:
        plan = (
            usage_module.recovery_request_token_plan_from_usage(
                record,
                request_limit_scope=recovery_request_limit_scope,
                request_limit_count_before=recovery_request_limit_count_before,
            )
            if recovery_mode
            and recovery_request_limit_scope is not None
            and recovery_request_limit_count_before is not None
            else usage_module.request_token_plan_from_usage(record)
        )
    except ValueError:
        return False
    if plan is None:
        return False
    if plan.schema_version == "3.0":
        return allow_noncrediting_unknown_token_accounting and (_legacy_v3(record, plan))
    if plan.schema_version != "2.0":
        return False
    reasoning_plan = plan.reasoning_plan
    reasoning = record.reasoning_evidence
    if (reasoning_plan is None) != (reasoning is None):
        return False
    if reasoning is not None and (
        reasoning.request_plan != reasoning_plan
        or reasoning.request_token_plan_sha256 != plan.plan_sha256
        or reasoning.request_body_sha256 != record.request_body_sha256
        or reasoning.provider_completion_tokens != record.completion_tokens
        or (
            reasoning.observation_available
            and reasoning.observed_reasoning_tokens != record.reasoning_tokens
        )
        or (not reasoning.observation_available and record.reasoning_tokens != 0)
    ):
        return False
    if (
        reasoning_plan is not None
        and reasoning_plan.control_profile.mode != "disabled"
        and reasoning_plan.control_profile.reserved_reasoning_tokens > 0
        and (
            reasoning is None
            or reasoning.state != "active_observed"
            or reasoning.observed_reasoning_tokens is None
            or reasoning.observed_reasoning_tokens <= 0
        )
    ):
        return False
    limits = plan.route_intersection
    return (
        record.prompt_tokens <= plan.prompt_byte_upper_bound_tokens
        and record.prompt_tokens <= limits.max_prompt_tokens
        and record.completion_tokens <= plan.requested_completion_tokens
        and record.completion_tokens <= limits.max_completion_tokens
        and record.prompt_tokens + record.completion_tokens <= limits.context_tokens
        and record.reasoning_tokens <= record.completion_tokens
        and record.reasoning_tokens <= plan.reserved_reasoning_tokens
        and record.completion_tokens - record.reasoning_tokens <= plan.reserved_output_tokens
        and (
            not record.configured_provider_endpoints
            or limits.provider_endpoints == ("mmaudit-local-mock",)
            or (
                isinstance(record.actual_provider_endpoint, str)
                and record.actual_provider_endpoint.casefold()
                in {endpoint.casefold() for endpoint in limits.provider_endpoints}
            )
        )
    )


def _legacy_v3(
    record: UsageRecord,
    plan: RequestTokenPlan,
) -> bool:
    """Validate v3 full-plan accounting while deliberately withholding general credit."""

    token_detail = record.token_detail_accounting_evidence
    reasoning_plan = plan.reasoning_plan
    reasoning = record.reasoning_evidence
    if (
        plan.schema_version != "3.0"
        or plan.token_detail_accounting_method
        != "MMAUDIT_INDEPENDENT_REASONING_COMPONENT_ENVELOPE_V1"
        or plan.wire_max_tokens != plan.reserved_output_tokens
        or token_detail is None
        or token_detail.accounting_method != plan.token_detail_accounting_method
        or token_detail.request_token_plan_sha256 != plan.plan_sha256
        or token_detail.request_body_sha256 != record.request_body_sha256
        or reasoning_plan is None
        or reasoning is None
        or reasoning.schema_version != "1.1"
        or reasoning.request_plan != reasoning_plan
        or reasoning.request_token_plan_sha256 != plan.plan_sha256
        or reasoning.request_body_sha256 != record.request_body_sha256
        or reasoning.provider_completion_tokens != token_detail.provider_completion_tokens
        or reasoning.observed_reasoning_tokens != token_detail.provider_reasoning_tokens
        or reasoning.token_detail_accounting_evidence_sha256 != token_detail.evidence_sha256
    ):
        return False
    control = reasoning_plan.control_profile
    if (
        control.mode != "disabled"
        and control.reserved_reasoning_tokens > 0
        and (
            reasoning.state != "active_observed"
            or token_detail.provider_reasoning_tokens is None
            or token_detail.provider_reasoning_tokens <= 0
        )
    ):
        return False
    limits = plan.route_intersection
    raw_prompt = token_detail.provider_prompt_tokens
    raw_completion = token_detail.provider_completion_tokens
    raw_reasoning = token_detail.provider_reasoning_tokens
    if raw_reasoning is None:
        return False
    return (
        raw_prompt <= plan.prompt_byte_upper_bound_tokens
        and raw_prompt <= limits.max_prompt_tokens
        and raw_completion <= plan.reserved_output_tokens
        and raw_reasoning <= plan.reserved_reasoning_tokens
        and token_detail.accounted_prompt_tokens == plan.prompt_byte_upper_bound_tokens
        and token_detail.accounted_visible_output_tokens == plan.reserved_output_tokens
        and token_detail.accounted_reasoning_tokens == plan.reserved_reasoning_tokens
        and token_detail.accounted_completion_tokens == plan.requested_completion_tokens
        and token_detail.accounted_total_tokens
        == plan.prompt_byte_upper_bound_tokens + plan.requested_completion_tokens
        and record.prompt_tokens == token_detail.provider_prompt_tokens
        and record.completion_tokens == token_detail.provider_completion_tokens
        and record.reasoning_tokens == raw_reasoning
        and record.total_tokens == token_detail.provider_total_tokens
        and record.cached_tokens == token_detail.provider_cached_tokens
        and (
            not record.configured_provider_endpoints
            or (
                isinstance(record.actual_provider_endpoint, str)
                and record.actual_provider_endpoint.casefold()
                in {endpoint.casefold() for endpoint in limits.provider_endpoints}
            )
        )
    )
