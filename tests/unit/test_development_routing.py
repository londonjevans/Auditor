from __future__ import annotations

import json
import socket
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

import mmaudit.models.development_transport as transport_module
from mmaudit.models.candidate_revocation import CandidateSelectionRevocationError
from mmaudit.models.development_review import (
    DevelopmentReviewObservation,
    prepare_development_review,
)
from mmaudit.models.development_routing import (
    DevelopmentRoutingContext,
    DevelopmentRoutingEvidence,
    DevelopmentRoutingFailure,
    DevelopmentRoutingIdentity,
    observe_development_routing,
)
from mmaudit.models.development_transport import (
    review_development_audit_shard,
    review_development_fixture,
)
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from scripts.generate_release_schemas import MODELS, rendered_schema
from tests.development_audit_support import audit_case
from tests.development_review_support import (
    SYNTHETIC_CREDENTIAL,
    discovery_review_case,
    local_controls,
    response_payload,
    review_case,
)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("synthetic routing checks must never access the network")

    monkeypatch.setattr(socket.socket, "connect", forbidden)


@pytest.mark.parametrize(
    "filename",
    [
        "development_routing_observation.schema.json",
        "development_fixture_review_observation.schema.json",
        "development_audit_shard_observation.schema.json",
        "development_audit_observation.schema.json",
    ],
)
def test_routing_schemas_are_canonical_bounded_and_non_authorizing(filename):
    content = (Path(__file__).resolve().parents[2] / "schemas" / filename).read_text()
    assert content == rendered_schema(filename, MODELS[filename])
    schema = json.loads(content)
    routing = (
        schema
        if filename == "development_routing_observation.schema.json"
        else schema["$defs"]["DevelopmentRoutingEvidence"]
    )
    assert routing["additionalProperties"] is False
    fields = routing["properties"]
    assert fields["runtime_authority"]["const"] is False
    assert fields["failure_codes"]["maxItems"] == len(DevelopmentRoutingFailure)
    assert fields["selected_endpoints"]["maxItems"] == 128
    assert fields["attempts"]["maxItems"] == 128
    assert not {"raw_router_metadata", "raw_headers", "raw_response", "api_key"} & fields.keys()


def prepared_case(scope="fixture", *, discovery=True):
    if scope == "shard":
        return audit_case(discovery=discovery).shards[0]
    baseline = review_case()
    return prepare_development_review(
        policy=baseline.estimate.policy,
        endpoint_snapshot=discovery_review_case() if discovery else baseline.endpoint_snapshot,
        source_filename=baseline.source_filename,
        source_content=baseline.source_content,
        request_id=baseline.estimate.request_id,
    )


async def observe(tmp_path, prepared, payload, *, scope="fixture", headers=None):
    ledger, secrets = local_controls(tmp_path)
    transport = review_development_fixture if scope == "fixture" else review_development_audit_shard
    calls = []

    def handler(request):
        calls.append(request)
        assert request.content == prepared.request_content
        assert (
            ledger.snapshot().active_reserved_usd
            == prepared.estimate.estimated_cost_per_attempt_usd
        )
        return httpx.Response(200, json=payload, headers=headers)

    result = await transport(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert len(calls) == 1
    assert result.accounted_cost_usd == ledger.snapshot().spent_usd == Decimal("0.01")
    assert (
        result.audit_complete is result.qualification_eligible is result.release_eligible is False
    )
    return result


@pytest.mark.parametrize("scope", ["fixture", "shard"])
@pytest.mark.parametrize("location", ["returned", "selected", "attempted", "all"])
async def test_independently_bound_canonical_model_is_an_accepted_response_identity(
    tmp_path, scope, location
):
    prepared = prepared_case(scope)
    assert prepared.discovery is not None
    canonical = prepared.discovery.canonical_slug
    assert canonical != prepared.estimate.exact_model_id
    payload = response_payload()
    if location in {"returned", "all"}:
        payload["model"] = canonical
    if location in {"selected", "all"}:
        payload["openrouter_metadata"]["endpoints"]["available"][0]["model"] = canonical
    if location in {"attempted", "all"}:
        payload["openrouter_metadata"]["attempts"][0]["model"] = canonical
    result = await observe(tmp_path, prepared, payload, scope=scope)
    assert result.status == "OBSERVED"
    routing = result.routing_evidence
    assert routing is not None and routing.failure_codes == ()
    assert routing.context.identity_basis == "SUPPLIED_DISCOVERY_BOUND"
    assert routing.context.canonical_model_id == canonical
    assert (
        routing.context.catalog_identity_binding_sha256
        == prepared.discovery.catalog_identity_binding_sha256
    )
    assert (
        routing.context.model_metadata_snapshot_sha256
        == prepared.discovery.model_metadata_snapshot_sha256
    )
    assert routing.runtime_authority is False
    assert DevelopmentRoutingEvidence.model_validate_json(routing.model_dump_json()) == routing


@pytest.mark.parametrize("scope", ["fixture", "shard"])
async def test_absent_router_byok_requires_explicit_false_usage_evidence(tmp_path, scope):
    payload = response_payload()
    del payload["openrouter_metadata"]["is_byok"]
    payload["usage"]["is_byok"] = False
    result = await observe(tmp_path, prepared_case(scope), payload, scope=scope)
    assert result.status == "OBSERVED"
    assert result.routing_evidence.router_byok == "ABSENT"
    assert result.routing_evidence.usage_byok == "FALSE"


@pytest.mark.parametrize(
    "router_marker", ["absent", "false", "true", "null", "zero", "text", "object"]
)
@pytest.mark.parametrize(
    "usage_marker", ["absent", "false", "true", "null", "zero", "text", "object"]
)
async def test_byok_requires_positive_false_and_refuses_contradictory_or_malformed_evidence(
    tmp_path, router_marker, usage_marker
):
    payload = response_payload()
    values = {"false": False, "true": True, "null": None, "zero": 0, "text": "false", "object": {}}
    for container, marker in (
        (payload["openrouter_metadata"], router_marker),
        (payload["usage"], usage_marker),
    ):
        if marker == "absent":
            container.pop("is_byok", None)
        else:
            container["is_byok"] = values[marker]
    result = await observe(tmp_path, prepared_case(), payload)
    markers = {router_marker, usage_marker}
    accepted = markers.issubset({"absent", "false"}) and "false" in markers
    assert (result.status == "OBSERVED") is accepted
    evidence = result.routing_evidence
    assert evidence is not None
    if markers == {"absent"}:
        assert evidence.failure_codes == (DevelopmentRoutingFailure.BYOK_EVIDENCE_MISSING,)
    if "true" in markers:
        assert DevelopmentRoutingFailure.BYOK_REPORTED in evidence.failure_codes
    if not markers.issubset({"absent", "false", "true"}):
        assert DevelopmentRoutingFailure.BYOK_INVALID in evidence.failure_codes


@pytest.mark.parametrize("scope", ["fixture", "shard"])
async def test_endpoint_only_input_cannot_accept_response_authored_canonical_aliases(
    tmp_path, scope
):
    payload = response_payload()
    canonical = discovery_review_case().canonical_slug
    payload["model"] = canonical
    payload["canonical_slug"] = canonical
    payload["frozen_aliases"] = [payload["openrouter_metadata"]["requested"], canonical]
    payload["openrouter_metadata"]["endpoints"]["available"][0]["model"] = canonical
    payload["openrouter_metadata"]["attempts"][0]["model"] = canonical
    result = await observe(tmp_path, prepared_case(scope, discovery=False), payload, scope=scope)
    assert result.status == "INCOMPLETE"
    routing = result.routing_evidence
    assert routing.context.identity_basis == "REQUEST_ID_ONLY"
    assert routing.context.canonical_model_id is None
    assert routing.failure_codes == (
        DevelopmentRoutingFailure.RETURNED_MODEL,
        DevelopmentRoutingFailure.SELECTED_MODEL,
        DevelopmentRoutingFailure.ATTEMPT_MODEL,
    )
    assert canonical not in routing.model_dump_json()


@pytest.mark.parametrize(
    "failure",
    [
        "returned",
        "provider",
        "metadata",
        "requested",
        "canonical_requested",
        "strategy",
        "router_attempt",
        "numeric_attempt",
        "pipeline",
        "endpoints",
        "available",
        "selected_marker",
        "total",
        "none_selected",
        "many_selected",
        "selected_model",
        "selected_provider",
        "attempts",
        "attempt_model",
        "attempt_provider",
        "attempt_status",
        "generation_header",
    ],
)
async def test_every_routing_refusal_has_a_named_bounded_diagnostic(tmp_path, failure):
    payload = response_payload()
    router = payload["openrouter_metadata"]
    selected = router["endpoints"]["available"][0]
    attempt = router["attempts"][0]
    headers = None
    expected = {
        "returned": "RETURNED_MODEL",
        "provider": "RESPONSE_PROVIDER",
        "metadata": "ROUTER_METADATA",
        "requested": "REQUESTED_MODEL",
        "canonical_requested": "REQUESTED_MODEL",
        "strategy": "STRATEGY",
        "router_attempt": "ROUTER_ATTEMPT",
        "numeric_attempt": "ROUTER_ATTEMPT",
        "pipeline": "PIPELINE",
        "endpoints": "ENDPOINT_SHAPE",
        "available": "ENDPOINT_SHAPE",
        "selected_marker": "ENDPOINT_SHAPE",
        "total": "ENDPOINT_SHAPE",
        "none_selected": "SELECTION_COUNT",
        "many_selected": "SELECTION_COUNT",
        "selected_model": "SELECTED_MODEL",
        "selected_provider": "SELECTED_PROVIDER",
        "attempts": "ATTEMPT_SHAPE",
        "attempt_model": "ATTEMPT_MODEL",
        "attempt_provider": "ATTEMPT_PROVIDER",
        "attempt_status": "ATTEMPT_STATUS",
        "generation_header": "GENERATION_HEADER",
    }[failure]
    if failure == "returned":
        payload["model"] = {"untrusted": "SYNTHETIC_CANARY"}
    elif failure == "provider":
        payload["provider"] = ["SYNTHETIC_CANARY"]
    elif failure == "metadata":
        del payload["openrouter_metadata"]
    elif failure in {"requested", "canonical_requested"}:
        router["requested"] = (
            discovery_review_case().canonical_slug
            if failure == "canonical_requested"
            else "SYNTHETIC_CANARY"
        )
    elif failure == "strategy":
        router["strategy"] = "fallback"
    elif failure in {"router_attempt", "numeric_attempt"}:
        router["attempt"] = 2 if failure == "router_attempt" else True
    elif failure == "pipeline":
        router["pipeline"] = [
            {"summary": "SYNTHETIC_CANARY", "data": {"prompt": "SYNTHETIC_CANARY"}}
        ]
    elif failure == "endpoints":
        router["endpoints"] = None
    elif failure == "available":
        router["endpoints"]["available"] = [selected] * 129
    elif failure == "selected_marker":
        selected["selected"] = 1
    elif failure == "total":
        router["endpoints"]["total"] = 10**100
    elif failure == "none_selected":
        selected["selected"] = False
    elif failure == "many_selected":
        router["endpoints"]["available"] = [selected, selected.copy()]
        router["endpoints"]["total"] = 2
    elif failure == "selected_model":
        selected["model"] = "other-author/SYNTHETIC_CANARY"
    elif failure == "selected_provider":
        selected["provider"] = "SYNTHETIC_CANARY"
    elif failure == "attempts":
        router["attempts"] = [attempt, attempt.copy()]
    elif failure == "attempt_model":
        attempt["model"] = "synthetic/SYNTHETIC_CANARY"
    elif failure == "attempt_provider":
        attempt["provider"] = None
    elif failure == "attempt_status":
        attempt["status"] = True
    else:
        headers = {"x-generation-id": "gen-SYNTHETIC_CANARY"}
    result = await observe(tmp_path, prepared_case(), payload, headers=headers)
    assert result.status == "INCOMPLETE" and result.response is None
    assert "IDENTITY_MISMATCH" in result.diagnostics
    assert expected in result.routing_evidence.failure_codes
    assert "SYNTHETIC_CANARY" not in result.model_dump_json()
    assert len(result.routing_evidence.model_dump_json().encode()) < 100_000


@pytest.mark.parametrize(
    "value",
    [
        SYNTHETIC_CREDENTIAL,
        "sk-or-v1-" + "synthetic-only-" * 4,
        "SYNTHETIC_UNKNOWN_CANARY",
        "x" * 30_000,
    ],
    ids=["credential", "secret-pattern", "unknown-text", "oversize-identity"],
)
async def test_identity_and_extra_metadata_never_echo_arbitrary_or_secret_values(tmp_path, value):
    payload = response_payload()
    router = payload["openrouter_metadata"]
    payload["provider"] = value
    router["endpoints"]["available"][0]["provider"] = value
    router["attempts"][0]["provider"] = value
    router.update(summary=value, region=value, params={"prompt": value})
    result = await observe(tmp_path, prepared_case(), payload)
    assert result.status == "INCOMPLETE"
    assert value not in result.model_dump_json()
    assert result.routing_evidence.response_provider.value is None
    assert result.routing_evidence.selected_endpoints[0].provider.value is None
    assert result.routing_evidence.attempts[0].provider.value is None


@pytest.mark.parametrize("phase", ["before_reservation", "after_reservation"])
async def test_canonical_identity_revocation_is_checked_before_any_dispatch(
    tmp_path, monkeypatch, phase
):
    prepared = prepared_case()
    canonical = prepared.discovery.canonical_slug
    ledger, secrets = local_controls(tmp_path)
    original = transport_module.require_candidate_assignment_eligible
    canonical_checks = 0

    def gate(**kwargs):
        nonlocal canonical_checks
        if kwargs["exact_model_id"] == canonical:
            canonical_checks += 1
            if canonical_checks == (1 if phase == "before_reservation" else 2):
                raise CandidateSelectionRevocationError("synthetic canonical revocation")
        original(**kwargs)

    monkeypatch.setattr(transport_module, "require_candidate_assignment_eligible", gate)
    with pytest.raises(ValueError):
        await review_development_fixture(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(
                lambda _: pytest.fail("revoked canonical identity dispatched")
            ),
        )
    state = ledger.snapshot()
    assert state.spent_usd == state.active_reserved_usd == 0
    if phase == "before_reservation":
        assert state.entries == ()
    else:
        assert len(state.entries) == 1 and state.entries[0].status is CostEntryStatus.RELEASED


@pytest.mark.parametrize("failure", ["canonical", "metadata_hash", "context", "drop_parent"])
async def test_changed_discovery_or_context_refuses_before_reservation(tmp_path, failure):
    prepared = prepared_case()
    discovery = prepared.discovery
    if failure == "canonical":
        discovery = discovery.model_copy(update={"canonical_slug": "other-author/model"})
    elif failure == "metadata_hash":
        discovery = discovery.model_copy(update={"model_metadata_snapshot_sha256": "0" * 64})
    elif failure == "context":
        with pytest.raises(ValueError):
            DevelopmentRoutingContext.from_metadata(review_case().endpoint_snapshot, discovery)
        return
    else:
        discovery = None
    prepared = replace(prepared, discovery=discovery)
    ledger, secrets = local_controls(tmp_path)
    with pytest.raises(ValueError):
        await review_development_fixture(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(
                lambda _: pytest.fail("changed discovery dispatched")
            ),
        )
    assert ledger.snapshot().entries == ()


@pytest.mark.parametrize(
    "change",
    [
        "erase_failure",
        "promote",
        "coerce",
        "unbound_value",
        "wrong_model",
        "wrong_provider",
        "context_basis",
        "context_binding",
    ],
)
def test_serialized_routing_diagnostics_cannot_invent_identity_or_erase_visible_failure(change):
    prepared = prepared_case()
    context = DevelopmentRoutingContext.from_metadata(
        prepared.endpoint_snapshot, prepared.discovery
    )
    payload = response_payload()
    if change == "erase_failure":
        payload["openrouter_metadata"]["strategy"] = "fallback"
    evidence = observe_development_routing(payload, context=context, api_key=SYNTHETIC_CREDENTIAL)
    values = evidence.model_dump(mode="json")
    if change == "erase_failure":
        values["failure_codes"] = []
    elif change in {"promote", "coerce"}:
        values["runtime_authority"] = True if change == "promote" else 0
    elif change == "unbound_value":
        values["returned_model"] = {"status": "UNBOUND", "value": "do-not-retain"}
    elif change == "wrong_model":
        values["returned_model"]["value"] = "other/model"
    elif change == "wrong_provider":
        values["response_provider"]["value"] = "Other Provider"
    elif change == "context_basis":
        values["context"]["identity_basis"] = "REQUEST_ID_ONLY"
    else:
        values["context"]["catalog_identity_binding_sha256"] = "0" * 64
    with pytest.raises(ValidationError):
        DevelopmentRoutingEvidence.model_validate_json(json.dumps(values))
    with pytest.raises(ValidationError):
        DevelopmentRoutingIdentity(status="UNBOUND", value="untrusted")


@pytest.mark.parametrize(
    "change", ["diagnostic", "request", "provider", "snapshot", "no_response_hash", "no_http"]
)
async def test_parent_observation_requires_exact_request_and_refusal_join(tmp_path, change):
    payload = response_payload()
    payload["provider"] = "Unbound Provider"
    result = await observe(tmp_path, prepared_case(), payload)
    values = result.model_dump(mode="json")
    if change == "diagnostic":
        values["diagnostics"] = ["INVALID_RESPONSE"]
    elif change == "no_response_hash":
        values["response_sha256"] = None
    elif change == "no_http":
        values["http_status"] = None
    else:
        field = {
            "request": "exact_model_id",
            "provider": "provider_endpoint",
            "snapshot": "endpoint_snapshot_sha256",
        }[change]
        values["routing_evidence"]["context"][field] = "0" * 64
    with pytest.raises(ValidationError):
        DevelopmentReviewObservation.model_validate_json(json.dumps(values))
    legacy = result.model_dump(mode="json")
    del legacy["routing_evidence"]
    assert (
        DevelopmentReviewObservation.model_validate_json(json.dumps(legacy)).routing_evidence
        is None
    )
