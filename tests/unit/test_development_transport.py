from __future__ import annotations

import asyncio
import hashlib
import json
import socket
from collections.abc import AsyncIterator
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

import mmaudit.models.development_transport as transport_module
from mmaudit.models.candidate_revocation import CandidateSelectionRevocationError
from mmaudit.models.development_review import (
    DevelopmentReviewObservation,
    prepare_development_review,
)
from mmaudit.models.development_transport import (
    DEVELOPMENT_COMPLETION_URL,
    MAX_DEVELOPMENT_RESPONSE_BYTES,
    DevelopmentTransportError,
    review_development_fixture,
)
from mmaudit.models.openrouter import OpenRouterStructuredRequestCostPreview
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus, CostLedgerError
from tests.development_review_support import (
    SYNTHETIC_CREDENTIAL,
    discovery_review_case,
    local_controls,
    response_payload,
    review_case,
)


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("development regressions must never access the network")

    monkeypatch.setattr(socket.socket, "connect", forbidden)


async def test_dispatch_has_exact_estimated_bytes_and_durable_reservation_before_http(
    tmp_path: Path,
) -> None:
    prepared = review_case()
    ledger, secrets = local_controls(tmp_path)
    seen: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        state = AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("20")).snapshot()
        assert state.entries[0].status is CostEntryStatus.RESERVED
        assert state.active_reserved_usd == prepared.estimate.estimated_cost_per_attempt_usd
        assert str(request.url) == DEVELOPMENT_COMPLETION_URL
        assert request.method == "POST"
        assert request.headers["authorization"] == f"Bearer {SYNTHETIC_CREDENTIAL}"
        assert request.headers["x-openrouter-metadata"] == "enabled"
        assert request.headers["accept-encoding"] == "identity"
        assert request.content == prepared.request_content
        assert hashlib.sha256(request.content).hexdigest() == prepared.estimate.request_sha256
        seen.append(request.content)
        return httpx.Response(200, json=response_payload())

    result = await review_development_fixture(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert len(seen) == 1
    assert result.status == "OBSERVED"
    assert result.transport == "MOCK_HTTP"
    assert result.response is not None
    assert len(result.response.findings) == 1
    assert result.reported_cost_usd == result.accounted_cost_usd == Decimal("0.01")
    assert ledger.snapshot().spent_usd == Decimal("0.01")
    assert ledger.snapshot().active_reserved_usd == 0
    assert result.audit_complete is result.findings_validated is result.release_eligible is False
    assert DevelopmentReviewObservation.model_validate_json(result.model_dump_json()) == result
    assert SYNTHETIC_CREDENTIAL not in result.model_dump_json()
    assert "abstract contract ControlA" not in result.model_dump_json()
    with pytest.raises(ValidationError):
        OpenRouterStructuredRequestCostPreview.model_validate_json(result.model_dump_json())


@pytest.mark.parametrize("change", ("drop_parent", "parent_hash", "model_efforts", "snapshot"))
async def test_metadata_custody_is_revalidated_before_any_reservation_or_dispatch(
    tmp_path: Path, change: str
) -> None:
    baseline = review_case()
    discovery = discovery_review_case()
    prepared = prepare_development_review(
        policy=baseline.estimate.policy,
        endpoint_snapshot=discovery,
        source_filename=baseline.source_filename,
        source_content=baseline.source_content,
        request_id="metadata-custody",
    )
    assert prepared.discovery is not None
    if change == "drop_parent":
        prepared = replace(prepared, discovery=None)
    elif change == "parent_hash":
        altered = prepared.discovery.model_copy(update={"model_metadata_snapshot_sha256": "0" * 64})
        prepared = replace(prepared, discovery=altered)
    elif change == "model_efforts":
        altered = prepared.discovery.model_copy(
            update={"model_supported_reasoning_efforts": ("low",)}
        )
        prepared = replace(prepared, discovery=altered)
    else:
        prepared = replace(prepared, endpoint_snapshot=baseline.endpoint_snapshot)
    ledger, secrets = local_controls(tmp_path)
    before = ledger.path.read_bytes()

    def forbidden(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("changed metadata must not reach dispatch")

    with pytest.raises(ValueError):
        await review_development_fixture(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(forbidden),
        )
    assert ledger.path.read_bytes() == before
    assert ledger.snapshot().entries == ()


async def test_guarded_fixture_allows_empty_observations_without_claiming_security(
    tmp_path: Path,
) -> None:
    ledger, secrets = local_controls(tmp_path)
    payload = response_payload()
    payload["choices"][0]["message"]["content"] = json.dumps(
        {
            "summary": "No missing administrator guard observed in this local fixture.",
            "findings": [],
        }
    )
    result = await review_development_fixture(
        prepared=review_case(filename="ControlB.sol"),
        ledger=ledger,
        operator_secrets=secrets,
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload)),
    )
    assert result.status == "OBSERVED"
    assert result.response is not None and result.response.findings == ()
    assert result.audit_complete is False


@pytest.mark.parametrize(
    "change",
    (
        "model",
        "provider",
        "metadata_missing",
        "strategy",
        "router_retry",
        "numeric_attempt",
        "selected_model",
        "selected_provider",
        "selected_missing",
        "byok",
        "pipeline",
        "attempts",
        "tool_calls",
        "refusal",
        "truncated",
        "native_truncated",
        "bad_lines",
        "extra_field",
        "wrong_counts",
        "bool_count",
        "too_many_tokens",
        "generation_header",
        "key_echo",
        "secret_like_output",
    ),
)
async def test_invalid_responses_are_incomplete_but_their_known_cost_is_never_erased(
    tmp_path: Path, change: str
) -> None:
    ledger, secrets = local_controls(tmp_path)
    payload = response_payload()
    router = payload["openrouter_metadata"]
    message = payload["choices"][0]["message"]
    headers: dict[str, str] = {}
    if change == "model":
        payload["model"] = "synthetic/wrong"
    elif change == "provider":
        payload["provider"] = "Wrong Provider"
    elif change == "metadata_missing":
        del payload["openrouter_metadata"]
    elif change == "strategy":
        router["strategy"] = "fallback"
    elif change in {"router_retry", "numeric_attempt"}:
        router["attempt"] = 2 if change == "router_retry" else True
    elif change == "selected_model":
        router["endpoints"]["available"][0]["model"] = "synthetic/wrong"
    elif change == "selected_provider":
        router["endpoints"]["available"][0]["provider"] = "Wrong Provider"
    elif change == "selected_missing":
        router["endpoints"]["available"][0]["selected"] = False
    elif change == "byok":
        router["is_byok"] = True
    elif change == "pipeline":
        router["pipeline"] = [{"type": "server_tools", "name": "synthetic-disabled"}]
    elif change == "attempts":
        router["attempts"] *= 2
    elif change == "tool_calls":
        message["tool_calls"] = [{"name": "synthetic-disabled"}]
    elif change == "refusal":
        message["refusal"] = "synthetic refusal"
    elif change == "truncated":
        payload["choices"][0]["finish_reason"] = "length"
    elif change == "native_truncated":
        payload["choices"][0]["native_finish_reason"] = "MAX_TOKENS"
    elif change in {"bad_lines", "extra_field", "key_echo", "secret_like_output"}:
        value = json.loads(message["content"])
        if change == "bad_lines":
            value["findings"][0]["line_end"] = 999
        elif change == "extra_field":
            value["commands"] = ["synthetic-disabled"]
        elif change == "key_echo":
            value["summary"] = SYNTHETIC_CREDENTIAL
        else:
            value["summary"] = "sk-or-v1-" + "synthetic-fixture-only-" * 2
        message["content"] = json.dumps(value)
    elif change == "wrong_counts":
        payload["usage"]["total_tokens"] = 1
    elif change == "bool_count":
        payload["usage"]["prompt_tokens"] = True
    elif change == "too_many_tokens":
        payload["usage"].update(completion_tokens=10000, total_tokens=10400)
    else:
        headers["x-generation-id"] = "gen-wrong"
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=payload, headers=headers)

    result = await review_development_fixture(
        prepared=review_case(attempts=3),
        ledger=ledger,
        operator_secrets=secrets,
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert calls == 1  # No automatic retry, even when the policy permits more explicit attempts.
    assert result.status == "INCOMPLETE"
    assert result.response is None
    assert result.diagnostics
    assert result.accounting_status is CostEntryStatus.RECONCILED
    assert result.accounted_cost_usd == ledger.snapshot().spent_usd == Decimal("0.01")
    assert SYNTHETIC_CREDENTIAL not in result.model_dump_json()


@pytest.mark.parametrize(
    "failure",
    (
        "timeout",
        "disconnect",
        "malformed",
        "duplicate",
        "missing_cost",
        "negative_cost",
        "float_overflow",
        "compression",
        "oversize",
        "redirect",
    ),
)
async def test_unknown_charges_stop_retries_and_remain_blocking_after_restart(
    tmp_path: Path, failure: str
) -> None:
    ledger, secrets = local_controls(tmp_path)
    prepared = review_case(attempts=2)
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if failure == "timeout":
            raise httpx.ReadTimeout("synthetic transport timeout", request=request)
        if failure == "disconnect":
            raise httpx.ReadError("synthetic disconnected stream", request=request)
        if failure == "malformed":
            return httpx.Response(200, content=b"not-json")
        if failure == "duplicate":
            return httpx.Response(200, content=b'{"usage":{"cost":0.01,"cost":0.02}}')
        if failure == "float_overflow":
            return httpx.Response(200, content=b'{"usage":{"cost":1e999999}}')
        if failure == "oversize":
            return httpx.Response(200, content=b"x" * (MAX_DEVELOPMENT_RESPONSE_BYTES + 1))
        if failure == "redirect":
            return httpx.Response(
                307, headers={"location": "https://synthetic.invalid/never-contact"}
            )
        payload = response_payload()
        if failure == "missing_cost":
            del payload["usage"]["cost"]
        elif failure == "negative_cost":
            payload["usage"]["cost"] = -1
        else:
            # Avoid HTTPX decoding the fixture: stream carries intentionally unsupported encoding.
            return httpx.Response(
                200, headers={"content-encoding": "synthetic-encoding"}, content=b"{}"
            )
        return httpx.Response(200, json=payload)

    result = await review_development_fixture(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert result.status == "INCOMPLETE"
    assert "UNKNOWN_COST" in result.diagnostics
    assert result.accounting_status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert result.reported_cost_usd is None
    assert ledger.snapshot().spent_usd == prepared.estimate.estimated_cost_per_attempt_usd
    reopened = AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("20"))
    with pytest.raises(CostLedgerError, match="settled"):
        await review_development_fixture(
            prepared=prepared,
            ledger=reopened,
            operator_secrets=secrets,
            attempt=2,
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    assert calls == 1


@pytest.mark.parametrize("actual", ("0.5", "21", "0.010000000000000001"))
async def test_exact_wire_decimal_cost_and_overruns_are_persisted(
    tmp_path: Path, actual: str
) -> None:
    ledger, secrets = local_controls(tmp_path)
    payload = json.dumps(response_payload()).replace('"cost": 0.01', f'"cost": {actual}').encode()
    result = await review_development_fixture(
        prepared=review_case(),
        ledger=ledger,
        operator_secrets=secrets,
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(lambda _request: httpx.Response(200, content=payload)),
    )
    assert ledger.snapshot().spent_usd == result.reported_cost_usd == Decimal(actual)
    if Decimal(actual) > result.estimate.estimated_cost_per_attempt_usd:
        assert result.status == "INCOMPLETE"
        assert "COST_OVERRUN" in result.diagnostics
        assert ledger.snapshot().has_reservation_overrun is True
        assert result.response is None
    else:
        assert result.status == "OBSERVED"


async def test_http_error_still_accounts_known_cost_and_never_follows_or_retries(
    tmp_path: Path,
) -> None:
    ledger, secrets = local_controls(tmp_path)
    result = await review_development_fixture(
        prepared=review_case(attempts=3),
        ledger=ledger,
        operator_secrets=secrets,
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                429, json={"usage": {"cost": 0.01}, "error": {"message": SYNTHETIC_CREDENTIAL}}
            )
        ),
    )
    assert result.status == "INCOMPLETE" and "HTTP_ERROR" in result.diagnostics
    assert ledger.snapshot().spent_usd == Decimal("0.01")
    assert len(ledger.snapshot().entries) == 1
    assert SYNTHETIC_CREDENTIAL not in result.model_dump_json()


@pytest.mark.parametrize("change", ("body", "consent", "numeric_consent", "attempt", "credentials"))
async def test_preflight_refusals_never_reserve_or_dispatch(tmp_path: Path, change: str) -> None:
    ledger, secrets = local_controls(tmp_path)
    prepared = review_case()
    kwargs: dict[str, Any] = {"allow_code_egress": True}
    if change == "body":
        prepared = replace(prepared, request_content=prepared.request_content + b" ")
    elif change in {"consent", "numeric_consent"}:
        kwargs["allow_code_egress"] = False if change == "consent" else 1
    elif change == "attempt":
        kwargs["attempt"] = 2
    else:
        secrets.clear()

    def handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("invalid preflight must never send")

    with pytest.raises((DevelopmentTransportError, ValueError)):
        await review_development_fixture(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            mock_transport=httpx.MockTransport(handler),
            **kwargs,
        )
    assert ledger.snapshot().entries == ()


async def test_revocation_is_rechecked_after_reservation_and_before_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = review_case()
    ledger, secrets = local_controls(tmp_path)
    original = transport_module.require_candidate_assignment_eligible
    calls = 0

    def gate(**kwargs: Any) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise CandidateSelectionRevocationError("synthetic late revocation")
        original(**kwargs)

    monkeypatch.setattr(transport_module, "require_candidate_assignment_eligible", gate)

    def handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("revoked request must not dispatch")

    with pytest.raises(DevelopmentTransportError):
        await review_development_fixture(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    state = ledger.snapshot()
    assert state.spent_usd == state.active_reserved_usd == 0
    assert state.entries[0].status is CostEntryStatus.RELEASED


async def test_cancellation_after_dispatch_durably_accounts_unknown_usage(tmp_path: Path) -> None:
    ledger, secrets = local_controls(tmp_path)
    prepared = review_case(attempts=2)
    entered = asyncio.Event()
    never = asyncio.Event()

    async def handler(_request: httpx.Request) -> httpx.Response:
        entered.set()
        await never.wait()
        raise AssertionError("cancelled fixture cannot produce a response")

    task = asyncio.create_task(
        review_development_fixture(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    )
    await asyncio.wait_for(entered.wait(), timeout=5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    state = ledger.snapshot()
    assert state.entries[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert state.active_reserved_usd == 0
    assert state.spent_usd == prepared.estimate.estimated_cost_per_attempt_usd


async def test_explicit_retry_counts_cost_without_automatic_or_duplicate_calls(
    tmp_path: Path,
) -> None:
    ledger, secrets = local_controls(tmp_path)
    prepared = review_case(attempts=2)
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=response_payload())

    for attempt in (1, 2):
        result = await review_development_fixture(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            allow_code_egress=True,
            attempt=attempt,
            mock_transport=httpx.MockTransport(handler),
        )
        assert result.attempt == attempt
    assert calls == 2 and ledger.snapshot().spent_usd == Decimal("0.02")
    with pytest.raises(CostLedgerError):
        await review_development_fixture(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            allow_code_egress=True,
            attempt=2,
            mock_transport=httpx.MockTransport(handler),
        )
    assert calls == 2


@pytest.mark.parametrize("failure", ("broken", "oversized", "unexpected"))
async def test_stream_failures_close_response_and_preserve_uncertain_cost(
    tmp_path: Path, failure: str
) -> None:
    ledger, secrets = local_controls(tmp_path)
    closed: list[bool] = []

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b'{"usage":'
            if failure == "broken":
                raise httpx.ReadError(SYNTHETIC_CREDENTIAL)
            if failure == "unexpected":
                raise RuntimeError(SYNTHETIC_CREDENTIAL)
            yield b" " * MAX_DEVELOPMENT_RESPONSE_BYTES

        async def aclose(self) -> None:
            closed.append(True)

    result = await review_development_fixture(
        prepared=review_case(),
        ledger=ledger,
        operator_secrets=secrets,
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(lambda _request: httpx.Response(200, stream=Stream())),
    )
    assert closed
    assert result.status == "INCOMPLETE"
    assert result.accounting_status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert SYNTHETIC_CREDENTIAL not in result.model_dump_json()


async def test_total_deadline_stops_stalled_transport_and_accounts_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger, secrets = local_controls(tmp_path)
    entered = False

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal entered
        entered = True
        await asyncio.Event().wait()
        raise AssertionError("stalled transport cannot complete")

    monkeypatch.setattr(transport_module, "DEVELOPMENT_ATTEMPT_TIMEOUT_SECONDS", 0.02)
    result = await asyncio.wait_for(
        review_development_fixture(
            prepared=review_case(),
            ledger=ledger,
            operator_secrets=secrets,
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        ),
        timeout=5,
    )
    assert entered
    assert result.status == "INCOMPLETE"
    assert set(result.diagnostics) == {"TIMEOUT", "UNKNOWN_COST"}
    assert ledger.snapshot().active_reserved_usd == 0


async def test_concurrent_request_cannot_dispatch_while_first_cost_is_unsettled(
    tmp_path: Path,
) -> None:
    ledger, secrets = local_controls(tmp_path)
    first_entered, finish = asyncio.Event(), asyncio.Event()
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        first_entered.set()
        await finish.wait()
        return httpx.Response(200, json=response_payload())

    first = asyncio.create_task(
        review_development_fixture(
            prepared=review_case(attempts=2),
            ledger=ledger,
            operator_secrets=secrets,
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    )
    await asyncio.wait_for(first_entered.wait(), timeout=5)
    try:
        with pytest.raises(CostLedgerError, match="settled"):
            await review_development_fixture(
                prepared=review_case(attempts=2),
                ledger=ledger,
                operator_secrets=secrets,
                allow_code_egress=True,
                attempt=2,
                mock_transport=httpx.MockTransport(handler),
            )
        assert calls == 1
    finally:
        finish.set()
        await first


async def test_ledger_persistence_failure_does_not_release_the_inflight_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger, secrets = local_controls(tmp_path)

    def broken_reconcile(*_args: object, **_kwargs: object) -> None:
        raise CostLedgerError("synthetic reconciliation persistence failure")

    monkeypatch.setattr(ledger, "reconcile", broken_reconcile)
    with pytest.raises(CostLedgerError):
        await review_development_fixture(
            prepared=review_case(),
            ledger=ledger,
            operator_secrets=secrets,
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(
                lambda _request: httpx.Response(200, json=response_payload())
            ),
        )
    assert ledger.snapshot().entries[0].status is CostEntryStatus.RESERVED
    assert ledger.snapshot().active_reserved_usd > 0
    assert ledger.snapshot().spent_usd == 0  # Unknown pending cost, not a pass or refund.


@pytest.mark.parametrize(
    "marker", ("findings_validated", "audit_complete", "qualification_eligible", "release_eligible")
)
@pytest.mark.parametrize("value", (True, 0, "false"))
async def test_observation_markers_refuse_authority_or_numeric_boolean_coercion(
    tmp_path: Path, marker: str, value: object
) -> None:
    ledger, secrets = local_controls(tmp_path)
    observation = await review_development_fixture(
        prepared=review_case(),
        ledger=ledger,
        operator_secrets=secrets,
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, json=response_payload())
        ),
    )
    payload = json.loads(observation.model_dump_json())
    payload[marker] = value
    with pytest.raises(ValidationError):
        DevelopmentReviewObservation.model_validate_json(json.dumps(payload))
