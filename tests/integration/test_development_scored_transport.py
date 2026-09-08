"""V2 claims reuse local durable accounting and mock HTTP, never a real provider."""

from __future__ import annotations

import json
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import httpx
import pytest

import mmaudit.models.development_transport as transport_module
from mmaudit.models.development_audit import (
    DevelopmentAuditObservation,
    DevelopmentScoredAuditShardObservation,
)
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from mmaudit.orchestration.development_audit import DevelopmentAuditError, run_development_audit
from tests.development_audit_support import audit_case, shard_payload
from tests.development_benchmark_support import scored_audit_case, scored_payload, scored_response
from tests.development_review_support import local_controls


@pytest.mark.asyncio
@pytest.mark.parametrize("variant", ["a", "b"])
async def test_v2_all_shards_retain_exact_bytes_costs_and_owned_elapsed_time(
    tmp_path: Path, variant: str
) -> None:
    prepared = scored_audit_case(variant=variant)
    ledger, secrets = local_controls(tmp_path)
    requests: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        index = len(requests)
        assert ledger.snapshot().active_reserved_usd > 0
        assert request.content == prepared.shards[index].request_content
        requests.append(request.content)
        body = json.loads(request.content)
        assert body["response_format"]["json_schema"]["name"].endswith("_v2")
        return httpx.Response(
            200,
            json=scored_payload(index + 1, response=scored_response(advisory=variant == "b")),
        )

    output = tmp_path / "scored"
    result = await run_development_audit(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=output,
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert len(requests) == result.completed_shard_count == 3
    assert result.status == "OBSERVED_ALL_SHARDS"
    assert result.total_accounted_cost_usd == Decimal("0.03")
    assert result.active_reserved_usd == 0
    for observation in result.observations:
        assert type(observation) is DevelopmentScoredAuditShardObservation
        assert observation.schema_version == "2.0"
        assert 0 <= observation.elapsed_seconds <= result.elapsed_seconds
        assert observation.response is not None
        assert observation.response.schema_version == "2.0"
        assert observation.findings_validated is False
        assert observation.audit_complete is False
        if variant == "b":
            assert all(
                finding.violated_invariant is None for finding in observation.response.findings
            )
    assert (
        DevelopmentAuditObservation.model_validate_json((output / "result.json").read_bytes())
        == result
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change", ["legacy_response", "outside_origin", "outside_line", "unknown_cost"]
)
async def test_v2_incomplete_shard_retains_cost_and_stops_without_retry(
    tmp_path: Path, change: str
) -> None:
    prepared = scored_audit_case()
    ledger, secrets = local_controls(tmp_path)
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        response = scored_response()
        if change == "outside_origin":
            response["findings"][0]["root_cause_ref"]["filename"] = "Unknown.sol"
        elif change == "outside_line":
            response["findings"][0]["root_cause_ref"]["line_end"] = 66
        payload = (
            shard_payload(1)
            if change == "legacy_response"
            else scored_payload(1, response=response)
        )
        if change == "unknown_cost":
            del payload["usage"]["cost"]
        return httpx.Response(200, json=payload)

    result = await run_development_audit(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "incomplete",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert calls == 1
    assert result.status == "INCOMPLETE"
    assert result.completed_shard_count == 0
    assert result.unobserved_shard_ids == ("file-01", "file-02", "file-03")
    assert len(result.observations) == 1
    assert type(result.observations[0]) is DevelopmentScoredAuditShardObservation
    assert result.observations[0].response is None
    assert result.total_accounted_cost_usd > 0
    assert result.accounting[0].status is (
        CostEntryStatus.UNCERTAIN_ACCOUNTED
        if change == "unknown_cost"
        else CostEntryStatus.RECONCILED
    )


@pytest.mark.asyncio
async def test_version_drift_refuses_before_any_reservation_or_output(tmp_path: Path) -> None:
    prepared = scored_audit_case()
    changed = replace(
        prepared,
        shards=(replace(prepared.shards[0], schema_version="1.0"), *prepared.shards[1:]),
    )
    ledger, secrets = local_controls(tmp_path)
    output = tmp_path / "refused"
    with pytest.raises(DevelopmentAuditError, match="changed"):
        await run_development_audit(
            prepared=changed,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=output,
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(lambda _request: pytest.fail("unexpected HTTP")),
        )
    assert not ledger.snapshot().entries
    assert not output.exists()


@pytest.mark.asyncio
async def test_v1_never_implicitly_decodes_the_v2_contract(tmp_path: Path) -> None:
    ledger, secrets = local_controls(tmp_path)
    result = await run_development_audit(
        prepared=audit_case(),
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "legacy-refusal",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, json=scored_payload(1))
        ),
    )
    assert result.status == "INCOMPLETE"
    assert result.total_accounted_cost_usd == Decimal("0.01")
    assert result.completed_shard_count == 0
    assert "elapsed_seconds" not in type(result.observations[0]).model_fields


@pytest.mark.asyncio
async def test_invalid_owned_clock_cannot_pass_or_erase_the_settled_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = iter([10.0, 9.0])
    monkeypatch.setattr(transport_module, "_DEVELOPMENT_MONOTONIC", lambda: next(values))
    ledger, secrets = local_controls(tmp_path)
    result = await run_development_audit(
        prepared=scored_audit_case(),
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "invalid-clock",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, json=scored_payload(1))
        ),
    )
    assert result.status == "INCOMPLETE"
    assert result.stop_reason == "LOCAL_FAILURE"
    assert result.observations == ()
    assert result.total_accounted_cost_usd == Decimal("0.01")
    assert result.active_reserved_usd == 0
