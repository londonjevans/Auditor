"""Synthetic mock HTTP and disposable accounting only; no live provider or credentials."""

from __future__ import annotations

import hashlib
import json
import socket
from decimal import Decimal

import httpx
import pytest

import mmaudit.models.development_transport as transport
from mmaudit.benchmark.development import DevelopmentBenchmarkScore
from mmaudit.models.development_audit import (
    DevelopmentAuditObservation,
    DevelopmentScoredAuditShardObservation,
)
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from mmaudit.orchestration.development_audit import run_development_audit
from mmaudit.orchestration.development_comparison import compare_development_score_files
from tests.development_benchmark_support import benchmark_truth, scored_audit_case, scored_payload
from tests.development_review_support import (
    SYNTHETIC_CREDENTIAL,
    local_controls,
    response_payload,
    review_case,
)


@pytest.fixture(autouse=True)
def forbid_real_network(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("telemetry test attempted real network access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.mark.asyncio
@pytest.mark.parametrize("accounting", ["known", "unknown", "overrun"])
@pytest.mark.parametrize(
    "change,diagnostic",
    [
        ("length", "INCOMPLETE_OUTPUT"),
        ("native_length", "INCOMPLETE_OUTPUT"),
        ("native_unknown", "INCOMPLETE_OUTPUT"),
        ("choices", "INVALID_RESPONSE"),
        ("count_type", "INVALID_RESPONSE"),
        ("count_sum", "INVALID_RESPONSE"),
        ("token_allowance", "INVALID_RESPONSE"),
        ("http_error", "HTTP_ERROR"),
        ("identity", "IDENTITY_MISMATCH"),
        ("structured", "INVALID_RESPONSE"),
        ("secret", "SECRET_OUTPUT"),
    ],
)
async def test_failed_second_shard_retains_metadata_cost_and_incomplete_scope_without_retry(
    tmp_path, accounting, change, diagnostic
):
    prepared = scored_audit_case()
    ledger, secrets = local_controls(tmp_path)
    bodies = []
    canary = "synthetic-provider-prose-must-not-be-retained"

    def handler(request):
        index = len(bodies)
        assert index < 2 and request.content == prepared.shards[index].request_content
        data = scored_payload(index + 1)
        data["usage"]["completion_tokens_details"] = {"reasoning_tokens": 80}
        data["choices"][0]["native_finish_reason"] = "end_turn"
        status = 200
        if index == 1:
            data["untrusted_metadata"] = canary
            choice = data["choices"][0]
            if change == "length":
                choice["finish_reason"] = "length"
                choice["native_finish_reason"] = "MAX_TOKENS"
                data["usage"].update(completion_tokens=4096, total_tokens=4496)
                data["usage"]["completion_tokens_details"]["reasoning_tokens"] = 4090
            elif change == "native_length":
                choice["native_finish_reason"] = "max_tokens"
            elif change == "native_unknown":
                choice["native_finish_reason"] = canary
            elif change == "choices":
                data["choices"].append({"index": 1, "finish_reason": "stop", "message": canary})
            elif change == "count_type":
                data["usage"]["completion_tokens"] = True
            elif change == "count_sum":
                data["usage"]["total_tokens"] = 1
            elif change == "token_allowance":
                data["usage"].update(completion_tokens=4097, total_tokens=4497)
            elif change == "http_error":
                status = 429
                data["error"] = {"message": canary}
            elif change == "identity":
                data["model"] = "synthetic/unselected-model"
            elif change == "structured":
                choice["message"]["content"] = json.dumps({"summary": canary})
            else:
                choice["message"]["content"] = SYNTHETIC_CREDENTIAL
            if accounting == "unknown":
                del data["usage"]["cost"]
            elif accounting == "overrun":
                data["usage"]["cost"] = 10
        response = httpx.Response(status, json=data)
        bodies.append(response.content)
        return response

    output = tmp_path / "diagnostic-run"
    result = await run_development_audit(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=output,
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_truth=benchmark_truth(),
    )
    assert len(bodies) == len(result.observations) == len(ledger.snapshot().entries) == 2
    assert result.status == "INCOMPLETE" and result.completed_shard_count == 1
    assert result.unobserved_shard_ids == ("file-02", "file-03")
    rejected = result.observations[1]
    assert rejected.response is None and diagnostic in rejected.diagnostics
    telemetry = rejected.completion_telemetry
    assert telemetry is not None
    assert (
        telemetry.response_sha256
        == rejected.response_sha256
        == hashlib.sha256(bodies[1]).hexdigest()
    )
    assert telemetry.prompt_tokens.value == 400
    if change == "length":
        assert (
            telemetry.finish_reason == "length" and telemetry.native_finish_reason == "max_tokens"
        )
        assert (
            telemetry.completion_tokens.value == 4096 and telemetry.reasoning_tokens.value == 4090
        )
    elif change == "choices":
        assert telemetry.finish_reason_state == telemetry.native_finish_reason_state == "AMBIGUOUS"
    elif change == "count_type":
        assert (
            telemetry.completion_tokens.state == "INVALID"
            and telemetry.completion_tokens.value is None
        )
    elif change == "count_sum":
        assert (
            telemetry.total_tokens.value == 1 and telemetry.token_sum_consistency == "INCONSISTENT"
        )
    elif change == "token_allowance":
        assert telemetry.completion_tokens.value == 4097
    elif change == "native_unknown":
        assert (
            telemetry.native_finish_reason is None
            and telemetry.native_finish_reason_state == "UNRECOGNIZED"
        )
    assert (
        rejected.accounting_status
        is {
            "known": CostEntryStatus.RECONCILED,
            "unknown": CostEntryStatus.UNCERTAIN_ACCOUNTED,
            "overrun": CostEntryStatus.RESERVATION_OVERRUN,
        }[accounting]
    )
    assert result.total_accounted_cost_usd == ledger.snapshot().spent_usd
    assert result.active_reserved_usd == 0
    if accounting == "unknown":
        assert rejected.reported_cost_usd is None
        assert rejected.accounted_cost_usd == rejected.estimate.estimated_cost_per_attempt_usd
    else:
        assert rejected.reported_cost_usd == (10 if accounting == "overrun" else Decimal("0.01"))
    assert (
        DevelopmentScoredAuditShardObservation.model_validate_json(
            (output / "file-02.json").read_bytes()
        )
        == rejected
    )
    assert (
        DevelopmentAuditObservation.model_validate_json((output / "result.json").read_bytes())
        == result
    )
    score = DevelopmentBenchmarkScore.model_validate_json((output / "score.json").read_bytes())
    assert score.observation.observations[1].completion_telemetry == telemetry
    assert (
        score.summary.quality_scope == "INCOMPLETE_OBSERVATIONS"
        and score.summary.unique_root_recall.value is None
    )
    assert score.summary.first_attempt_shard_completion.value == 0.333333
    for path in output.iterdir():
        assert canary not in path.read_text() and SYNTHETIC_CREDENTIAL not in path.read_text()
    assert (
        result.audit_complete is result.qualification_eligible is result.release_eligible is False
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        "normal",
        "reasoning_missing",
        "reasoning_invalid",
        "reasoning_inconsistent",
        "projection_failure",
    ],
)
async def test_telemetry_does_not_change_existing_success_admission(tmp_path, monkeypatch, change):
    prepared = scored_audit_case()
    ledger, secrets = local_controls(tmp_path)
    bodies = []
    if change == "projection_failure":

        def broken(*_args, **_kwargs):
            raise ValueError("synthetic-secret-diagnostic-error")

        monkeypatch.setattr(transport, "project_development_completion_telemetry", broken)

    def handler(request):
        index = len(bodies)
        assert request.content == prepared.shards[index].request_content
        data = scored_payload(index + 1)
        if change != "reasoning_missing":
            data["usage"]["completion_tokens_details"] = {
                "reasoning_tokens": {
                    "reasoning_invalid": "synthetic-private-count",
                    "reasoning_inconsistent": 101,
                }.get(change, 80)
            }
        response = httpx.Response(200, json=data)
        bodies.append(response.content)
        return response

    result = await run_development_audit(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "complete",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_truth=benchmark_truth(),
    )
    assert len(bodies) == result.completed_shard_count == 3
    assert result.total_accounted_cost_usd == Decimal("0.03")
    assert all(item.status == "OBSERVED" and not item.diagnostics for item in result.observations)
    for index, item in enumerate(result.observations):
        metadata = item.completion_telemetry
        if change == "projection_failure":
            assert metadata is None and "completion_telemetry" not in item.model_dump_json()
            continue
        assert metadata is not None and metadata.finish_reason == "stop"
        assert metadata.response_sha256 == hashlib.sha256(bodies[index]).hexdigest()
        assert metadata.reasoning_tokens.state == {
            "reasoning_missing": "NOT_REPORTED",
            "reasoning_invalid": "INVALID",
        }.get(change, "REPORTED")
        if change == "reasoning_inconsistent":
            assert (
                metadata.reasoning_tokens.value == 101
                and metadata.reasoning_subset_consistency == "INCONSISTENT"
            )
    assert "synthetic-private-count" not in result.model_dump_json()
    assert "synthetic-secret-diagnostic-error" not in result.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change", ["timeout", "json", "duplicate", "nonfinite", "encoding", "length", "top_level"]
)
async def test_unobserved_or_unparseable_body_cannot_acquire_telemetry(tmp_path, change):
    ledger, secrets = local_controls(tmp_path)
    calls = 0

    def handler(_request):
        nonlocal calls
        calls += 1
        if change == "timeout":
            raise httpx.ReadTimeout("synthetic-private-timeout")
        if change == "json":
            return httpx.Response(200, content=b"{unparsed")
        if change == "duplicate":
            return httpx.Response(200, content=b'{"usage":{},"usage":{}}')
        if change == "nonfinite":
            return httpx.Response(200, content=b'{"usage":{"completion_tokens":NaN}}')
        if change == "encoding":
            return httpx.Response(200, content=b"bounded", headers={"content-encoding": "gzip"})
        if change == "length":
            return httpx.Response(200, content=b"bounded", headers={"content-length": "1000001"})
        return httpx.Response(200, json=[])

    result = await run_development_audit(
        prepared=scored_audit_case(),
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "no-body",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_truth=benchmark_truth(),
    )
    assert calls == 1 and result.status == "INCOMPLETE" and result.completed_shard_count == 0
    assert result.observations[0].completion_telemetry is None
    assert "completion_telemetry" not in result.model_dump_json()
    assert result.observations[0].accounting_status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert result.total_accounted_cost_usd > 0


@pytest.mark.asyncio
@pytest.mark.parametrize("finish", ["stop", "length"])
async def test_legacy_fixture_transport_shares_bounded_metadata_without_a_new_request(
    tmp_path, finish
):
    ledger, secrets = local_controls(tmp_path)
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        assert request.content == review_case().request_content
        data = response_payload()
        data["choices"][0]["finish_reason"] = finish
        data["usage"]["completion_tokens_details"] = {"reasoning_tokens": 50}
        return httpx.Response(200, json=data)

    result = await transport.review_development_fixture(
        prepared=review_case(),
        ledger=ledger,
        operator_secrets=secrets,
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert calls == 1 and result.completion_telemetry is not None
    assert result.completion_telemetry.finish_reason == finish
    assert result.completion_telemetry.reasoning_tokens.value == 50
    assert result.status == ("OBSERVED" if finish == "stop" else "INCOMPLETE")
    assert result.accounted_cost_usd == Decimal("0.01")


@pytest.mark.asyncio
async def test_retained_telemetry_survives_exact_score_file_comparison(tmp_path):
    score_files = []
    calls = []
    for label in ("telemetry-run-a", "telemetry-run-b"):
        root = tmp_path / label
        root.mkdir(mode=0o700)
        ledger, secrets = local_controls(root)
        prepared = scored_audit_case(run_id=label)
        count = 0

        def handler(request, *, run_label=label):
            nonlocal count
            count += 1
            calls.append(request.content)
            data = scored_payload(count)
            data["id"] = f"gen-{run_label}-{count}"
            data["usage"]["completion_tokens_details"] = {"reasoning_tokens": 80}
            return httpx.Response(200, json=data)

        await run_development_audit(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=root / "result",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
            benchmark_truth=benchmark_truth(),
        )
        score_files.append(root / "result" / "score.json")
    before = tuple(path.read_bytes() for path in score_files)
    result = compare_development_score_files(
        score_files=tuple(score_files), output_file=tmp_path / "comparison.json"
    )
    assert len(calls) == 6 and result.union.sum_reported_actual_cost_usd == Decimal("0.06")
    assert before == tuple(path.read_bytes() for path in score_files)
    assert result == type(result).model_validate_json((tmp_path / "comparison.json").read_bytes())
    for score in result.scores:
        assert all(
            item.completion_telemetry is not None
            and item.completion_telemetry.reasoning_tokens.value == 80
            for item in score.observation.observations
        )
    assert result.lineage_independence == "NOT_ESTABLISHED"
    assert result.superiority == "NOT_EVALUATED"
