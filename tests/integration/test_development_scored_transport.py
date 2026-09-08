"""V2 claims reuse local durable accounting and mock HTTP, never a real provider."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

import mmaudit.models.development_transport as transport_module
from mmaudit.models.development_audit import (
    DevelopmentAuditObservation,
    DevelopmentScoredAuditShardObservation,
)
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from mmaudit.orchestration.development_audit import DevelopmentAuditError, run_development_audit
from tests.development_audit_support import audit_case, shard_payload
from tests.development_benchmark_support import (
    benchmark_truth,
    scored_audit_case,
    scored_file_response,
    scored_payload,
    scored_response,
)
from tests.development_review_support import SYNTHETIC_CREDENTIAL, local_controls


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


@pytest.mark.parametrize("accounting", ["known", "unknown", "overrun"])
async def test_rejected_claim_retains_safe_detail_and_cost_without_completion_credit(
    tmp_path: Path, accounting: str
) -> None:
    """INCOMPLETE_SHARD_CANNOT_GAIN_CREDIT: diagnostics never complete or retry a shard."""

    prepared = scored_audit_case(variant="b")
    ledger, secrets = local_controls(tmp_path)
    responses: list[bytes] = []
    canary = "synthetic-rejected-prose-must-not-be-persisted"

    def handler(request: httpx.Request) -> httpx.Response:
        index = len(responses)
        assert request.content == prepared.shards[index].request_content
        if index == 0:
            value = scored_file_response(1, advisory=True)
        else:
            value = json.loads(
                (
                    Path(__file__).parents[1]
                    / "fixtures/model_responses/development_invalid_advisory_response.json"
                ).read_text()
            )
            value["summary"] = canary
        payload = scored_payload(index + 1, response=value)
        if index == 1 and accounting == "unknown":
            del payload["usage"]["cost"]
        elif index == 1 and accounting == "overrun":
            assert prepared.shards[index].estimate.estimated_cost_per_attempt_usd < 10
            payload["usage"]["cost"] = 10
        response = httpx.Response(200, json=payload)
        responses.append(response.content)
        return response

    output = tmp_path / "bounded-rejection"
    result = await run_development_audit(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=output,
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_truth=benchmark_truth("b"),
    )
    assert len(responses) == len(result.observations) == 2
    assert len(ledger.snapshot().entries) == 2
    assert result.status == "INCOMPLETE" and result.completed_shard_count == 1
    assert result.unobserved_shard_ids == ("file-02", "file-03")
    assert result.active_reserved_usd == 0
    rejected = result.observations[1]
    assert rejected.response is None and rejected.status == "INCOMPLETE"
    detail = rejected.rejection_evidence
    assert detail is not None and detail.stage == "STRUCTURED_OUTPUT"
    assert detail.structured_failure == "SCHEMA_VALIDATION_FAILED"
    assert (
        detail.response_sha256
        == rejected.response_sha256
        == hashlib.sha256(responses[1]).hexdigest()
    )
    assert detail.schema_issues[0].constraint == "ADVISORY_FIELD_MUST_BE_NULL"
    assert detail.schema_issues[0].field == "vulnerability_class"
    assert detail.schema_issues[0].finding_index == 0
    assert (
        rejected.accounting_status
        is {
            "known": CostEntryStatus.RECONCILED,
            "unknown": CostEntryStatus.UNCERTAIN_ACCOUNTED,
            "overrun": CostEntryStatus.RESERVATION_OVERRUN,
        }[accounting]
    )
    assert result.total_accounted_cost_usd == ledger.snapshot().spent_usd
    if accounting == "unknown":
        assert rejected.reported_cost_usd is None
        assert rejected.accounted_cost_usd == rejected.estimate.estimated_cost_per_attempt_usd
        assert "UNKNOWN_COST" in rejected.diagnostics
    elif accounting == "overrun":
        assert rejected.reported_cost_usd == 10 and "COST_OVERRUN" in rejected.diagnostics
    else:
        assert rejected.reported_cost_usd == Decimal("0.01")
    saved = DevelopmentScoredAuditShardObservation.model_validate_json(
        (output / "file-02.json").read_bytes()
    )
    assert saved == rejected
    aggregate = DevelopmentAuditObservation.model_validate_json(
        (output / "result.json").read_bytes()
    )
    assert aggregate == result
    score = json.loads((output / "score.json").read_bytes())
    assert score["observation"]["observations"][1]["rejection_evidence"] == detail.model_dump(
        mode="json"
    )
    assert score["summary"]["quality_scope"] == "INCOMPLETE_OBSERVATIONS"
    assert score["summary"]["first_attempt_shard_completion"]["value"] == 0.333333
    assert score["summary"]["unique_root_recall"]["value"] is None
    for path in output.iterdir():
        assert canary not in path.read_text()
    assert (
        result.audit_complete is result.qualification_eligible is result.release_eligible is False
    )


@pytest.mark.parametrize(
    ("change", "stage", "reason"),
    [
        ("json", "HTTP_BODY", "RESPONSE_JSON"),
        ("encoding", "HTTP_BODY", "CONTENT_ENCODING"),
        ("length", "HTTP_BODY", "CONTENT_LENGTH"),
        ("generation", "COMPLETION_ENVELOPE", "GENERATION_ID"),
        ("usage", "COMPLETION_ENVELOPE", "USAGE"),
        ("object", "COMPLETION_ENVELOPE", "COMPLETION_OBJECT"),
        ("counts", "COMPLETION_ENVELOPE", "TOKEN_COUNTS"),
        ("tools", "COMPLETION_ENVELOPE", "SERVER_TOOLS"),
        ("choices", "COMPLETION_ENVELOPE", "CHOICES"),
        ("index", "COMPLETION_ENVELOPE", "CHOICE_INDEX"),
        ("message", "COMPLETION_ENVELOPE", "MESSAGE"),
        ("origin_file", "SOURCE_SCOPE", "ORIGIN_FILE_SCOPE"),
        ("origin_line", "SOURCE_SCOPE", "ORIGIN_LINE_BOUNDS"),
        ("finding_line", "SOURCE_SCOPE", "FINDING_LINE_BOUNDS"),
    ],
)
async def test_rejection_stages_are_persisted_with_exact_available_response_custody(
    tmp_path: Path, change: str, stage: str, reason: str
) -> None:
    ledger, secrets = local_controls(tmp_path)
    payload = scored_payload(1)
    headers: dict[str, str] = {}
    if change == "encoding":
        headers["content-encoding"] = "unknown-encoding"
    elif change == "length":
        headers["content-length"] = "not-a-length"
    elif change == "object":
        payload["object"] = "untrusted-object-name"
    elif change == "generation":
        payload["id"] = False
    elif change == "usage":
        payload["usage"] = []
    elif change == "counts":
        payload["usage"]["total_tokens"] = False
    elif change == "tools":
        payload["usage"]["server_tool_use_details"] = {"untrusted-tool": 1}
    elif change == "choices":
        payload["choices"] = []
    elif change == "index":
        payload["choices"][0]["index"] = True
    elif change == "message":
        payload["choices"][0]["message"]["content"] = None
    elif change.startswith("origin_") or change == "finding_line":
        value = scored_response()
        finding = value["findings"][0]
        if change == "origin_file":
            finding["root_cause_ref"]["filename"] = "UnknownPrivate.sol"
        elif change == "origin_line":
            finding["root_cause_ref"]["line_end"] = 999
        else:
            finding["line_end"] = 999
        payload = scored_payload(1, response=value)
    material = b"{" if change == "json" else json.dumps(payload).encode()
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, content=material, headers=headers)

    result = await run_development_audit(
        prepared=scored_audit_case(),
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "refusal",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert calls == 1 and result.completed_shard_count == 0
    observation = result.observations[0]
    detail = observation.rejection_evidence
    assert detail is not None and detail.stage == stage and detail.reason == reason
    assert detail.response_sha256 == observation.response_sha256
    assert detail.response_sha256 == (
        None if change in {"encoding", "length"} else hashlib.sha256(material).hexdigest()
    )
    assert "untrusted" not in detail.model_dump_json()
    assert "UnknownPrivate" not in detail.model_dump_json()
    if stage == "SOURCE_SCOPE":
        assert detail.finding_index == 0
    values: dict[str, Any] = observation.model_dump(mode="json")
    values["rejection_evidence"]["response_sha256"] = "a" * 64
    with pytest.raises(ValidationError):
        DevelopmentScoredAuditShardObservation.model_validate_json(json.dumps(values))


@pytest.mark.parametrize("mode", ["secret", "http_error", "timeout"])
async def test_no_schema_detail_is_invented_for_other_refusal_classes(
    tmp_path: Path, mode: str
) -> None:
    ledger, secrets = local_controls(tmp_path)
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if mode == "timeout":
            raise httpx.ReadTimeout("synthetic-private-error-text", request=request)
        if mode == "http_error":
            return httpx.Response(429, json={"error": {"message": SYNTHETIC_CREDENTIAL}})
        value = scored_response(advisory=True)
        value["summary"] = SYNTHETIC_CREDENTIAL
        value["findings"][0]["vulnerability_class"] = "access_control"
        return httpx.Response(200, json=scored_payload(1, response=value))

    result = await run_development_audit(
        prepared=scored_audit_case(),
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "other-refusal",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert calls == 1 and result.completed_shard_count == 0
    observation = result.observations[0]
    assert observation.rejection_evidence is None and observation.response is None
    assert "rejection_evidence" not in observation.model_dump_json()
    assert SYNTHETIC_CREDENTIAL not in result.model_dump_json()
    assert "synthetic-private-error-text" not in result.model_dump_json()
    assert {"secret": "SECRET_OUTPUT", "http_error": "HTTP_ERROR", "timeout": "TIMEOUT"}[mode] in (
        observation.diagnostics
    )
    if mode != "secret":
        assert "UNKNOWN_COST" in observation.diagnostics
        assert observation.accounting_status is CostEntryStatus.UNCERTAIN_ACCOUNTED


@pytest.mark.parametrize("variant", ["a", "b"])
async def test_all_three_actual_requests_enforce_the_same_claim_kind_contract(
    tmp_path: Path, variant: str
) -> None:
    """WIRE_CLIENT_KIND_PARITY: invalid metadata is rejected on every synthetic shard."""

    prepared = scored_audit_case(variant=variant)
    ledger, secrets = local_controls(tmp_path)
    sent: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        index = len(sent)
        sent.append(request.content)
        assert request.content == prepared.shards[index].request_content
        assert (
            ledger.snapshot().active_reserved_usd
            == prepared.shards[index].estimate.estimated_cost_per_attempt_usd
        )
        body = json.loads(request.content)
        schema = body["response_format"]["json_schema"]["schema"]
        validator = Draft202012Validator(schema)
        valid = scored_file_response(index + 1, advisory=variant == "b")
        assert validator.is_valid(valid)
        invalid = scored_file_response(index + 1, advisory=True)
        invalid["findings"][0]["root_cause_ref"] = scored_file_response(index + 1)["findings"][0][
            "root_cause_ref"
        ]
        assert not validator.is_valid(invalid)
        assert body["provider"]["allow_fallbacks"] is False and body["stream"] is False
        return httpx.Response(200, json=scored_payload(index + 1, response=valid))

    output = tmp_path / "aligned-schema"
    result = await run_development_audit(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=output,
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_truth=benchmark_truth(variant),
    )
    assert len(sent) == len(ledger.snapshot().entries) == result.completed_shard_count == 3
    assert result.status == "OBSERVED_ALL_SHARDS" and result.total_accounted_cost_usd == Decimal(
        "0.03"
    )
    assert all(item.rejection_evidence is None for item in result.observations)
    assert all(item.accounting_status is CostEntryStatus.RECONCILED for item in result.observations)
    assert (
        result.audit_complete is result.findings_validated is result.qualification_eligible is False
    )
    assert (
        DevelopmentAuditObservation.model_validate_json((output / "result.json").read_bytes())
        == result
    )


async def test_changed_wire_schema_refuses_before_reservation_or_output(tmp_path: Path) -> None:
    prepared = scored_audit_case()
    body = json.loads(prepared.shards[0].request_content)
    body["response_format"]["json_schema"]["schema"]["$defs"]["DevelopmentScoredFinding"]["anyOf"][
        0
    ]["properties"]["root_cause_ref"] = {}
    altered = replace(
        prepared,
        shards=(
            replace(prepared.shards[0], request_content=json.dumps(body).encode()),
            *prepared.shards[1:],
        ),
    )
    ledger, secrets = local_controls(tmp_path)
    before = ledger.path.read_bytes()
    output = tmp_path / "changed-schema"
    with pytest.raises(DevelopmentAuditError, match="changed"):
        await run_development_audit(
            prepared=altered,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=output,
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(lambda _request: pytest.fail("unexpected HTTP")),
        )
    assert ledger.path.read_bytes() == before and not output.exists()
