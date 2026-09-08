"""Real local CLI/file handoffs with synthetic metadata and mocked responses only."""

from __future__ import annotations

import socket
import subprocess
from decimal import Decimal

import httpx
import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as development_cli
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.development_audit import DevelopmentAuditObservation
from mmaudit.models.development_review import DevelopmentReviewObservation
from mmaudit.models.development_transport import review_development_fixture
from mmaudit.operator_secrets import load_operator_secrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.development_audit import run_development_audit
from tests.development_audit_support import shard_payload
from tests.development_review_support import (
    FIXTURE_ROOT,
    SYNTHETIC_CREDENTIAL,
    discovery_review_case,
)
from tests.integration.test_development_corpus_audit import inputs as corpus_inputs
from tests.integration.test_development_fixture_review import _inputs as fixture_inputs

RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def no_network_or_commands(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("local routing integration cannot network or execute model output")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)


def canonical_payload(index, *, empty=False):
    payload = shard_payload(index, empty=empty)
    canonical = discovery_review_case().canonical_slug
    payload["model"] = canonical
    router = payload["openrouter_metadata"]
    router["endpoints"]["available"][0]["model"] = canonical
    router["attempts"][0]["model"] = canonical
    del router["is_byok"]
    payload["usage"]["is_byok"] = False
    return payload


@pytest.mark.parametrize(
    "metadata_form", ["discovery_payload", "discovery_file", "constrained_snapshot"]
)
@pytest.mark.parametrize("guarded", [False, True])
def test_fixture_cli_consumes_bound_canonical_identity_without_promoting_serialized_provenance(
    tmp_path, monkeypatch, metadata_form, guarded
):
    arguments = fixture_inputs(tmp_path, metadata_form=metadata_form)
    if guarded:
        target = tmp_path / "ControlB.sol"
        target.write_bytes((FIXTURE_ROOT / "ControlB.sol").read_bytes())
        arguments[arguments.index("--fixture-file") + 1] = str(target)
    loaded = []
    calls = 0

    def loader(path, **kwargs):
        assert kwargs == {"environ": {}, "required": True}
        secrets = load_operator_secrets(path, **kwargs)
        loaded.append(secrets)
        return secrets

    def handler(request):
        nonlocal calls
        calls += 1
        state = AtomicCostLedger.open_existing(
            tmp_path / "synthetic-ledger.json", cap_usd=Decimal("20")
        ).snapshot()
        assert len(state.entries) == 1 and state.entries[0].status is CostEntryStatus.RESERVED
        assert SYNTHETIC_CREDENTIAL.encode() not in request.content
        return httpx.Response(200, json=canonical_payload(calls, empty=guarded))

    async def local_review(**kwargs):
        return await review_development_fixture(
            **kwargs, mock_transport=httpx.MockTransport(handler)
        )

    monkeypatch.setattr(development_cli, "load_operator_secrets", loader)
    monkeypatch.setattr(development_cli, "review_development_fixture", local_review)
    result = RUNNER.invoke(app, arguments)
    accepted = metadata_form != "constrained_snapshot"
    assert result.exit_code == (ExitCode.SUCCESS if accepted else ExitCode.INCOMPLETE), (
        result.output
    )
    observation = DevelopmentReviewObservation.model_validate_json(result.stdout)
    assert observation.transport == "MOCK_HTTP"
    assert (
        observation.audit_complete
        is observation.findings_validated
        is observation.qualification_eligible
        is False
    )
    assert observation.release_eligible is False
    assert calls == 1 and loaded[0].cleared is True
    assert observation.reported_cost_usd == observation.accounted_cost_usd == Decimal("0.01")
    routing = observation.routing_evidence
    assert routing.router_byok == "ABSENT" and routing.usage_byok == "FALSE"
    assert routing.runtime_authority is False
    if accepted:
        assert routing.returned_model.status == "CANONICAL" and routing.failure_codes == ()
        assert (observation.response.findings == ()) is guarded
    else:
        assert observation.status == "INCOMPLETE"
        assert routing.context.identity_basis == "REQUEST_ID_ONLY"
        assert routing.returned_model.status == "UNBOUND" and routing.returned_model.value is None
    assert SYNTHETIC_CREDENTIAL not in result.output


@pytest.mark.parametrize("failure", ["none", "identity", "unknown_cost", "overrun"])
def test_multishard_cli_persists_named_refusals_and_all_costs_at_the_exact_stop_boundary(
    tmp_path, monkeypatch, failure
):
    arguments = corpus_inputs(tmp_path, discovery=True)
    calls = 0
    loaded = []

    def loader(path, **kwargs):
        secrets = load_operator_secrets(path, **kwargs)
        loaded.append(secrets)
        return secrets

    def handler(_request):
        nonlocal calls
        calls += 1
        payload = canonical_payload(calls)
        router = payload["openrouter_metadata"]
        router["summary"] = SYNTHETIC_CREDENTIAL
        router["params"] = {"source": "SYNTHETIC_PRIVATE_CANARY"}
        if calls == 2 and failure != "none":
            router["endpoints"]["available"][0]["model"] = "synthetic/SYNTHETIC_PRIVATE_CANARY"
            if failure == "unknown_cost":
                del payload["usage"]["cost"]
            elif failure == "overrun":
                payload["usage"]["cost"] = 1
        return httpx.Response(200, json=payload)

    async def local_audit(**kwargs):
        return await run_development_audit(**kwargs, mock_transport=httpx.MockTransport(handler))

    monkeypatch.setattr(development_cli, "load_operator_secrets", loader)
    monkeypatch.setattr(development_cli, "run_development_audit", local_audit)
    result = RUNNER.invoke(app, arguments)
    assert result.exit_code == (ExitCode.SUCCESS if failure == "none" else ExitCode.INCOMPLETE), (
        result.output
    )
    observation = DevelopmentAuditObservation.model_validate_json(result.stdout)
    assert observation == DevelopmentAuditObservation.model_validate_json(
        (tmp_path / "run/result.json").read_bytes()
    )
    assert loaded[0].cleared is True
    if failure == "none":
        assert calls == observation.completed_shard_count == 3
        assert observation.total_accounted_cost_usd == Decimal("0.03")
        assert all(item.routing_evidence.failure_codes == () for item in observation.observations)
    else:
        assert calls == 2 and observation.completed_shard_count == 1
        assert observation.unobserved_shard_ids == ("file-02", "file-03")
        assert not (tmp_path / "run/file-03.json").exists()
        last = observation.observations[-1]
        assert last.routing_evidence.failure_codes == ("SELECTED_MODEL",)
        assert last.routing_evidence.selected_endpoints[0].model.value is None
        expected_status = {
            "identity": CostEntryStatus.RECONCILED,
            "unknown_cost": CostEntryStatus.UNCERTAIN_ACCOUNTED,
            "overrun": CostEntryStatus.RESERVATION_OVERRUN,
        }[failure]
        assert last.accounting_status is expected_status
        expected = (
            Decimal("0.01")
            if failure == "identity"
            else Decimal(1)
            if failure == "overrun"
            else last.estimate.estimated_cost_per_attempt_usd
        )
        assert observation.total_accounted_cost_usd == Decimal("0.01") + expected
    for path in (tmp_path / "run").iterdir():
        assert SYNTHETIC_CREDENTIAL not in path.read_text()
        assert "SYNTHETIC_PRIVATE_CANARY" not in path.read_text()
    assert (
        observation.audit_complete
        is observation.qualification_eligible
        is observation.release_eligible
        is False
    )
