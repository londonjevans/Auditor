"""All development commands retain explicit wait policy without real provider/credential access."""

from __future__ import annotations

import json
import socket
import subprocess
from decimal import Decimal

import httpx
import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as development_cli
from mmaudit.cli import app
from mmaudit.models.development_transport import review_development_fixture
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.development_audit import run_development_audit
from mmaudit.orchestration.development_corpus import run_development_corpus
from mmaudit.orchestration.development_ensemble import run_development_ensemble
from mmaudit.orchestration.development_judgment import run_development_judgment
from tests.development_audit_support import shard_payload
from tests.development_corpus_support import corpus_payload
from tests.development_ensemble_support import ensemble_payload
from tests.development_judgment_support import judgment_payload
from tests.development_review_support import SYNTHETIC_CREDENTIAL, response_payload
from tests.integration.test_development_corpus_audit import inputs as audit_inputs
from tests.integration.test_development_corpus_cli import inputs as manifest_inputs
from tests.integration.test_development_cost_preview import _inputs as preview_inputs
from tests.integration.test_development_ensemble_cli import inputs as ensemble_inputs
from tests.integration.test_development_fixture_review import _inputs as fixture_inputs
from tests.integration.test_development_judgment_cli import inputs as judgment_inputs

RUNNER = CliRunner()
COMMANDS = (
    "preview-cost",
    "review-fixture",
    "audit-corpus",
    "audit-manifest",
    "judge-audit",
    "ensemble-corpus",
)


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("deadline CLI test attempted real network or process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def inputs(tmp_path, command):
    if command == "preview-cost":
        return [*preview_inputs(tmp_path), "--accept-estimate-risk"], None, None, None, 0
    if command == "review-fixture":
        args = fixture_inputs(tmp_path)
        function, payload, count = review_development_fixture, lambda _: response_payload(), 1
    elif command == "audit-corpus":
        args = audit_inputs(tmp_path)
        function, payload, count = run_development_audit, shard_payload, 3
    elif command == "audit-manifest":
        args, ledger, *_ = manifest_inputs(tmp_path)
        return args, ledger, run_development_corpus, corpus_payload, 14
    elif command == "judge-audit":
        args, ledger = judgment_inputs(tmp_path, scored=False)
        return args, ledger, run_development_judgment, judgment_payload, 3
    else:
        args, ledger = ensemble_inputs(tmp_path, scored=False)
        return (
            args,
            ledger,
            run_development_ensemble,
            lambda index: ensemble_payload((index - 1) // 3, (index - 1) % 3 + 1),
            9,
        )
    ledger = AtomicCostLedger.open_existing(
        tmp_path / "synthetic-ledger.json", cap_usd=Decimal("20")
    )
    return args, ledger, function, payload, count


def retained_timeouts(value):
    if isinstance(value, list):
        return [t for item in value for t in retained_timeouts(item)]
    if isinstance(value, dict):
        return [v for k, v in value.items() if k == "request_timeout_seconds"] + [
            t for v in value.values() for t in retained_timeouts(v)
        ]
    return []


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("selected", [None, 360])
def test_every_cli_command_preserves_selected_deadline_and_default_omission(
    tmp_path, monkeypatch, command, selected
):
    args, ledger, function, payload, count = inputs(tmp_path, command)
    calls = []

    def handler(request):
        calls.append(request)
        assert request.extensions["timeout"]["read"] == (180 if selected is None else selected)
        assert b"request_timeout_seconds" not in request.content
        assert SYNTHETIC_CREDENTIAL.encode() not in request.content
        return httpx.Response(200, json=payload(len(calls)))

    if function is not None:

        async def execute(**kwargs):
            return await function(**kwargs, mock_transport=httpx.MockTransport(handler))

        monkeypatch.setattr(development_cli, function.__name__, execute)
    else:

        def forbidden(*_args, **_kwargs):
            pytest.fail("cost preview attempted secret access")

        monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    if selected is not None:
        args += ["--request-timeout-seconds", str(selected)]
    result = RUNNER.invoke(app, args)
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    timeouts = retained_timeouts(data)
    assert (set(timeouts) == {selected}) if selected is not None else not timeouts
    assert data["qualification_eligible"] is data["release_eligible"] is False
    assert len(calls) == count
    assert SYNTHETIC_CREDENTIAL not in result.output
    if ledger is not None:
        assert ledger.snapshot().active_reserved_usd == 0


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("value", ["0", "-1", "1801", "1.5", "not-an-integer"])
def test_invalid_cli_timeout_refuses_before_input_or_credential_access(
    tmp_path, monkeypatch, command, value
):
    args, ledger, _, _, _ = inputs(tmp_path, command)
    before = None if ledger is None else ledger.path.read_bytes()

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid deadline reached input or credential handling")

    for name in ("read_json_evidence", "load_development_corpus", "load_operator_secrets"):
        monkeypatch.setattr(development_cli, name, forbidden)
    result = RUNNER.invoke(app, [*args, "--request-timeout-seconds", value])
    assert result.exit_code == 2
    if ledger is not None:
        assert ledger.path.read_bytes() == before


def test_qualified_run_does_not_accept_development_timeout_option():
    result = RUNNER.invoke(app, ["run", "--request-timeout-seconds", "360"])
    assert result.exit_code != 0 and "No such option" in result.output
