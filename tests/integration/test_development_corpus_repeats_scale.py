"""Maximum real local repeat execution; synthetic HTTP does not establish audit or truth quality."""

import hashlib
import json
import socket
import stat
import subprocess
import sys
import time
from decimal import Decimal

import httpx
import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as cli
import mmaudit.orchestration.development_corpus_repeats as repeats
from mmaudit.benchmark.development_corpus_stability import read_development_corpus_stability
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.development_corpus_repeats import (
    read_development_corpus_repeats,
    read_development_corpus_repeats_plan,
)
from tests.development_corpus_repeats_scale_support import maximum_repeat_cli_inputs
from tests.development_corpus_support import corpus_payload
from tests.development_review_support import SYNTHETIC_CREDENTIAL


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("maximum repeat attempted real network or process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.mark.parametrize("kind", ["complete", "last_unknown", "missing_last"])
def test_actual_eight_by_64_repeats_retain_all_claims_scope_and_liabilities(
    tmp_path, monkeypatch, kind
):
    args, prepared, responses, ledger, output = maximum_repeat_cli_inputs(tmp_path)
    progress = sys.stderr
    started = time.monotonic()
    first_requests = []
    frozen_inputs = {}
    call_count = 0
    child_count = 0
    actual_child = repeats.run_development_corpus

    def handler(request):
        nonlocal call_count
        primary_index = call_count % 64
        if call_count == 0:
            selected = read_development_corpus_repeats_plan((output / "plan.json").read_bytes())
            assert selected.plan_sha256 == prepared.plan.plan_sha256
            frozen_inputs.update(
                {
                    name: (output / name).read_bytes()
                    for name in ("plan.json", "sources.json", "benchmark-plan.json")
                }
            )
        if call_count < 64:
            first_requests.append(hashlib.sha256(request.content).hexdigest())
        else:
            assert hashlib.sha256(request.content).hexdigest() == first_requests[primary_index]
        assert b"synthetic-maximum-continuation-structural-labels" not in request.content
        call_count += 1
        if call_count % 64 == 0:
            print(
                f"synthetic {kind}: mock request {call_count}/512 reached at "
                f"{time.monotonic() - started:.2f}s",
                file=progress,
                flush=True,
            )
        if kind == "last_unknown" and call_count == 512:
            return httpx.Response(429, json={"error": "synthetic unknown final charge"})
        payload = corpus_payload(primary_index + 1)
        payload["id"] = f"gen-synthetic-maximum-repeat-{call_count:04d}"
        provider = prepared.trials[0].shards[0].endpoint_snapshot.endpoints[0].provider_name
        payload["provider"] = provider
        payload["openrouter_metadata"]["endpoints"]["available"][0]["provider"] = provider
        payload["openrouter_metadata"]["attempts"][0]["provider"] = provider
        payload["choices"][0]["message"]["content"] = json.dumps(responses[primary_index])
        return httpx.Response(200, json=payload)

    async def child(**kwargs):
        nonlocal child_count
        child_count += 1
        if kind == "missing_last" and child_count == 8:
            raise ValueError("synthetic whole final child result unavailable")
        result = await actual_child(**kwargs)
        print(
            f"synthetic {kind}: child {child_count}/8 returned {result.status} at "
            f"{time.monotonic() - started:.2f}s",
            file=progress,
            flush=True,
        )
        return result

    async def execute(**kwargs):
        return await repeats.run_development_corpus_repeats(
            **kwargs, mock_transport=httpx.MockTransport(handler)
        )

    monkeypatch.setattr(repeats, "run_development_corpus", child)
    monkeypatch.setattr(cli, "run_development_corpus_repeats", execute)
    result = CliRunner().invoke(app, args)
    expected_exit = ExitCode.SUCCESS if kind == "complete" else ExitCode.INCOMPLETE
    assert result.exit_code == int(expected_exit), result.output
    summary = json.loads(result.stdout)
    assert len(result.stdout.encode()) < 2000
    assert SYNTHETIC_CREDENTIAL not in result.output
    observed = read_development_corpus_repeats((output / "result.json").read_bytes())
    assert observed.plan.plan_sha256 == prepared.plan.plan_sha256
    assert summary["result_sha256"] == observed.observation_sha256
    assert observed.plan.trial_count == observed.started_trial_count == child_count == 8
    assert observed.selected_request_count == 512 and len(observed.trials) == 8
    assert all(len(t.shards) == 64 for t in observed.plan.trials)
    expected_calls = 448 if kind == "missing_last" else 512
    assert call_count == len(ledger.snapshot().entries) == expected_calls
    assert observed.total_accounted_cost_usd == ledger.snapshot().spent_usd
    assert observed.active_reserved_usd == ledger.snapshot().active_reserved_usd == 0
    assert observed.reported_actual_cost_usd == Decimal(
        "5.12" if kind == "complete" else "5.11" if kind == "last_unknown" else "4.48"
    )
    assert observed.completed_trial_count == (8 if kind == "complete" else 7)
    assert len(observed.unknown_actual_cost_request_ids) == (1 if kind == "last_unknown" else 0)
    assert (observed.uncertain_accounted_cost_usd > 0) == (kind == "last_unknown")
    for name, raw in frozen_inputs.items():
        assert (output / name).read_bytes() == raw
    for path in output.rglob("*"):
        assert not path.is_symlink()
        assert stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600)
    assert not any(
        (
            observed.findings_validated,
            observed.audit_complete,
            observed.qualification_eligible,
            observed.release_eligible,
        )
    )
    if kind == "missing_last":
        assert observed.missing_result_trial_indexes == (7,)
        assert observed.trials[-1].observation is None
        assert observed.trials[-1].status == "MISSING_RESULT"
        assert len(observed.missing_accounting_request_ids) == 64
        assert len(observed.missing_runtime_request_ids) == 64
        assert observed.measurement_scope == "MISSING_PLANNED_TRIAL_RESULTS"
        assert not (output / "stability.json").exists()
        return
    assert observed.measurement_scope == "ALL_PREDECLARED_TRIAL_RESULTS_RETAINED"
    measured = read_development_corpus_stability((output / "stability.json").read_bytes())
    assert len(measured.trials) == 8 and len(measured.pairs) == 28 and len(measured.cohorts) == 1
    assert len(measured.combined.controls) == 1024
    assert measured.combined.total_claim_count == (8192 if kind == "complete" else 8176)
    assert all(t.selected_request_count == 64 for t in measured.trials)
    assert measured.accounted_cost_usd == observed.total_accounted_cost_usd
    assert measured.uncertain_accounted_cost_usd == observed.uncertain_accounted_cost_usd
    assert measured.trial_independence == measured.root_independence == "NOT_ESTABLISHED"
    assert not measured.audit_complete and not measured.qualification_eligible
    if kind == "complete":
        assert measured.combined.union_assertion_coverage.value == 1
        assert measured.combined.pooled_per_trial_assertion_precision.denominator == 81920
        assert all(c.assertion.classification == "STABLE" for c in measured.combined.controls)
    else:
        assert measured.combined.union_assertion_coverage.value is None
        assert measured.combined.pooled_per_trial_assertion_precision.value is None
        unknown = [c for c in measured.combined.controls if c.assertion.unobserved_trial_indexes]
        assert len(unknown) == 16
        assert all(c.assertion.unobserved_trial_indexes == (7,) for c in unknown)
        assert all(c.assertion.frequency.denominator == 8 for c in unknown)
