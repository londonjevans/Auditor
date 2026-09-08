"""Automatic score/ledger custody over local files and trapped mock HTTP only."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
from decimal import Decimal

import httpx
import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as development_cli
import mmaudit.orchestration.development_audit as audit_runner
from mmaudit.benchmark.development import DevelopmentBenchmarkBinding, DevelopmentBenchmarkScore
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.development_audit import DevelopmentAuditObservation
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from tests.development_audit_support import CORPUS_ROOT, shard_payload
from tests.development_benchmark_support import (
    benchmark_truth,
    scored_audit_case,
    scored_file_response,
    scored_payload,
)
from tests.development_review_support import SYNTHETIC_CREDENTIAL, local_controls
from tests.integration.test_development_corpus_audit import inputs

RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def no_network_or_subprocess(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("development scoring integration must not use network or subprocess")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def benchmark_inputs(tmp_path, *, variant="a"):
    args = inputs(tmp_path, variant=variant)
    truth = tmp_path / "truth.json"
    truth.write_bytes((CORPUS_ROOT / f"truth-{variant}.json").read_bytes())
    return [*args, "--truth-manifest", str(truth)]


def local_cli(monkeypatch, handler):
    async def run(**kwargs):
        return await audit_runner.run_development_audit(
            **kwargs, mock_transport=httpx.MockTransport(handler)
        )

    monkeypatch.setattr(development_cli, "run_development_audit", run)


def retained_score(tmp_path):
    return DevelopmentBenchmarkScore.model_validate_json((tmp_path / "run/score.json").read_bytes())


def retained_ledger(tmp_path):
    return AtomicCostLedger.open_existing(
        tmp_path / "synthetic-ledger.json", cap_usd=Decimal("20")
    ).snapshot()


@pytest.mark.parametrize("variant", ["a", "b"])
def test_cli_freezes_truth_before_dispatch_and_automatically_scores_exact_retained_results(
    tmp_path, monkeypatch, variant
):
    args = benchmark_inputs(tmp_path, variant=variant)
    calls = 0
    bindings = []

    def handler(request):
        nonlocal calls
        calls += 1
        binding = DevelopmentBenchmarkBinding.model_validate_json(
            (tmp_path / "run/benchmark-plan.json").read_bytes()
        )
        bindings.append(binding)
        assert retained_ledger(tmp_path).active_reserved_usd > 0
        assert binding.truth == benchmark_truth(variant)
        for forbidden in (
            binding.truth_file_sha256,
            binding.truth.controls[0].control_id,
            binding.truth.provenance,
            SYNTHETIC_CREDENTIAL,
            str(tmp_path),
        ):
            assert forbidden.encode() not in request.content
        assert json.loads(request.content)["response_format"]["json_schema"]["name"].endswith("_v2")
        return httpx.Response(
            200,
            json=scored_payload(
                calls, response=scored_file_response(calls, advisory=variant == "b")
            ),
        )

    local_cli(monkeypatch, handler)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == ExitCode.SUCCESS, result.output
    score = retained_score(tmp_path)
    observation = DevelopmentAuditObservation.model_validate_json(result.stdout)
    assert score.observation == observation
    assert observation == DevelopmentAuditObservation.model_validate_json(
        (tmp_path / "run/result.json").read_bytes()
    )
    assert bindings == [score.binding] * 3
    assert calls == observation.completed_shard_count == 3
    assert (
        score.summary.reported_actual_cost_usd
        == score.summary.accounted_cost_usd
        == Decimal("0.03")
    )
    assert score.summary.elapsed_seconds == observation.elapsed_seconds
    assert score.summary.missing_shard_runtime_ids == ()
    assert (
        score.findings_validated is score.qualification_eligible is score.release_eligible is False
    )
    if variant == "a":
        assert len(score.summary.matched_root_ids) == 1
        assert score.summary.duplicate_claim_count == 2
        assert score.summary.all_claim_unique_root_fraction.value == 0.333333
    else:
        assert score.summary.advisory_claim_count == 3
        assert score.summary.expected_root_ids == ()
        assert score.summary.unique_root_recall.value is None
    assert retained_ledger(tmp_path).active_reserved_usd == 0
    before = (tmp_path / "run/score.json").read_bytes()
    replay = RUNNER.invoke(app, args)
    assert replay.exit_code == ExitCode.CONFIGURATION
    assert calls == 3 and (tmp_path / "run/score.json").read_bytes() == before


@pytest.mark.parametrize(
    "failure",
    [
        "missing",
        "modified",
        "wrong_pair",
        "linked",
        "linked_parent",
        "relative",
        "same_control",
        "output_overlap",
    ],
)
def test_cli_rejects_bad_truth_before_credentials_accounting_or_dispatch(
    tmp_path, monkeypatch, failure
):
    args = benchmark_inputs(tmp_path)
    truth = tmp_path / "truth.json"
    if failure == "missing":
        truth.rename(tmp_path / "retained-truth.json")
    elif failure == "modified":
        truth.write_bytes(truth.read_bytes() + b" ")
    elif failure == "wrong_pair":
        truth.write_bytes((CORPUS_ROOT / "truth-b.json").read_bytes())
    elif failure == "linked":
        truth.rename(tmp_path / "retained-truth.json")
        truth.symlink_to(tmp_path / "retained-truth.json")
    elif failure == "linked_parent":
        (tmp_path / "alias").symlink_to(tmp_path, target_is_directory=True)
        args[-1] = str(tmp_path / "alias/truth.json")
    elif failure == "relative":
        args[-1] = "truth.json"
    elif failure == "same_control":
        args[-1] = str(tmp_path / "synthetic-operator-control.txt")
    else:
        args[-1] = str(tmp_path / "run/truth.json")
    before = retained_ledger(tmp_path)
    monkeypatch.setattr(
        development_cli,
        "load_operator_secrets",
        lambda *_a, **_k: pytest.fail("unexpected credential access"),
    )
    monkeypatch.setattr(
        development_cli, "run_development_audit", lambda **_k: pytest.fail("unexpected dispatch")
    )
    result = RUNNER.invoke(app, args)
    assert result.exit_code == ExitCode.CONFIGURATION
    assert retained_ledger(tmp_path) == before
    assert not (tmp_path / "run").exists()
    assert SYNTHETIC_CREDENTIAL not in result.output


@pytest.mark.parametrize("failure", ["malformed", "unknown_cost", "overrun", "legacy_response"])
def test_automatic_partial_score_retains_failed_attempt_and_missing_shards(
    tmp_path, monkeypatch, failure
):
    args = benchmark_inputs(tmp_path)
    calls = 0

    def handler(_request):
        nonlocal calls
        calls += 1
        payload = scored_payload(calls, response=scored_file_response(calls))
        if calls == 2:
            if failure == "malformed":
                payload["choices"][0]["message"]["content"] = "synthetic malformed JSON"
            elif failure == "unknown_cost":
                del payload["usage"]["cost"]
            elif failure == "overrun":
                payload["usage"]["cost"] = 10.0
            else:
                payload = shard_payload(calls)
        return httpx.Response(200, json=payload)

    local_cli(monkeypatch, handler)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == ExitCode.INCOMPLETE, result.output
    score = retained_score(tmp_path)
    assert calls == 2
    assert score.observation.status == "INCOMPLETE"
    assert score.summary.quality_scope == "INCOMPLETE_OBSERVATIONS"
    assert score.summary.first_attempt_shard_completion.value == 0.333333
    assert score.summary.unique_root_recall.value is None
    assert score.summary.severity_weighted_structural_precision.value is None
    assert score.summary.total_claim_count == 1
    assert score.summary.unobserved_shard_ids == ("file-02", "file-03")
    assert (
        score.summary.missing_accounting_shard_ids
        == score.summary.missing_shard_runtime_ids
        == ("file-03",)
    )
    assert score.summary.accounted_cost_usd == sum(
        entry.accounted_cost_usd for entry in retained_ledger(tmp_path).entries
    )
    assert score.summary.active_reserved_usd == 0
    if failure == "unknown_cost":
        assert score.summary.unknown_actual_cost_shard_ids == ("file-02",)
        assert score.summary.reported_actual_cost_usd == Decimal("0.01")
        assert score.summary.uncertain_accounted_cost_usd > 0
    else:
        assert score.summary.unknown_actual_cost_shard_ids == ()
        assert score.summary.uncertain_accounted_cost_usd == 0
        assert score.summary.reported_actual_cost_usd == Decimal(
            "10.01" if failure == "overrun" else "0.02"
        )


def test_output_binding_drift_stops_next_shard_without_refunding_or_overwriting(
    tmp_path, monkeypatch
):
    args = benchmark_inputs(tmp_path)
    calls = 0

    def handler(_request):
        nonlocal calls
        calls += 1
        (tmp_path / "run/benchmark-plan.json").write_text("SYNTHETIC_CHANGED_BINDING")
        return httpx.Response(200, json=scored_payload(calls, response=scored_file_response(calls)))

    local_cli(monkeypatch, handler)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == ExitCode.CONFIGURATION
    assert calls == 1
    ledger = retained_ledger(tmp_path)
    assert len(ledger.entries) == 1 and ledger.entries[0].actual_cost_usd == Decimal("0.01")
    assert ledger.active_reserved_usd == 0
    assert (tmp_path / "run/benchmark-plan.json").read_text() == "SYNTHETIC_CHANGED_BINDING"
    assert not (tmp_path / "run/score.json").exists()


def test_score_failure_keeps_completed_result_and_costs_but_cli_cannot_report_success(
    tmp_path, monkeypatch
):
    args = benchmark_inputs(tmp_path)
    calls = 0

    def handler(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=scored_payload(calls, response=scored_file_response(calls)))

    def refused_score(**_kwargs):
        raise ValueError("SYNTHETIC_SCORER_ERROR_CANARY")

    local_cli(monkeypatch, handler)
    monkeypatch.setattr(audit_runner, "score_development_audit", refused_score)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == ExitCode.CONFIGURATION
    assert calls == 3
    observation = DevelopmentAuditObservation.model_validate_json(
        (tmp_path / "run/result.json").read_bytes()
    )
    assert observation.status == "OBSERVED_ALL_SHARDS"
    assert observation.total_accounted_cost_usd == Decimal("0.03")
    assert retained_ledger(tmp_path).active_reserved_usd == 0
    assert not (tmp_path / "run/score.json").exists()
    assert "SYNTHETIC_SCORER_ERROR_CANARY" not in result.output


@pytest.mark.asyncio
async def test_interruption_preserves_unknown_charge_and_incomplete_score(tmp_path):
    ledger, secrets = local_controls(tmp_path)
    calls = 0

    def interrupted(_request):
        nonlocal calls
        calls += 1
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await audit_runner.run_development_audit(
            prepared=scored_audit_case(),
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "run",
            allow_code_egress=True,
            benchmark_truth=benchmark_truth(),
            mock_transport=httpx.MockTransport(interrupted),
        )
    assert calls == 1
    score = retained_score(tmp_path)
    assert score.observation.stop_reason == "INTERRUPTED"
    assert score.summary.first_attempt_shard_completion.value == 0
    assert score.summary.unique_root_recall.value is None
    assert score.summary.unknown_actual_cost_shard_ids == ("file-01",)
    assert len(score.summary.missing_shard_runtime_ids) == 3
    assert score.summary.uncertain_accounted_cost_usd > 0
    assert ledger.snapshot().entries[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert ledger.snapshot().active_reserved_usd == 0


@pytest.mark.asyncio
async def test_existing_private_output_parent_is_still_required_before_reservation(tmp_path):
    ledger, secrets = local_controls(tmp_path)
    with pytest.raises(ValueError):
        await audit_runner.run_development_audit(
            prepared=scored_audit_case(),
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "missing-parent/run",
            allow_code_egress=True,
            benchmark_truth=benchmark_truth(),
            mock_transport=httpx.MockTransport(lambda _request: pytest.fail("unexpected HTTP")),
        )
    assert not ledger.snapshot().entries
    assert not (tmp_path / "missing-parent").exists()
