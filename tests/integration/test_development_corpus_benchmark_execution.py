"""Source-bound structural measurement with fake HTTP only; no contract or network execution."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
from decimal import Decimal

import httpx
import pytest

import mmaudit.orchestration.development_corpus as orchestration
from mmaudit.benchmark.development_corpus import (
    DevelopmentCorpusBenchmarkBinding,
    DevelopmentCorpusBenchmarkScore,
    DevelopmentCorpusBenchmarkTruth,
)
from mmaudit.models.development_audit import development_ledger_request_id
from mmaudit.models.development_corpus import DevelopmentCorpusObservation
from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.development_corpus_benchmark_support import (
    labelled_truth,
    paired_case,
    paired_payload,
    paired_sources,
    truth_binding,
)
from tests.development_corpus_support import corpus_case, corpus_payload
from tests.development_review_support import SYNTHETIC_CREDENTIAL, local_controls


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("manifest measurement attempted real network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def retained_score(tmp_path):
    return DevelopmentCorpusBenchmarkScore.model_validate_json(
        (tmp_path / "run/score.json").read_bytes(), strict=True
    )


async def execute(tmp_path, prepared, ledger, secrets, handler, binding=None):
    return await orchestration.run_development_corpus(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_binding=truth_binding(prepared) if binding is None else binding,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [0, 1, 16])
async def test_labels_are_retained_before_dispatch_never_prompted_and_add_no_request(
    tmp_path, count
):
    prepared = paired_case()
    binding = truth_binding(prepared)
    ledger, secrets = local_controls(tmp_path)
    calls = []

    def handler(request):
        calls.append(request.content)
        assert request.content == prepared.shards[len(calls) - 1].request_content
        assert (
            DevelopmentCorpusBenchmarkBinding.model_validate_json(
                (tmp_path / "run/benchmark-plan.json").read_bytes(), strict=True
            )
            == binding
        )
        for value in (binding.truth_file_sha256, binding.truth.truth_id, binding.truth.provenance):
            assert value.encode() not in request.content
        assert SYNTHETIC_CREDENTIAL.encode() not in request.content
        assert not (tmp_path / "run/score.json").exists()
        return httpx.Response(200, json=paired_payload(len(calls), count=count))

    result = await execute(tmp_path, prepared, ledger, secrets, handler, binding)
    score = retained_score(tmp_path)
    assert score.observation == result
    assert score.binding == binding
    assert len(calls) == len(ledger.snapshot().entries) == 6
    assert score.summary.total_claim_count == result.candidate_claim_count == 3 * count
    assert score.summary.duplicate_claim_count == max(0, 3 * count - 1)
    assert score.summary.unique_root_recall.value == (1.0 if count else 0.0)
    assert score.summary.all_claim_unique_root_fraction.value == (
        round(1 / (3 * count), 6) if count else None
    )
    assert score.summary.reported_actual_cost_usd == Decimal("0.06")
    assert score.summary.accounted_cost_usd == result.total_accounted_cost_usd
    assert len(list((tmp_path / "run").iterdir())) == 12
    assert (tmp_path / "run/control-measurement.json").is_file()
    assert (tmp_path / "run").stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in (tmp_path / "run").iterdir())
    assert score.findings_validated is score.audit_complete is score.qualification_eligible is False


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_shard", [1, 3, 6])
@pytest.mark.parametrize("failure", ["known_http", "unknown_http", "malformed", "generation_reuse"])
async def test_failed_first_middle_last_shards_keep_original_claim_cost_and_scope_denominators(
    tmp_path, failed_shard, failure
):
    if failed_shard == 1 and failure == "generation_reuse":
        failed_shard = 2
    prepared = paired_case()
    ledger, secrets = local_controls(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        payload = paired_payload(len(calls))
        if len(calls) == failed_shard:
            if failure in {"known_http", "unknown_http"}:
                return httpx.Response(
                    429,
                    json={
                        "error": "synthetic refusal",
                        **({"usage": {"cost": 0.01}} if failure == "known_http" else {}),
                    },
                )
            if failure == "malformed":
                payload["choices"][0]["message"]["content"] = "{"
            else:
                payload["id"] = "gen-synthetic-corpus-1"
        return httpx.Response(200, json=payload)

    result = await execute(tmp_path, prepared, ledger, secrets, handler)
    score = retained_score(tmp_path)
    assert score.observation == result and result.status == "INCOMPLETE"
    assert len(calls) == len(result.accounting) == failed_shard
    assert len(score.claims) == min(3, failed_shard - 1)
    assert score.summary.unobserved_shard_ids == result.unobserved_shard_ids
    assert score.summary.missing_accounting_shard_ids == tuple(
        s.shard_id for s in prepared.plan.shards[failed_shard:]
    )
    assert score.summary.missing_shard_runtime_ids == score.summary.missing_accounting_shard_ids
    assert score.summary.first_attempt_shard_completion.denominator == 6
    for ratio in (
        score.summary.unique_root_recall,
        score.summary.severity_weighted_root_recall,
        score.summary.all_claim_unique_root_fraction,
        score.summary.severity_weighted_structural_precision,
    ):
        assert ratio.value is None and ratio.state == "INCOMPLETE_SCOPE"
    assert score.summary.accounted_cost_usd == sum(
        e.accounted_cost_usd for e in ledger.snapshot().entries
    )
    assert score.summary.uncertain_accounted_cost_usd == result.uncertain_accounted_cost_usd
    assert bool(score.summary.unknown_actual_cost_shard_ids) is (failure == "unknown_http")


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_deadline_or_cancellation_retains_score_and_unknown_unreturned_request(
    tmp_path, cancel
):
    prepared = paired_case(maximum_run_seconds=1.0)
    ledger, secrets = local_controls(tmp_path)
    entered = asyncio.Event()

    async def handler(_request):
        entered.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(execute(tmp_path, prepared, ledger, secrets, handler))
    await asyncio.wait_for(entered.wait(), timeout=4)
    if cancel:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        await asyncio.wait_for(task, timeout=4)
    score = retained_score(tmp_path)
    assert score.observation.status == "INCOMPLETE"
    assert score.observation.stop_reason == ("INTERRUPTED" if cancel else "LOCAL_FAILURE")
    assert not score.claims and not score.observation.observations
    assert len(score.observation.accounting) == len(ledger.snapshot().entries) == 1
    assert (
        len(score.summary.unobserved_shard_ids) == len(score.summary.missing_shard_runtime_ids) == 6
    )
    assert score.summary.uncertain_accounted_cost_usd == score.summary.accounted_cost_usd > 0
    assert score.summary.unique_root_recall.value is None


@pytest.mark.asyncio
async def test_carry_preserves_prior_liability_without_attributing_it_to_new_score(tmp_path):
    ledger, secrets = local_controls(tmp_path)
    hold = ledger.reserve(development_ledger_request_id("synthetic-before-score"), Decimal("1"))
    ledger.reconcile(hold, None)
    original = ledger.snapshot().entries[0]
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=paired_payload(len(calls)))

    with pytest.raises(ValueError, match="accounting"):
        await execute(tmp_path, paired_case(), ledger, secrets, handler)
    assert not calls and not (tmp_path / "run").exists()
    policy = DevelopmentCostPolicy.model_validate(
        {
            **paired_case().plan.policy.model_dump(),
            "uncertain_cost_policy": "CARRY_RESERVED_ESTIMATE",
        }
    )
    result = await execute(tmp_path, paired_case(policy=policy), ledger, secrets, handler)
    score = retained_score(tmp_path)
    assert original in ledger.snapshot().entries and len(calls) == 6
    assert sum(e.accounted_cost_usd for e in ledger.snapshot().entries) == Decimal("1.06")
    assert score.summary.accounted_cost_usd == result.total_accounted_cost_usd == Decimal("0.06")
    assert score.summary.uncertain_accounted_cost_usd == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["type", "plan", "raw", "typed", "source", "credential"])
async def test_invalid_binding_refuses_before_output_ledger_or_dispatch(tmp_path, kind):
    prepared = paired_case()
    binding = truth_binding(prepared)
    ledger, secrets = local_controls(tmp_path)
    if kind == "type":
        binding = object()
    elif kind == "plan":
        binding = binding.model_copy(update={"plan_sha256": "a" * 64})
    elif kind == "raw":
        binding = binding.model_copy(update={"truth_file_content": "{}"})
    elif kind == "typed":
        binding = binding.model_copy(
            update={"truth": binding.truth.model_copy(update={"truth_id": "changed-labels"})}
        )
    elif kind == "source":
        prepared = corpus_case(
            source_files=tuple((name, raw + b"\n") for name, raw in paired_sources())
        )
    else:
        secrets = OperatorSecrets({"OPENROUTER_API_KEY": binding.truth.truth_id})
    before = ledger.path.read_bytes()

    def forbidden(_request):
        pytest.fail("invalid label binding dispatched")

    with pytest.raises(ValueError):
        await execute(tmp_path, prepared, ledger, secrets, forbidden, binding)
    assert ledger.path.read_bytes() == before and not (tmp_path / "run").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind", ["labels", "source", "directory", "result", "score", "score_limit"]
)
async def test_owned_evidence_drift_or_score_bound_cannot_finalize_a_pass(
    tmp_path, monkeypatch, kind
):
    prepared = paired_case()
    ledger, secrets = local_controls(tmp_path)
    calls = []
    original_write = orchestration._write
    original_score_write = orchestration._write_score

    def write(*args, **kwargs):
        result = original_write(*args, **kwargs)
        if kind == "result" and args[1] == "result.json":
            (tmp_path / "run/result.json").write_text("{}")
        return result

    def write_score(*args, **kwargs):
        result = original_score_write(*args, **kwargs)
        if kind == "score":
            (tmp_path / "run/score.json").write_text("{}")
        return result

    monkeypatch.setattr(orchestration, "_write", write)
    monkeypatch.setattr(orchestration, "_write_score", write_score)
    if kind == "score_limit":
        monkeypatch.setattr(orchestration, "MAX_DEVELOPMENT_CORPUS_SCORE_BYTES", 1)

    def handler(request):
        calls.append(request)
        if kind in {"labels", "source"}:
            name = "benchmark-plan.json" if kind == "labels" else "sources.json"
            (tmp_path / "run" / name).write_text("{}")
        elif kind == "directory":
            (tmp_path / "run").rename(tmp_path / "retained-run")
            (tmp_path / "run").mkdir(mode=0o700)
        return httpx.Response(200, json=paired_payload(len(calls)))

    with pytest.raises(ValueError, match="finalized"):
        await execute(tmp_path, prepared, ledger, secrets, handler)
    assert (
        len(calls)
        == len(ledger.snapshot().entries)
        == (1 if kind in {"labels", "source", "directory"} else 6)
    )
    if kind == "score":
        with pytest.raises(ValueError):
            retained_score(tmp_path)
    else:
        assert not (tmp_path / "run/score.json").exists()


@pytest.mark.asyncio
async def test_maximum_64_sources_1024_critical_claims_and_controls_keep_10240_weights(tmp_path):
    # Repeated local source and line labels are structural scale controls, not semantic truth.
    raw = paired_sources()[0][1]
    sources = tuple((f"src/control-{i:04d}/Source.sol", raw) for i in range(1, 65))
    prepared = corpus_case(
        source_files=sources,
        policy=DevelopmentCostPolicy(
            overspend_risk_accepted=True,
            total_budget_usd=Decimal("250"),
            per_attempt_budget_usd=Decimal("5"),
        ),
    )
    template = labelled_truth(paired_case()).controls[0].model_dump(mode="json")
    controls = []
    for i, (name, _) in enumerate(sources, 1):
        for line in range(1, 17):
            ref = {"filename": name, "line_start": line, "line_end": line}
            controls.append(
                {
                    **template,
                    "control_id": f"control-{i:04d}-{line:02d}",
                    "severity": "critical",
                    "origin": ref,
                    "required_origin_line": line,
                    "claim_sites": [ref],
                }
            )
    truth = DevelopmentCorpusBenchmarkTruth.model_validate_json(
        json.dumps(
            {
                "truth_id": "synthetic-maximum-structural-labels",
                "provenance": "AGENT_CONSTRUCTED_DEVELOPMENT_CONTROLS",
                "manifest": prepared.plan.manifest.model_dump(mode="json"),
                "controls": controls,
            }
        ),
        strict=True,
    )
    binding = truth_binding(prepared, truth)
    _, secrets = local_controls(tmp_path)
    ledger = AtomicCostLedger.initialize(tmp_path / "max-ledger.json", cap_usd=Decimal("250"))
    calls = []

    def handler(request):
        calls.append(request)
        name = sources[len(calls) - 1][0]
        payload = corpus_payload(len(calls), count=16, origin=name)
        response = json.loads(payload["choices"][0]["message"]["content"])
        for line, finding in enumerate(response["findings"], 1):
            finding.update(
                line_start=line,
                line_end=line,
                severity="critical",
                vulnerability_class=template["vulnerability_class"],
                root_cause_ref={"filename": name, "line_start": line, "line_end": line},
            )
        payload["choices"][0]["message"]["content"] = json.dumps(response)
        return httpx.Response(200, json=payload)

    result = await execute(tmp_path, prepared, ledger, secrets, handler, binding)
    score = retained_score(tmp_path)
    assert len(calls) == result.completed_shard_count == len(result.accounting) == 64
    assert len(score.claims) == len(score.summary.matched_root_ids) == 1024
    assert score.claims[-1].claim_id == "file-0064:16"
    assert score.summary.severity_weighted_root_recall.numerator == 10240
    assert score.summary.severity_weighted_root_recall.denominator == 10240
    assert score.summary.severity_weighted_structural_precision.denominator == 10240
    assert score.summary.severity_weighted_structural_precision.value == 1.0
    assert score.summary.accounted_cost_usd == Decimal("0.64")
    with pytest.raises(ValueError):
        DevelopmentCorpusBenchmarkTruth.model_validate_json(
            json.dumps({**truth.model_dump(mode="json"), "controls": [*controls, controls[-1]]}),
            strict=True,
        )


@pytest.mark.asyncio
async def test_finalization_failure_after_all_responses_still_nulls_quality(tmp_path, monkeypatch):
    prepared = paired_case()
    ledger, secrets = local_controls(tmp_path)
    calls = []
    original_write = orchestration._write

    def write(*args, **kwargs):
        if args[1] == "file-0006.json":
            raise OSError("synthetic output refusal after final observation")
        return original_write(*args, **kwargs)

    monkeypatch.setattr(orchestration, "_write", write)

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=paired_payload(len(calls)))

    result = await execute(tmp_path, prepared, ledger, secrets, handler)
    score = retained_score(tmp_path)
    assert result.status == "INCOMPLETE" and result.stop_reason == "LOCAL_FAILURE"
    assert result.completed_shard_count == 6 and not result.unobserved_shard_ids
    assert score.summary.unique_root_recall.value is None
    assert score.summary.first_attempt_shard_completion.value == 1.0
    assert score.summary.accounted_cost_usd == Decimal("0.06")
    assert (
        DevelopmentCorpusObservation.model_validate_json(
            (tmp_path / "run/result.json").read_bytes(), strict=True
        )
        == result
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("variant", ["a", "b"])
async def test_single_source_empty_response_separates_missed_from_empty_truth(tmp_path, variant):
    index = 0 if variant == "a" else 3
    prepared = corpus_case(source_files=(paired_sources()[index],))
    template = labelled_truth(paired_case()).controls[0 if variant == "a" else 1]
    control = template.model_dump(mode="json")
    control["claim_sites"] = [
        ref
        for ref in control["claim_sites"]
        if ref["filename"] == prepared.plan.manifest.sources[0].filename
    ]
    truth = DevelopmentCorpusBenchmarkTruth.model_validate_json(
        json.dumps(
            {
                "truth_id": "synthetic-single-source-label",
                "manifest": prepared.plan.manifest.model_dump(mode="json"),
                "provenance": "AGENT_CONSTRUCTED_DEVELOPMENT_CONTROLS",
                "controls": [control],
            }
        ),
        strict=True,
    )
    ledger, secrets = local_controls(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=corpus_payload(1, count=0))

    result = await execute(
        tmp_path, prepared, ledger, secrets, handler, truth_binding(prepared, truth)
    )
    score = retained_score(tmp_path)
    assert len(calls) == result.completed_shard_count == 1
    assert score.summary.unique_root_recall.value == (0.0 if variant == "a" else None)
    assert score.summary.unique_root_recall.state == (
        "OBSERVED" if variant == "a" else "EMPTY_DENOMINATOR"
    )
    assert score.summary.all_claim_unique_root_fraction.value is None
    assert score.summary.severity_weighted_structural_precision.value is None
    assert len(score.summary.observed_missed_root_ids) == (1 if variant == "a" else 0)
