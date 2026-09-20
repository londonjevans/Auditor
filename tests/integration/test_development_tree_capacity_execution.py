"""Full-size synthetic source reaches every real mock consumer and exact closed-stage resume."""

from __future__ import annotations

import json
import signal
import time
from contextlib import contextmanager
from decimal import Decimal

import httpx
import pytest

from mmaudit.models.development_corpus import render_development_corpus_sources
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.development_tree import run_development_tree_plan
from mmaudit.repository.development_tree_plan import write_development_tree_plan
from tests.development_corpus_judgment_support import manifest_judgment_payload
from tests.development_corpus_support import corpus_payload
from tests.development_ensemble_support import ENSEMBLE_MODELS
from tests.development_review_support import SYNTHETIC_CREDENTIAL
from tests.development_tree_capacity_support import capacity_inputs, capacity_source
from tests.integration.test_development_tree_plan_custody import (
    no_external_execution as no_external_execution,
)
from tests.integration.test_development_tree_plan_custody import reopen

pytestmark = pytest.mark.usefixtures("no_external_execution")


@contextmanager
def bounded_scale_phase(label, seconds, timings):
    """Bound the local test process, independently of the unchanged production time policy."""

    def expired(*_args):
        pytest.fail(f"actual 256-file {label} exceeded its local test safety deadline")

    previous = signal.signal(signal.SIGALRM, expired)
    begin = time.monotonic()
    signal.setitimer(signal.ITIMER_REAL, seconds)
    print(f"capacity phase started: {label}", flush=True)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        timings[label] = time.monotonic() - begin
        print(f"capacity phase finished: {label} {timings[label]:.3f}s", flush=True)


@pytest.mark.asyncio
@pytest.mark.skipif(not hasattr(signal, "SIGALRM"), reason="bounded POSIX scale acceptance")
async def test_actual_256_source_controller_preserves_full_catalog_across_stage_resume(tmp_path):
    files = tuple((f"Source{i:03d}.sol", capacity_source(i)) for i in range(256))
    inputs = capacity_inputs(tmp_path, files)
    timings = {}
    calls = []
    try:
        with bounded_scale_phase("plan", 300, timings):
            loaded = write_development_tree_plan(**inputs)
        assert loaded.plan.status == "READY"
        assert loaded.plan.reference.source_files == files
        assert len(loaded.plan.primaries) == 256
        first = loaded.plan.primaries[0]
        rendered = render_development_corpus_sources(
            first.partition.manifest, (files[0],), files[0][0]
        )

        def handler(request):
            body = json.loads(request.content)
            role = ENSEMBLE_MODELS.index(body["model"])
            assert rendered in body["messages"][1]["content"]
            assert len(request.content) <= first.role_envelopes[role].serialized_request_bytes
            assert SYNTHETIC_CREDENTIAL.encode() not in request.content
            payload = (
                corpus_payload(1, count=1, origin=files[0][0])
                if role == 0
                else manifest_judgment_payload(
                    role + 1, shard_id=first.candidate.shards[0].shard_id, filename=files[0][0]
                )
            )
            model = ENSEMBLE_MODELS[role]
            payload["id"] = f"gen-synthetic-256-capacity-{role}"
            payload["model"] = model
            routing = payload["openrouter_metadata"]
            routing["requested"] = model
            routing["endpoints"]["available"][0]["model"] = model
            routing["attempts"][0]["model"] = model
            calls.append(role)
            return httpx.Response(200, json=payload)

        ledger = AtomicCostLedger.initialize(
            tmp_path / "synthetic-ledger.json", cap_usd=Decimal("250")
        )
        arguments = dict(
            loaded=loaded,
            ledger=ledger,
            operator_secrets=OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL}),
            output_dir=tmp_path / "run",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
        with bounded_scale_phase("controller start", 600, timings):
            paused = await run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
        assert calls == [0] and paused.completed_attempt_count == 1
        assert len(paused.primary_statuses) == 256
        assert all(p.status == "PENDING" for p in paused.primary_statuses[1:])
        assert paused.coverage.successful_primary_paths == (files[0][0],)
        assert paused.coverage.not_successfully_observed_paths == tuple(p for p, _ in files[1:])
        parent = arguments["output_dir"] / "cases/case-0001/run/candidate/result.json"
        original = parent.read_bytes()
        billed = ledger.snapshot().entries
        with bounded_scale_phase("controller resume", 600, timings):
            arguments["loaded"] = reopen(inputs)
            resumed = await run_development_tree_plan(
                **arguments, resume=True, maximum_stages_per_invocation=2
            )
        assert calls == [0, 1, 2] and resumed.completed_attempt_count == 3
        assert resumed.status == "INCOMPLETE"
        assert len(resumed.primary_statuses) == 256
        assert resumed.primary_statuses[0].status == "OBSERVED_ALL_STAGES"
        assert all(p.status == "PENDING" for p in resumed.primary_statuses[1:])
        assert resumed.coverage.not_successfully_observed_paths == tuple(p for p, _ in files[1:])
        assert parent.read_bytes() == original
        assert all(row in ledger.snapshot().entries for row in billed)
        assert ledger.snapshot().spent_usd == Decimal("0.03")
        assert not resumed.audit_complete and not resumed.qualification_eligible
    finally:
        (tmp_path / "scale-observation.json").write_text(
            json.dumps({"phase_seconds": timings, "mock_roles": calls}, sort_keys=True)
        )


@pytest.mark.asyncio
async def test_maximum_size_source_reaches_both_reviews_after_exact_candidate_resume(tmp_path):
    raw = capacity_source(0, 262_144)
    files = (("Source.sol", raw),)
    inputs = capacity_inputs(tmp_path, files)
    loaded = write_development_tree_plan(**inputs)
    assert loaded.plan.status == "READY"
    rendered = render_development_corpus_sources(
        loaded.plan.primaries[0].partition.manifest, files, "Source.sol"
    )
    calls = []

    def handler(request):
        body = json.loads(request.content)
        role = ENSEMBLE_MODELS.index(body["model"])
        prompt = body["messages"][1]["content"]
        assert rendered in prompt
        assert SYNTHETIC_CREDENTIAL.encode() not in request.content
        assert (
            len(request.content)
            <= loaded.plan.primaries[0].role_envelopes[role].serialized_request_bytes
        )
        payload = (
            corpus_payload(1, count=1, origin="Source.sol")
            if role == 0
            else manifest_judgment_payload(role + 1, shard_id="file-0001", filename="Source.sol")
        )
        model = ENSEMBLE_MODELS[role]
        payload["id"] = f"gen-synthetic-capacity-{role}"
        payload["model"] = model
        routing = payload["openrouter_metadata"]
        routing["requested"] = model
        routing["endpoints"]["available"][0]["model"] = model
        routing["attempts"][0]["model"] = model
        calls.append((role, request.content))
        return httpx.Response(200, json=payload)

    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("250"))
    arguments = dict(
        loaded=loaded,
        ledger=ledger,
        operator_secrets=OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL}),
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    paused = await run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    assert paused.completed_attempt_count == 1 and len(calls) == 1
    parent = arguments["output_dir"] / "cases/case-0001/run"
    retained = (parent / "candidate/result.json").read_bytes()
    billed = ledger.snapshot().entries
    arguments["loaded"] = reopen(inputs)
    final = await run_development_tree_plan(**arguments, resume=True)
    assert [role for role, _ in calls] == [0, 1, 2]
    assert final.completed_attempt_count == 3
    assert final.status == "OBSERVED_ALL_AVAILABLE_STAGES"
    assert final.coverage.status == "ALL_PRIMARY_RESPONSES_OBSERVED"
    assert (
        not final.audit_complete and not final.qualification_eligible and not final.release_eligible
    )
    assert (parent / "candidate/result.json").read_bytes() == retained
    assert all(row in ledger.snapshot().entries for row in billed)
    assert ledger.snapshot().spent_usd == Decimal("0.03")
