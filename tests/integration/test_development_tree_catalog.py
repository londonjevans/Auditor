"""Every synthetic catalog primary reaches all three real mock consumers across restart."""

from __future__ import annotations

import json
import resource
import signal
import sys
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
from tests.integration.test_development_tree_capacity_execution import bounded_scale_phase
from tests.integration.test_development_tree_plan_custody import (
    no_external_execution as no_external_execution,
)
from tests.integration.test_development_tree_plan_custody import reopen

pytestmark = pytest.mark.usefixtures("no_external_execution")


@pytest.mark.asyncio
@pytest.mark.skipif(not hasattr(signal, "SIGALRM"), reason="bounded POSIX catalog acceptance")
async def test_all_256_primaries_and_768_stages_complete_across_original_midpoint_resume(tmp_path):
    files = tuple((f"Source{i:03d}.sol", capacity_source(i)) for i in range(256))
    inputs = capacity_inputs(tmp_path, files)
    timings = {}
    calls = []
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("250"))
    try:
        with bounded_scale_phase("complete catalog plan", 300, timings):
            loaded = write_development_tree_plan(**inputs)
        assert loaded.plan.status == "READY"
        assert loaded.plan.reference.source_files == files
        assert len(loaded.plan.primaries) == 256
        assert loaded.plan.policy.maximum_manifest_seconds == 60
        assert loaded.plan.policy.maximum_total_seconds == 256 * 60
        assert loaded.plan.policy.cost_policy.per_attempt_budget_usd == Decimal("0.05")
        assert loaded.plan.policy.cost_policy.maximum_attempts == 1

        def handler(request):
            position, expected_role = divmod(len(calls), 3)
            assert position < 256
            body = json.loads(request.content)
            role = ENSEMBLE_MODELS.index(body["model"])
            assert role == expected_role
            primary = loaded.plan.primaries[position]
            filename, content = files[position]
            rendered = render_development_corpus_sources(
                primary.partition.manifest, ((filename, content),), filename
            )
            assert rendered in body["messages"][1]["content"]
            assert len(request.content) <= primary.role_envelopes[role].serialized_request_bytes
            assert SYNTHETIC_CREDENTIAL.encode() not in request.content
            payload = (
                corpus_payload(1, count=1, origin=filename)
                if role == 0
                else manifest_judgment_payload(
                    role + 1, shard_id=primary.candidate.shards[0].shard_id, filename=filename
                )
            )
            model = ENSEMBLE_MODELS[role]
            payload["id"] = f"gen-synthetic-complete-catalog-{position:03d}-{role}"
            payload["model"] = model
            routing = payload["openrouter_metadata"]
            routing["requested"] = model
            routing["endpoints"]["available"][0]["model"] = model
            routing["attempts"][0]["model"] = model
            calls.append((filename, role))
            if len(calls) % 24 == 0:
                print(f"complete catalog mock stages: {len(calls)}/768", flush=True)
            return httpx.Response(200, json=payload)

        arguments = dict(
            loaded=loaded,
            ledger=ledger,
            operator_secrets=OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL}),
            output_dir=tmp_path / "run",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
        with bounded_scale_phase("complete catalog first invocation", 1800, timings):
            paused = await run_development_tree_plan(**arguments, maximum_stages_per_invocation=385)
        assert paused.completed_attempt_count == len(calls) == 385
        assert len(paused.primary_statuses) == 256
        assert all(row.status == "OBSERVED_ALL_STAGES" for row in paused.primary_statuses[:128])
        assert paused.primary_statuses[128].status == "REVIEW_INCOMPLETE"
        assert all(row.status == "PENDING" for row in paused.primary_statuses[129:])
        assert paused.coverage.successful_primary_paths == tuple(name for name, _ in files[:129])
        assert paused.coverage.not_successfully_observed_paths == tuple(
            name for name, _ in files[129:]
        )
        interrupted = arguments["output_dir"] / "cases/case-0129/run/candidate/result.json"
        original = interrupted.read_bytes()
        charged = ledger.snapshot().entries
        checkpoint = arguments["output_dir"] / "progress-0385.json"
        original_checkpoint = checkpoint.read_bytes()
        with bounded_scale_phase("complete catalog resume", 1800, timings):
            arguments["loaded"] = reopen(inputs)
            final = await run_development_tree_plan(**arguments, resume=True)
        assert calls == [(name, role) for name, _ in files for role in range(3)]
        assert final.completed_attempt_count == 768
        assert final.status == "OBSERVED_ALL_AVAILABLE_STAGES"
        assert all(row.status == "OBSERVED_ALL_STAGES" for row in final.primary_statuses)
        assert final.coverage.status == "ALL_PRIMARY_RESPONSES_OBSERVED"
        assert final.coverage.successful_primary_paths == tuple(name for name, _ in files)
        assert final.coverage.not_successfully_observed_paths == ()
        assert interrupted.read_bytes() == original
        assert checkpoint.read_bytes() == original_checkpoint
        snapshot = ledger.snapshot()
        assert len(snapshot.entries) == len({row.request_id for row in snapshot.entries}) == 768
        assert all(row in snapshot.entries for row in charged)
        assert snapshot.spent_usd == final.reported_actual_cost_usd == Decimal("7.68")
        assert snapshot.active_reserved_usd == final.active_reserved_usd == 0
        assert final.uncertain_accounted_cost_usd == 0
        assert not final.audit_complete and not final.qualification_eligible
        assert not final.release_eligible
        assert (arguments["output_dir"] / "progress-0768.json").is_file()
        assert (arguments["output_dir"] / "coverage-0768.json").is_file()
        assert len(tuple(arguments["output_dir"].glob("progress-*.json"))) == 769
    finally:
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        (tmp_path / "complete-catalog-observation.json").write_text(
            json.dumps(
                {
                    "phase_seconds": timings,
                    "completed_mock_requests": calls,
                    "peak_process_rss_bytes": peak if sys.platform == "darwin" else peak * 1024,
                    "memory_measurement_scope": "process high-water mark, not per-test allocation",
                    "final_ledger": json.loads((tmp_path / "synthetic-ledger.json").read_bytes()),
                    "provider_calls": 0,
                },
                sort_keys=True,
            )
        )
