"""Mock primary-only execution and provider-free coverage retain every dependency and liability."""

from __future__ import annotations

import json
import socket
import subprocess
from dataclasses import replace

import httpx
import pytest
from typer.testing import CliRunner

from mmaudit import development_cli
from mmaudit.cli import app
from mmaudit.models.development_corpus import DevelopmentCorpusMaterial
from mmaudit.models.development_corpus_coverage import read_development_corpus_coverage
from mmaudit.models.development_corpus_resume import prepare_development_corpus_resume
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration import development_corpus_coverage as coverage_io
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.development_corpus import run_development_corpus
from mmaudit.orchestration.development_corpus_resume import (
    read_development_corpus_resume_inputs,
    run_development_corpus_resume,
)
from mmaudit.repository.development_corpus import load_development_corpus
from tests.development_corpus_ensemble_support import manifest_ensemble_case
from tests.development_corpus_judgment_support import selected_policy
from tests.development_corpus_support import corpus_payload
from tests.development_review_support import SYNTHETIC_CREDENTIAL
from tests.integration.test_development_call_closure_custody import tree_inputs
from tests.integration.test_development_corpus_ensemble_execution import (
    execute,
    execution_case,
    response_payload,
    retained,
)
from tests.unit.test_development_context_sources import partitioned_tree, prepared_partition
from tests.unit.test_development_corpus_coverage import candidate


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("context-source work attempted network, subprocess or secret loading")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)


def coverage_files(tmp_path):
    loaded = partitioned_tree(tmp_path)
    _, observation = candidate(loaded)
    path = tmp_path / "retained.json"
    path.write_text(observation.model_dump_json())
    return loaded, path


@pytest.mark.asyncio
@pytest.mark.parametrize("claims", [0, 1])
@pytest.mark.parametrize(
    "primaries", [("src/Controller.sol",), ("src/Controller.sol", "src/SecondReserve.sol")]
)
async def test_one_primary_retains_all_context_for_candidate_and_both_reviewers(
    tmp_path, claims, primaries
):
    loaded = partitioned_tree(tmp_path, primaries)
    manifest = loaded.material.manifest
    prepared = manifest_ensemble_case(
        source_files=loaded.material.source_files,
        manifest=manifest,
        policy=selected_policy(total="60", per_attempt="3"),
        source_custody=loaded,
    )
    case = execution_case(tmp_path, prepared=prepared, scored=False, claims=claims)
    assert len(prepared.candidate.shards) == len(primaries)

    def inspect(role, ordinal, request):
        primary = prepared.candidate.shards[ordinal - 1]
        assert 1 <= ordinal <= len(primaries)
        prompt = json.loads(request.content)["messages"][1]["content"]
        assert "context presence is not primary review" in prompt
        for name, raw in loaded.material.source_files:
            assert f"Source file: {name}" in prompt
            assert (
                "\n".join(f"{i}: {line}" for i, line in enumerate(raw.decode().splitlines(), 1))
                in prompt
            )
        payload = response_payload(prepared, role, ordinal, claims=claims)
        payload["choices"][0]["message"]["content"] = payload["choices"][0]["message"][
            "content"
        ].replace(f"file-{ordinal:04d}", primary.shard_id)
        return httpx.Response(200, json=payload)

    result = await execute(case, custom=inspect)
    assert result == retained(case)
    assert case.counts == ([len(primaries)] * 3 if claims else [len(primaries), 0, 0])
    assert len(case.ledger.snapshot().entries) == len(primaries) * (3 if claims else 1)
    assert result.candidate.completed_shard_count == len(primaries)
    assert result.candidate.selected_primary_line_count == sum(
        s.line_count for s in manifest.primary_sources
    )
    material = DevelopmentCorpusMaterial.model_validate_json(
        (case.root / "candidate/sources.json").read_bytes(), strict=True
    )
    assert material == loaded.material
    if claims:
        assert result.candidate.observations[0].response.findings[0].root_cause_ref.filename in {
            s.filename for s in manifest.context_sources
        }
    assert not result.audit_complete and result.lineage_independence == "NOT_ESTABLISHED"


@pytest.mark.asyncio
async def test_changed_context_request_refuses_before_any_reservation(tmp_path):
    loaded = partitioned_tree(tmp_path)
    prepared = prepared_partition(loaded)
    shard = prepared.shards[0]
    changed = shard.request_content.replace(
        b"context presence is not primary review", b"all context was reviewed", 1
    )
    assert changed != shard.request_content
    forged = replace(prepared, shards=(replace(shard, request_content=changed),))
    ledger = AtomicCostLedger.initialize(
        tmp_path / "ledger.json", cap_usd=prepared.plan.policy.total_budget_usd
    )
    with pytest.raises(ValueError):
        await run_development_corpus(
            prepared=forged,
            ledger=ledger,
            operator_secrets=OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL}),
            output_dir=tmp_path / "run",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(lambda _: pytest.fail("unexpected request")),
        )
    assert not ledger.snapshot().entries and not (tmp_path / "run").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("unknown", [False, True])
async def test_primary_failure_continuation_and_coverage_keep_original_costs_and_history(
    tmp_path, unknown
):
    loaded = partitioned_tree(tmp_path)
    prepared = prepared_partition(loaded)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "ledger.json", cap_usd=prepared.plan.policy.total_budget_usd
    )
    secrets = OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL})
    calls = []

    def fail(request):
        calls.append(request.content)
        if unknown:
            return httpx.Response(429, json={"error": {"message": "Synthetic missing usage."}})
        payload = corpus_payload(1, count=0)
        payload["choices"][0]["message"]["content"] = "{}"
        return httpx.Response(200, json=payload)

    original = await run_development_corpus(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "original",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(fail),
    )
    assert len(calls) == len(ledger.snapshot().entries) == 1
    assert original.status == "INCOMPLETE" and original.completed_shard_count == 0
    original_bytes = (tmp_path / "original/result.json").read_bytes()
    original_rows = ledger.snapshot().entries
    inputs = read_development_corpus_resume_inputs(
        candidate_file=tmp_path / "original/result.json",
        material_file=tmp_path / "original/sources.json",
    )
    resumed = prepare_development_corpus_resume(
        history=inputs.history,
        endpoint_snapshot=prepared.shards[0].endpoint_snapshot,
        run_id="synthetic-context-continuation",
        source_custody=loaded,
    )
    if unknown:
        with pytest.raises(ValueError):
            await run_development_corpus_resume(
                prepared=resumed,
                ledger=ledger,
                operator_secrets=secrets,
                output_dir=tmp_path / "continued",
                allow_code_egress=True,
                mock_transport=httpx.MockTransport(
                    lambda _: pytest.fail("unknown billing must stop work")
                ),
                inputs=inputs,
            )
        assert ledger.snapshot().entries == original_rows
        assert original_rows[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        record_file = tmp_path / "original/result.json"
    else:

        def succeed(request):
            calls.append(request.content)
            assert b"context presence is not primary review" in request.content
            payload = corpus_payload(1, count=0)
            payload["id"] = "gen-synthetic-context-continuation"
            return httpx.Response(200, json=payload)

        history = await run_development_corpus_resume(
            prepared=resumed,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "continued",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(succeed),
            inputs=inputs,
        )
        assert (
            history.original == original and history.summary.cumulative_completed_shard_count == 1
        )
        assert len(calls) == len(ledger.snapshot().entries) == 2
        rows_by_id = {row.request_id: row for row in ledger.snapshot().entries}
        assert all(rows_by_id[row.request_id] == row for row in original_rows)
        record_file = tmp_path / "continued/result.json"
    assert (tmp_path / "original/result.json").read_bytes() == original_bytes
    costs = ledger.snapshot()
    result = coverage_io.measure_development_corpus_coverage_files(
        manifest_file=loaded.manifest_file,
        corpus_root=loaded.corpus_root,
        record_files=(record_file,),
        output_dir=tmp_path / "coverage",
    )
    assert ledger.snapshot() == costs
    assert result.summary.original_successful_primary_paths == ()
    assert result.summary.successful_primary_paths == (() if unknown else ("src/Controller.sol",))
    assert result.summary.status == "INCOMPLETE" and len(result.summary.context_only_paths) == 4
    assert result.summary.failed_primary_paths == ("src/Controller.sol",)


def test_explicit_primary_cli_and_offline_coverage_emit_private_exact_records(tmp_path):
    inputs = tree_inputs(tmp_path)
    frozen = tmp_path / "frozen"
    result = CliRunner().invoke(
        app,
        [
            "development",
            "freeze-tree",
            "--primary-source",
            "src/Controller.sol",
            "--corpus-root",
            str(inputs["corpus_root"]),
            "--remappings-file",
            str(inputs["remappings_file"]),
            "--corpus-id",
            inputs["corpus_id"],
            "--source-scope",
            inputs["source_scope"],
            "--output-dir",
            str(frozen),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "1 primary and 4 context-only" in result.output
    loaded = load_development_corpus(
        manifest_file=frozen / "manifest.json", corpus_root=inputs["corpus_root"]
    )
    _, observation = candidate(loaded)
    path = tmp_path / "record.json"
    path.write_text(observation.model_dump_json())
    output = tmp_path / "coverage"
    result = CliRunner().invoke(
        app,
        [
            "development",
            "corpus-coverage",
            "--manifest-file",
            str(loaded.manifest_file),
            "--corpus-root",
            str(loaded.corpus_root),
            "--record-file",
            str(path),
            "--output-dir",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "INCOMPLETE; 1/5" in result.output
    coverage = read_development_corpus_coverage((output / "coverage.json").read_bytes())
    assert coverage.records == (observation,)
    assert output.stat().st_mode & 0o777 == 0o700
    assert (output / "coverage.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "change",
    ["record_bytes", "record_object", "source_bytes", "source_object", "new_source", "manifest"],
)
def test_coverage_rechecks_original_input_objects_and_source_root_before_writing(
    tmp_path, monkeypatch, change
):
    loaded, record = coverage_files(tmp_path)
    compute = coverage_io.compute_development_corpus_coverage
    source = loaded.corpus_root / loaded.material.manifest.context_sources[0].filename

    def mutate(**kwargs):
        result = compute(**kwargs)
        path = (
            record
            if change.startswith("record")
            else loaded.manifest_file
            if change == "manifest"
            else source
        )
        if change.endswith("object"):
            content = path.read_bytes()
            path.rename(tmp_path / "old-object")
            path.write_bytes(content)
        elif change == "new_source":
            (loaded.corpus_root / "Extra.sol").write_bytes(b"// Synthetic extra source.\n")
        else:
            path.write_bytes(path.read_bytes() + b"\n")
        return result

    monkeypatch.setattr(coverage_io, "compute_development_corpus_coverage", mutate)
    with pytest.raises(ValueError):
        coverage_io.measure_development_corpus_coverage_files(
            manifest_file=loaded.manifest_file,
            corpus_root=loaded.corpus_root,
            record_files=(record,),
            output_dir=tmp_path / "coverage",
        )
    assert not (tmp_path / "coverage").exists()


@pytest.mark.parametrize("kind", ["duplicate", "symlink", "overlap", "existing", "oversized"])
def test_coverage_refuses_invalid_inputs_or_output_without_overwriting(tmp_path, monkeypatch, kind):
    loaded, record = coverage_files(tmp_path)
    output = tmp_path / "coverage"
    records = (record,)
    if kind == "duplicate":
        records = (record, record)
    elif kind == "symlink":
        link = tmp_path / "linked.json"
        link.symlink_to(record)
        records = (link,)
    elif kind == "overlap":
        output = loaded.corpus_root / "coverage"
    elif kind == "existing":
        output.mkdir()
        (output / "keep.txt").write_text("synthetic existing data")
    else:
        monkeypatch.setattr(coverage_io, "MAX_DEVELOPMENT_COVERAGE_BYTES", 10)
    before = record.read_bytes()
    with pytest.raises(FileExistsError if kind == "existing" else ValueError):
        coverage_io.measure_development_corpus_coverage_files(
            manifest_file=loaded.manifest_file,
            corpus_root=loaded.corpus_root,
            record_files=records,
            output_dir=output,
        )
    assert record.read_bytes() == before
    if kind == "existing":
        assert (output / "keep.txt").read_text() == "synthetic existing data"
