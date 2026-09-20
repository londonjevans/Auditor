"""Standalone CLI root replay with real retained artifacts and mock transport, never real secrets."""

import asyncio
import json
import socket
import subprocess
from contextlib import contextmanager
from decimal import Decimal

import httpx
import pytest
from typer.testing import CliRunner

from mmaudit import development_cli as cli
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.development_corpus import run_development_corpus
from mmaudit.orchestration.development_corpus_ensemble import run_development_corpus_ensemble
from mmaudit.orchestration.development_corpus_judgment import run_development_corpus_judgment
from mmaudit.orchestration.development_corpus_repeats import run_development_corpus_repeats
from mmaudit.orchestration.development_corpus_resume import (
    read_development_corpus_resume_inputs,
    run_development_corpus_resume,
)
from tests.development_corpus_benchmark_support import truth_binding
from tests.development_corpus_ensemble_support import manifest_ensemble_case
from tests.development_corpus_judgment_support import manifest_judgment_payload
from tests.development_corpus_repeats_support import repeat_payload
from tests.development_corpus_support import corpus_payload
from tests.development_ensemble_support import ENSEMBLE_MODELS
from tests.development_review_support import SYNTHETIC_CREDENTIAL
from tests.development_source_custody_support import candidate_case, custody_metadata, loaded_case
from tests.integration.test_development_corpus_ensemble_execution import response_payload
from tests.integration.test_development_source_custody import candidate_run


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("source-root CLI attempted real network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.mark.parametrize("mode", ["judge", "resume-original", "resume-history"])
def test_standalone_cli_requires_exact_paired_root_before_secrets_then_executes_unchanged_history(
    tmp_path, monkeypatch, mode
):
    reviewing = mode == "judge"
    case = asyncio.run(candidate_run(tmp_path, partial=not reviewing))
    original_path = tmp_path / "original/result.json"
    original_bytes = original_path.read_bytes()
    original_cost = case.ledger.snapshot().spent_usd
    metadata = tmp_path / "metadata.json"
    metadata.write_text(
        (
            custody_metadata(model_id="synthetic/development-reviewer")
            if reviewing
            else case.prepared.shards[0].endpoint_snapshot
        ).model_dump_json()
    )
    secret_file = tmp_path / "synthetic-secrets-input.txt"
    # No secret file exists: the test supplies only an in-memory synthetic credential.
    assert not secret_file.exists()
    output = tmp_path / "review-or-resume"
    args = [
        "development",
        "judge-manifest" if reviewing else "resume-manifest",
        "--endpoint-snapshot",
        str(metadata),
        "--cost-ledger",
        str(case.ledger.path),
        "--secrets-env-file",
        str(secret_file),
        "--output-dir",
        str(output),
        "--run-id",
        "synthetic-cli-root-handoff",
        "--accept-estimate-risk",
        "--allow-code-egress",
    ]
    if mode == "resume-history":
        inputs = read_development_corpus_resume_inputs(
            candidate_file=original_path, material_file=tmp_path / "original/sources.json"
        )
        history_path = tmp_path / "history.json"
        history_path.write_text(inputs.history.model_dump_json())
        args += ["--history-file", str(history_path)]
    else:
        args += [
            "--candidate-audit-file",
            str(original_path),
            "--source-material-file",
            str(tmp_path / "original/sources.json"),
        ]
    if reviewing:
        args += ["--budget-usd", "250", "--per-attempt-usd", "10"]
    secret_loads, calls = [], []

    @contextmanager
    def synthetic_secrets(path, **kwargs):
        assert path == secret_file and kwargs == {"environ": {}, "required": True}
        secret_loads.append(path)
        yield case.secrets

    async def execute(**kwargs):
        prepared = kwargs["prepared"]
        selected = (
            prepared.shards
            if reviewing
            else tuple(
                s
                for s in prepared.candidate.shards
                if s.shard_id in prepared.plan.selected_shard_ids
            )
        )
        assert all(s.source_custody.material == case.loaded.material for s in selected)

        def handler(request):
            shard = selected[len(calls)]
            assert request.content == shard.request_content
            calls.append(shard.shard_id)
            ordinal = int(shard.shard_id[-4:])
            payload = (
                manifest_judgment_payload(ordinal, filename=shard.source_filename)
                if reviewing
                else corpus_payload(ordinal)
            )
            payload["id"] = "gen-synthetic-cli-root-handoff-" + shard.shard_id
            return httpx.Response(200, json=payload)

        run = run_development_corpus_judgment if reviewing else run_development_corpus_resume
        return await run(**kwargs, mock_transport=httpx.MockTransport(handler))

    monkeypatch.setattr(cli, "load_operator_secrets", synthetic_secrets)
    monkeypatch.setattr(
        cli,
        "run_development_corpus_judgment" if reviewing else "run_development_corpus_resume",
        execute,
    )
    other = loaded_case(tmp_path / "other", version="1.3")
    invalid_extras = (
        [],
        ["--source-manifest", str(case.loaded.manifest_file)],
        ["--corpus-root", str(case.loaded.corpus_root)],
        ["--source-manifest", str(other.manifest_file), "--corpus-root", str(other.corpus_root)],
        ["--source-manifest", str(case.loaded.manifest_file), "--corpus-root", str(output)],
    )
    ledger_bytes = case.ledger.path.read_bytes()
    for extra in invalid_extras:
        result = CliRunner().invoke(app, args + extra)
        assert result.exit_code == ExitCode.CONFIGURATION, result.output
        assert not secret_loads and not calls and not output.exists()
        assert case.ledger.path.read_bytes() == ledger_bytes
        assert str(tmp_path) not in result.output and SYNTHETIC_CREDENTIAL not in result.output
    result = CliRunner().invoke(
        app,
        [
            *args,
            "--source-manifest",
            str(case.loaded.manifest_file),
            "--corpus-root",
            str(case.loaded.corpus_root),
        ],
    )
    assert result.exit_code == 0, result.output
    value = json.loads(result.stdout)
    if reviewing:
        assert value["status"] == "OBSERVED_ALL_JUDGMENTS"
    else:
        assert value["summary"]["status"] == "OBSERVED_ALL_SOURCES_ACROSS_RECORDED_ATTEMPTS"
        assert "file-0001" not in calls
    assert len(secret_loads) == 1 and len(calls) == (6 if reviewing else 5)
    assert original_path.read_bytes() == original_bytes
    assert case.ledger.snapshot().spent_usd == original_cost + Decimal("0.01") * len(calls)
    assert str(tmp_path) not in result.output and SYNTHETIC_CREDENTIAL not in result.output


@pytest.mark.parametrize("mode", ["audit", "ensemble", "repeat"])
def test_ingestion_cli_automatically_carries_tree_custody_through_actual_mock_execution(
    tmp_path, monkeypatch, mode
):
    loaded = loaded_case(tmp_path)
    candidate = candidate_case(loaded)
    ledger = AtomicCostLedger.initialize(tmp_path / "ledger.json", cap_usd=Decimal("250"))
    secrets = OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL})
    secret_file = tmp_path / "synthetic-secrets-input.txt"
    output = tmp_path / "run"
    args = [
        "development",
        mode + "-manifest",
        "--source-manifest",
        str(loaded.manifest_file),
        "--corpus-root",
        str(loaded.corpus_root),
        "--cost-ledger",
        str(ledger.path),
        "--secrets-env-file",
        str(secret_file),
        "--output-dir",
        str(output),
        "--run-id",
        "synthetic-cli-tree-ingestion",
        "--budget-usd",
        "250",
        "--per-attempt-usd",
        "10",
        "--accept-estimate-risk",
        "--allow-code-egress",
    ]
    metadata = tmp_path / "metadata.json"
    metadata.write_text(candidate.shards[0].endpoint_snapshot.model_dump_json())
    expected_ensemble = None
    if mode == "ensemble":
        expected_ensemble = manifest_ensemble_case(
            manifest=loaded.material.manifest,
            source_files=loaded.material.source_files,
            source_custody=loaded,
            policy=candidate.plan.policy,
            candidate_metadata=custody_metadata(model_id=ENSEMBLE_MODELS[0]),
            reviewer_metadata=tuple(custody_metadata(model_id=m) for m in ENSEMBLE_MODELS[1:]),
        )
        for index, (option, model_id) in enumerate(
            zip(
                (
                    "--candidate-endpoint-snapshot",
                    "--first-reviewer-endpoint-snapshot",
                    "--second-reviewer-endpoint-snapshot",
                ),
                ENSEMBLE_MODELS,
                strict=True,
            )
        ):
            path = tmp_path / f"role-{index}.json"
            path.write_text(custody_metadata(model_id=model_id).model_dump_json())
            args += [option, str(path)]
    else:
        args += ["--endpoint-snapshot", str(metadata)]
    if mode == "repeat":
        binding = truth_binding(candidate)
        truth = tmp_path / "truth.json"
        truth.write_bytes(binding.truth_file_content.encode())
        args += [
            "--truth-manifest",
            str(truth),
            "--truth-sha256",
            binding.truth_file_sha256,
            "--trial-count",
            "2",
        ]
    calls, roles = [], [0, 0, 0]

    @contextmanager
    def synthetic_secrets(path, **kwargs):
        assert path == secret_file and kwargs == {"environ": {}, "required": True}
        yield secrets

    async def execute(**kwargs):
        prepared = kwargs["prepared"]
        first = (
            prepared.candidate
            if mode == "ensemble"
            else prepared.trials[0]
            if mode == "repeat"
            else prepared
        ).shards[0]
        assert first.source_custody.material == loaded.material
        assert first.source_custody.corpus_root == loaded.corpus_root

        def handler(request):
            calls.append(request)
            if mode == "ensemble":
                role = ENSEMBLE_MODELS.index(json.loads(request.content)["model"])
                roles[role] += 1
                payload = response_payload(expected_ensemble, role, roles[role])
            elif mode == "repeat":
                payload = repeat_payload(len(calls))
            else:
                payload = corpus_payload(len(calls))
            return httpx.Response(200, json=payload)

        run = {
            "audit": run_development_corpus,
            "ensemble": run_development_corpus_ensemble,
            "repeat": run_development_corpus_repeats,
        }[mode]
        return await run(**kwargs, mock_transport=httpx.MockTransport(handler))

    monkeypatch.setattr(cli, "load_operator_secrets", synthetic_secrets)
    target = {
        "audit": "run_development_corpus",
        "ensemble": "run_development_corpus_ensemble",
        "repeat": "run_development_corpus_repeats",
    }[mode]
    monkeypatch.setattr(cli, target, execute)
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    recorded = json.loads((output / "result.json").read_bytes())
    assert (
        recorded["status"]
        == {
            "audit": "OBSERVED_ALL_SHARDS",
            "ensemble": "OBSERVED_ALL_STAGES",
            "repeat": "COMPLETE",
        }[mode]
    )
    assert len(calls) == (6 if mode == "audit" else 12)
    assert ledger.snapshot().spent_usd == Decimal("0.01") * len(calls)
    assert str(tmp_path) not in json.dumps(recorded) and SYNTHETIC_CREDENTIAL not in result.output
