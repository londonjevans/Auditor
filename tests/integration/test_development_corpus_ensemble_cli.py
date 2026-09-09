"""Real manifest ensemble CLI with synthetic local controls and trapped external execution."""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess

import httpx
import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as development_cli
from mmaudit.benchmark.development_corpus_ensemble import DevelopmentCorpusEnsembleScore
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.development_corpus_ensemble import DevelopmentCorpusEnsembleObservation
from mmaudit.orchestration.development_corpus_ensemble import run_development_corpus_ensemble
from tests.development_corpus_benchmark_support import labelled_truth, paired_sources
from tests.development_corpus_ensemble_support import (
    manifest_ensemble_case,
    manifest_ensemble_payload,
)
from tests.development_ensemble_support import ENSEMBLE_MODELS
from tests.development_review_support import SYNTHETIC_CREDENTIAL
from tests.integration.test_development_corpus_cli import inputs

RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("manifest ensemble CLI attempted real network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def selected_inputs(tmp_path, *, scored=True):
    args, ledger, root, manifest, metadata = inputs(tmp_path)
    prepared = manifest_ensemble_case()
    for name, raw in paired_sources():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    manifest.write_text(prepared.plan.candidate.manifest.model_dump_json())
    metadata.write_text(prepared.candidate.shards[0].endpoint_snapshot.model_dump_json())
    args[1] = "ensemble-manifest"
    args[args.index("--endpoint-snapshot")] = "--candidate-endpoint-snapshot"
    args[args.index("--per-attempt-usd") + 1] = "1"
    metadata_paths = [metadata]
    for role, selected in zip(("first", "second"), prepared.reviewer_metadata, strict=True):
        path = tmp_path / f"{role}-reviewer.json"
        path.write_text(selected.model_dump_json())
        metadata_paths.append(path)
        args += [f"--{role}-reviewer-endpoint-snapshot", str(path)]
    truth_file = tmp_path / "truth.json"
    if scored:
        truth_file.write_text(labelled_truth(prepared.candidate).model_dump_json(indent=2))
        args += [
            "--truth-manifest",
            str(truth_file),
            "--truth-sha256",
            hashlib.sha256(truth_file.read_bytes()).hexdigest(),
        ]
    return args, ledger, root, metadata_paths, truth_file


@pytest.mark.parametrize("scored", [False, True])
@pytest.mark.parametrize("kind", ["complete", "empty", "partial"])
def test_cli_executes_original_stages_with_independent_allowances(
    tmp_path, monkeypatch, scored, kind
):
    args, ledger, _, _, truth_file = selected_inputs(tmp_path, scored=scored)
    allowances = (2048, 4096, 8192)
    for role, value in zip(
        ("candidate", "first-reviewer", "second-reviewer"), allowances, strict=True
    ):
        args += [f"--{role}-maximum-completion-tokens", str(value)]
    args += ["--request-timeout-seconds", "900", "--maximum-run-seconds", "1200"]
    counts = [0, 0, 0]

    def handler(request):
        body = json.loads(request.content)
        role = ENSEMBLE_MODELS.index(body["model"])
        counts[role] += 1
        assert body["max_tokens"] == allowances[role]
        assert SYNTHETIC_CREDENTIAL.encode() not in request.content
        assert b"synthetic-paired-nested-labels" not in request.content
        if scored:
            assert (tmp_path / "run/benchmark-plan.json").exists()
        if kind == "partial" and (role, counts[role]) == (1, 2):
            return httpx.Response(429, json={"error": "synthetic refusal"})
        return httpx.Response(
            200,
            json=manifest_ensemble_payload(
                role,
                counts[role],
                count=0 if kind == "empty" else 1,
                verdict="REFUTED" if role == 2 else "SUPPORTED",
            ),
        )

    async def execute(**kwargs):
        assert kwargs["prepared"].plan.policy.request_timeout_seconds == 900
        assert kwargs["prepared"].plan.maximum_run_seconds == 1200
        return await run_development_corpus_ensemble(
            **kwargs, mock_transport=httpx.MockTransport(handler)
        )

    monkeypatch.setattr(development_cli, "run_development_corpus_ensemble", execute)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(
        ExitCode.INCOMPLETE if kind == "partial" else ExitCode.SUCCESS
    ), result.output
    observation = DevelopmentCorpusEnsembleObservation.model_validate_json(
        result.stdout, strict=True
    )
    assert counts == {"complete": [6, 3, 3], "empty": [6, 0, 0], "partial": [6, 2, 0]}[kind]
    assert len(ledger.snapshot().entries) == sum(counts)
    assert observation.total_accounted_cost_usd == ledger.snapshot().spent_usd
    assert not observation.audit_complete and SYNTHETIC_CREDENTIAL not in result.output
    if scored:
        score = DevelopmentCorpusEnsembleScore.model_validate_json(
            (tmp_path / "run/score.json").read_bytes(), strict=True
        )
        assert score.observation == observation
        assert score.binding.truth_file_content.encode() == truth_file.read_bytes()
        assert score.candidate_score.observation == observation.candidate
    else:
        assert not (tmp_path / "run/score.json").exists()


@pytest.mark.parametrize(
    "flag", ["--accept-estimate-risk", "--allow-code-egress", "--truth-manifest", "--truth-sha256"]
)
def test_missing_consent_or_orphan_truth_refuses_before_input_reads(tmp_path, monkeypatch, flag):
    args, ledger, _, _, _ = selected_inputs(tmp_path)
    index = args.index(flag)
    del args[index : index + (2 if flag.startswith("--truth-") else 1)]

    def forbidden(*_args, **_kwargs):
        pytest.fail("missing explicit selection reached input handling")

    for name in (
        "load_development_corpus",
        "read_json_evidence",
        "load_operator_secrets",
        "run_development_corpus_ensemble",
    ):
        monkeypatch.setattr(development_cli, name, forbidden)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.CONFIGURATION)
    assert not ledger.snapshot().entries and not (tmp_path / "run").exists()


@pytest.mark.parametrize(
    "kind",
    [
        "relative",
        "duplicate",
        "output_overlap",
        "source_output",
        "wrong_pin",
        "malformed_truth",
        "duplicate_truth",
        "nonfinite_truth",
        "oversize_truth",
        "truth_link",
        "same_role",
        "malformed_metadata",
        "headroom",
        "source_drift",
        "metadata_drift",
        "truth_drift",
    ],
)
def test_bad_binding_or_preflight_refuses_before_credentials_and_dispatch(
    tmp_path, monkeypatch, kind
):
    args, ledger, root, metadata, truth = selected_inputs(tmp_path)

    def replace(flag, value):
        args[args.index(flag) + 1] = value

    if kind == "relative":
        replace("--corpus-root", "relative")
    elif kind == "duplicate":
        replace("--second-reviewer-endpoint-snapshot", str(metadata[1]))
    elif kind == "output_overlap":
        replace("--output-dir", str(tmp_path))
    elif kind == "source_output":
        replace("--output-dir", str(root / "out"))
    elif kind == "wrong_pin":
        replace("--truth-sha256", "a" * 64)
    elif kind in {"malformed_truth", "duplicate_truth", "nonfinite_truth", "oversize_truth"}:
        truth.write_text(
            {
                "malformed_truth": "{",
                "duplicate_truth": '{"truth_id":"duplicate",' + truth.read_text()[1:],
                "nonfinite_truth": '{"truth_id":NaN}',
                "oversize_truth": " " * 2_000_001,
            }[kind]
        )
        replace("--truth-sha256", hashlib.sha256(truth.read_bytes()).hexdigest())
    elif kind == "truth_link":
        original = tmp_path / "original-truth.json"
        truth.rename(original)
        truth.symlink_to(original)
    elif kind == "same_role":
        metadata[2].write_bytes(metadata[1].read_bytes())
    elif kind == "malformed_metadata":
        metadata[0].write_text("{")
    elif kind == "headroom":
        replace("--per-attempt-usd", "5")
    else:
        prepare = development_cli.prepare_development_corpus_ensemble

        def drift(**kwargs):
            prepared = prepare(**kwargs)
            target = (
                root / paired_sources()[0][0]
                if kind == "source_drift"
                else metadata[2]
                if kind == "metadata_drift"
                else truth
            )
            target.write_text("changed")
            return prepared

        monkeypatch.setattr(development_cli, "prepare_development_corpus_ensemble", drift)

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid manifest ensemble inputs reached credentials or dispatch")

    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    monkeypatch.setattr(development_cli, "run_development_corpus_ensemble", forbidden)
    before = ledger.path.read_bytes()
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    assert ledger.path.read_bytes() == before and not (tmp_path / "run").exists()
    assert SYNTHETIC_CREDENTIAL not in result.output
