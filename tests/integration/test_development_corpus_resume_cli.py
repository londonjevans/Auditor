"""Explicit continuation CLI with real evidence/ledger handling and synthetic transport only."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
from dataclasses import replace
from decimal import Decimal

import httpx
import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as development_cli
from mmaudit.benchmark.development_corpus import score_development_corpus
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.development_corpus_resume import DevelopmentCorpusResumeHistory
from mmaudit.orchestration.development_corpus_resume import (
    read_development_corpus_resume_inputs,
    require_development_corpus_resume_inputs,
    run_development_corpus_resume,
)
from tests.development_corpus_benchmark_support import paired_sources, truth_binding
from tests.development_corpus_support import corpus_payload
from tests.development_review_support import SYNTHETIC_CREDENTIAL
from tests.integration.test_development_corpus_resume_execution import execution_case

RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("continuation CLI attempted actual network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def cli_case(tmp_path, *, mode="original", claims=1, endpoint_snapshot=None):
    case = asyncio.run(
        execution_case(
            tmp_path,
            claims=claims,
            source_files=paired_sources() if mode == "score" else None,
            endpoint_snapshot=endpoint_snapshot,
        )
    )
    metadata = tmp_path / "metadata.json"
    first = case.original_prepared.shards[0]
    metadata.write_text((first.discovery or first.endpoint_snapshot).model_dump_json())
    secret = tmp_path / "synthetic-secrets.txt"
    secret.write_text("OPENROUTER_API_KEY=" + SYNTHETIC_CREDENTIAL + "\n")
    secret.chmod(0o600)
    args = [
        "development",
        "resume-manifest",
        "--endpoint-snapshot",
        str(metadata),
        "--cost-ledger",
        str(case.ledger.path),
        "--secrets-env-file",
        str(secret),
        "--output-dir",
        str(tmp_path / "resume"),
        "--run-id",
        "synthetic-cli-continuation",
        "--accept-estimate-risk",
        "--allow-code-egress",
    ]
    if mode == "history":
        history = tmp_path / "history.json"
        history.write_text(case.inputs.history.model_dump_json())
        args += ["--history-file", str(history)]
    else:
        args += [
            "--candidate-audit-file",
            str(tmp_path / "original/result.json"),
            "--source-material-file",
            str(tmp_path / "original/sources.json"),
        ]
    if mode == "score":
        score = score_development_corpus(
            binding=truth_binding(case.original_prepared), observation=case.original
        )
        score_file = tmp_path / "original-score.json"
        score_file.write_text(score.model_dump_json(indent=2))
        args += ["--original-score-file", str(score_file)]
    return case, args, metadata


def mocked(monkeypatch, case, *, claims=1, fail=False, mutate=None):
    async def execute(**kwargs):
        selected = kwargs["prepared"]

        def handler(request):
            shard = next(
                s for s in selected.candidate.shards if s.request_content == request.content
            )
            case.calls.append((selected.plan.candidate.run_id, shard.shard_id))
            assert shard.shard_id in selected.plan.selected_shard_ids
            assert (
                request.content
                == case.original_prepared.shards[int(shard.shard_id[-4:]) - 1].request_content
            )
            assert shard.source_files == case.original_prepared.shards[0].source_files
            assert SYNTHETIC_CREDENTIAL.encode() not in request.content
            if mutate is not None:
                mutate()
            if fail:
                return httpx.Response(429, json={"error": {"message": "synthetic unknown usage"}})
            payload = corpus_payload(int(shard.shard_id[-4:]), count=claims)
            payload["id"] = f"gen-{selected.plan.candidate.run_id}-{shard.shard_id}"
            return httpx.Response(200, json=payload)

        return await run_development_corpus_resume(
            **kwargs, mock_transport=httpx.MockTransport(handler)
        )

    monkeypatch.setattr(development_cli, "run_development_corpus_resume", execute)


@pytest.mark.parametrize("mode", ["original", "history", "score"])
@pytest.mark.parametrize("claims", [0, 1])
def test_cli_completes_only_original_gaps_and_retains_first_attempt_and_optional_score(
    tmp_path, monkeypatch, mode, claims
):
    case, args, _ = cli_case(tmp_path, mode=mode, claims=claims)
    before = case.ledger.snapshot().entries
    score_file = tmp_path / "original-score.json"
    raw_score = score_file.read_bytes() if mode == "score" else None
    mocked(monkeypatch, case, claims=claims)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == 0, result.output
    history = DevelopmentCorpusResumeHistory.model_validate_json(result.stdout, strict=True)
    expected = 6 if mode == "score" else 4
    assert history.summary.cumulative_completed_shard_count == expected
    assert history.summary.candidate_claim_count == expected * claims
    assert len(case.calls) == expected - 1
    assert history.summary.total_accounted_cost_usd == Decimal("0.01") * (expected + 1)
    assert history.original == case.original
    assert history.summary.original_first_attempt_completed_shard_count == 1
    assert all(e in case.ledger.snapshot().entries for e in before)
    assert all(p.read_bytes() == b for p, b in case.prior_bytes.items())
    assert SYNTHETIC_CREDENTIAL not in result.output
    if raw_score is not None:
        assert score_file.read_bytes() == raw_score
        assert history.original_score.model_dump(mode="json") == json.loads(raw_score)
        assert history.original_score.summary.quality_scope == "INCOMPLETE_OBSERVATIONS"
        assert (
            history.original_score.binding.truth_file_content
            == truth_binding(case.original_prepared).truth_file_content
        )
    assert not history.audit_complete and not history.qualification_eligible


def test_cli_unknown_new_response_returns_incomplete_and_retains_durable_liability(
    tmp_path, monkeypatch
):
    case, args, _ = cli_case(tmp_path)
    mocked(monkeypatch, case, fail=True)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.INCOMPLETE), result.output
    history = DevelopmentCorpusResumeHistory.model_validate_json(result.stdout, strict=True)
    assert history.summary.cumulative_completed_shard_count == 1
    assert len(case.calls) == 1 and history.summary.accounted_request_count == 3
    assert history.summary.uncertain_accounted_cost_usd > 0
    assert history.summary.total_accounted_cost_usd == case.ledger.snapshot().spent_usd
    assert (tmp_path / "resume/result.json").exists()


@pytest.mark.parametrize(
    "kind",
    [
        "estimate_consent",
        "egress_consent",
        "no_candidate",
        "no_material",
        "mixed_history",
        "relative",
        "duplicate",
        "ancestor",
    ],
)
def test_bad_selection_refuses_before_input_ledger_or_credential_handling(
    tmp_path, monkeypatch, kind
):
    case, args, _ = cli_case(tmp_path)
    if kind.endswith("consent"):
        args.remove(
            "--accept-estimate-risk" if kind == "estimate_consent" else "--allow-code-egress"
        )
    elif kind in {"no_candidate", "no_material"}:
        flag = "--candidate-audit-file" if kind == "no_candidate" else "--source-material-file"
        i = args.index(flag)
        del args[i : i + 2]
    elif kind == "mixed_history":
        args += ["--history-file", str(tmp_path / "history.json")]
    else:
        args[args.index("--output-dir") + 1] = (
            "relative-output"
            if kind == "relative"
            else str(case.ledger.path)
            if kind == "duplicate"
            else str(tmp_path)
        )

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid selection reached input or credential handling")

    monkeypatch.setattr(development_cli, "read_development_corpus_resume_inputs", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    monkeypatch.setattr(development_cli, "run_development_corpus_resume", forbidden)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.CONFIGURATION)
    assert len(case.ledger.snapshot().entries) == 2 and not (tmp_path / "resume").exists()


@pytest.mark.parametrize(
    "kind",
    [
        "malformed",
        "duplicate_json",
        "nonfinite",
        "oversize",
        "symlink",
        "hardlink",
        "fifo",
        "metadata",
        "score_join",
    ],
)
def test_bad_bound_evidence_refuses_before_credentials_or_dispatch(tmp_path, monkeypatch, kind):
    case, args, metadata = cli_case(tmp_path, mode="score" if kind == "score_join" else "original")
    target = tmp_path / "original/result.json"
    if kind == "malformed":
        target.write_text("{invalid")
    elif kind == "duplicate_json":
        target.write_bytes(target.read_bytes().replace(b"{", b'{"status":"INCOMPLETE",', 1))
    elif kind == "nonfinite":
        data = json.loads(target.read_bytes())
        data["elapsed_seconds"] = float("nan")
        target.write_text(json.dumps(data))
    elif kind == "oversize":
        target.write_bytes(b" " * 16_000_001)
    elif kind in {"symlink", "hardlink", "fifo"}:
        retained = target.with_name("retained-result.json")
        target.rename(retained)
        if kind == "symlink":
            target.symlink_to(retained)
        elif kind == "hardlink":
            os.link(retained, target)
        else:
            os.mkfifo(target)
    elif kind == "metadata":
        metadata.write_text("{}")
    else:
        score = tmp_path / "original-score.json"
        data = json.loads(score.read_bytes())
        data["observation"]["elapsed_seconds"] += 1
        score.write_text(json.dumps(data))

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid evidence reached credentials or dispatch")

    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    monkeypatch.setattr(development_cli, "run_development_corpus_resume", forbidden)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.CONFIGURATION)
    assert len(case.ledger.snapshot().entries) == 2 and not (tmp_path / "resume").exists()
    assert SYNTHETIC_CREDENTIAL not in result.output


@pytest.mark.parametrize("when", ["before_dispatch", "during_dispatch"])
@pytest.mark.parametrize("kind", ["metadata", "candidate", "material", "score", "history"])
def test_cli_never_rebases_replaced_input_files_around_control_handling_or_dispatch(
    tmp_path, monkeypatch, when, kind
):
    case, args, metadata = cli_case(tmp_path, mode="history" if kind == "history" else "score")
    target = {
        "metadata": metadata,
        "candidate": tmp_path / "original/result.json",
        "material": tmp_path / "original/sources.json",
        "score": tmp_path / "original-score.json",
        "history": tmp_path / "history.json",
    }[kind]

    def mutate():
        raw = target.read_bytes()
        target.rename(target.with_suffix(".retained"))
        target.write_bytes(raw)
        target.chmod(0o600)

    if when == "before_dispatch":
        real_loader = development_cli.load_operator_secrets

        def changed_loader(*a, **kw):
            mutate()
            return real_loader(*a, **kw)

        monkeypatch.setattr(development_cli, "load_operator_secrets", changed_loader)
    mocked(monkeypatch, case, mutate=mutate if when == "during_dispatch" else None)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    expected = 1 if when == "during_dispatch" else 0
    assert len(case.calls) == expected
    assert len(case.ledger.snapshot().entries) == 2 + expected
    assert not (tmp_path / "resume/result.json").exists()
    assert SYNTHETIC_CREDENTIAL not in result.output


@pytest.mark.parametrize("kind", ["short", "reversed", "empty", "leaf", "role", "missing_metadata"])
def test_input_custody_requires_full_ancestry_and_exact_role_bindings(tmp_path, kind):
    case, _args, metadata = cli_case(tmp_path)
    inputs = read_development_corpus_resume_inputs(
        candidate_file=tmp_path / "original/result.json",
        material_file=tmp_path / "original/sources.json",
        metadata_file=metadata,
    )
    item = inputs.files[0]
    chain = item.directory.component_identities
    if kind in {"short", "reversed", "empty", "leaf"}:
        chain = (
            chain[-1:]
            if kind == "short"
            else tuple(reversed(chain))
            if kind == "reversed"
            else ()
            if kind == "empty"
            else chain[:-1]
        )
        directory = replace(item.directory, component_identities=chain)
        item = replace(item, custody=replace(item.custody, parent=directory))
        inputs = replace(inputs, files=(item, *inputs.files[1:]))
    elif kind == "role":
        inputs = replace(inputs, files=(replace(item, role="history"), *inputs.files[1:]))
    else:
        inputs = replace(inputs, metadata=None)
    with pytest.raises(ValueError):
        require_development_corpus_resume_inputs(inputs)
    assert len(case.ledger.snapshot().entries) == 2


@pytest.mark.parametrize(
    "flag,value",
    [
        ("--budget-usd", "250"),
        ("--per-attempt-usd", "2"),
        ("--maximum-completion-tokens", "4096"),
        ("--request-timeout-seconds", "900"),
        ("--maximum-run-seconds", "900"),
        ("--carry-uncertain-estimates", None),
    ],
)
def test_cli_does_not_silently_change_original_policy_or_request_configuration(
    tmp_path, monkeypatch, flag, value
):
    case, args, _ = cli_case(tmp_path)
    args += [flag] + ([] if value is None else [value])
    mocked(monkeypatch, case)
    result = RUNNER.invoke(app, args)
    assert result.exit_code != 0 and not case.calls
    assert len(case.ledger.snapshot().entries) == 2
