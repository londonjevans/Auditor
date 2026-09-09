"""Local discovery-file CLI handoff; every source, credential and transport is synthetic."""

from __future__ import annotations

import json
import os
import socket
import subprocess

import pytest

import mmaudit.development_cli as development_cli
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.development_corpus_resume import DevelopmentCorpusResumeHistory
from mmaudit.models.discovery import OpenRouterModelDiscoveryEvidence, write_model_discovery_run
from tests.development_review_support import SYNTHETIC_CREDENTIAL
from tests.integration.test_development_corpus_resume_cli import RUNNER, cli_case, mocked
from tests.unit.test_development_corpus_resume_metadata import metadata_case


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("discovery-file continuation attempted actual network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.mark.parametrize("mode", ["original", "history", "score"])
def test_published_discovery_file_continues_candidate_without_manual_payload_conversion(
    tmp_path, monkeypatch, mode
):
    metadata = metadata_case()
    # Exercise the existing local publisher with explicitly constructed synthetic provenance.
    manifest = write_model_discovery_run(tmp_path / "synthetic-discovery", (metadata,))
    path = tmp_path / "synthetic-discovery" / manifest.artifacts[0].filename
    raw = path.read_bytes()
    metadata = OpenRouterModelDiscoveryEvidence.model_validate_json(raw, strict=True)
    case, args, _ = cli_case(tmp_path, mode=mode, endpoint_snapshot=metadata)
    args[args.index("--endpoint-snapshot") + 1] = str(path)
    before = case.ledger.snapshot().entries
    mocked(monkeypatch, case)
    execute = development_cli.run_development_corpus_resume
    retained = []

    async def capture(**kwargs):
        inputs, prepared = kwargs["inputs"], kwargs["prepared"]
        assert type(inputs.metadata) is OpenRouterModelDiscoveryEvidence
        assert inputs.metadata == metadata == prepared.candidate.shards[0].discovery
        assert inputs.files[-1].binding.path == path.name
        assert metadata.endpoint_snapshot.endpoints[0].supported_reasoning_efforts is None
        for shard in prepared.candidate.shards:
            body = json.loads(shard.request_content)
            assert body["reasoning"] == {"effort": "high"}
            assert body["provider"]["allow_fallbacks"] is False
            assert body["provider"]["zdr"] is True
            assert b"provenance" not in shard.request_content
        retained.append(inputs.metadata)
        return await execute(**kwargs)

    monkeypatch.setattr(development_cli, "run_development_corpus_resume", capture)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == 0, result.output
    history = DevelopmentCorpusResumeHistory.model_validate_json(result.stdout, strict=True)
    expected = len(case.original_prepared.shards)
    assert retained == [metadata] and path.read_bytes() == raw
    assert len(case.calls) == expected - 1
    assert history.original == case.original
    assert history.summary.original_first_attempt_completed_shard_count == 1
    assert history.summary.cumulative_completed_shard_count == expected
    assert history.summary.accounted_request_count == expected + 1
    assert history.summary.total_accounted_cost_usd == case.ledger.snapshot().spent_usd
    assert all(e in case.ledger.snapshot().entries for e in before)
    assert all(p.read_bytes() == b for p, b in case.prior_bytes.items())
    if mode == "score":
        assert history.original_score.model_dump(mode="json") == json.loads(
            (tmp_path / "original-score.json").read_bytes()
        )
    assert history.original.transport == history.continuations[0].transport == "MOCK_HTTP"
    assert not history.audit_complete and not history.qualification_eligible
    assert SYNTHETIC_CREDENTIAL not in result.output


@pytest.mark.parametrize(
    "kind",
    [
        "bad_hash",
        "low_reasoning",
        "changed_model",
        "changed_model_facts",
        "oversize",
        "symlink",
        "hardlink",
    ],
)
def test_invalid_discovery_metadata_refuses_before_credentials_or_new_request(
    tmp_path, monkeypatch, kind
):
    metadata = metadata_case()
    case, args, path = cli_case(tmp_path, endpoint_snapshot=metadata)
    before = case.ledger.snapshot().entries
    if kind == "bad_hash":
        path.write_text(
            metadata.model_copy(update={"discovery_evidence_sha256": "0" * 64}).model_dump_json()
        )
    elif kind == "low_reasoning":
        path.write_text(metadata_case(model_efforts=("low",)).model_dump_json())
    elif kind == "changed_model":
        path.write_text(metadata_case(model_id="synthetic/unselected-model").model_dump_json())
    elif kind == "changed_model_facts":
        path.write_text(metadata_case(model_efforts=("high",)).model_dump_json())
    elif kind == "oversize":
        raw = path.read_bytes()
        path.write_bytes(raw + b" " * (2_000_001 - len(raw)))
    else:
        retained = path.with_suffix(".retained")
        path.rename(retained)
        if kind == "symlink":
            path.symlink_to(retained)
        else:
            os.link(retained, path)

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid discovery reached credentials or continuation execution")

    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    monkeypatch.setattr(development_cli, "run_development_corpus_resume", forbidden)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    assert case.ledger.snapshot().entries == before and not case.calls
    assert not (tmp_path / "resume").exists()
    assert SYNTHETIC_CREDENTIAL not in result.output and str(path) not in result.output


@pytest.mark.parametrize("when", ["before_dispatch", "during_dispatch"])
@pytest.mark.parametrize("kind", ["replacement", "byte_change"])
def test_complete_discovery_file_custody_survives_control_loading_and_dispatch(
    tmp_path, monkeypatch, when, kind
):
    metadata = metadata_case()
    case, args, path = cli_case(tmp_path, mode="history", endpoint_snapshot=metadata)
    before = case.ledger.snapshot().entries

    def mutate():
        raw = path.read_bytes()
        if kind == "replacement":
            path.rename(path.with_suffix(".retained"))
            path.write_bytes(raw)
            path.chmod(0o600)
        else:
            path.write_bytes(raw + b" ")

    if when == "before_dispatch":
        loader = development_cli.load_operator_secrets

        def changed_loader(*a, **kw):
            mutate()
            return loader(*a, **kw)

        monkeypatch.setattr(development_cli, "load_operator_secrets", changed_loader)
    mocked(monkeypatch, case, mutate=mutate if when == "during_dispatch" else None)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    dispatched = int(when == "during_dispatch")
    assert len(case.calls) == dispatched
    assert len(case.ledger.snapshot().entries) == len(before) + dispatched
    assert all(e in case.ledger.snapshot().entries for e in before)
    assert all(p.read_bytes() == b for p, b in case.prior_bytes.items())
    assert not (tmp_path / "resume/result.json").exists()
    assert SYNTHETIC_CREDENTIAL not in result.output
