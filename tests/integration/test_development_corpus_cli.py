"""Exact local source-manifest loader and explicit CLI handoff, with real egress/process traps."""

from __future__ import annotations

import os
import socket
import subprocess
from dataclasses import replace

import httpx
import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as development_cli
import mmaudit.repository.development_corpus as corpus_io
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.development_corpus import (
    DevelopmentCorpusMaterial,
    DevelopmentCorpusObservation,
    freeze_development_corpus,
)
from mmaudit.orchestration.development_corpus import run_development_corpus
from tests.development_corpus_support import corpus_case, corpus_payload, supplied_sources
from tests.development_review_support import SYNTHETIC_CREDENTIAL, local_controls

RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("development corpus loader/CLI attempted real network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def inputs(tmp_path):
    prepared = corpus_case()
    root = tmp_path / "corpus"
    root.mkdir(mode=0o700)
    for name, raw in supplied_sources():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    manifest = tmp_path / "source-manifest.json"
    manifest.write_text(prepared.plan.manifest.model_dump_json())
    metadata = tmp_path / "metadata.json"
    metadata.write_text(prepared.shards[0].endpoint_snapshot.model_dump_json())
    ledger, _ = local_controls(tmp_path)
    secret = tmp_path / "synthetic-secrets.txt"
    secret.write_text("OPENROUTER_API_KEY=" + SYNTHETIC_CREDENTIAL + "\n")
    secret.chmod(0o600)
    args = [
        "development",
        "audit-manifest",
        "--source-manifest",
        str(manifest),
        "--corpus-root",
        str(root),
        "--endpoint-snapshot",
        str(metadata),
        "--cost-ledger",
        str(ledger.path),
        "--secrets-env-file",
        str(secret),
        "--output-dir",
        str(tmp_path / "run"),
        "--run-id",
        "cli-corpus",
        "--budget-usd",
        "20",
        "--per-attempt-usd",
        "5",
        "--accept-estimate-risk",
        "--allow-code-egress",
    ]
    return args, ledger, root, manifest, metadata


def mocked(monkeypatch, handler):
    async def execute(**kwargs):
        return await run_development_corpus(**kwargs, mock_transport=httpx.MockTransport(handler))

    monkeypatch.setattr(development_cli, "run_development_corpus", execute)


@pytest.mark.parametrize("count", [0, 1])
def test_cli_executes_exact_full_manifest_and_keeps_original_source_snapshot(
    tmp_path, monkeypatch, count
):
    args, ledger, _, _, _ = inputs(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=corpus_payload(len(calls), count=count))

    mocked(monkeypatch, handler)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == 0, result.output
    observation = DevelopmentCorpusObservation.model_validate_json(result.stdout, strict=True)
    assert observation.status == "OBSERVED_ALL_SHARDS"
    assert observation.completed_shard_count == len(calls) == len(ledger.snapshot().entries) == 14
    assert observation.candidate_claim_count == count * 14
    assert SYNTHETIC_CREDENTIAL not in result.output
    assert (
        DevelopmentCorpusMaterial.model_validate_json(
            (tmp_path / "run/sources.json").read_bytes()
        ).source_files
        == supplied_sources()
    )


@pytest.mark.parametrize("flag", ["--accept-estimate-risk", "--allow-code-egress"])
def test_missing_consent_refuses_before_any_source_metadata_ledger_or_secret_read(
    tmp_path, monkeypatch, flag
):
    args, ledger, _, _, _ = inputs(tmp_path)
    args.remove(flag)

    def forbidden(*_args, **_kwargs):
        pytest.fail("missing explicit consent reached input handling")

    monkeypatch.setattr(development_cli, "load_development_corpus", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    monkeypatch.setattr(development_cli, "run_development_corpus", forbidden)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.CONFIGURATION)
    assert not ledger.snapshot().entries and not (tmp_path / "run").exists()


@pytest.mark.parametrize(
    "kind",
    [
        "malformed",
        "duplicate_json",
        "nonfinite",
        "oversize",
        "manifest_link",
        "manifest_hardlink",
        "manifest_fifo",
        "source_link",
        "source_hardlink",
        "source_fifo",
        "source_drift",
        "source_missing",
        "metadata",
        "metadata_drift",
        "handoff_source_drift",
        "relative",
        "overlap",
        "allowance",
        "private_scope",
    ],
)
def test_bad_manifest_or_metadata_refuses_before_credentials_and_dispatch(
    tmp_path, monkeypatch, kind
):
    args, ledger, root, manifest, metadata = inputs(tmp_path)
    source = root / "src/AccessVault.sol"
    if kind == "malformed":
        manifest.write_text("{")
    elif kind == "duplicate_json":
        manifest.write_text('{"corpus_id":"synthetic-medium",' + manifest.read_text()[1:])
    elif kind == "nonfinite":
        manifest.write_text(
            manifest.read_text().replace('"total_source_bytes":12213', '"total_source_bytes":NaN')
        )
    elif kind == "oversize":
        manifest.write_text(" " * 131073)
    elif kind in {"manifest_link", "source_link"}:
        target = manifest if kind == "manifest_link" else source
        retained = target.with_name("original-" + target.name)
        target.rename(retained)
        target.symlink_to(retained)
    elif kind in {"manifest_hardlink", "source_hardlink"}:
        target = manifest if kind == "manifest_hardlink" else source
        os.link(target, target.with_name("linked-" + target.name))
    elif kind in {"manifest_fifo", "source_fifo"}:
        target = manifest if kind == "manifest_fifo" else source
        target.unlink()
        os.mkfifo(target)
    elif kind == "source_drift":
        source.write_bytes(source.read_bytes() + b"\n")
    elif kind == "source_missing":
        source.unlink()
    elif kind == "metadata":
        metadata.write_text("{}")
    elif kind in {"metadata_drift", "handoff_source_drift"}:
        original = development_cli.prepare_development_corpus

        def drift(**kwargs):
            prepared = original(**kwargs)
            (metadata if kind == "metadata_drift" else source).write_text("changed")
            return prepared

        monkeypatch.setattr(development_cli, "prepare_development_corpus", drift)
    elif kind == "relative":
        args[args.index("--source-manifest") + 1] = "relative.json"
    elif kind == "overlap":
        args[args.index("--output-dir") + 1] = str(root / "outputs")
    elif kind == "allowance":
        args += ["--maximum-completion-tokens", "65536"]
    else:
        manifest.write_text(manifest.read_text().replace("OPERATOR_SUPPLIED_SYNTHETIC", "PRIVATE"))

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid selected input reached credentials or dispatch")

    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    monkeypatch.setattr(development_cli, "run_development_corpus", forbidden)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    assert not ledger.snapshot().entries and not (tmp_path / "run").exists()
    assert SYNTHETIC_CREDENTIAL not in result.output


def test_loader_reads_exact_selected_members_and_does_not_discover_extra_files(
    tmp_path, monkeypatch
):
    _, _, root, manifest, _ = inputs(tmp_path)
    (root / "Unselected.sol").write_text("// Unselected source must not be read.\n")
    original = corpus_io.read_file_evidence
    calls = []

    def selected_only(**kwargs):
        calls.append(kwargs["relative_path"])
        assert kwargs["relative_path"] in {p for p, _ in supplied_sources()}
        return original(**kwargs)

    monkeypatch.setattr(corpus_io, "read_file_evidence", selected_only)
    loaded = corpus_io.load_development_corpus(manifest_file=manifest, corpus_root=root)
    assert calls == [p for p, _ in supplied_sources()]
    assert loaded.material.source_files == supplied_sources()


def test_loaded_material_cannot_substitute_a_different_manifest_while_reusing_file_binding(
    tmp_path,
):
    _, _, root, manifest, _ = inputs(tmp_path)
    loaded = corpus_io.load_development_corpus(manifest_file=manifest, corpus_root=root)
    replacement = freeze_development_corpus(
        corpus_id="different-selected-id",
        source_scope="OPERATOR_SUPPLIED_SYNTHETIC",
        source_files=supplied_sources(),
    )
    material = DevelopmentCorpusMaterial(manifest=replacement, sources=loaded.material.sources)
    with pytest.raises(ValueError, match="selected manifest"):
        corpus_io.revalidate_loaded_development_corpus(replace(loaded, material=material))


def test_cli_failure_retains_unknown_liability_and_emits_nonzero_status(tmp_path, monkeypatch):
    args, ledger, _, _, _ = inputs(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 2:
            return httpx.Response(429, json={"error": "Synthetic unknown cost."})
        return httpx.Response(200, json=corpus_payload(len(calls)))

    mocked(monkeypatch, handler)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.INCOMPLETE)
    observation = DevelopmentCorpusObservation.model_validate_json(result.stdout, strict=True)
    assert (
        observation.completed_shard_count == 1 and len(calls) == len(ledger.snapshot().entries) == 2
    )
    assert observation.uncertain_accounted_cost_usd > 0
    assert len(observation.unobserved_shard_ids) == 13
