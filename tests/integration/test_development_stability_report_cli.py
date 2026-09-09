"""Actual local report CLI preserves all trials, JSON, accounting and exact custody."""

import hashlib
import os
import socket
import stat
import subprocess

import httpx
import pytest

import mmaudit.orchestration.development_corpus_repeats as repeats
import mmaudit.orchestration.development_corpus_stability as retained
from mmaudit.benchmark.development_corpus_stability import (
    measure_development_corpus_stability,
    read_development_corpus_stability,
)
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.development_corpus_repeats import read_development_corpus_repeats
from mmaudit.reporting.development_stability import render_development_stability_report
from tests.development_corpus_repeats_support import repeat_payload
from tests.development_corpus_stability_support import trial
from tests.integration.test_development_corpus_repeats_cli import RUNNER, inputs, mocked
from tests.integration.test_development_corpus_stability_cli import case, invoke


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("candidate report integration attempted network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def execute(tmp_path, monkeypatch, *, kind="complete", count=2):
    args, selected, ledger, output = inputs(tmp_path, count=count)
    calls = []

    def handler(request):
        calls.append(request)
        if kind in {"known_failure", "unknown_failure"} and len(calls) == 1:
            return httpx.Response(
                429,
                json={
                    "error": "synthetic refusal",
                    **({"usage": {"cost": 0.01}} if kind == "known_failure" else {}),
                },
            )
        payload = repeat_payload(len(calls))
        if kind == "reused" and len(calls) == 7:
            payload["id"] = "gen-synthetic-repeat-1"
        return httpx.Response(200, json=payload)

    mocked(monkeypatch, handler)
    result = RUNNER.invoke(app, args)
    return result, output, ledger, calls, selected


@pytest.mark.parametrize("kind", ["complete", "known_failure", "unknown_failure", "reused"])
def test_real_repeat_cli_automatically_reports_complete_incomplete_and_unavailable_scope(
    tmp_path, monkeypatch, kind
):
    result, output, ledger, calls, _ = execute(tmp_path, monkeypatch, kind=kind)
    assert result.exit_code == (0 if kind == "complete" else int(ExitCode.INCOMPLETE)), (
        result.output
    )
    series = read_development_corpus_repeats((output / "result.json").read_bytes())
    path = output / "stability.md"
    text = path.read_text()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and path.stat().st_nlink == 1
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert series.observation_sha256 in text and series.plan.plan_sha256 in text
    assert "Planned trials: 2" in text and "Selected requests: 12" in text
    assert "Role measured: CANDIDATE. Other audit roles: NOT MEASURED." in text
    assert f"| Reported actual cost (USD) | {series.reported_actual_cost_usd} |" in text
    assert len(calls) == len(ledger.snapshot().entries)
    if kind in {"complete", "known_failure"}:
        stability = read_development_corpus_stability((output / "stability.json").read_bytes())
        assert text == render_development_stability_report(series=series, stability=stability)
        assert "## Measurement unavailable" not in text
        if kind == "known_failure":
            assert "unavailable (INCOMPLETE\\_SCOPE)" in text
    else:
        assert "## Measurement unavailable" in text and series.measurement_scope in text
        assert text == render_development_stability_report(series=series)
        assert not (output / "stability.json").exists()
        assert "## Pairwise overlap" not in text and "precision proxy" not in text
    assert "findings_validated=false; audit_complete=false" in text


def test_report_rejects_missing_reordered_subset_foreign_and_forged_series_evidence(
    tmp_path, monkeypatch
):
    result, output, _, _, _ = execute(tmp_path, monkeypatch, count=3)
    assert result.exit_code == 0, result.output
    series = read_development_corpus_repeats((output / "result.json").read_bytes())
    measured = read_development_corpus_stability((output / "stability.json").read_bytes())
    variants = [None]
    for selected in (measured.measurements[:2], tuple(reversed(measured.measurements))):
        variants.append(measure_development_corpus_stability(measurements=selected))
    variants.append(
        measure_development_corpus_stability(
            measurements=tuple(
                trial(f"synthetic-foreign-{i}", score=m.source_score)
                for i, m in enumerate(measured.measurements)
            )
        )
    )
    for changed in variants:
        with pytest.raises(ValueError):
            render_development_stability_report(series=series, stability=changed)
    with pytest.raises(ValueError):
        render_development_stability_report(
            series=series.model_copy(update={"observation_sha256": "0" * 64}), stability=measured
        )


def run_consumer(tmp_path, monkeypatch, consumer):
    if consumer == "retained":
        _, selection, paths, output = case(tmp_path)
        old = {path: path.read_bytes() for path in [selection, *paths]}
        result = invoke(selection, output)
        assert all(path.read_bytes() == raw for path, raw in old.items())
        return result, output
    result, output, ledger, calls, _ = execute(tmp_path, monkeypatch)
    assert len(calls) == len(ledger.snapshot().entries) == 12
    assert ledger.snapshot().spent_usd > 0
    return result, output


@pytest.mark.parametrize("consumer", ["retained", "repeat"])
@pytest.mark.parametrize("target", ["report", "source_json"])
@pytest.mark.parametrize("kind", ["bytes", "inode", "mode", "hardlink"])
def test_consumers_reject_report_or_source_replacement_after_writer_return(
    tmp_path, monkeypatch, consumer, target, kind
):
    original = retained.write_development_stability_report
    saved = {}

    def replaced(output, **kwargs):
        json_files = [output / "stability.json"]
        if consumer == "repeat":
            json_files.append(output / "result.json")
        saved.update({path: path.read_bytes() for path in json_files})
        custody = original(output, **kwargs)
        path = output / ("stability.md" if target == "report" else "stability.json")
        if kind == "bytes":
            path.write_bytes(path.read_bytes() + b" ")
        elif kind == "inode":
            raw = path.read_bytes()
            path.rename(path.with_suffix(".retained"))
            path.write_bytes(raw)
            path.chmod(0o600)
        elif kind == "mode":
            path.chmod(0o644)
        else:
            os.link(path, path.with_suffix(".linked"))
        return custody

    monkeypatch.setattr(
        retained if consumer == "retained" else repeats,
        "write_development_stability_report",
        replaced,
    )
    result, output = run_consumer(tmp_path, monkeypatch, consumer)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    assert str(output) not in result.output
    if target == "report":
        assert all(path.read_bytes() == raw for path, raw in saved.items())
    assert (output / "stability.json").is_file()


@pytest.mark.parametrize("consumer", ["retained", "repeat"])
@pytest.mark.parametrize("phase", ["render", "partial_write"])
def test_report_failure_is_nonzero_and_preserves_durable_json_and_charges(
    tmp_path, monkeypatch, consumer, phase
):
    saved = {}
    original = retained.write_development_stability_report

    def capture(output, **kwargs):
        saved.update({p: hashlib.sha256(p.read_bytes()).hexdigest() for p in output.glob("*.json")})
        return original(output, **kwargs)

    monkeypatch.setattr(
        retained if consumer == "retained" else repeats,
        "write_development_stability_report",
        capture,
    )
    marker = "SYNTHETIC_PRIVATE_REPORT_FAILURE"
    if phase == "render":

        def fail_render(**_kwargs):
            raise ValueError(marker)

        monkeypatch.setattr(retained, "render_development_stability_report", fail_render)
    else:
        original_write = retained._write_file_content
        os_write = os.write

        def fail_bytes(**kwargs):
            calls = 0

            def interrupted(descriptor, content):
                nonlocal calls
                calls += 1
                if calls == 1:
                    return os_write(descriptor, content[:7])
                raise OSError(marker)

            with monkeypatch.context() as patch:
                patch.setattr(os, "write", interrupted)
                return original_write(**kwargs)

        monkeypatch.setattr(retained, "_write_file_content", fail_bytes)
    result, output = run_consumer(tmp_path, monkeypatch, consumer)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    assert marker not in result.output and str(output) not in result.output
    assert saved and all(
        hashlib.sha256(path.read_bytes()).hexdigest() == sha for path, sha in saved.items()
    )
    assert not (output / "stability.md").exists()
