"""Actual synthetic candidate/continuation measurement, immutable older evidence and failure custody."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess

import httpx
import pytest

import mmaudit.orchestration.development_corpus as candidate
import mmaudit.orchestration.development_corpus_control_measurement as output_io
import mmaudit.orchestration.development_corpus_resume as continuation
from mmaudit.benchmark.development_corpus import DevelopmentCorpusBenchmarkScore
from mmaudit.benchmark.development_corpus_control_measurement import (
    read_development_corpus_control_measurement,
)
from mmaudit.benchmark.development_corpus_resume import read_development_corpus_resume_score
from tests.development_corpus_benchmark_support import paired_case, paired_payload, paired_response
from tests.development_review_support import local_controls
from tests.integration.test_development_corpus_benchmark_execution import (
    execute as execute_original,
)
from tests.integration.test_development_corpus_control_cli import invoke
from tests.integration.test_development_corpus_resume_execution import execute
from tests.integration.test_development_corpus_resume_scoring_execution import (
    accepted_response,
    scored_case,
)


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("control measurement execution attempted real network or processes")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["known", "unknown"])
async def test_actual_original_continuation_and_offline_measurements_are_identical_without_new_calls(
    tmp_path, failure
):
    responses = [paired_response(i) for i in range(1, 7)]
    for response in responses:
        for finding in response["findings"]:
            finding["vulnerability_class"] = "other"
    case = await scored_case(tmp_path, failure=failure, responses=responses)
    original = read_development_corpus_control_measurement(
        (tmp_path / "original/control-measurement.json").read_bytes()
    )
    assert original.source_score == case.inputs.history.original_score
    assert original.summary.unique_root_location_coverage.value is None
    assert original.summary.unique_root_location_coverage.numerator == 1
    before = case.ledger.snapshot().entries

    def response(*args):
        payload = accepted_response(case, *args).json()
        body = json.loads(payload["choices"][0]["message"]["content"])
        for finding in body["findings"]:
            finding["vulnerability_class"] = "other"
        payload["choices"][0]["message"]["content"] = json.dumps(body)
        return httpx.Response(200, json=payload)

    history = await execute(case, custom=response)
    old = read_development_corpus_resume_score(
        (tmp_path / "resume/cumulative-score.json").read_bytes()
    )
    measured = read_development_corpus_control_measurement(
        (tmp_path / "resume/control-measurement.json").read_bytes()
    )
    assert old.history == history and measured.source_score == old
    assert old.cumulative_quality.unique_root_recall.value == 0
    assert measured.summary.unique_root_location_coverage.value == 1
    assert measured.summary.invariant_asserted_root_coverage.value == 1
    assert measured.summary.matched_category_disagreement_count == 3
    assert len(case.calls) == 5 and len(case.ledger.snapshot().entries) == 7
    assert all(entry in case.ledger.snapshot().entries for entry in before)
    assert all(path.read_bytes() == raw for path, raw in case.prior_bytes.items())
    ledger_bytes = case.ledger.path.read_bytes()
    result = invoke(tmp_path / "resume/cumulative-score.json", tmp_path / "offline")
    assert result.exit_code == 0, result.output
    assert (tmp_path / "offline/control-measurement.json").read_bytes() == (
        tmp_path / "resume/control-measurement.json"
    ).read_bytes()
    assert case.ledger.path.read_bytes() == ledger_bytes
    assert not measured.audit_complete and not measured.qualification_eligible


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["original", "continuation"])
@pytest.mark.parametrize(
    "failure",
    [
        "writer",
        "bound",
        "source_bytes",
        "history_bytes",
        "output_bytes",
        "output_inode",
        "output_mode",
    ],
)
async def test_measurement_failure_never_reports_success_or_discards_retained_costs(
    tmp_path, monkeypatch, stage, failure
):
    calls = []
    if stage == "original":
        prepared = paired_case()
        ledger, secrets = local_controls(tmp_path)
        root, old_name, module = tmp_path / "run", "score.json", candidate

        def handler(request):
            calls.append(request.content)
            return httpx.Response(200, json=paired_payload(len(calls)))

        async def run():
            return await execute_original(tmp_path, prepared, ledger, secrets, handler)

        total, expected_calls = 6, 6
    else:
        case = await scored_case(tmp_path)
        ledger = case.ledger
        calls = case.calls
        root, old_name, module = tmp_path / "resume", "cumulative-score.json", continuation

        async def run():
            return await execute(case, custom=lambda *a: accepted_response(case, *a))

        total, expected_calls = 7, 5
    writer = module.write_development_corpus_control_measurement

    def altered(*args, **kwargs):
        if failure == "writer":
            raise OSError("synthetic derivative refusal")
        if failure in {"source_bytes", "history_bytes"}:
            (root / (old_name if failure == "source_bytes" else "result.json")).write_text("{}")
        result = writer(*args, **kwargs)
        target = root / "control-measurement.json"
        if failure == "output_bytes":
            target.write_bytes(target.read_bytes() + b" ")
        elif failure == "output_inode":
            raw = target.read_bytes()
            target.rename(target.with_suffix(".retained"))
            target.write_bytes(raw)
            target.chmod(0o600)
        elif failure == "output_mode":
            target.chmod(0o644)
        return result

    monkeypatch.setattr(module, "write_development_corpus_control_measurement", altered)
    if failure == "bound":
        monkeypatch.setattr(output_io, "MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES", 1)
    with pytest.raises(ValueError, match="could not be finalized"):
        await run()
    assert len(calls) == expected_calls and len(ledger.snapshot().entries) == total
    assert (root / old_name).exists() and (root / "result.json").exists()
    if failure != "source_bytes":
        raw = (root / old_name).read_bytes()
        old = (
            DevelopmentCorpusBenchmarkScore.model_validate_json(raw)
            if stage == "original"
            else read_development_corpus_resume_score(raw)
        )
        assert not old.audit_complete
    if stage == "continuation":
        assert all(path.read_bytes() == raw for path, raw in case.prior_bytes.items())


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["original", "continuation"])
@pytest.mark.parametrize(
    "secondary", [ValueError, KeyboardInterrupt, SystemExit, asyncio.CancelledError]
)
async def test_original_cancellation_survives_every_secondary_measurement_failure(
    tmp_path, monkeypatch, stage, secondary
):
    primary = asyncio.CancelledError("synthetic original cancellation")

    def interrupted(*_args):
        raise primary

    if stage == "original":
        prepared = paired_case()
        ledger, secrets = local_controls(tmp_path)
        root, old_name, module = tmp_path / "run", "score.json", candidate

        async def run():
            return await execute_original(tmp_path, prepared, ledger, secrets, interrupted)

        total = 1
    else:
        case = await scored_case(tmp_path)
        ledger = case.ledger
        root, old_name, module = tmp_path / "resume", "cumulative-score.json", continuation

        async def run():
            return await execute(case, custom=interrupted)

        total = 3

    def refused(*_args, **_kwargs):
        raise secondary("synthetic derivative failure")

    monkeypatch.setattr(module, "write_development_corpus_control_measurement", refused)
    with pytest.raises(asyncio.CancelledError) as caught:
        await run()
    assert caught.value is primary
    assert len(ledger.snapshot().entries) == total
    assert (root / old_name).exists() and (root / "result.json").exists()
    assert not (root / "control-measurement.json").exists()
