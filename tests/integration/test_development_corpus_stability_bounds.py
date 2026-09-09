"""Actual byte-bound regressions over synthetic retained evidence, without external execution."""

from __future__ import annotations

import json
import socket
import subprocess

import pytest

import mmaudit.benchmark.development_corpus_stability as stability
from mmaudit.orchestration.development_corpus_stability import (
    measure_development_corpus_stability_files,
)
from tests.development_corpus_stability_support import trial
from tests.integration.test_development_corpus_stability_cli import bind, case


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("stability bounds touched network or a subprocess")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def test_actual_selection_bytes_accept_exact_bound_and_refuse_one_more(tmp_path):
    _, selection, _, _ = case(tmp_path)
    raw = selection.read_bytes()
    exact = raw + b" " * (65_536 - len(raw))
    assert stability.read_development_stability_selection(exact)
    with pytest.raises(ValueError):
        stability.read_development_stability_selection(exact + b" ")


def test_actual_aggregate_128mb_is_shared_and_bound_before_opening_any_measurement(tmp_path):
    values, selection, paths, output = case(tmp_path)
    original = paths[0].read_bytes()
    padding = 128_000_000 - sum(path.stat().st_size for path in paths)
    paths[0].write_bytes(original + b" " * padding)
    bind(selection, paths)
    assert paths[0].stat().st_size > 100_000_000
    result = measure_development_corpus_stability_files(selection_file=selection, output_dir=output)
    assert result.measurements == values
    assert sum(path.stat().st_size for path in paths) == 128_000_000
    invalid = json.loads(selection.read_bytes())
    invalid["measurements"][0]["size"] += 1
    selection.write_text(json.dumps(invalid))
    paths[0].unlink()
    refused = tmp_path / "refused"
    with pytest.raises(ValueError, match="aggregate read bound"):
        measure_development_corpus_stability_files(selection_file=selection, output_dir=refused)
    assert not refused.exists()


def test_actual_stability_reader_accepts_192mb_and_refuses_one_more():
    value = stability.measure_development_corpus_stability(
        measurements=(trial("synthetic-bound-first"), trial("synthetic-bound-second"))
    )
    raw = value.model_dump_json().encode()
    exact = raw + b" " * (192_000_000 - len(raw))
    assert stability.read_development_corpus_stability(exact) == value
    with pytest.raises(ValueError):
        stability.read_development_corpus_stability(exact + b" ")
