"""Actual original/cumulative/composed byte limits with synthetic local files and no provider."""

from __future__ import annotations

import hashlib
import socket
import subprocess

import pytest

from mmaudit.benchmark.development_corpus_control_measurement import (
    MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES,
    measure_development_corpus_controls,
    read_development_corpus_control_measurement,
    read_development_corpus_control_source,
)
from mmaudit.orchestration.development_corpus_control_measurement import (
    measure_development_corpus_score_file,
)
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release_io import (
    DEFAULT_MAX_EVIDENCE_BYTES,
    read_composed_file_evidence,
    read_file_evidence,
    write_composed_json_evidence,
)
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.file_custody import (
    observe_regular_file_custody,
    require_regular_file_custody_unchanged,
)
from tests.development_corpus_control_measurement_support import retained_score


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("control measurement bounds attempted network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.mark.parametrize("cumulative", [False, True])
def test_actual_retained_source_reader_keeps_original_32mb_and_cumulative_96mb_caps(cumulative):
    score = retained_score(cumulative=cumulative)
    maximum = 96_000_000 if cumulative else 32_000_000
    raw = score.model_dump_json().encode()
    padded = raw + b" " * (maximum - len(raw))
    assert len(padded) == maximum
    assert read_development_corpus_control_source(padded) == score
    with pytest.raises(ValueError):
        read_development_corpus_control_source(padded + b" ")


@pytest.mark.parametrize("cumulative", [False, True])
def test_actual_measurement_reader_accepts_128mb_and_refuses_one_additional_byte(cumulative):
    measured = measure_development_corpus_controls(score=retained_score(cumulative=cumulative))
    raw = measured.model_dump_json().encode()
    assert MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES == 128_000_000
    padded = raw + b" " * (128_000_000 - len(raw))
    assert read_development_corpus_control_measurement(padded) == measured
    with pytest.raises(ValueError, match="byte bound"):
        read_development_corpus_control_measurement(padded + b" ")


@pytest.mark.parametrize("cumulative", [False, True])
@pytest.mark.parametrize("oversize", [False, True])
def test_offline_file_consumer_obeys_each_source_cap_and_keeps_exact_input(
    tmp_path, cumulative, oversize
):
    score = retained_score(cumulative=cumulative)
    maximum = 96_000_000 if cumulative else 32_000_000
    raw = score.model_dump_json().encode()
    path = tmp_path / "synthetic-score.json"
    content = raw + b" " * (maximum + int(oversize) - len(raw))
    path.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()
    output = tmp_path / "output"
    if oversize:
        with pytest.raises(ValueError):
            measure_development_corpus_score_file(score_file=path, output_dir=output)
        assert not output.exists()
    else:
        result = measure_development_corpus_score_file(score_file=path, output_dir=output)
        assert result.source_score == score
        assert (
            read_development_corpus_control_measurement(
                (output / "control-measurement.json").read_bytes()
            )
            == result
        )
    assert path.stat().st_size == maximum + int(oversize)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected


def test_actual_128mb_measurement_file_requires_composed_prebinding_and_rejects_growth(tmp_path):
    measured = measure_development_corpus_controls(score=retained_score())
    raw = measured.model_dump_json().encode()
    padded = raw + b" " * (128_000_000 - len(raw))
    path = tmp_path / "synthetic-measurement.json"
    path.write_bytes(padded)
    path.chmod(0o600)
    bound = ManifestFileBinding(
        path=path.name, size=len(padded), sha256=hashlib.sha256(padded).hexdigest()
    )
    assert DEFAULT_MAX_EVIDENCE_BYTES == 100_000_000
    with pytest.raises(ValueError):
        read_file_evidence(evidence_root=tmp_path, relative_path=path.name)
    observed = read_composed_file_evidence(
        evidence_root=tmp_path,
        relative_path=path.name,
        expected_binding=bound,
        max_bytes=128_000_000,
    )
    assert observed.binding == bound and observed.content == padded
    assert read_development_corpus_control_measurement(observed.content) == measured
    retained = observe_regular_file_custody(
        root=tmp_path,
        relative_path=path.name,
        label="synthetic measurement",
        expected_binding=bound,
        max_bytes=128_000_000,
        allow_composed_evidence=True,
        allow_directory_entry_metadata_change=True,
    )
    require_regular_file_custody_unchanged(
        retained,
        label="synthetic measurement",
        max_bytes=128_000_000,
        allow_composed_evidence=True,
        allow_directory_entry_metadata_change=True,
    )
    path.write_bytes(padded + b" ")
    with pytest.raises(ValueError):
        require_regular_file_custody_unchanged(
            retained,
            label="synthetic measurement",
            max_bytes=128_000_000,
            allow_composed_evidence=True,
            allow_directory_entry_metadata_change=True,
        )
    with pytest.raises(ValueError):
        read_composed_file_evidence(
            evidence_root=tmp_path,
            relative_path=path.name,
            expected_binding=bound.model_copy(update={"size": 128_000_001}),
            max_bytes=128_000_000,
        )


@pytest.mark.parametrize("oversize", [False, True])
def test_actual_composed_writer_enforces_the_selected_128mb_profile(tmp_path, oversize):
    # This exercises the generic composed writer, not a claim that a score needs this padding.
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    overhead = len(stable_json({"synthetic": ""}).encode())
    value = {"synthetic": "X" * (128_000_000 + int(oversize) - overhead)}
    calls = []

    def validate(content):
        assert len(content) == 128_000_000
        calls.append(hashlib.sha256(content).hexdigest())

    def write():
        return write_composed_json_evidence(
            evidence_root=root,
            relative_path="synthetic-composition.json",
            value=value,
            max_bytes=128_000_000,
            validate_content=validate,
        )

    if oversize:
        with pytest.raises(ValueError, match="output bound"):
            write()
        assert not calls and not list(root.iterdir())
    else:
        bound = write()
        assert bound.size == 128_000_000 and calls == [bound.sha256]
        assert (root / bound.path).stat().st_mode & 0o777 == 0o600
        assert (
            read_composed_file_evidence(
                evidence_root=root,
                relative_path=bound.path,
                expected_binding=bound,
                max_bytes=128_000_000,
            ).binding
            == bound
        )
