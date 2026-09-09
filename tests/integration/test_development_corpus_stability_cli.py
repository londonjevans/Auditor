"""Explicit retained files, private output and custody failures; no provider or credential access."""

from __future__ import annotations

import hashlib
import os
import socket
import stat
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as cli
import mmaudit.orchestration.development_corpus_stability as orchestration
from mmaudit.benchmark.development_corpus_stability import (
    DevelopmentStabilitySelection,
    read_development_corpus_stability,
)
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.orchestration.manifest import ManifestFileBinding
from tests.development_corpus_stability_support import trial

RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("stability ingestion touched credentials, network or a subprocess")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(cli, "load_operator_secrets", forbidden)


def case(tmp_path, *, cumulative=False, complete=True):
    inputs = tmp_path / "inputs" / "middle"
    inputs.mkdir(parents=True)
    values = tuple(
        trial(f"synthetic-file-trial-{i}", cumulative=cumulative, complete=complete)
        for i in range(2)
    )
    paths = []
    for index, value in enumerate(values):
        path = inputs / "nested" / f"trial-{index}.json"
        path.parent.mkdir(exist_ok=True)
        path.write_text(value.model_dump_json(indent=2))
        path.chmod(0o600)
        paths.append(path)
    selection = inputs / "selection.json"
    bind(selection, paths)
    return values, selection, paths, tmp_path / "output"


def bind(selection, paths):
    selected = DevelopmentStabilitySelection(
        measurements=tuple(
            ManifestFileBinding(
                path=path.relative_to(selection.parent).as_posix(),
                size=path.stat().st_size,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            )
            for path in paths
        )
    )
    selection.write_text(selected.model_dump_json())
    selection.chmod(0o600)


def invoke(selection, output, *extra):
    return RUNNER.invoke(
        app,
        [
            "development",
            "measure-stability",
            "--selection-file",
            str(selection),
            "--output-dir",
            str(output),
            *extra,
        ],
    )


@pytest.mark.parametrize("cumulative", [False, True])
@pytest.mark.parametrize("complete", [False, True])
def test_cli_keeps_exact_selected_measurements_and_private_output_without_provider(
    tmp_path, cumulative, complete
):
    values, selection, paths, output = case(tmp_path, cumulative=cumulative, complete=complete)
    old = {path: path.read_bytes() for path in [selection, *paths]}
    result = invoke(selection, output)
    assert result.exit_code == 0, result.output
    artifact = output / "stability.json"
    measured = read_development_corpus_stability(artifact.read_bytes())
    assert measured.measurements == values
    assert {p.name for p in output.iterdir()} == {"stability.json"}
    assert all(path.read_bytes() == content for path, content in old.items())
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    assert measured.stability_sha256 in result.stdout
    assert "qualified stability remain unproved" in result.stdout
    assert str(selection) not in result.stdout
    assert measured.combined.union_location_coverage.value == (1 if complete else None)
    assert not measured.audit_complete and not measured.qualification_eligible


@pytest.mark.parametrize(
    "kind",
    [
        "missing",
        "stale_hash",
        "stale_size",
        "bad_json",
        "duplicate_json",
        "bad_measurement",
        "symlink",
        "dangling",
        "cycle",
        "hardlink",
        "directory",
        "linked_ancestor",
        "duplicate_measurement",
        "relative_selection",
        "relative_output",
        "overlap",
        "existing_output",
    ],
)
def test_invalid_unbound_missing_or_aliased_inputs_never_produce_an_aggregate(tmp_path, kind):
    _, selection, paths, output = case(tmp_path)
    path = paths[0]
    if kind == "missing":
        path.unlink()
    elif kind == "stale_hash":
        path.write_bytes(path.read_bytes().replace(b"high", b"xxxx", 1))
    elif kind == "stale_size":
        path.write_bytes(path.read_bytes() + b" ")
    elif kind in {"bad_json", "duplicate_json", "bad_measurement"}:
        path.write_bytes(
            {
                "bad_json": b"{",
                "duplicate_json": b'{"x":1,"x":2}',
                "bad_measurement": b'{"artifact_kind":"unselected"}',
            }[kind]
        )
        bind(selection, paths)
    elif kind in {"symlink", "dangling", "cycle", "hardlink", "directory"}:
        retained = path.with_suffix(".retained")
        path.rename(retained)
        if kind == "directory":
            path.mkdir()
        elif kind == "hardlink":
            os.link(retained, path)
        else:
            path.symlink_to(
                retained if kind == "symlink" else path.name if kind == "cycle" else "missing.json"
            )
    elif kind == "linked_ancestor":
        parent = path.parent
        retained = parent.with_name("retained-nested")
        parent.rename(retained)
        parent.symlink_to(retained, target_is_directory=True)
    elif kind == "duplicate_measurement":
        paths[1].write_bytes(paths[0].read_bytes())
        bind(selection, paths)
    elif kind == "relative_selection":
        selection = Path("relative-selection.json")
    elif kind == "relative_output":
        output = Path("relative-output")
    elif kind == "overlap":
        output = selection.parent
    else:
        output.mkdir()
    result = invoke(selection, output)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    assert "No provider call was selected" in result.output and str(selection) not in result.output
    assert not (output / "stability.json").exists()
    if kind not in {"overlap", "existing_output"}:
        assert not output.exists()


@pytest.mark.parametrize("target", ["selection", "first", "last"])
@pytest.mark.parametrize("when", ["after_compute", "inside_writer", "after_writer"])
@pytest.mark.parametrize("kind", ["bytes", "inode"])
def test_every_selected_file_stays_bound_through_finalization(
    tmp_path, monkeypatch, target, when, kind
):
    _, selection, paths, output = case(tmp_path)
    path = selection if target == "selection" else paths[0] if target == "first" else paths[-1]
    raw = path.read_bytes()
    compute = orchestration.measure_development_corpus_stability
    writer = orchestration.write_development_corpus_stability

    def mutate():
        if kind == "inode":
            path.rename(path.with_suffix(".retained"))
            path.write_bytes(raw)
            path.chmod(0o600)
        else:
            path.write_bytes(raw + b" ")

    def computed(**kwargs):
        result = compute(**kwargs)
        if when == "after_compute":
            mutate()
        return result

    def written(*args, **kwargs):
        if when == "inside_writer":
            mutate()
        result = writer(*args, **kwargs)
        if when == "after_writer":
            mutate()
        return result

    monkeypatch.setattr(orchestration, "measure_development_corpus_stability", computed)
    monkeypatch.setattr(orchestration, "write_development_corpus_stability", written)
    result = invoke(selection, output)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    assert str(path) not in result.output
    if when == "after_compute":
        assert not output.exists()
    elif when == "inside_writer":
        assert not (output / "stability.json").exists()


@pytest.mark.parametrize("kind", ["bytes", "inode", "directory", "mode"])
def test_written_aggregate_bytes_objects_and_permissions_are_rechecked(tmp_path, monkeypatch, kind):
    _, selection, paths, output = case(tmp_path)
    old = [p.read_bytes() for p in paths]
    writer = orchestration.write_development_corpus_stability

    def written(*args, **kwargs):
        result = writer(*args, **kwargs)
        path = output / "stability.json"
        raw = path.read_bytes()
        if kind == "inode":
            path.rename(path.with_suffix(".retained"))
            path.write_bytes(raw)
            path.chmod(0o600)
        elif kind == "directory":
            output.rename(output.with_name("retained-output"))
            output.mkdir(mode=0o700)
            path.write_bytes(raw)
            path.chmod(0o600)
        elif kind == "mode":
            path.chmod(0o644)
        else:
            path.write_bytes(raw + b" ")
        return result

    monkeypatch.setattr(orchestration, "write_development_corpus_stability", written)
    result = invoke(selection, output)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    assert old == [p.read_bytes() for p in paths]


@pytest.mark.parametrize("which", ["input_ancestor", "output_parent"])
def test_directory_object_replacement_is_not_rebased_after_computation(
    tmp_path, monkeypatch, which
):
    _, selection, paths, output = case(tmp_path)
    output_parent = tmp_path / "outputs"
    output_parent.mkdir()
    output = output_parent / "run"
    compute = orchestration.measure_development_corpus_stability

    def computed(**kwargs):
        result = compute(**kwargs)
        if which == "output_parent":
            output_parent.rename(tmp_path / "retained-outputs")
            output_parent.mkdir()
        else:
            old = {p.relative_to(selection.parent): p.read_bytes() for p in [selection, *paths]}
            selection.parent.rename(selection.parent.with_name("retained-middle"))
            selection.parent.mkdir()
            for relative, content in old.items():
                p = selection.parent / relative
                p.parent.mkdir(exist_ok=True)
                p.write_bytes(content)
                p.chmod(0o600)
        return result

    monkeypatch.setattr(orchestration, "measure_development_corpus_stability", computed)
    result = invoke(selection, output)
    assert result.exit_code == int(ExitCode.CONFIGURATION)
    assert not output.exists()


@pytest.mark.parametrize(
    "option",
    [
        "--truth-file",
        "--cost-ledger",
        "--secrets-env-file",
        "--provider-endpoint",
        "--run-id",
        "--retry",
        "--ignore-missing",
    ],
)
def test_cli_exposes_no_truth_provider_retry_or_missing_evidence_override(tmp_path, option):
    _, selection, _, output = case(tmp_path)
    result = invoke(selection, output, option, "synthetic-unselected")
    assert result.exit_code != 0 and not output.exists()
