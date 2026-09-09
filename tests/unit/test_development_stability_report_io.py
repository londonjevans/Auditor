"""Private report writes cannot adopt aliases, overwritten evidence or drifting source custody."""

import hashlib
import os
import socket
import stat
import subprocess
from pathlib import Path

import pytest

import mmaudit.orchestration.development_corpus_stability as writer
from mmaudit.reporting.development_stability import render_development_stability_report
from mmaudit.repository.file_custody import (
    observe_regular_file_custody,
    require_regular_file_custody_unchanged,
)
from tests.unit.test_development_corpus_stability import evaluate


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("candidate report writer attempted network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.fixture
def measured():
    return evaluate((True, False))


def test_private_owned_report_preserves_exact_bytes_and_returns_file_custody(tmp_path, measured):
    output = tmp_path / "reports"
    output.mkdir(mode=0o700)
    calls = []
    written = writer.write_development_stability_report(
        output, stability=measured, revalidate_context=lambda: calls.append(True)
    )
    raw = (output / "stability.md").read_bytes()
    assert raw == render_development_stability_report(stability=measured).encode()
    assert written.binding.path == "stability.md"
    assert written.binding.sha256 == hashlib.sha256(raw).hexdigest()
    assert written.binding.size == len(raw)
    assert stat.S_IMODE(written.identity[2]) == 0o600
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert len(calls) >= 5
    require_regular_file_custody_unchanged(written, label="test report")


@pytest.mark.parametrize(
    "kind", ["existing", "symlink", "dangling", "hardlink", "directory", "fifo"]
)
def test_report_refuses_every_occupied_leaf_without_overwriting_it(tmp_path, measured, kind):
    output = tmp_path / "reports"
    output.mkdir(mode=0o700)
    retained = tmp_path / "retained.txt"
    retained.write_bytes(b"synthetic preserved evidence")
    leaf = output / "stability.md"
    if kind == "existing":
        leaf.write_bytes(retained.read_bytes())
    elif kind == "symlink":
        leaf.symlink_to(retained)
    elif kind == "dangling":
        leaf.symlink_to("missing.txt")
    elif kind == "hardlink":
        os.link(retained, leaf)
    elif kind == "directory":
        leaf.mkdir()
    else:
        os.mkfifo(leaf)
    identity = leaf.lstat()
    with pytest.raises(ValueError):
        writer.write_development_stability_report(
            output, stability=measured, revalidate_context=lambda: None
        )
    assert leaf.lstat() == identity
    assert retained.read_bytes() == b"synthetic preserved evidence"


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o770, 0o777])
def test_report_requires_an_owned_0700_output_directory(tmp_path, measured, mode):
    tmp_path.chmod(mode)
    with pytest.raises(ValueError, match="private and owned"):
        writer.write_development_stability_report(
            tmp_path, stability=measured, revalidate_context=lambda: None
        )
    assert not (tmp_path / "stability.md").exists()


def test_writer_retains_created_inode_across_the_byte_writer_return(
    tmp_path, monkeypatch, measured
):
    tmp_path.chmod(0o700)
    original = writer._write_file_content

    def replaced(**kwargs):
        binding = original(**kwargs)
        path = tmp_path / "stability.md"
        content = path.read_bytes()
        path.rename(tmp_path / "retained-original.md")
        path.write_bytes(content)
        path.chmod(0o600)
        return binding

    monkeypatch.setattr(writer, "_write_file_content", replaced)
    with pytest.raises(ValueError):
        writer.write_development_stability_report(
            tmp_path, stability=measured, revalidate_context=lambda: None
        )


@pytest.mark.parametrize("when", ["render", "write", "return"])
@pytest.mark.parametrize("kind", ["bytes", "inode", "mode"])
def test_writer_never_accepts_source_mutation_at_any_derivative_boundary(
    tmp_path, monkeypatch, measured, when, kind
):
    source = tmp_path / "source.json"
    source.write_text(measured.model_dump_json())
    source.chmod(0o600)
    custody = observe_regular_file_custody(root=tmp_path, relative_path=source.name, label="source")
    output = tmp_path / "reports"
    output.mkdir(mode=0o700)

    def mutate():
        if kind == "bytes":
            source.write_bytes(source.read_bytes() + b" ")
        elif kind == "inode":
            old = source.read_bytes()
            source.rename(source.with_suffix(".retained"))
            source.write_bytes(old)
            source.chmod(0o600)
        else:
            source.chmod(0o644)

    original_render = writer.render_development_stability_report
    original_write = writer._write_file_content
    original_observe = writer.observe_regular_file_custody

    def rendered(**kwargs):
        text = original_render(**kwargs)
        if when == "render":
            mutate()
        return text

    def written(**kwargs):
        bound = original_write(**kwargs)
        if when == "write":
            mutate()
        return bound

    def observed(**kwargs):
        result = original_observe(**kwargs)
        if when == "return":
            mutate()
        return result

    monkeypatch.setattr(writer, "render_development_stability_report", rendered)
    monkeypatch.setattr(writer, "_write_file_content", written)
    monkeypatch.setattr(writer, "observe_regular_file_custody", observed)
    with pytest.raises(ValueError):
        writer.write_development_stability_report(
            output,
            stability=measured,
            revalidate_context=lambda: require_regular_file_custody_unchanged(
                custody, label="source", allow_directory_entry_metadata_change=True
            ),
        )
    if when == "render":
        assert not (output / "stability.md").exists()


@pytest.mark.parametrize(
    "path,context",
    [
        (Path("relative"), lambda: None),
        ("not-a-path", lambda: None),
        (Path("/unused/../output"), lambda: None),
        (Path("/unused"), None),
    ],
)
def test_writer_refuses_noncanonical_outputs_and_missing_context(path, context, measured):
    with pytest.raises(ValueError, match="normalized output and context"):
        writer.write_development_stability_report(
            path, stability=measured, revalidate_context=context
        )
