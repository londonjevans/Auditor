"""Whole synthetic tree capture, actual loader/CLI and retained mock ensemble custody."""

from __future__ import annotations

import json
import os
import socket
import subprocess
from dataclasses import replace

import pytest
from typer.testing import CliRunner

from mmaudit import development_cli
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.development_corpus import DevelopmentCorpusManifest
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.repository import development_corpus as corpus_io
from mmaudit.repository import development_corpus_tree as tree_io
from tests.development_corpus_ensemble_support import manifest_ensemble_case
from tests.integration.test_development_corpus_ensemble_execution import (
    execute,
    execution_case,
    retained,
)
from tests.unit.test_development_dependency_targets import target_sources


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("tree capture attempted network, credentials or child execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)


def tree_case(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    for path, raw in target_sources():
        target = root / path
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(raw)
    (root / "empty").mkdir()
    (root / "README.txt").write_text("Synthetic non-source metadata; never model input.\n")
    remappings = tmp_path / "remappings.txt"
    remappings.write_text("@local/=lib/\n")
    return dict(
        corpus_root=root,
        remappings_file=remappings,
        corpus_id="synthetic-tree",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
    )


def capture(case):
    return tree_io.capture_development_corpus_tree(**case)


def frozen_load(tmp_path):
    case = tree_case(tmp_path)
    output = tmp_path / "frozen"
    manifest = tree_io.freeze_development_corpus_tree(**case, output_dir=output)
    loaded = corpus_io.load_development_corpus(
        manifest_file=output / "manifest.json", corpus_root=case["corpus_root"]
    )
    assert loaded.material.manifest == manifest
    return case, loaded


def test_capture_enumerates_all_sources_and_empty_directories_without_reading_non_source(
    tmp_path, monkeypatch
):
    case = tree_case(tmp_path)
    (case["corpus_root"] / ".env").write_text("SYNTHETIC_DO_NOT_READ")
    original = tree_io.read_file_evidence
    reads = []

    def selected_reads(**kwargs):
        reads.append(kwargs["relative_path"])
        assert kwargs["relative_path"] not in {".env", "README.txt"}
        return original(**kwargs)

    monkeypatch.setattr(tree_io, "read_file_evidence", selected_reads)
    result = capture(case)
    assert result.material.source_files == target_sources()
    evidence = result.material.manifest.source_tree_evidence
    assert evidence.solidity_file_count == 8 and evidence.non_source_file_count == 2
    assert [d.path for d in evidence.directories] == [".", "empty", "lib", "src"]
    assert "SYNTHETIC_DO_NOT_READ" not in result.material.model_dump_json()
    assert "README.txt" not in result.material.manifest.model_dump_json()
    assert set(reads) == {"remappings.txt", *(p for p, _ in target_sources())}


@pytest.mark.parametrize(
    "change",
    [
        "add_source",
        "remove_source",
        "add_directory",
        "replace_source",
        "replace_directory",
        "non_source_change",
    ],
)
def test_loaded_tree_refuses_scope_or_object_drift_even_when_selected_hashes_can_match(
    tmp_path, change
):
    case, loaded = frozen_load(tmp_path)
    root = case["corpus_root"]
    source = root / "src/InheritedReserve.sol"
    if change == "add_source":
        (root / "Extra.sol").write_bytes(target_sources()[0][1])
    elif change == "remove_source":
        source.unlink()
    elif change == "add_directory":
        (root / "extra").mkdir()
    elif change == "replace_source":
        raw = source.read_bytes()
        source.rename(tmp_path / "old-source.sol")
        source.write_bytes(raw)
    elif change == "replace_directory":
        original = root / "src"
        original.rename(tmp_path / "old-src")
        original.mkdir()
        for path in (tmp_path / "old-src").iterdir():
            (original / path.name).write_bytes(path.read_bytes())
    else:
        (root / "README.txt").write_text("Changed metadata snapshot")
    with pytest.raises((OSError, ValueError)):
        corpus_io.revalidate_loaded_development_corpus(loaded)


@pytest.mark.parametrize(
    "change",
    [
        "symlink_file",
        "symlink_directory",
        "hardlink",
        "fifo",
        "sensitive_directory",
        "uppercase_source",
    ],
)
def test_capture_refuses_unreadable_scope_without_silently_excluding_it(tmp_path, change):
    case = tree_case(tmp_path)
    root = case["corpus_root"]
    if change == "symlink_file":
        (root / "Linked.sol").symlink_to(root / "src/InheritedReserve.sol")
    elif change == "symlink_directory":
        (root / "linked").symlink_to(root / "src", target_is_directory=True)
    elif change == "hardlink":
        os.link(root / "src/InheritedReserve.sol", root / "Shared.sol")
    elif change == "fifo":
        os.mkfifo(root / "Waiting.sol")
    elif change == "sensitive_directory":
        (root / ".git").mkdir()
    else:
        (root / "Upper.SOL").write_bytes(target_sources()[0][1])
    with pytest.raises((OSError, ValueError)):
        capture(case)


@pytest.mark.parametrize(
    "bound,value",
    [
        ("MAX_DEVELOPMENT_TREE_ENTRIES", 2),
        ("MAX_DEVELOPMENT_TREE_DIRECTORIES", 2),
        ("MAX_DEVELOPMENT_CORPUS_FILES", 2),
        ("MAX_DEVELOPMENT_CORPUS_BYTES", 50),
        ("MAX_DEVELOPMENT_CORPUS_FILE_BYTES", 50),
    ],
)
def test_namespace_capacity_refuses_before_any_source_content_read(
    tmp_path, monkeypatch, bound, value
):
    case = tree_case(tmp_path)
    monkeypatch.setattr(tree_io, bound, value)
    original = tree_io.read_file_evidence

    def remappings_only(**kwargs):
        assert kwargs["relative_path"] == "remappings.txt"
        return original(**kwargs)

    monkeypatch.setattr(tree_io, "read_file_evidence", remappings_only)
    with pytest.raises(ValueError, match=r"ceiling|bounds"):
        capture(case)


def test_namespace_mutation_between_observations_is_not_a_complete_snapshot(tmp_path, monkeypatch):
    case = tree_case(tmp_path)
    original = tree_io._observe_namespace_once
    calls = 0

    def mutate(root):
        nonlocal calls
        result = original(root)
        calls += 1
        if calls == 1:
            (root / "Late.sol").write_bytes(target_sources()[0][1])
        return result

    monkeypatch.setattr(tree_io, "_observe_namespace_once", mutate)
    with pytest.raises(ValueError, match="between namespace"):
        capture(case)


def test_remapping_drift_is_not_adopted_by_a_captured_tree(tmp_path):
    case = tree_case(tmp_path)
    captured = capture(case)
    case["remappings_file"].write_text("@local/=changed/\n")
    with pytest.raises(ValueError, match="remapping input changed"):
        tree_io.revalidate_captured_development_corpus_tree(captured)


def test_scope_mutation_during_source_read_refuses_capture(tmp_path, monkeypatch):
    case = tree_case(tmp_path)
    original = tree_io.read_file_evidence
    changed = False

    def mutate(**kwargs):
        nonlocal changed
        result = original(**kwargs)
        if kwargs["relative_path"].endswith(".sol") and not changed:
            changed = True
            (case["corpus_root"] / "Late.sol").write_bytes(target_sources()[0][1])
        return result

    monkeypatch.setattr(tree_io, "read_file_evidence", mutate)
    with pytest.raises(ValueError, match="custody"):
        capture(case)


def test_unreadable_nested_namespace_cannot_be_skipped(tmp_path, monkeypatch):
    case = tree_case(tmp_path)
    original = tree_io._open_parent

    def refuse_nested(root, path):
        if path.startswith("src/"):
            raise PermissionError("Synthetic unreadable source directory")
        return original(root, path)

    monkeypatch.setattr(tree_io, "_open_parent", refuse_nested)
    with pytest.raises(ValueError, match="every entry safely"):
        capture(case)


def test_case_colliding_directory_receipt_and_sensitive_root_are_refused(tmp_path):
    from mmaudit.models.development_corpus import DevelopmentCorpusTreeEvidence

    case = tree_case(tmp_path)
    data = capture(case).material.manifest.source_tree_evidence.model_dump(mode="json")
    data["directories"][-1]["path"] = "LIB"
    data["directories"].sort(key=lambda d: d["path"])
    data["tree_sha256"] = canonical_sha256({k: v for k, v in data.items() if k != "tree_sha256"})
    with pytest.raises(ValueError, match="namespace"):
        DevelopmentCorpusTreeEvidence.model_validate_json(json.dumps(data), strict=True)
    sensitive = tmp_path / ".git"
    sensitive.mkdir()
    with pytest.raises(ValueError, match="local root"):
        tree_io.observe_development_corpus_tree(sensitive)


def test_forged_retained_source_material_cannot_pass_tree_revalidation(tmp_path):
    from mmaudit.models.development_corpus import DevelopmentCorpusText

    captured = capture(tree_case(tmp_path))
    first = captured.material.sources[0]
    changed = DevelopmentCorpusText(filename=first.filename, content=first.content + "\n")
    material = captured.material.model_copy(
        update={"sources": (changed, *captured.material.sources[1:])}
    )
    with pytest.raises(ValueError):
        tree_io.revalidate_captured_development_corpus_tree(replace(captured, material=material))


def test_loader_refuses_resealed_namespace_and_missing_custody_observation(tmp_path):
    case, loaded = frozen_load(tmp_path)
    with pytest.raises(ValueError, match="observation is missing"):
        corpus_io.revalidate_loaded_development_corpus(replace(loaded, tree_observation=None))
    data = loaded.material.manifest.model_dump(mode="json")
    evidence = data["source_tree_evidence"]
    evidence["directories"][0]["entries_sha256"] = "0" * 64
    evidence["tree_sha256"] = canonical_sha256(
        {k: v for k, v in evidence.items() if k != "tree_sha256"}
    )
    data["manifest_sha256"] = canonical_sha256(
        {k: v for k, v in data.items() if k != "manifest_sha256"}
    )
    forged = DevelopmentCorpusManifest.model_validate_json(json.dumps(data), strict=True)
    loaded.manifest_file.write_text(forged.model_dump_json())
    with pytest.raises(ValueError, match="namespace"):
        corpus_io.load_development_corpus(
            manifest_file=loaded.manifest_file, corpus_root=case["corpus_root"]
        )


def test_provider_free_cli_freezes_actual_complete_tree_and_loader_replays_it(tmp_path):
    case = tree_case(tmp_path)
    output = tmp_path / "frozen"
    arguments = [
        "development",
        "freeze-tree",
        "--corpus-root",
        str(case["corpus_root"]),
        "--remappings-file",
        str(case["remappings_file"]),
        "--corpus-id",
        case["corpus_id"],
        "--source-scope",
        case["source_scope"],
        "--output-dir",
        str(output),
    ]
    result = CliRunner().invoke(app, arguments)
    assert result.exit_code == int(ExitCode.SUCCESS), result.output
    assert "root replay required" in result.output
    loaded = corpus_io.load_development_corpus(
        manifest_file=output / "manifest.json", corpus_root=case["corpus_root"]
    )
    assert loaded.material.source_files == target_sources()
    assert output.stat().st_mode & 0o777 == 0o700
    assert (output / "manifest.json").stat().st_mode & 0o777 == 0o600


def test_freeze_output_overlap_refuses_before_source_reads(tmp_path, monkeypatch):
    case = tree_case(tmp_path)

    def forbidden(**_kwargs):
        pytest.fail("overlapping output reached source capture")

    monkeypatch.setattr(tree_io, "capture_development_corpus_tree", forbidden)
    with pytest.raises(ValueError, match="overlaps"):
        tree_io.freeze_development_corpus_tree(**case, output_dir=case["corpus_root"] / "output")


def test_tree_change_during_output_validation_removes_only_the_unaccepted_manifest(
    tmp_path, monkeypatch
):
    case = tree_case(tmp_path)
    original = tree_io.write_json_evidence

    def changed(**kwargs):
        (case["corpus_root"] / "Late.sol").write_bytes(target_sources()[0][1])
        return original(**kwargs)

    monkeypatch.setattr(tree_io, "write_json_evidence", changed)
    output = tmp_path / "frozen"
    with pytest.raises(ValueError, match="custody"):
        tree_io.freeze_development_corpus_tree(**case, output_dir=output)
    assert not (output / "manifest.json").exists()
    assert (case["corpus_root"] / "Late.sol").is_file()


@pytest.mark.asyncio
async def test_tree_manifest_sources_and_namespace_reach_actual_candidate_and_both_reviewers(
    tmp_path,
):
    _case, loaded = frozen_load(tmp_path)
    prepared = manifest_ensemble_case(
        source_files=loaded.material.source_files,
        manifest=loaded.material.manifest,
        source_custody=loaded,
    )
    case = execution_case(tmp_path, prepared=prepared, scored=False)

    def inspect(_role, _ordinal, request):
        prompt = json.loads(request.content)["messages"][1]["content"]
        assert loaded.material.manifest.source_tree_evidence.model_dump_json() in prompt
        assert all("Source file: " + p in prompt for p, _ in target_sources())
        assert "return 2;" in prompt and "NOT_ESTABLISHED" in prompt

    result = await execute(case, custom=inspect)
    assert case.counts == [8, 8, 8] and result == retained(case)
    assert not result.audit_complete and not result.qualification_eligible
