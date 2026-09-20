"""Exact retained-input/plan replay under synthetic local custody and no-execution traps."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, NoReturn

import pytest

from mmaudit.orchestration import mutation_reconstruction as reconstruction
from mmaudit.orchestration.mutation_pipeline import MutationProjectExecution
from mmaudit.release_io import read_composed_file_evidence
from mmaudit.scanners.foundry_inventory import parse_foundry_test_inventory
from tests.mutation_reconstruction_support import project_pin, reconstruction_case, source_binding


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        pytest.fail("retained mutation reader attempted network/process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def load(
    project: MutationProjectExecution, root: Path, **kwargs: Any
) -> reconstruction.ReconstructedMutationProject:
    return reconstruction.reconstruct_mutation_project(
        project=project, expected_project_sha256=project_pin(project), artifact_root=root, **kwargs
    )


def replace_bound_input(
    project: MutationProjectExecution, root: Path, name: str, raw: bytes
) -> MutationProjectExecution:
    """Reseal only synthetic declarations to exercise joins beyond a simple stale file hash."""

    (root / name).write_bytes(raw)
    replaced = source_binding(name, raw)
    manifest_path = "compiler-inputs/manifest.json"
    if name != manifest_path:
        value = json.loads((root / manifest_path).read_bytes())

        def update(value: Any) -> Any:
            if isinstance(value, dict):
                if value.get("path") == name and set(value) == {"path", "sha256", "size"}:
                    return replaced.model_dump()
                return {k: update(v) for k, v in value.items()}
            if isinstance(value, list):
                return [update(v) for v in value]
            return value

        (root / manifest_path).write_text(json.dumps(update(value)))
    manifest = source_binding(manifest_path, (root / manifest_path).read_bytes())
    values = project.model_dump(mode="python")
    values["compiler_input_files"] = [
        manifest if b.path == manifest_path else replaced if b.path == name else b
        for b in project.compiler_input_files
    ]
    return MutationProjectExecution.model_validate(values)


def test_original_writer_reconstructs_exact_inventory_counts_and_complete_plan(
    tmp_path: Path,
) -> None:
    project, original = reconstruction_case(tmp_path)
    result = load(project, tmp_path)
    assert result.inventory == original and result.plan == project.plan
    assert result.project_sha256 == project_pin(project)
    assert result.evidence_authority == "COLLECTED_UNATTESTED"
    assert not result.execution_validated and not result.qualification_eligible
    assert result.plan.discovery is not None and len(result.plan.discovery.source_classes) == 11
    assert len(result.plan.bindings) == len(result.plan.non_applicability) == 2


@pytest.mark.parametrize(
    "case", ["pin", "legacy", "duplicate", "order", "relative-root", "no-plan"]
)
def test_ambiguous_or_unpinned_selection_refuses_before_input_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    project, _ = reconstruction_case(tmp_path)
    values = project.model_dump(mode="python")
    if case == "legacy":
        values["compiler_input_files"] = [
            b for b in project.compiler_input_files if b.path != "compiler-inputs/manifest.json"
        ]
    if case == "duplicate":
        values["compiler_input_files"] = [
            *project.compiler_input_files,
            project.compiler_input_files[0],
        ]
    if case == "order":
        values["compiler_input_files"] = list(reversed(project.compiler_input_files))
    if case == "no-plan":
        values.update(plan=None, score=None)
    selected = MutationProjectExecution.model_validate(values)

    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        pytest.fail("invalid selection reached private input traversal")

    monkeypatch.setattr(reconstruction, "_input_tree", forbidden)
    with pytest.raises(ValueError):
        reconstruction.reconstruct_mutation_project(
            project=selected,
            expected_project_sha256="0" * 64 if case == "pin" else project_pin(selected),
            artifact_root=Path("relative") if case == "relative-root" else tmp_path,
        )


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "changed",
        "extra-file",
        "extra-directory",
        "hidden",
        "link",
        "hardlink",
        "fifo",
        "file-directory",
        "root-link",
        "parent-link",
    ],
)
def test_exact_input_tree_refuses_missing_extra_or_unsafe_members(
    tmp_path: Path, case: str
) -> None:
    project, _ = reconstruction_case(tmp_path)
    root = tmp_path / "compiler-inputs"
    file = root / "project-0000/forge-list.json"
    if case == "missing":
        file.unlink()
    elif case == "changed":
        file.write_bytes(file.read_bytes() + b" ")
    elif case in {"extra-file", "hidden"}:
        (root / ("extra.json" if case == "extra-file" else ".hidden")).write_text("{}")
    elif case == "extra-directory":
        (root / "extra").mkdir()
    elif case in {"link", "hardlink", "fifo", "file-directory"}:
        original = file.read_bytes()
        file.unlink()
        target = tmp_path / "synthetic-original.json"
        target.write_bytes(original)
        if case == "link":
            file.symlink_to(target)
        elif case == "hardlink":
            os.link(target, file)
        elif case == "fifo":
            os.mkfifo(file)
        else:
            file.mkdir()
    else:
        selected = root if case == "root-link" else root / "project-0000"
        moved = tmp_path / "synthetic-moved"
        selected.rename(moved)
        selected.symlink_to(moved, target_is_directory=True)
    with pytest.raises(ValueError):
        load(project, tmp_path)


@pytest.mark.parametrize(
    "case",
    [
        "schema",
        "duplicate-json-key",
        "nonfinite",
        "missing-source-index",
        "project",
        "accounting",
        "build-json",
        "forge-tests",
        "parser-limit",
        "duplicate-build",
        "evidence-path",
        "source-bytes",
    ],
)
def test_resealed_metadata_cannot_override_original_parser_evidence_and_scope(
    tmp_path: Path, case: str
) -> None:
    project, _ = reconstruction_case(tmp_path)
    name = "compiler-inputs/manifest.json"
    value = json.loads((tmp_path / name).read_bytes())
    if case == "schema":
        value["schema_version"] = "2.0"
    elif case == "missing-source-index":
        value["projects"][0]["sources"].pop()
    elif case == "project":
        value["projects"][0]["project_root"] = "packages/elsewhere"
    elif case == "accounting":
        value["accounted_output_bytes"] += 1
    elif case == "duplicate-build":
        value["projects"][0]["build_info"] *= 2
    elif case == "evidence-path":
        value["evidence"]["path"] = "compiler-inputs/elsewhere.json"
    elif case in {"build-json", "forge-tests", "parser-limit", "source-bytes"}:
        key = {
            "build-json": "build_info",
            "forge-tests": "forge_list",
            "parser-limit": "parser_limits",
            "source-bytes": "sources",
        }[case]
        item = value["projects"][0][key]
        name = (item[0] if isinstance(item, list) else item)["path"]
        if case == "parser-limit":
            value = json.loads((tmp_path / name).read_bytes())
            value["max_build_info_json_bytes"] = 1024
    raw = json.dumps(value).encode()
    if case == "duplicate-json-key":
        raw = b'{"schema_version":"1.0",' + raw[1:]
    elif case == "nonfinite":
        raw = b'{"schema_version":NaN}'
    elif case == "build-json":
        raw = b"{"
    elif case == "forge-tests":
        raw = (tmp_path / name).read_bytes().replace(b"Authorization", b"Unselected")
    elif case == "source-bytes":
        raw = (tmp_path / name).read_bytes() + b"\n// synthetic source drift\n"
    modified = replace_bound_input(project, tmp_path, name, raw)
    with pytest.raises(ValueError):
        load(modified, tmp_path)


@pytest.mark.parametrize("case", ["file", "parent", "root", "parse"])
def test_same_byte_replacement_during_read_or_parse_cannot_reuse_initial_custody(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    project, _ = reconstruction_case(tmp_path)
    root = tmp_path / "compiler-inputs"
    changed = False

    def change() -> None:
        nonlocal changed
        if changed:
            return
        changed = True
        if case in {"file", "parse"}:
            file = root / "project-0000/forge-list.json"
            replacement = tmp_path / "synthetic-replacement.json"
            replacement.write_bytes(file.read_bytes())
            replacement.replace(file)
        else:
            selected = root if case == "root" else root / "project-0000"
            moved = tmp_path / "synthetic-moved"
            selected.rename(moved)
            shutil.copytree(moved, selected)

    if case == "parse":
        parser = parse_foundry_test_inventory

        def parse(**kwargs: Any) -> Any:
            result = parser(**kwargs)
            change()
            return result

        monkeypatch.setattr(reconstruction, "parse_foundry_test_inventory", parse)
    else:
        reader = read_composed_file_evidence

        def read(**kwargs: Any) -> Any:
            change()
            return reader(**kwargs)

        monkeypatch.setattr(reconstruction, "read_composed_file_evidence", read)
    with pytest.raises(ValueError):
        load(project, tmp_path)
    assert changed


@pytest.mark.parametrize("case", ["file", "files", "total", "deadline"])
def test_reconstruction_bounds_refuse_before_any_input_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    project, _ = reconstruction_case(tmp_path)
    bounds: dict[str, Any] = {}
    if case == "file":
        bounds["maximum_file_bytes"] = max(b.size for b in project.compiler_input_files) - 1
    elif case == "files":
        bounds["maximum_files"] = len(project.compiler_input_files) - 1
    elif case == "total":
        bounds["maximum_total_bytes"] = sum(b.size for b in project.compiler_input_files) - 1

    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        pytest.fail("exhausted reconstruction bounds reached the input tree")

    monkeypatch.setattr(reconstruction, "_input_tree", forbidden)
    with pytest.raises(ValueError):
        load(
            project,
            tmp_path,
            limits=reconstruction.MutationReconstructionLimits(**bounds),
            absolute_deadline=time.monotonic() - 1 if case == "deadline" else None,
        )


@pytest.mark.parametrize("deadline", [True, float("inf"), float("-inf"), float("nan")])
def test_invalid_absolute_reconstruction_deadline_refuses(tmp_path: Path, deadline: float) -> None:
    project, _ = reconstruction_case(tmp_path)
    with pytest.raises(ValueError, match="finite"):
        load(project, tmp_path, absolute_deadline=deadline)


@pytest.mark.parametrize("boundary", ["parser", "final-tree"])
def test_expired_post_operation_deadline_cannot_return_reconstructed_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    project, _ = reconstruction_case(tmp_path)
    now = 100.0
    monkeypatch.setattr(time, "monotonic", lambda: now)
    observed = 0
    original = parse_foundry_test_inventory if boundary == "parser" else reconstruction._input_tree

    def expire(*args: Any, **kwargs: Any) -> Any:
        nonlocal now, observed
        result = original(*args, **kwargs)
        observed += 1
        if boundary == "parser" or observed == 2:
            now = 200.0
        return result

    monkeypatch.setattr(
        reconstruction,
        "parse_foundry_test_inventory" if boundary == "parser" else "_input_tree",
        expire,
    )
    with pytest.raises(ValueError, match="deadline exceeded"):
        load(project, tmp_path, absolute_deadline=150.0)
    assert observed == (1 if boundary == "parser" else 2)


def test_exact_file_count_and_byte_bounds_are_admitted(tmp_path: Path) -> None:
    project, original = reconstruction_case(tmp_path)
    limits = reconstruction.MutationReconstructionLimits(
        maximum_files=len(project.compiler_input_files),
        maximum_file_bytes=max(b.size for b in project.compiler_input_files),
        maximum_total_bytes=sum(b.size for b in project.compiler_input_files),
    )
    assert load(project, tmp_path, limits=limits).inventory == original


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("evidence_authority", "AUTHENTICATED"),
        ("execution_validated", True),
        ("qualification_eligible", True),
        ("unexpected_authority", True),
    ],
)
def test_resealed_manifest_cannot_declare_runtime_authority(
    tmp_path: Path, field: str, value: object
) -> None:
    project, _ = reconstruction_case(tmp_path)
    name = "compiler-inputs/manifest.json"
    payload = json.loads((tmp_path / name).read_bytes())
    payload[field] = value
    selected = replace_bound_input(project, tmp_path, name, json.dumps(payload).encode())
    with pytest.raises(ValueError):
        load(selected, tmp_path)
