"""Original writer and fresh-process reconstruction using only disposable synthetic inputs."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, NoReturn

import pytest

from mmaudit.orchestration.mutation_pipeline import MutationPipelineArtifact
from tests.integration.test_mutation_pipeline_execution import (
    test_original_source_local_pipeline_collects_native_campaigns_and_disposes_workspaces as _run_native_control,
)
from tests.mutation_reconstruction_support import project_pin, reconstruction_case

_READ_ONLY_CHILD = """
import json, socket, subprocess, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from mmaudit.orchestration.mutation_pipeline import MutationProjectExecution
from mmaudit.orchestration.mutation_reconstruction import reconstruct_mutation_project
from mmaudit.release_io import read_file_evidence
def forbidden(*args, **kwargs):
    raise AssertionError('restart reconstruction attempted network/process execution')
socket.socket = forbidden
socket.create_connection = forbidden
subprocess.Popen = forbidden
path = Path(sys.argv[2])
raw = read_file_evidence(evidence_root=path.parent, relative_path=path.name).content
project = MutationProjectExecution.model_validate_json(raw)
result = reconstruct_mutation_project(project=project, expected_project_sha256=sys.argv[3], artifact_root=Path(sys.argv[4]))
print(json.dumps({'plan':result.plan.model_dump(mode='json'), 'accounted_output_bytes':result.inventory.accounted_output_bytes, 'generated_artifact_bytes':result.inventory.generated_artifact_bytes, 'execution_validated':result.execution_validated, 'qualification_eligible':result.qualification_eligible, 'authority':result.evidence_authority},separators=(',',':')))
"""


def _restart(
    project_path: Path, pin: str, artifact_root: Path
) -> subprocess.CompletedProcess[bytes]:
    executable = Path(sys.executable)
    repository = Path(__file__).resolve().parents[2]
    assert not executable.resolve(strict=True).is_relative_to(repository)
    result = subprocess.run(
        [
            str(executable),
            "-I",
            "-B",
            "-c",
            _READ_ONLY_CHILD,
            str(repository / "src"),
            str(project_path),
            pin,
            str(artifact_root),
        ],
        cwd=project_path.parent,
        env={
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C",
            "LC_ALL": "C",
            "MMAUDIT_RUN_REAL_PROVIDER_TESTS": "0",
            "MMAUDIT_SECRETS_ENV_FILE": "",
        },
        capture_output=True,
        timeout=60,
        check=False,
        shell=False,
    )
    assert len(result.stdout) < 4_000_000 and len(result.stderr) < 100_000
    (project_path.parent / "restart.stdout.json").write_bytes(result.stdout)
    (project_path.parent / "restart.stderr.txt").write_bytes(result.stderr)
    (project_path.parent / "restart.returncode.txt").write_text(str(result.returncode))
    return result


@pytest.mark.parametrize("project_root", [".", "packages/local"])
def test_original_native_pipeline_can_reconstruct_its_complete_plan_in_a_fresh_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, project_root: str
) -> None:
    _run_native_control(tmp_path, monkeypatch, (project_root,), 40)
    result = MutationPipelineArtifact.model_validate_json((tmp_path / "result.json").read_bytes())
    project = result.projects[0]
    assert project.plan is not None
    serialized = tmp_path / "selected-project.json"
    serialized.write_text(project.model_dump_json())
    private = tmp_path / "private/project-0000"
    before = {
        p.relative_to(private).as_posix(): (p.stat().st_ino, p.read_bytes())
        for p in private.rglob("*")
        if p.is_file()
    }
    restarted = _restart(serialized, project_pin(project), private)
    assert restarted.returncode == 0, restarted.stderr.decode()
    replay = json.loads(restarted.stdout)
    assert replay["plan"] == project.plan.model_dump(mode="json")
    manifest = json.loads((private / "compiler-inputs/manifest.json").read_bytes())
    assert replay["accounted_output_bytes"] == manifest["accounted_output_bytes"]
    assert replay["generated_artifact_bytes"] == manifest["generated_artifact_bytes"]
    assert replay["authority"] == "COLLECTED_UNATTESTED"
    assert not replay["execution_validated"] and not replay["qualification_eligible"]
    after = {
        p.relative_to(private).as_posix(): (p.stat().st_ino, p.read_bytes())
        for p in private.rglob("*")
        if p.is_file()
    }
    assert before == after
    assert project.source_preserved and project.workspace_disposed


@pytest.mark.parametrize("case", ["none", "missing", "changed", "extra", "link"])
def test_fresh_process_retained_input_readback_never_compiles_or_invents_missing_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        pytest.fail("synthetic restart control attempted a network connection")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    artifact_root = tmp_path / "retained"
    project, original = reconstruction_case(artifact_root)
    path = tmp_path / "selected-project.json"
    path.write_text(project.model_dump_json())
    selected = artifact_root / "compiler-inputs/project-0000/forge-list.json"
    if case == "missing":
        selected.unlink()
    elif case == "changed":
        selected.write_bytes(selected.read_bytes() + b" ")
    elif case == "extra":
        (artifact_root / "compiler-inputs/extra.txt").write_text("synthetic unexpected file")
    elif case == "link":
        renamed = tmp_path / "synthetic-linked.json"
        selected.rename(renamed)
        selected.symlink_to(renamed)
    result = _restart(path, project_pin(project), artifact_root)
    if case == "none":
        assert result.returncode == 0, result.stderr.decode()
        value = json.loads(result.stdout)
        assert project.plan is not None and value["plan"] == project.plan.model_dump(mode="json")
        assert value["accounted_output_bytes"] == original.accounted_output_bytes
        assert value["generated_artifact_bytes"] == original.generated_artifact_bytes
    else:
        assert result.returncode != 0 and not result.stdout
    assert not list(artifact_root.rglob("*.pyc"))
