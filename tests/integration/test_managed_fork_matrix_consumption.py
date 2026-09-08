"""Actual offline prepared pipeline: unavailable matrix remains incomplete, without execution."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess

import pytest

from mmaudit.models.schemas import RepositoryDifferentialRunStatus
from mmaudit.orchestration.manifest import load_run_evidence_manifest, validate_manifest_artifacts
from mmaudit.orchestration.pipeline import AuditPipeline
from mmaudit.repository import discovery
from mmaudit.scanners.base import scanner_workspace_sha256
from tests.unit.test_managed_fork_matrix import _Backend, prepared_matrix


@pytest.mark.asyncio
@pytest.mark.parametrize("repeat", [False, True])
async def test_prepared_matrix_pipeline_publishes_truthful_failure_without_rpc_or_tools(
    tmp_path, config_factory, monkeypatch, repeat
):
    repository, material, private, _ = prepared_matrix(tmp_path, config_factory)
    original_source = scanner_workspace_sha256(repository)

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: unavailable prepared matrix cannot execute, connect or search PATH")

    with monkeypatch.context() as patch:
        patch.setattr(subprocess, "Popen", forbidden)
        patch.setattr(shutil, "which", forbidden)
        patch.setattr(socket, "socket", forbidden)
        patch.setattr(discovery, "_git_commit", lambda root: None)
        audit = AuditPipeline(
            material.config,
            repo=repository,
            output=private,
            host_tools=material,
            managed_backend=_Backend(),
        )
        for _ in range(2 if repeat else 1):
            result = await audit.run(scanner_only=True)
            matrix = result.report.repository_suite_differential
            assert matrix is not None
            assert matrix.status is RepositoryDifferentialRunStatus.FAILED
            assert matrix.matrix is None
            assert any("isolation" in item for item in matrix.limitations)
            assert result.report.completed is False
            assert result.report.usage == []
            published = json.loads((result.run_dir / "final-findings.json").read_text())
            assert published["completed"] is False
            assert published["repository_suite_differential"]["status"] == matrix.status.value
            validate_manifest_artifacts(
                load_run_evidence_manifest(result.run_dir / "run-evidence-manifest.json"),
                result.run_dir,
            )
            assert not (result.run_dir / "private/repository-fork-matrix").exists()
    assert scanner_workspace_sha256(repository) == original_source
    assert material.runtime_authority is material.managed_run_ready is False
    assert audit.client is None and audit.api_key == "" and audit._run_log_handler is None
