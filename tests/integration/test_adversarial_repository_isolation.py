"""Real-or-fail-closed adversarial repository isolation coverage."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from mmaudit.adversarial_acceptance import (
    AdversarialAcceptanceObservation,
    AdversarialAcceptanceStatus,
    AdversarialCaseId,
    AdversarialDisposition,
    AdversarialEvidenceKind,
    build_adversarial_acceptance_report,
    load_adversarial_acceptance_manifest,
)
from mmaudit.isolation.container import discover_rootless_container_backend
from mmaudit.models.schemas import RepositoryCodeExecutionState
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.solidity.compile import compile_solidity_projects
from mmaudit.solidity.projects import discover_solidity_projects

FIXTURE = Path(__file__).parents[1] / "fixtures" / "adversarial_repository"


def _copy_fixture(tmp_path: Path) -> Path:
    root = tmp_path / "adversarial-repository"
    shutil.copytree(FIXTURE, root)
    return root


def _real_acceptance_observations(
    backend_name: str,
) -> list[AdversarialAcceptanceObservation]:
    static = {
        AdversarialCaseId.CRAFTED_NAMES: (
            AdversarialDisposition.DETERMINISTICALLY_CONTAINED,
            AdversarialEvidenceKind.PATH_NORMALIZATION,
        ),
        AdversarialCaseId.FAKE_BINARIES: (
            AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
            AdversarialEvidenceKind.EXTERNAL_EXECUTABLE_VALIDATION,
        ),
        AdversarialCaseId.PROMPT_INJECTION: (
            AdversarialDisposition.DETERMINISTICALLY_CONTAINED,
            AdversarialEvidenceKind.UNTRUSTED_CONTEXT,
        ),
        AdversarialCaseId.SYMLINK_ESCAPE: (
            AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
            AdversarialEvidenceKind.WORKSPACE_VALIDATION,
        ),
    }
    observations: list[AdversarialAcceptanceObservation] = []
    for case_id in AdversarialCaseId:
        if case_id in static:
            disposition, evidence_kind = static[case_id]
            observations.append(
                AdversarialAcceptanceObservation(
                    case_id=case_id,
                    disposition=disposition,
                    evidence_kind=evidence_kind,
                )
            )
        else:
            observations.append(
                AdversarialAcceptanceObservation(
                    case_id=case_id,
                    disposition=AdversarialDisposition.REAL_ISOLATION_CONTAINED,
                    evidence_kind=AdversarialEvidenceKind.ROOTLESS_RUNTIME,
                    real_isolation_backend=backend_name,
                )
            )
    return observations


def test_adversarial_repository_fails_closed_without_off_host_execution(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_fixture(tmp_path)
    config = config_factory(
        privacy={"fail_on_detected_secret": False},
        smart_contracts={"compile": True},
    )
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    monkeypatch.setattr(
        "mmaudit.solidity.compile.default_isolation_backend",
        lambda configured: None,
    )
    monkeypatch.setattr(
        "mmaudit.solidity.compile.subprocess.Popen",
        lambda *args, **kwargs: pytest.fail("repository code must not execute"),
    )

    compilation = compile_solidity_projects(
        root,
        projects,
        config.smart_contracts,
        tmp_path / "private-fail-closed",
    )

    result = compilation.results[0]
    assert result.status == "unavailable"
    assert result.repository_code_execution is RepositoryCodeExecutionState.BLOCKED
    assert not list(root.rglob("*.marker"))


def test_real_rootless_backend_contains_adversarial_runtime_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = os.environ.get("MMAUDIT_TEST_ROOTLESS_IMAGE")
    if image is None:
        pytest.skip("MMAUDIT_TEST_ROOTLESS_IMAGE is not configured")
    backend = discover_rootless_container_backend(image)
    if backend is None:
        pytest.skip("no verified rootless Docker or Podman runtime is available")

    source_hashes = {
        path.relative_to(FIXTURE): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in FIXTURE.rglob("*")
        if path.is_file()
    }
    private = tmp_path / "private-adversarial"
    workspace = private / "workspace"
    shutil.copytree(FIXTURE, workspace)
    monkeypatch.setenv("MMAUDIT_HOST_ENV_CANARY", "synthetic-host-value")
    command = backend.wrap_repository_javascript(
        [
            "/bin/sh",
            "-c",
            "command -v node >/dev/null 2>&1 || exit 77; node probes/runtime_probe.js",
        ],
        workspace=workspace,
        private_dir=private,
        rpc_port=1,
    )
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=workspace,
            env=backend.host_environment(private),
            shell=False,
        )
    finally:
        backend.cleanup(private)
    if result.returncode == 77:
        pytest.skip("configured rootless image does not contain Node.js")

    assert result.returncode == 0, result.stdout + result.stderr
    assert 1_000 < len(result.stdout) < 5_000
    for marker in (
        "environment-private.marker",
        "home-private.marker",
        "network-blocked.marker",
        "traversal-blocked.marker",
    ):
        assert (workspace / marker).is_file()
    assert any(
        (workspace / marker).is_file()
        for marker in ("child-contained.marker", "child-blocked.marker")
    )
    for marker in (
        "environment-visible.marker",
        "home-visible.marker",
        "network-visible.marker",
        "traversal-visible.marker",
    ):
        assert not (workspace / marker).exists()
    assert not (private / "adversarial-escape.marker").exists()
    assert not list(FIXTURE.rglob("*.marker"))
    assert source_hashes == {
        path.relative_to(FIXTURE): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in FIXTURE.rglob("*")
        if path.is_file()
    }
    assert not (private / "container-runtime" / "container.cid").exists()

    report = build_adversarial_acceptance_report(
        load_adversarial_acceptance_manifest(FIXTURE / "cases.json"),
        _real_acceptance_observations(backend.name),
    )
    assert report.status is AdversarialAcceptanceStatus.PASSED
    assert report.safe_cases == report.total_cases == 10
    assert report.real_isolation_executed
    assert report.blocked_integrations == []
