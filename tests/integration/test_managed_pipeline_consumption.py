"""Real offline scanner-only pipeline plumbing, not real engine or audit evidence."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import sys
from pathlib import Path

import pytest

from mmaudit.models.schemas import ExecutionEvidenceKind, ScannerStatus
from mmaudit.orchestration import pipeline as pipeline_module
from mmaudit.orchestration.managed_host_tools import ManagedHostToolSource
from mmaudit.orchestration.managed_provisioning_runtime import provision_managed_local_run
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainRole,
    seal_managed_toolchain_bundle,
)
from mmaudit.orchestration.manifest import load_run_evidence_manifest, validate_manifest_artifacts
from mmaudit.repository import discovery as discovery_module
from mmaudit.scanners import base
from mmaudit.scanners.runner import ScannerRunner
from mmaudit.scanners.semgrep import SemgrepScanner
from tests.host_tool_material_support import setup_host_material_inputs

_CONTROL_CODE = 'print(\'{"results":[],"errors":[]}\')'


class _FixedControlBackend:
    name = "synthetic-prepared-pipeline-control"
    supports_local_fork_rpc = False

    def __init__(self, executable):
        self.executable = str(executable)

    def wrap(self, command, *, workspace, private_dir, rpc_port):
        assert rpc_port == 0
        assert command in (
            [self.executable, "--version"],
            [self.executable, "-c", _CONTROL_CODE],
        )
        return command


@pytest.mark.asyncio
@pytest.mark.parametrize("repeated", [False, True])
@pytest.mark.parametrize("mode", ["generic", "solidity", "blocked", "drift"])
async def test_pipeline_consumes_one_prepared_selection_with_zero_provider_or_rpc(
    tmp_path, config_factory, monkeypatch, repeated, mode
):
    config = config_factory(
        language_profile="generic-source-review" if mode == "generic" else "solidity-evm",
        scanners={"semgrep": {"enabled": True, "required": True}},
        smart_contracts={"compile": mode == "blocked", "framework": "foundry"},
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
        invariants={"enabled": False},
        formal={"enabled": False},
    )
    repository, store, prepared_output, bundle = setup_host_material_inputs(tmp_path, config)
    original_source = base.scanner_workspace_sha256(repository)
    trusted_python = Path(sys.executable).resolve(strict=True)
    assert not trusted_python.is_relative_to(repository)
    with trusted_python.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    version = ".".join(str(value) for value in sys.version_info[:3])
    blob = store / f"{digest}.blob"
    shutil.copyfile(trusted_python, blob)
    blob.chmod(0o600)
    # A fixed trusted Python control occupies this synthetic role; it cannot
    # attest Semgrep, engine coverage, real isolation or completed analysis.
    bundle = seal_managed_toolchain_bundle(
        members=tuple(
            member.model_copy(update={"sha256": digest, "version": version})
            if member.role is ManagedToolchainRole.SEMGREP
            else member
            for member in bundle.members
        ),
        target_platform=bundle.target_platform,
    )
    arguments = dict(
        config=config, bundle=bundle, repository=repository, output_dir=prepared_output
    )
    real_popen = base.subprocess.Popen
    original_build = SemgrepScanner.build_command
    original_compile = pipeline_module.compile_solidity_projects
    original_scanners = ScannerRunner.run_all
    calls, compilations = [], []

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: managed pipeline must not discover tools, use providers or sockets")

    with monkeypatch.context() as patch:
        patch.setattr(base.subprocess, "Popen", forbidden)
        patch.setattr(shutil, "which", forbidden)
        patch.setattr(socket, "socket", forbidden)
        patch.setattr(discovery_module, "_git_commit", lambda root: None)
        patch.setenv("PATH", str(tmp_path / "must-not-search"))
        run = provision_managed_local_run(
            **arguments, verify_only=False, host_tool_source=ManagedHostToolSource(blob_root=store)
        )
        if repeated:
            run = provision_managed_local_run(
                **arguments, verify_only=True, host_tool_source=ManagedHostToolSource()
            )
        material = run.host_tools
        assert material is not None
        executable = material.executable_for(ManagedToolchainRole.SEMGREP)
        backend = _FixedControlBackend(executable)
        audit = pipeline_module.AuditPipeline(
            run.config,
            repo=repository,
            output=tmp_path / "audit-output",
            host_tools=material,
            managed_backend=backend,
        )
        original_handlers = tuple(audit.logger.handlers)

        def control_build(adapter, root, private_dir):
            assert original_build(adapter, root, private_dir)[0] == str(executable)
            return [adapter.executable, "-c", _CONTROL_CODE]

        def guarded_popen(command, *args, **kwargs):
            assert command in (
                [str(executable), "--version"],
                [str(executable), "-c", _CONTROL_CODE],
            )
            assert kwargs["shell"] is False
            with executable.open("rb") as stream:
                assert hashlib.file_digest(stream, "sha256").hexdigest() == digest
            calls.append(command.copy())
            return real_popen(command, *args, **kwargs)

        def compile_control(root, projects, selected_config, private_dir, **kwargs):
            assert mode not in {"generic", "blocked"}
            assert selected_config == run.config.smart_contracts
            assert selected_config.compile is False
            assert kwargs["host_tools"] is material and kwargs["backend"] is backend
            compilations.append(selected_config.model_dump_json())
            return original_compile(root, projects, selected_config, private_dir, **kwargs)

        async def scanners_then_drift(runner, *args, **kwargs):
            outcomes = await original_scanners(runner, *args, **kwargs)
            # Same-byte replacement after the consumer's own final check must
            # still refuse before the pipeline can use or publish its outcomes.
            replacement = executable.with_suffix(".replacement")
            shutil.copyfile(executable, replacement)
            replacement.chmod(0o500)
            replacement.replace(executable)
            return outcomes

        patch.setattr(SemgrepScanner, "build_command", control_build)
        patch.setattr(base.subprocess, "Popen", guarded_popen)
        patch.setattr(pipeline_module, "compile_solidity_projects", compile_control)
        if mode == "drift":
            patch.setattr(ScannerRunner, "run_all", scanners_then_drift)
            with pytest.raises(ValueError, match="managed pipeline tool identity changed"):
                await audit.run(scanner_only=True)
            assert not list((tmp_path / "audit-output").rglob("final-findings.json"))
        else:
            result = await audit.run(scanner_only=True, require_maximum_assurance=mode == "blocked")
            assert result.report.completed is False
            assert result.report.usage == []
            artifact = json.loads((result.run_dir / "solidity-compilation.json").read_text())
            if mode in {"generic", "blocked"}:
                assert artifact["results"] == [] and compilations == []
            if mode == "blocked":
                assert result.report.maximum_assurance.required is True
                assert result.report.maximum_assurance.status.value != "COMPLETE"
                taxonomy = next(
                    gate
                    for gate in result.report.quality_gates
                    if gate.gate == "known_issue_taxonomy_critical_disposition"
                )
                assert taxonomy.required is True and taxonomy.passed is False
                assert (
                    json.loads((result.run_dir / "final-findings.json").read_text())["completed"]
                    is False
                )
                validate_manifest_artifacts(
                    load_run_evidence_manifest(result.run_dir / "run-evidence-manifest.json"),
                    result.run_dir,
                )
            if mode != "blocked":
                control = next(
                    item for item in result.report.scanner_runs if item.scanner == "semgrep"
                )
                assert control.status is ScannerStatus.SUCCESS
                assert control.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
                assert control.executable_sha256 == digest
        assert len(calls) == (0 if mode == "blocked" else 2)
        assert len(compilations) == (1 if mode in {"solidity", "drift"} else 0)
        assert audit.client is None and audit.api_key == ""
        assert audit._run_log_handler is None
        assert tuple(audit.logger.handlers) == original_handlers
        assert base.scanner_workspace_sha256(repository) == original_source
        assert run.receipt.managed_run_ready is run.receipt.runtime_authority is False
        assert run.receipt.state.installed_members_verified is False
