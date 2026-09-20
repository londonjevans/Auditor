"""Original managed-tool mutation lifecycle on synthetic offline source; no runtime authority."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import socket
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn

import pytest

from mmaudit.config import AuditConfig
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    SolidityProjectMetadata,
    SolidityProjectType,
)
from mmaudit.orchestration.managed_host_tools import (
    ManagedHostToolSource,
    materialize_managed_host_tools,
)
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainRole,
    seal_managed_toolchain_bundle,
)
from mmaudit.orchestration.mutation_pipeline import (
    MutationPipelineArtifact,
    MutationPipelineLimits,
    run_source_local_mutation_pipeline,
)
from mmaudit.scanners import base
from mmaudit.scanners import foundry_inventory_runner as inventory_runner
from mmaudit.solidity.invariant_execution import (
    FoundryInvariantRunner,
    _external_executable_version,
)
from tests.host_tool_material_support import setup_host_material_inputs
from tests.integration.test_mutation_compilation import _solc_0_8_30
from tests.integration.test_mutation_pipeline_execution import NativeLocalMutationBackend
from tests.property_mutation_support import FIXTURE, property_inputs


class ManagedNativeControl(NativeLocalMutationBackend):
    def __init__(self, mutation: str) -> None:
        self.mutation = mutation
        self.commands: list[list[str]] = []
        self.cleanup_calls = 0
        self.solc: Path | None = None
        self.changed = False

    def replace_compiler(self) -> None:
        assert self.solc is not None and not self.changed
        replacement = self.solc.with_name("replacement")
        shutil.copyfile(self.solc, replacement)
        replacement.chmod(0o500)
        replacement.replace(self.solc)
        self.changed = True

    def wrap(
        self, command: list[str], *, workspace: Path, private_dir: Path, rpc_port: int
    ) -> list[str]:
        selected = super().wrap(
            command, workspace=workspace, private_dir=private_dir, rpc_port=rpc_port
        )
        self.commands.append(command.copy())
        if "--list" in command:
            assert "--no-auto-detect" in command
            assert Path(command[command.index("--use") + 1]).is_relative_to(private_dir)
            if self.mutation == "inventory-wrap":
                self.replace_compiler()
        elif command[1] == "test":
            assert self.solc is not None
            assert command[command.index("--use") + 1] == str(self.solc)
            assert "--no-auto-detect" in command
            assert not (workspace / "test/mmaudit_generated/toolchain/solc").exists()
        return selected

    wrap_without_network = wrap

    def cleanup(self, private_dir: Path) -> None:
        super().cleanup(private_dir)
        self.cleanup_calls += 1
        if (
            self.mutation == "inventory-cleanup"
            and not self.changed
            and "--list" in self.commands[-1]
        ):
            self.replace_compiler()


@pytest.mark.parametrize(
    "project_root,excluded_output,mutation",
    [
        (".", False, "none"),
        ("packages/local", True, "none"),
        (".", False, "inventory-wrap"),
        (".", False, "inventory-cleanup"),
    ],
)
def test_original_managed_tools_reach_inventory_campaigns_and_cleanup(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
    project_root: str,
    excluded_output: bool,
    mutation: str,
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        pytest.fail("managed synthetic control attempted ambient discovery or network")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    forge = Path.home() / ".foundry/bin/forge"
    solc = _solc_0_8_30()
    if not forge.is_file() or solc is None:
        pytest.skip("Requires already installed external Forge/solc0.8.30; no installation")
    external = {
        ManagedToolchainRole.FORGE: forge.resolve(strict=True),
        ManagedToolchainRole.SOLC: solc.resolve(strict=True),
    }
    config = config_factory(
        language_profile="solidity-evm",
        smart_contracts={"compile": False, "framework": "foundry"},
        reproduction={
            "enabled": False,
            "isolation_backend": "bubblewrap",
            "targets": {"LocalAccounting": "0x1000000000000000000000000000000000000001"},
            "expected_chain_id": 31337,
            "timeout_seconds": 20,
            "repetitions": 2,
        },
        invariants={"enabled": True, "execute_generated": True},
        formal={"enabled": False},
    )
    source, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    selected_project = source / project_root
    selected_project.mkdir(parents=True, exist_ok=True)
    shutil.copytree(FIXTURE / "src", selected_project / "src")
    shutil.copyfile(FIXTURE / "foundry.toml", selected_project / "foundry.toml")
    members = []
    for member in bundle.members:
        if member.role in external:
            executable = external[member.role]
            assert not executable.is_relative_to(Path(__file__).resolve().parents[2])
            digest = hashlib.sha256(executable.read_bytes()).hexdigest()
            version = _external_executable_version(
                executable,
                backend=NativeLocalMutationBackend(),
                private_dir=tmp_path / "trusted-version-controls" / member.role.value,
            )
            matched = re.search(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", version)
            assert matched is not None
            blob = store / (digest + ".blob")
            shutil.copyfile(executable, blob)
            blob.chmod(0o600)
            member = member.model_copy(update={"sha256": digest, "version": matched[0]})
        members.append(member)
    bundle = seal_managed_toolchain_bundle(
        members=tuple(members), target_platform=bundle.target_platform
    )
    material = materialize_managed_host_tools(
        bundle=bundle,
        config=config,
        repository=source,
        output_root=output,
        source=ManagedHostToolSource(blob_root=store),
    )
    backend = ManagedNativeControl(mutation)
    backend.solc = material.executable_for(ManagedToolchainRole.SOLC)
    runner = FoundryInvariantRunner(
        material.config.reproduction,
        material.config.smart_contracts,
        host_tools=material,
        backend=backend,
    )
    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    # Inventory requires a policy digest; this test never upgrades its MOCK execution evidence.
    monkeypatch.setattr(inventory_runner, "isolation_attestation_sha256", lambda _: "a" * 64)
    launches: list[list[str]] = []
    real_popen = subprocess.Popen
    allowed = {str(material.executable_for(role)) for role in external}

    def launch(command: list[str], *args: Any, **kwargs: Any) -> Any:
        assert command[0] in allowed and kwargs["shell"] is False
        assert not {"OPENROUTER_API_KEY", "MMAUDIT_SECRETS_ENV_FILE"}.intersection(kwargs["env"])
        assert "--fork-url" not in command
        launches.append(command.copy())
        return real_popen(command, *args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", launch)
    exclusion = source / ".mmaudit" if excluded_output else None
    private = exclusion / "mutations" if exclusion is not None else tmp_path / "private"
    if exclusion is not None:
        exclusion.mkdir(mode=0o700)
        (exclusion / "excluded.txt").write_text("Synthetic excluded private state.\n")
    original = base.scanner_workspace_sha256(
        source, private_dir=exclusion, allow_custom_private_exclusion=exclusion is not None
    )
    corpus, harnesses = property_inputs(project_root)
    result = run_source_local_mutation_pipeline(
        repository_root=source,
        repository_exclusion_root=exclusion,
        expected_source_sha256=original,
        private_dir=private,
        corpus=corpus,
        harnesses=harnesses,
        projects=[
            SolidityProjectMetadata(
                project_root=project_root, project_type=SolidityProjectType.FOUNDRY
            )
        ],
        invariant_runner=runner,
        enabled=True,
        limits=MutationPipelineLimits(
            maximum_campaigns=1, maximum_runner_attempts=8, stage_timeout_seconds=120
        ),
    )
    (tmp_path / "result.json").write_text(result.model_dump_json(indent=2))
    project = result.projects[0]
    assert project.source_preserved and project.workspace_disposed
    assert not list(private.rglob("mmaudit-generated-*"))
    assert (
        base.scanner_workspace_sha256(
            source, private_dir=exclusion, allow_custom_private_exclusion=exclusion is not None
        )
        == original
    )
    # Exactly two bound preflight probes precede inventory; no duplicate unchecked probes.
    assert [c[1] for c in launches[:2]] == ["--version", "--version"]
    if mutation == "none":
        assert project.plan is not None, project.limitations
        assert len(project.campaigns) == 1 and project.campaigns[0].failure_kind is None
        assert len(project.executions) == 4 and result.runner_attempts == 8
        assert sum("--list" in c for c in launches) == 1
        assert sum(c[1] == "test" and "--list" not in c for c in launches) == 8
        assert project.workspace is not None
        assert all(not p.path.startswith(".mmaudit/") for p in project.workspace.original_files)
        for binding in project.compiler_input_files:
            raw = (private / "project-0000" / binding.path).read_bytes()
            assert len(raw) == binding.size and hashlib.sha256(raw).hexdigest() == binding.sha256
        for execution in project.executions:
            assert execution.result.execution_evidence is ExecutionEvidenceKind.MOCK
            for attempt in execution.result.attempt_evidence:
                raw = (
                    private / "project-0000" / execution.artifact_path / attempt.stdout_path
                ).read_bytes()
                assert hashlib.sha256(raw).hexdigest() == attempt.stdout_sha256
                assert json.loads(raw)
        assert project.score is not None and not project.score.gate_passed
        material.verify()
    else:
        assert project.plan is None and project.limitations and backend.changed
        assert result.runner_attempts == 0 and not project.campaigns
        assert len(launches) == (2 if mutation == "inventory-wrap" else 3)
        with pytest.raises(ValueError, match="identity"):
            runner._verify_managed_selection()
    assert not result.execution_validated and not result.qualification_eligible
    assert not result.audit_complete and not material.runtime_authority
    assert MutationPipelineArtifact.model_validate_json(result.model_dump_json()) == result
