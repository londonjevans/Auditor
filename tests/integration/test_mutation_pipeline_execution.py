"""Original source-local mutation pipeline on inert offline fixtures; isolation is MOCK."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
from pathlib import Path
from typing import Any, NoReturn

import pytest

import mmaudit.scanners.foundry_inventory_runner as inventory_runner
from mmaudit.benchmark.mutation_portfolio import SecurityMutationClass
from mmaudit.benchmark.mutations import mutation_repository_sha256
from mmaudit.config import ReproductionConfig, SmartContractsConfig
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    InvariantExecutionStatus,
    SolidityProjectMetadata,
    SolidityProjectType,
)
from mmaudit.orchestration.mutation_pipeline import (
    MutationPipelineArtifact,
    MutationPipelineLimits,
    run_source_local_mutation_pipeline,
)
from mmaudit.solidity.invariant_execution import FoundryInvariantRunner
from mmaudit.solidity.properties import _corpus
from tests.integration.test_mutation_compilation import _solc_0_8_30
from tests.property_mutation_support import FIXTURE, property_inputs


class NativeLocalMutationBackend:
    name = "synthetic-local-mutation-mock"
    execution_evidence = ExecutionEvidenceKind.MOCK

    def wrap(
        self, command: list[str], *, workspace: Path, private_dir: Path, rpc_port: int
    ) -> list[str]:
        assert rpc_port in {0, 1} and workspace.is_dir() and private_dir.is_dir()
        assert "--version" in command or ("--offline" in command and command[1] == "test")
        assert "--fork-url" not in command
        return command

    wrap_without_network = wrap

    def host_environment(self, private_dir: Path) -> dict[str, str]:
        return {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}

    def cleanup(self, private_dir: Path) -> None:
        assert private_dir.is_dir()


@pytest.mark.parametrize(
    "project_roots,maximum_attempts",
    [((".",), 40), (("packages/local",), 40), (("packages/a", "packages/b"), 8)],
)
def test_original_source_local_pipeline_collects_native_campaigns_and_disposes_workspaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    project_roots: tuple[str, ...],
    maximum_attempts: int,
) -> None:
    def deny_network(*args: Any, **kwargs: Any) -> NoReturn:
        pytest.fail("local mutation control attempted network access")

    monkeypatch.setattr(socket.socket, "connect", deny_network)
    forge, solc = Path.home() / ".foundry/bin/forge", _solc_0_8_30()
    if not forge.is_file() or solc is None:
        pytest.skip("Requires installed external Forge/solc0.8.30; no provisioning")
    source = tmp_path / "source"
    properties = []
    for project_root in project_roots:
        project = source / project_root
        project.mkdir(parents=True)
        shutil.copytree(FIXTURE / "src", project / "src")
        shutil.copyfile(FIXTURE / "foundry.toml", project / "foundry.toml")
        projected, harnesses = property_inputs(project_root)
        properties.extend(projected.properties)
    original = mutation_repository_sha256(source)
    corpus = _corpus(properties, [])
    runner = FoundryInvariantRunner(
        ReproductionConfig(
            targets={"LocalAccounting": "0x1000000000000000000000000000000000000001"},
            expected_chain_id=31337,
            timeout_seconds=20,
            repetitions=2,
        ),
        SmartContractsConfig(),
        backend=NativeLocalMutationBackend(),
        forge_executable=forge.resolve(strict=True),
        solc_executable=solc.resolve(strict=True),
    )
    # The original inventory writer needs a policy identity. This test-only digest
    # does not alter MOCK execution evidence or admit any runtime authority.
    monkeypatch.setattr(inventory_runner, "isolation_attestation_sha256", lambda _: "a" * 64)
    result = run_source_local_mutation_pipeline(
        repository_root=source,
        repository_exclusion_root=None,
        expected_source_sha256=original,
        private_dir=tmp_path / "private",
        corpus=corpus,
        harnesses=harnesses,
        projects=[
            SolidityProjectMetadata(
                project_root=project_root, project_type=SolidityProjectType.FOUNDRY
            )
            for project_root in project_roots
        ],
        invariant_runner=runner,
        enabled=True,
        limits=MutationPipelineLimits(
            maximum_campaigns=2, maximum_runner_attempts=maximum_attempts, stage_timeout_seconds=120
        ),
    )
    (tmp_path / "result.json").write_text(result.model_dump_json(indent=2))
    assert len(result.projects) == len(project_roots)
    observed = result.projects[0]
    assert observed.plan is not None, observed.limitations
    assert bool(observed.limitations) is (len(project_roots) == 2)
    assert observed.source_preserved and observed.workspace_disposed
    assert observed.workspace is not None
    assert observed.workspace.original_sha256 == original
    assert observed.workspace.augmented_sha256 != original
    expected_campaigns = 1 if len(project_roots) == 2 else 2
    assert len(observed.campaigns) == expected_campaigns
    assert all(c.failure_kind is None for c in observed.campaigns), observed.campaigns
    assert (
        len(observed.executions) == expected_campaigns * 4
        and result.runner_attempts == expected_campaigns * 8
    )
    if len(project_roots) == 2:
        second = result.projects[1]
        assert second.plan is not None and not second.campaigns and second.limitations
        assert second.source_preserved and second.workspace_disposed
        assert second.score is not None and len(second.score.outcomes) == 4
        assert all(o.outcome.value == "inconclusive" for o in second.score.outcomes)
    assert all(
        e.result.execution_evidence is ExecutionEvidenceKind.MOCK for e in observed.executions
    )
    assert observed.score is not None and not observed.score.gate_passed
    assert all(o.outcome.value == "inconclusive" for o in observed.score.outcomes)
    assert mutation_repository_sha256(source) == original
    assert not list((tmp_path / "private").rglob("mmaudit-generated-*"))
    for binding in observed.compiler_input_files:
        raw = (tmp_path / "private/project-0000" / binding.path).read_bytes()
        assert len(raw) == binding.size and hashlib.sha256(raw).hexdigest() == binding.sha256
    for execution in observed.executions:
        specification = next(
            s for s in observed.plan.specifications if s.id == execution.mutation_id
        )
        expected_failure = (
            "Authorization"
            if specification.kind is SecurityMutationClass.AUTHORIZATION_REMOVAL
            else "Scaling"
        )
        assert execution.result.status is (
            InvariantExecutionStatus.COUNTEREXAMPLE
            if execution.stage == "mutant" and execution.result.harness_name == expected_failure
            else InvariantExecutionStatus.PASSED
        )
        assert execution.result.source_path is not None
        retained_source = (
            tmp_path
            / "private/project-0000"
            / execution.artifact_path
            / execution.result.source_path
        )
        assert (
            hashlib.sha256(retained_source.read_bytes()).hexdigest()
            == execution.result.source_sha256
        )
        for attempt in execution.result.attempt_evidence:
            path = tmp_path / "private/project-0000" / execution.artifact_path / attempt.stdout_path
            assert hashlib.sha256(path.read_bytes()).hexdigest() == attempt.stdout_sha256
            payload = json.loads(path.read_bytes())
            for suite in payload.values():
                for test in suite["test_results"].values():
                    assert (
                        sum(m["calls"] for m in test["kind"]["Invariant"]["metrics"].values()) > 0
                    )
    assert MutationPipelineArtifact.model_validate_json(result.model_dump_json()) == result
    assert (
        not result.execution_validated
        and not result.qualification_eligible
        and not result.audit_complete
    )
