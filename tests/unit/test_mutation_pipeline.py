"""Fail-closed source lineage, complete scope and shared local execution budgets."""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, NoReturn

import pytest

import mmaudit.orchestration.mutation_pipeline as pipeline
from mmaudit.benchmark.mutations import mutation_repository_sha256
from mmaudit.config import ReproductionConfig, SmartContractsConfig
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    InvariantExecutionAttemptEvidence,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    SolidityProjectMetadata,
    SolidityProjectType,
)
from mmaudit.repository.workspace import audited_workspace_bindings_sha256
from mmaudit.solidity.invariant_execution import FoundryInvariantRunner, InvariantExecutionBudget
from mmaudit.solidity.properties import generated_local_property_source
from tests.property_mutation_support import (
    property_inputs,
    property_plan,
    retained_property_fixture,
)


class ForbiddenBackend:
    name = "synthetic-never-execute"
    execution_evidence = ExecutionEvidenceKind.MOCK

    def wrap(
        self, command: list[str], *, workspace: Path, private_dir: Path, rpc_port: int
    ) -> list[str]:
        pytest.fail("unit control attempted process execution")


@pytest.fixture(autouse=True)
def forbid_external_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        pytest.fail("unit control attempted network/process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)


def arguments(tmp_path: Path) -> dict[str, Any]:
    corpus, harnesses = property_inputs()
    source = tmp_path / "source"
    source.mkdir()
    (source / "Local.sol").write_text("// inert local-only source\n")
    return dict(
        repository_root=source,
        repository_exclusion_root=None,
        expected_source_sha256=mutation_repository_sha256(source),
        private_dir=tmp_path / "private",
        corpus=corpus,
        harnesses=harnesses,
        projects=[
            SolidityProjectMetadata(project_root=".", project_type=SolidityProjectType.FOUNDRY)
        ],
        invariant_runner=FoundryInvariantRunner(
            ReproductionConfig(), SmartContractsConfig(), backend=ForbiddenBackend()
        ),
        enabled=True,
    )


@pytest.mark.parametrize(
    "case", ["disabled", "missing-source", "missing-harness", "missing-project"]
)
def test_unavailable_scope_retains_every_property_without_io(tmp_path: Path, case: str) -> None:
    args = arguments(tmp_path)
    if case == "disabled":
        args["enabled"] = False
    elif case == "missing-source":
        args["expected_source_sha256"] = None
    else:
        args["harnesses" if case == "missing-harness" else "projects"] = []
    result = pipeline.run_source_local_mutation_pipeline(**args)
    assert result.unresolved_property_ids == [p.id for p in args["corpus"].properties]
    assert result.projects == [] and result.runner_attempts == 0
    assert not result.execution_validated and not result.qualification_eligible
    assert not args["private_dir"].exists()
    assert pipeline.MutationPipelineArtifact.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize("case", ["source-drift", "tools", "copy", "custody"])
def test_failed_preparation_still_disposes_owned_child_and_preserves_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    args = arguments(tmp_path)

    def refuse(*args: Any, **kwargs: Any) -> NoReturn:
        raise ValueError("synthetic preparation refusal")

    if case == "source-drift":
        args["expected_source_sha256"] = "0" * 64
    elif case == "custody":
        monkeypatch.setattr(pipeline, "retain_scanner_workspace_source_custody", refuse)
    elif case == "tools":
        monkeypatch.setattr(pipeline, "_tools", refuse)
    else:
        monkeypatch.setattr(
            pipeline,
            "_tools",
            lambda *a: (Path("/unused-forge"), Path("/unused-solc"), "1", "0.8.30"),
        )
        monkeypatch.setattr(pipeline, "copy_scanner_workspace_with_custody", refuse)
    original = mutation_repository_sha256(args["repository_root"])
    result = pipeline.run_source_local_mutation_pipeline(**args)
    project = result.projects[0]
    assert project.limitations and project.plan is None and not project.campaigns
    assert project.workspace_disposed
    assert project.source_preserved is (case not in {"source-drift", "custody"})
    assert not list(args["private_dir"].rglob("mmaudit-generated-*"))
    assert mutation_repository_sha256(args["repository_root"]) == original


@pytest.mark.parametrize(
    "case",
    ["duplicate-project", "duplicate-harness", "bad-source-id", "output-link", "source-output"],
)
def test_ambiguous_or_unsafe_entry_refuses_before_owned_work(tmp_path: Path, case: str) -> None:
    args = arguments(tmp_path)
    if case == "duplicate-project":
        args["projects"] *= 2
    elif case == "duplicate-harness":
        args["harnesses"] *= 2
    elif case == "bad-source-id":
        args["expected_source_sha256"] = "bad"
    elif case == "output-link":
        args["private_dir"].symlink_to(tmp_path, target_is_directory=True)
    else:
        args["private_dir"] = args["repository_root"] / "unexcluded"
    with pytest.raises(ValueError):
        pipeline.run_source_local_mutation_pipeline(**args)
    assert not list(tmp_path.rglob("mmaudit-generated-*"))


@pytest.mark.parametrize(
    "field,value",
    [
        ("maximum_campaigns", True),
        ("maximum_campaigns", 201),
        ("maximum_runner_attempts", -1),
        ("maximum_runner_attempts", 501),
        ("stage_timeout_seconds", float("inf")),
        ("stage_timeout_seconds", float("nan")),
        ("inventory_timeout_seconds", 0),
        ("minimum_property_kill_score", 1.1),
    ],
)
def test_execution_limits_remain_strict_and_finite(field: str, value: Any) -> None:
    with pytest.raises(ValueError):
        pipeline.MutationPipelineLimits(**{field: value})


def test_shared_budget_stops_attempts_and_expired_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(time, "monotonic", lambda: 10.0)
    budget = InvariantExecutionBudget(2, 11)
    budget.reserve_attempt()
    budget.reserve_attempt()
    with pytest.raises(ValueError, match="attempts exhausted"):
        budget.reserve_attempt()
    assert budget.attempts == 2
    monkeypatch.setattr(time, "monotonic", lambda: 11.0)
    with pytest.raises(ValueError, match="deadline exhausted"):
        budget.remaining_seconds()


@pytest.mark.parametrize(
    "case", ["changed-original", "changed-generated", "duplicate", "replacement"]
)
def test_generated_workspace_cannot_replace_or_drop_audited_source(case: str) -> None:
    original = pipeline.MutationSourceFile(
        path="src/Local.sol", size=3, sha256=hashlib.sha256(b"old").hexdigest()
    )
    generated = pipeline.MutationSourceFile(
        path="test/Local.t.sol", size=3, sha256=hashlib.sha256(b"new").hexdigest()
    )
    values = dict(
        original_files=[original],
        generated_files=[generated],
        original_sha256=audited_workspace_bindings_sha256([original.model_dump()]),
        augmented_sha256=audited_workspace_bindings_sha256(
            [original.model_dump(), generated.model_dump()]
        ),
    )
    assert pipeline.GeneratedMutationWorkspace(**values)
    if case == "changed-original":
        values["original_sha256"] = "0" * 64
    elif case == "changed-generated":
        values["augmented_sha256"] = "0" * 64
    elif case == "duplicate":
        values["generated_files"] = [generated, generated]
    else:
        values["generated_files"] = [generated.model_copy(update={"path": original.path})]
    with pytest.raises(ValueError):
        pipeline.GeneratedMutationWorkspace(**values)


@pytest.mark.parametrize("chain", [0, -1, True, 2**256])
def test_generated_source_rejects_invalid_chain_identity(chain: int) -> None:
    _, harnesses = property_inputs()
    with pytest.raises(ValueError):
        generated_local_property_source(harnesses[0], project_root=".", expected_chain_id=chain)


@pytest.mark.parametrize(
    "case",
    [
        "complete",
        "suite-swap",
        "test-swap",
        "stdout-drift",
        "source-drift",
        "compiler-drift",
        "tool-drift",
        "replay-drift",
        "attempt-omission",
        "unvalidated",
        "exit-code",
        "unclassified",
        "result-digest",
    ],
)
def test_local_executor_requires_exact_original_compiler_source_and_per_test_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    args = arguments(tmp_path)
    runner = args["invariant_runner"]
    plan = property_plan(retained_property_fixture())
    assert plan.compiler_inventory is not None

    def fake_run(**kw: Any) -> InvariantExecutionResult:
        harness, output = kw["specification"], kw["private_dir"]
        output.mkdir(parents=True)
        generated = generated_local_property_source(harness, project_root=".")
        assert generated is not None
        (output / "harness.sol").write_bytes(generated[1])
        source_sha = hashlib.sha256(generated[1]).hexdigest()
        evidence = []
        for index in range(2):
            suite = generated[0] + ":MMAuditInvariant_" + harness.name
            name = "invariant_" + harness.properties[0].property_id + "()"
            if case == "suite-swap":
                suite = "wrong.sol:Wrong"
            if case == "test-swap":
                name = "invariant_Wrong()"
            status = "Failure" if case == "replay-drift" and index == 1 else "Success"
            if case == "unclassified":
                status = "Skipped"
            raw = json.dumps({suite: {"test_results": {name: {"status": status}}}}).encode()
            stdout, stderr = f"out-{index}.json", f"err-{index}.txt"
            (output / stdout).write_bytes(raw + (b" " if case == "stdout-drift" else b""))
            (output / stderr).write_bytes(b"")
            evidence.append(
                InvariantExecutionAttemptEvidence(
                    attempt=index + 1,
                    status=InvariantExecutionStatus.PASSED,
                    source_sha256=source_sha,
                    fresh_workspace=True,
                    stdout_sha256=hashlib.sha256(raw).hexdigest(),
                    stderr_sha256=hashlib.sha256(b"").hexdigest(),
                    stdout_path=stdout,
                    stderr_path=stderr,
                    process_exit_code=2
                    if case == "exit-code"
                    else (1 if status == "Failure" else 0),
                    machine_output_validated=case != "unvalidated",
                )
            )
        assert plan.compiler_inventory is not None
        result = InvariantExecutionResult(
            invariant_id=harness.invariant_id,
            harness_name=harness.name,
            harness_spec_sha256=harness.specification_sha256(),
            status=InvariantExecutionStatus.PASSED,
            source_sha256="0" * 64 if case == "source-drift" else source_sha,
            source_path="harness.sol",
            execution_evidence=ExecutionEvidenceKind.MOCK,
            compiler_sha256="0" * 64
            if case == "compiler-drift"
            else plan.compiler_inventory.compiler_sha256,
            executable_sha256="0" * 64
            if case == "tool-drift"
            else plan.compiler_inventory.tool_sha256,
            attempts=2,
            successful_attempts=2,
            runs=harness.runs,
            depth=harness.depth,
            seed=harness.seed,
            replay_confirmed=True,
            attempt_evidence=evidence[:1] if case == "attempt-omission" else evidence,
        )
        return result.model_copy(
            update={
                "execution_observation_sha256": "0" * 64
                if case == "result-digest"
                else result.expected_execution_observation_sha256()
            }
        )

    monkeypatch.setattr(runner, "run", fake_run)
    executor = pipeline._LocalInvariantMutationExecutor(
        runner,
        args["projects"][0],
        plan,
        tmp_path / "observations",
        tmp_path / "execution",
        InvariantExecutionBudget(40, time.monotonic() + 10),
        [],
    )
    if case == "complete":
        result = executor.execute(
            baseline_workspace=args["repository_root"],
            mutant_workspace=args["repository_root"],
            specification=plan.specifications[0],
        )
        assert result.baseline_execution_evidence is ExecutionEvidenceKind.UNVERIFIED
        assert result.mutant_execution_evidence is ExecutionEvidenceKind.UNVERIFIED
        assert len(result.baseline_tests) == len(result.mutant_tests) == 2
    else:
        with pytest.raises(ValueError):
            executor.execute(
                baseline_workspace=args["repository_root"],
                mutant_workspace=args["repository_root"],
                specification=plan.specifications[0],
            )


def test_expired_runner_budget_refuses_before_any_process(tmp_path: Path) -> None:
    args = arguments(tmp_path)
    with pytest.raises(ValueError, match="deadline exhausted"):
        args["invariant_runner"].run(
            repository_root=args["repository_root"],
            project=args["projects"][0],
            specification=args["harnesses"][0],
            private_dir=tmp_path / "refused",
            execution_budget=InvariantExecutionBudget(40, time.monotonic() - 1),
        )
    assert not (tmp_path / "refused").exists()


def test_shared_deadline_stops_an_inflight_process_before_the_runner_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mmaudit.solidity.invariant_execution as execution

    args = arguments(tmp_path)
    runner = args["invariant_runner"]
    observations = []

    class SyntheticProcess:
        def poll(self) -> None:
            return None

        def wait(self, *, timeout: float) -> int:
            return 0

    process = SyntheticProcess()
    monkeypatch.setattr(runner.backend, "wrap", lambda command, **kw: command)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: process)
    monkeypatch.setattr(execution, "_stop_process", lambda p: observations.append(p))
    readings = iter((0.0, 0.0, 2.0))
    monkeypatch.setattr(time, "monotonic", lambda: next(readings, 2.0))
    result = runner._execute(
        ["synthetic-never-launched"],
        workspace=args["repository_root"],
        private_dir=tmp_path / "process",
        rpc_port=0,
        runs=1,
        depth=1,
        seed=1,
        action_functions={},
        property_ids=set(),
        execution_budget=InvariantExecutionBudget(1, 1.0),
    )
    assert result.status is InvariantExecutionStatus.TIMED_OUT
    assert observations and all(p is process for p in observations)
    assert runner.reproduction.timeout_seconds > 1
