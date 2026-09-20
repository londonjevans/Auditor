"""Compiler reference to guarded property to native owned campaign; synthetic/MOCK only."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
from pathlib import Path
from typing import Any, NoReturn

import pytest

import mmaudit.orchestration.mutation_pipeline as mutation_pipeline_module
import mmaudit.scanners.foundry_inventory_runner as inventory_runner
from mmaudit.benchmark.mutation_portfolio import SecurityMutationClass
from mmaudit.benchmark.mutations import (
    build_property_bound_inventory_mutation_plan,
    mutation_repository_sha256,
)
from mmaudit.config import ReproductionConfig, SmartContractsConfig
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    InvariantExecutionStatus,
    SolidityProjectMetadata,
    SolidityProjectType,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.orchestration.mutation_pipeline import (
    MutationPipelineLimits,
    run_source_local_mutation_pipeline,
)
from mmaudit.orchestration.mutation_reconstruction import reconstruct_mutation_project
from mmaudit.scanners.foundry_inventory import parse_foundry_test_inventory
from mmaudit.scanners.foundry_inventory_runner import run_foundry_test_inventory
from mmaudit.solidity.invariant_execution import FoundryInvariantRunner
from tests.compiler_source_binding_support import inconsistent_declared_source_map
from tests.integration.test_mutation_compilation import _solc_0_8_30
from tests.integration.test_mutation_pipeline_execution import NativeLocalMutationBackend
from tests.integration.test_mutation_reconstruction_files import _restart
from tests.property_reachability_support import FIXTURE, SOURCE, guard_inputs, inventory_snapshot


@pytest.mark.parametrize("project_root", [".", "packages/guards"])
@pytest.mark.parametrize(
    "variant", ["original", "renamed-unicode", "renamed-crlf", "renamed-mixed"]
)
def test_native_guard_reference_planning_maps_original_source_and_reconstructs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, project_root: str, variant: str
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        pytest.fail("guarded property control attempted network access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    forge, solc = Path.home() / ".foundry/bin/forge", _solc_0_8_30()
    if not forge.is_file() or solc is None:
        pytest.skip("Requires existing external Forge/solc0.8.30; no provisioning")
    repository = Path(__file__).resolve().parents[2]
    forge, solc = forge.resolve(strict=True), solc.resolve(strict=True)
    assert not forge.is_relative_to(repository) and not solc.is_relative_to(repository)
    source = tmp_path / "source"
    project_dir = source / project_root
    project_dir.mkdir(parents=True)
    shutil.copytree(FIXTURE / "src", project_dir / "src")
    shutil.copyfile(FIXTURE / "foundry.toml", project_dir / "foundry.toml")
    source_text = (FIXTURE / SOURCE).read_text()
    if variant != "original":
        for old, new in (
            ("requireLive", "controlModifier"),
            ("_liveCheck", "_firstGate"),
            ("_nestedLiveCheck", "_deepGate"),
            ("_freshCheck", "_snapshotGate"),
        ):
            source_text = source_text.replace(old, new)
        source_text = "// Synthetic Unicode byte-offset control: Ω.\n" + source_text
    if variant == "renamed-crlf":
        source_text = source_text.replace("\n", "\r\n")
    elif variant == "renamed-mixed":
        source_text = "".join(
            line.replace("\n", "\r\n") if index % 2 == 0 else line
            for index, line in enumerate(source_text.splitlines(keepends=True))
        )
    source_bytes = source_text.encode()
    (project_dir / SOURCE).write_bytes(source_bytes)
    before = mutation_repository_sha256(source)
    corpus, harnesses = guard_inputs(project_root, source_text=source_text)
    runner = FoundryInvariantRunner(
        ReproductionConfig(
            targets={"GuardedValue": "0x1000000000000000000000000000000000000001"},
            expected_chain_id=31337,
            timeout_seconds=20,
            repetitions=2,
        ),
        SmartContractsConfig(),
        backend=NativeLocalMutationBackend(),
        forge_executable=forge,
        solc_executable=solc,
    )
    monkeypatch.setattr(inventory_runner, "isolation_attestation_sha256", lambda _: "a" * 64)
    inventory_errors: list[str] = []
    source_comparisons: list[dict[str, Any]] = []

    def retain_compiler_source(**kwargs: Any) -> Any:
        supplied = next(s.content for s in kwargs["sources"] if s.path == SOURCE)
        for index, raw in enumerate(kwargs["build_info_jsons"]):
            compiled = json.loads(raw)["input"]["sources"][SOURCE]["content"].encode()
            source_comparisons.append(
                dict(
                    supplied_sha256=hashlib.sha256(supplied).hexdigest(),
                    compiler_sha256=hashlib.sha256(compiled).hexdigest(),
                    supplied_crlf=supplied.count(b"\r\n"),
                    compiler_crlf=compiled.count(b"\r\n"),
                    identical=supplied == compiled,
                    lf_normalized_equal=supplied.replace(b"\r\n", b"\n") == compiled,
                )
            )
            (tmp_path / f"compiler-source-{index}.sol").write_bytes(compiled)
        (tmp_path / "compiler-source-comparison.json").write_text(json.dumps(source_comparisons))
        return parse_foundry_test_inventory(**kwargs)

    monkeypatch.setattr(inventory_runner, "parse_foundry_test_inventory", retain_compiler_source)

    def retain_inventory_failure(**kwargs: Any) -> Any:
        try:
            return run_foundry_test_inventory(**kwargs)
        except Exception as exc:
            current: BaseException | None = exc
            while current is not None:
                inventory_errors.append(f"{type(current).__name__}: {current}")
                current = current.__cause__
            (tmp_path / "inventory-error.json").write_text(json.dumps(inventory_errors))
            raise

    monkeypatch.setattr(
        mutation_pipeline_module, "run_foundry_test_inventory", retain_inventory_failure
    )
    result = run_source_local_mutation_pipeline(
        repository_root=source,
        repository_exclusion_root=None,
        expected_source_sha256=before,
        private_dir=tmp_path / "private",
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
            maximum_campaigns=2, maximum_runner_attempts=40, stage_timeout_seconds=120
        ),
    )
    (tmp_path / "result.json").write_text(result.model_dump_json(indent=2))
    assert len(result.projects) == 1
    project = result.projects[0]
    assert project.source_preserved and project.workspace_disposed
    assert mutation_repository_sha256(source) == before
    assert (project_dir / SOURCE).read_bytes() == source_bytes
    assert not list((tmp_path / "private").rglob("mmaudit-generated-*"))
    assert (
        not result.execution_validated
        and not result.qualification_eligible
        and not result.audit_complete
    )
    assert source_comparisons
    if variant in {"renamed-crlf", "renamed-mixed"}:
        # Actual compiler bytes differ. Original source and every compiler span
        # must remain explicitly bound; neither source nor AST is rewritten.
        assert all(
            not s["identical"]
            and s["supplied_crlf"] > 0
            and s["compiler_crlf"] == 0
            and s["lf_normalized_equal"]
            for s in source_comparisons
        )
    else:
        assert all(s["identical"] for s in source_comparisons)
    assert not inventory_errors
    assert project.plan is not None and not project.limitations, (
        project.limitations,
        inventory_errors,
    )
    plan = project.plan
    assert plan.property_tests is not None and plan.discovery is not None
    graph = plan.property_tests.compiler_reachability
    assert graph is not None
    bindings = [b for s in graph.sources for b in s.compiler_source_bindings]
    if variant in {"renamed-crlf", "renamed-mixed"}:
        assert len(bindings) == 1
        transformation = bindings[0].transformation
        assert transformation.original_sha256 == hashlib.sha256(source_bytes).hexdigest()
        assert transformation.removed_crlf_count == source_bytes.count(b"\r\n")
        assert transformation.compiler_sha256 == source_comparisons[0]["compiler_sha256"]
    else:
        assert not bindings
        assert all("compiler_source_bindings" not in s.model_dump() for s in graph.sources)
    assert len(plan.bindings) == len(plan.non_applicability) == len(plan.specifications) == 2
    assert {s.kind for s in plan.specifications} == {
        SecurityMutationClass.PAUSE_ENFORCEMENT_REMOVAL,
        SecurityMutationClass.STALE_PRICE_VALIDATION_REMOVAL,
    }
    assert all(
        not any(e.location.start_line <= s.line <= e.location.end_line for e in p.source_evidence)
        for p in corpus.properties
        for s in plan.specifications
    )
    assert (
        len(project.campaigns) == 2
        and len(project.executions) == 8
        and result.runner_attempts == 16
    )
    assert all(
        c.failure_kind is None
        and c.restoration_verified
        and c.source_preserved
        and c.workspace_disposed
        for c in project.campaigns
    )
    private = tmp_path / "private/project-0000"
    for execution in project.executions:
        spec = next(s for s in plan.specifications if s.id == execution.mutation_id)
        expected = (
            "Pause" if spec.kind is SecurityMutationClass.PAUSE_ENFORCEMENT_REMOVAL else "Fresh"
        )
        status = (
            InvariantExecutionStatus.COUNTEREXAMPLE
            if execution.stage == "mutant" and execution.result.harness_name == expected
            else InvariantExecutionStatus.PASSED
        )
        assert execution.result.status is status
        assert execution.result.execution_evidence is ExecutionEvidenceKind.MOCK
        for attempt in execution.result.attempt_evidence:
            raw = (private / execution.artifact_path / attempt.stdout_path).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == attempt.stdout_sha256
            tests = [
                t for suite in json.loads(raw).values() for t in suite["test_results"].values()
            ]
            assert tests and all(
                sum(m["calls"] for m in t["kind"]["Invariant"]["metrics"].values()) > 0
                for t in tests
            )
    assert project.score is not None and len(project.score.outcomes) == 4
    assert all(o.outcome.value == "inconclusive" for o in project.score.outcomes)
    reconstructed = reconstruct_mutation_project(
        project=project,
        expected_project_sha256=canonical_sha256(project.model_dump(mode="json")),
        artifact_root=private,
    )
    assert reconstructed.plan == plan
    (tmp_path / "snapshot.json").write_text(
        json.dumps(
            inventory_snapshot(reconstructed.inventory), sort_keys=True, separators=(",", ":")
        )
    )
    direct = build_property_bound_inventory_mutation_plan(
        inventory_result=reconstructed.inventory,
        project_root=project_root,
        target_paths=(SOURCE,),
        corpus=plan.property_tests.corpus,
        harnesses=plan.property_tests.harnesses,
        expected_chain_id=31337,
        repository_id="audited-source",
        approved_executor_sha256=plan.approved_executor_sha256,
        approved_isolation_policy_sha256=plan.approved_isolation_policy_sha256,
        include_compiler_reachability=False,
    )
    assert not direct.bindings and len(direct.non_applicability) == 4
    assert direct.property_tests is not None
    assert "compiler_reachability" not in direct.property_tests.model_dump(mode="json")
    selected = tmp_path / "selected-project.json"
    selected.write_text(project.model_dump_json())
    restart = _restart(selected, canonical_sha256(project.model_dump(mode="json")), private)
    assert restart.returncode == 0, restart.stderr.decode()
    assert json.loads(restart.stdout)["plan"] == plan.model_dump(mode="json")
    if bindings:
        for change in ("omitted", "map-digest"):
            changed = inconsistent_declared_source_map(project, change)
            altered_root = tmp_path / ("tampered-" + change)
            altered_root.mkdir()
            altered_path = altered_root / "selected-project.json"
            altered_path.write_text(changed.model_dump_json())
            refused = _restart(
                altered_path, canonical_sha256(changed.model_dump(mode="json")), private
            )
            assert refused.returncode != 0 and not refused.stdout
            assert b"full original selection" in refused.stderr
