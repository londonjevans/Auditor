"""Native original-inventory-writer handoff, with explicitly MOCK isolation and no audit credit."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import mmaudit.scanners.foundry_inventory_runner as runner
from mmaudit.benchmark.foundry_mutation_executor import canonical_foundry_inventory_mutation_test_id
from mmaudit.benchmark.mutation_portfolio import SecurityMutationClass
from mmaudit.benchmark.mutations import (
    MutationApplicabilityPlan,
    MutationSpecification,
    MutationSuiteObservation,
    MutationSuiteTestObservation,
    MutationSuiteTestStatus,
    mutation_repository_sha256,
    run_owned_mutation_campaign,
    score_planned_mutation_campaigns,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    RepositorySuiteInventoryPhase,
    SolidityProjectMetadata,
    SolidityProjectType,
)
from tests.integration.test_mutation_compilation import _solc_0_8_30
from tests.integration.test_mutation_portfolio_execution import _run_local_suite
from tests.mutation_inventory_support import inventory_fixture_plan
from tests.mutation_portfolio_support import CASES, FIXTURE, SOURCE_PATH


class _SyntheticInventoryBackend:
    """No real isolation claim; run only the bounded inert, offline local fixture compiler."""

    name = "synthetic-mutation-inventory-mock"
    execution_evidence = ExecutionEvidenceKind.MOCK

    def wrap(
        self, command: list[str], *, workspace: Path, private_dir: Path, rpc_port: int
    ) -> list[str]:
        assert rpc_port == 1 and "--offline" in command and "--list" in command
        assert workspace.is_dir() and private_dir.is_dir()
        return command

    wrap_without_network = wrap

    def host_environment(self, private_dir: Path) -> dict[str, str]:
        return {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}

    def cleanup(self, private_dir: Path) -> None:
        assert private_dir.is_dir()


class _NativeSyntheticExecutor:
    def __init__(
        self, forge: Path, solc: Path, plan: MutationApplicabilityPlan, artifacts: Path
    ) -> None:
        self.forge, self.solc, self.plan, self.artifacts = forge, solc, plan, artifacts
        self.calls = 0

    def execute(
        self,
        *,
        baseline_workspace: Path,
        mutant_workspace: Path,
        specification: MutationSpecification,
    ) -> MutationSuiteObservation:
        self.calls += 1
        test_ids = {b.property_id: b.test_ids[0] for b in self.plan.bindings}
        from tests.mutation_portfolio_support import property_id

        names = {case[1] + "()": test_ids[property_id(kind)] for kind, case in CASES.items()}
        observations: list[list[MutationSuiteTestObservation]] = []
        assert self.plan.discovery is not None
        assert isinstance(specification.kind, SecurityMutationClass)
        for label, workspace in (("baseline", baseline_workspace), ("mutant", mutant_workspace)):
            results = _run_local_suite(
                self.forge,
                self.solc,
                workspace / self.plan.discovery.project_root,
                self.artifacts / specification.id / label,
            )
            failed = [name for name, result in results.items() if result["status"] == "Failure"]
            assert failed == ([] if label == "baseline" else [CASES[specification.kind][1] + "()"])
            observations.append(
                sorted(
                    [
                        MutationSuiteTestObservation(
                            test_id=names[name],
                            status=(
                                MutationSuiteTestStatus.PASSED
                                if result["status"] == "Success"
                                else MutationSuiteTestStatus.FAILED
                            ),
                        )
                        for name, result in results.items()
                    ],
                    key=lambda test: test.test_id,
                )
            )
        return MutationSuiteObservation.sealed(
            mutation_id=specification.id,
            baseline_source_sha256=mutation_repository_sha256(baseline_workspace),
            mutant_source_sha256=mutation_repository_sha256(mutant_workspace),
            suite_selection_sha256=MutationSuiteObservation.calculate_selection_sha256(
                sorted(names.values())
            ),
            executor_sha256=self.plan.approved_executor_sha256,
            isolation_policy_sha256=self.plan.approved_isolation_policy_sha256,
            baseline_execution_evidence=ExecutionEvidenceKind.MOCK,
            mutant_execution_evidence=ExecutionEvidenceKind.MOCK,
            baseline_compilation_succeeded=True,
            mutant_compilation_succeeded=True,
            baseline_tests=observations[0],
            mutant_tests=observations[1],
        )


@pytest.mark.parametrize(
    "project_roots", [(".",), ("packages/local-vault",), ("packages/zeta", "packages/alpha")]
)
def test_native_inventory_handoff_executes_every_discovered_owned_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    project_roots: tuple[str, ...],
    record_testsuite_property: Callable[[str, str], None],
) -> None:
    forge = Path.home() / ".foundry/bin/forge"
    solc = _solc_0_8_30()
    if not forge.is_file() or solc is None:
        pytest.skip("Installed external Forge/solc0.8.30 required; no tools are provisioned")
    forge, solc = forge.resolve(strict=True), solc.resolve(strict=True)
    assert not forge.is_relative_to(FIXTURE.parents[2]) and not solc.is_relative_to(
        FIXTURE.parents[2]
    )
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    workspace = private / "source"
    for project in project_roots:
        shutil.copytree(FIXTURE, workspace / project)
    project_root = project_roots[0]
    copied_solc = private / "solc"
    shutil.copyfile(solc, copied_solc)
    copied_solc.chmod(0o700)
    version = subprocess.run(
        [str(forge), "--version"],
        capture_output=True,
        timeout=10,
        check=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
    ).stdout
    (tmp_path / "forge.version.txt").write_bytes(version)
    monkeypatch.setattr(runner, "isolation_attestation_sha256", lambda _backend: "a" * 64)
    result = runner.run_foundry_test_inventory(
        workspace=workspace,
        private_dir=private,
        projects=tuple(
            SolidityProjectMetadata(project_root=project, project_type=SolidityProjectType.FOUNDRY)
            for project in project_roots
        ),
        phase=RepositorySuiteInventoryPhase.PRE_EXECUTION,
        forge_executable=forge,
        copied_solc=copied_solc,
        repository_sha256=mutation_repository_sha256(workspace),
        configuration_sha256="b" * 64,
        tool_version=version.decode().splitlines()[0],
        tool_sha256=hashlib.sha256(forge.read_bytes()).hexdigest(),
        compiler_version="0.8.30",
        compiler_sha256=hashlib.sha256(solc.read_bytes()).hexdigest(),
        backend=_SyntheticInventoryBackend(),
        timeout_seconds=30,
    )
    record_testsuite_property("mutation_inventory_native_" + project_root, str(tmp_path))
    snapshot: dict[str, Any] = {
        "scope": "NATIVE_SYNTHETIC_INPUTS_MOCK_ISOLATION_NO_RUNTIME_AUTHORITY",
        "evidence": result.evidence.model_dump(mode="json"),
        "accounted_output_bytes": result.accounted_output_bytes,
        "generated_artifact_bytes": result.generated_artifact_bytes,
        "snapshots": [
            {
                "project_root": s.project_root,
                "forge_list_json": s.forge_list_json.decode(),
                "build_info_jsons": [raw.decode() for raw in s.build_info_jsons],
                "sources": [
                    {"path": source.path, "source_sha256": source.source_sha256}
                    for source in s.sources
                ],
                "parser_limits": s.parser_limits.model_dump(mode="json"),
            }
            for s in result.compiler_inputs
        ],
    }
    (tmp_path / "snapshot.json").write_text(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    )
    plan = inventory_fixture_plan(result, workspace, project_root=project_root)
    (tmp_path / "plan.json").write_text(plan.model_dump_json(indent=2))
    assert len(plan.specifications) == 13
    assert {s.kind for s in plan.specifications} == set(SecurityMutationClass)
    assert plan.compiler_inventory == result.evidence and plan.discovery is not None
    assert tuple(p.project_root for p in result.compiler_inputs) == tuple(sorted(project_roots))
    assert len(plan.compiler_inventory.projects) == len(project_roots)
    if len(project_roots) > 1:
        other = next(p for p in result.evidence.projects if p.project_root != project_root)
        foreign_test = canonical_foundry_inventory_mutation_test_id(
            other.records[0],
            inventory_sha256=result.evidence.normalized_inventory_sha256,
        )
        values = {
            name: getattr(plan, name) for name in type(plan).model_fields if name != "plan_sha256"
        }
        values["bindings"] = [
            plan.bindings[0].model_copy(update={"test_ids": [foreign_test]}),
            *plan.bindings[1:],
        ]
        with pytest.raises(ValueError, match="tests absent"):
            MutationApplicabilityPlan.sealed(**values)
    assert not plan.discovery.execution_validated and not plan.discovery.qualification_eligible
    campaigns_root = tmp_path / "campaigns"
    campaigns_root.mkdir(mode=0o700)
    executor = _NativeSyntheticExecutor(forge, solc, plan, tmp_path / "campaign-artifacts")
    # Named invariant: a stale source tree never reaches mutation execution.
    selected_source = workspace / project_root / SOURCE_PATH
    original_source = selected_source.read_bytes()
    try:
        selected_source.write_bytes(original_source + b"// synthetic post-plan drift\n")
        with pytest.raises(ValueError, match="source does not match"):
            run_owned_mutation_campaign(
                source_repository=workspace,
                private_root=campaigns_root,
                plan=plan,
                mutation_id=plan.specifications[0].id,
                executor=executor,
            )
        assert executor.calls == 0 and not list(campaigns_root.iterdir())
    finally:
        selected_source.write_bytes(original_source)
    campaigns = []
    for spec in plan.specifications:
        campaign = run_owned_mutation_campaign(
            source_repository=workspace,
            private_root=campaigns_root,
            plan=plan,
            mutation_id=spec.id,
            executor=executor,
        )
        campaigns.append(campaign)
        assert campaign.failure_kind is None
        assert (
            campaign.restoration_verified
            and campaign.workspace_disposed
            and campaign.source_preserved
        )
        assert not list(campaigns_root.iterdir())
        assert mutation_repository_sha256(workspace) == plan.source_repository_sha256
    (tmp_path / "campaigns.json").write_text(
        json.dumps([c.model_dump(mode="json") for c in campaigns])
    )
    assert executor.calls == 13
    score = score_planned_mutation_campaigns(
        plan=plan, campaigns=campaigns, minimum_property_kill_score=0.95
    )
    assert not score.gate_passed
    assert all(outcome.outcome.value == "inconclusive" for outcome in score.outcomes)
