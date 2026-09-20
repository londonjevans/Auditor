"""Original compiler writer to generated assertion to owned native campaign; MOCK isolation only."""

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
from mmaudit.solidity.properties import generated_local_property_source
from tests.integration.test_mutation_compilation import _solc_0_8_30
from tests.integration.test_mutation_inventory_execution import _SyntheticInventoryBackend
from tests.property_mutation_support import FIXTURE, SOURCE, property_inputs, property_plan


class NativePropertyExecutor:
    """Actual offline synthetic suite execution; no admitted isolation or audit authority."""

    def __init__(self, forge: Path, solc: Path, plan: MutationApplicabilityPlan, artifacts: Path):
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
        assert self.plan.property_tests is not None and self.plan.discovery is not None
        tests = self.plan.property_tests.tests
        by_name = {test.record.declaration_signature: test.test_id for test in tests}
        observations = []
        for label, workspace in (("baseline", baseline_workspace), ("mutant", mutant_workspace)):
            artifact_dir = self.artifacts / specification.id / label
            artifact_dir.mkdir(parents=True)
            project = workspace / self.plan.discovery.project_root
            process = subprocess.run(
                [
                    str(self.forge),
                    "test",
                    "--root",
                    str(project),
                    "--use",
                    str(self.solc),
                    "--offline",
                    "--json",
                    "--out",
                    str(artifact_dir / "out"),
                    "--cache-path",
                    str(artifact_dir / "cache"),
                ],
                cwd=project,
                env={
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "NO_COLOR": "1",
                },
                capture_output=True,
                timeout=30,
                check=False,
            )
            assert len(process.stdout) < 1_000_000 and len(process.stderr) < 1_000_000
            (artifact_dir / "stdout.json").write_bytes(process.stdout)
            (artifact_dir / "stderr.txt").write_bytes(process.stderr)
            (artifact_dir / "returncode.txt").write_text(str(process.returncode))
            payload = json.loads(process.stdout)
            results = {
                name: result
                for suite in payload.values()
                if isinstance(suite, dict)
                for name, result in suite.get("test_results", {}).items()
            }
            assert set(results) == set(by_name), payload
            assert all(r["status"] in {"Success", "Failure"} for r in results.values())
            failed = sorted(name for name, r in results.items() if r["status"] == "Failure")
            expected = (
                "Authorization"
                if specification.kind is SecurityMutationClass.AUTHORIZATION_REMOVAL
                else "Scaling"
            )
            assert failed == ([] if label == "baseline" else [f"invariant_{expected}()"])
            assert process.returncode == (1 if failed else 0)
            # Actual stateful campaign observations, not just declared runs/depth.
            for result in results.values():
                details = result["kind"]["Invariant"]
                assert sum(metric["calls"] for metric in details["metrics"].values()) > 0
                if result["status"] == "Success":
                    assert details["runs"] == 8 and details["calls"] == 32
            observations.append(
                sorted(
                    [
                        MutationSuiteTestObservation(
                            test_id=by_name[name],
                            status=MutationSuiteTestStatus.PASSED
                            if result["status"] == "Success"
                            else MutationSuiteTestStatus.FAILED,
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
                sorted(by_name.values())
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


@pytest.mark.parametrize("project_root", [".", "packages/local-control"])
def test_native_generated_assertion_mapping_drives_owned_mutations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    project_root: str,
    record_testsuite_property: Callable[[str, str], None],
) -> None:
    forge = Path.home() / ".foundry/bin/forge"
    solc = _solc_0_8_30()
    if not forge.is_file() or solc is None:
        pytest.skip("Installed external Forge/solc0.8.30 required; no provisioning")
    forge, solc = forge.resolve(strict=True), solc.resolve(strict=True)
    assert not forge.is_relative_to(FIXTURE.parents[2]) and not solc.is_relative_to(
        FIXTURE.parents[2]
    )
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    workspace = private / "source"
    project = workspace / project_root
    project.mkdir(parents=True)
    shutil.copytree(FIXTURE / "src", project / "src")
    shutil.copyfile(FIXTURE / "foundry.toml", project / "foundry.toml")
    corpus, harnesses = property_inputs(project_root)
    assert len(corpus.properties) == 2
    for harness in harnesses:
        generated = generated_local_property_source(harness, project_root=project_root)
        assert generated is not None
        path = workspace / generated[0]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(generated[1])
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
        projects=(
            SolidityProjectMetadata(
                project_root=project_root, project_type=SolidityProjectType.FOUNDRY
            ),
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
    snapshot: dict[str, Any] = {
        "scope": "NATIVE_SYNTHETIC_GENERATED_PROPERTIES_MOCK_ISOLATION_NO_AUTHORITY",
        "evidence": result.evidence.model_dump(mode="json"),
        "accounted_output_bytes": result.accounted_output_bytes,
        "generated_artifact_bytes": result.generated_artifact_bytes,
        "snapshots": [
            dict(
                project_root=s.project_root,
                forge_list_json=s.forge_list_json.decode(),
                build_info_jsons=[raw.decode() for raw in s.build_info_jsons],
                sources=[
                    dict(path=source.path, source_sha256=source.source_sha256)
                    for source in s.sources
                ],
                parser_limits=s.parser_limits.model_dump(mode="json"),
            )
            for s in result.compiler_inputs
        ],
    }
    (tmp_path / "snapshot.json").write_text(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    )
    record_testsuite_property("property_mutation_native_" + project_root, str(tmp_path))
    plan = property_plan(result, project_root)
    (tmp_path / "plan.json").write_text(plan.model_dump_json(indent=2))
    assert len(plan.specifications) == len(plan.bindings) == 2
    assert len(plan.non_applicability) == 2 and plan.property_tests is not None
    assert len(plan.property_tests.tests) == 2 and not plan.property_tests.unresolved_property_ids
    campaigns_root = tmp_path / "campaigns"
    campaigns_root.mkdir(mode=0o700)
    executor = NativePropertyExecutor(forge, solc, plan, tmp_path / "campaign-artifacts")
    campaigns = []
    for specification in plan.specifications:
        campaign = run_owned_mutation_campaign(
            source_repository=workspace,
            private_root=campaigns_root,
            plan=plan,
            mutation_id=specification.id,
            executor=executor,
        )
        campaigns.append(campaign)
        assert campaign.failure_kind is None, campaign
        assert (
            campaign.restoration_verified
            and campaign.workspace_disposed
            and campaign.source_preserved
        )
        assert mutation_repository_sha256(workspace) == plan.source_repository_sha256
        assert not list(campaigns_root.iterdir())
    (tmp_path / "campaigns.json").write_text(
        json.dumps([c.model_dump(mode="json") for c in campaigns])
    )
    assert executor.calls == 2
    assert (project / SOURCE).read_bytes() == (FIXTURE / SOURCE).read_bytes()
    score = score_planned_mutation_campaigns(
        plan=plan, campaigns=campaigns, minimum_property_kill_score=0.95
    )
    assert len(score.outcomes) == 4 and not score.gate_passed
    assert all(outcome.outcome.value == "inconclusive" for outcome in score.outcomes)
    (tmp_path / "score.json").write_text(score.model_dump_json(indent=2))
