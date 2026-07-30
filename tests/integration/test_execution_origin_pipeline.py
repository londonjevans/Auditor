"""Real local pipeline regression for deterministic execution-origin findings."""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from mmaudit.isolation.provenance import (
    isolation_attestation_sha256,
    isolation_execution_evidence,
)
from mmaudit.models.schemas import (
    AuditReport,
    CandidateFindingArtifact,
    CandidateOriginKind,
    EvidenceStrength,
    ExecutionEvidenceKind,
    FindingOriginKind,
    FindingStatus,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    LocalInvariantDeployment,
    LocalInvariantDeploymentArgument,
    ScannerRun,
    SolidityProjectMetadata,
)
from mmaudit.orchestration.manifest import (
    canonical_sha256,
    load_run_evidence_manifest,
    validate_manifest_artifacts,
)
from mmaudit.orchestration.pipeline import AuditPipeline
from mmaudit.orchestration.replay import (
    OfflineReplayOrchestrator,
    OfflineReplayStatus,
    ReplayComponentKind,
    ReplayComponentStatus,
)
from mmaudit.orchestration.verification import (
    RunVerificationStatus,
    verify_run_evidence,
)
from mmaudit.repository.locations import validate_location
from mmaudit.scanners.runner import ScannerRunner
from mmaudit.solidity.invariant_execution import FoundryInvariantRunner
from mmaudit.solidity.reproduction import (
    IsolationBackend,
    default_isolation_backend,
)
from tests.conftest import FIXTURES


class _NoScannerRunner(ScannerRunner):
    """Keep this regression scoped to the real local invariant engine."""

    def __init__(self) -> None:
        pass

    async def run_all(
        self,
        root: Path,
        private_dir: Path,
        *,
        skip_codeql: bool = False,
        allow_fork_probing: bool = False,
        projects: Sequence[SolidityProjectMetadata] = (),
        expected_repository_sha256: str | None = None,
        repository_exclusion_root: Path | None = None,
    ) -> list[ScannerRun]:
        del (
            root,
            private_dir,
            skip_codeql,
            allow_fork_probing,
            projects,
            expected_repository_sha256,
            repository_exclusion_root,
        )
        return []

    def required_failures(self, runs: list[ScannerRun]) -> list[str]:
        del runs
        return []


def _real_local_toolchain() -> tuple[Path, Path, IsolationBackend]:
    forge_raw = shutil.which("forge")
    if forge_raw is None:
        pytest.skip("real execution-origin regression requires external forge")
    forge = Path(forge_raw).resolve(strict=True)
    solc_candidates = (
        Path.home() / "Library" / "Application Support" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".local" / "share" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".svm" / "0.8.30" / "solc-0.8.30",
    )
    solc = next((candidate.resolve() for candidate in solc_candidates if candidate.is_file()), None)
    if solc is None:
        pytest.skip("real execution-origin regression requires external solc 0.8.30")
    backend = default_isolation_backend("auto")
    if backend is None:
        pytest.skip("real execution-origin regression requires hardened local isolation")
    assert isolation_execution_evidence(backend) is ExecutionEvidenceKind.REAL
    assert isolation_attestation_sha256(backend) is not None
    repository_root = Path(__file__).resolve().parents[2]
    assert not forge.is_relative_to(repository_root)
    assert not solc.is_relative_to(repository_root)
    return forge, solc, backend


def _local_deployments() -> list[dict[str, Any]]:
    source_path = "src/EconomicVaults.sol"
    return [
        deployment.model_dump(mode="json")
        for deployment in (
            LocalInvariantDeployment(
                target_alias="VulnerableInflationVaultAsset",
                contract_name="SimpleToken",
                source_path=source_path,
                token_seed_function_signature="mint(address,uint256)",
            ),
            LocalInvariantDeployment(
                target_alias="VulnerableInflationVault",
                contract_name="VulnerableInflationVault",
                source_path=source_path,
                constructor_arguments=[
                    LocalInvariantDeploymentArgument(
                        target_alias="VulnerableInflationVaultAsset",
                        cast_contract="SimpleToken",
                    )
                ],
            ),
            LocalInvariantDeployment(
                target_alias="PatchedInflationVaultAsset",
                contract_name="SimpleToken",
                source_path=source_path,
                token_seed_function_signature="mint(address,uint256)",
            ),
            LocalInvariantDeployment(
                target_alias="PatchedInflationVault",
                contract_name="PatchedInflationVault",
                source_path=source_path,
                constructor_arguments=[
                    LocalInvariantDeploymentArgument(
                        target_alias="PatchedInflationVaultAsset",
                        cast_contract="SimpleToken",
                    )
                ],
            ),
        )
    ]


@pytest.mark.asyncio
async def test_real_counterexample_originates_pipeline_finding_but_safe_control_does_not(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    forge, solc, backend = _real_local_toolchain()
    repository = tmp_path / "execution-origin-erc4626"
    shutil.copytree(FIXTURES / "solidity" / "economic_erc4626", repository)
    config = config_factory(
        privacy={"fail_on_detected_secret": False},
        smart_contracts={"enabled": True, "compile": False},
        reproduction={
            "enabled": False,
            "required_for_solidity": False,
            "require_hardened_isolation": True,
            "expected_chain_id": 31_337,
            "repetitions": 2,
            "targets": {
                "VulnerableInflationVault": "0x2000000000000000000000000000000000000002",
                "VulnerableInflationVaultAsset": ("0x3000000000000000000000000000000000000002"),
                "PatchedInflationVault": "0x2000000000000000000000000000000000000003",
                "PatchedInflationVaultAsset": "0x3000000000000000000000000000000000000003",
            },
        },
        invariants={
            "execute_generated": True,
            "local_deployments": _local_deployments(),
        },
    )
    invariant_runner = FoundryInvariantRunner(
        config.reproduction,
        config.smart_contracts,
        backend=backend,
        forge_executable=forge,
        solc_executable=solc,
    )
    result = await AuditPipeline(
        config,
        repo=repository,
        output=tmp_path / "output",
        scanner_runner=_NoScannerRunner(),
        invariant_runner=invariant_runner,
    ).run(scanner_only=True)

    execution_payload = json.loads(
        (result.run_dir / "invariant-execution-results.json").read_text(encoding="utf-8")
    )
    executions = [
        InvariantExecutionResult.model_validate(item)
        for item in execution_payload["results"]
        if item["economic_template"] == "erc4626_donation_inflation"
    ]
    assert len(executions) == 2
    unsafe = next(
        item for item in executions if item.status is InvariantExecutionStatus.COUNTEREXAMPLE
    )
    safe = next(item for item in executions if item.status is InvariantExecutionStatus.PASSED)
    harness_payload = json.loads(
        (result.run_dir / "invariant-harness-plan.json").read_text(encoding="utf-8")
    )
    harnesses = {item["invariant_id"]: item for item in harness_payload["harnesses"]}
    unsafe_targets = {
        item["target_alias"] for item in harnesses[unsafe.invariant_id]["local_deployments"]
    }
    safe_targets = {
        item["target_alias"] for item in harnesses[safe.invariant_id]["local_deployments"]
    }
    assert "VulnerableInflationVault" in unsafe_targets
    assert "PatchedInflationVault" in safe_targets
    assert all(
        item.execution_evidence is ExecutionEvidenceKind.REAL
        and item.replay_confirmed
        and item.attempts == item.successful_attempts == 2
        and item.executable_sha256 is not None
        and item.compiler_sha256 == hashlib.sha256(solc.read_bytes()).hexdigest()
        and item.isolation_attestation_sha256 == isolation_attestation_sha256(backend)
        for item in executions
    )

    candidate_artifact = CandidateFindingArtifact.model_validate_json(
        (result.run_dir / "candidate-findings.json").read_text(encoding="utf-8")
    )
    assert candidate_artifact.schema_version == "1.1"
    assert len(candidate_artifact.findings) == 1
    execution_candidates = [
        item
        for item in candidate_artifact.findings
        if item.origin_kind is CandidateOriginKind.DETERMINISTIC_EXECUTION
    ]
    assert len(execution_candidates) == 1
    candidate = execution_candidates[0]
    provenance = candidate.execution_provenance
    assert provenance is not None
    assert candidate.role is None
    assert candidate.model_family is None
    assert provenance.invariant_id == unsafe.invariant_id
    assert provenance.invariant_id != safe.invariant_id
    assert provenance.execution_result_sha256 == canonical_sha256(unsafe.model_dump(mode="json"))
    assert provenance.execution_observation_sha256 == unsafe.execution_observation_sha256
    assert provenance.source_sha256 == unsafe.source_sha256
    assert provenance.compiler_sha256 == unsafe.compiler_sha256
    assert provenance.executable_sha256 == unsafe.executable_sha256
    assert provenance.isolation_attestation_sha256 == unsafe.isolation_attestation_sha256
    assert tuple(candidate.locations) == provenance.source_locations
    assert all(validate_location(repository, location).valid for location in candidate.locations)

    report = AuditReport.model_validate_json(
        (result.run_dir / "final-findings.json").read_text(encoding="utf-8")
    )
    execution_findings = [
        item
        for item in report.findings
        if item.origin_kind is FindingOriginKind.DETERMINISTIC_EXECUTION
    ]
    assert len(execution_findings) == 1
    finding = execution_findings[0]
    assert finding.status is FindingStatus.CONFIRMED
    assert finding.evidence_strength in {
        EvidenceStrength.DETERMINISTIC_EXECUTION_COUNTEREXAMPLE,
        EvidenceStrength.LOCAL_FORK_REPRODUCTION,
        EvidenceStrength.MINIMIZED_LOCAL_FORK_REPRODUCTION,
        EvidenceStrength.FORMAL_COUNTEREXAMPLE,
    }
    assert candidate.candidate_id in finding.contributing_candidate_ids
    assert finding.execution_provenance == (provenance,)
    assert finding.location_validation.valid
    assert tuple(finding.locations) == provenance.source_locations
    execution_evidence = [item for item in finding.evidence if item.type == "execution"]
    assert len(execution_evidence) == 1
    assert execution_evidence[0].source == "mmaudit-foundry-invariant"
    assert execution_evidence[0].rule_id == provenance.invariant_id
    assert execution_evidence[0].fingerprint == provenance.provenance_sha256
    assert not finding.model_votes
    assert all(item.type != "model" for item in finding.evidence)

    markdown = (result.run_dir / "audit-report.md").read_text(encoding="utf-8")
    assert "Finding discovery origins: deterministic execution=1" in markdown
    assert (
        "This finding originated from deterministic execution and is not model-attributed."
        in markdown
    )
    sarif = json.loads((result.run_dir / "audit-results.sarif").read_text(encoding="utf-8"))
    assert len(sarif["runs"][0]["results"]) == 1
    sarif_result = sarif["runs"][0]["results"][0]
    assert "[deterministic_execution]" in sarif_result["message"]["text"]
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "origin/deterministic_execution" in rule["properties"]["tags"]
    assert rule["properties"]["executionProvenanceSha256s"] == [provenance.provenance_sha256]

    manifest_path = result.run_dir / "run-evidence-manifest.json"
    manifest = load_run_evidence_manifest(manifest_path)
    validate_manifest_artifacts(manifest, result.run_dir)
    verification = verify_run_evidence(
        manifest_path=manifest_path,
        run_dir=result.run_dir,
        repository_root=repository,
        config=config,
    )
    assert verification.status is RunVerificationStatus.CURRENT

    replay = await OfflineReplayOrchestrator(
        config,
        invariant_runner=invariant_runner,
    ).replay(
        manifest_path=manifest_path,
        run_dir=result.run_dir,
        repository_root=repository,
        work_dir=tmp_path / "offline-replay",
    )
    assert replay.status is OfflineReplayStatus.REPLAYED
    assert not replay.missing_kinds
    assert {(item.kind, item.status) for item in replay.components} == {
        (ReplayComponentKind.COUNTEREXAMPLE, ReplayComponentStatus.MATCHED),
        (ReplayComponentKind.SAVED_TEST, ReplayComponentStatus.MATCHED),
    }
