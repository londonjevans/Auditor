from __future__ import annotations

import asyncio
import hashlib
import json
import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.schemas import (
    AnalysisState,
    AttackerCapabilityPolicy,
    AuditReport,
    ForkActor,
    ForkAssertion,
    ForkCallStep,
    ForkTestType,
    FoundryInvariantHarnessSpec,
    GeneratedFoundryTestSpec,
    InvariantCategory,
    InvariantExecutionAttemptEvidence,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    InvariantProbe,
    InvariantPropertySpec,
    InvariantRelation,
    InvariantSpec,
    InvariantSuite,
    RepositoryFile,
    RepositoryMap,
    ReproductionAttemptEvidence,
    ReproductionResult,
    ReproductionState,
    ScannerRun,
    ScannerStatus,
    SolidityProjectMetadata,
    SolidityProjectType,
    SolidityProvenance,
    StatefulActionSpec,
)
from mmaudit.orchestration.manifest import (
    build_run_evidence_manifest,
    canonical_sha256,
    write_run_evidence_manifest,
)
from mmaudit.orchestration.replay import (
    OfflineReplay,
    OfflineReplayOrchestrator,
    OfflineReplayStatus,
    ReplayComponentKind,
    ReplayComponentStatus,
    write_offline_replay,
)
from mmaudit.reporting.json_report import write_json

runner = CliRunner()
_NOW = datetime(2026, 7, 27, tzinfo=UTC)


class _LocalScannerRunner:
    def __init__(self, runs: list[ScannerRun]) -> None:
        self.runs = runs
        self.calls = 0

    async def run_all(
        self,
        root: Path,
        private_dir: Path,
        *,
        skip_codeql: bool = False,
        allow_fork_probing: bool = False,
    ) -> list[ScannerRun]:
        del root, private_dir
        assert not skip_codeql
        assert not allow_fork_probing
        self.calls += 1
        return self.runs


class _LocalInvariantRunner:
    def __init__(self, result: InvariantExecutionResult) -> None:
        self.result = result
        self.calls = 0

    def run(
        self,
        *,
        repository_root: Path,
        project: SolidityProjectMetadata,
        specification: FoundryInvariantHarnessSpec,
        private_dir: Path,
    ) -> InvariantExecutionResult:
        del repository_root, private_dir
        assert project.project_root == "."
        assert specification.invariant_id == self.result.invariant_id
        self.calls += 1
        return self.result


class _LocalReproductionRunner:
    def __init__(self, result: ReproductionResult) -> None:
        self.result = result
        self.calls = 0

    def run(
        self,
        *,
        repository_root: Path,
        project: SolidityProjectMetadata,
        candidate,
        specification: GeneratedFoundryTestSpec,
        private_dir: Path,
    ) -> ReproductionResult:
        del repository_root, private_dir
        assert project.project_root == "."
        assert candidate.candidate_id == specification.candidate_id
        self.calls += 1
        return self.result


def _scanner_run() -> ScannerRun:
    return ScannerRun(
        scanner="synthetic-local",
        status=ScannerStatus.SUCCESS,
        version="1.0.0",
        executable_sha256="1" * 64,
        started_at=_NOW,
        finished_at=_NOW,
        duration_seconds=0,
        findings=[],
        isolation_backend="synthetic-no-network",
    )


def _harness() -> FoundryInvariantHarnessSpec:
    return FoundryInvariantHarnessSpec(
        invariant_id="inv-replay-counterexample",
        name="ReplayCounterexample",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000001",
            )
        ],
        actions=[
            StatefulActionSpec(
                action_id="Touch",
                target="Vault",
                function_signature="touch()",
                actor_names=["attacker"],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="StateRemainsZero",
                left=InvariantProbe(
                    target="Vault",
                    function_signature="state()",
                ),
                relation=InvariantRelation.LTE,
                expected_uint=0,
            )
        ],
        runs=2,
        depth=1,
        seed=7,
    )


def _invariant_result(
    status: InvariantExecutionStatus = InvariantExecutionStatus.COUNTEREXAMPLE,
) -> InvariantExecutionResult:
    return InvariantExecutionResult(
        invariant_id="inv-replay-counterexample",
        harness_name="ReplayCounterexample",
        status=status,
        source_sha256="2" * 64,
        runs=2,
        depth=1,
        seed=7,
        attempts=1,
        successful_attempts=1,
        attempt_evidence=[
            InvariantExecutionAttemptEvidence(
                attempt=1,
                status=status,
                source_sha256="2" * 64,
                fresh_workspace=True,
                stdout_sha256="3" * 64,
                stderr_sha256="4" * 64,
                stdout_path="attempt-1.stdout.txt",
                stderr_path="attempt-1.stderr.txt",
            )
        ],
    )


def _test_specification() -> GeneratedFoundryTestSpec:
    return GeneratedFoundryTestSpec(
        candidate_id="candidate-replay",
        name="SavedRemediationTest",
        test_type=ForkTestType.AUTHORIZATION_MATRIX,
        rationale="Validate the saved synthetic remediation boundary.",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000001",
            )
        ],
        attacker_policy=AttackerCapabilityPolicy(
            attacker_controlled_actors=["attacker"],
        ),
        attack_calls=[
            ForkCallStep(
                step_id="touch",
                actor="attacker",
                target="Vault",
                function_signature="touch()",
            )
        ],
        assertions=[ForkAssertion(kind="call_reverts", step_id="touch")],
        assumptions=["The local synthetic fixture is unchanged"],
    )


def _reproduction_result() -> ReproductionResult:
    return ReproductionResult(
        candidate_id="candidate-replay",
        test_name="SavedRemediationTest",
        state=ReproductionState.NOT_REPRODUCED,
        specification_sha256=canonical_sha256(_test_specification().model_dump(mode="json")),
        generated_test_sha256="6" * 64,
        attempts=1,
        successful_attempts=0,
        original_steps=1,
        minimized_steps=1,
        repository_sha256="7" * 64,
        attempt_evidence=[
            ReproductionAttemptEvidence(
                attempt=1,
                state=ReproductionState.NOT_REPRODUCED,
                repository_sha256="7" * 64,
                generated_test_sha256="6" * 64,
                fresh_workspace=True,
                stdout_sha256="8" * 64,
                stderr_sha256="9" * 64,
            )
        ],
    )


def _invariant_suite(source_hash: str) -> InvariantSuite:
    return InvariantSuite(
        invariants=[
            InvariantSpec(
                id="inv-replay-counterexample",
                title="Synthetic replay counterexample",
                category=InvariantCategory.STATE_MACHINE,
                description="A local fixture exposes a deterministic incorrect state transition.",
                locations=[
                    {
                        "path": "src/Vault.sol",
                        "start_line": 1,
                        "end_line": 1,
                        "content_hash": source_hash,
                    }
                ],
                entity_ids=[],
                state_variables=["state"],
                functions=["touch"],
                protocol_profiles=["synthetic"],
                assumptions=["Local synthetic fixture only"],
                provenance=SolidityProvenance.HEURISTIC,
                confidence=0.9,
                template_available=True,
                executable=True,
                analysis_state=AnalysisState.DETERMINISTIC,
                evidence_hash="a" * 64,
            )
        ],
        protocol_profiles=["synthetic"],
        templates_available_count=1,
        executable_count=1,
    )


def _write_replay_run(
    root: Path,
    config,
    candidate,
) -> tuple[Path, Path, Path]:
    repository = root / "repository"
    source = repository / "src" / "Vault.sol"
    source.parent.mkdir(parents=True)
    source_text = "contract Vault { uint256 public state; function touch() external {} }\n"
    source.write_text(source_text, encoding="utf-8")
    source_hash = hashlib.sha256(source_text.encode()).hexdigest()
    project = SolidityProjectMetadata(
        project_type=SolidityProjectType.FOUNDRY,
        project_root=".",
        source_directories=["src"],
        test_directories=["test"],
        build_command=["forge", "build"],
        test_command=["forge", "test"],
    )
    scanner = _scanner_run()
    harness = _harness()
    invariant_result = _invariant_result()
    specification = _test_specification()
    reproduction = _reproduction_result()
    report = AuditReport(
        schema_version="1.0",
        run_id="offline-replay-test",
        generated_at=_NOW,
        completed=True,
        incomplete_reasons=[],
        repository=RepositoryMap(
            root_name=repository.name,
            languages={"Solidity": 1},
            frameworks=["Foundry"],
            manifests=[],
            entry_points=[],
            api_surfaces=[],
            auth_components=[],
            data_layers=[],
            network_clients=[],
            file_handlers=[],
            configuration_files=[],
            sensitive_processing=[],
            security_tests=[],
            files=[
                RepositoryFile(
                    path="src/Vault.sol",
                    size=len(source_text.encode()),
                    lines=1,
                    sha256=source_hash,
                    language="Solidity",
                )
            ],
        ),
        configuration_hash=config.stable_hash(),
        model_configuration_hash=config.model_hash(),
        privacy={"code_egress_enabled": False},
        scanner_runs=[scanner],
        usage=[],
        budget_usd=20,
        accounted_cost_usd=0,
        findings=[],
        rejected_findings=[],
    )
    run_dir = root / "run"
    run_dir.mkdir()
    artifacts = {
        "scanner-results.json": {
            "schema_version": "1.0",
            "runs": [scanner.model_dump(mode="json")],
        },
        "solidity-projects.json": {
            "schema_version": "1.0",
            "projects": [project.model_dump(mode="json")],
        },
        "solidity-compilation.json": {"schema_version": "1.0", "results": []},
        "solidity-invariants.json": {
            "schema_version": "1.0",
            "invariants": _invariant_suite(source_hash).model_dump(mode="json"),
        },
        "invariant-harness-plan.json": {
            "schema_version": "1.0",
            "harnesses": [harness.model_dump(mode="json")],
            "limitations": [],
        },
        "property-corpus.json": {
            "schema_version": "1.0",
            "corpus": {
                "schema_version": "1.0",
                "properties": [],
                "limitations": [],
                "corpus_hash": "b" * 64,
            },
        },
        "invariant-execution-results.json": {
            "schema_version": "1.0",
            "harnesses": [harness.model_dump(mode="json")],
            "results": [invariant_result.model_dump(mode="json")],
        },
        "candidate-findings.json": {
            "schema_version": "1.0",
            "findings": [candidate.model_dump(mode="json")],
        },
        "reproduction-results.json": {
            "schema_version": "1.0",
            "test_specifications": [specification.model_dump(mode="json")],
            "results": [reproduction.model_dump(mode="json")],
            "falsification_decisions": [],
        },
        "formal-results.json": {"schema_version": "1.0", "runs": []},
        "solidity-coverage.json": {"schema_version": "1.0", "coverage": None},
        "model-review-coverage.json": {"schema_version": "1.0", "coverage": None},
        "scope-assessment.json": {"schema_version": "1.0", "assessment": None},
    }
    for name, payload in artifacts.items():
        write_json(run_dir / name, payload)
    write_json(run_dir / "final-findings.json", report)
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
    )
    manifest_path = run_dir / "run-evidence-manifest.json"
    write_run_evidence_manifest(manifest_path, manifest)
    return repository, run_dir, manifest_path


def _orchestrator(
    config,
) -> tuple[
    OfflineReplayOrchestrator,
    _LocalScannerRunner,
    _LocalInvariantRunner,
    _LocalReproductionRunner,
]:
    scanner = _LocalScannerRunner([_scanner_run()])
    invariant = _LocalInvariantRunner(_invariant_result())
    reproduction = _LocalReproductionRunner(_reproduction_result())
    return (
        OfflineReplayOrchestrator(
            config,
            scanner_runner=scanner,
            invariant_runner=invariant,
            reproduction_runner=reproduction,
        ),
        scanner,
        invariant,
        reproduction,
    )


@pytest.mark.asyncio
async def test_local_fixture_replays_scanner_saved_test_and_counterexample_offline(
    tmp_path: Path,
    config_factory,
    candidate_factory,
    monkeypatch,
) -> None:
    config = config_factory()
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(tmp_path, config, candidate)
    orchestrator, scanner, invariant, reproduction = _orchestrator(config)

    def deny_network(*_args, **_kwargs):
        raise AssertionError("offline replay attempted network access")

    monkeypatch.setattr(socket.socket, "connect", deny_network)
    monkeypatch.setattr(
        "mmaudit.models.openrouter.OpenRouterClient.__init__",
        deny_network,
    )
    first = await orchestrator.replay(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
        work_dir=tmp_path / "work-one",
    )
    second = await orchestrator.replay(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
        work_dir=tmp_path / "work-two",
    )

    assert first == second
    assert first.status is OfflineReplayStatus.REPLAYED
    assert not first.model_provider_contacted
    assert first.remote_network_policy == "denied"
    assert not first.missing_kinds
    assert {item.kind for item in first.components} == set(ReplayComponentKind)
    assert all(item.status is ReplayComponentStatus.MATCHED for item in first.components)
    assert (scanner.calls, invariant.calls, reproduction.calls) == (2, 2, 2)
    assert OfflineReplay.model_validate_json(first.model_dump_json()) == first


@pytest.mark.asyncio
async def test_replay_detects_semantic_drift_and_verifies_before_execution(
    tmp_path: Path,
    config_factory,
    candidate_factory,
) -> None:
    config = config_factory()
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(tmp_path, config, candidate)
    scanner = _LocalScannerRunner([_scanner_run()])
    invariant = _LocalInvariantRunner(_invariant_result(InvariantExecutionStatus.PASSED))
    reproduction = _LocalReproductionRunner(_reproduction_result())
    orchestrator = OfflineReplayOrchestrator(
        config,
        scanner_runner=scanner,
        invariant_runner=invariant,
        reproduction_runner=reproduction,
    )

    drifted = await orchestrator.replay(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
        work_dir=tmp_path / "drift-work",
    )
    assert drifted.status is OfflineReplayStatus.DRIFTED
    assert any(
        item.kind is ReplayComponentKind.COUNTEREXAMPLE
        and item.status is ReplayComponentStatus.DRIFTED
        for item in drifted.components
    )

    (repository / "src" / "Vault.sol").write_text("contract Vault { }\n", encoding="utf-8")
    calls_before = (scanner.calls, invariant.calls, reproduction.calls)
    with pytest.raises(ValueError, match="refused stale"):
        await orchestrator.replay(
            manifest_path=manifest_path,
            run_dir=run_dir,
            repository_root=repository,
            work_dir=tmp_path / "stale-work",
        )
    assert (scanner.calls, invariant.calls, reproduction.calls) == calls_before


def test_replay_cli_and_published_schema(
    tmp_path: Path,
    config_factory,
    candidate_factory,
    monkeypatch,
) -> None:
    config = config_factory()
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(tmp_path, config, candidate)
    orchestrator, _, _, _ = _orchestrator(config)
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    monkeypatch.setattr(
        "mmaudit.cli.OfflineReplayOrchestrator",
        lambda _config: orchestrator,
    )
    output = tmp_path / "offline-replay.json"
    result = runner.invoke(
        app,
        [
            "replay",
            "--manifest",
            str(manifest_path),
            "--run-dir",
            str(run_dir),
            "--repo",
            str(repository),
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--output",
            str(output),
            "--work-dir",
            str(tmp_path / "cli-work"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.SUCCESS
    replay = OfflineReplay.model_validate_json(output.read_text(encoding="utf-8"))
    assert replay.status is OfflineReplayStatus.REPLAYED
    tampered = replay.model_dump(mode="json")
    tampered["run_id"] = "tampered"
    with pytest.raises(ValidationError, match="hash is inconsistent"):
        OfflineReplay.model_validate(tampered)

    schema = json.loads(
        (Path(__file__).resolve().parents[2] / "schemas" / "offline_replay.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert schema["additionalProperties"] is False
    assert schema["properties"]["components"]["maxItems"] == 200_000
    assert schema["$defs"]["component"]["additionalProperties"] is False
    assert schema["properties"]["model_provider_contacted"] == {"const": False}


def test_replay_writer_rejects_links(
    tmp_path: Path,
    config_factory,
    candidate_factory,
) -> None:
    config = config_factory()
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(tmp_path, config, candidate)
    orchestrator, _, _, _ = _orchestrator(config)
    replay = asyncio.run(
        orchestrator.replay(
            manifest_path=manifest_path,
            run_dir=run_dir,
            repository_root=repository,
            work_dir=tmp_path / "writer-work",
        )
    )
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    linked = tmp_path / "linked.json"
    try:
        linked.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="may not be a link"):
        write_offline_replay(linked, replay)
