from __future__ import annotations

import gc
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

import mmaudit.orchestration.pipeline as pipeline_module
import mmaudit.scanners.foundry as foundry_module
import mmaudit.scanners.runner as runner_module
import mmaudit.scanners.runtime_evidence as runtime_evidence_module
from mmaudit.config import AuditConfig
from mmaudit.models.schemas import (
    EvidenceStrength,
    ExecutionEvidenceKind,
    FoundryTestExecutionSummary,
    Location,
    RepositoryCodeExecutionState,
    RepositorySuiteExecutionPolicy,
    RepositorySuiteFramework,
    RepositorySuiteSelection,
    RepositorySuiteTestDescriptor,
    RepositoryTestExecution,
    RepositoryTestExecutionStatus,
    RepositoryTestKind,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
    Severity,
)
from mmaudit.orchestration.pipeline import _annotate_scanner_locations
from mmaudit.scanners.base import (
    ScannerAdapter,
    ScannerIsolationBackend,
    ScannerSourceIntegrityError,
    scanner_workspace_sha256,
)
from mmaudit.scanners.fork_rpc import PinnedForkObservation
from mmaudit.scanners.foundry import (
    FoundryForkScanner,
    _finalize_foundry_repository_suite,
    _FoundryTestObservation,
)
from mmaudit.scanners.runner import ScannerRunner
from mmaudit.scanners.runtime_evidence import (
    has_host_repository_suite_runtime_authority,
    validated_scanner_run_copy_preserving_runtime_authority,
)

_HASH_A = "a" * 64
_HASH_B = "b" * 64
_HASH_C = "c" * 64
_HASH_D = "d" * 64
_FORK_SEED = "0x" + ("0" * 63) + "1"


@dataclass
class _SyntheticRuntimeAuthority:
    """Isolated test authority that cannot issue receipts trusted by production consumers."""

    _holder: dict[str, ScannerRun | None]
    invoke: Callable[..., ScannerRun]
    contains: Callable[[ScannerRun], bool]
    validated_copy: Callable[[ScannerRun], ScannerRun]
    annotate: Callable[[Path, ScannerRun], ScannerRun]

    @property
    def result(self) -> ScannerRun | None:
        return self._holder["result"]

    @result.setter
    def result(self, value: ScannerRun | None) -> None:
        self._holder["result"] = value


def _install_synthetic_runtime_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> _SyntheticRuntimeAuthority:
    existing = getattr(monkeypatch, "_mmaudit_synthetic_runtime_authority", None)
    if isinstance(existing, _SyntheticRuntimeAuthority):
        return existing

    holder: dict[str, ScannerRun | None] = {"result": None}

    def synthetic_foundry_repository_suite(
        self: FoundryForkScanner,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: ScannerIsolationBackend | None = None,
        expected_version: str | None = None,
        expected_sha256: str | None = None,
        workspace_custody_guard: list[object],
    ) -> ScannerRun:
        del (
            self,
            root,
            private_dir,
            timeout_seconds,
            backend,
            expected_version,
            expected_sha256,
            workspace_custody_guard,
        )
        result = holder["result"]
        if result is None:
            raise AssertionError("synthetic runtime authority has no configured result")
        return result

    invoke, contains, validated_copy, annotate = (
        runtime_evidence_module._build_foundry_runtime_authority(
            adapter_type=FoundryForkScanner,
            producer_body=synthetic_foundry_repository_suite,
            execution_evidence_resolver=lambda _backend: ExecutionEvidenceKind.REAL,
            attestation_resolver=lambda _backend: _HASH_C,
        )
    )
    authority = _SyntheticRuntimeAuthority(
        _holder=holder,
        invoke=invoke,
        contains=contains,
        validated_copy=validated_copy,
        annotate=annotate,
    )
    monkeypatch.setattr(
        monkeypatch,
        "_mmaudit_synthetic_runtime_authority",
        authority,
        raising=False,
    )
    monkeypatch.setattr(runner_module, "_invoke_builtin_foundry_adapter", authority.invoke)
    monkeypatch.setattr(
        pipeline_module,
        "validated_scanner_run_location_annotation_preserving_runtime_authority",
        authority.annotate,
    )
    monkeypatch.setattr(
        sys.modules[__name__],
        "has_host_repository_suite_runtime_authority",
        authority.contains,
    )
    monkeypatch.setattr(
        sys.modules[__name__],
        "validated_scanner_run_copy_preserving_runtime_authority",
        authority.validated_copy,
    )
    return authority


def _repository_suite_run(*, failed: bool = False, duration_seconds: float = 0.25) -> ScannerRun:
    descriptor = RepositorySuiteTestDescriptor.sealed(
        framework=RepositorySuiteFramework.FOUNDRY,
        project_root="contracts",
        path="contracts/test/Vault.t.sol",
        suite_name="VaultTest",
        test_name="testInvariant",
        source_sha256=_HASH_A,
        start_line=10,
        end_line=12,
    )
    selection = RepositorySuiteSelection.sealed(
        profile="explicit",
        repository_sha256=_HASH_B,
        repository_exclusion_path=".mmaudit",
        configuration_sha256=_HASH_C,
        candidate_file_count=1,
        candidate_test_count=1,
        selected_file_count=1,
        selected_test_count=1,
        omitted_file_count=0,
        omitted_test_count=0,
        limit_reached=False,
        tests=(descriptor,),
    )
    policy = RepositorySuiteExecutionPolicy.sealed(
        selection_sha256=selection.selection_sha256,
        selection_configuration_sha256=selection.configuration_sha256,
        chain_id=31_337,
        block_number=1_234,
        block_hash="0x" + _HASH_D,
        tool_version="1.3.2",
        tool_sha256=_HASH_A,
        compiler_version="solc 0.8.30",
        compiler_sha256=_HASH_D,
        isolation_backend="synthetic-isolation",
        isolation_attestation_sha256=_HASH_C,
        fuzz_seed=_FORK_SEED,
        fuzz_runs=256,
        invariant_runs=64,
        per_test_timeout_seconds=120,
        total_timeout_seconds=900,
        max_output_bytes_per_test=1_000_000,
        max_total_output_bytes=10_000_000,
    )
    execution = RepositoryTestExecution.sealed(
        selection_sha256=selection.selection_sha256,
        descriptor_sha256=descriptor.descriptor_sha256,
        framework=descriptor.framework,
        project_root=descriptor.project_root,
        path=descriptor.path,
        suite_name=descriptor.suite_name,
        test_name=descriptor.test_name,
        chain_id=policy.chain_id,
        block_number=policy.block_number,
        block_hash=policy.block_hash,
        fuzz_seed=policy.fuzz_seed,
        test_kind=RepositoryTestKind.UNIT,
        status=(
            RepositoryTestExecutionStatus.FAILED if failed else RepositoryTestExecutionStatus.PASSED
        ),
        terminal_detail="synthetic negative regression failure" if failed else None,
        duration_seconds=duration_seconds,
        command_sha256=_HASH_A,
        output_sha256=_HASH_B,
        output_bytes=123,
        machine_result_sha256=_HASH_C,
        process_exit_code=1 if failed else 0,
        machine_output_validated=True,
        execution_evidence=ExecutionEvidenceKind.REAL,
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
        isolation_backend=policy.isolation_backend,
        isolation_attestation_sha256=policy.isolation_attestation_sha256,
        compiler_version=policy.compiler_version,
        compiler_sha256=policy.compiler_sha256,
        execution_policy_sha256=policy.policy_sha256,
    )
    findings = (
        [
            ScannerFinding(
                scanner="foundry_fork",
                rule_id="repository-fork-test-failure",
                title="Synthetic repository regression failed",
                severity=Severity.HIGH,
                message="Synthetic negative regression failure",
                locations=[
                    Location(
                        path=descriptor.path,
                        start_line=descriptor.start_line,
                        end_line=descriptor.end_line,
                        symbol=descriptor.test_name,
                        content_hash=descriptor.source_sha256,
                    )
                ],
                metadata={
                    "repository_test_execution_sha256": execution.execution_sha256,
                },
                evidence_strength=EvidenceStrength.DETERMINISTIC_ANALYZER,
                fingerprint=_HASH_D,
            )
        ]
        if failed
        else []
    )
    observed_at = datetime(2026, 1, 1, tzinfo=UTC)
    provisional = ScannerRun(
        scanner="foundry_fork",
        status=ScannerStatus.SUCCESS,
        execution_evidence=ExecutionEvidenceKind.REAL,
        version=policy.tool_version,
        executable_sha256=policy.tool_sha256,
        command=["forge", "test", "--offline", "--json"],
        started_at=observed_at,
        finished_at=observed_at,
        duration_seconds=duration_seconds,
        findings=findings,
        raw_output_path="private/scanners/foundry.json",
        raw_output_sha256=_HASH_B,
        raw_output_bytes=123,
        process_exit_code=1 if failed else 0,
        isolation_backend=policy.isolation_backend,
        isolation_attestation_sha256=policy.isolation_attestation_sha256,
        machine_output_validated=True,
        foundry_summary=FoundryTestExecutionSummary(
            unit_tests=1,
            fuzz_tests=0,
            invariant_tests=0,
            passed_tests=0 if failed else 1,
            failed_tests=1 if failed else 0,
            skipped_tests=0,
            fuzz_cases=0,
            invariant_runs=0,
            invariant_calls=0,
        ),
        repository_suite_selection=selection,
        repository_suite_execution_policy=policy,
        repository_test_executions=[execution],
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
    )
    return ScannerRun.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "execution_observation_sha256": (provisional.expected_execution_observation_sha256()),
        }
    )


class _NoopIsolation:
    name = "synthetic-isolation"

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del workspace, private_dir, rpc_port
        return command


class _SelfAssertedRealIsolation(_NoopIsolation):
    name = "sandbox-exec"
    execution_evidence = ExecutionEvidenceKind.REAL


class _ImpostorFoundryAdapter(ScannerAdapter):
    name = "foundry_fork"
    executable = "forge"

    def __init__(self, result: ScannerRun) -> None:
        self._result = result
        self.calls = 0

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        del root, private_dir
        return []

    def parse(
        self,
        root: Path,
        stdout: str,
        private_dir: Path,
    ) -> list[ScannerFinding]:
        del root, stdout, private_dir
        return []

    def run(
        self,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: ScannerIsolationBackend | None = None,
        expected_version: str | None = None,
        expected_sha256: str | None = None,
        expected_repository_sha256: str | None = None,
        audited_relative_paths: Sequence[str] = (),
        repository_exclusion_root: Path | None = None,
        allow_custom_repository_exclusion: bool = False,
    ) -> ScannerRun:
        self.calls += 1
        del (
            root,
            private_dir,
            timeout_seconds,
            backend,
            expected_version,
            expected_sha256,
            expected_repository_sha256,
            audited_relative_paths,
            repository_exclusion_root,
            allow_custom_repository_exclusion,
        )
        return self._result


def test_self_authored_and_serialized_runs_lack_runtime_authority() -> None:
    self_authored = _repository_suite_run()
    serialized_copy = ScannerRun.model_validate_json(self_authored.model_dump_json())

    assert not has_host_repository_suite_runtime_authority(self_authored)
    assert not has_host_repository_suite_runtime_authority(serialized_copy)


def test_direct_schema_helpers_cannot_mint_runtime_authority() -> None:
    untrusted = _repository_suite_run()
    untrusted_copy = validated_scanner_run_copy_preserving_runtime_authority(untrusted)

    assert not hasattr(runtime_evidence_module, "attest_host_repository_suite_run")
    assert not hasattr(
        runtime_evidence_module,
        "validated_scanner_run_derivation_preserving_runtime_authority",
    )
    assert not hasattr(runtime_evidence_module, "_derive_runtime_authority")
    assert untrusted_copy is not untrusted
    assert not has_host_repository_suite_runtime_authority(untrusted_copy)


async def _synthetic_runner_authority(
    *,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    run: ScannerRun,
) -> tuple[ScannerRun, ScannerRunner]:
    """Simulate the trusted issuance path; this is not a real isolation integration."""

    authority = _install_synthetic_runtime_authority(monkeypatch)
    authority.result = run
    config = config_factory(scanners={"foundry_fork": {"enabled": True, "required": False}})
    runner = ScannerRunner(
        config,
        adapters={"foundry_fork": FoundryForkScanner(config.smart_contracts)},
        backend=_NoopIsolation(),
    )
    runs = await runner.run_all(
        tmp_path,
        tmp_path / ".mmaudit",
        audited_relative_paths=(),
        expected_repository_sha256=scanner_workspace_sha256(tmp_path),
    )
    assert len(runs) == 1
    return runs[0], runner


@pytest.mark.asyncio
async def test_synthetic_exact_runner_path_preserves_authority_for_validated_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    trusted, runner = await _synthetic_runner_authority(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        config_factory=config_factory,
        run=_repository_suite_run(),
    )
    trusted_copy = validated_scanner_run_copy_preserving_runtime_authority(trusted)

    assert runner.backend is not None
    assert trusted_copy is not trusted
    assert has_host_repository_suite_runtime_authority(trusted)
    assert has_host_repository_suite_runtime_authority(trusted_copy)


@pytest.mark.asyncio
async def test_rebinding_foundry_run_cannot_mint_runtime_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    caller_authored = _repository_suite_run()
    rebound_called = False
    rebound_body_called = False
    rebound_evidence_called = False
    rebound_attestation_called = False

    def rebound_foundry_run(
        self: FoundryForkScanner,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: ScannerIsolationBackend | None = None,
        expected_version: str | None = None,
        expected_sha256: str | None = None,
    ) -> ScannerRun:
        nonlocal rebound_called
        del (
            self,
            root,
            private_dir,
            timeout_seconds,
            backend,
            expected_version,
            expected_sha256,
        )
        rebound_called = True
        return caller_authored

    def rebound_foundry_repository_suite(
        self: FoundryForkScanner,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: ScannerIsolationBackend | None = None,
        expected_version: str | None = None,
        expected_sha256: str | None = None,
        workspace_custody_guard: list[object],
    ) -> ScannerRun:
        nonlocal rebound_body_called
        del (
            self,
            root,
            private_dir,
            timeout_seconds,
            backend,
            expected_version,
            expected_sha256,
            workspace_custody_guard,
        )
        rebound_body_called = True
        return caller_authored

    def rebound_execution_evidence(_backend: object | None) -> ExecutionEvidenceKind:
        nonlocal rebound_evidence_called
        rebound_evidence_called = True
        return ExecutionEvidenceKind.REAL

    def rebound_attestation(_backend: object | None) -> str:
        nonlocal rebound_attestation_called
        rebound_attestation_called = True
        return _HASH_C

    monkeypatch.setattr(FoundryForkScanner, "run", rebound_foundry_run)
    monkeypatch.setattr(
        FoundryForkScanner,
        "_run_repository_suite",
        rebound_foundry_repository_suite,
    )
    monkeypatch.setattr(
        runtime_evidence_module,
        "isolation_execution_evidence",
        rebound_execution_evidence,
    )
    monkeypatch.setattr(
        runtime_evidence_module,
        "isolation_attestation_sha256",
        rebound_attestation,
    )
    config = config_factory(scanners={"foundry_fork": {"enabled": True, "required": False}})
    runner = ScannerRunner(
        config,
        adapters={"foundry_fork": FoundryForkScanner(config.smart_contracts)},
        backend=_NoopIsolation(),
    )

    runs = await runner.run_all(
        tmp_path,
        tmp_path / ".mmaudit",
        audited_relative_paths=(),
        expected_repository_sha256=scanner_workspace_sha256(tmp_path),
    )

    assert not rebound_called
    assert not rebound_body_called
    assert not rebound_evidence_called
    assert not rebound_attestation_called
    assert runs != [caller_authored]
    assert all(not has_host_repository_suite_runtime_authority(run) for run in runs)


@pytest.mark.asyncio
async def test_synthetic_location_annotation_is_the_only_finding_projection_with_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    trusted, runner = await _synthetic_runner_authority(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        config_factory=config_factory,
        run=_repository_suite_run(failed=True),
    )

    annotated = _annotate_scanner_locations(tmp_path, trusted)

    assert runner.backend is not None
    assert annotated is not trusted
    assert annotated.findings[0].metadata["location_validation"]
    assert annotated.execution_observation_sha256_is_valid()
    assert has_host_repository_suite_runtime_authority(annotated)


@pytest.mark.asyncio
async def test_caller_crafted_location_metadata_cannot_receive_runtime_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    trusted, runner = await _synthetic_runner_authority(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        config_factory=config_factory,
        run=_repository_suite_run(failed=True),
    )
    finding = trusted.findings[0]
    crafted_finding = finding.model_copy(
        update={
            "metadata": {
                **finding.metadata,
                "location_validation": [{"valid": True, "caller_authored": True}],
            }
        }
    )
    provisional = trusted.model_copy(
        update={
            "findings": [crafted_finding],
            "execution_observation_sha256": None,
        }
    )
    crafted = ScannerRun.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "execution_observation_sha256": (provisional.expected_execution_observation_sha256()),
        }
    )
    normalized = validated_scanner_run_copy_preserving_runtime_authority(crafted)

    assert runner.backend is not None
    assert has_host_repository_suite_runtime_authority(trusted)
    assert not has_host_repository_suite_runtime_authority(crafted)
    assert not has_host_repository_suite_runtime_authority(normalized)


@pytest.mark.asyncio
async def test_authority_is_bound_to_exact_run_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    trusted, runner = await _synthetic_runner_authority(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        config_factory=config_factory,
        run=_repository_suite_run(),
    )
    assert has_host_repository_suite_runtime_authority(trusted)

    trusted.duration_seconds += 1

    assert runner.backend is not None
    assert not has_host_repository_suite_runtime_authority(trusted)


@pytest.mark.asyncio
async def test_reconstructed_same_named_backend_cannot_inherit_runtime_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    trusted, runner = await _synthetic_runner_authority(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        config_factory=config_factory,
        run=_repository_suite_run(),
    )
    assert has_host_repository_suite_runtime_authority(trusted)

    runner.backend = _NoopIsolation()
    gc.collect()

    assert not has_host_repository_suite_runtime_authority(trusted)


@pytest.mark.asyncio
async def test_exact_foundry_result_without_live_sealed_backend_has_no_authority(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory(scanners={"foundry_fork": {"enabled": True, "required": False}})
    runner = ScannerRunner(
        config,
        adapters={"foundry_fork": FoundryForkScanner(config.smart_contracts)},
        backend=_SelfAssertedRealIsolation(),
    )

    runs = await runner.run_all(
        tmp_path,
        tmp_path / ".mmaudit",
        audited_relative_paths=(),
        expected_repository_sha256=scanner_workspace_sha256(tmp_path),
    )

    assert len(runs) == 1
    assert not has_host_repository_suite_runtime_authority(runs[0])


@pytest.mark.asyncio
async def test_scanner_runner_rejects_named_impostor_adapter_authority(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    self_authored = _repository_suite_run()
    config = config_factory(scanners={"foundry_fork": {"enabled": True, "required": False}})
    runner = ScannerRunner(
        config,
        adapters={"foundry_fork": _ImpostorFoundryAdapter(self_authored)},
        backend=_NoopIsolation(),
    )

    runs = await runner.run_all(
        tmp_path,
        tmp_path / ".mmaudit",
        audited_relative_paths=(),
        expected_repository_sha256=scanner_workspace_sha256(tmp_path),
    )

    assert runs == [self_authored]
    assert not has_host_repository_suite_runtime_authority(runs[0])


@pytest.mark.asyncio
async def test_scanner_runner_rejects_excluded_audited_source_before_adapter_task(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    source = tmp_path / "vendor" / "ExplicitlyAudited.sol"
    source.parent.mkdir()
    source.write_text("contract ExplicitlyAudited {}\n", encoding="utf-8")
    adapter = _ImpostorFoundryAdapter(_repository_suite_run())
    config = config_factory(scanners={"foundry_fork": {"enabled": True, "required": False}})
    runner = ScannerRunner(
        config,
        adapters={"foundry_fork": adapter},
        backend=_NoopIsolation(),
    )

    with pytest.raises(
        ScannerSourceIntegrityError,
        match="scanner execution could not acquire frozen audited source custody",
    ):
        await runner.run_all(
            tmp_path,
            tmp_path / ".mmaudit",
            audited_relative_paths=("vendor/ExplicitlyAudited.sol",),
            expected_repository_sha256=scanner_workspace_sha256(tmp_path),
        )

    assert adapter.calls == 0


def _finalized_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    scanner_status: ScannerStatus,
    execution_status: RepositoryTestExecutionStatus,
    cleanup_error: str | None = None,
    partial_selection: bool = False,
    process_started: bool = True,
    upstream_integrity_valid: bool = True,
) -> ScannerRun:
    base = _repository_suite_run()
    base_selection = base.repository_suite_selection
    assert base_selection is not None
    selection = base_selection
    if partial_selection:
        descriptor = RepositorySuiteTestDescriptor.sealed(
            framework=RepositorySuiteFramework.FOUNDRY,
            project_root="contracts",
            path="contracts/test/Vault.t.sol",
            suite_name="VaultTest",
            test_name="testOtherInvariant",
            source_sha256=_HASH_A,
            start_line=14,
            end_line=16,
        )
        selection = RepositorySuiteSelection.sealed(
            profile="explicit",
            repository_sha256=_HASH_B,
            repository_exclusion_path=".mmaudit",
            configuration_sha256=_HASH_C,
            candidate_file_count=1,
            candidate_test_count=2,
            selected_file_count=1,
            selected_test_count=2,
            omitted_file_count=0,
            omitted_test_count=0,
            limit_reached=False,
            tests=tuple(
                sorted((*base_selection.tests, descriptor), key=lambda item: item.canonical_key)
            ),
        )
    base_policy = base.repository_suite_execution_policy
    assert base_policy is not None
    policy = RepositorySuiteExecutionPolicy.sealed(
        selection_sha256=selection.selection_sha256,
        selection_configuration_sha256=selection.configuration_sha256,
        chain_id=base_policy.chain_id,
        block_number=base_policy.block_number,
        block_hash=base_policy.block_hash,
        tool_version=base_policy.tool_version,
        tool_sha256=base_policy.tool_sha256,
        compiler_version=base_policy.compiler_version,
        compiler_sha256=base_policy.compiler_sha256,
        isolation_backend=base_policy.isolation_backend,
        isolation_attestation_sha256=base_policy.isolation_attestation_sha256,
        fuzz_seed=base_policy.fuzz_seed,
        fuzz_runs=base_policy.fuzz_runs,
        invariant_runs=base_policy.invariant_runs,
        per_test_timeout_seconds=base_policy.per_test_timeout_seconds,
        total_timeout_seconds=base_policy.total_timeout_seconds,
        max_output_bytes_per_test=base_policy.max_output_bytes_per_test,
        max_total_output_bytes=base_policy.max_total_output_bytes,
    )
    observation = _FoundryTestObservation(
        descriptor=selection.tests[0],
        status=execution_status,
        terminal_detail=f"synthetic {execution_status.value} attempt",
        duration_seconds=0.25,
        command_sha256=_HASH_A,
        output_sha256=_HASH_B,
        output_bytes=123,
        process_exit_code=None,
        machine_output_validated=False,
        process_started=process_started,
    )
    monkeypatch.setattr(
        foundry_module,
        "isolation_execution_evidence",
        lambda _backend: ExecutionEvidenceKind.REAL,
    )
    monkeypatch.setattr(
        foundry_module,
        "isolation_attestation_sha256",
        lambda _backend: _HASH_C,
    )
    monkeypatch.setattr(
        foundry_module,
        "_cleanup_error",
        lambda _backend, _private_dir: cleanup_error,
    )
    private_dir = tmp_path / f"private-{scanner_status.value}-{execution_status.value}"
    private_dir.mkdir()
    return _finalize_foundry_repository_suite(
        root=tmp_path,
        private_dir=private_dir,
        backend=_NoopIsolation(),
        start=datetime.now(UTC),
        monotonic_start=time.monotonic(),
        deadline=time.monotonic() + 10,
        total_timeout_seconds=10,
        status=scanner_status,
        error=f"synthetic {execution_status.value} suite status",
        selection=selection,
        observations=[observation],
        fork=PinnedForkObservation(
            chain_id=policy.chain_id,
            block_number=policy.block_number,
            block_hash=policy.block_hash,
        ),
        executable_sha256=policy.tool_sha256,
        version=policy.tool_version,
        compiler_version=policy.compiler_version,
        compiler_sha256=policy.compiler_sha256,
        execution_policy=policy,
        inventory=None,
        post_inventory=None,
        fuzz_seed=policy.fuzz_seed,
        upstream_integrity_valid=upstream_integrity_valid,
    )


@pytest.mark.parametrize(
    ("scanner_status", "execution_status"),
    [
        (ScannerStatus.TIMED_OUT, RepositoryTestExecutionStatus.TIMED_OUT),
        (ScannerStatus.FAILED, RepositoryTestExecutionStatus.INVALID_OUTPUT),
    ],
)
def test_synthetic_finalizer_labels_complete_invoked_attempt_status_honestly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scanner_status: ScannerStatus,
    execution_status: RepositoryTestExecutionStatus,
) -> None:
    """Unit simulation of finalization; this is not a real Foundry integration."""

    run = _finalized_attempt(
        tmp_path,
        monkeypatch,
        scanner_status=scanner_status,
        execution_status=execution_status,
    )

    assert run.status is scanner_status
    assert run.execution_evidence is ExecutionEvidenceKind.REAL
    assert run.repository_code_execution is RepositoryCodeExecutionState.ISOLATED
    assert run.repository_test_executions[0].status is execution_status
    assert run.repository_test_executions[0].execution_evidence is ExecutionEvidenceKind.REAL
    assert not has_host_repository_suite_runtime_authority(run)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scanner_status", "execution_status"),
    [
        (ScannerStatus.TIMED_OUT, RepositoryTestExecutionStatus.TIMED_OUT),
        (ScannerStatus.FAILED, RepositoryTestExecutionStatus.INVALID_OUTPUT),
    ],
)
async def test_synthetic_runner_issues_authority_for_complete_interrupted_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    scanner_status: ScannerStatus,
    execution_status: RepositoryTestExecutionStatus,
) -> None:
    """Unit simulation of issuance; this is not a real isolation integration."""

    finalized = _finalized_attempt(
        tmp_path,
        monkeypatch,
        scanner_status=scanner_status,
        execution_status=execution_status,
    )
    trusted, runner = await _synthetic_runner_authority(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        config_factory=config_factory,
        run=finalized,
    )

    assert runner.backend is not None
    assert trusted.status is scanner_status
    assert trusted.repository_test_executions[0].status is execution_status
    assert has_host_repository_suite_runtime_authority(trusted)


def test_synthetic_finalizer_never_marks_cleanup_failure_real(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _finalized_attempt(
        tmp_path,
        monkeypatch,
        scanner_status=ScannerStatus.FAILED,
        execution_status=RepositoryTestExecutionStatus.INVALID_OUTPUT,
        cleanup_error="isolation cleanup verification failed: synthetic",
    )

    assert run.status is ScannerStatus.FAILED
    assert run.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert all(
        execution.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
        for execution in run.repository_test_executions
    )


def test_synthetic_finalizer_never_marks_process_launch_failure_real(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _finalized_attempt(
        tmp_path,
        monkeypatch,
        scanner_status=ScannerStatus.FAILED,
        execution_status=RepositoryTestExecutionStatus.INVALID_OUTPUT,
        process_started=False,
    )

    assert run.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert run.repository_test_executions[0].execution_evidence is ExecutionEvidenceKind.UNVERIFIED


def test_synthetic_finalizer_never_marks_inventory_integrity_failure_real(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _finalized_attempt(
        tmp_path,
        monkeypatch,
        scanner_status=ScannerStatus.FAILED,
        execution_status=RepositoryTestExecutionStatus.INVALID_OUTPUT,
        upstream_integrity_valid=False,
    )

    assert run.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert run.repository_test_executions[0].execution_evidence is ExecutionEvidenceKind.UNVERIFIED


def test_synthetic_finalizer_never_marks_fallback_observation_real(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _finalized_attempt(
        tmp_path,
        monkeypatch,
        scanner_status=ScannerStatus.TIMED_OUT,
        execution_status=RepositoryTestExecutionStatus.TIMED_OUT,
        partial_selection=True,
    )

    assert run.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert [execution.status for execution in run.repository_test_executions] == [
        RepositoryTestExecutionStatus.TIMED_OUT,
        RepositoryTestExecutionStatus.UNAVAILABLE,
    ]
    assert all(
        execution.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
        for execution in run.repository_test_executions
    )
