"""Fixed, provider-free local command execution for release-gate evidence."""

from __future__ import annotations

import hashlib
import importlib.metadata
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, Literal

from pydantic import Field, field_validator, model_validator

import mmaudit
from mmaudit.models.schemas import ExecutionEvidenceKind, StrictModel
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release import ReleaseGateId, ReleaseGateStatus
from mmaudit.release_gates import (
    ReleaseGateEvidenceBundle,
    ReleaseGateFixedPlan,
    ReleaseGatePlanExecutor,
    ReleaseGateReceipt,
    build_release_gate_receipt,
    get_release_gate_child_environment_contract,
    get_release_gate_fixed_plan,
    get_release_gate_network_guard_source,
)
from mmaudit.release_io import (
    create_evidence_file_binding,
    read_json_evidence,
    revalidate_evidence_file_binding,
    write_json_evidence,
)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_CAPTURE_BYTES = 4 * 1024 * 1024
_MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
_MAX_DISTRIBUTION_FILE_BYTES = 256 * 1024 * 1024
_MAX_DISTRIBUTION_TOTAL_BYTES = 1024 * 1024 * 1024
_MAX_DISTRIBUTION_FILES = 10_000
_MAX_JUNIT_BYTES = 32 * 1024 * 1024
_MAX_JUNIT_TESTS = 10_000_000
_LOCAL_GATE_IDS = frozenset(
    {
        ReleaseGateId.RUFF_FORMAT,
        ReleaseGateId.RUFF_CHECK,
        ReleaseGateId.MYPY,
        ReleaseGateId.PYTEST,
    }
)


class JUnitValidationStatus(StrEnum):
    """Typed state for the fixed pytest JUnit artifact."""

    NOT_APPLICABLE = "not_applicable"
    VALID = "valid"
    EMPTY = "empty"
    INVALID = "invalid"


class PytestJUnitCounts(StrictModel):
    """Nonempty bounded aggregate parsed from pytest's local JUnit XML."""

    tests: int = Field(ge=1, le=_MAX_JUNIT_TESTS)
    passed: int = Field(ge=0, le=_MAX_JUNIT_TESTS)
    failures: int = Field(ge=0, le=_MAX_JUNIT_TESTS)
    errors: int = Field(ge=0, le=_MAX_JUNIT_TESTS)
    skipped: int = Field(ge=0, le=_MAX_JUNIT_TESTS)

    @model_validator(mode="after")
    def counts_are_consistent(self) -> PytestJUnitCounts:
        if self.tests != self.passed + self.failures + self.errors + self.skipped:
            raise ValueError("pytest JUnit counts are inconsistent")
        return self


class LocalReleaseGateResultPayload(StrictModel):
    """Canonical non-secret runtime result written before receipt construction."""

    schema_version: Literal["1.0"]
    generated_by: Literal["mmaudit"]
    gate_id: ReleaseGateId
    candidate_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    run_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    plan: ReleaseGateFixedPlan
    status: ReleaseGateStatus
    started_at: datetime
    ended_at: datetime
    argv: tuple[str, ...] = Field(min_length=3, max_length=16)
    argv_sha256: str = Field(pattern=_SHA256_PATTERN)
    tool_name: str = Field(min_length=1, max_length=100)
    tool_version: str = Field(min_length=1, max_length=200)
    python_executable_sha256: str = Field(pattern=_SHA256_PATTERN)
    tool_distribution_sha256: str = Field(pattern=_SHA256_PATTERN)
    execution_evidence: Literal[ExecutionEvidenceKind.REAL]
    process_exit_code: int | None = Field(default=None, ge=-255, le=255)
    timed_out: bool
    timeout_seconds: int = Field(ge=1, le=3_600)
    max_output_bytes: int = Field(ge=1, le=_MAX_CAPTURE_BYTES)
    stdout_size: int = Field(ge=0, le=_MAX_CAPTURE_BYTES)
    stdout_sha256: str = Field(pattern=_SHA256_PATTERN)
    stderr_size: int = Field(ge=0, le=_MAX_CAPTURE_BYTES)
    stderr_sha256: str = Field(pattern=_SHA256_PATTERN)
    child_environment_keys: tuple[str, ...] = Field(min_length=1, max_length=100)
    child_environment_contract: dict[str, str] = Field(min_length=1, max_length=100)
    child_environment_contract_sha256: str = Field(pattern=_SHA256_PATTERN)
    network_guard_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider_access: Literal["disabled"]
    junit_status: JUnitValidationStatus
    junit_counts: PytestJUnitCounts | None
    junit_binding: ManifestFileBinding | None

    @field_validator("started_at", "ended_at")
    @classmethod
    def timestamps_are_utc_whole_seconds(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
            raise ValueError("local release-gate timestamps must be UTC whole seconds")
        return value

    @field_validator("argv", "child_environment_keys")
    @classmethod
    def string_tuples_are_literal(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            not item
            or len(item) > 4_096
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
            for item in value
        ):
            raise ValueError("local release-gate string lists must contain bounded literals")
        return value

    @model_validator(mode="after")
    def result_is_consistent(self) -> LocalReleaseGateResultPayload:
        if self.gate_id not in _LOCAL_GATE_IDS:
            raise ValueError("local release result uses an unsupported gate")
        if self.plan != get_release_gate_fixed_plan(self.gate_id):
            raise ValueError("local release result does not use the canonical fixed plan")
        if self.ended_at < self.started_at:
            raise ValueError("local release result end time precedes its start time")
        if self.argv_sha256 != canonical_sha256(list(self.argv)):
            raise ValueError("local release result argv hash is inconsistent")
        if self.timeout_seconds != self.plan.timeout_seconds:
            raise ValueError("local release result timeout differs from its fixed plan")
        if self.max_output_bytes != self.plan.max_output_bytes:
            raise ValueError("local release output bound differs from its fixed plan")
        expected_status = (
            ReleaseGateStatus.FAILED
            if self.timed_out or self.process_exit_code != 0
            else ReleaseGateStatus.PASSED
        )
        if self.status is not expected_status:
            raise ValueError("local release result status is inconsistent")
        if self.timed_out and self.process_exit_code == 0:
            raise ValueError("timed-out local release execution cannot report exit zero")
        if self.child_environment_keys != tuple(sorted(set(self.child_environment_keys))):
            raise ValueError("local release environment keys must be unique and sorted")
        if any(
            key.upper().startswith(("OPENROUTER", "MMAUDIT")) for key in self.child_environment_keys
        ):
            raise ValueError("local release environment contains a provider control variable")
        expected_environment_contract = get_release_gate_child_environment_contract(self.gate_id)
        if (
            self.child_environment_contract != expected_environment_contract
            or self.child_environment_keys != tuple(sorted(expected_environment_contract))
            or self.child_environment_contract_sha256
            != canonical_sha256(expected_environment_contract)
            or self.plan.child_environment_contract_sha256 != self.child_environment_contract_sha256
        ):
            raise ValueError("local release child environment contract is inconsistent")
        expected_guard_sha256 = hashlib.sha256(
            get_release_gate_network_guard_source(self.gate_id)
        ).hexdigest()
        if (
            self.network_guard_sha256 != expected_guard_sha256
            or self.plan.network_guard_sha256 != expected_guard_sha256
        ):
            raise ValueError("local release network guard differs from its fixed plan")
        if self.tool_name != self.plan.module:
            raise ValueError("local release tool name differs from its fixed plan")

        if self.gate_id is ReleaseGateId.PYTEST:
            if self.junit_binding is None:
                raise ValueError("pytest release evidence requires a JUnit artifact binding")
            if self.status is ReleaseGateStatus.PASSED and (
                self.junit_status is not JUnitValidationStatus.VALID
                or self.junit_counts is None
                or self.junit_counts.failures
                or self.junit_counts.errors
            ):
                raise ValueError("passed pytest release evidence requires valid nonempty JUnit")
            if self.junit_status is JUnitValidationStatus.VALID and self.junit_counts is None:
                raise ValueError("valid pytest JUnit evidence requires parsed counts")
            if (
                self.junit_status is not JUnitValidationStatus.VALID
                and self.junit_counts is not None
            ):
                raise ValueError("invalid pytest JUnit evidence cannot claim parsed counts")
        elif (
            self.junit_status is not JUnitValidationStatus.NOT_APPLICABLE
            or self.junit_counts is not None
            or self.junit_binding is not None
        ):
            raise ValueError("non-pytest local release evidence cannot claim JUnit results")
        return self


class LocalReleaseGateResult(LocalReleaseGateResultPayload):
    """Self-hashed runtime result that carries candidate, run, and plan provenance."""

    result_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def result_hash_is_consistent(self) -> LocalReleaseGateResult:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"result_sha256"}))
        if self.result_sha256 != expected:
            raise ValueError("local release-gate result hash is inconsistent")
        return self


@dataclass(frozen=True, slots=True)
class _ExecutableObservation:
    declared_path: str
    resolved_path: str
    sha256: str
    identity: tuple[int, int, int, int, int, int, int]
    declared_identity: tuple[int, int, int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class _DistributionObservation:
    name: str
    version: str
    inventory_sha256: str


@dataclass(frozen=True, slots=True)
class _ProcessOutcome:
    returncode: int
    timed_out: bool
    stdout: bytes
    stderr: bytes


def execute_local_release_gate(
    *,
    gate_id: ReleaseGateId,
    repository_root: Path,
    evidence_root: Path,
    candidate_observation_sha256: str,
    run_binding_sha256: str,
) -> ReleaseGateReceipt:
    """Execute one of four closed local plans and return its evidence-bound receipt."""

    if not isinstance(gate_id, ReleaseGateId) or gate_id not in _LOCAL_GATE_IDS:
        raise ValueError("only fixed local release gates may execute")
    if os.name == "nt":
        raise ValueError("fixed local release gates require POSIX process-group containment")
    _require_sha256(candidate_observation_sha256, label="candidate observation")
    _require_sha256(run_binding_sha256, label="run binding")
    root, repository_identity = _require_executing_repository_root(repository_root)
    evidence = _require_unlinked_directory(evidence_root, label="release evidence root")
    plan = get_release_gate_fixed_plan(gate_id)
    if (
        plan.executor is not ReleaseGatePlanExecutor.FIXED_LOCAL_PYTHON_MODULE
        or plan.module is None
        or plan.timeout_seconds is None
    ):
        raise ValueError("release gate has no fixed local execution plan")
    _require_fresh_destination(evidence / plan.result_artifact_path)
    if plan.supplemental_artifact_path is not None:
        _require_fresh_destination(evidence / plan.supplemental_artifact_path)

    executable_before = _observe_executing_python()
    tool_before = _observe_tool_distribution(plan.module)
    argv = _materialize_argv(plan, evidence_root=evidence)
    started_at = _utc_now()
    junit_descriptor: int | None = None
    junit_identity: tuple[int, int] | None = None
    try:
        if plan.supplemental_artifact_path is not None:
            junit_descriptor, junit_identity = _create_fresh_private_file(
                evidence / plan.supplemental_artifact_path
            )
        with tempfile.TemporaryDirectory(
            prefix=".mmaudit-release-runtime-",
            dir=evidence,
        ) as runtime_name:
            runtime_root = Path(runtime_name)
            network_guard_root = _install_network_guard(runtime_root, gate_id=gate_id)
            environment = _fixed_child_environment(
                runtime_root,
                network_guard_root=network_guard_root,
                gate_id=gate_id,
            )
            environment_contract = get_release_gate_child_environment_contract(gate_id)
            outcome = _execute_fixed_process(
                argv=argv,
                repository_root=root,
                runtime_root=runtime_root,
                environment=environment,
                timeout_seconds=plan.timeout_seconds,
            )
        ended_at = _utc_now()

        executable_after = _observe_executing_python()
        tool_after = _observe_tool_distribution(plan.module)
        final_root, final_repository_identity = _require_executing_repository_root(repository_root)
        if (
            final_root != root
            or final_repository_identity != repository_identity
            or executable_after != executable_before
            or tool_after != tool_before
        ):
            raise ValueError("local release toolchain or repository changed during execution")

        junit_status, junit_counts, junit_binding = _observe_junit(
            gate_id=gate_id,
            evidence_root=evidence,
            relative_path=plan.supplemental_artifact_path,
            descriptor=junit_descriptor,
            created_identity=junit_identity,
        )
        status = (
            ReleaseGateStatus.FAILED
            if outcome.timed_out or outcome.returncode != 0
            else ReleaseGateStatus.PASSED
        )
        if (
            gate_id is ReleaseGateId.PYTEST
            and status is ReleaseGateStatus.PASSED
            and (
                junit_status is not JUnitValidationStatus.VALID
                or junit_counts is None
                or junit_counts.failures
                or junit_counts.errors
            )
        ):
            raise ValueError("successful pytest command lacks valid nonempty JUnit evidence")

        result = _build_result(
            gate_id=gate_id,
            candidate_observation_sha256=candidate_observation_sha256,
            run_binding_sha256=run_binding_sha256,
            plan=plan,
            status=status,
            started_at=started_at,
            ended_at=ended_at,
            argv=argv,
            tool_version=tool_before.version,
            python_executable_sha256=executable_before.sha256,
            tool_distribution_sha256=tool_before.inventory_sha256,
            outcome=outcome,
            environment=environment,
            environment_contract=environment_contract,
            junit_status=junit_status,
            junit_counts=junit_counts,
            junit_binding=junit_binding,
        )
        result_binding = write_json_evidence(
            evidence_root=evidence,
            relative_path=plan.result_artifact_path,
            value=result,
            max_bytes=_MAX_CAPTURE_BYTES,
        )
        artifact_bindings = sorted(
            [
                result_binding,
                *([junit_binding] if junit_binding is not None else []),
            ],
            key=lambda binding: binding.path,
        )
        receipt = build_release_gate_receipt(
            gate_id=gate_id,
            candidate_observation_sha256=candidate_observation_sha256,
            run_binding_sha256=run_binding_sha256,
            fixed_plan_sha256=plan.fixed_plan_sha256,
            started_at=started_at,
            ended_at=ended_at,
            argv=argv,
            tool_name=plan.module,
            tool_version=tool_before.version,
            tool_executable_sha256=executable_before.sha256,
            tool_distribution_sha256=tool_before.inventory_sha256,
            execution_evidence=ExecutionEvidenceKind.REAL,
            exit_code=None if outcome.timed_out else outcome.returncode,
            timed_out=outcome.timed_out,
            stdout=outcome.stdout,
            stderr=outcome.stderr,
            summary=_result_summary(gate_id, status, junit_counts),
            prerequisite_blocker=None,
            artifact_bindings=artifact_bindings,
        )
        validate_local_release_gate_result_artifact(
            evidence_root=evidence,
            binding=result_binding,
            expected_candidate_observation_sha256=candidate_observation_sha256,
            expected_run_binding_sha256=run_binding_sha256,
            expected_receipt=receipt,
        )
        return receipt
    finally:
        if junit_descriptor is not None:
            os.close(junit_descriptor)


def validate_local_release_gate_result_artifact(
    *,
    evidence_root: Path,
    binding: ManifestFileBinding,
    expected_candidate_observation_sha256: str,
    expected_run_binding_sha256: str,
    expected_receipt: ReleaseGateReceipt,
) -> LocalReleaseGateResult:
    """Validate one typed result artifact and reconcile every receipt projection."""

    expected_binding = revalidate_evidence_file_binding(
        evidence_root=evidence_root,
        binding=binding,
        max_bytes=_MAX_CAPTURE_BYTES,
    )
    observation = read_json_evidence(
        evidence_root=evidence_root,
        relative_path=expected_binding.path,
        max_bytes=_MAX_CAPTURE_BYTES,
    )
    if observation.binding != expected_binding:
        raise ValueError("local release result differs from its declared artifact binding")
    result = LocalReleaseGateResult.model_validate(observation.value)
    receipt = ReleaseGateReceipt.model_validate(expected_receipt.model_dump(mode="json"))
    plan = get_release_gate_fixed_plan(receipt.gate_id)
    expected_result_path = plan.result_artifact_path
    expected_argv = _materialize_argv(
        plan,
        evidence_root=_require_unlinked_directory(
            evidence_root,
            label="release evidence root",
        ),
    )
    current_executable = _observe_executing_python()
    current_tool = _observe_tool_distribution(plan.module or "")
    receipt_bindings = {item.path: item for item in receipt.artifact_bindings}
    if (
        expected_binding.path != expected_result_path
        or receipt_bindings.get(expected_result_path) != expected_binding
        or result.candidate_observation_sha256 != expected_candidate_observation_sha256
        or result.run_binding_sha256 != expected_run_binding_sha256
        or receipt.candidate_observation_sha256 != expected_candidate_observation_sha256
        or receipt.run_binding_sha256 != expected_run_binding_sha256
        or result.gate_id is not receipt.gate_id
        or result.plan.fixed_plan_sha256 != receipt.fixed_plan_sha256
        or result.status is not receipt.status
        or result.started_at != receipt.started_at
        or result.ended_at != receipt.ended_at
        or result.argv != receipt.argv
        or result.argv != expected_argv
        or result.argv_sha256 != receipt.argv_sha256
        or result.tool_name != receipt.tool_name
        or result.tool_name != plan.module
        or result.tool_version != receipt.tool_version
        or result.tool_version != current_tool.version
        or result.python_executable_sha256 != receipt.tool_executable_sha256
        or result.python_executable_sha256 != current_executable.sha256
        or result.tool_distribution_sha256 != receipt.tool_distribution_sha256
        or result.tool_distribution_sha256 != current_tool.inventory_sha256
        or result.execution_evidence is not receipt.execution_evidence
        or result.timed_out is not receipt.timed_out
        or result.stdout_size != receipt.stdout_size
        or result.stdout_sha256 != receipt.stdout_sha256
        or result.stderr_size != receipt.stderr_size
        or result.stderr_sha256 != receipt.stderr_sha256
    ):
        raise ValueError("local release result differs from its receipt projection")
    expected_receipt_exit = None if result.timed_out else result.process_exit_code
    if receipt.exit_code != expected_receipt_exit:
        raise ValueError("local release result exit status differs from its receipt")
    expected_passed_checks = 1 if result.status is ReleaseGateStatus.PASSED else 0
    expected_failed_checks = 1 - expected_passed_checks
    if (
        receipt.result_summary.checks_total != 1
        or receipt.result_summary.checks_passed != expected_passed_checks
        or receipt.result_summary.checks_failed != expected_failed_checks
    ):
        raise ValueError("local release receipt check accounting is not semantically exact")

    expected_paths = {expected_result_path}
    if result.junit_binding is not None:
        supplemental = plan.supplemental_artifact_path
        if supplemental is None or result.junit_binding.path != supplemental:
            raise ValueError("local release result has an unexpected supplemental artifact")
        revalidate_evidence_file_binding(
            evidence_root=evidence_root,
            binding=result.junit_binding,
            max_bytes=_MAX_JUNIT_BYTES,
        )
        expected_paths.add(supplemental)
    if set(receipt_bindings) != expected_paths:
        raise ValueError("local release receipt artifact set is not semantically exact")
    _revalidate_junit_result(result, evidence_root=evidence_root)
    return result


def validate_local_release_gate_receipts(
    *,
    bundle: ReleaseGateEvidenceBundle,
    evidence_root: Path,
) -> tuple[LocalReleaseGateResult, ...]:
    """Validate all four local result artifacts carried by one candidate/run bundle."""

    validated = ReleaseGateEvidenceBundle.model_validate(bundle.model_dump(mode="json"))
    by_gate = {receipt.gate_id: receipt for receipt in validated.receipts}
    results = []
    for gate_id in sorted(_LOCAL_GATE_IDS, key=lambda item: item.value):
        receipt = by_gate[gate_id]
        result_path = get_release_gate_fixed_plan(gate_id).result_artifact_path
        binding = next(
            (item for item in receipt.artifact_bindings if item.path == result_path),
            None,
        )
        if receipt.status is ReleaseGateStatus.BLOCKED_TECHNICAL:
            if binding is not None:
                raise ValueError(
                    f"blocked local release receipt claims an executed result: {gate_id}"
                )
            continue
        if binding is None:
            raise ValueError(f"local release receipt lacks its typed result artifact: {gate_id}")
        results.append(
            validate_local_release_gate_result_artifact(
                evidence_root=evidence_root,
                binding=binding,
                expected_candidate_observation_sha256=validated.candidate_observation_sha256,
                expected_run_binding_sha256=validated.run_binding_sha256,
                expected_receipt=receipt,
            )
        )
    return tuple(results)


def _build_result(
    *,
    gate_id: ReleaseGateId,
    candidate_observation_sha256: str,
    run_binding_sha256: str,
    plan: ReleaseGateFixedPlan,
    status: ReleaseGateStatus,
    started_at: datetime,
    ended_at: datetime,
    argv: tuple[str, ...],
    tool_version: str,
    python_executable_sha256: str,
    tool_distribution_sha256: str,
    outcome: _ProcessOutcome,
    environment: dict[str, str],
    environment_contract: dict[str, str],
    junit_status: JUnitValidationStatus,
    junit_counts: PytestJUnitCounts | None,
    junit_binding: ManifestFileBinding | None,
) -> LocalReleaseGateResult:
    payload = LocalReleaseGateResultPayload(
        schema_version="1.0",
        generated_by="mmaudit",
        gate_id=gate_id,
        candidate_observation_sha256=candidate_observation_sha256,
        run_binding_sha256=run_binding_sha256,
        plan=plan,
        status=status,
        started_at=started_at,
        ended_at=ended_at,
        argv=argv,
        argv_sha256=canonical_sha256(list(argv)),
        tool_name=plan.module or "",
        tool_version=tool_version,
        python_executable_sha256=python_executable_sha256,
        tool_distribution_sha256=tool_distribution_sha256,
        execution_evidence=ExecutionEvidenceKind.REAL,
        process_exit_code=outcome.returncode,
        timed_out=outcome.timed_out,
        timeout_seconds=plan.timeout_seconds or 0,
        max_output_bytes=plan.max_output_bytes,
        stdout_size=len(outcome.stdout),
        stdout_sha256=hashlib.sha256(outcome.stdout).hexdigest(),
        stderr_size=len(outcome.stderr),
        stderr_sha256=hashlib.sha256(outcome.stderr).hexdigest(),
        child_environment_keys=tuple(sorted(environment)),
        child_environment_contract=environment_contract,
        child_environment_contract_sha256=canonical_sha256(environment_contract),
        network_guard_sha256=hashlib.sha256(
            get_release_gate_network_guard_source(gate_id)
        ).hexdigest(),
        provider_access="disabled",
        junit_status=junit_status,
        junit_counts=junit_counts,
        junit_binding=junit_binding,
    )
    serialized = payload.model_dump(mode="json")
    return LocalReleaseGateResult.model_validate(
        {
            **serialized,
            "result_sha256": canonical_sha256(serialized),
        }
    )


def _execute_fixed_process(
    *,
    argv: tuple[str, ...],
    repository_root: Path,
    runtime_root: Path,
    environment: dict[str, str],
    timeout_seconds: int,
) -> _ProcessOutcome:
    with (
        tempfile.TemporaryFile(mode="w+b", dir=runtime_root) as stdout_file,
        tempfile.TemporaryFile(mode="w+b", dir=runtime_root) as stderr_file,
    ):
        try:
            process = subprocess.Popen(
                list(argv),
                cwd=repository_root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                shell=False,
                close_fds=True,
                start_new_session=os.name != "nt",
                preexec_fn=_limit_release_child if os.name != "nt" else None,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError("fixed local release command could not start") from exc
        timed_out = False
        try:
            try:
                returncode = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                _stop_process(process)
                returncode = process.wait(timeout=5)
        finally:
            _terminate_release_process_group(process.pid)
        stdout = _read_capture(stdout_file)
        stderr = _read_capture(stderr_file)
    if not -255 <= returncode <= 255:
        raise ValueError("fixed local release command returned an invalid exit status")
    return _ProcessOutcome(
        returncode=returncode,
        timed_out=timed_out,
        stdout=stdout,
        stderr=stderr,
    )


def _fixed_child_environment(
    runtime_root: Path,
    *,
    network_guard_root: Path,
    gate_id: ReleaseGateId,
) -> dict[str, str]:
    home = runtime_root / "home"
    cache = runtime_root / "cache"
    temporary = runtime_root / "tmp"
    for path in (home, cache, temporary):
        path.mkdir(mode=0o700)
        path.chmod(0o700)
    substitutions = {
        "{devnull}": os.devnull,
        "{python_bin}": str(Path(sys.executable).parent),
        "{runtime_root}": str(runtime_root),
        "{network_guard_root}": str(network_guard_root),
    }
    environment = get_release_gate_child_environment_contract(gate_id)
    for key, template in tuple(environment.items()):
        value = template
        for marker, replacement in substitutions.items():
            value = value.replace(marker, replacement)
        if "{" in value or "}" in value:
            raise ValueError("local release child environment has an unresolved placeholder")
        environment[key] = value
    return environment


def _install_network_guard(
    runtime_root: Path,
    *,
    gate_id: ReleaseGateId,
) -> Path:
    """Install the exact private sitecustomize source bound by the fixed gate plan."""

    guard_root = runtime_root / "network-guard"
    try:
        guard_root.mkdir(mode=0o700)
        guard_root.chmod(0o700)
        guard_metadata = guard_root.lstat()
    except OSError as exc:
        raise ValueError("local release network guard root could not be created") from exc
    if (
        not stat.S_ISDIR(guard_metadata.st_mode)
        or stat.S_ISLNK(guard_metadata.st_mode)
        or guard_root.is_junction()
        or stat.S_IMODE(guard_metadata.st_mode) != 0o700
    ):
        raise ValueError("local release network guard root is not a private directory")

    source = get_release_gate_network_guard_source(gate_id)
    expected_sha256 = get_release_gate_fixed_plan(gate_id).network_guard_sha256
    if expected_sha256 is None or hashlib.sha256(source).hexdigest() != expected_sha256:
        raise ValueError("local release network guard source differs from its fixed plan")
    destination = guard_root / "sitecustomize.py"
    descriptor, created_identity = _create_fresh_private_file(destination)
    try:
        remaining = memoryview(source)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise ValueError("local release network guard could not be written")
            remaining = remaining[written:]
        os.fsync(descriptor)
        observed = _read_descriptor(descriptor, max_bytes=_MAX_CAPTURE_BYTES)
        metadata = os.fstat(descriptor)
        if (
            (metadata.st_dev, metadata.st_ino) != created_identity
            or metadata.st_size != len(source)
            or observed != source
            or hashlib.sha256(observed).hexdigest() != expected_sha256
        ):
            raise ValueError("local release network guard changed during installation")
    finally:
        os.close(descriptor)
    return guard_root


def _materialize_argv(
    plan: ReleaseGateFixedPlan,
    *,
    evidence_root: Path,
) -> tuple[str, ...]:
    if plan.module is None:
        raise ValueError("local release plan has no Python module")
    arguments = tuple(
        (
            item.replace(
                "{evidence_root}",
                str(evidence_root),
            )
            if "{evidence_root}" in item
            else item
        )
        for item in plan.arguments
    )
    argv = (sys.executable, "-P", "-m", plan.module, *arguments)
    expected = {
        ReleaseGateId.RUFF_FORMAT: (
            sys.executable,
            "-P",
            "-m",
            "ruff",
            "format",
            "--check",
            ".",
        ),
        ReleaseGateId.RUFF_CHECK: (
            sys.executable,
            "-P",
            "-m",
            "ruff",
            "check",
            ".",
        ),
        ReleaseGateId.MYPY: (sys.executable, "-P", "-m", "mypy"),
        ReleaseGateId.PYTEST: (
            sys.executable,
            "-P",
            "-m",
            "pytest",
            "-q",
            "--junitxml",
            str(evidence_root / "release-gate-pytest-junit.xml"),
        ),
    }[plan.gate_id]
    if argv != expected:
        raise ValueError("local release argv differs from its fixed semantic plan")
    return argv


def _observe_junit(
    *,
    gate_id: ReleaseGateId,
    evidence_root: Path,
    relative_path: str | None,
    descriptor: int | None,
    created_identity: tuple[int, int] | None,
) -> tuple[
    JUnitValidationStatus,
    PytestJUnitCounts | None,
    ManifestFileBinding | None,
]:
    if gate_id is not ReleaseGateId.PYTEST:
        if relative_path is not None or descriptor is not None or created_identity is not None:
            raise ValueError("non-pytest plan unexpectedly created JUnit evidence")
        return JUnitValidationStatus.NOT_APPLICABLE, None, None
    if relative_path is None or descriptor is None or created_identity is None:
        raise ValueError("pytest plan did not create its fixed JUnit destination")
    os.fsync(descriptor)
    held = _read_descriptor(descriptor, max_bytes=_MAX_JUNIT_BYTES)
    metadata = os.fstat(descriptor)
    if (
        (metadata.st_dev, metadata.st_ino) != created_identity
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError("pytest JUnit destination changed during execution")
    binding = create_evidence_file_binding(
        evidence_root=evidence_root,
        relative_path=relative_path,
        max_bytes=_MAX_JUNIT_BYTES,
    )
    if binding.size != len(held) or binding.sha256 != hashlib.sha256(held).hexdigest():
        raise ValueError("pytest JUnit path differs from its held file descriptor")
    if not held:
        return JUnitValidationStatus.EMPTY, None, binding
    try:
        counts = _parse_junit_counts(held)
    except ValueError:
        return JUnitValidationStatus.INVALID, None, binding
    return JUnitValidationStatus.VALID, counts, binding


def _parse_junit_counts(content: bytes) -> PytestJUnitCounts:
    upper = content[:4_096].upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError("pytest JUnit XML declarations are unsupported")
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError as exc:
        raise ValueError("pytest JUnit XML is malformed") from exc
    tag = root.tag.rsplit("}", 1)[-1]
    if tag == "testsuite":
        suites = [root]
    elif tag == "testsuites":
        suites = [child for child in list(root) if child.tag.rsplit("}", 1)[-1] == "testsuite"]
    else:
        raise ValueError("pytest JUnit XML root is unsupported")
    if not suites:
        raise ValueError("pytest JUnit XML contains no test suites")
    tests = failures = errors = skipped = 0
    for suite in suites:
        tests += _xml_nonnegative_integer(suite, "tests")
        failures += _xml_nonnegative_integer(suite, "failures")
        errors += _xml_nonnegative_integer(suite, "errors")
        skipped += _xml_nonnegative_integer(suite, "skipped")
    passed = tests - failures - errors - skipped
    return PytestJUnitCounts(
        tests=tests,
        passed=passed,
        failures=failures,
        errors=errors,
        skipped=skipped,
    )


def _xml_nonnegative_integer(element: ElementTree.Element, name: str) -> int:
    raw = element.attrib.get(name)
    if raw is None or re.fullmatch(r"0|[1-9][0-9]{0,7}", raw) is None:
        raise ValueError(f"pytest JUnit {name} count is malformed")
    value = int(raw)
    if value > _MAX_JUNIT_TESTS:
        raise ValueError(f"pytest JUnit {name} count exceeds its bound")
    return value


def _revalidate_junit_result(
    result: LocalReleaseGateResult,
    *,
    evidence_root: Path,
) -> None:
    if result.gate_id is not ReleaseGateId.PYTEST:
        return
    binding = result.junit_binding
    if binding is None:
        raise ValueError("pytest local release result lacks its JUnit binding")
    observation = revalidate_evidence_file_binding(
        evidence_root=evidence_root,
        binding=binding,
        max_bytes=_MAX_JUNIT_BYTES,
    )
    content = _read_bound_bytes(evidence_root=evidence_root, binding=observation)
    if not content:
        status, counts = JUnitValidationStatus.EMPTY, None
    else:
        try:
            counts = _parse_junit_counts(content)
            status = JUnitValidationStatus.VALID
        except ValueError:
            status, counts = JUnitValidationStatus.INVALID, None
    if result.junit_status is not status or result.junit_counts != counts:
        raise ValueError("pytest JUnit evidence differs from its typed result")


def _read_bound_bytes(
    *,
    evidence_root: Path,
    binding: ManifestFileBinding,
) -> bytes:
    path = _require_unlinked_directory(evidence_root, label="release evidence root") / binding.path
    flags = os.O_RDONLY | _required_flag("O_NOFOLLOW") | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("bound local release artifact could not be opened") from exc
    try:
        content = _read_descriptor(descriptor, max_bytes=_MAX_JUNIT_BYTES)
    finally:
        os.close(descriptor)
    if len(content) != binding.size or hashlib.sha256(content).hexdigest() != binding.sha256:
        raise ValueError("bound local release artifact content differs from its binding")
    return content


def _create_fresh_private_file(path: Path) -> tuple[int, tuple[int, int]]:
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | _required_flag("O_NOFOLLOW")
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ValueError("fixed local release artifact destination must be fresh") from exc
    try:
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("fixed local release artifact is not a fresh private file")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, (metadata.st_dev, metadata.st_ino)


def _read_descriptor(descriptor: int, *, max_bytes: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    content = bytearray()
    while len(content) <= max_bytes:
        chunk = os.read(
            descriptor,
            min(1024 * 1024, max_bytes + 1 - len(content)),
        )
        if not chunk:
            break
        content.extend(chunk)
    if len(content) > max_bytes:
        raise ValueError("local release artifact exceeds its byte bound")
    return bytes(content)


def _read_capture(handle: BinaryIO) -> bytes:
    handle.seek(0)
    content = handle.read(_MAX_CAPTURE_BYTES + 1)
    if not isinstance(content, bytes) or len(content) > _MAX_CAPTURE_BYTES:
        raise ValueError("fixed local release command output exceeds its bound")
    return content


def _observe_executing_python() -> _ExecutableObservation:
    if not sys.executable:
        raise ValueError("executing Python path is unavailable")
    declared = Path(sys.executable)
    try:
        declared_before = declared.lstat()
        resolved = declared.resolve(strict=True)
        base = Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)
    except OSError as exc:
        raise ValueError("executing Python identity is unavailable") from exc
    if resolved != base:
        raise ValueError("declared Python executable differs from the running interpreter")
    flags = os.O_RDONLY | _required_flag("O_NOFOLLOW") | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise ValueError("executing Python could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size <= 0
            or opened.st_size > _MAX_EXECUTABLE_BYTES
            or stat.S_IMODE(opened.st_mode) & 0o022
        ):
            raise ValueError("executing Python is not a bounded trusted executable")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > _MAX_EXECUTABLE_BYTES:
                raise ValueError("executing Python exceeds its byte bound")
            digest.update(chunk)
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        resolved_after = resolved.lstat()
        declared_after = declared.lstat()
    except OSError as exc:
        raise ValueError("executing Python changed while it was measured") from exc
    identities = {
        _stat_identity(opened),
        _stat_identity(finished),
        _stat_identity(resolved_after),
    }
    declared_identities = {
        _stat_identity(declared_before),
        _stat_identity(declared_after),
    }
    if len(identities) != 1 or len(declared_identities) != 1 or size != opened.st_size:
        raise ValueError("executing Python changed while it was measured")
    return _ExecutableObservation(
        declared_path=str(declared),
        resolved_path=str(resolved),
        sha256=digest.hexdigest(),
        identity=_stat_identity(finished),
        declared_identity=_stat_identity(declared_after),
    )


def _require_executing_repository_root(
    path: Path,
) -> tuple[Path, tuple[tuple[int, int, int], ...]]:
    root = _require_unlinked_directory(path, label="release repository")
    package_file = mmaudit.__file__
    if package_file is None:
        raise ValueError("executing mmaudit package location is unavailable")
    try:
        expected_package = _require_unlinked_directory(
            root / "src" / "mmaudit",
            label="release repository package",
        )
        executing_package = _require_unlinked_directory(
            Path(package_file).parent,
            label="executing mmaudit package",
        )
        source_root = _require_unlinked_directory(
            root / "src",
            label="release repository source root",
        )
        identities = tuple(
            (metadata.st_dev, metadata.st_ino, metadata.st_mode)
            for metadata in (
                root.stat(),
                source_root.stat(),
                expected_package.stat(),
            )
        )
    except OSError as exc:
        raise ValueError("release repository package is unavailable") from exc
    if expected_package != executing_package:
        raise ValueError("release repository is not the executing mmaudit repository")
    return root, identities


def _require_unlinked_directory(path: Path, *, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            current /= part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or current.is_junction():
                raise ValueError(f"{label} may not traverse a link")
        metadata = absolute.lstat()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} must be a directory")
    return absolute.resolve(strict=True)


def _require_fresh_destination(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ValueError("fixed local release destination is unavailable") from exc
    raise ValueError("fixed local release destination must be fresh")


def _observe_tool_distribution(distribution: str) -> _DistributionObservation:
    """Hash the exact bounded installed distribution inventory used by a local gate."""

    try:
        installed = importlib.metadata.distribution(distribution)
    except importlib.metadata.PackageNotFoundError as exc:
        raise ValueError(f"fixed local release tool is unavailable: {distribution}") from exc
    version = installed.version
    if (
        not version
        or len(version) > 200
        or any(ord(character) < 32 or ord(character) == 127 for character in version)
    ):
        raise ValueError("fixed local release tool version is malformed")
    name = installed.metadata.get("Name")
    if (
        not name
        or len(name) > 200
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise ValueError("fixed local release distribution name is malformed")
    files = installed.files
    if files is None or not files or len(files) > _MAX_DISTRIBUTION_FILES:
        raise ValueError("fixed local release distribution inventory is empty or unbounded")
    prefix = _require_unlinked_directory(Path(sys.prefix), label="Python environment prefix")
    inventory_files = sorted(((str(item), item) for item in files), key=lambda item: item[0])
    relative_names = [item[0] for item in inventory_files]
    if len(relative_names) != len(set(relative_names)) or any(
        not item
        or len(item.encode("utf-8")) > 4_096
        or any(ord(character) < 32 or ord(character) == 127 for character in item)
        for item in relative_names
    ):
        raise ValueError("fixed local release distribution inventory paths are malformed")

    inventory: list[dict[str, int | str]] = []
    total_bytes = 0
    for relative_name, package_path in inventory_files:
        try:
            located = Path(os.path.abspath(str(installed.locate_file(package_path))))
            located_parent = _require_unlinked_directory(
                located.parent,
                label="fixed local release distribution file parent",
            )
            candidate = located_parent / located.name
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise ValueError("fixed local release distribution file is unavailable") from exc
        if resolved != candidate or not resolved.is_relative_to(prefix):
            raise ValueError("fixed local release distribution file escapes its Python environment")
        size, sha256 = _observe_regular_file(
            candidate,
            max_bytes=_MAX_DISTRIBUTION_FILE_BYTES,
            label="fixed local release distribution file",
        )
        total_bytes += size
        if total_bytes > _MAX_DISTRIBUTION_TOTAL_BYTES:
            raise ValueError("fixed local release distribution inventory exceeds its byte bound")
        inventory.append(
            {
                "path": relative_name,
                "size": size,
                "sha256": sha256,
            }
        )
    return _DistributionObservation(
        name=name,
        version=version,
        inventory_sha256=canonical_sha256(
            {
                "name": name,
                "version": version,
                "files": inventory,
            }
        ),
    )


def _observe_regular_file(
    path: Path,
    *,
    max_bytes: int,
    label: str,
) -> tuple[int, str]:
    parent = _require_unlinked_directory(path.parent, label=f"{label} parent")
    candidate = parent / path.name
    flags = os.O_RDONLY | _required_flag("O_NOFOLLOW") | getattr(os, "O_CLOEXEC", 0)
    try:
        before = candidate.lstat()
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise ValueError(f"{label} could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or opened.st_nlink != 1
            or opened.st_size < 0
            or opened.st_size > max_bytes
            or stat.S_IMODE(opened.st_mode) & 0o022
        ):
            raise ValueError(f"{label} is not a bounded trusted regular file")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"{label} exceeds its byte bound")
            digest.update(chunk)
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after = candidate.lstat()
    except OSError as exc:
        raise ValueError(f"{label} changed while it was measured") from exc
    if (
        _stat_identity(before) != _stat_identity(opened)
        or _stat_identity(opened) != _stat_identity(finished)
        or _stat_identity(finished) != _stat_identity(after)
        or size != opened.st_size
    ):
        raise ValueError(f"{label} changed while it was measured")
    return size, digest.hexdigest()


def _result_summary(
    gate_id: ReleaseGateId,
    status: ReleaseGateStatus,
    junit_counts: PytestJUnitCounts | None,
) -> str:
    if status is ReleaseGateStatus.FAILED:
        return f"fixed local {gate_id.value} gate failed"
    if gate_id is ReleaseGateId.PYTEST and junit_counts is not None:
        return (
            f"fixed local pytest gate passed with {junit_counts.tests} tests "
            f"and {junit_counts.skipped} skipped"
        )
    return f"fixed local {gate_id.value} gate passed"


def _limit_release_child() -> None:
    os.umask(0o077)
    try:
        import resource
    except ImportError as exc:
        raise RuntimeError("fixed local release resource limits are unavailable") from exc
    resource.setrlimit(resource.RLIMIT_CPU, (1_800, 1_800))
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (_MAX_CAPTURE_BYTES + 1, _MAX_CAPTURE_BYTES + 1),
    )
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.platform != "darwin" and hasattr(resource, "RLIMIT_NPROC"):
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    if sys.platform != "darwin" and hasattr(resource, "RLIMIT_AS"):
        resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        process.kill()


def _terminate_release_process_group(process_group_id: int) -> None:
    """Kill and confirm removal of descendants left in the isolated process group."""

    if os.name == "nt" or process_group_id <= 1:
        raise ValueError("fixed local release process group cannot be safely terminated")
    try:
        os.killpg(process_group_id, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError as exc:
        raise ValueError("fixed local release process group cleanup failed") from exc
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            os.killpg(process_group_id, 0)
        except ProcessLookupError:
            return
        except PermissionError:
            time.sleep(0.01)
            continue
        except OSError as exc:
            raise ValueError(
                "fixed local release process group cleanup could not be confirmed"
            ) from exc
        time.sleep(0.01)
    raise ValueError("fixed local release process group survived cleanup")


def _required_flag(name: str) -> int:
    value = getattr(os, name, None)
    if not isinstance(value, int) or value == 0:
        raise ValueError(f"required safe file flag is unavailable: {name}")
    return value


def _require_sha256(value: str, *, label: str) -> None:
    if re.fullmatch(_SHA256_PATTERN, value) is None:
        raise ValueError(f"{label} hash is malformed")


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
