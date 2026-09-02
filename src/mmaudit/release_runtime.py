"""Fixed, provider-free local command execution for release-gate evidence."""

from __future__ import annotations

import hashlib
import importlib.metadata
import os
import re
import stat
import sys
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
from mmaudit.release_candidate import ReleaseCandidateObservation
from mmaudit.release_gates import (
    ReleaseGateEvidenceBundle,
    ReleaseGateFixedPlan,
    ReleaseGatePlanExecutor,
    ReleaseGatePrerequisiteBlocker,
    ReleaseGateReceipt,
    ReleaseGateResultKind,
    build_release_gate_receipt,
    get_release_gate_child_environment_contract,
    get_release_gate_fixed_plan,
    get_release_gate_network_guard_source,
)
from mmaudit.release_io import (
    create_evidence_file_binding,
    revalidate_evidence_file_binding,
)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_CAPTURE_BYTES = 4 * 1024 * 1024
_MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
_MAX_DISTRIBUTION_FILE_BYTES = 256 * 1024 * 1024
_MAX_DISTRIBUTION_TOTAL_BYTES = 1024 * 1024 * 1024
_MAX_DISTRIBUTION_FILES = 10_000
_MAX_JUNIT_BYTES = 32 * 1024 * 1024
_MAX_JUNIT_TESTS = 10_000_000
_StatIdentity = tuple[int, int, int, int, int, int, int]
_LOCAL_GATE_IDS = frozenset(
    {
        ReleaseGateId.RUFF_FORMAT,
        ReleaseGateId.RUFF_CHECK,
        ReleaseGateId.MYPY,
        ReleaseGateId.PYTEST,
    }
)
_LOCAL_GATE_BLOCKER_CODE = "secure_local_gate_runner_unavailable"
_LOCAL_GATE_BLOCKER_SUMMARY = (
    "No local runner currently proves pre-startup import isolation, subprocess network denial, "
    "and descriptor-rooted evidence writes."
)
_LOCAL_GATE_RESULT_SUMMARY = (
    "local execution is blocked until the runner provides OS network confinement and "
    "descriptor-rooted candidate and evidence I/O"
)
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


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
    argv: tuple[str, ...] = Field(min_length=3, max_length=32)
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
            or len(item.encode("utf-8")) > 16_384
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
    candidate: ReleaseCandidateObservation,
    run_binding_sha256: str,
) -> ReleaseGateReceipt:
    """Fail closed until an OS-confined, descriptor-rooted local runner is available."""

    if type(gate_id) is not ReleaseGateId or gate_id not in _LOCAL_GATE_IDS:
        raise ValueError("only fixed local release gates may execute")
    if type(candidate) is not ReleaseCandidateObservation:
        raise TypeError("local release candidate must be an exact observation value")
    candidate_observation_sha256 = candidate.observation_sha256
    _require_sha256(candidate_observation_sha256, label="candidate observation")
    _require_sha256(run_binding_sha256, label="run binding")
    del repository_root, evidence_root
    plan = get_release_gate_fixed_plan(gate_id)
    if (
        plan.executor is not ReleaseGatePlanExecutor.FIXED_LOCAL_PYTHON_MODULE
        or plan.module is None
        or plan.timeout_seconds is None
    ):
        raise ValueError("release gate has no fixed local execution plan")
    timestamp = _utc_now()
    return build_release_gate_receipt(
        gate_id=gate_id,
        candidate_observation_sha256=candidate_observation_sha256,
        run_binding_sha256=run_binding_sha256,
        fixed_plan_sha256=plan.fixed_plan_sha256,
        started_at=timestamp,
        ended_at=timestamp,
        argv=("mmaudit-release", "blocked-local-gate", gate_id.value),
        tool_name=plan.module,
        tool_version=None,
        tool_executable_sha256=None,
        tool_distribution_sha256=None,
        execution_evidence=ExecutionEvidenceKind.UNVERIFIED,
        exit_code=None,
        timed_out=False,
        stdout=b"",
        stderr=b"",
        summary=_LOCAL_GATE_RESULT_SUMMARY,
        prerequisite_blocker=ReleaseGatePrerequisiteBlocker(
            code=_LOCAL_GATE_BLOCKER_CODE,
            summary=_LOCAL_GATE_BLOCKER_SUMMARY,
        ),
        artifact_bindings=(),
    )


def validate_local_release_gate_result_artifact(
    *,
    evidence_root: Path,
    binding: ManifestFileBinding,
    expected_candidate_observation_sha256: str,
    expected_run_binding_sha256: str,
    expected_receipt: ReleaseGateReceipt,
) -> LocalReleaseGateResult:
    """Reject executed local artifacts under the current no-execution plan."""

    del evidence_root, binding, expected_candidate_observation_sha256, expected_run_binding_sha256
    if type(expected_receipt) is not ReleaseGateReceipt:
        raise TypeError("local release receipt must be an exact typed value")
    receipt = ReleaseGateReceipt.model_validate(expected_receipt.model_dump(mode="json"))
    if receipt.gate_id not in _LOCAL_GATE_IDS:
        raise ValueError("local result validation received a non-local release gate")
    raise ValueError("current local release plan rejects executed result artifacts")


def validate_local_release_gate_receipts(
    *,
    bundle: ReleaseGateEvidenceBundle,
    evidence_root: Path,
) -> tuple[LocalReleaseGateResult, ...]:
    """Require canonical no-execution blockers for all four current local gates."""

    del evidence_root
    validated = ReleaseGateEvidenceBundle.model_validate(bundle.model_dump(mode="json"))
    by_gate = {receipt.gate_id: receipt for receipt in validated.receipts}
    for gate_id in sorted(_LOCAL_GATE_IDS, key=lambda item: item.value):
        _require_canonical_local_gate_blocker(by_gate[gate_id], gate_id=gate_id)
    return ()


def _require_canonical_local_gate_blocker(
    receipt: ReleaseGateReceipt,
    *,
    gate_id: ReleaseGateId,
) -> None:
    plan = get_release_gate_fixed_plan(gate_id)
    blocker = receipt.prerequisite_blocker
    summary = receipt.result_summary
    if (
        receipt.gate_id is not gate_id
        or receipt.status is not ReleaseGateStatus.BLOCKED_TECHNICAL
        or receipt.started_at != receipt.ended_at
        or receipt.argv != ("mmaudit-release", "blocked-local-gate", gate_id.value)
        or receipt.tool_name != plan.module
        or receipt.tool_version is not None
        or receipt.tool_executable_sha256 is not None
        or receipt.tool_distribution_sha256 is not None
        or receipt.execution_evidence is not ExecutionEvidenceKind.UNVERIFIED
        or receipt.exit_code is not None
        or receipt.timed_out
        or receipt.stdout_size != 0
        or receipt.stdout_sha256 != _EMPTY_SHA256
        or receipt.stderr_size != 0
        or receipt.stderr_sha256 != _EMPTY_SHA256
        or summary.kind is not ReleaseGateResultKind.BLOCKED_TECHNICAL
        or summary.summary != _LOCAL_GATE_RESULT_SUMMARY
        or summary.checks_total != 0
        or summary.checks_passed != 0
        or summary.checks_failed != 0
        or blocker is None
        or blocker.code != _LOCAL_GATE_BLOCKER_CODE
        or blocker.summary != _LOCAL_GATE_BLOCKER_SUMMARY
        or receipt.artifact_bindings
    ):
        raise ValueError(
            f"local release receipt is not the canonical current-plan blocker: {gate_id}"
        )


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


def _fixed_child_environment(
    *,
    evidence_root: Path,
    candidate_root: Path,
    gate_id: ReleaseGateId,
) -> dict[str, str]:
    substitutions = {
        "{devnull}": os.devnull,
        "{python_bin}": str(Path(sys.executable).parent),
        "{evidence_root}": str(evidence_root),
        "{candidate_root}": str(candidate_root),
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


def _materialize_argv(
    plan: ReleaseGateFixedPlan,
    *,
    evidence_root: Path,
) -> tuple[str, ...]:
    if plan.module is None:
        raise ValueError("local release plan has no Python module")
    bootstrap_source = get_release_gate_network_guard_source(plan.gate_id)
    expected_bootstrap_sha256 = plan.network_guard_sha256
    if (
        expected_bootstrap_sha256 is None
        or hashlib.sha256(bootstrap_source).hexdigest() != expected_bootstrap_sha256
    ):
        raise ValueError("local release trusted bootstrap differs from its fixed plan")
    launcher = (
        'exec(compile(bytes.fromhex("'
        + bootstrap_source.hex()
        + '").decode("utf-8"),"<mmaudit-release-bootstrap>","exec"))'
    )
    if len(launcher.encode("utf-8")) > 16_384 or any(
        ord(character) < 32 or ord(character) == 127 for character in launcher
    ):
        raise ValueError("local release trusted bootstrap launcher is not a bounded literal")
    substitutions = {
        "{devnull}": os.devnull,
        "{evidence_root}": str(evidence_root),
    }
    materialized_arguments: list[str] = []
    for item in plan.arguments:
        value = item
        for marker, replacement in substitutions.items():
            value = value.replace(marker, replacement)
        if "{" in value or "}" in value:
            raise ValueError("local release argv has an unresolved placeholder")
        materialized_arguments.append(value)
    arguments = tuple(materialized_arguments)
    argv = (sys.executable, "-P", "-S", "-c", launcher, plan.module, *arguments)
    expected = {
        ReleaseGateId.RUFF_FORMAT: (
            sys.executable,
            "-P",
            "-S",
            "-c",
            launcher,
            "ruff",
            "format",
            "--check",
            "--no-cache",
            "--isolated",
            "--target-version",
            "py312",
            "--line-length",
            "100",
            "--extend-exclude",
            "config/public_model_lineage/sources/**",
            "--extend-exclude",
            "docs/remediation/v3/operator_captures/**",
            ".",
        ),
        ReleaseGateId.RUFF_CHECK: (
            sys.executable,
            "-P",
            "-S",
            "-c",
            launcher,
            "ruff",
            "check",
            "--no-cache",
            "--isolated",
            "--target-version",
            "py312",
            "--line-length",
            "100",
            "--select",
            "E,F,I,UP,B,SIM,RUF",
            "--ignore",
            "E501",
            "--extend-exclude",
            "config/public_model_lineage/sources/**",
            "--extend-exclude",
            "docs/remediation/v3/operator_captures/**",
            ".",
        ),
        ReleaseGateId.MYPY: (
            sys.executable,
            "-P",
            "-S",
            "-c",
            launcher,
            "mypy",
            "--no-incremental",
            "--config-file",
            os.devnull,
            "--strict",
            "--python-version",
            "3.12",
            "--disable-error-code",
            "import-untyped",
            "src/mmaudit",
        ),
        ReleaseGateId.PYTEST: (
            sys.executable,
            "-P",
            "-S",
            "-c",
            launcher,
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "-p",
            "pytest_asyncio.plugin",
            "-c",
            os.devnull,
            "--rootdir=.",
            "--confcutdir=.",
            "--import-mode=importlib",
            "--junitxml",
            str(evidence_root / "release-gate-pytest-junit.xml"),
            "tests",
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
