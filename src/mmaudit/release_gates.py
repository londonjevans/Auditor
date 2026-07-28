"""Typed, self-hashed runtime receipts for release-gate execution."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Sequence
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.models.schemas import ExecutionEvidenceKind, StrictModel
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release import ReleaseGateId, ReleaseGateStatus

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_ARGV_ITEMS = 256
_MAX_ARGV_ITEM_BYTES = 16_384
_MAX_CAPTURE_BYTES = 4 * 1024 * 1024
_MAX_GATE_ARTIFACT_BYTES = 100_000_000
_MAX_BUNDLE_ARTIFACTS = 4_096
_MAX_BUNDLE_ARTIFACT_BYTES = 1024**3
_REQUIRED_GATE_COUNT = 12


class ReleaseGateResultKind(StrEnum):
    """Machine-readable outcome represented by a gate result summary."""

    PASSED = "passed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    BLOCKED_TECHNICAL = "blocked_technical"


class ReleaseGateResultSummary(StrictModel):
    """Bounded structured summary without retaining command output."""

    kind: ReleaseGateResultKind
    summary: str = Field(min_length=1, max_length=2_000)
    checks_total: int = Field(ge=0, le=1_000_000)
    checks_passed: int = Field(ge=0, le=1_000_000)
    checks_failed: int = Field(ge=0, le=1_000_000)

    @field_validator("summary")
    @classmethod
    def summary_is_single_line(cls, value: str) -> str:
        if not value.strip() or any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise ValueError("release gate summary must be bounded single-line text")
        return value

    @model_validator(mode="after")
    def check_counts_are_consistent(self) -> ReleaseGateResultSummary:
        if self.checks_total != self.checks_passed + self.checks_failed:
            raise ValueError("release gate summary check counts are inconsistent")
        if self.kind is ReleaseGateResultKind.PASSED and (
            self.checks_total == 0 or self.checks_failed != 0
        ):
            raise ValueError("passed release gate summaries require non-empty passing checks")
        if (
            self.kind
            in {
                ReleaseGateResultKind.FAILED,
                ReleaseGateResultKind.TIMED_OUT,
            }
            and self.checks_failed == 0
        ):
            raise ValueError("failed release gate summaries require a failed check")
        if self.kind is ReleaseGateResultKind.BLOCKED_TECHNICAL and self.checks_total != 0:
            raise ValueError("blocked release gate summaries cannot claim completed checks")
        return self


class ReleaseGatePrerequisiteBlocker(StrictModel):
    """Typed reason that a real prerequisite could not execute."""

    code: str = Field(
        min_length=1,
        max_length=100,
        pattern=r"^[a-z][a-z0-9_]{0,99}$",
    )
    summary: str = Field(min_length=1, max_length=1_000)

    @field_validator("summary")
    @classmethod
    def summary_is_single_line(cls, value: str) -> str:
        if not value.strip() or any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise ValueError("release gate blocker must be bounded single-line text")
        return value


class ReleaseGatePlanExecutor(StrEnum):
    """Closed executor family for one release-gate semantic contract."""

    FIXED_LOCAL_PYTHON_MODULE = "fixed_local_python_module"
    BOUND_RUNTIME_OBSERVATION = "bound_runtime_observation"


class ReleaseGateFixedPlanPayload(StrictModel):
    """Canonical non-secret execution contract for one fixed release gate."""

    schema_version: Literal["1.0"]
    generated_by: Literal["mmaudit"]
    gate_id: ReleaseGateId
    executor: ReleaseGatePlanExecutor
    semantic_contract: str = Field(min_length=1, max_length=1_000)
    module: str | None = Field(default=None, min_length=1, max_length=100)
    arguments: tuple[str, ...] = Field(max_length=32)
    timeout_seconds: int | None = Field(default=None, ge=1, le=3_600)
    max_output_bytes: int = Field(ge=1, le=_MAX_CAPTURE_BYTES)
    python_safe_path: Literal[True] | None
    child_environment_contract_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    network_guard_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    result_artifact_path: str = Field(
        pattern=r"^release-gate-[a-z0-9_]+-result\.json$",
    )
    supplemental_artifact_path: str | None = Field(
        default=None,
        pattern=r"^release-gate-[a-z0-9_]+-[a-z0-9_-]+\.[a-z0-9]+$",
    )
    network_allowed: Literal[False]

    @field_validator("semantic_contract", "module")
    @classmethod
    def plan_text_is_single_line(cls, value: str | None) -> str | None:
        if value is not None and (
            not value.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("release gate fixed-plan text must be bounded and single-line")
        return value

    @field_validator("arguments")
    @classmethod
    def plan_arguments_are_literal(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            not item
            or len(item.encode("utf-8")) > _MAX_ARGV_ITEM_BYTES
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
            for item in value
        ):
            raise ValueError("release gate fixed-plan arguments must be bounded literals")
        return value

    @model_validator(mode="after")
    def executor_fields_are_consistent(self) -> ReleaseGateFixedPlanPayload:
        if self.executor is ReleaseGatePlanExecutor.FIXED_LOCAL_PYTHON_MODULE:
            if (
                self.module is None
                or self.timeout_seconds is None
                or self.python_safe_path is not True
                or self.child_environment_contract_sha256 is None
                or self.network_guard_sha256 is None
            ):
                raise ValueError(
                    "fixed local release plans require a module, timeout, and environment"
                )
        elif (
            self.module is not None
            or self.arguments
            or self.timeout_seconds is not None
            or self.python_safe_path is not None
            or self.supplemental_artifact_path is not None
            or self.child_environment_contract_sha256 is not None
            or self.network_guard_sha256 is not None
        ):
            raise ValueError("runtime-observation release plans cannot claim a local command")
        return self


class ReleaseGateFixedPlan(ReleaseGateFixedPlanPayload):
    """Self-hashed canonical plan used to prevent receipt semantic replay."""

    fixed_plan_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def fixed_plan_hash_is_consistent(self) -> ReleaseGateFixedPlan:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"fixed_plan_sha256"}))
        if self.fixed_plan_sha256 != expected:
            raise ValueError("release gate fixed-plan hash is inconsistent")
        return self


class ReleaseGateReceiptPayload(StrictModel):
    """Canonical contents of one gate receipt before its self-hash."""

    schema_version: Literal["1.0"]
    generated_by: Literal["mmaudit"]
    gate_id: ReleaseGateId
    candidate_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    run_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    fixed_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    status: ReleaseGateStatus
    started_at: datetime
    ended_at: datetime
    argv: tuple[str, ...] = Field(min_length=1, max_length=_MAX_ARGV_ITEMS)
    argv_sha256: str = Field(pattern=_SHA256_PATTERN)
    tool_name: str = Field(min_length=1, max_length=200)
    tool_version: str | None = Field(default=None, min_length=1, max_length=500)
    tool_executable_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    tool_distribution_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    execution_evidence: ExecutionEvidenceKind
    exit_code: int | None = Field(default=None, ge=-255, le=255)
    timed_out: bool
    stdout_size: int = Field(ge=0, le=_MAX_CAPTURE_BYTES)
    stdout_sha256: str = Field(pattern=_SHA256_PATTERN)
    stderr_size: int = Field(ge=0, le=_MAX_CAPTURE_BYTES)
    stderr_sha256: str = Field(pattern=_SHA256_PATTERN)
    result_summary: ReleaseGateResultSummary
    prerequisite_blocker: ReleaseGatePrerequisiteBlocker | None
    artifact_bindings: list[ManifestFileBinding] = Field(default_factory=list, max_length=1_000)

    @field_validator("started_at", "ended_at")
    @classmethod
    def timestamps_are_utc_whole_seconds(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond != 0:
            raise ValueError("release gate timestamps must be UTC whole seconds")
        return value

    @field_validator("argv")
    @classmethod
    def argv_is_bounded_and_literal(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            encoded = item.encode("utf-8")
            if (
                not item
                or len(encoded) > _MAX_ARGV_ITEM_BYTES
                or any(ord(character) < 32 or ord(character) == 127 for character in item)
            ):
                raise ValueError("release gate argv must contain bounded literal arguments")
        return value

    @field_validator("tool_name", "tool_version")
    @classmethod
    def tool_text_is_single_line(cls, value: str | None) -> str | None:
        if value is not None and (
            not value.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("release gate tool identity must be bounded single-line text")
        return value

    @field_validator("artifact_bindings")
    @classmethod
    def artifact_bindings_are_sorted_unique_and_bounded(
        cls,
        value: list[ManifestFileBinding],
    ) -> list[ManifestFileBinding]:
        paths = [binding.path for binding in value]
        if paths != sorted(set(paths)):
            raise ValueError("release gate artifact bindings must be unique and sorted")
        if any(binding.size > _MAX_GATE_ARTIFACT_BYTES for binding in value):
            raise ValueError("release gate artifact binding exceeds its size bound")
        return value

    @model_validator(mode="after")
    def receipt_inputs_are_consistent(self) -> ReleaseGateReceiptPayload:
        if self.ended_at < self.started_at:
            raise ValueError("release gate end time precedes its start time")
        if self.argv_sha256 != canonical_sha256(list(self.argv)):
            raise ValueError("release gate argv hash is inconsistent")
        if self.fixed_plan_sha256 != release_gate_fixed_plan_sha256(self.gate_id):
            raise ValueError("release gate receipt does not use its canonical fixed plan")
        expected_kind = _result_kind(
            status=self.status,
            timed_out=self.timed_out,
        )
        if self.result_summary.kind is not expected_kind:
            raise ValueError("release gate result summary is inconsistent")
        if self.timed_out and self.exit_code == 0:
            raise ValueError("timed-out release gates cannot report exit zero")
        if self.status is not ReleaseGateStatus.BLOCKED_TECHNICAL and (
            self.tool_version is None or self.tool_executable_sha256 is None
        ):
            raise ValueError("executed release gates require a measured tool identity")

        if self.status is ReleaseGateStatus.PASSED:
            if (
                self.execution_evidence is not ExecutionEvidenceKind.REAL
                or self.exit_code != 0
                or self.timed_out
                or self.prerequisite_blocker is not None
                or not self.artifact_bindings
            ):
                raise ValueError(
                    "passed release gates require real successful execution and artifact evidence"
                )
        elif self.status is ReleaseGateStatus.BLOCKED_TECHNICAL:
            if self.prerequisite_blocker is None:
                raise ValueError("blocked release gates require a prerequisite blocker")
            if self.exit_code is not None or self.timed_out:
                raise ValueError("terminal release gate execution cannot be classified as blocked")
        else:
            if self.prerequisite_blocker is not None:
                raise ValueError("failed release gates cannot claim a prerequisite blocker")
            if not self.timed_out and self.exit_code in {None, 0}:
                raise ValueError("failed release gates require a nonzero exit or timeout")
        return self


class ReleaseGateReceipt(ReleaseGateReceiptPayload):
    """One immutable-by-hash runtime receipt."""

    receipt_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def receipt_hash_is_consistent(self) -> ReleaseGateReceipt:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"receipt_sha256"}))
        if self.receipt_sha256 != expected:
            raise ValueError("release gate receipt hash is inconsistent")
        return self


class ReleaseGateEvidenceBundlePayload(StrictModel):
    """Canonical fixed-gate receipt set for one release candidate and run."""

    schema_version: Literal["1.0"]
    generated_by: Literal["mmaudit"]
    candidate_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    run_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    receipts: tuple[ReleaseGateReceipt, ...] = Field(
        min_length=_REQUIRED_GATE_COUNT,
        max_length=_REQUIRED_GATE_COUNT,
    )
    receipt_set_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def gate_set_and_hash_are_consistent(self) -> ReleaseGateEvidenceBundlePayload:
        gate_ids = [receipt.gate_id for receipt in self.receipts]
        expected_gate_ids = sorted(ReleaseGateId, key=lambda gate_id: gate_id.value)
        if gate_ids != expected_gate_ids or len(set(gate_ids)) != _REQUIRED_GATE_COUNT:
            raise ValueError("release gate bundle must cover every gate exactly once and sorted")
        if any(
            receipt.candidate_observation_sha256 != self.candidate_observation_sha256
            or receipt.run_binding_sha256 != self.run_binding_sha256
            or receipt.fixed_plan_sha256 != release_gate_fixed_plan_sha256(receipt.gate_id)
            for receipt in self.receipts
        ):
            raise ValueError(
                "release gate receipts are not bound to the bundle candidate, run, and plans"
            )
        unique_bindings: dict[str, ManifestFileBinding] = {}
        for receipt in self.receipts:
            for binding in receipt.artifact_bindings:
                prior = unique_bindings.get(binding.path)
                if prior is not None and prior != binding:
                    raise ValueError("release gates contain conflicting artifact bindings")
                unique_bindings[binding.path] = binding
        if len(unique_bindings) > _MAX_BUNDLE_ARTIFACTS:
            raise ValueError("release gate bundle exceeds its unique-artifact bound")
        if sum(binding.size for binding in unique_bindings.values()) > _MAX_BUNDLE_ARTIFACT_BYTES:
            raise ValueError("release gate bundle exceeds its aggregate artifact-byte bound")
        expected_receipt_set = canonical_sha256(
            [
                {
                    "gate_id": receipt.gate_id.value,
                    "receipt_sha256": receipt.receipt_sha256,
                }
                for receipt in self.receipts
            ]
        )
        if self.receipt_set_sha256 != expected_receipt_set:
            raise ValueError("release gate receipt-set hash is inconsistent")
        return self


class ReleaseGateEvidenceBundle(ReleaseGateEvidenceBundlePayload):
    """Self-hashed fixed release-gate evidence bundle."""

    bundle_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def bundle_hash_is_consistent(self) -> ReleaseGateEvidenceBundle:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"bundle_sha256"}))
        if self.bundle_sha256 != expected:
            raise ValueError("release gate bundle hash is inconsistent")
        return self


_BOUND_GATE_SEMANTIC_CONTRACTS: dict[ReleaseGateId, str] = {
    ReleaseGateId.ARTIFACTS: (
        "observe the exact emitted artifact set and require every declared size and SHA-256"
    ),
    ReleaseGateId.BENCHMARK_CERTIFICATE: (
        "verify a current nonempty benchmark certificate against the exact candidate bindings"
    ),
    ReleaseGateId.DOCTOR: (
        "execute real prerequisite diagnostics without disclosing credentials or promoting blockers"
    ),
    ReleaseGateId.MANIFESTS: (
        "verify reconstructable run manifests and their exact effective configuration bindings"
    ),
    ReleaseGateId.MAXIMUM_ASSURANCE_RUN: (
        "require requested and achieved maximum-assurance with every mandatory clause satisfied"
    ),
    ReleaseGateId.MODEL_BENCHMARK: (
        "require a real nonempty exact-model benchmark bound to current qualification evidence"
    ),
    ReleaseGateId.REPLAY: (
        "require real isolated deterministic replay with source and runtime identity preserved"
    ),
    ReleaseGateId.SCHEMAS: (
        "validate every published schema and static release corpus with nonempty denominators"
    ),
}
_LOCAL_GATE_PLAN_SPECS: dict[
    ReleaseGateId,
    tuple[str, tuple[str, ...], int, str | None, str],
] = {
    ReleaseGateId.RUFF_FORMAT: (
        "ruff",
        ("format", "--check", "."),
        300,
        None,
        "run the exact local command python -P -m ruff format --check . and require exit zero",
    ),
    ReleaseGateId.RUFF_CHECK: (
        "ruff",
        ("check", "."),
        300,
        None,
        "run the exact local command python -P -m ruff check . and require exit zero",
    ),
    ReleaseGateId.MYPY: (
        "mypy",
        (),
        600,
        None,
        "run the exact local command python -P -m mypy and require exit zero",
    ),
    ReleaseGateId.PYTEST: (
        "pytest",
        (
            "-q",
            "--junitxml",
            "{evidence_root}/release-gate-pytest-junit.xml",
        ),
        1_800,
        "release-gate-pytest-junit.xml",
        "run python -P -m pytest -q with fixed JUnit evidence and require a nonempty valid suite",
    ),
}
_LOCAL_CHILD_ENVIRONMENT_CONTRACT: dict[str, str] = {
    "ALL_PROXY": "http://127.0.0.1:9",
    "CI": "true",
    "GIT_CONFIG_GLOBAL": "{devnull}",
    "GIT_CONFIG_NOSYSTEM": "1",
    "HOME": "{runtime_root}/home",
    "HTTPS_PROXY": "http://127.0.0.1:9",
    "HTTP_PROXY": "http://127.0.0.1:9",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "NO_COLOR": "1",
    "NO_PROXY": "",
    "PATH": "{python_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
    "PIP_CONFIG_FILE": "{devnull}",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
    "PYTHONNOUSERSITE": "1",
    "PYTHONPATH": "{network_guard_root}",
    "PYTHONSAFEPATH": "1",
    "TMPDIR": "{runtime_root}/tmp",
    "XDG_CACHE_HOME": "{runtime_root}/cache",
    "all_proxy": "http://127.0.0.1:9",
    "http_proxy": "http://127.0.0.1:9",
    "https_proxy": "http://127.0.0.1:9",
    "no_proxy": "",
}
_LOCAL_NETWORK_GUARD_SOURCE = b'''"""Deny network operations in fixed mmaudit release-gate children."""

import _socket as _raw_socket
import socket as _socket

_OriginalRawSocket = _raw_socket.socket
_OriginalSocket = _socket.socket


def _deny_network(*_args, **_kwargs):
    raise PermissionError("network access is disabled for this release gate")


class _NetworkDenyMixin:
    def connect(self, *_args, **_kwargs):
        return _deny_network()

    def connect_ex(self, *_args, **_kwargs):
        return _deny_network()

    def bind(self, *_args, **_kwargs):
        return _deny_network()

    def listen(self, *_args, **_kwargs):
        return _deny_network()

    def accept(self, *_args, **_kwargs):
        return _deny_network()

    def sendto(self, *_args, **_kwargs):
        return _deny_network()

    def sendmsg(self, *_args, **_kwargs):
        return _deny_network()


class _RawNetworkDeniedSocket(_NetworkDenyMixin, _OriginalRawSocket):
    pass


class _NetworkDeniedSocket(_NetworkDenyMixin, _OriginalSocket):
    pass


_socket.socket = _NetworkDeniedSocket
_socket.SocketType = _RawNetworkDeniedSocket
_raw_socket.socket = _RawNetworkDeniedSocket
for _name in (
    "create_connection",
    "create_server",
    "getaddrinfo",
    "gethostbyaddr",
    "gethostbyname",
    "gethostbyname_ex",
    "getnameinfo",
):
    if hasattr(_socket, _name):
        setattr(_socket, _name, _deny_network)
'''


def get_release_gate_child_environment_contract(
    gate_id: ReleaseGateId,
) -> dict[str, str]:
    """Return the exact normalized child environment for a fixed local gate."""

    if gate_id not in _LOCAL_GATE_PLAN_SPECS:
        raise ValueError("release gate has no fixed local child environment")
    return dict(_LOCAL_CHILD_ENVIRONMENT_CONTRACT)


def get_release_gate_network_guard_source(gate_id: ReleaseGateId) -> bytes:
    """Return the exact sitecustomize source bound by a fixed local gate plan."""

    if gate_id not in _LOCAL_GATE_PLAN_SPECS:
        raise ValueError("release gate has no fixed local network guard")
    return bytes(_LOCAL_NETWORK_GUARD_SOURCE)


def get_release_gate_fixed_plan(gate_id: ReleaseGateId) -> ReleaseGateFixedPlan:
    """Return the only accepted semantic plan for one release gate."""

    if gate_id in _LOCAL_GATE_PLAN_SPECS:
        module, arguments, timeout_seconds, supplemental, semantic_contract = (
            _LOCAL_GATE_PLAN_SPECS[gate_id]
        )
        executor = ReleaseGatePlanExecutor.FIXED_LOCAL_PYTHON_MODULE
        python_safe_path: Literal[True] | None = True
        child_environment_contract_sha256 = canonical_sha256(
            get_release_gate_child_environment_contract(gate_id)
        )
        network_guard_sha256 = hashlib.sha256(
            get_release_gate_network_guard_source(gate_id)
        ).hexdigest()
    else:
        try:
            semantic_contract = _BOUND_GATE_SEMANTIC_CONTRACTS[gate_id]
        except KeyError as exc:
            raise ValueError("release gate has no fixed semantic contract") from exc
        module = None
        arguments = ()
        timeout_seconds = None
        supplemental = None
        executor = ReleaseGatePlanExecutor.BOUND_RUNTIME_OBSERVATION
        python_safe_path = None
        child_environment_contract_sha256 = None
        network_guard_sha256 = None
    payload = ReleaseGateFixedPlanPayload(
        schema_version="1.0",
        generated_by="mmaudit",
        gate_id=gate_id,
        executor=executor,
        semantic_contract=semantic_contract,
        module=module,
        arguments=arguments,
        timeout_seconds=timeout_seconds,
        max_output_bytes=_MAX_CAPTURE_BYTES,
        python_safe_path=python_safe_path,
        child_environment_contract_sha256=child_environment_contract_sha256,
        network_guard_sha256=network_guard_sha256,
        result_artifact_path=f"release-gate-{gate_id.value}-result.json",
        supplemental_artifact_path=supplemental,
        network_allowed=False,
    )
    serialized = payload.model_dump(mode="json")
    return ReleaseGateFixedPlan.model_validate(
        {
            **serialized,
            "fixed_plan_sha256": canonical_sha256(serialized),
        }
    )


def release_gate_fixed_plan_sha256(gate_id: ReleaseGateId) -> str:
    """Return the canonical fixed-plan digest required by every receipt."""

    return get_release_gate_fixed_plan(gate_id).fixed_plan_sha256


def build_release_gate_receipt(
    *,
    gate_id: ReleaseGateId,
    candidate_observation_sha256: str,
    run_binding_sha256: str,
    fixed_plan_sha256: str,
    started_at: datetime,
    ended_at: datetime,
    argv: Sequence[str],
    tool_name: str,
    tool_version: str | None,
    tool_executable_sha256: str | None,
    execution_evidence: ExecutionEvidenceKind,
    exit_code: int | None,
    timed_out: bool,
    stdout: bytes,
    stderr: bytes,
    summary: str,
    prerequisite_blocker: ReleaseGatePrerequisiteBlocker | None,
    artifact_bindings: Sequence[ManifestFileBinding],
    tool_distribution_sha256: str | None = None,
    checks_total: int | None = None,
    checks_passed: int | None = None,
    checks_failed: int | None = None,
) -> ReleaseGateReceipt:
    """Build one bounded receipt and derive its status and integrity hashes."""

    if len(stdout) > _MAX_CAPTURE_BYTES or len(stderr) > _MAX_CAPTURE_BYTES:
        raise ValueError("release gate captured output exceeds its bound")
    status = _derive_status(
        execution_evidence=execution_evidence,
        exit_code=exit_code,
        timed_out=timed_out,
        prerequisite_blocker=prerequisite_blocker,
        has_artifacts=bool(artifact_bindings),
    )
    result_kind = _result_kind(status=status, timed_out=timed_out)
    total, passed, failed = _normalize_check_counts(
        kind=result_kind,
        checks_total=checks_total,
        checks_passed=checks_passed,
        checks_failed=checks_failed,
    )
    result_summary = ReleaseGateResultSummary(
        kind=result_kind,
        summary=summary,
        checks_total=total,
        checks_passed=passed,
        checks_failed=failed,
    )
    normalized_argv = tuple(argv)
    payload = ReleaseGateReceiptPayload(
        schema_version="1.0",
        generated_by="mmaudit",
        gate_id=gate_id,
        candidate_observation_sha256=candidate_observation_sha256,
        run_binding_sha256=run_binding_sha256,
        fixed_plan_sha256=fixed_plan_sha256,
        status=status,
        started_at=started_at,
        ended_at=ended_at,
        argv=normalized_argv,
        argv_sha256=canonical_sha256(list(normalized_argv)),
        tool_name=tool_name,
        tool_version=tool_version,
        tool_executable_sha256=tool_executable_sha256,
        tool_distribution_sha256=tool_distribution_sha256,
        execution_evidence=execution_evidence,
        exit_code=exit_code,
        timed_out=timed_out,
        stdout_size=len(stdout),
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_size=len(stderr),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        result_summary=result_summary,
        prerequisite_blocker=prerequisite_blocker,
        artifact_bindings=sorted(artifact_bindings, key=lambda binding: binding.path),
    )
    serialized = payload.model_dump(mode="json")
    return ReleaseGateReceipt.model_validate(
        {
            **serialized,
            "receipt_sha256": canonical_sha256(serialized),
        }
    )


def build_release_gate_evidence_bundle(
    *,
    candidate_observation_sha256: str,
    run_binding_sha256: str,
    receipts: Sequence[ReleaseGateReceipt],
) -> ReleaseGateEvidenceBundle:
    """Build an exact, sorted receipt bundle for all fixed release gates."""

    ordered = tuple(sorted(receipts, key=lambda receipt: receipt.gate_id.value))
    receipt_set_sha256 = canonical_sha256(
        [
            {
                "gate_id": receipt.gate_id.value,
                "receipt_sha256": receipt.receipt_sha256,
            }
            for receipt in ordered
        ]
    )
    payload = ReleaseGateEvidenceBundlePayload(
        schema_version="1.0",
        generated_by="mmaudit",
        candidate_observation_sha256=candidate_observation_sha256,
        run_binding_sha256=run_binding_sha256,
        receipts=ordered,
        receipt_set_sha256=receipt_set_sha256,
    )
    serialized = payload.model_dump(mode="json")
    return ReleaseGateEvidenceBundle.model_validate(
        {
            **serialized,
            "bundle_sha256": canonical_sha256(serialized),
        }
    )


def validate_release_gate_evidence_bundle(
    bundle: ReleaseGateEvidenceBundle,
    *,
    evidence_root: Path,
) -> ReleaseGateEvidenceBundle:
    """Resolve artifacts through held directory descriptors beneath one explicit root."""

    validated = ReleaseGateEvidenceBundle.model_validate(bundle.model_dump(mode="json"))
    root_path, root_descriptor, root_identity = _open_unlinked_directory(evidence_root)
    try:
        observations: dict[str, _FileObservation] = {}
        observed_identities: dict[tuple[int, int], str] = {}
        for receipt in validated.receipts:
            for binding in receipt.artifact_bindings:
                if binding.path in observations:
                    continue
                observation = _read_unique_regular_file_at(root_descriptor, binding.path)
                if observation.size != binding.size or observation.sha256 != binding.sha256:
                    raise ValueError(f"release gate artifact hash mismatch: {binding.path}")
                file_identity = observation.identity[:2]
                aliased_path = observed_identities.get(file_identity)
                if aliased_path is not None and aliased_path != binding.path:
                    raise ValueError("release gate artifact paths alias the same file")
                observed_identities[file_identity] = binding.path
                observations[binding.path] = observation

        final_root_path, final_root_descriptor, final_root_identity = _open_unlinked_directory(
            evidence_root
        )
        try:
            if final_root_path != root_path or final_root_identity != root_identity:
                raise ValueError("release gate evidence root changed during validation")
            for relative_path, initial in observations.items():
                held_root_final = _read_unique_regular_file_at(
                    root_descriptor,
                    relative_path,
                )
                current_root_final = _read_unique_regular_file_at(
                    final_root_descriptor,
                    relative_path,
                )
                if held_root_final != initial or current_root_final != initial:
                    raise ValueError(
                        f"release gate artifact changed during validation: {relative_path}"
                    )
        finally:
            os.close(final_root_descriptor)
    finally:
        os.close(root_descriptor)
    return validated


def _derive_status(
    *,
    execution_evidence: ExecutionEvidenceKind,
    exit_code: int | None,
    timed_out: bool,
    prerequisite_blocker: ReleaseGatePrerequisiteBlocker | None,
    has_artifacts: bool,
) -> ReleaseGateStatus:
    if timed_out or exit_code not in {None, 0}:
        return ReleaseGateStatus.FAILED
    if prerequisite_blocker is not None:
        return ReleaseGateStatus.BLOCKED_TECHNICAL
    if exit_code != 0:
        raise ValueError("release gate has no terminal execution result")
    if execution_evidence is not ExecutionEvidenceKind.REAL:
        raise ValueError("mock or unverified execution cannot pass a release gate")
    if not has_artifacts:
        raise ValueError("passed release gates require artifact evidence")
    return ReleaseGateStatus.PASSED


def _result_kind(
    *,
    status: ReleaseGateStatus,
    timed_out: bool,
) -> ReleaseGateResultKind:
    if status is ReleaseGateStatus.PASSED:
        return ReleaseGateResultKind.PASSED
    if status is ReleaseGateStatus.BLOCKED_TECHNICAL:
        return ReleaseGateResultKind.BLOCKED_TECHNICAL
    return ReleaseGateResultKind.TIMED_OUT if timed_out else ReleaseGateResultKind.FAILED


def _normalize_check_counts(
    *,
    kind: ReleaseGateResultKind,
    checks_total: int | None,
    checks_passed: int | None,
    checks_failed: int | None,
) -> tuple[int, int, int]:
    default = {
        ReleaseGateResultKind.PASSED: (1, 1, 0),
        ReleaseGateResultKind.FAILED: (1, 0, 1),
        ReleaseGateResultKind.TIMED_OUT: (1, 0, 1),
        ReleaseGateResultKind.BLOCKED_TECHNICAL: (0, 0, 0),
    }[kind]
    supplied = (checks_total, checks_passed, checks_failed)
    if all(value is None for value in supplied):
        return default
    if checks_total is None or checks_passed is None or checks_failed is None:
        raise ValueError("release gate check counts must be supplied together")
    return checks_total, checks_passed, checks_failed


class _FileObservation(StrictModel):
    size: int
    sha256: str
    identity: tuple[int, int, int, int, int, int, int]


def _open_unlinked_directory(
    path: Path,
) -> tuple[Path, int, tuple[int, int, int, int, int, int, int]]:
    """Open every root component with no-follow semantics and retain the final fd."""

    absolute = Path(os.path.abspath(path))
    flags = _directory_open_flags()
    descriptor: int | None = None
    try:
        descriptor = os.open(absolute.anchor, flags)
        for part in absolute.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise ValueError(
            "release gate evidence root may not traverse a link or be unavailable"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise ValueError("release gate evidence root must be a directory")
    return absolute, descriptor, _stat_identity(metadata)


def _read_unique_regular_file_at(root_descriptor: int, relative_path: str) -> _FileObservation:
    """Hash one artifact using descriptor-relative no-follow component traversal."""

    parts = PurePosixPath(relative_path).parts
    if not parts:
        raise ValueError("release gate artifact path is empty")
    directory_descriptor = os.dup(root_descriptor)
    file_descriptor: int | None = None
    try:
        for part in parts[:-1]:
            before_directory = _stat_at(
                directory_descriptor,
                part,
                relative_path=relative_path,
            )
            if stat.S_ISLNK(before_directory.st_mode):
                raise ValueError("release gate artifact path may not traverse a link")
            if not stat.S_ISDIR(before_directory.st_mode):
                raise ValueError("release gate artifact parent must be a directory")
            try:
                child = os.open(
                    part,
                    _directory_open_flags(),
                    dir_fd=directory_descriptor,
                )
            except OSError as exc:
                raise ValueError("release gate artifact parent changed while opening") from exc
            opened_directory = os.fstat(child)
            if _stat_identity(before_directory) != _stat_identity(opened_directory):
                os.close(child)
                raise ValueError("release gate artifact parent changed while opening")
            os.close(directory_descriptor)
            directory_descriptor = child

        filename = parts[-1]
        before = _stat_at(
            directory_descriptor,
            filename,
            relative_path=relative_path,
        )
        if stat.S_ISLNK(before.st_mode):
            raise ValueError("release gate artifact path may not traverse a link")
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > _MAX_GATE_ARTIFACT_BYTES
        ):
            raise ValueError("release gate artifact must be a bounded unshared regular file")
        try:
            file_descriptor = os.open(
                filename,
                _file_open_flags(),
                dir_fd=directory_descriptor,
            )
        except OSError as exc:
            raise ValueError("release gate artifact could not be opened safely") from exc
        opened = os.fstat(file_descriptor)
        if _stat_identity(before) != _stat_identity(opened):
            raise ValueError("release gate artifact changed while being opened")

        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(
                file_descriptor,
                min(1024 * 1024, _MAX_GATE_ARTIFACT_BYTES + 1 - size),
            )
            if not chunk:
                break
            size += len(chunk)
            if size > _MAX_GATE_ARTIFACT_BYTES:
                raise ValueError("release gate artifact exceeds its read bound")
            digest.update(chunk)
        finished = os.fstat(file_descriptor)
        after = _stat_at(
            directory_descriptor,
            filename,
            relative_path=relative_path,
        )
        identities = {
            _stat_identity(before),
            _stat_identity(opened),
            _stat_identity(finished),
            _stat_identity(after),
        }
        if len(identities) != 1 or size != before.st_size:
            raise ValueError("release gate artifact changed while being read")
        return _FileObservation(
            size=size,
            sha256=digest.hexdigest(),
            identity=_stat_identity(after),
        )
    except OSError as exc:
        raise ValueError("release gate artifact could not be read safely") from exc
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        os.close(directory_descriptor)


def _stat_at(
    directory_descriptor: int,
    name: str,
    *,
    relative_path: str,
) -> os.stat_result:
    try:
        return os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise ValueError(f"release gate artifact is missing: {relative_path}") from exc


def _directory_open_flags() -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if not isinstance(no_follow, int) or not isinstance(directory, int):
        raise ValueError("descriptor-relative no-follow directory access is unavailable")
    close_exec = getattr(os, "O_CLOEXEC", 0)
    if not isinstance(close_exec, int):
        raise ValueError("close-on-exec file access is unavailable")
    return os.O_RDONLY | no_follow | directory | close_exec


def _file_open_flags() -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(no_follow, int):
        raise ValueError("descriptor-relative no-follow file access is unavailable")
    close_exec = getattr(os, "O_CLOEXEC", 0)
    if not isinstance(close_exec, int):
        raise ValueError("close-on-exec file access is unavailable")
    return os.O_RDONLY | no_follow | close_exec


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
