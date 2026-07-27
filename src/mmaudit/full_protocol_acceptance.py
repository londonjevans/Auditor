"""Typed offline acceptance evidence for the synthetic full-protocol fixture."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.models.schemas import (
    AuditScope,
    AuditScopeAssessment,
    PriorAuditComparison,
    PriorAuditRemediationStatus,
    StrictModel,
)
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.secrets import is_sensitive_workspace_name
from mmaudit.snapshots.compare import (
    DeploymentSnapshotComparisonReport,
    SnapshotComparisonStatus,
)
from mmaudit.snapshots.schema import DeploymentSnapshot

_MAX_MANIFEST_BYTES = 1_000_000
_MAX_FIXTURE_FILE_BYTES = 10_000_000
_MAX_FIXTURE_BYTES = 20_000_000
_MAX_REPORT_BYTES = 2_000_000
_ADDRESS_PATTERN = r"^0x[0-9a-f]{40}$"
_BYTES32_PATTERN = r"^0x[0-9a-f]{64}$"
_EXPECTED_FIXTURE_FILES = {
    "README.md",
    "audit/prior.json",
    "compiler/FullProtocol.json",
    "foundry.toml",
    "script/Deploy.s.sol",
    "service/relayer.py",
    "snapshot.json",
    "src/FullProtocol.sol",
    "test/FullProtocol.t.sol",
}


class FullProtocolAcceptanceStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"


class FullProtocolCheckId(StrEnum):
    ADMIN_ROLE = "admin_role"
    DEPLOYMENT_CONSISTENCY = "deployment_consistency"
    FULL_PROTOCOL_SCOPE = "full_protocol_scope"
    OFFLINE_EXECUTION = "offline_execution"
    ORACLE_CONFIGURATION = "oracle_configuration"
    PRIOR_BLINDING = "prior_blinding"
    PRIOR_REMEDIATION = "prior_remediation"
    RELAYER_ASSUMPTION = "relayer_assumption"
    SOURCE_BINDING = "source_binding"
    TIMELOCK_CONFIGURATION = "timelock_configuration"


class FullProtocolExpectations(StrictModel):
    """Source-bound expected observations for the synthetic offline deployment."""

    protocol_address: str = Field(pattern=_ADDRESS_PATTERN)
    source_path: Literal["src/FullProtocol.sol"]
    contract_name: Literal["FullProtocol"]
    compiler_artifact_path: Literal["compiler/FullProtocol.json"]
    snapshot_path: Literal["snapshot.json"]
    prior_audit_path: Literal["audit/prior.json"]
    admin_role_id: str = Field(pattern=_BYTES32_PATTERN)
    admin_member: str = Field(pattern=_ADDRESS_PATTERN)
    relayer_role_id: str = Field(pattern=_BYTES32_PATTERN)
    relayer_member: str = Field(pattern=_ADDRESS_PATTERN)
    timelock_address: str = Field(pattern=_ADDRESS_PATTERN)
    minimum_delay_seconds: int = Field(ge=1, le=2**64 - 1)
    oracle_address: str = Field(pattern=_ADDRESS_PATTERN)
    oracle_feed_decimals: int = Field(ge=0, le=255)
    oracle_heartbeat_seconds: int = Field(ge=1, le=2**64 - 1)
    prior_ids: list[str] = Field(min_length=1, max_length=100)

    @field_validator("prior_ids")
    @classmethod
    def prior_ids_are_sorted_unique_and_bounded(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("full-protocol prior IDs must be unique and sorted")
        if any(not item or len(item) > 160 for item in value):
            raise ValueError("full-protocol prior IDs must be bounded")
        return value


class FullProtocolAcceptanceManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    generated_by: Literal["mmaudit"] = "mmaudit"
    expectations: FullProtocolExpectations
    fixture_files: list[ManifestFileBinding] = Field(min_length=9, max_length=9)
    fixture_tree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def inventory_and_hashes_are_consistent(self) -> FullProtocolAcceptanceManifest:
        paths = [item.path for item in self.fixture_files]
        if paths != sorted(_EXPECTED_FIXTURE_FILES):
            raise ValueError("full-protocol manifest must bind the exact fixture inventory")
        serialized_files = [item.model_dump(mode="json") for item in self.fixture_files]
        if self.fixture_tree_sha256 != canonical_sha256(serialized_files):
            raise ValueError("full-protocol fixture-tree hash is inconsistent")
        referenced = {
            self.expectations.source_path,
            self.expectations.compiler_artifact_path,
            self.expectations.snapshot_path,
            self.expectations.prior_audit_path,
        }
        if not referenced <= set(paths):
            raise ValueError("full-protocol expectations reference unbound fixture files")
        expected_manifest = canonical_sha256(
            self.model_dump(mode="json", exclude={"manifest_sha256"})
        )
        if self.manifest_sha256 != expected_manifest:
            raise ValueError("full-protocol manifest hash is inconsistent")
        return self


class FullProtocolAcceptanceCheck(StrictModel):
    check_id: FullProtocolCheckId
    passed: bool
    evidence: str = Field(min_length=1, max_length=1_000)


class FullProtocolAcceptanceReportPayload(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    generated_by: Literal["mmaudit"] = "mmaudit"
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_id: str = Field(min_length=1, max_length=128)
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_comparison_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    prior_audit_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    status: FullProtocolAcceptanceStatus
    total_checks: int = Field(ge=10, le=10)
    passed_checks: int = Field(ge=0, le=10)
    failed_checks: list[FullProtocolCheckId] = Field(max_length=10)
    source_bound_contracts: int = Field(ge=0, le=10_000)
    source_bound_contracts_matched: int = Field(ge=0, le=10_000)
    prior_findings: int = Field(ge=0, le=2_000)
    prior_findings_remediated: int = Field(ge=0, le=2_000)
    live_network_contacted: bool
    model_provider_contacted: bool
    checks: list[FullProtocolAcceptanceCheck] = Field(min_length=10, max_length=10)
    limitations: list[str] = Field(max_length=20)

    @model_validator(mode="after")
    def counts_and_status_are_consistent(self) -> FullProtocolAcceptanceReportPayload:
        check_ids = [item.check_id for item in self.checks]
        if check_ids != sorted(FullProtocolCheckId, key=lambda item: item.value):
            raise ValueError("full-protocol report must cover every check exactly once")
        expected_failed = [item.check_id for item in self.checks if not item.passed]
        if self.failed_checks != expected_failed:
            raise ValueError("full-protocol failed-check accounting is inconsistent")
        if self.total_checks != len(self.checks):
            raise ValueError("full-protocol total-check accounting is inconsistent")
        if self.passed_checks != sum(item.passed for item in self.checks):
            raise ValueError("full-protocol passed-check accounting is inconsistent")
        if self.source_bound_contracts_matched > self.source_bound_contracts:
            raise ValueError("matched source-bound contracts exceed expected contracts")
        if self.prior_findings_remediated > self.prior_findings:
            raise ValueError("remediated prior findings exceed compared findings")
        offline = next(
            item for item in self.checks if item.check_id is FullProtocolCheckId.OFFLINE_EXECUTION
        )
        if offline.passed is (self.live_network_contacted or self.model_provider_contacted):
            raise ValueError("full-protocol offline-execution evidence is inconsistent")
        expected_status = (
            FullProtocolAcceptanceStatus.PASSED
            if not expected_failed
            else FullProtocolAcceptanceStatus.FAILED
        )
        if self.status is not expected_status:
            raise ValueError("full-protocol acceptance status is inconsistent")
        if self.limitations != sorted(set(self.limitations)):
            raise ValueError("full-protocol limitations must be unique and sorted")
        if any(not item or len(item) > 500 for item in self.limitations):
            raise ValueError("full-protocol limitations must be bounded")
        return self


class FullProtocolAcceptanceReport(FullProtocolAcceptanceReportPayload):
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def report_hash_matches(self) -> FullProtocolAcceptanceReport:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"report_sha256"}))
        if self.report_sha256 != expected:
            raise ValueError("full-protocol acceptance report hash is inconsistent")
        return self


def load_full_protocol_acceptance_manifest(path: Path) -> FullProtocolAcceptanceManifest:
    """Load a self-hashed full-protocol fixture inventory without following links."""

    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError("full-protocol manifest must be a regular non-link file")
    metadata = path.stat()
    if (
        metadata.st_nlink != 1
        or metadata.st_size > _MAX_MANIFEST_BYTES
        or is_sensitive_workspace_name(path.name)
    ):
        raise ValueError("full-protocol manifest must be bounded and unshared")
    manifest = FullProtocolAcceptanceManifest.model_validate_json(path.read_text(encoding="utf-8"))
    root = path.parent.resolve(strict=True)
    expected = {item.path: item for item in manifest.fixture_files}
    observed: dict[str, ManifestFileBinding] = {}
    total_bytes = 0
    for candidate in path.parent.rglob("*"):
        if candidate == path:
            continue
        if candidate.is_symlink() or candidate.is_junction():
            raise ValueError("full-protocol fixture may not contain links")
        if candidate.is_dir():
            continue
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        file_metadata = resolved.stat()
        if (
            not resolved.is_file()
            or file_metadata.st_nlink != 1
            or file_metadata.st_size > _MAX_FIXTURE_FILE_BYTES
            or is_sensitive_workspace_name(resolved.name)
        ):
            raise ValueError("full-protocol fixture must contain bounded unshared files")
        total_bytes += file_metadata.st_size
        relative = resolved.relative_to(root).as_posix()
        observed[relative] = ManifestFileBinding(
            path=relative,
            sha256=_file_sha256(resolved),
            size=file_metadata.st_size,
        )
    if total_bytes > _MAX_FIXTURE_BYTES:
        raise ValueError("full-protocol fixture exceeds its aggregate size bound")
    if observed != expected:
        raise ValueError("full-protocol fixture inventory or content hash mismatch")
    return manifest


def build_full_protocol_acceptance_report(
    *,
    manifest: FullProtocolAcceptanceManifest,
    snapshot: DeploymentSnapshot,
    comparison: DeploymentSnapshotComparisonReport,
    scope: AuditScopeAssessment,
    prior_audit: PriorAuditComparison,
    live_network_contacted: bool,
    model_provider_contacted: bool,
) -> FullProtocolAcceptanceReport:
    """Reconcile source, deployment, authority, and blind remediation evidence."""

    expected = manifest.expectations
    bindings = {item.path: item for item in manifest.fixture_files}
    protocol_contracts = [
        item for item in snapshot.contracts if item.address == expected.protocol_address
    ]
    protocol = protocol_contracts[0] if len(protocol_contracts) == 1 else None
    source_binding = protocol.source_binding if protocol is not None else None
    source_valid = (
        source_binding is not None
        and source_binding.source_path == expected.source_path
        and source_binding.contract_name == expected.contract_name
        and source_binding.source_sha256 == bindings[expected.source_path].sha256
        and source_binding.compiler_artifact_sha256
        == bindings[expected.compiler_artifact_path].sha256
    )

    deployment_valid = (
        comparison.snapshot_id == snapshot.snapshot_id
        and comparison.snapshot_sha256 == snapshot.snapshot_sha256
        and comparison.status is SnapshotComparisonStatus.MATCHED
        and comparison.contracts_expected == 1
        and comparison.contracts_compared == 1
        and comparison.contracts_matched == 1
        and len(comparison.comparisons) == 1
        and comparison.comparisons[0].address == expected.protocol_address
        and comparison.comparisons[0].source_path == expected.source_path
        and comparison.comparisons[0].contract_name == expected.contract_name
        and comparison.comparisons[0].matched
    )
    scope_valid = (
        scope.requested is AuditScope.FULL_PROTOCOL
        and scope.achieved is AuditScope.FULL_PROTOCOL
        and scope.complete
        and not scope.missing_required_components
    )

    admin_roles = [
        item
        for item in snapshot.roles
        if item.contract_address == expected.protocol_address
        and item.role_id == expected.admin_role_id
        and item.role_label == "ADMIN_ROLE"
    ]
    admin_valid = (
        len(admin_roles) == 1
        and admin_roles[0].admin_role_id == "0x" + "0" * 64
        and admin_roles[0].members == [expected.admin_member]
        and _configuration(snapshot, expected.protocol_address, "admin") == expected.admin_member
    )
    relayer_roles = [
        item
        for item in snapshot.roles
        if item.contract_address == expected.protocol_address
        and item.role_id == expected.relayer_role_id
        and item.role_label == "RELAYER_ROLE"
    ]
    relayer_valid = (
        len(relayer_roles) == 1
        and relayer_roles[0].admin_role_id == expected.admin_role_id
        and relayer_roles[0].members == [expected.relayer_member]
        and _configuration(snapshot, expected.protocol_address, "authorized_relayer")
        == expected.relayer_member
    )

    timelocks = [
        item for item in snapshot.timelocks if item.contract_address == expected.timelock_address
    ]
    timelock_valid = (
        len(timelocks) == 1
        and timelocks[0].minimum_delay_seconds == expected.minimum_delay_seconds
        and timelocks[0].proposers == [expected.admin_member]
        and timelocks[0].executors == [expected.admin_member]
        and timelocks[0].cancellers == [expected.admin_member]
        and _configuration(snapshot, expected.protocol_address, "timelock")
        == expected.timelock_address
        and _configuration(snapshot, expected.protocol_address, "minimum_delay_seconds")
        == str(expected.minimum_delay_seconds)
    )
    oracles = [
        item
        for item in snapshot.oracles
        if item.consumer_address == expected.protocol_address
        and item.feed_address == expected.oracle_address
    ]
    oracle_valid = (
        len(oracles) == 1
        and oracles[0].feed_decimals == expected.oracle_feed_decimals
        and oracles[0].heartbeat_seconds == expected.oracle_heartbeat_seconds
        and oracles[0].observed_answer > 0
        and snapshot.chain.block_timestamp - oracles[0].updated_at
        <= expected.oracle_heartbeat_seconds
        and _configuration(snapshot, expected.protocol_address, "oracle") == expected.oracle_address
        and _configuration(snapshot, expected.protocol_address, "oracle_heartbeat_seconds")
        == str(expected.oracle_heartbeat_seconds)
    )

    prior_ids = [item.prior_id for item in prior_audit.items]
    prior_blinding_valid = (
        prior_audit.configured
        and prior_audit.required
        and prior_audit.loaded
        and prior_audit.source_path == expected.prior_audit_path
        and prior_audit.source_sha256 == bindings[expected.prior_audit_path].sha256
        and prior_audit.prior_material_withheld_from_discovery
        and prior_audit.blind_discovery_completed_before_load
        and prior_audit.model_request_count_before_load == 0
        and not prior_audit.errors
    )
    remediated = [
        item
        for item in prior_audit.items
        if item.source_valid and item.remediation_status is PriorAuditRemediationStatus.REMEDIATED
    ]
    prior_remediation_valid = (
        prior_ids == expected.prior_ids
        and len(remediated) == len(prior_audit.items)
        and bool(prior_audit.items)
    )
    offline_valid = not live_network_contacted and not model_provider_contacted

    checks = sorted(
        [
            FullProtocolAcceptanceCheck(
                check_id=FullProtocolCheckId.ADMIN_ROLE,
                passed=admin_valid,
                evidence=f"member={expected.admin_member}; observations={len(admin_roles)}",
            ),
            FullProtocolAcceptanceCheck(
                check_id=FullProtocolCheckId.DEPLOYMENT_CONSISTENCY,
                passed=deployment_valid,
                evidence=(
                    f"status={comparison.status.value}; matched="
                    f"{comparison.contracts_matched}/{comparison.contracts_expected}"
                ),
            ),
            FullProtocolAcceptanceCheck(
                check_id=FullProtocolCheckId.FULL_PROTOCOL_SCOPE,
                passed=scope_valid,
                evidence=(
                    f"requested={scope.requested.value}; "
                    f"achieved={scope.achieved.value if scope.achieved is not None else 'none'}; "
                    f"complete={str(scope.complete).lower()}"
                ),
            ),
            FullProtocolAcceptanceCheck(
                check_id=FullProtocolCheckId.OFFLINE_EXECUTION,
                passed=offline_valid,
                evidence=(
                    f"live_network={str(live_network_contacted).lower()}; "
                    f"model_provider={str(model_provider_contacted).lower()}"
                ),
            ),
            FullProtocolAcceptanceCheck(
                check_id=FullProtocolCheckId.ORACLE_CONFIGURATION,
                passed=oracle_valid,
                evidence=(
                    f"feed={expected.oracle_address}; heartbeat="
                    f"{expected.oracle_heartbeat_seconds}; observations={len(oracles)}"
                ),
            ),
            FullProtocolAcceptanceCheck(
                check_id=FullProtocolCheckId.PRIOR_BLINDING,
                passed=prior_blinding_valid,
                evidence=(
                    f"withheld={str(prior_audit.prior_material_withheld_from_discovery).lower()}; "
                    "loaded_after_discovery="
                    f"{str(prior_audit.blind_discovery_completed_before_load).lower()}"
                ),
            ),
            FullProtocolAcceptanceCheck(
                check_id=FullProtocolCheckId.PRIOR_REMEDIATION,
                passed=prior_remediation_valid,
                evidence=f"remediated={len(remediated)}/{len(prior_audit.items)}",
            ),
            FullProtocolAcceptanceCheck(
                check_id=FullProtocolCheckId.RELAYER_ASSUMPTION,
                passed=relayer_valid,
                evidence=f"member={expected.relayer_member}; observations={len(relayer_roles)}",
            ),
            FullProtocolAcceptanceCheck(
                check_id=FullProtocolCheckId.SOURCE_BINDING,
                passed=source_valid,
                evidence=(
                    f"source={expected.source_path}; sha256={bindings[expected.source_path].sha256}"
                ),
            ),
            FullProtocolAcceptanceCheck(
                check_id=FullProtocolCheckId.TIMELOCK_CONFIGURATION,
                passed=timelock_valid,
                evidence=(
                    f"timelock={expected.timelock_address}; "
                    f"minimum_delay={expected.minimum_delay_seconds}; "
                    f"observations={len(timelocks)}"
                ),
            ),
        ],
        key=lambda item: item.check_id.value,
    )
    failed = [item.check_id for item in checks if not item.passed]
    payload = FullProtocolAcceptanceReportPayload(
        manifest_sha256=manifest.manifest_sha256,
        snapshot_id=snapshot.snapshot_id,
        snapshot_sha256=snapshot.snapshot_sha256,
        snapshot_comparison_sha256=comparison.report_sha256,
        prior_audit_sha256=prior_audit.source_sha256,
        status=(
            FullProtocolAcceptanceStatus.PASSED
            if not failed
            else FullProtocolAcceptanceStatus.FAILED
        ),
        total_checks=len(checks),
        passed_checks=sum(item.passed for item in checks),
        failed_checks=failed,
        source_bound_contracts=comparison.contracts_expected,
        source_bound_contracts_matched=comparison.contracts_matched,
        prior_findings=len(prior_audit.items),
        prior_findings_remediated=len(remediated),
        live_network_contacted=live_network_contacted,
        model_provider_contacted=model_provider_contacted,
        checks=checks,
        limitations=[
            "offline synthetic snapshot only; no live deployment was contacted",
            (
                "synthetic timelock and oracle bytecode are configuration evidence, "
                "not source-consistency comparisons"
            ),
        ],
    )
    serialized = payload.model_dump(mode="json")
    return FullProtocolAcceptanceReport.model_validate(
        {
            **serialized,
            "report_sha256": canonical_sha256(serialized),
        }
    )


def write_full_protocol_acceptance_report(
    path: Path,
    report: FullProtocolAcceptanceReport,
) -> None:
    """Write normalized full-protocol evidence to a bounded non-link file."""

    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to write a sensitive full-protocol report filename")
    if path.is_symlink() or path.is_junction():
        raise ValueError("full-protocol report destination may not be a link")
    if path.exists() and (
        not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > _MAX_REPORT_BYTES
    ):
        raise ValueError("full-protocol report destination must be an unshared file")
    serialized = stable_json(report)
    if len(serialized.encode("utf-8")) > _MAX_REPORT_BYTES:
        raise ValueError("full-protocol report exceeds its output bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialized, encoding="utf-8")


def _configuration(snapshot: DeploymentSnapshot, contract_address: str, key: str) -> str | None:
    values = [
        item.value
        for item in snapshot.configuration
        if item.contract_address == contract_address and item.key == key
    ]
    return values[0] if len(values) == 1 else None


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
