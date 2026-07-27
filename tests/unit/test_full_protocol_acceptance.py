from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.config import AuditConfig
from mmaudit.full_protocol_acceptance import (
    FullProtocolAcceptanceManifest,
    FullProtocolAcceptanceReport,
    FullProtocolAcceptanceStatus,
    FullProtocolCheckId,
    build_full_protocol_acceptance_report,
    load_full_protocol_acceptance_manifest,
    write_full_protocol_acceptance_report,
)
from mmaudit.models.schemas import (
    AuditScopeAssessment,
    PriorAuditComparison,
    PriorAuditRemediationStatus,
)
from mmaudit.orchestration.prior_audit import (
    build_prior_audit_comparison,
    withhold_prior_audit_from_discovery,
)
from mmaudit.orchestration.scope import assess_audit_scope
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.snapshots.compare import (
    DeploymentSnapshotComparisonReport,
    compare_deployment_snapshot,
    load_compiler_contract_artifacts,
)
from mmaudit.snapshots.schema import (
    DeploymentSnapshot,
    DeploymentSnapshotPayload,
    load_deployment_snapshot,
    seal_deployment_snapshot,
)
from mmaudit.solidity.projects import discover_solidity_projects

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "full_protocol_offline"
MANIFEST_PATH = FIXTURE / "manifest.json"


def _evidence(
    config_factory: Callable[..., AuditConfig],
    *,
    root: Path = FIXTURE,
) -> tuple[
    FullProtocolAcceptanceManifest,
    DeploymentSnapshot,
    DeploymentSnapshotComparisonReport,
    AuditScopeAssessment,
    PriorAuditComparison,
]:
    manifest = load_full_protocol_acceptance_manifest(root / "manifest.json")
    config = config_factory(
        repository={"include_docs": True, "include_tests": True},
        scope={"mode": "full-protocol", "require_complete": True},
        prior_audit={
            "path": manifest.expectations.prior_audit_path,
            "required": True,
            "fail_on_missed": False,
        },
    )
    unfiltered = discover_repository(root, config.repository, IgnoreMatcher())
    discovery, withheld = withhold_prior_audit_from_discovery(
        unfiltered,
        config.prior_audit.path,
    )
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    scope = assess_audit_scope(
        discovery,
        projects,
        config.scope,
        include_docs=config.repository.include_docs,
        include_tests=config.repository.include_tests,
    )
    prior = build_prior_audit_comparison(
        repository_root=root,
        config=config.prior_audit,
        discovery=discovery,
        candidates=[],
        candidate_validations={},
        findings=[],
        model_request_count_before_load=0,
        prior_material_withheld_from_discovery=withheld,
    )
    snapshot = load_deployment_snapshot(root / manifest.expectations.snapshot_path)
    artifacts = load_compiler_contract_artifacts(
        root,
        [Path(manifest.expectations.compiler_artifact_path)],
    )
    comparison = compare_deployment_snapshot(snapshot, artifacts)
    return manifest, snapshot, comparison, scope, prior


def _report(
    config_factory: Callable[..., AuditConfig],
) -> FullProtocolAcceptanceReport:
    manifest, snapshot, comparison, scope, prior = _evidence(config_factory)
    return build_full_protocol_acceptance_report(
        manifest=manifest,
        snapshot=snapshot,
        comparison=comparison,
        scope=scope,
        prior_audit=prior,
        live_network_contacted=False,
        model_provider_contacted=False,
    )


def _reseal_snapshot(
    snapshot: DeploymentSnapshot,
    *,
    section: str,
    index: int,
    update: dict[str, object],
) -> DeploymentSnapshot:
    payload = snapshot.model_dump(mode="json", exclude={"snapshot_sha256"})
    observations = payload[section]
    assert isinstance(observations, list)
    item = observations[index]
    assert isinstance(item, dict)
    item.update(update)
    return seal_deployment_snapshot(DeploymentSnapshotPayload.model_validate(payload))


def test_manifest_is_exact_source_bound_and_self_hashed() -> None:
    manifest = load_full_protocol_acceptance_manifest(MANIFEST_PATH)

    assert len(manifest.fixture_files) == 9
    assert {item.path for item in manifest.fixture_files} == {
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
    source = next(
        item for item in manifest.fixture_files if item.path == manifest.expectations.source_path
    )
    assert source.sha256 == "6f7fdbefaa96a4dc7c9077bcda4123eee14d77d4c78bf160724f990e4b5f784c"


def test_complete_offline_evidence_produces_normalized_passing_report(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
) -> None:
    report = _report(config_factory)

    assert report.status is FullProtocolAcceptanceStatus.PASSED
    assert report.passed_checks == report.total_checks == 10
    assert report.failed_checks == []
    assert report.source_bound_contracts_matched == report.source_bound_contracts == 1
    assert report.prior_findings_remediated == report.prior_findings == 1
    assert not report.live_network_contacted
    assert not report.model_provider_contacted

    output = tmp_path / "full-protocol-acceptance.json"
    write_full_protocol_acceptance_report(output, report)
    assert (
        FullProtocolAcceptanceReport.model_validate_json(output.read_text(encoding="utf-8"))
        == report
    )


def test_source_binding_drift_fails_without_changing_deployment_result(
    config_factory: Callable[..., AuditConfig],
) -> None:
    manifest, snapshot, comparison, scope, prior = _evidence(config_factory)
    binding = snapshot.contracts[0].source_binding
    assert binding is not None
    changed_binding = binding.model_copy(update={"source_sha256": "0" * 64})
    changed = _reseal_snapshot(
        snapshot,
        section="contracts",
        index=0,
        update={"source_binding": changed_binding.model_dump(mode="json")},
    )
    report = build_full_protocol_acceptance_report(
        manifest=manifest,
        snapshot=changed,
        comparison=compare_deployment_snapshot(
            changed,
            load_compiler_contract_artifacts(
                FIXTURE,
                [Path(manifest.expectations.compiler_artifact_path)],
            ),
        ),
        scope=scope,
        prior_audit=prior,
        live_network_contacted=False,
        model_provider_contacted=False,
    )

    assert comparison.status.value == "matched"
    assert report.status is FullProtocolAcceptanceStatus.FAILED
    assert report.failed_checks == [FullProtocolCheckId.SOURCE_BINDING]


@pytest.mark.parametrize(
    ("section", "index", "update", "failed_check"),
    [
        (
            "roles",
            0,
            {"members": ["0xcccccccccccccccccccccccccccccccccccccccc"]},
            FullProtocolCheckId.ADMIN_ROLE,
        ),
        (
            "roles",
            1,
            {"members": ["0xcccccccccccccccccccccccccccccccccccccccc"]},
            FullProtocolCheckId.RELAYER_ASSUMPTION,
        ),
        (
            "timelocks",
            0,
            {"minimum_delay_seconds": 1},
            FullProtocolCheckId.TIMELOCK_CONFIGURATION,
        ),
        (
            "oracles",
            0,
            {"heartbeat_seconds": 1},
            FullProtocolCheckId.ORACLE_CONFIGURATION,
        ),
    ],
)
def test_authority_and_configuration_mismatches_fail_the_named_check(
    config_factory: Callable[..., AuditConfig],
    section: str,
    index: int,
    update: dict[str, object],
    failed_check: FullProtocolCheckId,
) -> None:
    manifest, snapshot, _, scope, prior = _evidence(config_factory)
    changed = _reseal_snapshot(
        snapshot,
        section=section,
        index=index,
        update=update,
    )
    comparison = compare_deployment_snapshot(
        changed,
        load_compiler_contract_artifacts(
            FIXTURE,
            [Path(manifest.expectations.compiler_artifact_path)],
        ),
    )
    report = build_full_protocol_acceptance_report(
        manifest=manifest,
        snapshot=changed,
        comparison=comparison,
        scope=scope,
        prior_audit=prior,
        live_network_contacted=False,
        model_provider_contacted=False,
    )

    assert report.status is FullProtocolAcceptanceStatus.FAILED
    assert failed_check in report.failed_checks


def test_incomplete_scope_blinding_or_remediation_fails_closed(
    config_factory: Callable[..., AuditConfig],
) -> None:
    manifest, snapshot, comparison, scope, prior = _evidence(config_factory)
    incomplete_config = config_factory(
        repository={"include_docs": False, "include_tests": True},
        scope={"mode": "full-protocol", "require_complete": True},
        prior_audit={"path": manifest.expectations.prior_audit_path, "required": True},
    )
    incomplete_discovery = discover_repository(
        FIXTURE,
        incomplete_config.repository,
        IgnoreMatcher(),
    )
    incomplete_discovery, _ = withhold_prior_audit_from_discovery(
        incomplete_discovery,
        incomplete_config.prior_audit.path,
    )
    incomplete_projects = discover_solidity_projects(
        incomplete_discovery,
        incomplete_config.smart_contracts,
    )
    incomplete_scope = assess_audit_scope(
        incomplete_discovery,
        incomplete_projects,
        incomplete_config.scope,
        include_docs=incomplete_config.repository.include_docs,
        include_tests=incomplete_config.repository.include_tests,
    )
    scope_report = build_full_protocol_acceptance_report(
        manifest=manifest,
        snapshot=snapshot,
        comparison=comparison,
        scope=incomplete_scope,
        prior_audit=prior,
        live_network_contacted=False,
        model_provider_contacted=False,
    )
    assert FullProtocolCheckId.FULL_PROTOCOL_SCOPE in scope_report.failed_checks

    item_payload = prior.items[0].model_dump(mode="json")
    item_payload["remediation_status"] = PriorAuditRemediationStatus.CHANGED_UNVERIFIED
    prior_payload = prior.model_dump(mode="json")
    prior_payload["items"] = [item_payload]
    changed_prior = PriorAuditComparison.model_validate(prior_payload)
    remediation_report = build_full_protocol_acceptance_report(
        manifest=manifest,
        snapshot=snapshot,
        comparison=comparison,
        scope=scope,
        prior_audit=changed_prior,
        live_network_contacted=False,
        model_provider_contacted=False,
    )
    assert remediation_report.failed_checks == [FullProtocolCheckId.PRIOR_REMEDIATION]

    failed_load = PriorAuditComparison(
        configured=True,
        required=True,
        loaded=False,
        source_path=manifest.expectations.prior_audit_path,
        prior_material_withheld_from_discovery=False,
        blind_discovery_completed_before_load=True,
        errors=["synthetic prior input unavailable"],
    )
    blinding_report = build_full_protocol_acceptance_report(
        manifest=manifest,
        snapshot=snapshot,
        comparison=comparison,
        scope=scope,
        prior_audit=failed_load,
        live_network_contacted=False,
        model_provider_contacted=False,
    )
    assert FullProtocolCheckId.PRIOR_BLINDING in blinding_report.failed_checks
    assert FullProtocolCheckId.PRIOR_REMEDIATION in blinding_report.failed_checks


def test_network_or_model_contact_cannot_pass_offline_acceptance(
    config_factory: Callable[..., AuditConfig],
) -> None:
    manifest, snapshot, comparison, scope, prior = _evidence(config_factory)
    report = build_full_protocol_acceptance_report(
        manifest=manifest,
        snapshot=snapshot,
        comparison=comparison,
        scope=scope,
        prior_audit=prior,
        live_network_contacted=True,
        model_provider_contacted=False,
    )

    assert report.status is FullProtocolAcceptanceStatus.FAILED
    assert report.failed_checks == [FullProtocolCheckId.OFFLINE_EXECUTION]


def test_manifest_tamper_content_drift_extra_files_and_links_are_rejected(
    tmp_path: Path,
) -> None:
    payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    payload["expectations"]["minimum_delay_seconds"] = 1
    tampered = tmp_path / "manifest.json"
    tampered.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValidationError, match="manifest hash"):
        load_full_protocol_acceptance_manifest(tampered)

    copied = tmp_path / "copied"
    shutil.copytree(FIXTURE, copied)
    (copied / "src" / "FullProtocol.sol").write_text("changed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="inventory or content hash"):
        load_full_protocol_acceptance_manifest(copied / "manifest.json")

    extra = tmp_path / "extra"
    shutil.copytree(FIXTURE, extra)
    (extra / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
    with pytest.raises(ValueError, match="inventory or content hash"):
        load_full_protocol_acceptance_manifest(extra / "manifest.json")

    linked = tmp_path / "linked-manifest.json"
    linked.symlink_to(MANIFEST_PATH)
    with pytest.raises(ValueError, match="regular non-link"):
        load_full_protocol_acceptance_manifest(linked)


def test_report_tamper_and_link_destination_are_rejected(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
) -> None:
    report = _report(config_factory)
    payload = report.model_dump(mode="json")
    payload["passed_checks"] = 0
    with pytest.raises(ValidationError, match="passed-check"):
        FullProtocolAcceptanceReport.model_validate(payload)

    target = tmp_path / "target.json"
    target.write_text("{}\n", encoding="utf-8")
    linked = tmp_path / "linked.json"
    linked.symlink_to(target)
    with pytest.raises(ValueError, match="may not be a link"):
        write_full_protocol_acceptance_report(linked, report)


def test_manifest_and_report_schemas_are_strict_and_complete() -> None:
    manifest_schema = json.loads(
        (ROOT / "schemas/full_protocol_acceptance_manifest.schema.json").read_text(encoding="utf-8")
    )
    report_schema = json.loads(
        (ROOT / "schemas/full_protocol_acceptance_report.schema.json").read_text(encoding="utf-8")
    )

    assert manifest_schema["additionalProperties"] is False
    assert manifest_schema["$defs"]["expectations"]["additionalProperties"] is False
    assert manifest_schema["$defs"]["fileBinding"]["additionalProperties"] is False
    assert set(manifest_schema["required"]) == set(FullProtocolAcceptanceManifest.model_fields)
    assert report_schema["additionalProperties"] is False
    assert report_schema["$defs"]["check"]["additionalProperties"] is False
    assert set(report_schema["required"]) == set(FullProtocolAcceptanceReport.model_fields)
