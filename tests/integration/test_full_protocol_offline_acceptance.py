from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from mmaudit.config import AuditConfig
from mmaudit.full_protocol_acceptance import (
    FullProtocolAcceptanceReport,
    FullProtocolAcceptanceStatus,
    build_full_protocol_acceptance_report,
    load_full_protocol_acceptance_manifest,
    write_full_protocol_acceptance_report,
)
from mmaudit.models.schemas import (
    AuditScope,
    PriorAuditDiscoveryStatus,
    PriorAuditRemediationStatus,
)
from mmaudit.orchestration.context import ContextBuilder, render_context
from mmaudit.orchestration.prior_audit import (
    build_prior_audit_comparison,
    withhold_prior_audit_from_discovery,
)
from mmaudit.orchestration.scope import assess_audit_scope
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.repository.mapping import build_repository_map
from mmaudit.scanners.base import sanitized_scanner_environment
from mmaudit.snapshots.compare import (
    SnapshotComparisonStatus,
    compare_deployment_snapshot,
    load_compiler_contract_artifacts,
)
from mmaudit.snapshots.schema import load_deployment_snapshot
from mmaudit.solidity.projects import discover_solidity_projects

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "full_protocol_offline"
_PRIOR_CANARY = "BLIND-PRIOR-RELAYER-REPLAY-CANARY"
_PROHIBITED_FIXTURE_MARKERS = (
    "ffi = true",
    "http://",
    "https://",
    "vm.ffi",
    "envaddress(",
    "envbytes(",
    "envstring(",
    "envuint(",
)


def _external_solc() -> Path | None:
    candidates = (
        Path.home() / "Library" / "Application Support" / "svm" / "0.8.20" / "solc-0.8.20",
        Path.home() / ".local" / "share" / "svm" / "0.8.20" / "solc-0.8.20",
        Path.home() / ".svm" / "0.8.20" / "solc-0.8.20",
    )
    return next(
        (
            candidate
            for candidate in candidates
            if candidate.is_file() and os.access(candidate, os.X_OK)
        ),
        None,
    )


def _assert_fixture_has_no_host_interaction_markers() -> None:
    for path in sorted(FIXTURE.rglob("*")):
        if not path.is_file():
            continue
        contents = path.read_text(encoding="utf-8").casefold()
        assert all(marker not in contents for marker in _PROHIBITED_FIXTURE_MARKERS)


def test_full_protocol_offline_snapshot_acceptance_is_blind_and_source_consistent(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
) -> None:
    forge = shutil.which("forge")
    if forge is None:
        pytest.skip("forge is not installed")
    solc = _external_solc()
    if solc is None:
        pytest.skip("external Foundry-managed solc 0.8.20 is not installed")
    forge_path = Path(forge).resolve()
    assert not forge_path.is_relative_to(FIXTURE.resolve())
    assert not solc.resolve().is_relative_to(FIXTURE.resolve())
    _assert_fixture_has_no_host_interaction_markers()

    manifest = load_full_protocol_acceptance_manifest(FIXTURE / "manifest.json")
    workspace = tmp_path / "forge"
    result = subprocess.run(
        [
            forge,
            "test",
            "--root",
            str(FIXTURE),
            "--offline",
            "--use",
            str(solc),
            "--color",
            "never",
            "--cache-path",
            str(workspace / "cache"),
            "--out",
            str(workspace / "out"),
            "-vv",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=sanitized_scanner_environment(workspace / "environment"),
    )
    foundry_output = result.stdout + result.stderr
    assert result.returncode == 0, foundry_output[-4_000:]
    assert "Suite result: ok. 3 passed; 0 failed; 0 skipped" in foundry_output

    generated_artifact = workspace / "out" / "FullProtocol.sol" / "FullProtocol.json"
    generated_payload = json.loads(generated_artifact.read_text(encoding="utf-8"))
    committed_payload = json.loads(
        (FIXTURE / manifest.expectations.compiler_artifact_path).read_text(encoding="utf-8")
    )
    committed = load_compiler_contract_artifacts(
        FIXTURE,
        [Path(manifest.expectations.compiler_artifact_path)],
    )
    assert len(committed) == 1
    assert (
        generated_payload["deployedBytecode"]["object"]
        == committed_payload["deployedBytecode"]["object"]
    )
    assert (
        generated_payload["deployedBytecode"]["linkReferences"]
        == committed_payload["deployedBytecode"]["linkReferences"]
    )
    assert generated_payload["metadata"]["compiler"] == committed_payload["metadata"]["compiler"]
    for key, value in committed_payload["metadata"]["settings"].items():
        assert generated_payload["metadata"]["settings"][key] == value

    snapshot = load_deployment_snapshot(FIXTURE / manifest.expectations.snapshot_path)
    source_binding = snapshot.contracts[0].source_binding
    assert source_binding is not None
    assert (
        source_binding.source_sha256
        == hashlib.sha256((FIXTURE / manifest.expectations.source_path).read_bytes()).hexdigest()
    )
    comparison = compare_deployment_snapshot(snapshot, committed)
    assert comparison.status is SnapshotComparisonStatus.MATCHED
    assert comparison.contracts_matched == comparison.contracts_expected == 1

    config = config_factory(
        repository={
            "include_docs": True,
            "include_tests": True,
            "max_total_context_bytes": 1_000_000,
        },
        scope={"mode": AuditScope.FULL_PROTOCOL, "require_complete": True},
        prior_audit={
            "path": manifest.expectations.prior_audit_path,
            "required": True,
            "fail_on_missed": False,
        },
    )
    unfiltered = discover_repository(FIXTURE, config.repository, IgnoreMatcher())
    assert manifest.expectations.prior_audit_path in {
        item.relative_path for item in unfiltered.files
    }
    discovery, withheld = withhold_prior_audit_from_discovery(
        unfiltered,
        config.prior_audit.path,
    )
    assert withheld
    assert manifest.expectations.prior_audit_path not in {
        item.relative_path for item in discovery.files
    }
    assert _PRIOR_CANARY not in "\n".join(item.content for item in discovery.files)

    projects = discover_solidity_projects(discovery, config.smart_contracts)
    repository_map = build_repository_map(discovery)
    context = ContextBuilder(
        discovery=discovery,
        repository_map=repository_map,
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
        solidity_projects=projects,
    ).build("source_audit")
    rendered_context = render_context(context)
    assert _PRIOR_CANARY not in rendered_context
    assert manifest.expectations.prior_audit_path not in {
        excerpt.path for excerpt in context.excerpts
    }

    scope = assess_audit_scope(
        discovery,
        projects,
        config.scope,
        include_docs=config.repository.include_docs,
        include_tests=config.repository.include_tests,
    )
    assert scope.requested is scope.achieved is AuditScope.FULL_PROTOCOL
    assert scope.complete

    prior = build_prior_audit_comparison(
        repository_root=FIXTURE,
        config=config.prior_audit,
        discovery=discovery,
        candidates=[],
        candidate_validations={},
        findings=[],
        model_request_count_before_load=0,
        prior_material_withheld_from_discovery=withheld,
    )
    assert prior.loaded
    assert prior.prior_material_withheld_from_discovery
    assert prior.blind_discovery_completed_before_load
    assert prior.items[0].discovery_status is PriorAuditDiscoveryStatus.MISSED
    assert prior.items[0].remediation_status is PriorAuditRemediationStatus.REMEDIATED

    report = build_full_protocol_acceptance_report(
        manifest=manifest,
        snapshot=snapshot,
        comparison=comparison,
        scope=scope,
        prior_audit=prior,
        live_network_contacted=False,
        model_provider_contacted=False,
    )
    assert report.status is FullProtocolAcceptanceStatus.PASSED
    assert report.passed_checks == report.total_checks == 10
    assert report.prior_findings_remediated == report.prior_findings == 1

    output = tmp_path / "full-protocol-acceptance.json"
    write_full_protocol_acceptance_report(output, report)
    payload = json.loads(output.read_text(encoding="utf-8"))
    schema = json.loads(
        (ROOT / "schemas/full_protocol_acceptance_report.schema.json").read_text(encoding="utf-8")
    )
    assert set(payload) == set(schema["required"])
    assert all(
        set(check) == set(schema["$defs"]["check"]["required"]) for check in payload["checks"]
    )
    assert FullProtocolAcceptanceReport.model_validate(payload) == report
    assert not (FIXTURE / "cache").exists()
    assert not (FIXTURE / "out").exists()
