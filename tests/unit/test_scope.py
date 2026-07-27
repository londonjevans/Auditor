from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from mmaudit.config import AuditConfig
from mmaudit.models.schemas import (
    AuditProfile,
    AuditScope,
    AuditScopeAssessment,
    ScopeComponent,
    ScopeEvidenceStatus,
)
from mmaudit.orchestration.scope import (
    assess_audit_scope,
    filter_discovery_for_scope,
    scope_quality_gate,
)
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.solidity.projects import discover_solidity_projects


def _protocol_repository(root: Path) -> None:
    for directory in ("src", "script", "service", "test"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\ntest = "test"\nscript = "script"\n',
        encoding="utf-8",
    )
    (root / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.24;\ncontract Vault {}\n",
        encoding="utf-8",
    )
    (root / "script" / "Deploy.s.sol").write_text(
        "pragma solidity ^0.8.24;\ncontract Deploy {}\n",
        encoding="utf-8",
    )
    (root / "service" / "relayer.py").write_text(
        "def relay() -> None:\n    return None\n",
        encoding="utf-8",
    )
    (root / "test" / "Vault.t.sol").write_text(
        "pragma solidity ^0.8.24;\ncontract VaultTest {}\n",
        encoding="utf-8",
    )
    (root / "README.md").write_text(
        "# Synthetic protocol\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    ("requested", "expected_paths"),
    [
        (
            AuditScope.CONTRACTS_ONLY,
            {"foundry.toml", "src/Vault.sol", "test/Vault.t.sol"},
        ),
        (
            AuditScope.CONTRACTS_AND_DEPLOYMENT,
            {
                "foundry.toml",
                "script/Deploy.s.sol",
                "src/Vault.sol",
                "test/Vault.t.sol",
            },
        ),
        (
            AuditScope.FULL_PROTOCOL,
            {
                "README.md",
                "foundry.toml",
                "script/Deploy.s.sol",
                "service/relayer.py",
                "src/Vault.sol",
                "test/Vault.t.sol",
            },
        ),
    ],
)
def test_scope_modes_filter_discovery_and_report_exact_achievement(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
    requested: AuditScope,
    expected_paths: set[str],
) -> None:
    _protocol_repository(tmp_path)
    config = config_factory(
        scope={"mode": requested, "require_complete": True},
        repository={"include_docs": True, "include_tests": True},
    )
    unfiltered = discover_repository(tmp_path, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(unfiltered, config.smart_contracts)
    discovery = filter_discovery_for_scope(unfiltered, projects, requested)
    filtered_projects = discover_solidity_projects(discovery, config.smart_contracts)

    assessment = assess_audit_scope(
        discovery,
        filtered_projects,
        config.scope,
        include_docs=config.repository.include_docs,
        include_tests=config.repository.include_tests,
    )

    assert {item.relative_path for item in discovery.files} == expected_paths
    assert assessment.requested is requested
    assert assessment.achieved is requested
    assert assessment.complete
    assert not assessment.missing_required_components
    assert scope_quality_gate(assessment).passed
    assert AuditScopeAssessment.model_validate_json(assessment.model_dump_json()) == assessment


def test_required_full_protocol_scope_fails_closed_on_configured_omissions(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
) -> None:
    _protocol_repository(tmp_path)
    config = config_factory(
        scope={"mode": AuditScope.FULL_PROTOCOL, "require_complete": True},
        repository={"include_docs": False, "include_tests": False},
    )
    discovery = discover_repository(tmp_path, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)

    assessment = assess_audit_scope(
        discovery,
        projects,
        config.scope,
        include_docs=config.repository.include_docs,
        include_tests=config.repository.include_tests,
    )

    assert assessment.achieved is AuditScope.CONTRACTS_AND_DEPLOYMENT
    assert not assessment.complete
    assert assessment.missing_required_components == [
        ScopeComponent.DOCUMENTATION,
        ScopeComponent.TESTS,
    ]
    evidence = {item.component: item for item in assessment.components}
    assert evidence[ScopeComponent.DOCUMENTATION].status is ScopeEvidenceStatus.OMITTED
    assert evidence[ScopeComponent.TESTS].status is ScopeEvidenceStatus.OMITTED
    gate = scope_quality_gate(assessment)
    assert gate.required
    assert not gate.passed
    assert gate.artifacts == ["scope-assessment.json"]


def test_maximum_assurance_forces_required_full_protocol_scope(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory(
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        scope={
            "mode": AuditScope.CONTRACTS_ONLY,
            "require_complete": False,
        },
    ).effective()

    assert config.scope.mode is AuditScope.FULL_PROTOCOL
    assert config.scope.require_complete
