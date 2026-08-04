from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.config import AuditConfig, SmartContractsConfig
from mmaudit.language_plugins import (
    assess_language_capability,
    build_language_capability_artifact,
    resolve_language_plugin,
)
from mmaudit.models.schemas import (
    AuditProfile,
    LanguageCapabilityArtifact,
    LanguageCapabilityProfile,
    LanguageCapabilityStatus,
)
from mmaudit.orchestration.assurance import MaximumAssuranceContract
from mmaudit.repository.discovery import DiscoveredFile, DiscoveryResult
from mmaudit.solidity.projects import discover_solidity_projects
from tests.conftest import base_config_data


def _discovery(
    root: Path,
    files: dict[str, tuple[str, str]],
    *,
    omitted: tuple[str, ...] = (),
) -> DiscoveryResult:
    discovered: list[DiscoveredFile] = []
    for relative_path, (language, content) in sorted(files.items()):
        absolute_path = root / relative_path
        absolute_path.parent.mkdir(parents=True, exist_ok=True)
        absolute_path.write_text(content, encoding="utf-8")
        payload = content.encode("utf-8")
        discovered.append(
            DiscoveredFile(
                absolute_path=absolute_path,
                relative_path=relative_path,
                content=content,
                size=len(payload),
                lines=len(content.splitlines()),
                sha256=hashlib.sha256(payload).hexdigest(),
                language=language,
                categories=(),
            )
        )
    return DiscoveryResult(
        root=root,
        files=tuple(discovered),
        omitted=omitted,
        changed_paths=frozenset(),
        git_commit=None,
    )


def test_solidity_evm_profile_matches_only_a_detected_enabled_project(tmp_path: Path) -> None:
    discovery = _discovery(
        tmp_path,
        {"src/SafeFixture.sol": ("Solidity", "contract SafeFixture {}\n")},
    )
    smart_contracts = SmartContractsConfig(enabled=True)
    projects = discover_solidity_projects(discovery, smart_contracts)

    assessment = assess_language_capability(
        LanguageCapabilityProfile.SOLIDITY_EVM,
        discovery,
        solidity_projects=projects,
        smart_contracts_enabled=smart_contracts.enabled,
    )

    assert assessment.status is LanguageCapabilityStatus.MATCHED
    assert assessment.achieved_profile is LanguageCapabilityProfile.SOLIDITY_EVM
    assert assessment.evm_portfolio_applicable
    assert assessment.evm_maximum_assurance_eligible
    assert assessment.solidity_file_count == 1
    assert assessment.solidity_project_count == 1


def test_solidity_evm_profile_rejects_non_solidity_without_generic_fallback(
    tmp_path: Path,
) -> None:
    discovery = _discovery(tmp_path, {"app.py": ("Python", "def main():\n    return 0\n")})

    assessment = assess_language_capability(
        LanguageCapabilityProfile.SOLIDITY_EVM,
        discovery,
        solidity_projects=[],
        smart_contracts_enabled=True,
    )

    assert assessment.status is LanguageCapabilityStatus.MISMATCH
    assert assessment.achieved_profile is None
    assert not assessment.reduced_capability
    assert not assessment.evm_portfolio_applicable
    assert not assessment.evm_maximum_assurance_eligible
    assert "generic-source-review was not requested" in " ".join(assessment.limitations)


def test_explicit_generic_source_review_is_reduced_and_never_evm_assurance(
    tmp_path: Path,
) -> None:
    discovery = _discovery(tmp_path, {"app.py": ("Python", "def main():\n    return 0\n")})

    assessment = assess_language_capability(
        LanguageCapabilityProfile.GENERIC_SOURCE_REVIEW,
        discovery,
        solidity_projects=[],
        smart_contracts_enabled=True,
    )

    assert assessment.status is LanguageCapabilityStatus.REDUCED
    assert assessment.achieved_profile is LanguageCapabilityProfile.GENERIC_SOURCE_REVIEW
    assert assessment.reduced_capability
    assert not assessment.evm_portfolio_applicable
    assert not assessment.evm_maximum_assurance_eligible
    assert resolve_language_plugin(assessment.requested_profile).profile is assessment.requested_profile


def test_global_discovery_truncation_is_inconclusive_not_a_clean_language_mismatch(
    tmp_path: Path,
) -> None:
    discovery = _discovery(
        tmp_path,
        {"app.py": ("Python", "def main():\n    return 0\n")},
        omitted=("repository: max_files reached",),
    )

    assessment = assess_language_capability(
        LanguageCapabilityProfile.SOLIDITY_EVM,
        discovery,
        solidity_projects=[],
        smart_contracts_enabled=True,
    )

    assert assessment.status is LanguageCapabilityStatus.INCONCLUSIVE
    assert assessment.achieved_profile is None
    assert assessment.blocking_discovery_omissions == ("repository: max_files reached",)
    assert not assessment.evm_maximum_assurance_eligible


def test_language_capability_artifact_recomputes_inventory_hash_and_census(
    tmp_path: Path,
) -> None:
    discovery = _discovery(
        tmp_path,
        {
            "app.py": ("Python", "def main():\n    return 0\n"),
            "src/SafeFixture.sol": ("Solidity", "contract SafeFixture {}\n"),
        },
    )
    projects = discover_solidity_projects(discovery, SmartContractsConfig(enabled=True))
    assessment = assess_language_capability(
        LanguageCapabilityProfile.SOLIDITY_EVM,
        discovery,
        solidity_projects=projects,
        smart_contracts_enabled=True,
    )
    artifact = build_language_capability_artifact(assessment, discovery)

    assert LanguageCapabilityArtifact.model_validate_json(artifact.model_dump_json()) == artifact

    digest_tamper = artifact.model_dump(mode="json")
    digest_tamper["assessment"]["discovery_inventory_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="inventory hash"):
        LanguageCapabilityArtifact.model_validate(digest_tamper)

    census_tamper = artifact.model_dump(mode="json")
    census_tamper["files"][0]["language"] = "Rust"
    with pytest.raises(ValidationError, match="language counts"):
        LanguageCapabilityArtifact.model_validate(census_tamper)


def test_maximum_assurance_preflight_requires_solidity_evm_capability_profile() -> None:
    data = base_config_data()
    data["profile"] = AuditProfile.MAXIMUM_ASSURANCE.value
    data["language_profile"] = LanguageCapabilityProfile.GENERIC_SOURCE_REVIEW.value
    config = AuditConfig.model_validate(data).effective()

    requirements = MaximumAssuranceContract(config).configuration_requirements(
        isolation_available=True,
        scanner_only=False,
    )

    requirement = next(
        item for item in requirements if item.engine == "solidity_evm_capability_profile"
    )
    assert requirement.required
    assert not requirement.passed
    assert "generic-source-review" in requirement.detail
