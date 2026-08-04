"""Trusted language-capability plugins selected only from a fixed local registry."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from mmaudit.models.schemas import (
    AnalysisState,
    LanguageCapabilityAssessment,
    LanguageCapabilityProfile,
    LanguageCapabilityStatus,
    QualityGateResult,
    SolidityProjectMetadata,
)
from mmaudit.repository.discovery import DiscoveryResult

_GLOBAL_TRUNCATION_PREFIXES = (
    "repository: max_files reached",
    "repository: max_walk_entries reached",
)
_UNKNOWN_PATH_OMISSIONS = frozenset(
    {
        "repository directory omitted: unsupported path",
        "repository file omitted: unsupported path",
    }
)


class LanguagePlugin(Protocol):
    """Future-extension seam implemented only by trusted installed mmaudit code."""

    profile: LanguageCapabilityProfile
    plugin_id: str
    plugin_version: str
    supports_evm_maximum_assurance: bool

    def assess(
        self,
        discovery: DiscoveryResult,
        *,
        solidity_projects: Sequence[SolidityProjectMetadata],
        smart_contracts_enabled: bool,
    ) -> LanguageCapabilityAssessment:
        """Assess one bounded, unfiltered repository discovery result."""


def _discovery_inventory_sha256(discovery: DiscoveryResult) -> str:
    payload = {
        "files": [
            {
                "path": item.relative_path,
                "sha256": item.sha256,
                "size": item.size,
                "lines": item.lines,
                "language": item.language,
            }
            for item in sorted(discovery.files, key=lambda candidate: candidate.relative_path)
        ],
        "omitted": sorted(discovery.omitted),
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _blocking_discovery_omissions(discovery: DiscoveryResult) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                omission
                for omission in discovery.omitted
                if omission.startswith(_GLOBAL_TRUNCATION_PREFIXES)
                or omission in _UNKNOWN_PATH_OMISSIONS
            }
        )
    )


def _common_evidence(
    discovery: DiscoveryResult,
    solidity_projects: Sequence[SolidityProjectMetadata],
) -> dict[str, object]:
    counts = Counter(item.language for item in discovery.files)
    language_counts = dict(sorted(counts.items()))
    solidity_files = language_counts.get("Solidity", 0)
    return {
        "language_counts": language_counts,
        "discovered_text_file_count": len(discovery.files),
        "solidity_file_count": solidity_files,
        "non_solidity_file_count": len(discovery.files) - solidity_files,
        "solidity_project_count": len(solidity_projects),
        "discovery_inventory_sha256": _discovery_inventory_sha256(discovery),
        "blocking_discovery_omissions": _blocking_discovery_omissions(discovery),
    }


@dataclass(frozen=True)
class SolidityEvmLanguagePlugin:
    """Authorize the implemented EVM engine portfolio only from source-bound evidence."""

    profile: LanguageCapabilityProfile = LanguageCapabilityProfile.SOLIDITY_EVM
    plugin_id: str = "mmaudit.language.solidity-evm"
    plugin_version: str = "1.0"
    supports_evm_maximum_assurance: bool = True

    def assess(
        self,
        discovery: DiscoveryResult,
        *,
        solidity_projects: Sequence[SolidityProjectMetadata],
        smart_contracts_enabled: bool,
    ) -> LanguageCapabilityAssessment:
        evidence = _common_evidence(discovery, solidity_projects)
        solidity_file_count = int(evidence["solidity_file_count"])
        blocking_omissions = tuple(evidence["blocking_discovery_omissions"])
        if smart_contracts_enabled and solidity_file_count > 0 and solidity_projects:
            status = LanguageCapabilityStatus.MATCHED
            achieved_profile: LanguageCapabilityProfile | None = self.profile
            applicable = True
            eligible = True
            limitations: tuple[str, ...] = ()
        elif solidity_file_count == 0 and blocking_omissions:
            status = LanguageCapabilityStatus.INCONCLUSIVE
            achieved_profile = None
            applicable = False
            eligible = False
            limitations = (
                "bounded discovery ended before a complete Solidity/EVM language decision",
                "generic-source-review was not requested and was not selected",
            )
        else:
            status = LanguageCapabilityStatus.MISMATCH
            achieved_profile = None
            applicable = False
            eligible = False
            mismatch_reasons = {"generic-source-review was not requested and was not selected"}
            if solidity_file_count == 0:
                mismatch_reasons.add("no Solidity source was detected within the audited scope")
            if not smart_contracts_enabled:
                mismatch_reasons.add("Solidity/EVM analysis is disabled by effective configuration")
            if solidity_file_count > 0 and not solidity_projects:
                mismatch_reasons.add("no analyzable Solidity/EVM project was detected")
            limitations = tuple(sorted(mismatch_reasons))
        return LanguageCapabilityAssessment(
            plugin_id=self.plugin_id,
            plugin_version=self.plugin_version,
            requested_profile=self.profile,
            achieved_profile=achieved_profile,
            status=status,
            evm_portfolio_applicable=applicable,
            evm_maximum_assurance_eligible=eligible,
            reduced_capability=False,
            limitations=limitations,
            **evidence,
        )


@dataclass(frozen=True)
class GenericSourceReviewLanguagePlugin:
    """Authorize only the explicitly reduced, language-neutral source-review path."""

    profile: LanguageCapabilityProfile = LanguageCapabilityProfile.GENERIC_SOURCE_REVIEW
    plugin_id: str = "mmaudit.language.generic-source-review"
    plugin_version: str = "1.0"
    supports_evm_maximum_assurance: bool = False

    def assess(
        self,
        discovery: DiscoveryResult,
        *,
        solidity_projects: Sequence[SolidityProjectMetadata],
        smart_contracts_enabled: bool,
    ) -> LanguageCapabilityAssessment:
        del smart_contracts_enabled
        evidence = _common_evidence(discovery, solidity_projects)
        discovered_count = int(evidence["discovered_text_file_count"])
        blocking_omissions = tuple(evidence["blocking_discovery_omissions"])
        if discovered_count > 0:
            status = LanguageCapabilityStatus.REDUCED
            achieved_profile: LanguageCapabilityProfile | None = self.profile
            reduced = True
            limitations = (
                "generic-source-review excludes the Solidity/EVM compilation, invariant, "
                "economic, reproduction, and formal assurance portfolio",
                "no Solidity/EVM or maximum-assurance claim is authorized",
            )
        elif blocking_omissions:
            status = LanguageCapabilityStatus.INCONCLUSIVE
            achieved_profile = None
            reduced = False
            limitations = (
                "bounded discovery ended before any source-review input was established",
            )
        else:
            status = LanguageCapabilityStatus.MISMATCH
            achieved_profile = None
            reduced = False
            limitations = ("no reviewable text source was detected within the audited scope",)
        return LanguageCapabilityAssessment(
            plugin_id=self.plugin_id,
            plugin_version=self.plugin_version,
            requested_profile=self.profile,
            achieved_profile=achieved_profile,
            status=status,
            evm_portfolio_applicable=False,
            evm_maximum_assurance_eligible=False,
            reduced_capability=reduced,
            limitations=limitations,
            **evidence,
        )


_LANGUAGE_PLUGINS: Mapping[LanguageCapabilityProfile, LanguagePlugin] = MappingProxyType(
    {
        LanguageCapabilityProfile.SOLIDITY_EVM: SolidityEvmLanguagePlugin(),
        LanguageCapabilityProfile.GENERIC_SOURCE_REVIEW: GenericSourceReviewLanguagePlugin(),
    }
)


def resolve_language_plugin(profile: LanguageCapabilityProfile) -> LanguagePlugin:
    """Resolve only a built-in trusted plugin; repository content cannot extend this registry."""

    try:
        normalized = LanguageCapabilityProfile(profile)
    except ValueError as exc:
        raise ValueError(f"unsupported language capability profile: {profile}") from exc
    return _LANGUAGE_PLUGINS[normalized]


def assess_language_capability(
    profile: LanguageCapabilityProfile,
    discovery: DiscoveryResult,
    *,
    solidity_projects: Sequence[SolidityProjectMetadata],
    smart_contracts_enabled: bool,
) -> LanguageCapabilityAssessment:
    """Assess one explicit profile without loading target-controlled plugins or code."""

    return resolve_language_plugin(profile).assess(
        discovery,
        solidity_projects=solidity_projects,
        smart_contracts_enabled=smart_contracts_enabled,
    )


def language_capability_quality_gate(
    assessment: LanguageCapabilityAssessment | None,
) -> QualityGateResult:
    """Project one explicit required gate from the source-bound capability evidence."""

    if assessment is None:
        return QualityGateResult(
            gate="language_capability_profile",
            required=True,
            passed=False,
            detail="language capability assessment was not produced",
            state=AnalysisState.NOT_ANALYZED,
            artifacts=[],
        )
    passed = assessment.status in {
        LanguageCapabilityStatus.MATCHED,
        LanguageCapabilityStatus.REDUCED,
    }
    achieved = assessment.achieved_profile.value if assessment.achieved_profile else "none"
    return QualityGateResult(
        gate="language_capability_profile",
        required=True,
        passed=passed,
        detail=(
            f"requested={assessment.requested_profile.value}; achieved={achieved}; "
            f"status={assessment.status.value}"
            + (f"; {'; '.join(assessment.limitations)}" if assessment.limitations else "")
        ),
        state=(AnalysisState.DETERMINISTIC if passed else AnalysisState.ATTEMPTED_FAILED),
        artifacts=["language-capability.json"],
    )
