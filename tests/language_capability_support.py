from __future__ import annotations

import hashlib
import json
from pathlib import Path

from mmaudit.models.schemas import (
    LanguageCapabilityArtifact,
    LanguageCapabilityAssessment,
    LanguageCapabilityFileEvidence,
    LanguageCapabilityProfile,
    LanguageCapabilityStatus,
)
from mmaudit.repository.ignore import IgnoreMatcher


def _inventory_sha256(
    files: tuple[LanguageCapabilityFileEvidence, ...],
    omitted: tuple[str, ...] = (),
) -> str:
    payload = {
        "files": [item.model_dump(mode="json") for item in files],
        "omitted": list(omitted),
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def empty_language_capability(
    profile: LanguageCapabilityProfile,
) -> LanguageCapabilityArtifact:
    """Return an internally bound no-source mismatch for release/manifest fixtures."""

    plugin_id = {
        LanguageCapabilityProfile.SOLIDITY_EVM: "mmaudit.language.solidity-evm",
        LanguageCapabilityProfile.GENERIC_SOURCE_REVIEW: ("mmaudit.language.generic-source-review"),
    }[profile]
    files: tuple[LanguageCapabilityFileEvidence, ...] = ()
    assessment = LanguageCapabilityAssessment(
        plugin_id=plugin_id,
        requested_profile=profile,
        status=LanguageCapabilityStatus.MISMATCH,
        language_counts={},
        discovered_text_file_count=0,
        solidity_file_count=0,
        non_solidity_file_count=0,
        solidity_project_count=0,
        discovery_inventory_sha256=_inventory_sha256(files),
        evm_portfolio_applicable=False,
        evm_maximum_assurance_eligible=False,
        reduced_capability=False,
        limitations=("no reviewable text source was detected within the audited scope",),
    )
    return LanguageCapabilityArtifact(
        assessment=assessment,
        files=files,
        effective_ignore_rules=tuple(IgnoreMatcher().rules),
        runtime_output_exclusion_root=None,
    )


def matched_solidity_language_capability(
    *,
    path: str = "src/Synthetic.sol",
    content: bytes = b"contract Synthetic {}\n",
) -> LanguageCapabilityArtifact:
    """Return one minimal source-bound matched Solidity/EVM fixture artifact."""

    text = content.decode("utf-8")
    files = (
        LanguageCapabilityFileEvidence(
            path=path,
            sha256=hashlib.sha256(content).hexdigest(),
            size=len(content),
            lines=len(text.splitlines()),
            language="Solidity",
        ),
    )
    return language_capability_for_files(
        LanguageCapabilityProfile.SOLIDITY_EVM,
        files,
        solidity_project_count=1,
    )


def language_capability_for_files(
    profile: LanguageCapabilityProfile,
    files: tuple[LanguageCapabilityFileEvidence, ...],
    *,
    solidity_project_count: int = 0,
) -> LanguageCapabilityArtifact:
    """Build one internally consistent matched or reduced capability test artifact."""

    ordered = tuple(sorted(files, key=lambda item: item.path))
    counts: dict[str, int] = {}
    for item in ordered:
        counts[item.language] = counts.get(item.language, 0) + 1
    counts = dict(sorted(counts.items()))
    solidity_files = counts.get("Solidity", 0)
    if profile is LanguageCapabilityProfile.SOLIDITY_EVM:
        status = LanguageCapabilityStatus.MATCHED
        plugin_id = "mmaudit.language.solidity-evm"
        applicable = True
        eligible = True
        reduced = False
        limitations: tuple[str, ...] = ()
    else:
        status = LanguageCapabilityStatus.REDUCED
        plugin_id = "mmaudit.language.generic-source-review"
        applicable = False
        eligible = False
        reduced = True
        limitations = (
            "generic-source-review excludes the Solidity/EVM compilation, invariant, economic, reproduction, and formal assurance portfolio",
            "no Solidity/EVM or maximum-assurance claim is authorized",
        )
    assessment = LanguageCapabilityAssessment(
        plugin_id=plugin_id,
        requested_profile=profile,
        achieved_profile=profile,
        status=status,
        language_counts=counts,
        discovered_text_file_count=len(ordered),
        solidity_file_count=solidity_files,
        non_solidity_file_count=len(ordered) - solidity_files,
        solidity_project_count=solidity_project_count,
        discovery_inventory_sha256=_inventory_sha256(ordered),
        evm_portfolio_applicable=applicable,
        evm_maximum_assurance_eligible=eligible,
        reduced_capability=reduced,
        limitations=limitations,
    )
    return LanguageCapabilityArtifact(
        assessment=assessment,
        files=ordered,
        effective_ignore_rules=tuple(IgnoreMatcher().rules),
        runtime_output_exclusion_root=None,
    )


def write_language_capability_artifact(
    run_dir: Path,
    artifact: LanguageCapabilityArtifact,
) -> None:
    (run_dir / "language-capability.json").write_text(
        artifact.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
