"""Post-run certification for manifest-bound maximum-assurance replay evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from mmaudit.config import AuditConfig
from mmaudit.models.schemas import (
    AnalysisState,
    AuditProfile,
    AuditReport,
    MaximumAssuranceAssessment,
    MaximumAssuranceRequirement,
    MaximumAssuranceStatus,
    StrictModel,
)
from mmaudit.orchestration.assurance import offline_replay_is_qualifying
from mmaudit.orchestration.manifest import canonical_sha256, load_run_evidence_manifest
from mmaudit.orchestration.replay import (
    OfflineReplay,
    expected_replay_components_for_run,
    expected_replay_kinds_for_run,
    load_offline_replay,
)
from mmaudit.orchestration.verification import RunVerificationStatus, verify_run_evidence
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.secrets import is_sensitive_workspace_name

_MAX_REPORT_BYTES = 100_000_000
_MAX_CERTIFICATION_BYTES = 100_000_000
_POST_RUN_CLAUSES = frozenset(
    {
        "isolated_replay_execution",
        "certified_execution_isolation",
    }
)


class MaximumAssuranceCertificationPayload(StrictModel):
    """Hash-linked post-run assessment over an immutable base run and replay."""

    schema_version: Literal["1.0"] = "1.0"
    generated_by: Literal["mmaudit"] = "mmaudit"
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_verification_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    replay_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    base_assessment_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    assessment: MaximumAssuranceAssessment

    @model_validator(mode="after")
    def assessment_is_maximum_assurance(self) -> MaximumAssuranceCertificationPayload:
        if not self.assessment.requested:
            raise ValueError("post-run certification requires a requested maximum-assurance run")
        return self


class MaximumAssuranceCertification(MaximumAssuranceCertificationPayload):
    certification_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def certification_hash_matches(self) -> MaximumAssuranceCertification:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"certification_sha256"}))
        if self.certification_sha256 != expected:
            raise ValueError("maximum-assurance certification hash is inconsistent")
        return self


def certify_maximum_assurance_run(
    *,
    manifest_path: Path,
    run_dir: Path,
    repository_root: Path,
    replay_path: Path,
    config: AuditConfig,
) -> MaximumAssuranceCertification:
    """Re-verify a sealed run, bind replay evidence, and recompute only replay clauses."""

    manifest = load_run_evidence_manifest(manifest_path)
    verification = verify_run_evidence(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository_root,
        config=config,
    )
    if verification.status is not RunVerificationStatus.CURRENT:
        raise ValueError("maximum-assurance certification refused stale run evidence")
    report = _load_report(run_dir)
    replay = load_offline_replay(replay_path)
    if report.audit_profile is not AuditProfile.MAXIMUM_ASSURANCE:
        raise ValueError("post-run certification requires the maximum-assurance profile")
    if report.run_id != manifest.run_id or verification.run_id != manifest.run_id:
        raise ValueError("report, manifest, and verification run identities differ")
    base = report.maximum_assurance
    if base is None or not base.requested:
        raise ValueError("run report has no requested maximum-assurance assessment")

    replay_qualified = offline_replay_is_qualifying(
        replay,
        expected_run_id=manifest.run_id,
        expected_manifest_sha256=manifest.manifest_sha256,
        expected_verification_sha256=verification.verification_sha256,
        expected_applicable_kinds=expected_replay_kinds_for_run(run_dir),
        expected_components=expected_replay_components_for_run(run_dir),
    )
    failed_before = {
        requirement.engine
        for requirement in base.requirements
        if requirement.required and not requirement.passed
    }
    clauses_present = {requirement.engine for requirement in base.requirements} >= _POST_RUN_CLAUSES
    replay_is_only_blocker = failed_before <= _POST_RUN_CLAUSES
    may_promote = replay_qualified and clauses_present and replay_is_only_blocker
    requirements = [
        _certified_requirement(requirement, replay, promote=may_promote)
        for requirement in base.requirements
    ]
    failed_after = [
        requirement
        for requirement in requirements
        if requirement.required and not requirement.passed
    ]
    if not failed_after:
        status = MaximumAssuranceStatus.COMPLETE
        downgraded = False
    elif base.downgrade_allowed:
        status = MaximumAssuranceStatus.DOWNGRADED
        downgraded = True
    elif any(item.state is AnalysisState.ATTEMPTED_FAILED for item in failed_after):
        status = MaximumAssuranceStatus.INCONCLUSIVE
        downgraded = False
    else:
        status = MaximumAssuranceStatus.FAILED
        downgraded = False
    assessment = MaximumAssuranceAssessment(
        requested=base.requested,
        required=base.required,
        downgrade_allowed=base.downgrade_allowed,
        downgraded=downgraded,
        status=status,
        requirements=requirements,
        downgrade_reasons=[item.detail for item in failed_after] if downgraded else [],
    )
    payload = MaximumAssuranceCertificationPayload(
        run_id=manifest.run_id,
        manifest_sha256=manifest.manifest_sha256,
        run_verification_sha256=verification.verification_sha256,
        replay_sha256=replay.replay_sha256,
        base_assessment_sha256=canonical_sha256(base.model_dump(mode="json")),
        assessment=assessment,
    )
    serialized = payload.model_dump(mode="json")
    return MaximumAssuranceCertification.model_validate(
        {
            **serialized,
            "certification_sha256": canonical_sha256(serialized),
        }
    )


def write_maximum_assurance_certification(
    path: Path,
    certification: MaximumAssuranceCertification,
) -> None:
    """Write bounded certification evidence without following links."""

    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing a sensitive maximum-assurance certification filename")
    if path.is_symlink() or path.is_junction():
        raise ValueError("maximum-assurance certification destination may not be a link")
    if path.exists() and (
        not path.is_file()
        or path.stat().st_nlink != 1
        or path.stat().st_size > _MAX_CERTIFICATION_BYTES
    ):
        raise ValueError("maximum-assurance certification destination must be an unshared file")
    serialized = stable_json(certification)
    if len(serialized.encode("utf-8")) > _MAX_CERTIFICATION_BYTES:
        raise ValueError("maximum-assurance certification exceeds the bounded output size")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialized, encoding="utf-8")


def _certified_requirement(
    requirement: MaximumAssuranceRequirement,
    replay: OfflineReplay,
    *,
    promote: bool,
) -> MaximumAssuranceRequirement:
    if not promote or requirement.engine not in _POST_RUN_CLAUSES:
        return requirement
    if requirement.engine == "isolated_replay_execution":
        return requirement.model_copy(
            update={
                "passed": True,
                "blocking": False,
                "state": AnalysisState.REPRODUCED,
                "detail": (
                    f"{len(replay.components)} applicable manifest-bound replay component(s) "
                    "matched under real hardened isolation"
                ),
                "artifacts": ["offline-replay.json"],
            }
        )
    return requirement.model_copy(
        update={
            "passed": True,
            "blocking": False,
            "state": AnalysisState.DETERMINISTIC,
            "detail": (
                "all mandatory execution portfolio members, including manifest-bound replay, "
                "have qualifying real hardened-isolation evidence"
            ),
        }
    )


def _load_report(run_dir: Path) -> AuditReport:
    root = run_dir.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("maximum-assurance certification run root must be a directory")
    path = root / "final-findings.json"
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError("maximum-assurance certification report is missing or linked")
    metadata = path.stat()
    if metadata.st_nlink != 1 or metadata.st_size > _MAX_REPORT_BYTES:
        raise ValueError("maximum-assurance certification report must be bounded and unshared")
    return AuditReport.model_validate_json(path.read_text(encoding="utf-8"))
