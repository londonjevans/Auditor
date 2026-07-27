"""Blind-first parsing and deterministic comparison of historical audit findings."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from pydantic import ValidationError

from mmaudit.config import PriorAuditConfig
from mmaudit.models.schemas import (
    AnalysisState,
    CandidateFinding,
    Finding,
    Location,
    LocationValidation,
    PriorAuditComparison,
    PriorAuditComparisonItem,
    PriorAuditCorpus,
    PriorAuditDiscoveryStatus,
    PriorAuditFinding,
    PriorAuditPreviousState,
    PriorAuditRemediationStatus,
    QualityGateResult,
)
from mmaudit.repository.discovery import DiscoveryResult
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.locations import validate_location
from mmaudit.repository.redaction import SecretSafetyError, redact_text

_FORBIDDEN_INPUT_NAMES = frozenset(
    {
        ".env",
        "credentials.json",
        "key.json",
        "keystore.json",
        "secrets.json",
        "wallet.json",
    }
)


def withhold_prior_audit_from_discovery(
    discovery: DiscoveryResult,
    configured_path: str | None,
) -> tuple[DiscoveryResult, bool]:
    """Remove the exact historical input before repository maps or contexts exist."""

    if configured_path is None:
        return discovery, False
    normalized = normalize_relative_path(configured_path)
    files = tuple(item for item in discovery.files if item.relative_path != normalized)
    return (
        DiscoveryResult(
            root=discovery.root,
            files=files,
            omitted=tuple(
                item for item in discovery.omitted if not item.startswith(f"{normalized}:")
            ),
            changed_paths=frozenset(path for path in discovery.changed_paths if path != normalized),
            git_commit=discovery.git_commit,
        ),
        all(item.relative_path != normalized for item in files),
    )


def build_prior_audit_comparison(
    *,
    repository_root: Path,
    config: PriorAuditConfig,
    discovery: DiscoveryResult,
    candidates: list[CandidateFinding],
    candidate_validations: dict[str, LocationValidation],
    findings: list[Finding],
    model_request_count_before_load: int,
    prior_material_withheld_from_discovery: bool,
) -> PriorAuditComparison:
    """Load and compare only after the caller has completed blind discovery."""

    if config.path is None:
        return PriorAuditComparison(
            configured=False,
            required=False,
            loaded=False,
            prior_material_withheld_from_discovery=False,
            blind_discovery_completed_before_load=False,
            independent_candidate_count=len(candidates),
            model_request_count_before_load=model_request_count_before_load,
        )
    try:
        corpus, source_sha256 = _load_prior_audit(
            repository_root,
            config,
        )
    except (OSError, ValueError, SecretSafetyError) as exc:
        return PriorAuditComparison(
            configured=True,
            required=config.required or config.fail_on_missed,
            loaded=False,
            source_path=config.path,
            prior_material_withheld_from_discovery=(prior_material_withheld_from_discovery),
            blind_discovery_completed_before_load=True,
            independent_candidate_count=len(candidates),
            model_request_count_before_load=model_request_count_before_load,
            errors=[_safe_load_error(exc)],
        )
    allowed_paths = {item.relative_path for item in discovery.files}
    comparisons = [
        _compare_finding(
            repository_root,
            prior,
            allowed_paths=allowed_paths,
            candidates=candidates,
            candidate_validations=candidate_validations,
            findings=findings,
        )
        for prior in corpus.findings
    ]
    return PriorAuditComparison(
        configured=True,
        required=config.required or config.fail_on_missed,
        loaded=True,
        source_path=config.path,
        source_sha256=source_sha256,
        prior_material_withheld_from_discovery=prior_material_withheld_from_discovery,
        blind_discovery_completed_before_load=True,
        independent_candidate_count=len(candidates),
        model_request_count_before_load=model_request_count_before_load,
        items=sorted(comparisons, key=lambda item: item.prior_id),
    )


def prior_audit_quality_gate(
    comparison: PriorAuditComparison | None,
    config: PriorAuditConfig,
) -> QualityGateResult:
    """Fail only requested historical-input and missed-finding policies."""

    required = config.required or config.fail_on_missed
    if comparison is None:
        return QualityGateResult(
            gate="prior_audit_comparison",
            required=required,
            passed=False,
            detail="prior-audit comparison was not produced",
            state=AnalysisState.NOT_ANALYZED,
        )
    if not comparison.configured:
        return QualityGateResult(
            gate="prior_audit_comparison",
            required=required,
            passed=not required,
            detail="no prior-audit input was configured",
            state=AnalysisState.NOT_ANALYZED,
            artifacts=["prior-audit-comparison.json"],
        )
    missed = [
        item
        for item in comparison.items
        if item.discovery_status is PriorAuditDiscoveryStatus.MISSED
    ]
    invalid = [item for item in comparison.items if not item.source_valid]
    passed = comparison.loaded and not invalid and (not config.fail_on_missed or not missed)
    return QualityGateResult(
        gate="prior_audit_comparison",
        required=required,
        passed=passed,
        detail=(
            f"loaded={comparison.loaded}; findings={len(comparison.items)}; "
            f"missed={len(missed)}; source-invalid={len(invalid)}"
        ),
        state=(
            AnalysisState.DETERMINISTIC
            if passed
            else (
                AnalysisState.ATTEMPTED_FAILED
                if comparison.configured
                else AnalysisState.NOT_ANALYZED
            )
        ),
        artifacts=["prior-audit-comparison.json"],
    )


def _load_prior_audit(
    repository_root: Path,
    config: PriorAuditConfig,
) -> tuple[PriorAuditCorpus, str]:
    assert config.path is not None
    relative = normalize_relative_path(config.path)
    if PurePosixPath(relative).name.lower() in _FORBIDDEN_INPUT_NAMES:
        raise ValueError("prior-audit input uses a forbidden credential-like filename")
    root = repository_root.resolve(strict=True)
    candidate = root
    for part in PurePosixPath(relative).parts:
        candidate /= part
        if candidate.is_symlink() or candidate.is_junction():
            raise ValueError("prior-audit input may not traverse a symlink or junction")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("prior-audit input escaped the repository") from exc
    if not resolved.is_file():
        raise ValueError("prior-audit input is not a regular file")
    stat = resolved.stat()
    if stat.st_nlink > 1:
        raise ValueError("prior-audit input may not be hardlinked")
    if stat.st_size > config.max_bytes:
        raise ValueError("prior-audit input exceeds max_bytes")
    raw = resolved.read_bytes()
    text = raw.decode("utf-8")
    redact_text(
        text,
        fail_on_detected_secret=True,
        redact=False,
    )
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("prior-audit input is not valid JSON") from exc
    corpus = PriorAuditCorpus.model_validate(payload)
    if len(corpus.findings) > config.max_findings:
        raise ValueError("prior-audit input exceeds max_findings")
    return corpus, hashlib.sha256(raw).hexdigest()


def _compare_finding(
    repository_root: Path,
    prior: PriorAuditFinding,
    *,
    allowed_paths: set[str],
    candidates: list[CandidateFinding],
    candidate_validations: dict[str, LocationValidation],
    findings: list[Finding],
) -> PriorAuditComparisonItem:
    current_hashes: list[str] = []
    validation_errors: list[str] = []
    historical_matches: list[bool] = []
    remediation_matches: list[bool] = []
    for location in prior.locations:
        if location.path not in allowed_paths:
            validation_errors.append(
                f"{location.path}:{location.start_line}: outside achieved audit scope"
            )
            continue
        validation = validate_location(
            repository_root,
            Location(
                path=location.path,
                start_line=location.start_line,
                end_line=location.end_line,
                symbol=location.symbol,
            ),
        )
        if not validation.valid or validation.content_hash is None:
            validation_errors.extend(
                f"{location.path}:{location.start_line}: {error}" for error in validation.errors
            )
            continue
        current_hashes.append(validation.content_hash)
        historical_matches.append(validation.content_hash == location.historical_content_sha256)
        remediation_matches.append(
            location.remediated_content_sha256 is not None
            and validation.content_hash == location.remediated_content_sha256
        )
    source_valid = not validation_errors and len(current_hashes) == len(prior.locations)
    matched_candidates = sorted(
        candidate.candidate_id
        for candidate in candidates
        if candidate_validations.get(
            candidate.candidate_id,
            LocationValidation(valid=False),
        ).valid
        and _finding_matches_prior(
            prior,
            candidate.cwe,
            candidate.title,
            candidate.locations,
        )
    )
    matched_findings = sorted(
        finding.id
        for finding in findings
        if finding.location_validation.valid
        and _finding_matches_prior(
            prior,
            finding.cwe,
            finding.title,
            finding.locations,
        )
    )
    if not source_valid:
        matched_candidates = []
        matched_findings = []
        discovery_status = PriorAuditDiscoveryStatus.INCONCLUSIVE
        remediation_status = PriorAuditRemediationStatus.INCONCLUSIVE
    else:
        discovery_status = (
            PriorAuditDiscoveryStatus.REDISCOVERED
            if matched_candidates or matched_findings
            else PriorAuditDiscoveryStatus.MISSED
        )
        if any(historical_matches):
            remediation_status = (
                PriorAuditRemediationStatus.REGRESSED
                if prior.previous_state is PriorAuditPreviousState.REMEDIATED
                else PriorAuditRemediationStatus.UNRESOLVED
            )
        elif remediation_matches and all(remediation_matches):
            remediation_status = PriorAuditRemediationStatus.REMEDIATED
        else:
            remediation_status = PriorAuditRemediationStatus.CHANGED_UNVERIFIED
    return PriorAuditComparisonItem(
        prior_id=prior.prior_id,
        title=prior.title,
        discovery_status=discovery_status,
        remediation_status=remediation_status,
        source_valid=source_valid,
        current_content_sha256=sorted(set(current_hashes)),
        matched_candidate_ids=matched_candidates,
        matched_finding_ids=matched_findings,
        validation_errors=sorted(set(validation_errors)),
    )


def _finding_matches_prior(
    prior: PriorAuditFinding,
    current_cwe: list[str],
    current_title: str,
    current_locations: list[Location],
) -> bool:
    if not all(
        any(
            prior_location.path == current_location.path
            and prior_location.start_line <= current_location.end_line
            and prior_location.end_line >= current_location.start_line
            for current_location in current_locations
        )
        for prior_location in prior.locations
    ):
        return False
    prior_cwe = {value.upper() for value in prior.cwe}
    current_cwe_set = {value.upper() for value in current_cwe}
    if prior_cwe:
        return bool(prior_cwe & current_cwe_set)
    return _normalized_title(prior.title) == _normalized_title(current_title)


def _normalized_title(value: str) -> str:
    return " ".join(
        token
        for token in "".join(
            character.lower() if character.isalnum() else " " for character in value
        ).split()
        if token
    )


def _safe_load_error(exc: Exception) -> str:
    if isinstance(exc, SecretSafetyError):
        return "prior-audit input was rejected by local secret safeguards"
    if isinstance(exc, UnicodeDecodeError):
        return "prior-audit input is not valid UTF-8"
    if isinstance(exc, ValidationError):
        return "prior-audit input failed schema validation"
    if isinstance(exc, FileNotFoundError):
        return "prior-audit input was not found or is inaccessible"
    if isinstance(exc, OSError):
        return "prior-audit input could not be read safely"
    return str(exc)
