"""Canonical defensive projection of typed scanner evidence into report findings."""

from __future__ import annotations

import hashlib
from datetime import datetime

from mmaudit.models.schemas import (
    Evidence,
    EvidenceStrength,
    Finding,
    FindingOriginKind,
    FindingStatus,
    Location,
    LocationValidation,
    ScannerFinding,
    VerificationTest,
)
from mmaudit.scanners.base import scanner_fingerprint


def project_scanner_finding(
    scanner: ScannerFinding,
    validations: list[LocationValidation],
    *,
    validated_at: datetime | None,
) -> Finding:
    """Build the one canonical scanner-only finding from host location evidence."""

    if not scanner.locations or len(validations) != len(scanner.locations):
        raise ValueError("scanner finding requires one host validation per location")
    primary = scanner.locations[0]
    expected_fingerprint = scanner_fingerprint(
        scanner.scanner,
        scanner.rule_id,
        primary.path,
        primary.start_line,
        scanner.message,
    )
    if scanner.fingerprint != expected_fingerprint:
        raise ValueError("scanner finding fingerprint differs from its canonical semantics")

    errors = [error for result in validations for error in result.errors]
    valid_locations = [
        location.model_copy(update={"content_hash": result.content_hash})
        for location, result in zip(scanner.locations, validations, strict=True)
        if result.valid and result.content_hash is not None
    ]
    hashes = [result.content_hash for result in validations if result.valid and result.content_hash]
    if any(
        result.valid
        and (
            result.errors
            or result.content_hash is None
            or len(result.content_hash) != 64
            or any(character not in "0123456789abcdef" for character in result.content_hash)
        )
        for result in validations
    ):
        raise ValueError("valid scanner location lacks exact content-hash evidence")
    aggregate_hash = (
        hashlib.sha256("".join(sorted(hashes)).encode()).hexdigest() if hashes else None
    )
    status = FindingStatus.NEEDS_REVIEW if valid_locations else FindingStatus.REJECTED
    projected_locations = valid_locations or scanner.locations
    return Finding(
        id=scanner_stable_finding_id(scanner, projected_locations),
        group_id=f"scanner-{scanner.fingerprint[:16]}",
        origin_kind=FindingOriginKind.STATIC_ANALYZER,
        title=scanner.title,
        status=status,
        severity=scanner.severity,
        confidence=0.8 if valid_locations else 0.0,
        cwe=scanner.cwe,
        owasp=[],
        summary=scanner.message,
        impact=(
            "The scanner matched a potentially security-relevant pattern; "
            "reachability and concrete impact require local review."
        ),
        preconditions=["The scanner rule applies to a reachable application path"],
        locations=projected_locations,
        attack_path=[
            f"{scanner.scanner} matched rule {scanner.rule_id}",
            "A maintainer confirms attacker reachability and impact locally",
        ],
        evidence=[
            Evidence(
                type="scanner",
                source=scanner.scanner,
                rule_id=scanner.rule_id,
                description=scanner.message,
                fingerprint=scanner.fingerprint,
            )
        ],
        false_positive_conditions=[
            "The matched path is unreachable or protected by a control the scanner cannot model"
        ],
        recommendation=(
            "Review the cited location and the scanner rule guidance, then apply "
            "the narrowest remediation supported by local verification."
        ),
        verification_test=VerificationTest(
            description=(
                "Reproduce the scanner condition against a synthetic local fixture "
                "without contacting external systems"
            )
        ),
        location_validation=LocationValidation(
            valid=bool(valid_locations),
            content_hash=aggregate_hash,
            errors=errors,
            validated_at=validated_at,
        ),
        disagreement="Scanner-only output has not been accepted by the independent verifier.",
        contributing_candidate_ids=[scanner.fingerprint],
        evidence_strength=(
            scanner.evidence_strength
            if status is not FindingStatus.REJECTED
            else EvidenceStrength.NONE
        ),
    )


def scanner_stable_finding_id(
    scanner: ScannerFinding,
    locations: list[Location],
) -> str:
    """Return the stable report identifier for one canonical scanner projection."""

    if not locations:
        raise ValueError("scanner finding lacks a source location")
    primary = sorted(
        locations,
        key=lambda location: (
            location.path,
            location.start_line,
            location.end_line,
            location.symbol or "",
        ),
    )[0]
    vulnerability_class = (
        sorted(value.upper() for value in scanner.cwe)[0]
        if scanner.cwe
        else f"{scanner.scanner}:{scanner.rule_id}"
    )
    payload = "\0".join(
        (
            vulnerability_class,
            primary.path,
            str(primary.start_line),
            primary.symbol or "",
        )
    )
    return f"MMA-{hashlib.sha256(payload.encode()).hexdigest()[:12].upper()}"
