"""Deterministic, nonauthorizing host stamping for raw candidate reviews."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from typing import Final

from mmaudit.models.schemas import (
    CandidateFinding,
    CandidateOriginKind,
    Evidence,
    ModelVote,
    UsageRecord,
)

MAX_CANDIDATE_REVIEW_FINDINGS: Final = 100_000
MAX_TRUSTED_SCANNER_FINGERPRINTS: Final = 100_000


class CandidateReviewStampingError(ValueError):
    """Raised when detached candidate-stamping inputs are incomplete or incoherent."""


def _candidate_model_family(model_id: str) -> str:
    """Mirror the established conservative family projection without an agents dependency."""

    if type(model_id) is not str or not model_id or "/" not in model_id:
        raise CandidateReviewStampingError("candidate-review requested model is invalid")
    provider, model = model_id.lower().split("/", 1)
    if not provider or not model:
        raise CandidateReviewStampingError("candidate-review requested model is invalid")
    model = re.sub(r"[:@].*$", "", model)
    tokens = [token for token in re.split(r"[-_.]", model) if token]
    lineage: list[str] = []
    for token in tokens:
        if token.isdigit() or re.fullmatch(r"v?\d+(?:\d+)?", token):
            break
        if re.fullmatch(r"\d{4,8}", token):
            break
        lineage.append(token)
        if len(lineage) == 2:
            break
    return f"{provider}/{'-'.join(lineage) if lineage else model}"


def model_review_origin_candidate_id(
    *,
    request_role: str,
    request_id: str,
    candidate: CandidateFinding,
) -> str:
    """Derive the legacy-stable origin ID from exact request and raw candidate evidence."""

    if type(request_role) is not str or not request_role:
        raise CandidateReviewStampingError("model candidate origin identity is incomplete")
    if type(request_id) is not str or not request_id:
        raise CandidateReviewStampingError("model candidate origin identity is incomplete")
    if type(candidate) is not CandidateFinding:
        raise CandidateReviewStampingError("raw candidate has an invalid exact type")
    raw_candidate = candidate.model_dump(
        mode="json",
        exclude={
            "execution_provenance",
            "model_family",
            "model_votes",
            "origin_kind",
            "role",
        },
    )
    payload = {
        "domain": "mmaudit.model-review-origin-candidate.v1",
        "request_id": request_id,
        "request_role": request_role,
        "raw_candidate": raw_candidate,
    }
    digest = hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return f"cand-{digest[:24]}"


def require_unique_raw_candidate_ids(findings: Sequence[CandidateFinding]) -> None:
    """Reject an unbounded inventory or one that reuses a provider candidate identity."""

    if isinstance(findings, (str, bytes)) or not isinstance(findings, Sequence):
        raise CandidateReviewStampingError("raw candidate inventory must be a bounded sequence")
    if len(findings) > MAX_CANDIDATE_REVIEW_FINDINGS:
        raise CandidateReviewStampingError("raw candidate inventory exceeds the limit")
    if any(type(finding) is not CandidateFinding for finding in findings):
        raise CandidateReviewStampingError("raw candidate has an invalid exact type")
    candidate_ids = [finding.candidate_id for finding in findings]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise CandidateReviewStampingError("model response contained duplicate raw candidate IDs")


def _freeze_usage_identity(record: UsageRecord) -> UsageRecord:
    if type(record) is not UsageRecord:
        raise CandidateReviewStampingError("candidate-review usage has an invalid exact type")
    try:
        frozen = UsageRecord.model_validate(record.model_dump(mode="python"), strict=True)
    except (TypeError, ValueError) as exc:
        raise CandidateReviewStampingError(
            "candidate-review usage failed exact structural validation"
        ) from exc
    if frozen != record:
        raise CandidateReviewStampingError("candidate-review usage changed during validation")
    return frozen


def _freeze_raw_findings(
    findings: Sequence[CandidateFinding],
) -> tuple[CandidateFinding, ...]:
    require_unique_raw_candidate_ids(findings)
    frozen: list[CandidateFinding] = []
    for finding in findings:
        try:
            exact = CandidateFinding.model_validate(
                finding.model_dump(mode="python"),
                strict=True,
            )
        except (TypeError, ValueError) as exc:
            raise CandidateReviewStampingError(
                "raw candidate failed exact structural validation"
            ) from exc
        if exact != finding:
            raise CandidateReviewStampingError("raw candidate changed during validation")
        frozen.append(exact)
    return tuple(frozen)


def _freeze_trusted_scanner_fingerprints(fingerprints: Sequence[str]) -> frozenset[str]:
    if isinstance(fingerprints, (str, bytes)) or not isinstance(fingerprints, Sequence):
        raise CandidateReviewStampingError(
            "trusted scanner fingerprint inventory must be a bounded sequence"
        )
    if len(fingerprints) > MAX_TRUSTED_SCANNER_FINGERPRINTS:
        raise CandidateReviewStampingError(
            "trusted scanner fingerprint inventory exceeds the limit"
        )
    if any(type(fingerprint) is not str or not fingerprint for fingerprint in fingerprints):
        raise CandidateReviewStampingError("trusted scanner fingerprint inventory is invalid")
    if len(fingerprints) != len(set(fingerprints)):
        raise CandidateReviewStampingError(
            "trusted scanner fingerprint inventory contains duplicates"
        )
    return frozenset(fingerprints)


def stamp_candidate_review_findings(
    *,
    request_role: str,
    usage_record: UsageRecord,
    trusted_scanner_fingerprints: Sequence[str],
    raw_findings: Sequence[CandidateFinding],
) -> tuple[CandidateFinding, ...]:
    """Rebuild host-stamped candidates without granting usage or review authority.

    This pure projection accepts structurally valid usage, including truncated usage.  It does
    not check or create live usage ownership, completion credit, scheduler capability, coverage
    closure, or promotion authority; callers must establish those properties separately.
    """

    if type(request_role) is not str or not request_role:
        raise CandidateReviewStampingError("candidate-review request role is invalid")
    usage = _freeze_usage_identity(usage_record)
    if usage.role != request_role:
        raise CandidateReviewStampingError("candidate-review role differs from usage identity")
    family = _candidate_model_family(usage.requested_model)
    scanner_fingerprints = _freeze_trusted_scanner_fingerprints(trusted_scanner_fingerprints)
    findings = _freeze_raw_findings(raw_findings)

    stamped: list[CandidateFinding] = []
    for finding in findings:
        evidence = [
            (
                item
                if item.type == "scanner" and item.fingerprint in scanner_fingerprints
                else Evidence(
                    type="model",
                    source=request_role,
                    description=item.description,
                    rule_id=None,
                    fingerprint=None,
                )
            )
            for item in finding.evidence
        ]
        candidate = finding.model_copy(
            update={
                "candidate_id": model_review_origin_candidate_id(
                    request_role=request_role,
                    request_id=usage.request_id,
                    candidate=finding,
                ),
                "origin_kind": CandidateOriginKind.MODEL_REVIEW,
                "execution_provenance": None,
                "role": request_role,
                "model_family": family,
                "model_votes": [
                    ModelVote(
                        role=request_role,
                        requested_model=usage.requested_model,
                        returned_model=usage.returned_model,
                        family=family,
                        verdict="proposed",
                        rationale=finding.summary,
                    )
                ],
                "evidence": evidence,
            }
        )
        try:
            stamped.append(
                CandidateFinding.model_validate(
                    candidate.model_dump(mode="python"),
                    strict=True,
                )
            )
        except (TypeError, ValueError) as exc:
            raise CandidateReviewStampingError("host-stamped candidate is invalid") from exc
    return tuple(stamped)


__all__ = [
    "MAX_CANDIDATE_REVIEW_FINDINGS",
    "MAX_TRUSTED_SCANNER_FINGERPRINTS",
    "CandidateReviewStampingError",
    "model_review_origin_candidate_id",
    "require_unique_raw_candidate_ids",
    "stamp_candidate_review_findings",
]
