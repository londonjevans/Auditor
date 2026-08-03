"""Pure derivation of terminal candidate reproduction resolutions."""

from __future__ import annotations

from collections.abc import Collection, Iterable

from mmaudit.models.schemas import (
    CandidateFinding,
    CandidateReproductionResolution,
    ReproductionIntegrityStatus,
    ReproductionResolutionKind,
    ReproductionResult,
    ReproductionState,
    Severity,
)


def build_candidate_reproduction_resolutions(
    *,
    candidates: Iterable[CandidateFinding],
    results: Iterable[ReproductionResult],
    forced_candidate_ids: Collection[str] | None = None,
) -> list[CandidateReproductionResolution]:
    """Derive one exact fail-closed resolution per high/critical obligation.

    Forced IDs retain their frozen candidate payload while a post-judgment
    impact assessment introduces the high/critical assurance obligation.  The
    function is intentionally pure so detached verification can replay the
    same projection from retained producer evidence.
    """

    forced_ids = forced_candidate_ids or set()
    results_by_candidate: dict[str, list[ReproductionResult]] = {}
    for result in results:
        results_by_candidate.setdefault(result.candidate_id, []).append(result)
    resolutions: list[CandidateReproductionResolution] = []
    for candidate in sorted(candidates, key=lambda item: item.candidate_id):
        if (
            candidate.severity not in {Severity.HIGH, Severity.CRITICAL}
            and candidate.candidate_id not in forced_ids
        ):
            continue
        candidate_results = results_by_candidate.get(candidate.candidate_id, [])
        reproduced_refs: set[str] = set()
        for result in candidate_results:
            if (
                result.state
                in {
                    ReproductionState.REPRODUCED,
                    ReproductionState.REPRODUCED_AND_MINIMIZED,
                }
                and result.attempts > 0
                and result.successful_attempts == result.attempts
                and result.integrity is not None
                and result.integrity.status is ReproductionIntegrityStatus.VERIFIED
            ):
                reproduced_refs.add(f"reproduction:{result.integrity.integrity_sha256}")
        if reproduced_refs:
            resolutions.append(
                CandidateReproductionResolution(
                    candidate_id=candidate.candidate_id,
                    kind=ReproductionResolutionKind.REPRODUCED,
                    evidence_refs=sorted(reproduced_refs),
                    detail="verified deterministic reproduction resolved candidate",
                )
            )
            continue

        attempted_states = sorted(
            {result.state.value for result in candidate_results if result.attempts > 0}
        )
        resolutions.append(
            CandidateReproductionResolution(
                candidate_id=candidate.candidate_id,
                kind=ReproductionResolutionKind.INCONCLUSIVE,
                evidence_refs=[],
                detail=(
                    "attempted reproduction did not produce a qualifying terminal outcome: "
                    + ", ".join(attempted_states)
                    if attempted_states
                    else "no qualifying integrity-bound deterministic reproduction evidence"
                ),
            )
        )
    return resolutions
