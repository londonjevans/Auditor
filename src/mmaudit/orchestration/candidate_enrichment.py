"""Deterministic, replayable enrichment of candidate evidence."""

from __future__ import annotations

import hashlib
import json

from mmaudit.models.schemas import (
    CandidateFinding,
    Evidence,
    FormalResultKind,
    FormalToolRun,
)


def _deduplicate_evidence(evidence: list[Evidence]) -> list[Evidence]:
    by_key: dict[tuple[str, str, str | None, str | None], Evidence] = {}
    for item in evidence:
        by_key[(item.type, item.source, item.rule_id, item.fingerprint)] = item
    return list(by_key.values())


def attach_formal_counterexamples(
    candidates: list[CandidateFinding],
    formal_runs: list[FormalToolRun],
) -> list[CandidateFinding]:
    """Attach only source-overlapping formal counterexamples to candidates.

    The pure projection is shared by pipeline execution and detached manifest
    verification so a post-run coherent reseal cannot invent candidate changes.
    """

    result: list[CandidateFinding] = []
    for candidate in candidates:
        evidence = list(candidate.evidence)
        for run in formal_runs:
            for formal in run.evidence:
                if (
                    formal.result_kind is not FormalResultKind.COUNTEREXAMPLE
                    or not formal.locations
                    or not any(
                        candidate_location.path == formal_location.path
                        and candidate_location.start_line <= formal_location.end_line
                        and formal_location.start_line <= candidate_location.end_line
                        for candidate_location in candidate.locations
                        for formal_location in formal.locations
                    )
                ):
                    continue
                fingerprint = hashlib.sha256(
                    json.dumps(
                        {
                            "tool": formal.tool,
                            "property": formal.property_id,
                            "counterexample": formal.counterexample,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest()
                evidence.append(
                    Evidence(
                        type="formal",
                        source=formal.tool,
                        rule_id=FormalResultKind.COUNTEREXAMPLE.value,
                        description=(
                            f"Source-overlapping formal counterexample for "
                            f"{formal.property_id}: {formal.property_description}"
                        ),
                        fingerprint=fingerprint,
                    )
                )
        result.append(candidate.model_copy(update={"evidence": _deduplicate_evidence(evidence)}))
    return result
