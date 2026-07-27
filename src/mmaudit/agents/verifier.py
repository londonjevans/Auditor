"""Independent candidate-challenging verifier."""

from __future__ import annotations

import json
from typing import Any

from mmaudit.agents.base import AgentBase, load_prompt
from mmaudit.config import AuditConfig, model_lineage_index
from mmaudit.models.openrouter import OpenRouterClient, OpenRouterSchemaError
from mmaudit.models.schemas import (
    CandidateCrossExaminationDecision,
    CandidateCrossExaminationResponse,
    CandidateFinding,
    ContextPackage,
    VerificationBatch,
    VerificationDecision,
    VerificationTest,
    VerificationVerdict,
)
from mmaudit.models.usage import is_creditable_usage_record
from mmaudit.orchestration.context import render_context


def select_candidate_falsifier_models(config: AuditConfig) -> list[tuple[str, str]]:
    """Select two exact models from distinct immutable root lineages."""

    if "falsifier" not in config.models.specialists:
        return []
    falsifier = config.models.specialists["falsifier"]
    ordered_ids = [
        falsifier.primary,
        *falsifier.fallbacks,
        config.models.verifier.primary,
        *config.models.verifier.fallbacks,
        config.models.judge.primary,
        *config.models.judge.fallbacks,
    ]
    lineage_by_id = model_lineage_index(config)
    selected: list[tuple[str, str]] = []
    seen_lineages: set[str] = set()
    for model_id in ordered_ids:
        lineage = lineage_by_id.get(model_id.lower())
        if lineage is None or lineage.root_lineage in seen_lineages:
            continue
        selected.append((model_id, lineage.root_lineage))
        seen_lineages.add(lineage.root_lineage)
        if len(selected) == 2:
            break
    return selected


def anonymize_cross_examination_candidates(
    candidates: list[CandidateFinding],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Remove originating IDs, roles, model families, votes, and evidence sources."""

    payload: list[dict[str, Any]] = []
    candidate_ids: dict[str, str] = {}
    for index, candidate in enumerate(
        sorted(candidates, key=lambda item: item.candidate_id),
        start=1,
    ):
        candidate_ref = f"candidate-{index:04d}"
        candidate_ids[candidate_ref] = candidate.candidate_id
        payload.append(
            {
                "candidate_ref": candidate_ref,
                "title": candidate.title,
                "severity": candidate.severity.value,
                "confidence": candidate.confidence,
                "cwe": candidate.cwe,
                "owasp": candidate.owasp,
                "summary": candidate.summary,
                "impact": candidate.impact,
                "preconditions": candidate.preconditions,
                "locations": [location.model_dump(mode="json") for location in candidate.locations],
                "source": (
                    candidate.source.model_dump(mode="json")
                    if candidate.source is not None
                    else None
                ),
                "sink": (
                    candidate.sink.model_dump(mode="json") if candidate.sink is not None else None
                ),
                "attack_path": candidate.attack_path,
                "evidence": [
                    {
                        "type": evidence.type,
                        "description": evidence.description,
                        "rule_id": evidence.rule_id,
                        "fingerprint": evidence.fingerprint,
                    }
                    for evidence in candidate.evidence
                ],
                "compensating_controls": candidate.compensating_controls,
                "false_positive_conditions": candidate.false_positive_conditions,
                "verification_test": candidate.verification_test.model_dump(mode="json"),
            }
        )
    return payload, candidate_ids


def normalize_cross_examination_response(
    response: CandidateCrossExaminationResponse,
    *,
    candidate_ids: dict[str, str],
    reviewer_index: int,
    requested_model: str,
    returned_model: str | None,
    root_lineage: str,
) -> list[CandidateCrossExaminationDecision]:
    """Restore only submitted IDs and reject unknown, duplicate, or omitted intake."""

    returned_refs = [decision.candidate_ref for decision in response.decisions]
    if set(returned_refs) != set(candidate_ids) or len(returned_refs) != len(set(returned_refs)):
        raise OpenRouterSchemaError(
            "candidate falsifier returned an incomplete, duplicate, or unknown "
            "candidate decision set"
        )
    return [
        CandidateCrossExaminationDecision(
            candidate_id=candidate_ids[decision.candidate_ref],
            reviewer_index=reviewer_index,
            requested_model=requested_model,
            returned_model=returned_model,
            root_lineage=root_lineage,
            verdict=decision.verdict,
            rationale=decision.rationale,
            contradictions=decision.contradictions,
            missing_evidence=decision.missing_evidence,
        )
        for decision in response.decisions
    ]


class CandidateCrossExaminerAgent:
    """Run one anonymized candidate review with one exact root lineage."""

    def __init__(
        self,
        config: AuditConfig,
        client: OpenRouterClient,
        *,
        reviewer_index: int,
        model_id: str,
        root_lineage: str,
    ) -> None:
        self.config = config
        self.client = client
        self.reviewer_index = reviewer_index
        self.model_id = model_id
        self.root_lineage = root_lineage

    async def run(
        self,
        candidates: list[CandidateFinding],
        context: ContextPackage,
    ) -> list[CandidateCrossExaminationDecision]:
        anonymized, candidate_ids = anonymize_cross_examination_candidates(candidates)
        if not anonymized:
            return []
        request_role = f"specialist:falsifier:cross_exam_{self.reviewer_index}"
        response = await self.client.complete(
            role=request_role,
            models=[self.model_id],
            system_prompt="\n\n".join(
                (
                    load_prompt("shared_security_rules.md"),
                    load_prompt("cross_examination.md"),
                )
            ),
            user_prompt="\n".join(
                (
                    "<ANONYMIZED_CANDIDATES_JSON>",
                    json.dumps(anonymized, sort_keys=True),
                    "</ANONYMIZED_CANDIDATES_JSON>",
                    render_context(context),
                )
            ),
            response_model=CandidateCrossExaminationResponse,
            schema_name=(f"mmaudit_candidate_cross_examination_{self.reviewer_index}"),
        )
        usage = next(
            (
                record
                for record in reversed(self.client.usage.records)
                if record.role == request_role and is_creditable_usage_record(record)
            ),
            None,
        )
        return normalize_cross_examination_response(
            response,
            candidate_ids=candidate_ids,
            reviewer_index=self.reviewer_index,
            requested_model=self.model_id,
            returned_model=usage.returned_model if usage is not None else None,
            root_lineage=self.root_lineage,
        )


class VerifierAgent(AgentBase):
    role = "verifier"
    prompt_file = "verifier.md"

    async def run(
        self,
        candidates: list[CandidateFinding],
        context: ContextPackage,
    ) -> VerificationBatch:
        candidate_json = json.dumps(
            [candidate.model_dump(mode="json") for candidate in candidates],
            sort_keys=True,
        )
        prompt = "\n".join(
            (
                "<SUBMITTED_CANDIDATES_JSON>",
                candidate_json,
                "</SUBMITTED_CANDIDATES_JSON>",
                render_context(context),
            )
        )
        response = await self.client.complete(
            role=self.role,
            models=self.configured_models,
            system_prompt=self.system_prompt,
            user_prompt=prompt,
            response_model=VerificationBatch,
            schema_name="mmaudit_verification",
        )
        submitted_ids = {candidate.candidate_id for candidate in candidates}
        response_ids = [decision.candidate_id for decision in response.decisions]
        if set(response_ids) - submitted_ids or len(response_ids) != len(set(response_ids)):
            raise OpenRouterSchemaError(
                "verifier returned unknown or duplicate candidate identifiers"
            )
        by_id = {decision.candidate_id: decision for decision in response.decisions}
        normalized: list[VerificationDecision] = []
        for candidate in candidates:
            decision = by_id.get(candidate.candidate_id)
            if decision is None:
                normalized.append(
                    VerificationDecision(
                        candidate_id=candidate.candidate_id,
                        verdict=VerificationVerdict.INSUFFICIENT_CONTEXT,
                        rationale="Verifier omitted this submitted candidate",
                        source_to_sink="Not established",
                        reachability="Not established",
                        authentication="Unknown",
                        privilege_requirements="Unknown",
                        environmental_assumptions=[],
                        guards_and_controls=[],
                        false_positive_conditions=candidate.false_positive_conditions,
                        safe_verification_test=VerificationTest(
                            description="Review the cited code locally without contacting external systems"
                        ),
                        confidence=0,
                    )
                )
            else:
                normalized.append(decision)
        return VerificationBatch(decisions=normalized)
