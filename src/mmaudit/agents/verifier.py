"""Independent candidate-challenging verifier."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
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
from mmaudit.models.usage import candidate_falsifier_role, is_creditable_usage_record
from mmaudit.orchestration.context import render_context


def _prepared_workflow(
    payload: object,
    *,
    opening_tag: str,
    closing_tag: str,
) -> tuple[str, int, str]:
    payload_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    workflow_prompt = "\n".join((opening_tag, payload_json, closing_tag, ""))
    encoded = workflow_prompt.encode("utf-8")
    return workflow_prompt, len(encoded), hashlib.sha256(encoded).hexdigest()


def _validate_prepared_workflow(
    *,
    workflow_prompt: str,
    workflow_byte_upper_bound_tokens: int,
    workflow_sha256: str,
    opening_tag: str,
    closing_tag: str,
    label: str,
) -> object:
    encoded = workflow_prompt.encode("utf-8")
    if workflow_byte_upper_bound_tokens != len(encoded):
        raise ValueError(f"prepared {label} workflow byte bound is inconsistent")
    if workflow_sha256 != hashlib.sha256(encoded).hexdigest():
        raise ValueError(f"prepared {label} workflow hash is inconsistent")
    prefix = f"{opening_tag}\n"
    suffix = f"\n{closing_tag}\n"
    if not workflow_prompt.startswith(prefix) or not workflow_prompt.endswith(suffix):
        raise ValueError(f"prepared {label} workflow envelope is inconsistent")
    payload_json = workflow_prompt[len(prefix) : -len(suffix)]
    try:
        payload = json.loads(payload_json)
        canonical_json = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"prepared {label} workflow JSON is inconsistent") from exc
    if payload_json != canonical_json:
        raise ValueError(f"prepared {label} workflow JSON is not canonical")
    return payload


@dataclass(frozen=True, slots=True)
class PreparedCandidateCrossExaminationInput:
    """Exact anonymous candidate workflow and private response-normalization map."""

    workflow_prompt: str
    workflow_byte_upper_bound_tokens: int
    workflow_sha256: str
    candidate_ids: tuple[tuple[str, str], ...]

    @classmethod
    def build(
        cls,
        anonymized_candidates: list[dict[str, Any]],
        *,
        candidate_ids: Mapping[str, str],
    ) -> PreparedCandidateCrossExaminationInput:
        normalized_ids = tuple(sorted(candidate_ids.items()))
        workflow_prompt, byte_bound, workflow_sha256 = _prepared_workflow(
            anonymized_candidates,
            opening_tag="<ANONYMIZED_CANDIDATES_JSON>",
            closing_tag="</ANONYMIZED_CANDIDATES_JSON>",
        )
        return cls(
            workflow_prompt=workflow_prompt,
            workflow_byte_upper_bound_tokens=byte_bound,
            workflow_sha256=workflow_sha256,
            candidate_ids=normalized_ids,
        )

    def __post_init__(self) -> None:
        payload = _validate_prepared_workflow(
            workflow_prompt=self.workflow_prompt,
            workflow_byte_upper_bound_tokens=self.workflow_byte_upper_bound_tokens,
            workflow_sha256=self.workflow_sha256,
            opening_tag="<ANONYMIZED_CANDIDATES_JSON>",
            closing_tag="</ANONYMIZED_CANDIDATES_JSON>",
            label="candidate cross-examination",
        )
        immutable_map = isinstance(self.candidate_ids, tuple) and all(
            isinstance(item, tuple)
            and len(item) == 2
            and all(isinstance(value, str) for value in item)
            for item in self.candidate_ids
        )
        if (
            not isinstance(payload, list)
            or len(payload) != 1
            or not immutable_map
            or len(self.candidate_ids) != 1
        ):
            raise ValueError(
                "prepared candidate cross-examination workflow must contain one candidate"
            )
        candidate = payload[0]
        if not isinstance(candidate, dict):
            raise ValueError(
                "prepared candidate cross-examination workflow candidate is inconsistent"
            )
        candidate_ref = candidate.get("candidate_ref")
        if (
            not isinstance(candidate_ref, str)
            or not candidate_ref
            or self.candidate_ids[0][0] != candidate_ref
            or not self.candidate_ids[0][1]
        ):
            raise ValueError(
                "prepared candidate cross-examination workflow reference map is inconsistent"
            )


@dataclass(frozen=True, slots=True)
class PreparedVerificationInput:
    """Exact verification workflow material prepared before context allocation."""

    workflow_prompt: str
    workflow_byte_upper_bound_tokens: int
    workflow_sha256: str

    @classmethod
    def build(cls, payload: object) -> PreparedVerificationInput:
        workflow_prompt, byte_bound, workflow_sha256 = _prepared_workflow(
            payload,
            opening_tag="<SUBMITTED_CANDIDATES_JSON>",
            closing_tag="</SUBMITTED_CANDIDATES_JSON>",
        )
        return cls(
            workflow_prompt=workflow_prompt,
            workflow_byte_upper_bound_tokens=byte_bound,
            workflow_sha256=workflow_sha256,
        )

    def __post_init__(self) -> None:
        _validate_prepared_workflow(
            workflow_prompt=self.workflow_prompt,
            workflow_byte_upper_bound_tokens=self.workflow_byte_upper_bound_tokens,
            workflow_sha256=self.workflow_sha256,
            opening_tag="<SUBMITTED_CANDIDATES_JSON>",
            closing_tag="</SUBMITTED_CANDIDATES_JSON>",
            label="verification",
        )


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
    approved_lineages = set(config.privacy.approved_model_lineages)
    selected: list[tuple[str, str]] = []
    seen_lineages: set[str] = set()
    for model_id in ordered_ids:
        lineage = lineage_by_id.get(model_id.lower())
        if (
            lineage is None
            or lineage.root_lineage not in approved_lineages
            or lineage.root_lineage in seen_lineages
        ):
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
    request_id: str,
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
            request_id=request_id,
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

    @staticmethod
    def prepare_input(
        candidates: list[CandidateFinding],
    ) -> PreparedCandidateCrossExaminationInput:
        """Prepare one anonymous candidate while retaining its private reference map."""

        if len(candidates) != 1:
            raise ValueError("candidate falsifier requests must review exactly one candidate")
        anonymized, candidate_ids = anonymize_cross_examination_candidates(candidates)
        return PreparedCandidateCrossExaminationInput.build(
            anonymized,
            candidate_ids=candidate_ids,
        )

    async def run(
        self,
        candidates: list[CandidateFinding],
        context: ContextPackage,
        *,
        prepared_input: PreparedCandidateCrossExaminationInput | None = None,
    ) -> list[CandidateCrossExaminationDecision]:
        expected_input = self.prepare_input(candidates)
        if prepared_input is not None and prepared_input != expected_input:
            raise OpenRouterSchemaError(
                "prepared candidate cross-examination workflow differs from submitted "
                "candidate evidence"
            )
        effective_input = prepared_input or expected_input
        request_role = candidate_falsifier_role(
            candidates[0].candidate_id,
            self.reviewer_index,
        )
        usage_start = len(self.client.usage.records)
        response = await self.client.complete(
            role=request_role,
            models=[self.model_id],
            system_prompt="\n\n".join(
                (
                    load_prompt("shared_security_rules.md"),
                    load_prompt("cross_examination.md"),
                )
            ),
            user_prompt=effective_input.workflow_prompt + render_context(context),
            context_package=context,
            response_model=CandidateCrossExaminationResponse,
            schema_name=(f"mmaudit_candidate_cross_examination_{self.reviewer_index}"),
        )
        matching_usage = [
            record
            for record in self.client.usage.records[usage_start:]
            if record.role == request_role and is_creditable_usage_record(record)
        ]
        if len(matching_usage) != 1:
            raise OpenRouterSchemaError(
                "candidate falsifier response lacks one exact new completed request record"
            )
        usage = matching_usage[0]
        return normalize_cross_examination_response(
            response,
            candidate_ids=dict(effective_input.candidate_ids),
            request_id=usage.request_id,
            reviewer_index=self.reviewer_index,
            requested_model=self.model_id,
            returned_model=usage.returned_model,
            root_lineage=self.root_lineage,
        )


class VerifierAgent(AgentBase):
    role = "verifier"
    prompt_file = "verifier.md"

    @staticmethod
    def prepare_input(candidates: list[CandidateFinding]) -> PreparedVerificationInput:
        """Prepare the exact non-context verification workflow."""

        return PreparedVerificationInput.build(
            [candidate.model_dump(mode="json") for candidate in candidates]
        )

    async def run(
        self,
        candidates: list[CandidateFinding],
        context: ContextPackage,
        *,
        prepared_input: PreparedVerificationInput | None = None,
    ) -> VerificationBatch:
        expected_input = self.prepare_input(candidates)
        if prepared_input is not None and prepared_input != expected_input:
            raise OpenRouterSchemaError(
                "prepared verification workflow differs from submitted verification evidence"
            )
        effective_input = prepared_input or expected_input
        response = await self.client.complete(
            role=self.role,
            models=self.configured_models,
            system_prompt=self.system_prompt,
            user_prompt=effective_input.workflow_prompt + render_context(context),
            context_package=context,
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
