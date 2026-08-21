"""Durable NONCREDITING evidence for the one-case authenticated-runner smoke path.

This module deliberately does not issue benchmark, runner, qualification, or
AUTHSEAL custody.  It only seals exact request-cost plans and the resulting
transport evidence for offline replay.
"""

from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal, InvalidOperation, localcontext
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from mmaudit.benchmark.cross_lineage_adjudication import (
    CrossLineageAdjudicationPreparedRun,
    CrossLineageAdjudicationReport,
    CrossLineageAdjudicationRunKind,
)
from mmaudit.benchmark.models import NoncreditingModelBenchmarkSmokeReport
from mmaudit.models.authenticated_runner import AuthenticatedCrossLineageLedgerIntervalEvidence
from mmaudit.models.generation_evidence import (
    OpenRouterGenerationEvidence,
    _reconcile_generation_evidence_structural,
)
from mmaudit.models.openrouter import OpenRouterStructuredRequestCostPreview
from mmaudit.models.qualification import CandidateModel, LineageReviewStatus
from mmaudit.models.schemas import UsageRecord
from mmaudit.models.token_planning import RequestTokenPlan
from mmaudit.reporting.json_report import stable_json_bytes

AUTHENTICATED_RUNNER_SMOKE_CASE_COUNT = 1
AUTHENTICATED_RUNNER_SMOKE_RUN_COUNT = 2
AUTHENTICATED_RUNNER_SMOKE_LOGICAL_REQUEST_COUNT = 4
MAX_AUTHENTICATED_RUNNER_SMOKE_BUNDLE_BYTES = 4_000_000

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ROOT_LINEAGE_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_CASE_ID_PATTERN = r"^case-[0-9a-f]{16}$"
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CANONICAL_DECIMAL_PATTERN = re.compile(r"^(?:0|[1-9][0-9]{0,49})(?:\.[0-9]{1,48})?$")
_SMOKE_SOURCE_SHA256 = "2530063df1ec8b0c7911a1aeb2a4e17d6ed59c6dd72829b0fc52a7bf785eef0e"
_PARENT_CORPUS_SHA256 = "f92ff08ffff2de6fc4b8a4be547d2a0aef45990f7090f734c551ec696ca33e38"
_PARENT_GROUND_TRUTH_SHA256 = "246f5f84aac6aaeecf20a017c9bd5a0f1897e56d54c82ce5ba75a02751d7118c"
_SMOKE_CORPUS_CASE_SHA256 = "b1ee77e30e881ee328d6563e78755b5442c19f3a134e17d73385afbffe02114d"
_SMOKE_GROUND_TRUTH_CASE_SHA256 = "94b73e47bfe8cbc8f0974c8041b7654e7c3a251fd23d02318c16a15de019fbbc"


class AuthenticatedRunnerSmokeError(ValueError):
    """The NONCREDITING smoke contract or its durable replay is inconsistent."""


class _StrictSmokeModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


class AuthenticatedRunnerSmokeCostPlan(_StrictSmokeModel):
    """One retry-inclusive exact request plan with no dispatch authority."""

    artifact_kind: Literal["authenticated_runner_smoke_cost_plan"] = (
        "authenticated_runner_smoke_cost_plan"
    )
    schema_version: Literal["1.0"] = "1.0"
    disposition: Literal["NONCREDITING_SMOKE"] = "NONCREDITING_SMOKE"
    run_kind: CrossLineageAdjudicationRunKind
    stage: Literal["CANDIDATE", "JUDGE"]
    case_id: str = Field(pattern=_CASE_ID_PATTERN)
    selection_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_preview: OpenRouterStructuredRequestCostPreview
    maximum_attempts: int = Field(ge=1, le=32)
    provider_attempt_request_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    maximum_cost_usd_per_attempt_exact: str
    maximum_cost_usd_all_attempts_exact: str
    authorizes_dispatch: Literal[False] = False
    authorizes_budget_reservation: Literal[False] = False
    authorizes_provider_transport: Literal[False] = False
    grants_review_credit: Literal[False] = False
    grants_completion_credit: Literal[False] = False
    runner_custody_authorized: Literal[False] = False
    qualification_authorized: Literal[False] = False
    calibration_authorized: Literal[False] = False
    authseal_authorized: Literal[False] = False
    release_authorized: Literal[False] = False
    plan_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "maximum_cost_usd_per_attempt_exact",
        "maximum_cost_usd_all_attempts_exact",
    )
    @classmethod
    def costs_are_canonical(cls, value: str) -> str:
        return _canonical_decimal(value, label="smoke request cost")

    @field_validator(
        "authorizes_dispatch",
        "authorizes_budget_reservation",
        "authorizes_provider_transport",
        "grants_review_credit",
        "grants_completion_credit",
        "runner_custody_authorized",
        "qualification_authorized",
        "calibration_authorized",
        "authseal_authorized",
        "release_authorized",
        mode="before",
    )
    @classmethod
    def authority_is_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("authenticated runner smoke plans grant no authority or credit")
        return value

    @model_validator(mode="after")
    def request_is_exact_and_self_bound(self) -> Self:
        preview = self.request_preview
        expected_prefix = (
            f"authrunner.smoke.r1.candidate.{self.run_kind.value.casefold()}:"
            if self.stage == "CANDIDATE"
            else f"authrunner.smoke.r1.judge.{self.run_kind.value.casefold()}:"
        )
        expected_candidate_request_id = (
            f"{expected_prefix}{self.selection_sha256}" if self.stage == "CANDIDATE" else None
        )
        if (
            type(preview) is not OpenRouterStructuredRequestCostPreview
            or not preview.logical_request_id.startswith(expected_prefix)
            or (
                expected_candidate_request_id is not None
                and preview.logical_request_id != expected_candidate_request_id
            )
            or preview.role != "model_benchmark"
            or preview.maximum_attempts != self.maximum_attempts
            or preview.maximum_cost_usd_per_attempt_exact != self.maximum_cost_usd_per_attempt_exact
            or preview.maximum_cost_usd_all_attempts_exact
            != self.maximum_cost_usd_all_attempts_exact
            or preview.context_request_evidence_sha256 is not None
            or preview.rendered_context_sha256 is not None
            or preview.reasoning_qualification_sha256 is not None
        ):
            raise ValueError("authenticated runner smoke plan differs from its exact request")
        expected_attempts = tuple(
            preview.logical_request_id
            if index == 1
            else f"{preview.logical_request_id}:attempt:{index}"
            for index in range(1, preview.maximum_attempts + 1)
        )
        if (
            self.provider_attempt_request_ids != expected_attempts
            or len(set(expected_attempts)) != len(expected_attempts)
            or any(_REQUEST_ID_PATTERN.fullmatch(item) is None for item in expected_attempts)
        ):
            raise ValueError("authenticated runner smoke retry inventory is inconsistent")
        if self.plan_sha256 != _canonical_sha256(
            self.model_dump(mode="json", exclude={"plan_sha256"})
        ):
            raise ValueError("authenticated runner smoke plan hash is inconsistent")
        return self


class AuthenticatedRunnerSmokeRunEvidence(_StrictSmokeModel):
    """One candidate request, one independent judge request, and both refetches."""

    artifact_kind: Literal["authenticated_runner_smoke_run_evidence"] = (
        "authenticated_runner_smoke_run_evidence"
    )
    schema_version: Literal["1.0"] = "1.0"
    disposition: Literal["NONCREDITING_SMOKE"] = "NONCREDITING_SMOKE"
    run_kind: CrossLineageAdjudicationRunKind
    candidate: CandidateModel
    judge: CandidateModel
    candidate_cost_plan: AuthenticatedRunnerSmokeCostPlan
    candidate_report: NoncreditingModelBenchmarkSmokeReport
    candidate_generation_refetch: OpenRouterGenerationEvidence
    prepared_adjudication: CrossLineageAdjudicationPreparedRun
    judge_cost_plan: AuthenticatedRunnerSmokeCostPlan
    adjudication_report: CrossLineageAdjudicationReport
    judge_generation_refetch: OpenRouterGenerationEvidence
    serialized_authority: Literal[False] = False
    grants_review_credit: Literal[False] = False
    runner_custody_authorized: Literal[False] = False
    authseal_authorized: Literal[False] = False
    release_authorized: Literal[False] = False
    run_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "serialized_authority",
        "grants_review_credit",
        "runner_custody_authorized",
        "authseal_authorized",
        "release_authorized",
        mode="before",
    )
    @classmethod
    def authority_is_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("authenticated runner smoke run grants no authority or credit")
        return value

    @model_validator(mode="after")
    def run_is_exact_and_self_bound(self) -> Self:
        candidate_usage = self.candidate_report.result.usage_record
        judge_cases = self.adjudication_report.cases
        judge_usage = judge_cases[0].usage_record if len(judge_cases) == 1 else None
        target = self.prepared_adjudication.target
        candidate_report_root = self.candidate_report.target.root_lineage
        if (
            type(self.candidate) is not CandidateModel
            or type(self.judge) is not CandidateModel
            or self.candidate.exact_model_id == self.judge.exact_model_id
            or (
                self.candidate.root_lineage is None
                and self.candidate.lineage_review.status is not LineageReviewStatus.PENDING
            )
            or (
                self.judge.root_lineage is None
                and self.judge.lineage_review.status is not LineageReviewStatus.PENDING
            )
            or self.candidate_cost_plan.run_kind is not self.run_kind
            or self.candidate_cost_plan.stage != "CANDIDATE"
            or self.candidate_report.run_kind != self.run_kind.value
            or self.candidate_report.selection_sha256 != self.candidate_cost_plan.selection_sha256
            or self.candidate_report.corpus_sha256 != _PARENT_CORPUS_SHA256
            or self.candidate_report.ground_truth_sha256 != _PARENT_GROUND_TRUTH_SHA256
            or self.candidate_report.selected_case_sha256 != _SMOKE_CORPUS_CASE_SHA256
            or self.candidate_report.selected_ground_truth_sha256 != _SMOKE_GROUND_TRUTH_CASE_SHA256
            or self.candidate_report.result.case_id != self.candidate_cost_plan.case_id
            or candidate_usage is None
            or candidate_usage.request_id
            != self.candidate_cost_plan.request_preview.logical_request_id
            or self.prepared_adjudication.run_kind is not self.run_kind
            or self.prepared_adjudication.candidate_report_sha256
            != self.candidate_report.report_sha256
            or _ROOT_LINEAGE_PATTERN.fullmatch(target.candidate_root_lineage) is None
            or _ROOT_LINEAGE_PATTERN.fullmatch(target.judge_root_lineage) is None
            or (
                self.candidate.root_lineage is not None
                and target.candidate_root_lineage != self.candidate.root_lineage
            )
            or (
                self.judge.root_lineage is not None
                and target.judge_root_lineage != self.judge.root_lineage
            )
            or (
                candidate_report_root is not None
                and target.candidate_root_lineage != candidate_report_root
            )
            or candidate_report_root != self.candidate.root_lineage
            or self.prepared_adjudication.corpus_sha256 != _PARENT_CORPUS_SHA256
            or self.prepared_adjudication.ground_truth_sha256 != _PARENT_GROUND_TRUTH_SHA256
            or self.prepared_adjudication.case_ids != (self.candidate_cost_plan.case_id,)
            or self.prepared_adjudication.requests[0].corpus_case_sha256
            != _SMOKE_CORPUS_CASE_SHA256
            or self.prepared_adjudication.requests[0].ground_truth_case_sha256
            != _SMOKE_GROUND_TRUTH_CASE_SHA256
            or len(self.prepared_adjudication.requests) != 1
            or self.judge_cost_plan.request_preview.logical_request_id
            != (
                f"authrunner.smoke.r1.judge.{self.run_kind.value.casefold()}:"
                f"{self.prepared_adjudication.requests[0].request_sha256}"
            )
            or self.judge_cost_plan.run_kind is not self.run_kind
            or self.judge_cost_plan.stage != "JUDGE"
            or self.judge_cost_plan.selection_sha256 != self.candidate_cost_plan.selection_sha256
            or self.judge_cost_plan.case_id != self.candidate_cost_plan.case_id
            or self.adjudication_report.run_kind is not self.run_kind
            or self.adjudication_report.prepared_run_sha256
            != self.prepared_adjudication.prepared_run_sha256
            or self.adjudication_report.candidate_report_sha256
            != self.candidate_report.report_sha256
            or len(judge_cases) != 1
            or judge_usage is None
            or judge_usage.request_id != self.judge_cost_plan.request_preview.logical_request_id
            or self.candidate_report.target.model_id != self.candidate.exact_model_id
            or target.candidate_model_id != self.candidate.exact_model_id
            or target.judge_model_id != self.judge.exact_model_id
            or self.candidate_cost_plan.request_preview.exact_model_id
            != self.candidate.exact_model_id
            or self.judge_cost_plan.request_preview.exact_model_id != self.judge.exact_model_id
        ):
            raise ValueError("authenticated runner smoke run evidence differs from its exact pair")
        candidate_routing = candidate_usage.routing
        if (
            candidate_routing.get("privacy_profile") != "SYNTHETIC_BENCHMARK"
            or candidate_routing.get("privacy_source_classification") != "SYNTHETIC_COMMITTED"
            or candidate_routing.get("privacy_source_sha256") != _SMOKE_SOURCE_SHA256
            or candidate_routing.get("privacy_source_proof_kind")
            != "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK"
        ):
            raise ValueError("authenticated runner smoke candidate lacks exact source custody")
        _require_generation_refetch(
            self.candidate_generation_refetch,
            usage=candidate_usage,
            model=self.candidate,
        )
        _require_generation_refetch(
            self.judge_generation_refetch,
            usage=judge_usage,
            model=self.judge,
        )
        candidate_embedded_generation = self.candidate_report.result.generation_evidence
        judge_embedded_generation = judge_cases[0].generation_evidence
        if (
            candidate_embedded_generation is None
            or self.candidate_generation_refetch.retrieved_at
            < candidate_embedded_generation.retrieved_at
            or self.judge_generation_refetch.retrieved_at < judge_embedded_generation.retrieved_at
        ):
            raise ValueError("authenticated runner smoke generation refetch is not fresh")
        if self.run_sha256 != _canonical_sha256(
            self.model_dump(mode="json", exclude={"run_sha256"})
        ):
            raise ValueError("authenticated runner smoke run hash is inconsistent")
        return self


class AuthenticatedRunnerSmokeEvidenceBundle(_StrictSmokeModel):
    """Canonical four-request smoke evidence that no authority consumer accepts."""

    artifact_kind: Literal["authenticated_runner_noncrediting_smoke_evidence"] = (
        "authenticated_runner_noncrediting_smoke_evidence"
    )
    schema_version: Literal["1.0"] = "1.0"
    purpose: Literal["NONCREDITING_SMOKE"] = "NONCREDITING_SMOKE"
    disposition: Literal["TRANSPORT_SCHEMA_IDENTITY_COST_VALID"] = (
        "TRANSPORT_SCHEMA_IDENTITY_COST_VALID"
    )
    smoke_corpus_bundle_sha256: Literal[
        "721f058726cf9509c07cb2aae662fb6ac23b5c30a363db40229faf8895034497"
    ]
    parent_corpus_sha256: Literal[
        "f92ff08ffff2de6fc4b8a4be547d2a0aef45990f7090f734c551ec696ca33e38"
    ]
    parent_ground_truth_sha256: Literal[
        "246f5f84aac6aaeecf20a017c9bd5a0f1897e56d54c82ce5ba75a02751d7118c"
    ]
    effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    selected_case_id: Literal["case-df79ea132113b863"]
    selected_case_count: Literal[1] = 1
    parent_case_count: Literal[24] = 24
    run_count: Literal[2] = 2
    logical_request_count: Literal[4] = 4
    maximum_provider_attempt_count: Literal[8] = 8
    generation_refetch_count: Literal[4] = 4
    execution_sequence_request_ids: tuple[str, str, str, str]
    runs: tuple[AuthenticatedRunnerSmokeRunEvidence, ...] = Field(min_length=2, max_length=2)
    closed_ledger_evidence: AuthenticatedCrossLineageLedgerIntervalEvidence
    full_corpus_execution_completed: Literal[False] = False
    benchmark_authorized: Literal[False] = False
    benchmark_scoring_authorized: Literal[False] = False
    grants_review_credit: Literal[False] = False
    grants_completion_credit: Literal[False] = False
    model_qualification_authorized: Literal[False] = False
    calibration_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    runner_custody_authorized: Literal[False] = False
    runner_authority_authorized: Literal[False] = False
    authseal_comparison_authorized: Literal[False] = False
    seal_publication_authorized: Literal[False] = False
    audit_execution_authorized: Literal[False] = False
    audit_completion_authorized: Literal[False] = False
    authority_issuance_authorized: Literal[False] = False
    provider_call_authorized: Literal[False] = False
    source_egress_authorized: Literal[False] = False
    baseline_update_authorized: Literal[False] = False
    release_authorized: Literal[False] = False
    bundle_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "full_corpus_execution_completed",
        "benchmark_authorized",
        "benchmark_scoring_authorized",
        "grants_review_credit",
        "grants_completion_credit",
        "model_qualification_authorized",
        "calibration_authorized",
        "production_selection_authorized",
        "runner_custody_authorized",
        "runner_authority_authorized",
        "authseal_comparison_authorized",
        "seal_publication_authorized",
        "audit_execution_authorized",
        "audit_completion_authorized",
        "authority_issuance_authorized",
        "provider_call_authorized",
        "source_egress_authorized",
        "baseline_update_authorized",
        "release_authorized",
        mode="before",
    )
    @classmethod
    def authority_is_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("authenticated runner smoke evidence grants no authority or credit")
        return value

    @model_validator(mode="after")
    def protocol_is_exact_and_self_bound(self) -> Self:
        targets = tuple(item.prepared_adjudication.target for item in self.runs)
        if (
            tuple(item.run_kind for item in self.runs)
            != (
                CrossLineageAdjudicationRunKind.PRIMARY,
                CrossLineageAdjudicationRunKind.REPLAY,
            )
            or len({item.run_sha256 for item in self.runs}) != 2
            or len({item.judge.exact_model_id for item in self.runs}) != 2
            or len({item.candidate.exact_model_id for item in self.runs}) != 1
            or any(
                item.candidate_cost_plan.case_id != self.selected_case_id
                or item.candidate_cost_plan.selection_sha256 != self.smoke_corpus_bundle_sha256
                for item in self.runs
            )
        ):
            raise ValueError("authenticated runner smoke bundle has a different protocol inventory")
        documentary_roots = (
            targets[0].candidate_root_lineage,
            targets[0].judge_root_lineage,
            targets[1].judge_root_lineage,
        )
        if (
            targets[1].candidate_root_lineage != documentary_roots[0]
            or len(set(documentary_roots)) != 3
            or any(_ROOT_LINEAGE_PATTERN.fullmatch(item) is None for item in documentary_roots)
            or len({item.public_lineage_bundle_sha256 for item in targets}) != 1
            or len({item.public_lineage_manifest_file_sha256 for item in targets}) != 1
            or any(
                target.candidate_model_id != run.candidate.exact_model_id
                or target.judge_model_id != run.judge.exact_model_id
                for target, run in zip(targets, self.runs, strict=True)
            )
        ):
            raise ValueError(
                "authenticated runner smoke bundle has inconsistent documentary lineage"
            )
        plans = tuple(
            plan for run in self.runs for plan in (run.candidate_cost_plan, run.judge_cost_plan)
        )
        previews = tuple(plan.request_preview for plan in plans)
        common_config_fields = (
            "execution_config_sha256",
            "privacy_config_sha256",
            "token_budget_config_sha256",
            "reasoning_policy_sha256",
            "reasoning_policy_role_binding_sha256",
            "reasoning_profile_sha256",
        )
        if (
            self.maximum_provider_attempt_count != sum(plan.maximum_attempts for plan in plans)
            or any(plan.maximum_attempts != 2 for plan in plans)
            or any(
                len({getattr(preview, field) for preview in previews}) != 1
                for field in common_config_fields
            )
        ):
            raise ValueError("authenticated runner smoke maximum-attempt inventory is inconsistent")
        usages = tuple(
            usage
            for run in self.runs
            for usage in (
                run.candidate_report.result.usage_record,
                run.adjudication_report.cases[0].usage_record,
            )
            if usage is not None
        )
        if len(usages) != AUTHENTICATED_RUNNER_SMOKE_LOGICAL_REQUEST_COUNT:
            raise ValueError("authenticated runner smoke bundle lacks four exact usages")
        expected_sequence = (
            usages[0].request_id,
            usages[2].request_id,
            usages[1].request_id,
            usages[3].request_id,
        )
        if self.execution_sequence_request_ids != expected_sequence:
            raise ValueError("authenticated runner smoke execution sequence is inconsistent")
        generation_ids = tuple(item.openrouter_generation_id for item in usages)
        request_body_hashes = tuple(item.request_body_sha256 for item in usages)
        if (
            any(value is None for value in generation_ids)
            or any(value is None for value in request_body_hashes)
            or len(set(generation_ids)) != AUTHENTICATED_RUNNER_SMOKE_LOGICAL_REQUEST_COUNT
            or len(set(request_body_hashes)) != AUTHENTICATED_RUNNER_SMOKE_LOGICAL_REQUEST_COUNT
            or len({item.request_id for item in usages})
            != AUTHENTICATED_RUNNER_SMOKE_LOGICAL_REQUEST_COUNT
        ):
            raise ValueError("authenticated runner smoke bundle reuses provider request evidence")
        entries = {item.request_id: item for item in self.closed_ledger_evidence.entries}
        expected_entry_ids: list[str] = []
        for plan, usage in zip(plans, usages, strict=True):
            _require_usage_preview_join(usage, plan.request_preview)
            with localcontext() as context:
                context.prec = 160
                usage_entry_cost = Decimal(0)
                for attempt in range(1, usage.attempts + 1):
                    request_id = (
                        usage.request_id
                        if attempt == 1
                        else f"{usage.request_id}:attempt:{attempt}"
                    )
                    entry = entries.get(request_id)
                    if (
                        entry is None
                        or entry.reserved_usd != plan.maximum_cost_usd_per_attempt_exact
                        or Decimal(entry.actual_cost_usd)
                        > Decimal(plan.maximum_cost_usd_per_attempt_exact)
                    ):
                        raise ValueError(
                            "authenticated runner smoke ledger differs from exact request admission"
                        )
                    expected_entry_ids.append(request_id)
                    usage_entry_cost += Decimal(entry.actual_cost_usd)
            if usage.accounted_cost_usd_exact is None or usage_entry_cost != Decimal(
                usage.accounted_cost_usd_exact
            ):
                raise ValueError(
                    "authenticated runner smoke ledger cost differs from provider usage"
                )
        if tuple(sorted(expected_entry_ids)) != tuple(sorted(entries)):
            raise ValueError("authenticated runner smoke ledger contains a different request set")
        if self.bundle_sha256 != _canonical_sha256(
            self.model_dump(mode="json", exclude={"bundle_sha256"})
        ):
            raise ValueError("authenticated runner smoke bundle hash is inconsistent")
        return self


def build_authenticated_runner_smoke_cost_plan(
    *,
    run_kind: CrossLineageAdjudicationRunKind,
    stage: Literal["CANDIDATE", "JUDGE"],
    case_id: str,
    selection_sha256: str,
    request_preview: OpenRouterStructuredRequestCostPreview,
) -> AuthenticatedRunnerSmokeCostPlan:
    """Seal one exact smoke request preview without creating dispatch authority."""

    if (
        type(run_kind) is not CrossLineageAdjudicationRunKind
        or stage not in {"CANDIDATE", "JUDGE"}
        or type(request_preview) is not OpenRouterStructuredRequestCostPreview
    ):
        raise AuthenticatedRunnerSmokeError("authenticated runner smoke cost inputs are invalid")
    try:
        preview = OpenRouterStructuredRequestCostPreview.model_validate_json(
            request_preview.model_dump_json(), strict=True
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise AuthenticatedRunnerSmokeError(
            "authenticated runner smoke request preview failed detached validation"
        ) from None
    attempt_ids = tuple(
        preview.logical_request_id
        if index == 1
        else f"{preview.logical_request_id}:attempt:{index}"
        for index in range(1, preview.maximum_attempts + 1)
    )
    values: dict[str, Any] = {
        "artifact_kind": "authenticated_runner_smoke_cost_plan",
        "schema_version": "1.0",
        "disposition": "NONCREDITING_SMOKE",
        "run_kind": run_kind,
        "stage": stage,
        "case_id": case_id,
        "selection_sha256": selection_sha256,
        "request_preview": preview,
        "maximum_attempts": preview.maximum_attempts,
        "provider_attempt_request_ids": attempt_ids,
        "maximum_cost_usd_per_attempt_exact": preview.maximum_cost_usd_per_attempt_exact,
        "maximum_cost_usd_all_attempts_exact": preview.maximum_cost_usd_all_attempts_exact,
        **_false_plan_authority_payload(),
    }
    try:
        return AuthenticatedRunnerSmokeCostPlan.model_validate(
            {**values, "plan_sha256": _canonical_sha256(values)}, strict=True
        )
    except (TypeError, ValueError, ValidationError):
        raise AuthenticatedRunnerSmokeError(
            "authenticated runner smoke cost plan is invalid"
        ) from None


def seal_authenticated_runner_smoke_run_evidence(
    **values: object,
) -> AuthenticatedRunnerSmokeRunEvidence:
    """Seal one run after all four exact runtime joins have already succeeded."""

    payload = {
        **values,
        "artifact_kind": "authenticated_runner_smoke_run_evidence",
        "schema_version": "1.0",
        "disposition": "NONCREDITING_SMOKE",
        "serialized_authority": False,
        "grants_review_credit": False,
        "runner_custody_authorized": False,
        "authseal_authorized": False,
        "release_authorized": False,
    }
    try:
        return AuthenticatedRunnerSmokeRunEvidence.model_validate(
            {**payload, "run_sha256": _canonical_sha256(payload)}, strict=True
        )
    except (TypeError, ValueError, ValidationError):
        raise AuthenticatedRunnerSmokeError("authenticated runner smoke run is invalid") from None


def seal_authenticated_runner_smoke_evidence_bundle(
    **values: object,
) -> AuthenticatedRunnerSmokeEvidenceBundle:
    """Seal the final four-request result while keeping every authority flag false."""

    payload = {
        **values,
        "artifact_kind": "authenticated_runner_noncrediting_smoke_evidence",
        "schema_version": "1.0",
        "purpose": "NONCREDITING_SMOKE",
        "disposition": "TRANSPORT_SCHEMA_IDENTITY_COST_VALID",
        **_false_bundle_authority_payload(),
    }
    try:
        return AuthenticatedRunnerSmokeEvidenceBundle.model_validate(
            {**payload, "bundle_sha256": _canonical_sha256(payload)}, strict=True
        )
    except (TypeError, ValueError, ValidationError):
        raise AuthenticatedRunnerSmokeError(
            "authenticated runner smoke evidence bundle is invalid"
        ) from None


def authenticated_runner_smoke_evidence_bytes(
    bundle: AuthenticatedRunnerSmokeEvidenceBundle,
) -> bytes:
    """Return the sole bounded canonical representation of a smoke bundle."""

    if type(bundle) is not AuthenticatedRunnerSmokeEvidenceBundle:
        raise AuthenticatedRunnerSmokeError("authenticated runner smoke bundle type is invalid")
    raw = stable_json_bytes(bundle)
    if not raw or len(raw) > MAX_AUTHENTICATED_RUNNER_SMOKE_BUNDLE_BYTES:
        raise AuthenticatedRunnerSmokeError("authenticated runner smoke bundle exceeds its bound")
    return raw


def revalidate_authenticated_runner_smoke_evidence_bytes(
    raw: bytes,
) -> AuthenticatedRunnerSmokeEvidenceBundle:
    """Replay canonical smoke evidence without issuing any live capability."""

    if type(raw) is not bytes or not raw or len(raw) > MAX_AUTHENTICATED_RUNNER_SMOKE_BUNDLE_BYTES:
        raise AuthenticatedRunnerSmokeError("authenticated runner smoke bytes are invalid")
    try:
        bundle = AuthenticatedRunnerSmokeEvidenceBundle.model_validate_json(raw, strict=True)
    except (TypeError, ValueError, ValidationError):
        raise AuthenticatedRunnerSmokeError(
            "authenticated runner smoke bytes do not validate"
        ) from None
    if authenticated_runner_smoke_evidence_bytes(bundle) != raw:
        raise AuthenticatedRunnerSmokeError("authenticated runner smoke bytes are not canonical")
    return bundle


def _require_generation_refetch(
    evidence: OpenRouterGenerationEvidence,
    *,
    usage: UsageRecord,
    model: CandidateModel,
) -> None:
    try:
        reconciled = _reconcile_generation_evidence_structural(
            evidence,
            usage_record=usage,
            expected_exact_model=model.exact_model_id,
            expected_canonical_model=model.canonical_model_slug,
            expected_catalog_identity_binding_sha256=_canonical_sha256(
                {"canonical_slug": model.canonical_model_slug, "id": model.exact_model_id}
            ),
            expected_discovery_evidence_sha256=model.discovery_evidence_sha256,
            expected_provider_name=model.approved_provider_name,
        )
    except (TypeError, ValueError):
        raise ValueError(
            "authenticated runner smoke generation refetch does not reconcile"
        ) from None
    if reconciled != evidence:
        raise ValueError("authenticated runner smoke generation refetch changed during replay")


def _require_usage_preview_join(
    usage: UsageRecord,
    preview: OpenRouterStructuredRequestCostPreview,
) -> None:
    accounted = usage.accounted_cost_usd_exact
    raw_token_plan = usage.routing.get("request_token_plan")
    try:
        token_plan = RequestTokenPlan.model_validate_json(
            json.dumps(
                raw_token_plan,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        )
    except (TypeError, ValueError, ValidationError):
        raise ValueError("authenticated runner smoke usage token plan is invalid") from None
    reasoning_plan = token_plan.reasoning_plan
    if (
        usage.request_id != preview.logical_request_id
        or usage.role != preview.role
        or usage.requested_model != preview.exact_model_id
        or tuple(usage.configured_provider_endpoints) != (preview.provider_endpoint,)
        or usage.actual_provider_endpoint != preview.provider_endpoint
        or usage.prompt_sha256 != preview.prompt_sha256
        or usage.user_prompt_sha256 != preview.user_prompt_sha256
        or usage.schema_sha256 != preview.response_schema_sha256
        or not 1 <= usage.attempts <= preview.maximum_attempts
        or usage.routing.get("request_cost_preview_sha256") != preview.preview_sha256
        or usage.routing.get("request_cost_preview_maximum_cost_usd_per_attempt_exact")
        != preview.maximum_cost_usd_per_attempt_exact
        or usage.routing.get("request_cost_preview_maximum_cost_usd_all_attempts_exact")
        != preview.maximum_cost_usd_all_attempts_exact
        or usage.routing.get("selected_provider_endpoint") != preview.provider_endpoint
        or usage.routing.get("discovery_evidence_sha256") != preview.discovery_evidence_sha256
        or usage.routing.get("discovery_provenance_sha256") != preview.discovery_provenance_sha256
        or usage.routing.get("catalog_snapshot_sha256") != preview.catalog_snapshot_sha256
        or usage.routing.get("catalog_identity_binding_sha256")
        != preview.catalog_identity_binding_sha256
        or usage.routing.get("model_metadata_snapshot_sha256")
        != preview.model_metadata_snapshot_sha256
        or usage.routing.get("identity_snapshot_sha256") != preview.model_identity_snapshot_sha256
        or usage.routing.get("endpoint_snapshot_sha256") != preview.endpoint_policy_snapshot_sha256
        or usage.routing.get("endpoint_pricing_sha256") != preview.endpoint_pricing_sha256
        or usage.routing.get("output_capability_sha256") != preview.output_capability_sha256
        or usage.routing.get("structured_output_mode") != preview.structured_output_mode.value
        or usage.routing.get("structured_output_request_shape_sha256")
        != preview.output_request_shape_sha256
        or _canonical_sha256(usage.routing.get("structured_output_required_provider_parameters"))
        != preview.required_provider_parameters_sha256
        or usage.routing.get("structured_output_protocol_sha256")
        != preview.strict_output_protocol_sha256
        or usage.routing.get("structured_output_reasoning_request_sha256")
        != preview.reasoning_request_sha256
        or usage.routing.get("request_token_plan_sha256") != token_plan.plan_sha256
        or token_plan.request_id != preview.logical_request_id
        or token_plan.role != preview.role
        or token_plan.prompt_byte_upper_bound_tokens != preview.prompt_byte_upper_bound_tokens
        or token_plan.requested_completion_tokens != preview.requested_completion_tokens
        or token_plan.reserved_output_tokens != preview.reserved_output_tokens
        or token_plan.reserved_reasoning_tokens != preview.reserved_reasoning_tokens
        or reasoning_plan is None
        or reasoning_plan.evidence_sha256 != preview.reasoning_plan_sha256
        or reasoning_plan.policy_artifact_sha256 != preview.reasoning_policy_sha256
        or reasoning_plan.policy_role_binding_sha256 != preview.reasoning_policy_role_binding_sha256
        or reasoning_plan.control_profile.profile_sha256 != preview.reasoning_profile_sha256
        or reasoning_plan.endpoint_capability_sha256 != preview.reasoning_capability_sha256
        or reasoning_plan.qualification_binding_sha256 != preview.reasoning_qualification_sha256
        or accounted is None
    ):
        raise ValueError("authenticated runner smoke usage differs from its exact cost preview")
    with localcontext() as context:
        context.prec = 160
        if Decimal(accounted) > Decimal(preview.maximum_cost_usd_per_attempt_exact) * Decimal(
            usage.attempts
        ):
            raise ValueError("authenticated runner smoke usage exceeds its exact cost preview")


def _false_plan_authority_payload() -> dict[str, bool]:
    return {
        name: False
        for name in (
            "authorizes_dispatch",
            "authorizes_budget_reservation",
            "authorizes_provider_transport",
            "grants_review_credit",
            "grants_completion_credit",
            "runner_custody_authorized",
            "qualification_authorized",
            "calibration_authorized",
            "authseal_authorized",
            "release_authorized",
        )
    }


def _false_bundle_authority_payload() -> dict[str, bool]:
    return {
        name: False
        for name in (
            "full_corpus_execution_completed",
            "benchmark_authorized",
            "benchmark_scoring_authorized",
            "grants_review_credit",
            "grants_completion_credit",
            "model_qualification_authorized",
            "calibration_authorized",
            "production_selection_authorized",
            "runner_custody_authorized",
            "runner_authority_authorized",
            "authseal_comparison_authorized",
            "seal_publication_authorized",
            "audit_execution_authorized",
            "audit_completion_authorized",
            "authority_issuance_authorized",
            "provider_call_authorized",
            "source_egress_authorized",
            "baseline_update_authorized",
            "release_authorized",
        )
    }


def _canonical_decimal(value: object, *, label: str) -> str:
    if type(value) is not str or _CANONICAL_DECIMAL_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be canonical non-negative decimal text")
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        raise ValueError(f"{label} must be canonical non-negative decimal text") from None
    rendered = format(parsed, "f").rstrip("0").rstrip(".") if "." in value else value
    if not parsed.is_finite() or parsed < 0 or (rendered or "0") != value:
        raise ValueError(f"{label} must be canonical non-negative decimal text")
    return value


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=_json_default,
        ).encode("utf-8")
    ).hexdigest()


def _json_default(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Decimal):
        return format(value, "f")
    raise TypeError(f"unsupported smoke evidence value: {type(value).__name__}")


__all__ = [
    "AUTHENTICATED_RUNNER_SMOKE_CASE_COUNT",
    "AUTHENTICATED_RUNNER_SMOKE_LOGICAL_REQUEST_COUNT",
    "AUTHENTICATED_RUNNER_SMOKE_RUN_COUNT",
    "MAX_AUTHENTICATED_RUNNER_SMOKE_BUNDLE_BYTES",
    "AuthenticatedRunnerSmokeCostPlan",
    "AuthenticatedRunnerSmokeError",
    "AuthenticatedRunnerSmokeEvidenceBundle",
    "AuthenticatedRunnerSmokeRunEvidence",
    "authenticated_runner_smoke_evidence_bytes",
    "build_authenticated_runner_smoke_cost_plan",
    "revalidate_authenticated_runner_smoke_evidence_bytes",
    "seal_authenticated_runner_smoke_evidence_bundle",
    "seal_authenticated_runner_smoke_run_evidence",
]
