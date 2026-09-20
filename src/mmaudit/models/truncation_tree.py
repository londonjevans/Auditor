"""Bounded full-tree comparison evidence; serialized data never grants audit credit."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Literal, Self, cast

from pydantic import Field, model_validator

from mmaudit.constants import SPECIALIST_INVESTIGATOR_ROLES
from mmaudit.models.candidate_review_stamping import (
    CandidateReviewStampingError,
    stamp_candidate_review_findings,
)
from mmaudit.models.schemas import (
    CandidateFinding,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
    UsageRecord,
)
from mmaudit.models.truncation import (
    MAX_CANDIDATE_REVIEW_FINDINGS,
    CandidateReviewChannelState,
    CandidateReviewFramePhase,
    CandidateReviewNormalizationEvidence,
    CandidateReviewTruncationProjection,
    candidate_review_schema_algorithm_version,
)
from mmaudit.models.truncation_closure import (
    _EXACT_DECIMAL_CONTEXT,
    MAX_TRUNCATION_CLOSURE_SURFACES,
    TruncationRecoveryBridgeAttemptEvidence,
    TruncationRecoveryChildCompletionEvidence,
    TruncationRecoveryInvariantBinding,
    TruncationRecoveryParentAttemptEvidence,
    TruncationRecoverySurfaceOrigin,
    _bounded_tuple,
    _canonical_sha256,
    _decimal,
    _decimal_text,
    _exact_model,
    _exact_sum,
    _invariant_binding,
    _JsonUsageRecord,
    _model_sha256,
    _NonAuthorizingModel,
    _recursive_surface_origins,
    _require_invariant_binding,
    _routing_invariant_sha256,
    _scheduler_canonical_sha256,
    _surface_origins,
    _usage_context,
    _usage_decimal,
)
from mmaudit.models.truncation_recovery import (
    TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    TRUNCATION_RECOVERY_MAX_COMPLETION_TOKENS,
    TRUNCATION_RECOVERY_MAX_PROVIDER_ATTEMPTS,
    TRUNCATION_RECOVERY_MAX_USD_EXACT,
    TruncationRecoveryChannel,
    TruncationRecoveryChildPlan,
    TruncationRecoveryPlan,
    TruncationRecoveryResourceBudget,
)
from mmaudit.models.truncation_recovery_journal import (
    SCHEDULER_TRUNCATION_RECOVERY_MAX_ENTRIES,
    SCHEDULER_TRUNCATION_RECOVERY_MAX_FAMILIES,
    SchedulerRecoveredCandidateOrigin,
    SchedulerRecoveredCandidateOriginKind,
    SchedulerTruncationRecoveryChildActivation,
    SchedulerTruncationRecoveryChildPreflightResult,
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryClosureStatus,
    SchedulerTruncationRecoveryEntry,
    SchedulerTruncationRecoveryFamilyClosure,
    SchedulerTruncationRecoveryFamilyPromotion,
    SchedulerTruncationRecoveryFamilyRoot,
    SchedulerTruncationRecoveryFullTreeBinding,
    SchedulerTruncationRecoveryParentKind,
    SchedulerTruncationRecoveryResultOrigin,
    SchedulerTruncationRecoveryTerminalStatus,
    _require_nested_recovery_terminal_outcome,
    resolve_truncation_recovery_root_family,
    validate_truncation_recovery_entry_chain,
)
from mmaudit.models.usage import atomic_request_limit_reservations_from_usage

if TYPE_CHECKING:
    from mmaudit.models.scheduler import (
        SchedulerProviderAttemptEvidence,
        SchedulerTruncationRecoveryModelRequestEvidence,
    )

_SHA256 = r"^[0-9a-f]{64}$"
_USD = r"^(?:0|[1-9][0-9]{0,12})(?:\.[0-9]{1,36})?$"
_NONAUTHORIZING: dict[str, Any] = {
    "evidence_authority": "comparison_required",
    "provider_dispatch_authorized": False,
    "review_credit_authorized": False,
    "coverage_credit_authorized": False,
    "completion_authorized": False,
    "release_authorized": False,
}


@dataclass(frozen=True, slots=True)
class TruncationRecoveryTreeInventory:
    """Exact comparison-only subtree; unrelated prefix entries remain outside its members."""

    families: tuple[SchedulerTruncationRecoveryFamilyRoot, ...]
    closures: tuple[SchedulerTruncationRecoveryFamilyClosure, ...]
    children: tuple[TruncationRecoveryChildPlan, ...]
    results: tuple[SchedulerTruncationRecoveryChildResult, ...]


def truncation_recovery_tree_inventory(
    entries: Iterable[SchedulerTruncationRecoveryEntry], *, root_family_id: str
) -> TruncationRecoveryTreeInventory:
    """Retain exact role-bound terminals; structural closure never grants promotion."""

    prefix = validate_truncation_recovery_entry_chain(entries)
    families: dict[str, SchedulerTruncationRecoveryFamilyRoot] = {}
    activations: dict[str, SchedulerTruncationRecoveryChildActivation] = {}
    results: dict[
        str,
        SchedulerTruncationRecoveryChildResult | SchedulerTruncationRecoveryChildPreflightResult,
    ] = {}
    closures: dict[str, SchedulerTruncationRecoveryFamilyClosure] = {}
    for entry in prefix:
        if isinstance(entry, SchedulerTruncationRecoveryFamilyRoot):
            if entry.family_id in families:
                raise ValueError("full recovery prefix repeats a family")
            families[entry.family_id] = entry
        elif isinstance(entry, SchedulerTruncationRecoveryChildActivation):
            if entry.child_task_id in activations:
                raise ValueError("full recovery prefix repeats an activation")
            activations[entry.child_task_id] = entry
        elif isinstance(
            entry,
            SchedulerTruncationRecoveryChildResult
            | SchedulerTruncationRecoveryChildPreflightResult,
        ):
            if entry.child_task_id in results:
                raise ValueError("full recovery prefix repeats a terminal result")
            results[entry.child_task_id] = entry
        elif isinstance(entry, SchedulerTruncationRecoveryFamilyClosure):
            if entry.family_id in closures:
                raise ValueError("full recovery prefix repeats a closure")
            closures[entry.family_id] = entry
    root = families.get(root_family_id)
    root_closure = closures.get(root_family_id)
    if (
        root is None
        or root.parent_kind is not SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK
        or root_closure is None
        or not prefix
        or prefix[-1] != root_closure
    ):
        raise ValueError("full recovery prefix must end at its exact root closure")
    request_role = root.request_limit_binding.parent_request_limit_reservation.role
    if (
        request_role.startswith("specialist:")
        and request_role.removeprefix("specialist:") not in SPECIALIST_INVESTIGATOR_ROLES
    ):
        raise ValueError("full recovery tree requires a known specialist investigator role")
    selected = tuple(
        family
        for family in families.values()
        if resolve_truncation_recovery_root_family(
            family=family,
            families=families,
            activations=activations,
            results=results,
            closures=closures,
        ).family_id
        == root_family_id
    )
    if not selected or selected[0] != root:
        raise ValueError("full recovery tree has no unique ordered root")
    nested_by_task: dict[str, SchedulerTruncationRecoveryFamilyRoot] = {}
    for family in selected[1:]:
        task_id = family.recovery_plan.parent.parent_task_id
        if task_id in nested_by_task:
            raise ValueError("full recovery tree repeats a truncated parent")
        nested_by_task[task_id] = family
    ordered: list[tuple[TruncationRecoveryChildPlan, SchedulerTruncationRecoveryChildResult]] = []
    tree_closures: list[SchedulerTruncationRecoveryFamilyClosure] = []
    for family in selected:
        closure = closures.get(family.family_id)
        if (
            closure is None
            or family.request_limit_binding != root.request_limit_binding
            or family.requested_surface_manifest != root.requested_surface_manifest
            or family.recovery_plan.policy != root.recovery_plan.policy
            or family.truncation_projection.findings_state
            is not CandidateReviewChannelState.COMPLETE
            or len(family.recovery_plan.children) != 2
            or any(
                child.channel is not TruncationRecoveryChannel.COVERAGE
                for child in family.recovery_plan.children
            )
        ):
            raise ValueError("full recovery tree lacks a complete exact family")
        hashes: list[str] = []
        nested_hashes: list[str] = []
        covered: list[str] = []
        generalized = family.parent_kind is SchedulerTruncationRecoveryParentKind.RECOVERY_CHILD
        for child in family.recovery_plan.children:
            result = results.get(child.child_task_id)
            activation = activations.get(child.child_task_id)
            if (
                type(result) is not SchedulerTruncationRecoveryChildResult
                or result.schema_version not in {"1.1", "1.2"}
                or result.result_origin is not SchedulerTruncationRecoveryResultOrigin.RUNTIME
                or result.runtime_usage_record is None
                or result.runtime_usage_record.role != request_role
                or activation is None
                or activation.request_role != request_role
                or result.runtime_activation != activation
                or result.family_id != family.family_id
                or result.family_root_sha256 != family.entry_sha256
                or result.child_plan_sha256 != child.child_plan_sha256
                or result.child_surface_ids != child.surface_ids
                or result.global_request_ordinal
                != family.request_count_before_family + child.ordinal + 1
                or not family.entry_index
                < activation.entry_index
                < result.entry_index
                < closure.entry_index
            ):
                raise ValueError("full recovery tree lacks exact role-bound typed child custody")
            _require_nested_recovery_terminal_outcome(result, activation)
            hashes.append(result.entry_sha256)
            ordered.append((child, result))
            nested = nested_by_task.get(child.child_task_id)
            if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED:
                if nested is not None or result.completed_surface_ids != child.surface_ids:
                    raise ValueError("full recovery leaf differs from its completed partition")
                covered.extend(result.completed_surface_ids)
            elif result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED:
                nested_closure = closures.get(nested.family_id) if nested is not None else None
                if (
                    nested is None
                    or nested_closure is None
                    or nested.parent_family_id != family.family_id
                    or nested_closure.closure_status
                    not in {
                        SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED,
                        SchedulerTruncationRecoveryClosureStatus.RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING,
                    }
                    or nested_closure.entry_index >= closure.entry_index
                    or tuple(
                        sorted(
                            (
                                *result.retained_surface_ids,
                                *nested_closure.covered_unfinished_surface_ids,
                            )
                        )
                    )
                    != child.surface_ids
                ):
                    raise ValueError("full recovery bridge lacks its complete exact descendants")
                covered.extend(result.retained_surface_ids)
                covered.extend(nested_closure.covered_unfinished_surface_ids)
                nested_hashes.append(nested_closure.entry_sha256)
                generalized = generalized or nested_closure.schema_version != "1.1"
            else:
                raise ValueError("full recovery tree contains an incomplete or uncertain child")
        expected_status = (
            SchedulerTruncationRecoveryClosureStatus.RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING
            if nested_hashes
            else SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
        )
        expected_version = (
            ("1.3" if generalized or len(nested_hashes) != 1 else "1.2") if nested_hashes else "1.1"
        )
        if (
            closure.closure_status is not expected_status
            or closure.schema_version != expected_version
            or closure.family_root_sha256 != family.entry_sha256
            or closure.campaign_id != family.campaign_id
            or closure.request_limit_id != family.request_limit_id
            or closure.request_limit_binding_sha256 != family.request_limit_binding_sha256
            or closure.family_index != family.family_index
            or closure.recovery_plan_sha256 != family.recovery_plan.plan_sha256
            or closure.child_result_sha256s != tuple(hashes)
            or closure.nested_family_closure_sha256s != tuple(nested_hashes)
            or tuple(sorted(covered)) != family.recovery_plan.parent.unfinished_surface_ids
            or closure.covered_unfinished_surface_ids != tuple(sorted(covered))
        ):
            raise ValueError("full recovery closure differs from its complete bottom-up partition")
        tree_closures.append(closure)
    ordered.sort(key=lambda pair: pair[1].global_request_ordinal)
    if len(ordered) > TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS or len(
        {child.child_task_id for child, _ in ordered}
    ) != len(ordered):
        raise ValueError("full recovery tree exceeds or repeats its child inventory")
    return TruncationRecoveryTreeInventory(
        families=selected,
        closures=tuple(tree_closures),
        children=tuple(child for child, _ in ordered),
        results=tuple(result for _, result in ordered),
    )


def _generic_truncation_recovery_tree_inventory(
    entries: Iterable[SchedulerTruncationRecoveryEntry], *, root_family_id: str
) -> TruncationRecoveryTreeInventory:
    """Explicit generic-only comparison; never issues live evidence or promotion custody."""

    tree = truncation_recovery_tree_inventory(entries, root_family_id=root_family_id)
    if any(
        result.schema_version != "1.1"
        or result.runtime_specialist_accepted_outcome is not None
        or result.runtime_specialist_accepted_outcome_sha256 is not None
        for result in tree.results
    ):
        raise ValueError("full recovery tree lacks exact generic typed child custody")
    return tree


def _prefix_commitments(
    entries: tuple[SchedulerTruncationRecoveryEntry, ...],
    *,
    before_index: int,
    excluded_child: str | None = None,
) -> tuple[tuple[str, ...], int, int, int]:
    children: dict[str, TruncationRecoveryChildPlan] = {}
    results: dict[
        str,
        SchedulerTruncationRecoveryChildResult | SchedulerTruncationRecoveryChildPreflightResult,
    ] = {}
    for entry in entries[:before_index]:
        if isinstance(entry, SchedulerTruncationRecoveryFamilyRoot):
            for child in entry.recovery_plan.children:
                if child.child_task_id in children:
                    raise ValueError("full recovery accounting repeats a planned child")
                children[child.child_task_id] = child
        elif isinstance(
            entry,
            SchedulerTruncationRecoveryChildResult
            | SchedulerTruncationRecoveryChildPreflightResult,
        ):
            if entry.child_task_id not in children or entry.child_task_id in results:
                raise ValueError("full recovery accounting has a foreign or repeated result")
            results[entry.child_task_id] = entry
    costs: list[str] = []
    attempts = tokens = 0
    for key, child in children.items():
        if key == excluded_child:
            continue
        result = results.get(key)
        costs.append(result.accounted_cost_usd_exact if result else child.reserved_usd_exact)
        attempts += (
            result.accounted_provider_attempts if result else child.reserved_provider_attempts
        )
        tokens += result.accounted_completion_tokens if result else child.reserved_completion_tokens
    return tuple(costs), attempts, tokens, len(children)


class TruncationRecoveryTreeAccounting(_NonAuthorizingModel):
    """Tree costs and all other liabilities as of the captured root-closure prefix."""

    schema_version: Literal["1.0"] = "1.0"
    algorithm_version: Literal["mmaudit.truncation-tree-accounting.v1"] = (
        "mmaudit.truncation-tree-accounting.v1"
    )
    parent_usage_record_sha256: str = Field(pattern=_SHA256)
    child_usage_record_sha256s: tuple[str, ...] = Field(
        min_length=2, max_length=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS
    )
    provider_request_count: int = Field(ge=3, le=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS + 1)
    provider_attempt_count: int = Field(ge=3, le=TRUNCATION_RECOVERY_MAX_PROVIDER_ATTEMPTS)
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0, le=TRUNCATION_RECOVERY_MAX_COMPLETION_TOKENS)
    total_tokens: int = Field(ge=0)
    campaign_provider_attempt_count: int = Field(ge=3, le=TRUNCATION_RECOVERY_MAX_PROVIDER_ATTEMPTS)
    campaign_completion_tokens: int = Field(ge=0, le=TRUNCATION_RECOVERY_MAX_COMPLETION_TOKENS)
    parent_accounted_cost_usd_exact: str = Field(pattern=_USD)
    child_accounted_cost_usd_exact: str = Field(pattern=_USD)
    tree_accounted_cost_usd_exact: str = Field(pattern=_USD)
    other_accounted_cost_usd_exact: str = Field(pattern=_USD)
    campaign_accounted_cost_usd_exact: str = Field(pattern=_USD)
    child_reserved_usd_exact: str = Field(pattern=_USD)
    campaign_cap_usd_exact: str = Field(pattern=_USD)
    parent_cost_refunded: Literal[False] = False
    accounting_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def exact_totals(self) -> Self:
        parent = _decimal(self.parent_accounted_cost_usd_exact, label="tree parent cost")
        children = _decimal(self.child_accounted_cost_usd_exact, label="tree child cost")
        tree = _decimal(self.tree_accounted_cost_usd_exact, label="tree cost")
        other = _decimal(self.other_accounted_cost_usd_exact, label="other prefix liabilities")
        campaign = _decimal(self.campaign_accounted_cost_usd_exact, label="campaign cost")
        cap = _decimal(self.campaign_cap_usd_exact, label="campaign cap")
        if (
            tree != _exact_sum((parent, children))
            or campaign != _exact_sum((tree, other))
            or not campaign < cap <= Decimal(TRUNCATION_RECOVERY_MAX_USD_EXACT)
            or self.provider_request_count != 1 + len(self.child_usage_record_sha256s)
            or len(set(self.child_usage_record_sha256s)) != len(self.child_usage_record_sha256s)
            or self.parent_usage_record_sha256 in self.child_usage_record_sha256s
            or self.campaign_provider_attempt_count < self.provider_attempt_count
            or self.campaign_completion_tokens < self.completion_tokens
            or self.total_tokens != self.prompt_tokens + self.completion_tokens
            or self.accounting_sha256 != _model_sha256(self, exclude={"accounting_sha256"})
        ):
            raise ValueError("full recovery tree accounting is inconsistent")
        return self


class TruncationRecoveredTreeArtifact(_NonAuthorizingModel):
    """Exact complete tree data, requiring original-live verification and later promotion."""

    schema_version: Literal["1.0"] = "1.0"
    algorithm_version: Literal["mmaudit.truncation-tree-closure.v1"] = (
        "mmaudit.truncation-tree-closure.v1"
    )
    scheduler_custody_verified: Literal[False] = False
    surface_review_credit_eligible: Literal[False] = False
    candidate_credit_eligible: Literal[False] = False
    root_family_id: str = Field(pattern=r"^scheduler-recovery-family-[0-9a-f]{64}$")
    journal_manifest_sha256: str = Field(pattern=_SHA256)
    recovery_prefix: tuple[SchedulerTruncationRecoveryEntry, ...] = Field(
        min_length=1, max_length=SCHEDULER_TRUNCATION_RECOVERY_MAX_ENTRIES
    )
    main_usage_records: tuple[_JsonUsageRecord, ...] = Field(
        min_length=1, max_length=TRUNCATION_RECOVERY_MAX_PROVIDER_ATTEMPTS
    )
    baseline_spent_usd_exact: str = Field(pattern=_USD)
    campaign_cap_usd_exact: str = Field(pattern=_USD)
    invariant_binding: TruncationRecoveryInvariantBinding
    requests: tuple[ModelSurfaceReviewRequest, ...] = Field(
        min_length=1, max_length=MAX_TRUNCATION_CLOSURE_SURFACES
    )
    parent: TruncationRecoveryParentAttemptEvidence
    bridges: tuple[TruncationRecoveryBridgeAttemptEvidence, ...] = Field(
        max_length=SCHEDULER_TRUNCATION_RECOVERY_MAX_FAMILIES - 1
    )
    leaves: tuple[TruncationRecoveryChildCompletionEvidence, ...] = Field(
        min_length=2, max_length=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS
    )
    records: tuple[ModelSurfaceReviewRecord, ...] = Field(
        min_length=1, max_length=MAX_TRUNCATION_CLOSURE_SURFACES
    )
    origins: tuple[TruncationRecoverySurfaceOrigin, ...] = Field(
        min_length=1, max_length=MAX_TRUNCATION_CLOSURE_SURFACES
    )
    accounting: TruncationRecoveryTreeAccounting
    artifact_sha256: str = Field(pattern=_SHA256)

    @property
    def recovery_plan(self) -> TruncationRecoveryPlan:
        return next(
            entry.recovery_plan
            for entry in self.recovery_prefix
            if isinstance(entry, SchedulerTruncationRecoveryFamilyRoot)
            and entry.family_id == self.root_family_id
        )

    @property
    def campaign_id(self) -> str:
        return self.recovery_plan.parent.campaign_id

    @property
    def pass_plan_id(self) -> str:
        return self.recovery_plan.parent.pass_plan_id

    @property
    def parent_task_id(self) -> str:
        return self.parent.parent_task_id

    @property
    def parent_logical_request_id(self) -> str:
        return self.parent.parent_logical_request_id

    @property
    def requested_surface_manifest_sha256(self) -> str:
        return self.recovery_plan.parent.requested_surface_manifest_sha256

    @property
    def children(self) -> tuple[TruncationRecoveryChildCompletionEvidence, ...]:
        return self.leaves

    @model_validator(mode="after")
    def exact_tree_and_evidence(self) -> Self:
        tree = truncation_recovery_tree_inventory(
            self.recovery_prefix, root_family_id=self.root_family_id
        )
        root = tree.families[0]
        parent = root.recovery_plan.parent
        if (
            self.journal_manifest_sha256 != root.request_limit_binding.manifest_sha256
            or self.parent.parent_task_id != parent.parent_task_id
            or self.parent.parent_logical_request_id != parent.parent_logical_request_id
            or self.parent.parent_activation_sha256 != parent.parent_activation_sha256
            or self.parent.provider_attempt_evidence_sha256
            != parent.provider_attempt_evidence_sha256
            or self.parent.projection != root.truncation_projection
            or self.parent.retained_surface_ids != parent.retained_surface_ids
            or self.requests != root.requested_surface_manifest.requests
            or ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(self.requests)
            != parent.requested_surface_manifest_sha256
            or atomic_request_limit_reservations_from_usage(self.parent.usage_record)
            != (root.request_limit_binding.parent_request_limit_reservation,)
        ):
            raise ValueError("full recovery artifact differs from its exact root")
        bridge_results = tuple(
            r
            for r in tree.results
            if r.terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED
        )
        leaf_results = tuple(
            r
            for r in tree.results
            if r.terminal_status is SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
        )
        if tuple(b.child_plan.child_task_id for b in self.bridges) != tuple(
            r.child_task_id for r in bridge_results
        ) or tuple(c.child_plan.child_task_id for c in self.leaves) != tuple(
            r.child_task_id for r in leaf_results
        ):
            raise ValueError("full recovery artifact omits or reorders a bridge or leaf")
        plans = {child.child_task_id: child for child in tree.children}
        evidence_items: tuple[
            TruncationRecoveryBridgeAttemptEvidence | TruncationRecoveryChildCompletionEvidence, ...
        ] = (*self.bridges, *self.leaves)
        for evidence, result in zip(evidence_items, (*bridge_results, *leaf_results), strict=True):
            activation = result.runtime_activation
            if (
                activation is None
                or evidence.child_plan != plans[result.child_task_id]
                or evidence.usage_record != result.runtime_usage_record
                or evidence.request_limit_scope != activation.request_limit_id
                or evidence.request_limit_count_before
                != activation.request_limit_count_before_child
            ):
                raise ValueError("full recovery artifact has detached child evidence")
            if isinstance(evidence, TruncationRecoveryBridgeAttemptEvidence):
                if (
                    evidence.activation_sha256 != activation.entry_sha256
                    or evidence.provider_attempt_evidence_sha256
                    != result.provider_attempt_evidence_sha256
                    or evidence.projection != result.truncation_projection
                    or evidence.envelope != result.runtime_truncated_envelope_evidence
                ):
                    raise ValueError("full recovery bridge differs from original truncated custody")
                usage = evidence.usage_record
                binding = self.invariant_binding
                if (
                    usage.role != binding.review_role
                    or _usage_context(usage).context_role != binding.context_role
                    or usage.requested_model != binding.requested_model
                    or usage.actual_model != binding.selected_model
                    or usage.provider != binding.response_provider
                    or usage.actual_provider_endpoint != binding.selected_provider_endpoint
                    or usage.routing.get("selected_provider_identity")
                    != binding.selected_provider_identity
                    or usage.model_family != binding.model_family
                    or usage.schema_sha256 != binding.wire_schema_sha256
                    or evidence.projection.normalized_batch_schema_sha256
                    != binding.normalized_batch_schema_sha256
                    or evidence.analysis_context_sha256 != binding.analysis_context_sha256
                    or _routing_invariant_sha256(usage) != binding.routing_invariant_sha256
                ):
                    raise ValueError("full recovery bridge drifted from invariant custody")
            elif (
                evidence.requests != result.runtime_requested_surface_requests
                or evidence.normalization != result.runtime_normalization_evidence
                or evidence.normalized_batch != result.runtime_normalized_batch
                or evidence.surface_artifact != result.runtime_output_artifact
            ):
                raise ValueError("full recovery leaf differs from original completion custody")
        _require_invariant_binding(self.invariant_binding, self.parent, self.leaves)
        usages = (
            self.parent.usage_record,
            *(b.usage_record for b in self.bridges),
            *(c.usage_record for c in self.leaves),
        )
        for identities in (
            tuple(u.request_id for u in usages),
            tuple(u.openrouter_generation_id for u in usages),
        ):
            if None in identities or len(set(identities)) != len(identities):
                raise ValueError("full recovery tree repeats an original request or generation")
        findings_count = (
            len(self.parent.projection.findings)
            + sum(len(b.projection.findings) for b in self.bridges)
            + sum(len(c.normalized_batch.findings) for c in self.leaves)
        )
        if findings_count > MAX_CANDIDATE_REVIEW_FINDINGS * 5:
            raise ValueError("full recovery tree exceeds the original aggregate candidate bound")
        records, origins = _tree_surfaces(self.parent, self.bridges, self.leaves)
        if (
            self.records != records
            or self.origins != origins
            or tuple(r.surface_id for r in records) != tuple(r.surface_id for r in self.requests)
            or any(
                r.status
                not in {
                    ModelSurfaceReviewStatus.CANDIDATE,
                    ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
                }
                for r in records
            )
        ):
            raise ValueError("full recovery tree retained/leaf surface partition is inconsistent")
        if self.accounting != _tree_accounting(self, tree):
            raise ValueError("full recovery tree omits or changes prefix liabilities")
        algorithm = candidate_review_schema_algorithm_version(
            wire_schema_sha256=self.invariant_binding.wire_schema_sha256,
            normalized_batch_schema_sha256=self.invariant_binding.normalized_batch_schema_sha256,
        )
        if self.artifact_sha256 != _model_sha256(
            self, exclude={"artifact_sha256"}, algorithm_version=algorithm
        ):
            raise ValueError("full recovery tree artifact hash is inconsistent")
        return self


def _tree_surfaces(
    parent: TruncationRecoveryParentAttemptEvidence,
    bridges: tuple[TruncationRecoveryBridgeAttemptEvidence, ...],
    leaves: tuple[TruncationRecoveryChildCompletionEvidence, ...],
) -> tuple[tuple[ModelSurfaceReviewRecord, ...], tuple[TruncationRecoverySurfaceOrigin, ...]]:
    records = [
        *parent.projection.surface_reviews,
        *(r for b in bridges for r in b.projection.surface_reviews),
        *(r for c in leaves for r in c.surface_artifact.records),
    ]
    origins = list(_surface_origins(parent=parent, children=leaves))
    for bridge in bridges:
        origins.extend(
            o
            for o in _recursive_surface_origins(parent=parent, bridge=bridge, children=())
            if o.request_id == bridge.usage_record.request_id
        )
    if len({r.surface_id for r in records}) != len(records) or len(
        {o.surface_id for o in origins}
    ) != len(origins):
        raise ValueError("full recovery tree repeats a retained or leaf surface")
    return tuple(sorted(records, key=lambda r: r.surface_id)), tuple(
        sorted(origins, key=lambda o: o.surface_id)
    )


def _tree_accounting(
    artifact: TruncationRecoveredTreeArtifact, tree: TruncationRecoveryTreeInventory
) -> TruncationRecoveryTreeAccounting:
    main = artifact.main_usage_records
    if len({u.request_id for u in main}) != len(main):
        raise ValueError("full recovery prefix repeats a main usage")
    parent_usage = artifact.parent.usage_record
    if tuple(u for u in main if u.request_id == parent_usage.request_id) != (parent_usage,):
        raise ValueError("full recovery prefix omits its exact main parent usage")
    main_by_id = {u.request_id: u for u in main}
    baseline = _decimal(artifact.baseline_spent_usd_exact, label="campaign baseline spent")
    for family in tree.families:
        resources = family.recovery_plan.resources
        parent_id = family.recovery_plan.parent.parent_logical_request_id
        root_parent = main_by_id.get(parent_id)
        before = tuple(u for u in main if u is not root_parent)
        costs, attempts, tokens, requests = _prefix_commitments(
            artifact.recovery_prefix,
            before_index=family.entry_index,
            excluded_child=family.recovery_plan.parent.parent_task_id
            if root_parent is None
            else None,
        )
        usage = root_parent or next(
            (
                r.runtime_usage_record
                for r in tree.results
                if r.child_logical_request_id == parent_id
            ),
            None,
        )
        if usage is None:
            raise ValueError("full recovery prefix lacks its exact nested parent usage")
        expected = TruncationRecoveryResourceBudget.build(
            campaign_cap_usd_exact=artifact.campaign_cap_usd_exact,
            accounted_usd_before_parent_exact=_decimal_text(
                _exact_sum(
                    (
                        baseline,
                        *(
                            _usage_decimal(
                                u.accounted_cost_usd_exact or "", label="prior main cost"
                            )
                            for u in before
                        ),
                        *(_decimal(c, label="prior recovery liability") for c in costs),
                    )
                )
            ),
            parent_accounted_cost_usd_exact=_decimal_text(
                _usage_decimal(usage.accounted_cost_usd_exact or "", label="family parent cost")
            ),
            child_reserved_usd_exact=resources.child_reserved_usd_exact,
            recovery_requests_consumed=requests,
            provider_attempts_before_parent=sum(u.attempts for u in before) + attempts,
            parent_provider_attempts=usage.attempts,
            child_provider_attempts=resources.child_provider_attempts,
            completion_tokens_before_parent=sum(u.completion_tokens for u in before) + tokens,
            parent_completion_tokens=usage.completion_tokens,
            child_completion_tokens=resources.child_completion_tokens,
        )
        if resources != expected:
            raise ValueError("full recovery family resources differ from the entire prefix")
    children = tuple(r.runtime_usage_record for r in tree.results)
    if any(u is None for u in children):
        raise ValueError("full recovery accounting lacks a typed child usage")
    child_usages = tuple(u for u in children if u is not None)
    costs, attempts, tokens, _ = _prefix_commitments(
        artifact.recovery_prefix, before_index=len(artifact.recovery_prefix)
    )
    campaign_cost = _exact_sum(
        (
            baseline,
            *(_usage_decimal(u.accounted_cost_usd_exact or "", label="main cost") for u in main),
            *(_decimal(c, label="recovery liability") for c in costs),
        )
    )
    parent_cost = _usage_decimal(parent_usage.accounted_cost_usd_exact or "", label="root cost")
    child_cost = _exact_sum(
        _usage_decimal(u.accounted_cost_usd_exact or "", label="tree child cost")
        for u in child_usages
    )
    tree_cost = _exact_sum((parent_cost, child_cost))
    other_cost = _EXACT_DECIMAL_CONTEXT.subtract(campaign_cost, tree_cost)
    all_usages = (parent_usage, *child_usages)
    values = {
        **_NONAUTHORIZING,
        "schema_version": "1.0",
        "algorithm_version": "mmaudit.truncation-tree-accounting.v1",
        "parent_usage_record_sha256": artifact.parent.usage_record_sha256,
        "child_usage_record_sha256s": tuple(
            _canonical_sha256(u.model_dump(mode="json")) for u in child_usages
        ),
        "provider_request_count": len(all_usages),
        "provider_attempt_count": sum(u.attempts for u in all_usages),
        "prompt_tokens": sum(u.prompt_tokens for u in all_usages),
        "completion_tokens": sum(u.completion_tokens for u in all_usages),
        "total_tokens": sum(u.total_tokens for u in all_usages),
        "campaign_provider_attempt_count": sum(u.attempts for u in main) + attempts,
        "campaign_completion_tokens": sum(u.completion_tokens for u in main) + tokens,
        "parent_accounted_cost_usd_exact": _decimal_text(parent_cost),
        "child_accounted_cost_usd_exact": _decimal_text(child_cost),
        "tree_accounted_cost_usd_exact": _decimal_text(tree_cost),
        "other_accounted_cost_usd_exact": _decimal_text(other_cost),
        "campaign_accounted_cost_usd_exact": _decimal_text(campaign_cost),
        "child_reserved_usd_exact": _decimal_text(
            _exact_sum(
                _decimal(c.reserved_usd_exact, label="child reservation") for c in tree.children
            )
        ),
        "campaign_cap_usd_exact": artifact.campaign_cap_usd_exact,
        "parent_cost_refunded": False,
    }
    return TruncationRecoveryTreeAccounting(**values, accounting_sha256=_canonical_sha256(values))


def build_truncation_recovered_tree_artifact(
    *,
    root_family_id: str,
    journal_manifest_sha256: str,
    recovery_prefix: Iterable[SchedulerTruncationRecoveryEntry],
    main_usage_records: Iterable[UsageRecord],
    baseline_spent_usd_exact: str,
    campaign_cap_usd_exact: str,
    analysis_context_sha256: str,
    requests: Iterable[ModelSurfaceReviewRequest],
    parent: TruncationRecoveryParentAttemptEvidence,
    bridges: Iterable[TruncationRecoveryBridgeAttemptEvidence],
    leaves: Iterable[TruncationRecoveryChildCompletionEvidence],
) -> TruncationRecoveredTreeArtifact:
    """Build complete bounded comparison data without issuing any live capability."""

    prefix = validate_truncation_recovery_entry_chain(recovery_prefix)
    exact_parent = _exact_model(parent, TruncationRecoveryParentAttemptEvidence)
    exact_bridges = tuple(
        _exact_model(b, TruncationRecoveryBridgeAttemptEvidence)
        for b in _bounded_tuple(
            bridges, limit=SCHEDULER_TRUNCATION_RECOVERY_MAX_FAMILIES - 1, label="tree bridges"
        )
    )
    exact_leaves = tuple(
        _exact_model(c, TruncationRecoveryChildCompletionEvidence)
        for c in _bounded_tuple(
            leaves, limit=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS, label="tree leaves"
        )
    )
    records, origins = _tree_surfaces(exact_parent, exact_bridges, exact_leaves)
    binding = _invariant_binding(
        analysis_context_sha256=analysis_context_sha256, parent=exact_parent, children=exact_leaves
    )
    values = {
        **_NONAUTHORIZING,
        "schema_version": "1.0",
        "algorithm_version": "mmaudit.truncation-tree-closure.v1",
        "scheduler_custody_verified": False,
        "surface_review_credit_eligible": False,
        "candidate_credit_eligible": False,
        "root_family_id": root_family_id,
        "journal_manifest_sha256": journal_manifest_sha256,
        "recovery_prefix": prefix,
        "main_usage_records": tuple(
            _exact_model(u, UsageRecord)
            for u in _bounded_tuple(
                main_usage_records,
                limit=TRUNCATION_RECOVERY_MAX_PROVIDER_ATTEMPTS,
                label="main usages",
            )
        ),
        "baseline_spent_usd_exact": baseline_spent_usd_exact,
        "campaign_cap_usd_exact": campaign_cap_usd_exact,
        "invariant_binding": binding,
        "requests": tuple(
            _exact_model(r, ModelSurfaceReviewRequest)
            for r in _bounded_tuple(
                requests, limit=MAX_TRUNCATION_CLOSURE_SURFACES, label="tree surfaces"
            )
        ),
        "parent": exact_parent,
        "bridges": exact_bridges,
        "leaves": exact_leaves,
        "records": records,
        "origins": origins,
    }
    # Construction is only a temporary input to exact arithmetic, never returned or registered.
    provisional = TruncationRecoveredTreeArtifact.model_construct(**values)
    values["accounting"] = _tree_accounting(
        provisional,
        truncation_recovery_tree_inventory(prefix, root_family_id=root_family_id),
    )
    algorithm = candidate_review_schema_algorithm_version(
        wire_schema_sha256=binding.wire_schema_sha256,
        normalized_batch_schema_sha256=binding.normalized_batch_schema_sha256,
    )
    return TruncationRecoveredTreeArtifact(
        **values, artifact_sha256=_scheduler_canonical_sha256(values, algorithm_version=algorithm)
    )


@dataclass(frozen=True, slots=True)
class _RecoveredCandidateReviewContent:
    findings: tuple[CandidateFinding, ...]
    surface_reviews: tuple[ModelSurfaceReviewRecord, ...]
    origins: tuple[SchedulerRecoveredCandidateOrigin, ...]
    child_results: tuple[SchedulerTruncationRecoveryChildResult, ...]


def _candidate_review_projection_algorithm(
    projection: CandidateReviewTruncationProjection,
) -> str:
    """Resolve the immutable scheduler algorithm bound by one truncation projection."""

    return candidate_review_schema_algorithm_version(
        wire_schema_sha256=projection.wire_schema_sha256,
        normalized_batch_schema_sha256=projection.normalized_batch_schema_sha256,
    )


def _require_candidate_review_normalization_algorithm(
    normalization: CandidateReviewNormalizationEvidence,
    *,
    algorithm_version: str,
) -> None:
    """Reject a recovery leaf whose normalized schema pair crosses scheduler versions."""

    observed = candidate_review_schema_algorithm_version(
        wire_schema_sha256=normalization.wire_schema_sha256,
        normalized_batch_schema_sha256=normalization.normalized_batch_schema_sha256,
    )
    if observed != algorithm_version:
        raise ValueError("scheduler recovery candidate-review schema custody mixes algorithms")


def rebuild_bounded_tree_candidate_content(
    *,
    family: SchedulerTruncationRecoveryFamilyRoot,
    parent_attempt: SchedulerProviderAttemptEvidence | None,
    nested_families: dict[str, SchedulerTruncationRecoveryFamilyRoot],
    child_plans: dict[str, TruncationRecoveryChildPlan],
    scanner_fingerprints_by_request: tuple[tuple[str, tuple[str, ...]], ...],
    bridges: tuple[SchedulerTruncationRecoveryChildResult, ...],
    leaves: tuple[SchedulerTruncationRecoveryChildResult, ...],
    results: tuple[SchedulerTruncationRecoveryChildResult, ...],
) -> _RecoveredCandidateReviewContent:
    """Replay original frames and host stamping after the caller proves the whole topology."""

    from mmaudit.models.scheduler import scheduler_candidate_payload_sha256

    if not 4 <= len(results) <= TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS:
        raise ValueError("scheduler recovered tree candidate inventory exceeds its original cap")
    if (
        parent_attempt is None
        or parent_attempt.schema_version != "1.1"
        or parent_attempt.truncation_projection != family.truncation_projection
    ):
        raise ValueError("scheduler recursive promotion lacks a typed root parent attempt")
    algorithm_version = _candidate_review_projection_algorithm(family.truncation_projection)

    expected_surface_records = list(family.truncation_projection.surface_reviews)
    raw_candidates: dict[tuple[str, str], tuple[CandidateFinding, dict[str, Any]]] = {}
    usage_by_request: dict[str, UsageRecord] = {}
    parent_usage = parent_attempt.usage_record
    usage_by_request[parent_usage.request_id] = parent_usage
    for finding in family.truncation_projection.findings:
        finding_sha256 = scheduler_candidate_payload_sha256(
            finding,
            algorithm_version=algorithm_version,
        )
        frames = tuple(
            frame
            for frame in family.truncation_projection.accepted_frames
            if frame.phase is CandidateReviewFramePhase.FINDING
            and frame.record_id == finding.candidate_id
            and frame.normalized_value_sha256 == finding_sha256
        )
        if len(frames) != 1:
            raise ValueError("scheduler recursive root finding lacks one accepted frame")
        frame = frames[0]
        raw_candidates[(parent_usage.request_id, finding.candidate_id)] = (
            finding,
            {
                "origin_kind": SchedulerRecoveredCandidateOriginKind.PARENT_FRAME,
                "usage_record_sha256": parent_attempt.usage_record_sha256,
                "context_request_evidence_sha256": (parent_attempt.context_request_evidence_sha256),
                "parent_projection_sha256": family.truncation_projection.evidence_sha256,
                "accepted_frame_sequence": frame.sequence,
                "accepted_frame_sha256": frame.frame_sha256,
            },
        )

    for bridge in bridges:
        bridge_projection = bridge.truncation_projection
        bridge_usage = bridge.runtime_usage_record
        nested = nested_families.get(bridge.child_task_id)
        if (
            bridge_projection is None
            or bridge_usage is None
            or nested is None
            or nested.truncation_projection != bridge_projection
            or _candidate_review_projection_algorithm(bridge_projection) != algorithm_version
            or bridge_usage.request_id in usage_by_request
        ):
            raise ValueError("scheduler tree bridge lacks exact original truncation custody")
        expected_surface_records.extend(bridge_projection.surface_reviews)
        bridge_context_sha256 = bridge_usage.routing.get("context_request_evidence_sha256")
        if not isinstance(bridge_context_sha256, str):
            raise ValueError("scheduler recursive promotion bridge lacks context-request custody")
        usage_by_request[bridge_usage.request_id] = bridge_usage
        for finding in bridge_projection.findings:
            finding_sha256 = scheduler_candidate_payload_sha256(
                finding,
                algorithm_version=algorithm_version,
            )
            frames = tuple(
                frame
                for frame in bridge_projection.accepted_frames
                if frame.phase is CandidateReviewFramePhase.FINDING
                and frame.record_id == finding.candidate_id
                and frame.normalized_value_sha256 == finding_sha256
            )
            if len(frames) != 1:
                raise ValueError("scheduler recursive bridge finding lacks one accepted frame")
            frame = frames[0]
            key = (bridge_usage.request_id, finding.candidate_id)
            if key in raw_candidates:
                raise ValueError("scheduler recursive raw bridge candidate is duplicated")
            raw_candidates[key] = (
                finding,
                {
                    "origin_kind": SchedulerRecoveredCandidateOriginKind.TRUNCATED_CHILD_FRAME,
                    "usage_record_sha256": bridge.runtime_usage_record_sha256,
                    "context_request_evidence_sha256": bridge_context_sha256,
                    "child_task_id": bridge.child_task_id,
                    "child_result_sha256": bridge.entry_sha256,
                    "truncation_projection_sha256": bridge_projection.evidence_sha256,
                    "accepted_frame_sequence": frame.sequence,
                    "accepted_frame_sha256": frame.frame_sha256,
                },
            )

    for result in leaves:
        usage = result.runtime_usage_record
        normalized_batch = result.runtime_normalized_batch
        output_artifact = result.runtime_output_artifact
        normalization = result.runtime_normalization_evidence
        child = child_plans.get(result.child_task_id)
        if (
            usage is None
            or normalized_batch is None
            or output_artifact is None
            or normalization is None
            or child is None
        ):
            raise ValueError("scheduler recursive promotion leaf lacks typed runtime custody")
        _require_candidate_review_normalization_algorithm(
            normalization,
            algorithm_version=algorithm_version,
        )
        if usage.request_id in usage_by_request:
            raise ValueError("scheduler recursive promotion reused a request identity")
        usage_by_request[usage.request_id] = usage
        expected_surface_records.extend(output_artifact.records)
        context_sha256 = usage.routing.get("context_request_evidence_sha256")
        if not isinstance(context_sha256, str):
            raise ValueError("scheduler recursive promotion leaf lacks context-request custody")
        for finding in normalized_batch.findings:
            key = (usage.request_id, finding.candidate_id)
            if key in raw_candidates:
                raise ValueError("scheduler recursive raw leaf candidate is duplicated")
            raw_candidates[key] = (
                finding,
                {
                    "origin_kind": SchedulerRecoveredCandidateOriginKind.CHILD_BATCH,
                    "usage_record_sha256": result.runtime_usage_record_sha256,
                    "context_request_evidence_sha256": context_sha256,
                    "child_task_id": child.child_task_id,
                    "child_result_sha256": result.entry_sha256,
                    "normalization_evidence_sha256": normalization.evidence_sha256,
                    "surface_artifact_sha256": output_artifact.artifact_sha256,
                },
            )

    scanner_projection = dict(scanner_fingerprints_by_request)
    if (
        len(usage_by_request) != len(results) + 1
        or len(scanner_projection) != len(scanner_fingerprints_by_request)
        or set(scanner_projection) != set(usage_by_request)
    ):
        raise ValueError("scheduler tree promotion lacks exact all-request scanner custody")
    if len(raw_candidates) > 5000:
        raise ValueError("scheduler recovered tree exceeds the aggregate candidate limit")
    raw_by_request: dict[str, list[tuple[CandidateFinding, dict[str, Any]]]] = {
        request_id: [] for request_id in usage_by_request
    }
    for (request_id, _raw_candidate_id), raw in raw_candidates.items():
        raw_by_request[request_id].append(raw)

    expected_findings: list[CandidateFinding] = []
    expected_origins: list[SchedulerRecoveredCandidateOrigin] = []
    for request_id in sorted(usage_by_request):
        usage = usage_by_request[request_id]
        entries = tuple(sorted(raw_by_request[request_id], key=lambda item: item[0].candidate_id))
        raw_findings = tuple(item[0] for item in entries)
        try:
            stamped = stamp_candidate_review_findings(
                request_role=usage.role,
                usage_record=usage,
                trusted_scanner_fingerprints=scanner_projection[request_id],
                raw_findings=raw_findings,
            )
        except CandidateReviewStampingError as exc:
            raise ValueError("scheduler recursive candidate stamping failed exact replay") from exc
        for (raw_finding, expected), accepted in zip(entries, stamped, strict=True):
            origin_kind = cast(SchedulerRecoveredCandidateOriginKind, expected["origin_kind"])
            common: dict[str, Any] = {
                "origin_kind": origin_kind,
                "accepted_candidate_id": accepted.candidate_id,
                "accepted_candidate_sha256": scheduler_candidate_payload_sha256(
                    accepted,
                    algorithm_version=algorithm_version,
                ),
                "raw_candidate_id": raw_finding.candidate_id,
                "raw_candidate_sha256": scheduler_candidate_payload_sha256(
                    raw_finding,
                    algorithm_version=algorithm_version,
                ),
                "request_id": request_id,
                "request_role": usage.role,
                "usage_record_sha256": cast(str, expected["usage_record_sha256"]),
                "context_request_evidence_sha256": cast(
                    str,
                    expected["context_request_evidence_sha256"],
                ),
            }
            if origin_kind is SchedulerRecoveredCandidateOriginKind.PARENT_FRAME:
                origin = SchedulerRecoveredCandidateOrigin.build(
                    **common,
                    parent_projection_sha256=cast(str, expected["parent_projection_sha256"]),
                    accepted_frame_sequence=cast(int, expected["accepted_frame_sequence"]),
                    accepted_frame_sha256=cast(str, expected["accepted_frame_sha256"]),
                )
            elif origin_kind is SchedulerRecoveredCandidateOriginKind.TRUNCATED_CHILD_FRAME:
                origin = SchedulerRecoveredCandidateOrigin.build(
                    **common,
                    child_task_id=cast(str, expected["child_task_id"]),
                    child_result_sha256=cast(str, expected["child_result_sha256"]),
                    truncation_projection_sha256=cast(
                        str,
                        expected["truncation_projection_sha256"],
                    ),
                    accepted_frame_sequence=cast(int, expected["accepted_frame_sequence"]),
                    accepted_frame_sha256=cast(str, expected["accepted_frame_sha256"]),
                )
            else:
                origin = SchedulerRecoveredCandidateOrigin.build(
                    **common,
                    child_task_id=cast(str, expected["child_task_id"]),
                    child_result_sha256=cast(str, expected["child_result_sha256"]),
                    normalization_evidence_sha256=cast(
                        str,
                        expected["normalization_evidence_sha256"],
                    ),
                    surface_artifact_sha256=cast(str, expected["surface_artifact_sha256"]),
                )
            expected_findings.append(accepted)
            expected_origins.append(origin)

    return _RecoveredCandidateReviewContent(
        findings=tuple(sorted(expected_findings, key=lambda item: item.candidate_id)),
        surface_reviews=tuple(sorted(expected_surface_records, key=lambda item: item.surface_id)),
        origins=tuple(sorted(expected_origins, key=lambda item: item.accepted_candidate_id)),
        child_results=results,
    )


def full_tree_promotion_binding(
    tree: TruncationRecoveryTreeInventory,
) -> SchedulerTruncationRecoveryFullTreeBinding:
    closures = {item.family_id: item for item in tree.closures}
    return SchedulerTruncationRecoveryFullTreeBinding(
        family_root_sha256s=tuple(item.entry_sha256 for item in tree.families),
        family_closure_sha256s=tuple(
            closures[item.family_id].entry_sha256 for item in tree.families
        ),
        child_result_sha256s=tuple(item.entry_sha256 for item in tree.results),
        bridge_result_sha256s=tuple(
            item.entry_sha256
            for item in tree.results
            if item.terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED
        ),
        leaf_result_sha256s=tuple(
            item.entry_sha256
            for item in tree.results
            if item.terminal_status is SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
        ),
    )


def validate_full_tree_promotion(
    *,
    entries: tuple[SchedulerTruncationRecoveryEntry, ...],
    promotion: SchedulerTruncationRecoveryFamilyPromotion,
    parent_attempt: SchedulerProviderAttemptEvidence,
) -> TruncationRecoveryTreeInventory:
    """Replay comparison data against every original family and candidate source."""

    closures = tuple(
        entry
        for entry in entries
        if isinstance(entry, SchedulerTruncationRecoveryFamilyClosure)
        and entry.entry_sha256 == promotion.family_closure_sha256
    )
    if len(closures) != 1 or closures[0].schema_version != "1.3":
        raise ValueError("public full-tree promotion lacks one original root closure")
    closure = closures[0]
    tree = truncation_recovery_tree_inventory(
        tuple(entry for entry in entries if entry.entry_index <= closure.entry_index),
        root_family_id=promotion.family_id,
    )
    root = tree.families[0]
    if (
        promotion.schema_version != "1.2"
        or promotion.full_tree_binding != full_tree_promotion_binding(tree)
        or promotion.family_root_sha256 != root.entry_sha256
        or promotion.recovery_plan_sha256 != root.recovery_plan.plan_sha256
        or promotion.family_closure_id != closure.closure_id
        or promotion.parent_task_id != root.recovery_plan.parent.parent_task_id
        or promotion.original_truncated_result_sha256 != root.parent_terminal_result_sha256
        or promotion.entry_index <= closure.entry_index
    ):
        raise ValueError("public full-tree promotion differs from every original branch")
    content = rebuild_bounded_tree_candidate_content(
        family=root,
        parent_attempt=parent_attempt,
        nested_families={
            family.recovery_plan.parent.parent_task_id: family for family in tree.families[1:]
        },
        child_plans={child.child_task_id: child for child in tree.children},
        scanner_fingerprints_by_request=promotion.recovered_output.scanner_fingerprints_by_request,
        bridges=tuple(
            result
            for result in tree.results
            if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED
        ),
        leaves=tuple(
            result
            for result in tree.results
            if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
        ),
        results=tree.results,
    )
    output = promotion.recovered_output
    if (
        content.findings != tuple(output.recovered_batch.findings)
        or content.surface_reviews != tuple(output.recovered_batch.surface_reviews)
        or content.origins != output.candidate_origins
    ):
        raise ValueError("public full-tree promotion changed original recovered content")
    return tree


def full_tree_public_requests_match(
    binding: SchedulerTruncationRecoveryFullTreeBinding,
    requests: tuple[SchedulerTruncationRecoveryModelRequestEvidence, ...],
) -> bool:
    """Hash-only topology comparison; not live review authority or contiguous ordinals."""

    from mmaudit.models.scheduler import (
        SchedulerTerminalStatus,
        SchedulerTruncationRecoveryPromotionDisposition,
    )

    ordered = tuple(sorted(requests, key=lambda request: request.global_request_ordinal or 0))
    ordinals = tuple(request.global_request_ordinal for request in ordered)
    if (
        tuple(request.child_result_entry_sha256 for request in ordered)
        != binding.child_result_sha256s
        or None in ordinals
        or len(set(ordinals)) != len(ordinals)
    ):
        return False
    family_groups: dict[str, list[SchedulerTruncationRecoveryModelRequestEvidence]] = {}
    for request in ordered:
        if request.family_root_sha256 is None:
            return False
        family_groups.setdefault(request.family_root_sha256, []).append(request)
        bridge = request.child_result_entry_sha256 in binding.bridge_result_sha256s
        if request.terminal_status is not (
            SchedulerTerminalStatus.TRUNCATED if bridge else SchedulerTerminalStatus.SUCCEEDED
        ):
            return False
        if request.promotion_disposition is not (
            SchedulerTruncationRecoveryPromotionDisposition.SUPERSEDED_TRUNCATED_BRIDGE
            if bridge
            else SchedulerTruncationRecoveryPromotionDisposition.SUCCESSFUL_LEAF
        ):
            return False
    if tuple(family_groups) != binding.family_root_sha256s:
        return False
    return all(
        len(group) == 2
        and group[0].recovery_family_id is not None
        and group[0].recovery_plan_sha256 is not None
        and group[0].family_closure_id is not None
        and all(
            request.recovery_family_id == group[0].recovery_family_id
            and request.recovery_plan_sha256 == group[0].recovery_plan_sha256
            and request.family_closure_id == group[0].family_closure_id
            and request.family_closure_sha256 == closure_sha256
            for request in group
        )
        for group, closure_sha256 in zip(
            family_groups.values(), binding.family_closure_sha256s, strict=True
        )
    )
