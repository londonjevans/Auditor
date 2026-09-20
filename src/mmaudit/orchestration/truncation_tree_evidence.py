"""Original-journal, process-local verification of bounded complete recovery trees.

This is verification custody only. Neither its opaque token nor its comparison
projection is a journal promotion, a candidate output, or audit/release authority.
"""

from __future__ import annotations

import os
import threading
import weakref
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Never, Protocol, SupportsIndex

from mmaudit.models.schemas import (
    ContextPackage,
    ModelSurfaceReviewArtifact,
    UsageRecord,
)
from mmaudit.models.truncation_closure import (
    TruncationRecoveryBridgeAttemptEvidence,
    TruncationRecoveryChildCompletionEvidence,
    TruncationRecoveryParentAttemptEvidence,
)
from mmaudit.models.truncation_recovery import TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS
from mmaudit.models.truncation_recovery_journal import SchedulerTruncationRecoveryTerminalStatus
from mmaudit.models.truncation_tree import (
    TruncationRecoveredTreeArtifact,
    build_truncation_recovered_tree_artifact,
    truncation_recovery_tree_inventory,
)
from mmaudit.models.usage import (
    is_accountable_usage_record,
    is_recovery_accountable_usage_record,
    is_recovery_creditable_usage_record,
)
from mmaudit.orchestration.context import revalidate_model_surface_context_package
from mmaudit.orchestration.model_review_authority import ModelReviewPreDispatchBinding
from mmaudit.orchestration.scheduler import (
    SchedulerJournal,
    _read_live_recovery_tree_journal_snapshot,
    _ReadRecoveryTreeJournalSnapshot,
)
from mmaudit.orchestration.truncation_recovery_evidence import (
    TruncationRecoveryEvidenceError,
    _AccountableUsagePredicate,
    _bounded_tuple,
    _canonical_model_json,
    _models_are_byte_equal,
    _RecoveryAccountableUsagePredicate,
    _RecoveryCreditableUsagePredicate,
    _require_usage_context,
    _scanner_fingerprint_projection,
    _truncated_envelope_from_usage,
    _validate_surface_record,
    build_truncation_recovery_child_context,
    model_surface_analysis_context_sha256,
)


class VerifiedTruncationRecoveryFullTree:
    """Nontransferable proof of verification, never a substitute for promotion."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> Never:
        raise TypeError("verified full recovery tree cannot be constructed directly")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def __copy__(self) -> Never:
        raise TypeError("verified full recovery tree cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("verified full recovery tree cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("verified full recovery tree cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("verified full recovery tree cannot be serialized")


@dataclass(frozen=True, slots=True)
class VerifiedTruncationRecoveryFullTreeProjection:
    """Fresh comparison projection; construction or serialization grants no authority."""

    journal: SchedulerJournal
    artifact: TruncationRecoveredTreeArtifact
    model_review_bindings: tuple[ModelReviewPreDispatchBinding, ...]
    parent_usage_record: UsageRecord
    child_usage_records: tuple[UsageRecord, ...]
    parent_context: ContextPackage
    child_contexts: tuple[ContextPackage, ...]
    scanner_fingerprints_by_request: tuple[tuple[str, tuple[str, ...]], ...]


@dataclass(frozen=True, slots=True)
class _TreeVerificationState:
    journal: SchedulerJournal
    root_family_id: str
    artifact_json: str
    model_review_bindings: tuple[ModelReviewPreDispatchBinding, ...]
    parent_usage_record: UsageRecord
    child_usage_records: tuple[UsageRecord, ...]
    parent_context_json: str
    child_context_jsons: tuple[str, ...]
    scanner_fingerprints_by_request: tuple[tuple[str, tuple[str, ...]], ...]


class _VerifyFullTree(Protocol):
    def __call__(
        self,
        *,
        journal: SchedulerJournal,
        root_family_id: str,
        parent_usage_record: UsageRecord,
        child_usage_records: Iterable[UsageRecord],
        parent_context: ContextPackage,
        child_contexts: Iterable[ContextPackage],
    ) -> tuple[VerifiedTruncationRecoveryFullTree, TruncationRecoveredTreeArtifact]: ...


class _RequireFullTree(Protocol):
    def __call__(
        self, capability: VerifiedTruncationRecoveryFullTree
    ) -> VerifiedTruncationRecoveryFullTreeProjection: ...


def _verify_live_tree_material(
    *,
    journal: SchedulerJournal,
    root_family_id: str,
    parent_usage_record: UsageRecord,
    child_usage_records: Iterable[UsageRecord],
    parent_context: ContextPackage,
    child_contexts: Iterable[ContextPackage],
    _snapshot_reader: _ReadRecoveryTreeJournalSnapshot = _read_live_recovery_tree_journal_snapshot,
    _parent_predicate: _AccountableUsagePredicate = is_accountable_usage_record,
    _bridge_predicate: _RecoveryAccountableUsagePredicate = is_recovery_accountable_usage_record,
    _leaf_predicate: _RecoveryCreditableUsagePredicate = is_recovery_creditable_usage_record,
) -> VerifiedTruncationRecoveryFullTreeProjection:
    usages = _bounded_tuple(
        child_usage_records, limit=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS, label="tree usages"
    )
    contexts = _bounded_tuple(
        child_contexts, limit=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS, label="tree contexts"
    )
    if (
        type(parent_usage_record) is not UsageRecord
        or type(parent_context) is not ContextPackage
        or any(type(u) is not UsageRecord for u in usages)
        or any(type(c) is not ContextPackage for c in contexts)
        or not _parent_predicate(parent_usage_record, require_real=True)
    ):
        raise TruncationRecoveryEvidenceError(
            "full recovery tree lacks original live parent custody"
        )
    snapshot = _snapshot_reader(owner=journal, root_family_id=root_family_id)
    tree = truncation_recovery_tree_inventory(
        snapshot.recovery_prefix, root_family_id=root_family_id
    )
    if (
        len(usages) != len(tree.children)
        or len(contexts) != len(usages)
        or not _models_are_byte_equal(parent_usage_record, snapshot.parent_usage_record)
    ):
        raise TruncationRecoveryEvidenceError(
            "full recovery tree differs from original journal usage"
        )
    root = tree.families[0]
    requests = root.requested_surface_manifest.requests
    sealed_parent = revalidate_model_surface_context_package(parent_context)
    if tuple(sealed_parent.requested_model_surfaces) != requests:
        raise TruncationRecoveryEvidenceError(
            "full recovery parent context changed its surface set"
        )
    _require_usage_context(usage=parent_usage_record, context=sealed_parent)
    analysis_sha256 = model_surface_analysis_context_sha256(sealed_parent)
    parent_plan = root.recovery_plan.parent
    parent = TruncationRecoveryParentAttemptEvidence.build(
        parent_task_id=parent_plan.parent_task_id,
        parent_activation_sha256=parent_plan.parent_activation_sha256,
        provider_attempt_evidence_sha256=parent_plan.provider_attempt_evidence_sha256,
        usage_record=parent_usage_record,
        envelope=_truncated_envelope_from_usage(parent_usage_record),
        projection=root.truncation_projection,
    )
    request_by_id = {r.surface_id: r for r in requests}
    for record in parent.projection.surface_reviews:
        _validate_surface_record(
            context=sealed_parent,
            request=request_by_id[record.surface_id],
            record=record,
            expected_role=parent_usage_record.role,
        )
    contexts_by_task = {parent_plan.parent_task_id: sealed_parent}
    parent_by_child = {
        child.child_task_id: family.recovery_plan.parent.parent_task_id
        for family in tree.families
        for child in family.recovery_plan.children
    }
    bridges: list[TruncationRecoveryBridgeAttemptEvidence] = []
    leaves: list[TruncationRecoveryChildCompletionEvidence] = []
    sealed_children: list[ContextPackage] = []
    for child, result, usage, context in zip(
        tree.children, tree.results, usages, contexts, strict=True
    ):
        activation = result.runtime_activation
        structural_usage = result.runtime_usage_record
        if (
            activation is None
            or structural_usage is None
            or not _models_are_byte_equal(usage, structural_usage)
        ):
            raise TruncationRecoveryEvidenceError("full recovery child differs from original usage")
        is_bridge = result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED
        predicate = _bridge_predicate if is_bridge else _leaf_predicate
        if not predicate(
            usage,
            request_limit_scope=activation.request_limit_id,
            request_limit_count_before=activation.request_limit_count_before_child,
            require_real=True,
        ):
            raise TruncationRecoveryEvidenceError("full recovery child lacks original live custody")
        sealed = revalidate_model_surface_context_package(context)
        immediate_parent = contexts_by_task.get(parent_by_child[child.child_task_id])
        if (
            immediate_parent is None
            or sealed
            != build_truncation_recovery_child_context(parent_context=immediate_parent, child=child)
            or model_surface_analysis_context_sha256(sealed) != analysis_sha256
        ):
            raise TruncationRecoveryEvidenceError("full recovery context drifted from its ancestor")
        _require_usage_context(usage=usage, context=sealed)
        contexts_by_task[child.child_task_id] = sealed
        sealed_children.append(sealed)
        if is_bridge:
            envelope = result.runtime_truncated_envelope_evidence
            projection = result.truncation_projection
            attempt_sha256 = result.provider_attempt_evidence_sha256
            if envelope is None or projection is None or attempt_sha256 is None:
                raise TruncationRecoveryEvidenceError("full recovery bridge lacks typed evidence")
            bridge = TruncationRecoveryBridgeAttemptEvidence.build(
                child_plan=child,
                activation_sha256=activation.entry_sha256,
                provider_attempt_evidence_sha256=attempt_sha256,
                analysis_context_sha256=analysis_sha256,
                request_limit_scope=activation.request_limit_id,
                request_limit_count_before=activation.request_limit_count_before_child,
                usage_record=usage,
                envelope=envelope,
                projection=projection,
            )
            bridges.append(bridge)
            records = projection.surface_reviews
        else:
            normalization = result.runtime_normalization_evidence
            batch = result.runtime_normalized_batch
            child_requests = result.runtime_requested_surface_requests
            output = result.runtime_output_artifact
            if normalization is None or batch is None or child_requests is None or output is None:
                raise TruncationRecoveryEvidenceError("full recovery leaf lacks typed evidence")
            if tuple(sealed.requested_model_surfaces) != child_requests:
                raise TruncationRecoveryEvidenceError("full recovery leaf changed its surface set")
            leaves.append(
                TruncationRecoveryChildCompletionEvidence.build(
                    child_plan=child,
                    analysis_context_sha256=analysis_sha256,
                    requests=child_requests,
                    request_limit_scope=activation.request_limit_id,
                    request_limit_count_before=activation.request_limit_count_before_child,
                    usage_record=usage,
                    normalization=normalization,
                    normalized_batch=batch,
                    surface_artifact=output,
                )
            )
            records = output.records
        for record in records:
            _validate_surface_record(
                context=sealed,
                request=request_by_id[record.surface_id],
                record=record,
                expected_role=usage.role,
            )
    all_contexts = (sealed_parent, *sealed_children)
    for binding, usage, sealed in zip(
        snapshot.model_review_bindings, (parent_usage_record, *usages), all_contexts, strict=True
    ):
        if (
            binding.request_id != usage.request_id
            or binding.review_role != usage.role
            or binding.requested_model != usage.requested_model
            or binding.rendered_context_sha256 != usage.user_prompt_sha256
            or binding.provider_prompt_sha256 != usage.prompt_sha256
            or binding.response_schema_sha256 != usage.schema_sha256
            or binding.root_lineage != snapshot.model_review_bindings[0].root_lineage
            or binding.requested_surface_manifest_sha256
            != ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(
                tuple(sealed.requested_model_surfaces)
            )
        ):
            raise TruncationRecoveryEvidenceError(
                "full recovery usage differs from original dispatch"
            )
    artifact = build_truncation_recovered_tree_artifact(
        root_family_id=root_family_id,
        journal_manifest_sha256=snapshot.manifest_sha256,
        recovery_prefix=snapshot.recovery_prefix,
        main_usage_records=snapshot.main_usage_records,
        baseline_spent_usd_exact=snapshot.baseline_spent_usd_exact,
        campaign_cap_usd_exact=snapshot.campaign_cap_usd_exact,
        analysis_context_sha256=analysis_sha256,
        requests=requests,
        parent=parent,
        bridges=bridges,
        leaves=leaves,
    )
    return VerifiedTruncationRecoveryFullTreeProjection(
        journal=journal,
        artifact=artifact,
        model_review_bindings=snapshot.model_review_bindings,
        parent_usage_record=parent_usage_record,
        child_usage_records=usages,
        parent_context=sealed_parent,
        child_contexts=tuple(sealed_children),
        scanner_fingerprints_by_request=_scanner_fingerprint_projection(
            parent_request_id=parent_usage_record.request_id,
            parent_context=sealed_parent,
            child_request_ids=tuple(u.request_id for u in usages),
            child_contexts=tuple(sealed_children),
        ),
    )


def _build_full_tree_authority() -> tuple[_VerifyFullTree, _RequireFullTree]:
    capability_type = VerifiedTruncationRecoveryFullTree
    state_type = _TreeVerificationState
    verify_material = _verify_live_tree_material
    canonical_json = _canonical_model_json
    current_pid = os.getpid
    owner_pid = current_pid()
    make_weakref = weakref.ref
    lock = threading.RLock()
    registry: dict[
        int,
        tuple[weakref.ReferenceType[VerifiedTruncationRecoveryFullTree], _TreeVerificationState],
    ] = {}

    def verify(
        *,
        journal: SchedulerJournal,
        root_family_id: str,
        parent_usage_record: UsageRecord,
        child_usage_records: Iterable[UsageRecord],
        parent_context: ContextPackage,
        child_contexts: Iterable[ContextPackage],
    ) -> tuple[VerifiedTruncationRecoveryFullTree, TruncationRecoveredTreeArtifact]:
        if current_pid() != owner_pid:
            raise TruncationRecoveryEvidenceError("full recovery tree cannot cross a process fork")
        material = verify_material(
            journal=journal,
            root_family_id=root_family_id,
            parent_usage_record=parent_usage_record,
            child_usage_records=child_usage_records,
            parent_context=parent_context,
            child_contexts=child_contexts,
        )
        state = state_type(
            journal=journal,
            root_family_id=root_family_id,
            artifact_json=canonical_json(material.artifact),
            model_review_bindings=material.model_review_bindings,
            parent_usage_record=parent_usage_record,
            child_usage_records=material.child_usage_records,
            parent_context_json=canonical_json(material.parent_context),
            child_context_jsons=tuple(canonical_json(c) for c in material.child_contexts),
            scanner_fingerprints_by_request=material.scanner_fingerprints_by_request,
        )
        capability = object.__new__(capability_type)
        key = id(capability)

        def discard(reference: weakref.ReferenceType[VerifiedTruncationRecoveryFullTree]) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        with lock:
            registry[key] = (make_weakref(capability, discard), state)
        return capability, material.artifact

    def require(
        capability: VerifiedTruncationRecoveryFullTree,
    ) -> VerifiedTruncationRecoveryFullTreeProjection:
        if current_pid() != owner_pid:
            raise TruncationRecoveryEvidenceError("full recovery tree cannot cross a process fork")
        with lock:
            registered = registry.get(id(capability))
        if (
            type(capability) is not capability_type
            or registered is None
            or registered[0]() is not capability
        ):
            raise TruncationRecoveryEvidenceError(
                "full recovery tree capability is absent or forged"
            )
        state = registered[1]
        material = verify_material(
            journal=state.journal,
            root_family_id=state.root_family_id,
            parent_usage_record=state.parent_usage_record,
            child_usage_records=state.child_usage_records,
            parent_context=ContextPackage.model_validate_json(
                state.parent_context_json, strict=True
            ),
            child_contexts=tuple(
                ContextPackage.model_validate_json(c, strict=True)
                for c in state.child_context_jsons
            ),
        )
        if (
            canonical_json(material.artifact) != state.artifact_json
            or material.model_review_bindings != state.model_review_bindings
            or material.scanner_fingerprints_by_request != state.scanner_fingerprints_by_request
        ):
            raise TruncationRecoveryEvidenceError(
                "full recovery tree changed during original-live replay"
            )
        return material

    return verify, require


verify_truncation_recovery_full_tree, require_verified_truncation_recovery_full_tree = (
    _build_full_tree_authority()
)
del _build_full_tree_authority
