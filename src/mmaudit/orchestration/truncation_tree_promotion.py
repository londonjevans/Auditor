"""Original-journal private promotion of fully verified bounded recovery trees.

Private tokens prove the original append and recovered candidate provenance.
Separate public tokens revalidate that custody before any coverage consumer can use it.
"""

from __future__ import annotations

import os
import threading
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from typing import Never, Protocol, SupportsIndex

from mmaudit.models.schemas import CandidateReviewBatch
from mmaudit.models.truncation_recovery_journal import (
    SchedulerRecoveredCandidateReviewOutput,
    SchedulerTruncationRecoveryFamilyPromotion,
    SchedulerTruncationRecoveryPromotionBinding,
)
from mmaudit.models.truncation_tree import (
    full_tree_promotion_binding as _full_tree_promotion_binding,
)
from mmaudit.orchestration.scheduler import (
    SchedulerJournal,
    _full_tree_promotion_capability_binding,
    _rebuild_full_tree_recovered_candidate_content,
)
from mmaudit.orchestration.truncation_recovery_evidence import (
    TruncationRecoveryEvidenceError,
    VerifiedPromotedFullTreeTruncationRecoverySurfaceCoverage,
    VerifiedPromotedFullTreeTruncationRecoverySurfaceCoverageProjection,
)
from mmaudit.orchestration.truncation_tree_evidence import (
    VerifiedTruncationRecoveryFullTree,
    VerifiedTruncationRecoveryFullTreeProjection,
    require_verified_truncation_recovery_full_tree,
)


class VerifiedJournalPromotedTruncationRecoveryTree:
    """Original private append custody, never transferable audit or release authority."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> Never:
        raise TypeError("journal-promoted full tree cannot be constructed directly")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def __copy__(self) -> Never:
        raise TypeError("journal-promoted full tree cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("journal-promoted full tree cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("journal-promoted full tree cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("journal-promoted full tree cannot be serialized")


@dataclass(frozen=True, slots=True)
class JournalPromotedTruncationRecoveryTreeProjection:
    """Fresh comparison data; constructing it cannot confer original append custody."""

    source: VerifiedTruncationRecoveryFullTreeProjection
    promotion: SchedulerTruncationRecoveryFamilyPromotion


@dataclass(frozen=True, slots=True)
class _PromotedTreeState:
    journal: SchedulerJournal
    source: VerifiedTruncationRecoveryFullTree
    family_id: str
    promotion_json: str


class _PromoteTree(Protocol):
    def __call__(
        self,
        *,
        journal: SchedulerJournal,
        capability: VerifiedTruncationRecoveryFullTree,
        existing_only: bool = False,
    ) -> tuple[
        VerifiedJournalPromotedTruncationRecoveryTree,
        SchedulerTruncationRecoveryFamilyPromotion,
    ]: ...


class _RequirePromotedTree(Protocol):
    def __call__(
        self, capability: VerifiedJournalPromotedTruncationRecoveryTree
    ) -> JournalPromotedTruncationRecoveryTreeProjection: ...


def _build_tree_promotion_authority() -> tuple[
    _PromoteTree,
    _RequirePromotedTree,
    Callable[
        [VerifiedJournalPromotedTruncationRecoveryTree],
        VerifiedPromotedFullTreeTruncationRecoverySurfaceCoverage,
    ],
    Callable[
        [VerifiedPromotedFullTreeTruncationRecoverySurfaceCoverage],
        VerifiedPromotedFullTreeTruncationRecoverySurfaceCoverageProjection,
    ],
    Callable[
        [SchedulerJournal], tuple[VerifiedPromotedFullTreeTruncationRecoverySurfaceCoverage, ...]
    ],
]:
    """Capture original verification and append methods, not caller-provided callbacks."""

    require_source = require_verified_truncation_recovery_full_tree
    append = SchedulerJournal._append_truncation_recovery_entry
    assert_writable = SchedulerJournal._assert_writable_custody
    current_promotion = SchedulerJournal._require_current_promoted_truncation_recovery_family
    rebuild_content = _rebuild_full_tree_recovered_candidate_content
    tree_binding = _full_tree_promotion_binding
    capability_binding = _full_tree_promotion_capability_binding
    promotion_type = SchedulerTruncationRecoveryFamilyPromotion
    output_type = SchedulerRecoveredCandidateReviewOutput
    capability_type = VerifiedJournalPromotedTruncationRecoveryTree
    projection_type = JournalPromotedTruncationRecoveryTreeProjection
    state_type = _PromotedTreeState
    current_pid = os.getpid
    owner_pid = current_pid()
    make_weakref = weakref.ref
    lock = threading.RLock()
    registry: dict[
        int,
        tuple[
            weakref.ReferenceType[VerifiedJournalPromotedTruncationRecoveryTree],
            _PromotedTreeState,
        ],
    ] = {}
    public_type = VerifiedPromotedFullTreeTruncationRecoverySurfaceCoverage
    public_projection_type = VerifiedPromotedFullTreeTruncationRecoverySurfaceCoverageProjection
    public_binding = SchedulerTruncationRecoveryPromotionBinding.from_promotion
    public_registry: dict[
        int,
        tuple[
            weakref.ReferenceType[VerifiedPromotedFullTreeTruncationRecoverySurfaceCoverage],
            VerifiedJournalPromotedTruncationRecoveryTree,
        ],
    ] = {}

    def require_process() -> None:
        if current_pid() != owner_pid:
            raise TruncationRecoveryEvidenceError(
                "journal-promoted tree cannot cross a process fork"
            )

    def require(
        capability: VerifiedJournalPromotedTruncationRecoveryTree,
    ) -> JournalPromotedTruncationRecoveryTreeProjection:
        require_process()
        with lock:
            registered = registry.get(id(capability))
        if (
            type(capability) is not capability_type
            or registered is None
            or registered[0]() is not capability
        ):
            raise TruncationRecoveryEvidenceError("journal-promoted tree is absent or forged")
        state = registered[1]
        source = require_source(state.source)
        promotion = current_promotion(state.journal, state.family_id)
        if (
            source.journal is not state.journal
            or promotion.schema_version != "1.2"
            or promotion.model_dump_json() != state.promotion_json
            or promotion.recovered_output.structural_surface_artifact_sha256
            != source.artifact.artifact_sha256
            or tuple(promotion.recovered_output.recovered_batch.surface_reviews)
            != source.artifact.records
        ):
            raise TruncationRecoveryEvidenceError(
                "journal-promoted tree lost original append custody"
            )
        return projection_type(source=source, promotion=promotion)

    def promote(
        *,
        journal: SchedulerJournal,
        capability: VerifiedTruncationRecoveryFullTree,
        existing_only: bool = False,
    ) -> tuple[
        VerifiedJournalPromotedTruncationRecoveryTree,
        SchedulerTruncationRecoveryFamilyPromotion,
    ]:
        require_process()
        source = require_source(capability)
        if source.journal is not journal:
            raise TruncationRecoveryEvidenceError(
                "full-tree promotion requires its original journal"
            )
        assert_writable(journal)
        artifact = source.artifact
        indexes = journal._truncation_recovery_indexes
        family = indexes.families.get(artifact.root_family_id)
        closure = indexes.closures.get(artifact.root_family_id)
        if existing_only:
            retained = current_promotion(journal, artifact.root_family_id)
            if (
                retained.schema_version != "1.2"
                or retained.recovered_output.structural_surface_artifact_sha256
                != artifact.artifact_sha256
                or tuple(retained.recovered_output.recovered_batch.surface_reviews)
                != artifact.records
            ):
                raise TruncationRecoveryEvidenceError(
                    "retained full-tree promotion differs from original live verification"
                )
            return register(journal, capability, retained)
        if (
            family is None
            or closure is None
            or closure.schema_version != "1.3"
            or family.family_id in indexes.promotions
            or not journal._truncation_recovery_entries
            or journal._truncation_recovery_entries[-1] != closure
        ):
            raise TruncationRecoveryEvidenceError(
                "full-tree promotion requires its original live head"
            )
        root_task_id = family.recovery_plan.parent.parent_task_id
        scheduler = journal._indexes
        task_and_plan = scheduler.tasks.get(root_task_id)
        activation = scheduler.activations.get(root_task_id)
        attempt = scheduler.provider_attempts.get(root_task_id)
        result = scheduler.credited_results.get(root_task_id)
        if task_and_plan is None or activation is None or attempt is None or result is None:
            raise TruncationRecoveryEvidenceError(
                "full-tree promotion lost its original root request"
            )
        task, plan = task_and_plan
        ordinals = tuple(
            index
            for index, item in enumerate(journal._plans)
            if item.pass_plan_id == plan.pass_plan_id
        )
        if len(ordinals) != 1 or ordinals[0] < len(journal._pass_results):
            raise TruncationRecoveryEvidenceError(
                "cannot promote a full tree after its pass is sealed"
            )
        content, tree = rebuild_content(
            family=family,
            closure=closure,
            indexes=indexes,
            scheduler=scheduler,
            scanner_fingerprints_by_request=source.scanner_fingerprints_by_request,
        )
        if content.surface_reviews != artifact.records:
            raise TruncationRecoveryEvidenceError("full-tree promotion changed an original surface")
        binding = tree_binding(tree)
        output = output_type.build(
            campaign_id=family.campaign_id,
            pass_plan_id=plan.pass_plan_id,
            parent_task_id=task.task_id,
            parent_logical_request_id=task.logical_request_id,
            parent_activation_sha256=activation.activation_sha256,
            original_truncated_result_sha256=result.result_sha256,
            parent_provider_attempt_sha256=attempt.attempt_evidence_sha256,
            recovery_family_id=family.family_id,
            family_root_sha256=family.entry_sha256,
            family_closure_sha256=closure.entry_sha256,
            structural_surface_artifact_sha256=artifact.artifact_sha256,
            recovered_batch=CandidateReviewBatch(
                findings=content.findings, surface_reviews=content.surface_reviews
            ),
            candidate_origins=content.origins,
            scanner_fingerprints_by_request=source.scanner_fingerprints_by_request,
            delivered_source_descriptor_sha256s=activation.delivered_source_descriptor_sha256s,
            recursive_tree=True,
            algorithm_version=plan.manifest.algorithm_version,
        )
        direct = binding.child_result_sha256s[:2]
        promotion = promotion_type.build(
            family=family,
            closure=closure,
            direct_child_result_sha256s=(direct[0], direct[1]),
            recovered_output=output,
            capability_binding_sha256=capability_binding(
                family=family, closure=closure, output=output, binding=binding
            ),
            entry_index=len(journal._truncation_recovery_entries),
            previous_entry_sha256=journal._truncation_recovery_chain_head,
            full_tree_binding=binding,
        )
        # Persist a detached copy so returned comparison aliases never own journal state.
        append(
            journal, promotion_type.model_validate_json(promotion.model_dump_json(), strict=True)
        )
        source = require_source(capability)
        retained = current_promotion(journal, family.family_id)
        if retained != promotion or source.artifact.artifact_sha256 != artifact.artifact_sha256:
            raise TruncationRecoveryEvidenceError(
                "full-tree promotion changed across the original append"
            )
        return register(journal, capability, promotion)

    def register(
        journal: SchedulerJournal,
        capability: VerifiedTruncationRecoveryFullTree,
        promotion: SchedulerTruncationRecoveryFamilyPromotion,
    ) -> tuple[
        VerifiedJournalPromotedTruncationRecoveryTree, SchedulerTruncationRecoveryFamilyPromotion
    ]:
        token = object.__new__(capability_type)
        key = id(token)

        def discard(
            reference: weakref.ReferenceType[VerifiedJournalPromotedTruncationRecoveryTree],
        ) -> None:
            if current_pid() != owner_pid:
                return
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        with lock:
            registry[key] = (
                make_weakref(token, discard),
                state_type(journal, capability, promotion.family_id, promotion.model_dump_json()),
            )
        return token, promotion

    def require_public(
        capability: VerifiedPromotedFullTreeTruncationRecoverySurfaceCoverage,
    ) -> VerifiedPromotedFullTreeTruncationRecoverySurfaceCoverageProjection:
        require_process()
        with lock:
            registered = public_registry.get(id(capability))
        if (
            type(capability) is not public_type
            or registered is None
            or registered[0]() is not capability
        ):
            raise TruncationRecoveryEvidenceError("public full-tree promotion is absent or forged")
        private = require(registered[1])
        source = private.source
        usage_by_id = {usage.request_id: usage for usage in source.child_usage_records}
        context_by_id = {
            usage.request_id: context
            for usage, context in zip(
                source.child_usage_records, source.child_contexts, strict=True
            )
        }
        return public_projection_type(
            binding=public_binding(private.promotion),
            artifact=source.artifact,
            scanner_fingerprints_by_request=source.scanner_fingerprints_by_request,
            parent_usage_record=source.parent_usage_record,
            parent_context=source.parent_context,
            bridge_usage_records=tuple(
                usage_by_id[b.usage_record.request_id] for b in source.artifact.bridges
            ),
            leaf_usage_records=tuple(
                usage_by_id[c.usage_record.request_id] for c in source.artifact.children
            ),
            bridge_contexts=tuple(
                context_by_id[b.usage_record.request_id] for b in source.artifact.bridges
            ),
            leaf_contexts=tuple(
                context_by_id[c.usage_record.request_id] for c in source.artifact.children
            ),
        )

    def issue_public(
        capability: VerifiedJournalPromotedTruncationRecoveryTree,
    ) -> VerifiedPromotedFullTreeTruncationRecoverySurfaceCoverage:
        private = require(capability)
        with lock:
            existing = tuple(public_registry.values())
        for reference, source_capability in existing:
            token = reference()
            registered_source = registry.get(id(source_capability))
            if (
                token is not None
                and registered_source is not None
                and registered_source[1].journal is private.source.journal
            ):
                retained = require(source_capability)
                if (
                    retained.source.journal is private.source.journal
                    and retained.promotion == private.promotion
                ):
                    require_public(token)
                    return token
        token = object.__new__(public_type)
        key = id(token)

        def discard(
            reference: weakref.ReferenceType[
                VerifiedPromotedFullTreeTruncationRecoverySurfaceCoverage
            ],
        ) -> None:
            if current_pid() != owner_pid:
                return
            with lock:
                current = public_registry.get(key)
                if current is not None and current[0] is reference:
                    public_registry.pop(key, None)

        with lock:
            public_registry[key] = (make_weakref(token, discard), capability)
        require_public(token)
        return token

    def live_public(
        journal: SchedulerJournal,
    ) -> tuple[VerifiedPromotedFullTreeTruncationRecoverySurfaceCoverage, ...]:
        require_process()
        with lock:
            existing = tuple(public_registry.values())
        retained: list[tuple[str, VerifiedPromotedFullTreeTruncationRecoverySurfaceCoverage]] = []
        for reference, private_capability in existing:
            token = reference()
            if token is None:
                continue
            # Inspect only registry-owned source identity before validating this owner.
            registered = registry.get(id(private_capability))
            if registered is not None and registered[1].journal is journal:
                projection = require_public(token)
                retained.append((projection.promotion_entry_sha256, token))
        return tuple(token for _sha256, token in sorted(retained, key=lambda item: item[0]))

    return promote, require, issue_public, require_public, live_public


(
    promote_truncation_recovery_full_tree,
    require_journal_promoted_truncation_recovery_tree,
    issue_promoted_full_tree_surface_coverage,
    require_promoted_full_tree_surface_coverage,
    live_promoted_full_tree_surface_coverages,
) = _build_tree_promotion_authority()
del _build_tree_promotion_authority
