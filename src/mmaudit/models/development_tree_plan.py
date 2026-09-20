"""Automatic minimal per-primary plans with whole-tree, three-role resource preflight."""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any, Literal, Self

from pydantic import Field, model_validator

from mmaudit.models.development_audit import _AuditArtifact
from mmaudit.models.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_FILES,
    DevelopmentCorpusMaterial,
    DevelopmentCorpusPlan,
    DevelopmentCorpusShardPlan,
    development_corpus_request_body,
    development_corpus_request_id,
)
from mmaudit.models.development_corpus_judgment import development_corpus_judgment_request_body
from mmaudit.models.development_corpus_partition import (
    DevelopmentCorpusPartition,
    _derive_partition_from_replayed_reference,
)
from mmaudit.models.development_corpus_replay import replay_development_corpus_material
from mmaudit.models.development_costs import (
    MAX_DEVELOPMENT_REQUEST_BYTES,
    DevelopmentCostError,
    DevelopmentCostEstimate,
    DevelopmentCostPolicy,
)
from mmaudit.models.development_ensemble import (
    DEVELOPMENT_ENSEMBLE_STAGES,
    DevelopmentEnsembleStageId,
    _require_distinct_roles,
    development_ensemble_stage_run_id,
)
from mmaudit.models.development_judgment import _money_sum
from mmaudit.models.development_review import (
    DevelopmentReviewMetadata,
    _development_metadata,
    _development_request_bytes,
    _DevelopmentModel,
)
from mmaudit.models.development_routing import DevelopmentRoutingContext
from mmaudit.models.development_transport import development_request_timeout_seconds
from mmaudit.models.development_tree_request_bounds import development_tree_review_claims_bound
from mmaudit.orchestration.manifest import canonical_sha256

MAX_DEVELOPMENT_TREE_PLAN_BYTES = 64_000_000
_SHA = r"^[0-9a-f]{64}$"
_RUN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"
type TreeEnvelopeShortfall = Literal[
    "REQUEST_BYTE_LIMIT",
    "PROMPT_LIMIT",
    "CONTEXT_LIMIT",
    "COMPLETION_LIMIT",
    "PER_ATTEMPT_BUDGET",
    "EXACT_REQUEST_REJECTED",
]
type TreePrimaryShortfall = Literal[
    "CALL_CLOSURE_NOT_ESTABLISHED",
    "DERIVED_CLOSURE_REFUSED",
    "ROLE_ENVELOPE_REFUSED",
    "MANIFEST_TIME_ENVELOPE",
    "PLANNING_WORK_BOUND",
]
type TreePlanShortfall = Literal[
    "UNPLACEABLE_PRIMARY",
    "WHOLE_COST_ENVELOPE",
    "WHOLE_REQUEST_ENVELOPE",
    "WHOLE_TIME_ENVELOPE",
    "PLANNING_WORK_BOUND",
]


class DevelopmentTreePlanPolicy(_DevelopmentModel):
    """Scheduling inputs; the embedded cost and route policies retain their existing meaning."""

    run_id: str = Field(pattern=_RUN)
    cost_policy: DevelopmentCostPolicy
    role_metadata: tuple[DevelopmentReviewMetadata, ...] = Field(min_length=3, max_length=3)
    maximum_completion_tokens: tuple[int, int, int] = (4096, 4096, 4096)
    maximum_manifest_seconds: int = Field(default=600, ge=1, le=1800)
    maximum_total_seconds: int = Field(ge=1, le=MAX_DEVELOPMENT_CORPUS_FILES * 1800)
    maximum_requests: int = Field(default=MAX_DEVELOPMENT_CORPUS_FILES * 3, ge=1, le=768)
    local_processing_allowance_seconds: int = Field(default=30, ge=1, le=1800)

    @model_validator(mode="after")
    def existing_roles_attempts_and_completion_bounds(self) -> Self:
        if self.cost_policy.maximum_attempts != 1:
            raise ValueError("automatic tree plans do not introduce retries")
        contexts = []
        for metadata, tokens in zip(
            self.role_metadata, self.maximum_completion_tokens, strict=True
        ):
            snapshot, discovery = _development_metadata(metadata)
            if type(tokens) is not int or not 1 <= tokens <= 65536:
                raise ValueError("automatic tree completion allowance is invalid")
            contexts.append(DevelopmentRoutingContext.from_metadata(snapshot, discovery))
        _require_distinct_roles(tuple(contexts))
        return self


class DevelopmentTreeRoleEnvelope(_DevelopmentModel):
    """Candidate exact bytes or reviewer size-only upper bound; never future billed cost."""

    role: DevelopmentEnsembleStageId
    kind: Literal["EXACT_CANDIDATE_REQUEST", "REVIEW_SCHEMA_SERIALIZATION_UPPER_BOUND"]
    serialized_request_bytes: int = Field(gt=0, le=256_000_000)
    estimate: DevelopmentCostEstimate | None
    shortfalls: tuple[TreeEnvelopeShortfall, ...] = Field(max_length=6)


class DevelopmentTreePrimaryPlan(_DevelopmentModel):
    primary_filename: str = Field(min_length=1, max_length=512)
    case_run_id: str = Field(pattern=_RUN)
    partition: DevelopmentCorpusPartition | None
    candidate: DevelopmentCorpusPlan | None
    role_envelopes: tuple[DevelopmentTreeRoleEnvelope, ...] = Field(max_length=3)
    shortfalls: tuple[TreePrimaryShortfall, ...] = Field(max_length=5)


def _case_id(
    policy: DevelopmentTreePlanPolicy, reference: DevelopmentCorpusMaterial, path: str
) -> str:
    return (
        "dvt-"
        + canonical_sha256(
            {
                "run_id": policy.run_id,
                "reference": reference.manifest.manifest_sha256,
                "primary": path,
            }
        )[:60]
    )


def _envelope(
    policy: DevelopmentTreePlanPolicy,
    role_index: int,
    body: dict[str, Any],
    request_id: str,
) -> DevelopmentTreeRoleEnvelope:
    snapshot, _ = _development_metadata(policy.role_metadata[role_index])
    endpoint = snapshot.endpoints[0]
    size = len(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
    tokens = policy.maximum_completion_tokens[role_index]
    shortfalls: list[TreeEnvelopeShortfall] = []
    checks: tuple[tuple[bool, TreeEnvelopeShortfall], ...] = (
        (size > MAX_DEVELOPMENT_REQUEST_BYTES, "REQUEST_BYTE_LIMIT"),
        (size > endpoint.max_prompt_tokens, "PROMPT_LIMIT"),
        (size + tokens > endpoint.context_length, "CONTEXT_LIMIT"),
        (tokens > endpoint.max_completion_tokens, "COMPLETION_LIMIT"),
    )
    for failed, code in checks:
        if failed:
            shortfalls.append(code)
    estimate = None
    if not shortfalls:
        try:
            _, estimate = _development_request_bytes(policy.cost_policy, snapshot, request_id, body)
            if not estimate.within_estimated_budget:
                shortfalls.append("PER_ATTEMPT_BUDGET")
        except DevelopmentCostError:
            shortfalls.append("EXACT_REQUEST_REJECTED")
    return DevelopmentTreeRoleEnvelope(
        role=DEVELOPMENT_ENSEMBLE_STAGES[role_index],
        kind="EXACT_CANDIDATE_REQUEST"
        if role_index == 0
        else "REVIEW_SCHEMA_SERIALIZATION_UPPER_BOUND",
        serialized_request_bytes=size,
        estimate=estimate,
        shortfalls=tuple(shortfalls),
    )


def _primary(
    reference: DevelopmentCorpusMaterial,
    policy: DevelopmentTreePlanPolicy,
    path: str,
    claims_bound: str,
    work_refused: bool,
) -> DevelopmentTreePrimaryPlan:
    case_id = _case_id(policy, reference, path)
    witness = reference.manifest.dependency_evidence
    assert witness is not None and witness.static_call_closure is not None
    closure = next(p for p in witness.static_call_closure.primaries if p.primary == path)
    reasons: list[TreePrimaryShortfall] = []
    if closure.call_closure != "CALL_CLOSED":
        reasons.append("CALL_CLOSURE_NOT_ESTABLISHED")
    if work_refused:
        reasons.append("PLANNING_WORK_BOUND")
    minimum_seconds = 3 * (development_request_timeout_seconds(policy.cost_policy) + 5)
    if (
        minimum_seconds + policy.local_processing_allowance_seconds
        > policy.maximum_manifest_seconds
    ):
        reasons.append("MANIFEST_TIME_ENVELOPE")
    partition = None
    candidate = None
    envelopes: list[DevelopmentTreeRoleEnvelope] = []
    if closure.call_closure == "CALL_CLOSED" and not work_refused:
        try:
            partition = _derive_partition_from_replayed_reference(reference, (path,))
        except ValueError:
            reasons.append("DERIVED_CLOSURE_REFUSED")
    if partition is not None:
        members = {s.filename for s in partition.manifest.sources}
        files = tuple((p, b) for p, b in reference.source_files if p in members)
        for index, role in enumerate(DEVELOPMENT_ENSEMBLE_STAGES):
            snapshot, _ = _development_metadata(policy.role_metadata[index])
            stage_id = development_ensemble_stage_run_id(case_id, role)
            if index == 0:
                body = development_corpus_request_body(
                    snapshot=snapshot,
                    manifest=partition.manifest,
                    source_files=files,
                    primary_filename=path,
                    maximum_completion_tokens=policy.maximum_completion_tokens[index],
                )
                request_id = development_corpus_request_id(stage_id, partition.manifest, path)
            else:
                body = development_corpus_judgment_request_body(
                    snapshot=snapshot,
                    manifest=partition.manifest,
                    source_files=files,
                    primary_filename=path,
                    claims_json=claims_bound,
                    maximum_completion_tokens=policy.maximum_completion_tokens[index],
                )
                # This identity labels a bound, not a request using an invented candidate hash.
                request_id = "bound-" + canonical_sha256({"case": case_id, "role": role})[:58]
            envelopes.append(_envelope(policy, index, body, request_id))
        if any(e.shortfalls for e in envelopes):
            reasons.append("ROLE_ENVELOPE_REFUSED")
        estimate = envelopes[0].estimate
        if estimate is not None and not envelopes[0].shortfalls:
            index = next(
                i for i, s in enumerate(partition.manifest.sources, 1) if s.filename == path
            )
            snapshot, discovery = _development_metadata(policy.role_metadata[0])
            values: dict[str, Any] = dict(
                run_id=development_ensemble_stage_run_id(case_id, "candidate"),
                manifest=partition.manifest,
                routing=DevelopmentRoutingContext.from_metadata(snapshot, discovery),
                shards=(
                    DevelopmentCorpusShardPlan(
                        shard_id=f"file-{index:04d}",
                        primary_filename=path,
                        source_sha256=partition.manifest.sources[index - 1].sha256,
                        estimate=estimate,
                    ),
                ),
                maximum_run_seconds=float(policy.maximum_manifest_seconds),
                estimated_total_cost_usd=estimate.estimated_cost_per_attempt_usd,
            )
            raw = DevelopmentCorpusPlan.model_construct(**values, plan_sha256="0" * 64)
            candidate = DevelopmentCorpusPlan.model_validate(
                {
                    **values,
                    "plan_sha256": canonical_sha256(
                        raw.model_dump(mode="json", exclude={"plan_sha256"})
                    ),
                }
            )
    return DevelopmentTreePrimaryPlan(
        primary_filename=path,
        case_run_id=case_id,
        partition=partition,
        candidate=candidate,
        role_envelopes=tuple(envelopes),
        shortfalls=tuple(reasons),
    )


def _projection(
    reference: DevelopmentCorpusMaterial, policy: DevelopmentTreePlanPolicy
) -> dict[str, Any]:
    witness = reference.manifest.dependency_evidence
    if (
        reference.manifest.source_tree_evidence is None
        or reference.manifest.source_origin is not None
        or witness is None
        or witness.static_call_closure is None
    ):
        raise ValueError(
            "automatic tree planning requires the complete original static-closure universe"
        )
    sizes = {s.filename: s.size for s in reference.manifest.sources}
    work = reference.manifest.total_source_bytes + sum(
        sizes[p] for primary in witness.static_call_closure.primaries for p in primary.members
    )
    work_refused = work > MAX_DEVELOPMENT_TREE_PLAN_BYTES
    claims_bound, schema_pin = development_tree_review_claims_bound()
    primaries = tuple(_primary(reference, policy, p, claims_bound, work_refused) for p in sizes)
    # Reuse existing ensemble allowances, not just currently observed cheap or empty reviews.
    headroom = _money_sum(
        c.candidate.estimated_total_cost_usd + 2 * policy.cost_policy.per_attempt_budget_usd
        for c in primaries
        if c.candidate is not None
    )
    requests = 3 * len(primaries)
    seconds = len(primaries) * policy.maximum_manifest_seconds
    shortfalls: list[TreePlanShortfall] = []
    checks: tuple[tuple[bool, TreePlanShortfall], ...] = (
        (any(p.shortfalls for p in primaries), "UNPLACEABLE_PRIMARY"),
        (headroom > policy.cost_policy.total_budget_usd, "WHOLE_COST_ENVELOPE"),
        (requests > policy.maximum_requests, "WHOLE_REQUEST_ENVELOPE"),
        (seconds > policy.maximum_total_seconds, "WHOLE_TIME_ENVELOPE"),
        (work_refused, "PLANNING_WORK_BOUND"),
    )
    for failed, code in checks:
        if failed:
            shortfalls.append(code)
    return dict(
        primaries=primaries,
        review_claim_schema_sha256=schema_pin,
        source_replay_bytes=work,
        maximum_requests=requests,
        reserved_run_seconds=seconds,
        estimated_headroom_usd=headroom,
        headroom_complete=all(
            p.candidate is not None
            and len(p.role_envelopes) == 3
            and all(e.estimate is not None for e in p.role_envelopes)
            for p in primaries
        ),
        shortfalls=tuple(shortfalls),
        status="REFUSED" if shortfalls else "READY",
    )


class DevelopmentTreePlan(_AuditArtifact):
    """All original files are primaries; READY is estimated schedulability, never audit authority."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_tree_plan"] = "development_tree_plan"
    partition_policy: Literal["ONE_PRIMARY_MINIMAL_ORIGINAL_CLOSURE_V1"] = (
        "ONE_PRIMARY_MINIMAL_ORIGINAL_CLOSURE_V1"
    )
    interpretation: Literal[
        "CONDITIONAL_RESOURCE_ENVELOPES_NOT_A_COMPLETION_OR_PRICE_GUARANTEE"
    ] = "CONDITIONAL_RESOURCE_ENVELOPES_NOT_A_COMPLETION_OR_PRICE_GUARANTEE"
    reference: DevelopmentCorpusMaterial
    policy: DevelopmentTreePlanPolicy
    review_claim_schema_sha256: str = Field(pattern=_SHA)
    primaries: tuple[DevelopmentTreePrimaryPlan, ...] = Field(min_length=1, max_length=256)
    source_replay_bytes: int = Field(gt=0, le=2_155_872_256)
    maximum_requests: int = Field(ge=3, le=768)
    reserved_run_seconds: int = Field(ge=1, le=460800)
    estimated_headroom_usd: Decimal = Field(ge=0)
    headroom_complete: bool
    status: Literal["READY", "REFUSED"]
    shortfalls: tuple[TreePlanShortfall, ...] = Field(max_length=5)
    plan_sha256: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def all_source_slots_and_envelopes_recompute(self) -> Self:
        if len(self.model_dump_json().encode()) > MAX_DEVELOPMENT_TREE_PLAN_BYTES:
            raise ValueError("automatic tree plan exceeds its aggregate byte bound")
        expected = _projection(self.reference, self.policy)
        if any(getattr(self, key) != value for key, value in expected.items()):
            raise ValueError(
                "automatic tree plan changed its source population or resource envelopes"
            )
        if self.plan_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"plan_sha256"})
        ):
            raise ValueError("automatic tree plan digest differs")
        return self


def plan_development_tree(
    *,
    reference: DevelopmentCorpusMaterial,
    policy: DevelopmentTreePlanPolicy,
) -> DevelopmentTreePlan:
    """Derive every minimal closure before any bundle write, ledger access or provider call."""

    if (
        type(reference) is not DevelopmentCorpusMaterial
        or type(policy) is not DevelopmentTreePlanPolicy
    ):
        raise ValueError("automatic tree plan requires exact material and policy types")
    reference = replay_development_corpus_material(reference.model_dump_json())
    policy = DevelopmentTreePlanPolicy.model_validate_json(policy.model_dump_json(), strict=True)
    values = dict(reference=reference, policy=policy, **_projection(reference, policy))
    raw = DevelopmentTreePlan.model_construct(**values, plan_sha256="0" * 64)
    return DevelopmentTreePlan.model_validate(
        {
            **values,
            "plan_sha256": canonical_sha256(raw.model_dump(mode="json", exclude={"plan_sha256"})),
        }
    )


def read_development_tree_plan(content: bytes) -> DevelopmentTreePlan:
    if type(content) is not bytes or not 0 < len(content) <= MAX_DEVELOPMENT_TREE_PLAN_BYTES:
        raise ValueError("automatic tree plan input exceeds its byte bound")
    return DevelopmentTreePlan.model_validate_json(content, strict=True)
