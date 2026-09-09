"""Owned sequential manifest-candidate reviews, with original gaps and charges kept intact."""

from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import httpx
from pydantic import BaseModel

from mmaudit.models.development_audit import development_ledger_request_id
from mmaudit.models.development_corpus import (
    DevelopmentCorpusAccountingEntry,
    DevelopmentCorpusMaterial,
    DevelopmentCorpusText,
)
from mmaudit.models.development_corpus_ensemble import (
    MAX_DEVELOPMENT_CORPUS_ENSEMBLE_BYTES,
    manifest_review_has_all_available_opinions,
)
from mmaudit.models.development_corpus_judgment import (
    MAX_DEVELOPMENT_CORPUS_JUDGMENT_ARTIFACT_BYTES,
    DevelopmentCorpusJudgmentObservation,
    DevelopmentCorpusJudgmentPlan,
    DevelopmentCorpusJudgmentShardObservation,
    PreparedDevelopmentCorpusJudgment,
    PreparedDevelopmentCorpusJudgmentShard,
    prepare_development_corpus_judgment,
)
from mmaudit.models.development_ensemble import _require_distinct_roles
from mmaudit.models.development_judgment import (
    _money_sum,
    validate_development_accounting_entries,
    validate_development_candidate_accounting,
)
from mmaudit.models.development_review import DevelopmentReviewDiagnostic
from mmaudit.models.development_routing import (
    DEVELOPMENT_GENERATION_ID,
    DevelopmentRoutingEvidence,
    DevelopmentRoutingFailure,
)
from mmaudit.models.development_transport import review_development_corpus_judgment_shard
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.development_budget import development_uncertain_reservations
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release_io import revalidate_evidence_file_binding, write_json_evidence
from mmaudit.repository.directory_custody import (
    DirectoryCustodyObservation,
    prepare_owned_empty_directory,
    require_same_unlinked_directory_objects,
)
from mmaudit.repository.redaction import detect_secrets

type _Transport = Literal["MOCK_HTTP", "HTTP_OBSERVATION"]
type _StopReason = Literal[
    "JUDGMENT_INCOMPLETE", "CANDIDATE_INCOMPLETE", "LOCAL_FAILURE", "INTERRUPTED"
]


class DevelopmentCorpusJudgmentError(ValueError):
    """Controlled refusal without provider prose, source content, paths or credential detail."""


@dataclass(frozen=True)
class DevelopmentCorpusJudgmentUpstream:
    """Owned parent/previous-stage custody; no callbacks or additional provider input."""

    evidence_root: Path
    directories: tuple[DirectoryCustodyObservation, ...]
    files: tuple[ManifestFileBinding, ...]
    prior_review: DevelopmentCorpusJudgmentObservation | None = None


def require_development_corpus_upstream(
    upstream: DevelopmentCorpusJudgmentUpstream,
    *,
    prepared: PreparedDevelopmentCorpusJudgment,
    ledger: AtomicCostLedger,
) -> None:
    """Before each review request, preserve every retained upstream byte and stage charge."""

    if (
        type(upstream) is not DevelopmentCorpusJudgmentUpstream
        or not isinstance(upstream.evidence_root, Path)
        or not upstream.evidence_root.is_absolute()
        or ".." in upstream.evidence_root.parts
        or type(upstream.directories) is not tuple
        or not 2 <= len(upstream.directories) <= 3
        or type(upstream.files) is not tuple
        or not 1 <= len(upstream.files) <= 200
        or any(type(d) is not DirectoryCustodyObservation for d in upstream.directories)
        or any(
            type(f) is not ManifestFileBinding
            or not 0 < f.size <= MAX_DEVELOPMENT_CORPUS_ENSEMBLE_BYTES
            for f in upstream.files
        )
    ):
        raise DevelopmentCorpusJudgmentError("manifest judgment upstream custody is invalid")
    root = upstream.evidence_root
    prior = upstream.prior_review
    expected_directories = (
        root,
        root / "candidate",
        *((root / "review-01",) if prior is not None else ()),
    )
    if tuple(d.path for d in upstream.directories) != expected_directories or any(
        not d.component_identities or d.component_identities[-1][0] != d.path
        for d in upstream.directories
    ):
        raise DevelopmentCorpusJudgmentError("manifest judgment upstream directory scope differs")
    required = {
        "plan.json",
        "sources.json",
        "candidate/plan.json",
        "candidate/sources.json",
        "candidate/result.json",
    }
    required.update(
        "candidate/" + s.shard_id + ".json" for s in prepared.plan.candidate.observations
    )
    if prior is not None:
        if type(prior) is not DevelopmentCorpusJudgmentObservation:
            raise DevelopmentCorpusJudgmentError("manifest judgment prior review type differs")
        content = prior.model_dump_json()
        if len(content.encode()) > MAX_DEVELOPMENT_CORPUS_JUDGMENT_ARTIFACT_BYTES or detect_secrets(
            content
        ):
            raise DevelopmentCorpusJudgmentError("manifest judgment prior review exceeds its bound")
        prior = DevelopmentCorpusJudgmentObservation.model_validate_json(content, strict=True)
        if (
            prior.plan.candidate != prepared.plan.candidate
            or prior.plan.policy != prepared.plan.policy
            or prior.plan.run_id == prepared.plan.run_id
            or not manifest_review_has_all_available_opinions(prior)
        ):
            raise DevelopmentCorpusJudgmentError("manifest judgment prior stage selection differs")
        _require_distinct_roles(
            (prepared.plan.candidate.plan.routing, prior.plan.reviewer, prepared.plan.reviewer)
        )
        required.update(
            {
                "review-01-plan.json",
                "review-01/plan.json",
                "review-01/sources.json",
                "review-01/result.json",
            }
        )
        required.update("review-01/" + s.shard_id + ".json" for s in prior.observations)
        validate_development_accounting_entries(
            prior.accounting, ledger.snapshot(), budget_usd=prepared.plan.policy.total_budget_usd
        )
    paths = tuple(f.path for f in upstream.files)
    if len(paths) != len(set(paths)) or not required <= set(paths):
        raise DevelopmentCorpusJudgmentError("manifest judgment upstream artifact scope differs")
    validate_development_candidate_accounting(prepared.plan.candidate, ledger.snapshot())
    for directory in upstream.directories:
        require_same_unlinked_directory_objects(directory, label="manifest judgment upstream")
    for binding in upstream.files:
        revalidate_evidence_file_binding(
            evidence_root=root, binding=binding, max_bytes=binding.size
        )


def _rebuild(prepared: PreparedDevelopmentCorpusJudgment) -> PreparedDevelopmentCorpusJudgment:
    if (
        type(prepared) is not PreparedDevelopmentCorpusJudgment
        or type(prepared.plan) is not DevelopmentCorpusJudgmentPlan
        or type(prepared.shards) is not tuple
        or any(type(s) is not PreparedDevelopmentCorpusJudgmentShard for s in prepared.shards)
    ):
        raise DevelopmentCorpusJudgmentError("manifest judgment requires exact prepared types")
    plan = DevelopmentCorpusJudgmentPlan.model_validate_json(
        prepared.plan.model_dump_json(), strict=True
    )
    rebuilt = prepare_development_corpus_judgment(
        candidate=plan.candidate,
        policy=plan.policy,
        endpoint_snapshot=prepared.endpoint_snapshot,
        source_files=prepared.source_files,
        run_id=plan.run_id,
        maximum_completion_tokens=plan.maximum_completion_tokens,
        maximum_run_seconds=plan.maximum_run_seconds,
    )
    if rebuilt != prepared:
        raise DevelopmentCorpusJudgmentError(
            "manifest judgment source, candidate or request changed"
        )
    return rebuilt


def _write(output_dir: Path, filename: str, model: BaseModel) -> ManifestFileBinding:
    """Use the existing private evidence writer with an explicit larger composed-record ceiling."""

    expected = model.model_dump(mode="json")

    def validate(content: bytes) -> None:
        restored = type(model).model_validate_json(content, strict=True)
        if restored.model_dump(mode="json") != expected:
            raise DevelopmentCorpusJudgmentError(
                "manifest judgment output differs from its observation"
            )

    return write_json_evidence(
        evidence_root=output_dir,
        relative_path=filename,
        value=expected,
        max_bytes=MAX_DEVELOPMENT_CORPUS_JUDGMENT_ARTIFACT_BYTES,
        validate_content=validate,
        require_private_parent=True,
    )


def _report(
    prepared: PreparedDevelopmentCorpusJudgment,
    ledger: AtomicCostLedger,
    observations: list[DevelopmentCorpusJudgmentShardObservation],
    transport: _Transport,
    reason: _StopReason | None,
    elapsed: float,
) -> DevelopmentCorpusJudgmentObservation:
    snapshot = ledger.snapshot()
    validate_development_candidate_accounting(prepared.plan.candidate, snapshot)
    entries = {entry.request_id: entry for entry in snapshot.entries}
    accounting: list[DevelopmentCorpusAccountingEntry] = []
    for shard in prepared.plan.shards:
        entry = entries.get(development_ledger_request_id(shard.estimate.request_id))
        if entry is not None:
            accounting.append(
                DevelopmentCorpusAccountingEntry(
                    shard_id=shard.shard_id,
                    ledger_request_id=entry.request_id,
                    reservation_id=entry.reservation_id,
                    status=entry.status,
                    reserved_usd=entry.reserved_usd,
                    actual_cost_usd=entry.actual_cost_usd,
                    accounted_cost_usd=entry.accounted_cost_usd,
                )
            )
    reviewed = {c.claim_id for s in observations if s.status == "OBSERVED" for c in s.claims}
    gaps = tuple(
        c.claim_id for s in prepared.plan.shards for c in s.claims if c.claim_id not in reviewed
    )
    if reason is None and prepared.plan.candidate.status != "OBSERVED_ALL_SHARDS":
        reason = "CANDIDATE_INCOMPLETE"
    cost = _money_sum(e.accounted_cost_usd for e in accounting)
    return DevelopmentCorpusJudgmentObservation(
        plan=prepared.plan,
        transport=transport,
        status="INCOMPLETE"
        if gaps or reason is not None
        else ("OBSERVED_ALL_JUDGMENTS" if prepared.plan.shards else "NO_CANDIDATES"),
        stop_reason=reason,
        observations=tuple(observations),
        accounting=tuple(accounting),
        unobserved_candidate_shard_ids=prepared.plan.unobserved_candidate_shard_ids,
        unreviewed_claim_ids=gaps,
        completed_judgment_count=len(reviewed),
        judgment_accounted_cost_usd=cost,
        combined_accounted_cost_usd=_money_sum(
            (cost, prepared.plan.candidate.total_accounted_cost_usd)
        ),
        active_reserved_usd=_money_sum(
            e.reserved_usd for e in accounting if e.status is CostEntryStatus.RESERVED
        ),
        elapsed_seconds=elapsed,
        summed_stage_elapsed_seconds=elapsed + prepared.plan.candidate.elapsed_seconds,
    )


async def run_development_corpus_judgment(
    *,
    prepared: PreparedDevelopmentCorpusJudgment,
    ledger: AtomicCostLedger,
    operator_secrets: OperatorSecrets,
    output_dir: Path,
    allow_code_egress: bool = False,
    mock_transport: httpx.MockTransport | None = None,
    excluded_generation_ids: tuple[str, ...] = (),
    upstream: DevelopmentCorpusJudgmentUpstream | None = None,
    output_custody: DirectoryCustodyObservation | None = None,
    parent_deadline: float | None = None,
) -> DevelopmentCorpusJudgmentObservation:
    """Review observed claims once; preserve incomplete source scope, all charges and cancellation.

    Same-ledger checks and generation exclusions prevent repeated charged evidence from becoming
    fresh review credit. Distinct model identities never establish verified root independence.
    """

    if allow_code_egress is not True:
        raise DevelopmentCorpusJudgmentError(
            "manifest judgment requires explicit source egress consent"
        )
    if parent_deadline is not None and (
        type(parent_deadline) is not float
        or not math.isfinite(parent_deadline)
        or parent_deadline <= 0
    ):
        raise DevelopmentCorpusJudgmentError("manifest judgment parent deadline is invalid")
    if (
        type(ledger) is not AtomicCostLedger
        or type(operator_secrets) is not OperatorSecrets
        or not operator_secrets.openrouter_api_key_present
    ):
        raise DevelopmentCorpusJudgmentError(
            "manifest judgment requires exact ledger and credential handles"
        )
    if mock_transport is not None and type(mock_transport) is not httpx.MockTransport:
        raise DevelopmentCorpusJudgmentError(
            "manifest judgment test transport must be an exact MockTransport"
        )
    if (
        type(excluded_generation_ids) is not tuple
        or len(excluded_generation_ids) > 128
        or any(
            type(v) is not str
            or DEVELOPMENT_GENERATION_ID.fullmatch(v) is None
            or detect_secrets(v)
            or operator_secrets.openrouter_api_key in v
            for v in excluded_generation_ids
        )
        or len(set(excluded_generation_ids)) != len(excluded_generation_ids)
    ):
        raise DevelopmentCorpusJudgmentError(
            "manifest judgment prior-generation exclusion is invalid"
        )
    prepared = _rebuild(prepared)
    transport: _Transport = "MOCK_HTTP" if mock_transport is not None else "HTTP_OBSERVATION"
    if prepared.plan.candidate.transport != transport:
        raise DevelopmentCorpusJudgmentError(
            "manifest judgment cannot mix mock and HTTP observations"
        )
    if operator_secrets.openrouter_api_key in prepared.plan.model_dump_json():
        raise DevelopmentCorpusJudgmentError(
            "development credential overlaps retained candidate or plan"
        )
    if upstream is not None:
        require_development_corpus_upstream(upstream, prepared=prepared, ledger=ledger)
        if (
            upstream.prior_review is not None
            and operator_secrets.openrouter_api_key in upstream.prior_review.model_dump_json()
        ):
            raise DevelopmentCorpusJudgmentError("development credential overlaps prior review")
    state = ledger.snapshot()
    validate_development_candidate_accounting(prepared.plan.candidate, state)
    carried = {
        e.request_id
        for e in development_uncertain_reservations(policy=prepared.plan.policy, snapshot=state)
    }
    request_ids = {
        development_ledger_request_id(s.estimate.request_id) for s in prepared.plan.shards
    }
    if (
        state.over_cap
        or state.has_reservation_overrun
        or state.active_reserved_usd != 0
        or any(
            e.request_id in request_ids
            or (e.status is CostEntryStatus.UNCERTAIN_ACCOUNTED and e.request_id not in carried)
            for e in state.entries
        )
        or prepared.plan.estimated_total_cost_usd > state.remaining_usd
    ):
        raise DevelopmentCorpusJudgmentError(
            "manifest judgment preflight refuses cumulative accounting"
        )
    if not output_dir.is_absolute() or ".." in output_dir.parts:
        raise DevelopmentCorpusJudgmentError(
            "manifest judgment output must be absolute and normalized"
        )
    custody = prepare_owned_empty_directory(
        output_dir, label="manifest judgment output", precreated=output_custody
    )
    material = DevelopmentCorpusMaterial(
        manifest=prepared.plan.candidate.plan.manifest,
        sources=tuple(
            DevelopmentCorpusText(filename=name, content=content.decode("utf-8"))
            for name, content in prepared.source_files
        ),
    )
    bindings = [
        _write(output_dir, "plan.json", prepared.plan),
        _write(output_dir, "sources.json", material),
    ]

    def require_outputs() -> None:
        if upstream is not None:
            require_development_corpus_upstream(upstream, prepared=prepared, ledger=ledger)
        require_same_unlinked_directory_objects(custody, label="manifest judgment output")
        for binding in bindings:
            revalidate_evidence_file_binding(
                evidence_root=output_dir,
                binding=binding,
                max_bytes=MAX_DEVELOPMENT_CORPUS_JUDGMENT_ARTIFACT_BYTES,
            )

    start = time.monotonic()
    deadline = start + prepared.plan.maximum_run_seconds
    if parent_deadline is not None:
        deadline = min(deadline, parent_deadline)
    observations: list[DevelopmentCorpusJudgmentShardObservation] = []
    reason: _StopReason | None = None
    interruption: BaseException | None = None
    generations = {
        *excluded_generation_ids,
        *(
            (
                s.generation_id
                for s in upstream.prior_review.observations
                if s.generation_id is not None
            )
            if upstream is not None and upstream.prior_review is not None
            else ()
        ),
        *(
            s.generation_id
            for s in prepared.plan.candidate.observations
            if s.generation_id is not None
        ),
    }
    try:
        async with asyncio.timeout(max(0.0, deadline - time.monotonic())):
            for shard in prepared.shards:
                require_outputs()
                if time.monotonic() >= deadline:
                    raise TimeoutError("manifest judgment deadline exceeded before dispatch")
                observation = await review_development_corpus_judgment_shard(
                    prepared=shard,
                    ledger=ledger,
                    operator_secrets=operator_secrets,
                    allow_code_egress=allow_code_egress,
                    mock_transport=mock_transport,
                )
                if observation.status == "OBSERVED" and observation.generation_id in generations:
                    routing = observation.routing_evidence
                    if routing is not None:
                        routing = DevelopmentRoutingEvidence.model_validate(
                            {
                                **routing.model_dump(),
                                "failure_codes": (DevelopmentRoutingFailure.GENERATION_REUSE,),
                            }
                        )
                    observation = DevelopmentCorpusJudgmentShardObservation.model_validate(
                        {
                            **observation.model_dump(),
                            "status": "INCOMPLETE",
                            "response": None,
                            "diagnostics": (DevelopmentReviewDiagnostic.IDENTITY_MISMATCH,),
                            "routing_evidence": routing,
                        }
                    )
                if observation.generation_id is not None:
                    generations.add(observation.generation_id)
                observations.append(observation)
                require_outputs()
                bindings.append(_write(output_dir, shard.shard_id + ".json", observation))
                if time.monotonic() >= deadline:
                    raise TimeoutError("manifest judgment deadline exceeded after observation")
                if observation.status != "OBSERVED":
                    reason = "JUDGMENT_INCOMPLETE"
                    break
    except (asyncio.CancelledError, KeyboardInterrupt, SystemExit) as exc:
        interruption = exc
        reason = "INTERRUPTED"
    except Exception:
        reason = "LOCAL_FAILURE"
    try:
        result = _report(
            prepared, ledger, observations, transport, reason, time.monotonic() - start
        )
        require_outputs()
        bindings.append(_write(output_dir, "result.json", result))
        require_outputs()
    except Exception:
        if interruption is not None:
            raise interruption from None
        raise DevelopmentCorpusJudgmentError(
            "manifest judgment output/accounting could not be finalized"
        ) from None
    if interruption is not None:
        raise interruption
    return result
