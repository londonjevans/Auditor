"""Owned full-manifest candidate and dual-review execution; original scope and liabilities persist."""

from __future__ import annotations

import asyncio
import hashlib
import time
from decimal import Decimal
from pathlib import Path
from typing import Literal

import httpx
from pydantic import BaseModel

from mmaudit.benchmark.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_SCORE_BYTES,
    DevelopmentCorpusBenchmarkBinding,
    bind_development_corpus_benchmark,
    score_development_corpus,
)
from mmaudit.benchmark.development_corpus_control_measurement import (
    MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES,
    measure_development_corpus_controls,
)
from mmaudit.models.development_audit import development_ledger_request_id
from mmaudit.models.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_RESULT_BYTES,
    DevelopmentCorpusAccountingEntry,
    DevelopmentCorpusMaterial,
    DevelopmentCorpusObservation,
    DevelopmentCorpusPlan,
    DevelopmentCorpusText,
    PreparedDevelopmentCorpus,
    PreparedDevelopmentCorpusShard,
)
from mmaudit.models.development_corpus_ensemble import (
    MAX_DEVELOPMENT_CORPUS_ENSEMBLE_BYTES,
    DevelopmentCorpusEnsembleAccountingEntry,
    DevelopmentCorpusEnsembleObservation,
    DevelopmentCorpusEnsemblePlan,
    PreparedDevelopmentCorpusEnsemble,
    development_corpus_ensemble_claims,
    manifest_review_has_all_available_opinions,
    prepare_development_corpus_ensemble,
)
from mmaudit.models.development_corpus_judgment import (
    MAX_DEVELOPMENT_CORPUS_JUDGMENT_ARTIFACT_BYTES,
    DevelopmentCorpusJudgmentObservation,
    DevelopmentCorpusJudgmentPlan,
    prepare_development_corpus_judgment,
)
from mmaudit.models.development_ensemble import (
    DEVELOPMENT_ENSEMBLE_STAGES,
    DevelopmentEnsembleStageId,
)
from mmaudit.models.development_judgment import (
    _money_sum,
    validate_development_candidate_accounting,
)
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.development_budget import development_uncertain_reservations
from mmaudit.orchestration.development_corpus import (
    DevelopmentCorpusUpstream,
    run_development_corpus,
)
from mmaudit.orchestration.development_corpus_judgment import (
    DevelopmentCorpusJudgmentUpstream,
    run_development_corpus_judgment,
)
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release_io import (
    read_composed_file_evidence,
    read_json_evidence,
    revalidate_composed_evidence_file_binding,
    write_composed_json_evidence,
)
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.directory_custody import (
    DirectoryCustodyObservation,
    prepare_owned_empty_directory,
    require_same_unlinked_directory_objects,
)

type _StopReason = Literal[
    "CANDIDATE_INCOMPLETE", "REVIEW_INCOMPLETE", "LOCAL_FAILURE", "INTERRUPTED"
]
type _Transport = Literal["MOCK_HTTP", "HTTP_OBSERVATION"]
type _ChildPlan = DevelopmentCorpusPlan | DevelopmentCorpusJudgmentPlan
type _ChildObservation = DevelopmentCorpusObservation | DevelopmentCorpusJudgmentObservation


class DevelopmentCorpusEnsembleError(ValueError):
    """Controlled local refusal; no source, provider prose, credential or private path detail."""


def _rebuild(prepared: PreparedDevelopmentCorpusEnsemble) -> PreparedDevelopmentCorpusEnsemble:
    if (
        type(prepared) is not PreparedDevelopmentCorpusEnsemble
        or type(prepared.plan) is not DevelopmentCorpusEnsemblePlan
        or type(prepared.candidate) is not PreparedDevelopmentCorpus
        or type(prepared.candidate.shards) is not tuple
        or not 1 <= len(prepared.candidate.shards) <= 64
        or any(type(s) is not PreparedDevelopmentCorpusShard for s in prepared.candidate.shards)
    ):
        raise DevelopmentCorpusEnsembleError("manifest ensemble requires exact prepared stages")
    plan = DevelopmentCorpusEnsemblePlan.model_validate_json(
        prepared.plan.model_dump_json(), strict=True
    )
    first = prepared.candidate.shards[0]
    rebuilt = prepare_development_corpus_ensemble(
        policy=plan.policy,
        candidate_metadata=first.discovery or first.endpoint_snapshot,
        reviewer_metadata=prepared.reviewer_metadata,
        manifest=plan.candidate.manifest,
        source_files=first.source_files,
        run_id=plan.run_id,
        candidate_maximum_completion_tokens=first.estimate.maximum_completion_tokens,
        reviewer_maximum_completion_tokens=(
            plan.reviewers[0].maximum_completion_tokens,
            plan.reviewers[1].maximum_completion_tokens,
        ),
        maximum_run_seconds=plan.maximum_run_seconds,
    )
    if rebuilt != prepared:
        raise DevelopmentCorpusEnsembleError("manifest ensemble source, selection or bytes changed")
    return rebuilt


def _write(
    root: Path,
    filename: str,
    model: BaseModel,
    *,
    max_bytes: int = MAX_DEVELOPMENT_CORPUS_ENSEMBLE_BYTES,
) -> ManifestFileBinding:
    """Explicit composed-record bound; existing child writer ceilings are unchanged."""

    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_DEVELOPMENT_CORPUS_ENSEMBLE_BYTES:
        raise DevelopmentCorpusEnsembleError("manifest ensemble output bound is invalid")
    expected = model.model_dump(mode="json")

    def validate(content: bytes) -> None:
        if (
            type(model).model_validate_json(content, strict=True).model_dump(mode="json")
            != expected
        ):
            raise DevelopmentCorpusEnsembleError(
                "manifest ensemble output differs from observation"
            )

    return write_composed_json_evidence(
        evidence_root=root,
        relative_path=filename,
        value=expected,
        max_bytes=max_bytes,
        validate_content=validate,
    )


def _report(
    prepared: PreparedDevelopmentCorpusEnsemble,
    ledger: AtomicCostLedger,
    candidate: DevelopmentCorpusObservation | None,
    plans: list[DevelopmentCorpusJudgmentPlan],
    judgments: list[DevelopmentCorpusJudgmentObservation],
    transport: _Transport,
    reason: _StopReason | None,
    elapsed: float,
) -> DevelopmentCorpusEnsembleObservation:
    snapshot = ledger.snapshot()
    if snapshot.cap_usd != prepared.plan.policy.total_budget_usd:
        raise DevelopmentCorpusEnsembleError("manifest ensemble ledger target changed")
    entries = {e.request_id: e for e in snapshot.entries}
    stages: list[tuple[DevelopmentEnsembleStageId, _ChildPlan]] = [
        ("candidate", prepared.plan.candidate),
        *((prepared.plan.reviewers[i].stage_id, p) for i, p in enumerate(plans)),
    ]
    accounting = tuple(
        DevelopmentCorpusEnsembleAccountingEntry(
            stage_id=stage,
            entry=DevelopmentCorpusAccountingEntry(
                shard_id=shard.shard_id,
                ledger_request_id=entry.request_id,
                reservation_id=entry.reservation_id,
                status=entry.status,
                reserved_usd=entry.reserved_usd,
                actual_cost_usd=entry.actual_cost_usd,
                accounted_cost_usd=entry.accounted_cost_usd,
            ),
        )
        for stage, plan in stages
        for shard in plan.shards
        if (entry := entries.get(development_ledger_request_id(shard.estimate.request_id)))
        is not None
    )
    claims = development_corpus_ensemble_claims(candidate, tuple(judgments))
    completed = (
        candidate is not None and candidate.status == "OBSERVED_ALL_SHARDS",
        *(i < len(judgments) and judgments[i].status == "OBSERVED_ALL_JUDGMENTS" for i in range(2)),
    )
    gaps = tuple(
        s for s, done in zip(DEVELOPMENT_ENSEMBLE_STAGES, completed, strict=True) if not done
    )
    if reason is None:
        reason = (
            "CANDIDATE_INCOMPLETE"
            if not completed[0]
            else "REVIEW_INCOMPLETE"
            if gaps and claims
            else None
        )
    return DevelopmentCorpusEnsembleObservation(
        plan=prepared.plan,
        transport=transport,
        status="INCOMPLETE" if reason else "OBSERVED_ALL_STAGES" if claims else "NO_CANDIDATES",
        stop_reason=reason,
        candidate=candidate,
        judgment_plans=tuple(plans),
        judgments=tuple(judgments),
        accounting=accounting,
        claims=claims,
        unobserved_candidate_shard_ids=tuple(s.shard_id for s in prepared.plan.candidate.shards)
        if candidate is None
        else candidate.unobserved_shard_ids,
        unobserved_stage_ids=gaps,
        completed_stage_count=sum(completed),
        completed_judgment_count=sum(op is not None for row in claims for op in row.opinions),
        available_claim_reviews_complete=bool(claims)
        and all(None not in r.opinions for r in claims),
        total_accounted_cost_usd=_money_sum(r.entry.accounted_cost_usd for r in accounting),
        reported_actual_cost_usd=_money_sum(
            r.entry.actual_cost_usd or Decimal(0) for r in accounting
        ),
        uncertain_accounted_cost_usd=_money_sum(
            r.entry.accounted_cost_usd
            for r in accounting
            if r.entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        ),
        active_reserved_usd=_money_sum(
            r.entry.reserved_usd for r in accounting if r.entry.status is CostEntryStatus.RESERVED
        ),
        elapsed_seconds=elapsed,
        observed_stage_elapsed_seconds=(candidate.elapsed_seconds if candidate is not None else 0)
        + sum(j.elapsed_seconds for j in judgments),
    )


def _bind_child(
    root: Path,
    stage: DevelopmentEnsembleStageId,
    observation: _ChildObservation,
    material: DevelopmentCorpusMaterial,
    benchmark_binding: DevelopmentCorpusBenchmarkBinding | None,
    *,
    recovered: bool = False,
) -> list[ManifestFileBinding]:
    maximum = (
        MAX_DEVELOPMENT_CORPUS_RESULT_BYTES
        if stage == "candidate"
        else MAX_DEVELOPMENT_CORPUS_JUDGMENT_ARTIFACT_BYTES
    )
    expected: dict[str, BaseModel] = {
        "plan.json": observation.plan,
        "sources.json": material,
        "result.json": observation,
        **{s.shard_id + ".json": s for s in observation.observations},
    }
    if stage == "candidate" and benchmark_binding is not None:
        if type(observation) is not DevelopmentCorpusObservation:
            raise DevelopmentCorpusEnsembleError("manifest candidate result type changed")
        expected["benchmark-plan.json"] = benchmark_binding
        if not recovered or (root / stage / "score.json").exists():
            score = score_development_corpus(binding=benchmark_binding, observation=observation)
            expected["score.json"] = score
            if not recovered or (root / stage / "control-measurement.json").exists():
                expected["control-measurement.json"] = measure_development_corpus_controls(
                    score=score
                )
    bindings = []
    for name, model in expected.items():
        expected_value = model.model_dump(mode="json")
        if name == "control-measurement.json":
            content = stable_json(expected_value).encode("utf-8")
            bound = ManifestFileBinding(
                path=stage + "/" + name,
                sha256=hashlib.sha256(content).hexdigest(),
                size=len(content),
            )
            measured = read_composed_file_evidence(
                evidence_root=root,
                relative_path=bound.path,
                expected_binding=bound,
                max_bytes=MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES,
            )
            bindings.append(measured.binding)
            continue
        actual = read_json_evidence(
            evidence_root=root,
            relative_path=stage + "/" + name,
            max_bytes=MAX_DEVELOPMENT_CORPUS_SCORE_BYTES if name == "score.json" else maximum,
        )
        if actual.value != expected_value or actual.content != stable_json(expected_value).encode(
            "utf-8"
        ):
            raise DevelopmentCorpusEnsembleError("manifest child output differs from its result")
        bindings.append(actual.binding)
    return bindings


def _recover_child(
    root: Path, stage: DevelopmentEnsembleStageId, plan: _ChildPlan, transport: _Transport
) -> _ChildObservation | None:
    """Read only a terminated child's durable result beneath its original directory custody."""

    if not (root / stage / "result.json").exists():
        return None
    original = read_json_evidence(
        evidence_root=root,
        relative_path=stage + "/result.json",
        max_bytes=MAX_DEVELOPMENT_CORPUS_RESULT_BYTES
        if stage == "candidate"
        else MAX_DEVELOPMENT_CORPUS_JUDGMENT_ARTIFACT_BYTES,
    )
    model = (
        DevelopmentCorpusObservation
        if stage == "candidate"
        else DevelopmentCorpusJudgmentObservation
    )
    recovered = model.model_validate_json(original.content, strict=True)
    if recovered.plan != plan or recovered.transport != transport:
        raise DevelopmentCorpusEnsembleError(
            "manifest durable child differs from its planned stage"
        )
    return recovered


async def run_development_corpus_ensemble(
    *,
    prepared: PreparedDevelopmentCorpusEnsemble,
    ledger: AtomicCostLedger,
    operator_secrets: OperatorSecrets,
    output_dir: Path,
    allow_code_egress: bool = False,
    mock_transport: httpx.MockTransport | None = None,
    benchmark_binding: DevelopmentCorpusBenchmarkBinding | None = None,
) -> DevelopmentCorpusEnsembleObservation:
    """Execute all selected stages once; opinions cannot complete missing scope or erase costs.

    A single outer deadline bounds active child execution; bounded cleanup/finalization remains.
    Preflight headroom is an estimate, not a portfolio reservation or provider-enforced ceiling.
    Cancellation retains verified durable child evidence before propagating, never redispatching.
    """

    if allow_code_egress is not True:
        raise DevelopmentCorpusEnsembleError("manifest ensemble requires source egress consent")
    if (
        type(ledger) is not AtomicCostLedger
        or type(operator_secrets) is not OperatorSecrets
        or not operator_secrets.openrouter_api_key_present
        or (mock_transport is not None and type(mock_transport) is not httpx.MockTransport)
    ):
        raise DevelopmentCorpusEnsembleError("manifest ensemble requires exact control handles")
    prepared = _rebuild(prepared)
    if benchmark_binding is not None:
        if type(benchmark_binding) is not DevelopmentCorpusBenchmarkBinding:
            raise DevelopmentCorpusEnsembleError("manifest ensemble requires exact pinned labels")
        rebuilt = bind_development_corpus_benchmark(
            plan=prepared.plan.candidate,
            truth_content=benchmark_binding.truth_file_content.encode("utf-8"),
            expected_truth_sha256=benchmark_binding.truth_file_sha256,
        )
        if rebuilt != benchmark_binding:
            raise DevelopmentCorpusEnsembleError(
                "manifest ensemble candidate label binding differs"
            )
        benchmark_binding = rebuilt
    material = DevelopmentCorpusMaterial(
        manifest=prepared.plan.candidate.manifest,
        sources=tuple(
            DevelopmentCorpusText(filename=n, content=b.decode("utf-8"))
            for n, b in prepared.candidate.shards[0].source_files
        ),
    )
    if any(
        operator_secrets.openrouter_api_key in item.model_dump_json()
        for item in (prepared.plan, material, benchmark_binding)
        if item is not None
    ):
        raise DevelopmentCorpusEnsembleError("development credential overlaps retained inputs")
    snapshot = ledger.snapshot()
    carried = {
        e.request_id
        for e in development_uncertain_reservations(policy=prepared.plan.policy, snapshot=snapshot)
    }
    requests = {
        development_ledger_request_id(s.estimate.request_id) for s in prepared.plan.candidate.shards
    }
    if (
        snapshot.cap_usd != prepared.plan.policy.total_budget_usd
        or snapshot.over_cap
        or snapshot.has_reservation_overrun
        or snapshot.active_reserved_usd != 0
        or any(
            e.request_id in requests
            or (e.status is CostEntryStatus.UNCERTAIN_ACCOUNTED and e.request_id not in carried)
            for e in snapshot.entries
        )
        or prepared.plan.estimated_headroom_usd > snapshot.remaining_usd
    ):
        raise DevelopmentCorpusEnsembleError(
            "manifest ensemble refuses cumulative costs or headroom"
        )
    custody = prepare_owned_empty_directory(output_dir, label="manifest ensemble output")
    bindings = [
        _write(
            output_dir, "plan.json", prepared.plan, max_bytes=MAX_DEVELOPMENT_CORPUS_RESULT_BYTES
        ),
        _write(output_dir, "sources.json", material, max_bytes=MAX_DEVELOPMENT_CORPUS_RESULT_BYTES),
    ]
    if benchmark_binding is not None:
        bindings.append(
            _write(
                output_dir,
                "benchmark-plan.json",
                benchmark_binding,
                max_bytes=MAX_DEVELOPMENT_CORPUS_RESULT_BYTES,
            )
        )
    candidate_upstream = DevelopmentCorpusUpstream(custody, tuple(bindings))
    children: dict[DevelopmentEnsembleStageId, DirectoryCustodyObservation] = {}

    def require_outputs() -> None:
        for directory in (custody, *children.values()):
            require_same_unlinked_directory_objects(directory, label="manifest ensemble output")
        for binding in bindings:
            revalidate_composed_evidence_file_binding(evidence_root=output_dir, binding=binding)

    def create_child(stage: DevelopmentEnsembleStageId) -> DirectoryCustodyObservation:
        require_outputs()
        child = prepare_owned_empty_directory(output_dir / stage, label="manifest ensemble child")
        children[stage] = child
        require_outputs()
        return child

    started = time.monotonic()
    deadline = started + prepared.plan.maximum_run_seconds

    def remaining() -> float:
        require_outputs()
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("manifest ensemble whole-run deadline exhausted")
        return min(value, prepared.plan.maximum_run_seconds)

    candidate: DevelopmentCorpusObservation | None = None
    plans: list[DevelopmentCorpusJudgmentPlan] = []
    judgments: list[DevelopmentCorpusJudgmentObservation] = []
    pending: tuple[DevelopmentEnsembleStageId, _ChildPlan] | None = None
    reason: _StopReason | None = None
    interruption: BaseException | None = None
    transport: _Transport = "MOCK_HTTP" if mock_transport is not None else "HTTP_OBSERVATION"
    try:
        async with asyncio.timeout(remaining()):
            pending = ("candidate", prepared.plan.candidate)
            child = create_child("candidate")
            candidate = await run_development_corpus(
                prepared=prepared.candidate,
                ledger=ledger,
                operator_secrets=operator_secrets,
                output_dir=output_dir / "candidate",
                allow_code_egress=allow_code_egress,
                mock_transport=mock_transport,
                benchmark_binding=benchmark_binding,
                upstream=candidate_upstream,
                output_custody=child,
                parent_deadline=deadline,
            )
            require_outputs()
            bindings.extend(
                _bind_child(output_dir, "candidate", candidate, material, benchmark_binding)
            )
            pending = None
            validate_development_candidate_accounting(candidate, ledger.snapshot())
            blocked = any(
                e.status in {CostEntryStatus.RESERVED, CostEntryStatus.RESERVATION_OVERRUN}
                or (
                    e.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
                    and prepared.plan.policy.uncertain_cost_policy == "STOP"
                )
                for e in candidate.accounting
            )
            if candidate.candidate_claim_count and not blocked:
                for role, metadata in zip(
                    prepared.plan.reviewers, prepared.reviewer_metadata, strict=True
                ):
                    review = prepare_development_corpus_judgment(
                        candidate=candidate,
                        policy=prepared.plan.policy,
                        endpoint_snapshot=metadata,
                        source_files=prepared.candidate.shards[0].source_files,
                        run_id=role.run_id,
                        maximum_completion_tokens=role.maximum_completion_tokens,
                        maximum_run_seconds=remaining(),
                    )
                    plans.append(review.plan)
                    bindings.append(
                        _write(
                            output_dir,
                            role.stage_id + "-plan.json",
                            review.plan,
                            max_bytes=MAX_DEVELOPMENT_CORPUS_JUDGMENT_ARTIFACT_BYTES,
                        )
                    )
                    upstream = DevelopmentCorpusJudgmentUpstream(
                        evidence_root=output_dir,
                        directories=(
                            custody,
                            children["candidate"],
                            *((children["review-01"],) if judgments else ()),
                        ),
                        files=tuple(bindings),
                        prior_review=judgments[0] if judgments else None,
                    )
                    pending = (role.stage_id, review.plan)
                    child = create_child(role.stage_id)
                    judgment = await run_development_corpus_judgment(
                        prepared=review,
                        ledger=ledger,
                        operator_secrets=operator_secrets,
                        output_dir=output_dir / role.stage_id,
                        allow_code_egress=allow_code_egress,
                        mock_transport=mock_transport,
                        upstream=upstream,
                        output_custody=child,
                        parent_deadline=deadline,
                    )
                    require_outputs()
                    bindings.extend(
                        _bind_child(output_dir, role.stage_id, judgment, material, None)
                    )
                    judgments.append(judgment)
                    pending = None
                    if not manifest_review_has_all_available_opinions(judgment):
                        reason = "REVIEW_INCOMPLETE"
                        break
            remaining()
    except (asyncio.CancelledError, KeyboardInterrupt, SystemExit) as exc:
        interruption = exc
        reason = "INTERRUPTED"
    except Exception:
        reason = "LOCAL_FAILURE"
    try:
        require_outputs()
        if pending is not None and pending[0] in children:
            restored = _recover_child(output_dir, pending[0], pending[1], transport)
            if restored is not None:
                bindings.extend(
                    _bind_child(
                        output_dir,
                        pending[0],
                        restored,
                        material,
                        benchmark_binding if pending[0] == "candidate" else None,
                        recovered=True,
                    )
                )
                if isinstance(restored, DevelopmentCorpusObservation):
                    candidate = restored
                else:
                    judgments.append(restored)
        result = _report(
            prepared,
            ledger,
            candidate,
            plans,
            judgments,
            transport,
            reason,
            time.monotonic() - started,
        )
        require_outputs()
        bindings.append(_write(output_dir, "result.json", result))
        require_outputs()
        if benchmark_binding is not None:
            from mmaudit.benchmark.development_corpus_ensemble import (
                score_development_corpus_ensemble,
            )

            score = score_development_corpus_ensemble(binding=benchmark_binding, observation=result)
            bindings.append(_write(output_dir, "score.json", score))
            require_outputs()
    except Exception:
        if interruption is not None:
            raise interruption from None
        raise DevelopmentCorpusEnsembleError(
            "manifest ensemble output/accounting could not be finalized"
        ) from None
    if interruption is not None:
        raise interruption
    return result
