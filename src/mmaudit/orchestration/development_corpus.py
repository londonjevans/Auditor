"""Execute an exact local source-manifest audit through the shared non-qualifying transport."""

from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Literal

import httpx

from mmaudit.benchmark.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_SCORE_BYTES,
    DevelopmentCorpusBenchmarkBinding,
    DevelopmentCorpusBenchmarkScore,
    bind_development_corpus_benchmark,
    score_development_corpus,
)
from mmaudit.models.development_audit import development_ledger_request_id
from mmaudit.models.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_RESULT_BYTES,
    DevelopmentCorpusAccountingEntry,
    DevelopmentCorpusMaterial,
    DevelopmentCorpusObservation,
    DevelopmentCorpusPlan,
    DevelopmentCorpusShardObservation,
    DevelopmentCorpusText,
    PreparedDevelopmentCorpus,
    PreparedDevelopmentCorpusShard,
    prepare_development_corpus,
)
from mmaudit.models.development_judgment import _money_sum
from mmaudit.models.development_review import DevelopmentReviewDiagnostic
from mmaudit.models.development_routing import DevelopmentRoutingEvidence, DevelopmentRoutingFailure
from mmaudit.models.development_transport import review_development_corpus_shard
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.development_audit import _write
from mmaudit.orchestration.development_budget import development_uncertain_reservations
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release_io import revalidate_evidence_file_binding, write_json_evidence
from mmaudit.repository.directory_custody import (
    DirectoryCustodyObservation,
    prepare_owned_empty_directory,
    require_same_unlinked_directory_objects,
)

type _StopReason = Literal["SHARD_INCOMPLETE", "LOCAL_FAILURE", "INTERRUPTED"]


class DevelopmentCorpusError(ValueError):
    """Controlled refusal; never disclose source excerpts, secret values or private file paths."""


@dataclass(frozen=True)
class DevelopmentCorpusUpstream:
    """Exact parent inputs; custody is local evidence, not a callback or provider authority."""

    directory: DirectoryCustodyObservation
    files: tuple[ManifestFileBinding, ...]


def require_development_corpus_upstream(upstream: DevelopmentCorpusUpstream) -> None:
    """Recheck original parent plan/material/optional labels before any next candidate request."""

    if (
        type(upstream) is not DevelopmentCorpusUpstream
        or type(upstream.directory) is not DirectoryCustodyObservation
        or type(upstream.files) is not tuple
        or not 2 <= len(upstream.files) <= 3
        or any(type(f) is not ManifestFileBinding for f in upstream.files)
        or tuple(f.path for f in upstream.files)
        not in {("plan.json", "sources.json"), ("plan.json", "sources.json", "benchmark-plan.json")}
        or any(not 0 < f.size <= MAX_DEVELOPMENT_CORPUS_RESULT_BYTES for f in upstream.files)
        or not upstream.directory.path.is_absolute()
        or ".." in upstream.directory.path.parts
        or not upstream.directory.component_identities
        or upstream.directory.component_identities[-1][0] != upstream.directory.path
    ):
        raise DevelopmentCorpusError("manifest candidate upstream custody is invalid")
    require_same_unlinked_directory_objects(upstream.directory, label="manifest candidate upstream")
    for binding in upstream.files:
        revalidate_evidence_file_binding(
            evidence_root=upstream.directory.path, binding=binding, max_bytes=binding.size
        )


def _rebuild(prepared: PreparedDevelopmentCorpus) -> PreparedDevelopmentCorpus:
    if (
        type(prepared) is not PreparedDevelopmentCorpus
        or type(prepared.plan) is not DevelopmentCorpusPlan
        or type(prepared.shards) is not tuple
        or not 1 <= len(prepared.shards) <= 64
        or any(type(s) is not PreparedDevelopmentCorpusShard for s in prepared.shards)
    ):
        raise DevelopmentCorpusError("development corpus requires exact prepared plan/shard types")
    plan = DevelopmentCorpusPlan.model_validate_json(prepared.plan.model_dump_json(), strict=True)
    first = prepared.shards[0]
    rebuilt = prepare_development_corpus(
        policy=plan.policy,
        endpoint_snapshot=first.discovery or first.endpoint_snapshot,
        manifest=plan.manifest,
        source_files=first.source_files,
        run_id=plan.run_id,
        maximum_completion_tokens=first.estimate.maximum_completion_tokens,
        maximum_run_seconds=plan.maximum_run_seconds,
    )
    if rebuilt != prepared:
        raise DevelopmentCorpusError(
            "development corpus source, metadata, selection or requests changed"
        )
    return rebuilt


def _report(
    prepared: PreparedDevelopmentCorpus,
    ledger: AtomicCostLedger,
    observations: list[DevelopmentCorpusShardObservation],
    transport: Literal["MOCK_HTTP", "HTTP_OBSERVATION"],
    reason: _StopReason | None,
    elapsed: float,
) -> DevelopmentCorpusObservation:
    snapshot = ledger.snapshot()
    entries = {entry.request_id: entry for entry in snapshot.entries}
    accounting = []
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
    complete = {s.shard_id for s in observations if s.status == "OBSERVED"}
    gaps = tuple(s.shard_id for s in prepared.plan.shards if s.shard_id not in complete)
    return DevelopmentCorpusObservation(
        plan=prepared.plan,
        transport=transport,
        status="OBSERVED_ALL_SHARDS" if not gaps and reason is None else "INCOMPLETE",
        stop_reason=reason,
        observations=tuple(observations),
        accounting=tuple(accounting),
        unobserved_shard_ids=gaps,
        completed_shard_count=len(complete),
        selected_primary_line_count=sum(s.line_count for s in prepared.plan.manifest.sources),
        primary_lines_with_observed_responses=sum(
            s.line_count
            for s, p in zip(prepared.plan.manifest.sources, prepared.plan.shards, strict=True)
            if p.shard_id in complete
        ),
        candidate_claim_count=sum(
            len(s.response.findings) for s in observations if s.response is not None
        ),
        total_accounted_cost_usd=_money_sum(s.accounted_cost_usd for s in accounting),
        reported_actual_cost_usd=_money_sum(s.actual_cost_usd or Decimal(0) for s in accounting),
        uncertain_accounted_cost_usd=_money_sum(
            s.accounted_cost_usd
            for s in accounting
            if s.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        ),
        active_reserved_usd=_money_sum(
            s.reserved_usd for s in accounting if s.status is CostEntryStatus.RESERVED
        ),
        elapsed_seconds=elapsed,
    )


def _write_score(output_dir: Path, score: DevelopmentCorpusBenchmarkScore) -> ManifestFileBinding:
    """Bound the composed score without widening the existing candidate writer's contract."""

    expected = score.model_dump(mode="json")

    def validate(content: bytes) -> None:
        restored = DevelopmentCorpusBenchmarkScore.model_validate_json(content, strict=True)
        if restored.model_dump(mode="json") != expected:
            raise DevelopmentCorpusError("manifest score differs from its exact observation")

    return write_json_evidence(
        evidence_root=output_dir,
        relative_path="score.json",
        value=expected,
        max_bytes=MAX_DEVELOPMENT_CORPUS_SCORE_BYTES,
        validate_content=validate,
        require_private_parent=True,
    )


async def run_development_corpus(
    *,
    prepared: PreparedDevelopmentCorpus,
    ledger: AtomicCostLedger,
    operator_secrets: OperatorSecrets,
    output_dir: Path,
    allow_code_egress: bool = False,
    mock_transport: httpx.MockTransport | None = None,
    benchmark_binding: DevelopmentCorpusBenchmarkBinding | None = None,
    upstream: DevelopmentCorpusUpstream | None = None,
    output_custody: DirectoryCustodyObservation | None = None,
    parent_deadline: float | None = None,
) -> DevelopmentCorpusObservation:
    """Run each selected file once, with exact source retention and no silent retry or scope loss.

    Scope is the explicit manifest, not an independently complete or compiled protocol.
    Costs remain estimated; failures/cancellation retain liabilities and never gain audit credit.
    """

    if allow_code_egress is not True:
        raise DevelopmentCorpusError("development corpus requires explicit source egress consent")
    if parent_deadline is not None and (
        type(parent_deadline) is not float
        or not math.isfinite(parent_deadline)
        or parent_deadline <= 0
    ):
        raise DevelopmentCorpusError("development corpus parent deadline is invalid")
    if (
        type(ledger) is not AtomicCostLedger
        or type(operator_secrets) is not OperatorSecrets
        or not operator_secrets.openrouter_api_key_present
        or (mock_transport is not None and type(mock_transport) is not httpx.MockTransport)
    ):
        raise DevelopmentCorpusError(
            "development corpus requires exact ledger and credential handles"
        )
    prepared = _rebuild(prepared)
    if benchmark_binding is not None:
        if type(benchmark_binding) is not DevelopmentCorpusBenchmarkBinding:
            raise DevelopmentCorpusError("manifest scoring requires an exact label binding")
        rebuilt_binding = bind_development_corpus_benchmark(
            plan=prepared.plan,
            truth_content=benchmark_binding.truth_file_content.encode("utf-8"),
            expected_truth_sha256=benchmark_binding.truth_file_sha256,
        )
        if rebuilt_binding != benchmark_binding:
            raise DevelopmentCorpusError("manifest label binding differs from its candidate")
        benchmark_binding = rebuilt_binding
    material = DevelopmentCorpusMaterial(
        manifest=prepared.plan.manifest,
        sources=tuple(
            DevelopmentCorpusText(filename=name, content=raw.decode("utf-8"))
            for name, raw in prepared.shards[0].source_files
        ),
    )
    if (
        operator_secrets.openrouter_api_key in prepared.plan.model_dump_json()
        or operator_secrets.openrouter_api_key in material.model_dump_json()
        or (
            benchmark_binding is not None
            and operator_secrets.openrouter_api_key in benchmark_binding.model_dump_json()
        )
    ):
        raise DevelopmentCorpusError("development credential overlaps the retained corpus inputs")
    if upstream is not None:
        require_development_corpus_upstream(upstream)
    state = ledger.snapshot()
    carried = {
        a.request_id
        for a in development_uncertain_reservations(policy=prepared.plan.policy, snapshot=state)
    }
    requests = {development_ledger_request_id(s.estimate.request_id) for s in prepared.plan.shards}
    if (
        state.cap_usd != prepared.plan.policy.total_budget_usd
        or state.over_cap
        or state.has_reservation_overrun
        or state.active_reserved_usd != 0
        or any(
            e.request_id in requests
            or (e.status is CostEntryStatus.UNCERTAIN_ACCOUNTED and e.request_id not in carried)
            for e in state.entries
        )
        or prepared.plan.estimated_total_cost_usd > state.remaining_usd
    ):
        raise DevelopmentCorpusError("development corpus preflight refuses cumulative accounting")
    if not output_dir.is_absolute() or ".." in output_dir.parts:
        raise DevelopmentCorpusError("development corpus output must be absolute and normalized")
    custody = prepare_owned_empty_directory(
        output_dir, label="development corpus output", precreated=output_custody
    )
    bindings = [
        _write(output_dir, "plan.json", prepared.plan),
        _write(output_dir, "sources.json", material),
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

    def require_outputs() -> None:
        if upstream is not None:
            require_development_corpus_upstream(upstream)
        require_same_unlinked_directory_objects(custody, label="development corpus output")
        for binding in bindings:
            revalidate_evidence_file_binding(
                evidence_root=output_dir,
                binding=binding,
                max_bytes=MAX_DEVELOPMENT_CORPUS_SCORE_BYTES
                if binding.path == "score.json"
                else MAX_DEVELOPMENT_CORPUS_RESULT_BYTES,
            )

    started = time.monotonic()
    deadline = started + prepared.plan.maximum_run_seconds
    if parent_deadline is not None:
        deadline = min(deadline, parent_deadline)
    observations: list[DevelopmentCorpusShardObservation] = []
    reason: _StopReason | None = None
    interruption: BaseException | None = None
    try:
        async with asyncio.timeout(max(0.0, deadline - time.monotonic())):
            for shard in prepared.shards:
                require_outputs()
                if time.monotonic() >= deadline:
                    raise TimeoutError("development corpus deadline exhausted before dispatch")
                observation = await review_development_corpus_shard(
                    prepared=shard,
                    ledger=ledger,
                    operator_secrets=operator_secrets,
                    allow_code_egress=allow_code_egress,
                    mock_transport=mock_transport,
                )
                if observation.status == "OBSERVED" and any(
                    s.generation_id == observation.generation_id for s in observations
                ):
                    routing = observation.routing_evidence
                    if routing is not None:
                        routing = DevelopmentRoutingEvidence.model_validate(
                            {
                                **routing.model_dump(),
                                "failure_codes": (DevelopmentRoutingFailure.GENERATION_REUSE,),
                            }
                        )
                    observation = DevelopmentCorpusShardObservation.model_validate(
                        {
                            **observation.model_dump(),
                            "status": "INCOMPLETE",
                            "response": None,
                            "diagnostics": (DevelopmentReviewDiagnostic.IDENTITY_MISMATCH,),
                            "routing_evidence": routing,
                        }
                    )
                observations.append(observation)
                require_outputs()
                bindings.append(_write(output_dir, shard.shard_id + ".json", observation))
                if time.monotonic() >= deadline:
                    raise TimeoutError("development corpus deadline exhausted after observation")
                if observation.status != "OBSERVED":
                    reason = "SHARD_INCOMPLETE"
                    break
    except (asyncio.CancelledError, KeyboardInterrupt, SystemExit) as exc:
        interruption = exc
        reason = "INTERRUPTED"
    except Exception:
        reason = "LOCAL_FAILURE"
    try:
        result = _report(
            prepared,
            ledger,
            observations,
            "MOCK_HTTP" if mock_transport is not None else "HTTP_OBSERVATION",
            reason,
            time.monotonic() - started,
        )
        require_outputs()
        bindings.append(
            _write(output_dir, "result.json", result, max_bytes=MAX_DEVELOPMENT_CORPUS_RESULT_BYTES)
        )
        require_outputs()
        if benchmark_binding is not None:
            score = score_development_corpus(binding=benchmark_binding, observation=result)
            bindings.append(_write_score(output_dir, score))
            require_outputs()
    except Exception:
        if interruption is not None:
            raise interruption from None
        raise DevelopmentCorpusError(
            "development corpus output/accounting could not be finalized"
        ) from None
    if interruption is not None:
        raise interruption
    return result
