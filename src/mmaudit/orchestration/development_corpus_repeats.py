"""Owned predeclared candidate repeats; missing trials never become a successful-only series."""

from __future__ import annotations

import asyncio
import hashlib
import stat
import time
from pathlib import Path
from typing import Any, Literal

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
from mmaudit.benchmark.development_corpus_stability import (
    MAX_DEVELOPMENT_STABILITY_BYTES,
    measure_development_corpus_stability,
)
from mmaudit.models.development_audit import development_ledger_request_id
from mmaudit.models.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_RESULT_BYTES,
    DevelopmentCorpusAccountingEntry,
    DevelopmentCorpusMaterial,
    DevelopmentCorpusObservation,
    DevelopmentCorpusText,
)
from mmaudit.models.development_corpus_repeats import (
    MAX_DEVELOPMENT_CORPUS_REPEATS_BYTES,
    MAX_DEVELOPMENT_CORPUS_REPEATS_PLAN_BYTES,
    DevelopmentCorpusRepeatsObservation,
    DevelopmentCorpusRepeatsPlan,
    DevelopmentCorpusRepeatsStop,
    DevelopmentCorpusRepeatTrial,
    PreparedDevelopmentCorpusRepeats,
    prepare_development_corpus_repeats,
    read_development_corpus_repeats_plan,
    repeat_projection,
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
from mmaudit.orchestration.development_corpus import (
    _rebuild as rebuild_corpus,
)
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release_io import (
    read_composed_file_evidence,
    read_json_evidence,
    write_composed_json_evidence,
)
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.directory_custody import (
    DirectoryCustodyObservation,
    prepare_owned_empty_directory,
    require_same_unlinked_directory_objects,
)
from mmaudit.repository.file_custody import (
    RegularFileCustodyObservation,
    observe_regular_file_custody,
    require_regular_file_custody_unchanged,
)


class DevelopmentCorpusRepeatsError(ValueError):
    """Controlled refusal; no provider prose, source excerpts, credentials or private paths."""


def _rebuild(prepared: PreparedDevelopmentCorpusRepeats) -> PreparedDevelopmentCorpusRepeats:
    if (
        type(prepared) is not PreparedDevelopmentCorpusRepeats
        or type(prepared.plan) is not DevelopmentCorpusRepeatsPlan
        or type(prepared.trials) is not tuple
        or not 2 <= len(prepared.trials) <= 8
    ):
        raise DevelopmentCorpusRepeatsError("candidate repeats require exact prepared trials")
    plan = read_development_corpus_repeats_plan(prepared.plan.model_dump_json().encode())
    trials = tuple(rebuild_corpus(t) for t in prepared.trials)
    first = trials[0].shards[0]
    rebuilt = prepare_development_corpus_repeats(
        policy=plan.policy,
        endpoint_snapshot=first.discovery or first.endpoint_snapshot,
        manifest=plan.trials[0].manifest,
        source_files=first.source_files,
        run_id=plan.run_id,
        trial_count=plan.trial_count,
        truth_content=plan.benchmark.truth_file_content.encode(),
        expected_truth_sha256=plan.benchmark.truth_file_sha256,
        maximum_completion_tokens=first.estimate.maximum_completion_tokens,
        maximum_trial_seconds=plan.trials[0].maximum_run_seconds,
        maximum_run_seconds=plan.maximum_run_seconds,
    )
    if rebuilt != prepared:
        raise DevelopmentCorpusRepeatsError("candidate repeat source, labels or requests changed")
    return rebuilt


def _write(root: Path, name: str, model: BaseModel, maximum: int) -> ManifestFileBinding:
    expected = model.model_dump(mode="json")

    def validate(raw: bytes) -> None:
        if type(model).model_validate_json(raw, strict=True).model_dump(mode="json") != expected:
            raise DevelopmentCorpusRepeatsError("candidate repeat output differs from its result")

    return write_composed_json_evidence(
        evidence_root=root,
        relative_path=name,
        value=expected,
        max_bytes=maximum,
        validate_content=validate,
    )


def _custody(root: Path, binding: ManifestFileBinding) -> RegularFileCustodyObservation:
    retained = observe_regular_file_custody(
        root=root,
        relative_path=binding.path,
        label="candidate repeat file",
        expected_binding=binding,
        max_bytes=binding.size,
        allow_directory_entry_metadata_change=True,
        allow_composed_evidence=True,
    )
    if stat.S_IMODE(retained.identity[2]) != 0o600:
        raise DevelopmentCorpusRepeatsError("candidate repeat file must remain private")
    return retained


def _preflight(
    prepared: PreparedDevelopmentCorpusRepeats,
    ledger: AtomicCostLedger,
    next_index: int,
    observations: list[DevelopmentCorpusObservation | None],
) -> None:
    """Recheck the whole remaining estimate; this is not an atomic portfolio or hard-price proof."""

    state = ledger.snapshot()
    carried = {
        e.request_id
        for e in development_uncertain_reservations(policy=prepared.plan.policy, snapshot=state)
    }
    requests = {
        development_ledger_request_id(s.estimate.request_id)
        for p in prepared.plan.trials[next_index:]
        for s in p.shards
    }
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
        or _money_sum(p.estimated_total_cost_usd for p in prepared.plan.trials[next_index:])
        > state.remaining_usd
    ):
        raise DevelopmentCorpusRepeatsError(
            "candidate repeats refuse shared accounting or headroom"
        )
    for observation in observations:
        if observation is not None:
            validate_development_candidate_accounting(observation, state)


def _label_binding(
    plan: DevelopmentCorpusRepeatsPlan, index: int
) -> DevelopmentCorpusBenchmarkBinding:
    return bind_development_corpus_benchmark(
        plan=plan.trials[index],
        truth_content=plan.benchmark.truth_file_content.encode(),
        expected_truth_sha256=plan.benchmark.truth_file_sha256,
    )


def _bind_trial(
    root: Path,
    index: int,
    observation: DevelopmentCorpusObservation,
    material: DevelopmentCorpusMaterial,
    labels: DevelopmentCorpusBenchmarkBinding,
    *,
    recovered: bool = False,
) -> list[ManifestFileBinding]:
    stage = f"trial-{index + 1:02d}"
    expected: dict[str, BaseModel] = {
        "plan.json": observation.plan,
        "sources.json": material,
        "benchmark-plan.json": labels,
        "result.json": observation,
        **{s.shard_id + ".json": s for s in observation.observations},
    }
    score_path = root / stage / "score.json"
    control_path = root / stage / "control-measurement.json"
    if not recovered or score_path.exists() or score_path.is_symlink():
        expected["score.json"] = score_development_corpus(binding=labels, observation=observation)
    if not recovered or control_path.exists() or control_path.is_symlink():
        expected["control-measurement.json"] = measure_development_corpus_controls(
            score=score_development_corpus(binding=labels, observation=observation)
        )
    bindings = []
    for name, model in expected.items():
        raw = stable_json(model.model_dump(mode="json")).encode()
        bound = ManifestFileBinding(
            path=stage + "/" + name, size=len(raw), sha256=hashlib.sha256(raw).hexdigest()
        )
        maximum = (
            MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES
            if name == "control-measurement.json"
            else MAX_DEVELOPMENT_CORPUS_SCORE_BYTES
            if name == "score.json"
            else MAX_DEVELOPMENT_CORPUS_RESULT_BYTES
        )
        bindings.append(
            read_composed_file_evidence(
                evidence_root=root,
                relative_path=bound.path,
                expected_binding=bound,
                max_bytes=maximum,
            ).binding
        )
    return bindings


def _report(
    prepared: PreparedDevelopmentCorpusRepeats,
    ledger: AtomicCostLedger,
    observations: list[DevelopmentCorpusObservation | None],
    started_count: int,
    transport: Literal["MOCK_HTTP", "HTTP_OBSERVATION"],
    reason: DevelopmentCorpusRepeatsStop | None,
    elapsed: float,
) -> DevelopmentCorpusRepeatsObservation:
    snapshot = ledger.snapshot()
    if snapshot.cap_usd != prepared.plan.policy.total_budget_usd:
        raise DevelopmentCorpusRepeatsError("candidate repeat ledger target changed")
    entries = {e.request_id: e for e in snapshot.entries}
    slots = []
    for index, (plan, observation) in enumerate(
        zip(prepared.plan.trials, observations, strict=True)
    ):
        accounts = tuple(
            DevelopmentCorpusAccountingEntry(
                shard_id=s.shard_id,
                ledger_request_id=e.request_id,
                reservation_id=e.reservation_id,
                status=e.status,
                reserved_usd=e.reserved_usd,
                actual_cost_usd=e.actual_cost_usd,
                accounted_cost_usd=e.accounted_cost_usd,
            )
            for s in plan.shards
            if (e := entries.get(development_ledger_request_id(s.estimate.request_id))) is not None
        )
        slots.append(
            DevelopmentCorpusRepeatTrial(
                trial_index=index,
                status=("COMPLETE" if observation.status == "OBSERVED_ALL_SHARDS" else "INCOMPLETE")
                if observation is not None
                else "MISSING_RESULT"
                if index < started_count
                else "NOT_STARTED",
                observation=observation,
                accounting=accounts,
            )
        )
    trials = tuple(slots)
    if reason is None and any(t.status != "COMPLETE" for t in trials):
        reason = "TRIAL_INCOMPLETE"
    values: dict[str, Any] = dict(
        plan=prepared.plan,
        transport=transport,
        trials=trials,
        stop_reason=reason,
        elapsed_seconds=elapsed,
        **repeat_projection(prepared.plan, trials, reason),
    )
    provisional = DevelopmentCorpusRepeatsObservation.model_construct(
        **values, observation_sha256="0" * 64
    )
    values["observation_sha256"] = canonical_sha256(
        provisional.model_dump(mode="json", exclude={"observation_sha256"})
    )
    return DevelopmentCorpusRepeatsObservation.model_validate(values)


async def run_development_corpus_repeats(
    *,
    prepared: PreparedDevelopmentCorpusRepeats,
    ledger: AtomicCostLedger,
    operator_secrets: OperatorSecrets,
    output_dir: Path,
    allow_code_egress: bool = False,
    mock_transport: httpx.MockTransport | None = None,
) -> DevelopmentCorpusRepeatsObservation:
    """Execute each declared trial at most once under one active-execution deadline and ledger.

    Frozen input bytes precede the first dispatch. Finalization retains all planned slots and costs;
    missing trial results withhold full-series measurement. Cleanup and bounded artifact computation
    can outlast the active-execution deadline. Estimated headroom is not a provider-enforced ceiling.
    """

    if allow_code_egress is not True:
        raise DevelopmentCorpusRepeatsError(
            "candidate repeats require explicit source egress consent"
        )
    if (
        type(ledger) is not AtomicCostLedger
        or type(operator_secrets) is not OperatorSecrets
        or not operator_secrets.openrouter_api_key_present
        or (mock_transport is not None and type(mock_transport) is not httpx.MockTransport)
    ):
        raise DevelopmentCorpusRepeatsError("candidate repeats require exact control handles")
    prepared = _rebuild(prepared)
    material = DevelopmentCorpusMaterial(
        manifest=prepared.plan.trials[0].manifest,
        sources=tuple(
            DevelopmentCorpusText(filename=n, content=b.decode())
            for n, b in prepared.trials[0].shards[0].source_files
        ),
    )
    if any(
        operator_secrets.openrouter_api_key in m.model_dump_json()
        for m in (prepared.plan, material)
    ):
        raise DevelopmentCorpusRepeatsError(
            "development credential overlaps retained repeat inputs"
        )
    observations: list[DevelopmentCorpusObservation | None] = [None] * prepared.plan.trial_count
    _preflight(prepared, ledger, 0, observations)
    custody = prepare_owned_empty_directory(output_dir, label="candidate repeat output")
    bindings = [
        _write(output_dir, "plan.json", prepared.plan, MAX_DEVELOPMENT_CORPUS_REPEATS_PLAN_BYTES),
        _write(output_dir, "sources.json", material, MAX_DEVELOPMENT_CORPUS_RESULT_BYTES),
        _write(
            output_dir,
            "benchmark-plan.json",
            prepared.plan.benchmark,
            MAX_DEVELOPMENT_CORPUS_RESULT_BYTES,
        ),
    ]
    owned_files = [_custody(output_dir, binding) for binding in bindings]
    upstream = DevelopmentCorpusUpstream(custody, tuple(bindings), tuple(owned_files))
    children: dict[int, DirectoryCustodyObservation] = {}

    def require_outputs() -> None:
        for directory in (custody, *children.values()):
            require_same_unlinked_directory_objects(directory, label="candidate repeat output")
        for retained in owned_files:
            require_regular_file_custody_unchanged(
                retained,
                label="candidate repeat file",
                max_bytes=retained.binding.size,
                allow_directory_entry_metadata_change=True,
                allow_composed_evidence=True,
            )

    def retain(new_bindings: list[ManifestFileBinding]) -> None:
        require_outputs()
        observations = [_custody(output_dir, binding) for binding in new_bindings]
        bindings.extend(new_bindings)
        owned_files.extend(observations)
        require_outputs()

    started = time.monotonic()
    deadline = started + prepared.plan.maximum_run_seconds
    started_count = 0
    pending: int | None = None
    reason: DevelopmentCorpusRepeatsStop | None = None
    interruption: BaseException | None = None
    transport: Literal["MOCK_HTTP", "HTTP_OBSERVATION"] = (
        "MOCK_HTTP" if mock_transport is not None else "HTTP_OBSERVATION"
    )
    try:
        async with asyncio.timeout(max(0.0, deadline - time.monotonic())):
            for index, candidate in enumerate(prepared.trials):
                require_outputs()
                if time.monotonic() >= deadline:
                    raise TimeoutError("candidate repeat deadline exhausted")
                try:
                    _preflight(prepared, ledger, index, observations)
                except ValueError:
                    reason = "BUDGET_STOP"
                    break
                stage = f"trial-{index + 1:02d}"
                child = prepare_owned_empty_directory(
                    output_dir / stage, label="candidate repeat child"
                )
                children[index] = child
                require_outputs()
                pending = index
                started_count = index + 1
                observed = await run_development_corpus(
                    prepared=candidate,
                    ledger=ledger,
                    operator_secrets=operator_secrets,
                    output_dir=output_dir / stage,
                    allow_code_egress=allow_code_egress,
                    mock_transport=mock_transport,
                    benchmark_binding=_label_binding(prepared.plan, index),
                    upstream=upstream,
                    output_custody=child,
                    parent_deadline=deadline,
                )
                require_outputs()
                if (
                    type(observed) is not DevelopmentCorpusObservation
                    or observed.plan != candidate.plan
                    or observed.transport != transport
                ):
                    raise DevelopmentCorpusRepeatsError("repeat child differs from its frozen slot")
                retain(
                    _bind_trial(
                        output_dir, index, observed, material, _label_binding(prepared.plan, index)
                    )
                )
                observations[index] = observed
                pending = None
                generations = [
                    s.generation_id
                    for o in observations
                    if o is not None
                    for s in o.observations
                    if s.generation_id
                ]
                if len(generations) != len(set(generations)):
                    reason = "IDENTITY_REUSE"
                    break
                require_outputs()
                if time.monotonic() >= deadline:
                    raise TimeoutError("candidate repeat deadline exhausted after observation")
    except (asyncio.CancelledError, KeyboardInterrupt, SystemExit) as exc:
        interruption = exc
        reason = "INTERRUPTED"
    except Exception:
        reason = "LOCAL_FAILURE"
    try:
        require_outputs()
        if pending is not None:
            path = output_dir / f"trial-{pending + 1:02d}" / "result.json"
            if path.exists() or path.is_symlink():
                raw = read_json_evidence(
                    evidence_root=output_dir,
                    relative_path=f"trial-{pending + 1:02d}/result.json",
                    max_bytes=MAX_DEVELOPMENT_CORPUS_RESULT_BYTES,
                )
                restored = DevelopmentCorpusObservation.model_validate_json(
                    raw.content, strict=True
                )
                if (
                    restored.plan != prepared.plan.trials[pending]
                    or restored.transport != transport
                ):
                    raise DevelopmentCorpusRepeatsError(
                        "repeat durable child changes its planned slot"
                    )
                retain(
                    _bind_trial(
                        output_dir,
                        pending,
                        restored,
                        material,
                        _label_binding(prepared.plan, pending),
                        recovered=True,
                    )
                )
                observations[pending] = restored
        result = _report(
            prepared,
            ledger,
            observations,
            started_count,
            transport,
            reason,
            time.monotonic() - started,
        )
        require_outputs()
        retain([_write(output_dir, "result.json", result, MAX_DEVELOPMENT_CORPUS_REPEATS_BYTES)])
        require_outputs()
        if result.measurement_scope == "ALL_PREDECLARED_TRIAL_RESULTS_RETAINED":
            measured = tuple(
                measure_development_corpus_controls(
                    score=score_development_corpus(
                        binding=_label_binding(prepared.plan, index), observation=observation
                    )
                )
                for index, observation in enumerate(observations)
                if observation is not None
            )
            stability = measure_development_corpus_stability(measurements=measured)
            require_outputs()
            retain(
                [_write(output_dir, "stability.json", stability, MAX_DEVELOPMENT_STABILITY_BYTES)]
            )
            require_outputs()
    except BaseException as exc:
        if interruption is not None:
            raise interruption from None
        if not isinstance(exc, Exception):
            raise
        raise DevelopmentCorpusRepeatsError(
            "candidate repeat output/accounting could not be finalized"
        ) from None
    if interruption is not None:
        raise interruption
    return result
