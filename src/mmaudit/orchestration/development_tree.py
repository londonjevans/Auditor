"""Execute an admitted local tree plan in stable stages, reopening completed work without replay."""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field, replace
from decimal import Decimal
from pathlib import Path

import httpx
from pydantic import BaseModel

from mmaudit.models.development_audit import development_ledger_request_id
from mmaudit.models.development_corpus import (
    DevelopmentCorpusMaterial,
    DevelopmentCorpusObservation,
    DevelopmentCorpusPlan,
)
from mmaudit.models.development_corpus_coverage import (
    MAX_DEVELOPMENT_COVERAGE_BYTES,
    MAX_DEVELOPMENT_COVERAGE_RUNS,
    DevelopmentCorpusCoverage,
    compute_development_corpus_coverage,
)
from mmaudit.models.development_corpus_ensemble import (
    PreparedDevelopmentCorpusEnsemble,
    manifest_review_has_all_available_opinions,
    prepare_development_corpus_ensemble,
)
from mmaudit.models.development_corpus_judgment import (
    DevelopmentCorpusJudgmentObservation,
    DevelopmentCorpusJudgmentPlan,
    PreparedDevelopmentCorpusJudgment,
    prepare_development_corpus_judgment,
)
from mmaudit.models.development_corpus_partition import DevelopmentCorpusPartition
from mmaudit.models.development_corpus_replay import with_development_corpus_replay
from mmaudit.models.development_ensemble import (
    DEVELOPMENT_ENSEMBLE_STAGES,
    DevelopmentEnsembleStageId,
)
from mmaudit.models.development_judgment import _money_sum, validate_development_accounting_entries
from mmaudit.models.development_tree_execution import (
    DevelopmentTreeExecutionProgress,
    DevelopmentTreePrimaryProgress,
    DevelopmentTreeStageEnd,
    DevelopmentTreeStageStart,
)
from mmaudit.models.development_tree_plan import MAX_DEVELOPMENT_TREE_PLAN_BYTES
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.development_budget import development_uncertain_reservations
from mmaudit.orchestration.development_corpus import (
    DevelopmentCorpusUpstream,
    run_development_corpus,
)
from mmaudit.orchestration.development_corpus_ensemble import _bind_child, _recover_child
from mmaudit.orchestration.development_corpus_judgment import (
    DevelopmentCorpusJudgmentUpstream,
    run_development_corpus_judgment,
)
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release_io import read_json_evidence, write_json_evidence
from mmaudit.repository.development_corpus import LoadedDevelopmentCorpus
from mmaudit.repository.development_corpus_partition import (
    load_development_corpus_partition,
    materialize_development_corpus_partition,
)
from mmaudit.repository.development_tree_plan import (
    LoadedDevelopmentTreePlan,
    bind_development_tree_plan_replay,
)
from mmaudit.repository.directory_custody import (
    DirectoryCustodyObservation,
    observe_unlinked_directory,
    prepare_owned_empty_directory,
    require_same_unlinked_directory_objects,
)
from mmaudit.repository.file_custody import (
    RegularFileCustodyObservation,
    observe_regular_file_custody,
    require_regular_file_custody_batch_unchanged,
)

type _Child = DevelopmentCorpusObservation | DevelopmentCorpusJudgmentObservation


@dataclass
class _Case:
    index: int
    bundle: LoadedDevelopmentCorpus
    prepared: PreparedDevelopmentCorpusEnsemble
    directory: DirectoryCustodyObservation
    bindings: list[ManifestFileBinding]
    files: list[RegularFileCustodyObservation] = field(default_factory=list)
    children: dict[DevelopmentEnsembleStageId, DirectoryCustodyObservation] = field(
        default_factory=dict
    )
    records: list[_Child] = field(default_factory=list)
    ends: list[DevelopmentTreeStageEnd] = field(default_factory=list)


@dataclass(frozen=True)
class _UnstartedCase:
    """An original preflight slot, not an omitted primary or a fabricated child observation."""

    index: int
    records: tuple[_Child, ...] = ()
    ends: tuple[DevelopmentTreeStageEnd, ...] = ()


type _TreeCase = _Case | _UnstartedCase

_MAX_CLOSED_TREE_STAGES = 256 * len(DEVELOPMENT_ENSEMBLE_STAGES)
_MAX_CHECKPOINT_ROOT_ENTRIES = 2 * (_MAX_CLOSED_TREE_STAGES + 1) + 2


class _CoverageReplay:
    """Keep one pure coverage result for exact inputs inside a single invocation.

    Reviewer-only progress does not change candidate coverage. Every lookup still binds all
    input bytes and the private result bytes. This never substitutes for live file, source,
    policy, accounting or checkpoint custody; nothing is persisted or shared across invocations.
    """

    def __init__(self) -> None:
        self._key: tuple[int, int, tuple[bytes, ...]] | None = None
        self._coverage: DevelopmentCorpusCoverage | None = None
        self._content: bytes | None = None

    @staticmethod
    def _inputs_key(
        *,
        reference: DevelopmentCorpusMaterial,
        records: tuple[DevelopmentCorpusObservation, ...],
        partitions: tuple[DevelopmentCorpusPartition, ...] | None,
    ) -> tuple[int, int, tuple[bytes, ...]]:
        if (
            type(reference) is not DevelopmentCorpusMaterial
            or type(records) is not tuple
            or len(records) > MAX_DEVELOPMENT_COVERAGE_RUNS
            or any(type(record) is not DevelopmentCorpusObservation for record in records)
            or (
                partitions is not None
                and (
                    type(partitions) is not tuple
                    or not 0 < len(partitions) <= MAX_DEVELOPMENT_COVERAGE_RUNS
                    or any(type(p) is not DevelopmentCorpusPartition for p in partitions)
                )
            )
        ):
            raise ValueError("automatic tree coverage replay requires exact bounded inputs")
        contents = []
        size = 0
        for model in (reference, *records, *(partitions or ())):
            content = model.model_dump_json().encode()
            size += len(content)
            if size > MAX_DEVELOPMENT_COVERAGE_BYTES:
                raise ValueError("automatic tree coverage replay exceeds its input byte bound")
            contents.append(content)
        return (len(records), -1 if partitions is None else len(partitions), tuple(contents))

    def compute(
        self,
        *,
        reference: DevelopmentCorpusMaterial,
        records: tuple[DevelopmentCorpusObservation, ...],
        partitions: tuple[DevelopmentCorpusPartition, ...] | None,
    ) -> DevelopmentCorpusCoverage:
        key = self._inputs_key(reference=reference, records=records, partitions=partitions)
        if key == self._key:
            if self._coverage is None or self._coverage.model_dump_json().encode() != self._content:
                raise ValueError("automatic tree cached coverage changed during replay")
            if self._content is None or len(self._content) > MAX_DEVELOPMENT_COVERAGE_BYTES:
                raise ValueError("automatic tree coverage replay exceeds its result byte bound")
            return self._coverage
        # Drop the previous population before constructing another full source-bearing result.
        self._key = self._coverage = self._content = None
        coverage = compute_development_corpus_coverage(
            reference=reference, records=records, partitions=partitions
        )
        content = coverage.model_dump_json().encode()
        if len(content) > MAX_DEVELOPMENT_COVERAGE_BYTES:
            raise ValueError("automatic tree coverage replay exceeds its result byte bound")
        if key != self._inputs_key(reference=reference, records=records, partitions=partitions):
            raise ValueError("automatic tree coverage inputs changed during computation")
        self._key, self._coverage, self._content = key, coverage, content
        return coverage


def _closed_prefix(cases: list[_TreeCase], count: int) -> list[_TreeCase]:
    """Project an original closed-stage prefix without dropping later primary liabilities."""

    if (
        type(count) is not int
        or not 0 <= count <= _MAX_CLOSED_TREE_STAGES
        or len(cases) > 256
        or count > sum(len(case.ends) for case in cases)
        or any(len(case.records) < len(case.ends) for case in cases)
    ):
        raise ValueError("automatic tree checkpoint prefix is unavailable or invalid")
    remaining = count
    result: list[_TreeCase] = []
    for case in cases:
        selected = min(remaining, len(case.ends))
        result.append(
            replace(case, records=case.records[:selected], ends=case.ends[:selected])
            if selected and isinstance(case, _Case)
            else _UnstartedCase(case.index)
        )
        remaining -= selected
    return result


def _checkpoint_names(root: Path) -> tuple[str, ...]:
    """Bound the owned root namespace; filenames cannot introduce future or foreign work."""

    names = []
    with os.scandir(root) as entries:
        for index, entry in enumerate(entries):
            if index >= _MAX_CHECKPOINT_ROOT_ENTRIES:
                raise ValueError("automatic tree checkpoint namespace exceeds its bound")
            if entry.name in {"plan.json", "cases"}:
                continue
            match = re.fullmatch(r"(?:progress|coverage)-([0-9]{4})\.json", entry.name)
            if match is None or int(match[1]) > _MAX_CLOSED_TREE_STAGES:
                raise ValueError("automatic tree checkpoint namespace contains a foreign entry")
            names.append(entry.name)
    return tuple(sorted(names))


def _replay_checkpoints(
    loaded: LoadedDevelopmentTreePlan,
    cases: list[_TreeCase],
    root: Path,
    *,
    coverage_replay: _CoverageReplay | None = None,
) -> list[RegularFileCustodyObservation]:
    """Recompute retained checkpoints from original children, never from claimed summaries.

    Sparse legacy checkpoints remain valid only at matching original closed-stage prefixes.
    This is local retained-evidence consistency and live custody, not authenticated history.
    """

    names = _checkpoint_names(root)
    files = []
    for count in sorted({int(name.split("-")[1].split(".")[0]) for name in names}):
        coverage, progress = _progress_values(
            loaded, _closed_prefix(cases, count), coverage_replay=coverage_replay
        )
        for name, expected in (
            (f"coverage-{count:04d}.json", coverage),
            (f"progress-{count:04d}.json", progress),
        ):
            if name not in names:
                continue
            read = read_json_evidence(
                evidence_root=root, relative_path=name, max_bytes=MAX_DEVELOPMENT_TREE_PLAN_BYTES
            )
            observed = type(expected).model_validate_json(read.content, strict=True)
            if observed != expected or read.value != expected.model_dump(mode="json"):
                raise ValueError(
                    "automatic tree checkpoint differs from its original closed prefix"
                )
            files.append(_observe_file(root, read.binding))
    return files


def _observe_file(root: Path, binding: ManifestFileBinding) -> RegularFileCustodyObservation:
    return observe_regular_file_custody(
        root=root,
        relative_path=binding.path,
        expected_binding=binding,
        label="automatic tree execution file",
        max_bytes=MAX_DEVELOPMENT_TREE_PLAN_BYTES,
        allow_directory_entry_metadata_change=True,
    )


def _same_files(files: list[RegularFileCustodyObservation]) -> None:
    require_regular_file_custody_batch_unchanged(
        files,
        label="automatic tree execution file",
        max_bytes=MAX_DEVELOPMENT_TREE_PLAN_BYTES,
    )


def _model_file(root: Path, name: str, model: BaseModel, *, create: bool) -> ManifestFileBinding:
    if create:
        return write_json_evidence(
            evidence_root=root,
            relative_path=name,
            value=model,
            max_bytes=MAX_DEVELOPMENT_TREE_PLAN_BYTES,
            require_private_parent=True,
        )
    read = read_json_evidence(
        evidence_root=root, relative_path=name, max_bytes=MAX_DEVELOPMENT_TREE_PLAN_BYTES
    )
    if read.value != model.model_dump(mode="json"):
        raise ValueError("automatic tree retained selection differs")
    return read.binding


def _pending(case: _TreeCase) -> tuple[DevelopmentEnsembleStageId, ...]:
    if not case.records:
        return DEVELOPMENT_ENSEMBLE_STAGES
    candidate = case.records[0]
    assert isinstance(candidate, DevelopmentCorpusObservation)
    if candidate.status != "OBSERVED_ALL_SHARDS" or not candidate.candidate_claim_count:
        return ()
    if any(
        not manifest_review_has_all_available_opinions(r)
        for r in case.records[1:]
        if isinstance(r, DevelopmentCorpusJudgmentObservation)
    ):
        return ()
    return DEVELOPMENT_ENSEMBLE_STAGES[len(case.records) :]


def _review(case: _Case, index: int) -> PreparedDevelopmentCorpusJudgment:
    candidate = case.records[0]
    assert isinstance(candidate, DevelopmentCorpusObservation)
    role = case.prepared.plan.reviewers[index - 1]
    return prepare_development_corpus_judgment(
        candidate=candidate,
        policy=case.prepared.plan.policy,
        endpoint_snapshot=case.prepared.reviewer_metadata[index - 1],
        source_files=case.bundle.material.source_files,
        run_id=role.run_id,
        maximum_completion_tokens=role.maximum_completion_tokens,
        maximum_run_seconds=case.prepared.plan.maximum_run_seconds,
        source_custody=case.bundle,
    )


def _stage_seconds(loaded: LoadedDevelopmentTreePlan, index: int) -> float:
    base, remainder = divmod(loaded.plan.policy.maximum_manifest_seconds, 3)
    return float(base + (index < remainder))


def _start(
    loaded: LoadedDevelopmentTreePlan,
    case: _Case,
    index: int,
    plan: DevelopmentCorpusPlan | DevelopmentCorpusJudgmentPlan,
) -> DevelopmentTreeStageStart:
    """Bind the exact already prepared dispatch; do not reconstruct a second reviewer request."""

    return DevelopmentTreeStageStart(
        tree_plan_sha256=loaded.plan.plan_sha256,
        primary_index=case.index,
        stage=DEVELOPMENT_ENSEMBLE_STAGES[index],
        child_plan_sha256=plan.plan_sha256,
        request_id=plan.shards[0].estimate.request_id,
        allotted_seconds=_stage_seconds(loaded, index),
    )


def _bind_record(
    case: _Case, stage: DevelopmentEnsembleStageId, record: _Child
) -> ManifestFileBinding:
    bindings = _bind_child(case.directory.path, stage, record, case.bundle.material, None)
    case.bindings.extend(bindings)
    case.files.extend(_observe_file(case.directory.path, b) for b in bindings)
    case.records.append(record)
    return next(b for b in bindings if b.path == stage + "/result.json")


def _restore_case(loaded: LoadedDevelopmentTreePlan, case: _Case, mock: bool) -> None:
    root = case.directory.path
    for index, stage in enumerate(DEVELOPMENT_ENSEMBLE_STAGES):
        started = root / (stage + "-start.json")
        ended = root / (stage + "-end.json")
        child = root / stage
        exists = started.exists() or started.is_symlink()
        if not exists:
            if ended.exists() or ended.is_symlink() or child.exists() or child.is_symlink():
                raise ValueError("automatic tree child has no original dispatch marker")
            continue
        if stage not in _pending(case) or index != len(case.records):
            raise ValueError("automatic tree stage order or failed-stage history differs")
        child_plan = case.prepared.candidate.plan if index == 0 else _review(case, index).plan
        start = _start(loaded, case, index, child_plan)
        start_binding = _model_file(root, started.name, start, create=False)
        case.files.append(_observe_file(root, start_binding))
        if not ended.exists():
            # Missing result does not prove unsent; even a durable child needs the closed interval.
            raise ValueError("automatic tree has an unclosed stage; no automatic redispatch")
        read = read_json_evidence(evidence_root=root, relative_path=ended.name, max_bytes=16384)
        end = DevelopmentTreeStageEnd.model_validate_json(read.content, strict=True)
        if end.start != start:
            raise ValueError("automatic tree stage receipt changes its dispatch identity")
        if index:
            case.bindings.append(_model_file(root, stage + "-plan.json", child_plan, create=False))
            case.files.append(_observe_file(root, case.bindings[-1]))
        case.children[stage] = observe_unlinked_directory(child, label="automatic tree child")
        record = _recover_child(
            root, stage, child_plan, "MOCK_HTTP" if mock else "HTTP_OBSERVATION"
        )
        if record is None:
            raise ValueError("automatic tree closed stage has no exact retained child")
        if end.elapsed_seconds < record.elapsed_seconds:
            raise ValueError("automatic tree stage interval is shorter than its durable child")
        if _bind_record(case, stage, record) != end.result_file:
            raise ValueError("automatic tree closed stage has no exact retained child")
        case.ends.append(end)
        case.files.append(_observe_file(root, read.binding))


def _prepare_case(
    loaded: LoadedDevelopmentTreePlan, root: Path, index: int, *, resume: bool, mock: bool
) -> _Case:
    """Materialize or reopen one original closed bundle without changing its planned request."""

    policy = loaded.plan.policy
    primary = loaded.plan.primaries[index - 1]
    assert primary.partition is not None and primary.candidate is not None
    case_root = root / "cases" / f"case-{index:04d}"
    if not resume:
        prepare_owned_empty_directory(case_root, label="automatic tree case")
    if resume:
        bundle = load_development_corpus_partition(
            reference=loaded.reference,
            partition_file=case_root / "bundle/partition.json",
            manifest_file=case_root / "bundle/manifest.json",
            corpus_root=case_root / "bundle/source",
        )
    else:
        bundle = materialize_development_corpus_partition(
            reference=loaded.reference,
            partition=primary.partition,
            output_dir=case_root / "bundle",
        )
    if bundle.partition_custody is None or bundle.partition_custody.partition != primary.partition:
        raise ValueError("automatic tree bundle differs from the planned original closure")
    prepared = prepare_development_corpus_ensemble(
        policy=policy.cost_policy,
        candidate_metadata=policy.role_metadata[0],
        reviewer_metadata=policy.role_metadata[1:],
        manifest=bundle.material.manifest,
        source_files=bundle.material.source_files,
        source_custody=bundle,
        run_id=primary.case_run_id,
        candidate_maximum_completion_tokens=policy.maximum_completion_tokens[0],
        reviewer_maximum_completion_tokens=policy.maximum_completion_tokens[1:],
        maximum_run_seconds=float(policy.maximum_manifest_seconds),
    )
    if prepared.candidate.plan != primary.candidate:
        raise ValueError("automatic tree actual candidate differs from its preflight")
    directory = (
        observe_unlinked_directory(case_root / "run", label="automatic tree case run")
        if resume
        else prepare_owned_empty_directory(case_root / "run", label="automatic tree case run")
    )
    bindings = [
        _model_file(directory.path, "plan.json", prepared.plan, create=not resume),
        _model_file(directory.path, "sources.json", bundle.material, create=not resume),
    ]
    case = _Case(index, bundle, prepared, directory, bindings)
    case.files.extend(_observe_file(directory.path, b) for b in bindings)
    if resume:
        _restore_case(loaded, case, mock)
    return case


def _prepare_cases(
    loaded: LoadedDevelopmentTreePlan, root: Path, *, resume: bool, mock: bool
) -> list[_TreeCase]:
    """Replay every existing bundle; keep all untouched future slots without materializing them."""

    cases: list[_TreeCase] = []
    cases_root = root / "cases"
    if not resume:
        prepare_owned_empty_directory(cases_root, label="automatic tree cases")
    for index in range(1, len(loaded.plan.primaries) + 1):
        case_root = cases_root / f"case-{index:04d}"
        cases.append(
            _prepare_case(loaded, root, index, resume=True, mock=mock)
            if resume and (case_root.exists() or case_root.is_symlink())
            else _UnstartedCase(index)
        )
    # The engine schedules a prefix; an earlier unfinished case cannot be bypassed on reopen.
    pending_seen = False
    for case in cases:
        if pending_seen and case.records:
            raise ValueError("automatic tree retained work skips a pending earlier primary")
        pending_seen = pending_seen or bool(_pending(case))
    return cases


def _accounting_guard(
    loaded: LoadedDevelopmentTreePlan, ledger: AtomicCostLedger, cases: list[_TreeCase]
) -> None:
    policy = loaded.plan.policy.cost_policy
    snapshot = ledger.snapshot()
    carried = {
        e.request_id for e in development_uncertain_reservations(policy=policy, snapshot=snapshot)
    }
    if (
        snapshot.cap_usd != policy.total_budget_usd
        or snapshot.over_cap
        or snapshot.has_reservation_overrun
        or snapshot.active_reserved_usd != 0
        or any(
            e.status is CostEntryStatus.UNCERTAIN_ACCOUNTED and e.request_id not in carried
            for e in snapshot.entries
        )
    ):
        raise ValueError("automatic tree refuses cumulative accounting or uncertain billing")
    used = set()
    generations = set()
    for case in cases:
        for record in case.records:
            validate_development_accounting_entries(
                record.accounting, snapshot, budget_usd=policy.total_budget_usd
            )
            for entry in record.accounting:
                if entry.ledger_request_id in used:
                    raise ValueError("automatic tree repeats a paid request identity")
                used.add(entry.ledger_request_id)
            for observed in record.observations:
                if observed.generation_id is not None:
                    if observed.generation_id in generations:
                        raise ValueError("automatic tree repeats a generation identity")
                    generations.add(observed.generation_id)
    candidate_costs = tuple(
        primary.candidate.estimated_total_cost_usd
        for primary in loaded.plan.primaries
        if primary.candidate is not None
    )
    if len(candidate_costs) != len(loaded.plan.primaries):
        raise ValueError("automatic tree accounting lacks a planned candidate envelope")
    remaining = (
        loaded.plan.estimated_headroom_usd
        if not cases
        else _money_sum(
            candidate_costs[case.index - 1]
            if stage == "candidate"
            else policy.per_attempt_budget_usd
            for case in cases
            for stage in _pending(case)
        )
    )
    pending_candidates = {
        development_ledger_request_id(p.candidate.shards[0].estimate.request_id)
        for p in loaded.plan.primaries
        if p.candidate is not None
    } - used
    if remaining > snapshot.remaining_usd or any(
        e.request_id in pending_candidates for e in snapshot.entries
    ):
        raise ValueError("automatic tree refuses remaining headroom or request-id reuse")


def _time_guard(loaded: LoadedDevelopmentTreePlan, cases: list[_TreeCase]) -> None:
    policy = loaded.plan.policy
    elapsed = sum(e.elapsed_seconds for c in cases for e in c.ends)
    remaining = sum(
        _stage_seconds(loaded, DEVELOPMENT_ENSEMBLE_STAGES.index(stage))
        for c in cases
        for stage in _pending(c)
    )
    if elapsed + remaining > policy.maximum_total_seconds:
        raise ValueError("automatic tree cumulative active-time envelope is exhausted")
    for case in cases:
        spent = sum(e.elapsed_seconds for e in case.ends)
        if (
            any(e.elapsed_seconds > e.start.allotted_seconds for e in case.ends)
            or spent > policy.maximum_manifest_seconds
        ):
            raise ValueError("automatic tree per-manifest active-time ceiling is exhausted")


def _progress_values(
    loaded: LoadedDevelopmentTreePlan,
    cases: list[_TreeCase],
    *,
    coverage_replay: _CoverageReplay | None = None,
) -> tuple[DevelopmentCorpusCoverage, DevelopmentTreeExecutionProgress]:
    records = tuple(c.records[0] for c in cases if c.records)
    assert all(isinstance(r, DevelopmentCorpusObservation) for r in records)
    candidates = tuple(r for r in records if isinstance(r, DevelopmentCorpusObservation))
    partitions = tuple(loaded.plan.primaries[c.index - 1].partition for c in cases if c.records)
    recipes = tuple(p for p in partitions if p is not None)
    compute = (
        compute_development_corpus_coverage if coverage_replay is None else coverage_replay.compute
    )
    coverage = compute(
        reference=loaded.plan.reference, records=candidates, partitions=recipes or None
    )
    rows = []
    for case in cases:
        candidate = case.records[0] if case.records else None
        assert candidate is None or isinstance(candidate, DevelopmentCorpusObservation)
        status = (
            "PENDING"
            if candidate is None
            else "CANDIDATE_INCOMPLETE"
            if candidate.status != "OBSERVED_ALL_SHARDS"
            else "NO_CANDIDATES"
            if not candidate.candidate_claim_count
            else "OBSERVED_ALL_STAGES"
            if len(case.records) == 3
            and all(
                manifest_review_has_all_available_opinions(r)
                for r in case.records[1:]
                if isinstance(r, DevelopmentCorpusJudgmentObservation)
            )
            else "REVIEW_INCOMPLETE"
        )
        rows.append(
            DevelopmentTreePrimaryProgress.model_validate(
                dict(
                    filename=loaded.plan.primaries[case.index - 1].primary_filename,
                    status=status,
                    completed_attempt_count=sum(len(record.accounting) for record in case.records),
                    elapsed_seconds=sum(e.elapsed_seconds for e in case.ends),
                )
            )
        )
    accounts = tuple(e for c in cases for r in c.records for e in r.accounting)
    progress = DevelopmentTreeExecutionProgress(
        tree_plan_sha256=loaded.plan.plan_sha256,
        status="OBSERVED_ALL_AVAILABLE_STAGES"
        if all(r.status in {"NO_CANDIDATES", "OBSERVED_ALL_STAGES"} for r in rows)
        else "INCOMPLETE",
        primary_statuses=tuple(rows),
        coverage=coverage.summary,
        completed_attempt_count=len(accounts),
        total_accounted_cost_usd=_money_sum(e.accounted_cost_usd for e in accounts),
        reported_actual_cost_usd=_money_sum(e.actual_cost_usd or Decimal(0) for e in accounts),
        uncertain_accounted_cost_usd=_money_sum(
            e.accounted_cost_usd
            for e in accounts
            if e.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        ),
        active_reserved_usd=_money_sum(
            e.reserved_usd for e in accounts if e.status is CostEntryStatus.RESERVED
        ),
        elapsed_active_seconds=sum(e.elapsed_seconds for c in cases for e in c.ends),
    )
    return coverage, progress


def _progress(
    loaded: LoadedDevelopmentTreePlan,
    cases: list[_TreeCase],
    root: Path,
    *,
    checkpoint_files: list[RegularFileCustodyObservation] | None = None,
    write_coverage: bool = True,
    coverage_replay: _CoverageReplay | None = None,
) -> DevelopmentTreeExecutionProgress:
    """Persist an exact closed-stage summary; source-bearing coverage need not be duplicated."""

    coverage, progress = _progress_values(loaded, cases, coverage_replay=coverage_replay)
    count = sum(len(c.ends) for c in cases)
    for name, model in (
        (f"coverage-{count:04d}.json", coverage),
        (f"progress-{count:04d}.json", progress),
    ):
        if not write_coverage and name.startswith("coverage-"):
            continue
        path = root / name
        binding = _model_file(root, name, model, create=not (path.exists() or path.is_symlink()))
        if checkpoint_files is not None:
            existing = [file for file in checkpoint_files if file.binding.path == name]
            if existing:
                _same_files(existing)
            else:
                checkpoint_files.append(_observe_file(root, binding))
    return progress


@with_development_corpus_replay
async def run_development_tree_plan(
    *,
    loaded: LoadedDevelopmentTreePlan,
    ledger: AtomicCostLedger,
    operator_secrets: OperatorSecrets,
    output_dir: Path,
    allow_code_egress: bool = False,
    mock_transport: httpx.MockTransport | None = None,
    resume: bool = False,
    maximum_stages_per_invocation: int = 768,
) -> DevelopmentTreeExecutionProgress:
    """Run all pending fixed-route stages by default; resume only closed, byte-bound intervals.

    The optional invocation limit provides a deliberate stage-boundary pause. A recorded failed
    attempt is retained, not retried. An unclosed stage refuses rather than guessing it was unsent.
    All actual calls still use the existing ledger, source-custody and transport consumers.
    """

    if type(loaded) is not LoadedDevelopmentTreePlan or loaded.plan.status != "READY":
        raise ValueError("automatic tree execution requires a READY original-tree plan")
    if (
        allow_code_egress is not True
        or type(ledger) is not AtomicCostLedger
        or type(operator_secrets) is not OperatorSecrets
        or not operator_secrets.openrouter_api_key_present
        or type(resume) is not bool
        or (mock_transport is not None and type(mock_transport) is not httpx.MockTransport)
    ):
        raise ValueError(
            "automatic tree execution requires exact controls and explicit source consent"
        )
    if (
        type(maximum_stages_per_invocation) is not int
        or not 1 <= maximum_stages_per_invocation <= 768
    ):
        raise ValueError("automatic tree invocation limit is invalid")
    if (
        not isinstance(output_dir, Path)
        or not output_dir.is_absolute()
        or ".." in output_dir.parts
        or any(
            output_dir.is_relative_to(p) or p.is_relative_to(output_dir)
            for p in (
                loaded.reference.corpus_root,
                loaded.directory.path,
                loaded.policy_file.root / loaded.policy_file.binding.path,
                loaded.captured.remappings_file,
            )
        )
    ):
        raise ValueError("automatic tree execution output overlaps inputs or is not absolute")
    replay_plan = bind_development_tree_plan_replay(loaded)
    if operator_secrets.openrouter_api_key in loaded.plan.model_dump_json():
        raise ValueError("automatic tree credential overlaps retained inputs")
    if not resume:
        _accounting_guard(loaded, ledger, [])
    custody = (
        observe_unlinked_directory(output_dir, label="automatic tree execution")
        if resume
        else prepare_owned_empty_directory(output_dir, label="automatic tree execution")
    )
    root_binding = _model_file(output_dir, "plan.json", loaded.plan, create=not resume)
    root_file = _observe_file(output_dir, root_binding)
    cases = _prepare_cases(loaded, output_dir, resume=resume, mock=mock_transport is not None)
    cases_custody = observe_unlinked_directory(output_dir / "cases", label="automatic tree cases")
    coverage_replay = _CoverageReplay()
    checkpoint_files = _replay_checkpoints(
        loaded, cases, output_dir, coverage_replay=coverage_replay
    )

    def require_inputs() -> None:
        replay_plan()
        require_same_unlinked_directory_objects(custody, label="automatic tree execution")
        require_same_unlinked_directory_objects(cases_custody, label="automatic tree cases")
        _same_files([root_file])
        if _checkpoint_names(output_dir) != tuple(
            sorted(file.binding.path for file in checkpoint_files)
        ):
            raise ValueError("automatic tree checkpoint namespace changed during execution")
        _same_files(checkpoint_files)
        for case in cases:
            if isinstance(case, _UnstartedCase):
                pending_root = cases_custody.path / f"case-{case.index:04d}"
                if pending_root.exists() or pending_root.is_symlink():
                    raise ValueError("automatic tree unstarted case has unexpected output")
                continue
            require_same_unlinked_directory_objects(case.directory, label="automatic tree case")
            for child in case.children.values():
                require_same_unlinked_directory_objects(child, label="automatic tree child")
            _same_files(case.files)

    def checkpoint(*, write_coverage: bool = True) -> DevelopmentTreeExecutionProgress:
        require_inputs()
        progress = _progress(
            loaded,
            cases,
            output_dir,
            checkpoint_files=checkpoint_files,
            write_coverage=write_coverage,
            coverage_replay=coverage_replay,
        )
        require_inputs()
        return progress

    require_inputs()
    _accounting_guard(loaded, ledger, cases)
    _time_guard(loaded, cases)
    checkpoint(write_coverage=False)
    dispatched = 0
    for position in range(len(cases)):
        case = cases[position]
        if isinstance(case, _UnstartedCase):
            if dispatched >= maximum_stages_per_invocation:
                require_inputs()
                return checkpoint()
            require_inputs()
            _accounting_guard(loaded, ledger, cases)
            _time_guard(loaded, cases)
            case = _prepare_case(
                loaded, output_dir, case.index, resume=False, mock=mock_transport is not None
            )
            cases[position] = case
            require_inputs()
        while _pending(case):
            if dispatched >= maximum_stages_per_invocation:
                require_inputs()
                return checkpoint()
            begin = time.monotonic()
            require_inputs()
            _accounting_guard(loaded, ledger, cases)
            _time_guard(loaded, cases)
            index = len(case.records)
            stage = DEVELOPMENT_ENSEMBLE_STAGES[index]
            review = None if index == 0 else _review(case, index)
            child_plan = case.prepared.candidate.plan if review is None else review.plan
            envelope = loaded.plan.primaries[case.index - 1].role_envelopes[index]
            request = case.prepared.candidate.shards[0] if review is None else review.shards[0]
            if (
                len(request.request_content) > envelope.serialized_request_bytes
                or envelope.estimate is None
                or request.estimate.estimated_cost_per_attempt_usd
                > envelope.estimate.estimated_cost_per_attempt_usd
            ):
                raise ValueError("automatic tree actual request exceeds its preflight envelope")
            start = _start(loaded, case, index, child_plan)
            root = case.directory.path
            if review is not None:
                binding = _model_file(root, stage + "-plan.json", review.plan, create=True)
                case.bindings.append(binding)
                case.files.append(_observe_file(root, binding))
            candidate_upstream = DevelopmentCorpusUpstream(
                case.directory, tuple(case.bindings[:2]), tuple(case.files[:2])
            )
            prior = case.records[1] if len(case.records) > 1 else None
            assert prior is None or isinstance(prior, DevelopmentCorpusJudgmentObservation)
            upstream = (
                None
                if review is None
                else DevelopmentCorpusJudgmentUpstream(
                    evidence_root=root,
                    directories=(
                        case.directory,
                        case.children["candidate"],
                        *((case.children["review-01"],) if prior is not None else ()),
                    ),
                    files=tuple(case.bindings),
                    prior_review=prior,
                )
            )
            binding = _model_file(root, stage + "-start.json", start, create=True)
            case.files.append(_observe_file(root, binding))
            child_custody = prepare_owned_empty_directory(
                root / stage, label="automatic tree child"
            )
            case.children[stage] = child_custody
            failure: BaseException | None = None
            record: _Child | None = None
            try:
                if review is None:
                    record = await run_development_corpus(
                        prepared=case.prepared.candidate,
                        ledger=ledger,
                        operator_secrets=operator_secrets,
                        output_dir=root / stage,
                        allow_code_egress=allow_code_egress,
                        mock_transport=mock_transport,
                        upstream=candidate_upstream,
                        output_custody=child_custody,
                        parent_deadline=begin + start.allotted_seconds,
                    )
                else:
                    record = await run_development_corpus_judgment(
                        prepared=review,
                        ledger=ledger,
                        operator_secrets=operator_secrets,
                        output_dir=root / stage,
                        allow_code_egress=allow_code_egress,
                        mock_transport=mock_transport,
                        upstream=upstream,
                        output_custody=child_custody,
                        parent_deadline=begin + start.allotted_seconds,
                    )
            except BaseException as exc:
                failure = exc
                record = _recover_child(
                    root,
                    stage,
                    child_plan,
                    "MOCK_HTTP" if mock_transport is not None else "HTTP_OBSERVATION",
                )
            require_inputs()
            if record is not None:
                result_binding = _bind_record(case, stage, record)
                end = DevelopmentTreeStageEnd(
                    start=start,
                    result_file=result_binding,
                    elapsed_seconds=time.monotonic() - begin,
                )
                if end.elapsed_seconds < record.elapsed_seconds:
                    raise ValueError(
                        "automatic tree stage interval is shorter than its durable child"
                    )
                binding = _model_file(root, stage + "-end.json", end, create=True)
                case.files.append(_observe_file(root, binding))
                case.ends.append(end)
                dispatched += 1
                checkpoint(write_coverage=failure is not None)
            if failure is not None:
                raise failure
            if record is None:
                raise ValueError("automatic tree stage has no durable result")
    require_inputs()
    _accounting_guard(loaded, ledger, cases)
    _time_guard(loaded, cases)
    return checkpoint()
