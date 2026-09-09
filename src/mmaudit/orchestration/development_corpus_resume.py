"""Explicit candidate continuation with original-input custody and cumulative ledger continuity."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import httpx
from pydantic import BaseModel, TypeAdapter

from mmaudit.benchmark.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_SCORE_BYTES,
    DevelopmentCorpusBenchmarkScore,
)
from mmaudit.benchmark.development_corpus_control_measurement import (
    MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES,
    measure_development_corpus_controls,
)
from mmaudit.benchmark.development_corpus_resume import (
    MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES,
    DevelopmentCorpusResumeBenchmarkScore,
    read_development_corpus_resume_score,
    score_development_corpus_resume,
)
from mmaudit.models.development_audit import development_ledger_request_id
from mmaudit.models.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_RESULT_BYTES,
    DevelopmentCorpusAccountingEntry,
    DevelopmentCorpusMaterial,
    DevelopmentCorpusObservation,
    DevelopmentCorpusShardObservation,
    PreparedDevelopmentCorpus,
    PreparedDevelopmentCorpusShard,
)
from mmaudit.models.development_corpus_resume import (
    MAX_DEVELOPMENT_CORPUS_RESUME_BYTES,
    DevelopmentCorpusResumeAttempt,
    DevelopmentCorpusResumeHistory,
    DevelopmentCorpusResumePlan,
    PreparedDevelopmentCorpusResume,
    freeze_development_corpus_resume_history,
    prepare_development_corpus_resume,
)
from mmaudit.models.development_judgment import validate_development_accounting_entries
from mmaudit.models.development_review import DevelopmentReviewDiagnostic, DevelopmentReviewMetadata
from mmaudit.models.development_routing import DevelopmentRoutingEvidence, DevelopmentRoutingFailure
from mmaudit.models.development_transport import review_development_corpus_shard
from mmaudit.models.discovery import (
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryPayload,
)
from mmaudit.models.endpoint_snapshots import OpenRouterEndpointSnapshotEvidence
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus, CostLedgerSnapshot
from mmaudit.orchestration.development_budget import development_uncertain_reservations
from mmaudit.orchestration.development_corpus_control_measurement import (
    write_development_corpus_control_measurement,
)
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release_io import (
    read_json_evidence,
    write_json_evidence,
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
    require_regular_file_custody_unchanged,
)

type _InputRole = Literal["history", "candidate", "material", "score", "metadata"]
type _StopReason = Literal["SHARD_INCOMPLETE", "LOCAL_FAILURE", "INTERRUPTED"]


class DevelopmentCorpusResumeError(ValueError):
    """Controlled refusal without credential values, source excerpts or private path details."""


@dataclass(frozen=True)
class DevelopmentCorpusResumeInputFile:
    role: _InputRole
    custody: RegularFileCustodyObservation

    @property
    def directory(self) -> DirectoryCustodyObservation:
        return self.custody.parent

    @property
    def binding(self) -> ManifestFileBinding:
        return self.custody.binding


@dataclass(frozen=True)
class DevelopmentCorpusResumeInputs:
    history: DevelopmentCorpusResumeHistory = field(repr=False)
    files: tuple[DevelopmentCorpusResumeInputFile, ...]
    metadata: DevelopmentReviewMetadata | None = field(default=None, repr=False)


def _input_limit(role: _InputRole) -> int:
    return (
        MAX_DEVELOPMENT_CORPUS_RESUME_BYTES
        if role == "history"
        else MAX_DEVELOPMENT_CORPUS_SCORE_BYTES
        if role == "score"
        else 2_000_000
        if role == "metadata"
        else MAX_DEVELOPMENT_CORPUS_RESULT_BYTES
    )


def _require_file(expected: RegularFileCustodyObservation, *, max_bytes: int) -> None:
    """Keep exact file identity while allowing owned directory-entry metadata to evolve."""

    require_same_unlinked_directory_objects(expected.parent, label="continuation file parent")
    current = observe_regular_file_custody(
        root=expected.root,
        relative_path=expected.binding.path,
        label="continuation file",
        expected_binding=expected.binding,
        max_bytes=max_bytes,
        allow_directory_entry_metadata_change=True,
    )
    if (current.root, current.binding, current.identity) != (
        expected.root,
        expected.binding,
        expected.identity,
    ):
        raise DevelopmentCorpusResumeError("continuation file object or bytes changed")
    require_same_unlinked_directory_objects(expected.parent, label="continuation file parent")


def require_development_corpus_resume_inputs(inputs: DevelopmentCorpusResumeInputs) -> None:
    """Retain every original directory ancestor and exact selected input bytes, without rebasing."""

    if (
        type(inputs) is not DevelopmentCorpusResumeInputs
        or type(inputs.history) is not DevelopmentCorpusResumeHistory
        or type(inputs.files) is not tuple
        or not 1 <= len(inputs.files) <= 4
        or any(type(f) is not DevelopmentCorpusResumeInputFile for f in inputs.files)
        or tuple(f.role for f in inputs.files)
        not in {
            ("history",),
            ("candidate", "material"),
            ("candidate", "material", "score"),
            ("history", "metadata"),
            ("candidate", "material", "metadata"),
            ("candidate", "material", "score", "metadata"),
        }
        or (any(f.role == "metadata" for f in inputs.files) != (inputs.metadata is not None))
        or (
            inputs.metadata is not None
            and type(inputs.metadata)
            not in {
                OpenRouterEndpointSnapshotEvidence,
                OpenRouterModelDiscoveryPayload,
                OpenRouterModelDiscoveryEvidence,
            }
        )
    ):
        raise DevelopmentCorpusResumeError("continuation input selection is invalid")
    paths = []
    for item in inputs.files:
        if type(item.custody) is not RegularFileCustodyObservation:
            raise DevelopmentCorpusResumeError("continuation input file custody is invalid")
        directory = item.directory
        if (
            type(directory) is not DirectoryCustodyObservation
            or type(item.binding) is not ManifestFileBinding
            or item.custody.root != directory.path
            or not directory.path.is_absolute()
            or ".." in directory.path.parts
            or tuple(p for p, _identity in directory.component_identities)
            != (*reversed(directory.path.parents), directory.path)
            or len(Path(item.binding.path).parts) != 1
            or not 0 < item.binding.size <= _input_limit(item.role)
        ):
            raise DevelopmentCorpusResumeError("continuation input custody is incomplete")
        paths.append(directory.path / item.binding.path)
        require_same_unlinked_directory_objects(directory, label="continuation input")
        _require_file(item.custody, max_bytes=_input_limit(item.role))
    if len(set(paths)) != len(paths) or any(
        a != b and (a.is_relative_to(b) or b.is_relative_to(a)) for a in paths for b in paths
    ):
        raise DevelopmentCorpusResumeError("continuation input files overlap")


def _verify_input_meaning(inputs: DevelopmentCorpusResumeInputs) -> None:
    require_development_corpus_resume_inputs(inputs)
    expected: dict[_InputRole, BaseModel | None] = {
        "history": inputs.history,
        "candidate": inputs.history.original,
        "material": inputs.history.material,
        "score": inputs.history.original_score,
        "metadata": inputs.metadata,
    }
    for item in inputs.files:
        value = expected[item.role]
        observed = read_json_evidence(
            evidence_root=item.directory.path,
            relative_path=item.binding.path,
            max_bytes=_input_limit(item.role),
        )
        if value is None or type(value).model_validate_json(observed.content, strict=True) != value:
            raise DevelopmentCorpusResumeError(
                "continuation input bytes differ from retained history"
            )
    require_development_corpus_resume_inputs(inputs)


def read_development_corpus_resume_inputs(
    *,
    history_file: Path | None = None,
    candidate_file: Path | None = None,
    material_file: Path | None = None,
    original_score_file: Path | None = None,
    metadata_file: Path | None = None,
) -> DevelopmentCorpusResumeInputs:
    """Read only explicitly selected local evidence, never discover source, credentials or a ledger."""

    selected: tuple[tuple[_InputRole, Path], ...]
    if history_file is not None:
        if any(p is not None for p in (candidate_file, material_file, original_score_file)):
            raise DevelopmentCorpusResumeError(
                "continuation history and original inputs are exclusive"
            )
        selected = (("history", history_file),)
    else:
        if candidate_file is None or material_file is None:
            raise DevelopmentCorpusResumeError("continuation needs original candidate and material")
        selected = (
            ("candidate", candidate_file),
            ("material", material_file),
            *(((("score", original_score_file),)) if original_score_file is not None else ()),
        )
    if metadata_file is not None:
        selected += (("metadata", metadata_file),)
    if any(not isinstance(p, Path) or not p.is_absolute() or ".." in p.parts for _, p in selected):
        raise DevelopmentCorpusResumeError("continuation inputs must be absolute and normalized")
    contents: dict[_InputRole, bytes] = {}
    files = []
    for role, path in selected:
        directory = observe_unlinked_directory(
            path.parent, label="continuation input", allow_entry_metadata_change=True
        )
        observed = read_json_evidence(
            evidence_root=path.parent, relative_path=path.name, max_bytes=_input_limit(role)
        )
        custody = observe_regular_file_custody(
            root=path.parent,
            relative_path=path.name,
            expected_binding=observed.binding,
            label="continuation input",
            max_bytes=_input_limit(role),
            allow_directory_entry_metadata_change=True,
        )
        require_same_unlinked_directory_objects(directory, label="continuation input")
        files.append(DevelopmentCorpusResumeInputFile(role, custody))
        contents[role] = observed.content
    if history_file is not None:
        history = DevelopmentCorpusResumeHistory.model_validate_json(
            contents["history"], strict=True
        )
    else:
        history = freeze_development_corpus_resume_history(
            original=DevelopmentCorpusObservation.model_validate_json(
                contents["candidate"], strict=True
            ),
            material=DevelopmentCorpusMaterial.model_validate_json(
                contents["material"], strict=True
            ),
            original_score=DevelopmentCorpusBenchmarkScore.model_validate_json(
                contents["score"], strict=True
            )
            if "score" in contents
            else None,
        )
    metadata = (
        TypeAdapter(DevelopmentReviewMetadata).validate_json(contents["metadata"], strict=True)
        if "metadata" in contents
        else None
    )
    result = DevelopmentCorpusResumeInputs(history, tuple(files), metadata)
    _verify_input_meaning(result)
    return result


def _rebuild(prepared: PreparedDevelopmentCorpusResume) -> PreparedDevelopmentCorpusResume:
    if (
        type(prepared) is not PreparedDevelopmentCorpusResume
        or type(prepared.plan) is not DevelopmentCorpusResumePlan
        or type(prepared.candidate) is not PreparedDevelopmentCorpus
        or type(prepared.candidate.shards) is not tuple
        or not 1 <= len(prepared.candidate.shards) <= 64
        or any(type(s) is not PreparedDevelopmentCorpusShard for s in prepared.candidate.shards)
    ):
        raise DevelopmentCorpusResumeError(
            "continuation requires exact prepared history and requests"
        )
    first = prepared.candidate.shards[0]
    rebuilt = prepare_development_corpus_resume(
        history=prepared.history,
        endpoint_snapshot=first.discovery or first.endpoint_snapshot,
        run_id=prepared.plan.candidate.run_id,
    )
    if rebuilt != prepared:
        raise DevelopmentCorpusResumeError(
            "continuation source, ancestry, selection or bytes changed"
        )
    return rebuilt


def _prior_accounting(
    history: DevelopmentCorpusResumeHistory,
) -> tuple[DevelopmentCorpusAccountingEntry, ...]:
    return (
        *history.original.accounting,
        *(a for stage in history.continuations for a in stage.accounting),
    )


def _current_accounting(
    prepared: PreparedDevelopmentCorpusResume, snapshot: CostLedgerSnapshot
) -> tuple[DevelopmentCorpusAccountingEntry, ...]:
    entries = {e.request_id: e for e in snapshot.entries}
    rows = []
    for shard in prepared.plan.candidate.shards:
        actual = entries.get(development_ledger_request_id(shard.estimate.request_id))
        if actual is None:
            continue
        if shard.shard_id not in prepared.plan.selected_shard_ids:
            raise DevelopmentCorpusResumeError("continuation has accounting for unselected work")
        rows.append(
            DevelopmentCorpusAccountingEntry(
                shard_id=shard.shard_id,
                ledger_request_id=actual.request_id,
                reservation_id=actual.reservation_id,
                status=actual.status,
                reserved_usd=actual.reserved_usd,
                actual_cost_usd=actual.actual_cost_usd,
                accounted_cost_usd=actual.accounted_cost_usd,
            )
        )
    return tuple(rows)


def _write(root: Path, name: str, model: BaseModel) -> RegularFileCustodyObservation:
    expected = model.model_dump(mode="json")

    def validate(content: bytes) -> None:
        if (
            type(model).model_validate_json(content, strict=True).model_dump(mode="json")
            != expected
        ):
            raise DevelopmentCorpusResumeError(
                "continuation output differs from its retained evidence"
            )

    binding = write_json_evidence(
        evidence_root=root,
        relative_path=name,
        value=expected,
        max_bytes=MAX_DEVELOPMENT_CORPUS_RESUME_BYTES,
        validate_content=validate,
        require_private_parent=True,
    )
    return observe_regular_file_custody(
        root=root,
        relative_path=name,
        expected_binding=binding,
        label="continuation output",
        max_bytes=MAX_DEVELOPMENT_CORPUS_RESUME_BYTES,
        allow_directory_entry_metadata_change=True,
    )


def _write_cumulative_score(
    root: Path,
    score: DevelopmentCorpusResumeBenchmarkScore,
    *,
    revalidate_context: Callable[[], object],
) -> RegularFileCustodyObservation:
    """Keep the composed score's separate 96 MB cap; no older history/output bound is widened."""

    if type(score) is not DevelopmentCorpusResumeBenchmarkScore:
        raise DevelopmentCorpusResumeError("cumulative output requires its exact score type")

    def validate(content: bytes) -> None:
        revalidate_context()
        if read_development_corpus_resume_score(content) != score:
            raise DevelopmentCorpusResumeError("cumulative output differs from retained evidence")
        revalidate_context()

    revalidate_context()
    binding = write_json_evidence(
        evidence_root=root,
        relative_path="cumulative-score.json",
        value=score.model_dump(mode="json"),
        max_bytes=MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES,
        validate_content=validate,
        require_private_parent=True,
    )
    return observe_regular_file_custody(
        root=root,
        relative_path="cumulative-score.json",
        expected_binding=binding,
        label="cumulative score output",
        max_bytes=MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES,
        allow_directory_entry_metadata_change=True,
    )


async def run_development_corpus_resume(
    *,
    prepared: PreparedDevelopmentCorpusResume,
    ledger: AtomicCostLedger,
    operator_secrets: OperatorSecrets,
    output_dir: Path,
    allow_code_egress: bool = False,
    mock_transport: httpx.MockTransport | None = None,
    inputs: DevelopmentCorpusResumeInputs | None = None,
) -> DevelopmentCorpusResumeHistory:
    """Run one explicit continuation stage, preserving original scope, prior costs and interruption.

    No automatic second continuation is scheduled. Existing STOP/CARRY policy, request timeout
    and selected stage deadline remain; successful source responses are never redispatched.
    """

    if allow_code_egress is not True:
        raise DevelopmentCorpusResumeError("continuation requires explicit source-egress consent")
    if (
        type(ledger) is not AtomicCostLedger
        or type(operator_secrets) is not OperatorSecrets
        or not operator_secrets.openrouter_api_key_present
        or (mock_transport is not None and type(mock_transport) is not httpx.MockTransport)
    ):
        raise DevelopmentCorpusResumeError(
            "continuation requires exact ledger and credential handles"
        )
    prepared = _rebuild(prepared)
    history = prepared.history
    if history.original.transport != (
        "MOCK_HTTP" if mock_transport is not None else "HTTP_OBSERVATION"
    ):
        raise DevelopmentCorpusResumeError("continuation transport differs from original history")
    if (
        operator_secrets.openrouter_api_key in history.model_dump_json()
        or operator_secrets.openrouter_api_key in prepared.plan.model_dump_json()
    ):
        raise DevelopmentCorpusResumeError(
            "development credential overlaps retained continuation inputs"
        )
    if not isinstance(output_dir, Path) or not output_dir.is_absolute() or ".." in output_dir.parts:
        raise DevelopmentCorpusResumeError("continuation output must be absolute and normalized")
    if inputs is not None:
        _verify_input_meaning(inputs)
        first = prepared.candidate.shards[0]
        if (
            inputs.history != history
            or (
                inputs.metadata is not None
                and inputs.metadata != (first.discovery or first.endpoint_snapshot)
            )
            or any(
                (f.directory.path / f.binding.path).is_relative_to(output_dir)
                or output_dir.is_relative_to(f.directory.path / f.binding.path)
                for f in inputs.files
            )
        ):
            raise DevelopmentCorpusResumeError(
                "continuation input and output selections overlap or differ"
            )
    policy = history.original.plan.policy
    prior = _prior_accounting(history)
    state = ledger.snapshot()
    validate_development_accounting_entries(prior, state, budget_usd=policy.total_budget_usd)
    carried = {
        e.request_id for e in development_uncertain_reservations(policy=policy, snapshot=state)
    }
    requests = {
        development_ledger_request_id(s.estimate.request_id) for s in prepared.plan.candidate.shards
    }
    if (
        state.over_cap
        or state.has_reservation_overrun
        or state.active_reserved_usd != 0
        or state.portfolio_holds
        or any(
            e.request_id in requests
            or (e.status is CostEntryStatus.UNCERTAIN_ACCOUNTED and e.request_id not in carried)
            for e in state.entries
        )
        or prepared.plan.estimated_continuation_cost_usd > state.remaining_usd
    ):
        raise DevelopmentCorpusResumeError("continuation preflight refuses cumulative accounting")
    custody = prepare_owned_empty_directory(output_dir, label="continuation output")
    bindings = [
        _write(output_dir, "prior-history.json", history),
        _write(output_dir, "plan.json", prepared.plan),
    ]
    current: tuple[DevelopmentCorpusAccountingEntry, ...] = ()
    score_binding: RegularFileCustodyObservation | None = None
    measurement_binding: RegularFileCustodyObservation | None = None

    def require_context() -> CostLedgerSnapshot:
        if inputs is not None:
            require_development_corpus_resume_inputs(inputs)
        require_same_unlinked_directory_objects(custody, label="continuation output")
        for binding in bindings:
            _require_file(binding, max_bytes=MAX_DEVELOPMENT_CORPUS_RESUME_BYTES)
        if score_binding is not None:
            _require_file(score_binding, max_bytes=MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES)
        if measurement_binding is not None:
            require_regular_file_custody_unchanged(
                measurement_binding,
                label="continuation control measurement",
                max_bytes=MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES,
                allow_directory_entry_metadata_change=True,
                allow_composed_evidence=True,
            )
        snapshot = ledger.snapshot()
        validate_development_accounting_entries(
            (*prior, *current), snapshot, budget_usd=policy.total_budget_usd
        )
        return snapshot

    generations = {
        s.generation_id for s in history.original.observations if s.generation_id is not None
    } | {
        s.generation_id
        for stage in history.continuations
        for s in stage.observations
        if s.generation_id is not None
    }
    started = time.monotonic()
    deadline = started + prepared.plan.candidate.maximum_run_seconds
    observations: list[DevelopmentCorpusShardObservation] = []
    reason: _StopReason | None = None
    interruption: BaseException | None = None
    try:
        async with asyncio.timeout(max(0.0, deadline - time.monotonic())):
            for shard in prepared.candidate.shards:
                if shard.shard_id not in prepared.plan.selected_shard_ids:
                    continue
                require_context()
                if time.monotonic() >= deadline:
                    raise TimeoutError("continuation stage deadline exhausted before dispatch")
                observation = await review_development_corpus_shard(
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
                current = _current_accounting(prepared, require_context())
                bindings.append(_write(output_dir, shard.shard_id + ".json", observation))
                require_context()
                if observation.generation_id is not None:
                    generations.add(observation.generation_id)
                if time.monotonic() >= deadline:
                    raise TimeoutError("continuation stage deadline exhausted after observation")
                if observation.status != "OBSERVED":
                    reason = "SHARD_INCOMPLETE"
                    break
    except (asyncio.CancelledError, KeyboardInterrupt, SystemExit) as exc:
        interruption, reason = exc, "INTERRUPTED"
    except Exception:
        reason = "LOCAL_FAILURE"
    try:
        current = _current_accounting(prepared, require_context())
        attempt = DevelopmentCorpusResumeAttempt(
            plan=prepared.plan,
            transport="MOCK_HTTP" if mock_transport is not None else "HTTP_OBSERVATION",
            status="OBSERVED_ALL_SELECTED_SHARDS" if reason is None else "INCOMPLETE",
            stop_reason=reason,
            observations=tuple(observations),
            accounting=current,
            elapsed_seconds=time.monotonic() - started,
        )
        bindings.append(_write(output_dir, "attempt.json", attempt))
        result = freeze_development_corpus_resume_history(
            original=history.original,
            material=history.material,
            original_score=history.original_score,
            continuations=(*history.continuations, attempt),
        )
        require_context()
        bindings.append(_write(output_dir, "result.json", result))
        require_context()
        if result.original_score is not None:
            score = score_development_corpus_resume(history=result)
            score_binding = _write_cumulative_score(
                output_dir, score, revalidate_context=require_context
            )
            require_context()
            measured = measure_development_corpus_controls(score=score)
            require_context()
            measurement_binding = write_development_corpus_control_measurement(
                output_dir, measured, revalidate_context=require_context
            )
            require_context()
    except BaseException as exc:
        if interruption is not None:
            raise interruption from None
        if not isinstance(exc, Exception):
            raise
        raise DevelopmentCorpusResumeError(
            "continuation output or accounting could not be finalized"
        ) from None
    if interruption is not None:
        raise interruption
    return result
