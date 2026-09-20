"""Complete, noncrediting compiler/report gaps and their original failure-manifest handoff."""

from __future__ import annotations

import json
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import mmaudit.scanners.foundry as runner
import mmaudit.scanners.foundry_statement_producer as producer
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    FoundryTestExecutionSummary,
    RepositorySuiteExecutionPolicy,
    RepositorySuiteWorkspaceCopyEvidence,
    RepositoryTestExecution,
    ScannerStatus,
)
from mmaudit.scanners.fork_rpc import PinnedForkObservation
from mmaudit.scanners.foundry_inventory_runner import FoundryInventoryOverflowError
from tests.unit.test_foundry_statement_producer import (
    _debug_coverage,
    _Inputs,
    _inputs,
    _process,
)


def _missing_inputs() -> _Inputs:
    inputs = _inputs()
    return replace(
        inputs,
        processes=tuple(
            _process(
                descriptor,
                index,
                _debug_coverage(hit_count=0, include_statement=False),
                execution.machine_result_sha256 or "",
            )
            for index, (descriptor, execution) in enumerate(
                zip(inputs.selection.tests, inputs.executions, strict=True), 1
            )
        ),
    )


def _gaps(inputs: _Inputs | None = None) -> producer.FoundryStatementCoverageGaps:
    with pytest.raises(producer.FoundryStatementCoverageProductionError) as error:
        producer.produce_foundry_statement_coverage(**(inputs or _missing_inputs()).kwargs())
    assert error.value.observation_gaps is not None
    return error.value.observation_gaps


def _executions(inputs: _Inputs) -> list[RepositoryTestExecution]:
    return [
        RepositoryTestExecution.sealed(
            **{
                **execution.model_dump(mode="python", exclude={"execution_sha256"}),
                "execution_evidence": ExecutionEvidenceKind.UNVERIFIED,
            }
        )
        for execution in inputs.executions
    ]


def _manifest_args(tmp_path: Path, inputs: _Inputs | None = None) -> dict[str, Any]:
    inputs = inputs or _missing_inputs()
    return dict(
        private_dir=tmp_path,
        selection=inputs.selection,
        inventory=inputs.pre_inventory,
        post_inventory=inputs.post_inventory,
        execution_policy=inputs.execution_policy,
        executions=_executions(inputs),
        repository_test_fork_rpc_scopes=inputs.fork_rpc_scopes,
        statement_observation_gaps=_gaps(inputs),
        statement_gap_entity_catalog=inputs.entity_catalog,
        previously_charged_artifact_bytes=sum(p.private_artifact_bytes for p in inputs.processes),
        deadline=time.monotonic() + 30,
    )


def _reseal(
    gaps: producer.FoundryStatementCoverageGaps, **changes: Any
) -> producer.FoundryStatementCoverageGaps:
    return producer.FoundryStatementCoverageGaps.sealed(
        **{
            **gaps.model_dump(mode="python", exclude={"gaps_sha256"}),
            **changes,
        }
    )


def test_missing_spans_retain_every_original_compiler_obligation_and_process() -> None:
    inputs = _missing_inputs()
    gaps = _gaps(inputs)
    assert len(gaps.statements) == 1 and len(gaps.processes) == 2
    physical_id = gaps.statements[0].physical_statement_id
    assert physical_id.startswith("compiler-statement:")
    assert "covered" not in gaps.statements[0].model_dump()
    for gap, process, execution, scope in zip(
        gaps.processes, inputs.processes, inputs.executions, inputs.fork_rpc_scopes, strict=True
    ):
        assert gap.missing_statement_ids == (physical_id,) and not gap.mapped_statement_ids
        assert gap.stdout_sha256 == process.stdout_sha256
        assert gap.private_artifact_sha256 == process.private_artifact_sha256
        assert gap.primary_machine_result_sha256 == execution.machine_result_sha256
        assert gap.coverage_machine_result_sha256 == process.machine_result_sha256
        assert gap.coverage_command_sha256 == process.coverage_command_sha256
        assert gap.fork_rpc_scope_sha256 == scope.evidence_sha256
    assert gaps.interpretation == "MISSING_IS_UNKNOWN_NOT_UNCOVERED_MAPPED_IS_NOT_EXECUTED"
    assert not any(
        (
            gaps.coverage_complete,
            gaps.runtime_authority,
            gaps.qualification_eligible,
            gaps.safety_claim,
        )
    )
    assert producer.FoundryStatementCoverageGaps.model_validate_json(gaps.model_dump_json()) == gaps


@pytest.mark.parametrize(
    "field", ["coverage_complete", "runtime_authority", "qualification_eligible", "safety_claim"]
)
def test_diagnostic_cannot_promote_any_authority_even_with_a_new_digest(field: str) -> None:
    with pytest.raises(ValueError):
        _reseal(_gaps(), **{field: True})


@pytest.mark.parametrize(
    "change",
    [
        "dropped",
        "duplicate",
        "reordered",
        "wrong-sequence",
        "added-reference",
        "dropped-reference",
        "overlap",
        "no-gap",
        "bad-path",
        "bad-span",
        "no-ast",
        "non-atomic",
        "changed-physical-id",
    ],
)
def test_rehashed_incomplete_or_ambiguous_diagnostics_still_refuse(change: str) -> None:
    payload = _gaps().model_dump(mode="python", exclude={"gaps_sha256"})
    processes = payload["processes"]
    statement = payload["statements"][0]
    if change == "dropped":
        payload["processes"] = processes[1:]
    elif change == "duplicate":
        payload["processes"] = (processes[0], processes[0])
    elif change == "reordered":
        payload["processes"] = tuple(reversed(processes))
    elif change == "wrong-sequence":
        processes[0]["sequence_index"] = 2
    elif change == "added-reference":
        processes[0]["missing_statement_ids"] += ("compiler-statement:" + "f" * 64,)
    elif change == "dropped-reference":
        processes[0]["missing_statement_ids"] = ()
    elif change == "overlap":
        processes[0]["mapped_statement_ids"] = processes[0]["missing_statement_ids"]
    elif change == "no-gap":
        for process in processes:
            process["mapped_statement_ids"] = process["missing_statement_ids"]
            process["missing_statement_ids"] = ()
    elif change == "bad-path":
        statement["path"] = "../Source.sol"
    elif change == "bad-span":
        statement["end_byte_exclusive"] = statement["start_byte"]
    elif change == "no-ast":
        statement["compiler_ast_id"] = statement["enclosing_inline_assembly_ast_id"] = None
    elif change == "non-atomic":
        statement["node_type"] = "Block"
    else:
        statement["physical_statement_id"] = "compiler-statement:" + "f" * 64
    with pytest.raises(ValueError):
        producer.FoundryStatementCoverageGaps.sealed(**payload)


def test_missing_span_diagnostic_obeys_inclusive_complete_reference_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(producer, "MAX_FOUNDRY_STATEMENT_GAP_REFERENCES", 2)
    assert len(_gaps().processes) == 2
    monkeypatch.setattr(producer, "MAX_FOUNDRY_STATEMENT_GAP_REFERENCES", 1)
    with pytest.raises(
        producer.FoundryStatementCoverageProductionError, match="population bound"
    ) as error:
        producer.produce_foundry_statement_coverage(**_missing_inputs().kwargs())
    assert error.value.observation_gaps is None  # No truncated population substituted.


def test_other_producer_refusals_do_not_acquire_partial_gap_diagnostics() -> None:
    inputs = _missing_inputs()
    processes = (inputs.processes[0], _inputs().processes[1])
    with pytest.raises(
        producer.FoundryStatementCoverageProductionError, match="population changed"
    ) as error:
        producer.produce_foundry_statement_coverage(**replace(inputs, processes=processes).kwargs())
    assert error.value.observation_gaps is None


def test_failure_manifest_retains_gaps_without_success_or_coverage_receipts(tmp_path: Path) -> None:
    args = _manifest_args(tmp_path)
    path = runner._write_repository_suite_manifest(**args)
    payload = json.loads(path.read_bytes())
    assert payload["schema_version"] == "1.4" and payload["safety_claim"] is False
    assert not any(
        key in payload
        for key in (
            "repository_statement_coverage_evidence",
            "repository_statement_coverage_receipt",
            "repository_statement_entity_catalog",
        )
    )
    assert (
        payload["unvalidated_statement_entity_catalog"]["catalog_sha256"]
        == args["statement_gap_entity_catalog"].catalog_sha256
    )
    assert (
        producer.FoundryStatementCoverageGaps.model_validate_json(
            json.dumps(payload["repository_statement_observation_gaps"])
        )
        == args["statement_observation_gaps"]
    )
    assert len(payload["executions"]) == len(payload["repository_test_fork_rpc_scopes"]) == 2
    assert all(
        e["execution_evidence"] == ExecutionEvidenceKind.UNVERIFIED.value
        for e in payload["executions"]
    )


@pytest.mark.parametrize(
    "change",
    [
        "no-pre",
        "no-post",
        "no-policy",
        "no-catalog",
        "no-gaps",
        "real-executions",
        "missing-execution",
        "missing-scope",
        "reordered-scopes",
        "uncharged",
        "bool-charge",
        "changed-selection",
        "changed-catalog",
        "changed-policy",
        "changed-primary",
        "forged-digest",
        "success-receipt",
    ],
)
def test_failure_manifest_refuses_changed_context_or_promoted_credit(
    tmp_path: Path, change: str
) -> None:
    args = _manifest_args(tmp_path)
    absent = {
        "no-pre": "inventory",
        "no-post": "post_inventory",
        "no-policy": "execution_policy",
        "no-catalog": "statement_gap_entity_catalog",
        "no-gaps": "statement_observation_gaps",
    }
    if change in absent:
        args[absent[change]] = None
    elif change == "real-executions":
        args["executions"] = list(_inputs().executions)
    elif change == "missing-execution":
        args["executions"] = args["executions"][:1]
    elif change == "missing-scope":
        args["repository_test_fork_rpc_scopes"] = args["repository_test_fork_rpc_scopes"][:1]
    elif change == "reordered-scopes":
        args["repository_test_fork_rpc_scopes"] = tuple(
            reversed(args["repository_test_fork_rpc_scopes"])
        )
    elif change in {"uncharged", "bool-charge"}:
        args["previously_charged_artifact_bytes"] = 199 if change == "uncharged" else True
    elif change in {"changed-selection", "changed-catalog", "changed-policy"}:
        field = {
            "changed-selection": "selection_sha256",
            "changed-catalog": "entity_catalog_sha256",
            "changed-policy": "execution_policy_sha256",
        }[change]
        args["statement_observation_gaps"] = _reseal(
            args["statement_observation_gaps"], **{field: "f" * 64}
        )
    elif change == "changed-primary":
        payload = args["statement_observation_gaps"].model_dump(
            mode="python", exclude={"gaps_sha256"}
        )
        payload["processes"][0]["primary_machine_result_sha256"] = "f" * 64
        args["statement_observation_gaps"] = producer.FoundryStatementCoverageGaps.sealed(**payload)
    elif change == "forged-digest":
        args["statement_observation_gaps"] = args["statement_observation_gaps"].model_copy(
            update={"gaps_sha256": "f" * 64}
        )
    else:
        success = producer.produce_foundry_statement_coverage(**_inputs().kwargs())
        args.update(
            statement_coverage_receipt=success.receipt,
            statement_entity_catalog=_inputs().entity_catalog,
            statement_coverage_evidence=success.evidence,
        )
    with pytest.raises(ValueError):
        runner._write_repository_suite_manifest(**args)
    assert not (tmp_path / "repository-suite-execution.json").exists()


def _change_budget(args: dict[str, Any], budget: int) -> None:
    policy = RepositorySuiteExecutionPolicy.sealed(
        **{
            **args["execution_policy"].model_dump(mode="python", exclude={"policy_sha256"}),
            "max_total_output_bytes": budget,
            "max_output_bytes_per_test": 1_024,
        }
    )
    args["execution_policy"] = policy
    args["statement_observation_gaps"] = _reseal(
        args["statement_observation_gaps"], execution_policy_sha256=policy.policy_sha256
    )
    args["executions"] = [
        RepositoryTestExecution.sealed(
            **{
                **e.model_dump(mode="python", exclude={"execution_sha256"}),
                "execution_policy_sha256": policy.policy_sha256,
            }
        )
        for e in args["executions"]
    ]


def test_whole_manifest_including_gaps_is_charged_at_exact_and_one_over_limits(
    tmp_path: Path,
) -> None:
    args = _manifest_args(tmp_path)
    # Keep serialized budget width constant while measuring the whole original payload.
    _change_budget(args, 99_999)
    size = runner._write_repository_suite_manifest(**args).stat().st_size
    limit = size + args["previously_charged_artifact_bytes"]
    assert len(str(limit)) == len(str(99_999))
    _change_budget(args, limit)
    assert runner._write_repository_suite_manifest(**args).stat().st_size == size
    refused = tmp_path / "refused"
    refused.mkdir()
    args["private_dir"] = refused
    _change_budget(args, limit - 1)
    with pytest.raises(FoundryInventoryOverflowError, match="complete artifact byte budget"):
        runner._write_repository_suite_manifest(**args)
    assert not (refused / "repository-suite-execution.json").exists()


def test_expired_failure_manifest_deadline_cannot_write(tmp_path: Path) -> None:
    args = _manifest_args(tmp_path)
    args["deadline"] = time.monotonic() - 1
    with pytest.raises(runner._FoundrySuiteDeadlineExpired):
        runner._write_repository_suite_manifest(**args)
    assert not (tmp_path / "repository-suite-execution.json").exists()


@pytest.mark.parametrize(
    "failure", ["none", "overflow", "write", "deadline-before", "deadline-after"]
)
def test_original_finalizer_retains_failure_only_and_never_promotes_after_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    # This is a synthetic lifecycle unit control, not isolation/runtime evidence.
    # Separate native controls exercise the real admission and original runner.
    inputs = _missing_inputs()
    policy = inputs.execution_policy
    workspace_copy = RepositorySuiteWorkspaceCopyEvidence.sealed(
        attempt_binding_sha256=inputs.fork_rpc_scopes[0].attempt_binding_sha256,
        selection_sha256=inputs.selection.selection_sha256,
        repository_sha256=inputs.selection.repository_sha256,
        source_inventory_sha256_before=inputs.selection.repository_sha256,
        source_inventory_sha256_after=inputs.selection.repository_sha256,
        workspace_inventory_sha256_after_copy=inputs.selection.repository_sha256,
        workspace_inventory_sha256_after_execution=inputs.selection.repository_sha256,
        source_root_device_before=1,
        source_root_inode_before=2,
        source_root_device_after=1,
        source_root_inode_after=2,
        workspace_root_device_before=1,
        workspace_root_inode_before=3,
        workspace_root_device_after=1,
        workspace_root_inode_after=3,
        workspace_parent_device=1,
        workspace_parent_inode=4,
    )
    clock = [100.0]
    monkeypatch.setattr(runner, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(runner, "_cleanup_error", lambda *_args: None)
    monkeypatch.setattr(
        runner, "isolation_attestation_sha256", lambda _: policy.isolation_attestation_sha256
    )
    monkeypatch.setattr(
        runner, "isolation_execution_evidence", lambda _: ExecutionEvidenceKind.REAL
    )
    monkeypatch.setattr(runner, "_foundry_observations_support_real_execution", lambda **_: True)
    original_writer = runner._write_repository_suite_manifest
    writes = []

    def write(*args: Any, **kwargs: Any) -> Path:
        writes.append(kwargs)
        assert kwargs["statement_observation_gaps"] is not None
        assert all(e.execution_evidence is ExecutionEvidenceKind.UNVERIFIED for e in args[5])
        if failure == "deadline-before":
            clock[0] = 111.0
        path = original_writer(*args, **kwargs)
        if failure == "write":
            raise OSError("synthetic incomplete failure write")
        if failure == "deadline-after":
            clock[0] = 111.0
        return path

    monkeypatch.setattr(runner, "_write_repository_suite_manifest", write)
    observations = [
        runner._FoundryTestObservation(
            descriptor=descriptor,
            status=execution.status,
            terminal_detail=None,
            duration_seconds=0.1,
            command_sha256=execution.command_sha256,
            output_sha256=execution.output_sha256,
            output_bytes=execution.output_bytes,
            process_exit_code=0,
            machine_output_validated=True,
            machine_result_sha256=execution.machine_result_sha256,
            summary=FoundryTestExecutionSummary(
                unit_tests=1,
                passed_tests=1,
                fuzz_tests=0,
                invariant_tests=0,
                failed_tests=0,
                skipped_tests=0,
                fuzz_cases=0,
                invariant_runs=0,
                invariant_calls=0,
            ),
            process_started=True,
        )
        for descriptor, execution in zip(inputs.selection.tests, inputs.executions, strict=True)
    ]
    run = runner._finalize_foundry_repository_suite(
        root=tmp_path,
        private_dir=tmp_path,
        backend=SimpleNamespace(name=policy.isolation_backend),
        start=datetime.now(UTC),
        monotonic_start=100.0,
        deadline=110.0,
        total_timeout_seconds=10.0,
        status=ScannerStatus.SUCCESS,
        error=None,
        selection=inputs.selection,
        observations=observations,
        fork=PinnedForkObservation(
            chain_id=policy.chain_id, block_number=policy.block_number, block_hash=policy.block_hash
        ),
        executable_sha256=policy.tool_sha256,
        version=policy.tool_version,
        compiler_version=policy.compiler_version,
        compiler_sha256=policy.compiler_sha256,
        execution_policy=policy,
        inventory=inputs.pre_inventory,
        post_inventory=inputs.post_inventory,
        fuzz_seed=policy.fuzz_seed,
        repository_test_fork_rpc_scopes=inputs.fork_rpc_scopes,
        repository_suite_workspace_copy=workspace_copy,
        repository_statement_entity_catalog=inputs.entity_catalog,
        repository_statement_coverage_processes=inputs.processes,
        pre_statement_catalogs=inputs.pre_compiler_catalogs,
        post_statement_catalogs=inputs.post_compiler_catalogs,
        repository_suite_artifact_bytes=policy.max_total_output_bytes
        if failure == "overflow"
        else 200,
    )
    assert len(writes) == 1
    assert run.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert all(
        e.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
        for e in run.repository_test_executions
    )
    assert not run.machine_output_validated and run.foundry_summary is None
    assert not run.repository_statement_coverage_evidence
    assert run.repository_statement_coverage_receipt is None
    assert run.execution_observation_sha256_is_valid()
    if failure.startswith("deadline"):
        assert run.status is ScannerStatus.TIMED_OUT
    else:
        assert run.status is ScannerStatus.FAILED
    if failure == "none":
        assert run.raw_output_path is not None and run.raw_output_bytes > 0
    else:
        assert run.raw_output_path is None and run.raw_output_bytes == 0
        assert not (tmp_path / "repository-suite-execution.json").exists()
