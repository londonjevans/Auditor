"""Offline finding replay from retained Foundry suite and per-test artifacts.

Only original per-test Forge output supplies finding semantics. Coverage,
debugger and gap records are separate claims and gain no authority here.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    RepositoryCodeExecutionState,
    RepositoryTestExecutionStatus,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
)
from mmaudit.scanners.fork_rpc import PinnedForkObservation
from mmaudit.scanners.foundry import (
    _aggregate_foundry_summaries,
    _FoundrySuiteDeadlineExpired,
    _FoundryTestObservation,
    _parse_exact_foundry_test_with_deadline,
    _private_artifact_usage,
    _remaining_deadline_seconds,
    _repository_test_executions,
    _repository_test_findings,
    _SuiteArtifactBudget,
)
from mmaudit.scanners.foundry_inventory_runner import (
    FoundryInventoryRunnerError,
    _strict_json_object,
)

_REPLAY_TIMEOUT_SECONDS = 30.0
_MANIFEST_BYTE_LIMIT = 100_000_000


def reparse_retained_foundry_findings(
    *,
    run: ScannerRun,
    repository_root: Path,
    artifact_root: Path,
    retained_manifest: bytes,
) -> tuple[ScannerFinding, ...]:
    """Recreate findings without executing a tool, contract, or RPC request.

    The caller holds manifest, owner and workspace custody throughout this call.
    Every auxiliary test tree is independently observed through the original
    bounded no-follow descriptor snapshot, not reopened by a claimed JSON path.
    """

    deadline = time.monotonic() + _REPLAY_TIMEOUT_SECONDS
    try:
        return _reparse(
            run=run,
            repository_root=repository_root,
            artifact_root=artifact_root,
            retained_manifest=retained_manifest,
            deadline=deadline,
        )
    except _FoundrySuiteDeadlineExpired as exc:
        raise ValueError("Foundry finding replay exceeded its bounded deadline") from exc
    except (FoundryInventoryRunnerError, OSError, UnicodeError) as exc:
        raise ValueError("Foundry finding replay lacks exact retained artifact custody") from exc


def _reparse(
    *,
    run: ScannerRun,
    repository_root: Path,
    artifact_root: Path,
    retained_manifest: bytes,
    deadline: float,
) -> tuple[ScannerFinding, ...]:
    if len(retained_manifest) > _MANIFEST_BYTE_LIMIT:
        raise ValueError("Foundry finding replay manifest exceeds its byte ceiling")
    # Revalidate nested seals and all cross-field relationships, even if a caller
    # used model_copy/model_construct to bypass the normal report parser.
    run = ScannerRun.model_validate(run.model_dump(mode="python"))
    selection = run.repository_suite_selection
    policy = run.repository_suite_execution_policy
    if (
        run.scanner != "foundry_fork"
        or run.status is not ScannerStatus.SUCCESS
        or run.execution_evidence is not ExecutionEvidenceKind.REAL
        or run.repository_code_execution is not RepositoryCodeExecutionState.ISOLATED
        or not run.machine_output_validated
        or selection is None
        or not selection.tests
        or policy is None
        or run.repository_suite_inventory is None
        or run.repository_suite_post_inventory is None
        or run.raw_output_path != "foundry_fork/repository-suite-execution.json"
        or run.raw_output_bytes != len(retained_manifest)
        or run.raw_output_sha256 != hashlib.sha256(retained_manifest).hexdigest()
    ):
        raise ValueError("Foundry finding replay requires a complete current repository suite")
    if repository_root != artifact_root / "workspace":
        raise ValueError("Foundry finding replay workspace differs from its owner")
    _validate_manifest_bindings(run, retained_manifest)
    _remaining_deadline_seconds(deadline)

    generated_root = (
        artifact_root / "container-output"
        if run.isolation_backend == "rootless-container"
        else artifact_root
    )
    budget = _SuiteArtifactBudget(
        max_bytes_per_test=policy.max_output_bytes_per_test,
        max_total_bytes=policy.max_total_output_bytes,
    )
    observations: list[_FoundryTestObservation] = []
    for index, (descriptor, execution) in enumerate(
        zip(selection.tests, run.repository_test_executions, strict=True)
    ):
        if execution.descriptor_sha256 != descriptor.descriptor_sha256:
            raise ValueError("Foundry finding replay execution order differs from selection")
        usage = _private_artifact_usage(
            generated_root / "repository-suite" / "tests" / f"{index:05d}",
            deadline=deadline,
            trusted_root=artifact_root,
            capture_relative_paths=frozenset({"stdout.json", "stderr.txt"}),
        )
        budget.charge(usage, label="Foundry finding replay", per_test=True)
        if (
            usage.artifact_sha256 != execution.output_sha256
            or usage.bytes != execution.output_bytes
        ):
            raise ValueError("Foundry finding replay test tree differs from original output")
        status, detail, summary, machine_sha256 = _parse_exact_foundry_test_with_deadline(
            usage.captured("stdout.json").decode("utf-8"),
            descriptor=descriptor,
            return_code=execution.process_exit_code,
            deadline=deadline,
        )
        observations.append(
            _FoundryTestObservation(
                descriptor=descriptor,
                status=status,
                terminal_detail=detail,
                duration_seconds=execution.duration_seconds,
                command_sha256=execution.command_sha256,
                output_sha256=usage.artifact_sha256,
                output_bytes=usage.bytes,
                process_exit_code=execution.process_exit_code,
                machine_output_validated=execution.machine_output_validated,
                machine_result_sha256=machine_sha256,
                summary=summary,
                process_started=True,
            )
        )
    replayed_executions = _repository_test_executions(
        selection=selection,
        observations=observations,
        fallback_detail="Foundry finding replay lacks original output",
        fork=PinnedForkObservation(policy.chain_id, policy.block_number, policy.block_hash),
        fuzz_seed=policy.fuzz_seed,
        execution_evidence=run.execution_evidence,
        repository_code_execution=run.repository_code_execution,
        isolation_backend=run.isolation_backend,
        isolation_attestation=run.isolation_attestation_sha256,
        compiler_version=policy.compiler_version,
        compiler_sha256=policy.compiler_sha256,
        execution_policy=policy,
        inventory=run.repository_suite_inventory,
        post_inventory=run.repository_suite_post_inventory,
        deadline=deadline,
    )
    expected_exit = int(
        any(item.status is not RepositoryTestExecutionStatus.PASSED for item in observations)
    )
    if (
        replayed_executions != run.repository_test_executions
        or _aggregate_foundry_summaries(observations) != run.foundry_summary
        or run.process_exit_code != expected_exit
    ):
        raise ValueError("Foundry finding replay differs from classified execution semantics")
    return tuple(
        _repository_test_findings(
            repository_root, replayed_executions, selection, deadline=deadline
        )
    )


def _validate_manifest_bindings(run: ScannerRun, retained: bytes) -> None:
    """Join exact report claims; do not promote auxiliary diagnostic claims."""

    payload = _strict_json_object(retained, label="Foundry suite replay manifest")
    report = run.model_dump(mode="json")
    mapping = {
        "selection": "repository_suite_selection",
        "pre_execution_inventory": "repository_suite_inventory",
        "post_execution_inventory": "repository_suite_post_inventory",
        "execution_policy": "repository_suite_execution_policy",
        "executions": "repository_test_executions",
    }
    expected = {key: report[value] for key, value in mapping.items()}
    for key in (
        "repository_test_fork_rpc_scopes",
        "repository_statement_coverage_evidence",
        "repository_statement_entity_catalog",
        "repository_statement_coverage_receipt",
    ):
        if key in report:
            expected[key] = report[key]
    expected["safety_claim"] = False
    # The full bytes remain hash-bound, but these separate diagnostics are never
    # treated as test stdout, coverage evidence or authority by this normalizer.
    diagnostic_keys = {
        "repository_debugger_observations",
        "repository_statement_observation_gaps",
        "unvalidated_statement_entity_catalog",
    }
    observed = {key: value for key, value in payload.items() if key not in diagnostic_keys}
    has_gaps = "repository_statement_observation_gaps" in payload
    if has_gaps != ("unvalidated_statement_entity_catalog" in payload):
        raise ValueError("Foundry replay gap diagnostics lack their paired catalog")
    if has_gaps:
        # The native finalizer emits these only after downgrading the run to
        # FAILED/UNVERIFIED. A coherently rehashed success must not hide that gap.
        raise ValueError("Foundry failure-only gap manifest cannot authorize successful findings")
    debugger = payload.get("repository_debugger_observations")
    if "repository_debugger_observations" in payload and (
        not isinstance(debugger, dict)
        or debugger.get("runtime_authority") is not False
        or debugger.get("coverage_complete") is not False
        or debugger.get("execution_scope")
        != "SEPARATE_INVOCATIONS_NOT_ORIGINAL_COVERAGE_OR_FULL_FUZZ_POPULATION"
    ):
        raise ValueError("Foundry replay debugger diagnostics claim unsupported authority")
    expected["schema_version"] = (
        "1.4"
        if has_gaps
        else "1.3"
        if debugger is not None
        else "1.2"
        if run.repository_statement_coverage_receipt is not None
        else "1.1"
        if run.repository_statement_coverage_evidence
        else "1.0"
    )

    # Canonical JSON preserves exact bool/int distinctions which dict equality
    # would erase. Duplicate keys and non-finite values were rejected above.
    def canonical(value: object) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)

    if canonical(observed) != canonical(expected):
        raise ValueError("Foundry replay manifest differs from exact scanner claims")
