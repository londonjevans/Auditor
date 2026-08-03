"""Evidence-derived minimum analysis floor and terminal run status."""

from __future__ import annotations

from collections import Counter
from collections.abc import Collection, Mapping, Sequence

from mmaudit.models.schemas import (
    AnalysisState,
    AuditQualityStatus,
    AuditRunStatus,
    CompilationStatus,
    CoverageMetric,
    MinimumAnalysisFloor,
    QualityGateResult,
    RepositoryMap,
    ScannerRun,
    SolidityCompilationResult,
    UsageRecord,
)
from mmaudit.models.usage import is_creditable_usage_record
from mmaudit.orchestration.assurance import is_qualifying_real_scanner_run
from mmaudit.reporting.status import quality_status_for_run_status

DEFAULT_STATIC_SCANNER_NAMES: frozenset[str] = frozenset(
    {
        "codeql",
        "semgrep",
        "slither",
    }
)


def assess_minimum_analysis_floor(
    *,
    repository: RepositoryMap,
    compilations: Sequence[SolidityCompilationResult],
    scanner_runs: Sequence[ScannerRun],
    usage: Sequence[UsageRecord],
    required_model_roles: Collection[str],
    coverage_metrics: Mapping[str, CoverageMetric],
    solidity_applicable: bool = True,
    static_analysis_applicable: bool = True,
    applicable_static_scanner_names: Collection[str] = DEFAULT_STATIC_SCANNER_NAMES,
    model_review_applicable: bool = True,
    scanner_only: bool = False,
    explicit_downgrade_reason: str | None = None,
    surface_analysis_feasible: bool = True,
    surface_feasibility_reasons: Sequence[str] = (),
    orchestration_failures: Sequence[str] = (),
) -> MinimumAnalysisFloor:
    """Derive the terminal status from qualifying runtime evidence only."""

    scanner_names = _canonical_text(applicable_static_scanner_names)
    roles_required = _canonical_text(required_model_roles)
    surface_reasons = _canonical_text(surface_feasibility_reasons)
    orchestration_errors = _canonical_text(orchestration_failures)
    downgrade_reason = (
        explicit_downgrade_reason.strip() if explicit_downgrade_reason is not None else None
    )

    source_files_ingested = sum(
        _is_applicable_source_file(file.path, file.language, solidity_applicable)
        for file in repository.files
    )
    source_ingestion_succeeded = source_files_ingested > 0

    applicable_compilations = tuple(compilations) if solidity_applicable else ()
    compilation_counts = Counter(result.status for result in applicable_compilations)
    compilation_statuses = {
        status: compilation_counts[status]
        for status in sorted(compilation_counts, key=lambda item: item.value)
    }
    qualifying_compilations = sum(
        result.status is CompilationStatus.SUCCESS
        and result.ast_available
        and bool(result.contracts_compiled)
        for result in applicable_compilations
    )
    compilation_satisfied = not solidity_applicable or (
        bool(applicable_compilations) and qualifying_compilations == len(applicable_compilations)
    )

    qualifying_real_static_scanners = sorted(
        {
            run.scanner
            for run in scanner_runs
            if (
                static_analysis_applicable
                and run.scanner in scanner_names
                and is_qualifying_real_scanner_run(run)
            )
        }
    )
    static_analysis_satisfied = not static_analysis_applicable or bool(
        qualifying_real_static_scanners
    )

    completed_real_model_roles = sorted(
        {record.role for record in usage if is_creditable_usage_record(record, require_real=True)}
    )
    qualifying_real_analysis = bool(qualifying_real_static_scanners or completed_real_model_roles)
    model_review_required = model_review_applicable and not scanner_only
    model_review_satisfied = not model_review_required or (
        bool(roles_required) and set(roles_required) <= set(completed_real_model_roles)
    )

    metric_ids = sorted(coverage_metrics)
    coverage_denominators_valid = bool(metric_ids) and all(
        not metric.failures and (metric.denominator > 0 or bool(metric.not_applicable_evidence))
        for metric in coverage_metrics.values()
    )

    limitations: list[str] = []
    if not qualifying_real_analysis:
        limitations.append("no qualifying real scanner or real model analysis completed")
    if not source_ingestion_succeeded:
        limitations.append("source ingestion did not retain an applicable source file")
    if not compilation_satisfied:
        if any(
            status in {CompilationStatus.FAILED, CompilationStatus.TIMED_OUT}
            for status in compilation_statuses
        ):
            limitations.append("Solidity compilation failed or timed out")
        else:
            limitations.append("Solidity compilation did not produce AST-backed contracts")
    if not static_analysis_satisfied:
        limitations.append("no qualifying REAL applicable static analyzer completed")
    if not model_review_satisfied:
        missing_roles = sorted(set(roles_required) - set(completed_real_model_roles))
        limitations.append(
            "required REAL model roles did not complete"
            + (f": {', '.join(missing_roles)}" if missing_roles else "")
        )
    if not coverage_denominators_valid:
        limitations.append("coverage denominators are missing or invalid")
    if not surface_analysis_feasible:
        limitations.append(
            "required surface analysis is infeasible"
            + (f": {', '.join(surface_reasons)}" if surface_reasons else "")
        )
    limitations.extend(f"orchestration failure: {failure}" for failure in orchestration_errors)
    if downgrade_reason is not None:
        limitations.append(f"explicit downgrade: {downgrade_reason}")
    elif scanner_only:
        limitations.append("scanner-only analysis lacks an explicit downgrade authorization")

    hard_failure = (
        not source_ingestion_succeeded
        or (bool(orchestration_errors) and not qualifying_real_analysis)
        or any(
            status in {CompilationStatus.FAILED, CompilationStatus.TIMED_OUT}
            for status in compilation_statuses
        )
    )
    complete_floor = (
        qualifying_real_analysis
        and source_ingestion_succeeded
        and compilation_satisfied
        and static_analysis_satisfied
        and model_review_satisfied
        and coverage_denominators_valid
        and bool(metric_ids)
        and surface_analysis_feasible
        and not orchestration_errors
        and not scanner_only
        and downgrade_reason is None
    )
    degraded_floor = (
        downgrade_reason is not None
        and qualifying_real_analysis
        and source_ingestion_succeeded
        and compilation_satisfied
        and coverage_denominators_valid
        and bool(metric_ids)
        and surface_analysis_feasible
        and not orchestration_errors
        and (
            not scanner_only
            or (static_analysis_applicable and bool(qualifying_real_static_scanners))
        )
    )
    run_status = (
        AuditRunStatus.FAILED
        if hard_failure
        else (
            AuditRunStatus.COMPLETE
            if complete_floor
            else (AuditRunStatus.DEGRADED if degraded_floor else AuditRunStatus.INCOMPLETE)
        )
    )

    return MinimumAnalysisFloor(
        run_status=run_status,
        source_files_ingested=source_files_ingested,
        source_ingestion_succeeded=source_ingestion_succeeded,
        solidity_applicable=solidity_applicable,
        compilation_statuses=compilation_statuses,
        qualifying_compilations=qualifying_compilations,
        compilation_satisfied=compilation_satisfied,
        static_analysis_applicable=static_analysis_applicable,
        qualifying_real_static_scanners=qualifying_real_static_scanners,
        static_analysis_satisfied=static_analysis_satisfied,
        model_review_required=model_review_required,
        scanner_only=scanner_only,
        explicit_downgrade_reason=downgrade_reason,
        required_model_roles=roles_required,
        completed_real_model_roles=completed_real_model_roles,
        model_review_satisfied=model_review_satisfied,
        coverage_metric_ids=metric_ids,
        coverage_denominators_valid=coverage_denominators_valid,
        surface_analysis_feasible=surface_analysis_feasible,
        orchestration_failures=orchestration_errors,
        minimum_floor_met=run_status is AuditRunStatus.COMPLETE,
        limitations=sorted(set(limitations)),
    )


def minimum_analysis_floor_quality_gate(
    floor: MinimumAnalysisFloor,
) -> QualityGateResult:
    """Convert minimum-floor evidence into the existing quality-gate schema."""

    if floor.run_status is AuditRunStatus.COMPLETE:
        state = AnalysisState.DETERMINISTIC
    elif floor.run_status is AuditRunStatus.FAILED:
        state = AnalysisState.ATTEMPTED_FAILED
    elif floor.qualifying_real_static_scanners:
        state = AnalysisState.SCANNER_SUPPORTED
    elif floor.completed_real_model_roles:
        state = AnalysisState.MODEL_ONLY
    else:
        state = AnalysisState.NOT_ANALYZED
    return QualityGateResult(
        gate="minimum_analysis_floor",
        required=True,
        passed=floor.run_status is AuditRunStatus.COMPLETE,
        detail=(
            "minimum analysis floor satisfied by qualifying REAL execution evidence"
            if floor.minimum_floor_met
            else "; ".join(floor.limitations)
        ),
        state=state,
    )


def audit_quality_status_for_run_status(status: AuditRunStatus) -> AuditQualityStatus:
    """Return the only compatible legacy quality status for a typed run state."""

    return quality_status_for_run_status(status)


def _is_applicable_source_file(path: str, language: str, solidity_applicable: bool) -> bool:
    if solidity_applicable:
        return language.casefold() == "solidity" or path.casefold().endswith(".sol")
    return bool(path and language)


def _canonical_text(values: Collection[str] | Sequence[str]) -> list[str]:
    return sorted({value.strip() for value in values if value.strip()})
