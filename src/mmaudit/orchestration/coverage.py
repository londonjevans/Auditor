"""Language-neutral deterministic coverage evidence."""

from __future__ import annotations

from collections.abc import Sequence

from mmaudit.models.schemas import (
    AnalysisState,
    CoverageExclusion,
    CoverageMetric,
    CoverageProvenance,
    ExecutionEvidenceKind,
    RepositoryMap,
    ScannerRun,
    ScannerStatus,
)


def _scanner_completion_failure(run: ScannerRun) -> str | None:
    """Return why one requested scanner lacks qualifying deterministic runtime evidence."""

    from mmaudit.orchestration.assurance import (
        CERTIFIED_ISOLATION_BACKENDS,
        is_qualifying_real_scanner_run,
    )

    if run.status is not ScannerStatus.SUCCESS:
        return f"scanner status {run.status.value}"
    if run.execution_evidence is not ExecutionEvidenceKind.REAL:
        return f"execution evidence is {run.execution_evidence.value}, not real"
    if not run.machine_output_validated:
        return "machine output was not strictly validated"
    if (
        not run.version
        or run.executable_sha256 is None
        or not run.command
        or run.raw_output_path is None
        or run.raw_output_sha256 is None
        or run.raw_output_bytes <= 0
        or run.process_exit_code is None
        or run.isolation_backend is None
        or run.isolation_attestation_sha256 is None
    ):
        return "runtime evidence is incomplete"
    if run.isolation_backend not in CERTIFIED_ISOLATION_BACKENDS:
        return "isolation backend is not certified"
    if not run.execution_observation_sha256_is_valid():
        return "execution observation digest is absent or invalid"
    if not is_qualifying_real_scanner_run(run):
        return "scanner runtime evidence does not satisfy qualifying REAL authority"
    return None


def scanner_completion_coverage_metric(
    scanner_runs: Sequence[ScannerRun],
) -> CoverageMetric:
    """Measure exact requested-versus-qualified deterministic scanner completion."""

    excluded_statuses = {ScannerStatus.SKIPPED, ScannerStatus.NOT_APPLICABLE}
    requested = [run for run in scanner_runs if run.status not in excluded_statuses]
    successful = [run for run in requested if _scanner_completion_failure(run) is None]
    exclusions = [
        CoverageExclusion(
            subject=f"{run.scanner}[{position}]",
            reason=(
                run.error
                or (
                    "scanner was not applicable to the audited scope"
                    if run.status is ScannerStatus.NOT_APPLICABLE
                    else "scanner was explicitly skipped"
                )
            ),
            provenance=(
                CoverageProvenance.DISCOVERY
                if run.status is ScannerStatus.NOT_APPLICABLE
                else CoverageProvenance.CONFIGURATION
            ),
        )
        for position, run in enumerate(scanner_runs)
        if run.status in excluded_statuses
    ]
    denominator = len(requested)
    numerator = len(successful)
    return CoverageMetric(
        numerator=numerator,
        denominator=denominator,
        population=len(scanner_runs),
        percentage=round((numerator / denominator) * 100, 4) if denominator else None,
        exclusions=exclusions,
        not_applicable_evidence=(
            ["all inventoried scanners were explicitly skipped or not applicable"]
            if scanner_runs and not requested
            else []
        ),
        confidence=1,
        provenance=[
            CoverageProvenance.CONFIGURATION,
            CoverageProvenance.STATIC_TOOL,
        ],
        failures=(
            [
                f"{run.scanner}: {failure}"
                for run in requested
                if (failure := _scanner_completion_failure(run)) is not None
            ]
            if requested
            else (["scanner inventory was not produced"] if not scanner_runs else [])
        ),
        state=(AnalysisState.SCANNER_SUPPORTED if requested else AnalysisState.NOT_ANALYZED),
        detail="Requested deterministic scanners that completed successfully",
    )


def generic_source_ingestion_coverage_metric(retained_sources: int) -> CoverageMetric:
    """Measure retained language-neutral sources without implying review coverage."""

    if retained_sources < 0:
        raise ValueError("retained generic source count cannot be negative")
    return CoverageMetric(
        numerator=retained_sources,
        denominator=retained_sources,
        population=retained_sources,
        percentage=100.0 if retained_sources else None,
        exclusions=[],
        not_applicable_evidence=[],
        confidence=1,
        provenance=[CoverageProvenance.DISCOVERY],
        failures=([] if retained_sources else ["repository retained no generic source files"]),
        state=(AnalysisState.DETERMINISTIC if retained_sources else AnalysisState.NOT_ANALYZED),
        detail="Retained non-EVM source files included in deterministic ingestion",
    )


def generic_source_coverage_metrics(
    repository: RepositoryMap,
    scanner_runs: Sequence[ScannerRun],
    *,
    require_scanner_completion: bool,
) -> dict[str, CoverageMetric]:
    """Build non-EVM ingestion and scanner coverage from retained runtime evidence."""

    retained_sources = sum(bool(item.path and item.language) for item in repository.files)
    metrics = {
        "generic_source_files_ingested": generic_source_ingestion_coverage_metric(retained_sources)
    }
    if require_scanner_completion:
        metrics["scanner_completion"] = scanner_completion_coverage_metric(scanner_runs)
    return dict(sorted(metrics.items()))
