from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mmaudit.models.scheduler import (
    SCHEDULER_ANALYSIS_INPUT_LABELS,
    SchedulerAnalysisInputDescriptor,
    SchedulerAnalysisInputInventory,
)
from mmaudit.models.schemas import (
    CompilationStatus,
    FormalToolRun,
    FormalToolStatus,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    ScannerRun,
    ScannerStatus,
    SolidityCompilationResult,
    SolidityProjectType,
)
from mmaudit.orchestration.scheduler_runtime import scheduler_analysis_semantic_projection


def _engine_inputs(
    run_root: Path,
) -> tuple[
    ScannerRun,
    SolidityCompilationResult,
    InvariantExecutionResult,
    FormalToolRun,
]:
    started = datetime(2026, 1, 1, tzinfo=UTC)
    root = str(run_root)
    return (
        ScannerRun(
            scanner="slither",
            status=ScannerStatus.SUCCESS,
            version="0.11.3",
            executable_sha256="1" * 64,
            command=[f"{root}/bin/slither", "--json", f"{root}/out.json"],
            started_at=started,
            finished_at=started + timedelta(seconds=2),
            duration_seconds=2,
            raw_output_path=f"{root}/out.json",
            raw_output_sha256="2" * 64,
            raw_output_bytes=128,
            process_exit_code=0,
            machine_output_validated=True,
        ),
        SolidityCompilationResult(
            status=CompilationStatus.SUCCESS,
            framework=SolidityProjectType.FOUNDRY,
            project_root=f"{root}/source",
            executable_sha256="3" * 64,
            command=[f"{root}/bin/forge", "build", "--out", f"{root}/out"],
            compiler_versions=["0.8.30"],
            contracts_compiled=["SafeVault"],
            artifacts=[f"{root}/out/SafeVault.json"],
            source_maps_available=True,
            ast_available=True,
            duration_seconds=3,
            stdout_path=f"{root}/compile.stdout",
            stderr_path=f"{root}/compile.stderr",
        ),
        InvariantExecutionResult(
            invariant_id="accounting-conservation",
            harness_name="AccountingConservationInvariant",
            harness_spec_sha256="4" * 64,
            status=InvariantExecutionStatus.PASSED,
            executable_sha256="5" * 64,
            source_sha256="6" * 64,
            compiler_version="0.8.30",
            compiler_sha256="7" * 64,
            command=[f"{root}/bin/forge", "test", "--root", root],
            runs=256,
            depth=64,
            seed=7,
            duration_seconds=4,
            source_path=f"{root}/Invariant.t.sol",
            stdout_path=f"{root}/invariant.stdout",
            stderr_path=f"{root}/invariant.stderr",
        ),
        FormalToolRun(
            tool="halmos",
            version="0.3.3",
            executable_sha256="8" * 64,
            status=FormalToolStatus.SUCCESS,
            command=[f"{root}/bin/halmos", "--root", root],
            duration_seconds=5,
            coverage={"properties": 1},
            specification_artifacts=["private/formal/spec.json"],
            stdout_path=f"{root}/formal.stdout",
            stderr_path=f"{root}/formal.stderr",
            result_path=f"{root}/formal.json",
            process_exit_code=0,
            stdout_sha256="9" * 64,
            stderr_sha256="a" * 64,
            result_sha256="b" * 64,
            stdout_bytes=32,
            stderr_bytes=0,
            result_bytes=64,
            machine_output_validated=True,
        ),
    )


def _inventory(values: tuple[object, ...]) -> SchedulerAnalysisInputInventory:
    engine_labels = ("scanner_runs", "compilations", "invariant_executions", "formal_runs")
    projections = dict(zip(engine_labels, values, strict=True))
    return SchedulerAnalysisInputInventory.build(
        SchedulerAnalysisInputDescriptor.build(
            label=label,
            type_name="SemanticProjection",
            value=projections.get(label, {"stable": label}),
        )
        for label in SCHEDULER_ANALYSIS_INPUT_LABELS
    )


def test_analysis_input_binding_ignores_only_incidental_engine_runtime_identity(
    tmp_path: Path,
) -> None:
    audited_root = tmp_path / "repository"
    run_a = tmp_path / "run-a"
    run_b = tmp_path / "run-b"
    audited_root.mkdir()
    run_a.mkdir()
    run_b.mkdir()
    scanner, compilation, invariant, formal = _engine_inputs(run_a)
    later = datetime(2026, 2, 1, tzinfo=UTC)
    equivalent = (
        scanner.model_copy(
            update={
                "command": [
                    f"{run_b}/bin/slither",
                    "--json",
                    f"{run_b}/out.json",
                ],
                "started_at": later,
                "finished_at": later + timedelta(seconds=20),
                "duration_seconds": 20,
                "raw_output_path": f"{run_b}/out.json",
            }
        ),
        compilation.model_copy(
            update={
                "project_root": f"{run_b}/source",
                "command": [
                    f"{run_b}/bin/forge",
                    "build",
                    "--out",
                    f"{run_b}/out",
                ],
                "artifacts": [f"{run_b}/out/SafeVault.json"],
                "duration_seconds": 30,
                "stdout_path": f"{run_b}/compile.stdout",
                "stderr_path": f"{run_b}/compile.stderr",
            }
        ),
        invariant.model_copy(
            update={
                "command": [
                    f"{run_b}/bin/forge",
                    "test",
                    "--root",
                    str(run_b),
                ],
                "duration_seconds": 40,
                "source_path": f"{run_b}/Invariant.t.sol",
                "stdout_path": f"{run_b}/invariant.stdout",
                "stderr_path": f"{run_b}/invariant.stderr",
            }
        ),
        formal.model_copy(
            update={
                "command": [
                    f"{run_b}/bin/halmos",
                    "--root",
                    str(run_b),
                ],
                "duration_seconds": 50,
                "specification_artifacts": ["private/formal/spec.json"],
                "stdout_path": f"{run_b}/formal.stdout",
                "stderr_path": f"{run_b}/formal.stderr",
                "result_path": f"{run_b}/formal.json",
            }
        ),
    )

    original_projections = tuple(
        scheduler_analysis_semantic_projection(
            item,
            audited_repository_root=audited_root,
            disposable_roots=(run_a,),
        )
        for item in (scanner, compilation, invariant, formal)
    )
    equivalent_projections = tuple(
        scheduler_analysis_semantic_projection(
            item,
            audited_repository_root=audited_root,
            disposable_roots=(run_b,),
        )
        for item in equivalent
    )

    assert equivalent_projections == original_projections
    assert (
        _inventory(equivalent_projections).analysis_input_sha256
        == _inventory(original_projections).analysis_input_sha256
    )


def test_analysis_input_binding_retains_engine_identity_status_and_result(tmp_path: Path) -> None:
    audited_root = tmp_path / "repository"
    run_root = tmp_path / "run"
    audited_root.mkdir()
    run_root.mkdir()
    scanner, compilation, invariant, formal = _engine_inputs(run_root)

    def project(item: object) -> object:
        return scheduler_analysis_semantic_projection(
            item,
            audited_repository_root=audited_root,
            disposable_roots=(run_root,),
        )

    baseline = tuple(project(item) for item in (scanner, compilation, invariant, formal))
    changed_identity = tuple(
        project(item)
        for item in (
            scanner.model_copy(update={"executable_sha256": "c" * 64}),
            compilation,
            invariant,
            formal,
        )
    )
    changed_status = tuple(
        project(item)
        for item in (
            scanner,
            compilation.model_copy(update={"status": CompilationStatus.FAILED}),
            invariant,
            formal,
        )
    )
    changed_result = tuple(
        project(item)
        for item in (
            scanner,
            compilation,
            invariant,
            formal.model_copy(update={"result_sha256": "d" * 64}),
        )
    )

    baseline_hash = _inventory(baseline).analysis_input_sha256
    assert _inventory(changed_identity).analysis_input_sha256 != baseline_hash
    assert _inventory(changed_status).analysis_input_sha256 != baseline_hash
    assert _inventory(changed_result).analysis_input_sha256 != baseline_hash


def test_analysis_input_binding_does_not_normalize_unbound_rule_or_source_paths(
    tmp_path: Path,
) -> None:
    audited_root = tmp_path / "repository"
    run_root = tmp_path / "run"
    audited_root.mkdir()
    run_root.mkdir()
    scanner, compilation, _invariant, _formal = _engine_inputs(run_root)

    def project(item: object) -> object:
        return scheduler_analysis_semantic_projection(
            item,
            audited_repository_root=audited_root,
            disposable_roots=(run_root,),
        )

    first_rule = scanner.model_copy(
        update={
            "command": [
                f"{run_root}/bin/slither",
                "--config-file",
                "/opt/trusted-rules/access-control.json",
            ]
        }
    )
    second_rule = scanner.model_copy(
        update={
            "command": [
                f"{run_root}/bin/slither",
                "--config-file",
                "/opt/trusted-rules/accounting.json",
            ]
        }
    )
    first_source = compilation.model_copy(
        update={"errors": ["/opt/targets/Alpha.sol:10: compilation failed"]}
    )
    second_source = compilation.model_copy(
        update={"errors": ["/opt/targets/Beta.sol:10: compilation failed"]}
    )

    assert project(first_rule) != project(second_rule)
    assert project(first_source) != project(second_source)


def test_analysis_projection_accepts_only_exact_excluded_in_repository_disposable_root(
    tmp_path: Path,
) -> None:
    audited_root = tmp_path / "repository"
    exclusion_root = audited_root / ".mmaudit"
    disposable_root = exclusion_root / "runs" / "run-1" / "private"
    arbitrary_root = audited_root / "build" / "private"
    discovered_exclusion = audited_root / "generated"
    disposable_root.mkdir(parents=True)
    arbitrary_root.mkdir(parents=True)
    discovered_exclusion.mkdir()
    scanner, _compilation, _invariant, _formal = _engine_inputs(disposable_root)

    projection = scheduler_analysis_semantic_projection(
        scanner,
        audited_repository_root=audited_root,
        disposable_roots=(disposable_root,),
        audited_exclusion_roots=(exclusion_root,),
        audited_source_paths=("src/Vault.sol",),
    )
    assert projection["command"][-1] == "<disposable-root>/out.json"  # type: ignore[index]

    with pytest.raises(ValueError, match="lacks exact exclusion authority"):
        scheduler_analysis_semantic_projection(
            scanner,
            audited_repository_root=audited_root,
            disposable_roots=(arbitrary_root,),
            audited_exclusion_roots=(exclusion_root,),
            audited_source_paths=("src/Vault.sol",),
        )
    with pytest.raises(ValueError, match="overlaps audited source evidence"):
        scheduler_analysis_semantic_projection(
            scanner,
            audited_repository_root=audited_root,
            disposable_roots=(discovered_exclusion,),
            audited_exclusion_roots=(discovered_exclusion,),
            audited_source_paths=("generated/Contract.sol",),
        )
