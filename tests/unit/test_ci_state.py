from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    AnalysisState,
    AuditRunStatus,
    CoverageExclusion,
    CoverageMetric,
    CoverageProvenance,
    ExecutionEvidenceKind,
    Location,
    LocationValidation,
    RepositoryCodeExecutionState,
    RepositorySuiteFramework,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
    Severity,
)
from mmaudit.orchestration import ci as ci_module
from mmaudit.orchestration.assurance import is_qualifying_real_scanner_run
from mmaudit.orchestration.ci import (
    CIDeterministicEvidence,
    CIJobStatus,
    CIRepositorySuiteEvidence,
    CIRepositorySuiteScannerCoverage,
    CIRepositorySuiteStatus,
    CIToolEvidence,
    build_ci_run_state,
    ci_coverage_evidence,
    ci_finding_evidence,
    ci_invocation_policy_sha256,
    ci_producer_sha256,
    ci_tool_evidence,
    project_ci_findings,
    seal_ci_evidence,
)
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256

NOW = datetime(2026, 7, 30, tzinfo=UTC)
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64


def _source(path: str, sha256: str) -> ManifestFileBinding:
    return ManifestFileBinding(path=path, sha256=sha256, size=100)


def _scanner_run(
    *,
    scanner: str = "semgrep",
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.REAL,
    status: ScannerStatus = ScannerStatus.SUCCESS,
    executable_sha256: str = HASH_B,
    command: list[str] | None = None,
    raw_output_path: str | None = None,
    raw_output_bytes: int = 2,
    process_exit_code: int | None = 0,
    isolation_backend: str = "bubblewrap",
) -> ScannerRun:
    run = ScannerRun(
        scanner=scanner,
        status=status,
        execution_evidence=execution_evidence,
        version="1.2.3",
        executable_sha256=executable_sha256,
        command=command if command is not None else ["/trusted/semgrep", "--json"],
        started_at=NOW,
        finished_at=NOW,
        duration_seconds=0,
        raw_output_path=(
            raw_output_path if raw_output_path is not None else f"{scanner}/stdout.json"
        ),
        raw_output_sha256=HASH_C,
        raw_output_bytes=raw_output_bytes,
        process_exit_code=process_exit_code,
        isolation_backend=isolation_backend,
        isolation_attestation_sha256=HASH_D,
        machine_output_validated=True,
    )
    return ScannerRun.model_validate(
        {
            **run.model_dump(mode="json"),
            "execution_observation_sha256": run.expected_execution_observation_sha256(),
        }
    )


def _resealed_scanner_run(run: ScannerRun, **updates: object) -> ScannerRun:
    candidate = run.model_copy(
        update={
            **updates,
            "execution_observation_sha256": None,
        }
    )
    return ScannerRun.model_validate(
        {
            **candidate.model_dump(mode="json"),
            "execution_observation_sha256": candidate.expected_execution_observation_sha256(),
        }
    )


def _finding(*, severity: Severity = Severity.HIGH) -> ScannerFinding:
    validation = LocationValidation(
        valid=True,
        content_hash=HASH_A,
        errors=[],
        validated_at=NOW,
    )
    return ScannerFinding(
        scanner="semgrep",
        rule_id="synthetic-rule",
        title="Synthetic unsafe condition",
        severity=severity,
        message="A deterministic rule observed the unsafe condition.",
        locations=[
            Location(
                path="src/Vault.sol",
                start_line=10,
                end_line=12,
                symbol="withdraw",
            )
        ],
        fingerprint="scanner-fingerprint",
        metadata={"location_validation": [validation.model_dump(mode="json")]},
    )


def _coverage(
    *,
    numerator: int = 8,
    denominator: int = 10,
    population: int = 10,
) -> CoverageMetric:
    return CoverageMetric(
        numerator=numerator,
        denominator=denominator,
        population=population,
        percentage=round(numerator / denominator * 100, 4),
        exclusions=[],
        not_applicable_evidence=[],
        confidence=1,
        provenance=[CoverageProvenance.STATIC_TOOL],
        failures=[] if numerator == denominator else ["two functions were not covered"],
        state=AnalysisState.DETERMINISTIC,
        detail="Synthetic deterministic coverage.",
    )


def _evidence(
    *,
    source_sha256: str = HASH_A,
    scanner_workspace_sha256: str = HASH_A,
    severity: Severity = Severity.HIGH,
    coverage: CoverageMetric | None = None,
    run: ScannerRun | None = None,
    extra_sources: tuple[ManifestFileBinding, ...] = (),
    producer_sha256: str = HASH_D,
    audit_run_status: AuditRunStatus = AuditRunStatus.COMPLETE,
    include_finding: bool = True,
    finding: ScannerFinding | None = None,
) -> CIDeterministicEvidence:
    sources = (_source("src/Vault.sol", source_sha256), *extra_sources)
    tool = ci_tool_evidence(run or _scanner_run())
    findings = (
        (ci_finding_evidence(finding or _finding(severity=severity), sources),)
        if include_finding and tool.reuse_eligible
        else ()
    )
    return seal_ci_evidence(
        run_id="20260730T000000Z-synthetic",
        generated_at=NOW,
        changed_since="origin/main",
        audit_run_status=audit_run_status,
        scanner_workspace_sha256=scanner_workspace_sha256,
        effective_config_sha256=HASH_B,
        deterministic_policy_sha256=HASH_C,
        producer_sha256=producer_sha256,
        sources=sources,
        tools=(tool,),
        findings=findings,
        coverage=(ci_coverage_evidence("entry_point_coverage", coverage or _coverage()),),
        repository_suite=CIRepositorySuiteEvidence.not_applicable(),
    )


def _suite_tool(
    *,
    selected: int,
    executed: int,
    selection_sha256: str,
) -> CIToolEvidence:
    payload = ci_tool_evidence(_scanner_run(scanner="foundry_fork")).model_dump(mode="json")
    payload.update(
        {
            "invocation_policy_sha256": canonical_sha256({"selection_sha256": selection_sha256}),
            "repository_code_execution": RepositoryCodeExecutionState.ISOLATED.value,
            "repository_suite_selected_test_count": selected,
            "repository_suite_executed_test_count": executed,
            "repository_suite_configuration_sha256": HASH_A,
        }
    )
    identity = {
        "scanner": payload["scanner"],
        "version": payload["version"],
        "executable_sha256": payload["executable_sha256"],
        "invocation_policy_sha256": payload["invocation_policy_sha256"],
        "isolation_backend": payload["isolation_backend"],
        "isolation_attestation_sha256": payload["isolation_attestation_sha256"],
        "repository_suite_configuration_sha256": (payload["repository_suite_configuration_sha256"]),
    }
    payload["tool_identity_sha256"] = canonical_sha256(identity)
    payload["evidence_sha256"] = canonical_sha256(
        {
            **identity,
            "status": payload["status"],
            "execution_evidence": payload["execution_evidence"],
            "command_present": payload["command_present"],
            "raw_output_path_present": payload["raw_output_path_present"],
            "certified_isolation": payload["certified_isolation"],
            "execution_time_order_valid": payload["execution_time_order_valid"],
            "machine_output_validated": payload["machine_output_validated"],
            "raw_output_sha256": payload["raw_output_sha256"],
            "raw_output_bytes": payload["raw_output_bytes"],
            "process_exit_code": payload["process_exit_code"],
            "execution_observation_sha256": payload["execution_observation_sha256"],
            "repository_code_execution": payload["repository_code_execution"],
            "repository_suite_selected_test_count": selected,
            "repository_suite_executed_test_count": executed,
        }
    )
    return CIToolEvidence.model_validate(payload)


def _suite_evidence(
    *,
    selected: int,
    executed: int,
    selected_descriptor_sha256s: tuple[str, ...] | None = None,
) -> CIDeterministicEvidence:
    descriptor_sha256s = selected_descriptor_sha256s or tuple(
        canonical_sha256({"synthetic_repository_test": index}) for index in range(selected)
    )
    assert len(descriptor_sha256s) == selected
    executed_descriptor_sha256s = descriptor_sha256s[:executed]
    selection_sha256 = canonical_sha256({"selected_descriptor_sha256s": sorted(descriptor_sha256s)})
    tool = _suite_tool(
        selected=selected,
        executed=executed,
        selection_sha256=selection_sha256,
    )
    suite = CIRepositorySuiteEvidence(
        status=CIRepositorySuiteStatus.PASSED,
        applicable_frameworks=(RepositorySuiteFramework.FOUNDRY,),
        required_scanners=("foundry_fork",),
        successful_scanners=("foundry_fork",),
        scanner_coverage=(
            CIRepositorySuiteScannerCoverage.sealed(
                scanner="foundry_fork",
                selection_sha256=selection_sha256,
                selected_descriptor_sha256s=descriptor_sha256s,
                executed_descriptor_sha256s=executed_descriptor_sha256s,
                selected_test_count=selected,
                executed_test_count=executed,
            ),
        ),
    )
    return seal_ci_evidence(
        run_id="20260730T000000Z-suite",
        generated_at=NOW,
        changed_since="origin/main",
        audit_run_status=AuditRunStatus.COMPLETE,
        scanner_workspace_sha256=HASH_A,
        effective_config_sha256=HASH_B,
        deterministic_policy_sha256=HASH_C,
        producer_sha256=HASH_D,
        sources=(_source("src/Vault.sol", HASH_A),),
        tools=(tool,),
        findings=(),
        coverage=(ci_coverage_evidence("entry_point_coverage", _coverage()),),
        repository_suite=suite,
    )


def test_ci_state_credits_only_source_and_tool_bound_unchanged_findings() -> None:
    baseline = build_ci_run_state(_evidence())
    current = build_ci_run_state(
        _evidence(),
        baseline=baseline,
        baseline_manifest_sha256=HASH_A,
    )

    assert current.job_status is CIJobStatus.UNCHANGED
    assert current.comparison is not None
    assert current.comparison.whole_run_reuse_eligible
    assert current.comparison.new_finding_ids == ()
    assert len(current.comparison.unchanged_finding_ids) == 1
    assert current.comparison.coverage_regressions == ()


def test_ci_whole_run_equivalence_ignores_only_volatile_tool_timestamps() -> None:
    baseline = build_ci_run_state(_evidence())
    later_run = _scanner_run().model_copy(
        update={
            "started_at": NOW + timedelta(minutes=5),
            "finished_at": NOW + timedelta(minutes=5),
            "execution_observation_sha256": None,
        }
    )
    later_run = ScannerRun.model_validate(
        {
            **later_run.model_dump(mode="json"),
            "execution_observation_sha256": later_run.expected_execution_observation_sha256(),
        }
    )
    current = build_ci_run_state(
        _evidence(run=later_run),
        baseline=baseline,
        baseline_manifest_sha256=HASH_A,
    )

    assert current.comparison is not None
    assert current.comparison.whole_run_reuse_eligible
    assert current.job_status is CIJobStatus.UNCHANGED


def test_ci_whole_run_equivalence_binds_machine_output_hash() -> None:
    baseline = build_ci_run_state(_evidence())
    changed_run = _scanner_run().model_copy(
        update={
            "raw_output_sha256": HASH_A,
            "execution_observation_sha256": None,
        }
    )
    changed_run = ScannerRun.model_validate(
        {
            **changed_run.model_dump(mode="json"),
            "execution_observation_sha256": changed_run.expected_execution_observation_sha256(),
        }
    )
    current = build_ci_run_state(
        _evidence(run=changed_run),
        baseline=baseline,
        baseline_manifest_sha256=HASH_A,
    )

    assert current.comparison is not None
    assert not current.comparison.whole_run_reuse_eligible
    assert "tool_observation_changed" in current.comparison.reuse_rejections


def test_ci_state_never_calls_a_finding_unchanged_after_bound_source_drift() -> None:
    baseline = build_ci_run_state(_evidence())
    current = build_ci_run_state(
        _evidence(source_sha256=HASH_B, scanner_workspace_sha256=HASH_B),
        baseline=baseline,
        baseline_manifest_sha256=HASH_A,
    )

    assert current.job_status is CIJobStatus.NEW_FINDINGS
    assert current.comparison is not None
    assert not current.comparison.whole_run_reuse_eligible
    assert current.comparison.unchanged_finding_ids == ()
    assert len(current.comparison.new_finding_ids) == 1


def test_ci_state_never_calls_finding_unchanged_after_unrelated_source_drift() -> None:
    baseline = build_ci_run_state(
        _evidence(
            extra_sources=(_source("src/Accounting.sol", HASH_C),),
        )
    )
    current = build_ci_run_state(
        _evidence(
            extra_sources=(_source("src/Accounting.sol", HASH_D),),
        ),
        baseline=baseline,
        baseline_manifest_sha256=HASH_A,
    )

    assert current.comparison is not None
    assert current.comparison.unchanged_finding_ids == ()
    assert len(current.comparison.new_finding_ids) == 1
    assert "source_inventory_changed" in current.comparison.reuse_rejections


def test_ci_state_rejects_added_source_and_tool_drift_for_whole_run_reuse() -> None:
    baseline = build_ci_run_state(_evidence())
    current = build_ci_run_state(
        _evidence(
            scanner_workspace_sha256=HASH_B,
            run=_scanner_run(executable_sha256=HASH_A),
            extra_sources=(_source("src/New.sol", HASH_C),),
        ),
        baseline=baseline,
        baseline_manifest_sha256=HASH_A,
    )

    assert current.comparison is not None
    assert not current.comparison.whole_run_reuse_eligible
    assert {
        "source_inventory_changed",
        "scanner_workspace_changed",
        "tool_identity_changed",
    } <= set(current.comparison.reuse_rejections)


@pytest.mark.parametrize(
    ("metric", "reason"),
    [
        (_coverage(numerator=7), "coverage_percentage_decreased"),
        (_coverage(numerator=7, denominator=9, population=9), "coverage_population_decreased"),
    ],
)
def test_ci_state_reports_coverage_regressions(
    metric: CoverageMetric,
    reason: str,
) -> None:
    baseline = build_ci_run_state(_evidence())
    current = build_ci_run_state(
        _evidence(coverage=metric),
        baseline=baseline,
        baseline_manifest_sha256=HASH_A,
    )

    assert current.job_status is CIJobStatus.COVERAGE_REGRESSION
    assert current.comparison is not None
    assert len(current.comparison.coverage_regressions) == 1
    assert reason in current.comparison.coverage_regressions[0].reasons
    assert not current.comparison.whole_run_reuse_eligible
    assert "coverage_evidence_changed" in current.comparison.reuse_rejections


def test_ci_state_reports_repository_suite_test_count_regression_as_coverage() -> None:
    baseline = build_ci_run_state(_suite_evidence(selected=10, executed=10))
    current = build_ci_run_state(
        _suite_evidence(selected=8, executed=8),
        baseline=baseline,
        baseline_manifest_sha256=HASH_A,
    )

    assert current.job_status is CIJobStatus.COVERAGE_REGRESSION
    assert current.analysis_failures == ()
    assert current.comparison is not None
    assert len(current.comparison.coverage_regressions) == 1
    regression = current.comparison.coverage_regressions[0]
    assert regression.metric_id == "repository_suite.foundry_fork.execution_coverage"
    assert {
        "coverage_population_decreased",
        "coverage_denominator_decreased",
        "coverage_numerator_decreased",
    } <= set(regression.reasons)
    assert not current.comparison.whole_run_reuse_eligible


def test_ci_state_reports_same_count_repository_suite_selection_replacement() -> None:
    baseline_descriptors = tuple(
        canonical_sha256({"synthetic_repository_test": index}) for index in range(10)
    )
    replacement_descriptors = (*baseline_descriptors[:-1], HASH_D)
    baseline = build_ci_run_state(
        _suite_evidence(
            selected=10,
            executed=10,
            selected_descriptor_sha256s=baseline_descriptors,
        )
    )
    current = build_ci_run_state(
        _suite_evidence(
            selected=10,
            executed=10,
            selected_descriptor_sha256s=replacement_descriptors,
        ),
        baseline=baseline,
        baseline_manifest_sha256=HASH_A,
    )

    assert current.job_status is CIJobStatus.COVERAGE_REGRESSION
    assert current.comparison is not None
    regression = current.comparison.coverage_regressions[0]
    assert regression.metric_id == "repository_suite.foundry_fork.execution_coverage"
    assert {
        "repository_suite_selected_test_removed",
        "repository_suite_executed_test_removed",
    } <= set(regression.reasons)


def test_ci_state_never_reuses_mock_or_failed_tool_evidence() -> None:
    for run in (
        _scanner_run(execution_evidence=ExecutionEvidenceKind.MOCK),
        _scanner_run(status=ScannerStatus.FAILED),
    ):
        state = build_ci_run_state(_evidence(run=run))
        assert state.job_status is CIJobStatus.ANALYSIS_FAILED
        assert not state.evidence.tools[0].reuse_eligible


@pytest.mark.parametrize(
    "run",
    [
        _scanner_run(command=[]),
        _resealed_scanner_run(_scanner_run(), raw_output_path=None),
        _scanner_run(raw_output_bytes=0),
        _scanner_run(isolation_backend="uncertified-container"),
        _scanner_run(process_exit_code=None),
    ],
)
def test_ci_tool_reuse_requires_complete_qualifying_real_scanner_evidence(
    run: ScannerRun,
) -> None:
    tool = ci_tool_evidence(run)

    assert not tool.reuse_eligible
    assert tool.command_present is bool(run.command)
    assert tool.raw_output_path_present is bool(run.raw_output_path)
    assert tool.certified_isolation is (run.isolation_backend == "bubblewrap")


def test_ci_tool_reuse_exactly_honors_canonical_accepted_finding_exit() -> None:
    run = _scanner_run(process_exit_code=1)

    assert is_qualifying_real_scanner_run(run)
    assert ci_tool_evidence(run).reuse_eligible


def test_ci_invocation_policy_normalizes_ephemeral_paths_and_loopback_ports() -> None:
    first = _scanner_run(
        command=[
            "/opt/trusted/semgrep",
            "scan",
            "--root=/private/tmp/run-a/workspace",
            "--output=/tmp/output-a/runs/first/private/scanner-output/semgrep/result.json",
            "--rpc-url",
            "http://127.0.0.1:41001",
            "--json",
        ],
        raw_output_path="run-a/semgrep.json",
    )
    second = _scanner_run(
        command=[
            "/another/trusted/semgrep",
            "scan",
            "--root=/tmp/run-b/workspace",
            "--output=/private/tmp/output-b/runs/second/private/scanner-output/semgrep/result.json",
            "--rpc-url",
            "http://localhost:51001",
            "--json",
        ],
        raw_output_path="run-b/semgrep.json",
    )

    assert ci_invocation_policy_sha256(first) == ci_invocation_policy_sha256(second)
    baseline = build_ci_run_state(_evidence(run=first))
    current = build_ci_run_state(
        _evidence(run=second),
        baseline=baseline,
        baseline_manifest_sha256=HASH_A,
    )
    assert current.job_status is CIJobStatus.UNCHANGED
    assert current.comparison is not None
    assert current.comparison.whole_run_reuse_eligible


def test_ci_invocation_policy_preserves_unproven_absolute_semantic_paths() -> None:
    first = _scanner_run(
        command=[
            "/opt/trusted/semgrep",
            "scan",
            "--config",
            "/alpha/policy/rules.yml",
            "--json",
        ]
    )
    second = _scanner_run(
        command=[
            "/opt/trusted/semgrep",
            "scan",
            "--config",
            "/beta/policy/rules.yml",
            "--json",
        ]
    )

    assert ci_invocation_policy_sha256(first) != ci_invocation_policy_sha256(second)
    baseline = build_ci_run_state(_evidence(run=first))
    current = build_ci_run_state(
        _evidence(run=second),
        baseline=baseline,
        baseline_manifest_sha256=HASH_A,
    )
    assert current.comparison is not None
    assert "tool_invocation_policy_changed" in current.comparison.reuse_rejections
    assert current.comparison.unchanged_finding_ids == ()


@pytest.mark.parametrize(
    ("first_path", "second_path"),
    [
        ("/alpha/.mmaudit/policy/rules.yml", "/beta/.mmaudit/policy/rules.yml"),
        ("/alpha/runs/private/policy.json", "/beta/runs/private/policy.json"),
        ("/alpha/src/mmaudit/policy.json", "/beta/src/mmaudit/policy.json"),
        ("/alpha/tmp/workspace/policy.json", "/beta/tmp/workspace/policy.json"),
        ("/alpha/_temp/workspace/policy.json", "/beta/_temp/workspace/policy.json"),
        ("/alpha/runs/workspace/policy.json", "/beta/runs/workspace/policy.json"),
    ],
)
def test_ci_invocation_policy_does_not_treat_semantic_names_as_ephemeral(
    first_path: str,
    second_path: str,
) -> None:
    first = _scanner_run(command=["/opt/trusted/semgrep", "scan", "--config", first_path])
    second = _scanner_run(command=["/opt/trusted/semgrep", "scan", "--config", second_path])

    assert ci_invocation_policy_sha256(first) != ci_invocation_policy_sha256(second)


def test_ci_invocation_policy_distinguishes_default_from_explicit_loopback_port() -> None:
    implicit = _scanner_run(
        command=["/opt/trusted/scanner", "--rpc-url", "http://localhost/config"]
    )
    explicit = _scanner_run(
        command=["/opt/trusted/scanner", "--rpc-url", "http://localhost:51001/config"]
    )

    assert ci_invocation_policy_sha256(implicit) != ci_invocation_policy_sha256(explicit)


def test_ci_command_scope_drift_denies_reuse_and_unchanged_finding_credit() -> None:
    baseline = build_ci_run_state(
        _evidence(
            run=_scanner_run(
                command=["/trusted/semgrep", "scan", "--config", "rules-a.yml", "--json"]
            )
        )
    )
    current = build_ci_run_state(
        _evidence(
            run=_scanner_run(
                command=["/trusted/semgrep", "scan", "--config", "rules-b.yml", "--json"]
            )
        ),
        baseline=baseline,
        baseline_manifest_sha256=HASH_A,
    )

    assert current.job_status is CIJobStatus.NEW_FINDINGS
    assert current.comparison is not None
    assert not current.comparison.whole_run_reuse_eligible
    assert "tool_invocation_policy_changed" in current.comparison.reuse_rejections
    assert current.comparison.unchanged_finding_ids == ()
    assert len(current.comparison.new_finding_ids) == 1


def test_ci_state_self_hash_rejects_tampering() -> None:
    state = build_ci_run_state(_evidence())
    payload = state.model_dump(mode="json")
    payload["evidence"]["changed_since"] = "HEAD"

    with pytest.raises(ValidationError, match="self-hash"):
        type(state).model_validate(payload)


def test_ci_state_does_not_credit_unchanged_after_producer_drift() -> None:
    baseline = build_ci_run_state(_evidence())
    current = build_ci_run_state(
        _evidence(producer_sha256=HASH_A),
        baseline=baseline,
        baseline_manifest_sha256=HASH_A,
    )

    assert current.comparison is not None
    assert "producer_changed" in current.comparison.reuse_rejections
    assert current.comparison.unchanged_finding_ids == ()
    assert len(current.comparison.new_finding_ids) == 1


def test_ci_state_treats_incomplete_audit_as_analysis_failure() -> None:
    state = build_ci_run_state(
        _evidence(audit_run_status=AuditRunStatus.INCOMPLETE),
    )

    assert state.job_status is CIJobStatus.ANALYSIS_FAILED
    assert "audit_run_status:INCOMPLETE" in state.analysis_failures


def test_ci_state_never_marks_incomplete_audit_whole_run_reusable() -> None:
    baseline = build_ci_run_state(_evidence())
    current = build_ci_run_state(
        _evidence(audit_run_status=AuditRunStatus.INCOMPLETE),
        baseline=baseline,
        baseline_manifest_sha256=HASH_A,
    )

    assert current.comparison is not None
    assert not current.comparison.whole_run_reuse_eligible
    assert {
        "analysis_failures_present",
        "current_audit_not_eligible",
    } <= set(current.comparison.reuse_rejections)


def test_ci_state_reports_clean_when_every_baseline_finding_resolved() -> None:
    baseline = build_ci_run_state(_evidence())
    current = build_ci_run_state(
        _evidence(include_finding=False),
        baseline=baseline,
        baseline_manifest_sha256=HASH_A,
    )

    assert current.job_status is CIJobStatus.CLEAN
    assert current.comparison is not None
    assert current.comparison.new_finding_ids == ()
    assert current.comparison.unchanged_finding_ids == ()
    assert len(current.comparison.resolved_finding_ids) == 1


def test_ci_finding_rejects_duplicate_locations() -> None:
    finding = _finding()
    duplicate = finding.model_copy(
        update={
            "locations": [*finding.locations, *finding.locations],
            "metadata": {
                **finding.metadata,
                "location_validation": [
                    *finding.metadata["location_validation"],
                    *finding.metadata["location_validation"],
                ],
            },
        }
    )

    with pytest.raises(ValidationError, match="locations must be unique"):
        ci_finding_evidence(duplicate, (_source("src/Vault.sol", HASH_A),))


def test_ci_finding_normalizes_volatile_validation_timestamp() -> None:
    original = _finding()
    later = original.model_copy(
        update={
            "metadata": {
                **original.metadata,
                "location_validation": [
                    LocationValidation(
                        valid=True,
                        content_hash=HASH_A,
                        errors=[],
                        validated_at=NOW + timedelta(minutes=5),
                    ).model_dump(mode="json")
                ],
            }
        }
    )

    first = ci_finding_evidence(original, (_source("src/Vault.sol", HASH_A),))
    second = ci_finding_evidence(later, (_source("src/Vault.sol", HASH_A),))

    assert first == second
    assert first.location_validations[0].validated_at is None
    assert first.locations[0].content_hash == HASH_A


@pytest.mark.parametrize(
    "finding",
    [
        _finding().model_copy(update={"metadata": {}}),
        _finding().model_copy(
            update={
                "metadata": {
                    "location_validation": [
                        LocationValidation(
                            valid=False,
                            content_hash=HASH_A,
                            errors=["synthetic invalid range"],
                            validated_at=NOW,
                        ).model_dump(mode="json")
                    ]
                }
            }
        ),
        _finding().model_copy(
            update={
                "metadata": {
                    "location_validation": [
                        LocationValidation(
                            valid=True,
                            content_hash=None,
                            errors=[],
                            validated_at=NOW,
                        ).model_dump(mode="json")
                    ]
                }
            }
        ),
        _finding().model_copy(
            update={
                "locations": [
                    Location(
                        path="src/Vault.sol",
                        start_line=10,
                        end_line=12,
                        symbol="withdraw",
                        content_hash=HASH_B,
                    )
                ]
            }
        ),
    ],
)
def test_ci_finding_requires_valid_aligned_host_location_evidence(
    finding: ScannerFinding,
) -> None:
    with pytest.raises(ValueError, match=r"host location|host location evidence"):
        ci_finding_evidence(finding, (_source("src/Vault.sol", HASH_A),))


def test_ci_finding_projection_rejects_cross_scanner_attribution() -> None:
    mismatched = _finding().model_copy(update={"scanner": "other-scanner"})
    run = _scanner_run().model_copy(update={"findings": [mismatched]})

    findings, failures = project_ci_findings(
        (run,),
        (_source("src/Vault.sol", HASH_A),),
        reusable_scanners={"semgrep"},
    )

    assert findings == ()
    assert len(failures) == 1
    assert failures[0].endswith(":scanner_attribution_mismatch")


def test_ci_finding_projection_preserves_validation_failure_as_analysis_failure() -> None:
    invalid = _finding().model_copy(update={"metadata": {}})
    run = _scanner_run().model_copy(update={"findings": [invalid]})
    findings, failures = project_ci_findings(
        (run,),
        (_source("src/Vault.sol", HASH_A),),
        reusable_scanners={"semgrep"},
    )
    evidence = seal_ci_evidence(
        run_id="20260730T000000Z-invalid-finding",
        generated_at=NOW,
        changed_since="main",
        audit_run_status=AuditRunStatus.COMPLETE,
        scanner_workspace_sha256=HASH_A,
        effective_config_sha256=HASH_B,
        deterministic_policy_sha256=HASH_C,
        producer_sha256=HASH_D,
        sources=(_source("src/Vault.sol", HASH_A),),
        tools=(ci_tool_evidence(_scanner_run()),),
        findings=findings,
        finding_validation_failures=failures,
        coverage=(ci_coverage_evidence("entry_point_coverage", _coverage()),),
        repository_suite=CIRepositorySuiteEvidence.not_applicable(),
    )

    state = build_ci_run_state(evidence)

    assert state.job_status is CIJobStatus.ANALYSIS_FAILED
    assert state.analysis_failures == failures


def test_ci_evidence_rejects_unsafe_metadata() -> None:
    base = _evidence()
    payload = base.model_dump(mode="python")
    payload["generated_at"] = NOW.replace(tzinfo=None)

    with pytest.raises(ValidationError, match="timezone"):
        type(base).model_validate(payload)

    payload = base.model_dump(mode="python")
    payload["changed_since"] = "main\nforged"
    with pytest.raises(ValidationError, match="printable"):
        type(base).model_validate(payload)


def test_ci_repository_suite_pass_requires_matching_isolated_tool_evidence() -> None:
    suite = CIRepositorySuiteEvidence(
        status=CIRepositorySuiteStatus.PASSED,
        applicable_frameworks=(RepositorySuiteFramework.FOUNDRY,),
        required_scanners=("foundry_fork",),
        successful_scanners=("foundry_fork",),
        scanner_coverage=(
            CIRepositorySuiteScannerCoverage.sealed(
                scanner="foundry_fork",
                selection_sha256=HASH_B,
                selected_descriptor_sha256s=(HASH_A,),
                executed_descriptor_sha256s=(HASH_A,),
                selected_test_count=1,
                executed_test_count=1,
            ),
        ),
    )

    with pytest.raises(ValidationError, match=r"repository-suite (?:coverage|success)"):
        seal_ci_evidence(
            run_id="20260730T000000Z-suite",
            generated_at=NOW,
            changed_since="main",
            audit_run_status=AuditRunStatus.COMPLETE,
            scanner_workspace_sha256=HASH_A,
            effective_config_sha256=HASH_B,
            deterministic_policy_sha256=HASH_C,
            producer_sha256=HASH_D,
            sources=(_source("src/Vault.sol", HASH_A),),
            tools=(ci_tool_evidence(_scanner_run(scanner="foundry_fork")),),
            findings=(),
            coverage=(),
            repository_suite=suite,
        )


@pytest.mark.skipif(
    not hasattr(os, "mkfifo") or not isinstance(getattr(os, "O_NONBLOCK", None), int),
    reason="FIFO and nonblocking descriptor support are required",
)
def test_ci_bundle_member_open_is_nonblocking_across_fifo_substitution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    member = tmp_path / "ci-state.json"
    member.write_text("{}\n", encoding="utf-8")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    root_descriptor = os.open(tmp_path, directory_flags)
    original_open = os.open
    substituted = False

    def swap_before_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal substituted
        if path == member.name and dir_fd == root_descriptor and not substituted:
            assert flags & os.O_NONBLOCK
            substituted = True
            member.unlink()
            os.mkfifo(member)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(ci_module.os, "open", swap_before_open)
    try:
        with pytest.raises(ValueError, match="changed while opening"):
            ci_module._read_ci_bundle_member_at(
                root_descriptor,
                member.name,
                max_bytes=1_000,
            )
    finally:
        os.close(root_descriptor)
    assert substituted


@pytest.mark.parametrize("flag_name", ["O_NOFOLLOW", "O_NONBLOCK"])
def test_ci_stable_file_reader_fails_closed_without_required_open_flag(
    flag_name: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "state.json"
    source.write_text("{}\n", encoding="utf-8")
    monkeypatch.delattr(ci_module.os, flag_name, raising=False)

    with pytest.raises(
        ValueError,
        match="descriptor-relative no-follow file access is unavailable",
    ):
        ci_module._read_unique_regular_file(
            source,
            max_bytes=1_000,
            label="synthetic CI state",
        )


def test_ci_bundle_inventory_rejects_after_constant_number_of_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    names = [*ci_module._CI_BASELINE_BUNDLE_FILES, "unexpected.json", "never-consumed"]

    class BoundedEntries:
        def __init__(self) -> None:
            self.index = 0

        def __enter__(self) -> BoundedEntries:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def __iter__(self) -> BoundedEntries:
            return self

        def __next__(self) -> object:
            if self.index >= 4:
                raise AssertionError("CI inventory consumed more than four entries")
            name = names[self.index]
            self.index += 1
            return type("SyntheticDirectoryEntry", (), {"name": name})()

    entries = BoundedEntries()
    monkeypatch.setattr(ci_module.os, "scandir", lambda _descriptor: entries)

    with pytest.raises(ValueError, match="unexpected or unsafe member inventory"):
        ci_module._validate_ci_bundle_inventory_at(-1)

    assert entries.index == 4


def test_ci_producer_hash_binds_non_python_package_resources(tmp_path: Path) -> None:
    package_root = tmp_path / "mmaudit"
    package_root.mkdir()
    (package_root / "__init__.py").write_text("", encoding="utf-8")
    rules = package_root / "security.yml"
    rules.write_text("rules: []\n", encoding="utf-8")

    before = ci_producer_sha256(package_root)
    rules.write_text("rules:\n  - id: changed\n", encoding="utf-8")
    after = ci_producer_sha256(package_root)

    assert before != after


def test_ci_state_rejects_resealed_erasure_of_derived_analysis_failures() -> None:
    state = build_ci_run_state(
        _evidence(run=_scanner_run(execution_evidence=ExecutionEvidenceKind.MOCK)),
    )
    payload = state.model_dump(mode="json")
    payload["analysis_failures"] = []
    payload["job_status"] = CIJobStatus.NO_BASELINE.value
    payload["state_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "state_sha256"}
    )

    with pytest.raises(ValidationError, match="analysis failures differ"):
        type(state).model_validate(payload)


def test_ci_evidence_rejects_finding_binding_from_another_source_version() -> None:
    current_source = _source("src/Vault.sol", HASH_A)
    stale_finding = ci_finding_evidence(
        _finding(),
        (_source("src/Vault.sol", HASH_B),),
    )

    with pytest.raises(ValidationError, match="enclosing source inventory"):
        seal_ci_evidence(
            run_id="20260730T000000Z-stale-source",
            generated_at=NOW,
            changed_since="main",
            audit_run_status=AuditRunStatus.COMPLETE,
            scanner_workspace_sha256=HASH_A,
            effective_config_sha256=HASH_B,
            deterministic_policy_sha256=HASH_C,
            producer_sha256=HASH_D,
            sources=(current_source,),
            tools=(ci_tool_evidence(_scanner_run()),),
            findings=(stale_finding,),
            coverage=(),
            repository_suite=CIRepositorySuiteEvidence.not_applicable(),
        )


def test_ci_state_does_not_credit_changed_scanner_finding_payload() -> None:
    baseline = build_ci_run_state(_evidence())
    changed = _finding().model_copy(update={"title": "Changed deterministic diagnostic"})
    current = build_ci_run_state(
        _evidence(finding=changed),
        baseline=baseline,
        baseline_manifest_sha256=HASH_A,
    )

    assert current.comparison is not None
    assert current.comparison.unchanged_finding_ids == ()
    assert len(current.comparison.new_finding_ids) == 1
    assert not current.comparison.whole_run_reuse_eligible
    assert "finding_evidence_changed" in current.comparison.reuse_rejections


def test_ci_coverage_detects_replaced_exclusion_and_confidence_decline() -> None:
    prior = CoverageMetric(
        numerator=9,
        denominator=9,
        population=10,
        percentage=100,
        exclusions=[
            CoverageExclusion(
                subject="src/Generated.sol",
                reason="Generated source",
                provenance=CoverageProvenance.STATIC_TOOL,
            )
        ],
        not_applicable_evidence=[],
        confidence=1,
        provenance=[CoverageProvenance.STATIC_TOOL],
        failures=[],
        state=AnalysisState.DETERMINISTIC,
        detail="Synthetic deterministic coverage.",
    )
    current_metric = prior.model_copy(
        update={
            "exclusions": [
                CoverageExclusion(
                    subject="src/Critical.sol",
                    reason="Incorrectly excluded",
                    provenance=CoverageProvenance.STATIC_TOOL,
                )
            ],
            "confidence": 0.5,
        }
    )
    baseline = build_ci_run_state(_evidence(coverage=prior))
    current = build_ci_run_state(
        _evidence(coverage=current_metric),
        baseline=baseline,
        baseline_manifest_sha256=HASH_A,
    )

    assert current.comparison is not None
    reasons = set(current.comparison.coverage_regressions[0].reasons)
    assert "coverage_new_exclusion_subject" in reasons
    assert "coverage_confidence_decreased" in reasons


def test_ci_producer_hash_rejects_sensitive_paths(tmp_path: Path) -> None:
    package_root = tmp_path / "mmaudit"
    package_root.mkdir()
    (package_root / "__init__.py").write_text("", encoding="utf-8")
    (package_root / ".env").write_text("SYNTHETIC_CANARY=value\n", encoding="utf-8")

    with pytest.raises(ValueError, match="sensitive paths"):
        ci_producer_sha256(package_root)
