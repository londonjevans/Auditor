"""Cross-artifact integrity regressions for execution-originated candidates."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.constants import ANALYSIS_ROLES
from mmaudit.models.schemas import (
    AuditReport,
    AuditRunStatus,
    CandidateFinding,
    CandidateFindingArtifact,
    CandidateOriginKind,
    CandidateReproductionResolution,
    Evidence,
    ExecutionOriginDispositionKind,
    ExecutionOriginRejectionCategory,
    Finding,
    FindingStatus,
    FoundryInvariantHarnessSpec,
    InvariantExecutionCandidateProvenance,
    InvariantExecutionOriginDisposition,
    InvariantExecutionOriginDispositionArtifact,
    InvariantExecutionResult,
    InvariantSuite,
    Location,
    LocationValidation,
    PropertyCorpus,
    RepositoryMap,
    ReproductionResolutionKind,
    ReproductionResult,
    ReproductionState,
    Severity,
    VerificationTest,
)
from mmaudit.orchestration.manifest import _validate_report_artifact_consistency
from mmaudit.orchestration.replay import _ReplayArtifacts
from mmaudit.reporting.json_report import write_json
from tests.unit import test_run_status as run_status_fixtures
from tests.unit.test_execution_candidate_schema import (
    _execution_candidate,
    _execution_finding,
    _provenance,
)
from tests.unit.test_execution_candidates import _build, _inputs


def _model_candidate() -> CandidateFinding:
    return CandidateFinding(
        candidate_id="candidate-model-review",
        title="Model-reviewed concern",
        severity=Severity.MEDIUM,
        confidence=0.7,
        summary="A model identified a concern for independent validation.",
        impact="The concern may affect expected behavior.",
        preconditions=["The affected path is reachable."],
        locations=[
            Location(
                path="src/SyntheticVault.sol",
                start_line=20,
                end_line=22,
                content_hash="c" * 64,
            )
        ],
        attack_path=["Review the affected path."],
        evidence=[
            Evidence(
                type="model",
                source="specialist",
                description="Structured model review record.",
            )
        ],
        false_positive_conditions=["The reported path is unreachable."],
        recommendation="Validate and remediate the affected path.",
        verification_test=VerificationTest(description="Run a safe local regression test."),
        role="business_logic",
        model_family="author/model-family",
    )


def _legacy_model_payload() -> dict[str, Any]:
    payload = _model_candidate().model_dump(mode="json")
    payload.pop("origin_kind")
    payload.pop("execution_provenance")
    return payload


def _reseal_provenance(
    provenance: InvariantExecutionCandidateProvenance,
    **updates: object,
) -> InvariantExecutionCandidateProvenance:
    payload = provenance.model_dump(mode="python", exclude={"provenance_sha256"})
    payload["source_locations"] = provenance.source_locations
    payload.update(updates)
    return InvariantExecutionCandidateProvenance.sealed(**payload)


def _originated_disposition(
    provenance: InvariantExecutionCandidateProvenance,
    *,
    execution_index: int = 0,
) -> InvariantExecutionOriginDisposition:
    return InvariantExecutionOriginDisposition(
        execution_index=execution_index,
        invariant_id=provenance.invariant_id,
        harness_name=provenance.harness_name,
        execution_result_sha256=provenance.execution_result_sha256,
        kind=ExecutionOriginDispositionKind.ORIGINATED,
        candidate_id=f"exec-{provenance.provenance_sha256[:24]}",
        execution_provenance=provenance,
    )


def _replay_payload(
    tmp_path: Path,
) -> tuple[dict[str, Any], CandidateFinding, InvariantExecutionCandidateProvenance]:
    repository, suite, harness, corpus, execution = _inputs(tmp_path)
    build = _build(repository, suite, harness, corpus, execution)
    assert len(build.candidates) == 1
    candidate = build.candidates[0]
    provenance = candidate.execution_provenance
    assert provenance is not None
    return (
        {
            "scanners": {"schema_version": "1.0", "runs": []},
            "projects": {"schema_version": "1.0", "projects": []},
            "invariants": {
                "schema_version": "1.0",
                "invariants": suite.model_dump(mode="json"),
            },
            "harnesses": {
                "schema_version": "1.0",
                "harnesses": [harness.model_dump(mode="json")],
            },
            "property_corpus": {
                "schema_version": "1.0",
                "corpus": corpus.model_dump(mode="json"),
            },
            "invariant_results": {
                "schema_version": "1.0",
                "harnesses": [harness.model_dump(mode="json")],
                "results": [execution.model_dump(mode="json")],
            },
            "candidates": {
                "schema_version": "1.1",
                "findings": [candidate.model_dump(mode="json")],
            },
            "reproductions": {
                "schema_version": "1.0",
                "test_specifications": [],
                "results": [],
                "candidate_resolutions": [],
            },
        },
        candidate,
        provenance,
    )


def _with_replay_candidate(
    payload: dict[str, Any],
    candidate: CandidateFinding,
) -> dict[str, Any]:
    reproductions = dict(payload["reproductions"])
    reproductions["candidate_resolutions"] = [
        CandidateReproductionResolution(
            candidate_id=candidate.candidate_id,
            kind=ReproductionResolutionKind.INCONCLUSIVE,
            detail="synthetic fixture preserves an explicit unresolved terminal disposition",
        ).model_dump(mode="json")
    ]
    return {
        **payload,
        "candidates": {
            "schema_version": "1.1",
            "findings": [candidate.model_dump(mode="json")],
        },
        "reproductions": reproductions,
    }


def _report_shell(
    *,
    findings: list[Finding] | None = None,
    rejected_findings: list[Finding] | None = None,
    invariants: InvariantSuite | None = None,
    invariant_executions: list[InvariantExecutionResult] | None = None,
    execution_origin_dispositions: list[InvariantExecutionOriginDisposition] | None = None,
    incomplete_reasons: list[str] | None = None,
) -> AuditReport:
    """Build only the typed fields exercised by the manifest consistency gate."""

    return AuditReport.model_construct(
        schema_version="1.2",
        run_id="execution-origin-artifact-test",
        generated_at=datetime(2026, 7, 30, tzinfo=UTC),
        completed=False,
        incomplete_reasons=incomplete_reasons
        or ["Synthetic partial report for artifact validation."],
        repository=RepositoryMap(
            root_name="synthetic-execution-origin-repository",
            languages={"Solidity": 1},
            frameworks=["Foundry"],
            manifests=[],
            entry_points=[],
            api_surfaces=[],
            auth_components=[],
            data_layers=[],
            network_clients=[],
            file_handlers=[],
            configuration_files=[],
            sensitive_processing=[],
            security_tests=[],
            files=[],
        ),
        configuration_hash="a" * 64,
        model_configuration_hash="b" * 64,
        privacy={},
        metadata={},
        repository_suite_differential=None,
        scanner_runs=[],
        usage=[],
        budget_usd=0,
        accounted_cost_usd=0,
        findings=findings or [],
        rejected_findings=rejected_findings or [],
        invariants=invariants,
        invariant_executions=invariant_executions or [],
        execution_origin_dispositions=execution_origin_dispositions or [],
    )


def _write_manifest_inputs(
    tmp_path: Path,
    *,
    candidates: list[dict[str, Any]],
    schema_version: object = "1.1",
    execution_runtime: tuple[
        InvariantSuite,
        FoundryInvariantHarnessSpec,
        PropertyCorpus,
        InvariantExecutionResult,
    ]
    | None = None,
    dispositions: list[InvariantExecutionOriginDisposition] | None = None,
    candidate_resolutions: list[CandidateReproductionResolution] | None = None,
) -> Path:
    root = tmp_path.resolve()
    write_json(
        root / "metadata.json",
        {
            "privacy": {},
            "metadata": {},
            "repository_suite_differential": None,
        },
    )
    write_json(root / "scanner-results.json", {"runs": []})
    write_json(
        root / "candidate-findings.json",
        {
            "schema_version": schema_version,
            "findings": candidates,
        },
    )
    write_json(
        root / "execution-origin-dispositions.json",
        InvariantExecutionOriginDispositionArtifact(dispositions=dispositions or []).model_dump(
            mode="json"
        ),
    )
    write_json(
        root / "reproduction-results.json",
        {
            "schema_version": "1.0",
            "test_specifications": [],
            "results": [],
            "candidate_resolutions": [
                resolution.model_dump(mode="json") for resolution in (candidate_resolutions or [])
            ],
            "falsification_decisions": [],
        },
    )
    if execution_runtime is not None:
        suite, harness, corpus, execution = execution_runtime
        write_json(
            root / "solidity-invariants.json",
            {
                "schema_version": "1.2",
                "invariants": suite.model_dump(mode="json"),
            },
        )
        write_json(
            root / "invariant-harness-plan.json",
            {
                "schema_version": "1.0",
                "harnesses": [harness.model_dump(mode="json")],
            },
        )
        write_json(
            root / "property-corpus.json",
            {
                "schema_version": "1.0",
                "corpus": corpus.model_dump(mode="json"),
            },
        )
        write_json(
            root / "invariant-execution-results.json",
            {
                "schema_version": "1.0",
                "harnesses": [harness.model_dump(mode="json")],
                "results": [execution.model_dump(mode="json")],
            },
        )
    return root


def _manifest_execution_fixture(
    tmp_path: Path,
) -> tuple[Path, AuditReport, CandidateFinding, InvariantExecutionCandidateProvenance]:
    repository, suite, harness, corpus, execution = _inputs(tmp_path)
    build = _build(repository, suite, harness, corpus, execution)
    candidate = build.candidates[0]
    provenance = candidate.execution_provenance
    assert provenance is not None
    root = _write_manifest_inputs(
        tmp_path,
        candidates=[candidate.model_dump(mode="json")],
        execution_runtime=(suite, harness, corpus, execution),
        dispositions=list(build.dispositions),
        candidate_resolutions=[
            CandidateReproductionResolution(
                candidate_id=candidate.candidate_id,
                kind=ReproductionResolutionKind.INCONCLUSIVE,
                detail="post-judgment impact remained unresolved",
            )
        ],
    )
    report = _report_shell(
        findings=[
            _execution_finding(provenance).model_copy(update={"status": FindingStatus.NEEDS_REVIEW})
        ],
        invariants=suite,
        invariant_executions=[execution],
        execution_origin_dispositions=list(build.dispositions),
    )
    return root, report, candidate, provenance


def _current_report_payload(
    report: AuditReport,
    *,
    complete: bool,
) -> dict[str, object]:
    if complete:
        scanner = run_status_fixtures._real_scanner()
        usage = [run_status_fixtures._usage(role) for role in ANALYSIS_ROLES]
        floor = run_status_fixtures._assessment(
            scanner_runs=[scanner],
            usage=usage,
            required_model_roles=ANALYSIS_ROLES,
        )
        payload = run_status_fixtures._typed_report_payload(
            floor=floor,
            scanner_runs=[scanner],
            usage=usage,
            coverage=run_status_fixtures._coverage(),
        )
    else:
        floor = run_status_fixtures._assessment(required_model_roles=ANALYSIS_ROLES)
        payload = run_status_fixtures._typed_report_payload(
            floor=floor,
            scanner_runs=[],
            usage=[],
            coverage=run_status_fixtures._coverage(),
        )
    payload.update(
        {
            "invariants": report.invariants,
            "invariant_executions": report.invariant_executions,
            "execution_origin_dispositions": report.execution_origin_dispositions,
        }
    )
    return payload


def test_candidate_artifact_preserves_legacy_1_0_and_explicit_1_1_model_candidates() -> None:
    legacy = CandidateFindingArtifact.model_validate(
        {
            "schema_version": "1.0",
            "findings": [_legacy_model_payload()],
        }
    )
    current = CandidateFindingArtifact.model_validate(
        {
            "schema_version": "1.1",
            "findings": [_model_candidate().model_dump(mode="json")],
        }
    )

    assert legacy.findings[0].origin_kind is CandidateOriginKind.MODEL_REVIEW
    assert legacy.findings[0].execution_provenance is None
    assert current.findings[0] == _model_candidate()


def test_candidate_artifact_1_1_requires_explicit_origin() -> None:
    payload = _model_candidate().model_dump(mode="json")
    payload.pop("origin_kind")

    with pytest.raises(ValidationError, match="requires explicit origin"):
        CandidateFindingArtifact.model_validate(
            {
                "schema_version": "1.1",
                "findings": [payload],
            }
        )


def test_candidate_artifact_1_0_cannot_claim_execution_origin() -> None:
    candidate = _execution_candidate(_provenance())

    with pytest.raises(ValidationError, match="cannot claim deterministic execution origin"):
        CandidateFindingArtifact.model_validate(
            {
                "schema_version": "1.0",
                "findings": [candidate.model_dump(mode="json")],
            }
        )


def test_candidate_artifact_rejects_model_attribution_on_execution_origin() -> None:
    payload = _execution_candidate(_provenance()).model_dump(mode="json")
    payload["role"] = "business_logic"
    payload["model_family"] = "author/model-family"

    with pytest.raises(ValidationError, match="cannot claim a model role"):
        CandidateFindingArtifact.model_validate(
            {
                "schema_version": "1.1",
                "findings": [payload],
            }
        )


def test_candidate_artifact_rejects_unsealed_provenance_tampering() -> None:
    payload = _execution_candidate(_provenance()).model_dump(mode="json")
    payload["execution_provenance"]["compiler_version"] = "forged compiler identity"

    with pytest.raises(ValidationError, match="provenance hash does not match"):
        CandidateFindingArtifact.model_validate(
            {
                "schema_version": "1.1",
                "findings": [payload],
            }
        )


def test_replay_accepts_exact_execution_candidate_artifact_join(tmp_path: Path) -> None:
    payload, candidate, provenance = _replay_payload(tmp_path)

    artifacts = _ReplayArtifacts.model_validate(payload)

    assert artifacts.candidates.schema_version == "1.1"
    assert artifacts.candidates.findings == [candidate]
    assert artifacts.candidates.findings[0].execution_provenance == provenance


def test_replay_accepts_forced_resolution_for_exact_execution_origin_candidate(
    tmp_path: Path,
) -> None:
    payload, candidate, _provenance = _replay_payload(tmp_path)
    payload["reproductions"]["candidate_resolutions"] = [
        CandidateReproductionResolution(
            candidate_id=candidate.candidate_id,
            kind=ReproductionResolutionKind.INCONCLUSIVE,
            detail="post-judgment severity requires explicit unresolved disposition",
        ).model_dump(mode="json")
    ]

    artifacts = _ReplayArtifacts.model_validate(payload)

    assert artifacts.reproductions.candidate_resolutions[0].candidate_id == candidate.candidate_id


def test_final_report_accepts_exact_invariant_execution_binding(tmp_path: Path) -> None:
    repository, suite, harness, corpus, execution = _inputs(tmp_path)
    build = _build(repository, suite, harness, corpus, execution)
    candidate = build.candidates[0]
    provenance = candidate.execution_provenance
    assert provenance is not None
    report = _report_shell(
        findings=[_execution_finding(provenance)],
        rejected_findings=[],
        invariant_executions=[execution],
        invariants=suite,
        execution_origin_dispositions=list(build.dispositions),
    )

    report._validate_execution_origin_bindings()


def test_final_report_rejects_qualifying_counterexample_without_disposition(
    tmp_path: Path,
) -> None:
    _repository, suite, _harness, _corpus, execution = _inputs(tmp_path)
    report = _report_shell(
        invariants=suite,
        invariant_executions=[execution],
    )

    with pytest.raises(
        ValueError,
        match="requires one exact execution-origin disposition",
    ):
        report._validate_execution_origin_bindings()


def test_final_report_rejects_forged_invariant_evidence_binding(tmp_path: Path) -> None:
    repository, suite, harness, corpus, execution = _inputs(tmp_path)
    candidate = _build(repository, suite, harness, corpus, execution).candidates[0]
    provenance = candidate.execution_provenance
    assert provenance is not None
    forged = _reseal_provenance(provenance, invariant_evidence_sha256="f" * 64)
    report = _report_shell(
        findings=[_execution_finding(forged)],
        rejected_findings=[],
        invariant_executions=[execution],
        invariants=suite,
        execution_origin_dispositions=[_originated_disposition(forged)],
    )

    with pytest.raises(ValueError, match="serialized invariant evidence"):
        report._validate_execution_origin_bindings()


def test_final_report_rejects_runtime_provenance_that_contradicts_result(
    tmp_path: Path,
) -> None:
    repository, suite, harness, corpus, execution = _inputs(tmp_path)
    candidate = _build(repository, suite, harness, corpus, execution).candidates[0]
    provenance = candidate.execution_provenance
    assert provenance is not None
    forged = _reseal_provenance(provenance, compiler_sha256="f" * 64)
    report = _report_shell(
        findings=[_execution_finding(forged)],
        rejected_findings=[],
        invariant_executions=[execution],
        invariants=suite,
        execution_origin_dispositions=[_originated_disposition(forged)],
    )

    with pytest.raises(ValueError, match="serialized invariant evidence"):
        report._validate_execution_origin_bindings()


def test_execution_origin_disposition_schema_rejects_inexact_terminal_fields(
    tmp_path: Path,
) -> None:
    repository, suite, harness, corpus, execution = _inputs(tmp_path)
    build = _build(repository, suite, harness, corpus, execution)
    disposition_payload = build.dispositions[0].model_dump(mode="python")
    disposition_payload["execution_result_sha256"] = "f" * 64

    with pytest.raises(ValidationError, match="differs from its exact provenance"):
        InvariantExecutionOriginDisposition.model_validate(disposition_payload)

    rejected_payload = {
        "execution_index": 0,
        "invariant_id": execution.invariant_id,
        "harness_name": execution.harness_name,
        "execution_result_sha256": execution.canonical_result_sha256(),
        "kind": ExecutionOriginDispositionKind.REJECTED,
        "candidate_id": build.candidates[0].candidate_id,
        "rejection_category": ExecutionOriginRejectionCategory.HARNESS_BINDING,
        "rejection_detail": "the synthetic harness binding was rejected",
    }
    with pytest.raises(ValidationError, match="only a typed bounded rejection"):
        InvariantExecutionOriginDisposition.model_validate(rejected_payload)


def test_execution_origin_disposition_artifact_requires_one_sorted_runtime_index(
    tmp_path: Path,
) -> None:
    repository, suite, harness, corpus, execution = _inputs(tmp_path)
    disposition = _build(repository, suite, harness, corpus, execution).dispositions[0]

    with pytest.raises(ValidationError, match="indices must be unique and sorted"):
        InvariantExecutionOriginDispositionArtifact(dispositions=[disposition, disposition])


def test_rejected_execution_origin_requires_prominent_incomplete_reason(
    tmp_path: Path,
) -> None:
    repository, suite, harness, corpus, execution = _inputs(tmp_path)
    changed_harness = harness.model_copy(update={"seed": harness.seed + 1})
    build = _build(repository, suite, changed_harness, corpus, execution)
    disposition = build.dispositions[0]
    assert disposition.kind is ExecutionOriginDispositionKind.REJECTED

    report = _report_shell(
        invariants=suite,
        invariant_executions=[execution],
        execution_origin_dispositions=[disposition],
    )
    with pytest.raises(ValueError, match="must force an incomplete run"):
        report._validate_execution_origin_bindings()

    required_reason = f"execution-origin evidence rejected: {disposition.rejection_detail}"
    report = _report_shell(
        invariants=suite,
        invariant_executions=[execution],
        execution_origin_dispositions=[disposition],
        incomplete_reasons=[required_reason],
    )
    report._validate_execution_origin_bindings()


@pytest.mark.parametrize(
    ("field", "forged_value"),
    [
        ("invariant_id", "inv-forged"),
        ("harness_spec_sha256", "a" * 64),
        ("execution_observation_sha256", "b" * 64),
        ("execution_result_sha256", "c" * 64),
    ],
)
def test_replay_rejects_nonexact_invariant_result_harness_or_observation_join(
    tmp_path: Path,
    field: str,
    forged_value: str,
) -> None:
    payload, _candidate, provenance = _replay_payload(tmp_path)
    forged = _execution_candidate(_reseal_provenance(provenance, **{field: forged_value}))

    with pytest.raises(ValidationError, match="differs from its saved invariant execution"):
        _ReplayArtifacts.model_validate(_with_replay_candidate(payload, forged))


@pytest.mark.parametrize(
    "updates",
    [
        {"executable_sha256": "d" * 64},
        {"compiler_sha256": "e" * 64},
        {"isolation_backend": "forged-isolation"},
        {"attempts": 3, "successful_attempts": 3},
    ],
    ids=["executable", "compiler", "isolation", "attempt-count"],
)
def test_replay_rejects_resealed_provenance_that_contradicts_saved_result(
    tmp_path: Path,
    updates: dict[str, object],
) -> None:
    payload, _candidate, provenance = _replay_payload(tmp_path)
    forged = _execution_candidate(_reseal_provenance(provenance, **updates))

    with pytest.raises(ValidationError, match="differs from its saved invariant execution"):
        _ReplayArtifacts.model_validate(_with_replay_candidate(payload, forged))


@pytest.mark.parametrize(
    ("schema_version", "candidate_payload"),
    [
        ("1.0", _legacy_model_payload()),
        ("1.1", _model_candidate().model_dump(mode="json")),
    ],
)
def test_manifest_accepts_supported_candidate_artifact_versions(
    tmp_path: Path,
    schema_version: str,
    candidate_payload: dict[str, Any],
) -> None:
    root = _write_manifest_inputs(
        tmp_path,
        candidates=[candidate_payload],
        schema_version=schema_version,
    )

    _validate_report_artifact_consistency(root, _report_shell())


@pytest.mark.parametrize(
    ("schema_version", "drop_explicit_origin"),
    [
        ("9.9", False),
        ("1.1", True),
    ],
)
def test_manifest_rejects_unsupported_or_ambiguous_candidate_artifact(
    tmp_path: Path,
    schema_version: str,
    drop_explicit_origin: bool,
) -> None:
    candidate_payload = _model_candidate().model_dump(mode="json")
    if drop_explicit_origin:
        candidate_payload.pop("origin_kind")
    root = _write_manifest_inputs(
        tmp_path,
        candidates=[candidate_payload],
        schema_version=schema_version,
    )

    with pytest.raises(ValueError):
        _validate_report_artifact_consistency(root, _report_shell())


def test_manifest_binds_execution_candidate_to_exact_final_finding(tmp_path: Path) -> None:
    root, report, _candidate, _provenance_record = _manifest_execution_fixture(tmp_path)

    _validate_report_artifact_consistency(root, report)


def test_current_report_rejects_complete_active_rejected_execution_splice(
    tmp_path: Path,
) -> None:
    _root, report, candidate, _provenance_record = _manifest_execution_fixture(tmp_path)
    assert candidate.severity is Severity.INFORMATIONAL
    rejected_high = report.findings[0].model_copy(
        update={
            "severity": Severity.HIGH,
            "status": FindingStatus.REJECTED,
        }
    )
    payload = _current_report_payload(report, complete=True)
    payload.update({"findings": [rejected_high], "rejected_findings": []})

    with pytest.raises(
        ValidationError,
        match="findings inventory cannot contain rejected findings",
    ):
        AuditReport.model_validate(payload)


def test_current_report_rejects_nonrejected_finding_spliced_into_rejected_inventory(
    tmp_path: Path,
) -> None:
    _root, report, _candidate, _provenance_record = _manifest_execution_fixture(tmp_path)
    payload = _current_report_payload(report, complete=True)
    payload.update({"findings": [], "rejected_findings": report.findings})

    with pytest.raises(
        ValidationError,
        match="rejected-findings inventory may contain only rejected findings",
    ):
        AuditReport.model_validate(payload)


def test_current_report_accepts_active_and_invalid_rejected_execution_shapes(
    tmp_path: Path,
) -> None:
    _root, report, _candidate, _provenance_record = _manifest_execution_fixture(tmp_path)
    active = report.findings[0].model_copy(update={"status": FindingStatus.CONFIRMED})
    active_payload = _current_report_payload(report, complete=True)
    active_payload.update({"findings": [active], "rejected_findings": []})
    assert AuditReport.model_validate(active_payload).findings == [active]

    rejected = report.findings[0].model_copy(
        update={
            "status": FindingStatus.REJECTED,
            "location_validation": LocationValidation(
                valid=False,
                errors=["synthetic current-source location rejection"],
            ),
        }
    )
    rejected_payload = _current_report_payload(report, complete=False)
    rejected_payload.update({"findings": [], "rejected_findings": [rejected]})
    validated = AuditReport.model_validate(rejected_payload)
    assert validated.rejected_findings == [rejected]
    assert validated.run_status is not AuditRunStatus.COMPLETE


def test_current_report_rejects_valid_location_or_complete_execution_rejection(
    tmp_path: Path,
) -> None:
    _root, report, _candidate, _provenance_record = _manifest_execution_fixture(tmp_path)
    valid_location_rejection = report.findings[0].model_copy(
        update={"status": FindingStatus.REJECTED}
    )
    invalid_location_rejection = valid_location_rejection.model_copy(
        update={
            "location_validation": LocationValidation(
                valid=False,
                errors=["synthetic current-source location rejection"],
            )
        }
    )

    valid_location_payload = _current_report_payload(report, complete=False)
    valid_location_payload.update({"findings": [], "rejected_findings": [valid_location_rejection]})
    with pytest.raises(
        ValidationError,
        match="rejected execution-origin finding requires invalid source-location evidence",
    ):
        AuditReport.model_validate(valid_location_payload)

    complete_payload = _current_report_payload(report, complete=True)
    complete_payload.update({"findings": [], "rejected_findings": [invalid_location_rejection]})
    with pytest.raises(
        ValidationError,
        match="rejected execution-origin finding requires a non-complete report",
    ):
        AuditReport.model_validate(complete_payload)


@pytest.mark.parametrize("schema_version", ["1.0", "1.1"])
def test_legacy_report_preserves_unpartitioned_finding_inventories(schema_version: str) -> None:
    rejected = Finding(
        id="legacy-rejected-finding",
        title="Legacy rejected finding",
        status=FindingStatus.REJECTED,
        severity=Severity.LOW,
        confidence=0,
        summary="Legacy reports did not type their active and rejected inventories.",
        impact="The legacy finding was rejected.",
        location_validation=LocationValidation(
            valid=False,
            errors=["synthetic legacy location rejection"],
        ),
    )
    payload = _report_shell().model_dump(mode="python")
    payload.update({"schema_version": schema_version, "findings": [rejected]})

    validated = AuditReport.model_validate(payload)

    assert validated.findings == [rejected]


def test_manifest_rejects_post_judge_execution_elevation_with_accepted_status(
    tmp_path: Path,
) -> None:
    root, report, _candidate, _provenance_record = _manifest_execution_fixture(tmp_path)
    elevated = report.findings[0].model_copy(update={"status": FindingStatus.CONFIRMED})
    tampered_report = report.model_copy(update={"findings": [elevated]})

    with pytest.raises(
        ValueError,
        match="post-judgment execution severity elevation cannot retain an accepted status",
    ):
        _validate_report_artifact_consistency(root, tampered_report)


def test_manifest_rejects_post_judge_execution_elevation_without_terminal_resolution(
    tmp_path: Path,
) -> None:
    root, report, _candidate, _provenance_record = _manifest_execution_fixture(tmp_path)
    write_json(
        root / "reproduction-results.json",
        {
            "schema_version": "1.0",
            "test_specifications": [],
            "results": [],
            "candidate_resolutions": [],
            "falsification_decisions": [],
        },
    )

    with pytest.raises(
        ValueError,
        match="high/critical candidate obligations require terminal candidate resolutions",
    ):
        _validate_report_artifact_consistency(root, report)


def test_manifest_rejects_post_judge_execution_elevation_on_complete_report(
    tmp_path: Path,
) -> None:
    root, report, _candidate, _provenance_record = _manifest_execution_fixture(tmp_path)
    tampered_report = report.model_copy(
        update={
            "completed": True,
            "run_status": AuditRunStatus.COMPLETE,
        }
    )

    with pytest.raises(
        ValueError,
        match="post-judgment execution severity elevation requires a non-complete report",
    ):
        _validate_report_artifact_consistency(root, tampered_report)


def test_manifest_rejects_reproduced_resolution_without_qualifying_result(
    tmp_path: Path,
) -> None:
    root, report, candidate, _provenance_record = _manifest_execution_fixture(tmp_path)
    write_json(
        root / "reproduction-results.json",
        {
            "schema_version": "1.0",
            "test_specifications": [],
            "results": [],
            "candidate_resolutions": [
                CandidateReproductionResolution(
                    candidate_id=candidate.candidate_id,
                    kind=ReproductionResolutionKind.REPRODUCED,
                    evidence_refs=["reproduction:" + ("a" * 64)],
                    detail="forged reproduced resolution",
                ).model_dump(mode="json")
            ],
            "falsification_decisions": [],
        },
    )

    with pytest.raises(
        ValueError,
        match="reproduced resolution is not exactly bound to qualifying results",
    ):
        _validate_report_artifact_consistency(root, report)


def test_manifest_requires_exact_report_reproduction_results(tmp_path: Path) -> None:
    root, report, candidate, _provenance_record = _manifest_execution_fixture(tmp_path)
    tampered_report = report.model_copy(
        update={
            "reproductions": [
                ReproductionResult(
                    candidate_id=candidate.candidate_id,
                    test_name="UnserializedReproduction",
                    state=ReproductionState.NOT_ATTEMPTED,
                    specification_sha256="b" * 64,
                )
            ]
        }
    )

    with pytest.raises(
        ValueError,
        match=r"reproduction-results\.json differs from final report reproductions",
    ):
        _validate_report_artifact_consistency(root, tampered_report)


def test_manifest_allows_incomplete_harness_rejection_without_candidate(
    tmp_path: Path,
) -> None:
    repository, suite, harness, corpus, execution = _inputs(tmp_path)
    changed_harness = harness.model_copy(update={"seed": harness.seed + 1})
    build = _build(repository, suite, changed_harness, corpus, execution)
    assert build.candidates == ()
    assert len(build.dispositions) == 1
    disposition = build.dispositions[0]
    assert disposition.kind is ExecutionOriginDispositionKind.REJECTED
    assert disposition.rejection_category is ExecutionOriginRejectionCategory.HARNESS_BINDING
    required_reason = f"execution-origin evidence rejected: {disposition.rejection_detail}"
    root = _write_manifest_inputs(
        tmp_path,
        candidates=[],
        execution_runtime=(suite, changed_harness, corpus, execution),
        dispositions=list(build.dispositions),
    )
    report = _report_shell(
        invariants=suite,
        invariant_executions=[execution],
        execution_origin_dispositions=list(build.dispositions),
        incomplete_reasons=[required_reason],
    )

    _validate_report_artifact_consistency(root, report)


def test_manifest_allows_incomplete_current_source_rejection_without_candidate(
    tmp_path: Path,
) -> None:
    repository, suite, harness, corpus, execution = _inputs(tmp_path)
    source = repository / "src" / "Vault.sol"
    source.write_text(
        source.read_text(encoding="utf-8").replace(
            "accountedAssets += 1",
            "accountedAssets += 2",
        ),
        encoding="utf-8",
    )
    build = _build(repository, suite, harness, corpus, execution)
    assert build.candidates == ()
    assert len(build.dispositions) == 1
    disposition = build.dispositions[0]
    assert disposition.kind is ExecutionOriginDispositionKind.REJECTED
    assert disposition.rejection_category is ExecutionOriginRejectionCategory.SOURCE_BINDING
    required_reason = f"execution-origin evidence rejected: {disposition.rejection_detail}"
    root = _write_manifest_inputs(
        tmp_path,
        candidates=[],
        execution_runtime=(suite, harness, corpus, execution),
        dispositions=list(build.dispositions),
    )
    report = _report_shell(
        invariants=suite,
        invariant_executions=[execution],
        execution_origin_dispositions=list(build.dispositions),
        incomplete_reasons=[required_reason],
    )

    _validate_report_artifact_consistency(root, report)


def test_manifest_rejects_tampered_execution_disposition_artifact(tmp_path: Path) -> None:
    root, report, _candidate, _provenance_record = _manifest_execution_fixture(tmp_path)
    tampered = report.execution_origin_dispositions[0].model_copy(update={"execution_index": 1})
    write_json(
        root / "execution-origin-dispositions.json",
        InvariantExecutionOriginDispositionArtifact(dispositions=[tampered]).model_dump(
            mode="json"
        ),
    )

    with pytest.raises(
        ValueError,
        match=r"execution-origin-dispositions\.json differs from the final report",
    ):
        _validate_report_artifact_consistency(root, report)


def test_manifest_rejects_execution_candidate_omitted_from_final_findings(
    tmp_path: Path,
) -> None:
    root, report, _candidate, _provenance_record = _manifest_execution_fixture(tmp_path)
    report = _report_shell(
        invariants=report.invariants,
        invariant_executions=report.invariant_executions,
        execution_origin_dispositions=report.execution_origin_dispositions,
    )

    with pytest.raises(ValueError, match="omitted from final report evidence"):
        _validate_report_artifact_consistency(root, report)


def test_manifest_rejects_qualifying_runtime_omitted_from_candidate_inventory(
    tmp_path: Path,
) -> None:
    _repository, suite, harness, corpus, execution = _inputs(tmp_path)
    root = _write_manifest_inputs(
        tmp_path,
        candidates=[],
        execution_runtime=(suite, harness, corpus, execution),
    )
    report = _report_shell(
        invariants=suite,
        invariant_executions=[execution],
    )

    with pytest.raises(
        ValueError,
        match="requires one exact execution-origin disposition",
    ):
        _validate_report_artifact_consistency(root, report)


def test_manifest_rejects_emitted_runtime_omitted_from_report_and_candidates(
    tmp_path: Path,
) -> None:
    _repository, suite, harness, corpus, execution = _inputs(tmp_path)
    root = _write_manifest_inputs(
        tmp_path,
        candidates=[],
        execution_runtime=(suite, harness, corpus, execution),
    )
    report = _report_shell(invariants=suite)

    with pytest.raises(
        ValueError,
        match="differs from the final report runtime evidence",
    ):
        _validate_report_artifact_consistency(root, report)


def test_manifest_rejects_execution_finding_without_emitted_candidate(
    tmp_path: Path,
) -> None:
    finding = _execution_finding(_provenance())
    root = _write_manifest_inputs(tmp_path, candidates=[])

    with pytest.raises(ValueError, match="candidate"):
        _validate_report_artifact_consistency(
            root,
            _report_shell(findings=[finding]),
        )


def test_manifest_rejects_mismatched_candidate_and_finding_provenance(
    tmp_path: Path,
) -> None:
    root, report, candidate, provenance = _manifest_execution_fixture(tmp_path)
    finding_provenance = _reseal_provenance(provenance, compiler_sha256="f" * 64)
    finding = _execution_finding(finding_provenance).model_copy(
        update={"contributing_candidate_ids": [candidate.candidate_id]}
    )
    report = report.model_copy(update={"findings": [finding]})

    with pytest.raises(ValueError, match="provenance differs"):
        _validate_report_artifact_consistency(root, report)


def test_manifest_rejects_unbound_contributing_candidate_id(tmp_path: Path) -> None:
    root, report, _candidate, provenance = _manifest_execution_fixture(tmp_path)
    finding_payload = _execution_finding(provenance).model_dump(mode="python")
    finding_payload["contributing_candidate_ids"].append("candidate-not-emitted")
    finding = Finding.model_validate(finding_payload)
    report = report.model_copy(update={"findings": [finding]})

    with pytest.raises(ValueError):
        _validate_report_artifact_consistency(root, report)
