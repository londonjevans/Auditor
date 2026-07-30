"""Cross-artifact integrity regressions for execution-originated candidates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    AuditReport,
    CandidateFinding,
    CandidateFindingArtifact,
    CandidateOriginKind,
    Evidence,
    Finding,
    FoundryInvariantHarnessSpec,
    InvariantExecutionCandidateProvenance,
    InvariantExecutionResult,
    InvariantSuite,
    Location,
    PropertyCorpus,
    Severity,
    VerificationTest,
)
from mmaudit.orchestration.manifest import _validate_report_artifact_consistency
from mmaudit.orchestration.replay import _ReplayArtifacts
from mmaudit.reporting.json_report import write_json
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
            },
        },
        candidate,
        provenance,
    )


def _with_replay_candidate(
    payload: dict[str, Any],
    candidate: CandidateFinding,
) -> dict[str, Any]:
    return {
        **payload,
        "candidates": {
            "schema_version": "1.1",
            "findings": [candidate.model_dump(mode="json")],
        },
    }


def _report_shell(
    *,
    findings: list[Finding] | None = None,
    rejected_findings: list[Finding] | None = None,
    invariants: InvariantSuite | None = None,
    invariant_executions: list[InvariantExecutionResult] | None = None,
) -> AuditReport:
    """Build only the typed fields exercised by the manifest consistency gate."""

    return AuditReport.model_construct(
        privacy={},
        metadata={},
        repository_suite_differential=None,
        scanner_runs=[],
        findings=findings or [],
        rejected_findings=rejected_findings or [],
        invariants=invariants,
        invariant_executions=invariant_executions or [],
    )


def _write_manifest_inputs(
    tmp_path: Path,
    *,
    candidates: list[dict[str, Any]],
    schema_version: object = "1.1",
    execution_runtime: tuple[
        FoundryInvariantHarnessSpec,
        PropertyCorpus,
        InvariantExecutionResult,
    ]
    | None = None,
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
    if execution_runtime is not None:
        harness, corpus, execution = execution_runtime
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
    candidate = _build(repository, suite, harness, corpus, execution).candidates[0]
    provenance = candidate.execution_provenance
    assert provenance is not None
    root = _write_manifest_inputs(
        tmp_path,
        candidates=[candidate.model_dump(mode="json")],
        execution_runtime=(harness, corpus, execution),
    )
    report = _report_shell(
        findings=[_execution_finding(provenance)],
        invariants=suite,
        invariant_executions=[execution],
    )
    return root, report, candidate, provenance


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


def test_final_report_accepts_exact_invariant_execution_binding(tmp_path: Path) -> None:
    repository, suite, harness, corpus, execution = _inputs(tmp_path)
    candidate = _build(repository, suite, harness, corpus, execution).candidates[0]
    provenance = candidate.execution_provenance
    assert provenance is not None
    report = AuditReport.model_construct(
        findings=[_execution_finding(provenance)],
        rejected_findings=[],
        invariant_executions=[execution],
        invariants=suite,
    )

    report._validate_execution_origin_bindings()


def test_final_report_rejects_forged_invariant_evidence_binding(tmp_path: Path) -> None:
    repository, suite, harness, corpus, execution = _inputs(tmp_path)
    candidate = _build(repository, suite, harness, corpus, execution).candidates[0]
    provenance = candidate.execution_provenance
    assert provenance is not None
    forged = _reseal_provenance(provenance, invariant_evidence_sha256="f" * 64)
    report = AuditReport.model_construct(
        findings=[_execution_finding(forged)],
        rejected_findings=[],
        invariant_executions=[execution],
        invariants=suite,
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
    report = AuditReport.model_construct(
        findings=[_execution_finding(forged)],
        rejected_findings=[],
        invariant_executions=[execution],
        invariants=suite,
    )

    with pytest.raises(ValueError, match="serialized invariant evidence"):
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


def test_manifest_rejects_execution_candidate_omitted_from_final_findings(
    tmp_path: Path,
) -> None:
    root, report, _candidate, _provenance_record = _manifest_execution_fixture(tmp_path)
    report = _report_shell(
        invariants=report.invariants,
        invariant_executions=report.invariant_executions,
    )

    with pytest.raises(ValueError, match="omitted from final report evidence"):
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
