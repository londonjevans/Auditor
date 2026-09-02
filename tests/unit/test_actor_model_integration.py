from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.agents.judge import JudgeAgent
from mmaudit.config import (
    AuditConfig,
    audit_config_overrides,
    canonical_audit_config_json,
    parse_canonical_audit_config,
)
from mmaudit.constants import ANALYSIS_ROLES
from mmaudit.models.actor_model import (
    ActorExposureState,
    ActorFindingAssessmentBinding,
    ActorGovernanceConflictKind,
    ActorGovernanceFinding,
    ActorModelEvaluation,
    ActorModelInputEvidence,
    ActorModelInputState,
    ActorSeverity,
    CandidateActorContext,
    FindingActorAssessment,
)
from mmaudit.models.openrouter import OpenRouterSchemaError
from mmaudit.models.schemas import (
    ActorModelBaselineArtifact,
    AuditReport,
    CandidateFinding,
    ContextPackage,
    Finding,
    JudgeDecision,
    RepositoryFile,
    RepositoryMap,
    Severity,
)
from mmaudit.orchestration.actor_model import (
    bind_judged_actor_context,
    build_actor_model_evaluation,
    calibrate_finding,
)
from mmaudit.orchestration.context import (
    ContextBuilder,
    provider_actor_model_payload_sha256,
    render_context,
    revalidate_context_package,
)
from mmaudit.orchestration.manifest import (
    _validate_actor_model_baseline_artifact,
    _validate_actor_model_configuration,
)
from mmaudit.reporting.bundle import (
    FindingsArtifact,
    _candidate_payload_for_findings_artifact_version,
    build_findings_artifact,
)
from mmaudit.reporting.client import render_client_markdown
from mmaudit.reporting.markdown import render_markdown
from mmaudit.reporting.sarif import generate_report_sarif
from mmaudit.repository.chunking import line_range_hash
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.repository.mapping import build_repository_map
from tests.unit.test_actor_model import (
    _current_actor_input,
    _finding,
    _missing_actor_input,
    _scenario_payload,
)
from tests.unit.test_run_status import (
    _assessment,
    _coverage,
    _typed_report_payload,
)
from tests.unit.test_run_status import _report_payload as _legacy_report_payload

_SOURCE_PATH = "tests/fixtures/actor_model/SyntheticOrchard.sol"
_SOURCE = "contract SyntheticOrchard { function syntheticTransition() external {} }\n"


class _NoTransportClient:
    def __init__(self) -> None:
        self.calls = 0

    async def complete(self, **_kwargs: object) -> object:
        self.calls += 1
        raise AssertionError("transport must not run for drifted actor-model evidence")


def _repository_map(*, include_source: bool = False) -> RepositoryMap:
    files = []
    languages: dict[str, int] = {}
    if include_source:
        encoded = _SOURCE.encode("utf-8")
        files = [
            RepositoryFile(
                path=_SOURCE_PATH,
                size=len(encoded),
                lines=1,
                sha256=hashlib.sha256(encoded).hexdigest(),
                language="Solidity",
            )
        ]
        languages = {"Solidity": 1}
    return RepositoryMap(
        root_name="synthetic-actor-integration",
        languages=languages,
        frameworks=[],
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
        files=files,
    )


def _actor_baseline(*findings: Finding) -> ActorModelBaselineArtifact:
    baselines: list[Finding] = []
    for finding in findings:
        assessment = finding.actor_assessment
        baselines.append(
            finding.model_copy(
                update={
                    "severity": (
                        Severity(assessment.original_severity.value)
                        if assessment is not None
                        else finding.severity
                    ),
                    "actor_assessment": None,
                }
            )
        )
    return ActorModelBaselineArtifact.build(baselines)


def _calibrated_finding() -> tuple[Finding, ActorModelInputEvidence, ActorModelEvaluation]:
    scenario = next(
        item
        for item in _scenario_payload()["scenarios"]
        if item["scenario_id"] == "request-cooldown-severity"
    )
    actor_context = CandidateActorContext.model_validate_json(
        json.dumps(scenario["actor_context"]),
        strict=True,
    )
    actor_input = _current_actor_input()
    baseline_finding = _finding(
        finding_id=scenario["finding_id"],
        severity=Severity(scenario["original_severity"]),
        actor_context=actor_context,
    )
    location = baseline_finding.locations[0].model_copy(
        update={"content_hash": line_range_hash(_SOURCE, 1, 1)}
    )
    baseline_finding = baseline_finding.model_copy(update={"locations": [location]})
    baseline = ActorModelBaselineArtifact.build((baseline_finding,))
    calibrated = calibrate_finding(
        baseline_finding,
        actor_context=actor_context,
        actor_input=actor_input,
    )
    finding = calibrated.finding
    evaluation = build_actor_model_evaluation(
        actor_input=actor_input,
        findings=(finding,),
        baseline_artifact=baseline,
        governance_findings=calibrated.governance_findings,
    )
    return finding, actor_input, evaluation


def _judge_decision_for(
    finding: Finding,
    *,
    group_id: str | None = None,
) -> JudgeDecision:
    resolved_group_id = group_id or finding.group_id
    if resolved_group_id is None:
        raise ValueError("synthetic judge decision requires a finding group")
    return JudgeDecision(
        group_id=resolved_group_id,
        status=finding.status,
        severity=finding.severity,
        confidence=finding.confidence,
        cwe=list(finding.cwe),
        owasp=list(finding.owasp),
        rationale="Synthetic retained actor annotation.",
        actor_model_applicability=finding.actor_model_applicability,
        actor_context=finding.actor_context,
    )


def _report_payload(
    finding: Finding,
    evaluation: ActorModelEvaluation | None,
) -> dict[str, Any]:
    coverage = _coverage()
    floor = _assessment(coverage=coverage, required_model_roles=ANALYSIS_ROLES)
    payload = _typed_report_payload(
        floor=floor,
        scanner_runs=[],
        usage=[],
        coverage=coverage,
    )
    metadata = payload["metadata"]
    assert isinstance(metadata, dict)
    payload.update(
        {
            "schema_version": "1.3",
            "run_id": "synthetic-actor-report",
            "generated_at": (
                evaluation.evaluated_at
                if evaluation is not None
                else datetime(2026, 10, 1, tzinfo=UTC)
            ),
            "repository": _repository_map(include_source=True),
            "configuration_hash": "a" * 64,
            "model_configuration_hash": "b" * 64,
            "findings": [finding],
            "rejected_findings": [],
            "actor_model_baseline": (_actor_baseline(finding) if evaluation is not None else None),
            "actor_model_evaluation": evaluation,
            "judge_decisions": (
                [_judge_decision_for(finding)]
                if evaluation is not None
                and evaluation.input_evidence.state is ActorModelInputState.CURRENT
                and finding.group_id is not None
                else []
            ),
            "metadata": {
                **metadata,
                "configured_models": {},
                "configured_fallbacks": {},
                "severity_threshold": "informational",
                "run_started_at": (
                    evaluation.evaluated_at.isoformat()
                    if evaluation is not None
                    else datetime(2026, 10, 1, tzinfo=UTC).isoformat()
                ),
            },
        }
    )
    return payload


def _rebuilt_assessment(
    assessment: FindingActorAssessment,
    **updates: object,
) -> FindingActorAssessment:
    values = {
        field_name: getattr(assessment, field_name)
        for field_name in FindingActorAssessment.model_fields
        if field_name != "assessment_sha256"
    }
    values.update(updates)
    return FindingActorAssessment.build(**values)


def _artifact_payload_with_finding(
    artifact: FindingsArtifact,
    finding: Finding,
    evaluation: ActorModelEvaluation,
) -> dict[str, Any]:
    payload = artifact.model_dump(mode="python")
    payload["findings"] = [finding]
    payload["records"] = [
        artifact.records[0].model_copy(update={"finding": finding}),
    ]
    payload["actor_model_evaluation"] = evaluation
    return payload


def _empty_judge_context(actor_input: ActorModelInputEvidence) -> ContextPackage:
    return ContextPackage(
        role="judge",
        byte_budget=100_000,
        bytes_used=0,
        configured_maximum_source_tokens_per_request=200_000,
        effective_source_byte_ceiling=0,
        repository_map=_repository_map(),
        scanner_findings=[],
        excerpts=[],
        actor_model_evidence=actor_input,
    )


def _rendered_actor_payload(rendered: str) -> dict[str, Any]:
    encoded = rendered.split("<OPERATOR_ACTOR_MODEL_EVIDENCE_JSON>\n", 1)[1].split(
        "\n</OPERATOR_ACTOR_MODEL_EVIDENCE_JSON>",
        1,
    )[0]
    payload = json.loads(encoded)
    assert isinstance(payload, dict)
    return payload


def test_context_builder_retains_actor_custody_but_withholds_facts_from_severity_pass(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = tmp_path / "actor-context"
    repository.mkdir()
    (repository / "large.py").write_text(
        "value = " + repr("x" * 80_000) + "\n",
        encoding="utf-8",
    )
    config = config_factory(
        repository={"max_total_context_bytes": 30_000},
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(repository, config.repository, IgnoreMatcher())
    actor_input = _current_actor_input()
    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
        actor_model_evidence=actor_input,
    ).build("source_audit", requested_budget=30_000)

    assert package.actor_model_evidence == actor_input
    assert package.actor_model_evidence is not actor_input
    assert package.omissions
    rendered = render_context(package)
    assert rendered.count("<OPERATOR_ACTOR_MODEL_EVIDENCE_JSON>") == 1
    assert '"semantic_actor_facts_withheld": true' in rendered
    assert actor_input.source_evidence is not None
    assert actor_input.source_evidence.actor_model.subject_name not in rendered
    actor_payload = _rendered_actor_payload(rendered)
    assert "evaluated_at" not in actor_payload
    assert "evidence_sha256" not in actor_payload
    later_actor_input = ActorModelInputEvidence.build(
        **{
            **actor_input.model_dump(
                mode="python",
                exclude={"evaluated_at", "evidence_sha256"},
            ),
            "evaluated_at": actor_input.evaluated_at + timedelta(seconds=1),
        }
    )
    assert later_actor_input.evidence_sha256 != actor_input.evidence_sha256
    assert (
        render_context(package.model_copy(update={"actor_model_evidence": later_actor_input}))
        == rendered
    )
    assert revalidate_context_package(package) == package


@pytest.mark.asyncio
async def test_judge_binds_actor_evidence_and_rejects_drift_before_transport(
    config_factory: Callable[..., AuditConfig],
) -> None:
    actor_input = _current_actor_input()
    prepared = JudgeAgent.prepare_input(
        groups=[{"group_id": "group-actor"}],
        threat_model=None,
        actor_model_evidence=actor_input,
    )
    envelope = json.loads(
        prepared.workflow_prompt.removeprefix("<VERIFIED_GROUPS_JSON>\n").removesuffix(
            "\n</VERIFIED_GROUPS_JSON>\n"
        )
    )
    source = actor_input.source_evidence
    assert source is not None
    rendered_judge_context = render_context(_empty_judge_context(actor_input))
    assert source.actor_model.subject_name in rendered_judge_context
    assert "semantic_actor_facts_withheld" not in rendered_judge_context
    judge_actor_payload = _rendered_actor_payload(rendered_judge_context)
    assert "evaluated_at" not in judge_actor_payload
    assert "evidence_sha256" not in judge_actor_payload
    assert envelope["actor_model_binding"] == {
        "state": "current",
        "provider_projection_sha256": provider_actor_model_payload_sha256(
            actor_input,
            role="judge",
        ),
        "source_sha256": source.source_sha256,
        "actor_model_sha256": source.actor_model.artifact_sha256,
    }
    later_actor_input = ActorModelInputEvidence.build(
        **{
            **actor_input.model_dump(
                mode="python",
                exclude={"evaluated_at", "evidence_sha256"},
            ),
            "evaluated_at": actor_input.evaluated_at + timedelta(seconds=1),
        }
    )
    later_prepared = JudgeAgent.prepare_input(
        groups=[{"group_id": "group-actor"}],
        threat_model=None,
        actor_model_evidence=later_actor_input,
    )
    assert later_actor_input.evidence_sha256 != actor_input.evidence_sha256
    assert later_prepared == prepared
    assert render_context(_empty_judge_context(later_actor_input)) == rendered_judge_context

    client = _NoTransportClient()
    agent = JudgeAgent(config_factory(), client)  # type: ignore[arg-type]
    with pytest.raises(OpenRouterSchemaError, match="differs from submitted judgment evidence"):
        await agent.run(
            groups=[{"group_id": "group-actor"}],
            context=_empty_judge_context(_missing_actor_input()),
            threat_model=None,
            prepared_input=prepared,
        )
    assert client.calls == 0


def test_stale_actor_semantics_are_withheld_from_provider_context() -> None:
    current = _current_actor_input()
    source = current.source_evidence
    assert source is not None
    stale = ActorModelInputEvidence.build(
        evaluated_at=datetime(2027, 2, 1, tzinfo=UTC),
        state=ActorModelInputState.STALE,
        configured=True,
        configured_path=current.configured_path,
        source_evidence=source,
        limitations=("Synthetic actor evidence expired before this review.",),
    )

    rendered = render_context(_empty_judge_context(stale))

    assert '"semantic_actor_facts_withheld": true' in rendered
    assert source.source_sha256 in rendered
    assert source.actor_model.artifact_sha256 in rendered
    assert source.actor_model.subject_name not in rendered
    assert "protect synthetic first-loss capital" not in rendered
    actor_payload = _rendered_actor_payload(rendered)
    assert "evaluated_at" not in actor_payload
    assert "evidence_sha256" not in actor_payload
    source_binding = actor_payload["source_binding"]
    assert isinstance(source_binding, dict)
    assert source_binding["source_sha256"] == source.source_sha256
    assert source_binding["actor_model_sha256"] == source.actor_model.artifact_sha256


def test_verifier_prompt_preserves_actor_blind_candidate_authority() -> None:
    prompt = Path("src/mmaudit/prompts/verifier.md").read_text(encoding="utf-8")
    normalized = " ".join(prompt.split())

    assert "actor-blind, code/mechanism verification pass" in prompt
    assert "do not reject or mark a candidate insufficient" in normalized
    assert "actor_model_applicability=unstated" in prompt
    assert "Treat an omitted privileged context" not in prompt


def _finding_with_only_actor_evidence_kind(
    finding: Finding,
    evidence_kind: str,
) -> Finding:
    payload = finding.model_dump(mode="python")
    if evidence_kind == "applicability":
        payload.update(
            {
                "actor_model_applicability": "no_privileged_actor_required",
                "actor_context": None,
                "actor_assessment": None,
            }
        )
    elif evidence_kind == "context":
        payload["actor_assessment"] = None
    elif evidence_kind == "assessment":
        payload.update(
            {
                "actor_model_applicability": "unstated",
                "actor_context": None,
            }
        )
    else:
        raise AssertionError(f"unsupported synthetic actor evidence kind: {evidence_kind}")
    return Finding.model_validate(payload)


@pytest.mark.parametrize("schema_version", ["1.0", "1.1"])
@pytest.mark.parametrize(
    "inventory_name",
    ["findings", "rejected_findings", "filtered_findings"],
)
@pytest.mark.parametrize("evidence_kind", ["applicability", "context", "assessment"])
def test_legacy_report_rejects_nested_actor_evidence_without_top_level_custody(
    schema_version: str,
    inventory_name: str,
    evidence_kind: str,
) -> None:
    finding, _actor_input, _evaluation = _calibrated_finding()
    nested = _finding_with_only_actor_evidence_kind(finding, evidence_kind)
    payload = _legacy_report_payload()
    payload["schema_version"] = schema_version
    payload[inventory_name] = [nested.model_dump(mode="python")]

    with pytest.raises(
        ValidationError,
        match="legacy report cannot carry nested actor-model finding evidence",
    ):
        AuditReport.model_validate(payload)


@pytest.mark.parametrize("schema_version", ["1.1", "1.2"])
@pytest.mark.parametrize(
    "inventory_name",
    ["findings", "rejected_findings", "filtered_findings"],
)
@pytest.mark.parametrize("evidence_kind", ["applicability", "context", "assessment"])
def test_legacy_findings_artifact_rejects_nested_actor_evidence_without_top_level_custody(
    schema_version: str,
    inventory_name: str,
    evidence_kind: str,
) -> None:
    finding, _actor_input, evaluation = _calibrated_finding()
    report = AuditReport.model_validate(_report_payload(finding, evaluation))
    payload = build_findings_artifact(report).model_dump(mode="python")
    payload["schema_version"] = schema_version
    if schema_version == "1.1":
        payload.pop("language_capability")
    payload.pop("actor_model_baseline")
    payload.pop("actor_model_evaluation")
    payload["judge_decisions"] = []
    payload["findings"] = []
    payload["rejected_findings"] = []
    payload["filtered_findings"] = []
    nested = _finding_with_only_actor_evidence_kind(finding, evidence_kind)
    payload[inventory_name] = [nested.model_dump(mode="python")]

    with pytest.raises(
        ValidationError,
        match="legacy findings artifact cannot carry nested actor-model evidence",
    ):
        FindingsArtifact.model_validate(payload)


@pytest.mark.parametrize("schema_version", ["1.1", "1.2"])
@pytest.mark.parametrize("inventory_name", ["candidate_findings", "record_candidates"])
def test_pre_actor_findings_artifact_rejects_nested_candidate_actor_evidence(
    schema_version: str,
    inventory_name: str,
    candidate_factory: Callable[..., CandidateFinding],
) -> None:
    finding, _actor_input, evaluation = _calibrated_finding()
    context = finding.actor_context
    assert context is not None
    candidate_payload = candidate_factory(candidate_id="synthetic-actor-nested").model_dump(
        mode="python"
    )
    candidate_payload.update(
        {
            "actor_model_applicability": "privileged_actor_required",
            "actor_context": context,
        }
    )
    annotated_candidate = CandidateFinding.model_validate(candidate_payload)
    neutral_finding_payload = finding.model_dump(mode="python")
    neutral_finding_payload.pop("actor_model_applicability")
    neutral_finding_payload.pop("actor_context")
    neutral_finding_payload.pop("actor_assessment")
    neutral_finding = Finding.model_validate(neutral_finding_payload)

    report = AuditReport.model_validate(_report_payload(finding, evaluation))
    payload = build_findings_artifact(report).model_dump(mode="python")
    payload["schema_version"] = schema_version
    if schema_version == "1.1":
        payload.pop("language_capability")
    payload.pop("actor_model_baseline")
    payload.pop("actor_model_evaluation")
    payload["judge_decisions"] = []
    payload["findings"] = [neutral_finding.model_dump(mode="python")]
    payload["records"][0]["finding"] = neutral_finding.model_dump(mode="python")
    payload["candidate_findings"] = []
    payload["records"][0]["candidate_findings"] = []
    if inventory_name == "candidate_findings":
        payload["candidate_findings"] = [annotated_candidate.model_dump(mode="python")]
    else:
        payload["records"][0]["candidate_findings"] = [
            annotated_candidate.model_dump(mode="python")
        ]

    with pytest.raises(
        ValidationError,
        match="legacy findings artifact cannot carry nested actor-model evidence",
    ):
        FindingsArtifact.model_validate(payload)


def test_legacy_finding_actor_defaults_are_serialization_and_hash_neutral(
    candidate_factory: Callable[..., CandidateFinding],
) -> None:
    candidate = candidate_factory(candidate_id="synthetic-legacy-actor-defaults")
    finding, _actor_input, _evaluation = _calibrated_finding()
    neutral_finding_payload = finding.model_dump(mode="python")
    neutral_finding_payload.pop("actor_model_applicability")
    neutral_finding_payload.pop("actor_context")
    neutral_finding_payload.pop("actor_assessment")
    neutral_finding = Finding.model_validate(neutral_finding_payload)
    neutral_judgment = JudgeDecision(
        group_id="synthetic-legacy-actor-defaults",
        status=finding.status,
        severity=finding.severity,
        confidence=finding.confidence,
        rationale="Synthetic actor-neutral legacy judgment.",
    )
    actor_keys = {
        "actor_model_applicability",
        "actor_context",
        "actor_assessment",
    }

    assert {"actor_model_applicability", "actor_context"} <= set(candidate.model_dump(mode="json"))
    assert actor_keys.isdisjoint(neutral_finding.model_dump(mode="json"))
    assert {"actor_model_applicability", "actor_context"} <= set(
        neutral_judgment.model_dump(mode="json")
    )

    context = finding.actor_context
    assert context is not None
    current_candidate_payload = candidate.model_dump(mode="python")
    current_candidate_payload.update(
        {
            "actor_model_applicability": "privileged_actor_required",
            "actor_context": context,
        }
    )
    current_candidate = CandidateFinding.model_validate(current_candidate_payload)
    assert {"actor_model_applicability", "actor_context"} <= set(
        current_candidate.model_dump(mode="json")
    )
    assert {"actor_model_applicability", "actor_context"}.isdisjoint(
        _candidate_payload_for_findings_artifact_version(
            candidate,
            schema_version="1.2",
        )
    )
    assert {"actor_model_applicability", "actor_context"} <= set(
        _candidate_payload_for_findings_artifact_version(
            candidate,
            schema_version="1.3",
        )
    )
    assert {"actor_model_applicability", "actor_context"} <= set(
        _candidate_payload_for_findings_artifact_version(
            current_candidate,
            schema_version="1.2",
        )
    )
    assert actor_keys <= set(finding.model_dump(mode="json"))
    assert {"actor_model_applicability", "actor_context"} <= set(
        _judge_decision_for(finding).model_dump(mode="json")
    )


def test_actor_neutral_legacy_report_and_findings_artifact_remain_compatible() -> None:
    finding, _actor_input, evaluation = _calibrated_finding()
    neutral_payload = finding.model_dump(mode="python")
    neutral_payload.pop("actor_model_applicability")
    neutral_payload.pop("actor_context")
    neutral_payload.pop("actor_assessment")
    neutral_finding = Finding.model_validate(neutral_payload)

    for schema_version in ("1.0", "1.1"):
        report_payload = _legacy_report_payload()
        report_payload["schema_version"] = schema_version
        report_payload["findings"] = [neutral_finding.model_dump(mode="python")]
        assert AuditReport.model_validate(report_payload).findings == [neutral_finding]

    current_report = AuditReport.model_validate(_report_payload(finding, evaluation))
    current_artifact_payload = build_findings_artifact(current_report).model_dump(mode="python")
    for artifact_schema_version in ("1.1", "1.2"):
        artifact_payload = dict(current_artifact_payload)
        artifact_payload["records"] = [dict(current_artifact_payload["records"][0])]
        artifact_payload["schema_version"] = artifact_schema_version
        if artifact_schema_version == "1.1":
            artifact_payload.pop("language_capability")
        artifact_payload.pop("actor_model_baseline")
        artifact_payload.pop("actor_model_evaluation")
        artifact_payload["judge_decisions"] = []
        artifact_payload["findings"] = [neutral_finding.model_dump(mode="python")]
        artifact_payload["records"][0]["finding"] = neutral_finding.model_dump(mode="python")

        legacy_artifact = FindingsArtifact.model_validate(artifact_payload)
        assert legacy_artifact.schema_version == artifact_schema_version
        assert legacy_artifact.findings == [neutral_finding]


def test_legacy_json_schema_branches_constrain_nested_actor_evidence() -> None:
    report_schema = AuditReport.model_json_schema()
    report_branch = next(
        branch
        for branch in report_schema["allOf"]
        if branch["if"]["properties"]["schema_version"] == {"enum": ["1.0", "1.1"]}
    )
    artifact_schema = FindingsArtifact.model_json_schema()
    artifact_branch = next(
        branch
        for branch in artifact_schema["allOf"]
        if branch["if"]["properties"]["schema_version"] == {"enum": ["1.1", "1.2"]}
    )
    expected_actor_constraints = {
        "actor_model_applicability": {"const": "unstated"},
        "actor_context": {"type": "null"},
        "actor_assessment": {"type": "null"},
    }

    for inventory_name in ("findings", "rejected_findings", "filtered_findings"):
        assert (
            report_branch["then"]["properties"][inventory_name]["items"]["properties"]
            == expected_actor_constraints
        )
        assert (
            artifact_branch["then"]["properties"][inventory_name]["items"]["properties"]
            == expected_actor_constraints
        )
    assert (
        artifact_branch["then"]["properties"]["records"]["items"]["properties"]["finding"][
            "properties"
        ]
        == expected_actor_constraints
    )
    expected_candidate_constraints = {
        "actor_model_applicability": {"const": "unstated"},
        "actor_context": {"type": "null"},
    }
    assert (
        artifact_branch["then"]["properties"]["candidate_findings"]["items"]["properties"]
        == expected_candidate_constraints
    )
    assert (
        artifact_branch["then"]["properties"]["records"]["items"]["properties"][
            "candidate_findings"
        ]["items"]["properties"]
        == expected_candidate_constraints
    )


def test_report_13_requires_exact_actor_evaluation() -> None:
    finding, actor_input, evaluation = _calibrated_finding()

    with pytest.raises(ValidationError, match="requires typed actor-model baseline and evaluation"):
        AuditReport.model_validate(_report_payload(finding, None))

    exact_report = AuditReport.model_validate(_report_payload(finding, evaluation))
    assert exact_report.actor_model_evaluation == evaluation
    assert exact_report.judge_decisions == [_judge_decision_for(finding)]

    missing_judge_inventory = _report_payload(finding, evaluation)
    missing_judge_inventory.pop("judge_decisions")
    with pytest.raises(ValidationError, match="explicit judge-decision inventory"):
        AuditReport.model_validate(missing_judge_inventory)

    assessment = finding.actor_assessment
    assert assessment is not None
    wrong_evaluation = ActorModelEvaluation.build(
        evaluated_at=actor_input.evaluated_at,
        input_evidence=actor_input,
        governance_findings=(),
        finding_assessments=(
            ActorFindingAssessmentBinding(
                finding_id="synthetic-other-finding",
                baseline_finding_sha256=assessment.baseline_finding_sha256,
                assessment_sha256=assessment.assessment_sha256,
            ),
        ),
    )
    with pytest.raises(ValidationError, match="differs from report finding assessments"):
        AuditReport.model_validate(_report_payload(finding, wrong_evaluation))


def test_actor_annotation_is_bound_to_exact_retained_judge_decision() -> None:
    finding, actor_input, evaluation = _calibrated_finding()
    report = AuditReport.model_validate(_report_payload(finding, evaluation))
    alternate_scenario = _scenario_payload()["scenarios"][1]
    alternate_context = CandidateActorContext.model_validate(alternate_scenario["actor_context"])
    original_baseline = report.actor_model_baseline
    assert original_baseline is not None
    alternate_baseline_finding = original_baseline.findings[0].finding.model_copy(
        update={"actor_context": alternate_context}
    )
    alternate_baseline = ActorModelBaselineArtifact.build((alternate_baseline_finding,))
    alternate_result = calibrate_finding(
        alternate_baseline_finding,
        actor_context=alternate_context,
        actor_input=actor_input,
    )
    alternate_evaluation = build_actor_model_evaluation(
        actor_input=actor_input,
        findings=(alternate_result.finding,),
        baseline_artifact=alternate_baseline,
        governance_findings=alternate_result.governance_findings,
    )
    payload = report.model_dump(mode="python")
    payload["findings"] = [alternate_result.finding]
    payload["actor_model_baseline"] = alternate_baseline
    payload["actor_model_evaluation"] = alternate_evaluation

    with pytest.raises(ValidationError, match="differs from its retained judge decision"):
        AuditReport.model_validate(payload)

    artifact = build_findings_artifact(report).model_dump(mode="python")
    artifact["findings"] = [alternate_result.finding]
    artifact["records"][0]["finding"] = alternate_result.finding
    artifact["actor_model_baseline"] = alternate_baseline
    artifact["actor_model_evaluation"] = alternate_evaluation
    with pytest.raises(ValidationError, match="differs from its retained judge decision"):
        FindingsArtifact.model_validate(artifact)


def test_actor_judge_inventory_is_canonical_and_exact() -> None:
    finding, _actor_input, evaluation = _calibrated_finding()
    payload = _report_payload(finding, evaluation)
    decision = _judge_decision_for(finding)

    payload["judge_decisions"] = [decision, decision]
    with pytest.raises(ValidationError, match="unique and sorted"):
        AuditReport.model_validate(payload)

    payload["judge_decisions"] = [_judge_decision_for(finding, group_id="unknown-group")]
    with pytest.raises(ValidationError, match="differ from terminal finding groups"):
        AuditReport.model_validate(payload)

    payload["judge_decisions"] = []
    with pytest.raises(ValidationError, match="differs from its retained judge decision"):
        AuditReport.model_validate(payload)


def test_actor_judge_binder_rejects_wrong_group_and_strips_noncurrent_annotation() -> None:
    finding, _actor_input, _evaluation = _calibrated_finding()
    baseline = finding.model_copy(update={"actor_assessment": None})
    decision = _judge_decision_for(finding, group_id="different-group")

    with pytest.raises(ValueError, match="differs from the finding group"):
        bind_judged_actor_context(
            baseline,
            judgment=decision,
            actor_input=_current_actor_input(),
        )

    matching = _judge_decision_for(finding)
    stripped = bind_judged_actor_context(
        baseline,
        judgment=matching,
        actor_input=_missing_actor_input(),
    )
    assert stripped.actor_model_applicability.value == "unstated"
    assert stripped.actor_context is None


def test_judge_schema_rejects_nonprivileged_context_claimed_as_privileged() -> None:
    finding, _actor_input, _evaluation = _calibrated_finding()
    context = finding.actor_context
    assert context is not None
    nonprivileged_context = context.model_copy(
        update={
            "privileged_action_required": False,
            "permission": None,
            "ordinary_legitimate_behavior": False,
            "action_against_stated_interest": False,
            "stated_interest": None,
            "relevant_constraint_ids": (),
            "required_concentrated_role_ids": (),
            "relevant_economic_exposures": (),
            "plausibility_rationale": None,
            "plausibility_evidence_reference_ids": (),
        }
    )

    with pytest.raises(ValidationError, match="must describe privileged conduct"):
        JudgeDecision(
            group_id=finding.group_id or "synthetic-group",
            status=finding.status,
            severity=finding.severity,
            confidence=finding.confidence,
            rationale="Synthetic invalid actor annotation.",
            actor_model_applicability=finding.actor_model_applicability,
            actor_context=nonprivileged_context,
        )


def test_manifest_bound_baseline_rejects_coherent_actor_recalibration_rehash(
    tmp_path: Path,
) -> None:
    finding, actor_input, evaluation = _calibrated_finding()
    exact_report = AuditReport.model_validate(_report_payload(finding, evaluation))
    exact_baseline = exact_report.actor_model_baseline
    assessment = finding.actor_assessment
    assert exact_baseline is not None
    assert assessment is not None

    fake_baseline_finding = exact_baseline.findings[0].finding.model_copy(
        update={"severity": Severity.CRITICAL}
    )
    fake_baseline = ActorModelBaselineArtifact.build((fake_baseline_finding,))
    fake_assessment = _rebuilt_assessment(
        assessment,
        baseline_finding_sha256=fake_baseline.findings[0].finding_sha256,
        original_severity=ActorSeverity.CRITICAL,
        calibrated_severity=ActorSeverity.HIGH,
    )
    fake_finding = finding.model_copy(
        update={"severity": Severity.HIGH, "actor_assessment": fake_assessment}
    )
    fake_evaluation = build_actor_model_evaluation(
        actor_input=actor_input,
        findings=(fake_finding,),
        baseline_artifact=fake_baseline,
        governance_findings=evaluation.governance_findings,
    )

    payload = exact_report.model_dump(mode="python")
    payload["findings"] = [fake_finding]
    payload["actor_model_evaluation"] = fake_evaluation
    with pytest.raises(ValidationError, match="retained calibration baseline"):
        AuditReport.model_validate(payload)

    payload["actor_model_baseline"] = fake_baseline
    coherently_rehashed_report = AuditReport.model_validate(payload)
    (tmp_path / "actor-model-baseline.json").write_text(
        json.dumps(exact_baseline.model_dump(mode="json")),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="baseline artifact differs"):
        _validate_actor_model_baseline_artifact(tmp_path, coherently_rehashed_report)


def test_report_rejects_actor_evaluation_after_report_generation() -> None:
    finding, _actor_input, evaluation = _calibrated_finding()
    payload = _report_payload(finding, evaluation)
    payload["generated_at"] = evaluation.evaluated_at - timedelta(seconds=1)

    with pytest.raises(ValidationError, match="occurs after report generation"):
        AuditReport.model_validate(payload)


@pytest.mark.parametrize("input_kind", ["missing", "stale"])
def test_report_13_discloses_noncurrent_actor_input_on_every_severity(
    input_kind: str,
) -> None:
    finding, current_input, _evaluation = _calibrated_finding()
    if input_kind == "missing":
        actor_input = _missing_actor_input()
    else:
        source = current_input.source_evidence
        assert source is not None
        actor_input = ActorModelInputEvidence.build(
            evaluated_at=datetime(2027, 2, 1, tzinfo=UTC),
            state=ActorModelInputState.STALE,
            configured=True,
            configured_path=current_input.configured_path,
            source_evidence=source,
            limitations=("Synthetic actor evidence is stale.",),
        )
    baseline = bind_judged_actor_context(
        finding.model_copy(update={"actor_assessment": None}),
        judgment=None,
        actor_input=actor_input,
    )
    recalibrated = calibrate_finding(
        baseline,
        actor_context=baseline.actor_context,
        actor_input=actor_input,
    ).finding
    evaluation = build_actor_model_evaluation(
        actor_input=actor_input,
        findings=(recalibrated,),
        baseline_artifact=_actor_baseline(recalibrated),
        governance_findings=(),
    )

    report = AuditReport.model_validate(_report_payload(recalibrated, evaluation))
    artifact = build_findings_artifact(report)

    assessment = report.findings[0].actor_assessment
    assert assessment is not None
    assert assessment.input_state.value == input_kind
    assert assessment.limitation is not None
    assert artifact.actor_model_evaluation == evaluation


def test_report_13_accepts_explicit_nonprivileged_finding_with_missing_actor_input() -> None:
    finding, _current_input, _evaluation = _calibrated_finding()
    payload = finding.model_dump(mode="python")
    payload.update(
        {
            "id": "synthetic-nonprivileged-missing-input",
            "group_id": "group-synthetic-nonprivileged-missing-input",
            "actor_model_applicability": "no_privileged_actor_required",
            "actor_context": None,
            "actor_assessment": None,
        }
    )
    uncalibrated = Finding.model_validate(payload)
    actor_input = _missing_actor_input()
    uncalibrated = bind_judged_actor_context(
        uncalibrated,
        judgment=None,
        actor_input=actor_input,
    )
    calibrated = calibrate_finding(
        uncalibrated,
        actor_context=uncalibrated.actor_context,
        actor_input=actor_input,
    ).finding
    evaluation = build_actor_model_evaluation(
        actor_input=actor_input,
        findings=(calibrated,),
        baseline_artifact=_actor_baseline(calibrated),
        governance_findings=(),
    )

    report = AuditReport.model_validate(_report_payload(calibrated, evaluation))
    artifact = build_findings_artifact(report)

    assessment = report.findings[0].actor_assessment
    assert assessment is not None
    assert assessment.disposition.value == "actor_model_missing"
    assert assessment.limitation is not None
    assert artifact.actor_model_evaluation == evaluation


def test_findings_artifact_propagates_and_revalidates_actor_evaluation() -> None:
    finding, actor_input, evaluation = _calibrated_finding()
    report = AuditReport.model_validate(_report_payload(finding, evaluation))

    artifact = build_findings_artifact(report)
    assert artifact.schema_version == "1.3"
    assert artifact.actor_model_evaluation == evaluation
    assert artifact.findings[0].actor_assessment == finding.actor_assessment

    missing_evaluation = artifact.model_dump(mode="python")
    missing_evaluation.pop("actor_model_evaluation")
    with pytest.raises(ValidationError, match="requires actor-model baseline, evaluation"):
        FindingsArtifact.model_validate(missing_evaluation)

    missing_assessment = artifact.model_dump(mode="python")
    missing_assessment["findings"] = [finding.model_copy(update={"actor_assessment": None})]
    with pytest.raises(ValidationError, match="requires assessment on every finding"):
        FindingsArtifact.model_validate(missing_assessment)

    pre_actor_12_with_evidence = artifact.model_dump(mode="python")
    pre_actor_12_with_evidence["schema_version"] = "1.2"
    with pytest.raises(ValidationError, match="legacy findings artifact cannot carry"):
        FindingsArtifact.model_validate(pre_actor_12_with_evidence)
    legacy_with_judgment = artifact.model_dump(mode="python")
    legacy_with_judgment["schema_version"] = "1.1"
    legacy_with_judgment.pop("language_capability")
    legacy_with_judgment.pop("actor_model_baseline")
    legacy_with_judgment.pop("actor_model_evaluation")
    with pytest.raises(ValidationError, match="legacy findings artifact cannot carry actor judge"):
        FindingsArtifact.model_validate(legacy_with_judgment)
    for legacy_schema_version in ("1.1", "1.2"):
        with pytest.raises(ValueError, match="cannot discard actor-model evidence"):
            build_findings_artifact(report, schema_version=legacy_schema_version)

    assessment = finding.actor_assessment
    assert assessment is not None
    wrong_evaluation = ActorModelEvaluation.build(
        evaluated_at=actor_input.evaluated_at,
        input_evidence=actor_input,
        governance_findings=(),
        finding_assessments=(
            ActorFindingAssessmentBinding(
                finding_id="synthetic-other-finding",
                baseline_finding_sha256=assessment.baseline_finding_sha256,
                assessment_sha256=assessment.assessment_sha256,
            ),
        ),
    )
    payload = artifact.model_dump(mode="python")
    payload["actor_model_evaluation"] = wrong_evaluation
    with pytest.raises(ValidationError, match="differs from finding assessments"):
        FindingsArtifact.model_validate(payload)


def test_findings_artifact_13_preserves_nested_candidate_actor_evidence(
    candidate_factory: Callable[..., CandidateFinding],
) -> None:
    finding, actor_input, _evaluation = _calibrated_finding()
    assessment = finding.actor_assessment
    context = finding.actor_context
    assert assessment is not None
    assert context is not None
    candidate_id = "synthetic-current-actor-candidate"
    baseline_finding = finding.model_copy(
        update={
            "severity": Severity(assessment.original_severity.value),
            "actor_assessment": None,
            "contributing_candidate_ids": [candidate_id],
        }
    )
    baseline = ActorModelBaselineArtifact.build((baseline_finding,))
    calibrated = calibrate_finding(
        baseline_finding,
        actor_context=context,
        actor_input=actor_input,
    ).finding
    evaluation = build_actor_model_evaluation(
        actor_input=actor_input,
        findings=(calibrated,),
        baseline_artifact=baseline,
        governance_findings=(),
    )
    candidate_payload = candidate_factory(candidate_id=candidate_id).model_dump(mode="python")
    candidate_payload.update(
        {
            "actor_model_applicability": "privileged_actor_required",
            "actor_context": context,
        }
    )
    candidate = CandidateFinding.model_validate(candidate_payload)
    report = AuditReport.model_validate(_report_payload(calibrated, evaluation))

    artifact = build_findings_artifact(report, candidates=(candidate,))
    replayed = FindingsArtifact.model_validate_json(artifact.model_dump_json())

    assert artifact.schema_version == "1.3"
    assert artifact.candidate_findings == [candidate]
    assert artifact.records[0].candidate_findings == [candidate]
    assert replayed.candidate_findings[0].actor_context == context
    assert replayed.records[0].candidate_findings[0].actor_context == context


@pytest.mark.parametrize(
    ("tamper", "message"),
    [
        ("severity", "severity differs from its forensic actor calibration"),
        ("input", "differs from forensic input evidence"),
        ("context", "differs from its forensic context"),
        ("governance", "governance conflict lacks forensic custody"),
        ("role", "role facts differ from forensic operator evidence"),
        ("exposure", "exposure facts differ from forensic operator evidence"),
    ],
)
def test_findings_artifact_rejects_actor_custody_tampering(
    tamper: str,
    message: str,
) -> None:
    finding, actor_input, evaluation = _calibrated_finding()
    report = AuditReport.model_validate(_report_payload(finding, evaluation))
    artifact = build_findings_artifact(report)
    assessment = finding.actor_assessment
    assert assessment is not None

    if tamper == "severity":
        tampered_finding = finding.model_copy(update={"severity": Severity.HIGH})
        tampered_evaluation = evaluation
    else:
        assessment_updates: dict[str, dict[str, object]] = {
            "input": {"actor_model_sha256": "0" * 64},
            "context": {"permission": "different synthetic permission"},
            "governance": {"governance_conflict_id": "actor-governance:" + "0" * 64},
            "role": {"concentrated_with_role_ids": ()},
            "exposure": {"holder_fee_revenue_exposure": ActorExposureState.NONE},
        }
        updates = assessment_updates[tamper]
        tampered_assessment = _rebuilt_assessment(assessment, **updates)
        tampered_finding = finding.model_copy(update={"actor_assessment": tampered_assessment})
        tampered_evaluation = build_actor_model_evaluation(
            actor_input=actor_input,
            findings=(tampered_finding,),
            baseline_artifact=_actor_baseline(finding),
            governance_findings=evaluation.governance_findings,
        )

    payload = _artifact_payload_with_finding(
        artifact,
        tampered_finding,
        tampered_evaluation,
    )
    with pytest.raises(ValidationError, match=message):
        FindingsArtifact.model_validate(payload)


def test_actor_calibration_projects_to_markdown_client_and_sarif() -> None:
    finding, _actor_input, evaluation = _calibrated_finding()
    report = AuditReport.model_validate(_report_payload(finding, evaluation))
    artifact = build_findings_artifact(report)

    forensic_markdown = render_markdown(report, findings_artifact=artifact)
    client_markdown = render_client_markdown(report, {_SOURCE_PATH: _SOURCE})
    sarif = generate_report_sarif(report, findings_artifact=artifact)
    sarif_actor = sarif["runs"][0]["results"][0]["properties"]["actorModel"]
    assessment = finding.actor_assessment
    assert assessment is not None

    assert "## Operator actor and incentive evidence" in forensic_markdown
    assert "- Input state: `current`" in forensic_markdown
    assert "- Severity: `high` → `medium`" in forensic_markdown
    assert "- Remediation focus: `economic_plausibility`" in forensic_markdown
    assert (
        "Actor-model basis: aligned\\_action\\_unjustified; likelihood decreased; "
        "severity high → medium; input current." in client_markdown
    )
    assert "Actor-aware remediation:" in client_markdown
    assert sarif_actor["inputState"] == "current"
    assert sarif_actor["disposition"] == "aligned_action_unjustified"
    assert sarif_actor["roleId"] == "anchor_curator"
    assert sarif_actor["originalSeverity"] == "high"
    assert sarif_actor["calibratedSeverity"] == "medium"
    assert sarif_actor["likelihoodAdjustment"] == "decreased"
    assert sarif_actor["remediationFocus"] == "economic_plausibility"
    assert sarif_actor["concentratedWithRoleIds"] == ["risk_council"]
    assert sarif_actor["assessmentSha256"] == assessment.assessment_sha256
    assert sarif_actor["limitation"] is None


def test_ordinary_behavior_supersedes_attack_framing_in_every_user_projection() -> None:
    scenario = _scenario_payload()["scenarios"][1]
    context = CandidateActorContext.model_validate(scenario["actor_context"])
    baseline_finding = _finding(
        finding_id=scenario["finding_id"],
        severity=Severity.MEDIUM,
        actor_context=context,
    ).model_copy(
        update={
            "title": "Synthetic servicer attack drains users",
            "summary": "A malicious synthetic servicer attacks users through forbearance.",
            "impact": "The attacker drains every synthetic user.",
            "attack_path": ["A synthetic servicer uses an authorized forbearance transition."],
            "recommendation": "Remove all synthetic servicer authority.",
        }
    )
    location = baseline_finding.locations[0].model_copy(
        update={"content_hash": line_range_hash(_SOURCE, 1, 1)}
    )
    baseline_finding = baseline_finding.model_copy(update={"locations": [location]})

    current_input = _current_actor_input()
    current_result = calibrate_finding(
        baseline_finding,
        actor_context=context,
        actor_input=current_input,
    )
    current_baseline = ActorModelBaselineArtifact.build((baseline_finding,))
    current_evaluation = build_actor_model_evaluation(
        actor_input=current_input,
        findings=(current_result.finding,),
        baseline_artifact=current_baseline,
        governance_findings=current_result.governance_findings,
    )
    current_report = AuditReport.model_validate(
        _report_payload(current_result.finding, current_evaluation)
    )
    current_artifact = build_findings_artifact(current_report)
    forensic = render_markdown(current_report, findings_artifact=current_artifact)
    client = render_client_markdown(current_report, {_SOURCE_PATH: _SOURCE})
    sarif = generate_report_sarif(current_report, findings_artifact=current_artifact)
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    result = sarif["runs"][0]["results"][0]

    assert "### Ordinary legitimate behavior finding" in forensic
    assert "Legitimate behavior path:" in forensic
    assert "ordinary authorized state transition" in forensic
    assert "Submitted model title (superseded): Synthetic servicer attack drains users" in forensic
    assert "### Ordinary legitimate behavior finding" in client
    assert "Legitimate behavior path:" in client
    assert "authorized legitimate state transition must preserve" in client
    assert 'unsafe condition "Synthetic servicer attack drains users"' not in client
    assert "Submitted model title (superseded): Synthetic servicer attack drains users" in client
    assert rule["shortDescription"]["text"] == "Ordinary legitimate behavior finding"
    assert "ordinary authorized state transition" in rule["fullDescription"]["text"]
    assert baseline_finding.summary not in result["message"]["text"]
    assert rule["help"]["text"] != baseline_finding.recommendation
    assert result["properties"]["submittedModelTitle"] == baseline_finding.title
    assert result["properties"]["submittedModelFramingSuperseded"] is True

    missing_input = _missing_actor_input()
    missing_baseline = bind_judged_actor_context(
        baseline_finding,
        judgment=None,
        actor_input=missing_input,
    )
    missing_result = calibrate_finding(
        missing_baseline,
        actor_context=missing_baseline.actor_context,
        actor_input=missing_input,
    )
    missing_evaluation = build_actor_model_evaluation(
        actor_input=missing_input,
        findings=(missing_result.finding,),
        baseline_artifact=ActorModelBaselineArtifact.build((missing_baseline,)),
        governance_findings=missing_result.governance_findings,
    )
    missing_report = AuditReport.model_validate(
        _report_payload(missing_result.finding, missing_evaluation)
    )
    missing_client = render_client_markdown(missing_report, {_SOURCE_PATH: _SOURCE})
    assert "### Synthetic servicer attack drains users" in missing_client
    assert "Reachable path:" in missing_client
    assert baseline_finding.recommendation in missing_client


def test_actor_governance_is_client_visible_and_a_separate_sarif_result() -> None:
    finding, actor_input, _evaluation = _calibrated_finding()
    source = actor_input.source_evidence
    assert source is not None
    governance = ActorGovernanceFinding.build(
        kind=ActorGovernanceConflictKind.GRAPH_EVIDENCE_INCOMPLETE,
        role_id="graph-evidence",
        source_finding_ids=(),
        detail="synthetic privilege graph evidence is incomplete",
        actor_model_sha256=source.actor_model.artifact_sha256,
    )
    evaluation = build_actor_model_evaluation(
        actor_input=actor_input,
        findings=(finding,),
        baseline_artifact=_actor_baseline(finding),
        governance_findings=(governance,),
    )
    report = AuditReport.model_validate(_report_payload(finding, evaluation))
    artifact = build_findings_artifact(report)

    client_markdown = render_client_markdown(report, {_SOURCE_PATH: _SOURCE})
    sarif = generate_report_sarif(report, findings_artifact=artifact)
    run = sarif["runs"][0]

    assert "## Actor-model evidence and governance" in client_markdown
    assert governance.conflict_id in client_markdown
    assert run["properties"]["actorModel"]["governanceFindingCount"] == 1
    governance_results = [
        result for result in run["results"] if result["ruleId"] == "MMAUDIT-ACTOR-GOVERNANCE"
    ]
    assert len(governance_results) == 1
    assert (
        governance_results[0]["partialFingerprints"]["actorGovernanceConflictId"]
        == governance.conflict_id
    )


def test_nondefault_actor_config_is_canonical_hash_and_override_input(
    config_factory: Callable[..., AuditConfig],
) -> None:
    baseline = config_factory()
    actor_input = _current_actor_input()
    source = actor_input.source_evidence
    assert source is not None
    overrides = audit_config_overrides(
        {
            "actor_model.required": True,
            "actor_model.path": "evidence/operator-actor-model.json",
            "actor_model.expected_subject_id": source.actor_model.subject_id,
            "actor_model.expected_model_sha256": source.actor_model.artifact_sha256,
            "actor_model.expected_source_sha256": source.source_sha256,
        }
    )
    configured = overrides.apply(baseline)
    canonical = canonical_audit_config_json(configured)

    assert [entry.path for entry in overrides.entries] == [
        "actor_model.expected_model_sha256",
        "actor_model.expected_source_sha256",
        "actor_model.expected_subject_id",
        "actor_model.path",
        "actor_model.required",
    ]
    assert configured.actor_model.path == "evidence/operator-actor-model.json"
    assert configured.actor_model.required is True
    assert configured.stable_hash() != baseline.stable_hash()
    assert '"actor_model":{' in canonical
    assert parse_canonical_audit_config(canonical) == configured


def test_manifest_configuration_joins_exact_actor_path_pins_and_run_start(
    config_factory: Callable[..., AuditConfig],
) -> None:
    finding, actor_input, evaluation = _calibrated_finding()
    source = actor_input.source_evidence
    assert source is not None
    report = AuditReport.model_validate(_report_payload(finding, evaluation))
    config = audit_config_overrides(
        {
            "actor_model.path": actor_input.configured_path,
            "actor_model.expected_subject_id": source.actor_model.subject_id,
            "actor_model.expected_model_sha256": source.actor_model.artifact_sha256,
            "actor_model.expected_source_sha256": source.source_sha256,
            "actor_model.required": True,
        }
    ).apply(config_factory())

    _validate_actor_model_configuration(report, config)

    mismatched = config.model_copy(
        update={
            "actor_model": config.actor_model.model_copy(update={"expected_model_sha256": "0" * 64})
        }
    )
    with pytest.raises(ValueError, match="differs from manifest operator pins"):
        _validate_actor_model_configuration(report, mismatched)
