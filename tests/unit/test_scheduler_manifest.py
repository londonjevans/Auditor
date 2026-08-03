from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import BaseModel
from typer.testing import CliRunner

from mmaudit.cli import app
from mmaudit.config import model_lineage_index
from mmaudit.constants import ExitCode
from mmaudit.models.scheduler import (
    ABSENT_QUALIFICATION_SHA256,
    SCHEDULER_ANALYSIS_INPUT_LABELS,
    SchedulerAnalysisInputDescriptor,
    SchedulerAnalysisInputInventory,
    SchedulerArtifact,
    SchedulerBindings,
    SchedulerCampaignManifest,
    SchedulerCampaignSummary,
    SchedulerJournalEvidence,
    SchedulerModelRequestEvidence,
    SchedulerPassKind,
    SchedulerPassPlan,
    SchedulerPassResult,
    SchedulerPrivacyEvidenceCustody,
    SchedulerReportBinding,
    SchedulerScope,
    SchedulerShardInventory,
    SchedulerShardKind,
    SchedulerTaskActivation,
    SchedulerTaskEvent,
    SchedulerTaskEventKind,
    SchedulerTaskKind,
    SchedulerTaskOutput,
    SchedulerTaskPlan,
    SchedulerTaskResult,
    SchedulerTerminalStatus,
    build_scheduler_model_request_evidence,
)
from mmaudit.models.schemas import (
    AuditReport,
    ContextRequestEvidence,
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    RepositoryFile,
    UsageRecord,
)
from mmaudit.orchestration.manifest import (
    build_run_evidence_manifest,
    canonical_sha256,
    validate_manifest_artifacts,
    validate_scheduler_artifact,
    write_run_evidence_manifest,
)
from mmaudit.orchestration.scheduler import (
    SchedulerJournal,
    create_scheduler_journal,
    resume_scheduler_journal,
)
from mmaudit.orchestration.scheduler_runtime import (
    build_scheduler_shard_inventory,
    scheduler_prompt_template_set_sha256,
    scheduler_response_schema_set_sha256,
    scheduler_tool_policy_sha256,
)
from mmaudit.orchestration.verification import (
    RunVerification,
    RunVerificationStatus,
    verify_run_evidence,
)
from mmaudit.privacy import (
    EffectivePrivacyPolicyEvidence,
    EndpointPolicyClass,
    PrivacyProfile,
    PrivacySourceClassification,
)
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.privacy_provenance import PrivacySourceProvenanceEvidence
from tests.scheduler_support import (
    build_scheduler_test_model_payload,
    scheduler_test_response_schema_sha256,
)
from tests.unit.test_manifest import _report, _write_required_artifacts


def _analysis_inventory() -> SchedulerAnalysisInputInventory:
    return SchedulerAnalysisInputInventory.build(
        SchedulerAnalysisInputDescriptor.build(
            label=label,
            type_name="SyntheticProjection",
            value={"label": label},
        )
        for label in SCHEDULER_ANALYSIS_INPUT_LABELS
    )


def _privacy_evidence(
    *,
    source_sha256: str,
    observed_at,
    model_ids: tuple[str, ...],
) -> tuple[PrivacySourceProvenanceEvidence, EffectivePrivacyPolicyEvidence]:
    provenance_values = {
        "schema_version": "1.0",
        "source_classification": PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE.value,
        "source_sha256": source_sha256,
        "proof_kind": "PRIVATE_DEFAULT",
        "distribution_commit": None,
        "distribution_scope": None,
        "committed_file_count": 0,
        "committed_file_inventory_sha256": None,
        "synthetic_declaration_path": None,
        "synthetic_declaration_sha256": None,
        "synthetic_declaration_entry_sha256": None,
        "observed_at": observed_at,
        "limitations": ("Synthetic unit evidence for descriptor-custody validation only.",),
    }
    provisional_provenance = PrivacySourceProvenanceEvidence.model_construct(
        **provenance_values,
        evidence_sha256="0" * 64,
    )
    serialized_provenance = provisional_provenance.model_dump(
        mode="json",
        exclude={"evidence_sha256"},
    )
    provenance = PrivacySourceProvenanceEvidence.model_validate(
        {
            **serialized_provenance,
            "evidence_sha256": canonical_sha256(serialized_provenance),
        }
    )
    policy_values = {
        "schema_version": "1.0",
        "privacy_profile": PrivacyProfile.STRICT_ZDR,
        "source_classification": PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        "source_sha256": source_sha256,
        "source_provenance_sha256": provenance.evidence_sha256,
        "source_proof_kind": "PRIVATE_DEFAULT",
        "source_distribution_commit": None,
        "source_distribution_scope": None,
        "source_synthetic_declaration_sha256": None,
        "source_synthetic_declaration_entry_sha256": None,
        "require_zdr": True,
        "data_collection": "deny",
        "permitted_model_ids": tuple(sorted(set(model_ids))),
        "permitted_provider_endpoints": ("synthetic-provider",),
        "endpoint_policy_classes": (EndpointPolicyClass.ZDR,),
        "endpoint_disclosures": (),
        "consent_file_sha256": None,
        "consent_file_size": None,
        "consent_sha256": None,
        "consent_issued_at": None,
        "consent_expires_at": None,
        "operator_reference_sha256": None,
        "consent_maximum_cost_usd": None,
        "requested_budget_usd": "20",
        "limitations": ("Synthetic unit policy requires zero-data-retention routing.",),
    }
    provisional_policy = EffectivePrivacyPolicyEvidence.model_construct(
        **policy_values,
        evidence_sha256="0" * 64,
    )
    serialized_policy = provisional_policy.model_dump(mode="json", exclude={"evidence_sha256"})
    policy = EffectivePrivacyPolicyEvidence.model_validate(
        {
            **serialized_policy,
            "evidence_sha256": canonical_sha256(serialized_policy),
        }
    )
    return provenance, policy


def _privacy_custody(
    provenance: PrivacySourceProvenanceEvidence,
    policy: EffectivePrivacyPolicyEvidence,
) -> SchedulerPrivacyEvidenceCustody:
    provenance_bytes = stable_json(provenance).encode()
    policy_bytes = stable_json(policy).encode()
    return SchedulerPrivacyEvidenceCustody.build(
        source_sha256=provenance.source_sha256,
        source_provenance_size=len(provenance_bytes),
        source_provenance_artifact_sha256=hashlib.sha256(provenance_bytes).hexdigest(),
        source_provenance_evidence_sha256=provenance.evidence_sha256,
        effective_policy_size=len(policy_bytes),
        effective_policy_artifact_sha256=hashlib.sha256(policy_bytes).hexdigest(),
        effective_policy_evidence_sha256=policy.evidence_sha256,
        policy_source_provenance_sha256=policy.source_provenance_sha256,
    )


def _scheduler_artifact(
    report,
    *,
    config=None,
    shard_inventory: SchedulerShardInventory | None = None,
    terminal_status: SchedulerTerminalStatus = SchedulerTerminalStatus.SUCCEEDED,
) -> tuple[SchedulerArtifact, SchedulerModelRequestEvidence]:
    inventory = shard_inventory or build_scheduler_shard_inventory(report.repository, None)
    prompt_set_sha256 = scheduler_prompt_template_set_sha256()
    tool_policy_sha256 = "5" * 64
    requested_model = "alpha/model"
    root_lineage = "sha256:" + "6" * 64
    if config is not None:
        tool_policy_sha256 = scheduler_tool_policy_sha256(config)
        requested_model = config.models.threat_model.primary
        root_lineage = model_lineage_index(config)[requested_model.lower()].root_lineage
    provenance, policy = _privacy_evidence(
        source_sha256=inventory.source_tree_sha256,
        observed_at=report.generated_at,
        model_ids=(requested_model,),
    )
    privacy_custody = _privacy_custody(provenance, policy)
    bindings = SchedulerBindings.build(
        source_sha256=inventory.source_tree_sha256,
        analysis_input_sha256=_analysis_inventory().analysis_input_sha256,
        effective_config_sha256=report.configuration_hash,
        shard_inventory_sha256=inventory.inventory_sha256,
        model_selection_sha256=report.model_configuration_hash,
        qualification_sha256=ABSENT_QUALIFICATION_SHA256,
        prompt_set_sha256=prompt_set_sha256,
        schema_set_sha256=scheduler_response_schema_set_sha256(),
        tool_policy_sha256=tool_policy_sha256,
        privacy_evidence_custody_sha256=privacy_custody.custody_sha256,
    )
    campaign = SchedulerCampaignManifest.build(
        bindings=bindings,
        shard_inventory=inventory,
        privacy_evidence_custody=privacy_custody,
    )
    response_schema_sha256 = scheduler_test_response_schema_sha256(
        SchedulerPassKind.ORIENTATION,
        "threat_model",
    )
    task = SchedulerTaskPlan.build(
        manifest=campaign,
        pass_kind=SchedulerPassKind.ORIENTATION,
        scope=SchedulerScope.global_scope(),
        task_kind=SchedulerTaskKind.MODEL_REQUEST,
        task_key="threat-model",
        role="threat_model",
        requested_model=requested_model,
        root_lineage=root_lineage,
        input_sha256="1" * 64,
        prompt_sha256=prompt_set_sha256,
        system_prompt_sha256="7" * 64,
        normalizer_sha256="8" * 64,
        response_schema_sha256=response_schema_sha256,
    )
    plan = SchedulerPassPlan.build(
        manifest=campaign,
        pass_kind=SchedulerPassKind.ORIENTATION,
        dependencies=(),
        tasks=(task,),
    )
    user_prompt_sha256 = "2" * 64
    activation = SchedulerTaskActivation.build(
        plan=plan,
        task=task,
        actual_input_sha256=user_prompt_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256=user_prompt_sha256,
        provider_prompt_sha256="3" * 64,
        response_schema_sha256=response_schema_sha256,
    )
    raw_output_payload = build_scheduler_test_model_payload(plan, task)
    assert isinstance(raw_output_payload, BaseModel)
    output_payload = raw_output_payload.model_dump(mode="json")
    normalized_output_sha256 = hashlib.sha256(
        json.dumps(
            output_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    terminal_evidence_sha256 = (
        normalized_output_sha256
        if terminal_status is SchedulerTerminalStatus.SUCCEEDED
        else "9" * 64
    )
    usage = _provider_usage_material(
        report,
        request_id=task.logical_request_id,
        role=task.role,
        requested_model=requested_model,
        root_lineage=root_lineage,
        user_prompt_sha256=user_prompt_sha256,
        provider_prompt_sha256=activation.provider_prompt_sha256 or "0" * 64,
        response_schema_sha256=response_schema_sha256,
        validated_response_sha256=terminal_evidence_sha256,
        privacy_provenance=provenance,
        privacy_policy=policy,
    )
    output = (
        SchedulerTaskOutput.build(
            plan=plan,
            task=task,
            activation=activation,
            payload=output_payload,
            usage_record=usage,
        )
        if terminal_status is SchedulerTerminalStatus.SUCCEEDED
        else None
    )
    result = SchedulerTaskResult.build(
        plan=plan,
        task=task,
        activation=activation,
        terminal_status=terminal_status,
        terminal_evidence_sha256=terminal_evidence_sha256,
        output=output,
    )
    pass_result = SchedulerPassResult.build(plan=plan, task_results=(result,))
    summary = SchedulerCampaignSummary.build(manifest=campaign, pass_results=(pass_result,))
    events: list[SchedulerTaskEvent] = []
    planned = SchedulerTaskEvent.build(
        plan=plan,
        task=task,
        kind=SchedulerTaskEventKind.PLANNED,
        event_index=0,
    )
    events.append(planned)
    activated = SchedulerTaskEvent.build(
        plan=plan,
        task=task,
        kind=SchedulerTaskEventKind.ACTIVATED,
        event_index=1,
        previous_event=planned,
        prior_task_event=planned,
        activation=activation,
    )
    events.append(activated)
    dispatched = SchedulerTaskEvent.build(
        plan=plan,
        task=task,
        kind=SchedulerTaskEventKind.DISPATCHED,
        event_index=2,
        previous_event=activated,
        prior_task_event=activated,
        activation=activation,
        request_id=task.logical_request_id,
    )
    events.append(dispatched)
    events.append(
        SchedulerTaskEvent.build(
            plan=plan,
            task=task,
            kind=SchedulerTaskEventKind.TERMINAL,
            event_index=3,
            previous_event=dispatched,
            prior_task_event=dispatched,
            activation=activation,
            request_id=task.logical_request_id,
            result=result,
        )
    )
    model_requests = build_scheduler_model_request_evidence(
        plans=(plan,),
        activations=(activation,),
        task_results=(result,),
    )
    journal_evidence = SchedulerJournalEvidence.build(
        manifest=campaign,
        analysis_input_inventory=_analysis_inventory(),
        summary=summary,
        plans=(plan,),
        model_requests=model_requests,
        activations=(activation,),
        outputs=(() if output is None else (output,)),
        task_results=(result,),
        result_observations=(result,),
        events=events,
    )
    artifact = SchedulerArtifact.build(
        summary=summary,
        journal_evidence=journal_evidence,
        model_requests=model_requests,
    )
    return artifact, model_requests[0]


def _provider_usage_material(
    report,
    *,
    request_id: str,
    role: str,
    requested_model: str,
    root_lineage: str,
    user_prompt_sha256: str,
    provider_prompt_sha256: str,
    response_schema_sha256: str,
    validated_response_sha256: str,
    privacy_provenance: PrivacySourceProvenanceEvidence,
    privacy_policy: EffectivePrivacyPolicyEvidence,
) -> UsageRecord:
    started_at = report.generated_at
    context = ContextRequestEvidence.build(
        request_id=request_id,
        request_role=role,
        context_role=role,
        byte_budget=100,
        declared_bytes_used=1,
        rendered_bytes=1,
        source_bytes=0,
        configured_maximum_source_tokens_per_request=1,
        effective_source_byte_ceiling=3,
        rendered_sha256=user_prompt_sha256,
    )
    return UsageRecord(
        request_id=request_id,
        role=role,
        execution_evidence=ExecutionEvidenceKind.MOCK,
        requested_model=requested_model,
        returned_model=requested_model,
        actual_model=requested_model,
        provider="Synthetic Provider",
        model_family=requested_model,
        timestamp=started_at,
        prompt_tokens=10,
        completion_tokens=5,
        total_tokens=15,
        reported_cost_usd=0,
        accounted_cost_usd=0,
        routing={
            "qualified_root_lineage": root_lineage,
            "context_request_evidence": context.model_dump(mode="json"),
            "context_request_evidence_sha256": context.evidence_sha256,
            "data_collection": privacy_policy.data_collection,
            "zdr_requested": privacy_policy.require_zdr,
            "privacy_profile": privacy_policy.privacy_profile.value,
            "privacy_authorization": "STRICT_ZDR_ENFORCED",
            "privacy_source_classification": privacy_policy.source_classification.value,
            "privacy_source_sha256": privacy_policy.source_sha256,
            "effective_privacy_policy_sha256": privacy_policy.evidence_sha256,
            "privacy_source_provenance_sha256": privacy_provenance.evidence_sha256,
            "privacy_consent_file_sha256": None,
            "privacy_consent_sha256": None,
            "privacy_consent_expires_at": None,
        },
        prompt_sha256=provider_prompt_sha256,
        user_prompt_sha256=user_prompt_sha256,
        response_sha256="4" * 64,
        validated_response_sha256=validated_response_sha256,
        request_body_sha256="5" * 64,
        schema_sha256=response_schema_sha256,
        openrouter_generation_id="synthetic-generation",
        configured_provider_endpoints=["synthetic-provider"],
        actual_provider_endpoint="synthetic-provider",
        started_at=started_at,
        ended_at=started_at + timedelta(milliseconds=1),
        latency_ms=1,
        finish_reason="stop",
        retry_count=0,
        validation_status=ModelRequestValidationStatus.VALID,
        status="success",
        attempts=1,
    )


def _provider_usage(report, request: SchedulerModelRequestEvidence) -> UsageRecord:
    assert request.user_prompt_sha256 is not None
    assert request.provider_prompt_sha256 is not None
    assert request.response_schema_sha256 is not None
    assert request.terminal_evidence_sha256 is not None
    inventory = build_scheduler_shard_inventory(report.repository, None)
    provenance, policy = _privacy_evidence(
        source_sha256=inventory.source_tree_sha256,
        observed_at=report.generated_at,
        model_ids=(request.requested_model,),
    )
    return _provider_usage_material(
        report,
        request_id=request.logical_request_id,
        role=request.role,
        requested_model=request.requested_model,
        root_lineage=request.root_lineage,
        user_prompt_sha256=request.user_prompt_sha256,
        provider_prompt_sha256=request.provider_prompt_sha256,
        response_schema_sha256=request.response_schema_sha256,
        validated_response_sha256=request.terminal_evidence_sha256,
        privacy_provenance=provenance,
        privacy_policy=policy,
    )


def _non_solidity_report(config):
    report = _report(config)
    repository = report.repository.model_copy(
        update={
            "languages": {"Python": 1},
            "files": [
                RepositoryFile(
                    path="src/safe_target.py",
                    size=17,
                    lines=1,
                    sha256="c" * 64,
                    language="Python",
                )
            ],
        }
    )
    return report.model_copy(update={"repository": repository})


def _with_scheduler(report, artifact: SchedulerArtifact):
    metadata = dict(report.metadata)
    metadata["scheduler"] = SchedulerReportBinding.from_artifact(artifact).model_dump(mode="json")
    custody = artifact.summary.manifest.privacy_evidence_custody
    assert custody is not None
    provenance, policy = _privacy_evidence(
        source_sha256=custody.source_sha256,
        observed_at=report.generated_at,
        model_ids=tuple(item.requested_model for item in artifact.model_requests),
    )
    assert _privacy_custody(provenance, policy) == custody
    privacy = {
        **report.privacy,
        "profile": policy.privacy_profile.value,
        "source_provenance": provenance.model_dump(mode="json"),
        "effective_policy": policy.model_dump(mode="json"),
    }
    return report.model_copy(update={"metadata": metadata, "privacy": privacy})


def _write_privacy_artifacts(run_dir: Path, report) -> None:
    (run_dir / "privacy-source-provenance.json").write_text(
        stable_json(report.privacy["source_provenance"]),
        encoding="utf-8",
    )
    (run_dir / "privacy-policy.json").write_text(
        stable_json(report.privacy["effective_policy"]),
        encoding="utf-8",
    )


def _write_scheduler_run(run_dir: Path, report, artifact: SchedulerArtifact) -> None:
    _write_required_artifacts(run_dir, report)
    _write_privacy_artifacts(run_dir, report)
    private = run_dir / "private"
    private.mkdir(exist_ok=True, mode=0o700)
    journal = create_scheduler_journal(
        private / "scheduler-journal",
        bindings=artifact.summary.manifest.bindings,
        analysis_input_inventory=_analysis_inventory(),
        shard_inventory=artifact.summary.manifest.shard_inventory,
        privacy_evidence_custody=artifact.summary.manifest.privacy_evidence_custody,
    )
    try:
        requests = {item.task_id: item for item in artifact.model_requests}
        for pass_result in artifact.summary.pass_results:
            plan = journal.seal_pass_plan(pass_result.plan)
            for result in pass_result.task_results:
                task = next(item for item in plan.tasks if item.task_id == result.task_id)
                request = requests[task.task_id]
                activation = journal.activate_task(
                    task.task_id,
                    actual_input_sha256=request.actual_input_sha256 or "0" * 64,
                    system_prompt_sha256=request.system_prompt_sha256,
                    user_prompt_sha256=request.user_prompt_sha256,
                    provider_prompt_sha256=request.provider_prompt_sha256,
                    response_schema_sha256=request.response_schema_sha256,
                    delivered_source_descriptor_sha256s=(
                        request.delivered_source_descriptor_sha256s
                    ),
                )
                assert activation.activation_sha256 == request.activation_sha256
                journal.mark_dispatched(task.task_id)
                if result.terminal_status is SchedulerTerminalStatus.SUCCEEDED:
                    raw_payload = build_scheduler_test_model_payload(plan, task)
                    assert isinstance(raw_payload, BaseModel)
                    output = journal.persist_output(
                        task.task_id,
                        raw_payload.model_dump(mode="json"),
                        usage_record=_provider_usage(report, request),
                    )
                    assert output.output_artifact_sha256 == result.output_artifact_sha256
                journal.record_terminal(result)
            assert journal.seal_pass_result(plan.pass_kind) == pass_result
        assert journal.artifact() == artifact
    finally:
        journal.close()
    (run_dir / "scheduler-state.json").write_text(
        artifact.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )


@contextmanager
def _live_scheduler_journal(
    run_dir: Path,
    artifact: SchedulerArtifact,
) -> Iterator[SchedulerJournal]:
    owner = resume_scheduler_journal(
        run_dir / "private" / "scheduler-journal",
        expected_bindings=artifact.summary.manifest.bindings,
        expected_analysis_input_inventory=_analysis_inventory(),
        expected_shard_inventory=artifact.summary.manifest.shard_inventory,
    )
    try:
        yield owner
    finally:
        owner.close()


def test_scheduler_schema_is_generated_strict_and_bounded() -> None:
    schema = json.loads(
        (Path(__file__).parents[2] / "schemas" / "scheduler_state.schema.json").read_text(
            encoding="utf-8"
        )
    )

    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {
        "artifact_sha256",
        "journal_evidence",
        "model_requests",
        "summary",
    }
    assert schema["properties"]["schema_version"]["const"] == "1.0"
    assert schema["properties"]["evidence_authority"]["const"] == "comparison_required"
    assert (
        schema["$defs"]["SchedulerPassResult"]["properties"]["task_results"]["maxItems"] == 100_000
    )


def test_manifest_accepts_exact_scheduler_artifact_and_report_binding(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    report = _non_solidity_report(config)
    artifact, _request = _scheduler_artifact(
        report,
        config=config,
        terminal_status=SchedulerTerminalStatus.INVALID,
    )
    report = _with_scheduler(report, artifact)
    run_dir = tmp_path / "run"
    _write_scheduler_run(run_dir, report, artifact)

    with _live_scheduler_journal(run_dir, artifact) as owner:
        manifest = build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=config,
            scheduler_runtime_journal=owner,
        )

    scheduler_binding = next(
        item for item in manifest.bindings.coverage if item.identifier == "scheduler/artifact"
    )
    assert scheduler_binding.sha256 == artifact.artifact_sha256
    persisted_binding = next(
        item for item in manifest.artifacts if item.path == "scheduler-state.json"
    )
    assert (
        persisted_binding.sha256
        == hashlib.sha256((run_dir / "scheduler-state.json").read_bytes()).hexdigest()
    )
    assert scheduler_binding.details == {
        "artifact": "scheduler-state.json",
        "status": "FAILED",
        "passes": "1",
    }


def test_manifest_issuance_requires_live_scheduler_authority_then_reopens_closed_journal(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    report = _non_solidity_report(config)
    artifact, _request = _scheduler_artifact(
        report,
        config=config,
        terminal_status=SchedulerTerminalStatus.INVALID,
    )
    report = _with_scheduler(report, artifact)
    run_dir = tmp_path / "run"
    _write_scheduler_run(run_dir, report, artifact)
    owner = resume_scheduler_journal(
        run_dir / "private" / "scheduler-journal",
        expected_bindings=artifact.summary.manifest.bindings,
        expected_analysis_input_inventory=_analysis_inventory(),
        expected_shard_inventory=artifact.summary.manifest.shard_inventory,
    )
    try:
        live_artifact = owner.artifact()
        with pytest.raises(ValueError, match="live runtime journal authority"):
            build_run_evidence_manifest(run_dir=run_dir, report=report, config=config)
        with pytest.raises(ValueError, match="owner-held live journal"):
            build_run_evidence_manifest(
                run_dir=run_dir,
                report=report,
                config=config,
                scheduler_runtime_journal=live_artifact,  # type: ignore[arg-type]
            )

        manifest = build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=config,
            scheduler_runtime_journal=owner,
        )
        validate_manifest_artifacts(
            manifest,
            run_dir,
            scheduler_runtime_journal=owner,
        )
    finally:
        owner.close()
    validate_manifest_artifacts(manifest, run_dir)

    other_run = tmp_path / "other-run"
    _write_scheduler_run(other_run, report, artifact)
    with (
        _live_scheduler_journal(other_run, artifact) as other_owner,
        pytest.raises(ValueError, match="path differs"),
    ):
        validate_scheduler_artifact(
            run_dir,
            report,
            config=config,
            scheduler_runtime_journal=other_owner,
        )

    with pytest.raises(ValueError, match="journal custody is closed"):
        validate_scheduler_artifact(
            run_dir,
            report,
            config=config,
            scheduler_runtime_journal=owner,
        )


def test_scheduler_verification_rejects_absent_tampered_and_coherently_resealed_journal(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    base_report = _non_solidity_report(config)

    def write_case(name: str) -> tuple[Path, AuditReport, SchedulerArtifact]:
        artifact, _request = _scheduler_artifact(
            base_report,
            config=config,
            terminal_status=SchedulerTerminalStatus.INVALID,
        )
        report = _with_scheduler(base_report, artifact)
        run_dir = tmp_path / name
        _write_scheduler_run(run_dir, report, artifact)
        return run_dir, report, artifact

    missing_dir, missing_report, missing_artifact = write_case("missing")
    with _live_scheduler_journal(missing_dir, missing_artifact) as owner:
        missing_manifest = build_run_evidence_manifest(
            run_dir=missing_dir,
            report=missing_report,
            config=config,
            scheduler_runtime_journal=owner,
        )
    (missing_dir / "private" / "scheduler-journal").rename(tmp_path / "detached-journal")
    with pytest.raises(ValueError, match="lacks its private journal"):
        validate_scheduler_artifact(missing_dir, missing_report, config=config)
    with pytest.raises(ValueError, match="artifact set"):
        validate_manifest_artifacts(missing_manifest, missing_dir)

    tampered_dir, tampered_report, _artifact = write_case("tampered")
    tampered_manifest = tampered_dir / "private" / "scheduler-journal" / "manifest.json"
    tampered_manifest.write_bytes(tampered_manifest.read_bytes() + b"\n")
    with pytest.raises(ValueError, match=r"not canonical|invalid"):
        validate_scheduler_artifact(tampered_dir, tampered_report, config=config)

    resealed_dir, resealed_report, artifact = write_case("resealed")
    bindings = artifact.summary.manifest.bindings
    changed_bindings = SchedulerBindings.build(
        source_sha256=bindings.source_sha256,
        analysis_input_sha256=bindings.analysis_input_sha256,
        effective_config_sha256=bindings.effective_config_sha256,
        shard_inventory_sha256=bindings.shard_inventory_sha256,
        model_selection_sha256=bindings.model_selection_sha256,
        qualification_sha256=bindings.qualification_sha256,
        prompt_set_sha256=bindings.prompt_set_sha256,
        schema_set_sha256=bindings.schema_set_sha256,
        tool_policy_sha256="a" * 64,
        privacy_evidence_custody_sha256=bindings.privacy_evidence_custody_sha256,
    )
    changed_manifest = SchedulerCampaignManifest.build(
        bindings=changed_bindings,
        shard_inventory=artifact.summary.manifest.shard_inventory,
        privacy_evidence_custody=artifact.summary.manifest.privacy_evidence_custody,
    )
    resealed_manifest = resealed_dir / "private" / "scheduler-journal" / "manifest.json"
    resealed_manifest.write_text(stable_json(changed_manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="verification bindings or shard inventory"):
        validate_scheduler_artifact(resealed_dir, resealed_report, config=config)

    public_dir, _original_report, _original_artifact = write_case("public-resealed")
    coherent_public, _request = _scheduler_artifact(
        base_report,
        config=config,
        terminal_status=SchedulerTerminalStatus.FAILED,
    )
    coherent_report = _with_scheduler(base_report, coherent_public)
    (public_dir / "scheduler-state.json").write_text(
        coherent_public.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="differs from its private journal"):
        validate_scheduler_artifact(public_dir, coherent_report, config=config)


def test_scheduler_report_binding_and_resealed_source_drift_fail_manifest_build(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    report = _non_solidity_report(config)
    artifact, _request = _scheduler_artifact(
        report,
        config=config,
        terminal_status=SchedulerTerminalStatus.INVALID,
    )
    report = _with_scheduler(report, artifact)
    wrong_binding = SchedulerReportBinding.from_artifact(artifact).model_copy(
        update={"scheduler_artifact_sha256": "d" * 64}
    )
    wrong_payload = wrong_binding.model_dump(mode="json", exclude={"binding_sha256"})
    wrong_payload["binding_sha256"] = canonical_sha256(wrong_payload)
    report_with_wrong_binding = report.model_copy(
        update={"metadata": {**report.metadata, "scheduler": wrong_payload}}
    )
    wrong_binding_dir = tmp_path / "wrong-binding"
    _write_scheduler_run(wrong_binding_dir, report_with_wrong_binding, artifact)

    with (
        _live_scheduler_journal(wrong_binding_dir, artifact) as owner,
        pytest.raises(ValueError, match="report binding differs"),
    ):
        build_run_evidence_manifest(
            run_dir=wrong_binding_dir,
            report=report_with_wrong_binding,
            config=config,
            scheduler_runtime_journal=owner,
        )

    changed_source = report.repository.files[0].model_copy(update={"sha256": "e" * 64})
    changed_repository = report.repository.model_copy(update={"files": [changed_source]})
    resealed_inventory = build_scheduler_shard_inventory(changed_repository, None)
    resealed, _task = _scheduler_artifact(
        report,
        config=config,
        shard_inventory=resealed_inventory,
        terminal_status=SchedulerTerminalStatus.INVALID,
    )
    report_with_resealed = _with_scheduler(report, resealed)
    resealed_dir = tmp_path / "resealed"
    _write_scheduler_run(resealed_dir, report_with_resealed, resealed)
    with (
        _live_scheduler_journal(resealed_dir, resealed) as owner,
        pytest.raises(ValueError, match=r"source (?:binding|provenance) differs"),
    ):
        build_run_evidence_manifest(
            run_dir=resealed_dir,
            report=report_with_resealed,
            config=config,
            scheduler_runtime_journal=owner,
        )


def test_scheduler_rejects_orphan_provider_usage_and_requires_exact_success_mapping(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    base_report = _non_solidity_report(config)
    artifact, model_request = _scheduler_artifact(base_report, config=config)
    usage = _provider_usage(base_report, model_request)
    report = _with_scheduler(base_report.model_copy(update={"usage": [usage]}), artifact)
    run_dir = tmp_path / "provider"
    _write_scheduler_run(run_dir, report, artifact)
    assert validate_scheduler_artifact(run_dir, report) == artifact

    orphan = usage.model_copy(update={"request_id": "scheduler-request-" + "0" * 64})
    orphan_report = report.model_copy(update={"usage": [orphan]})
    with pytest.raises(ValueError, match="orphaned"):
        validate_scheduler_artifact(run_dir, orphan_report)

    fallback = usage.model_copy(
        update={
            "request_id": f"{model_request.logical_request_id}:route:2",
            "fallback_used": True,
        }
    )
    fallback_report = report.model_copy(update={"usage": [fallback]})
    with pytest.raises(ValueError, match=r"provider usage|exact creditable"):
        validate_scheduler_artifact(run_dir, fallback_report)

    duplicate_failed = usage.model_copy(update={"status": "failed"})
    duplicate_report = report.model_copy(update={"usage": [duplicate_failed, duplicate_failed]})
    with pytest.raises(ValueError, match="duplicate scheduler request"):
        validate_scheduler_artifact(run_dir, duplicate_report)

    unvalidated = usage.model_copy(
        update={
            "status": "failed",
            "validation_status": ModelRequestValidationStatus.TRUNCATED,
            "validated_response_sha256": None,
        }
    )
    with pytest.raises(ValueError, match=r"provider usage|exact creditable"):
        validate_scheduler_artifact(
            run_dir,
            report.model_copy(update={"usage": [unvalidated]}),
            config=config,
        )

    unqualified = usage.model_copy(update={"routing": {}})
    with pytest.raises(ValueError, match=r"provider usage|exact creditable"):
        validate_scheduler_artifact(
            run_dir,
            report.model_copy(update={"usage": [unqualified]}),
        )

    malformed = usage.model_copy(update={"request_body_sha256": None})
    with pytest.raises(ValueError, match=r"provider usage|exact creditable"):
        validate_scheduler_artifact(
            run_dir,
            report.model_copy(update={"usage": [malformed]}),
            config=config,
        )


def test_scheduler_retains_valid_provider_success_followed_by_host_invalid_result(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    base_report = _non_solidity_report(config)
    artifact, request = _scheduler_artifact(
        base_report,
        config=config,
        terminal_status=SchedulerTerminalStatus.INVALID,
    )
    usage = _provider_usage(base_report, request)
    report = _with_scheduler(base_report.model_copy(update={"usage": [usage]}), artifact)
    run_dir = tmp_path / "host-invalid"
    _write_scheduler_run(run_dir, report, artifact)

    assert validate_scheduler_artifact(run_dir, report, config=config) == artifact
    assert artifact.summary.status.value == "FAILED"


def test_scheduler_retains_crash_output_as_uncertain_without_provider_credit(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    base_report = _non_solidity_report(config)
    planned_artifact, planned_request = _scheduler_artifact(base_report, config=config)
    usage = _provider_usage(base_report, planned_request)
    journal_path = tmp_path / "orphan-journal"
    journal = create_scheduler_journal(
        journal_path,
        bindings=planned_artifact.summary.manifest.bindings,
        analysis_input_inventory=_analysis_inventory(),
        shard_inventory=planned_artifact.summary.manifest.shard_inventory,
        privacy_evidence_custody=planned_artifact.summary.manifest.privacy_evidence_custody,
    )
    plan = journal.seal_pass_plan(planned_artifact.summary.pass_results[0].plan)
    task = plan.tasks[0]
    journal.activate_task(
        task.task_id,
        actual_input_sha256=planned_request.actual_input_sha256 or "0" * 64,
        system_prompt_sha256=planned_request.system_prompt_sha256,
        user_prompt_sha256=planned_request.user_prompt_sha256,
        provider_prompt_sha256=planned_request.provider_prompt_sha256,
        response_schema_sha256=planned_request.response_schema_sha256,
        delivered_source_descriptor_sha256s=(planned_request.delivered_source_descriptor_sha256s),
    )
    journal.mark_dispatched(task.task_id)
    raw_payload = build_scheduler_test_model_payload(plan, task)
    assert isinstance(raw_payload, BaseModel)
    retained = journal.persist_output(
        task.task_id,
        raw_payload.model_dump(mode="json"),
        usage_record=usage,
    )
    journal.close()

    recovered = resume_scheduler_journal(
        journal_path,
        expected_bindings=planned_artifact.summary.manifest.bindings,
        expected_analysis_input_inventory=_analysis_inventory(),
        expected_shard_inventory=planned_artifact.summary.manifest.shard_inventory,
    )
    artifact = recovered.artifact()
    assert artifact.journal_evidence.task_output_artifact_sha256s == (
        retained.output_artifact_sha256,
    )
    assert artifact.journal_evidence.task_output_count == 1
    assert artifact.journal_evidence.succeeded_count == 0
    assert artifact.journal_evidence.uncertain_count == 1
    assert len(recovered.restorable_usage_records) == 1
    assert recovered.restorable_review_usage_records == ()
    assert artifact.model_requests[0].terminal_status is SchedulerTerminalStatus.UNCERTAIN
    assert artifact.model_requests[0].output_artifact_sha256 is None
    recovered.close()

    binding = SchedulerReportBinding.from_artifact(artifact)
    assert binding.task_output_count == 1
    assert binding.succeeded_count == 0
    assert binding.uncertain_count == 1
    report = _with_scheduler(base_report.model_copy(update={"usage": [usage]}), artifact)
    run_dir = tmp_path / "run"
    _write_required_artifacts(run_dir, report)
    _write_privacy_artifacts(run_dir, report)
    private = run_dir / "private"
    private.mkdir(mode=0o700)
    journal_path.rename(private / "scheduler-journal")
    (run_dir / "scheduler-state.json").write_text(
        artifact.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )

    assert validate_scheduler_artifact(run_dir, report, config=config) == artifact


def test_scheduler_reconstructs_exact_mixed_semantic_and_repository_inventory(
    tmp_path: Path,
    config_factory,
) -> None:
    from mmaudit.repository.mapping import build_repository_map
    from tests.unit.test_semantic_sharding import (
        _inventory,
        _report_for_shards,
        _shard_inputs,
        _write_shard_artifacts,
    )

    inputs = _shard_inputs(tmp_path, config_factory)
    semantic_inventory = _inventory(inputs)
    repository = build_repository_map(inputs.discovery)
    exact_inventory = build_scheduler_shard_inventory(repository, semantic_inventory)
    assert {shard.kind for shard in exact_inventory.shards} == {
        SchedulerShardKind.SOLIDITY_SEMANTIC,
        SchedulerShardKind.REPOSITORY_PSEUDO,
    }
    report = _report_for_shards(
        repository=repository,
        index=inputs.index,
        graphs=inputs.graphs,
        inventory=semantic_inventory,
    )
    artifact, _request = _scheduler_artifact(
        report,
        shard_inventory=exact_inventory,
        terminal_status=SchedulerTerminalStatus.INVALID,
    )
    report = _with_scheduler(report, artifact)
    run_dir = tmp_path / "mixed-run"
    _write_scheduler_run(run_dir, report, artifact)
    _write_shard_artifacts(
        run_dir,
        index=inputs.index,
        graphs=inputs.graphs,
        inventory=semantic_inventory,
    )

    assert validate_scheduler_artifact(run_dir, report) == artifact

    semantic_only = SchedulerShardInventory.build(
        semantic_inventory_sha256=semantic_inventory.inventory_sha256,
        shards=(
            shard
            for shard in exact_inventory.shards
            if shard.kind is SchedulerShardKind.SOLIDITY_SEMANTIC
        ),
    )
    stale_artifact, _request = _scheduler_artifact(
        report,
        shard_inventory=semantic_only,
        terminal_status=SchedulerTerminalStatus.INVALID,
    )
    stale_report = _with_scheduler(report, stale_artifact)
    stale_dir = tmp_path / "semantic-only-run"
    _write_scheduler_run(stale_dir, stale_report, stale_artifact)
    _write_shard_artifacts(
        stale_dir,
        index=inputs.index,
        graphs=inputs.graphs,
        inventory=semantic_inventory,
    )
    with pytest.raises(
        ValueError,
        match=r"source binding differs|exact audited shard inventory",
    ):
        validate_scheduler_artifact(stale_dir, stale_report)


def test_scheduler_duplicate_and_orphan_results_are_rejected_before_manifest_credit(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    report = _non_solidity_report(config)
    artifact, _task = _scheduler_artifact(report, config=config)
    payload = artifact.model_dump(mode="json")
    first_pass = payload["summary"]["pass_results"][0]
    first_pass["task_results"].append(dict(first_pass["task_results"][0]))
    path = tmp_path / "scheduler-state.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match=r"unique|exact task plan"):
        SchedulerArtifact.model_validate(json.loads(path.read_text(encoding="utf-8")))

    payload = artifact.model_dump(mode="json")
    payload["summary"]["pass_results"][0]["task_results"][0]["task_id"] = (
        "scheduler-task-" + "0" * 64
    )
    with pytest.raises(ValueError, match=r"planned identity|inconsistent"):
        SchedulerArtifact.model_validate(payload)


def test_current_completed_report_cannot_erase_scheduler_evidence(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    report = _non_solidity_report(config).model_copy(
        update={"schema_version": "1.2", "completed": True}
    )
    run_dir = tmp_path / "missing"
    run_dir.mkdir()

    with pytest.raises(ValueError, match="lacks scheduler evidence"):
        validate_scheduler_artifact(run_dir, report)

    artifact, _task = _scheduler_artifact(report, config=config)
    (run_dir / "scheduler-state.json").write_text(
        artifact.model_dump_json(),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="lacks its final-report binding"):
        validate_scheduler_artifact(run_dir, report)

    incomplete_provider_report = report.model_copy(
        update={
            "completed": False,
            "usage": [
                UsageRecord(
                    request_id="scheduler-request-" + "1" * 64,
                    role="source_audit",
                    requested_model="alpha/model",
                    model_family="alpha/model",
                    timestamp=report.generated_at,
                    accounted_cost_usd=0,
                    routing={},
                    prompt_sha256="2" * 64,
                    status="failed",
                    attempts=1,
                )
            ],
        }
    )
    (run_dir / "scheduler-state.json").unlink()
    with pytest.raises(ValueError, match="provider or completed report"):
        validate_scheduler_artifact(run_dir, incomplete_provider_report)


def test_verify_run_is_stale_after_scheduler_artifact_tampering(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    source_contents = b"synthetic safe\n"
    report = _non_solidity_report(config)
    source_file = report.repository.files[0].model_copy(
        update={
            "size": len(source_contents),
            "sha256": hashlib.sha256(source_contents).hexdigest(),
        }
    )
    report = report.model_copy(
        update={"repository": report.repository.model_copy(update={"files": [source_file]})}
    )
    artifact, _request = _scheduler_artifact(
        report,
        config=config,
        terminal_status=SchedulerTerminalStatus.INVALID,
    )
    report = _with_scheduler(report, artifact)
    run_dir = tmp_path / "run"
    _write_scheduler_run(run_dir, report, artifact)
    with _live_scheduler_journal(run_dir, artifact) as owner:
        manifest = build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=config,
            scheduler_runtime_journal=owner,
        )
    write_run_evidence_manifest(run_dir / "run-evidence-manifest.json", manifest)
    repository = tmp_path / "repository"
    source = repository / "src" / "safe_target.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(source_contents)

    payload = artifact.model_dump(mode="json")
    payload["artifact_sha256"] = "0" * 64
    (run_dir / "scheduler-state.json").write_text(json.dumps(payload), encoding="utf-8")

    verification = verify_run_evidence(
        manifest_path=run_dir / "run-evidence-manifest.json",
        run_dir=run_dir,
        repository_root=repository,
        config=config,
    )
    assert verification.status is RunVerificationStatus.STALE


def test_verify_run_cli_fails_closed_after_scheduler_artifact_tampering(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    source_contents = b"synthetic safe\n"
    report = _non_solidity_report(config)
    source_file = report.repository.files[0].model_copy(
        update={
            "size": len(source_contents),
            "sha256": hashlib.sha256(source_contents).hexdigest(),
        }
    )
    report = report.model_copy(
        update={"repository": report.repository.model_copy(update={"files": [source_file]})}
    )
    artifact, _request = _scheduler_artifact(
        report,
        config=config,
        terminal_status=SchedulerTerminalStatus.INVALID,
    )
    report = _with_scheduler(report, artifact)
    run_dir = tmp_path / "run"
    _write_scheduler_run(run_dir, report, artifact)
    with _live_scheduler_journal(run_dir, artifact) as owner:
        manifest = build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=config,
            scheduler_runtime_journal=owner,
        )
    manifest_path = run_dir / "run-evidence-manifest.json"
    write_run_evidence_manifest(manifest_path, manifest)
    repository = tmp_path / "repository"
    source = repository / "src" / "safe_target.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(source_contents)

    payload = artifact.model_dump(mode="json")
    payload["artifact_sha256"] = "0" * 64
    (run_dir / "scheduler-state.json").write_text(json.dumps(payload), encoding="utf-8")
    output = tmp_path / "run-verification.json"
    result = CliRunner().invoke(
        app,
        [
            "verify-run",
            "--manifest",
            str(manifest_path),
            "--run-dir",
            str(run_dir),
            "--repo",
            str(repository),
            "--output",
            str(output),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.INCOMPLETE, result.stdout
    verification = RunVerification.model_validate_json(output.read_text(encoding="utf-8"))
    assert verification.status is RunVerificationStatus.STALE
    assert verification.mismatches
