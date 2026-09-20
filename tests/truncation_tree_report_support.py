"""Original nonempty seven-pass report fixture; synthetic opinions never prove an audit."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from typing import Any

import pytest

from mmaudit.agents.verifier import normalize_cross_examination_response
from mmaudit.config import AuditConfig
from mmaudit.constants import ANALYSIS_ROLES
from mmaudit.models.scheduler import (
    SchedulerCrossShardIntegrationOutput,
    SchedulerEvidenceCapJudgmentOutput,
    SchedulerEvidencePayloadBinding,
    SchedulerFindingReductionOutput,
    SchedulerPassKind,
    SchedulerReportBinding,
    SchedulerTaskPlan,
    scheduler_canonical_sha256,
)
from mmaudit.models.schemas import (
    ActorModelBaselineArtifact,
    CandidateCrossExaminationResponse,
    CandidateFinding,
    FalsificationBatch,
    FindingStatus,
    InvariantReviewResult,
    JudgeDecisionBatch,
    Location,
    MinimumFloorRecoveryModelUsageBinding,
    ModelVote,
    ReportQualityReview,
    Severity,
    VerificationBatch,
)
from mmaudit.models.sharding import SolidityShardReportBinding
from mmaudit.orchestration import manifest, pipeline
from mmaudit.orchestration.actor_model import (
    bind_judged_actor_context,
    build_actor_model_evaluation,
    calibrate_finding,
)
from mmaudit.orchestration.assurance import AssuranceRuntime
from mmaudit.orchestration.candidate_enrichment import (
    attach_consensus_review_votes,
    attach_cross_examination_votes,
)
from mmaudit.orchestration.consensus import (
    enforce_critical_evidence_cap,
    merge_group,
    publication_groups,
)
from mmaudit.orchestration.reproduction_resolution import build_candidate_reproduction_resolutions
from mmaudit.orchestration.run_status import (
    assess_minimum_analysis_floor,
    audit_quality_status_for_run_status,
    minimum_analysis_floor_quality_gate,
)
from mmaudit.solidity.coverage import build_solidity_coverage, with_model_review_coverage
from tests.truncation_tree_manifest_support import (
    ReviewPrivacyFixture,
    ReviewSourceFixture,
    build_review_manifest_report,
)
from tests.unit.test_truncation import _candidate


def candidate_report_config() -> AuditConfig:
    """Declare every synthetic primary route before creating any journal or authority."""

    from mmaudit.config import configured_model_ids
    from tests.conftest import base_config_data, model_registry_entry
    from tests.unit import test_assurance as assurance

    def config_factory(**sections: Any) -> AuditConfig:
        data = base_config_data()
        data["execution"]["budget_usd"] = 250
        for section, values in sections.items():
            if isinstance(data.get(section), dict):
                data[section].update(values)
            else:
                data[section] = values
        return AuditConfig.model_validate(data)

    config = assurance._maximum_config(config_factory)
    data = config.model_dump(mode="json")
    primary_ids = sorted(set(configured_model_ids(config)))
    registered = {entry["canonical_model_id"] for entry in data["models"]["registry"]}
    data["models"]["registry"].extend(
        model_registry_entry(model_id) for model_id in primary_ids if model_id not in registered
    )
    data["privacy"]["approved_model_lineages"] = sorted(
        {entry["root_lineage"] for entry in data["models"]["registry"]}
    )
    # These are the exact deterministic routes authored by the existing synthetic registry.
    data["models"]["provider_policy"]["only"] = [
        f"provider-{index}/fp8" for index in range(len(primary_ids))
    ]
    data["models"]["specialists"]["falsifier"]["fallbacks"] = []
    return AuditConfig.model_validate(data).effective()


def original_candidate_report_fixture(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Any]:
    """Construct a fresh owner behind network/secret traps without leaking those patches."""

    from tests.integration.test_truncation_tree_manifest_files import (
        no_provider_or_operator_secrets,
    )
    from tests.truncation_tree_assurance_support import build_complete_tree_assurance_fixture

    config = candidate_report_config()
    with pytest.MonkeyPatch.context() as patch:
        no_provider_or_operator_secrets.__wrapped__(patch)
        fixture = build_complete_tree_assurance_fixture(
            config,
            tmp_path_factory.mktemp("original-candidate-report") / "private" / "scheduler-journal",
            candidate_report=True,
        )
        try:
            report = fixture.candidate_report.final_report(fixture.runtime)
        except BaseException:
            fixture.close()
            raise
    try:
        yield config, fixture, report
    finally:
        fixture.close()


def _rebind_task(task: SchedulerTaskPlan, journal: Any, **updates: Any) -> SchedulerTaskPlan:
    """Derive new plans before sealing, without changing any completed task."""

    values = {
        name: getattr(task, name)
        for name in (
            "pass_kind",
            "scope",
            "task_kind",
            "task_key",
            "role",
            "input_sha256",
            "prompt_sha256",
            "system_prompt_sha256",
            "normalizer_sha256",
            "requested_model",
            "root_lineage",
            "candidate_ids",
            "response_schema_sha256",
            "model_surface_review_request_manifest_sha256",
        )
    }
    return SchedulerTaskPlan.build(manifest=journal.manifest, **(values | updates))


class TreeCandidateReportState:
    """Build later host inputs from original accepted findings before activation."""

    def __init__(
        self,
        config: AuditConfig,
        source: ReviewSourceFixture,
        privacy: ReviewPrivacyFixture,
        *,
        include_invocation: bool = False,
    ) -> None:
        self.config = config
        self.source = source
        self.privacy = privacy
        self.include_invocation = include_invocation
        self.raw_findings = (
            _candidate("same-synthetic-raw-id").model_copy(
                update={"locations": [Location(path="src/Vault.sol", start_line=7, end_line=9)]}
            ),
        )
        self.candidates: list[CandidateFinding] = []
        self.validations: dict[str, Any] = {}
        self.integration: SchedulerCrossShardIntegrationOutput | None = None
        self.annotations: dict[str, Any] = {}
        self.contexts: dict[str, list[Any]] = {}
        self.origins: dict[str, Any] = {}
        self.baselines: list[Any] = []
        self.report = build_review_manifest_report(
            config,
            source,
            AssuranceRuntime(),
            "250",
            privacy=privacy,
            include_invocation=include_invocation,
        )
        assert self.report.actor_model_evaluation is not None
        self.actor_input = self.report.actor_model_evaluation.input_evidence

    def tasks(
        self, journal: Any, original_plan: Any, tasks: tuple[Any, ...], workset: Any
    ) -> tuple[Any, ...]:
        kind = original_plan.pass_kind
        if kind is SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION:
            templates = sorted(tasks, key=lambda task: task.role)
            assert len(templates) == 2
            return tuple(
                _rebind_task(
                    template,
                    journal,
                    task_key=f"cross:{candidate_id}:{index}",
                    role=(
                        "candidate_falsifier:"
                        + hashlib.sha256(candidate_id.encode()).hexdigest()
                        + f":reviewer_{index}"
                    ),
                    candidate_ids=(candidate_id,),
                )
                for candidate_id in workset.selected_candidate_ids
                for index, template in enumerate(templates, 1)
            )
        if kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION:
            return tuple(
                _rebind_task(task, journal, candidate_ids=workset.selected_candidate_ids)
                if task.candidate_ids
                else task
                for task in tasks
            )
        if kind is SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT:
            groups = tuple(sorted(group.group_id for group in publication_groups(self.candidates)))
            return tuple(
                _rebind_task(
                    task,
                    journal,
                    candidate_ids=groups
                    if task.role == "judge"
                    else tuple(item.candidate_id for item in self.candidates),
                )
                if task.candidate_ids
                else task
                for task in tasks
            )
        return tasks

    def _original_blind_candidates(self, journal: Any) -> None:
        blind = next(
            item
            for item in journal.pass_results
            if item.plan.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
        )
        ids = {task.task_id for task in blind.plan.tasks}
        candidates = [
            candidate
            for output in journal.outputs
            if output.task_id in ids
            for candidate in output.accepted_candidates
        ]
        for task_id in sorted(ids):
            recovered = journal.recovered_candidate_review_output_for_task(task_id)
            if recovered is not None:
                candidates.extend(recovered.recovered_batch.findings)
                for origin in recovered.candidate_origins:
                    pipeline._register_candidate_origin_packages(
                        self.origins,
                        candidate_ids=[origin.accepted_candidate_id],
                        context=self.contexts[origin.request_id][0],
                    )
        for output in journal.outputs:
            if output.task_id in ids and output.accepted_candidates:
                pipeline._register_candidate_origin_packages(
                    self.origins,
                    candidate_ids=[item.candidate_id for item in output.accepted_candidates],
                    context=self.contexts[output.model_completion_evidence.usage_record.request_id][
                        0
                    ],
                )
        self.candidates = sorted(candidates, key=lambda item: item.candidate_id)
        assert len(self.candidates) == len({item.candidate_id for item in self.candidates}) == 9
        self.validations = {
            candidate.candidate_id: pipeline._deterministic_candidate_validation(
                self.source.discovery.root,
                candidate,
                context_hashes=pipeline._candidate_origin_source_hashes(self.origins, candidate),
            )
            for candidate in self.candidates
        }
        assert all(validation.valid for validation in self.validations.values())

    def host_payload(self, journal: Any, plan: Any, task: Any) -> tuple[Any, str]:
        if task.role == "host:finding_reducer":
            self._original_blind_candidates(journal)
            ids = {item.candidate_id for item in self.candidates}
            payload = SchedulerFindingReductionOutput.model_validate(
                pipeline._build_deterministic_finding_reduction(
                    self.candidates,
                    self.validations,
                    blind_candidate_ids=ids,
                    execution_candidate_ids=set(),
                )
            )
            activated = pipeline._finding_reduction_activation_input(
                self.candidates, blind_candidate_ids=ids, execution_candidate_ids=set()
            )
        elif task.role == "host:cross_shard_integrator":
            self.integration = SchedulerCrossShardIntegrationOutput.model_validate(
                pipeline._build_cross_shard_integration(
                    self.source.semantic_shards,
                    self.candidates,
                    self.validations,
                    shard_ids=plan.manifest.shard_ids,
                    invariant_review=InvariantReviewResult(),
                    boundary_surface_requests={},
                    boundary_review_artifacts={},
                    boundary_candidate_ids={},
                    overlap_surface_requests={},
                    overlap_review_artifacts={},
                    overlap_candidate_ids={},
                )
            )
            payload = self.integration
            raw = payload.model_dump(mode="json")
            activated = {
                name: raw[name]
                for name in (
                    "candidate_ids",
                    "candidate_payload_sha256s",
                    "candidate_records",
                    "semantic_inventory_sha256",
                    "shard_ids",
                    "semantic_relationship_ids",
                    "boundary_review_artifact_sha256s",
                    "invariant_review_present",
                    "high_critical_candidate_ids",
                    "validation_candidate_ids",
                )
            } | {"semantic_relationships": raw["relationships"]}
        else:
            assert task.role == "host:evidence_cap_judgment"
            payload = self._judgment(journal, plan)
            activated = payload.model_dump(mode="json")
        return payload, scheduler_canonical_sha256(activated)

    def _judgment(self, journal: Any, plan: Any) -> SchedulerEvidenceCapJudgmentOutput:
        assert self.integration is not None
        task_by_id = {
            task.task_id: task for item in journal.pass_results for task in item.plan.tasks
        } | {task.task_id: task for task in plan.tasks}
        cross: list[Any] = []
        verification: list[Any] = []
        falsification: list[Any] = []
        judges: list[Any] = []
        quality = None
        judge_usage = None
        for output in journal.outputs:
            task = task_by_id[output.task_id]
            if task.pass_kind is SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION:
                usage = output.model_completion_evidence.usage_record
                cross.extend(
                    normalize_cross_examination_response(
                        CandidateCrossExaminationResponse.model_validate(output.payload),
                        candidate_ids={"candidate-0001": task.candidate_ids[0]},
                        request_id=usage.request_id,
                        reviewer_index=int(task.role[-1]),
                        requested_model=task.requested_model,
                        returned_model=usage.returned_model,
                        root_lineage=task.root_lineage,
                    )
                )
            elif task.role == "verifier":
                verification.extend(VerificationBatch.model_validate(output.payload).decisions)
            elif task.role == "specialist:falsifier":
                falsification.extend(FalsificationBatch.model_validate(output.payload).decisions)
            elif task.role == "judge":
                judges.extend(JudgeDecisionBatch.model_validate(output.payload).decisions)
                judge_usage = output.model_completion_evidence.usage_record
            elif task.role == "specialist:report_quality":
                quality = ReportQualityReview.model_validate(output.payload)
        consensus = manifest._reconstruct_scheduler_consensus_review(
            snapshot=manifest._scheduler_report_authority_snapshot(journal)
        )
        assert consensus is not None and judges and judge_usage is not None and quality is not None
        enriched = attach_consensus_review_votes(
            attach_cross_examination_votes(self.candidates, cross), consensus
        )
        enriched, rejected_ids = manifest.apply_reproduction_results(
            enriched, [], FalsificationBatch(decisions=falsification)
        )
        judge_by_group = {item.group_id: item for item in judges}
        groups = publication_groups(enriched)
        active, rejected = [], []
        for group in groups:
            judge = judge_by_group[group.group_id]
            finding = merge_group(
                group,
                decisions={item.candidate_id: item for item in verification},
                validations=self.validations,
                scanner_findings=[],
                judge=judge,
                consensus_review=consensus,
                cross_examinations=cross,
                deterministically_rejected_candidate_ids=rejected_ids,
            )
            finding = enforce_critical_evidence_cap(
                finding,
                require_formal_or_reproduction=(
                    self.config.maximum_assurance.require_formal_or_reproduction_for_confirmed_critical
                ),
            )
            finding = bind_judged_actor_context(
                finding, judgment=judge, actor_input=self.actor_input
            )
            self.baselines.append(finding)
            finding = calibrate_finding(
                finding, actor_context=finding.actor_context, actor_input=self.actor_input
            ).finding
            finding = finding.model_copy(
                update={
                    "model_votes": [
                        *finding.model_votes,
                        ModelVote(
                            role="judge",
                            requested_model=judge_usage.requested_model,
                            returned_model=judge_usage.returned_model,
                            family=judge_usage.model_family,
                            verdict=judge.status.value,
                            rationale=judge.rationale,
                        ),
                    ]
                }
            )
            (rejected if finding.status is FindingStatus.REJECTED else active).append(finding)
        active = pipeline._bind_terminal_finding_source_ranges(
            active,
            source_contents=self.source.sources,
            audited_source_paths=frozenset(self.source.sources),
            scanner_runs=[],
            label="active",
        )
        self.annotations = {
            "findings": active,
            "rejected_findings": rejected,
            "filtered_findings": [],
            "judge_decisions": sorted(judges, key=lambda item: item.group_id),
            "verification_decisions": verification,
            "cross_examination_decisions": cross,
            "falsification_decisions": falsification,
            "consensus_review": consensus,
            "report_quality_review": quality,
        }
        self.resolutions = build_candidate_reproduction_resolutions(
            candidates=self.candidates, results=[]
        )
        terminal = [
            {
                "group_id": finding.group_id,
                "candidate_ids": sorted(finding.contributing_candidate_ids),
                "finding_id": finding.id,
                "finding_payload_sha256": scheduler_canonical_sha256(
                    finding.model_dump(mode="json")
                ),
                "state": state,
                "finding_status": finding.status.value,
                "finding_severity": finding.severity.value,
                "finding_origin_kind": finding.origin_kind.value,
            }
            for state, findings in (("REPORTED_ACTIVE", active), ("REPORTED_REJECTED", rejected))
            for finding in findings
        ]
        terminal.sort(key=lambda item: item["group_id"])
        raw_integration = self.integration.model_dump(mode="json")
        body = {
            "schema_version": "2.0",
            "algorithm": "mmaudit.evidence-cap-terminal-authority.v2",
            "severity_threshold": Severity.INFORMATIONAL.value,
            "critical_confirmation_requires_execution": (
                self.config.maximum_assurance.require_formal_or_reproduction_for_confirmed_critical
            ),
            "group_ids": sorted(group.group_id for group in groups),
            "judge_decision_ids": sorted(judge_by_group),
            "candidate_ids": raw_integration["candidate_ids"],
            "candidate_payload_sha256s": raw_integration["candidate_payload_sha256s"],
            "terminal_candidate_records": raw_integration["candidate_records"],
            "candidate_grouping_sha256": scheduler_canonical_sha256(
                [
                    {name: record[name] for name in ("group_id", "candidate_ids")}
                    for record in terminal
                ]
            ),
            "terminal_findings": terminal,
        }
        for prefix, findings in (("final", active), ("rejected", rejected), ("filtered", [])):
            body[prefix + "_finding_ids"] = sorted(item.id for item in findings)
            body[prefix + "_finding_payload_sha256s"] = {
                item.id: scheduler_canonical_sha256(item.model_dump(mode="json"))
                for item in sorted(findings, key=lambda item: item.id)
            }
        for field, kind, values, identity in (
            ("judge_decisions", "judge", judges, "group_id"),
            ("verification_decisions", "verification", verification, "candidate_id"),
            ("cross_examination_decisions", "cross_examination", cross, "candidate_id"),
            ("falsification_decisions", "falsification", falsification, "candidate_id"),
            ("reproduction_results", "reproduction", [], "candidate_id"),
            (
                "reproduction_resolutions",
                "reproduction_resolution",
                self.resolutions,
                "candidate_id",
            ),
        ):
            body[field] = sorted(
                [
                    SchedulerEvidencePayloadBinding.build(
                        kind=kind, subject_id=getattr(item, identity), payload=item
                    ).model_dump(mode="json")
                    for item in values
                ],
                key=lambda item: (item["subject_id"], item["record_id"]),
            )
        body["consensus_review"] = SchedulerEvidencePayloadBinding.build(
            kind="consensus_review", subject_id=consensus.campaign_id, payload=consensus
        ).model_dump(mode="json")
        return SchedulerEvidenceCapJudgmentOutput.model_validate(
            body | {"judgment_sha256": scheduler_canonical_sha256(body)}
        )

    def final_report(self, runtime: Any) -> Any:
        base = build_review_manifest_report(
            self.config,
            self.source,
            runtime,
            "250",
            privacy=self.privacy,
            include_invocation=self.include_invocation,
        )
        evaluation = build_actor_model_evaluation(
            actor_input=self.actor_input,
            findings=(*self.annotations["findings"], *self.annotations["rejected_findings"]),
            baseline_artifact=ActorModelBaselineArtifact.build(self.baselines),
            governance_findings=(),
        )
        coverage = build_solidity_coverage(
            discovery=self.source.discovery,
            projects=self.source.index.projects,
            compilations=[],
            index=self.source.index,
            graphs=self.source.graphs,
            scanner_runs=[],
            invariants=self.source.invariants,
        )
        coverage = with_model_review_coverage(
            coverage, self.source.index, runtime.model_review_coverage, self.source.graphs
        )
        public = runtime.scheduler_artifact
        leaves = pipeline._require_promoted_recovery_leaf_requests(
            authorities=pipeline._require_current_promoted_recovery_leaf_authorities(
                direct_capabilities=(),
                recursive_capabilities=runtime.promoted_recursive_recovery_surface_coverages,
            ),
            recovery_requests=public.recovery_model_requests,
        )
        credit_usage = pipeline._minimum_floor_creditable_usage_records(
            usage_records=runtime.model_usage,
            successful_request_ids={
                request.logical_request_id
                for request in (*public.model_requests, *public.recovery_model_requests)
                if request.terminal_status.value == "SUCCEEDED"
            },
            all_recovery_requests=public.recovery_model_requests,
            promoted_recovery_leaf_requests=leaves,
        )
        by_request = {record.request_id: record for record in credit_usage}
        bindings = tuple(
            MinimumFloorRecoveryModelUsageBinding.build(
                usage_record=by_request[request.logical_request_id],
                request_limit_scope=request.request_limit_scope,
                request_limit_count_before=request.request_limit_count_before,
                scheduler_request_evidence_sha256=request.request_evidence_sha256,
            )
            for request in leaves
        )
        assert len(bindings) == 4
        floor = assess_minimum_analysis_floor(
            repository=self.source.repository_map,
            compilations=[],
            scanner_runs=[],
            usage=credit_usage,
            required_model_roles=ANALYSIS_ROLES,
            coverage_metrics=coverage.quality_metrics,
            recovery_model_usage_bindings=bindings,
        )
        assert not floor.minimum_floor_met
        assert self.source.graphs.generation_complete
        self.report = base.model_copy(
            update=self.annotations
            | {
                "actor_model_evaluation": evaluation,
                "actor_model_baseline": ActorModelBaselineArtifact.build(self.baselines),
                "solidity_coverage": coverage,
                "minimum_analysis_floor": floor,
                "completed": floor.minimum_floor_met,
                "run_status": floor.run_status,
                "quality_status": audit_quality_status_for_run_status(floor.run_status),
                "incomplete_reasons": [
                    *floor.limitations,
                    "No compiler, scanner, formal or genuine-provider execution supplied.",
                ],
                "quality_gates": [
                    minimum_analysis_floor_quality_gate(floor),
                    *base.quality_gates[1:],
                ],
                "metadata": base.metadata
                | {
                    "severity_threshold": Severity.INFORMATIONAL.value,
                    "scheduler": SchedulerReportBinding.from_artifact(
                        runtime.scheduler_artifact
                    ).model_dump(mode="json"),
                    "solidity": base.metadata["solidity"]
                    | {
                        "index_summary": {
                            "entities": len(self.source.index.entities),
                            "ast_sources": len(self.source.index.ast_sources),
                            "fallback_sources": len(self.source.index.fallback_sources),
                        },
                        "graph_summary": {
                            "edges": len(self.source.graphs.edges),
                            "warnings": len(self.source.graphs.warnings),
                        },
                        "shard_summary": SolidityShardReportBinding.from_inventory(
                            self.source.semantic_shards
                        ).model_dump(mode="json"),
                    },
                },
            }
        )
        assert (
            not self.report.completed
            and not self.report.scanner_runs
            and not self.report.reproductions
        )
        return self.report
