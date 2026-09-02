from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pytest

from mmaudit.agents.specialists import completed_specialist_roles
from mmaudit.config import AuditConfig
from mmaudit.constants import (
    CANDIDATE_DEPENDENT_SPECIALIST_ROLES,
    CANDIDATE_INDEPENDENT_SPECIALIST_ROLES,
    SPECIALIST_INVESTIGATOR_ROLES,
    ExitCode,
)
from mmaudit.models.coverage_planning import (
    ModelPortfolioResourcePreflight,
    ModelPortfolioTaskKind,
    ModelSurfaceCoveragePlan,
)
from mmaudit.models.openrouter import trusted_openrouter_execution_evidence
from mmaudit.models.scheduler import (
    SchedulerActivationStatus,
    SchedulerArtifact,
    SchedulerPassKind,
    SchedulerTaskOutput,
    SchedulerTaskPurpose,
)
from mmaudit.models.schemas import (
    AnalysisState,
    ExecutionEvidenceKind,
    LanguageCapabilityProfile,
    QualityGateResult,
    SpecialistExecutionRecord,
)
from mmaudit.orchestration import pipeline as pipeline_runtime
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntryStatus,
    PortfolioHoldStatus,
    PortfolioSlotStatus,
)
from mmaudit.orchestration.model_coverage import build_model_surface_requests
from tests.conftest import model_registry_entry
from tests.fake_openrouter import FakeOpenRouter
from tests.integration import test_pipeline as pipeline_test_support
from tests.integration.test_pipeline import StaticScannerRunner, _foundry_repo, _run

_MISSING_PRE_DISPATCH_AUTHORITY_REASON = (
    "model review lacked exact journal-derived pre-dispatch authorization"
)


def _compact_solidity_config(
    config_factory: Any,
    *,
    global_input_token_budget: int | None = None,
    per_role_cost_budget_usd: dict[str, float] | None = None,
) -> AuditConfig:
    token_budgets: dict[str, Any] = {}
    if global_input_token_budget is not None:
        token_budgets["global_input_token_budget"] = global_input_token_budget
    if per_role_cost_budget_usd is not None:
        token_budgets["per_role_cost_budget_usd"] = per_role_cost_budget_usd
    return cast(
        AuditConfig,
        config_factory(
            profile="deep",
            language_profile=LanguageCapabilityProfile.SOLIDITY_EVM,
            privacy={"fail_on_detected_secret": False},
            smart_contracts={"compile": False},
            reproduction={"required_for_solidity": False},
            models={"specialists": {}},
            token_budgets=token_budgets,
        ).effective(),
    )


def _candidate_independent_specialist_config(config_factory: Any) -> AuditConfig:
    specialists = {
        role: {
            "primary": f"clean-specialist/security-model-{index}",
            "fallbacks": [],
            "quality_tier": "high",
            "capabilities": ["structured_json", "security_reasoning", "solidity"],
        }
        for index, role in enumerate(CANDIDATE_INDEPENDENT_SPECIALIST_ROLES)
    }
    base_registry = [entry.model_dump(mode="json") for entry in config_factory().models.registry]
    specialist_registry = [model_registry_entry(slot["primary"]) for slot in specialists.values()]
    registry = [*base_registry, *specialist_registry]
    return cast(
        AuditConfig,
        config_factory(
            profile="deep",
            language_profile=LanguageCapabilityProfile.SOLIDITY_EVM,
            privacy={
                "fail_on_detected_secret": False,
                "approved_model_lineages": [entry["root_lineage"] for entry in registry],
            },
            smart_contracts={"compile": False},
            reproduction={"required_for_solidity": False},
            models={"specialists": specialists, "registry": registry},
        ).effective(),
    )


def _coverage_request_surfaces(
    fake: FakeOpenRouter,
    _scheduler: SchedulerArtifact,
    plan: ModelSurfaceCoveragePlan,
) -> dict[str, tuple[str, ...]]:
    task_id_by_request = {(task.review_role, task.surface_ids): task.task_id for task in plan.tasks}
    observed: dict[str, tuple[str, ...]] = {}
    for body in fake.requests:
        metadata = body.get("metadata")
        if not isinstance(metadata, dict):
            continue
        role = metadata.get("mmaudit_role")
        if not isinstance(role, str):
            continue
        user_prompt = body["messages"][1]["content"]
        surface_json = user_prompt.split(
            "<TRUSTED_MODEL_SURFACE_REQUESTS_JSON>\n",
            1,
        )[1].split("\n</TRUSTED_MODEL_SURFACE_REQUESTS_JSON>", 1)[0]
        requested_surfaces = json.loads(surface_json)
        surfaces = tuple(surface["surface_id"] for surface in requested_surfaces)
        task_id = task_id_by_request.get((role, surfaces))
        if task_id is not None:
            observed[task_id] = surfaces
    return observed


def _assert_reopened_coverage_only_adds_missing_authority(
    first_bytes: bytes,
    resumed_bytes: bytes,
) -> None:
    assert resumed_bytes != first_bytes
    first_payload = json.loads(first_bytes)
    resumed_payload = json.loads(resumed_bytes)
    first_references = [
        reference
        for surface in first_payload["coverage"]["surfaces"]
        for reference in surface["evidence_references"]
    ]
    resumed_references = [
        reference
        for surface in resumed_payload["coverage"]["surfaces"]
        for reference in surface["evidence_references"]
    ]
    assert first_references

    def reference_key(reference: dict[str, Any]) -> tuple[str, str, str]:
        return (
            reference["surface_id"],
            reference["request_id"],
            reference["artifact_sha256"],
        )

    first_by_key = {reference_key(reference): reference for reference in first_references}
    resumed_by_key = {reference_key(reference): reference for reference in resumed_references}
    assert len(first_by_key) == len(first_references)
    assert len(resumed_by_key) == len(resumed_references)
    assert first_by_key.keys() == resumed_by_key.keys()

    for key, first_reference in first_by_key.items():
        resumed_reference = resumed_by_key[key]
        assert not first_reference["credited"]
        assert not resumed_reference["credited"]
        first_reasons = set(first_reference["reason"].split("; "))
        resumed_reasons = set(resumed_reference["reason"].split("; "))
        assert _MISSING_PRE_DISPATCH_AUTHORITY_REASON not in first_reasons
        assert resumed_reasons == first_reasons | {_MISSING_PRE_DISPATCH_AUTHORITY_REASON}
        resumed_reference["reason"] = first_reference["reason"]
    assert resumed_payload == first_payload


def _install_bounded_compact_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    original_build_requests = build_model_surface_requests

    def one_authoritative_surface(**kwargs: Any) -> list[Any]:
        return original_build_requests(**kwargs)[:1]

    def feasible_assignment_gate(*_args: Any, **kwargs: Any) -> QualityGateResult:
        return QualityGateResult(
            gate="model_surface_assignment_feasibility",
            required=bool(kwargs.get("required")),
            passed=True,
            detail="bounded synthetic integration fixture",
            state=AnalysisState.DETERMINISTIC,
        )

    monkeypatch.setattr(
        "mmaudit.orchestration.pipeline.build_model_surface_requests",
        one_authoritative_surface,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.pipeline.model_surface_assignment_feasibility_gate",
        feasible_assignment_gate,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.pipeline.plan_model_surface_review_assignments",
        lambda _config, requests, **_kwargs: {"business_logic": list(requests)},
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.pipeline._whole_protocol_review_models",
        lambda *_args, **_kwargs: (),
    )
    # These tests exercise scheduler replay and provider-call conservation, not the
    # expensive truncation-schema self-check already covered by its focused suite.
    monkeypatch.setattr(
        "mmaudit.models.scheduler.candidate_review_protocol_implementation_is_pristine",
        lambda: True,
    )


@pytest.mark.asyncio
async def test_compact_surface_tasks_conserve_exact_requests_and_resume_without_transport(
    config_factory: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _foundry_repo(tmp_path, patched=True)
    config = _compact_solidity_config(config_factory)
    control = tmp_path / "coverage-control"
    control.mkdir(mode=0o700)
    ledger = AtomicCostLedger.initialize(
        (control / "model-cost-ledger.json").resolve(),
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    _install_bounded_compact_fixture(monkeypatch)
    first_fake = FakeOpenRouter(mode="maximum_assurance")
    first = await _run(
        config,
        repository,
        tmp_path,
        first_fake,
        scanner_runner=StaticScannerRunner(),
        cost_ledger=ledger,
    )
    plan = ModelSurfaceCoveragePlan.model_validate_json(
        (first.run_dir / "private" / "model-surface-coverage-plan.json").read_bytes()
    )
    scheduler = SchedulerArtifact.model_validate_json(
        (first.run_dir / "scheduler-state.json").read_bytes()
    )
    expected = {task.task_id: task.surface_ids for task in plan.tasks}
    assert _coverage_request_surfaces(first_fake, scheduler, plan) == expected
    compact_roles = {task.review_role for task in plan.tasks}
    compact_positions = [
        index
        for index, body in enumerate(first_fake.requests)
        if body.get("metadata", {}).get("mmaudit_role") in compact_roles
    ]
    source_positions = [
        index
        for index, body in enumerate(first_fake.requests)
        if body.get("metadata", {}).get("mmaudit_role") == "source_audit"
    ]
    assert compact_positions and source_positions
    assert len(compact_positions) == len(plan.tasks)
    assert max(compact_positions) < min(source_positions)
    public_coverage_before = (first.run_dir / "model-review-coverage.json").read_bytes()

    resumed_fake = FakeOpenRouter(mode="maximum_assurance")
    resumed = await _run(
        config,
        repository,
        tmp_path,
        resumed_fake,
        scanner_runner=StaticScannerRunner(),
        cost_ledger=ledger,
        resume_run_dir=first.run_dir,
    )
    assert resumed_fake.chat_calls == 0
    resumed_coverage_bytes = (resumed.run_dir / "model-review-coverage.json").read_bytes()
    _assert_reopened_coverage_only_adds_missing_authority(
        public_coverage_before,
        resumed_coverage_bytes,
    )


@pytest.mark.asyncio
async def test_resume_after_portfolio_release_before_blind_pass_seal_reuses_initial_transport(
    config_factory: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _foundry_repo(tmp_path, patched=True)
    config = _compact_solidity_config(config_factory)
    _install_bounded_compact_fixture(monkeypatch)
    control = tmp_path / "release-crash-control"
    control.mkdir(mode=0o700)
    ledger_path = (control / "model-cost-ledger.json").resolve()
    ledger = AtomicCostLedger.initialize(
        ledger_path,
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    original_seal_pass_result = pipeline_runtime.PipelineScheduler.seal_pass_result
    blind_seal_interruptions = 0

    def crash_before_blind_pass_seal(scheduler: Any) -> Any:
        nonlocal blind_seal_interruptions
        if scheduler.active_plan.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW:
            blind_seal_interruptions += 1
            raise RuntimeError("synthetic crash after durable portfolio release")
        return original_seal_pass_result(scheduler)

    monkeypatch.setattr(
        pipeline_runtime.PipelineScheduler,
        "seal_pass_result",
        crash_before_blind_pass_seal,
    )
    output = tmp_path / "release-crash-output"
    first_fake = FakeOpenRouter(mode="clean_no_candidates")
    with pytest.raises(RuntimeError, match="synthetic crash after durable portfolio release"):
        await _run(
            config,
            repository,
            tmp_path,
            first_fake,
            scanner_runner=StaticScannerRunner(emit_finding=False),
            cost_ledger=ledger,
            output=output,
        )

    assert blind_seal_interruptions == 1
    interrupted_runs = tuple(path for path in (output / "runs").iterdir() if path.is_dir())
    assert len(interrupted_runs) == 1
    interrupted_run = interrupted_runs[0]
    assert not (
        interrupted_run / "private" / "scheduler-journal" / "pass-results" / "pass-02-result.json"
    ).exists()
    first_request_ids = {
        metadata["mmaudit_request_id"]
        for body in first_fake.requests
        if isinstance((metadata := body.get("metadata")), dict)
        and isinstance(metadata.get("mmaudit_request_id"), str)
    }
    assert first_request_ids
    interrupted_preflight = ModelPortfolioResourcePreflight.model_validate_json(
        (interrupted_run / "private" / "model-portfolio-resource-preflight.json").read_bytes()
    )
    interrupted_ledger = ledger.snapshot()
    assert len(interrupted_ledger.portfolio_holds) == 1
    interrupted_hold = interrupted_ledger.portfolio_holds[0]
    assert interrupted_hold.plan_sha256 == interrupted_preflight.preflight_sha256
    assert interrupted_hold.status is PortfolioHoldStatus.RELEASED
    assert {slot.request_id for slot in interrupted_hold.claimed_slots} == first_request_ids
    assert interrupted_hold.remaining_slots == ()
    interrupted_ledger_bytes = ledger_path.read_bytes()

    monkeypatch.setattr(
        pipeline_runtime.PipelineScheduler,
        "seal_pass_result",
        original_seal_pass_result,
    )
    resumed_fake = FakeOpenRouter(mode="clean_no_candidates")
    resumed = await _run(
        config,
        repository,
        tmp_path,
        resumed_fake,
        scanner_runner=StaticScannerRunner(emit_finding=False),
        cost_ledger=ledger,
        resume_run_dir=interrupted_run,
        output=output,
    )

    assert resumed_fake.chat_calls == 0
    assert resumed_fake.requests == []
    assert {usage.request_id for usage in resumed.report.usage} == first_request_ids
    assert all(
        "lacks its exact active durable hold" not in reason
        for reason in resumed.report.incomplete_reasons
    )
    assert ledger.snapshot() == interrupted_ledger
    assert ledger_path.read_bytes() == interrupted_ledger_bytes
    assert (
        interrupted_run / "private" / "scheduler-journal" / "pass-results" / "pass-02-result.json"
    ).is_file()


@pytest.mark.asyncio
async def test_resumed_failed_blind_context_plan_skips_retained_terminal_results(
    config_factory: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _foundry_repo(tmp_path, patched=True)
    config = _compact_solidity_config(config_factory)
    _install_bounded_compact_fixture(monkeypatch)
    control = tmp_path / "context-failure-resume-control"
    control.mkdir(mode=0o700)
    ledger = AtomicCostLedger.initialize(
        (control / "model-cost-ledger.json").resolve(),
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    original_context_build = pipeline_runtime.ContextBuilder.build

    def fail_source_context(
        builder: Any,
        role: str,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        if role == "source_audit":
            raise pipeline_runtime.ContextBudgetError("synthetic resumed context shortfall")
        return original_context_build(builder, role, *args, **kwargs)

    monkeypatch.setattr(
        pipeline_runtime.ContextBuilder,
        "build",
        fail_source_context,
    )
    original_seal_pass_result = pipeline_runtime.PipelineScheduler.seal_pass_result
    blind_seal_interruptions = 0

    def crash_before_failed_blind_pass_seal(scheduler: Any) -> Any:
        nonlocal blind_seal_interruptions
        if scheduler.active_plan.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW:
            blind_seal_interruptions += 1
            raise RuntimeError("synthetic crash before failed blind pass seal")
        return original_seal_pass_result(scheduler)

    monkeypatch.setattr(
        pipeline_runtime.PipelineScheduler,
        "seal_pass_result",
        crash_before_failed_blind_pass_seal,
    )
    output = tmp_path / "context-failure-resume-output"
    with pytest.raises(RuntimeError, match="synthetic crash before failed blind pass seal"):
        await _run(
            config,
            repository,
            tmp_path,
            FakeOpenRouter(mode="clean_no_candidates"),
            scanner_runner=StaticScannerRunner(emit_finding=False),
            cost_ledger=ledger,
            output=output,
        )

    assert blind_seal_interruptions == 1
    interrupted_runs = tuple(path for path in (output / "runs").iterdir() if path.is_dir())
    assert len(interrupted_runs) == 1
    interrupted_run = interrupted_runs[0]
    result_paths = tuple(
        (interrupted_run / "private" / "scheduler-journal" / "task-results").glob("*.json")
    )
    assert result_paths
    assert not (
        interrupted_run / "private" / "scheduler-journal" / "pass-results" / "pass-02-result.json"
    ).exists()

    monkeypatch.setattr(
        pipeline_runtime.PipelineScheduler,
        "seal_pass_result",
        original_seal_pass_result,
    )
    resumed_fake = FakeOpenRouter(mode="clean_no_candidates")
    resumed = await _run(
        config,
        repository,
        tmp_path,
        resumed_fake,
        scanner_runner=StaticScannerRunner(emit_finding=False),
        cost_ledger=ledger,
        resume_run_dir=interrupted_run,
        output=output,
    )

    assert resumed.exit_code is ExitCode.INCOMPLETE
    assert resumed_fake.chat_calls == 0
    assert resumed_fake.requests == []
    assert (
        interrupted_run / "private" / "scheduler-journal" / "pass-results" / "pass-02-result.json"
    ).is_file()
    assert not (
        interrupted_run / "private" / "scheduler-journal" / "pass-plans" / "pass-03-plan.json"
    ).exists()


@pytest.mark.asyncio
async def test_threat_model_timeout_releases_unused_portfolio_and_resumes_without_transport(
    config_factory: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _foundry_repo(tmp_path, patched=True)
    config = _compact_solidity_config(config_factory)
    _install_bounded_compact_fixture(monkeypatch)
    control = tmp_path / "orientation-timeout-control"
    control.mkdir(mode=0o700)
    ledger_path = (control / "model-cost-ledger.json").resolve()
    ledger = AtomicCostLedger.initialize(
        ledger_path,
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    first_fake = FakeOpenRouter(mode="timeout", role="threat_model")
    first = await _run(
        config,
        repository,
        tmp_path,
        first_fake,
        scanner_runner=StaticScannerRunner(emit_finding=False),
        cost_ledger=ledger,
    )

    assert first_fake.chat_calls == 1
    assert len(first_fake.requests) == 1
    first_metadata = first_fake.requests[0].get("metadata")
    assert isinstance(first_metadata, dict)
    assert first_metadata["mmaudit_role"] == "threat_model"
    first_request_id = first_metadata["mmaudit_request_id"]
    assert isinstance(first_request_id, str)
    portfolio_preflight_path = first.run_dir / "private" / "model-portfolio-resource-preflight.json"
    portfolio_preflight_bytes = portfolio_preflight_path.read_bytes()
    portfolio_preflight = ModelPortfolioResourcePreflight.model_validate_json(
        portfolio_preflight_bytes
    )
    orientation_request_ids = {
        request_id
        for envelope in portfolio_preflight.task_envelopes
        if envelope.task_kind is ModelPortfolioTaskKind.ORIENTATION
        for request_id in envelope.attempt_request_ids
    }
    all_portfolio_request_ids = {
        request_id
        for envelope in portfolio_preflight.task_envelopes
        for request_id in envelope.attempt_request_ids
    }
    assert orientation_request_ids == {first_request_id}

    terminal_ledger = ledger.snapshot()
    assert terminal_ledger.active_reserved_usd == 0
    assert terminal_ledger.held_portfolio_usd == 0
    assert len(terminal_ledger.portfolio_holds) == 1
    portfolio_hold = terminal_ledger.portfolio_holds[0]
    assert portfolio_hold.plan_sha256 == portfolio_preflight.preflight_sha256
    assert portfolio_hold.status is PortfolioHoldStatus.RELEASED
    assert {slot.request_id for slot in portfolio_hold.claimed_slots} == {first_request_id}
    assert {slot.request_id for slot in portfolio_hold.released_slots} == (
        all_portfolio_request_ids - {first_request_id}
    )
    assert portfolio_hold.remaining_slots == ()
    assert len(portfolio_hold.claimed_slots) == 1
    assert len(portfolio_hold.released_slots) == len(portfolio_hold.initial_slots) - 1
    public_coverage_bytes = (first.run_dir / "model-review-coverage.json").read_bytes()
    public_coverage = json.loads(public_coverage_bytes)
    assert (
        public_coverage["portfolio_resource_preflight_sha256"]
        == portfolio_preflight.preflight_sha256
    )
    assert public_coverage["portfolio_reservation_durable"] is True
    assert public_coverage["portfolio_hold_status"] == "released"
    assert public_coverage["portfolio_claimed_slot_count"] == 1
    assert public_coverage["portfolio_released_slot_count"] == len(portfolio_hold.released_slots)
    assert public_coverage["portfolio_held_slot_count"] == 0
    terminal_ledger_bytes = ledger_path.read_bytes()

    resumed_fake = FakeOpenRouter(mode="timeout", role="threat_model")
    resumed = await _run(
        config,
        repository,
        tmp_path,
        resumed_fake,
        scanner_runner=StaticScannerRunner(emit_finding=False),
        cost_ledger=ledger,
        resume_run_dir=first.run_dir,
    )

    assert resumed_fake.chat_calls == 0
    assert resumed_fake.requests == []
    assert ledger.snapshot() == terminal_ledger
    assert ledger_path.read_bytes() == terminal_ledger_bytes
    assert (
        resumed.run_dir / "private" / "model-portfolio-resource-preflight.json"
    ).read_bytes() == portfolio_preflight_bytes
    assert (resumed.run_dir / "model-review-coverage.json").read_bytes() == public_coverage_bytes


@pytest.mark.asyncio
async def test_clean_solidity_runtime_executes_exact_candidate_independent_specialist_portfolio(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    repository = _foundry_repo(tmp_path, patched=True)
    config = _candidate_independent_specialist_config(config_factory)
    assert config.execution.max_model_retries == 0
    control = tmp_path / "clean-coverage-control"
    control.mkdir(mode=0o700)
    ledger_path = (control / "model-cost-ledger.json").resolve()
    ledger = AtomicCostLedger.initialize(
        ledger_path,
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    specialist_model_ids = [slot.primary for slot in config.models.specialists.values()]
    first_fake = FakeOpenRouter(
        mode="clean_no_candidates",
        extra_model_ids=specialist_model_ids,
    )

    first = await _run(
        config,
        repository,
        tmp_path,
        first_fake,
        scanner_runner=StaticScannerRunner(emit_finding=False),
        cost_ledger=ledger,
    )

    assert first.report.findings == []
    assert first.report.rejected_findings == []
    assert first.report.filtered_findings == []
    assert first.report.verification_decisions == []
    assert first.report.usage
    request_roles = tuple(
        metadata["mmaudit_role"]
        for body in first_fake.requests
        if isinstance((metadata := body.get("metadata")), dict)
        and isinstance(metadata.get("mmaudit_role"), str)
    )
    specialist_request_roles = {
        role.removeprefix("specialist:") for role in request_roles if role.startswith("specialist:")
    }
    expected_independent_roles = set(CANDIDATE_INDEPENDENT_SPECIALIST_ROLES)
    expected_dependent_roles = set(CANDIDATE_DEPENDENT_SPECIALIST_ROLES)
    assert specialist_request_roles == expected_independent_roles
    assert len(specialist_request_roles) == len(CANDIDATE_INDEPENDENT_SPECIALIST_ROLES) == 24
    assert specialist_request_roles.isdisjoint(expected_dependent_roles)
    assert {"verifier", "judge"}.isdisjoint(request_roles)

    scheduler = SchedulerArtifact.model_validate_json(
        (first.run_dir / "scheduler-state.json").read_bytes()
    )
    scheduled_roles = {request.role for request in scheduler.model_requests}
    assert {
        role.removeprefix("specialist:")
        for role in scheduled_roles
        if role.startswith("specialist:")
    } == expected_independent_roles
    assert (
        not {f"specialist:{role}" for role in CANDIDATE_DEPENDENT_SPECIALIST_ROLES}
        & scheduled_roles
    )
    assert {"verifier", "judge"}.isdisjoint(scheduled_roles)

    specialist_payload = json.loads(
        (first.run_dir / "specialist-execution.json").read_text(encoding="utf-8")
    )
    specialist_records = [
        SpecialistExecutionRecord.model_validate(record) for record in specialist_payload["records"]
    ]
    records_by_role = {record.role: record for record in specialist_records}
    configured_roles = {record.role for record in specialist_records if record.configured}
    assert configured_roles == expected_independent_roles
    assert len(
        {records_by_role[role].schema_name for role in CANDIDATE_INDEPENDENT_SPECIALIST_ROLES}
    ) == len(CANDIDATE_INDEPENDENT_SPECIALIST_ROLES)
    for role in CANDIDATE_INDEPENDENT_SPECIALIST_ROLES:
        record = records_by_role[role]
        assert record.status.value == "completed"
        assert record.execution_evidence is ExecutionEvidenceKind.MOCK
        assert record.successful_requests > 0
        assert record.failed_requests == 0
        assert set(record.successful_request_ids) == {
            outcome.request_id for outcome in record.accepted_outcomes
        }
    for role in CANDIDATE_DEPENDENT_SPECIALIST_ROLES:
        record = records_by_role[role]
        assert not record.configured
        assert record.status.value == "not_configured"
        assert record.successful_requests == record.failed_requests == 0
        assert record.accepted_outcomes == ()
    assert completed_specialist_roles(specialist_records) == set()

    coverage = first.report.model_review_coverage
    assert coverage is not None
    assert coverage.overall.numerator == 0
    assert all(not surface.reviewed for surface in coverage.surfaces)
    assert all(
        usage.execution_evidence is ExecutionEvidenceKind.MOCK
        and usage.attempts == 1
        and usage.retry_count == 0
        and usage.reported_cost_usd_exact is not None
        and Decimal(usage.reported_cost_usd_exact) == Decimal("0.001")
        and usage.accounted_cost_usd_exact is not None
        and Decimal(usage.accounted_cost_usd_exact) == Decimal("0.001")
        for usage in first.report.usage
    )

    output_paths = sorted(
        (first.run_dir / "private" / "scheduler-journal" / "task-outputs").glob("*.json")
    )
    scheduler_outputs = tuple(
        SchedulerTaskOutput.model_validate_json(path.read_bytes()) for path in output_paths
    )
    retained_usage = {
        output.model_completion_evidence.usage_record.request_id: (
            output.model_completion_evidence.usage_record
        )
        for output in scheduler_outputs
        if output.model_completion_evidence is not None
    }
    report_usage = {usage.request_id: usage for usage in first.report.usage}
    assert retained_usage == report_usage
    scheduler_requests_by_id = {
        request.logical_request_id: request for request in scheduler.model_requests
    }
    untransported_request_ids = set(scheduler_requests_by_id) - set(report_usage)
    assert set(scheduler_requests_by_id) == set(report_usage) | untransported_request_ids
    assert untransported_request_ids
    assert all(
        scheduler_requests_by_id[request_id].purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
        and scheduler_requests_by_id[request_id].activation_status
        is SchedulerActivationStatus.PREFLIGHT_FAILED
        for request_id in untransported_request_ids
    )
    request_ids = {
        metadata["mmaudit_request_id"]
        for body in first_fake.requests
        if isinstance((metadata := body.get("metadata")), dict)
        and isinstance(metadata.get("mmaudit_request_id"), str)
    }
    assert request_ids == set(report_usage)
    assert first_fake.chat_calls == len(first_fake.requests) == len(report_usage)

    portfolio_preflight_path = first.run_dir / "private" / "model-portfolio-resource-preflight.json"
    portfolio_preflight = ModelPortfolioResourcePreflight.model_validate_json(
        portfolio_preflight_path.read_bytes()
    )
    assert portfolio_preflight.feasible is True
    assert portfolio_preflight.candidate_independent_request_roles == tuple(
        f"specialist:{role}" for role in SPECIALIST_INVESTIGATOR_ROLES
    )
    assert all(
        len(envelope.attempt_request_ids) == 1 for envelope in portfolio_preflight.task_envelopes
    )
    portfolio_request_ids = {
        request_id
        for envelope in portfolio_preflight.task_envelopes
        for request_id in envelope.attempt_request_ids
    }
    public_coverage = json.loads(
        (first.run_dir / "model-review-coverage.json").read_text(encoding="utf-8")
    )
    assert (
        public_coverage["portfolio_resource_preflight_sha256"]
        == portfolio_preflight.preflight_sha256
    )
    assert (
        public_coverage["portfolio_resource_preflight_scope"]
        == "orientation_compact_source_audit_whole_protocol_all_attempts"
    )
    assert public_coverage["portfolio_resource_preflight_position"] == "before_paid_orientation"
    assert public_coverage["portfolio_reservation_durable"] is True

    terminal_ledger = ledger.snapshot()
    assert terminal_ledger.active_reserved_usd == 0
    assert terminal_ledger.held_portfolio_usd == 0
    assert len(terminal_ledger.entries) == len(report_usage)
    assert {entry.request_id for entry in terminal_ledger.entries} == set(report_usage)
    assert all(
        entry.status is CostEntryStatus.RECONCILED
        and entry.actual_cost_usd == Decimal("0.001")
        and entry.accounted_cost_usd == Decimal("0.001")
        for entry in terminal_ledger.entries
    )
    assert terminal_ledger.spent_usd == Decimal("0.001") * len(report_usage)
    assert len(terminal_ledger.portfolio_holds) == 1
    portfolio_hold = terminal_ledger.portfolio_holds[0]
    assert portfolio_hold.plan_sha256 == portfolio_preflight.preflight_sha256
    assert portfolio_hold.status is PortfolioHoldStatus.RELEASED
    assert portfolio_hold.remaining_slots == ()
    assert {slot.request_id for slot in portfolio_hold.released_slots} == (
        untransported_request_ids
    )
    assert all(
        slot.status in {PortfolioSlotStatus.CLAIMED, PortfolioSlotStatus.RELEASED}
        for slot in portfolio_hold.slots
    )
    hold_request_ids = {slot.request_id for slot in portfolio_hold.initial_slots}
    post_portfolio_usage_ids = {
        request_id
        for request_id, usage in report_usage.items()
        if usage.role in {"specialist:invariant_review", "specialist:report_quality"}
    }
    assert hold_request_ids == portfolio_request_ids
    transported_portfolio_request_ids = portfolio_request_ids - untransported_request_ids
    assert transported_portfolio_request_ids | post_portfolio_usage_ids == set(report_usage)
    assert portfolio_request_ids.isdisjoint(post_portfolio_usage_ids)
    assert {report_usage[request_id].role for request_id in post_portfolio_usage_ids} == {
        "specialist:invariant_review",
        "specialist:report_quality",
    }
    assert {slot.request_id for slot in portfolio_hold.claimed_slots} == (
        transported_portfolio_request_ids
    )
    assert len(portfolio_hold.initial_slots) == len(portfolio_request_ids)
    assert public_coverage["portfolio_hold_status"] == "released"
    assert public_coverage["portfolio_initial_slot_count"] == len(portfolio_request_ids)
    assert public_coverage["portfolio_claimed_slot_count"] == len(transported_portfolio_request_ids)
    assert public_coverage["portfolio_released_slot_count"] == len(untransported_request_ids)
    assert public_coverage["portfolio_held_slot_count"] == 0
    terminal_ledger_bytes = ledger_path.read_bytes()

    stable_artifact_names = (
        "candidate-findings.json",
        "known-issue-taxonomy-coverage.json",
        "private/model-portfolio-resource-preflight.json",
        "scheduler-state.json",
        "specialist-execution.json",
    )
    stable_artifacts = {name: (first.run_dir / name).read_bytes() for name in stable_artifact_names}
    first_coverage_bytes = (first.run_dir / "model-review-coverage.json").read_bytes()
    resumed_fake = FakeOpenRouter(
        mode="clean_no_candidates",
        extra_model_ids=specialist_model_ids,
    )
    resumed = await _run(
        config,
        repository,
        tmp_path,
        resumed_fake,
        scanner_runner=StaticScannerRunner(emit_finding=False),
        cost_ledger=ledger,
        resume_run_dir=first.run_dir,
    )

    assert resumed_fake.chat_calls == 0
    assert resumed_fake.requests == []
    assert ledger.snapshot() == terminal_ledger
    assert ledger_path.read_bytes() == terminal_ledger_bytes
    assert resumed.report.usage == first.report.usage
    assert {
        name: (resumed.run_dir / name).read_bytes() for name in stable_artifact_names
    } == stable_artifacts
    _assert_reopened_coverage_only_adds_missing_authority(
        first_coverage_bytes,
        (resumed.run_dir / "model-review-coverage.json").read_bytes(),
    )


@pytest.mark.asyncio
async def test_infeasible_compact_resource_preflight_blocks_every_blind_transport(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    repository = _foundry_repo(tmp_path, patched=True)
    config = _compact_solidity_config(
        config_factory,
        global_input_token_budget=100_000,
    )
    fake = FakeOpenRouter()
    result = await _run(
        config,
        repository,
        tmp_path,
        fake,
        scanner_runner=StaticScannerRunner(),
    )

    assert fake.chat_calls == 0
    assert fake.requests == []
    assert result.report.incomplete_reasons
    portfolio_preflight = ModelPortfolioResourcePreflight.model_validate_json(
        (result.run_dir / "private" / "model-portfolio-resource-preflight.json").read_text(
            encoding="utf-8"
        )
    )
    assert portfolio_preflight.feasible is False
    assert "INPUT_TOKEN_CAP_EXCEEDED" in {code.value for code in portfolio_preflight.failure_codes}
    public_coverage = json.loads(
        (result.run_dir / "model-review-coverage.json").read_text(encoding="utf-8")
    )
    assert (
        public_coverage["portfolio_resource_preflight_sha256"]
        == portfolio_preflight.preflight_sha256
    )
    assert public_coverage["portfolio_resource_preflight_position"] == "before_paid_orientation"
    assert public_coverage["portfolio_reservation_durable"] is False
    assert not (result.run_dir / "private" / "model-surface-resource-preflight.json").exists()


@pytest.mark.asyncio
async def test_instance_preview_shadow_is_rejected_before_any_paid_transport(
    config_factory: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _foundry_repo(tmp_path, patched=True)
    config = _compact_solidity_config(config_factory)
    fake = FakeOpenRouter()
    original_provider = pipeline_test_support._provider
    shadow_calls = 0
    observed_execution_evidence: list[ExecutionEvidenceKind] = []

    def provider_with_instance_shadow(*args: Any, **kwargs: Any) -> tuple[Any, Any]:
        nonlocal shadow_calls
        client, http_client = original_provider(*args, **kwargs)
        observed_execution_evidence.append(trusted_openrouter_execution_evidence(client))

        def preview_shadow(**_kwargs: Any) -> Any:
            nonlocal shadow_calls
            shadow_calls += 1
            raise AssertionError("untrusted instance preview shadow was invoked")

        object.__setattr__(
            client,
            "preview_candidate_review_task_resources",
            preview_shadow,
        )
        observed_execution_evidence.append(trusted_openrouter_execution_evidence(client))
        return client, http_client

    monkeypatch.setattr(pipeline_test_support, "_provider", provider_with_instance_shadow)

    result = await _run(
        config,
        repository,
        tmp_path,
        fake,
        scanner_runner=StaticScannerRunner(),
    )

    assert shadow_calls == 0
    assert observed_execution_evidence == [
        ExecutionEvidenceKind.MOCK,
        ExecutionEvidenceKind.MOCK,
    ]
    assert fake.chat_calls == 0
    assert fake.requests == []
    assert any(
        "portfolio resource preview client boundary changed" in reason
        for reason in result.report.incomplete_reasons
    )


@pytest.mark.asyncio
async def test_pipeline_preview_wrapper_shadow_is_rejected_before_blind_transport(
    config_factory: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _foundry_repo(tmp_path, patched=True)
    config = _compact_solidity_config(config_factory)
    fake = FakeOpenRouter()
    shadow_calls = 0

    def preview_wrapper_shadow(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal shadow_calls
        shadow_calls += 1
        raise AssertionError("untrusted pipeline preview wrapper shadow was invoked")

    monkeypatch.setattr(
        pipeline_runtime,
        "trusted_preview_candidate_review_task_resources",
        preview_wrapper_shadow,
    )

    result = await _run(
        config,
        repository,
        tmp_path,
        fake,
        scanner_runner=StaticScannerRunner(),
    )

    assert shadow_calls == 0
    assert fake.chat_calls == 1
    assert any(
        "pipeline candidate-review resource preview dispatch boundary changed" in reason
        for reason in result.report.incomplete_reasons
    )


@pytest.mark.asyncio
async def test_portfolio_preflight_persistence_failure_blocks_orientation_transport(
    config_factory: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _foundry_repo(tmp_path, patched=True)
    config = _compact_solidity_config(config_factory)
    fake = FakeOpenRouter()
    original_persist = pipeline_runtime._persist_private_coverage_evidence

    def fail_portfolio_persistence(path: Path, evidence: Any) -> None:
        if path.name == "model-portfolio-resource-preflight.json":
            raise OSError("synthetic portfolio persistence failure")
        original_persist(path, evidence)

    monkeypatch.setattr(
        pipeline_runtime,
        "_persist_private_coverage_evidence",
        fail_portfolio_persistence,
    )

    result = await _run(
        config,
        repository,
        tmp_path,
        fake,
        scanner_runner=StaticScannerRunner(),
    )

    assert fake.chat_calls == 0
    assert fake.requests == []
    assert any(
        "seven-pass scheduler preflight failed: OSError: "
        "synthetic portfolio persistence failure" in reason
        for reason in result.report.incomplete_reasons
    )
    assert not (result.run_dir / "private" / "model-portfolio-resource-preflight.json").exists()


@pytest.mark.asyncio
async def test_observer_bind_failure_precedes_portfolio_reservation_and_transport(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    repository = _foundry_repo(tmp_path, patched=True)
    config = _compact_solidity_config(config_factory)
    fake = FakeOpenRouter()
    ledger = AtomicCostLedger.initialize(
        tmp_path / "observer-bind-cost-ledger.json",
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    client, http_client = pipeline_test_support._provider(
        config,
        fake,
        atomic_ledger=ledger,
    )
    client.bind_request_lifecycle_observer(cast(Any, object()))
    pipeline = pipeline_runtime.AuditPipeline(
        config,
        repo=repository,
        output=tmp_path / "observer-bind-output",
        client=client,
        scanner_runner=StaticScannerRunner(),
        cost_ledger=ledger,
    )
    try:
        result = await pipeline.run(allow_code_egress=True)
    finally:
        await http_client.aclose()

    assert fake.chat_calls == 0
    assert fake.requests == []
    snapshot = ledger.snapshot()
    assert snapshot.entries == ()
    assert snapshot.portfolio_holds == ()
    assert snapshot.held_portfolio_usd == 0
    assert any(
        "provider request lifecycle observer is already bound" in reason
        for reason in result.report.incomplete_reasons
    )


@pytest.mark.asyncio
async def test_missing_scoped_role_cap_blocks_every_blind_transport(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    repository = _foundry_repo(tmp_path, patched=True)
    config = _compact_solidity_config(
        config_factory,
        per_role_cost_budget_usd={"threat_model": 20.0},
    )
    fake = FakeOpenRouter()

    result = await _run(
        config,
        repository,
        tmp_path,
        fake,
        scanner_runner=StaticScannerRunner(),
    )

    assert fake.chat_calls == 0
    assert fake.requests == []
    portfolio_preflight = ModelPortfolioResourcePreflight.model_validate_json(
        (result.run_dir / "private" / "model-portfolio-resource-preflight.json").read_text(
            encoding="utf-8"
        )
    )
    assert portfolio_preflight.feasible is False
    assert "ROLE_USD_CAP_MISSING" in {code.value for code in portfolio_preflight.failure_codes}
    public_coverage = json.loads(
        (result.run_dir / "model-review-coverage.json").read_text(encoding="utf-8")
    )
    assert (
        public_coverage["portfolio_resource_preflight_sha256"]
        == portfolio_preflight.preflight_sha256
    )
    assert public_coverage["portfolio_resource_preflight_position"] == "before_paid_orientation"
    assert public_coverage["portfolio_reservation_durable"] is False
    assert not (result.run_dir / "private" / "model-surface-resource-preflight.json").exists()
