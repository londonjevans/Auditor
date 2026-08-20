from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pytest

from mmaudit.config import AuditConfig
from mmaudit.models.coverage_planning import ModelSurfaceCoveragePlan
from mmaudit.models.openrouter import trusted_openrouter_execution_evidence
from mmaudit.models.scheduler import SchedulerArtifact
from mmaudit.models.schemas import (
    AnalysisState,
    ExecutionEvidenceKind,
    LanguageCapabilityProfile,
    QualityGateResult,
)
from mmaudit.orchestration import pipeline as pipeline_runtime
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.model_coverage import build_model_surface_requests
from tests.fake_openrouter import FakeOpenRouter
from tests.integration import test_pipeline as pipeline_test_support
from tests.integration.test_pipeline import StaticScannerRunner, _foundry_repo, _run


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
    # This test exercises scheduler replay and provider-call conservation, not the
    # expensive truncation-schema self-check already covered by its focused suite.
    monkeypatch.setattr(
        "mmaudit.models.scheduler.candidate_review_protocol_implementation_is_pristine",
        lambda: True,
    )
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
    assert (resumed.run_dir / "model-review-coverage.json").read_bytes() == (public_coverage_before)


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

    assert fake.chat_calls == 1
    assert result.report.incomplete_reasons
    public_coverage = json.loads(
        (result.run_dir / "model-review-coverage.json").read_text(encoding="utf-8")
    )
    assert public_coverage["resource_preflight_scope"] == "compact_surface_gap_tasks_only"
    assert public_coverage["supplemental_blind_spend_included"] is False


@pytest.mark.asyncio
async def test_instance_preview_shadow_is_rejected_before_blind_transport(
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
    assert fake.chat_calls == 1
    assert any(
        "candidate-review resource_preview dispatch boundary changed before provider work" in reason
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

    assert fake.chat_calls == 1
    preflight = json.loads(
        (result.run_dir / "private" / "model-surface-resource-preflight.json").read_text(
            encoding="utf-8"
        )
    )
    assert "ROLE_USD_CAP_MISSING" in preflight["failure_codes"]
