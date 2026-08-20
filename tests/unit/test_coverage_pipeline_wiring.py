from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from mmaudit.constants import SPECIALIST_INVESTIGATOR_ROLES
from mmaudit.models.coverage_planning import (
    ModelSurfaceReviewerBinding,
    ModelSurfaceTaskResourcePreview,
    build_model_surface_coverage_plan,
    build_model_surface_resource_preflight,
)
from mmaudit.models.scheduler import (
    SchedulerShardDescriptor,
    SchedulerShardInventory,
    SchedulerSourceDescriptor,
)
from mmaudit.models.schemas import Location, ModelReviewSurfaceKind, ModelSurfaceReviewRequest
from mmaudit.orchestration.model_review_evidence import build_source_file_review_request
from mmaudit.orchestration.pipeline import (
    _load_private_coverage_preflight,
    _model_surface_reviewer_bindings,
    _model_surface_scheduler_scopes,
    _persist_private_coverage_evidence,
)
from tests.conftest import MODEL_IDS


def _source(path: str, content: str) -> tuple[SchedulerSourceDescriptor, str]:
    encoded = content.encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    return SchedulerSourceDescriptor.build(path=path, sha256=digest, size=len(encoded)), digest


def _shard(shard_digit: str, source: SchedulerSourceDescriptor) -> SchedulerShardDescriptor:
    return SchedulerShardDescriptor.semantic(
        shard_id="shard-" + shard_digit * 24,
        semantic_shard_sha256=shard_digit * 64,
        sources=(source,),
    )


def test_surface_scope_mapping_is_exact_for_single_and_cross_shard_requests() -> None:
    first_source, first_digest = _source("src/First.sol", "contract First {}\n")
    second_source, second_digest = _source("src/Second.sol", "contract Second {}\n")
    first_shard = _shard("1", first_source)
    second_shard = _shard("2", second_source)
    inventory = SchedulerShardInventory.build(
        semantic_inventory_sha256="3" * 64,
        shards=(first_shard, second_shard),
    )
    first_request = build_source_file_review_request(
        path=first_source.path,
        size=first_source.size,
        lines=1,
        sha256=first_digest,
    )

    assert _model_surface_scheduler_scopes(
        (first_request,),
        scheduler_inventory=inventory,
        semantic_inventory=None,
        index=None,
    ) == {first_request.surface_id: first_shard.shard_id}

    cross_subject = "cross-shard-call"
    cross_request = ModelSurfaceReviewRequest(
        surface_id=ModelSurfaceReviewRequest.calculate_surface_id(
            ModelReviewSurfaceKind.CALL,
            cross_subject,
        ),
        kind=ModelReviewSurfaceKind.CALL,
        subject_id=cross_subject,
        contract="First",
        function_or_state_surface="First -> Second",
        critical=False,
        allowed_locations=(
            Location(
                path=first_source.path,
                start_line=1,
                end_line=1,
                content_hash=first_digest,
            ),
            Location(
                path=second_source.path,
                start_line=1,
                end_line=1,
                content_hash=second_digest,
            ),
        ),
        invariant_considered="Cross-contract calls preserve authorization boundaries.",
    )
    assert _model_surface_scheduler_scopes(
        (cross_request,),
        scheduler_inventory=inventory,
        semantic_inventory=None,
        index=None,
    ) == {cross_request.surface_id: first_shard.shard_id}


def test_reviewer_binding_inventory_contains_all_24_investigators(
    config_factory: Any,
) -> None:
    specialists = {
        role: {"primary": MODEL_IDS["business_logic"], "fallbacks": []}
        for role in SPECIALIST_INVESTIGATOR_ROLES
    }
    config = config_factory(
        profile="deep",
        models={"specialists": specialists},
    ).effective()

    bindings, mandatory_roles = _model_surface_reviewer_bindings(
        config,
        specialist_roles=SPECIALIST_INVESTIGATOR_ROLES,
        selected_model_ids=None,
    )

    expected_roles = {
        "business_logic",
        "configuration",
        *(f"specialist:{role}" for role in SPECIALIST_INVESTIGATOR_ROLES),
    }
    assert len(bindings) == 24
    assert {binding.review_role for binding in bindings} == expected_roles
    assert set(mandatory_roles) == expected_roles


def test_private_plan_and_preflight_are_exactly_compared_on_resume(tmp_path: Path) -> None:
    source, digest = _source("src/Only.sol", "contract Only {}\n")
    request = build_source_file_review_request(
        path=source.path,
        size=source.size,
        lines=1,
        sha256=digest,
    )
    binding = ModelSurfaceReviewerBinding.build(
        review_role="business_logic",
        requested_model="provider/model",
        root_lineage="sha256:" + "4" * 64,
    )
    plan = build_model_surface_coverage_plan(
        (request,),
        (binding,),
        surface_scope_by_id={request.surface_id: "shard-" + "5" * 24},
        mandatory_reviewer_roles=("business_logic",),
        minimum_t0_root_lineages=1,
    )
    assert len(plan.tasks) == 1
    preview = ModelSurfaceTaskResourcePreview.build(
        task=plan.tasks[0],
        scheduler_task_id="scheduler-task-" + "6" * 64,
        scheduler_task_plan_sha256="7" * 64,
        campaign_manifest_sha256="8" * 64,
        rendered_context_sha256="9" * 64,
        context_request_evidence_sha256="a" * 64,
        request_token_plan_projection_sha256="b" * 64,
        request_material_projection_sha256="c" * 64,
        request_material_projection_utf8_bytes=1,
        endpoint_policy_snapshot_sha256="d" * 64,
        endpoint_policy_pricing_sha256="e" * 64,
        provider_endpoint="synthetic-provider",
        endpoint_pricing_snapshot_sha256="f" * 64,
        endpoint_cost_bound_projection_sha256="0" * 64,
        maximum_attempts=1,
        maximum_prompt_tokens_per_attempt=100,
        maximum_completion_tokens_per_attempt=50,
        maximum_cost_usd_per_attempt_exact="0.01",
    )
    preflight = build_model_surface_resource_preflight(
        plan,
        (preview,),
        maximum_requests=1,
        maximum_input_tokens=100,
        maximum_output_tokens=50,
        maximum_cost_usd_exact="0.01",
        remaining_cost_usd_by_role={"business_logic": "0.01"},
        remaining_cost_usd_by_model={"provider/model": "0.01"},
    )
    plan_path = tmp_path / "private" / "model-surface-coverage-plan.json"
    preflight_path = tmp_path / "private" / "model-surface-resource-preflight.json"

    _persist_private_coverage_evidence(plan_path, plan)
    _persist_private_coverage_evidence(plan_path, plan)
    _persist_private_coverage_evidence(preflight_path, preflight)
    assert _load_private_coverage_preflight(preflight_path) == preflight

    preflight_path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="failed validation"):
        _load_private_coverage_preflight(preflight_path)
