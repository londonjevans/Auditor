"""Configured original requests keep profile, context and resource ceilings joined."""

import hashlib
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from mmaudit.models.registry import ModelRegistry
from mmaudit.models.runtime import build_reasoning_policy
from mmaudit.models.usage import request_token_plan_from_usage
from mmaudit.orchestration import manifest
from mmaudit.orchestration.context_manifest import build_context_manifest
from tests.integration.test_truncation_tree_manifest_files import (
    no_provider_or_operator_secrets as no_provider_or_operator_secrets,
)
from tests.refresh_runtime_support import _catalog_model, _endpoint
from tests.truncation_tree_manifest_support import build_review_source_fixture
from tests.truncation_tree_report_support import candidate_report_config
from tests.truncation_tree_request_support import (
    CONFIGURED_RUN_TOKEN_CAPACITY,
    configured_child_resource_limits,
)
from tests.truncation_tree_run_support import OriginalRunAccounting
from tests.unit import test_assurance as assurance
from tests.unit import test_model_coverage as surfaces
from tests.unit.test_truncation_tree_run_accounting import _DispatchProbe


@pytest.fixture(scope="module")
def configured_inputs() -> dict[str, tuple[Any, ...]]:
    results = {}
    with pytest.MonkeyPatch.context() as patch:
        no_provider_or_operator_secrets.__wrapped__(patch)
        for name, capacity in (("configured", CONFIGURED_RUN_TOKEN_CAPACITY), ("legacy", None)):
            config = candidate_report_config()
            source = build_review_source_fixture()
            now = datetime.now(UTC).replace(microsecond=0)
            authorities = assurance._assurance_policy_selection(
                config, now, source_inventory=source.scheduler_shards, token_capacity=capacity
            )
            template = assurance._complete_assurance_scheduler_fixture(
                config,
                authorities.qualification,
                authorities.evidence_bundle,
                authorities.refresh_runtime,
                now,
                source_inventory=source.scheduler_shards,
                analysis_input_inventory=source.analysis_inputs,
                candidate_falsifier_models=("specialist-0/model-0", "specialist-1/model-1"),
            )
            original = next(
                output.model_completion_evidence.usage_record
                for output in template.outputs
                if output.model_completion_evidence is not None
            )
            usage = assurance._bind_promoted_assurance_usage(original, authorities)
            context = surfaces._promoted_surface_context((), usage, source.index, source.graphs)
            usage = surfaces._with_context_request_evidence(usage, context, request_role=usage.role)
            results[name] = config, authorities.refresh_runtime, usage, context
    return results


def test_original_configured_request_matches_profile_context_and_exact_price(
    configured_inputs: dict[str, tuple[Any, ...]], tmp_path: Path
) -> None:
    config, runtime, original, context = configured_inputs["configured"]
    before = original.model_dump_json()
    accounting = OriginalRunAccounting(tmp_path / "ledger", configured_requests=True)
    usage = accounting.prepare(original, runtime, context=context)
    plan = request_token_plan_from_usage(usage)
    assert plan is not None and plan.reserved_output_tokens == 32_768
    assert plan.global_budget.global_input_token_budget == 8_000_000
    assert plan.global_budget.global_output_token_budget == 2_000_000
    assert plan.context_utilization == Decimal("0.7")
    context_manifest = build_context_manifest(run_id="synthetic-configured", usage_records=[usage])
    # Named invariant: the original maximum-assurance profile is not lowered to fit a fixture.
    manifest._validate_context_manifest_configuration(context_manifest, config)
    qualification = runtime.technical_qualification
    validation = ModelRegistry.validate_production_qualification(
        config, qualification, now=qualification.verified_at
    )
    qualified = manifest._require_opaque_reasoning_qualification(
        usage=usage,
        reasoning_policy=build_reasoning_policy(config),
        validation=validation,
        qualification=qualification,
    )
    assert qualified.binding_sha256 == plan.reasoning_plan.qualification_binding_sha256
    retry = usage.routing
    assert retry["model_retry_policy_sha256"] == config.execution.model_retry_policy.policy_sha256
    assert retry["maximum_attempts_for_request"] == 1
    assert retry["model_retry_attempts"] == [{"attempt_ordinal": 1, "outcome": "SUCCESS"}]
    assert retry["transient_retries_used"] == retry["schema_validation_retries_used"] == 0
    assert original.model_dump_json() == before
    maximum = (
        Decimal("0.000001") * plan.hard_prompt_tokens
        + Decimal("0.000002") * plan.requested_completion_tokens
    )
    assert accounting.pending[usage.request_id].reserved_usd == maximum
    child_cost, child_tokens = configured_child_resource_limits(runtime)
    assert maximum <= Decimal(child_cost) and plan.requested_completion_tokens <= child_tokens
    probe = _DispatchProbe(accounting, usage.request_id)
    accounting.dispatch(probe, "synthetic-task", usage)
    accounting.finish(usage)
    assert probe.called and not accounting.pending
    assert accounting.spent_input_tokens == usage.prompt_tokens
    assert accounting.spent_output_tokens == usage.completion_tokens


@pytest.mark.parametrize("change", ("missing", "role", "rendered"))
def test_configured_request_refuses_nonoriginal_context_before_reserving(
    configured_inputs: dict[str, tuple[Any, ...]], tmp_path: Path, change: str
) -> None:
    _, runtime, original, context = configured_inputs["configured"]
    if change == "missing":
        context = None
    elif change == "role":
        context = context.model_copy(update={"role": "substituted-context"})
    else:
        excerpts = []
        for item in context.excerpts:
            content = item.content + "\n// changed synthetic context"
            excerpts.append(
                item.model_copy(
                    update={
                        "content": content,
                        "content_hash": hashlib.sha256(content.encode()).hexdigest(),
                    }
                )
            )
        context = context.model_copy(update={"excerpts": excerpts})
    accounting = OriginalRunAccounting(tmp_path / "ledger", configured_requests=True)
    with pytest.raises(ValueError, match="original context"):
        accounting.prepare(original, runtime, context=context)
    assert not accounting.pending and not accounting.ledger.snapshot().entries


@pytest.mark.parametrize("exhausted", ("input", "output"))
def test_configured_request_refuses_exhausted_global_ceiling_before_reserving(
    configured_inputs: dict[str, tuple[Any, ...]], tmp_path: Path, exhausted: str
) -> None:
    config, runtime, original, context = configured_inputs["configured"]
    accounting = OriginalRunAccounting(tmp_path / "ledger", configured_requests=True)
    if exhausted == "input":
        accounting.spent_input_tokens = config.token_budgets.global_input_token_budget
    else:
        accounting.spent_output_tokens = config.token_budgets.global_output_token_budget
    # Named invariant: reconciliation never makes the selected cumulative ceiling optional.
    with pytest.raises(ValueError):
        accounting.prepare(original, runtime, context=context)
    assert not accounting.pending and not accounting.ledger.snapshot().entries


def test_legacy_endpoint_capacity_cannot_satisfy_unchanged_profile(
    configured_inputs: dict[str, tuple[Any, ...]], tmp_path: Path
) -> None:
    config, runtime, original, context = configured_inputs["legacy"]
    assert config.effective_reserved_output_tokens == 32_768
    assert all(item.output_limit == 8_192 for item in runtime.history.candidate_registry.candidates)
    accounting = OriginalRunAccounting(tmp_path / "ledger", configured_requests=True)
    with pytest.raises(ValueError):
        accounting.prepare(original, runtime, context=context)
    assert not accounting.pending and not accounting.ledger.snapshot().entries


def test_capacity_metadata_opt_in_preserves_omitted_defaults() -> None:
    legacy = (100_000, 91_808, 8_192)
    assert _catalog_model("synthetic/model") == _catalog_model(
        "synthetic/model", token_capacity=legacy
    )
    assert _endpoint("synthetic/model", "synthetic") == _endpoint(
        "synthetic/model", "synthetic", token_capacity=legacy
    )
    catalog = _catalog_model("synthetic/model", token_capacity=CONFIGURED_RUN_TOKEN_CAPACITY)
    endpoint = _endpoint(
        "synthetic/model", "synthetic", token_capacity=CONFIGURED_RUN_TOKEN_CAPACITY
    )
    assert catalog["context_length"] == endpoint["context_length"] == 262_144
    assert catalog["top_provider"]["max_completion_tokens"] == 65_536
    assert endpoint["max_prompt_tokens"] == 196_608
    assert endpoint["max_completion_tokens"] == 65_536


def test_original_child_limits_cover_every_selected_endpoint(
    configured_inputs: dict[str, tuple[Any, ...]],
) -> None:
    _, runtime, _, _ = configured_inputs["configured"]
    assert configured_child_resource_limits(runtime) == ("0.32768", 65_536)
    assert all(
        (item.context_size, item.max_prompt_tokens, item.output_limit)
        == CONFIGURED_RUN_TOKEN_CAPACITY
        for item in runtime.history.candidate_registry.candidates
    )


@pytest.mark.parametrize("key", ("benchmark_report_sha256", "qualified_reasoning_binding_sha256"))
def test_original_qualification_projection_cannot_replace_conflicting_evidence(
    configured_inputs: dict[str, tuple[Any, ...]], tmp_path: Path, key: str
) -> None:
    _, runtime, original, context = configured_inputs["configured"]
    changed = original.model_copy(update={"routing": original.routing | {key: "0" * 64}})
    accounting = OriginalRunAccounting(tmp_path / "ledger", configured_requests=True)
    # Named invariant: original opaque qualification joins cannot hide contradictory evidence.
    with pytest.raises(ValueError, match="original reasoning qualification differs"):
        accounting.prepare(changed, runtime, context=context)
    assert not accounting.pending and not accounting.ledger.snapshot().entries
