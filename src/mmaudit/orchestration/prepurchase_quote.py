"""Provider-free planning for bounded pre-purchase quote artifacts."""

from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Context, Decimal, localcontext
from typing import Any

from pydantic import BaseModel, ConfigDict

from mmaudit.agents.verifier import (
    select_candidate_falsifier_models,
    select_validation_falsifier_models,
)
from mmaudit.config import AuditConfig
from mmaudit.models.coverage_planning import (
    ModelPortfolioResourcePreflight,
    ModelPortfolioTaskResourceEnvelope,
)
from mmaudit.models.discovery import (
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
)
from mmaudit.models.openrouter import (
    OpenRouterStructuredRequestCostPreview,
    preview_openrouter_structured_request_cost,
)
from mmaudit.models.prepurchase_quote import (
    AcceptedPrepurchaseQuote,
    PrepurchaseQuote,
    PrepurchaseQuoteLocalAnalysisCeiling,
    PrepurchaseQuoteTaskCeiling,
    PrepurchaseQuoteTaskClass,
    build_prepurchase_quote,
)
from mmaudit.models.runtime import build_openrouter_runtime_controls
from mmaudit.models.scheduler import SchedulerCampaignManifest
from mmaudit.models.schemas import AuditProfile
from mmaudit.models.sharding import SolidityShardInventory
from mmaudit.models.truncation_recovery import (
    TRUNCATION_RECOVERY_MAX_CHILD_PROVIDER_ATTEMPTS,
    TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    TRUNCATION_RECOVERY_MAX_COMPLETION_TOKENS,
    TRUNCATION_RECOVERY_MAX_DEPTH,
    TRUNCATION_RECOVERY_MAX_PROVIDER_ATTEMPTS,
    TRUNCATION_RECOVERY_MAX_USD_EXACT,
)
from mmaudit.scanners.fork_matrix import repository_fork_matrix_timeout_budget_seconds


class PrepurchaseQuotePlanningError(ValueError):
    """Raised when an exact target cannot receive a finite provider-free quote."""


class _QuoteCostProbe(BaseModel):
    """Minimal schema used only to project frozen endpoint price components."""

    model_config = ConfigDict(extra="forbid", strict=True)

    bounded: bool


@dataclass(frozen=True, slots=True)
class _PlannedRoute:
    task_class: PrepurchaseQuoteTaskClass
    request_role: str
    requested_model: str
    standard_task_count: int
    maximum_task_count: int


_EARLY_TASK_CLASS_BY_VALUE = {
    "orientation": PrepurchaseQuoteTaskClass.ORIENTATION,
    "retrieval_planning": PrepurchaseQuoteTaskClass.RETRIEVAL_PLANNING,
    "compact_coverage": PrepurchaseQuoteTaskClass.COMPACT_COVERAGE,
    "source_audit": PrepurchaseQuoteTaskClass.SOURCE_AUDIT,
    "whole_protocol": PrepurchaseQuoteTaskClass.WHOLE_PROTOCOL,
    "invariant_review": PrepurchaseQuoteTaskClass.INVARIANT_REVIEW,
    "report_quality": PrepurchaseQuoteTaskClass.REPORT_QUALITY,
}

_PROMPT_PRICING_FIELDS = frozenset({"prompt", "input_cache_read", "input_cache_write"})


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _format_decimal(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"


def _maximum_per_attempt_cost(
    preview: OpenRouterStructuredRequestCostPreview,
    *,
    maximum_input_tokens: int,
    maximum_output_tokens: int,
) -> str:
    with localcontext(Context(prec=96)):
        total = Decimal(0)
        for component in preview.cost_components:
            if component.pricing_field in _PROMPT_PRICING_FIELDS:
                units = maximum_input_tokens
            elif component.pricing_field == "completion":
                units = maximum_output_tokens
            elif component.pricing_field == "internal_reasoning":
                units = preview.reserved_reasoning_tokens
            elif component.pricing_field == "request":
                units = 1
            else:
                # Current audit requests do not emit image or web-search units.
                units = 0
            total += Decimal(component.unit_price_usd_exact) * units
    return _format_decimal(total)


def _task_wall_clock_bounds(config: AuditConfig) -> tuple[int, int]:
    attempt_seconds = max(1, math.ceil(config.execution.request_timeout_seconds * 2 + 120))
    attempts = config.execution.maximum_model_attempts
    maximum = attempt_seconds * attempts + 30 * max(0, attempts - 1)
    return attempt_seconds, maximum


def _policy_selected_auxiliary_config(
    config: AuditConfig,
    selected_model_ids: frozenset[str] | None,
) -> AuditConfig:
    if selected_model_ids is None:
        return config
    if type(selected_model_ids) is not frozenset or any(
        type(model_id) is not str or not model_id for model_id in selected_model_ids
    ):
        raise PrepurchaseQuotePlanningError(
            "quote selected-model projection must be an exact nonempty-ID frozenset"
        )
    core_roles = (
        "threat_model",
        "source_audit",
        "business_logic",
        "configuration",
        "verifier",
        "judge",
    )
    updates: dict[str, Any] = {
        role: config.models.role(role).model_copy(
            update={
                "fallbacks": [
                    model_id
                    for model_id in config.models.role(role).fallbacks
                    if model_id in selected_model_ids
                ]
            }
        )
        for role in core_roles
    }
    updates["specialists"] = {
        role: role_config.model_copy(
            update={
                "fallbacks": [
                    model_id for model_id in role_config.fallbacks if model_id in selected_model_ids
                ]
            }
        )
        for role, role_config in config.models.specialists.items()
        if role_config.primary in selected_model_ids
    }
    return config.model_copy(update={"models": config.models.model_copy(update=updates)})


def _resolve_selected_model_projection(
    campaign_manifest: SchedulerCampaignManifest,
    selected_model_ids: frozenset[str] | None,
) -> tuple[frozenset[str] | None, str | None]:
    binding = campaign_manifest.bindings.audit_model_selection
    if binding is None:
        if selected_model_ids is not None:
            raise PrepurchaseQuotePlanningError(
                "runtime selected-model set lacks a scheduler selection binding"
            )
        return None, None
    bound_ids = frozenset(binding.selected_model_ids)
    if selected_model_ids is not None and selected_model_ids != bound_ids:
        raise PrepurchaseQuotePlanningError(
            "runtime selected-model set differs from the scheduler selection binding"
        )
    return bound_ids, binding.selected_model_set_sha256


def _role_output_token_ceiling(config: AuditConfig, request_role: str) -> int:
    controls = build_openrouter_runtime_controls(config, certification=False)
    control = controls.reasoning_policy.control_for_request(request_role)
    return config.effective_reserved_output_tokens + control.reserved_reasoning_tokens


def _later_request_envelope_recipe_sha256(
    config: AuditConfig,
    *,
    route: _PlannedRoute,
    endpoint_policy_snapshot_sha256: str,
    endpoint_policy_pricing_sha256: str,
    provider_endpoint: str,
    endpoint_pricing_snapshot_sha256: str,
    maximum_input_tokens: int,
    maximum_output_tokens: int,
    maximum_cost_usd_per_attempt_exact: str,
    selected_model_set_sha256: str | None,
) -> str:
    controls = build_openrouter_runtime_controls(config, certification=False)
    reasoning = controls.reasoning_policy.control_for_request(route.request_role)
    return _canonical_sha256(
        {
            "domain": "mmaudit.prepurchase-quote.request-envelope.v1",
            "effective_config_sha256": config.stable_hash(),
            "policy_selected_model_set_sha256": selected_model_set_sha256,
            "task_class": route.task_class.value,
            "request_role": route.request_role,
            "requested_model": route.requested_model,
            "maximum_attempts": config.execution.maximum_model_attempts,
            "retry_policy_sha256": config.execution.model_retry_policy.policy_sha256,
            "transient_retry_limit": config.execution.max_model_retries,
            "schema_validation_retry_limit": (config.execution.max_schema_validation_retries),
            "maximum_serialized_request_bytes": config.execution.max_request_bytes,
            "maximum_input_tokens": maximum_input_tokens,
            "maximum_visible_output_tokens": config.effective_reserved_output_tokens,
            "maximum_reasoning_tokens": reasoning.reserved_reasoning_tokens,
            "maximum_output_tokens": maximum_output_tokens,
            "maximum_cost_usd_per_attempt_exact": maximum_cost_usd_per_attempt_exact,
            "endpoint_policy_snapshot_sha256": endpoint_policy_snapshot_sha256,
            "endpoint_policy_pricing_sha256": endpoint_policy_pricing_sha256,
            "provider_endpoint": provider_endpoint,
            "endpoint_pricing_snapshot_sha256": endpoint_pricing_snapshot_sha256,
        }
    )


def _standard_candidate_count(
    config: AuditConfig,
    inventory: SolidityShardInventory,
) -> int:
    semantic_units = (
        len(inventory.entity_ids) + len(inventory.graph_edge_ids) + len(inventory.storage_entry_ids)
    )
    per_shard = math.ceil(semantic_units / max(1, len(inventory.shards)))
    return min(config.execution.max_candidates_per_run, max(1, per_shard))


def _enabled_scanner_names(config: AuditConfig) -> tuple[str, ...]:
    return tuple(
        sorted(
            name
            for name in (
                "semgrep",
                "gitleaks",
                "trivy",
                "osv",
                "codeql",
                "slither",
                "foundry_fork",
                "hardhat_fork",
            )
            if getattr(config.scanners, name).enabled
        )
    )


def _formal_tool_count(config: AuditConfig) -> int:
    if not config.formal.enabled:
        return 0
    selected: set[str] = {"foundry-invariant", *config.formal.required_tools}
    configured_flags = {
        "solc-smtchecker": config.formal.run_smtchecker,
        "mythril": config.formal.run_mythril,
        "echidna": config.formal.run_echidna,
        "medusa": config.formal.run_medusa,
        "halmos": config.formal.run_halmos,
        "kontrol": config.formal.run_kontrol,
    }
    selected.update(name for name, enabled in configured_flags.items() if enabled)
    if config.formal.certora.enabled:
        selected.add("certora")
    return len(selected)


def build_quote_local_analysis_ceiling(
    config: AuditConfig,
    *,
    campaign_manifest: SchedulerCampaignManifest,
    solidity_shard_inventory: SolidityShardInventory,
) -> PrepurchaseQuoteLocalAnalysisCeiling:
    """Derive a finite serial local-analysis estimate from exact target and timeout limits."""

    if type(config) is not AuditConfig:
        raise PrepurchaseQuotePlanningError("quote planning requires an exact audit config")
    if config.stable_hash() != campaign_manifest.bindings.effective_config_sha256:
        raise PrepurchaseQuotePlanningError(
            "quote config differs from the scheduler effective-config binding"
        )
    repository_bytes = sum(
        source.size
        for shard in campaign_manifest.shard_inventory.shards
        for source in shard.sources
    )
    deterministic_units = max(
        1,
        math.ceil(repository_bytes / 1_000_000)
        + math.ceil(len(solidity_shard_inventory.entity_ids) / 1_000)
        + len(solidity_shard_inventory.shards),
    )
    scanners = _enabled_scanner_names(config)
    scanner_timeout = math.ceil(config.execution.scanner_timeout_seconds)
    compilation_project_ceiling = len(solidity_shard_inventory.source_units)
    compilation_per_project = math.ceil(config.smart_contracts.compilation_timeout_seconds)
    compilation = (
        compilation_per_project * compilation_project_ceiling
        if config.smart_contracts.enabled and config.smart_contracts.compile
        else 0
    )
    repository_suite = 0
    repository_matrix = 0
    if config.smart_contracts.enabled:
        repository_suite = math.ceil(config.smart_contracts.repository_suite.total_timeout_seconds)
        if config.smart_contracts.repository_suite.fork_matrix_states:
            try:
                repository_matrix = math.ceil(
                    repository_fork_matrix_timeout_budget_seconds(
                        config.smart_contracts.repository_suite
                    )
                )
            except ValueError as exc:
                raise PrepurchaseQuotePlanningError(
                    "configured repository fork matrix has no finite timeout ceiling"
                ) from exc
    reproduction = (
        math.ceil(config.reproduction.timeout_seconds)
        * config.reproduction.max_total_tests
        * config.reproduction.repetitions
        if config.reproduction.enabled
        else 0
    )
    configured_harness_count = len(config.invariants.harnesses)
    generated_harness_ceiling = (
        config.invariants.max_invariants * 2 if config.invariants.generate_foundry_templates else 0
    )
    invariant_harness_count = (
        configured_harness_count + generated_harness_ceiling
        if config.invariants.enabled and config.invariants.execute_generated
        else 0
    )
    invariant_harness_execution = (
        math.ceil(config.reproduction.timeout_seconds) * invariant_harness_count
    )
    formal_tools = _formal_tool_count(config)
    formal = math.ceil(config.formal.timeout_seconds) * formal_tools
    fork_probe = (
        math.ceil(config.smart_contracts.max_fork_probe_seconds)
        if config.smart_contracts.enabled and config.smart_contracts.allow_fork_probing
        else 0
    )
    standard_candidates = _standard_candidate_count(config, solidity_shard_inventory)
    standard = (
        deterministic_units
        + (scanner_timeout if scanners else 0)
        + compilation
        + repository_suite
        + repository_matrix
        + math.ceil(config.reproduction.timeout_seconds)
        * (
            configured_harness_count
            if config.invariants.enabled and config.invariants.execute_generated
            else 0
        )
        + (
            math.ceil(config.reproduction.timeout_seconds)
            * min(config.reproduction.max_candidates, standard_candidates)
            if config.reproduction.enabled
            else 0
        )
        + (math.ceil(config.formal.timeout_seconds) if formal_tools else 0)
    )
    maximum = (
        deterministic_units * 4
        + scanner_timeout * len(scanners)
        + compilation
        + repository_suite
        + repository_matrix
        + reproduction
        + invariant_harness_execution
        + formal
        + fork_probe
    )
    maximum = max(1, maximum, standard)
    execution_limits = {
        "domain": "mmaudit.prepurchase-quote.local-analysis-limits.v1",
        "effective_config_sha256": config.stable_hash(),
        "repository_bytes": repository_bytes,
        "deterministic_units": deterministic_units,
        "enabled_scanners": scanners,
        "scanner_timeout_seconds": scanner_timeout,
        "compilation_timeout_seconds_per_project": compilation_per_project,
        "compilation_project_count_ceiling": compilation_project_ceiling,
        "compilation_timeout_seconds": compilation,
        "repository_suite_timeout_seconds": repository_suite,
        "repository_fork_matrix_timeout_seconds": repository_matrix,
        "reproduction_timeout_seconds": math.ceil(config.reproduction.timeout_seconds),
        "reproduction_max_total_tests": config.reproduction.max_total_tests,
        "reproduction_repetitions": config.reproduction.repetitions,
        "configured_invariant_harness_count": configured_harness_count,
        "generated_invariant_harness_count_ceiling": generated_harness_ceiling,
        "invariant_harness_count_ceiling": invariant_harness_count,
        "invariant_harness_execution_timeout_seconds": invariant_harness_execution,
        "formal_timeout_seconds": math.ceil(config.formal.timeout_seconds),
        "formal_tool_count": formal_tools,
        "fork_probe_seconds": fork_probe,
        "standard_candidate_count": standard_candidates,
    }
    return PrepurchaseQuoteLocalAnalysisCeiling.build(
        analysis_input_sha256=campaign_manifest.bindings.analysis_input_sha256,
        execution_limits_sha256=_canonical_sha256(execution_limits),
        standard_wall_clock_seconds=standard,
        maximum_wall_clock_seconds=maximum,
    )


def _aggregate_early_envelopes(
    config: AuditConfig,
    preflight: ModelPortfolioResourcePreflight,
) -> list[PrepurchaseQuoteTaskCeiling]:
    grouped: dict[tuple[str, ...], list[ModelPortfolioTaskResourceEnvelope]] = defaultdict(list)
    for envelope in preflight.task_envelopes:
        task_class = _EARLY_TASK_CLASS_BY_VALUE.get(envelope.task_kind.value)
        if task_class is None:
            raise PrepurchaseQuotePlanningError("portfolio contains an unknown paid task class")
        identity = (
            task_class.value,
            envelope.request_role,
            envelope.requested_model,
            envelope.request_envelope_recipe_sha256,
            envelope.endpoint_policy_snapshot_sha256,
            envelope.endpoint_policy_pricing_sha256,
            envelope.provider_endpoint,
            envelope.endpoint_pricing_snapshot_sha256,
        )
        grouped[identity].append(envelope)
    standard_seconds, maximum_seconds = _task_wall_clock_bounds(config)
    ceilings: list[PrepurchaseQuoteTaskCeiling] = []
    for grouped_identity, envelopes in sorted(grouped.items()):
        ceilings.append(
            PrepurchaseQuoteTaskCeiling.build(
                task_class=PrepurchaseQuoteTaskClass(grouped_identity[0]),
                request_role=grouped_identity[1],
                requested_model=grouped_identity[2],
                request_envelope_recipe_sha256=grouped_identity[3],
                endpoint_policy_snapshot_sha256=grouped_identity[4],
                endpoint_policy_pricing_sha256=grouped_identity[5],
                provider_endpoint=grouped_identity[6],
                endpoint_pricing_snapshot_sha256=grouped_identity[7],
                standard_task_count=len(envelopes),
                maximum_task_count=len(envelopes),
                standard_attempts_per_task=1,
                maximum_attempts_per_task=max(item.maximum_attempts for item in envelopes),
                maximum_input_tokens_per_attempt=max(
                    item.maximum_prompt_tokens_per_attempt for item in envelopes
                ),
                maximum_output_tokens_per_attempt=max(
                    item.maximum_completion_tokens_per_attempt for item in envelopes
                ),
                maximum_cost_usd_per_attempt_exact=max(
                    (item.maximum_cost_usd_per_attempt_exact for item in envelopes),
                    key=Decimal,
                ),
                standard_wall_clock_seconds_per_task=standard_seconds,
                maximum_wall_clock_seconds_per_task=maximum_seconds,
            )
        )
    return ceilings


def _configured_role_exists(config: AuditConfig, request_role: str) -> bool:
    configured_role = request_role.removeprefix("specialist:")
    try:
        config.models.role(configured_role)
    except KeyError:
        return False
    return True


def _later_routes(
    config: AuditConfig,
    *,
    inventory: SolidityShardInventory,
    preflight: ModelPortfolioResourcePreflight,
) -> tuple[_PlannedRoute, ...]:
    standard_candidates = _standard_candidate_count(config, inventory)
    maximum_candidates = config.execution.max_candidates_per_run
    routes: list[_PlannedRoute] = []

    relationship_count = len(inventory.boundaries) + len(inventory.overlaps)
    if relationship_count:
        routes.append(
            _PlannedRoute(
                PrepurchaseQuoteTaskClass.CROSS_SHARD_INTEGRATION,
                "business_logic",
                config.models.business_logic.primary,
                relationship_count,
                relationship_count,
            )
        )
    if (
        config.profile in {AuditProfile.DEEP, AuditProfile.MAXIMUM_ASSURANCE}
        and "invariant_review" in config.models.specialists
    ):
        routes.append(
            _PlannedRoute(
                PrepurchaseQuoteTaskClass.INVARIANT_REVIEW,
                "specialist:invariant_review",
                config.models.specialists["invariant_review"].primary,
                1,
                1,
            )
        )

    cross_models = select_candidate_falsifier_models(config)
    if len(cross_models) != 2:
        raise PrepurchaseQuotePlanningError(
            "quote requires two configured candidate cross-examination lineages"
        )
    for model_id, _lineage in cross_models:
        routes.append(
            _PlannedRoute(
                PrepurchaseQuoteTaskClass.ADVERSARIAL_CROSS_EXAMINATION,
                "candidate_falsifier",
                model_id,
                standard_candidates,
                maximum_candidates,
            )
        )

    routes.append(
        _PlannedRoute(
            PrepurchaseQuoteTaskClass.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
            "verifier",
            config.models.verifier.primary,
            1,
            1,
        )
    )
    validation_models = select_validation_falsifier_models(config)
    if len(validation_models) != 2:
        raise PrepurchaseQuotePlanningError(
            "quote requires two verifier-independent validation lineages"
        )
    for model_id, _lineage in validation_models:
        routes.append(
            _PlannedRoute(
                PrepurchaseQuoteTaskClass.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
                "candidate_falsifier",
                model_id,
                1,
                1,
            )
        )

    if config.reproduction.enabled:
        configured_planners = tuple(
            role
            for role in ("test_generation", "exploit_reproduction_planner")
            if role in config.models.specialists
        )
        if configured_planners:
            planning_roles = tuple(f"specialist:{role}" for role in configured_planners)
        else:
            planning_roles = tuple(
                role
                for role in (
                    "source_audit",
                    "business_logic",
                    "configuration",
                    *preflight.candidate_independent_request_roles,
                )
                if _configured_role_exists(config, role)
            )
        for index, role in enumerate(sorted(set(planning_roles))):
            configured_role = role.removeprefix("specialist:")
            routes.append(
                _PlannedRoute(
                    PrepurchaseQuoteTaskClass.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
                    f"specialist:{configured_role}:exploit_test",
                    config.models.role(configured_role).primary,
                    int(index < standard_candidates),
                    1,
                )
            )
        falsifier_role = "falsifier" if "falsifier" in config.models.specialists else "verifier"
        routes.append(
            _PlannedRoute(
                PrepurchaseQuoteTaskClass.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
                "specialist:falsifier" if falsifier_role == "falsifier" else "falsifier",
                config.models.role(falsifier_role).primary,
                1,
                1,
            )
        )

    routes.append(
        _PlannedRoute(
            PrepurchaseQuoteTaskClass.EVIDENCE_CAPPED_JUDGMENT,
            "judge",
            config.models.judge.primary,
            1,
            1,
        )
    )
    if "report_quality" in config.models.specialists:
        routes.append(
            _PlannedRoute(
                PrepurchaseQuoteTaskClass.REPORT_QUALITY,
                "specialist:report_quality",
                config.models.specialists["report_quality"].primary,
                1,
                1,
            )
        )
    return tuple(routes)


def _evidence_by_model(
    manifest: OpenRouterModelDiscoveryRunManifest,
    evidence: Sequence[OpenRouterModelDiscoveryEvidence],
) -> dict[str, OpenRouterModelDiscoveryEvidence]:
    if not evidence:
        raise PrepurchaseQuotePlanningError("quote requires frozen endpoint pricing evidence")
    by_model = {item.exact_model_id: item for item in evidence}
    if len(by_model) != len(evidence):
        raise PrepurchaseQuotePlanningError("quote discovery evidence repeats a model")
    if tuple(sorted(by_model)) != tuple(sorted(item.exact_model_id for item in manifest.artifacts)):
        raise PrepurchaseQuotePlanningError(
            "quote discovery evidence differs from its exact-set manifest"
        )
    return by_model


def _price_preview(
    config: AuditConfig,
    *,
    discovery_manifest: OpenRouterModelDiscoveryRunManifest,
    evidence: OpenRouterModelDiscoveryEvidence,
    request_role: str,
    requested_model: str,
) -> OpenRouterStructuredRequestCostPreview:
    logical_digest = _canonical_sha256(
        {
            "domain": "mmaudit.prepurchase-quote.cost-probe.v1",
            "role": request_role,
            "model": requested_model,
        }
    )
    try:
        controls = build_openrouter_runtime_controls(config, certification=True)
        return preview_openrouter_structured_request_cost(
            execution=config.execution,
            privacy=config.privacy,
            token_budgets=config.token_budgets,
            provider_policy=controls.provider_policy,
            reasoning_policy=controls.reasoning_policy,
            discovery_manifest=discovery_manifest,
            discovery_evidence=evidence,
            role=request_role,
            system_prompt="Bounded provider-free pre-purchase quote cost probe.",
            user_prompt="No target source is included in this local pricing projection.",
            response_model=_QuoteCostProbe,
            schema_name="prepurchase_quote_cost_probe",
            logical_request_id=f"quote-request-{logical_digest}",
            maximum_attempts=config.execution.maximum_model_attempts,
        )
    except ValueError as exc:
        raise PrepurchaseQuotePlanningError(
            f"frozen endpoint pricing cannot bound role {request_role}: {exc}"
        ) from exc


def _priced_route_ceiling(
    config: AuditConfig,
    *,
    route: _PlannedRoute,
    discovery_manifest: OpenRouterModelDiscoveryRunManifest,
    discovery_evidence: OpenRouterModelDiscoveryEvidence,
    selected_model_set_sha256: str | None,
) -> PrepurchaseQuoteTaskCeiling:
    preview = _price_preview(
        config,
        discovery_manifest=discovery_manifest,
        evidence=discovery_evidence,
        request_role=route.request_role,
        requested_model=route.requested_model,
    )
    endpoint = discovery_evidence.endpoint_snapshot.endpoint(preview.provider_endpoint)
    if endpoint is None:
        raise PrepurchaseQuotePlanningError(
            f"priced endpoint disappeared for role {route.request_role}"
        )
    maximum_input = config.execution.max_request_bytes
    maximum_output = _role_output_token_ceiling(config, route.request_role)
    if preview.requested_completion_tokens != maximum_output:
        raise PrepurchaseQuotePlanningError(
            f"priced output ceiling changed for role {route.request_role}"
        )
    per_attempt_cost = _maximum_per_attempt_cost(
        preview,
        maximum_input_tokens=maximum_input,
        maximum_output_tokens=maximum_output,
    )
    standard_seconds, maximum_seconds = _task_wall_clock_bounds(config)
    return PrepurchaseQuoteTaskCeiling.build(
        task_class=route.task_class,
        request_role=route.request_role,
        requested_model=route.requested_model,
        request_envelope_recipe_sha256=_later_request_envelope_recipe_sha256(
            config,
            route=route,
            endpoint_policy_snapshot_sha256=preview.endpoint_policy_snapshot_sha256,
            endpoint_policy_pricing_sha256=preview.endpoint_policy_pricing_sha256,
            provider_endpoint=preview.provider_endpoint,
            endpoint_pricing_snapshot_sha256=preview.endpoint_cost_bound_pricing_sha256,
            maximum_input_tokens=maximum_input,
            maximum_output_tokens=maximum_output,
            maximum_cost_usd_per_attempt_exact=per_attempt_cost,
            selected_model_set_sha256=selected_model_set_sha256,
        ),
        endpoint_policy_snapshot_sha256=preview.endpoint_policy_snapshot_sha256,
        endpoint_policy_pricing_sha256=preview.endpoint_policy_pricing_sha256,
        provider_endpoint=preview.provider_endpoint,
        endpoint_pricing_snapshot_sha256=preview.endpoint_cost_bound_pricing_sha256,
        standard_task_count=route.standard_task_count,
        maximum_task_count=route.maximum_task_count,
        standard_attempts_per_task=1,
        maximum_attempts_per_task=config.execution.maximum_model_attempts,
        maximum_input_tokens_per_attempt=maximum_input,
        maximum_output_tokens_per_attempt=maximum_output,
        maximum_cost_usd_per_attempt_exact=per_attempt_cost,
        standard_wall_clock_seconds_per_task=standard_seconds,
        maximum_wall_clock_seconds_per_task=maximum_seconds,
    )


def _disabled_ceiling(task_class: PrepurchaseQuoteTaskClass) -> PrepurchaseQuoteTaskCeiling:
    return PrepurchaseQuoteTaskCeiling.build(
        task_class=task_class,
        request_role=None,
        requested_model=None,
        request_envelope_recipe_sha256=None,
        endpoint_policy_snapshot_sha256=None,
        endpoint_policy_pricing_sha256=None,
        provider_endpoint=None,
        endpoint_pricing_snapshot_sha256=None,
        standard_task_count=0,
        maximum_task_count=0,
        standard_attempts_per_task=1,
        maximum_attempts_per_task=1,
        maximum_input_tokens_per_attempt=0,
        maximum_output_tokens_per_attempt=0,
        maximum_cost_usd_per_attempt_exact="0",
        standard_wall_clock_seconds_per_task=0,
        maximum_wall_clock_seconds_per_task=0,
    )


def _add_recovery_ceilings(
    config: AuditConfig,
    *,
    priced: Sequence[PrepurchaseQuoteTaskCeiling],
) -> list[PrepurchaseQuoteTaskCeiling]:
    del config
    routes = tuple(
        sorted(
            (
                item
                for item in priced
                if item.maximum_task_count and item.request_role and item.requested_model
            ),
            key=lambda item: item.ceiling_sha256,
        )
    )
    if not routes:
        return []
    source = max(
        routes,
        key=lambda item: (
            Decimal(item.maximum_cost_usd_per_attempt_exact),
            item.maximum_input_tokens_per_attempt,
            item.maximum_output_tokens_per_attempt,
            item.ceiling_sha256,
        ),
    )
    assert source.request_role is not None
    assert source.requested_model is not None
    return [
        PrepurchaseQuoteTaskCeiling.build(
            task_class=PrepurchaseQuoteTaskClass.TRUNCATION_RECOVERY,
            request_role=source.request_role,
            requested_model=source.requested_model,
            request_envelope_recipe_sha256=_canonical_sha256(
                {
                    "domain": "mmaudit.prepurchase-quote.truncation-recovery.v1",
                    "eligible_parent_ceiling_sha256s": tuple(
                        item.ceiling_sha256 for item in routes
                    ),
                    "selected_maximum_cost_ceiling_sha256": source.ceiling_sha256,
                    "maximum_depth": TRUNCATION_RECOVERY_MAX_DEPTH,
                    "maximum_child_requests_campaign_global": (
                        TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS
                    ),
                    "maximum_provider_attempts_campaign_global": (
                        TRUNCATION_RECOVERY_MAX_PROVIDER_ATTEMPTS
                    ),
                    "maximum_completion_tokens_campaign_global": (
                        TRUNCATION_RECOVERY_MAX_COMPLETION_TOKENS
                    ),
                    "maximum_usd_campaign_global_exact": TRUNCATION_RECOVERY_MAX_USD_EXACT,
                    "compiled_child_provider_attempt_limit": (
                        TRUNCATION_RECOVERY_MAX_CHILD_PROVIDER_ATTEMPTS
                    ),
                    "runtime_child_single_route_single_attempt": True,
                }
            ),
            endpoint_policy_snapshot_sha256=source.endpoint_policy_snapshot_sha256,
            endpoint_policy_pricing_sha256=source.endpoint_policy_pricing_sha256,
            provider_endpoint=source.provider_endpoint,
            endpoint_pricing_snapshot_sha256=source.endpoint_pricing_snapshot_sha256,
            standard_task_count=0,
            maximum_task_count=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
            standard_attempts_per_task=1,
            maximum_attempts_per_task=1,
            maximum_input_tokens_per_attempt=max(
                item.maximum_input_tokens_per_attempt for item in routes
            ),
            maximum_output_tokens_per_attempt=max(
                item.maximum_output_tokens_per_attempt for item in routes
            ),
            maximum_cost_usd_per_attempt_exact=max(
                (item.maximum_cost_usd_per_attempt_exact for item in routes),
                key=Decimal,
            ),
            standard_wall_clock_seconds_per_task=max(
                item.standard_wall_clock_seconds_per_task for item in routes
            ),
            maximum_wall_clock_seconds_per_task=max(
                item.maximum_wall_clock_seconds_per_task for item in routes
            ),
        )
    ]


def _require_configured_ledger_capacity(
    config: AuditConfig,
    campaign_manifest: SchedulerCampaignManifest,
) -> None:
    baseline = campaign_manifest.cost_ledger_baseline
    if baseline is None:
        raise PrepurchaseQuotePlanningError(
            "quote requires an exact persistent cost-ledger baseline"
        )
    if Decimal(baseline.cap_usd_exact) > Decimal(str(config.execution.budget_usd)):
        raise PrepurchaseQuotePlanningError(
            "cost-ledger cap exceeds the effective configured execution budget"
        )


def build_prepurchase_quote_from_frozen_inputs(
    config: AuditConfig,
    *,
    campaign_manifest: SchedulerCampaignManifest,
    solidity_shard_inventory: SolidityShardInventory,
    portfolio_preflight: ModelPortfolioResourcePreflight,
    discovery_manifest: OpenRouterModelDiscoveryRunManifest,
    discovery_evidence: Sequence[OpenRouterModelDiscoveryEvidence],
    selected_model_ids: frozenset[str] | None = None,
) -> PrepurchaseQuote:
    """Build a whole-run quote without provider transport, secrets, or budget mutation."""

    if type(config) is not AuditConfig:
        raise PrepurchaseQuotePlanningError("quote planning requires an exact audit config")
    if config.execution.max_requests_per_agent < config.execution.maximum_model_attempts:
        raise PrepurchaseQuotePlanningError(
            "request capacity is below the configured same-route attempt ceiling"
        )
    _require_configured_ledger_capacity(config, campaign_manifest)
    evidence_by_model = _evidence_by_model(discovery_manifest, discovery_evidence)
    ceilings = _aggregate_early_envelopes(config, portfolio_preflight)
    resolved_model_ids, selected_model_set_sha256 = _resolve_selected_model_projection(
        campaign_manifest,
        selected_model_ids,
    )
    auxiliary_config = _policy_selected_auxiliary_config(config, resolved_model_ids)
    routes = _later_routes(
        auxiliary_config,
        inventory=solidity_shard_inventory,
        preflight=portfolio_preflight,
    )
    for route in routes:
        evidence = evidence_by_model.get(route.requested_model)
        if evidence is None:
            raise PrepurchaseQuotePlanningError(
                f"frozen endpoint pricing is missing model {route.requested_model}"
            )
        ceilings.append(
            _priced_route_ceiling(
                config,
                route=route,
                discovery_manifest=discovery_manifest,
                discovery_evidence=evidence,
                selected_model_set_sha256=selected_model_set_sha256,
            )
        )
    ceilings.extend(_add_recovery_ceilings(config, priced=ceilings))
    covered = {item.task_class for item in ceilings}
    ceilings.extend(
        _disabled_ceiling(task_class)
        for task_class in PrepurchaseQuoteTaskClass
        if task_class not in covered
    )
    local_analysis = build_quote_local_analysis_ceiling(
        config,
        campaign_manifest=campaign_manifest,
        solidity_shard_inventory=solidity_shard_inventory,
    )
    try:
        return build_prepurchase_quote(
            campaign_manifest=campaign_manifest,
            solidity_shard_inventory=solidity_shard_inventory,
            portfolio_preflight=portfolio_preflight,
            local_analysis_ceiling=local_analysis,
            retry_policy=config.execution.model_retry_policy,
            task_ceilings=ceilings,
        )
    except (TypeError, ValueError) as exc:
        raise PrepurchaseQuotePlanningError(f"target cannot be bounded safely: {exc}") from exc


def _expected_later_ceiling_from_acceptance(
    config: AuditConfig,
    *,
    route: _PlannedRoute,
    observed: PrepurchaseQuoteTaskCeiling,
    selected_model_set_sha256: str | None,
) -> PrepurchaseQuoteTaskCeiling:
    pricing_fields = (
        observed.endpoint_policy_snapshot_sha256,
        observed.endpoint_policy_pricing_sha256,
        observed.provider_endpoint,
        observed.endpoint_pricing_snapshot_sha256,
    )
    if any(value is None for value in pricing_fields):
        raise PrepurchaseQuotePlanningError(
            f"accepted quote lacks frozen pricing for role {route.request_role}"
        )
    endpoint_policy_snapshot_sha256 = observed.endpoint_policy_snapshot_sha256
    endpoint_policy_pricing_sha256 = observed.endpoint_policy_pricing_sha256
    provider_endpoint = observed.provider_endpoint
    endpoint_pricing_snapshot_sha256 = observed.endpoint_pricing_snapshot_sha256
    assert endpoint_policy_snapshot_sha256 is not None
    assert endpoint_policy_pricing_sha256 is not None
    assert provider_endpoint is not None
    assert endpoint_pricing_snapshot_sha256 is not None
    maximum_input = config.execution.max_request_bytes
    maximum_output = _role_output_token_ceiling(config, route.request_role)
    standard_seconds, maximum_seconds = _task_wall_clock_bounds(config)
    return PrepurchaseQuoteTaskCeiling.build(
        task_class=route.task_class,
        request_role=route.request_role,
        requested_model=route.requested_model,
        request_envelope_recipe_sha256=_later_request_envelope_recipe_sha256(
            config,
            route=route,
            endpoint_policy_snapshot_sha256=endpoint_policy_snapshot_sha256,
            endpoint_policy_pricing_sha256=endpoint_policy_pricing_sha256,
            provider_endpoint=provider_endpoint,
            endpoint_pricing_snapshot_sha256=endpoint_pricing_snapshot_sha256,
            maximum_input_tokens=maximum_input,
            maximum_output_tokens=maximum_output,
            maximum_cost_usd_per_attempt_exact=(observed.maximum_cost_usd_per_attempt_exact),
            selected_model_set_sha256=selected_model_set_sha256,
        ),
        endpoint_policy_snapshot_sha256=endpoint_policy_snapshot_sha256,
        endpoint_policy_pricing_sha256=endpoint_policy_pricing_sha256,
        provider_endpoint=provider_endpoint,
        endpoint_pricing_snapshot_sha256=endpoint_pricing_snapshot_sha256,
        standard_task_count=route.standard_task_count,
        maximum_task_count=route.maximum_task_count,
        standard_attempts_per_task=1,
        maximum_attempts_per_task=config.execution.maximum_model_attempts,
        maximum_input_tokens_per_attempt=maximum_input,
        maximum_output_tokens_per_attempt=maximum_output,
        maximum_cost_usd_per_attempt_exact=(observed.maximum_cost_usd_per_attempt_exact),
        standard_wall_clock_seconds_per_task=standard_seconds,
        maximum_wall_clock_seconds_per_task=maximum_seconds,
    )


def _current_accepted_task_ceilings(
    config: AuditConfig,
    *,
    acceptance: AcceptedPrepurchaseQuote,
    solidity_shard_inventory: SolidityShardInventory,
    portfolio_preflight: ModelPortfolioResourcePreflight,
    resolved_model_ids: frozenset[str] | None,
    selected_model_set_sha256: str | None,
) -> tuple[PrepurchaseQuoteTaskCeiling, ...]:
    pool = list(acceptance.quote.task_ceilings)
    early = _aggregate_early_envelopes(config, portfolio_preflight)
    for expected in early:
        early_matches = [index for index, item in enumerate(pool) if item == expected]
        if len(early_matches) != 1:
            raise PrepurchaseQuotePlanningError(
                "accepted quote differs from the exact early portfolio ceiling"
            )
        pool.pop(early_matches[0])
    auxiliary_config = _policy_selected_auxiliary_config(config, resolved_model_ids)
    routes = _later_routes(
        auxiliary_config,
        inventory=solidity_shard_inventory,
        preflight=portfolio_preflight,
    )
    later: list[PrepurchaseQuoteTaskCeiling] = []
    for route in routes:
        route_matches = [
            (index, item)
            for index, item in enumerate(pool)
            if item.maximum_task_count
            and item.task_class is route.task_class
            and item.request_role == route.request_role
            and item.requested_model == route.requested_model
        ]
        if len(route_matches) != 1:
            raise PrepurchaseQuotePlanningError(
                f"accepted quote lacks one exact current ceiling for role {route.request_role}"
            )
        index, observed = route_matches[0]
        expected = _expected_later_ceiling_from_acceptance(
            config,
            route=route,
            observed=observed,
            selected_model_set_sha256=selected_model_set_sha256,
        )
        if observed != expected:
            raise PrepurchaseQuotePlanningError(
                f"accepted quote understates or changes current role {route.request_role}"
            )
        later.append(expected)
        pool.pop(index)
    primary = [*early, *later]
    ceilings = [*primary, *_add_recovery_ceilings(config, priced=primary)]
    covered = {item.task_class for item in ceilings}
    ceilings.extend(
        _disabled_ceiling(task_class)
        for task_class in PrepurchaseQuoteTaskClass
        if task_class not in covered
    )
    return tuple(ceilings)


def validate_accepted_prepurchase_quote_for_run(
    config: AuditConfig,
    *,
    acceptance: AcceptedPrepurchaseQuote,
    campaign_manifest: SchedulerCampaignManifest,
    solidity_shard_inventory: SolidityShardInventory,
    portfolio_preflight: ModelPortfolioResourcePreflight,
    selected_model_ids: frozenset[str] | None = None,
) -> PrepurchaseQuote:
    """Rebuild current target joins and reject a stale accepted quote before dispatch."""

    if type(acceptance) is not AcceptedPrepurchaseQuote:
        raise PrepurchaseQuotePlanningError("run quote acceptance has an invalid exact type")
    _require_configured_ledger_capacity(config, campaign_manifest)
    resolved_model_ids, selected_model_set_sha256 = _resolve_selected_model_projection(
        campaign_manifest,
        selected_model_ids,
    )
    local_analysis = build_quote_local_analysis_ceiling(
        config,
        campaign_manifest=campaign_manifest,
        solidity_shard_inventory=solidity_shard_inventory,
    )
    expected_task_ceilings = _current_accepted_task_ceilings(
        config,
        acceptance=acceptance,
        solidity_shard_inventory=solidity_shard_inventory,
        portfolio_preflight=portfolio_preflight,
        resolved_model_ids=resolved_model_ids,
        selected_model_set_sha256=selected_model_set_sha256,
    )
    try:
        rebuilt = build_prepurchase_quote(
            campaign_manifest=campaign_manifest,
            solidity_shard_inventory=solidity_shard_inventory,
            portfolio_preflight=portfolio_preflight,
            local_analysis_ceiling=local_analysis,
            retry_policy=config.execution.model_retry_policy,
            task_ceilings=expected_task_ceilings,
        )
    except (TypeError, ValueError) as exc:
        raise PrepurchaseQuotePlanningError(
            f"accepted quote differs from current run inputs: {exc}"
        ) from exc
    if rebuilt != acceptance.quote or rebuilt.quote_sha256 != acceptance.quote_sha256:
        raise PrepurchaseQuotePlanningError("accepted quote is stale for the current target")
    return rebuilt


__all__ = [
    "PrepurchaseQuotePlanningError",
    "build_prepurchase_quote_from_frozen_inputs",
    "build_quote_local_analysis_ceiling",
    "validate_accepted_prepurchase_quote_for_run",
]
