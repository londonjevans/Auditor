"""Role-specific, redacted, bounded context packages."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import Any

from mmaudit.config import PrivacyConfig, RepositoryConfig
from mmaudit.models.schemas import (
    ContextExcerpt,
    ContextPackage,
    EconomicSimulationPlan,
    EvidenceStrength,
    FormalToolRun,
    InvariantExecutionResult,
    InvariantSuite,
    ModelSurfaceReviewRequest,
    RepositoryMap,
    ScannerFinding,
    SolidityCompilationResult,
    SolidityCoverage,
    SolidityGraphSet,
    SolidityProjectMetadata,
    SoliditySymbolIndex,
    ThreatModel,
)
from mmaudit.models.token_planning import (
    ContextOmissionCategory,
    ContextOmissionItem,
    ContextOmissionReason,
)
from mmaudit.orchestration.model_coverage import build_model_surface_requests
from mmaudit.repository.chunking import chunk_text
from mmaudit.repository.discovery import DiscoveredFile, DiscoveryResult
from mmaudit.repository.redaction import SecretSafetyError, detect_secrets, redact_text
from mmaudit.solidity.retrieval import (
    compact_solidity_graphs,
    compact_solidity_index,
    solidity_preferred_paths,
)


class ContextBudgetError(RuntimeError):
    """Raised when even metadata cannot fit an explicit context allocation."""


@dataclass(frozen=True, slots=True)
class ContextCategoryMeasurement:
    """Hash/count projection for one provider-visible context category."""

    content_sha256: str
    utf8_bytes: int


def _scanner_context_payload(findings: Iterable[ScannerFinding]) -> list[dict[str, Any]]:
    """Serialize scanner evidence compactly without dropping non-default strength."""

    payloads: list[dict[str, Any]] = []
    for finding in findings:
        payload = finding.model_dump(mode="json")
        if finding.evidence_strength is EvidenceStrength.NONE:
            payload.pop("evidence_strength", None)
        payloads.append(payload)
    return payloads


def _add_context_omission(
    inventory: dict[str, ContextOmissionItem],
    *,
    category: ContextOmissionCategory,
    reason: ContextOmissionReason,
    identity: Any,
) -> None:
    """Bind one omission to deterministic identity while retaining hash-only evidence."""

    identity_payload = {
        "category": category.value,
        "reason": reason.value,
        "identity": identity,
    }
    item = ContextOmissionItem.build(
        category=category,
        reason=reason,
        omitted_item_sha256=hashlib.sha256(
            json.dumps(
                identity_payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest(),
    )
    inventory[item.evidence_sha256] = item


def _inventory_transition_identity(
    component: str,
    *,
    before: Any,
    after: Any,
    bounds: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Return hash-only before/after inventory identity for one reduction."""

    def content_hash(value: Any) -> str:
        return hashlib.sha256(
            json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()

    identity: dict[str, Any] = {
        "kind": "inventory_transition",
        "component": component,
        "before_sha256": content_hash(before),
        "after_sha256": content_hash(after),
    }
    if bounds is not None:
        identity["bounds"] = dict(sorted(bounds.items()))
    return identity


def _canonical_context_omissions(
    inventory: dict[str, ContextOmissionItem],
) -> list[ContextOmissionItem]:
    return sorted(
        inventory.values(),
        key=lambda item: (
            item.category.value,
            item.reason.value,
            item.omitted_item_sha256,
        ),
    )


_ROLE_CATEGORY_WEIGHTS: dict[str, dict[str, int]] = {
    "threat_model": {
        "api": 8,
        "auth": 9,
        "network": 7,
        "sensitive": 8,
        "business_logic": 6,
        "configuration": 4,
        "changed": 5,
        "smart_contract": 9,
        "evm_auth": 9,
        "evm_external_call": 8,
        "evm_upgrade": 8,
        "evm_value": 8,
        "evm_signature": 7,
        "evm_oracle": 7,
    },
    "source_audit": {
        "api": 8,
        "auth": 9,
        "data": 8,
        "file": 8,
        "network": 9,
        "serialization": 9,
        "command": 10,
        "sensitive": 7,
        "changed": 8,
        "test": 3,
        "smart_contract": 10,
        "evm_auth": 9,
        "evm_external_call": 10,
        "evm_upgrade": 9,
        "evm_value": 9,
        "evm_signature": 8,
        "evm_storage": 7,
    },
    "business_logic": {
        "business_logic": 10,
        "api": 7,
        "auth": 8,
        "data": 6,
        "changed": 8,
        "test": 5,
        "smart_contract": 9,
        "evm_value": 10,
        "evm_token": 8,
        "evm_oracle": 7,
        "evm_storage": 7,
    },
    "configuration": {
        "configuration": 10,
        "dependency": 10,
        "sensitive": 7,
        "network": 5,
        "changed": 6,
        "smart_contract": 6,
        "evm_upgrade": 9,
        "evm_oracle": 8,
        "evm_signature": 6,
    },
    "verifier": {
        "auth": 9,
        "api": 8,
        "data": 8,
        "test": 8,
        "changed": 7,
        "source": 3,
        "smart_contract": 8,
        "evm_auth": 9,
        "evm_external_call": 8,
        "evm_upgrade": 8,
        "evm_value": 8,
    },
    "judge": {
        "auth": 5,
        "api": 5,
        "data": 5,
        "configuration": 5,
        "test": 5,
        "changed": 6,
        "smart_contract": 7,
    },
}

_SPECIALIST_CATEGORY_WEIGHTS: dict[str, dict[str, int]] = {
    "access_control": {"evm_auth": 12, "auth": 10, "evm_upgrade": 7, "smart_contract": 8},
    "reentrancy_control_flow": {
        "evm_external_call": 12,
        "evm_value": 10,
        "evm_storage": 9,
        "smart_contract": 8,
    },
    "economic_game_theory": {
        "evm_value": 12,
        "evm_oracle": 10,
        "business_logic": 10,
        "evm_external_call": 8,
    },
    "oracle_price_manipulation": {
        "evm_oracle": 12,
        "evm_value": 10,
        "evm_external_call": 8,
    },
    "accounting_invariant": {"evm_value": 12, "evm_storage": 10, "business_logic": 9},
    "token_standard": {"evm_token": 12, "evm_value": 10, "evm_external_call": 8},
    "erc4626_vault": {"evm_value": 12, "evm_token": 10, "evm_storage": 9},
    "amm_dex_liquidity": {"evm_value": 12, "evm_oracle": 9, "evm_external_call": 10},
    "lending_liquidation": {"evm_value": 12, "evm_oracle": 10, "evm_storage": 9},
    "governance_timelock": {"evm_auth": 11, "evm_upgrade": 10, "business_logic": 9},
    "upgradeability_storage": {"evm_upgrade": 12, "evm_storage": 12, "evm_auth": 9},
    "initialization_deployment": {
        "evm_upgrade": 12,
        "evm_auth": 10,
        "configuration": 9,
        "smart_contract": 8,
    },
    "signature_permit_replay": {"evm_signature": 12, "evm_auth": 8, "evm_storage": 7},
    "mev_ordering": {"evm_value": 12, "evm_oracle": 9, "business_logic": 10},
    "denial_of_service_griefing": {
        "evm_external_call": 11,
        "business_logic": 10,
        "evm_storage": 8,
    },
    "precision_rounding": {"evm_value": 12, "evm_storage": 9, "business_logic": 8},
    "cross_chain_bridge": {"evm_signature": 10, "evm_value": 10, "evm_external_call": 9},
    "dependency_supply_chain": {
        "dependency": 12,
        "configuration": 11,
        "evm_upgrade": 7,
        "smart_contract": 5,
    },
    "formal_methods_property": {"evm_storage": 10, "evm_auth": 9, "evm_value": 9},
    "false_negative_hunter": {"smart_contract": 10, "changed": 8, "test": 5},
    "invariant_review": {
        "evm_storage": 12,
        "evm_value": 12,
        "evm_auth": 10,
        "evm_token": 9,
        "evm_oracle": 9,
        "smart_contract": 8,
    },
    "test_generation": {
        "smart_contract": 12,
        "test": 11,
        "evm_external_call": 10,
        "evm_value": 10,
    },
    "exploit_reproduction_planner": {
        "smart_contract": 12,
        "evm_external_call": 11,
        "evm_value": 11,
        "evm_auth": 10,
    },
    "falsifier": {
        "smart_contract": 12,
        "test": 10,
        "evm_auth": 10,
        "evm_value": 10,
    },
    "report_quality": {
        "smart_contract": 8,
        "changed": 8,
        "test": 8,
        "configuration": 8,
        "dependency": 8,
    },
}


def _role_weights(role: str) -> dict[str, int]:
    specialist = role.removeprefix("specialist:")
    return _ROLE_CATEGORY_WEIGHTS.get(
        role,
        _SPECIALIST_CATEGORY_WEIGHTS.get(specialist, {}),
    )


def _score(file: DiscoveredFile, role: str) -> tuple[int, str]:
    weights = _role_weights(role)
    score = sum(weights.get(category, 1) for category in file.categories)
    return (-score, file.relative_path)


def _compact_map(repository_map: RepositoryMap, role: str, max_files: int = 300) -> RepositoryMap:
    sorted_files = sorted(
        repository_map.files,
        key=lambda file: (
            -sum(_role_weights(role).get(category, 1) for category in file.categories),
            file.path,
        ),
    )
    list_limit = min(100, max(1, max_files))
    omitted = list(repository_map.omitted_files[:list_limit])
    if len(sorted_files) > max_files:
        omitted.append(f"repository map: {len(sorted_files) - max_files} file entries omitted")
    return repository_map.model_copy(
        update={
            "files": sorted_files[:max_files],
            "omitted_files": omitted,
            "manifests": repository_map.manifests[:list_limit],
            "entry_points": repository_map.entry_points[:list_limit],
            "api_surfaces": repository_map.api_surfaces[:list_limit],
            "auth_components": repository_map.auth_components[:list_limit],
            "data_layers": repository_map.data_layers[:list_limit],
            "network_clients": repository_map.network_clients[:list_limit],
            "file_handlers": repository_map.file_handlers[:list_limit],
            "configuration_files": repository_map.configuration_files[:list_limit],
            "sensitive_processing": repository_map.sensitive_processing[:list_limit],
            "security_tests": repository_map.security_tests[:list_limit],
        }
    )


class ContextBuilder:
    """Prepare all potential source locally before any model request is possible."""

    def __init__(
        self,
        *,
        discovery: DiscoveryResult,
        repository_map: RepositoryMap,
        repository_config: RepositoryConfig,
        privacy: PrivacyConfig,
        scanner_findings: list[ScannerFinding],
        scanner_secret_paths: set[str] | None = None,
        solidity_projects: list[SolidityProjectMetadata] | None = None,
        solidity_compilations: list[SolidityCompilationResult] | None = None,
        solidity_index: SoliditySymbolIndex | None = None,
        solidity_graphs: SolidityGraphSet | None = None,
        solidity_invariants: InvariantSuite | None = None,
        invariant_executions: list[InvariantExecutionResult] | None = None,
        economic_simulations: list[EconomicSimulationPlan] | None = None,
        formal_runs: list[FormalToolRun] | None = None,
        solidity_coverage: SolidityCoverage | None = None,
        planned_packages: int = 6,
        maximum_source_tokens_per_request: int = 200_000,
    ) -> None:
        self.discovery = discovery
        self.repository_map = repository_map
        self.repository_config = repository_config
        self.privacy = privacy
        self._scanner_secret_paths = {
            *(scanner_secret_paths or set()),
            *(
                location.path
                for finding in scanner_findings
                if finding.scanner == "gitleaks" or finding.metadata.get("class") == "secret"
                for location in finding.locations
            ),
        }
        if self._scanner_secret_paths and privacy.fail_on_detected_secret:
            raise SecretSafetyError(
                "deterministic scanner detected a potential secret in model-eligible source; "
                "model egress blocked"
            )
        self._safe_files = self._redact_every_file(discovery.files)
        safe_paths = {item.relative_path for item in self._safe_files}
        self.repository_map = self._safe_repository_map(repository_map, safe_paths)
        self.scanner_findings = self._redact_scanner_findings(
            scanner_findings,
            safe_paths,
        )
        self.solidity_projects = solidity_projects or []
        self.solidity_compilations = solidity_compilations or []
        self.solidity_index = solidity_index
        self.solidity_graphs = solidity_graphs
        self.solidity_invariants = solidity_invariants
        self.invariant_executions = invariant_executions or []
        self.economic_simulations = economic_simulations or []
        self.formal_runs = formal_runs or []
        self.solidity_coverage = solidity_coverage
        self.planned_packages = max(1, planned_packages)
        if (
            isinstance(maximum_source_tokens_per_request, bool)
            or maximum_source_tokens_per_request <= 0
        ):
            raise ContextBudgetError("maximum source token budget must be positive")
        self.maximum_source_tokens_per_request = maximum_source_tokens_per_request

    def _redact_every_file(self, files: Iterable[DiscoveredFile]) -> tuple[DiscoveredFile, ...]:
        safe: list[DiscoveredFile] = []
        for item in files:
            if item.relative_path in self._scanner_secret_paths:
                continue
            path_matches = detect_secrets(item.relative_path)
            if any(match.confidence == "high" for match in path_matches):
                redact_text(
                    item.relative_path,
                    fail_on_detected_secret=self.privacy.fail_on_detected_secret,
                    redact=False,
                )
            if path_matches:
                continue
            redacted, _matches = redact_text(
                item.content,
                fail_on_detected_secret=self.privacy.fail_on_detected_secret,
                redact=self.privacy.redact_secrets,
            )
            safe.append(replace(item, content=redacted, size=len(redacted.encode())))
        return tuple(safe)

    def _safe_repository_map(
        self,
        repository_map: RepositoryMap,
        safe_paths: set[str],
    ) -> RepositoryMap:
        path_fields = (
            "manifests",
            "entry_points",
            "api_surfaces",
            "auth_components",
            "data_layers",
            "network_clients",
            "file_handlers",
            "configuration_files",
            "sensitive_processing",
            "security_tests",
        )
        updates: dict[str, Any] = {
            field: [path for path in getattr(repository_map, field) if path in safe_paths]
            for field in path_fields
        }
        updates["files"] = [file for file in repository_map.files if file.path in safe_paths]
        updates["root_name"] = self._redact_string(repository_map.root_name)
        updates["changed_since"] = (
            self._redact_string(repository_map.changed_since)
            if repository_map.changed_since
            else None
        )
        updates["omitted_files"] = [
            self._redact_string(value) for value in repository_map.omitted_files
        ]
        omitted_path_count = len(repository_map.files) - len(updates["files"])
        if omitted_path_count:
            updates["omitted_files"].append(
                f"{omitted_path_count} file(s) withheld by local secret safeguards"
            )
        return repository_map.model_copy(update=updates)

    def _redact_scanner_findings(
        self,
        scanner_findings: list[ScannerFinding],
        safe_paths: set[str],
    ) -> list[ScannerFinding]:
        safe: list[ScannerFinding] = []
        for finding in scanner_findings:
            locations = [location for location in finding.locations if location.path in safe_paths]
            if not locations:
                continue
            safe.append(
                finding.model_copy(
                    update={
                        "rule_id": self._redact_string(finding.rule_id),
                        "title": self._redact_string(finding.title),
                        "message": self._redact_string(finding.message),
                        "locations": locations,
                        "metadata": self._redact_value(finding.metadata),
                    }
                )
            )
        return safe

    def _redact_string(self, value: str) -> str:
        redacted, _matches = redact_text(
            value,
            fail_on_detected_secret=self.privacy.fail_on_detected_secret,
            redact=self.privacy.redact_secrets,
        )
        return redacted

    def _redact_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._redact_string(value)
        if isinstance(value, list):
            return [self._redact_value(item) for item in value]
        if isinstance(value, dict):
            return {
                self._redact_string(str(key)): self._redact_value(item)
                for key, item in value.items()
            }
        return value

    @property
    def remaining_bytes(self) -> int:
        """Return the per-package serialization ceiling kept for compatibility."""

        return self.repository_config.max_total_context_bytes

    def build(
        self,
        role: str,
        *,
        threat_model: ThreatModel | None = None,
        requested_budget: int | None = None,
        preferred_paths: set[str] | None = None,
        requested_model_surfaces: list[ModelSurfaceReviewRequest] | None = None,
        request_model_surface_reviews: bool = False,
    ) -> ContextPackage:
        """Allocate one independently bounded package."""

        if request_model_surface_reviews and requested_model_surfaces is not None:
            raise ContextBudgetError("model surface requests cannot be both derived and supplied")
        # The source limit is an estimated-token planning ceiling, while the
        # package budget covers source plus deterministic metadata. The provider
        # planner independently reserves the full UTF-8 byte upper bound before
        # transport, so allowing the deterministic byte/3 estimate here cannot
        # overrun an endpoint.
        source_byte_ceiling = min(
            2**31 - 1,
            self.maximum_source_tokens_per_request * 3,
        )
        default_share = self.repository_config.max_total_context_bytes
        budget = min(
            requested_budget or default_share,
            self.repository_config.max_total_context_bytes,
        )
        if budget <= 0:
            raise ContextBudgetError("repository context package budget is invalid")
        omissions: dict[str, ContextOmissionItem] = {}

        def omit(
            category: ContextOmissionCategory,
            reason: ContextOmissionReason,
            identity: Any,
        ) -> None:
            _add_context_omission(
                omissions,
                category=category,
                reason=reason,
                identity=identity,
            )

        file_limit = min(300, len(self.repository_map.files))
        scanner_limit = min(200, len(self.scanner_findings))
        entity_limit = 500
        graph_edge_limit = 700
        include_solidity_index = self.solidity_index is not None
        include_solidity_graphs = self.solidity_graphs is not None
        included_threat_model = threat_model
        included_solidity_compilations = list(self.solidity_compilations)
        included_solidity_invariants = (
            None if request_model_surface_reviews else self.solidity_invariants
        )
        included_invariant_executions = (
            [] if request_model_surface_reviews else list(self.invariant_executions)
        )
        included_economic_simulations = (
            [] if request_model_surface_reviews else list(self.economic_simulations)
        )
        included_formal_runs = [] if request_model_surface_reviews else list(self.formal_runs)
        included_solidity_coverage = (
            None if request_model_surface_reviews else self.solidity_coverage
        )
        selected_model_surfaces = list(requested_model_surfaces or [])
        deterministic_preferred_paths = set(preferred_paths or set())
        deterministic_preferred_paths.update(
            location.path
            for request in selected_model_surfaces
            for location in request.allowed_locations
        )
        available_source_bytes = min(
            source_byte_ceiling,
            sum(len(item.content.encode("utf-8")) for item in self._safe_files),
        )
        source_serialization_capacity = min(
            max(0, budget - 1),
            available_source_bytes + (8_192 if available_source_bytes else 0),
        )
        minimum_source_reserve = min(8_192, source_serialization_capacity)
        source_reserve = min(
            max(0, budget - 1),
            source_serialization_capacity,
            max(minimum_source_reserve, (budget * 65) // 100),
        )
        metadata_ceiling = max(1, budget - source_reserve)
        review_request_mode = bool(selected_model_surfaces) or request_model_surface_reviews
        if review_request_mode:
            omit(
                ContextOmissionCategory.METADATA,
                ContextOmissionReason.REVIEW_CONTRACT_WITHHELD,
                _inventory_transition_identity(
                    "bulk_deterministic_analysis",
                    before={
                        "solidity_invariants": (
                            self.solidity_invariants.model_dump(mode="json")
                            if self.solidity_invariants is not None
                            else None
                        ),
                        "invariant_executions": [
                            result.model_dump(mode="json") for result in self.invariant_executions
                        ],
                        "economic_simulations": [
                            plan.model_dump(mode="json") for plan in self.economic_simulations
                        ],
                        "formal_runs": [run.model_dump(mode="json") for run in self.formal_runs],
                        "solidity_coverage": (
                            self.solidity_coverage.model_dump(mode="json")
                            if self.solidity_coverage is not None
                            else None
                        ),
                    },
                    after={
                        "solidity_invariants": None,
                        "invariant_executions": [],
                        "economic_simulations": [],
                        "formal_runs": [],
                        "solidity_coverage": None,
                    },
                ),
            )
        minimum_compact_limit = 8 if review_request_mode else 32
        preserve_invariant_index = role.removeprefix("specialist:") == "invariant_review"
        while True:
            compact_map = _compact_map(self.repository_map, role, max_files=file_limit)
            selected_scanners = self.scanner_findings[:scanner_limit]
            compact_index = compact_solidity_index(
                self.solidity_index if include_solidity_index else None,
                role=role,
                max_entities=entity_limit,
                preferred_paths=deterministic_preferred_paths,
            )
            compact_graphs = compact_solidity_graphs(
                self.solidity_graphs if include_solidity_graphs else None,
                role=role,
                max_edges=graph_edge_limit,
                preferred_paths=deterministic_preferred_paths,
            )
            if request_model_surface_reviews:
                selected_model_surfaces = build_model_surface_requests(
                    index=compact_index,
                    graphs=compact_graphs,
                    invariants=self.solidity_invariants,
                    economic_simulations=self.economic_simulations,
                )
            base_package = ContextPackage(
                role=role,
                byte_budget=budget,
                bytes_used=0,
                repository_map=compact_map,
                scanner_findings=selected_scanners,
                excerpts=[],
                requested_model_surfaces=selected_model_surfaces,
                threat_model=included_threat_model,
                solidity_projects=self.solidity_projects,
                solidity_compilations=included_solidity_compilations,
                solidity_index=compact_index,
                solidity_graphs=compact_graphs,
                solidity_invariants=(None if review_request_mode else included_solidity_invariants),
                invariant_executions=([] if review_request_mode else included_invariant_executions),
                economic_simulations=([] if review_request_mode else included_economic_simulations),
                formal_runs=[] if review_request_mode else included_formal_runs,
                solidity_coverage=(None if review_request_mode else included_solidity_coverage),
                omissions=_canonical_context_omissions(omissions),
            )
            base_bytes = len(render_context(base_package).encode("utf-8"))
            if base_bytes <= metadata_ceiling:
                break
            if (
                compact_graphs is not None
                and compact_graphs.edges
                and graph_edge_limit > minimum_compact_limit
            ):
                previous_limit = graph_edge_limit
                next_limit = max(minimum_compact_limit, graph_edge_limit // 2)
                next_graphs = compact_solidity_graphs(
                    self.solidity_graphs,
                    role=role,
                    max_edges=next_limit,
                    preferred_paths=deterministic_preferred_paths,
                )
                before_graphs = compact_graphs.model_dump(mode="json")
                after_graphs = (
                    next_graphs.model_dump(mode="json") if next_graphs is not None else None
                )
                graph_edge_limit = next_limit
                if before_graphs == after_graphs:
                    continue
                omit(
                    ContextOmissionCategory.GRAPH,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    _inventory_transition_identity(
                        "solidity_graphs",
                        before=before_graphs,
                        after=after_graphs,
                        bounds={"before_limit": previous_limit, "after_limit": next_limit},
                    ),
                )
            elif include_solidity_graphs:
                include_solidity_graphs = False
                if compact_graphs is None:
                    continue
                omit(
                    ContextOmissionCategory.GRAPH,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    _inventory_transition_identity(
                        "solidity_graphs",
                        before=compact_graphs.model_dump(mode="json"),
                        after=None,
                        bounds={"before_limit": graph_edge_limit, "after_limit": 0},
                    ),
                )
            elif preserve_invariant_index and included_formal_runs:
                before_formal_runs = [run.model_dump(mode="json") for run in included_formal_runs]
                included_formal_runs = []
                omit(
                    ContextOmissionCategory.INVARIANT,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    _inventory_transition_identity(
                        "formal_runs",
                        before=before_formal_runs,
                        after=[],
                    ),
                )
            elif preserve_invariant_index and included_economic_simulations:
                before_economic_simulations = [
                    plan.model_dump(mode="json") for plan in included_economic_simulations
                ]
                included_economic_simulations = []
                omit(
                    ContextOmissionCategory.INVARIANT,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    _inventory_transition_identity(
                        "economic_simulations",
                        before=before_economic_simulations,
                        after=[],
                    ),
                )
            elif preserve_invariant_index and included_invariant_executions:
                before_invariant_executions = [
                    result.model_dump(mode="json") for result in included_invariant_executions
                ]
                included_invariant_executions = []
                omit(
                    ContextOmissionCategory.INVARIANT,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    _inventory_transition_identity(
                        "invariant_executions",
                        before=before_invariant_executions,
                        after=[],
                    ),
                )
            elif preserve_invariant_index and included_solidity_coverage is not None:
                before_solidity_coverage = included_solidity_coverage.model_dump(mode="json")
                included_solidity_coverage = None
                omit(
                    ContextOmissionCategory.FRAMEWORK,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    _inventory_transition_identity(
                        "solidity_coverage",
                        before=before_solidity_coverage,
                        after=None,
                    ),
                )
            elif preserve_invariant_index and included_solidity_compilations:
                before_solidity_compilations = [
                    result.model_dump(mode="json") for result in included_solidity_compilations
                ]
                included_solidity_compilations = []
                omit(
                    ContextOmissionCategory.FRAMEWORK,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    _inventory_transition_identity(
                        "solidity_compilations",
                        before=before_solidity_compilations,
                        after=[],
                    ),
                )
            elif (
                compact_index is not None
                and compact_index.entities
                and entity_limit > minimum_compact_limit
            ):
                previous_limit = entity_limit
                next_limit = max(minimum_compact_limit, entity_limit // 2)
                next_index = compact_solidity_index(
                    self.solidity_index,
                    role=role,
                    max_entities=next_limit,
                    preferred_paths=deterministic_preferred_paths,
                )
                before_index = compact_index.model_dump(mode="json")
                after_index = next_index.model_dump(mode="json") if next_index is not None else None
                entity_limit = next_limit
                if before_index == after_index:
                    continue
                omit(
                    ContextOmissionCategory.FRAMEWORK,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    _inventory_transition_identity(
                        "solidity_index",
                        before=before_index,
                        after=after_index,
                        bounds={"before_limit": previous_limit, "after_limit": next_limit},
                    ),
                )
            elif include_solidity_index:
                include_solidity_index = False
                if compact_index is None:
                    continue
                omit(
                    ContextOmissionCategory.FRAMEWORK,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    _inventory_transition_identity(
                        "solidity_index",
                        before=compact_index.model_dump(mode="json"),
                        after=None,
                        bounds={"before_limit": entity_limit, "after_limit": 0},
                    ),
                )
            elif included_formal_runs:
                before_formal_runs = [run.model_dump(mode="json") for run in included_formal_runs]
                included_formal_runs = []
                omit(
                    ContextOmissionCategory.INVARIANT,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    _inventory_transition_identity(
                        "formal_runs",
                        before=before_formal_runs,
                        after=[],
                    ),
                )
            elif included_economic_simulations:
                before_economic_simulations = [
                    plan.model_dump(mode="json") for plan in included_economic_simulations
                ]
                included_economic_simulations = []
                omit(
                    ContextOmissionCategory.INVARIANT,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    _inventory_transition_identity(
                        "economic_simulations",
                        before=before_economic_simulations,
                        after=[],
                    ),
                )
            elif included_invariant_executions:
                before_invariant_executions = [
                    result.model_dump(mode="json") for result in included_invariant_executions
                ]
                included_invariant_executions = []
                omit(
                    ContextOmissionCategory.INVARIANT,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    _inventory_transition_identity(
                        "invariant_executions",
                        before=before_invariant_executions,
                        after=[],
                    ),
                )
            elif included_solidity_invariants is not None:
                before_solidity_invariants = included_solidity_invariants.model_dump(mode="json")
                included_solidity_invariants = None
                omit(
                    ContextOmissionCategory.INVARIANT,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    _inventory_transition_identity(
                        "solidity_invariants",
                        before=before_solidity_invariants,
                        after=None,
                    ),
                )
            elif included_solidity_coverage is not None:
                before_solidity_coverage = included_solidity_coverage.model_dump(mode="json")
                included_solidity_coverage = None
                omit(
                    ContextOmissionCategory.FRAMEWORK,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    _inventory_transition_identity(
                        "solidity_coverage",
                        before=before_solidity_coverage,
                        after=None,
                    ),
                )
            elif included_solidity_compilations:
                before_solidity_compilations = [
                    result.model_dump(mode="json") for result in included_solidity_compilations
                ]
                included_solidity_compilations = []
                omit(
                    ContextOmissionCategory.FRAMEWORK,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    _inventory_transition_identity(
                        "solidity_compilations",
                        before=before_solidity_compilations,
                        after=[],
                    ),
                )
            elif scanner_limit:
                previous_limit = scanner_limit
                next_limit = scanner_limit // 2
                before_scanners = _scanner_context_payload(selected_scanners)
                after_scanners = _scanner_context_payload(self.scanner_findings[:next_limit])
                scanner_limit = next_limit
                if before_scanners == after_scanners:
                    continue
                omit(
                    ContextOmissionCategory.SCANNER,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    _inventory_transition_identity(
                        "scanner_findings",
                        before=before_scanners,
                        after=after_scanners,
                        bounds={"before_limit": previous_limit, "after_limit": next_limit},
                    ),
                )
            elif file_limit:
                previous_limit = file_limit
                next_limit = file_limit // 2
                next_map = _compact_map(self.repository_map, role, max_files=next_limit)
                before_map = compact_map.model_dump(mode="json")
                after_map = next_map.model_dump(mode="json")
                file_limit = next_limit
                if before_map == after_map:
                    continue
                omit(
                    ContextOmissionCategory.METADATA,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    _inventory_transition_identity(
                        "repository_map",
                        before=before_map,
                        after=after_map,
                        bounds={"before_limit": previous_limit, "after_limit": next_limit},
                    ),
                )
            elif included_threat_model is not None:
                before_threat_model = included_threat_model.model_dump(mode="json")
                included_threat_model = None
                omit(
                    ContextOmissionCategory.METADATA,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    _inventory_transition_identity(
                        "threat_model",
                        before=before_threat_model,
                        after=None,
                    ),
                )
            elif base_bytes <= budget:
                omit(
                    ContextOmissionCategory.METADATA,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    {
                        "kind": "metadata_source_reserve_conflict",
                        "metadata_sha256": hashlib.sha256(
                            render_context(base_package).encode("utf-8")
                        ).hexdigest(),
                        "metadata_bytes": base_bytes,
                        "metadata_ceiling": metadata_ceiling,
                        "source_reserve": source_reserve,
                    },
                )
                break
            else:
                raise ContextBudgetError(
                    f"minimum metadata for role {role} exceeds its {budget}-byte allocation"
                )
        excerpt_budget = min(
            source_byte_ceiling,
            max(0, budget - base_bytes),
        )
        used = base_bytes
        source_used = 0
        excerpts: list[ContextExcerpt] = []
        preferred_paths = deterministic_preferred_paths | solidity_preferred_paths(
            self.solidity_index,
            role,
        )
        ranked = sorted(
            self._safe_files,
            key=lambda item: (
                0 if item.relative_path in preferred_paths else 1,
                *_score(item, role),
            ),
        )
        ranked_source_inventory = [
            {
                "path_sha256": hashlib.sha256(item.relative_path.encode("utf-8")).hexdigest(),
                "content_sha256": hashlib.sha256(item.content.encode("utf-8")).hexdigest(),
                "utf8_bytes": len(item.content.encode("utf-8")),
            }
            for item in ranked
        ]
        for item_index, item in enumerate(ranked):
            remaining_source_inventory = ranked_source_inventory[item_index:]
            if used >= budget:
                omit(
                    ContextOmissionCategory.SOURCE,
                    ContextOmissionReason.SOURCE_BUDGET_EXCLUDED,
                    {
                        "kind": "source_inventory_excluded",
                        "cause": "context_byte_budget",
                        "items": remaining_source_inventory,
                    },
                )
                break
            remaining_source_bytes = excerpt_budget - source_used
            if remaining_source_bytes <= 0:
                omit(
                    ContextOmissionCategory.SOURCE,
                    ContextOmissionReason.SOURCE_BUDGET_EXCLUDED,
                    {
                        "kind": "source_inventory_excluded",
                        "cause": "source_token_budget",
                        "items": remaining_source_inventory,
                    },
                )
                break
            chunk_limit = min(48_000, remaining_source_bytes, max(1, budget - used))
            result = chunk_text(
                path=item.relative_path,
                content=item.content,
                categories=item.categories,
                max_chunk_bytes=chunk_limit,
            )
            for descriptor in result.omissions:
                omit(
                    ContextOmissionCategory.SOURCE,
                    ContextOmissionReason.LOGICAL_BLOCK_EXCEEDS_LIMIT,
                    {
                        "kind": "logical_block_excluded",
                        "path_sha256": hashlib.sha256(
                            item.relative_path.encode("utf-8")
                        ).hexdigest(),
                        "source_sha256": hashlib.sha256(item.content.encode("utf-8")).hexdigest(),
                        "descriptor_sha256": hashlib.sha256(descriptor.encode("utf-8")).hexdigest(),
                    },
                )
            for excerpt in result.excerpts:
                size = len(excerpt.content.encode("utf-8"))
                remaining_excerpt_bytes = min(
                    max(0, budget - used),
                    max(0, excerpt_budget - source_used),
                )
                if size > remaining_excerpt_bytes:
                    omit(
                        ContextOmissionCategory.SOURCE,
                        ContextOmissionReason.SOURCE_BUDGET_EXCLUDED,
                        {
                            "kind": "source_excerpt_excluded",
                            "path_sha256": hashlib.sha256(excerpt.path.encode("utf-8")).hexdigest(),
                            "start_line": excerpt.start_line,
                            "end_line": excerpt.end_line,
                            "content_sha256": excerpt.content_hash,
                            "utf8_bytes": size,
                            "available_bytes": remaining_excerpt_bytes,
                        },
                    )
                    continue
                excerpts.append(excerpt)
                used += size
                source_used += size
        package = ContextPackage(
            role=role,
            byte_budget=budget,
            bytes_used=0,
            repository_map=compact_map,
            scanner_findings=selected_scanners,
            excerpts=excerpts,
            requested_model_surfaces=selected_model_surfaces,
            threat_model=included_threat_model,
            solidity_projects=self.solidity_projects,
            solidity_compilations=included_solidity_compilations,
            solidity_index=compact_solidity_index(
                self.solidity_index if include_solidity_index else None,
                role=role,
                max_entities=entity_limit,
                preferred_paths=deterministic_preferred_paths,
            ),
            solidity_graphs=compact_solidity_graphs(
                self.solidity_graphs if include_solidity_graphs else None,
                role=role,
                max_edges=graph_edge_limit,
                preferred_paths=deterministic_preferred_paths,
            ),
            solidity_invariants=(None if review_request_mode else included_solidity_invariants),
            invariant_executions=([] if review_request_mode else included_invariant_executions),
            economic_simulations=([] if review_request_mode else included_economic_simulations),
            formal_runs=[] if review_request_mode else included_formal_runs,
            solidity_coverage=(None if review_request_mode else included_solidity_coverage),
            omissions=_canonical_context_omissions(omissions),
        )
        actual_bytes = len(render_context(package).encode())
        while package.excerpts and actual_bytes > budget:
            removed = package.excerpts[-1]
            omit(
                ContextOmissionCategory.SOURCE,
                ContextOmissionReason.SERIALIZED_BUDGET_EXCLUDED,
                {
                    "kind": "source_excerpt_excluded",
                    "path_sha256": hashlib.sha256(removed.path.encode("utf-8")).hexdigest(),
                    "start_line": removed.start_line,
                    "end_line": removed.end_line,
                    "content_sha256": removed.content_hash,
                    "utf8_bytes": len(removed.content.encode("utf-8")),
                    "serialized_bytes_before": actual_bytes,
                    "serialized_budget": budget,
                },
            )
            package = package.model_copy(
                update={
                    "excerpts": package.excerpts[:-1],
                    "omissions": _canonical_context_omissions(omissions),
                }
            )
            actual_bytes = len(render_context(package).encode())
        if actual_bytes > budget:
            raise ContextBudgetError(
                f"serialized metadata for role {role} exceeds its {budget}-byte allocation"
            )
        package = package.model_copy(update={"bytes_used": actual_bytes})
        if package.requested_model_surfaces and not package.excerpts:
            raise ContextBudgetError(
                f"model surface review context for role {role} omitted all source evidence"
            )
        return package


def context_hash_index(packages: Iterable[ContextPackage]) -> dict[tuple[str, int, int], str]:
    result: dict[tuple[str, int, int], str] = {}
    for package in packages:
        for file in package.repository_map.files:
            result[(file.path, 0, 0)] = file.sha256
        for excerpt in package.excerpts:
            result[(excerpt.path, excerpt.start_line, excerpt.end_line)] = excerpt.content_hash
    return result


def render_context(package: ContextPackage) -> str:
    """Serialize with explicit source delimiters and metadata outside bodies."""

    parts = [
        "<REPOSITORY_MAP_JSON>",
        json.dumps(package.repository_map.model_dump(mode="json"), sort_keys=True),
        "</REPOSITORY_MAP_JSON>",
        "<NORMALIZED_SCANNER_EVIDENCE_JSON>",
        json.dumps(
            _scanner_context_payload(package.scanner_findings),
            sort_keys=True,
        ),
        "</NORMALIZED_SCANNER_EVIDENCE_JSON>",
        "<TRUSTED_MODEL_SURFACE_REQUESTS_JSON>",
        json.dumps(
            [request.model_dump(mode="json") for request in package.requested_model_surfaces],
            sort_keys=True,
        ),
        "</TRUSTED_MODEL_SURFACE_REQUESTS_JSON>",
    ]
    if package.threat_model is not None:
        parts.extend(
            [
                "<THREAT_MODEL_JSON>",
                json.dumps(package.threat_model.model_dump(mode="json"), sort_keys=True),
                "</THREAT_MODEL_JSON>",
            ]
        )
    solidity_payload = {
        "projects": [project.model_dump(mode="json") for project in package.solidity_projects],
        "compilations": [
            result.model_dump(mode="json") for result in package.solidity_compilations
        ],
        "symbol_index": (
            package.solidity_index.model_dump(mode="json") if package.solidity_index else None
        ),
        "graphs": package.solidity_graphs.model_dump(mode="json")
        if package.solidity_graphs
        else None,
        "invariants": (
            package.solidity_invariants.model_dump(mode="json")
            if package.solidity_invariants
            else None
        ),
        "invariant_executions": [
            result.model_dump(mode="json") for result in package.invariant_executions
        ],
        "economic_simulations": [
            plan.model_dump(mode="json") for plan in package.economic_simulations
        ],
        "formal_runs": [run.model_dump(mode="json") for run in package.formal_runs],
        "coverage": package.solidity_coverage.model_dump(mode="json")
        if package.solidity_coverage
        else None,
    }
    if any(value for value in solidity_payload.values()):
        parts.extend(
            [
                "<DETERMINISTIC_SOLIDITY_FACTS_JSON>",
                json.dumps(solidity_payload, sort_keys=True),
                "</DETERMINISTIC_SOLIDITY_FACTS_JSON>",
            ]
        )
    for excerpt in package.excerpts:
        metadata = json.dumps(
            {
                "path": excerpt.path,
                "start_line": excerpt.start_line,
                "end_line": excerpt.end_line,
                "content_sha256": excerpt.content_hash,
            },
            sort_keys=True,
        )
        sentinel = f"MMAUDIT-UNTRUSTED-{excerpt.content_hash.upper()}"
        parts.extend(
            [
                "<REPOSITORY_EXCERPT_METADATA_JSON>",
                metadata,
                "</REPOSITORY_EXCERPT_METADATA_JSON>",
                f"-----BEGIN {sentinel}-----",
                excerpt.content,
                f"-----END {sentinel}-----",
            ]
        )
    if package.omissions:
        parts.extend(
            [
                "<OMISSIONS_JSON>",
                json.dumps(
                    [item.model_dump(mode="json") for item in package.omissions],
                    sort_keys=True,
                ),
                "</OMISSIONS_JSON>",
            ]
        )
    return "\n".join(parts)


def context_json_escape_overhead_tokens(package: ContextPackage) -> int:
    """Return exact JSON-string escaping overhead for the rendered context.

    OpenRouter transports the user message inside JSON. This local measurement
    accounts for quotes, control characters, backslashes, and non-ASCII source
    without retaining a second serialized copy in runtime evidence.
    """

    rendered = render_context(package)
    raw_bytes = len(rendered.encode("utf-8"))
    encoded_string = json.dumps(
        rendered,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    escaped_bytes = len(encoded_string) - 2
    if escaped_bytes < raw_bytes:
        raise ContextBudgetError("context JSON escaping measurement is inconsistent")
    return escaped_bytes - raw_bytes


def context_category_byte_counts(package: ContextPackage) -> dict[str, int]:
    """Account rendered context bytes without persisting source or prompt material."""

    rendered_bytes = len(render_context(package).encode("utf-8"))
    source_bytes = sum(len(excerpt.content.encode("utf-8")) for excerpt in package.excerpts)
    scanner_bytes = len(
        json.dumps(
            _scanner_context_payload(package.scanner_findings),
            sort_keys=True,
        ).encode("utf-8")
    )
    framework_payload = {
        "projects": [project.model_dump(mode="json") for project in package.solidity_projects],
        "compilations": [
            result.model_dump(mode="json") for result in package.solidity_compilations
        ],
        "symbol_index": (
            package.solidity_index.model_dump(mode="json") if package.solidity_index else None
        ),
        "coverage": (
            package.solidity_coverage.model_dump(mode="json") if package.solidity_coverage else None
        ),
    }
    graph_payload = (
        package.solidity_graphs.model_dump(mode="json") if package.solidity_graphs else None
    )
    invariant_payload = {
        "invariants": (
            package.solidity_invariants.model_dump(mode="json")
            if package.solidity_invariants
            else None
        ),
        "invariant_executions": [
            result.model_dump(mode="json") for result in package.invariant_executions
        ],
        "economic_simulations": [
            plan.model_dump(mode="json") for plan in package.economic_simulations
        ],
        "formal_runs": [run.model_dump(mode="json") for run in package.formal_runs],
    }

    def payload_bytes(value: Any) -> int:
        if value is None or value == [] or value == {}:
            return 0
        return len(json.dumps(value, sort_keys=True).encode("utf-8"))

    framework_bytes = payload_bytes(framework_payload) if any(framework_payload.values()) else 0
    graph_bytes = payload_bytes(graph_payload)
    invariant_bytes = payload_bytes(invariant_payload) if any(invariant_payload.values()) else 0
    accounted = source_bytes + scanner_bytes + framework_bytes + graph_bytes + invariant_bytes
    if accounted > rendered_bytes:
        raise ContextBudgetError("context category accounting exceeds rendered context")
    return {
        "framework": framework_bytes,
        "graph": graph_bytes,
        "invariant": invariant_bytes,
        "metadata": rendered_bytes - accounted,
        "prior_audit": 0,
        "scanner": scanner_bytes,
        "source": source_bytes,
        "workflow": 0,
    }


def context_category_measurements(
    package: ContextPackage,
) -> dict[str, ContextCategoryMeasurement]:
    """Bind category byte counts to actual local semantic context projections."""

    counts = context_category_byte_counts(package)
    rendered_sha256 = hashlib.sha256(render_context(package).encode("utf-8")).hexdigest()
    scanner_projection = json.dumps(
        _scanner_context_payload(package.scanner_findings),
        sort_keys=True,
    )
    framework_projection = json.dumps(
        {
            "projects": [project.model_dump(mode="json") for project in package.solidity_projects],
            "compilations": [
                result.model_dump(mode="json") for result in package.solidity_compilations
            ],
            "symbol_index": (
                package.solidity_index.model_dump(mode="json") if package.solidity_index else None
            ),
            "coverage": (
                package.solidity_coverage.model_dump(mode="json")
                if package.solidity_coverage
                else None
            ),
        },
        sort_keys=True,
    )
    graph_projection = json.dumps(
        package.solidity_graphs.model_dump(mode="json") if package.solidity_graphs else None,
        sort_keys=True,
    )
    invariant_projection = json.dumps(
        {
            "invariants": (
                package.solidity_invariants.model_dump(mode="json")
                if package.solidity_invariants
                else None
            ),
            "invariant_executions": [
                result.model_dump(mode="json") for result in package.invariant_executions
            ],
            "economic_simulations": [
                plan.model_dump(mode="json") for plan in package.economic_simulations
            ],
            "formal_runs": [run.model_dump(mode="json") for run in package.formal_runs],
        },
        sort_keys=True,
    )
    source_projection = json.dumps(
        [
            {
                "path": excerpt.path,
                "start_line": excerpt.start_line,
                "end_line": excerpt.end_line,
                "content_sha256": excerpt.content_hash,
                "utf8_bytes": len(excerpt.content.encode("utf-8")),
            }
            for excerpt in package.excerpts
        ],
        sort_keys=True,
    )
    projections = {
        "framework": framework_projection,
        "graph": graph_projection,
        "invariant": invariant_projection,
        "prior_audit": "",
        "scanner": scanner_projection,
        "source": source_projection,
        "workflow": "",
    }
    projection_hashes = {
        category: hashlib.sha256(value.encode("utf-8")).hexdigest()
        for category, value in projections.items()
    }
    metadata_projection = json.dumps(
        {
            "rendered_context_sha256": rendered_sha256,
            "category_byte_counts": counts,
            "semantic_projection_sha256s": projection_hashes,
        },
        sort_keys=True,
    )
    projection_hashes["metadata"] = hashlib.sha256(metadata_projection.encode("utf-8")).hexdigest()
    return {
        category: ContextCategoryMeasurement(
            content_sha256=projection_hashes[category],
            utf8_bytes=utf8_bytes,
        )
        for category, utf8_bytes in counts.items()
    }
