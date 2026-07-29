"""Role-specific, redacted, bounded context packages."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import replace
from typing import Any

from mmaudit.config import PrivacyConfig, RepositoryConfig
from mmaudit.models.schemas import (
    ContextExcerpt,
    ContextPackage,
    EconomicSimulationPlan,
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
        default_share = self.repository_config.max_total_context_bytes
        budget = min(
            requested_budget or default_share,
            self.repository_config.max_total_context_bytes,
        )
        if budget <= 0:
            raise ContextBudgetError("repository context package budget is invalid")
        omissions: list[str] = []
        file_limit = min(300, len(self.repository_map.files))
        scanner_limit = min(200, len(self.scanner_findings))
        entity_limit = 500
        graph_edge_limit = 700
        included_threat_model = threat_model
        selected_model_surfaces = list(requested_model_surfaces or [])
        deterministic_preferred_paths = set(preferred_paths or set())
        deterministic_preferred_paths.update(
            location.path
            for request in selected_model_surfaces
            for location in request.allowed_locations
        )
        source_reserve = min(64_000, max(8_192, budget // 4))
        metadata_ceiling = max(1, budget - source_reserve)
        review_request_mode = bool(selected_model_surfaces) or request_model_surface_reviews
        if review_request_mode:
            omissions.append(
                "bulk deterministic analysis omitted because exact surface requests "
                "carry the bounded review contract"
            )
        minimum_compact_limit = 8 if review_request_mode else 32
        while True:
            compact_map = _compact_map(self.repository_map, role, max_files=file_limit)
            selected_scanners = self.scanner_findings[:scanner_limit]
            compact_index = compact_solidity_index(
                self.solidity_index,
                role=role,
                max_entities=entity_limit,
                preferred_paths=deterministic_preferred_paths,
            )
            compact_graphs = compact_solidity_graphs(
                self.solidity_graphs,
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
            base_payload = {
                "repository_map": compact_map.model_dump(mode="json"),
                "scanner_findings": [
                    finding.model_dump(mode="json") for finding in selected_scanners
                ],
                "requested_model_surfaces": [
                    request.model_dump(mode="json") for request in selected_model_surfaces
                ],
                "threat_model": (
                    included_threat_model.model_dump(mode="json") if included_threat_model else None
                ),
                "solidity_projects": [
                    project.model_dump(mode="json") for project in self.solidity_projects
                ],
                "solidity_compilations": [
                    result.model_dump(mode="json") for result in self.solidity_compilations
                ],
                "solidity_index": (
                    compact_index.model_dump(mode="json") if compact_index is not None else None
                ),
                "solidity_graphs": (
                    compact_graphs.model_dump(mode="json") if compact_graphs is not None else None
                ),
                "solidity_invariants": (
                    self.solidity_invariants.model_dump(mode="json")
                    if self.solidity_invariants is not None and not review_request_mode
                    else None
                ),
                "invariant_executions": [
                    result.model_dump(mode="json") for result in self.invariant_executions
                ]
                if not review_request_mode
                else [],
                "economic_simulations": [
                    plan.model_dump(mode="json") for plan in self.economic_simulations
                ]
                if not review_request_mode
                else [],
                "formal_runs": (
                    [run.model_dump(mode="json") for run in self.formal_runs]
                    if not review_request_mode
                    else []
                ),
                "solidity_coverage": (
                    self.solidity_coverage.model_dump(mode="json")
                    if self.solidity_coverage is not None and not review_request_mode
                    else None
                ),
            }
            base_bytes = len(json.dumps(base_payload, sort_keys=True).encode()) + 512
            if base_bytes <= metadata_ceiling:
                break
            if graph_edge_limit > minimum_compact_limit:
                graph_edge_limit = max(minimum_compact_limit, graph_edge_limit // 2)
                omissions.append("semantic graph evidence reduced to reserve source-excerpt budget")
            elif entity_limit > minimum_compact_limit:
                entity_limit = max(minimum_compact_limit, entity_limit // 2)
                omissions.append("Solidity symbol index reduced to reserve source-excerpt budget")
            elif scanner_limit:
                scanner_limit //= 2
                omissions.append("normalized scanner evidence reduced to fit context budget")
            elif file_limit:
                file_limit //= 2
                omissions.append("repository map file list reduced to fit context budget")
            elif included_threat_model is not None:
                included_threat_model = None
                omissions.append("threat model omitted because it exceeded this role budget")
            elif base_bytes <= budget:
                omissions.append(
                    "minimum deterministic metadata prevented the requested source-excerpt reserve"
                )
                break
            else:
                raise ContextBudgetError(
                    f"minimum metadata for role {role} exceeds its {budget}-byte allocation"
                )
        excerpt_budget = max(0, budget - base_bytes)
        used = base_bytes
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
        for item in ranked:
            if used >= budget:
                omissions.append("context byte budget exhausted")
                break
            chunk_limit = min(48_000, max(1, excerpt_budget))
            result = chunk_text(
                path=item.relative_path,
                content=item.content,
                categories=item.categories,
                max_chunk_bytes=chunk_limit,
            )
            omissions.extend(result.omissions)
            for excerpt in result.excerpts:
                size = len(excerpt.content.encode())
                if size > budget - used:
                    omissions.append(
                        f"{excerpt.path}:{excerpt.start_line}-{excerpt.end_line} omitted by role budget"
                    )
                    continue
                excerpts.append(excerpt)
                used += size
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
            solidity_compilations=self.solidity_compilations,
            solidity_index=compact_solidity_index(
                self.solidity_index,
                role=role,
                max_entities=entity_limit,
                preferred_paths=deterministic_preferred_paths,
            ),
            solidity_graphs=compact_solidity_graphs(
                self.solidity_graphs,
                role=role,
                max_edges=graph_edge_limit,
                preferred_paths=deterministic_preferred_paths,
            ),
            solidity_invariants=(None if review_request_mode else self.solidity_invariants),
            invariant_executions=([] if review_request_mode else self.invariant_executions),
            economic_simulations=([] if review_request_mode else self.economic_simulations),
            formal_runs=[] if review_request_mode else self.formal_runs,
            solidity_coverage=None if review_request_mode else self.solidity_coverage,
            omissions=sorted(set(omissions)),
        )
        actual_bytes = len(render_context(package).encode())
        while package.excerpts and actual_bytes > budget:
            removed = package.excerpts[-1]
            omissions.append(
                f"{removed.path}:{removed.start_line}-{removed.end_line} omitted by serialized budget"
            )
            package = package.model_copy(
                update={
                    "excerpts": package.excerpts[:-1],
                    "omissions": sorted(set(omissions)),
                }
            )
            actual_bytes = len(render_context(package).encode())
        if actual_bytes > budget:
            raise ContextBudgetError(
                f"serialized metadata for role {role} exceeds its {budget}-byte allocation"
            )
        package = package.model_copy(update={"bytes_used": actual_bytes})
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
            [finding.model_dump(mode="json") for finding in package.scanner_findings],
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
                json.dumps(package.omissions, sort_keys=True),
                "</OMISSIONS_JSON>",
            ]
        )
    return "\n".join(parts)


def context_category_byte_counts(package: ContextPackage) -> dict[str, int]:
    """Account rendered context bytes without persisting source or prompt material."""

    rendered_bytes = len(render_context(package).encode("utf-8"))
    source_bytes = sum(len(excerpt.content.encode("utf-8")) for excerpt in package.excerpts)
    scanner_bytes = len(
        json.dumps(
            [finding.model_dump(mode="json") for finding in package.scanner_findings],
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
            package.solidity_coverage.model_dump(mode="json")
            if package.solidity_coverage
            else None
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
