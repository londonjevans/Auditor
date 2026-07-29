"""Configuration-driven, narrowly scoped specialist investigator ensemble."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal

from mmaudit.agents.base import FindingReviewResult, load_prompt
from mmaudit.config import AuditConfig, model_family
from mmaudit.constants import (
    ALL_SPECIALIST_ROLES,
    SPECIALIST_AUXILIARY_ROLES,
    SPECIALIST_INVESTIGATOR_ROLES,
)
from mmaudit.models.openrouter import OpenRouterClient, OpenRouterSchemaError
from mmaudit.models.schemas import (
    CandidateReviewBatch,
    ContextPackage,
    Evidence,
    Finding,
    ModelVote,
    QualityGateResult,
    ReportQualityReview,
    SolidityCoverage,
    SpecialistExecutionRecord,
    SpecialistExecutionStatus,
    UsageRecord,
)
from mmaudit.models.usage import is_creditable_usage_record
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.model_review_evidence import (
    ModelReviewEvidenceError,
    seal_model_surface_review_artifact,
)


@dataclass(frozen=True)
class SpecialistRoleDefinition:
    name: str
    mission: str
    required_checks: tuple[str, ...]
    context_priorities: tuple[str, ...]
    exclusions: tuple[str, ...] = ()
    role_kind: Literal["investigator", "auxiliary"] = "investigator"
    response_schema: str = "CandidateReviewBatch"
    schema_name: str = ""
    max_context_bytes: int = 256_000

    def effective_schema_name(self) -> str:
        return self.schema_name or f"mmaudit_specialist_{self.name}"

    def prompt_contract(self) -> str:
        return json.dumps(
            {
                "role": self.name,
                "role_kind": self.role_kind,
                "mission": self.mission,
                "required_checks": self.required_checks,
                "context_priorities": self.context_priorities,
                "scope_exclusions": self.exclusions,
                "response_schema": self.response_schema,
                "schema_name": self.effective_schema_name(),
                "max_context_bytes": self.max_context_bytes,
            },
            sort_keys=True,
        )


SPECIALIST_ROLE_REGISTRY: dict[str, SpecialistRoleDefinition] = {
    "access_control": SpecialistRoleDefinition(
        "access_control",
        "Find concrete authorization, privilege-escalation, tenant/role, and emergency-power defects.",
        (
            "Trace every privileged entry point to its role or caller check",
            "Check role administration, ownership transfer, timelock, and bypass paths",
            "Distinguish intended permissionless functions from missing authorization",
        ),
        ("privilege graph", "modifier graph", "public entry points", "deployment roles"),
    ),
    "reentrancy_control_flow": SpecialistRoleDefinition(
        "reentrancy_control_flow",
        "Find cross-function and cross-contract reentrancy, callback, and unsafe control-flow defects.",
        (
            "Trace external calls and all state writes before and after them",
            "Consider ERC777/ERC1155 callbacks and malicious receiver behavior",
            "Check guards across inherited and cross-contract paths",
        ),
        ("reentrancy graph", "external/delegate calls", "state flow", "modifiers"),
    ),
    "economic_game_theory": SpecialistRoleDefinition(
        "economic_game_theory",
        "Find profitable multi-actor, incentive, liquidity, sequencing, and mechanism-design defects.",
        (
            "State required capital, liquidity, privileges, timing, and repeatability assumptions",
            "Trace value extraction and victim/protocol loss across complete transaction sequences",
            "Separate technical state violations from economically infeasible strategies",
        ),
        ("asset flow", "state transitions", "economic plans", "oracle and market dependencies"),
    ),
    "oracle_price_manipulation": SpecialistRoleDefinition(
        "oracle_price_manipulation",
        "Find stale, manipulable, incorrectly scaled, or economically unsafe price dependencies.",
        (
            "Trace price source to every value-sensitive sink",
            "Check freshness, decimals, sign, sequencer, and TWAP assumptions",
            "Separate technical manipulability from economically feasible extraction",
        ),
        ("oracle graph", "asset flow", "AMM calls", "liquidation paths"),
    ),
    "accounting_invariant": SpecialistRoleDefinition(
        "accounting_invariant",
        "Find violated solvency, conservation, share, reward, debt, and fee invariants.",
        (
            "Identify conserved quantities and rounding direction",
            "Trace every balance/share/debt update across success and failure paths",
            "Check repeated and multi-actor transaction sequences",
        ),
        ("state dependencies", "asset flow", "inferred invariants", "tests"),
    ),
    "token_standard": SpecialistRoleDefinition(
        "token_standard",
        "Find token-standard and non-standard-token integration defects.",
        (
            "Check return values, callbacks, fee-on-transfer, rebasing, and unusual decimals",
            "Check supply, ownership, approval, and receiver invariants",
            "Check ERC20/ERC721/ERC1155 compatibility assumptions",
        ),
        ("token calls", "asset flow", "state writes", "interfaces"),
    ),
    "erc4626_vault": SpecialistRoleDefinition(
        "erc4626_vault",
        "Find ERC4626/vault inflation, donation, conversion, rounding, and solvency defects.",
        (
            "Test first depositor and direct donation scenarios",
            "Compare preview and execution rounding",
            "Trace totalAssets through strategies and losses",
        ),
        ("vault profile", "asset/share state", "conversion functions", "invariants"),
    ),
    "amm_dex_liquidity": SpecialistRoleDefinition(
        "amm_dex_liquidity",
        "Find reserve, liquidity, callback, slippage, and AMM integration defects.",
        (
            "Check reserve manipulation and callback ordering",
            "Check minimum-output/deadline enforcement",
            "Trace fee and liquidity-token accounting",
        ),
        ("AMM calls", "asset flow", "oracle graph", "transaction ordering"),
    ),
    "lending_liquidation": SpecialistRoleDefinition(
        "lending_liquidation",
        "Find collateral, interest, liquidation, bad-debt, and solvency defects.",
        (
            "Trace debt and collateral unit conversions",
            "Test boundary health factors and partial liquidation",
            "Check stale interest and oracle state across sequences",
        ),
        ("debt/collateral state", "oracle graph", "asset flow", "invariants"),
    ),
    "governance_timelock": SpecialistRoleDefinition(
        "governance_timelock",
        "Find proposal, voting, quorum, execution, and timelock bypass defects.",
        (
            "Trace proposal lifecycle and execution authority",
            "Check vote snapshot and flash-vote resistance",
            "Check cancellation, replay, and queued-call identity",
        ),
        ("privilege graph", "state machine", "delegate calls", "tests"),
    ),
    "upgradeability_storage": SpecialistRoleDefinition(
        "upgradeability_storage",
        "Find proxy initialization, upgrade authorization, selector, and storage-layout defects.",
        (
            "Identify proxy pattern, implementation, admin, and upgrade path",
            "Check initializer/reinitializer and disabled-initializer behavior",
            "Compare compiler storage layouts and inherited ordering",
        ),
        ("proxy graph", "storage layout", "initializer graph", "privilege graph"),
    ),
    "initialization_deployment": SpecialistRoleDefinition(
        "initialization_deployment",
        "Find constructor, initializer, deployment-order, ownership-handoff, and configuration defects.",
        (
            "Trace initial authority and every deployment-time trust assumption",
            "Check initializer uniqueness, disabled implementations, and reinitializer ordering",
            "Check zero/default addresses, partial deployments, and ownership handoff",
        ),
        ("initializer graph", "constructors", "deployment scripts", "proxy and privilege graphs"),
    ),
    "signature_permit_replay": SpecialistRoleDefinition(
        "signature_permit_replay",
        "Find signature validation, permit, nonce, domain separation, and replay defects.",
        (
            "Verify signer, nonce, deadline, chain, domain, and action binding",
            "Check malleability and contract-signature handling",
            "Check cross-chain and cross-contract replay",
        ),
        ("signature functions", "state writes", "chain assumptions", "tests"),
    ),
    "mev_ordering": SpecialistRoleDefinition(
        "mev_ordering",
        "Find frontrunning, sandwich, ordering, liquidation, and griefing defects.",
        (
            "Identify user-controlled price/slippage/deadline assumptions",
            "Evaluate transaction and multi-block ordering",
            "Separate extractable value from generic market risk",
        ),
        ("asset flow", "oracle/AMM calls", "state transitions", "economic invariants"),
    ),
    "denial_of_service_griefing": SpecialistRoleDefinition(
        "denial_of_service_griefing",
        "Find boundedness, liveness, gas, revert-propagation, lock, and griefing vulnerabilities.",
        (
            "Check attacker-controlled loops, queues, recipients, callbacks, and revert paths",
            "Trace whether one actor can block withdrawals, settlement, liquidation, or governance",
            "Distinguish temporary inconvenience from durable protocol or fund liveness failure",
        ),
        ("external calls", "collections", "state machines", "critical liveness entry points"),
    ),
    "precision_rounding": SpecialistRoleDefinition(
        "precision_rounding",
        "Find unit, decimal, truncation, overflow-boundary, dust, and repeated-rounding defects.",
        (
            "Track units and rounding direction across every conversion",
            "Test minimum, maximum, zero, repeated, and adversarially split operations",
            "Determine whether rounding loss is bounded or economically extractable",
        ),
        ("accounting state", "asset/share conversions", "fee calculations", "boundary tests"),
    ),
    "cross_chain_bridge": SpecialistRoleDefinition(
        "cross_chain_bridge",
        "Find message authentication, replay, finality, chain-domain, and bridge accounting defects.",
        (
            "Trace origin sender and chain validation",
            "Check message replay and failure recovery",
            "Check mint/burn or lock/release conservation",
        ),
        ("external dependencies", "signature state", "asset flow", "privilege graph"),
    ),
    "dependency_supply_chain": SpecialistRoleDefinition(
        "dependency_supply_chain",
        "Find unsafe Solidity dependencies, build configuration, package, compiler, and CI trust.",
        (
            "Check pins, remappings, compiler versions, optimizer settings, and imported trust",
            "Review privileged third-party contracts and deployment artifact assumptions",
            "Treat unavailable dependency source and failed resolution as coverage gaps",
        ),
        ("dependency manifests", "remappings", "compiler metadata", "CI and deployment files"),
    ),
    "formal_methods_property": SpecialistRoleDefinition(
        "formal_methods_property",
        "Identify narrow high-value properties and assess formal/symbolic evidence.",
        (
            "State properties with explicit assumptions and quantified state",
            "Interpret timeout/unknown as missing coverage",
            "Never claim proof from testing or model agreement",
        ),
        ("invariant suite", "formal results", "state graph", "source locations"),
    ),
    "false_negative_hunter": SpecialistRoleDefinition(
        "false_negative_hunter",
        "Blindly search weakly covered paths and vulnerability classes likely missed by other engines.",
        (
            "Prioritize uncovered public/state-writing/privileged functions",
            "Check cross-contract paths and scanner blind spots",
            "Return only independently derived candidates",
        ),
        ("coverage gaps", "semantic graphs", "unsupported files", "context omissions"),
    ),
    "invariant_review": SpecialistRoleDefinition(
        name="invariant_review",
        mission=(
            "Review source-derived invariant hypotheses and propose bounded, "
            "source-linked missing properties without creating findings."
        ),
        required_checks=(
            "Reference only supplied invariant and semantic entity identifiers",
            "Separate supported, unsupported, and context-limited hypotheses",
            "Keep every new property model-only until deterministic validation",
        ),
        context_priorities=(
            "invariant suite",
            "state and asset-flow graphs",
            "symbol index",
            "source locations",
        ),
        exclusions=("finding creation", "executable-test claims", "proof claims"),
        role_kind="auxiliary",
        response_schema="InvariantReviewBatch",
        schema_name="mmaudit_invariant_review",
        max_context_bytes=192_000,
    ),
    "test_generation": SpecialistRoleDefinition(
        name="test_generation",
        mission=(
            "Translate submitted verified candidates into minimal declarative negative "
            "regression specifications."
        ),
        required_checks=(
            "Bind every test to one submitted candidate and operator-approved target",
            "Separate explicit setup from attacker-reachable calls",
            "Use assertions that distinguish the unsafe condition from the remediation",
        ),
        context_priorities=(
            "candidate locations",
            "source reachability",
            "configured targets",
            "attacker capability bounds",
        ),
        exclusions=("new findings", "commands", "generated Solidity"),
        role_kind="auxiliary",
        response_schema="GeneratedFoundryTestBatch",
        schema_name="mmaudit_test_generation",
        max_context_bytes=192_000,
    ),
    "exploit_reproduction_planner": SpecialistRoleDefinition(
        name="exploit_reproduction_planner",
        mission=(
            "Plan bounded candidate reproduction with explicit preconditions, "
            "capabilities, settlement assumptions, and minimality."
        ),
        required_checks=(
            "Declare every actor, resource, privilege, timing, and ordering assumption",
            "Reject paths outside the typed local reproduction vocabulary",
            "Prefer the shortest candidate-specific sequence with a prohibited-state assertion",
        ),
        context_priorities=(
            "candidate evidence",
            "semantic call paths",
            "economic assumptions",
            "reproduction policy",
        ),
        exclusions=("live targets", "wallet operations", "undeclared capabilities"),
        role_kind="auxiliary",
        response_schema="GeneratedFoundryTestBatch",
        schema_name="mmaudit_exploit_reproduction_plan",
        max_context_bytes=192_000,
    ),
    "falsifier": SpecialistRoleDefinition(
        name="falsifier",
        mission=(
            "Independently reject reproduction evidence that does not establish its "
            "submitted candidate or relies on unsupported assumptions."
        ),
        required_checks=(
            "Match every decision to exactly one submitted candidate and test",
            "Check reachability, assumptions, assertion relevance, and remediation behavior",
            "Retain inconclusive or unsafe outcomes instead of manufacturing agreement",
        ),
        context_priorities=(
            "candidate evidence",
            "test specifications",
            "execution results",
            "source controls",
        ),
        exclusions=("new findings", "new tests", "source or command generation"),
        role_kind="auxiliary",
        response_schema="FalsificationBatch",
        schema_name="mmaudit_falsification",
        max_context_bytes=192_000,
    ),
    "report_quality": SpecialistRoleDefinition(
        name="report_quality",
        mission=(
            "Review report completeness, evidence calibration, coverage caveats, and "
            "unsupported assurance claims without changing findings."
        ),
        required_checks=(
            "Reconcile required sections, quality gates, and incomplete reasons",
            "Identify unsupported certainty and hidden coverage limitations",
            "Preserve finding decisions as non-authoritative input",
        ),
        context_priorities=(
            "quality gates",
            "coverage evidence",
            "findings and dissent",
            "unreviewed areas",
        ),
        exclusions=("finding creation", "severity changes", "assurance overrides"),
        role_kind="auxiliary",
        response_schema="ReportQualityReview",
        schema_name="mmaudit_report_quality_review",
        max_context_bytes=192_000,
    ),
}


def _validate_specialist_registry() -> None:
    if set(SPECIALIST_ROLE_REGISTRY) != set(ALL_SPECIALIST_ROLES):
        raise RuntimeError("specialist role registry does not match configured specialist roles")
    if {
        role
        for role, definition in SPECIALIST_ROLE_REGISTRY.items()
        if definition.role_kind == "investigator"
    } != set(SPECIALIST_INVESTIGATOR_ROLES):
        raise RuntimeError("specialist investigator classifications are inconsistent")
    if {
        role
        for role, definition in SPECIALIST_ROLE_REGISTRY.items()
        if definition.role_kind == "auxiliary"
    } != set(SPECIALIST_AUXILIARY_ROLES):
        raise RuntimeError("specialist auxiliary classifications are inconsistent")
    responsibilities = {
        (
            definition.mission,
            definition.required_checks,
            definition.context_priorities,
        )
        for definition in SPECIALIST_ROLE_REGISTRY.values()
    }
    if len(responsibilities) != len(SPECIALIST_ROLE_REGISTRY):
        raise RuntimeError("specialist responsibilities must be distinct")
    schema_names = {
        definition.effective_schema_name() for definition in SPECIALIST_ROLE_REGISTRY.values()
    }
    if len(schema_names) != len(SPECIALIST_ROLE_REGISTRY):
        raise RuntimeError("specialist structured schema names must be distinct")
    if any(
        definition.name != role
        or not definition.response_schema
        or definition.max_context_bytes <= 0
        for role, definition in SPECIALIST_ROLE_REGISTRY.items()
    ):
        raise RuntimeError("specialist role metadata is incomplete")


_validate_specialist_registry()


def specialist_context_budget(
    role: str,
    *,
    total_context_bytes: int,
    planned_packages: int,
) -> int:
    """Return one role's local serialization cap without peer-count coupling."""

    definition = SPECIALIST_ROLE_REGISTRY[role]
    if planned_packages < 1:
        raise ValueError("planned package count must be positive")
    return min(definition.max_context_bytes, max(1, total_context_bytes))


def canonical_specialist_role(request_role: str) -> str | None:
    """Resolve a usage-ledger request role to one configured specialist role."""

    parts = request_role.split(":", 2)
    if len(parts) < 2 or parts[0] != "specialist":
        return None
    role = parts[1]
    return role if role in SPECIALIST_ROLE_REGISTRY else None


def build_specialist_execution_records(
    config: AuditConfig,
    *,
    usage_records: list[UsageRecord],
    contexts: list[ContextPackage],
) -> list[SpecialistExecutionRecord]:
    """Normalize configured, scheduled, failed, and completed specialist evidence."""

    configured_roles = set(config.models.specialists)
    records: list[SpecialistExecutionRecord] = []
    for role in ALL_SPECIALIST_ROLES:
        definition = SPECIALIST_ROLE_REGISTRY[role]
        request_prefix = f"specialist:{role}"
        role_usage = [
            record for record in usage_records if canonical_specialist_role(record.role) == role
        ]
        context = next(
            (package for package in contexts if package.role == request_prefix),
            None,
        )
        successful_requests = sum(is_creditable_usage_record(record) for record in role_usage)
        failed_requests = len(role_usage) - successful_requests
        configured = role in configured_roles
        if not configured:
            status = SpecialistExecutionStatus.NOT_CONFIGURED
        elif successful_requests:
            status = SpecialistExecutionStatus.COMPLETED
        elif failed_requests:
            status = SpecialistExecutionStatus.FAILED
        else:
            status = SpecialistExecutionStatus.NOT_SCHEDULED
        records.append(
            SpecialistExecutionRecord(
                role=role,
                role_kind=definition.role_kind,
                responsibility=definition.mission,
                response_schema=definition.response_schema,
                schema_name=definition.effective_schema_name(),
                configured=configured,
                context_limit_bytes=definition.max_context_bytes,
                context_budget_bytes=context.byte_budget if context is not None else None,
                context_bytes_used=context.bytes_used if context is not None else None,
                request_roles=sorted({record.role for record in role_usage}),
                successful_requests=successful_requests,
                failed_requests=failed_requests,
                status=status,
            )
        )
    return records


class SpecialistFindingAgent:
    """Run one blind specialist pass with explicit surface-review evidence."""

    def __init__(
        self,
        config: AuditConfig,
        client: OpenRouterClient,
        role: str,
    ) -> None:
        if role not in SPECIALIST_ROLE_REGISTRY:
            raise KeyError(role)
        if role not in SPECIALIST_INVESTIGATOR_ROLES:
            raise ValueError(f"{role} is not a finding-investigator role")
        self.config = config
        self.client = client
        self.role = role
        self.definition = SPECIALIST_ROLE_REGISTRY[role]

    async def run(self, context: ContextPackage) -> FindingReviewResult:
        configured = self.config.models.role(self.role)
        request_role = f"specialist:{self.role}"
        request_context = context.model_copy(deep=True)
        rendered_user_context = render_context(request_context)
        completion = await self.client.complete_with_evidence(
            role=request_role,
            models=[configured.primary, *configured.fallbacks],
            system_prompt="\n\n".join(
                (
                    load_prompt("shared_security_rules.md"),
                    load_prompt("specialist.md"),
                    "<ROLE_CONTRACT_JSON>",
                    self.definition.prompt_contract(),
                    "</ROLE_CONTRACT_JSON>",
                )
            ),
            user_prompt=rendered_user_context,
            context_package=request_context,
            response_model=CandidateReviewBatch,
            schema_name=self.definition.effective_schema_name(),
        )
        result = completion.value
        usage = completion.usage_record
        try:
            surface_review_artifact = seal_model_surface_review_artifact(
                context=request_context,
                completion=completion,
                rendered_user_context=rendered_user_context,
            )
        except ModelReviewEvidenceError as exc:
            raise OpenRouterSchemaError(
                f"model response did not provide valid requested-surface evidence: {exc}"
            ) from None
        requested = usage.requested_model
        returned = usage.returned_model
        family = model_family(requested)
        scanner_fingerprints = {finding.fingerprint for finding in request_context.scanner_findings}
        stamped = []
        for finding in result.findings:
            stable = hashlib.sha256(
                "\0".join(
                    (
                        request_role,
                        finding.title.casefold(),
                        finding.locations[0].path,
                        str(finding.locations[0].start_line),
                    )
                ).encode()
            ).hexdigest()[:16]
            evidence = [
                (
                    item
                    if item.type == "scanner" and item.fingerprint in scanner_fingerprints
                    else Evidence(
                        type="model",
                        source=request_role,
                        description=item.description,
                    )
                )
                for item in finding.evidence
            ]
            stamped.append(
                finding.model_copy(
                    update={
                        "candidate_id": f"cand-{stable}",
                        "role": request_role,
                        "model_family": family,
                        "evidence": evidence,
                        "model_votes": [
                            ModelVote(
                                role=request_role,
                                requested_model=requested,
                                returned_model=returned,
                                family=family,
                                verdict="proposed",
                                rationale=finding.summary,
                            )
                        ],
                    }
                )
            )
        return FindingReviewResult(
            findings=tuple(stamped),
            surface_review_artifact=surface_review_artifact,
            surface_review_context=request_context,
        )


@dataclass(frozen=True, slots=True)
class PreparedReportQualityInput:
    """Exact bounded workflow material prepared before context allocation."""

    workflow_prompt: str
    workflow_byte_upper_bound_tokens: int
    workflow_sha256: str

    @classmethod
    def build(cls, payload: dict[str, object]) -> PreparedReportQualityInput:
        payload_json = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        workflow_prompt = "\n".join(
            (
                "<REPORT_QUALITY_INPUT_JSON>",
                payload_json,
                "</REPORT_QUALITY_INPUT_JSON>",
                "",
            )
        )
        encoded = workflow_prompt.encode("utf-8")
        return cls(
            workflow_prompt=workflow_prompt,
            workflow_byte_upper_bound_tokens=len(encoded),
            workflow_sha256=hashlib.sha256(encoded).hexdigest(),
        )

    def __post_init__(self) -> None:
        encoded = self.workflow_prompt.encode("utf-8")
        if self.workflow_byte_upper_bound_tokens != len(encoded):
            raise ValueError("prepared report-quality workflow byte bound is inconsistent")
        if self.workflow_sha256 != hashlib.sha256(encoded).hexdigest():
            raise ValueError("prepared report-quality workflow hash is inconsistent")


class ReportQualityAgent:
    """Review report calibration without receiving authority over findings."""

    def __init__(self, config: AuditConfig, client: OpenRouterClient) -> None:
        self.config = config
        self.client = client

    @staticmethod
    def prepare_input(
        *,
        findings: list[Finding],
        rejected_count: int,
        coverage: SolidityCoverage | None,
        quality_gates: list[QualityGateResult],
        incomplete_reasons: list[str],
    ) -> PreparedReportQualityInput:
        """Prepare the exact non-context workflow before endpoint budgeting."""

        payload = {
            "findings": [finding.model_dump(mode="json") for finding in findings],
            "rejected_finding_count": rejected_count,
            "coverage": coverage.model_dump(mode="json") if coverage else None,
            "quality_gates": [gate.model_dump(mode="json") for gate in quality_gates],
            "incomplete_reasons": incomplete_reasons,
            "required_sections": [
                "scope_and_exclusions",
                "profile_and_downgrade",
                "tool_and_model_manifest",
                "semantic_graph_coverage",
                "invariant_and_reproduction_coverage",
                "findings_and_dissent",
                "unreviewed_areas",
                "clean_report_limitation",
            ],
        }
        return PreparedReportQualityInput.build(payload)

    async def run(
        self,
        *,
        findings: list[Finding],
        rejected_count: int,
        coverage: SolidityCoverage | None,
        quality_gates: list[QualityGateResult],
        incomplete_reasons: list[str],
        context: ContextPackage,
        prepared_input: PreparedReportQualityInput | None = None,
    ) -> ReportQualityReview:
        configured = self.config.models.role("report_quality")
        definition = SPECIALIST_ROLE_REGISTRY["report_quality"]
        expected_input = self.prepare_input(
            findings=findings,
            rejected_count=rejected_count,
            coverage=coverage,
            quality_gates=quality_gates,
            incomplete_reasons=incomplete_reasons,
        )
        if prepared_input is not None and prepared_input != expected_input:
            raise OpenRouterSchemaError(
                "prepared report-quality workflow differs from the reviewed evidence"
            )
        effective_input = prepared_input or expected_input
        return await self.client.complete(
            role="specialist:report_quality",
            models=[configured.primary, *configured.fallbacks],
            system_prompt="\n\n".join(
                (
                    load_prompt("shared_security_rules.md"),
                    load_prompt("report_quality.md"),
                    "<ROLE_CONTRACT_JSON>",
                    definition.prompt_contract(),
                    "</ROLE_CONTRACT_JSON>",
                )
            ),
            user_prompt=effective_input.workflow_prompt + render_context(context),
            context_package=context,
            response_model=ReportQualityReview,
            schema_name=definition.effective_schema_name(),
        )
