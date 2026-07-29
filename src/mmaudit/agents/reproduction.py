"""Typed exploit-test planning and independent falsification roles."""

from __future__ import annotations

import json

from mmaudit.agents.base import load_prompt
from mmaudit.agents.specialists import SPECIALIST_ROLE_REGISTRY
from mmaudit.config import AuditConfig, model_family
from mmaudit.models.openrouter import OpenRouterClient, OpenRouterSchemaError
from mmaudit.models.schemas import (
    CandidateFinding,
    ContextPackage,
    FalsificationBatch,
    GeneratedFoundryTestBatch,
    GeneratedFoundryTestSpec,
    ReproductionResult,
)
from mmaudit.orchestration.context import render_context
from mmaudit.solidity.reproduction import capability_policy_error


class ExploitTestPlannerAgent:
    """Ask an originating investigator for declarative tests, never source or commands."""

    def __init__(
        self,
        config: AuditConfig,
        client: OpenRouterClient,
        *,
        investigator_role: str,
        planner_role: str | None = None,
    ) -> None:
        self.config = config
        self.client = client
        self.investigator_role = investigator_role
        self.planner_role = planner_role

    async def run(
        self,
        candidates: list[CandidateFinding],
        context: ContextPackage,
    ) -> GeneratedFoundryTestBatch:
        if not candidates:
            return GeneratedFoundryTestBatch(tests=[])
        configured_role = self.planner_role or (
            "exploit_reproduction_planner"
            if "exploit_reproduction_planner" in self.config.models.specialists
            else self.investigator_role.removeprefix("specialist:")
        )
        definition = SPECIALIST_ROLE_REGISTRY[self.planner_role or "exploit_reproduction_planner"]
        configured = self.config.models.role(configured_role)
        role = f"specialist:{configured_role}:exploit_test"
        payload = {
            "candidates": [candidate.model_dump(mode="json") for candidate in candidates],
            "available_targets": sorted(self.config.reproduction.targets),
            "pinned_block_number": self.config.reproduction.pinned_block_number,
            "expected_chain_id": self.config.reproduction.expected_chain_id,
            "operator_capability_limits": {
                "max_attacker_controlled_actors": (
                    self.config.reproduction.max_attacker_controlled_actors
                ),
                "max_attacker_controlled_contracts": (
                    self.config.reproduction.max_attacker_controlled_contracts
                ),
                "max_starting_native_capital_wei": (
                    self.config.reproduction.max_starting_native_capital_wei
                ),
                "max_flash_liquidity_wei": (self.config.reproduction.max_flash_liquidity_wei),
                "allowed_token_approval_targets": (
                    self.config.reproduction.allowed_token_approval_targets
                ),
                "max_time_shift_seconds": self.config.reproduction.max_time_shift_seconds,
                "max_block_advance": self.config.reproduction.max_block_advance,
                "allowed_transaction_ordering": (
                    self.config.reproduction.allowed_transaction_ordering.value
                ),
                "allowed_oracle_influence": (
                    self.config.reproduction.allowed_oracle_influence.value
                ),
                "allow_governance_rights": (self.config.reproduction.allow_governance_rights),
                "allowed_privileged_roles": (self.config.reproduction.allowed_privileged_roles),
                "allowed_cross_chain_messages": (
                    self.config.reproduction.allowed_cross_chain_messages.value
                ),
                "max_attack_transactions": (self.config.reproduction.max_attack_transactions),
            },
            "limits": {
                "max_tests_per_candidate": self.config.reproduction.max_tests_per_candidate,
                "max_setup_calls_per_test": 40,
                "max_attack_calls_per_test": 40,
                "max_assertions_per_test": 40,
            },
        }
        response = await self.client.complete(
            role=role,
            models=[configured.primary, *configured.fallbacks],
            system_prompt="\n\n".join(
                (
                    load_prompt("shared_security_rules.md"),
                    load_prompt("exploit_test.md"),
                    "<ROLE_CONTRACT_JSON>",
                    definition.prompt_contract(),
                    "</ROLE_CONTRACT_JSON>",
                )
            ),
            user_prompt="\n".join(
                (
                    "<REPRODUCTION_INPUT_JSON>",
                    json.dumps(payload, sort_keys=True),
                    "</REPRODUCTION_INPUT_JSON>",
                    render_context(context),
                )
            ),
            context_package=context,
            response_model=GeneratedFoundryTestBatch,
            schema_name=definition.effective_schema_name(),
        )
        submitted = {candidate.candidate_id for candidate in candidates}
        counts: dict[str, int] = {}
        stamped: list[GeneratedFoundryTestSpec] = []
        for test in response.tests:
            if test.candidate_id not in submitted:
                raise OpenRouterSchemaError(
                    "exploit-test planner returned an unknown candidate identifier"
                )
            counts[test.candidate_id] = counts.get(test.candidate_id, 0) + 1
            if counts[test.candidate_id] > self.config.reproduction.max_tests_per_candidate:
                raise OpenRouterSchemaError("exploit-test planner exceeded the per-candidate limit")
            policy_error = capability_policy_error(test, self.config.reproduction)
            if policy_error is not None:
                raise OpenRouterSchemaError(
                    f"exploit-test capability policy rejected: {policy_error}"
                )
            stamped.append(
                test.model_copy(
                    update={
                        "generator_role": configured_role,
                        "generator_model_family": model_family(configured.primary),
                    }
                )
            )
        return GeneratedFoundryTestBatch(tests=stamped)


class FalsifierAgent:
    """Challenge whether a generated test actually exercises its submitted claim."""

    def __init__(self, config: AuditConfig, client: OpenRouterClient) -> None:
        self.config = config
        self.client = client

    async def run(
        self,
        *,
        candidates: list[CandidateFinding],
        tests: list[GeneratedFoundryTestSpec],
        results: list[ReproductionResult],
        context: ContextPackage,
    ) -> FalsificationBatch:
        configured_role = (
            "falsifier" if "falsifier" in self.config.models.specialists else "verifier"
        )
        definition = SPECIALIST_ROLE_REGISTRY["falsifier"]
        verifier = self.config.models.role(configured_role)
        payload = {
            "candidates": [candidate.model_dump(mode="json") for candidate in candidates],
            "test_specifications": [test.model_dump(mode="json") for test in tests],
            "execution_results": [result.model_dump(mode="json") for result in results],
        }
        response = await self.client.complete(
            role=("specialist:falsifier" if configured_role == "falsifier" else "falsifier"),
            models=[verifier.primary, *verifier.fallbacks],
            system_prompt="\n\n".join(
                (
                    load_prompt("shared_security_rules.md"),
                    load_prompt("falsifier.md"),
                    "<ROLE_CONTRACT_JSON>",
                    definition.prompt_contract(),
                    "</ROLE_CONTRACT_JSON>",
                )
            ),
            user_prompt="\n".join(
                (
                    "<FALSIFICATION_INPUT_JSON>",
                    json.dumps(payload, sort_keys=True),
                    "</FALSIFICATION_INPUT_JSON>",
                    render_context(context),
                )
            ),
            context_package=context,
            response_model=FalsificationBatch,
            schema_name=definition.effective_schema_name(),
        )
        expected = {(test.candidate_id, test.name) for test in tests}
        returned = [(decision.candidate_id, decision.test_name) for decision in response.decisions]
        if (
            set(returned) - expected
            or len(returned) != len(set(returned))
            or set(returned) != expected
        ):
            raise OpenRouterSchemaError(
                "falsifier returned an incomplete, duplicate, or unknown test decision set"
            )
        return response
