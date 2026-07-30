"""Typed exploit-test planning and independent falsification roles."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass

from mmaudit.agents.base import ValidatedAgentResult, load_prompt
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


def _prepared_workflow(
    payload: Mapping[str, object],
    *,
    opening_tag: str,
    closing_tag: str,
) -> tuple[str, int, str]:
    payload_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    workflow_prompt = "\n".join((opening_tag, payload_json, closing_tag, ""))
    encoded = workflow_prompt.encode("utf-8")
    return workflow_prompt, len(encoded), hashlib.sha256(encoded).hexdigest()


def _validate_prepared_workflow(
    *,
    workflow_prompt: str,
    workflow_byte_upper_bound_tokens: int,
    workflow_sha256: str,
    label: str,
) -> None:
    encoded = workflow_prompt.encode("utf-8")
    if workflow_byte_upper_bound_tokens != len(encoded):
        raise ValueError(f"prepared {label} workflow byte bound is inconsistent")
    if workflow_sha256 != hashlib.sha256(encoded).hexdigest():
        raise ValueError(f"prepared {label} workflow hash is inconsistent")


@dataclass(frozen=True, slots=True)
class PreparedExploitTestInput:
    """Exact exploit-planning workflow material prepared before context allocation."""

    workflow_prompt: str
    workflow_byte_upper_bound_tokens: int
    workflow_sha256: str

    @classmethod
    def build(cls, payload: Mapping[str, object]) -> PreparedExploitTestInput:
        workflow_prompt, byte_bound, workflow_sha256 = _prepared_workflow(
            payload,
            opening_tag="<REPRODUCTION_INPUT_JSON>",
            closing_tag="</REPRODUCTION_INPUT_JSON>",
        )
        return cls(
            workflow_prompt=workflow_prompt,
            workflow_byte_upper_bound_tokens=byte_bound,
            workflow_sha256=workflow_sha256,
        )

    def __post_init__(self) -> None:
        _validate_prepared_workflow(
            workflow_prompt=self.workflow_prompt,
            workflow_byte_upper_bound_tokens=self.workflow_byte_upper_bound_tokens,
            workflow_sha256=self.workflow_sha256,
            label="exploit-test",
        )


@dataclass(frozen=True, slots=True)
class PreparedFalsificationInput:
    """Exact falsification workflow material prepared before context allocation."""

    workflow_prompt: str
    workflow_byte_upper_bound_tokens: int
    workflow_sha256: str

    @classmethod
    def build(cls, payload: Mapping[str, object]) -> PreparedFalsificationInput:
        workflow_prompt, byte_bound, workflow_sha256 = _prepared_workflow(
            payload,
            opening_tag="<FALSIFICATION_INPUT_JSON>",
            closing_tag="</FALSIFICATION_INPUT_JSON>",
        )
        return cls(
            workflow_prompt=workflow_prompt,
            workflow_byte_upper_bound_tokens=byte_bound,
            workflow_sha256=workflow_sha256,
        )

    def __post_init__(self) -> None:
        _validate_prepared_workflow(
            workflow_prompt=self.workflow_prompt,
            workflow_byte_upper_bound_tokens=self.workflow_byte_upper_bound_tokens,
            workflow_sha256=self.workflow_sha256,
            label="falsification",
        )


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

    def prepare_input(
        self,
        candidates: list[CandidateFinding],
    ) -> PreparedExploitTestInput:
        """Prepare the exact non-context exploit-planning workflow."""

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
        return PreparedExploitTestInput.build(payload)

    async def run(
        self,
        candidates: list[CandidateFinding],
        context: ContextPackage,
        *,
        prepared_input: PreparedExploitTestInput | None = None,
    ) -> GeneratedFoundryTestBatch:
        result = await self.run_with_evidence(
            candidates,
            context,
            prepared_input=prepared_input,
        )
        return result.value if result is not None else GeneratedFoundryTestBatch(tests=[])

    async def run_with_evidence(
        self,
        candidates: list[CandidateFinding],
        context: ContextPackage,
        *,
        prepared_input: PreparedExploitTestInput | None = None,
    ) -> ValidatedAgentResult[GeneratedFoundryTestBatch] | None:
        expected_input = self.prepare_input(candidates)
        if prepared_input is not None and prepared_input != expected_input:
            raise OpenRouterSchemaError(
                "prepared exploit-test workflow differs from submitted planning evidence"
            )
        if not candidates:
            return None
        effective_input = prepared_input or expected_input
        configured_role = self.planner_role or (
            "exploit_reproduction_planner"
            if "exploit_reproduction_planner" in self.config.models.specialists
            else self.investigator_role.removeprefix("specialist:")
        )
        definition = SPECIALIST_ROLE_REGISTRY[self.planner_role or "exploit_reproduction_planner"]
        configured = self.config.models.role(configured_role)
        role = f"specialist:{configured_role}:exploit_test"
        completion = await self.client.complete_with_evidence(
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
            user_prompt=effective_input.workflow_prompt + render_context(context),
            context_package=context,
            response_model=GeneratedFoundryTestBatch,
            schema_name=definition.effective_schema_name(),
        )
        response = completion.value
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
        return ValidatedAgentResult(
            value=GeneratedFoundryTestBatch(tests=stamped),
            completion_usage=completion.usage_record,
        )


class FalsifierAgent:
    """Challenge whether a generated test actually exercises its submitted claim."""

    def __init__(self, config: AuditConfig, client: OpenRouterClient) -> None:
        self.config = config
        self.client = client

    @staticmethod
    def prepare_input(
        *,
        candidates: list[CandidateFinding],
        tests: list[GeneratedFoundryTestSpec],
        results: list[ReproductionResult],
    ) -> PreparedFalsificationInput:
        """Prepare the exact non-context falsification workflow."""

        payload = {
            "candidates": [candidate.model_dump(mode="json") for candidate in candidates],
            "test_specifications": [test.model_dump(mode="json") for test in tests],
            "execution_results": [result.model_dump(mode="json") for result in results],
        }
        return PreparedFalsificationInput.build(payload)

    async def run(
        self,
        *,
        candidates: list[CandidateFinding],
        tests: list[GeneratedFoundryTestSpec],
        results: list[ReproductionResult],
        context: ContextPackage,
        prepared_input: PreparedFalsificationInput | None = None,
    ) -> FalsificationBatch:
        return (
            await self.run_with_evidence(
                candidates=candidates,
                tests=tests,
                results=results,
                context=context,
                prepared_input=prepared_input,
            )
        ).value

    async def run_with_evidence(
        self,
        *,
        candidates: list[CandidateFinding],
        tests: list[GeneratedFoundryTestSpec],
        results: list[ReproductionResult],
        context: ContextPackage,
        prepared_input: PreparedFalsificationInput | None = None,
    ) -> ValidatedAgentResult[FalsificationBatch]:
        expected_input = self.prepare_input(
            candidates=candidates,
            tests=tests,
            results=results,
        )
        if prepared_input is not None and prepared_input != expected_input:
            raise OpenRouterSchemaError(
                "prepared falsification workflow differs from submitted evidence"
            )
        effective_input = prepared_input or expected_input
        configured_role = (
            "falsifier" if "falsifier" in self.config.models.specialists else "verifier"
        )
        definition = SPECIALIST_ROLE_REGISTRY["falsifier"]
        verifier = self.config.models.role(configured_role)
        completion = await self.client.complete_with_evidence(
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
            user_prompt=effective_input.workflow_prompt + render_context(context),
            context_package=context,
            response_model=FalsificationBatch,
            schema_name=definition.effective_schema_name(),
        )
        response = completion.value
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
        return ValidatedAgentResult(
            value=response,
            completion_usage=completion.usage_record,
        )
