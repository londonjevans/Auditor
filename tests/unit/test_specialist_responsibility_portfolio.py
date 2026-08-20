from __future__ import annotations

from mmaudit.agents.specialists import SPECIALIST_ROLE_REGISTRY
from mmaudit.constants import (
    ALL_SPECIALIST_ROLES,
    CANDIDATE_DEPENDENT_SPECIALIST_ROLES,
    CANDIDATE_INDEPENDENT_SPECIALIST_ROLES,
    SPECIALIST_AUXILIARY_ROLES,
    SPECIALIST_INVESTIGATOR_ROLES,
)
from mmaudit.models.schemas import (
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphKind,
    SolidityProvenance,
)
from mmaudit.orchestration.context import _role_weights
from mmaudit.solidity.retrieval import _edge_rank, _entity_rank


def _entity(*, entity_id: str, name: str) -> SolidityEntity:
    return SolidityEntity(
        id=entity_id,
        kind=SolidityEntityKind.FUNCTION,
        name=name,
        contract_name="SyntheticPortfolio",
        path="src/SyntheticPortfolio.sol",
        start_line=1,
        end_line=1,
        byte_start=0,
        byte_end=1,
        source_hash="a" * 64,
        provenance=SolidityProvenance.COMPILER,
        confidence=1.0,
        transformation="synthetic portfolio regression",
        visibility="external",
    )


def _edge(*, graph: SolidityGraphKind) -> SolidityGraphEdge:
    return SolidityGraphEdge(
        graph=graph,
        source_id="entity:source",
        target_id="entity:target",
        label=graph.value,
        provenance=SolidityProvenance.COMPILER,
        path="src/SyntheticPortfolio.sol",
        start_line=1,
        end_line=1,
        source_hash="a" * 64,
        confidence=1.0,
        transformation="synthetic portfolio regression",
    )


def test_candidate_independent_specialist_portfolio_is_exact_and_disjoint() -> None:
    assert len(SPECIALIST_INVESTIGATOR_ROLES) == 22
    assert (
        *SPECIALIST_INVESTIGATOR_ROLES,
        "invariant_review",
        "report_quality",
    ) == CANDIDATE_INDEPENDENT_SPECIALIST_ROLES
    assert len(CANDIDATE_INDEPENDENT_SPECIALIST_ROLES) == 24
    assert len(set(CANDIDATE_INDEPENDENT_SPECIALIST_ROLES)) == 24
    assert CANDIDATE_DEPENDENT_SPECIALIST_ROLES == (
        "test_generation",
        "exploit_reproduction_planner",
        "falsifier",
    )
    assert not set(CANDIDATE_INDEPENDENT_SPECIALIST_ROLES) & set(
        CANDIDATE_DEPENDENT_SPECIALIST_ROLES
    )
    assert (
        "invariant_review",
        *CANDIDATE_DEPENDENT_SPECIALIST_ROLES,
        "report_quality",
    ) == SPECIALIST_AUXILIARY_ROLES
    assert set(CANDIDATE_INDEPENDENT_SPECIALIST_ROLES) | set(
        CANDIDATE_DEPENDENT_SPECIALIST_ROLES
    ) == set(ALL_SPECIALIST_ROLES)


def test_state_machine_lifecycle_contract_is_frozen() -> None:
    definition = SPECIALIST_ROLE_REGISTRY["state_machine_lifecycle"]

    assert definition.role_kind == "investigator"
    assert definition.mission == (
        "Find illegal, skipped, repeated, or permanently stuck lifecycle transitions across "
        "initialization, operation, pause, settlement, migration, and termination."
    )
    assert definition.required_checks == (
        "Enumerate valid states and every entry point that changes them.",
        "Check transition guards, one-way/terminal states, repeated and out-of-order calls.",
        (
            "Trace callback, timing, and partial-failure paths that can desynchronize lifecycle "
            "state across contracts."
        ),
    )
    assert definition.context_priorities == (
        "state-machine and state-dependency graphs",
        "public entry points and modifiers",
        "events and terminal states",
        "cross-contract boundaries",
    )


def test_randomness_entropy_commit_reveal_contract_is_frozen() -> None:
    definition = SPECIALIST_ROLE_REGISTRY["randomness_entropy_commit_reveal"]

    assert definition.role_kind == "investigator"
    assert definition.mission == (
        "Find predictable, biasable, replayable, or prematurely revealed randomness and "
        "commit-reveal defects."
    )
    assert definition.required_checks == (
        (
            "Trace every entropy input and actor/block-builder influence to value-sensitive "
            "selection or output."
        ),
        (
            "Check commitment binding, reveal timing, non-reveal/forfeiture behavior, and "
            "replay/domain separation."
        ),
        (
            "Distinguish authenticated VRF/oracle guarantees from block-variable "
            "pseudo-randomness and unsupported trust assumptions."
        ),
    )
    assert definition.context_priorities == (
        "entropy and randomness dependencies",
        "commit/reveal state",
        "block and timing inputs",
        "value allocation and winner selection",
    )


def test_new_roles_have_distinct_context_weights_and_retrieval_priorities() -> None:
    assert _role_weights("specialist:state_machine_lifecycle") == {
        "evm_storage": 12,
        "business_logic": 11,
        "evm_auth": 9,
        "evm_external_call": 8,
        "smart_contract": 8,
    }
    assert _role_weights("specialist:randomness_entropy_commit_reveal") == {
        "smart_contract": 11,
        "business_logic": 10,
        "evm_value": 10,
        "evm_oracle": 8,
        "evm_signature": 7,
    }

    neutral_entity = _entity(entity_id="entity:neutral", name="process")
    lifecycle_entity = _entity(entity_id="entity:lifecycle", name="finalizeMigration")
    randomness_entity = _entity(entity_id="entity:randomness", name="revealWinner")
    assert _entity_rank(lifecycle_entity, "specialist:state_machine_lifecycle") < _entity_rank(
        neutral_entity,
        "specialist:state_machine_lifecycle",
    )
    assert _entity_rank(
        randomness_entity,
        "specialist:randomness_entropy_commit_reveal",
    ) < _entity_rank(
        neutral_entity,
        "specialist:randomness_entropy_commit_reveal",
    )

    neutral_edge = _edge(graph=SolidityGraphKind.INHERITANCE)
    assert _edge_rank(
        _edge(graph=SolidityGraphKind.STATE_DEPENDENCY),
        "specialist:state_machine_lifecycle",
    ) < _edge_rank(neutral_edge, "specialist:state_machine_lifecycle")
    assert _edge_rank(
        _edge(graph=SolidityGraphKind.ORACLE_DEPENDENCY),
        "specialist:randomness_entropy_commit_reveal",
    ) < _edge_rank(neutral_edge, "specialist:randomness_entropy_commit_reveal")
