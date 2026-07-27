from __future__ import annotations

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    AnalysisState,
    ForkActor,
    ForkArgumentKind,
    FoundryInvariantHarnessSpec,
    HarnessArgument,
    HarnessArgumentSource,
    InvariantCategory,
    InvariantProbe,
    InvariantPropertySpec,
    InvariantRelation,
    InvariantSpec,
    InvariantSuite,
    InvariantTemplate,
    PropertyCorpus,
    SolidityEntity,
    SolidityEntityKind,
    SolidityProvenance,
    SoliditySymbolIndex,
    StatefulActionSpec,
)
from mmaudit.solidity.properties import build_property_corpus


def _entity(
    *,
    entity_id: str,
    kind: SolidityEntityKind,
    name: str,
    line: int,
    provenance: SolidityProvenance,
    confidence: float,
) -> SolidityEntity:
    return SolidityEntity(
        id=entity_id,
        kind=kind,
        name=name,
        contract_name="Vault",
        path="src/Vault.sol",
        start_line=line,
        end_line=line,
        byte_start=line * 10,
        byte_end=line * 10 + 9,
        source_hash=f"{line:064x}",
        provenance=provenance,
        confidence=confidence,
        transformation=(
            "compiler_ast_entity"
            if provenance is SolidityProvenance.COMPILER
            else "source_fallback"
        ),
        visibility="external" if kind is SolidityEntityKind.FUNCTION else None,
    )


def _inputs() -> tuple[InvariantSuite, SoliditySymbolIndex, FoundryInvariantHarnessSpec]:
    function = _entity(
        entity_id="function:Vault:deposit",
        kind=SolidityEntityKind.FUNCTION,
        name="deposit",
        line=10,
        provenance=SolidityProvenance.COMPILER,
        confidence=1,
    )
    state = _entity(
        entity_id="state:Vault:accountedAssets",
        kind=SolidityEntityKind.STATE_VARIABLE,
        name="accountedAssets",
        line=4,
        provenance=SolidityProvenance.FALLBACK,
        confidence=0.7,
    )
    invariant = InvariantSpec(
        id="inv-accounting",
        title="Observed assets cover internal accounting",
        category=InvariantCategory.ACCOUNTING,
        description="Observed asset balances must cover the tracked accounting total.",
        template=InvariantTemplate.OBSERVED_ASSET_ACCOUNTING,
        locations=[
            {
                "path": function.path,
                "start_line": function.start_line,
                "end_line": function.end_line,
                "symbol": function.name,
                "content_hash": function.source_hash,
            },
            {
                "path": state.path,
                "start_line": state.start_line,
                "end_line": state.end_line,
                "symbol": state.name,
                "content_hash": state.source_hash,
            },
        ],
        entity_ids=[function.id, state.id],
        state_variables=[state.name],
        functions=[function.name],
        protocol_profiles=["vault"],
        assumptions=["Asset target uses the synthetic local fixture"],
        provenance=SolidityProvenance.HEURISTIC,
        confidence=0.85,
        template_available=True,
        executable=True,
        analysis_state=AnalysisState.DETERMINISTIC,
        evidence_hash="c" * 64,
    )
    harness = FoundryInvariantHarnessSpec(
        invariant_id=invariant.id,
        name="ObservedAssetAccounting",
        actors=[
            ForkActor(
                name="alice",
                address="0x1000000000000000000000000000000000000001",
                initial_native_balance_wei=10**18,
            ),
            ForkActor(
                name="bob",
                address="0x1000000000000000000000000000000000000002",
                initial_native_balance_wei=2 * 10**18,
            ),
        ],
        actions=[
            StatefulActionSpec(
                action_id="Deposit",
                target="Vault",
                function_signature="deposit(uint256,address)",
                actor_names=["alice", "bob"],
                arguments=[
                    HarnessArgument(
                        kind=ForkArgumentKind.UINT256,
                        source=HarnessArgumentSource.FUZZ_UINT,
                        minimum=1,
                        maximum=10**18,
                        fuzz_slot=0,
                    ),
                    HarnessArgument(
                        kind=ForkArgumentKind.ADDRESS,
                        source=HarnessArgumentSource.ACTOR,
                        fuzz_slot=1,
                    ),
                ],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="ObservedAssetsCoverAccounting",
                left=InvariantProbe(
                    target="Vault",
                    function_signature="totalAssets()",
                ),
                relation=InvariantRelation.GTE,
                expected_uint=0,
            )
        ],
        runs=32,
        depth=8,
        seed=7,
        assumptions=["Campaign starts from a clean synthetic deployment"],
    )
    return (
        InvariantSuite(
            invariants=[invariant],
            protocol_profiles=["vault"],
            templates_available_count=1,
            executable_count=1,
        ),
        SoliditySymbolIndex(
            projects=[],
            entities=[function, state],
            ast_sources=["src/Vault.sol"],
            fallback_sources=["src/Vault.sol"],
        ),
        harness,
    )


def test_property_corpus_retains_evidence_assumptions_coverage_seed_and_bounds() -> None:
    suite, index, harness = _inputs()

    first = build_property_corpus(suite, index, [harness])
    second = build_property_corpus(suite, index, [harness])

    assert first.model_dump_json() == second.model_dump_json()
    assert PropertyCorpus.model_validate_json(first.model_dump_json()) == first
    assert len(first.properties) == 1
    property_spec = first.properties[0]
    assert property_spec.id == f"prop-{property_spec.property_hash[:24]}"
    assert property_spec.invariant_evidence_hash == "c" * 64
    assert [item.entity_id for item in property_spec.source_evidence] == sorted(
        suite.invariants[0].entity_ids
    )
    assert {item.provenance for item in property_spec.source_evidence} == {
        SolidityProvenance.COMPILER,
        SolidityProvenance.FALLBACK,
    }
    assert property_spec.confidence == 0.7
    assert property_spec.covered_state_variables == ["accountedAssets"]
    assert {
        "deposit",
        "deposit(uint256,address)",
        "totalAssets()",
    } <= set(property_spec.covered_functions)
    assert property_spec.assumptions == sorted(
        {
            *suite.invariants[0].assumptions,
            *harness.assumptions,
        }
    )
    assert property_spec.campaign.seed == 7
    assert property_spec.campaign.runs == 32
    assert property_spec.campaign.depth == 8
    assert [
        (bound.slot, bound.kind, bound.minimum, bound.maximum)
        for bound in property_spec.campaign.fuzz_inputs
    ] == [
        (0, ForkArgumentKind.UINT256, 1, 10**18),
        (1, ForkArgumentKind.ADDRESS, None, None),
    ]
    assert property_spec.campaign.maximum_actor_initial_balance_wei == 2 * 10**18
    assert not first.limitations


def test_property_corpus_omits_unresolved_source_evidence() -> None:
    suite, index, harness = _inputs()
    incomplete_index = index.model_copy(update={"entities": index.entities[:1]})

    corpus = build_property_corpus(suite, incomplete_index, [harness])

    assert corpus.properties == []
    assert corpus.limitations == [
        "inv-accounting/ObservedAssetAccounting: unresolved source entities "
        "state:Vault:accountedAssets"
    ]


def test_property_corpus_omits_source_location_hash_mismatch() -> None:
    suite, index, harness = _inputs()
    invariant = suite.invariants[0]
    mismatched = invariant.model_copy(
        update={
            "locations": [
                invariant.locations[0].model_copy(update={"content_hash": "d" * 64}),
                *invariant.locations[1:],
            ]
        }
    )

    corpus = build_property_corpus(
        suite.model_copy(update={"invariants": [mismatched]}),
        index,
        [harness],
    )

    assert corpus.properties == []
    assert corpus.limitations == [
        "inv-accounting/ObservedAssetAccounting: source location mismatch for "
        "function:Vault:deposit"
    ]


def test_property_corpus_rejects_conflicting_shared_fuzz_slot_bounds() -> None:
    suite, index, harness = _inputs()
    conflicting = harness.model_copy(
        update={
            "actions": [
                *harness.actions,
                StatefulActionSpec(
                    action_id="Withdraw",
                    target="Vault",
                    function_signature="withdraw(uint256)",
                    actor_names=["alice"],
                    arguments=[
                        HarnessArgument(
                            kind=ForkArgumentKind.UINT256,
                            source=HarnessArgumentSource.FUZZ_UINT,
                            minimum=0,
                            maximum=100,
                            fuzz_slot=0,
                        )
                    ],
                ),
            ]
        }
    )

    corpus = build_property_corpus(suite, index, [conflicting])

    assert corpus.properties == []
    assert corpus.limitations == [
        "inv-accounting/ObservedAssetAccounting: fuzz slot 0 has conflicting type or numeric bounds"
    ]


def test_property_corpus_hash_detects_serialized_tampering() -> None:
    suite, index, harness = _inputs()
    payload = build_property_corpus(suite, index, [harness]).model_dump(mode="json")
    properties = payload["properties"]
    assert isinstance(properties, list)
    property_payload = properties[0]
    assert isinstance(property_payload, dict)
    campaign = property_payload["campaign"]
    assert isinstance(campaign, dict)
    campaign["runs"] = 33

    with pytest.raises(
        ValidationError,
        match="property hash does not match",
    ):
        PropertyCorpus.model_validate(payload)
