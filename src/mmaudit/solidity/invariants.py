"""Source-linked deterministic invariant discovery for Solidity projects."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable

from mmaudit.config import InvariantConfig
from mmaudit.models.schemas import (
    AnalysisState,
    InvariantCategory,
    InvariantSpec,
    InvariantSuite,
    InvariantTemplate,
    Location,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphKind,
    SolidityGraphSet,
    SolidityProvenance,
    SoliditySymbolIndex,
)
from mmaudit.repository.discovery import DiscoveryResult


def discover_invariants(
    discovery: DiscoveryResult,
    index: SoliditySymbolIndex | None,
    graphs: SolidityGraphSet | None,
    config: InvariantConfig,
) -> InvariantSuite:
    """Infer bounded, reviewable invariants without claiming protocol intent."""

    if not config.enabled or index is None:
        return InvariantSuite(
            warnings=["invariant discovery disabled or Solidity index unavailable"]
        )
    files = {
        item.relative_path: item.content for item in discovery.files if item.language == "Solidity"
    }
    profiles = _protocol_profiles(index.entities, graphs, files)
    proposed: list[InvariantSpec] = []
    proposed.extend(_accounting_invariants(index.entities, graphs, profiles, files))
    proposed.extend(_authorization_invariants(index.entities, graphs, files))
    proposed.extend(_token_invariants(index.entities, graphs, profiles, files))
    proposed.extend(_state_machine_invariants(index.entities, graphs, files))
    proposed.extend(_economic_invariants(index.entities, graphs, profiles, files))
    unique: dict[str, InvariantSpec] = {}
    for invariant in proposed:
        if invariant.confidence < config.minimum_confidence:
            continue
        previous = unique.get(invariant.id)
        if previous is None or invariant.confidence > previous.confidence:
            unique[invariant.id] = invariant
    invariants = sorted(
        unique.values(),
        key=lambda item: (-item.confidence, item.category.value, item.id),
    )[: config.max_invariants]
    return InvariantSuite(
        invariants=invariants,
        protocol_profiles=sorted(profiles),
        warnings=_invariant_warnings(index, profiles),
        templates_available_count=sum(item.template_available for item in invariants),
        executable_count=sum(item.executable for item in invariants),
    )


def _accounting_invariants(
    entities: list[SolidityEntity],
    graphs: SolidityGraphSet | None,
    profiles: set[str],
    files: dict[str, str],
) -> list[InvariantSpec]:
    invariants: list[InvariantSpec] = []
    names = _by_normalized_name(entities)
    if "erc4626_vault" in profiles:
        for contract_name, evidence in _erc4626_accounting_evidence(entities):
            invariants.append(
                _make_invariant(
                    f"{contract_name} share/asset conversion remains internally consistent",
                    InvariantCategory.ACCOUNTING,
                    (
                        "Deposits, withdrawals, and conversions should not create unbacked shares "
                        "or make aggregate redeemable claims exceed available assets."
                    ),
                    InvariantTemplate.ERC4626_CONVERSION_SANITY,
                    evidence,
                    profiles,
                    assumptions=[
                        "The detected ERC4626-like functions implement the protocol's share ledger",
                        "External strategy assets are included by totalAssets when present",
                    ],
                    confidence=0.78,
                    executable=True,
                )
            )
    if "erc20_token" in profiles:
        entity = _first_named(names, "totalsupply", "balanceof", "mint")
        if entity:
            invariants.append(
                _make_invariant(
                    "Token supply changes correspond to balance changes",
                    InvariantCategory.ACCOUNTING,
                    "Mint and burn transitions should preserve total-supply and account-balance consistency.",
                    InvariantTemplate.ERC20_SUPPLY_BALANCE,
                    [entity],
                    profiles,
                    assumptions=[
                        "No intentionally elastic or rebasing supply semantics are documented"
                    ],
                    confidence=0.75,
                    executable=True,
                )
            )
    asset_flow_sources = {
        edge.source_id
        for edge in (graphs.edges if graphs else [])
        if edge.graph is SolidityGraphKind.ASSET_FLOW
        and edge.metadata.get("classification") != "function_name"
    }
    for deposit in _entities_named_like(
        entities,
        ("deposit", "stake", "supply", "contribute"),
    ):
        if deposit.kind is not SolidityEntityKind.FUNCTION:
            continue
        source = _entity_source(files.get(deposit.path, ""), deposit)
        if not _has_unchecked_erc20_return(source):
            continue
        claim = _accounting_claim_entity(entities, deposit.contract_name)
        if claim is None:
            continue
        invariants.append(
            _make_invariant(
                "Token return outcomes cannot create unbacked internal claims",
                InvariantCategory.TOKEN_STANDARD,
                (
                    "A deposit must validate ERC20 call success and any returned value before "
                    "recording a claim, while explicitly handling compatible empty return data."
                ),
                InvariantTemplate.ERC20_RETURN_HANDLING,
                [deposit, claim],
                profiles,
                assumptions=[
                    "The detected claim variable represents an asset-denominated user claim",
                    "The low-level transferFrom call is intended to move the configured asset",
                    "Empty return data is compatible only when the observed asset balance increases",
                ],
                confidence=0.82,
                executable=True,
            )
        )
    for deposit in _entities_named_like(
        entities,
        ("deposit", "stake", "supply", "contribute"),
    ):
        if deposit.kind is not SolidityEntityKind.FUNCTION:
            continue
        source = _entity_source(files.get(deposit.path, ""), deposit).lower()
        if deposit.id not in asset_flow_sources and "transferfrom" not in source:
            continue
        claim = _accounting_claim_entity(entities, deposit.contract_name)
        if claim is None:
            continue
        invariants.append(
            _make_invariant(
                "Internal claims do not exceed assets actually received",
                InvariantCategory.ACCOUNTING,
                (
                    "Asset-moving deposits must credit observed balance changes rather than a "
                    "nominal transfer amount, including fee-on-transfer or elastic balances."
                ),
                InvariantTemplate.OBSERVED_ASSET_ACCOUNTING,
                [deposit, claim],
                profiles,
                assumptions=[
                    "The detected claim variable represents an asset-denominated user claim",
                    "The configured asset alias identifies the transferred token",
                ],
                confidence=0.78 if deposit.id in asset_flow_sources else 0.68,
                executable=True,
            )
        )
        break
    reward_entity = next(
        (
            entity
            for entity in entities
            if entity.kind
            in {
                SolidityEntityKind.STATE_VARIABLE,
                SolidityEntityKind.FUNCTION,
            }
            and any(
                token in entity.name.lower()
                for token in ("rewardindex", "accpershare", "rewardpershare")
            )
        ),
        None,
    )
    if reward_entity:
        reward_transitions = [
            entity
            for entity in entities
            if entity.contract_name == reward_entity.contract_name
            and entity.kind is SolidityEntityKind.FUNCTION
            and entity.mutability not in {"view", "pure"}
            and any(
                token in entity.name.lower()
                for token in ("reward", "accrue", "update", "resetindex")
            )
        ]
        invariants.append(
            _make_invariant(
                "Reward accumulator does not decrease unexpectedly",
                InvariantCategory.ACCOUNTING,
                "A cumulative reward index should be monotonic except at a documented epoch reset.",
                InvariantTemplate.REWARD_INDEX_MONOTONIC,
                [reward_entity, *reward_transitions[:3]],
                profiles,
                assumptions=["The indexed variable is cumulative rather than per-epoch"],
                confidence=0.7,
                executable=True,
            )
        )
    claim = next(
        (
            entity
            for entity in entities
            if entity.kind is SolidityEntityKind.FUNCTION
            and entity.mutability not in {"view", "pure"}
            and any(token in entity.name.lower() for token in ("claim", "redeemreward", "harvest"))
        ),
        None,
    )
    if claim:
        claim_state = [
            entity
            for entity in entities
            if entity.contract_name == claim.contract_name
            and entity.kind is SolidityEntityKind.STATE_VARIABLE
            and any(
                token in entity.name.lower()
                for token in ("entitlement", "claimable", "claimed", "rewardspaid", "claimspaid")
            )
        ]
        invariants.append(
            _make_invariant(
                "A single entitlement cannot be claimed twice",
                InvariantCategory.ACCOUNTING,
                "Repeating an identical claim transition must not increase the claimant's entitlement twice.",
                InvariantTemplate.CLAIM_ONCE,
                [claim, *claim_state[:3]],
                profiles,
                assumptions=["The operation consumes a finite entitlement"],
                confidence=0.62,
                executable=True,
            )
        )
    lending = [
        entity
        for entity in _entities_named_like(
            entities,
            ("borrow", "repay", "liquidat", "collateral", "debt"),
        )
        if not entity.path.startswith(("test/", "tests/"))
    ]
    lending_contracts = sorted(
        {
            entity.contract_name
            for entity in lending
            if entity.contract_name is not None
            and entity.kind is SolidityEntityKind.FUNCTION
            and "liquidat" in entity.name.casefold()
        }
    )
    for contract_name in lending_contracts:
        contract_lending = [entity for entity in lending if entity.contract_name == contract_name]
        debt = next(
            (entity for entity in contract_lending if "debt" in entity.name.casefold()),
            None,
        )
        collateral = next(
            (entity for entity in contract_lending if "collateral" in entity.name.casefold()),
            None,
        )
        liquidation = next(
            (
                entity
                for entity in contract_lending
                if entity.kind is SolidityEntityKind.FUNCTION
                and "liquidat" in entity.name.casefold()
            ),
            None,
        )
        if debt is None or collateral is None or liquidation is None:
            continue
        evidence = [
            liquidation,
            debt,
            collateral,
            *(
                entity
                for entity in contract_lending
                if entity.id not in {liquidation.id, debt.id, collateral.id}
            ),
        ][:12]
        invariants.append(
            _make_invariant(
                f"{contract_name} debt and collateral remain mutually consistent",
                InvariantCategory.ACCOUNTING,
                (
                    "Liquidation transitions must reject healthy positions and preserve "
                    "debt totals, collateral bounds, and settled asset accounting."
                ),
                InvariantTemplate.DEBT_COLLATERAL_CONSISTENCY,
                evidence,
                profiles,
                assumptions=[
                    "Detected debt and collateral fields use compatible units",
                    "A position is healthy when collateral is greater than or equal to debt",
                ],
                confidence=0.68,
                executable=True,
            )
        )
    return invariants


def _authorization_invariants(
    entities: list[SolidityEntity],
    graphs: SolidityGraphSet | None,
    files: dict[str, str],
) -> list[InvariantSpec]:
    invariants: list[InvariantSpec] = []
    privilege_sources = {
        edge.source_id
        for edge in (graphs.edges if graphs else [])
        if edge.graph is SolidityGraphKind.PRIVILEGE
    }
    for entity in entities:
        if entity.kind is not SolidityEntityKind.FUNCTION:
            continue
        lowered = entity.name.lower()
        if "upgrade" in lowered or "implementation" in lowered:
            invariants.append(
                _make_invariant(
                    f"Only an authorized principal can invoke {entity.name}",
                    InvariantCategory.AUTHORIZATION,
                    "Implementation changes must be reachable only through the intended upgrade authority.",
                    InvariantTemplate.AUTHORIZED_UPGRADE,
                    [entity],
                    set(),
                    assumptions=[
                        "No external governance layer adds a control absent from repository source"
                    ],
                    confidence=0.85 if entity.id in privilege_sources else 0.58,
                    executable=True,
                )
            )
        elif any(
            token in lowered
            for token in (
                "setoracle",
                "setfee",
                "settreasury",
                "setstrategy",
                "transferownership",
                "grantrole",
                "revokerole",
                "pause",
                "unpause",
                "rescue",
                "sweep",
            )
        ):
            invariants.append(
                _make_invariant(
                    f"Sensitive transition {entity.name} is authorization constrained",
                    InvariantCategory.AUTHORIZATION,
                    "Unauthorized actors must not change privileged protocol configuration or assets.",
                    InvariantTemplate.AUTHORIZED_ADMIN_CHANGE,
                    [entity],
                    set(),
                    assumptions=["The function is not intentionally permissionless"],
                    confidence=0.78 if entity.id in privilege_sources else 0.55,
                    executable=True,
                )
            )
    del files
    return invariants


def _token_invariants(
    entities: list[SolidityEntity],
    graphs: SolidityGraphSet | None,
    profiles: set[str],
    files: dict[str, str],
) -> list[InvariantSpec]:
    invariants: list[InvariantSpec] = []
    if "erc20_token" in profiles:
        mint = _first_name_contains(entities, ("mint",))
        if mint:
            invariants.append(
                _make_invariant(
                    "Unprivileged actors cannot mint value for free",
                    InvariantCategory.TOKEN_STANDARD,
                    "A caller without the documented mint authority cannot increase supply or balance.",
                    InvariantTemplate.NO_FREE_MINT,
                    [mint],
                    profiles,
                    assumptions=["Minting is not intentionally permissionless"],
                    confidence=0.73,
                    executable=True,
                )
            )
    signature_function_ids = {
        edge.source_id
        for edge in (graphs.edges if graphs else [])
        if edge.graph is SolidityGraphKind.SIGNATURE_REPLAY
        and edge.metadata.get("aspect") == "signature_primitive"
    }
    permit = next(
        (
            entity
            for entity in entities
            if entity.kind is SolidityEntityKind.FUNCTION
            and (
                entity.id in signature_function_ids
                or any(token in entity.name.lower() for token in ("permit", "signed"))
            )
        ),
        None,
    )
    if permit:
        replay_state = [
            entity
            for entity in entities
            if entity.contract_name == permit.contract_name
            and entity.kind is SolidityEntityKind.STATE_VARIABLE
            and any(
                token in entity.name.lower() for token in ("nonce", "domain", "deadline", "expiry")
            )
        ]
        invariants.append(
            _make_invariant(
                "Signed approvals cannot be replayed",
                InvariantCategory.TOKEN_STANDARD,
                "Permit-like signatures must bind nonce, chain/domain, signer, and intended action.",
                InvariantTemplate.PERMIT_REPLAY_PROTECTION,
                [permit, *replay_state[:4]],
                profiles,
                assumptions=["The detected signature path authorizes state changes"],
                confidence=0.72,
                executable=True,
            )
        )
    del files
    return invariants


def _state_machine_invariants(
    entities: list[SolidityEntity],
    graphs: SolidityGraphSet | None,
    files: dict[str, str],
) -> list[InvariantSpec]:
    invariants: list[InvariantSpec] = []
    initializers = [
        entity
        for entity in entities
        if entity.kind is SolidityEntityKind.FUNCTION and "initialize" in entity.name.lower()
    ]
    if initializers:
        invariants.append(
            _make_invariant(
                "Initialization succeeds at most once per initialization version",
                InvariantCategory.STATE_MACHINE,
                "Repeated initializer or reinitializer calls must not reset authority or accounting.",
                InvariantTemplate.INITIALIZE_ONCE,
                initializers[:4],
                set(),
                assumptions=["Functions detected by name are initialization entry points"],
                confidence=0.78,
                executable=True,
            )
        )
    pause_functions = _entities_named_like(entities, ("pause", "unpause"))
    paused_state = _first_name_contains(entities, ("paused",))
    if pause_functions and paused_state:
        invariants.append(
            _make_invariant(
                "Paused state blocks configured sensitive transitions",
                InvariantCategory.STATE_MACHINE,
                "When paused, asset-moving or state-sensitive entry points should obey the intended guard.",
                InvariantTemplate.PAUSE_ENFORCEMENT,
                [paused_state, *pause_functions[:3]],
                set(),
                assumptions=["Paused state is intended as an emergency control"],
                confidence=0.72,
                executable=True,
            )
        )
    del graphs, files
    return invariants


def _economic_invariants(
    entities: list[SolidityEntity],
    graphs: SolidityGraphSet | None,
    profiles: set[str],
    files: dict[str, str],
) -> list[InvariantSpec]:
    invariants: list[InvariantSpec] = []
    oracle_edges = [
        edge
        for edge in (graphs.edges if graphs else [])
        if edge.graph is SolidityGraphKind.ORACLE_DEPENDENCY
    ]
    if oracle_edges:
        evidence = _entities_by_id(entities, [edge.source_id for edge in oracle_edges])
        for source_entity in evidence[:20]:
            invariants.append(
                _make_invariant(
                    "Bounded oracle movement cannot create unbounded extraction",
                    InvariantCategory.ECONOMIC,
                    "Price-sensitive transitions should enforce freshness, manipulation resistance, and bounds.",
                    InvariantTemplate.ORACLE_MANIPULATION_RESISTANCE,
                    [source_entity],
                    profiles,
                    assumptions=[
                        "Detected price sources materially affect minting, borrowing, swaps, or liquidation"
                    ],
                    confidence=0.68,
                    executable=True,
                )
            )
        validation_fields = (
            "freshness_validation",
            "scale_validation",
            "availability_validation",
            "sequencer_validation",
        )
        configured_source_ids = sorted(
            {
                edge.source_id
                for edge in oracle_edges
                if edge.metadata.get("oracle_guard_configuration") == "configured"
                and any(edge.metadata.get(field) != "present" for field in validation_fields)
            }
        )
        for source_id in configured_source_ids:
            source_entities = _entities_by_id(entities, [source_id])
            if not source_entities:
                continue
            source_edges = [edge for edge in oracle_edges if edge.source_id == source_id]
            missing_guards = [
                field.removesuffix("_validation")
                for field in validation_fields
                if any(edge.metadata.get(field) != "present" for edge in source_edges)
            ]
            invariants.append(
                _make_invariant(
                    "Configured oracle inputs require complete validation",
                    InvariantCategory.ECONOMIC,
                    (
                        "A configured feed state must be rejected unless freshness, decimal "
                        "scale, answer availability, and sequencer checks all pass."
                    ),
                    InvariantTemplate.ORACLE_GUARD_SANITY,
                    source_entities,
                    profiles,
                    assumptions=[
                        "The source explicitly references decimal and sequencer feed inputs",
                        f"Missing deterministic guard evidence: {', '.join(missing_guards)}",
                    ],
                    confidence=0.88,
                    executable=True,
                )
            )
    governance_edges = [
        edge
        for edge in (graphs.edges if graphs else [])
        if edge.graph is SolidityGraphKind.GOVERNANCE
    ]
    entities_by_id = {entity.id: entity for entity in entities}
    governance_contracts = sorted(
        {
            str(entities_by_id[edge.source_id].contract_name)
            for edge in governance_edges
            if edge.source_id in entities_by_id
            and entities_by_id[edge.source_id].contract_name is not None
        }
    )
    required_stages = ("proposal", "vote", "queue", "execute", "cancel")
    for contract_name in governance_contracts:
        contract_edges = [
            edge
            for edge in governance_edges
            if edge.source_id in entities_by_id
            and entities_by_id[edge.source_id].contract_name == contract_name
        ]
        edges_by_stage = {str(edge.metadata.get("stage")): edge for edge in contract_edges}
        by_stage = {stage: entities_by_id[edge.source_id] for stage, edge in edges_by_stage.items()}
        execute_edges = [
            edge
            for edge in contract_edges
            if edge.metadata.get("stage") == "execute"
            and edge.metadata.get("delay_control") != "present"
        ]
        if (
            not execute_edges
            or not all(stage in by_stage for stage in required_stages)
            or any(
                edges_by_stage[stage].metadata.get("authorization_control") != "present"
                for stage in required_stages
            )
        ):
            continue
        evidence = [by_stage[stage] for stage in required_stages]
        invariants.append(
            _make_invariant(
                "Queued governance execution respects the configured delay",
                InvariantCategory.ECONOMIC,
                (
                    "A proposed, approved, and queued action must not execute before its "
                    "configured readiness boundary, and cancellation remains terminal."
                ),
                InvariantTemplate.GOVERNANCE_DELAY_SANITY,
                evidence,
                profiles,
                assumptions=[
                    "Proposal, vote, queue, execute, and cancel stages are source-linked",
                    "The execute stage has no deterministic rejection guard for its delay state",
                ],
                confidence=0.9,
                executable=True,
            )
        )
    proxy_edges = [
        edge
        for edge in (graphs.edges if graphs else [])
        if edge.graph is SolidityGraphKind.PROXY
        and edge.metadata.get("surface") == "upgrade_or_implementation"
    ]
    initializer_edges = [
        edge
        for edge in (graphs.edges if graphs else [])
        if edge.graph is SolidityGraphKind.INITIALIZER
    ]
    upgrade_contracts = sorted(
        {
            str(entities_by_id[edge.source_id].contract_name)
            for edge in [*proxy_edges, *initializer_edges]
            if edge.source_id in entities_by_id
            and entities_by_id[edge.source_id].contract_name is not None
        }
    )
    for contract_name in upgrade_contracts:
        contract_proxy_edges = [
            edge
            for edge in proxy_edges
            if edge.source_id in entities_by_id
            and entities_by_id[edge.source_id].contract_name == contract_name
            and entities_by_id[edge.source_id].signature == "upgradePreset()"
        ]
        contract_initializer_edges = [
            edge
            for edge in initializer_edges
            if edge.source_id in entities_by_id
            and entities_by_id[edge.source_id].contract_name == contract_name
            and entities_by_id[edge.source_id].signature == "initializePreset()"
        ]
        unsafe_upgrade = next(
            (
                edge
                for edge in contract_proxy_edges
                if edge.metadata.get("authorization_resolution") != "present"
            ),
            None,
        )
        unsafe_initializer = next(
            (
                edge
                for edge in contract_initializer_edges
                if edge.metadata.get("guard_resolution") == "unknown"
            ),
            None,
        )
        if unsafe_upgrade is None or unsafe_initializer is None:
            continue
        evidence = _entities_by_id(
            entities,
            [unsafe_initializer.source_id, unsafe_upgrade.source_id],
        )
        if len(evidence) != 2:
            continue
        invariants.append(
            _make_invariant(
                "Proxy upgrades stay authorized and initialization is one-time",
                InvariantCategory.ECONOMIC,
                (
                    "Only the configured proxy authority may change implementation state, "
                    "and a completed initializer must reject every repeated call."
                ),
                InvariantTemplate.UPGRADE_INITIALIZER_SANITY,
                evidence,
                profiles,
                assumptions=[
                    "Upgrade and initializer entry points are source-linked on one proxy",
                    "No deterministic authorization or one-time guard was resolved",
                ],
                confidence=0.92,
                executable=True,
            )
        )
    unsafe_callback_edges_by_function = {
        str(edge.metadata.get("function_id")): edge
        for edge in (graphs.edges if graphs else [])
        if edge.graph is SolidityGraphKind.REENTRANCY
        and edge.metadata.get("unsafe_transition_candidate") is True
        and edge.metadata.get("callback_reachability") == "present"
        and edge.metadata.get("callback_kind") == "explicit_receiver_hook"
        and edge.metadata.get("callback_member") == "onCreditReceived"
        and edge.metadata.get("affected_state_name") == "availableCredit"
        and str(edge.metadata.get("function_id")) in entities_by_id
        and entities_by_id[str(edge.metadata.get("function_id"))].signature
        == "withdrawCallbackPreset()"
        and edge.target_id in entities_by_id
    }
    for function_id, edge in sorted(unsafe_callback_edges_by_function.items()):
        evidence = _entities_by_id(entities, [function_id, edge.target_id])
        if len(evidence) != 2:
            continue
        invariants.append(
            _make_invariant(
                "Reachable receiver callbacks preserve affected accounting state",
                InvariantCategory.ECONOMIC,
                (
                    "A source-linked receiver callback must not observe reusable credit "
                    "before the affected accounting state is consumed."
                ),
                InvariantTemplate.CALLBACK_STATE_CONSISTENCY,
                evidence,
                profiles,
                assumptions=[
                    "Reachable callback receiver.onCreditReceived() precedes affected state "
                    "availableCredit",
                    "The public preset transition has no resolved named reentrancy guard",
                ],
                confidence=0.9,
                executable=True,
            )
        )
    unsafe_growth_edges = [
        edge
        for edge in (graphs.edges if graphs else [])
        if edge.graph is SolidityGraphKind.STATE_GROWTH
        and edge.metadata.get("operation") == "array_push"
        and edge.metadata.get("entrypoint_visibility") in {"public", "external"}
        and edge.metadata.get("growth_limit_resolution") != "present"
        and edge.source_id in entities_by_id
        and entities_by_id[edge.source_id].signature == "appendPreset()"
        and edge.target_id in entities_by_id
        and entities_by_id[edge.target_id].name == "entries"
    ]
    for edge in sorted(unsafe_growth_edges, key=lambda item: item.source_id):
        source_entity = entities_by_id[edge.source_id]
        contract_entities = [
            entity for entity in entities if entity.contract_name == source_entity.contract_name
        ]
        entry_count = next(
            (
                entity
                for entity in contract_entities
                if entity.signature == "entryCount()"
                and (
                    entity.return_types == ["uint256"]
                    or "returns (uint256)" in _entity_source(files.get(entity.path, ""), entity)
                )
            ),
            None,
        )
        threshold = next(
            (
                entity
                for entity in contract_entities
                if entity.signature == "growthThreshold()"
                and (
                    entity.return_types == ["uint256"]
                    or "returns (uint256)" in _entity_source(files.get(entity.path, ""), entity)
                )
            ),
            None,
        )
        if entry_count is None or threshold is None:
            continue
        threshold_source = _entity_source(files.get(threshold.path, ""), threshold)
        if not re.search(r"\breturn\s+4\s*;", threshold_source):
            continue
        evidence = _entities_by_id(
            entities,
            [edge.source_id, edge.target_id, entry_count.id, threshold.id],
        )
        if len(evidence) != 4:
            continue
        invariants.append(
            _make_invariant(
                "Public collection growth respects its configured threshold",
                InvariantCategory.ECONOMIC,
                (
                    "A bounded public append transition must not increase the source-linked "
                    "collection beyond its configured threshold."
                ),
                InvariantTemplate.STATE_GROWTH_BOUND,
                evidence,
                profiles,
                assumptions=[
                    "appendPreset() is the only generated growth action",
                    "entryCount() and growthThreshold() expose the measured state and bound",
                    "No deterministic pre-append length guard was resolved",
                ],
                confidence=0.86,
                executable=True,
            )
        )
    unsafe_message_source_ids = sorted(
        {
            edge.source_id
            for edge in (graphs.edges if graphs else [])
            if edge.graph is SolidityGraphKind.CROSS_CHAIN
            and edge.metadata.get("direction") == "inbound"
            and (
                edge.metadata.get("replay_protection_evidence") != "present"
                or edge.metadata.get("ordering_evidence") != "present"
            )
            and edge.source_id in entities_by_id
            and entities_by_id[edge.source_id].signature == "processMessagePreset(uint256,bytes32)"
        }
    )
    for source_id in unsafe_message_source_ids:
        source_entities = _entities_by_id(entities, [source_id])
        if not source_entities:
            continue
        invariants.append(
            _make_invariant(
                "Synthetic inbound messages are consumed once and in order",
                InvariantCategory.ECONOMIC,
                (
                    "A consumed message identifier must reject replay, and a valid message "
                    "must match the next configured sequence number."
                ),
                InvariantTemplate.MESSAGE_CONSUMPTION_ONCE,
                source_entities,
                profiles,
                assumptions=[
                    "Only fixture-confined offline messages are exercised",
                    "Replay or ordering guard evidence is unresolved on the inbound transition",
                ],
                confidence=0.88,
                executable=True,
            )
        )
    if "erc4626_vault" in profiles:
        for contract_name, evidence in _erc4626_contract_evidence(entities):
            invariants.append(
                _make_invariant(
                    (
                        f"Donations cannot make the first or next {contract_name} "
                        "depositor lose unbounded value"
                    ),
                    InvariantCategory.ECONOMIC,
                    "Direct asset donation and rounding must not permit a share-price inflation extraction.",
                    InvariantTemplate.DONATION_INFLATION_RESISTANCE,
                    evidence,
                    profiles,
                    assumptions=["The vault accepts externally transferable underlying assets"],
                    confidence=0.75,
                    executable=True,
                )
            )
    fee = _first_name_contains(entities, ("fee", "setfee", "protocolfee"))
    if fee:
        invariants.append(
            _make_invariant(
                "Fees remain within an explicit bounded denominator",
                InvariantCategory.ECONOMIC,
                "Configured or calculated fees must not exceed the operation amount or denominator.",
                InvariantTemplate.FEE_BOUNDS,
                [fee],
                profiles,
                assumptions=["The detected value represents a fee or fee denominator"],
                confidence=0.58,
                executable=True,
            )
        )
    division_entities = [
        entity
        for entity in entities
        if entity.kind is SolidityEntityKind.FUNCTION
        and "/" in _entity_source(files.get(entity.path, ""), entity)
    ]
    if division_entities:
        invariants.append(
            _make_invariant(
                "Rounding error remains bounded across repeated operations",
                InvariantCategory.ECONOMIC,
                "Integer conversion loops must not allow cumulative extraction beyond a documented bound.",
                InvariantTemplate.ROUNDING_BOUNDS,
                division_entities[:5],
                profiles,
                assumptions=["Repeated operations can reach the detected integer divisions"],
                confidence=0.52,
                executable=True,
            )
        )
    contract_names = sorted(
        {entity.contract_name for entity in entities if entity.contract_name is not None}
    )
    for contract_name in contract_names:
        by_signature = {
            entity.signature: entity
            for entity in entities
            if entity.contract_name == contract_name
            and entity.kind is SolidityEntityKind.FUNCTION
            and entity.visibility in {"public", "external"}
            and entity.signature is not None
        }
        stage = by_signature.get("stagePreset()")
        reorder = by_signature.get("reorderPreset()")
        shortfall = by_signature.get("shortfall(address)")
        if stage is None or reorder is None or shortfall is None:
            continue
        shortfall_source = _entity_source(files.get(shortfall.path, ""), shortfall)
        if shortfall.return_types != ["uint256"] and "returns (uint256)" not in shortfall_source:
            continue
        invariants.append(
            _make_invariant(
                "Same-block ordering preserves the staged value bound",
                InvariantCategory.ECONOMIC,
                (
                    "A bounded reorder transition after a staged action must not settle "
                    "below the staged minimum value."
                ),
                InvariantTemplate.ORDERING_VALUE_BOUND,
                [stage, reorder, shortfall],
                profiles,
                assumptions=[
                    "stagePreset() records the value-bound transition under review",
                    "reorderPreset() represents the declared same-block ordering action",
                    "shortfall(address) is zero until or unless settlement violates the bound",
                ],
                confidence=0.76,
                executable=True,
            )
        )
    for contract_name in contract_names:
        contract_entities = [
            entity
            for entity in entities
            if entity.contract_name == contract_name
            and entity.kind is SolidityEntityKind.FUNCTION
            and not entity.path.startswith(("test/", "tests/"))
        ]
        by_signature = {
            entity.signature: entity
            for entity in contract_entities
            if entity.visibility in {"public", "external"} and entity.signature is not None
        }
        prepare = by_signature.get("preparePreset()")
        commit = by_signature.get("commitPreset()")
        invalid_state = by_signature.get("invalidState()")
        if prepare is None or commit is None or invalid_state is None:
            continue
        invalid_source = _entity_source(files.get(invalid_state.path, ""), invalid_state)
        if invalid_state.return_types != ["uint256"] and "returns (uint256)" not in invalid_source:
            continue
        invariants.append(
            _make_invariant(
                "Prepared state is consumed before finalization",
                InvariantCategory.STATE_MACHINE,
                (
                    "A bounded prepare-then-commit sequence must not leave the prepared "
                    "and finalized states simultaneously active."
                ),
                InvariantTemplate.MULTI_STEP_STATE_CONSISTENCY,
                [prepare, commit, invalid_state],
                profiles,
                assumptions=[
                    "preparePreset() and commitPreset() are the exact ordered transitions",
                    "invalidState() is zero unless the source-linked states overlap",
                    "Each transition is one unprivileged synthetic local transaction",
                ],
                confidence=0.84,
                executable=True,
            )
        )
    return invariants


def _protocol_profiles(
    entities: list[SolidityEntity],
    graphs: SolidityGraphSet | None,
    files: dict[str, str],
) -> set[str]:
    names = {entity.name.lower() for entity in entities}
    joined_source = "\n".join(files.values()).lower()
    profiles: set[str] = set()
    if {"totalsupply", "balanceof", "transfer"} <= names or "ierc20" in joined_source:
        profiles.add("erc20_token")
    if any(value in joined_source for value in ("ierc721", "erc721")):
        profiles.add("erc721")
    if any(value in joined_source for value in ("ierc1155", "erc1155")):
        profiles.add("erc1155")
    if (
        {"totalassets", "converttoshares"} <= names
        or {"totalassets", "deposit", "balanceof"} <= names
        or "erc4626" in joined_source
    ):
        profiles.add("erc4626_vault")
    if any(token in name for name in names for token in ("stake", "unstake", "reward")):
        profiles.add("staking")
    if any(token in name for name in names for token in ("borrow", "repay", "liquidat")):
        profiles.add("lending")
    if any(token in joined_source for token in ("getreserves", "swap(", "liquidity")):
        profiles.add("amm")
    if any(token in joined_source for token in ("governor", "timelock", "proposal")):
        profiles.add("governance")
    if any(token in joined_source for token in ("bridge", "messenger", "crossdomain")):
        profiles.add("bridge")
    if graphs and any(edge.graph is SolidityGraphKind.ORACLE_DEPENDENCY for edge in graphs.edges):
        profiles.add("oracle_consumer")
    if graphs and any(edge.graph is SolidityGraphKind.PROXY for edge in graphs.edges):
        profiles.add("upgradeable_system")
    if any(token in name for name in names for token in ("claim", "merkleproof")):
        profiles.add("token_distribution")
    return profiles


def _make_invariant(
    title: str,
    category: InvariantCategory,
    description: str,
    template: InvariantTemplate,
    entities: list[SolidityEntity],
    profiles: Iterable[str],
    *,
    assumptions: list[str],
    confidence: float,
    executable: bool,
) -> InvariantSpec:
    locations = [
        Location(
            path=entity.path,
            start_line=entity.start_line,
            end_line=entity.end_line,
            symbol=entity.name,
            content_hash=entity.source_hash,
        )
        for entity in entities
    ]
    payload = {
        "title": title,
        "template": template.value,
        "entities": sorted(entity.id for entity in entities),
        "locations": [
            (location.path, location.start_line, location.end_line, location.content_hash)
            for location in locations
        ],
    }
    evidence_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    provenance = (
        SolidityProvenance.COMPILER
        if entities and all(entity.provenance is SolidityProvenance.COMPILER for entity in entities)
        else SolidityProvenance.HEURISTIC
    )
    # The entity locations may be compiler-derived, while the semantic invariant
    # inference itself remains a deterministic heuristic.
    if provenance is SolidityProvenance.COMPILER:
        provenance = SolidityProvenance.HEURISTIC
    return InvariantSpec(
        id="inv-" + evidence_hash[:20],
        title=title,
        category=category,
        description=description,
        template=template,
        locations=locations,
        entity_ids=[entity.id for entity in entities],
        state_variables=[
            entity.name
            for entity in entities
            if entity.kind
            in {
                SolidityEntityKind.STATE_VARIABLE,
                SolidityEntityKind.IMMUTABLE,
                SolidityEntityKind.CONSTANT,
            }
        ],
        functions=[
            entity.name
            for entity in entities
            if entity.kind in {SolidityEntityKind.FUNCTION, SolidityEntityKind.CONSTRUCTOR}
        ],
        protocol_profiles=sorted(set(profiles)),
        assumptions=assumptions,
        provenance=provenance,
        confidence=confidence,
        template_available=executable,
        # Source-level inference can identify a useful template, but cannot
        # supply deployment bindings and action semantics safely. It becomes
        # executable only after a typed harness has been validated.
        executable=False,
        analysis_state=AnalysisState.DETERMINISTIC,
        evidence_hash=evidence_hash,
    )


def _by_normalized_name(entities: list[SolidityEntity]) -> dict[str, SolidityEntity]:
    return {entity.name.lower(): entity for entity in entities}


def _erc4626_contract_evidence(
    entities: list[SolidityEntity],
) -> list[tuple[str, list[SolidityEntity]]]:
    """Return exact contract-local ERC4626 entry points without profile-only binding."""

    contract_names = sorted(
        {entity.contract_name for entity in entities if entity.contract_name is not None}
    )
    evidence: list[tuple[str, list[SolidityEntity]]] = []
    for contract_name in contract_names:
        contract_entities = sorted(
            [entity for entity in entities if entity.contract_name == contract_name],
            key=lambda item: (item.path, item.start_line, item.end_line, item.id),
        )
        callable_entities = [
            entity for entity in contract_entities if entity.visibility in {"public", "external"}
        ]
        by_signature = {
            entity.signature: entity for entity in callable_entities if entity.signature is not None
        }
        by_name = {entity.name.lower(): entity for entity in contract_entities}
        deposit = by_signature.get("deposit(uint256,address)")
        total_assets = by_signature.get("totalAssets()") or by_name.get("totalassets")
        balance_of = by_signature.get("balanceOf(address)") or by_name.get("balanceof")
        if deposit is None or total_assets is None or balance_of is None:
            continue
        evidence.append(
            (
                contract_name,
                [deposit, total_assets, balance_of],
            )
        )
    return evidence


def _erc4626_accounting_evidence(
    entities: list[SolidityEntity],
) -> list[tuple[str, list[SolidityEntity]]]:
    """Return contract-local evidence for reviewable ERC4626-like accounting."""

    evidence: list[tuple[str, list[SolidityEntity]]] = []
    required_names = ("deposit", "totalassets", "converttoshares")
    contract_names = sorted(
        {entity.contract_name for entity in entities if entity.contract_name is not None}
    )
    for contract_name in contract_names:
        by_name: dict[str, SolidityEntity] = {}
        for entity in sorted(
            entities,
            key=lambda item: (item.path, item.start_line, item.end_line, item.id),
        ):
            if not (
                entity.contract_name == contract_name
                and (
                    entity.visibility in {"public", "external"}
                    or entity.kind
                    in {
                        SolidityEntityKind.STATE_VARIABLE,
                        SolidityEntityKind.IMMUTABLE,
                        SolidityEntityKind.CONSTANT,
                    }
                )
            ):
                continue
            by_name.setdefault(entity.name.lower(), entity)
        if not all(name in by_name for name in required_names):
            continue
        rate_boundary = by_name.get("exchangerateboundarypreset")
        evidence.append(
            (
                contract_name,
                [
                    *(by_name[name] for name in required_names),
                    *((rate_boundary,) if rate_boundary is not None else ()),
                ],
            )
        )
    return evidence


def _first_named(
    names: dict[str, SolidityEntity],
    *values: str,
) -> SolidityEntity | None:
    return next((names[value] for value in values if value in names), None)


def _first_name_contains(
    entities: list[SolidityEntity],
    values: tuple[str, ...],
) -> SolidityEntity | None:
    return next(
        (entity for entity in entities if any(value in entity.name.lower() for value in values)),
        None,
    )


def _entities_named_like(
    entities: list[SolidityEntity],
    values: tuple[str, ...],
) -> list[SolidityEntity]:
    return [entity for entity in entities if any(value in entity.name.lower() for value in values)]


def _entities_by_id(
    entities: list[SolidityEntity],
    entity_ids: list[str],
) -> list[SolidityEntity]:
    by_id = {entity.id: entity for entity in entities}
    return [by_id[entity_id] for entity_id in entity_ids if entity_id in by_id]


def _entity_source(content: str, entity: SolidityEntity) -> str:
    lines = content.splitlines(keepends=True)
    return "".join(lines[entity.start_line - 1 : entity.end_line])


def _accounting_claim_entity(
    entities: list[SolidityEntity],
    contract_name: str | None,
) -> SolidityEntity | None:
    return next(
        (
            entity
            for entity in entities
            if entity.contract_name == contract_name
            and entity.kind
            in {
                SolidityEntityKind.STATE_VARIABLE,
                SolidityEntityKind.FUNCTION,
            }
            and any(
                token in entity.name.lower()
                for token in ("credit", "claimable", "shares", "depositbalance")
            )
        ),
        None,
    )


def _has_unchecked_erc20_return(source: str) -> bool:
    """Identify source-local transferFrom outcomes that are not validated."""

    lowered = source.casefold()
    compact = re.sub(r"\s+", "", lowered)
    if "transferfrom" not in compact:
        return False

    if ".call(" in compact:
        captures_bytes = re.search(
            r"\(\s*bool\s+\w+\s*,\s*bytes(?:\s+memory)?\s+\w+\s*\)\s*=",
            lowered,
        )
        validates_length = re.search(r"\b[a-z_]\w*\.length\b", lowered)
        decodes_boolean = re.search(
            r"abi\s*\.\s*decode\s*\([^;]+bool",
            lowered,
            flags=re.DOTALL,
        )
        return not (captures_bytes and validates_length and decodes_boolean)

    raw_transfer = re.search(r"\.\s*transferfrom\s*\(", lowered)
    if raw_transfer is None:
        return False
    call_statement = lowered[lowered.rfind(";", 0, raw_transfer.start()) + 1 :]
    call_statement = call_statement[: call_statement.find(";") + 1]
    if re.search(r"\b(require|assert)\s*\(", call_statement):
        return False
    assigned = re.search(
        r"\bbool\s+([a-z_]\w*)\s*=\s*[^;]*\.\s*transferfrom\s*\(",
        call_statement,
    )
    if assigned is None:
        return True
    result_name = re.escape(assigned.group(1))
    remainder = lowered[raw_transfer.end() :]
    return (
        re.search(
            rf"\b(require|assert)\s*\(\s*{result_name}\b|if\s*\(\s*!\s*{result_name}\b",
            remainder,
        )
        is None
    )


def _invariant_warnings(
    index: SoliditySymbolIndex,
    profiles: set[str],
) -> list[str]:
    warnings = [
        "Inferred invariants are audit hypotheses, not verified protocol intent; "
        "repository documentation or executable evidence must validate them."
    ]
    if index.fallback_sources:
        warnings.append(
            f"{len(index.fallback_sources)} source file(s) used fallback parsing; "
            "their invariant inputs carry lower confidence."
        )
    if not profiles:
        warnings.append("No supported protocol profile was detected.")
    return warnings
