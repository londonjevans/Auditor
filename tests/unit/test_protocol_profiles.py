from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from mmaudit.config import InvariantConfig
from mmaudit.models.schemas import (
    InvariantSuite,
    KnownIssueApplicability,
    KnownIssueDisposition,
    ProtocolProfileAssessment,
    ProtocolProfileEvidence,
    ProtocolProfileKind,
    ProtocolProfileStatus,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphKind,
    SolidityGraphNode,
    SolidityGraphNodeKind,
    SolidityGraphOccurrenceKind,
    SolidityGraphOmission,
    SolidityGraphRetainedOccurrence,
    SolidityGraphSet,
    SolidityProvenance,
    SoliditySymbolIndex,
    solidity_graph_occurrence_sha256,
)
from mmaudit.repository.chunking import line_range_hash
from mmaudit.repository.discovery import DiscoveredFile, DiscoveryResult
from mmaudit.solidity.graphs import build_solidity_graphs
from mmaudit.solidity.index import AstDocument, SolidityIndexBuild, build_solidity_index
from mmaudit.solidity.invariants import (
    detect_protocol_profiles,
    discover_invariants,
    validate_protocol_profile_replay,
)
from mmaudit.solidity.taxonomy import (
    build_known_issue_taxonomy_coverage,
    known_issue_taxonomy_quality_gate,
    load_known_issue_taxonomy,
)

_PATH = "src/Split.sol"
_SOURCE = "function totalSupply() external {}\nfunction balanceOf() external {}\nfunction transfer() external {}\n"


def _function(
    entity_id: str,
    name: str,
    contract: str,
    line: int,
    *,
    provenance: SolidityProvenance = SolidityProvenance.COMPILER,
) -> SolidityEntity:
    return SolidityEntity(
        id=entity_id,
        kind=SolidityEntityKind.FUNCTION,
        name=name,
        contract_name=contract,
        path=_PATH,
        start_line=line,
        end_line=line,
        byte_start=line - 1,
        byte_end=line,
        source_hash=line_range_hash(_SOURCE, line, line),
        provenance=provenance,
        confidence=1 if provenance is SolidityProvenance.COMPILER else 0.7,
        transformation="synthetic_protocol_profile_test",
        visibility="external",
        signature=f"{name}()",
    )


def _complete_empty_profile_graphs() -> SolidityGraphSet:
    return SolidityGraphSet(
        edges=[],
        retained_occurrences=(),
        analyzed_graphs=[
            SolidityGraphKind.ORACLE_DEPENDENCY,
            SolidityGraphKind.PROXY,
        ],
    )


def _discovery(
    *,
    source: str = _SOURCE,
    retained_content: str = _SOURCE,
    omissions: tuple[str, ...] = (),
) -> DiscoveryResult:
    source_bytes = source.encode("utf-8")
    return DiscoveryResult(
        root=Path("/synthetic/protocol-profile-test"),
        files=(
            DiscoveredFile(
                absolute_path=Path("/synthetic/protocol-profile-test") / _PATH,
                relative_path=_PATH,
                content=retained_content,
                size=len(source_bytes),
                lines=len(source.splitlines()),
                sha256=hashlib.sha256(source_bytes).hexdigest(),
                language="Solidity",
                categories=("smart_contract",),
            ),
        ),
        omitted=omissions,
        changed_paths=frozenset(),
        git_commit=None,
    )


def _same_contract_functions(
    *,
    provenance: SolidityProvenance = SolidityProvenance.COMPILER,
) -> list[SolidityEntity]:
    return [
        _function(
            "function:A.totalSupply",
            "totalSupply",
            "A",
            1,
            provenance=provenance,
        ),
        _function(
            "function:A.balanceOf",
            "balanceOf",
            "A",
            2,
            provenance=provenance,
        ),
        _function(
            "function:A.transfer",
            "transfer",
            "A",
            3,
            provenance=provenance,
        ),
    ]


def _assessment_from_discovery(
    discovery: DiscoveryResult,
    index: SoliditySymbolIndex,
) -> ProtocolProfileAssessment:
    suite = discover_invariants(
        discovery,
        index,
        _complete_empty_profile_graphs(),
        InvariantConfig(enabled=False),
    )
    assert suite.protocol_profile_assessment is not None
    return suite.protocol_profile_assessment


def _forge_profile_as_not_detected(
    assessment: ProtocolProfileAssessment,
    profile: ProtocolProfileKind,
) -> ProtocolProfileAssessment:
    classifications: list[ProtocolProfileEvidence] = []
    for evidence in assessment.classifications:
        if evidence.profile is not profile:
            classifications.append(evidence)
            continue
        payload = evidence.model_dump(mode="json")
        payload.update(
            {
                "status": ProtocolProfileStatus.NOT_DETECTED,
                "matched_facts": ["forged:absence"],
                "entity_ids": [],
                "locations": [],
            }
        )
        payload["evidence_sha256"] = ProtocolProfileEvidence.calculate_evidence_sha256(payload)
        classifications.append(ProtocolProfileEvidence.model_validate(payload))
    payload = assessment.model_dump(mode="json")
    payload["classifications"] = [item.model_dump(mode="json") for item in classifications]
    payload["assessment_sha256"] = ProtocolProfileAssessment.calculate_assessment_sha256(payload)
    return ProtocolProfileAssessment.model_validate(payload)


def test_profile_inventory_is_complete_and_contract_local() -> None:
    index = SoliditySymbolIndex(
        projects=[],
        entities=[
            _function("function:A.totalSupply", "totalSupply", "A", 1),
            _function("function:B.balanceOf", "balanceOf", "B", 2),
            _function("function:C.transfer", "transfer", "C", 3),
        ],
        ast_sources=[_PATH],
    )

    assessment = detect_protocol_profiles(
        index,
        _complete_empty_profile_graphs(),
        {_PATH: _SOURCE},
    )
    by_profile = {item.profile: item for item in assessment.classifications}

    assert set(by_profile) == set(ProtocolProfileKind)
    assert by_profile[ProtocolProfileKind.SOLIDITY_GENERAL].status is (
        ProtocolProfileStatus.DETECTED
    )
    assert by_profile[ProtocolProfileKind.ERC20_TOKEN].status is (
        ProtocolProfileStatus.INDETERMINATE
    )
    assert not assessment.classification_complete
    assert any(
        "compiler_execution_not_independently_authenticated_for_profile_absence" in item
        for item in assessment.limitations
    )
    assert assessment.assessment_sha256 == assessment.calculate_assessment_sha256(
        assessment.model_dump(mode="json")
    )


def test_profile_assessment_is_order_stable_and_missing_graphs_are_indeterminate() -> None:
    entities = _same_contract_functions()
    first = detect_protocol_profiles(
        SoliditySymbolIndex(projects=[], entities=entities, ast_sources=[_PATH]),
        None,
        {_PATH: _SOURCE},
    )
    second = detect_protocol_profiles(
        SoliditySymbolIndex(projects=[], entities=list(reversed(entities)), ast_sources=[_PATH]),
        None,
        {_PATH: _SOURCE},
    )
    by_profile = {item.profile: item for item in first.classifications}

    assert first == second
    assert by_profile[ProtocolProfileKind.ERC20_TOKEN].status is ProtocolProfileStatus.DETECTED
    assert by_profile[ProtocolProfileKind.ERC20_TOKEN].entity_ids == [
        "function:A.balanceOf",
        "function:A.totalSupply",
        "function:A.transfer",
    ]
    assert by_profile[ProtocolProfileKind.ORACLE_CONSUMER].status is (
        ProtocolProfileStatus.INDETERMINATE
    )
    assert by_profile[ProtocolProfileKind.UPGRADEABLE_SYSTEM].status is (
        ProtocolProfileStatus.INDETERMINATE
    )
    assert not first.classification_complete


def test_mapped_without_content_keeps_positive_profiles_and_invalidates_all_negatives() -> None:
    index = SoliditySymbolIndex(
        projects=[],
        entities=_same_contract_functions(),
        ast_sources=[_PATH],
    )
    complete = detect_protocol_profiles(
        index,
        _complete_empty_profile_graphs(),
        {_PATH: _SOURCE},
    )
    mapped = _assessment_from_discovery(
        _discovery(
            retained_content="",
            omissions=(f"{_PATH}: mapped without content after max_discovery_bytes",),
        ),
        index,
    )
    different_hidden_source = _SOURCE.replace("external", "public  ", 1)
    assert len(different_hidden_source.encode("utf-8")) == len(_SOURCE.encode("utf-8"))
    mapped_different_bytes = _assessment_from_discovery(
        _discovery(
            source=different_hidden_source,
            retained_content="",
            omissions=(f"{_PATH}: mapped without content after max_discovery_bytes",),
        ),
        index,
    )
    by_profile = {item.profile: item for item in mapped.classifications}

    assert by_profile[ProtocolProfileKind.ERC20_TOKEN].status is ProtocolProfileStatus.DETECTED
    assert by_profile[ProtocolProfileKind.ERC721].status is (ProtocolProfileStatus.INDETERMINATE)
    assert by_profile[ProtocolProfileKind.ORACLE_CONSUMER].status is (
        ProtocolProfileStatus.INDETERMINATE
    )
    assert not mapped.classification_complete
    assert mapped.input_sha256 != complete.input_sha256
    assert mapped_different_bytes.input_sha256 != mapped.input_sha256
    assert mapped_different_bytes.limitations != mapped.limitations
    assert any("mapped_without_content_solidity_count:1" in item for item in mapped.limitations)


def test_global_discovery_limit_invalidates_even_complete_retained_graph_negatives() -> None:
    source_with_marker = _SOURCE + "// IERC721 retained positive marker\n"
    index = SoliditySymbolIndex(
        projects=[],
        entities=_same_contract_functions(),
        ast_sources=[_PATH],
    )
    complete = detect_protocol_profiles(
        index,
        _complete_empty_profile_graphs(),
        {_PATH: source_with_marker},
    )
    assessment = _assessment_from_discovery(
        _discovery(
            source=source_with_marker,
            retained_content=source_with_marker,
            omissions=("repository: max_files reached",),
        ),
        index,
    )
    complete_by_profile = {item.profile: item for item in complete.classifications}
    by_profile = {item.profile: item for item in assessment.classifications}

    for profile, complete_evidence in complete_by_profile.items():
        expected = (
            ProtocolProfileStatus.DETECTED
            if complete_evidence.status is ProtocolProfileStatus.DETECTED
            else ProtocolProfileStatus.INDETERMINATE
        )
        assert by_profile[profile].status is expected
    assert by_profile[ProtocolProfileKind.ERC721].status is ProtocolProfileStatus.DETECTED
    assert (
        "discovery_global_limit:max_files"
        in by_profile[ProtocolProfileKind.UPGRADEABLE_SYSTEM].matched_facts
    )
    assert any("discovery_global_limit:max_files" in item for item in assessment.limitations)
    assert assessment.input_sha256 != complete.input_sha256


def test_fallback_only_parsing_invalidates_negatives_and_becomes_taxonomy_gap() -> None:
    index = SoliditySymbolIndex(
        projects=[],
        entities=_same_contract_functions(provenance=SolidityProvenance.FALLBACK),
        fallback_sources=[_PATH],
    )
    assessment = _assessment_from_discovery(_discovery(), index)
    by_profile = {item.profile: item for item in assessment.classifications}

    assert by_profile[ProtocolProfileKind.ERC20_TOKEN].status is ProtocolProfileStatus.DETECTED
    assert by_profile[ProtocolProfileKind.ERC721].status is (ProtocolProfileStatus.INDETERMINATE)
    assert by_profile[ProtocolProfileKind.ORACLE_CONSUMER].status is (
        ProtocolProfileStatus.INDETERMINATE
    )
    assert any("profile_positive_only_solidity_count:1" in item for item in assessment.limitations)

    coverage = build_known_issue_taxonomy_coverage(
        load_known_issue_taxonomy(),
        invariants=InvariantSuite(
            protocol_profiles=[profile.value for profile in assessment.detected_profiles],
            protocol_profile_assessment=assessment,
        ),
        model_review_coverage=None,
    )
    unknown = [
        item
        for item in coverage.dispositions
        if item.applicability is KnownIssueApplicability.UNKNOWN
    ]
    assert unknown
    assert all(item.disposition is KnownIssueDisposition.GAP for item in unknown)


def test_any_retained_solidity_source_keeps_all_negative_profiles_indeterminate() -> None:
    assessment = _assessment_from_discovery(
        _discovery(),
        SoliditySymbolIndex(projects=[], entities=[]),
    )

    assert all(
        item.status is ProtocolProfileStatus.INDETERMINATE for item in assessment.classifications
    )
    assert any("profile_positive_only_solidity_count:1" in item for item in assessment.limitations)


def test_profile_replay_rejects_coherently_rehashed_detected_to_negative_forgery() -> None:
    path = "src/Token.sol"
    source = (
        "contract A {\n"
        "function totalSupply() external {}\n"
        "function balanceOf() external {}\n"
        "function transfer() external {}\n"
        "}\n"
    )
    source_bytes = source.encode("utf-8")
    discovery = DiscoveryResult(
        root=Path("/synthetic/profile-replay-forgery-test"),
        files=(
            DiscoveredFile(
                absolute_path=Path("/synthetic/profile-replay-forgery-test") / path,
                relative_path=path,
                content=source,
                size=len(source_bytes),
                lines=len(source.splitlines()),
                sha256=hashlib.sha256(source_bytes).hexdigest(),
                language="Solidity",
                categories=("smart_contract",),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    source_build = build_solidity_index(discovery, [], [])
    index = SoliditySymbolIndex(
        projects=[],
        entities=[
            entity.model_copy(
                update={
                    "provenance": SolidityProvenance.COMPILER,
                    "confidence": 0.95,
                    "transformation": "synthetic_compiler_ast",
                }
            )
            for entity in source_build.index.entities
        ],
        ast_sources=[path],
    )
    graphs = _complete_empty_profile_graphs()
    assessment = _assessment_from_discovery(discovery, index)
    forged_assessment = _forge_profile_as_not_detected(
        assessment,
        ProtocolProfileKind.ERC20_TOKEN,
    )
    forged_suite = InvariantSuite(
        protocol_profiles=[profile.value for profile in forged_assessment.detected_profiles],
        protocol_profile_assessment=forged_assessment,
    )

    with pytest.raises(ValueError, match="differs from exact source replay"):
        validate_protocol_profile_replay(
            discovery,
            index,
            graphs,
            forged_suite,
        )


def test_profile_replay_rejects_coherent_source_entity_deletion() -> None:
    path = "src/Token.sol"
    source = (
        "contract Token {\n"
        "function totalSupply() external {}\n"
        "function balanceOf() external {}\n"
        "function transfer() external {}\n"
        "}\n"
    )
    source_bytes = source.encode("utf-8")
    discovery = DiscoveryResult(
        root=Path("/synthetic/source-rebuilt-profile-test"),
        files=(
            DiscoveredFile(
                absolute_path=Path("/synthetic/source-rebuilt-profile-test") / path,
                relative_path=path,
                content=source,
                size=len(source_bytes),
                lines=len(source.splitlines()),
                sha256=hashlib.sha256(source_bytes).hexdigest(),
                language="Solidity",
                categories=("smart_contract",),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    source_build = build_solidity_index(discovery, [], [])
    retained_entities = [
        entity.model_copy(
            update={
                "provenance": SolidityProvenance.COMPILER,
                "confidence": 0.95,
                "transformation": "synthetic_compiler_ast",
            }
        )
        for entity in source_build.index.entities
    ]
    retained_index = SoliditySymbolIndex(
        projects=[],
        entities=retained_entities,
        ast_sources=[path],
    )
    graphs = build_solidity_graphs(discovery, source_build)
    legitimate = discover_invariants(
        discovery,
        retained_index,
        graphs,
        InvariantConfig(enabled=False),
    )
    assert legitimate.protocol_profile_assessment is not None
    assert ProtocolProfileKind.ERC20_TOKEN in (
        legitimate.protocol_profile_assessment.detected_profiles
    )

    deleted_index = retained_index.model_copy(
        update={
            "entities": [
                entity for entity in retained_index.entities if entity.name != "totalSupply"
            ]
        }
    )
    forged_assessment = detect_protocol_profiles(
        deleted_index,
        graphs,
        {path: source},
    )
    forged_by_profile = {item.profile: item for item in forged_assessment.classifications}
    assert forged_by_profile[ProtocolProfileKind.ERC20_TOKEN].status is (
        ProtocolProfileStatus.INDETERMINATE
    )
    forged_suite = InvariantSuite(
        protocol_profiles=[profile.value for profile in forged_assessment.detected_profiles],
        protocol_profile_assessment=forged_assessment,
    )

    with pytest.raises(ValueError, match="omits source-rebuilt profile"):
        validate_protocol_profile_replay(
            discovery,
            deleted_index,
            graphs,
            forged_suite,
        )


def test_profile_replay_accepts_compiler_provenance_entity_id_remap() -> None:
    path = "src/Consumer.sol"
    source = (
        "contract ConsumerProxy {\n"
        "uint256 public constant rewardRate = 1;\n"
        "function read() external view { feed.latestRoundData(); }\n"
        "}\n"
    )
    source_bytes = source.encode("utf-8")
    discovery = DiscoveryResult(
        root=Path("/synthetic/compiler-id-remap-profile-test"),
        files=(
            DiscoveredFile(
                absolute_path=Path("/synthetic/compiler-id-remap-profile-test") / path,
                relative_path=path,
                content=source,
                size=len(source_bytes),
                lines=len(source.splitlines()),
                sha256=hashlib.sha256(source_bytes).hexdigest(),
                language="Solidity",
                categories=("smart_contract", "evm_oracle"),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    source_build = build_solidity_index(discovery, [], [])
    retained_entities = [
        entity.model_copy(
            update={
                "id": f"compiler-{hashlib.sha256(entity.id.encode()).hexdigest()[:20]}",
                "kind": (
                    SolidityEntityKind.CONSTANT if entity.name == "rewardRate" else entity.kind
                ),
                "provenance": SolidityProvenance.COMPILER,
                "confidence": 0.95,
                "transformation": "synthetic_compiler_ast",
            }
        )
        for entity in source_build.index.entities
    ]
    retained_index = SoliditySymbolIndex(
        projects=[],
        entities=retained_entities,
        ast_sources=[path],
    )
    retained_graphs = build_solidity_graphs(
        discovery,
        SolidityIndexBuild(index=retained_index, ast_documents=[]),
    )
    suite = discover_invariants(
        discovery,
        retained_index,
        retained_graphs,
        InvariantConfig(enabled=False),
    )
    assessment = suite.protocol_profile_assessment

    assert assessment is not None
    assert ProtocolProfileKind.ORACLE_CONSUMER in assessment.detected_profiles
    assert ProtocolProfileKind.UPGRADEABLE_SYSTEM in assessment.detected_profiles
    assert ProtocolProfileKind.STAKING in assessment.detected_profiles
    assert (
        validate_protocol_profile_replay(
            discovery,
            retained_index,
            retained_graphs,
            suite,
        )
        == assessment
    )


def test_profile_replay_accepts_proxy_inheritance_header_signal() -> None:
    path = "src/UUPS.sol"
    source = "contract Vault is UUPSUpgradeable {\n}\n"
    source_bytes = source.encode("utf-8")
    discovery = DiscoveryResult(
        root=Path("/synthetic/proxy-header-profile-test"),
        files=(
            DiscoveredFile(
                absolute_path=Path("/synthetic/proxy-header-profile-test") / path,
                relative_path=path,
                content=source,
                size=len(source_bytes),
                lines=len(source.splitlines()),
                sha256=hashlib.sha256(source_bytes).hexdigest(),
                language="Solidity",
                categories=("smart_contract", "evm_proxy"),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    source_build = build_solidity_index(discovery, [], [])
    graphs = build_solidity_graphs(discovery, source_build)
    suite = discover_invariants(
        discovery,
        source_build.index,
        graphs,
        InvariantConfig(enabled=False),
    )

    assert any(edge.graph is SolidityGraphKind.PROXY for edge in graphs.edges)
    assert suite.protocol_profile_assessment is not None
    assert ProtocolProfileKind.UPGRADEABLE_SYSTEM in (
        suite.protocol_profile_assessment.detected_profiles
    )
    assert (
        validate_protocol_profile_replay(
            discovery,
            source_build.index,
            graphs,
            suite,
        )
        == suite.protocol_profile_assessment
    )


def test_profile_replay_accepts_function_typed_and_multiline_state_declarations() -> None:
    path = "src/Rewards.sol"
    source = (
        "contract Rewards {\n"
        "function(uint256) external returns (uint256) public rewardCallback;\n"
        "uint256 public rewardRate = 1;\n"
        "uint256 public constant\n"
        "rewardBoost = 2;\n"
        "}\n"
    )
    source_bytes = source.encode("utf-8")
    discovery = DiscoveryResult(
        root=Path("/synthetic/state-declaration-profile-test"),
        files=(
            DiscoveredFile(
                absolute_path=Path("/synthetic/state-declaration-profile-test") / path,
                relative_path=path,
                content=source,
                size=len(source_bytes),
                lines=len(source.splitlines()),
                sha256=hashlib.sha256(source_bytes).hexdigest(),
                language="Solidity",
                categories=("smart_contract",),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    source_build = build_solidity_index(discovery, [], [])
    lines = source.splitlines(keepends=True)

    def state_entity(
        name: str,
        kind: SolidityEntityKind,
        start_line: int,
        end_line: int,
    ) -> SolidityEntity:
        return SolidityEntity(
            id=f"compiler-state-{name}",
            kind=kind,
            name=name,
            contract_name="Rewards",
            path=path,
            start_line=start_line,
            end_line=end_line,
            byte_start=len("".join(lines[: start_line - 1]).encode("utf-8")),
            byte_end=len("".join(lines[:end_line]).encode("utf-8")),
            source_hash=line_range_hash(source, start_line, end_line),
            provenance=SolidityProvenance.COMPILER,
            confidence=0.95,
            transformation="synthetic_compiler_ast_state",
            visibility="public",
        )

    retained_index = SoliditySymbolIndex(
        projects=[],
        entities=[
            *(
                entity
                for entity in source_build.index.entities
                if entity.kind is SolidityEntityKind.CONTRACT
            ),
            state_entity("rewardCallback", SolidityEntityKind.STATE_VARIABLE, 2, 2),
            state_entity("rewardRate", SolidityEntityKind.STATE_VARIABLE, 3, 3),
            state_entity("rewardBoost", SolidityEntityKind.CONSTANT, 4, 5),
        ],
        ast_sources=[path],
    )
    suite = discover_invariants(
        discovery,
        retained_index,
        None,
        InvariantConfig(enabled=False),
    )

    assert suite.protocol_profile_assessment is not None
    assert ProtocolProfileKind.STAKING in suite.protocol_profile_assessment.detected_profiles
    assert (
        validate_protocol_profile_replay(
            discovery,
            retained_index,
            None,
            suite,
        )
        == suite.protocol_profile_assessment
    )


def test_profile_replay_accepts_source_declared_compiler_only_profile_entity() -> None:
    path = "src/MultilineToken.sol"
    source = (
        "contract Token {\n"
        "function\n"
        "totalSupply() external {}\n"
        "function balanceOf() external {}\n"
        "function transfer() external {}\n"
        "}\n"
    )
    source_bytes = source.encode("utf-8")
    discovery = DiscoveryResult(
        root=Path("/synthetic/compiler-only-profile-entity-test"),
        files=(
            DiscoveredFile(
                absolute_path=Path("/synthetic/compiler-only-profile-entity-test") / path,
                relative_path=path,
                content=source,
                size=len(source_bytes),
                lines=len(source.splitlines()),
                sha256=hashlib.sha256(source_bytes).hexdigest(),
                language="Solidity",
                categories=("smart_contract",),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    source_build = build_solidity_index(discovery, [], [])
    compiler_entity = SolidityEntity(
        id="compiler-multiline-total-supply",
        kind=SolidityEntityKind.FUNCTION,
        name="totalSupply",
        contract_name="Token",
        path=path,
        start_line=2,
        end_line=3,
        byte_start=len(b"contract Token {\n"),
        byte_end=len(b"contract Token {\nfunction\ntotalSupply() external {}\n"),
        source_hash=line_range_hash(source, 2, 3),
        provenance=SolidityProvenance.COMPILER,
        confidence=0.95,
        transformation="synthetic_compiler_ast",
        visibility="external",
        signature="totalSupply()",
    )
    retained_index = SoliditySymbolIndex(
        projects=[],
        entities=[
            *(
                entity.model_copy(
                    update={
                        "provenance": SolidityProvenance.COMPILER,
                        "confidence": 0.95,
                        "transformation": "synthetic_compiler_ast",
                    }
                )
                for entity in source_build.index.entities
            ),
            compiler_entity,
        ],
        ast_sources=[path],
    )
    graphs = build_solidity_graphs(
        discovery,
        SolidityIndexBuild(index=retained_index, ast_documents=[]),
    )
    suite = discover_invariants(
        discovery,
        retained_index,
        graphs,
        InvariantConfig(enabled=False),
    )
    assessment = suite.protocol_profile_assessment

    assert assessment is not None
    assert ProtocolProfileKind.ERC20_TOKEN in assessment.detected_profiles
    assert (
        validate_protocol_profile_replay(
            discovery,
            retained_index,
            graphs,
            suite,
        )
        == assessment
    )


def test_profile_replay_rejects_coherent_state_symbol_deletion() -> None:
    path = "src/Rewards.sol"
    source = "contract Pool {\nuint256 public constant\nrewardRate = 1;\n}\n"
    source_bytes = source.encode("utf-8")
    discovery = DiscoveryResult(
        root=Path("/synthetic/source-rebuilt-state-test"),
        files=(
            DiscoveredFile(
                absolute_path=Path("/synthetic/source-rebuilt-state-test") / path,
                relative_path=path,
                content=source,
                size=len(source_bytes),
                lines=len(source.splitlines()),
                sha256=hashlib.sha256(source_bytes).hexdigest(),
                language="Solidity",
                categories=("smart_contract",),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    source_build = build_solidity_index(discovery, [], [])
    fallback_reward_rate = next(
        entity for entity in source_build.index.entities if entity.name == "rewardRate"
    )
    assert (fallback_reward_rate.start_line, fallback_reward_rate.end_line) == (2, 3)
    compiler_reward_rate = fallback_reward_rate.model_copy(
        update={
            "id": "compiler-multiline-reward-rate",
            "kind": SolidityEntityKind.CONSTANT,
            "provenance": SolidityProvenance.COMPILER,
            "confidence": 0.95,
            "transformation": "synthetic_compiler_ast",
            "visibility": "public",
        }
    )
    retained_entities = [
        entity.model_copy(
            update={
                "provenance": SolidityProvenance.COMPILER,
                "confidence": 0.95,
                "transformation": "synthetic_compiler_ast",
            }
        )
        for entity in source_build.index.entities
        if entity.name != "rewardRate"
    ]
    retained_index = SoliditySymbolIndex(
        projects=[],
        entities=[*retained_entities, compiler_reward_rate],
        ast_sources=[path],
    )
    graphs = build_solidity_graphs(
        discovery,
        SolidityIndexBuild(index=retained_index, ast_documents=[]),
    )
    legitimate = discover_invariants(
        discovery,
        retained_index,
        graphs,
        InvariantConfig(enabled=False),
    )
    assert legitimate.protocol_profile_assessment is not None
    assert ProtocolProfileKind.STAKING in legitimate.protocol_profile_assessment.detected_profiles
    assert (
        validate_protocol_profile_replay(
            discovery,
            retained_index,
            graphs,
            legitimate,
        )
        == legitimate.protocol_profile_assessment
    )
    deleted_index = retained_index.model_copy(
        update={
            "entities": [
                entity for entity in retained_index.entities if entity.name != "rewardRate"
            ]
        }
    )
    forged_assessment = detect_protocol_profiles(
        deleted_index,
        graphs,
        {path: source},
    )
    forged_by_profile = {item.profile: item for item in forged_assessment.classifications}
    assert forged_by_profile[ProtocolProfileKind.STAKING].status is (
        ProtocolProfileStatus.INDETERMINATE
    )
    forged_suite = InvariantSuite(
        protocol_profiles=[profile.value for profile in forged_assessment.detected_profiles],
        protocol_profile_assessment=forged_assessment,
    )

    with pytest.raises(ValueError, match="omits source-rebuilt profile"):
        validate_protocol_profile_replay(
            discovery,
            deleted_index,
            graphs,
            forged_suite,
        )


def test_fallback_to_compiler_relabel_cannot_authorize_negative_profiles() -> None:
    path = "src/Plain.sol"
    source = "contract Plain {\nfunction ping() external { feed.latestAnswer(); }\n}\n"
    source_bytes = source.encode("utf-8")
    discovery = DiscoveryResult(
        root=Path("/synthetic/profile-provenance-upgrade-test"),
        files=(
            DiscoveredFile(
                absolute_path=Path("/synthetic/profile-provenance-upgrade-test") / path,
                relative_path=path,
                content=source,
                size=len(source_bytes),
                lines=len(source.splitlines()),
                sha256=hashlib.sha256(source_bytes).hexdigest(),
                language="Solidity",
                categories=("smart_contract",),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    source_build = build_solidity_index(discovery, [], [])
    fallback_graphs = build_solidity_graphs(discovery, source_build)
    fallback_suite = discover_invariants(
        discovery,
        source_build.index,
        fallback_graphs,
        InvariantConfig(enabled=False),
    )
    assert fallback_suite.protocol_profile_assessment is not None
    assert not fallback_suite.protocol_profile_assessment.classification_complete
    assert any(
        item.status is ProtocolProfileStatus.INDETERMINATE
        for item in fallback_suite.protocol_profile_assessment.classifications
    )

    forged_index = SoliditySymbolIndex(
        projects=[],
        entities=[
            entity.model_copy(
                update={
                    "provenance": SolidityProvenance.COMPILER,
                    "confidence": 0.95,
                    "transformation": "forged_compiler_ast",
                }
            )
            for entity in source_build.index.entities
        ],
        ast_sources=[path],
    )
    relabelled_edges = [
        edge.model_copy(
            update={
                "provenance": SolidityProvenance.COMPILER,
                "confidence": 0.95,
                "transformation": "forged_compiler_ast_edge",
            }
        )
        for edge in fallback_graphs.edges
    ]
    relabelled_edge_hashes = {
        solidity_graph_occurrence_sha256(
            SolidityGraphOccurrenceKind.EDGE, original
        ): solidity_graph_occurrence_sha256(SolidityGraphOccurrenceKind.EDGE, relabelled)
        for original, relabelled in zip(fallback_graphs.edges, relabelled_edges, strict=True)
    }
    forged_graph_payload = fallback_graphs.model_dump(mode="python")
    forged_graph_payload["edges"] = relabelled_edges
    forged_graph_payload["retained_occurrences"] = sorted(
        [
            occurrence.model_copy(
                update={"subject_sha256": relabelled_edge_hashes[occurrence.subject_sha256]}
            )
            if occurrence.subject_kind is SolidityGraphOccurrenceKind.EDGE
            else occurrence
            for occurrence in fallback_graphs.retained_occurrences
        ],
        key=lambda item: (item.subject_kind.value, item.subject_sha256),
    )
    forged_graphs = SolidityGraphSet.model_validate(forged_graph_payload)
    persisted_index = forged_index.model_dump(mode="json")
    persisted_graphs = forged_graphs.model_dump(mode="json")
    forged_suite = discover_invariants(
        discovery,
        forged_index,
        forged_graphs,
        InvariantConfig(enabled=False),
    )
    assert forged_index.model_dump(mode="json") == persisted_index
    assert forged_graphs.model_dump(mode="json") == persisted_graphs
    assert all(entity.provenance is SolidityProvenance.COMPILER for entity in forged_index.entities)
    assert forged_suite.protocol_profile_assessment is not None
    assert not forged_suite.protocol_profile_assessment.classification_complete
    assert all(
        item.status is not ProtocolProfileStatus.NOT_DETECTED
        for item in forged_suite.protocol_profile_assessment.classifications
    )
    assert forged_suite.protocol_profile_assessment == fallback_suite.protocol_profile_assessment
    assert (
        forged_suite.protocol_profile_assessment.input_sha256
        == fallback_suite.protocol_profile_assessment.input_sha256
    )
    assert (
        validate_protocol_profile_replay(
            discovery,
            forged_index,
            forged_graphs,
            forged_suite,
        )
        == forged_suite.protocol_profile_assessment
    )


def test_profile_replay_rejects_source_unbacked_profile_entity_addition() -> None:
    path = "src/PartialToken.sol"
    source = (
        "contract Token {\nfunction balanceOf() external {}\nfunction transfer() external {}\n}\n"
    )
    source_bytes = source.encode("utf-8")
    discovery = DiscoveryResult(
        root=Path("/synthetic/source-unbacked-entity-test"),
        files=(
            DiscoveredFile(
                absolute_path=Path("/synthetic/source-unbacked-entity-test") / path,
                relative_path=path,
                content=source,
                size=len(source_bytes),
                lines=len(source.splitlines()),
                sha256=hashlib.sha256(source_bytes).hexdigest(),
                language="Solidity",
                categories=("smart_contract",),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    source_build = build_solidity_index(discovery, [], [])
    retained_entities = [
        entity.model_copy(
            update={
                "provenance": SolidityProvenance.COMPILER,
                "confidence": 0.95,
                "transformation": "synthetic_compiler_ast",
            }
        )
        for entity in source_build.index.entities
    ]
    forged_entity = SolidityEntity(
        id="compiler-forged-total-supply",
        kind=SolidityEntityKind.FUNCTION,
        name="totalSupply",
        contract_name="Token",
        path=path,
        start_line=1,
        end_line=1,
        byte_start=0,
        byte_end=len(b"contract Token {\n"),
        source_hash=line_range_hash(source, 1, 1),
        provenance=SolidityProvenance.COMPILER,
        confidence=0.95,
        transformation="synthetic_forged_compiler_ast",
        visibility="external",
        signature="totalSupply()",
    )
    forged_index = SoliditySymbolIndex(
        projects=[],
        entities=[*retained_entities, forged_entity],
        ast_sources=[path],
    )
    forged_graphs = build_solidity_graphs(
        discovery,
        SolidityIndexBuild(index=forged_index, ast_documents=[]),
    )
    forged_suite = discover_invariants(
        discovery,
        forged_index,
        forged_graphs,
        InvariantConfig(enabled=False),
    )
    assert forged_suite.protocol_profile_assessment is not None
    assert ProtocolProfileKind.ERC20_TOKEN in (
        forged_suite.protocol_profile_assessment.detected_profiles
    )

    with pytest.raises(ValueError, match="adds profile entities not declared by source"):
        validate_protocol_profile_replay(
            discovery,
            forged_index,
            forged_graphs,
            forged_suite,
        )


def test_profile_replay_rejects_source_unbacked_profile_graph_edge_addition() -> None:
    path = "src/Plain.sol"
    source = "contract Plain {\nfunction read() external {}\n}\n"
    source_bytes = source.encode("utf-8")
    discovery = DiscoveryResult(
        root=Path("/synthetic/source-unbacked-graph-test"),
        files=(
            DiscoveredFile(
                absolute_path=Path("/synthetic/source-unbacked-graph-test") / path,
                relative_path=path,
                content=source,
                size=len(source_bytes),
                lines=len(source.splitlines()),
                sha256=hashlib.sha256(source_bytes).hexdigest(),
                language="Solidity",
                categories=("smart_contract",),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    source_build = build_solidity_index(discovery, [], [])
    retained_index = SoliditySymbolIndex(
        projects=[],
        entities=[
            entity.model_copy(
                update={
                    "provenance": SolidityProvenance.COMPILER,
                    "confidence": 0.95,
                    "transformation": "synthetic_compiler_ast",
                }
            )
            for entity in source_build.index.entities
        ],
        ast_sources=[path],
    )
    retained_build = SolidityIndexBuild(index=retained_index, ast_documents=[])
    base_graphs = build_solidity_graphs(discovery, retained_build)
    read_entity = next(entity for entity in retained_index.entities if entity.name == "read")
    forged_node = SolidityGraphNode(
        id="compiler-forged-oracle-target",
        kind=SolidityGraphNodeKind.ORACLE,
        label="forgedFeed.latestRoundData",
        path=path,
        start_line=2,
        end_line=2,
        source_hash=line_range_hash(source, 2, 2),
        provenance=SolidityProvenance.COMPILER,
        confidence=0.95,
        transformation="synthetic_forged_compiler_oracle_node",
    )
    forged_edge = SolidityGraphEdge(
        graph=SolidityGraphKind.ORACLE_DEPENDENCY,
        source_id=read_entity.id,
        target_id=forged_node.id,
        label="depends on oracle/source forgedFeed.latestRoundData",
        provenance=SolidityProvenance.COMPILER,
        path=path,
        start_line=2,
        end_line=2,
        source_hash=line_range_hash(source, 2, 2),
        confidence=0.95,
        transformation="synthetic_forged_compiler_oracle_edge",
        metadata={"occurrence_relative_start": 0},
    )
    added_occurrences = [
        SolidityGraphRetainedOccurrence(
            subject_kind=kind,
            subject_sha256=solidity_graph_occurrence_sha256(kind, subject),
            occurrence_count=1,
        )
        for kind, subject in (
            (SolidityGraphOccurrenceKind.GRAPH_NODE, forged_node),
            (SolidityGraphOccurrenceKind.EDGE, forged_edge),
        )
    ]
    forged_graph_payload = base_graphs.model_dump(mode="python")
    forged_graph_payload["nodes"] = [*base_graphs.nodes, forged_node]
    forged_graph_payload["edges"] = [*base_graphs.edges, forged_edge]
    forged_graph_payload["retained_occurrences"] = sorted(
        [*base_graphs.retained_occurrences, *added_occurrences],
        key=lambda item: (item.subject_kind.value, item.subject_sha256),
    )
    forged_graph_payload["coverage"] = {
        **base_graphs.coverage,
        SolidityGraphKind.ORACLE_DEPENDENCY.value: 1,
    }
    forged_graphs = SolidityGraphSet.model_validate(forged_graph_payload)
    forged_suite = discover_invariants(
        discovery,
        retained_index,
        forged_graphs,
        InvariantConfig(enabled=False),
    )
    assert forged_suite.protocol_profile_assessment is not None
    assert ProtocolProfileKind.ORACLE_CONSUMER in (
        forged_suite.protocol_profile_assessment.detected_profiles
    )

    with pytest.raises(ValueError, match="adds profile edges unsupported by source"):
        validate_protocol_profile_replay(
            discovery,
            retained_index,
            forged_graphs,
            forged_suite,
        )


@pytest.mark.parametrize(
    ("call", "target_label", "member"),
    (
        ("feed.latestAnswer()", "feed", "latestAnswer"),
        ("IOracle(feed).customRead()", "IOracle(feed)", "customRead"),
    ),
)
def test_profile_replay_accepts_source_backed_compiler_only_profile_graph_edge(
    call: str,
    target_label: str,
    member: str,
) -> None:
    path = "src/CompilerOracle.sol"
    source = f"contract Consumer {{\nfunction read() external {{ {call}; }}\n}}\n"
    source_bytes = source.encode("utf-8")
    discovery = DiscoveryResult(
        root=Path("/synthetic/compiler-only-profile-graph-test"),
        files=(
            DiscoveredFile(
                absolute_path=Path("/synthetic/compiler-only-profile-graph-test") / path,
                relative_path=path,
                content=source,
                size=len(source_bytes),
                lines=len(source.splitlines()),
                sha256=hashlib.sha256(source_bytes).hexdigest(),
                language="Solidity",
                categories=("smart_contract", "evm_oracle"),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    source_build = build_solidity_index(discovery, [], [])
    fallback_graphs = build_solidity_graphs(discovery, source_build)
    fallback_suite = discover_invariants(
        discovery,
        source_build.index,
        fallback_graphs,
        InvariantConfig(enabled=False),
    )
    assert fallback_suite.protocol_profile_assessment is not None
    assert ProtocolProfileKind.ORACLE_CONSUMER in (
        fallback_suite.protocol_profile_assessment.detected_profiles
    )
    assert (
        validate_protocol_profile_replay(
            discovery,
            source_build.index,
            fallback_graphs,
            fallback_suite,
        )
        == fallback_suite.protocol_profile_assessment
    )
    retained_index = SoliditySymbolIndex(
        projects=[],
        entities=[
            entity.model_copy(
                update={
                    "provenance": SolidityProvenance.COMPILER,
                    "confidence": 0.95,
                    "transformation": "synthetic_compiler_ast",
                }
            )
            for entity in source_build.index.entities
        ],
        ast_sources=[path],
    )
    base_graphs = build_solidity_graphs(
        discovery,
        SolidityIndexBuild(index=retained_index, ast_documents=[]),
    )
    fallback_oracle_edges = [
        edge for edge in base_graphs.edges if edge.graph is SolidityGraphKind.ORACLE_DEPENDENCY
    ]
    assert len(fallback_oracle_edges) == 1
    fallback_oracle_edge = fallback_oracle_edges[0]
    read_entity = next(entity for entity in retained_index.entities if entity.name == "read")
    compiler_node = SolidityGraphNode(
        id="compiler-oracle-target",
        kind=SolidityGraphNodeKind.ORACLE,
        label=f"{target_label}.{member}",
        path=path,
        start_line=2,
        end_line=2,
        source_hash=line_range_hash(source, 2, 2),
        provenance=SolidityProvenance.COMPILER,
        confidence=0.95,
        transformation="known_oracle_interface_call.target_node",
    )
    compiler_edge = SolidityGraphEdge(
        graph=SolidityGraphKind.ORACLE_DEPENDENCY,
        source_id=read_entity.id,
        target_id=compiler_node.id,
        label=f"depends on oracle/source {target_label}.{member}",
        provenance=SolidityProvenance.COMPILER,
        path=path,
        start_line=2,
        end_line=2,
        source_hash=line_range_hash(source, 2, 2),
        confidence=0.95,
        transformation="known_oracle_interface_call",
    )
    added_occurrences = [
        SolidityGraphRetainedOccurrence(
            subject_kind=kind,
            subject_sha256=solidity_graph_occurrence_sha256(kind, subject),
            occurrence_count=1,
        )
        for kind, subject in (
            (SolidityGraphOccurrenceKind.GRAPH_NODE, compiler_node),
            (SolidityGraphOccurrenceKind.EDGE, compiler_edge),
        )
    ]
    supplemented_payload = base_graphs.model_dump(mode="python")
    supplemented_payload["nodes"] = [*base_graphs.nodes, compiler_node]
    supplemented_payload["edges"] = [*base_graphs.edges, compiler_edge]
    supplemented_payload["retained_occurrences"] = sorted(
        [*base_graphs.retained_occurrences, *added_occurrences],
        key=lambda item: (item.subject_kind.value, item.subject_sha256),
    )
    supplemented_payload["coverage"] = {
        **base_graphs.coverage,
        SolidityGraphKind.ORACLE_DEPENDENCY.value: 2,
    }
    supplemented_graphs = SolidityGraphSet.model_validate(supplemented_payload)
    supplemented_suite = discover_invariants(
        discovery,
        retained_index,
        supplemented_graphs,
        InvariantConfig(enabled=False),
    )
    assert (
        validate_protocol_profile_replay(
            discovery,
            retained_index,
            supplemented_graphs,
            supplemented_suite,
        )
        == supplemented_suite.protocol_profile_assessment
    )

    graph_payload = base_graphs.model_dump(mode="python")
    graph_payload["nodes"] = [*base_graphs.nodes, compiler_node]
    graph_payload["edges"] = [
        *(edge for edge in base_graphs.edges if edge != fallback_oracle_edge),
        compiler_edge,
    ]
    fallback_edge_hash = solidity_graph_occurrence_sha256(
        SolidityGraphOccurrenceKind.EDGE,
        fallback_oracle_edge,
    )
    graph_payload["retained_occurrences"] = sorted(
        [
            *(
                occurrence
                for occurrence in base_graphs.retained_occurrences
                if occurrence.subject_sha256 != fallback_edge_hash
            ),
            *added_occurrences,
        ],
        key=lambda item: (item.subject_kind.value, item.subject_sha256),
    )
    graph_payload["coverage"] = {
        **base_graphs.coverage,
        SolidityGraphKind.ORACLE_DEPENDENCY.value: 1,
    }
    compiler_graphs = SolidityGraphSet.model_validate(graph_payload)
    suite = discover_invariants(
        discovery,
        retained_index,
        compiler_graphs,
        InvariantConfig(enabled=False),
    )
    assessment = suite.protocol_profile_assessment

    assert assessment is not None
    assert ProtocolProfileKind.ORACLE_CONSUMER in assessment.detected_profiles
    assert (
        validate_protocol_profile_replay(
            discovery,
            retained_index,
            compiler_graphs,
            suite,
        )
        == assessment
    )

    removed_hashes = {
        solidity_graph_occurrence_sha256(kind, subject)
        for kind, subject in (
            (SolidityGraphOccurrenceKind.GRAPH_NODE, compiler_node),
            (SolidityGraphOccurrenceKind.EDGE, compiler_edge),
        )
    }
    forged_payload = compiler_graphs.model_dump(mode="python")
    forged_payload["nodes"] = [
        node for node in compiler_graphs.nodes if node.id != compiler_node.id
    ]
    forged_payload["edges"] = [edge for edge in compiler_graphs.edges if edge != compiler_edge]
    forged_payload["retained_occurrences"] = [
        occurrence
        for occurrence in compiler_graphs.retained_occurrences
        if occurrence.subject_sha256 not in removed_hashes
    ]
    forged_payload["coverage"] = {
        **compiler_graphs.coverage,
        SolidityGraphKind.ORACLE_DEPENDENCY.value: 0,
    }
    forged_graphs = SolidityGraphSet.model_validate(forged_payload)
    forged_assessment = detect_protocol_profiles(
        retained_index,
        forged_graphs,
        {path: source},
    )
    forged_by_profile = {item.profile: item for item in forged_assessment.classifications}
    assert forged_by_profile[ProtocolProfileKind.ORACLE_CONSUMER].status is (
        ProtocolProfileStatus.INDETERMINATE
    )
    forged_suite = InvariantSuite(
        protocol_profiles=[profile.value for profile in forged_assessment.detected_profiles],
        protocol_profile_assessment=forged_assessment,
    )

    with pytest.raises(ValueError, match="omit source-rebuilt profile edges"):
        validate_protocol_profile_replay(
            discovery,
            retained_index,
            forged_graphs,
            forged_suite,
        )


def test_profile_replay_accepts_compiler_and_source_edges_for_one_lexical_signal() -> None:
    path = "src/CompilerAndSourceOracle.sol"
    source = (
        "contract Consumer {\n"
        "    function read() external {\n"
        "        feed.latestRoundData();\n"
        "    }\n"
        "}\n"
    )
    source_bytes = source.encode("utf-8")
    discovery = DiscoveryResult(
        root=Path("/synthetic/compiler-and-source-profile-graph-test"),
        files=(
            DiscoveredFile(
                absolute_path=(Path("/synthetic/compiler-and-source-profile-graph-test") / path),
                relative_path=path,
                content=source,
                size=len(source_bytes),
                lines=len(source.splitlines()),
                sha256=hashlib.sha256(source_bytes).hexdigest(),
                language="Solidity",
                categories=("smart_contract", "evm_oracle"),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    fallback = build_solidity_index(discovery, [], [])
    compiler_index = SoliditySymbolIndex(
        projects=[],
        entities=[
            entity.model_copy(
                update={
                    "provenance": SolidityProvenance.COMPILER,
                    "confidence": 0.95,
                    "transformation": "synthetic_compiler_ast",
                }
            )
            for entity in fallback.index.entities
        ],
        ast_sources=[path],
    )
    contract = next(
        entity for entity in compiler_index.entities if entity.kind is SolidityEntityKind.CONTRACT
    )
    function = next(
        entity for entity in compiler_index.entities if entity.kind is SolidityEntityKind.FUNCTION
    )
    function_start = source.index("function")
    call_start = source.index("feed")
    body_start = source.index("{", function_start)
    ast = {
        "nodes": [
            {
                "nodeType": "ContractDefinition",
                "id": 1,
                "name": "Consumer",
                "baseContracts": [],
                "src": f"0:{len(source_bytes) - 1}:0",
                "nodes": [
                    {
                        "nodeType": "FunctionDefinition",
                        "id": 2,
                        "name": "read",
                        "kind": "function",
                        "src": f"{function_start}:{len(source_bytes) - function_start - 3}:0",
                        "modifiers": [],
                        "body": {
                            "nodeType": "Block",
                            "src": f"{body_start}:{len(source_bytes) - body_start - 5}:0",
                            "statements": [
                                {
                                    "nodeType": "ExpressionStatement",
                                    "src": f"{call_start}:23:0",
                                    "expression": {
                                        "nodeType": "FunctionCall",
                                        "src": f"{call_start}:22:0",
                                        "expression": {
                                            "nodeType": "MemberAccess",
                                            "memberName": "latestRoundData",
                                            "src": f"{call_start}:20:0",
                                            "expression": {
                                                "nodeType": "Identifier",
                                                "name": "feed",
                                                "src": f"{call_start}:4:0",
                                            },
                                        },
                                    },
                                }
                            ],
                        },
                    }
                ],
            }
        ]
    }
    build = SolidityIndexBuild(
        index=compiler_index,
        ast_documents=[AstDocument(source_path=path, ast=ast)],
        ast_entity_ids={(path, 1): contract.id, (path, 2): function.id},
        contract_entity_by_name={"Consumer": contract.id},
        function_entity_by_contract_name={("Consumer", "read"): function.id},
    )
    graphs = build_solidity_graphs(discovery, build)
    oracle_edges = [
        edge for edge in graphs.edges if edge.graph is SolidityGraphKind.ORACLE_DEPENDENCY
    ]
    assert len(oracle_edges) == 2
    assert {edge.provenance for edge in oracle_edges} == {
        SolidityProvenance.COMPILER,
        SolidityProvenance.HEURISTIC,
    }
    assert {(edge.path, edge.start_line, edge.metadata.get("member")) for edge in oracle_edges} == {
        (path, 3, "latestRoundData")
    }
    suite = discover_invariants(
        discovery,
        compiler_index,
        graphs,
        InvariantConfig(enabled=False),
    )

    assert (
        validate_protocol_profile_replay(
            discovery,
            compiler_index,
            graphs,
            suite,
        )
        == suite.protocol_profile_assessment
    )


def test_profile_replay_requires_typed_coverage_for_omitted_profile_edges() -> None:
    path = "src/Consumer.sol"
    source = (
        "contract Consumer {\n"
        "function read() external { feed.latestRoundData(); feed.latestRoundData(); }\n"
        "}\n"
    )
    source_bytes = source.encode("utf-8")
    discovery = DiscoveryResult(
        root=Path("/synthetic/source-rebuilt-graph-test"),
        files=(
            DiscoveredFile(
                absolute_path=Path("/synthetic/source-rebuilt-graph-test") / path,
                relative_path=path,
                content=source,
                size=len(source_bytes),
                lines=len(source.splitlines()),
                sha256=hashlib.sha256(source_bytes).hexdigest(),
                language="Solidity",
                categories=("smart_contract", "evm_oracle"),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    source_build = build_solidity_index(discovery, [], [])
    retained_index = SoliditySymbolIndex(
        projects=[],
        entities=[
            entity.model_copy(
                update={
                    "provenance": SolidityProvenance.COMPILER,
                    "confidence": 0.95,
                    "transformation": "synthetic_compiler_ast",
                }
            )
            for entity in source_build.index.entities
        ],
        ast_sources=[path],
    )
    graphs = build_solidity_graphs(discovery, source_build)
    oracle_edges = [
        edge for edge in graphs.edges if edge.graph is SolidityGraphKind.ORACLE_DEPENDENCY
    ]
    assert oracle_edges
    removed_hashes = {
        solidity_graph_occurrence_sha256(SolidityGraphOccurrenceKind.EDGE, edge)
        for edge in oracle_edges
    }
    forged_graph_payload = graphs.model_dump(mode="python")
    forged_graph_payload["edges"] = [
        edge for edge in graphs.edges if edge.graph is not SolidityGraphKind.ORACLE_DEPENDENCY
    ]
    forged_graph_payload["retained_occurrences"] = [
        occurrence
        for occurrence in graphs.retained_occurrences
        if not (
            occurrence.subject_kind is SolidityGraphOccurrenceKind.EDGE
            and occurrence.subject_sha256 in removed_hashes
        )
    ]
    forged_graph_payload["analyzed_graphs"] = [
        kind for kind in graphs.analyzed_graphs if kind is not SolidityGraphKind.ORACLE_DEPENDENCY
    ]
    forged_graph_payload["coverage"] = {
        **graphs.coverage,
        SolidityGraphKind.ORACLE_DEPENDENCY.value: 0,
    }
    forged_graphs = SolidityGraphSet.model_validate(forged_graph_payload)
    forged_assessment = detect_protocol_profiles(
        retained_index,
        forged_graphs,
        {path: source},
    )
    forged_by_profile = {item.profile: item for item in forged_assessment.classifications}
    assert forged_by_profile[ProtocolProfileKind.ORACLE_CONSUMER].status is (
        ProtocolProfileStatus.INDETERMINATE
    )
    forged_suite = InvariantSuite(
        protocol_profiles=[profile.value for profile in forged_assessment.detected_profiles],
        protocol_profile_assessment=forged_assessment,
    )

    with pytest.raises(ValueError, match="omit source-rebuilt profile edges"):
        validate_protocol_profile_replay(
            discovery,
            retained_index,
            forged_graphs,
            forged_suite,
        )

    omitted_occurrence_count = sum(
        occurrence.occurrence_count
        for occurrence in graphs.retained_occurrences
        if occurrence.subject_kind is SolidityGraphOccurrenceKind.EDGE
        and occurrence.subject_sha256 in removed_hashes
    )
    assert omitted_occurrence_count == 2
    occurrence_counts = {
        occurrence.subject_sha256: occurrence.occurrence_count
        for occurrence in graphs.retained_occurrences
        if occurrence.subject_kind is SolidityGraphOccurrenceKind.EDGE
    }
    omitted_candidate_bytes = sorted(
        encoded
        for edge in oracle_edges
        for encoded in (
            json.dumps(
                edge.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8"),
        )
        for _ in range(
            occurrence_counts[
                solidity_graph_occurrence_sha256(SolidityGraphOccurrenceKind.EDGE, edge)
            ]
        )
    )
    assert len(omitted_candidate_bytes) == omitted_occurrence_count

    def partial_graphs_with_omission(
        graph_kind: SolidityGraphKind,
        omitted_count: int,
        *,
        analytical: bool = False,
    ) -> SolidityGraphSet:
        selected_bytes = omitted_candidate_bytes[:omitted_count]
        selected_digests = [hashlib.sha256(encoded).hexdigest() for encoded in selected_bytes]
        digest_integers = [int(digest, 16) for digest in selected_digests]
        digest_xor = 0
        for digest_integer in digest_integers:
            digest_xor ^= digest_integer
        digest_sum = sum(digest_integers) % (1 << 256)
        analytical_digest = hashlib.sha256(b"synthetic analytical population").hexdigest()
        analytical_integer = int(analytical_digest, 16) if analytical else 0
        commitment_payload = (
            f"{omitted_count}:{0 if analytical else digest_xor:064x}:"
            f"{0 if analytical else digest_sum:064x}:"
            f"{analytical_integer:064x}:{analytical_integer:064x}"
        )
        omission = SolidityGraphOmission.build(
            graph=graph_kind,
            candidate_count=omitted_count,
            retained_count=0,
            retained_occurrence_count=0,
            omitted_count=omitted_count,
            omitted_canonical_bytes=(0 if analytical else sum(map(len, selected_bytes))),
            analytical_omitted_count=(omitted_count if analytical else 0),
            analytical_population_sample_sha256s=((analytical_digest,) if analytical else ()),
            omitted_stream_sha256=hashlib.sha256(commitment_payload.encode("ascii")).hexdigest(),
            omitted_sample_sha256s=(() if analytical else tuple(sorted(set(selected_digests)))),
        )
        partial_graph_payload = forged_graphs.model_dump(mode="python")
        partial_graph_payload.update(
            {
                "generation_complete": False,
                "analyzed_graphs": [
                    kind for kind in forged_graphs.analyzed_graphs if kind is not graph_kind
                ],
                "edge_omissions": (omission,),
            }
        )
        return SolidityGraphSet.model_validate(partial_graph_payload)

    for partial_graphs in (
        partial_graphs_with_omission(SolidityGraphKind.PROXY, omitted_occurrence_count),
        partial_graphs_with_omission(
            SolidityGraphKind.ORACLE_DEPENDENCY,
            omitted_occurrence_count - 1,
        ),
        partial_graphs_with_omission(
            SolidityGraphKind.ORACLE_DEPENDENCY,
            omitted_occurrence_count,
            analytical=True,
        ),
    ):
        insufficient_suite = discover_invariants(
            discovery,
            retained_index,
            partial_graphs,
            InvariantConfig(enabled=False),
        )
        with pytest.raises(ValueError, match="omit source-rebuilt profile edges"):
            validate_protocol_profile_replay(
                discovery,
                retained_index,
                partial_graphs,
                insufficient_suite,
            )

    partial_graphs = partial_graphs_with_omission(
        SolidityGraphKind.ORACLE_DEPENDENCY,
        omitted_occurrence_count,
    )
    partial_suite = discover_invariants(
        discovery,
        retained_index,
        partial_graphs,
        InvariantConfig(enabled=False),
    )
    assert partial_suite.protocol_profile_assessment is not None
    partial_by_profile = {
        item.profile: item for item in partial_suite.protocol_profile_assessment.classifications
    }
    assert partial_by_profile[ProtocolProfileKind.ORACLE_CONSUMER].status is (
        ProtocolProfileStatus.INDETERMINATE
    )
    assert (
        validate_protocol_profile_replay(
            discovery,
            retained_index,
            partial_graphs,
            partial_suite,
        )
        == partial_suite.protocol_profile_assessment
    )


def test_detached_replay_rejects_artifact_forged_ignore_rule_and_source_omission(
    tmp_path: Path,
    config_factory: Any,
) -> None:
    import mmaudit.orchestration.verification as verification_module
    from mmaudit.language_plugins import (
        assess_language_capability,
        build_language_capability_artifact,
    )
    from mmaudit.models.schemas import LanguageCapabilityProfile
    from mmaudit.repository.discovery import discover_repository
    from mmaudit.repository.ignore import IgnoreMatcher
    from mmaudit.solidity.projects import discover_solidity_projects

    repository = tmp_path / "repository"
    source_dir = repository / "src"
    source_dir.mkdir(parents=True)
    (source_dir / "Visible.sol").write_text("contract Visible {}\n", encoding="utf-8")
    (source_dir / "Hidden.sol").write_text(
        "contract Hidden { function totalSupply() external {} }\n",
        encoding="utf-8",
    )
    run_dir = tmp_path / "run" / "forged-ignore-run"
    run_dir.mkdir(parents=True)
    config = config_factory(language_profile=LanguageCapabilityProfile.SOLIDITY_EVM)
    forged_matcher = IgnoreMatcher(["/src/Hidden.sol"])
    forged_discovery = discover_repository(
        repository,
        config.repository,
        forged_matcher,
    )
    assert {item.relative_path for item in forged_discovery.files} == {"src/Visible.sol"}
    projects = discover_solidity_projects(forged_discovery, config.smart_contracts)
    capability = assess_language_capability(
        config.language_profile,
        forged_discovery,
        solidity_projects=projects,
        smart_contracts_enabled=config.smart_contracts.enabled,
    )
    forged_artifact = build_language_capability_artifact(
        capability,
        forged_discovery,
        effective_ignore_rules=forged_matcher.rules,
        runtime_output_exclusion_root=None,
    )

    with pytest.raises(ValueError, match="ignore rules differ from effective configuration"):
        verification_module._reconstruct_current_discovery(
            artifact=forged_artifact,
            run_dir=run_dir,
            repository_root=repository,
            configuration_root=repository,
            config=config,
            changed_since=None,
        )


def test_detached_verification_rejects_resealed_profile_and_taxonomy_forgery(
    tmp_path: Path,
    config_factory: Any,
) -> None:
    import mmaudit.orchestration.manifest as manifest_module
    from mmaudit.models.schemas import AuditReport, LanguageCapabilityProfile, RepositoryFile
    from mmaudit.orchestration.manifest import (
        ManifestFileBinding,
        RunEvidenceManifest,
        build_run_evidence_manifest,
        canonical_sha256,
        collect_run_artifacts,
        seal_run_evidence_manifest,
        write_run_evidence_manifest,
    )
    from mmaudit.orchestration.verification import (
        RunVerificationCategory,
        RunVerificationMismatchKind,
        RunVerificationStatus,
        verify_run_evidence,
    )
    from mmaudit.reporting.json_report import write_json
    from mmaudit.reporting.status import effective_report_status
    from mmaudit.solidity.properties import build_property_corpus
    from tests.unit import test_manifest as manifest_support

    config = config_factory(language_profile=LanguageCapabilityProfile.SOLIDITY_EVM)
    repository, run_dir, original_manifest, base_report = manifest_support._write_verifiable_run(
        tmp_path, config
    )
    profile_source = (
        "contract A {\n"
        "function totalSupply() external {}\n"
        "function balanceOf() external {}\n"
        "function transfer() external {}\n"
        "}\n"
    )
    source_path = repository / "src" / "Vault.sol"
    source_path.write_text(profile_source, encoding="utf-8")
    source_bytes = profile_source.encode("utf-8")
    discovery = DiscoveryResult(
        root=repository,
        files=(
            DiscoveredFile(
                absolute_path=source_path,
                relative_path="src/Vault.sol",
                content=profile_source,
                size=len(source_bytes),
                lines=len(profile_source.splitlines()),
                sha256=hashlib.sha256(source_bytes).hexdigest(),
                language="Solidity",
                categories=("smart_contract",),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    source_build = build_solidity_index(discovery, [], [])
    index = source_build.index
    legitimate_suite = discover_invariants(
        discovery,
        index,
        None,
        InvariantConfig(enabled=False),
    )
    assert legitimate_suite.protocol_profile_assessment is not None
    assert ProtocolProfileKind.ERC20_TOKEN in (
        legitimate_suite.protocol_profile_assessment.detected_profiles
    )
    property_corpus = build_property_corpus(legitimate_suite, index, [])

    repository_map = base_report.repository.model_copy(
        update={
            "root_name": repository.name,
            "files": [
                RepositoryFile(
                    path="src/Vault.sol",
                    size=len(source_bytes),
                    lines=len(profile_source.splitlines()),
                    sha256=hashlib.sha256(source_bytes).hexdigest(),
                    language="Solidity",
                )
            ],
        }
    )
    base_report = manifest_support._with_repository_capability(
        base_report,
        repository_map,
        config,
    )
    metadata = dict(base_report.metadata)
    solidity_metadata = dict(metadata["solidity"])
    solidity_metadata["index_summary"] = {
        "entities": len(index.entities),
        "ast_sources": len(index.ast_sources),
        "fallback_sources": len(index.fallback_sources),
    }
    solidity_metadata["property_corpus_summary"] = {
        "properties": len(property_corpus.properties),
        "limitations": len(property_corpus.limitations),
        "corpus_hash": property_corpus.corpus_hash,
    }
    metadata["solidity"] = solidity_metadata

    def report_for_suite(suite: InvariantSuite) -> AuditReport:
        coverage = build_known_issue_taxonomy_coverage(
            load_known_issue_taxonomy(),
            invariants=suite,
            model_review_coverage=None,
        )
        quality_gates = [
            (
                known_issue_taxonomy_quality_gate(coverage, required=False)
                if gate.gate == "known_issue_taxonomy_critical_disposition"
                else gate
            )
            for gate in base_report.quality_gates
        ]
        candidate = base_report.model_copy(
            update={
                "invariants": suite,
                "taxonomy_coverage": coverage,
                "quality_gates": quality_gates,
                "metadata": metadata,
            }
        )
        return AuditReport.model_validate(candidate.model_dump(mode="python"))

    def write_and_reseal(
        report: AuditReport,
        prior_manifest: RunEvidenceManifest,
    ) -> RunEvidenceManifest:
        manifest_path = run_dir / "run-evidence-manifest.json"
        manifest_path.unlink(missing_ok=True)
        manifest_support._write_required_artifacts(run_dir, report)
        write_json(
            run_dir / "solidity-index.json",
            {"schema_version": "1.0", "index": index.model_dump(mode="json")},
        )
        property_corpus_payload = {
            "schema_version": "1.0",
            "corpus": property_corpus.model_dump(mode="json"),
        }
        write_json(run_dir / "property-corpus.json", property_corpus_payload)
        status_projection = effective_report_status(report)
        taxonomy_bindings = {
            binding.identifier: binding
            for binding in manifest_module._known_issue_taxonomy_bindings(report)
        }
        coverage_bindings = []
        for binding in prior_manifest.bindings.coverage:
            replacement = taxonomy_bindings.get(binding.identifier)
            if replacement is not None:
                coverage_bindings.append(replacement)
            elif binding.identifier == "quality-gates/report":
                coverage_bindings.append(
                    binding.model_copy(
                        update={
                            "sha256": canonical_sha256(
                                [
                                    gate.model_dump(mode="json")
                                    for gate in status_projection.quality_gates
                                ]
                            )
                        }
                    )
                )
            elif binding.identifier == "report-status/projection":
                coverage_bindings.append(
                    binding.model_copy(
                        update={
                            "sha256": canonical_sha256(status_projection.model_dump(mode="json"))
                        }
                    )
                )
            else:
                coverage_bindings.append(binding)
        bindings = prior_manifest.bindings.model_copy(
            update={
                "coverage": sorted(
                    coverage_bindings,
                    key=lambda item: item.identifier,
                ),
                "corpora": manifest_module._corpus_bindings(property_corpus_payload),
            }
        )
        sources = [
            ManifestFileBinding(path=item.path, sha256=item.sha256, size=item.size)
            for item in report.repository.files
        ]
        assert prior_manifest.run_configuration is not None
        resealed = seal_run_evidence_manifest(
            run_id=prior_manifest.run_id,
            repository_root_name=report.repository.root_name,
            git_commit=report.repository.git_commit,
            sources=sources,
            run_configuration=prior_manifest.run_configuration,
            bindings=bindings,
            artifacts=collect_run_artifacts(run_dir),
            tool_version=prior_manifest.tool_version,
        )
        write_run_evidence_manifest(manifest_path, resealed)
        return resealed

    legitimate_report = report_for_suite(legitimate_suite)
    legitimate_manifest = write_and_reseal(legitimate_report, original_manifest)
    assert legitimate_manifest.run_configuration is not None
    with pytest.raises(
        ValueError,
        match="current protocol-profile assessment lacks scoped source replay authority",
    ):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=legitimate_report,
            config=config,
            run_options=legitimate_manifest.run_configuration.run_options,
        )
    issued = build_run_evidence_manifest(
        run_dir=run_dir,
        report=legitimate_report,
        config=config,
        run_options=legitimate_manifest.run_configuration.run_options,
        protocol_profile_replay_discovery=discovery,
    )
    assert issued.bindings.coverage == legitimate_manifest.bindings.coverage
    current = verify_run_evidence(
        manifest_path=run_dir / "run-evidence-manifest.json",
        run_dir=run_dir,
        repository_root=repository,
        configuration_root=repository,
        config=config,
    )
    assert current.status is RunVerificationStatus.CURRENT, [
        (item.category.value, item.identifier, item.kind.value) for item in current.mismatches
    ]

    forged_assessment = _forge_profile_as_not_detected(
        legitimate_suite.protocol_profile_assessment,
        ProtocolProfileKind.ERC20_TOKEN,
    )
    forged_payload = legitimate_suite.model_dump(mode="json")
    forged_payload["protocol_profile_assessment"] = forged_assessment.model_dump(mode="json")
    forged_payload["protocol_profiles"] = [
        profile.value for profile in forged_assessment.detected_profiles
    ]
    forged_suite = InvariantSuite.model_validate(forged_payload)
    forged_report = report_for_suite(forged_suite)
    forged_manifest = write_and_reseal(forged_report, legitimate_manifest)

    legitimate_artifacts = {item.path: item for item in legitimate_manifest.artifacts}
    forged_artifacts = {item.path: item for item in forged_manifest.artifacts}
    assert forged_report.taxonomy_coverage is not None
    assert legitimate_report.taxonomy_coverage is not None
    assert (
        forged_report.taxonomy_coverage.coverage_sha256
        != legitimate_report.taxonomy_coverage.coverage_sha256
    )
    assert (
        forged_artifacts["final-findings.json"].sha256
        != legitimate_artifacts["final-findings.json"].sha256
    )
    stale = verify_run_evidence(
        manifest_path=run_dir / "run-evidence-manifest.json",
        run_dir=run_dir,
        repository_root=repository,
        configuration_root=repository,
        config=config,
    )

    assert stale.status is RunVerificationStatus.STALE
    assert any(
        mismatch.category is RunVerificationCategory.ARTIFACT
        and mismatch.identifier == "protocol-profile/source-replay"
        and mismatch.kind is RunVerificationMismatchKind.UNVERIFIABLE
        for mismatch in stale.mismatches
    )
