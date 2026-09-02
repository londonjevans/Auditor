"""Source-linked deterministic invariant discovery for Solidity projects."""

from __future__ import annotations

import hashlib
import json
import re
from bisect import bisect_right
from collections.abc import Iterable

from mmaudit.config import InvariantConfig
from mmaudit.models.schemas import (
    AnalysisState,
    InvariantCategory,
    InvariantSpec,
    InvariantSuite,
    InvariantTemplate,
    Location,
    ProtocolProfileAssessment,
    ProtocolProfileDetectionRule,
    ProtocolProfileEvidence,
    ProtocolProfileKind,
    ProtocolProfileStatus,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphKind,
    SolidityGraphOccurrenceKind,
    SolidityGraphSet,
    SolidityProvenance,
    SoliditySymbolIndex,
    solidity_graph_occurrence_sha256,
)
from mmaudit.repository.chunking import line_range_hash
from mmaudit.repository.discovery import DiscoveryResult
from mmaudit.solidity.index import build_solidity_index


def discover_invariants(
    discovery: DiscoveryResult,
    index: SoliditySymbolIndex | None,
    graphs: SolidityGraphSet | None,
    config: InvariantConfig,
) -> InvariantSuite:
    """Infer bounded, reviewable invariants without claiming protocol intent."""

    if index is None:
        return InvariantSuite(
            warnings=["invariant discovery disabled or Solidity index unavailable"]
        )
    solidity_files = [item for item in discovery.files if item.language == "Solidity"]
    files = {item.relative_path: item.content for item in solidity_files}
    profile_assessment = _detect_protocol_profiles_from_discovery(discovery, index, graphs)
    profiles = {profile.value for profile in profile_assessment.detected_profiles}
    if not config.enabled:
        return InvariantSuite(
            protocol_profiles=sorted(profiles),
            protocol_profile_assessment=profile_assessment,
            warnings=["invariant discovery disabled"],
        )
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
        protocol_profile_assessment=profile_assessment,
        warnings=sorted(
            {
                *_invariant_warnings(index, profiles),
                *profile_assessment.limitations,
            }
        ),
        templates_available_count=sum(item.template_available for item in invariants),
        executable_count=sum(item.executable for item in invariants),
    )


def validate_protocol_profile_replay(
    discovery: DiscoveryResult,
    index: SoliditySymbolIndex | None,
    graphs: SolidityGraphSet | None,
    suite: InvariantSuite | None,
) -> ProtocolProfileAssessment | None:
    """Replay source-derived profile evidence before it may receive release custody."""

    if suite is None:
        return None
    if index is None:
        raise ValueError("protocol-profile replay requires the retained Solidity index")
    retained = InvariantSuite.model_validate(suite.model_dump(mode="json"))
    _validate_source_rebuilt_profile_semantics(
        discovery=discovery,
        retained_index=index,
        retained_graphs=graphs,
    )
    observed = _detect_protocol_profiles_from_discovery(discovery, index, graphs)
    if retained.protocol_profile_assessment != observed:
        raise ValueError("retained protocol-profile assessment differs from exact source replay")
    expected_legacy = sorted(profile.value for profile in observed.detected_profiles)
    if retained.protocol_profiles != expected_legacy:
        raise ValueError("legacy protocol-profile projection differs from exact source replay")
    return observed


_PROFILE_REPLAY_ENTITY_KINDS = frozenset(
    {
        SolidityEntityKind.CONTRACT,
        SolidityEntityKind.INTERFACE,
        SolidityEntityKind.LIBRARY,
        SolidityEntityKind.FUNCTION,
        SolidityEntityKind.CONSTRUCTOR,
        SolidityEntityKind.MODIFIER,
        SolidityEntityKind.STATE_VARIABLE,
        SolidityEntityKind.IMMUTABLE,
        SolidityEntityKind.CONSTANT,
        SolidityEntityKind.EVENT,
        SolidityEntityKind.ERROR,
        SolidityEntityKind.STRUCT,
        SolidityEntityKind.ENUM,
    }
)
_PROFILE_REPLAY_GRAPH_KINDS = frozenset(
    {
        SolidityGraphKind.ORACLE_DEPENDENCY,
        SolidityGraphKind.PROXY,
    }
)
_PROFILE_REPLAY_ORACLE_MEMBERS = frozenset(
    {
        "decimals",
        "latestAnswer",
        "latestPrice",
        "latestRoundData",
        "getPrice",
        "price",
        "spotPrice",
        "consult",
        "observe",
        "slot0",
        "getReserves",
        "exchangeRate",
        "getRate",
        "sequencerUp",
    }
)
_PROFILE_REPLAY_MEMBER_CALL = re.compile(
    r"\b(?P<target>[A-Za-z_][A-Za-z0-9_.\[\]]*)\s*\.\s*"
    r"(?P<member>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\{[^}]*\})?\s*\("
)
_PROFILE_REPLAY_KNOWN_ORACLE_CALL = re.compile(
    r"\.\s*(?P<member>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\{[^}]*\})?\s*\("
)
_PROFILE_REPLAY_ORACLE_NAMED_TARGET_CALL = re.compile(
    r"\b(?P<target>[A-Za-z_][A-Za-z0-9_]*(?:oracle|feed|price|twap|sequencer)"
    r"[A-Za-z0-9_]*)\s*(?:\([^;{}\n]{0,512}\))?\s*\.\s*"
    r"(?P<member>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\{[^}]*\})?\s*\(",
    re.IGNORECASE,
)
_PROFILE_REPLAY_PROXY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("transparent", re.compile(r"\bTransparentUpgradeableProxy\b|\bProxyAdmin\b")),
    ("uups", re.compile(r"\bUUPSUpgradeable\b|\b_authorizeUpgrade\b")),
    ("beacon", re.compile(r"\bBeaconProxy\b|\bUpgradeableBeacon\b|\bbeacon\b", re.I)),
    ("diamond", re.compile(r"\bdiamondCut\b|\bfacetAddress\b|\bEIP[- ]?2535\b", re.I)),
    (
        "minimal_proxy",
        re.compile(r"\bClones\b|\bcloneDeterministic\b|363d3d373d3d363d73", re.I),
    ),
    ("custom_delegatecall", re.compile(r"\.\s*delegatecall\s*\(")),
)
_PROFILE_REPLAY_PROXY_SLOT_PATTERNS = (
    re.compile(
        r"\bIMPLEMENTATION_SLOT\b|"
        r"360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
        re.I,
    ),
    re.compile(r"\bADMIN_SLOT\b", re.I),
    re.compile(r"\bBEACON_SLOT\b", re.I),
    re.compile(r"\bROLLBACK_SLOT\b", re.I),
)
_PROFILE_REPLAY_DECLARATION = re.compile(
    r"\b(?:"
    r"(?P<contract_kind>contract|interface|library)\s+"
    r"(?P<contract_name>[A-Za-z_][A-Za-z0-9_]*)|"
    r"(?P<function>function)\s+(?P<function_name>[A-Za-z_][A-Za-z0-9_]*)|"
    r"(?P<modifier>modifier)\s+(?P<modifier_name>[A-Za-z_][A-Za-z0-9_]*)|"
    r"(?P<constructor>constructor)\s*(?=\()|"
    r"(?P<receive>receive)\s*(?=\()|"
    r"(?P<fallback>fallback)\s*(?=\()|"
    r"(?P<event>event)\s+(?P<event_name>[A-Za-z_][A-Za-z0-9_]*)\s*(?=\()|"
    r"(?P<error>error)\s+(?P<error_name>[A-Za-z_][A-Za-z0-9_]*)\s*(?=\()|"
    r"(?P<struct>struct)\s+(?P<struct_name>[A-Za-z_][A-Za-z0-9_]*)\s*(?=\{)|"
    r"(?P<enum>enum)\s+(?P<enum_name>[A-Za-z_][A-Za-z0-9_]*)\s*(?=\{)"
    r")",
)


def _validate_source_rebuilt_profile_semantics(
    *,
    discovery: DiscoveryResult,
    retained_index: SoliditySymbolIndex,
    retained_graphs: SolidityGraphSet | None,
) -> None:
    """Require retained profile inputs to cover an independent source-only rebuild."""

    source_build = build_solidity_index(discovery, [], [])
    source_contents = {
        item.relative_path: item.content
        for item in discovery.files
        if item.language == "Solidity" and item.content
    }
    source_analysis = {
        path: (
            masked,
            _profile_replay_contract_spans(masked),
            _profile_replay_line_starts(masked),
        )
        for path, content in source_contents.items()
        for masked in (_mask_solidity_comments_and_strings(content),)
    }
    source_declaration_keys = {
        declaration
        for path, content in source_contents.items()
        for declaration in _profile_replay_source_declarations(
            path,
            content,
            masked=source_analysis[path][0],
            contract_spans=source_analysis[path][1],
            line_starts=source_analysis[path][2],
        )
    }
    source_state_declaration_keys = {
        declaration
        for path, (masked, contract_spans, line_starts) in source_analysis.items()
        for declaration in _profile_replay_source_state_declarations(
            path,
            masked,
            contract_spans=contract_spans,
            line_starts=line_starts,
        )
    }
    source_declaration_keys.update(source_state_declaration_keys)
    retained_entity_keys = {
        _profile_replay_entity_key(entity)
        for entity in retained_index.entities
        if entity.kind in _PROFILE_REPLAY_ENTITY_KINDS
    }
    required_entity_keys = {
        _profile_replay_entity_key(entity)
        for entity in source_build.index.entities
        if entity.kind in _PROFILE_REPLAY_ENTITY_KINDS
        and _profile_replay_entity_key(entity) in source_declaration_keys
    }
    required_entity_keys.update(source_state_declaration_keys)
    if not required_entity_keys <= retained_entity_keys:
        raise ValueError("retained Solidity index omits source-rebuilt profile entities")

    fabricated_entity_keys = {
        _profile_replay_entity_key(entity)
        for entity in retained_index.entities
        if entity.kind in _PROFILE_REPLAY_ENTITY_KINDS
        and _profile_replay_entity_can_affect_profile(entity)
        and _profile_replay_entity_key(entity) not in source_declaration_keys
    }
    if fabricated_entity_keys:
        raise ValueError("retained Solidity index adds profile entities not declared by source")

    retained_declarations = {
        _profile_replay_entity_key(entity)
        for entity in retained_index.entities
        if entity.kind
        in {
            SolidityEntityKind.FUNCTION,
            SolidityEntityKind.CONSTRUCTOR,
            SolidityEntityKind.MODIFIER,
        }
    }
    required_declarations = {
        declaration
        for declaration in source_declaration_keys
        if declaration[2]
        in {
            SolidityEntityKind.FUNCTION.value,
            SolidityEntityKind.CONSTRUCTOR.value,
            SolidityEntityKind.MODIFIER.value,
        }
        and declaration[3] not in {"receive", "fallback"}
    }
    if not required_declarations <= retained_declarations:
        raise ValueError("retained Solidity index omits source-declared profile symbols")

    source_signals = _profile_replay_source_graph_signals(source_analysis)
    retained_signals, retained_unmapped = _profile_replay_retained_graph_signals(
        retained_graphs,
        retained_index,
    )
    if retained_unmapped or any(key not in source_signals for key in retained_signals):
        raise ValueError("retained Solidity graph adds profile edges unsupported by source")
    missing_signal_counts: dict[str, int] = {}
    for key, occurrence_count in source_signals.items():
        missing_count = occurrence_count - retained_signals.get(key, 0)
        if missing_count > 0:
            missing_signal_counts[key[0]] = missing_signal_counts.get(key[0], 0) + missing_count
    omission_allowances = {
        omission.graph.value: omission.omitted_count - omission.analytical_omitted_count
        for omission in (retained_graphs.edge_omissions if retained_graphs is not None else ())
    }
    if any(
        missing_count > omission_allowances.get(graph_kind, 0)
        for graph_kind, missing_count in missing_signal_counts.items()
    ):
        raise ValueError("retained Solidity graphs omit source-rebuilt profile edges")


def _profile_replay_entity_key(
    entity: SolidityEntity,
) -> tuple[str, int, str, str, str | None]:
    return (
        entity.path,
        entity.start_line,
        _profile_replay_entity_kind(entity.kind),
        entity.name,
        entity.contract_name,
    )


def _profile_replay_entity_kind(kind: SolidityEntityKind) -> str:
    if kind in {
        SolidityEntityKind.STATE_VARIABLE,
        SolidityEntityKind.IMMUTABLE,
        SolidityEntityKind.CONSTANT,
    }:
        return "state_value"
    return kind.value


def _profile_replay_source_declarations(
    path: str,
    content: str,
    *,
    masked: str | None = None,
    contract_spans: tuple[tuple[int, int, str], ...] | None = None,
    line_starts: tuple[int, ...] | None = None,
) -> tuple[tuple[str, int, str, str, str | None], ...]:
    if masked is None:
        masked = _mask_solidity_comments_and_strings(content)
    if contract_spans is None:
        contract_spans = _profile_replay_contract_spans(masked)
    if line_starts is None:
        line_starts = _profile_replay_line_starts(masked)
    declarations: list[tuple[str, int, str, str, str | None]] = []
    for match in _PROFILE_REPLAY_DECLARATION.finditer(masked):
        contract_name: str | None
        if match.group("contract_kind") is not None:
            kind = SolidityEntityKind(match.group("contract_kind"))
            name = match.group("contract_name")
            contract_name = None
        elif match.group("function") is not None:
            kind = SolidityEntityKind.FUNCTION
            name = match.group("function_name")
            contract_name = _profile_replay_contract_name(match.start(), contract_spans)
        elif match.group("modifier") is not None:
            kind = SolidityEntityKind.MODIFIER
            name = match.group("modifier_name")
            contract_name = _profile_replay_contract_name(match.start(), contract_spans)
        elif match.group("constructor") is not None:
            kind = SolidityEntityKind.CONSTRUCTOR
            name = "constructor"
            contract_name = _profile_replay_contract_name(match.start(), contract_spans)
        elif match.group("receive") is not None:
            kind = SolidityEntityKind.FUNCTION
            name = "receive"
            contract_name = _profile_replay_contract_name(match.start(), contract_spans)
        elif match.group("fallback") is not None:
            kind = SolidityEntityKind.FUNCTION
            name = "fallback"
            contract_name = _profile_replay_contract_name(match.start(), contract_spans)
        elif match.group("event") is not None:
            kind = SolidityEntityKind.EVENT
            name = match.group("event_name")
            contract_name = _profile_replay_contract_name(match.start(), contract_spans)
        elif match.group("error") is not None:
            kind = SolidityEntityKind.ERROR
            name = match.group("error_name")
            contract_name = _profile_replay_contract_name(match.start(), contract_spans)
        elif match.group("struct") is not None:
            kind = SolidityEntityKind.STRUCT
            name = match.group("struct_name")
            contract_name = _profile_replay_contract_name(match.start(), contract_spans)
        else:
            assert match.group("enum") is not None
            kind = SolidityEntityKind.ENUM
            name = match.group("enum_name")
            contract_name = _profile_replay_contract_name(match.start(), contract_spans)
        assert name is not None
        declarations.append(
            (
                path,
                bisect_right(line_starts, match.start()),
                _profile_replay_entity_kind(kind),
                name,
                contract_name,
            )
        )
    return tuple(declarations)


def _profile_replay_line_starts(content: str) -> tuple[int, ...]:
    return (0, *(match.end() for match in re.finditer("\n", content)))


def _profile_replay_contract_spans(masked: str) -> tuple[tuple[int, int, str], ...]:
    spans: list[tuple[int, int, str]] = []
    for match in _PROFILE_REPLAY_DECLARATION.finditer(masked):
        if match.group("contract_kind") is None:
            continue
        name = match.group("contract_name")
        assert name is not None
        opening = masked.find("{", match.end())
        if opening < 0:
            continue
        depth = 0
        for offset in range(opening, len(masked)):
            character = masked[offset]
            if character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    spans.append((opening, offset, name))
                    break
    return tuple(spans)


def _profile_replay_contract_name(
    offset: int,
    contract_spans: tuple[tuple[int, int, str], ...],
) -> str | None:
    candidates = [span for span in contract_spans if span[0] < offset < span[1]]
    return max(candidates, key=lambda span: span[0])[2] if candidates else None


def _profile_replay_source_state_declarations(
    path: str,
    masked: str,
    *,
    contract_spans: tuple[tuple[int, int, str], ...],
    line_starts: tuple[int, ...],
) -> tuple[tuple[str, int, str, str, str | None], ...]:
    """Parse contract-level state declarations without using retained index candidates."""

    declarations: list[tuple[str, int, str, str, str | None]] = []
    for opening, closing, contract_name in contract_spans:
        statement_start = opening + 1
        depth = 1
        reset_on_close: list[bool] = []
        for offset in range(opening + 1, closing):
            character = masked[offset]
            if character == "{":
                header = masked[statement_start:offset].lstrip() if depth == 1 else ""
                reset_on_close.append(
                    depth == 1
                    and re.match(
                        r"(?:function|constructor|receive|fallback|modifier|struct|enum)\b",
                        header,
                    )
                    is not None
                )
                depth += 1
                continue
            if character == "}":
                depth -= 1
                reset = reset_on_close.pop() if reset_on_close else False
                if depth == 1 and reset:
                    statement_start = offset + 1
                continue
            if character != ";" or depth != 1:
                continue
            statement = masked[statement_start : offset + 1]
            leading_offset = len(statement) - len(statement.lstrip())
            stripped = statement[leading_offset:]
            statement_start = offset + 1
            if not stripped or re.match(
                r"(?:using|event|error|constructor|receive|fallback|modifier|"
                r"struct|enum|type)\b",
                stripped,
            ):
                continue
            if re.match(r"function\s+[A-Za-z_][A-Za-z0-9_]*\s*\(", stripped):
                continue
            declarator = next(
                (
                    match
                    for match in re.finditer(r"\b[A-Za-z_][A-Za-z0-9_]*\b", stripped)
                    if _profile_replay_is_state_declarator(stripped, match)
                ),
                None,
            )
            if declarator is None:
                continue
            declarations.append(
                (
                    path,
                    bisect_right(line_starts, offset - len(stripped) + 1),
                    "state_value",
                    declarator.group(),
                    contract_name,
                )
            )
    return tuple(declarations)


def _profile_replay_is_state_declarator(
    statement: str,
    match: re.Match[str],
) -> bool:
    suffix = statement[match.end() :].lstrip()
    assignment = suffix.startswith("=") and not suffix.startswith(("=>", "=="))
    if not suffix.startswith(";") and not assignment:
        return False
    prefix = statement[: match.start()]
    boundary = max(prefix.rfind("{"), prefix.rfind("}"), prefix.rfind(";"))
    declaration_prefix = prefix[boundary + 1 :]
    declaration_prefix = re.sub(
        r"\b(?:public|private|internal|external|constant|immutable|transient|override)\b",
        " ",
        declaration_prefix,
    )
    return re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\b", declaration_prefix) is not None


def _profile_replay_entity_can_affect_profile(entity: SolidityEntity) -> bool:
    name = entity.name.casefold()
    contract_symbols = {
        symbol
        for required_sets in _PROFILE_SYMBOL_SETS.values()
        for required in required_sets
        for symbol in required
    }
    indexed_tokens = {token for tokens in _PROFILE_INDEXED_NAME_TOKENS.values() for token in tokens}
    return name in contract_symbols or any(token in name for token in indexed_tokens)


def _profile_replay_source_graph_signals(
    source_analysis: dict[
        str,
        tuple[str, tuple[tuple[int, int, str], ...], tuple[int, ...]],
    ],
) -> dict[tuple[str, str, int, str, str], int]:
    """Inventory profile graph facts directly from source, independent of graph artifacts."""

    signals: dict[tuple[str, str, int, str, str], int] = {}
    for path, (masked, _contract_spans, line_starts) in source_analysis.items():
        recognized_oracle_offsets: set[int] = set()
        for match in _PROFILE_REPLAY_MEMBER_CALL.finditer(masked):
            member = match.group("member")
            if member not in _PROFILE_REPLAY_ORACLE_MEMBERS and not any(
                token in match.group("target").casefold()
                for token in ("oracle", "feed", "price", "twap", "sequencer")
            ):
                continue
            member_offset = match.start("member")
            recognized_oracle_offsets.add(member_offset)
            _profile_replay_add_graph_signal(
                signals,
                SolidityGraphKind.ORACLE_DEPENDENCY,
                path,
                bisect_right(line_starts, match.start()),
                "member_call",
                member,
            )
        for match in _PROFILE_REPLAY_KNOWN_ORACLE_CALL.finditer(masked):
            member = match.group("member")
            member_offset = match.start("member")
            if (
                member not in _PROFILE_REPLAY_ORACLE_MEMBERS
                or member_offset in recognized_oracle_offsets
            ):
                continue
            recognized_oracle_offsets.add(member_offset)
            _profile_replay_add_graph_signal(
                signals,
                SolidityGraphKind.ORACLE_DEPENDENCY,
                path,
                bisect_right(line_starts, match.start()),
                "member_call",
                member,
            )
        for match in _PROFILE_REPLAY_ORACLE_NAMED_TARGET_CALL.finditer(masked):
            member = match.group("member")
            member_offset = match.start("member")
            if member_offset in recognized_oracle_offsets:
                continue
            recognized_oracle_offsets.add(member_offset)
            _profile_replay_add_graph_signal(
                signals,
                SolidityGraphKind.ORACLE_DEPENDENCY,
                path,
                bisect_right(line_starts, match.start()),
                "member_call",
                member,
            )
        _profile_replay_add_proxy_source_signals(
            signals,
            path=path,
            masked=masked,
            line_starts=line_starts,
        )
    return signals


def _profile_replay_add_proxy_source_signals(
    signals: dict[tuple[str, str, int, str, str], int],
    *,
    path: str,
    masked: str,
    line_starts: tuple[int, ...],
) -> None:
    for declaration in _PROFILE_REPLAY_DECLARATION.finditer(masked):
        if declaration.group("contract_kind") is None:
            continue
        contract_name = declaration.group("contract_name")
        assert contract_name is not None
        opening = masked.find("{", declaration.end())
        closing = _profile_replay_matching_brace(masked, opening)
        if opening < 0 or closing is None:
            continue
        # Inheritance clauses and base constructors live before the opening brace.
        # Retained proxy edges inspect the complete contract span, so replay must
        # inventory the same header bytes (for example ``is UUPSUpgradeable``).
        contract_source = masked[declaration.start() : closing + 1]
        patterns = [
            name
            for name, pattern in _PROFILE_REPLAY_PROXY_PATTERNS
            if pattern.search(contract_source)
        ]
        has_slots = any(
            pattern.search(contract_source) for pattern in _PROFILE_REPLAY_PROXY_SLOT_PATTERNS
        )
        has_delegate = re.search(r"\b(?:delegatecall|callcode)\s*\(", contract_source) is not None
        if not patterns and ("proxy" in contract_name.casefold() or has_slots or has_delegate):
            patterns = ["name_based_proxy"]
        declaration_line = bisect_right(line_starts, declaration.start())
        for pattern in patterns:
            _profile_replay_add_graph_signal(
                signals,
                SolidityGraphKind.PROXY,
                path,
                declaration_line,
                "proxy_pattern",
                pattern,
            )
        for function in _PROFILE_REPLAY_DECLARATION.finditer(
            masked,
            opening + 1,
            closing,
        ):
            if function.group("function") is None:
                continue
            function_name = function.group("function_name")
            assert function_name is not None
            lowered = function_name.casefold()
            if "upgrade" not in lowered and "implementation" not in lowered:
                continue
            _profile_replay_add_graph_signal(
                signals,
                SolidityGraphKind.PROXY,
                path,
                bisect_right(line_starts, function.start()),
                "proxy_control",
                function_name,
            )


def _profile_replay_matching_brace(masked: str, opening: int) -> int | None:
    if opening < 0:
        return None
    depth = 0
    for offset in range(opening, len(masked)):
        if masked[offset] == "{":
            depth += 1
        elif masked[offset] == "}":
            depth -= 1
            if depth == 0:
                return offset
    return None


def _profile_replay_add_graph_signal(
    signals: dict[tuple[str, str, int, str, str], int],
    graph: SolidityGraphKind,
    path: str,
    line: int,
    signal_kind: str,
    marker: str,
    *,
    occurrence_count: int = 1,
) -> None:
    key = (graph.value, path, line, signal_kind, marker)
    signals[key] = signals.get(key, 0) + occurrence_count


def _profile_replay_retained_graph_signals(
    graphs: SolidityGraphSet | None,
    index: SoliditySymbolIndex,
) -> tuple[dict[tuple[str, str, int, str, str], int], bool]:
    signals: dict[tuple[str, str, int, str, str], int] = {}
    if graphs is None:
        return signals, False
    occurrences = {
        occurrence.subject_sha256: occurrence.occurrence_count
        for occurrence in graphs.retained_occurrences
        if occurrence.subject_kind is SolidityGraphOccurrenceKind.EDGE
    }
    entities = {entity.id: entity for entity in index.entities}
    unmapped = False
    for edge in graphs.edges:
        if edge.graph not in _PROFILE_REPLAY_GRAPH_KINDS:
            continue
        digest = solidity_graph_occurrence_sha256(SolidityGraphOccurrenceKind.EDGE, edge)
        occurrence_count = occurrences.get(digest, 0)
        marker: str | None
        signal_kind: str | None
        if edge.graph is SolidityGraphKind.ORACLE_DEPENDENCY:
            marker = _profile_replay_oracle_edge_member(edge)
            signal_kind = "member_call"
        else:
            marker, signal_kind = _profile_replay_proxy_edge_marker(edge, entities)
        if marker is None or signal_kind is None:
            unmapped = True
            continue
        _profile_replay_add_graph_signal(
            signals,
            edge.graph,
            edge.path,
            edge.start_line,
            signal_kind,
            marker,
            occurrence_count=occurrence_count,
        )
    return signals, unmapped


def _profile_replay_oracle_edge_member(edge: SolidityGraphEdge) -> str | None:
    member = edge.metadata.get("member")
    if isinstance(member, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", member):
        return member
    match = re.search(r"\.\s*(?P<member>[A-Za-z_][A-Za-z0-9_]*)\s*$", edge.label)
    return match.group("member") if match is not None else None


def _profile_replay_proxy_edge_marker(
    edge: SolidityGraphEdge,
    entities: dict[str, SolidityEntity],
) -> tuple[str | None, str | None]:
    control = re.fullmatch(
        r"upgrade/implementation control (?P<name>[A-Za-z_][A-Za-z0-9_]*)",
        edge.label,
    )
    if control is not None:
        source = entities.get(edge.source_id)
        name = control.group("name")
        if source is None or source.name != name:
            return None, None
        return name, "proxy_control"
    pattern = re.fullmatch(r"detected (?P<name>[a-z_]+) proxy pattern", edge.label)
    if pattern is not None:
        source = entities.get(edge.source_id)
        if source is None or source.kind not in {
            SolidityEntityKind.CONTRACT,
            SolidityEntityKind.INTERFACE,
            SolidityEntityKind.LIBRARY,
        }:
            return None, None
        return pattern.group("name"), "proxy_pattern"
    return None, None


def _mask_solidity_comments_and_strings(content: str) -> str:
    """Mask non-code bytes while preserving exact character and line offsets."""

    characters = list(content)
    index = 0
    state = "code"
    quote = ""
    while index < len(characters):
        character = characters[index]
        following = characters[index + 1] if index + 1 < len(characters) else ""
        if state == "code":
            if character == "/" and following == "/":
                characters[index] = characters[index + 1] = " "
                index += 2
                state = "line_comment"
                continue
            if character == "/" and following == "*":
                characters[index] = characters[index + 1] = " "
                index += 2
                state = "block_comment"
                continue
            if character in {"'", '"'}:
                quote = character
                characters[index] = " "
                index += 1
                state = "string"
                continue
        elif state == "line_comment":
            if character == "\n":
                state = "code"
            else:
                characters[index] = " "
        elif state == "block_comment":
            if character == "*" and following == "/":
                characters[index] = characters[index + 1] = " "
                index += 2
                state = "code"
                continue
            if character != "\n":
                characters[index] = " "
        else:
            if character == "\\" and following:
                characters[index] = " "
                if following != "\n":
                    characters[index + 1] = " "
                index += 2
                continue
            if character == quote:
                state = "code"
            if character != "\n":
                characters[index] = " "
        index += 1
    return "".join(characters)


def _detect_protocol_profiles_from_discovery(
    discovery: DiscoveryResult,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet | None,
) -> ProtocolProfileAssessment:
    solidity_files = [item for item in discovery.files if item.language == "Solidity"]
    return detect_protocol_profiles(
        index,
        graphs,
        {item.relative_path: item.content for item in solidity_files},
        discovery_omissions=discovery.omitted,
        mapped_without_content_sources=(
            (item.relative_path, item.size, item.sha256)
            for item in solidity_files
            if not item.content and item.size > 0
        ),
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


_PROFILE_SYMBOL_SETS: dict[ProtocolProfileKind, tuple[frozenset[str], ...]] = {
    ProtocolProfileKind.ERC20_TOKEN: (frozenset({"totalsupply", "balanceof", "transfer"}),),
    ProtocolProfileKind.ERC721: (frozenset({"balanceof", "ownerof", "transferfrom"}),),
    ProtocolProfileKind.ERC1155: (frozenset({"balanceof", "safetransferfrom", "balanceofbatch"}),),
    ProtocolProfileKind.ERC4626_VAULT: (
        frozenset({"totalassets", "converttoshares"}),
        frozenset({"totalassets", "deposit", "balanceof"}),
    ),
    ProtocolProfileKind.STATE_MACHINE: (frozenset({"pause", "unpause"}),),
}

_PROFILE_INDEXED_NAME_TOKENS: dict[ProtocolProfileKind, tuple[str, ...]] = {
    ProtocolProfileKind.STAKING: ("stake", "unstake", "reward"),
    ProtocolProfileKind.LENDING: ("borrow", "repay", "liquidat"),
    ProtocolProfileKind.AMM: ("getreserves", "swap", "liquidity"),
    ProtocolProfileKind.GOVERNANCE: ("governor", "timelock", "proposal"),
    ProtocolProfileKind.BRIDGE: ("bridge", "messenger", "crossdomain"),
    ProtocolProfileKind.TOKEN_DISTRIBUTION: ("claim", "merkleproof"),
    ProtocolProfileKind.STATE_MACHINE: ("initialize", "reinitialize"),
}

_PROFILE_SOURCE_MARKERS: dict[ProtocolProfileKind, tuple[str, ...]] = {
    ProtocolProfileKind.ERC20_TOKEN: ("ierc20",),
    ProtocolProfileKind.ERC721: ("ierc721", "erc721"),
    ProtocolProfileKind.ERC1155: ("ierc1155", "erc1155"),
    ProtocolProfileKind.ERC4626_VAULT: ("ierc4626", "erc4626"),
    ProtocolProfileKind.AMM: ("getreserves", "swap(", "liquidity"),
    ProtocolProfileKind.GOVERNANCE: ("governor", "timelock", "proposal"),
    ProtocolProfileKind.BRIDGE: ("bridge", "messenger", "crossdomain"),
}

_GRAPH_PROFILES: dict[ProtocolProfileKind, SolidityGraphKind] = {
    ProtocolProfileKind.ORACLE_CONSUMER: SolidityGraphKind.ORACLE_DEPENDENCY,
    ProtocolProfileKind.UPGRADEABLE_SYSTEM: SolidityGraphKind.PROXY,
}

_DISCOVERY_GLOBAL_LIMITS = {
    "repository: max_files reached": "max_files",
    "repository: max_walk_entries reached": "max_walk_entries",
}


def _profile_source_inventory(
    *,
    index: SoliditySymbolIndex,
    files: dict[str, str],
    discovery_omissions: Iterable[str],
    mapped_without_content_sources: Iterable[tuple[str, int, str]],
) -> tuple[dict[str, object], tuple[str, ...]]:
    """Commit to the bounded source evidence required for absence classifications."""

    omissions = tuple(sorted(discovery_omissions))
    mapped_without_content_records = tuple(sorted(set(mapped_without_content_sources)))
    mapped_without_content = tuple(
        _profile_mapped_source_record(path, size, sha256)
        for path, size, sha256 in mapped_without_content_records
    )
    retained_sources = tuple(sorted(files))
    ast_sources = tuple(sorted(index.ast_sources))
    fallback_sources = tuple(sorted(index.fallback_sources))
    indexed_source_set = set(ast_sources) | set(fallback_sources)
    retained_source_set = set(retained_sources)
    entity_sources = tuple(sorted({entity.path for entity in index.entities}))
    entity_source_set = set(entity_sources)
    retained_without_index = tuple(sorted(retained_source_set - indexed_source_set))
    indexed_without_retained = tuple(sorted(indexed_source_set - retained_source_set))
    entity_sources_without_index = tuple(sorted(set(entity_sources) - indexed_source_set))
    entity_sources_without_retained = tuple(sorted(set(entity_sources) - retained_source_set))
    ast_sources_without_entities = tuple(sorted(set(ast_sources) - entity_source_set))
    retained_line_counts = {
        path: len(content.splitlines(keepends=True)) for path, content in files.items()
    }
    retained_byte_counts = {path: len(content.encode("utf-8")) for path, content in files.items()}
    invalid_entity_span_records = tuple(
        sorted(
            _profile_entity_source_record(entity)
            for entity in index.entities
            if entity.path in files
            and not _profile_entity_span_is_valid(
                entity,
                line_counts=retained_line_counts,
                byte_counts=retained_byte_counts,
            )
        )
    )
    stale_entity_source_records = tuple(
        sorted(
            _profile_entity_source_record(entity)
            for entity in index.entities
            if entity.path in files
            and _profile_entity_span_is_valid(
                entity,
                line_counts=retained_line_counts,
                byte_counts=retained_byte_counts,
            )
            and entity.source_hash
            != line_range_hash(files[entity.path], entity.start_line, entity.end_line)
        )
    )
    ast_fallback_overlap = tuple(sorted(set(ast_sources) & set(fallback_sources)))
    duplicate_ast_source_count = len(ast_sources) - len(set(ast_sources))
    duplicate_fallback_source_count = len(fallback_sources) - len(set(fallback_sources))
    global_limits = tuple(
        sorted(kind for omission, kind in _DISCOVERY_GLOBAL_LIMITS.items() if omission in omissions)
    )

    inventories = {
        "discovery_omissions": _profile_inventory_commitment(omissions),
        "mapped_without_content_solidity": _profile_inventory_commitment(mapped_without_content),
        "retained_solidity_sources": _profile_inventory_commitment(retained_sources),
        "ast_sources": _profile_inventory_commitment(ast_sources),
        "fallback_sources": _profile_inventory_commitment(fallback_sources),
        "entity_sources": _profile_inventory_commitment(entity_sources),
        "retained_without_index": _profile_inventory_commitment(retained_without_index),
        "indexed_without_retained": _profile_inventory_commitment(indexed_without_retained),
        "entity_sources_without_index": _profile_inventory_commitment(entity_sources_without_index),
        "entity_sources_without_retained": _profile_inventory_commitment(
            entity_sources_without_retained
        ),
        "ast_sources_without_entities": _profile_inventory_commitment(ast_sources_without_entities),
        "invalid_entity_span_records": _profile_inventory_commitment(invalid_entity_span_records),
        "stale_entity_source_records": _profile_inventory_commitment(stale_entity_source_records),
        "ast_fallback_overlap": _profile_inventory_commitment(ast_fallback_overlap),
    }
    incomplete_facts: list[str] = []
    _append_profile_inventory_facts(
        incomplete_facts,
        "discovery_omission_inventory",
        omissions,
    )
    incomplete_facts.extend(f"discovery_global_limit:{kind}" for kind in global_limits)
    _append_profile_inventory_facts(
        incomplete_facts,
        "mapped_without_content_solidity",
        mapped_without_content,
    )
    _append_profile_inventory_facts(
        incomplete_facts,
        "profile_positive_only_solidity",
        fallback_sources,
    )
    if retained_sources:
        incomplete_facts.append(
            "compiler_execution_not_independently_authenticated_for_profile_absence"
        )
    _append_profile_inventory_facts(
        incomplete_facts,
        "retained_solidity_without_index",
        retained_without_index,
    )
    _append_profile_inventory_facts(
        incomplete_facts,
        "indexed_solidity_without_retained_source",
        indexed_without_retained,
    )
    _append_profile_inventory_facts(
        incomplete_facts,
        "entity_source_without_index",
        entity_sources_without_index,
    )
    _append_profile_inventory_facts(
        incomplete_facts,
        "entity_source_without_retained_source",
        entity_sources_without_retained,
    )
    _append_profile_inventory_facts(
        incomplete_facts,
        "ast_source_without_indexed_entity",
        ast_sources_without_entities,
    )
    _append_profile_inventory_facts(
        incomplete_facts,
        "invalid_indexed_entity_source_span",
        invalid_entity_span_records,
    )
    _append_profile_inventory_facts(
        incomplete_facts,
        "stale_indexed_entity_source",
        stale_entity_source_records,
    )
    _append_profile_inventory_facts(
        incomplete_facts,
        "ast_fallback_source_overlap",
        ast_fallback_overlap,
    )
    if duplicate_ast_source_count:
        incomplete_facts.append(f"duplicate_ast_source_count:{duplicate_ast_source_count}")
    if duplicate_fallback_source_count:
        incomplete_facts.append(
            f"duplicate_fallback_source_count:{duplicate_fallback_source_count}"
        )
    normalized_facts = tuple(sorted(set(incomplete_facts)))
    source_inventory: dict[str, object] = {
        "schema_version": "1.0",
        "negative_evidence_complete": not normalized_facts,
        "global_discovery_limits": list(global_limits),
        "duplicate_ast_source_count": duplicate_ast_source_count,
        "duplicate_fallback_source_count": duplicate_fallback_source_count,
        "inventories": inventories,
    }
    return source_inventory, normalized_facts


def _append_profile_inventory_facts(
    facts: list[str],
    name: str,
    values: tuple[str, ...],
) -> None:
    if not values:
        return
    commitment = _profile_inventory_commitment(values)
    facts.extend(
        (
            f"{name}_count:{commitment['count']}",
            f"{name}_sha256:{commitment['sha256']}",
        )
    )


def _profile_inventory_commitment(values: tuple[str, ...]) -> dict[str, int | str]:
    canonical = tuple(sorted(values))
    payload = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return {
        "count": len(canonical),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _profile_mapped_source_record(path: str, size: int, sha256: str) -> str:
    return json.dumps(
        {
            "path": path,
            "reason": "mapped_without_content_after_max_discovery_bytes",
            "sha256": sha256,
            "size": size,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _profile_entity_source_record(entity: SolidityEntity) -> str:
    return json.dumps(
        {
            "end_line": entity.end_line,
            "entity_id": entity.id,
            "path": entity.path,
            "indexed_source_hash": entity.source_hash,
            "start_line": entity.start_line,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _profile_entity_span_is_valid(
    entity: SolidityEntity,
    *,
    line_counts: dict[str, int],
    byte_counts: dict[str, int],
) -> bool:
    return (
        entity.end_line <= line_counts[entity.path]
        and entity.byte_start <= byte_counts[entity.path]
        and entity.byte_end <= byte_counts[entity.path]
    )


def detect_protocol_profiles(
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet | None,
    files: dict[str, str],
    *,
    discovery_omissions: Iterable[str] = (),
    mapped_without_content_sources: Iterable[tuple[str, int, str]] = (),
) -> ProtocolProfileAssessment:
    """Classify every closed protocol profile from immutable host-derived source facts."""

    normalized_files = dict(sorted(files.items()))
    validated_index = SoliditySymbolIndex.model_validate(index.model_dump(mode="json"))
    validated_index = _profile_positive_only_index(validated_index, normalized_files)
    validated_graphs = (
        SolidityGraphSet.model_validate(graphs.model_dump(mode="json"))
        if graphs is not None
        else None
    )
    source_inventory, incomplete_negative_evidence = _profile_source_inventory(
        index=validated_index,
        files=normalized_files,
        discovery_omissions=discovery_omissions,
        mapped_without_content_sources=mapped_without_content_sources,
    )
    classifications = [
        _classify_protocol_profile(
            profile,
            entities=validated_index.entities,
            graphs=validated_graphs,
            files=normalized_files,
            incomplete_negative_evidence=incomplete_negative_evidence,
        )
        for profile in ProtocolProfileKind
    ]
    classifications.sort(key=lambda item: item.profile.value)
    limitations = [
        f"protocol profile {item.profile.value} is indeterminate: {', '.join(item.matched_facts)}"
        for item in classifications
        if item.status is ProtocolProfileStatus.INDETERMINATE
    ]
    if incomplete_negative_evidence and limitations:
        limitations.append(
            "protocol-profile absence evidence is incomplete: "
            + ", ".join(incomplete_negative_evidence)
        )
    limitations = sorted(limitations)
    payload = {
        "schema_version": "1.0",
        "input_sha256": _profile_input_sha256(
            index=validated_index,
            graphs=validated_graphs,
            files=normalized_files,
            source_inventory=source_inventory,
        ),
        "classification_complete": not limitations,
        "classifications": [item.model_dump(mode="json") for item in classifications],
        "limitations": limitations,
    }
    return ProtocolProfileAssessment(
        **payload,
        assessment_sha256=ProtocolProfileAssessment.calculate_assessment_sha256(payload),
    )


def _profile_positive_only_index(
    index: SoliditySymbolIndex,
    files: dict[str, str],
) -> SoliditySymbolIndex:
    """Keep compiler-derived positives while denying unauthenticated AST absence authority."""

    return index.model_copy(
        update={
            "entities": [
                entity.model_copy(
                    update={
                        "provenance": SolidityProvenance.FALLBACK,
                        "confidence": 0.5,
                        "transformation": "protocol_profile_positive_only_source_fact",
                    }
                )
                for entity in index.entities
            ],
            "ast_sources": [],
            "fallback_sources": sorted(files),
        }
    )


def _classify_protocol_profile(
    profile: ProtocolProfileKind,
    *,
    entities: list[SolidityEntity],
    graphs: SolidityGraphSet | None,
    files: dict[str, str],
    incomplete_negative_evidence: tuple[str, ...],
) -> ProtocolProfileEvidence:
    if profile is ProtocolProfileKind.SOLIDITY_GENERAL:
        if entities:
            retained = sorted(entities, key=_entity_evidence_key)[:100]
            return _profile_evidence(
                profile=profile,
                status=ProtocolProfileStatus.DETECTED,
                rule=ProtocolProfileDetectionRule.INDEXED_SYMBOL,
                matched_facts=[f"indexed_solidity_entity_count:{len(entities)}"],
                entities=retained,
                locations=[_profile_entity_location(entity) for entity in retained],
            )
        status = (
            ProtocolProfileStatus.INDETERMINATE
            if files or incomplete_negative_evidence
            else ProtocolProfileStatus.NOT_DETECTED
        )
        fact = (
            "solidity_sources_exist_without_indexed_entities"
            if files
            else "no_indexed_solidity_entities"
        )
        return _profile_evidence(
            profile=profile,
            status=status,
            rule=ProtocolProfileDetectionRule.INDEXED_SYMBOL,
            matched_facts=[fact, *incomplete_negative_evidence],
        )

    graph_kind = _GRAPH_PROFILES.get(profile)
    if graph_kind is not None:
        return _classify_graph_profile(
            profile,
            graph_kind=graph_kind,
            graphs=graphs,
            entities=entities,
            incomplete_negative_evidence=incomplete_negative_evidence,
        )

    symbol_match = _contract_local_symbol_match(
        profile,
        entities=entities,
    )
    if symbol_match is not None:
        matched_entities, matched_facts = symbol_match
        return _profile_evidence(
            profile=profile,
            status=ProtocolProfileStatus.DETECTED,
            rule=ProtocolProfileDetectionRule.CONTRACT_SYMBOL_SET,
            matched_facts=matched_facts,
            entities=matched_entities,
            locations=[_profile_entity_location(entity) for entity in matched_entities],
        )

    indexed_match = _indexed_name_match(profile, entities=entities)
    if indexed_match is not None:
        matched_entities, matched_facts = indexed_match
        return _profile_evidence(
            profile=profile,
            status=ProtocolProfileStatus.DETECTED,
            rule=ProtocolProfileDetectionRule.INDEXED_SYMBOL,
            matched_facts=matched_facts,
            entities=matched_entities,
            locations=[_profile_entity_location(entity) for entity in matched_entities],
        )

    marker_match = _source_marker_match(profile, files=files, entities=entities)
    if marker_match is not None:
        matched_entities, locations, matched_facts = marker_match
        return _profile_evidence(
            profile=profile,
            status=ProtocolProfileStatus.DETECTED,
            rule=ProtocolProfileDetectionRule.SOURCE_MARKER,
            matched_facts=matched_facts,
            entities=matched_entities,
            locations=locations,
        )

    default_rule = (
        ProtocolProfileDetectionRule.CONTRACT_SYMBOL_SET
        if profile in _PROFILE_SYMBOL_SETS
        else ProtocolProfileDetectionRule.INDEXED_SYMBOL
    )
    return _profile_evidence(
        profile=profile,
        status=(
            ProtocolProfileStatus.INDETERMINATE
            if incomplete_negative_evidence
            else ProtocolProfileStatus.NOT_DETECTED
        ),
        rule=default_rule,
        matched_facts=["no_matching_host_owned_source_facts", *incomplete_negative_evidence],
    )


def _classify_graph_profile(
    profile: ProtocolProfileKind,
    *,
    graph_kind: SolidityGraphKind,
    graphs: SolidityGraphSet | None,
    entities: list[SolidityEntity],
    incomplete_negative_evidence: tuple[str, ...],
) -> ProtocolProfileEvidence:
    edges = sorted(
        [edge for edge in (graphs.edges if graphs is not None else []) if edge.graph is graph_kind],
        key=lambda edge: (
            edge.path,
            edge.start_line,
            edge.end_line,
            edge.source_id,
            edge.target_id,
            edge.label,
        ),
    )
    if edges:
        entities_by_id = {entity.id: entity for entity in entities}
        entity_ids = sorted(
            {
                entity_id
                for edge in edges
                for entity_id in (edge.source_id, edge.target_id)
                if entity_id in entities_by_id
            }
        )[:100]
        return _profile_evidence(
            profile=profile,
            status=ProtocolProfileStatus.DETECTED,
            rule=ProtocolProfileDetectionRule.SEMANTIC_GRAPH,
            matched_facts=[f"{graph_kind.value}_edge_count:{len(edges)}"],
            entity_ids=entity_ids,
            locations=[
                Location(
                    path=edge.path,
                    start_line=edge.start_line,
                    end_line=edge.end_line,
                    content_hash=edge.source_hash,
                )
                for edge in edges[:100]
            ],
        )
    graph_complete = (
        graphs is not None
        and graph_kind in graphs.analyzed_graphs
        and all(omission.graph is not graph_kind for omission in graphs.edge_omissions)
    )
    if graph_complete and not incomplete_negative_evidence:
        status = ProtocolProfileStatus.NOT_DETECTED
        fact = f"no_{graph_kind.value}_edges_in_complete_graph"
    else:
        status = ProtocolProfileStatus.INDETERMINATE
        if graph_complete:
            fact = f"no_{graph_kind.value}_edges_in_complete_retained_graph"
        elif graphs is None:
            fact = f"{graph_kind.value}_graph_unavailable"
        elif graph_kind not in graphs.analyzed_graphs:
            fact = f"{graph_kind.value}_graph_not_analyzed"
        else:
            fact = f"{graph_kind.value}_graph_has_omitted_edges"
    return _profile_evidence(
        profile=profile,
        status=status,
        rule=ProtocolProfileDetectionRule.SEMANTIC_GRAPH,
        matched_facts=[fact, *incomplete_negative_evidence],
    )


def _contract_local_symbol_match(
    profile: ProtocolProfileKind,
    *,
    entities: list[SolidityEntity],
) -> tuple[list[SolidityEntity], list[str]] | None:
    required_sets = _PROFILE_SYMBOL_SETS.get(profile, ())
    if not required_sets:
        return None
    groups: dict[tuple[str, str], list[SolidityEntity]] = {}
    for entity in entities:
        contract_name = entity.contract_name
        if contract_name is None and entity.kind in {
            SolidityEntityKind.CONTRACT,
            SolidityEntityKind.INTERFACE,
            SolidityEntityKind.LIBRARY,
        }:
            contract_name = entity.name
        if contract_name is not None:
            groups.setdefault((entity.path, contract_name), []).append(entity)
    matches: list[SolidityEntity] = []
    facts: set[str] = set()
    for (path, contract_name), group in sorted(groups.items()):
        names = {entity.name.casefold() for entity in group}
        for required in required_sets:
            if not required <= names:
                continue
            matches.extend(entity for entity in group if entity.name.casefold() in required)
            facts.add(f"contract_symbol_set:{path}:{contract_name}:{','.join(sorted(required))}")
    if not matches:
        return None
    retained = sorted(
        {entity.id: entity for entity in matches}.values(),
        key=_entity_evidence_key,
    )[:100]
    return retained, sorted(facts)[:50]


def _indexed_name_match(
    profile: ProtocolProfileKind,
    *,
    entities: list[SolidityEntity],
) -> tuple[list[SolidityEntity], list[str]] | None:
    tokens = _PROFILE_INDEXED_NAME_TOKENS.get(profile, ())
    matches = sorted(
        [entity for entity in entities if any(token in entity.name.casefold() for token in tokens)],
        key=_entity_evidence_key,
    )
    if not matches:
        return None
    retained = matches[:100]
    facts = sorted(
        {
            f"indexed_symbol_token:{token}"
            for entity in retained
            for token in tokens
            if token in entity.name.casefold()
        }
    )
    return retained, facts[:50]


def _source_marker_match(
    profile: ProtocolProfileKind,
    *,
    files: dict[str, str],
    entities: list[SolidityEntity],
) -> tuple[list[SolidityEntity], list[Location], list[str]] | None:
    markers = _PROFILE_SOURCE_MARKERS.get(profile, ())
    if not markers:
        return None
    locations: list[Location] = []
    matched_markers: set[str] = set()
    matched_paths: set[str] = set()
    for path, content in files.items():
        for line_number, line in enumerate(content.splitlines(keepends=True), start=1):
            lowered = line.casefold()
            line_markers = [marker for marker in markers if marker in lowered]
            if not line_markers:
                continue
            matched_markers.update(line_markers)
            matched_paths.add(path)
            locations.append(
                Location(
                    path=path,
                    start_line=line_number,
                    end_line=line_number,
                    content_hash=line_range_hash(content, line_number, line_number),
                )
            )
    if not locations:
        return None
    matched_entities = sorted(
        [entity for entity in entities if entity.path in matched_paths],
        key=_entity_evidence_key,
    )[:100]
    return (
        matched_entities,
        _canonical_profile_locations(locations)[:100],
        [f"source_marker:{marker}" for marker in sorted(matched_markers)][:50],
    )


def _profile_evidence(
    *,
    profile: ProtocolProfileKind,
    status: ProtocolProfileStatus,
    rule: ProtocolProfileDetectionRule,
    matched_facts: list[str],
    entities: list[SolidityEntity] | None = None,
    entity_ids: list[str] | None = None,
    locations: list[Location] | None = None,
) -> ProtocolProfileEvidence:
    retained_entities = entities or []
    normalized_entity_ids = sorted(
        {
            *(entity.id for entity in retained_entities),
            *(entity_ids or []),
        }
    )[:100]
    payload = {
        "profile": profile,
        "status": status,
        "rule": rule,
        "matched_facts": sorted(set(matched_facts))[:50],
        "entity_ids": normalized_entity_ids,
        "locations": [
            location.model_dump(mode="json")
            for location in _canonical_profile_locations(locations or [])[:100]
        ],
    }
    return ProtocolProfileEvidence(
        **payload,
        evidence_sha256=ProtocolProfileEvidence.calculate_evidence_sha256(payload),
    )


def _profile_input_sha256(
    *,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet | None,
    files: dict[str, str],
    source_inventory: dict[str, object],
) -> str:
    payload = {
        "detector": "mmaudit.protocol-profile-detector.v1",
        "index": {
            "entities": [
                entity.model_dump(mode="json")
                for entity in sorted(index.entities, key=_entity_evidence_key)
            ],
            "ast_sources": sorted(index.ast_sources),
            "fallback_sources": sorted(index.fallback_sources),
        },
        "graphs": (
            {
                "edges": sorted(
                    (_profile_edge_input_record(edge) for edge in graphs.edges),
                    key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
                ),
                "analyzed_graphs": sorted(item.value for item in graphs.analyzed_graphs),
                "generation_complete": graphs.generation_complete,
                "edge_omissions": [item.model_dump(mode="json") for item in graphs.edge_omissions],
                "fact_omissions": [item.model_dump(mode="json") for item in graphs.fact_omissions],
            }
            if graphs is not None
            else None
        ),
        "files": [
            {
                "path": path,
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            }
            for path, content in files.items()
        ],
        "source_inventory": source_inventory,
    }
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _profile_edge_input_record(edge: SolidityGraphEdge) -> dict[str, object]:
    """Ignore unauthenticated provenance labels without changing persisted graphs."""

    record = edge.model_dump(mode="json")
    record.update(
        {
            "provenance": SolidityProvenance.FALLBACK.value,
            "confidence": 0.5,
            "transformation": "protocol_profile_positive_only_graph_fact",
        }
    )
    return record


def _profile_entity_location(entity: SolidityEntity) -> Location:
    return Location(
        path=entity.path,
        start_line=entity.start_line,
        end_line=entity.end_line,
        symbol=entity.signature or entity.name,
        content_hash=entity.source_hash,
    )


def _entity_evidence_key(entity: SolidityEntity) -> tuple[str, int, int, str]:
    return (entity.path, entity.start_line, entity.end_line, entity.id)


def _canonical_profile_locations(locations: list[Location]) -> list[Location]:
    unique = {
        (
            location.path,
            location.start_line,
            location.end_line,
            location.symbol or "",
            location.content_hash or "",
        ): location
        for location in locations
    }
    return [unique[key] for key in sorted(unique)]


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
