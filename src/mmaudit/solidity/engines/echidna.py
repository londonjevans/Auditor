"""Deterministic translation of shared properties into a bounded Echidna harness."""

from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath

from mmaudit.models.schemas import (
    DynamicPropertySpec,
    ForkArgument,
    ForkArgumentKind,
    HarnessArgument,
    HarnessArgumentSource,
    InvariantProbe,
    InvariantRelation,
    PropertyCorpus,
    SolidityEntity,
    SolidityEntityKind,
    SoliditySymbolIndex,
    TransactionOrderingCapability,
)
from mmaudit.repository.ignore import normalize_relative_path

_MAX_UINT256 = 2**256 - 1


@dataclass(frozen=True)
class PropertyEngineTranslation:
    """Generated source/config plus exact property lineage and limitations."""

    source: str
    configuration: str
    property_map: dict[str, DynamicPropertySpec]
    limitations: list[str]
    seed: int | None
    runs: int
    depth: int
    source_path: str = ""
    configuration_path: str = ""
    property_map_path: str = ""
    assumptions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _TranslatedProperty:
    property_spec: DynamicPropertySpec
    generated_name: str
    target: SolidityEntity
    prefix: str


EchidnaTranslation = PropertyEngineTranslation


def translate_echidna_corpus(
    corpus: PropertyCorpus,
    index: SoliditySymbolIndex,
    *,
    timeout_seconds: float,
) -> EchidnaTranslation:
    """Translate the safely expressible no-argument local-deployment subset."""

    translation = translate_property_corpus(
        corpus,
        index,
        harness_contract_name="MMAuditEchidnaProperties",
        property_prefix="echidna",
        engine_name="Echidna",
        generated_source_path="mmaudit-echidna/MMAuditEchidna.sol",
    )
    if not translation.property_map or translation.seed is None:
        return translation
    return replace(
        translation,
        configuration=_render_configuration(
            seed=translation.seed,
            runs=translation.runs,
            depth=translation.depth,
            timeout_seconds=timeout_seconds,
        ),
        configuration_path="mmaudit-echidna/echidna.yaml",
        property_map_path="mmaudit-echidna/property-map.json",
    )


def translate_property_corpus(
    corpus: PropertyCorpus,
    index: SoliditySymbolIndex,
    *,
    harness_contract_name: str,
    property_prefix: str,
    engine_name: str,
    generated_source_path: str,
    assert_predicates: bool = False,
    uses_campaign_seed: bool = True,
) -> PropertyEngineTranslation:
    """Build engine-neutral Solidity for one bounded property campaign."""

    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", harness_contract_name) is None:
        raise ValueError("generated harness contract name is invalid")
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", property_prefix) is None:
        raise ValueError("generated property prefix is invalid")
    normalized_generated_path = normalize_relative_path(generated_source_path)
    if not normalized_generated_path.endswith(".sol"):
        raise ValueError("generated property source path must be Solidity")
    entities_by_contract: dict[str, list[SolidityEntity]] = {}
    contracts: dict[str, SolidityEntity] = {}
    for entity in index.entities:
        if entity.contract_name:
            entities_by_contract.setdefault(entity.contract_name, []).append(entity)
        if entity.kind is SolidityEntityKind.CONTRACT:
            contracts.setdefault(entity.name, entity)

    reserved_names = {"MMAuditPropertyActor", harness_contract_name}
    collisions = sorted(reserved_names.intersection(contracts))
    if collisions:
        return PropertyEngineTranslation(
            source="",
            configuration="",
            property_map={},
            limitations=sorted(
                {
                    *corpus.limitations,
                    (f"{engine_name} generated contract name collision: {', '.join(collisions)}"),
                }
            ),
            seed=None,
            runs=0,
            depth=0,
            source_path=normalized_generated_path,
        )

    limitations: list[str] = []
    translated: list[_TranslatedProperty] = []
    campaign: tuple[int, int, int] | None = None
    for property_spec in corpus.properties:
        reason = _unsupported_reason(
            property_spec,
            contracts,
            entities_by_contract,
            engine_name=engine_name,
        )
        if reason is not None:
            limitations.append(f"{property_spec.id}: {reason}")
            continue
        current_campaign = (
            property_spec.campaign.seed if uses_campaign_seed else 0,
            property_spec.campaign.runs,
            property_spec.campaign.depth,
        )
        if uses_campaign_seed and property_spec.campaign.seed > 2**63 - 1:
            limitations.append(
                f"{property_spec.id}: {engine_name} seed exceeds signed 64-bit range"
            )
            continue
        if campaign is not None and current_campaign != campaign:
            limitations.append(
                f"{property_spec.id}: campaign seed/runs/depth differ from this invocation"
            )
            continue
        campaign = current_campaign
        alias = property_spec.target_aliases[0]
        translated.append(
            _TranslatedProperty(
                property_spec=property_spec,
                generated_name=f"{property_prefix}_{property_spec.property_hash[:24]}",
                target=contracts[alias],
                prefix=property_spec.property_hash[:12],
            )
        )

    translated.sort(key=lambda item: item.generated_name)
    limitations = sorted(set([*corpus.limitations, *limitations]))
    if not translated or campaign is None:
        return PropertyEngineTranslation(
            source="",
            configuration="",
            property_map={},
            limitations=limitations,
            seed=None,
            runs=0,
            depth=0,
            source_path=normalized_generated_path,
        )

    seed, runs, depth = campaign
    return PropertyEngineTranslation(
        source=_render_source(
            translated,
            harness_contract_name,
            generated_source_path=normalized_generated_path,
            assert_predicates=assert_predicates,
        ),
        configuration="",
        property_map={item.generated_name: item.property_spec for item in translated},
        limitations=limitations,
        seed=seed,
        runs=runs,
        depth=depth,
        source_path=normalized_generated_path,
    )


def _unsupported_reason(
    property_spec: DynamicPropertySpec,
    contracts: dict[str, SolidityEntity],
    entities_by_contract: dict[str, list[SolidityEntity]],
    *,
    engine_name: str,
) -> str | None:
    if len(property_spec.target_aliases) != 1:
        return "translation currently requires exactly one locally deployable target alias"
    alias = property_spec.target_aliases[0]
    contract = contracts.get(alias)
    if contract is None:
        return f"target alias {alias} does not resolve to an indexed contract"
    try:
        normalized_path = normalize_relative_path(contract.path)
    except ValueError:
        return "target source path is unsafe"
    if re.fullmatch(r"[A-Za-z0-9_./-]+\.sol", normalized_path) is None:
        return "target source path cannot be represented in generated Solidity"
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", contract.name) is None:
        return "target contract name cannot be represented in generated Solidity"
    if contract.path not in {evidence.location.path for evidence in property_spec.source_evidence}:
        return "target contract path lacks exact property source evidence"
    constructors = [
        entity
        for entity in entities_by_contract.get(alias, [])
        if entity.kind is SolidityEntityKind.CONSTRUCTOR
    ]
    if any(entity.signature not in {None, "constructor()"} for entity in constructors):
        return "target constructor requires unsupported deployment arguments"
    if property_spec.token_balance_seeds:
        return f"generic {engine_name} translation cannot safely synthesize ERC20 storage balances"
    if property_spec.campaign.maximum_call_value_wei:
        return f"value-bearing calls are outside the current {engine_name} translation subset"
    if property_spec.campaign.maximum_time_shift_seconds:
        return f"time-shifting actions are outside the current {engine_name} translation subset"
    if property_spec.campaign.transaction_ordering is not TransactionOrderingCapability.NONE:
        return f"ordered transaction capabilities are outside the current {engine_name} subset"
    if any(call.value_wei for call in property_spec.setup_calls):
        return "value-bearing setup calls are unsupported"
    if any(
        action.value_wei or action.time_shift_seconds_before for action in property_spec.actions
    ):
        return "value-bearing or time-shifting actions are unsupported"
    used_targets = {
        *(call.target for call in property_spec.setup_calls),
        *(action.target for action in property_spec.actions),
        property_spec.predicate.left.target,
        *(
            [property_spec.predicate.right.target]
            if property_spec.predicate.right is not None
            else []
        ),
    }
    if used_targets != {alias}:
        return "every setup, action, and probe must use the single local target"
    actor_fields = {
        key: "actor" for actor in property_spec.actors for key in (actor.name, actor.address)
    }
    constant_arguments = [
        *(argument for call in property_spec.setup_calls for argument in call.arguments),
        *property_spec.predicate.left.arguments,
        *(
            property_spec.predicate.right.arguments
            if property_spec.predicate.right is not None
            else []
        ),
        *(
            ForkArgument(kind=argument.kind, value=argument.value or "")
            for action in property_spec.actions
            for argument in action.arguments
            if argument.source is HarnessArgumentSource.CONSTANT
        ),
    ]
    try:
        for argument in constant_arguments:
            _constant_expression(argument, actor_fields)
    except (TypeError, ValueError):
        return "a constant argument cannot be represented safely in generated Solidity"
    return None


def _render_source(
    properties: list[_TranslatedProperty],
    harness_contract_name: str,
    *,
    generated_source_path: str,
    assert_predicates: bool,
) -> str:
    imports = sorted({normalize_relative_path(item.target.path) for item in properties})
    generated_parent = PurePosixPath(generated_source_path).parent.as_posix()
    relative_imports = [
        posixpath.relpath(path, start=generated_parent if generated_parent != "." else ".")
        for path in imports
    ]
    relative_imports = [path if path.startswith(".") else f"./{path}" for path in relative_imports]
    lines = [
        "// SPDX-License-Identifier: UNLICENSED",
        "pragma solidity ^0.8.20;",
        "",
        *[f'import "{path}";' for path in relative_imports],
        "",
        "contract MMAuditPropertyActor {",
        "    function execute(address target, bytes memory data) external returns (bool) {",
        "        (bool ok,) = target.call(data);",
        "        return ok;",
        "    }",
        "}",
        "",
        f"contract {harness_contract_name} {{",
    ]
    for item in properties:
        lines.extend(_property_fields(item))
    lines.extend(["", "    constructor() {"])
    for item in properties:
        lines.extend(_property_constructor(item))
    lines.extend(["    }", ""])
    for item in properties:
        lines.extend(_property_functions(item, assert_predicate=assert_predicates))
    lines.extend(["}", ""])
    return "\n".join(lines)


def _property_fields(item: _TranslatedProperty) -> list[str]:
    prop = item.property_spec
    fields = [
        f"    {item.target.name} private target_{item.prefix};",
        *[
            f"    MMAuditPropertyActor private actor_{item.prefix}_{_identifier(actor.name)};"
            for actor in prop.actors
        ],
    ]
    if prop.predicate.compare_to_initial:
        fields.append(f"    uint256 private initial_{item.prefix};")
    return fields


def _property_constructor(item: _TranslatedProperty) -> list[str]:
    prop = item.property_spec
    lines = [
        f"        target_{item.prefix} = new {item.target.name}();",
        *[
            f"        actor_{item.prefix}_{_identifier(actor.name)} = new MMAuditPropertyActor();"
            for actor in prop.actors
        ],
    ]
    actor_fields = _actor_fields(item)
    for call in prop.setup_calls:
        arguments = ", ".join(
            _constant_expression(argument, actor_fields) for argument in call.arguments
        )
        encoded = _encode_call(call.function_signature, arguments)
        actor = actor_fields[call.actor]
        lines.extend(
            [
                "        require(",
                f"            {actor}.execute(address(target_{item.prefix}), {encoded}),",
                f'            "setup {call.step_id}"',
                "        );",
            ]
        )
    if prop.predicate.compare_to_initial:
        helper = f"_probe_{item.prefix}_left"
        lines.extend(
            [
                f"        (bool initialOk, uint256 initialValue) = {helper}();",
                '        require(initialOk, "initial property probe");',
                f"        initial_{item.prefix} = initialValue;",
            ]
        )
    return lines


def _property_functions(
    item: _TranslatedProperty,
    *,
    assert_predicate: bool,
) -> list[str]:
    prop = item.property_spec
    lines: list[str] = []
    actor_fields = _actor_fields(item)
    needs_actor_choice = any(
        argument.source is HarnessArgumentSource.ACTOR
        for action in prop.actions
        for argument in action.arguments
    )
    if needs_actor_choice:
        lines.extend(_actor_selector(item))
    for action in prop.actions:
        for actor_name in action.actor_names:
            parameters = _action_parameters(action.arguments)
            expressions = [
                _harness_argument_expression(argument, item, actor_fields)
                for argument in action.arguments
            ]
            arguments = ", ".join(expressions)
            encoded = _encode_call(action.function_signature, arguments)
            function_name = _identifier(f"mmaudit_{item.prefix}_{action.action_id}_{actor_name}")[
                :63
            ]
            lines.extend(
                [
                    f"    function {function_name}({', '.join(parameters)}) public {{",
                    f"        {actor_fields[actor_name]}.execute(",
                    f"            address(target_{item.prefix}),",
                    f"            {encoded}",
                    "        );",
                    "    }",
                    "",
                ]
            )
    lines.extend(_probe_function(item, prop.predicate.left, "left"))
    if prop.predicate.right is not None:
        lines.extend(_probe_function(item, prop.predicate.right, "right"))
    lines.extend(_property_function(item, assert_predicate=assert_predicate))
    return lines


def _actor_selector(item: _TranslatedProperty) -> list[str]:
    actors = item.property_spec.actors
    lines = [
        f"    function _actor_{item.prefix}(uint8 choice) internal view returns (address) {{",
    ]
    for position, actor in enumerate(actors[:-1]):
        lines.append(
            f"        if (choice % {len(actors)} == {position}) "
            f"return address(actor_{item.prefix}_{_identifier(actor.name)});"
        )
    final = actors[-1]
    lines.extend(
        [
            f"        return address(actor_{item.prefix}_{_identifier(final.name)});",
            "    }",
            "",
        ]
    )
    return lines


def _probe_function(
    item: _TranslatedProperty,
    probe: InvariantProbe,
    side: str,
) -> list[str]:
    actor_fields = _actor_fields(item)
    arguments = ", ".join(
        _constant_expression(argument, actor_fields) for argument in probe.arguments
    )
    encoded = _encode_call(probe.function_signature, arguments)
    return [
        f"    function _probe_{item.prefix}_{side}()",
        "        internal",
        "        view",
        "        returns (bool ok, uint256 value)",
        "    {",
        "        bytes memory data;",
        f"        (ok, data) = address(target_{item.prefix}).staticcall({encoded});",
        "        if (!ok || data.length < 32) return (false, 0);",
        "        value = abi.decode(data, (uint256));",
        "    }",
        "",
    ]


def _property_function(
    item: _TranslatedProperty,
    *,
    assert_predicate: bool,
) -> list[str]:
    predicate = item.property_spec.predicate
    declaration = (
        f"    function {item.generated_name}() public view {{"
        if assert_predicate
        else f"    function {item.generated_name}() public view returns (bool) {{"
    )
    lines = [
        declaration,
        f"        (bool leftOk, uint256 leftValue) = _probe_{item.prefix}_left();",
        "        assert(leftOk);" if assert_predicate else "        if (!leftOk) return false;",
    ]
    if predicate.right is not None:
        lines.extend(
            [
                f"        (bool rightOk, uint256 rightValue) = _probe_{item.prefix}_right();",
                (
                    "        assert(rightOk);"
                    if assert_predicate
                    else "        if (!rightOk) return false;"
                ),
            ]
        )
        operand = "rightValue"
    elif predicate.expected_uint is not None:
        operand = str(predicate.expected_uint)
    else:
        operand = f"initial_{item.prefix}"
    relation = {
        InvariantRelation.EQ: "==",
        InvariantRelation.GTE: ">=",
        InvariantRelation.LTE: "<=",
    }[predicate.relation]
    statement = (
        f"        assert(leftValue {relation} {operand});"
        if assert_predicate
        else f"        return leftValue {relation} {operand};"
    )
    lines.extend([statement, "    }", ""])
    return lines


def _action_parameters(arguments: list[HarnessArgument]) -> list[str]:
    parameters: dict[int, str] = {}
    for argument in arguments:
        if argument.source is HarnessArgumentSource.FUZZ_UINT and argument.fuzz_slot is not None:
            parameters[argument.fuzz_slot] = f"uint256 fuzz{argument.fuzz_slot}"
        elif argument.source is HarnessArgumentSource.ACTOR and argument.fuzz_slot is not None:
            parameters[argument.fuzz_slot] = f"uint8 fuzz{argument.fuzz_slot}"
    return [parameters[slot] for slot in sorted(parameters)]


def _harness_argument_expression(
    argument: HarnessArgument,
    item: _TranslatedProperty,
    actor_fields: dict[str, str],
) -> str:
    if argument.source is HarnessArgumentSource.CONSTANT:
        assert argument.value is not None
        return _constant_expression(
            ForkArgument(kind=argument.kind, value=argument.value),
            actor_fields,
        )
    assert argument.fuzz_slot is not None
    if argument.source is HarnessArgumentSource.ACTOR:
        return f"_actor_{item.prefix}(fuzz{argument.fuzz_slot})"
    assert argument.minimum is not None and argument.maximum is not None
    if argument.minimum == 0 and argument.maximum == _MAX_UINT256:
        return f"fuzz{argument.fuzz_slot}"
    span = argument.maximum - argument.minimum + 1
    return f"{argument.minimum} + (fuzz{argument.fuzz_slot} % {span})"


def _constant_expression(argument: ForkArgument, actor_fields: dict[str, str]) -> str:
    value = argument.value
    if argument.kind is ForkArgumentKind.UINT256:
        parsed = int(value, 0)
        if not 0 <= parsed <= _MAX_UINT256:
            raise ValueError("uint256 constant is out of range")
        return str(parsed)
    if argument.kind is ForkArgumentKind.INT256:
        parsed = int(value, 0)
        if not -(2**255) <= parsed <= 2**255 - 1:
            raise ValueError("int256 constant is out of range")
        return str(parsed)
    if argument.kind is ForkArgumentKind.ADDRESS:
        for actor_name, field in actor_fields.items():
            if actor_name.startswith("0x") and actor_name.casefold() == value.casefold():
                return f"address({field})"
        if re.fullmatch(r"0x[0-9a-fA-F]{40}", value) is None:
            raise ValueError("address constant is invalid")
        return f"address({value})"
    if argument.kind is ForkArgumentKind.BOOL:
        if value not in {"true", "false"}:
            raise ValueError("bool constant is invalid")
        return value
    if argument.kind is ForkArgumentKind.BYTES32:
        if re.fullmatch(r"0x[0-9a-fA-F]{64}", value) is None:
            raise ValueError("bytes32 constant is invalid")
        return value
    if argument.kind is ForkArgumentKind.BYTES:
        if re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value) is None:
            raise ValueError("bytes constant is invalid")
        return f'hex"{value[2:]}"'
    return json.dumps(value)


def _actor_fields(item: _TranslatedProperty) -> dict[str, str]:
    fields: dict[str, str] = {}
    for actor in item.property_spec.actors:
        field = f"actor_{item.prefix}_{_identifier(actor.name)}"
        fields[actor.name] = field
        fields[actor.address] = field
    return fields


def _encode_call(signature: str, arguments: str) -> str:
    suffix = f", {arguments}" if arguments else ""
    return f'abi.encodeWithSignature("{signature}"{suffix})'


def _render_configuration(
    *,
    seed: int,
    runs: int,
    depth: int,
    timeout_seconds: float,
) -> str:
    return "\n".join(
        (
            "testMode: property",
            f"testLimit: {runs}",
            f"seqLen: {depth}",
            f"seed: {seed}",
            f"timeout: {max(1, int(timeout_seconds))}",
            "shrinkLimit: 5000",
            'corpusDir: "mmaudit-echidna/corpus"',
            "",
        )
    )


def _identifier(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "Generated_" + cleaned
    return cleaned
