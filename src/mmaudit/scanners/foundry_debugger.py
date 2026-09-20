"""Bounded original compiler/machine/debugger joins, without execution authority.

Debugger observations do not represent a complete fuzz population or prove an
atomic Solidity statement executed. Original process/isolation custody remains
the caller's responsibility. Unknown code and source locations stay explicit.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Literal

from pydantic import ConfigDict, Field

from mmaudit.models.schemas import (
    RepositorySuiteFramework,
    RepositorySuiteTestDescriptor,
    StrictModel,
)
from mmaudit.scanners.foundry_inventory import (
    FoundrySourceInput,
    _decode_json_object,
    _normalized_source_path,
)
from mmaudit.scanners.foundry_statement_coverage import (
    SolcBytecodeMap,
    parse_solc_bytecode_source_map,
)
from mmaudit.scanners.solc_capture import CapturedSolcInvocation
from mmaudit.solidity.compiler_source import CompilerSourceMap


class FoundryDebuggerError(ValueError):
    """Original debugger evidence is malformed, incomplete or contradictory."""


class FoundryDebuggerLimits(StrictModel):
    """Finite parser resources, unrelated to cost, ledger or execution policy."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    max_artifact_bytes: int = Field(default=16_000_000, ge=1, le=64_000_000)
    max_total_bytes: int = Field(default=64_000_000, ge=1, le=128_000_000)
    max_json_nodes: int = Field(default=1_000_000, ge=1, le=2_000_000)
    max_json_depth: int = Field(default=64, ge=1, le=128)
    max_call_depth: int = Field(default=128, ge=1, le=256)
    max_compiler_calls: int = Field(default=128, ge=1, le=128)
    max_sources: int = Field(default=10_000, ge=1, le=10_000)
    max_contracts: int = Field(default=10_000, ge=1, le=10_000)
    max_frames: int = Field(default=10_000, ge=1, le=100_000)
    max_steps: int = Field(default=500_000, ge=1, le=1_000_000)
    max_compiler_instructions: int = Field(default=1_000_000, ge=1, le=2_000_000)


@dataclass(frozen=True, slots=True)
class DebuggerSourceBinding:
    source_id: int
    path: str
    mapping: CompilerSourceMap = field(repr=False)


@dataclass(frozen=True, slots=True)
class DebuggerCompilerUnit:
    """Original compiler identity; unresolved link placeholders are refused."""

    unit_id: str
    invocation_sequence: int
    source_path: str
    contract_name: str
    input_sha256: str
    output_sha256: str
    creation_bytecode: bytes | None = field(repr=False)
    runtime_bytecode: bytes | None = field(repr=False)
    creation_map: SolcBytecodeMap | None = field(repr=False)
    runtime_map: SolcBytecodeMap | None = field(repr=False)
    sources: tuple[DebuggerSourceBinding, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class DebuggerStepObservation:
    ordinal: int
    frame_index: int
    frame_step_index: int
    raw_step_sha256: str
    pc: int
    opcode: int
    phase: Literal["CREATION", "RUNTIME"]
    code_unit_id: str | None
    unresolved_code_reason: str | None
    source_id: int | None
    source_path: str | None
    compiler_span: tuple[int, int] | None
    original_span: tuple[int, int] | None
    modifier_depth: int | None


@dataclass(frozen=True, slots=True)
class DebuggerFrameObservation:
    arena_label: str
    arena_index: int
    frame_index: int
    parent_index: int | None
    children: tuple[int, ...]
    kind: str
    address: str
    succeeded: bool
    step_count: int
    frame_sha256: str


@dataclass(frozen=True, slots=True)
class FoundryDebuggerObservation:
    """Immutable diagnostic data, not a receipt accepted by any coverage gate."""

    descriptor_sha256: str
    machine_stdout_sha256: str
    debugger_dump_sha256: str
    debugger_annotations_sha256: str
    compiler_transcript_sha256s: tuple[str, ...]
    compiler_units: tuple[DebuggerCompilerUnit, ...]
    frames: tuple[DebuggerFrameObservation, ...]
    steps: tuple[DebuggerStepObservation, ...]
    test_status: str
    test_kind_sha256: str
    annotation_scope: Literal["HASHED_NOT_USED_FOR_CODE_OR_SOURCE_BINDING"] = field(
        default="HASHED_NOT_USED_FOR_CODE_OR_SOURCE_BINDING", init=False
    )
    execution_scope: Literal["ONE_DEBUGGER_TRACE_NOT_FULL_TEST_OR_FUZZ_POPULATION"] = field(
        default="ONE_DEBUGGER_TRACE_NOT_FULL_TEST_OR_FUZZ_POPULATION",
        init=False,
    )
    evidence_authority: Literal["UNATTESTED_DEBUGGER_OBSERVATION"] = field(
        default="UNATTESTED_DEBUGGER_OBSERVATION",
        init=False,
    )

    def require_code_bound_steps(self) -> None:
        """Refuse unresolved code; this never verifies source/statement coverage."""
        if not self.steps or any(step.unresolved_code_reason is not None for step in self.steps):
            raise FoundryDebuggerError("debugger steps have unresolved compiler code identities")


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _object(value: Any, label: str, keys: set[str] | None = None) -> dict[str, Any]:
    if type(value) is not dict or (keys is not None and set(value) != keys):
        raise FoundryDebuggerError(f"{label} has an unsupported object shape")
    return value


def _array(value: Any, label: str, maximum: int) -> list[Any]:
    if type(value) is not list or len(value) > maximum:
        raise FoundryDebuggerError(f"{label} is not a bounded array")
    return value


def _integer(value: Any, label: str, maximum: int = 2**64 - 1, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise FoundryDebuggerError(f"{label} is not an exact bounded integer")
    return value


def _hex(value: Any, label: str, maximum: int) -> bytes:
    if (
        type(value) is not str
        or len(value) > maximum * 2 + 2
        or re.fullmatch(r"0x(?:[0-9a-f]{2})*", value) is None
    ):
        raise FoundryDebuggerError(f"{label} is not bounded byte hex")
    return bytes.fromhex(value[2:])


def _address(value: Any) -> str:
    if type(value) is not str or len(_hex(value, "address", 20)) != 20:
        raise FoundryDebuggerError("debugger address is not exactly20 bytes")
    return value


def _decode(raw: bytes, label: str, limits: FoundryDebuggerLimits) -> dict[str, Any]:
    value = _decode_json_object(raw, label=label, maximum_bytes=limits.max_artifact_bytes)
    pending: list[tuple[Any, int]] = [(value, 1)]
    visited = 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if visited > limits.max_json_nodes or depth > limits.max_json_depth:
            raise FoundryDebuggerError("debugger JSON exceeds its node/depth ceiling")
        if type(item) is dict:
            pending.extend((v, depth + 1) for pair in item.items() for v in pair)
        elif type(item) is list:
            pending.extend((v, depth + 1) for v in item)
        elif type(item) is str:
            item.encode("utf-8", errors="strict")
    return value


def _compiler_units(
    calls: tuple[CapturedSolcInvocation, ...],
    sources: tuple[FoundrySourceInput, ...],
    limits: FoundryDebuggerLimits,
    reserved_bytes: int,
) -> tuple[DebuggerCompilerUnit, ...]:
    if type(calls) is not tuple or not 1 <= len(calls) <= limits.max_compiler_calls:
        raise FoundryDebuggerError("compiler invocation population is invalid")
    if type(sources) is not tuple or not 1 <= len(sources) <= limits.max_sources:
        raise FoundryDebuggerError("original source population is invalid")
    original: dict[str, bytes] = {}
    for source in sources:
        if (
            type(source) is not FoundrySourceInput
            or type(source.content) is not bytes
            or len(source.content) > limits.max_artifact_bytes
            or _hash(source.content) != source.source_sha256
            or _normalized_source_path(source.path) != source.path
            or source.path in original
        ):
            raise FoundryDebuggerError("original source identity is invalid or duplicate")
        original[source.path] = source.content
    if tuple(original) != tuple(sorted(original)):
        raise FoundryDebuggerError("original source paths are not sorted")
    observed_sources: set[str] = set()
    total_bytes = reserved_bytes + sum(len(raw) for raw in original.values())
    result: list[DebuggerCompilerUnit] = []
    mapped_count = 0
    contract_count = 0
    for index, call in enumerate(calls):
        if (
            type(call) is not CapturedSolcInvocation
            or type(call.sequence) is not int
            or call.sequence != index
            or call.evidence_authority != "UNATTESTED_COMPILER_TRANSCRIPT"
            or type(call.compiler_exit_code) is not int
            or call.compiler_exit_code != 0
            or re.fullmatch(r"[0-9a-f]{64}", call.transcript_sha256) is None
        ):
            raise FoundryDebuggerError("compiler invocation identity/status differs")
        for argv in (call.received_argv, call.compiler_argv):
            if (
                type(argv) is not tuple
                or not 1 <= len(argv) <= 128
                or any(type(a) is not str or len(a) > 8192 or "\0" in a for a in argv)
            ):
                raise FoundryDebuggerError("compiler invocation arguments are invalid")
        for raw in (call.stdin, call.stdout, call.stderr):
            if type(raw) is not bytes or len(raw) > limits.max_artifact_bytes:
                raise FoundryDebuggerError("compiler stream exceeds its parser bound")
            total_bytes += len(raw)
        if total_bytes > limits.max_total_bytes:
            raise FoundryDebuggerError(
                "compiler/source population exceeds its aggregate byte bound"
            )
        if not call.stdin:
            if call.compiler_argv != ("--version",):
                raise FoundryDebuggerError("empty compiler input is not a version observation")
            continue
        if (
            "--standard-json" not in call.compiler_argv
            or call.compiler_argv[-1] != "--no-import-callback"
        ):
            raise FoundryDebuggerError("compiler invocation lacks closed literal input")
        incoming = _decode(call.stdin, "compiler input", limits)
        outgoing = _decode(call.stdout, "compiler output", limits)
        if incoming.get("language") != "Solidity":
            raise FoundryDebuggerError("debugger compiler input is not Solidity")
        supplied = _object(incoming.get("sources"), "compiler sources")
        emitted = _object(outgoing.get("sources"), "compiler source IDs")
        if not supplied or set(supplied) != set(emitted) or not set(supplied) <= set(original):
            raise FoundryDebuggerError("compiler input/output source population differs")
        if len(supplied) > limits.max_sources:
            raise FoundryDebuggerError("compiler source count exceeds its limit")
        for error in _array(outgoing.get("errors", []), "compiler errors", limits.max_json_nodes):
            if _object(error, "compiler error").get("severity") == "error":
                raise FoundryDebuggerError("compiler output contains an error")
        bound_sources: list[DebuggerSourceBinding] = []
        for path in sorted(supplied):
            literal = _object(supplied[path], "literal source", {"content"})["content"]
            if type(literal) is not str:
                raise FoundryDebuggerError("compiler literal source is not text")
            source_id = _integer(_object(emitted[path], "source ID").get("id"), "source ID")
            bound_sources.append(
                DebuggerSourceBinding(
                    source_id,
                    path,
                    CompilerSourceMap(original[path], literal.encode("utf-8")),
                )
            )
        if len({s.source_id for s in bound_sources}) != len(bound_sources):
            raise FoundryDebuggerError("compiler source IDs are not one-to-one")
        observed_sources.update(supplied)
        contracts = _object(outgoing.get("contracts", {}), "compiled contracts")
        if not set(contracts) <= set(supplied):
            raise FoundryDebuggerError("compiled contract path is not a supplied source")
        for path, members in contracts.items():
            for name, contract in _object(members, "source contracts").items():
                contract_count += 1
                if contract_count > limits.max_contracts:
                    raise FoundryDebuggerError("compiler contract population exceeds its bound")
                if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]{0,999}", name) is None:
                    raise FoundryDebuggerError("compiler contract name is unsupported")
                contract = _object(contract, "contract")
                if "evm" not in contract:
                    # ABI-only output is retained in calls, not counted as executable code.
                    if set(contract) != {"abi"}:
                        raise FoundryDebuggerError("compiler output has no recognized code or ABI")
                    continue
                evm = _object(contract["evm"], "compiler EVM object")
                bytecodes: list[bytes | None] = []
                maps: list[SolcBytecodeMap | None] = []
                for key in ("bytecode", "deployedBytecode"):
                    value = _object(evm.get(key), "compiler bytecode")
                    obj, source_map = value.get("object"), value.get("sourceMap")
                    if type(obj) is not str or type(source_map) is not str:
                        raise FoundryDebuggerError("compiler bytecode/map fields are unavailable")
                    if _object(value.get("linkReferences", {}), "compiler link references"):
                        raise FoundryDebuggerError("unresolved compiler link references")
                    code = _hex("0x" + obj, "compiler bytecode", limits.max_artifact_bytes)
                    if not code:
                        if source_map:
                            raise FoundryDebuggerError("empty compiler bytecode has a source map")
                        mapped = None
                    else:
                        # Refuse the full population before expanding compressed rows.
                        mapped_count += source_map.count(";") + 1
                        if mapped_count > limits.max_compiler_instructions:
                            raise FoundryDebuggerError(
                                "compiler instruction population exceeds its bound"
                            )
                        mapped = parse_solc_bytecode_source_map(code, source_map)
                    bytecodes.append(code)
                    maps.append(mapped)
                result.append(
                    DebuggerCompilerUnit(
                        f"{index}:{path}:{name}",
                        index,
                        path,
                        name,
                        _hash(call.stdin),
                        _hash(call.stdout),
                        bytecodes[0],
                        bytecodes[1],
                        maps[0],
                        maps[1],
                        tuple(bound_sources),
                    )
                )
    if observed_sources != set(original) or not result:
        raise FoundryDebuggerError(
            "compiler calls lack the complete original source/code population"
        )
    return tuple(result)


_STEP_KEYS = {
    "contract",
    "decoded",
    "depth",
    "gas_cost",
    "gas_refund_counter",
    "gas_remaining",
    "gas_used",
    "immediate_bytes",
    "memory",
    "op",
    "pc",
    "push_stack",
    "returndata",
    "stack",
    "status",
    "storage_change",
}
_TRACE_KEYS = {
    "address",
    "caller",
    "data",
    "decoded",
    "depth",
    "gas_limit",
    "gas_used",
    "kind",
    "maybe_precompile",
    "output",
    "selfdestruct_address",
    "selfdestruct_refund_target",
    "selfdestruct_transferred_value",
    "status",
    "steps",
    "success",
    "value",
}
_CALL_KINDS = {"CALL", "STATICCALL", "CALLCODE", "DELEGATECALL", "CREATE", "CREATE2"}


def _step(value: Any, trace: dict[str, Any], limits: FoundryDebuggerLimits) -> dict[str, Any]:
    step = _object(value, "debugger step", _STEP_KEYS)
    if _address(step["contract"]) != trace["address"]:
        raise FoundryDebuggerError("step contract differs from its frame")
    if _integer(step["depth"], "step depth", limits.max_call_depth + 1) != trace["depth"] + 1:
        raise FoundryDebuggerError("step depth differs from its frame")
    _integer(step["pc"], "step PC")
    opcode = _integer(step["op"], "step opcode", 255)
    size = opcode - 0x5F if 0x60 <= opcode <= 0x7F else 0
    if (size == 0 and step["immediate_bytes"] is not None) or (
        size and len(_hex(step["immediate_bytes"], "PUSH operand", 32)) != size
    ):
        raise FoundryDebuggerError("step PUSH operand width differs")
    for name in ("gas_cost", "gas_remaining", "gas_used"):
        _integer(step[name], name)
    _integer(step["gas_refund_counter"], "gas refund", 2**63 - 1, -(2**63))
    for name in ("memory", "returndata"):
        _hex(step[name], name, limits.max_artifact_bytes)
    for name in ("stack", "push_stack"):
        if name == "push_stack" and step[name] is None:
            continue
        for word in _array(step[name], name, 1024):
            if type(word) is not str or re.fullmatch(r"0x[0-9a-f]{1,64}", word) is None:
                raise FoundryDebuggerError("step stack word is not a bounded EVM quantity")
    return step


def _arena(value: Any, limits: FoundryDebuggerLimits) -> list[dict[str, Any]]:
    nodes = _array(
        _object(value, "trace arena", {"arena"})["arena"], "call frames", limits.max_frames
    )
    if not nodes:
        raise FoundryDebuggerError("trace arena has no root")
    owned: set[int] = set()
    step_count = 0
    for i, node in enumerate(nodes):
        node = _object(
            node, "call frame", {"parent", "children", "idx", "trace", "logs", "ordering"}
        )
        if _integer(node["idx"], "frame index", len(nodes) - 1) != i:
            raise FoundryDebuggerError("call frame indices are not canonical")
        trace = _object(node["trace"], "call trace", _TRACE_KEYS)
        depth = _integer(trace["depth"], "frame depth", limits.max_call_depth)
        if i == 0:
            if node["parent"] is not None or depth != 0:
                raise FoundryDebuggerError("trace root parent/depth differs")
        else:
            parent = _integer(node["parent"], "frame parent", i - 1)
            if nodes[parent]["trace"]["depth"] + 1 != depth:
                raise FoundryDebuggerError("call depth differs from its parent")
        _address(trace["address"])
        _address(trace["caller"])
        if trace["kind"] not in _CALL_KINDS or type(trace["success"]) is not bool:
            raise FoundryDebuggerError("call kind/status is unsupported")
        for name in ("data", "output"):
            _hex(trace[name], name, limits.max_artifact_bytes)
        children = _array(node["children"], "call children", limits.max_frames)
        for child in children:
            _integer(child, "child index", len(nodes) - 1, i + 1)
            if child in owned or nodes[child].get("parent") != i:
                raise FoundryDebuggerError("call child ownership is duplicate or contradictory")
            owned.add(child)
        steps = _array(trace["steps"], "frame steps", limits.max_steps)
        step_count += len(steps)
        if step_count > limits.max_steps:
            raise FoundryDebuggerError("trace step population exceeds its bound")
        for step in steps:
            _step(step, trace, limits)
        logs = _array(node["logs"], "frame logs", limits.max_json_nodes)
        order = _array(node["ordering"], "frame ordering", limits.max_json_nodes)
        counters = {"Step": 0, "Call": 0, "Log": 0}
        for event in order:
            event = _object(event, "ordering event")
            if len(event) != 1 or not set(event) <= set(counters):
                raise FoundryDebuggerError("ordering event kind is unsupported")
            kind, index = next(iter(event.items()))
            if _integer(index, "ordering index") != counters[kind]:
                raise FoundryDebuggerError("frame order skips, repeats or reorders an event")
            counters[kind] += 1
        if counters != {"Step": len(steps), "Call": len(children), "Log": len(logs)}:
            raise FoundryDebuggerError("frame ordering does not cover its complete population")
    if owned != set(range(1, len(nodes))):
        raise FoundryDebuggerError("trace arena contains orphaned frames")
    return nodes


def _segments(nodes: list[dict[str, Any]], index: int = 0) -> list[tuple[int, tuple[int, ...]]]:
    """Project the complete machine event order into uninterrupted debugger segments."""
    result: list[tuple[int, tuple[int, ...]]] = []
    pending: list[int] = []
    node = nodes[index]
    for event in node["ordering"]:
        if "Step" in event:
            pending.append(event["Step"])
        elif "Call" in event:
            if pending:
                result.append((index, tuple(pending)))
                pending.clear()
            result.extend(_segments(nodes, node["children"][event["Call"]]))
    if pending:
        result.append((index, tuple(pending)))
    return result


def _match_dump(
    dump: dict[str, Any],
    nodes: list[dict[str, Any]],
    limits: FoundryDebuggerLimits,
) -> tuple[tuple[int, int], ...]:
    _object(dump, "debugger dump", {"contracts", "debug_arena"})
    annotations = _object(
        dump["contracts"], "debugger contract annotations", {"identified_contracts", "sources"}
    )
    # Names and rendered maps are not bytecode identities. Retain their exact
    # hash, but derive every location from the original compiler output instead.
    for key in ("identified_contracts", "sources"):
        _object(annotations[key], "debugger annotation table")
    segments = _segments(nodes)
    reported = _array(dump["debug_arena"], "debugger segments", limits.max_steps)
    if len(reported) != len(segments):
        raise FoundryDebuggerError("debugger segment population differs from machine ordering")
    ordered: list[tuple[int, int]] = []
    for (frame, indices), segment in zip(segments, reported, strict=True):
        segment = _object(segment, "debugger segment", {"address", "kind", "calldata", "steps"})
        trace = nodes[frame]["trace"]
        calldata = "0x" if trace["kind"] in {"CREATE", "CREATE2"} else trace["data"]
        if (segment["address"], segment["kind"], segment["calldata"]) != (
            trace["address"],
            trace["kind"],
            calldata,
        ):
            raise FoundryDebuggerError("debugger segment differs from its exact machine call")
        steps = _array(segment["steps"], "debugger segment steps", limits.max_steps)
        expected = [trace["steps"][i] for i in indices]
        if _canonical(steps) != _canonical(expected):
            raise FoundryDebuggerError("debugger step bytes differ from complete machine ordering")
        ordered.extend((frame, i) for i in indices)
    if not ordered:
        raise FoundryDebuggerError("debugger has no observed execution steps")
    return tuple(ordered)


def _frame_bindings(
    arenas: list[tuple[str, list[dict[str, Any]]]],
    units: tuple[DebuggerCompilerUnit, ...],
) -> dict[int, tuple[DebuggerCompilerUnit, ...]]:
    """Publish code only after successful creation; unwind publications on ancestor revert."""
    deployed: dict[str, tuple[DebuggerCompilerUnit, ...]] = {}
    journal: list[tuple[str, tuple[DebuggerCompilerUnit, ...] | None]] = []
    execution: dict[int, tuple[DebuggerCompilerUnit, ...]] = {}

    def publish(address: str, candidates: tuple[DebuggerCompilerUnit, ...]) -> None:
        journal.append((address, deployed.get(address)))
        deployed[address] = candidates

    def visit(label: str, nodes: list[dict[str, Any]], index: int) -> None:
        node, checkpoint = nodes[index], len(journal)
        trace = node["trace"]
        creation = trace["kind"] in {"CREATE", "CREATE2"}
        if creation:
            incoming, outgoing = (
                bytes.fromhex(trace["data"][2:]),
                bytes.fromhex(trace["output"][2:]),
            )
            # Exact full compiler creation bytes may be followed by constructor
            # arguments. No runtime-prefix/metadata stripping or immutable patching.
            candidates = tuple(
                u
                for u in units
                if u.creation_bytecode
                and incoming.startswith(u.creation_bytecode)
                and (not trace["success"] or u.runtime_bytecode == outgoing)
            )
        elif trace["kind"] in {"CALL", "STATICCALL"}:
            candidates = deployed.get(trace["address"], ())
        else:
            # Delegate/storage-context identity needs its own exact evidence.
            candidates = ()
        if label == "Execution":
            execution[index] = candidates
        for event in node["ordering"]:
            if "Call" in event:
                visit(label, nodes, node["children"][event["Call"]])
        if not trace["success"]:
            while len(journal) > checkpoint:
                address, prior = journal.pop()
                if prior is None:
                    deployed.pop(address, None)
                else:
                    deployed[address] = prior
        elif creation:
            publish(trace["address"], candidates if trace["address"] not in deployed else ())
        if trace["success"] and trace["selfdestruct_address"] is not None:
            # Do not assume fork-specific persistence/redeployment semantics.
            publish(_address(trace["selfdestruct_address"]), ())

    for label, nodes in arenas:
        visit(label, nodes, 0)
    return execution


def parse_forge_debugger_observation(
    machine_stdout: bytes,
    debugger_dump: bytes,
    *,
    compiler_transcripts: tuple[CapturedSolcInvocation, ...],
    source_inputs: tuple[FoundrySourceInput, ...],
    descriptor: RepositorySuiteTestDescriptor,
    process_exit_code: int,
    limits: FoundryDebuggerLimits | None = None,
) -> FoundryDebuggerObservation:
    """Parse one original debugger trace; never substitute it for complete suite coverage.

    Call-tree ordering, every step and both raw output identities are retained.
    Unknown/delegate code, ambiguous compiler units and missing source locations
    remain liabilities. Compiler transcript hashes are references, not authority.
    """
    try:
        return _parse(
            machine_stdout,
            debugger_dump,
            compiler_transcripts=compiler_transcripts,
            source_inputs=source_inputs,
            descriptor=descriptor,
            process_exit_code=process_exit_code,
            limits=FoundryDebuggerLimits() if limits is None else limits,
        )
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError) as exc:
        if isinstance(exc, FoundryDebuggerError):
            raise
        raise FoundryDebuggerError(
            f"debugger evidence failed validation: {type(exc).__name__}"
        ) from exc


def _parse(
    machine_stdout: bytes,
    debugger_dump: bytes,
    *,
    compiler_transcripts: tuple[CapturedSolcInvocation, ...],
    source_inputs: tuple[FoundrySourceInput, ...],
    descriptor: RepositorySuiteTestDescriptor,
    process_exit_code: int,
    limits: FoundryDebuggerLimits,
) -> FoundryDebuggerObservation:
    if (
        type(limits) is not FoundryDebuggerLimits
        or type(descriptor) is not RepositorySuiteTestDescriptor
    ):
        raise FoundryDebuggerError(
            "debugger parser requires exact typed limits and test descriptor"
        )
    limits = FoundryDebuggerLimits.model_validate(limits.model_dump(mode="json"), strict=True)
    descriptor = RepositorySuiteTestDescriptor.model_validate(descriptor.model_dump(mode="json"))
    if (
        descriptor.framework is not RepositorySuiteFramework.FOUNDRY
        or descriptor.declaration_signature is None
    ):
        raise FoundryDebuggerError("debugger selection lacks an exact Foundry declaration")
    _integer(process_exit_code, "process exit code", 1)
    machine, dump = (
        _decode(machine_stdout, "machine stdout", limits),
        _decode(debugger_dump, "debugger dump", limits),
    )
    if len(machine_stdout) + len(debugger_dump) > limits.max_total_bytes:
        raise FoundryDebuggerError("debugger output exceeds its aggregate byte bound")
    units = _compiler_units(
        compiler_transcripts, source_inputs, limits, len(machine_stdout) + len(debugger_dump)
    )
    test_path = PurePosixPath(descriptor.path)
    if descriptor.project_root != ".":
        test_path = test_path.relative_to(descriptor.project_root)
    selected_path = test_path.as_posix()
    if not any(
        s.path == selected_path and s.source_sha256 == descriptor.source_sha256
        for s in source_inputs
    ):
        raise FoundryDebuggerError("selected test source differs from original compiler inputs")
    suite_id = f"{selected_path}:{descriptor.suite_name}"
    if set(machine) != {suite_id}:
        raise FoundryDebuggerError("machine suite differs from exact selected test")
    results = _object(
        _object(machine[suite_id], "selected suite").get("test_results"), "test results"
    )
    if set(results) != {descriptor.declaration_signature}:
        raise FoundryDebuggerError("machine test signature/population differs")
    result = _object(results[descriptor.declaration_signature], "test result")
    kind = _object(result.get("kind"), "test kind")
    if len(kind) != 1 or not set(kind) <= {"Unit", "Fuzz", "Invariant"}:
        raise FoundryDebuggerError("machine selected-test kind is unsupported")
    _object(next(iter(kind.values())), "test kind details")
    if result.get("status") not in {"Success", "Failure"} or (
        result["status"] == "Success" and process_exit_code != 0
    ):
        raise FoundryDebuggerError("machine selected-test status is unavailable or contradictory")
    traces = _array(result.get("traces"), "machine traces", limits.max_frames)
    arenas: list[tuple[str, list[dict[str, Any]]]] = []
    prior_stage = -1
    totals = [0, 0]
    for trace in traces:
        if (
            type(trace) is not list
            or len(trace) != 2
            or trace[0] not in {"Deployment", "Setup", "Execution"}
        ):
            raise FoundryDebuggerError("machine trace stage is unsupported")
        stage = {"Deployment": 0, "Setup": 1, "Execution": 2}[trace[0]]
        if stage < prior_stage or (stage == prior_stage == 2):
            raise FoundryDebuggerError("machine debugger stages are reordered or repeat execution")
        prior_stage = stage
        nodes = _arena(trace[1], limits)
        totals[0] += len(nodes)
        totals[1] += sum(len(n["trace"]["steps"]) for n in nodes)
        if totals[0] > limits.max_frames or totals[1] > limits.max_steps:
            raise FoundryDebuggerError("complete trace population exceeds parser limits")
        arenas.append((trace[0], nodes))
    if not arenas or arenas[-1][0] != "Execution":
        raise FoundryDebuggerError("machine lacks its exact execution arena")
    nodes = arenas[-1][1]
    if nodes[0]["trace"]["success"] != (result["status"] == "Success"):
        raise FoundryDebuggerError("root trace and selected-test status disagree")
    ordered = _match_dump(dump, nodes, limits)
    bindings = _frame_bindings(arenas, units)
    observed: list[DebuggerStepObservation] = []
    pc_maps = {
        u.unit_id: (
            {} if u.creation_map is None else {r.pc: r for r in u.creation_map.instructions},
            {} if u.runtime_map is None else {r.pc: r for r in u.runtime_map.instructions},
        )
        for u in units
    }
    for ordinal, (frame, step_index) in enumerate(ordered):
        trace = nodes[frame]["trace"]
        step = trace["steps"][step_index]
        creation = trace["kind"] in {"CREATE", "CREATE2"}
        candidates = bindings[frame]
        unit = candidates[0] if len(candidates) == 1 else None
        reason: str | None = (
            "AMBIGUOUS_COMPILER_CODE" if len(candidates) > 1 else "UNRESOLVED_COMPILER_CODE"
        )
        source_id = None
        path = None
        compiled_span = None
        original_span = None
        depth = None
        if unit is not None:
            row = pc_maps[unit.unit_id][0 if creation else 1].get(step["pc"])
            if row is None:
                reason = "UNMAPPED_COMPILER_PC"
            else:
                if (
                    row.opcode != step["op"]
                    or (None if not row.push_data else "0x" + row.push_data.hex())
                    != step["immediate_bytes"]
                ):
                    raise FoundryDebuggerError(
                        "original compiler instruction differs from observed step"
                    )
                reason = None
                source_id, depth = row.source_id, row.modifier_depth
                if source_id >= 0:
                    compiled_span = (row.start_byte, row.start_byte + row.length)
                matching = [s for s in unit.sources if s.source_id == source_id]
                if source_id >= 0 and matching:
                    source = matching[0]
                    compiled_span = (row.start_byte, row.start_byte + row.length)
                    original_span = source.mapping.original_span(*compiled_span)
                    path = source.path
        observed.append(
            DebuggerStepObservation(
                ordinal,
                frame,
                step_index,
                _hash(_canonical(step)),
                step["pc"],
                step["op"],
                "CREATION" if creation else "RUNTIME",
                None if unit is None else unit.unit_id,
                reason,
                source_id,
                path,
                compiled_span,
                original_span,
                depth,
            )
        )
    frames = tuple(
        DebuggerFrameObservation(
            label,
            ai,
            i,
            node["parent"],
            tuple(node["children"]),
            node["trace"]["kind"],
            node["trace"]["address"],
            node["trace"]["success"],
            len(node["trace"]["steps"]),
            _hash(_canonical(node)),
        )
        for ai, (label, group) in enumerate(arenas)
        for i, node in enumerate(group)
    )
    return FoundryDebuggerObservation(
        descriptor.descriptor_sha256,
        _hash(machine_stdout),
        _hash(debugger_dump),
        _hash(_canonical(dump["contracts"])),
        tuple(c.transcript_sha256 for c in compiler_transcripts),
        units,
        frames,
        tuple(observed),
        result["status"],
        _hash(_canonical(kind)),
    )
