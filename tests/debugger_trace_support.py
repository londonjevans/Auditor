"""Synthetic parser-only compiler/trace data; never evidence of actual EVM execution."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from mmaudit.models.schemas import RepositorySuiteFramework, RepositorySuiteTestDescriptor
from mmaudit.scanners.foundry_debugger import (
    FoundryDebuggerObservation,
    parse_forge_debugger_observation,
)
from mmaudit.scanners.foundry_inventory import FoundrySourceInput
from mmaudit.scanners.solc_capture import CapturedSolcInvocation

FIXTURE = Path(__file__).resolve().parent / "fixtures/coverage_compilation"
SOURCE = "src/ModifierControl.sol"
TEST_SOURCE = "test/ModifierControl.t.sol"
SIGNATURE = "test_invariant_permitted_transition_increments_once()"
TEST_ADDRESS = "0x" + "11" * 20
CONTROL_ADDRESS = "0x" + "22" * 20
CALLER = "0x" + "33" * 20
TEST_CREATION, TEST_RUNTIME = "606000", "f15f5000"
CONTROL_CREATION, CONTROL_RUNTIME = "600100", "60025000"


def raw(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def sources() -> tuple[FoundrySourceInput, ...]:
    return tuple(
        FoundrySourceInput(p, b, hashlib.sha256(b).hexdigest())
        for p in (SOURCE, TEST_SOURCE)
        for b in ((FIXTURE / p).read_bytes(),)
    )


def descriptor(signature: str = SIGNATURE) -> RepositorySuiteTestDescriptor:
    digest = sources()[1].source_sha256
    return RepositorySuiteTestDescriptor.sealed(
        framework=RepositorySuiteFramework.FOUNDRY,
        project_root=".",
        path=TEST_SOURCE,
        suite_name="ModifierControlTest",
        test_name=signature.partition("(")[0],
        source_sha256=digest,
        start_line=1,
        end_line=3,
        inventory_sha256="a" * 64,
        inventory_record_sha256="b" * 64,
        execution_contract_ast_id=10,
        declaration_path=TEST_SOURCE,
        declaration_suite_name="ModifierControlTest",
        declaration_signature=signature,
        declaration_source_sha256=digest,
        declaration_start_line=1,
        declaration_end_line=3,
        declaration_contract_ast_id=10,
        declaration_function_ast_id=11,
    )


def contract(creation: str, runtime: str, source_id: int) -> dict[str, Any]:
    return {
        "abi": [],
        "evm": {
            "bytecode": {
                "object": creation,
                "sourceMap": f"0:1:{source_id};",
                "linkReferences": {},
            },
            "deployedBytecode": {
                "object": runtime,
                "sourceMap": f"0:1:{source_id};" + ";" * (2 if source_id else 1),
                "linkReferences": {},
                "immutableReferences": {},
            },
        },
    }


def compiler_input() -> dict[str, Any]:
    return {
        "language": "Solidity",
        "sources": {s.path: {"content": s.content.decode()} for s in sources()},
        "settings": {"optimizer": {"enabled": False}, "outputSelection": {}},
    }


def compiler_output() -> dict[str, Any]:
    return {
        "sources": {s.path: {"id": i} for i, s in enumerate(sources())},
        "contracts": {
            SOURCE: {"ModifierControl": contract(CONTROL_CREATION, CONTROL_RUNTIME, 0)},
            TEST_SOURCE: {"ModifierControlTest": contract(TEST_CREATION, TEST_RUNTIME, 1)},
        },
    }


def calls(
    incoming: dict[str, Any] | None = None, outgoing: dict[str, Any] | None = None
) -> tuple[CapturedSolcInvocation, ...]:
    return (
        CapturedSolcInvocation(
            0,
            ("--standard-json",),
            ("--standard-json", "--no-import-callback"),
            0,
            raw(compiler_input() if incoming is None else incoming),
            raw(compiler_output() if outgoing is None else outgoing),
            b"",
            "c" * 64,
        ),
    )


def step(
    address: str, depth: int, pc: int, opcode: int, immediate: str | None = None
) -> dict[str, Any]:
    return dict(
        contract=address,
        decoded=None,
        depth=depth,
        gas_cost=0,
        gas_refund_counter=0,
        gas_remaining=100,
        gas_used=0,
        immediate_bytes=immediate,
        memory="0x",
        op=opcode,
        pc=pc,
        push_stack=None,
        returndata="0x",
        stack=[],
        status=None,
        storage_change=None,
    )


def frame(
    address: str,
    kind: str,
    data: str,
    output: str = "0x",
    *,
    index: int = 0,
    parent: int | None = None,
    depth: int = 0,
    success: bool = True,
    steps: list[dict[str, Any]] | None = None,
    children: list[int] | None = None,
    ordering: list[dict[str, int]] | None = None,
) -> dict[str, Any]:
    items = [] if steps is None else steps
    return dict(
        parent=parent,
        children=[] if children is None else children,
        idx=index,
        trace=dict(
            address=address,
            caller=CALLER,
            data=data,
            decoded=None,
            depth=depth,
            gas_limit=1000,
            gas_used=0,
            kind=kind,
            maybe_precompile=False,
            output=output,
            selfdestruct_address=None,
            selfdestruct_refund_target=None,
            selfdestruct_transferred_value=None,
            status="Return" if success else "Revert",
            steps=items,
            success=success,
            value="0x0",
        ),
        logs=[],
        ordering=[{"Step": i} for i in range(len(items))] if ordering is None else ordering,
    )


def payload() -> dict[str, Any]:
    root_steps = [
        step(TEST_ADDRESS, 1, 0, 0xF1),
        step(TEST_ADDRESS, 1, 1, 0x5F),
        step(TEST_ADDRESS, 1, 2, 0x50),
        step(TEST_ADDRESS, 1, 3, 0),
    ]
    child_steps = [
        step(CONTROL_ADDRESS, 2, 0, 0x60, "0x02"),
        step(CONTROL_ADDRESS, 2, 2, 0x50),
        step(CONTROL_ADDRESS, 2, 3, 0),
    ]
    execution = [
        frame(
            TEST_ADDRESS,
            "CALL",
            "0x12345678",
            steps=root_steps,
            children=[1],
            ordering=[{"Step": 0}, {"Call": 0}, {"Step": 1}, {"Step": 2}, {"Step": 3}],
        ),
        frame(CONTROL_ADDRESS, "CALL", "0xabcdef01", index=1, parent=0, depth=1, steps=child_steps),
    ]
    return {
        f"{TEST_SOURCE}:ModifierControlTest": {
            "test_results": {
                SIGNATURE: {
                    "status": "Success",
                    "kind": {"Unit": {"gas": 0}},
                    "traces": [
                        [
                            "Deployment",
                            {
                                "arena": [
                                    frame(
                                        TEST_ADDRESS,
                                        "CREATE",
                                        "0x" + TEST_CREATION,
                                        "0x" + TEST_RUNTIME,
                                    )
                                ]
                            },
                        ],
                        [
                            "Setup",
                            {
                                "arena": [
                                    frame(
                                        CONTROL_ADDRESS,
                                        "CREATE",
                                        "0x" + CONTROL_CREATION,
                                        "0x" + CONTROL_RUNTIME,
                                    )
                                ]
                            },
                        ],
                        ["Execution", {"arena": execution}],
                    ],
                }
            }
        }
    }


def test_result(machine: dict[str, Any]) -> dict[str, Any]:
    value = machine[f"{TEST_SOURCE}:ModifierControlTest"]["test_results"][SIGNATURE]
    assert isinstance(value, dict)
    return value


def dump(machine: dict[str, Any]) -> dict[str, Any]:
    nodes = test_result(machine)["traces"][-1][1]["arena"]
    segments: list[dict[str, Any]] = []

    def visit(index: int) -> None:
        node = nodes[index]
        trace = node["trace"]
        pending: list[dict[str, Any]] = []

        def flush() -> None:
            if pending:
                segments.append(
                    dict(
                        address=trace["address"],
                        kind=trace["kind"],
                        calldata="0x" if trace["kind"] in {"CREATE", "CREATE2"} else trace["data"],
                        steps=copy.deepcopy(pending),
                    )
                )
                pending.clear()

        for event in node["ordering"]:
            if "Step" in event:
                pending.append(trace["steps"][event["Step"]])
            elif "Call" in event:
                flush()
                visit(node["children"][event["Call"]])
        flush()

    visit(0)
    return {"contracts": {"identified_contracts": {}, "sources": {}}, "debug_arena": segments}


def parse(machine: dict[str, Any] | None = None, **changes: Any) -> FoundryDebuggerObservation:
    data = payload() if machine is None else machine
    inputs: dict[str, Any] = dict(
        machine_stdout=raw(data),
        debugger_dump=raw(dump(data)),
        compiler_transcripts=calls(),
        source_inputs=sources(),
        descriptor=descriptor(),
        process_exit_code=0,
    )
    inputs.update(changes)
    return parse_forge_debugger_observation(**inputs)
