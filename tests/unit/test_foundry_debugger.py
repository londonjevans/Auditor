"""Negative parser/ordering controls; all compiler and EVM payloads are synthetic mocks."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from typing import Any

import pytest

from mmaudit.scanners.foundry_debugger import FoundryDebuggerError, FoundryDebuggerLimits
from tests.debugger_trace_support import (
    CONTROL_ADDRESS,
    SOURCE,
    TEST_ADDRESS,
    TEST_SOURCE,
    calls,
    compiler_input,
    compiler_output,
    descriptor,
    dump,
    frame,
    parse,
    payload,
    raw,
    sources,
)
from tests.debugger_trace_support import (
    test_result as result,
)


def test_complete_original_order_binds_both_outputs_code_phases_and_source_spans() -> None:
    machine = payload()
    value = parse(machine)
    value.require_code_bound_steps()
    assert value.machine_stdout_sha256 == hashlib.sha256(raw(machine)).hexdigest()
    assert value.debugger_dump_sha256 == hashlib.sha256(raw(dump(machine))).hexdigest()
    assert len(value.compiler_units) == 2 and len(value.frames) == 4 and len(value.steps) == 7
    assert [(s.frame_index, s.frame_step_index) for s in value.steps] == [
        (0, 0),
        (1, 0),
        (1, 1),
        (1, 2),
        (0, 1),
        (0, 2),
        (0, 3),
    ]
    assert all(s.compiler_span == s.original_span == (0, 1) for s in value.steps)
    assert value.execution_scope == "ONE_DEBUGGER_TRACE_NOT_FULL_TEST_OR_FUZZ_POPULATION"
    assert value.evidence_authority == "UNATTESTED_DEBUGGER_OBSERVATION"
    assert not hasattr(value, "covered") and not hasattr(value, "coverage_complete")


@pytest.mark.parametrize(
    "mutation",
    [
        "extra_suite",
        "extra_test",
        "signature",
        "status",
        "exit",
        "root_status",
        "root_parent",
        "frame_index",
        "parent",
        "depth",
        "orphan",
        "duplicate_child",
        "ordering_missing",
        "ordering_duplicate",
        "ordering_reversed",
        "ordering_extra",
        "step_opcode",
        "step_bool",
        "step_depth",
        "step_address",
        "step_push_width",
        "step_stack",
        "step_extra",
        "step_memory",
        "stage_reordered",
        "stage_repeat",
        "stage_missing",
    ],
)
def test_invalid_machine_population_or_compiler_step_is_refused(mutation: str) -> None:
    machine = payload()
    selected = result(machine)
    nodes = selected["traces"][-1][1]["arena"]
    root, child = nodes
    options: dict[str, Any] = {}
    if mutation == "extra_suite":
        machine["other"] = {}
    elif mutation == "extra_test":
        machine[f"{TEST_SOURCE}:ModifierControlTest"]["test_results"]["other()"] = {}
    elif mutation == "signature":
        options["descriptor"] = descriptor("test_other()")
    elif mutation == "status":
        selected["status"] = "Skipped"
    elif mutation == "exit":
        options["process_exit_code"] = 1
    elif mutation == "root_status":
        root["trace"]["success"] = False
    elif mutation == "root_parent":
        root["parent"] = 0
    elif mutation == "frame_index":
        child["idx"] = True
    elif mutation == "parent":
        child["parent"] = 1
    elif mutation == "depth":
        child["trace"]["depth"] = 0
    elif mutation == "orphan":
        root["children"] = []
        root["ordering"] = [{"Step": i} for i in range(4)]
    elif mutation == "duplicate_child":
        root["children"] = [1, 1]
    elif mutation == "ordering_missing":
        root["ordering"].pop()
    elif mutation == "ordering_duplicate":
        root["ordering"].append({"Step": 3})
    elif mutation == "ordering_reversed":
        root["ordering"][-1], root["ordering"][-2] = (
            root["ordering"][-2],
            root["ordering"][-1],
        )
    elif mutation == "ordering_extra":
        root["ordering"].append({"Unknown": 0})
    elif mutation == "step_opcode":
        child["trace"]["steps"][-1]["op"] = 0x5B
    elif mutation == "step_bool":
        child["trace"]["steps"][-1]["pc"] = True
    elif mutation == "step_depth":
        child["trace"]["steps"][-1]["depth"] = 1
    elif mutation == "step_address":
        child["trace"]["steps"][-1]["contract"] = "0x" + "44" * 20
    elif mutation == "step_push_width":
        child["trace"]["steps"][0]["immediate_bytes"] = "0x0002"
    elif mutation == "step_stack":
        child["trace"]["steps"][0]["stack"] = ["0x" + "a" * 65]
    elif mutation == "step_extra":
        child["trace"]["steps"][0]["injected"] = True
    elif mutation == "step_memory":
        child["trace"]["steps"][0]["memory"] = "0x0"
    elif mutation == "stage_reordered":
        selected["traces"][:2] = selected["traces"][:2][::-1]
    elif mutation == "stage_repeat":
        selected["traces"].append(copy.deepcopy(selected["traces"][-1]))
    elif mutation == "stage_missing":
        selected["traces"].pop()
    # Keep the original independently supplied dump when machine shape is invalid.
    with pytest.raises(FoundryDebuggerError):
        parse(machine, debugger_dump=raw(dump(payload())), **options)


@pytest.mark.parametrize(
    "mutation", ["omit", "repeat", "reorder", "address", "kind", "calldata", "step", "bool"]
)
def test_dump_must_match_every_complete_machine_segment_and_step(mutation: str) -> None:
    data = dump(payload())
    segments = data["debug_arena"]
    if mutation == "omit":
        segments.pop()
    elif mutation == "repeat":
        segments.append(copy.deepcopy(segments[-1]))
    elif mutation == "reorder":
        segments.reverse()
    elif mutation == "address":
        segments[0]["address"] = CONTROL_ADDRESS
    elif mutation == "kind":
        segments[0]["kind"] = "STATICCALL"
    elif mutation == "calldata":
        segments[0]["calldata"] = "0x"
    elif mutation == "step":
        segments[1]["steps"].pop()
    elif mutation == "bool":
        segments[0]["steps"][0]["gas_cost"] = False
    with pytest.raises(FoundryDebuggerError):
        parse(debugger_dump=raw(data))


@pytest.mark.parametrize("label", ["missing", "failure", "deferred"])
def test_code_not_yet_successfully_created_stays_unresolved(label: str) -> None:
    machine = payload()
    traces = result(machine)["traces"]
    if label == "failure":
        traces[1][1]["arena"][0]["trace"]["success"] = False
    elif label == "missing":
        traces.pop(1)
    else:
        creation = traces.pop(1)[1]["arena"][0]
        nodes = traces[-1][1]["arena"]
        creation.update(idx=2, parent=0)
        creation["trace"]["depth"] = 1
        nodes.append(creation)
        nodes[0]["children"].append(2)
        nodes[0]["ordering"].append({"Call": 1})
    value = parse(machine)
    child = [s for s in value.steps if s.frame_index == 1]
    assert child and all(s.unresolved_code_reason == "UNRESOLVED_COMPILER_CODE" for s in child)
    with pytest.raises(FoundryDebuggerError, match="unresolved"):
        value.require_code_bound_steps()


def test_constructor_argument_tail_is_retained_without_runtime_prefix_matching() -> None:
    machine = payload()
    result(machine)["traces"][1][1]["arena"][0]["trace"]["data"] += "00" * 32
    parse(machine).require_code_bound_steps()
    result(machine)["traces"][1][1]["arena"][0]["trace"]["output"] += "00"
    with pytest.raises(FoundryDebuggerError, match="unresolved"):
        parse(machine).require_code_bound_steps()


def test_identical_code_units_are_ambiguous_not_resolved_by_a_debugger_name() -> None:
    output = compiler_output()
    output["contracts"][SOURCE]["Alias"] = copy.deepcopy(
        output["contracts"][SOURCE]["ModifierControl"]
    )
    value = parse(compiler_transcripts=calls(outgoing=output))
    assert any(s.unresolved_code_reason == "AMBIGUOUS_COMPILER_CODE" for s in value.steps)
    with pytest.raises(FoundryDebuggerError, match="unresolved"):
        value.require_code_bound_steps()


def test_generated_source_and_unmapped_pc_do_not_become_supplied_source_locations() -> None:
    output = compiler_output()
    output["contracts"][SOURCE]["ModifierControl"]["evm"]["deployedBytecode"]["sourceMap"] = (
        "0:1:2;;"
    )
    value = parse(compiler_transcripts=calls(outgoing=output))
    value.require_code_bound_steps()
    assert all(
        s.original_span is None and s.source_path is None and s.compiler_span == (0, 1)
        for s in value.steps
        if s.frame_index == 1
    )
    machine = payload()
    result(machine)["traces"][-1][1]["arena"][1]["trace"]["steps"][-1]["pc"] = 100
    with pytest.raises(FoundryDebuggerError, match="unresolved"):
        parse(machine).require_code_bound_steps()


@pytest.mark.parametrize(
    "mutation",
    [
        "source",
        "source_id",
        "missing_source",
        "compiler_error",
        "map",
        "calls",
        "exit",
        "sequence",
        "argv",
        "hash",
    ],
)
def test_compiler_sources_population_and_invocations_are_checked(mutation: str) -> None:
    incoming, outgoing = compiler_input(), compiler_output()
    options: dict[str, Any] = {}
    if mutation == "source":
        incoming["sources"][SOURCE]["content"] += "changed"
    elif mutation == "source_id":
        outgoing["sources"][TEST_SOURCE]["id"] = 0
    elif mutation == "missing_source":
        outgoing["sources"].pop(SOURCE)
    elif mutation == "compiler_error":
        outgoing["errors"] = [{"severity": "error"}]
    elif mutation == "map":
        outgoing["contracts"][SOURCE]["ModifierControl"]["evm"]["bytecode"]["sourceMap"] = "0:1:0;x"
    records = calls(incoming, outgoing)
    if mutation == "calls":
        records = ()
    elif mutation == "exit":
        records = (replace(records[0], compiler_exit_code=True),)
    elif mutation == "sequence":
        records = (replace(records[0], sequence=1),)
    elif mutation == "argv":
        records = (replace(records[0], compiler_argv=("--standard-json",)),)
    elif mutation == "hash":
        options["source_inputs"] = (replace(sources()[0], source_sha256="0" * 64), sources()[1])
    with pytest.raises(FoundryDebuggerError):
        parse(compiler_transcripts=records, **options)


@pytest.mark.parametrize(
    "raw_input",
    [
        b"",
        b"[]",
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b'{"x":1e10000}',
        b'{"x":"\\ud800"}',
        b"\xff",
        b"{" * 1000,
    ],
)
def test_invalid_or_ambiguous_json_never_becomes_an_observation(raw_input: bytes) -> None:
    with pytest.raises(FoundryDebuggerError):
        parse(machine_stdout=raw_input)


@pytest.mark.parametrize(
    "limit,value",
    [
        ("max_artifact_bytes", 1),
        ("max_total_bytes", 1),
        ("max_json_nodes", 1),
        ("max_json_depth", 1),
        ("max_frames", 3),
        ("max_steps", 6),
        ("max_contracts", 1),
        ("max_sources", 1),
        ("max_compiler_instructions", 1),
    ],
)
def test_parser_limits_refuse_instead_of_truncating_populations(limit: str, value: int) -> None:
    with pytest.raises(FoundryDebuggerError):
        parse(limits=FoundryDebuggerLimits(**{limit: value}))


@pytest.mark.parametrize("succeeded", [False, True])
def test_descendant_creation_is_rolled_back_with_its_failed_ancestor(succeeded: bool) -> None:
    machine = payload()
    traces = result(machine)["traces"]
    creation = traces[1][1]["arena"][0]
    creation.update(idx=1, parent=0)
    creation["trace"]["depth"] = 1
    ancestor = frame(
        TEST_ADDRESS,
        "CALL",
        "0x",
        success=succeeded,
        children=[1],
        ordering=[{"Call": 0}],
    )
    traces[1][1]["arena"] = [ancestor, creation]
    value = parse(machine)
    observed = [s for s in value.steps if s.frame_index == 1]
    assert observed
    assert all((s.unresolved_code_reason is None) is succeeded for s in observed)


@pytest.mark.parametrize("change", ["redeployment", "selfdestruct", "DELEGATECALL", "CALLCODE"])
def test_ambiguous_lifecycle_and_context_never_reuse_a_previous_code_identity(change: str) -> None:
    machine = payload()
    traces = result(machine)["traces"]
    if change == "redeployment":
        traces.insert(2, copy.deepcopy(traces[1]))
    elif change == "selfdestruct":
        destruction = frame(CONTROL_ADDRESS, "CALL", "0x")
        destruction["trace"]["selfdestruct_address"] = CONTROL_ADDRESS
        traces.insert(2, ["Setup", {"arena": [destruction]}])
    else:
        traces[-1][1]["arena"][1]["trace"]["kind"] = change
    value = parse(machine)
    observed = [s for s in value.steps if s.frame_index == 1]
    assert observed and all(s.unresolved_code_reason for s in observed)
    with pytest.raises(FoundryDebuggerError, match="unresolved"):
        value.require_code_bound_steps()


@pytest.mark.parametrize("process_exit_code", [0, 1])
def test_failed_debugger_result_is_retained_without_a_test_pass(process_exit_code: int) -> None:
    machine = payload()
    result(machine)["status"] = "Failure"
    result(machine)["traces"][-1][1]["arena"][0]["trace"]["success"] = False
    value = parse(machine, process_exit_code=process_exit_code)
    assert value.test_status == "Failure"
    assert value.evidence_authority == "UNATTESTED_DEBUGGER_OBSERVATION"


@pytest.mark.parametrize("kind", ["Fuzz", "Invariant"])
def test_reported_population_never_expands_the_single_debugger_trace(kind: str) -> None:
    machine = payload()
    reported = {kind: {"runs": 256}}
    result(machine)["kind"] = reported
    value = parse(machine)
    assert value.test_kind_sha256 == hashlib.sha256(raw(reported)).hexdigest()
    assert len(value.steps) == 7
    assert value.execution_scope == "ONE_DEBUGGER_TRACE_NOT_FULL_TEST_OR_FUZZ_POPULATION"


@pytest.mark.parametrize("kind", [None, {}, {"Other": {}}, {"Unit": []}, {"Unit": {}, "Fuzz": {}}])
def test_missing_or_ambiguous_test_kind_is_refused(kind: Any) -> None:
    machine = payload()
    result(machine)["kind"] = kind
    with pytest.raises(FoundryDebuggerError):
        parse(machine)


def test_debugger_annotations_are_hashed_but_cannot_choose_code_or_source_locations() -> None:
    original = parse()
    data = dump(payload())
    data["contracts"]["identified_contracts"] = {CONTROL_ADDRESS: "WrongContract"}
    data["contracts"]["sources"] = {"untrusted_label": "not compiler source"}
    changed = parse(debugger_dump=raw(data))
    assert changed.steps == original.steps
    assert changed.compiler_units == original.compiler_units
    assert changed.debugger_dump_sha256 != original.debugger_dump_sha256
    assert changed.debugger_annotations_sha256 != original.debugger_annotations_sha256
    assert changed.annotation_scope == "HASHED_NOT_USED_FOR_CODE_OR_SOURCE_BINDING"


@pytest.mark.parametrize("key", ["identified_contracts", "sources"])
def test_nonobject_annotation_tables_are_refused(key: str) -> None:
    data = dump(payload())
    data["contracts"][key] = []
    with pytest.raises(FoundryDebuggerError, match="annotation"):
        parse(debugger_dump=raw(data))


def test_version_and_abi_only_invocations_remain_in_the_complete_compiler_population() -> None:
    compilation = calls()[0]
    abi = compiler_output()
    for members in abi["contracts"].values():
        for name in members:
            members[name] = {"abi": []}
    records = (
        replace(
            compilation,
            received_argv=("--version",),
            compiler_argv=("--version",),
            stdin=b"",
            stdout=b"synthetic compiler version observation",
            transcript_sha256="d" * 64,
        ),
        replace(compilation, sequence=1, stdout=raw(abi), transcript_sha256="e" * 64),
        replace(compilation, sequence=2),
    )
    value = parse(compiler_transcripts=records)
    assert value.compiler_transcript_sha256s == tuple(c.transcript_sha256 for c in records)
    assert all(u.invocation_sequence == 2 for u in value.compiler_units)
    value.require_code_bound_steps()
    with pytest.raises(FoundryDebuggerError, match="contract population"):
        parse(compiler_transcripts=records, limits=FoundryDebuggerLimits(max_contracts=3))
    with pytest.raises(FoundryDebuggerError, match="invocation population"):
        parse(compiler_transcripts=records, limits=FoundryDebuggerLimits(max_compiler_calls=2))


@pytest.mark.parametrize("links", [[1], True, {SOURCE: {"Library": [{"start": 1, "length": 20}]}}])
def test_unresolved_or_malformed_compiler_relocations_are_refused(links: Any) -> None:
    output = compiler_output()
    output["contracts"][SOURCE]["ModifierControl"]["evm"]["bytecode"]["linkReferences"] = links
    with pytest.raises(FoundryDebuggerError, match="link references"):
        parse(compiler_transcripts=calls(outgoing=output))


def test_complete_byte_bound_includes_both_outputs_every_compiler_stream_and_original_source() -> (
    None
):
    machine = payload()
    records = (replace(calls()[0], stderr=b"synthetic retained diagnostic"),)
    total = (
        len(raw(machine))
        + len(raw(dump(machine)))
        + sum(len(s.content) for s in sources())
        + sum(len(b) for c in records for b in (c.stdin, c.stdout, c.stderr))
    )
    parse(compiler_transcripts=records, limits=FoundryDebuggerLimits(max_total_bytes=total))
    with pytest.raises(FoundryDebuggerError, match="aggregate"):
        parse(compiler_transcripts=records, limits=FoundryDebuggerLimits(max_total_bytes=total - 1))


def test_compiler_lf_locations_map_to_exact_original_crlf_bytes_in_a_nested_project() -> None:
    original = sources()
    crlf = tuple(
        replace(
            s,
            content=s.content.replace(b"\n", b"\r\n"),
            source_sha256=hashlib.sha256(s.content.replace(b"\n", b"\r\n")).hexdigest(),
        )
        for s in original
    )
    values = descriptor().model_dump(exclude={"descriptor_sha256"})
    values.update(
        project_root="packages/local",
        path="packages/local/" + TEST_SOURCE,
        declaration_path="packages/local/" + TEST_SOURCE,
        source_sha256=crlf[1].source_sha256,
        declaration_source_sha256=crlf[1].source_sha256,
    )
    selected = type(descriptor()).sealed(**values)
    outgoing = compiler_output()
    start = original[0].content.index(b"pragma")
    outgoing["contracts"][SOURCE]["ModifierControl"]["evm"]["deployedBytecode"]["sourceMap"] = (
        f"{start}:6:0;;"
    )
    value = parse(
        source_inputs=crlf, descriptor=selected, compiler_transcripts=calls(outgoing=outgoing)
    )
    observed = [s for s in value.steps if s.frame_index == 1]
    assert observed and all(s.compiler_span == (start, start + 6) for s in observed)
    assert all(s.original_span == (start + 1, start + 7) for s in observed)


@pytest.mark.parametrize("source_map", ["999999:1:0;;", "0:999999:0;;"])
def test_original_source_bounds_cannot_be_filled_by_debugger_annotations(source_map: str) -> None:
    outgoing = compiler_output()
    outgoing["contracts"][SOURCE]["ModifierControl"]["evm"]["deployedBytecode"]["sourceMap"] = (
        source_map
    )
    with pytest.raises(FoundryDebuggerError):
        parse(compiler_transcripts=calls(outgoing=outgoing))
