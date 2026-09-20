"""Fixed offline compiler/coverage observations; no admitted execution or audit credit."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, NoReturn

import pytest

from mmaudit.scanners.foundry_debugger import (
    FoundryDebuggerError,
    parse_forge_debugger_observation,
)
from mmaudit.scanners.foundry_inventory import FoundrySourceInput
from mmaudit.scanners.foundry_statement_coverage import (
    FoundryStatementCoverageError,
    parse_forge_debug_statement_coverage,
    parse_solc_bytecode_source_map,
    reconcile_forge_bytecode_report,
)
from mmaudit.scanners.solc_capture import prepare_solc_capture
from tests.debugger_trace_support import descriptor as synthetic_descriptor
from tests.integration.test_mutation_compilation import _solc_0_8_30

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/coverage_compilation"


@pytest.mark.parametrize("transition", ["blocked", "permitted"])
@pytest.mark.parametrize("captured", [False, True])
def test_native_bytecode_report_retains_exact_modifier_transition_observations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, transition: str, captured: bool
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        pytest.fail("synthetic coverage control attempted network access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    forge, solc = Path.home() / ".foundry/bin/forge", _solc_0_8_30()
    if not forge.is_file() or solc is None:
        pytest.skip("Requires existing external Forge/solc0.8.30; no provisioning")
    repository = FIXTURE.parents[2]
    forge, solc = forge.resolve(strict=True), solc.resolve(strict=True)
    assert not forge.is_relative_to(repository) and not solc.is_relative_to(repository)
    workspace = tmp_path / "source"
    shutil.copytree(FIXTURE, workspace)
    original = {
        p.relative_to(workspace).as_posix(): p.read_bytes()
        for p in workspace.rglob("*")
        if p.is_file()
    }
    artifact_root = tmp_path / "coverage"
    artifact_root.mkdir()
    session = (
        prepare_solc_capture(
            root=tmp_path / "compiler-transcript",
            workspace=workspace,
            compiler=solc,
            compiler_sha256=hashlib.sha256(solc.read_bytes()).hexdigest(),
            sources=tuple(
                FoundrySourceInput(p, raw, hashlib.sha256(raw).hexdigest())
                for p, raw in sorted(original.items())
                if p.endswith(".sol")
            ),
            deadline_monotonic=time.monotonic() + 30,
        )
        if captured
        else None
    )
    command = [
        str(forge),
        "coverage",
        "--root",
        str(workspace),
        "--match-path",
        "test/ModifierControl.t.sol",
        "--match-contract",
        "^ModifierControlTest$",
        "--match-test",
        f"^test_invariant_{transition}_transition_.*$",
        "--report",
        "debug",
        "--report",
        "bytecode",
        "--report-file",
        str(artifact_root / "report"),
        "--json",
        "--exclude-tests",
        "--use",
        str(solc if session is None else session.launcher),
        "--offline",
        "--no-auto-detect",
        "--force",
        "--cache-path",
        str(artifact_root / "cache"),
        "--out",
        str(artifact_root / "out"),
        "--build-info",
        "--build-info-path",
        str(artifact_root / "build-info"),
        "--ast",
    ]
    completed = subprocess.run(
        command,
        cwd=workspace,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        capture_output=True,
        timeout=30,
        check=False,
        shell=False,
    )
    (tmp_path / "stdout.txt").write_bytes(completed.stdout)
    (tmp_path / "stderr.txt").write_bytes(completed.stderr)
    (tmp_path / "returncode.txt").write_text(str(completed.returncode))
    files = sorted(p for p in tmp_path.rglob("*") if p.is_file())
    assert len(files) <= 100 and sum(p.stat().st_size for p in files) < 4_000_000
    (tmp_path / "capture.json").write_text(
        json.dumps(
            dict(
                scope="SYNTHETIC_LOCAL_ONLY_UNATTESTED_NO_AUDIT_AUTHORITY",
                transition=transition,
                captured=captured,
                command=command,
                forge_sha256=hashlib.sha256(forge.read_bytes()).hexdigest(),
                solc_sha256=hashlib.sha256(solc.read_bytes()).hexdigest(),
                sources={p: hashlib.sha256(raw).hexdigest() for p, raw in original.items()},
                artifacts={
                    p.relative_to(tmp_path).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in files
                },
                returncode=completed.returncode,
                execution_validated=False,
                qualification_eligible=False,
                audit_complete=False,
            ),
            indent=2,
        )
    )
    assert completed.returncode == 0, completed.stderr.decode()
    assert all((workspace / p).read_bytes() == raw for p, raw in original.items())
    debug = parse_forge_debug_statement_coverage(completed.stdout)
    machine = json.loads(debug.machine_json_bytes)
    tests = [(n, t["status"]) for s in machine.values() for n, t in s["test_results"].items()]
    assert len(tests) == 1 and tests[0][1] == "Success"
    assert tests[0][0].startswith(f"test_invariant_{transition}_transition_")
    if session is not None:
        invocations = session.collect()
        compilations = [c for c in invocations if c.stdin]
        assert len(compilations) == 1
        invocation = compilations[0]
        assert invocation.compiler_argv[-1] == "--no-import-callback"
        assert json.loads(invocation.stdin)["language"] == "Solidity"
        assert set(json.loads(invocation.stdout)["sources"]) == {
            "src/ModifierControl.sol",
            "test/ModifierControl.t.sol",
        }
        output = json.loads(invocation.stdout)
        evm = output["contracts"]["src/ModifierControl.sol"]["ModifierControl"]["evm"]
        report = (workspace / "bytecode-coverage/ModifierControl.asm").read_bytes()
        binding = reconcile_forge_bytecode_report(
            report,
            creation_bytecode=bytes.fromhex(evm["bytecode"]["object"]),
            creation_source_map=evm["bytecode"]["sourceMap"],
            runtime_bytecode=bytes.fromhex(evm["deployedBytecode"]["object"]),
            runtime_source_map=evm["deployedBytecode"]["sourceMap"],
            source_paths=tuple(sorted((v["id"], k) for k, v in output["sources"].items())),
        )
        # Diagnose the original report, including a mixed-phase result. Do not retry
        # until a coherent report appears or grant execution credit to either shape.
        assert binding.instruction_phases in (("CREATION",), ("RUNTIME",))
        assert binding.source_map_phases == ("RUNTIME",)
        assert len(binding.rows) == len(binding.runtime.instructions)
        if binding.instruction_phases == ("CREATION",):
            with pytest.raises(FoundryStatementCoverageError, match="one consistent"):
                binding.require_consistent_phase()
        else:
            assert binding.require_consistent_phase() == "RUNTIME"
        source_id = output["sources"]["src/ModifierControl.sol"]["id"]
        placeholder = original["src/ModifierControl.sol"].index(b"_;")
        assert not any(
            item.source_identity == (source_id, placeholder, placeholder + 1)
            for item in (*binding.creation.instructions, *binding.runtime.instructions)
        )
        assert any(item.modifier_depth > 0 for item in binding.runtime.instructions)
        (tmp_path / "transcript-summary.json").write_text(
            json.dumps(
                dict(
                    invocations=len(invocations),
                    compilations=len(compilations),
                    transcript_sha256s=[c.transcript_sha256 for c in invocations],
                    authority="UNATTESTED_COMPILER_TRANSCRIPT",
                    coverage_complete=False,
                    report_sha256=binding.report_sha256,
                    instruction_phases=binding.instruction_phases,
                    source_map_phases=binding.source_map_phases,
                    report_rows=len(binding.rows),
                    creation_map_entries=len(binding.creation.instructions),
                    runtime_map_entries=len(binding.runtime.instructions),
                    reported_hits_verified=False,
                    line_columns_verified=False,
                )
            )
        )


@pytest.mark.parametrize("transition", ["blocked", "permitted"])
def test_native_debugger_dump_keeps_original_compiler_and_step_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    transition: str,
) -> None:
    """Observe fixed local debugger output without granting trace/coverage authority."""

    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        pytest.fail("synthetic debugger control attempted network access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    forge, solc = Path.home() / ".foundry/bin/forge", _solc_0_8_30()
    if not forge.is_file() or solc is None:
        pytest.skip("Requires existing external Forge/solc0.8.30; no provisioning")
    forge, solc = forge.resolve(strict=True), solc.resolve(strict=True)
    assert not forge.is_relative_to(FIXTURE.parents[2])
    assert not solc.is_relative_to(FIXTURE.parents[2])
    workspace = tmp_path / "source"
    shutil.copytree(FIXTURE, workspace)
    original = {
        p.relative_to(workspace).as_posix(): p.read_bytes()
        for p in workspace.rglob("*")
        if p.is_file()
    }
    session = prepare_solc_capture(
        root=tmp_path / "compiler-transcript",
        workspace=workspace,
        compiler=solc,
        compiler_sha256=hashlib.sha256(solc.read_bytes()).hexdigest(),
        sources=tuple(
            FoundrySourceInput(p, raw, hashlib.sha256(raw).hexdigest())
            for p, raw in sorted(original.items())
            if p.endswith(".sol")
        ),
        deadline_monotonic=time.monotonic() + 30,
    )
    command = [
        str(forge),
        "test",
        "--root",
        str(workspace),
        "--match-path",
        "test/ModifierControl.t.sol",
        "--match-contract",
        "^ModifierControlTest$",
        "--match-test",
        f"^test_invariant_{transition}_transition_.*$",
        "--debug",
        "--dump",
        str(tmp_path / "steps.json"),
        "--json",
        "--use",
        str(session.launcher),
        "--offline",
        "--no-auto-detect",
        "--force",
        "--cache-path",
        str(tmp_path / "cache"),
        "--out",
        str(tmp_path / "out"),
        "--build-info",
        "--build-info-path",
        str(tmp_path / "build-info"),
        "--ast",
    ]
    completed = subprocess.run(
        command,
        cwd=workspace,
        stdin=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        capture_output=True,
        timeout=30,
        check=False,
        shell=False,
    )
    (tmp_path / "stdout.txt").write_bytes(completed.stdout)
    (tmp_path / "stderr.txt").write_bytes(completed.stderr)
    (tmp_path / "returncode.txt").write_text(str(completed.returncode))
    assert completed.returncode == 0, completed.stderr.decode()
    assert all((workspace / p).read_bytes() == raw for p, raw in original.items())
    invocations = session.collect()
    compilations = [c for c in invocations if c.stdin]
    # Debugger selection performs an ABI-only pass before the full build. Both
    # original calls must survive collection; never discard the first as noise.
    assert len(compilations) == 2
    abi_input, build_input = [json.loads(c.stdin) for c in compilations]
    abi_output, build_output = [json.loads(c.stdout) for c in compilations]
    assert abi_input["sources"] == build_input["sources"]
    assert {k: v for k, v in abi_input["settings"].items() if k != "outputSelection"} == {
        k: v for k, v in build_input["settings"].items() if k != "outputSelection"
    }
    assert all(
        selections == {"*": ["abi"]}
        for selections in abi_input["settings"]["outputSelection"].values()
    )
    assert all(set(c) == {"abi"} for cs in abi_output["contracts"].values() for c in cs.values())
    step_bytes = (tmp_path / "steps.json").read_bytes()
    assert 0 < len(step_bytes) <= 8_000_000
    dump = json.loads(step_bytes)
    assert set(dump) == {"contracts", "debug_arena"}
    assert 0 < len(completed.stdout) <= 8_000_000 and len(completed.stderr) <= 100_000
    machine = json.loads(completed.stdout)
    tests = [(n, t) for suite in machine.values() for n, t in suite["test_results"].items()]
    assert len(tests) == 1 and tests[0][1]["status"] == "Success"
    assert tests[0][0].startswith(f"test_invariant_{transition}_transition_")

    compiled = {
        name: contract["evm"]
        for contracts in build_output["contracts"].values()
        for name, contract in contracts.items()
    }
    assert len(compiled) == 2
    mappings = {
        (name, key): parse_solc_bytecode_source_map(
            bytes.fromhex(evm[key]["object"]), evm[key]["sourceMap"]
        )
        for name, evm in compiled.items()
        for key in ("bytecode", "deployedBytecode")
    }
    artifacts = dump["contracts"]["sources"]["artifacts_by_name"]
    assert set(artifacts) == set(compiled)
    unknown_projections = 0
    for name, entries in artifacts.items():
        assert len(entries) == 1
        artifact = entries[0]
        dumped_sources = dump["contracts"]["sources"]["sources_by_id"][artifact["build_id"]]
        for path, source in build_output["sources"].items():
            supplied = dumped_sources[str(source["id"])]
            assert supplied["source"] == build_input["sources"][path]["content"]
            assert supplied["language"] == "Solidity"
            assert supplied["path"] == path
        for key, suffix in (("bytecode", ""), ("deployedBytecode", "_runtime")):
            mapped = mappings[name, key]
            assert len(mapped.instructions) == len(artifact["source_map" + suffix])
            for i, (row, reported) in enumerate(
                zip(
                    mapped.instructions,
                    artifact["source_map" + suffix],
                    strict=True,
                )
            ):
                assert artifact["pc_ic_map" + suffix][str(row.pc)] == i
                # This dump represents unknown (-1) offsets/lengths as zero.
                # Retain the original compiler values; neither version gains a span.
                assert reported == dict(
                    offset=max(0, row.start_byte),
                    length=max(0, row.length),
                    index=row.source_id,
                    jump={"i": 0, "o": 1, "-": 2}[row.jump],
                    modifier_depth=row.modifier_depth,
                )
                unknown_projections += row.start_byte < 0 or row.length < 0

    # Bind local addresses through the original CREATE input/output bytes, not
    # guessed names, source overlap, runtime-prefix similarity or debugger labels.
    deployed: dict[str, str] = {}
    for _, arena in tests[0][1]["traces"]:
        for node in arena["arena"]:
            trace = node["trace"]
            if trace["kind"] != "CREATE":
                continue
            assert trace["success"] is True and trace["address"] not in deployed
            matches = [
                name
                for name, evm in compiled.items()
                if trace["data"] == "0x" + evm["bytecode"]["object"]
                and trace["output"] == "0x" + evm["deployedBytecode"]["object"]
            ]
            assert len(matches) == 1
            deployed[trace["address"]] = matches[0]
    assert set(deployed.values()) == set(compiled)
    checked_steps = 0
    body_pcs: list[int] = []
    for segment in dump["debug_arena"]:
        assert segment["kind"] in {"CREATE", "CALL", "STATICCALL"}
        name = deployed[segment["address"]]
        phase = "bytecode" if segment["kind"] == "CREATE" else "deployedBytecode"
        by_pc = {r.pc: r for r in mappings[name, phase].instructions}
        for step in segment["steps"]:
            row = by_pc[step["pc"]]
            assert step["contract"] == segment["address"]
            assert step["op"] == row.opcode
            assert (None if not row.push_data else "0x" + row.push_data.hex()) == step[
                "immediate_bytes"
            ]
            checked_steps += 1
            if name == "ModifierControl" and phase == "deployedBytecode" and row.modifier_depth > 0:
                body_pcs.append(row.pc)
    assert checked_steps > 0
    assert bool(body_pcs) == (transition == "permitted")
    parser_inputs: dict[str, Any] = dict(
        compiler_transcripts=invocations,
        source_inputs=tuple(
            FoundrySourceInput(p, raw, hashlib.sha256(raw).hexdigest())
            for p, raw in sorted(original.items())
            if p.endswith(".sol")
        ),
        # A test-only selection descriptor, not a production inventory receipt.
        descriptor=synthetic_descriptor(tests[0][0]),
        process_exit_code=completed.returncode,
    )
    observation = parse_forge_debugger_observation(
        (tmp_path / "stdout.txt").read_bytes(), step_bytes, **parser_inputs
    )
    observation.require_code_bound_steps()
    assert len(observation.steps) == checked_steps
    assert len(observation.frames) == sum(len(a["arena"]) for _, a in tests[0][1]["traces"])
    assert observation.compiler_transcript_sha256s == tuple(
        c.transcript_sha256 for c in invocations
    )
    assert observation.machine_stdout_sha256 == hashlib.sha256(completed.stdout).hexdigest()
    assert observation.debugger_dump_sha256 == hashlib.sha256(step_bytes).hexdigest()
    assert observation.execution_scope == "ONE_DEBUGGER_TRACE_NOT_FULL_TEST_OR_FUZZ_POPULATION"
    assert observation.evidence_authority == "UNATTESTED_DEBUGGER_OBSERVATION"
    assert observation.annotation_scope == "HASHED_NOT_USED_FOR_CODE_OR_SOURCE_BINDING"
    assert [
        s.pc
        for s in observation.steps
        if s.phase == "RUNTIME" and s.source_path == "src/ModifierControl.sol" and s.modifier_depth
    ] == body_pcs
    # Original compiler-derived locations are preserved even when debugger labels
    # are unavailable; an omitted or reordered native step is never filled in.
    damaged = json.loads(step_bytes)
    damaged["debug_arena"][0]["steps"].pop()
    with pytest.raises(FoundryDebuggerError, match="step bytes"):
        parse_forge_debugger_observation(
            completed.stdout, json.dumps(damaged).encode(), **parser_inputs
        )
    damaged = json.loads(step_bytes)
    damaged["debug_arena"].reverse()
    with pytest.raises(FoundryDebuggerError):
        parse_forge_debugger_observation(
            completed.stdout, json.dumps(damaged).encode(), **parser_inputs
        )
    (tmp_path / "comparison.json").write_text(
        json.dumps(
            dict(
                compiler_calls=len(compilations),
                checked_steps=checked_steps,
                checked_compiler_maps=len(mappings),
                local_creation_bindings=len(deployed),
                unknown_location_projections=unknown_projections,
                modifier_body_observed_pcs=body_pcs,
                production_parser_steps=len(observation.steps),
                production_parser_frames=len(observation.frames),
                production_parser_observation=observation.evidence_authority,
                production_parser_scope=observation.execution_scope,
                production_parser_annotation_scope=observation.annotation_scope,
                observation="SYNTHETIC_PHASE_SEPARATED_STEPS_NOT_GENERIC_PLACEHOLDER_COVERAGE",
                execution_validated=False,
                coverage_complete=False,
            ),
            indent=2,
        )
    )
    files = sorted(p for p in tmp_path.rglob("*") if p.is_file())
    assert len(files) <= 100 and sum(p.stat().st_size for p in files) < 16_000_000
    (tmp_path / "capture.json").write_text(
        json.dumps(
            dict(
                scope="SYNTHETIC_LOCAL_DEBUGGER_DUMP_UNATTESTED",
                transition=transition,
                command=command,
                forge_sha256=hashlib.sha256(forge.read_bytes()).hexdigest(),
                solc_sha256=hashlib.sha256(solc.read_bytes()).hexdigest(),
                sources={p: hashlib.sha256(raw).hexdigest() for p, raw in original.items()},
                artifacts={
                    p.relative_to(tmp_path).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in files
                },
                returncode=completed.returncode,
                execution_validated=False,
                coverage_complete=False,
                qualification_eligible=False,
            ),
            indent=2,
        )
    )
