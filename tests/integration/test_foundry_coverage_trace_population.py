"""Observe original coverage/debugger populations on a bounded synthetic local VM."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import subprocess
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, NoReturn

import pytest

from mmaudit.scanners.foundry_inventory import FoundrySourceInput
from mmaudit.scanners.foundry_statement_coverage import parse_forge_debug_statement_coverage
from mmaudit.scanners.solc_capture import prepare_owned_coverage_launch, prepare_solc_capture
from mmaudit.solidity.reproduction import MacOSSandboxBackend
from tests.integration.test_foundry_coverage_custody import FIXTURE
from tests.integration.test_mutation_compilation import _solc_0_8_30

POPULATION = FIXTURE.parent / "coverage_trace_population/PopulationControl.t.sol"
NAMES = {
    "unit": "test_invariant_unit_transition_increments_once()",
    "fuzz": "testFuzz_invariant_transition_matches_permission(bool)",
}


@pytest.mark.parametrize("selection", ["unit", "fuzz"])
@pytest.mark.parametrize("trace_mode", ["plain", "dump", "decoded_dump", "debug_dump"])
def test_original_native_coverage_retains_selected_population_and_trace_observations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, selection: str, trace_mode: str
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        pytest.fail("synthetic population control attempted network access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    forge, solc = Path.home() / ".foundry/bin/forge", _solc_0_8_30()
    sandbox = Path("/usr/bin/sandbox-exec")
    if not forge.is_file() or solc is None or not sandbox.is_file():
        pytest.skip("Requires existing external Forge/solc/macOS sandbox; no provisioning")
    forge, solc = forge.resolve(strict=True), solc.resolve(strict=True)
    assert all(not p.is_relative_to(FIXTURE.parents[2]) for p in (forge, solc))
    private = tmp_path / "private"
    workspace = private / "workspace"
    shutil.copytree(FIXTURE, workspace)
    shutil.copyfile(POPULATION, workspace / "test/PopulationControl.t.sol")
    copied_solc = private / "solc"
    shutil.copyfile(solc, copied_solc)
    copied_solc.chmod(0o500)
    original = {
        p.relative_to(workspace).as_posix(): p.read_bytes()
        for p in workspace.rglob("*")
        if p.is_file()
    }
    source_inputs = tuple(
        FoundrySourceInput(p, b, hashlib.sha256(b).hexdigest())
        for p, b in sorted(original.items())
        if p.endswith(".sol")
    )
    artifacts = private / "coverage"
    artifacts.mkdir()
    trusted = private / "trusted-inputs"
    owner = trusted / "coverage-00000"
    owner.mkdir(parents=True)
    session = prepare_solc_capture(
        root=artifacts / "compiler-transcript",
        helper_root=owner / "compiler",
        owner_launch_receipt_path=artifacts / "launch-receipt.json",
        workspace=workspace,
        compiler=copied_solc,
        compiler_sha256=hashlib.sha256(solc.read_bytes()).hexdigest(),
        sources=source_inputs,
        deadline_monotonic=time.monotonic() + 30,
    )
    command = [
        str(forge),
        "coverage",
        "--report",
        "debug",
        "--exclude-tests",
        "--root",
        str(workspace),
        "--match-path",
        "test/PopulationControl.t.sol",
        "--match-contract",
        "^PopulationControlTest$",
        "--match-test",
        "^" + NAMES[selection].replace("(", r"\(").replace(")", r"\)") + "$",
        "--fuzz-seed",
        "0x" + "0" * 63 + "1",
        "--fuzz-runs",
        "8",
        "--use",
        str(session.launcher),
        "--offline",
        "--no-auto-detect",
        "--force",
        "--no-storage-caching",
        "--threads",
        "1",
        "--cache-path",
        str(artifacts / "cache"),
        "--out",
        str(artifacts / "out"),
        "--ast",
        "--json",
    ]
    if trace_mode != "plain":
        command.extend(["--dump", str(artifacts / "steps.json")])
    if trace_mode == "decoded_dump":
        command.append("--decode-internal")
    if trace_mode == "debug_dump":
        command.append("--debug")
    launch = prepare_owned_coverage_launch(
        session=session,
        trusted_root=trusted,
        forge=forge,
        forge_sha256=hashlib.sha256(forge.read_bytes()).hexdigest(),
        command=tuple(command),
        receipt_path=artifacts / "launch-receipt.json",
    )
    backend = MacOSSandboxBackend(str(sandbox))
    wrapped = backend.wrap_without_network(
        list(launch.command),
        workspace=workspace,
        private_dir=private,
        rpc_port=0,
    )
    completed = subprocess.run(
        wrapped,
        cwd=workspace,
        stdin=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        capture_output=True,
        timeout=30,
        check=False,
        shell=False,
    )
    (artifacts / "stdout.txt").write_bytes(completed.stdout)
    (artifacts / "stderr.txt").write_bytes(completed.stderr)
    (artifacts / "returncode.txt").write_text(str(completed.returncode))
    if trace_mode == "dump":
        # The pinned CLI requires a debugger/decoder mode with --dump. This
        # refusal is not a test execution or an empty successful population.
        assert completed.returncode == 2 and b"--debug" in completed.stderr
        assert not completed.stdout
        assert not tuple((session.root / "calls").iterdir())
        assert not (artifacts / "steps.json").exists()
        assert all((workspace / p).read_bytes() == b for p, b in original.items())
        (artifacts / "observation.json").write_text(
            json.dumps(
                {
                    "scope": "SYNTHETIC_CLI_REFUSAL_NO_EXECUTION_OR_COVERAGE",
                    "selection": selection,
                    "trace_mode": trace_mode,
                    "returncode": completed.returncode,
                    "launch_plan_sha256": launch.plan_sha256,
                    "execution_validated": False,
                    "coverage_complete": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    assert completed.returncode == 0, completed.stderr.decode()
    assert all((workspace / p).read_bytes() == b for p, b in original.items())
    records = launch.collect()
    coverage = parse_forge_debug_statement_coverage(completed.stdout)
    machine = json.loads(coverage.machine_json_bytes)
    results = [r for suite in machine.values() for r in suite["test_results"].items()]
    assert len(results) == 1 and results[0][0] == NAMES[selection]
    result = results[0][1]
    assert result["status"] == "Success"
    assert set(result["kind"]) == {"Unit" if selection == "unit" else "Fuzz"}
    if selection == "fuzz":
        assert result["kind"]["Fuzz"]["runs"] == 8
    dumped = artifacts / "steps.json"
    dump = json.loads(dumped.read_bytes()) if dumped.is_file() else None
    steps = [s for a in result["traces"] for n in a[1]["arena"] for s in n["trace"]["steps"]]
    # These are measured limitations of the pinned native producer, not optional
    # success criteria for atomic coverage or a full EVM/fuzz trace population.
    assert dump is None
    if trace_mode == "decoded_dump":
        assert [a[0] for a in result["traces"]] == ["Deployment", "Execution"]
        assert len(steps) == (106 if selection == "unit" else 126)
        assert {s["op"] for s in steps} == {0x56, 0x5B}
    else:
        assert not result["traces"] and not steps
    files = sorted(p for p in artifacts.rglob("*") if p.is_file())
    assert len(files) <= 100 and sum(p.stat().st_size for p in files) <= 16_000_000
    report = {
        "scope": "SYNTHETIC_ORIGINAL_COVERAGE_POPULATION_OBSERVATION_NO_AUTHORITY",
        "selection": selection,
        "trace_mode": trace_mode,
        "kind": result["kind"],
        "returncode": completed.returncode,
        "original_command": command,
        "forge_sha256": launch.forge_sha256,
        "solc_sha256": session.compiler_sha256,
        "launch_plan_sha256": launch.plan_sha256,
        "compiler_transcript_sha256s": [r.transcript_sha256 for r in records],
        "source_sha256s": {s.path: s.source_sha256 for s in source_inputs},
        "coverage_statements": len(coverage.statements),
        "statement_inventory_sha256": coverage.statement_inventory_sha256,
        "reported_statement_hits": [asdict(s) for s in coverage.statements],
        "machine_trace_labels": [a[0] for a in result["traces"]],
        "machine_frames": sum(len(a[1]["arena"]) for a in result["traces"]),
        "machine_steps": len(steps),
        "observed_opcodes": sorted({s["op"] for s in steps}),
        "dump_exists": dumped.is_file(),
        "dump_segments": None if dump is None else len(dump["debug_arena"]),
        "dump_steps": None if dump is None else sum(len(s["steps"]) for s in dump["debug_arena"]),
        "artifacts": {
            p.relative_to(artifacts).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in files
        },
        "execution_validated": False,
        "coverage_complete": False,
    }
    (artifacts / "observation.json").write_text(json.dumps(report, indent=2, sort_keys=True))
