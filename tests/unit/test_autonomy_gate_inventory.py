from __future__ import annotations

import ast
import inspect
import os
import subprocess
import sys
import textwrap
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import pytest
from pydantic import Field, ValidationError, create_model

import mmaudit.orchestration.autonomy_gate_inventory as inventory_module
from mmaudit.config import AuditConfig, AuditRunOptions
from mmaudit.models.schemas import StrictModel
from mmaudit.orchestration.autonomy_gate_inventory import (
    AUTONOMY_INVENTORY_PATH,
    AutonomousGateDisposition,
    AutonomyGateInventory,
    AutonomyInventoryError,
    CompletionInputSourceKind,
    GateImplementationState,
    SourceCoverageClassification,
    _audit_gate_for_path,
    _discover_audited_module_sources,
    _discover_completion_entrypoint_sources,
    _discover_direct_environment_sources,
    _discover_external_input_sources,
    build_autonomy_gate_inventory,
    load_autonomy_gate_inventory,
    render_autonomy_gate_inventory,
)

ROOT = Path(__file__).resolve().parents[2]
_FULL_TREE_ADDITIONS = {
    "models/truncation_tree.py",
    "orchestration/truncation_tree_evidence.py",
    "orchestration/truncation_tree_promotion.py",
}


_CAPTURE_MODULES = {"scanners/solc_capture.py", "solidity/solc_capture_worker.py"}


def _before_property_compiler_inputs(rows, *, family):
    """Retain the complete predecessor after removing only the 21 reviewed new loci."""
    counts_and_pins = {
        "environment": (
            583,
            "d39430929f514d9023a465e11ede76dba5994034d0d732f35cf9c87a0c7b7d9d",
            581,
            "7966553e1c6ed16b03250f4ac4023454588e9004592cb24701ed730c533fac11",
        ),
        "filesystem": (
            2347,
            "321a8c4603179ad294e5af46e578e56452fc4ba3169f837a7d44d8ffbb338959",
            2333,
            "87594869e50937943955010581d3a7982c953086ce24fc79c201eb434d465d23",
        ),
        "runtime": (
            1493,
            "d0d6bd48f4c7c1da3f7135eea2e6c3810b2b7b8a524c8b61189ef41a41191d9f",
            1488,
            "d5d629755cbf0d977b1b35fe700a39d86acd0dda47a37a727c8557fd98cc26ec",
        ),
    }
    count, pin, prior_count, prior_pin = counts_and_pins[family]
    assert len(rows) == count and inventory_module._canonical_sha256(rows) == pin
    previous = tuple(
        row
        for row in rows
        if not (
            row[0] == "solidity/formal.py"
            and (
                row[1].startswith("_CompiledPropertyToolAdapter.")
                or row[1] == "_observe_property_compiler"
            )
        )
    )
    assert len(previous) == prior_count
    assert inventory_module._canonical_sha256(previous) == prior_pin
    return previous


def _before_formal_supervision_environment(rows):
    """Remove exactly the two reviewed platform reads for historical comparisons."""
    rows = _before_property_compiler_inputs(rows, family="environment")
    assert len(rows) == 581 and inventory_module._canonical_sha256(rows) == (
        "7966553e1c6ed16b03250f4ac4023454588e9004592cb24701ed730c533fac11"
    )
    selected = ("solidity/formal.py", "_limit_process", "host-platform")
    added = [row for row in rows if row[:3] == selected]
    assert len(added) == 2 and all(
        row[3] == ("Attribute(value=Name(id='sys', ctx=Load()), attr='platform', ctx=Load())")
        for row in added
    )
    previous = tuple(row for row in rows if row[:3] != selected)
    assert len(previous) == 579 and inventory_module._canonical_sha256(previous) == (
        "ee9d0257948a0542836df12f15cda1044402227eb9645ac5b07ecf05eb05b893"
    )
    return previous


def _before_source_binding_batch_inputs(rows, *, filesystem: bool):
    """Remove exactly the five added descriptor-held source-batch observations."""
    rows = _before_property_compiler_inputs(rows, family="filesystem" if filesystem else "runtime")
    count, pin = (
        (2333, "87594869e50937943955010581d3a7982c953086ce24fc79c201eb434d465d23")
        if filesystem
        else (1488, "d5d629755cbf0d977b1b35fe700a39d86acd0dda47a37a727c8557fd98cc26ec")
    )
    assert len(rows) == count and inventory_module._canonical_sha256(rows) == pin

    def row(scope, kind, expression):
        return (
            "release_io.py",
            scope,
            kind,
            inventory_module._canonical_ast_dump(ast.parse(expression, mode="eval").body),
        )

    expected = (
        {
            row("revalidate_evidence_file_bindings", "metadata-observation", "path.lstat()"),
            row("_require_evidence_binding_batch_root", "metadata-observation", "path.lstat()"),
            row(
                "_require_evidence_binding_batch_root", "metadata-observation", "path.is_junction()"
            ),
            row(
                "_require_evidence_binding_batch_root",
                "metadata-observation",
                "os.fstat(root.descriptor)",
            ),
        }
        if filesystem
        else {
            row("revalidate_evidence_file_bindings", "descriptor-io", "os.close(root.descriptor)")
        }
    )
    assert sum(value in expected for value in rows) == len(expected)
    previous = tuple(value for value in rows if value not in expected)
    previous_count, previous_pin = (
        (2329, "66c4249f90b4ed9bff68db3c9a58f005c623e5a6ca71fe9af183278a2590a738")
        if filesystem
        else (1487, "4c787191bcf8ca1023c1e799865406fcce0840fbf9329047b6a335ae58507bc0")
    )
    assert len(previous) == previous_count
    assert inventory_module._canonical_sha256(previous) == previous_pin
    return previous


def _before_formal_supervision_inputs(rows, *, filesystem: bool):
    """Rejoin only the reviewed descriptor reads, child binding and supervision observations."""
    rows = _before_source_binding_batch_inputs(rows, filesystem=filesystem)
    count, pin = (
        (2329, "66c4249f90b4ed9bff68db3c9a58f005c623e5a6ca71fe9af183278a2590a738")
        if filesystem
        else (1487, "4c787191bcf8ca1023c1e799865406fcce0840fbf9329047b6a335ae58507bc0")
    )
    assert len(rows) == count and inventory_module._canonical_sha256(rows) == pin

    def expression(source):
        return inventory_module._canonical_ast_dump(ast.parse(source, mode="eval").body)

    previous = []
    polls = 0
    for path, scope, kind, value in rows:
        if path == "solidity/formal.py":
            if scope == "_bounded_process.output_exceeded":
                if not filesystem:
                    assert value in {
                        expression("stdout_handle.fileno()"),
                        expression("stderr_handle.fileno()"),
                    }
                    continue
                scope = "_bounded_process"
                for stream in ("stdout", "stderr"):
                    value = value.replace(
                        expression(f"os.fstat({stream}_handle.fileno())"),
                        expression(f"{stream}_path.stat()"),
                    )
            if scope == "_bounded_process" and not filesystem:
                if kind == "process-observation" or value == expression(
                    "process.wait(timeout=0.05)"
                ):
                    continue
                if value == expression("process.poll()"):
                    polls += 1
                    if polls == 2:
                        continue
                if kind == "child-dispatch":
                    selected = expression("partial(_limit_process, nproc_ceiling=nproc_ceiling)")
                    assert value.count(selected) == 1
                    value = value.replace(selected, expression("_limit_process"))
        previous.append((path, scope, kind, value))
    if not filesystem:
        assert polls == 2
    return tuple(previous)


def _before_batch_custody_inputs(rows, *, filesystem: bool):
    """Rejoin only the reviewed read-helper moves and bounded batch observations."""
    rows = _before_formal_supervision_inputs(rows, filesystem=filesystem)
    if not filesystem:
        assert len(rows) == 1482 and inventory_module._canonical_sha256(rows) == (
            "d07e1e1d0a2eb35c098f33fbb7dbca0b29ed89b7e9a594bd0b5e7218142cbe3a"
        )
        replay_rows = [row for row in rows if row[0] == "scanners/foundry_normalization.py"]
        assert replay_rows == [
            (
                "scanners/foundry_normalization.py",
                "reparse_retained_foundry_findings",
                "elapsed-clock",
                "Call(func=Attribute(value=Name(id='time', ctx=Load()), attr='monotonic', ctx=Load()))",
            )
        ]
        rows = tuple(row for row in rows if row not in replay_rows)
        assert len(rows) == 1481 and inventory_module._canonical_sha256(rows) == (
            "1b8c9d8411fb26c3126e2a9b61e0da3d7968125819ca686ccfa9b87b13e9b778"
        )
        formatter_rows = [row for row in rows if row[1] == "_canonical_ast_dump"]
        assert formatter_rows == [
            (
                "orchestration/autonomy_gate_inventory.py",
                "_canonical_ast_dump",
                "dynamic-attribute",
                "Call(func=Name(id='getattr', ctx=Load()), args=[Call(func=Name(id='type', "
                "ctx=Load()), args=[Name(id='value', ctx=Load())]), Name(id='name', ctx=Load()), "
                "Constant(value=Ellipsis)])",
            )
        ]
        rows = tuple(row for row in rows if row not in formatter_rows)
        assert len(rows) == 1480 and inventory_module._canonical_sha256(rows) == (
            "8f07e7c57665f056e3e0a57d825ca2b8f60cf4277775e9935e526fecc4daf938"
        )
        added = [row for row in rows if row[0] == "models/development_corpus_replay.py"]
        assert added == [
            (
                "models/development_corpus_replay.py",
                "development_corpus_replay_scope",
                "runtime-method",
                "Call(func=Attribute(value=Name(id='state', ctx=Load()), attr='close', ctx=Load()))",
            )
        ]
        rows = tuple(row for row in rows if row[0] != "models/development_corpus_replay.py")
    count, pin = (
        (2329, "dcdd5f89556528ae1220db1ce5620f49e59f5c8ae94afbc38e80392fc632e43f")
        if filesystem
        else (1479, "b218795e05c4cbd5d01155660f5dd05d6e72356d4852dbf8e4623b6a1c639009")
    )
    assert len(rows) == count and inventory_module._canonical_sha256(rows) == pin
    if filesystem:
        return tuple(
            (row[0], "_read_file_once", *row[2:])
            if row[0] == "release_io.py" and row[1] == "_read_file_at_parent"
            else row
            for row in rows
            if not (row[0] == "repository/file_custody.py" and row[1] == "_require_batch_ancestry")
        )
    moved = [
        row
        for row in rows
        if row[0] == "release_io.py"
        and row[1] in {"_read_file_once", "_read_file_at_root", "_read_file_at_parent"}
    ]
    assert len(moved) == 3 and [row[1] for row in moved] == [
        "_read_file_once",
        "_read_file_at_root",
        "_read_file_at_parent",
    ]
    original = []
    for row in rows:
        if row == moved[0]:
            original.extend((item[0], "_read_file_once", *item[2:]) for item in reversed(moved))
        elif row not in moved and not (
            row[0] == "repository/file_custody.py"
            and row[1] == "require_regular_file_custody_batch_unchanged"
        ):
            original.append(row)
    return tuple(original)


def _before_lazy_tree_inputs(rows, *, filesystem: bool):
    """Remove only four deferred-bundle observations or the progress field census."""
    rows = _before_batch_custody_inputs(rows, filesystem=filesystem)
    if filesystem:
        assert len(rows) == 2325 and inventory_module._canonical_sha256(rows) == (
            "19c4be6753c9aa9dd3c29ec48a5832e16572a8d271130d2088248800bc18b8f9"
        )
        rows = tuple(
            row
            for row in rows
            if not (row[0] == "orchestration/development_tree.py" and row[1] == "_checkpoint_names")
        )
    count, pin = (
        (2324, "432b3d221e2eac98d3cbf6990e599c6763c2fcf3319be8dea6f5cdaa26945b1a")
        if filesystem
        else (1476, "6add23d0d7037e8a87782ef1aa61044d8ac980e05e461e5dc5d29d8c60138668")
    )
    assert len(rows) == count and inventory_module._canonical_sha256(rows) == pin
    return tuple(
        row
        for row in rows
        if not (
            row[0] == "orchestration/development_tree.py"
            and row[1] in {"_prepare_cases", "run_development_tree_plan.require_inputs"}
            if filesystem
            else row[0] == "models/development_tree_execution.py"
        )
    )


def _before_development_tree_inputs(rows, *, filesystem: bool = False):
    rows = _before_lazy_tree_inputs(rows, filesystem=filesystem)
    current_count, current_pin = (
        (2320, "bd8e81aa11f557d10d9a9c65788454526cf0a9df730f8aeea111e236336a425c")
        if filesystem
        else (1475, "c9ee47c19cd91059d2f91b8b4a13fba4655c0363f03360975fedb5282efceef4")
    )
    assert len(rows) == current_count and inventory_module._canonical_sha256(rows) == current_pin
    rows = tuple(
        row
        for row in rows
        if row[0] not in {"models/development_tree_plan.py", "orchestration/development_tree.py"}
    )
    expected_count, expected_pin = (
        (2311, "f72408ff1a14ec5de0d3f6eb9ae51c5ba4d5fd756cd7697c4c719070ab2831ec")
        if filesystem
        else (1472, "e664df65a011ac509c1ffa0c5e401978d7fe52fa60571b3ce3857dc34bbb331f")
    )
    assert len(rows) == expected_count and inventory_module._canonical_sha256(rows) == expected_pin
    previous = tuple(row for row in rows if row[0] != "repository/development_corpus_tree.py")
    count, pin = (
        (2307, "5c34f20a6e00752ac2d65d04cffbebbf660a60370c8faf7814578e3ce6156032")
        if filesystem
        else (1470, "4094e1bb4d714c21258aa7bdea23f4f6f62e5d462df5e64b63cad2b8193c6c6b")
    )
    assert len(previous) == count and inventory_module._canonical_sha256(previous) == pin
    return previous


def _before_failure_gap_retention(
    rows: tuple[tuple[str, str, str, str], ...],
) -> tuple[tuple[str, str, str, str], ...]:
    """Reconstruct the exact prior population, removing only the reviewed new clock."""
    rows = _before_development_tree_inputs(rows)
    assert len(rows) == 1470 and inventory_module._canonical_sha256(rows) == (
        "4094e1bb4d714c21258aa7bdea23f4f6f62e5d462df5e64b63cad2b8193c6c6b"
    )
    for index, row in enumerate(rows):
        if row[:3] != (
            "scanners/foundry.py",
            "_finalize_foundry_repository_suite",
            "elapsed-clock",
        ):
            continue
        previous = rows[:index] + rows[index + 1 :]
        if inventory_module._canonical_sha256(previous) == (
            "c8bcfe62c84c6d94f4fe4d0bd590b986d5161c94cee4c3fe7f76822c0f62fc8f"
        ):
            return previous
    pytest.fail("the complete predecessor population was not exactly reconstructed")


_DEBUGGER_LIFECYCLE_SCOPES = {
    ("scanners/foundry.py", "_FoundryDebuggerProcess.retained_payload"),
    ("scanners/foundry.py", "_execute_foundry_debugger_trace"),
    ("scanners/foundry.py", "_charge_selected_test_artifacts"),
}


def test_debugger_lifecycle_retains_every_prior_input_locus(
    inventory: AutonomyGateInventory,
) -> None:
    root = ROOT / "src/mmaudit"
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    populations = {
        "runtime": _before_failure_gap_retention(
            inventory_module._runtime_execution_occurrences(root)
        ),
        "filesystem": _before_development_tree_inputs(filesystem, filesystem=True),
        "ambient": _before_formal_supervision_environment(
            inventory_module._direct_environment_occurrences(root)
        ),
    }
    pins = {
        "runtime": (
            1458,
            "04e063bc36eccaef3b4dda1a8c9e80cb9eb110aaa453fa93eacc931db4c2af51",
            11,
            "73c4519ef2bc8d2a9c33cc997ef7e1de54d6c2a9f3be2b75d9c3edd414d8bd1e",
        ),
        "filesystem": (
            2302,
            "6c3e71b049ed7cfa5d224d96d2c5360914ddf82b39bda492f9242bd3dad9c9f4",
            5,
            "6c564acf5c046d41d23d5f123d3d511c83f58706fc71ab010b1ddca73cb9a0be",
        ),
        "ambient": (
            576,
            "64117360b24d4f7bc395aa0e5758b857481fd9148e1576c85a669a750b346168",
            3,
            "47dd0d815aa695b8c121c5cba6e128d7b32d41229b332fdfc769188457118184",
        ),
    }
    for kind, rows in populations.items():
        previous = tuple(row for row in rows if row[:2] not in _DEBUGGER_LIFECYCLE_SCOPES)
        added = tuple(row for row in rows if row[:2] in _DEBUGGER_LIFECYCLE_SCOPES)
        count, pin, added_count, added_pin = pins[kind]
        assert len(previous) == count and inventory_module._canonical_sha256(previous) == pin
        assert len(added) == added_count and inventory_module._canonical_sha256(added) == added_pin
    assert not interactive
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


_SEPARATE_DEBUGGER_SCOPES = {
    ("scanners/solc_capture.py", "OwnedSolcDebuggerLaunch.collect"),
    ("scanners/solc_capture.py", "prepare_owned_debugger_launch"),
    ("solidity/solc_capture_worker.py", "debugger_launch_main"),
}


def _before_separate_debugger(
    rows: tuple[tuple[str, str, str, str], ...],
) -> tuple[tuple[str, str, str, str], ...]:
    return tuple(
        row for row in rows if row[:2] not in _SEPARATE_DEBUGGER_SCOPES | _DEBUGGER_LIFECYCLE_SCOPES
    )


def test_separate_debugger_keeps_every_predecessor_locus_and_gate(
    inventory: AutonomyGateInventory,
) -> None:
    root = ROOT / "src/mmaudit"
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    populations = {
        "runtime": _before_failure_gap_retention(
            inventory_module._runtime_execution_occurrences(root)
        ),
        "filesystem": _before_development_tree_inputs(filesystem, filesystem=True),
        "ambient": _before_formal_supervision_environment(
            inventory_module._direct_environment_occurrences(root)
        ),
    }
    pins = {
        "runtime": (
            1450,
            "eb5bca9d53b51bfc7504c874ef378daff2b38a549187409bdf8722b2e497692b",
            8,
            "7b321a2c592efab4a20c3dc8a30addeb7b3467f55d75a87735325cf05905fb47",
        ),
        "filesystem": (
            2293,
            "998198c7b18162b9c1b15d0e041e07fe6913197fa11096199bb476ab9de29565",
            9,
            "871dcd12cf8aab13218e7b5413e4a6419652bf1e61812a6c175e170cf4e9e731",
        ),
        "ambient": (
            574,
            "2ff3319c262a805cd2b066d932ce4e57292f8a68891ca776a3239c8e98d4522e",
            2,
            "62f9462368575293dcecf6e1e42f789d0f4513d8392ea0d7f2248192fce8e4fd",
        ),
    }
    for kind, rows in populations.items():
        previous = _before_separate_debugger(rows)
        added = tuple(row for row in rows if row[:2] in _SEPARATE_DEBUGGER_SCOPES)
        count, pin, added_count, added_pin = pins[kind]
        assert len(previous) == count and inventory_module._canonical_sha256(previous) == pin
        assert len(added) == added_count and inventory_module._canonical_sha256(added) == added_pin
    assert not interactive
    assert (
        inventory_module._canonical_sha256(inventory_module._entropy_input_occurrences(root))
        == "0733596cdf7a505c59105dc60a1c8c22a9c65873112b7f45ffc4c47be0aad5b0"
    )
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_pure_invocation_replay_adds_only_reviewed_gated_runtime_members(inventory):
    root = ROOT / "src/mmaudit"
    sources = {
        s.source_id: s
        for s in inventory.source_coverage
        if "models.development_corpus_replay" in s.source_id
    }
    assert set(sources) == {
        "audited-module:models.development_corpus_replay",
        "runtime-input:models.development_corpus_replay:development_corpus_replay_scope:runtime-method:1",
    }
    assert all(s.classification is SourceCoverageClassification.GATE for s in sources.values())
    assert sources["audited-module:models.development_corpus_replay"].logical_gate_id == (
        "gate-runtime-package-integrity"
    )
    assert (
        sources[
            "runtime-input:models.development_corpus_replay:development_corpus_replay_scope:runtime-method:1"
        ].logical_gate_id
        == "gate-client-audit-scope"
    )
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    _before_batch_custody_inputs(filesystem, filesystem=True)
    _before_batch_custody_inputs(
        inventory_module._runtime_execution_occurrences(root), filesystem=False
    )
    assert not interactive
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def _paths_before_automatic_tree(source_root: Path) -> list[str]:
    paths = [
        path.relative_to(source_root).as_posix()
        for path in inventory_module._runtime_package_paths(source_root)
    ]
    assert len(paths) == 367 and inventory_module._canonical_sha256(paths) == (
        "6c7961edf762436bba1a941d16b13c24732976561fbd738cd7a217c5093af788"
    )
    paths = [p for p in paths if p != "scanners/foundry_normalization.py"]
    assert len(paths) == 366 and inventory_module._canonical_sha256(paths) == (
        "e2bf0e2179382d4dac3d2ddcf5844d1695e6a60ef3ac6bec6db4cb63e0669479"
    )
    paths = [p for p in paths if p != "models/development_corpus_replay.py"]
    assert len(paths) == 365 and inventory_module._canonical_sha256(paths) == (
        "332b4e97da003815d4932ba50b83b859e0ef87fe374f5b68202be4c481e6ac7e"
    )
    previous = [
        p
        for p in paths
        if p
        not in {
            "models/development_tree_plan.py",
            "models/development_tree_request_bounds.py",
            "models/development_tree_execution.py",
            "repository/development_tree_plan.py",
            "orchestration/development_tree.py",
        }
    ]
    assert len(previous) == 360 and inventory_module._canonical_sha256(previous) == (
        "bc532e6a4e1b3aba94eeb680a27c3eb14fcf565ae3c31183c5187813263cec41"
    )
    return previous


def _paths_before_source_partitions(source_root: Path) -> list[str]:
    paths = _paths_before_automatic_tree(source_root)
    assert len(paths) == 360 and inventory_module._canonical_sha256(paths) == (
        "bc532e6a4e1b3aba94eeb680a27c3eb14fcf565ae3c31183c5187813263cec41"
    )
    previous = [
        p
        for p in paths
        if p
        not in {
            "models/development_corpus_partition.py",
            "repository/development_corpus_partition.py",
        }
    ]
    assert len(previous) == 358 and inventory_module._canonical_sha256(previous) == (
        "cc2f165b7e2a30aba303306e7a3d55f1ab5a61e6e1611ea88a6a15ec07b10c79"
    )
    return previous


def _paths_before_context_sources(source_root: Path) -> list[str]:
    paths = _paths_before_source_partitions(source_root)
    assert len(paths) == 358 and inventory_module._canonical_sha256(paths) == (
        "cc2f165b7e2a30aba303306e7a3d55f1ab5a61e6e1611ea88a6a15ec07b10c79"
    )
    previous = [
        p
        for p in paths
        if p
        not in {
            "models/development_corpus_coverage.py",
            "orchestration/development_corpus_coverage.py",
        }
    ]
    assert len(previous) == 356 and inventory_module._canonical_sha256(previous) == (
        "c4e1b90be1e1ebdbe264ff51bb38ddb817dc73e1891f8c5faa931d1d7e76896b"
    )
    return previous


def _paths_before_static_call_closure(source_root: Path) -> list[str]:
    paths = _paths_before_context_sources(source_root)
    assert len(paths) == 356 and inventory_module._canonical_sha256(paths) == (
        "c4e1b90be1e1ebdbe264ff51bb38ddb817dc73e1891f8c5faa931d1d7e76896b"
    )
    previous = [p for p in paths if p != "solidity/dependency_static_closure.py"]
    assert len(previous) == 355 and inventory_module._canonical_sha256(previous) == (
        "b4d23c6c495fdd488109b0c963fc8a93b7a597f309f8e7f0a5de866197ca5cfe"
    )
    return previous


def _paths_before_constructor_resolution(source_root: Path) -> list[str]:
    paths = _paths_before_static_call_closure(source_root)
    assert len(paths) == 355 and inventory_module._canonical_sha256(paths) == (
        "b4d23c6c495fdd488109b0c963fc8a93b7a597f309f8e7f0a5de866197ca5cfe"
    )
    previous = [p for p in paths if p != "solidity/dependency_constructors.py"]
    assert len(previous) == 354 and inventory_module._canonical_sha256(previous) == (
        "8f0c339c7d74046a7085d24e2243271d8dc185f7e31a595da0db991e3a7f6cfa"
    )
    return previous


def _paths_before_syntax_accounting(source_root: Path) -> list[str]:
    paths = _paths_before_constructor_resolution(source_root)
    assert len(paths) == 354 and inventory_module._canonical_sha256(paths) == (
        "8f0c339c7d74046a7085d24e2243271d8dc185f7e31a595da0db991e3a7f6cfa"
    )
    previous = [p for p in paths if p != "solidity/dependency_syntax.py"]
    assert len(previous) == 353 and inventory_module._canonical_sha256(previous) == (
        "5118043e2419a365c3c0db77cff45fdbb479c927dbdd5926907760668ab3d997"
    )
    return previous


def _paths_before_argument_resolution(source_root: Path) -> list[str]:
    paths = _paths_before_syntax_accounting(source_root)
    assert len(paths) == 353 and inventory_module._canonical_sha256(paths) == (
        "5118043e2419a365c3c0db77cff45fdbb479c927dbdd5926907760668ab3d997"
    )
    previous = [p for p in paths if p != "solidity/dependency_calls.py"]
    assert len(previous) == 352 and inventory_module._canonical_sha256(previous) == (
        "5b63716235a8074727b100ca8e69bc7522bbc7b4dcbc9ef1a31fae98e9ffa0b7"
    )
    return previous


def _paths_before_scoped_resolution(source_root: Path) -> list[str]:
    paths = _paths_before_argument_resolution(source_root)
    assert len(paths) == 352 and inventory_module._canonical_sha256(paths) == (
        "5b63716235a8074727b100ca8e69bc7522bbc7b4dcbc9ef1a31fae98e9ffa0b7"
    )
    previous = [p for p in paths if p != "solidity/dependency_scopes.py"]
    assert len(previous) == 351 and inventory_module._canonical_sha256(previous) == (
        "049f837aa4dfa0f0df1911bb5a8ceca7b679cb6b61d7abe83679ff345dd0c917"
    )
    return previous


def _paths_before_development_tree(source_root: Path) -> list[str]:
    paths = _paths_before_scoped_resolution(source_root)
    previous = [p for p in paths if p != "repository/development_corpus_tree.py"]
    assert len(previous) == 350 and inventory_module._canonical_sha256(previous) == (
        "886b06c01921e5b1ffcd8efab4cd984b565ac29dcb7dc8cd2c3ae22e1dc18c81"
    )
    return previous


def test_scoped_resolution_is_pure_and_retains_all_predecessor_input_loci(inventory):
    root = ROOT / "src/mmaudit"
    assert len(_paths_before_scoped_resolution(root)) == 351
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    _before_development_tree_inputs(filesystem, filesystem=True)
    _before_development_tree_inputs(inventory_module._runtime_execution_occurrences(root))
    assert not interactive
    assert not any(
        row[0] == "solidity/dependency_scopes.py"
        for row in (
            *inventory_module._direct_environment_occurrences(root),
            *inventory_module._entropy_input_occurrences(root),
        )
    )
    sources = {s.source_id: s for s in inventory.source_coverage}
    assert (
        sources["audited-module:solidity.dependency_scopes"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    for name in ("development-scoped-context-evidence", "development-scoped-source-resolution"):
        assert sources["explicit:" + name].logical_gate_id == "gate-client-audit-scope"
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert not inventory.runtime_authority and not inventory.managed_run_ready


def test_argument_return_resolution_is_pure_and_keeps_all_predecessor_inputs(inventory):
    root = ROOT / "src/mmaudit"
    assert len(_paths_before_argument_resolution(root)) == 352
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    assert not interactive
    for rows, pin in (
        (filesystem, inventory_module._FROZEN_FILESYSTEM_INPUT_LOCI_SHA256),
        (
            inventory_module._runtime_execution_occurrences(root),
            inventory_module._FROZEN_RUNTIME_EXECUTION_LOCI_SHA256,
        ),
        (
            inventory_module._direct_environment_occurrences(root),
            inventory_module._FROZEN_DIRECT_ENVIRONMENT_LOCI_SHA256,
        ),
        (
            inventory_module._entropy_input_occurrences(root),
            inventory_module._FROZEN_ENTROPY_INPUT_LOCI_SHA256,
        ),
    ):
        assert inventory_module._canonical_sha256([list(row) for row in rows]) == pin
        assert not any(row[0] == "solidity/dependency_calls.py" for row in rows)
    sources = {s.source_id: s for s in inventory.source_coverage}
    assert (
        sources["audited-module:solidity.dependency_calls"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    for name in ("development-typed-call-evidence", "development-argument-return-resolution"):
        assert sources["explicit:" + name].logical_gate_id == "gate-client-audit-scope"
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert not inventory.runtime_authority and not inventory.managed_run_ready


def test_syntax_accounting_is_pure_and_preserves_every_prior_input_boundary(inventory):
    root = ROOT / "src/mmaudit"
    assert len(_paths_before_syntax_accounting(root)) == 353
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    assert not interactive
    for rows, pin in (
        (filesystem, inventory_module._FROZEN_FILESYSTEM_INPUT_LOCI_SHA256),
        (
            inventory_module._runtime_execution_occurrences(root),
            inventory_module._FROZEN_RUNTIME_EXECUTION_LOCI_SHA256,
        ),
        (
            inventory_module._direct_environment_occurrences(root),
            inventory_module._FROZEN_DIRECT_ENVIRONMENT_LOCI_SHA256,
        ),
        (
            inventory_module._entropy_input_occurrences(root),
            inventory_module._FROZEN_ENTROPY_INPUT_LOCI_SHA256,
        ),
    ):
        assert inventory_module._canonical_sha256([list(row) for row in rows]) == pin
        assert not any(row[0] == "solidity/dependency_syntax.py" for row in rows)
    sources = {s.source_id: s for s in inventory.source_coverage}
    assert (
        sources["audited-module:solidity.dependency_syntax"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    for name in ("development-syntax-census-evidence", "development-source-syntax-accounting"):
        assert sources["explicit:" + name].logical_gate_id == "gate-client-audit-scope"
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert not inventory.runtime_authority and not inventory.managed_run_ready


def test_constructor_resolution_is_pure_and_preserves_every_prior_input_boundary(inventory):
    root = ROOT / "src/mmaudit"
    assert len(_paths_before_constructor_resolution(root)) == 354
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    assert not interactive
    for rows, pin in (
        (filesystem, inventory_module._FROZEN_FILESYSTEM_INPUT_LOCI_SHA256),
        (
            inventory_module._runtime_execution_occurrences(root),
            inventory_module._FROZEN_RUNTIME_EXECUTION_LOCI_SHA256,
        ),
        (
            inventory_module._direct_environment_occurrences(root),
            inventory_module._FROZEN_DIRECT_ENVIRONMENT_LOCI_SHA256,
        ),
        (
            inventory_module._entropy_input_occurrences(root),
            inventory_module._FROZEN_ENTROPY_INPUT_LOCI_SHA256,
        ),
    ):
        assert inventory_module._canonical_sha256([list(row) for row in rows]) == pin
        assert not any(row[0] == "solidity/dependency_constructors.py" for row in rows)
    sources = {s.source_id: s for s in inventory.source_coverage}
    assert (
        sources["audited-module:solidity.dependency_constructors"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    for name in ("development-constructor-evidence", "development-constructor-source-resolution"):
        assert sources["explicit:" + name].logical_gate_id == "gate-client-audit-scope"
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert not inventory.runtime_authority and not inventory.managed_run_ready


def test_static_call_closure_preserves_input_boundaries_and_adds_no_authority(inventory):
    root = ROOT / "src/mmaudit"
    assert len(_paths_before_static_call_closure(root)) == 355
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    assert not interactive
    for rows, pin in (
        (filesystem, inventory_module._FROZEN_FILESYSTEM_INPUT_LOCI_SHA256),
        (
            inventory_module._runtime_execution_occurrences(root),
            inventory_module._FROZEN_RUNTIME_EXECUTION_LOCI_SHA256,
        ),
        (
            inventory_module._direct_environment_occurrences(root),
            inventory_module._FROZEN_DIRECT_ENVIRONMENT_LOCI_SHA256,
        ),
        (
            inventory_module._entropy_input_occurrences(root),
            inventory_module._FROZEN_ENTROPY_INPUT_LOCI_SHA256,
        ),
    ):
        assert inventory_module._canonical_sha256([list(row) for row in rows]) == pin
        assert not any(row[0] == "solidity/dependency_static_closure.py" for row in rows)
    sources = {s.source_id: s for s in inventory.source_coverage}
    assert (
        sources["audited-module:solidity.dependency_static_closure"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    for name in ("development-static-closure-evidence", "development-static-closure-computation"):
        assert sources["explicit:" + name].logical_gate_id == "gate-client-audit-scope"
    assert (
        inventory.logical_gate_count,
        inventory.unsatisfied_gate_count,
        inventory.current_manual_gate_count,
    ) == (35, 29, 15)
    assert not inventory.runtime_authority and not inventory.managed_run_ready


def test_source_partitions_preserve_inputs_and_gate_every_origin_boundary(inventory):
    root = ROOT / "src/mmaudit"
    assert len(_paths_before_source_partitions(root)) == 358
    sources = {s.source_id: s for s in inventory.source_coverage}
    for name in ("models.development_corpus_partition", "repository.development_corpus_partition"):
        assert sources["audited-module:" + name].logical_gate_id == "gate-runtime-package-integrity"
    expected = {
        "origin",
        "evidence",
        "derivation",
        "replay",
        "custody",
        "origin-handoff",
        "bound-loader",
        "output",
    }
    selected = {k: s for k, s in sources.items() if k.startswith("explicit:development-partition-")}
    assert set(selected) == {"explicit:development-partition-" + name for name in expected}
    for name in expected:
        source = selected["explicit:development-partition-" + name]
        assert source.classification is SourceCoverageClassification.GATE
        assert source.logical_gate_id == (
            "gate-managed-output-provisioning" if name == "output" else "gate-client-audit-scope"
        )
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert not inventory.runtime_authority and not inventory.managed_run_ready


def test_context_source_coverage_preserves_prior_inputs_and_gate_dispositions(inventory):
    root = ROOT / "src/mmaudit"
    assert len(_paths_before_context_sources(root)) == 356
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    assert not interactive
    for rows, pin in (
        (filesystem, inventory_module._FROZEN_FILESYSTEM_INPUT_LOCI_SHA256),
        (
            inventory_module._runtime_execution_occurrences(root),
            inventory_module._FROZEN_RUNTIME_EXECUTION_LOCI_SHA256,
        ),
        (
            inventory_module._direct_environment_occurrences(root),
            inventory_module._FROZEN_DIRECT_ENVIRONMENT_LOCI_SHA256,
        ),
        (
            inventory_module._entropy_input_occurrences(root),
            inventory_module._FROZEN_ENTROPY_INPUT_LOCI_SHA256,
        ),
    ):
        assert inventory_module._canonical_sha256([list(row) for row in rows]) == pin
    sources = {s.source_id: s for s in inventory.source_coverage}
    for name in ("models.development_corpus_coverage", "orchestration.development_corpus_coverage"):
        assert sources["audited-module:" + name].logical_gate_id == "gate-runtime-package-integrity"
    for name in (
        "development-primary-context-partition",
        "development-tree-primary-coverage-evidence",
        "development-tree-primary-coverage-computation",
        "development-tree-primary-coverage-cli",
    ):
        assert sources["explicit:" + name].logical_gate_id == "gate-client-audit-scope"
    assert (
        sources["explicit:development-tree-primary-coverage-output"].logical_gate_id
        == "gate-managed-output-provisioning"
    )
    assert (
        inventory.logical_gate_count,
        inventory.unsatisfied_gate_count,
        inventory.current_manual_gate_count,
    ) == (35, 29, 15)
    assert not inventory.runtime_authority and not inventory.managed_run_ready


def test_development_tree_retains_prior_inputs_and_gates_every_new_namespace_boundary(inventory):
    root = ROOT / "src/mmaudit"
    assert len(_paths_before_development_tree(root)) == 350
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    _before_development_tree_inputs(filesystem, filesystem=True)
    _before_development_tree_inputs(inventory_module._runtime_execution_occurrences(root))
    assert not interactive
    module = "repository/development_corpus_tree.py"
    assert not any(r[0] == module for r in inventory_module._direct_environment_occurrences(root))
    assert not any(r[0] == module for r in inventory_module._entropy_input_occurrences(root))
    sources = [
        s
        for s in inventory.source_coverage
        if "repository.development_corpus_tree" in s.source_id
        or s.source_id.startswith("explicit:development-tree-")
    ]
    coverage_sources = {
        s.source_id: s.logical_gate_id
        for s in sources
        if s.source_id.startswith("explicit:development-tree-primary-coverage-")
    }
    assert coverage_sources == {
        "explicit:development-tree-primary-coverage-cli": "gate-client-audit-scope",
        "explicit:development-tree-primary-coverage-computation": "gate-client-audit-scope",
        "explicit:development-tree-primary-coverage-evidence": "gate-client-audit-scope",
        "explicit:development-tree-primary-coverage-output": "gate-managed-output-provisioning",
    }
    previous = [s for s in sources if s.source_id not in coverage_sources]
    assert len(sources) == 18 and len(previous) == 14
    assert Counter(s.logical_gate_id for s in previous) == {
        "gate-client-audit-scope": 12,
        "gate-runtime-package-integrity": 1,
        "gate-managed-output-provisioning": 1,
    }
    assert all(s.classification is SourceCoverageClassification.GATE for s in sources)
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def _paths_before_dependency_targets(source_root: Path) -> list[str]:
    paths = _paths_before_development_tree(source_root)
    assert len(paths) == 350 and inventory_module._canonical_sha256(paths) == (
        "886b06c01921e5b1ffcd8efab4cd984b565ac29dcb7dc8cd2c3ae22e1dc18c81"
    )
    previous = [p for p in paths if p != "solidity/dependency_targets.py"]
    assert len(previous) == 349 and inventory_module._canonical_sha256(previous) == (
        "e0625f0f3606f2507201029e31f4ea432ba636afcb952f6e3c6c2045c01ed143"
    )
    return previous


def test_dependency_targets_add_only_one_pure_gated_module(
    inventory: AutonomyGateInventory,
) -> None:
    root = ROOT / "src/mmaudit"
    assert len(_paths_before_dependency_targets(root)) == 349
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    assert not interactive
    for population in (
        filesystem,
        inventory_module._runtime_execution_occurrences(root),
        inventory_module._direct_environment_occurrences(root),
        inventory_module._entropy_input_occurrences(root),
    ):
        assert not any(r[0] == "solidity/dependency_targets.py" for r in population)
    selected = [
        s
        for s in inventory.source_coverage
        if s.source_id == "audited-module:solidity.dependency_targets"
    ]
    assert len(selected) == 1 and selected[0].logical_gate_id == "gate-runtime-package-integrity"
    assert selected[0].classification is SourceCoverageClassification.GATE
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def _paths_before_dependency_closure(source_root: Path) -> list[str]:
    paths = _paths_before_dependency_targets(source_root)
    assert len(paths) == 349 and inventory_module._canonical_sha256(paths) == (
        "e0625f0f3606f2507201029e31f4ea432ba636afcb952f6e3c6c2045c01ed143"
    )
    previous = [p for p in paths if p != "solidity/dependency_closure.py"]
    assert len(previous) == 348 and inventory_module._canonical_sha256(previous) == (
        "12b1954bae7c9a797d3a4510ebb92f572db7a3b014fcbfab6877d80cc46f27fc"
    )
    return previous


def test_dependency_closure_adds_only_a_pure_gated_module(inventory: AutonomyGateInventory) -> None:
    root = ROOT / "src/mmaudit"
    assert len(_paths_before_dependency_closure(root)) == 348
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    assert not interactive
    for population in (
        filesystem,
        inventory_module._runtime_execution_occurrences(root),
        inventory_module._direct_environment_occurrences(root),
        inventory_module._entropy_input_occurrences(root),
    ):
        assert not any(r[0] == "solidity/dependency_closure.py" for r in population)
    selected = [
        s
        for s in inventory.source_coverage
        if s.source_id == "audited-module:solidity.dependency_closure"
    ]
    assert len(selected) == 1 and selected[0].logical_gate_id == "gate-runtime-package-integrity"
    assert selected[0].classification is SourceCoverageClassification.GATE
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def _paths_before_debugger_parser(source_root: Path) -> list[str]:
    paths = _paths_before_dependency_closure(source_root)
    assert paths.count("scanners/foundry_debugger.py") == 1
    previous = [p for p in paths if p != "scanners/foundry_debugger.py"]
    assert len(previous) == 347
    assert inventory_module._canonical_sha256(previous) == (
        "31553b27e16fcecf4766e596406b54b32a74ef632730a2350562cd8e3dccb000"
    )
    return previous


def test_debugger_parser_retains_all_predecessor_inputs_and_gates(
    inventory: AutonomyGateInventory,
) -> None:
    root = ROOT / "src/mmaudit"
    assert len(_paths_before_debugger_parser(root)) == 347
    module = "scanners/foundry_debugger.py"
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    assert not interactive
    assert not any(
        r[0] == module
        for rows in (
            filesystem,
            inventory_module._direct_environment_occurrences(root),
            inventory_module._entropy_input_occurrences(root),
        )
        for r in rows
    )
    runtime = _before_separate_debugger(
        _before_failure_gap_retention(inventory_module._runtime_execution_occurrences(root))
    )
    previous = tuple(r for r in runtime if r[0] != module)
    assert len(previous) == 1442
    assert inventory_module._canonical_sha256(previous) == (
        "580b4550a6c71777b9745d8730affa3e21586d1d3fdb1a7e8f8f32599e39f9e7"
    )
    added = [r for r in runtime if r[0] == module]
    assert len(added) == 8
    assert all(r[1:3] == ("_compiler_units", "process-observation") for r in added)
    assert Counter(r[3] for r in added) == Counter(
        {
            ast.dump(ast.parse("call.stdin", mode="eval").body): 4,
            ast.dump(ast.parse("call.stdout", mode="eval").body): 3,
            ast.dump(ast.parse("call.stderr", mode="eval").body): 1,
        }
    )
    selected = [s for s in inventory.source_coverage if "scanners.foundry_debugger" in s.source_id]
    assert len(selected) == 9 and all(
        s.classification is SourceCoverageClassification.GATE for s in selected
    )
    assert Counter(s.logical_gate_id for s in selected) == {
        "gate-runtime-package-integrity": 1,
        "gate-full-quality-analysis": 8,
    }
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def _paths_before_compiler_capture(source_root: Path) -> list[str]:
    paths = _paths_before_debugger_parser(source_root)
    assert all(paths.count(path) == 1 for path in _CAPTURE_MODULES)
    previous = [path for path in paths if path not in _CAPTURE_MODULES]
    assert len(previous) == 345
    assert inventory_module._canonical_sha256(previous) == (
        "c1b1c68d0441e446d76dd93e9ea584f59e98cce567e1e8f1e15b6bcfa5cce25d"
    )
    return previous


def _environment_before_compiler_capture(
    source_root: Path,
) -> tuple[tuple[str, str, str, str], ...]:
    rows = _before_separate_debugger(
        _before_formal_supervision_environment(
            inventory_module._direct_environment_occurrences(source_root)
        )
    )
    previous = tuple(row for row in rows if row[0] not in _CAPTURE_MODULES)
    assert len(rows) - len(previous) == 5 and len(previous) == 569
    assert inventory_module._canonical_sha256(previous) == (
        "fe58c74364e79742296d3541671af62d390523ca30a8763aedd2c4608e22b559"
    )
    return previous


def _external_before_compiler_capture(
    source_root: Path,
) -> tuple[tuple[tuple[str, str, str, str], ...], tuple[tuple[str, str, str], ...]]:
    filesystem, interactive = inventory_module._external_input_occurrences(source_root)
    filesystem = _before_separate_debugger(
        _before_development_tree_inputs(filesystem, filesystem=True)
    )
    owner_additions = {
        # Frozen predecessor spelling, independent of the host's ast.dump defaults.
        "Call(func=Attribute(value=Name(id='trusted_root', ctx=Load()), attr='resolve', "
        "ctx=Load()), keywords=[keyword(arg='strict', value=Constant(value=True))])",
        "Call(func=Attribute(value=Name(id='trusted_root', ctx=Load()), attr='is_dir', "
        "ctx=Load()))",
    }
    new_reader = (
        "Call(func=Attribute(value=Name(id='path', ctx=Load()), attr='read_text', "
        "ctx=Load()), keywords=[keyword(arg='encoding', value=Constant(value='utf-8'))])"
    )
    previous = []
    removed: Counter[str] = Counter()
    for row in filesystem:
        path, scope, _, expression = row
        if path in _CAPTURE_MODULES:
            removed["capture"] += 1
        elif (
            path == "scanners/foundry.py"
            and scope == "_execute_foundry_statement_coverage"
            and expression in owner_additions
        ):
            removed[expression] += 1
        elif (
            path == "orchestration/autonomy_gate_inventory.py"
            and scope == "_runtime_execution_occurrences"
            and expression == new_reader
        ):
            removed["reader"] += 1
        else:
            previous.append(row)
    assert removed == Counter({"capture": 44, "reader": 1, **dict.fromkeys(owner_additions, 1)})
    assert len(previous) == 2246
    assert inventory_module._canonical_sha256(previous) == (
        "6553d887282b7fd2a4810a226562597a7d93b0ce88ed1ea854813d8deb6d05fb"
    )
    return tuple(previous), interactive


def _paths_before_compiler_source(source_root: Path) -> list[str]:
    """Retain every predecessor module while adding a pure exact byte-map helper."""
    paths = _paths_before_compiler_capture(source_root)
    assert paths.count("solidity/compiler_source.py") == 1
    previous = [p for p in paths if p != "solidity/compiler_source.py"]
    assert inventory_module._canonical_sha256(previous) == (
        "02daf640f0a110a7501ae278a9ee7e6ee27fdcfc1af9ca0ed157773c60047e57"
    )
    return previous


def test_compiler_source_map_adds_no_external_input_or_authority(
    inventory: AutonomyGateInventory,
) -> None:
    root = ROOT / "src/mmaudit"
    assert len(_paths_before_compiler_source(root)) == 344
    module = "solidity/compiler_source.py"
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    assert not interactive
    assert not any(
        r[0] == module
        for rows in (
            filesystem,
            inventory_module._direct_environment_occurrences(root),
            inventory_module._entropy_input_occurrences(root),
        )
        for r in rows
    )
    selected = [s for s in inventory.source_coverage if "solidity.compiler_source" in s.source_id]
    assert len(selected) == 1 and selected[0].logical_gate_id == "gate-runtime-package-integrity"
    assert selected[0].classification is SourceCoverageClassification.GATE
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def _paths_before_property_reachability(source_root: Path) -> list[str]:
    """Account for the pure compiler-reference module without dropping predecessor inputs."""
    paths = _paths_before_compiler_source(source_root)
    assert paths.count("solidity/property_reachability.py") == 1
    previous = [p for p in paths if p != "solidity/property_reachability.py"]
    assert inventory_module._canonical_sha256(previous) == (
        "ed86bd63d3136be0e9974575084e3ec960db8a9379b967fa9e091841ce4a95e9"
    )
    return previous


def test_compiler_property_reachability_adds_no_external_input_or_authority(
    inventory: AutonomyGateInventory,
) -> None:
    root = ROOT / "src/mmaudit"
    assert len(_paths_before_property_reachability(root)) == 343
    module = "solidity/property_reachability.py"
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    assert not interactive
    assert not any(
        r[0] == module
        for rows in (
            filesystem,
            inventory_module._direct_environment_occurrences(root),
            inventory_module._entropy_input_occurrences(root),
        )
        for r in rows
    )
    selected = [
        s for s in inventory.source_coverage if "solidity.property_reachability" in s.source_id
    ]
    assert len(selected) == 1 and selected[0].logical_gate_id == "gate-runtime-package-integrity"
    assert selected[0].classification is SourceCoverageClassification.GATE
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def _paths_before_mutation_reconstruction(source_root: Path) -> list[str]:
    """Retain every predecessor module while reviewing one explicit new input consumer."""
    paths = _paths_before_property_reachability(source_root)
    assert paths.count("orchestration/mutation_reconstruction.py") == 1
    previous = [p for p in paths if p != "orchestration/mutation_reconstruction.py"]
    assert inventory_module._canonical_sha256(previous) == (
        "4f23157e2315cab0d9b99b1bfa5fd7609bea851a7c662d37a926f699f61e350c"
    )
    return previous


def test_mutation_reconstruction_preserves_all_original_input_loci_and_authority(
    inventory: AutonomyGateInventory,
) -> None:
    root = ROOT / "src/mmaudit"
    module = "orchestration/mutation_reconstruction.py"
    assert len(_paths_before_mutation_reconstruction(root)) == 342
    filesystem, interactive = _external_before_compiler_capture(root)
    environment = inventory_module._direct_environment_occurrences(root)
    entropy = inventory_module._entropy_input_occurrences(root)
    assert inventory_module._canonical_sha256([list(r) for r in filesystem if r[0] != module]) == (
        "695ae0b807f00cb0c507e32da33d6887f4641cb273a4ef6b7811b08a17a292bc"
    )
    assert len([r for r in filesystem if r[0] == module]) == 7
    assert not interactive and not any(r[0] == module for r in (*environment, *entropy))
    selected = [
        s
        for s in inventory.source_coverage
        if "orchestration.mutation_reconstruction" in s.source_id
    ]
    assert len(selected) == 12
    assert all(s.classification is SourceCoverageClassification.GATE for s in selected)
    assert {s.logical_gate_id for s in selected} == {
        "gate-runtime-package-integrity",
        "gate-benchmark-evidence-authority",
    }
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def _paths_before_mutation_pipeline(source_root: Path) -> list[str]:
    """Keep the original pipeline predecessor independent of later reconstruction inputs."""
    paths = _paths_before_mutation_reconstruction(source_root)
    assert paths.count("orchestration/mutation_pipeline.py") == 1
    previous = [p for p in paths if p != "orchestration/mutation_pipeline.py"]
    assert inventory_module._canonical_sha256(previous) == (
        "d586d605e0862b828922e3d3e7d4785e742d48e94184c3ee5bfa996da866098e"
    )
    return previous


def test_mutation_pipeline_additions_preserve_every_original_input_and_gate(
    inventory: AutonomyGateInventory,
) -> None:
    root = ROOT / "src/mmaudit"
    module = "orchestration/mutation_pipeline.py"
    assert len(_paths_before_mutation_pipeline(root)) == 341
    filesystem, interactive = _external_before_compiler_capture(root)
    entropy = inventory_module._entropy_input_occurrences(root)
    assert inventory_module._canonical_sha256(
        [
            list(r)
            for r in filesystem
            if r[0] not in {module, "orchestration/mutation_reconstruction.py"}
        ]
    ) == ("997d5e65632eaabb8a55cd4933d456f689a60e4d372cce9813d7c7d9fa30178a")
    assert inventory_module._canonical_sha256(
        [
            list(r)
            for r in entropy
            if r[0] not in {module, "orchestration/mutation_reconstruction.py"}
        ]
    ) == ("556dcc2d348b2b7bc3c6c3f11f8828edfb6e1aac0e1c5827b70528cbe32e3836")
    assert len([r for r in filesystem if r[0] == module]) == 6
    assert [(r[1], r[2]) for r in entropy if r[0] == module] == [("_run_project", "uuid.uuid4")]
    sources = [
        s for s in inventory.source_coverage if "orchestration.mutation_pipeline" in s.source_id
    ]
    assert len(sources) == 17 and all(
        s.classification is SourceCoverageClassification.GATE for s in sources
    )
    assert {s.logical_gate_id for s in sources} == {
        "gate-runtime-package-integrity",
        "gate-benchmark-evidence-authority",
    }
    assert not interactive and inventory.unsatisfied_gate_count == 29
    assert not inventory.runtime_authority and not inventory.managed_run_ready


def _paths_before_mutation_discovery(source_root: Path) -> list[str]:
    """Preserve the exact 340-module universe before compiler-bound discovery."""
    paths = _paths_before_mutation_pipeline(source_root)
    addition = "benchmark/mutation_discovery.py"
    assert paths.count(addition) == 1
    previous = [path for path in paths if path != addition]
    assert inventory_module._canonical_sha256(previous) == (
        "e08d45663c36a386d7062b4f1e049f901853c18ded8507bdc9efafd7f1d5f644"
    )
    return previous


def test_mutation_discovery_adds_only_one_gated_pure_module(
    inventory: AutonomyGateInventory,
) -> None:
    root = ROOT / "src/mmaudit"
    assert len(_paths_before_mutation_discovery(root)) == 340
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    assert not any(
        row[0] == "benchmark/mutation_discovery.py"
        for rows in (
            inventory_module._direct_environment_occurrences(root),
            filesystem,
            interactive,
            inventory_module._entropy_input_occurrences(root),
        )
        for row in rows
    )
    source = next(
        item
        for item in inventory.source_coverage
        if item.source_id == "audited-module:benchmark.mutation_discovery"
    )
    assert source.classification is SourceCoverageClassification.GATE
    assert source.logical_gate_id == "gate-runtime-package-integrity"
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def _paths_before_mutation_portfolio(source_root: Path) -> list[str]:
    """Remove exactly the reviewed addition, preserving the frozen earlier universe."""
    paths = _paths_before_mutation_discovery(source_root)
    addition = "benchmark/mutation_portfolio.py"
    assert paths.count(addition) == 1
    previous = [path for path in paths if path != addition]
    assert inventory_module._canonical_sha256(previous) == (
        "3484a6cc2969a7a71c5f57225e98d106fb5345b7bfbca538f0a74055dc6b1fba"
    )
    return previous


def test_mutation_portfolio_adds_one_gated_module_without_external_input(
    inventory: AutonomyGateInventory,
) -> None:
    root = ROOT / "src/mmaudit"
    assert len(_paths_before_mutation_portfolio(root)) == 339
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    assert not any(
        row[0] == "benchmark/mutation_portfolio.py"
        for rows in (
            inventory_module._direct_environment_occurrences(root),
            filesystem,
            interactive,
            inventory_module._entropy_input_occurrences(root),
        )
        for row in rows
    )
    source = next(
        item
        for item in inventory.source_coverage
        if item.source_id == "audited-module:benchmark.mutation_portfolio"
    )
    assert source.classification is SourceCoverageClassification.GATE
    assert source.logical_gate_id == "gate-runtime-package-integrity"
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def _paths_before_provisional_findings(source_root: Path) -> list[str]:
    """Reconstruct the exact previous path universe after only this bounded addition."""

    paths = _paths_before_mutation_portfolio(source_root)
    additions = {"models/provisional_findings.py", "orchestration/provisional_findings.py"}
    assert all(paths.count(path) == 1 for path in additions)
    previous = [path for path in paths if path not in additions]
    assert inventory_module._canonical_sha256(previous) == (
        "82b060558b143698e00958cd8e7fddcb6cb61e78c50d84fc1240fa8087adb65f"
    )
    return previous


def _paths_before_legacy_cost_allowance(source_root: Path) -> list[str]:
    """Keep older temporal comparisons on their exact baseline, not newly added modules."""

    paths = _paths_before_provisional_findings(source_root)
    addition = "models/legacy_cost_allowance.py"
    assert paths.count(addition) == 1
    previous = [path for path in paths if path != addition]
    assert inventory_module._canonical_sha256(previous) == (
        "4b2e21b7ca0329c7cfcfa81deec32305c08f25f369a656e16a9fee49b0b9b719"
    )
    return previous


def test_provisional_findings_add_only_two_gated_modules_without_external_input(
    inventory: AutonomyGateInventory,
) -> None:
    root = ROOT / "src/mmaudit"
    assert len(_paths_before_provisional_findings(root)) == 337
    additions = {"models/provisional_findings.py", "orchestration/provisional_findings.py"}
    environment = inventory_module._direct_environment_occurrences(root)
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    entropy = inventory_module._entropy_input_occurrences(root)
    assert not any(
        row[0] in additions
        for rows in (environment, filesystem, interactive, entropy)
        for row in rows
    )
    sources = {item.source_id: item for item in inventory.source_coverage}
    for path in additions:
        source_id = "audited-module:" + path.removesuffix(".py").replace("/", ".")
        source = sources[source_id]
        assert source.source_path == "src/mmaudit/" + path
        assert source.classification is SourceCoverageClassification.GATE
        assert source.source_kind is CompletionInputSourceKind.AUDITED_MODULE_UNIVERSE
        assert source.source_occurrence_count == 1
        assert source.logical_gate_id == "gate-runtime-package-integrity"
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_legacy_cost_allowance_adds_one_gated_module_and_no_external_input(
    inventory: AutonomyGateInventory,
) -> None:
    root = ROOT / "src/mmaudit"
    assert len(_paths_before_legacy_cost_allowance(root)) == 336
    addition = "models/legacy_cost_allowance.py"
    environment = inventory_module._direct_environment_occurrences(root)
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    entropy = inventory_module._entropy_input_occurrences(root)
    assert not any(
        row[0] == addition
        for rows in (environment, filesystem, interactive, entropy)
        for row in rows
    )
    source = next(
        item
        for item in inventory.source_coverage
        if item.source_id == "audited-module:models.legacy_cost_allowance"
    )
    assert source.classification is SourceCoverageClassification.GATE
    assert source.logical_gate_id == "gate-runtime-package-integrity"
    assert inventory.runtime_authority is inventory.managed_run_ready is False


@pytest.fixture(scope="module")
def inventory() -> AutonomyGateInventory:
    return build_autonomy_gate_inventory(repository_root=ROOT)


@pytest.mark.parametrize(
    "parameter", ("refresh_endpoint_inventory", "primary_judge_endpoint", "replay_judge_endpoint")
)
def test_three_role_refresh_inputs_remain_unsatisfied_model_authority_gates(
    inventory: AutonomyGateInventory, parameter: str
) -> None:
    source = next(
        item
        for item in inventory.source_coverage
        if item.source_id
        == f"completion-entrypoint:models_emit_selection_plan_reactivation:{parameter}"
    )
    assert source.classification is SourceCoverageClassification.GATE
    assert source.logical_gate_id == "gate-autonomous-model-authority"
    assert inventory.runtime_authority is False
    assert inventory.managed_run_ready is False


@pytest.mark.parametrize(
    "anchor",
    (
        "policy",
        "contract",
        "request-binding",
        "budget-consumer",
        "cost-transition",
        "attempt-evidence",
        "usage-binding",
        "planning-envelope",
        "rate-projection",
    ),
)
def test_operator_reservation_consumers_remain_cost_gates_without_runtime_authority(
    inventory: AutonomyGateInventory, anchor: str
) -> None:
    source = next(
        item
        for item in inventory.source_coverage
        if item.source_id == f"explicit:operator-reservation-{anchor}"
    )
    assert source.classification is SourceCoverageClassification.GATE
    assert source.logical_gate_id == "gate-cost-ledger-provisioning"
    assert inventory.runtime_authority is False and inventory.managed_run_ready is False


def test_cost_relaxation_cli_is_a_cost_gate_without_selection_authority(
    inventory: AutonomyGateInventory,
) -> None:
    source = next(
        item
        for item in inventory.source_coverage
        if item.source_id
        == "completion-entrypoint:models_emit_selection_plan_reactivation:reserve_then_reconcile_costs"
    )
    assert source.classification is SourceCoverageClassification.GATE
    assert source.logical_gate_id == "gate-cost-ledger-provisioning"
    assert inventory.runtime_authority is False and inventory.managed_run_ready is False


def test_endpoint_trial_cli_is_a_selection_gate_without_paid_or_adoption_authority(
    inventory: AutonomyGateInventory,
) -> None:
    source = next(
        item
        for item in inventory.source_coverage
        if item.source_id
        == (
            "completion-entrypoint:models_emit_selection_plan_reactivation:candidate_endpoint_trial"
        )
    )
    assert source.classification is SourceCoverageClassification.GATE
    assert source.logical_gate_id == "gate-autonomous-model-authority"
    assert inventory.runtime_authority is False and inventory.managed_run_ready is False


def test_property_compiler_inputs_preserve_predecessor_observations_and_toolchain_gate(
    inventory: AutonomyGateInventory,
) -> None:
    root = ROOT / "src/mmaudit"
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    assert not interactive
    for family, rows in (
        ("environment", inventory_module._direct_environment_occurrences(root)),
        ("filesystem", filesystem),
        ("runtime", inventory_module._runtime_execution_occurrences(root)),
    ):
        _before_property_compiler_inputs(rows, family=family)
    scope = "solidity.formal:_compiledpropertytooladapter."
    expected = {
        f"direct-env-ast:{scope}dependencies:{kind}:1"
        for kind in ("environment-call", "path-resolution")
    }
    for method, count in (
        ("dependencies", 1),
        ("prepare_workspace_with_dependencies", 5),
        ("build_command_with_dependencies", 1),
        ("validate_pre_execution_inputs", 4),
    ):
        expected.update(f"filesystem-input:{scope}{method}:{i}" for i in range(1, count + 1))
    expected.update(
        f"filesystem-input:solidity.formal:_observe_property_compiler:{i}" for i in range(1, 4)
    )
    runtime = f"runtime-input:{scope}prepare_workspace_with_dependencies:"
    expected.add(f"{runtime}descriptor-io:1")
    expected.update(f"{runtime}runtime-method:{i}" for i in range(1, 5))
    selected = [
        row
        for row in inventory.source_coverage
        if scope in row.source_id or "solidity.formal:_observe_property_compiler:" in row.source_id
    ]
    assert len(selected) == 21
    assert {row.source_id for row in selected} == expected
    assert all(row.classification is SourceCoverageClassification.GATE for row in selected)
    assert all(row.logical_gate_id == "gate-managed-toolchain-bundle" for row in selected)
    gate = next(
        gate for gate in inventory.logical_gates if gate.gate_id == "gate-managed-toolchain-bundle"
    )
    assert expected <= set(gate.source_ids)
    assert (
        inventory.logical_gate_count,
        inventory.unsatisfied_gate_count,
        inventory.current_manual_gate_count,
    ) == (35, 29, 15)
    assert not inventory.runtime_authority and not inventory.managed_run_ready


def test_source_binding_batch_keeps_every_predecessor_input_and_gate(inventory):
    root = ROOT / "src/mmaudit"
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    assert not interactive
    _before_source_binding_batch_inputs(filesystem, filesystem=True)
    _before_source_binding_batch_inputs(
        inventory_module._runtime_execution_occurrences(root), filesystem=False
    )
    expected = {
        "filesystem-input:release_io:revalidate_evidence_file_bindings:1",
        "filesystem-input:release_io:_require_evidence_binding_batch_root:1",
        "filesystem-input:release_io:_require_evidence_binding_batch_root:2",
        "filesystem-input:release_io:_require_evidence_binding_batch_root:3",
        "runtime-input:release_io:revalidate_evidence_file_bindings:descriptor-io:1",
    }
    rows = [item for item in inventory.source_coverage if item.source_id in expected]
    assert {item.source_id for item in rows} == expected
    assert all(item.classification is SourceCoverageClassification.GATE for item in rows)
    assert not inventory.runtime_authority and not inventory.managed_run_ready


def test_formal_supervision_retains_predecessor_observations_and_existing_gates(inventory):
    root = ROOT / "src/mmaudit"
    filesystem, interactive = inventory_module._external_input_occurrences(root)
    assert not interactive
    for rows, is_filesystem, count, pin in (
        (
            filesystem,
            True,
            2329,
            "dcdd5f89556528ae1220db1ce5620f49e59f5c8ae94afbc38e80392fc632e43f",
        ),
        (
            inventory_module._runtime_execution_occurrences(root),
            False,
            1482,
            "d07e1e1d0a2eb35c098f33fbb7dbca0b29ed89b7e9a594bd0b5e7218142cbe3a",
        ),
    ):
        previous = _before_formal_supervision_inputs(rows, filesystem=is_filesystem)
        assert len(previous) == count and inventory_module._canonical_sha256(previous) == pin
    environment = _before_property_compiler_inputs(
        inventory_module._direct_environment_occurrences(root), family="environment"
    )
    added = [
        row
        for row in environment
        if row[:3] == ("solidity/formal.py", "_limit_process", "host-platform")
    ]
    assert len(added) == 2
    assert all(
        row[3] == "Attribute(value=Name(id='sys', ctx=Load()), attr='platform', ctx=Load())"
        for row in added
    )
    previous = tuple(row for row in environment if row not in added)
    assert len(previous) == 579 and inventory_module._canonical_sha256(previous) == (
        "ee9d0257948a0542836df12f15cda1044402227eb9645ac5b07ecf05eb05b893"
    )
    selected = [s for s in inventory.source_coverage if "solidity.formal:" in s.source_id]
    assert selected and all(s.classification is SourceCoverageClassification.GATE for s in selected)
    assert all(
        s.logical_gate_id
        in {
            "gate-formal-analysis",
            "gate-managed-toolchain-bundle",
            "gate-provider-secret-transport",
        }
        for s in selected
    )
    assert (
        inventory.logical_gate_count,
        inventory.unsatisfied_gate_count,
        inventory.current_manual_gate_count,
    ) == (35, 29, 15)
    assert not inventory.runtime_authority and not inventory.managed_run_ready


def test_inventory_freezes_the_exact_recursive_source_universe(
    inventory: AutonomyGateInventory,
) -> None:
    assert inventory.source_count == 6160
    assert inventory.source_occurrence_count == 6163
    assert inventory.audit_config_leaf_locator_count == 513
    assert inventory.audit_config_leaf_occurrence_count == 516
    assert inventory.audit_config_shared_locator_count == 3
    assert inventory.audit_run_option_leaf_count == 16
    assert inventory.audit_override_path_count == 51
    assert inventory.environment_override_count == 28
    assert inventory.cli_run_parameter_count == 53
    assert inventory.pipeline_init_parameter_count == 29
    assert inventory.pipeline_run_parameter_count == 16
    assert inventory.completion_entrypoint_parameter_count == 360
    assert {kind.value: count for kind, count in inventory.source_kind_counts.items()} == {
        "AUDIT_CONFIG_LEAF": 513,
        "AUDIT_RUN_OPTION_LEAF": 16,
        "AUDIT_OVERRIDE_PATH": 51,
        "ENVIRONMENT_OVERRIDE": 28,
        "CLI_RUN_PARAMETER": 53,
        "PIPELINE_INIT_PARAMETER": 29,
        "PIPELINE_RUN_PARAMETER": 16,
        "COMPLETION_ENTRYPOINT_PARAMETER": 360,
        "DIRECT_ENVIRONMENT_INPUT": 602,
        "ENTROPY_INPUT": 21,
        "RUNTIME_EXECUTION_INPUT": 1493,
        "AUDITED_MODULE_UNIVERSE": 367,
        "EXPLICIT_NON_FIELD_GATE": 2597,
        "REQUIRED_MISSING_GATE": 14,
    }
    assert Counter(source.classification for source in inventory.source_coverage) == {
        SourceCoverageClassification.GATE: 6108,
        SourceCoverageClassification.NON_GATING_CONTROL: 52,
    }
    assert {item.value for item in SourceCoverageClassification} == {
        "GATE",
        "NON_GATING_CONTROL",
    }
    portfolio = next(
        item
        for item in inventory.source_coverage
        if item.source_id == "audited-module:benchmark.mutation_portfolio"
    )
    assert portfolio.source_path == "src/mmaudit/benchmark/mutation_portfolio.py"
    assert portfolio.logical_gate_id == "gate-runtime-package-integrity"
    assert portfolio.classification is SourceCoverageClassification.GATE
    assert sum(":wall-clock:" in source.source_path for source in inventory.source_coverage) == 108
    assert (
        sum(":working-directory:" in source.source_path for source in inventory.source_coverage)
        == 117
    )
    assert (
        sum(":process-identity" in source.source_path for source in inventory.source_coverage)
        == 140
    )
    assert (
        sum(
            source.source_kind is CompletionInputSourceKind.ENTROPY_INPUT
            for source in inventory.source_coverage
        )
        == 21
    )
    assert (
        sum(":content-read:" in source.source_path for source in inventory.source_coverage) == 322
    )
    assert (
        sum(":directory-enumeration:" in source.source_path for source in inventory.source_coverage)
        == 104  # One bounded checkpoint namespace census.
    )
    assert (
        sum(":metadata-observation:" in source.source_path for source in inventory.source_coverage)
        == 1921  # Thirteen additional pinned property-compiler path and descriptor observations.
    )
    assert all(
        source.classification is SourceCoverageClassification.GATE
        for source in inventory.source_coverage
        if source.source_kind
        in {
            CompletionInputSourceKind.AUDIT_CONFIG_LEAF,
            CompletionInputSourceKind.AUDIT_RUN_OPTION_LEAF,
            CompletionInputSourceKind.AUDIT_OVERRIDE_PATH,
            CompletionInputSourceKind.ENVIRONMENT_OVERRIDE,
            CompletionInputSourceKind.PIPELINE_INIT_PARAMETER,
            CompletionInputSourceKind.PIPELINE_RUN_PARAMETER,
            CompletionInputSourceKind.DIRECT_ENVIRONMENT_INPUT,
            CompletionInputSourceKind.RUNTIME_EXECUTION_INPUT,
            CompletionInputSourceKind.AUDITED_MODULE_UNIVERSE,
            CompletionInputSourceKind.EXPLICIT_NON_FIELD_GATE,
            CompletionInputSourceKind.REQUIRED_MISSING_GATE,
        }
    )


def test_authenticated_calibration_retains_unverified_benchmark_and_custody_gates(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    for source_id, gate_id in {
        "audited-module:models.authenticated_calibration": "gate-runtime-package-integrity",
        "explicit:authenticated-calibration-observation": "gate-benchmark-evidence-authority",
        "explicit:authenticated-calibration-policy-proposal": "gate-benchmark-evidence-authority",
        "explicit:authenticated-calibration-reader": "gate-release-evidence-pipeline",
        "explicit:authenticated-calibration-canonical-bytes": "gate-release-evidence-pipeline",
        "explicit:authenticated-calibration-revocation": "gate-benchmark-evidence-authority",
    }.items():
        assert by_id[source_id].logical_gate_id == gate_id
        assert by_id[source_id].classification is SourceCoverageClassification.GATE
    process_inputs = [
        source
        for source in inventory.source_coverage
        if "models/authenticated_calibration.py:" in source.source_path
        and source.source_kind is CompletionInputSourceKind.DIRECT_ENVIRONMENT_INPUT
    ]
    assert len(process_inputs) == 5
    assert all(
        source.logical_gate_id == "gate-benchmark-evidence-authority" for source in process_inputs
    )
    runtime_inputs = [
        source
        for source in inventory.source_coverage
        if "models/authenticated_calibration.py:" in source.source_path
        and source.source_kind is CompletionInputSourceKind.RUNTIME_EXECUTION_INPUT
    ]
    assert len(runtime_inputs) == 13
    assert all(
        source.logical_gate_id == "gate-runtime-package-integrity"
        and source.classification is SourceCoverageClassification.GATE
        for source in runtime_inputs
    )
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_calibration_accounting_keeps_cost_and_runtime_gates_without_benchmark_authority(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        source
        for source in inventory.source_coverage
        if "orchestration/authenticated_calibration_accounting.py" in source.source_path
    ]
    modules = [
        source
        for source in sources
        if source.source_kind is CompletionInputSourceKind.AUDITED_MODULE_UNIVERSE
    ]
    process_inputs = [
        source
        for source in sources
        if source.source_kind is CompletionInputSourceKind.DIRECT_ENVIRONMENT_INPUT
    ]
    assert len(sources) == 5 and len(modules) == 1 and len(process_inputs) == 4
    assert modules[0].logical_gate_id == "gate-runtime-package-integrity"
    assert all(
        source.logical_gate_id == "gate-cost-ledger-provisioning" for source in process_inputs
    )
    assert all(source.classification is SourceCoverageClassification.GATE for source in sources)
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_retained_runner_and_relocated_ledger_preserve_real_campaign_gates(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    retained = sources["explicit:retained-runner-ledger-custody"]
    assert retained.logical_gate_id == "gate-authenticated-real-campaign"
    module = sources["audited-module:models.authenticated_runner_ledger"]
    assert module.logical_gate_id == "gate-runtime-package-integrity"
    migrated = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("direct-env-ast:models.authenticated_runner_ledger:")
    ]
    assert len(migrated) == 5
    assert all(source.logical_gate_id == "gate-authenticated-real-campaign" for source in migrated)
    assert all(source.classification is SourceCoverageClassification.GATE for source in migrated)
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_owned_openrouter_calibration_batch_does_not_promote_campaign_authority(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    for name in (
        "explicit:authenticated-calibration-batch-ownership",
        "explicit:authenticated-retained-runner-handoff",
    ):
        assert sources[name].logical_gate_id == "gate-authenticated-real-campaign"
        assert sources[name].classification is SourceCoverageClassification.GATE
    module = sources["audited-module:orchestration.authenticated_calibration_openrouter"]
    assert module.logical_gate_id == "gate-runtime-package-integrity"
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_registered_population_does_not_replace_external_campaign_authority(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    for name in (
        "registered-calibration-population",
        "owned-calibration-batch-lifecycle",
        "calibration-population-attempt-prefix",
    ):
        source = sources[f"explicit:{name}"]
        assert source.logical_gate_id == "gate-authenticated-real-campaign"
        assert source.classification is SourceCoverageClassification.GATE
    assert (
        sources["audited-module:orchestration.calibration_population"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    assert (
        sources[
            "filesystem-input:orchestration.calibration_population:_event_names:1"
        ].logical_gate_id
        == "gate-authenticated-real-campaign"
    )
    clocks = [
        source
        for name, source in sources.items()
        if name.startswith("direct-env-ast:orchestration.calibration_population:")
    ]
    assert len(clocks) == 2
    assert all(
        source.logical_gate_id == "gate-trusted-time-independent-replay" for source in clocks
    )
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_registered_measurement_keeps_native_and_external_campaign_gates(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    for name in (
        "registered-native-measurement-lifecycle",
        "registered-measurement-execution",
        "registered-measurement-data-readback",
        "owned-registered-calibration-batch",
    ):
        assert sources[f"explicit:{name}"].logical_gate_id == "gate-authenticated-real-campaign"
    assert (
        sources[
            "audited-module:orchestration.authenticated_calibration_measurement"
        ].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    assert (
        sources[
            "filesystem-input:orchestration.authenticated_calibration_measurement:_output_names:1"
        ].logical_gate_id
        == "gate-authenticated-real-campaign"
    )
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_runner_transfer_retains_the_original_unsatisfied_real_campaign_gate(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    expected = [
        "explicit:runner-custody-transfer",
        "direct-env-ast:models.authenticated_runner:_build_authenticated_cross_lineage_runner_authority:process-identity:1",
        "direct-env-ast:models.authenticated_runner:_build_authenticated_cross_lineage_runner_authority.require_transfer_pristine:process-identity:1",
    ]
    assert all(
        sources[name].logical_gate_id == "gate-authenticated-real-campaign"
        and sources[name].classification is SourceCoverageClassification.GATE
        for name in expected
    )
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_campaign_custody_transfer_preserves_original_unsatisfied_authority_gate(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    expected = [
        "explicit:campaign-custody-transfer",
        "direct-env-ast:benchmark.model_portfolio:_build_campaign_runtime_authority:process-identity:1",
        "direct-env-ast:benchmark.model_portfolio:_build_campaign_runtime_authority.move_capability:process-identity:1",
        "direct-env-ast:benchmark.model_portfolio:_build_campaign_custody_transfer:process-identity-binding:1",
        "direct-env-ast:benchmark.model_portfolio:_build_campaign_custody_transfer:process-identity:1",
        "direct-env-ast:benchmark.model_portfolio:_build_campaign_custody_transfer.pristine:process-identity:1",
    ]
    assert all(
        sources[name].logical_gate_id == "gate-benchmark-evidence-authority"
        and sources[name].classification is SourceCoverageClassification.GATE
        for name in expected
    )
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_generation_custody_transfer_keeps_unsatisfied_authority_gates(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    move = sources["explicit:generation-custody-transfer"]
    assert move.logical_gate_id == "gate-autonomous-model-authority"
    assert move.classification is SourceCoverageClassification.GATE
    process_inputs = [
        source
        for source in inventory.source_coverage
        if source.source_kind is CompletionInputSourceKind.DIRECT_ENVIRONMENT_INPUT
        and "models/generation_evidence.py:_build_generation_custody_transfer" in source.source_path
    ]
    assert len(process_inputs) == 3
    assert all(
        source.logical_gate_id == "gate-autonomous-model-authority"
        and source.classification is SourceCoverageClassification.GATE
        for source in process_inputs
    )
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_development_routing_observation_confers_no_transport_authority(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    for source_id, gate_id in {
        "explicit:development-routing-observation": "gate-provider-secret-transport",
        "audited-module:models.development_routing": "gate-runtime-package-integrity",
    }.items():
        assert by_id[source_id].logical_gate_id == gate_id
        assert by_id[source_id].classification is SourceCoverageClassification.GATE
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_development_measurement_preserves_unverified_benchmark_and_scope_gates(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    for source_id, gate_id in {
        "audited-module:benchmark.development": "gate-runtime-package-integrity",
        "explicit:development-benchmark-truth": "gate-benchmark-evidence-authority",
        "explicit:development-benchmark-plan-binding": "gate-client-audit-scope",
        "explicit:development-benchmark-score": "gate-benchmark-evidence-authority",
    }.items():
        assert by_id[source_id].logical_gate_id == gate_id
        assert by_id[source_id].classification is SourceCoverageClassification.GATE
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_development_shard_boundaries_are_gated_not_a_qualified_audit(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    expected = {
        "explicit:development-audit-frozen-plan": "gate-client-audit-scope",
        "explicit:development-audit-shard-transport": "gate-provider-secret-transport",
        "explicit:development-audit-sequential-run": "gate-full-quality-analysis",
        "audited-module:models.development_audit": "gate-runtime-package-integrity",
        "audited-module:orchestration.development_audit": "gate-runtime-package-integrity",
    }
    for source_id, gate_id in expected.items():
        assert by_id[source_id].logical_gate_id == gate_id
        assert by_id[source_id].classification is SourceCoverageClassification.GATE
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_executable_observation_inputs_join_the_unverified_toolchain_gate(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            "filesystem-input:scanners.base:_observe_scanner_executable:"
        )
    ]
    assert len(sources) == 7
    assert sum(":content-read:" in source.source_path for source in sources) == 1
    assert sum(":metadata-observation:" in source.source_path for source in sources) == 6
    assert all(source.logical_gate_id == "gate-managed-toolchain-bundle" for source in sources)
    assert all(source.classification is SourceCoverageClassification.GATE for source in sources)
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_offline_image_metadata_chain_does_not_promote_layer_or_execution_authority(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    anchor = by_id["explicit:managed-image-metadata-chain"]
    module = by_id["audited-module:orchestration.managed_image_metadata"]
    assert anchor.logical_gate_id == "gate-managed-toolchain-bundle"
    assert module.logical_gate_id == "gate-runtime-package-integrity"
    assert anchor.classification is module.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_local_layer_identity_and_stream_custody_do_not_promote_image_admission(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    assert (
        by_id["explicit:managed-image-layer-bytes"].logical_gate_id
        == "gate-managed-toolchain-bundle"
    )
    assert (
        by_id["explicit:bound-read-only-evidence-stream"].logical_gate_id
        == "gate-release-evidence-pipeline"
    )
    assert (
        by_id["audited-module:orchestration.managed_image_layers"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    stream_inputs = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            (
                "filesystem-input:release_io:stream_file_evidence:",
                "filesystem-input:release_io:_require_stream_custody:",
            )
        )
    ]
    assert len(stream_inputs) == 8
    assert sum(":metadata-observation:" in item.source_path for item in stream_inputs) == 7
    assert sum(":content-read:" in item.source_path for item in stream_inputs) == 1
    assert all(item.logical_gate_id == "gate-release-evidence-pipeline" for item in stream_inputs)
    assert all(item.classification is SourceCoverageClassification.GATE for item in stream_inputs)
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_static_image_membership_keeps_lookup_and_parser_gated_without_runtime_authority(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    assert by_id["explicit:managed-image-file-membership"].logical_gate_id == (
        "gate-managed-toolchain-bundle"
    )
    for module in ("isolation.oci_layer", "orchestration.managed_image_files"):
        assert by_id["audited-module:" + module].logical_gate_id == "gate-runtime-package-integrity"
    # The conservative AST visitor records resolve() even for this in-memory view.
    lookup = by_id[
        "filesystem-input:orchestration.managed_image_files:verify_managed_image_files:1"
    ]
    assert lookup.logical_gate_id == "gate-managed-toolchain-bundle"
    assert lookup.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_prepared_pipeline_inputs_are_classified_without_promoting_authority(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    assert by_id["pipeline-init:host_tools"].logical_gate_id == "gate-managed-toolchain-bundle"
    assert (
        by_id["pipeline-init:managed_backend"].logical_gate_id
        == "gate-reproduction-capability-policy"
    )
    roots = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("filesystem-input:orchestration.managed_pipeline:")
    ]
    assert len(roots) == 4
    assert all(source.logical_gate_id == "gate-managed-toolchain-bundle" for source in roots)
    assert all(":metadata-observation:" in source.source_path for source in roots)
    assert "audited-module:orchestration.managed_pipeline" in by_id
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_prepared_matrix_roots_and_module_are_classified_without_promoting_readiness(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    assert (
        by_id["audited-module:orchestration.managed_fork_matrix"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    roots = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("filesystem-input:orchestration.managed_fork_matrix:")
    ]
    assert len(roots) == 1
    assert roots[0].logical_gate_id == "gate-managed-toolchain-bundle"
    assert ":metadata-observation:" in roots[0].source_path
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_prepared_matrix_uses_existing_observations_without_ambient_tool_selection() -> None:
    from mmaudit.orchestration import managed_fork_matrix

    tree = ast.parse(inspect.getsource(managed_fork_matrix))
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_observe_scanner_executable"
        for node in ast.walk(tree)
    )
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"open", "read_bytes", "which", "getenv"}
        for node in ast.walk(tree)
    )


def test_offline_fork_archive_input_is_classified_without_promoting_a_running_fork(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    source = by_id["explicit:offline-fork-read-archive"]
    assert source.logical_gate_id == "gate-fork-environment"
    assert source.classification is SourceCoverageClassification.GATE
    assert (
        by_id["audited-module:scanners.offline_fork_rpc"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_offline_read_lease_remains_a_fork_prerequisite_not_runtime_authority(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    source = by_id["explicit:offline-fork-read-lease"]
    assert source.logical_gate_id == "gate-fork-environment"
    assert source.classification is SourceCoverageClassification.GATE
    assert (
        by_id["audited-module:scanners.offline_fork_service"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_managed_archive_handoff_inputs_are_explicit_without_promoting_fork_readiness(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    for source_id in (
        "pipeline-init:offline_forks",
        "explicit:managed-offline-fork-archive-preparation",
        "explicit:managed-offline-fork-archive-consumption",
        "filesystem-input:orchestration.managed_fork_archives:_verify_archive_roots:1",
        "filesystem-input:orchestration.managed_fork_archives:_verify_archive_roots:2",
    ):
        assert by_id[source_id].logical_gate_id == "gate-fork-environment"
        assert by_id[source_id].classification is SourceCoverageClassification.GATE
    assert (
        by_id["audited-module:orchestration.managed_fork_archives"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_primary_archive_selection_and_foundry_consumer_are_explicit_nonauthorizing_inputs(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    for source_id in (
        "explicit:managed-offline-primary-archive-selection",
        "explicit:managed-primary-foundry-consumption",
    ):
        assert by_id[source_id].logical_gate_id == "gate-fork-environment"
        assert by_id[source_id].classification is SourceCoverageClassification.GATE
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_reproduction_archive_selection_and_existing_consumer_remain_nonauthorizing_inputs(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    for source_id in (
        "explicit:managed-reproduction-archive-selection",
        "explicit:fork-reproduction-runner",
    ):
        assert by_id[source_id].logical_gate_id == "gate-fork-environment"
        assert by_id[source_id].classification is SourceCoverageClassification.GATE
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_invariant_archive_selection_and_existing_consumer_remain_nonauthorizing_inputs(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    for source_id, gate_id in (
        ("explicit:managed-invariant-archive-selection", "gate-fork-environment"),
        ("explicit:typed-invariant-runner", "gate-invariant-template-library"),
    ):
        assert by_id[source_id].logical_gate_id == gate_id
        assert by_id[source_id].classification is SourceCoverageClassification.GATE
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_hardhat_parent_capture_inputs_do_not_promote_execution_or_runtime_authority(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    assert (
        by_id["audited-module:scanners.hardhat_supervision"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    assert (
        by_id["explicit:hardhat-phase-output-supervision"].logical_gate_id
        == "gate-full-quality-analysis"
    )
    filesystem = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("filesystem-input:scanners.hardhat_supervision:")
    ]
    assert len(filesystem) == 10
    assert all(":metadata-observation:" in source.source_path for source in filesystem)
    assert all(source.logical_gate_id == "gate-full-quality-analysis" for source in filesystem)
    environment = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("direct-env-ast:scanners.hardhat_supervision:")
    ]
    assert {source.source_id for source in environment} == {
        "direct-env-ast:scanners.hardhat_supervision:_root_identity:host-identity:1",
        "direct-env-ast:scanners.hardhat_supervision:"
        "supervise_hardhat_phase_process:host-platform:1",
    }
    assert all(source.logical_gate_id == "gate-managed-toolchain-bundle" for source in environment)
    assert all(
        source.classification is SourceCoverageClassification.GATE
        for source in filesystem + environment
    )
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_hardhat_capture_protocol_join_inputs_preserve_unverified_readiness(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    for source_id in (
        "explicit:hardhat-captured-inventory-preparation",
        "explicit:hardhat-captured-test-consumption",
    ):
        assert by_id[source_id].logical_gate_id == "gate-full-quality-analysis"
        assert by_id[source_id].classification is SourceCoverageClassification.GATE
    assert (
        by_id["audited-module:scanners.hardhat_protocol"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_hardhat_phase_layout_inputs_preserve_unverified_fork_boundary(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    roots = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            "filesystem-input:isolation.container:_hardhat_phase_workspace_identity:"
        )
    ]
    assert len(roots) == 2
    for source in [*roots, by_id["explicit:hardhat-phase-container-layout"]]:
        assert source.logical_gate_id == "gate-fork-environment"
        assert source.classification is SourceCoverageClassification.GATE
    relocated = "filesystem-input:isolation.container:singleloopbackhardhatbackend."
    assert relocated + "wrap_hardhat_fork_suite:1" not in by_id
    assert (
        by_id[relocated + "_wrap_hardhat_with_layout:1"].logical_gate_id == "gate-fork-environment"
    )
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_exact_rootless_cleanup_inputs_never_promote_runtime_admission(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    assert (
        by_id["explicit:rootless-exact-container-cleanup"].logical_gate_id
        == "gate-managed-output-provisioning"
    )
    assert (
        by_id["audited-module:isolation.container_cleanup"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    filesystem = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("filesystem-input:isolation.container_cleanup:")
    ]
    environment = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("direct-env-ast:isolation.container_cleanup:")
    ]
    assert len(filesystem) == 7 and len(environment) == 6
    for source in filesystem + environment:
        expected = (
            "gate-managed-toolchain-bundle"
            if any(
                token in source.source_id
                for token in (
                    ":_runtime_identity:",
                    ":_control_environment:",
                    ":_run_control_command:",
                    ":host-platform:",
                )
            )
            else "gate-managed-output-provisioning"
        )
        assert source.logical_gate_id == expected
        assert source.classification is SourceCoverageClassification.GATE
    assert not any(
        ":RootlessContainerBackend.cleanup:" in s.source_path for s in inventory.source_coverage
    )
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_owned_hardhat_lifecycle_is_classified_without_promoting_admission(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    anchor = by_id["explicit:hardhat-owned-two-phase-execution"]
    module = by_id["audited-module:scanners.hardhat_execution"]
    assert anchor.logical_gate_id == "gate-full-quality-analysis"
    assert module.logical_gate_id == "gate-runtime-package-integrity"
    assert anchor.classification is module.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_phase_finalizer_and_retained_cleanup_handoff_do_not_supply_admission(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    assert (
        by_id["explicit:hardhat-phase-finalization"].logical_gate_id == "gate-full-quality-analysis"
    )
    assert (
        by_id["audited-module:scanners.hardhat_finalization"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    filesystem = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("filesystem-input:scanners.hardhat_finalization:")
    ]
    assert len(filesystem) == 3
    assert all(source.logical_gate_id == "gate-full-quality-analysis" for source in filesystem)
    assert all(source.classification is SourceCoverageClassification.GATE for source in filesystem)
    assert (
        by_id["explicit:rootless-exact-container-cleanup"].logical_gate_id
        == "gate-managed-output-provisioning"
    )
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


@pytest.mark.parametrize("field", ["source_count", "source_occurrence_count", "gate_source_count"])
def test_expanded_inventory_ceiling_remains_bounded(
    inventory: AutonomyGateInventory, field: str
) -> None:
    schema = AutonomyGateInventory.model_json_schema()
    assert schema["properties"][field]["maximum"] == 8192
    assert schema["properties"]["source_coverage"]["maxItems"] == 8192
    values = inventory.model_dump(mode="json")
    values[field] = 8193
    with pytest.raises(ValidationError) as error:
        AutonomyGateInventory.model_validate(values)
    assert any(item["loc"] == (field,) for item in error.value.errors())


def test_host_material_inputs_remain_an_unverified_toolchain_gate(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            (
                "filesystem-input:orchestration.managed_host_tools:",
                "direct-env-ast:orchestration.managed_host_tools:",
            )
        )
    ]
    assert len(sources) == 17
    assert sum(":content-read:" in source.source_path for source in sources) == 2
    assert sum(":metadata-observation:" in source.source_path for source in sources) == 12
    assert sum(":directory-enumeration:" in source.source_path for source in sources) == 1
    assert sum(":host-identity:" in source.source_path for source in sources) == 2
    assert all(source.logical_gate_id == "gate-managed-toolchain-bundle" for source in sources)
    assert all(source.classification is SourceCoverageClassification.GATE for source in sources)
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_isolation_admission_reuses_existing_bounded_filesystem_observations(
    inventory: AutonomyGateInventory,
) -> None:
    from mmaudit.isolation import provenance

    tree = ast.parse(textwrap.dedent(inspect.getsource(provenance._admit_isolation_executable)))
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    assert (
        sum(
            isinstance(node.func, ast.Name) and node.func.id == "_observe_scanner_executable"
            for node in calls
        )
        == 1
    )
    assert not any(
        isinstance(node.func, ast.Attribute) and node.func.attr in {"open", "resolve", "is_file"}
        for node in calls
    )
    assert not hasattr(provenance, "_file_sha256")
    removed = {
        "filesystem-input:isolation.provenance:_file_sha256:1",
        "filesystem-input:isolation.provenance:_seal_builtin_isolation_backend:1",
        "filesystem-input:isolation.provenance:_seal_builtin_isolation_backend:2",
        "filesystem-input:isolation.provenance:_attestation_still_valid:1",
    }
    assert removed.isdisjoint(source.source_id for source in inventory.source_coverage)
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_isolation_sealing_lookup_and_each_probe_preserve_launcher_admission() -> None:
    from mmaudit.isolation import provenance

    expected: dict[Callable[..., object], tuple[int, int]] = {
        provenance._seal_builtin_isolation_backend: (1, 4),
        provenance._attestation_still_valid: (1, 1),
        provenance._execute_probe: (0, 3),
        provenance._run_builtin_preflight: (1, 2),
        provenance._network_probe_denied: (1, 1),
    }
    for consumer, (admit_count, recheck_count) in expected.items():
        tree = ast.parse(textwrap.dedent(inspect.getsource(consumer)))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        named = Counter(node.func.id for node in calls if isinstance(node.func, ast.Name))
        assert named["_admit_isolation_executable"] == admit_count
        assert named["_require_isolation_executable_unchanged"] == recheck_count
        for node in calls:
            if isinstance(node.func, ast.Name) and node.func.id in {
                "_execute_probe",
                "_run_builtin_preflight",
                "_network_probe_denied",
            }:
                assert any(
                    keyword.arg == "admission"
                    and isinstance(keyword.value, ast.Name)
                    and keyword.value.id == "admission"
                    for keyword in node.keywords
                )


def test_absolute_executable_availability_inputs_share_the_unverified_toolchain_gate(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            (
                "filesystem-input:scanners.base:scanner_executable_candidate:",
                "direct-env-ast:scanners.base:scanner_executable_candidate:",
            )
        )
    ]
    assert len(sources) == 3
    assert sum(":metadata-observation:" in source.source_path for source in sources) == 2
    assert sum(":path-resolution:" in source.source_path for source in sources) == 1
    assert all(source.logical_gate_id == "gate-managed-toolchain-bundle" for source in sources)
    assert all(source.classification is SourceCoverageClassification.GATE for source in sources)
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_shared_path_resolver_preserves_all_four_previous_lookup_consumers() -> None:
    from mmaudit.scanners.base import ScannerAdapter
    from mmaudit.scanners.foundry import FoundryForkScanner
    from mmaudit.scanners.runner import preflight_configured_scanner_tools

    for consumer in (
        ScannerAdapter.available,
        ScannerAdapter._run,
        FoundryForkScanner._run_repository_suite,
        preflight_configured_scanner_tools,
    ):
        tree = ast.parse(textwrap.dedent(inspect.getsource(consumer)))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        assert (
            sum(
                isinstance(node.func, ast.Name) and node.func.id == "scanner_executable_candidate"
                for node in calls
            )
            == 1
        )
        assert not any(
            isinstance(node.func, ast.Attribute) and node.func.attr == "which" for node in calls
        )


def test_managed_isolation_cpu_and_os_inputs_retain_unverified_toolchain_gate(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        item
        for item in inventory.source_coverage
        if item.source_id.startswith("direct-env-ast:isolation.managed:")
    ]
    assert len(sources) == 2
    assert all(":host-platform:" in item.source_path for item in sources)
    assert all(item.logical_gate_id == "gate-managed-toolchain-bundle" for item in sources)
    assert all(item.classification is SourceCoverageClassification.GATE for item in sources)
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_managed_compiler_path_checks_remain_unverified_toolchain_inputs(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            "filesystem-input:solidity.compile:_managed_compilation_selection:"
        )
    ]
    assert len(sources) == 2
    assert all(":metadata-observation:" in source.source_path for source in sources)
    assert all(source.logical_gate_id == "gate-managed-toolchain-bundle" for source in sources)
    assert all(source.classification is SourceCoverageClassification.GATE for source in sources)
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_managed_formal_root_checks_remain_unverified_toolchain_inputs(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            "filesystem-input:solidity.formal:_managedformalselection.verify_roots:"
        )
    ]
    assert len(sources) == 2
    assert all(":metadata-observation:" in source.source_path for source in sources)
    assert all(source.logical_gate_id == "gate-managed-toolchain-bundle" for source in sources)
    assert all(source.classification is SourceCoverageClassification.GATE for source in sources)
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_prepared_clean_anvil_root_check_is_classified_without_promoting_readiness(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            "filesystem-input:scanners.clean_chain:_managedcleananviltool.verify:"
        )
    ]
    assert len(sources) == 1
    assert ":metadata-observation:" in sources[0].source_path
    assert sources[0].logical_gate_id == "gate-managed-toolchain-bundle"
    assert sources[0].classification is SourceCoverageClassification.GATE
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_prepared_clean_anvil_reuses_bounded_identity_observation_without_new_path_lookup() -> None:
    from mmaudit.scanners import clean_chain

    parameter = inspect.signature(clean_chain.TrustedCleanAnvilLauncher).parameters["host_tools"]
    assert parameter.default is None
    for consumer in (
        clean_chain._managed_clean_anvil_tool,
        clean_chain._ManagedCleanAnvilTool.verify,
    ):
        tree = ast.parse(textwrap.dedent(inspect.getsource(consumer)))
        assert any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_observe_scanner_executable"
            for node in ast.walk(tree)
        )
        assert not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"open", "read_bytes", "which", "getenv"}
            for node in ast.walk(tree)
        )


def test_managed_reproduction_root_checks_remain_unverified_toolchain_inputs(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            "filesystem-input:solidity.reproduction:_managedreproductionselection.verify_roots:"
        )
    ]
    assert len(sources) == 2
    assert all(":metadata-observation:" in source.source_path for source in sources)
    assert all(source.logical_gate_id == "gate-managed-toolchain-bundle" for source in sources)
    assert all(source.classification is SourceCoverageClassification.GATE for source in sources)
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_managed_reproduction_retains_shared_bounded_identity_and_probe_admission() -> None:
    from mmaudit.solidity import reproduction

    for consumer in (
        reproduction._managed_reproduction_selection,
        reproduction._ManagedReproductionSelection.verify,
    ):
        tree = ast.parse(textwrap.dedent(inspect.getsource(consumer)))
        assert any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_observe_scanner_executable"
            for node in ast.walk(tree)
        )
        assert not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"open", "read_bytes", "which"}
            for node in ast.walk(tree)
        )
    tree = ast.parse(
        textwrap.dedent(
            inspect.getsource(reproduction.ForkReproductionRunner._preflight_managed_tools)
        )
    )
    probes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "isolated_executable_version_probe"
    ]
    assert len(probes) == 1
    assert "expected_host_observation" in {keyword.arg for keyword in probes[0].keywords}


def test_managed_invariant_root_checks_remain_unverified_toolchain_inputs(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            "filesystem-input:solidity.invariant_execution:_managedinvariantselection.verify_roots:"
        )
    ]
    assert len(sources) == 2
    assert all(":metadata-observation:" in source.source_path for source in sources)
    assert all(source.logical_gate_id == "gate-managed-toolchain-bundle" for source in sources)
    assert all(source.classification is SourceCoverageClassification.GATE for source in sources)
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_managed_invariant_retains_shared_bounded_identity_and_probe_admission() -> None:
    from mmaudit.solidity import invariant_execution as invariant

    for consumer in (
        invariant._managed_invariant_selection,
        invariant._ManagedInvariantSelection.verify,
    ):
        tree = ast.parse(textwrap.dedent(inspect.getsource(consumer)))
        assert any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_observe_scanner_executable"
            for node in ast.walk(tree)
        )
        assert not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"open", "read_bytes", "which"}
            for node in ast.walk(tree)
        )
    tree = ast.parse(textwrap.dedent(inspect.getsource(invariant._external_executable_version)))
    probes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "isolated_executable_version_probe"
    ]
    assert len(probes) == 1
    assert "expected_host_observation" in {keyword.arg for keyword in probes[0].keywords}


def test_managed_formal_retains_shared_bounded_identity_and_probe_admission() -> None:
    from mmaudit.solidity import formal

    for consumer in (formal._managed_formal_selection, formal._ManagedFormalSelection.verify):
        tree = ast.parse(textwrap.dedent(inspect.getsource(consumer)))
        assert any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_observe_scanner_executable"
            for node in ast.walk(tree)
        )
        assert not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"open", "read_bytes", "which"}
            for node in ast.walk(tree)
        )
    tree = ast.parse(textwrap.dedent(inspect.getsource(formal._isolated_tool_version)))
    probes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "isolated_executable_version_probe"
    ]
    assert len(probes) == 1
    assert "expected_host_observation" in {keyword.arg for keyword in probes[0].keywords}


def test_managed_compilation_retains_shared_bounded_identity_and_probe_admission() -> None:
    from mmaudit.solidity import compile as compiler

    for consumer in (
        compiler._managed_compilation_selection,
        compiler._ManagedCompilationSelection.verify,
    ):
        tree = ast.parse(textwrap.dedent(inspect.getsource(consumer)))
        assert any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_observe_scanner_executable"
            for node in ast.walk(tree)
        )
        assert not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"open", "read_bytes", "which"}
            for node in ast.walk(tree)
        )
    tree = ast.parse(textwrap.dedent(inspect.getsource(compiler._isolated_tool_versions)))
    probes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "isolated_executable_version_probe"
    ]
    assert len(probes) == 1
    assert any(keyword.arg == "expected_host_observation" for keyword in probes[0].keywords)


@pytest.mark.parametrize(
    "source",
    [
        "import platform as host\ndef selected_cpu():\n    return host.machine()\n",
        "from platform import machine as cpu\nselected = cpu\ndef selected_cpu():\n    return selected()\n",
    ],
)
def test_new_direct_or_aliased_cpu_platform_input_fails_closed(tmp_path: Path, source: str) -> None:
    root = tmp_path / "mmaudit"
    root.mkdir()
    (root / "new_platform.py").write_text(source)
    observed = inventory_module._direct_environment_occurrences(root)
    assert len(observed) == 1
    assert observed[0][:3] == ("new_platform.py", "selected_cpu", "host-platform")
    with pytest.raises(AutonomyInventoryError, match="direct environment"):
        _discover_direct_environment_sources(root)


def test_inventory_has_exact_autonomous_dispositions_and_honest_phase_zero_state(
    inventory: AutonomyGateInventory,
) -> None:
    # Input registration may add source joins, never alter any gate's integrity or state.
    assert (
        inventory_module._canonical_sha256(
            [
                gate.model_dump(mode="json", exclude={"source_ids"})
                for gate in inventory.logical_gates
            ]
        )
        == "83f08f7362e794f68dc23ba88443a98f31fde21f0573252bc3cb8f97953c525d"
    )
    assert {gate.desired_disposition for gate in inventory.logical_gates} == set(
        AutonomousGateDisposition
    )
    assert {item.value for item in AutonomousGateDisposition} == {
        "AUTONOMOUS_EVIDENCE_SUBSTITUTE",
        "PREPROVISIONED_NONHUMAN_INPUT",
        "PRERUN_CLIENT_DECISION",
        "OBJECTIVE_OUT_OF_SCOPE",
    }
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is False
    assert inventory.managed_run_ready is False
    assert inventory.provider_or_network_accessed is False
    assert inventory.secret_material_read is False
    assert inventory.completion_scope == "SYNTHETIC_PUBLIC_ONLY"
    assert inventory.discovery_scope == (
        "TYPED_BOUNDARIES_REGISTERED_ENTRYPOINTS_RUNTIME_PACKAGE_RESOURCES_"
        "UNSEALED_ENV_HOST_WALL_CLOCK_AUTHORITY_ENTROPY_FILESYSTEM_INTERACTIVE_"
        "RUNTIME_STATE_ELAPSED_CLOCK_PROCESS_IO_GENERATED_CODE_"
        "OPAQUE_AUTHORITIES_"
        "EXPLICIT_MISSING_OBJECTIVE_BOUNDARIES"
    )
    assert inventory.private_repository_completion_in_scope is False
    managed_toolchain = next(
        gate for gate in inventory.logical_gates if gate.gate_id == "gate-managed-toolchain-bundle"
    )
    assert managed_toolchain.implementation_state is GateImplementationState.PARTIAL
    assert "independent bundle trust" in managed_toolchain.implementation_detail
    assert "operating-system probe helpers remain unmodeled" in (
        managed_toolchain.implementation_detail
    )
    sources = {source.source_id: source for source in inventory.source_coverage}
    retained_writer_inputs = tuple(
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("filesystem-input:release_io:_write_file_content:")
        or source.source_id == "direct-env-ast:release_io:_write_file_content:host-identity:1"
    )
    assert len(retained_writer_inputs) == 13
    assert all(
        source.logical_gate_id == "gate-release-evidence-pipeline"
        and source.classification is SourceCoverageClassification.GATE
        for source in retained_writer_inputs
    )
    for source_id in (
        "direct-env-ast:orchestration.budgets:_accounting_portfolio_scope_material:"
        "process-identity:1",
        "direct-env-ast:orchestration.budgets:budgetmanager.portfolio_task_scope:"
        "process-identity:1",
        "direct-env-ast:orchestration.budgets:budgetmanager.reserve:process-identity:1",
        "entropy-ast:orchestration.cost_ledger:atomiccostledger.claim_portfolio_slot:uuid-uuid4:1",
        "entropy-ast:orchestration.cost_ledger:atomiccostledger.reserve_portfolio:uuid-uuid4:1",
    ):
        assert sources[source_id].logical_gate_id == "gate-cost-ledger-provisioning"
    scheduler_filesystem_sources = tuple(
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("filesystem-input:orchestration.scheduler:")
    )
    assert len(scheduler_filesystem_sources) == 59
    assert all(
        source.logical_gate_id == "gate-managed-output-provisioning"
        for source in scheduler_filesystem_sources
    )
    assert {
        "filesystem-input:orchestration.scheduler:_adopt_pending_private_file:1",
        "filesystem-input:orchestration.scheduler:_cleanup_orphan_immutable_writes:1",
        "filesystem-input:orchestration.scheduler:_durable_directory_names:1",
        "filesystem-input:orchestration.scheduler:_inspect_orphan_immutable_writes:1",
        "filesystem-input:orchestration.scheduler:"
        "_build_scheduler_journal_custody_registry.record_validated_snapshot:2",
        "filesystem-input:orchestration.scheduler:_write_exclusive_private_file:1",
        "filesystem-input:orchestration.scheduler:_write_model:1",
    } <= set(sources)
    smoke_run_index = sources[
        "completion-entrypoint:models_authenticated_runner_smoke:smoke_run_index"
    ]
    assert smoke_run_index.source_kind is CompletionInputSourceKind.COMPLETION_ENTRYPOINT_PARAMETER
    assert smoke_run_index.classification is SourceCoverageClassification.GATE
    assert smoke_run_index.logical_gate_id == "gate-authenticated-real-campaign"
    runtime_evidence = sources[
        "completion-entrypoint:models_authenticated_runner:runtime_evidence_smoke_bundle"
    ]
    assert runtime_evidence.source_kind is CompletionInputSourceKind.COMPLETION_ENTRYPOINT_PARAMETER
    assert runtime_evidence.classification is SourceCoverageClassification.GATE
    assert runtime_evidence.logical_gate_id == "gate-autonomous-model-authority"
    for source_id in (
        "completion-entrypoint:models_emit_selection_plan_successor:candidate",
        "completion-entrypoint:models_emit_selection_plan_successor:predecessor_plan",
        "completion-entrypoint:models_emit_selection_plan_successor:refresh_endpoint_inventory",
        "completion-entrypoint:models_emit_selection_plan_successor:upgrade_price_cap_profile_v2",
        "completion-entrypoint:models_list_endpoints:model_id",
    ):
        assert sources[source_id].logical_gate_id == "gate-autonomous-model-authority"
    for source_id in (
        "completion-entrypoint:certify_run_command:configuration_root",
        "completion-entrypoint:replay_command:configuration_root",
        "completion-entrypoint:verify_run_command:configuration_root",
        "filesystem-input:cli:_verification_configuration_root:1",
        "filesystem-input:repository.configuration_custody:observe_configuration_input:1",
    ):
        assert sources[source_id].logical_gate_id == "gate-managed-profile"
    scheduler_process_sources = tuple(
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("direct-env-ast:orchestration.scheduler:")
        and ":process-identity" in source.source_id
    )
    assert len(scheduler_process_sources) == 12
    assert all(
        source.logical_gate_id == "gate-release-evidence-pipeline"
        for source in scheduler_process_sources
        if "privacy_evidence_custody" not in source.source_id
    )
    assert (
        sources[
            "direct-env-ast:orchestration.scheduler:open_scheduler_privacy_evidence_custody:"
            "process-identity:1"
        ].logical_gate_id
        == "gate-client-privacy-consent"
    )
    for source_id in (
        "cli-run:accepted_quote",
        "completion-entrypoint:_execute_audit:accepted_quote",
        "completion-entrypoint:quote_accept:quote_path",
        "completion-entrypoint:quote_create:portfolio_preflight",
        "completion-entrypoint:quote_reconcile:acceptance_path",
        "pipeline-init:accepted_prepurchase_quote",
    ):
        assert sources[source_id].logical_gate_id == "gate-budget-ceiling"
    for source_id in (
        "audit-config:execution.max_schema_validation_retries",
        "audit-override:execution.max_schema_validation_retries",
        "cli-run:schema_validation_retries",
        "completion-entrypoint:_execute_audit:schema_validation_retries",
        "completion-entrypoint:quote_create:schema_validation_retries",
    ):
        assert sources[source_id].logical_gate_id == "gate-full-quality-analysis"
    assert (
        sources["completion-entrypoint:quote_create:campaign_manifest"].logical_gate_id
        == "gate-authenticated-real-campaign"
    )
    assert (
        sources["completion-entrypoint:quote_reconcile:cost_ledger_evidence"].logical_gate_id
        == "gate-cost-ledger-provisioning"
    )
    assert (
        sources["completion-entrypoint:quote_reconcile:model_execution"].logical_gate_id
        == "gate-release-evidence-pipeline"
    )
    assert sources["audited-module:models.route_runtime_evidence"].logical_gate_id == (
        "gate-runtime-package-integrity"
    )
    for source_id in (
        "direct-env-ast:models.route_runtime_evidence:"
        "_build_runtime_capability_authority:process-identity-binding:1",
        "direct-env-ast:models.route_runtime_evidence:"
        "_build_runtime_capability_authority.issue:process-identity:1",
        "direct-env-ast:models.route_runtime_evidence:"
        "_build_runtime_capability_authority.reasons:process-identity:1",
    ):
        assert sources[source_id].logical_gate_id == "gate-authenticated-real-campaign"
    for source_id in (
        "audited-module:orchestration.managed_toolchain",
        "audited-module:resources.managed_toolchain_bundle.json",
    ):
        assert sources[source_id].logical_gate_id == "gate-runtime-package-integrity"
    assert (
        sources[
            "filesystem-input:orchestration.managed_toolchain:_load_managed_toolchain_bundle_path:1"
        ].logical_gate_id
        == "gate-managed-toolchain-bundle"
    )


def test_every_gate_source_has_exactly_one_logical_assignment(
    inventory: AutonomyGateInventory,
) -> None:
    covered = {
        source.source_id
        for source in inventory.source_coverage
        if source.classification is SourceCoverageClassification.GATE
    }
    assigned = [source_id for gate in inventory.logical_gates for source_id in gate.source_ids]
    assert len(assigned) == len(set(assigned))
    assert set(assigned) == covered
    assert all(
        source.logical_gate_id is None
        for source in inventory.source_coverage
        if source.source_id not in covered
    )


def test_full_tree_verifier_remains_gated_without_promotion(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    for module in ("models.truncation_tree", "orchestration.truncation_tree_evidence"):
        source = sources["audited-module:" + module]
        assert source.logical_gate_id == "gate-runtime-package-integrity"
        assert source.classification is SourceCoverageClassification.GATE
    identities = tuple(
        source
        for source in sources.values()
        if source.source_id.startswith("direct-env-ast:orchestration.truncation_tree_evidence:")
    )
    assert len(identities) == 4
    assert all(source.logical_gate_id == "gate-release-evidence-pipeline" for source in identities)
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_full_tree_additions_preserve_every_prior_external_input_locus() -> None:
    root = ROOT / "src/mmaudit"
    paths = _paths_before_legacy_cost_allowance(root)
    environment = _environment_before_compiler_capture(root)
    filesystem, interactive = _external_before_compiler_capture(root)
    entropy = inventory_module._entropy_input_occurrences(root)
    # Compare this historical snapshot before the later pipeline module.
    filesystem = tuple(
        r
        for r in filesystem
        if r[0]
        not in {"orchestration/mutation_pipeline.py", "orchestration/mutation_reconstruction.py"}
    )
    entropy = tuple(
        r
        for r in entropy
        if r[0]
        not in {"orchestration/mutation_pipeline.py", "orchestration/mutation_reconstruction.py"}
    )
    assert inventory_module._canonical_sha256(
        [p for p in paths if p not in _FULL_TREE_ADDITIONS]
    ) == ("c2471ef24fd724fd8fe76bc15ceeb82fe97eef470c05749d877d4bb6c8b01a4e")
    assert (
        inventory_module._canonical_sha256(
            [list(row) for row in environment if row[0] not in _FULL_TREE_ADDITIONS]
        )
        == "f7e98c98eade04a86b2fa2897b284b696f5fcdc7d6002b3bbe36d913614396cc"
    )
    assert inventory_module._canonical_sha256([list(row) for row in filesystem]) == (
        "997d5e65632eaabb8a55cd4933d456f689a60e4d372cce9813d7c7d9fa30178a"
    )
    assert inventory_module._canonical_sha256([list(row) for row in entropy]) == (
        "556dcc2d348b2b7bc3c6c3f11f8828edfb6e1aac0e1c5827b70528cbe32e3836"
    )
    assert sum(p in _FULL_TREE_ADDITIONS for p in paths) == 3
    assert sum(row[0] in _FULL_TREE_ADDITIONS for row in environment) == 9
    assert not any(row[0] in _FULL_TREE_ADDITIONS for row in filesystem)
    assert (len(paths), len(environment), len(filesystem), len(entropy)) == (336, 569, 2233, 20)
    assert not interactive


def test_full_tree_private_promotion_remains_gated(inventory: AutonomyGateInventory) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    module = sources["audited-module:orchestration.truncation_tree_promotion"]
    assert module.logical_gate_id == "gate-runtime-package-integrity"
    identities = tuple(
        source
        for source in sources.values()
        if source.source_id.startswith("direct-env-ast:orchestration.truncation_tree_promotion:")
    )
    assert len(identities) == 5
    assert all(source.logical_gate_id == "gate-release-evidence-pipeline" for source in identities)
    assert all(source.classification is SourceCoverageClassification.GATE for source in identities)
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_private_promotion_preserves_complete_verifier_input_universe() -> None:
    root = ROOT / "src/mmaudit"
    addition = "orchestration/truncation_tree_promotion.py"
    paths = _paths_before_legacy_cost_allowance(root)
    environment = _environment_before_compiler_capture(root)
    assert inventory_module._canonical_sha256([p for p in paths if p != addition]) == (
        "d6cb767ac9157b6b3e03ac89138aab4b7d3c923dd867aedc8e8a28e1c924e64f"
    )
    assert (
        inventory_module._canonical_sha256([list(row) for row in environment if row[0] != addition])
        == "32f0d4f4983b93f51f9d18d5e927018eaf65430dcd3c5d7a0cee903b70e120e7"
    )
    assert (len(paths), len(environment)) == (336, 569)


def test_public_full_tree_custody_preserves_every_predecessor_input() -> None:
    rows = _environment_before_compiler_capture(ROOT / "src/mmaudit")
    normalized = []
    added = []
    for path, scope, kind, expression in rows:
        if path == "orchestration/truncation_tree_promotion.py":
            if scope == "_build_tree_promotion_authority.issue_public.discard":
                added.append((path, scope, kind, expression))
                continue
            scope = scope.replace(".register.discard", ".promote.discard")
        normalized.append([path, scope, kind, expression])
    assert len(added) == 1 and added[0][2] == "process-identity"
    assert len(normalized) == 568
    assert inventory_module._canonical_sha256(normalized) == (
        "2cef0ec4caf2830b84bd0f3788c9f41940ba5f32786e75b9b14b250fc848852d"
    )


def test_offline_opentimestamps_replay_does_not_satisfy_external_seal(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    for source_id in (
        "explicit:offline-opentimestamps-proof-replay",
        "required:external-transparency-publication",
    ):
        assert sources[source_id].logical_gate_id == "gate-external-transparency-seal"
        assert sources[source_id].classification is SourceCoverageClassification.GATE
    assert sources["audited-module:models.opentimestamps_replay"].logical_gate_id == (
        "gate-runtime-package-integrity"
    )
    gate = next(
        item
        for item in inventory.logical_gates
        if item.gate_id == "gate-external-transparency-seal"
    )
    assert gate.implementation_state is GateImplementationState.MISSING
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_offline_calendar_wire_coverage_does_not_grant_transport_or_seal_authority(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    for source_id in (
        "explicit:offline-opentimestamps-calendar-proof-replay",
        "explicit:offline-opentimestamps-calendar-request",
        "explicit:offline-opentimestamps-calendar-response",
        "explicit:offline-opentimestamps-submission-context",
        "explicit:offline-opentimestamps-submission-assembly",
        "required:external-transparency-publication",
    ):
        assert sources[source_id].logical_gate_id == "gate-external-transparency-seal"
        assert sources[source_id].classification is SourceCoverageClassification.GATE
    assert sources["audited-module:models.opentimestamps_calendar"].logical_gate_id == (
        "gate-runtime-package-integrity"
    )
    gate = next(
        item
        for item in inventory.logical_gates
        if item.gate_id == "gate-external-transparency-seal"
    )
    assert gate.implementation_state is GateImplementationState.MISSING
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_owned_calendar_transport_and_nonce_remain_below_external_seal_authority(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {item.source_id: item for item in inventory.source_coverage}
    for source_id in (
        "explicit:owned-opentimestamps-calendar-exchange",
        "explicit:owned-opentimestamps-calendar-submission",
        "explicit:owned-opentimestamps-calendar-lookup",
        "explicit:owned-calibration-calendar-submission",
        "entropy-ast:orchestration.opentimestamps_calendar_transport:_prepare_submission_context:secrets-token_bytes:1",
        "required:external-transparency-publication",
    ):
        assert sources[source_id].logical_gate_id == "gate-external-transparency-seal"
        assert sources[source_id].classification is SourceCoverageClassification.GATE
    assert sources[
        "audited-module:orchestration.opentimestamps_calendar_transport"
    ].logical_gate_id == ("gate-runtime-package-integrity")
    gate = next(
        item
        for item in inventory.logical_gates
        if item.gate_id == "gate-external-transparency-seal"
    )
    assert gate.implementation_state is GateImplementationState.MISSING
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_durable_calendar_journal_inputs_remain_missing_external_seal_authority(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {item.source_id: item for item in inventory.source_coverage}
    anchors = (
        "durable-calendar-journal-preparation",
        "durable-calendar-journal-submission",
        "durable-calendar-journal-dispatch",
        "durable-calendar-journal-process-exclusion",
        "durable-calendar-journal-readback",
        "durable-calendar-journal-recovery",
        "owned-opentimestamps-calendar-context",
        "owned-opentimestamps-prepared-calendar-submission",
    )
    selected = [sources[f"explicit:{anchor}"] for anchor in anchors]
    selected.extend(
        source
        for key, source in sources.items()
        if "opentimestamps_calendar_journal:" in key
        and key.startswith(("direct-env-ast:", "filesystem-input:"))
    )
    assert len(selected) == 17
    assert all(source.logical_gate_id == "gate-external-transparency-seal" for source in selected)
    assert all(source.classification is SourceCoverageClassification.GATE for source in selected)
    assert sources[
        "audited-module:orchestration.opentimestamps_calendar_journal"
    ].logical_gate_id == ("gate-runtime-package-integrity")
    gate = next(
        g for g in inventory.logical_gates if g.gate_id == "gate-external-transparency-seal"
    )
    assert gate.implementation_state is GateImplementationState.MISSING
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_journal_loci_additions_and_nonce_relocation_preserve_every_prior_frozen_input() -> None:
    module = "orchestration/opentimestamps_calendar_journal.py"
    later_modules = {
        "orchestration/mutation_reconstruction.py",
        "orchestration/mutation_pipeline.py",
        *_FULL_TREE_ADDITIONS,
        "orchestration/calibration_calendar_publication.py",
        "orchestration/calibration_calendar_controller.py",
        "models/calibration_checkpoint.py",
        "orchestration/calibration_checkpoint_publication.py",
    }
    source_root = ROOT / "src/mmaudit"
    paths = _paths_before_legacy_cost_allowance(source_root)
    environment = _environment_before_compiler_capture(source_root)
    filesystem, _ = _external_before_compiler_capture(source_root)
    # Each later module has its own exact immediate-predecessor test below.
    paths = [path for path in paths if path not in later_modules]
    environment = tuple(row for row in environment if row[0] not in later_modules)
    filesystem = tuple(row for row in filesystem if row[0] not in later_modules)
    entropy = tuple(
        row
        for row in inventory_module._entropy_input_occurrences(source_root)
        if row[0]
        not in {"orchestration/mutation_pipeline.py", "orchestration/mutation_reconstruction.py"}
    )
    previous_entropy = [
        (
            path,
            "submit_opentimestamps_calendar"
            if path == "orchestration/opentimestamps_calendar_transport.py"
            and scope == "_prepare_submission_context"
            else scope,
            kind,
            expression,
        )
        for path, scope, kind, expression in entropy
    ]
    assert inventory_module._canonical_sha256([p for p in paths if p != module]) == (
        "3967552b9c29c89bc0c8443762d5823430f6ee666be29caafc161ed8ac6ff204"
    )
    assert inventory_module._canonical_sha256([list(x) for x in environment if x[0] != module]) == (
        "5ba83c4366f9f471711d7b31cc88f68c6110312e6305e699e00ceb8f94bab3c9"
    )
    assert inventory_module._canonical_sha256([list(x) for x in filesystem if x[0] != module]) == (
        "c0e922263648c7774799438cb2c55756a2d810bc78a8a8502df25a81e0950942"
    )
    assert inventory_module._canonical_sha256([list(x) for x in previous_entropy]) == (
        "365d21bd552f48df27b794ab34a2dd496a086b38ab19da46262def979915bea3"
    )
    assert sum(x[0] == module for x in environment) == 4
    assert sum(x[0] == module for x in filesystem) == 5
    assert len(entropy) == 20


def test_population_calendar_publisher_cannot_grant_external_or_native_authority(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    anchors = (
        "registration",
        "native-measurement",
        "source-owned-submit",
        "retained-preparation",
        "descriptor",
        "readback",
        "recovery",
    )
    selected = [sources[f"explicit:population-calendar-{anchor}"] for anchor in anchors]
    selected.extend(
        source
        for key, source in sources.items()
        if "calibration_calendar_publication:" in key
        and key.startswith(("direct-env-ast:", "filesystem-input:"))
    )
    assert len(selected) == 12
    assert all(source.logical_gate_id == "gate-external-transparency-seal" for source in selected)
    assert all(source.classification is SourceCoverageClassification.GATE for source in selected)
    assert (
        sources["audited-module:orchestration.calibration_calendar_publication"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    gate = next(
        g for g in inventory.logical_gates if g.gate_id == "gate-external-transparency-seal"
    )
    assert gate.implementation_state is GateImplementationState.MISSING
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_population_publisher_loci_preserve_the_complete_original_journal_baseline() -> None:
    module = "orchestration/calibration_calendar_publication.py"
    source_root = ROOT / "src/mmaudit"
    paths = _paths_before_legacy_cost_allowance(source_root)
    environment = _environment_before_compiler_capture(source_root)
    filesystem, _ = _external_before_compiler_capture(source_root)
    entropy = inventory_module._entropy_input_occurrences(source_root)
    # Compare this historical snapshot before the later pipeline module.
    filesystem = tuple(
        r
        for r in filesystem
        if r[0]
        not in {"orchestration/mutation_pipeline.py", "orchestration/mutation_reconstruction.py"}
    )
    entropy = tuple(
        r
        for r in entropy
        if r[0]
        not in {"orchestration/mutation_pipeline.py", "orchestration/mutation_reconstruction.py"}
    )
    later = {
        *_FULL_TREE_ADDITIONS,
        "orchestration/calibration_calendar_controller.py",
        "models/calibration_checkpoint.py",
        "orchestration/calibration_checkpoint_publication.py",
    }
    paths = [path for path in paths if path not in later]
    environment = tuple(row for row in environment if row[0] not in later)
    filesystem = tuple(row for row in filesystem if row[0] not in later)
    assert inventory_module._canonical_sha256([p for p in paths if p != module]) == (
        "835036ca1e31bfcbef494b1b8fd86478f4ea549887ee7bca61b0f68820b57e3d"
    )
    assert inventory_module._canonical_sha256([list(x) for x in environment if x[0] != module]) == (
        "30b1ae260ad67ed29c4828e655023dee411a37ab3bbb5d31fb32867cb4659294"
    )
    assert inventory_module._canonical_sha256([list(x) for x in filesystem if x[0] != module]) == (
        "2d66a364f5e5a5c99dc9f489e4c07b4db0fb79db4d55900527a10282f18775d0"
    )
    assert inventory_module._canonical_sha256([list(x) for x in entropy]) == (
        "556dcc2d348b2b7bc3c6c3f11f8828edfb6e1aac0e1c5827b70528cbe32e3836"
    )
    assert sum(x[0] == module for x in environment) == 2
    assert sum(x[0] == module for x in filesystem) == 3
    assert len(entropy) == 20


def test_calendar_controller_keeps_phase_recording_below_external_seal_authority(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    anchors = (
        "execution",
        "registration",
        "measurement",
        "custody",
        "phase-files",
        "phase-retention",
        "native-output-bindings",
    )
    selected = [sources[f"explicit:calendar-controller-{anchor}"] for anchor in anchors]
    selected.extend(
        source
        for key, source in sources.items()
        if key.startswith("direct-env-ast:orchestration.calibration_calendar_controller:")
    )
    assert len(selected) == 9
    assert all(source.logical_gate_id == "gate-external-transparency-seal" for source in selected)
    assert all(source.classification is SourceCoverageClassification.GATE for source in selected)
    assert sources[
        "audited-module:orchestration.calibration_calendar_controller"
    ].logical_gate_id == ("gate-runtime-package-integrity")
    gate = next(
        g for g in inventory.logical_gates if g.gate_id == "gate-external-transparency-seal"
    )
    assert gate.implementation_state is GateImplementationState.MISSING
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_calendar_controller_additions_preserve_every_prior_publisher_input_locus() -> None:
    module = "orchestration/calibration_calendar_controller.py"
    root = ROOT / "src/mmaudit"
    paths = _paths_before_legacy_cost_allowance(root)
    environment = _environment_before_compiler_capture(root)
    filesystem, interactive = _external_before_compiler_capture(root)
    entropy = inventory_module._entropy_input_occurrences(root)
    # Compare this historical snapshot before the later pipeline module.
    filesystem = tuple(
        r
        for r in filesystem
        if r[0]
        not in {"orchestration/mutation_pipeline.py", "orchestration/mutation_reconstruction.py"}
    )
    entropy = tuple(
        r
        for r in entropy
        if r[0]
        not in {"orchestration/mutation_pipeline.py", "orchestration/mutation_reconstruction.py"}
    )
    later = {
        *_FULL_TREE_ADDITIONS,
        "models/calibration_checkpoint.py",
        "orchestration/calibration_checkpoint_publication.py",
    }
    paths = [path for path in paths if path not in later]
    environment = tuple(row for row in environment if row[0] not in later)
    filesystem = tuple(row for row in filesystem if row[0] not in later)
    assert inventory_module._canonical_sha256([p for p in paths if p != module]) == (
        "570257c36cd2d8fb7c28536e3ea5493063d539d35eda14678a7d7bfa57176e7b"
    )
    assert inventory_module._canonical_sha256([list(x) for x in environment if x[0] != module]) == (
        "852aa76c6c10853056558c58fbaa4ee0aec3a54ed174106ba72cd937c4d6518a"
    )
    assert inventory_module._canonical_sha256([list(x) for x in filesystem]) == (
        "0973e31f4a0f066cb5bc84d93cff9cab4c81506831ebe657c253f483fb3ae033"
    )
    assert inventory_module._canonical_sha256([list(x) for x in entropy]) == (
        "556dcc2d348b2b7bc3c6c3f11f8828edfb6e1aac0e1c5827b70528cbe32e3836"
    )
    assert sum(row[0] == module for row in environment) == 2
    assert not any(row[0] == module for row in filesystem)
    assert not interactive and len(entropy) == 20


def test_checkpoint_publisher_inputs_do_not_grant_external_seal_or_native_authority(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    anchors = (
        "checkpoint-publication-subject",
        "checkpoint-calendar-registration",
        "checkpoint-calendar-native-measurement",
        "checkpoint-calendar-source-owned-submit",
        "checkpoint-calendar-retained-preparation",
        "checkpoint-calendar-descriptor",
        "checkpoint-calendar-original-history",
        "checkpoint-calendar-readback",
        "checkpoint-calendar-recovery",
        "checkpoint-calendar-journal-preparation",
        "checkpoint-calendar-journal-recovery",
    )
    selected = [sources[f"explicit:{anchor}"] for anchor in anchors]
    selected.extend(
        source
        for key, source in sources.items()
        if key.startswith("filesystem-input:orchestration.calibration_checkpoint_publication:")
    )
    assert len(selected) == 12
    assert all(source.logical_gate_id == "gate-external-transparency-seal" for source in selected)
    assert all(source.classification is SourceCoverageClassification.GATE for source in selected)
    for module in (
        "models.calibration_checkpoint",
        "orchestration.calibration_checkpoint_publication",
    ):
        assert (
            sources[f"audited-module:{module}"].logical_gate_id == "gate-runtime-package-integrity"
        )
    gate = next(
        g for g in inventory.logical_gates if g.gate_id == "gate-external-transparency-seal"
    )
    assert gate.implementation_state is GateImplementationState.MISSING
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_checkpoint_additions_preserve_all_original_controller_input_loci() -> None:
    root = ROOT / "src/mmaudit"
    new = {
        "models/calibration_checkpoint.py",
        "orchestration/calibration_checkpoint_publication.py",
    }
    paths = _paths_before_legacy_cost_allowance(root)
    environment = _environment_before_compiler_capture(root)
    filesystem, interactive = _external_before_compiler_capture(root)
    entropy = inventory_module._entropy_input_occurrences(root)
    # Compare this historical snapshot before the later pipeline module.
    filesystem = tuple(
        r
        for r in filesystem
        if r[0]
        not in {"orchestration/mutation_pipeline.py", "orchestration/mutation_reconstruction.py"}
    )
    entropy = tuple(
        r
        for r in entropy
        if r[0]
        not in {"orchestration/mutation_pipeline.py", "orchestration/mutation_reconstruction.py"}
    )
    # Later full-tree modules have their own complete immediate-predecessor test.
    paths = [path for path in paths if path not in _FULL_TREE_ADDITIONS]
    environment = tuple(row for row in environment if row[0] not in _FULL_TREE_ADDITIONS)
    assert inventory_module._canonical_sha256([p for p in paths if p not in new]) == (
        "64fa26c4702ee072b8e49dbb60b6c207147b076540776a07bfb3a8b15539eb6f"
    )
    assert inventory_module._canonical_sha256([list(x) for x in environment]) == (
        "f7e98c98eade04a86b2fa2897b284b696f5fcdc7d6002b3bbe36d913614396cc"
    )
    assert inventory_module._canonical_sha256([list(x) for x in filesystem if x[0] not in new]) == (
        "0973e31f4a0f066cb5bc84d93cff9cab4c81506831ebe657c253f483fb3ae033"
    )
    assert inventory_module._canonical_sha256([list(x) for x in entropy]) == (
        "556dcc2d348b2b7bc3c6c3f11f8828edfb6e1aac0e1c5827b70528cbe32e3836"
    )
    assert sum(path in new for path in paths) == 2
    assert not any(row[0] in new for row in environment)
    assert [(p, scope, kind) for p, scope, kind, _ in filesystem if p in new] == [
        ("orchestration/calibration_checkpoint_publication.py", "_names", "directory-enumeration")
    ]
    assert not interactive and len(entropy) == 20


def test_checkpoint_controller_inputs_preserve_unsatisfied_external_seal_gate(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    anchors = (
        "execution",
        "initial-tip",
        "tip-custody",
        "phase-retention",
        "phase-files",
        "proof-extension",
    )
    selected = [sources[f"explicit:checkpoint-controller-{anchor}"] for anchor in anchors]
    assert all(source.logical_gate_id == "gate-external-transparency-seal" for source in selected)
    assert all(source.classification is SourceCoverageClassification.GATE for source in selected)
    gate = next(
        g for g in inventory.logical_gates if g.gate_id == "gate-external-transparency-seal"
    )
    assert gate.implementation_state is GateImplementationState.MISSING
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_checkpoint_controller_preserves_the_entire_existing_external_input_surface() -> None:
    root = ROOT / "src/mmaudit"
    paths = _paths_before_legacy_cost_allowance(root)
    environment = _environment_before_compiler_capture(root)
    filesystem, interactive = _external_before_compiler_capture(root)
    entropy = inventory_module._entropy_input_occurrences(root)
    # Compare this historical snapshot before the later pipeline module.
    filesystem = tuple(
        r
        for r in filesystem
        if r[0]
        not in {"orchestration/mutation_pipeline.py", "orchestration/mutation_reconstruction.py"}
    )
    entropy = tuple(
        r
        for r in entropy
        if r[0]
        not in {"orchestration/mutation_pipeline.py", "orchestration/mutation_reconstruction.py"}
    )
    paths = [path for path in paths if path not in _FULL_TREE_ADDITIONS]
    environment = tuple(row for row in environment if row[0] not in _FULL_TREE_ADDITIONS)
    assert inventory_module._canonical_sha256(paths) == (
        "c2471ef24fd724fd8fe76bc15ceeb82fe97eef470c05749d877d4bb6c8b01a4e"
    )
    assert inventory_module._canonical_sha256([list(x) for x in environment]) == (
        "f7e98c98eade04a86b2fa2897b284b696f5fcdc7d6002b3bbe36d913614396cc"
    )
    assert inventory_module._canonical_sha256([list(x) for x in filesystem]) == (
        "997d5e65632eaabb8a55cd4933d456f689a60e4d372cce9813d7c7d9fa30178a"
    )
    assert inventory_module._canonical_sha256([list(x) for x in entropy]) == (
        "556dcc2d348b2b7bc3c6c3f11f8828edfb6e1aac0e1c5827b70528cbe32e3836"
    )
    assert (len(paths), len(environment), len(filesystem), len(entropy)) == (333, 560, 2233, 20)
    assert not interactive


def test_owned_checkpoint_completion_does_not_satisfy_external_seal_authority(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    for anchor in ("scope", "observation", "native-inputs"):
        source = sources[f"explicit:checkpoint-completion-{anchor}"]
        assert source.logical_gate_id == "gate-external-transparency-seal"
        assert source.classification is SourceCoverageClassification.GATE
    gate = next(
        gate
        for gate in inventory.logical_gates
        if gate.gate_id == "gate-external-transparency-seal"
    )
    assert gate.implementation_state is GateImplementationState.MISSING
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_completion_scope_does_not_add_an_external_input_or_runtime_file() -> None:
    root = ROOT / "src/mmaudit"
    paths = _paths_before_legacy_cost_allowance(root)
    environment = _environment_before_compiler_capture(root)
    filesystem, interactive = _external_before_compiler_capture(root)
    entropy = inventory_module._entropy_input_occurrences(root)
    # Compare this historical snapshot before the later pipeline module.
    filesystem = tuple(
        r
        for r in filesystem
        if r[0]
        not in {"orchestration/mutation_pipeline.py", "orchestration/mutation_reconstruction.py"}
    )
    entropy = tuple(
        r
        for r in entropy
        if r[0]
        not in {"orchestration/mutation_pipeline.py", "orchestration/mutation_reconstruction.py"}
    )
    paths = [path for path in paths if path not in _FULL_TREE_ADDITIONS]
    environment = tuple(row for row in environment if row[0] not in _FULL_TREE_ADDITIONS)
    assert inventory_module._canonical_sha256(paths) == (
        "c2471ef24fd724fd8fe76bc15ceeb82fe97eef470c05749d877d4bb6c8b01a4e"
    )
    assert inventory_module._canonical_sha256([list(x) for x in environment]) == (
        "f7e98c98eade04a86b2fa2897b284b696f5fcdc7d6002b3bbe36d913614396cc"
    )
    assert inventory_module._canonical_sha256([list(x) for x in filesystem]) == (
        "997d5e65632eaabb8a55cd4933d456f689a60e4d372cce9813d7c7d9fa30178a"
    )
    assert inventory_module._canonical_sha256([list(x) for x in entropy]) == (
        "556dcc2d348b2b7bc3c6c3f11f8828edfb6e1aac0e1c5827b70528cbe32e3836"
    )
    assert (len(paths), len(environment), len(filesystem), len(entropy)) == (333, 560, 2233, 20)
    assert not interactive


def test_native_release_input_join_cannot_grant_population_or_qualification_authority(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    assert (
        sources["explicit:native-calibration-successor-release-inputs"].logical_gate_id
        == "gate-autonomous-model-authority"
    )
    assert (
        sources["audited-module:orchestration.authenticated_calibration_release"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_native_configuration_proposal_is_not_policy_or_release_admission(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    for anchor in (
        "native-calibration-config-proposal",
        "native-calibration-config-readback",
        "native-calibration-config-export",
    ):
        assert sources[f"explicit:{anchor}"].logical_gate_id == "gate-autonomous-model-authority"
        assert sources[f"explicit:{anchor}"].classification is SourceCoverageClassification.GATE
    assert sources[
        "audited-module:orchestration.authenticated_calibration_config"
    ].logical_gate_id == ("gate-runtime-package-integrity")
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_population_publication_inputs_cannot_satisfy_external_authentication(
    inventory: AutonomyGateInventory,
) -> None:
    sources = {source.source_id: source for source in inventory.source_coverage}
    for anchor in (
        "calibration-registration-publication-subject",
        "calibration-measurement-publication-subject",
        "calibration-publication-prefix-comparison",
    ):
        assert sources[f"explicit:{anchor}"].logical_gate_id == "gate-external-transparency-seal"
        assert sources[f"explicit:{anchor}"].classification is SourceCoverageClassification.GATE
    assert sources["required:external-transparency-publication"].logical_gate_id == (
        "gate-external-transparency-seal"
    )
    assert sources["audited-module:orchestration.calibration_publication"].logical_gate_id == (
        "gate-runtime-package-integrity"
    )
    gate = next(
        item
        for item in inventory.logical_gates
        if item.gate_id == "gate-external-transparency-seal"
    )
    assert gate.implementation_state is GateImplementationState.MISSING
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_unresolved_findings_and_external_authorities_remain_separately_unsatisfied(
    inventory: AutonomyGateInventory,
) -> None:
    gates = {gate.gate_id: gate for gate in inventory.logical_gates}
    unresolved = gates["gate-unresolved-finding-disposition"]
    assert unresolved.implementation_state is GateImplementationState.MISSING
    assert {
        "explicit:post-judge-manual-review-incomplete-branch",
        "explicit:consensus-needs-review-status",
        "required:autonomous-unresolved-finding-terminal-resolution",
    } <= set(unresolved.source_ids)
    assert gates["gate-external-transparency-seal"].implementation_state is (
        GateImplementationState.MISSING
    )
    assert gates["gate-trusted-time-independent-replay"].implementation_state is (
        GateImplementationState.MISSING
    )
    assert set(gates["gate-external-transparency-seal"].source_ids).isdisjoint(
        gates["gate-trusted-time-independent-replay"].source_ids
    )


def test_equivalent_config_and_cli_boundaries_use_consistent_primary_gates() -> None:
    assert _audit_gate_for_path("language_profile") == "gate-client-audit-scope"
    assert _audit_gate_for_path("smart_contracts.project_root") == "gate-client-audit-scope"
    assert _audit_gate_for_path("smart_contracts.allow_network") == "gate-dependency-snapshot"
    assert _audit_gate_for_path("maximum_assurance.benchmark_gate") == (
        "gate-benchmark-evidence-authority"
    )
    assert _audit_gate_for_path("execution.conservative_usd_per_million_tokens") == (
        "gate-budget-ceiling"
    )
    assert inventory_module._command_parameter_classification(
        "models_authenticated_runner_smoke", "smoke_corpus"
    ) == (SourceCoverageClassification.GATE, "gate-authenticated-real-campaign")
    assert inventory_module._command_parameter_classification(
        "managed_provision", "verify_only"
    ) == (SourceCoverageClassification.GATE, "gate-managed-provisioning")


def test_managed_provisioning_mechanism_is_partial_and_nonauthorizing(
    inventory: AutonomyGateInventory,
) -> None:
    gate = next(
        item for item in inventory.logical_gates if item.gate_id == "gate-managed-provisioning"
    )
    assert gate.implementation_state is GateImplementationState.PARTIAL
    assert "portfolio holds" in gate.implementation_detail
    assert "authority stay false" in gate.implementation_detail
    assert inventory.runtime_authority is False
    assert inventory.managed_run_ready is False


def test_development_rejection_projection_is_audited_without_acquiring_authority(
    inventory: AutonomyGateInventory,
) -> None:
    source = next(
        item
        for item in inventory.source_coverage
        if item.source_id == "audited-module:models.development_diagnostics"
    )
    assert source.source_path == "src/mmaudit/models/development_diagnostics.py"
    assert source.logical_gate_id == "gate-runtime-package-integrity"
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


@pytest.mark.parametrize(
    ("source_id", "gate_id"),
    [
        ("audited-module:benchmark.development_comparison", "gate-runtime-package-integrity"),
        ("audited-module:orchestration.development_comparison", "gate-runtime-package-integrity"),
        ("explicit:development-benchmark-comparison", "gate-benchmark-evidence-authority"),
        ("explicit:development-comparison-files", "gate-client-audit-scope"),
    ],
)
def test_development_comparison_inputs_and_outputs_have_explicit_gate_coverage(
    inventory: AutonomyGateInventory, source_id: str, gate_id: str
) -> None:
    source = next(item for item in inventory.source_coverage if item.source_id == source_id)
    assert source.logical_gate_id == gate_id
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_development_completion_telemetry_has_explicit_non_authorizing_coverage(
    inventory: AutonomyGateInventory,
) -> None:
    source = next(
        item
        for item in inventory.source_coverage
        if item.source_id == "explicit:development-completion-telemetry"
    )
    assert source.logical_gate_id == "gate-provider-secret-transport"
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_development_uncertain_carry_has_explicit_non_authorizing_coverage(
    inventory: AutonomyGateInventory,
) -> None:
    source = next(
        item
        for item in inventory.source_coverage
        if item.source_id == "explicit:development-uncertain-estimate-carry"
    )
    assert source.logical_gate_id == "gate-cost-ledger-provisioning"
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


@pytest.mark.parametrize(
    "source_id,gate_id",
    [
        ("audited-module:models.development_judgment", "gate-runtime-package-integrity"),
        ("audited-module:orchestration.development_judgment", "gate-runtime-package-integrity"),
        ("explicit:development-judgment-frozen-plan", "gate-client-audit-scope"),
        ("explicit:development-judgment-shard-transport", "gate-provider-secret-transport"),
        ("explicit:development-judgment-sequential-run", "gate-full-quality-analysis"),
        ("explicit:development-judgment-candidate-accounting", "gate-cost-ledger-provisioning"),
        ("explicit:development-judgment-impact", "gate-benchmark-evidence-authority"),
    ],
)
def test_development_judgment_execution_and_impact_are_explicitly_nonauthorizing(
    inventory: AutonomyGateInventory, source_id: str, gate_id: str
) -> None:
    source = next(item for item in inventory.source_coverage if item.source_id == source_id)
    assert source.logical_gate_id == gate_id
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_committed_inventory_is_canonical_self_hashed_and_current(
    inventory: AutonomyGateInventory,
) -> None:
    path = ROOT / AUTONOMY_INVENTORY_PATH
    assert path.read_text(encoding="utf-8") == render_autonomy_gate_inventory(repository_root=ROOT)
    assert load_autonomy_gate_inventory(path) == inventory
    assert render_autonomy_gate_inventory(repository_root=ROOT) == (
        render_autonomy_gate_inventory(repository_root=ROOT)
    )


@pytest.mark.parametrize(
    "source_id,gate_id",
    [
        ("audited-module:benchmark.development_ensemble", "gate-runtime-package-integrity"),
        ("audited-module:models.development_ensemble", "gate-runtime-package-integrity"),
        ("audited-module:orchestration.development_ensemble", "gate-runtime-package-integrity"),
        ("explicit:development-ensemble-frozen-plan", "gate-client-audit-scope"),
        ("explicit:development-ensemble-sequential-run", "gate-full-quality-analysis"),
        ("explicit:development-ensemble-accounting", "gate-cost-ledger-provisioning"),
        ("explicit:development-ensemble-impact", "gate-benchmark-evidence-authority"),
    ],
)
def test_executed_development_ensemble_remains_explicitly_nonauthorizing(
    inventory: AutonomyGateInventory, source_id: str, gate_id: str
) -> None:
    source = next(item for item in inventory.source_coverage if item.source_id == source_id)
    assert source.logical_gate_id == gate_id
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


@pytest.mark.parametrize(
    "source_id,gate_id",
    [
        ("audited-module:models.development_corpus", "gate-runtime-package-integrity"),
        ("audited-module:orchestration.development_corpus", "gate-runtime-package-integrity"),
        ("audited-module:repository.development_corpus", "gate-runtime-package-integrity"),
        ("explicit:development-corpus-frozen-manifest", "gate-client-audit-scope"),
        ("explicit:development-corpus-selected-source-loader", "gate-client-audit-scope"),
        ("explicit:development-corpus-frozen-plan", "gate-client-audit-scope"),
        ("explicit:development-corpus-shard-transport", "gate-provider-secret-transport"),
        ("explicit:development-corpus-sequential-run", "gate-full-quality-analysis"),
        ("explicit:development-corpus-accounting", "gate-cost-ledger-provisioning"),
    ],
)
def test_manifest_development_corpus_remains_explicitly_nonauthorizing(
    inventory: AutonomyGateInventory, source_id: str, gate_id: str
) -> None:
    source = next(item for item in inventory.source_coverage if item.source_id == source_id)
    assert source.logical_gate_id == gate_id
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_selected_development_deadline_is_a_nonauthorizing_transport_input(
    inventory: AutonomyGateInventory,
) -> None:
    source = next(
        item
        for item in inventory.source_coverage
        if item.source_id == "explicit:development-selected-request-deadline"
    )
    assert source.logical_gate_id == "gate-provider-secret-transport"
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


@pytest.mark.parametrize(
    "source_id,gate_id",
    [
        ("audited-module:models.development_corpus_judgment", "gate-runtime-package-integrity"),
        (
            "audited-module:orchestration.development_corpus_judgment",
            "gate-runtime-package-integrity",
        ),
        ("explicit:development-corpus-judgment-retained-candidate", "gate-client-audit-scope"),
        ("explicit:development-corpus-judgment-frozen-plan", "gate-client-audit-scope"),
        ("explicit:development-corpus-judgment-shard-transport", "gate-provider-secret-transport"),
        ("explicit:development-corpus-judgment-sequential-run", "gate-full-quality-analysis"),
        ("explicit:development-corpus-judgment-accounting", "gate-cost-ledger-provisioning"),
    ],
)
def test_manifest_candidate_review_preserves_all_nonauthorizing_gates(
    inventory: AutonomyGateInventory, source_id: str, gate_id: str
) -> None:
    source = next(item for item in inventory.source_coverage if item.source_id == source_id)
    assert source.logical_gate_id == gate_id
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


@pytest.mark.parametrize(
    "source_id,gate_id",
    [
        ("audited-module:benchmark.development_corpus", "gate-runtime-package-integrity"),
        ("explicit:development-corpus-pinned-label-reader", "gate-client-audit-scope"),
        ("explicit:development-corpus-benchmark-binding", "gate-client-audit-scope"),
        ("explicit:development-corpus-candidate-measurement", "gate-benchmark-evidence-authority"),
    ],
)
def test_manifest_candidate_measurement_does_not_promote_development_labels(
    inventory: AutonomyGateInventory, source_id: str, gate_id: str
) -> None:
    source = next(item for item in inventory.source_coverage if item.source_id == source_id)
    assert source.logical_gate_id == gate_id
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


@pytest.mark.parametrize(
    "source_id,gate_id",
    [
        ("audited-module:models.development_corpus_ensemble", "gate-runtime-package-integrity"),
        ("explicit:development-corpus-ensemble-frozen-plan", "gate-client-audit-scope"),
        ("explicit:development-corpus-judgment-upstream-custody", "gate-client-audit-scope"),
        ("explicit:development-prior-stage-accounting", "gate-cost-ledger-provisioning"),
    ],
)
def test_manifest_ensemble_foundation_does_not_claim_an_executed_parent_or_authority(
    inventory: AutonomyGateInventory, source_id: str, gate_id: str
) -> None:
    source = next(item for item in inventory.source_coverage if item.source_id == source_id)
    assert source.logical_gate_id == gate_id
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


@pytest.mark.parametrize(
    "source_id,gate_id",
    [
        (
            "audited-module:orchestration.development_corpus_ensemble",
            "gate-runtime-package-integrity",
        ),
        ("audited-module:benchmark.development_corpus_ensemble", "gate-runtime-package-integrity"),
        ("explicit:development-corpus-ensemble-sequential-run", "gate-full-quality-analysis"),
        ("explicit:development-corpus-ensemble-accounting", "gate-cost-ledger-provisioning"),
        ("explicit:development-corpus-ensemble-child-adoption", "gate-release-evidence-pipeline"),
        (
            "explicit:development-corpus-ensemble-terminated-child-recovery",
            "gate-release-evidence-pipeline",
        ),
        (
            "explicit:development-corpus-ensemble-original-measurement",
            "gate-benchmark-evidence-authority",
        ),
        ("explicit:development-corpus-ensemble-cli", "gate-client-audit-scope"),
        ("explicit:development-corpus-candidate-upstream-custody", "gate-client-audit-scope"),
        ("explicit:precreated-private-directory-custody", "gate-managed-output-provisioning"),
        ("explicit:bounded-composed-json-writer", "gate-release-evidence-pipeline"),
        ("explicit:composed-evidence-original-size-custody", "gate-release-evidence-pipeline"),
    ],
)
def test_manifest_parent_checkpoint_does_not_promote_development_execution(
    inventory: AutonomyGateInventory, source_id: str, gate_id: str
) -> None:
    source = next(item for item in inventory.source_coverage if item.source_id == source_id)
    assert source.logical_gate_id == gate_id
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


@pytest.mark.parametrize(
    "source_id,gate_id",
    [
        ("audited-module:models.development_corpus_resume", "gate-runtime-package-integrity"),
        (
            "audited-module:orchestration.development_corpus_resume",
            "gate-runtime-package-integrity",
        ),
        ("explicit:development-corpus-resume-original-history", "gate-release-evidence-pipeline"),
        ("explicit:development-corpus-resume-frozen-plan", "gate-client-audit-scope"),
        ("explicit:development-corpus-resume-input-loader", "gate-client-audit-scope"),
        ("explicit:development-corpus-resume-input-custody", "gate-release-evidence-pipeline"),
        (
            "explicit:development-corpus-resume-stable-file-objects",
            "gate-release-evidence-pipeline",
        ),
        ("explicit:development-corpus-resume-sequential-run", "gate-full-quality-analysis"),
        ("explicit:development-corpus-resume-cli", "gate-client-audit-scope"),
        ("audited-module:benchmark.development_corpus_resume", "gate-runtime-package-integrity"),
        (
            "audited-module:orchestration.development_corpus_resume_score",
            "gate-runtime-package-integrity",
        ),
        (
            "explicit:development-corpus-shared-claim-measurement",
            "gate-benchmark-evidence-authority",
        ),
        ("explicit:development-corpus-cumulative-measurement", "gate-benchmark-evidence-authority"),
        ("explicit:development-corpus-cumulative-score-reader", "gate-release-evidence-pipeline"),
        ("explicit:development-corpus-cumulative-score-writer", "gate-release-evidence-pipeline"),
        ("explicit:development-corpus-cumulative-offline-scoring", "gate-client-audit-scope"),
        ("explicit:development-corpus-cumulative-score-cli", "gate-client-audit-scope"),
        (
            "audited-module:benchmark.development_corpus_control_measurement",
            "gate-runtime-package-integrity",
        ),
        (
            "audited-module:orchestration.development_corpus_control_measurement",
            "gate-runtime-package-integrity",
        ),
        ("explicit:development-corpus-control-measurement", "gate-benchmark-evidence-authority"),
        ("explicit:development-corpus-control-source-reader", "gate-release-evidence-pipeline"),
        (
            "explicit:development-corpus-control-measurement-reader",
            "gate-release-evidence-pipeline",
        ),
        (
            "explicit:development-corpus-control-measurement-writer",
            "gate-release-evidence-pipeline",
        ),
        ("explicit:development-corpus-control-offline-measurement", "gate-client-audit-scope"),
        ("explicit:development-corpus-control-measurement-cli", "gate-client-audit-scope"),
        ("explicit:bounded-prebound-composed-reader", "gate-release-evidence-pipeline"),
        (
            "filesystem-input:orchestration.development_corpus_ensemble:_bind_child:2",
            "gate-release-evidence-pipeline",
        ),
        (
            "filesystem-input:orchestration.development_corpus_ensemble:_bind_child:3",
            "gate-release-evidence-pipeline",
        ),
    ],
)
def test_manifest_continuation_does_not_promote_response_coverage_to_audit_authority(
    inventory: AutonomyGateInventory, source_id: str, gate_id: str
) -> None:
    source = next(item for item in inventory.source_coverage if item.source_id == source_id)
    assert source.logical_gate_id == gate_id
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


class _InnocuousNestedConfig(StrictModel):
    harmless_counter: int = 0


@pytest.mark.parametrize(
    "source_id,gate_id",
    [
        ("audited-module:benchmark.development_corpus_stability", "gate-runtime-package-integrity"),
        (
            "audited-module:orchestration.development_corpus_stability",
            "gate-runtime-package-integrity",
        ),
        ("explicit:development-corpus-stability-measurement", "gate-benchmark-evidence-authority"),
        ("explicit:development-corpus-stability-selection-reader", "gate-client-audit-scope"),
        ("explicit:development-corpus-stability-reader", "gate-release-evidence-pipeline"),
        ("explicit:development-corpus-stability-writer", "gate-release-evidence-pipeline"),
        ("explicit:development-corpus-stability-offline-measurement", "gate-client-audit-scope"),
        ("explicit:development-corpus-stability-cli", "gate-client-audit-scope"),
        ("audited-module:reporting.development_stability", "gate-runtime-package-integrity"),
        ("explicit:development-corpus-stability-report-renderer", "gate-client-audit-scope"),
        ("explicit:development-corpus-stability-report-writer", "gate-release-evidence-pipeline"),
        (
            "direct-env-ast:orchestration.development_corpus_stability:"
            "write_development_stability_report.require_context:host-identity:1",
            "gate-managed-toolchain-bundle",
        ),
        (
            "filesystem-input:orchestration.development_corpus_stability:"
            "write_development_stability_report.require_context:1",
            "gate-release-evidence-pipeline",
        ),
    ],
)
def test_retained_stability_never_promotes_selected_runs_to_independent_audits(
    inventory: AutonomyGateInventory, source_id: str, gate_id: str
) -> None:
    source = next(item for item in inventory.source_coverage if item.source_id == source_id)
    assert source.logical_gate_id == gate_id
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


@pytest.mark.parametrize(
    "source_id,gate_id",
    [
        ("audited-module:models.development_corpus_repeats", "gate-runtime-package-integrity"),
        (
            "audited-module:orchestration.development_corpus_repeats",
            "gate-runtime-package-integrity",
        ),
        ("explicit:development-corpus-repeats-prepare", "gate-client-audit-scope"),
        ("explicit:development-corpus-repeats-projection", "gate-benchmark-evidence-authority"),
        ("explicit:development-corpus-repeats-reader", "gate-release-evidence-pipeline"),
        ("explicit:development-corpus-repeats-plan-reader", "gate-release-evidence-pipeline"),
        ("explicit:development-corpus-repeats-writer", "gate-release-evidence-pipeline"),
        ("explicit:development-corpus-repeats-preflight", "gate-cost-ledger-provisioning"),
        ("explicit:development-corpus-repeats-runner", "gate-provider-secret-transport"),
        (
            "audited-module:orchestration.development_corpus_repeats_inputs",
            "gate-runtime-package-integrity",
        ),
        ("explicit:development-corpus-repeats-cli", "gate-client-audit-scope"),
        ("explicit:development-corpus-repeats-input-reader", "gate-release-evidence-pipeline"),
        ("explicit:development-corpus-repeats-input-custody", "gate-release-evidence-pipeline"),
        ("explicit:development-corpus-repeats-budget-handoff", "gate-cost-ledger-provisioning"),
    ],
)
def test_predeclared_candidate_series_cannot_self_qualify(
    inventory: AutonomyGateInventory, source_id: str, gate_id: str
) -> None:
    source = next(item for item in inventory.source_coverage if item.source_id == source_id)
    assert source.logical_gate_id == gate_id
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


class _AuditConfigWithNewLeaf(AuditConfig):
    innocuous: _InnocuousNestedConfig = Field(default_factory=_InnocuousNestedConfig)


class _AuditRunOptionsWithNewLeaf(AuditRunOptions):
    innocuous: bool = False


def test_new_innocuously_named_config_and_run_option_leaves_fail_closed() -> None:
    with pytest.raises(AutonomyInventoryError, match="AuditConfig leaves"):
        build_autonomy_gate_inventory(
            repository_root=ROOT, audit_config_model=_AuditConfigWithNewLeaf
        )
    with pytest.raises(AutonomyInventoryError, match="AuditRunOptions leaves"):
        build_autonomy_gate_inventory(
            repository_root=ROOT,
            audit_run_options_model=_AuditRunOptionsWithNewLeaf,
        )


def test_new_override_and_environment_entries_fail_closed() -> None:
    from mmaudit.config import _AUDIT_OVERRIDE_VALUE_TYPES, _ENVIRONMENT_OVERRIDE_MAPPINGS

    overrides = dict(_AUDIT_OVERRIDE_VALUE_TYPES)
    overrides["innocuous.harmless_counter"] = (int,)
    with pytest.raises(AutonomyInventoryError, match="audit override allowlist"):
        build_autonomy_gate_inventory(repository_root=ROOT, audit_override_value_types=overrides)
    environment = dict(_ENVIRONMENT_OVERRIDE_MAPPINGS)
    environment["MMAUDIT_INNOCUOUS_COUNTER"] = ("innocuous.harmless_counter", int)
    with pytest.raises(AutonomyInventoryError, match="environment override allowlist"):
        build_autonomy_gate_inventory(
            repository_root=ROOT, environment_override_mappings=environment
        )


def test_new_cli_and_pipeline_parameters_fail_closed() -> None:
    def changed_cli(innocuous: bool = False) -> None:
        del innocuous

    def changed_pipeline_init(self: object, innocuous: bool = False) -> None:
        del self, innocuous

    async def changed_pipeline_run(self: object, innocuous: bool = False) -> None:
        del self, innocuous

    with pytest.raises(AutonomyInventoryError, match="run_command parameters"):
        build_autonomy_gate_inventory(repository_root=ROOT, cli_run_command=changed_cli)
    with pytest.raises(AutonomyInventoryError, match=r"AuditPipeline\.__init__ parameters"):
        build_autonomy_gate_inventory(repository_root=ROOT, pipeline_init=changed_pipeline_init)
    with pytest.raises(AutonomyInventoryError, match=r"AuditPipeline\.run parameters"):
        build_autonomy_gate_inventory(repository_root=ROOT, pipeline_run=changed_pipeline_run)


def test_new_auxiliary_completion_entrypoint_parameter_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = inventory_module._registered_cli_commands()

    def new_completion_command(innocuous: bool = False) -> None:
        del innocuous

    monkeypatch.setattr(
        inventory_module,
        "_registered_cli_commands",
        lambda: (*current, ("new_completion_command", new_completion_command)),
    )
    with pytest.raises(AutonomyInventoryError, match="completion entrypoint parameters"):
        _discover_completion_entrypoint_sources()
    with pytest.raises(AutonomyInventoryError, match="unclassified completion command parameter"):
        inventory_module._command_parameter_classification("new_completion_command", "innocuous")


def test_model_owner_source_is_read_once_per_traversal_without_cross_call_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class LocalOwner(StrictModel):
        first: int = 1
        second: str = "synthetic"

    source = inventory_module._normalized_ast(LocalOwner)
    observations: list[object] = []

    def observe(owner: object) -> str:
        observations.append(owner)
        return source

    monkeypatch.setattr(inventory_module, "_normalized_ast", observe)
    first = inventory_module._discover_model_leaf_details(LocalOwner)
    assert observations == [LocalOwner]
    assert tuple(row[0] for row in first) == ("first", "second")
    assert tuple(row[2] for row in first) == (1, 1)
    assert inventory_module._discover_model_leaf_details(LocalOwner) == first
    assert observations == [LocalOwner, LocalOwner]

    source = inventory_module._canonical_ast_dump(ast.parse("class ChangedOwner: pass"))
    changed = inventory_module._discover_model_leaf_details(LocalOwner)
    assert observations == [LocalOwner, LocalOwner, LocalOwner]
    assert tuple(row[1] for row in changed) != tuple(row[1] for row in first)


def test_existing_field_semantics_drift_changes_the_objective_source_universe() -> None:
    changed_model = create_model(
        "AuditConfigWithChangedSemantics",
        __base__=AuditConfig,
        version=(Literal[1], Field(default=1, description="semantics-only mutation")),
    )

    baseline = build_autonomy_gate_inventory(repository_root=ROOT)
    changed = build_autonomy_gate_inventory(
        repository_root=ROOT,
        audit_config_model=changed_model,
    )
    assert changed.source_universe_sha256 != baseline.source_universe_sha256
    assert changed.inventory_sha256 != baseline.inventory_sha256


def test_repository_local_path_defaults_are_worktree_independent(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    relative_path = Path("benchmarks/model_corpus/manifest.json")

    first = inventory_module._canonical_default(
        first_root / relative_path,
        repository_root=first_root,
    )
    second = inventory_module._canonical_default(
        second_root / relative_path,
        repository_root=second_root,
    )

    assert first == second == {"repository_path": relative_path.as_posix()}
    assert inventory_module._canonical_default(
        (first_root / relative_path, frozenset({first_root / "schemas/current.json"})),
        repository_root=first_root,
    ) == [
        {"repository_path": relative_path.as_posix()},
        [{"repository_path": "schemas/current.json"}],
    ]
    assert inventory_module._canonical_default(
        tmp_path / "external.json",
        repository_root=first_root,
    ) == {"path": (tmp_path / "external.json").as_posix()}


def test_new_runtime_resource_and_interactive_input_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "mmaudit"
    source_root.mkdir()
    (source_root / "new_resource.dat").write_text("bounded", encoding="utf-8")
    assert [
        path.relative_to(source_root).as_posix()
        for path in inventory_module._runtime_package_paths(source_root)
    ] == ["new_resource.dat"]
    with pytest.raises(AutonomyInventoryError, match="runtime package paths"):
        _discover_audited_module_sources(source_root)
    monkeypatch.setattr(
        inventory_module,
        "_FROZEN_AUDITED_MODULE_PATHS_SHA256",
        inventory_module._canonical_sha256(["new_resource.dat"]),
    )
    before = _discover_audited_module_sources(source_root)[0].source_semantics_sha256
    (source_root / "new_resource.dat").write_text("changed bytes", encoding="utf-8")
    after = _discover_audited_module_sources(source_root)[0].source_semantics_sha256
    assert after != before
    (source_root / "new_gate.py").write_text(
        "from builtins import input as ask\ndef request_operator():\n    return ask('approve?')\n",
        encoding="utf-8",
    )
    filesystem, interactive = inventory_module._external_input_occurrences(source_root)
    assert filesystem == ()
    assert [(path, scope) for path, scope, _ in interactive] == [
        ("new_gate.py", "request_operator")
    ]
    assert "approve?" in interactive[0][2]
    with pytest.raises(AutonomyInventoryError, match="interactive operator input loci"):
        _discover_external_input_sources(source_root)


def test_new_aliased_filesystem_read_fails_closed(tmp_path: Path) -> None:
    source_root = tmp_path / "mmaudit"
    source_root.mkdir()
    (source_root / "new_reader.py").write_text(
        "from os import F_OK, O_RDONLY, access as permitted, fstat as descriptor_status\n"
        "from os import listdir as members, open as raw_open, stat as status\n"
        "from os.path import lexists as link_exists\n"
        "from pathlib import Path as P\n"
        "from shutil import copy2 as clone\n"
        "read_path = P.read_text\n"
        "list_path = P.iterdir\n"
        "path_exists = P.exists\n"
        "def read_external():\n"
        "    raw_open('opaque', O_RDONLY)\n"
        "    clone('source', 'destination')\n"
        "    members('.')\n"
        "    status('opaque')\n"
        "    permitted('opaque', F_OK)\n"
        "    descriptor_status(0)\n"
        "    tuple(P('.').iterdir())\n"
        "    P('opaque').is_junction()\n"
        "    getattr(P('opaque'), 'is_junction', lambda: False)()\n"
        "    link_exists('opaque')\n"
        "    read_path(P('opaque'))\n"
        "    tuple(list_path(P('.')))\n"
        "    path_exists(P('opaque'))\n"
        "    return P('opaque').read_text()\n",
        encoding="utf-8",
    )
    filesystem, interactive = inventory_module._external_input_occurrences(source_root)
    assert interactive == ()
    assert Counter(kind for _, _, kind, _ in filesystem) == {
        "content-read": 4,
        "directory-enumeration": 3,
        "metadata-observation": 7,
    }
    assert {(path, scope) for path, scope, _, _ in filesystem} == {
        ("new_reader.py", "read_external")
    }
    with pytest.raises(AutonomyInventoryError, match="unclassified filesystem input authority"):
        inventory_module._filesystem_input_gate("new_reader.py", "read_external")
    with pytest.raises(AutonomyInventoryError, match="filesystem input loci"):
        _discover_external_input_sources(source_root)


def test_new_aliased_wall_clock_read_fails_closed(tmp_path: Path) -> None:
    source_root = tmp_path / "mmaudit"
    source_root.mkdir()
    (source_root / "new_clock.py").write_text(
        "from elsewhere import clock\n"
        "from datetime import UTC, datetime as D\n"
        "import os\n"
        "from os.path import abspath as absolute_name\n"
        "from pathlib import Path\n"
        "clock = D.now\n"
        "current_uid = getattr(os, 'getuid', lambda: 0)\n"
        "trusted_process = os.getpid\n"
        "def authority_time():\n"
        "    return (clock(UTC), current_uid(), trusted_process(), "
        "absolute_name('x'), Path('x').absolute())\n"
        "def custom_attribute_is_not_os(custom):\n"
        "    trusted = custom.getpid\n"
        "    return trusted()\n",
        encoding="utf-8",
    )
    occurrences = inventory_module._direct_environment_occurrences(source_root)
    assert Counter((path, scope, kind) for path, scope, kind, _ in occurrences) == {
        ("new_clock.py", "authority_time", "host-identity"): 1,
        ("new_clock.py", "authority_time", "process-identity"): 1,
        ("new_clock.py", "authority_time", "wall-clock"): 1,
        ("new_clock.py", "authority_time", "working-directory"): 2,
        ("new_clock.py", "module", "process-identity-binding"): 1,
    }
    assert any("clock" in expression for *_, expression in occurrences)
    assert all("custom" not in expression for *_, expression in occurrences)
    with pytest.raises(AutonomyInventoryError, match="direct environment and PATH-resolution"):
        _discover_direct_environment_sources(source_root)


def test_budget_portfolio_scope_process_identity_is_a_cost_ledger_gate() -> None:
    assert (
        inventory_module._direct_environment_gate(
            "orchestration/budgets.py",
            "BudgetManager.portfolio_task_scope",
            "process-identity",
            "os.getpid()",
        )
        == "gate-cost-ledger-provisioning"
    )


def test_filesystem_privacy_provenance_has_exact_nonfallback_gate() -> None:
    assert (
        inventory_module._filesystem_input_gate(
            "repository/privacy_provenance.py", "classify_repository_source"
        )
        == "gate-synthetic-public-scope"
    )
    assert (
        inventory_module._filesystem_input_gate(
            "solidity/invariant_execution.py", "FoundryInvariantRunner._execute"
        )
        == "gate-full-quality-analysis"
    )


@pytest.mark.parametrize(
    ("relative_path", "scope", "expected_gate"),
    [
        (
            "models/authenticated_runner_durable_bundle.py",
            "load_authenticated_runner_durable_bundle",
            "gate-managed-output-provisioning",
        ),
        (
            "scanners/trusted_inputs.py",
            "_validated_private_directory",
            "gate-managed-toolchain-bundle",
        ),
        (
            "isolation/provenance.py",
            "_run_builtin_preflight",
            "gate-reproduction-capability-policy",
        ),
        (
            "isolation/provenance.py",
            "_trusted_helper",
            "gate-managed-toolchain-bundle",
        ),
        (
            "isolation/container.py",
            "discover_rootless_container_backend",
            "gate-managed-toolchain-bundle",
        ),
        (
            "orchestration/managed_toolchain.py",
            "_load_managed_toolchain_bundle_path",
            "gate-managed-toolchain-bundle",
        ),
        (
            "scanners/base.py",
            "_observe_scanner_executable",
            "gate-managed-toolchain-bundle",
        ),
        (
            "orchestration/managed_host_tools.py",
            "materialize_managed_host_tools",
            "gate-managed-toolchain-bundle",
        ),
        (
            "isolation/container.py",
            "SingleLoopbackHardhatBackend.bridge_socket_path",
            "gate-fork-environment",
        ),
        (
            "scanners/fork_matrix.py",
            "_open_private_root",
            "gate-managed-output-provisioning",
        ),
        (
            "scanners/read_only_rpc.py",
            "ReadOnlyRpcBridge.start",
            "gate-fork-environment",
        ),
        ("solidity/formal.py", "_read_halmos_plan", "gate-formal-analysis"),
        (
            "solidity/formal.py",
            "FormalAdapter.available",
            "gate-managed-toolchain-bundle",
        ),
    ],
)
def test_filesystem_primary_gate_map_is_scope_specific(
    relative_path: str,
    scope: str,
    expected_gate: str,
) -> None:
    assert inventory_module._filesystem_input_gate(relative_path, scope) == expected_gate


def test_write_only_opens_are_not_filesystem_content_inputs(tmp_path: Path) -> None:
    source_root = tmp_path / "mmaudit"
    source_root.mkdir()
    (source_root / "writer.py").write_text(
        "from os import O_CREAT, O_EXCL, O_WRONLY, open as descriptor_open\n"
        "from pathlib import Path\n"
        "def write_only():\n"
        "    Path('plain').open('wb')\n"
        "    descriptor_open('plain', O_WRONLY | O_CREAT)\n"
        "    descriptor_open('exclusive', O_WRONLY | O_CREAT | O_EXCL)\n",
        encoding="utf-8",
    )
    filesystem, interactive = inventory_module._external_input_occurrences(source_root)
    assert interactive == ()
    assert [(path, scope, kind) for path, scope, kind, _ in filesystem] == [
        ("writer.py", "write_only", "metadata-observation")
    ]


def test_authority_entropy_alias_is_detected_without_a_default_gate(tmp_path: Path) -> None:
    source_root = tmp_path / "mmaudit"
    source_root.mkdir()
    (source_root / "entropy.py").write_text(
        "from uuid import uuid4 as new_id\ndef authority_id():\n    return new_id().hex\n",
        encoding="utf-8",
    )
    occurrences = inventory_module._entropy_input_occurrences(source_root)
    assert [(path, scope, kind) for path, scope, kind, _ in occurrences] == [
        ("entropy.py", "authority_id", "uuid.uuid4")
    ]
    with pytest.raises(AutonomyInventoryError, match="unclassified entropy input authority"):
        inventory_module._entropy_input_classification("entropy.py", "authority_id")


def test_binary_nonce_entropy_alias_cannot_escape_inventory_discovery(tmp_path: Path) -> None:
    source_root = tmp_path / "mmaudit"
    source_root.mkdir()
    (source_root / "nonce.py").write_text(
        "from secrets import token_bytes as fresh\ndef nonce():\n    return fresh(16)\n",
        encoding="utf-8",
    )
    occurrences = inventory_module._entropy_input_occurrences(source_root)
    assert [(path, scope, kind) for path, scope, kind, _ in occurrences] == [
        ("nonce.py", "nonce", "secrets.token_bytes")
    ]
    with pytest.raises(AutonomyInventoryError, match="unclassified entropy input authority"):
        inventory_module._entropy_input_classification("nonce.py", "nonce")


def test_objective_drift_fails_before_any_runtime_discovery(tmp_path: Path) -> None:
    objective = tmp_path / "docs" / "remediation" / "v3" / "product_completion_goal.txt"
    objective.parent.mkdir(parents=True)
    objective.write_text("drifted objective\n", encoding="utf-8")
    with pytest.raises(AutonomyInventoryError, match="objective bytes drifted"):
        build_autonomy_gate_inventory(repository_root=tmp_path)


def test_missing_duplicate_and_multiple_assignments_are_rejected(
    inventory: AutonomyGateInventory,
) -> None:
    values = inventory.model_dump(mode="json")
    values["source_coverage"] = values["source_coverage"][:-1]
    with pytest.raises(ValidationError):
        AutonomyGateInventory.model_validate(values)

    values = inventory.model_dump(mode="json")
    values["source_coverage"].append(values["source_coverage"][0])
    with pytest.raises(ValidationError):
        AutonomyGateInventory.model_validate(values)

    values = inventory.model_dump(mode="json")
    first_source = values["logical_gates"][0]["source_ids"][0]
    second_sources = set(values["logical_gates"][1]["source_ids"])
    second_sources.add(first_source)
    values["logical_gates"][1]["source_ids"] = sorted(second_sources)
    with pytest.raises(ValidationError):
        AutonomyGateInventory.model_validate(values)


def test_cold_generation_is_provider_network_and_secret_free() -> None:
    assay = textwrap.dedent(
        f"""
        import os
        import socket
        from collections import UserDict
        from pathlib import Path

        class GuardedEnvironment(UserDict):
            def _guard(self, key):
                text = str(key).upper()
                if any(token in text for token in ("SECRET", "TOKEN", "API_KEY", "OPENROUTER")):
                    raise AssertionError(f"sensitive environment key was read: {{key}}")

            def __getitem__(self, key):
                self._guard(key)
                return super().__getitem__(key)

            def __contains__(self, key):
                self._guard(key)
                return super().__contains__(key)

        def forbidden(*args, **kwargs):
            raise AssertionError("network access is forbidden during inventory generation")

        class GuardedSocket(socket.socket):
            def connect(self, *args, **kwargs):
                return forbidden(*args, **kwargs)

            def connect_ex(self, *args, **kwargs):
                return forbidden(*args, **kwargs)

        safe = dict(os.environ)
        safe["OPENROUTER_API_KEY"] = "must-not-be-read"
        os.environ = GuardedEnvironment(safe)
        os.getenv = lambda key, default=None: os.environ.get(key, default)
        socket.socket = GuardedSocket
        socket.create_connection = forbidden
        socket.getaddrinfo = forbidden
        socket.gethostbyname = forbidden
        socket.gethostbyname_ex = forbidden

        from mmaudit.orchestration.autonomy_gate_inventory import build_autonomy_gate_inventory

        generated = build_autonomy_gate_inventory(repository_root=Path({str(ROOT)!r}))
        assert generated.provider_or_network_accessed is False
        assert generated.secret_material_read is False
        """
    )
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(ROOT / "src"),
    }
    completed = subprocess.run(
        [sys.executable, "-c", assay],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
