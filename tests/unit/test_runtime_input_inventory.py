"""Source-only runtime-input discovery; synthetic snippets are parsed, never executed."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from mmaudit.orchestration import autonomy_gate_inventory as inventory


def _observations(source: str, module: str = "control.py") -> list[tuple[str, str, str]]:
    tree = ast.parse(source)
    visitor = inventory._RuntimeExecutionBoundaryVisitor(inventory._import_aliases(tree), module)
    visitor.visit(tree)
    return visitor.occurrences


@pytest.mark.parametrize(
    "source,kind",
    [
        ("import time; time.monotonic()", "elapsed-clock"),
        ("from time import monotonic as clock; clock()", "elapsed-clock"),
        ("import time; clock = time.monotonic; clock()", "elapsed-clock"),
        ("import time; clock = getattr(time, 'monotonic'); clock()", "elapsed-clock"),
        ("import time; getattr(time, 'monotonic')()", "elapsed-clock"),
        ("import sys; sys.modules.items()", "python-runtime-state"),
        ("import sys as runtime; runtime.stdlib_module_names", "python-runtime-state"),
        ("from sys import flags; flags", "python-runtime-state"),
        ("import sys; flags = sys.flags; flags", "python-runtime-state"),
        ("import sys; getattr(sys, 'flags')", "python-runtime-state"),
        ("trusted_sys.modules.get('synthetic_control')", "python-runtime-state"),
        ("getattr(module, '__spec__', None)", "imported-module-attribute"),
        ("module.__cached__", "imported-module-attribute"),
        ("getattr(module, attribute, None)", "dynamic-attribute"),
        ("import subprocess; subprocess.Popen(['synthetic'], shell=False)", "child-dispatch"),
        ("from subprocess import Popen as launch; launch(['synthetic'])", "child-dispatch"),
        ("import os; os.execve(path, argv, {})", "child-dispatch"),
        ("import os; os.read(fd, 1)", "descriptor-io"),
        ("import os; reader = os.read; reader(fd, 1)", "descriptor-io"),
        ("import fcntl; fcntl.flock(fd, 0)", "descriptor-io"),
        ("selector.select(0.01)", "runtime-method"),
        ("process.wait(timeout=1)", "runtime-method"),
        ("factory().wait(timeout=1)", "runtime-method"),
        ("waiter = process.wait; waiter(timeout=1)", "runtime-method"),
        ("waiter = getattr(process, 'wait'); waiter(timeout=1)", "runtime-method"),
        ("process.stdout", "process-observation"),
        ("process.returncode", "process-observation"),
        ("import os; os.killpg(pid, 0)", "process-lifecycle"),
        ("exec('raise AssertionError()')", "dynamic-code"),
        ("compile('raise AssertionError()', '<synthetic>', 'exec')", "dynamic-code"),
    ],
)
def test_runtime_boundary_is_discovered_without_execution(source: str, kind: str) -> None:
    rows = _observations(source)
    assert any(row[1] == kind for row in rows)
    assert all(row[0] == "module" for row in rows)


def test_lexical_aliases_do_not_escape_their_scope_or_override_a_parameter() -> None:
    rows = _observations(
        "from time import monotonic as clock\n"
        "def shadowed(clock):\n    return clock()\n"
        "def owner():\n    from os import read as selected\n    selected(0, 1)\n"
        "def sibling():\n    return selected(0, 1)\n"
        "def observed():\n    return clock()\n"
    )
    assert [(scope, kind) for scope, kind, _ in rows] == [
        ("owner", "descriptor-io"),
        ("observed", "elapsed-clock"),
    ]


def test_same_named_parameter_is_not_assumed_to_be_an_imported_clock() -> None:
    assert _observations("def synthetic(time_source):\n    return time_source()\n") == []


@pytest.mark.parametrize(
    "scope",
    [
        "_worker_bootstrap",
        "prepare_solc_capture",
        "prepare_owned_coverage_launch",
        "prepare_owned_debugger_launch",
    ],
)
def test_generated_producer_binds_literal_template_and_interpolated_handoff(scope: str) -> None:
    def rows(body: str) -> list[tuple[str, str, str]]:
        return _observations(
            f"def {scope}(value):\n    return {body}\n", "scanners/solc_capture.py"
        )

    original = rows("f'never executed {value!r}'")
    changed_literal = rows("f'changed literal {value!r}'")
    changed_binding = rows("f'never executed {str(value)!r}'")
    assert len(original) == len(changed_literal) == len(changed_binding) == 1
    assert original[0][:2] == (scope, "generated-code-producer")
    assert original != changed_literal and original != changed_binding


def test_wall_clock_and_runtime_clock_are_distinct_families() -> None:
    assert _observations("import time; time.time(); time.time_ns()") == []


def test_unclassified_runtime_consumer_cannot_gain_a_default_pass() -> None:
    with pytest.raises(inventory.AutonomyInventoryError, match="unclassified filesystem"):
        inventory._runtime_execution_gate("new_consumer.py", "run", "child-dispatch", "spawn()")


def test_new_runtime_locus_is_rejected_by_the_production_frozen_inventory(tmp_path: Path) -> None:
    (tmp_path / "new_consumer.py").write_text("import time\nobserved = time.monotonic()\n")
    with pytest.raises(inventory.AutonomyInventoryError, match="runtime execution"):
        inventory._discover_runtime_execution_sources(tmp_path)


def test_unparseable_runtime_source_is_not_silently_omitted(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text("def incomplete(")
    with pytest.raises(inventory.AutonomyInventoryError, match="runtime-input module"):
        inventory._runtime_execution_occurrences(tmp_path)


def test_all_capture_runtime_families_are_classified_without_authority() -> None:
    root = Path(__file__).resolve().parents[2] / "src/mmaudit"
    rows = inventory._runtime_execution_occurrences(root)
    selected = [
        row
        for row in rows
        if row[0] in {"scanners/solc_capture.py", "solidity/solc_capture_worker.py"}
    ]
    assert {row[2] for row in selected} == {
        "python-runtime-state",
        "imported-module-attribute",
        "dynamic-attribute",
        "elapsed-clock",
        "child-dispatch",
        "descriptor-io",
        "runtime-method",
        "process-observation",
        "generated-code-producer",
    }
    assert {inventory._runtime_execution_gate(*row) for row in selected} == {
        "gate-runtime-package-integrity",
        "gate-managed-toolchain-bundle",
    }
    assert all(
        inventory._runtime_execution_gate(*row) in inventory._GATE_SPEC_BY_ID for row in rows
    )
    assert len([row for row in selected if row[2] == "generated-code-producer"]) == 4


def test_failure_gap_retention_adds_one_gated_clock_and_preserves_every_previous_locus() -> None:
    from tests.unit.test_autonomy_gate_inventory import _before_development_tree_inputs

    rows = inventory._runtime_execution_occurrences(
        Path(__file__).resolve().parents[2] / "src/mmaudit"
    )
    rows = _before_development_tree_inputs(rows)
    prior = "c8bcfe62c84c6d94f4fe4d0bd590b986d5161c94cee4c3fe7f76822c0f62fc8f"
    candidates = [
        index
        for index, row in enumerate(rows)
        if row[:3] == ("scanners/foundry.py", "_finalize_foundry_repository_suite", "elapsed-clock")
    ]
    assert len(candidates) == 7
    assert any(
        inventory._canonical_sha256([list(row) for row in rows[:index] + rows[index + 1 :]])
        == prior
        for index in candidates
    )
    assert {inventory._runtime_execution_gate(*rows[index]) for index in candidates} == {
        "gate-full-quality-analysis"
    }
