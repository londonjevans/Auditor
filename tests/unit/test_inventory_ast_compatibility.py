"""Inventory fingerprints must not depend on the interpreter's debug formatter."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import mmaudit.orchestration.autonomy_gate_inventory as inventory

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        ("pass", "Module(body=[Pass()])"),
        (
            "f()",
            "Module(body=[Expr(value=Call(func=Name(id='f', ctx=Load())))])",
        ),
        (
            "x = []",
            "Module(body=[Assign(targets=[Name(id='x', ctx=Store())], value=List(ctx=Load()))])",
        ),
        (
            "x = None",
            "Module(body=[Assign(targets=[Name(id='x', ctx=Store())], value=Constant(value=None))])",
        ),
        (
            "def f[T](): pass",
            "Module(body=[FunctionDef(name='f', args=arguments(), body=[Pass()], "
            "type_params=[TypeVar(name='T')])])",
        ),
    ),
)
def test_inventory_ast_has_version_independent_frozen_representation(
    source: str, expected: str
) -> None:
    formatter = getattr(inventory, "_canonical_ast_dump", None)
    assert callable(formatter), "inventory needs an explicit version-stable AST format"
    assert formatter(ast.parse(source)) == expected


def test_inventory_ast_preserves_all_current_python313_fingerprints() -> None:
    if sys.version_info[:2] != (3, 13):
        pytest.skip("comparison to the original debug formatter requires Python 3.13")
    formatter = getattr(inventory, "_canonical_ast_dump", None)
    assert callable(formatter)
    sources = sorted((ROOT / "src/mmaudit").rglob("*.py"))
    assert len(sources) >= 300
    for path in sources:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assert formatter(tree) == ast.dump(tree), path.relative_to(ROOT)


def test_inventory_ast_fingerprints_match_real_python312_without_project_dependencies() -> None:
    python312 = shutil.which("python3.12")
    if python312 is None:
        pytest.skip("INCONCLUSIVE: Python 3.12 is unavailable for the cross-interpreter check")
    formatter = getattr(inventory, "_canonical_ast_dump", None)
    assert callable(formatter)
    sources = {
        path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "src/mmaudit").rglob("*.py"))
    }
    expected = {
        name: hashlib.sha256(formatter(ast.parse(source)).encode()).hexdigest()
        for name, source in sources.items()
    }
    # Execute the actual pure formatter under 3.12, without importing 3.13 extensions.
    program = (
        "import ast, hashlib, json, sys\n"
        "assert sys.version_info[:2] == (3, 12)\n"
        + inspect.getsource(formatter)
        + "\nsources = json.load(sys.stdin)\n"
        + "print(json.dumps({name: hashlib.sha256(_canonical_ast_dump(ast.parse(source)).encode())"
        + ".hexdigest() for name, source in sources.items()}))\n"
    )
    result = subprocess.run(
        [python312, "-I", "-c", program],
        input=json.dumps(sources),
        text=True,
        capture_output=True,
        env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
        timeout=90,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == expected
