"""Real installed-tool controls in disposable local-only synthetic workspaces."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

from mmaudit.benchmark.mutation_portfolio import SecurityMutationClass
from mmaudit.benchmark.mutations import (
    MutationPropertyOutcome,
    MutationTestOutcome,
    _class_mutation_scores,
    apply_source_mutation,
    mutation_repository_sha256,
    revert_source_mutation,
    score_planned_mutation_campaigns,
)
from tests.integration.test_mutation_compilation import _solc_0_8_30
from tests.mutation_portfolio_support import (
    CASES,
    FIXTURE,
    portfolio_plan,
    property_id,
    specification,
)


def _run_local_suite(forge: Path, solc: Path, workspace: Path, artifacts: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [
            str(forge),
            "test",
            "--root",
            str(workspace),
            "--use",
            str(solc),
            "--offline",
            "--json",
            "--out",
            str(artifacts / "out"),
            "--cache-path",
            str(artifacts / "cache"),
        ],
        cwd=workspace,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C", "NO_COLOR": "1"},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode in {0, 1}, completed.stderr
    assert len(completed.stdout.encode()) < 1_000_000
    assert len(completed.stderr.encode()) < 1_000_000
    artifacts.mkdir(mode=0o700, parents=True, exist_ok=True)
    (artifacts / "suite.stdout.json").write_text(completed.stdout)
    (artifacts / "suite.stderr.txt").write_text(completed.stderr)
    (artifacts / "returncode.txt").write_text(str(completed.returncode))
    payload = json.loads(completed.stdout)
    assert isinstance(payload, dict), completed.stderr
    suites = [
        suite for suite in payload.values() if isinstance(suite, dict) and "test_results" in suite
    ]
    assert len(suites) == 1, (payload, completed.stderr)
    results = suites[0]["test_results"]
    assert set(results) == {case[1] + "()" for case in CASES.values()}
    assert all(value["status"] in {"Success", "Failure"} for value in results.values())
    failures = sum(value["status"] == "Failure" for value in results.values())
    assert completed.returncode == (1 if failures else 0)
    return cast(dict[str, Any], results)


def test_all_eleven_mutants_compile_fail_the_named_property_and_restore(
    tmp_path: Path,
    record_testsuite_property: Callable[[str, str], None],
) -> None:
    forge = Path.home() / ".foundry" / "bin" / "forge"
    solc = _solc_0_8_30()
    if not forge.is_file() or solc is None:
        pytest.skip(
            "installed external Forge and solc 0.8.30 are required; no tools are provisioned"
        )
    forge, solc = forge.resolve(strict=True), solc.resolve(strict=True)
    record_testsuite_property("mutation_native_artifacts", str(tmp_path))
    assert not forge.is_relative_to(FIXTURE.parents[2])
    assert not solc.is_relative_to(FIXTURE.parents[2])
    baseline = tmp_path / "baseline"
    shutil.copytree(FIXTURE, baseline)
    original_tree = mutation_repository_sha256(FIXTURE)
    baseline_results = _run_local_suite(forge, solc, baseline, tmp_path / "baseline-artifacts")
    assert all(value["status"] == "Success" for value in baseline_results.values())
    assert mutation_repository_sha256(baseline) == original_tree
    observed = []
    for index, kind in enumerate(SecurityMutationClass):
        spec = specification(kind)
        applied = apply_source_mutation(
            source_repository=FIXTURE,
            workspace=tmp_path / f"mutant-{index}",
            specification=spec,
        )
        try:
            results = _run_local_suite(
                forge, solc, applied.workspace, tmp_path / f"artifacts-{index}"
            )
            failed = {name for name, result in results.items() if result["status"] == "Failure"}
            assert failed == {CASES[kind][1] + "()"}, (kind, results)
            observed.append(
                MutationPropertyOutcome(
                    mutation_id=spec.id,
                    mutation_kind=kind,
                    property_id=property_id(kind),
                    outcome=MutationTestOutcome.KILLED,
                    evidence_sha256=applied.mutated_file_sha256,
                )
            )
        finally:
            assert revert_source_mutation(applied).exact_restoration
            assert mutation_repository_sha256(FIXTURE) == original_tree
    classes = _class_mutation_scores(observed, minimum_required=0.95)
    assert len(classes) == 11 and all(item.gate_passed for item in classes)
    # Native synthetic execution is not an admitted campaign or qualified audit.
    unadmitted = score_planned_mutation_campaigns(
        plan=portfolio_plan(),
        campaigns=[],
        minimum_property_kill_score=0.95,
    )
    assert not unadmitted.gate_passed
    assert all(item.outcome is MutationTestOutcome.INCONCLUSIVE for item in unadmitted.outcomes)
