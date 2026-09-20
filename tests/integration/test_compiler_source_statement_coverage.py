"""Actual offline synthetic coverage offsets; no admitted execution or audit authority."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any, NoReturn

import pytest

import mmaudit.scanners.foundry_inventory_runner as inventory_runner
from mmaudit.benchmark.mutations import mutation_repository_sha256
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    RepositorySuiteInventoryPhase,
    SolidityProjectMetadata,
    SolidityProjectType,
)
from mmaudit.scanners.foundry_inventory_runner import FoundryInventoryRunResult
from mmaudit.scanners.foundry_statement_coverage import parse_forge_debug_statement_coverage
from mmaudit.scanners.foundry_statement_producer import (
    FoundryStatementCoverageProductionError,
    _aggregate_coverage,
    _PhysicalStatement,
    _validate_catalog_structure,
)
from mmaudit.solidity.properties import generated_local_property_source
from tests.integration.test_mutation_compilation import _solc_0_8_30
from tests.integration.test_mutation_pipeline_execution import NativeLocalMutationBackend
from tests.property_reachability_support import FIXTURE, SOURCE, guard_inputs, inventory_snapshot
from tests.unit.test_foundry_statement_producer import _inputs


@pytest.mark.parametrize("style", ["lf", "crlf", "mixed"])
def test_native_coverage_keeps_compiler_hits_bound_to_original_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, style: str
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        pytest.fail("synthetic compiler-source coverage attempted network access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    forge, solc = Path.home() / ".foundry/bin/forge", _solc_0_8_30()
    if not forge.is_file() or solc is None:
        pytest.skip("Requires existing external Forge/solc0.8.30; no provisioning")
    forge, solc = forge.resolve(strict=True), solc.resolve(strict=True)
    repository = Path(__file__).resolve().parents[2]
    assert not forge.is_relative_to(repository) and not solc.is_relative_to(repository)
    workspace = tmp_path / "source"
    workspace.mkdir()
    shutil.copyfile(FIXTURE / "foundry.toml", workspace / "foundry.toml")
    text = "// Synthetic Unicode offset control: Ω.\n" + (FIXTURE / SOURCE).read_text()
    if style != "lf":
        text = "".join(
            line.replace("\n", "\r\n") if style == "crlf" or i % 2 == 0 else line
            for i, line in enumerate(text.splitlines(keepends=True))
        )
    _, harnesses = guard_inputs(source_text=text)
    originals = {SOURCE: text.encode()}
    for harness in harnesses:
        generated = generated_local_property_source(
            harness, project_root=".", expected_chain_id=31337
        )
        assert generated is not None
        originals[generated[0]] = generated[1]
    for name, raw in originals.items():
        path = workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    copied_solc = tmp_path / "solc"
    shutil.copyfile(solc, copied_solc)
    copied_solc.chmod(0o700)
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
    version = subprocess.run(
        [str(forge), "--version"],
        env=environment,
        capture_output=True,
        timeout=10,
        check=True,
        shell=False,
    ).stdout
    (tmp_path / "forge.version.txt").write_bytes(version)
    repository_sha256 = mutation_repository_sha256(workspace)
    # Only test-only MOCK input custody; no real isolation or execution admission.
    monkeypatch.setattr(inventory_runner, "isolation_attestation_sha256", lambda _: "a" * 64)

    def inventory(phase: RepositorySuiteInventoryPhase) -> FoundryInventoryRunResult:
        result = inventory_runner.run_foundry_test_inventory(
            workspace=workspace,
            private_dir=tmp_path,
            projects=(
                SolidityProjectMetadata(project_root=".", project_type=SolidityProjectType.FOUNDRY),
            ),
            phase=phase,
            forge_executable=forge,
            copied_solc=copied_solc,
            repository_sha256=repository_sha256,
            configuration_sha256=hashlib.sha256(b"synthetic compiler-source coverage").hexdigest(),
            tool_version=version.decode().splitlines()[0],
            tool_sha256=hashlib.sha256(forge.read_bytes()).hexdigest(),
            compiler_version="0.8.30",
            compiler_sha256=hashlib.sha256(solc.read_bytes()).hexdigest(),
            backend=NativeLocalMutationBackend(),
            timeout_seconds=30,
        )
        (tmp_path / f"{phase.value}.json").write_text(json.dumps(inventory_snapshot(result)))
        assert result.evidence.execution_evidence is ExecutionEvidenceKind.MOCK
        return result

    before = inventory(RepositorySuiteInventoryPhase.PRE_EXECUTION)
    build_info = tmp_path / "build-info"
    completed = subprocess.run(
        [
            str(forge),
            "coverage",
            "--root",
            str(workspace),
            "--report",
            "debug",
            "--json",
            "--exclude-tests",
            "--use",
            str(solc),
            "--offline",
            "--no-auto-detect",
            "--force",
            "--cache-path",
            str(tmp_path / "cache"),
            "--out",
            str(tmp_path / "out"),
            "--build-info",
            "--build-info-path",
            str(build_info),
            "--ast",
        ],
        cwd=workspace,
        env=environment,
        capture_output=True,
        timeout=30,
        check=False,
        shell=False,
    )
    (tmp_path / "coverage.stdout").write_bytes(completed.stdout)
    (tmp_path / "coverage.stderr").write_bytes(completed.stderr)
    (tmp_path / "coverage.returncode").write_text(str(completed.returncode))
    assert completed.returncode == 0, completed.stderr.decode()
    assert len(completed.stdout) <= 2_000_000 and len(completed.stderr) <= 100_000
    debug = parse_forge_debug_statement_coverage(completed.stdout, max_bytes=2_000_000)
    after = inventory(RepositorySuiteInventoryPhase.POST_EXECUTION)
    assert before.compiler_inputs == after.compiler_inputs
    assert before.statement_catalogs == after.statement_catalogs
    assert before.inventories == after.inventories
    assert mutation_repository_sha256(workspace) == repository_sha256
    # Coverage currently discards its compiler artifacts. These are the real
    # unchanged pre/post inventories, not an invented coverage compiler capture.
    assert len(before.statement_catalogs) == 1
    catalog = before.statement_catalogs[0]
    _validate_catalog_structure(catalog, "native synthetic coverage")
    unit = catalog.units[0]
    source = next(s for s in unit.sources if s.path == SOURCE)
    rows = [_PhysicalStatement(".", s.path, unit, s) for s in unit.statements if s.path == SOURCE]
    hits = {s.identity: s.hits for s in debug.statements}
    missing = [r for r in rows if r.debug_identity not in hits]
    matched = [r for r in rows if r.debug_identity in hits]
    # Preserve the actual format gap: Forge omits the modifier placeholder.
    # Do not discard it from the full population or claim complete coverage.
    assert len(rows) == 14 and len(matched) == 13
    assert [r.statement.node_type for r in missing] == ["PlaceholderStatement"]
    assert any(hits[r.debug_identity] > 0 for r in matched)
    # Synthetic process metadata is only a unit adapter for the unchanged
    # aggregator refusal; it is not a host-custody receipt for this native run.
    synthetic_process = replace(_inputs().processes[0], debug_coverage=debug)
    with pytest.raises(FoundryStatementCoverageProductionError, match="lacks an exact Forge"):
        _aggregate_coverage(
            {r.source_key: r for r in rows},
            catalogs={".": catalog},
            processes_by_project={".": (synthetic_process,)},
        )
    if style == "lf":
        assert source.source_mapping is None
    else:
        assert source.source_mapping is not None
        assert any(r.statement.start_byte != r.debug_identity[1] for r in rows)
    assert all((workspace / name).read_bytes() == raw for name, raw in originals.items())
    transformation = None if source.source_mapping is None else source.source_mapping.transformation
    assert (transformation is None) == (style == "lf")
    (tmp_path / "comparison.json").write_text(
        json.dumps(
            dict(
                style=style,
                source_sha256=source.source_sha256,
                transformation=None
                if transformation is None
                else transformation.model_dump(mode="json"),
                atomic_statements=len(rows),
                matched_atomic_statements=len(matched),
                unmatched_atomic_statements=[
                    dict(node_type=r.statement.node_type, compiler_identity=r.debug_identity)
                    for r in missing
                ],
                covered_atomic_statements=sum(hits[r.debug_identity] > 0 for r in matched),
                full_statement_population_accepted=False,
                stdout_sha256=hashlib.sha256(completed.stdout).hexdigest(),
                compiler_catalog_origin="EXACT_PRE_POST_INVENTORY_NOT_COVERAGE_BUILD_INFO",
                coverage_build_info_files=len(tuple(build_info.glob("*.json"))),
                execution_validated=False,
                qualification_eligible=False,
                audit_complete=False,
            )
        )
    )
