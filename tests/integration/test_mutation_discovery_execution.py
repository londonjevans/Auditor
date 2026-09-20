"""Native local compiler-to-discovery-to-mutation controls, without selected source spans."""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from mmaudit.benchmark.mutation_discovery import (
    PortfolioMutationDiscovery,
    discover_portfolio_mutations,
)
from mmaudit.benchmark.mutation_portfolio import SecurityMutationClass
from mmaudit.benchmark.mutations import (
    apply_source_mutation,
    mutation_repository_sha256,
    revert_source_mutation,
)
from mmaudit.scanners.foundry_inventory import FoundrySourceInput
from tests.integration.test_mutation_compilation import _solc_0_8_30
from tests.integration.test_mutation_portfolio_execution import _run_local_suite
from tests.mutation_discovery_support import COMPILER_FIXTURE, declared_fixture_plan
from tests.mutation_portfolio_support import CASES, FIXTURE, SOURCE_PATH


def _compile_discovery(
    solc: Path, *, source: bytes, path: str, root: Path, artifacts: Path
) -> PortfolioMutationDiscovery:
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
    version = subprocess.run(
        [str(solc), "--version"], capture_output=True, env=environment, timeout=10, check=True
    ).stdout
    (artifacts / "compiler.version.txt").write_bytes(version)
    long_version = version.decode().strip().split("Version: ")[-1]
    assert long_version.startswith("0.8.30+")
    compiler_input = {
        "language": "Solidity",
        "sources": {path: {"content": source.decode()}},
        "settings": {"outputSelection": {"*": {"": ["ast"]}}},
    }
    completed = subprocess.run(
        [str(solc), "--standard-json"],
        input=json.dumps(compiler_input).encode(),
        capture_output=True,
        cwd=root,
        env=environment,
        timeout=20,
        check=False,
    )
    (artifacts / "compiler.stdout.json").write_bytes(completed.stdout)
    (artifacts / "compiler.stderr.txt").write_bytes(completed.stderr)
    (artifacts / "compiler.returncode.txt").write_text(str(completed.returncode))
    assert completed.returncode == 0 and len(completed.stdout) < 5_000_000
    assert len(completed.stderr) < 100_000
    output = json.loads(completed.stdout)
    assert not any(error["severity"] == "error" for error in output.get("errors", []))
    payload = {
        "_format": "ethers-rs-sol-build-info-1",
        "id": "0" * 16,
        "language": "Solidity",
        "solcVersion": "0.8.30",
        "solcLongVersion": long_version,
        "source_id_to_path": {str(item["id"]): name for name, item in output["sources"].items()},
        "input": {**compiler_input, "version": "0.8.30"},
        "output": output,
    }
    build_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    (artifacts / "compiler.normalized.json").write_bytes(build_bytes)
    discovered = discover_portfolio_mutations(
        build_info_jsons=(build_bytes,),
        sources=(FoundrySourceInput(path, source, hashlib.sha256(source).hexdigest()),),
        target_paths=(path,),
        compiler_version="0.8.30",
        compiler_sha256=hashlib.sha256(solc.read_bytes()).hexdigest(),
    )
    (artifacts / "discovery.json").write_text(discovered.model_dump_json(indent=2))
    return discovered


@pytest.mark.parametrize("variant", ["original", "renamed", "unicode-crlf"])
def test_native_compiler_discovers_and_executes_every_candidate(
    tmp_path: Path,
    variant: str,
    record_testsuite_property: Callable[[str, str], None],
) -> None:
    forge = Path.home() / ".foundry" / "bin" / "forge"
    solc = _solc_0_8_30()
    if not forge.is_file() or solc is None:
        pytest.skip("Installed external Forge/solc0.8.30 are required; no tools are provisioned")
    forge, solc = forge.resolve(strict=True), solc.resolve(strict=True)
    assert not forge.is_relative_to(FIXTURE.parents[2]) and not solc.is_relative_to(
        FIXTURE.parents[2]
    )
    root = tmp_path / "source"
    (root / "src").mkdir(parents=True)
    (root / "test").mkdir()
    source = (FIXTURE / SOURCE_PATH).read_bytes()
    properties = (FIXTURE / "test/PortfolioProperties.t.sol").read_bytes()
    path = SOURCE_PATH
    if variant == "renamed":
        for original, replacement in (
            (b"PortfolioTargets", b"AlternateVault"),
            (b"LocalMath", b"AnotherMath"),
            (b"pendingValue", b"pendingUnits"),
        ):
            source = source.replace(original, replacement)
            properties = properties.replace(original, replacement)
        path = "src/AlternateVault.sol"
    elif variant == "unicode-crlf":
        source = ("// Synthetic Unicode comment: π.\n".encode() + source).replace(b"\n", b"\r\n")
    (root / path).write_bytes(source)
    (root / "test/PortfolioProperties.t.sol").write_bytes(properties)
    (root / "foundry.toml").write_bytes((FIXTURE / "foundry.toml").read_bytes())
    record_testsuite_property("mutation_discovery_native_" + variant, str(tmp_path))
    discovered = _compile_discovery(solc, source=source, path=path, root=root, artifacts=tmp_path)
    assert len(discovered.candidates) == 13
    assert {item.specification.kind for item in discovered.candidates} == set(SecurityMutationClass)
    assert not discovered.unsupported
    plan = declared_fixture_plan(discovered, root)
    assert plan.discovery == discovered and len(plan.specifications) == 13
    original_tree = mutation_repository_sha256(root)
    baseline = _run_local_suite(forge, solc, root, tmp_path / "baseline-artifacts")
    assert all(result["status"] == "Success" for result in baseline.values())
    observations = []
    for index, candidate in enumerate(discovered.candidates):
        spec = candidate.specification
        applied = apply_source_mutation(
            source_repository=root, workspace=tmp_path / f"mutant-{index}", specification=spec
        )
        try:
            results = _run_local_suite(
                forge, solc, applied.workspace, tmp_path / f"artifacts-{index}"
            )
            failed = sorted(
                name for name, result in results.items() if result["status"] == "Failure"
            )
            expected = [CASES[spec.kind][1] + "()"]
            observations.append(
                {"id": spec.id, "kind": spec.kind.value, "failed": failed, "expected": expected}
            )
        finally:
            assert revert_source_mutation(applied).exact_restoration
            assert mutation_repository_sha256(root) == original_tree
            assert mutation_repository_sha256(applied.workspace) == original_tree
    (tmp_path / "observations.json").write_text(json.dumps(observations, indent=2))
    assert all(row["failed"] == row["expected"] for row in observations), observations
    assert not discovered.execution_validated and not discovered.qualification_eligible


def test_native_name_lookalikes_and_internal_calls_remain_explicit_gaps(tmp_path: Path) -> None:
    solc = _solc_0_8_30()
    if solc is None:
        pytest.skip("Installed external solc0.8.30 required; no tools are provisioned")
    solc = solc.resolve(strict=True)
    assert not solc.is_relative_to(FIXTURE.parents[2])
    source = (COMPILER_FIXTURE / "NearMiss.sol").read_bytes()
    result = _compile_discovery(
        solc, source=source, path="src/NearMiss.sol", root=tmp_path, artifacts=tmp_path
    )
    assert not result.candidates
    assert len(result.source_classes) == 11
    assert all(row.limitation for row in result.source_classes)
    assert {row.kind for row in result.unsupported} == {
        SecurityMutationClass.INITIALIZER_PROTECTION_REMOVAL,
        SecurityMutationClass.PAUSE_ENFORCEMENT_REMOVAL,
        SecurityMutationClass.NONCE_UPDATE_REMOVAL,
        SecurityMutationClass.EXTERNAL_CALL_BEFORE_STATE_UPDATE,
        SecurityMutationClass.UNCHECKED_RETURN_HANDLING,
        SecurityMutationClass.ROUNDING_DIRECTION,
    }
    assert not result.execution_validated and not result.property_applicability_established
