from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from mmaudit.economic_acceptance import (
    EconomicAcceptanceObservation,
    EconomicAcceptanceReport,
    EconomicAcceptanceStatus,
    build_economic_acceptance_report,
    load_economic_acceptance_manifest,
    write_economic_acceptance_report,
)
from mmaudit.models.schemas import InvariantExecutionStatus
from mmaudit.scanners.base import sanitized_scanner_environment
from mmaudit.solidity.invariant_execution import normalize_foundry_invariant_output

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = (
    ROOT / "tests" / "fixtures" / "solidity" / "maximum_assurance_economic" / "manifest.json"
)
_CONTRACT_BLOCK = re.compile(
    r"(?ms)^Ran [0-9]+ tests? for [^\n:]+:"
    r"(?P<contract>[A-Za-z_][A-Za-z0-9_]*)\n"
    r"(?P<body>.*?)(?=^Ran [0-9]+ tests? for |\Z)"
)
_PROHIBITED_FIXTURE_MARKERS = (
    "ffi = true",
    "http://",
    "https://",
    "vm.ffi",
    "envaddress(",
    "envbytes(",
    "envstring(",
    "envuint(",
)


def _contract_pattern(contracts: list[str]) -> str:
    return "^(" + "|".join(re.escape(contract) for contract in contracts) + ")$"


def _external_solc() -> Path | None:
    candidates = (
        Path.home() / "Library" / "Application Support" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".local" / "share" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".svm" / "0.8.30" / "solc-0.8.30",
    )
    return next(
        (
            candidate
            for candidate in candidates
            if candidate.is_file() and os.access(candidate, os.X_OK)
        ),
        None,
    )


def _run_contracts(
    forge: str,
    *,
    solc: Path,
    fixture: Path,
    contracts: list[str],
    workspace: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            forge,
            "test",
            "--root",
            str(fixture),
            "--offline",
            "--use",
            str(solc),
            "--color",
            "never",
            "--cache-path",
            str(workspace / "cache"),
            "--out",
            str(workspace / "out"),
            "--match-contract",
            _contract_pattern(contracts),
            "-vv",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=sanitized_scanner_environment(workspace / "environment"),
    )


def _normalized(result: subprocess.CompletedProcess[str]) -> InvariantExecutionStatus:
    status, _, _ = normalize_foundry_invariant_output(
        result.returncode,
        result.stdout + result.stderr,
    )
    return status


def _contract_statuses(
    result: subprocess.CompletedProcess[str],
) -> dict[str, InvariantExecutionStatus]:
    output = result.stdout + result.stderr
    statuses: dict[str, InvariantExecutionStatus] = {}
    for match in _CONTRACT_BLOCK.finditer(output):
        block = match.group(0)
        suite_ok = "Suite result: ok." in block
        suite_failed = "Suite result: FAILED." in block
        if suite_ok is suite_failed:
            raise AssertionError("Foundry contract block has no unambiguous suite result")
        status, _, _ = normalize_foundry_invariant_output(
            0 if suite_ok else 1,
            block,
        )
        contract = match.group("contract")
        if contract in statuses:
            raise AssertionError(f"Foundry emitted duplicate contract block: {contract}")
        statuses[contract] = status
    return statuses


def _assert_fixture_has_no_host_interaction_markers(fixture: Path) -> None:
    for path in sorted(fixture.rglob("*")):
        if not path.is_file():
            continue
        contents = path.read_text(encoding="utf-8").casefold()
        assert all(marker not in contents for marker in _PROHIBITED_FIXTURE_MARKERS)


def _validate_report_against_schema_shape(report_path: Path) -> None:
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    schema = json.loads(
        (ROOT / "schemas/economic_acceptance_report.schema.json").read_text(encoding="utf-8")
    )
    assert set(payload) == set(schema["required"])
    assert all(
        set(outcome) == set(schema["$defs"]["outcome"]["required"])
        for outcome in payload["outcomes"]
    )
    EconomicAcceptanceReport.model_validate(payload)


def test_real_foundry_economic_portfolio_reproduces_only_unsafe_conditions(
    tmp_path: Path,
) -> None:
    forge = shutil.which("forge")
    if forge is None:
        pytest.skip("forge is not installed")
    solc = _external_solc()
    if solc is None:
        pytest.skip("external Foundry-managed solc 0.8.30 is not installed")
    forge_path = Path(forge).resolve()
    assert not forge_path.is_relative_to((ROOT / "tests" / "fixtures").resolve())
    assert not solc.resolve().is_relative_to((ROOT / "tests" / "fixtures").resolve())
    manifest = load_economic_acceptance_manifest(
        MANIFEST_PATH,
        repository_root=ROOT,
    )
    observations: list[EconomicAcceptanceObservation] = []

    for case in manifest.cases:
        fixture = ROOT / case.fixture_path
        _assert_fixture_has_no_host_interaction_markers(fixture)

        first = _run_contracts(
            forge,
            solc=solc,
            fixture=fixture,
            contracts=case.unsafe_contracts,
            workspace=tmp_path / case.ticket_id / "unsafe-first",
        )
        second = _run_contracts(
            forge,
            solc=solc,
            fixture=fixture,
            contracts=case.unsafe_contracts,
            workspace=tmp_path / case.ticket_id / "unsafe-second",
        )
        safe = _run_contracts(
            forge,
            solc=solc,
            fixture=fixture,
            contracts=case.safe_contracts,
            workspace=tmp_path / case.ticket_id / "safe",
        )

        first_statuses = _contract_statuses(first)
        second_statuses = _contract_statuses(second)
        safe_statuses = _contract_statuses(safe)
        expected_unsafe = set(case.unsafe_contracts)
        expected_safe = set(case.safe_contracts)
        assert set(first_statuses) == expected_unsafe
        assert set(second_statuses) == expected_unsafe
        assert set(safe_statuses) == expected_safe
        assert _normalized(first) is InvariantExecutionStatus.COUNTEREXAMPLE
        assert _normalized(second) is InvariantExecutionStatus.COUNTEREXAMPLE
        assert safe.returncode == 0, (safe.stdout + safe.stderr)[-4000:]
        assert _normalized(safe) is InvariantExecutionStatus.PASSED

        observations.append(
            EconomicAcceptanceObservation(
                ticket_id=case.ticket_id,
                first_unsafe_contracts_executed=sorted(first_statuses),
                first_unsafe_counterexamples=sorted(
                    contract
                    for contract, status in first_statuses.items()
                    if status is InvariantExecutionStatus.COUNTEREXAMPLE
                ),
                second_unsafe_contracts_executed=sorted(second_statuses),
                second_unsafe_counterexamples=sorted(
                    contract
                    for contract, status in second_statuses.items()
                    if status is InvariantExecutionStatus.COUNTEREXAMPLE
                ),
                safe_contracts_executed=sorted(safe_statuses),
                safe_contracts_passed=sorted(
                    contract
                    for contract, status in safe_statuses.items()
                    if status is InvariantExecutionStatus.PASSED
                ),
            )
        )

    report = build_economic_acceptance_report(manifest, observations)
    assert report.status is EconomicAcceptanceStatus.PASSED
    assert report.executed_harnesses == report.applicable_harnesses == 43
    assert report.reproduced_issues == report.planted_issues == 21
    assert report.unconfirmed_safe_near_misses == report.safe_near_misses == 22
    output = tmp_path / "economic-acceptance.json"
    write_economic_acceptance_report(output, report)
    _validate_report_against_schema_shape(output)

    for case in manifest.cases:
        fixture = ROOT / case.fixture_path
        assert not (fixture / "cache").exists()
        assert not (fixture / "out").exists()
