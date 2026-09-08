"""Read-only local governance CLI checks with no provider or credential transport."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from mmaudit.orchestration.manifest import canonical_sha256
from scripts.validate_governance_state import (
    ARTIFACT_PATHS,
    CURRENT_STATE_KEY,
    HISTORICAL_PAYLOAD_SHA256S,
    OPERATOR_RESULTS_PATH,
    QUEUE_PATHS,
    WORKLOG_PATHS,
    validate_governance_state,
)
from tests.governance_state_support import (
    FIXTURES,
    LATEST_TIMESTAMP,
    prepend_report,
    synthetic_operator_observation,
)

ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts/validate_governance_state.py"


def test_governance_validation_is_read_only_without_network_or_subprocesses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = (
        set(ARTIFACT_PATHS)
        | set(HISTORICAL_PAYLOAD_SHA256S)
        | set(QUEUE_PATHS)
        | set(WORKLOG_PATHS)
        | {OPERATOR_RESULTS_PATH}
    )
    before = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in paths}

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("local governance validation must not execute or contact a provider")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    state = validate_governance_state(ROOT)
    assert state.provider_call_authorized is False
    assert state.operator.completed_real_audits == 0
    assert before == {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in paths
    }


@pytest.mark.parametrize("case", ("valid", "duplicate_json", "linked_document", "missing_document"))
def test_governance_cli_reports_validity_without_authority(tmp_path: Path, case: str) -> None:
    repository = ROOT if case == "valid" else tmp_path
    if case in {"duplicate_json", "linked_document"}:
        destination = repository / "docs/remediation/v3/runtime_status.json"
        destination.parent.mkdir(parents=True)
        if case == "duplicate_json":
            destination.write_bytes(b'{"synthetic":false,"synthetic":true}')
        else:
            local = repository / "synthetic.json"
            local.write_bytes(b"{}")
            destination.symlink_to(local)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--repository-root", str(repository)],
        cwd=ROOT,
        env={"PATH": os.defpath, "PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        timeout=30,
    )
    if case == "valid":
        assert result.returncode == 0, result.stderr
        assert "unfinished tickets; NONAUTHORIZING" in result.stdout
    else:
        assert result.returncode == 1, result.stderr
        assert result.stdout == "Governance coordination INVALID; no authority granted.\n"
    assert not result.stderr


@pytest.mark.parametrize(
    "case", ("reconciled", "stale_binding", "altered_history", "invented_summary", "authority")
)
@pytest.mark.parametrize("entry_name", ("operator_new_entry.md", "operator_wrapped_entry.md"))
def test_real_governance_cli_reconciles_only_exact_nonauthorizing_new_reports(
    tmp_path: Path, case: str, entry_name: str
) -> None:
    paths = (
        set(ARTIFACT_PATHS)
        | set(HISTORICAL_PAYLOAD_SHA256S)
        | set(QUEUE_PATHS)
        | set(WORKLOG_PATHS)
        | {OPERATOR_RESULTS_PATH}
    )
    # Copy only the validator's explicit public evidence scope, never private inputs or a ledger.
    for name in paths:
        destination = tmp_path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / name).read_bytes())
    operator_path = tmp_path / OPERATOR_RESULTS_PATH
    original = operator_path.read_bytes()
    copied_state = json.loads((tmp_path / "docs/remediation/v3/runtime_status.json").read_bytes())
    prior_timestamp = copied_state[CURRENT_STATE_KEY]["operator"]["latest_entry_timestamp"]
    # Keep the synthetic append newer than copied evidence without reading the host clock.
    # Production chronology checks and all negative cases remain unchanged.
    timestamp = (datetime.fromisoformat(prior_timestamp) + timedelta(seconds=1)).isoformat()
    timestamp = timestamp.replace("+00:00", "Z")
    entry = (FIXTURES / entry_name).read_bytes()
    assert entry.count(LATEST_TIMESTAMP.encode()) == 1
    entry = entry.replace(LATEST_TIMESTAMP.encode(), timestamp.encode(), 1)
    appended = prepend_report(original, entry)
    if case == "altered_history":
        # Even coherent current digest updates must not bless edits to the frozen introduction.
        appended = appended.replace(
            b"# Operator execution results", b"# Changed execution results", 1
        )
    operator_path.write_bytes(appended)
    if case != "stale_binding":
        old_state_hash = ""
        new_state_hash = ""
        observation = synthetic_operator_observation(appended, timestamp=timestamp).model_dump(
            mode="json"
        )
        if case == "invented_summary":
            observation["reported_ledger_entries"] = 99
        for name in HISTORICAL_PAYLOAD_SHA256S:
            path = tmp_path / name
            document = json.loads(path.read_bytes())
            state = document[CURRENT_STATE_KEY]
            old_state_hash = canonical_sha256(state)
            state["operator"] = observation
            if case == "authority":
                state["provider_call_authorized"] = True
            new_state_hash = canonical_sha256(state)
            path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        for name in WORKLOG_PATHS:
            path = tmp_path / name
            header, history = path.read_text(encoding="utf-8").split("\n## ", 1)
            header = header.replace(old_state_hash, new_state_hash)
            header = re.sub(
                r"^LAST_RECONCILED_OPERATOR_RESULTS: .+$",
                "LAST_RECONCILED_OPERATOR_RESULTS: Synthetic local observation "
                f"{observation['raw_sha256']} / {observation['byte_count']} bytes / "
                f"{observation['line_count']} lines; latest {observation['latest_entry_timestamp']}. "
                f"Reported {observation['reported_ledger_entries']} entries / "
                f"USD {observation['reported_ledger_used_usd']}; zero completed real audits. "
                "Not independently authenticated; no execution authority.",
                header,
                flags=re.MULTILINE,
            )
            path.write_text(header + "\n## " + history, encoding="utf-8")
    before = {name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() for name in paths}
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--repository-root", str(tmp_path)],
        cwd=ROOT,
        env={"PATH": os.defpath, "PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert not result.stderr
    if case == "reconciled":
        assert result.returncode == 0, result.stdout
        assert "unfinished tickets; NONAUTHORIZING" in result.stdout
    else:
        assert result.returncode == 1, result.stdout
        assert result.stdout == "Governance coordination INVALID; no authority granted.\n"
    assert before == {
        name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() for name in paths
    }
    assert (ROOT / OPERATOR_RESULTS_PATH).read_bytes() == original
