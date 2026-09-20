"""Disposable cost-adoption checks run the real read-only governance CLI."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mmaudit.models.candidate_selection import load_candidate_selection_plan
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json
from scripts.validate_governance_state import (
    ARTIFACT_PATHS,
    CURRENT_STATE_KEY,
    HISTORICAL_PAYLOAD_SHA256S,
    OPERATOR_RESULTS_PATH,
    QUEUE_PATHS,
    WORKLOG_PATHS,
    validate_governance_state,
)
from tests.unit.test_candidate_plan_cost_adoption import (
    PREDECESSOR,
    coherent_cost_successor_mutation,
)
from tests.unit.test_candidate_plan_cost_transition import _cost_plan

ROOT = Path(__file__).parents[2]
PLAN_PATH = "config/models.selection-plan.json"


@pytest.mark.parametrize(
    "case",
    (
        "exact_reservation",
        "exact_provider_ceiling",
        "stale_artifact_hash",
        "ancestry_evidence_sha256",
        "minimum_prompt_tokens",
    ),
)
def test_governance_cli_accepts_only_exact_nonauthorizing_cost_adoption(
    tmp_path: Path, case: str
) -> None:
    """Invariant: coherent current-state hashes cannot replace authenticated ancestry."""

    paths = (
        set(ARTIFACT_PATHS)
        | set(HISTORICAL_PAYLOAD_SHA256S)
        | set(QUEUE_PATHS)
        | set(WORKLOG_PATHS)
        | {OPERATOR_RESULTS_PATH}
    )
    active_before = (ROOT / PLAN_PATH).read_bytes()
    for name in paths:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    if case == "exact_provider_ceiling":
        plan = load_candidate_selection_plan(PREDECESSOR)
    elif case in {"ancestry_evidence_sha256", "minimum_prompt_tokens"}:
        plan = coherent_cost_successor_mutation(case)
    else:
        plan = _cost_plan()
    raw = stable_json(plan).encode()
    (tmp_path / PLAN_PATH).write_bytes(raw)
    pin = "0" * 64 if case == "stale_artifact_hash" else hashlib.sha256(raw).hexdigest()
    for name in HISTORICAL_PAYLOAD_SHA256S:
        target = tmp_path / name
        document = json.loads(target.read_bytes())
        state = document[CURRENT_STATE_KEY]
        before_hash = canonical_sha256(state)
        state["artifact_sha256s"][PLAN_PATH] = pin
        after_hash = canonical_sha256(state)
        target.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    for name in WORKLOG_PATHS:
        target = tmp_path / name
        header, history = target.read_text(encoding="utf-8").split("\n## ", 1)
        target.write_text(
            header.replace(before_hash, after_hash) + "\n## " + history, encoding="utf-8"
        )
    before = {name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() for name in paths}
    if case in {"exact_reservation", "exact_provider_ceiling"}:
        assert validate_governance_state(tmp_path).provider_call_authorized is False
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/validate_governance_state.py"),
            "--repository-root",
            str(tmp_path),
        ],
        cwd=ROOT,
        env={
            "PATH": os.defpath,
            "PYTHONPATH": str(ROOT / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "MMAUDIT_RUN_REAL_PROVIDER_TESTS": "0",
            "MMAUDIT_SECRETS_ENV_FILE": "",
        },
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert not result.stderr
    if case in {"exact_reservation", "exact_provider_ceiling"}:
        assert result.returncode == 0, result.stdout
        assert "unfinished tickets; NONAUTHORIZING" in result.stdout
    else:
        assert result.returncode == 1, result.stdout
        assert result.stdout == "Governance coordination INVALID; no authority granted.\n"
    assert before == {
        name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() for name in paths
    }
    assert (ROOT / PLAN_PATH).read_bytes() == active_before
