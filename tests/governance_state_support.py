"""Synthetic operator reports for read-only development-coordination regressions."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from scripts.validate_governance_state import OperatorObservation

FIXTURES = Path(__file__).parent / "fixtures/governance"
HISTORICAL_TIMESTAMP = "2026-09-04T03:39Z"
LATEST_TIMESTAMP = "2026-09-08T10:00:00Z"


def prepend_report(document: bytes, entry: bytes) -> bytes:
    prefix, marker, rest = document.partition(b"\n## ")
    assert marker, "synthetic report needs an existing dated heading"
    return prefix + b"\n" + entry.rstrip() + b"\n\n## " + rest


def synthetic_operator_history() -> tuple[bytes, dict[str, Any]]:
    content = (FIXTURES / "operator_history.md").read_bytes()
    return content, {
        "latest_entry_timestamp": HISTORICAL_TIMESTAMP,
        "operator_results_sha256": hashlib.sha256(content).hexdigest(),
        "operator_results_bytes": len(content),
        "operator_results_lines": len(content.decode("utf-8").splitlines()),
        "global_ledger_entry_count": 3,
        "global_ledger_spent_usd_exact": "0.12500000",
        "completed_real_audits": 0,
    }


def synthetic_operator_observation(
    content: bytes,
    *,
    timestamp: str = LATEST_TIMESTAMP,
    entries: int = 7,
    amount: str = "1.37500000",
) -> OperatorObservation:
    return OperatorObservation(
        raw_sha256=hashlib.sha256(content).hexdigest(),
        byte_count=len(content),
        line_count=len(content.decode("utf-8").splitlines()),
        latest_entry_timestamp=timestamp,
        reported_ledger_entries=entries,
        reported_ledger_used_usd=amount,
        completed_real_audits=0,
        evidence_class="OPERATOR_REPORTED_NOT_INDEPENDENTLY_AUTHENTICATED",
    )
