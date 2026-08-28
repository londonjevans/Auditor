from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from mmaudit.models.prepurchase_quote import reconcile_prepurchase_quote
from mmaudit.reporting.bundle import build_run_cost_ledger_evidence
from tests.unit.test_forensic_cost_ledger import _usage
from tests.unit.test_prepurchase_quote import _ACCEPTED_AT, _quote_fixture


def test_reconciliation_rejects_valid_evidence_bound_to_another_campaign(
    tmp_path: Path,
    config_factory: Callable[..., Any],
) -> None:
    quoted_root = tmp_path / "quoted"
    other_root = tmp_path / "other"
    quoted_root.mkdir(mode=0o700)
    other_root.mkdir(mode=0o700)
    quoted = _quote_fixture(quoted_root, config_factory, seed="quoted-campaign")
    other = _quote_fixture(other_root, config_factory, seed="other-campaign")
    baseline = quoted.manifest.cost_ledger_baseline
    assert baseline is not None
    request_id = quoted.preflight.task_envelopes[0].scheduler_logical_request_id
    reservation = quoted.ledger.reserve(request_id, Decimal("0.2"))
    quoted.ledger.reconcile(reservation, Decimal("0.1"))
    swapped = build_run_cost_ledger_evidence(
        baseline=baseline,
        final_snapshot=quoted.ledger.snapshot(),
        campaign_logical_request_ids=(request_id,),
        usage_records=(_usage(cost="0.1", request_id=request_id),),
        campaign_id=other.manifest.campaign_id,
        campaign_manifest_sha256=other.manifest.manifest_sha256,
    )

    assert swapped.schema_version == "1.1"
    with pytest.raises(ValueError, match="accepted quote baseline"):
        reconcile_prepurchase_quote(
            quoted.acceptance,
            swapped,
            reconciled_at=_ACCEPTED_AT + timedelta(hours=1),
        )
