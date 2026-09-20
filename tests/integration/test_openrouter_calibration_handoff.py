"""Local native source replay with isolated runner registration and two explicit fake origins.

The original provider adapter and ledger owner compose here. Only launch/provider
execution and runner registration/origin are test stand-ins; no production REAL
capability is issued, and the real calibration consumer must reject these handles.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import mmaudit.models.authenticated_runner as runner
import mmaudit.orchestration.authenticated_calibration_accounting as accounting
import mmaudit.orchestration.authenticated_calibration_openrouter as batch_module
import mmaudit.orchestration.authenticated_runner_openrouter as adapter
from mmaudit.models.authenticated_calibration import observe_authenticated_model_calibration
from mmaudit.operator_secrets import OPENROUTER_API_KEY_NAME, OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.integration.test_operator_reservation_boundary import (
    forbid_network_and_secrets as forbid_network_and_secrets,
)
from tests.unit import test_authenticated_runner as sources
from tests.unit import test_authenticated_runner_openrouter as fixtures
from tests.unit.test_calibration_ledger_accounting import closed_interval
from tests.unit.test_retained_runner_custody import build_retained_runner


@pytest.mark.asyncio
@pytest.mark.parametrize("later", ("known", "unknown", "source-drift"))
async def test_original_adapter_retains_and_disposes_native_semantic_custody(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    forbid_network_and_secrets: list[str],
    later: str,
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic.json", cap_usd=Decimal("250"))
    state: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=1) as executor:
        live = executor.submit(sources.live_inputs.__wrapped__).result(timeout=60)
        launch = replace(
            fixtures._structural_launch(),
            benchmark_suite=live.suite,
            ground_truth_capability=live.ground_truth,
            public_lineage_capability=live.public_lineage,
            budget=SimpleNamespace(atomic_ledger=ledger),
            candidate_registry=SimpleNamespace(
                candidates=(SimpleNamespace(exact_model_id=sources.CANDIDATE_ID),)
            ),
        )
        secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-no-provider-key"})
        actual_accounting_scope = batch_module.calibration_ledger_accounting_scope

        def owned_accounting(exact_ledger: Any) -> Any:
            from contextlib import contextmanager

            @contextmanager
            def scope() -> Any:
                with actual_accounting_scope(exact_ledger) as owner:
                    state["owner"] = owner
                    yield owner

            return scope()

        async def execute(**_kwargs: Any) -> Any:
            owned = build_retained_runner(tmp_path, ledger=ledger, owner=state["owner"], live=live)
            state["context"] = owned
            subject = executor.submit(owned.__enter__).result(timeout=60)
            state["subject"] = subject
            lease = subject.registry.snapshot(subject.original)
            state["original_interval"] = lease.state.closed_ledger_interval
            original = fixtures._completed_execution()
            execution = replace(
                original,
                runner_capability=subject.original,
                runner_evidence=subject.evidence,
                runner_projection=subject.require(subject.original, evidence=subject.evidence),
                closed_ledger_interval=lease.state.closed_ledger_interval,
                runs=tuple(
                    replace(item, custody=run)
                    for item, run in zip(original.runs, live.runs, strict=True)
                ),
            )
            # Change adapter-local bindings only. Production runner exports and
            # all original pristine-runtime checks remain unmodified.
            proxy = SimpleNamespace(
                require_verified_cross_lineage_runner_custody=subject.require,
                revoke_verified_cross_lineage_runner_custody=subject.revoke,
                retain_verified_cross_lineage_runner_custody=subject.retain,
            )
            monkeypatch.setattr(adapter, "_runner_authority_module", proxy)
            for name, value in (
                ("require_verified_cross_lineage_runner_custody", subject.require),
                ("revoke_verified_cross_lineage_runner_custody", subject.revoke),
                ("retain_verified_cross_lineage_runner_custody", subject.retain),
                ("_TRUSTED_REQUIRE_RUNNER_CUSTODY", subject.require),
                ("_TRUSTED_REVOKE_RUNNER_CUSTODY", subject.revoke),
                ("_TRUSTED_RETAIN_RUNNER_CUSTODY", subject.retain),
            ):
                monkeypatch.setattr(adapter, name, value)
            return execution

        monkeypatch.setattr(batch_module, "calibration_ledger_accounting_scope", owned_accounting)
        for module in (adapter, batch_module):
            monkeypatch.setattr(
                module,
                "preflight_authenticated_openrouter_launch",
                lambda _launch: fixtures._execution_inventory(),
            )
        monkeypatch.setattr(adapter, "execute_authenticated_cross_lineage_runner", execute)

        async def consume() -> None:
            async with batch_module.authenticated_openrouter_calibration_scope(
                launches=(launch,), operator_secrets=(secrets,)
            ) as batch:
                subject = state["subject"]
                item = batch.inputs[0]
                state["moved"] = item.runner_custody
                assert secrets.cleared
                assert item.runner_custody is not subject.original
                with pytest.raises(ValueError, match="revoked"):
                    subject.require(subject.original, evidence=subject.evidence)
                subject.require(item.runner_custody, evidence=item.runner_evidence)
                with pytest.raises(ValueError, match=r"absent|mismatched|revoked"):
                    observe_authenticated_model_calibration(
                        selected_model_ids=batch.selected_model_ids,
                        benchmark_suite=batch.benchmark_suite,
                        ground_truth=batch.ground_truth,
                        inputs=batch.inputs,
                    )
                if later == "known":
                    interval = closed_interval(ledger, "synthetic-later", actual=Decimal("0.5"))
                    accounting.retain_calibration_ledger_interval(state["owner"], interval=interval)
                    with pytest.raises(ValueError, match="ledger changed after closure"):
                        runner._require_closed_cross_lineage_ledger_interval(
                            state["original_interval"]
                        )
                    subject.require(item.runner_custody, evidence=item.runner_evidence)
                elif later == "unknown":
                    pending = ledger.reserve("synthetic-unknown", Decimal("1"))
                    ledger.commit_for_transport(pending)
                    ledger.reconcile(pending, None)
                else:
                    object.__setattr__(item.runs[0].candidate_report, "report_sha256", "0" * 64)
                state["ledger_bytes"] = ledger.path.read_bytes()

        try:
            if later == "known":
                await consume()
            else:
                with pytest.raises(ValueError):
                    await consume()
            assert ledger.path.read_bytes() == state["ledger_bytes"]
            assert secrets.cleared
            with pytest.raises(ValueError, match="revoked"):
                state["subject"].require(state["moved"], evidence=state["subject"].evidence)
            assert state["subject"].registry._entries == {}
            with pytest.raises(ValueError, match="revoked"):
                accounting.observe_calibration_ledger_accounting(state["owner"])
            assert forbid_network_and_secrets == []
        finally:
            if "context" in state:
                executor.submit(state["context"].__exit__, None, None, None).result(timeout=60)
