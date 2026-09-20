"""Original synthetic invocation and ledger boundaries, without provider execution."""

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from mmaudit.config import AuditConfigOverrides
from mmaudit.models.usage import request_token_plan_from_usage
from mmaudit.orchestration import manifest
from mmaudit.orchestration.assurance import AssuranceRuntime
from mmaudit.orchestration.cost_ledger import CostEntryStatus, CostPriorBillingUnknownError
from mmaudit.reporting.bundle import build_run_cost_ledger_evidence
from tests.integration.test_truncation_tree_manifest_files import (
    no_provider_or_operator_secrets as no_provider_or_operator_secrets,
)
from tests.refresh_runtime_support import bind_usage_to_refresh_pricing_runtime
from tests.truncation_tree_manifest_support import (
    build_review_manifest_report,
    build_review_source_fixture,
)
from tests.truncation_tree_report_support import candidate_report_config
from tests.truncation_tree_run_support import OriginalRunAccounting
from tests.unit import test_assurance as assurance


@pytest.fixture(scope="module")
def original_inputs() -> tuple[Any, ...]:
    config = candidate_report_config()
    source = build_review_source_fixture()
    now = datetime.now(UTC).replace(microsecond=0)
    authorities = assurance._assurance_policy_selection(
        config, now, source_inventory=source.scheduler_shards
    )
    template = assurance._complete_assurance_scheduler_fixture(
        config,
        authorities.qualification,
        authorities.evidence_bundle,
        authorities.refresh_runtime,
        now,
        source_inventory=source.scheduler_shards,
        analysis_input_inventory=source.analysis_inputs,
        candidate_falsifier_models=("specialist-0/model-0", "specialist-1/model-1"),
    )
    original = next(
        output.model_completion_evidence.usage_record
        for output in template.outputs
        if output.model_completion_evidence is not None
    )
    usage = assurance._bind_promoted_assurance_usage(original, authorities)
    return config, source, authorities.refresh_runtime, usage


class _DispatchProbe:
    def __init__(self, accounting: OriginalRunAccounting, request_id: str) -> None:
        self.accounting = accounting
        self.request_id = request_id
        self.called = False

    def mark_dispatched(self, task_id: str) -> None:
        entry = next(
            item
            for item in self.accounting.ledger.snapshot().entries
            if item.request_id == self.request_id
        )
        assert entry.status is CostEntryStatus.RESERVED and task_id == "synthetic-task"
        self.called = True


def test_original_accounting_reserves_before_dispatch_and_closes_exact_usage(
    original_inputs: tuple[Any, ...],
    tmp_path: Path,
) -> None:
    _, _, refresh, original = original_inputs
    before = original.model_dump_json()
    accounting = OriginalRunAccounting(tmp_path / "cost")
    usage = accounting.prepare(original, refresh)
    plan = request_token_plan_from_usage(usage)
    assert plan is not None
    expected = (
        Decimal("0.000001") * plan.hard_prompt_tokens
        + Decimal("0.000002") * plan.requested_completion_tokens
    )
    reservation = accounting.pending[usage.request_id]
    assert reservation.reserved_usd == expected < Decimal("250")
    assert original.model_dump_json() == before
    assert accounting.baseline.spent_usd_exact == "0" and not accounting.baseline.entries
    probe = _DispatchProbe(accounting, usage.request_id)
    # Named invariant: dispatch cannot precede durable reservation or erase its final charge.
    accounting.dispatch(probe, "synthetic-task", usage)
    assert probe.called
    accounting.finish(usage)
    assert not accounting.pending
    final = accounting.ledger.snapshot()
    evidence = build_run_cost_ledger_evidence(
        baseline=accounting.baseline,
        final_snapshot=final,
        campaign_logical_request_ids=(usage.request_id,),
        usage_records=(usage,),
    )
    assert Decimal(evidence.run_accounted_cost_usd_exact) == Decimal(usage.accounted_cost_usd_exact)
    assert len(evidence.attempts) == len(final.entries) == 1
    assert final.entries[0].status is CostEntryStatus.RECONCILED


def test_original_accounting_refuses_completion_before_dispatch(
    original_inputs: tuple[Any, ...],
    tmp_path: Path,
) -> None:
    _, _, refresh, original = original_inputs
    accounting = OriginalRunAccounting(tmp_path / "cost")
    usage = accounting.prepare(original, refresh)
    with pytest.raises(ValueError, match="before original dispatch"):
        accounting.finish(usage)
    assert accounting.ledger.snapshot().entries[0].status is CostEntryStatus.RESERVED


def test_original_accounting_refuses_duplicate_and_unknown_previous_billing(
    original_inputs: tuple[Any, ...],
    tmp_path: Path,
) -> None:
    _, _, refresh, original = original_inputs
    accounting = OriginalRunAccounting(tmp_path / "cost")
    accounting.prepare(original, refresh)
    with pytest.raises(ValueError, match="already reserved"):
        accounting.prepare(original, refresh)
    other = OriginalRunAccounting(tmp_path / "uncertain-cost")
    uncertain = other.ledger.reserve("synthetic.previous", Decimal("0.01"))
    other.ledger.reconcile(uncertain, None)
    before = other.ledger.snapshot()
    with pytest.raises(CostPriorBillingUnknownError):
        other.prepare(original, refresh)
    assert other.ledger.snapshot() == before


def test_explicit_synthetic_price_bounds_cannot_omit_a_component(
    original_inputs: tuple[Any, ...],
) -> None:
    _, _, refresh, usage = original_inputs
    with pytest.raises(ValueError, match="every priced component"):
        bind_usage_to_refresh_pricing_runtime(usage, refresh, planned_maximum_units={"prompt": 100})


@pytest.mark.parametrize("include_invocation", (False, True))
def test_original_invocation_is_exact_and_legacy_fixture_remains_explicit(
    original_inputs: tuple[Any, ...],
    include_invocation: bool,
) -> None:
    config, source, _, _ = original_inputs
    report = build_review_manifest_report(
        config, source, AssuranceRuntime(), "250", include_invocation=include_invocation
    )
    args = dict(
        report=report,
        file_config=config,
        environment_overrides=AuditConfigOverrides(),
        cli_overrides=AuditConfigOverrides(),
        run_options=source.analysis_arguments["run_options"],
        effective_config=config,
    )
    if not include_invocation:
        with pytest.raises(ValueError, match="run options differ"):
            manifest._run_configuration_binding(**args)
    else:
        binding = manifest._run_configuration_binding(**args)
        assert binding.achieved_profile is None and not report.completed
        assert binding.run_options == source.analysis_arguments["run_options"]
        corpus = source.analysis_arguments["property_corpus"]
        assert report.metadata["solidity"]["property_corpus_summary"] == {
            "properties": len(corpus.properties),
            "limitations": len(corpus.limitations),
            "corpus_hash": corpus.corpus_hash,
        }


@pytest.mark.parametrize("field", ("run_options", "configuration_provenance"))
def test_original_invocation_refuses_substituted_report_metadata(
    original_inputs: tuple[Any, ...],
    field: str,
) -> None:
    config, source, _, _ = original_inputs
    report = build_review_manifest_report(
        config, source, AssuranceRuntime(), "250", include_invocation=True
    )
    changed = report.model_copy(update={"metadata": report.metadata | {field: {}}})
    with pytest.raises(ValueError, match=r"report .* differ"):
        manifest._run_configuration_binding(
            report=changed,
            file_config=config,
            environment_overrides=AuditConfigOverrides(),
            cli_overrides=AuditConfigOverrides(),
            run_options=source.analysis_arguments["run_options"],
            effective_config=config,
        )
