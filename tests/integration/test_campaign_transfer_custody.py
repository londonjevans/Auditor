"""Original local issuer/consumer with MOCK or explicitly failed UNVERIFIED reports."""

import asyncio
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

import mmaudit.benchmark.model_portfolio as campaign_module
from mmaudit.benchmark.model_portfolio import (
    CandidateBenchmarkCampaignJournal,
    ModelBenchmarkPortfolio,
    TrustedCandidateBenchmarkCampaignVerification,
)
from mmaudit.benchmark.models import (
    ModelBenchmarkReport,
    ModelBenchmarkTarget,
    load_model_benchmark_corpus,
    run_model_benchmark,
)
from mmaudit.models.candidate_benchmark import (
    CandidateBenchmarkDiagnostic,
    CandidateBenchmarkRunState,
    candidate_cost_ledger_snapshot,
)
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.models.usage import is_creditable_usage_record
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.manifest import canonical_sha256
from tests.integration.test_operator_reservation_boundary import (
    forbid_network_and_secrets as forbid_network_and_secrets,
)
from tests.unit.test_model_benchmark_portfolio import (
    CORPUS_PATH,
    _candidate_registry,
    _report,
    _UnavailableProvider,
)


@dataclass(frozen=True)
class CampaignInputs:
    original: TrustedCandidateBenchmarkCampaignVerification
    journal: CandidateBenchmarkCampaignJournal
    portfolio: ModelBenchmarkPortfolio
    reports: tuple[ModelBenchmarkReport, ...]
    ledger: AtomicCostLedger

    def arguments(self) -> dict[str, Any]:
        return {
            "portfolio_sha256": self.portfolio.portfolio_sha256,
            "reports": self.reports,
            "policy_sha256": self.journal.manifest.qualification_policy_sha256,
            "effective_config_sha256": self.journal.manifest.effective_config_sha256,
        }

    def require(self, capability: TrustedCandidateBenchmarkCampaignVerification) -> None:
        capability.require_for(**self.arguments())


def campaign_inputs(path: Path, count: int = 1, *, unavailable: bool = False) -> CampaignInputs:
    """Issue original local custody without replacing any issuer or verifier."""

    suite = load_model_benchmark_corpus(CORPUS_PATH)
    registry = _candidate_registry(tuple(f"synthetic/campaign-move-{i:03}" for i in range(count)))
    ledger = AtomicCostLedger.initialize(path / "ledger.json", cap_usd=Decimal("250"))
    journal = campaign_module.create_candidate_benchmark_campaign(
        path / "campaign",
        candidate_registry=registry,
        corpus=suite,
        effective_config_sha256="3" * 64,
        qualification_policy_sha256="4" * 64,
        cost_ledger=ledger,
    )
    reports = []
    for candidate in registry.candidates:
        if unavailable:
            # Preserve the full corpus and every failed case. No usage is invented
            # to fill the artifact: even the 128-report fixture retains the 5 MB limit.
            with asyncio.Runner(loop_factory=asyncio.new_event_loop) as runner:
                report = runner.run(
                    run_model_benchmark(
                        corpus=suite,
                        targets=[ModelBenchmarkTarget(model_id=candidate.exact_model_id)],
                        provider=_UnavailableProvider(),
                    )
                )
            assert report.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
            assert all(case.error_kind is not None for case in report.results[0].cases)
        else:
            report = _report(suite, candidate.exact_model_id)
            assert report.execution_evidence is ExecutionEvidenceKind.MOCK
        usage = tuple(
            case.usage_record for case in report.results[0].cases if case.usage_record is not None
        )
        before = candidate_cost_ledger_snapshot(ledger.snapshot())
        for record in usage:
            cost = Decimal(str(record.accounted_cost_usd))
            if cost:
                reservation = ledger.reserve(record.request_id, cost)
                ledger.reconcile(reservation, cost)
        after = candidate_cost_ledger_snapshot(ledger.snapshot())
        cases = report.results[0].cases
        failed = sum(case.error_kind is not None for case in cases)
        diagnostic = CandidateBenchmarkDiagnostic(
            exact_model_id=candidate.exact_model_id,
            approved_provider_endpoint=candidate.approved_provider_endpoint,
            endpoint_snapshot_sha256=candidate.endpoint_snapshot_sha256,
            report_sha256=report.report_sha256,
            execution_evidence=report.execution_evidence,
            state=(
                CandidateBenchmarkRunState.COMPLETE_WITH_FAILURES
                if failed
                else CandidateBenchmarkRunState.COMPLETE
            ),
            failure_stage=None,
            reasoning_suppressed=False,
            corpus_cases=len(cases),
            requests_observed=len(usage),
            logical_request_count=len(usage),
            provider_attempt_count=sum(record.attempts for record in usage),
            retry_count=sum(record.attempts - 1 for record in usage),
            successful_request_count=sum(record.status == "success" for record in usage),
            failed_request_count=sum(record.status != "success" for record in usage),
            unresolved_cost_count=0,
            observed_usage_sha256=canonical_sha256(
                [record.model_dump(mode="json") for record in usage]
            ),
            cost_ledger_before=before,
            cost_ledger_after=after,
            successful_cases=len(cases) - failed,
            failed_cases=failed,
            error_kinds=tuple(sorted({case.error_kind for case in cases if case.error_kind})),
        )
        journal.persist_candidate(
            candidate=candidate,
            report=report,
            diagnostic=diagnostic,
            observed_usage=usage,
            ledger_before=before,
            ledger_after=after,
        )
        reports.append(report)
    portfolio = campaign_module.seal_model_benchmark_portfolio_from_campaign(
        path / "portfolio", campaign=journal
    )
    original = campaign_module.issue_trusted_candidate_benchmark_campaign_verification(
        campaign=journal, portfolio=portfolio, reports=tuple(reports)
    )
    result = CampaignInputs(original, journal, portfolio, tuple(reports), ledger)
    result.require(original)
    return result


@pytest.mark.parametrize("count", (1, 2, 128))
def test_original_campaign_proof_moves_complete_set_without_io_or_evidence_promotion(
    tmp_path: Path, forbid_network_and_secrets: list[str], count: int
) -> None:
    inputs = campaign_inputs(tmp_path, count, unavailable=count == 128)
    before = {str(path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    successor = campaign_module.transfer_trusted_candidate_benchmark_campaign_verification(
        inputs.original, **inputs.arguments()
    )
    try:
        inputs.require(successor)
        with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
            inputs.require(inputs.original)
        assert len(inputs.reports) == count
        for report in inputs.reports:
            assert report.case_ids == [case.case_id for case in inputs.journal._corpus.cases]
            assert report.execution_evidence is (
                ExecutionEvidenceKind.UNVERIFIED if count == 128 else ExecutionEvidenceKind.MOCK
            )
            for case in report.results[0].cases:
                if count == 128:
                    assert case.usage_record is None and case.error_kind is not None
                else:
                    assert case.usage_record is not None
                    assert not is_creditable_usage_record(case.usage_record, require_real=True)
        after = {str(path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
        assert after == before
        assert forbid_network_and_secrets == []
    finally:
        campaign_module.revoke_trusted_candidate_benchmark_campaign_verification(successor)


@pytest.mark.parametrize("kind", ("missing", "extra", "duplicate", "reordered"))
def test_partial_or_rewritten_campaign_inventory_cannot_be_transferred(
    tmp_path: Path, forbid_network_and_secrets: list[str], kind: str
) -> None:
    inputs = campaign_inputs(tmp_path, 2)
    arguments = inputs.arguments()
    arguments["reports"] = {
        "missing": inputs.reports[:1],
        "extra": (*inputs.reports, inputs.reports[0]),
        "duplicate": (inputs.reports[0], inputs.reports[0]),
        "reordered": tuple(reversed(inputs.reports)),
    }[kind]
    try:
        with pytest.raises(ValueError):
            campaign_module.transfer_trusted_candidate_benchmark_campaign_verification(
                inputs.original, **arguments
            )
        inputs.require(inputs.original)
        assert forbid_network_and_secrets == []
    finally:
        campaign_module.revoke_trusted_candidate_benchmark_campaign_verification(inputs.original)
