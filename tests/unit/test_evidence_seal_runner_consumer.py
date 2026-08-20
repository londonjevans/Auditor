from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from functools import cache
from pathlib import Path
from typing import cast

import pytest

from mmaudit.benchmark.cross_lineage_adjudication import (
    CrossLineageAdjudicationDisposition,
    build_cross_lineage_adjudication_case_result,
    build_cross_lineage_adjudication_report,
    build_cross_lineage_adjudication_response,
    prepare_cross_lineage_adjudication,
)
from mmaudit.models.authenticated_runner import (
    AuthenticatedCrossLineageRunnerError,
    AuthenticatedCrossLineageRunnerEvidence,
    CrossLineageRunnerRunCustody,
    VerifiedCrossLineageRunnerCustody,
)
from mmaudit.models.ground_truth_authority import VerifiedFrozenGroundTruthProjection
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.unit import test_authenticated_runner as runner_fixtures
from tests.unit.test_authenticated_runner import _LiveInputs
from tests.unit.test_cross_lineage_adjudication import _judge_usage_and_generation

_LIVE_INPUTS_FACTORY = cast(
    Callable[[], _LiveInputs],
    runner_fixtures.live_inputs.__wrapped__,
)


@cache
def _live_inputs() -> _LiveInputs:
    return _LIVE_INPUTS_FACTORY()


def _ground_projection(
    live_inputs: _LiveInputs,
    evidence: AuthenticatedCrossLineageRunnerEvidence,
) -> VerifiedFrozenGroundTruthProjection:
    return live_inputs.ground_truth.require_for(
        objective_sha256=evidence.objective_sha256,
        provenance_sha256=evidence.frozen_ground_truth_provenance_sha256,
        source_revision=evidence.frozen_source_revision,
        benchmark_corpus_sha256=evidence.benchmark_corpus_sha256,
        benchmark_ground_truth_sha256=evidence.benchmark_ground_truth_sha256,
    )


def _issue(
    tmp_path_name: str,
    tmp_path: Path,
    live_inputs: _LiveInputs,
    *,
    runs: tuple[CrossLineageRunnerRunCustody, ...] | None = None,
) -> tuple[
    AtomicCostLedger,
    VerifiedCrossLineageRunnerCustody,
    AuthenticatedCrossLineageRunnerEvidence,
]:
    retained = live_inputs.runs if runs is None else runs
    ledger, interval = runner_fixtures._closed_runner_interval(
        tmp_path / tmp_path_name,
        retained,
    )
    custody, evidence = runner_fixtures._issue(
        live_inputs,
        interval,
        runs=retained,
    )
    return ledger, custody, evidence


def test_provider_free_runner_fixture_cannot_reach_authenticated_consumer(
    tmp_path: Path,
) -> None:
    live_inputs = _live_inputs()
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="owned REAL transport origin"):
        _issue("nominal.json", tmp_path, live_inputs)


def test_provider_free_inventory_fixture_cannot_mint_authseal_inputs(
    tmp_path: Path,
) -> None:
    live_inputs = _live_inputs()
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="owned REAL transport origin"):
        _issue("inventory.json", tmp_path, live_inputs)


def test_rejected_provider_free_adjudication_cannot_mint_authseal_inputs(
    tmp_path: Path,
) -> None:
    live_inputs = _live_inputs()
    original = live_inputs.runs[0]
    judge = runner_fixtures._judge(runner_fixtures.PRIMARY_JUDGE_ID, index=1)
    prepared = prepare_cross_lineage_adjudication(
        public_lineage_capability=live_inputs.public_lineage,
        suite=live_inputs.suite,
        candidate_report=original.candidate_report,
        judge=judge,
        run_kind=original.run_kind,
    )
    results = []
    for index, request in enumerate(prepared.requests):
        response = build_cross_lineage_adjudication_response(
            request=request,
            dimension_outcomes=request.expected_dimension_outcomes,
            disposition=CrossLineageAdjudicationDisposition.REJECTED,
            rationale="Synthetic independent adjudication rejects this candidate result.",
        )
        usage, generation = _judge_usage_and_generation(
            case_index=index,
            request=request,
            response=response,
            judge=judge,
        )
        results.append(
            build_cross_lineage_adjudication_case_result(
                request=request,
                response=response,
                usage_record=usage,
                generation_evidence=generation,
            )
        )
    rejected_report = build_cross_lineage_adjudication_report(
        prepared=prepared,
        results=results,
    )
    rejected_run = replace(
        original,
        adjudication_report=rejected_report,
        judge_generation_verification=runner_fixtures._judge_generation_capability(
            rejected_report,
            judge,
        ),
    )
    runs = (rejected_run, live_inputs.runs[1])
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="owned REAL transport origin"):
        _issue(
            "rejected-disposition.json",
            tmp_path,
            live_inputs,
            runs=runs,
        )


def test_provider_free_ledger_custody_cannot_mint_serialized_authority(
    tmp_path: Path,
) -> None:
    live_inputs = _live_inputs()
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="owned REAL transport origin"):
        _issue("revoked.json", tmp_path, live_inputs)


def test_provider_free_runtime_fixture_cannot_reach_authseal_retarget_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live_inputs = _live_inputs()
    del monkeypatch
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="owned REAL transport origin"):
        _issue("retarget.json", tmp_path, live_inputs)
