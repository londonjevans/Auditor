from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from mmaudit.benchmark.model_portfolio import (
    ModelBenchmarkPortfolio,
    TrustedCandidateBenchmarkCampaignVerification,
    create_candidate_benchmark_campaign,
    seal_model_benchmark_portfolio_from_campaign,
    verify_model_benchmark_portfolio_campaign,
    write_model_benchmark_portfolio,
)
from mmaudit.benchmark.models import (
    ModelBenchmarkDimension,
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
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    CandidateModel,
    CandidateOperationalStatus,
    LineageReviewStatus,
    QualificationDimensionThreshold,
    QualificationDisposition,
    seal_candidate_registry,
    seal_operator_lineage_review,
    seal_qualification_policy,
)
from mmaudit.models.qualification_workflow import (
    QualificationWorkflowBundle,
    candidate_generation_verification_requests,
    load_private_model_benchmark_report,
    load_qualification_release_bindings,
    load_qualification_workflow_bundle,
    run_qualification_workflow,
    seal_qualification_release_bindings,
    validate_qualification_portfolio_readiness,
    write_qualification_workflow_bundle,
)
from mmaudit.models.schemas import ExecutionEvidenceKind, UsageRecord
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json
from tests.qualification_support import synthetic_release_observation
from tests.unit import test_model_benchmark as benchmark_fixtures
from tests.unit import test_model_qualification as qualification_fixtures

ROOT = Path(__file__).parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
MODEL_ID = "synthetic/model-a"
ROOT_LINEAGE = "sha256:" + ("a" * 64)


def _candidate_inputs(
    *,
    lineage_status: LineageReviewStatus = LineageReviewStatus.APPROVED,
):
    manifest, evidence = qualification_fixtures._discovery_run(
        model_id=MODEL_ID,
        index=0,
    )
    review_arguments = {
        "status": lineage_status,
        "reviewed_model_ids": (MODEL_ID,),
        "rationale": "Synthetic operator-reviewed lineage decision.",
    }
    if lineage_status is LineageReviewStatus.APPROVED:
        review_arguments.update(
            {
                "root_lineage": ROOT_LINEAGE,
                "reviewed_by": "operator",
                "reviewed_at": NOW,
                "evidence_sha256": "a" * 64,
            }
        )
    review = seal_operator_lineage_review(**review_arguments)
    candidate = CandidateModel(
        exact_model_id=MODEL_ID,
        canonical_model_slug=evidence.canonical_slug,
        root_lineage=(ROOT_LINEAGE if lineage_status is LineageReviewStatus.APPROVED else None),
        lineage_review=review,
        discovery_evidence_sha256=evidence.discovery_evidence_sha256,
        approved_provider_endpoint=evidence.approved_provider_endpoint,
        approved_provider_name=evidence.provider_name,
        endpoint_snapshot_sha256=evidence.endpoint_snapshot_sha256,
        model_metadata_snapshot_sha256=evidence.model_metadata_snapshot_sha256,
        pricing_snapshot_sha256=evidence.pricing_snapshot_sha256,
        context_size=evidence.context_size,
        output_limit=evidence.output_limit,
        structured_output_supported=evidence.structured_output_supported,
        reasoning_supported=evidence.reasoning_supported,
        zdr_eligible=evidence.zdr_eligible,
        data_collection_deny_eligible=evidence.data_collection_deny_eligible,
        operational_status=CandidateOperationalStatus.AVAILABLE,
        benchmark_status=CandidateBenchmarkStatus.PENDING,
        approved_roles=("whole_protocol_review",),
    )
    registry = seal_candidate_registry(
        created_at=manifest.run_provenance.retrieved_at,
        discovery_run_sha256=manifest.manifest_sha256,
        candidates=(candidate,),
    )
    return manifest, (evidence,), registry


def _policy():
    return seal_qualification_policy(
        created_at=NOW,
        thresholds=tuple(
            QualificationDimensionThreshold(
                dimension=dimension,
                minimum_cases=1,
                minimum_score=1,
            )
            for dimension in sorted(
                ModelBenchmarkDimension,
                key=lambda item: item.value,
            )
        ),
        tier_a_minimum_overall_score=1,
        maximum_validity_days=30,
    )


async def _mock_report(
    *,
    target: ModelBenchmarkTarget = benchmark_fixtures.TARGET,
    schema_failure_case: str | None = None,
    semantic_failure: bool = False,
) -> ModelBenchmarkReport:
    provider = benchmark_fixtures.DeterministicModelBenchmarkProvider(
        schema_failure_case=schema_failure_case,
        follow_repository_instruction=semantic_failure,
        targets=(target,),
    )
    return await run_model_benchmark(
        corpus=load_model_benchmark_corpus(CORPUS_PATH),
        targets=[target],
        provider=provider,
    )


def _as_real_report(
    report: ModelBenchmarkReport,
    *,
    candidate: CandidateModel,
) -> ModelBenchmarkReport:
    payload = report.model_dump(mode="json")
    payload["execution_evidence"] = ExecutionEvidenceKind.REAL.value
    payload["results"][0]["execution_evidence"] = ExecutionEvidenceKind.REAL.value
    for case in payload["results"][0]["cases"]:
        case["execution_evidence"] = ExecutionEvidenceKind.REAL.value
        usage = dict(case["usage_record"])
        routing = dict(usage["routing"])
        routing.update(
            {
                "selected_model": candidate.canonical_model_slug,
                "canonical_model": candidate.canonical_model_slug,
                "selected_provider_endpoint": candidate.approved_provider_endpoint,
                "selected_provider_name": candidate.approved_provider_name,
                "certification_request": True,
                "endpoint_snapshot_sha256": candidate.endpoint_snapshot_sha256,
                "endpoint_pricing_sha256": candidate.pricing_snapshot_sha256,
                "catalog_identity_binding_sha256": canonical_sha256(
                    {
                        "canonical_slug": candidate.canonical_model_slug,
                        "id": candidate.exact_model_id,
                    }
                ),
                "catalog_snapshot_sha256": "6" * 64,
                "discovery_provenance_sha256": "7" * 64,
                "discovery_evidence_sha256": candidate.discovery_evidence_sha256,
            }
        )
        usage.update(
            {
                "execution_evidence": ExecutionEvidenceKind.REAL.value,
                "actual_model": candidate.canonical_model_slug,
                "provider": candidate.approved_provider_name,
                "configured_provider_endpoints": [candidate.approved_provider_endpoint],
                "actual_provider_endpoint": candidate.approved_provider_endpoint,
                "routing": routing,
            }
        )
        record = UsageRecord.model_validate(usage)
        case["usage_record"] = record.model_dump(mode="json")
        case["generation_evidence"] = benchmark_fixtures._forged_real_generation_evidence(
            record
        ).model_dump(mode="json")
    payload["report_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "report_sha256"}
    )
    return ModelBenchmarkReport.model_validate(payload)


def _release_bindings(
    report: ModelBenchmarkReport,
    *,
    benchmark_corpus_version: str = "2.0",
    benchmark_ground_truth_version: str = "2.0",
):
    records = [
        case.usage_record for case in report.results[0].cases if case.usage_record is not None
    ]
    prompt_sha256 = canonical_sha256(sorted(record.prompt_sha256 for record in records))
    schema_hashes = {record.schema_sha256 for record in records}
    assert len(schema_hashes) == 1
    response_schema_sha256 = schema_hashes.pop()
    assert response_schema_sha256 is not None
    return seal_qualification_release_bindings(
        source_commit="1" * 40,
        source_tree_sha256="2" * 64,
        effective_config_sha256="3" * 64,
        prompt_sha256=prompt_sha256,
        response_schema_sha256=response_schema_sha256,
        toolchain_sha256="4" * 64,
        isolation_sha256="5" * 64,
        benchmark_corpus_version=benchmark_corpus_version,
        benchmark_ground_truth_version=benchmark_ground_truth_version,
    )


def _portfolio_evidence(
    *,
    registry,
    report: ModelBenchmarkReport,
    policy=None,
) -> tuple[ModelBenchmarkPortfolio, TrustedCandidateBenchmarkCampaignVerification]:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    selected_policy = _policy() if policy is None else policy
    with TemporaryDirectory(dir="/private/tmp") as directory:
        ledger = AtomicCostLedger.initialize(
            Path(directory) / "cost-ledger.json",
            cap_usd=Decimal("10"),
        )
        campaign = create_candidate_benchmark_campaign(
            Path(directory) / "campaign",
            candidate_registry=registry,
            corpus=suite,
            effective_config_sha256="3" * 64,
            qualification_policy_sha256=selected_policy.policy_sha256,
            cost_ledger=ledger,
        )
        initial_snapshot = campaign.manifest.initial_cost_ledger_snapshot
        result = report.results[0]
        usage = tuple(case.usage_record for case in result.cases if case.usage_record is not None)
        for record in usage:
            cost = Decimal(str(record.accounted_cost_usd))
            if cost:
                reservation = ledger.reserve(record.request_id, cost)
                ledger.reconcile(reservation, cost)
        final_snapshot = candidate_cost_ledger_snapshot(ledger.snapshot())
        failed_cases = sum(case.error_kind is not None for case in result.cases)
        diagnostic = CandidateBenchmarkDiagnostic(
            exact_model_id=result.target.model_id,
            approved_provider_endpoint=registry.candidates[0].approved_provider_endpoint,
            endpoint_snapshot_sha256=registry.candidates[0].endpoint_snapshot_sha256,
            report_sha256=report.report_sha256,
            execution_evidence=report.execution_evidence,
            state=(
                CandidateBenchmarkRunState.COMPLETE_WITH_FAILURES
                if failed_cases
                else CandidateBenchmarkRunState.COMPLETE
            ),
            failure_stage=None,
            reasoning_suppressed=False,
            corpus_cases=len(result.cases),
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
            cost_ledger_before=initial_snapshot,
            cost_ledger_after=final_snapshot,
            successful_cases=len(result.cases) - failed_cases,
            failed_cases=failed_cases,
            error_kinds=tuple(
                sorted({case.error_kind for case in result.cases if case.error_kind is not None})
            ),
        )
        campaign.persist_candidate(
            candidate=registry.candidates[0],
            report=report,
            diagnostic=diagnostic,
            observed_usage=usage,
            ledger_before=initial_snapshot,
            ledger_after=final_snapshot,
        )
        portfolio = seal_model_benchmark_portfolio_from_campaign(
            Path(directory) / "portfolio",
            campaign=campaign,
        )
        verification = verify_model_benchmark_portfolio_campaign(
            campaign.path,
            portfolio=portfolio,
            reports=(report,),
            candidate_registry=registry,
            corpus=suite,
            effective_config_sha256="3" * 64,
            qualification_policy_sha256=selected_policy.policy_sha256,
            cost_ledger=ledger,
        )
        return portfolio, verification


def _portfolio(
    *,
    registry,
    report: ModelBenchmarkReport,
    policy=None,
) -> ModelBenchmarkPortfolio:
    portfolio, _verification = _portfolio_evidence(
        registry=registry,
        report=report,
        policy=policy,
    )
    return portfolio


def _run(
    *,
    report: ModelBenchmarkReport,
    lineage_status: LineageReviewStatus = LineageReviewStatus.APPROVED,
    observed_at: datetime = NOW + timedelta(hours=1),
    evaluated_at: datetime | None = None,
    qualification_expires_at: datetime = NOW + timedelta(days=6),
) -> QualificationWorkflowBundle:
    manifest, evidence, registry = _candidate_inputs(lineage_status=lineage_status)
    portfolio, campaign_verification = _portfolio_evidence(
        registry=registry,
        report=report,
    )
    release_bindings = _release_bindings(report)
    return run_qualification_workflow(
        candidate_registry=registry,
        discovery_run_manifest=manifest,
        discovery_evidence=evidence,
        policy=_policy(),
        benchmark_suite=load_model_benchmark_corpus(CORPUS_PATH),
        benchmark_portfolio=portfolio,
        benchmark_reports=(report,),
        release_bindings=release_bindings,
        trusted_campaign_verification=campaign_verification,
        trusted_generation_verification=None,
        trusted_release_observation=synthetic_release_observation(
            release_bindings,
            observed_at=observed_at,
        ),
        evaluated_at=observed_at if evaluated_at is None else evaluated_at,
        qualification_expires_at=qualification_expires_at,
    )


@pytest.mark.asyncio
async def test_relabelled_real_report_without_authenticated_refetch_is_inconclusive() -> None:
    _, _, registry = _candidate_inputs()
    report = _as_real_report(
        await _mock_report(),
        candidate=registry.candidates[0],
    )

    bundle = _run(report=report)

    assert bundle.qualification_verification.valid
    assert not bundle.qualification_verification.production_selection_ready
    assert bundle.trusted_benchmark_evidence == ()
    assert (
        bundle.qualification_artifact.results[0].disposition
        is QualificationDisposition.INCONCLUSIVE
    )
    assert (
        bundle.updated_registry.candidates[0].benchmark_status
        is CandidateBenchmarkStatus.INCONCLUSIVE
    )
    assert QualificationWorkflowBundle.model_validate_json(bundle.model_dump_json()) == bundle


@pytest.mark.asyncio
async def test_deterministic_semantic_scoring_without_real_capability_is_inconclusive() -> None:
    _, _, registry = _candidate_inputs()
    report = _as_real_report(
        await _mock_report(semantic_failure=True),
        candidate=registry.candidates[0],
    )

    bundle = _run(report=report)

    assert bundle.qualification_verification.valid
    assert not bundle.qualification_verification.production_selection_ready
    assert (
        bundle.qualification_artifact.results[0].disposition
        is QualificationDisposition.INCONCLUSIVE
    )
    assert (
        bundle.updated_registry.candidates[0].benchmark_status
        is CandidateBenchmarkStatus.INCONCLUSIVE
    )
    assert bundle.trusted_benchmark_evidence == ()


@pytest.mark.asyncio
async def test_qualification_time_and_expiry_are_anchored_to_campaign_completion() -> None:
    _, _, registry = _candidate_inputs()
    report = _as_real_report(
        await _mock_report(),
        candidate=registry.candidates[0],
    )

    first = _run(report=report)
    second = _run(
        report=report,
        observed_at=NOW + timedelta(hours=2),
    )

    final_record = report.results[0].cases[-1].usage_record
    assert final_record is not None
    assert final_record.ended_at is not None
    expected_completion = final_record.ended_at + timedelta(seconds=1)
    expected_completion = expected_completion.replace(microsecond=0)
    assert first.evaluated_at == expected_completion
    assert first.qualification_artifact.created_at == expected_completion
    assert first.qualification_artifact.results[0].evaluated_at == expected_completion
    assert (
        first.qualification_artifact.results[0].quality_measurement_sha256
        == second.qualification_artifact.results[0].quality_measurement_sha256
    )
    assert (
        first.qualification_artifact.results[0].result_sha256
        == second.qualification_artifact.results[0].result_sha256
    )


@pytest.mark.asyncio
async def test_stale_campaign_cannot_be_reissued_with_refreshed_times() -> None:
    _, _, registry = _candidate_inputs()
    report = _as_real_report(
        await _mock_report(),
        candidate=registry.candidates[0],
    )

    with pytest.raises(ValueError, match="exceeds the policy age"):
        _run(
            report=report,
            observed_at=NOW + timedelta(days=8),
            qualification_expires_at=NOW + timedelta(days=8, hours=1),
        )
    with pytest.raises(ValueError, match="policy-bound benchmark window"):
        _run(
            report=report,
            qualification_expires_at=NOW + timedelta(days=8),
        )
    with pytest.raises(ValueError, match="trusted release observation"):
        _run(
            report=report,
            evaluated_at=NOW + timedelta(hours=2),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ("mock", "incomplete"))
async def test_non_real_or_incomplete_portfolio_is_rejected(kind: str) -> None:
    schema_failure_case = (
        benchmark_fixtures._case_id_for_dimension(ModelBenchmarkDimension.FALSE_POSITIVE_REJECTION)
        if kind == "incomplete"
        else None
    )
    report = await _mock_report(schema_failure_case=schema_failure_case)

    with pytest.raises(ValueError, match="all-REAL benchmark portfolio"):
        _run(report=report)


@pytest.mark.asyncio
async def test_qualification_rejects_legacy_real_portfolio_without_campaign(
    tmp_path: Path,
) -> None:
    _, _, registry = _candidate_inputs()
    report = _as_real_report(
        await _mock_report(),
        candidate=registry.candidates[0],
    )
    portfolio = write_model_benchmark_portfolio(
        tmp_path / "legacy-portfolio",
        candidate_registry=registry,
        corpus=load_model_benchmark_corpus(CORPUS_PATH),
        reports=(report,),
    )

    with pytest.raises(ValueError, match="journal-bound"):
        validate_qualification_portfolio_readiness(
            portfolio=portfolio,
            policy=_policy(),
        )


@pytest.mark.asyncio
async def test_qualification_rejects_wrong_campaign_policy() -> None:
    _, _, registry = _candidate_inputs()
    report = _as_real_report(
        await _mock_report(),
        candidate=registry.candidates[0],
    )
    portfolio = _portfolio(registry=registry, report=report).model_copy(
        update={"qualification_policy_sha256": "0" * 64}
    )

    with pytest.raises(ValueError, match="policy-matched"):
        validate_qualification_portfolio_readiness(
            portfolio=portfolio,
            policy=_policy(),
        )


@pytest.mark.asyncio
async def test_qualification_rejects_caller_forged_campaign_capability() -> None:
    manifest, evidence, registry = _candidate_inputs()
    report = _as_real_report(
        await _mock_report(),
        candidate=registry.candidates[0],
    )
    portfolio, _trusted = _portfolio_evidence(registry=registry, report=report)
    release_bindings = _release_bindings(report)

    class CallerForgedCapability:
        def require_for(self, **_kwargs: object) -> None:
            return None

    with pytest.raises(ValueError, match="trusted campaign verification"):
        run_qualification_workflow(
            candidate_registry=registry,
            discovery_run_manifest=manifest,
            discovery_evidence=evidence,
            policy=_policy(),
            benchmark_suite=load_model_benchmark_corpus(CORPUS_PATH),
            benchmark_portfolio=portfolio,
            benchmark_reports=(report,),
            release_bindings=release_bindings,
            trusted_campaign_verification=CallerForgedCapability(),  # type: ignore[arg-type]
            trusted_generation_verification=None,
            trusted_release_observation=synthetic_release_observation(
                release_bindings,
                observed_at=NOW + timedelta(hours=1),
            ),
            evaluated_at=NOW + timedelta(hours=1),
            qualification_expires_at=NOW + timedelta(days=6),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("binding_name", "binding_value"),
    (
        ("benchmark_corpus_version", "wrong-corpus-version"),
        ("benchmark_ground_truth_version", "wrong-ground-truth-version"),
    ),
)
async def test_qualification_rejects_release_version_not_observed_in_loaded_suite(
    binding_name: str,
    binding_value: str,
) -> None:
    manifest, evidence, registry = _candidate_inputs()
    report = _as_real_report(
        await _mock_report(),
        candidate=registry.candidates[0],
    )
    portfolio, campaign_verification = _portfolio_evidence(
        registry=registry,
        report=report,
    )
    release_arguments = {binding_name: binding_value}
    release_bindings = _release_bindings(report, **release_arguments)

    with pytest.raises(ValueError, match="benchmark versions differ from the loaded suite"):
        run_qualification_workflow(
            candidate_registry=registry,
            discovery_run_manifest=manifest,
            discovery_evidence=evidence,
            policy=_policy(),
            benchmark_suite=load_model_benchmark_corpus(CORPUS_PATH),
            benchmark_portfolio=portfolio,
            benchmark_reports=(report,),
            release_bindings=release_bindings,
            trusted_campaign_verification=campaign_verification,
            trusted_generation_verification=None,
            trusted_release_observation=synthetic_release_observation(
                release_bindings,
                observed_at=NOW + timedelta(hours=1),
            ),
            evaluated_at=NOW + timedelta(hours=1),
            qualification_expires_at=NOW + timedelta(days=6),
        )


@pytest.mark.asyncio
async def test_malformed_report_fails_closed_before_artifact_creation() -> None:
    report = await _mock_report()
    malformed = report.model_copy(update={"report_sha256": "0" * 64})

    with pytest.raises(ValueError, match="hash is inconsistent"):
        _run(report=malformed)


@pytest.mark.asyncio
async def test_missing_duplicate_or_wrong_model_report_set_fails_closed() -> None:
    manifest, evidence, registry = _candidate_inputs()
    report = await _mock_report()
    bindings = _release_bindings(report)
    portfolio, campaign_verification = _portfolio_evidence(
        registry=registry,
        report=report,
    )
    arguments = {
        "candidate_registry": registry,
        "discovery_run_manifest": manifest,
        "discovery_evidence": evidence,
        "policy": _policy(),
        "benchmark_suite": load_model_benchmark_corpus(CORPUS_PATH),
        "benchmark_portfolio": portfolio,
        "release_bindings": bindings,
        "trusted_campaign_verification": campaign_verification,
        "trusted_generation_verification": None,
        "trusted_release_observation": synthetic_release_observation(
            bindings,
            observed_at=NOW + timedelta(hours=1),
        ),
        "evaluated_at": NOW + timedelta(hours=1),
        "qualification_expires_at": NOW + timedelta(days=6),
    }

    with pytest.raises(ValueError, match="non-empty"):
        run_qualification_workflow(benchmark_reports=(), **arguments)
    with pytest.raises(ValueError, match="duplicate"):
        run_qualification_workflow(
            benchmark_reports=(report, report),
            **arguments,
        )
    wrong_target = ModelBenchmarkTarget(
        model_id="synthetic/model-b",
        root_lineage="sha256:" + ("b" * 64),
    )
    wrong = await _mock_report(target=wrong_target)
    with pytest.raises(ValueError, match="differs from candidates"):
        run_qualification_workflow(benchmark_reports=(wrong,), **arguments)


@pytest.mark.asyncio
async def test_pending_lineage_can_score_tier_a_but_is_not_production_ready() -> None:
    _, _, registry = _candidate_inputs(lineage_status=LineageReviewStatus.PENDING)
    report = _as_real_report(
        await _mock_report(),
        candidate=registry.candidates[0],
    )

    bundle = _run(
        report=report,
        lineage_status=LineageReviewStatus.PENDING,
    )

    assert bundle.qualification_verification.valid
    assert not bundle.qualification_verification.production_selection_ready
    assert bundle.qualification_verification.eligible_tier_a_model_ids == ()
    assert (
        bundle.qualification_artifact.results[0].disposition
        is QualificationDisposition.INCONCLUSIVE
    )


@pytest.mark.asyncio
async def test_private_bundle_writer_is_atomic_canonical_and_mode_0600(
    tmp_path: Path,
) -> None:
    _, _, registry = _candidate_inputs()
    report = _as_real_report(
        await _mock_report(),
        candidate=registry.candidates[0],
    )
    bundle = _run(report=report)
    output = tmp_path / "qualification.json"

    write_qualification_workflow_bundle(output, bundle)

    assert output.stat().st_mode & 0o777 == 0o600
    assert output.read_bytes() == stable_json(bundle).encode()
    assert load_qualification_workflow_bundle(output) == bundle
    with pytest.raises(ValueError, match="fresh"):
        write_qualification_workflow_bundle(output, bundle)


@pytest.mark.asyncio
async def test_candidate_generation_requests_bind_exact_report_usage() -> None:
    _, _, registry = _candidate_inputs()
    report = _as_real_report(
        await _mock_report(),
        candidate=registry.candidates[0],
    )
    requests = candidate_generation_verification_requests(
        registry=registry,
        benchmark_reports=(report,),
    )

    assert len(requests) == len(report.results[0].cases)
    assert {item.benchmark_report_sha256 for item in requests} == {report.report_sha256}
    assert {item.exact_model_id for item in requests} == {MODEL_ID}
    assert {item.canonical_model_id for item in requests} == {
        registry.candidates[0].canonical_model_slug
    }
    assert {item.catalog_identity_binding_sha256 for item in requests} == {
        canonical_sha256(
            {
                "canonical_slug": registry.candidates[0].canonical_model_slug,
                "id": MODEL_ID,
            }
        )
    }
    assert {item.discovery_evidence_sha256 for item in requests} == {
        registry.candidates[0].discovery_evidence_sha256
    }
    assert {item.expected_provider_name for item in requests} == {
        registry.candidates[0].approved_provider_name
    }


@pytest.mark.asyncio
async def test_arbitrary_real_evidence_callback_is_not_a_qualification_api() -> None:
    manifest, evidence, registry = _candidate_inputs()
    report = _as_real_report(
        await _mock_report(),
        candidate=registry.candidates[0],
    )
    arguments = {
        "candidate_registry": registry,
        "discovery_run_manifest": manifest,
        "discovery_evidence": evidence,
        "policy": _policy(),
        "benchmark_suite": load_model_benchmark_corpus(CORPUS_PATH),
        "benchmark_reports": (report,),
        "release_bindings": _release_bindings(report),
        "real_evidence_resolver": lambda **_: True,
        "evaluated_at": NOW + timedelta(hours=1),
        "qualification_expires_at": NOW + timedelta(days=6),
    }

    with pytest.raises(TypeError, match="unexpected keyword"):
        run_qualification_workflow(**arguments)


@pytest.mark.asyncio
async def test_private_loaders_reject_links_hardlinks_duplicates_and_tamper(
    tmp_path: Path,
) -> None:
    _, _, registry = _candidate_inputs()
    report = _as_real_report(
        await _mock_report(),
        candidate=registry.candidates[0],
    )
    bundle = _run(report=report)
    report_path = tmp_path / "report.json"
    report_path.write_text(stable_json(report), encoding="utf-8")
    linked_report = tmp_path / "report-hardlink.json"
    linked_report.hardlink_to(report_path)
    with pytest.raises(ValueError, match="unshared"):
        load_private_model_benchmark_report(report_path)
    with pytest.raises(ValueError, match="unshared"):
        load_private_model_benchmark_report(linked_report)

    symlink = tmp_path / "report-symlink.json"
    symlink.symlink_to(report_path)
    with pytest.raises(ValueError, match="links"):
        load_private_model_benchmark_report(symlink)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":"1.0","schema_version":"1.0"}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate"):
        load_qualification_release_bindings(duplicate)

    bundle_path = tmp_path / "bundle.json"
    write_qualification_workflow_bundle(bundle_path, bundle)
    tampered = bundle.model_dump(mode="json")
    tampered["workflow_sha256"] = "0" * 64
    tampered_path = tmp_path / "tampered.json"
    tampered_path.write_text(stable_json(tampered), encoding="utf-8")
    tampered_path.chmod(0o600)
    with pytest.raises(ValueError, match="strict validation"):
        load_qualification_workflow_bundle(tampered_path)

    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_text(bundle.model_dump_json(), encoding="utf-8")
    noncanonical.chmod(0o600)
    with pytest.raises(ValueError, match="canonically serialized"):
        load_qualification_workflow_bundle(noncanonical)
