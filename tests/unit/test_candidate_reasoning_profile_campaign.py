from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mmaudit.benchmark.model_portfolio import (
    create_candidate_reasoning_profile_benchmark_campaign,
    issue_trusted_candidate_reasoning_profile_campaign_verification,
    resume_candidate_reasoning_profile_benchmark_campaign,
    verify_candidate_reasoning_profile_benchmark_campaign,
)
from mmaudit.benchmark.models import ModelBenchmarkDimension, load_model_benchmark_corpus
from mmaudit.config import AuditConfig
from mmaudit.models.candidate_benchmark import (
    build_candidate_reasoning_profile_benchmark_plan,
    run_candidate_reasoning_profile_benchmarks,
    run_candidate_registry_benchmarks,
)
from mmaudit.models.qualification import (
    QualificationBindings,
    QualificationDimensionResult,
    QualificationDisposition,
    load_qualification_policy,
    seal_model_qualification_artifact,
    seal_model_qualification_result,
)
from mmaudit.models.runtime import build_reasoning_policy
from mmaudit.models.usage import UsageLedger
from mmaudit.orchestration.manifest import canonical_sha256
from tests.unit import test_candidate_benchmark as fixtures

ROOT = Path(__file__).parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
POLICY_PATH = ROOT / "config" / "models.maximum-assurance.toml"
NOW = datetime(2026, 8, 2, 9, 0, tzinfo=UTC)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _config(config_factory: Callable[..., AuditConfig]) -> AuditConfig:
    base = config_factory()
    return config_factory(
        execution={"budget_usd": 250, "max_requests_per_agent": 512},
        models={
            "reasoning": {"effort": "high", "reserved_tokens": 4_096},
            "judge": {
                **base.models.judge.model_dump(mode="python"),
                "reasoning": {"effort": "low", "reserved_tokens": 512},
            },
        },
    )


def _qualification_artifact(*, candidate, report, registry, suite, policy_sha256: str):
    dimensions = tuple(
        QualificationDimensionResult(
            dimension=dimension,
            passed=1,
            evaluated=1,
            score=1,
        )
        for dimension in sorted(ModelBenchmarkDimension, key=lambda item: item.value)
    )
    result = seal_model_qualification_result(
        exact_model_id=candidate.exact_model_id,
        canonical_model_slug=candidate.canonical_model_slug,
        root_lineage=candidate.root_lineage or f"sha256:{_sha('synthetic-root')}",
        approved_provider_endpoint=candidate.approved_provider_endpoint,
        approved_provider_name=candidate.approved_provider_name,
        endpoint_snapshot_sha256=candidate.endpoint_snapshot_sha256,
        output_capability_sha256=candidate.output_capability_sha256 or _sha("output"),
        model_metadata_snapshot_sha256=candidate.model_metadata_snapshot_sha256,
        pricing_snapshot_sha256=candidate.pricing_snapshot_sha256,
        structured_output_mode=candidate.structured_output_mode,
        benchmark_report_sha256=report.report_sha256,
        benchmark_verification_sha256=_sha("independent-verification"),
        disposition=QualificationDisposition.TIER_A,
        dimensions=dimensions,
        overall_score=1.0,
        approved_roles=("judge", "source_audit"),
        evaluated_at=NOW,
        expires_at=NOW + timedelta(days=7),
    )
    bindings = QualificationBindings(
        source_commit="1" * 40,
        source_tree_sha256=_sha("source-tree"),
        effective_config_sha256=_sha("qualification-config"),
        prompt_sha256=_sha("prompt"),
        response_schema_sha256=_sha("schema"),
        toolchain_sha256=_sha("toolchain"),
        isolation_sha256=_sha("isolation"),
        benchmark_corpus_version=suite.corpus.schema_version,
        benchmark_corpus_sha256=suite.corpus_sha256,
        benchmark_ground_truth_version=suite.ground_truth.schema_version,
        benchmark_ground_truth_sha256=suite.ground_truth_sha256,
        benchmark_portfolio_sha256=_sha("portfolio"),
        candidate_registry_sha256=registry.registry_sha256,
        qualification_policy_sha256=policy_sha256,
    )
    return seal_model_qualification_artifact(
        created_at=NOW,
        bindings=bindings,
        results=(result,),
    )


@pytest.mark.asyncio
async def test_distinct_reasoning_profile_plan_executes_and_retains_live_authority(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    manifest, evidence, registry = fixtures._discovery_and_registry(
        tmp_path=tmp_path / "inputs",
        config=config,
        specs=(
            fixtures._CandidateSpec(
                model_id="alpha/atlas-secure",
                provider_endpoint="provider-alpha",
                provider_name="Provider Alpha",
            ),
        ),
    )
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    policy = load_qualification_policy(POLICY_PATH)
    budget = fixtures._budget(tmp_path / "ledger", config)
    usage = UsageLedger()
    primary_factory = fixtures._MockClientFactory()
    supplemental_factory = fixtures._MockClientFactory()
    try:
        primary = await run_candidate_registry_benchmarks(
            config=config,
            discovery_manifest=manifest,
            discovery_evidence=evidence,
            candidate_registry=registry,
            benchmark_suite=suite,
            budget=budget,
            usage=usage,
            operator_api_key="synthetic-secret",
            explicitly_allow_synthetic_egress=True,
            client_factory=primary_factory,
        )
        artifact = _qualification_artifact(
            candidate=registry.candidates[0],
            report=primary.reports[0],
            registry=registry,
            suite=suite,
            policy_sha256=policy.policy_sha256,
        )
        reasoning_policy = build_reasoning_policy(config)
        plan = build_candidate_reasoning_profile_benchmark_plan(
            artifact=artifact,
            primary_reports=primary.reports,
            reasoning_policy=reasoning_policy,
        )
        assert len(plan.routes) == 1
        route = plan.routes[0]
        assert route.request_role == "model_benchmark:judge:judge"
        assert route.control_profile.effort == "low"
        assert route.qualified_roles == ("judge",)

        assert budget.atomic_ledger is not None
        config_sha256 = canonical_sha256(config.model_dump(mode="json"))
        journal = create_candidate_reasoning_profile_benchmark_campaign(
            tmp_path / "reasoning-campaign",
            plan=plan,
            candidate_registry=registry,
            corpus=suite,
            effective_config_sha256=config_sha256,
            qualification_policy_sha256=policy.policy_sha256,
            cost_ledger=budget.atomic_ledger,
        )
        execution = await run_candidate_reasoning_profile_benchmarks(
            config=config,
            discovery_manifest=manifest,
            discovery_evidence=evidence,
            candidate_registry=registry,
            benchmark_suite=suite,
            plan=plan,
            budget=budget,
            usage=usage,
            operator_api_key="synthetic-secret",
            explicitly_allow_synthetic_egress=True,
            evidence_sink=journal,
            client_factory=supplemental_factory,
        )
    finally:
        await primary_factory.close()
        await supplemental_factory.close()

    assert tuple(item.route for item in execution.runs) == plan.routes
    assert all(
        result.target.request_role == route.request_role
        for report in execution.reports
        for result in report.results
    )
    assert execution.diagnostics[0].failure_stage is None
    assert supplemental_factory.request_bodies
    assert all(body["reasoning"]["effort"] == "low" for body in supplemental_factory.request_bodies)
    capability = issue_trusted_candidate_reasoning_profile_campaign_verification(
        campaign=journal,
        execution=execution,
    )
    capability.require_for(
        plan_sha256=plan.plan_sha256,
        reports=execution.reports,
        policy_sha256=policy.policy_sha256,
        effective_config_sha256=config_sha256,
    )
    verify_candidate_reasoning_profile_benchmark_campaign(
        journal.path,
        execution=execution,
        plan=plan,
        candidate_registry=registry,
        corpus=suite,
        effective_config_sha256=config_sha256,
        qualification_policy_sha256=policy.policy_sha256,
        cost_ledger=budget.atomic_ledger,
    )
    resumed = resume_candidate_reasoning_profile_benchmark_campaign(
        journal.path,
        plan=plan,
        candidate_registry=registry,
        corpus=suite,
        effective_config_sha256=config_sha256,
        qualification_policy_sha256=policy.policy_sha256,
        cost_ledger=budget.atomic_ledger,
    )
    assert resumed.runs == execution.runs
    with pytest.raises(ValueError, match="original live report"):
        issue_trusted_candidate_reasoning_profile_campaign_verification(
            campaign=resumed,
            execution=execution,
        )
    resumed_factory = fixtures._MockClientFactory()
    usage_count = len(usage.records)
    try:
        with pytest.raises(ValueError, match="lacks live runtime authority"):
            await run_candidate_reasoning_profile_benchmarks(
                config=config,
                discovery_manifest=manifest,
                discovery_evidence=evidence,
                candidate_registry=registry,
                benchmark_suite=suite,
                plan=plan,
                budget=budget,
                usage=usage,
                operator_api_key="synthetic-secret",
                explicitly_allow_synthetic_egress=True,
                evidence_sink=resumed,
                client_factory=resumed_factory,
            )
    finally:
        await resumed_factory.close()
    assert not resumed_factory.calls
    assert len(usage.records) == usage_count
    changed = execution.reports[0].model_copy(update={"report_sha256": "f" * 64})
    with pytest.raises(ValueError, match="does not bind qualification inputs"):
        capability.require_for(
            plan_sha256=plan.plan_sha256,
            reports=(changed,),
            policy_sha256=policy.policy_sha256,
            effective_config_sha256=config_sha256,
        )


def test_reasoning_campaign_authority_has_no_public_registrar() -> None:
    import mmaudit.benchmark.model_portfolio as module

    assert not hasattr(module, "_register_reasoning_campaign")
    assert not hasattr(module, "_reasoning_campaign_live_bindings")
