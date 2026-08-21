from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Never, cast

import pytest

import mmaudit.benchmark.model_portfolio as model_portfolio_module
from mmaudit.benchmark.model_portfolio import (
    TrustedCandidateBenchmarkCampaignVerification,
    create_candidate_benchmark_campaign,
    issue_trusted_candidate_benchmark_campaign_verification,
    load_model_benchmark_portfolio,
    resume_candidate_benchmark_campaign,
    revoke_trusted_candidate_benchmark_campaign_verification,
    seal_model_benchmark_portfolio_from_campaign,
)
from mmaudit.benchmark.models import ModelBenchmarkReport, load_model_benchmark_corpus
from mmaudit.config import AuditConfig
from mmaudit.models.candidate_benchmark import (
    CandidateBenchmarkRunState,
    run_candidate_registry_benchmarks,
)
from mmaudit.models.qualification import load_qualification_policy
from mmaudit.models.qualification_workflow import (
    validate_qualification_portfolio_readiness,
)
from mmaudit.models.schemas import UsageRecord
from mmaudit.models.usage import UsageLedger
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.privacy import PrivacyProfile
from tests.unit import test_candidate_benchmark as fixtures

ROOT = Path(__file__).parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
POLICY_PATH = ROOT / "config" / "models.maximum-assurance.toml"


def test_campaign_authority_exposes_no_raw_capability_registrar() -> None:
    assert not hasattr(model_portfolio_module, "_register_fresh_campaign_journal")
    assert not hasattr(model_portfolio_module, "_record_live_campaign_binding")
    assert not hasattr(model_portfolio_module, "_live_campaign_bindings")
    assert not hasattr(model_portfolio_module, "_register_trusted_campaign_capability")
    assert not hasattr(model_portfolio_module, "_TrustedCampaignCapabilityState")


def _config(config_factory: Callable[..., AuditConfig]) -> AuditConfig:
    return config_factory(
        execution={"max_requests_per_agent": 512},
        privacy={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK},
        models={"reasoning": {"effort": "high", "reserved_tokens": 4_096}},
    )


def _config_sha256(config: AuditConfig) -> str:
    return canonical_sha256(config.model_dump(mode="json"))


def _policy_sha256() -> str:
    return load_qualification_policy(POLICY_PATH).policy_sha256


@pytest.mark.asyncio
async def test_usage_then_raise_is_atomically_retained_with_retry_accounting(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(config_factory)
    model_id = "alpha/atlas-secure"
    manifest, evidence, registry = fixtures._discovery_and_registry(
        tmp_path=tmp_path / "inputs",
        config=config,
        specs=(
            fixtures._CandidateSpec(
                model_id=model_id,
                provider_endpoint="provider-alpha",
                provider_name="Provider Alpha",
            ),
        ),
    )
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    budget = fixtures._budget(tmp_path / "ledger", config)
    assert budget.atomic_ledger is not None
    journal = create_candidate_benchmark_campaign(
        tmp_path / "campaign",
        candidate_registry=registry,
        corpus=suite,
        effective_config_sha256=_config_sha256(config),
        qualification_policy_sha256=_policy_sha256(),
        cost_ledger=budget.atomic_ledger,
    )

    def usage_then_raise(**kwargs: Any) -> Never:
        usage = kwargs["usage"]
        candidate = kwargs["candidate"]
        request_budget = kwargs["budget"]
        assert isinstance(usage, UsageLedger)
        assert isinstance(request_budget, BudgetManager)
        assert request_budget.atomic_ledger is not None
        reservation = request_budget.atomic_ledger.reserve(
            "logical-request-with-retry",
            Decimal("0.02"),
        )
        request_budget.atomic_ledger.reconcile(reservation, Decimal("0.01"))
        usage.add(
            UsageRecord(
                request_id="logical-request-with-retry",
                role="model_benchmark",
                requested_model=candidate.exact_model_id,
                actual_model=candidate.exact_model_id,
                model_family=candidate.exact_model_id,
                timestamp=datetime(2026, 7, 28, 1, 0, tzinfo=UTC),
                routing={"selected_model": candidate.exact_model_id},
                prompt_sha256="a" * 64,
                reported_cost_usd=0.01,
                accounted_cost_usd=0.01,
                status="failed",
                attempts=2,
                retry_count=1,
            )
        )
        raise RuntimeError("synthetic terminal provider failure")

    result = await run_candidate_registry_benchmarks(
        config=config,
        discovery_manifest=manifest,
        discovery_evidence=evidence,
        candidate_registry=registry,
        benchmark_suite=suite,
        budget=budget,
        usage=UsageLedger(),
        operator_api_key="synthetic-secret",
        explicitly_allow_synthetic_egress=True,
        client_factory=usage_then_raise,
        evidence_sink=journal,
        qualification_policy=load_qualification_policy(POLICY_PATH),
    )

    diagnostic = result.diagnostics[0]
    assert diagnostic.state is CandidateBenchmarkRunState.UNVERIFIED_FAILURE
    assert diagnostic.requests_observed == 1
    assert diagnostic.provider_attempt_count == 2
    assert diagnostic.retry_count == 1
    assert diagnostic.failed_request_count == 1
    assert diagnostic.unresolved_cost_count == 0
    assert diagnostic.cost_ledger_after is not None
    assert diagnostic.cost_ledger_after.spent_usd == "0.01"
    assert diagnostic.cost_ledger_after.active_reserved_usd == "0"
    assert diagnostic.cost_ledger_after.reconciled_count == 1
    portfolio = seal_model_benchmark_portfolio_from_campaign(
        tmp_path / "portfolio",
        campaign=journal,
    )
    capability = issue_trusted_candidate_benchmark_campaign_verification(
        campaign=journal,
        portfolio=portfolio,
        reports=result.reports,
    )
    capability.require_for(
        portfolio_sha256=portfolio.portfolio_sha256,
        reports=result.reports,
        policy_sha256=_policy_sha256(),
        effective_config_sha256=_config_sha256(config),
    )

    forged = object.__new__(TrustedCandidateBenchmarkCampaignVerification)
    with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
        revoke_trusted_candidate_benchmark_campaign_verification(forged)
    with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
        revoke_trusted_candidate_benchmark_campaign_verification(
            cast(TrustedCandidateBenchmarkCampaignVerification, object())
        )
    capability.require_for(
        portfolio_sha256=portfolio.portfolio_sha256,
        reports=result.reports,
        policy_sha256=_policy_sha256(),
        effective_config_sha256=_config_sha256(config),
    )

    pristine_capability = issue_trusted_candidate_benchmark_campaign_verification(
        campaign=journal,
        portfolio=portfolio,
        reports=result.reports,
    )
    revoke_for_result = cast(
        Callable[[TrustedCandidateBenchmarkCampaignVerification], object],
        revoke_trusted_candidate_benchmark_campaign_verification,
    )
    assert revoke_for_result(pristine_capability) is None
    with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
        pristine_capability.require_for(
            portfolio_sha256=portfolio.portfolio_sha256,
            reports=result.reports,
            policy_sha256=_policy_sha256(),
            effective_config_sha256=_config_sha256(config),
        )

    trusted_revoke = revoke_trusted_candidate_benchmark_campaign_verification
    for binding_name in (
        "TrustedCandidateBenchmarkCampaignVerification",
        "_revoke_trusted_campaign_capability",
        "_require_trusted_campaign_capability",
        "_require_trusted_campaign_capability_positional",
        "_report_content_bindings",
        "create_candidate_benchmark_campaign",
        "issue_trusted_candidate_benchmark_campaign_verification",
        "revoke_trusted_candidate_benchmark_campaign_verification",
    ):
        retargeted = issue_trusted_candidate_benchmark_campaign_verification(
            campaign=journal,
            portfolio=portfolio,
            reports=result.reports,
        )
        retained = retargeted
        with monkeypatch.context() as binding_patch:
            binding_patch.setattr(model_portfolio_module, binding_name, object())
            with pytest.raises(ValueError, match="revocation runtime is not pristine"):
                trusted_revoke(retargeted)
        assert retained is retargeted
        with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
            retained.require_for(
                portfolio_sha256=portfolio.portfolio_sha256,
                reports=result.reports,
                policy_sha256=_policy_sha256(),
                effective_config_sha256=_config_sha256(config),
            )

    method_retargeted = issue_trusted_candidate_benchmark_campaign_verification(
        campaign=journal,
        portfolio=portfolio,
        reports=result.reports,
    )
    with monkeypatch.context() as binding_patch:
        binding_patch.setattr(
            TrustedCandidateBenchmarkCampaignVerification,
            "require_for",
            lambda *_args, **_kwargs: None,
        )
        with pytest.raises(ValueError, match="revocation runtime is not pristine"):
            trusted_revoke(method_retargeted)
    with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
        method_retargeted.require_for(
            portfolio_sha256=portfolio.portfolio_sha256,
            reports=result.reports,
            policy_sha256=_policy_sha256(),
            effective_config_sha256=_config_sha256(config),
        )

    if hasattr(os, "fork"):
        child_pid = os.fork()
        if child_pid == 0:
            child_status = 1
            try:
                with pytest.raises(ValueError, match="belongs to another process"):
                    capability.require_for(
                        portfolio_sha256=portfolio.portfolio_sha256,
                        reports=result.reports,
                        policy_sha256=_policy_sha256(),
                        effective_config_sha256=_config_sha256(config),
                    )
                with pytest.raises(ValueError, match="belongs to another process"):
                    revoke_trusted_candidate_benchmark_campaign_verification(capability)
                with pytest.raises(ValueError, match="belongs to another process"):
                    issue_trusted_candidate_benchmark_campaign_verification(
                        campaign=journal,
                        portfolio=portfolio,
                        reports=result.reports,
                    )
                child_status = 0
            finally:
                os._exit(child_status)
        waited_pid, wait_status = os.waitpid(child_pid, 0)
        assert waited_pid == child_pid
        assert os.waitstatus_to_exitcode(wait_status) == 0
    capability.require_for(
        portfolio_sha256=portfolio.portfolio_sha256,
        reports=result.reports,
        policy_sha256=_policy_sha256(),
        effective_config_sha256=_config_sha256(config),
    )

    validation_started = threading.Event()
    continue_validation = threading.Event()
    validation_failures: list[str] = []
    actual_report_bindings = model_portfolio_module._report_content_bindings

    def delayed_report_bindings(
        reports: tuple[ModelBenchmarkReport, ...],
    ) -> tuple[tuple[str, str], ...]:
        validation_started.set()
        if not continue_validation.wait(timeout=5):
            raise RuntimeError("campaign verification race test timed out")
        return actual_report_bindings(reports)

    monkeypatch.setattr(
        model_portfolio_module,
        "_report_content_bindings",
        delayed_report_bindings,
    )

    def finish_validation() -> None:
        try:
            capability.require_for(
                portfolio_sha256=portfolio.portfolio_sha256,
                reports=result.reports,
                policy_sha256=_policy_sha256(),
                effective_config_sha256=_config_sha256(config),
            )
        except ValueError as exc:
            validation_failures.append(str(exc))

    validation = threading.Thread(target=finish_validation)
    validation.start()
    assert validation_started.wait(timeout=5)
    revoke = cast(
        Callable[[TrustedCandidateBenchmarkCampaignVerification], object],
        revoke_trusted_candidate_benchmark_campaign_verification,
    )
    with pytest.raises(ValueError, match="revocation runtime is not pristine"):
        revoke(capability)
    continue_validation.set()
    validation.join(timeout=5)
    monkeypatch.setattr(
        model_portfolio_module,
        "_report_content_bindings",
        actual_report_bindings,
    )

    assert not validation.is_alive()
    assert validation_failures == [
        "trusted campaign verification changed or was revoked during validation"
    ]
    with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
        capability.require_for(
            portfolio_sha256=portfolio.portfolio_sha256,
            reports=result.reports,
            policy_sha256=_policy_sha256(),
            effective_config_sha256=_config_sha256(config),
        )
    with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
        revoke_trusted_candidate_benchmark_campaign_verification(capability)

    resumed = resume_candidate_benchmark_campaign(
        journal.path,
        candidate_registry=registry,
        corpus=suite,
        effective_config_sha256=_config_sha256(config),
        qualification_policy_sha256=_policy_sha256(),
        cost_ledger=budget.atomic_ledger,
    )
    assert resumed.reports == result.reports
    assert resumed.diagnostics == result.diagnostics
    resumed._live_content_bindings = [  # type: ignore[attr-defined]
        report.report_sha256 for report in result.reports
    ]
    with pytest.raises(ValueError, match="original runtime-attested report"):
        issue_trusted_candidate_benchmark_campaign_verification(
            campaign=resumed,
            portfolio=portfolio,
            reports=result.reports,
        )
    loaded, _reports = load_model_benchmark_portfolio(
        tmp_path / "portfolio",
        candidate_registry=registry,
        corpus=suite,
    )
    assert loaded == portfolio
    assert portfolio.usage.logical_request_count == 1
    assert portfolio.usage.provider_attempt_count == 2
    assert portfolio.usage.retry_count == 1
    assert portfolio.usage.failed_request_count == 1
    assert portfolio.usage.accounted_cost_usd == "0.01"
    assert portfolio.campaign_journal_sha256 == resumed.journal_sha256
    assert portfolio.qualification_policy_sha256 == _policy_sha256()
    assert portfolio.cost_ledger_snapshot == resumed.final_cost_ledger_snapshot


@pytest.mark.asyncio
async def test_two_uncertain_attempts_are_durable_and_fail_qualification(
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
    assert budget.atomic_ledger is not None
    journal = create_candidate_benchmark_campaign(
        tmp_path / "campaign",
        candidate_registry=registry,
        corpus=suite,
        effective_config_sha256=_config_sha256(config),
        qualification_policy_sha256=policy.policy_sha256,
        cost_ledger=budget.atomic_ledger,
    )

    def two_uncertain_attempts(**kwargs: Any) -> Never:
        usage = kwargs["usage"]
        candidate = kwargs["candidate"]
        request_budget = kwargs["budget"]
        assert isinstance(usage, UsageLedger)
        assert isinstance(request_budget, BudgetManager)
        assert request_budget.atomic_ledger is not None
        for attempt in (1, 2):
            reservation = request_budget.atomic_ledger.reserve(
                f"uncertain-attempt-{attempt}",
                Decimal("0.01"),
            )
            request_budget.atomic_ledger.reconcile(reservation, None)
        usage.add(
            UsageRecord(
                request_id="logical-uncertain-request",
                role="model_benchmark",
                requested_model=candidate.exact_model_id,
                actual_model=candidate.exact_model_id,
                model_family=candidate.exact_model_id,
                timestamp=datetime(2026, 7, 28, 1, 0, tzinfo=UTC),
                routing={"selected_model": candidate.exact_model_id},
                prompt_sha256="b" * 64,
                accounted_cost_usd=0.02,
                status="failed",
                attempts=2,
                retry_count=1,
            )
        )
        raise RuntimeError("synthetic terminal timeout with unknown provider cost")

    result = await run_candidate_registry_benchmarks(
        config=config,
        discovery_manifest=manifest,
        discovery_evidence=evidence,
        candidate_registry=registry,
        benchmark_suite=suite,
        budget=budget,
        usage=UsageLedger(),
        operator_api_key="synthetic-secret",
        explicitly_allow_synthetic_egress=True,
        client_factory=two_uncertain_attempts,
        evidence_sink=journal,
        qualification_policy=policy,
    )

    diagnostic = result.diagnostics[0]
    assert diagnostic.provider_attempt_count == 2
    assert diagnostic.unresolved_cost_count == 2
    assert diagnostic.cost_ledger_after is not None
    assert diagnostic.cost_ledger_after.uncertain_accounted_count == 2
    assert diagnostic.cost_ledger_after.active_reserved_usd == "0"
    resumed = resume_candidate_benchmark_campaign(
        journal.path,
        candidate_registry=registry,
        corpus=suite,
        effective_config_sha256=_config_sha256(config),
        qualification_policy_sha256=policy.policy_sha256,
        cost_ledger=budget.atomic_ledger,
    )
    portfolio = seal_model_benchmark_portfolio_from_campaign(
        tmp_path / "portfolio",
        campaign=resumed,
    )
    assert portfolio.usage.logical_request_count == 1
    assert portfolio.usage.provider_attempt_count == 2
    assert portfolio.usage.unresolved_cost_count == 2
    with pytest.raises(ValueError, match="reconciled"):
        validate_qualification_portfolio_readiness(
            portfolio=portfolio,
            policy=policy,
        )


@pytest.mark.asyncio
async def test_second_candidate_interrupt_preserves_first_entry_and_ledger(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    specs = (
        fixtures._CandidateSpec(
            model_id="alpha/atlas-secure",
            provider_endpoint="provider-alpha",
            provider_name="Provider Alpha",
        ),
        fixtures._CandidateSpec(
            model_id="bravo/borealis-secure",
            provider_endpoint="provider-bravo",
            provider_name="Provider Bravo",
        ),
    )
    manifest, evidence, registry = fixtures._discovery_and_registry(
        tmp_path=tmp_path / "inputs",
        config=config,
        specs=specs,
    )
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    budget = fixtures._budget(tmp_path / "ledger", config)
    assert budget.atomic_ledger is not None
    journal = create_candidate_benchmark_campaign(
        tmp_path / "campaign",
        candidate_registry=registry,
        corpus=suite,
        effective_config_sha256=_config_sha256(config),
        qualification_policy_sha256=_policy_sha256(),
        cost_ledger=budget.atomic_ledger,
    )
    delegate = fixtures._MockClientFactory()

    def interrupt_second(**kwargs: Any) -> Any:
        if kwargs["candidate"].exact_model_id == specs[1].model_id:
            raise KeyboardInterrupt
        return delegate(**kwargs)

    with pytest.raises(KeyboardInterrupt):
        await run_candidate_registry_benchmarks(
            config=config,
            discovery_manifest=manifest,
            discovery_evidence=evidence,
            candidate_registry=registry,
            benchmark_suite=suite,
            budget=budget,
            usage=UsageLedger(),
            operator_api_key="synthetic-secret",
            explicitly_allow_synthetic_egress=True,
            client_factory=interrupt_second,
            evidence_sink=journal,
            qualification_policy=load_qualification_policy(POLICY_PATH),
        )

    resumed = resume_candidate_benchmark_campaign(
        journal.path,
        candidate_registry=registry,
        corpus=suite,
        effective_config_sha256=_config_sha256(config),
        qualification_policy_sha256=_policy_sha256(),
        cost_ledger=budget.atomic_ledger,
    )
    assert len(resumed.reports) == 1
    assert resumed.reports[0].results[0].target.model_id == specs[0].model_id
    assert resumed.diagnostics[0].cost_ledger_after == resumed.final_cost_ledger_snapshot
    assert resumed.final_cost_ledger_snapshot.entry_count > 0
    with pytest.raises(ValueError, match="exact-set"):
        seal_model_benchmark_portfolio_from_campaign(
            tmp_path / "incomplete-portfolio",
            campaign=resumed,
        )


def test_resume_rejects_tampering_links_and_wrong_bindings(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    _manifest, _evidence, registry = fixtures._discovery_and_registry(
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

    def new_campaign(name: str) -> tuple[Path, AtomicCostLedger]:
        budget = fixtures._budget(tmp_path / f"ledger-{name}", config)
        assert budget.atomic_ledger is not None
        path = tmp_path / f"campaign-{name}"
        create_candidate_benchmark_campaign(
            path,
            candidate_registry=registry,
            corpus=suite,
            effective_config_sha256=_config_sha256(config),
            qualification_policy_sha256=_policy_sha256(),
            cost_ledger=budget.atomic_ledger,
        )
        return path, budget.atomic_ledger

    wrong_path, wrong_ledger = new_campaign("wrong")
    with pytest.raises(ValueError, match="fresh"):
        create_candidate_benchmark_campaign(
            wrong_path,
            candidate_registry=registry,
            corpus=suite,
            effective_config_sha256=_config_sha256(config),
            qualification_policy_sha256=_policy_sha256(),
            cost_ledger=wrong_ledger,
        )
    with pytest.raises(ValueError, match="bindings"):
        resume_candidate_benchmark_campaign(
            wrong_path,
            candidate_registry=registry,
            corpus=suite,
            effective_config_sha256="f" * 64,
            qualification_policy_sha256=_policy_sha256(),
            cost_ledger=wrong_ledger,
        )
    other_budget = fixtures._budget(tmp_path / "different-ledger", config)
    assert other_budget.atomic_ledger is not None
    with pytest.raises(ValueError, match="bindings"):
        resume_candidate_benchmark_campaign(
            wrong_path,
            candidate_registry=registry,
            corpus=suite,
            effective_config_sha256=_config_sha256(config),
            qualification_policy_sha256=_policy_sha256(),
            cost_ledger=other_budget.atomic_ledger,
        )
    with pytest.raises(ValueError, match="bindings"):
        resume_candidate_benchmark_campaign(
            wrong_path,
            candidate_registry=registry,
            corpus=suite,
            effective_config_sha256=_config_sha256(config),
            qualification_policy_sha256="d" * 64,
            cost_ledger=wrong_ledger,
        )

    tampered_path, tampered_ledger = new_campaign("tampered")
    manifest_path = tampered_path / "candidate-benchmark-campaign.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["effective_config_sha256"] = "e" * 64
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    manifest_path.chmod(0o600)
    with pytest.raises(ValueError):
        resume_candidate_benchmark_campaign(
            tampered_path,
            candidate_registry=registry,
            corpus=suite,
            effective_config_sha256=_config_sha256(config),
            qualification_policy_sha256=_policy_sha256(),
            cost_ledger=tampered_ledger,
        )

    linked_path, linked_ledger = new_campaign("linked")
    linked_manifest = linked_path / "candidate-benchmark-campaign.json"
    outside = tmp_path / "outside.json"
    outside.write_bytes(linked_manifest.read_bytes())
    outside.chmod(0o600)
    linked_manifest.unlink()
    try:
        linked_manifest.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError):
        resume_candidate_benchmark_campaign(
            linked_path,
            candidate_registry=registry,
            corpus=suite,
            effective_config_sha256=_config_sha256(config),
            qualification_policy_sha256=_policy_sha256(),
            cost_ledger=linked_ledger,
        )
