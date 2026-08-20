from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest

from mmaudit.config import AuditConfig
from mmaudit.models.policy_selection import (
    AUDIT_MODEL_SELECTION_EVIDENCE_FILENAME,
    AuditModelSelectionEvidenceBundle,
)
from mmaudit.models.refresh_runtime import (
    AUDIT_MODEL_REFRESH_EVIDENCE_FILENAME,
    AUDIT_MODEL_REFRESH_PRICING_EVIDENCE_FILENAME,
    AuditModelRefreshEvidence,
    AuditModelRefreshPricingEvidence,
)
from mmaudit.models.schemas import AuditProfile, ExecutionEvidenceKind
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.pipeline import (
    AuditPipeline,
    _policy_selected_auxiliary_config,
    _refresh_latest_artifact,
    _require_policy_selected_scheduled_model,
    _whole_protocol_review_models,
)
from tests.conftest import MODEL_IDS, base_config_data, model_registry_entry
from tests.qualification_support import synthetic_production_qualification
from tests.refresh_runtime_support import SyntheticRefreshRuntime, synthetic_refresh_runtime
from tests.unit.test_model_policy_selection import (
    BASE_TIME,
    _hash,
    _policy_authority,
    _policy_bundle,
    _PolicyBundle,
    _resolve,
    _technical_qualification,
)


def _selection_config() -> AuditConfig:
    data = base_config_data()
    base_ids = tuple(MODEL_IDS.values())
    extra_ids = (
        "golf/glacier-secure",
        "hotel/harbor-secure",
        "india/ion-secure",
    )
    model_ids = (*base_ids, *extra_ids)
    roots = tuple(f"sha256:{_hash(f'root-{index}')}" for index in range(6))
    data["privacy"]["approved_model_lineages"] = list(roots)
    data["models"]["registry"] = [
        model_registry_entry(
            model_id,
            root_lineage=roots[index] if index < 6 else roots[index - 6],
        )
        for index, model_id in enumerate(model_ids)
    ]
    data["models"]["specialists"] = {
        "access_control": {"primary": extra_ids[0], "fallbacks": []},
        "false_negative_hunter": {"primary": extra_ids[1], "fallbacks": []},
        "report_quality": {"primary": extra_ids[2], "fallbacks": []},
    }
    return AuditConfig.model_validate(data)


def _pipeline(
    tmp_path: Path,
    *,
    excluded_ids: frozenset[str] = frozenset(),
) -> tuple[AuditPipeline, _PolicyBundle]:
    technical = _technical_qualification()
    policy = _policy_bundle(technical, excluded_ids=excluded_ids)
    authority = _policy_authority(tmp_path / "authority", policy)
    _selection, evidence, capability = _resolve(technical, policy, authority)
    config = _selection_config()
    assert technical.production_effective_config_sha256 == config.stable_hash()
    repository = tmp_path / "repository"
    repository.mkdir()
    pipeline = AuditPipeline(
        config,
        repo=repository,
        output=tmp_path / "output",
        production_qualification=technical,
        audit_model_selection_evidence=evidence,
        verified_audit_model_selection=capability,
    )
    return pipeline, policy


def _refresh_pipeline(
    tmp_path: Path,
    *,
    include_refresh_evidence: bool = True,
    include_refresh_guard: bool = True,
    include_pricing_evidence: bool = True,
    include_pricing_authority: bool = True,
    paid: bool = False,
) -> tuple[AuditPipeline, SyntheticRefreshRuntime]:
    refresh = synthetic_refresh_runtime(tmp_path / "refresh-authority")
    repository = tmp_path / "refresh-repository"
    repository.mkdir()
    pipeline = AuditPipeline(
        refresh.config,
        repo=repository,
        output=tmp_path / "refresh-output",
        production_qualification=refresh.technical_qualification,
        audit_model_selection_evidence=refresh.audit_selection_evidence,
        verified_audit_model_selection=refresh.audit_selection,
        audit_model_refresh_evidence=(refresh.evidence if include_refresh_evidence else None),
        audit_model_refresh_guard=refresh.guard if include_refresh_guard else None,
        audit_model_refresh_pricing_evidence=(
            refresh.pricing_evidence if include_pricing_evidence else None
        ),
        audit_model_refresh_pricing_authority=(
            refresh.pricing_authority if include_pricing_authority else None
        ),
        api_key="synthetic-nonempty-credential" if paid else None,
        cost_ledger=(
            AtomicCostLedger.initialize(
                tmp_path / "refresh-cost-ledger.json",
                cap_usd=Decimal(str(refresh.config.execution.budget_usd)),
            )
            if paid
            else None
        ),
    )
    return pipeline, refresh


@pytest.mark.asyncio
async def test_real_paid_pipeline_requires_policy_selection_before_run_artifacts(
    tmp_path: Path,
) -> None:
    config = _selection_config()
    repository = tmp_path / "repository"
    repository.mkdir()
    output = tmp_path / "output"
    pipeline = AuditPipeline(
        config,
        repo=repository,
        output=output,
        production_qualification=synthetic_production_qualification(
            config,
            datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=1),
            provider_endpoint="openrouter/provider-a",
            provider_name="Synthetic Provider",
        ),
        api_key="synthetic-nonempty-credential",
        cost_ledger=AtomicCostLedger.initialize(
            tmp_path / "cost-ledger.json",
            cap_usd=Decimal(str(config.execution.budget_usd)),
        ),
    )

    with pytest.raises(ValueError, match="real paid audit requires exact model-selection"):
        await pipeline.run(allow_code_egress=True)

    assert not output.exists()
    assert pipeline.client is None


def test_pipeline_requires_atomic_model_refresh_evidence_and_guard(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="evidence and live guard must be supplied together"):
        _refresh_pipeline(
            tmp_path,
            include_refresh_guard=False,
            include_pricing_evidence=False,
            include_pricing_authority=False,
        )


def test_pipeline_requires_atomic_model_refresh_pricing_evidence_and_authority(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ValueError,
        match="pricing evidence and live authority must be supplied together",
    ):
        _refresh_pipeline(tmp_path, include_pricing_authority=False)


@pytest.mark.asyncio
async def test_real_paid_pipeline_requires_model_refresh_before_run_artifacts(
    tmp_path: Path,
) -> None:
    pipeline, _refresh = _refresh_pipeline(
        tmp_path,
        include_refresh_evidence=False,
        include_refresh_guard=False,
        include_pricing_evidence=False,
        include_pricing_authority=False,
        paid=True,
    )

    with pytest.raises(
        ValueError,
        match="paid REAL provider audits require model-refresh evidence and a live guard",
    ):
        await pipeline.run(allow_code_egress=True)

    assert not pipeline.output.exists()
    assert pipeline.client is None


@pytest.mark.asyncio
async def test_real_paid_pipeline_requires_refresh_pricing_before_run_artifacts(
    tmp_path: Path,
) -> None:
    pipeline, _refresh = _refresh_pipeline(
        tmp_path,
        include_pricing_evidence=False,
        include_pricing_authority=False,
        paid=True,
    )

    with pytest.raises(
        ValueError,
        match="paid REAL provider audits require refreshed-pricing evidence and live authority",
    ):
        await pipeline.run(allow_code_egress=True)

    assert not pipeline.output.exists()
    assert pipeline.client is None


@pytest.mark.asyncio
async def test_scanner_only_pipeline_rejects_model_refresh_custody_without_policy_pair(
    tmp_path: Path,
) -> None:
    refresh = synthetic_refresh_runtime(tmp_path / "refresh-authority")
    repository = tmp_path / "refresh-repository"
    repository.mkdir()
    pipeline = AuditPipeline(
        refresh.config,
        repo=repository,
        output=tmp_path / "refresh-output",
        production_qualification=refresh.technical_qualification,
        audit_model_refresh_evidence=refresh.evidence,
        audit_model_refresh_guard=refresh.guard,
    )

    with pytest.raises(
        ValueError,
        match="audit model-refresh custody is accepted only for paid REAL provider audits",
    ):
        await pipeline.run(scanner_only=True)


@pytest.mark.asyncio
async def test_non_real_pipeline_rejects_model_refresh_custody_without_policy_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refresh = synthetic_refresh_runtime(tmp_path / "refresh-authority")
    repository = tmp_path / "refresh-repository"
    repository.mkdir()
    pipeline = AuditPipeline(
        refresh.config,
        repo=repository,
        output=tmp_path / "refresh-output",
        production_qualification=refresh.technical_qualification,
        audit_model_refresh_evidence=refresh.evidence,
        audit_model_refresh_guard=refresh.guard,
    )
    monkeypatch.setattr(
        pipeline,
        "_planned_model_execution_evidence",
        lambda: ExecutionEvidenceKind.MOCK,
    )

    with pytest.raises(
        ValueError,
        match="audit model-refresh custody is accepted only for paid REAL provider audits",
    ):
        await pipeline.run()


@pytest.mark.asyncio
@pytest.mark.parametrize("scanner_only", (True, False), ids=("scanner", "non-real"))
async def test_nonpaid_pipeline_rejects_refresh_pricing_custody(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scanner_only: bool,
) -> None:
    refresh = synthetic_refresh_runtime(tmp_path / "refresh-pricing-authority")
    repository = tmp_path / "refresh-pricing-repository"
    repository.mkdir()
    pipeline = AuditPipeline(
        refresh.config,
        repo=repository,
        output=tmp_path / "refresh-pricing-output",
        production_qualification=refresh.technical_qualification,
        audit_model_refresh_evidence=refresh.evidence,
        audit_model_refresh_guard=refresh.guard,
        audit_model_refresh_pricing_evidence=refresh.pricing_evidence,
        audit_model_refresh_pricing_authority=refresh.pricing_authority,
    )
    if not scanner_only:
        monkeypatch.setattr(
            pipeline,
            "_planned_model_execution_evidence",
            lambda: ExecutionEvidenceKind.MOCK,
        )

    with pytest.raises(
        ValueError,
        match="refresh pricing custody is accepted only for paid REAL provider audits",
    ):
        await pipeline.run(scanner_only=scanner_only)


@pytest.mark.asyncio
async def test_scanner_only_pipeline_rejects_supplied_paid_audit_policy_authority(
    tmp_path: Path,
) -> None:
    pipeline, _policy = _pipeline(tmp_path)

    with pytest.raises(
        ValueError,
        match="audit model-selection evidence is accepted only for paid REAL provider audits",
    ):
        await pipeline.run(scanner_only=True)


@pytest.mark.asyncio
async def test_non_real_pipeline_rejects_supplied_paid_audit_policy_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline, _policy = _pipeline(tmp_path)
    monkeypatch.setattr(
        pipeline,
        "_planned_model_execution_evidence",
        lambda: ExecutionEvidenceKind.MOCK,
    )

    with pytest.raises(
        ValueError,
        match="audit model-selection evidence is accepted only for paid REAL provider audits",
    ):
        await pipeline.run()


@pytest.mark.asyncio
async def test_policy_free_non_real_pipeline_passes_policy_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _selection_config()
    repository = tmp_path / "repository"
    repository.mkdir()
    pipeline = AuditPipeline(
        config,
        repo=repository,
        output=tmp_path / "output",
    )
    monkeypatch.setattr(
        pipeline,
        "_planned_model_execution_evidence",
        lambda: ExecutionEvidenceKind.MOCK,
    )

    with pytest.raises(
        ValueError,
        match="provider audits require an explicit existing cumulative cost ledger",
    ):
        await pipeline.run()


def test_pipeline_rechecks_exact_selection_and_frozen_source(tmp_path: Path) -> None:
    pipeline, policy = _pipeline(tmp_path)

    selected = pipeline._require_current_audit_model_selection(
        now=BASE_TIME + timedelta(hours=2),
        expected_source_sha256=policy.audit_context.source_sha256,
    )

    assert pipeline.audit_model_selection_evidence is not None
    assert selected == frozenset(
        pipeline.audit_model_selection_evidence.selection.selected_model_ids
    )
    with pytest.raises(ValueError, match="frozen repository map"):
        pipeline._require_current_audit_model_selection(
            now=BASE_TIME + timedelta(hours=2),
            expected_source_sha256=_hash("different-frozen-source"),
        )


def test_policy_evidence_persistence_and_latest_projection_are_exact(tmp_path: Path) -> None:
    pipeline, policy = _pipeline(tmp_path)
    run_dir = tmp_path / "run-with-policy"
    run_dir.mkdir()

    selected = pipeline._persist_current_audit_model_selection_evidence(
        run_dir=run_dir,
        now=BASE_TIME + timedelta(hours=2),
        expected_source_sha256=policy.audit_context.source_sha256,
    )
    artifact = run_dir / AUDIT_MODEL_SELECTION_EVIDENCE_FILENAME
    observed = AuditModelSelectionEvidenceBundle.model_validate_json(
        artifact.read_text(encoding="utf-8"),
        strict=True,
    )

    assert pipeline.audit_model_selection_evidence is not None
    assert observed == pipeline.audit_model_selection_evidence
    assert observed.technical_evidence_mode == "EXTERNAL_AUTHORITY_HASH_JOIN_REQUIRED"
    assert selected == frozenset(observed.selection.selected_model_ids)

    latest = tmp_path / "latest"
    latest.mkdir()
    _refresh_latest_artifact(
        run_dir=run_dir,
        latest=latest,
        filename=AUDIT_MODEL_SELECTION_EVIDENCE_FILENAME,
    )
    latest_artifact = latest / AUDIT_MODEL_SELECTION_EVIDENCE_FILENAME
    assert latest_artifact.read_bytes() == artifact.read_bytes()

    subsequent_run = tmp_path / "run-without-policy"
    subsequent_run.mkdir()
    _refresh_latest_artifact(
        run_dir=subsequent_run,
        latest=latest,
        filename=AUDIT_MODEL_SELECTION_EVIDENCE_FILENAME,
    )
    assert not latest_artifact.exists()


def test_refresh_evidence_persistence_is_canonical_and_non_authorizing(tmp_path: Path) -> None:
    pipeline, refresh = _refresh_pipeline(tmp_path)
    run_dir = tmp_path / "run-with-refresh"
    run_dir.mkdir()

    observed = pipeline._require_current_audit_model_refresh(
        now=refresh.verified_at,
        expected_source_sha256=refresh.evidence.source_sha256,
    )
    pipeline._persist_current_audit_model_refresh_evidence(
        run_dir=run_dir,
        now=refresh.verified_at,
        expected_source_sha256=refresh.evidence.source_sha256,
    )
    artifact = run_dir / AUDIT_MODEL_REFRESH_EVIDENCE_FILENAME
    persisted = AuditModelRefreshEvidence.model_validate_json(
        artifact.read_text(encoding="utf-8"),
        strict=True,
    )

    assert observed == refresh.evidence
    assert persisted == refresh.evidence
    assert not persisted.technical_selection_authorized
    assert not persisted.audit_selection_authorized
    assert not persisted.provider_access_authorized
    assert not persisted.production_promotion_authorized
    assert refresh.guard.capability_sha256 not in artifact.read_text(encoding="utf-8")


def test_refresh_pricing_persistence_is_canonical_and_non_authorizing(tmp_path: Path) -> None:
    pipeline, refresh = _refresh_pipeline(tmp_path)
    run_dir = tmp_path / "run-with-refresh-pricing"
    run_dir.mkdir()

    observed = pipeline._require_current_audit_model_refresh_pricing(
        now=refresh.verified_at,
        expected_source_sha256=refresh.pricing_evidence.source_sha256,
    )
    pipeline._persist_current_audit_model_refresh_pricing_evidence(
        run_dir=run_dir,
        now=refresh.verified_at,
        expected_source_sha256=refresh.pricing_evidence.source_sha256,
    )
    artifact = run_dir / AUDIT_MODEL_REFRESH_PRICING_EVIDENCE_FILENAME
    persisted = AuditModelRefreshPricingEvidence.model_validate_json(
        artifact.read_text(encoding="utf-8"),
        strict=True,
    )

    assert observed == refresh.pricing_evidence
    assert persisted == refresh.pricing_evidence
    assert not persisted.pricing_use_authorized
    assert not persisted.technical_selection_authorized
    assert not persisted.audit_selection_authorized
    assert not persisted.provider_access_authorized
    assert not persisted.production_promotion_authorized
    assert refresh.pricing_authority.capability_sha256 not in artifact.read_text(encoding="utf-8")


def test_pipeline_rejects_policy_excluded_configured_primary(tmp_path: Path) -> None:
    technical = _technical_qualification()
    excluded_id = _selection_config().models.threat_model.primary
    policy = _policy_bundle(technical, excluded_ids=frozenset({excluded_id}))
    authority = _policy_authority(tmp_path / "authority", policy)
    _selection, evidence, capability = _resolve(technical, policy, authority)
    repository = tmp_path / "repository"
    repository.mkdir()
    pipeline = AuditPipeline(
        _selection_config(),
        repo=repository,
        output=tmp_path / "output",
        production_qualification=technical,
        audit_model_selection_evidence=evidence,
        verified_audit_model_selection=capability,
    )

    with pytest.raises(ValueError, match=r"configured role primary.*policy eligibility"):
        pipeline._require_current_audit_model_selection(
            now=BASE_TIME + timedelta(hours=2),
            expected_source_sha256=policy.audit_context.source_sha256,
        )


def test_dormant_standard_specialist_is_not_a_universal_policy_gate(
    tmp_path: Path,
) -> None:
    technical = _technical_qualification()
    config = _selection_config()
    excluded_id = config.models.specialists["report_quality"].primary
    policy = _policy_bundle(technical, excluded_ids=frozenset({excluded_id}))
    authority = _policy_authority(tmp_path / "authority", policy)
    _selection, evidence, capability = _resolve(technical, policy, authority)
    repository = tmp_path / "repository"
    repository.mkdir()
    pipeline = AuditPipeline(
        config,
        repo=repository,
        output=tmp_path / "output",
        production_qualification=technical,
        audit_model_selection_evidence=evidence,
        verified_audit_model_selection=capability,
    )

    selected = pipeline._require_current_audit_model_selection(
        now=BASE_TIME + timedelta(hours=2),
        expected_source_sha256=policy.audit_context.source_sha256,
    )

    assert excluded_id not in selected
    with pytest.raises(ValueError, match="scheduled role specialist:report_quality"):
        _require_policy_selected_scheduled_model(
            selected_model_ids=selected,
            request_role="specialist:report_quality",
            model_id=excluded_id,
        )


def test_auxiliary_model_pools_filter_policy_exclusions_without_score_changes() -> None:
    config = _selection_config()
    excluded_id = config.models.specialists["report_quality"].primary
    verifier = config.models.verifier.model_copy(update={"fallbacks": [excluded_id]})
    config = config.model_copy(
        update={
            "models": config.models.model_copy(update={"verifier": verifier}),
        }
    )
    selected_ids = frozenset(
        model_id
        for model_id in {
            *MODEL_IDS.values(),
            *(configured.primary for configured in config.models.specialists.values()),
        }
        if model_id != excluded_id
    )

    filtered = _policy_selected_auxiliary_config(
        config,
        selected_model_ids=selected_ids,
    )

    assert config.models.verifier.fallbacks == [excluded_id]
    assert filtered.models.verifier.fallbacks == []
    assert "report_quality" not in filtered.models.specialists
    assert filtered.models.registry == config.models.registry
    assert tuple(entry.measured_quality for entry in filtered.models.registry) == tuple(
        entry.measured_quality for entry in config.models.registry
    )


def test_whole_protocol_pool_uses_only_policy_selected_models() -> None:
    config = _selection_config().model_copy(update={"profile": AuditProfile.MAXIMUM_ASSURANCE})
    technical = _technical_qualification()
    excluded_id = technical.models[0].exact_model_id

    reviewers = _whole_protocol_review_models(
        config,
        technical,
        selected_model_ids=frozenset(
            model.exact_model_id
            for model in technical.models
            if model.exact_model_id != excluded_id
        ),
        now=BASE_TIME + timedelta(hours=2),
    )

    assert len(reviewers) == 4
    assert excluded_id not in {model_id for model_id, _lineage in reviewers}
