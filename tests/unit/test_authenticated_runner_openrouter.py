from __future__ import annotations

import pickle
from collections.abc import Callable
from dataclasses import fields, replace
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import mmaudit.orchestration.authenticated_runner_openrouter as adapter_module
from mmaudit.benchmark.cross_lineage_adjudication import CrossLineageAdjudicationRunKind
from mmaudit.benchmark.models import load_model_benchmark_corpus
from mmaudit.config import AuditConfig
from mmaudit.models.authenticated_runner import (
    AuthenticatedCrossLineageRunnerError,
    AuthenticatedCrossLineageRunnerEvidence,
    VerifiedCrossLineageRunnerCustody,
)
from mmaudit.models.authenticated_runner_execution import (
    AuthenticatedRunnerExecutedRun,
    AuthenticatedRunnerExecutionError,
    AuthenticatedRunnerExecutionInventory,
    AuthenticatedRunnerExecutionResult,
    AuthenticatedRunnerGenerationSubject,
)
from mmaudit.models.candidate_benchmark import (
    CandidateBenchmarkFailureStage,
    CandidateBenchmarkPreDispatchError,
)
from mmaudit.models.evidence_seal_authority import (
    EvidenceSealCollisionMap,
    EvidenceSealDecisionProjection,
)
from mmaudit.models.ground_truth_authority import (
    VerifiedFrozenGroundTruth,
    load_frozen_ground_truth_provenance,
    resolve_verified_frozen_ground_truth,
)
from mmaudit.models.openrouter import OpenRouterModelError, OpenRouterProviderPolicy
from mmaudit.models.runtime import build_reasoning_policy
from mmaudit.operator_secrets import OPENROUTER_API_KEY_NAME, OperatorSecrets
from mmaudit.orchestration.authenticated_runner_openrouter import (
    AUTHENTICATED_RUNNER_OPENROUTER_LAUNCH_CONTRACT_VERSION,
    AUTHENTICATED_RUNNER_OPENROUTER_LAUNCH_FIELDS,
    AuthenticatedRunnerOpenRouterError,
    AuthenticatedRunnerOpenRouterExecutionSnapshot,
    AuthenticatedRunnerOpenRouterLaunch,
    AuthenticatedRunnerOpenRouterRunSnapshot,
    execute_authenticated_openrouter_runner,
    preflight_authenticated_openrouter_launch,
)
from tests.unit import test_authenticated_runner as runner_fixtures
from tests.unit import test_authenticated_runner_execution as execution_fixtures

ROOT = Path(__file__).resolve().parents[2]


def _structural_launch() -> AuthenticatedRunnerOpenRouterLaunch:
    placeholder = cast(Any, object())
    return AuthenticatedRunnerOpenRouterLaunch(
        config=placeholder,
        explicitly_allow_synthetic_egress=True,
        public_lineage_capability=placeholder,
        ground_truth_capability=placeholder,
        benchmark_suite=placeholder,
        candidate_discovery_manifest=placeholder,
        candidate_discovery_evidence=(),
        candidate_registry=placeholder,
        qualification_policy=placeholder,
        budget=placeholder,
        usage=placeholder,
        run_plans=(),
    )


def _execution_inventory() -> AuthenticatedRunnerExecutionInventory:
    return AuthenticatedRunnerExecutionInventory(
        run_count=2,
        case_count=24,
        candidate_logical_request_count=48,
        judge_logical_request_count=48,
        logical_request_count=96,
        maximum_attempts_per_logical_request=1,
        maximum_provider_attempt_count=96,
        generation_refetch_count=96,
        effective_config_sha256="e" * 64,
        initial_spent_usd=Decimal("0"),
        declared_interval_cost_cap_usd=Decimal("1"),
        declared_final_spent_cap_usd=Decimal("1"),
    )


def _completed_execution(
    *,
    capability: VerifiedCrossLineageRunnerCustody | None = None,
) -> AuthenticatedRunnerExecutionResult:
    evidence = AuthenticatedCrossLineageRunnerEvidence.model_construct(
        evidence_sha256="a" * 64,
        serialized_authority=False,
        runner_custody_authorized=False,
    )
    runs = tuple(
        AuthenticatedRunnerExecutedRun(
            prepared_adjudication=cast(Any, f"prepared-{index}"),
            custody=cast(Any, SimpleNamespace(label=f"custody-{index}")),
        )
        for index in range(2)
    )
    return AuthenticatedRunnerExecutionResult(
        inventory=_execution_inventory(),
        runs=runs,
        closed_ledger_interval=cast(Any, object()),
        runner_capability=(
            object.__new__(VerifiedCrossLineageRunnerCustody) if capability is None else capability
        ),
        runner_evidence=evidence,
        runner_projection=cast(Any, object()),
    )


def _install_completed_runner(
    monkeypatch: pytest.MonkeyPatch,
    execution: AuthenticatedRunnerExecutionResult,
) -> None:
    async def completed_runner(**_kwargs: object) -> AuthenticatedRunnerExecutionResult:
        return execution

    monkeypatch.setattr(
        adapter_module,
        "preflight_authenticated_openrouter_launch",
        lambda _launch: execution.inventory,
    )
    monkeypatch.setattr(
        adapter_module,
        "execute_authenticated_cross_lineage_runner",
        completed_runner,
    )
    monkeypatch.setattr(
        adapter_module,
        "_require_launch_ground_truth",
        lambda _launch: object(),
    )

    def detached(item: AuthenticatedRunnerExecutedRun) -> AuthenticatedRunnerOpenRouterRunSnapshot:
        return AuthenticatedRunnerOpenRouterRunSnapshot(
            candidate_report=cast(Any, f"candidate-{item.prepared_adjudication}"),
            prepared_adjudication=item.prepared_adjudication,
            adjudication_report=cast(Any, f"adjudication-{item.prepared_adjudication}"),
        )

    monkeypatch.setattr(adapter_module, "_detached_durable_run_snapshot", detached)
    monkeypatch.setattr(adapter_module, "_TRUSTED_DETACHED_DURABLE_RUN_SNAPSHOT", detached)


def _install_lifecycle_doubles(
    monkeypatch: pytest.MonkeyPatch,
    *,
    revoke: Callable[[VerifiedCrossLineageRunnerCustody], object],
    require: Callable[..., object],
) -> None:
    for target, name, value in (
        (adapter_module, "_TRUSTED_REVOKE_RUNNER_CUSTODY", revoke),
        (adapter_module, "revoke_verified_cross_lineage_runner_custody", revoke),
        (
            adapter_module._runner_authority_module,
            "revoke_verified_cross_lineage_runner_custody",
            revoke,
        ),
        (adapter_module, "_TRUSTED_REQUIRE_RUNNER_CUSTODY", require),
        (adapter_module, "require_verified_cross_lineage_runner_custody", require),
        (
            adapter_module._runner_authority_module,
            "require_verified_cross_lineage_runner_custody",
            require,
        ),
    ):
        monkeypatch.setattr(target, name, value)


def test_detached_run_snapshot_copies_only_durable_report_models() -> None:
    inputs = cast(Callable[[], Any], runner_fixtures.live_inputs.__wrapped__)()
    custody = inputs.runs[0]
    executed = AuthenticatedRunnerExecutedRun(
        prepared_adjudication=custody.prepared_adjudication,
        custody=custody,
    )

    snapshot = adapter_module._detached_durable_run_snapshot(executed)

    assert type(snapshot) is AuthenticatedRunnerOpenRouterRunSnapshot
    assert tuple(item.name for item in fields(snapshot)) == (
        "candidate_report",
        "prepared_adjudication",
        "adjudication_report",
    )
    assert snapshot.candidate_report == custody.candidate_report
    assert snapshot.candidate_report is not custody.candidate_report
    assert snapshot.prepared_adjudication == custody.prepared_adjudication
    assert snapshot.prepared_adjudication is not custody.prepared_adjudication
    assert snapshot.adjudication_report == custody.adjudication_report
    assert snapshot.adjudication_report is not custody.adjudication_report
    assert (
        snapshot.candidate_report.results[0].cases[0].usage_record
        is not custody.candidate_report.results[0].cases[0].usage_record
    )
    assert (
        snapshot.adjudication_report.cases[0].usage_record
        is not custody.adjudication_report.cases[0].usage_record
    )
    for live_field in (
        "candidate_campaign_verification",
        "candidate_generation_verification",
        "judge_generation_verification",
        "custody",
    ):
        assert not hasattr(snapshot, live_field)
    with pytest.raises(TypeError, match="run snapshot cannot be serialized"):
        pickle.dumps(snapshot)


def test_launch_contract_is_versioned_ordered_and_nonserializable() -> None:
    assert AUTHENTICATED_RUNNER_OPENROUTER_LAUNCH_CONTRACT_VERSION == "2.0"
    assert tuple(item.name for item in fields(AuthenticatedRunnerOpenRouterLaunch)) == (
        AUTHENTICATED_RUNNER_OPENROUTER_LAUNCH_FIELDS
    )

    with pytest.raises(TypeError, match="launch cannot be serialized"):
        pickle.dumps(_structural_launch())


def test_candidate_setup_rejection_preserves_exact_bounded_operator_detail() -> None:
    rejection = CandidateBenchmarkPreDispatchError(
        stage=CandidateBenchmarkFailureStage.ENDPOINT_REGISTRATION,
        detail="configured endpoint is not operational",
    )

    with pytest.raises(
        CandidateBenchmarkPreDispatchError,
        match=r"^configured endpoint is not operational$",
    ):
        adapter_module._raise_candidate_pre_dispatch_rejection(rejection)


@pytest.mark.asyncio
async def test_adapter_clears_secret_holder_when_runner_rejects_missing_real_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    async def reject_missing_origin(**kwargs: object) -> Any:
        seen.update(kwargs)
        raise AuthenticatedRunnerExecutionError(
            "runner case lacks strong owned REAL transport origin"
        )

    def forbidden_authseal(**_kwargs: object) -> Any:
        raise AssertionError("AUTHSEAL must not consume a rejected runner")

    monkeypatch.setattr(
        adapter_module,
        "execute_authenticated_cross_lineage_runner",
        reject_missing_origin,
    )
    monkeypatch.setattr(
        adapter_module,
        "build_authenticated_evidence_seal_runner_inputs",
        forbidden_authseal,
    )
    monkeypatch.setattr(
        adapter_module,
        "preflight_authenticated_openrouter_launch",
        lambda _launch: cast(Any, object()),
    )
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-provider-free-unit-key"})

    with pytest.raises(
        AuthenticatedRunnerExecutionError,
        match="strong owned REAL transport origin",
    ):
        await execute_authenticated_openrouter_runner(
            launch=_structural_launch(),
            operator_secrets=secrets,
        )

    assert secrets.cleared is True
    assert secrets.openrouter_api_key == ""
    assert "operator_api_key" not in seen
    assert "operator_secrets" not in seen
    assert seen["explicitly_allow_synthetic_egress"] is True
    assert set(seen) == {
        "benchmark_suite",
        "budget",
        "candidate_executor",
        "candidate_registry",
        "config",
        "discovery_evidence",
        "discovery_manifest",
        "explicitly_allow_synthetic_egress",
        "generation_executor",
        "ground_truth_capability",
        "judge_executor",
        "public_lineage_capability",
        "qualification_policy",
        "run_plans",
        "usage",
    }


@pytest.mark.asyncio
async def test_adapter_rejects_missing_secret_before_runner_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def forbidden_dispatch(**_kwargs: object) -> Any:
        raise AssertionError("runner must not dispatch without an operator credential")

    monkeypatch.setattr(
        adapter_module,
        "execute_authenticated_cross_lineage_runner",
        forbidden_dispatch,
    )
    monkeypatch.setattr(
        adapter_module,
        "preflight_authenticated_openrouter_launch",
        lambda _launch: cast(Any, object()),
    )
    secrets = OperatorSecrets()

    with pytest.raises(AuthenticatedRunnerOpenRouterError, match="OPENROUTER_API_KEY is missing"):
        await execute_authenticated_openrouter_runner(
            launch=_structural_launch(),
            operator_secrets=secrets,
        )

    assert secrets.cleared is True


@pytest.mark.asyncio
async def test_adapter_revokes_once_after_authseal_success_and_returns_no_live_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = _completed_execution()
    collision_map = EvidenceSealCollisionMap.model_construct(collision_map_sha256="b" * 64)
    decisions = tuple(
        EvidenceSealDecisionProjection.model_construct(projection_sha256=digest)
        for digest in ("c" * 64, "d" * 64)
    )
    events: list[str] = []
    revoked: list[VerifiedCrossLineageRunnerCustody] = []

    def accepted_authseal(**kwargs: object) -> Any:
        events.append("authseal")
        assert kwargs["runner_custody"] is execution.runner_capability
        assert kwargs["runner_evidence"] is execution.runner_evidence
        return collision_map, decisions

    def revoke(capability: VerifiedCrossLineageRunnerCustody) -> None:
        events.append("revoke")
        revoked.append(capability)

    def require_revoked(
        capability: VerifiedCrossLineageRunnerCustody,
        *,
        evidence: AuthenticatedCrossLineageRunnerEvidence,
    ) -> None:
        events.append("require-revoked")
        assert capability is execution.runner_capability
        assert evidence is execution.runner_evidence
        raise AuthenticatedCrossLineageRunnerError(adapter_module._REVOKED_RUNNER_CUSTODY_DETAIL)

    _install_completed_runner(monkeypatch, execution)
    monkeypatch.setattr(
        adapter_module,
        "build_authenticated_evidence_seal_runner_inputs",
        accepted_authseal,
    )
    _install_lifecycle_doubles(
        monkeypatch,
        revoke=revoke,
        require=require_revoked,
    )
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-provider-free-unit-key"})

    result = await execute_authenticated_openrouter_runner(
        launch=_structural_launch(),
        operator_secrets=secrets,
    )

    assert events == ["authseal", "revoke", "require-revoked"]
    assert revoked == [execution.runner_capability]
    assert type(result.execution) is AuthenticatedRunnerOpenRouterExecutionSnapshot
    assert tuple(item.name for item in fields(result.execution)) == ("inventory", "runs")
    assert result.execution.inventory is execution.inventory
    assert result.execution.runs is not execution.runs
    assert len(result.execution.runs) == len(execution.runs)
    assert all(
        type(item) is AuthenticatedRunnerOpenRouterRunSnapshot for item in result.execution.runs
    )
    assert all(not hasattr(item, "custody") for item in result.execution.runs)
    for live_field in (
        "closed_ledger_interval",
        "runner_capability",
        "runner_evidence",
        "runner_projection",
    ):
        assert not hasattr(result.execution, live_field)
    with pytest.raises(TypeError, match="execution snapshot cannot be serialized"):
        pickle.dumps(result.execution)
    assert result.runner_evidence is execution.runner_evidence
    assert result.authseal_collision_map is collision_map
    assert result.authseal_decision_projections == decisions
    assert result.authseal_rejection_kind is None
    assert secrets.cleared is True


@pytest.mark.asyncio
async def test_adapter_retains_completed_runner_evidence_when_authseal_rejects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = _completed_execution()
    events: list[str] = []
    revoked: list[VerifiedCrossLineageRunnerCustody] = []

    def rejected_authseal(**_kwargs: object) -> Any:
        events.append("authseal")
        raise ValueError("synthetic comparison rejected")

    def revoke(capability: VerifiedCrossLineageRunnerCustody) -> None:
        events.append("revoke")
        revoked.append(capability)

    def require_revoked(
        capability: VerifiedCrossLineageRunnerCustody,
        *,
        evidence: AuthenticatedCrossLineageRunnerEvidence,
    ) -> None:
        events.append("require-revoked")
        assert capability is execution.runner_capability
        assert evidence is execution.runner_evidence
        raise AuthenticatedCrossLineageRunnerError(adapter_module._REVOKED_RUNNER_CUSTODY_DETAIL)

    _install_completed_runner(monkeypatch, execution)
    monkeypatch.setattr(
        adapter_module,
        "build_authenticated_evidence_seal_runner_inputs",
        rejected_authseal,
    )
    _install_lifecycle_doubles(
        monkeypatch,
        revoke=revoke,
        require=require_revoked,
    )
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-provider-free-unit-key"})

    result = await execute_authenticated_openrouter_runner(
        launch=_structural_launch(),
        operator_secrets=secrets,
    )

    assert events == ["authseal", "revoke", "require-revoked"]
    assert revoked == [execution.runner_capability]
    assert type(result.execution) is AuthenticatedRunnerOpenRouterExecutionSnapshot
    assert result.runner_evidence is execution.runner_evidence
    assert result.authseal_collision_map is None
    assert result.authseal_decision_projections == ()
    assert result.authseal_rejection_kind == "ValueError"
    assert secrets.cleared is True


@pytest.mark.asyncio
async def test_adapter_revokes_once_when_authseal_raises_post_issuance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = _completed_execution()
    events: list[str] = []
    revoked: list[VerifiedCrossLineageRunnerCustody] = []

    def failed_authseal(**_kwargs: object) -> Any:
        events.append("authseal")
        raise RuntimeError("synthetic unexpected AUTHSEAL failure")

    def revoke(capability: VerifiedCrossLineageRunnerCustody) -> None:
        events.append("revoke")
        revoked.append(capability)

    def require_revoked(
        capability: VerifiedCrossLineageRunnerCustody,
        *,
        evidence: AuthenticatedCrossLineageRunnerEvidence,
    ) -> None:
        events.append("require-revoked")
        assert capability is execution.runner_capability
        assert evidence is execution.runner_evidence
        raise AuthenticatedCrossLineageRunnerError(adapter_module._REVOKED_RUNNER_CUSTODY_DETAIL)

    _install_completed_runner(monkeypatch, execution)
    monkeypatch.setattr(
        adapter_module,
        "build_authenticated_evidence_seal_runner_inputs",
        failed_authseal,
    )
    _install_lifecycle_doubles(
        monkeypatch,
        revoke=revoke,
        require=require_revoked,
    )
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-provider-free-unit-key"})

    with pytest.raises(RuntimeError, match="unexpected AUTHSEAL failure"):
        await execute_authenticated_openrouter_runner(
            launch=_structural_launch(),
            operator_secrets=secrets,
        )

    assert events == ["authseal", "revoke", "require-revoked"]
    assert revoked == [execution.runner_capability]
    assert secrets.cleared is True


@pytest.mark.asyncio
async def test_adapter_refuses_return_when_post_revoke_self_check_remains_positive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = _completed_execution()
    events: list[str] = []

    def accepted_authseal(**_kwargs: object) -> tuple[None, tuple[()]]:
        events.append("authseal")
        return None, ()

    def non_revoking(_capability: VerifiedCrossLineageRunnerCustody) -> None:
        events.append("revoke")

    def still_live(*_args: object, **_kwargs: object) -> object:
        events.append("require-live")
        return object()

    _install_completed_runner(monkeypatch, execution)
    monkeypatch.setattr(
        adapter_module,
        "build_authenticated_evidence_seal_runner_inputs",
        accepted_authseal,
    )
    _install_lifecycle_doubles(
        monkeypatch,
        revoke=non_revoking,
        require=still_live,
    )
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-provider-free-unit-key"})

    with pytest.raises(AuthenticatedRunnerOpenRouterError, match="remained live after revocation"):
        await execute_authenticated_openrouter_runner(
            launch=_structural_launch(),
            operator_secrets=secrets,
        )

    assert events == ["authseal", "revoke", "require-live"]
    assert secrets.cleared is True


@pytest.mark.asyncio
async def test_adapter_retarget_cannot_replace_exactly_once_lifecycle_disposal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = _completed_execution()
    events: list[str] = []

    def accepted_authseal(**_kwargs: object) -> tuple[None, tuple[()]]:
        events.append("authseal")
        return None, ()

    def trusted_revoke(capability: VerifiedCrossLineageRunnerCustody) -> None:
        events.append("trusted-revoke")
        assert capability is execution.runner_capability

    def forged_revoke(_capability: VerifiedCrossLineageRunnerCustody) -> None:
        events.append("forged-revoke")

    def require_revoked(*_args: object, **_kwargs: object) -> None:
        events.append("require-revoked")
        raise AuthenticatedCrossLineageRunnerError(adapter_module._REVOKED_RUNNER_CUSTODY_DETAIL)

    _install_completed_runner(monkeypatch, execution)
    monkeypatch.setattr(
        adapter_module,
        "build_authenticated_evidence_seal_runner_inputs",
        accepted_authseal,
    )
    _install_lifecycle_doubles(
        monkeypatch,
        revoke=trusted_revoke,
        require=require_revoked,
    )
    monkeypatch.setattr(
        adapter_module,
        "revoke_verified_cross_lineage_runner_custody",
        forged_revoke,
    )
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-provider-free-unit-key"})

    with pytest.raises(AuthenticatedRunnerOpenRouterError, match="callable binding changed"):
        await execute_authenticated_openrouter_runner(
            launch=_structural_launch(),
            operator_secrets=secrets,
        )

    assert events == ["authseal", "trusted-revoke", "require-revoked"]
    assert secrets.cleared is True


@pytest.mark.parametrize(
    "binding_name",
    (
        "_detached_durable_run_snapshot",
        "AuthenticatedRunnerOpenRouterRunSnapshot",
        "AuthenticatedRunnerOpenRouterExecutionSnapshot",
    ),
)
@pytest.mark.asyncio
async def test_adapter_snapshot_binding_retarget_rejects_before_forged_invocation_and_revokes(
    monkeypatch: pytest.MonkeyPatch,
    binding_name: str,
) -> None:
    execution = _completed_execution()
    events: list[str] = []
    forged_calls: list[str] = []

    def accepted_authseal(**_kwargs: object) -> tuple[None, tuple[()]]:
        events.append("authseal")
        return None, ()

    def revoke(_capability: VerifiedCrossLineageRunnerCustody) -> None:
        events.append("revoke")

    def require_revoked(*_args: object, **_kwargs: object) -> None:
        events.append("require-revoked")
        raise AuthenticatedCrossLineageRunnerError(adapter_module._REVOKED_RUNNER_CUSTODY_DETAIL)

    def forged(*_args: object, **_kwargs: object) -> object:
        forged_calls.append(binding_name)
        return object()

    _install_completed_runner(monkeypatch, execution)
    monkeypatch.setattr(
        adapter_module,
        "build_authenticated_evidence_seal_runner_inputs",
        accepted_authseal,
    )
    _install_lifecycle_doubles(monkeypatch, revoke=revoke, require=require_revoked)
    monkeypatch.setattr(adapter_module, binding_name, forged)
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-provider-free-unit-key"})

    with pytest.raises(AuthenticatedRunnerOpenRouterError, match="snapshot binding changed"):
        await execute_authenticated_openrouter_runner(
            launch=_structural_launch(),
            operator_secrets=secrets,
        )

    assert forged_calls == []
    assert events == ["authseal", "revoke", "require-revoked"]
    assert secrets.cleared is True


@pytest.mark.asyncio
async def test_adapter_forged_runner_custody_cannot_escape_real_revoker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = _completed_execution()
    authseal_calls = 0

    def accepted_authseal(**_kwargs: object) -> tuple[None, tuple[()]]:
        nonlocal authseal_calls
        authseal_calls += 1
        return None, ()

    _install_completed_runner(monkeypatch, execution)
    monkeypatch.setattr(
        adapter_module,
        "build_authenticated_evidence_seal_runner_inputs",
        accepted_authseal,
    )
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-provider-free-unit-key"})

    with pytest.raises(
        AuthenticatedCrossLineageRunnerError,
        match="absent, mismatched, or revoked",
    ):
        await execute_authenticated_openrouter_runner(
            launch=_structural_launch(),
            operator_secrets=secrets,
        )

    assert authseal_calls == 1
    assert secrets.cleared is True


@pytest.mark.asyncio
async def test_adapter_rejects_a_raw_key_or_untrusted_secret_holder() -> None:
    with pytest.raises(AuthenticatedRunnerOpenRouterError, match="existing operator secret loader"):
        await execute_authenticated_openrouter_runner(
            launch=_structural_launch(),
            operator_secrets=cast(Any, "synthetic-provider-free-unit-key"),
        )


@pytest.mark.asyncio
async def test_generation_subject_is_exactly_once_without_provider_dispatch() -> None:
    run_kind = CrossLineageAdjudicationRunKind.PRIMARY
    launch = replace(
        _structural_launch(),
        run_plans=(cast(Any, SimpleNamespace(run_kind=run_kind)),),
    )
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-provider-free-unit-key"})
    adapter = adapter_module._OpenRouterExecutionAdapter(launch=launch, secrets=secrets)
    assert "_generation_subjects" in adapter_module._OpenRouterExecutionAdapter.__slots__

    with pytest.raises(
        AuthenticatedRunnerOpenRouterError,
        match="preceded candidate execution",
    ):
        await adapter.generation_executor(
            run_kind=run_kind,
            subject=AuthenticatedRunnerGenerationSubject.CANDIDATE,
            requests=(),
        )
    with pytest.raises(AuthenticatedRunnerOpenRouterError, match="replayed"):
        await adapter.generation_executor(
            run_kind=run_kind,
            subject=AuthenticatedRunnerGenerationSubject.CANDIDATE,
            requests=(),
        )

    await adapter.close()
    secrets.clear()


def test_ground_truth_method_retarget_is_rejected_before_authseal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite = load_model_benchmark_corpus(ROOT / "benchmarks/model_corpus/manifest.json")
    provenance = load_frozen_ground_truth_provenance(
        ROOT / "benchmarks/model_corpus/provenance.json"
    )
    capability = resolve_verified_frozen_ground_truth(
        provenance=provenance,
        benchmark_suite=suite,
    )
    launch = replace(
        _structural_launch(),
        benchmark_suite=suite,
        ground_truth_capability=capability,
    )

    monkeypatch.setattr(
        VerifiedFrozenGroundTruth, "require_for", lambda *_args, **_kwargs: object()
    )

    with pytest.raises(AuthenticatedRunnerOpenRouterError, match="method changed"):
        adapter_module._require_launch_ground_truth(launch)


@pytest.mark.asyncio
async def test_provider_free_preflight_returns_exact_inventory_without_dispatch(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    harness = await execution_fixtures._harness(tmp_path, config_factory)
    launch = AuthenticatedRunnerOpenRouterLaunch(
        config=harness.config,
        explicitly_allow_synthetic_egress=True,
        public_lineage_capability=harness.public_lineage,
        ground_truth_capability=harness.ground_truth,
        benchmark_suite=harness.suite,
        candidate_discovery_manifest=harness.discovery_manifest,
        candidate_discovery_evidence=harness.discovery_evidence,
        candidate_registry=harness.registry,
        qualification_policy=harness.policy,
        budget=harness.budget,
        usage=harness.usage,
        run_plans=harness.plans,
    )
    assert harness.budget.atomic_ledger is not None
    before = harness.budget.atomic_ledger.snapshot()

    inventory = preflight_authenticated_openrouter_launch(launch)

    assert inventory.run_count == 2
    assert inventory.case_count == 24
    assert inventory.logical_request_count == 96
    assert inventory.generation_refetch_count == 96
    assert harness.usage.records == []
    assert harness.budget.atomic_ledger.snapshot() == before
    assert all(not plan.campaign_path.exists() for plan in harness.plans)
    assert all(not plan.portfolio_path.exists() for plan in harness.plans)

    with pytest.raises(
        AuthenticatedRunnerExecutionError,
        match="explicit synthetic-source egress authorization",
    ):
        preflight_authenticated_openrouter_launch(
            replace(launch, explicitly_allow_synthetic_egress=False)
        )
    assert harness.usage.records == []
    assert harness.budget.atomic_ledger.snapshot() == before


@pytest.mark.asyncio
async def test_judge_refresh_observes_current_metadata_in_order_before_registration(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    harness = await execution_fixtures._harness(tmp_path, config_factory)
    plan = harness.plans[0]
    judge = plan.judge
    factory = execution_fixtures.candidate_fixtures._MockClientFactory()
    client = factory(
        api_key="synthetic-provider-free-unit-key",
        config=harness.config,
        budget=harness.budget,
        usage=harness.usage,
        candidate=judge,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=(judge.approved_provider_endpoint,),
            allow_fallbacks=False,
        ),
        reasoning_policy=build_reasoning_policy(harness.config),
    )
    try:
        await adapter_module._refresh_and_register_judge_discovery(
            client=client,
            config=harness.config,
            judge=judge,
            evidence=plan.judge_discovery_evidence[0],
            manifest=plan.judge_discovery_manifest,
        )
        registered = client.registered_model_identity_snapshot(judge.exact_model_id)
    finally:
        await factory.close()

    assert registered.discovery_evidence_sha256 == judge.discovery_evidence_sha256
    assert factory.metadata_requests == [
        "/api/v1/key",
        "/api/v1/models",
        f"/api/v1/model/{judge.exact_model_id}",
        f"/api/v1/models/{judge.exact_model_id}/endpoints",
        "/api/v1/endpoints/zdr",
    ]
    assert factory.request_bodies == []


@pytest.mark.asyncio
async def test_judge_refresh_rejects_pricing_drift_without_registration_or_completion(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    harness = await execution_fixtures._harness(tmp_path, config_factory)
    plan = harness.plans[0]
    judge = plan.judge
    factory = execution_fixtures.candidate_fixtures._MockClientFactory(
        pricing_drift_models={judge.exact_model_id}
    )
    client = factory(
        api_key="synthetic-provider-free-unit-key",
        config=harness.config,
        budget=harness.budget,
        usage=harness.usage,
        candidate=judge,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=(judge.approved_provider_endpoint,),
            allow_fallbacks=False,
        ),
        reasoning_policy=build_reasoning_policy(harness.config),
    )
    try:
        with pytest.raises(AuthenticatedRunnerOpenRouterError, match=r"pricing.*differs"):
            await adapter_module._refresh_and_register_judge_discovery(
                client=client,
                config=harness.config,
                judge=judge,
                evidence=plan.judge_discovery_evidence[0],
                manifest=plan.judge_discovery_manifest,
            )
        with pytest.raises(OpenRouterModelError, match="not registered"):
            client.registered_model_identity_snapshot(judge.exact_model_id)
    finally:
        await factory.close()

    assert factory.request_bodies == []
