from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import mmaudit.cli as cli_module
import mmaudit.orchestration.authenticated_runner_smoke_openrouter as smoke_runtime_module
from mmaudit.config import AuditConfig
from mmaudit.models.candidate_registry_bridge import write_candidate_registry_json
from mmaudit.models.candidate_selection import (
    CandidateSelectionPlan,
    derive_candidate_selection_plan_successor,
    seal_authenticated_runner_route_predicate_profile,
    seal_authenticated_runner_selection,
    seal_candidate_selection_entry,
    seal_candidate_selection_plan,
    seal_candidate_selection_source_binding,
)
from mmaudit.models.discovery import (
    OpenRouterDiscoveryRunProvenance,
    OpenRouterModelDiscoveryEvidence,
    load_model_discovery_run,
)
from mmaudit.models.openrouter import OpenRouterProviderPolicy
from mmaudit.models.qualification import (
    CandidateRegistry,
    load_candidate_registry,
    validate_candidate_registry_discovery,
)
from mmaudit.models.route_constraints import ExactRouteConstraint, ExactRouteRole
from mmaudit.models.runtime import build_reasoning_policy
from mmaudit.models.usage import UsageLedger
from mmaudit.reporting.json_report import stable_json
from tests.unit import test_authenticated_runner_smoke_runtime as smoke_fixtures
from tests.unit import test_candidate_benchmark as candidate_fixtures

RUNNER = CliRunner()
ROOT = Path(__file__).resolve().parents[2]
REVOKED_CANDIDATE = "deepseek/deepseek-v4-pro-0813"
REVOKED_ENDPOINT = "parasail/fp8"
SUCCESSOR_CANDIDATE = "google/gemma-4-26b-a4b-it"
SUCCESSOR_ENDPOINT = "deepinfra/fp8"
STALE_SUCCESSOR_ENDPOINT = "deepinfra/legacy"
PRIMARY_JUDGE = "z-ai/glm-5.2"
PRIMARY_ENDPOINT = "sail-research/fp8"
REPLAY_JUDGE = "moonshotai/kimi-k3"
REPLAY_ENDPOINT = "modal/mxfp4"
SYNTHETIC_KEY = "synthetic-successor-smoke-key"


def _predecessor(config: AuditConfig) -> tuple[CandidateSelectionPlan, bytes, bytes]:
    ranking = b"synthetic successor ranking input\n"
    lineage = b"synthetic successor lineage input\n"
    profile = seal_authenticated_runner_route_predicate_profile(
        reasoning_policy=build_reasoning_policy(config),
        minimum_prompt_tokens=65_536,
        required_output_tokens=config.effective_reserved_output_tokens,
        minimum_context_tokens=73_728,
    )
    constraints = tuple(
        ExactRouteConstraint.build(
            role=role,
            exact_model_id=model_id,
            provider_endpoint=endpoint,
            profile=profile,
        )
        for role, model_id, endpoint in (
            (ExactRouteRole.CANDIDATE, REVOKED_CANDIDATE, REVOKED_ENDPOINT),
            (ExactRouteRole.PRIMARY_JUDGE, PRIMARY_JUDGE, PRIMARY_ENDPOINT),
            (ExactRouteRole.REPLAY_JUDGE, REPLAY_JUDGE, REPLAY_ENDPOINT),
        )
    )
    plan = seal_candidate_selection_plan(
        source_bindings=(
            seal_candidate_selection_source_binding(
                kind="MODEL_RANKING_IMPLEMENTATION",
                filename="synthetic-ranking.py",
                content=ranking,
            ),
            seal_candidate_selection_source_binding(
                kind="OPERATOR_LINEAGE_REVIEW",
                filename="synthetic-lineage.md",
                content=lineage,
            ),
        ),
        entries=tuple(
            seal_candidate_selection_entry(
                exact_model_id=model_id,
                priority_rank=rank,
                advisory_lineage_group=f"Synthetic successor group {rank}",
                allowed_provider_endpoints=(endpoint,),
            )
            for rank, (model_id, endpoint) in enumerate(
                (
                    (REVOKED_CANDIDATE, REVOKED_ENDPOINT),
                    (SUCCESSOR_CANDIDATE, STALE_SUCCESSOR_ENDPOINT),
                    (PRIMARY_JUDGE, PRIMARY_ENDPOINT),
                    (REPLAY_JUDGE, REPLAY_ENDPOINT),
                ),
                start=1,
            )
        ),
        authenticated_runner_selection=seal_authenticated_runner_selection(
            candidate_model_id=REVOKED_CANDIDATE,
            primary_judge_model_id=PRIMARY_JUDGE,
            replay_judge_model_id=REPLAY_JUDGE,
            route_predicate_profile=profile,
            route_constraints=constraints,
        ),
    )
    return plan, ranking, lineage


def _candidate_constraint(plan: CandidateSelectionPlan) -> ExactRouteConstraint:
    selection = plan.authenticated_runner_selection
    assert selection is not None
    return next(
        constraint
        for constraint in selection.route_constraints
        if constraint.role is ExactRouteRole.CANDIDATE
    )


def _write_judge_route(
    *,
    tmp_path: Path,
    config: AuditConfig,
    successor: CandidateSelectionPlan,
    role: ExactRouteRole,
    model_id: str,
    endpoint: str,
) -> tuple[Path, Path, CandidateRegistry]:
    selection = successor.authenticated_runner_selection
    assert selection is not None
    manifest, evidence, registry = candidate_fixtures._discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        route_role=role,
        selection_plan_sha256=successor.plan_sha256,
        route_predicate_profile=selection.route_predicate_profile,
        specs=(
            candidate_fixtures._CandidateSpec(
                model_id=model_id,
                provider_endpoint=endpoint,
                provider_name=f"Synthetic {role.value} provider",
                native_structured_output_parameter="structured_outputs",
            ),
        ),
    )
    discovery_path = tmp_path / "discovery-run"
    registry_path = tmp_path / "registry.json"
    write_candidate_registry_json(registry_path, registry)
    loaded_manifest, loaded_evidence = load_model_discovery_run(discovery_path)
    loaded_registry = load_candidate_registry(registry_path)
    assert loaded_manifest == manifest
    assert loaded_evidence == evidence
    validate_candidate_registry_discovery(
        registry=loaded_registry,
        run_manifest=loaded_manifest,
        evidence=loaded_evidence,
    )
    assert loaded_registry.candidates[0].selection_plan_sha256 == successor.plan_sha256
    return discovery_path, registry_path, loaded_registry


def test_successor_constrained_discovery_reaches_live_route_smoke_without_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    tmp_path.chmod(0o700)
    config = smoke_fixtures._smoke_config(config_factory)
    predecessor, ranking, lineage = _predecessor(config)
    successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=SUCCESSOR_CANDIDATE,
        provider_endpoint=SUCCESSOR_ENDPOINT,
        refresh_endpoint_inventory=True,
    )
    assert predecessor.authenticated_runner_selection is not None
    assert predecessor.authenticated_runner_selection.candidate_model_id == REVOKED_CANDIDATE
    assert successor.predecessor_plan_sha256 == predecessor.plan_sha256
    assert successor.plan_sha256 != predecessor.plan_sha256
    assert successor.schema_version == "1.6"
    assert successor.endpoint_inventory_refresh is not None
    assert successor.endpoint_inventory_refresh.provider_endpoint == SUCCESSOR_ENDPOINT
    assert successor.endpoint_inventory_refresh.predecessor_allowed_provider_endpoints == (
        STALE_SUCCESSOR_ENDPOINT,
    )
    assert successor.endpoint_inventory_refresh.constrained_discovery_required is True
    assert successor.endpoint_inventory_refresh.endpoint_authority is False
    successor_constraint = _candidate_constraint(successor)

    selection_dir = tmp_path / "selection"
    selection_dir.mkdir(mode=0o700)
    plan_path = selection_dir / "successor.json"
    ranking_path = selection_dir / "synthetic-ranking.py"
    lineage_path = selection_dir / "synthetic-lineage.md"
    plan_path.write_text(stable_json(successor), encoding="utf-8")
    ranking_path.write_bytes(ranking)
    lineage_path.write_bytes(lineage)

    spec = candidate_fixtures._CandidateSpec(
        model_id=SUCCESSOR_CANDIDATE,
        provider_endpoint=SUCCESSOR_ENDPOINT,
        provider_name="Synthetic successor candidate provider",
        native_structured_output_parameter="structured_outputs",
    )
    _fixture_manifest, sealed_evidence, _fixture_registry = (
        candidate_fixtures._discovery_and_registry(
            tmp_path=tmp_path / "candidate-fixture",
            config=config,
            route_role=ExactRouteRole.CANDIDATE,
            selection_plan_sha256=successor.plan_sha256,
            route_predicate_profile=(
                successor.authenticated_runner_selection.route_predicate_profile
            ),
            specs=(spec,),
        )
    )
    endpoint = candidate_fixtures._endpoint(spec)
    catalog_payload = {"data": [candidate_fixtures._catalog_model(spec)]}
    endpoint_payload = {
        "data": {
            "id": SUCCESSOR_CANDIDATE,
            "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
        }
    }
    constructor_constraints: list[ExactRouteConstraint | None] = []

    class ProviderFreeSuccessorDiscoveryClient:
        def __init__(self, *, api_key: str, **kwargs: object) -> None:
            assert api_key == SYNTHETIC_KEY
            supplied = kwargs.get("candidate_revocation_route_constraint")
            assert supplied is None or type(supplied) is ExactRouteConstraint
            constructor_constraints.append(supplied)
            assert supplied == successor_constraint
            assert kwargs.get("provider_policy") == OpenRouterProviderPolicy(
                only=(SUCCESSOR_ENDPOINT,),
                allow_fallbacks=False,
            )

        async def validate_authentication(self) -> None:
            return None

        async def get_certification_model_metadata(self) -> dict[str, Any]:
            return catalog_payload

        async def list_zdr_endpoints(self) -> dict[str, Any]:
            return {"data": [endpoint]}

        async def get_model_metadata(self, model_id: str) -> dict[str, Any]:
            assert model_id == SUCCESSOR_CANDIDATE
            return {"data": candidate_fixtures._catalog_model(spec)}

        async def get_model_endpoint_metadata(self, model_id: str) -> dict[str, Any]:
            assert model_id == SUCCESSOR_CANDIDATE
            return endpoint_payload

        def seal_real_model_discovery_run(
            self,
            **kwargs: Any,
        ) -> tuple[
            OpenRouterDiscoveryRunProvenance,
            tuple[OpenRouterModelDiscoveryEvidence, ...],
        ]:
            assert tuple(item.exact_model_id for item in kwargs["payloads"]) == (
                SUCCESSOR_CANDIDATE,
            )
            return sealed_evidence[0].provenance, sealed_evidence

        async def close(self) -> None:
            return None

    secret_path = tmp_path / "operator-secrets.env"
    secret_path.write_text(f"OPENROUTER_API_KEY={SYNTHETIC_KEY}\n", encoding="utf-8")
    secret_path.chmod(0o600)
    config_path = tmp_path / "mmaudit.toml"
    config_path.write_text("# synthetic config path; load is patched to the typed fixture\n")
    candidate_discovery_path = tmp_path / "candidate-discovery"
    candidate_registry_path = tmp_path / "candidate-registry.json"
    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(cli_module, "OpenRouterClient", ProviderFreeSuccessorDiscoveryClient)
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_CLIENT_TYPE",
        ProviderFreeSuccessorDiscoveryClient,
    )
    discovery_result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            f"{SUCCESSOR_CANDIDATE}={SUCCESSOR_ENDPOINT}",
            "--config",
            str(config_path),
            "--secrets-env-file",
            str(secret_path),
            "--output-dir",
            str(candidate_discovery_path),
            "--candidate-selection-plan",
            str(plan_path),
            "--candidate-selection-ranking-source",
            str(ranking_path),
            "--candidate-selection-lineage-review-source",
            str(lineage_path),
            "--candidate-registry-output",
            str(candidate_registry_path),
            "--no-color",
        ],
    )
    assert discovery_result.exit_code == 0, discovery_result.output
    assert constructor_constraints == [successor_constraint]
    candidate_manifest, candidate_evidence = load_model_discovery_run(candidate_discovery_path)
    candidate_registry = load_candidate_registry(candidate_registry_path)
    validate_candidate_registry_discovery(
        registry=candidate_registry,
        run_manifest=candidate_manifest,
        evidence=candidate_evidence,
    )
    candidate_snapshot = candidate_evidence[0].endpoint_snapshot
    assert candidate_snapshot.exact_route_constraint == successor_constraint
    assert candidate_snapshot.normalized_route_facts is not None
    assert (
        candidate_snapshot.normalized_route_facts.expected_selection_plan_sha256
        == successor.plan_sha256
    )
    assert candidate_registry.candidates[0].selection_plan_sha256 == successor.plan_sha256
    assert (
        candidate_registry.candidates[0].exact_route_constraint_sha256
        == successor_constraint.constraint_sha256
    )

    primary_discovery_path, primary_registry_path, _primary_registry = _write_judge_route(
        tmp_path=tmp_path / "primary-judge",
        config=config,
        successor=successor,
        role=ExactRouteRole.PRIMARY_JUDGE,
        model_id=PRIMARY_JUDGE,
        endpoint=PRIMARY_ENDPOINT,
    )
    replay_discovery_path, replay_registry_path, _replay_registry = _write_judge_route(
        tmp_path=tmp_path / "replay-judge",
        config=config,
        successor=successor,
        role=ExactRouteRole.REPLAY_JUDGE,
        model_id=REPLAY_JUDGE,
        endpoint=REPLAY_ENDPOINT,
    )

    budget = candidate_fixtures._budget(tmp_path / "smoke-ledger", config)
    usage = UsageLedger()
    ledger = budget.atomic_ledger
    assert ledger is not None
    ledger_before = ledger.snapshot()
    usage_before = tuple(usage.records)
    monkeypatch.setattr(
        cli_module,
        "_budget_and_usage",
        lambda *_args, **_kwargs: (budget, usage),
    )
    original_live_preflight = smoke_runtime_module.preflight_authenticated_runner_smoke_live_routes
    observed: dict[str, object] = {}

    async def run_full_mocked_preflight(**kwargs: Any) -> Any:
        launch = kwargs["launch"]
        observed["launch"] = launch
        factory = smoke_fixtures._install_live_route_client_factory(
            monkeypatch,
            launch,
            canonical_shape_models={
                SUCCESSOR_CANDIDATE,
                PRIMARY_JUDGE,
                REPLAY_JUDGE,
            },
        )
        observed["factory"] = factory
        return await original_live_preflight(**kwargs)

    async def forbidden_completion(**_kwargs: object) -> None:
        raise AssertionError("live-route-only successor smoke must not dispatch a completion")

    monkeypatch.setattr(
        cli_module,
        "preflight_authenticated_runner_smoke_live_routes",
        run_full_mocked_preflight,
    )
    monkeypatch.setattr(
        cli_module,
        "execute_authenticated_runner_smoke_openrouter",
        forbidden_completion,
    )
    smoke_output = tmp_path / "smoke-output.json"
    smoke_result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "authenticated-runner-smoke",
            "--candidate-registry",
            str(candidate_registry_path),
            "--candidate-discovery-run",
            str(candidate_discovery_path),
            "--primary-judge-registry",
            str(primary_registry_path),
            "--primary-judge-discovery-run",
            str(primary_discovery_path),
            "--replay-judge-registry",
            str(replay_registry_path),
            "--replay-judge-discovery-run",
            str(replay_discovery_path),
            "--smoke-corpus",
            str(ROOT / "benchmarks" / "model_corpus_smoke"),
            "--smoke-run-index",
            "1",
            "--output",
            str(smoke_output),
            "--candidate-cost-cap-usd-per-attempt",
            "1.00",
            "--primary-judge-cost-cap-usd-per-attempt",
            "1.00",
            "--replay-judge-cost-cap-usd-per-attempt",
            "1.00",
            "--config",
            str(config_path),
            "--corpus",
            str(ROOT / "benchmarks" / "model_corpus" / "manifest.json"),
            "--cost-ledger",
            str(ledger.path),
            "--secrets-env-file",
            str(secret_path),
            "--allow-metadata-egress",
            "--live-route-preflight-only",
            "--no-color",
        ],
    )
    assert smoke_result.exit_code == 0, smoke_result.output
    factory = observed["factory"]
    assert isinstance(factory, candidate_fixtures._MockClientFactory)
    assert factory.request_bodies == []
    assert len(factory.clients) == 3
    assert tuple(usage.records) == usage_before
    assert ledger.snapshot() == ledger_before
    assert not smoke_output.exists()
    normalized = " ".join(smoke_result.output.split())
    assert "METADATA EGRESS ONLY / NO MODEL COMPLETION" in normalized
    assert f"candidate={SUCCESSOR_CANDIDATE}" in normalized
    assert f"primary_judge={PRIMARY_JUDGE}" in normalized
    assert f"replay_judge={REPLAY_JUDGE}" in normalized
    assert (
        "usage_records=0; budget=UNCHANGED; atomic_cost_ledger=UNCHANGED; output=NOT_PUBLISHED"
    ) in normalized
    assert SYNTHETIC_KEY not in discovery_result.output
    assert SYNTHETIC_KEY not in smoke_result.output
