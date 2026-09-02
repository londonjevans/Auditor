from __future__ import annotations

import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

import pytest
from typer.testing import CliRunner

import mmaudit.cli as cli_module
from mmaudit.config import AuditConfig
from mmaudit.constants import ExitCode
from mmaudit.models.candidate_registry_bridge import (
    derive_candidate_registry_from_discovery,
    validate_candidate_registry_template_selection,
    write_candidate_registry_json,
)
from mmaudit.models.candidate_revocation import CandidateSelectionRevocationError
from mmaudit.models.candidate_selection import (
    load_candidate_selection_plan,
    seal_authenticated_runner_route_predicate_profile,
    seal_authenticated_runner_selection,
    seal_candidate_selection_entry,
    seal_candidate_selection_plan,
    seal_candidate_selection_source_binding,
    validate_candidate_selection_plan_successor,
)
from mmaudit.models.discovery import (
    DiscoveryCandidateRoute,
    OpenRouterDiscoveryRunProvenance,
    OpenRouterModelDiscoveryEvidence,
    load_model_discovery_run,
)
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    LineageReviewStatus,
    load_candidate_registry,
    validate_candidate_registry_discovery,
)
from mmaudit.models.reasoning import (
    CANONICAL_REASONING_POLICY_ROLES,
    ReasoningControlProfile,
    ReasoningEffort,
    ReasoningPolicyArtifact,
)
from mmaudit.models.route_constraints import ExactRouteConstraint, ExactRouteRole
from mmaudit.privacy import PrivacyProfile
from mmaudit.reporting.json_report import stable_json
from tests.unit import test_candidate_benchmark as fixtures

ROOT = Path(__file__).parents[2]
RUNNER = CliRunner()
MODEL_ID = "alpha/atlas-secure"
PROVIDER_ENDPOINT = "provider-alpha"
REFRESHED_PROVIDER_ENDPOINT = "provider-alpha/new-fp8"
REVOKED_MODEL_ID = "deepseek/deepseek-v4-pro-0813"
REVOKED_CANONICAL_ALIAS = "deepseek/deepseek-v4-pro-20260813"
REVOKED_PROVIDER_ENDPOINT = "parasail/fp8"
CANARY = "synthetic-registry-bridge-canary"
RANKING_SOURCE = b"synthetic operator-staged ranking implementation\n"
LINEAGE_SOURCE = b"synthetic operator-staged lineage review\n"
HIGH_REASONING_EFFORTS: tuple[ReasoningEffort, ...] = (
    "none",
    "minimal",
    "low",
    "medium",
    "high",
    "xhigh",
)
NON_HIGH_REASONING_EFFORTS: tuple[ReasoningEffort, ...] = (
    "none",
    "minimal",
    "low",
    "medium",
    "xhigh",
)


def _config(config_factory: Callable[..., AuditConfig]) -> AuditConfig:
    return config_factory(
        privacy={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK},
        models={"reasoning": {"effort": "high", "reserved_tokens": 4_096}},
    )


def _selection_plan_paths(
    tmp_path: Path,
    *,
    model_id: str = MODEL_ID,
    provider_endpoint: str = PROVIDER_ENDPOINT,
    pin_revoked_candidate_route: bool = False,
) -> tuple[Path, Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    ranking_path = tmp_path / "model-ranking.py"
    lineage_path = tmp_path / "V3-LINEAGE-001-operator-review.md"
    ranking_path.write_bytes(RANKING_SOURCE)
    lineage_path.write_bytes(LINEAGE_SOURCE)
    sources = (
        seal_candidate_selection_source_binding(
            kind="MODEL_RANKING_IMPLEMENTATION",
            filename=ranking_path.name,
            content=RANKING_SOURCE,
        ),
        seal_candidate_selection_source_binding(
            kind="OPERATOR_LINEAGE_REVIEW",
            filename=lineage_path.name,
            content=LINEAGE_SOURCE,
        ),
    )
    if pin_revoked_candidate_route:
        entries = (
            seal_candidate_selection_entry(
                exact_model_id=REVOKED_MODEL_ID,
                priority_rank=1,
                advisory_lineage_group="Revoked historical advisory group",
                allowed_provider_endpoints=(REVOKED_PROVIDER_ENDPOINT,),
            ),
            seal_candidate_selection_entry(
                exact_model_id=model_id,
                priority_rank=2,
                advisory_lineage_group="Synthetic advisory group",
                allowed_provider_endpoints=(provider_endpoint,),
            ),
            seal_candidate_selection_entry(
                exact_model_id="beta/beacon-secure",
                priority_rank=3,
                advisory_lineage_group="Synthetic beta group",
                allowed_provider_endpoints=("provider-beta",),
            ),
            seal_candidate_selection_entry(
                exact_model_id="gamma/compass-secure",
                priority_rank=4,
                advisory_lineage_group="Synthetic gamma group",
                allowed_provider_endpoints=("provider-gamma",),
            ),
        )
    else:
        entries = (
            seal_candidate_selection_entry(
                exact_model_id=model_id,
                priority_rank=1,
                advisory_lineage_group="Synthetic advisory group",
                allowed_provider_endpoints=(provider_endpoint,),
            ),
            seal_candidate_selection_entry(
                exact_model_id="beta/beacon-secure",
                priority_rank=2,
                advisory_lineage_group="Synthetic beta group",
                allowed_provider_endpoints=("provider-beta",),
            ),
            seal_candidate_selection_entry(
                exact_model_id="gamma/compass-secure",
                priority_rank=3,
                advisory_lineage_group="Synthetic gamma group",
                allowed_provider_endpoints=("provider-gamma",),
            ),
        )
    control = ReasoningControlProfile.build(
        mode="effort",
        effort="high",
        reserved_reasoning_tokens=4_096,
    )
    policy = ReasoningPolicyArtifact.build(
        controls_by_role={role: control for role in CANONICAL_REASONING_POLICY_ROLES}
    )
    profile = seal_authenticated_runner_route_predicate_profile(
        reasoning_policy=policy,
        minimum_prompt_tokens=65_536,
        required_output_tokens=4_096,
        minimum_context_tokens=73_728,
    )
    constraints = (
        ExactRouteConstraint.build(
            role=ExactRouteRole.CANDIDATE,
            exact_model_id=(REVOKED_MODEL_ID if pin_revoked_candidate_route else model_id),
            provider_endpoint=(
                REVOKED_PROVIDER_ENDPOINT if pin_revoked_candidate_route else provider_endpoint
            ),
            profile=profile,
        ),
        ExactRouteConstraint.build(
            role=ExactRouteRole.PRIMARY_JUDGE,
            exact_model_id="beta/beacon-secure",
            provider_endpoint="provider-beta",
            profile=profile,
        ),
        ExactRouteConstraint.build(
            role=ExactRouteRole.REPLAY_JUDGE,
            exact_model_id="gamma/compass-secure",
            provider_endpoint="provider-gamma",
            profile=profile,
        ),
    )
    plan = seal_candidate_selection_plan(
        source_bindings=sources,
        entries=entries,
        authenticated_runner_selection=seal_authenticated_runner_selection(
            candidate_model_id=(REVOKED_MODEL_ID if pin_revoked_candidate_route else model_id),
            primary_judge_model_id="beta/beacon-secure",
            replay_judge_model_id="gamma/compass-secure",
            route_predicate_profile=profile,
            route_constraints=constraints,
        ),
    )
    plan_path = tmp_path / "candidate-selection-plan.json"
    plan_path.write_text(stable_json(plan), encoding="utf-8")
    return plan_path, ranking_path, lineage_path


def _selection_plan_paths_with_revoked_identity_as_judge(
    tmp_path: Path,
    *,
    role: ExactRouteRole,
) -> tuple[Path, Path, Path]:
    assert role in {ExactRouteRole.PRIMARY_JUDGE, ExactRouteRole.REPLAY_JUDGE}
    plan_path, ranking_path, lineage_path = _selection_plan_paths(tmp_path)
    base = load_candidate_selection_plan(plan_path)
    selection = base.authenticated_runner_selection
    assert selection is not None
    constraints = tuple(
        sorted(
            (
                ExactRouteConstraint.build(
                    role=role,
                    exact_model_id=REVOKED_MODEL_ID,
                    provider_endpoint=REVOKED_PROVIDER_ENDPOINT,
                    profile=selection.route_predicate_profile,
                ),
                *(
                    constraint
                    for constraint in selection.route_constraints
                    if constraint.role is not role
                ),
            ),
            key=lambda item: (item.role.value, item.exact_model_id, item.provider_endpoint),
        )
    )
    updated = seal_candidate_selection_plan(
        source_bindings=base.source_bindings,
        entries=(
            *base.entries,
            seal_candidate_selection_entry(
                exact_model_id=REVOKED_MODEL_ID,
                priority_rank=4,
                advisory_lineage_group="Candidate-tombstone identity judge group",
                allowed_provider_endpoints=(REVOKED_PROVIDER_ENDPOINT,),
            ),
        ),
        authenticated_runner_selection=seal_authenticated_runner_selection(
            candidate_model_id=selection.candidate_model_id,
            primary_judge_model_id=(
                REVOKED_MODEL_ID
                if role is ExactRouteRole.PRIMARY_JUDGE
                else selection.primary_judge_model_id
            ),
            replay_judge_model_id=(
                REVOKED_MODEL_ID
                if role is ExactRouteRole.REPLAY_JUDGE
                else selection.replay_judge_model_id
            ),
            route_predicate_profile=selection.route_predicate_profile,
            route_constraints=constraints,
        ),
    )
    plan_path.write_text(stable_json(updated), encoding="utf-8")
    return plan_path, ranking_path, lineage_path


def test_emit_selection_plan_successor_is_provider_free_deterministic_and_fresh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan_path, ranking_path, lineage_path = _selection_plan_paths(
        tmp_path / "inputs",
        pin_revoked_candidate_route=True,
    )
    predecessor = load_candidate_selection_plan(plan_path)
    frozen_inputs = {
        plan_path: plan_path.read_bytes(),
        ranking_path: ranking_path.read_bytes(),
        lineage_path: lineage_path.read_bytes(),
    }
    external_access: list[str] = []

    def forbidden_external_access(*_args: object, **_kwargs: object) -> None:
        external_access.append("accessed")
        raise AssertionError("successor emission must remain provider-free")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_external_access)
    monkeypatch.setattr(cli_module, "OpenRouterClient", forbidden_external_access)

    outputs = (
        tmp_path / "private-a" / "successor.json",
        tmp_path / "private-b" / "successor.json",
    )
    successors = []
    for output in outputs:
        result = RUNNER.invoke(
            cli_module.app,
            [
                "models",
                "emit-selection-plan-successor",
                "--predecessor-plan",
                str(plan_path),
                "--candidate",
                f"{MODEL_ID}={PROVIDER_ENDPOINT}",
                "--output",
                str(output),
                "--no-color",
            ],
        )
        assert result.exit_code == 0, result.output
        normalized_output = " ".join(result.output.split())
        assert "NONAUTHORIZING" in normalized_output
        assert "no provider access occurred" in normalized_output
        assert output.stat().st_mode & 0o777 == 0o600
        successor = load_candidate_selection_plan(output)
        assert (
            validate_candidate_selection_plan_successor(
                predecessor=predecessor,
                successor=successor,
            )
            == successor
        )
        successors.append(successor)

    assert successors[0] == successors[1]
    selection = successors[0].authenticated_runner_selection
    assert selection is not None
    assert selection.candidate_model_id == MODEL_ID
    assert tuple(
        (constraint.role, constraint.exact_model_id, constraint.provider_endpoint)
        for constraint in selection.route_constraints
    ) == (
        (ExactRouteRole.CANDIDATE, MODEL_ID, PROVIDER_ENDPOINT),
        (ExactRouteRole.PRIMARY_JUDGE, "beta/beacon-secure", "provider-beta"),
        (ExactRouteRole.REPLAY_JUDGE, "gamma/compass-secure", "provider-gamma"),
    )
    assert all(path.read_bytes() == content for path, content in frozen_inputs.items())
    assert external_access == []

    revoked_output = tmp_path / "private-c" / "revoked-successor.json"
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "emit-selection-plan-successor",
            "--predecessor-plan",
            str(outputs[0]),
            "--candidate",
            f"{REVOKED_MODEL_ID}={REVOKED_PROVIDER_ENDPOINT}",
            "--output",
            str(revoked_output),
            "--no-color",
        ],
    )
    assert result.exit_code == ExitCode.CONFIGURATION
    assert "candidate selection route is revoked" in " ".join(result.output.split())
    assert not revoked_output.exists()
    assert external_access == []


def test_emit_selection_plan_successor_requires_explicit_unverified_endpoint_refresh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan_path, _ranking_path, _lineage_path = _selection_plan_paths(
        tmp_path / "inputs",
        pin_revoked_candidate_route=True,
    )
    predecessor = load_candidate_selection_plan(plan_path)

    def forbidden_external_access(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("endpoint inventory staging must remain provider-free")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_external_access)
    monkeypatch.setattr(cli_module, "OpenRouterClient", forbidden_external_access)

    refused_output = tmp_path / "private-a" / "refused.json"
    refused = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "emit-selection-plan-successor",
            "--predecessor-plan",
            str(plan_path),
            "--candidate",
            f"{MODEL_ID}={REFRESHED_PROVIDER_ENDPOINT}",
            "--output",
            str(refused_output),
            "--no-color",
        ],
    )
    assert refused.exit_code == ExitCode.CONFIGURATION
    assert "uses an unlisted endpoint" in " ".join(refused.output.split())
    assert not refused_output.exists()

    output = tmp_path / "private-b" / "refreshed.json"
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "emit-selection-plan-successor",
            "--predecessor-plan",
            str(plan_path),
            "--candidate",
            f"{MODEL_ID}={REFRESHED_PROVIDER_ENDPOINT}",
            "--refresh-endpoint-inventory",
            "--output",
            str(output),
            "--no-color",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "staged as unverified" in " ".join(result.output.split())
    successor = load_candidate_selection_plan(output)
    assert successor.schema_version == "1.6"
    assert successor.endpoint_inventory_refresh is not None
    assert successor.endpoint_inventory_refresh.provider_endpoint == (REFRESHED_PROVIDER_ENDPOINT)
    assert successor.endpoint_inventory_refresh.endpoint_authority is False
    assert (
        validate_candidate_selection_plan_successor(
            predecessor=predecessor,
            successor=successor,
        )
        == successor
    )


@pytest.mark.parametrize(
    "model_id",
    (REVOKED_MODEL_ID, REVOKED_CANONICAL_ALIAS),
)
@pytest.mark.parametrize("bridge_mode", ("plain", "template"))
def test_discover_rejects_tombstoned_alias_before_any_downstream_access(
    model_id: str,
    bridge_mode: Literal["plain", "template", "plan"],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    downstream_access: list[str] = []

    def forbidden_access(*_args: object, **_kwargs: object) -> None:
        downstream_access.append("accessed")
        raise AssertionError("revoked discovery must reject before downstream access")

    for name in (
        "load_candidate_registry",
        "load_candidate_selection_plan",
        "read_candidate_selection_source",
        "preflight_candidate_registry_output",
        "_preflight_model_discovery_output_dir",
        "load_config",
        "load_operator_secrets",
        "OpenRouterClient",
    ):
        monkeypatch.setattr(cli_module, name, forbidden_access)

    discovery_output = tmp_path / "discovery"
    registry_output = tmp_path / "registry.json"
    arguments = [
        "models",
        "discover",
        "--candidate",
        f"{model_id}={REVOKED_PROVIDER_ENDPOINT}",
        "--output-dir",
        str(discovery_output),
        "--no-color",
    ]
    if bridge_mode == "template":
        arguments.extend(
            (
                "--candidate-registry-template",
                str(tmp_path / "missing-template.json"),
                "--candidate-registry-output",
                str(registry_output),
            )
        )
    elif bridge_mode == "plan":
        arguments.extend(
            (
                "--candidate-selection-plan",
                str(tmp_path / "missing-plan.json"),
                "--candidate-selection-ranking-source",
                str(tmp_path / "model-ranking.py"),
                "--candidate-selection-lineage-review-source",
                str(tmp_path / "V3-LINEAGE-001-operator-review.md"),
                "--candidate-registry-output",
                str(registry_output),
            )
        )

    result = RUNNER.invoke(cli_module.app, arguments)

    assert result.exit_code == ExitCode.CONFIGURATION
    output = " ".join(result.output.split())
    assert "candidate selection assignment is revoked" in output
    assert "role=candidate" in output
    assert f"model={model_id}" in output
    assert "endpoint=parasail/fp8" in output
    assert "reason=EMPIRICAL_STRUCTURED_OUTPUT_NONCONFORMANCE" in output
    assert downstream_access == []
    assert not discovery_output.exists()
    assert not registry_output.exists()


def test_discover_unrevoked_route_reaches_staged_source_validation_with_stale_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    downstream_access: list[str] = []

    def source_probe(*_args: object, **_kwargs: object) -> bytes:
        downstream_access.append("source")
        raise ValueError("unrevoked route reached staged source validation")

    def forbidden_access(*_args: object, **_kwargs: object) -> None:
        downstream_access.append("accessed")
        raise AssertionError("source validation failure must reject before later access")

    monkeypatch.setattr(cli_module, "read_candidate_selection_source", source_probe)
    for name in (
        "preflight_candidate_registry_output",
        "_preflight_model_discovery_output_dir",
        "load_config",
        "load_operator_secrets",
        "OpenRouterClient",
    ):
        monkeypatch.setattr(cli_module, name, forbidden_access)

    discovery_output = tmp_path / "discovery"
    registry_output = tmp_path / "registry.json"
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            "moonshotai/kimi-k3=modal/mxfp4",
            "--candidate-selection-plan",
            str(ROOT / "config" / "models.selection-plan.json"),
            "--candidate-selection-ranking-source",
            str(tmp_path / "model-ranking.py"),
            "--candidate-selection-lineage-review-source",
            str(tmp_path / "V3-LINEAGE-001-operator-review.md"),
            "--candidate-registry-output",
            str(registry_output),
            "--output-dir",
            str(discovery_output),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "unrevoked route reached staged source validation" in " ".join(result.output.split())
    assert downstream_access == ["source"]
    assert not discovery_output.exists()
    assert not registry_output.exists()


def test_discover_valid_plan_rejects_candidate_tombstone_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan_path, ranking_path, lineage_path = _selection_plan_paths(
        tmp_path / "selection",
        model_id="moonshotai/kimi-k3",
        provider_endpoint="modal/mxfp4",
        pin_revoked_candidate_route=True,
    )
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("revoked candidate must reject before secret access")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    discovery_output = tmp_path / "discovery"
    registry_output = tmp_path / "registry.json"
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            f"{REVOKED_MODEL_ID}={REVOKED_PROVIDER_ENDPOINT}",
            "--candidate-selection-plan",
            str(plan_path),
            "--candidate-selection-ranking-source",
            str(ranking_path),
            "--candidate-selection-lineage-review-source",
            str(lineage_path),
            "--candidate-registry-output",
            str(registry_output),
            "--output-dir",
            str(discovery_output),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    output = " ".join(result.output.split())
    assert "role=candidate" in output
    assert f"model={REVOKED_MODEL_ID}" in output
    assert f"endpoint={REVOKED_PROVIDER_ENDPOINT}" in output
    assert "reason=EMPIRICAL_STRUCTURED_OUTPUT_NONCONFORMANCE" in output
    assert secret_accessed is False
    assert not discovery_output.exists()
    assert not registry_output.exists()


@pytest.mark.parametrize(
    ("model_id", "canonical_model_id"),
    (
        (REVOKED_MODEL_ID, None),
        (REVOKED_CANONICAL_ALIAS, None),
        ("deepseek/deepseek-v4-pro-observed-0813", REVOKED_CANONICAL_ALIAS),
    ),
)
def test_registry_template_validation_rejects_tombstoned_alias(
    model_id: str,
    canonical_model_id: str | None,
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    spec = fixtures._CandidateSpec(
        model_id=model_id,
        provider_endpoint=REVOKED_PROVIDER_ENDPOINT,
        provider_name="Synthetic Parasail",
        canonical_model_id=canonical_model_id,
    )
    _manifest, _evidence, template = fixtures._discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=(spec,),
    )

    with pytest.raises(CandidateSelectionRevocationError, match="assignment is revoked"):
        validate_candidate_registry_template_selection(
            template=template,
            routes=(
                DiscoveryCandidateRoute(
                    exact_model_id=model_id,
                    approved_provider_endpoint=REVOKED_PROVIDER_ENDPOINT,
                ),
            ),
        )


@pytest.mark.parametrize(
    ("model_id", "provider_endpoint"),
    (
        (REVOKED_MODEL_ID, "parasail/fp16"),
        ("deepseek/deepseek-v4-pro-0814", REVOKED_PROVIDER_ENDPOINT),
    ),
)
def test_registry_template_validation_allows_adjacent_endpoint_or_model(
    model_id: str,
    provider_endpoint: str,
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    spec = fixtures._CandidateSpec(
        model_id=model_id,
        provider_endpoint=provider_endpoint,
        provider_name="Synthetic Parasail",
    )
    _manifest, _evidence, template = fixtures._discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=(spec,),
    )

    assert (
        validate_candidate_registry_template_selection(
            template=template,
            routes=(
                DiscoveryCandidateRoute(
                    exact_model_id=model_id,
                    approved_provider_endpoint=provider_endpoint,
                ),
            ),
        )
        == template
    )


def test_registry_derivation_rejects_fresh_tombstoned_canonical_identity(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    exact_model_id = "deepseek/deepseek-v4-pro-observed-0813"
    _template_manifest, _template_evidence, template = fixtures._discovery_and_registry(
        tmp_path=tmp_path / "template",
        config=config,
        specs=(
            fixtures._CandidateSpec(
                model_id=exact_model_id,
                canonical_model_id="deepseek/deepseek-v4-pro-adjacent-0813",
                provider_endpoint=REVOKED_PROVIDER_ENDPOINT,
                provider_name="Synthetic Parasail",
            ),
        ),
    )
    manifest, evidence, _fresh_registry = fixtures._discovery_and_registry(
        tmp_path=tmp_path / "fresh",
        config=config,
        specs=(
            fixtures._CandidateSpec(
                model_id=exact_model_id,
                canonical_model_id=REVOKED_CANONICAL_ALIAS,
                provider_endpoint=REVOKED_PROVIDER_ENDPOINT,
                provider_name="Synthetic Parasail",
            ),
        ),
    )

    with pytest.raises(CandidateSelectionRevocationError, match="assignment is revoked"):
        derive_candidate_registry_from_discovery(
            template=template,
            run_manifest=manifest,
            evidence=evidence,
        )


@pytest.mark.parametrize(
    "option",
    ("--candidate-registry-template", "--candidate-registry-output"),
)
def test_discover_registry_bridge_requires_paired_options_before_secret_access(
    option: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            f"{MODEL_ID}={PROVIDER_ENDPOINT}",
            option,
            str(tmp_path / "registry.json"),
            "--output-dir",
            str(tmp_path / "discovery"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "must be supplied together" in result.output
    assert not secret_accessed


def test_discover_registry_bridge_rejects_template_endpoint_drift_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            "deepcogito/cogito-v2.1-671b=provider-drift",
            "--candidate-registry-template",
            str(ROOT / "config" / "models.candidates.toml"),
            "--candidate-registry-output",
            str(tmp_path / "fresh-registry.json"),
            "--output-dir",
            str(tmp_path / "discovery"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "operator-approved template endpoint" in result.output
    assert not secret_accessed
    assert not (tmp_path / "fresh-registry.json").exists()


def test_discover_registry_bridge_rejects_output_inside_discovery_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    discovery = tmp_path / "discovery"
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            f"{MODEL_ID}={PROVIDER_ENDPOINT}",
            "--candidate-registry-template",
            str(tmp_path / "missing-template.json"),
            "--candidate-registry-output",
            str(discovery / "fresh-registry.json"),
            "--output-dir",
            str(discovery),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "outside the discovery directory" in " ".join(result.output.split())
    assert not secret_accessed
    assert not discovery.exists()


def test_discover_selection_plan_requires_complete_inputs_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    plan_path, _ranking_path, _lineage_path = _selection_plan_paths(tmp_path)
    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            f"{MODEL_ID}={PROVIDER_ENDPOINT}",
            "--candidate-selection-plan",
            str(plan_path),
            "--output-dir",
            str(tmp_path / "discovery"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "must be supplied together" in result.output
    assert not secret_accessed
    assert not (tmp_path / "discovery").exists()


def test_discover_selection_plan_requires_registry_output_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    plan_path, ranking_path, lineage_path = _selection_plan_paths(tmp_path)
    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            f"{MODEL_ID}={PROVIDER_ENDPOINT}",
            "--candidate-selection-plan",
            str(plan_path),
            "--candidate-selection-ranking-source",
            str(ranking_path),
            "--candidate-selection-lineage-review-source",
            str(lineage_path),
            "--output-dir",
            str(tmp_path / "discovery"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "requires --candidate-registry-output" in " ".join(result.output.split())
    assert not secret_accessed
    assert not (tmp_path / "discovery").exists()


def test_discover_selection_plan_rejects_output_aliasing_source_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    plan_path, ranking_path, lineage_path = _selection_plan_paths(tmp_path)
    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            f"{MODEL_ID}={PROVIDER_ENDPOINT}",
            "--candidate-selection-plan",
            str(plan_path),
            "--candidate-selection-ranking-source",
            str(ranking_path),
            "--candidate-selection-lineage-review-source",
            str(lineage_path),
            "--candidate-registry-output",
            str(ranking_path),
            "--output-dir",
            str(tmp_path / "discovery"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "differ from every bridge input" in " ".join(result.output.split())
    assert not secret_accessed
    assert not (tmp_path / "discovery").exists()


def test_discover_selection_plan_rejects_unlisted_route_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    plan_path, ranking_path, lineage_path = _selection_plan_paths(tmp_path)
    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    registry_output = tmp_path / "fresh-registry.json"
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            f"{MODEL_ID}=provider-drift",
            "--candidate-selection-plan",
            str(plan_path),
            "--candidate-selection-ranking-source",
            str(ranking_path),
            "--candidate-selection-lineage-review-source",
            str(lineage_path),
            "--candidate-registry-output",
            str(registry_output),
            "--output-dir",
            str(tmp_path / "discovery"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "unlisted endpoint" in result.output
    assert not secret_accessed
    assert not registry_output.exists()
    assert not (tmp_path / "discovery").exists()


def test_discover_selection_plan_rejects_source_drift_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    plan_path, ranking_path, lineage_path = _selection_plan_paths(tmp_path)
    ranking_path.write_bytes(RANKING_SOURCE + b"tamper")
    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            f"{MODEL_ID}={PROVIDER_ENDPOINT}",
            "--candidate-selection-plan",
            str(plan_path),
            "--candidate-selection-ranking-source",
            str(ranking_path),
            "--candidate-selection-lineage-review-source",
            str(lineage_path),
            "--candidate-registry-output",
            str(tmp_path / "fresh-registry.json"),
            "--output-dir",
            str(tmp_path / "discovery"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "differs from its binding" in result.output
    assert not secret_accessed
    assert not (tmp_path / "discovery").exists()


def test_discover_selection_plan_rejects_source_filename_before_reading_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_read = False
    secret_accessed = False

    def forbidden_source_read(_path: Path) -> bytes:
        nonlocal source_read
        source_read = True
        raise AssertionError("mismatched source filename must reject before reading")

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    plan_path, ranking_path, lineage_path = _selection_plan_paths(tmp_path)
    renamed_ranking = ranking_path.with_name("renamed-ranking.py")
    ranking_path.rename(renamed_ranking)
    monkeypatch.setattr(cli_module, "read_candidate_selection_source", forbidden_source_read)
    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            f"{MODEL_ID}={PROVIDER_ENDPOINT}",
            "--candidate-selection-plan",
            str(plan_path),
            "--candidate-selection-ranking-source",
            str(renamed_ranking),
            "--candidate-selection-lineage-review-source",
            str(lineage_path),
            "--candidate-registry-output",
            str(tmp_path / "fresh-registry.json"),
            "--output-dir",
            str(tmp_path / "discovery"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "source filename differs" in " ".join(result.output.split())
    assert not source_read
    assert not secret_accessed
    assert not (tmp_path / "discovery").exists()


def test_discover_selection_plan_is_exclusive_with_legacy_template(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    plan_path, ranking_path, lineage_path = _selection_plan_paths(tmp_path)
    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_secret_access)
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            f"{MODEL_ID}={PROVIDER_ENDPOINT}",
            "--candidate-registry-template",
            str(ROOT / "config" / "models.candidates.toml"),
            "--candidate-selection-plan",
            str(plan_path),
            "--candidate-selection-ranking-source",
            str(ranking_path),
            "--candidate-selection-lineage-review-source",
            str(lineage_path),
            "--candidate-registry-output",
            str(tmp_path / "fresh-registry.json"),
            "--output-dir",
            str(tmp_path / "discovery"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "mutually exclusive" in result.output
    assert not secret_accessed
    assert not (tmp_path / "discovery").exists()


def test_discover_registry_bridge_publishes_exact_selected_registry_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    spec = fixtures._CandidateSpec(
        model_id=MODEL_ID,
        provider_endpoint=PROVIDER_ENDPOINT,
        provider_name="Provider Alpha",
    )
    _fixture_manifest, sealed_evidence, template = fixtures._discovery_and_registry(
        tmp_path=tmp_path / "fixture-discovery",
        config=config,
        specs=(spec,),
    )
    template_path = tmp_path / "template" / "candidate-template.json"
    write_candidate_registry_json(template_path, template)
    secret_file = tmp_path / "synthetic-secrets.env"
    secret_file.write_text(f"OPENROUTER_API_KEY={CANARY}\n", encoding="utf-8")
    secret_file.chmod(0o600)

    endpoint = fixtures._endpoint(spec)
    catalog_payload = {"data": [fixtures._catalog_model(spec)]}
    endpoint_payload = {
        "data": {
            "id": MODEL_ID,
            "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
        }
    }

    class ProviderFreeDiscoveryClient:
        def __init__(self, *, api_key: str, **_kwargs: object) -> None:
            assert api_key == CANARY

        async def validate_authentication(self) -> None:
            return None

        async def get_certification_model_metadata(self) -> dict[str, Any]:
            return catalog_payload

        async def list_zdr_endpoints(self) -> dict[str, Any]:
            return {"data": [endpoint]}

        async def get_model_metadata(self, model_id: str) -> dict[str, Any]:
            assert model_id == MODEL_ID
            return {"data": fixtures._catalog_model(spec)}

        async def get_model_endpoint_metadata(self, model_id: str) -> dict[str, Any]:
            assert model_id == MODEL_ID
            return endpoint_payload

        def seal_real_model_discovery_run(
            self,
            **kwargs: Any,
        ) -> tuple[
            OpenRouterDiscoveryRunProvenance,
            tuple[OpenRouterModelDiscoveryEvidence, ...],
        ]:
            assert tuple(item.exact_model_id for item in kwargs["payloads"]) == (MODEL_ID,)
            return sealed_evidence[0].provenance, sealed_evidence

        async def close(self) -> None:
            return None

    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(cli_module, "OpenRouterClient", ProviderFreeDiscoveryClient)
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_CLIENT_TYPE",
        ProviderFreeDiscoveryClient,
    )
    discovery_output = tmp_path / "private" / "fresh-discovery"
    registry_output = tmp_path / "private" / "fresh-registry.json"
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            f"{MODEL_ID}={PROVIDER_ENDPOINT}",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--secrets-env-file",
            str(secret_file),
            "--output-dir",
            str(discovery_output),
            "--candidate-registry-template",
            str(template_path),
            "--candidate-registry-output",
            str(registry_output),
            "--no-color",
        ],
    )

    assert result.exit_code == 0, result.output
    manifest, evidence = load_model_discovery_run(discovery_output)
    registry = load_candidate_registry(registry_output)
    validate_candidate_registry_discovery(
        registry=registry,
        run_manifest=manifest,
        evidence=evidence,
    )
    assert tuple(candidate.exact_model_id for candidate in registry.candidates) == (MODEL_ID,)
    assert registry.candidates[0].benchmark_status is CandidateBenchmarkStatus.PENDING
    assert stat.S_IMODE(registry_output.stat().st_mode) == 0o600
    assert CANARY not in result.output


@pytest.mark.parametrize(
    ("model_id", "provider_endpoint", "pin_revoked_candidate_route"),
    (
        (MODEL_ID, PROVIDER_ENDPOINT, False),
        (MODEL_ID, PROVIDER_ENDPOINT, True),
        ("minimax/minimax-m3", "coreweave/fp4", True),
        ("google/gemma-4-26b-a4b-it", "deepinfra/fp8", True),
        ("tencent/hy3", "novita", True),
    ),
)
def test_discover_selection_plan_publishes_rootless_registry_from_fresh_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    model_id: str,
    provider_endpoint: str,
    pin_revoked_candidate_route: bool,
) -> None:
    config = _config(config_factory)
    plan_path, ranking_path, lineage_path = _selection_plan_paths(
        tmp_path / "selection",
        model_id=model_id,
        provider_endpoint=provider_endpoint,
        pin_revoked_candidate_route=pin_revoked_candidate_route,
    )
    selection_plan = load_candidate_selection_plan(plan_path)
    spec = fixtures._CandidateSpec(
        model_id=model_id,
        provider_endpoint=provider_endpoint,
        provider_name="Synthetic provider",
        canonical_model_id=f"{model_id}-canonical-20260828",
        native_structured_output_parameter="structured_outputs",
    )
    discovery_kwargs: dict[str, object] = {}
    if not pin_revoked_candidate_route:
        discovery_kwargs = {
            "route_role": ExactRouteRole.CANDIDATE,
            "selection_plan_sha256": selection_plan.plan_sha256,
            "route_predicate_profile": (
                selection_plan.authenticated_runner_selection.route_predicate_profile
            ),
        }
    _fixture_manifest, sealed_evidence, _template = fixtures._discovery_and_registry(
        tmp_path=tmp_path / "fixture-discovery",
        config=config,
        specs=(spec,),
        **discovery_kwargs,
    )
    secret_file = tmp_path / "synthetic-secrets.env"
    secret_file.write_text(f"OPENROUTER_API_KEY={CANARY}\n", encoding="utf-8")
    secret_file.chmod(0o600)
    endpoint = fixtures._endpoint(spec)
    catalog_payload = {"data": [fixtures._catalog_model(spec)]}
    endpoint_payload = {
        "data": {
            "id": model_id,
            "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
        }
    }

    class ProviderFreeSelectionClient:
        def __init__(self, *, api_key: str, **_kwargs: object) -> None:
            assert api_key == CANARY
            reasoning_policy = _kwargs.get("reasoning_policy")
            assert type(reasoning_policy) is ReasoningPolicyArtifact
            assert (
                reasoning_policy.artifact_sha256
                == selection_plan.authenticated_runner_selection.route_predicate_profile.reasoning_policy_sha256
            )

        async def validate_authentication(self) -> None:
            return None

        async def get_certification_model_metadata(self) -> dict[str, Any]:
            return catalog_payload

        async def list_zdr_endpoints(self) -> dict[str, Any]:
            return {"data": [endpoint]}

        async def get_model_metadata(self, model_id: str) -> dict[str, Any]:
            assert model_id == spec.model_id
            return {"data": fixtures._catalog_model(spec)}

        async def get_model_endpoint_metadata(self, model_id: str) -> dict[str, Any]:
            assert model_id == spec.model_id
            return endpoint_payload

        def seal_real_model_discovery_run(
            self,
            **kwargs: Any,
        ) -> tuple[
            OpenRouterDiscoveryRunProvenance,
            tuple[OpenRouterModelDiscoveryEvidence, ...],
        ]:
            assert tuple(item.exact_model_id for item in kwargs["payloads"]) == (spec.model_id,)
            return sealed_evidence[0].provenance, sealed_evidence

        async def close(self) -> None:
            return None

    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(cli_module, "OpenRouterClient", ProviderFreeSelectionClient)
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_CLIENT_TYPE",
        ProviderFreeSelectionClient,
    )
    discovery_output = tmp_path / "private" / "fresh-selection-discovery"
    registry_output = tmp_path / "private" / "fresh-selection-registry.json"
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            f"{model_id}={provider_endpoint}",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--secrets-env-file",
            str(secret_file),
            "--output-dir",
            str(discovery_output),
            "--candidate-selection-plan",
            str(plan_path),
            "--candidate-selection-ranking-source",
            str(ranking_path),
            "--candidate-selection-lineage-review-source",
            str(lineage_path),
            "--candidate-registry-output",
            str(registry_output),
            "--no-color",
        ],
    )

    assert result.exit_code == 0, result.output
    manifest, evidence = load_model_discovery_run(discovery_output)
    registry = load_candidate_registry(registry_output)
    validate_candidate_registry_discovery(
        registry=registry,
        run_manifest=manifest,
        evidence=evidence,
    )
    candidate = registry.candidates[0]
    assert candidate.exact_model_id == model_id
    assert candidate.root_lineage is None
    assert candidate.lineage_review.status is LineageReviewStatus.PENDING
    assert candidate.approved_roles == ()
    assert candidate.output_capability_sha256 == evidence[0].output_capability_sha256
    assert stat.S_IMODE(registry_output.stat().st_mode) == 0o600
    assert CANARY not in result.output


@pytest.mark.parametrize(
    "role",
    (ExactRouteRole.PRIMARY_JUDGE, ExactRouteRole.REPLAY_JUDGE),
)
def test_discover_selection_plan_preserves_exact_judge_role_for_candidate_tombstone_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    role: ExactRouteRole,
) -> None:
    config = _config(config_factory)
    plan_path, ranking_path, lineage_path = _selection_plan_paths_with_revoked_identity_as_judge(
        tmp_path / "selection",
        role=role,
    )
    selection_plan = load_candidate_selection_plan(plan_path)
    selection = selection_plan.authenticated_runner_selection
    assert selection is not None
    spec = fixtures._CandidateSpec(
        model_id=REVOKED_MODEL_ID,
        provider_endpoint=REVOKED_PROVIDER_ENDPOINT,
        provider_name="Synthetic Parasail",
        canonical_model_id=REVOKED_CANONICAL_ALIAS,
        native_structured_output_parameter="structured_outputs",
    )
    _fixture_manifest, sealed_evidence, _template = fixtures._discovery_and_registry(
        tmp_path=tmp_path / "fixture-discovery",
        config=config,
        specs=(spec,),
        route_role=role,
        selection_plan_sha256=selection_plan.plan_sha256,
        route_predicate_profile=selection.route_predicate_profile,
    )
    route_constraint = sealed_evidence[0].endpoint_snapshot.exact_route_constraint
    assert type(route_constraint) is ExactRouteConstraint
    secret_file = tmp_path / "synthetic-secrets.env"
    secret_file.write_text(f"OPENROUTER_API_KEY={CANARY}\n", encoding="utf-8")
    secret_file.chmod(0o600)
    endpoint = fixtures._endpoint(spec)
    catalog_payload = {"data": [fixtures._catalog_model(spec)]}
    endpoint_payload = {
        "data": {
            "id": REVOKED_MODEL_ID,
            "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
        }
    }
    constructor_constraints: list[ExactRouteConstraint | None] = []

    class ProviderFreeJudgeSelectionClient:
        def __init__(self, *, api_key: str, **kwargs: object) -> None:
            assert api_key == CANARY
            supplied_constraint = kwargs.get("candidate_revocation_route_constraint")
            assert supplied_constraint is None or type(supplied_constraint) is ExactRouteConstraint
            constructor_constraints.append(supplied_constraint)
            assert supplied_constraint == route_constraint
            assert kwargs.get("provider_policy") == cli_module.OpenRouterProviderPolicy(
                only=(REVOKED_PROVIDER_ENDPOINT,),
                allow_fallbacks=False,
            )

        async def validate_authentication(self) -> None:
            return None

        async def get_certification_model_metadata(self) -> dict[str, Any]:
            return catalog_payload

        async def list_zdr_endpoints(self) -> dict[str, Any]:
            return {"data": [endpoint]}

        async def get_model_metadata(self, model_id: str) -> dict[str, Any]:
            assert model_id == REVOKED_MODEL_ID
            return {"data": fixtures._catalog_model(spec)}

        async def get_model_endpoint_metadata(self, model_id: str) -> dict[str, Any]:
            assert model_id == REVOKED_MODEL_ID
            return endpoint_payload

        def seal_real_model_discovery_run(
            self,
            **kwargs: Any,
        ) -> tuple[
            OpenRouterDiscoveryRunProvenance,
            tuple[OpenRouterModelDiscoveryEvidence, ...],
        ]:
            assert tuple(item.exact_model_id for item in kwargs["payloads"]) == (REVOKED_MODEL_ID,)
            return sealed_evidence[0].provenance, sealed_evidence

        async def close(self) -> None:
            return None

    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(cli_module, "OpenRouterClient", ProviderFreeJudgeSelectionClient)
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_CLIENT_TYPE",
        ProviderFreeJudgeSelectionClient,
    )
    discovery_output = tmp_path / "private" / f"{role.value}-discovery"
    registry_output = tmp_path / "private" / f"{role.value}-registry.json"
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            f"{REVOKED_MODEL_ID}={REVOKED_PROVIDER_ENDPOINT}",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--secrets-env-file",
            str(secret_file),
            "--output-dir",
            str(discovery_output),
            "--candidate-selection-plan",
            str(plan_path),
            "--candidate-selection-ranking-source",
            str(ranking_path),
            "--candidate-selection-lineage-review-source",
            str(lineage_path),
            "--candidate-registry-output",
            str(registry_output),
            "--no-color",
        ],
    )

    assert result.exit_code == 0, result.output
    assert constructor_constraints == [route_constraint]
    manifest, evidence = load_model_discovery_run(discovery_output)
    registry = load_candidate_registry(registry_output)
    validate_candidate_registry_discovery(
        registry=registry,
        run_manifest=manifest,
        evidence=evidence,
    )
    assert registry.candidates[0].exact_model_id == REVOKED_MODEL_ID


@pytest.mark.parametrize(
    (
        "native_parameter",
        "endpoint_reasoning_efforts",
        "completion_limit_published",
        "expected",
    ),
    (
        (None, HIGH_REASONING_EFFORTS, True, "required structured-output mode"),
        ("json_schema", HIGH_REASONING_EFFORTS, True, "MODEL_NATIVE_MARKER_MISSING"),
        (
            "structured_outputs",
            NON_HIGH_REASONING_EFFORTS,
            True,
            "REASONING_EFFORT_UNSUPPORTED",
        ),
        (
            "structured_outputs",
            HIGH_REASONING_EFFORTS,
            False,
            "COMPLETION_CAPACITY_NOT_METADATA",
        ),
    ),
)
def test_discover_selection_plan_rejects_ineligible_runner_route_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    native_parameter: Literal["json_schema", "structured_outputs"] | None,
    endpoint_reasoning_efforts: tuple[ReasoningEffort, ...],
    completion_limit_published: bool,
    expected: str,
) -> None:
    config = _config(config_factory)
    spec = fixtures._CandidateSpec(
        model_id=MODEL_ID,
        provider_endpoint=PROVIDER_ENDPOINT,
        provider_name="Provider Alpha",
        canonical_model_id="alpha/atlas-secure-20260820",
        native_structured_output_parameter=native_parameter,
        endpoint_reasoning_efforts=endpoint_reasoning_efforts,
        endpoint_completion_limit_published=completion_limit_published,
    )
    plan_path, ranking_path, lineage_path = _selection_plan_paths(tmp_path / "selection")
    secret_file = tmp_path / "synthetic-secrets.env"
    secret_file.write_text(f"OPENROUTER_API_KEY={CANARY}\n", encoding="utf-8")
    secret_file.chmod(0o600)
    endpoint = fixtures._endpoint(spec)
    catalog_payload = {"data": [fixtures._catalog_model(spec)]}
    endpoint_payload = {
        "data": {
            "id": MODEL_ID,
            "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
        }
    }

    class ProviderFreeSelectionClient:
        def __init__(self, *, api_key: str, **_kwargs: object) -> None:
            assert api_key == CANARY

        async def validate_authentication(self) -> None:
            return None

        async def get_certification_model_metadata(self) -> dict[str, Any]:
            return catalog_payload

        async def list_zdr_endpoints(self) -> dict[str, Any]:
            return {"data": [endpoint]}

        async def get_model_metadata(self, model_id: str) -> dict[str, Any]:
            assert model_id == MODEL_ID
            return {"data": fixtures._catalog_model(spec)}

        async def get_model_endpoint_metadata(self, model_id: str) -> dict[str, Any]:
            assert model_id == MODEL_ID
            return endpoint_payload

        def seal_real_model_discovery_run(self, **_kwargs: object) -> object:
            raise AssertionError("ineligible route must reject before discovery sealing")

        async def close(self) -> None:
            return None

    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(cli_module, "OpenRouterClient", ProviderFreeSelectionClient)
    monkeypatch.setattr(
        cli_module,
        "_TRUSTED_OPENROUTER_CLIENT_TYPE",
        ProviderFreeSelectionClient,
    )
    discovery_output = tmp_path / "private" / "rejected-selection-discovery"
    registry_output = tmp_path / "private" / "rejected-selection-registry.json"

    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "discover",
            "--candidate",
            f"{MODEL_ID}={PROVIDER_ENDPOINT}",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--secrets-env-file",
            str(secret_file),
            "--output-dir",
            str(discovery_output),
            "--candidate-selection-plan",
            str(plan_path),
            "--candidate-selection-ranking-source",
            str(ranking_path),
            "--candidate-selection-lineage-review-source",
            str(lineage_path),
            "--candidate-registry-output",
            str(registry_output),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert expected in " ".join(result.output.split())
    assert not discovery_output.exists()
    assert not registry_output.exists()
    assert CANARY not in result.output
