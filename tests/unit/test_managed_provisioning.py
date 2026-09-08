from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from decimal import localcontext
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.config import AuditConfig
from mmaudit.orchestration.managed_provisioning import (
    MANAGED_PROVISIONING_POLICY_SHA256,
    MAX_MANAGED_PROVISIONING_RECEIPT_BYTES,
    CodeQLProvisioningObservation,
    CostLedgerProvisioningObservation,
    DependencySnapshotProvisioningObservation,
    ForkRpcProvisioningObservation,
    ManagedProvisioningAction,
    ManagedProvisioningError,
    ManagedProvisioningKind,
    ManagedProvisioningObservations,
    ManagedProvisioningObservationStatus,
    ManagedProvisioningPlan,
    ManagedProvisioningReceipt,
    ManagedProvisioningRefusalCode,
    ManagedProvisioningRequirement,
    ManagedProvisioningState,
    ManagedProvisioningStateStatus,
    build_managed_provisioning_receipt,
    derive_managed_provisioning_plan,
    parse_and_verify_managed_provisioning_state,
    parse_managed_provisioning_receipt,
    parse_managed_provisioning_state,
    reduce_managed_provisioning_observations,
    render_managed_provisioning_receipt,
    render_managed_provisioning_state,
    verify_managed_provisioning_receipt,
    verify_managed_provisioning_state,
)
from mmaudit.orchestration.managed_toolchain import (
    MANAGED_TOOLCHAIN_ROLE_SPECS,
    ManagedToolchainBundle,
    ManagedToolchainDisposition,
    ManagedToolchainError,
    ManagedToolchainMember,
    ManagedToolchainRole,
    load_packaged_managed_toolchain_bundle,
    seal_managed_toolchain_bundle,
)

REPOSITORY_SHA256 = "a" * 64
SNAPSHOT_SHA256 = "b" * 64
OTHER_SHA256 = "c" * 64
LEDGER_SNAPSHOT_SHA256 = "d" * 64
PACKAGED_BUNDLE_SHA256 = "55c412fdb2dd56a2541c0e737d953b5d0e770ece42b4c1c11ebfb7e1c233498d"


def test_new_policy_keeps_legacy_receipts_reproducible_without_relabeling(config_factory):
    plan = _plan(config_factory())
    assert plan.setup_policy_sha256 == MANAGED_PROVISIONING_POLICY_SHA256
    payload = plan.model_dump(mode="json", exclude={"plan_sha256"})
    payload["setup_policy_sha256"] = (
        "ff438f3fd072329a5abfadfebc75e800a4cb36dbaa0d4e8c9f761d8e4b76750f"
    )
    payload["plan_sha256"] = _canonical_sha256(payload)
    legacy = ManagedProvisioningPlan.model_validate(payload)
    refused = ManagedProvisioningObservations.refused_for(
        legacy, code=ManagedProvisioningRefusalCode.UNSUPPORTED_RUNTIME_SURFACE
    )
    state = reduce_managed_provisioning_observations(legacy, refused)
    receipt = build_managed_provisioning_receipt(legacy, state)
    assert receipt.setup_policy_sha256 == state.setup_policy_sha256 == legacy.setup_policy_sha256
    serialized = render_managed_provisioning_receipt(receipt)
    assert (
        render_managed_provisioning_receipt(parse_managed_provisioning_receipt(serialized))
        == serialized
    )
    assert receipt.runtime_authority is receipt.managed_run_ready is False


@pytest.mark.parametrize("location", ["envelope", "state", "plan"])
def test_policy_versions_cannot_be_mixed_even_after_resealing(config_factory, location):
    plan = _plan(config_factory())
    observations = ManagedProvisioningObservations.refused_for(
        plan, code=ManagedProvisioningRefusalCode.UNSUPPORTED_RUNTIME_SURFACE
    )
    receipt = build_managed_provisioning_receipt(
        plan, reduce_managed_provisioning_observations(plan, observations)
    )
    payload = receipt.model_dump(mode="json")
    target = payload if location == "envelope" else payload[location]
    target["setup_policy_sha256"] = (
        "ff438f3fd072329a5abfadfebc75e800a4cb36dbaa0d4e8c9f761d8e4b76750f"
    )
    if location != "envelope":
        field = location + "_sha256"
        target[field] = _canonical_sha256({k: v for k, v in target.items() if k != field})
    payload["receipt_sha256"] = _canonical_sha256(
        {k: v for k, v in payload.items() if k != "receipt_sha256"}
    )
    with pytest.raises(ValueError):
        parse_managed_provisioning_receipt(_canonical_render(payload))


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def _canonical_render(value: dict[str, object]) -> str:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    )


def _updated_config(config: AuditConfig, **sections: object) -> AuditConfig:
    payload = config.model_dump(mode="json")
    for section, value in sections.items():
        if isinstance(value, dict) and isinstance(payload.get(section), dict):
            payload[section].update(value)
        else:
            payload[section] = value
    return AuditConfig.model_validate(payload)


def _plan(
    config: AuditConfig,
    *,
    bundle: ManagedToolchainBundle | None = None,
    repository_sha256: str = REPOSITORY_SHA256,
) -> ManagedProvisioningPlan:
    return derive_managed_provisioning_plan(
        bundle or load_packaged_managed_toolchain_bundle(),
        config,
        repository_identity_sha256=repository_sha256,
    )


def _refused_observations(plan: ManagedProvisioningPlan) -> ManagedProvisioningObservations:
    return ManagedProvisioningObservations.refused_for(
        plan,
        code=ManagedProvisioningRefusalCode.MISSING_INPUT,
    )


def _refused_state(plan: ManagedProvisioningPlan) -> ManagedProvisioningState:
    return reduce_managed_provisioning_observations(plan, _refused_observations(plan))


def _verified_cost(
    plan: ManagedProvisioningPlan,
    *,
    path_sha256: str | None = None,
    cap_usd_exact: str | None = None,
) -> CostLedgerProvisioningObservation:
    expected_path = plan.cost_ledger.expected_path_sha256
    assert expected_path is not None
    expected_cap = plan.cost_ledger.expected_cap_usd_exact
    assert expected_cap is not None
    return CostLedgerProvisioningObservation.verified(
        requirement_id=plan.cost_ledger.requirement_id,
        config_binding_sha256=plan.cost_ledger.config_binding_sha256,
        action=ManagedProvisioningAction.CREATED,
        ledger_path_sha256=path_sha256 or expected_path,
        provisioning_marker_identity_sha256="d" * 64,
        ledger_identity_sha256=OTHER_SHA256,
        ledger_snapshot_sha256=LEDGER_SNAPSHOT_SHA256,
        cap_usd_exact=cap_usd_exact or expected_cap,
        entry_count=0,
        active_reservation_count=0,
        portfolio_hold_count=0,
        active_portfolio_hold_count=0,
        held_portfolio_usd_exact="0",
    )


def _reseal_observation[ObservationT](
    observation: ObservationT,
    **updates: object,
) -> ObservationT:
    model = type(observation)
    payload = observation.model_dump(mode="json")  # type: ignore[attr-defined]
    payload.update(updates)
    payload["evidence_sha256"] = _canonical_sha256(
        {key: value for key, value in payload.items() if key != "evidence_sha256"}
    )
    return model.model_validate(payload)  # type: ignore[no-any-return,attr-defined]


def _drifted_bundle(bundle: ManagedToolchainBundle) -> ManagedToolchainBundle:
    members = list(bundle.members)
    index = next(
        index
        for index, member in enumerate(members)
        if member.disposition is ManagedToolchainDisposition.UNRESOLVED
    )
    members[index] = members[index].model_copy(
        update={"limitation": "Synthetic declaration drift remains unresolved."}
    )
    return seal_managed_toolchain_bundle(
        members=tuple(members),
        target_platform=bundle.target_platform,
    )


def test_current_packaged_bundle_derives_one_deterministic_nonauthorizing_plan(
    config_factory: Callable[..., AuditConfig],
) -> None:
    bundle = load_packaged_managed_toolchain_bundle()
    config = config_factory()
    bundle_before = bundle.model_dump(mode="json")
    config_before = config.model_dump(mode="json")

    first = _plan(config, bundle=bundle)
    second = _plan(config, bundle=bundle)

    assert first == second
    assert first.plan_sha256 == _canonical_sha256(
        first.model_dump(mode="json", exclude={"plan_sha256"})
    )
    assert bundle.bundle_sha256 == PACKAGED_BUNDLE_SHA256
    assert first.source_bundle_sha256 == PACKAGED_BUNDLE_SHA256
    assert first.repository_identity_sha256 == REPOSITORY_SHA256
    assert first.required_roles == (
        ManagedToolchainRole.GIT,
        ManagedToolchainRole.PYTHON_RUNTIME,
    )
    assert first.unresolved_required_roles == first.required_roles
    assert first.cost_ledger.required is True
    assert first.cost_ledger.expected_path_sha256 is None
    assert first.cost_ledger.expected_cap_usd_exact == "20"
    assert first.codeql.required is False
    assert first.dependency_snapshot.required is False
    assert first.fork_rpcs == ()
    assert first.status == "PLAN_NONAUTHORIZING"
    assert bundle.model_dump(mode="json") == bundle_before
    assert config.model_dump(mode="json") == config_before


def test_plan_refuses_pinned_member_that_conflicts_with_per_run_trust_pins(
    config_factory: Callable[..., AuditConfig],
) -> None:
    packaged = load_packaged_managed_toolchain_bundle()
    spec = next(
        item for item in MANAGED_TOOLCHAIN_ROLE_SPECS if item.role is ManagedToolchainRole.SEMGREP
    )
    declared_sha256 = hashlib.sha256(b"managed-semgrep").hexdigest()
    pinned = ManagedToolchainMember(
        role=spec.role,
        kind=spec.kind,
        disposition=ManagedToolchainDisposition.PINNED,
        locator=spec.allowed_locators[0],
        version="1.2.3",
        sha256=declared_sha256,
        consumers=spec.consumers,
        limitation=None,
    )
    members = tuple(pinned if member.role is spec.role else member for member in packaged.members)
    bundle = seal_managed_toolchain_bundle(
        members=members,
        target_platform=packaged.target_platform,
    )
    config = _updated_config(
        config_factory(),
        scanners={
            "semgrep": {
                "enabled": True,
                "required": True,
                "version": "9.9.9",
                "sha256": "9" * 64,
            }
        },
        reproduction={"isolation_backend": "bubblewrap"},
    )

    with pytest.raises(
        ManagedProvisioningError,
        match="cannot be projected exactly",
    ) as raised:
        _plan(config, bundle=bundle)
    assert isinstance(raised.value.__cause__, ManagedToolchainError)
    assert "trust pins conflict" in str(raised.value.__cause__)


def test_plan_refuses_rootless_roles_without_image_side_representation(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _updated_config(
        config_factory(),
        scanners={"semgrep": {"enabled": True, "required": True}},
        reproduction={
            "isolation_backend": "rootless-container",
            "rootless_container_runtime": "docker",
            "rootless_container_image": f"registry.example/tool@sha256:{'a' * 64}",
        },
    )

    with pytest.raises(
        ManagedProvisioningError,
        match="cannot be projected exactly",
    ) as raised:
        _plan(config)
    assert isinstance(raised.value.__cause__, ManagedToolchainError)
    assert "unrepresented image-side identities" in str(raised.value.__cause__)


def test_plan_refuses_budget_beyond_exact_ledger_precision(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _updated_config(
        config_factory(),
        execution={"budget_usd": 1e-19},
    )

    with pytest.raises(ManagedProvisioningError, match="exact ledger representation"):
        _plan(config)


@pytest.mark.parametrize(
    "repository_sha256",
    ["", "0" * 64, "A" * 64, "0x" + ("a" * 64), "a" * 63, "g" * 64],
)
def test_plan_rejects_noncanonical_repository_identity(
    config_factory: Callable[..., AuditConfig],
    repository_sha256: str,
) -> None:
    with pytest.raises(ManagedProvisioningError, match="repository identity is invalid"):
        _plan(config_factory(), repository_sha256=repository_sha256)


def test_plan_rejects_nonexact_repository_identity_types(
    config_factory: Callable[..., AuditConfig],
) -> None:
    class DerivedDigest(str):
        pass

    bundle = load_packaged_managed_toolchain_bundle()
    for repository_sha256 in (
        DerivedDigest(REPOSITORY_SHA256),
        REPOSITORY_SHA256.encode("ascii"),
        None,
        1,
    ):
        with pytest.raises(ManagedProvisioningError, match="repository identity is invalid"):
            derive_managed_provisioning_plan(
                bundle,
                config_factory(),
                repository_identity_sha256=repository_sha256,  # type: ignore[arg-type]
            )


def test_plan_derivation_is_independent_of_decimal_context(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _updated_config(
        config_factory(),
        execution={"budget_usd": 123.456789},
    )
    expected = _plan(config)

    with localcontext() as context:
        context.prec = 3
        context.rounding = "ROUND_UP"
        observed = _plan(config)

    assert observed == expected
    assert observed.cost_ledger.expected_cap_usd_exact == "123.456789"


def test_refused_reduction_is_deterministic_complete_and_reproducible(
    config_factory: Callable[..., AuditConfig],
) -> None:
    plan = _plan(config_factory())
    observations = _refused_observations(plan)

    first = reduce_managed_provisioning_observations(plan, observations)
    second = reduce_managed_provisioning_observations(plan, observations)

    assert first == second
    assert first.status is ManagedProvisioningStateStatus.REFUSED_INCOMPLETE
    assert first.verified_requirement_ids == ()
    assert observations.cost_ledger.status is ManagedProvisioningObservationStatus.REFUSED
    assert observations.codeql.status is ManagedProvisioningObservationStatus.NOT_REQUIRED
    assert (
        observations.dependency_snapshot.status is ManagedProvisioningObservationStatus.NOT_REQUIRED
    )
    assert observations.fork_rpcs == ()
    assert [(item.requirement_id, item.code) for item in first.refusals] == [
        ("cost-ledger", ManagedProvisioningRefusalCode.MISSING_INPUT),
        (
            "managed-toolchain-git",
            ManagedProvisioningRefusalCode.UNRESOLVED_TOOLCHAIN_ROLE,
        ),
        (
            "managed-toolchain-installation",
            ManagedProvisioningRefusalCode.INSTALLED_TOOLCHAIN_UNVERIFIED,
        ),
        (
            "managed-toolchain-python-runtime",
            ManagedProvisioningRefusalCode.UNRESOLVED_TOOLCHAIN_ROLE,
        ),
    ]
    assert verify_managed_provisioning_state(plan, first) == first


def test_verified_local_inputs_are_recorded_without_granting_readiness(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _updated_config(
        config_factory(),
        execution={
            "budget_usd": 123.456789,
            "cost_ledger_path": "/tmp/mmaudit-synthetic-ledger.json",
        },
        dependency_preparation={
            "enabled": True,
            "required": True,
            "offline_snapshot_path": ".mmaudit-dependencies/snapshot.json",
            "offline_snapshot_sha256": SNAPSHOT_SHA256,
        },
    )
    plan = _plan(config)
    assert plan.dependency_snapshot.expected_identity_sha256 == SNAPSHOT_SHA256
    observations = _refused_observations(plan).model_copy(
        update={
            "cost_ledger": _verified_cost(plan),
            "dependency_snapshot": DependencySnapshotProvisioningObservation.verified(
                plan.dependency_snapshot,
                observed_identity_sha256=SNAPSHOT_SHA256,
            ),
        }
    )

    state = reduce_managed_provisioning_observations(plan, observations)

    assert state.verified_requirement_ids == ("cost-ledger", "dependency-snapshot")
    assert state.status is ManagedProvisioningStateStatus.REFUSED_INCOMPLETE
    assert all(item.requirement_id != "dependency-snapshot" for item in state.refusals)
    assert any(
        item.code is ManagedProvisioningRefusalCode.INSTALLED_TOOLCHAIN_UNVERIFIED
        for item in state.refusals
    )
    assert state.managed_run_ready is False
    assert state.runtime_authority is False


def test_primary_and_matrix_forks_are_distinct_sorted_and_exactly_reduced(
    config_factory: Callable[..., AuditConfig],
) -> None:
    base = config_factory()
    suite = base.smart_contracts.repository_suite.model_dump(mode="json")
    suite["fork_matrix_states"] = [
        {
            "state_id": "clean-local",
            "kind": "clean_local",
            "expected_chain_id": 31_337,
            "anvil_executable_env": "MMAUDIT_ANVIL_EXECUTABLE",
            "anvil_version": "anvil Version: 1.3.2-stable",
            "anvil_sha256": "e" * 64,
            "hardfork": "cancun",
            "genesis_timestamp": 1,
            "startup_timeout_seconds": 5,
            "shutdown_timeout_seconds": 5,
        },
        {
            "state_id": "main",
            "kind": "pinned_fork",
            "rpc_url_env": "MMAUDIT_PINNED_FORK_RPC_URL",
            "expected_chain_id": 1,
            "pinned_block_number": 20_000_000,
            "state_source_sha256": SNAPSHOT_SHA256,
        },
    ]
    config = _updated_config(
        base,
        language_profile="solidity-evm",
        smart_contracts={"repository_suite": suite},
        reproduction={
            "enabled": True,
            "isolation_backend": "sandbox-exec",
            "expected_chain_id": 1,
            "pinned_block_number": 42,
        },
    )
    plan = _plan(config)

    assert tuple(item.requirement_id for item in plan.fork_rpcs) == (
        "fork-rpc-matrix-main",
        "fork-rpc-primary",
    )
    assert plan.fork_rpcs[0].expected_identity_sha256 == SNAPSHOT_SHA256
    assert plan.fork_rpcs[1].expected_identity_sha256 == _canonical_sha256(
        {"expected_chain_id": 1, "pinned_block_number": 42}
    )
    fork_observations = tuple(
        ForkRpcProvisioningObservation.verified(
            requirement,
            observed_identity_sha256=requirement.expected_identity_sha256,
        )
        for requirement in plan.fork_rpcs
        if requirement.expected_identity_sha256 is not None
    )
    observations = _refused_observations(plan).model_copy(update={"fork_rpcs": fork_observations})
    state = reduce_managed_provisioning_observations(plan, observations)
    assert {
        "fork-rpc-matrix-main",
        "fork-rpc-primary",
    } <= set(state.verified_requirement_ids)

    with pytest.raises(ManagedProvisioningError, match="fork observation set differs"):
        reduce_managed_provisioning_observations(
            plan,
            observations.model_copy(update={"fork_rpcs": fork_observations[:-1]}),
        )
    with pytest.raises(ValidationError, match="unique and sorted"):
        observations.model_copy(update={"fork_rpcs": tuple(reversed(fork_observations))})


@pytest.mark.parametrize(
    "requirement_id",
    ["cost-ledger", "codeql", "dependency-snapshot", "fork-synthetic"],
)
def test_plan_rejects_fork_ids_outside_the_disjoint_fork_namespace(
    config_factory: Callable[..., AuditConfig],
    requirement_id: str,
) -> None:
    plan = _plan(config_factory())
    fork_requirement = ManagedProvisioningRequirement(
        requirement_id=requirement_id,
        kind=ManagedProvisioningKind.PINNED_FORK_RPC,
        required=True,
        config_binding_sha256="e" * 64,
        expected_identity_sha256="f" * 64,
    )
    payload = plan.model_dump(mode="json")
    payload["fork_rpcs"] = [fork_requirement.model_dump(mode="json")]
    payload["plan_sha256"] = _canonical_sha256(
        {key: value for key, value in payload.items() if key != "plan_sha256"}
    )

    with pytest.raises(ValidationError):
        ManagedProvisioningPlan.model_validate(payload)


@pytest.mark.parametrize(
    ("portfolio_hold_count", "active_portfolio_hold_count", "held_portfolio_usd_exact"),
    [(0, 0, "1"), (2, 2, "1")],
)
def test_cost_observation_rejects_impossible_portfolio_summaries(
    config_factory: Callable[..., AuditConfig],
    portfolio_hold_count: int,
    active_portfolio_hold_count: int,
    held_portfolio_usd_exact: str,
) -> None:
    plan = _plan(
        _updated_config(
            config_factory(),
            execution={"cost_ledger_path": "/tmp/mmaudit-synthetic-ledger.json"},
        )
    )
    observation = _verified_cost(plan)

    with pytest.raises(ValidationError):
        _reseal_observation(
            observation,
            portfolio_hold_count=portfolio_hold_count,
            active_portfolio_hold_count=active_portfolio_hold_count,
            held_portfolio_usd_exact=held_portfolio_usd_exact,
        )


def test_every_authority_and_external_effect_flag_remains_false(
    config_factory: Callable[..., AuditConfig],
) -> None:
    bundle = load_packaged_managed_toolchain_bundle()
    plan = _plan(config_factory(), bundle=bundle)
    state = _refused_state(plan)
    false_bundle_fields = {
        "independently_trusted",
        "installed_members_verified",
        "transitive_dependency_closure_verified",
        "image_side_attestation_verified",
        "provisioning_state_verified",
        "execution_evidence_verified",
        "runtime_authority",
        "managed_run_ready",
    }
    false_plan_fields = {
        "independently_trusted",
        "installed_members_verified",
        "runtime_authority",
        "managed_run_ready",
    }
    false_state_fields = {
        "independently_trusted",
        "bundle_trusted",
        "installed_members_verified",
        "transitive_dependency_closure_verified",
        "image_side_attestation_verified",
        "provisioning_state_verified",
        "execution_evidence_verified",
        "spend_admission_evaluated",
        "runtime_authority",
        "managed_run_ready",
        "provider_or_network_accessed",
        "operator_secret_sources_accessed",
    }

    for artifact, fields in (
        (bundle, false_bundle_fields),
        (plan, false_plan_fields),
        (state, false_state_fields),
    ):
        payload = artifact.model_dump(mode="python")
        assert {field for field in fields if payload[field] is False} == fields
    assert state.local_checks_recorded is True
    assert state.repository_content_hashed is True
    assert state.self_consistent is True


def test_plan_config_bundle_and_observation_drift_fail_closed(
    config_factory: Callable[..., AuditConfig],
) -> None:
    bundle = load_packaged_managed_toolchain_bundle()
    config = _updated_config(
        config_factory(),
        execution={"cost_ledger_path": "/tmp/mmaudit-synthetic-ledger.json"},
    )
    plan = _plan(config, bundle=bundle)
    observations = _refused_observations(plan)
    state = reduce_managed_provisioning_observations(plan, observations)

    plan_drift = _plan(config, bundle=bundle, repository_sha256=OTHER_SHA256)
    with pytest.raises(ManagedProvisioningError, match="state differs from its plan"):
        verify_managed_provisioning_state(plan_drift, state)

    config_drift = _updated_config(config, execution={"budget_usd": 21})
    config_plan = _plan(config_drift, bundle=bundle)
    assert config_plan.effective_config_sha256 != plan.effective_config_sha256
    with pytest.raises(ManagedProvisioningError, match="observation differs from plan"):
        reduce_managed_provisioning_observations(config_plan, observations)

    bundle_plan = _plan(config, bundle=_drifted_bundle(bundle))
    assert bundle_plan.source_bundle_sha256 != plan.source_bundle_sha256
    with pytest.raises(ManagedProvisioningError, match="state differs from its plan"):
        verify_managed_provisioning_state(bundle_plan, state)

    drifted_cost = _reseal_observation(
        observations.cost_ledger,
        config_binding_sha256=OTHER_SHA256,
    )
    drifted_observations = observations.model_copy(update={"cost_ledger": drifted_cost})
    with pytest.raises(ManagedProvisioningError, match="observation differs from plan"):
        reduce_managed_provisioning_observations(plan, drifted_observations)


def test_reducer_checks_verified_cost_and_simple_identity_against_plan(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _updated_config(
        config_factory(),
        execution={"cost_ledger_path": "/tmp/mmaudit-synthetic-ledger.json"},
        dependency_preparation={
            "enabled": True,
            "required": True,
            "offline_snapshot_path": ".mmaudit-dependencies/snapshot.json",
            "offline_snapshot_sha256": SNAPSHOT_SHA256,
        },
    )
    plan = _plan(config)
    baseline = _refused_observations(plan)

    wrong_cost = _verified_cost(plan, path_sha256="e" * 64)
    with pytest.raises(ManagedProvisioningError, match="cost ledger differs from plan"):
        reduce_managed_provisioning_observations(
            plan,
            baseline.model_copy(update={"cost_ledger": wrong_cost}),
        )

    dependency = DependencySnapshotProvisioningObservation.verified(
        plan.dependency_snapshot,
        observed_identity_sha256=SNAPSHOT_SHA256,
    )
    resealed_wrong_identity = _reseal_observation(
        dependency,
        configured_identity_sha256=OTHER_SHA256,
        observed_identity_sha256=OTHER_SHA256,
    )
    with pytest.raises(ManagedProvisioningError, match="identity differs from plan"):
        reduce_managed_provisioning_observations(
            plan,
            baseline.model_copy(update={"dependency_snapshot": resealed_wrong_identity}),
        )


def test_optional_and_required_observation_statuses_are_not_interchangeable(
    config_factory: Callable[..., AuditConfig],
) -> None:
    optional_plan = _plan(config_factory())
    optional = _refused_observations(optional_plan)
    refused_optional = CodeQLProvisioningObservation.refused(
        optional_plan.codeql,
        code=ManagedProvisioningRefusalCode.MISSING_INPUT,
    )
    with pytest.raises(ManagedProvisioningError, match=r"optional.*must be not required"):
        reduce_managed_provisioning_observations(
            optional_plan,
            optional.model_copy(update={"codeql": refused_optional}),
        )

    required_plan = _plan(
        _updated_config(
            config_factory(),
            dependency_preparation={
                "enabled": True,
                "required": True,
                "offline_snapshot_path": ".mmaudit-dependencies/snapshot.json",
                "offline_snapshot_sha256": SNAPSHOT_SHA256,
            },
        )
    )
    with pytest.raises(ManagedProvisioningError, match="cannot be not-required"):
        DependencySnapshotProvisioningObservation.not_required(required_plan.dependency_snapshot)
    with pytest.raises(ManagedProvisioningError, match="requires one expected identity"):
        CodeQLProvisioningObservation.verified(
            optional_plan.codeql,
            observed_identity_sha256=OTHER_SHA256,
        )

    codeql_plan = _plan(
        _updated_config(
            config_factory(),
            scanners={
                "codeql": {
                    "enabled": True,
                    "required": True,
                    "database_path": ".mmaudit-codeql/database",
                    "query_suite": "security-extended",
                }
            },
            reproduction={"isolation_backend": "sandbox-exec"},
        )
    )
    assert codeql_plan.codeql.required is True
    assert codeql_plan.codeql.expected_identity_sha256 is None
    codeql_state = _refused_state(codeql_plan)
    assert any(
        refusal.requirement_id == "codeql"
        and refusal.code is ManagedProvisioningRefusalCode.MISSING_INPUT
        for refusal in codeql_state.refusals
    )
    with pytest.raises(ManagedProvisioningError, match="requires one expected identity"):
        CodeQLProvisioningObservation.verified(
            codeql_plan.codeql,
            observed_identity_sha256=OTHER_SHA256,
        )


def test_canonical_render_parse_and_all_self_hashes_round_trip(
    config_factory: Callable[..., AuditConfig],
) -> None:
    plan = _plan(config_factory())
    state = _refused_state(plan)
    rendered = render_managed_provisioning_state(state)

    assert rendered == render_managed_provisioning_state(state)
    assert rendered.endswith("\n")
    assert rendered == _canonical_render(state.model_dump(mode="json"))
    assert parse_managed_provisioning_state(rendered) == state
    assert parse_managed_provisioning_state(rendered.encode("utf-8")) == state
    assert parse_and_verify_managed_provisioning_state(plan, rendered) == state
    assert plan.plan_sha256 == _canonical_sha256(
        plan.model_dump(mode="json", exclude={"plan_sha256"})
    )
    assert state.state_sha256 == _canonical_sha256(
        state.model_dump(mode="json", exclude={"state_sha256"})
    )
    for observation in (
        state.observations.cost_ledger,
        state.observations.codeql,
        state.observations.dependency_snapshot,
        *state.observations.fork_rpcs,
    ):
        assert observation.evidence_sha256 == _canonical_sha256(
            observation.model_dump(mode="json", exclude={"evidence_sha256"})
        )


def test_self_contained_receipt_round_trips_without_external_plan_input(
    config_factory: Callable[..., AuditConfig],
) -> None:
    plan = _plan(config_factory())
    state = _refused_state(plan)

    receipt = build_managed_provisioning_receipt(plan, state)
    rendered = render_managed_provisioning_receipt(receipt)
    parsed = parse_managed_provisioning_receipt(rendered.encode("utf-8"))

    assert isinstance(receipt, ManagedProvisioningReceipt)
    assert parsed == receipt
    assert parsed.plan == plan
    assert parsed.state == state
    assert verify_managed_provisioning_receipt(parsed) == receipt
    assert rendered == render_managed_provisioning_receipt(parsed)
    assert receipt.receipt_sha256 == _canonical_sha256(
        receipt.model_dump(mode="json", exclude={"receipt_sha256"})
    )
    assert receipt.spend_admission_evaluated is False
    assert receipt.runtime_authority is False
    assert receipt.managed_run_ready is False
    assert receipt.provider_or_network_accessed is False
    assert receipt.operator_secret_sources_accessed is False


def test_receipt_rejects_resealed_plan_state_mismatch_and_authority_bypass(
    config_factory: Callable[..., AuditConfig],
) -> None:
    first_plan = _plan(config_factory())
    second_plan = _plan(config_factory(), repository_sha256=OTHER_SHA256)
    receipt = build_managed_provisioning_receipt(first_plan, _refused_state(first_plan))
    payload = receipt.model_dump(mode="json")
    payload["plan"] = second_plan.model_dump(mode="json")
    payload["receipt_sha256"] = _canonical_sha256(
        {key: value for key, value in payload.items() if key != "receipt_sha256"}
    )
    with pytest.raises(ValidationError, match="state differs from its plan"):
        ManagedProvisioningReceipt.model_validate(payload)

    payload = receipt.model_dump(mode="json")
    payload["runtime_authority"] = True
    payload["receipt_sha256"] = _canonical_sha256(
        {key: value for key, value in payload.items() if key != "receipt_sha256"}
    )
    with pytest.raises(ValidationError):
        ManagedProvisioningReceipt.model_validate(payload, strict=True)

    constructed_payload = {field: getattr(receipt, field) for field in type(receipt).model_fields}
    constructed_payload["runtime_authority"] = True
    constructed = ManagedProvisioningReceipt.model_construct(**constructed_payload)
    with pytest.raises(ValidationError):
        verify_managed_provisioning_receipt(constructed)
    with pytest.raises(ValidationError):
        render_managed_provisioning_receipt(constructed)


def test_receipt_parser_rejects_duplicate_oversized_and_noncanonical_bytes(
    config_factory: Callable[..., AuditConfig],
) -> None:
    plan = _plan(config_factory())
    rendered = render_managed_provisioning_receipt(
        build_managed_provisioning_receipt(plan, _refused_state(plan))
    )
    duplicate_nested = rendered.replace(
        '    "runtime_authority": false,\n',
        '    "runtime_authority": false,\n    "runtime_authority": false,\n',
        1,
    )

    with pytest.raises(ManagedProvisioningError, match="duplicate key"):
        parse_managed_provisioning_receipt(duplicate_nested)
    with pytest.raises(ManagedProvisioningError, match="bytes are not canonical"):
        parse_managed_provisioning_receipt(rendered.rstrip("\n"))
    with pytest.raises(ManagedProvisioningError, match="input bound"):
        parse_managed_provisioning_receipt(b" " * (MAX_MANAGED_PROVISIONING_RECEIPT_BYTES + 1))


def test_parser_rejects_duplicate_nonfinite_unknown_missing_and_noncanonical_json(
    config_factory: Callable[..., AuditConfig],
) -> None:
    state = _refused_state(_plan(config_factory()))
    rendered = render_managed_provisioning_state(state)
    duplicate = rendered.replace(
        '  "runtime_authority": false,\n',
        '  "runtime_authority": false,\n  "runtime_authority": false,\n',
        1,
    )
    with pytest.raises(ManagedProvisioningError, match="duplicate key"):
        parse_managed_provisioning_state(duplicate)

    nonfinite = rendered.replace(
        '  "local_checks_recorded": true,',
        '  "local_checks_recorded": NaN,',
        1,
    )
    with pytest.raises(ManagedProvisioningError, match="non-finite"):
        parse_managed_provisioning_state(nonfinite)

    payload = state.model_dump(mode="json")
    payload["unknown_authority"] = False
    with pytest.raises(ManagedProvisioningError, match="state is invalid"):
        parse_managed_provisioning_state(_canonical_render(payload))

    payload = state.model_dump(mode="json")
    del payload["runtime_authority"]
    with pytest.raises(ManagedProvisioningError, match="state is invalid"):
        parse_managed_provisioning_state(_canonical_render(payload))

    payload = state.model_dump(mode="json")
    payload["runtime_authority"] = True
    with pytest.raises(ManagedProvisioningError, match="state is invalid"):
        parse_managed_provisioning_state(_canonical_render(payload))

    with pytest.raises(ManagedProvisioningError, match="bytes are not canonical"):
        parse_managed_provisioning_state(rendered.rstrip("\n"))
    with pytest.raises(ManagedProvisioningError, match="one JSON object"):
        parse_managed_provisioning_state("[]")
    with pytest.raises(ManagedProvisioningError, match="strict JSON"):
        parse_managed_provisioning_state(b"{\xff}")
    with pytest.raises(ManagedProvisioningError, match="input bound"):
        parse_managed_provisioning_state(b" " * ((1024 * 1024) + 1))


def test_parser_accepts_only_exact_string_or_bytes_inputs(
    config_factory: Callable[..., AuditConfig],
) -> None:
    class LyingText(str):
        def encode(self, *_args: object, **_kwargs: object) -> bytes:
            raise AssertionError("a string subclass must not control parsed bytes")

    rendered = render_managed_provisioning_state(_refused_state(_plan(config_factory())))
    for content in (
        LyingText(rendered),
        bytearray(rendered.encode("utf-8")),
        memoryview(rendered.encode("utf-8")),
        1,
        None,
    ):
        with pytest.raises(ManagedProvisioningError, match="input type is invalid"):
            parse_managed_provisioning_state(content)  # type: ignore[arg-type]
    with pytest.raises(ManagedProvisioningError, match=r"UTF-8|input"):
        parse_managed_provisioning_state("\ud800")


def test_models_reject_duplicate_nonfinite_unknown_and_missing_required_fields(
    config_factory: Callable[..., AuditConfig],
) -> None:
    plan = _plan(config_factory())
    observations = _refused_observations(plan)
    state = reduce_managed_provisioning_observations(plan, observations)

    with pytest.raises(ValidationError, match="unique and sorted"):
        plan.model_copy(update={"required_roles": (*plan.required_roles, plan.required_roles[0])})
    with pytest.raises(ValidationError, match="unique and sorted"):
        state.model_copy(update={"verified_requirement_ids": ("cost-ledger", "cost-ledger")})
    with pytest.raises(ValidationError, match="unique and sorted"):
        state.model_copy(update={"refusals": (*state.refusals, state.refusals[0])})

    alternate = reduce_managed_provisioning_observations(
        plan,
        ManagedProvisioningObservations.refused_for(
            plan,
            code=ManagedProvisioningRefusalCode.UNAVAILABLE,
        ),
    )
    duplicate_requirement_refusal = next(
        item for item in alternate.refusals if item.requirement_id == "cost-ledger"
    )
    state_payload = state.model_dump(mode="json")
    state_payload["refusals"] = sorted(
        [
            *state_payload["refusals"],
            duplicate_requirement_refusal.model_dump(mode="json"),
        ],
        key=lambda item: (item["requirement_id"], item["code"]),
    )
    state_payload["state_sha256"] = _canonical_sha256(
        {key: value for key, value in state_payload.items() if key != "state_sha256"}
    )
    with pytest.raises(ValidationError, match="refusals must be unique"):
        ManagedProvisioningState.model_validate(state_payload)

    fork_requirement = ManagedProvisioningRequirement(
        requirement_id="fork-rpc-synthetic",
        kind=ManagedProvisioningKind.PINNED_FORK_RPC,
        required=True,
        config_binding_sha256="e" * 64,
        expected_identity_sha256="f" * 64,
    )
    fork = ForkRpcProvisioningObservation.verified(
        fork_requirement,
        observed_identity_sha256="f" * 64,
    )
    with pytest.raises(ValidationError, match="unique and sorted"):
        ManagedProvisioningObservations.model_validate(
            {
                **observations.model_dump(mode="python"),
                "fork_rpcs": (fork, fork),
            },
            strict=True,
        )

    cost_payload = observations.cost_ledger.model_dump(mode="json")
    cost_payload["entry_count"] = float("nan")
    with pytest.raises(ValidationError):
        CostLedgerProvisioningObservation.model_validate(cost_payload, strict=True)

    plan_payload = plan.model_dump(mode="json")
    plan_payload["unknown_authority"] = False
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ManagedProvisioningPlan.model_validate(plan_payload, strict=True)
    plan_payload = plan.model_dump(mode="json")
    del plan_payload["runtime_authority"]
    with pytest.raises(ValidationError, match="missing"):
        ManagedProvisioningPlan.model_validate(plan_payload, strict=True)

    observation_payload = observations.cost_ledger.model_dump(mode="json")
    del observation_payload["refusal_code"]
    with pytest.raises(ValidationError, match="missing"):
        CostLedgerProvisioningObservation.model_validate(observation_payload, strict=True)


def test_model_copy_revalidates_hashes_literals_and_strict_primitives(
    config_factory: Callable[..., AuditConfig],
) -> None:
    plan = _plan(config_factory())
    observations = _refused_observations(plan)
    state = reduce_managed_provisioning_observations(plan, observations)

    with pytest.raises(ValidationError):
        plan.model_copy(update={"runtime_authority": True})
    with pytest.raises(ValidationError):
        plan.model_copy(update={"runtime_authority": 0})
    with pytest.raises(ValidationError):
        plan.cost_ledger.model_copy(update={"required": 1})
    with pytest.raises(ValidationError, match="hash is inconsistent"):
        plan.model_copy(update={"repository_identity_sha256": OTHER_SHA256})
    with pytest.raises(ValidationError, match="hash is inconsistent"):
        observations.cost_ledger.model_copy(update={"evidence_sha256": "f" * 64})
    with pytest.raises(ValidationError):
        state.model_copy(update={"provider_or_network_accessed": True})
    with pytest.raises(ValidationError, match="hash is inconsistent"):
        state.model_copy(update={"repository_identity_sha256": OTHER_SHA256})


def test_exact_type_consumers_reject_subclasses(
    config_factory: Callable[..., AuditConfig],
) -> None:
    bundle = load_packaged_managed_toolchain_bundle()
    config = config_factory()
    plan = _plan(config, bundle=bundle)
    observations = _refused_observations(plan)
    state = reduce_managed_provisioning_observations(plan, observations)

    class DerivedBundle(ManagedToolchainBundle):
        pass

    class DerivedConfig(AuditConfig):
        pass

    class DerivedPlan(ManagedProvisioningPlan):
        pass

    class DerivedObservations(ManagedProvisioningObservations):
        pass

    class DerivedState(ManagedProvisioningState):
        pass

    derived_bundle = DerivedBundle.model_validate(bundle.model_dump(mode="json"))
    derived_config = DerivedConfig.model_validate(config.model_dump(mode="json"))
    derived_plan = DerivedPlan.model_validate(plan.model_dump(mode="json"))
    derived_observations = DerivedObservations.model_validate(observations.model_dump(mode="json"))
    derived_state = DerivedState.model_validate(state.model_dump(mode="json"))

    with pytest.raises(ManagedProvisioningError, match="exact compiled inputs"):
        derive_managed_provisioning_plan(
            derived_bundle,
            config,
            repository_identity_sha256=REPOSITORY_SHA256,
        )
    with pytest.raises(ManagedProvisioningError, match="exact compiled inputs"):
        derive_managed_provisioning_plan(
            bundle,
            derived_config,
            repository_identity_sha256=REPOSITORY_SHA256,
        )
    with pytest.raises(ManagedProvisioningError, match="plan must be the exact compiled type"):
        reduce_managed_provisioning_observations(derived_plan, observations)
    with pytest.raises(ManagedProvisioningError, match="observations must be the exact"):
        reduce_managed_provisioning_observations(plan, derived_observations)
    with pytest.raises(ManagedProvisioningError, match="plan must be the exact compiled type"):
        ManagedProvisioningObservations.refused_for(
            derived_plan,
            code=ManagedProvisioningRefusalCode.MISSING_INPUT,
        )
    with pytest.raises(ManagedProvisioningError, match="state must be the exact compiled type"):
        verify_managed_provisioning_state(plan, derived_state)
    with pytest.raises(ManagedProvisioningError, match="state must be the exact compiled type"):
        render_managed_provisioning_state(derived_state)


def test_consumers_revalidate_model_construct_bypasses(
    config_factory: Callable[..., AuditConfig],
) -> None:
    bundle = load_packaged_managed_toolchain_bundle()
    config = config_factory()
    plan = _plan(config, bundle=bundle)
    observations = _refused_observations(plan)
    state = reduce_managed_provisioning_observations(plan, observations)

    bundle_payload = {field: getattr(bundle, field) for field in type(bundle).model_fields}
    bundle_payload["runtime_authority"] = True
    constructed_bundle = ManagedToolchainBundle.model_construct(**bundle_payload)
    with pytest.raises(ManagedProvisioningError, match="cannot be projected exactly"):
        derive_managed_provisioning_plan(
            constructed_bundle,
            config,
            repository_identity_sha256=REPOSITORY_SHA256,
        )

    for bypassed_config in (
        config.model_copy(update={"language_profile": "invalid-profile"}),
        AuditConfig.model_construct(
            **{
                **{field: getattr(config, field) for field in type(config).model_fields},
                "language_profile": "invalid-profile",
            }
        ),
    ):
        with (
            pytest.warns(UserWarning, match="Pydantic serializer warnings"),
            pytest.raises(ManagedProvisioningError, match="cannot be projected exactly"),
        ):
            derive_managed_provisioning_plan(
                bundle,
                bypassed_config,
                repository_identity_sha256=REPOSITORY_SHA256,
            )

    plan_payload = {field: getattr(plan, field) for field in type(plan).model_fields}
    plan_payload["managed_run_ready"] = True
    constructed_plan = ManagedProvisioningPlan.model_construct(**plan_payload)
    with pytest.raises(ValidationError):
        reduce_managed_provisioning_observations(constructed_plan, observations)

    observations_payload = {
        field: getattr(observations, field) for field in type(observations).model_fields
    }
    malformed_cost_payload = {
        field: getattr(observations.cost_ledger, field)
        for field in type(observations.cost_ledger).model_fields
    }
    del malformed_cost_payload["status"]
    observations_payload["cost_ledger"] = CostLedgerProvisioningObservation.model_construct(
        **malformed_cost_payload
    )
    constructed_observations = ManagedProvisioningObservations.model_construct(
        **observations_payload
    )
    with pytest.raises(ValidationError):
        reduce_managed_provisioning_observations(plan, constructed_observations)

    state_payload = {field: getattr(state, field) for field in type(state).model_fields}
    state_payload["runtime_authority"] = True
    constructed_state = ManagedProvisioningState.model_construct(**state_payload)
    with pytest.raises(ValidationError):
        verify_managed_provisioning_state(plan, constructed_state)
    with pytest.raises(ValidationError):
        render_managed_provisioning_state(constructed_state)


def test_resealed_state_with_invented_verified_id_is_structurally_invalid(
    config_factory: Callable[..., AuditConfig],
) -> None:
    plan = _plan(config_factory())
    state = _refused_state(plan)
    payload: dict[str, Any] = state.model_dump(mode="json")
    payload["verified_requirement_ids"] = ["invented-requirement"]
    payload["state_sha256"] = _canonical_sha256(
        {key: value for key, value in payload.items() if key != "state_sha256"}
    )
    with pytest.raises(ValidationError, match="verified IDs differ from observations"):
        ManagedProvisioningState.model_validate(payload)
