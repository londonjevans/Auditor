from __future__ import annotations

import json
import os
import stat
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path

import pytest

import mmaudit.orchestration.managed_provisioning_runtime as runtime_module
from mmaudit.config import AuditConfig, canonical_audit_config_json
from mmaudit.isolation.dependency_snapshot import (
    DependencySnapshotBuildError,
    build_managed_dependency_snapshot,
)
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostLedgerSnapshot,
    PortfolioAttemptSlot,
)
from mmaudit.orchestration.managed_host_tools import ManagedHostToolError, ManagedHostToolSource
from mmaudit.orchestration.managed_provisioning import (
    ManagedProvisioningAction,
    ManagedProvisioningObservationStatus,
    ManagedProvisioningRefusalCode,
    derive_managed_provisioning_plan,
    parse_managed_provisioning_receipt,
)
from mmaudit.orchestration.managed_provisioning_runtime import (
    ManagedDependencySource,
    ManagedProvisioningRun,
    ManagedProvisioningRuntimeError,
    provision_managed_local_receipt,
    provision_managed_local_run,
)
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainError,
    ManagedToolchainRole,
    load_packaged_managed_toolchain_bundle,
    seal_managed_toolchain_bundle,
)
from mmaudit.scanners.base import ScannerWorkspaceSourceCustody, scanner_workspace_sha256
from tests.dependency_snapshot_support import setup_snapshot_inputs
from tests.host_tool_material_support import setup_host_material_inputs
from tests.managed_toolchain_support import synthetic_pinned_bundle


def test_setup_hands_off_prepared_host_paths_without_promoting_receipt_readiness(
    tmp_path, config_factory
):
    config = config_factory()
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    arguments = dict(bundle=bundle, config=config, repository=repository, output_dir=output)
    first = provision_managed_local_run(
        **arguments, verify_only=False, host_tool_source=ManagedHostToolSource(blob_root=store)
    )
    assert first.host_tools is not None
    assert first.host_tools.action == "CREATED"
    assert first.host_tools.config == first.config
    assert first.host_tools.manifest.source_bundle_sha256 == first.receipt.plan.source_bundle_sha256
    assert first.host_tools.manifest.required_roles == first.receipt.plan.required_roles
    assert first.host_tools.executable_for(ManagedToolchainRole.GIT).is_file()
    assert first.receipt.state.installed_members_verified is False
    assert first.receipt.state.managed_run_ready is False
    assert any(
        refusal.code is ManagedProvisioningRefusalCode.INSTALLED_TOOLCHAIN_UNVERIFIED
        for refusal in first.receipt.state.refusals
    )
    repeated = provision_managed_local_run(
        **arguments, verify_only=True, host_tool_source=ManagedHostToolSource()
    )
    assert repeated.host_tools is not None
    assert repeated.host_tools.action == "VERIFIED_EXISTING"
    assert repeated.host_tools.manifest == first.host_tools.manifest
    assert repeated.receipt == first.receipt


@pytest.mark.parametrize("phase", ["prepared", "published"])
@pytest.mark.parametrize("existing", [False, True])
def test_host_material_drift_prevents_setup_handoff_and_preserves_historical_receipts(
    tmp_path, config_factory, monkeypatch, phase, existing
):
    config = config_factory()
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    arguments = dict(
        bundle=bundle,
        config=config,
        repository=repository,
        output_dir=output,
        verify_only=False,
        host_tool_source=ManagedHostToolSource(blob_root=store),
    )
    previous = provision_managed_local_run(**arguments) if existing else None
    old_receipts = {
        path.name: path.read_bytes() for path in output.glob("managed-provisioning-receipt-*.json")
    }
    method = "prepare" if phase == "prepared" else "_publish_or_verify_locked"
    original = getattr(runtime_module._PrivateOutputCustody, method)

    def mutate(self, *args):
        result = original(self, *args)
        executable = next(output.glob("managed-host-tools-*/git"))
        executable.chmod(0o700)
        executable.write_bytes(b"changed synthetic host material\n")
        executable.chmod(0o500)
        return result

    monkeypatch.setattr(runtime_module._PrivateOutputCustody, method, mutate)
    with pytest.raises(ManagedHostToolError):
        provision_managed_local_run(**arguments)
    assert {
        path.name: path.read_bytes() for path in output.glob("managed-provisioning-receipt-*.json")
    } == old_receipts
    assert not list(output.glob(".*.tmp"))
    if previous is not None:
        assert old_receipts
        assert (
            parse_managed_provisioning_receipt(next(iter(old_receipts.values())))
            == previous.receipt
        )


def test_unresolved_host_selection_refuses_before_dependency_or_ledger_writes(
    tmp_path, config_factory, monkeypatch
):
    config = config_factory()
    repository, store, output, _ = setup_host_material_inputs(tmp_path, config)

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: unresolved host selection must stop before setup writes")

    monkeypatch.setattr(runtime_module, "_build_managed_dependency_config", forbidden)
    monkeypatch.setattr(runtime_module, "_managed_cost_ledger_observation", forbidden)
    with pytest.raises(ManagedHostToolError, match="every required host role"):
        provision_managed_local_run(
            bundle=load_packaged_managed_toolchain_bundle(),
            config=config,
            repository=repository,
            output_dir=output,
            verify_only=False,
            host_tool_source=ManagedHostToolSource(blob_root=store),
        )
    assert list(output.iterdir()) == []


@pytest.mark.parametrize("partial_bundle", [False, True])
def test_selected_bundle_pins_reach_the_returned_receipt_bound_config(
    tmp_path, config_factory, partial_bundle
):
    repository = tmp_path / "repository"
    repository.mkdir()
    output = _private_directory(tmp_path / "receipts")
    bundle = synthetic_pinned_bundle()
    semgrep = next(
        member for member in bundle.members if member.role is ManagedToolchainRole.SEMGREP
    )
    if partial_bundle:
        original_bundle = load_packaged_managed_toolchain_bundle()
        bundle = seal_managed_toolchain_bundle(
            members=tuple(
                semgrep if member.role is semgrep.role else member
                for member in original_bundle.members
            ),
            target_platform=original_bundle.target_platform,
        )
    config = config_factory(
        scanners={"semgrep": {"enabled": True, "required": True}},
        reproduction={"isolation_backend": "bubblewrap"},
    )
    original_config = config.model_dump(mode="json")
    arguments = dict(config=config, bundle=bundle, repository=repository, output_dir=output)
    run = provision_managed_local_run(**arguments, verify_only=False)
    assert run.config.scanners.semgrep.version == semgrep.version
    assert run.config.scanners.semgrep.sha256 == semgrep.sha256
    assert run.config.scanners.gitleaks.sha256 is None
    assert run.config.stable_hash() == run.receipt.plan.effective_config_sha256
    assert config.model_dump(mode="json") == original_config
    assert run.receipt.managed_run_ready is run.receipt.runtime_authority is False
    assert any(
        item.code is ManagedProvisioningRefusalCode.INSTALLED_TOOLCHAIN_UNVERIFIED
        for item in run.receipt.state.refusals
    )
    assert provision_managed_local_run(**arguments, verify_only=True) == run


def test_conflicting_toolchain_pin_refuses_before_any_setup_write(
    tmp_path, config_factory, monkeypatch
):
    inputs = _automatic_inputs(tmp_path, config_factory)
    inputs["bundle"] = synthetic_pinned_bundle()
    inputs["config"] = config_factory(
        scanners={
            "semgrep": {
                "enabled": True,
                "version": "9.9.9",
                "sha256": "c" * 64,
            }
        },
        reproduction={"isolation_backend": "bubblewrap"},
    )
    accesses: list[str] = []

    def forbidden(**_kwargs):
        accesses.append("setup")
        raise AssertionError("pin conflicts must be rejected before dependency or ledger setup")

    monkeypatch.setattr(runtime_module, "build_managed_dependency_snapshot", forbidden)
    monkeypatch.setattr(runtime_module, "_managed_cost_ledger_observation", forbidden)
    with pytest.raises(ManagedToolchainError, match="trust pins conflict"):
        provision_managed_local_run(**inputs, verify_only=False)
    assert accesses == []
    assert list(inputs["output_dir"].iterdir()) == []
    assert not (inputs["repository"] / ".mmaudit").exists()


def _automatic_inputs(tmp_path, config_factory):
    repository, archives, advisories, digest = setup_snapshot_inputs(tmp_path)
    output = _private_directory(tmp_path / "receipts")
    source = ManagedDependencySource(
        archive_root=archives, advisory_path=advisories, advisory_sha256=digest
    )
    return dict(
        repository=repository,
        output_dir=output,
        config=config_factory(),
        bundle=load_packaged_managed_toolchain_bundle(),
        dependency_source=source,
    )


@pytest.mark.parametrize("surface", ["archives", "advisory"])
def test_automatic_source_material_must_not_overlap_receipt_output(
    tmp_path, config_factory, surface
):
    inputs = _automatic_inputs(tmp_path, config_factory)
    selected = inputs["dependency_source"].model_dump()
    if surface == "archives":
        selected["archive_root"] = inputs["output_dir"]
    else:
        selected["advisory_path"] = inputs["output_dir"] / "advisory.json"
    inputs["dependency_source"] = ManagedDependencySource.model_validate(selected)
    with pytest.raises(ManagedProvisioningRuntimeError):
        provision_managed_local_run(**inputs, verify_only=False)
    assert list(inputs["output_dir"].iterdir()) == []
    assert not (inputs["repository"] / ".mmaudit").exists()


def test_build_failure_preserves_partial_output_and_never_resets_it(tmp_path, config_factory):
    inputs = _automatic_inputs(tmp_path, config_factory)
    result = provision_managed_local_run(**inputs, verify_only=False)
    snapshot = inputs["repository"] / result.config.dependency_preparation.offline_snapshot_path
    snapshot.unlink()
    retained = {path: path.read_bytes() for path in snapshot.parent.rglob("*") if path.is_file()}
    receipts = {path: path.read_bytes() for path in inputs["output_dir"].iterdir()}
    with pytest.raises(DependencySnapshotBuildError):
        provision_managed_local_run(**inputs, verify_only=False)
    assert not snapshot.exists()
    assert {path: path.read_bytes() for path in retained} == retained
    assert {path: path.read_bytes() for path in inputs["output_dir"].iterdir()} == receipts


def test_automatic_handoff_changes_only_dependency_config_and_returns_detached_copies(
    tmp_path, config_factory
):
    inputs = _automatic_inputs(tmp_path, config_factory)
    original = inputs["config"].model_dump(mode="json")
    before = scanner_workspace_sha256(inputs["repository"])
    result = provision_managed_local_run(**inputs, verify_only=False)
    assert inputs["config"].model_dump(mode="json") == original
    effective = inputs["config"].effective().model_dump(mode="json")
    derived = result.config.model_dump(mode="json")
    assert {k: v for k, v in derived.items() if k != "dependency_preparation"} == {
        k: v for k, v in effective.items() if k != "dependency_preparation"
    }
    assert result.config.dependency_preparation.enabled is True
    assert result.config.dependency_preparation.required is True
    assert result.receipt.plan.effective_config_sha256 == result.config.stable_hash()
    assert result.receipt.state.verified_requirement_ids == ("dependency-snapshot",)
    assert result.receipt.managed_run_ready is False
    assert scanner_workspace_sha256(inputs["repository"]) == before
    edited = result.config
    edited.execution.budget_usd = 1
    assert result.config.execution.budget_usd == 20
    assert "_config_json" not in repr(result)
    assert provision_managed_local_run(**inputs, verify_only=True) == result
    assert len(list(inputs["output_dir"].iterdir())) == 1


def test_verify_only_cannot_construct_missing_material_or_create_a_ledger(tmp_path, config_factory):
    inputs = _automatic_inputs(tmp_path, config_factory)
    ledger = _private_directory(tmp_path / "ledger")
    inputs["config"] = config_factory(execution={"cost_ledger_path": str(ledger / "costs.json")})
    with pytest.raises(DependencySnapshotBuildError):
        provision_managed_local_run(**inputs, verify_only=True)
    assert not (inputs["repository"] / ".mmaudit").exists()
    assert list(ledger.iterdir()) == list(inputs["output_dir"].iterdir()) == []


@pytest.mark.parametrize("enabled", [True, False])
def test_automatic_handoff_rejects_existing_explicit_pins_before_construction(
    tmp_path, config_factory, monkeypatch, enabled
):
    inputs = _automatic_inputs(tmp_path, config_factory)
    inputs["config"] = config_factory(
        dependency_preparation={
            "enabled": enabled,
            "offline_snapshot_path": "private/snapshot.json",
            "offline_snapshot_sha256": "a" * 64,
        }
    )

    def forbidden(**_kwargs):
        raise AssertionError("explicit snapshot selection must not be replaced")

    monkeypatch.setattr(runtime_module, "build_managed_dependency_snapshot", forbidden)
    with pytest.raises(ManagedProvisioningRuntimeError, match="conflicts"):
        provision_managed_local_run(**inputs, verify_only=False)
    assert not (inputs["repository"] / ".mmaudit").exists()
    assert list(inputs["output_dir"].iterdir()) == []


def test_automatic_handoff_enforces_tighter_selected_limits(tmp_path, config_factory):
    inputs = _automatic_inputs(tmp_path, config_factory)
    inputs["config"] = config_factory(dependency_preparation={"max_files": 1})
    with pytest.raises(DependencySnapshotBuildError):
        provision_managed_local_run(**inputs, verify_only=False)
    assert not (inputs["repository"] / ".mmaudit").exists()


@pytest.mark.parametrize("failure", ["bad-digest", "missing-archive", "corrupt-archive"])
def test_invalid_local_input_cannot_create_a_ledger_or_receipt(tmp_path, config_factory, failure):
    inputs = _automatic_inputs(tmp_path, config_factory)
    source = inputs["dependency_source"]
    if failure == "bad-digest":
        inputs["dependency_source"] = source.model_copy(update={"advisory_sha256": "0" * 64})
    else:
        archive = next(source.archive_root.iterdir())
        if failure == "missing-archive":
            archive.unlink()
        else:
            archive.write_bytes(b"synthetic invalid archive")
    ledger = _private_directory(tmp_path / "ledger")
    inputs["config"] = config_factory(execution={"cost_ledger_path": str(ledger / "costs.json")})
    with pytest.raises(DependencySnapshotBuildError):
        provision_managed_local_run(**inputs, verify_only=False)
    assert list(ledger.iterdir()) == list(inputs["output_dir"].iterdir()) == []


def test_build_target_identity_cannot_change_between_construction_and_handoff(
    tmp_path, config_factory, monkeypatch
):
    inputs = _automatic_inputs(tmp_path, config_factory)
    original = runtime_module.build_managed_dependency_snapshot

    def changed(**kwargs):
        (inputs["repository"] / "contracts/UsesDependency.sol").write_text(
            "// synthetic changed target"
        )
        return original(**kwargs)

    monkeypatch.setattr(runtime_module, "build_managed_dependency_snapshot", changed)
    with pytest.raises(ManagedProvisioningRuntimeError, match="different target"):
        provision_managed_local_run(**inputs, verify_only=False)
    assert list(inputs["output_dir"].iterdir()) == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("archive_root", Path("relative")),
        ("advisory_path", Path("relative")),
        ("advisory_sha256", "invalid"),
    ],
)
def test_automatic_input_selection_requires_exact_absolute_paths_and_digest(tmp_path, field, value):
    payload = dict(
        archive_root=tmp_path, advisory_path=tmp_path / "advisories.json", advisory_sha256="a" * 64
    )
    payload[field] = value
    with pytest.raises(ValueError):
        ManagedDependencySource.model_validate(payload)


def test_returned_config_cannot_be_rebound_to_another_receipt(tmp_path, config_factory):
    inputs = _automatic_inputs(tmp_path, config_factory)
    result = provision_managed_local_run(**inputs, verify_only=False)
    with pytest.raises(ManagedProvisioningRuntimeError, match="differs"):
        ManagedProvisioningRun(
            receipt=result.receipt, _config_json=canonical_audit_config_json(inputs["config"])
        )


def _dependency_inputs(tmp_path, config_factory):
    repository, archives, advisories, digest = setup_snapshot_inputs(tmp_path)
    built = build_managed_dependency_snapshot(
        repository=repository,
        archive_root=archives,
        advisory_path=advisories,
        advisory_sha256=digest,
    )
    config = config_factory(dependency_preparation=built.config.model_dump())
    output = _private_directory(tmp_path / "receipts")
    snapshot = repository / built.config.offline_snapshot_path
    value = json.loads(snapshot.read_bytes())
    package = snapshot.parent / value["projects"][0]["packages"][0]["source"]
    return repository, config, output, package


def test_runtime_records_verified_dependency_material_but_still_refuses_readiness(
    tmp_path, config_factory
):
    repository, config, output, _ = _dependency_inputs(tmp_path, config_factory)
    receipt = _run(config=config, repository=repository, output_dir=output, verify_only=True)
    assert receipt.state.verified_requirement_ids == ("dependency-snapshot",)
    observation = receipt.state.observations.dependency_snapshot
    assert observation.status is ManagedProvisioningObservationStatus.VERIFIED_NONAUTHORIZING
    assert (
        observation.observed_identity_sha256
        == config.dependency_preparation.offline_snapshot_sha256
    )
    assert "managed-toolchain-installation" in {r.requirement_id for r in receipt.state.refusals}
    assert receipt.runtime_authority is receipt.managed_run_ready is False
    assert receipt.state.transitive_dependency_closure_verified is False
    repeat = _run(config=config, repository=repository, output_dir=output, verify_only=True)
    assert repeat == receipt
    assert len(list(output.iterdir())) == 1


def test_runtime_records_closed_dependency_refusal_without_resetting_material(
    tmp_path, config_factory
):
    repository, config, output, package = _dependency_inputs(tmp_path, config_factory)
    file = package / "DependencyBase.sol"
    file.write_text("// changed synthetic material")
    receipt = _run(config=config, repository=repository, output_dir=output, verify_only=True)
    assert (
        receipt.state.observations.dependency_snapshot.refusal_code
        is ManagedProvisioningRefusalCode.INVALID_LOCAL_STATE
    )
    assert "dependency-snapshot" not in receipt.state.verified_requirement_ids
    assert file.read_text() == "// changed synthetic material"


@pytest.mark.parametrize("phase", ["prepared", "published"])
def test_dependency_drift_at_publication_cannot_leave_a_new_success_receipt(
    tmp_path, config_factory, monkeypatch, phase
):
    repository, config, output, package = _dependency_inputs(tmp_path, config_factory)
    method = "prepare" if phase == "prepared" else "_publish_or_verify_locked"
    original = getattr(runtime_module._PrivateOutputCustody, method)

    def mutate(self, *args):
        result = original(self, *args)
        (package / "DependencyBase.sol").write_text("// drift after observation")
        return result

    monkeypatch.setattr(runtime_module._PrivateOutputCustody, method, mutate)
    with pytest.raises(ManagedProvisioningRuntimeError, match="dependency material changed"):
        _run(config=config, repository=repository, output_dir=output, verify_only=True)
    assert list(output.iterdir()) == []
    assert (package / "DependencyBase.sol").read_text() == "// drift after observation"


def test_dependency_drift_on_repeat_preserves_the_original_historical_receipt(
    tmp_path, config_factory, monkeypatch
):
    repository, config, output, package = _dependency_inputs(tmp_path, config_factory)
    receipt = _run(config=config, repository=repository, output_dir=output, verify_only=True)
    path = next(output.iterdir())
    content = path.read_bytes()
    original = runtime_module._PrivateOutputCustody._publish_or_verify_locked

    def mutate(self, *args):
        result = original(self, *args)
        (package / "DependencyBase.sol").write_text("// changed synthetic dependency")
        return result

    monkeypatch.setattr(runtime_module._PrivateOutputCustody, "_publish_or_verify_locked", mutate)
    with pytest.raises(ManagedProvisioningRuntimeError, match="dependency material changed"):
        _run(config=config, repository=repository, output_dir=output, verify_only=True)
    assert list(output.iterdir()) == [path]
    assert path.read_bytes() == content
    assert parse_managed_provisioning_receipt(content) == receipt


def test_runtime_uses_one_detached_config_selection_through_dependency_rechecks(
    tmp_path, config_factory, monkeypatch
):
    repository, config, output, _ = _dependency_inputs(tmp_path, config_factory)
    selected = config.dependency_preparation.offline_snapshot_sha256
    original = runtime_module._PrivateOutputCustody.prepare

    def mutate(self, *args):
        result = original(self, *args)
        config.dependency_preparation.offline_snapshot_sha256 = "0" * 64
        return result

    monkeypatch.setattr(runtime_module._PrivateOutputCustody, "prepare", mutate)
    receipt = _run(config=config, repository=repository, output_dir=output, verify_only=True)
    assert receipt.state.observations.dependency_snapshot.observed_identity_sha256 == selected


def test_optional_dependency_configuration_never_opens_material(
    tmp_path, config_factory, monkeypatch
):
    def forbidden(**_kwargs):
        raise AssertionError("unselected dependency input must not be accessed")

    monkeypatch.setattr(runtime_module, "verify_managed_dependency_snapshot", forbidden)
    repository = _private_directory(tmp_path / "repo")
    output = _private_directory(tmp_path / "receipts")
    receipt = _run(
        config=config_factory(), repository=repository, output_dir=output, verify_only=True
    )
    assert (
        receipt.state.observations.dependency_snapshot.status
        is ManagedProvisioningObservationStatus.NOT_REQUIRED
    )


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _config(
    config_factory: Callable[..., AuditConfig],
    ledger_path: Path,
    *,
    budget_usd: float = 20.0,
) -> AuditConfig:
    return config_factory(
        execution={
            "cost_ledger_path": str(ledger_path),
            "budget_usd": budget_usd,
        }
    )


def _run(
    *,
    config: AuditConfig,
    repository: Path,
    output_dir: Path,
    verify_only: bool,
):
    return provision_managed_local_receipt(
        config=config,
        bundle=load_packaged_managed_toolchain_bundle(),
        repository=repository,
        output_dir=output_dir,
        verify_only=verify_only,
    )


def test_runtime_binds_repository_contents_and_portfolio_holds(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    source = repository / "Example.sol"
    source.write_text("contract Example {}\n", encoding="utf-8")
    output = _private_directory(tmp_path / "receipts")
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    config = _config(config_factory, ledger_path)
    ledger = AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    ledger.reserve_portfolio(
        "a" * 64,
        (
            PortfolioAttemptSlot("candidate-a", Decimal("0.5")),
            PortfolioAttemptSlot("candidate-b", Decimal("0.25")),
        ),
    )

    first = _run(
        config=config,
        repository=repository,
        output_dir=output,
        verify_only=True,
    )
    first_state = first.state
    first_identity = scanner_workspace_sha256(repository)

    assert first.plan.repository_identity_sha256 == first_identity
    assert first_state.repository_identity_sha256 == first_identity
    assert (
        first_state.observations.cost_ledger.action is ManagedProvisioningAction.VERIFIED_EXISTING
    )
    assert first_state.observations.cost_ledger.portfolio_hold_count == 1
    assert first_state.observations.cost_ledger.active_portfolio_hold_count == 1
    assert first_state.observations.cost_ledger.held_portfolio_usd_exact == "0.75"
    assert first_state.observations.cost_ledger.provisioning_marker_identity_sha256 is not None
    assert first.runtime_authority is False
    assert first.managed_run_ready is False

    source.write_text("contract Example { uint256 value; }\n", encoding="utf-8")
    second = _run(
        config=config,
        repository=repository,
        output_dir=output,
        verify_only=True,
    )

    assert second.state.repository_identity_sha256 == scanner_workspace_sha256(repository)
    assert second.state.repository_identity_sha256 != first_state.repository_identity_sha256
    assert second.state.state_sha256 != first_state.state_sha256
    assert second.receipt_sha256 != first.receipt_sha256
    assert len(tuple(output.glob("managed-provisioning-receipt-*.json"))) == 2


def test_runtime_detects_repository_mutation_during_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    source = repository / "source.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    output = _private_directory(tmp_path / "receipts")
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    config = _config(config_factory, ledger_path)
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    original = runtime_module._managed_cost_ledger_observation

    def mutate_repository(**kwargs: object):
        observation = original(**kwargs)  # type: ignore[arg-type]
        source.write_text("VALUE = 2\n", encoding="utf-8")
        return observation

    monkeypatch.setattr(runtime_module, "_managed_cost_ledger_observation", mutate_repository)

    with pytest.raises(ValueError, match="source inventory changed during custody"):
        _run(
            config=config,
            repository=repository,
            output_dir=output,
            verify_only=True,
        )

    assert tuple(output.iterdir()) == ()


def test_runtime_refuses_ledger_inside_repository_before_creation(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    ledger_parent = _private_directory(repository / "ledger")
    ledger_path = ledger_parent / "costs.json"
    output = _private_directory(tmp_path / "receipts")

    with pytest.raises(ManagedProvisioningRuntimeError, match="outside the repository"):
        _run(
            config=_config(config_factory, ledger_path),
            repository=repository,
            output_dir=output,
            verify_only=False,
        )

    assert not ledger_path.exists()
    assert not (ledger_parent / ".costs.json.lock").exists()
    assert tuple(output.iterdir()) == ()


def test_runtime_refuses_ledger_inside_receipt_directory_before_creation(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    output = _private_directory(tmp_path / "receipts")
    ledger_path = output / "costs.json"

    with pytest.raises(ManagedProvisioningRuntimeError, match="receipt directory"):
        _run(
            config=_config(config_factory, ledger_path),
            repository=repository,
            output_dir=output,
            verify_only=False,
        )

    assert tuple(output.iterdir()) == ()


def test_cost_observation_hashes_actual_configured_path_before_mutation(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    config = _config(config_factory, ledger_path)
    plan = derive_managed_provisioning_plan(
        load_packaged_managed_toolchain_bundle(),
        config,
        repository_identity_sha256="a" * 64,
    )
    mismatched = plan.cost_ledger.model_copy(update={"expected_path_sha256": "f" * 64})

    observation = runtime_module._managed_cost_ledger_observation(
        plan_cost_ledger=mismatched,
        config=config,
        verify_only=False,
    )

    assert observation.status is ManagedProvisioningObservationStatus.REFUSED
    assert observation.refusal_code is ManagedProvisioningRefusalCode.IDENTITY_MISMATCH
    assert not ledger_path.exists()
    assert not (ledger_parent / ".costs.json.lock").exists()


@pytest.mark.parametrize(
    "marker_state",
    ("missing", "symlink", "hardlinked", "mode-invalid"),
)
def test_verify_only_refuses_invalid_provisioning_marker_without_repair(
    marker_state: str,
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    output = _private_directory(tmp_path / "receipts")
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    marker = ledger_parent / ".costs.json.provision.lock"
    config = _config(config_factory, ledger_path)
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    ledger_bytes = ledger_path.read_bytes()

    if marker_state == "missing":
        marker.unlink()
    elif marker_state == "symlink":
        marker.unlink()
        target = ledger_parent / "synthetic-marker-target"
        target.write_bytes(b"")
        target.chmod(0o600)
        marker.symlink_to(target.name)
    elif marker_state == "hardlinked":
        os.link(marker, ledger_parent / "synthetic-marker-peer")
    else:
        marker.chmod(0o640)

    receipt = _run(
        config=config,
        repository=repository,
        output_dir=output,
        verify_only=True,
    )

    observation = receipt.state.observations.cost_ledger
    assert observation.status is ManagedProvisioningObservationStatus.REFUSED
    assert observation.refusal_code is ManagedProvisioningRefusalCode.INVALID_LOCAL_STATE
    assert observation.provisioning_marker_identity_sha256 is None
    assert ledger_path.read_bytes() == ledger_bytes
    if marker_state == "missing":
        assert not marker.exists()
    elif marker_state == "symlink":
        assert marker.is_symlink()
    elif marker_state == "hardlinked":
        assert marker.stat().st_nlink == 2
    else:
        assert marker.stat().st_mode & 0o777 == 0o640


def test_cost_observation_refuses_lock_replacement_between_bound_snapshots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    output = _private_directory(tmp_path / "receipts")
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    lock_path = ledger_parent / ".costs.json.lock"
    config = _config(config_factory, ledger_path)
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    ledger_bytes = ledger_path.read_bytes()
    original_snapshot = AtomicCostLedger.snapshot_with_identity_sha256
    calls = 0

    def replace_before_second_snapshot(
        ledger: AtomicCostLedger,
    ) -> tuple[str, CostLedgerSnapshot]:
        nonlocal calls
        calls += 1
        if calls == 3:
            lock_path.unlink()
            lock_path.write_bytes(b"")
            lock_path.chmod(0o600)
        return original_snapshot(ledger)

    monkeypatch.setattr(
        AtomicCostLedger,
        "snapshot_with_identity_sha256",
        replace_before_second_snapshot,
    )

    receipt = _run(
        config=config,
        repository=repository,
        output_dir=output,
        verify_only=True,
    )

    observation = receipt.state.observations.cost_ledger
    assert calls == 3
    assert observation.status is ManagedProvisioningObservationStatus.REFUSED
    assert observation.refusal_code is ManagedProvisioningRefusalCode.INVALID_LOCAL_STATE
    assert ledger_path.read_bytes() == ledger_bytes


def test_runtime_rejects_tampered_existing_receipt_without_ledger_mutation(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    output = _private_directory(tmp_path / "receipts")
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    config = _config(config_factory, ledger_path)
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    receipt_envelope = _run(
        config=config,
        repository=repository,
        output_dir=output,
        verify_only=True,
    )
    ledger_bytes = ledger_path.read_bytes()
    receipt = output / (f"managed-provisioning-receipt-{receipt_envelope.receipt_sha256}.json")
    receipt.write_bytes(receipt.read_bytes() + b" ")

    with pytest.raises(ValueError):
        _run(
            config=config,
            repository=repository,
            output_dir=output,
            verify_only=True,
        )

    assert ledger_path.read_bytes() == ledger_bytes


def test_existing_receipt_fifo_swap_is_rejected_without_blocking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFOs unavailable")
    repository = _private_directory(tmp_path / "repo")
    output = _private_directory(tmp_path / "receipts")
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    config = _config(config_factory, ledger_path)
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    receipt = _run(
        config=config,
        repository=repository,
        output_dir=output,
        verify_only=True,
    )
    final_name = f"managed-provisioning-receipt-{receipt.receipt_sha256}.json"
    final = output / final_name
    original_open = os.open
    swapped = False

    def swap_to_fifo_before_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if not swapped and path == final_name and dir_fd is not None:
            swapped = True
            final.unlink()
            os.mkfifo(final, mode=0o600)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(runtime_module.os, "open", swap_to_fifo_before_open)

    with pytest.raises(ManagedProvisioningRuntimeError, match="changed while being reopened"):
        _run(
            config=config,
            repository=repository,
            output_dir=output,
            verify_only=True,
        )

    assert swapped is True
    assert stat.S_ISFIFO(final.stat().st_mode)


def test_output_directory_swap_is_detected_and_never_writes_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    output = _private_directory(tmp_path / "receipts")
    moved = tmp_path / "receipts-original"
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    config = _config(config_factory, ledger_path)
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    original_write = runtime_module._write_all

    def swap_output(descriptor: int, content: bytes) -> None:
        output.rename(moved)
        _private_directory(output)
        original_write(descriptor, content)

    monkeypatch.setattr(runtime_module, "_write_all", swap_output)

    with pytest.raises(ManagedProvisioningRuntimeError, match="output path changed"):
        _run(
            config=config,
            repository=repository,
            output_dir=output,
            verify_only=True,
        )

    assert tuple(output.iterdir()) == ()
    assert tuple(moved.iterdir()) == ()


def test_receipt_publication_is_atomic_for_identical_concurrent_writers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    (repository / "source.py").write_text("VALUE = 1\n", encoding="utf-8")
    output = _private_directory(tmp_path / "receipts")
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    config = _config(config_factory, ledger_path)
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    barrier = threading.Barrier(2)
    original_publish = runtime_module._PrivateOutputCustody.publish_or_verify

    def synchronized_publish(*args: object, **kwargs: object):
        barrier.wait(timeout=5)
        return original_publish(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        runtime_module._PrivateOutputCustody,
        "publish_or_verify",
        synchronized_publish,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                _run,
                config=config,
                repository=repository,
                output_dir=output,
                verify_only=True,
            )
            for _ in range(2)
        ]
        receipts = [future.result(timeout=10) for future in futures]

    assert receipts[0] == receipts[1]
    paths = tuple(output.iterdir())
    assert len(paths) == 1
    assert paths[0].name == (f"managed-provisioning-receipt-{receipts[0].receipt_sha256}.json")
    assert parse_managed_provisioning_receipt(paths[0].read_bytes()) == receipts[0]


def test_failed_temp_write_never_exposes_partial_final_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    output = _private_directory(tmp_path / "receipts")
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    config = _config(config_factory, ledger_path)
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))

    def partial_write_then_fail(descriptor: int, content: bytes) -> None:
        assert os.write(descriptor, content[:10]) == 10
        raise OSError("synthetic local write failure")

    monkeypatch.setattr(runtime_module, "_write_all", partial_write_then_fail)

    with pytest.raises(OSError, match="synthetic local write failure"):
        _run(
            config=config,
            repository=repository,
            output_dir=output,
            verify_only=True,
        )

    assert tuple(output.iterdir()) == ()


def test_post_link_stat_failure_strictly_rolls_back_final_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    output = _private_directory(tmp_path / "receipts")
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    config = _config(config_factory, ledger_path)
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    original_stat = os.stat
    failed = False

    def fail_first_final_stat(
        path: str | bytes | int | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal failed
        if (
            not failed
            and isinstance(path, str)
            and path.startswith("managed-provisioning-receipt-")
        ):
            failed = True
            raise OSError("synthetic final stat failure")
        return original_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(runtime_module.os, "stat", fail_first_final_stat)

    with pytest.raises(ManagedProvisioningRuntimeError, match="could not be published safely"):
        _run(
            config=config,
            repository=repository,
            output_dir=output,
            verify_only=True,
        )

    assert failed is True
    assert tuple(output.iterdir()) == ()


def test_failed_final_rollback_is_surfaced_as_a_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    output = _private_directory(tmp_path / "receipts")
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    config = _config(config_factory, ledger_path)
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    original_stat = os.stat
    original_unlink = os.unlink
    failed = False

    def fail_first_final_stat(
        path: str | bytes | int | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal failed
        if (
            not failed
            and isinstance(path, str)
            and path.startswith("managed-provisioning-receipt-")
        ):
            failed = True
            raise OSError("synthetic final stat failure")
        return original_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    def fail_final_unlink(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
    ) -> None:
        if isinstance(path, str) and path.startswith("managed-provisioning-receipt-"):
            raise OSError("synthetic final unlink failure")
        original_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(runtime_module.os, "stat", fail_first_final_stat)
    monkeypatch.setattr(runtime_module.os, "unlink", fail_final_unlink)

    with pytest.raises(ManagedProvisioningRuntimeError, match="could not be rolled back") as error:
        _run(
            config=config,
            repository=repository,
            output_dir=output,
            verify_only=True,
        )

    assert failed is True
    assert error.value.__cause__ is not None
    assert "could not be published safely" in str(error.value.__cause__)
    receipts = tuple(output.glob("managed-provisioning-receipt-*.json"))
    assert len(receipts) == 1
    assert parse_managed_provisioning_receipt(receipts[0].read_bytes())


def test_repository_receipt_is_honest_point_in_time_after_source_finalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    source = repository / "source.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    output = _private_directory(tmp_path / "receipts")
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    config = _config(config_factory, ledger_path)
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    observed_identity = scanner_workspace_sha256(repository)
    original_publish = runtime_module._PrivateOutputCustody.publish_or_verify

    @contextmanager
    def publish_then_mutate(*args: object, **kwargs: object):
        with original_publish(*args, **kwargs) as publication:  # type: ignore[arg-type]
            source.write_text("VALUE = 2\n", encoding="utf-8")
            yield publication

    monkeypatch.setattr(
        runtime_module._PrivateOutputCustody,
        "publish_or_verify",
        publish_then_mutate,
    )

    receipt = _run(
        config=config,
        repository=repository,
        output_dir=output,
        verify_only=True,
    )

    assert receipt.plan.repository_identity_sha256 == observed_identity
    assert receipt.state.repository_identity_sha256 == observed_identity
    assert scanner_workspace_sha256(repository) != observed_identity
    published = tuple(output.glob("managed-provisioning-receipt-*.json"))
    assert len(published) == 1
    assert parse_managed_provisioning_receipt(published[0].read_bytes()) == receipt


def test_receipt_final_name_is_not_linked_before_source_finalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    (repository / "source.py").write_text("VALUE = 1\n", encoding="utf-8")
    output = _private_directory(tmp_path / "receipts")
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    config = _config(config_factory, ledger_path)
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    original_finalize = ScannerWorkspaceSourceCustody.finalize
    original_link = os.link
    source_finalized = False

    def observe_finalize(custody: ScannerWorkspaceSourceCustody) -> str:
        nonlocal source_finalized
        result = original_finalize(custody)
        source_finalized = True
        return result

    def require_finalized_before_link(
        source: str,
        destination: str,
        *,
        src_dir_fd: int,
        dst_dir_fd: int,
        follow_symlinks: bool,
    ) -> None:
        assert source_finalized is True
        original_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(ScannerWorkspaceSourceCustody, "finalize", observe_finalize)
    monkeypatch.setattr(runtime_module.os, "link", require_finalized_before_link)

    receipt = _run(
        config=config,
        repository=repository,
        output_dir=output,
        verify_only=True,
    )

    assert source_finalized is True
    published = tuple(output.glob("managed-provisioning-receipt-*.json"))
    assert len(published) == 1
    assert parse_managed_provisioning_receipt(published[0].read_bytes()) == receipt


def test_receipt_unlinked_during_source_finalization_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    output = _private_directory(tmp_path / "receipts")
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    config = _config(config_factory, ledger_path)
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    original_publish = runtime_module._PrivateOutputCustody.publish_or_verify

    @contextmanager
    def unlink_after_finalize(*args: object, **kwargs: object):
        with original_publish(*args, **kwargs) as publication:  # type: ignore[arg-type]
            yield publication
            (output / publication.name).unlink()

    monkeypatch.setattr(
        runtime_module._PrivateOutputCustody,
        "publish_or_verify",
        unlink_after_finalize,
    )

    with pytest.raises(ManagedProvisioningRuntimeError, match="could not be reopened safely"):
        _run(
            config=config,
            repository=repository,
            output_dir=output,
            verify_only=True,
        )

    assert tuple(output.iterdir()) == ()


def test_receipt_content_changed_during_source_finalization_is_rolled_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    output = _private_directory(tmp_path / "receipts")
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    config = _config(config_factory, ledger_path)
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    original_publish = runtime_module._PrivateOutputCustody.publish_or_verify

    @contextmanager
    def alter_after_finalize(*args: object, **kwargs: object):
        with original_publish(*args, **kwargs) as publication:  # type: ignore[arg-type]
            yield publication
            final = output / publication.name
            final.write_bytes(b"x" * final.stat().st_size)
            final.chmod(0o600)

    monkeypatch.setattr(
        runtime_module._PrivateOutputCustody,
        "publish_or_verify",
        alter_after_finalize,
    )

    with pytest.raises(ValueError):
        _run(
            config=config,
            repository=repository,
            output_dir=output,
            verify_only=True,
        )

    assert tuple(output.iterdir()) == ()


def test_identical_receipt_replacement_during_finalization_is_detected_not_deleted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    output = _private_directory(tmp_path / "receipts")
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    config = _config(config_factory, ledger_path)
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    original_publish = runtime_module._PrivateOutputCustody.publish_or_verify
    original_identity: tuple[int, int] | None = None

    @contextmanager
    def replace_after_finalize(*args: object, **kwargs: object):
        nonlocal original_identity
        with original_publish(*args, **kwargs) as publication:  # type: ignore[arg-type]
            yield publication
            final = output / publication.name
            content = final.read_bytes()
            details = final.stat()
            original_identity = (details.st_dev, details.st_ino)
            replacement = output / ".synthetic-replacement.tmp"
            replacement.write_bytes(content)
            replacement.chmod(0o600)
            final.unlink()
            replacement.rename(final)

    monkeypatch.setattr(
        runtime_module._PrivateOutputCustody,
        "publish_or_verify",
        replace_after_finalize,
    )

    with pytest.raises(ManagedProvisioningRuntimeError, match="changed before rollback") as error:
        _run(
            config=config,
            repository=repository,
            output_dir=output,
            verify_only=True,
        )

    assert error.value.__cause__ is not None
    assert "identity changed during finalization" in str(error.value.__cause__)
    replacements = tuple(output.glob("managed-provisioning-receipt-*.json"))
    assert len(replacements) == 1
    replacement = replacements[0]
    details = replacement.stat()
    assert original_identity is not None
    assert (details.st_dev, details.st_ino) != original_identity
    assert parse_managed_provisioning_receipt(replacement.read_bytes())


def test_failed_publisher_rolls_back_before_concurrent_verifier_returns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository_a = _private_directory(tmp_path / "repo-a")
    repository_b = _private_directory(tmp_path / "repo-b")
    source_a = repository_a / "source.py"
    source_a.write_text("VALUE = 1\n", encoding="utf-8")
    (repository_b / "source.py").write_text("VALUE = 1\n", encoding="utf-8")
    output = _private_directory(tmp_path / "receipts")
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    config = _config(config_factory, ledger_path)
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    first_published = threading.Event()
    second_attempted = threading.Event()
    assignment_lock = threading.Lock()
    first_assigned = False
    original_publish = runtime_module._PrivateOutputCustody.publish_or_verify

    @contextmanager
    def coordinated_publish(*args: object, **kwargs: object):
        nonlocal first_assigned
        with assignment_lock:
            is_first = not first_assigned
            first_assigned = True
        if is_first:
            with original_publish(*args, **kwargs) as publication:  # type: ignore[arg-type]
                first_published.set()
                assert second_attempted.wait(timeout=5)
                yield publication
                raise ValueError("synthetic post-publication failure")
            return
        second_attempted.set()
        with original_publish(*args, **kwargs) as publication:  # type: ignore[arg-type]
            yield publication

    monkeypatch.setattr(
        runtime_module._PrivateOutputCustody,
        "publish_or_verify",
        coordinated_publish,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        failing = executor.submit(
            _run,
            config=config,
            repository=repository_a,
            output_dir=output,
            verify_only=True,
        )
        assert first_published.wait(timeout=5)
        succeeding = executor.submit(
            _run,
            config=config,
            repository=repository_b,
            output_dir=output,
            verify_only=True,
        )
        with pytest.raises(ValueError, match="synthetic post-publication failure"):
            failing.result(timeout=10)
        receipt = succeeding.result(timeout=10)

    paths = tuple(output.glob("managed-provisioning-receipt-*.json"))
    assert len(paths) == 1
    assert parse_managed_provisioning_receipt(paths[0].read_bytes()) == receipt


def test_swapped_prepared_inode_never_leaves_a_poisoned_final_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    output = _private_directory(tmp_path / "receipts")
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    config = _config(config_factory, ledger_path)
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    original_link = os.link

    def swap_then_link(
        source: str,
        destination: str,
        *,
        src_dir_fd: int,
        dst_dir_fd: int,
        follow_symlinks: bool,
    ) -> None:
        temporary = output / source
        temporary.unlink()
        temporary.write_bytes(b"same-user synthetic replacement")
        temporary.chmod(0o600)
        original_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(runtime_module.os, "link", swap_then_link)

    with pytest.raises(ManagedProvisioningRuntimeError, match="changed during publication"):
        _run(
            config=config,
            repository=repository,
            output_dir=output,
            verify_only=True,
        )

    assert tuple(output.glob("managed-provisioning-receipt-*.json")) == ()
    assert len(tuple(output.glob("*.tmp"))) == 1


def test_output_unlock_error_cannot_escape_without_a_rollback_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = _private_directory(tmp_path / "repo")
    output = _private_directory(tmp_path / "receipts")
    ledger_parent = _private_directory(tmp_path / "ledger")
    ledger_path = ledger_parent / "costs.json"
    config = _config(config_factory, ledger_path)
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    real_fcntl = runtime_module.fcntl

    class FcntlProxy:
        LOCK_EX = real_fcntl.LOCK_EX
        LOCK_UN = real_fcntl.LOCK_UN

        @staticmethod
        def flock(descriptor: int, operation: int) -> None:
            if operation == real_fcntl.LOCK_UN:
                raise OSError("synthetic unlock failure")
            real_fcntl.flock(descriptor, operation)

    monkeypatch.setattr(runtime_module, "fcntl", FcntlProxy)

    receipt = _run(
        config=config,
        repository=repository,
        output_dir=output,
        verify_only=True,
    )

    paths = tuple(output.glob("managed-provisioning-receipt-*.json"))
    assert len(paths) == 1
    assert parse_managed_provisioning_receipt(paths[0].read_bytes()) == receipt
