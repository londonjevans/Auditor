from __future__ import annotations

import shutil
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import mmaudit.release_candidate as candidate_module
import mmaudit.release_runtime as runtime_module
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release import ReleaseGateId, ReleaseGateStatus
from mmaudit.release_candidate import ReleaseCandidateObservation
from mmaudit.release_gates import (
    ReleaseGatePrerequisiteBlocker,
    ReleaseGateReceipt,
    build_release_gate_evidence_bundle,
    build_release_gate_receipt,
    get_release_gate_fixed_plan,
)
from mmaudit.release_io import write_json_evidence
from mmaudit.release_runtime import (
    execute_local_release_gate,
    validate_local_release_gate_receipts,
    validate_local_release_gate_result_artifact,
)

START = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
END = datetime(2026, 7, 28, 12, 1, tzinfo=UTC)
RUN_BINDING_SHA256 = "b" * 64


def _candidate() -> ReleaseCandidateObservation:
    payload = {
        "schema_version": "1.0",
        "generated_by": "mmaudit",
        "candidate_commit": "1" * 40,
        "git_object_format": "sha1",
        "candidate_tree_object": "2" * 40,
        "tracked_source_inventory_sha256": "3" * 64,
        "tracked_file_count": 1,
        "tracked_file_bytes": 12,
        "worktree_clean": True,
        "worktree_status_sha256": canonical_sha256([]),
        "observed_at": START.isoformat().replace("+00:00", "Z"),
    }
    return ReleaseCandidateObservation.model_validate(
        {
            **payload,
            "observation_sha256": canonical_sha256(payload),
        }
    )


def _self_authored_executed_receipt(
    evidence_root: Path,
    *,
    status: ReleaseGateStatus,
) -> ReleaseGateReceipt:
    gate_id = ReleaseGateId.RUFF_CHECK
    plan = get_release_gate_fixed_plan(gate_id)
    binding = write_json_evidence(
        evidence_root=evidence_root,
        relative_path=plan.result_artifact_path,
        value={"self_authored": status.value},
    )
    passed = status is ReleaseGateStatus.PASSED
    return build_release_gate_receipt(
        gate_id=gate_id,
        candidate_observation_sha256=_candidate().observation_sha256,
        run_binding_sha256=RUN_BINDING_SHA256,
        fixed_plan_sha256=plan.fixed_plan_sha256,
        started_at=START,
        ended_at=END,
        argv=("python", "-P", "-m", "ruff", "check", "."),
        tool_name="ruff",
        tool_version="1.2.3",
        tool_executable_sha256="c" * 64,
        tool_distribution_sha256="d" * 64,
        execution_evidence=ExecutionEvidenceKind.REAL,
        exit_code=0 if passed else 7,
        timed_out=False,
        stdout=b"self-authored output",
        stderr=b"",
        summary="self-authored local result",
        prerequisite_blocker=None,
        artifact_bindings=(binding,),
    )


def _blocked_receipt(
    gate_id: ReleaseGateId,
    *,
    artifact_bindings: tuple[Any, ...] = (),
    ended_at: datetime = START,
    result_summary: str = (
        "local execution is blocked until the runner provides OS network confinement and "
        "descriptor-rooted candidate and evidence I/O"
    ),
    blocker_summary: str = (
        "No local runner currently proves pre-startup import isolation, subprocess network "
        "denial, and descriptor-rooted evidence writes."
    ),
    stdout: bytes = b"",
    tool_name: str | None = None,
) -> ReleaseGateReceipt:
    plan = get_release_gate_fixed_plan(gate_id)
    return build_release_gate_receipt(
        gate_id=gate_id,
        candidate_observation_sha256=_candidate().observation_sha256,
        run_binding_sha256=RUN_BINDING_SHA256,
        fixed_plan_sha256=plan.fixed_plan_sha256,
        started_at=START,
        ended_at=ended_at,
        argv=("mmaudit-release", "blocked-local-gate", gate_id.value),
        tool_name=tool_name or plan.module or "mmaudit-release",
        tool_version=None,
        tool_executable_sha256=None,
        tool_distribution_sha256=None,
        execution_evidence=ExecutionEvidenceKind.UNVERIFIED,
        exit_code=None,
        timed_out=False,
        stdout=stdout,
        stderr=b"",
        summary=result_summary,
        prerequisite_blocker=ReleaseGatePrerequisiteBlocker(
            code="secure_local_gate_runner_unavailable",
            summary=blocker_summary,
        ),
        artifact_bindings=artifact_bindings,
    )


@pytest.mark.parametrize(
    "gate_id",
    (
        ReleaseGateId.RUFF_FORMAT,
        ReleaseGateId.RUFF_CHECK,
        ReleaseGateId.MYPY,
        ReleaseGateId.PYTEST,
    ),
)
def test_local_gate_returns_typed_blocker_before_filesystem_or_process_access(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    gate_id: ReleaseGateId,
) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("blocked local gate attempted filesystem or process access")

    monkeypatch.setattr(runtime_module, "_require_executing_repository_root", forbidden)
    monkeypatch.setattr(runtime_module, "_require_unlinked_directory", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    missing_repository = tmp_path / "missing-candidate"
    missing_evidence = tmp_path / "missing-evidence"

    receipt = execute_local_release_gate(
        gate_id=gate_id,
        repository_root=missing_repository,
        evidence_root=missing_evidence,
        candidate=_candidate(),
        run_binding_sha256=RUN_BINDING_SHA256,
    )

    assert receipt.status is ReleaseGateStatus.BLOCKED_TECHNICAL
    assert receipt.execution_evidence.value == "unverified"
    assert receipt.prerequisite_blocker is not None
    assert receipt.prerequisite_blocker.code == "secure_local_gate_runner_unavailable"
    assert receipt.tool_version is None
    assert receipt.tool_executable_sha256 is None
    assert receipt.tool_distribution_sha256 is None
    assert receipt.artifact_bindings == []
    assert receipt.argv == ("mmaudit-release", "blocked-local-gate", gate_id.value)
    assert not missing_repository.exists()
    assert not missing_evidence.exists()


def test_local_gate_rejects_candidate_proxy_before_property_access(tmp_path: Path) -> None:
    property_accessed = False

    class SideEffectingCandidateProxy:
        @property
        def observation_sha256(self) -> str:
            nonlocal property_accessed
            property_accessed = True
            raise AssertionError("candidate proxy property executed")

    with pytest.raises(TypeError, match="exact observation"):
        execute_local_release_gate(
            gate_id=ReleaseGateId.RUFF_CHECK,
            repository_root=tmp_path / "candidate",
            evidence_root=tmp_path / "evidence",
            candidate=SideEffectingCandidateProxy(),  # type: ignore[arg-type]
            run_binding_sha256=RUN_BINDING_SHA256,
        )

    assert property_accessed is False
    assert tuple(tmp_path.iterdir()) == ()


def test_local_gate_rejects_invalid_binding_before_filesystem_access(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        runtime_module,
        "_require_executing_repository_root",
        lambda _path: pytest.fail("invalid binding reached filesystem access"),
    )

    with pytest.raises(ValueError, match="run binding"):
        execute_local_release_gate(
            gate_id=ReleaseGateId.RUFF_CHECK,
            repository_root=tmp_path / "candidate",
            evidence_root=tmp_path / "evidence",
            candidate=_candidate(),
            run_binding_sha256="not-a-digest",
        )

    assert tuple(tmp_path.iterdir()) == ()


@pytest.mark.parametrize(
    "status",
    (ReleaseGateStatus.PASSED, ReleaseGateStatus.FAILED),
)
def test_current_plan_rejects_self_authored_executed_result_artifact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: ReleaseGateStatus,
) -> None:
    receipt = _self_authored_executed_receipt(tmp_path, status=status)
    binding = receipt.artifact_bindings[0]

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("current-plan rejection attempted to read self-authored evidence")

    monkeypatch.setattr(runtime_module, "revalidate_evidence_file_binding", forbidden)

    with pytest.raises(ValueError, match="current local release plan rejects executed"):
        validate_local_release_gate_result_artifact(
            evidence_root=tmp_path,
            binding=binding,
            expected_candidate_observation_sha256=_candidate().observation_sha256,
            expected_run_binding_sha256=RUN_BINDING_SHA256,
            expected_receipt=receipt,
        )


def test_blocked_local_receipt_set_rejects_claimed_result_artifact(tmp_path: Path) -> None:
    clean_receipts = tuple(_blocked_receipt(gate_id) for gate_id in ReleaseGateId)
    clean_bundle = build_release_gate_evidence_bundle(
        candidate_observation_sha256=_candidate().observation_sha256,
        run_binding_sha256=RUN_BINDING_SHA256,
        receipts=clean_receipts,
    )
    assert (
        validate_local_release_gate_receipts(
            bundle=clean_bundle,
            evidence_root=tmp_path,
        )
        == ()
    )

    binding = write_json_evidence(
        evidence_root=tmp_path,
        relative_path=get_release_gate_fixed_plan(ReleaseGateId.RUFF_CHECK).result_artifact_path,
        value={"synthetic": True},
    )
    receipts_with_claim = tuple(
        _blocked_receipt(
            gate_id,
            artifact_bindings=(binding,) if gate_id is ReleaseGateId.RUFF_CHECK else (),
        )
        for gate_id in ReleaseGateId
    )
    bundle_with_claim = build_release_gate_evidence_bundle(
        candidate_observation_sha256=_candidate().observation_sha256,
        run_binding_sha256=RUN_BINDING_SHA256,
        receipts=receipts_with_claim,
    )

    with pytest.raises(ValueError, match="canonical current-plan blocker"):
        validate_local_release_gate_receipts(
            bundle=bundle_with_claim,
            evidence_root=tmp_path,
        )


@pytest.mark.parametrize(
    "receipt_overrides",
    (
        {"ended_at": END},
        {"result_summary": "noncanonical blocker summary"},
        {"blocker_summary": "Noncanonical prerequisite blocker."},
        {"stdout": b"unexpected output"},
        {"tool_name": "not-ruff"},
    ),
)
def test_local_receipt_set_rejects_noncanonical_blocker_fields(
    tmp_path: Path,
    receipt_overrides: dict[str, Any],
) -> None:
    receipts = tuple(
        (
            _blocked_receipt(gate_id, **receipt_overrides)
            if gate_id is ReleaseGateId.RUFF_CHECK
            else _blocked_receipt(gate_id)
        )
        for gate_id in ReleaseGateId
    )
    bundle = build_release_gate_evidence_bundle(
        candidate_observation_sha256=_candidate().observation_sha256,
        run_binding_sha256=RUN_BINDING_SHA256,
        receipts=receipts,
    )

    with pytest.raises(ValueError, match="canonical current-plan blocker"):
        validate_local_release_gate_receipts(bundle=bundle, evidence_root=tmp_path)


@pytest.mark.parametrize(
    "status",
    (ReleaseGateStatus.PASSED, ReleaseGateStatus.FAILED),
)
def test_local_receipt_set_rejects_self_authored_executed_receipt(
    tmp_path: Path,
    status: ReleaseGateStatus,
) -> None:
    evidence = tmp_path / "self-authored"
    evidence.mkdir()
    forged = _self_authored_executed_receipt(evidence, status=status)
    receipts = tuple(
        forged if gate_id is ReleaseGateId.RUFF_CHECK else _blocked_receipt(gate_id)
        for gate_id in ReleaseGateId
    )
    bundle = build_release_gate_evidence_bundle(
        candidate_observation_sha256=_candidate().observation_sha256,
        run_binding_sha256=RUN_BINDING_SHA256,
        receipts=receipts,
    )

    with pytest.raises(ValueError, match="canonical current-plan blocker"):
        validate_local_release_gate_receipts(bundle=bundle, evidence_root=evidence)


def test_release_candidate_custody_rejects_ancestor_twin_use_and_restore(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    authority = tmp_path / "authority"
    repository = authority / "candidate"
    repository.mkdir(parents=True)
    git = candidate_module._trusted_git_executable()
    git_environment = candidate_module._git_environment()

    def run_git(*arguments: str) -> None:
        subprocess.run(
            [str(git), "-C", str(repository), *arguments],
            check=True,
            capture_output=True,
            env=git_environment,
            shell=False,
        )

    run_git("init", "-q")
    run_git("config", "user.name", "Synthetic Release Test")
    run_git("config", "user.email", "release-test@example.invalid")
    source = repository / "src/mmaudit/example.py"
    source.parent.mkdir(parents=True)
    (source.parent / "__init__.py").write_bytes(b"\n")
    source.write_bytes(b"VALUE = 1\n")
    run_git("add", "--all")
    run_git("commit", "-q", "-m", "Synthetic release candidate")
    twin_authority = tmp_path / "twin-authority"
    shutil.copytree(authority, twin_authority)
    resolved_repository = repository.resolve(strict=True)
    monkeypatch.setattr(
        candidate_module,
        "_require_executing_repository_root",
        lambda _root: resolved_repository,
    )
    candidate = candidate_module.observe_release_candidate(resolved_repository)
    custody = candidate_module.observe_release_candidate_custody(
        resolved_repository,
        expected_candidate=candidate,
    )

    parked_authority = tmp_path / "parked-authority"
    original_mode = stat.S_IMODE(authority.stat().st_mode)
    authority.rename(parked_authority)
    twin_authority.rename(authority)
    assert (authority / "candidate/src/mmaudit/example.py").read_bytes() == b"VALUE = 1\n"
    authority.rename(twin_authority)
    parked_authority.rename(authority)
    authority.chmod(original_mode ^ 0o004)
    authority.chmod(original_mode)

    with pytest.raises(ValueError, match="release candidate custody"):
        candidate_module.require_unchanged_release_candidate_custody(custody)


def test_local_gate_blocks_ignored_pytest_configuration_without_consuming_it(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "candidate"
    evidence = tmp_path / "evidence"
    ignored_config = repository / "pytest.ini"
    ignored_conftest = repository / "tests/conftest.py"
    ignored_conftest.parent.mkdir(parents=True)
    evidence.mkdir()
    ignored_config.write_bytes(b"[pytest]\n")
    ignored_conftest.write_bytes(b"raise AssertionError('must not load')\n")

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("blocked local gate attempted to inspect or execute ignored input")

    monkeypatch.setattr(subprocess, "Popen", forbidden)

    receipt = execute_local_release_gate(
        gate_id=ReleaseGateId.PYTEST,
        repository_root=repository,
        evidence_root=evidence,
        candidate=_candidate(),
        run_binding_sha256=RUN_BINDING_SHA256,
    )

    assert receipt.status is ReleaseGateStatus.BLOCKED_TECHNICAL
    assert ignored_config.read_bytes() == b"[pytest]\n"
    assert ignored_conftest.read_bytes() == b"raise AssertionError('must not load')\n"
    assert tuple(evidence.iterdir()) == ()


def test_local_gate_blocks_before_real_directory_adoption_or_victim_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "candidate"
    evidence = tmp_path / "evidence"
    parked_evidence = tmp_path / "parked-evidence"
    victim = tmp_path / "victim"
    repository.mkdir()
    evidence.mkdir()
    victim.mkdir()
    sentinel = victim / "sentinel"
    sentinel.write_bytes(b"unchanged")
    evidence.rename(parked_evidence)
    victim.rename(evidence)

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("blocked local gate attempted an adopted-root side effect")

    monkeypatch.setattr(runtime_module, "_require_unlinked_directory", forbidden)
    monkeypatch.setattr(runtime_module, "_create_fresh_private_file", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    receipt = execute_local_release_gate(
        gate_id=ReleaseGateId.RUFF_CHECK,
        repository_root=repository,
        evidence_root=evidence,
        candidate=_candidate(),
        run_binding_sha256=RUN_BINDING_SHA256,
    )

    assert receipt.status is ReleaseGateStatus.BLOCKED_TECHNICAL
    moved_sentinel = evidence / sentinel.name
    assert moved_sentinel.read_bytes() == b"unchanged"
    assert tuple(evidence.iterdir()) == (moved_sentinel,)
    assert tuple(parked_evidence.iterdir()) == ()


def test_local_gate_blocks_before_tracked_tool_and_stdlib_shadow_import(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "candidate"
    evidence = tmp_path / "evidence"
    package = repository / "src/mmaudit"
    package.mkdir(parents=True)
    evidence.mkdir()
    (package / "__init__.py").write_bytes(b'CANDIDATE_MARKER = "exact"\n')
    shadow_paths = tuple(
        repository / "src" / f"{module_name}.py"
        for module_name in ("ruff", "mypy", "pytest", "socket")
    )
    for shadow in shadow_paths:
        shadow.write_bytes(b"raise AssertionError('shadow imported')\n")

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("blocked local gate attempted tool or candidate import")

    monkeypatch.setattr(runtime_module, "_materialize_argv", forbidden)
    monkeypatch.setattr(runtime_module, "_observe_tool_distribution", forbidden)
    monkeypatch.setattr(runtime_module, "_observe_executing_python", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    receipt = execute_local_release_gate(
        gate_id=ReleaseGateId.RUFF_CHECK,
        repository_root=repository,
        evidence_root=evidence,
        candidate=_candidate(),
        run_binding_sha256=RUN_BINDING_SHA256,
    )

    assert receipt.status is ReleaseGateStatus.BLOCKED_TECHNICAL
    assert all(
        shadow.read_bytes() == b"raise AssertionError('shadow imported')\n"
        for shadow in shadow_paths
    )
    assert tuple(evidence.iterdir()) == ()


def test_real_distribution_inventory_is_nonempty_and_deterministic() -> None:
    first = runtime_module._observe_tool_distribution("ruff")
    second = runtime_module._observe_tool_distribution("ruff")

    assert first == second
    assert first.name.casefold() == "ruff"
    assert len(first.inventory_sha256) == 64
