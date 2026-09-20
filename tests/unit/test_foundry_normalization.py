"""Synthetic byte-custody controls; these unit records are not native-run receipts."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

import pytest

import mmaudit.scanners.foundry_normalization as replay_module
from mmaudit.models.schemas import (
    RepositoryTestExecution,
    RepositoryTestKind,
    ScannerFinding,
    ScannerRun,
    Severity,
)
from mmaudit.orchestration.manifest import _validate_scanner_stream_artifact_custody
from mmaudit.scanners.foundry import (
    _parse_exact_foundry_test,
    _private_artifact_usage,
    _repository_test_findings,
    _write_repository_suite_manifest,
)
from mmaudit.scanners.foundry_normalization import reparse_retained_foundry_findings
from mmaudit.scanners.normalization import validate_real_foundry_normalization_replay
from tests.unit.test_foundry_mutation_executor import _repository_suite_run
from tests.unit.test_scanner_normalization_replay import _annotated

_SOURCE = "// Inert synthetic normalization fixture; no deployment or execution.\n" * 12


def _retain(owner: Path, run: ScannerRun) -> ScannerRun:
    selection = run.repository_suite_selection
    assert selection is not None
    raw_path = _write_repository_suite_manifest(
        owner,
        selection,
        run.repository_suite_inventory,
        run.repository_suite_post_inventory,
        run.repository_suite_execution_policy,
        run.repository_test_executions,
        run.repository_test_fork_rpc_scopes,
        deadline=time.monotonic() + 30,
    )
    raw = raw_path.read_bytes()
    provisional = run.model_copy(
        update={
            "raw_output_path": "foundry_fork/repository-suite-execution.json",
            "raw_output_sha256": hashlib.sha256(raw).hexdigest(),
            "raw_output_bytes": len(raw),
            "execution_observation_sha256": None,
        }
    )
    return ScannerRun.model_validate(
        {
            **provisional.model_dump(mode="python"),
            "execution_observation_sha256": provisional.expected_execution_observation_sha256(),
        }
    )


def _bundle(
    tmp_path: Path,
    *,
    kind: str = "unit",
    failed: bool = True,
    reason: str = "synthetic assertion failed",
) -> tuple[Path, ScannerRun]:
    owner = tmp_path / "run" / "private" / "scanner-output" / "foundry_fork"
    workspace = owner / "workspace"
    test = workspace / "test" / "Vault.t.sol"
    test.parent.mkdir(parents=True)
    test.write_text(_SOURCE, encoding="utf-8")
    run = _repository_suite_run(
        workspace,
        descriptor_source_sha256=hashlib.sha256(_SOURCE.encode()).hexdigest(),
        include_scopes=False,
        include_egress=False,
    )
    selection = run.repository_suite_selection
    assert selection is not None
    descriptor = selection.tests[0]
    kinds = {
        "unit": {"Unit": {"gas": 1}},
        "fuzz": {"Fuzz": {"runs": 3}},
        "invariant": {"Invariant": {"runs": 2, "calls": 4}},
    }
    raw = json.dumps(
        {
            f"{descriptor.path}:{descriptor.suite_name}": {
                "test_results": {
                    descriptor.declaration_signature: {
                        "status": "Failure" if failed else "Success",
                        "reason": reason if failed else None,
                        "kind": kinds[kind],
                    }
                }
            }
        }
    ).encode()
    artifacts = owner / "repository-suite" / "tests" / "00000"
    artifacts.mkdir(parents=True)
    (artifacts / "stdout.json").write_bytes(raw)
    (artifacts / "stderr.txt").write_bytes(b"")
    (artifacts / "cache").mkdir()
    (artifacts / "cache" / "synthetic.json").write_bytes(b"{}")
    usage = _private_artifact_usage(artifacts, trusted_root=owner)
    status, detail, summary, machine_hash = _parse_exact_foundry_test(
        raw.decode(), descriptor=descriptor, return_code=int(failed)
    )
    execution = RepositoryTestExecution.sealed(
        **{
            **run.repository_test_executions[0].model_dump(exclude={"execution_sha256"}),
            "status": status,
            "terminal_detail": detail,
            "test_kind": RepositoryTestKind(kind),
            "fuzz_cases": summary.fuzz_cases,
            "invariant_runs": summary.invariant_runs,
            "invariant_calls": summary.invariant_calls,
            "output_sha256": usage.artifact_sha256,
            "output_bytes": usage.bytes,
            "machine_result_sha256": machine_hash,
            "process_exit_code": int(failed),
        }
    )
    findings = _repository_test_findings(workspace, [execution], selection)
    return owner, _retain(
        owner,
        run.model_copy(
            update={
                "repository_test_executions": [execution],
                "foundry_summary": summary,
                "findings": findings,
                "process_exit_code": int(failed),
            }
        ),
    )


def _replay(owner: Path, run: ScannerRun, raw: bytes | None = None) -> tuple[Any, ...]:
    return reparse_retained_foundry_findings(
        run=run,
        repository_root=owner / "workspace",
        artifact_root=owner,
        retained_manifest=(owner / "repository-suite-execution.json").read_bytes()
        if raw is None
        else raw,
    )


def _rebind_raw(run: ScannerRun, raw: bytes) -> ScannerRun:
    provisional = run.model_copy(
        update={
            "raw_output_sha256": hashlib.sha256(raw).hexdigest(),
            "raw_output_bytes": len(raw),
            "execution_observation_sha256": None,
        }
    )
    return ScannerRun.model_validate(
        {
            **provisional.model_dump(mode="python"),
            "execution_observation_sha256": provisional.expected_execution_observation_sha256(),
        }
    )


@pytest.mark.parametrize("kind", ["unit", "fuzz", "invariant"])
@pytest.mark.parametrize("failed", [False, True])
@pytest.mark.parametrize(
    "reason", ["synthetic assertion failed", "synthetic revert", "synthetic failure"]
)
def test_complete_original_output_reproduces_exact_findings(
    tmp_path: Path, kind: str, failed: bool, reason: str
) -> None:
    owner, run = _bundle(tmp_path, kind=kind, failed=failed, reason=reason)
    assert _replay(owner, run) == tuple(run.findings)
    assert len(run.findings) == int(failed)


@pytest.mark.parametrize("name", ["stdout.json", "stderr.txt", "cache/synthetic.json"])
@pytest.mark.parametrize("mutation", ["remove", "replace", "symlink", "hardlink"])
def test_original_tree_missing_changed_or_aliased_artifact_refuses(
    tmp_path: Path, name: str, mutation: str
) -> None:
    owner, run = _bundle(tmp_path)
    artifact = owner / "repository-suite/tests/00000" / name
    if mutation == "replace":
        artifact.write_bytes(b"changed synthetic bytes")
    else:
        artifact.unlink()
        if mutation != "remove":
            replacement = tmp_path / "replacement"
            replacement.write_bytes(b"{}")
            if mutation == "symlink":
                artifact.symlink_to(replacement)
            else:
                os.link(replacement, artifact)
    with pytest.raises(ValueError):
        _replay(owner, run)


@pytest.mark.parametrize(
    "field,value",
    [
        ("terminal_detail", "coherently changed synthetic failure"),
        ("machine_result_sha256", "f" * 64),
        ("fuzz_cases", 4),
    ],
)
def test_coherently_resealed_claims_cannot_replace_native_semantics(
    tmp_path: Path, field: str, value: object
) -> None:
    owner, run = _bundle(tmp_path, kind="fuzz")
    execution = RepositoryTestExecution.sealed(
        **{
            **run.repository_test_executions[0].model_dump(exclude={"execution_sha256"}),
            field: value,
        }
    )
    assert run.repository_suite_selection is not None
    assert run.foundry_summary is not None
    summary = (
        run.foundry_summary.model_copy(update={"fuzz_cases": value})
        if field == "fuzz_cases"
        else run.foundry_summary
    )
    altered = _retain(
        owner,
        run.model_copy(
            update={
                "repository_test_executions": [execution],
                "foundry_summary": summary,
                "findings": _repository_test_findings(
                    owner / "workspace", [execution], run.repository_suite_selection
                ),
            }
        ),
    )
    with pytest.raises(ValueError, match="classified execution semantics"):
        _replay(owner, altered)


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown",
        "version",
        "boolean",
        "policy",
        "inventory",
        "execution",
        "duplicate",
        "nonfinite",
        "scopes",
    ],
)
def test_resealed_manifest_requires_exact_complete_claims(tmp_path: Path, mutation: str) -> None:
    owner, run = _bundle(tmp_path)
    original = (owner / "repository-suite-execution.json").read_bytes()
    payload = json.loads(original)
    if mutation == "unknown":
        payload["unknown_authority"] = True
    elif mutation == "version":
        payload["schema_version"] = "2.0"
    elif mutation == "boolean":
        payload["safety_claim"] = 0
    elif mutation == "policy":
        payload["execution_policy"] = None
    elif mutation == "inventory":
        payload["post_execution_inventory"] = None
    elif mutation == "execution":
        payload["executions"] = []
    elif mutation == "scopes":
        payload["repository_test_fork_rpc_scopes"] = [{}]
    raw = json.dumps(payload).encode()
    if mutation == "duplicate":
        raw = b'{"safety_claim":false,' + raw[1:]
    elif mutation == "nonfinite":
        raw = b'{"unknown":NaN,' + raw[1:]
    with pytest.raises(ValueError):
        _replay(owner, _rebind_raw(run, raw), raw)


def test_replay_has_one_fixed_deadline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    owner, run = _bundle(tmp_path)
    monkeypatch.setattr(replay_module, "_REPLAY_TIMEOUT_SECONDS", 0)
    with pytest.raises(ValueError, match="bounded deadline"):
        _replay(owner, run)


def test_replay_rejects_wrong_owner_workspace(tmp_path: Path) -> None:
    owner, run = _bundle(tmp_path)
    with pytest.raises(ValueError, match="workspace differs"):
        reparse_retained_foundry_findings(
            run=run,
            repository_root=owner / "different",
            artifact_root=owner,
            retained_manifest=(owner / "repository-suite-execution.json").read_bytes(),
        )


@pytest.mark.parametrize(
    "missing",
    [
        "repository_suite_inventory",
        "repository_suite_post_inventory",
        "repository_suite_execution_policy",
        "repository_suite_selection",
    ],
)
def test_model_copy_cannot_hide_required_nested_evidence(tmp_path: Path, missing: str) -> None:
    owner, run = _bundle(tmp_path)
    changed = run.model_copy(update={missing: None, "execution_observation_sha256": None})
    with pytest.raises(ValueError):
        _replay(owner, changed)


def test_original_per_test_artifact_ceiling_is_enforced(tmp_path: Path) -> None:
    owner, run = _bundle(tmp_path)
    policy = run.repository_suite_execution_policy
    assert policy is not None
    (owner / "repository-suite/tests/00000/cache/synthetic.json").write_bytes(
        b" " * (policy.max_output_bytes_per_test + 1)
    )
    with pytest.raises(ValueError, match="artifact custody"):
        _replay(owner, run)


@pytest.mark.parametrize("promotion", [False, True])
def test_debugger_record_is_separate_and_cannot_grant_authority(
    tmp_path: Path, promotion: bool
) -> None:
    owner, run = _bundle(tmp_path)
    payload = json.loads((owner / "repository-suite-execution.json").read_bytes())
    payload["schema_version"] = "1.3"
    payload["repository_debugger_observations"] = {
        "execution_scope": "SEPARATE_INVOCATIONS_NOT_ORIGINAL_COVERAGE_OR_FULL_FUZZ_POPULATION",
        "runtime_authority": promotion,
        "coverage_complete": False,
        "observed": [],
        "unproduced_descriptors": [run.repository_test_executions[0].descriptor_sha256],
    }
    raw = json.dumps(payload).encode()
    changed = _rebind_raw(run, raw)
    if promotion:
        with pytest.raises(ValueError, match="unsupported authority"):
            _replay(owner, changed, raw)
    else:
        assert _replay(owner, changed, raw) == tuple(run.findings)
        assert not changed.repository_statement_coverage_evidence


@pytest.mark.parametrize(
    "mutation", ["duplicate", "extra_test", "wrong_signature", "zero_campaign"]
)
def test_rehashed_machine_bytes_do_not_bypass_exact_parser(tmp_path: Path, mutation: str) -> None:
    owner, run = _bundle(tmp_path, kind="fuzz")
    path = owner / "repository-suite/tests/00000/stdout.json"
    payload = json.loads(path.read_bytes())
    results = payload["test/Vault.t.sol:VaultTest"]["test_results"]
    if mutation == "extra_test":
        results["testOther()"] = results["testAccessGuard()"]
    elif mutation == "wrong_signature":
        results["testAccessGuard(uint256)"] = results.pop("testAccessGuard()")
    elif mutation == "zero_campaign":
        results["testAccessGuard()"]["kind"] = {"Fuzz": {"runs": 0}}
    raw = json.dumps(payload).encode()
    if mutation == "duplicate":
        raw = b'{"test/Vault.t.sol:VaultTest":{},' + raw[1:]
    path.write_bytes(raw)
    usage = _private_artifact_usage(path.parent, trusted_root=owner)
    execution = RepositoryTestExecution.sealed(
        **{
            **run.repository_test_executions[0].model_dump(exclude={"execution_sha256"}),
            "output_sha256": usage.artifact_sha256,
            "output_bytes": usage.bytes,
        }
    )
    assert run.repository_suite_selection is not None
    changed = _retain(
        owner,
        run.model_copy(
            update={
                "repository_test_executions": [execution],
                "findings": _repository_test_findings(
                    owner / "workspace", [execution], run.repository_suite_selection
                ),
            }
        ),
    )
    with pytest.raises(ValueError):
        _replay(owner, changed)


def test_manifest_custody_accepts_only_original_replayed_fingerprints(tmp_path: Path) -> None:
    owner, run = _bundle(tmp_path)
    fingerprints = _validate_scanner_stream_artifact_custody(tmp_path / "run", [run])
    assert fingerprints == frozenset(finding.fingerprint for finding in run.findings)
    raw = (owner / "repository-suite-execution.json").read_bytes()
    annotated = _rebind_raw(run.model_copy(update={"findings": _annotated(run.findings)}), raw)
    assert _validate_scanner_stream_artifact_custody(tmp_path / "run", [annotated]) == fingerprints


def test_empty_suite_preserves_existing_no_finding_authority_boundary(tmp_path: Path) -> None:
    owner, run = _bundle(tmp_path, failed=False)
    # No finding fingerprints are granted even without an auxiliary test tree.
    # Other execution and coverage verifiers keep their existing separate gates.
    (owner / "repository-suite/tests/00000/stdout.json").unlink()
    assert _validate_scanner_stream_artifact_custody(tmp_path / "run", [run]) == frozenset()
    with pytest.raises(ValueError):
        _replay(owner, run)


@pytest.mark.parametrize(
    "field,value",
    [
        ("rule_id", "changed-rule"),
        ("title", "Changed synthetic title"),
        ("severity", Severity.LOW),
        ("message", "Changed synthetic message"),
        ("cwe", ["CWE-999"]),
        ("fingerprint", "f" * 64),
    ],
)
def test_manifest_custody_rejects_resealed_nonhost_finding_changes(
    tmp_path: Path, field: str, value: object
) -> None:
    owner, run = _bundle(tmp_path)
    changed_finding = ScannerFinding.model_validate({**run.findings[0].model_dump(), field: value})
    raw = (owner / "repository-suite-execution.json").read_bytes()
    changed = _rebind_raw(run.model_copy(update={"findings": [changed_finding]}), raw)
    with pytest.raises(ValueError, match="complete normalized finding inventory"):
        _validate_scanner_stream_artifact_custody(tmp_path / "run", [changed])


def test_untyped_host_location_annotation_never_grants_credit(tmp_path: Path) -> None:
    owner, run = _bundle(tmp_path)
    finding = run.findings[0].model_copy(
        update={"metadata": {**run.findings[0].metadata, "location_validation": True}}
    )
    raw = (owner / "repository-suite-execution.json").read_bytes()
    changed = _rebind_raw(run.model_copy(update={"findings": [finding]}), raw)
    with pytest.raises(ValueError, match="exact location inventory"):
        validate_real_foundry_normalization_replay(
            run=changed,
            repository_root=owner / "workspace",
            artifact_root=owner,
            retained_manifest=raw,
        )


def test_failure_only_gap_manifest_cannot_be_resealed_as_success(tmp_path: Path) -> None:
    owner, run = _bundle(tmp_path)
    payload = json.loads((owner / "repository-suite-execution.json").read_bytes())
    payload.update(
        schema_version="1.4",
        repository_statement_observation_gaps={},
        unvalidated_statement_entity_catalog={},
    )
    raw = json.dumps(payload).encode()
    with pytest.raises(ValueError, match="failure-only gap manifest"):
        _replay(owner, _rebind_raw(run, raw), raw)
