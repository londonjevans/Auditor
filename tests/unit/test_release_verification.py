from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

import mmaudit.release_verification as verification_module
from mmaudit.config import (
    AuditConfig,
    AuditConfigOverrides,
    AuditRunOptions,
    canonical_audit_config_json,
)
from mmaudit.orchestration.manifest import (
    ManifestBindingSet,
    ManifestFileBinding,
    ManifestHashBinding,
    RunConfigurationBinding,
    RunEvidenceManifest,
    canonical_sha256,
    seal_run_evidence_manifest,
    write_run_evidence_manifest,
)
from mmaudit.orchestration.verification import (
    RunVerification,
    RunVerificationCategory,
    RunVerificationMismatch,
    RunVerificationMismatchKind,
    RunVerificationPayload,
    RunVerificationStatus,
)
from mmaudit.release_run import ReleaseRunBinding, ReleaseRunBindingPayload
from mmaudit.release_verification import observe_release_run_verification
from mmaudit.reporting.json_report import stable_json


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _bindings() -> ManifestBindingSet:
    values: dict[str, list[ManifestHashBinding]] = {}
    for name in ManifestBindingSet.model_fields:
        values[name] = [
            ManifestHashBinding(
                identifier=f"{name}/synthetic",
                sha256=_sha(name),
                details={"kind": "synthetic"},
            )
        ]
    return ManifestBindingSet.model_validate(values)


def _run_configuration(config: AuditConfig) -> RunConfigurationBinding:
    effective = config.effective()
    environment = AuditConfigOverrides()
    cli = AuditConfigOverrides()
    options = AuditRunOptions()
    invocation = {
        "environment_overrides_sha256": environment.stable_hash(),
        "cli_overrides_sha256": cli.stable_hash(),
        "run_options_sha256": options.stable_hash(),
        "effective_config_sha256": effective.stable_hash(),
        "requested_profile": effective.profile.value,
        "achieved_profile": effective.profile.value,
    }
    return RunConfigurationBinding(
        file_configuration_json=canonical_audit_config_json(config),
        file_config_sha256=config.stable_hash(),
        environment_overrides=environment,
        environment_overrides_sha256=environment.stable_hash(),
        cli_overrides=cli,
        cli_overrides_sha256=cli.stable_hash(),
        run_options=options,
        run_options_sha256=options.stable_hash(),
        effective_configuration_json=canonical_audit_config_json(effective),
        effective_config_sha256=effective.stable_hash(),
        model_config_sha256=effective.model_hash(),
        invocation_sha256=canonical_sha256(invocation),
        requested_profile=effective.profile,
        achieved_profile=effective.profile,
    )


def _run_binding(
    manifest: RunEvidenceManifest,
    manifest_bytes: bytes,
) -> ReleaseRunBinding:
    run_configuration = manifest.run_configuration
    assert run_configuration is not None
    payload = ReleaseRunBindingPayload(
        schema_version="1.0",
        generated_by="mmaudit",
        run_id=manifest.run_id,
        target_repository_name=manifest.repository_root_name,
        target_git_commit=manifest.git_commit,
        target_source_tree_sha256=manifest.source_tree_sha256,
        manifest_path="run-evidence-manifest.json",
        manifest_file_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        manifest_sha256=manifest.manifest_sha256,
        run_configuration_sha256=canonical_sha256(run_configuration.model_dump(mode="json")),
        file_config_sha256=run_configuration.file_config_sha256,
        environment_overrides_sha256=run_configuration.environment_overrides_sha256,
        cli_overrides_sha256=run_configuration.cli_overrides_sha256,
        run_options_sha256=run_configuration.run_options_sha256,
        effective_config_sha256=run_configuration.effective_config_sha256,
        model_config_sha256=run_configuration.model_config_sha256,
        invocation_sha256=run_configuration.invocation_sha256,
        requested_profile=run_configuration.requested_profile,
        achieved_profile=run_configuration.achieved_profile,
        artifact_evidence_file_sha256="c" * 64,
        artifact_evidence_file_size=100,
        artifact_evidence_sha256="d" * 64,
        artifact_inventory_sha256="e" * 64,
        artifact_count=len(manifest.artifacts),
        traceability_sha256="f" * 64,
        observed_at=datetime(2026, 7, 28, tzinfo=UTC),
    )
    serialized = payload.model_dump(mode="json")
    return ReleaseRunBinding.model_validate(
        {
            **serialized,
            "binding_sha256": canonical_sha256(serialized),
        }
    )


def _verification(
    manifest: RunEvidenceManifest,
    *,
    current: bool = True,
) -> RunVerification:
    mismatches = (
        []
        if current
        else [
            RunVerificationMismatch(
                category=RunVerificationCategory.ARTIFACT,
                identifier="report.json",
                kind=RunVerificationMismatchKind.MISSING,
                expected_sha256="0" * 64,
            )
        ]
    )
    payload = RunVerificationPayload(
        status=(RunVerificationStatus.CURRENT if current else RunVerificationStatus.STALE),
        run_id=manifest.run_id,
        manifest_sha256=manifest.manifest_sha256,
        mismatches=mismatches,
    )
    serialized = payload.model_dump(mode="json")
    return RunVerification.model_validate(
        {
            **serialized,
            "verification_sha256": canonical_sha256(serialized),
        }
    )


def _workspace(
    tmp_path: Path,
    config: AuditConfig,
) -> tuple[
    Path,
    Path,
    Path,
    Path,
    ReleaseRunBinding,
    RunEvidenceManifest,
    RunVerification,
]:
    run_dir = tmp_path / "run"
    source = tmp_path / "source"
    release_repository = tmp_path / "release-product"
    evidence_dir = tmp_path / "evidence"
    artifact_evidence = evidence_dir / "release-artifacts.json"
    verification_path = evidence_dir / "run-verification.json"
    run_dir.mkdir()
    source.mkdir()
    release_repository.mkdir()
    evidence_dir.mkdir()
    source_bytes = b"contract Synthetic {}\n"
    source_path = source / "contracts" / "Synthetic.sol"
    source_path.parent.mkdir()
    source_path.write_bytes(source_bytes)
    artifact_bytes = b'{"synthetic":"artifact"}\n'
    artifact_path = run_dir / "synthetic-artifact.json"
    artifact_path.write_bytes(artifact_bytes)
    source_binding = ManifestFileBinding(
        path="contracts/Synthetic.sol",
        sha256=hashlib.sha256(source_bytes).hexdigest(),
        size=len(source_bytes),
    )
    artifact_binding = ManifestFileBinding(
        path=artifact_path.name,
        sha256=hashlib.sha256(artifact_bytes).hexdigest(),
        size=len(artifact_bytes),
    )
    manifest = seal_run_evidence_manifest(
        run_id="synthetic-run",
        repository_root_name="synthetic-target",
        git_commit="1" * 40,
        sources=[source_binding],
        run_configuration=_run_configuration(config),
        bindings=_bindings(),
        artifacts=[artifact_binding],
        schema_version="1.2",
        tool_version="test",
    )
    manifest_path = run_dir / "run-evidence-manifest.json"
    write_run_evidence_manifest(manifest_path, manifest)
    manifest_bytes = manifest_path.read_bytes()
    artifact_evidence.write_text('{"synthetic":"artifact-evidence"}\n', encoding="utf-8")
    run_binding = _run_binding(manifest, manifest_bytes)
    verification = _verification(manifest)
    verification_path.write_text(stable_json(verification), encoding="utf-8")
    return (
        run_dir,
        source,
        artifact_evidence,
        verification_path,
        run_binding,
        manifest,
        verification,
    )


def _observe(
    *,
    run_dir: Path,
    source: Path,
    artifact_evidence: Path,
    verification_path: Path,
    run_binding: ReleaseRunBinding,
) -> verification_module.ReleaseRunVerificationBinding:
    return observe_release_run_verification(
        run_dir=run_dir,
        target_repository_root=source,
        release_repository_root=run_dir.parent / "release-product",
        artifact_evidence_path=artifact_evidence,
        verification_path=verification_path,
        run_binding=run_binding,
    )


def test_observation_binds_exact_current_file_and_two_recomputations(
    tmp_path: Path,
    config_factory,
) -> None:
    (
        run_dir,
        source,
        artifact_evidence,
        verification_path,
        run_binding,
        _manifest,
        verification,
    ) = _workspace(tmp_path, config_factory())

    with (
        patch.object(
            verification_module,
            "verify_run_evidence",
            side_effect=[verification, verification],
        ) as recompute,
        patch.object(
            verification_module,
            "observe_release_run_binding",
            side_effect=[run_binding, run_binding],
        ) as observe_run,
    ):
        binding = _observe(
            run_dir=run_dir,
            source=source,
            artifact_evidence=artifact_evidence,
            verification_path=verification_path,
            run_binding=run_binding,
        )

    assert recompute.call_count == 2
    assert observe_run.call_count == 2
    assert all(
        call.args
        == (
            run_dir.resolve(),
            (run_dir.parent / "release-product").resolve(),
            artifact_evidence,
        )
        for call in observe_run.call_args_list
    )
    assert all(
        call.kwargs["repository_root"] == source.resolve() for call in recompute.call_args_list
    )
    assert binding.run_id == run_binding.run_id
    assert binding.run_binding_sha256 == run_binding.binding_sha256
    assert binding.effective_config_sha256 == run_binding.effective_config_sha256
    assert binding.status == RunVerificationStatus.CURRENT
    assert binding.mismatches == 0
    assert binding.verification_sha256 == verification.verification_sha256
    assert binding.observed_at.utcoffset() == UTC.utcoffset(None)
    assert binding.observed_at.microsecond == 0
    assert binding.binding_sha256 == canonical_sha256(
        binding.model_dump(mode="json", exclude={"binding_sha256"})
    )


def test_observation_rejects_stale_supplied_or_different_recomputation(
    tmp_path: Path,
    config_factory,
) -> None:
    (
        run_dir,
        source,
        artifact_evidence,
        verification_path,
        run_binding,
        manifest,
        current,
    ) = _workspace(tmp_path, config_factory())
    stale = _verification(manifest, current=False)
    verification_path.write_text(stable_json(stale), encoding="utf-8")
    with (
        patch.object(verification_module, "verify_run_evidence", return_value=stale),
        patch.object(
            verification_module,
            "observe_release_run_binding",
            return_value=run_binding,
        ),
        pytest.raises(ValueError, match="CURRENT"),
    ):
        _observe(
            run_dir=run_dir,
            source=source,
            artifact_evidence=artifact_evidence,
            verification_path=verification_path,
            run_binding=run_binding,
        )

    verification_path.write_text(stable_json(current), encoding="utf-8")
    with (
        patch.object(verification_module, "verify_run_evidence", return_value=stale),
        patch.object(
            verification_module,
            "observe_release_run_binding",
            return_value=run_binding,
        ),
        pytest.raises(ValueError, match="CURRENT"),
    ):
        _observe(
            run_dir=run_dir,
            source=source,
            artifact_evidence=artifact_evidence,
            verification_path=verification_path,
            run_binding=run_binding,
        )


def test_observation_rejects_tampered_duplicate_linked_and_in_run_evidence(
    tmp_path: Path,
    config_factory,
) -> None:
    (
        run_dir,
        source,
        artifact_evidence,
        verification_path,
        run_binding,
        _manifest,
        _verification_result,
    ) = _workspace(tmp_path, config_factory())
    verification_path.write_text(
        '{"schema_version":"1.0","schema_version":"1.0"}',
        encoding="utf-8",
    )
    with (
        patch.object(
            verification_module,
            "observe_release_run_binding",
            return_value=run_binding,
        ),
        pytest.raises(ValueError, match="duplicate"),
    ):
        _observe(
            run_dir=run_dir,
            source=source,
            artifact_evidence=artifact_evidence,
            verification_path=verification_path,
            run_binding=run_binding,
        )

    verification_path.write_text(
        stable_json(_verification_result),
        encoding="utf-8",
    )
    alias = verification_path.with_name("alias.json")
    try:
        os.link(verification_path, alias)
    except OSError:
        pytest.skip("hardlinks are unavailable")
    with (
        patch.object(
            verification_module,
            "observe_release_run_binding",
            return_value=run_binding,
        ),
        pytest.raises(ValueError, match="unshared"),
    ):
        _observe(
            run_dir=run_dir,
            source=source,
            artifact_evidence=artifact_evidence,
            verification_path=verification_path,
            run_binding=run_binding,
        )

    alias.unlink()
    in_run = run_dir / "verification.json"
    in_run.write_text(stable_json(_verification_result), encoding="utf-8")
    with pytest.raises(ValueError, match="outside"):
        _observe(
            run_dir=run_dir,
            source=source,
            artifact_evidence=artifact_evidence,
            verification_path=in_run,
            run_binding=run_binding,
        )


def test_observation_rejects_changed_file_between_equal_recomputations(
    tmp_path: Path,
    config_factory,
) -> None:
    (
        run_dir,
        source,
        artifact_evidence,
        verification_path,
        run_binding,
        manifest,
        verification,
    ) = _workspace(tmp_path, config_factory())
    original_reader = verification_module._read_verification_exact
    reads = 0

    def changing_reader(path: Path) -> tuple[RunVerification, bytes]:
        nonlocal reads
        result = original_reader(path)
        reads += 1
        if reads == 1:
            path.write_text(
                stable_json(_verification(manifest, current=False)),
                encoding="utf-8",
            )
        return result

    with (
        patch.object(
            verification_module,
            "verify_run_evidence",
            side_effect=[verification, verification],
        ),
        patch.object(
            verification_module,
            "observe_release_run_binding",
            return_value=run_binding,
        ),
        patch.object(
            verification_module,
            "_read_verification_exact",
            side_effect=changing_reader,
        ),
        pytest.raises((ValueError, ValidationError)),
    ):
        _observe(
            run_dir=run_dir,
            source=source,
            artifact_evidence=artifact_evidence,
            verification_path=verification_path,
            run_binding=run_binding,
        )


def test_observation_rejects_model_copy_run_binding_mutation(
    tmp_path: Path,
    config_factory,
) -> None:
    (
        run_dir,
        source,
        artifact_evidence,
        verification_path,
        run_binding,
        _manifest,
        _verification_result,
    ) = _workspace(tmp_path, config_factory())
    mutated = run_binding.model_copy(update={"effective_config_sha256": "0" * 64})

    with pytest.raises(ValueError, match="integrity validation"):
        _observe(
            run_dir=run_dir,
            source=source,
            artifact_evidence=artifact_evidence,
            verification_path=verification_path,
            run_binding=mutated,
        )


def test_observation_rejects_self_consistent_fabricated_run_binding(
    tmp_path: Path,
    config_factory,
) -> None:
    (
        run_dir,
        source,
        artifact_evidence,
        verification_path,
        run_binding,
        _manifest,
        _verification_result,
    ) = _workspace(tmp_path, config_factory())
    fabricated_payload = run_binding.model_dump(
        mode="json",
        exclude={"binding_sha256"},
    )
    fabricated_payload["artifact_evidence_sha256"] = "0" * 64
    fabricated = ReleaseRunBinding.model_validate(
        {
            **fabricated_payload,
            "binding_sha256": canonical_sha256(fabricated_payload),
        }
    )

    with (
        patch.object(
            verification_module,
            "observe_release_run_binding",
            return_value=run_binding,
        ),
        pytest.raises(ValueError, match="differs from fresh run evidence"),
    ):
        _observe(
            run_dir=run_dir,
            source=source,
            artifact_evidence=artifact_evidence,
            verification_path=verification_path,
            run_binding=fabricated,
        )


def test_observation_rejects_linked_repository_root_ancestor(
    tmp_path: Path,
    config_factory,
) -> None:
    (
        run_dir,
        source,
        artifact_evidence,
        verification_path,
        run_binding,
        _manifest,
        _verification_result,
    ) = _workspace(tmp_path, config_factory())
    alias = tmp_path / "source-alias"
    try:
        alias.symlink_to(source, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are unavailable")

    with pytest.raises(ValueError, match="may not traverse a link"):
        _observe(
            run_dir=run_dir,
            source=alias,
            artifact_evidence=artifact_evidence,
            verification_path=verification_path,
            run_binding=run_binding,
        )


def test_observation_rejects_wrong_target_root_and_linked_release_root(
    tmp_path: Path,
    config_factory,
) -> None:
    (
        run_dir,
        source,
        artifact_evidence,
        verification_path,
        run_binding,
        _manifest,
        _verification_result,
    ) = _workspace(tmp_path, config_factory())
    release_repository = run_dir.parent / "release-product"

    with pytest.raises(ValueError, match="source is unavailable"):
        _observe(
            run_dir=run_dir,
            source=release_repository,
            artifact_evidence=artifact_evidence,
            verification_path=verification_path,
            run_binding=run_binding,
        )

    release_alias = tmp_path / "release-alias"
    try:
        release_alias.symlink_to(release_repository, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are unavailable")
    with pytest.raises(ValueError, match="may not traverse a link"):
        observe_release_run_verification(
            run_dir=run_dir,
            target_repository_root=source,
            release_repository_root=release_alias,
            artifact_evidence_path=artifact_evidence,
            verification_path=verification_path,
            run_binding=run_binding,
        )


def test_observation_rejects_internal_source_parent_symlink(
    tmp_path: Path,
    config_factory,
) -> None:
    (
        run_dir,
        source,
        artifact_evidence,
        verification_path,
        run_binding,
        _manifest,
        _verification_result,
    ) = _workspace(tmp_path, config_factory())
    contracts = source / "contracts"
    backing = source / "contracts-backing"
    contracts.rename(backing)
    try:
        contracts.symlink_to(backing, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are unavailable")

    with pytest.raises(ValueError, match="may not traverse a link"):
        _observe(
            run_dir=run_dir,
            source=source,
            artifact_evidence=artifact_evidence,
            verification_path=verification_path,
            run_binding=run_binding,
        )


def test_observation_rejects_source_replacement_between_passes(
    tmp_path: Path,
    config_factory,
) -> None:
    (
        run_dir,
        source,
        artifact_evidence,
        verification_path,
        run_binding,
        _manifest,
        verification,
    ) = _workspace(tmp_path, config_factory())
    source_path = source / "contracts" / "Synthetic.sol"
    calls = 0

    def verify_then_replace(**_kwargs: object) -> RunVerification:
        nonlocal calls
        calls += 1
        if calls == 1:
            replacement = source_path.with_suffix(".replacement")
            replacement.write_bytes(source_path.read_bytes())
            replacement.replace(source_path)
        return verification

    with (
        patch.object(
            verification_module,
            "verify_run_evidence",
            side_effect=verify_then_replace,
        ),
        patch.object(
            verification_module,
            "observe_release_run_binding",
            return_value=run_binding,
        ),
        pytest.raises(ValueError, match="inputs changed"),
    ):
        _observe(
            run_dir=run_dir,
            source=source,
            artifact_evidence=artifact_evidence,
            verification_path=verification_path,
            run_binding=run_binding,
        )


def test_observation_rejects_source_path_swap_before_descriptor_open(
    tmp_path: Path,
    config_factory,
) -> None:
    (
        run_dir,
        source,
        artifact_evidence,
        verification_path,
        run_binding,
        _manifest,
        _verification_result,
    ) = _workspace(tmp_path, config_factory())
    source_path = source / "contracts" / "Synthetic.sol"
    original_open = os.open
    swapped = False

    def swap_then_open(path: str | bytes | os.PathLike[str] | os.PathLike[bytes], *args, **kwargs):
        nonlocal swapped
        if not swapped and Path(path) == source_path:
            replacement = source_path.with_suffix(".replacement")
            replacement.write_bytes(source_path.read_bytes())
            replacement.replace(source_path)
            swapped = True
        return original_open(path, *args, **kwargs)

    with (
        patch.object(verification_module.os, "open", side_effect=swap_then_open),
        pytest.raises(ValueError, match="changed before hashing"),
    ):
        _observe(
            run_dir=run_dir,
            source=source,
            artifact_evidence=artifact_evidence,
            verification_path=verification_path,
            run_binding=run_binding,
        )


def test_binding_rejects_tampered_self_hash_and_timestamp(
    tmp_path: Path,
    config_factory,
) -> None:
    (
        run_dir,
        source,
        artifact_evidence,
        verification_path,
        run_binding,
        _manifest,
        verification,
    ) = _workspace(tmp_path, config_factory())
    with (
        patch.object(
            verification_module,
            "verify_run_evidence",
            side_effect=[verification, verification],
        ),
        patch.object(
            verification_module,
            "observe_release_run_binding",
            side_effect=[run_binding, run_binding],
        ),
    ):
        binding = _observe(
            run_dir=run_dir,
            source=source,
            artifact_evidence=artifact_evidence,
            verification_path=verification_path,
            run_binding=run_binding,
        )
    payload = binding.model_dump(mode="json")
    payload["binding_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="binding hash"):
        verification_module.ReleaseRunVerificationBinding.model_validate(payload)

    payload = binding.model_dump(mode="json")
    payload["observed_at"] = "2026-07-28T12:00:00.1Z"
    payload["binding_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "binding_sha256"}
    )
    with pytest.raises(ValidationError, match="whole-second UTC"):
        verification_module.ReleaseRunVerificationBinding.model_validate(payload)
