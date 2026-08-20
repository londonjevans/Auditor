from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import mmaudit.models.refresh_staging as refresh_staging_module
from mmaudit.models.policy_eligibility import (
    PolicyReviewReason,
    build_model_policy_eligibility_artifact,
    build_policy_eligibility_route,
)
from mmaudit.models.policy_eligibility_authority import (
    build_policy_eligibility_source_observation,
)
from mmaudit.models.policy_eligibility_refresh import (
    POLICY_ELIGIBILITY_REFRESH_FILENAME,
    ModelPolicyEligibilityRefreshArtifact,
    build_model_policy_eligibility_refresh_artifact,
    load_model_policy_eligibility_refresh_artifact,
)
from mmaudit.models.qualification import seal_candidate_registry
from mmaudit.models.refresh import (
    ATTEMPT_FILENAME,
    CANDIDATE_REGISTRY_FILENAME,
    DIFF_FILENAME,
    FRESHNESS_FILENAME,
    SNAPSHOT_FILENAME,
    SOURCE_EVIDENCE_FILENAME,
    ModelRefreshFailureCode,
    SelectedModelRoute,
    build_model_refresh_snapshot_from_source,
    diff_model_refresh,
    evaluate_model_refresh_freshness,
    load_model_refresh_attempt,
    load_model_refresh_diff,
    load_model_refresh_freshness,
    load_model_refresh_snapshot,
    load_model_refresh_source_evidence,
    seal_model_refresh_attempt,
    write_model_refresh_failure,
    write_model_refresh_success,
)
from mmaudit.models.refresh_staging import (
    PREVIOUS_CANDIDATE_REGISTRY_FILENAME,
    PREVIOUS_SNAPSHOT_FILENAME,
    PREVIOUS_SOURCE_EVIDENCE_FILENAME,
    PREVIOUS_WORKFLOW_STATUS_FILENAME,
    WORKFLOW_STATUS_FILENAME,
    ModelRefreshStagingError,
    ModelRefreshWorkflowDisposition,
    ModelRefreshWorkflowStatus,
    load_model_refresh_workflow_status,
    load_previous_model_refresh_history,
    stage_model_refresh_evidence,
)
from mmaudit.reporting.json_report import stable_json
from scripts.stage_model_refresh_artifacts import main as stage_script_main
from tests.unit.test_model_refresh import (
    ENDPOINT,
    MODEL,
    NOW,
    _endpoint,
    _registry,
    _reseal_catalog_model,
    _sha,
    _snapshot,
    _source,
)

SOURCE_COMMIT = "a" * 40
ROOT = Path(__file__).resolve().parents[2]
SUCCESS_NAMES = {
    CANDIDATE_REGISTRY_FILENAME,
    SOURCE_EVIDENCE_FILENAME,
    SNAPSHOT_FILENAME,
    DIFF_FILENAME,
    ATTEMPT_FILENAME,
    FRESHNESS_FILENAME,
    WORKFLOW_STATUS_FILENAME,
}
IMMEDIATE_PREDECESSOR_NAMES = {
    PREVIOUS_WORKFLOW_STATUS_FILENAME,
    PREVIOUS_CANDIDATE_REGISTRY_FILENAME,
    PREVIOUS_SOURCE_EVIDENCE_FILENAME,
    PREVIOUS_SNAPSHOT_FILENAME,
}
POLICY_SUCCESS_NAMES = SUCCESS_NAMES | {POLICY_ELIGIBILITY_REFRESH_FILENAME}


def _missing_policy_inputs(
    registry: Any,
    *,
    observed_at: datetime = NOW,
) -> tuple[Any, Any, tuple[Any, ...]]:
    candidate = registry.candidates[0]
    route = build_policy_eligibility_route(
        exact_model_id=candidate.exact_model_id,
        provider_name=candidate.approved_provider_name,
        provider_endpoint=candidate.approved_provider_endpoint,
    )
    artifact = build_model_policy_eligibility_artifact(
        created_at=observed_at - timedelta(hours=1),
        official_evidence=(),
        determinations=(),
    )
    observation = build_policy_eligibility_source_observation(
        artifact=artifact,
        observed_at=observed_at,
        expires_at=observed_at + timedelta(hours=12),
        source_commitments=(),
    )
    return artifact, observation, (route,)


def _write_success_bundle(
    output: Path,
    *,
    registry: Any | None = None,
    previous: Any | None = None,
    previous_source: Any | None = None,
    previous_registry: Any | None = None,
    blocked: bool = False,
    retrieved_at: datetime | None = None,
    policy_inputs: tuple[Any, Any, tuple[Any, ...]] | None = None,
) -> tuple[Any, tuple[SelectedModelRoute, ...]]:
    registry = _registry() if registry is None else registry
    observed_at = (
        retrieved_at
        if retrieved_at is not None
        else (NOW if previous is None else NOW + timedelta(minutes=1))
    )
    selected = (
        (SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),) if blocked else ()
    )
    source = _source(
        registry,
        retrieved_at=observed_at,
        zdr_endpoints=[_endpoint()],
        candidate_endpoints={MODEL: [_endpoint()] if not blocked else []},
    )
    snapshot = build_model_refresh_snapshot_from_source(
        source_evidence=source,
        candidate_registry=registry,
    )
    if previous is not None:
        previous_registry = registry if previous_registry is None else previous_registry
        previous_source = _source(previous_registry) if previous_source is None else previous_source
    diff = diff_model_refresh(
        current=snapshot,
        previous=previous,
        previous_source_evidence=previous_source,
        previous_candidate_registry=previous_registry,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=observed_at,
        selected_routes=selected,
    )
    attempt = seal_model_refresh_attempt(
        attempted_at=observed_at,
        candidate_registry_sha256=registry.registry_sha256,
        snapshot=snapshot,
        diff=diff,
    )
    freshness = evaluate_model_refresh_freshness(
        observed_at=observed_at,
        snapshot=snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=bool(selected),
    )
    policy_refresh: ModelPolicyEligibilityRefreshArtifact | None = None
    if policy_inputs is not None:
        policy_refresh = build_model_policy_eligibility_refresh_artifact(
            refresh_snapshot=snapshot,
            policy_artifact=policy_inputs[0],
            source_observation=policy_inputs[1],
            checked_routes=policy_inputs[2],
        )
    write_model_refresh_success(
        output,
        source_evidence=source,
        snapshot=snapshot,
        diff=diff,
        attempt=attempt,
        freshness=freshness,
        policy_eligibility_refresh=policy_refresh,
    )
    return registry, selected


def _stage(
    *,
    output: Path,
    staging: Path,
    registry: Any,
    exit_status: int,
    previous: Any | None = None,
    previous_source: Any | None = None,
    previous_registry: Any | None = None,
    previous_workflow_status: Any | None = None,
    workflow_run_id: str = "123",
    workflow_run_attempt: str = "1",
    selected: tuple[SelectedModelRoute, ...] = (),
    pricing_tolerance_fraction: str = "0.05",
    soft_max_age_hours: int = 30,
    hard_max_age_hours: int = 72,
    policy_inputs: tuple[Any, Any, tuple[Any, ...]] | None = None,
    validation_observed_at: Any = NOW + timedelta(minutes=1),
):
    return stage_model_refresh_evidence(
        output_dir=output,
        staging_dir=staging,
        candidate_registry=registry,
        refresh_exit_status=exit_status,
        source_commit=SOURCE_COMMIT,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
        pricing_tolerance_fraction=pricing_tolerance_fraction,
        soft_max_age_hours=soft_max_age_hours,
        hard_max_age_hours=hard_max_age_hours,
        previous_snapshot=previous,
        previous_source_evidence=previous_source,
        previous_candidate_registry=previous_registry,
        previous_workflow_status=previous_workflow_status,
        expected_selected_routes=selected,
        policy_eligibility_artifact=(None if policy_inputs is None else policy_inputs[0]),
        policy_source_observation=(None if policy_inputs is None else policy_inputs[1]),
        policy_checked_routes=(None if policy_inputs is None else policy_inputs[2]),
        _validation_observed_at=validation_observed_at,
    )


def _write_validated_history(
    root: Path,
    *,
    name: str,
    registry: Any | None = None,
    retrieved_at: datetime = NOW,
    validated_at: datetime = NOW + timedelta(minutes=1),
    workflow_run_id: str = "122",
    workflow_run_attempt: str = "1",
) -> Any:
    output = root / f"{name}-output"
    history_dir = root / f"{name}-history"
    registry, selected = _write_success_bundle(
        output,
        registry=registry,
        retrieved_at=retrieved_at,
    )
    _stage(
        output=output,
        staging=history_dir,
        registry=registry,
        exit_status=0,
        selected=selected,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
        validation_observed_at=validated_at,
    )
    return load_previous_model_refresh_history(
        history_dir,
        expected_workflow_run_id=workflow_run_id,
        expected_workflow_run_attempt=workflow_run_attempt,
        expected_source_commit=SOURCE_COMMIT,
    )


def _write_history_archive(*, history_dir: Path, archive_path: Path) -> None:
    with zipfile.ZipFile(archive_path, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(history_dir.iterdir(), key=lambda item: item.name):
            archive.write(path, arcname=path.name)


def _replace_bound_artifacts(
    history_dir: Path,
    replacements: dict[str, tuple[dict[str, Any], str]],
) -> None:
    status_path = history_dir / WORKFLOW_STATUS_FILENAME
    status = json.loads(status_path.read_text(encoding="utf-8"))
    bindings = {binding["filename"]: binding for binding in status["artifacts"]}
    for filename, (payload, self_hash_field) in replacements.items():
        raw = stable_json(payload).encode("utf-8")
        artifact_path = history_dir / filename
        artifact_path.write_bytes(raw)
        artifact_path.chmod(0o600)
        bindings[filename].update(
            content_sha256=hashlib.sha256(raw).hexdigest(),
            artifact_sha256=payload[self_hash_field],
            byte_count=len(raw),
        )
    status["workflow_status_sha256"] = _sha(
        {key: value for key, value in status.items() if key != "workflow_status_sha256"}
    )
    status_path.write_text(stable_json(status), encoding="utf-8")
    status_path.chmod(0o600)


def _replace_workflow_status(history_dir: Path, payload: dict[str, Any]) -> None:
    payload["workflow_status_sha256"] = _sha(
        {key: value for key, value in payload.items() if key != "workflow_status_sha256"}
    )
    status_path = history_dir / WORKFLOW_STATUS_FILENAME
    status_path.write_text(stable_json(payload), encoding="utf-8")
    status_path.chmod(0o600)


def _registry_rebound_artifacts(
    bundle_dir: Path,
    registry: Any,
) -> dict[str, tuple[dict[str, Any], str]]:
    source = json.loads((bundle_dir / SOURCE_EVIDENCE_FILENAME).read_text(encoding="utf-8"))
    source["candidate_registry_sha256"] = registry.registry_sha256
    source["source_evidence_sha256"] = _sha(
        {key: value for key, value in source.items() if key != "source_evidence_sha256"}
    )
    snapshot = json.loads((bundle_dir / SNAPSHOT_FILENAME).read_text(encoding="utf-8"))
    snapshot["candidate_registry_sha256"] = registry.registry_sha256
    snapshot["source_evidence_sha256"] = source["source_evidence_sha256"]
    snapshot["snapshot_sha256"] = _sha(
        {key: value for key, value in snapshot.items() if key != "snapshot_sha256"}
    )
    diff = json.loads((bundle_dir / DIFF_FILENAME).read_text(encoding="utf-8"))
    assert diff["baseline_kind"] == "CANDIDATE_REGISTRY_HASH_ONLY"
    diff["baseline_sha256"] = registry.registry_sha256
    diff["baseline_candidate_registry_sha256"] = registry.registry_sha256
    diff["current_candidate_registry_sha256"] = registry.registry_sha256
    diff["current_snapshot_sha256"] = snapshot["snapshot_sha256"]
    diff["diff_sha256"] = _sha({key: value for key, value in diff.items() if key != "diff_sha256"})
    attempt = json.loads((bundle_dir / ATTEMPT_FILENAME).read_text(encoding="utf-8"))
    attempt["candidate_registry_sha256"] = registry.registry_sha256
    attempt["snapshot_sha256"] = snapshot["snapshot_sha256"]
    attempt["diff_sha256"] = diff["diff_sha256"]
    attempt["attempt_sha256"] = _sha(
        {key: value for key, value in attempt.items() if key != "attempt_sha256"}
    )
    freshness = json.loads((bundle_dir / FRESHNESS_FILENAME).read_text(encoding="utf-8"))
    freshness["snapshot_sha256"] = snapshot["snapshot_sha256"]
    freshness["freshness_sha256"] = _sha(
        {key: value for key, value in freshness.items() if key != "freshness_sha256"}
    )
    return {
        CANDIDATE_REGISTRY_FILENAME: (
            registry.model_dump(mode="json"),
            "registry_sha256",
        ),
        SOURCE_EVIDENCE_FILENAME: (source, "source_evidence_sha256"),
        SNAPSHOT_FILENAME: (snapshot, "snapshot_sha256"),
        DIFF_FILENAME: (diff, "diff_sha256"),
        ATTEMPT_FILENAME: (attempt, "attempt_sha256"),
        FRESHNESS_FILENAME: (freshness, "freshness_sha256"),
    }


def test_success_bundle_is_revalidated_reconstructed_and_commit_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "synthetic-staging-secret-canary"
    monkeypatch.setenv("OPENROUTER_API_KEY", canary)
    output = tmp_path / "output"
    staging = tmp_path / "staging"
    registry, selected = _write_success_bundle(output)

    status = _stage(
        output=output,
        staging=staging,
        registry=registry,
        exit_status=0,
        selected=selected,
    )

    assert status.disposition is ModelRefreshWorkflowDisposition.COMPLETED
    assert status.source_commit == SOURCE_COMMIT
    assert status.candidate_registry_sha256 == registry.registry_sha256
    assert status.pricing_tolerance_fraction == "0.05"
    assert status.soft_max_age_hours == 30
    assert status.hard_max_age_hours == 72
    assert status.policy_projection_expected is False
    assert status.validated_at == NOW + timedelta(minutes=1)
    assert {path.name for path in staging.iterdir()} == SUCCESS_NAMES
    assert staging.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in staging.iterdir())
    assert load_model_refresh_workflow_status(staging / WORKFLOW_STATUS_FILENAME) == status
    assert (staging / CANDIDATE_REGISTRY_FILENAME).read_text(encoding="utf-8") == stable_json(
        registry
    )
    serialized = "".join(path.read_text(encoding="utf-8") for path in staging.iterdir())
    assert canary not in serialized
    assert all(binding.content_sha256 for binding in status.artifacts)
    assert all(binding.artifact_sha256 for binding in status.artifacts)
    expected_self_hashes = {
        CANDIDATE_REGISTRY_FILENAME: registry.registry_sha256,
        SOURCE_EVIDENCE_FILENAME: load_model_refresh_source_evidence(
            output / SOURCE_EVIDENCE_FILENAME
        ).source_evidence_sha256,
        SNAPSHOT_FILENAME: load_model_refresh_snapshot(output / SNAPSHOT_FILENAME).snapshot_sha256,
        DIFF_FILENAME: load_model_refresh_diff(output / DIFF_FILENAME).diff_sha256,
        ATTEMPT_FILENAME: load_model_refresh_attempt(output / ATTEMPT_FILENAME).attempt_sha256,
        FRESHNESS_FILENAME: load_model_refresh_freshness(
            output / FRESHNESS_FILENAME
        ).freshness_sha256,
    }
    assert {
        binding.filename: binding.artifact_sha256 for binding in status.artifacts
    } == expected_self_hashes

    legacy_payload = status.model_dump(mode="json")
    legacy_payload["schema_version"] = "3.0"
    legacy_payload["workflow_status_sha256"] = _sha(
        {key: value for key, value in legacy_payload.items() if key != "workflow_status_sha256"}
    )
    with pytest.raises(ValidationError, match=r"4\.0"):
        ModelRefreshWorkflowStatus.model_validate(legacy_payload)


def test_durable_history_loads_exact_inventory_and_script_validates_identity(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "output"
    history_dir = tmp_path / "history"
    registry, selected = _write_success_bundle(output)
    status = _stage(
        output=output,
        staging=history_dir,
        registry=registry,
        exit_status=0,
        selected=selected,
        workflow_run_id="122",
    )

    history = load_previous_model_refresh_history(
        history_dir,
        expected_workflow_run_id="122",
        expected_workflow_run_attempt="1",
        expected_source_commit=SOURCE_COMMIT,
    )

    assert history.workflow_status == status
    assert history.candidate_registry == registry
    assert history.source_evidence == load_model_refresh_source_evidence(
        history_dir / SOURCE_EVIDENCE_FILENAME
    )
    assert history.snapshot == load_model_refresh_snapshot(history_dir / SNAPSHOT_FILENAME)
    with pytest.raises(ModelRefreshStagingError, match="source commit"):
        load_previous_model_refresh_history(
            history_dir,
            expected_workflow_run_id="122",
            expected_workflow_run_attempt="1",
            expected_source_commit="e" * 40,
        )
    assert (
        stage_script_main(
            [
                "validate-history",
                "--history-dir",
                str(history_dir),
                "--expected-workflow-run-id",
                "122",
                "--expected-workflow-run-attempt",
                "1",
                "--expected-source-commit",
                SOURCE_COMMIT,
            ]
        )
        == 0
    )
    assert "history validated" in capsys.readouterr().out
    assert (
        stage_script_main(
            [
                "validate-history",
                "--history-dir",
                str(history_dir),
                "--expected-workflow-run-id",
                "121",
                "--expected-workflow-run-attempt",
                "1",
                "--expected-source-commit",
                SOURCE_COMMIT,
            ]
        )
        == 74
    )
    assert capsys.readouterr().out == "model-refresh history validation failed\n"


def test_history_archive_extractor_retains_exact_private_inventory(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    history = _write_validated_history(tmp_path, name="archive-source")
    source_dir = tmp_path / "archive-source-history"
    archive_path = tmp_path / "history.zip"
    extracted_dir = tmp_path / "extracted"
    _write_history_archive(history_dir=source_dir, archive_path=archive_path)

    assert (
        stage_script_main(
            [
                "extract-history",
                "--archive",
                str(archive_path),
                "--history-dir",
                str(extracted_dir),
                "--expected-archive-bytes",
                str(archive_path.stat().st_size),
            ]
        )
        == 0
    )

    assert capsys.readouterr().out == "model-refresh history extracted\n"
    assert stat.S_IMODE(extracted_dir.stat().st_mode) == 0o700
    assert {path.name for path in extracted_dir.iterdir()} == SUCCESS_NAMES
    for source_path in source_dir.iterdir():
        extracted_path = extracted_dir / source_path.name
        assert extracted_path.read_bytes() == source_path.read_bytes()
        assert stat.S_IMODE(extracted_path.stat().st_mode) == 0o600
    assert (
        load_previous_model_refresh_history(
            extracted_dir,
            expected_workflow_run_id="122",
            expected_workflow_run_attempt="1",
            expected_source_commit=SOURCE_COMMIT,
        )
        == history
    )


@pytest.mark.parametrize("mutation", ["traversal", "unexpected", "symlink", "lzma"])
def test_history_archive_extractor_rejects_unsafe_entries_or_inventory(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    mutation: str,
) -> None:
    _write_validated_history(tmp_path, name="archive-source")
    source_dir = tmp_path / "archive-source-history"
    archive_path = tmp_path / f"{mutation}.zip"
    extracted_dir = tmp_path / f"{mutation}-extracted"
    with zipfile.ZipFile(archive_path, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for source_path in sorted(source_dir.iterdir(), key=lambda item: item.name):
            name = source_path.name
            if source_path.name == ATTEMPT_FILENAME and mutation == "traversal":
                name = f"../{name}"
            elif source_path.name == ATTEMPT_FILENAME and mutation == "unexpected":
                name = "unexpected.json"
            entry = zipfile.ZipInfo(name)
            entry.compress_type = (
                zipfile.ZIP_LZMA
                if source_path.name == ATTEMPT_FILENAME and mutation == "lzma"
                else zipfile.ZIP_DEFLATED
            )
            entry.external_attr = (
                (stat.S_IFLNK | 0o777) << 16
                if source_path.name == ATTEMPT_FILENAME and mutation == "symlink"
                else (stat.S_IFREG | 0o600) << 16
            )
            archive.writestr(entry, source_path.read_bytes())

    assert (
        stage_script_main(
            [
                "extract-history",
                "--archive",
                str(archive_path),
                "--history-dir",
                str(extracted_dir),
                "--expected-archive-bytes",
                str(archive_path.stat().st_size),
            ]
        )
        == 74
    )
    assert capsys.readouterr().out == "model-refresh history extraction failed\n"
    assert not extracted_dir.exists()


def test_history_archive_extractor_rejects_oversize_or_preexisting_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    oversized = tmp_path / "oversized.zip"
    with oversized.open("wb") as stream:
        stream.truncate(32_000_001)
    output = tmp_path / "extracted"

    assert (
        stage_script_main(
            [
                "extract-history",
                "--archive",
                str(oversized),
                "--history-dir",
                str(output),
                "--expected-archive-bytes",
                str(oversized.stat().st_size),
            ]
        )
        == 74
    )
    assert not output.exists()
    assert capsys.readouterr().out == "model-refresh history extraction failed\n"

    _write_validated_history(tmp_path, name="archive-source")
    archive_path = tmp_path / "history.zip"
    _write_history_archive(
        history_dir=tmp_path / "archive-source-history",
        archive_path=archive_path,
    )
    target = tmp_path / "existing"
    target.mkdir()
    output.symlink_to(target, target_is_directory=True)
    assert (
        stage_script_main(
            [
                "extract-history",
                "--archive",
                str(archive_path),
                "--history-dir",
                str(output),
                "--expected-archive-bytes",
                str(archive_path.stat().st_size),
            ]
        )
        == 74
    )
    assert output.is_symlink()
    assert capsys.readouterr().out == "model-refresh history extraction failed\n"


@pytest.mark.parametrize("mutation", ["partial", "tampered", "swapped"])
def test_durable_history_rejects_partial_tampered_or_swapped_artifacts(
    tmp_path: Path,
    mutation: str,
) -> None:
    output = tmp_path / "output"
    history_dir = tmp_path / "history"
    registry, selected = _write_success_bundle(output)
    _stage(
        output=output,
        staging=history_dir,
        registry=registry,
        exit_status=0,
        selected=selected,
        workflow_run_id="122",
    )
    source_path = history_dir / SOURCE_EVIDENCE_FILENAME
    if mutation == "partial":
        (history_dir / SNAPSHOT_FILENAME).unlink()
    elif mutation == "tampered":
        source_path.write_bytes(source_path.read_bytes() + b"\n")
    else:
        second_output = tmp_path / "second-output"
        second_history = tmp_path / "second-history"
        second_registry, second_selected = _write_success_bundle(
            second_output,
            retrieved_at=NOW + timedelta(minutes=1),
        )
        _stage(
            output=second_output,
            staging=second_history,
            registry=second_registry,
            exit_status=0,
            selected=second_selected,
            workflow_run_id="121",
            validation_observed_at=NOW + timedelta(minutes=1),
        )
        shutil.copyfile(second_history / SOURCE_EVIDENCE_FILENAME, source_path)
    if source_path.exists():
        source_path.chmod(0o600)

    with pytest.raises(ModelRefreshStagingError):
        load_previous_model_refresh_history(
            history_dir,
            expected_workflow_run_id="122",
            expected_workflow_run_attempt="1",
            expected_source_commit=SOURCE_COMMIT,
        )


@pytest.mark.parametrize("binding_field", ["content_sha256", "artifact_sha256", "byte_count"])
def test_durable_history_rejects_resealed_false_status_bindings(
    tmp_path: Path,
    binding_field: str,
) -> None:
    output = tmp_path / "output"
    history_dir = tmp_path / "history"
    registry, selected = _write_success_bundle(output)
    _stage(
        output=output,
        staging=history_dir,
        registry=registry,
        exit_status=0,
        selected=selected,
        workflow_run_id="122",
    )
    status_path = history_dir / WORKFLOW_STATUS_FILENAME
    payload = json.loads(status_path.read_text(encoding="utf-8"))
    binding = next(
        item for item in payload["artifacts"] if item["filename"] == SOURCE_EVIDENCE_FILENAME
    )
    binding[binding_field] = (
        binding[binding_field] + 1 if binding_field == "byte_count" else "f" * 64
    )
    payload["workflow_status_sha256"] = _sha(
        {key: value for key, value in payload.items() if key != "workflow_status_sha256"}
    )
    status_path.write_text(stable_json(payload), encoding="utf-8")
    status_path.chmod(0o600)

    with pytest.raises(ModelRefreshStagingError, match="content binding"):
        load_previous_model_refresh_history(
            history_dir,
            expected_workflow_run_id="122",
            expected_workflow_run_attempt="1",
            expected_source_commit=SOURCE_COMMIT,
        )


def test_workflow_status_loader_rejects_extreme_fraction_text_without_expansion(
    tmp_path: Path,
) -> None:
    _write_validated_history(tmp_path, name="extreme-fraction")
    status_path = tmp_path / "extreme-fraction-history" / WORKFLOW_STATUS_FILENAME
    payload = json.loads(status_path.read_text(encoding="utf-8"))
    payload["pricing_tolerance_fraction"] = "1e-1000000000"
    payload["workflow_status_sha256"] = _sha(
        {key: value for key, value in payload.items() if key != "workflow_status_sha256"}
    )
    status_path.write_text(stable_json(payload), encoding="utf-8")
    status_path.chmod(0o600)

    with pytest.raises(ModelRefreshStagingError, match="strict validation"):
        load_model_refresh_workflow_status(status_path)


def test_durable_history_rejects_resealed_diff_status_tolerance_mismatch(
    tmp_path: Path,
) -> None:
    _write_validated_history(tmp_path, name="tolerance")
    history_dir = tmp_path / "tolerance-history"
    diff_path = history_dir / DIFF_FILENAME
    diff = json.loads(diff_path.read_text(encoding="utf-8"))
    diff["pricing_tolerance_fraction"] = "0.5"
    diff["diff_sha256"] = _sha({key: value for key, value in diff.items() if key != "diff_sha256"})
    attempt_path = history_dir / ATTEMPT_FILENAME
    attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
    attempt["diff_sha256"] = diff["diff_sha256"]
    attempt["attempt_sha256"] = _sha(
        {key: value for key, value in attempt.items() if key != "attempt_sha256"}
    )
    _replace_bound_artifacts(
        history_dir,
        {
            DIFF_FILENAME: (diff, "diff_sha256"),
            ATTEMPT_FILENAME: (attempt, "attempt_sha256"),
        },
    )

    with pytest.raises(ModelRefreshStagingError, match="hash bindings"):
        load_previous_model_refresh_history(
            history_dir,
            expected_workflow_run_id="122",
            expected_workflow_run_attempt="1",
            expected_source_commit=SOURCE_COMMIT,
        )


def test_durable_history_rejects_resealed_selected_route_freshness_mismatch(
    tmp_path: Path,
) -> None:
    _write_validated_history(tmp_path, name="selection")
    history_dir = tmp_path / "selection-history"
    freshness_path = history_dir / FRESHNESS_FILENAME
    freshness = json.loads(freshness_path.read_text(encoding="utf-8"))
    freshness["production_selection_present"] = True
    freshness["freshness_sha256"] = _sha(
        {key: value for key, value in freshness.items() if key != "freshness_sha256"}
    )
    _replace_bound_artifacts(
        history_dir,
        {FRESHNESS_FILENAME: (freshness, "freshness_sha256")},
    )

    with pytest.raises(ModelRefreshStagingError, match="hash bindings"):
        load_previous_model_refresh_history(
            history_dir,
            expected_workflow_run_id="122",
            expected_workflow_run_attempt="1",
            expected_source_commit=SOURCE_COMMIT,
        )


def test_durable_history_rejects_resealed_unregistered_selected_route(tmp_path: Path) -> None:
    _write_validated_history(tmp_path, name="unregistered-selection")
    history_dir = tmp_path / "unregistered-selection-history"
    diff_path = history_dir / DIFF_FILENAME
    diff = json.loads(diff_path.read_text(encoding="utf-8"))
    diff["selected_routes"] = [
        {"exact_model_id": MODEL, "provider_endpoint": "synthetic/unregistered"}
    ]
    diff["diff_sha256"] = _sha({key: value for key, value in diff.items() if key != "diff_sha256"})
    attempt_path = history_dir / ATTEMPT_FILENAME
    attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
    attempt["diff_sha256"] = diff["diff_sha256"]
    attempt["attempt_sha256"] = _sha(
        {key: value for key, value in attempt.items() if key != "attempt_sha256"}
    )
    freshness_path = history_dir / FRESHNESS_FILENAME
    freshness = json.loads(freshness_path.read_text(encoding="utf-8"))
    freshness["production_selection_present"] = True
    freshness["freshness_sha256"] = _sha(
        {key: value for key, value in freshness.items() if key != "freshness_sha256"}
    )
    _replace_bound_artifacts(
        history_dir,
        {
            DIFF_FILENAME: (diff, "diff_sha256"),
            ATTEMPT_FILENAME: (attempt, "attempt_sha256"),
            FRESHNESS_FILENAME: (freshness, "freshness_sha256"),
        },
    )

    with pytest.raises(ModelRefreshStagingError, match="selected routes differ"):
        load_previous_model_refresh_history(
            history_dir,
            expected_workflow_run_id="122",
            expected_workflow_run_attempt="1",
            expected_source_commit=SOURCE_COMMIT,
        )


def test_durable_history_rejects_resealed_status_disposition(tmp_path: Path) -> None:
    _write_validated_history(tmp_path, name="false-disposition")
    history_dir = tmp_path / "false-disposition-history"
    status_path = history_dir / WORKFLOW_STATUS_FILENAME
    status = json.loads(status_path.read_text(encoding="utf-8"))
    status["disposition"] = "PRODUCTION_BLOCKED"
    status["refresh_exit_status"] = 6
    _replace_workflow_status(history_dir, status)

    with pytest.raises(ModelRefreshStagingError, match="production-blocked attempt"):
        load_previous_model_refresh_history(
            history_dir,
            expected_workflow_run_id="122",
            expected_workflow_run_attempt="1",
            expected_source_commit=SOURCE_COMMIT,
        )


@pytest.mark.parametrize("validation_delay", [timedelta(hours=29), timedelta(days=3650)])
def test_durable_history_rejects_resealed_future_validation_time(
    tmp_path: Path,
    validation_delay: timedelta,
) -> None:
    _write_validated_history(tmp_path, name="future-status")
    history_dir = tmp_path / "future-status-history"
    status_path = history_dir / WORKFLOW_STATUS_FILENAME
    status = json.loads(status_path.read_text(encoding="utf-8"))
    status["validated_at"] = (NOW + validation_delay).isoformat().replace("+00:00", "Z")
    _replace_workflow_status(history_dir, status)

    with pytest.raises(ModelRefreshStagingError, match="hash bindings"):
        load_previous_model_refresh_history(
            history_dir,
            expected_workflow_run_id="122",
            expected_workflow_run_attempt="1",
            expected_source_commit=SOURCE_COMMIT,
        )


def test_durable_bootstrap_history_rejects_resealed_predecessor_identity(
    tmp_path: Path,
) -> None:
    _write_validated_history(tmp_path, name="false-predecessor")
    history_dir = tmp_path / "false-predecessor-history"
    status_path = history_dir / WORKFLOW_STATUS_FILENAME
    status = json.loads(status_path.read_text(encoding="utf-8"))
    status["previous_workflow_run_id"] = "121"
    status["previous_workflow_run_attempt"] = "1"
    status["previous_workflow_status_sha256"] = "f" * 64
    _replace_workflow_status(history_dir, status)

    with pytest.raises(ModelRefreshStagingError, match="strict validation"):
        load_previous_model_refresh_history(
            history_dir,
            expected_workflow_run_id="122",
            expected_workflow_run_attempt="1",
            expected_source_commit=SOURCE_COMMIT,
        )


def test_successful_previous_snapshot_staging_requires_workflow_status(tmp_path: Path) -> None:
    history = _write_validated_history(tmp_path, name="previous")
    output = tmp_path / "current-output"
    registry, selected = _write_success_bundle(
        output,
        registry=history.candidate_registry,
        previous=history.snapshot,
        previous_source=history.source_evidence,
        previous_registry=history.candidate_registry,
    )

    with pytest.raises(ModelRefreshStagingError, match="requires its workflow status"):
        _stage(
            output=output,
            staging=tmp_path / "current-history",
            registry=registry,
            exit_status=0,
            selected=selected,
            previous=history.snapshot,
            previous_source=history.source_evidence,
            previous_registry=history.candidate_registry,
            workflow_run_id="123",
        )


def test_staging_rejects_previous_workflow_status_newer_than_current(tmp_path: Path) -> None:
    history = _write_validated_history(
        tmp_path,
        name="future-previous",
        validated_at=NOW + timedelta(minutes=4),
    )
    output = tmp_path / "current-output"
    registry, selected = _write_success_bundle(
        output,
        registry=history.candidate_registry,
        previous=history.snapshot,
        previous_source=history.source_evidence,
        previous_registry=history.candidate_registry,
        retrieved_at=NOW + timedelta(minutes=1),
    )

    with pytest.raises(ModelRefreshStagingError, match="newer than the current workflow"):
        _stage(
            output=output,
            staging=tmp_path / "current-history",
            registry=registry,
            exit_status=0,
            selected=selected,
            previous=history.snapshot,
            previous_source=history.source_evidence,
            previous_registry=history.candidate_registry,
            previous_workflow_status=history.workflow_status,
            workflow_run_id="123",
            validation_observed_at=NOW - timedelta(minutes=2),
        )


def test_staging_rejects_candidate_registry_created_after_current_observation(
    tmp_path: Path,
) -> None:
    base_registry = _registry()
    future_registry = seal_candidate_registry(
        created_at=NOW + timedelta(hours=1),
        discovery_run_sha256="e" * 64,
        candidates=base_registry.candidates,
    )
    output = tmp_path / "output"
    _registry_again, selected = _write_success_bundle(output, registry=base_registry)
    replacements = _registry_rebound_artifacts(output, future_registry)
    for filename, (payload, _self_hash_field) in replacements.items():
        if filename == CANDIDATE_REGISTRY_FILENAME:
            continue
        path = output / filename
        path.write_text(stable_json(payload), encoding="utf-8")
        path.chmod(0o600)

    with pytest.raises(ModelRefreshStagingError, match="created after its metadata observation"):
        _stage(
            output=output,
            staging=tmp_path / "staging",
            registry=future_registry,
            exit_status=0,
            selected=selected,
            validation_observed_at=NOW + timedelta(hours=1),
        )


def test_durable_history_rejects_resealed_future_candidate_registry(tmp_path: Path) -> None:
    _write_validated_history(tmp_path, name="future-registry")
    history_dir = tmp_path / "future-registry-history"
    base_registry = _registry()
    future_registry = seal_candidate_registry(
        created_at=NOW + timedelta(hours=1),
        discovery_run_sha256="e" * 64,
        candidates=base_registry.candidates,
    )
    _replace_bound_artifacts(
        history_dir,
        _registry_rebound_artifacts(history_dir, future_registry),
    )
    status_path = history_dir / WORKFLOW_STATUS_FILENAME
    status = json.loads(status_path.read_text(encoding="utf-8"))
    status["candidate_registry_sha256"] = future_registry.registry_sha256
    _replace_workflow_status(history_dir, status)

    with pytest.raises(ModelRefreshStagingError, match="candidate registry postdates"):
        load_previous_model_refresh_history(
            history_dir,
            expected_workflow_run_id="122",
            expected_workflow_run_attempt="1",
            expected_source_commit=SOURCE_COMMIT,
        )


def test_staging_rejects_previous_registry_newer_than_current_registry(tmp_path: Path) -> None:
    base_registry = _registry()
    previous_registry = seal_candidate_registry(
        created_at=NOW - timedelta(hours=1),
        discovery_run_sha256="d" * 64,
        candidates=base_registry.candidates,
    )
    current_registry = seal_candidate_registry(
        created_at=NOW - timedelta(hours=2),
        discovery_run_sha256="e" * 64,
        candidates=base_registry.candidates,
    )
    history = _write_validated_history(
        tmp_path,
        name="reverse-registry",
        registry=previous_registry,
        retrieved_at=NOW,
    )
    output = tmp_path / "current-output"
    registry, selected = _write_success_bundle(
        output,
        registry=current_registry,
        retrieved_at=NOW + timedelta(hours=1),
    )

    with pytest.raises(ModelRefreshStagingError, match="newer than the current registry"):
        _stage(
            output=output,
            staging=tmp_path / "current-history",
            registry=registry,
            exit_status=0,
            selected=selected,
            previous=history.snapshot,
            previous_source=history.source_evidence,
            previous_registry=history.candidate_registry,
            previous_workflow_status=history.workflow_status,
            workflow_run_id="123",
            validation_observed_at=NOW + timedelta(hours=1),
        )


def test_cross_registry_history_is_chained_into_the_next_staged_status(tmp_path: Path) -> None:
    current_registry = _registry()
    previous_registry = seal_candidate_registry(
        created_at=current_registry.created_at - timedelta(days=1),
        discovery_run_sha256="d" * 64,
        candidates=current_registry.candidates,
    )
    previous_output = tmp_path / "previous-output"
    _previous_registry, previous_selected = _write_success_bundle(
        previous_output,
        registry=previous_registry,
    )
    previous_history_dir = tmp_path / "previous-history"
    previous_status = _stage(
        output=previous_output,
        staging=previous_history_dir,
        registry=previous_registry,
        exit_status=0,
        selected=previous_selected,
        workflow_run_id="122",
    )
    history = load_previous_model_refresh_history(
        previous_history_dir,
        expected_workflow_run_id="122",
        expected_workflow_run_attempt="1",
        expected_source_commit=SOURCE_COMMIT,
    )
    current_output = tmp_path / "current-output"
    _current_registry, current_selected = _write_success_bundle(
        current_output,
        registry=current_registry,
        previous=history.snapshot,
        previous_source=history.source_evidence,
        previous_registry=history.candidate_registry,
    )

    current_status = _stage(
        output=current_output,
        staging=tmp_path / "current-history",
        registry=current_registry,
        exit_status=0,
        selected=current_selected,
        previous=history.snapshot,
        previous_source=history.source_evidence,
        previous_registry=history.candidate_registry,
        previous_workflow_status=history.workflow_status,
        workflow_run_id="123",
    )

    assert current_status.previous_workflow_run_id == "122"
    assert current_status.previous_workflow_run_attempt == "1"
    assert current_status.previous_workflow_status_sha256 == previous_status.workflow_status_sha256
    assert current_status.candidate_registry_sha256 == current_registry.registry_sha256
    staged_registry = (tmp_path / "current-history" / CANDIDATE_REGISTRY_FILENAME).read_text(
        encoding="utf-8"
    )
    assert staged_registry == stable_json(current_registry)


def test_chained_history_stages_exact_bounded_immediate_predecessor_evidence(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    previous = _write_validated_history(
        tmp_path,
        name="previous",
        workflow_run_id="122",
    )
    previous_history = tmp_path / "previous-history"
    output = tmp_path / "current-output"
    registry, selected = _write_success_bundle(
        output,
        registry=previous.candidate_registry,
        previous=previous.snapshot,
        previous_source=previous.source_evidence,
        previous_registry=previous.candidate_registry,
    )
    current_history = tmp_path / "current-history"

    status = _stage(
        output=output,
        staging=current_history,
        registry=registry,
        exit_status=0,
        previous=previous.snapshot,
        previous_source=previous.source_evidence,
        previous_registry=previous.candidate_registry,
        previous_workflow_status=previous.workflow_status,
        selected=selected,
        workflow_run_id="123",
    )

    assert {path.name for path in current_history.iterdir()} == (
        SUCCESS_NAMES | IMMEDIATE_PREDECESSOR_NAMES
    )
    assert {binding.filename for binding in status.artifacts} == (
        (SUCCESS_NAMES - {WORKFLOW_STATUS_FILENAME}) | IMMEDIATE_PREDECESSOR_NAMES
    )
    predecessor_copies = {
        PREVIOUS_WORKFLOW_STATUS_FILENAME: WORKFLOW_STATUS_FILENAME,
        PREVIOUS_CANDIDATE_REGISTRY_FILENAME: CANDIDATE_REGISTRY_FILENAME,
        PREVIOUS_SOURCE_EVIDENCE_FILENAME: SOURCE_EVIDENCE_FILENAME,
        PREVIOUS_SNAPSHOT_FILENAME: SNAPSHOT_FILENAME,
    }
    for staged_name, original_name in predecessor_copies.items():
        assert (current_history / staged_name).read_bytes() == (
            previous_history / original_name
        ).read_bytes()
    assert (
        load_previous_model_refresh_history(
            current_history,
            expected_workflow_run_id="123",
            expected_workflow_run_attempt="1",
            expected_source_commit=SOURCE_COMMIT,
        ).workflow_status
        == status
    )
    archive_path = tmp_path / "current-history.zip"
    extracted_history = tmp_path / "extracted-current-history"
    _write_history_archive(history_dir=current_history, archive_path=archive_path)
    assert (
        stage_script_main(
            [
                "extract-history",
                "--archive",
                str(archive_path),
                "--history-dir",
                str(extracted_history),
                "--expected-archive-bytes",
                str(archive_path.stat().st_size),
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == "model-refresh history extracted\n"
    assert {path.name for path in extracted_history.iterdir()} == (
        SUCCESS_NAMES | IMMEDIATE_PREDECESSOR_NAMES
    )
    assert (
        load_previous_model_refresh_history(
            extracted_history,
            expected_workflow_run_id="123",
            expected_workflow_run_attempt="1",
            expected_source_commit=SOURCE_COMMIT,
        ).workflow_status
        == status
    )


def test_chained_history_rejects_fully_resealed_false_semantic_baseline(
    tmp_path: Path,
) -> None:
    previous = _write_validated_history(
        tmp_path,
        name="previous",
        workflow_run_id="122",
    )
    output = tmp_path / "current-output"
    registry, selected = _write_success_bundle(
        output,
        registry=previous.candidate_registry,
        previous=previous.snapshot,
        previous_source=previous.source_evidence,
        previous_registry=previous.candidate_registry,
    )
    current_history = tmp_path / "current-history"
    _stage(
        output=output,
        staging=current_history,
        registry=registry,
        exit_status=0,
        previous=previous.snapshot,
        previous_source=previous.source_evidence,
        previous_registry=previous.candidate_registry,
        previous_workflow_status=previous.workflow_status,
        selected=selected,
        workflow_run_id="123",
    )
    diff_path = current_history / DIFF_FILENAME
    diff = json.loads(diff_path.read_text(encoding="utf-8"))
    assert diff["baseline_sha256"] == previous.snapshot.snapshot_sha256
    diff["baseline_sha256"] = "f" * 64
    diff["diff_sha256"] = _sha({key: value for key, value in diff.items() if key != "diff_sha256"})
    attempt_path = current_history / ATTEMPT_FILENAME
    attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
    attempt["diff_sha256"] = diff["diff_sha256"]
    attempt["attempt_sha256"] = _sha(
        {key: value for key, value in attempt.items() if key != "attempt_sha256"}
    )
    _replace_bound_artifacts(
        current_history,
        {
            DIFF_FILENAME: (diff, "diff_sha256"),
            ATTEMPT_FILENAME: (attempt, "attempt_sha256"),
        },
    )

    with pytest.raises(ModelRefreshStagingError, match="reproduced semantic diff"):
        load_previous_model_refresh_history(
            current_history,
            expected_workflow_run_id="123",
            expected_workflow_run_attempt="1",
            expected_source_commit=SOURCE_COMMIT,
        )


def test_same_workflow_rerun_chains_from_an_earlier_attempt(tmp_path: Path) -> None:
    history = _write_validated_history(
        tmp_path,
        name="attempt-one",
        workflow_run_id="123",
        workflow_run_attempt="1",
    )
    output = tmp_path / "attempt-two-output"
    registry, selected = _write_success_bundle(
        output,
        registry=history.candidate_registry,
        previous=history.snapshot,
        previous_source=history.source_evidence,
        previous_registry=history.candidate_registry,
    )

    status = _stage(
        output=output,
        staging=tmp_path / "attempt-two-history",
        registry=registry,
        exit_status=0,
        selected=selected,
        previous=history.snapshot,
        previous_source=history.source_evidence,
        previous_registry=history.candidate_registry,
        previous_workflow_status=history.workflow_status,
        workflow_run_id="123",
        workflow_run_attempt="2",
    )

    assert status.previous_workflow_run_id == "123"
    assert status.previous_workflow_run_attempt == "1"
    assert (
        load_previous_model_refresh_history(
            tmp_path / "attempt-two-history",
            expected_workflow_run_id="123",
            expected_workflow_run_attempt="2",
            expected_source_commit=SOURCE_COMMIT,
        ).workflow_status
        == status
    )


@pytest.mark.parametrize(
    ("previous_attempt", "current_attempt"),
    [("1", "1"), ("2", "1")],
)
def test_same_workflow_rerun_rejects_equal_or_later_previous_attempt(
    tmp_path: Path,
    previous_attempt: str,
    current_attempt: str,
) -> None:
    history = _write_validated_history(
        tmp_path,
        name=f"previous-{previous_attempt}-{current_attempt}",
        workflow_run_id="123",
        workflow_run_attempt=previous_attempt,
    )
    output = tmp_path / f"current-{previous_attempt}-{current_attempt}-output"
    registry, selected = _write_success_bundle(
        output,
        registry=history.candidate_registry,
        previous=history.snapshot,
        previous_source=history.source_evidence,
        previous_registry=history.candidate_registry,
    )
    staging = tmp_path / f"current-{previous_attempt}-{current_attempt}-history"

    with pytest.raises(ModelRefreshStagingError, match="workflow identity is invalid"):
        _stage(
            output=output,
            staging=staging,
            registry=registry,
            exit_status=0,
            selected=selected,
            previous=history.snapshot,
            previous_source=history.source_evidence,
            previous_registry=history.candidate_registry,
            previous_workflow_status=history.workflow_status,
            workflow_run_id="123",
            workflow_run_attempt=current_attempt,
        )
    assert not staging.exists()


def test_staging_rejects_status_paired_with_swapped_prior_triple(tmp_path: Path) -> None:
    first_output = tmp_path / "first-output"
    first_history = tmp_path / "first-history"
    registry, selected = _write_success_bundle(first_output)
    first_status = _stage(
        output=first_output,
        staging=first_history,
        registry=registry,
        exit_status=0,
        selected=selected,
        workflow_run_id="121",
    )
    second_output = tmp_path / "second-output"
    second_registry, second_selected = _write_success_bundle(
        second_output,
        retrieved_at=NOW + timedelta(minutes=1),
    )
    second_history = tmp_path / "second-history"
    _stage(
        output=second_output,
        staging=second_history,
        registry=second_registry,
        exit_status=0,
        selected=second_selected,
        workflow_run_id="122",
        validation_observed_at=NOW + timedelta(minutes=1),
    )
    second = load_previous_model_refresh_history(
        second_history,
        expected_workflow_run_id="122",
        expected_workflow_run_attempt="1",
        expected_source_commit=SOURCE_COMMIT,
    )

    with pytest.raises(ModelRefreshStagingError, match="content binding"):
        stage_model_refresh_evidence(
            output_dir=tmp_path / "absent-output",
            staging_dir=tmp_path / "unused-staging",
            candidate_registry=registry,
            refresh_exit_status=78,
            source_commit=SOURCE_COMMIT,
            workflow_run_id="123",
            workflow_run_attempt="1",
            pricing_tolerance_fraction="0.05",
            soft_max_age_hours=30,
            hard_max_age_hours=72,
            previous_snapshot=second.snapshot,
            previous_source_evidence=second.source_evidence,
            previous_candidate_registry=second.candidate_registry,
            previous_workflow_status=first_status,
            _validation_observed_at=NOW + timedelta(minutes=1),
        )


def test_policy_projection_is_rebuilt_staged_and_bound_in_workflow_status(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    registry = _registry()
    policy_inputs = _missing_policy_inputs(registry)
    _registry_again, selected = _write_success_bundle(output, policy_inputs=policy_inputs)
    staging = tmp_path / "staging"

    status = _stage(
        output=output,
        staging=staging,
        registry=registry,
        exit_status=0,
        selected=selected,
        policy_inputs=policy_inputs,
    )

    assert status.policy_projection_expected is True
    assert {path.name for path in staging.iterdir()} == POLICY_SUCCESS_NAMES
    projection = load_model_policy_eligibility_refresh_artifact(
        staging / POLICY_ELIGIBILITY_REFRESH_FILENAME
    )
    assert projection.redetermination_required is True
    assert projection.route_records[0].review_reasons == (PolicyReviewReason.MISSING,)
    projection_binding = next(
        binding
        for binding in status.artifacts
        if binding.filename == POLICY_ELIGIBILITY_REFRESH_FILENAME
    )
    assert projection_binding.artifact_sha256 == projection.artifact_sha256


@pytest.mark.parametrize("mutation", ["omitted", "unexpected", "tampered"])
def test_policy_projection_omission_extra_or_tamper_is_rejected(
    tmp_path: Path,
    mutation: str,
) -> None:
    output = tmp_path / "output"
    registry = _registry()
    policy_inputs = _missing_policy_inputs(registry)
    _registry_again, selected = _write_success_bundle(output, policy_inputs=policy_inputs)
    projection_path = output / POLICY_ELIGIBILITY_REFRESH_FILENAME
    staged_policy_inputs = policy_inputs
    if mutation == "omitted":
        projection_path.unlink()
    elif mutation == "unexpected":
        staged_policy_inputs = None
    else:
        projection_path.write_text(
            projection_path.read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )

    with pytest.raises((ModelRefreshStagingError, ValueError)):
        _stage(
            output=output,
            staging=tmp_path / "staging",
            registry=registry,
            exit_status=0,
            selected=selected,
            policy_inputs=staged_policy_inputs,
        )
    assert not (tmp_path / "staging").exists()


def test_production_blocked_bundle_requires_exit_six_and_expected_routes(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    registry, selected = _write_success_bundle(output, blocked=True)

    status = _stage(
        output=output,
        staging=tmp_path / "staging",
        registry=registry,
        exit_status=6,
        selected=selected,
    )

    assert status.disposition is ModelRefreshWorkflowDisposition.PRODUCTION_BLOCKED
    assert status.refresh_exit_status == 6
    with pytest.raises(ModelRefreshStagingError, match="blocking attempt"):
        _stage(
            output=output,
            staging=tmp_path / "wrong-staging",
            registry=registry,
            exit_status=0,
            selected=selected,
        )


def test_typed_provider_failure_and_missing_prerequisite_have_exact_inventories(
    tmp_path: Path,
) -> None:
    registry = _registry()
    failed = seal_model_refresh_attempt(
        attempted_at=NOW,
        candidate_registry_sha256=registry.registry_sha256,
        failure_code=ModelRefreshFailureCode.AUTHENTICATION,
    )
    output = tmp_path / "failed"
    write_model_refresh_failure(output, attempt=failed)

    failure_status = _stage(
        output=output,
        staging=tmp_path / "failure-staging",
        registry=registry,
        exit_status=4,
    )
    assert failure_status.disposition is ModelRefreshWorkflowDisposition.FAILED
    assert failure_status.artifacts[0].artifact_sha256 == failed.attempt_sha256
    assert {path.name for path in (tmp_path / "failure-staging").iterdir()} == {
        ATTEMPT_FILENAME,
        WORKFLOW_STATUS_FILENAME,
    }

    prerequisite_status = _stage(
        output=tmp_path / "absent-output",
        staging=tmp_path / "prerequisite-staging",
        registry=registry,
        exit_status=78,
    )
    assert prerequisite_status.disposition is ModelRefreshWorkflowDisposition.PREREQUISITE_MISSING
    assert [path.name for path in (tmp_path / "prerequisite-staging").iterdir()] == [
        WORKFLOW_STATUS_FILENAME
    ]


def test_previous_snapshot_baseline_must_be_supplied_and_hash_bound(tmp_path: Path) -> None:
    history = _write_validated_history(tmp_path, name="previous")
    registry = history.candidate_registry
    previous = history.snapshot
    previous_source = history.source_evidence
    output = tmp_path / "output"
    _registry_again, selected = _write_success_bundle(
        output,
        registry=registry,
        previous=previous,
        previous_source=previous_source,
        previous_registry=registry,
    )

    with pytest.raises(ModelRefreshStagingError, match="baseline, source, or registry"):
        _stage(
            output=output,
            staging=tmp_path / "missing-prior",
            registry=registry,
            exit_status=0,
            selected=selected,
        )
    with pytest.raises(ModelRefreshStagingError, match="must be supplied together"):
        _stage(
            output=output,
            staging=tmp_path / "unpaired-prior",
            registry=registry,
            exit_status=0,
            previous=previous,
            selected=selected,
        )
    status = _stage(
        output=output,
        staging=tmp_path / "with-prior",
        registry=registry,
        exit_status=0,
        previous=previous,
        previous_source=previous_source,
        previous_registry=registry,
        previous_workflow_status=history.workflow_status,
        selected=selected,
    )
    assert status.disposition is ModelRefreshWorkflowDisposition.COMPLETED


def test_resealed_previous_snapshot_requires_matching_workflow_binding(
    tmp_path: Path,
) -> None:
    history = _write_validated_history(tmp_path, name="previous")
    registry = history.candidate_registry
    previous_source = history.source_evidence
    previous = history.snapshot
    payload = previous.model_dump(mode="json")
    payload["source_evidence_sha256"] = "f" * 64
    payload["snapshot_sha256"] = _sha(
        {key: value for key, value in payload.items() if key != "snapshot_sha256"}
    )
    forged_previous = type(previous).model_validate(payload)
    output = tmp_path / "output"
    _write_success_bundle(
        output,
        previous=previous,
        previous_source=previous_source,
        previous_registry=registry,
    )

    with pytest.raises(ModelRefreshStagingError, match="content binding"):
        _stage(
            output=output,
            staging=tmp_path / "staging",
            registry=registry,
            exit_status=0,
            previous=forged_previous,
            previous_source=previous_source,
            previous_registry=registry,
            previous_workflow_status=history.workflow_status,
        )


@pytest.mark.parametrize(
    ("tolerance", "soft_age", "hard_age"),
    [
        ("0.99", 30, 72),
        ("0.05", 1, 2),
    ],
)
def test_staging_rejects_workflow_policy_mismatch(
    tmp_path: Path,
    tolerance: str,
    soft_age: int,
    hard_age: int,
) -> None:
    output = tmp_path / "output"
    registry, selected = _write_success_bundle(output)

    with pytest.raises(ModelRefreshStagingError, match="hash bindings"):
        _stage(
            output=output,
            staging=tmp_path / "staging",
            registry=registry,
            exit_status=0,
            selected=selected,
            pricing_tolerance_fraction=tolerance,
            soft_max_age_hours=soft_age,
            hard_max_age_hours=hard_age,
        )


def test_staging_rejects_a_self_consistent_hard_expired_success_bundle(
    tmp_path: Path,
) -> None:
    registry = _registry()
    source = _source(registry)
    snapshot = build_model_refresh_snapshot_from_source(
        source_evidence=source,
        candidate_registry=registry,
    )
    diff = diff_model_refresh(
        current=snapshot,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
    )
    attempt = seal_model_refresh_attempt(
        attempted_at=NOW,
        candidate_registry_sha256=registry.registry_sha256,
        snapshot=snapshot,
        diff=diff,
    )
    freshness = evaluate_model_refresh_freshness(
        observed_at=NOW + timedelta(hours=73),
        snapshot=snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=False,
    )
    output = tmp_path / "output"
    write_model_refresh_success(
        output,
        source_evidence=source,
        snapshot=snapshot,
        diff=diff,
        attempt=attempt,
        freshness=freshness,
    )

    with pytest.raises(ModelRefreshStagingError, match="not current"):
        _stage(
            output=output,
            staging=tmp_path / "staging",
            registry=registry,
            exit_status=0,
        )


def test_staging_uses_its_own_clock_to_reject_future_and_stale_bundles(
    tmp_path: Path,
) -> None:
    future_output = tmp_path / "future-output"
    future_at = datetime(2099, 1, 1, tzinfo=UTC)
    registry, selected = _write_success_bundle(
        future_output,
        retrieved_at=future_at,
    )
    with pytest.raises(ModelRefreshStagingError, match="validation time differs"):
        _stage(
            output=future_output,
            staging=tmp_path / "future-staging",
            registry=registry,
            exit_status=0,
            selected=selected,
            validation_observed_at=NOW,
        )

    stale_output = tmp_path / "stale-output"
    registry, selected = _write_success_bundle(stale_output, retrieved_at=NOW)
    with pytest.raises(ModelRefreshStagingError, match="validation time differs"):
        _stage(
            output=stale_output,
            staging=tmp_path / "stale-staging",
            registry=registry,
            exit_status=0,
            selected=selected,
            validation_observed_at=NOW + timedelta(hours=31),
        )


@pytest.mark.parametrize("validation_delay", [timedelta(minutes=6), timedelta(hours=29)])
def test_staging_rejects_success_observed_outside_validation_clock_skew(
    tmp_path: Path,
    validation_delay: timedelta,
) -> None:
    output = tmp_path / "output"
    registry, selected = _write_success_bundle(output, retrieved_at=NOW)

    with pytest.raises(ModelRefreshStagingError, match="validation time differs"):
        _stage(
            output=output,
            staging=tmp_path / "staging",
            registry=registry,
            exit_status=0,
            selected=selected,
            validation_observed_at=NOW + validation_delay,
        )

    assert not (tmp_path / "staging").exists()


def test_staging_rejects_a_resealed_semantically_false_diff(tmp_path: Path) -> None:
    history = _write_validated_history(tmp_path, name="previous")
    registry = history.candidate_registry
    previous = history.snapshot
    parameters = ["max_tokens", "reasoning", "response_format", "seed", "temperature"]
    endpoint = _endpoint(parameters=parameters)
    observed_at = NOW + timedelta(hours=1)
    # Build the changed live snapshot from provider-shaped inputs rather than
    # reusing normalized evidence as untrusted metadata.
    source = _source(
        registry,
        retrieved_at=observed_at,
        models=[
            {
                "id": MODEL,
                "canonical_slug": MODEL,
                "context_length": 100_000,
                "top_provider": {
                    "context_length": 100_000,
                    "max_completion_tokens": 8_192,
                },
                "supported_parameters": parameters,
            }
        ],
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )
    snapshot = build_model_refresh_snapshot_from_source(
        source_evidence=source,
        candidate_registry=registry,
    )
    actual = diff_model_refresh(
        current=snapshot,
        previous=previous,
        previous_source_evidence=history.source_evidence,
        previous_candidate_registry=registry,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=observed_at,
    )
    assert actual.changes
    payload = actual.model_dump(mode="json")
    payload["changes"] = []
    payload["semantic_unchanged"] = True
    payload["status"] = "UNCHANGED"
    payload["production_block_reasons"] = []
    payload["diff_sha256"] = _sha(
        {key: value for key, value in payload.items() if key != "diff_sha256"}
    )
    forged = type(actual).model_validate(payload)
    attempt = seal_model_refresh_attempt(
        attempted_at=observed_at,
        candidate_registry_sha256=registry.registry_sha256,
        snapshot=snapshot,
        diff=forged,
    )
    freshness = evaluate_model_refresh_freshness(
        observed_at=observed_at,
        snapshot=snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=False,
    )
    output = tmp_path / "output"
    write_model_refresh_success(
        output,
        source_evidence=source,
        snapshot=snapshot,
        diff=forged,
        attempt=attempt,
        freshness=freshness,
    )

    with pytest.raises(ModelRefreshStagingError, match="reproduced semantic diff"):
        _stage(
            output=output,
            staging=tmp_path / "staging",
            registry=registry,
            exit_status=0,
            previous=previous,
            previous_source=history.source_evidence,
            previous_registry=registry,
            previous_workflow_status=history.workflow_status,
            validation_observed_at=observed_at,
        )


def test_staging_rejects_a_fully_resealed_snapshot_without_source_support(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    registry, _selected = _write_success_bundle(output)
    snapshot = load_model_refresh_snapshot(output / SNAPSHOT_FILENAME)
    payload = snapshot.model_dump(mode="json")
    payload["models"][0]["catalog_context_limit"] -= 1
    payload["models"][0] = _reseal_catalog_model(payload["models"][0])
    payload["semantic_sha256"] = _sha(payload["models"])
    payload["snapshot_sha256"] = _sha(
        {key: value for key, value in payload.items() if key != "snapshot_sha256"}
    )
    forged_snapshot = type(snapshot).model_validate(payload)
    forged_diff = diff_model_refresh(
        current=forged_snapshot,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=forged_snapshot.retrieved_at,
    )
    forged_attempt = seal_model_refresh_attempt(
        attempted_at=forged_snapshot.retrieved_at,
        candidate_registry_sha256=registry.registry_sha256,
        snapshot=forged_snapshot,
        diff=forged_diff,
    )
    forged_freshness = evaluate_model_refresh_freshness(
        observed_at=forged_snapshot.retrieved_at,
        snapshot=forged_snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=False,
    )
    for filename, artifact in (
        (SNAPSHOT_FILENAME, forged_snapshot),
        (DIFF_FILENAME, forged_diff),
        (ATTEMPT_FILENAME, forged_attempt),
        (FRESHNESS_FILENAME, forged_freshness),
    ):
        (output / filename).write_text(stable_json(artifact), encoding="utf-8")

    with pytest.raises(ModelRefreshStagingError, match="reproduced semantic snapshot"):
        _stage(
            output=output,
            staging=tmp_path / "staging",
            registry=registry,
            exit_status=0,
        )


def test_staging_rejects_a_cross_run_source_evidence_swap(tmp_path: Path) -> None:
    first = tmp_path / "first"
    registry, selected = _write_success_bundle(first)
    previous = _snapshot(registry)
    second = tmp_path / "second"
    _write_success_bundle(second, previous=previous)
    (first / SOURCE_EVIDENCE_FILENAME).write_bytes((second / SOURCE_EVIDENCE_FILENAME).read_bytes())
    (first / SOURCE_EVIDENCE_FILENAME).chmod(0o600)

    with pytest.raises(ModelRefreshStagingError, match="reproduced semantic snapshot"):
        _stage(
            output=first,
            staging=tmp_path / "staging",
            registry=registry,
            exit_status=0,
            selected=selected,
        )


@pytest.mark.parametrize("mutation", ["extra", "mode", "hardlink", "tamper"])
def test_unsafe_or_tampered_source_inventory_is_rejected_without_staging(
    tmp_path: Path,
    mutation: str,
) -> None:
    output = tmp_path / "output"
    staging = tmp_path / "staging"
    registry, selected = _write_success_bundle(output)
    attempt = output / ATTEMPT_FILENAME
    if mutation == "extra":
        extra = output / "unexpected.json"
        extra.write_text("{}\n", encoding="utf-8")
        extra.chmod(0o600)
    elif mutation == "mode":
        attempt.chmod(0o644)
    elif mutation == "hardlink":
        outside = tmp_path / "shared-attempt.json"
        try:
            os.link(attempt, outside)
        except OSError:
            pytest.skip("hardlinks unavailable")
    else:
        attempt.write_text(attempt.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises((ModelRefreshStagingError, ValueError)):
        _stage(
            output=output,
            staging=staging,
            registry=registry,
            exit_status=0,
            selected=selected,
        )
    assert not staging.exists()


def test_cross_hash_exit_identity_and_reused_destination_fail_closed(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    registry, selected = _write_success_bundle(first)
    second = tmp_path / "second"
    previous = _snapshot(registry)
    _write_success_bundle(second, previous=previous)
    (first / ATTEMPT_FILENAME).write_bytes((second / ATTEMPT_FILENAME).read_bytes())
    (first / ATTEMPT_FILENAME).chmod(0o600)

    with pytest.raises(ModelRefreshStagingError, match="hash bindings"):
        _stage(
            output=first,
            staging=tmp_path / "cross-hash",
            registry=registry,
            exit_status=0,
            selected=selected,
        )
    with pytest.raises(ModelRefreshStagingError, match="accepted workflow"):
        _stage(
            output=first,
            staging=tmp_path / "unknown-exit",
            registry=registry,
            exit_status=70,
            selected=selected,
        )

    clean = tmp_path / "clean"
    registry, selected = _write_success_bundle(clean)
    reused = tmp_path / "reused"
    reused.mkdir(mode=0o700)
    with pytest.raises(ModelRefreshStagingError, match="must be fresh"):
        _stage(
            output=clean,
            staging=reused,
            registry=registry,
            exit_status=0,
            selected=selected,
        )


def test_invalid_workflow_identity_removes_partial_staging(tmp_path: Path) -> None:
    output = tmp_path / "output"
    staging = tmp_path / "staging"
    registry, selected = _write_success_bundle(output)

    with pytest.raises(ModelRefreshStagingError, match="workflow identity"):
        stage_model_refresh_evidence(
            output_dir=output,
            staging_dir=staging,
            candidate_registry=registry,
            refresh_exit_status=0,
            source_commit="not-a-commit",
            workflow_run_id="123",
            workflow_run_attempt="1",
            pricing_tolerance_fraction="0.05",
            soft_max_age_hours=30,
            hard_max_age_hours=72,
            expected_selected_routes=selected,
            _validation_observed_at=NOW + timedelta(minutes=1),
        )
    assert not staging.exists()


def test_final_inventory_injection_quarantines_the_upload_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "output"
    staging = tmp_path / "staging"
    registry, selected = _write_success_bundle(output)
    original_write = refresh_staging_module.write_json_evidence

    def inject_after_status(**kwargs: Any) -> Any:
        result = original_write(**kwargs)
        if kwargs["relative_path"] == WORKFLOW_STATUS_FILENAME:
            injected = Path(kwargs["evidence_root"]) / "injected.txt"
            injected.write_text("untrusted\n", encoding="utf-8")
            injected.chmod(0o600)
        return result

    monkeypatch.setattr(
        refresh_staging_module,
        "write_json_evidence",
        inject_after_status,
    )
    with pytest.raises(ModelRefreshStagingError, match="inventory"):
        _stage(
            output=output,
            staging=staging,
            registry=registry,
            exit_status=0,
            selected=selected,
        )

    assert not staging.exists()
    assert list(tmp_path.glob(".staging.rejected-*"))


def test_staging_script_executes_prerequisite_and_rejects_unknown_exit(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    common = [
        "--output-dir",
        str(tmp_path / "absent-output"),
        "--candidate-registry",
        str(ROOT / "config" / "models.candidates.toml"),
        "--source-commit",
        SOURCE_COMMIT,
        "--workflow-run-id",
        "123",
        "--workflow-run-attempt",
        "1",
        "--pricing-tolerance-fraction",
        "0.05",
        "--soft-max-age-hours",
        "30",
        "--hard-max-age-hours",
        "72",
    ]
    staged = tmp_path / "staged"

    assert (
        stage_script_main(
            [
                *common,
                "--staging-dir",
                str(staged),
                "--refresh-exit-status",
                "78",
            ]
        )
        == 0
    )
    assert load_model_refresh_workflow_status(staged / WORKFLOW_STATUS_FILENAME)
    assert "PREREQUISITE_MISSING" in capsys.readouterr().out

    rejected = tmp_path / "rejected"
    assert (
        stage_script_main(
            [
                *common,
                "--staging-dir",
                str(rejected),
                "--refresh-exit-status",
                "70",
            ]
        )
        == 74
    )
    assert not rejected.exists()
    assert capsys.readouterr().out == "model-refresh artifact staging failed\n"
