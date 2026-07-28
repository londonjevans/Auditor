from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.registry import ModelRegistry
from mmaudit.models.schemas import (
    AuditReport,
    RepositoryFile,
    RepositoryMap,
)
from mmaudit.orchestration.manifest import (
    ManifestBindingSet,
    ManifestFileBinding,
    ManifestHashBinding,
    RunEvidenceManifest,
    build_run_evidence_manifest,
    validate_manifest_artifacts,
    write_run_evidence_manifest,
)
from mmaudit.orchestration.verification import (
    RunVerification,
    RunVerificationCategory,
    RunVerificationMismatchKind,
    RunVerificationStatus,
    verify_run_evidence,
)
from tests.unit.test_model_registry import _verified_production_config_and_capability

runner = CliRunner()


def _report(config) -> AuditReport:
    return AuditReport(
        schema_version="1.0",
        run_id="manifest-test-run",
        generated_at=datetime(2026, 1, 2, tzinfo=UTC),
        completed=True,
        incomplete_reasons=[],
        repository=RepositoryMap(
            root_name="synthetic-manifest-repository",
            languages={"Solidity": 1},
            frameworks=["Foundry"],
            manifests=["foundry.toml"],
            entry_points=[],
            api_surfaces=[],
            auth_components=[],
            data_layers=[],
            network_clients=[],
            file_handlers=[],
            configuration_files=["foundry.toml"],
            sensitive_processing=[],
            security_tests=[],
            files=[
                RepositoryFile(
                    path="src/Vault.sol",
                    size=32,
                    lines=1,
                    sha256="a" * 64,
                    language="Solidity",
                )
            ],
        ),
        configuration_hash=config.stable_hash(),
        model_configuration_hash=config.model_hash(),
        privacy={"code_egress_enabled": False},
        scanner_runs=[],
        usage=[],
        budget_usd=20,
        accounted_cost_usd=0,
        findings=[],
        rejected_findings=[],
    )


def _write_required_artifacts(run_dir: Path) -> None:
    payloads = {
        "solidity-compilation.json": {"schema_version": "1.0", "results": []},
        "invariant-harness-plan.json": {
            "schema_version": "1.0",
            "harnesses": [{"name": "InvariantHarness", "invariant_id": "inv-1"}],
        },
        "property-corpus.json": {
            "schema_version": "1.0",
            "corpus": {
                "corpus_hash": "b" * 64,
                "properties": [{"property_id": "property-1", "campaign": {"seed": 17}}],
            },
        },
        "invariant-execution-results.json": {
            "schema_version": "1.0",
            "results": [{"harness_name": "InvariantHarness", "campaign_seed": 17}],
        },
        "formal-results.json": {
            "schema_version": "1.0",
            "runs": [{"tool": "synthetic-formal", "campaign_seed": 23}],
        },
        "reproduction-results.json": {
            "schema_version": "1.0",
            "test_specifications": [{"name": "test_Remediation"}],
            "results": [
                {
                    "candidate_id": "candidate-1",
                    "state": "not_reproduced",
                    "specification_sha256": "c" * 64,
                    "generated_test_sha256": None,
                }
            ],
        },
        "solidity-coverage.json": {"schema_version": "1.0", "coverage": None},
        "model-review-coverage.json": {"schema_version": "1.0", "coverage": None},
        "scope-assessment.json": {"schema_version": "1.0", "assessment": None},
    }
    run_dir.mkdir()
    for name, payload in payloads.items():
        (run_dir / name).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def _write_verifiable_run(
    root: Path,
    config,
) -> tuple[Path, Path, RunEvidenceManifest, AuditReport]:
    repository = root / "repository"
    source = repository / "src" / "Vault.sol"
    source.parent.mkdir(parents=True)
    source_contents = "contract Vault { function safe() external {} }\n"
    source.write_text(source_contents, encoding="utf-8")
    report = _report(config)
    report = report.model_copy(
        update={
            "repository": report.repository.model_copy(
                update={
                    "root_name": repository.name,
                    "files": [
                        RepositoryFile(
                            path="src/Vault.sol",
                            size=len(source_contents.encode("utf-8")),
                            lines=1,
                            sha256=hashlib.sha256(source_contents.encode("utf-8")).hexdigest(),
                            language="Solidity",
                        )
                    ],
                }
            )
        }
    )
    run_dir = root / "run"
    _write_required_artifacts(run_dir)
    (run_dir / "final-findings.json").write_text(
        report.model_dump_json(),
        encoding="utf-8",
    )
    (run_dir / "benchmark-certificate-verification.json").write_text(
        '{"schema_version":"1.0","status":"current"}\n',
        encoding="utf-8",
    )
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
    )
    write_run_evidence_manifest(
        run_dir / "run-evidence-manifest.json",
        manifest,
    )
    return repository, run_dir, manifest, report


def test_manifest_serialization_and_all_required_bindings_are_stable(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    first_run = tmp_path / "first"
    second_run = tmp_path / "second"
    _write_required_artifacts(first_run)
    _write_required_artifacts(second_run)

    first = build_run_evidence_manifest(
        run_dir=first_run,
        report=_report(config),
        config=config,
    )
    second = build_run_evidence_manifest(
        run_dir=second_run,
        report=_report(config),
        config=config,
    )

    assert first.model_dump_json() == second.model_dump_json()
    assert first.manifest_sha256 == second.manifest_sha256
    assert first.source_tree_sha256
    assert set(ManifestBindingSet.model_fields) == {
        name for name, bindings in first.bindings if bindings
    }
    assert any(binding.identifier.startswith("seed/") for binding in first.bindings.seeds)
    assert {binding.path for binding in first.artifacts} == {
        path.name for path in first_run.iterdir()
    }


def test_manifest_self_hash_and_artifact_hashes_reject_tampering(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    run_dir = tmp_path / "run"
    _write_required_artifacts(run_dir)
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=_report(config),
        config=config,
    )
    manifest_path = run_dir / "run-evidence-manifest.json"
    write_run_evidence_manifest(manifest_path, manifest)
    validate_manifest_artifacts(manifest, run_dir)

    altered_manifest = manifest.model_dump(mode="json")
    altered_manifest["repository_root_name"] = "tampered"
    with pytest.raises(ValidationError, match="self-hash"):
        RunEvidenceManifest.model_validate(altered_manifest)

    (run_dir / "solidity-coverage.json").write_text(
        '{"schema_version":"1.0","coverage":{"tampered":true}}\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="artifact hash mismatch"):
        validate_manifest_artifacts(manifest, run_dir)


def test_manifest_semantically_binds_runtime_model_qualification(
    tmp_path: Path,
) -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    validation = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        required=True,
        now=observed_at,
    )
    assert validation.valid
    run_dir = tmp_path / "qualified-run"
    _write_required_artifacts(run_dir)
    qualification_path = run_dir / "model-qualification-runtime.json"
    qualification_path.write_text(
        json.dumps(validation.as_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=_report(config),
        config=config,
    )

    model_bindings = {binding.identifier: binding for binding in manifest.bindings.models}
    assert model_bindings["qualification/artifact"].sha256 == qualification.artifact_sha256
    assert (
        model_bindings["qualification/production-selection"].sha256
        == qualification.production_selection_sha256
    )
    assert (
        model_bindings["qualification/production-effective-config"].sha256
        == qualification.production_effective_config_sha256
    )
    assert (
        model_bindings["qualification/release-observation"].sha256
        == qualification.release_observation_sha256
    )
    per_model_kinds = {
        "result": "qualification_result_sha256",
        "benchmark-report": "benchmark_report_sha256",
        "benchmark-verification": "benchmark_verification_sha256",
        "fresh-benchmark-evidence": "fresh_benchmark_evidence_sha256",
        "endpoint-snapshot": "endpoint_snapshot_sha256",
        "model-metadata-snapshot": "model_metadata_snapshot_sha256",
        "pricing-snapshot": "pricing_snapshot_sha256",
    }
    for kind, attribute in per_model_kinds.items():
        qualified_bindings = [
            binding
            for identifier, binding in model_bindings.items()
            if identifier.startswith(f"qualification/{kind}/")
        ]
        assert len(qualified_bindings) == len(qualification.models)
        assert {binding.sha256 for binding in qualified_bindings} == {
            getattr(model, attribute) for model in qualification.models
        }
        assert all(
            int(binding.details["benchmark_case_count"]) > 0 for binding in qualified_bindings
        )
        assert all(binding.details["evaluated_at"] for binding in qualified_bindings)
        assert all(binding.details["expires_at"] for binding in qualified_bindings)

    tampered = validation.as_dict()
    tampered["qualification_artifact_sha256"] = "f" * 64
    qualification_path.write_text(
        json.dumps(tampered, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError, match="self-hash"):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=_report(config),
            config=config,
        )

    tampered = validation.as_dict()
    tampered["model_bindings"][0]["benchmark_report_sha256"] = "e" * 64
    qualification_path.write_text(
        json.dumps(tampered, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError, match="self-hash"):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=_report(config),
            config=config,
        )


def test_manifest_rejects_linked_artifacts(
    tmp_path: Path,
    config_factory,
) -> None:
    run_dir = tmp_path / "run"
    _write_required_artifacts(run_dir)
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    try:
        (run_dir / "linked.json").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")

    with pytest.raises(ValueError, match="links"):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=_report(config_factory()),
            config=config_factory(),
        )


def test_manifest_file_bindings_reject_sensitive_paths() -> None:
    with pytest.raises(ValidationError, match="identify a file"):
        ManifestFileBinding(path=".env", sha256="a" * 64, size=1)


def test_published_manifest_schema_is_strict_and_bounded() -> None:
    schema_path = (
        Path(__file__).resolve().parents[2] / "schemas" / ("run_evidence_manifest.schema.json")
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    assert schema["additionalProperties"] is False
    assert schema["properties"]["artifacts"]["maxItems"] == 100_000
    assert schema["$defs"]["fileBinding"]["additionalProperties"] is False
    assert schema["$defs"]["hashBinding"]["additionalProperties"] is False
    assert schema["$defs"]["bindingSet"]["additionalProperties"] is False


def test_verify_run_is_current_and_serializes_deterministically(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    repository, run_dir, manifest, _ = _write_verifiable_run(tmp_path, config)

    first = verify_run_evidence(
        manifest_path=run_dir / "run-evidence-manifest.json",
        run_dir=run_dir,
        repository_root=repository,
        config=config,
    )
    second = verify_run_evidence(
        manifest_path=run_dir / "run-evidence-manifest.json",
        run_dir=run_dir,
        repository_root=repository,
        config=config,
    )

    assert first == second
    assert first.status is RunVerificationStatus.CURRENT
    assert not first.mismatches
    assert first.manifest_sha256 == manifest.manifest_sha256
    assert RunVerification.model_validate_json(first.model_dump_json()) == first

    tampered = first.model_dump(mode="json")
    tampered["status"] = RunVerificationStatus.STALE
    with pytest.raises(ValidationError, match="inconsistent"):
        RunVerification.model_validate(tampered)


def test_verify_run_detects_every_security_relevant_drift_category(
    tmp_path: Path,
    config_factory,
    monkeypatch,
) -> None:
    config = config_factory()
    repository, run_dir, _, _ = _write_verifiable_run(tmp_path, config)
    (repository / "src" / "Vault.sol").write_text(
        "contract Vault { function changed() external {} }\n",
        encoding="utf-8",
    )
    (run_dir / "solidity-compilation.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "results": [
                    {
                        "framework": "foundry",
                        "project_root": ".",
                        "status": "passed",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "benchmark-certificate-verification.json").write_text(
        '{"schema_version":"1.0","status":"stale"}\n',
        encoding="utf-8",
    )
    changed_role = config.models.threat_model.model_copy(
        update={"primary": config.models.source_audit.primary}
    )
    changed_config = config.model_copy(
        update={"models": config.models.model_copy(update={"threat_model": changed_role})}
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.manifest._prompt_bindings",
        lambda _report: [
            ManifestHashBinding(
                identifier="template/synthetic-changed.md",
                sha256="d" * 64,
            )
        ],
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.manifest._tool_bindings",
        lambda _config, _report: [
            ManifestHashBinding(
                identifier="configured/changed-tool",
                sha256="e" * 64,
            )
        ],
    )

    verification = verify_run_evidence(
        manifest_path=run_dir / "run-evidence-manifest.json",
        run_dir=run_dir,
        repository_root=repository,
        config=changed_config,
    )

    assert verification.status is RunVerificationStatus.STALE
    categories = {mismatch.category for mismatch in verification.mismatches}
    assert categories >= {
        RunVerificationCategory.SOURCE,
        RunVerificationCategory.CONFIGURATION,
        RunVerificationCategory.PROMPT,
        RunVerificationCategory.MODEL,
        RunVerificationCategory.TOOL,
        RunVerificationCategory.COMPILER,
        RunVerificationCategory.ARTIFACT,
        RunVerificationCategory.CERTIFICATE,
    }
    assert all(
        mismatch.kind
        in {
            RunVerificationMismatchKind.CHANGED,
            RunVerificationMismatchKind.MISSING,
            RunVerificationMismatchKind.UNEXPECTED,
        }
        for mismatch in verification.mismatches
    )


def test_verify_run_cli_clean_tampered_and_missing_artifact(
    tmp_path: Path,
    config_factory,
    monkeypatch,
) -> None:
    config = config_factory()
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)

    clean_repository, clean_run, _, _ = _write_verifiable_run(
        tmp_path / "clean",
        config,
    )
    clean_output = tmp_path / "clean-verification.json"
    clean = runner.invoke(
        app,
        [
            "verify-run",
            "--manifest",
            str(clean_run / "run-evidence-manifest.json"),
            "--run-dir",
            str(clean_run),
            "--repo",
            str(clean_repository),
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--output",
            str(clean_output),
            "--no-color",
        ],
    )
    assert clean.exit_code == ExitCode.SUCCESS
    assert (
        RunVerification.model_validate_json(clean_output.read_text(encoding="utf-8")).status
        is RunVerificationStatus.CURRENT
    )

    changed_repository, changed_run, _, _ = _write_verifiable_run(
        tmp_path / "changed",
        config,
    )
    (changed_repository / "src" / "Vault.sol").write_text(
        "contract Vault { function changed() external {} }\n",
        encoding="utf-8",
    )
    changed_output = tmp_path / "changed-verification.json"
    changed = runner.invoke(
        app,
        [
            "verify-run",
            "--manifest",
            str(changed_run / "run-evidence-manifest.json"),
            "--run-dir",
            str(changed_run),
            "--repo",
            str(changed_repository),
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--output",
            str(changed_output),
            "--no-color",
        ],
    )
    assert changed.exit_code == ExitCode.INCOMPLETE
    assert (
        RunVerification.model_validate_json(changed_output.read_text(encoding="utf-8")).status
        is RunVerificationStatus.STALE
    )

    missing_repository, missing_run, _, _ = _write_verifiable_run(
        tmp_path / "missing",
        config,
    )
    (missing_run / "scope-assessment.json").unlink()
    missing_output = tmp_path / "missing-verification.json"
    missing = runner.invoke(
        app,
        [
            "verify-run",
            "--manifest",
            str(missing_run / "run-evidence-manifest.json"),
            "--run-dir",
            str(missing_run),
            "--repo",
            str(missing_repository),
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--output",
            str(missing_output),
            "--no-color",
        ],
    )
    assert missing.exit_code == ExitCode.INCOMPLETE
    missing_verification = RunVerification.model_validate_json(
        missing_output.read_text(encoding="utf-8")
    )
    assert any(
        mismatch.identifier == "scope-assessment.json"
        and mismatch.kind is RunVerificationMismatchKind.MISSING
        for mismatch in missing_verification.mismatches
    )


def test_published_run_verification_schema_is_strict_and_bounded() -> None:
    schema = json.loads(
        (
            Path(__file__).resolve().parents[2] / "schemas" / "run_verification.schema.json"
        ).read_text(encoding="utf-8")
    )

    assert schema["additionalProperties"] is False
    assert schema["properties"]["mismatches"]["maxItems"] == 200_000
    assert schema["$defs"]["mismatch"]["additionalProperties"] is False
    assert schema["properties"]["verification_sha256"] == {"$ref": "#/$defs/sha256"}
