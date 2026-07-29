from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from mmaudit.cli import app
from mmaudit.config import (
    _AUDIT_OVERRIDE_PATHS,
    _AUDIT_OVERRIDE_VALUE_TYPES,
    AuditConfigOverride,
    AuditConfigOverrides,
    AuditRunOptions,
    LoadedAuditConfig,
)
from mmaudit.constants import ExitCode
from mmaudit.models.registry import ModelRegistry
from mmaudit.models.schemas import (
    AuditReport,
    RepositoryDifferentialRunStatus,
    RepositoryFile,
    RepositoryForkRpcPrivacyEvidence,
    RepositoryMap,
    RepositorySuiteDifferentialRun,
    ScannerRun,
    ScannerStatus,
)
from mmaudit.orchestration.manifest import (
    ManifestBindingSet,
    ManifestFileBinding,
    ManifestHashBinding,
    RunConfigurationBinding,
    RunEvidenceManifest,
    _seed_bindings,
    build_run_evidence_manifest,
    canonical_sha256,
    collect_run_artifacts,
    load_run_evidence_manifest,
    seal_run_evidence_manifest,
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
    empty_overrides = AuditConfigOverrides()
    run_options = AuditRunOptions()
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
        metadata={
            "run_options": run_options.model_dump(mode="json"),
            "configuration_provenance": {
                "file_config_sha256": config.stable_hash(),
                "environment_overrides_sha256": empty_overrides.stable_hash(),
                "cli_overrides_sha256": empty_overrides.stable_hash(),
                "run_options_sha256": run_options.stable_hash(),
            },
        },
    )


def _write_required_artifacts(run_dir: Path, report: AuditReport) -> None:
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
        "scanner-results.json": {
            "schema_version": "1.0",
            "runs": [run.model_dump(mode="json") for run in report.scanner_runs],
        },
    }
    run_dir.mkdir()
    for name, payload in payloads.items():
        (run_dir / name).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if report.repository_suite_differential is not None:
        (run_dir / "repository-suite-differential.json").write_text(
            report.repository_suite_differential.model_dump_json(),
            encoding="utf-8",
        )
        (run_dir / "privacy-fork-rpc-egress.json").write_text(
            json.dumps(report.privacy["fork_rpc_egress"], indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    (run_dir / "metadata.json").write_text(
        json.dumps(
            {
                "schema_version": report.schema_version,
                "run_id": report.run_id,
                "generated_at": report.generated_at.isoformat(),
                "completed": report.completed,
                "incomplete_reasons": report.incomplete_reasons,
                "configuration_hash": report.configuration_hash,
                "model_configuration_hash": report.model_configuration_hash,
                "privacy": report.privacy,
                "repository_suite_differential": (
                    report.repository_suite_differential.model_dump(mode="json")
                    if report.repository_suite_differential is not None
                    else None
                ),
                "metadata": report.metadata,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (run_dir / "final-findings.json").write_text(
        report.model_dump_json(),
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
    _write_required_artifacts(run_dir, report)
    (run_dir / "metadata.json").write_text(
        json.dumps(
            {
                "schema_version": report.schema_version,
                "run_id": report.run_id,
                "generated_at": report.generated_at.isoformat(),
                "completed": report.completed,
                "incomplete_reasons": report.incomplete_reasons,
                "configuration_hash": report.configuration_hash,
                "model_configuration_hash": report.model_configuration_hash,
                "privacy": report.privacy,
                "metadata": report.metadata,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
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
    report = _report(config)
    _write_required_artifacts(first_run, report)
    _write_required_artifacts(second_run, report)

    first = build_run_evidence_manifest(
        run_dir=first_run,
        report=report,
        config=config,
    )
    second = build_run_evidence_manifest(
        run_dir=second_run,
        report=report,
        config=config,
    )

    assert first.model_dump_json() == second.model_dump_json()
    assert first.manifest_sha256 == second.manifest_sha256
    assert first.source_tree_sha256
    assert first.schema_version == "1.1"
    assert first.run_configuration is not None
    assert first.run_configuration.requested_profile.value == "standard"
    assert first.run_configuration.achieved_profile is not None
    assert first.run_configuration.effective_config_sha256 == config.stable_hash()
    assert first.run_configuration.model_config_sha256 == config.model_hash()
    assert set(ManifestBindingSet.model_fields) == {
        name for name, bindings in first.bindings if bindings
    }
    assert any(binding.identifier.startswith("seed/") for binding in first.bindings.seeds)
    assert {binding.path for binding in first.artifacts} == {
        path.name for path in first_run.iterdir()
    }


def test_manifest_seed_bindings_include_repository_suite_fuzz_seed() -> None:
    fuzz_seed = "0x" + "ab" * 32

    bindings = _seed_bindings(
        {
            "runs": [
                {
                    "repository_suite_execution_policy": {
                        "fuzz_seed": fuzz_seed,
                    }
                }
            ]
        }
    )

    assert any(
        binding.details.get("value") == fuzz_seed
        and binding.details.get("field", "").endswith("/fuzz_seed")
        for binding in bindings
    )


def test_manifest_rejects_scanner_results_that_differ_from_report(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    run_dir = tmp_path / "run"
    report = _report(config)
    now = datetime(2026, 1, 2, tzinfo=UTC)
    scanner_run = ScannerRun(
        scanner="synthetic",
        status=ScannerStatus.SKIPPED,
        started_at=now,
        finished_at=now,
        duration_seconds=0,
        error="disabled in synthetic manifest test",
    )
    report = AuditReport.model_validate(
        {
            **report.model_dump(mode="json"),
            "scanner_runs": [scanner_run.model_dump(mode="json")],
        }
    )
    _write_required_artifacts(run_dir, report)
    (run_dir / "scanner-results.json").write_text(
        json.dumps({"schema_version": "1.0", "runs": []}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"scanner-results\.json"):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=config,
        )


def test_manifest_binds_differential_and_fork_rpc_privacy_artifacts(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory(
        smart_contracts={
            "repository_suite": {
                "fork_matrix_states": [
                    {
                        "state_id": "clean-local",
                        "kind": "clean_local",
                        "expected_chain_id": 31_337,
                        "anvil_executable_env": "MMAUDIT_ANVIL_EXECUTABLE",
                        "anvil_version": "anvil Version: 1.3.2-stable",
                        "anvil_sha256": "a" * 64,
                        "hardfork": "cancun",
                        "genesis_timestamp": 1,
                        "startup_timeout_seconds": 5,
                        "shutdown_timeout_seconds": 5,
                    },
                    {
                        "state_id": "pinned-state",
                        "kind": "pinned_fork",
                        "rpc_url_env": "MMAUDIT_PINNED_FORK_RPC_URL",
                        "expected_chain_id": 1,
                        "pinned_block_number": 20_000_000,
                        "state_source_sha256": "b" * 64,
                    },
                ],
                "fork_matrix_repetitions": 2,
            }
        }
    )
    differential = RepositorySuiteDifferentialRun.sealed(
        status=RepositoryDifferentialRunStatus.FAILED,
        configuration_sha256=config.smart_contracts.repository_suite.stable_hash(),
        requested_state_ids=("clean-local", "pinned-state"),
        required_repetitions=2,
        matrix=None,
        limitations=("The configured local execution state was unavailable.",),
    )
    privacy = RepositoryForkRpcPrivacyEvidence.from_differential(differential)
    report_payload = _report(config).model_dump(mode="python")
    report_payload["repository_suite_differential"] = differential
    report_payload["privacy"] = {
        **report_payload["privacy"],
        "fork_rpc_egress": privacy.model_dump(mode="json"),
    }
    report = AuditReport.model_validate(report_payload)
    run_dir = tmp_path / "run"
    _write_required_artifacts(run_dir, report)

    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
    )

    artifact_names = {artifact.path for artifact in manifest.artifacts}
    assert "repository-suite-differential.json" in artifact_names
    assert "privacy-fork-rpc-egress.json" in artifact_names

    (run_dir / "privacy-fork-rpc-egress.json").write_text(
        json.dumps(
            {
                **privacy.model_dump(mode="json"),
                "differential_result_sha256": "f" * 64,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="privacy-fork-rpc-egress"):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=config,
        )


def test_manifest_self_hash_and_artifact_hashes_reject_tampering(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    run_dir = tmp_path / "run"
    report = _report(config)
    _write_required_artifacts(run_dir, report)
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
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


def test_manifest_rejects_resealed_metadata_privacy_disagreement(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    _repository, run_dir, manifest, report = _write_verifiable_run(tmp_path, config)
    metadata_path = run_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["privacy"] = {
        **metadata["privacy"],
        "code_egress_enabled": not metadata["privacy"]["code_egress_enabled"],
    }
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"metadata\.json privacy"):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=config,
        )

    assert manifest.run_configuration is not None
    resealed = seal_run_evidence_manifest(
        run_id=manifest.run_id,
        repository_root_name=manifest.repository_root_name,
        git_commit=manifest.git_commit,
        sources=manifest.sources,
        run_configuration=manifest.run_configuration,
        bindings=manifest.bindings,
        artifacts=collect_run_artifacts(run_dir),
        tool_version=manifest.tool_version,
    )
    with pytest.raises(ValueError, match=r"metadata\.json privacy"):
        validate_manifest_artifacts(resealed, run_dir)


def test_manifest_provenance_hashes_fail_closed_and_v1_0_remains_readable(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    run_dir = tmp_path / "run"
    report = _report(config)
    _write_required_artifacts(run_dir, report)
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
    )

    tampered = manifest.model_dump(mode="json")
    tampered["run_configuration"]["cli_overrides_sha256"] = "0" * 64
    tampered["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in tampered.items() if key != "manifest_sha256"}
    )
    with pytest.raises(ValidationError, match="CLI-override hash"):
        RunEvidenceManifest.model_validate(tampered)

    missing_provenance = manifest.model_dump(mode="json")
    missing_provenance.pop("run_configuration")
    missing_provenance["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in missing_provenance.items() if key != "manifest_sha256"}
    )
    with pytest.raises(ValidationError, match=r"1\.1 requires"):
        RunEvidenceManifest.model_validate(missing_provenance)

    legacy = manifest.model_dump(mode="json")
    legacy["schema_version"] = "1.0"
    legacy.pop("run_configuration")
    legacy["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in legacy.items() if key != "manifest_sha256"}
    )
    parsed_legacy = RunEvidenceManifest.model_validate(legacy)
    assert parsed_legacy.schema_version == "1.0"
    assert parsed_legacy.run_configuration is None

    legacy_with_provenance = manifest.model_dump(mode="json")
    legacy_with_provenance["schema_version"] = "1.0"
    legacy_with_provenance["manifest_sha256"] = canonical_sha256(
        {
            key: value
            for key, value in legacy_with_provenance.items()
            if key not in {"manifest_sha256", "run_configuration"}
        }
    )
    with pytest.raises(ValidationError, match=r"1\.1 requires"):
        RunEvidenceManifest.model_validate(legacy_with_provenance)


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
    report = _report(config)
    _write_required_artifacts(run_dir, report)
    qualification_path = run_dir / "model-qualification-runtime.json"
    qualification_path.write_text(
        json.dumps(validation.as_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
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
        "output-capability": "output_capability_sha256",
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
        assert {binding.details["structured_output_mode"] for binding in qualified_bindings} == {
            model.structured_output_mode.value for model in qualification.models
        }

    tampered = validation.as_dict()
    tampered["qualification_artifact_sha256"] = "f" * 64
    qualification_path.write_text(
        json.dumps(tampered, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError, match="self-hash"):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
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
            report=report,
            config=config,
        )


def test_manifest_rejects_linked_artifacts(
    tmp_path: Path,
    config_factory,
) -> None:
    run_dir = tmp_path / "run"
    config = config_factory()
    report = _report(config)
    _write_required_artifacts(run_dir, report)
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    try:
        (run_dir / "linked.json").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")

    with pytest.raises(ValueError, match="links"):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=config,
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
    assert schema["properties"]["schema_version"]["enum"] == ["1.0", "1.1"]
    expected_profiles = {"quick", "standard", "deep", "maximum-assurance"}
    assert (
        set(schema["$defs"]["runConfiguration"]["properties"]["requested_profile"]["enum"])
        == expected_profiles
    )
    achieved_profile = schema["$defs"]["runConfiguration"]["properties"]["achieved_profile"]
    assert set(achieved_profile["anyOf"][0]["enum"]) == expected_profiles
    assert schema["$defs"]["runConfiguration"]["additionalProperties"] is False
    assert set(schema["$defs"]["runConfiguration"]["required"]) == set(
        RunConfigurationBinding.model_fields
    )
    assert schema["$defs"]["auditConfigOverride"]["additionalProperties"] is False
    assert schema["$defs"]["auditConfigOverrides"]["additionalProperties"] is False
    assert schema["$defs"]["auditRunOptions"]["additionalProperties"] is False
    assert set(schema["$defs"]["auditConfigOverride"]["required"]) == set(
        AuditConfigOverride.model_fields
    )
    assert set(schema["$defs"]["auditConfigOverrides"]["required"]) == set(
        AuditConfigOverrides.model_fields
    )
    assert set(schema["$defs"]["auditRunOptions"]["required"]) == set(AuditRunOptions.model_fields)
    assert set(schema["$defs"]["auditConfigOverride"]["properties"]["path"]["enum"]) == set(
        _AUDIT_OVERRIDE_PATHS
    )
    assert schema["$defs"]["auditConfigOverrides"]["properties"]["entries"]["maxItems"] == len(
        _AUDIT_OVERRIDE_PATHS
    )
    override_variants = schema["$defs"]["auditConfigOverride"]["oneOf"]
    schema_paths_by_type = {
        variant["properties"]["value"]["type"]: set(variant["properties"]["path"]["enum"])
        for variant in override_variants
    }
    expected_paths_by_type = {
        "boolean": {
            path
            for path, value_types in _AUDIT_OVERRIDE_VALUE_TYPES.items()
            if value_types == (bool,)
        },
        "integer": {
            path
            for path, value_types in _AUDIT_OVERRIDE_VALUE_TYPES.items()
            if value_types == (int,)
        },
        "number": {
            path
            for path, value_types in _AUDIT_OVERRIDE_VALUE_TYPES.items()
            if value_types == (float,)
        },
        "string": {
            path
            for path, value_types in _AUDIT_OVERRIDE_VALUE_TYPES.items()
            if value_types == (str,)
        },
    }
    assert schema_paths_by_type == expected_paths_by_type
    assert set().union(*schema_paths_by_type.values()) == set(_AUDIT_OVERRIDE_PATHS)
    serialized_schema = json.dumps(schema, sort_keys=True)
    assert "OPENROUTER_API_KEY" not in serialized_schema
    assert "MMAUDIT_SECRETS_ENV_FILE" not in serialized_schema

    compatibility = schema["allOf"]
    legacy_rule = next(
        rule
        for rule in compatibility
        if rule["if"]["properties"]["schema_version"]["const"] == "1.0"
    )
    current_rule = next(
        rule
        for rule in compatibility
        if rule["if"]["properties"]["schema_version"]["const"] == "1.1"
    )
    assert legacy_rule["then"]["properties"]["run_configuration"] == {"type": "null"}
    assert "run_configuration" in current_rule["then"]["required"]
    assert current_rule["then"]["properties"]["run_configuration"] == {
        "$ref": "#/$defs/runConfiguration"
    }


def test_manifest_loader_rejects_duplicate_json_keys(tmp_path: Path, config_factory) -> None:
    run_dir = tmp_path / "run"
    config = config_factory()
    report = _report(config)
    _write_required_artifacts(run_dir, report)
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
    )
    path = run_dir / "run-evidence-manifest.json"
    write_run_evidence_manifest(path, manifest)
    duplicate = path.read_text(encoding="utf-8").replace(
        "{",
        '{"schema_version":"1.1",',
        1,
    )
    path.write_text(duplicate, encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate keys"):
        load_run_evidence_manifest(path)


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


def test_verify_run_rejects_report_configuration_identity_resealed_into_manifest(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    repository, run_dir, manifest, report = _write_verifiable_run(tmp_path, config)
    tampered_report = report.model_copy(
        update={
            "configuration_hash": "d" * 64,
            "model_configuration_hash": "e" * 64,
        }
    )
    report_bytes = tampered_report.model_dump_json().encode("utf-8")
    (run_dir / "final-findings.json").write_bytes(report_bytes)

    resealed = manifest.model_dump(mode="json")
    for artifact in resealed["artifacts"]:
        if artifact["path"] == "final-findings.json":
            artifact["sha256"] = hashlib.sha256(report_bytes).hexdigest()
            artifact["size"] = len(report_bytes)
    resealed["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in resealed.items() if key != "manifest_sha256"}
    )
    write_run_evidence_manifest(
        run_dir / "run-evidence-manifest.json",
        RunEvidenceManifest.model_validate(resealed),
    )

    verification = verify_run_evidence(
        manifest_path=run_dir / "run-evidence-manifest.json",
        run_dir=run_dir,
        repository_root=repository,
    )

    assert verification.status is RunVerificationStatus.STALE
    assert {
        mismatch.identifier
        for mismatch in verification.mismatches
        if mismatch.category is RunVerificationCategory.CONFIGURATION
    } >= {
        "report/configuration-hash",
        "report/model-configuration-hash",
    }


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
    monkeypatch.setattr(
        "mmaudit.cli.load_config_with_provenance",
        lambda _path, **_kwargs: LoadedAuditConfig(
            file_config=config,
            environment_overrides=AuditConfigOverrides(),
            effective_config=config,
        ),
    )

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
