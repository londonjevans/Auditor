from __future__ import annotations

import errno
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

import mmaudit.orchestration.manifest as manifest_module
from mmaudit.cli import app
from mmaudit.config import (
    _AUDIT_OVERRIDE_PATHS,
    _AUDIT_OVERRIDE_VALUE_TYPES,
    AuditConfig,
    AuditConfigOverride,
    AuditConfigOverrides,
    AuditRunOptions,
    LoadedAuditConfig,
)
from mmaudit.constants import ExitCode
from mmaudit.models.qualification import VerifiedProductionQualification
from mmaudit.models.reasoning import (
    ReasoningExecutionEvidence,
    ReasoningRequestPlanEvidence,
    resolve_reasoning_request_role,
)
from mmaudit.models.registry import ModelRegistry
from mmaudit.models.runtime import build_reasoning_policy
from mmaudit.models.schemas import (
    AuditReport,
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    RepositoryDifferentialRunStatus,
    RepositoryFile,
    RepositoryForkRpcPrivacyEvidence,
    RepositoryMap,
    RepositorySuiteDifferentialRun,
    ScannerRun,
    ScannerStatus,
    UsageRecord,
)
from mmaudit.orchestration.manifest import (
    ManifestBindingSet,
    ManifestFileBinding,
    ManifestHashBinding,
    RunConfigurationBinding,
    RunEvidenceManifest,
    _model_bindings,
    _seed_bindings,
    build_run_evidence_manifest,
    canonical_sha256,
    collect_run_artifacts,
    load_run_evidence_manifest,
    open_manifest_bound_json_artifacts,
    rebuild_run_evidence_manifest_for_verification,
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
from tests.identity_fixtures import bind_synthetic_usage_identity, synthetic_token_plan_routing
from tests.output_evidence_fixtures import synthetic_structured_output_routing
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


def _qualified_reasoning_usage(
    config: AuditConfig,
    qualification: VerifiedProductionQualification,
    *,
    observed_at: datetime,
    role: str = "source_audit",
) -> UsageRecord:
    """Build one synthetic request with the complete opaque qualification projection."""

    policy = build_reasoning_policy(config)
    resolution = resolve_reasoning_request_role(role)
    model_id = config.models.role(role).primary
    model = qualification.model_for(model_id, now=observed_at)
    matching_routes = tuple(
        route
        for route in model.reasoning_bindings
        if route.qualified_role == resolution.qualification_role
        and route.configured_policy_role == resolution.configured_policy_role
    )
    assert len(matching_routes) == 1
    route = matching_routes[0]
    reasoning_plan = ReasoningRequestPlanEvidence.build(
        request_role=role,
        policy=policy,
        endpoint_capability_sha256=route.endpoint_reasoning_capability_sha256,
        qualification_binding_sha256=route.binding_sha256,
    )
    request_id = "request-qualified-reasoning-manifest"
    generation_id = "generation-qualified-reasoning-manifest"
    started_at = observed_at
    ended_at = observed_at.replace(second=min(59, observed_at.second + 1))
    prompt_sha256 = "c" * 64
    request_body_sha256 = "d" * 64
    response_sha256 = "e" * 64
    validated_response_sha256 = "f" * 64
    schema_sha256 = "1" * 64
    provider_policy_sha256 = "2" * 64
    observed_reasoning_tokens = 0 if reasoning_plan.control_profile.mode == "disabled" else 1
    routing: dict[str, object] = {
        "generation_id": generation_id,
        "selected_model": model.canonical_model_slug,
        "canonical_model": model.canonical_model_slug,
        "selected_provider_endpoint": model.approved_provider_endpoint,
        "selected_provider_name": model.approved_provider_name,
        "router_strategy": "direct",
        "router_attempt": 1,
        "router_attempt_count": 1,
        "router_pipeline": [],
        "finish_reason": "stop",
        "schema_sha256": schema_sha256,
        "router_metadata_sha256": "3" * 64,
        "provider_policy_sha256": provider_policy_sha256,
        "provider_fallbacks_allowed": False,
        "certification_request": True,
        "endpoint_snapshot_sha256": model.endpoint_snapshot_sha256,
        "output_capability_sha256": model.output_capability_sha256,
        "endpoint_pricing_sha256": model.pricing_snapshot_sha256,
        "model_metadata_snapshot_sha256": model.model_metadata_snapshot_sha256,
        "catalog_identity_binding_sha256": canonical_sha256(
            {
                "canonical_slug": model.canonical_model_slug,
                "id": model.exact_model_id,
            }
        ),
        "catalog_snapshot_sha256": "4" * 64,
        "discovery_provenance_sha256": "5" * 64,
        "discovery_evidence_sha256": "6" * 64,
        "validation_status": "valid",
        "zdr_requested": True,
        "data_collection": "deny",
        "repair_used": False,
        "repair_request": False,
        "request_started_at": started_at.isoformat(),
        "request_ended_at": ended_at.isoformat(),
        "latency_ms": 1_000,
        "structured_output": synthetic_structured_output_routing(
            configured_provider_endpoints=(model.approved_provider_endpoint,),
            selected_provider_endpoint=model.approved_provider_endpoint,
            endpoint_snapshot_sha256=model.endpoint_snapshot_sha256,
            output_capability_sha256=model.output_capability_sha256,
            prompt_sha256=prompt_sha256,
            request_body_sha256=request_body_sha256,
            provider_policy_sha256=provider_policy_sha256,
            schema_sha256=schema_sha256,
            original_response_sha256=response_sha256,
            validated_response_sha256=validated_response_sha256,
            mode=model.structured_output_mode,
            reasoning_requested=reasoning_plan.control_profile.mode != "disabled",
        ),
        "qualified_exact_model_id": model.exact_model_id,
        "qualified_canonical_model_slug": model.canonical_model_slug,
        "qualified_root_lineage": model.root_lineage,
        "qualified_provider_endpoint": model.approved_provider_endpoint,
        "qualified_provider_name": model.approved_provider_name,
        "qualified_endpoint_snapshot_sha256": model.endpoint_snapshot_sha256,
        "qualified_output_capability_sha256": model.output_capability_sha256,
        "qualified_structured_output_mode": model.structured_output_mode.value,
        "qualified_model_metadata_snapshot_sha256": model.model_metadata_snapshot_sha256,
        "qualified_pricing_snapshot_sha256": model.pricing_snapshot_sha256,
        "qualified_roles": list(model.approved_roles),
        "qualification_verified_at": qualification.verified_at.isoformat(),
        "qualification_expires_at": model.expires_at.isoformat(),
        "qualification_artifact_sha256": qualification.artifact_sha256,
        "qualification_verification_sha256": (qualification.qualification_verification_sha256),
        "production_selection_sha256": qualification.production_selection_sha256,
        "selection_verification_sha256": qualification.selection_verification_sha256,
        "qualification_result_sha256": model.qualification_result_sha256,
        "benchmark_report_sha256": model.benchmark_report_sha256,
        "qualified_reasoning_binding_sha256": [
            binding.binding_sha256 for binding in model.reasoning_bindings
        ],
    }
    provisional = UsageRecord(
        request_id=request_id,
        role=role,
        execution_evidence=ExecutionEvidenceKind.REAL,
        requested_model=model.exact_model_id,
        returned_model=model.canonical_model_slug,
        actual_model=model.canonical_model_slug,
        provider=model.approved_provider_name,
        model_family=model.exact_model_id,
        timestamp=observed_at,
        prompt_tokens=10,
        completion_tokens=10,
        total_tokens=20,
        reported_cost_usd=0,
        accounted_cost_usd=0,
        routing=routing,
        prompt_sha256=prompt_sha256,
        response_sha256=response_sha256,
        validated_response_sha256=validated_response_sha256,
        request_body_sha256=request_body_sha256,
        schema_sha256=schema_sha256,
        openrouter_generation_id=generation_id,
        configured_provider_endpoints=[model.approved_provider_endpoint],
        actual_provider_endpoint=model.approved_provider_endpoint,
        started_at=started_at,
        ended_at=ended_at,
        latency_ms=1_000,
        finish_reason="stop",
        retry_count=0,
        validation_status=ModelRequestValidationStatus.VALID,
        status="success",
        attempts=1,
    )
    return bind_synthetic_usage_identity(
        provisional,
        reasoning_plan=reasoning_plan,
        observed_reasoning_tokens=observed_reasoning_tokens,
    )


def _reseal_qualification_validation(payload: dict[str, object]) -> None:
    payload["validation_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "validation_sha256"}
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
        "candidate-findings.json": {
            "schema_version": "1.1",
            "findings": [],
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


def _write_qualified_verifiable_run(
    root: Path,
) -> tuple[
    AuditConfig,
    Path,
    Path,
    RunEvidenceManifest,
    AuditReport,
]:
    config, qualification, observed_at = _verified_production_config_and_capability()
    validation = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        required=True,
        now=observed_at,
    )
    repository = root / "repository"
    source = repository / "src" / "Vault.sol"
    source.parent.mkdir(parents=True)
    source_contents = "contract Vault { function safe() external {} }\n"
    source.write_text(source_contents, encoding="utf-8")
    base_report = _report(config)
    report = base_report.model_copy(
        update={
            "repository": base_report.repository.model_copy(
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
            ),
            "usage": [
                _qualified_reasoning_usage(
                    config,
                    qualification,
                    observed_at=observed_at,
                )
            ],
        }
    )
    run_dir = root / "run"
    _write_required_artifacts(run_dir, report)
    (run_dir / "model-qualification-runtime.json").write_text(
        json.dumps(validation.as_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
        production_qualification=qualification,
    )
    write_run_evidence_manifest(run_dir / "run-evidence-manifest.json", manifest)
    return config, repository, run_dir, manifest, report


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


def test_manifest_reconstructs_per_role_reasoning_policy_bindings(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory(
        models={
            "reasoning": {
                "effort": "low",
                "reserved_tokens": 512,
            },
            "source_audit": {
                "primary": "alpha/atlas-secure",
                "reasoning": {
                    "effort": "high",
                    "reserved_tokens": 2_048,
                },
            },
        }
    )
    run_dir = tmp_path / "reasoning-run"
    report = _report(config)
    _write_required_artifacts(run_dir, report)

    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
    )
    model_bindings = {binding.identifier: binding for binding in manifest.bindings.models}

    assert model_bindings["reasoning/policy"].details["roles"]
    assert model_bindings["reasoning/configured/source_audit"].details == {
        "mode": "effort",
        "effort": "high",
        "max_tokens": "0",
        "reserved_reasoning_tokens": "2048",
        "profile_sha256": model_bindings["reasoning/configured/source_audit"].details[
            "profile_sha256"
        ],
    }
    assert model_bindings["reasoning/configured/judge"].details["effort"] == "low"


def test_manifest_binds_reasoning_execution_and_rejects_effective_policy_drift(
    config_factory,
) -> None:
    config = config_factory(
        models={
            "reasoning": {"effort": "low", "reserved_tokens": 512},
            "source_audit": {
                "primary": "alpha/atlas-secure",
                "reasoning": {"effort": "high", "reserved_tokens": 2_048},
            },
        }
    )
    policy = build_reasoning_policy(config)
    reasoning_plan = ReasoningRequestPlanEvidence.build(
        request_role="source_audit",
        policy=policy,
        endpoint_capability_sha256="a" * 64,
    )
    provisional = UsageRecord(
        request_id="request-reasoning-manifest",
        role="source_audit",
        requested_model="alpha/atlas-secure",
        returned_model="alpha/atlas-secure",
        actual_model="alpha/atlas-secure",
        provider="Synthetic Provider",
        model_family="alpha/atlas-secure",
        timestamp=datetime(2026, 1, 2, tzinfo=UTC),
        prompt_tokens=10,
        completion_tokens=10,
        total_tokens=20,
        accounted_cost_usd=0,
        routing={},
        prompt_sha256="c" * 64,
        request_body_sha256="d" * 64,
        configured_provider_endpoints=["synthetic-provider"],
        actual_provider_endpoint="synthetic-provider",
        status="success",
        attempts=1,
    )
    routing = synthetic_token_plan_routing(
        provisional,
        provisional.routing,
        reasoning_plan=reasoning_plan,
    )
    token_plan_sha256 = routing["request_token_plan_sha256"]
    assert isinstance(token_plan_sha256, str)
    execution = ReasoningExecutionEvidence.build(
        request_plan=reasoning_plan,
        observed_reasoning_tokens=2,
        provider_completion_tokens=10,
        request_token_plan_sha256=token_plan_sha256,
        request_body_sha256="d" * 64,
    )
    usage = UsageRecord.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "routing": routing,
            "reasoning_tokens": 2,
            "reasoning_evidence": execution.model_dump(mode="json"),
        }
    )
    report = _report(config).model_copy(update={"usage": [usage]})

    bindings = {
        binding.identifier: binding
        for binding in _model_bindings(config, report, qualification_runtime=None)
    }

    assert bindings["reasoning/execution/request-reasoning-manifest"].sha256 == (
        execution.evidence_sha256
    )
    assert bindings["reasoning/capability/request-reasoning-manifest"].sha256 == "a" * 64
    assert "reasoning/qualification/request-reasoning-manifest" not in bindings

    changed_config = config_factory(
        models={
            "reasoning": {"effort": "low", "reserved_tokens": 512},
            "source_audit": {
                "primary": "alpha/atlas-secure",
                "reasoning": {"effort": "medium", "reserved_tokens": 1_024},
            },
        }
    )
    changed_report = _report(changed_config).model_copy(update={"usage": [usage]})
    with pytest.raises(ValueError, match="differs from the effective configuration"):
        _model_bindings(
            changed_config,
            changed_report,
            qualification_runtime=None,
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
        production_qualification=qualification,
    )

    model_bindings = {binding.identifier: binding for binding in manifest.bindings.models}
    assert (
        model_bindings["qualification/opaque-authority"].sha256 == qualification.capability_sha256
    )
    assert (
        model_bindings["qualification/runtime-validation"].details["authority"] == "opaque_joined"
    )
    reasoning_route_bindings = [
        binding
        for identifier, binding in model_bindings.items()
        if identifier.startswith("qualification/reasoning-route/")
    ]
    assert len(reasoning_route_bindings) == sum(
        len(model.reasoning_bindings) for model in qualification.models
    )
    assert all(
        binding.details["authority"] == "opaque_joined" for binding in reasoning_route_bindings
    )
    assert {binding.sha256 for binding in reasoning_route_bindings} == {
        route.binding_sha256 for model in qualification.models for route in model.reasoning_bindings
    }
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
    with pytest.raises(
        ValidationError,
        match=r"self-hash|reasoning qualification",
    ):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=config,
            production_qualification=qualification,
        )

    tampered = validation.as_dict()
    tampered["model_bindings"][0]["benchmark_report_sha256"] = "e" * 64
    qualification_path.write_text(
        json.dumps(tampered, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(
        ValidationError,
        match=r"self-hash|reasoning qualification",
    ):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=config,
            production_qualification=qualification,
        )


def test_manifest_requires_opaque_authority_before_granting_reasoning_credit() -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    validation = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        required=True,
        now=observed_at,
    )
    usage = _qualified_reasoning_usage(
        config,
        qualification,
        observed_at=observed_at,
    )
    report = _report(config).model_copy(update={"usage": [usage]})

    projection_only = {
        binding.identifier: binding
        for binding in _model_bindings(
            config,
            _report(config),
            qualification_runtime=validation.as_dict(),
        )
    }
    assert "qualification/opaque-authority" not in projection_only
    assert (
        projection_only["qualification/runtime-validation"].details["authority"]
        == "serialized_projection_only"
    )
    assert all(
        binding.details["authority"] == "serialized_projection_only"
        for identifier, binding in projection_only.items()
        if identifier.startswith("qualification/reasoning-route/")
    )

    with pytest.raises(ValueError, match="opaque production qualification authority"):
        _model_bindings(
            config,
            report,
            qualification_runtime=validation.as_dict(),
        )

    mock_usage = usage.model_copy(update={"execution_evidence": ExecutionEvidenceKind.MOCK})
    with pytest.raises(ValueError, match="creditable real opaque-authority evidence"):
        _model_bindings(
            config,
            _report(config).model_copy(update={"usage": [mock_usage]}),
            qualification_runtime=validation.as_dict(),
            production_qualification=qualification,
        )

    bindings = {
        binding.identifier: binding
        for binding in _model_bindings(
            config,
            report,
            qualification_runtime=validation.as_dict(),
            production_qualification=qualification,
        )
    }

    request_binding = bindings["reasoning/qualification/request-qualified-reasoning-manifest"]
    assert (
        request_binding.sha256 == usage.reasoning_evidence.request_plan.qualification_binding_sha256
    )
    assert request_binding.details["authority"] == "opaque_production_qualification"
    assert (
        request_binding.details["qualification_verification_sha256"]
        == qualification.qualification_verification_sha256
    )
    qualified_route = next(
        route
        for route in qualification.model_for(
            usage.requested_model,
            now=observed_at,
        ).reasoning_bindings
        if route.binding_sha256 == request_binding.sha256
    )
    assert request_binding.details["reasoning_benchmark_report_sha256"] == (
        qualified_route.reasoning_benchmark_report_sha256
    )
    assert request_binding.details["reasoning_benchmark_verification_sha256"] == (
        qualified_route.reasoning_benchmark_verification_sha256
    )
    assert request_binding.details["reasoning_benchmark_fresh_evidence_sha256"] == (
        qualified_route.reasoning_benchmark_fresh_evidence_sha256
    )
    assert bindings["qualification/opaque-authority"].sha256 == qualification.capability_sha256


def test_manifest_rejects_truncated_serialized_reasoning_route_inventory() -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    validation = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        required=True,
        now=observed_at,
    )
    usage = _qualified_reasoning_usage(
        config,
        qualification,
        observed_at=observed_at,
    )
    report = _report(config).model_copy(update={"usage": [usage]})
    payload = validation.as_dict()
    model_bindings = payload["model_bindings"]
    assert isinstance(model_bindings, list)
    reasoning_bindings = model_bindings[0]["reasoning_bindings"]
    assert isinstance(reasoning_bindings, list)
    reasoning_bindings.pop()
    _reseal_qualification_validation(payload)

    with pytest.raises(ValueError, match=r"reasoning.*routes|opaque runtime authority"):
        _model_bindings(
            config,
            report,
            qualification_runtime=payload,
            production_qualification=qualification,
        )


@pytest.mark.parametrize(
    "field",
    [
        "reasoning_policy_artifact_sha256",
        "reasoning_policy_role_binding_sha256",
        "endpoint_reasoning_capability_sha256",
    ],
)
def test_manifest_rejects_resealed_nested_reasoning_authority_tamper(
    field: str,
) -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    validation = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        required=True,
        now=observed_at,
    )
    usage = _qualified_reasoning_usage(
        config,
        qualification,
        observed_at=observed_at,
    )
    report = _report(config).model_copy(update={"usage": [usage]})
    payload = validation.as_dict()
    model_bindings = payload["model_bindings"]
    assert isinstance(model_bindings, list)
    reasoning_bindings = model_bindings[0]["reasoning_bindings"]
    assert isinstance(reasoning_bindings, list)
    route = reasoning_bindings[0]
    assert isinstance(route, dict)
    route[field] = "f" * 64
    route["binding_sha256"] = canonical_sha256(
        {key: value for key, value in route.items() if key != "binding_sha256"}
    )
    _reseal_qualification_validation(payload)

    with pytest.raises(ValueError, match="opaque runtime authority"):
        _model_bindings(
            config,
            report,
            qualification_runtime=payload,
            production_qualification=qualification,
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


def test_manifest_bound_artifacts_propagate_consumer_abort_and_close_descriptors(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ConsumerAbort(BaseException):
        pass

    config = config_factory()
    report = _report(config)
    run_dir = tmp_path / report.run_id
    _write_required_artifacts(run_dir, report)
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
    )
    write_run_evidence_manifest(run_dir / "run-evidence-manifest.json", manifest)

    original_open = os.open
    original_close = os.close
    original_fstat = os.fstat
    opened_descriptors: list[int] = []
    closed_descriptors: list[int] = []
    fstat_descriptors: list[int] = []

    def observed_open(path: os.PathLike[str] | str, flags: int, mode: int = 0o777) -> int:
        descriptor = original_open(path, flags, mode)
        opened_descriptors.append(descriptor)
        return descriptor

    def observed_close(descriptor: int) -> None:
        closed_descriptors.append(descriptor)
        original_close(descriptor)

    def observed_fstat(descriptor: int) -> os.stat_result:
        fstat_descriptors.append(descriptor)
        return original_fstat(descriptor)

    monkeypatch.setattr(manifest_module.os, "open", observed_open)
    monkeypatch.setattr(manifest_module.os, "close", observed_close)
    monkeypatch.setattr(manifest_module.os, "fstat", observed_fstat)

    names = ("metadata.json", "final-findings.json")
    sentinel = ConsumerAbort("synthetic consumer abort")
    with (
        pytest.raises(ConsumerAbort) as raised,
        open_manifest_bound_json_artifacts(run_dir, names) as payloads,
    ):
        assert set(payloads) == set(names)
        raise sentinel

    assert raised.value is sentinel
    assert len(opened_descriptors) == 3
    assert len(set(opened_descriptors)) == 3
    assert closed_descriptors == list(reversed(opened_descriptors))
    assert all(fstat_descriptors.count(descriptor) == 3 for descriptor in opened_descriptors)
    for descriptor in opened_descriptors:
        with pytest.raises(OSError) as closed:
            original_fstat(descriptor)
        assert closed.value.errno == errno.EBADF


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


def test_verify_run_checks_sealed_qualified_evidence_without_recreating_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "mmaudit.orchestration.manifest.validate_report_privacy_consistency",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.manifest._validated_context_manifest",
        lambda *_args, **_kwargs: None,
    )
    config, repository, run_dir, manifest, report = _write_qualified_verifiable_run(tmp_path)
    observed_manifest = rebuild_run_evidence_manifest_for_verification(
        run_dir=run_dir,
        report=report,
        config=config,
        sealed_manifest=manifest,
    )
    assert observed_manifest.bindings.models == manifest.bindings.models
    rebuild_errors: list[Exception] = []

    def capture_rebuild_error(**kwargs):
        try:
            return rebuild_run_evidence_manifest_for_verification(**kwargs)
        except Exception as exc:
            rebuild_errors.append(exc)
            raise

    monkeypatch.setattr(
        "mmaudit.orchestration.verification.rebuild_run_evidence_manifest_for_verification",
        capture_rebuild_error,
    )

    verification = verify_run_evidence(
        manifest_path=run_dir / "run-evidence-manifest.json",
        run_dir=run_dir,
        repository_root=repository,
        config=config,
    )

    assert not rebuild_errors, rebuild_errors
    assert verification.status is RunVerificationStatus.CURRENT, [
        (item.category.value, item.identifier, item.kind.value) for item in verification.mismatches
    ]
    assert not verification.mismatches
    assert verification.manifest_sha256 == manifest.manifest_sha256


@pytest.mark.parametrize(
    "tamper",
    ["usage_projection", "qualification_route", "manifest_authority"],
)
def test_verify_run_rejects_resealed_qualified_evidence_tamper(
    tmp_path: Path,
    tamper: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "mmaudit.orchestration.manifest.validate_report_privacy_consistency",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.manifest._validated_context_manifest",
        lambda *_args, **_kwargs: None,
    )
    config, repository, run_dir, manifest, _ = _write_qualified_verifiable_run(tmp_path)
    manifest_payload = manifest.model_dump(mode="json")

    if tamper == "usage_projection":
        report_path = run_dir / "final-findings.json"
        report_payload = json.loads(report_path.read_text(encoding="utf-8"))
        report_payload["usage"][0]["routing"]["qualified_provider_name"] = "Changed Provider"
        report_path.write_text(
            json.dumps(report_payload, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        artifact_name = report_path.name
    elif tamper == "qualification_route":
        qualification_path = run_dir / "model-qualification-runtime.json"
        qualification_payload = json.loads(qualification_path.read_text(encoding="utf-8"))
        route = qualification_payload["model_bindings"][0]["reasoning_bindings"][0]
        route["reasoning_benchmark_report_sha256"] = "9" * 64
        route["binding_sha256"] = canonical_sha256(
            {key: value for key, value in route.items() if key != "binding_sha256"}
        )
        qualification_payload["validation_sha256"] = canonical_sha256(
            {
                key: value
                for key, value in qualification_payload.items()
                if key != "validation_sha256"
            }
        )
        qualification_path.write_text(
            json.dumps(qualification_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        artifact_name = qualification_path.name
    else:
        opaque = next(
            binding
            for binding in manifest_payload["bindings"]["models"]
            if binding["identifier"] == "qualification/opaque-authority"
        )
        opaque["sha256"] = "8" * 64
        artifact_name = None

    if artifact_name is not None:
        artifact_path = run_dir / artifact_name
        artifact_bytes = artifact_path.read_bytes()
        artifact = next(
            binding for binding in manifest_payload["artifacts"] if binding["path"] == artifact_name
        )
        artifact["sha256"] = hashlib.sha256(artifact_bytes).hexdigest()
        artifact["size"] = len(artifact_bytes)
    manifest_payload["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in manifest_payload.items() if key != "manifest_sha256"}
    )
    write_run_evidence_manifest(
        run_dir / "run-evidence-manifest.json",
        RunEvidenceManifest.model_validate(manifest_payload),
    )

    verification = verify_run_evidence(
        manifest_path=run_dir / "run-evidence-manifest.json",
        run_dir=run_dir,
        repository_root=repository,
        config=config,
    )

    assert verification.status is RunVerificationStatus.STALE
    assert any(
        mismatch.identifier == "bindings/recalculation"
        or mismatch.category is RunVerificationCategory.MODEL
        for mismatch in verification.mismatches
    )


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
