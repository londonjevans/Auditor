"""Synthetic qualification capabilities for runtime integration tests only."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from mmaudit.config import (
    MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_SHA256,
    MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_VERSION,
    MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_SHA256,
    MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_VERSION,
    MAXIMUM_ASSURANCE_QUALIFICATION_POLICY_SHA256,
    AuditConfig,
    model_lineage_index,
)
from mmaudit.constants import ALL_MODEL_ROLES
from mmaudit.models.qualification import (
    _VERIFIED_QUALIFICATION_ISSUER,
    QualificationBindings,
    QualificationDisposition,
    VerifiedProductionQualification,
    VerifiedTierAModelQualification,
    _canonical_json_sha256,
    _verified_production_qualification_payload,
)
from mmaudit.models.qualification_workflow import (
    QualificationReleaseBindings,
    seal_qualification_release_bindings,
)
from mmaudit.models.release_attestation import (
    ReleaseEnvironmentMeasurement,
    TrustedReleaseBindingObservation,
    observe_and_verify_qualification_release,
)
from mmaudit.models.schemas import UsageRecord
from mmaudit.orchestration.manifest import canonical_sha256


def synthetic_release_observation(
    bindings: QualificationBindings | QualificationReleaseBindings,
    *,
    observed_at: datetime,
) -> TrustedReleaseBindingObservation:
    """Issue a test-only opaque observation through the production verifier boundary."""

    release_bindings = (
        bindings
        if type(bindings) is QualificationReleaseBindings
        else seal_qualification_release_bindings(
            source_commit=bindings.source_commit,
            source_tree_sha256=bindings.source_tree_sha256,
            effective_config_sha256=bindings.effective_config_sha256,
            prompt_sha256=bindings.prompt_sha256,
            response_schema_sha256=bindings.response_schema_sha256,
            toolchain_sha256=bindings.toolchain_sha256,
            isolation_sha256=bindings.isolation_sha256,
            benchmark_corpus_version=bindings.benchmark_corpus_version,
            benchmark_ground_truth_version=bindings.benchmark_ground_truth_version,
        )
    )
    payload = {
        "schema_version": "1.0",
        "source_commit": bindings.source_commit,
        "source_tree_sha256": bindings.source_tree_sha256,
        "toolchain_sha256": bindings.toolchain_sha256,
        "isolation_sha256": bindings.isolation_sha256,
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
    }
    measurement = ReleaseEnvironmentMeasurement.model_validate(
        {
            **payload,
            "measurement_sha256": canonical_sha256(payload),
        }
    )
    with (
        patch(
            "mmaudit.models.release_attestation.measure_qualification_release_environment",
            return_value=measurement,
        ),
        patch(
            "mmaudit.models.release_attestation._utc_now",
            return_value=observed_at,
        ),
    ):
        return observe_and_verify_qualification_release(
            release_bindings=release_bindings,
            source_root=Path("/synthetic-release"),
            isolation_backend=object(),
        )


def synthetic_production_qualification(
    config: AuditConfig,
    now: datetime,
    *,
    provider_endpoint: str = "approved-provider",
    provider_name: str | None = None,
) -> VerifiedProductionQualification:
    """Issue bounded synthetic runtime evidence; resolver behavior is tested separately."""

    roles = (
        *ALL_MODEL_ROLES,
        *tuple(sorted(config.models.specialists)),
    )
    model_ids = tuple(sorted({config.models.role(role).primary for role in roles}))
    lineage_by_model = model_lineage_index(config)
    approved_roles = tuple(
        sorted(
            {
                *roles,
                "falsifier",
                "whole_protocol_review",
            }
        )
    )
    expiry = now + timedelta(days=30)
    models: list[VerifiedTierAModelQualification] = []
    for model_id in model_ids:
        configured_lineage = lineage_by_model.get(model_id.lower())
        root_lineage = (
            configured_lineage.root_lineage
            if configured_lineage is not None
            else f"sha256:{hashlib.sha256(f'lineage:{model_id}'.encode()).hexdigest()}"
        )
        model = VerifiedTierAModelQualification(_VERIFIED_QUALIFICATION_ISSUER)
        object.__setattr__(model, "_issuer", _VERIFIED_QUALIFICATION_ISSUER)
        object.__setattr__(model, "exact_model_id", model_id)
        object.__setattr__(model, "canonical_model_slug", model_id)
        object.__setattr__(model, "root_lineage", root_lineage)
        object.__setattr__(model, "approved_provider_endpoint", provider_endpoint)
        object.__setattr__(
            model,
            "approved_provider_name",
            provider_name or provider_endpoint,
        )
        object.__setattr__(
            model,
            "endpoint_snapshot_sha256",
            hashlib.sha256(f"endpoint:{model_id}".encode()).hexdigest(),
        )
        object.__setattr__(
            model,
            "model_metadata_snapshot_sha256",
            hashlib.sha256(f"metadata:{model_id}".encode()).hexdigest(),
        )
        object.__setattr__(
            model,
            "pricing_snapshot_sha256",
            hashlib.sha256(f"pricing:{model_id}".encode()).hexdigest(),
        )
        object.__setattr__(model, "approved_roles", approved_roles)
        object.__setattr__(
            model,
            "qualification_disposition",
            QualificationDisposition.TIER_A,
        )
        object.__setattr__(
            model,
            "overall_score",
            configured_lineage.measured_quality_score if configured_lineage is not None else 1.0,
        )
        object.__setattr__(
            model,
            "quality_measurement_sha256",
            (
                configured_lineage.quality_measurement.removeprefix("sha256:")
                if configured_lineage is not None
                else hashlib.sha256(f"quality:{model_id}".encode()).hexdigest()
            ),
        )
        object.__setattr__(
            model,
            "qualification_result_sha256",
            hashlib.sha256(f"result:{model_id}".encode()).hexdigest(),
        )
        object.__setattr__(
            model,
            "benchmark_report_sha256",
            hashlib.sha256(f"report:{model_id}".encode()).hexdigest(),
        )
        object.__setattr__(
            model,
            "benchmark_verification_sha256",
            hashlib.sha256(f"verification:{model_id}".encode()).hexdigest(),
        )
        object.__setattr__(
            model,
            "fresh_benchmark_evidence_sha256",
            hashlib.sha256(f"fresh-evidence:{model_id}".encode()).hexdigest(),
        )
        object.__setattr__(model, "evaluated_at", now)
        object.__setattr__(model, "expires_at", expiry)
        object.__setattr__(model, "benchmark_case_count", 1)
        models.append(model)

    capability = VerifiedProductionQualification(_VERIFIED_QUALIFICATION_ISSUER)
    object.__setattr__(capability, "_issuer", _VERIFIED_QUALIFICATION_ISSUER)
    bindings = QualificationBindings(
        source_commit="1" * 40,
        source_tree_sha256="2" * 64,
        effective_config_sha256=config.stable_hash(),
        prompt_sha256="3" * 64,
        response_schema_sha256="4" * 64,
        toolchain_sha256="5" * 64,
        isolation_sha256="6" * 64,
        benchmark_corpus_version=MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_VERSION,
        benchmark_corpus_sha256=MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_SHA256,
        benchmark_ground_truth_version=MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_VERSION,
        benchmark_ground_truth_sha256=MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_SHA256,
        benchmark_portfolio_sha256="9" * 64,
        candidate_registry_sha256="c" * 64,
        qualification_policy_sha256=MAXIMUM_ASSURANCE_QUALIFICATION_POLICY_SHA256,
    )
    object.__setattr__(capability, "verified_at", now)
    object.__setattr__(capability, "expires_at", expiry)
    object.__setattr__(capability, "artifact_sha256", "8" * 64)
    object.__setattr__(capability, "qualification_verification_sha256", "9" * 64)
    object.__setattr__(
        capability,
        "production_effective_config_sha256",
        config.stable_hash(),
    )
    object.__setattr__(capability, "production_selection_sha256", "a" * 64)
    object.__setattr__(capability, "selection_verification_sha256", "b" * 64)
    object.__setattr__(capability, "candidate_registry_sha256", "c" * 64)
    object.__setattr__(
        capability,
        "policy_sha256",
        MAXIMUM_ASSURANCE_QUALIFICATION_POLICY_SHA256,
    )
    object.__setattr__(capability, "bindings", bindings)
    object.__setattr__(
        capability,
        "expected_bindings_sha256",
        _canonical_json_sha256(bindings.model_dump(mode="json")),
    )
    object.__setattr__(capability, "release_observation_sha256", "e" * 64)
    object.__setattr__(capability, "models", tuple(models))
    object.__setattr__(
        capability,
        "capability_sha256",
        _canonical_json_sha256(_verified_production_qualification_payload(capability)),
    )
    return capability.require_current(now=now)


def bind_usage_to_qualification(
    record: UsageRecord,
    qualification: VerifiedProductionQualification,
    now: datetime,
) -> UsageRecord:
    """Attach the exact synthetic capability joins used by assurance tests."""

    model = qualification.model_for(record.requested_model, now=now)
    return record.model_copy(
        update={
            "routing": {
                **record.routing,
                "selected_provider_name": model.approved_provider_name,
                "qualification_artifact_sha256": qualification.artifact_sha256,
                "qualification_verification_sha256": (
                    qualification.qualification_verification_sha256
                ),
                "production_selection_sha256": qualification.production_selection_sha256,
                "selection_verification_sha256": qualification.selection_verification_sha256,
                "qualification_result_sha256": model.qualification_result_sha256,
            }
        }
    )
