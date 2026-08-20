from __future__ import annotations

import stat
from collections.abc import Callable
from pathlib import Path

import pytest

from mmaudit.config import AuditConfig
from mmaudit.models.candidate_registry_bridge import (
    derive_candidate_registry_from_discovery,
    validate_candidate_registry_template_selection,
    write_candidate_registry_json,
)
from mmaudit.models.discovery import DiscoveryCandidateRoute
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    CandidateOperationalStatus,
    load_candidate_registry,
    seal_candidate_registry,
)
from mmaudit.privacy import PrivacyProfile
from tests.unit import test_candidate_benchmark as fixtures


def _config(config_factory: Callable[..., AuditConfig]) -> AuditConfig:
    return config_factory(privacy={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK})


def _specs() -> tuple[fixtures._CandidateSpec, ...]:
    return (
        fixtures._CandidateSpec(
            model_id="alpha/atlas-secure",
            provider_endpoint="provider-alpha",
            provider_name="Provider Alpha",
        ),
        fixtures._CandidateSpec(
            model_id="bravo/borealis-secure",
            provider_endpoint="provider-bravo",
            provider_name="Provider Bravo",
        ),
    )


def test_fresh_registry_supports_selected_subset_and_resets_stale_runtime_state(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    _old_manifest, _old_evidence, template = fixtures._discovery_and_registry(
        tmp_path=tmp_path / "template-discovery",
        config=config,
        specs=_specs(),
    )
    selected = template.candidates[0].model_copy(
        update={
            "operational_status": CandidateOperationalStatus.UNAVAILABLE,
            "benchmark_status": CandidateBenchmarkStatus.FAILED,
            "benchmark_artifact_sha256": "f" * 64,
            "approved_roles": ("source_audit",),
        }
    )
    template = seal_candidate_registry(
        created_at=template.created_at,
        discovery_run_sha256=template.discovery_run_sha256,
        candidates=(selected, template.candidates[1]),
    )
    manifest, evidence, _unused_registry = fixtures._discovery_and_registry(
        tmp_path=tmp_path / "fresh-discovery",
        config=config,
        specs=(_specs()[0],),
    )

    registry = derive_candidate_registry_from_discovery(
        template=template,
        run_manifest=manifest,
        evidence=evidence,
    )

    assert tuple(candidate.exact_model_id for candidate in registry.candidates) == (
        "alpha/atlas-secure",
    )
    candidate = registry.candidates[0]
    discovered = evidence[0]
    endpoint = discovered.endpoint_snapshot.endpoint(discovered.approved_provider_endpoint)
    assert registry.discovery_run_sha256 == manifest.manifest_sha256
    assert registry.created_at == manifest.run_provenance.retrieved_at
    assert candidate.lineage_review == selected.lineage_review
    assert candidate.approved_roles == ("source_audit",)
    assert candidate.operational_status is CandidateOperationalStatus.AVAILABLE
    assert candidate.benchmark_status is CandidateBenchmarkStatus.PENDING
    assert candidate.benchmark_artifact_sha256 is None
    assert candidate.qualification_expires_at is None
    assert candidate.canonical_model_slug == discovered.canonical_slug
    assert candidate.output_capability_sha256 == discovered.output_capability_sha256
    assert candidate.max_prompt_tokens == endpoint.max_prompt_tokens
    assert candidate.max_prompt_tokens_source == endpoint.max_prompt_tokens_source
    assert candidate.output_limit_source == endpoint.max_completion_tokens_source
    assert candidate.data_collection_deny_evidence_sha256 == (
        discovered.data_collection_deny_evidence_sha256
    )


@pytest.mark.parametrize(
    ("routes", "message"),
    [
        (
            (
                DiscoveryCandidateRoute(
                    exact_model_id="charlie/cirrus-secure",
                    approved_provider_endpoint="provider-charlie",
                ),
            ),
            "missing a selected exact model ID",
        ),
        (
            (
                DiscoveryCandidateRoute(
                    exact_model_id="alpha/atlas-secure",
                    approved_provider_endpoint="provider-other",
                ),
            ),
            "differs from its operator-approved template endpoint",
        ),
        (
            (
                DiscoveryCandidateRoute(
                    exact_model_id="alpha/atlas-secure",
                    approved_provider_endpoint="provider-alpha",
                ),
                DiscoveryCandidateRoute(
                    exact_model_id="alpha/atlas-secure",
                    approved_provider_endpoint="provider-alpha",
                ),
            ),
            "unique, and sorted",
        ),
    ],
)
def test_template_selection_rejects_missing_duplicate_and_endpoint_drift(
    routes: tuple[DiscoveryCandidateRoute, ...],
    message: str,
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    _manifest, _evidence, template = fixtures._discovery_and_registry(
        tmp_path=tmp_path / "template",
        config=_config(config_factory),
        specs=_specs(),
    )

    with pytest.raises(ValueError, match=message):
        validate_candidate_registry_template_selection(
            template=template,
            routes=routes,
        )


def test_fresh_registry_rejects_extra_or_duplicate_discovery_evidence(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    manifest, evidence, template = fixtures._discovery_and_registry(
        tmp_path=tmp_path / "fresh",
        config=config,
        specs=(_specs()[0],),
    )

    with pytest.raises(ValueError, match="exactly cover unique discovery routes"):
        derive_candidate_registry_from_discovery(
            template=template,
            run_manifest=manifest,
            evidence=(evidence[0], evidence[0]),
        )


def test_candidate_registry_writer_is_private_atomic_and_fresh(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    manifest, evidence, template = fixtures._discovery_and_registry(
        tmp_path=tmp_path / "fresh",
        config=_config(config_factory),
        specs=(_specs()[0],),
    )
    registry = derive_candidate_registry_from_discovery(
        template=template,
        run_manifest=manifest,
        evidence=evidence,
    )
    output = tmp_path / "private" / "fresh-candidate-registry.json"

    written = write_candidate_registry_json(output, registry)

    assert written == registry
    assert load_candidate_registry(output) == registry
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    original = output.read_bytes()
    with pytest.raises(ValueError, match="fresh file"):
        write_candidate_registry_json(output, registry)
    assert output.read_bytes() == original
