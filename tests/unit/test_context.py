from __future__ import annotations

from pathlib import Path

from mmaudit.agents.specialists import specialist_context_budget
from mmaudit.models.schemas import (
    ContextPackage,
    Location,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewRequest,
)
from mmaudit.orchestration.context import (
    ContextBuilder,
    context_category_byte_counts,
    context_category_measurements,
    render_context,
)
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.repository.mapping import build_repository_map


def test_specialist_context_budget_is_independent_of_unrelated_peer_roles() -> None:
    """Adding unrelated model roles must not reduce one endpoint-bound review budget."""

    few_roles = specialist_context_budget(
        "access_control",
        total_context_bytes=2_000_000,
        planned_packages=7,
    )
    many_roles = specialist_context_budget(
        "access_control",
        total_context_bytes=2_000_000,
        planned_packages=31,
    )

    assert few_roles == many_roles


def test_context_builder_package_is_independent_of_unrelated_peer_roles(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(
        repository={"max_total_context_bytes": 200_000},
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    repository_map = build_repository_map(discovery)

    def build(planned_packages: int) -> ContextPackage:
        return ContextBuilder(
            discovery=discovery,
            repository_map=repository_map,
            repository_config=config.repository,
            privacy=config.privacy,
            scanner_findings=[],
            planned_packages=planned_packages,
        ).build("source_audit")

    few_roles = build(7)
    many_roles = build(31)

    assert few_roles.byte_budget == many_roles.byte_budget == 200_000
    assert few_roles.bytes_used == many_roles.bytes_used
    assert render_context(few_roles) == render_context(many_roles)


def test_context_builder_uses_source_token_ceiling_instead_of_global_role_share(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(
        repository={"max_total_context_bytes": 2_000_000},
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
        maximum_source_tokens_per_request=50_000,
    ).build("source_audit")

    assert package.byte_budget == 50_000
    assert package.bytes_used <= package.byte_budget


def test_context_builder_accounts_for_trusted_surface_request_manifest(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(
        repository={"max_total_context_bytes": 200_000},
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    repository_map = build_repository_map(discovery)
    subject_id = "entity:synthetic-entry-point"
    request = ModelSurfaceReviewRequest(
        surface_id=ModelSurfaceReviewRequest.calculate_surface_id(
            ModelReviewSurfaceKind.ENTRY_POINT,
            subject_id,
        ),
        kind=ModelReviewSurfaceKind.ENTRY_POINT,
        subject_id=subject_id,
        contract="SyntheticApplication",
        function_or_state_surface="synthetic_entry_point",
        critical=True,
        allowed_locations=(Location(path="app.py", start_line=1, end_line=1),),
        allowed_symbols=("synthetic_entry_point",),
        invariant_considered="Only an authorized identity may reach the protected state transition.",
    )
    builder = ContextBuilder(
        discovery=discovery,
        repository_map=repository_map,
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    )

    package = builder.build(
        "source_audit",
        requested_model_surfaces=[request],
    )
    rendered = render_context(package)

    assert package.requested_model_surfaces == [request]
    assert package.bytes_used == len(rendered.encode())
    assert "<TRUSTED_MODEL_SURFACE_REQUESTS_JSON>" in rendered
    assert "</TRUSTED_MODEL_SURFACE_REQUESTS_JSON>" in rendered
    assert request.surface_id in rendered
    assert request.invariant_considered in rendered

    categories = context_category_byte_counts(package)
    assert sum(categories.values()) == package.bytes_used
    assert categories["source"] > 0
    assert categories["metadata"] > 0
    assert categories["prior_audit"] == 0

    measurements = context_category_measurements(package)
    assert set(measurements) == set(categories)
    assert {
        category: measurement.utf8_bytes for category, measurement in measurements.items()
    } == categories
    assert all(len(measurement.content_sha256) == 64 for measurement in measurements.values())
