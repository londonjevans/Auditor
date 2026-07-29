from __future__ import annotations

import json
from pathlib import Path

import pytest

from mmaudit.agents.specialists import specialist_context_budget
from mmaudit.models.schemas import (
    ContextPackage,
    Location,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewRequest,
)
from mmaudit.orchestration.context import (
    ContextBudgetError,
    ContextBuilder,
    context_category_byte_counts,
    context_category_measurements,
    context_json_escape_overhead_tokens,
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


def test_context_builder_separates_source_ceiling_from_total_package_budget(
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

    categories = context_category_byte_counts(package)
    assert package.byte_budget == 2_000_000
    assert package.bytes_used <= package.byte_budget
    assert (categories["source"] + 2) // 3 <= 50_000


def test_context_metadata_does_not_consume_explicit_source_token_budget(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(
        repository={"max_total_context_bytes": 100_000},
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
        maximum_source_tokens_per_request=8_192,
    ).build("source_audit", requested_budget=100_000)

    categories = context_category_byte_counts(package)
    assert package.byte_budget == 100_000
    assert package.bytes_used <= package.byte_budget
    assert 0 < (categories["source"] + 2) // 3 <= 8_192
    assert categories["metadata"] > 0


def test_context_builder_never_exceeds_cumulative_source_token_ceiling(
    tmp_path: Path,
    config_factory,
) -> None:
    repository = tmp_path / "many-small-logical-blocks"
    source_path = repository / "src" / "many_blocks.py"
    source_path.parent.mkdir(parents=True)
    source_path.write_text(
        "\n\n".join(
            (f"def bounded_surface_{index}() -> str:\n    return {'x' * 700!r}\n")
            for index in range(12)
        ),
        encoding="utf-8",
    )
    config = config_factory(
        repository={
            "max_file_bytes": 20_000,
            "max_total_context_bytes": 100_000,
        },
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(repository, config.repository, IgnoreMatcher())

    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
        maximum_source_tokens_per_request=1_000,
    ).build("source_audit")

    source_bytes = sum(len(excerpt.content.encode("utf-8")) for excerpt in package.excerpts)
    assert 0 < source_bytes <= 3_000


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


def test_context_json_escape_overhead_matches_provider_visible_string_encoding(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    ).build("source_audit")

    rendered = render_context(package)
    raw_bytes = len(rendered.encode("utf-8"))
    escaped_bytes = (
        len(
            json.dumps(
                rendered,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        - 2
    )

    assert context_json_escape_overhead_tokens(package) == escaped_bytes - raw_bytes
    assert escaped_bytes > raw_bytes


def test_model_surface_context_rejects_zero_source_before_transport(
    tmp_path: Path,
    config_factory,
) -> None:
    repository = tmp_path / "oversized-logical-block"
    source_path = repository / "SyntheticVault.sol"
    repository.mkdir()
    source_path.write_text(
        f'contract SyntheticVault {{\n    string internal constant PAD = "{"x" * 75_000}";\n}}\n',
        encoding="utf-8",
    )
    config = config_factory(
        repository={
            "max_file_bytes": 100_000,
            "max_total_context_bytes": 100_000,
        },
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(repository, config.repository, IgnoreMatcher())
    subject_id = "entity:oversized-synthetic-vault"
    request = ModelSurfaceReviewRequest(
        surface_id=ModelSurfaceReviewRequest.calculate_surface_id(
            ModelReviewSurfaceKind.ENTRY_POINT,
            subject_id,
        ),
        kind=ModelReviewSurfaceKind.ENTRY_POINT,
        subject_id=subject_id,
        contract="SyntheticVault",
        function_or_state_surface="PAD",
        critical=True,
        allowed_locations=(Location(path="SyntheticVault.sol", start_line=1, end_line=3),),
        allowed_symbols=("PAD",),
        invariant_considered="The supplied source must be present before review credit.",
    )

    with pytest.raises(ContextBudgetError, match="omitted all source evidence"):
        ContextBuilder(
            discovery=discovery,
            repository_map=build_repository_map(discovery),
            repository_config=config.repository,
            privacy=config.privacy,
            scanner_findings=[],
        ).build(
            "source_audit",
            requested_model_surfaces=[request],
        )
