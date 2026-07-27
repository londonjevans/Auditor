from __future__ import annotations

from pathlib import Path

from mmaudit.models.schemas import (
    Location,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewRequest,
)
from mmaudit.orchestration.context import ContextBuilder, render_context
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.repository.mapping import build_repository_map


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
