from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import cast

import httpx
import pytest
from pydantic import BaseModel, ConfigDict

from mmaudit.config import AuditConfig
from mmaudit.models.openrouter import (
    OpenRouterClient,
    OpenRouterProviderPolicy,
    OpenRouterRequestLimitError,
    StructuredCompletion,
)
from mmaudit.models.schemas import (
    CandidateReviewBatch,
    ContextPackage,
    Location,
    ModelSurfaceReviewArtifact,
    RepositoryMap,
    ScannerFinding,
    Severity,
)
from mmaudit.models.usage import UsageLedger
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.context import (
    ContextBoundaryError,
    ContextBuilder,
    render_context,
    revalidate_context_package,
)
from mmaudit.orchestration.context_manifest import ContextPreflightReason
from mmaudit.orchestration.model_coverage import build_model_review_coverage
from mmaudit.orchestration.model_review_evidence import (
    ModelReviewEvidenceError,
    seal_model_surface_review_artifact,
)
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.repository.mapping import build_repository_map


class _Answer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer: str


def _repository_map() -> RepositoryMap:
    return RepositoryMap(
        root_name="synthetic-context-boundary",
        languages={"Solidity": 1},
        frameworks=[],
        manifests=[],
        entry_points=[],
        api_surfaces=[],
        auth_components=[],
        data_layers=[],
        network_clients=[],
        file_handlers=[],
        configuration_files=[],
        sensitive_processing=[],
        security_tests=[],
        files=[],
        omitted_files=[],
    )


def _scanner_finding(*, metadata: dict[str, object] | None = None) -> ScannerFinding:
    return ScannerFinding(
        scanner="synthetic",
        rule_id="synthetic.metadata",
        title="Synthetic metadata boundary",
        severity=Severity.INFORMATIONAL,
        message="Synthetic local scanner evidence",
        locations=[Location(path="Synthetic.sol", start_line=1, end_line=1)],
        metadata=metadata or {"state": "safe"},
        fingerprint=hashlib.sha256(b"synthetic metadata boundary").hexdigest(),
    )


def _bounded_package() -> ContextPackage:
    package = ContextPackage(
        role="source_audit",
        byte_budget=100_000,
        bytes_used=0,
        configured_maximum_source_tokens_per_request=200_000,
        effective_source_byte_ceiling=0,
        repository_map=_repository_map(),
        scanner_findings=(_scanner_finding(),),
        excerpts=(),
    )
    return package.model_copy(update={"bytes_used": len(render_context(package).encode("utf-8"))})


def _poison_nested_metadata(package: ContextPackage) -> None:
    package.scanner_findings[0].metadata["opaque"] = object()


def test_context_builder_normalizes_opaque_cyclic_and_nonfinite_scanner_metadata(
    vulnerable_repo: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    assert discovery.files
    cycle: list[object] = []
    cycle.append(cycle)
    finding = _scanner_finding(
        metadata={
            "opaque": object(),
            "nonfinite": float("nan"),
            "nested": ("retained", object()),
            "cycle": cycle,
            "oversized_integer": 2**100,
        }
    ).model_copy(
        update={
            "locations": [
                Location(
                    path=discovery.files[0].relative_path,
                    start_line=1,
                    end_line=1,
                )
            ]
        }
    )

    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[finding],
    ).build("source_audit")

    assert package.scanner_findings[0].metadata == {
        "cycle": [None],
        "nested": ["retained", None],
        "nonfinite": None,
        "opaque": None,
        "oversized_integer": None,
    }
    assert revalidate_context_package(package) == package


def test_context_boundary_wraps_opaque_nested_serialization_failure() -> None:
    package = _bounded_package()
    _poison_nested_metadata(package)

    with pytest.raises(
        ContextBoundaryError,
        match="failed detached boundary validation",
    ):
        revalidate_context_package(package)


@pytest.mark.asyncio
async def test_opaque_nested_metadata_fails_provider_preflight_without_transport(
    config_factory: Callable[..., AuditConfig],
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    config = config_factory()
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://synthetic.invalid/api/v1/",
    )
    usage = UsageLedger()
    client = OpenRouterClient(
        api_key="synthetic-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=BudgetManager(
            total_usd=config.execution.budget_usd,
            max_output_tokens=config.execution.max_output_tokens_per_request,
            conservative_usd_per_million_tokens=(
                config.execution.conservative_usd_per_million_tokens
            ),
            max_requests_per_agent=config.execution.max_requests_per_agent,
            global_input_token_budget=config.token_budgets.global_input_token_budget,
            global_output_token_budget=config.token_budgets.global_output_token_budget,
        ),
        usage=usage,
        http_client=http_client,
        provider_policy=OpenRouterProviderPolicy(),
        token_budgets=config.token_budgets,
    )
    package = _bounded_package()
    valid_prompt = render_context(package)
    _poison_nested_metadata(package)
    try:
        with pytest.raises(OpenRouterRequestLimitError, match="bounded context plan"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt=valid_prompt,
                context_package=package,
                response_model=_Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []
    assert client.context_preflight.records[-1].reason is (
        ContextPreflightReason.CONTEXT_PLAN_INVALID
    )


def test_opaque_nested_metadata_cannot_seal_surface_artifact() -> None:
    package = _bounded_package()
    valid_prompt = render_context(package)
    _poison_nested_metadata(package)

    with pytest.raises(ModelReviewEvidenceError, match="exact boundary validation"):
        seal_model_surface_review_artifact(
            context=package,
            completion=cast(StructuredCompletion[CandidateReviewBatch], None),
            rendered_user_context=valid_prompt,
        )


def test_opaque_nested_metadata_cannot_authorize_model_coverage(
    config_factory: Callable[..., AuditConfig],
) -> None:
    package = _bounded_package()
    _poison_nested_metadata(package)
    request_id = "synthetic-invalid-context"
    artifact = ModelSurfaceReviewArtifact.model_construct(
        schema_version="1.0",
        request_id=request_id,
        review_role="source_audit",
        requested_surface_ids=("model-surface:" + "a" * 64,),
        requested_surface_ids_sha256="b" * 64,
        requested_surface_manifest_sha256="c" * 64,
        rendered_context_sha256="d" * 64,
        prompt_sha256="e" * 64,
        response_sha256="f" * 64,
        validated_response_sha256="1" * 64,
        response_schema_sha256="2" * 64,
        records=(),
        artifact_sha256="3" * 64,
    )

    coverage = build_model_review_coverage(
        config_factory(),
        usage_records=[],
        review_artifacts=[artifact],
        review_contexts_by_request={request_id: [package]},
        index=None,
        graphs=None,
        invariants=None,
        economic_simulations=[],
    )

    assert any(
        "used an invalid context package" in limitation for limitation in coverage.limitations
    )
