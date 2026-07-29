from __future__ import annotations

import hashlib

import pytest

from mmaudit.agents.specialists import (
    PreparedReportQualityInput,
    ReportQualityAgent,
)
from mmaudit.models.openrouter import OpenRouterSchemaError
from mmaudit.models.schemas import ContextPackage, RepositoryMap


class _SpyClient:
    def __init__(self) -> None:
        self.calls = 0

    async def complete(self, **_kwargs: object) -> object:
        self.calls += 1
        raise AssertionError("transport must not run for a drifted prepared workflow")


def _context() -> ContextPackage:
    return ContextPackage(
        role="specialist:report_quality",
        byte_budget=1,
        bytes_used=0,
        scanner_findings=[],
        excerpts=[],
        repository_map=RepositoryMap(
            root_name="synthetic-report-quality",
            languages={},
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
        ),
    )


def test_report_quality_workflow_is_prepared_once_with_exact_byte_evidence() -> None:
    prepared = ReportQualityAgent.prepare_input(
        findings=[],
        rejected_count=2,
        coverage=None,
        quality_gates=[],
        incomplete_reasons=["synthetic incomplete analysis"],
    )

    encoded = prepared.workflow_prompt.encode("utf-8")
    assert prepared.workflow_prompt.endswith("</REPORT_QUALITY_INPUT_JSON>\n")
    assert prepared.workflow_byte_upper_bound_tokens == len(encoded)
    assert prepared.workflow_sha256 == hashlib.sha256(encoded).hexdigest()


@pytest.mark.parametrize("field", ["bound", "hash"])
def test_report_quality_workflow_rejects_tampered_preparation(field: str) -> None:
    prepared = PreparedReportQualityInput.build({"synthetic": "report evidence"})

    with pytest.raises(ValueError, match="workflow"):
        PreparedReportQualityInput(
            workflow_prompt=prepared.workflow_prompt,
            workflow_byte_upper_bound_tokens=(
                prepared.workflow_byte_upper_bound_tokens + (1 if field == "bound" else 0)
            ),
            workflow_sha256=("0" * 64 if field == "hash" else prepared.workflow_sha256),
        )


@pytest.mark.asyncio
async def test_report_quality_rejects_valid_but_drifted_preparation_before_transport(
    config_factory,
) -> None:
    config = config_factory(
        models={
            "specialists": {
                "report_quality": {
                    "primary": "alpha/atlas-secure",
                    "fallbacks": [],
                }
            }
        }
    )
    prepared = ReportQualityAgent.prepare_input(
        findings=[],
        rejected_count=0,
        coverage=None,
        quality_gates=[],
        incomplete_reasons=["different evidence"],
    )
    client = _SpyClient()
    agent = ReportQualityAgent(config, client)  # type: ignore[arg-type]

    with pytest.raises(OpenRouterSchemaError, match="differs from the reviewed evidence"):
        await agent.run(
            findings=[],
            rejected_count=0,
            coverage=None,
            quality_gates=[],
            incomplete_reasons=["current evidence"],
            context=_context(),
            prepared_input=prepared,
        )

    assert client.calls == 0
