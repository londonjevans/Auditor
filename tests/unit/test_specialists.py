from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

import mmaudit.agents.specialists as specialists_module
import mmaudit.orchestration.pipeline as pipeline_module
from mmaudit.agents.specialists import (
    SPECIALIST_ROLE_REGISTRY,
    PreparedReportQualityInput,
    ReportQualityAgent,
    build_specialist_execution_records,
    canonical_specialist_role,
    completed_specialist_roles,
    specialist_context_budget,
)
from mmaudit.models.openrouter import OpenRouterSchemaError
from mmaudit.models.schemas import (
    CandidateFinding,
    ContextExcerpt,
    ContextExecutionEvidence,
    ContextPackage,
    ContextRequestEvidence,
    ExecutionEvidenceKind,
    Location,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewRequest,
    RepositoryMap,
    SpecialistAcceptedOutcome,
    SpecialistAcceptedOutcomeKind,
    SpecialistExecutionRecord,
    SpecialistExecutionStatus,
    UsageRecord,
)
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.pipeline import (
    _candidate_origin_context_hashes,
    _exact_completed_usage,
    _register_candidate_origin_packages,
)
from mmaudit.repository.locations import validate_candidate


class _SpyClient:
    def __init__(self) -> None:
        self.calls = 0

    async def complete(self, **_kwargs: object) -> object:
        self.calls += 1
        raise AssertionError("transport must not run for a drifted prepared workflow")


def _context(
    *,
    role: str = "specialist:report_quality",
    byte_budget: int = 10_000,
    source: str | None = None,
    path: str = "Synthetic.sol",
    requested_model_surfaces: tuple[ModelSurfaceReviewRequest, ...] = (),
) -> ContextPackage:
    source_bytes = len(source.encode("utf-8")) if source is not None else 0
    package = ContextPackage(
        role=role,
        byte_budget=byte_budget,
        bytes_used=0,
        configured_maximum_source_tokens_per_request=200_000,
        effective_source_byte_ceiling=source_bytes,
        scanner_findings=[],
        requested_model_surfaces=requested_model_surfaces,
        excerpts=(
            [
                ContextExcerpt(
                    path=path,
                    start_line=1,
                    end_line=1,
                    content_hash=hashlib.sha256(source.encode("utf-8")).hexdigest(),
                    content=source,
                )
            ]
            if source is not None
            else []
        ),
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
    return package.model_copy(update={"bytes_used": len(render_context(package).encode("utf-8"))})


def _usage(
    *,
    request_id: str,
    role: str,
    context: ContextPackage,
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.REAL,
) -> UsageRecord:
    rendered = render_context(context).encode("utf-8")
    context_evidence = ContextRequestEvidence.build(
        request_id=request_id,
        request_role=role,
        context_role=context.role,
        byte_budget=context.byte_budget,
        declared_bytes_used=context.bytes_used,
        rendered_bytes=len(rendered),
        source_bytes=sum(len(excerpt.content.encode("utf-8")) for excerpt in context.excerpts),
        configured_maximum_source_tokens_per_request=(
            context.configured_maximum_source_tokens_per_request
        ),
        effective_source_byte_ceiling=context.effective_source_byte_ceiling,
        rendered_sha256=hashlib.sha256(rendered).hexdigest(),
    )
    return UsageRecord(
        request_id=request_id,
        role=role,
        execution_evidence=execution_evidence,
        requested_model="alpha/atlas-secure",
        model_family="alpha",
        timestamp=datetime(2026, 7, 30, tzinfo=UTC),
        validated_response_sha256="a" * 64,
        routing={
            "context_request_evidence": context_evidence.model_dump(mode="json"),
            "context_request_evidence_sha256": context_evidence.evidence_sha256,
        },
        prompt_sha256="b" * 64,
        status="success",
        attempts=1,
    )


def _accepted(
    usage: UsageRecord,
    *,
    specialist_role: str = "access_control",
    outcome_kind: SpecialistAcceptedOutcomeKind = (SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW),
    requested_surface_count: int = 1,
    surface_review_artifact_sha256: str | None = "c" * 64,
) -> SpecialistAcceptedOutcome:
    context_evidence_sha256 = usage.routing["context_request_evidence_sha256"]
    assert isinstance(context_evidence_sha256, str)
    assert usage.validated_response_sha256 is not None
    return SpecialistAcceptedOutcome.build(
        request_id=usage.request_id,
        specialist_role=specialist_role,
        request_role=usage.role,
        outcome_kind=outcome_kind,
        validated_response_sha256=usage.validated_response_sha256,
        context_request_evidence_sha256=context_evidence_sha256,
        requested_surface_count=requested_surface_count,
        surface_review_artifact_sha256=surface_review_artifact_sha256,
    )


def _surface_request() -> ModelSurfaceReviewRequest:
    subject_id = "entity:synthetic"
    return ModelSurfaceReviewRequest(
        surface_id=ModelSurfaceReviewRequest.calculate_surface_id(
            ModelReviewSurfaceKind.ENTRY_POINT,
            subject_id,
        ),
        kind=ModelReviewSurfaceKind.ENTRY_POINT,
        subject_id=subject_id,
        contract="Synthetic",
        function_or_state_surface="reviewedSurface()",
        critical=True,
        allowed_symbols=("Synthetic",),
        invariant_considered="Authorized callers preserve the declared state invariant.",
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


def test_specialist_roles_have_no_hidden_static_context_cap() -> None:
    contracts = [definition.prompt_contract() for definition in SPECIALIST_ROLE_REGISTRY.values()]

    assert all("max_context_bytes" not in contract for contract in contracts)
    assert specialist_context_budget(
        "access_control",
        total_context_bytes=2_000_000,
        maximum_source_tokens_per_request=200_000,
    ) == specialist_context_budget(
        "report_quality",
        total_context_bytes=2_000_000,
        maximum_source_tokens_per_request=200_000,
    )


def test_specialist_execution_records_configured_cap_and_every_actual_context(
    config_factory,
) -> None:
    config = config_factory(
        repository={"max_total_context_bytes": 2_000_000},
        token_budgets={"maximum_source_tokens_per_request": 200_000},
        models={
            "specialists": {
                "access_control": {
                    "primary": "alpha/atlas-secure",
                    "fallbacks": [],
                }
            }
        },
    )
    first_context = _context(
        role="specialist:access_control",
        byte_budget=321_000,
    )
    second_context = _context(
        role="specialist:access_control",
        byte_budget=222_000,
    )

    record = next(
        item
        for item in build_specialist_execution_records(
            config,
            usage_records=[],
            contexts=[first_context, second_context],
        )
        if item.role == "access_control"
    )

    assert record.context_limit_bytes == 665_536
    assert record.context_budget_bytes is None
    assert record.context_bytes_used is None
    assert [context.byte_budget for context in record.contexts] == [321_000, 222_000]
    assert [context.rendered_bytes for context in record.contexts] == [
        first_context.bytes_used,
        second_context.bytes_used,
    ]
    assert record.status is SpecialistExecutionStatus.NOT_SCHEDULED
    assert record.execution_evidence is ExecutionEvidenceKind.UNVERIFIED


def test_mock_multi_shard_specialist_execution_is_observed_without_real_credit(
    config_factory,
    monkeypatch,
) -> None:
    config = config_factory(
        repository={"max_total_context_bytes": 2_000_000},
        token_budgets={"maximum_source_tokens_per_request": 200_000},
        models={
            "specialists": {
                "access_control": {
                    "primary": "alpha/atlas-secure",
                    "fallbacks": [],
                }
            }
        },
    )
    contexts = [
        _context(
            role="specialist:access_control",
            byte_budget=321_000,
            source="contract First {}",
            path="First.sol",
            requested_model_surfaces=(_surface_request(),),
        ),
        _context(
            role="specialist:access_control",
            byte_budget=222_000,
            source="contract Second {}",
            path="Second.sol",
            requested_model_surfaces=(_surface_request(),),
        ),
    ]
    usage = [
        _usage(
            request_id=f"mock-shard-{index}",
            role="specialist:access_control",
            context=context,
            execution_evidence=ExecutionEvidenceKind.MOCK,
        )
        for index, context in enumerate(contexts, start=1)
    ]
    monkeypatch.setattr(specialists_module, "is_creditable_usage_record", lambda _record: True)

    record = next(
        item
        for item in build_specialist_execution_records(
            config,
            usage_records=usage,
            contexts=contexts,
            accepted_outcomes=[_accepted(item) for item in usage],
        )
        if item.role == "access_control"
    )

    assert record.status is SpecialistExecutionStatus.COMPLETED
    assert record.execution_evidence is ExecutionEvidenceKind.MOCK
    assert record.successful_requests == 2
    assert record.failed_requests == 0
    assert record.context_budget_bytes is None
    assert record.context_bytes_used is None
    assert len(record.contexts) == 2
    assert completed_specialist_roles([record]) == set()


def test_specialist_execution_rejects_mixed_real_and_mock_role_evidence(
    config_factory,
) -> None:
    config = config_factory(
        models={
            "specialists": {
                "access_control": {
                    "primary": "alpha/atlas-secure",
                    "fallbacks": [],
                }
            }
        }
    )
    context = _context(role="specialist:access_control")
    usage = [
        _usage(
            request_id="real-shard",
            role="specialist:access_control",
            context=context,
        ),
        _usage(
            request_id="mock-shard",
            role="specialist:access_control",
            context=context,
            execution_evidence=ExecutionEvidenceKind.MOCK,
        ),
    ]

    with pytest.raises(ValueError, match="mixes incompatible execution evidence"):
        build_specialist_execution_records(
            config,
            usage_records=usage,
            contexts=[context],
        )


def test_scheduler_failed_request_cannot_receive_descriptive_completion(
    config_factory,
    monkeypatch,
) -> None:
    config = config_factory(
        models={
            "specialists": {
                "access_control": {
                    "primary": "alpha/atlas-secure",
                    "fallbacks": [],
                }
            }
        }
    )
    context = _context(role="specialist:access_control", source="contract Synthetic {}")
    succeeded = _usage(
        request_id="scheduler-succeeded",
        role="specialist:access_control",
        context=context,
        execution_evidence=ExecutionEvidenceKind.MOCK,
    )
    failed = _usage(
        request_id="scheduler-failed",
        role="specialist:access_control",
        context=context,
        execution_evidence=ExecutionEvidenceKind.MOCK,
    )
    monkeypatch.setattr(specialists_module, "is_creditable_usage_record", lambda _record: True)

    record = next(
        item
        for item in build_specialist_execution_records(
            config,
            usage_records=[succeeded, failed],
            contexts=[context],
            accepted_outcomes=[_accepted(succeeded)],
            structurally_successful_request_ids={succeeded.request_id},
        )
        if item.role == "access_control"
    )

    assert record.status is SpecialistExecutionStatus.PARTIAL
    assert record.execution_evidence is ExecutionEvidenceKind.MOCK
    assert record.successful_request_ids == (succeeded.request_id,)
    assert record.failed_request_ids == (failed.request_id,)
    assert completed_specialist_roles([record]) == set()


def test_specialist_execution_rejects_package_above_configured_limit(
    config_factory,
) -> None:
    config = config_factory(
        repository={"max_total_context_bytes": 2_000_000},
        token_budgets={"maximum_source_tokens_per_request": 200_000},
        models={
            "specialists": {
                "access_control": {
                    "primary": "alpha/atlas-secure",
                    "fallbacks": [],
                }
            }
        },
    )
    context = _context(
        role="specialist:access_control",
        byte_budget=665_537,
    )

    with pytest.raises(ValueError, match="effective configured package limit"):
        build_specialist_execution_records(
            config,
            usage_records=[],
            contexts=[context],
        )


def test_specialist_execution_rejects_stale_declared_render_bytes(config_factory) -> None:
    config = config_factory(
        models={
            "specialists": {
                "access_control": {
                    "primary": "alpha/atlas-secure",
                    "fallbacks": [],
                }
            }
        }
    )
    context = _context(role="specialist:access_control")
    stale = context.model_copy(update={"bytes_used": context.bytes_used - 1})

    with pytest.raises(ValueError, match="declared context bytes"):
        build_specialist_execution_records(
            config,
            usage_records=[],
            contexts=[stale],
        )


def test_mixed_specialist_outcomes_are_partial_and_not_runtime_credit(
    config_factory,
    monkeypatch,
) -> None:
    config = config_factory(
        models={
            "specialists": {
                "access_control": {
                    "primary": "alpha/atlas-secure",
                    "fallbacks": [],
                }
            }
        }
    )
    context = _context(role="specialist:access_control")
    usage = [
        _usage(
            request_id="success",
            role="specialist:access_control",
            context=context,
        ),
        _usage(
            request_id="failure",
            role="specialist:access_control",
            context=context,
        ),
    ]
    monkeypatch.setattr(
        specialists_module,
        "is_creditable_usage_record",
        lambda record: record.request_id == "success",
    )

    record = next(
        item
        for item in build_specialist_execution_records(
            config,
            usage_records=usage,
            contexts=[context],
            accepted_outcomes=[_accepted(usage[0])],
        )
        if item.role == "access_control"
    )

    assert record.status is SpecialistExecutionStatus.PARTIAL
    assert record.successful_requests == 1
    assert record.failed_requests == 1
    assert record.successful_request_ids == ("success",)
    assert record.failed_request_ids == ("failure",)
    assert completed_specialist_roles([record]) == set()


def test_source_free_investigator_completion_receives_no_runtime_credit(
    config_factory,
    monkeypatch,
) -> None:
    config = config_factory(
        models={
            "specialists": {
                "access_control": {
                    "primary": "alpha/atlas-secure",
                    "fallbacks": [],
                }
            }
        }
    )
    context = _context(role="specialist:access_control")
    usage = _usage(
        request_id="source-free-success",
        role="specialist:access_control",
        context=context,
    )
    monkeypatch.setattr(
        specialists_module,
        "is_creditable_usage_record",
        lambda _record: True,
    )

    record = next(
        item
        for item in build_specialist_execution_records(
            config,
            usage_records=[usage],
            contexts=[context],
            accepted_outcomes=[_accepted(usage)],
        )
        if item.role == "access_control"
    )

    assert record.status is SpecialistExecutionStatus.COMPLETED
    assert record.source_review_creditable_requests == 0
    assert completed_specialist_roles([record]) == set()
    relabeled = SpecialistExecutionRecord.model_validate(
        {
            **record.model_dump(mode="json"),
            "role_kind": "auxiliary",
        }
    )
    assert completed_specialist_roles([relabeled]) == set()


def test_source_backed_zero_surface_candidate_outcome_is_rejected_during_construction() -> None:
    context = _context(
        role="specialist:access_control",
        source="contract Synthetic {}",
    )
    usage = _usage(
        request_id="zero-surface-success",
        role="specialist:access_control",
        context=context,
    )

    with pytest.raises(
        ValidationError,
        match="candidate-review outcome requires requested surfaces and an accepted artifact",
    ):
        _accepted(
            usage,
            requested_surface_count=0,
            surface_review_artifact_sha256=None,
        )


def test_raw_provider_success_without_host_accepted_outcome_is_failed(
    config_factory,
    monkeypatch,
) -> None:
    config = config_factory(
        models={
            "specialists": {
                "access_control": {
                    "primary": "alpha/atlas-secure",
                    "fallbacks": [],
                }
            }
        }
    )
    context = _context(
        role="specialist:access_control",
        source="contract Synthetic {}",
    )
    usage = _usage(
        request_id="provider-only-success",
        role="specialist:access_control",
        context=context,
    )
    monkeypatch.setattr(
        specialists_module,
        "is_creditable_usage_record",
        lambda _record: True,
    )

    record = next(
        item
        for item in build_specialist_execution_records(
            config,
            usage_records=[usage],
            contexts=[context],
        )
        if item.role == "access_control"
    )

    assert record.status is SpecialistExecutionStatus.FAILED
    assert record.successful_requests == 0
    assert record.failed_request_ids == ("provider-only-success",)
    assert record.accepted_outcomes == ()
    assert completed_specialist_roles([record]) == set()


def test_exact_completion_identity_selects_one_of_two_same_role_records(
    config_factory,
    monkeypatch,
) -> None:
    del config_factory
    context = _context(role="specialist:access_control")
    first = _usage(
        request_id="same-role-first",
        role="specialist:access_control",
        context=context,
    )
    second = _usage(
        request_id="same-role-second",
        role="specialist:access_control",
        context=context,
    )
    monkeypatch.setattr(
        pipeline_module,
        "is_creditable_usage_record",
        lambda _record: True,
    )

    selected = _exact_completed_usage(
        [first, second],
        first,
        expected_role="specialist:access_control",
    )

    assert selected.request_id == "same-role-first"
    tampered = first.model_copy(update={"validated_response_sha256": "f" * 64})
    with pytest.raises(OpenRouterSchemaError, match="differed from its exact"):
        _exact_completed_usage(
            [first, second],
            tampered,
            expected_role="specialist:access_control",
        )


def test_exact_host_accepted_investigator_outcome_receives_source_review_credit(
    config_factory,
    monkeypatch,
) -> None:
    config = config_factory(
        models={
            "specialists": {
                "access_control": {
                    "primary": "alpha/atlas-secure",
                    "fallbacks": [],
                }
            }
        }
    )
    surface = _surface_request()
    context = _context(
        role="specialist:access_control",
        source="contract Synthetic {}",
        requested_model_surfaces=(surface,),
    )
    usage = _usage(
        request_id="host-accepted-success",
        role="specialist:access_control",
        context=context,
    )
    accepted = _accepted(
        usage,
        requested_surface_count=1,
        surface_review_artifact_sha256="c" * 64,
    )
    monkeypatch.setattr(
        specialists_module,
        "is_creditable_usage_record",
        lambda _record: True,
    )

    record = next(
        item
        for item in build_specialist_execution_records(
            config,
            usage_records=[usage],
            contexts=[context],
            accepted_outcomes=[accepted],
        )
        if item.role == "access_control"
    )

    assert record.status is SpecialistExecutionStatus.COMPLETED
    assert record.successful_request_ids == ("host-accepted-success",)
    assert record.accepted_outcomes == (accepted,)
    assert record.source_review_creditable_requests == 1
    assert completed_specialist_roles([record]) == {"access_control"}


def test_stale_hash_accepted_outcome_is_rejected_during_normalization(
    config_factory,
    monkeypatch,
) -> None:
    config = config_factory(
        models={
            "specialists": {
                "access_control": {
                    "primary": "alpha/atlas-secure",
                    "fallbacks": [],
                }
            }
        }
    )
    context = _context(role="specialist:access_control")
    usage = _usage(
        request_id="stale-outcome",
        role="specialist:access_control",
        context=context,
    )
    stale = _accepted(usage).model_copy(update={"validated_response_sha256": "f" * 64})
    accepted = _accepted(usage)
    with pytest.raises(ValidationError):
        accepted.request_id = "mutated"  # type: ignore[misc]
    monkeypatch.setattr(
        specialists_module,
        "is_creditable_usage_record",
        lambda _record: True,
    )

    with pytest.raises(ValueError, match="outcome hash is inconsistent"):
        build_specialist_execution_records(
            config,
            usage_records=[usage],
            contexts=[context],
            accepted_outcomes=[stale],
        )


def test_specialist_record_rejects_self_hashed_outcome_with_wrong_context_digest(
    config_factory,
    monkeypatch,
) -> None:
    config = config_factory(
        models={
            "specialists": {
                "access_control": {
                    "primary": "alpha/atlas-secure",
                    "fallbacks": [],
                }
            }
        }
    )
    context = _context(
        role="specialist:access_control",
        source="contract Synthetic {}",
    )
    usage = _usage(
        request_id="context-digest-splice",
        role="specialist:access_control",
        context=context,
    )
    accepted = _accepted(usage)
    spliced = SpecialistAcceptedOutcome.build(
        request_id=accepted.request_id,
        specialist_role=accepted.specialist_role,
        request_role=accepted.request_role,
        outcome_kind=accepted.outcome_kind,
        validated_response_sha256=accepted.validated_response_sha256,
        context_request_evidence_sha256="f" * 64,
        requested_surface_count=accepted.requested_surface_count,
        surface_review_artifact_sha256=accepted.surface_review_artifact_sha256,
    )
    monkeypatch.setattr(
        specialists_module,
        "is_creditable_usage_record",
        lambda _record: True,
    )
    record = next(
        item
        for item in build_specialist_execution_records(
            config,
            usage_records=[usage],
            contexts=[context],
            accepted_outcomes=[accepted],
        )
        if item.role == "access_control"
    )
    payload = record.model_dump(mode="json")
    payload["accepted_outcomes"] = [spliced.model_dump(mode="json")]

    with pytest.raises(ValueError, match="context evidence digest is inconsistent"):
        SpecialistExecutionRecord.model_validate(payload)

    constructed = record.model_copy(update={"accepted_outcomes": (spliced,)})
    assert constructed.derived_source_review_creditable_requests() == 0
    assert completed_specialist_roles([constructed]) == set()


def test_forged_auxiliary_completion_cannot_bypass_record_revalidation() -> None:
    forged = SpecialistExecutionRecord.model_construct(
        role="report_quality",
        role_kind="auxiliary",
        status=SpecialistExecutionStatus.COMPLETED,
    )

    assert completed_specialist_roles([forged]) == set()


def test_investigator_exploit_test_request_cannot_cross_credit_investigation(
    config_factory,
    monkeypatch,
) -> None:
    config = config_factory(
        models={
            "specialists": {
                "access_control": {
                    "primary": "alpha/atlas-secure",
                    "fallbacks": [],
                }
            }
        }
    )
    context = _context(
        role="specialist:access_control",
        source="contract Synthetic {}",
    )
    usage = _usage(
        request_id="auxiliary-planning-success",
        role="specialist:access_control:exploit_test",
        context=context,
    )
    monkeypatch.setattr(
        specialists_module,
        "is_creditable_usage_record",
        lambda _record: True,
    )

    record = next(
        item
        for item in build_specialist_execution_records(
            config,
            usage_records=[usage],
            contexts=[context],
        )
        if item.role == "access_control"
    )

    assert canonical_specialist_role(usage.role) is None
    assert canonical_specialist_role("specialist:test_generation") is None
    assert canonical_specialist_role("specialist:test_generation:exploit_test") == "test_generation"
    assert record.status is SpecialistExecutionStatus.NOT_SCHEDULED
    assert record.successful_requests == 0
    assert record.source_review_creditable_requests == 0
    assert completed_specialist_roles([record]) == set()


def test_candidate_origin_hashes_cannot_be_lent_across_disjoint_contexts(
    tmp_path,
) -> None:
    first_source = "contract First {}"
    second_source = "contract Second {}"
    (tmp_path / "First.sol").write_text(first_source, encoding="utf-8")
    (tmp_path / "Second.sol").write_text(second_source, encoding="utf-8")
    first_context = _context(
        role="source_audit",
        source=first_source,
        path="First.sol",
    )
    second_context = _context(
        role="business_logic",
        source=second_source,
        path="Second.sol",
    )
    origins: dict[str, ContextPackage] = {}
    _register_candidate_origin_packages(
        origins,
        candidate_ids=["candidate-first"],
        context=first_context,
    )
    _register_candidate_origin_packages(
        origins,
        candidate_ids=["candidate-second"],
        context=second_context,
    )
    candidate = CandidateFinding.model_construct(
        candidate_id="candidate-first",
        locations=[Location(path="Second.sol", start_line=1, end_line=1)],
        source=None,
        sink=None,
    )

    validation = validate_candidate(
        tmp_path,
        candidate,
        context_hashes=_candidate_origin_context_hashes(
            origins,
            candidate.candidate_id,
        ),
    )

    assert not validation.valid
    assert any("not present in supplied context" in error for error in validation.errors)


def test_duplicate_candidate_origin_registration_fails_closed() -> None:
    context = _context(role="source_audit")
    origins: dict[str, ContextPackage] = {}
    _register_candidate_origin_packages(
        origins,
        candidate_ids=["candidate-duplicate"],
        context=context,
    )

    with pytest.raises(OpenRouterSchemaError, match="duplicate or conflicting"):
        _register_candidate_origin_packages(
            origins,
            candidate_ids=["candidate-duplicate"],
            context=context,
        )


def test_context_package_bytes_and_omissions_remain_bounded_after_validation() -> None:
    context = _context()

    assert isinstance(context.omissions, tuple)
    with pytest.raises(AttributeError):
        context.omissions.append(object())  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="bytes exceed"):
        context.model_copy(update={"bytes_used": context.byte_budget + 1})


@pytest.mark.parametrize(
    ("byte_budget", "configured_source_tokens", "effective_source_bytes"),
    [
        (100, 1_000, 101),
        (2**40, 2**40, 2**31),
    ],
)
def test_context_execution_evidence_rejects_impossible_source_ceiling(
    byte_budget: int,
    configured_source_tokens: int,
    effective_source_bytes: int,
) -> None:
    with pytest.raises(ValueError, match="governing limit"):
        ContextExecutionEvidence(
            context_role="specialist:access_control",
            byte_budget=byte_budget,
            declared_bytes_used=0,
            rendered_bytes=0,
            source_bytes=0,
            configured_maximum_source_tokens_per_request=configured_source_tokens,
            effective_source_byte_ceiling=effective_source_bytes,
            rendered_sha256="0" * 64,
        )


@pytest.mark.parametrize(
    "field",
    [
        "byte_budget",
        "configured_maximum_source_tokens_per_request",
        "effective_source_byte_ceiling",
    ],
)
def test_context_execution_evidence_rejects_boolean_integer_bounds(field: str) -> None:
    payload: dict[str, object] = {
        "context_role": "specialist:access_control",
        "byte_budget": 100,
        "declared_bytes_used": 0,
        "rendered_bytes": 0,
        "source_bytes": 0,
        "configured_maximum_source_tokens_per_request": 10,
        "effective_source_byte_ceiling": 0,
        "rendered_sha256": "0" * 64,
    }
    payload[field] = True

    with pytest.raises(ValueError):
        ContextExecutionEvidence.model_validate(payload)


def test_context_request_evidence_rejects_impossible_source_ceiling() -> None:
    with pytest.raises(ValueError, match="governing limit"):
        ContextRequestEvidence.build(
            request_id="request-1",
            request_role="specialist:access_control",
            context_role="specialist:access_control",
            byte_budget=100,
            declared_bytes_used=0,
            rendered_bytes=0,
            source_bytes=0,
            configured_maximum_source_tokens_per_request=1_000,
            effective_source_byte_ceiling=101,
            rendered_sha256="0" * 64,
        )


def test_specialist_record_rejects_unbound_success_and_free_source_credit(
    config_factory,
    monkeypatch,
) -> None:
    config = config_factory(
        models={
            "specialists": {
                "access_control": {
                    "primary": "alpha/atlas-secure",
                    "fallbacks": [],
                }
            }
        }
    )
    context = _context(
        role="specialist:access_control",
        source="contract Synthetic {}",
    )
    usage = _usage(
        request_id="source-success",
        role="specialist:access_control",
        context=context,
    )
    monkeypatch.setattr(
        specialists_module,
        "is_creditable_usage_record",
        lambda _record: True,
    )
    record = next(
        item
        for item in build_specialist_execution_records(
            config,
            usage_records=[usage],
            contexts=[context],
            accepted_outcomes=[_accepted(usage)],
        )
        if item.role == "access_control"
    )
    payload = record.model_dump(mode="json")
    payload["request_contexts"] = []

    with pytest.raises(ValueError, match=r"context evidence"):
        SpecialistExecutionRecord.model_validate(payload)

    constructed = record.model_copy(
        update={
            "request_contexts": (),
            "source_review_creditable_requests": 99,
        }
    )
    assert completed_specialist_roles([constructed]) == set()


def test_specialist_record_rejects_request_context_not_in_retained_inventory(
    config_factory,
    monkeypatch,
) -> None:
    config = config_factory(
        models={
            "specialists": {
                "access_control": {
                    "primary": "alpha/atlas-secure",
                    "fallbacks": [],
                }
            }
        }
    )
    context = _context(
        role="specialist:access_control",
        source="contract Synthetic {}",
    )
    usage = _usage(
        request_id="source-success",
        role="specialist:access_control",
        context=context,
    )
    monkeypatch.setattr(
        specialists_module,
        "is_creditable_usage_record",
        lambda _record: True,
    )
    record = next(
        item
        for item in build_specialist_execution_records(
            config,
            usage_records=[usage],
            contexts=[context],
            accepted_outcomes=[_accepted(usage)],
        )
        if item.role == "access_control"
    )
    retained = record.contexts[0]
    mismatched = ContextRequestEvidence.build(
        request_id="source-success",
        request_role="specialist:access_control",
        context_role=retained.context_role,
        byte_budget=retained.byte_budget,
        declared_bytes_used=retained.declared_bytes_used,
        rendered_bytes=retained.rendered_bytes,
        source_bytes=retained.source_bytes,
        configured_maximum_source_tokens_per_request=(
            retained.configured_maximum_source_tokens_per_request
        ),
        effective_source_byte_ceiling=retained.effective_source_byte_ceiling,
        rendered_sha256="f" * 64,
    )
    payload = record.model_dump(mode="json")
    payload["request_contexts"] = [mismatched.model_dump(mode="json")]

    with pytest.raises(ValueError, match="retained specialist context"):
        SpecialistExecutionRecord.model_validate(payload)


def test_specialist_record_rejects_source_credit_for_source_free_success(
    config_factory,
    monkeypatch,
) -> None:
    config = config_factory(
        models={
            "specialists": {
                "access_control": {
                    "primary": "alpha/atlas-secure",
                    "fallbacks": [],
                }
            }
        }
    )
    context = _context(role="specialist:access_control")
    usage = _usage(
        request_id="source-free-success",
        role="specialist:access_control",
        context=context,
    )
    monkeypatch.setattr(
        specialists_module,
        "is_creditable_usage_record",
        lambda _record: True,
    )
    record = next(
        item
        for item in build_specialist_execution_records(
            config,
            usage_records=[usage],
            contexts=[context],
            accepted_outcomes=[_accepted(usage)],
        )
        if item.role == "access_control"
    )
    payload = record.model_dump(mode="json")
    payload["source_review_creditable_requests"] = 1

    with pytest.raises(ValueError, match="source-review credit"):
        SpecialistExecutionRecord.model_validate(payload)
