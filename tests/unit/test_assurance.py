from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime

from mmaudit.agents.specialists import SPECIALIST_ROLE_REGISTRY
from mmaudit.benchmark.certificate import (
    BenchmarkCertificateVerification,
    CertificateVerificationStatus,
)
from mmaudit.config import validate_model_independence
from mmaudit.constants import ALL_SPECIALIST_ROLES, SPECIALIST_INVESTIGATOR_ROLES
from mmaudit.models.schemas import (
    AnalysisState,
    AuditProfile,
    AuditQualityStatus,
    AuditReport,
    AuditScope,
    AuditScopeAssessment,
    CompilationStatus,
    CoverageMetric,
    CoverageProvenance,
    EconomicSimulationKind,
    EconomicSimulationPlan,
    FormalToolRun,
    FormalToolStatus,
    InvariantCategory,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    InvariantSpec,
    InvariantSuite,
    InvariantTemplate,
    Location,
    MaximumAssuranceStatus,
    ModelReviewCoverage,
    ModelReviewSurface,
    ModelReviewSurfaceKind,
    RepositoryMap,
    ScannerRun,
    ScannerStatus,
    ScopeComponent,
    ScopeComponentEvidence,
    ScopeEvidenceStatus,
    SolidityCompilationResult,
    SolidityCoverage,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphSet,
    SolidityProjectMetadata,
    SolidityProjectType,
    SolidityProvenance,
    SoliditySymbolIndex,
)
from mmaudit.orchestration.assurance import (
    FULL_SEMANTIC_GRAPHS,
    AssuranceRuntime,
    MaximumAssuranceContract,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.markdown import render_markdown
from mmaudit.reporting.sarif import generate_sarif
from mmaudit.traceability import (
    ImplementationStatus,
    MaximumAssuranceTraceability,
    TraceabilityRequirement,
    build_traceability_matrix,
)


def _specialists(*, families: int = 8) -> dict[str, dict[str, object]]:
    return {
        role: {
            "primary": f"specialist-{index % families}/model-{index % families}",
            "fallbacks": [],
            "quality_tier": "high",
            "capabilities": ["structured_json", "security_reasoning", "solidity"],
        }
        for index, role in enumerate(ALL_SPECIALIST_ROLES)
    }


def _maximum_config(config_factory, *, allow_downgrade: bool = False, families: int = 8):
    return config_factory(
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        maximum_assurance={"allow_downgrade": allow_downgrade},
        models={"specialists": _specialists(families=families)},
    ).effective()


def _model_metric(numerator: int, denominator: int, detail: str) -> CoverageMetric:
    return CoverageMetric(
        numerator=numerator,
        denominator=denominator,
        population=denominator,
        percentage=round((numerator / denominator) * 100, 4) if denominator else None,
        exclusions=[],
        not_applicable_evidence=([] if denominator else ["no synthetic surfaces of this category"]),
        confidence=1,
        provenance=[CoverageProvenance.MODEL_CONTEXT],
        failures=[],
        state=AnalysisState.MODEL_ONLY,
        detail=detail,
    )


def _complete_model_coverage() -> ModelReviewCoverage:
    surface = ModelReviewSurface(
        surface_id="model-surface:" + ("a" * 64),
        kind=ModelReviewSurfaceKind.CONTRACT,
        subject_id="contract:Vault",
        label="Vault",
        critical=True,
        locations=[
            Location(
                path="src/Vault.sol",
                start_line=1,
                end_line=5,
                content_hash="a" * 64,
            )
        ],
        reviewer_roles=["business_logic", "source_audit"],
        root_lineages=["sha256:" + ("a" * 64), "sha256:" + ("b" * 64)],
        reviewed=True,
    )
    return ModelReviewCoverage(
        applicable=True,
        surfaces=[surface],
        overall=_model_metric(1, 1, "synthetic complete overall model coverage"),
        by_kind={
            kind: _model_metric(
                1 if kind is ModelReviewSurfaceKind.CONTRACT else 0,
                1 if kind is ModelReviewSurfaceKind.CONTRACT else 0,
                f"synthetic {kind.value} model coverage",
            )
            for kind in ModelReviewSurfaceKind
        },
        critical=_model_metric(1, 1, "synthetic complete critical model coverage"),
        critical_gate_passed=True,
    )


def _complete_scope_assessment() -> AuditScopeAssessment:
    return AuditScopeAssessment(
        requested=AuditScope.FULL_PROTOCOL,
        achieved=AuditScope.FULL_PROTOCOL,
        gate_required=True,
        complete=True,
        components=[
            ScopeComponentEvidence(
                component=component,
                required=True,
                status=ScopeEvidenceStatus.ANALYZED,
                analyzed_paths=[f"scope/{component.value}.txt"],
                detail="synthetic analyzed scope evidence",
            )
            for component in sorted(ScopeComponent, key=lambda item: item.value)
        ],
        missing_required_components=[],
    )


def _complete_runtime() -> AssuranceRuntime:
    now = datetime.now(UTC)
    project = SolidityProjectMetadata(
        project_type=SolidityProjectType.FOUNDRY,
        project_root=".",
        source_directories=["src"],
    )
    invariant = InvariantSpec(
        id="inv-economic",
        title="Economic invariant",
        category=InvariantCategory.ECONOMIC,
        description="Synthetic invariant used to satisfy contract gate coverage.",
        template=InvariantTemplate.DONATION_INFLATION_RESISTANCE,
        locations=[
            Location(
                path="src/Vault.sol",
                start_line=1,
                end_line=5,
                content_hash="a" * 64,
            )
        ],
        provenance=SolidityProvenance.HEURISTIC,
        confidence=0.9,
        template_available=True,
        executable=True,
        evidence_hash="b" * 64,
    )
    return AssuranceRuntime(
        projects=[project],
        compilations=[
            SolidityCompilationResult(
                status=CompilationStatus.SUCCESS,
                framework=SolidityProjectType.FOUNDRY,
                project_root=".",
                contracts_compiled=["Vault"],
                ast_available=True,
            )
        ],
        index=SoliditySymbolIndex(
            projects=[project],
            entities=[
                SolidityEntity(
                    id="contract:Vault",
                    kind=SolidityEntityKind.CONTRACT,
                    name="Vault",
                    path="src/Vault.sol",
                    start_line=1,
                    end_line=5,
                    byte_start=0,
                    byte_end=1,
                    source_hash="a" * 64,
                    provenance=SolidityProvenance.COMPILER,
                    confidence=1,
                    transformation="synthetic_test_entity",
                )
            ],
            ast_sources=["src/Vault.sol"],
        ),
        graphs=SolidityGraphSet(edges=[], analyzed_graphs=list(FULL_SEMANTIC_GRAPHS)),
        scanners=[
            ScannerRun(
                scanner="slither",
                status=ScannerStatus.SUCCESS,
                started_at=now,
                finished_at=now,
                duration_seconds=0,
            )
        ],
        invariants=InvariantSuite(
            invariants=[invariant],
            templates_available_count=1,
            executable_count=1,
        ),
        invariant_executions=[
            InvariantExecutionResult(
                invariant_id=invariant.id,
                harness_name="DonationInflation",
                status=InvariantExecutionStatus.PASSED,
                economic_template=EconomicSimulationKind.ERC4626_DONATION,
            )
        ],
        economic_simulations=[
            EconomicSimulationPlan(
                kind=EconomicSimulationKind.ERC4626_DONATION,
                applicable=True,
                rationale="synthetic",
                invariant_ids=[invariant.id],
                typed_harness_available=True,
                execution_required=True,
            )
        ],
        formal_runs=[
            FormalToolRun(
                tool="solc-smtchecker",
                status=FormalToolStatus.SUCCESS,
            )
        ],
        model_roles_completed={
            "threat_model",
            "source_audit",
            "business_logic",
            "configuration",
        },
        specialist_roles_completed=set(SPECIALIST_INVESTIGATOR_ROLES),
        auxiliary_roles_completed={
            "invariant_review",
            "test_generation",
            "exploit_reproduction_planner",
            "falsifier",
            "report_quality",
        },
        verifier_completed=True,
        falsifier_completed=True,
        judge_completed=True,
        coverage=SolidityCoverage(projects_discovered=1),
        model_review_coverage=_complete_model_coverage(),
        scope_assessment=_complete_scope_assessment(),
        isolation_available=True,
        artifacts={
            "solidity-projects.json",
            "solidity-compilation.json",
            "solidity-index.json",
            "solidity-graphs.json",
            "scanner-results.json",
            "solidity-invariants.json",
            "invariant-review.json",
            "invariant-execution-results.json",
            "economic-simulation-plan.json",
            "reproduction-results.json",
            "solidity-coverage.json",
            "formal-results.json",
            "cross-examination.json",
            "specialist-execution.json",
            "model-review-coverage.json",
            "scope-assessment.json",
            "maximum_assurance_traceability.json",
        },
        traceability=_implemented_traceability(),
    )


def _implemented_traceability() -> MaximumAssuranceTraceability:
    return MaximumAssuranceTraceability(
        last_verified_commit="synthetic-test",
        requirements=[
            TraceabilityRequirement(
                requirement_id="MA-SYNTHETIC-READY",
                description="Synthetic fully implemented assurance dependency.",
                implementation_status=ImplementationStatus.IMPLEMENTED,
                implementation_paths=["src/mmaudit/orchestration/assurance.py"],
                unit_tests=["tests/unit/test_assurance.py"],
                runtime_artifacts=["maximum_assurance_traceability.json"],
                required_for_complete=True,
                last_verified_commit="synthetic-test",
            )
        ],
    )


def _current_benchmark_verification() -> BenchmarkCertificateVerification:
    payload = {
        "schema_version": "1.0",
        "certificate_sha256": "a" * 64,
        "status": CertificateVerificationStatus.CURRENT,
        "observed_repository_git_commit": "b" * 40,
        "observed_bindings_sha256": "c" * 64,
        "mismatches": [],
    }
    payload["verification_sha256"] = canonical_sha256(payload)
    return BenchmarkCertificateVerification.model_validate(payload)


def test_maximum_assurance_rejects_missing_model_families(config_factory) -> None:
    repeated_specialists = {
        role: {
            "primary": "alpha/atlas-secure",
            "fallbacks": [],
            "quality_tier": "high",
            "capabilities": ["structured_json", "security_reasoning", "solidity"],
        }
        for role in ALL_SPECIALIST_ROLES
    }
    config = config_factory(
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        models={"specialists": repeated_specialists},
    ).effective()
    errors = validate_model_independence(config)
    assert any("independent analysis model families" in error for error in errors)
    assert any("unique high-quality model slots" in error for error in errors)


def test_maximum_assurance_complete_requires_all_runtime_clauses(config_factory) -> None:
    config = _maximum_config(config_factory)
    assessment = MaximumAssuranceContract(config).evaluate(_complete_runtime())
    assert assessment.status is MaximumAssuranceStatus.COMPLETE
    assert not assessment.downgraded
    assert all(
        requirement.passed for requirement in assessment.requirements if requirement.required
    )


def test_benchmark_gate_requires_current_typed_verification_and_artifact(
    config_factory,
) -> None:
    config = config_factory(
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        maximum_assurance={"benchmark_gate": True},
        models={"specialists": _specialists()},
    ).effective()
    contract = MaximumAssuranceContract(config)
    base_runtime = _complete_runtime()
    absent = contract.evaluate(base_runtime)
    absent_gate = next(
        requirement
        for requirement in absent.requirements
        if requirement.engine == "benchmark_regression_gate"
    )
    current = contract.evaluate(
        replace(
            base_runtime,
            benchmark_verification=_current_benchmark_verification(),
            artifacts={
                *base_runtime.artifacts,
                "benchmark-certificate-verification.json",
            },
        )
    )
    current_gate = next(
        requirement
        for requirement in current.requirements
        if requirement.engine == "benchmark_regression_gate"
    )

    assert absent_gate.required
    assert not absent_gate.passed
    assert absent_gate.state is AnalysisState.NOT_ANALYZED
    assert current_gate.passed
    assert current_gate.state is AnalysisState.DETERMINISTIC
    assert current_gate.artifacts == ["benchmark-certificate-verification.json"]


def test_missing_traceability_fails_without_downgrade(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = replace(_complete_runtime(), traceability=None)
    assessment = MaximumAssuranceContract(config).evaluate(runtime)
    gate = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "requirements_traceability"
    )
    assert assessment.status is MaximumAssuranceStatus.FAILED
    assert not gate.passed


def test_missing_full_protocol_scope_blocks_maximum_assurance(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime()
    assessment = MaximumAssuranceContract(config).evaluate(
        replace(
            runtime,
            scope_assessment=None,
            artifacts=runtime.artifacts - {"scope-assessment.json"},
        )
    )
    gate = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "full_protocol_scope"
    )
    assert assessment.status is MaximumAssuranceStatus.FAILED
    assert not gate.passed
    assert gate.artifacts == []


def test_incomplete_required_traceability_is_failed_or_explicitly_downgraded(
    config_factory,
) -> None:
    for status in (
        ImplementationStatus.PARTIALLY_IMPLEMENTED,
        ImplementationStatus.UNAVAILABLE,
        ImplementationStatus.UNIMPLEMENTED,
    ):
        runtime = replace(
            _complete_runtime(),
            traceability=MaximumAssuranceTraceability(
                last_verified_commit="synthetic-test",
                requirements=[
                    TraceabilityRequirement(
                        requirement_id="MA-SYNTHETIC-GAP",
                        description="Synthetic blocking dependency.",
                        implementation_status=status,
                        required_for_complete=True,
                        downgrade_reason="synthetic capability is incomplete",
                        last_verified_commit="synthetic-test",
                    )
                ],
            ),
        )
        failed = MaximumAssuranceContract(_maximum_config(config_factory)).evaluate(runtime)
        assert failed.status is MaximumAssuranceStatus.FAILED
        gap = next(
            requirement
            for requirement in failed.requirements
            if requirement.engine == "traceability:ma-synthetic-gap"
        )
        assert not gap.passed
        assert status.value in gap.detail

        downgraded = MaximumAssuranceContract(
            _maximum_config(config_factory, allow_downgrade=True)
        ).evaluate(runtime)
        assert downgraded.status is MaximumAssuranceStatus.DOWNGRADED
        assert downgraded.downgraded
        assert any(status.value in reason for reason in downgraded.downgrade_reasons)


def test_incomplete_nonblocking_traceability_does_not_block(config_factory) -> None:
    runtime = replace(
        _complete_runtime(),
        traceability=MaximumAssuranceTraceability(
            last_verified_commit="synthetic-test",
            requirements=[
                TraceabilityRequirement(
                    requirement_id="MA-SYNTHETIC-OPTIONAL",
                    description="Synthetic nonblocking evaluation.",
                    implementation_status=ImplementationStatus.UNAVAILABLE,
                    required_for_complete=False,
                    downgrade_reason="independent evaluation has not been run",
                    last_verified_commit="synthetic-test",
                )
            ],
        ),
    )
    assessment = MaximumAssuranceContract(_maximum_config(config_factory)).evaluate(runtime)
    assert assessment.status is MaximumAssuranceStatus.COMPLETE
    assert not any(
        requirement.engine == "traceability:ma-synthetic-optional"
        for requirement in assessment.requirements
    )


def test_current_required_traceability_gaps_all_block_complete(config_factory) -> None:
    matrix = build_traceability_matrix("synthetic-test")
    runtime = replace(_complete_runtime(), traceability=matrix)
    assessment = MaximumAssuranceContract(_maximum_config(config_factory)).evaluate(runtime)
    expected = {
        f"traceability:{item.requirement_id.lower()}"
        for item in matrix.requirements
        if item.required_for_complete
        and item.implementation_status is not ImplementationStatus.IMPLEMENTED
    }
    failed = {
        requirement.engine
        for requirement in assessment.requirements
        if requirement.required and not requirement.passed
    }
    assert assessment.status is MaximumAssuranceStatus.FAILED
    assert expected
    assert expected <= failed


def test_maximum_assurance_reports_untyped_economic_templates(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime()
    runtime.economic_simulations.append(
        EconomicSimulationPlan(
            kind=EconomicSimulationKind.FLASH_ORACLE,
            applicable=True,
            rationale="synthetic unimplemented template",
            execution_required=True,
            typed_harness_available=False,
        )
    )

    assessment = MaximumAssuranceContract(config).evaluate(runtime)

    assert assessment.status is MaximumAssuranceStatus.FAILED
    economic = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "protocol_economic_simulation"
    )
    assert not economic.passed
    assert "lack deterministic typed harness support" in economic.detail


def test_maximum_assurance_preflight_requires_isolation(config_factory) -> None:
    config = _maximum_config(config_factory)
    requirements = MaximumAssuranceContract(config).configuration_requirements(
        isolation_available=False,
        scanner_only=False,
    )
    isolation = next(
        requirement
        for requirement in requirements
        if requirement.engine == "hardened_dynamic_isolation"
    )
    assert isolation.required
    assert not isolation.passed
    assert isolation.blocking


def test_maximum_assurance_requires_every_narrow_specialist(config_factory) -> None:
    specialists = _specialists()
    specialists.pop("precision_rounding")
    config = config_factory(
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        models={"specialists": specialists},
    ).effective()
    requirements = MaximumAssuranceContract(config).configuration_requirements(
        isolation_available=True,
        scanner_only=False,
    )
    coverage = next(
        requirement
        for requirement in requirements
        if requirement.engine == "specialist_role_coverage"
    )
    assert not coverage.passed
    assert "precision_rounding" in coverage.detail
    assert len(SPECIALIST_INVESTIGATOR_ROLES) >= 20
    assert set(SPECIALIST_ROLE_REGISTRY) == set(ALL_SPECIALIST_ROLES)
    assert len({definition.mission for definition in SPECIALIST_ROLE_REGISTRY.values()}) == len(
        SPECIALIST_ROLE_REGISTRY
    )
    assert len(
        {definition.effective_schema_name() for definition in SPECIALIST_ROLE_REGISTRY.values()}
    ) == len(SPECIALIST_ROLE_REGISTRY)
    assert all(
        definition.required_checks
        and definition.context_priorities
        and definition.max_context_bytes > 0
        for definition in SPECIALIST_ROLE_REGISTRY.values()
    )


def test_critical_reproduction_impossibility_requires_a_reason(config_factory) -> None:
    config = _maximum_config(config_factory)
    contract = MaximumAssuranceContract(config)
    unexplained = contract.evaluate(
        AssuranceRuntime(
            eligible_high_critical_ids={"critical-1"},
            feasible_high_critical_ids=set(),
            documented_infeasible_ids=set(),
            isolation_available=True,
        )
    )
    gate = next(
        requirement
        for requirement in unexplained.requirements
        if requirement.engine == "critical_high_reproduction"
    )
    assert not gate.passed
    assert "lacked a reason" in gate.detail

    explained = contract.evaluate(
        AssuranceRuntime(
            eligible_high_critical_ids={"critical-1"},
            feasible_high_critical_ids=set(),
            documented_infeasible_ids={"critical-1"},
            isolation_available=True,
        )
    )
    explained_gate = next(
        requirement
        for requirement in explained.requirements
        if requirement.engine == "critical_high_reproduction"
    )
    assert explained_gate.passed


def test_high_critical_cross_examination_requires_two_lineages(config_factory) -> None:
    config = _maximum_config(config_factory)
    contract = MaximumAssuranceContract(config)
    one_lineage = contract.evaluate(
        replace(
            _complete_runtime(),
            eligible_high_critical_ids={"critical-1"},
            falsifier_completed=True,
            candidate_falsifier_lineages={"sha256:" + ("a" * 64)},
        )
    )
    one_lineage_gate = next(
        requirement
        for requirement in one_lineage.requirements
        if requirement.engine == "independent_falsifier"
    )
    assert not one_lineage_gate.passed

    two_lineages = contract.evaluate(
        replace(
            _complete_runtime(),
            eligible_high_critical_ids={"critical-1"},
            falsifier_completed=True,
            candidate_falsifier_lineages={
                "sha256:" + ("a" * 64),
                "sha256:" + ("b" * 64),
            },
        )
    )
    two_lineage_gate = next(
        requirement
        for requirement in two_lineages.requirements
        if requirement.engine == "independent_falsifier"
    )
    assert two_lineage_gate.passed


def test_downgrade_is_visible_in_markdown_json_and_sarif(config_factory) -> None:
    config = _maximum_config(config_factory, allow_downgrade=True)
    assessment = MaximumAssuranceContract(config).evaluate(
        AssuranceRuntime(isolation_available=False, scanner_only=True)
    )
    assert assessment.status is MaximumAssuranceStatus.DOWNGRADED
    report = AuditReport(
        schema_version="1.0",
        run_id="assurance-test",
        generated_at=datetime.now(UTC),
        completed=True,
        incomplete_reasons=[],
        repository=RepositoryMap(
            root_name="synthetic",
            languages={"Solidity": 1},
            frameworks=["Foundry"],
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
        configuration_hash="a" * 64,
        model_configuration_hash="b" * 64,
        privacy={"code_egress_enabled": False},
        scanner_runs=[],
        usage=[],
        budget_usd=1,
        accounted_cost_usd=0,
        findings=[],
        rejected_findings=[],
        audit_profile=AuditProfile.MAXIMUM_ASSURANCE,
        quality_status=AuditQualityStatus.COMPLETED_WITH_LIMITATIONS,
        maximum_assurance=assessment,
    )
    markdown = render_markdown(report)
    assert "DOWNGRADED" in markdown
    assert "must not be represented as maximum assurance" in markdown
    payload = json.loads(report.model_dump_json())
    assert payload["maximum_assurance"]["status"] == "DOWNGRADED"
    sarif = generate_sarif([], maximum_assurance=assessment)
    run = sarif["runs"][0]
    assert run["properties"]["maximumAssurance"]["status"] == "DOWNGRADED"
    assert run["invocations"][0]["properties"]["downgraded"] is True
