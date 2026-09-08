"""Source-only refusal reports through the actual pipeline; no engine or provider credit."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    AuditProfile,
    AuditReport,
    AuditRunStatus,
    MaximumAssuranceStatus,
)
from mmaudit.orchestration import pipeline as pipeline_module
from mmaudit.orchestration.manifest import load_run_evidence_manifest, validate_manifest_artifacts
from mmaudit.repository import discovery
from mmaudit.scanners.runner import ScannerRunner
from mmaudit.solidity.formal import FormalRunner
from mmaudit.solidity.invariant_execution import FoundryInvariantRunner
from mmaudit.solidity.reproduction import ForkReproductionRunner


class _NoExecutionBackend:
    name = "unverified-assurance-report-control"
    supports_local_fork_rpc = False

    def wrap(self, *args, **kwargs):
        pytest.fail("invariant: missing assurance must never execute a tool in this control")


def _pipeline(tmp_path, config_factory, *, configured, language):
    repository = tmp_path / "repository"
    repository.mkdir()
    shutil.copyfile(
        Path(__file__).parents[1] / "fixtures/solidity/development_review/ControlB.sol",
        repository / "ControlB.sol",
    )
    config = config_factory(
        language_profile=language,
        smart_contracts={"compile": False, "framework": "foundry"},
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
        invariants={"enabled": False},
        formal={"enabled": False},
        maximum_assurance={"require": configured},
    ).effective()
    backend = _NoExecutionBackend()
    return pipeline_module.AuditPipeline(
        config,
        repo=repository,
        output=tmp_path / "output",
        scanner_runner=ScannerRunner(config, adapters={}, backend=backend),
        reproduction_runner=ForkReproductionRunner(
            config.reproduction, config.smart_contracts, backend=backend
        ),
        invariant_runner=FoundryInvariantRunner(
            config.reproduction, config.smart_contracts, backend=backend
        ),
        formal_runner=FormalRunner(config.formal, backend=backend),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("language", ["solidity-evm", "generic-source-review"])
@pytest.mark.parametrize("allow_downgrade", [False, True])
@pytest.mark.parametrize(
    ("configured", "run_requirement"),
    [(False, True), (True, None), (True, False), (False, None)],
)
async def test_unmet_assurance_returns_truthful_validated_report_without_execution(
    tmp_path, config_factory, monkeypatch, language, allow_downgrade, configured, run_requirement
):
    audit = _pipeline(tmp_path, config_factory, configured=configured, language=language)
    before = audit.config.model_dump_json()
    source = (audit.repo_input / "ControlB.sol").read_bytes()
    expected = configured if run_requirement is None else run_requirement
    original = pipeline_module._evaluate_quality_gates
    evaluations = []

    def observe(**kwargs):
        evaluations.append(kwargs.get("maximum_assurance_required"))
        return original(**kwargs)

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: source-only report control cannot discover, execute or connect")

    with monkeypatch.context() as patch:
        patch.setattr(subprocess, "Popen", forbidden)
        patch.setattr(shutil, "which", forbidden)
        patch.setattr(socket, "socket", forbidden)
        patch.setattr(discovery, "_git_commit", lambda root: None)
        patch.setattr(pipeline_module, "_evaluate_quality_gates", observe)
        if run_requirement is True and allow_downgrade:
            with pytest.raises(ValueError, match=r"maximum.*downgrade|downgrade.*maximum"):
                await audit.run(
                    scanner_only=True,
                    require_maximum_assurance=True,
                    allow_maximum_assurance_downgrade=True,
                )
            assert evaluations == [] and not audit.output.exists()
            assert audit.api_key == "" and audit.client is None
            assert audit.config.model_dump_json() == before
            return
        result = await audit.run(
            scanner_only=True,
            require_maximum_assurance=run_requirement,
            allow_maximum_assurance_downgrade=allow_downgrade,
        )
    assert evaluations == [expected, expected]
    report = result.report
    assert AuditReport.model_validate_json(report.model_dump_json()) == report
    assert report.audit_profile is AuditProfile.STANDARD
    assert report.completed is False and report.run_status is not AuditRunStatus.COMPLETE
    assert report.incomplete_reasons and report.usage == []
    assert report.accounted_cost_usd_exact == "0"
    assert report.maximum_assurance is not None
    assert report.maximum_assurance.required is expected
    assert report.maximum_assurance.requested is False
    assert report.maximum_assurance.status is not MaximumAssuranceStatus.COMPLETE
    assert report.maximum_assurance.downgrade_allowed is allow_downgrade
    assert report.maximum_assurance.downgraded is (expected and allow_downgrade)
    taxonomy_gate = next(
        gate
        for gate in report.quality_gates
        if gate.gate == "known_issue_taxonomy_critical_disposition"
    )
    assert taxonomy_gate.required is expected
    assert report.taxonomy_coverage is not None
    assert taxonomy_gate.passed is report.taxonomy_coverage.critical_gate_passed is False
    if expected:
        if allow_downgrade:
            assert report.maximum_assurance.status is MaximumAssuranceStatus.DOWNGRADED
            assert report.maximum_assurance.downgrade_reasons
        else:
            assert report.maximum_assurance.status in {
                MaximumAssuranceStatus.FAILED,
                MaximumAssuranceStatus.INCONCLUSIVE,
            }
            assert report.maximum_assurance.downgrade_reasons == []
        clauses = {item.engine: item for item in report.maximum_assurance.requirements}
        assert clauses["maximum_assurance_profile"].passed is False
        assert clauses["full_pipeline_mode"].passed is False
        assert clauses["known_issue_taxonomy_critical_disposition"].required is True
        assert clauses["known_issue_taxonomy_critical_disposition"].passed is False
        tampered = report.model_dump(mode="json")
        for gate in tampered["quality_gates"]:
            if gate["gate"] == taxonomy_gate.gate:
                gate["required"] = False
        with pytest.raises(ValidationError, match="taxonomy quality gate differs"):
            AuditReport.model_validate_json(json.dumps(tampered))
    else:
        assert report.maximum_assurance.status is MaximumAssuranceStatus.NOT_REQUESTED
    persisted = AuditReport.model_validate_json(
        (result.run_dir / "final-findings.json").read_text()
    )
    assert persisted == report and persisted.completed is False
    validate_manifest_artifacts(
        load_run_evidence_manifest(result.run_dir / "run-evidence-manifest.json"), result.run_dir
    )
    sarif = json.loads((result.run_dir / "audit-results.sarif").read_text())["runs"][0]
    assert sarif["properties"]["completed"] is False
    assert sarif["properties"]["runStatus"] == report.run_status.value
    if expected:
        markdown = (result.run_dir / "audit-report.md").read_text()
        assert (
            f"Maximum-assurance contract status: **{report.maximum_assurance.status.value}**"
            in markdown
        )
    assert audit.config.model_dump_json() == before
    assert (audit.repo_input / "ControlB.sol").read_bytes() == source
    assert audit.client is None and audit.api_key == ""
    assert audit._run_log_handler is None


@pytest.mark.asyncio
@pytest.mark.parametrize("configured", [False, True])
async def test_reused_pipeline_resolves_each_run_without_retaining_the_previous_requirement(
    tmp_path, config_factory, monkeypatch, configured
):
    audit = _pipeline(tmp_path, config_factory, configured=configured, language="solidity-evm")
    before = audit.config.model_dump_json()
    results = []

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: run-policy reuse control cannot execute or connect")

    with monkeypatch.context() as patch:
        patch.setattr(subprocess, "Popen", forbidden)
        patch.setattr(shutil, "which", forbidden)
        patch.setattr(socket, "socket", forbidden)
        patch.setattr(discovery, "_git_commit", lambda root: None)
        for option, expected in ((True, True), (False, False), (None, configured)):
            result = await audit.run(scanner_only=True, require_maximum_assurance=option)
            assert result.report.maximum_assurance.required is expected
            gate = next(
                gate
                for gate in result.report.quality_gates
                if gate.gate == "known_issue_taxonomy_critical_disposition"
            )
            assert gate.required is expected and gate.passed is False
            assert result.report.completed is False and result.report.usage == []
            assert audit.config.model_dump_json() == before
            assert audit._run_log_handler is None
            results.append(result)
    assert len({result.run_dir for result in results}) == 3
    for result in results:
        persisted = AuditReport.model_validate_json(
            (result.run_dir / "final-findings.json").read_text()
        )
        assert persisted == result.report
        validate_manifest_artifacts(
            load_run_evidence_manifest(result.run_dir / "run-evidence-manifest.json"),
            result.run_dir,
        )
