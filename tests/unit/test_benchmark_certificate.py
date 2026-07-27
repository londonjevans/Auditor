from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.benchmark.certificate import (
    BenchmarkCertificate,
    BenchmarkCertificateBindingSet,
    BenchmarkCertificateFileInputs,
    BenchmarkCertificatePayload,
    BenchmarkCertificateVerification,
    CertificateComponentBinding,
    CertificateMismatchKind,
    CertificateVerificationOrigin,
    CertificateVerificationStatus,
    bind_certificate_file,
    bind_certificate_projection,
    build_file_backed_benchmark_certificate,
    load_benchmark_certificate,
    observe_file_backed_certificate,
    seal_benchmark_certificate,
    verify_benchmark_certificate,
    verify_file_backed_benchmark_certificate,
    write_benchmark_certificate,
)
from mmaudit.benchmark.engine import (
    BenchmarkBlindingProtocol,
    BenchmarkGate,
    BenchmarkReport,
    BenchmarkRepositoryMetrics,
    BenchmarkStatus,
)
from mmaudit.benchmark.mutations import (
    MutationKind,
    MutationPropertyOutcome,
    MutationTestOutcome,
    score_mutation_outcomes,
)
from mmaudit.models.schemas import AuditProfile
from mmaudit.orchestration.manifest import canonical_sha256

COMMIT = "a" * 40
PROPERTY_ID = "prop-" + ("a" * 24)


def _bindings(*, configuration_value: str = "base") -> BenchmarkCertificateBindingSet:
    return BenchmarkCertificateBindingSet(
        configuration=[
            bind_certificate_projection(
                "config/full",
                {"profile": configuration_value},
            )
        ],
        prompts=[
            bind_certificate_projection("prompt/discovery", {"template": "discover"}),
            bind_certificate_projection("prompt/verification", {"template": "verify"}),
        ],
        models=[
            bind_certificate_projection(
                "model/root-lineage-a",
                {"model": "synthetic-model", "lineage": "lineage-a"},
            )
        ],
        tools=[
            bind_certificate_projection(
                "tool/scanner",
                {"name": "synthetic-scanner", "version": "1.0", "sha256": "b" * 64},
            )
        ],
        compilers=[
            bind_certificate_projection(
                "compiler/solc",
                {"version": "0.8.30", "sha256": "c" * 64},
            )
        ],
        corpus=[
            bind_certificate_projection(
                "corpus/manifest",
                {"name": "synthetic-corpus", "cases": ["unsafe", "safe"]},
            )
        ],
        ground_truth=[
            bind_certificate_projection(
                "ground-truth/blinded",
                {"case_hashes": ["d" * 64, "e" * 64]},
            )
        ],
    )


def _report_binding() -> CertificateComponentBinding:
    return bind_certificate_projection(
        "benchmark-report",
        {"status": "passed", "gates": [{"name": "synthetic", "passed": True}]},
    )


def _certificate() -> BenchmarkCertificate:
    return seal_benchmark_certificate(
        BenchmarkCertificatePayload(
            certificate_id="synthetic-certificate",
            benchmark_name="Synthetic defensive benchmark",
            profile=AuditProfile.MAXIMUM_ASSURANCE,
            repository_git_commit=COMMIT,
            bindings=_bindings(),
            benchmark_report=_report_binding(),
        )
    )


def _benchmark_report(
    *,
    status: BenchmarkStatus = BenchmarkStatus.PASSED,
    gates: list[BenchmarkGate] | None = None,
    profile: AuditProfile = AuditProfile.MAXIMUM_ASSURANCE,
) -> BenchmarkReport:
    passed = status is BenchmarkStatus.PASSED
    mutation_scorecard = (
        score_mutation_outcomes(
            property_corpus_hash="d" * 64,
            expected_property_ids=[PROPERTY_ID],
            property_repositories={PROPERTY_ID: "synthetic_repository"},
            outcomes=[
                MutationPropertyOutcome(
                    mutation_id="mut-accounting",
                    mutation_kind=MutationKind.ACCOUNTING_OPERATOR_REPLACEMENT,
                    property_id=PROPERTY_ID,
                    outcome=MutationTestOutcome.KILLED,
                    evidence_sha256="e" * 64,
                )
            ],
            minimum_property_kill_score=1,
        )
        if profile is AuditProfile.MAXIMUM_ASSURANCE
        else None
    )
    repository_metrics = BenchmarkRepositoryMetrics(
        repository_id="synthetic_repository",
        report_loaded=True,
        vulnerable_cases=1,
        vulnerable_cases_detected=int(passed),
        recall=float(passed),
        critical_cases=1,
        critical_cases_detected=int(passed),
        critical_recall=float(passed),
        safe_cases=1,
        safe_false_confirmations=0,
        safe_false_confirmation_rate=0,
        location_cases=1,
        exact_locations=int(passed),
        location_accuracy=float(passed),
        vulnerable_cases_reproduced=int(passed),
        reproduction_success_rate=float(passed),
        mutation_property_ids=([PROPERTY_ID] if mutation_scorecard is not None else []),
        mutation_kill_score=(1.0 if mutation_scorecard is not None else None),
        mutation_gate_passed=(True if mutation_scorecard is not None else None),
        cost_usd=0,
        total_tokens=0,
    )
    default_gates = [
        BenchmarkGate(
            name="synthetic_gate",
            passed=passed,
            detail="synthetic benchmark gate",
        )
    ]
    if profile is AuditProfile.MAXIMUM_ASSURANCE:
        default_gates.extend(
            [
                BenchmarkGate(
                    name="maximum_assurance_property_mutation_score",
                    passed=True,
                    detail="synthetic property mutation score passed",
                ),
                BenchmarkGate(
                    name="maximum_assurance_repository_mutation_score",
                    passed=True,
                    detail="synthetic repository mutation score passed",
                ),
            ]
        )
    return BenchmarkReport(
        corpus_name="Synthetic file-backed benchmark",
        corpus_sha256="a" * 64,
        blinding=BenchmarkBlindingProtocol(),
        profile=profile,
        status=status,
        reports_expected=1,
        reports_loaded=1,
        vulnerable_cases=1,
        vulnerable_cases_detected=int(passed),
        vulnerable_cases_reproduced=int(passed),
        critical_cases=1,
        critical_cases_detected=int(passed),
        safe_cases=1,
        safe_high_critical_confirmations=0,
        evidence_cap_bypasses=0,
        reports_missing_coverage=0,
        model_only_findings_kept_below_confirmed=0,
        recall=float(passed),
        recall_by_severity={"critical": float(passed)},
        critical_recall=float(passed),
        precision=float(passed),
        false_positive_rate=0,
        safe_false_confirmation_rate=0,
        reproduction_success_rate=float(passed),
        location_cases=1,
        exact_locations=int(passed),
        location_accuracy=float(passed),
        total_cost_usd=0,
        total_tokens=0,
        mutation_scorecard=mutation_scorecard,
        repository_metrics=[repository_metrics],
        case_results=[],
        gates=(gates if gates is not None else default_gates),
        limitations=[],
    )


def _empty_benchmark_report() -> BenchmarkReport:
    payload = _benchmark_report(profile=AuditProfile.STANDARD).model_dump(mode="json")
    payload.update(
        {
            "reports_expected": 0,
            "reports_loaded": 0,
            "vulnerable_cases": 0,
            "vulnerable_cases_detected": 0,
            "vulnerable_cases_reproduced": 0,
            "critical_cases": 0,
            "critical_cases_detected": 0,
            "safe_cases": 0,
            "safe_high_critical_confirmations": 0,
            "recall": 0,
            "critical_recall": 0,
            "precision": 0,
            "reproduction_success_rate": 0,
            "location_cases": 0,
            "exact_locations": 0,
            "location_accuracy": 0,
            "repository_metrics": [],
        }
    )
    return BenchmarkReport.model_validate(payload)


def _write_file_backed_components(
    tmp_path: Path,
    report: BenchmarkReport,
) -> tuple[Path, BenchmarkCertificateFileInputs]:
    component_root = tmp_path / "components"
    component_root.mkdir()
    contents = {
        "mmaudit.toml": 'profile = "maximum-assurance"\n',
        "prompt.md": "Synthetic defensive prompt.\n",
        "models.json": '{"lineage":"synthetic-a"}\n',
        "tools.json": '{"scanner":"synthetic","version":"1"}\n',
        "compilers.json": '{"compiler":"solc","version":"0.8.30"}\n',
        "corpus.json": '{"cases":["unsafe","safe"]}\n',
        "ground-truth.json": '{"case_hashes":["aaaaaaaa"]}\n',
        "benchmark-results.json": report.model_dump_json(),
    }
    for name, content in contents.items():
        (component_root / name).write_text(content, encoding="utf-8")
    return (
        component_root,
        BenchmarkCertificateFileInputs(
            configuration=["mmaudit.toml"],
            prompts=["prompt.md"],
            models=["models.json"],
            tools=["tools.json"],
            compilers=["compilers.json"],
            corpus=["corpus.json"],
            ground_truth=["ground-truth.json"],
            benchmark_report="benchmark-results.json",
        ),
    )


def _write_file_backed_certificate(
    tmp_path: Path,
) -> tuple[Path, Path, BenchmarkCertificate]:
    component_root, inputs = _write_file_backed_components(
        tmp_path,
        _benchmark_report(),
    )
    certificate = build_file_backed_benchmark_certificate(
        component_root=component_root,
        inputs=inputs,
        repository_git_commit=COMMIT,
        certificate_id="file-backed-certificate",
    )
    certificate_path = tmp_path / "benchmark-certificate.json"
    write_benchmark_certificate(certificate_path, certificate)
    return component_root, certificate_path, certificate


def test_certificate_round_trip_and_current_verification_are_deterministic(
    tmp_path: Path,
) -> None:
    certificate = _certificate()
    second = _certificate()
    path = tmp_path / "benchmark-certificate.json"

    write_benchmark_certificate(path, certificate)
    loaded = load_benchmark_certificate(path)
    first_verification = verify_benchmark_certificate(
        loaded,
        repository_git_commit=COMMIT,
        bindings=_bindings(),
        benchmark_report=_report_binding(),
    )
    second_verification = verify_benchmark_certificate(
        second,
        repository_git_commit=COMMIT,
        bindings=_bindings(),
        benchmark_report=_report_binding(),
    )

    assert loaded == certificate == second
    assert loaded.bindings_sha256
    assert loaded.certificate_sha256
    assert first_verification == second_verification
    assert first_verification.status is CertificateVerificationStatus.CURRENT
    assert first_verification.mismatches == []
    assert first_verification.observed_bindings_sha256 == loaded.bindings_sha256
    assert first_verification.origin is CertificateVerificationOrigin.IN_MEMORY
    assert first_verification.file_backed_evidence is None


def test_file_backed_verification_attests_exact_loaded_passed_report(
    tmp_path: Path,
) -> None:
    component_root, certificate_path, certificate = _write_file_backed_certificate(tmp_path)

    verification = verify_file_backed_benchmark_certificate(
        certificate_path,
        component_root=component_root,
        repository_git_commit=COMMIT,
    )

    assert verification.status is CertificateVerificationStatus.CURRENT
    assert verification.origin is CertificateVerificationOrigin.FILE_BACKED
    assert verification.file_backed_evidence is not None
    evidence = verification.file_backed_evidence
    assert evidence.certificate_loaded is True
    assert (
        evidence.certificate_file_sha256
        == hashlib.sha256(certificate_path.read_bytes()).hexdigest()
    )
    assert evidence.benchmark_report_loaded is True
    assert (
        evidence.benchmark_report_file_sha256
        == hashlib.sha256((component_root / "benchmark-results.json").read_bytes()).hexdigest()
    )
    assert evidence.benchmark_report_status == "passed"
    assert evidence.benchmark_report_gate_count == 3
    assert evidence.benchmark_name == "Synthetic file-backed benchmark"
    assert evidence.benchmark_profile is AuditProfile.MAXIMUM_ASSURANCE
    assert evidence.benchmark_reports_expected == 1
    assert evidence.benchmark_reports_loaded == 1
    assert verification.certificate_sha256 == certificate.certificate_sha256
    assert (
        BenchmarkCertificateVerification.model_validate_json(verification.model_dump_json())
        == verification
    )


def test_legacy_hand_constructed_current_verification_remains_non_file_backed() -> None:
    payload = {
        "schema_version": "1.0",
        "certificate_sha256": "a" * 64,
        "status": "current",
        "observed_repository_git_commit": COMMIT,
        "observed_bindings_sha256": "b" * 64,
        "mismatches": [],
    }
    payload["verification_sha256"] = canonical_sha256(payload)

    verification = BenchmarkCertificateVerification.model_validate(payload)
    round_tripped = BenchmarkCertificateVerification.model_validate_json(
        verification.model_dump_json()
    )

    assert verification.status is CertificateVerificationStatus.CURRENT
    assert verification.origin is CertificateVerificationOrigin.IN_MEMORY
    assert verification.file_backed_evidence is None
    assert round_tripped == verification


@pytest.mark.parametrize(
    "report",
    [
        pytest.param(
            _benchmark_report(
                gates=[],
                profile=AuditProfile.STANDARD,
            ),
            id="empty_gate_evidence",
        ),
        pytest.param(
            _empty_benchmark_report(),
            id="empty_loaded_reports",
        ),
        pytest.param(
            _benchmark_report(
                status=BenchmarkStatus.FAILED,
                gates=[
                    BenchmarkGate(
                        name="synthetic_gate",
                        passed=False,
                        detail="synthetic failed gate",
                    )
                ],
                profile=AuditProfile.STANDARD,
            ),
            id="failed_report",
        ),
    ],
)
def test_file_backed_verification_rejects_empty_or_failed_report(
    tmp_path: Path,
    report: BenchmarkReport,
) -> None:
    component_root, certificate_path, original = _write_file_backed_certificate(tmp_path)
    (component_root / "benchmark-results.json").write_text(
        report.model_dump_json(),
        encoding="utf-8",
    )
    observed_bindings, observed_report = observe_file_backed_certificate(
        original,
        component_root=component_root,
    )
    manually_resealed = seal_benchmark_certificate(
        BenchmarkCertificatePayload(
            certificate_id=original.certificate_id,
            benchmark_name=report.corpus_name,
            profile=report.profile,
            repository_git_commit=original.repository_git_commit,
            bindings=observed_bindings,
            benchmark_report=observed_report,
        )
    )
    write_benchmark_certificate(certificate_path, manually_resealed)

    with pytest.raises(
        ValueError,
        match="requires a passed report and passed gates",
    ):
        verify_file_backed_benchmark_certificate(
            certificate_path,
            component_root=component_root,
            repository_git_commit=COMMIT,
        )


def test_file_backed_origin_requires_loaded_file_evidence() -> None:
    verification = verify_benchmark_certificate(
        _certificate(),
        repository_git_commit=COMMIT,
        bindings=_bindings(),
        benchmark_report=_report_binding(),
    )
    payload = verification.model_dump(mode="json", exclude={"verification_sha256"})
    payload["origin"] = CertificateVerificationOrigin.FILE_BACKED
    payload["verification_sha256"] = canonical_sha256(payload)

    with pytest.raises(ValidationError, match="requires exact loaded-file evidence"):
        BenchmarkCertificateVerification.model_validate(payload)


def test_certificate_rejects_component_and_envelope_tampering() -> None:
    certificate = _certificate()
    component_tamper = certificate.model_dump(mode="json")
    component_tamper["bindings"]["prompts"][0]["sha256"] = "f" * 64

    with pytest.raises(ValidationError, match="component hash"):
        BenchmarkCertificate.model_validate(component_tamper)

    envelope_tamper = certificate.model_dump(mode="json")
    envelope_tamper["benchmark_name"] = "Tampered benchmark label"
    envelope_tamper["bindings_sha256"] = canonical_sha256(
        {
            "repository_git_commit": envelope_tamper["repository_git_commit"],
            "bindings": envelope_tamper["bindings"],
            "benchmark_report": envelope_tamper["benchmark_report"],
        }
    )
    with pytest.raises(ValidationError, match="self-hash"):
        BenchmarkCertificate.model_validate(envelope_tamper)


def test_certificate_verification_reports_commit_changed_missing_and_unexpected() -> None:
    certificate = _certificate()
    observed = _bindings(configuration_value="changed")
    observed.prompts = observed.prompts[:1]
    observed.tools = sorted(
        [
            *observed.tools,
            bind_certificate_projection("tool/second", {"version": "2.0"}),
        ],
        key=lambda item: item.identifier,
    )

    result = verify_benchmark_certificate(
        certificate,
        repository_git_commit="b" * 40,
        bindings=observed,
        benchmark_report=_report_binding(),
    )

    assert result.status is CertificateVerificationStatus.STALE
    assert {(item.category, item.identifier, item.kind) for item in result.mismatches} == {
        ("configuration", "config/full", CertificateMismatchKind.CHANGED),
        ("prompts", "prompt/verification", CertificateMismatchKind.MISSING),
        ("repository", "git-commit", CertificateMismatchKind.GIT_COMMIT),
        ("tools", "tool/second", CertificateMismatchKind.UNEXPECTED),
    }
    assert result.verification_sha256

    tampered = result.model_dump(mode="json")
    tampered["status"] = "current"
    with pytest.raises(ValidationError, match="status"):
        type(result).model_validate(tampered)


def test_file_binding_and_certificate_paths_are_contained_and_non_linked(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    component = root / "config.toml"
    component.write_text('profile = "maximum-assurance"\n', encoding="utf-8")

    binding = bind_certificate_file(
        root,
        "config.toml",
        identifier="config/file",
    )

    assert binding.path == "config.toml"
    assert binding.size == component.stat().st_size
    assert binding.sha256
    with pytest.raises(ValueError, match="unsafe repository-relative path"):
        bind_certificate_file(root, "../outside", identifier="config/traversal")
    (root / ".env").write_text("SYNTHETIC=not-a-secret\n", encoding="utf-8")
    with pytest.raises(ValueError, match="sensitive"):
        bind_certificate_file(root, ".env", identifier="config/sensitive")

    linked = root / "linked.toml"
    try:
        linked.symlink_to(component)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="links"):
        bind_certificate_file(root, "linked.toml", identifier="config/link")


def test_file_binding_rejects_hardlinks_and_certificate_loader_rejects_links(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    component = root / "corpus.json"
    component.write_text("{}\n", encoding="utf-8")
    hardlink = root / "ground-truth.json"
    try:
        os.link(component, hardlink)
    except OSError:
        pytest.skip("hardlinks unavailable")

    with pytest.raises(ValueError, match="unique regular files"):
        bind_certificate_file(root, "corpus.json", identifier="corpus/file")

    certificate_path = tmp_path / "benchmark-certificate.json"
    write_benchmark_certificate(certificate_path, _certificate())
    certificate_link = tmp_path / "linked-certificate.json"
    try:
        certificate_link.symlink_to(certificate_path)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="non-link"):
        load_benchmark_certificate(certificate_link)


def test_binding_categories_are_required_sorted_and_strict() -> None:
    dumped = _bindings().model_dump(mode="json")
    dumped["prompts"] = list(reversed(dumped["prompts"]))
    with pytest.raises(ValidationError, match="unique and sorted"):
        BenchmarkCertificateBindingSet.model_validate(dumped)

    missing = _bindings().model_dump(mode="json")
    missing["ground_truth"] = []
    with pytest.raises(ValidationError):
        BenchmarkCertificateBindingSet.model_validate(missing)

    certificate = _certificate().model_dump(mode="json")
    certificate["rpc_url"] = "http://127.0.0.1:8545"
    with pytest.raises(ValidationError, match="Extra inputs"):
        BenchmarkCertificate.model_validate(certificate)


def test_published_certificate_schema_is_strict_and_bounded() -> None:
    schema_path = (
        Path(__file__).resolve().parents[2] / "schemas" / "benchmark_certificate.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    assert schema["additionalProperties"] is False
    assert schema["$defs"]["componentBinding"]["additionalProperties"] is False
    assert schema["$defs"]["bindingSet"]["additionalProperties"] is False
    assert schema["$defs"]["bindingSet"]["required"] == [
        "configuration",
        "prompts",
        "models",
        "tools",
        "compilers",
        "corpus",
        "ground_truth",
    ]
    assert schema["$defs"]["bindingSet"]["properties"]["ground_truth"] == {
        "$ref": "#/$defs/componentList"
    }
    assert schema["$defs"]["componentList"]["minItems"] == 1
    assert schema["properties"]["certificate_sha256"]["pattern"] == "^[0-9a-f]{64}$"
