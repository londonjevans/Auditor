from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.benchmark.certificate import (
    BenchmarkCertificate,
    BenchmarkCertificateBindingSet,
    BenchmarkCertificatePayload,
    CertificateMismatchKind,
    CertificateVerificationStatus,
    bind_certificate_file,
    bind_certificate_projection,
    load_benchmark_certificate,
    seal_benchmark_certificate,
    verify_benchmark_certificate,
    write_benchmark_certificate,
)
from mmaudit.models.schemas import AuditProfile
from mmaudit.orchestration.manifest import canonical_sha256

COMMIT = "a" * 40


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


def _report_binding():
    return bind_certificate_projection(
        "benchmark-report",
        {"status": "passed", "gates": [{"name": "synthetic", "passed": True}]},
    )


def _certificate():
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
