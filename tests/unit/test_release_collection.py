from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import pytest

import mmaudit.release_collection as collection_module
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release import ReleaseGateId, ReleaseStatus
from mmaudit.release_collection import RELEASE_REPORT_PATH, collect_release_report
from mmaudit.release_report import ReleaseReportInputRole
from scripts import generate_release_report


def _roots(tmp_path: Path) -> dict[str, Path]:
    values = {
        "release_repository_root": tmp_path / "release",
        "target_repository_root": tmp_path / "target",
        "emitted_run_dir": tmp_path / "run",
        "evidence_root": tmp_path / "evidence",
        "report_root": tmp_path / "report",
    }
    for path in values.values():
        path.mkdir()
    values["evidence_root"].chmod(0o700)
    values["report_root"].chmod(0o700)
    return values


def _binding(path: str) -> ManifestFileBinding:
    content = path.encode()
    return ManifestFileBinding(
        path=path,
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
    )


def test_collection_executes_the_fixed_portfolio_and_authoritatively_validates(
    tmp_path: Path,
) -> None:
    roots = _roots(tmp_path)
    candidate = SimpleNamespace(observation_sha256="a" * 64)
    run = SimpleNamespace(binding_sha256="b" * 64)
    verification = SimpleNamespace(binding_sha256="c" * 64)
    static = SimpleNamespace(evidence_sha256="d" * 64)
    gate_bundle = SimpleNamespace(
        bundle_sha256="e" * 64,
        receipts=tuple(SimpleNamespace(artifact_bindings=()) for _ in ReleaseGateId),
    )
    report = SimpleNamespace(
        status=ReleaseStatus.BLOCKED_TECHNICAL,
        passed_gates=7,
        total_gates=12,
    )
    write = Mock(side_effect=lambda **kwargs: _binding(str(kwargs["relative_path"])))
    local = Mock(side_effect=lambda **kwargs: f"local:{kwargs['gate_id'].value}")
    bound_input_lengths: list[int] = []

    def collect_bound(**kwargs: object) -> str:
        bindings = kwargs["input_bindings"]
        assert isinstance(bindings, list)
        bound_input_lengths.append(len(bindings))
        gate_id = kwargs["gate_id"]
        assert isinstance(gate_id, ReleaseGateId)
        return f"bound:{gate_id.value}"

    bound = Mock(side_effect=collect_bound)
    build_bundle = Mock(return_value=gate_bundle)
    assemble = Mock(return_value=report)
    validate = Mock(return_value=report)

    with (
        patch.object(collection_module, "observe_release_candidate", return_value=candidate),
        patch.object(collection_module, "observe_release_run_binding", return_value=run),
        patch.object(
            collection_module,
            "observe_release_run_verification",
            return_value=verification,
        ),
        patch.object(collection_module, "collect_static_release_evidence", return_value=static),
        patch.object(collection_module, "write_json_evidence", write),
        patch.object(collection_module, "execute_local_release_gate", local),
        patch.object(collection_module, "collect_bound_release_gate_receipt", bound),
        patch.object(collection_module, "build_release_gate_evidence_bundle", build_bundle),
        patch.object(collection_module, "_assemble_release_gate_report", assemble),
        patch.object(collection_module, "validate_release_report_integrity", validate),
        patch.object(collection_module, "_require_exact_flat_file_inventory"),
    ):
        observed = collect_release_report(
            release_id="candidate-1",
            artifact_evidence_path=tmp_path / "artifact-evidence.json",
            run_verification_path=tmp_path / "verification.json",
            **roots,
        )

    assert observed is report
    local_ids = {item.kwargs["gate_id"] for item in local.call_args_list}
    assert local_ids == {
        ReleaseGateId.MYPY,
        ReleaseGateId.PYTEST,
        ReleaseGateId.RUFF_CHECK,
        ReleaseGateId.RUFF_FORMAT,
    }
    bound_ids = {item.kwargs["gate_id"] for item in bound.call_args_list}
    assert bound_ids == set(ReleaseGateId) - local_ids
    assert all(
        item.kwargs["candidate"] is candidate and item.kwargs["run"] is run
        for item in bound.call_args_list
    )
    assert bound_input_lengths == [4] * len(bound_ids)
    bundle_receipts = build_bundle.call_args.kwargs["receipts"]
    assert len(bundle_receipts) == len(ReleaseGateId)
    report_inputs = assemble.call_args.kwargs["input_files"]
    assert {item.role for item in report_inputs} == set(ReleaseReportInputRole)
    assert write.call_args_list[-1] == call(
        evidence_root=roots["report_root"].resolve(),
        relative_path=RELEASE_REPORT_PATH,
        value=report,
    )
    assert validate.call_args.kwargs["report_relative_path"] == RELEASE_REPORT_PATH


@pytest.mark.parametrize("output_key", ("evidence_root", "report_root"))
def test_collection_rejects_nonempty_output_roots_before_observation(
    tmp_path: Path,
    output_key: str,
) -> None:
    roots = _roots(tmp_path)
    (roots[output_key] / "preexisting.json").write_text("{}\n", encoding="utf-8")
    observer = Mock()

    with (
        patch.object(collection_module, "observe_release_candidate", observer),
        pytest.raises(ValueError, match="root must be empty"),
    ):
        collect_release_report(
            release_id="candidate-1",
            artifact_evidence_path=tmp_path / "artifact-evidence.json",
            run_verification_path=tmp_path / "verification.json",
            **roots,
        )

    observer.assert_not_called()


def test_collection_rejects_output_root_inside_the_untrusted_target(
    tmp_path: Path,
) -> None:
    roots = _roots(tmp_path)
    roots["evidence_root"].rmdir()
    roots["evidence_root"] = roots["target_repository_root"] / "evidence"
    roots["evidence_root"].mkdir()
    roots["evidence_root"].chmod(0o700)

    with pytest.raises(ValueError, match="must be disjoint"):
        collect_release_report(
            release_id="candidate-1",
            artifact_evidence_path=tmp_path / "artifact-evidence.json",
            run_verification_path=tmp_path / "verification.json",
            **roots,
        )


def test_collection_inventory_rejects_an_unbound_file(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "expected.json").write_text("{}\n", encoding="utf-8")
    (root / "undeclared.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="missing or undeclared"):
        collection_module._require_exact_flat_file_inventory(
            root,
            expected_paths={"expected.json"},
            label="release evidence",
        )


def test_generator_cli_requires_explicit_paths_and_reports_honest_status(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = SimpleNamespace(
        status=ReleaseStatus.BLOCKED_TECHNICAL,
        passed_gates=7,
        total_gates=12,
    )
    with patch.object(
        generate_release_report, "collect_release_report", return_value=report
    ) as run:
        generate_release_report.main(
            [
                "--release-id",
                "candidate-1",
                "--release-repository",
                str(tmp_path / "release"),
                "--target-repository",
                str(tmp_path / "target"),
                "--run-dir",
                str(tmp_path / "run"),
                "--artifact-evidence-file",
                str(tmp_path / "artifact.json"),
                "--run-verification-file",
                str(tmp_path / "verification.json"),
                "--evidence-root",
                str(tmp_path / "evidence"),
                "--report-root",
                str(tmp_path / "report"),
            ]
        )

    assert run.call_count == 1
    assert "release_status=blocked_technical" in capsys.readouterr().out


@pytest.mark.parametrize("value", ("", "../release", "not valid", "é"))
def test_generator_cli_rejects_invalid_release_id(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError, match="release ID"):
        generate_release_report._release_id(value)
