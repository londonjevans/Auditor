from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

import mmaudit.release_io as release_io_module
import mmaudit.release_runtime as release_runtime_module
from mmaudit.release_collection import (
    RELEASE_COLLECTION_BLOCKER,
    ReleaseCollectionUnavailableError,
    collect_release_report,
)
from scripts import generate_release_report


def _collection_arguments(tmp_path: Path) -> dict[str, Path | str]:
    return {
        "release_id": "candidate-1",
        "release_repository_root": tmp_path / "release",
        "target_repository_root": tmp_path / "target",
        "configuration_root": tmp_path / "configuration",
        "emitted_run_dir": tmp_path / "run",
        "artifact_evidence_path": tmp_path / "artifact-evidence.json",
        "run_verification_path": tmp_path / "verification.json",
        "publication_root": tmp_path / "published-release",
    }


def test_collection_fails_before_top_directory_adoption_or_any_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    victim = tmp_path / "top-victim"
    victim.mkdir()
    keep = victim / "keep"
    keep.write_text("must survive\n", encoding="utf-8")
    mkdir_calls: list[tuple[object, ...]] = []
    gate = Mock()
    write = Mock()
    forbidden_io = Mock(side_effect=AssertionError("collection attempted a side effect"))

    def adopt_top_victim(*args: object, **kwargs: object) -> None:
        mkdir_calls.append((*args, kwargs))
        victim.rename(tmp_path / "adopted-top-victim")

    with monkeypatch.context() as guard:
        guard.setattr(os, "mkdir", adopt_top_victim)
        guard.setattr(os, "open", forbidden_io)
        guard.setattr(os, "rename", forbidden_io)
        guard.setattr(os, "replace", forbidden_io)
        guard.setattr(os, "unlink", forbidden_io)
        guard.setattr(Path, "open", forbidden_io)
        guard.setattr(Path, "write_bytes", forbidden_io)
        guard.setattr(Path, "write_text", forbidden_io)
        guard.setattr(Path, "rename", forbidden_io)
        guard.setattr(Path, "replace", forbidden_io)
        guard.setattr(Path, "unlink", forbidden_io)
        guard.setattr(subprocess, "run", forbidden_io)
        guard.setattr(subprocess, "Popen", forbidden_io)
        guard.setattr(release_runtime_module, "execute_local_release_gate", gate)
        guard.setattr(release_io_module, "write_json_evidence", write)

        with pytest.raises(ReleaseCollectionUnavailableError, match="same-EUID name adoption"):
            collect_release_report(**_collection_arguments(tmp_path))

    assert mkdir_calls == []
    forbidden_io.assert_not_called()
    gate.assert_not_called()
    write.assert_not_called()
    assert keep.read_text(encoding="utf-8") == "must survive\n"
    assert not (tmp_path / "published-release").exists()


def test_collection_fails_before_child_directory_adoption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    victim = tmp_path / "child-victim"
    victim.mkdir()
    keep = victim / "keep"
    keep.write_text("must survive\n", encoding="utf-8")
    mkdir_calls: list[tuple[object, ...]] = []

    def adopt_child_victim(*args: object, **kwargs: object) -> None:
        mkdir_calls.append((*args, kwargs))
        victim.rename(tmp_path / "adopted-child-victim")

    monkeypatch.setattr(os, "mkdir", adopt_child_victim)

    with pytest.raises(ReleaseCollectionUnavailableError, match="same-EUID name adoption"):
        collect_release_report(**_collection_arguments(tmp_path))

    assert mkdir_calls == []
    assert keep.read_text(encoding="utf-8") == "must survive\n"
    assert not (tmp_path / "published-release").exists()
    assert not (tmp_path / "evidence").exists()
    assert not (tmp_path / "report").exists()


def test_generator_cli_reports_collection_technical_blocker(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit, match="2"):
        generate_release_report.main(
            [
                "--release-id",
                "candidate-1",
                "--release-repository",
                str(tmp_path / "release"),
                "--target-repository",
                str(tmp_path / "target"),
                "--configuration-root",
                str(tmp_path / "configuration"),
                "--run-dir",
                str(tmp_path / "run"),
                "--artifact-evidence-file",
                str(tmp_path / "artifact.json"),
                "--run-verification-file",
                str(tmp_path / "verification.json"),
                "--publication-root",
                str(tmp_path / "published-release"),
            ]
        )

    captured = capsys.readouterr()
    assert RELEASE_COLLECTION_BLOCKER in captured.err
    assert "published" not in captured.out


def test_generator_success_projection_does_not_claim_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    snapshot = Mock(
        snapshot_sha256="a" * 64,
        report=Mock(status=Mock(value="blocked"), passed_gates=0, total_gates=12),
    )
    monkeypatch.setattr(
        generate_release_report, "collect_release_report", Mock(return_value=snapshot)
    )

    generate_release_report.main(
        [
            "--release-id",
            "candidate-1",
            "--release-repository",
            str(tmp_path / "release"),
            "--target-repository",
            str(tmp_path / "target"),
            "--configuration-root",
            str(tmp_path / "configuration"),
            "--run-dir",
            str(tmp_path / "run"),
            "--artifact-evidence-file",
            str(tmp_path / "artifact.json"),
            "--run-verification-file",
            str(tmp_path / "verification.json"),
            "--publication-root",
            str(tmp_path / "published-release"),
        ]
    )

    captured = capsys.readouterr()
    assert "release snapshot validated:" in captured.out
    assert "atomically published" not in captured.out
    assert "published" not in captured.out


@pytest.mark.parametrize("value", ("", "../release", "not valid", "é"))
def test_generator_cli_rejects_invalid_release_id(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError, match="release ID"):
        generate_release_report._release_id(value)
