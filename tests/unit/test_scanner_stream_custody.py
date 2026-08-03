from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

import pytest

from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
    Severity,
)
from mmaudit.orchestration import manifest as manifest_module
from mmaudit.orchestration.manifest import _validate_scanner_stream_artifact_custody
from mmaudit.scanners.base import scanner_fingerprint
from mmaudit.scanners.normalization import (
    reparse_trusted_scanner_stdout,
    validate_real_scanner_normalization_replay,
)

_NOW = datetime(2026, 8, 3, tzinfo=UTC)


def _run(
    scanner: str,
    *,
    status: ScannerStatus = ScannerStatus.SUCCESS,
    stdout: tuple[str, bytes] | None = None,
    stderr: tuple[str, bytes] | None = None,
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.UNVERIFIED,
    findings: list[ScannerFinding] | None = None,
    process_exit_code: int | None = None,
    machine_output_validated: bool = False,
) -> ScannerRun:
    stdout_path, stdout_bytes = stdout or (None, b"")
    stderr_path, stderr_bytes = stderr or (None, b"")
    return ScannerRun(
        scanner=scanner,
        status=status,
        execution_evidence=execution_evidence,
        started_at=_NOW,
        finished_at=_NOW,
        duration_seconds=0,
        findings=findings or [],
        raw_output_path=stdout_path,
        raw_output_sha256=(
            hashlib.sha256(stdout_bytes).hexdigest() if stdout_path is not None else None
        ),
        raw_output_bytes=len(stdout_bytes),
        private_stderr_path=stderr_path,
        private_stderr_sha256=(
            hashlib.sha256(stderr_bytes).hexdigest() if stderr_path is not None else None
        ),
        private_stderr_bytes=len(stderr_bytes),
        process_exit_code=process_exit_code,
        machine_output_validated=machine_output_validated,
    )


def _semgrep_stdout() -> bytes:
    return json.dumps(
        {
            "results": [
                {
                    "check_id": "synthetic.accounting-check",
                    "path": "app.py",
                    "start": {"line": 3, "col": 1},
                    "end": {"line": 3, "col": 12},
                    "extra": {
                        "message": "Synthetic unsafe condition",
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-682"]},
                    },
                }
            ],
            "errors": [],
        },
        separators=(",", ":"),
    ).encode()


def _real_semgrep_run(root: Path, stdout: bytes) -> ScannerRun:
    workspace = root / "private" / "scanner-output" / "semgrep" / "workspace"
    findings = list(
        reparse_trusted_scanner_stdout(
            scanner="semgrep",
            repository_root=workspace,
            retained_stdout=stdout,
        )
    )
    return _run(
        "semgrep",
        stdout=("semgrep/output.json", stdout),
        execution_evidence=ExecutionEvidenceKind.REAL,
        findings=findings,
        process_exit_code=0,
        machine_output_validated=True,
    )


def _scanner_root(root: Path) -> Path:
    result = root / "private" / "scanner-output"
    result.mkdir(parents=True)
    return result


def _write_stream(root: Path, relative: str, content: bytes) -> Path:
    path = (root / "private" / "scanner-output").joinpath(*PurePosixPath(relative).parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def test_scanner_stream_custody_accepts_exact_nested_unique_artifacts(tmp_path: Path) -> None:
    root = tmp_path / "run"
    stdout = b'{"success":true}'
    stderr = b""
    _write_stream(root, "slither/machine/slither.json", stdout)
    _write_stream(root, "slither/diagnostics/slither.stderr.txt", stderr)

    authorized = _validate_scanner_stream_artifact_custody(
        root,
        [
            _run(
                "slither",
                stdout=("slither/machine/slither.json", stdout),
                stderr=("slither/diagnostics/slither.stderr.txt", stderr),
            )
        ],
    )

    assert authorized == frozenset()


def test_scanner_stream_custody_preserves_absent_stream_legacy_behavior(
    tmp_path: Path,
) -> None:
    authorized = _validate_scanner_stream_artifact_custody(
        tmp_path / "absent-run",
        [_run("slither")],
    )

    assert authorized == frozenset()


def test_scanner_stream_custody_rejects_non_nfc_claim_before_open(tmp_path: Path) -> None:
    decomposed = "e\N{COMBINING ACUTE ACCENT}vidence.json"
    claim = f"slither/{decomposed}"

    with pytest.raises(ValueError, match="exact portable NFC"):
        _validate_scanner_stream_artifact_custody(
            tmp_path / "absent-run",
            [_run("slither", stdout=(claim, b""))],
        )


def test_scanner_stream_custody_rejects_casefold_owner_collision_before_open(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="portable-name collision"):
        _validate_scanner_stream_artifact_custody(
            tmp_path / "absent-run",
            [
                _run("slither", stdout=("slither/one.json", b"one")),
                _run("SLITHER", stdout=("SLITHER/two.json", b"two")),
            ],
        )


def test_scanner_stream_custody_rejects_casefold_file_directory_prefix_collision(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="portable-name collision"):
        _validate_scanner_stream_artifact_custody(
            tmp_path / "absent-run",
            [
                _run(
                    "slither",
                    stdout=("slither/result", b"one"),
                    stderr=("slither/RESULT/stderr.txt", b"two"),
                )
            ],
        )


def test_scanner_stream_custody_requires_exact_owner_spelling(tmp_path: Path) -> None:
    root = tmp_path / "run"
    payload = b"{}"
    _write_stream(root, "ExactOwner/output.json", payload)

    with pytest.raises(ValueError, match="owner spelling"):
        _validate_scanner_stream_artifact_custody(
            root,
            [_run("exactowner", stdout=("exactowner/output.json", payload))],
        )


def test_scanner_stream_custody_rejects_duplicate_opened_owner_identity(
    tmp_path: Path,
) -> None:
    root = tmp_path / "run"
    first = b"first"
    second = b"second"
    _write_stream(root, "slither/first.json", first)
    _write_stream(root, "slither/second.json", second)

    with pytest.raises(ValueError, match="owner identity"):
        _validate_scanner_stream_artifact_custody(
            root,
            [
                _run("slither", stdout=("slither/first.json", first)),
                _run("slither", stdout=("slither/second.json", second)),
            ],
        )


def test_scanner_stream_custody_rejects_duplicate_opened_stream_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "run"
    stdout = b"stdout"
    stderr = b"stderr"
    _write_stream(root, "slither/output.json", stdout)
    _write_stream(root, "slither/output.stderr.txt", stderr)
    original = manifest_module._open_scanner_stream_observation

    @contextmanager
    def duplicate_identity(
        path: Path,
        *,
        parent_descriptor: int,
        component: str,
        label: str,
    ) -> Iterator[tuple[str, int, tuple[int, int], bytes]]:
        with original(
            path,
            parent_descriptor=parent_descriptor,
            component=component,
            label=label,
        ) as (sha256, size, _identity, content):
            yield sha256, size, (101, 202), content

    monkeypatch.setattr(
        manifest_module,
        "_open_scanner_stream_observation",
        duplicate_identity,
    )

    with pytest.raises(ValueError, match="stream identity"):
        _validate_scanner_stream_artifact_custody(
            root,
            [
                _run(
                    "slither",
                    stdout=("slither/output.json", stdout),
                    stderr=("slither/output.stderr.txt", stderr),
                )
            ],
        )


def test_scanner_stream_custody_rejects_hardlinked_streams(tmp_path: Path) -> None:
    root = tmp_path / "run"
    payload = b"shared"
    stdout = _write_stream(root, "slither/output.json", payload)
    stderr = stdout.with_name("output.stderr.txt")
    os.link(stdout, stderr)

    with pytest.raises(ValueError, match="bounded unique regular file"):
        _validate_scanner_stream_artifact_custody(
            root,
            [
                _run(
                    "slither",
                    stdout=("slither/output.json", payload),
                    stderr=("slither/output.stderr.txt", payload),
                )
            ],
        )


def test_scanner_stream_custody_rejects_path_replacement_while_descriptor_is_held(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "run"
    payload = b"fixed machine output"
    stream = _write_stream(root, "slither/output.json", payload)
    replacement = stream.with_name("replacement.json")
    replacement.write_bytes(payload)
    original_read = os.read
    replaced = False

    def replace_after_read(descriptor: int, count: int) -> bytes:
        nonlocal replaced
        content = original_read(descriptor, count)
        if content and not replaced:
            replaced = True
            os.replace(replacement, stream)
        return content

    monkeypatch.setattr(os, "read", replace_after_read)

    with pytest.raises(ValueError, match="changed while it was read"):
        _validate_scanner_stream_artifact_custody(
            root,
            [_run("slither", stdout=("slither/output.json", payload))],
        )


def test_real_success_custody_replays_builtin_output_while_descriptor_is_held(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "run"
    stdout = _semgrep_stdout()
    _write_stream(root, "semgrep/output.json", stdout)
    _write_stream(
        root, "semgrep/workspace/app.py", b"def synthetic():\n    value = 1\n    return value\n"
    )
    run = _real_semgrep_run(root, stdout)
    original_observation = manifest_module._open_scanner_stream_observation
    descriptor_held = False

    @contextmanager
    def observed(
        path: Path,
        *,
        parent_descriptor: int,
        component: str,
        label: str,
    ) -> Iterator[tuple[str, int, tuple[int, int], bytes]]:
        nonlocal descriptor_held
        with original_observation(
            path,
            parent_descriptor=parent_descriptor,
            component=component,
            label=label,
        ) as observation:
            descriptor_held = True
            try:
                yield observation
            finally:
                descriptor_held = False

    def replay(
        *,
        run: ScannerRun,
        repository_root: Path,
        retained_stdout: bytes,
    ) -> tuple[ScannerFinding, ...]:
        assert descriptor_held
        return validate_real_scanner_normalization_replay(
            run=run,
            repository_root=repository_root,
            retained_stdout=retained_stdout,
        )

    monkeypatch.setattr(manifest_module, "_open_scanner_stream_observation", observed)
    monkeypatch.setattr(manifest_module, "validate_real_scanner_normalization_replay", replay)

    authorized = _validate_scanner_stream_artifact_custody(root, [run])

    assert authorized == frozenset(finding.fingerprint for finding in run.findings)


def test_real_success_custody_rejects_semantically_tampered_findings(tmp_path: Path) -> None:
    root = tmp_path / "run"
    stdout = _semgrep_stdout()
    _write_stream(root, "semgrep/output.json", stdout)
    _write_stream(root, "semgrep/workspace/app.py", b"def synthetic():\n    return 1\n")
    run = _real_semgrep_run(root, stdout)
    tampered = run.findings[0].model_copy(update={"severity": Severity.LOW})

    with pytest.raises(ValueError, match="complete normalized finding inventory"):
        _validate_scanner_stream_artifact_custody(
            root,
            [run.model_copy(update={"findings": [tampered]})],
        )


@pytest.mark.parametrize("scanner", ["codeql", "custom", "foundry_fork"])
def test_real_success_custody_retains_empty_unsupported_stream_without_authority(
    tmp_path: Path,
    scanner: str,
) -> None:
    root = tmp_path / "run"
    stdout = b"{}"
    _write_stream(root, f"{scanner}/output.json", stdout)
    _write_stream(root, f"{scanner}/workspace/app.py", b"def synthetic():\n    return 1\n")
    run = _run(
        scanner,
        stdout=(f"{scanner}/output.json", stdout),
        execution_evidence=ExecutionEvidenceKind.REAL,
        process_exit_code=0,
        machine_output_validated=True,
    )

    assert _validate_scanner_stream_artifact_custody(root, [run]) == frozenset()


@pytest.mark.parametrize("scanner", ["codeql", "custom", "foundry_fork"])
def test_real_success_custody_rejects_unsupported_scanner_findings(
    tmp_path: Path,
    scanner: str,
) -> None:
    root = tmp_path / "run"
    stdout = b"{}"
    _write_stream(root, f"{scanner}/output.json", stdout)
    semgrep_stdout = _semgrep_stdout()
    _write_stream(root, "semgrep/workspace/app.py", b"def synthetic():\n    return 1\n")
    source_finding = _real_semgrep_run(root, semgrep_stdout).findings[0]
    message = "Typed suite evidence cannot mint scanner normalization authority"
    finding = source_finding.model_copy(
        update={
            "scanner": scanner,
            "rule_id": "unsupported-normalization",
            "message": message,
            "fingerprint": scanner_fingerprint(
                scanner,
                "unsupported-normalization",
                source_finding.locations[0].path,
                source_finding.locations[0].start_line,
                message,
            ),
        }
    )
    run = _run(
        scanner,
        stdout=(f"{scanner}/output.json", stdout),
        execution_evidence=ExecutionEvidenceKind.REAL,
        findings=[finding],
        process_exit_code=0,
        machine_output_validated=True,
    )

    with pytest.raises(ValueError, match="findings have no current trusted stdout"):
        _validate_scanner_stream_artifact_custody(root, [run])


@pytest.mark.parametrize(
    ("execution_evidence", "status", "process_exit_code", "machine_output_validated"),
    [
        (ExecutionEvidenceKind.UNVERIFIED, ScannerStatus.SUCCESS, 0, True),
        (ExecutionEvidenceKind.MOCK, ScannerStatus.SUCCESS, 0, True),
        (ExecutionEvidenceKind.REAL, ScannerStatus.FAILED, 1, False),
    ],
)
def test_nonqualifying_scanner_findings_remain_uncredited_raw_evidence(
    tmp_path: Path,
    execution_evidence: ExecutionEvidenceKind,
    status: ScannerStatus,
    process_exit_code: int,
    machine_output_validated: bool,
) -> None:
    root = tmp_path / "run"
    stdout = _semgrep_stdout()
    _write_stream(root, "semgrep/output.json", stdout)
    _write_stream(root, "semgrep/workspace/app.py", b"def synthetic():\n    return 1\n")
    replayed = _real_semgrep_run(root, stdout).findings
    run = _run(
        "semgrep",
        status=status,
        stdout=("semgrep/output.json", stdout),
        execution_evidence=execution_evidence,
        findings=replayed,
        process_exit_code=process_exit_code,
        machine_output_validated=machine_output_validated,
    )

    assert _validate_scanner_stream_artifact_custody(root, [run]) == frozenset()


def test_real_success_custody_rejects_missing_retained_stdout(tmp_path: Path) -> None:
    run = _run(
        "semgrep",
        execution_evidence=ExecutionEvidenceKind.REAL,
        process_exit_code=0,
        machine_output_validated=True,
    )

    with pytest.raises(ValueError, match="lacks retained stdout normalization evidence"):
        _validate_scanner_stream_artifact_custody(tmp_path / "absent-run", [run])
