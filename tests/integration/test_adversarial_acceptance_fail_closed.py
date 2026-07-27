from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

from mmaudit.adversarial_acceptance import (
    AdversarialAcceptanceObservation,
    AdversarialAcceptanceReport,
    AdversarialAcceptanceStatus,
    AdversarialCaseId,
    AdversarialDisposition,
    AdversarialEvidenceKind,
    build_adversarial_acceptance_report,
    load_adversarial_acceptance_manifest,
    write_adversarial_acceptance_report,
)
from mmaudit.models.schemas import RepositoryCodeExecutionState, ScannerStatus
from mmaudit.orchestration.context import ContextBuilder, render_context
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher, normalize_relative_path
from mmaudit.repository.mapping import build_repository_map
from mmaudit.repository.workspace import validate_copyable_workspace
from mmaudit.scanners.base import ScannerAdapter
from mmaudit.solidity.compile import compile_solidity_projects
from mmaudit.solidity.projects import discover_solidity_projects

FIXTURE = Path(__file__).parents[1] / "fixtures" / "adversarial_repository"
_LIMITATION = ["real rootless containment not executed"]


class _PassthroughIsolation:
    name = "synthetic-test-isolation"

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del workspace, private_dir, rpc_port
        return command


class _FixtureScanner(ScannerAdapter):
    name = "synthetic-fixture-tool"
    executable = "semgrep"

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        del root, private_dir
        return [self.executable, "--version"]

    def parse(self, root: Path, stdout: str, private_dir: Path):
        del root, stdout, private_dir
        return []


class _BoundedTrustedScanner(ScannerAdapter):
    name = "synthetic-bounded-trusted-tool"
    executable = sys.executable

    def __init__(self, code: str, *, output_limit: int = 50_000_000) -> None:
        self.code = code
        self.max_stdout_bytes = output_limit

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        del root, private_dir
        return [self.executable, "-c", self.code]

    def parse(self, root: Path, stdout: str, private_dir: Path):
        del root, stdout, private_dir
        return []


def _copy_fixture(tmp_path: Path, name: str) -> Path:
    root = tmp_path / name
    shutil.copytree(FIXTURE, root)
    return root


def _observations() -> list[AdversarialAcceptanceObservation]:
    entries = (
        (
            AdversarialCaseId.CRAFTED_NAMES,
            AdversarialDisposition.DETERMINISTICALLY_CONTAINED,
            AdversarialEvidenceKind.PATH_NORMALIZATION,
            False,
        ),
        (
            AdversarialCaseId.ENVIRONMENT_READ,
            AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
            AdversarialEvidenceKind.REPOSITORY_CODE_FAIL_CLOSED,
            True,
        ),
        (
            AdversarialCaseId.FAKE_BINARIES,
            AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
            AdversarialEvidenceKind.EXTERNAL_EXECUTABLE_VALIDATION,
            False,
        ),
        (
            AdversarialCaseId.HOME_READ,
            AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
            AdversarialEvidenceKind.REPOSITORY_CODE_FAIL_CLOSED,
            True,
        ),
        (
            AdversarialCaseId.NETWORK_SOCKET,
            AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
            AdversarialEvidenceKind.REPOSITORY_CODE_FAIL_CLOSED,
            True,
        ),
        (
            AdversarialCaseId.OUTPUT_ABUSE,
            AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
            AdversarialEvidenceKind.BOUNDED_OUTPUT,
            True,
        ),
        (
            AdversarialCaseId.PATH_TRAVERSAL,
            AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
            AdversarialEvidenceKind.WORKSPACE_VALIDATION,
            True,
        ),
        (
            AdversarialCaseId.PROCESS_RESOURCE_ABUSE,
            AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
            AdversarialEvidenceKind.BOUNDED_PROCESS,
            True,
        ),
        (
            AdversarialCaseId.PROMPT_INJECTION,
            AdversarialDisposition.DETERMINISTICALLY_CONTAINED,
            AdversarialEvidenceKind.UNTRUSTED_CONTEXT,
            False,
        ),
        (
            AdversarialCaseId.SYMLINK_ESCAPE,
            AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
            AdversarialEvidenceKind.WORKSPACE_VALIDATION,
            False,
        ),
    )
    return [
        AdversarialAcceptanceObservation(
            case_id=case_id,
            disposition=disposition,
            evidence_kind=evidence_kind,
            limitations=_LIMITATION if runtime else [],
        )
        for case_id, disposition, evidence_kind, runtime in entries
    ]


def test_hostile_portfolio_is_source_bound_and_fails_closed_before_host_execution(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_fixture(tmp_path, "adversarial-repository")
    manifest = load_adversarial_acceptance_manifest(root / "cases.json")
    config = config_factory(
        privacy={"fail_on_detected_secret": False},
        repository={"max_total_context_bytes": 1_000_000},
        smart_contracts={"compile": True},
    )
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    paths = {item.relative_path for item in discovery.files}
    assert "crafted/markdown_[local](target).sol" in paths
    with pytest.raises(ValueError):
        normalize_relative_path("../outside.sol")

    repository_map = build_repository_map(discovery)
    context = ContextBuilder(
        discovery=discovery,
        repository_map=repository_map,
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    ).build("source_audit")
    excerpt = next(
        item for item in context.excerpts if item.path == "contracts/PromptInjection.sol"
    )
    rendered = render_context(context)
    sentinel = f"MMAUDIT-UNTRUSTED-{excerpt.content_hash.upper()}"
    canary = "SYNTHETIC_PROMPT_INJECTION_CANARY"
    assert rendered.index(f"-----BEGIN {sentinel}-----") < rendered.index(canary)
    assert rendered.index(canary) < rendered.index(f"-----END {sentinel}-----")

    fake_root = _copy_fixture(tmp_path, "fake-binary-repository")
    for name in ("git", "semgrep"):
        (fake_root / "bin" / name).chmod(0o755)
    with monkeypatch.context() as fake_context:
        fake_context.setenv("PATH", str(fake_root / "bin"))
        fake_result = _FixtureScanner().run(
            fake_root,
            tmp_path / "private-fake-tool",
            2,
            backend=_PassthroughIsolation(),
        )
    assert fake_result.status is ScannerStatus.FAILED
    assert "inside audited repository" in (fake_result.error or "")

    linked_root = _copy_fixture(tmp_path, "linked-repository")
    outside = tmp_path / "outside.sol"
    outside.write_text("contract Outside {}\n", encoding="utf-8")
    (linked_root / "escape.sol").symlink_to(outside)
    with pytest.raises(ValueError, match="symlink"):
        validate_copyable_workspace(linked_root, excluded=lambda _: False)

    timeout = _BoundedTrustedScanner("import time; time.sleep(2)").run(
        root,
        tmp_path / "private-timeout",
        0.05,
        backend=_PassthroughIsolation(),
    )
    output = _BoundedTrustedScanner(
        "print('x' * 10000)",
        output_limit=100,
    ).run(
        root,
        tmp_path / "private-output",
        2,
        backend=_PassthroughIsolation(),
    )
    assert timeout.status is ScannerStatus.TIMED_OUT
    assert output.status is ScannerStatus.FAILED

    projects = discover_solidity_projects(discovery, config.smart_contracts)
    monkeypatch.setattr(
        "mmaudit.solidity.compile.default_isolation_backend",
        lambda configured: None,
    )
    monkeypatch.setattr(
        "mmaudit.solidity.compile.subprocess.Popen",
        lambda *args, **kwargs: pytest.fail("hostile repository code must not execute"),
    )
    compilation = compile_solidity_projects(
        root,
        projects,
        config.smart_contracts,
        tmp_path / "private-fail-closed",
    )
    assert compilation.results[0].repository_code_execution is (
        RepositoryCodeExecutionState.BLOCKED
    )

    report = build_adversarial_acceptance_report(manifest, _observations())
    assert report.status is AdversarialAcceptanceStatus.FAIL_CLOSED
    assert report.safe_cases == report.total_cases == 10
    assert report.hostile_host_executions == 0
    assert report.blocked_integrations == ["real_rootless_containment"]
    output_path = tmp_path / "adversarial-acceptance.json"
    write_adversarial_acceptance_report(output_path, report)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    schema = json.loads(
        Path("schemas/adversarial_acceptance_report.schema.json").read_text(encoding="utf-8")
    )
    assert set(payload) == set(schema["required"])
    assert all(
        set(item) == set(schema["$defs"]["outcome"]["required"]) for item in payload["outcomes"]
    )
    assert AdversarialAcceptanceReport.model_validate(payload) == report

    assert not list(FIXTURE.rglob("*.marker"))
    assert not list(root.rglob("*.marker"))
    assert not (tmp_path / "adversarial-escape.marker").exists()
