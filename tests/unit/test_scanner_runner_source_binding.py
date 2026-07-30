"""Regression coverage for scanner-runner audited source custody."""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from mmaudit.config import AuditConfig
from mmaudit.models.schemas import ScannerFinding
from mmaudit.scanners import base as scanner_base
from mmaudit.scanners.base import (
    ScannerAdapter,
    ScannerSourceIntegrityError,
    scanner_workspace_sha256,
)
from mmaudit.scanners.runner import ScannerRunner


class _LocalIsolation:
    name = "synthetic-local-isolation"

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


class _SyntheticScanner(ScannerAdapter):
    name = "semgrep"
    executable = sys.executable

    def __init__(self, source_to_mutate: Path | None = None) -> None:
        self.source_to_mutate = source_to_mutate

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        del root, private_dir
        return [self.executable, "-c", "pass"]

    def parse(
        self,
        root: Path,
        stdout: str,
        private_dir: Path,
    ) -> list[ScannerFinding]:
        del root, stdout, private_dir
        if self.source_to_mutate is not None:
            self.source_to_mutate.write_text(
                "contract Safe { uint256 changed; }\n",
                encoding="utf-8",
            )
        return []


@pytest.mark.asyncio
async def test_ordinary_scanner_copy_uses_frozen_post_discovery_inventory(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = tmp_path / "repository"
    source = repository / "src" / "Safe.sol"
    source.parent.mkdir(parents=True)
    source.write_text("contract Safe {}\n", encoding="utf-8")
    output = repository / "custom-results"
    output.mkdir()
    expected = scanner_workspace_sha256(
        repository,
        output,
        audited_relative_paths=("src/Safe.sol",),
        allow_custom_private_exclusion=True,
    )
    config = config_factory(scanners={"semgrep": {"enabled": True, "required": False}})
    runner = ScannerRunner(
        config,
        adapters={"semgrep": _SyntheticScanner()},
        backend=_LocalIsolation(),
    )

    runs = await runner.run_all(
        repository,
        output / "run" / "scanner-output",
        audited_relative_paths=("src/Safe.sol",),
        expected_repository_sha256=expected,
        repository_exclusion_root=output,
        allow_custom_repository_exclusion=True,
    )

    assert runs[0].status.value == "success"
    copied = output / "run" / "scanner-output" / "semgrep" / "workspace"
    assert (copied / "src" / "Safe.sol").read_text(encoding="utf-8") == source.read_text(
        encoding="utf-8"
    )
    assert not (copied / "custom-results").exists()


@pytest.mark.asyncio
async def test_scanner_runner_rejects_source_drift_during_ordinary_execution(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "Safe.sol"
    source.write_text("contract Safe {}\n", encoding="utf-8")
    expected = scanner_workspace_sha256(
        repository,
        audited_relative_paths=("Safe.sol",),
    )
    config = config_factory(scanners={"semgrep": {"enabled": True, "required": False}})
    runner = ScannerRunner(
        config,
        adapters={"semgrep": _SyntheticScanner(source)},
        backend=_LocalIsolation(),
    )

    with pytest.raises(
        ScannerSourceIntegrityError,
        match="audited source changed during scanner execution",
    ):
        await runner.run_all(
            repository,
            tmp_path / "private",
            audited_relative_paths=("Safe.sol",),
            expected_repository_sha256=expected,
        )


@pytest.mark.asyncio
async def test_ordinary_scanner_rejects_source_root_swap_during_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "Safe.sol"
    original = "contract Safe {}\n"
    source.write_text(original, encoding="utf-8")
    expected = scanner_workspace_sha256(
        repository,
        audited_relative_paths=("Safe.sol",),
    )
    parked_repository = tmp_path / "parked-repository"
    real_copy = scanner_base.copy_scanner_workspace_with_custody

    def swapped_copy(
        *args: Any,
        **kwargs: Any,
    ) -> scanner_base.ScannerWorkspaceCopyCustody:
        repository.rename(parked_repository)
        repository.mkdir()
        (repository / "Safe.sol").write_text(
            "contract DifferentSource {}\n",
            encoding="utf-8",
        )
        try:
            custody = real_copy(*args, **kwargs)
        finally:
            (repository / "Safe.sol").unlink()
            repository.rmdir()
            parked_repository.rename(repository)
        return custody

    monkeypatch.setattr(
        scanner_base,
        "copy_scanner_workspace_with_custody",
        swapped_copy,
    )
    config = config_factory(scanners={"semgrep": {"enabled": True, "required": False}})
    runner = ScannerRunner(
        config,
        adapters={"semgrep": _SyntheticScanner()},
        backend=_LocalIsolation(),
    )

    with pytest.raises(
        ScannerSourceIntegrityError,
        match="scanner source copy failed its frozen inventory validation",
    ):
        await runner.run_all(
            repository,
            tmp_path / "private",
            audited_relative_paths=("Safe.sol",),
            expected_repository_sha256=expected,
        )

    assert source.read_text(encoding="utf-8") == original


@pytest.mark.asyncio
async def test_scanner_runner_rejects_stale_frozen_inventory_before_execution(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "Safe.sol").write_text("contract Safe {}\n", encoding="utf-8")
    config = config_factory(scanners={"semgrep": {"enabled": True, "required": False}})
    runner = ScannerRunner(
        config,
        adapters={"semgrep": _SyntheticScanner()},
        backend=_LocalIsolation(),
    )

    with pytest.raises(
        ScannerSourceIntegrityError,
        match="scanner audited source inventory differs",
    ):
        await runner.run_all(
            repository,
            tmp_path / "private",
            audited_relative_paths=("Safe.sol",),
            expected_repository_sha256="0" * 64,
        )

    assert not (tmp_path / "private").exists()
