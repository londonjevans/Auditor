from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from mmaudit.cli import app
from mmaudit.config import ScannerConfig, SmartContractsConfig
from mmaudit.constants import ExitCode
from mmaudit.models.schemas import ScannerFinding
from mmaudit.scanners.base import ScannerAdapter
from mmaudit.scanners.diagnostics import (
    ExecutableVersionProbeStatus,
    ScannerExecutablePreflight,
    ScannerExecutableState,
)
from mmaudit.scanners.hardhat import HardhatForkScanner
from mmaudit.scanners.runner import preflight_configured_scanner_tools


class _SyntheticAdapter(ScannerAdapter):
    def __init__(self, name: str, executable: str) -> None:
        self.name = name
        self.executable = executable

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        del root, private_dir
        return [self.executable, "--version"]

    def parse(
        self,
        root: Path,
        stdout: str,
        private_dir: Path,
    ) -> list[ScannerFinding]:
        del root, stdout, private_dir
        return []


class _SyntheticIsolation:
    name = "synthetic-isolation"

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


def _preflight(
    state: ScannerExecutableState,
    *,
    path: Path | None = None,
    version: str | None = None,
    failure: ExecutableVersionProbeStatus | None = None,
    diagnostic: str | None = None,
) -> ScannerExecutablePreflight:
    return ScannerExecutablePreflight(
        state=state,
        resolved_path=path,
        version=version,
        failure_kind=failure,
        diagnostic=diagnostic,
    )


def test_configured_tool_preflight_probes_exact_resolved_path_with_scrubbed_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    private = tmp_path / "private"
    executable = Path(sys.executable).resolve(strict=True)
    adapters = {"synthetic": _SyntheticAdapter("synthetic", "synthetic-tool")}
    backend = _SyntheticIsolation()
    observed: list[tuple[object, dict[str, str], object, Path, Path]] = []
    monkeypatch.setenv("OPENROUTER_API_KEY", "synthetic-secret-must-not-propagate")
    monkeypatch.setattr(
        "mmaudit.scanners.runner.shutil.which",
        lambda _name: str(executable),
    )

    def probe(
        selected: object,
        environment: dict[str, str],
        selected_backend: object,
        workspace: Path,
        private_dir: Path,
        **_kwargs: object,
    ) -> ScannerExecutablePreflight:
        observed.append((selected, environment, selected_backend, workspace, private_dir))
        return _preflight(
            ScannerExecutableState.PRESENT_EXECUTABLE,
            path=executable,
            version="synthetic-tool 1.2.3",
        )

    monkeypatch.setattr("mmaudit.scanners.runner.preflight_scanner_executable", probe)

    diagnostics = preflight_configured_scanner_tools(
        adapters,
        backend=backend,
        repository_root=repository,
        trusted_output_root=tmp_path,
        private_dir=private,
    )

    assert diagnostics["synthetic"].state is ScannerExecutableState.PRESENT_EXECUTABLE
    assert len(observed) == 1
    selected, environment, selected_backend, workspace, tool_private = observed[0]
    assert selected == executable
    assert selected_backend is backend
    assert workspace == tool_private / "workspace"
    assert workspace.is_dir()
    assert "OPENROUTER_API_KEY" not in environment


def test_configured_tool_preflight_refuses_repository_path_shadow_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    shadow = repository / "semgrep"
    shadow.write_text("synthetic non-production path shadow\n", encoding="utf-8")
    shadow.chmod(0o700)
    monkeypatch.setattr("mmaudit.scanners.runner.shutil.which", lambda _name: str(shadow))
    monkeypatch.setattr(
        "mmaudit.scanners.runner.preflight_scanner_executable",
        lambda *_args, **_kwargs: pytest.fail("repository-local executable must not run"),
    )

    diagnostics = preflight_configured_scanner_tools(
        {"semgrep": _SyntheticAdapter("semgrep", "semgrep")},
        backend=_SyntheticIsolation(),
        repository_root=repository,
        trusted_output_root=tmp_path,
        private_dir=tmp_path / "private",
    )

    result = diagnostics["semgrep"]
    assert result.state is ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE
    assert result.resolved_path == shadow
    assert result.failure_kind is ExecutableVersionProbeStatus.EXECUTION_REFUSED
    assert "audited repository" in (result.diagnostic or "")


@pytest.mark.parametrize("unsafe_name", [".", "..", "../escape", "bad/name", "bad\nname"])
def test_configured_tool_preflight_rejects_unsafe_private_workspace_name(
    tmp_path: Path,
    unsafe_name: str,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    private = tmp_path / "private"

    with pytest.raises(ValueError, match="safe path component"):
        preflight_configured_scanner_tools(
            {unsafe_name: _SyntheticAdapter(unsafe_name, "absent-tool")},
            backend=None,
            repository_root=repository,
            trusted_output_root=tmp_path,
            private_dir=private,
        )

    assert not (tmp_path / "escape").exists()


def test_configured_tool_preflight_rejects_symlinked_private_parent(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (output / "private").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="non-link directory"):
        preflight_configured_scanner_tools(
            {"semgrep": _SyntheticAdapter("semgrep", "absent-tool")},
            backend=None,
            repository_root=repository,
            trusted_output_root=output,
            private_dir=output / "private" / "doctor-tool-preflight" / "run-id",
        )

    assert list(outside.iterdir()) == []


def test_configured_tool_preflight_creates_private_chain_with_owner_only_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    output.chmod(0o755)
    selected = output / "private" / "doctor-tool-preflight" / "run-id"
    monkeypatch.setattr("mmaudit.scanners.runner.shutil.which", lambda _name: None)

    preflight_configured_scanner_tools(
        {"semgrep": _SyntheticAdapter("semgrep", "absent-tool")},
        backend=None,
        repository_root=repository,
        trusted_output_root=output,
        private_dir=selected,
    )

    if sys.platform != "win32":
        for path in (
            output / "private",
            output / "private" / "doctor-tool-preflight",
            selected,
            selected / "semgrep",
            selected / "semgrep" / "workspace",
        ):
            assert path.stat().st_mode & 0o777 == 0o700


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode validation")
def test_configured_tool_preflight_rejects_writable_output_root(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    output.chmod(0o777)

    with pytest.raises(ValueError, match="output root permissions are too broad"):
        preflight_configured_scanner_tools(
            {"semgrep": _SyntheticAdapter("semgrep", "absent-tool")},
            backend=None,
            repository_root=repository,
            trusted_output_root=output,
            private_dir=output / "private",
        )

    assert not (output / "private").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode validation")
def test_configured_tool_preflight_rejects_writable_output_ancestor(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    writable_parent = tmp_path / "writable-parent"
    writable_parent.mkdir()
    output = writable_parent / "output"
    output.mkdir()
    output.chmod(0o755)
    writable_parent.chmod(0o777)

    with pytest.raises(ValueError, match="output ancestor permissions are too broad"):
        preflight_configured_scanner_tools(
            {"semgrep": _SyntheticAdapter("semgrep", "absent-tool")},
            backend=None,
            repository_root=repository,
            trusted_output_root=output,
            private_dir=output / "private",
        )

    assert not (output / "private").exists()


def test_configured_tool_preflight_reports_absent_and_no_isolation_states(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    executable = Path(sys.executable).resolve(strict=True)
    adapters = {
        "absent": _SyntheticAdapter("absent", "absent-tool"),
        "present": _SyntheticAdapter("present", "present-tool"),
    }
    monkeypatch.setattr(
        "mmaudit.scanners.runner.shutil.which",
        lambda name: str(executable) if name == "present-tool" else None,
    )

    diagnostics = preflight_configured_scanner_tools(
        adapters,
        backend=None,
        repository_root=repository,
        trusted_output_root=tmp_path,
        private_dir=tmp_path / "private",
    )

    assert diagnostics["absent"].state is ScannerExecutableState.ABSENT
    present = diagnostics["present"]
    assert present.state is ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE
    assert present.resolved_path == executable
    assert present.failure_kind is ExecutableVersionProbeStatus.ISOLATION_FAILURE


def test_configured_tool_preflight_preserves_other_results_after_per_tool_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    toolchain = tmp_path / "toolchain"
    toolchain.mkdir()
    paths: dict[str, Path] = {}
    for name in ("hardhat", "good-tool", "bad-tool"):
        path = toolchain / name
        path.write_text("synthetic non-production tool placeholder\n", encoding="utf-8")
        path.chmod(0o700)
        paths[name] = path.resolve(strict=True)
    adapters: dict[str, ScannerAdapter] = {
        "hardhat_fork": HardhatForkScanner(SmartContractsConfig(), ScannerConfig()),
        "good": _SyntheticAdapter("good", "good-tool"),
        "bad": _SyntheticAdapter("bad", "bad-tool"),
    }
    monkeypatch.setattr(
        "mmaudit.scanners.runner.shutil.which",
        lambda name: str(paths[name]),
    )
    probed: list[Path] = []

    def probe(
        selected: object,
        *_args: object,
        **_kwargs: object,
    ) -> ScannerExecutablePreflight:
        path = Path(str(selected))
        probed.append(path)
        if path.name == "bad-tool":
            raise ValueError("synthetic private probe failure")
        return _preflight(
            ScannerExecutableState.PRESENT_EXECUTABLE,
            path=path,
            version="good-tool 1.0.0",
        )

    monkeypatch.setattr("mmaudit.scanners.runner.preflight_scanner_executable", probe)

    diagnostics = preflight_configured_scanner_tools(
        adapters,
        backend=_SyntheticIsolation(),
        repository_root=repository,
        trusted_output_root=tmp_path,
        private_dir=tmp_path / "private",
    )

    assert diagnostics["good"].state is ScannerExecutableState.PRESENT_EXECUTABLE
    assert diagnostics["bad"].state is ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE
    assert diagnostics["bad"].failure_kind is ExecutableVersionProbeStatus.ISOLATION_FAILURE
    assert (
        diagnostics["hardhat_fork"].state is ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE
    )
    assert "repository-JavaScript" in (diagnostics["hardhat_fork"].diagnostic or "")
    assert paths["hardhat"] not in probed
    assert sorted(path.name for path in probed) == ["bad-tool", "good-tool"]


def test_doctor_reports_three_tool_states_and_absolute_resolved_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    config_path = tmp_path / "mmaudit.toml"
    secret_file = tmp_path / "operator.env"
    secret_file.write_text("OPENROUTER_API_KEY=synthetic-doctor-key\n", encoding="utf-8")
    secret_file.chmod(0o600)
    config = config_factory(
        scanners={
            "gitleaks": {"enabled": True, "required": False},
            "osv": {"enabled": True, "required": False},
            "trivy": {"enabled": True, "required": False},
        }
    )
    backend = SimpleNamespace(name="synthetic-isolation", supports_local_fork_rpc=True)
    executable = (tmp_path / "toolchain" / "gitleaks").resolve()
    executable.parent.mkdir()
    executable.write_text("synthetic\n", encoding="utf-8")
    executable.chmod(0o700)
    ready = (tmp_path / "toolchain" / "trivy").resolve()
    ready.write_text("synthetic\n", encoding="utf-8")
    ready.chmod(0o700)
    invalid_version = (tmp_path / "toolchain" / "osv-scanner").resolve()
    invalid_version.write_text("synthetic\n", encoding="utf-8")
    invalid_version.chmod(0o700)
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    monkeypatch.setattr("mmaudit.cli._openrouter_authentication_valid", lambda *_args: True)
    monkeypatch.setattr("mmaudit.cli.default_isolation_backend", lambda *_args, **_kwargs: backend)

    def preflight(
        adapters: dict[str, ScannerAdapter],
        **_kwargs: object,
    ) -> dict[str, ScannerExecutablePreflight]:
        results = {name: _preflight(ScannerExecutableState.ABSENT) for name in adapters}
        results["gitleaks"] = _preflight(
            ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE,
            path=executable,
            failure=ExecutableVersionProbeStatus.INTERPRETER_OR_LOADER_FAILURE,
            diagnostic=(
                "tool interpreter or dynamic loader could not initialize; install a "
                "self-contained tool distribution"
            ),
        )
        results["trivy"] = _preflight(
            ScannerExecutableState.PRESENT_EXECUTABLE,
            path=ready,
            version="trivy 1.2.3",
        )
        results["osv"] = _preflight(
            ScannerExecutableState.PRESENT_EXECUTABLE,
            path=invalid_version,
            failure=ExecutableVersionProbeStatus.INVALID_VERSION,
            diagnostic="tool version is unavailable because its output was not safe public text",
        )
        return results

    monkeypatch.setattr("mmaudit.cli.preflight_configured_scanner_tools", preflight)
    result = CliRunner().invoke(
        app,
        [
            "doctor",
            "--config",
            str(config_path),
            "--secrets-env-file",
            str(secret_file),
            "--repo",
            str(repository),
            "--output",
            str(tmp_path / "output"),
            "--no-color",
        ],
        env={"COLUMNS": "500"},
    )
    output = " ".join(result.stdout.split())

    assert result.exit_code == ExitCode.SUCCESS, result.stdout
    assert "Scanner: semgrep" in output
    assert "absent from PATH" in output
    assert "resolved but not executable under isolation" in output
    assert "FAIL" in next(line for line in result.stdout.splitlines() if "gitleaks" in line)
    assert f"resolved absolute path: {executable}" in output
    assert "interpreter_or_loader_failure" in output
    assert "self-contained tool distribution" in output
    assert "resolved and executable under isolation" in output
    assert "PASS" in next(line for line in result.stdout.splitlines() if "trivy" in line)
    assert f"resolved absolute path: {ready}" in output
    assert "version: trivy 1.2.3" in output
    assert "FAIL" in next(line for line in result.stdout.splitlines() if "Scanner: osv" in line)
    assert "invalid_version" in output
    assert f"resolved absolute path: {invalid_version}" in output
    assert "synthetic-doctor-key" not in output


@pytest.mark.parametrize("enabled", [True, False])
def test_doctor_required_tool_that_cannot_execute_under_isolation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
    enabled: bool,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    secret_file = tmp_path / "operator.env"
    secret_file.write_text("OPENROUTER_API_KEY=synthetic-doctor-key\n", encoding="utf-8")
    secret_file.chmod(0o600)
    config = config_factory(scanners={"slither": {"enabled": enabled, "required": True}})
    executable = (tmp_path / "toolchain" / "slither").resolve()
    executable.parent.mkdir()
    executable.write_text("synthetic\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    monkeypatch.setattr("mmaudit.cli._openrouter_authentication_valid", lambda *_args: True)
    monkeypatch.setattr(
        "mmaudit.cli.default_isolation_backend",
        lambda *_args, **_kwargs: SimpleNamespace(
            name="synthetic-isolation",
            supports_local_fork_rpc=True,
        ),
    )

    def preflight(
        adapters: dict[str, ScannerAdapter],
        **_kwargs: object,
    ) -> dict[str, ScannerExecutablePreflight]:
        results = {name: _preflight(ScannerExecutableState.PRESENT_EXECUTABLE) for name in adapters}
        results["slither"] = _preflight(
            ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE,
            path=executable,
            failure=ExecutableVersionProbeStatus.ISOLATION_FAILURE,
            diagnostic="tool could not execute successfully under hardened isolation",
        )
        return results

    monkeypatch.setattr("mmaudit.cli.preflight_configured_scanner_tools", preflight)
    result = CliRunner().invoke(
        app,
        [
            "doctor",
            "--config",
            str(tmp_path / "mmaudit.toml"),
            "--secrets-env-file",
            str(secret_file),
            "--repo",
            str(repository),
            "--output",
            str(tmp_path / "output"),
            "--no-color",
        ],
        env={"COLUMNS": "500"},
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "Scanner: slither" in result.stdout
    assert "resolved but not executable under isolation" in result.stdout
    assert str(executable) in result.stdout
