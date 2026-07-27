"""Foundry fork-test adapter for defensive smart-contract probing."""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import time
import tomllib
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

from mmaudit.config import SmartContractsConfig
from mmaudit.models.schemas import ScannerFinding, ScannerRun, ScannerStatus, Severity
from mmaudit.scanners.base import (
    ScannerAdapter,
    ScannerIsolationBackend,
    copy_scanner_workspace,
    isolated_executable_version,
    make_finding,
    sanitized_scanner_environment,
)


class FoundryForkScanner(ScannerAdapter):
    """Run existing Foundry audit tests against an explicitly configured fork RPC."""

    name = "foundry_fork"
    executable = "forge"
    finding_exit_codes = frozenset({0, 1})
    max_stdout_bytes = 50_000_000
    max_stderr_bytes = 10_000_000

    def __init__(
        self,
        config: SmartContractsConfig,
        *,
        allow_fork_probing: bool = False,
    ) -> None:
        self.config = config
        self.allow_fork_probing = allow_fork_probing

    def with_runtime_allowance(self, allow_fork_probing: bool) -> FoundryForkScanner:
        return FoundryForkScanner(self.config, allow_fork_probing=allow_fork_probing)

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        del root, private_dir
        command = [
            self.executable,
            "test",
            "--fork-url",
            self._fork_rpc_url(),
            "--match-path",
            self.config.foundry_match_path,
            "--fuzz-runs",
            str(self.config.foundry_fuzz_runs),
            "--invariant-runs",
            str(self.config.foundry_invariant_runs),
            "--color",
            "never",
            "-vv",
        ]
        if self.config.foundry_match_test:
            command.extend(["--match-test", self.config.foundry_match_test])
        return command

    def display_command(self) -> list[str]:
        command = [
            self.executable,
            "test",
            "--fork-url",
            "[REDACTED_FORK_RPC_URL]",
            "--match-path",
            self.config.foundry_match_path,
            "--fuzz-runs",
            str(self.config.foundry_fuzz_runs),
            "--invariant-runs",
            str(self.config.foundry_invariant_runs),
            "--color",
            "never",
            "-vv",
        ]
        if self.config.foundry_match_test:
            command.extend(["--match-test", self.config.foundry_match_test])
        return command

    def parse(self, root: Path, stdout: str, private_dir: Path) -> list[ScannerFinding]:
        del private_dir
        findings: list[ScannerFinding] = []
        current_path: str | None = None
        for raw_line in stdout.splitlines():
            path_match = re.search(r"Encountered \d+ failing test[s]? in ([^:\s]+):", raw_line)
            if path_match:
                current_path = path_match.group(1)
                continue
            failure = re.search(
                r"\[FAIL(?:: (?P<reason>[^\]]+))?\]\s+(?P<test>[A-Za-z0-9_]+)", raw_line
            )
            if not failure or current_path is None:
                continue
            location = _find_test_location(root, current_path, failure.group("test"))
            reason = _clean_reason(failure.group("reason") or "Foundry fork test failed")
            finding = make_finding(
                root=root,
                scanner=self.name,
                rule_id="foundry-fork-test-failure",
                title=f"Fork reproduction test failed: {failure.group('test')}",
                severity=Severity.HIGH,
                message=reason,
                path=current_path,
                start_line=location[0],
                end_line=location[1],
                metadata={
                    "class": "fork_reproduction",
                    "fork_only": True,
                    "test_name": failure.group("test"),
                    "fork_rpc_url_env": self.config.fork_rpc_url_env,
                },
            )
            if finding is not None:
                findings.append(finding)
        return findings

    def run(
        self,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: ScannerIsolationBackend | None = None,
    ) -> ScannerRun:
        private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        environment = sanitized_scanner_environment(private_dir)
        start = datetime.now(UTC)
        monotonic_start = time.monotonic()
        skip_reason = self._skip_reason(root)
        if skip_reason is not None:
            return ScannerRun(
                scanner=self.name,
                status=ScannerStatus.SKIPPED,
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error=skip_reason,
            )
        executable = shutil.which(self.executable)
        if executable is None:
            return ScannerRun(
                scanner=self.name,
                status=ScannerStatus.UNAVAILABLE,
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error="forge is not installed",
            )
        if backend is None:
            return ScannerRun(
                scanner=self.name,
                status=ScannerStatus.UNAVAILABLE,
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error="hardened fork-test isolation is unavailable; tests were not executed",
            )
        executable_path = Path(executable).resolve(strict=True)
        try:
            executable_path.relative_to(root.resolve(strict=True))
        except ValueError:
            pass
        else:
            return ScannerRun(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error="refusing forge executable resolved from inside audited repository",
            )
        workspace = private_dir / "workspace"
        version: str | None = None
        try:
            _reject_unsafe_foundry_configuration(root)
            _rpc_url, rpc_port = self._fork_rpc()
            copy_scanner_workspace(root, workspace, private_dir)
            command = self.build_command(workspace, private_dir)
            command[0] = str(executable_path)
            command = backend.wrap(
                command,
                workspace=workspace,
                private_dir=private_dir,
                rpc_port=rpc_port,
            )
            version = isolated_executable_version(
                executable_path,
                environment,
                backend,
                workspace,
                private_dir,
            )
        except (OSError, ValueError) as exc:
            return ScannerRun(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                version=version,
                command=self.display_command(),
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error=f"unsafe or invalid fork probe configuration: {type(exc).__name__}",
            )
        raw_path = private_dir / "foundry-fork.stdout.txt"
        error_path = private_dir / "foundry-fork.stderr.txt"
        environment["ETH_RPC_URL"] = self._fork_rpc_url()
        environment["FOUNDRY_FFI"] = "false"
        environment["FOUNDRY_NO_STORAGE_CACHING"] = "true"
        if profile := os.environ.get("FOUNDRY_PROFILE"):
            environment["FOUNDRY_PROFILE"] = profile
        timeout = min(timeout_seconds, self.config.max_fork_probe_seconds)
        timed_out = False
        output_exceeded = False
        process: subprocess.Popen[bytes] | None = None
        try:
            with raw_path.open("wb") as stdout_handle, error_path.open("wb") as stderr_handle:
                process = subprocess.Popen(
                    command,
                    cwd=workspace,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    env=environment,
                    shell=False,
                    start_new_session=os.name != "nt",
                    creationflags=(
                        int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
                        if os.name == "nt"
                        else 0
                    ),
                    preexec_fn=_limit_process if os.name != "nt" else None,
                )
                deadline = time.monotonic() + timeout
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        _stop_process(process)
                        break
                    if (
                        raw_path.stat().st_size > self.max_stdout_bytes
                        or error_path.stat().st_size > self.max_stderr_bytes
                    ):
                        output_exceeded = True
                        _stop_process(process)
                        break
                    time.sleep(0.05)
                return_code = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            timed_out = True
            if process is not None:
                _stop_process(process)
            return_code = process.returncode if process is not None else -1
        except OSError as exc:
            return ScannerRun(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                version=version,
                command=self.display_command(),
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error=f"fork probe process failed: {type(exc).__name__}",
            )
        if timed_out:
            return ScannerRun(
                scanner=self.name,
                status=ScannerStatus.TIMED_OUT,
                version=version,
                command=self.display_command(),
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error=f"fork probe exceeded {timeout:.0f}s timeout",
                raw_output_path=str(raw_path.relative_to(private_dir.parent)),
            )
        if output_exceeded:
            return ScannerRun(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                version=version,
                command=self.display_command(),
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error="fork probe output exceeded the private output limit",
                raw_output_path=str(raw_path.relative_to(private_dir.parent)),
            )
        stdout = raw_path.read_text(encoding="utf-8", errors="replace")
        findings = self.parse(workspace, stdout, private_dir)
        status = ScannerStatus.SUCCESS if return_code == 0 else ScannerStatus.FAILED
        return ScannerRun(
            scanner=self.name,
            status=status,
            version=version,
            command=self.display_command(),
            started_at=start,
            finished_at=datetime.now(UTC),
            duration_seconds=time.monotonic() - monotonic_start,
            findings=findings,
            error=None
            if status is ScannerStatus.SUCCESS
            else f"forge exited with code {return_code}",
            raw_output_path=str(raw_path.relative_to(private_dir.parent)),
        )

    def _skip_reason(self, root: Path) -> str | None:
        if not self.config.enabled:
            return "smart-contract probing disabled by configuration"
        if not (self.allow_fork_probing or self.config.allow_fork_probing):
            return "fork probing not acknowledged; pass --allow-fork or set smart_contracts.allow_fork_probing"
        if not _looks_like_foundry_project(root):
            return "no Foundry smart-contract project detected"
        if not list(root.glob(self.config.foundry_match_path)):
            return f"no Foundry tests matched {self.config.foundry_match_path}"
        return None

    def _fork_rpc_url(self) -> str:
        return self._fork_rpc()[0]

    def _fork_rpc(self) -> tuple[str, int]:
        value = os.environ.get(self.config.fork_rpc_url_env, "")
        if not value:
            raise ValueError(f"{self.config.fork_rpc_url_env} is not set")
        parsed = urlparse(value)
        if parsed.scheme != "http" or not parsed.netloc:
            raise ValueError("fork RPC URL must be a plain HTTP URL")
        if self.config.require_local_fork_rpc and parsed.hostname not in {
            "127.0.0.1",
            "localhost",
            "::1",
        }:
            raise ValueError("fork RPC URL must point to a local fork endpoint")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("fork RPC URL must not contain credentials or query data")
        if parsed.port is None:
            raise ValueError("fork RPC URL must contain an explicit port")
        return value, parsed.port


def _looks_like_foundry_project(root: Path) -> bool:
    return (root / "foundry.toml").is_file() or any(
        path.suffix == ".sol"
        for path in [*root.glob("src/**/*.sol"), *root.glob("contracts/**/*.sol")]
    )


def _reject_unsafe_foundry_configuration(root: Path) -> None:
    foundry_config = root / "foundry.toml"
    if foundry_config.is_file():
        payload = tomllib.loads(foundry_config.read_text(encoding="utf-8", errors="replace"))
        if _toml_contains_true(payload, "ffi"):
            raise ValueError("Foundry FFI is enabled; refusing to execute fork tests")
    for path in root.glob("**/*.sol"):
        try:
            relative = PurePosixPath(path.relative_to(root).as_posix())
        except ValueError:
            continue
        if (
            ".git" in relative.parts
            or ".mmaudit" in relative.parts
            or "node_modules" in relative.parts
        ):
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        if "vm.ffi" in content:
            raise ValueError("Foundry test uses vm.ffi; refusing to execute fork tests")


def _toml_contains_true(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        return any(
            (name == key and item is True) or _toml_contains_true(item, key)
            for name, item in value.items()
        )
    if isinstance(value, list):
        return any(_toml_contains_true(item, key) for item in value)
    return False


def _find_test_location(root: Path, raw_path: str, test_name: str) -> tuple[int, int]:
    path = root / raw_path
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return (1, 1)
    pattern = re.compile(rf"\bfunction\s+{re.escape(test_name)}\b")
    for index, line in enumerate(lines, start=1):
        if pattern.search(line):
            return (index, _find_block_end(lines, index))
    return (1, min(1, len(lines)))


def _find_block_end(lines: list[str], start_line: int) -> int:
    depth = 0
    seen_open = False
    for index in range(start_line, len(lines) + 1):
        line = lines[index - 1]
        depth += line.count("{")
        if "{" in line:
            seen_open = True
        depth -= line.count("}")
        if seen_open and depth <= 0:
            return index
    return start_line


def _clean_reason(value: str) -> str:
    sanitized = "".join(character if ord(character) >= 32 else " " for character in value)
    return " ".join(sanitized.split())[:500]


def _limit_process() -> None:
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (900, 900))
        resource.setrlimit(resource.RLIMIT_FSIZE, (50_000_000, 50_000_000))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        if hasattr(resource, "RLIMIT_NPROC"):
            resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        if hasattr(resource, "RLIMIT_AS"):
            resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
    except (ImportError, OSError, ValueError):
        return


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        process.kill()
