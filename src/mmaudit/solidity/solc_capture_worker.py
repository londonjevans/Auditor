"""Standalone bounded compiler transcript worker; never audit or execution authority.

Only the owned launcher calls this module. Keep it standard-library-only so the
exact copied worker can run under a separately pinned isolated Python interpreter.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import selectors
import stat
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

type DirectoryIdentity = tuple[tuple[int, int, int], ...]
type FileIdentity = tuple[DirectoryIdentity, tuple[int, ...]]


def directory_identity(path: Path) -> DirectoryIdentity:
    """Retain every lexical ancestor object/mode, allowing directory entry churn only."""
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("capture directory is not an exact absolute path")
    result = []
    for parent in (path, *path.parents):
        observed = parent.lstat()
        if not stat.S_ISDIR(observed.st_mode):
            raise ValueError("capture directory has an unsafe ancestor")
        result.append((observed.st_dev, observed.st_ino, observed.st_mode))
    return tuple(result)


def _metadata(value: os.stat_result) -> tuple[int, ...]:
    return tuple(
        getattr(value, name)
        for name in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    )


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def decode(raw: bytes) -> Any:
    """Decode finite, duplicate-free UTF-8 JSON without interpreting it as code."""

    def reject_constant(value: str) -> Any:
        raise ValueError("nonfinite JSON value")

    return json.loads(
        raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=reject_constant
    )


def file_snapshot(path: Path, maximum: int) -> tuple[bytes, FileIdentity]:
    """Read one unshared regular file with stable lexical and descriptor identity."""
    if type(maximum) is not int or not 0 <= maximum <= 200_000_000:
        raise ValueError("capture read ceiling is invalid")
    parents = directory_identity(path.parent)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
        raise ValueError("capture file is not bounded unshared regular data")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        raw = bytearray()
        while len(raw) <= maximum:
            block = os.read(fd, min(65_536, maximum + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    observed = [_metadata(s) for s in (before, opened, after, path.lstat())]
    if (
        len(set(observed)) != 1
        or len(raw) > maximum
        or len(raw) != before.st_size
        or directory_identity(path.parent) != parents
    ):
        raise ValueError("capture file identity changed")
    return bytes(raw), (parents, observed[0])


def file_bytes(path: Path, maximum: int) -> bytes:
    return file_snapshot(path, maximum)[0]


def _write_all(fd: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("capture write made no progress")
        view = view[written:]
    os.fsync(fd)


def write_bytes(path: Path, raw: bytes) -> None:
    """Publish a new private file exclusively, with no replacement or alias following."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        _write_all(fd, raw)
    finally:
        os.close(fd)


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise TimeoutError("compiler transcript deadline expired")


def stdlib_file_paths() -> tuple[Path, ...]:
    """Observe imported stdlib source/cache/extensions, not their native dependency closure."""
    paths: set[Path] = set()
    for name, module in tuple(sys.modules.items()):
        if name.split(".", 1)[0] not in sys.stdlib_module_names or module is None:
            continue
        if getattr(getattr(module, "__spec__", None), "origin", None) in {"built-in", "frozen"}:
            continue
        for attribute in ("__file__", "__cached__"):
            value = getattr(module, attribute, None)
            if isinstance(value, str):
                path = Path(value)
                # -B prevents new cache writes, not reading an existing cache.
                if attribute == "__cached__" and not path.exists():
                    continue
                paths.add(path.resolve(strict=True))
        if len(paths) > 1024:
            raise ValueError("compiler runtime imported-file population exceeds its ceiling")
    return tuple(sorted(paths))


def isolated_runtime_flags() -> dict[str, int]:
    return {
        name: int(getattr(sys.flags, name))
        for name in ("isolated", "ignore_environment", "no_site", "dont_write_bytecode")
    }


def runtime_observation(plan: dict[str, Any]) -> bytes:
    """Check planned direct runtime files in this child; this is not an attestation."""
    flags = isolated_runtime_flags()
    if any(value != 1 for value in flags.values()):
        raise ValueError("compiler helper requires isolated no-site no-bytecode Python")
    interpreter = Path(sys.executable).resolve(strict=True)
    if (
        str(interpreter) != plan["interpreter_path"]
        or _hash(file_bytes(interpreter, 200_000_000)) != plan["interpreter_sha256"]
    ):
        raise ValueError("compiler helper interpreter differs from its original pin")
    files = {}
    for path in stdlib_file_paths():
        _check_deadline(plan["deadline_monotonic"])
        pin = _hash(file_bytes(path, 16_000_000))
        if plan["runtime_files"].get(str(path)) != pin:
            raise ValueError("compiler helper imported an unplanned or changed runtime file")
        files[str(path)] = pin
    return json.dumps(
        {
            "interpreter_sha256": plan["interpreter_sha256"],
            "flags": flags,
            "files": files,
            "transitive_native_dependency_closure_verified": False,
        },
        sort_keys=True,
    ).encode()


def coverage_launch_main(plan_path: str, plan_sha256: str) -> int:
    """Exec only the original fixed coverage command after checking its owned inputs."""
    try:
        raw = file_bytes(Path(plan_path), 2_000_000)
        if _hash(raw) != plan_sha256:
            raise ValueError("coverage launch plan changed")
        plan = decode(raw)
        _check_deadline(plan["deadline_monotonic"])
        if str(Path.cwd()) != plan["workspace"]:
            raise ValueError("coverage launch namespace differs from its original workspace")
        runtime = decode(runtime_observation(plan))
        command = plan["command"]
        if _hash(file_bytes(Path(command[0]), 200_000_000)) != plan["forge_sha256"]:
            raise ValueError("coverage launch Forge pin changed")
        if (
            _hash(file_bytes(Path(plan["capture_launcher"]), 2_000_000))
            != plan["capture_launcher_sha256"]
        ):
            raise ValueError("coverage compiler launcher changed")
        write_bytes(
            Path(plan["receipt_path"]),
            json.dumps(
                {"launch_plan_sha256": plan_sha256, "runtime": runtime}, sort_keys=True
            ).encode(),
        )
        _check_deadline(plan["deadline_monotonic"])
        os.execve(command[0], command, dict(os.environ))
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        return 125


def debugger_launch_main(plan_path: str, plan_sha256: str) -> int:
    """Write a distinct original receipt and exec the fixed separate debugger command."""
    handles: list[int] = []
    try:
        raw = file_bytes(Path(plan_path), 2_000_000)
        if _hash(raw) != plan_sha256:
            raise ValueError("debugger launch plan changed")
        plan = decode(raw)
        _check_deadline(plan["deadline_monotonic"])
        if (
            plan["launch_kind"] != "SEPARATE_FOUNDRY_DEBUGGER"
            or str(Path.cwd()) != plan["workspace"]
        ):
            raise ValueError("debugger launch kind or original namespace changed")
        runtime = decode(runtime_observation(plan))
        command = plan["command"]
        if command[1] != "test" or (
            _hash(file_bytes(Path(command[0]), 200_000_000)) != plan["forge_sha256"]
            or _hash(file_bytes(Path(plan["capture_launcher"]), 2_000_000))
            != plan["capture_launcher_sha256"]
        ):
            raise ValueError("debugger original executable or compiler launcher changed")
        output_file_identities = {}
        for name in ("stdout_path", "stderr_path", "dump_path"):
            path = Path(plan[name])
            parents = directory_identity(path.parent)
            handles.append(
                os.open(
                    path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
                )
            )
            initial = file_snapshot(path, 0)[1]
            if initial != (parents, _metadata(os.fstat(handles[-1]))):
                raise ValueError("debugger original output file was replaced before launch")
            output_file_identities[name] = (parents, initial[1][:4])
        write_bytes(
            Path(plan["receipt_path"]),
            json.dumps(
                {
                    "launch_kind": "SEPARATE_FOUNDRY_DEBUGGER",
                    "launch_plan_sha256": plan_sha256,
                    "descriptor_sha256": plan["descriptor_sha256"],
                    "output_file_identities": output_file_identities,
                    "runtime": runtime,
                },
                sort_keys=True,
            ).encode(),
        )
        for fd, destination in zip(handles[:2], (1, 2), strict=True):
            os.dup2(fd, destination)
        handles.append(os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC))
        os.dup2(handles[-1], 0)
        _check_deadline(plan["deadline_monotonic"])
        os.execve(command[0], command, dict(os.environ))
    except (OSError, ValueError, TypeError, KeyError, IndexError, RecursionError):
        return 125
    finally:
        for fd in handles:
            os.close(fd)


def _input(path: Path, maximum: int, deadline: float, *, input_fd: int = 0) -> bytes:
    """Retain input incrementally, including a bounded partial prefix on refusal."""
    result = bytearray()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.set_blocking(input_fd, False)
        with selectors.DefaultSelector() as selector:
            selector.register(input_fd, selectors.EVENT_READ)
            while True:
                _check_deadline(deadline)
                for _, _ in selector.select(min(0.05, max(0.0, deadline - time.monotonic()))):
                    try:
                        raw = os.read(input_fd, min(65_536, maximum + 1 - len(result)))
                    except BlockingIOError:
                        continue
                    if not raw:
                        return bytes(result)
                    result.extend(raw)
                    _write_all(fd, raw)
                    # One retained sentinel byte proves overflow; the call can
                    # never receive a complete marker or be collected as valid.
                    if len(result) > maximum:
                        raise ValueError("compiler input exceeds its byte ceiling")
    finally:
        os.close(fd)


def _forward(fd: int, raw: bytes, deadline: float) -> None:
    os.set_blocking(fd, False)
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_WRITE)
        view = memoryview(raw)
        while view:
            _check_deadline(deadline)
            for _, _ in selector.select(min(0.05, max(0.0, deadline - time.monotonic()))):
                try:
                    count = os.write(fd, view[:65_536])
                except BlockingIOError:
                    continue
                if count <= 0:
                    raise OSError("compiler forwarding made no progress")
                view = view[count:]


def compiler_arguments(argv: list[str], workspace: Path) -> tuple[str, ...]:
    """Admit only version or literal Standard JSON compilation in the owned source tree."""
    if (
        type(argv) is not list
        or not 1 <= len(argv) <= 128
        or any(type(arg) is not str for arg in argv)
        or len(json.dumps(argv, ensure_ascii=True).encode()) > 65_536
    ):
        raise ValueError("compiler argument population is not bounded")
    if argv == ["--version"]:
        return tuple(argv)
    result = []
    flags: set[str] = set()
    index = 0
    while index < len(argv):
        flag = argv[index]
        if flag in flags:
            raise ValueError("duplicate compiler argument")
        flags.add(flag)
        if flag == "--standard-json":
            result.append(flag)
            index += 1
            continue
        if flag not in {"--base-path", "--include-path", "--allow-paths"} or index + 1 >= len(argv):
            raise ValueError("unsupported compiler argument")
        paths = argv[index + 1].split(",") if flag == "--allow-paths" else [argv[index + 1]]
        if not paths:
            raise ValueError("empty compiler path argument")
        for text in paths:
            path = Path(text)
            if not text:
                raise ValueError("compiler argument path is not exact")
            directory_identity(path)
            path.relative_to(workspace)
        # solc forbids combining --allow-paths with --no-import-callback. Keep
        # the received argv in the transcript, validate its scope, then replace
        # this permission with the strictly closed literal-input policy.
        if flag != "--allow-paths":
            result.extend((flag, argv[index + 1]))
        index += 2
    if "--standard-json" not in flags:
        raise ValueError("compiler call is not Standard JSON")
    # Explicitly recorded hardening, not an assertion that argv is unchanged.
    return (*result, "--no-import-callback")


def _validate_input(raw: bytes, sources: dict[str, list[str]]) -> None:
    value = decode(raw)
    if type(value) is not dict or value.get("language") != "Solidity":
        raise ValueError("compiler input language is not Solidity")
    supplied = value.get("sources")
    if type(supplied) is not dict or not supplied or not supplied.keys() <= sources.keys():
        raise ValueError("compiler input source population escapes the owned plan")
    for path, item in supplied.items():
        if type(item) is not dict or set(item) != {"content"} or type(item["content"]) is not str:
            raise ValueError("compiler source is not literal content")
        if _hash(item["content"].encode("utf-8")) not in sources[path]:
            raise ValueError("compiler input source differs from the owned byte population")


def validate_output(incoming: bytes, outgoing: bytes) -> None:
    """Reject incomplete/failed Standard JSON output even when solc exits zero."""
    request, output = decode(incoming), decode(outgoing)
    if type(output) is not dict or type(output.get("sources")) is not dict:
        raise ValueError("compiler output lacks its exact source population")
    if set(output["sources"]) != set(request["sources"]):
        raise ValueError("compiler input/output source populations differ")
    errors = output.get("errors", [])
    if type(errors) is not list or any(
        type(item) is not dict or item.get("severity") not in {"info", "warning"} for item in errors
    ):
        raise ValueError("compiler output includes a compilation error or malformed diagnostic")


def _compile(
    command: list[str], input_path: Path, directory: Path, limits: dict[str, int], deadline: float
) -> tuple[int, bytes, bytes]:
    process: subprocess.Popen[bytes] | None = None
    streams: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    stream_fds: dict[str, int] = {}
    try:
        for name in streams:
            stream_fds[name] = os.open(
                directory / (name + ".bin"),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
        _check_deadline(deadline)
        original, identity = file_snapshot(input_path, limits["max_stdin_bytes"])
        source_fd = os.open(input_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(source_fd, "rb") as source:
            if _metadata(os.fstat(source.fileno())) != identity[1]:
                raise ValueError("retained compiler input was replaced before dispatch")
            process = subprocess.Popen(
                command,
                stdin=source,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=directory,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                shell=False,
            )
            assert process.stdout is not None and process.stderr is not None
            with selectors.DefaultSelector() as selector:
                for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                while selector.get_map():
                    _check_deadline(deadline)
                    for key, _ in selector.select(min(0.05, max(0.0, deadline - time.monotonic()))):
                        name = key.data
                        remaining = min(
                            limits["max_" + name + "_bytes"] - len(streams[name]),
                            limits["remaining_output_bytes"] - sum(map(len, streams.values())),
                        )
                        try:
                            block = os.read(key.fd, min(65_536, remaining + 1))
                        except BlockingIOError:
                            continue
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        streams[name].extend(block)
                        _write_all(stream_fds[name], block)
                        if len(streams[name]) > limits["max_" + name + "_bytes"] or (
                            sum(map(len, streams.values())) > limits["remaining_output_bytes"]
                        ):
                            raise ValueError("compiler output exceeds its byte ceiling")
                code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            _check_deadline(deadline)
            if _metadata(os.fstat(source.fileno())) != identity[1] or file_snapshot(
                input_path, limits["max_stdin_bytes"]
            ) != (original, identity):
                raise ValueError("retained compiler input changed during execution")
    finally:
        try:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=1)
        finally:
            if process is not None:
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
            for fd in stream_fds.values():
                os.close(fd)
            write_bytes(
                directory / "process.json",
                json.dumps(
                    {
                        "process_started": process is not None,
                        "compiler_exit_code": process.returncode if process is not None else None,
                    },
                    sort_keys=True,
                ).encode(),
            )
    return code, bytes(streams["stdout"]), bytes(streams["stderr"])


def capture_main(
    root: str, plan_sha256: str, argv: list[str], *, helper_root: str | None = None
) -> int:
    """Capture one original invocation; partial/failed records block later invocations."""
    directory: Path | None = None
    lock_fd: int | None = None
    selected: Path | None = None
    plan_verified = False
    try:
        selected = Path(root)
        root_identity = directory_identity(selected)
        helpers = selected if helper_root is None else Path(helper_root)
        directory_identity(helpers)
        plan_raw = file_bytes(helpers / "plan.json", 2_000_000)
        if _hash(plan_raw) != plan_sha256:
            raise ValueError("compiler capture plan changed")
        plan_verified = True
        plan = decode(plan_raw)
        deadline = plan["deadline_monotonic"]
        _check_deadline(deadline)
        launch_receipt_sha256 = (
            None
            if plan["owner_launch_receipt_path"] is None
            else _hash(file_bytes(Path(plan["owner_launch_receipt_path"]), 524_288))
        )
        limits = plan["limits"]
        lock_fd = os.open(selected / "serial.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        helper_names = {"plan.json", "worker.py", "solc-capture"}
        expected = {"serial.lock", "calls"} | (helper_names if helpers == selected else set())
        if {p.name for p in selected.iterdir()} != expected or (
            helpers != selected and {p.name for p in helpers.iterdir()} != helper_names
        ):
            raise ValueError("compiler capture has a refused attempt or changed population")
        calls = selected / "calls"
        calls_identity = directory_identity(calls)
        previous = sorted(calls.iterdir())
        if len(previous) >= limits["max_invocations"]:
            raise ValueError("compiler invocation ceiling exhausted")
        used = 0
        for index, path in enumerate(previous):
            _check_deadline(deadline)
            if path.name != f"{index:04d}":
                raise ValueError("compiler capture population is not exact")
            directory_identity(path)
            if {p.name for p in path.iterdir()} != {
                "request.json",
                "intent.json",
                "stdin.bin",
                "stdout.bin",
                "stderr.bin",
                "process.json",
                "runtime.json",
                "complete.json",
            }:
                raise ValueError("prior compiler invocation is partial or changed")
            complete = decode(file_bytes(path / "complete.json", 65_536))
            if (
                type(complete["compiler_exit_code"]) is not int
                or complete["compiler_exit_code"] != 0
            ):
                raise ValueError("prior compiler invocation failed")
            if _hash(file_bytes(path / "runtime.json", 524_288)) != complete["runtime_sha256"]:
                raise ValueError("prior compiler runtime observation changed")
            if complete["owner_launch_receipt_sha256"] != launch_receipt_sha256:
                raise ValueError("prior compiler owner launch receipt changed")
            for name in ("stdin", "stdout", "stderr"):
                _check_deadline(deadline)
                raw = file_bytes(path / (name + ".bin"), limits["max_total_stream_bytes"])
                if _hash(raw) != complete[name + "_sha256"]:
                    raise ValueError("prior compiler transcript changed")
                used += len(raw)
        directory = calls / f"{len(previous):04d}"
        directory.mkdir(mode=0o700)
        request_raw = json.dumps({"received_argv": argv}, sort_keys=True).encode()
        if len(request_raw) > 65_536:
            raise ValueError("compiler request arguments exceed their byte ceiling")
        write_bytes(directory / "request.json", request_raw)
        runtime_raw = runtime_observation(plan)
        write_bytes(directory / "runtime.json", runtime_raw)
        compiler = Path(plan["compiler_path"])
        actual = compiler_arguments(argv, Path(plan["workspace"]))
        write_bytes(
            directory / "intent.json",
            json.dumps({"received_argv": argv, "compiler_argv": actual}, sort_keys=True).encode(),
        )
        compiler_raw, compiler_identity = file_snapshot(compiler, 200_000_000)
        if _hash(compiler_raw) != plan["compiler_sha256"]:
            raise ValueError("pinned compiler bytes changed")
        remaining = limits["max_total_stream_bytes"] - used
        if remaining < 0:
            raise ValueError("prior compiler transcript exceeds the session ceiling")
        incoming = (
            b""
            if argv == ["--version"]
            else _input(
                directory / "stdin.bin", min(limits["max_stdin_bytes"], remaining), deadline
            )
        )
        if argv == ["--version"]:
            write_bytes(directory / "stdin.bin", incoming)
        if argv != ["--version"]:
            _validate_input(incoming, plan["source_sha256s"])
        limits = {**limits, "remaining_output_bytes": remaining - len(incoming)}
        code, stdout, stderr = _compile(
            [str(compiler), *actual], directory / "stdin.bin", directory, limits, deadline
        )
        if file_snapshot(compiler, 200_000_000) != (compiler_raw, compiler_identity):
            raise ValueError("pinned compiler changed during execution")
        _forward(1, stdout, deadline)
        _forward(2, stderr, deadline)
        if code == 0 and argv != ["--version"]:
            validate_output(incoming, stdout)
        _check_deadline(deadline)
        if (
            directory_identity(selected) != root_identity
            or directory_identity(calls) != calls_identity
            or (selected / "refused.json").exists()
        ):
            raise ValueError("compiler capture custody changed during execution")
        complete = {
            "compiler_exit_code": code,
            "stdin_sha256": _hash(incoming),
            "stdout_sha256": _hash(stdout),
            "stderr_sha256": _hash(stderr),
            "runtime_sha256": _hash(runtime_raw),
            "owner_launch_receipt_sha256": launch_receipt_sha256,
        }
        write_bytes(directory / "complete.json", json.dumps(complete, sort_keys=True).encode())
        return code
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        RecursionError,
        subprocess.SubprocessError,
    ) as exc:
        if directory is not None:
            with suppress(OSError):
                write_bytes(
                    directory / "failed.json",
                    json.dumps({"failure_kind": type(exc).__name__}).encode(),
                )
        if plan_verified and selected is not None:
            with suppress(OSError, ValueError):
                directory_identity(selected)
                write_bytes(
                    selected / "refused.json",
                    json.dumps({"failure_kind": type(exc).__name__}).encode(),
                )
        return 125
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
