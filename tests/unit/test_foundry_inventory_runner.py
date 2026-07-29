from __future__ import annotations

import hashlib
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import pytest

import mmaudit.scanners.foundry_inventory_runner as runner_module
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    RepositorySuiteInventoryPhase,
    SolidityProjectMetadata,
    SolidityProjectType,
)
from mmaudit.scanners.base import scanner_workspace_sha256
from mmaudit.scanners.foundry_inventory import (
    FoundryInventoryLimits,
    FoundryInventorySourceBinding,
    FoundrySourceInput,
    FoundryTestDeclaration,
    FoundryTestInventory,
)
from mmaudit.scanners.foundry_inventory_runner import (
    FoundryInventoryInvalidError,
    FoundryInventoryOverflowError,
    FoundryInventoryRunLimits,
    FoundryInventoryRunResult,
    FoundryInventoryTimeoutError,
    FoundryInventoryUnavailableError,
    run_foundry_test_inventory,
)

_ATTESTATION_SHA256 = "a" * 64
_CONFIGURATION_SHA256 = "b" * 64
_COMPILER_VERSION = "0.8.30"
_SOURCE_PATH = "test/Suite.t.sol"
_SOURCE = "contract SuiteTest { function testInventory() public {} }\n"


@dataclass
class _MockIsolationBackend:
    name: str = "mock-isolation"
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.MOCK
    commands: list[list[str]] = field(default_factory=list)
    cleanup_calls: int = 0

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        assert workspace.is_dir()
        assert private_dir.is_dir()
        assert rpc_port == 1
        self.commands.append(list(command))
        return list(command)

    def host_environment(self, private_dir: Path) -> dict[str, str]:
        return {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(private_dir / "host-home"),
            "ALCHEMY_API_KEY": "inventory-rpc-canary",
            "OPENROUTER_API_KEY": "inventory-secret-canary",
            "PRIVATE_KEY": "inventory-private-key-canary",
            "WALLET_PRIVATE_KEY": "inventory-wallet-canary",
            "MNEMONIC": "inventory-mnemonic-canary",
            "ETH_RPC_URL": "https://forbidden.invalid",
            "MMAUDIT_FORK_RPC_URL": "https://forbidden.invalid",
        }

    def cleanup(self, private_dir: Path) -> None:
        assert private_dir.is_dir()
        self.cleanup_calls += 1


class _NoNetworkMockIsolationBackend(_MockIsolationBackend):
    def __init__(self) -> None:
        super().__init__()
        self.no_network_calls = 0

    def wrap_without_network(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        self.no_network_calls += 1
        return self.wrap(
            command,
            workspace=workspace,
            private_dir=private_dir,
            rpc_port=rpc_port,
        )


@dataclass(frozen=True)
class _Harness:
    private_dir: Path
    workspace: Path
    forge: Path
    solc: Path
    forge_sha256: str
    solc_sha256: str
    repository_sha256: str
    projects: tuple[SolidityProjectMetadata, ...]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_executable(path: Path, body: str) -> None:
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(0o700)


def _forge_body(mode: str) -> str:
    prefix = (
        "import json, os, pathlib, sys, time\n"
        "for name in ('ALCHEMY_API_KEY', 'OPENROUTER_API_KEY', 'PRIVATE_KEY', "
        "'WALLET_PRIVATE_KEY', 'MNEMONIC', 'ETH_RPC_URL', 'MMAUDIT_FORK_RPC_URL'):\n"
        "    if name in os.environ:\n"
        "        raise SystemExit(91)\n"
    )
    if mode == "nonzero":
        return prefix + "raise SystemExit(3)\n"
    if mode == "timeout":
        return prefix + "time.sleep(5)\n"
    if mode == "overflow":
        return prefix + "print('x' * 8192)\n"
    if mode == "combined_overflow":
        return (
            prefix + "build_info = pathlib.Path("
            "sys.argv[sys.argv.index('--build-info-path') + 1])\n"
            + "(build_info / 'combined.bin').write_bytes(b'x' * 1536)\n"
            + "sys.stdout.write('y' * 1024)\n"
        )
    common = (
        "build_info = pathlib.Path(sys.argv[sys.argv.index('--build-info-path') + 1])\n"
        "build_info.mkdir(parents=True, exist_ok=True)\n"
        f"source_path = pathlib.Path({_SOURCE_PATH!r})\n"
        "source = source_path.read_text(encoding='utf-8')\n"
        "project = pathlib.Path.cwd().resolve()\n"
        "payload = {'id': 'a' * 16, 'input': {"
        "'basePath': str(project), "
        "'allowPaths': [str(project)], "
        "'includePaths': [str((project / 'test').resolve())], "
        "'sources': {str(source_path): {'content': source}}}}\n"
    )
    if mode == "symlink":
        return (
            prefix
            + common
            + "os.symlink(source_path.resolve(), build_info / 'linked.json')\n"
            + "print(json.dumps({str(source_path): {'SuiteTest': ['testInventory()']}}))\n"
        )
    if mode == "mutate":
        return (
            prefix
            + common
            + "(build_info / 'build.json').write_text(json.dumps(payload), encoding='utf-8')\n"
            + "source_path.write_text(source + '// changed\\n', encoding='utf-8')\n"
            + "print(json.dumps({str(source_path): {'SuiteTest': ['testInventory()']}}))\n"
        )
    assert mode == "success"
    return (
        prefix
        + common
        + "(build_info / 'build.json').write_text(json.dumps(payload), encoding='utf-8')\n"
        + "print(json.dumps({str(source_path): {'SuiteTest': ['testInventory()']}}))\n"
    )


def _harness(tmp_path: Path, *, mode: str, project_roots: tuple[str, ...] = (".",)) -> _Harness:
    private_dir = tmp_path / "private"
    workspace = private_dir / "workspace"
    workspace.mkdir(parents=True)
    projects: list[SolidityProjectMetadata] = []
    for project_root in project_roots:
        project_path = workspace if project_root == "." else workspace / project_root
        (project_path / "test").mkdir(parents=True)
        (project_path / _SOURCE_PATH).write_text(_SOURCE, encoding="utf-8")
        projects.append(
            SolidityProjectMetadata(
                project_type=SolidityProjectType.FOUNDRY,
                project_root=project_root,
                test_directories=["test"],
            )
        )
    forge = tmp_path / "forge"
    _write_executable(forge, _forge_body(mode))
    solc = private_dir / "toolchain" / "solc"
    solc.parent.mkdir()
    _write_executable(solc, "raise SystemExit(0)\n")
    return _Harness(
        private_dir=private_dir,
        workspace=workspace,
        forge=forge,
        solc=solc,
        forge_sha256=_sha256(forge.read_bytes()),
        solc_sha256=_sha256(solc.read_bytes()),
        repository_sha256=scanner_workspace_sha256(workspace),
        projects=tuple(reversed(projects)),
    )


def _parser_stub(
    *,
    forge_list_json: bytes,
    build_info_jsons: Sequence[bytes],
    sources: Sequence[FoundrySourceInput],
    project_root: str = ".",
    compiler_version: str,
    compiler_sha256: str,
    limits: FoundryInventoryLimits | None = None,
) -> FoundryTestInventory:
    del limits
    assert json.loads(forge_list_json) == {_SOURCE_PATH: {"SuiteTest": ["testInventory()"]}}
    assert len(build_info_jsons) == 1
    assert len(sources) == 1
    source = sources[0]
    assert source.path == _SOURCE_PATH
    assert source.content.decode() == _SOURCE
    build_info_sha256 = _sha256(build_info_jsons[0])
    declaration = FoundryTestDeclaration.sealed(
        project_root=project_root,
        execution_path=_SOURCE_PATH,
        execution_suite_name="SuiteTest",
        test_name="testInventory",
        test_signature="testInventory()",
        declaration_signature="testInventory()",
        declaration_path=_SOURCE_PATH,
        declaration_contract="SuiteTest",
        source_sha256=source.source_sha256,
        start_line=1,
        end_line=1,
        execution_source_sha256=source.source_sha256,
        execution_start_line=1,
        execution_end_line=1,
        execution_contract_ast_id=10,
        declaration_contract_ast_id=10,
        function_ast_id=11,
        build_info_sha256=build_info_sha256,
    )
    return FoundryTestInventory.sealed(
        project_root=project_root,
        forge_list_sha256=_sha256(forge_list_json),
        compiler_version=compiler_version,
        compiler_sha256=compiler_sha256,
        build_info_sha256s=(build_info_sha256,),
        sources=(
            FoundryInventorySourceBinding(
                path=source.path,
                source_sha256=source.source_sha256,
                size_bytes=len(source.content),
            ),
        ),
        suite_count=1,
        test_count=1,
        tests=(declaration,),
    )


def _run(
    harness: _Harness,
    backend: _MockIsolationBackend,
    monkeypatch: pytest.MonkeyPatch,
    *,
    timeout_seconds: float = 5,
    limits: FoundryInventoryRunLimits | None = None,
) -> FoundryInventoryRunResult:
    monkeypatch.setattr(
        runner_module,
        "isolation_attestation_sha256",
        lambda _backend: _ATTESTATION_SHA256,
    )
    monkeypatch.setattr(runner_module, "parse_foundry_test_inventory", _parser_stub)
    return run_foundry_test_inventory(
        workspace=harness.workspace,
        private_dir=harness.private_dir,
        projects=harness.projects,
        phase=RepositorySuiteInventoryPhase.PRE_EXECUTION,
        forge_executable=harness.forge,
        copied_solc=harness.solc,
        repository_sha256=harness.repository_sha256,
        configuration_sha256=_CONFIGURATION_SHA256,
        tool_version="forge 1.3.2",
        tool_sha256=harness.forge_sha256,
        compiler_version=_COMPILER_VERSION,
        compiler_sha256=harness.solc_sha256,
        backend=backend,
        timeout_seconds=timeout_seconds,
        limits=limits,
    )


def _build_info_with_paths(
    project_path: Path,
    *,
    build_id: str,
    base_path: str | None = None,
    allow_paths: list[object] | None = None,
) -> bytes:
    compiler_input: dict[str, object] = {
        "basePath": base_path or str(project_path),
        "allowPaths": (
            allow_paths
            if allow_paths is not None
            else [str(project_path), str(project_path / "lib")]
        ),
        "includePaths": [str(project_path / "include")],
        "sources": {_SOURCE_PATH: {"content": _SOURCE}},
    }
    return json.dumps(
        {"id": build_id, "input": compiler_input},
        separators=(", ", ": "),
    ).encode()


def test_build_info_normalization_is_stable_across_fresh_private_roots(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first-private" / "workspace" / "packages" / "core"
    second = tmp_path / "second-private" / "workspace" / "packages" / "core"
    for project in (first, second):
        (project / "include").mkdir(parents=True)
    first_raw = _build_info_with_paths(first, build_id="a" * 16)
    second_raw = _build_info_with_paths(second, build_id="b" * 16)

    first_normalized = runner_module._normalize_build_info_json(
        first_raw,
        project_path=first,
        project_root="packages/core",
        maximum_bytes=100_000,
    )
    second_normalized = runner_module._normalize_build_info_json(
        second_raw,
        project_path=second,
        project_root="packages/core",
        maximum_bytes=100_000,
    )

    assert first_raw != second_raw
    assert first_normalized == second_normalized
    assert _sha256(first_normalized) == _sha256(second_normalized)
    payload = json.loads(first_normalized)
    assert payload["id"] == "0" * 16
    assert payload["input"]["basePath"] == "packages/core"
    assert payload["input"]["allowPaths"] == [
        "packages/core",
        "packages/core/lib",
    ]
    assert payload["input"]["includePaths"] == ["packages/core/include"]


def test_generated_usage_rejects_symlinked_intermediate_directory(
    tmp_path: Path,
) -> None:
    trusted_root = tmp_path / "private"
    outside = tmp_path / "outside"
    (outside / "generated").mkdir(parents=True)
    trusted_root.mkdir()
    (outside / "generated" / "outside.bin").write_bytes(b"outside")
    try:
        (trusted_root / "redirect").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")

    with pytest.raises(
        FoundryInventoryInvalidError,
        match="opened safely",
    ):
        runner_module._generated_usage(
            (trusted_root / "redirect" / "generated",),
            FoundryInventoryRunLimits(),
            trusted_root=trusted_root,
        )


def test_live_generated_usage_tolerates_directory_entry_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated_root = tmp_path / "generated"
    generated_root.mkdir()
    (generated_root / "initial.bin").write_bytes(b"initial")
    real_entry_names = runner_module._directory_entry_names
    mutated = False

    def create_after_enumeration(descriptor: int, *, label: str) -> tuple[str, ...]:
        nonlocal mutated
        names = real_entry_names(descriptor, label=label)
        if not mutated:
            (generated_root / "created.bin").write_bytes(b"created")
            mutated = True
        return names

    monkeypatch.setattr(runner_module, "_directory_entry_names", create_after_enumeration)

    usage = runner_module._generated_usage(
        (generated_root,),
        FoundryInventoryRunLimits(),
        purpose=runner_module._GeneratedTraversalPurpose.LIVE_LIMIT_MONITOR,
    )

    assert mutated is True
    assert usage.entries == 1
    assert usage.bytes == len(b"initial")


def test_strict_generated_usage_rejects_directory_entry_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated_root = tmp_path / "generated"
    generated_root.mkdir()
    (generated_root / "initial.bin").write_bytes(b"initial")
    real_entry_names = runner_module._directory_entry_names
    mutated = False

    def create_after_enumeration(descriptor: int, *, label: str) -> tuple[str, ...]:
        nonlocal mutated
        names = real_entry_names(descriptor, label=label)
        if not mutated:
            (generated_root / "created.bin").write_bytes(b"created")
            mutated = True
        return names

    monkeypatch.setattr(runner_module, "_directory_entry_names", create_after_enumeration)

    with pytest.raises(
        FoundryInventoryInvalidError,
        match=r"generated root.*changed during traversal",
    ):
        runner_module._generated_usage(
            (generated_root,),
            FoundryInventoryRunLimits(),
        )

    assert mutated is True


def test_live_generated_usage_discards_replaced_directory_sample(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_root = tmp_path / "private"
    generated_root = trusted_root / "generated"
    generated_root.mkdir(parents=True)
    (generated_root / "initial.bin").write_bytes(b"initial")
    moved_root = trusted_root / "moved-generated"
    real_open_directory_at = runner_module._open_directory_at
    replaced = False

    def replace_before_open(
        parent_descriptor: int,
        name: str,
        *,
        expected: os.stat_result,
        label: str,
        require_stable_snapshot: bool,
    ):
        nonlocal replaced
        if name == "generated" and not replaced:
            generated_root.rename(moved_root)
            generated_root.mkdir()
            replaced = True
        return real_open_directory_at(
            parent_descriptor,
            name,
            expected=expected,
            label=label,
            require_stable_snapshot=require_stable_snapshot,
        )

    monkeypatch.setattr(runner_module, "_open_directory_at", replace_before_open)

    usage = runner_module._generated_usage(
        (generated_root,),
        FoundryInventoryRunLimits(),
        trusted_root=trusted_root,
        purpose=runner_module._GeneratedTraversalPurpose.LIVE_LIMIT_MONITOR,
    )

    assert replaced is True
    assert usage.entries == 0
    assert usage.bytes == 0


def test_build_info_normalization_preserves_include_path_precedence(
    tmp_path: Path,
) -> None:
    project = tmp_path / "private" / "workspace"
    (project / "first").mkdir(parents=True)
    (project / "second").mkdir()
    first = _build_info_with_paths(
        project,
        build_id="a" * 16,
        allow_paths=[str(project / "first"), str(project / "second")],
    )
    second = _build_info_with_paths(
        project,
        build_id="a" * 16,
        allow_paths=[str(project / "second"), str(project / "first")],
    )

    first_normalized = runner_module._normalize_build_info_json(
        first,
        project_path=project,
        project_root=".",
        maximum_bytes=100_000,
    )
    second_normalized = runner_module._normalize_build_info_json(
        second,
        project_path=project,
        project_root=".",
        maximum_bytes=100_000,
    )

    assert first_normalized != second_normalized
    assert json.loads(first_normalized)["input"]["allowPaths"] == ["first", "second"]
    assert json.loads(second_normalized)["input"]["allowPaths"] == ["second", "first"]


def test_build_info_normalization_rejects_absolute_path_outside_project(
    tmp_path: Path,
) -> None:
    project = tmp_path / "private" / "workspace" / "packages" / "core"
    outside = tmp_path / "outside"
    (project / "lib").mkdir(parents=True)
    (project / "include").mkdir()
    outside.mkdir()
    raw = _build_info_with_paths(
        project,
        build_id="a" * 16,
        base_path=str(outside),
    )

    with pytest.raises(
        FoundryInventoryInvalidError,
        match="escapes its project root",
    ):
        runner_module._normalize_build_info_json(
            raw,
            project_path=project,
            project_root="packages/core",
            maximum_bytes=100_000,
        )


def test_build_info_normalization_rejects_duplicate_keys_and_paths(
    tmp_path: Path,
) -> None:
    project = tmp_path / "private" / "workspace"
    (project / "lib").mkdir(parents=True)
    (project / "include").mkdir()
    duplicate_key = b'{"id":"aaaaaaaaaaaaaaaa","input":{},"input":{"basePath":"."}}'
    with pytest.raises(FoundryInventoryInvalidError, match="duplicate JSON keys"):
        runner_module._normalize_build_info_json(
            duplicate_key,
            project_path=project,
            project_root=".",
            maximum_bytes=100_000,
        )

    duplicate_paths = _build_info_with_paths(
        project,
        build_id="a" * 16,
        allow_paths=[str(project / "lib"), f"{project / 'lib'}/."],
    )
    with pytest.raises(
        FoundryInventoryInvalidError,
        match="duplicate normalized paths",
    ):
        runner_module._normalize_build_info_json(
            duplicate_paths,
            project_path=project,
            project_root=".",
            maximum_bytes=100_000,
        )


def test_inventory_process_limits_skip_unsupported_darwin_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, tuple[int, int]]] = []
    fake_resource = SimpleNamespace(
        RLIMIT_CPU=1,
        RLIMIT_FSIZE=2,
        RLIMIT_NOFILE=3,
        RLIMIT_NPROC=4,
        RLIMIT_AS=5,
        setrlimit=lambda kind, value: calls.append((kind, value)),
    )
    monkeypatch.setitem(sys.modules, "resource", fake_resource)
    monkeypatch.setattr(sys, "platform", "darwin")

    runner_module._limit_inventory_process()

    assert [kind for kind, _ in calls] == [1, 2, 3]


def test_inventory_process_limits_attempt_every_limit_then_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    def failing_setrlimit(kind: int, value: tuple[int, int]) -> None:
        del value
        calls.append(kind)
        if kind == 1:
            raise OSError("synthetic limit failure")

    fake_resource = SimpleNamespace(
        RLIMIT_CPU=1,
        RLIMIT_FSIZE=2,
        RLIMIT_NOFILE=3,
        RLIMIT_NPROC=4,
        RLIMIT_AS=5,
        setrlimit=failing_setrlimit,
    )
    monkeypatch.setitem(sys.modules, "resource", fake_resource)
    monkeypatch.setattr(sys, "platform", "linux")

    with pytest.raises(RuntimeError, match="resource limit setup failed"):
        runner_module._limit_inventory_process()

    assert calls == [1, 2, 3, 4, 5]


@pytest.mark.parametrize("aliased_root", ["private", "workspace"])
def test_inventory_roots_reject_symlink_aliases_before_resolution(
    tmp_path: Path,
    aliased_root: str,
) -> None:
    private_dir = tmp_path / "private"
    workspace = private_dir / "workspace"
    workspace.mkdir(parents=True)
    if aliased_root == "private":
        private_alias = tmp_path / "private-alias"
        private_alias.symlink_to(private_dir, target_is_directory=True)
        supplied_private = private_alias
        supplied_workspace = private_alias / "workspace"
    else:
        workspace_alias = private_dir / "workspace-alias"
        workspace_alias.symlink_to(workspace, target_is_directory=True)
        supplied_private = private_dir
        supplied_workspace = workspace_alias

    with pytest.raises(
        FoundryInventoryInvalidError,
        match="is not a non-link directory",
    ):
        runner_module._validated_roots(supplied_private, supplied_workspace)


def test_bounded_file_read_uses_no_follow_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "artifact.json"
    artifact.write_bytes(b'{"ok":true}')
    observed_flags: list[int] = []
    real_open = os.open

    def recording_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        observed_flags.append(flags)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", recording_open)

    assert (
        runner_module._read_bounded_file(
            artifact,
            maximum_bytes=1_024,
            allow_empty=False,
            label="test artifact",
        )
        == b'{"ok":true}'
    )
    assert len(observed_flags) == 1
    assert observed_flags[0] & os.O_NOFOLLOW


def test_bounded_file_read_fails_closed_without_no_follow_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "artifact.json"
    artifact.write_bytes(b'{"ok":true}')
    monkeypatch.delattr(os, "O_NOFOLLOW")

    with pytest.raises(
        FoundryInventoryUnavailableError,
        match="no no-follow open flag is available",
    ):
        runner_module._read_bounded_file(
            artifact,
            maximum_bytes=1_024,
            allow_empty=False,
            label="test artifact",
        )


def test_bounded_file_read_rejects_path_replacement_during_descriptor_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "artifact.json"
    moved_artifact = tmp_path / "opened-artifact.json"
    artifact.write_bytes(b"trusted")
    replacement = b"changed"
    real_read = os.read
    replaced = False

    def replacing_read(descriptor: int, maximum_bytes: int) -> bytes:
        nonlocal replaced
        if not replaced:
            artifact.rename(moved_artifact)
            artifact.write_bytes(replacement)
            replaced = True
        return real_read(descriptor, maximum_bytes)

    monkeypatch.setattr(os, "read", replacing_read)

    with pytest.raises(
        FoundryInventoryInvalidError,
        match="changed while it was read",
    ):
        runner_module._read_bounded_file(
            artifact,
            maximum_bytes=1_024,
            allow_empty=False,
            label="test artifact",
        )

    assert replaced is True
    assert moved_artifact.read_bytes() == b"trusted"
    assert artifact.read_bytes() == replacement


@pytest.mark.parametrize(
    "purpose",
    (
        runner_module._GeneratedTraversalPurpose.STRICT_SNAPSHOT,
        runner_module._GeneratedTraversalPurpose.LIVE_LIMIT_MONITOR,
    ),
)
def test_generated_usage_rejects_queued_directory_replaced_by_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    purpose: runner_module._GeneratedTraversalPurpose,
) -> None:
    generated_root = tmp_path / "generated"
    queued_directory = generated_root / "queued"
    queued_directory.mkdir(parents=True)
    (queued_directory / "trusted.json").write_bytes(b"trusted")
    opened_directory = tmp_path / "opened-queued"
    outside_directory = tmp_path / "outside"
    outside_directory.mkdir()
    (outside_directory / "outside.json").write_bytes(b"outside")
    real_scandir = os.scandir
    scandir_calls = 0
    replaced = False

    def replacing_scandir(path: int | os.PathLike[str]) -> os.ScandirIterator[str]:
        nonlocal replaced, scandir_calls
        scandir_calls += 1
        if scandir_calls == 2:
            queued_directory.rename(opened_directory)
            queued_directory.symlink_to(outside_directory, target_is_directory=True)
            replaced = True
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", replacing_scandir)

    with pytest.raises(
        FoundryInventoryInvalidError,
        match="changed during traversal",
    ):
        runner_module._generated_usage(
            (generated_root,),
            FoundryInventoryRunLimits(),
            purpose=purpose,
        )

    assert replaced is True
    assert (opened_directory / "trusted.json").read_bytes() == b"trusted"


def test_build_info_read_rejects_artifact_replaced_after_enumeration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    build_info = tmp_path / "build-info"
    build_info.mkdir()
    artifact = build_info / "build.json"
    artifact.write_bytes(b'{"trusted":true}')
    moved_artifact = tmp_path / "opened-build.json"
    outside_artifact = tmp_path / "outside.json"
    outside_artifact.write_bytes(b'{"trusted":false}')
    real_entry_names = runner_module._directory_entry_names
    replaced = False

    def replacing_entry_names(descriptor: int, *, label: str) -> tuple[str, ...]:
        nonlocal replaced
        names = real_entry_names(descriptor, label=label)
        artifact.rename(moved_artifact)
        artifact.symlink_to(outside_artifact)
        replaced = True
        return names

    monkeypatch.setattr(runner_module, "_directory_entry_names", replacing_entry_names)

    with pytest.raises(
        FoundryInventoryInvalidError,
        match="changed before it was read",
    ):
        runner_module._read_build_info_artifacts(
            build_info,
            FoundryInventoryRunLimits(),
        )

    assert replaced is True
    assert moved_artifact.read_bytes() == b'{"trusted":true}'


def test_inventory_runner_executes_sorted_projects_and_seals_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _harness(
        tmp_path,
        mode="success",
        project_roots=("packages/zeta", "packages/alpha"),
    )
    backend = _NoNetworkMockIsolationBackend()

    result = _run(harness, backend, monkeypatch)

    assert tuple(item.project_root for item in result.inventories) == (
        "packages/alpha",
        "packages/zeta",
    )
    assert tuple(item.project_root for item in result.evidence.projects) == (
        "packages/alpha",
        "packages/zeta",
    )
    assert result.evidence.phase is RepositorySuiteInventoryPhase.PRE_EXECUTION
    assert result.evidence.execution_evidence is ExecutionEvidenceKind.MOCK
    assert result.evidence.isolation_attestation_sha256 == _ATTESTATION_SHA256
    assert result.evidence.inventory_record_count == 2
    assert result.accounted_output_bytes > 0
    assert result.generated_artifact_bytes > 0
    assert backend.cleanup_calls == 2
    assert backend.no_network_calls == 2
    assert len(backend.commands) == 2
    for command in backend.commands:
        assert command[:6] == [
            str(harness.forge),
            "test",
            "--list",
            "--json",
            "--ast",
            "--build-info",
        ]
        assert "--offline" in command
        assert "--no-auto-detect" in command
        assert "--no-storage-caching" in command
        assert "--fork-url" not in command
        assert command[command.index("--use") + 1] == str(harness.solc)
    for index, project in enumerate(result.evidence.projects):
        assert project.parser_inventory_sha256
        assert project.normalized_build_info_bundle_sha256
        assert len(project.build_info_artifacts) == 1
        artifact = project.build_info_artifacts[0]
        raw_artifact = (
            harness.private_dir
            / "repository-suite"
            / "inventory"
            / "pre_execution"
            / f"{index:05d}"
            / "build-info"
            / artifact.name
        ).read_bytes()
        assert artifact.bytes == len(raw_artifact)
        assert artifact.sha256 == _sha256(raw_artifact)
        assert artifact.normalized_sha256
        assert artifact.normalized_sha256 != artifact.sha256
        assert project.records[0].build_info_sha256 == (artifact.normalized_sha256)
        assert project.records[0].execution_signature == "testInventory()"


def test_inventory_runner_rejects_unattested_backend_before_execution(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path, mode="success")
    backend = _MockIsolationBackend()

    with pytest.raises(
        FoundryInventoryUnavailableError,
        match="lacks current attested",
    ):
        run_foundry_test_inventory(
            workspace=harness.workspace,
            private_dir=harness.private_dir,
            projects=harness.projects,
            phase=RepositorySuiteInventoryPhase.PRE_EXECUTION,
            forge_executable=harness.forge,
            copied_solc=harness.solc,
            repository_sha256=harness.repository_sha256,
            configuration_sha256=_CONFIGURATION_SHA256,
            tool_version="forge 1.3.2",
            tool_sha256=harness.forge_sha256,
            compiler_version=_COMPILER_VERSION,
            compiler_sha256=harness.solc_sha256,
            backend=backend,
            timeout_seconds=5,
        )

    assert backend.commands == []


def test_inventory_runner_classifies_nonzero_exit_as_invalid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _harness(tmp_path, mode="nonzero")
    backend = _MockIsolationBackend()

    with pytest.raises(FoundryInventoryInvalidError, match="exited with code 3"):
        _run(harness, backend, monkeypatch)

    assert backend.cleanup_calls == 1


def test_inventory_runner_classifies_timeout_and_stops_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _harness(tmp_path, mode="timeout")
    backend = _MockIsolationBackend()

    with pytest.raises(FoundryInventoryTimeoutError, match="exceeded its deadline"):
        _run(harness, backend, monkeypatch, timeout_seconds=0.05)

    assert backend.cleanup_calls == 1


def test_inventory_runner_classifies_stream_overflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _harness(tmp_path, mode="overflow")
    backend = _MockIsolationBackend()
    limits = FoundryInventoryRunLimits(
        max_stdout_bytes_per_project=1_024,
        max_stderr_bytes_per_project=1_024,
        max_total_stream_bytes=2_048,
    )

    with pytest.raises(FoundryInventoryOverflowError, match="exceeded"):
        _run(harness, backend, monkeypatch, limits=limits)


def test_inventory_runner_enforces_combined_stream_and_artifact_ceiling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _harness(tmp_path, mode="combined_overflow")
    backend = _MockIsolationBackend()
    limits = FoundryInventoryRunLimits(
        max_stdout_bytes_per_project=2_048,
        max_stderr_bytes_per_project=1_024,
        max_total_stream_bytes=2_048,
        max_generated_file_bytes=2_048,
        max_generated_bytes_per_project=2_048,
        max_total_generated_bytes=2_048,
        max_combined_output_bytes=2_048,
    )

    with pytest.raises(
        FoundryInventoryOverflowError,
        match="combined output ceiling",
    ):
        _run(harness, backend, monkeypatch, limits=limits)


def test_inventory_runner_rejects_generated_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _harness(tmp_path, mode="symlink")
    backend = _MockIsolationBackend()

    with pytest.raises(
        FoundryInventoryInvalidError,
        match="not a unique regular file",
    ):
        _run(harness, backend, monkeypatch)


def test_inventory_runner_rejects_workspace_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _harness(tmp_path, mode="mutate")
    backend = _MockIsolationBackend()

    with pytest.raises(
        FoundryInventoryInvalidError,
        match="workspace changed",
    ):
        _run(harness, backend, monkeypatch)
