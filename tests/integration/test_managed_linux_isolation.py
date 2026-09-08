"""Real offline setup and conditional Linux isolation; never a real Semgrep audit."""

from __future__ import annotations

import hashlib
import platform
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from mmaudit.isolation.managed import ManagedIsolationError
from mmaudit.models.schemas import ExecutionEvidenceKind, ScannerStatus
from mmaudit.orchestration.managed_host_tools import ManagedHostToolSource
from mmaudit.orchestration.managed_provisioning_runtime import provision_managed_local_run
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainMemberKind,
    ManagedToolchainRole,
    seal_managed_toolchain_bundle,
)
from mmaudit.scanners import base
from mmaudit.scanners.runner import ScannerRunner
from mmaudit.scanners.semgrep import SemgrepScanner
from tests.host_tool_material_support import setup_host_material_inputs

_CONTROL = """from pathlib import Path
import sys
material, outside = (Path(value) for value in sys.argv[1:3])
assert material.is_dir()
assert {item.name for item in material.iterdir()} == set(sys.argv[3:])
assert not outside.exists()
try:
    with (material / "prohibited-write").open("xb") as stream:
        stream.write(b"synthetic invariant failure")
except OSError:
    pass
else:
    raise AssertionError("invariant: managed tool material must be read-only")
print('{"results":[],"errors":[]}')
"""
_SHELL_PROBES = {
    'printf "workspace-ok" > "$1"',
    'IFS= read -r _value < "$1"',
    'printf "boundary-failed" > "$1"',
    'test -z "${OPENROUTER_API_KEY+x}" && test -z "${MMAUDIT_SECRETS_ENV_FILE+x}"',
}


@pytest.mark.parametrize("repeat", [False, True])
def test_native_unsupported_host_refuses_after_real_offline_setup_without_invocation(
    tmp_path, config_factory, monkeypatch, repeat
):
    if platform.system() == "Linux":
        pytest.skip("native unsupported-host case is complementary to the Linux runtime test")
    config = config_factory(
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
        scanners={"semgrep": {"enabled": True, "required": True}},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    source_sha256 = base.scanner_workspace_sha256(repository)

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: unsupported managed host must not invoke, discover or connect")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    args = dict(bundle=bundle, config=config, repository=repository, output_dir=output)
    result = provision_managed_local_run(
        **args, verify_only=False, host_tool_source=ManagedHostToolSource(blob_root=store)
    )
    if repeat:
        result = provision_managed_local_run(
            **args, verify_only=True, host_tool_source=ManagedHostToolSource()
        )
    assert result.host_tools is not None
    with pytest.raises(ManagedIsolationError, match="managed"):
        ScannerRunner(result.config, host_tools=result.host_tools)
    result.host_tools.verify()
    assert base.scanner_workspace_sha256(repository) == source_sha256
    assert result.receipt.runtime_authority is result.receipt.managed_run_ready is False


@pytest.mark.skipif(
    platform.system() != "Linux", reason="INCONCLUSIVE: real managed Bubblewrap requires Linux"
)
@pytest.mark.parametrize("repeat", [False, True])
@pytest.mark.parametrize("mutation", ["none", "launcher", "scanner"])
@pytest.mark.asyncio
async def test_real_managed_linux_runner_keeps_tools_read_only_and_unrelated_output_hidden(
    tmp_path, config_factory, monkeypatch, repeat, mutation
):
    target = {
        "x86_64": "linux-amd64",
        "AMD64": "linux-amd64",
        "aarch64": "linux-arm64",
        "arm64": "linux-arm64",
    }.get(platform.machine())
    if target is None:
        pytest.skip("INCONCLUSIVE: unsupported native Linux architecture")
    launcher = Path("/usr/bin/bwrap")
    if not launcher.is_file():
        pytest.skip("INCONCLUSIVE: fixed system Bubblewrap is unavailable")
    launcher = launcher.resolve(strict=True)
    python = Path(sys.executable).resolve(strict=True)
    project_root = Path(__file__).resolve().parents[2]
    assert not launcher.is_relative_to(project_root) and not python.is_relative_to(project_root)
    helpers = {}
    for name, paths in {
        "true": ("/usr/bin/true", "/bin/true"),
        "sh": ("/bin/sh", "/usr/bin/sh"),
        "nc": ("/usr/bin/nc", "/bin/nc"),
    }.items():
        helper = next(
            (Path(path).resolve(strict=True) for path in paths if Path(path).is_file()), None
        )
        if helper is None:
            pytest.skip("INCONCLUSIVE: a fixed OS preflight helper is unavailable")
        helpers[name] = str(helper)
    config = config_factory(
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
        scanners={"semgrep": {"enabled": True, "required": True}},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    digests = {}
    for role, executable in (
        (ManagedToolchainRole.BUBBLEWRAP, launcher),
        (ManagedToolchainRole.SEMGREP, python),
    ):
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        blob = store / f"{digest}.blob"
        shutil.copyfile(executable, blob)
        blob.chmod(0o600)
        digests[role] = digest
    version = ".".join(str(value) for value in sys.version_info[:3])
    members = []
    for member in bundle.members:
        updates = {}
        if member.role in digests:
            updates["sha256"] = digests[member.role]
            updates["version"] = (
                version
                if member.role is ManagedToolchainRole.SEMGREP
                else "synthetic-system-control"
            )
        if member.kind is ManagedToolchainMemberKind.OCI_IMAGE:
            updates["platform"] = target
        members.append(member.model_copy(update=updates))
    bundle = seal_managed_toolchain_bundle(members=tuple(members), target_platform=target)
    args = dict(bundle=bundle, config=config, repository=repository, output_dir=output)
    prepared = provision_managed_local_run(
        **args, verify_only=False, host_tool_source=ManagedHostToolSource(blob_root=store)
    )
    if repeat:
        prepared = provision_managed_local_run(
            **args, verify_only=True, host_tool_source=ManagedHostToolSource()
        )
    material = prepared.host_tools
    assert material is not None
    bwrap = material.executable_for(ManagedToolchainRole.BUBBLEWRAP)
    control = material.executable_for(ManagedToolchainRole.SEMGREP)
    outside = output / "unrelated-synthetic-canary"
    outside.write_text("must remain outside the scanner namespace\n")
    names = sorted(path.name for path in material.directory.iterdir())
    scan_command = [
        str(control),
        "-I",
        "-c",
        _CONTROL,
        str(material.directory),
        str(outside),
        *names,
    ]
    real_popen = subprocess.Popen
    calls = []
    original_build = SemgrepScanner.build_command

    def build(adapter, root, private_dir):
        assert original_build(adapter, root, private_dir)[0] == str(control)
        return scan_command.copy()

    def local_nc(argv):
        return len(argv) == 6 and argv[:5] == [helpers["nc"], "-z", "-w", "1", "127.0.0.1"]

    def guarded_popen(argv, *args, **kwargs):
        assert kwargs["shell"] is False
        assert not {"OPENROUTER_API_KEY", "MMAUDIT_SECRETS_ENV_FILE"}.intersection(kwargs["env"])
        if argv[0] == str(bwrap):
            assert (
                hashlib.sha256(bwrap.read_bytes()).hexdigest()
                == digests[ManagedToolchainRole.BUBBLEWRAP]
            )
            payload = argv[argv.index("--") + 1 :]
            if payload[0] == str(control):
                assert payload in ([str(control), "--version"], scan_command)
                assert (
                    hashlib.sha256(control.read_bytes()).hexdigest()
                    == digests[ManagedToolchainRole.SEMGREP]
                )
            else:
                assert (
                    payload == [helpers["true"]]
                    or local_nc(payload)
                    or (payload[:2] == [helpers["sh"], "-c"] and payload[2] in _SHELL_PROBES)
                )
        else:
            assert local_nc(argv)
        calls.append(argv.copy())
        return real_popen(argv, *args, **kwargs)

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: prepared managed tools must not use ambient PATH discovery")

    monkeypatch.setattr(subprocess, "Popen", guarded_popen)
    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(SemgrepScanner, "build_command", build)
    if mutation != "none":
        changed = bwrap if mutation == "launcher" else control
        changed.chmod(0o600)
        changed.write_bytes(b"inert changed material must never execute\n")
        changed.chmod(0o500)
        with pytest.raises(ValueError, match=r"managed|material"):
            ScannerRunner(prepared.config, host_tools=material)
        assert calls == []
        return
    # Once Linux and the fixed tools are present, a failed boundary is a test
    # failure, not a skipped safety assertion or permission to fall back.
    runner = ScannerRunner(prepared.config, host_tools=material)
    outcomes = await runner.run_all(
        repository, tmp_path / "scanner-private", audited_relative_paths=("ControlB.sol",)
    )
    result = next(item for item in outcomes if item.scanner == "semgrep")
    assert result.status is ScannerStatus.SUCCESS
    assert (
        result.execution_evidence is ExecutionEvidenceKind.REAL
    )  # Real local control, not Semgrep.
    assert result.executable_sha256 == digests[ManagedToolchainRole.SEMGREP]
    assert result.findings == [] and runner.required_failures(outcomes) == []
    assert outside.read_text() == "must remain outside the scanner namespace\n"
    material.verify()
    assert prepared.receipt.runtime_authority is prepared.receipt.managed_run_ready is False
