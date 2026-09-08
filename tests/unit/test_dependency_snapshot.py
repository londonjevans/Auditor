from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import tarfile
from pathlib import Path

import pytest

import mmaudit.isolation.dependency_snapshot as snapshot_module
from mmaudit.isolation.dependency_snapshot import (
    DependencySnapshotBuildError,
    DependencySnapshotBuildLimits,
    DependencySnapshotVerificationError,
    build_managed_dependency_snapshot,
    verify_managed_dependency_snapshot,
)
from tests.dependency_snapshot_support import replace_archive, setup_snapshot_inputs


def _verify(inputs, built, **overrides):
    config = built.config.model_copy(update=overrides)
    return verify_managed_dependency_snapshot(repository=inputs[0], config=config)


def _snapshot_material(inputs, built):
    path = inputs[0] / built.config.offline_snapshot_path
    value = json.loads(path.read_bytes())
    package = path.parent / value["projects"][0]["packages"][0]["source"]
    return path, value, package


def _repin(path, value, built):
    path.write_text(json.dumps(value))
    return built.config.model_copy(
        update={"offline_snapshot_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    )


def test_configured_snapshot_verification_is_read_only_and_nonexecuting(tmp_path, monkeypatch):
    inputs = setup_snapshot_inputs(tmp_path)
    built = _build(inputs)
    path, _, package = _snapshot_material(inputs, built)
    before = {p: (p.stat(), p.read_bytes()) for p in path.parent.rglob("*") if p.is_file()}

    def forbidden(*_args, **_kwargs):
        raise AssertionError("dependency verification must remain inert and offline")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert _verify(inputs, built) == built.config.offline_snapshot_sha256
    assert _verify(inputs, built) == built.config.offline_snapshot_sha256
    assert {p: (p.stat(), p.read_bytes()) for p in before} == before
    assert (package / "DependencyBase.sol").is_file()


@pytest.mark.parametrize("target", ["snapshot", "lock", "package", "missing-manifest"])
def test_configured_snapshot_rejects_stale_or_incomplete_material(tmp_path, target):
    inputs = setup_snapshot_inputs(tmp_path)
    built = _build(inputs)
    path, _, package = _snapshot_material(inputs, built)
    changed = {
        "snapshot": path,
        "lock": inputs[0] / "package-lock.json",
        "package": package / "DependencyBase.sol",
        "missing-manifest": package / "package.json",
    }[target]
    if target == "missing-manifest":
        changed.unlink()
    else:
        changed.write_bytes(changed.read_bytes() + b" ")
    with pytest.raises(DependencySnapshotVerificationError):
        _verify(inputs, built)


@pytest.mark.parametrize(
    "kind", ["file-link", "directory-link", "hardlink", "fifo", "executable", "public"]
)
def test_configured_snapshot_rejects_unsafe_private_material(tmp_path, kind):
    inputs = setup_snapshot_inputs(tmp_path)
    built = _build(inputs)
    _, _, package = _snapshot_material(inputs, built)
    file = package / "DependencyBase.sol"
    if kind == "file-link":
        file.unlink()
        file.symlink_to(inputs[0] / "contracts/UsesDependency.sol")
    elif kind == "directory-link":
        (package / "linked").symlink_to(inputs[0], target_is_directory=True)
    elif kind == "hardlink":
        os.link(file, tmp_path / "linked.sol")
    elif kind == "fifo":
        os.mkfifo(package / "pipe")
    elif kind == "executable":
        file.chmod(0o700)
    else:
        package.chmod(0o755)
    with pytest.raises(DependencySnapshotVerificationError):
        _verify(inputs, built)


@pytest.mark.parametrize("name", [".env", "node_modules/hidden.js", "native.node", "archive.tgz"])
def test_configured_snapshot_rejects_sensitive_and_unmanaged_members_before_consumption(
    tmp_path, name
):
    inputs = setup_snapshot_inputs(tmp_path)
    built = _build(inputs)
    _, _, package = _snapshot_material(inputs, built)
    added = package / name
    added.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    added.write_text("synthetic inert placeholder")
    added.chmod(0o600)
    with pytest.raises(DependencySnapshotVerificationError):
        _verify(inputs, built)


@pytest.mark.parametrize("field,value", [("max_files", 1), ("max_total_bytes", 1024)])
def test_configured_snapshot_enforces_selected_aggregate_limits(tmp_path, field, value):
    inputs = setup_snapshot_inputs(
        tmp_path,
        members={
            "package/package.json": b'{"name":"safe-dep","version":"1.0.0"}',
            "package/large.txt": b"inert" * 400,
        },
    )
    built = _build(inputs)
    with pytest.raises(DependencySnapshotVerificationError):
        _verify(inputs, built, **{field: value})


@pytest.mark.parametrize("change", ["extra-project", "missing-project", "project-script"])
def test_configured_snapshot_requires_exact_complete_project_set_and_inert_manifest(
    tmp_path, change
):
    inputs = setup_snapshot_inputs(tmp_path)
    built = _build(inputs)
    if change == "extra-project":
        second = inputs[0] / "second"
        second.mkdir()
        (second / "hardhat.config.js").write_text("// synthetic metadata only")
    elif change == "missing-project":
        (inputs[0] / "hardhat.config.js").unlink()
    else:
        (inputs[0] / "package.json").write_text('{"scripts":{"prepare":"never execute"}}')
    with pytest.raises(DependencySnapshotVerificationError):
        _verify(inputs, built)


@pytest.mark.parametrize(
    "change",
    ["version", "tree", "source-alias", "lock-alias", "root-alias", "advisory", "package-script"],
)
def test_repinning_a_manifest_does_not_skip_semantic_material_verification(tmp_path, change):
    inputs = setup_snapshot_inputs(tmp_path)
    built = _build(inputs)
    path, value, package = _snapshot_material(inputs, built)
    project = value["projects"][0]
    item = project["packages"][0]
    if change == "version":
        item["version"] = "2.0.0"
    elif change == "tree":
        item["tree_sha256"] = "0" * 64
    elif change == "source-alias":
        item["source"] = item["source"].replace("packages/", "packages//")
    elif change == "lock-alias":
        item["lock_path"] = "node_modules//safe-dep"
    elif change == "root-alias":
        project["project_root"] = ""
    elif change == "advisory":
        value["advisories"] = [
            {
                "advisory_id": "SYNTHETIC-001",
                "package_name": "safe-dep",
                "versions": ["1.0.0"],
                "severity": "high",
                "summary": "Synthetic prohibited dependency version.",
            }
        ]
    else:
        (package / "package.json").write_text(
            '{"name":"safe-dep","version":"1.0.0","scripts":{"install":"never execute"}}'
        )
        tree = hashlib.sha256(b"mmaudit-dependency-tree-v1\0")
        for file in sorted(package.iterdir()):
            tree.update(
                file.name.encode() + b"\0" + hashlib.sha256(file.read_bytes()).digest() + b"\0"
            )
        item["tree_sha256"] = tree.hexdigest()
    config = _repin(path, value, built)
    with pytest.raises(DependencySnapshotVerificationError):
        verify_managed_dependency_snapshot(repository=inputs[0], config=config)


@pytest.mark.parametrize(
    "raw_path", ["node_modules//safe-dep", "node_modules/./safe-dep", "node_modules/safe-dep/"]
)
def test_verification_rejects_raw_lock_collisions_even_with_a_rebound_lock_hash(tmp_path, raw_path):
    inputs = setup_snapshot_inputs(tmp_path)
    built = _build(inputs)
    path, value, _ = _snapshot_material(inputs, built)
    lock_path = inputs[0] / "package-lock.json"
    lock = json.loads(lock_path.read_bytes())
    lock["packages"][raw_path] = lock["packages"]["node_modules/safe-dep"]
    lock_path.write_text(json.dumps(lock))
    value["projects"][0]["lockfile_sha256"] = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    with pytest.raises(DependencySnapshotVerificationError):
        verify_managed_dependency_snapshot(repository=inputs[0], config=_repin(path, value, built))


def test_verification_rechecks_material_after_collecting_it(tmp_path, monkeypatch):
    inputs = setup_snapshot_inputs(tmp_path)
    built = _build(inputs)
    _, _, package = _snapshot_material(inputs, built)
    original = snapshot_module._verify_output

    def changed(directory, descriptor, files):
        (package / "DependencyBase.sol").write_text("// changed synthetic material")
        return original(directory, descriptor, files)

    monkeypatch.setattr(snapshot_module, "_verify_output", changed)
    with pytest.raises(DependencySnapshotVerificationError):
        _verify(inputs, built)


def test_verification_detects_an_earlier_package_changing_while_a_later_one_is_checked(
    tmp_path, monkeypatch
):
    inputs = setup_snapshot_inputs(tmp_path)
    lock_path = inputs[0] / "package-lock.json"
    lock = json.loads(lock_path.read_bytes())
    lock["packages"]["node_modules/parent/node_modules/safe-dep"] = lock["packages"][
        "node_modules/safe-dep"
    ]
    lock_path.write_text(json.dumps(lock))
    built = _build(inputs)
    original = snapshot_module._read_material_tree
    seen = []

    def mutate(directory, budget):
        material = original(directory, budget)
        seen.append(directory)
        if len(seen) == 2:
            file = seen[0] / "DependencyBase.sol"
            original_bytes = file.read_bytes()
            file.write_bytes(original_bytes + b" ")
            file.write_bytes(original_bytes)
        return material

    monkeypatch.setattr(snapshot_module, "_read_material_tree", mutate)
    with pytest.raises(DependencySnapshotVerificationError):
        _verify(inputs, built)


def _build(inputs, **kwargs):
    repository, archives, advisories, advisory_sha256 = inputs
    return build_managed_dependency_snapshot(
        repository=repository,
        archive_root=archives,
        advisory_path=advisories,
        advisory_sha256=advisory_sha256,
        **kwargs,
    )


def test_snapshot_construction_is_deterministic_and_repeat_verifies(tmp_path: Path) -> None:
    inputs = setup_snapshot_inputs(tmp_path)
    first = _build(inputs)
    second = _build(inputs)
    assert first.action == "CREATED"
    assert second.action == "VERIFIED_EXISTING"
    assert first.config == second.config
    assert first.project_count == first.package_count == 1
    assert first.runtime_authority is False
    assert first.managed_run_ready is False
    snapshot = json.loads((inputs[0] / first.config.offline_snapshot_path).read_bytes())
    assert snapshot["projects"][0]["packages"][0]["name"] == "safe-dep"


def test_archive_bytes_must_match_the_actual_lockfile_sha512(tmp_path: Path) -> None:
    inputs = setup_snapshot_inputs(tmp_path)
    archive = next(inputs[1].iterdir())
    archive.write_bytes(archive.read_bytes() + b"changed")
    with pytest.raises(DependencySnapshotBuildError):
        _build(inputs)
    assert not (inputs[0] / ".mmaudit").exists()


@pytest.mark.parametrize("name", ["package/../outside", "/outside", "package/.env", "other/x"])
def test_archive_path_escape_and_sensitive_members_are_rejected(tmp_path: Path, name: str) -> None:
    inputs = setup_snapshot_inputs(
        tmp_path,
        members={"package/package.json": b'{"name":"safe-dep","version":"1.0.0"}', name: b"inert"},
    )
    with pytest.raises(DependencySnapshotBuildError):
        _build(inputs)
    assert not (inputs[0] / ".mmaudit").exists()


def test_expansion_is_bounded_before_tar_parsing(tmp_path: Path) -> None:
    inputs = setup_snapshot_inputs(tmp_path)
    with pytest.raises(DependencySnapshotBuildError):
        _build(inputs, limits=DependencySnapshotBuildLimits(max_expanded_archive_bytes=1024))
    assert not (inputs[0] / ".mmaudit").exists()


def test_verify_only_does_not_create_missing_output(tmp_path: Path) -> None:
    inputs = setup_snapshot_inputs(tmp_path)
    with pytest.raises(DependencySnapshotBuildError):
        _build(inputs, verify_only=True)
    assert not (inputs[0] / ".mmaudit").exists()


@pytest.mark.parametrize(
    "raw_path", ["node_modules//safe-dep", "node_modules/./safe-dep", "node_modules/safe-dep/"]
)
def test_raw_lock_paths_cannot_alias_and_silently_drop_locked_entries(
    tmp_path: Path, raw_path: str
) -> None:
    inputs = setup_snapshot_inputs(tmp_path)
    path = inputs[0] / "package-lock.json"
    lock = json.loads(path.read_bytes())
    lock["packages"][raw_path] = lock["packages"]["node_modules/safe-dep"]
    path.write_text(json.dumps(lock))
    with pytest.raises(DependencySnapshotBuildError):
        _build(inputs)
    assert not (inputs[0] / ".mmaudit").exists()


def test_duplicate_archive_at_distinct_lock_paths_and_multiple_projects(tmp_path: Path) -> None:
    inputs = setup_snapshot_inputs(tmp_path)
    lock_path = inputs[0] / "package-lock.json"
    lock = json.loads(lock_path.read_bytes())
    lock["packages"]["node_modules/parent/node_modules/safe-dep"] = lock["packages"][
        "node_modules/safe-dep"
    ]
    lock_path.write_text(json.dumps(lock))
    second = inputs[0] / "second"
    second.mkdir()
    for name in ("package.json", "package-lock.json", "hardhat.config.js"):
        shutil.copyfile(inputs[0] / name, second / name)
    result = _build(inputs)
    assert result.project_count == 2
    assert result.package_count == 4
    snapshot = json.loads((inputs[0] / result.config.offline_snapshot_path).read_bytes())
    sources = [item["source"] for project in snapshot["projects"] for item in project["packages"]]
    assert len(set(sources)) == 4


@pytest.mark.parametrize("case", ["wrong_digest", "duplicate_json", "missing_list", "extra_key"])
def test_advisory_inputs_are_explicit_exact_and_strict(tmp_path: Path, case: str) -> None:
    inputs = setup_snapshot_inputs(tmp_path)
    if case == "wrong_digest":
        changed = b'{"schema_version":"1.0","advisories":[]} '
    elif case == "duplicate_json":
        changed = b'{"schema_version":"1.0","advisories":[],"advisories":[]}'
    elif case == "missing_list":
        changed = b'{"schema_version":"1.0"}'
    else:
        changed = b'{"schema_version":"1.0","advisories":[],"trusted":true}'
    inputs[2].write_bytes(changed)
    if case != "wrong_digest":
        inputs = (*inputs[:3], hashlib.sha256(changed).hexdigest())
    with pytest.raises(DependencySnapshotBuildError):
        _build(inputs)


@pytest.mark.parametrize("case", ["symlink", "hardlink", "fifo", "missing"])
def test_archive_custody_rejects_nonunique_or_missing_inputs(tmp_path: Path, case: str) -> None:
    inputs = setup_snapshot_inputs(tmp_path)
    archive = next(inputs[1].iterdir())
    saved = tmp_path / "saved.tgz"
    archive.rename(saved)
    if case == "symlink":
        archive.symlink_to(saved)
    elif case == "hardlink":
        archive.hardlink_to(saved)
    elif case == "fifo":
        os.mkfifo(archive)
    with pytest.raises(DependencySnapshotBuildError):
        _build(inputs)
    assert not (inputs[0] / ".mmaudit").exists()


@pytest.mark.parametrize(
    "case", ["symlink", "hardlink", "fifo", "device", "duplicate", "executable", "sparse"]
)
def test_unsafe_tar_members_never_reach_output(tmp_path: Path, case: str) -> None:
    inputs = setup_snapshot_inputs(tmp_path)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        manifest = b'{"name":"safe-dep","version":"1.0.0"}'
        regular = tarfile.TarInfo("package/package.json")
        regular.size = len(manifest)
        archive.addfile(regular, io.BytesIO(manifest))
        member = tarfile.TarInfo("package/member")
        member.linkname = "../outside"
        member.type = {
            "symlink": tarfile.SYMTYPE,
            "hardlink": tarfile.LNKTYPE,
            "fifo": tarfile.FIFOTYPE,
            "device": tarfile.CHRTYPE,
        }.get(case, tarfile.REGTYPE)
        if case == "duplicate":
            member.name = regular.name
        if case == "executable":
            member.mode = 0o755
        if case == "sparse":
            member.pax_headers = {"GNU.sparse.size": "1000000"}
        archive.addfile(member)
    replace_archive(inputs[0], inputs[1], gzip.compress(stream.getvalue(), mtime=0))
    with pytest.raises(DependencySnapshotBuildError):
        _build(inputs)
    assert not (inputs[0] / ".mmaudit").exists()


@pytest.mark.parametrize(
    "case",
    [
        "lifecycle",
        "identity",
        "duplicate_json",
        "embedded_modules",
        "native_binary",
        "archive_payload",
        "file_directory_collision",
    ],
)
def test_package_policy_rejects_incompatible_inert_material(tmp_path: Path, case: str) -> None:
    manifest = b'{"name":"safe-dep","version":"1.0.0"}'
    members = {"package/package.json": manifest}
    if case == "lifecycle":
        members["package/package.json"] = (
            b'{"name":"safe-dep","version":"1.0.0","scripts":{"postinstall":"synthetic-disabled"}}'
        )
    elif case == "identity":
        members["package/package.json"] = b'{"name":"different-dep","version":"1.0.0"}'
    elif case == "duplicate_json":
        members["package/package.json"] = b'{"name":"safe-dep","name":"safe-dep","version":"1.0.0"}'
    elif case == "embedded_modules":
        members["package/node_modules/hidden/package.json"] = manifest
    elif case == "native_binary":
        members["package/native"] = b"\x7fELFsynthetic"
    elif case == "archive_payload":
        members["package/nested.tgz"] = b"inert"
    else:
        members["package/a"] = b"inert"
        members["package/a/child"] = b"inert"
    inputs = setup_snapshot_inputs(tmp_path, members=members)
    with pytest.raises(DependencySnapshotBuildError):
        _build(inputs)
    assert not (inputs[0] / ".mmaudit").exists()


@pytest.mark.parametrize(
    "case", ["changed_file", "extra_file", "missing_file", "symlink", "permissions"]
)
def test_existing_output_is_never_overwritten_or_repaired(tmp_path: Path, case: str) -> None:
    inputs = setup_snapshot_inputs(tmp_path)
    first = _build(inputs)
    directory = (inputs[0] / first.config.offline_snapshot_path).parent
    marker = directory / "provenance.json"
    if case == "changed_file":
        marker.write_bytes(b"{}")
    elif case == "extra_file":
        (directory / "foreign.txt").write_bytes(b"foreign")
    elif case == "missing_file":
        marker.unlink()
    elif case == "symlink":
        marker.unlink()
        marker.symlink_to(inputs[2])
    else:
        marker.chmod(0o644)
    with pytest.raises(DependencySnapshotBuildError):
        _build(inputs)
    if case == "changed_file":
        assert marker.read_bytes() == b"{}"
    elif case == "extra_file":
        assert (directory / "foreign.txt").read_bytes() == b"foreign"
    elif case == "missing_file":
        assert not marker.exists()
    elif case == "symlink":
        assert marker.is_symlink()
    else:
        assert marker.stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize("case", ["invalid_gzip", "truncated_gzip", "invalid_tar", "trailing_tar"])
def test_malformed_archives_fail_as_closed_build_errors(tmp_path: Path, case: str) -> None:
    inputs = setup_snapshot_inputs(tmp_path)
    if case == "invalid_gzip":
        content = b"not a gzip stream"
    elif case == "truncated_gzip":
        content = next(inputs[1].iterdir()).read_bytes()[:-9]
    elif case == "invalid_tar":
        content = gzip.compress(b"not a tar stream", mtime=0)
    else:
        valid = gzip.decompress(next(inputs[1].iterdir()).read_bytes())
        content = gzip.compress(valid + b"unaccounted bytes", mtime=0)
    replace_archive(inputs[0], inputs[1], content)
    with pytest.raises(DependencySnapshotBuildError):
        _build(inputs)
    assert not (inputs[0] / ".mmaudit").exists()


def test_source_drift_before_publication_leaves_no_generated_snapshot(tmp_path, monkeypatch):
    inputs = setup_snapshot_inputs(tmp_path)
    original = snapshot_module._construct_snapshot

    def change_source(*args, **kwargs):
        result = original(*args, **kwargs)
        (inputs[0] / "package.json").write_bytes(b"{}")
        return result

    monkeypatch.setattr(snapshot_module, "_construct_snapshot", change_source)
    with pytest.raises(DependencySnapshotBuildError):
        _build(inputs)
    assert not (inputs[0] / ".mmaudit").exists()


def test_incomplete_publication_is_preserved_and_repeat_does_not_repair(tmp_path, monkeypatch):
    inputs = setup_snapshot_inputs(tmp_path)
    original = snapshot_module.write_file_evidence

    def fail_package_write(**kwargs):
        if kwargs["relative_path"].startswith("packages/"):
            raise OSError("synthetic disk failure")
        return original(**kwargs)

    monkeypatch.setattr(snapshot_module, "write_file_evidence", fail_package_write)
    with pytest.raises(DependencySnapshotBuildError):
        _build(inputs)
    assert not list((inputs[0] / ".mmaudit").rglob("snapshot.json"))
    before = {
        p.relative_to(inputs[0]): p.read_bytes()
        for p in (inputs[0] / ".mmaudit").rglob("*")
        if p.is_file()
    }
    monkeypatch.setattr(snapshot_module, "write_file_evidence", original)
    with pytest.raises(DependencySnapshotBuildError):
        _build(inputs)
    assert before == {
        p.relative_to(inputs[0]): p.read_bytes()
        for p in (inputs[0] / ".mmaudit").rglob("*")
        if p.is_file()
    }


def test_linked_output_parent_cannot_publish_outside_the_target(tmp_path: Path) -> None:
    inputs = setup_snapshot_inputs(tmp_path)
    foreign = tmp_path / "foreign"
    foreign.mkdir(mode=0o700)
    (inputs[0] / ".mmaudit").symlink_to(foreign, target_is_directory=True)
    with pytest.raises(DependencySnapshotBuildError):
        _build(inputs)
    assert list(foreign.iterdir()) == []


@pytest.mark.parametrize(
    "field", ["max_packages", "max_files", "max_total_bytes", "max_file_bytes", "max_archive_bytes"]
)
def test_resource_limits_are_applied_to_the_entire_material(tmp_path: Path, field: str) -> None:
    inputs = setup_snapshot_inputs(tmp_path)
    if field == "max_packages":
        lock_path = inputs[0] / "package-lock.json"
        lock = json.loads(lock_path.read_bytes())
        lock["packages"]["node_modules/safe-dep/node_modules/safe-dep"] = lock["packages"][
            "node_modules/safe-dep"
        ]
        lock_path.write_text(json.dumps(lock))
        limit = 1
    elif field == "max_files":
        limit = 1
    elif field in {"max_file_bytes", "max_archive_bytes"}:
        from tests.dependency_snapshot_support import archive_bytes

        members = {
            "package/package.json": b'{"name":"safe-dep","version":"1.0.0"}',
            "package/material": bytes(range(256)) * 100,
        }
        content = archive_bytes(members)
        if field == "max_archive_bytes":
            content = gzip.compress(gzip.decompress(content), compresslevel=0, mtime=0)
        replace_archive(inputs[0], inputs[1], content)
        limit = 1024
    else:
        limit = 1024
    with pytest.raises(DependencySnapshotBuildError):
        _build(inputs, limits=DependencySnapshotBuildLimits(**{field: limit}))
    assert not (inputs[0] / ".mmaudit").exists()
