from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from scripts.generate_realistic_scale_fixtures import (
    CORPUS_MANIFEST_NAME,
    MANIFEST_NAME,
    PROFILES,
    render_corpus,
    verify_corpus,
    write_corpus,
)

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "solidity" / "realistic_scale"


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _manifest_self_hash(payload: dict[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("manifest_sha256")
    return _sha256(_canonical_json(unsigned))


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_realistic_scale_generator_is_deterministic_and_matches_golden_tree(
    tmp_path: Path,
) -> None:
    first_render = render_corpus()
    second_render = render_corpus()

    assert first_render == second_render
    assert verify_corpus(FIXTURE_ROOT) == []
    assert _tree_bytes(FIXTURE_ROOT) == first_render

    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    write_corpus(first_root)
    write_corpus(second_root)

    assert verify_corpus(first_root) == []
    assert verify_corpus(second_root) == []
    assert _tree_bytes(first_root) == _tree_bytes(second_root) == first_render


@pytest.mark.parametrize(
    ("unsafe_kind", "message"),
    (
        ("fifo", "non-regular fixture file"),
        ("symlink", "fixture symlink"),
        ("hardlink", "shared fixture hardlink"),
        ("mode", "mode other than 0644"),
    ),
)
def test_realistic_scale_writer_refuses_unsafe_existing_expected_entry(
    unsafe_kind: str,
    message: str,
    tmp_path: Path,
) -> None:
    root = tmp_path / unsafe_kind
    root.mkdir()
    target = root / CORPUS_MANIFEST_NAME
    outside = tmp_path / f"{unsafe_kind}-outside"
    outside.write_bytes(b"synthetic outside sentinel\n")
    if unsafe_kind == "fifo":
        os.mkfifo(target)
    elif unsafe_kind == "symlink":
        target.symlink_to(outside)
    elif unsafe_kind == "hardlink":
        os.link(outside, target)
    else:
        target.write_bytes(b"synthetic mode sentinel\n")
        target.chmod(0o664)

    before = target.lstat()
    with pytest.raises(ValueError, match=message):
        write_corpus(root)
    after = target.lstat()

    assert stat.S_IFMT(after.st_mode) == stat.S_IFMT(before.st_mode)
    assert after.st_ino == before.st_ino


def test_realistic_scale_writer_enforces_manifest_mode_under_restrictive_umask(
    tmp_path: Path,
) -> None:
    root = tmp_path / "restrictive-umask"
    previous_umask = os.umask(0o077)
    try:
        write_corpus(root)
    finally:
        os.umask(previous_umask)

    assert verify_corpus(root) == []
    assert {stat.S_IMODE(path.lstat().st_mode) for path in root.rglob("*") if path.is_file()} == {
        0o644
    }


def test_realistic_scale_manifests_independently_bind_every_source_byte() -> None:
    corpus = json.loads((FIXTURE_ROOT / CORPUS_MANIFEST_NAME).read_text(encoding="utf-8"))

    assert corpus["manifest_sha256"] == _manifest_self_hash(corpus)
    assert [item["fixture_id"] for item in corpus["profiles"]] == [
        profile.fixture_id for profile in PROFILES
    ]
    for summary, profile in zip(corpus["profiles"], PROFILES, strict=True):
        profile_root = FIXTURE_ROOT / profile.fixture_id
        manifest_path = profile_root / MANIFEST_NAME
        manifest_content = manifest_path.read_bytes()
        manifest = json.loads(manifest_content)

        assert summary["manifest_file_sha256"] == _sha256(manifest_content)
        assert summary["manifest_sha256"] == manifest["manifest_sha256"]
        assert manifest["manifest_sha256"] == _manifest_self_hash(manifest)
        assert manifest["fixture_id"] == profile.fixture_id
        assert manifest["provenance"] == {
            "copied_production_source": False,
            "deployment_artifacts_present": False,
            "non_deployable": True,
            "original_for_mmaudit_tests": True,
            "synthetic": True,
        }

        bound_files: list[dict[str, Any]] = manifest["files"]
        assert [item["path"] for item in bound_files] == sorted(
            item["path"] for item in bound_files
        )
        actual_solidity_lines = 0
        actual_source_bytes = 0
        tree_identity: list[dict[str, Any]] = []
        for binding in bound_files:
            relative = PurePosixPath(binding["path"])
            assert not relative.is_absolute()
            assert ".." not in relative.parts
            source_path = profile_root.joinpath(*relative.parts)
            source = source_path.read_bytes()

            assert binding["mode"] == "0644"
            assert binding["sha256"] == _sha256(source)
            assert binding["utf8_bytes"] == len(source)
            assert binding["lines"] == len(source.decode("utf-8").splitlines())
            assert source.endswith(b"\n")
            assert len(source) < 48_000
            if relative.suffix == ".sol":
                actual_solidity_lines += binding["lines"]
                actual_source_bytes += binding["utf8_bytes"]
            tree_identity.append(
                {
                    "path": binding["path"],
                    "sha256": binding["sha256"],
                    "utf8_bytes": binding["utf8_bytes"],
                    "lines": binding["lines"],
                }
            )

        assert manifest["source_tree_sha256"] == _sha256(_canonical_json(tree_identity))
        assert manifest["actual"]["solidity_lines"] == actual_solidity_lines
        assert manifest["actual"]["source_utf8_bytes"] == actual_source_bytes
        assert manifest["actual"]["file_count"] == len(bound_files)
        assert manifest["actual"]["module_count"] == profile.module_count
        tolerance = manifest["target"]["tolerance_basis_points"]
        target = manifest["target"]["solidity_lines"]
        assert abs(actual_solidity_lines - target) * 10_000 <= target * tolerance


def test_realistic_scale_sources_are_synthetic_non_deployable_and_prefix_stable() -> None:
    prohibited_parts = {"artifact", "artifacts", "broadcast", "cache", "deploy", "out", "script"}
    prohibited_source_fragments = (
        b"http://",
        b"https://",
        b".env",
        b"PRIVATE KEY",
        b"mnemonic",
        b"selfdestruct",
        b"tx.origin",
        b"vm.",
    )
    sources_by_profile: dict[str, dict[str, bytes]] = {}

    for profile in PROFILES:
        profile_root = FIXTURE_ROOT / profile.fixture_id
        sources = {
            path.relative_to(profile_root).as_posix(): path.read_bytes()
            for path in sorted(profile_root.rglob("*.sol"))
        }
        sources_by_profile[profile.fixture_id] = sources
        assert sources
        assert all(not (set(PurePosixPath(path).parts) & prohibited_parts) for path in sources)
        combined = b"\n".join(sources.values())
        assert b"revert SyntheticFixtureCannotDeploy();" in combined
        assert b"abstract contract SyntheticMarket" in combined
        assert b"delegatecall(" in combined
        assert b"transferFrom(" in combined
        assert b"onlyGovernor" in combined
        assert b"onlyGuardian" in combined
        assert all(fragment not in combined for fragment in prohibited_source_fragments)
        for line in combined.decode("utf-8").splitlines():
            if line.startswith("contract ") or line.startswith("contract\t"):
                raise AssertionError("every generated contract must be explicitly abstract")

    small, medium, large = (profile.fixture_id for profile in PROFILES)
    for path, content in sources_by_profile[small].items():
        assert sources_by_profile[medium][path] == content
        assert sources_by_profile[large][path] == content
    for path, content in sources_by_profile[medium].items():
        assert sources_by_profile[large][path] == content
