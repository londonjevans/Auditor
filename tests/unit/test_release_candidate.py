from __future__ import annotations

import hashlib
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

import mmaudit.release_candidate as candidate_module
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_candidate import ReleaseCandidateObservation, observe_release_candidate


def _git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        [
            str(candidate_module._trusted_git_executable()),
            "-C",
            str(root),
            *arguments,
        ],
        check=True,
        capture_output=True,
        env=candidate_module._git_environment(),
        shell=False,
    )
    return result.stdout


def _init_repository(root: Path, files: dict[str, bytes] | None = None) -> Path:
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Synthetic Release Test")
    _git(root, "config", "user.email", "release-test@example.invalid")
    inventory = files or {
        ".gitignore": b"*.ignored\n",
        "README.md": b"synthetic release candidate\n",
        "src/mmaudit/example.py": b"VALUE = 1\n",
    }
    for relative, content in inventory.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    _git(root, "add", "--all")
    _git(root, "commit", "-q", "-m", "Synthetic release candidate")
    return root.resolve(strict=True)


def _observe_temp_repository(root: Path) -> ReleaseCandidateObservation:
    git = candidate_module._trusted_git_executable()
    with (
        patch.object(
            candidate_module,
            "_require_executing_repository_root",
            return_value=root,
        ),
        patch.object(candidate_module, "_trusted_git_executable", return_value=git),
    ):
        return observe_release_candidate(root)


def _git_blob_id(content: bytes, algorithm: str = "sha1") -> str:
    digest = hashlib.new(algorithm)
    digest.update(f"blob {len(content)}\0".encode("ascii"))
    digest.update(content)
    return digest.hexdigest()


def _mock_git_observation(
    root: Path,
    *,
    inventory: dict[str, bytes],
    statuses: tuple[bytes, bytes] = (b"", b""),
    commits: tuple[str, str] = ("1" * 40, "1" * 40),
    trees: tuple[str, str] = ("2" * 40, "2" * 40),
):
    status_count = 0
    commit_count = 0
    tree_count = 0

    def run(
        _git_path: Path,
        _root: Path,
        arguments: tuple[str, ...],
        *,
        timeout: int = 30,
    ) -> bytes:
        nonlocal status_count, commit_count, tree_count
        del timeout
        assert _root == root
        if arguments == ("rev-parse", "--show-toplevel"):
            return f"{root}\n".encode()
        if arguments == ("rev-parse", "--show-object-format"):
            return b"sha1\n"
        if arguments == ("rev-parse", "--verify", "HEAD^{commit}"):
            result = commits[commit_count]
            commit_count += 1
            return f"{result}\n".encode()
        if arguments == ("rev-parse", "--verify", "HEAD^{tree}"):
            result = trees[tree_count]
            tree_count += 1
            return f"{result}\n".encode()
        if arguments[0] == "status":
            result = statuses[status_count]
            status_count += 1
            return result
        if arguments[:4] == ("ls-tree", "-r", "-z", "--full-tree"):
            return b"".join(
                (f"100644 blob {_git_blob_id(content)}\t{relative}".encode() + b"\0")
                for relative, content in sorted(inventory.items())
            )
        raise AssertionError(arguments)

    return run


def test_real_clean_repository_observation_binds_every_tracked_file(
    tmp_path: Path,
) -> None:
    root = _init_repository(tmp_path / "candidate")
    (root / "build.ignored").write_text("ignored local output\n", encoding="utf-8")

    observation = _observe_temp_repository(root)

    tracked = tuple(part for part in _git(root, "ls-files", "-z").split(b"\0") if part)
    assert observation.candidate_commit == _git(root, "rev-parse", "HEAD").decode().strip()
    assert (
        observation.candidate_tree_object == _git(root, "rev-parse", "HEAD^{tree}").decode().strip()
    )
    assert observation.tracked_file_count == len(tracked)
    assert observation.tracked_file_bytes == sum(
        (root / path.decode()).stat().st_size for path in tracked
    )
    assert observation.worktree_clean is True
    assert observation.worktree_status_sha256 == canonical_sha256([])
    assert observation.observed_at.utcoffset() == UTC.utcoffset(None)
    assert observation.observed_at.microsecond == 0
    assert observation.observation_sha256 == canonical_sha256(
        observation.model_dump(mode="json", exclude={"observation_sha256"})
    )


@pytest.mark.parametrize("change", ("untracked", "staged", "unstaged"))
def test_real_repository_rejects_dirty_relevant_state(
    tmp_path: Path,
    change: str,
) -> None:
    root = _init_repository(tmp_path / change)
    if change == "untracked":
        (root / "untracked.txt").write_text("not ignored\n", encoding="utf-8")
    elif change == "staged":
        (root / "README.md").write_text("staged change\n", encoding="utf-8")
        _git(root, "add", "README.md")
    else:
        (root / "README.md").write_text("unstaged change\n", encoding="utf-8")

    with pytest.raises(ValueError, match="worktree is not clean"):
        _observe_temp_repository(root)


def test_real_repository_detects_skip_worktree_byte_drift(tmp_path: Path) -> None:
    root = _init_repository(
        tmp_path / "skip-worktree",
        {"tracked.txt": b"committed bytes\n"},
    )
    _git(root, "update-index", "--skip-worktree", "tracked.txt")
    (root / "tracked.txt").write_bytes(b"different bytes\n")
    assert _git(root, "status", "--porcelain=v1") == b""

    with pytest.raises(ValueError, match="committed Git blob"):
        _observe_temp_repository(root)


def test_real_repository_detects_skip_worktree_mode_drift(tmp_path: Path) -> None:
    root = _init_repository(
        tmp_path / "skip-worktree-mode",
        {"tracked.sh": b"#!/bin/sh\nexit 0\n"},
    )
    (root / "tracked.sh").chmod(0o755)
    _git(root, "add", "tracked.sh")
    _git(root, "commit", "-q", "-m", "Track executable mode")
    _git(root, "update-index", "--skip-worktree", "tracked.sh")
    (root / "tracked.sh").chmod(0o644)
    assert _git(root, "status", "--porcelain=v1") == b""

    with pytest.raises(ValueError, match="bytes or mode"):
        _observe_temp_repository(root)


def test_real_repository_rejects_tracked_symlink(tmp_path: Path) -> None:
    root = _init_repository(tmp_path / "linked")
    link = root / "tracked-link"
    try:
        link.symlink_to("README.md")
    except OSError:
        pytest.skip("symlinks are unavailable")
    _git(root, "add", "tracked-link")
    _git(root, "commit", "-q", "-m", "Add unsafe link")

    with pytest.raises(ValueError, match="unsafe entry"):
        _observe_temp_repository(root)


def test_real_repository_rejects_unshared_tracked_inode(tmp_path: Path) -> None:
    root = _init_repository(tmp_path / "hardlinked")
    source = root / "README.md"
    alias = root / "local.ignored"
    try:
        os.link(source, alias)
    except OSError:
        pytest.skip("hardlinks are unavailable")
    assert _git(root, "status", "--porcelain=v1") == b""

    with pytest.raises(ValueError, match="bounded and unshared"):
        _observe_temp_repository(root)


def test_real_repository_rejects_sensitive_tracked_path(tmp_path: Path) -> None:
    root = _init_repository(
        tmp_path / "sensitive",
        {
            "README.md": b"synthetic\n",
            ".env.production": b"CANARY=synthetic-not-a-secret\n",
        },
    )

    with pytest.raises(ValueError, match="unsafe path"):
        _observe_temp_repository(root)


def test_mocked_git_observation_is_commit_tree_and_inventory_bound(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    inventory = {
        "README.md": b"release\n",
        "src/mmaudit/module.py": b"VALUE = 1\n",
    }
    for relative, content in inventory.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    with (
        patch.object(
            candidate_module,
            "_require_executing_repository_root",
            return_value=root,
        ),
        patch.object(
            candidate_module,
            "_trusted_git_executable",
            return_value=Path("/usr/bin/git"),
        ),
        patch.object(
            candidate_module,
            "_run_git",
            side_effect=_mock_git_observation(root, inventory=inventory),
        ),
    ):
        observation = observe_release_candidate(root)

    expected = [
        {
            "path": relative,
            "mode": "100644",
            "git_blob_object": _git_blob_id(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
        for relative, content in sorted(inventory.items())
    ]
    assert observation.candidate_commit == "1" * 40
    assert observation.candidate_tree_object == "2" * 40
    assert observation.tracked_source_inventory_sha256 == canonical_sha256(expected)


@pytest.mark.parametrize(
    ("statuses", "commits", "trees", "message"),
    (
        ((b"M README.md\0", b""), ("1" * 40, "1" * 40), ("2" * 40, "2" * 40), "not clean"),
        ((b"", b"?? late.txt\0"), ("1" * 40, "1" * 40), ("2" * 40, "2" * 40), "changed"),
        ((b"", b""), ("1" * 40, "3" * 40), ("2" * 40, "2" * 40), "changed"),
        ((b"", b""), ("1" * 40, "1" * 40), ("2" * 40, "4" * 40), "changed"),
    ),
)
def test_mocked_git_observation_rejects_dirty_or_changing_candidate(
    tmp_path: Path,
    statuses: tuple[bytes, bytes],
    commits: tuple[str, str],
    trees: tuple[str, str],
    message: str,
) -> None:
    inventory = {"README.md": b"release\n"}
    (tmp_path / "README.md").write_bytes(inventory["README.md"])
    with (
        patch.object(
            candidate_module,
            "_require_executing_repository_root",
            return_value=tmp_path,
        ),
        patch.object(
            candidate_module,
            "_trusted_git_executable",
            return_value=Path("/usr/bin/git"),
        ),
        patch.object(
            candidate_module,
            "_run_git",
            side_effect=_mock_git_observation(
                tmp_path,
                inventory=inventory,
                statuses=statuses,
                commits=commits,
                trees=trees,
            ),
        ),
        pytest.raises(ValueError, match=message),
    ):
        observe_release_candidate(tmp_path)


@pytest.mark.parametrize(
    "output",
    (
        b"",
        b"120000 blob " + b"1" * 40 + b"\tlink\0",
        b"160000 commit " + b"1" * 40 + b"\tsubmodule\0",
        b"100644 blob " + b"g" * 40 + b"\tbad-object\0",
        b"100644 blob " + b"1" * 40 + b"\t../escape\0",
        b"100644 blob " + b"1" * 40 + b"\t.env\0",
        b"100644 blob " + b"1" * 40 + b"\t-option\0",
        b"100644 blob " + b"1" * 40 + b"\tmissing-terminator",
        b"100644 blob " + b"1" * 40 + b"\tdouble-null\0\0",
        (
            b"100644 blob "
            + b"1" * 40
            + b"\tCase.sol\0"
            + b"100644 blob "
            + b"2" * 40
            + b"\tcase.sol\0"
        ),
    ),
)
def test_mocked_git_inventory_rejects_empty_malformed_or_unsafe_entries(
    output: bytes,
) -> None:
    with pytest.raises(ValueError):
        candidate_module._parse_tracked_entries(output, git_object_format="sha1")


def test_mocked_git_inventory_rejects_noncanonical_order() -> None:
    output = (
        b"100644 blob " + b"1" * 40 + b"\tz.sol\x00" + b"100644 blob " + b"2" * 40 + b"\ta.sol\0"
    )

    with pytest.raises(ValueError, match="not canonical"):
        candidate_module._parse_tracked_entries(output, git_object_format="sha1")


def test_alternate_repository_cannot_observe_executing_package(tmp_path: Path) -> None:
    (tmp_path / "src/mmaudit").mkdir(parents=True)

    with pytest.raises(ValueError, match="executing mmaudit package"):
        candidate_module._require_executing_repository_root(tmp_path)


def test_release_candidate_model_rejects_tampering_and_noncanonical_fields() -> None:
    payload = {
        "schema_version": "1.0",
        "generated_by": "mmaudit",
        "candidate_commit": "1" * 40,
        "git_object_format": "sha1",
        "candidate_tree_object": "2" * 40,
        "tracked_source_inventory_sha256": "3" * 64,
        "tracked_file_count": 1,
        "tracked_file_bytes": 12,
        "worktree_clean": True,
        "worktree_status_sha256": canonical_sha256([]),
        "observed_at": "2026-07-28T12:00:00Z",
    }
    valid = {
        **payload,
        "observation_sha256": canonical_sha256(payload),
    }
    observation = ReleaseCandidateObservation.model_validate(valid)
    assert observation.observed_at == datetime(2026, 7, 28, 12, 0, tzinfo=UTC)

    for changes in (
        {"candidate_commit": "1" * 64, "git_object_format": "sha1"},
        {"worktree_status_sha256": hashlib.sha256(b"").hexdigest()},
        {"observed_at": "2026-07-28T12:00:00.1Z"},
        {"observation_sha256": "f" * 64},
    ):
        with pytest.raises(ValidationError):
            ReleaseCandidateObservation.model_validate({**valid, **changes})
