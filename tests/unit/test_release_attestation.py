from __future__ import annotations

import copy
import hashlib
import pickle
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

import mmaudit.models.release_attestation as release_module
from mmaudit.models.qualification_workflow import seal_qualification_release_bindings
from mmaudit.models.release_attestation import (
    ReleaseEnvironmentMeasurement,
    TrustedReleaseBindingObservation,
    observe_and_verify_qualification_release,
)
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.orchestration.manifest import canonical_sha256

NOW = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)


def _blob_sha1(content: bytes) -> str:
    return hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()


def _source_git(
    root: Path,
    *,
    commit: str,
    inventory: dict[str, bytes],
):
    def run(_git: Path, _root: Path, arguments: tuple[str, ...], *, timeout: int = 30) -> bytes:
        del timeout
        assert _root == root
        if arguments == ("rev-parse", "--show-toplevel"):
            return f"{root}\n".encode()
        if arguments == ("rev-parse", "--verify", "HEAD"):
            return f"{commit}\n".encode()
        if arguments == ("rev-parse", "--show-object-format"):
            return b"sha1\n"
        if arguments[:4] == ("status", "--porcelain=v1", "-z", "--untracked-files=all"):
            return b""
        if arguments[:4] == ("ls-tree", "-r", "-z", "--full-tree"):
            assert arguments[4] == commit
            return b"".join(
                f"100644 blob {_blob_sha1(content)}\t{path}".encode() + b"\0"
                for path, content in sorted(inventory.items())
            )
        raise AssertionError(arguments)

    return run


def _measurement(
    bindings,
    *,
    observed_at: datetime = NOW,
) -> ReleaseEnvironmentMeasurement:
    payload = {
        "schema_version": "1.0",
        "source_commit": bindings.source_commit,
        "source_tree_sha256": bindings.source_tree_sha256,
        "toolchain_sha256": bindings.toolchain_sha256,
        "isolation_sha256": bindings.isolation_sha256,
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
    }
    return ReleaseEnvironmentMeasurement.model_validate(
        {**payload, "measurement_sha256": canonical_sha256(payload)}
    )


def test_source_observation_binds_exact_head_and_committed_release_bytes(
    tmp_path: Path,
) -> None:
    inventory = {
        "schemas/model_qualification.schema.json": b'{"type":"object"}\n',
        "src/mmaudit/module.py": b"VALUE = 1\n",
        "src/mmaudit/prompts/review.md": b"Review safely.\n",
    }
    for relative, content in inventory.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "note.md").write_text("unbound documentation\n", encoding="utf-8")
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "models.toml").write_text("unbound = true\n", encoding="utf-8")
    first_commit = "1" * 40

    with patch.object(
        release_module,
        "_run_git",
        side_effect=_source_git(tmp_path, commit=first_commit, inventory=inventory),
    ):
        observed_commit, first_tree = release_module._measure_release_source(
            tmp_path,
            git=Path("/usr/bin/git"),
        )
    assert observed_commit == first_commit

    (tmp_path / "docs" / "note.md").write_text("changed documentation\n", encoding="utf-8")
    (tmp_path / "config" / "models.toml").write_text("unbound = false\n", encoding="utf-8")
    second_commit = "2" * 40
    with patch.object(
        release_module,
        "_run_git",
        side_effect=_source_git(tmp_path, commit=second_commit, inventory=inventory),
    ):
        observed_commit, unchanged_tree = release_module._measure_release_source(
            tmp_path,
            git=Path("/usr/bin/git"),
        )
    assert observed_commit == second_commit
    assert unchanged_tree == first_tree

    changed = {**inventory, "src/mmaudit/module.py": b"VALUE = 2\n"}
    (tmp_path / "src/mmaudit/module.py").write_bytes(changed["src/mmaudit/module.py"])
    with patch.object(
        release_module,
        "_run_git",
        side_effect=_source_git(tmp_path, commit=second_commit, inventory=changed),
    ):
        _, changed_tree = release_module._measure_release_source(
            tmp_path,
            git=Path("/usr/bin/git"),
        )
    assert changed_tree != first_tree


def test_source_observation_detects_skip_worktree_or_assume_unchanged_drift(
    tmp_path: Path,
) -> None:
    committed = b"VALUE = 1\n"
    inventory = {"src/mmaudit/module.py": committed}
    path = tmp_path / "src/mmaudit/module.py"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"VALUE = 2\n")

    with (
        patch.object(
            release_module,
            "_run_git",
            side_effect=_source_git(tmp_path, commit="1" * 40, inventory=inventory),
        ),
        pytest.raises(ValueError, match="committed Git object"),
    ):
        release_module._measure_release_source(tmp_path, git=Path("/usr/bin/git"))


def test_source_observation_uses_head_tree_not_staged_index(tmp_path: Path) -> None:
    committed = b"VALUE = 1\n"
    staged = b"VALUE = 2\n"
    inventory = {"src/mmaudit/module.py": committed}
    path = tmp_path / "src/mmaudit/module.py"
    path.parent.mkdir(parents=True)
    path.write_bytes(staged)

    with (
        patch.object(
            release_module,
            "_run_git",
            side_effect=_source_git(tmp_path, commit="1" * 40, inventory=inventory),
        ),
        pytest.raises(ValueError, match="committed Git object"),
    ):
        release_module._measure_release_source(tmp_path, git=Path("/usr/bin/git"))


def test_alternate_clean_repository_cannot_attest_executing_package(tmp_path: Path) -> None:
    (tmp_path / "src/mmaudit").mkdir(parents=True)

    with pytest.raises(ValueError, match="executing mmaudit package"):
        release_module._require_executing_release_root(tmp_path)


def test_release_observation_is_opaque_and_exactly_bound() -> None:
    bindings = seal_qualification_release_bindings(
        source_commit="1" * 40,
        source_tree_sha256="2" * 64,
        effective_config_sha256="3" * 64,
        prompt_sha256="4" * 64,
        response_schema_sha256="5" * 64,
        toolchain_sha256="6" * 64,
        isolation_sha256="7" * 64,
        benchmark_corpus_version="2.0",
        benchmark_ground_truth_version="2.0",
    )
    measurement = _measurement(bindings)
    with (
        patch.object(
            release_module,
            "measure_qualification_release_environment",
            return_value=measurement,
        ),
        patch.object(
            release_module,
            "isolation_execution_evidence",
            return_value=ExecutionEvidenceKind.REAL,
        ),
        patch.object(release_module, "_utc_now", return_value=NOW),
    ):
        observation = observe_and_verify_qualification_release(
            release_bindings=bindings,
            source_root=Path("/synthetic"),
            isolation_backend=object(),
        )

    observation.require_for(bindings)
    assert observation.observed_at == NOW
    assert observation.measurement_sha256 == measurement.measurement_sha256
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(observation)

    drifted = seal_qualification_release_bindings(
        source_commit=bindings.source_commit,
        source_tree_sha256="8" * 64,
        effective_config_sha256=bindings.effective_config_sha256,
        prompt_sha256=bindings.prompt_sha256,
        response_schema_sha256=bindings.response_schema_sha256,
        toolchain_sha256=bindings.toolchain_sha256,
        isolation_sha256=bindings.isolation_sha256,
        benchmark_corpus_version=bindings.benchmark_corpus_version,
        benchmark_ground_truth_version=bindings.benchmark_ground_truth_version,
    )
    with pytest.raises(ValueError, match="differs from qualification bindings"):
        observation.require_for(drifted)

    forged = object.__new__(TrustedReleaseBindingObservation)
    with pytest.raises(ValueError, match="not trusted"):
        _ = forged.measurement_sha256


@pytest.mark.parametrize(
    "field,value",
    (
        ("__observed_at", NOW.replace(hour=13)),
        ("__measurement_sha256", "f" * 64),
    ),
)
def test_release_observation_rejects_post_issuance_measurement_mutation(
    field: str,
    value: object,
) -> None:
    bindings = seal_qualification_release_bindings(
        source_commit="1" * 40,
        source_tree_sha256="2" * 64,
        effective_config_sha256="3" * 64,
        prompt_sha256="4" * 64,
        response_schema_sha256="5" * 64,
        toolchain_sha256="6" * 64,
        isolation_sha256="7" * 64,
        benchmark_corpus_version="2.0",
        benchmark_ground_truth_version="2.0",
    )
    measurement = _measurement(bindings)
    with (
        patch.object(
            release_module,
            "measure_qualification_release_environment",
            return_value=measurement,
        ),
        patch.object(release_module, "_utc_now", return_value=NOW),
    ):
        observation = observe_and_verify_qualification_release(
            release_bindings=bindings,
            source_root=Path("/synthetic"),
            isolation_backend=object(),
        )

    object.__setattr__(
        observation,
        f"_TrustedReleaseBindingObservation{field}",
        value,
    )
    with pytest.raises(ValueError, match="integrity check failed"):
        _ = observation.measurement_sha256
    with pytest.raises(ValueError, match="integrity check failed"):
        observation.require_for(bindings)


@pytest.mark.parametrize("offset_hours", (-1, 1))
def test_release_observation_rejects_non_current_measurement_time(
    offset_hours: int,
) -> None:
    bindings = seal_qualification_release_bindings(
        source_commit="1" * 40,
        source_tree_sha256="2" * 64,
        effective_config_sha256="3" * 64,
        prompt_sha256="4" * 64,
        response_schema_sha256="5" * 64,
        toolchain_sha256="6" * 64,
        isolation_sha256="7" * 64,
        benchmark_corpus_version="2.0",
        benchmark_ground_truth_version="2.0",
    )
    measurement = _measurement(
        bindings,
        observed_at=NOW.replace(hour=NOW.hour + offset_hours),
    )
    with (
        patch.object(
            release_module,
            "measure_qualification_release_environment",
            return_value=measurement,
        ),
        patch.object(release_module, "_utc_now", return_value=NOW),
        pytest.raises(ValueError, match="not freshly observed"),
    ):
        observe_and_verify_qualification_release(
            release_bindings=bindings,
            source_root=Path("/synthetic"),
            isolation_backend=object(),
        )
