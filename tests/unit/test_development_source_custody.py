"""Admission is earned from the actual root; self-hashed retained bytes are not root custody."""

import shutil
import socket
import subprocess
from dataclasses import replace

import pytest

from mmaudit.models.development_corpus import (
    DevelopmentCorpusMaterial,
    prepare_development_corpus,
    prepare_development_corpus_shard,
)
from mmaudit.models.development_corpus_ensemble import prepare_development_corpus_ensemble
from mmaudit.models.development_corpus_judgment import (
    prepare_development_corpus_judgment,
    prepare_development_corpus_judgment_shard,
)
from mmaudit.models.development_corpus_repeats import prepare_development_corpus_repeats
from mmaudit.models.development_corpus_resume import (
    freeze_development_corpus_resume_history,
    prepare_development_corpus_resume,
)
from mmaudit.orchestration.development_corpus import _rebuild as rebuild_candidate
from mmaudit.orchestration.development_corpus_ensemble import _rebuild as rebuild_ensemble
from mmaudit.orchestration.development_corpus_judgment import _rebuild as rebuild_judgment
from mmaudit.orchestration.development_corpus_repeats import _rebuild as rebuild_repeats
from mmaudit.orchestration.development_corpus_resume import _rebuild as rebuild_resume
from tests.development_corpus_benchmark_support import truth_binding
from tests.development_corpus_judgment_support import pure_candidate, selected_policy
from tests.development_ensemble_support import ENSEMBLE_MODELS
from tests.development_judgment_support import judgment_metadata
from tests.development_source_custody_support import candidate_case, custody_metadata, loaded_case

KINDS = (
    "candidate",
    "shard",
    "ensemble",
    "judgment",
    "judgment-shard",
    "empty",
    "repeats",
    "resume",
)


def test_full_paired_context_still_refuses_insufficient_endpoint_or_attempt_capacity(tmp_path):
    loaded = loaded_case(tmp_path)
    with pytest.raises(ValueError, match="byte/input limit"):
        candidate_case(
            loaded, endpoint_snapshot=judgment_metadata(model_id="synthetic/corpus-review")
        )
    with pytest.raises(ValueError, match="source, request or selected route"):
        candidate_case(loaded, policy=selected_policy(total="60", per_attempt="3"))
    accepted = candidate_case(loaded)
    assert all(s.estimate.estimated_cost_per_attempt_usd > 3 for s in accepted.shards)


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("source admission attempted network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def preparations(loaded):
    original = candidate_case(loaded)
    first = original.shards[0]
    _, candidate = pure_candidate(prepared=original, observed_count=1)
    _, empty = pure_candidate(prepared=original, claims=0)
    history = freeze_development_corpus_resume_history(original=candidate, material=loaded.material)
    binding = truth_binding(original)
    common = dict(
        policy=original.plan.policy,
        endpoint_snapshot=first.endpoint_snapshot,
        manifest=original.plan.manifest,
        source_files=first.source_files,
        run_id=original.plan.run_id,
    )
    review = dict(
        candidate=candidate,
        policy=original.plan.policy,
        endpoint_snapshot=custody_metadata(model_id=ENSEMBLE_MODELS[1]),
        source_files=first.source_files,
        run_id="synthetic-custody-review",
    )
    return {
        "candidate": lambda custody: prepare_development_corpus(**common, source_custody=custody),
        "shard": lambda custody: prepare_development_corpus_shard(
            **common, primary_filename=first.source_filename, source_custody=custody
        ),
        "ensemble": lambda custody: prepare_development_corpus_ensemble(
            **{k: v for k, v in common.items() if k != "endpoint_snapshot"},
            candidate_metadata=first.endpoint_snapshot,
            reviewer_metadata=tuple(custody_metadata(model_id=m) for m in ENSEMBLE_MODELS[1:]),
            source_custody=custody,
        ),
        "judgment": lambda custody: prepare_development_corpus_judgment(
            **review, source_custody=custody
        ),
        "judgment-shard": lambda custody: prepare_development_corpus_judgment_shard(
            **review, shard_id="file-0001", source_custody=custody
        ),
        "empty": lambda custody: prepare_development_corpus_judgment(
            **{**review, "candidate": empty}, source_custody=custody
        ),
        "repeats": lambda custody: prepare_development_corpus_repeats(
            **common,
            trial_count=2,
            truth_content=binding.truth_file_content.encode(),
            expected_truth_sha256=binding.truth_file_sha256,
            source_custody=custody,
        ),
        "resume": lambda custody: prepare_development_corpus_resume(
            history=history,
            endpoint_snapshot=first.endpoint_snapshot,
            run_id="synthetic-custody-resume",
            source_custody=custody,
        ),
    }


@pytest.mark.parametrize("kind", KINDS)
def test_every_preparer_requires_actual_custody_including_zero_claim_review(tmp_path, kind):
    loaded = loaded_case(tmp_path)
    prepare = preparations(loaded)[kind]
    for missing in (None, object(), loaded.material, loaded.material.manifest.source_tree_evidence):
        with pytest.raises(ValueError, match="custody"):
            prepare(missing)
    accepted = prepare(loaded)
    assert accepted is not None
    assert str(tmp_path) not in repr(accepted)


@pytest.mark.parametrize("version", ["1.3", "1.4", "1.5", "1.6", "1.7"])
def test_all_tree_versions_require_roots_without_rewriting_historical_artifacts(tmp_path, version):
    loaded = loaded_case(tmp_path, version=version)
    serialized = loaded.material.model_dump_json()
    historical = DevelopmentCorpusMaterial.model_validate_json(serialized, strict=True)
    assert historical.model_dump_json() == serialized
    with pytest.raises(ValueError, match="custody"):
        candidate_case(loaded, source_custody=None)
    prepared = candidate_case(loaded)
    assert str(tmp_path) not in prepared.plan.model_dump_json()
    for shard in prepared.shards:
        assert shard.source_custody == loaded
        assert str(tmp_path).encode() not in shard.request_content


@pytest.mark.parametrize(
    "change",
    [
        "add",
        "omit",
        "bytes",
        "replace-file",
        "replace-root",
        "manifest",
        "binding",
        "directory",
        "tree",
        "other-material",
    ],
)
def test_preparation_replays_source_namespace_objects_and_exact_selected_bindings(tmp_path, change):
    loaded = loaded_case(tmp_path)
    first = loaded.corpus_root / loaded.material.manifest.sources[0].filename
    selected = loaded
    if change == "add":
        (loaded.corpus_root / "Added.sol").write_bytes(first.read_bytes())
    elif change == "omit":
        first.unlink()
    elif change == "bytes":
        first.write_bytes(first.read_bytes() + b"\n// synthetic changed bytes\n")
    elif change == "replace-file":
        clone = first.with_suffix(".replacement")
        clone.write_bytes(first.read_bytes())
        clone.replace(first)
    elif change == "replace-root":
        old = loaded.corpus_root.with_name("old-source")
        loaded.corpus_root.rename(old)
        shutil.copytree(old, loaded.corpus_root)
    elif change == "manifest":
        loaded.manifest_file.write_text(loaded.material.manifest.model_dump_json(indent=2))
    elif change == "binding":
        selected = replace(loaded, source_bindings=loaded.source_bindings[:-1])
    elif change == "directory":
        selected = replace(loaded, corpus_custody=replace(loaded.corpus_custody, path=tmp_path))
    elif change == "tree":
        selected = replace(loaded, tree_observation=None)
    else:
        other = loaded_case(tmp_path / "other", version="1.3")
        selected = replace(loaded, material=other.material)
    with pytest.raises((ValueError, OSError)):
        candidate_case(loaded, source_custody=selected)


@pytest.mark.parametrize(
    "kind", ["candidate", "ensemble", "judgment", "empty", "repeats", "resume"]
)
def test_each_parent_rebuild_replays_root_and_preserves_no_custody_bypass(tmp_path, kind):
    loaded = loaded_case(tmp_path)
    prepared = preparations(loaded)[kind](loaded)
    rebuild = {
        "candidate": rebuild_candidate,
        "ensemble": rebuild_ensemble,
        "judgment": rebuild_judgment,
        "empty": rebuild_judgment,
        "repeats": rebuild_repeats,
        "resume": rebuild_resume,
    }[kind]
    assert rebuild(prepared) == prepared
    (loaded.corpus_root / "new-empty-directory").mkdir()
    with pytest.raises(ValueError):
        rebuild(prepared)
