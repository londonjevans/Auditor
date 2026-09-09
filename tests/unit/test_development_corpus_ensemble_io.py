"""Synthetic private-directory and composed-output boundaries; existing I/O limits stay fixed."""

from __future__ import annotations

from dataclasses import replace

import pytest

from mmaudit.models.development_corpus import DevelopmentCorpusMaterial, DevelopmentCorpusText
from mmaudit.orchestration.development_corpus import (
    DevelopmentCorpusUpstream,
    require_development_corpus_upstream,
)
from mmaudit.orchestration.development_corpus_ensemble import _bind_child
from mmaudit.release_io import (
    DEFAULT_MAX_EVIDENCE_BYTES,
    MAX_COMPOSED_EVIDENCE_BYTES,
    read_json_evidence,
    revalidate_composed_evidence_file_binding,
    write_composed_json_evidence,
    write_json_evidence,
)
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.directory_custody import prepare_owned_empty_directory
from tests.development_corpus_judgment_support import pure_candidate


def test_precreated_child_must_be_the_same_private_empty_directory(tmp_path):
    path = tmp_path / "owned-child"
    custody = prepare_owned_empty_directory(path, label="synthetic child")
    assert path.stat().st_mode & 0o777 == 0o700
    assert (
        prepare_owned_empty_directory(path, label="synthetic child", precreated=custody) == custody
    )
    with pytest.raises(FileExistsError):
        prepare_owned_empty_directory(path, label="synthetic child")


@pytest.mark.parametrize("kind", ["exact", "truncated", "reordered", "empty"])
def test_candidate_upstream_retains_the_entire_ordered_directory_chain(tmp_path, kind):
    path = tmp_path / "synthetic-parent"
    custody = prepare_owned_empty_directory(path, label="synthetic parent")
    files = tuple(
        write_json_evidence(evidence_root=path, relative_path=name, value={})
        for name in ("plan.json", "sources.json")
    )
    if kind == "truncated":
        custody = replace(custody, component_identities=custody.component_identities[-1:])
    elif kind == "reordered":
        custody = replace(
            custody,
            component_identities=(
                *reversed(custody.component_identities[:-1]),
                custody.component_identities[-1],
            ),
        )
    elif kind == "empty":
        custody = replace(custody, component_identities=())
    upstream = DevelopmentCorpusUpstream(custody, files)
    if kind == "exact":
        require_development_corpus_upstream(upstream)
    else:
        with pytest.raises(ValueError, match="upstream custody"):
            require_development_corpus_upstream(upstream)


@pytest.mark.parametrize(
    "changed", [None, "plan.json", "sources.json", "result.json", "file-0001.json"]
)
def test_adopted_child_records_match_the_canonical_writer_bytes_not_only_json_values(
    tmp_path, changed
):
    prepared, candidate = pure_candidate(count=1, claims=0)
    material = DevelopmentCorpusMaterial(
        manifest=prepared.plan.manifest,
        sources=tuple(
            DevelopmentCorpusText(filename=name, content=raw.decode())
            for name, raw in prepared.shards[0].source_files
        ),
    )
    child = tmp_path / "candidate"
    child.mkdir(mode=0o700)
    values = {
        "plan.json": candidate.plan,
        "sources.json": material,
        "result.json": candidate,
        "file-0001.json": candidate.observations[0],
    }
    for name, value in values.items():
        write_json_evidence(
            evidence_root=child, relative_path=name, value=value.model_dump(mode="json")
        )
    if changed is not None:
        path = child / changed
        path.write_bytes(path.read_bytes() + b" ")
        with pytest.raises(ValueError, match="differs from its result"):
            _bind_child(tmp_path, "candidate", candidate, material, None)
    else:
        assert len(_bind_child(tmp_path, "candidate", candidate, material, None)) == 4


@pytest.mark.parametrize(
    "change", ["contents", "permissions", "replacement", "link", "shape", "type"]
)
def test_precreated_handoff_rejects_nonempty_shared_substituted_or_forged_directory(
    tmp_path, change
):
    path = tmp_path / "owned-child"
    custody = prepare_owned_empty_directory(path, label="synthetic child")
    if change == "contents":
        (path / "existing.json").write_text("{}")
    elif change == "permissions":
        path.chmod(0o755)
    elif change in {"replacement", "link"}:
        preserved = tmp_path / "preserved-child"
        path.rename(preserved)
        if change == "link":
            path.symlink_to(preserved, target_is_directory=True)
        else:
            path.mkdir(mode=0o700)
    elif change == "shape":
        custody = replace(custody, component_identities=custody.component_identities[-1:])
    else:
        custody = {}
    with pytest.raises(ValueError):
        prepare_owned_empty_directory(path, label="synthetic child", precreated=custody)


@pytest.mark.parametrize("maximum", [100_000_001, 256_000_000])
def test_new_composed_envelope_never_widens_ordinary_json_writer(tmp_path, maximum):
    assert DEFAULT_MAX_EVIDENCE_BYTES == 100_000_000
    assert MAX_COMPOSED_EVIDENCE_BYTES == 256_000_000
    with pytest.raises(ValueError, match="byte bound"):
        write_json_evidence(
            evidence_root=tmp_path, relative_path="ordinary.json", value={}, max_bytes=maximum
        )
    assert not (tmp_path / "ordinary.json").exists()


@pytest.mark.parametrize("maximum", [0, -1, True, 256_000_001])
def test_composed_byte_bound_is_explicit_finite_and_capped(tmp_path, maximum):
    with pytest.raises(ValueError, match="byte bound"):
        write_composed_json_evidence(
            evidence_root=tmp_path,
            relative_path="composed.json",
            value={},
            max_bytes=maximum,
            validate_content=lambda _raw: None,
        )
    assert not (tmp_path / "composed.json").exists()


@pytest.mark.parametrize("change", ["none", "growth", "same_size", "validator_failure"])
def test_composed_output_uses_exact_private_writer_and_original_size_custody(tmp_path, change):
    value = {"synthetic": "retained"}
    expected = stable_json(value).encode()
    seen = []

    def validate(raw):
        seen.append(raw)
        assert raw == expected
        if change == "validator_failure":
            raise ValueError("synthetic validation refusal")

    if change == "validator_failure":
        with pytest.raises(ValueError, match="synthetic validation refusal"):
            write_composed_json_evidence(
                evidence_root=tmp_path,
                relative_path="composed.json",
                value=value,
                max_bytes=MAX_COMPOSED_EVIDENCE_BYTES,
                validate_content=validate,
            )
        assert not (tmp_path / "composed.json").exists()
        return
    binding = write_composed_json_evidence(
        evidence_root=tmp_path,
        relative_path="composed.json",
        value=value,
        max_bytes=MAX_COMPOSED_EVIDENCE_BYTES,
        validate_content=validate,
    )
    path = tmp_path / "composed.json"
    assert seen == [expected] and path.stat().st_mode & 0o777 == 0o600
    assert binding.size == len(expected)
    assert (
        revalidate_composed_evidence_file_binding(evidence_root=tmp_path, binding=binding)
        == binding
    )
    if change == "none":
        return
    path.write_bytes(
        expected + b" " if change == "growth" else expected.replace(b"retained", b"modified")
    )
    with pytest.raises(ValueError):
        revalidate_composed_evidence_file_binding(evidence_root=tmp_path, binding=binding)


def test_composed_writer_really_crosses_ordinary_limit_with_original_size_readback(tmp_path):
    """A synthetic 100MB string exercises the distinct writer, not just its limit argument."""

    value = {"synthetic_padding": "x" * DEFAULT_MAX_EVIDENCE_BYTES}
    sizes = []

    def validate(raw):
        assert raw.startswith(b'{\n  "synthetic_padding": "')
        assert raw.endswith(b'"\n}\n')
        sizes.append(len(raw))

    binding = write_composed_json_evidence(
        evidence_root=tmp_path,
        relative_path="large-composed.json",
        value=value,
        max_bytes=MAX_COMPOSED_EVIDENCE_BYTES,
        validate_content=validate,
    )
    assert DEFAULT_MAX_EVIDENCE_BYTES < binding.size < MAX_COMPOSED_EVIDENCE_BYTES
    assert sizes == [binding.size]
    assert (tmp_path / "large-composed.json").stat().st_mode & 0o777 == 0o600
    assert (
        revalidate_composed_evidence_file_binding(evidence_root=tmp_path, binding=binding)
        == binding
    )
    with pytest.raises(ValueError):
        read_json_evidence(evidence_root=tmp_path, relative_path="large-composed.json")
