"""Synthetic private-directory and composed-output boundaries; existing I/O limits stay fixed."""

from __future__ import annotations

from dataclasses import replace

import pytest

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


def test_precreated_child_must_be_the_same_private_empty_directory(tmp_path):
    path = tmp_path / "owned-child"
    custody = prepare_owned_empty_directory(path, label="synthetic child")
    assert path.stat().st_mode & 0o777 == 0o700
    assert (
        prepare_owned_empty_directory(path, label="synthetic child", precreated=custody) == custody
    )
    with pytest.raises(FileExistsError):
        prepare_owned_empty_directory(path, label="synthetic child")


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
