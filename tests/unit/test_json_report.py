from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from mmaudit.artifact_limits import MAX_JSON_ARTIFACT_BYTES
from mmaudit.reporting.json_report import (
    JsonArtifactTooLargeError,
    stable_json_bytes,
    write_json_bounded,
)


def test_manifest_and_writer_share_the_json_artifact_ceiling() -> None:
    from mmaudit.orchestration import manifest

    assert manifest.__dict__["_MAX_JSON_ARTIFACT_BYTES"] == MAX_JSON_ARTIFACT_BYTES


def test_bounded_writer_uses_exact_stable_utf8_byte_count(tmp_path: Path) -> None:
    destination = tmp_path / "evidence.json"
    payload = {"unicode": "λλ", "value": 3}
    expected = stable_json_bytes(payload)

    written = write_json_bounded(destination, payload, max_bytes=len(expected))

    assert written == len(expected)
    assert destination.read_bytes() == expected
    assert len(expected) > len(expected.decode("utf-8"))
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_bounded_writer_rejects_before_creating_parent_or_destination(tmp_path: Path) -> None:
    destination = tmp_path / "missing" / "evidence.json"
    payload = {"unicode": "λλ", "value": 3}
    expected_size = len(stable_json_bytes(payload))

    with pytest.raises(JsonArtifactTooLargeError) as captured:
        write_json_bounded(destination, payload, max_bytes=expected_size - 1)

    assert captured.value.actual_bytes == expected_size
    assert captured.value.max_bytes == expected_size - 1
    assert not destination.parent.exists()
    assert not destination.exists()


def test_bounded_writer_preserves_destination_on_oversize(tmp_path: Path) -> None:
    destination = tmp_path / "evidence.json"
    original = b"previous bounded artifact\n"
    destination.write_bytes(original)

    with pytest.raises(JsonArtifactTooLargeError):
        write_json_bounded(destination, {"payload": "too large"}, max_bytes=1)

    assert destination.read_bytes() == original
    assert list(tmp_path.iterdir()) == [destination]


def test_bounded_writer_preserves_destination_and_cleans_temp_on_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "evidence.json"
    original = b"previous bounded artifact\n"
    destination.write_bytes(original)
    real_write = os.write
    writes = 0

    def fail_after_partial_write(descriptor: int, content: bytes | memoryview) -> int:
        nonlocal writes
        writes += 1
        if writes == 1:
            return real_write(descriptor, content[:3])
        raise OSError("synthetic bounded write failure")

    monkeypatch.setattr("mmaudit.reporting.json_report.os.write", fail_after_partial_write)

    with pytest.raises(OSError, match="synthetic bounded write failure"):
        write_json_bounded(destination, {"payload": "bounded"}, max_bytes=1_000)

    assert destination.read_bytes() == original
    assert list(tmp_path.iterdir()) == [destination]


def test_bounded_writer_preserves_destination_and_cleans_temp_on_replace_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "evidence.json"
    original = b"previous bounded artifact\n"
    destination.write_bytes(original)

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("synthetic atomic replace failure")

    monkeypatch.setattr("mmaudit.reporting.json_report.os.replace", fail_replace)

    with pytest.raises(OSError, match="synthetic atomic replace failure"):
        write_json_bounded(destination, {"payload": "bounded"}, max_bytes=1_000)

    assert destination.read_bytes() == original
    assert list(tmp_path.iterdir()) == [destination]


@pytest.mark.parametrize("invalid_limit", [True, False, 0, -1, 1.5])
def test_bounded_writer_rejects_invalid_limits_without_touching_disk(
    tmp_path: Path,
    invalid_limit: object,
) -> None:
    destination = tmp_path / "missing" / "evidence.json"

    with pytest.raises(ValueError, match="positive integer"):
        write_json_bounded(destination, {}, max_bytes=invalid_limit)  # type: ignore[arg-type]

    assert not destination.parent.exists()
