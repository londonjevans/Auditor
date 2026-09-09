"""Synthetic continuation custody and full-history bounds, with no real network or process."""

from __future__ import annotations

import socket
import subprocess
from decimal import Decimal

import httpx
import pytest
from pydantic import BaseModel

import mmaudit.repository.directory_custody as directory_custody
import mmaudit.repository.file_custody as file_custody
from mmaudit.models.development_corpus_resume import MAX_DEVELOPMENT_CORPUS_RESUME_BYTES
from mmaudit.orchestration.development_corpus_resume import (
    _require_file,
    _write,
    read_development_corpus_resume_inputs,
)
from mmaudit.reporting.json_report import stable_json
from tests.development_corpus_resume_support import resume_case, selected_resume
from tests.development_corpus_support import corpus_payload
from tests.integration.test_development_corpus_resume_execution import execute, execution_case


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("continuation boundary test attempted actual network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.mark.parametrize("level", ["parent", "ancestor"])
@pytest.mark.parametrize("kind", ["file", "directory"])
def test_continuation_file_guard_keeps_exact_file_while_unrelated_entries_change(
    tmp_path, monkeypatch, level, kind
):
    ancestor = tmp_path / "owned-ancestor"
    parent = ancestor / "owned-inputs"
    parent.mkdir(parents=True)
    path = parent / "synthetic-evidence.json"
    path.write_bytes(b'{"synthetic":true}')
    path.chmod(0o600)
    original_bytes = path.read_bytes()
    expected = file_custody.observe_regular_file_custody(
        root=parent, relative_path=path.name, label="synthetic evidence", max_bytes=100
    )
    real_read = file_custody.read_file_evidence
    calls = []
    peer = (parent if level == "parent" else ancestor) / "unrelated-synthetic-entry"

    def read_during_sibling_change(**kwargs):
        observed = real_read(**kwargs)
        calls.append(kwargs)
        if len(calls) == 2:
            if kind == "file":
                peer.write_bytes(b"synthetic unrelated entry")
            else:
                peer.mkdir()
        return observed

    monkeypatch.setattr(file_custody, "read_file_evidence", read_during_sibling_change)
    _require_file(expected, max_bytes=100)
    assert len(calls) == 2 and peer.exists()
    assert path.read_bytes() == original_bytes
    assert (
        file_custody._observe_regular_file_identity(path, label="synthetic evidence")
        == expected.identity
    )
    # Existing strict consumers must still reject metadata drift; this is not a new default.
    with pytest.raises(ValueError):
        file_custody.require_regular_file_custody_unchanged(expected, label="strict", max_bytes=100)


@pytest.mark.parametrize("allow", [False, True])
@pytest.mark.parametrize("phase", ["directory_resolution", "file_read"])
def test_directory_entry_churn_requires_explicit_opt_in_and_never_changes_strict_default(
    tmp_path, monkeypatch, allow, phase
):
    root = tmp_path / "owned-inputs"
    root.mkdir()
    path = root / "synthetic.json"
    path.write_bytes(b"{}")
    peer = root / "synthetic-peer"
    if phase == "directory_resolution":
        original = directory_custody._observe_components

        def observed(*args, **kwargs):
            result = original(*args, **kwargs)
            if not peer.exists():
                peer.mkdir()
            return result

        monkeypatch.setattr(directory_custody, "_observe_components", observed)
    else:
        original_read = file_custody.read_file_evidence
        calls = []

        def read(**kwargs):
            value = original_read(**kwargs)
            calls.append(value)
            if len(calls) == 2:
                peer.mkdir()
            return value

        monkeypatch.setattr(file_custody, "read_file_evidence", read)
    kwargs = dict(root=root, relative_path=path.name, label="synthetic")
    if allow:
        observation = file_custody.observe_regular_file_custody(
            **kwargs, allow_directory_entry_metadata_change=True
        )
        assert observation.identity == file_custody._observe_regular_file_identity(
            path, label="same"
        )
        assert tuple(p for p, _ in observation.parent.component_identities) == (
            *reversed(root.parents),
            root,
        )
    else:
        with pytest.raises(ValueError):
            file_custody.observe_regular_file_custody(**kwargs)


@pytest.mark.parametrize("value", [1, "true", None, [], object()])
def test_directory_metadata_policy_cannot_be_enabled_by_truthy_non_boolean_inputs(tmp_path, value):
    with pytest.raises(ValueError, match="must be boolean"):
        directory_custody.observe_unlinked_directory(
            tmp_path, label="synthetic", allow_entry_metadata_change=value
        )
    with pytest.raises(ValueError, match="must be boolean"):
        file_custody.observe_regular_file_custody(
            root=tmp_path,
            relative_path="absent.json",
            label="synthetic",
            allow_directory_entry_metadata_change=value,
        )


@pytest.mark.parametrize(
    "kind",
    [
        "file_object",
        "file_bytes",
        "file_mode",
        "directory_object",
        "directory_mode",
        "directory_link",
    ],
)
def test_entry_metadata_opt_in_never_allows_file_or_ancestor_identity_changes(
    tmp_path, monkeypatch, kind
):
    ancestor = tmp_path / "owned-ancestor"
    parent = ancestor / "owned-inputs"
    parent.mkdir(parents=True)
    ancestor.chmod(0o755)
    path = parent / "synthetic.json"
    path.write_bytes(b"{}")
    path.chmod(0o600)
    original_read = file_custody.read_file_evidence
    calls = []

    def changed_read(**kwargs):
        result = original_read(**kwargs)
        calls.append(result)
        if len(calls) == 2:
            if kind == "file_object":
                path.rename(parent / "retained-original.json")
                path.write_bytes(b"{}")
                path.chmod(0o600)
            elif kind == "file_bytes":
                path.write_bytes(b"[]")
            elif kind == "file_mode":
                path.chmod(0o644)
            elif kind == "directory_mode":
                ancestor.chmod(0o700)
            else:
                retained = ancestor.with_name("retained-ancestor")
                ancestor.rename(retained)
                if kind == "directory_link":
                    ancestor.symlink_to(retained, target_is_directory=True)
                else:
                    parent.mkdir(parents=True)
                    path.write_bytes(b"{}")
                    path.chmod(0o600)
        return result

    monkeypatch.setattr(file_custody, "read_file_evidence", changed_read)
    with pytest.raises(ValueError):
        file_custody.observe_regular_file_custody(
            root=parent,
            relative_path=path.name,
            label="synthetic",
            allow_directory_entry_metadata_change=True,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [4, 64])
async def test_actual_continuation_keeps_every_response_during_unrelated_ancestor_entry_churn(
    tmp_path, monkeypatch, count
):
    claims = 16 if count == 64 else 1
    case = await execution_case(tmp_path, count=count, claims=claims)
    original_read = file_custody.read_file_evidence
    peers = (tmp_path / "synthetic-peer-a", tmp_path / "synthetic-peer-b")
    peers[0].write_bytes(b"bounded synthetic sibling; not selected source")
    reads = []

    def noisy_read(**kwargs):
        value = original_read(**kwargs)
        index = len(reads) % 2
        peers[index].rename(peers[1 - index])
        reads.append(value.binding.path)
        return value

    monkeypatch.setattr(file_custody, "read_file_evidence", noisy_read)

    def response(shard, _ordinal, _request):
        payload = corpus_payload(int(shard[-4:]), count=claims)
        payload["id"] = "gen-synthetic-noisy-continuation-" + shard
        return httpx.Response(200, json=payload)

    result = await execute(case, custom=response)
    assert len(case.calls) == count - 1
    assert result.summary.cumulative_completed_shard_count == count
    assert result.summary.candidate_claim_count == count * claims
    assert result.summary.accounted_request_count == count + 1
    assert result.summary.total_accounted_cost_usd == Decimal("0.01") * (count + 1)
    assert result.original == case.original and result.material == case.inputs.history.material
    assert all(p.read_bytes() == raw for p, raw in case.prior_bytes.items())
    assert len(reads) > count and not result.audit_complete


@pytest.mark.asyncio
@pytest.mark.parametrize("complete_last", [False, True])
async def test_eight_explicit_stages_keep_all_original_and_repeated_failure_charges(
    tmp_path, complete_last
):
    case = await execution_case(tmp_path, count=64, claims=16)
    first = case.original_prepared.shards[0]
    metadata = first.discovery or first.endpoint_snapshot
    inputs = case.inputs
    prior_results = []
    for index in range(1, 9):
        prepared = selected_resume(inputs.history, metadata)
        assert prepared.plan.continuation_index == index
        assert prepared.plan.selected_shard_ids == tuple(f"file-{n:04d}" for n in range(2, 65))

        def respond(shard, _ordinal, _request, *, stage=index):
            payload = corpus_payload(int(shard[-4:]), count=16)
            payload["id"] = f"gen-synthetic-bounded-stage-{stage}-{shard}"
            if stage != 8 or not complete_last:
                payload["choices"][0]["message"]["content"] = "{}"
            return httpx.Response(200, json=payload)

        output = tmp_path / f"continuation-{index}"
        result = await execute(
            case, prepared=prepared, inputs=inputs, output_dir=output, custom=respond
        )
        assert result.continuations[:-1] == inputs.history.continuations
        assert result.original == case.original
        assert result.summary.original_first_attempt_completed_shard_count == 1
        assert result.summary.continuation_count == index
        assert result.summary.total_accounted_cost_usd == case.ledger.snapshot().spent_usd
        assert all(p.read_bytes() == b for p, b in prior_results)
        prior_results.append((output / "result.json", (output / "result.json").read_bytes()))
        inputs = read_development_corpus_resume_inputs(history_file=output / "result.json")
    expected_requests = 72 if complete_last else 10
    assert result.summary.accounted_request_count == expected_requests
    assert len(case.calls) == expected_requests - 2
    assert len(case.ledger.snapshot().entries) == expected_requests
    assert result.summary.total_accounted_cost_usd == Decimal("0.01") * expected_requests
    assert result.summary.cumulative_completed_shard_count == (64 if complete_last else 1)
    assert result.summary.candidate_claim_count == (1024 if complete_last else 16)
    assert len({e.reservation_id for e in case.ledger.snapshot().entries}) == expected_requests
    assert len({e.request_id for e in case.ledger.snapshot().entries}) == expected_requests
    with pytest.raises(ValueError, match="stage limit"):
        selected_resume(result, metadata)
    assert all(p.read_bytes() == b for p, b in case.prior_bytes.items())
    assert not result.audit_complete and not result.qualification_eligible


@pytest.mark.parametrize("over", [False, True])
def test_explicit_history_reader_enforces_exact_sixty_four_megabyte_raw_bound(tmp_path, over):
    history, _metadata = resume_case()
    content = history.model_dump_json().encode()
    path = tmp_path / "synthetic-history.json"
    size = MAX_DEVELOPMENT_CORPUS_RESUME_BYTES + int(over)
    # JSON whitespace is exact retained input evidence, not new source or model content.
    path.write_bytes(content + b" " * (size - len(content)))
    assert path.stat().st_size == size
    if over:
        with pytest.raises(ValueError):
            read_development_corpus_resume_inputs(history_file=path)
    else:
        inputs = read_development_corpus_resume_inputs(history_file=path)
        assert inputs.history == history
        assert inputs.files[0].binding.size == MAX_DEVELOPMENT_CORPUS_RESUME_BYTES
        _require_file(inputs.files[0].custody, max_bytes=MAX_DEVELOPMENT_CORPUS_RESUME_BYTES)


class _SyntheticBoundedContainer(BaseModel):
    payload: str


@pytest.mark.parametrize("over", [False, True])
def test_private_composed_writer_enforces_sixty_four_megabytes_without_changing_old_bounds(
    tmp_path, over
):
    from mmaudit.release_io import DEFAULT_MAX_EVIDENCE_BYTES

    root = tmp_path / "owned-output"
    root.mkdir(mode=0o700)
    overhead = len(stable_json({"payload": ""}).encode())
    value = _SyntheticBoundedContainer(
        payload="x" * (MAX_DEVELOPMENT_CORPUS_RESUME_BYTES - overhead + int(over))
    )
    if over:
        with pytest.raises(ValueError, match="output bound"):
            _write(root, "synthetic-boundary.json", value)
        assert not (root / "synthetic-boundary.json").exists()
    else:
        observed = _write(root, "synthetic-boundary.json", value)
        assert observed.binding.size == MAX_DEVELOPMENT_CORPUS_RESUME_BYTES
        assert (root / "synthetic-boundary.json").stat().st_mode & 0o777 == 0o600
    assert DEFAULT_MAX_EVIDENCE_BYTES == 100_000_000
