"""Synthetic metadata compatibility controls; serialized provenance confers no authority."""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
from dataclasses import replace
from typing import get_args

import pytest

from mmaudit.models.development_corpus_resume import prepare_development_corpus_resume
from mmaudit.models.development_review import DevelopmentReviewMetadata
from mmaudit.models.discovery import (
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryPayload,
)
from mmaudit.models.endpoint_snapshots import OpenRouterEndpointSnapshotEvidence
from mmaudit.orchestration.development_corpus_resume import (
    _verify_input_meaning,
    read_development_corpus_resume_inputs,
    require_development_corpus_resume_inputs,
)
from tests.development_corpus_resume_support import resume_case
from tests.development_corpus_support import CORPUS_MODEL, corpus_case
from tests.development_review_support import discovery_review_case
from tests.unit.test_model_discovery import (
    _real_evidence as synthetic_serialized_discovery_evidence,
)


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("metadata compatibility attempted network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def metadata_case(form="discovery_file", *, model_id=CORPUS_MODEL, **changes):
    payload = discovery_review_case(
        model_id=model_id,
        endpoint_efforts=("high",) if form == "endpoint" else None,
        **changes,
    )
    if form == "endpoint":
        return payload.endpoint_snapshot
    if form == "discovery_payload":
        return payload
    return synthetic_serialized_discovery_evidence((payload,))[0]


def input_files(tmp_path, metadata, *, mode="history"):
    history, _ = resume_case(endpoint_snapshot=metadata, observed_count=1)
    files = {"metadata_file": tmp_path / "synthetic-metadata.json"}
    files["metadata_file"].write_bytes(metadata.model_dump_json(indent=2).encode())
    if mode == "history":
        files["history_file"] = tmp_path / "synthetic-history.json"
        files["history_file"].write_text(history.model_dump_json())
    else:
        files["candidate_file"] = tmp_path / "synthetic-candidate.json"
        files["candidate_file"].write_text(history.original.model_dump_json())
        files["material_file"] = tmp_path / "synthetic-material.json"
        files["material_file"].write_text(history.material.model_dump_json())
    return history, files


@pytest.mark.parametrize("mode", ["original", "history"])
@pytest.mark.parametrize("form", ["endpoint", "discovery_payload", "discovery_file"])
def test_loader_preserves_each_shared_metadata_type_and_exact_original_request(
    tmp_path, mode, form
):
    metadata = metadata_case(form)
    history, files = input_files(tmp_path, metadata, mode=mode)
    original_bytes = {p: p.read_bytes() for p in files.values()}
    inputs = read_development_corpus_resume_inputs(**files)
    assert type(inputs.metadata) is type(metadata) and inputs.metadata == metadata
    assert inputs.history == history
    require_development_corpus_resume_inputs(inputs)
    bound = inputs.files[-1].binding
    assert bound.sha256 == hashlib.sha256(original_bytes[files["metadata_file"]]).hexdigest()
    prepared = prepare_development_corpus_resume(
        history=history, endpoint_snapshot=inputs.metadata, run_id="synthetic-metadata-resume"
    )
    original = corpus_case(
        source_files=history.material.source_files,
        policy=history.original.plan.policy,
        endpoint_snapshot=metadata,
    )
    assert original.plan == history.original.plan
    assert [s.request_content for s in prepared.candidate.shards] == [
        s.request_content for s in original.shards
    ]
    assert prepared.plan.selected_shard_ids == ("file-0002", "file-0003", "file-0004")
    assert prepared.plan.reused_observed_shard_ids == ("file-0001",)
    for shard in prepared.candidate.shards:
        assert json.loads(shard.request_content)["reasoning"] == {"effort": "high"}
    if form == "discovery_file":
        assert type(prepared.candidate.shards[0].discovery) is OpenRouterModelDiscoveryEvidence
        assert prepared.candidate.shards[0].discovery.discovery_evidence_sha256 == (
            metadata.discovery_evidence_sha256
        )
        assert metadata.endpoint_snapshot.endpoints[0].supported_reasoning_efforts is None
    assert all(p.read_bytes() == raw for p, raw in original_bytes.items())
    assert not history.audit_complete and not history.qualification_eligible


def test_metadata_compatibility_controls_cover_the_complete_shared_type_union():
    assert set(get_args(DevelopmentReviewMetadata.__value__)) == {
        OpenRouterEndpointSnapshotEvidence,
        OpenRouterModelDiscoveryPayload,
        OpenRouterModelDiscoveryEvidence,
    }


@pytest.mark.parametrize("form", ["endpoint", "discovery_payload", "discovery_file", "object"])
def test_metadata_admission_remains_exact_not_arbitrary_subclass_or_object(tmp_path, form):
    metadata = metadata_case("discovery_file" if form == "object" else form)
    _, files = input_files(tmp_path, metadata)
    inputs = read_development_corpus_resume_inputs(**files)
    if form == "object":
        altered = object()
    else:
        subtype = type("SyntheticUnselectedMetadataSubclass", (type(metadata),), {})
        altered = subtype.model_validate_json(metadata.model_dump_json(), strict=True)
    with pytest.raises(ValueError, match="input selection is invalid"):
        require_development_corpus_resume_inputs(replace(inputs, metadata=altered))


@pytest.mark.parametrize(
    "kind",
    [
        "evidence_hash",
        "model_hash",
        "route",
        "provenance",
        "missing_provenance",
        "extra",
        "duplicate",
        "malformed",
        "nonfinite",
    ],
)
def test_discovery_wrapper_never_bypasses_strict_json_or_bound_metadata_validation(tmp_path, kind):
    metadata = metadata_case()
    _, files = input_files(tmp_path, metadata)
    data = metadata.model_dump(mode="json")
    if kind == "evidence_hash":
        data["discovery_evidence_sha256"] = "0" * 64
    elif kind == "model_hash":
        data["model_metadata_snapshot_sha256"] = "0" * 64
    elif kind == "route":
        data["provenance"]["candidate_routes"][0]["approved_provider_endpoint"] = (
            "synthetic-unselected-provider"
        )
    elif kind == "provenance":
        data["provenance"]["authenticated_metadata"] = False
    elif kind == "missing_provenance":
        del data["provenance"]
    elif kind == "extra":
        data["unselected_field"] = "synthetic extra"
    elif kind == "nonfinite":
        data["catalog_context_size"] = float("nan")
    content = json.dumps(data).encode()
    if kind == "duplicate":
        content = content.replace(b"{", b'{"schema_version":"1.0",', 1)
    elif kind == "malformed":
        content = b"{invalid synthetic JSON"
    files["metadata_file"].write_bytes(content)
    with pytest.raises(ValueError):
        read_development_corpus_resume_inputs(**files)


@pytest.mark.parametrize("over", [False, True])
def test_complete_discovery_file_keeps_the_existing_two_megabyte_input_bound(tmp_path, over):
    metadata = metadata_case()
    _, files = input_files(tmp_path, metadata)
    path = files["metadata_file"]
    content = path.read_bytes()
    path.write_bytes(content + b" " * (2_000_000 + int(over) - len(content)))
    if over:
        with pytest.raises(ValueError):
            read_development_corpus_resume_inputs(**files)
    else:
        inputs = read_development_corpus_resume_inputs(**files)
        assert inputs.metadata == metadata and inputs.files[-1].binding.size == 2_000_000
        _verify_input_meaning(inputs)


@pytest.mark.parametrize("kind", ["changed_provenance", "flattened_payload"])
def test_retained_metadata_cannot_change_meaning_or_drop_wrapper_with_bound_bytes_fixed(
    tmp_path, kind
):
    metadata = metadata_case()
    _, files = input_files(tmp_path, metadata)
    inputs = read_development_corpus_resume_inputs(**files)
    if kind == "changed_provenance":
        altered = metadata.model_copy(
            update={"provenance": metadata.provenance.model_copy(update={"run_id": "2" * 32})}
        )
    else:
        altered = OpenRouterModelDiscoveryPayload.model_validate_json(
            metadata.model_dump_json(include=set(OpenRouterModelDiscoveryPayload.model_fields)),
            strict=True,
        )
    with pytest.raises(ValueError):
        _verify_input_meaning(replace(inputs, metadata=altered))


@pytest.mark.parametrize("kind", ["low_only", "snapshot_without_parent_efforts"])
def test_full_discovery_support_never_relaxes_required_high_reasoning(tmp_path, kind):
    metadata = metadata_case()
    _, files = input_files(tmp_path, metadata)
    altered = (
        metadata_case(model_efforts=("low",)) if kind == "low_only" else metadata.endpoint_snapshot
    )
    files["metadata_file"].write_text(altered.model_dump_json())
    inputs = read_development_corpus_resume_inputs(**files)
    with pytest.raises(ValueError, match="native JSON schema and high reasoning"):
        prepare_development_corpus_resume(
            history=inputs.history,
            endpoint_snapshot=inputs.metadata,
            run_id="synthetic-refused-metadata-resume",
        )
