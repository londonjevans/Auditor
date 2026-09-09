"""Frozen local repeat inputs cannot lose selected members, exact custody or prepared meaning."""

from dataclasses import replace

import pytest

from mmaudit.orchestration.development_corpus_repeats_inputs import (
    read_development_corpus_repeats_inputs,
    require_development_corpus_repeats_inputs,
)
from tests.development_corpus_repeats_support import repeat_input_files
from tests.unit.test_development_corpus_resume_metadata import metadata_case


@pytest.mark.parametrize("form", ["endpoint", "discovery_payload", "discovery_file"])
def test_input_handoff_preserves_all_supported_metadata_and_exact_original_files(tmp_path, form):
    metadata = metadata_case(form)
    arguments, ledger, _, output = repeat_input_files(tmp_path, metadata=metadata)
    selected = read_development_corpus_repeats_inputs(**arguments)
    assert len(selected.files) == 9
    assert selected.prepared.plan.trial_count == 2
    first = selected.prepared.trials[0].shards[0]
    assert (first.discovery or first.endpoint_snapshot) == metadata
    assert selected.prepared.plan.benchmark.truth_file_content.encode() == (
        arguments["truth_manifest"].read_bytes()
    )
    require_development_corpus_repeats_inputs(selected)
    assert not ledger.snapshot().entries and not output.exists()


@pytest.mark.parametrize("role", ["source", "manifest", "metadata", "truth"])
@pytest.mark.parametrize("mutation", ["bytes", "inode", "mode", "missing"])
def test_handoff_refuses_changed_original_files(tmp_path, role, mutation):
    arguments, ledger, _, output = repeat_input_files(tmp_path)
    selected = read_development_corpus_repeats_inputs(**arguments)
    path = {
        "source": arguments["corpus_root"] / selected.loaded.source_bindings[0].path,
        "manifest": arguments["source_manifest"],
        "metadata": arguments["endpoint_snapshot"],
        "truth": arguments["truth_manifest"],
    }[role]
    if mutation == "bytes":
        path.write_bytes(path.read_bytes() + b"\n")
    elif mutation == "inode":
        raw, mode = path.read_bytes(), path.stat().st_mode
        path.rename(path.with_name("retained-" + path.name))
        path.write_bytes(raw)
        path.chmod(mode)
    elif mutation == "mode":
        path.chmod(path.stat().st_mode ^ 0o020)
    else:
        path.unlink()
    with pytest.raises((ValueError, OSError)):
        require_development_corpus_repeats_inputs(selected)
    assert not ledger.snapshot().entries and not output.exists()


@pytest.mark.parametrize(
    "mutation", ["files", "order", "class", "metadata_path", "truth_path", "trial", "request"]
)
def test_handoff_cannot_replace_its_custody_or_prepared_snapshot(tmp_path, mutation):
    arguments, _, _, _ = repeat_input_files(tmp_path)
    selected = read_development_corpus_repeats_inputs(**arguments)
    if mutation == "files":
        selected = replace(selected, files=selected.files[:-1])
    elif mutation == "order":
        selected = replace(selected, files=tuple(reversed(selected.files)))
    elif mutation == "class":
        selected = replace(selected, files=(object(), *selected.files[1:]))
    elif mutation.endswith("path"):
        name = "metadata_file" if mutation == "metadata_path" else "truth_file"
        selected = replace(selected, **{name: tmp_path / "substituted.json"})
    elif mutation == "trial":
        selected = replace(selected, prepared=replace(selected.prepared, trials=()))
    else:
        first, *rest = selected.prepared.trials
        shard = replace(first.shards[0], request_content=b"changed synthetic request")
        first = replace(first, shards=(shard, *first.shards[1:]))
        selected = replace(selected, prepared=replace(selected.prepared, trials=(first, *rest)))
    with pytest.raises((ValueError, OSError)):
        require_development_corpus_repeats_inputs(selected)


def test_handoff_cannot_rewrite_raw_metadata_even_when_parsed_meaning_is_identical(tmp_path):
    arguments, _, _, _ = repeat_input_files(tmp_path)
    selected = read_development_corpus_repeats_inputs(**arguments)
    rewritten = replace(selected.metadata_input, content=selected.metadata_input.content + b"\n")
    selected = replace(selected, metadata_input=rewritten)
    with pytest.raises(ValueError):
        require_development_corpus_repeats_inputs(selected)


@pytest.mark.parametrize("role", ["metadata_input", "truth_input"])
@pytest.mark.parametrize("mutation", ["oversize", "binding_size", "binding_sha", "bytes_type"])
def test_raw_input_handoff_requires_original_bounded_bytes(tmp_path, role, mutation):
    arguments, _, _, _ = repeat_input_files(tmp_path)
    selected = read_development_corpus_repeats_inputs(**arguments)
    raw = getattr(selected, role)
    if mutation == "oversize":
        raw = replace(raw, content=b" " * 2_000_001)
    elif mutation == "bytes_type":
        raw = replace(raw, content=bytearray(raw.content))
    else:
        changes = (
            {"size": raw.binding.size + 1} if mutation == "binding_size" else {"sha256": "0" * 64}
        )
        raw = replace(raw, binding=raw.binding.model_copy(update=changes))
    selected = replace(selected, **{role: raw})
    with pytest.raises(ValueError):
        require_development_corpus_repeats_inputs(selected)
