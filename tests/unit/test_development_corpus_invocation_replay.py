"""Pure parse reuse is exact, bounded, detached and confined to its owning invocation."""

from __future__ import annotations

import asyncio
import json

import pytest

from mmaudit.models import development_corpus as models
from mmaudit.models import development_corpus_replay as module
from tests.integration.test_development_partition_custody import bundle


@pytest.fixture
def material(tmp_path):
    reference, _, _ = bundle(tmp_path)
    return reference.material


def counted_parser(monkeypatch, model):
    original = model.model_validate_json
    calls = []

    def parse(content, **kwargs):
        assert kwargs == {"strict": True}
        calls.append(content)
        return original(content, **kwargs)

    monkeypatch.setattr(model, "model_validate_json", parse)
    return calls


def test_material_is_replayed_once_per_owner_scope_and_never_shared_with_callers(
    material, monkeypatch
):
    content = material.model_dump_json()
    calls = counted_parser(monkeypatch, models.DevelopmentCorpusMaterial)
    first = module.replay_development_corpus_material(content)
    assert first == module.replay_development_corpus_material(content) == material
    assert len(calls) == 2
    for _ in range(2):
        with module.development_corpus_replay_scope():
            before = len(calls)
            first = module.replay_development_corpus_material(content)
            second = module.replay_development_corpus_material(content)
            assert first == second == material
            assert first is not second and first.manifest is not second.manifest
            object.__setattr__(first.manifest, "corpus_id", "synthetic-drift")
            assert module.replay_development_corpus_material(content) == material
            assert len(calls) == before + 1


@pytest.mark.parametrize("kind", ["material", "manifest"])
def test_exact_raw_inputs_not_declared_digest_determine_cache_hits(material, monkeypatch, kind):
    model = (
        models.DevelopmentCorpusMaterial if kind == "material" else models.DevelopmentCorpusManifest
    )
    content = (
        material.model_dump_json()
        if kind == "material"
        else material.manifest.model_dump_json().encode()
    )
    replay = getattr(module, "replay_development_corpus_" + kind)
    calls = counted_parser(monkeypatch, model)
    variants = [content, content + ("\n" if kind == "material" else b"\n")]
    with module.development_corpus_replay_scope():
        for value in variants:
            replay(value)
            replay(value)
        assert calls == variants
        changed = json.loads(content)
        if kind == "material":
            changed["sources"][0]["content"] += "\n"
        else:
            changed["corpus_id"] += "-changed"
        encoded = json.dumps(changed)
        with pytest.raises(ValueError):
            replay(encoded if kind == "material" else encoded.encode())
        assert len(calls) == 3


@pytest.mark.parametrize("kind", ["material", "manifest"])
def test_failed_validation_never_enters_the_replay_table(material, monkeypatch, kind):
    model = (
        models.DevelopmentCorpusMaterial if kind == "material" else models.DevelopmentCorpusManifest
    )
    content = (
        material.model_dump_json()
        if kind == "material"
        else material.manifest.model_dump_json().encode()
    )
    replay = getattr(module, "replay_development_corpus_" + kind)
    calls = counted_parser(monkeypatch, model)
    with module.development_corpus_replay_scope():
        replay(content)
        state = module._REPLAY.get()
        table = getattr(state, kind + "s")
        for _ in range(2):
            with pytest.raises(ValueError):
                replay(content[:-1])
        assert len(table.entries) == 1
        assert len(calls) == 3


@pytest.mark.parametrize("kind", ["material", "manifest"])
def test_replay_eviction_limits_each_table_to_two_exact_inputs(material, monkeypatch, kind):
    model = (
        models.DevelopmentCorpusMaterial if kind == "material" else models.DevelopmentCorpusManifest
    )
    content = (
        material.model_dump_json()
        if kind == "material"
        else material.manifest.model_dump_json().encode()
    )
    space = " " if kind == "material" else b" "
    replay = getattr(module, "replay_development_corpus_" + kind)
    calls = counted_parser(monkeypatch, model)
    with module.development_corpus_replay_scope():
        table = getattr(module._REPLAY.get(), kind + "s")
        for suffix in range(5):
            replay(content + space * suffix)
            assert len(table.entries) <= 2
        assert list(table.entries) == [content + space * 3, content + space * 4]
        replay(content)
        assert len(calls) == 6 and len(table.entries) == 2


@pytest.mark.parametrize("kind", ["material", "manifest"])
def test_cache_size_limit_is_not_a_new_admission_limit(material, monkeypatch, kind):
    model = (
        models.DevelopmentCorpusMaterial if kind == "material" else models.DevelopmentCorpusManifest
    )
    content = (
        material.model_dump_json()
        if kind == "material"
        else material.manifest.model_dump_json().encode()
    )
    replay = getattr(module, "replay_development_corpus_" + kind)
    calls = counted_parser(monkeypatch, model)
    monkeypatch.setattr(
        module,
        "_MAX_REPLAY_MATERIAL_BYTES" if kind == "material" else "_MAX_REPLAY_MANIFEST_BYTES",
        1,
    )
    with module.development_corpus_replay_scope():
        first = replay(content)
        assert replay(content) == first
        assert not getattr(module._REPLAY.get(), kind + "s").entries
    assert calls == [content, content]


def test_cached_model_tampering_is_refused_not_refreshed(material):
    content = material.model_dump_json()
    with module.development_corpus_replay_scope():
        module.replay_development_corpus_material(content)
        cached = module._REPLAY.get().materials.entries[content]
        object.__setattr__(cached.value.manifest, "corpus_id", "synthetic-cache-drift")
        with pytest.raises(ValueError, match=r"cached.*changed"):
            module.replay_development_corpus_material(content)


def test_live_source_validation_and_bound_changes_do_not_reuse_old_success(material, monkeypatch):
    content = material.model_dump_json()
    with module.development_corpus_replay_scope():
        module.replay_development_corpus_material(content)
        monkeypatch.setattr(models, "MAX_DEVELOPMENT_CORPUS_BYTES", 1)
        with pytest.raises(ValueError):
            module.replay_development_corpus_material(content)


def test_changed_validator_is_reapplied_with_strict_mode(material, monkeypatch):
    content = material.model_dump_json()
    with module.development_corpus_replay_scope():
        module.replay_development_corpus_material(content)

        def refused(_content, **kwargs):
            assert kwargs == {"strict": True}
            raise ValueError("synthetic parser refusal")

        monkeypatch.setattr(models.DevelopmentCorpusMaterial, "model_validate_json", refused)
        with pytest.raises(ValueError, match="synthetic parser refusal"):
            module.replay_development_corpus_material(content)


def test_nested_scope_and_exception_cleanup_discard_private_results(material, monkeypatch):
    content = material.model_dump_json()
    calls = counted_parser(monkeypatch, models.DevelopmentCorpusMaterial)
    with module.development_corpus_replay_scope():
        outer = module._REPLAY.get()
        module.replay_development_corpus_material(content)
        with (
            pytest.raises(RuntimeError, match="synthetic exit"),
            module.development_corpus_replay_scope(),
        ):
            inner = module._REPLAY.get()
            module.replay_development_corpus_material(content)
            assert inner is not outer
            raise RuntimeError("synthetic exit")
        assert not inner.active and not inner.materials.entries and not inner.manifests.entries
        assert module._REPLAY.get() is outer
        module.replay_development_corpus_material(content)
        assert len(calls) == 2
    assert module._REPLAY.get() is None and not outer.active and not outer.materials.entries


@pytest.mark.asyncio
async def test_parallel_invocations_and_inherited_child_tasks_cannot_share_results(
    material, monkeypatch
):
    content = material.model_dump_json()
    calls = counted_parser(monkeypatch, models.DevelopmentCorpusMaterial)
    ready = asyncio.Event()
    release = asyncio.Event()
    states = []

    @module.with_development_corpus_replay
    async def worker(wait):
        states.append(module._REPLAY.get())
        module.replay_development_corpus_material(content)
        ready.set()
        if wait:
            await release.wait()
        module.replay_development_corpus_material(content)

    first = asyncio.create_task(worker(True))
    await ready.wait()
    await worker(False)
    release.set()
    await first
    assert len(calls) == 2 and states[0] is not states[1]
    assert all(not state.active and not state.materials.entries for state in states)

    async def child():
        module.replay_development_corpus_material(content)
        module.replay_development_corpus_material(content)

    with module.development_corpus_replay_scope():
        module.replay_development_corpus_material(content)
        await asyncio.create_task(child())
        module.replay_development_corpus_material(content)
    assert len(calls) == 5


@pytest.mark.asyncio
async def test_cancelled_owner_clears_cache_before_an_inherited_child_outlives_it(
    material, monkeypatch
):
    content = material.model_dump_json()
    calls = counted_parser(monkeypatch, models.DevelopmentCorpusMaterial)
    ready = asyncio.Event()
    release_child = asyncio.Event()
    child_tasks = []
    states = []

    async def child():
        await release_child.wait()
        module.replay_development_corpus_material(content)
        module.replay_development_corpus_material(content)

    @module.with_development_corpus_replay
    async def owner():
        states.append(module._REPLAY.get())
        module.replay_development_corpus_material(content)
        child_tasks.append(asyncio.create_task(child()))
        ready.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(owner())
    await ready.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not states[0].active and not states[0].materials.entries
    assert states[0].owner is None and states[0].materials.validation_key == ()
    assert module._REPLAY.get() is None
    release_child.set()
    await child_tasks[0]
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_inherited_thread_context_cannot_reuse_the_owner_task_cache(material, monkeypatch):
    content = material.model_dump_json()
    calls = counted_parser(monkeypatch, models.DevelopmentCorpusMaterial)

    def thread():
        assert module._REPLAY.get() is not None
        module.replay_development_corpus_material(content)
        module.replay_development_corpus_material(content)

    with module.development_corpus_replay_scope():
        module.replay_development_corpus_material(content)
        await asyncio.to_thread(thread)
        module.replay_development_corpus_material(content)
    assert len(calls) == 3


@pytest.mark.parametrize("kind", ["material", "manifest"])
@pytest.mark.parametrize("malformed", ["boolean", "unknown", "missing"])
def test_strict_invalid_json_cannot_borrow_a_valid_digest(material, kind, malformed):
    content = (
        material.model_dump_json()
        if kind == "material"
        else material.manifest.model_dump_json().encode()
    )
    replay = getattr(module, "replay_development_corpus_" + kind)
    value = json.loads(content)
    manifest = value["manifest"] if kind == "material" else value
    if malformed == "boolean":
        manifest["total_source_bytes"] = True
    elif malformed == "unknown":
        manifest["undeclared"] = "synthetic"
    else:
        del manifest["sources"]
    changed = json.dumps(value)
    with module.development_corpus_replay_scope():
        original = replay(content)
        with pytest.raises(ValueError):
            replay(changed if kind == "material" else changed.encode())
        assert replay(content) == original


@pytest.mark.parametrize(
    "kind,value",
    [
        ("material", b"{}"),
        ("material", bytearray(b"{}")),
        ("manifest", "{}"),
        ("manifest", bytearray(b"{}")),
    ],
)
def test_mutable_or_wrongly_typed_input_cannot_enter_scope_tables(kind, value):
    with module.development_corpus_replay_scope():
        with pytest.raises(ValueError, match="immutable JSON"):
            getattr(module, "replay_development_corpus_" + kind)(value)
        assert not module._REPLAY.get().materials.entries
        assert not module._REPLAY.get().manifests.entries


def test_validation_binding_change_during_parse_is_refused_and_never_cached(material, monkeypatch):
    content = material.model_dump_json()
    original = models.DevelopmentCorpusMaterial.model_validate_json

    def parse(value, **kwargs):
        result = original(value, **kwargs)
        monkeypatch.setattr(models, "MAX_DEVELOPMENT_CORPUS_BYTES", 1)
        return result

    monkeypatch.setattr(models.DevelopmentCorpusMaterial, "model_validate_json", parse)
    with module.development_corpus_replay_scope():
        with pytest.raises(ValueError, match="validation bindings changed"):
            module.replay_development_corpus_material(content)
        assert not module._REPLAY.get().materials.entries
