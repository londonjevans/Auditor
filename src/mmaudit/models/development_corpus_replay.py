"""Invocation-owned, bounded reuse of strict pure parsing; never reuse live input custody."""

from __future__ import annotations

from asyncio import current_task
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Coroutine, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
from threading import get_ident
from typing import Any

from pydantic import BaseModel

from mmaudit.models import development_corpus as corpus
from mmaudit.models.development_corpus import DevelopmentCorpusManifest, DevelopmentCorpusMaterial

# Cacheability bounds, not admission limits. Larger otherwise-valid inputs still strictly parse.
_MAX_REPLAY_MATERIAL_BYTES = corpus.MAX_DEVELOPMENT_CORPUS_RESULT_BYTES
_MAX_REPLAY_MANIFEST_BYTES = corpus.MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES


def _owner() -> tuple[int, object | None]:
    try:
        task = current_task()
    except RuntimeError:  # Ordinary synchronous consumers need no event loop.
        task = None
    return get_ident(), task


def _validation_key(model: type[BaseModel]) -> tuple[object, ...]:
    """Do not retain earlier parser/source-rule bindings or mutable source bounds."""

    return (
        model.__pydantic_validator__,
        model.model_validate_json,
        corpus.validate_development_corpus_sources,
        vars(corpus)["compute_development_dependency_closure"],
        corpus._source_inventory,
        vars(corpus)["detect_secrets"],
        vars(corpus)["is_sensitive_workspace_path"],
        corpus.MAX_DEVELOPMENT_CORPUS_FILES,
        corpus.MAX_DEVELOPMENT_CORPUS_FILE_BYTES,
        corpus.MAX_DEVELOPMENT_CORPUS_LINES,
        corpus.MAX_DEVELOPMENT_CORPUS_BYTES,
        corpus.MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES,
        corpus.MAX_DEVELOPMENT_TREE_ENTRIES,
        corpus.MAX_DEVELOPMENT_TREE_DIRECTORIES,
        corpus.MAX_DEVELOPMENT_TREE_DEPTH,
    )


@dataclass(frozen=True)
class _Entry[T: BaseModel]:
    value: T
    content: str


class _Replay[T: BaseModel]:
    """At most two detached results: the original universe and the current source bundle."""

    def __init__(self, model: type[T]) -> None:
        self.model = model
        self.entries: OrderedDict[str | bytes, _Entry[T]] = OrderedDict()
        self.validation_key = _validation_key(model)

    def parse(self, content: str | bytes, *, maximum_bytes: int) -> T:
        key = _validation_key(self.model)
        if key != self.validation_key:
            self.entries.clear()
            self.validation_key = key
        size = len(content.encode("utf-8")) if isinstance(content, str) else len(content)
        if size > maximum_bytes:
            return self.model.model_validate_json(content, strict=True)
        if content in self.entries:
            entry = self.entries[content]
            if (
                type(entry.value) is not self.model
                or entry.value.model_dump_json() != entry.content
            ):
                raise ValueError("development corpus cached pure result changed during replay")
            self.entries.move_to_end(content)
            # A caller must never obtain the private object retained across later guards.
            return entry.value.model_copy(deep=True)
        if len(self.entries) >= 2:
            self.entries.popitem(last=False)
        value = self.model.model_validate_json(content, strict=True)
        if key != _validation_key(self.model):
            raise ValueError("development corpus pure validation bindings changed during replay")
        serialized = value.model_dump_json()
        if len(serialized.encode("utf-8")) <= maximum_bytes:
            self.entries[content] = _Entry(value.model_copy(deep=True), serialized)
        return value


class _InvocationReplay:
    def __init__(self) -> None:
        self.owner: tuple[int, object | None] | None = _owner()
        self.active = True
        self.materials = _Replay(DevelopmentCorpusMaterial)
        self.manifests = _Replay(DevelopmentCorpusManifest)

    def close(self) -> None:
        self.active = False
        self.owner = None
        self.materials.entries.clear()
        self.manifests.entries.clear()
        self.materials.validation_key = self.manifests.validation_key = ()


_REPLAY: ContextVar[_InvocationReplay | None] = ContextVar(
    "development_corpus_replay", default=None
)


@contextmanager
def development_corpus_replay_scope() -> Iterator[None]:
    """Own pure results until exit; nested/concurrent tasks and threads cannot inherit reuse.

    Every call site still observes its original file/source/root/namespace/recipe guards.
    This context carries no policy, route, ledger or execution permission. Cancellation and
    exceptions clear the tables; an inherited context cannot prolong the owner's cache lifetime.
    """

    state = _InvocationReplay()
    token = _REPLAY.set(state)
    try:
        yield
    finally:
        state.close()
        _REPLAY.reset(token)


def with_development_corpus_replay[**P, T](
    function: Callable[P, Awaitable[T]],
) -> Callable[P, Coroutine[Any, Any, T]]:
    """Keep the scope around the awaited invocation, including every exceptional exit."""

    @wraps(function)
    async def invoke(*args: P.args, **kwargs: P.kwargs) -> T:
        with development_corpus_replay_scope():
            return await function(*args, **kwargs)

    return invoke


def _current_replay() -> _InvocationReplay | None:
    state = _REPLAY.get()
    return state if state is not None and state.active and state.owner == _owner() else None


def replay_development_corpus_material(content: str) -> DevelopmentCorpusMaterial:
    """Strictly replay exact material text; ordinary consumers have no persistent reuse."""

    if type(content) is not str:
        raise ValueError("development corpus material replay requires immutable JSON text")
    state = _current_replay()
    if state is None:
        return DevelopmentCorpusMaterial.model_validate_json(content, strict=True)
    return state.materials.parse(content, maximum_bytes=_MAX_REPLAY_MATERIAL_BYTES)


def replay_development_corpus_manifest(content: bytes) -> DevelopmentCorpusManifest:
    """Strictly replay freshly read immutable bytes, never a manifest-file observation."""

    if type(content) is not bytes:
        raise ValueError("development corpus manifest replay requires immutable JSON bytes")
    state = _current_replay()
    if state is None:
        return DevelopmentCorpusManifest.model_validate_json(content, strict=True)
    return state.manifests.parse(content, maximum_bytes=_MAX_REPLAY_MANIFEST_BYTES)
