"""Exact original/compiler byte relations, not semantic equivalence or execution authority."""

from __future__ import annotations

import hashlib
import re
from bisect import bisect_left
from dataclasses import dataclass, field
from typing import Literal, Self

from pydantic import ConfigDict, Field, model_validator

from mmaudit.models.schemas import StrictModel

MAX_COMPILER_SOURCE_BYTES = 100_000_000
MAX_COMPILER_SOURCE_CRLF_PAIRS = 1_000_000
_SHA = r"^[0-9a-f]{64}$"
_MAP_DOMAIN = b"mmaudit.compiler-source-boundaries.CRLF_TO_LF_V1\x00"


class CompilerSourceTransformation(StrictModel):
    """Hash-bound description; the complete original/compiler bytes must reproduce it."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    algorithm: Literal["CRLF_TO_LF_V1"] = "CRLF_TO_LF_V1"
    original_sha256: str = Field(pattern=_SHA)
    compiler_sha256: str = Field(pattern=_SHA)
    original_size_bytes: int = Field(gt=0, le=MAX_COMPILER_SOURCE_BYTES)
    compiler_size_bytes: int = Field(ge=0, le=MAX_COMPILER_SOURCE_BYTES)
    removed_crlf_count: int = Field(gt=0, le=MAX_COMPILER_SOURCE_CRLF_PAIRS)
    boundary_map_sha256: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def exact_size_relation(self) -> Self:
        if (
            self.original_size_bytes - self.compiler_size_bytes != self.removed_crlf_count
            or self.original_sha256 == self.compiler_sha256
        ):
            raise ValueError("compiler source transformation identity or size relation differs")
        return self


class CompilerSourceBuildBinding(StrictModel):
    """A transformed source's exact compiler build and source-unit identity."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    build_info_sha256: str = Field(pattern=_SHA)
    source_id: int = Field(ge=0)
    transformation: CompilerSourceTransformation


@dataclass(frozen=True, slots=True)
class CompilerSourceMap:
    """Map complete compiler spans to original bytes without modifying either input.

    Only identity or removal of every CR immediately preceding LF is recognized.
    A compiler LF maps to the complete original CRLF; boundaries inside that pair
    cannot be projected back into compiler coordinates. Digests grant no authority.
    """

    original: bytes
    compiled: bytes
    transformation: CompilerSourceTransformation | None = field(init=False)
    _removed_compiler_offsets: tuple[int, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.original) is not bytes
            or type(self.compiled) is not bytes
            or len(self.original) > MAX_COMPILER_SOURCE_BYTES
            or len(self.compiled) > MAX_COMPILER_SOURCE_BYTES
        ):
            raise ValueError("compiler source map requires bounded immutable bytes")
        self.original.decode("utf-8", errors="strict")
        self.compiled.decode("utf-8", errors="strict")
        if self.original == self.compiled:
            object.__setattr__(self, "_removed_compiler_offsets", ())
            object.__setattr__(self, "transformation", None)
            return
        count = self.original.count(b"\r\n")
        if count > MAX_COMPILER_SOURCE_CRLF_PAIRS:
            raise ValueError("compiler source map exceeds its transformed-newline bound")
        if not count or self.original.replace(b"\r\n", b"\n") != self.compiled:
            raise ValueError("compiler source bytes contain an unrecognized transformation")
        offsets = tuple(
            match.start() - index for index, match in enumerate(re.finditer(b"\r\n", self.original))
        )
        digest = hashlib.sha256(_MAP_DOMAIN)
        for offset in offsets:
            digest.update(offset.to_bytes(8, "big"))
        transformation = CompilerSourceTransformation(
            original_sha256=hashlib.sha256(self.original).hexdigest(),
            compiler_sha256=hashlib.sha256(self.compiled).hexdigest(),
            original_size_bytes=len(self.original),
            compiler_size_bytes=len(self.compiled),
            removed_crlf_count=len(offsets),
            boundary_map_sha256=digest.hexdigest(),
        )
        object.__setattr__(self, "_removed_compiler_offsets", offsets)
        object.__setattr__(self, "transformation", transformation)

    @staticmethod
    def _validate_span(content: bytes, start: int, end: int) -> None:
        if type(start) is not int or type(end) is not int or not 0 <= start <= end <= len(content):
            raise ValueError("compiler source span exceeds its exact byte bounds")
        if any(
            offset < len(content) and content[offset] & 0b1100_0000 == 0b1000_0000
            for offset in (start, end)
        ):
            raise ValueError("compiler source span splits a UTF-8 boundary")

    def _original_boundary(self, offset: int) -> int:
        return offset + bisect_left(self._removed_compiler_offsets, offset)

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        """Return original half-open byte boundaries for an exact compiler span."""
        self._validate_span(self.compiled, start, end)
        result = self._original_boundary(start), self._original_boundary(end)
        self._validate_span(self.original, *result)
        return result

    def compiled_span(self, start: int, end: int) -> tuple[int, int]:
        """Invert only representable original boundaries; never split a CRLF pair."""
        self._validate_span(self.original, start, end)
        result = []
        for offset in (start, end):
            low, high = 0, len(self.compiled)
            while low < high:
                middle = (low + high) // 2
                if self._original_boundary(middle) < offset:
                    low = middle + 1
                else:
                    high = middle
            if self._original_boundary(low) != offset:
                raise ValueError("original source boundary splits a transformed CRLF pair")
            result.append(low)
        self._validate_span(self.compiled, result[0], result[1])
        return result[0], result[1]
