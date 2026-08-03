"""Logical source/configuration chunking with stable line hashes."""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from mmaudit.models.schemas import ContextExcerpt, Location


@dataclass(frozen=True)
class ChunkingResult:
    excerpts: tuple[ContextExcerpt, ...]
    omissions: tuple[str, ...]


def line_range_hash(content: str, start_line: int, end_line: int) -> str:
    lines = content.splitlines(keepends=True)
    selected = "".join(lines[start_line - 1 : end_line])
    return hashlib.sha256(selected.encode()).hexdigest()


def excerpt_proves_location(excerpt: ContextExcerpt, location: Location) -> bool:
    """Return whether exact provider-visible excerpt bytes prove one line-range hash."""

    if (
        excerpt.path != location.path
        or excerpt.start_line > location.start_line
        or location.end_line > excerpt.end_line
        or hashlib.sha256(excerpt.content.encode()).hexdigest() != excerpt.content_hash
    ):
        return False
    relative_start = location.start_line - excerpt.start_line
    relative_end = location.end_line - excerpt.start_line + 1
    lines = excerpt.content.splitlines(keepends=True)
    if relative_end > len(lines):
        return False
    observed_hash = hashlib.sha256("".join(lines[relative_start:relative_end]).encode()).hexdigest()
    return observed_hash == location.content_hash


def _make_excerpt(
    path: str,
    lines: list[str],
    start: int,
    end: int,
    categories: tuple[str, ...],
    total_lines: int,
) -> ContextExcerpt:
    content = "".join(lines[start - 1 : end])
    return ContextExcerpt(
        path=path,
        start_line=start,
        end_line=end,
        content_hash=hashlib.sha256(content.encode()).hexdigest(),
        content=content,
        categories=list(categories),
        omitted_before=start > 1,
        omitted_after=end < total_lines,
    )


def _python_ranges(content: str) -> list[tuple[int, int]]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    ranges: list[tuple[int, int]] = []
    imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    if imports:
        ranges.append((imports[0].lineno, imports[-1].end_lineno or imports[-1].lineno))
    for node in tree.body:
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ) or not isinstance(node, (ast.Import, ast.ImportFrom)):
            ranges.append((node.lineno, node.end_lineno or node.lineno))
    return ranges


def _block_ranges(content: str) -> list[tuple[int, int]]:
    lines = content.splitlines(keepends=True)
    ranges: list[tuple[int, int]] = []
    start: int | None = None
    for index, line in enumerate(lines, start=1):
        if line.strip() and start is None:
            start = index
        if not line.strip() and start is not None:
            ranges.append((start, index - 1))
            start = None
    if start is not None:
        ranges.append((start, len(lines)))
    return ranges


def _solidity_ranges(content: str) -> list[tuple[int, int]]:
    lines = content.splitlines(keepends=True)
    ranges: list[tuple[int, int]] = []
    header_start: int | None = None
    header_end: int | None = None
    declaration = re.compile(
        r"^\s*(contract|interface|library|function|modifier|constructor|fallback|receive)\b"
    )
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith(("pragma ", "import ")) or stripped.startswith("// SPDX-"):
            header_start = index if header_start is None else header_start
            header_end = index
    if header_start is not None and header_end is not None:
        ranges.append((header_start, header_end))
    seen: set[tuple[int, int]] = set(ranges)
    for index, line in enumerate(lines, start=1):
        if not declaration.search(line):
            continue
        end = _brace_range_end(lines, index)
        current = (index, end)
        if current not in seen:
            ranges.append(current)
            seen.add(current)
    return sorted(ranges)


def _brace_range_end(lines: list[str], start_line: int) -> int:
    depth = 0
    seen_open = False
    for index in range(start_line, len(lines) + 1):
        stripped = _strip_solidity_comments(lines[index - 1])
        depth += stripped.count("{")
        seen_open = seen_open or "{" in stripped
        depth -= stripped.count("}")
        if seen_open and depth <= 0:
            return index
        if not seen_open and stripped.rstrip().endswith(";"):
            return index
    return start_line


def _strip_solidity_comments(line: str) -> str:
    return line.split("//", 1)[0]


def chunk_text(
    *,
    path: str,
    content: str,
    categories: tuple[str, ...] = (),
    max_chunk_bytes: int = 48_000,
) -> ChunkingResult:
    """Chunk at Python AST nodes or text/configuration block boundaries."""

    lines = content.splitlines(keepends=True)
    if not lines:
        return ChunkingResult(
            excerpts=(
                ContextExcerpt(
                    path=path,
                    start_line=1,
                    end_line=1,
                    content_hash=hashlib.sha256(b"").hexdigest(),
                    content="",
                    categories=categories,
                    omitted_before=False,
                    omitted_after=False,
                ),
            ),
            omissions=(),
        )
    if len(content.encode()) <= max_chunk_bytes:
        return ChunkingResult(
            excerpts=(_make_excerpt(path, lines, 1, len(lines), categories, len(lines)),),
            omissions=(),
        )

    suffix = PurePosixPath(path).suffix.lower()
    if suffix == ".py":
        ranges = _python_ranges(content)
    elif suffix == ".sol":
        ranges = _solidity_ranges(content)
    else:
        ranges = _block_ranges(content)
    excerpts: list[ContextExcerpt] = []
    omissions: list[str] = []
    for start, end in ranges:
        block = "".join(lines[start - 1 : end])
        if len(block.encode()) > max_chunk_bytes:
            omissions.append(
                f"{path}:{start}-{end} omitted because the logical construct exceeds chunk limit"
            )
            continue
        excerpts.append(_make_excerpt(path, lines, start, end, categories, len(lines)))
    if not excerpts and not omissions:
        omissions.append(f"{path}: no complete logical block fit the chunk limit")
    return ChunkingResult(excerpts=tuple(excerpts), omissions=tuple(omissions))
