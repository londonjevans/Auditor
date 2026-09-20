"""Bounded exhaustive local Solidity enumeration; no exclusions, fetches or execution."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from mmaudit.models.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_BYTES,
    MAX_DEVELOPMENT_CORPUS_FILE_BYTES,
    MAX_DEVELOPMENT_CORPUS_FILES,
    MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES,
    MAX_DEVELOPMENT_TREE_DIRECTORIES,
    MAX_DEVELOPMENT_TREE_ENTRIES,
    DevelopmentCorpusManifest,
    DevelopmentCorpusMaterial,
    DevelopmentCorpusScope,
    DevelopmentCorpusSource,
    DevelopmentCorpusText,
    DevelopmentCorpusTreeDirectory,
    DevelopmentCorpusTreeEvidence,
    _source_inventory,
    _source_path,
    freeze_development_corpus,
)
from mmaudit.models.development_corpus_replay import (
    replay_development_corpus_manifest,
    replay_development_corpus_material,
)
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release_io import (
    _is_link_or_reparse,
    _open_parent,
    _open_root,
    _stat_identity,
    read_file_evidence,
    revalidate_evidence_file_bindings,
    write_json_evidence,
)
from mmaudit.repository.directory_custody import (
    DirectoryCustodyObservation,
    observe_unlinked_directory,
    prepare_owned_empty_directory,
    require_same_unlinked_directory_objects,
)
from mmaudit.repository.secrets import is_sensitive_workspace_path
from mmaudit.solidity.dependency_closure import MAX_DEPENDENCY_REMAPPING_BYTES

type _NodeIdentity = tuple[int, int, int, int, int, int, int]


@dataclass(frozen=True)
class DevelopmentCorpusTreeObservation:
    """Same-process namespace/object continuity; no absolute path is serialized in evidence."""

    root: Path
    sources: tuple[str, ...]
    directories: tuple[DevelopmentCorpusTreeDirectory, ...]
    non_source_file_count: int
    node_identities: tuple[tuple[str, _NodeIdentity], ...]
    root_custody: DirectoryCustodyObservation = field(compare=False)


def _observe_namespace_once(corpus_root: Path) -> DevelopmentCorpusTreeObservation:
    if (
        not corpus_root.is_absolute()
        or ".." in corpus_root.parts
        or is_sensitive_workspace_path(corpus_root, is_dir=True)
        or os.scandir not in os.supports_fd
    ):
        raise ValueError("development tree requires an absolute descriptor-safe local root")
    custody = observe_unlinked_directory(corpus_root, label="development tree root")
    root = _open_root(corpus_root)
    pending = ["."]
    directories: list[DevelopmentCorpusTreeDirectory] = []
    sources: list[str] = []
    identities: list[tuple[str, _NodeIdentity]] = []
    entry_count = non_sources = source_bytes = 0
    try:
        while pending:
            directory = pending.pop()
            descriptor, _ = _open_parent(
                root,
                "__directory_probe__" if directory == "." else directory + "/__directory_probe__",
            )
            try:
                before = os.fstat(descriptor)
                if before.st_dev != root.identity[0]:
                    raise ValueError("development tree may not cross filesystem mounts")
                identities.append((directory, _stat_identity(before)))
                rows: list[tuple[str, str]] = []
                names: set[str] = set()
                with os.scandir(descriptor) as entries:
                    for entry in entries:
                        entry_count += 1
                        if entry_count > MAX_DEVELOPMENT_TREE_ENTRIES:
                            raise ValueError("complete development tree exceeds its entry ceiling")
                        if entry.name.casefold() in names:
                            raise ValueError(
                                "development tree has case-colliding namespace entries"
                            )
                        names.add(entry.name.casefold())
                        path = entry.name if directory == "." else directory + "/" + entry.name
                        if len(path) > 512:
                            raise ValueError("complete development tree exceeds its path ceiling")
                        metadata = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
                        if _is_link_or_reparse(metadata) or metadata.st_dev != root.identity[0]:
                            raise ValueError(
                                "development tree refuses links or cross-mount entries"
                            )
                        if stat.S_ISDIR(metadata.st_mode):
                            # Validate before opening: control-plane directories are never entered.
                            DevelopmentCorpusTreeDirectory(
                                path=path, entry_count=0, entries_sha256="0" * 64
                            )
                            rows.append((entry.name, "DIRECTORY"))
                            pending.append(path)
                            if (
                                len(pending) + len(directories) + 1
                                > MAX_DEVELOPMENT_TREE_DIRECTORIES
                            ):
                                raise ValueError(
                                    "complete development tree exceeds its directory ceiling"
                                )
                        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                            identities.append((path, _stat_identity(metadata)))
                            rows.append((entry.name, "REGULAR_FILE"))
                            if entry.name.casefold().endswith(".sol"):
                                _source_path(path)
                                sources.append(path)
                                source_bytes += metadata.st_size
                                if (
                                    not 0 < metadata.st_size <= MAX_DEVELOPMENT_CORPUS_FILE_BYTES
                                    or source_bytes > MAX_DEVELOPMENT_CORPUS_BYTES
                                    or len(sources) > MAX_DEVELOPMENT_CORPUS_FILES
                                ):
                                    raise ValueError(
                                        "complete development tree exceeds source bounds"
                                    )
                            else:
                                non_sources += 1
                        else:
                            raise ValueError(
                                "development tree refuses shared or non-regular entries"
                            )
                if _stat_identity(os.fstat(descriptor)) != _stat_identity(before):
                    raise ValueError("development tree directory changed during enumeration")
                directories.append(
                    DevelopmentCorpusTreeDirectory(
                        path=directory,
                        entry_count=len(rows),
                        entries_sha256=canonical_sha256(sorted(rows)),
                    )
                )
            finally:
                os.close(descriptor)
    except OSError as exc:
        raise ValueError("development tree cannot enumerate every entry safely") from exc
    finally:
        os.close(root.descriptor)
    if not sources:
        raise ValueError("development tree contains no admissible Solidity sources")
    require_same_unlinked_directory_objects(custody, label="development tree root")
    return DevelopmentCorpusTreeObservation(
        corpus_root,
        tuple(sorted(sources)),
        tuple(sorted(directories, key=lambda item: item.path)),
        non_sources,
        tuple(sorted(identities)),
        custody,
    )


def observe_development_corpus_tree(corpus_root: Path) -> DevelopmentCorpusTreeObservation:
    """Two complete observations must agree, including every file/directory object and timestamp."""

    first = _observe_namespace_once(corpus_root)
    second = _observe_namespace_once(corpus_root)
    require_same_unlinked_directory_objects(first.root_custody, label="development tree root")
    if first != second:
        raise ValueError("complete development tree changed between namespace observations")
    return second


def development_corpus_tree_evidence(
    observation: DevelopmentCorpusTreeObservation,
    sources: tuple[DevelopmentCorpusSource, ...],
) -> DevelopmentCorpusTreeEvidence:
    """Bind an observation to exact selected bytes; loading must still replay the actual root."""

    if type(observation) is not DevelopmentCorpusTreeObservation or observation.sources != tuple(
        source.filename for source in sources
    ):
        raise ValueError("development tree and selected source membership differ")
    provisional = DevelopmentCorpusTreeEvidence.model_construct(
        source_inventory_sha256=canonical_sha256([s.model_dump(mode="json") for s in sources]),
        solidity_file_count=len(sources),
        non_source_file_count=observation.non_source_file_count,
        directories=observation.directories,
        tree_sha256="0" * 64,
    )
    return DevelopmentCorpusTreeEvidence.model_validate(
        {
            **provisional.model_dump(mode="python"),
            "tree_sha256": canonical_sha256(
                provisional.model_dump(mode="json", exclude={"tree_sha256"})
            ),
        }
    )


def revalidate_development_corpus_tree(
    observation: DevelopmentCorpusTreeObservation,
    manifest: DevelopmentCorpusManifest,
) -> None:
    """Reject omitted/added/replaced scope even when all previously selected source bytes match."""

    if type(observation) is not DevelopmentCorpusTreeObservation:
        raise ValueError("development tree handoff requires its exact observation type")
    require_same_unlinked_directory_objects(observation.root_custody, label="development tree root")
    current = observe_development_corpus_tree(observation.root)
    if current != observation or development_corpus_tree_evidence(current, manifest.sources) != (
        manifest.source_tree_evidence
    ):
        raise ValueError("complete development tree custody or recorded namespace differs")


@dataclass(frozen=True)
class CapturedDevelopmentCorpusTree:
    material: DevelopmentCorpusMaterial
    observation: DevelopmentCorpusTreeObservation
    source_bindings: tuple[ManifestFileBinding, ...]
    remappings_file: Path
    remappings_binding: ManifestFileBinding


def capture_development_corpus_tree(
    *,
    corpus_root: Path,
    remappings_file: Path,
    corpus_id: str,
    source_scope: DevelopmentCorpusScope,
    dependency_scoped_context: bool = False,
    dependency_call_context: bool = False,
    dependency_syntax_context: bool = False,
    dependency_modifier_context: bool = False,
    dependency_constructor_context: bool = False,
    dependency_static_closure: bool = False,
    dependency_graph_byte_limit: int | None = None,
    primary_filenames: tuple[str, ...] | None = None,
) -> CapturedDevelopmentCorpusTree:
    """Capture all selected-root Solidity source under existing bounds; never inspect secrets."""

    if type(dependency_scoped_context) is not bool:
        raise ValueError("scoped tree context requires an explicit boolean")
    if type(dependency_static_closure) is not bool or (
        dependency_static_closure and not dependency_constructor_context
    ):
        raise ValueError("static closure requires an explicit boolean and constructor context")
    if type(dependency_constructor_context) is not bool or (
        dependency_constructor_context and not dependency_modifier_context
    ):
        raise ValueError("constructor context requires an explicit boolean and modifier context")
    if type(dependency_modifier_context) is not bool or (
        dependency_modifier_context and not dependency_syntax_context
    ):
        raise ValueError("modifier context requires an explicit boolean and syntax context")
    if type(dependency_syntax_context) is not bool or (
        dependency_syntax_context and not dependency_call_context
    ):
        raise ValueError("syntax context requires an explicit boolean and typed call context")
    if type(dependency_call_context) is not bool or (
        dependency_call_context and not dependency_scoped_context
    ):
        raise ValueError("typed tree context requires an explicit boolean and scoped context")
    if (
        source_scope
        not in {
            "OPERATOR_SUPPLIED_SYNTHETIC",
            "OPERATOR_SUPPLIED_PUBLIC",
            "OPERATOR_SUPPLIED_PROTOCOL",
        }
        or not remappings_file.is_absolute()
        or ".." in remappings_file.parts
        or is_sensitive_workspace_path(remappings_file)
    ):
        raise ValueError("development remappings input is not a safe explicit path")
    remappings = read_file_evidence(
        evidence_root=remappings_file.parent,
        relative_path=remappings_file.name,
        max_bytes=MAX_DEPENDENCY_REMAPPING_BYTES,
    )
    observation = observe_development_corpus_tree(corpus_root)
    inputs = tuple(
        read_file_evidence(
            evidence_root=corpus_root,
            relative_path=path,
            max_bytes=MAX_DEVELOPMENT_CORPUS_FILE_BYTES,
        )
        for path in observation.sources
    )
    source_files = tuple((item.binding.path, item.content) for item in inputs)
    sources = _source_inventory(source_files)
    manifest = freeze_development_corpus(
        corpus_id=corpus_id,
        source_scope=source_scope,
        source_files=source_files,
        dependency_remapping_text=remappings.content.decode("utf-8", errors="strict"),
        dependency_target_context=True,
        dependency_scoped_context=dependency_scoped_context,
        dependency_call_context=dependency_call_context,
        dependency_syntax_context=dependency_syntax_context,
        dependency_modifier_context=dependency_modifier_context,
        dependency_constructor_context=dependency_constructor_context,
        dependency_static_closure=dependency_static_closure,
        dependency_graph_byte_limit=dependency_graph_byte_limit,
        source_tree_evidence=development_corpus_tree_evidence(observation, sources),
        primary_filenames=primary_filenames,
    )
    result = CapturedDevelopmentCorpusTree(
        DevelopmentCorpusMaterial(
            manifest=manifest,
            sources=tuple(
                DevelopmentCorpusText(filename=path, content=raw.decode("utf-8", errors="strict"))
                for path, raw in source_files
            ),
        ),
        observation,
        tuple(item.binding for item in inputs),
        remappings_file,
        remappings.binding,
    )
    revalidate_captured_development_corpus_tree(result)
    return result


def revalidate_captured_development_corpus_tree(captured: CapturedDevelopmentCorpusTree) -> None:
    if (
        type(captured) is not CapturedDevelopmentCorpusTree
        or type(captured.material) is not DevelopmentCorpusMaterial
    ):
        raise ValueError("development tree handoff requires the exact captured type")
    material = replay_development_corpus_material(captured.material.model_dump_json())
    manifest = material.manifest
    if tuple((b.path, b.sha256, b.size) for b in captured.source_bindings) != tuple(
        (s.filename, s.sha256, s.size) for s in manifest.sources
    ):
        raise ValueError("development tree source bindings differ from retained bytes")
    revalidate_development_corpus_tree(captured.observation, manifest)
    revalidate_evidence_file_bindings(
        evidence_root=captured.observation.root,
        bindings=captured.source_bindings,
        max_bytes=MAX_DEVELOPMENT_CORPUS_FILE_BYTES,
    )
    if captured.remappings_binding.path != captured.remappings_file.name:
        raise ValueError("development tree remapping binding changed")
    remappings = read_file_evidence(
        evidence_root=captured.remappings_file.parent,
        relative_path=captured.remappings_file.name,
        max_bytes=MAX_DEPENDENCY_REMAPPING_BYTES,
    )
    if (
        remappings.binding != captured.remappings_binding
        or manifest.dependency_evidence is None
        or remappings.content.decode("utf-8", errors="strict")
        != manifest.dependency_evidence.remapping_text
    ):
        raise ValueError("development tree remapping input changed")
    revalidate_development_corpus_tree(captured.observation, manifest)


def freeze_development_corpus_tree(
    *,
    corpus_root: Path,
    remappings_file: Path,
    corpus_id: str,
    source_scope: DevelopmentCorpusScope,
    output_dir: Path,
    dependency_scoped_context: bool = False,
    dependency_call_context: bool = False,
    dependency_syntax_context: bool = False,
    dependency_modifier_context: bool = False,
    dependency_constructor_context: bool = False,
    dependency_static_closure: bool = False,
    primary_filenames: tuple[str, ...] | None = None,
) -> DevelopmentCorpusManifest:
    """Write one fresh manifest only after complete local capture; this is not a provider command."""

    inputs = (corpus_root, remappings_file)
    if (
        any(not p.is_absolute() or ".." in p.parts for p in (*inputs, output_dir))
        or output_dir.is_relative_to(corpus_root)
        or any(p.is_relative_to(output_dir) for p in inputs)
    ):
        raise ValueError("development tree output overlaps input or is not absolute")
    captured = capture_development_corpus_tree(
        corpus_root=corpus_root,
        remappings_file=remappings_file,
        corpus_id=corpus_id,
        source_scope=source_scope,
        dependency_scoped_context=dependency_scoped_context,
        dependency_call_context=dependency_call_context,
        dependency_syntax_context=dependency_syntax_context,
        dependency_modifier_context=dependency_modifier_context,
        dependency_constructor_context=dependency_constructor_context,
        dependency_static_closure=dependency_static_closure,
        primary_filenames=primary_filenames,
    )
    output_custody = prepare_owned_empty_directory(output_dir, label="development tree output")

    def validate(content: bytes) -> None:
        if replay_development_corpus_manifest(content) != captured.material.manifest:
            raise ValueError("development tree output differs from captured material")
        revalidate_captured_development_corpus_tree(captured)
        require_same_unlinked_directory_objects(output_custody, label="development tree output")

    write_json_evidence(
        evidence_root=output_dir,
        relative_path="manifest.json",
        value=captured.material.manifest,
        max_bytes=MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES,
        validate_content=validate,
        require_private_parent=True,
    )
    revalidate_captured_development_corpus_tree(captured)
    require_same_unlinked_directory_objects(output_custody, label="development tree output")
    return captured.material.manifest
