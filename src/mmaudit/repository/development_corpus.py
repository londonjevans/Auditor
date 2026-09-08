"""Read only explicit local manifest members; never discover, download or execute source."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mmaudit.models.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_FILE_BYTES,
    MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES,
    DevelopmentCorpusManifest,
    DevelopmentCorpusMaterial,
    DevelopmentCorpusText,
)
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release_io import (
    read_file_evidence,
    read_json_evidence,
    revalidate_evidence_file_binding,
)
from mmaudit.repository.directory_custody import (
    DirectoryCustodyObservation,
    observe_unlinked_directory,
    require_same_unlinked_directory_objects,
)


@dataclass(frozen=True)
class LoadedDevelopmentCorpus:
    material: DevelopmentCorpusMaterial
    corpus_root: Path
    manifest_file: Path
    manifest_binding: ManifestFileBinding
    source_bindings: tuple[ManifestFileBinding, ...]
    corpus_custody: DirectoryCustodyObservation


def load_development_corpus(*, manifest_file: Path, corpus_root: Path) -> LoadedDevelopmentCorpus:
    """Capture a selected snapshot with exact bytes; declared public/synthetic labels grant no authority."""

    if any(not p.is_absolute() or ".." in p.parts for p in (manifest_file, corpus_root)):
        raise ValueError("development corpus input paths must be absolute and normalized")
    custody = observe_unlinked_directory(corpus_root, label="development corpus source root")
    manifest_input = read_json_evidence(
        evidence_root=manifest_file.parent,
        relative_path=manifest_file.name,
        max_bytes=MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES,
    )
    manifest = DevelopmentCorpusManifest.model_validate_json(manifest_input.content, strict=True)
    sources = tuple(
        read_file_evidence(
            evidence_root=corpus_root,
            relative_path=s.filename,
            max_bytes=MAX_DEVELOPMENT_CORPUS_FILE_BYTES,
        )
        for s in manifest.sources
    )
    material = DevelopmentCorpusMaterial(
        manifest=manifest,
        sources=tuple(
            DevelopmentCorpusText(
                filename=s.filename,
                content=raw.content.decode("utf-8", errors="strict"),
            )
            for s, raw in zip(manifest.sources, sources, strict=True)
        ),
    )
    result = LoadedDevelopmentCorpus(
        material,
        corpus_root,
        manifest_file,
        manifest_input.binding,
        tuple(s.binding for s in sources),
        custody,
    )
    revalidate_loaded_development_corpus(result)
    return result


def revalidate_loaded_development_corpus(loaded: LoadedDevelopmentCorpus) -> None:
    """Recheck all selected bytes and root custody before CLI handoff; never read omitted files."""

    if (
        type(loaded) is not LoadedDevelopmentCorpus
        or type(loaded.material) is not DevelopmentCorpusMaterial
    ):
        raise ValueError("development corpus handoff requires exact loaded input types")
    material = DevelopmentCorpusMaterial.model_validate_json(
        loaded.material.model_dump_json(), strict=True
    )
    if loaded.manifest_binding.path != loaded.manifest_file.name or tuple(
        (b.path, b.sha256, b.size) for b in loaded.source_bindings
    ) != tuple((s.filename, s.sha256, s.size) for s in material.manifest.sources):
        raise ValueError("development corpus handoff changed selected source bindings")
    require_same_unlinked_directory_objects(
        loaded.corpus_custody, label="development corpus source root"
    )
    manifest_input = read_json_evidence(
        evidence_root=loaded.manifest_file.parent,
        relative_path=loaded.manifest_file.name,
        max_bytes=MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES,
    )
    if (
        manifest_input.binding != loaded.manifest_binding
        or DevelopmentCorpusManifest.model_validate_json(manifest_input.content, strict=True)
        != material.manifest
    ):
        raise ValueError("development corpus material differs from the selected manifest file")
    for binding in loaded.source_bindings:
        revalidate_evidence_file_binding(
            evidence_root=loaded.corpus_root,
            binding=binding,
            max_bytes=MAX_DEVELOPMENT_CORPUS_FILE_BYTES,
        )
