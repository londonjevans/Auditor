"""Bounded Halmos translation and machine-result normalization."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any

from mmaudit.models.schemas import PropertyCorpus, SolidityEntityKind, SoliditySymbolIndex
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.solidity.engines.echidna import (
    PropertyEngineTranslation,
    translate_property_corpus,
)

_HALMOS_PROPERTY_PATTERN = re.compile(r"^(?:check|invariant)_[A-Za-z0-9_]+$")
_MAX_SOURCE_INSPECTION_BYTES = 2_000_000
_MAX_COUNTEREXAMPLES = 64
_MAX_MODELS = 16


@dataclass(frozen=True)
class HalmosCounterexample:
    """One bounded symbolic counterexample from Halmos JSON output."""

    property_name: str
    counterexample: dict[str, Any]


def translate_halmos_corpus(
    corpus: PropertyCorpus,
    index: SoliditySymbolIndex,
    *,
    timeout_seconds: float,
    maximum_invariant_depth: int,
    loop_bound: int,
    maximum_width: int,
    maximum_path_depth: int,
    solver_timeout_seconds: float,
    solver_max_memory_mb: int,
) -> PropertyEngineTranslation:
    """Translate the shared safe subset into assertion-based Halmos invariants."""

    source_path = _generated_source_path(corpus, index)
    translation = translate_property_corpus(
        corpus,
        index,
        harness_contract_name="MMAuditHalmosProperties",
        property_prefix="invariant",
        engine_name="Halmos",
        generated_source_path=source_path,
        assert_predicates=True,
        uses_campaign_seed=False,
    )
    if not translation.property_map:
        return replace(
            translation,
            configuration_path="mmaudit-halmos/plan.json",
            property_map_path="mmaudit-halmos/property-map.json",
        )

    invariant_depth = min(translation.depth, maximum_invariant_depth)
    width = min(translation.runs, maximum_width)
    limitations = list(translation.limitations)
    if invariant_depth < translation.depth:
        limitations.append(
            "Halmos invariant depth was clipped from "
            f"{translation.depth} to the configured cap {invariant_depth}"
        )
    if width < translation.runs:
        limitations.append(f"Halmos path width was clipped from {translation.runs} to {width}")
    assumptions = sorted(
        {
            "A bounded symbolic pass does not establish an unbounded safety proof",
            "FFI and repository-provided Halmos option annotations are not permitted",
            (
                "Halmos explores the generated local deployment under invariant depth "
                f"{invariant_depth}, loop bound {loop_bound}, path width {width}, "
                f"and path depth {maximum_path_depth}"
            ),
            (
                "Solver queries are bounded by "
                f"{solver_timeout_seconds:g} seconds, {solver_max_memory_mb} MiB, "
                "and one solver thread"
            ),
        }
    )
    plan = {
        "contract": "MMAuditHalmosProperties",
        "corpus_hash": corpus.corpus_hash,
        "function_prefix": "invariant_",
        "source_path": source_path,
        "bounds": {
            "invariant_depth": invariant_depth,
            "loop": loop_bound,
            "path_depth": maximum_path_depth,
            "solver_max_memory_mb": solver_max_memory_mb,
            "solver_timeout_seconds": solver_timeout_seconds,
            "timeout_seconds": timeout_seconds,
            "width": width,
        },
        "solver": "z3",
    }
    return replace(
        translation,
        configuration=json.dumps(plan, sort_keys=True, indent=2) + "\n",
        configuration_path="mmaudit-halmos/plan.json",
        property_map_path="mmaudit-halmos/property-map.json",
        limitations=sorted(set(limitations)),
        assumptions=assumptions,
        seed=None,
        runs=width,
        depth=invariant_depth,
    )


def untrusted_halmos_annotation_limitations(
    workspace: Path,
    index: SoliditySymbolIndex,
) -> list[str]:
    """Reject source annotations that could override trusted command-line policy."""

    limitations: list[str] = []
    source_paths: set[str] = set()
    for entity in index.entities:
        if not entity.path.endswith(".sol"):
            continue
        try:
            source_paths.add(normalize_relative_path(entity.path))
        except ValueError:
            limitations.append(
                f"{entity.path[:200]}: unsafe source path cannot be validated for Halmos"
            )
    for relative in sorted(source_paths):
        path = workspace / relative
        try:
            size = path.stat().st_size
            if size > _MAX_SOURCE_INSPECTION_BYTES:
                limitations.append(
                    f"{relative}: source is too large for Halmos option-annotation validation"
                )
                continue
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            limitations.append(
                f"{relative}: source could not be validated for Halmos option annotations"
            )
            continue
        if "@custom:halmos" in source.casefold():
            limitations.append(
                f"{relative}: repository-provided Halmos option annotations are unsupported"
            )
    return sorted(set(limitations))


def parse_halmos_json(raw: str) -> list[HalmosCounterexample]:
    """Parse bounded counterexample records from Halmos's result artifact."""

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []
    test_results = payload.get("test_results")
    if not isinstance(test_results, dict):
        return []

    counterexamples: list[HalmosCounterexample] = []
    for contract_key in sorted(test_results):
        results = test_results[contract_key]
        if not isinstance(results, list):
            continue
        for result in results:
            if len(counterexamples) >= _MAX_COUNTEREXAMPLES:
                return counterexamples
            if not isinstance(result, dict) or _strict_int(result.get("exitcode")) != 1:
                continue
            raw_name = result.get("name")
            if not isinstance(raw_name, str):
                continue
            property_name = raw_name.split("(", 1)[0]
            if _HALMOS_PROPERTY_PATTERN.fullmatch(property_name) is None:
                continue
            models = result.get("models")
            normalized_models = (
                [_normalize_solver_model(model) for model in models[:_MAX_MODELS]]
                if isinstance(models, list)
                else []
            )
            num_models = _strict_int(result.get("num_models"))
            summary = (
                f"Halmos produced {num_models if num_models is not None else len(normalized_models)} "
                f"counterexample model(s) for {property_name}"
            )
            counterexample: dict[str, Any] = {
                "summary": summary,
                "exitcode": 1,
                "models": normalized_models,
            }
            for source_key, target_key in (
                ("num_models", "num_models"),
                ("num_paths", "path_counts"),
                ("time", "timing"),
                ("num_bounded_loops", "bounded_loops"),
            ):
                value = result.get(source_key)
                if value is not None:
                    counterexample[target_key] = _bounded_json_value(value)
            counterexamples.append(
                HalmosCounterexample(
                    property_name=property_name,
                    counterexample=counterexample,
                )
            )
    return counterexamples


def _generated_source_path(
    corpus: PropertyCorpus,
    index: SoliditySymbolIndex,
) -> str:
    contracts = {
        entity.name: entity
        for entity in index.entities
        if entity.kind is SolidityEntityKind.CONTRACT
    }
    target_paths: set[str] = set()
    for property_spec in corpus.properties:
        for alias in property_spec.target_aliases:
            if alias not in contracts:
                continue
            try:
                target_paths.add(normalize_relative_path(contracts[alias].path))
            except ValueError:
                continue
    ordered_target_paths = sorted(target_paths)
    if not ordered_target_paths:
        return f"mmaudit-halmos/MMAuditHalmos_{corpus.corpus_hash[:12]}.sol"
    parent = PurePosixPath(ordered_target_paths[0]).parent
    return (parent / f"MMAuditHalmos_{corpus.corpus_hash[:12]}.sol").as_posix()


def _strict_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _normalize_solver_model(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"model": _bounded_json_value(value)}
    normalized: dict[str, Any] = {}
    for key in ("result", "returncode", "path_id", "model"):
        if key in value:
            normalized[key] = _bounded_json_value(value[key])
    return normalized


def _bounded_json_value(value: Any, *, depth: int = 0) -> Any:
    if depth >= 6:
        return "<depth limit>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:1_000]
    if isinstance(value, list):
        return [_bounded_json_value(item, depth=depth + 1) for item in value[:64]]
    if isinstance(value, dict):
        return {
            str(key)[:200]: _bounded_json_value(value[key], depth=depth + 1)
            for key in sorted(value, key=lambda item: str(item))[:64]
        }
    return f"<unsupported {type(value).__name__}>"
