"""Bounded Kontrol translation and counterexample normalization."""

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

_KONTROL_PROPERTY_PATTERN = re.compile(r"^testKontrol_[0-9a-f]{24}$")
_MAX_COUNTEREXAMPLES = 64


@dataclass(frozen=True)
class KontrolCounterexample:
    """One bounded failed proof and its normalized model."""

    property_name: str
    counterexample: dict[str, Any]


@dataclass(frozen=True)
class KontrolCommandPlan:
    """Validated selectors and bounds used by the fixed Kontrol command."""

    contract: str
    function_pattern: str
    max_depth: int
    max_iterations: int
    workers: int


def translate_kontrol_corpus(
    corpus: PropertyCorpus,
    index: SoliditySymbolIndex,
    *,
    maximum_depth: int,
    maximum_iterations: int,
) -> PropertyEngineTranslation:
    """Translate the shared safe subset into fixed assertion-based proof tests."""

    source_path = _generated_source_path(corpus, index)
    translation = translate_property_corpus(
        corpus,
        index,
        harness_contract_name="MMAuditKontrolProperties",
        property_prefix="testKontrol",
        engine_name="Kontrol",
        generated_source_path=source_path,
        assert_predicates=True,
        uses_campaign_seed=False,
    )
    if not translation.property_map:
        return replace(
            translation,
            configuration_path="mmaudit-kontrol/plan.json",
            property_map_path="mmaudit-kontrol/property-map.json",
        )
    depth = min(translation.depth, maximum_depth)
    iterations = min(translation.runs, maximum_iterations)
    limitations = list(translation.limitations)
    if depth < translation.depth:
        limitations.append(f"Kontrol proof depth was clipped from {translation.depth} to {depth}")
    if iterations < translation.runs:
        limitations.append(
            f"Kontrol proof iterations were clipped from {translation.runs} to {iterations}"
        )
    assumptions = sorted(
        {
            "A bounded Kontrol proof does not establish safety beyond the configured bounds",
            "Only generated assertion tests from the hash-linked property corpus are selected",
            (f"Kontrol explores at most depth {depth} and {iterations} iterations with one worker"),
            "Repository-provided Kontrol command configuration is not executed",
        }
    )
    plan = {
        "contract": "MMAuditKontrolProperties",
        "corpus_hash": corpus.corpus_hash,
        "function_pattern": "testKontrol_.*",
        "source_path": source_path,
        "bounds": {
            "max_depth": depth,
            "max_iterations": iterations,
            "workers": 1,
        },
    }
    return replace(
        translation,
        configuration=json.dumps(plan, sort_keys=True, indent=2) + "\n",
        configuration_path="mmaudit-kontrol/plan.json",
        property_map_path="mmaudit-kontrol/property-map.json",
        limitations=sorted(set(limitations)),
        assumptions=assumptions,
        seed=None,
        runs=iterations,
        depth=depth,
    )


def read_kontrol_plan(path: Path) -> KontrolCommandPlan:
    """Read back the generated plan without accepting repository command fields."""

    if path.stat().st_size > 100_000:
        raise ValueError("generated Kontrol plan exceeds its size bound")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("generated Kontrol plan must be an object")
    bounds = payload.get("bounds")
    if not isinstance(bounds, dict):
        raise ValueError("generated Kontrol plan bounds are missing")
    contract = payload.get("contract")
    function_pattern = payload.get("function_pattern")
    max_depth = _strict_positive_int(bounds.get("max_depth"), maximum=100_000)
    max_iterations = _strict_positive_int(
        bounds.get("max_iterations"),
        maximum=100_000,
    )
    workers = _strict_positive_int(bounds.get("workers"), maximum=1)
    if (
        contract != "MMAuditKontrolProperties"
        or function_pattern != "testKontrol_.*"
        or max_depth is None
        or max_iterations is None
        or workers != 1
    ):
        raise ValueError("generated Kontrol command plan is invalid")
    return KontrolCommandPlan(
        contract=contract,
        function_pattern=function_pattern,
        max_depth=max_depth,
        max_iterations=max_iterations,
        workers=workers,
    )


def parse_kontrol_output(raw: str) -> list[KontrolCounterexample]:
    """Parse bounded JSON or explicit textual failed-proof records."""

    counterexamples: list[KontrolCounterexample] = []
    seen: set[tuple[str, str]] = set()
    for document in _json_documents(raw):
        for item in _walk_dicts(document):
            property_name = _property_name(item)
            status = _status(item)
            if property_name is None or status not in {
                "failed",
                "failure",
                "counterexample",
                "violated",
            }:
                continue
            counterexample = _counterexample(item)
            serialized = json.dumps(counterexample, sort_keys=True, separators=(",", ":"))
            key = (property_name, serialized)
            if key in seen:
                continue
            seen.add(key)
            counterexamples.append(
                KontrolCounterexample(
                    property_name=property_name,
                    counterexample=counterexample,
                )
            )
            if len(counterexamples) >= _MAX_COUNTEREXAMPLES:
                return sorted(counterexamples, key=lambda item: item.property_name)
    if counterexamples:
        return sorted(counterexamples, key=lambda item: item.property_name)

    pattern = re.compile(
        r"(?P<property>testKontrol_[0-9a-f]{24}).{0,500}?"
        r"(?P<status>counterexample|failed|failure|violated)",
        re.IGNORECASE | re.DOTALL,
    )
    for match in pattern.finditer(raw[:2_000_000]):
        property_name = match.group("property")
        if any(item.property_name == property_name for item in counterexamples):
            continue
        counterexamples.append(
            KontrolCounterexample(
                property_name=property_name,
                counterexample={
                    "summary": " ".join(match.group(0).split())[:2_000],
                },
            )
        )
        if len(counterexamples) >= _MAX_COUNTEREXAMPLES:
            break
    return sorted(counterexamples, key=lambda item: item.property_name)


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
            contract = contracts.get(alias)
            if contract is None:
                continue
            try:
                target_paths.add(normalize_relative_path(contract.path))
            except ValueError:
                continue
    if not target_paths:
        return f"test/mmaudit-kontrol/MMAuditKontrol_{corpus.corpus_hash[:12]}.t.sol"
    first_parent = PurePosixPath(sorted(target_paths)[0]).parent
    project_root = first_parent.parent if first_parent.name == "src" else PurePosixPath(".")
    return (
        project_root
        / "test"
        / "mmaudit-kontrol"
        / f"MMAuditKontrol_{corpus.corpus_hash[:12]}.t.sol"
    ).as_posix()


def _json_documents(value: str) -> list[Any]:
    if not value.strip():
        return []
    try:
        return [json.loads(value)]
    except json.JSONDecodeError:
        documents: list[Any] = []
        for line in value.splitlines():
            candidate = line.strip()
            if not candidate or candidate[0] not in "[{":
                continue
            try:
                documents.append(json.loads(candidate))
            except json.JSONDecodeError:
                continue
        return documents


def _walk_dicts(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        found.append(value)
        for child in value.values():
            found.extend(_walk_dicts(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_walk_dicts(child))
    return found


def _property_name(item: dict[str, Any]) -> str | None:
    for key in ("test", "name", "property", "proof"):
        value = item.get(key)
        if not isinstance(value, str):
            continue
        match = re.search(r"\b(testKontrol_[0-9a-f]{24})\b", value)
        if match is not None and _KONTROL_PROPERTY_PATTERN.fullmatch(match.group(1)):
            return match.group(1)
    return None


def _status(item: dict[str, Any]) -> str | None:
    for key in ("status", "result", "outcome"):
        value = item.get(key)
        if isinstance(value, str):
            return value.strip().lower().replace(" ", "_")
    return None


def _counterexample(item: dict[str, Any]) -> dict[str, Any]:
    raw_counterexample = item.get("counterexample")
    normalized = _bounded_json(raw_counterexample) if isinstance(raw_counterexample, dict) else {}
    counterexample = dict(normalized) if isinstance(normalized, dict) else {"model": normalized}
    for source_key, target_key in (
        ("depth", "depth"),
        ("nodes", "nodes"),
        ("iterations", "iterations"),
    ):
        value = item.get(source_key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            counterexample[target_key] = value
    counterexample.setdefault(
        "summary",
        f"Kontrol produced a bounded failed proof for {_property_name(item) or 'property'}",
    )
    return counterexample


def _bounded_json(value: Any, *, depth: int = 0) -> Any:
    if depth >= 8:
        return "<depth-limit>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:2_000]
    if isinstance(value, list):
        return [_bounded_json(item, depth=depth + 1) for item in value[:64]]
    if isinstance(value, dict):
        return {
            str(key)[:200]: _bounded_json(item, depth=depth + 1)
            for key, item in list(sorted(value.items(), key=lambda pair: str(pair[0])))[:64]
            if str(key) not in {"command", "cwd", "query_file"}
        }
    return str(value)[:2_000]


def _strict_positive_int(value: Any, *, maximum: int) -> int | None:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= maximum
        else None
    )
