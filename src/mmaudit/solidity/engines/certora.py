"""Configured Certora plan generation and bounded result normalization."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from mmaudit.config import CertoraConfig
from mmaudit.models.schemas import (
    DynamicPropertySpec,
    SolidityEntityKind,
    SoliditySymbolIndex,
)
from mmaudit.repository.ignore import normalize_relative_path

_MAX_CERTORA_INPUT_BYTES = 5_000_000


@dataclass(frozen=True)
class CertoraPreparation:
    """Generated, hash-linked operator configuration for one Certora run."""

    property_map: dict[str, DynamicPropertySpec] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    seed: int | None = None
    runs: int = 0
    depth: int = 0
    execution_ready: bool = False
    specification_artifacts: list[str] = field(default_factory=list)
    assumption_artifacts: list[str] = field(default_factory=list)
    vacuity_artifacts: list[str] = field(default_factory=list)
    vacuity_checks: int = 0


@dataclass(frozen=True)
class CertoraRuleResult:
    """One bounded rule outcome parsed from configured machine output."""

    rule: str
    status: str
    assumptions: list[str]
    vacuity_status: str | None
    counterexample: dict[str, Any]
    path: str | None
    line: int | None

    @property
    def is_counterexample(self) -> bool:
        return self.status in {"counterexample", "failed", "violated"}

    @property
    def is_proof(self) -> bool:
        return self.status in {"passed", "proved", "verified"}

    @property
    def is_non_vacuous(self) -> bool:
        return self.vacuity_status in {
            "non_vacuous",
            "non-vacuous",
            "not_vacuous",
            "passed",
            "verified",
        }


def prepare_certora_workspace(
    *,
    workspace: Path,
    index: SoliditySymbolIndex,
    config: CertoraConfig,
) -> CertoraPreparation:
    """Validate operator-selected inputs and emit separate review artifacts."""

    if not config.enabled:
        return CertoraPreparation(limitations=["Certora execution was not explicitly enabled"])
    assert config.source is not None
    assert config.specification is not None
    assert config.contract is not None
    try:
        source = _safe_input_file(workspace, config.source, suffix=".sol")
        specification = _safe_input_file(
            workspace,
            config.specification,
            suffix=".spec",
        )
    except (OSError, ValueError) as exc:
        return CertoraPreparation(
            limitations=[
                f"configured Certora input rejected: {type(exc).__name__}",
            ]
        )
    contract = next(
        (
            entity
            for entity in index.entities
            if entity.kind is SolidityEntityKind.CONTRACT
            and entity.name == config.contract
            and entity.path == config.source
        ),
        None,
    )
    if contract is None:
        return CertoraPreparation(
            limitations=[
                "configured Certora contract and source do not match the validated symbol index"
            ]
        )

    generated = workspace / "mmaudit-certora"
    generated.mkdir(parents=True, exist_ok=False, mode=0o700)
    specification_artifact = generated / "specification-plan.json"
    assumption_artifact = generated / "assumptions.json"
    vacuity_artifact = generated / "vacuity-plan.json"
    assumptions = sorted(set(config.assumptions))
    specification_payload = {
        "contract": config.contract,
        "rule": config.rule,
        "source": config.source,
        "source_sha256": _file_sha256(source),
        "specification": config.specification,
        "specification_sha256": _file_sha256(specification),
    }
    assumption_payload = {
        "assumptions": assumptions,
        "count": len(assumptions),
    }
    vacuity_payload = {
        "mode": config.vacuity_check,
        "required": True,
        "rule": config.rule,
    }
    _write_json(specification_artifact, specification_payload)
    _write_json(assumption_artifact, assumption_payload)
    _write_json(vacuity_artifact, vacuity_payload)
    return CertoraPreparation(
        assumptions=assumptions,
        limitations=[
            "real Certora service execution requires explicitly configured CI connectivity"
        ],
        execution_ready=True,
        specification_artifacts=[
            "workspace/mmaudit-certora/specification-plan.json",
            f"workspace/{config.specification}",
        ],
        assumption_artifacts=["workspace/mmaudit-certora/assumptions.json"],
        vacuity_artifacts=["workspace/mmaudit-certora/vacuity-plan.json"],
        vacuity_checks=1,
    )


def parse_certora_results(value: str) -> list[CertoraRuleResult]:
    """Parse only bounded JSON rule records; unknown output remains inconclusive."""

    documents = _json_documents(value)
    candidates = [
        item
        for document in documents
        for item in _walk_dicts(document)
        if _rule_name(item) is not None and _status(item) is not None
    ]
    results: list[CertoraRuleResult] = []
    seen: set[tuple[str, str, str]] = set()
    for item in candidates:
        rule = _rule_name(item)
        status = _status(item)
        assert rule is not None
        assert status is not None
        counterexample = item.get("counterexample")
        normalized_counterexample = (
            json.loads(json.dumps(counterexample, sort_keys=True))
            if isinstance(counterexample, dict)
            else {}
        )
        serialized_counterexample = json.dumps(
            normalized_counterexample,
            sort_keys=True,
            separators=(",", ":"),
        )
        key = (rule, status, serialized_counterexample)
        if key in seen:
            continue
        seen.add(key)
        raw_assumptions = item.get("assumptions")
        assumptions = (
            sorted(
                {
                    assumption[:500]
                    for assumption in raw_assumptions
                    if isinstance(assumption, str) and assumption
                }
            )
            if isinstance(raw_assumptions, list)
            else []
        )
        vacuity = item.get("vacuity")
        vacuity_status = (
            str(vacuity.get("status", "")).strip().lower()
            if isinstance(vacuity, dict)
            else str(vacuity).strip().lower()
            if isinstance(vacuity, str)
            else None
        )
        raw_path = item.get("path")
        path: str | None = None
        if isinstance(raw_path, str):
            try:
                candidate = normalize_relative_path(raw_path)
            except ValueError:
                pass
            else:
                if candidate.endswith(".sol"):
                    path = candidate
        raw_line = item.get("line")
        line = (
            raw_line
            if isinstance(raw_line, int)
            and not isinstance(raw_line, bool)
            and 1 <= raw_line <= 10_000_000
            else None
        )
        results.append(
            CertoraRuleResult(
                rule=rule,
                status=status,
                assumptions=assumptions,
                vacuity_status=vacuity_status,
                counterexample=normalized_counterexample,
                path=path,
                line=line,
            )
        )
    return sorted(
        results,
        key=lambda result: (
            result.rule,
            result.status,
            json.dumps(result.counterexample, sort_keys=True),
        ),
    )


def _safe_input_file(workspace: Path, relative_path: str, *, suffix: str) -> Path:
    normalized = normalize_relative_path(relative_path)
    if not normalized.endswith(suffix):
        raise ValueError("configured Certora input has an unexpected suffix")
    root = workspace.resolve(strict=True)
    candidate = root.joinpath(*PurePosixPath(normalized).parts)
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(root)
    metadata = candidate.lstat()
    if (
        candidate.is_symlink()
        or not resolved.is_file()
        or metadata.st_nlink != 1
        or metadata.st_size > _MAX_CERTORA_INPUT_BYTES
    ):
        raise ValueError("configured Certora input is not a bounded unique regular file")
    return resolved


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def _rule_name(item: dict[str, Any]) -> str | None:
    for key in ("rule", "ruleName", "name"):
        value = item.get(key)
        if (
            isinstance(value, str)
            and value
            and len(value) <= 128
            and value.replace("_", "a").isalnum()
            and not value[0].isdigit()
        ):
            return value
    return None


def _status(item: dict[str, Any]) -> str | None:
    for key in ("status", "result", "outcome"):
        value = item.get(key)
        if not isinstance(value, str):
            continue
        normalized = value.strip().lower().replace(" ", "_")
        if normalized in {
            "counterexample",
            "failed",
            "violated",
            "passed",
            "proved",
            "verified",
            "timeout",
            "unknown",
        }:
            return normalized
    return None
