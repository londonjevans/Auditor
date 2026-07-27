"""Isolated, fixed-command formal and symbolic analysis adapters."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from mmaudit.config import FormalConfig
from mmaudit.models.schemas import (
    DynamicEngineComparison,
    DynamicPropertyOutcome,
    FormalDependencyProvenance,
    FormalEvidence,
    FormalResultKind,
    FormalToolRun,
    FormalToolStatus,
    InvariantSuite,
    Location,
    PropertyCorpus,
    SolidityProjectMetadata,
    SoliditySymbolIndex,
)
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_path
from mmaudit.repository.workspace import validate_copyable_workspace
from mmaudit.scanners.base import sanitized_scanner_environment
from mmaudit.solidity.engines.certora import (
    CertoraPreparation,
    parse_certora_results,
    prepare_certora_workspace,
)
from mmaudit.solidity.engines.echidna import (
    PropertyEngineTranslation,
    translate_echidna_corpus,
)
from mmaudit.solidity.engines.halmos import (
    parse_halmos_json,
    translate_halmos_corpus,
    untrusted_halmos_annotation_limitations,
)
from mmaudit.solidity.engines.kontrol import (
    parse_kontrol_output,
    read_kontrol_plan,
    translate_kontrol_corpus,
)
from mmaudit.solidity.engines.medusa import translate_medusa_corpus
from mmaudit.solidity.reproduction import IsolationBackend, default_isolation_backend

_EXCLUDED_DYNAMIC_WORKSPACE_NAMES = frozenset(
    {
        ".git",
        ".mmaudit",
        "artifacts",
        "broadcast",
        "cache",
        "mmaudit-certora",
        "mmaudit-echidna",
        "mmaudit-kontrol",
        "mmaudit-medusa",
        "node_modules",
        "out",
    }
)


@dataclass(frozen=True)
class FormalDependencySpec:
    """One operator-pinned executable dependency required by an adapter."""

    name: str
    executable: Path
    expected_version: str
    expected_sha256: str


@dataclass(frozen=True)
class HalmosCommandPlan:
    """Validated command fields read back from the generated Halmos plan."""

    contract: str
    function_prefix: str
    invariant_depth: int
    width: int


@dataclass(frozen=True)
class FormalEnvironmentExtension:
    """Adapter-requested environment values and their in-memory redaction set."""

    variables: dict[str, str]
    sensitive_values: tuple[str, ...] = ()
    failure_reason: str = ""


class FormalAdapter(ABC):
    """A fixed-command adapter. No field comes from model-generated commands."""

    name: str
    executable: str
    requires_preflight_trust: bool = False

    def available(self, repository_root: Path) -> Path | None:
        raw = shutil.which(self.executable)
        if raw is None:
            return None
        resolved = Path(raw).resolve(strict=True)
        try:
            resolved.relative_to(repository_root.resolve(strict=True))
        except ValueError:
            return resolved
        return None

    def applicable_with_corpus(
        self,
        index: SoliditySymbolIndex,
        invariants: InvariantSuite,
        property_corpus: PropertyCorpus | None,
    ) -> tuple[bool, str]:
        """Apply optional shared-property context without weakening existing adapters."""

        del property_corpus
        return self.applicable(index, invariants)

    def validate_trust(
        self,
        *,
        version: str | None,
        executable_sha256: str,
        config: FormalConfig,
    ) -> tuple[bool, str]:
        """Validate adapter-specific version/hash policy before target execution."""

        del version, executable_sha256, config
        return True, ""

    def dependencies(
        self,
        *,
        repository_root: Path,
        config: FormalConfig,
    ) -> tuple[list[FormalDependencySpec], str]:
        """Resolve exact external executable dependencies before target execution."""

        del repository_root, config
        return [], ""

    def prepare_workspace(
        self,
        *,
        workspace: Path,
        index: SoliditySymbolIndex,
        property_corpus: PropertyCorpus | None,
        config: FormalConfig,
    ) -> PropertyEngineTranslation | CertoraPreparation | None:
        """Generate deterministic engine inputs after the private copy is isolated."""

        del workspace, index, property_corpus, config
        return None

    def execution_environment(
        self,
        *,
        config: FormalConfig,
    ) -> FormalEnvironmentExtension:
        """Return bounded operator-owned environment additions for target execution."""

        del config
        return FormalEnvironmentExtension(variables={})

    def build_command_with_dependencies(
        self,
        executable: Path,
        workspace: Path,
        output_path: Path,
        index: SoliditySymbolIndex,
        config: FormalConfig,
        dependencies: list[FormalDependencySpec],
    ) -> list[str]:
        """Build a command after dependency trust has been established."""

        del dependencies
        return self.build_command(executable, workspace, output_path, index, config)

    def parse_result(
        self,
        stdout: str,
        stderr: str,
        machine_output: str,
        index: SoliditySymbolIndex,
    ) -> list[FormalEvidence]:
        """Normalize stdout/stderr or an adapter-specific machine artifact."""

        del machine_output
        return self.parse(stdout, stderr, index)

    @abstractmethod
    def applicable(
        self,
        index: SoliditySymbolIndex,
        invariants: InvariantSuite,
    ) -> tuple[bool, str]: ...

    @abstractmethod
    def build_command(
        self,
        executable: Path,
        workspace: Path,
        output_path: Path,
        index: SoliditySymbolIndex,
        config: FormalConfig,
    ) -> list[str]: ...

    @abstractmethod
    def parse(
        self,
        stdout: str,
        stderr: str,
        index: SoliditySymbolIndex,
    ) -> list[FormalEvidence]: ...


class SolcSMTCheckerAdapter(FormalAdapter):
    name = "solc-smtchecker"
    executable = "solc"

    def applicable(
        self,
        index: SoliditySymbolIndex,
        invariants: InvariantSuite,
    ) -> tuple[bool, str]:
        del invariants
        return (bool(index.entities), "no indexed Solidity entities")

    def build_command(
        self,
        executable: Path,
        workspace: Path,
        output_path: Path,
        index: SoliditySymbolIndex,
        config: FormalConfig,
    ) -> list[str]:
        del workspace, output_path
        source_paths = _safe_source_paths(index)[:100]
        return [
            str(executable),
            "--model-checker-engine",
            "all",
            "--model-checker-targets",
            "assert",
            "--model-checker-timeout",
            str(max(1, int(config.timeout_seconds * 1_000))),
            "--base-path",
            ".",
            *source_paths,
        ]

    def parse(
        self,
        stdout: str,
        stderr: str,
        index: SoliditySymbolIndex,
    ) -> list[FormalEvidence]:
        combined = "\n".join((stdout, stderr))
        evidence: list[FormalEvidence] = []
        blocks = re.split(r"(?=(?:Warning|Error):\s+(?:CHC|BMC):)", combined)
        for position, block in enumerate(blocks):
            lowered = block.lower()
            if "assertion violation" not in lowered and "counterexample" not in lowered:
                continue
            locations = _locations_from_text(block, index)
            evidence.append(
                FormalEvidence(
                    tool=self.name,
                    property_id=f"smt-assert-{position}",
                    property_description="Solidity assertion is reachable in a solver counterexample",
                    status=FormalToolStatus.SUCCESS,
                    result_kind=FormalResultKind.COUNTEREXAMPLE,
                    assumptions=["Solidity SMTChecker model and configured solver bounds"],
                    counterexample={"summary": _bounded_summary(block)},
                    locations=locations,
                    confidence=0.95 if locations else 0.8,
                )
            )
        return evidence


class MythrilAdapter(FormalAdapter):
    name = "mythril"
    executable = "myth"

    def applicable(
        self,
        index: SoliditySymbolIndex,
        invariants: InvariantSuite,
    ) -> tuple[bool, str]:
        del invariants
        return (bool(_safe_source_paths(index)), "no Solidity source path")

    def build_command(
        self,
        executable: Path,
        workspace: Path,
        output_path: Path,
        index: SoliditySymbolIndex,
        config: FormalConfig,
    ) -> list[str]:
        del workspace, output_path
        source = _safe_source_paths(index)[0]
        return [
            str(executable),
            "analyze",
            source,
            "--execution-timeout",
            str(max(1, int(config.timeout_seconds))),
            "-o",
            "json",
        ]

    def parse(
        self,
        stdout: str,
        stderr: str,
        index: SoliditySymbolIndex,
    ) -> list[FormalEvidence]:
        del stderr
        try:
            payload = json.loads(stdout or "{}")
        except json.JSONDecodeError:
            return []
        issues = payload.get("issues", []) if isinstance(payload, dict) else []
        evidence: list[FormalEvidence] = []
        for position, issue in enumerate(issues if isinstance(issues, list) else []):
            if not isinstance(issue, dict):
                continue
            path = str(issue.get("filename", ""))
            line = _positive_int(issue.get("lineno"))
            locations = _validated_index_locations(index, path, line)
            evidence.append(
                FormalEvidence(
                    tool=self.name,
                    property_id=str(issue.get("swc-id") or f"mythril-{position}"),
                    property_description=str(
                        issue.get("title") or issue.get("description") or "Symbolic counterexample"
                    )[:1_000],
                    status=FormalToolStatus.SUCCESS,
                    result_kind=FormalResultKind.COUNTEREXAMPLE,
                    assumptions=["Mythril symbolic execution bounds"],
                    path_constraints=[str(issue.get("extra", {}).get("debug", ""))[:2_000]]
                    if isinstance(issue.get("extra"), dict)
                    else [],
                    counterexample={"summary": str(issue.get("description", ""))[:2_000]},
                    locations=locations,
                    confidence=0.9 if locations else 0.65,
                )
            )
        return evidence


class PropertyToolAdapter(FormalAdapter):
    """Adapter for property engines that require repository/generated properties."""

    property_prefixes: tuple[str, ...] = ("invariant_", "echidna_")

    def applicable(
        self,
        index: SoliditySymbolIndex,
        invariants: InvariantSuite,
    ) -> tuple[bool, str]:
        has_harness = any(
            entity.name.startswith(self.property_prefixes) for entity in index.entities
        )
        if has_harness:
            return True, ""
        if invariants.executable_count:
            return False, "invariants were inferred but no reviewed executable harness exists"
        return False, "no executable property harness was discovered"

    def parse(
        self,
        stdout: str,
        stderr: str,
        index: SoliditySymbolIndex,
    ) -> list[FormalEvidence]:
        combined = "\n".join((stdout, stderr))
        evidence: list[FormalEvidence] = []
        failure_pattern = re.compile(
            r"(?P<property>(?:invariant_|echidna_)[A-Za-z0-9_]+).*?"
            r"(?P<result>fail(?:ed|ure)?|counterexample)",
            re.I,
        )
        for match in failure_pattern.finditer(combined):
            property_name = match.group("property")
            evidence.append(
                _property_counterexample_evidence(
                    self.name,
                    property_name,
                    _bounded_summary(combined[match.start() :]),
                    index,
                )
            )
        return evidence


class EchidnaAdapter(PropertyToolAdapter):
    name = "echidna"
    executable = "echidna"
    requires_preflight_trust = True

    def applicable_with_corpus(
        self,
        index: SoliditySymbolIndex,
        invariants: InvariantSuite,
        property_corpus: PropertyCorpus | None,
    ) -> tuple[bool, str]:
        if property_corpus is not None and property_corpus.properties:
            return True, ""
        return self.applicable(index, invariants)

    def validate_trust(
        self,
        *,
        version: str | None,
        executable_sha256: str,
        config: FormalConfig,
    ) -> tuple[bool, str]:
        if config.echidna_version is None or config.echidna_sha256 is None:
            return False, "Echidna requires exact configured version and SHA-256 trust pins"
        if executable_sha256 != config.echidna_sha256:
            return False, "Echidna executable SHA-256 does not match the configured trust pin"
        if (
            version is None
            or re.search(
                rf"(?<![0-9.]){re.escape(config.echidna_version)}(?![0-9.])",
                version,
            )
            is None
        ):
            return False, "Echidna version does not match the configured supported version"
        return True, ""

    def prepare_workspace(
        self,
        *,
        workspace: Path,
        index: SoliditySymbolIndex,
        property_corpus: PropertyCorpus | None,
        config: FormalConfig,
    ) -> PropertyEngineTranslation | None:
        if property_corpus is None or not property_corpus.properties:
            return None
        translation = translate_echidna_corpus(
            property_corpus,
            index,
            timeout_seconds=config.timeout_seconds,
        )
        if translation.property_map:
            generated = workspace / "mmaudit-echidna"
            generated.mkdir(mode=0o700)
            (generated / "MMAuditEchidna.sol").write_text(
                translation.source,
                encoding="utf-8",
            )
            (generated / "echidna.yaml").write_text(
                translation.configuration,
                encoding="utf-8",
            )
            (generated / "property-map.json").write_text(
                json.dumps(
                    {
                        "corpus_hash": property_corpus.corpus_hash,
                        "properties": {
                            generated_name: property_spec.id
                            for generated_name, property_spec in sorted(
                                translation.property_map.items()
                            )
                        },
                    },
                    sort_keys=True,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        return translation

    def build_command(
        self,
        executable: Path,
        workspace: Path,
        output_path: Path,
        index: SoliditySymbolIndex,
        config: FormalConfig,
    ) -> list[str]:
        del output_path, index, config
        generated = workspace / "mmaudit-echidna" / "MMAuditEchidna.sol"
        if generated.exists():
            return [
                str(executable),
                "mmaudit-echidna/MMAuditEchidna.sol",
                "--contract",
                "MMAuditEchidnaProperties",
                "--config",
                "mmaudit-echidna/echidna.yaml",
                "--format",
                "json",
            ]
        return [str(executable), ".", "--format", "json"]

    def parse(
        self,
        stdout: str,
        stderr: str,
        index: SoliditySymbolIndex,
    ) -> list[FormalEvidence]:
        payloads = [*_json_documents(stdout), *_json_documents(stderr)]
        if not payloads:
            return super().parse(stdout, stderr, index)
        evidence: list[FormalEvidence] = []
        seen: set[tuple[str, str]] = set()
        for payload in payloads:
            for item in _walk_dicts(payload):
                property_name = _property_name_from_json(item)
                if property_name is None:
                    continue
                status = str(item.get("status") or item.get("result") or item.get("state") or "")
                serialized = json.dumps(item, sort_keys=True)[:4_000]
                lowered = f"{status}\n{serialized}".lower()
                if not any(
                    token in lowered
                    for token in ("falsified", "failed", "failure", "counterexample")
                ):
                    continue
                key = (property_name, serialized)
                if key in seen:
                    continue
                seen.add(key)
                evidence.append(
                    _property_counterexample_evidence(
                        self.name,
                        property_name,
                        _bounded_summary(serialized),
                        index,
                        counterexample=_echidna_counterexample(item, serialized),
                    )
                )
        return evidence or super().parse(stdout, stderr, index)


class MedusaAdapter(PropertyToolAdapter):
    name = "medusa"
    executable = "medusa"
    requires_preflight_trust = True

    def applicable_with_corpus(
        self,
        index: SoliditySymbolIndex,
        invariants: InvariantSuite,
        property_corpus: PropertyCorpus | None,
    ) -> tuple[bool, str]:
        if property_corpus is not None and property_corpus.properties:
            return True, ""
        return self.applicable(index, invariants)

    def validate_trust(
        self,
        *,
        version: str | None,
        executable_sha256: str,
        config: FormalConfig,
    ) -> tuple[bool, str]:
        if config.medusa_version is None or config.medusa_sha256 is None:
            return False, "Medusa requires exact configured version and SHA-256 trust pins"
        if executable_sha256 != config.medusa_sha256:
            return False, "Medusa executable SHA-256 does not match the configured trust pin"
        if (
            version is None
            or re.search(
                rf"(?<![0-9.]){re.escape(config.medusa_version)}(?![0-9.])",
                version,
            )
            is None
        ):
            return False, "Medusa version does not match the configured supported version"
        return True, ""

    def prepare_workspace(
        self,
        *,
        workspace: Path,
        index: SoliditySymbolIndex,
        property_corpus: PropertyCorpus | None,
        config: FormalConfig,
    ) -> PropertyEngineTranslation | None:
        if property_corpus is None or not property_corpus.properties:
            return None
        translation = translate_medusa_corpus(
            property_corpus,
            index,
            timeout_seconds=config.timeout_seconds,
        )
        if translation.property_map:
            generated = workspace / "mmaudit-medusa"
            generated.mkdir(mode=0o700)
            (generated / "MMAuditMedusa.sol").write_text(
                translation.source,
                encoding="utf-8",
            )
            (generated / "medusa.json").write_text(
                translation.configuration,
                encoding="utf-8",
            )
            (generated / "property-map.json").write_text(
                json.dumps(
                    {
                        "corpus_hash": property_corpus.corpus_hash,
                        "properties": {
                            generated_name: property_spec.id
                            for generated_name, property_spec in sorted(
                                translation.property_map.items()
                            )
                        },
                    },
                    sort_keys=True,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        return translation

    def build_command(
        self,
        executable: Path,
        workspace: Path,
        output_path: Path,
        index: SoliditySymbolIndex,
        config: FormalConfig,
    ) -> list[str]:
        del output_path, index, config
        generated = workspace / "mmaudit-medusa" / "MMAuditMedusa.sol"
        if generated.exists():
            return [
                str(executable),
                "fuzz",
                "--config",
                "mmaudit-medusa/medusa.json",
            ]
        return [str(executable), "fuzz", "--compilation-target", "."]

    def parse(
        self,
        stdout: str,
        stderr: str,
        index: SoliditySymbolIndex,
    ) -> list[FormalEvidence]:
        payloads = [*_json_documents(stdout), *_json_documents(stderr)]
        if not payloads:
            return super().parse(stdout, stderr, index)
        evidence: list[FormalEvidence] = []
        seen: set[tuple[str, str]] = set()
        for payload in payloads:
            for item in _walk_dicts(payload):
                property_name = _property_name_from_json(item)
                if property_name is None:
                    continue
                status = str(item.get("status") or item.get("result") or item.get("state") or "")
                serialized = json.dumps(item, sort_keys=True)[:4_000]
                lowered = f"{status}\n{serialized}".lower()
                if not any(
                    token in lowered
                    for token in (
                        "falsified",
                        "failed",
                        "failure",
                        "counterexample",
                        "property_test_failed",
                    )
                ):
                    continue
                key = (property_name, serialized)
                if key in seen:
                    continue
                seen.add(key)
                evidence.append(
                    _property_counterexample_evidence(
                        self.name,
                        property_name,
                        _bounded_summary(serialized),
                        index,
                        counterexample=_echidna_counterexample(item, serialized),
                    )
                )
        return evidence or super().parse(stdout, stderr, index)


class FoundryInvariantAdapter(PropertyToolAdapter):
    name = "foundry-invariant"
    executable = "forge"
    property_prefixes = ("invariant_",)

    def build_command(
        self,
        executable: Path,
        workspace: Path,
        output_path: Path,
        index: SoliditySymbolIndex,
        config: FormalConfig,
    ) -> list[str]:
        del workspace, output_path, index, config
        return [
            str(executable),
            "test",
            "--offline",
            "--match-test",
            "invariant_",
            "-vv",
        ]


class HalmosAdapter(PropertyToolAdapter):
    name = "halmos"
    executable = "halmos"
    requires_preflight_trust = True

    def applicable_with_corpus(
        self,
        index: SoliditySymbolIndex,
        invariants: InvariantSuite,
        property_corpus: PropertyCorpus | None,
    ) -> tuple[bool, str]:
        if property_corpus is not None and property_corpus.properties:
            return True, ""
        return self.applicable(index, invariants)

    def validate_trust(
        self,
        *,
        version: str | None,
        executable_sha256: str,
        config: FormalConfig,
    ) -> tuple[bool, str]:
        if config.halmos_version is None or config.halmos_sha256 is None:
            return False, "Halmos requires exact configured version and SHA-256 trust pins"
        if executable_sha256 != config.halmos_sha256:
            return False, "Halmos executable SHA-256 does not match the configured trust pin"
        if not _version_contains(version, config.halmos_version):
            return False, "Halmos version does not match the configured supported version"
        return True, ""

    def dependencies(
        self,
        *,
        repository_root: Path,
        config: FormalConfig,
    ) -> tuple[list[FormalDependencySpec], str]:
        if config.halmos_solver_version is None or config.halmos_solver_sha256 is None:
            return [], "Halmos requires exact configured Z3 version and SHA-256 trust pins"
        raw_solver = shutil.which("z3")
        if raw_solver is None:
            return [], "the fixed local Z3 dependency is unavailable"
        try:
            solver = Path(raw_solver).resolve(strict=True)
            solver.relative_to(repository_root.resolve(strict=True))
        except ValueError:
            pass
        except OSError:
            return [], "the fixed local Z3 dependency could not be resolved"
        else:
            return [], "the fixed Z3 dependency resolved inside the target repository"
        return [
            FormalDependencySpec(
                name="z3",
                executable=solver,
                expected_version=config.halmos_solver_version,
                expected_sha256=config.halmos_solver_sha256,
            )
        ], ""

    def prepare_workspace(
        self,
        *,
        workspace: Path,
        index: SoliditySymbolIndex,
        property_corpus: PropertyCorpus | None,
        config: FormalConfig,
    ) -> PropertyEngineTranslation | None:
        annotation_limitations = untrusted_halmos_annotation_limitations(workspace, index)
        if annotation_limitations:
            return PropertyEngineTranslation(
                source="",
                configuration="",
                property_map={},
                limitations=annotation_limitations,
                seed=None,
                runs=0,
                depth=0,
            )
        trusted_configuration = workspace / "mmaudit-halmos" / "halmos.toml"
        trusted_configuration.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        trusted_configuration.write_text(
            "[global]\nffi = false\n",
            encoding="utf-8",
        )
        if property_corpus is None or not property_corpus.properties:
            return None
        translation = translate_halmos_corpus(
            property_corpus,
            index,
            timeout_seconds=config.timeout_seconds,
            maximum_invariant_depth=config.halmos_max_invariant_depth,
            loop_bound=config.halmos_loop_bound,
            maximum_width=config.halmos_max_width,
            maximum_path_depth=config.halmos_max_path_depth,
            solver_timeout_seconds=config.halmos_solver_timeout_seconds,
            solver_max_memory_mb=config.halmos_solver_max_memory_mb,
        )
        if not translation.property_map:
            return translation
        generated_source = workspace / translation.source_path
        generated_source.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if generated_source.exists():
            return replace(
                translation,
                source="",
                configuration="",
                property_map={},
                limitations=sorted(
                    {
                        *translation.limitations,
                        f"{translation.source_path}: generated Halmos source path already exists",
                    }
                ),
            )
        generated_source.write_text(translation.source, encoding="utf-8")
        configuration_path = workspace / translation.configuration_path
        configuration_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        configuration_path.write_text(translation.configuration, encoding="utf-8")
        property_map_path = workspace / translation.property_map_path
        property_map_path.write_text(
            json.dumps(
                {
                    "corpus_hash": property_corpus.corpus_hash,
                    "properties": {
                        generated_name: property_spec.id
                        for generated_name, property_spec in sorted(
                            translation.property_map.items()
                        )
                    },
                },
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return translation

    def build_command(
        self,
        executable: Path,
        workspace: Path,
        output_path: Path,
        index: SoliditySymbolIndex,
        config: FormalConfig,
    ) -> list[str]:
        return self.build_command_with_dependencies(
            executable,
            workspace,
            output_path,
            index,
            config,
            [],
        )

    def build_command_with_dependencies(
        self,
        executable: Path,
        workspace: Path,
        output_path: Path,
        index: SoliditySymbolIndex,
        config: FormalConfig,
        dependencies: list[FormalDependencySpec],
    ) -> list[str]:
        del index
        if len(dependencies) != 1 or dependencies[0].name != "z3":
            raise ValueError("Halmos requires one validated Z3 dependency")
        plan_path = workspace / "mmaudit-halmos" / "plan.json"
        contract_arguments: list[str] = []
        invariant_depth = config.halmos_max_invariant_depth
        width = config.halmos_max_width
        if plan_path.is_file():
            plan = _read_halmos_plan(plan_path)
            contract_arguments = [
                "--contract",
                plan.contract,
                "--function",
                plan.function_prefix,
            ]
            invariant_depth = plan.invariant_depth
            width = plan.width
        return [
            str(executable),
            "--root",
            str(workspace),
            "--config",
            "mmaudit-halmos/halmos.toml",
            *contract_arguments,
            "--panic-error-codes",
            "0x01",
            "--invariant-depth",
            str(invariant_depth),
            "--loop",
            str(config.halmos_loop_bound),
            "--width",
            str(width),
            "--depth",
            str(config.halmos_max_path_depth),
            "--default-array-lengths",
            "0,1,2",
            "--default-bytes-lengths",
            "0,32,65",
            "--storage-layout",
            "solidity",
            "--solver-command",
            shlex.join([str(dependencies[0].executable)]),
            "--solver-timeout-branching",
            f"{config.halmos_solver_timeout_seconds:g}s",
            "--solver-timeout-assertion",
            f"{config.halmos_solver_timeout_seconds:g}s",
            "--solver-max-memory",
            str(config.halmos_solver_max_memory_mb),
            "--solver-threads",
            "1",
            "--no-status",
            "--json-output",
            str(output_path),
        ]

    def parse_result(
        self,
        stdout: str,
        stderr: str,
        machine_output: str,
        index: SoliditySymbolIndex,
    ) -> list[FormalEvidence]:
        records = parse_halmos_json(machine_output)
        if not records:
            return super().parse_result(stdout, stderr, machine_output, index)
        return [
            _property_counterexample_evidence(
                self.name,
                record.property_name,
                str(record.counterexample["summary"]),
                index,
                counterexample=record.counterexample,
            )
            for record in records
        ]


class CertoraAdapter(FormalAdapter):
    """Explicitly configured, trust-pinned Certora verification adapter."""

    name = "certora"
    executable = "certoraRun"
    requires_preflight_trust = True

    def applicable(
        self,
        index: SoliditySymbolIndex,
        invariants: InvariantSuite,
    ) -> tuple[bool, str]:
        del invariants
        if any(entity.kind.value == "contract" for entity in index.entities):
            return True, ""
        return False, "no indexed Solidity contract is available for configured verification"

    def validate_trust(
        self,
        *,
        version: str | None,
        executable_sha256: str,
        config: FormalConfig,
    ) -> tuple[bool, str]:
        certora = config.certora
        if not certora.enabled:
            return False, "Certora execution was not explicitly enabled"
        if certora.cli_version is None or certora.cli_sha256 is None:
            return False, "Certora requires exact configured CLI version and SHA-256 trust pins"
        if executable_sha256 != certora.cli_sha256:
            return False, "Certora CLI SHA-256 does not match the configured trust pin"
        if not _version_contains(version, certora.cli_version):
            return False, "Certora CLI version does not match the configured supported version"
        return True, ""

    def prepare_workspace(
        self,
        *,
        workspace: Path,
        index: SoliditySymbolIndex,
        property_corpus: PropertyCorpus | None,
        config: FormalConfig,
    ) -> CertoraPreparation:
        del property_corpus
        return prepare_certora_workspace(
            workspace=workspace,
            index=index,
            config=config.certora,
        )

    def execution_environment(
        self,
        *,
        config: FormalConfig,
    ) -> FormalEnvironmentExtension:
        variable = config.certora.api_key_env_var
        value = os.environ.get(variable)
        if value is None:
            return FormalEnvironmentExtension(
                variables={},
                failure_reason="configured Certora API key environment variable is unavailable",
            )
        if not value or len(value) > 4_096 or "\x00" in value or "\n" in value or "\r" in value:
            return FormalEnvironmentExtension(
                variables={},
                failure_reason="configured Certora API key value is invalid or exceeds its bound",
            )
        return FormalEnvironmentExtension(
            variables={variable: value},
            sensitive_values=(value,),
        )

    def build_command(
        self,
        executable: Path,
        workspace: Path,
        output_path: Path,
        index: SoliditySymbolIndex,
        config: FormalConfig,
    ) -> list[str]:
        del workspace, index
        certora = config.certora
        assert certora.source is not None
        assert certora.contract is not None
        assert certora.specification is not None
        rule_arguments = ["--rule", certora.rule] if certora.rule is not None else []
        return [
            str(executable),
            certora.source,
            "--verify",
            f"{certora.contract}:{certora.specification}",
            *rule_arguments,
            "--rule_sanity",
            certora.vacuity_check,
            "--wait_for_results",
            "all",
            "--json_output",
            str(output_path),
        ]

    def parse(
        self,
        stdout: str,
        stderr: str,
        index: SoliditySymbolIndex,
    ) -> list[FormalEvidence]:
        return self.parse_result(stdout, stderr, "", index)

    def parse_result(
        self,
        stdout: str,
        stderr: str,
        machine_output: str,
        index: SoliditySymbolIndex,
    ) -> list[FormalEvidence]:
        records = parse_certora_results(
            "\n".join(value for value in (machine_output, stdout, stderr) if value)
        )
        evidence: list[FormalEvidence] = []
        for record in records:
            if record.path is not None and record.line is not None:
                locations = _validated_index_locations(index, record.path, record.line)
            else:
                entity = next(
                    (candidate for candidate in index.entities if candidate.name == record.rule),
                    None,
                )
                locations = (
                    [
                        Location(
                            path=entity.path,
                            start_line=entity.start_line,
                            end_line=entity.end_line,
                            symbol=entity.name,
                            content_hash=entity.source_hash,
                        )
                    ]
                    if entity is not None
                    else []
                )
            if record.is_counterexample:
                status = FormalToolStatus.SUCCESS
                result_kind = FormalResultKind.COUNTEREXAMPLE
                description = f"Configured Certora rule {record.rule} was violated"
            elif record.is_proof and record.is_non_vacuous:
                status = FormalToolStatus.SUCCESS
                result_kind = FormalResultKind.PROOF
                description = (
                    f"Configured Certora rule {record.rule} passed with non-vacuity evidence"
                )
            else:
                status = FormalToolStatus.INCONCLUSIVE
                result_kind = FormalResultKind.UNKNOWN
                description = (
                    f"Configured Certora rule {record.rule} lacks a non-vacuous conclusive result"
                )
            counterexample = dict(record.counterexample)
            if record.vacuity_status is not None:
                counterexample["vacuity_status"] = record.vacuity_status
            evidence.append(
                FormalEvidence(
                    tool=self.name,
                    property_id=record.rule,
                    property_description=description,
                    status=status,
                    result_kind=result_kind,
                    assumptions=record.assumptions,
                    counterexample=counterexample,
                    locations=locations,
                    confidence=0.95 if locations else 0.7,
                    artifact_paths=[
                        "certora/result.json",
                        "workspace/mmaudit-certora/assumptions.json",
                        "workspace/mmaudit-certora/specification-plan.json",
                        "workspace/mmaudit-certora/vacuity-plan.json",
                    ],
                )
            )
        return evidence


class KontrolAdapter(PropertyToolAdapter):
    name = "kontrol"
    executable = "kontrol"
    property_prefixes = ("testKontrol_",)
    requires_preflight_trust = True

    def applicable_with_corpus(
        self,
        index: SoliditySymbolIndex,
        invariants: InvariantSuite,
        property_corpus: PropertyCorpus | None,
    ) -> tuple[bool, str]:
        if property_corpus is not None and property_corpus.properties:
            return True, ""
        return self.applicable(index, invariants)

    def validate_trust(
        self,
        *,
        version: str | None,
        executable_sha256: str,
        config: FormalConfig,
    ) -> tuple[bool, str]:
        if config.kontrol_version is None or config.kontrol_sha256 is None:
            return False, "Kontrol requires exact configured version and SHA-256 trust pins"
        if executable_sha256 != config.kontrol_sha256:
            return False, "Kontrol executable SHA-256 does not match the configured trust pin"
        if not _version_contains(version, config.kontrol_version):
            return False, "Kontrol version does not match the configured supported version"
        return True, ""

    def prepare_workspace(
        self,
        *,
        workspace: Path,
        index: SoliditySymbolIndex,
        property_corpus: PropertyCorpus | None,
        config: FormalConfig,
    ) -> PropertyEngineTranslation | None:
        if property_corpus is None or not property_corpus.properties:
            return None
        translation = translate_kontrol_corpus(
            property_corpus,
            index,
            maximum_depth=config.kontrol_max_depth,
            maximum_iterations=config.kontrol_max_iterations,
        )
        if not translation.property_map:
            return translation
        generated_source = workspace / translation.source_path
        generated_source.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if generated_source.exists():
            return replace(
                translation,
                source="",
                configuration="",
                property_map={},
                limitations=sorted(
                    {
                        *translation.limitations,
                        f"{translation.source_path}: generated Kontrol source path already exists",
                    }
                ),
            )
        generated_source.write_text(translation.source, encoding="utf-8")
        plan_path = workspace / translation.configuration_path
        plan_path.parent.mkdir(parents=True, exist_ok=False, mode=0o700)
        plan_path.write_text(translation.configuration, encoding="utf-8")
        property_map_path = workspace / translation.property_map_path
        property_map_path.write_text(
            json.dumps(
                {
                    "corpus_hash": property_corpus.corpus_hash,
                    "properties": {
                        generated_name: property_spec.id
                        for generated_name, property_spec in sorted(
                            translation.property_map.items()
                        )
                    },
                },
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return translation

    def build_command(
        self,
        executable: Path,
        workspace: Path,
        output_path: Path,
        index: SoliditySymbolIndex,
        config: FormalConfig,
    ) -> list[str]:
        del output_path, index, config
        plan = read_kontrol_plan(workspace / "mmaudit-kontrol" / "plan.json")
        return [
            str(executable),
            "prove",
            "--project-root",
            str(workspace),
            "--match-test",
            f"{plan.contract}.{plan.function_pattern}",
            "--max-depth",
            str(plan.max_depth),
            "--max-iterations",
            str(plan.max_iterations),
            "--workers",
            str(plan.workers),
            "--failure-information",
            "--counterexample-information",
        ]

    def parse_result(
        self,
        stdout: str,
        stderr: str,
        machine_output: str,
        index: SoliditySymbolIndex,
    ) -> list[FormalEvidence]:
        del machine_output
        return [
            _property_counterexample_evidence(
                self.name,
                record.property_name,
                str(record.counterexample["summary"]),
                index,
                counterexample=record.counterexample,
            )
            for record in parse_kontrol_output("\n".join((stdout, stderr)))
        ]


class FormalRunner:
    """Execute configured adapters only in copied workspaces and hardened isolation."""

    def __init__(
        self,
        config: FormalConfig,
        *,
        backend: IsolationBackend | None = None,
        adapters: list[FormalAdapter] | None = None,
    ) -> None:
        self.config = config
        self.backend = backend if backend is not None else default_isolation_backend("auto")
        self.adapters = adapters or [
            SolcSMTCheckerAdapter(),
            MythrilAdapter(),
            EchidnaAdapter(),
            MedusaAdapter(),
            FoundryInvariantAdapter(),
            HalmosAdapter(),
            CertoraAdapter(),
            KontrolAdapter(),
        ]

    @property
    def isolation_available(self) -> bool:
        return self.backend is not None

    def run(
        self,
        *,
        repository_root: Path,
        projects: list[SolidityProjectMetadata],
        index: SoliditySymbolIndex,
        invariants: InvariantSuite,
        private_dir: Path,
        property_corpus: PropertyCorpus | None = None,
    ) -> list[FormalToolRun]:
        if not self.config.enabled:
            return []
        project = _root_project(projects)
        isolation_backend = (
            (str(getattr(self.backend, "name", "")) or None) if self.backend is not None else None
        )
        if project is None:
            return [
                FormalToolRun(
                    tool=adapter.name,
                    status=FormalToolStatus.SKIPPED,
                    isolation_backend=isolation_backend,
                    failure_reason="no supported Solidity project root",
                )
                for adapter in self.adapters
                if self._enabled(adapter.name)
            ]
        return [
            self._run_adapter(
                adapter,
                repository_root=repository_root,
                project=project,
                index=index,
                invariants=invariants,
                private_dir=private_dir / adapter.name,
                property_corpus=property_corpus,
            ).model_copy(
                update={"isolation_backend": isolation_backend},
            )
            for adapter in self.adapters
            if self._enabled(adapter.name)
        ]

    def _enabled(self, name: str) -> bool:
        return {
            "solc-smtchecker": self.config.run_smtchecker,
            "mythril": self.config.run_mythril,
            "echidna": self.config.run_echidna,
            "medusa": self.config.run_medusa,
            "foundry-invariant": True,
            "halmos": self.config.run_halmos,
            "certora": self.config.certora.enabled,
            "kontrol": self.config.run_kontrol,
        }.get(name, False)

    def _run_adapter(
        self,
        adapter: FormalAdapter,
        *,
        repository_root: Path,
        project: SolidityProjectMetadata,
        index: SoliditySymbolIndex,
        invariants: InvariantSuite,
        private_dir: Path,
        property_corpus: PropertyCorpus | None,
    ) -> FormalToolRun:
        started = time.monotonic()
        executable = adapter.available(repository_root)
        if executable is None:
            return FormalToolRun(
                tool=adapter.name,
                status=FormalToolStatus.UNAVAILABLE,
                duration_seconds=time.monotonic() - started,
                failure_reason=f"{adapter.executable} is unavailable outside the target repository",
            )
        applicable, reason = adapter.applicable_with_corpus(
            index,
            invariants,
            property_corpus,
        )
        if not applicable:
            return FormalToolRun(
                tool=adapter.name,
                version=None,
                status=FormalToolStatus.SKIPPED,
                duration_seconds=time.monotonic() - started,
                failure_reason=reason,
            )
        if self.backend is None:
            return FormalToolRun(
                tool=adapter.name,
                status=FormalToolStatus.INCONCLUSIVE,
                duration_seconds=time.monotonic() - started,
                failure_reason="hardened isolation backend unavailable; tool was not executed",
            )
        workspace = private_dir / "workspace"
        stdout_path = private_dir / "stdout.txt"
        stderr_path = private_dir / "stderr.txt"
        output_path = private_dir / "result.json"
        private_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        preparation: PropertyEngineTranslation | CertoraPreparation | None = None
        executable_sha256: str | None = None
        version: str | None = None
        dependency_specs: list[FormalDependencySpec] = []
        dependency_provenance: list[FormalDependencyProvenance] = []
        command: list[str] = []
        sensitive_values: tuple[str, ...] = ()
        try:
            _copy_project(repository_root, project, workspace)
            environment = sanitized_scanner_environment(private_dir)
            environment["FOUNDRY_OFFLINE"] = "true"
            executable_sha256 = _file_sha256(executable)
            if adapter.requires_preflight_trust:
                version = _isolated_tool_version(
                    executable,
                    backend=self.backend,
                    workspace=workspace,
                    private_dir=private_dir,
                    environment=environment,
                )
                trusted, trust_reason = adapter.validate_trust(
                    version=version,
                    executable_sha256=executable_sha256,
                    config=self.config,
                )
                if not trusted:
                    return FormalToolRun(
                        tool=adapter.name,
                        version=version,
                        executable_sha256=executable_sha256,
                        status=FormalToolStatus.INCONCLUSIVE,
                        duration_seconds=time.monotonic() - started,
                        property_corpus_hash=(
                            property_corpus.corpus_hash if property_corpus is not None else None
                        ),
                        failure_reason=f"trusted formal execution rejected: {trust_reason}",
                    )
            dependency_specs, dependency_reason = adapter.dependencies(
                repository_root=repository_root,
                config=self.config,
            )
            if dependency_reason:
                return FormalToolRun(
                    tool=adapter.name,
                    version=version,
                    executable_sha256=executable_sha256,
                    status=FormalToolStatus.INCONCLUSIVE,
                    duration_seconds=time.monotonic() - started,
                    property_corpus_hash=(
                        property_corpus.corpus_hash if property_corpus is not None else None
                    ),
                    failure_reason=(
                        f"trusted formal dependency execution rejected: {dependency_reason}"
                    ),
                )
            if [dependency.name for dependency in dependency_specs] != sorted(
                {dependency.name for dependency in dependency_specs}
            ):
                raise ValueError("formal dependency specifications must be unique and sorted")
            for dependency in dependency_specs:
                dependency_sha256 = _file_sha256(dependency.executable)
                dependency_version = _isolated_tool_version(
                    dependency.executable,
                    backend=self.backend,
                    workspace=workspace,
                    private_dir=private_dir,
                    environment=environment,
                    artifact_prefix=f"{dependency.name}.",
                )
                dependency_provenance.append(
                    FormalDependencyProvenance(
                        name=dependency.name,
                        version=dependency_version,
                        executable_sha256=dependency_sha256,
                    )
                )
                if dependency_sha256 != dependency.expected_sha256:
                    return FormalToolRun(
                        tool=adapter.name,
                        version=version,
                        executable_sha256=executable_sha256,
                        dependencies=dependency_provenance,
                        status=FormalToolStatus.INCONCLUSIVE,
                        duration_seconds=time.monotonic() - started,
                        property_corpus_hash=(
                            property_corpus.corpus_hash if property_corpus is not None else None
                        ),
                        failure_reason=(
                            f"trusted {dependency.name} dependency SHA-256 does not "
                            "match the configured trust pin"
                        ),
                    )
                if not _version_contains(
                    dependency_version,
                    dependency.expected_version,
                ):
                    return FormalToolRun(
                        tool=adapter.name,
                        version=version,
                        executable_sha256=executable_sha256,
                        dependencies=dependency_provenance,
                        status=FormalToolStatus.INCONCLUSIVE,
                        duration_seconds=time.monotonic() - started,
                        property_corpus_hash=(
                            property_corpus.corpus_hash if property_corpus is not None else None
                        ),
                        failure_reason=(
                            f"trusted {dependency.name} dependency version does not "
                            "match the configured supported version"
                        ),
                    )
            preparation = adapter.prepare_workspace(
                workspace=workspace,
                index=index,
                property_corpus=property_corpus,
                config=self.config,
            )
            if (
                preparation is not None
                and not preparation.property_map
                and not (
                    isinstance(preparation, CertoraPreparation) and preparation.execution_ready
                )
            ):
                return FormalToolRun(
                    tool=adapter.name,
                    version=version,
                    executable_sha256=executable_sha256,
                    dependencies=dependency_provenance,
                    status=FormalToolStatus.SKIPPED,
                    duration_seconds=time.monotonic() - started,
                    property_corpus_hash=(
                        property_corpus.corpus_hash if property_corpus is not None else None
                    ),
                    assumptions=preparation.assumptions,
                    translation_limitations=preparation.limitations,
                    specification_artifacts=_preparation_artifacts(
                        preparation,
                        "specification_artifacts",
                    ),
                    assumption_artifacts=_preparation_artifacts(
                        preparation,
                        "assumption_artifacts",
                    ),
                    vacuity_artifacts=_preparation_artifacts(
                        preparation,
                        "vacuity_artifacts",
                    ),
                    failure_reason="no shared property could be translated safely",
                )
            command = adapter.build_command_with_dependencies(
                executable,
                workspace,
                output_path,
                index,
                self.config,
                dependency_specs,
            )
            environment_extension = adapter.execution_environment(config=self.config)
            if environment_extension.failure_reason:
                return FormalToolRun(
                    tool=adapter.name,
                    version=version,
                    executable_sha256=executable_sha256,
                    dependencies=dependency_provenance,
                    status=FormalToolStatus.INCONCLUSIVE,
                    command=_redacted_command(
                        command,
                        workspace=workspace,
                        private_dir=private_dir,
                        dependencies=dependency_specs,
                    ),
                    duration_seconds=time.monotonic() - started,
                    assumptions=preparation.assumptions if preparation is not None else [],
                    translation_limitations=(
                        preparation.limitations if preparation is not None else []
                    ),
                    specification_artifacts=_preparation_artifacts(
                        preparation,
                        "specification_artifacts",
                    ),
                    assumption_artifacts=_preparation_artifacts(
                        preparation,
                        "assumption_artifacts",
                    ),
                    vacuity_artifacts=_preparation_artifacts(
                        preparation,
                        "vacuity_artifacts",
                    ),
                    failure_reason=environment_extension.failure_reason,
                )
            environment.update(environment_extension.variables)
            sensitive_values = environment_extension.sensitive_values
            wrapped = self.backend.wrap(
                command,
                workspace=workspace,
                private_dir=private_dir,
                rpc_port=1,
            )
            result = _bounded_process(
                wrapped,
                cwd=workspace,
                environment=environment,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                additional_output_paths=[output_path],
                timeout=self.config.timeout_seconds,
                max_output_bytes=self.config.max_output_bytes,
            )
            _redact_sensitive_artifacts(
                (stdout_path, stderr_path, output_path),
                sensitive_values,
                max_bytes=self.config.max_output_bytes,
            )
        except (OSError, ValueError) as exc:
            _redact_sensitive_artifacts(
                (stdout_path, stderr_path, output_path),
                sensitive_values,
                max_bytes=self.config.max_output_bytes,
            )
            return FormalToolRun(
                tool=adapter.name,
                version=version,
                executable_sha256=executable_sha256,
                dependencies=dependency_provenance,
                status=FormalToolStatus.FAILED,
                duration_seconds=time.monotonic() - started,
                failure_reason=f"safe formal execution setup failed: {type(exc).__name__}",
            )
        stdout = _read_bounded(stdout_path, self.config.max_output_bytes)
        stderr = _read_bounded(stderr_path, self.config.max_output_bytes)
        machine_output = (
            _read_bounded(output_path, self.config.max_output_bytes)
            if output_path.is_file()
            else ""
        )
        if version is None:
            version = _isolated_tool_version(
                executable,
                backend=self.backend,
                workspace=workspace,
                private_dir=private_dir,
                environment=environment,
            )
        status = FormalToolStatus.SUCCESS
        failure_reason: str | None = None
        if result == "timed_out":
            status = FormalToolStatus.TIMED_OUT
            failure_reason = "formal engine exceeded its wall-clock limit"
        elif result == "output_exceeded":
            status = FormalToolStatus.FAILED
            failure_reason = "formal engine output exceeded its private output limit"
        elif isinstance(result, int) and result != 0:
            status = FormalToolStatus.INCONCLUSIVE
            failure_reason = f"formal engine exited with code {result}"
        evidence = (
            adapter.parse_result(stdout, stderr, machine_output, index)
            if status in {FormalToolStatus.SUCCESS, FormalToolStatus.INCONCLUSIVE}
            else []
        )
        if (
            isinstance(preparation, PropertyEngineTranslation)
            and property_corpus is not None
            and preparation.property_map
        ):
            evidence = _remap_property_engine_evidence(
                evidence,
                preparation,
                property_corpus,
            )
        if preparation is not None and preparation.assumptions:
            evidence = [
                item.model_copy(
                    update={
                        "assumptions": sorted(
                            {
                                *item.assumptions,
                                *preparation.assumptions,
                            }
                        )
                    }
                )
                for item in evidence
            ]
        if (
            isinstance(adapter, CertoraAdapter)
            and status is FormalToolStatus.SUCCESS
            and (
                not evidence
                or any(item.status is FormalToolStatus.INCONCLUSIVE for item in evidence)
            )
        ):
            status = FormalToolStatus.INCONCLUSIVE
            failure_reason = (
                "configured Certora output lacked a complete non-vacuous normalized result"
            )
        return FormalToolRun(
            tool=adapter.name,
            version=version,
            executable_sha256=executable_sha256,
            dependencies=dependency_provenance,
            status=status,
            command=_redacted_command(
                command,
                workspace=workspace,
                private_dir=private_dir,
                dependencies=dependency_specs,
            ),
            duration_seconds=time.monotonic() - started,
            evidence=evidence,
            coverage={
                "indexed_sources": len(set(_safe_source_paths(index))),
                "properties": len(evidence),
                "timeout_seconds": self.config.timeout_seconds,
                "campaign_runs": preparation.runs if preparation is not None else 0,
                "campaign_depth": preparation.depth if preparation is not None else 0,
                "vacuity_checks": (
                    preparation.vacuity_checks if isinstance(preparation, CertoraPreparation) else 0
                ),
            },
            property_corpus_hash=(
                property_corpus.corpus_hash
                if preparation is not None and property_corpus is not None
                else None
            ),
            campaign_seed=preparation.seed if preparation is not None else None,
            translated_properties=(len(preparation.property_map) if preparation is not None else 0),
            executed_property_ids=(
                sorted(property_spec.id for property_spec in preparation.property_map.values())
                if preparation is not None
                else []
            ),
            assumptions=(preparation.assumptions if preparation is not None else []),
            translation_limitations=(preparation.limitations if preparation is not None else []),
            specification_artifacts=_preparation_artifacts(
                preparation,
                "specification_artifacts",
            ),
            assumption_artifacts=_preparation_artifacts(
                preparation,
                "assumption_artifacts",
            ),
            vacuity_artifacts=_preparation_artifacts(
                preparation,
                "vacuity_artifacts",
            ),
            failure_reason=failure_reason,
            stdout_path=stdout_path.relative_to(private_dir.parent).as_posix(),
            stderr_path=stderr_path.relative_to(private_dir.parent).as_posix(),
            result_path=(
                output_path.relative_to(private_dir.parent).as_posix()
                if output_path.is_file()
                else None
            ),
        )


def compare_dynamic_engine_outcomes(
    runs: list[FormalToolRun],
) -> list[DynamicEngineComparison]:
    """Compare independent bounded outcomes without aggregating disagreement away."""

    engines = ("echidna", "medusa")
    by_engine = {
        engine: next((run for run in runs if run.tool == engine), None) for engine in engines
    }
    property_ids = sorted(
        {
            property_id
            for run in by_engine.values()
            if run is not None
            for property_id in run.executed_property_ids
        }
    )
    comparisons: list[DynamicEngineComparison] = []
    for property_id in property_ids:
        outcomes: dict[str, DynamicPropertyOutcome] = {}
        for engine in engines:
            run = by_engine[engine]
            if run is None or property_id not in run.executed_property_ids:
                outcomes[engine] = DynamicPropertyOutcome.NOT_EXECUTED
            elif any(
                evidence.property_id == property_id
                and evidence.result_kind is FormalResultKind.COUNTEREXAMPLE
                for evidence in run.evidence
            ):
                outcomes[engine] = DynamicPropertyOutcome.COUNTEREXAMPLE
            elif run.status is FormalToolStatus.SUCCESS:
                outcomes[engine] = DynamicPropertyOutcome.NO_COUNTEREXAMPLE
            else:
                outcomes[engine] = DynamicPropertyOutcome.INCONCLUSIVE
        comparisons.append(
            DynamicEngineComparison(
                property_id=property_id,
                outcomes=outcomes,
                disagreement=len(set(outcomes.values())) > 1,
            )
        )
    return comparisons


def _read_halmos_plan(path: Path) -> HalmosCommandPlan:
    if path.stat().st_size > 100_000:
        raise ValueError("generated Halmos plan exceeds its size bound")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("generated Halmos plan must be an object")
    bounds = payload.get("bounds")
    if not isinstance(bounds, dict):
        raise ValueError("generated Halmos plan bounds are missing")
    contract = payload.get("contract")
    function_prefix = payload.get("function_prefix")
    invariant_depth = bounds.get("invariant_depth")
    width = bounds.get("width")
    if contract != "MMAuditHalmosProperties" or function_prefix != "invariant_":
        raise ValueError("generated Halmos command selectors are invalid")
    if (
        not isinstance(invariant_depth, int)
        or isinstance(invariant_depth, bool)
        or not 1 <= invariant_depth <= 32
    ):
        raise ValueError("generated Halmos invariant depth is invalid")
    if not isinstance(width, int) or isinstance(width, bool) or not 1 <= width <= 10_000:
        raise ValueError("generated Halmos path width is invalid")
    return HalmosCommandPlan(
        contract=contract,
        function_prefix=function_prefix,
        invariant_depth=invariant_depth,
        width=width,
    )


def _version_contains(version_output: str | None, expected_version: str) -> bool:
    return (
        version_output is not None
        and re.search(
            rf"(?<![0-9.]){re.escape(expected_version)}(?![0-9.])",
            version_output,
        )
        is not None
    )


def _root_project(
    projects: list[SolidityProjectMetadata],
) -> SolidityProjectMetadata | None:
    return min(projects, key=lambda item: len(item.project_root), default=None)


def _safe_source_paths(index: SoliditySymbolIndex) -> list[str]:
    paths: set[str] = set()
    for entity in index.entities:
        try:
            path = normalize_relative_path(entity.path)
        except ValueError:
            continue
        if path.endswith(".sol"):
            paths.add(path)
    return sorted(paths)


def _copy_project(
    repository_root: Path,
    project: SolidityProjectMetadata,
    workspace: Path,
) -> None:
    source = (
        repository_root
        if project.project_root == "."
        else repository_root / normalize_relative_path(project.project_root)
    )
    source = source.resolve(strict=True)
    source.relative_to(repository_root.resolve(strict=True))
    validate_copyable_workspace(
        source,
        excluded=lambda path: _dynamic_workspace_path_excluded(path, source),
    )
    shutil.copytree(source, workspace, ignore=_dynamic_workspace_ignore)


def _dynamic_workspace_ignore(directory: str, names: list[str]) -> set[str]:
    return {
        name
        for name in names
        if name.lower() in _EXCLUDED_DYNAMIC_WORKSPACE_NAMES
        or is_sensitive_workspace_path(
            Path(directory) / name,
            is_dir=(Path(directory) / name).is_dir(),
        )
    }


def _dynamic_workspace_path_excluded(path: Path, source: Path) -> bool:
    relative = path.relative_to(source)
    return any(
        part.lower() in _EXCLUDED_DYNAMIC_WORKSPACE_NAMES for part in relative.parts
    ) or is_sensitive_workspace_path(relative, is_dir=path.is_dir())


def _preparation_artifacts(
    preparation: PropertyEngineTranslation | CertoraPreparation | None,
    field_name: str,
) -> list[str]:
    if not isinstance(preparation, CertoraPreparation):
        return []
    artifacts = {
        "specification_artifacts": preparation.specification_artifacts,
        "assumption_artifacts": preparation.assumption_artifacts,
        "vacuity_artifacts": preparation.vacuity_artifacts,
    }.get(field_name, [])
    return sorted(set(artifacts))


def _redact_sensitive_artifacts(
    paths: tuple[Path, ...],
    sensitive_values: tuple[str, ...],
    *,
    max_bytes: int,
) -> None:
    encoded_values = sorted(
        {value.encode("utf-8") for value in sensitive_values if value},
        key=len,
        reverse=True,
    )
    if not encoded_values:
        return
    for path in paths:
        try:
            if not path.is_file():
                continue
            content = path.read_bytes()[:max_bytes]
            for value in encoded_values:
                content = content.replace(value, b"[REDACTED_FORMAL_SECRET]")
            path.write_bytes(content)
        except OSError:
            continue


def _bounded_process(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    stdout_path: Path,
    stderr_path: Path,
    timeout: float,
    max_output_bytes: int,
    additional_output_paths: list[Path] | None = None,
) -> int | str:
    process: subprocess.Popen[bytes] | None = None
    with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdout=stdout_handle,
            stderr=stderr_handle,
            env=environment,
            shell=False,
            start_new_session=os.name != "nt",
            creationflags=(
                int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)) if os.name == "nt" else 0
            ),
            preexec_fn=_limit_process if os.name != "nt" else None,
        )
        deadline = time.monotonic() + timeout
        while process.poll() is None:
            if time.monotonic() >= deadline:
                _stop_process(process)
                return "timed_out"
            if (
                stdout_path.stat().st_size > max_output_bytes
                or stderr_path.stat().st_size > max_output_bytes
                or any(
                    path.is_file() and path.stat().st_size > max_output_bytes
                    for path in (additional_output_paths or [])
                )
            ):
                _stop_process(process)
                return "output_exceeded"
            time.sleep(0.05)
        return process.wait(timeout=5)


def _isolated_tool_version(
    executable: Path,
    *,
    backend: IsolationBackend,
    workspace: Path,
    private_dir: Path,
    environment: dict[str, str],
    artifact_prefix: str = "",
) -> str | None:
    stdout_path = private_dir / f"{artifact_prefix}version.stdout.txt"
    stderr_path = private_dir / f"{artifact_prefix}version.stderr.txt"
    try:
        command = backend.wrap(
            [str(executable), "--version"],
            workspace=workspace,
            private_dir=private_dir,
            rpc_port=1,
        )
        result = _bounded_process(
            command,
            cwd=workspace,
            environment=environment,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            timeout=10,
            max_output_bytes=100_000,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None
    if result != 0:
        return None
    output = "\n".join(
        (
            _read_bounded(stdout_path, 100_000),
            _read_bounded(stderr_path, 100_000),
        )
    ).strip()
    lines = output.splitlines()
    return lines[0][:200] if lines else None


def _locations_from_text(
    text: str,
    index: SoliditySymbolIndex,
) -> list[Location]:
    locations: list[Location] = []
    for match in re.finditer(r"(?P<path>[A-Za-z0-9_./-]+\.sol):(?P<line>\d+)", text):
        locations.extend(
            _validated_index_locations(
                index,
                match.group("path"),
                int(match.group("line")),
            )
        )
    return locations


def _property_counterexample_evidence(
    tool: str,
    property_name: str,
    summary: str,
    index: SoliditySymbolIndex,
    *,
    counterexample: dict[str, Any] | None = None,
) -> FormalEvidence:
    entity = next((item for item in index.entities if item.name == property_name), None)
    locations = (
        [
            Location(
                path=entity.path,
                start_line=entity.start_line,
                end_line=entity.end_line,
                symbol=entity.name,
                content_hash=entity.source_hash,
            )
        ]
        if entity
        else []
    )
    return FormalEvidence(
        tool=tool,
        property_id=property_name,
        property_description=f"Property engine produced a counterexample for {property_name}",
        status=FormalToolStatus.SUCCESS,
        result_kind=FormalResultKind.COUNTEREXAMPLE,
        assumptions=["Configured bounded property campaign"],
        counterexample=counterexample or {"summary": summary},
        locations=locations,
        confidence=0.95 if locations else 0.7,
    )


def _echidna_counterexample(item: dict[str, Any], serialized: str) -> dict[str, Any]:
    sequence: list[Any] = []
    for key in ("callseq", "sequence", "transactions", "calls"):
        candidate = item.get(key)
        if isinstance(candidate, list):
            sequence = candidate[:64]
            break
    normalized_sequence = [
        value
        if isinstance(value, (str, int, float, bool)) or value is None
        else json.loads(json.dumps(value, sort_keys=True))
        for value in sequence
    ]
    counterexample: dict[str, Any] = {
        "summary": _bounded_summary(serialized),
        "sequence": normalized_sequence,
    }
    for key in ("seed", "test", "error"):
        value = item.get(key)
        if isinstance(value, (str, int, float, bool)):
            counterexample[key] = value
    return counterexample


def _remap_property_engine_evidence(
    evidence: list[FormalEvidence],
    translation: PropertyEngineTranslation,
    corpus: PropertyCorpus,
) -> list[FormalEvidence]:
    remapped: list[FormalEvidence] = []
    for item in evidence:
        property_spec = translation.property_map.get(item.property_id)
        if property_spec is None:
            continue
        counterexample = {
            **item.counterexample,
            "generated_property": item.property_id,
            "property_hash": property_spec.property_hash,
            "corpus_hash": corpus.corpus_hash,
            "replay": {
                "seed": translation.seed,
                "runs": translation.runs,
                "depth": translation.depth,
                "clean_workspace_required": True,
            },
        }
        artifact_paths = [
            f"workspace/{path}"
            for path in (
                translation.source_path,
                translation.configuration_path,
                translation.property_map_path,
            )
            if path
        ]
        if item.tool == "halmos":
            artifact_paths.append("workspace/mmaudit-halmos/halmos.toml")
            artifact_paths.append("halmos/result.json")
        elif item.tool == "kontrol":
            artifact_paths.append("kontrol/stdout.txt")
        remapped.append(
            item.model_copy(
                update={
                    "property_id": property_spec.id,
                    "property_description": property_spec.description,
                    "assumptions": sorted(
                        {
                            *item.assumptions,
                            *property_spec.assumptions,
                            *translation.assumptions,
                        }
                    ),
                    "counterexample": counterexample,
                    "locations": [source.location for source in property_spec.source_evidence],
                    "confidence": min(item.confidence, property_spec.confidence),
                    "artifact_paths": artifact_paths,
                }
            )
        )
    return remapped


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


def _property_name_from_json(value: dict[str, Any]) -> str | None:
    for key in ("name", "property", "test", "testName", "propertyName"):
        candidate = value.get(key)
        if not isinstance(candidate, str):
            continue
        match = re.search(r"\b(?P<name>(?:echidna_|invariant_)[A-Za-z0-9_]+)\b", candidate)
        if match is not None:
            return match.group("name")
    return None


def _validated_index_locations(
    index: SoliditySymbolIndex,
    raw_path: str,
    line: int,
) -> list[Location]:
    try:
        path = normalize_relative_path(raw_path)
    except ValueError:
        return []
    matching = [
        entity
        for entity in index.entities
        if entity.path == path and entity.start_line <= line <= entity.end_line
    ]
    if not matching:
        return []
    entity = min(matching, key=lambda item: item.end_line - item.start_line)
    return [
        Location(
            path=path,
            start_line=line,
            end_line=line,
            symbol=entity.name,
            content_hash=entity.source_hash,
        )
    ]


def _positive_int(value: Any) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return 1


def _bounded_summary(value: str) -> str:
    return " ".join(value.split())[:2_000]


def _read_bounded(path: Path, limit: int) -> str:
    if not path.exists():
        return ""
    with path.open("rb") as handle:
        return handle.read(limit).decode("utf-8", errors="replace")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _redacted_command(
    command: list[str],
    *,
    workspace: Path,
    private_dir: Path,
    dependencies: list[FormalDependencySpec],
) -> list[str]:
    dependency_paths = {
        str(dependency.executable): f"[DEPENDENCY:{dependency.name}]" for dependency in dependencies
    }
    dependency_paths.update(
        {
            shlex.join([str(dependency.executable)]): f"[DEPENDENCY:{dependency.name}]"
            for dependency in dependencies
        }
    )
    redacted = ["[EXTERNAL_TOOL]"]
    for argument in command[1:]:
        if argument in dependency_paths:
            redacted.append(dependency_paths[argument])
            continue
        replaced = argument
        for root, label in (
            (workspace, "[WORKSPACE]"),
            (private_dir, "[PRIVATE]"),
        ):
            raw_root = str(root)
            if argument == raw_root:
                replaced = label
                break
            if argument.startswith(f"{raw_root}{os.sep}"):
                relative = Path(argument).relative_to(root).as_posix()
                replaced = f"{label}/{relative}"
                break
        redacted.append(replaced)
    return redacted


def _limit_process() -> None:
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (600, 600))
        resource.setrlimit(resource.RLIMIT_FSIZE, (100_000_000, 100_000_000))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        if hasattr(resource, "RLIMIT_NPROC"):
            resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        if hasattr(resource, "RLIMIT_AS"):
            resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
    except (ImportError, OSError, ValueError):
        return


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        process.kill()
