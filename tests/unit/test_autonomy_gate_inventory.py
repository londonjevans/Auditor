from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from collections import Counter
from pathlib import Path
from typing import Literal

import pytest
from pydantic import Field, ValidationError, create_model

import mmaudit.orchestration.autonomy_gate_inventory as inventory_module
from mmaudit.config import AuditConfig, AuditRunOptions
from mmaudit.models.schemas import StrictModel
from mmaudit.orchestration.autonomy_gate_inventory import (
    AUTONOMY_INVENTORY_PATH,
    AutonomousGateDisposition,
    AutonomyGateInventory,
    AutonomyInventoryError,
    CompletionInputSourceKind,
    GateImplementationState,
    SourceCoverageClassification,
    _audit_gate_for_path,
    _discover_audited_module_sources,
    _discover_completion_entrypoint_sources,
    _discover_direct_environment_sources,
    _discover_external_input_sources,
    build_autonomy_gate_inventory,
    load_autonomy_gate_inventory,
    render_autonomy_gate_inventory,
)

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def inventory() -> AutonomyGateInventory:
    return build_autonomy_gate_inventory(repository_root=ROOT)


def test_inventory_freezes_the_exact_recursive_source_universe(
    inventory: AutonomyGateInventory,
) -> None:
    assert inventory.source_count == 3618
    assert inventory.source_occurrence_count == 3621
    assert inventory.audit_config_leaf_locator_count == 505
    assert inventory.audit_config_leaf_occurrence_count == 508
    assert inventory.audit_config_shared_locator_count == 3
    assert inventory.audit_run_option_leaf_count == 13
    assert inventory.audit_override_path_count == 45
    assert inventory.environment_override_count == 28
    assert inventory.cli_run_parameter_count == 50
    assert inventory.pipeline_init_parameter_count == 25
    assert inventory.pipeline_run_parameter_count == 15
    assert inventory.completion_entrypoint_parameter_count == 299
    assert {kind.value: count for kind, count in inventory.source_kind_counts.items()} == {
        "AUDIT_CONFIG_LEAF": 505,
        "AUDIT_RUN_OPTION_LEAF": 13,
        "AUDIT_OVERRIDE_PATH": 45,
        "ENVIRONMENT_OVERRIDE": 28,
        "CLI_RUN_PARAMETER": 50,
        "PIPELINE_INIT_PARAMETER": 25,
        "PIPELINE_RUN_PARAMETER": 15,
        "COMPLETION_ENTRYPOINT_PARAMETER": 299,
        "DIRECT_ENVIRONMENT_INPUT": 453,
        "ENTROPY_INPUT": 17,
        "AUDITED_MODULE_UNIVERSE": 228,
        "EXPLICIT_NON_FIELD_GATE": 1926,
        "REQUIRED_MISSING_GATE": 14,
    }
    assert Counter(source.classification for source in inventory.source_coverage) == {
        SourceCoverageClassification.GATE: 3575,
        SourceCoverageClassification.NON_GATING_CONTROL: 43,
    }
    assert {item.value for item in SourceCoverageClassification} == {
        "GATE",
        "NON_GATING_CONTROL",
    }
    assert sum(":wall-clock:" in source.source_path for source in inventory.source_coverage) == 99
    assert (
        sum(":working-directory:" in source.source_path for source in inventory.source_coverage)
        == 110
    )
    assert (
        sum(":process-identity" in source.source_path for source in inventory.source_coverage) == 44
    )
    assert (
        sum(
            source.source_kind is CompletionInputSourceKind.ENTROPY_INPUT
            for source in inventory.source_coverage
        )
        == 17
    )
    assert (
        sum(":content-read:" in source.source_path for source in inventory.source_coverage) == 271
    )
    assert (
        sum(":directory-enumeration:" in source.source_path for source in inventory.source_coverage)
        == 71
    )
    assert (
        sum(":metadata-observation:" in source.source_path for source in inventory.source_coverage)
        == 1569
    )
    assert all(
        source.classification is SourceCoverageClassification.GATE
        for source in inventory.source_coverage
        if source.source_kind
        in {
            CompletionInputSourceKind.AUDIT_CONFIG_LEAF,
            CompletionInputSourceKind.AUDIT_RUN_OPTION_LEAF,
            CompletionInputSourceKind.AUDIT_OVERRIDE_PATH,
            CompletionInputSourceKind.ENVIRONMENT_OVERRIDE,
            CompletionInputSourceKind.PIPELINE_INIT_PARAMETER,
            CompletionInputSourceKind.PIPELINE_RUN_PARAMETER,
            CompletionInputSourceKind.DIRECT_ENVIRONMENT_INPUT,
            CompletionInputSourceKind.AUDITED_MODULE_UNIVERSE,
            CompletionInputSourceKind.EXPLICIT_NON_FIELD_GATE,
            CompletionInputSourceKind.REQUIRED_MISSING_GATE,
        }
    )


def test_inventory_has_exact_autonomous_dispositions_and_honest_phase_zero_state(
    inventory: AutonomyGateInventory,
) -> None:
    assert {gate.desired_disposition for gate in inventory.logical_gates} == set(
        AutonomousGateDisposition
    )
    assert {item.value for item in AutonomousGateDisposition} == {
        "AUTONOMOUS_EVIDENCE_SUBSTITUTE",
        "PREPROVISIONED_NONHUMAN_INPUT",
        "PRERUN_CLIENT_DECISION",
        "OBJECTIVE_OUT_OF_SCOPE",
    }
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 16
    assert inventory.runtime_authority is False
    assert inventory.managed_run_ready is False
    assert inventory.provider_or_network_accessed is False
    assert inventory.secret_material_read is False
    assert inventory.completion_scope == "SYNTHETIC_PUBLIC_ONLY"
    assert inventory.discovery_scope == (
        "TYPED_BOUNDARIES_REGISTERED_ENTRYPOINTS_RUNTIME_PACKAGE_RESOURCES_"
        "UNSEALED_ENV_HOST_WALL_CLOCK_AUTHORITY_ENTROPY_FILESYSTEM_INTERACTIVE_"
        "OPAQUE_AUTHORITIES_"
        "EXPLICIT_MISSING_OBJECTIVE_BOUNDARIES"
    )
    assert inventory.private_repository_completion_in_scope is False


def test_every_gate_source_has_exactly_one_logical_assignment(
    inventory: AutonomyGateInventory,
) -> None:
    covered = {
        source.source_id
        for source in inventory.source_coverage
        if source.classification is SourceCoverageClassification.GATE
    }
    assigned = [source_id for gate in inventory.logical_gates for source_id in gate.source_ids]
    assert len(assigned) == len(set(assigned))
    assert set(assigned) == covered
    assert all(
        source.logical_gate_id is None
        for source in inventory.source_coverage
        if source.source_id not in covered
    )


def test_unresolved_findings_and_external_authorities_remain_separately_unsatisfied(
    inventory: AutonomyGateInventory,
) -> None:
    gates = {gate.gate_id: gate for gate in inventory.logical_gates}
    unresolved = gates["gate-unresolved-finding-disposition"]
    assert unresolved.implementation_state is GateImplementationState.MISSING
    assert {
        "explicit:post-judge-manual-review-incomplete-branch",
        "explicit:consensus-needs-review-status",
        "required:autonomous-unresolved-finding-terminal-resolution",
    } <= set(unresolved.source_ids)
    assert gates["gate-external-transparency-seal"].implementation_state is (
        GateImplementationState.MISSING
    )
    assert gates["gate-trusted-time-independent-replay"].implementation_state is (
        GateImplementationState.MISSING
    )
    assert set(gates["gate-external-transparency-seal"].source_ids).isdisjoint(
        gates["gate-trusted-time-independent-replay"].source_ids
    )


def test_equivalent_config_and_cli_boundaries_use_consistent_primary_gates() -> None:
    assert _audit_gate_for_path("language_profile") == "gate-client-audit-scope"
    assert _audit_gate_for_path("smart_contracts.project_root") == "gate-client-audit-scope"
    assert _audit_gate_for_path("smart_contracts.allow_network") == "gate-dependency-snapshot"
    assert _audit_gate_for_path("maximum_assurance.benchmark_gate") == (
        "gate-benchmark-evidence-authority"
    )
    assert _audit_gate_for_path("execution.conservative_usd_per_million_tokens") == (
        "gate-budget-ceiling"
    )
    assert inventory_module._command_parameter_classification(
        "models_authenticated_runner_smoke", "smoke_corpus"
    ) == (SourceCoverageClassification.GATE, "gate-authenticated-real-campaign")


def test_committed_inventory_is_canonical_self_hashed_and_current(
    inventory: AutonomyGateInventory,
) -> None:
    path = ROOT / AUTONOMY_INVENTORY_PATH
    assert path.read_text(encoding="utf-8") == render_autonomy_gate_inventory(repository_root=ROOT)
    assert load_autonomy_gate_inventory(path) == inventory
    assert render_autonomy_gate_inventory(repository_root=ROOT) == (
        render_autonomy_gate_inventory(repository_root=ROOT)
    )


class _InnocuousNestedConfig(StrictModel):
    harmless_counter: int = 0


class _AuditConfigWithNewLeaf(AuditConfig):
    innocuous: _InnocuousNestedConfig = Field(default_factory=_InnocuousNestedConfig)


class _AuditRunOptionsWithNewLeaf(AuditRunOptions):
    innocuous: bool = False


def test_new_innocuously_named_config_and_run_option_leaves_fail_closed() -> None:
    with pytest.raises(AutonomyInventoryError, match="AuditConfig leaves"):
        build_autonomy_gate_inventory(
            repository_root=ROOT, audit_config_model=_AuditConfigWithNewLeaf
        )
    with pytest.raises(AutonomyInventoryError, match="AuditRunOptions leaves"):
        build_autonomy_gate_inventory(
            repository_root=ROOT,
            audit_run_options_model=_AuditRunOptionsWithNewLeaf,
        )


def test_new_override_and_environment_entries_fail_closed() -> None:
    from mmaudit.config import _AUDIT_OVERRIDE_VALUE_TYPES, _ENVIRONMENT_OVERRIDE_MAPPINGS

    overrides = dict(_AUDIT_OVERRIDE_VALUE_TYPES)
    overrides["innocuous.harmless_counter"] = (int,)
    with pytest.raises(AutonomyInventoryError, match="audit override allowlist"):
        build_autonomy_gate_inventory(repository_root=ROOT, audit_override_value_types=overrides)
    environment = dict(_ENVIRONMENT_OVERRIDE_MAPPINGS)
    environment["MMAUDIT_INNOCUOUS_COUNTER"] = ("innocuous.harmless_counter", int)
    with pytest.raises(AutonomyInventoryError, match="environment override allowlist"):
        build_autonomy_gate_inventory(
            repository_root=ROOT, environment_override_mappings=environment
        )


def test_new_cli_and_pipeline_parameters_fail_closed() -> None:
    def changed_cli(innocuous: bool = False) -> None:
        del innocuous

    def changed_pipeline_init(self: object, innocuous: bool = False) -> None:
        del self, innocuous

    async def changed_pipeline_run(self: object, innocuous: bool = False) -> None:
        del self, innocuous

    with pytest.raises(AutonomyInventoryError, match="run_command parameters"):
        build_autonomy_gate_inventory(repository_root=ROOT, cli_run_command=changed_cli)
    with pytest.raises(AutonomyInventoryError, match=r"AuditPipeline\.__init__ parameters"):
        build_autonomy_gate_inventory(repository_root=ROOT, pipeline_init=changed_pipeline_init)
    with pytest.raises(AutonomyInventoryError, match=r"AuditPipeline\.run parameters"):
        build_autonomy_gate_inventory(repository_root=ROOT, pipeline_run=changed_pipeline_run)


def test_new_auxiliary_completion_entrypoint_parameter_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = inventory_module._registered_cli_commands()

    def new_completion_command(innocuous: bool = False) -> None:
        del innocuous

    monkeypatch.setattr(
        inventory_module,
        "_registered_cli_commands",
        lambda: (*current, ("new_completion_command", new_completion_command)),
    )
    with pytest.raises(AutonomyInventoryError, match="completion entrypoint parameters"):
        _discover_completion_entrypoint_sources()
    with pytest.raises(AutonomyInventoryError, match="unclassified completion command parameter"):
        inventory_module._command_parameter_classification("new_completion_command", "innocuous")


def test_existing_field_semantics_drift_changes_the_objective_source_universe() -> None:
    changed_model = create_model(
        "AuditConfigWithChangedSemantics",
        __base__=AuditConfig,
        version=(Literal[1], Field(default=1, description="semantics-only mutation")),
    )

    baseline = build_autonomy_gate_inventory(repository_root=ROOT)
    changed = build_autonomy_gate_inventory(
        repository_root=ROOT,
        audit_config_model=changed_model,
    )
    assert changed.source_universe_sha256 != baseline.source_universe_sha256
    assert changed.inventory_sha256 != baseline.inventory_sha256


def test_new_runtime_resource_and_interactive_input_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "mmaudit"
    source_root.mkdir()
    (source_root / "new_resource.dat").write_text("bounded", encoding="utf-8")
    assert [
        path.relative_to(source_root).as_posix()
        for path in inventory_module._runtime_package_paths(source_root)
    ] == ["new_resource.dat"]
    with pytest.raises(AutonomyInventoryError, match="runtime package paths"):
        _discover_audited_module_sources(source_root)
    monkeypatch.setattr(
        inventory_module,
        "_FROZEN_AUDITED_MODULE_PATHS_SHA256",
        inventory_module._canonical_sha256(["new_resource.dat"]),
    )
    before = _discover_audited_module_sources(source_root)[0].source_semantics_sha256
    (source_root / "new_resource.dat").write_text("changed bytes", encoding="utf-8")
    after = _discover_audited_module_sources(source_root)[0].source_semantics_sha256
    assert after != before
    (source_root / "new_gate.py").write_text(
        "from builtins import input as ask\ndef request_operator():\n    return ask('approve?')\n",
        encoding="utf-8",
    )
    filesystem, interactive = inventory_module._external_input_occurrences(source_root)
    assert filesystem == ()
    assert [(path, scope) for path, scope, _ in interactive] == [
        ("new_gate.py", "request_operator")
    ]
    assert "approve?" in interactive[0][2]
    with pytest.raises(AutonomyInventoryError, match="interactive operator input loci"):
        _discover_external_input_sources(source_root)


def test_new_aliased_filesystem_read_fails_closed(tmp_path: Path) -> None:
    source_root = tmp_path / "mmaudit"
    source_root.mkdir()
    (source_root / "new_reader.py").write_text(
        "from os import F_OK, O_RDONLY, access as permitted, fstat as descriptor_status\n"
        "from os import listdir as members, open as raw_open, stat as status\n"
        "from os.path import lexists as link_exists\n"
        "from pathlib import Path as P\n"
        "from shutil import copy2 as clone\n"
        "read_path = P.read_text\n"
        "list_path = P.iterdir\n"
        "path_exists = P.exists\n"
        "def read_external():\n"
        "    raw_open('opaque', O_RDONLY)\n"
        "    clone('source', 'destination')\n"
        "    members('.')\n"
        "    status('opaque')\n"
        "    permitted('opaque', F_OK)\n"
        "    descriptor_status(0)\n"
        "    tuple(P('.').iterdir())\n"
        "    P('opaque').is_junction()\n"
        "    getattr(P('opaque'), 'is_junction', lambda: False)()\n"
        "    link_exists('opaque')\n"
        "    read_path(P('opaque'))\n"
        "    tuple(list_path(P('.')))\n"
        "    path_exists(P('opaque'))\n"
        "    return P('opaque').read_text()\n",
        encoding="utf-8",
    )
    filesystem, interactive = inventory_module._external_input_occurrences(source_root)
    assert interactive == ()
    assert Counter(kind for _, _, kind, _ in filesystem) == {
        "content-read": 4,
        "directory-enumeration": 3,
        "metadata-observation": 7,
    }
    assert {(path, scope) for path, scope, _, _ in filesystem} == {
        ("new_reader.py", "read_external")
    }
    with pytest.raises(AutonomyInventoryError, match="unclassified filesystem input authority"):
        inventory_module._filesystem_input_gate("new_reader.py", "read_external")
    with pytest.raises(AutonomyInventoryError, match="filesystem input loci"):
        _discover_external_input_sources(source_root)


def test_new_aliased_wall_clock_read_fails_closed(tmp_path: Path) -> None:
    source_root = tmp_path / "mmaudit"
    source_root.mkdir()
    (source_root / "new_clock.py").write_text(
        "from elsewhere import clock\n"
        "from datetime import UTC, datetime as D\n"
        "import os\n"
        "from os.path import abspath as absolute_name\n"
        "from pathlib import Path\n"
        "clock = D.now\n"
        "current_uid = getattr(os, 'getuid', lambda: 0)\n"
        "trusted_process = os.getpid\n"
        "def authority_time():\n"
        "    return (clock(UTC), current_uid(), trusted_process(), "
        "absolute_name('x'), Path('x').absolute())\n"
        "def custom_attribute_is_not_os(custom):\n"
        "    trusted = custom.getpid\n"
        "    return trusted()\n",
        encoding="utf-8",
    )
    occurrences = inventory_module._direct_environment_occurrences(source_root)
    assert Counter((path, scope, kind) for path, scope, kind, _ in occurrences) == {
        ("new_clock.py", "authority_time", "host-identity"): 1,
        ("new_clock.py", "authority_time", "process-identity"): 1,
        ("new_clock.py", "authority_time", "wall-clock"): 1,
        ("new_clock.py", "authority_time", "working-directory"): 2,
        ("new_clock.py", "module", "process-identity-binding"): 1,
    }
    assert any("clock" in expression for *_, expression in occurrences)
    assert all("custom" not in expression for *_, expression in occurrences)
    with pytest.raises(AutonomyInventoryError, match="direct environment and PATH-resolution"):
        _discover_direct_environment_sources(source_root)


def test_filesystem_privacy_provenance_has_exact_nonfallback_gate() -> None:
    assert (
        inventory_module._filesystem_input_gate(
            "repository/privacy_provenance.py", "classify_repository_source"
        )
        == "gate-synthetic-public-scope"
    )
    assert (
        inventory_module._filesystem_input_gate(
            "solidity/invariant_execution.py", "FoundryInvariantRunner._execute"
        )
        == "gate-full-quality-analysis"
    )


@pytest.mark.parametrize(
    ("relative_path", "scope", "expected_gate"),
    [
        (
            "models/authenticated_runner_durable_bundle.py",
            "load_authenticated_runner_durable_bundle",
            "gate-managed-output-provisioning",
        ),
        (
            "scanners/trusted_inputs.py",
            "_validated_private_directory",
            "gate-managed-toolchain-bundle",
        ),
        (
            "isolation/provenance.py",
            "_run_builtin_preflight",
            "gate-reproduction-capability-policy",
        ),
        (
            "isolation/provenance.py",
            "_trusted_helper",
            "gate-managed-toolchain-bundle",
        ),
        (
            "isolation/container.py",
            "discover_rootless_container_backend",
            "gate-managed-toolchain-bundle",
        ),
        (
            "isolation/container.py",
            "SingleLoopbackHardhatBackend.bridge_socket_path",
            "gate-fork-environment",
        ),
        (
            "scanners/fork_matrix.py",
            "_open_private_root",
            "gate-managed-output-provisioning",
        ),
        (
            "scanners/read_only_rpc.py",
            "ReadOnlyRpcBridge.start",
            "gate-fork-environment",
        ),
        ("solidity/formal.py", "_read_halmos_plan", "gate-formal-analysis"),
        (
            "solidity/formal.py",
            "FormalAdapter.available",
            "gate-managed-toolchain-bundle",
        ),
    ],
)
def test_filesystem_primary_gate_map_is_scope_specific(
    relative_path: str,
    scope: str,
    expected_gate: str,
) -> None:
    assert inventory_module._filesystem_input_gate(relative_path, scope) == expected_gate


def test_write_only_opens_are_not_filesystem_content_inputs(tmp_path: Path) -> None:
    source_root = tmp_path / "mmaudit"
    source_root.mkdir()
    (source_root / "writer.py").write_text(
        "from os import O_CREAT, O_EXCL, O_WRONLY, open as descriptor_open\n"
        "from pathlib import Path\n"
        "def write_only():\n"
        "    Path('plain').open('wb')\n"
        "    descriptor_open('plain', O_WRONLY | O_CREAT)\n"
        "    descriptor_open('exclusive', O_WRONLY | O_CREAT | O_EXCL)\n",
        encoding="utf-8",
    )
    filesystem, interactive = inventory_module._external_input_occurrences(source_root)
    assert interactive == ()
    assert [(path, scope, kind) for path, scope, kind, _ in filesystem] == [
        ("writer.py", "write_only", "metadata-observation")
    ]


def test_authority_entropy_alias_is_detected_without_a_default_gate(tmp_path: Path) -> None:
    source_root = tmp_path / "mmaudit"
    source_root.mkdir()
    (source_root / "entropy.py").write_text(
        "from uuid import uuid4 as new_id\ndef authority_id():\n    return new_id().hex\n",
        encoding="utf-8",
    )
    occurrences = inventory_module._entropy_input_occurrences(source_root)
    assert [(path, scope, kind) for path, scope, kind, _ in occurrences] == [
        ("entropy.py", "authority_id", "uuid.uuid4")
    ]
    with pytest.raises(AutonomyInventoryError, match="unclassified entropy input authority"):
        inventory_module._entropy_input_classification("entropy.py", "authority_id")


def test_objective_drift_fails_before_any_runtime_discovery(tmp_path: Path) -> None:
    objective = tmp_path / "docs" / "remediation" / "v3" / "product_completion_goal.txt"
    objective.parent.mkdir(parents=True)
    objective.write_text("drifted objective\n", encoding="utf-8")
    with pytest.raises(AutonomyInventoryError, match="objective bytes drifted"):
        build_autonomy_gate_inventory(repository_root=tmp_path)


def test_missing_duplicate_and_multiple_assignments_are_rejected(
    inventory: AutonomyGateInventory,
) -> None:
    values = inventory.model_dump(mode="json")
    values["source_coverage"] = values["source_coverage"][:-1]
    with pytest.raises(ValidationError):
        AutonomyGateInventory.model_validate(values)

    values = inventory.model_dump(mode="json")
    values["source_coverage"].append(values["source_coverage"][0])
    with pytest.raises(ValidationError):
        AutonomyGateInventory.model_validate(values)

    values = inventory.model_dump(mode="json")
    first_source = values["logical_gates"][0]["source_ids"][0]
    second_sources = set(values["logical_gates"][1]["source_ids"])
    second_sources.add(first_source)
    values["logical_gates"][1]["source_ids"] = sorted(second_sources)
    with pytest.raises(ValidationError):
        AutonomyGateInventory.model_validate(values)


def test_cold_generation_is_provider_network_and_secret_free() -> None:
    assay = textwrap.dedent(
        f"""
        import os
        import socket
        from collections import UserDict
        from pathlib import Path

        class GuardedEnvironment(UserDict):
            def _guard(self, key):
                text = str(key).upper()
                if any(token in text for token in ("SECRET", "TOKEN", "API_KEY", "OPENROUTER")):
                    raise AssertionError(f"sensitive environment key was read: {{key}}")

            def __getitem__(self, key):
                self._guard(key)
                return super().__getitem__(key)

            def __contains__(self, key):
                self._guard(key)
                return super().__contains__(key)

        def forbidden(*args, **kwargs):
            raise AssertionError("network access is forbidden during inventory generation")

        class GuardedSocket(socket.socket):
            def connect(self, *args, **kwargs):
                return forbidden(*args, **kwargs)

            def connect_ex(self, *args, **kwargs):
                return forbidden(*args, **kwargs)

        safe = dict(os.environ)
        safe["OPENROUTER_API_KEY"] = "must-not-be-read"
        os.environ = GuardedEnvironment(safe)
        os.getenv = lambda key, default=None: os.environ.get(key, default)
        socket.socket = GuardedSocket
        socket.create_connection = forbidden
        socket.getaddrinfo = forbidden
        socket.gethostbyname = forbidden
        socket.gethostbyname_ex = forbidden

        from mmaudit.orchestration.autonomy_gate_inventory import build_autonomy_gate_inventory

        generated = build_autonomy_gate_inventory(repository_root=Path({str(ROOT)!r}))
        assert generated.provider_or_network_accessed is False
        assert generated.secret_material_read is False
        """
    )
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(ROOT / "src"),
    }
    completed = subprocess.run(
        [sys.executable, "-c", assay],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
