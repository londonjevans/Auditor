"""Original-owner manifest replay from disposable files; no provider or engine execution."""

import socket
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import BaseModel

import mmaudit.operator_secrets as secrets_module
from mmaudit.models.schemas import AuditReport
from mmaudit.models.sharding import SolidityGraphsArtifact, SolidityIndexArtifact
from mmaudit.orchestration import manifest, pipeline
from mmaudit.privacy import EffectivePrivacyPolicyEvidence, PrivacySourceClassification
from mmaudit.repository.privacy_provenance import PrivacySourceProvenanceEvidence
from tests.truncation_tree_assurance_support import build_complete_tree_assurance_fixture
from tests.unit import test_assurance as assurance
from tests.unit.test_truncation_tree_manifest import _manifest_arguments


@pytest.fixture(autouse=True)
def no_provider_or_operator_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Allow existing bounded synthetic signing, but no network or operator credentials."""

    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError(
            "private-file integration must not access providers or operator secrets"
        )

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(secrets_module, "load_operator_secrets", forbidden)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbidden)


def _write_model(path: Path, value: BaseModel) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(value.model_dump_json(indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _read_arguments(root: Path, arguments: dict[str, Any]) -> dict[str, Any]:
    report = AuditReport.model_validate_json((root / "report.json").read_bytes())
    index, graphs = manifest._load_model_review_semantic_authority(root)
    return arguments | {
        "report": report,
        "inventory": manifest._load_model_review_artifact_inventory(root, report),
        "promoted_inventory": manifest._load_promoted_model_review_artifact_inventory(root, report),
        "index": index,
        "graphs": graphs,
    }


def test_original_campaign_replays_private_files_and_refuses_coherent_omissions(
    config_factory: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = assurance._maximum_config(
        lambda **sections: config_factory(**sections, execution={"budget_usd": 250})
    )
    root = tmp_path / "model-review-run"
    (root / "private").mkdir(parents=True, mode=0o700)
    create_original = assurance.create_scheduler_journal
    observed_custodies = []

    def observe_original_creation(path: Path, **kwargs: Any) -> Any:
        assert path == root / "private" / "scheduler-journal" and not path.exists()
        provenance = PrivacySourceProvenanceEvidence.model_validate_json(
            (root / "privacy-source-provenance.json").read_bytes()
        )
        policy = EffectivePrivacyPolicyEvidence.model_validate_json(
            (root / "privacy-policy.json").read_bytes()
        )
        emitted = pipeline._build_scheduler_privacy_evidence_custody(
            root, provenance=provenance, policy=policy
        )
        assert kwargs["privacy_evidence_custody"] == emitted
        assert kwargs["bindings"].privacy_evidence_custody_sha256 == emitted.custody_sha256
        observed_custodies.append(emitted)
        return create_original(path, **kwargs)

    # Observe real creation without replacing its admission or retained-custody behavior.
    monkeypatch.setattr(assurance, "create_scheduler_journal", observe_original_creation)
    fixture = build_complete_tree_assurance_fixture(config, root / "private" / "scheduler-journal")
    try:
        assert observed_custodies == [fixture.privacy.custody]
        arguments = _manifest_arguments(config, fixture)
        original_journal = fixture.journal.artifact()
        raw_path = root / manifest.MODEL_REVIEW_ARTIFACT_INVENTORY_PATH
        promoted_path = root / manifest.PROMOTED_MODEL_REVIEW_ARTIFACT_INVENTORY_PATH
        index_path = root / "solidity-index.json"
        graphs_path = root / "solidity-graphs.json"
        index_artifact = SolidityIndexArtifact(index=fixture.source.index)
        _write_model(root / "report.json", arguments["report"])
        _write_model(raw_path, arguments["inventory"])
        _write_model(promoted_path, arguments["promoted_inventory"])
        _write_model(index_path, index_artifact)
        _write_model(graphs_path, SolidityGraphsArtifact(graphs=fixture.source.graphs))
        loaded = _read_arguments(root, arguments)
        assert loaded["report"] == arguments["report"]
        assert loaded["inventory"] == arguments["inventory"]
        assert loaded["promoted_inventory"] == arguments["promoted_inventory"]
        assert loaded["index"] == fixture.source.index
        assert loaded["graphs"] == fixture.source.graphs
        assert loaded["report"].model_review_coverage.critical_gate_passed
        assert not loaded["report"].completed
        with fixture.journal.open_privacy_evidence_custody() as custody:
            assert custody == fixture.privacy.custody
            manifest._validate_scheduler_privacy_artifacts(
                root=root, report=loaded["report"], custody=custody
            )
            manifest.validate_report_privacy_consistency(
                loaded["report"],
                source_tree_sha256=fixture.source.scheduler_shards.source_tree_sha256,
                expected_source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
            )
            for name in (custody.source_provenance_path, custody.effective_policy_path):
                path = root / name
                original = path.read_bytes()
                try:
                    path.write_bytes(original + b"\n")
                    # Named invariant: semantically equal later bytes cannot replace intake bytes.
                    with pytest.raises(ValueError):
                        manifest._validate_scheduler_privacy_artifacts(
                            root=root, report=loaded["report"], custody=custody
                        )
                finally:
                    path.write_bytes(original)
            manifest._validate_scheduler_privacy_artifacts(
                root=root, report=loaded["report"], custody=custody
            )
        manifest._validate_model_review_artifact_inventory_against_scheduler(**loaded)

        inventory = arguments["inventory"]
        root_id = fixture.projection.parent_usage_record.request_id
        bridge_ids = tuple(usage.request_id for usage in fixture.projection.bridge_usage_records)
        contexts = {item.request_id: item for item in inventory.context_authorities}
        leaf = fixture.projection.artifact.children[0].surface_artifact
        altered_inventories = (
            inventory.model_copy(
                update={
                    "context_authorities": tuple(
                        item for item in inventory.context_authorities if item.request_id != root_id
                    )
                }
            ),
            inventory.model_copy(
                update={
                    "context_authorities": tuple(
                        item.model_copy(update={"context": contexts[bridge_ids[1]].context})
                        if item.request_id == bridge_ids[0]
                        else item
                        for item in inventory.context_authorities
                    )
                }
            ),
            inventory.model_copy(
                update={
                    "artifacts": tuple(
                        artifact
                        for artifact in inventory.artifacts
                        if artifact.artifact_sha256 != leaf.artifact_sha256
                    )
                }
            ),
        )
        for altered in altered_inventories:
            _write_model(raw_path, altered)
            decoded = _read_arguments(root, arguments)
            assert decoded["inventory"] == altered
            # Named invariant: canonical comparison files cannot replace original source custody.
            with pytest.raises(ValueError):
                manifest._validate_model_review_artifact_inventory_against_scheduler(**decoded)
        _write_model(raw_path, inventory)
        _write_model(
            index_path,
            SolidityIndexArtifact(index=fixture.source.index.model_copy(update={"entities": []})),
        )
        with pytest.raises(ValueError):
            manifest._validate_model_review_artifact_inventory_against_scheduler(
                **_read_arguments(root, arguments)
            )
        _write_model(index_path, index_artifact)
        manifest._validate_model_review_artifact_inventory_against_scheduler(
            **_read_arguments(root, arguments)
        )
        assert fixture.journal.artifact() == original_journal
    finally:
        fixture.close()
