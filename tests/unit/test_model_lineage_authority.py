from __future__ import annotations

import copy
import json
import pickle
import subprocess
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.lineage_authority import (
    LINEAGE_AUTHORITY_NAMESPACE,
    ModelLineageAuthorityEnvelope,
    ModelLineageAuthorityError,
    ModelLineageReviewArtifact,
    TrustedModelLineageReviewVerification,
    build_model_lineage_authority_envelope,
    build_model_lineage_authority_statement,
    build_model_lineage_trust_anchor,
    load_model_lineage_authority_bundle,
    load_model_lineage_trust_anchor,
    model_lineage_authority_statement_bytes,
    trusted_ssh_keygen_sha256,
    verify_operator_model_lineage_authority,
    write_model_lineage_authority_envelope,
)
from mmaudit.models.qualification import CandidateRegistry
from mmaudit.release_io import write_json_evidence
from tests.unit import test_model_lineage_review as lineage_fixtures


def _ssh_keygen() -> Path:
    candidate = Path("/usr/bin/ssh-keygen")
    if not candidate.is_file():
        pytest.skip("fixed system ssh-keygen is unavailable")
    return candidate


def _generate_key(root: Path, *, name: str = "operator") -> tuple[Path, str]:
    executable = _ssh_keygen()
    key = root / name
    result = subprocess.run(
        [
            str(executable),
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "",
            "-f",
            str(key),
        ],
        check=False,
        capture_output=True,
        timeout=10,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        shell=False,
    )
    if result.returncode != 0:
        pytest.skip("system ssh-keygen cannot generate an ephemeral Ed25519 test key")
    public_key = " ".join(key.with_suffix(".pub").read_text(encoding="ascii").split()[:2])
    return key, public_key


def _signed_authority(
    *,
    root: Path,
    artifact: ModelLineageReviewArtifact,
    signed_at=lineage_fixtures.CREATED_AT,
    expires_at=lineage_fixtures.CREATED_AT + timedelta(days=1),
) -> tuple[Any, Any, TrustedModelLineageReviewVerification]:
    key, public_key = _generate_key(root)
    anchor = build_model_lineage_trust_anchor(
        operator_principal="synthetic-lineage-reviewer",
        public_key=public_key,
        verifier_executable_sha256=trusted_ssh_keygen_sha256(),
    )
    statement = build_model_lineage_authority_statement(
        artifact=artifact,
        trust_anchor=anchor,
        signed_at=signed_at,
        expires_at=expires_at,
    )
    message = root / "lineage-statement.json"
    message.write_bytes(model_lineage_authority_statement_bytes(statement))
    result = subprocess.run(
        [
            str(_ssh_keygen()),
            "-Y",
            "sign",
            "-f",
            str(key),
            "-n",
            LINEAGE_AUTHORITY_NAMESPACE,
            str(message),
        ],
        check=False,
        capture_output=True,
        timeout=10,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        shell=False,
    )
    assert result.returncode == 0
    envelope = build_model_lineage_authority_envelope(
        statement=statement,
        detached_signature=message.with_suffix(".json.sig").read_bytes(),
    )
    capability = verify_operator_model_lineage_authority(
        artifact=artifact,
        envelope=envelope,
        trust_anchor=anchor,
        observed_at=signed_at + timedelta(minutes=1),
    )
    return anchor, envelope, capability


def test_signed_lineage_authority_is_exact_opaque_and_non_authorizing(tmp_path: Path) -> None:
    bundle = lineage_fixtures._bundle()
    artifact = lineage_fixtures._artifact(bundle)
    anchor, envelope, capability = _signed_authority(root=tmp_path, artifact=artifact)

    verified = capability.require_for(
        candidate_registry=bundle.registry,
        discovery_manifest=bundle.manifest,
        campaign_started_at=lineage_fixtures.CREATED_AT + timedelta(hours=1),
        observed_at=lineage_fixtures.CREATED_AT + timedelta(hours=2),
    )

    assert verified.review_artifact_sha256 == artifact.artifact_sha256
    assert verified.authority_envelope_sha256 == envelope.authority_envelope_sha256
    assert tuple(item.exact_model_id for item in verified.candidates) == ("alpha/atlas",)
    assert envelope.statement.calibration_identity_authorized is True
    assert envelope.statement.source_egress_authorized is False
    assert envelope.statement.production_selection_authorized is False
    assert envelope.statement.provider_observation_authenticity == "NOT_INDEPENDENTLY_PROVEN"
    with pytest.raises(TypeError, match="cannot be constructed"):
        TrustedModelLineageReviewVerification()
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(capability)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(capability)

    evidence_root = tmp_path / "bundle"
    evidence_root.mkdir(mode=0o700)
    lineage_fixtures.write_model_lineage_review_artifact(evidence_root, artifact)
    write_model_lineage_authority_envelope(evidence_root, envelope)
    trust_path = tmp_path / "lineage-trust-anchor.json"
    write_json_evidence(
        evidence_root=tmp_path,
        relative_path=trust_path.name,
        value=anchor,
    )
    assert load_model_lineage_authority_bundle(evidence_root) == (artifact, envelope)
    assert load_model_lineage_trust_anchor(trust_path) == anchor


def test_signed_lineage_authority_rejects_tamper_transplant_and_wrong_anchor(
    tmp_path: Path,
) -> None:
    bundle = lineage_fixtures._bundle()
    artifact = lineage_fixtures._artifact(bundle)
    anchor, envelope, _capability = _signed_authority(root=tmp_path, artifact=artifact)

    signature = envelope.detached_signature
    replacement = "A" if signature[40] != "A" else "B"
    corrupted = build_model_lineage_authority_envelope(
        statement=envelope.statement,
        detached_signature=signature[:40] + replacement + signature[41:],
    )
    with pytest.raises(ModelLineageAuthorityError, match="not trusted"):
        verify_operator_model_lineage_authority(
            artifact=artifact,
            envelope=corrupted,
            trust_anchor=anchor,
            observed_at=lineage_fixtures.CREATED_AT + timedelta(minutes=1),
        )

    other_bundle = lineage_fixtures._bundle(("beta/other",))
    other_artifact = lineage_fixtures._artifact(other_bundle)
    with pytest.raises(ModelLineageAuthorityError, match="differs"):
        verify_operator_model_lineage_authority(
            artifact=other_artifact,
            envelope=envelope,
            trust_anchor=anchor,
            observed_at=lineage_fixtures.CREATED_AT + timedelta(minutes=1),
        )

    _other_key, other_public_key = _generate_key(tmp_path, name="other-operator")
    other_anchor = build_model_lineage_trust_anchor(
        operator_principal=anchor.operator_principal,
        public_key=other_public_key,
        verifier_executable_sha256=anchor.verifier_executable_sha256,
    )
    with pytest.raises(ModelLineageAuthorityError, match="differs"):
        verify_operator_model_lineage_authority(
            artifact=artifact,
            envelope=envelope,
            trust_anchor=other_anchor,
            observed_at=lineage_fixtures.CREATED_AT + timedelta(minutes=1),
        )


def test_signed_lineage_authority_rejects_expiry_and_capability_reuse(
    tmp_path: Path,
) -> None:
    bundle = lineage_fixtures._bundle()
    artifact = lineage_fixtures._artifact(bundle)
    anchor, envelope, capability = _signed_authority(root=tmp_path, artifact=artifact)

    with pytest.raises(ModelLineageAuthorityError, match="current-refresh window"):
        build_model_lineage_authority_statement(
            artifact=artifact,
            trust_anchor=anchor,
            signed_at=lineage_fixtures.CREATED_AT,
            expires_at=(
                artifact.refresh_retrieved_at
                + timedelta(hours=artifact.soft_max_age_hours, seconds=1)
            ),
        )

    with pytest.raises(ModelLineageAuthorityError, match="expired"):
        verify_operator_model_lineage_authority(
            artifact=artifact,
            envelope=envelope,
            trust_anchor=anchor,
            observed_at=envelope.statement.expires_at,
        )
    with pytest.raises(ValueError, match="campaign time"):
        capability.require_for(
            candidate_registry=bundle.registry,
            discovery_manifest=bundle.manifest,
            campaign_started_at=lineage_fixtures.CREATED_AT - timedelta(seconds=1),
            observed_at=lineage_fixtures.CREATED_AT + timedelta(hours=1),
        )

    different = lineage_fixtures._bundle(("beta/other",))
    with pytest.raises(ValueError, match="candidate evidence"):
        capability.require_for(
            candidate_registry=different.registry,
            discovery_manifest=different.manifest,
            campaign_started_at=lineage_fixtures.CREATED_AT + timedelta(hours=1),
            observed_at=lineage_fixtures.CREATED_AT + timedelta(hours=2),
        )


def test_lineage_authority_models_reject_hash_and_boolean_drift(tmp_path: Path) -> None:
    artifact = lineage_fixtures._artifact(lineage_fixtures._bundle())
    _anchor, envelope, _capability = _signed_authority(root=tmp_path, artifact=artifact)
    payload = envelope.model_dump(mode="json")
    payload["signature_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="signature hash"):
        ModelLineageAuthorityEnvelope.model_validate_json(json.dumps(payload), strict=True)

    payload = envelope.model_dump(mode="json")
    payload["statement"]["source_egress_authorized"] = True
    with pytest.raises(ValidationError):
        ModelLineageAuthorityEnvelope.model_validate_json(json.dumps(payload), strict=True)


def test_self_sealed_lineage_registry_cannot_forge_opaque_capability() -> None:
    forged = object.__new__(TrustedModelLineageReviewVerification)
    bundle = lineage_fixtures._bundle()
    with pytest.raises(ValueError, match="forged"):
        forged.require_for(
            candidate_registry=CandidateRegistry.model_validate(
                bundle.registry.model_dump(mode="json")
            ),
            discovery_manifest=bundle.manifest,
            campaign_started_at=lineage_fixtures.CREATED_AT + timedelta(hours=1),
            observed_at=lineage_fixtures.CREATED_AT + timedelta(hours=2),
        )


def test_published_lineage_authority_schemas_are_strict_and_non_authorizing() -> None:
    schema_root = Path(__file__).resolve().parents[2] / "schemas"
    authority = json.loads(
        (schema_root / "model_lineage_authority.schema.json").read_text(encoding="utf-8")
    )
    anchor = json.loads(
        (schema_root / "model_lineage_trust_anchor.schema.json").read_text(encoding="utf-8")
    )
    statement = authority["$defs"]["ModelLineageAuthorityStatement"]

    assert authority["additionalProperties"] is False
    assert authority["properties"]["detached_signature"]["maxLength"] == 16_384
    assert statement["properties"]["calibration_identity_authorized"]["const"] is True
    assert statement["properties"]["source_egress_authorized"]["const"] is False
    assert statement["properties"]["production_selection_authorized"]["const"] is False
    assert statement["properties"]["signature_namespace"]["const"] == (LINEAGE_AUTHORITY_NAMESPACE)
    assert anchor["additionalProperties"] is False
    assert {
        "public_key_sha256",
        "verifier_executable_sha256",
        "trust_anchor_sha256",
    } <= set(anchor["required"])
