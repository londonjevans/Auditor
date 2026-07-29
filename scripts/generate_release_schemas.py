"""Generate or verify the typed release-evidence JSON schemas."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import BaseModel

from mmaudit.models.qualification import ModelQualificationArtifact
from mmaudit.privacy import PrivacyRetentionConsent
from mmaudit.release_candidate import ReleaseCandidateObservation
from mmaudit.release_gates import ReleaseGateEvidenceBundle
from mmaudit.release_observations import BoundReleaseGateResult
from mmaudit.release_report import ReleaseGateReport
from mmaudit.release_run import ReleaseRunBinding
from mmaudit.release_runtime import LocalReleaseGateResult
from mmaudit.release_static import StaticReleaseEvidence
from mmaudit.release_verification import ReleaseRunVerificationBinding

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "schemas"
SCHEMA_BASE = "https://mmaudit.local/schemas"
MODELS: dict[str, type[BaseModel]] = {
    "model_qualification.schema.json": ModelQualificationArtifact,
    "privacy_retention_consent.schema.json": PrivacyRetentionConsent,
    "release_candidate_observation.schema.json": ReleaseCandidateObservation,
    "release_bound_gate_result.schema.json": BoundReleaseGateResult,
    "release_gate_evidence.schema.json": ReleaseGateEvidenceBundle,
    "release_gate_report.schema.json": ReleaseGateReport,
    "release_local_gate_result.schema.json": LocalReleaseGateResult,
    "release_run_binding.schema.json": ReleaseRunBinding,
    "release_run_verification_binding.schema.json": ReleaseRunVerificationBinding,
    "release_static_evidence.schema.json": StaticReleaseEvidence,
}
TITLE_OVERRIDES = {
    "model_qualification.schema.json": "mmaudit model qualification artifact",
}


def rendered_schema(filename: str, model: type[BaseModel]) -> str:
    """Return one deterministic draft-2020-12 schema."""

    schema = model.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = f"{SCHEMA_BASE}/{filename}"
    if filename in TITLE_OVERRIDES:
        schema["title"] = TITLE_OVERRIDES[filename]
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write generated schemas; without this option, verify committed bytes.",
    )
    arguments = parser.parse_args(argv)
    failures: list[str] = []
    for filename, model in sorted(MODELS.items()):
        expected = rendered_schema(filename, model)
        path = SCHEMA_ROOT / filename
        if arguments.write:
            path.write_text(expected, encoding="utf-8")
            continue
        try:
            observed = path.read_text(encoding="utf-8")
        except OSError:
            failures.append(f"{filename}: missing")
            continue
        if observed != expected:
            failures.append(f"{filename}: stale")
    if failures:
        raise SystemExit("release schema verification failed: " + ", ".join(failures))


if __name__ == "__main__":
    main()
