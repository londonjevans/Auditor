from __future__ import annotations

import mmaudit.release as release_module
from mmaudit.release import ReleaseGateId, ReleaseGateStatus, ReleaseStatus


def test_release_module_exposes_identities_not_a_declarative_legacy_certifier() -> None:
    assert set(ReleaseGateId) == {
        ReleaseGateId.ARTIFACTS,
        ReleaseGateId.BENCHMARK_CERTIFICATE,
        ReleaseGateId.DOCTOR,
        ReleaseGateId.MANIFESTS,
        ReleaseGateId.MAXIMUM_ASSURANCE_RUN,
        ReleaseGateId.MODEL_BENCHMARK,
        ReleaseGateId.MYPY,
        ReleaseGateId.PYTEST,
        ReleaseGateId.REPLAY,
        ReleaseGateId.RUFF_CHECK,
        ReleaseGateId.RUFF_FORMAT,
        ReleaseGateId.SCHEMAS,
    }
    assert set(ReleaseGateStatus) == {
        ReleaseGateStatus.PASSED,
        ReleaseGateStatus.BLOCKED_TECHNICAL,
        ReleaseGateStatus.FAILED,
    }
    assert set(ReleaseStatus) == {
        ReleaseStatus.COMPLETE,
        ReleaseStatus.BLOCKED_TECHNICAL,
        ReleaseStatus.FAILED,
    }
    assert not hasattr(release_module, "ReleaseGateObservation")
    assert not hasattr(release_module, "build_release_gate_report")
    assert not hasattr(release_module, "load_release_gate_report")
    assert not hasattr(release_module, "write_release_gate_report")
