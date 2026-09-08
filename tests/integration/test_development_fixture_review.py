from __future__ import annotations

import json
import socket
import subprocess
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as development_cli
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.development_review import DevelopmentReviewObservation
from mmaudit.models.development_transport import review_development_fixture
from mmaudit.models.discovery import write_model_discovery_run
from mmaudit.operator_secrets import OperatorSecrets, load_operator_secrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from tests.development_cost_support import development_case
from tests.development_review_support import (
    FIXTURE_ROOT,
    SYNTHETIC_CREDENTIAL,
    discovery_review_case,
    response_payload,
)
from tests.unit.test_model_discovery import (
    _real_evidence as _synthetic_serialized_discovery_evidence,
)

RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def no_network_or_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("fixture review must not use real networking or execute model output")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def _inputs(tmp_path: Path, *, metadata_form: str = "endpoint") -> list[str]:
    snapshot, _ = development_case()
    metadata_path = tmp_path / "snapshot.json"
    if metadata_form == "endpoint":
        metadata_path.write_text(snapshot.model_dump_json())
    else:
        payload = discovery_review_case(constrained=metadata_form == "constrained_snapshot")
        if metadata_form == "discovery_file":
            # Exercise the actual local discovery publisher; all input/provenance is synthetic.
            # A serialized REAL label must never upgrade the MOCK_HTTP review observation.
            manifest = write_model_discovery_run(
                tmp_path / "synthetic-discovery",
                _synthetic_serialized_discovery_evidence((payload,)),
            )
            metadata_path = tmp_path / "synthetic-discovery" / manifest.artifacts[0].filename
        else:
            metadata_path.write_text(
                (
                    payload.endpoint_snapshot
                    if metadata_form == "constrained_snapshot"
                    else payload
                ).model_dump_json()
            )
    (tmp_path / "ControlA.sol").write_bytes((FIXTURE_ROOT / "ControlA.sol").read_bytes())
    control = tmp_path / "synthetic-operator-control.txt"
    control.write_text(f"OPENROUTER_API_KEY={SYNTHETIC_CREDENTIAL}\n")
    control.chmod(0o600)
    AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("20"))
    return [
        "development",
        "review-fixture",
        "--endpoint-snapshot",
        str(metadata_path),
        "--fixture-file",
        str(tmp_path / "ControlA.sol"),
        "--cost-ledger",
        str(tmp_path / "synthetic-ledger.json"),
        "--secrets-env-file",
        str(control),
        "--request-id",
        "synthetic-cli-review-1",
        "--budget-usd",
        "20",
        "--per-attempt-usd",
        "5",
        "--allow-code-egress",
        "--accept-estimate-risk",
    ]


@pytest.mark.parametrize(
    "metadata_form", ("endpoint", "discovery_payload", "discovery_file", "constrained_snapshot")
)
def test_cli_reads_only_explicit_synthetic_controls_and_completes_the_accounted_request_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    metadata_form: str,
) -> None:
    arguments = _inputs(tmp_path, metadata_form=metadata_form)
    before_source = (tmp_path / "ControlA.sol").read_bytes()
    metadata_path = Path(arguments[arguments.index("--endpoint-snapshot") + 1])
    before_snapshot = metadata_path.read_bytes()
    loaded: list[OperatorSecrets] = []
    calls: list[httpx.Request] = []

    def explicit_secrets(path: Path | None, **kwargs: Any) -> OperatorSecrets:
        assert kwargs == {"environ": {}, "required": True}
        assert path == tmp_path / "synthetic-operator-control.txt"
        value = load_operator_secrets(path, **kwargs)
        loaded.append(value)
        return value

    def handler(request: httpx.Request) -> httpx.Response:
        ledger = AtomicCostLedger.open_existing(
            tmp_path / "synthetic-ledger.json", cap_usd=Decimal("20")
        )
        assert ledger.snapshot().entries[0].status is CostEntryStatus.RESERVED
        assert SYNTHETIC_CREDENTIAL.encode() not in request.content
        assert "abstract contract ControlA" in request.content.decode()
        assert "operator-control" not in request.content.decode()
        assert str(tmp_path) not in request.content.decode()
        body = json.loads(request.content)
        assert body["reasoning"] == {"effort": "high"}
        assert body["provider"]["only"] == ["synthetic-provider"]
        assert body["provider"]["allow_fallbacks"] is False
        assert body["provider"]["zdr"] is True
        assert "canonical_slug" not in request.content.decode()
        assert "provenance" not in request.content.decode()
        calls.append(request)
        return httpx.Response(200, json=response_payload())

    async def local_review(**kwargs: Any) -> DevelopmentReviewObservation:
        return await review_development_fixture(
            **kwargs, mock_transport=httpx.MockTransport(handler)
        )

    monkeypatch.setenv("MMAUDIT_SECRETS_ENV_FILE", "/synthetic-invalid-ambient-control")
    monkeypatch.setenv("OPENROUTER_API_KEY", "synthetic-unused-ambient-credential")
    monkeypatch.setattr(development_cli, "load_operator_secrets", explicit_secrets)
    monkeypatch.setattr(development_cli, "review_development_fixture", local_review)
    result = RUNNER.invoke(app, arguments)
    assert result.exit_code == ExitCode.SUCCESS, result.output
    observation = DevelopmentReviewObservation.model_validate_json(result.stdout)
    assert observation.status == "OBSERVED"
    assert observation.transport == "MOCK_HTTP"
    assert (
        observation.audit_complete
        is observation.qualification_eligible
        is observation.release_eligible
        is False
    )
    assert len(calls) == len(loaded) == 1
    assert loaded[0].cleared is True
    assert SYNTHETIC_CREDENTIAL not in result.output
    assert "synthetic-unused-ambient-credential" not in result.output
    assert before_source == (tmp_path / "ControlA.sol").read_bytes()
    assert before_snapshot == metadata_path.read_bytes()
    assert AtomicCostLedger.open_existing(
        tmp_path / "synthetic-ledger.json", cap_usd=Decimal("20")
    ).snapshot().spent_usd == Decimal("0.01")


@pytest.mark.parametrize(
    "failure",
    (
        "no_consent",
        "no_risk",
        "modified_source",
        "relative_path",
        "same_paths",
        "bad_cap",
        "over_target",
        "wrong_name",
        "missing_ledger",
        "linked_source",
    ),
)
def test_cli_refuses_unsafe_input_before_credential_loading_or_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    arguments = _inputs(tmp_path)
    ledger_path = tmp_path / "synthetic-ledger.json"
    before_ledger = ledger_path.read_bytes()
    if failure == "no_consent":
        arguments.remove("--allow-code-egress")
    elif failure == "no_risk":
        arguments.remove("--accept-estimate-risk")
    elif failure == "modified_source":
        (tmp_path / "ControlA.sol").write_text("// SYNTHETIC_SECRET_CANARY: not an approved source")
    elif failure == "relative_path":
        arguments[arguments.index("--fixture-file") + 1] = "ControlA.sol"
    elif failure == "same_paths":
        arguments[arguments.index("--secrets-env-file") + 1] = str(tmp_path / "ControlA.sol")
    elif failure == "bad_cap":
        arguments[arguments.index("--budget-usd") + 1] = "10"
    elif failure == "over_target":
        arguments[arguments.index("--per-attempt-usd") + 1] = "0.001"
    elif failure == "wrong_name":
        arguments[arguments.index("--fixture-file") + 1] = str(
            tmp_path / "synthetic-operator-control.txt"
        )
    elif failure == "missing_ledger":
        arguments[arguments.index("--cost-ledger") + 1] = str(tmp_path / "missing.json")
    else:
        fixture = tmp_path / "ControlA.sol"
        fixture.unlink()
        fixture.symlink_to(FIXTURE_ROOT / "ControlA.sol")

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("preflight refusal must not load credentials or invoke transport")

    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    monkeypatch.setattr(development_cli, "review_development_fixture", forbidden)
    result = RUNNER.invoke(app, arguments)
    assert result.exit_code == ExitCode.CONFIGURATION, result.output
    assert SYNTHETIC_CREDENTIAL not in result.output
    assert "SYNTHETIC_SECRET_CANARY" not in result.output
    assert ledger_path.read_bytes() == before_ledger
    assert not (tmp_path / "missing.json").exists()


def test_cli_unknown_usage_is_incomplete_with_no_automatic_retry_and_cleared_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = _inputs(tmp_path)
    loaded: list[OperatorSecrets] = []
    calls = 0

    def loader(path: Path | None, **kwargs: Any) -> OperatorSecrets:
        result = load_operator_secrets(path, **kwargs)
        loaded.append(result)
        return result

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout(SYNTHETIC_CREDENTIAL, request=request)

    async def local_review(**kwargs: Any) -> DevelopmentReviewObservation:
        return await review_development_fixture(
            **kwargs, mock_transport=httpx.MockTransport(handler)
        )

    monkeypatch.setattr(development_cli, "load_operator_secrets", loader)
    monkeypatch.setattr(development_cli, "review_development_fixture", local_review)
    result = RUNNER.invoke(app, [*arguments, "--maximum-attempts", "2"])
    assert result.exit_code == ExitCode.INCOMPLETE
    observation = DevelopmentReviewObservation.model_validate_json(result.stdout)
    assert "UNKNOWN_COST" in observation.diagnostics
    assert calls == 1 and loaded[0].cleared is True
    assert SYNTHETIC_CREDENTIAL not in result.output
    retried = RUNNER.invoke(app, [*arguments, "--maximum-attempts", "2", "--attempt", "2"])
    assert retried.exit_code == ExitCode.CONFIGURATION
    assert calls == 1


def test_development_cli_exposes_no_arbitrary_request_or_url_override() -> None:
    help_result = RUNNER.invoke(app, ["development", "review-fixture", "--help"])
    assert help_result.exit_code == ExitCode.SUCCESS
    for option in ("--request-file", "--base-url", "--transport", "--repo", "--run-command"):
        assert option not in help_result.output


@pytest.mark.parametrize(
    "failure",
    (
        "unknown_efforts",
        "model_unsupported",
        "explicit_endpoint_empty",
        "explicit_endpoint_low",
        "extracted_without_model",
        "changed_parent_hash",
        "wrong_parent_model",
        "partial_provenance",
        "duplicate_json",
        "linked_discovery",
    ),
)
def test_discovery_metadata_refusal_precedes_ledger_and_credential_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    arguments = _inputs(tmp_path, metadata_form="discovery_payload")
    metadata_path = tmp_path / "snapshot.json"
    if failure in {"unknown_efforts", "model_unsupported"}:
        payload = discovery_review_case(
            model_efforts=None if failure == "unknown_efforts" else ("low",)
        )
    elif failure in {"explicit_endpoint_empty", "explicit_endpoint_low"}:
        payload = discovery_review_case(
            endpoint_efforts=() if failure == "explicit_endpoint_empty" else ("low",)
        )
    else:
        payload = discovery_review_case()
    data = payload.model_dump(mode="json")
    if failure == "extracted_without_model":
        data = data["endpoint_snapshot"]
    elif failure == "changed_parent_hash":
        data["model_metadata_snapshot_sha256"] = "0" * 64
    elif failure == "wrong_parent_model":
        data["exact_model_id"] = "synthetic/different-model"
    elif failure == "partial_provenance":
        data["provenance"] = {}
    metadata_path.write_text(json.dumps(data))
    if failure == "duplicate_json":
        metadata_path.write_text('{"schema_version":"1.0",' + json.dumps(data)[1:])
    elif failure == "linked_discovery":
        original = tmp_path / "synthetic-original-metadata.json"
        metadata_path.rename(original)
        metadata_path.symlink_to(original)
    before = (tmp_path / "synthetic-ledger.json").read_bytes()
    forbidden_accesses: list[bool] = []

    def forbidden(*_args: object, **_kwargs: object) -> None:
        forbidden_accesses.append(True)
        raise AssertionError("invalid metadata must fail before ledger/credential/transport access")

    monkeypatch.setattr(AtomicCostLedger, "open_existing", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    monkeypatch.setattr(development_cli, "review_development_fixture", forbidden)
    result = RUNNER.invoke(app, arguments)
    assert result.exit_code == ExitCode.CONFIGURATION, result.output
    assert "No qualification or audit completion is implied" in result.output
    assert SYNTHETIC_CREDENTIAL not in result.output
    assert forbidden_accesses == []
    assert (tmp_path / "synthetic-ledger.json").read_bytes() == before
