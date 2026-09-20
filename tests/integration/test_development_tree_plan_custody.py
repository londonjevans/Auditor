"""Real local synthetic-tree capture and retained preflight; no network or credential loading."""

from __future__ import annotations

import json
import socket
import subprocess
from dataclasses import replace

import pytest

from mmaudit import development_cli
from mmaudit.repository.development_tree_plan import (
    load_development_tree_plan,
    revalidate_loaded_development_tree_plan,
    write_development_tree_plan,
)
from tests.development_tree_support import tree_policy
from tests.integration.test_development_call_closure_custody import tree_inputs


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("automatic tree planning attempted network, subprocess or secret loading")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)


def tree_plan_case(tmp_path, *, policy=None):
    inputs = tree_inputs(tmp_path)
    policy_file = tmp_path / "policy.json"
    policy_file.write_text((policy or tree_policy()).model_dump_json())
    return dict(**inputs, policy_file=policy_file, output_dir=tmp_path / "planned")


def reopen(inputs):
    return load_development_tree_plan(
        plan_file=inputs["output_dir"] / "plan.json",
        corpus_root=inputs["corpus_root"],
        remappings_file=inputs["remappings_file"],
        policy_file=inputs["policy_file"],
    )


def test_actual_tree_produces_all_source_plan_and_can_reopen_without_provisioning(tmp_path):
    inputs = tree_plan_case(tmp_path)
    loaded = write_development_tree_plan(**inputs)
    assert loaded.plan.status == "READY"
    assert len(loaded.plan.primaries) == 5
    assert reopen(inputs).plan == loaded.plan
    revalidate_loaded_development_tree_plan(loaded)
    assert {p.name for p in inputs["output_dir"].iterdir()} == {"plan.json", "manifest.json"}
    assert inputs["output_dir"].stat().st_mode & 0o777 == 0o700
    assert (inputs["output_dir"] / "plan.json").stat().st_mode & 0o777 == 0o600
    assert not loaded.plan.audit_complete


def test_refused_preflight_retains_all_shortfalls_but_creates_no_run_or_bundle(tmp_path):
    inputs = tree_plan_case(tmp_path, policy=tree_policy(maximum_requests=3))
    loaded = write_development_tree_plan(**inputs)
    assert loaded.plan.status == "REFUSED"
    assert loaded.plan.shortfalls == ("WHOLE_REQUEST_ENVELOPE",)
    assert len(loaded.plan.primaries) == 5
    assert {p.name for p in inputs["output_dir"].iterdir()} == {"plan.json", "manifest.json"}
    assert reopen(inputs).plan == loaded.plan


@pytest.mark.parametrize(
    "input_name", ["policy_file", "remappings_file", "source", "plan", "manifest"]
)
@pytest.mark.parametrize("replacement", [False, True])
def test_input_drift_or_same_byte_replacement_refuses_existing_custody(
    tmp_path, input_name, replacement
):
    inputs = tree_plan_case(tmp_path)
    loaded = write_development_tree_plan(**inputs)
    path = (
        inputs["corpus_root"] / "src/Controller.sol"
        if input_name == "source"
        else inputs["output_dir"] / (input_name + ".json")
        if input_name in {"plan", "manifest"}
        else inputs[input_name]
    )
    content = path.read_bytes()
    if replacement:
        path.rename(tmp_path / "previous-synthetic-input")
        path.write_bytes(content)
        if input_name in {"plan", "manifest"}:
            path.chmod(0o600)
    else:
        path.write_bytes(content + b"\n")
    with pytest.raises(ValueError):
        revalidate_loaded_development_tree_plan(loaded)


def test_reopening_cannot_change_original_policy_or_add_an_unplanned_source(tmp_path):
    inputs = tree_plan_case(tmp_path)
    write_development_tree_plan(**inputs)
    policy = json.loads(inputs["policy_file"].read_bytes())
    policy["maximum_requests"] -= 1
    inputs["policy_file"].write_text(json.dumps(policy))
    with pytest.raises(ValueError, match="original policy"):
        reopen(inputs)
    inputs["policy_file"].write_text(tree_policy().model_dump_json())
    (inputs["corpus_root"] / "Added.sol").write_text(
        "// Synthetic namespace test.\ncontract Added {}\n"
    )
    with pytest.raises(ValueError):
        reopen(inputs)


def test_forged_in_memory_policy_cannot_replace_bound_plan(tmp_path):
    inputs = tree_plan_case(tmp_path)
    loaded = write_development_tree_plan(**inputs)
    forged = loaded.plan.model_copy(update={"policy": tree_policy(maximum_requests=16)})
    with pytest.raises(ValueError, match="retained plan"):
        revalidate_loaded_development_tree_plan(replace(loaded, plan=forged))


@pytest.mark.parametrize("target", ["existing", "inside_source", "contains_source", "symlink"])
def test_writer_refuses_unsafe_or_existing_output_without_overwriting(tmp_path, target):
    inputs = tree_plan_case(tmp_path)
    output = inputs["output_dir"]
    if target == "existing":
        output.mkdir()
        (output / "keep").write_bytes(b"synthetic retained marker")
    elif target == "inside_source":
        output = inputs["corpus_root"] / "planned"
    elif target == "contains_source":
        output = tmp_path
    else:
        output.symlink_to(inputs["corpus_root"], target_is_directory=True)
    with pytest.raises((ValueError, FileExistsError)):
        write_development_tree_plan(**{**inputs, "output_dir": output})
    if target == "existing":
        assert (output / "keep").read_bytes() == b"synthetic retained marker"
