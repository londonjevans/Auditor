"""Exact temporary copies of existing non-deployable paired fixtures; no live source or credentials."""

import json

from mmaudit.models.development_corpus import prepare_development_corpus
from mmaudit.models.endpoint_snapshots import validate_openrouter_endpoint_snapshot
from mmaudit.repository.development_corpus import load_development_corpus
from mmaudit.repository.development_corpus_tree import freeze_development_corpus_tree
from tests.development_corpus_benchmark_support import paired_sources
from tests.development_corpus_judgment_support import selected_policy
from tests.development_corpus_support import CORPUS_MODEL
from tests.development_cost_support import FIXTURE


def custody_metadata(*, model_id=CORPUS_MODEL):
    """Synthetic large-context endpoint; production request/cost ceilings are not changed."""

    endpoint = json.loads(FIXTURE.read_bytes())["endpoint"]
    endpoint.update(context_length=1_000_000, max_prompt_tokens=900_000)
    return validate_openrouter_endpoint_snapshot(
        exact_model_id=model_id,
        configured_provider_endpoints=(endpoint["tag"],),
        provider_policy_mode="only",
        endpoint_payload={"data": {"id": model_id, "endpoints": [endpoint]}},
        require_zdr=True,
        zdr_payload={"data": [{**endpoint, "model_id": model_id}]},
    )


def loaded_case(tmp_path, *, version="1.7"):
    root = tmp_path / "source"
    root.mkdir(parents=True)
    for name, raw in paired_sources():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    (root / "empty").mkdir()
    remappings = tmp_path / "remappings.txt"
    remappings.write_text("")
    output = tmp_path / "frozen"
    frozen = freeze_development_corpus_tree(
        corpus_root=root,
        remappings_file=remappings,
        corpus_id="synthetic-source-custody",
        source_scope="OPERATOR_SUPPLIED_SYNTHETIC",
        output_dir=output,
        dependency_scoped_context=version >= "1.4",
        dependency_call_context=version >= "1.5",
        dependency_syntax_context=version >= "1.6",
        dependency_modifier_context=version >= "1.7",
    )
    loaded = load_development_corpus(manifest_file=output / "manifest.json", corpus_root=root)
    assert loaded.material.manifest == frozen and frozen.schema_version == version
    return loaded


def candidate_case(loaded, **changes):
    values = dict(
        policy=selected_policy(total="250", per_attempt="10"),
        endpoint_snapshot=custody_metadata(),
        manifest=loaded.material.manifest,
        source_files=loaded.material.source_files,
        source_custody=loaded,
        run_id="synthetic-source-custody",
    )
    values.update(changes)
    return prepare_development_corpus(**values)
