from __future__ import annotations

import ast
import hashlib
import json
import re
import stat
import subprocess
import tomllib
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AGENTS_PATH = ROOT / "AGENTS.md"
QUEUE_PATH = ROOT / "docs/remediation/v3/work_queue.md"
CODEX_QUEUE_PATH = ROOT / "docs/codex_work_queue.md"
CODEX_WORKLOG_PATH = ROOT / "docs/codex_worklog.md"
TRACEABILITY_PATH = ROOT / "docs/remediation/v3/review_traceability.json"
RUNTIME_STATUS_PATH = ROOT / "docs/remediation/v3/runtime_status.json"
README_PATH = ROOT / "README.md"
MODEL_SELECTION_PATH = ROOT / "docs/models/model_selection.md"
SELECTION_PLAN_PATH = ROOT / "config/models.selection-plan.json"
OPERATOR_PREREQUISITES_PATH = ROOT / "docs/remediation/operator_prerequisites.md"
V3_OPERATOR_PREREQUISITES_PATH = ROOT / "docs/remediation/v3/operator_prerequisites.md"
PRODUCT_VISION_PATH = ROOT / "product/CORROVERA_SECURITY_AUDITOR_PRODUCT_VISION.md"
CONFIG_PATH = ROOT / "src/mmaudit/config.py"
AUTONOMY_INVENTORY_PATH = ROOT / "docs/remediation/v3/autonomy_gate_inventory.json"
AUTONOMY_INVENTORY_SCHEMA_PATH = ROOT / "schemas/autonomy_gate_inventory.schema.json"
ROUTE_RUNTIME_EVIDENCE_SCHEMA_PATH = ROOT / "schemas/route_runtime_evidence_artifact.schema.json"
MANAGED_TOOLCHAIN_BUNDLE_PATH = ROOT / "src/mmaudit/resources/managed_toolchain_bundle.json"
MANAGED_TOOLCHAIN_SCHEMA_PATH = ROOT / "schemas/managed_toolchain_bundle.schema.json"

OBJECTIVE_RELATIVE_PATH = "docs/remediation/v3/product_completion_goal.txt"
OBJECTIVE_SHA256 = "e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"
PRODUCT_VISION_RELATIVE_PATH = "product/CORROVERA_SECURITY_AUDITOR_PRODUCT_VISION.md"
PRODUCT_VISION_SHA256 = "8b878b665e636b3b48500fefe2967394b2abdd69ce2ebfa0033d04542d2965e1"
LAST_RECONCILED_OPERATOR_RESULTS_SHA256 = (
    "4616c5a143db158f3af12d0a4d58306e0da6ca9dd4bbb54e6c7484dfc2de0251"
)
PLANCONSTRAINTS_PARENT_OPERATOR_RESULTS_SHA256 = (
    "ed416745d3d0d957e05919e7cf10e14e75b4e9f3da800000e5789371520abbe2"
)
HISTORICAL_PRE_REPLAY_REPAIR_OPERATOR_RESULTS_SHA256 = (
    "a87ca7efaf4adf0af60479fa5b26fcbfe80ad6d3aa58a92c9e18fab1a70eabce"
)
HISTORICAL_POST_DIAGNOSTIC_OPERATOR_RESULTS_SHA256 = (
    "dd6019db5bdf4e1c9b528b5f2949a81b9944336bef370be822ba52baf5a618fc"
)
PRE_RECEIPT_COMPOSITE_LIVE_OPERATOR_RESULTS_SHA256 = (
    "67b40784bce40a9369d721a922d5138a118d833105937219294778f4fc93ce98"
)
HISTORICAL_R8_GATE_OPERATOR_RESULTS_SHA256 = (
    "25ee5395a7e2360637f89d89cc0e89084a530c8921d0af395b06bc9b700b01e5"
)
HISTORICAL_R7_OPERATOR_RESULTS_SHA256 = (
    "00de61717cb6d61c003682abca12ae2c7e59613db03ef99558133b972c123516"
)
HISTORICAL_PAID_DIAGNOSTIC_OPERATOR_RESULTS_SHA256 = (
    "f0c87e608633dc8ae940a977c8207d9e371b2bf683d0a91f415316273d5ac0dc"
)
HISTORICAL_INELIGIBLE_GEMMA_CHECKPOINT = "3989e7592de6e1c355365443c10e00c2083829d8"
CURRENT_LINEAGE_RESEAL_CHECKPOINT = "331bde27c7085d4da34c7b8ec1f688f2ce1e52b3"
HISTORICAL_COMPLETION_CAPACITY_CHECKPOINT = "3975d2e12fd81a214b9faa1c3031c94506ab696d"
HISTORICAL_DCABE_SELECTION_CHECKPOINT = "dcabe3128ba1aca84c3df90d8a64b1a6bc77db1d"
AUTHRUNNER_TOKEN_ENVELOPE_CHECKPOINT = "531a9d822e9989bf2eda94530e88cf55f2dd2e0d"
AUTHRUNNER_IDENTITY_DIAGNOSTIC_CHECKPOINT = "77fb4b9a0c03969a9776edf2091dc09d3b67daec"
HISTORICAL_AUTHRUNNER_RECEIPT_SCAFFOLD_CHECKPOINT = "8058e7bff88594b44aa42b8695ce5c25442ae73c"
HISTORICAL_AUTHRUNNER_SCOPE_CUTOFF_CHECKPOINT = "d2364f6b528f2e839fbef8b878552f95c4b92c9c"
AUTHRUNNER_RECEIPT_COMPOSITE_PARENT_CHECKPOINT = "4e035a9d58b98284e7cceecf1fb844bc84e0dbe6"
HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT = "48ea635ab5a2fa778d6b5ce5c9a1592f0f27b375"
HISTORICAL_AUTHRUNNER_RECEIPT_STATE_SEAL_CHECKPOINT = "68126e0fe438f853fb9b75582023f807a208bdae"
HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT = (
    "3a1246daf19ffa4a772be7806bd903199634ab0b"
)
HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT = (
    "03d6e8a644dd4a807860bfcc4dfc9d004cff3cbc"
)
HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT = "c627f2debfa18df7d9567cd7c3300d19a9e9f5ce"
HISTORICAL_AUTHRUNNER_REPLAY_SMOKE_RAW_SHA256 = (
    "27e70a3c17ef5f03c503e594bca2c3e433fb2c4193de772eb7be829592c3555a"
)
HISTORICAL_PLANCONSTRAINTS_BASE_CHECKPOINT = "7ef471744adfce557edf612a74b2847aafb3e8bc"
HISTORICAL_PLANCONSTRAINTS_BASE_PARENT_CHECKPOINT = "85c06b07ccc3905af4e0231497276934f7ae142a"
PLANCONSTRAINTS_REPAIR_CHECKPOINT = "425502c5cbc173578053423d946ef24843f26285"
PLANCONSTRAINTS_REPAIR_PARENT_CHECKPOINT = "390e9b29e748e38d511da9f0a54cfc4fa1a2c0a8"
CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT = "721d17a4ff08cc52ccdf0aa92ed04258e4137807"
CURRENT_TRUNCATION_SPECIALIST_PARENT_CHECKPOINT = "847e7180923e95768271c6fe7e8b06732a7d919a"
HISTORICAL_TRUNCATION_RECURSIVE_CHECKPOINT = "dcd9ab2be15f4a0416372c110734b5079af1efe2"
HISTORICAL_TRUNCATION_RECURSIVE_PARENT_CHECKPOINT = "d738f2760da047d15d4e53f87d6e0aeaf13d442a"
CURRENT_TRUNCATION_PROMOTION_CHECKPOINT = "e61b7d7d168488bea8f27f40b31c4db4a0bf8386"
CURRENT_TRUNCATION_PROMOTION_PARENT_CHECKPOINT = "ea85af3849db30c9832624c675594541a698ab06"
CURRENT_COVERAGE_CHECKPOINT = "33001d12d62ffe54788a41ed7321a77cd9fcb05f"
CURRENT_COVERAGE_PARENT_CHECKPOINT = "d6c7c5b05d8466a3793b3174809e1cd48b6a02e8"
CURRENT_RETRY_CHECKPOINT = "4f666d05c79e550af4f5fc646c5e6ffabb60dcf0"
CURRENT_RETRY_PARENT_CHECKPOINT = "9a902192cae14bb14144094b3a3b3bf6dafed9a9"
CURRENT_OPERATOR_RESULTS_SHA256 = "af7a24e382b4f164c7bec0948816e6e6eb3f40e898b2f0688641c4475b697f1b"
CURRENT_OPERATOR_RESULTS_BYTES = 162_656
CURRENT_OPERATOR_RESULTS_LINES = 2_902
CURRENT_OPERATOR_RESULTS_LATEST_ENTRY = "2026-09-01T04:49Z"
CURRENT_OPERATOR_RESULTS_REPOSITORY_COMMIT = "4c553590fedd4d297442f0a73da703d993f5eec9"
HISTORICAL_50D_OPERATOR_RESULTS_CHECKPOINT = "e8610cd6325ae599f5a725a9bf6c64da12928564"
HISTORICAL_C627_AUTONOMY_INVENTORY_RAW_SHA256 = (
    "6fd2608825a5dff950f8c0a0239a446857c82783603ec81a15b060391c3d4778"
)
OPERATOR_INDEX_19_SOURCE_CHECKPOINT = "03d6e8a644dd4a807860bfcc4dfc9d004cff3cbc"
HISTORICAL_PHASE_ZERO_CHECKPOINT = "d0402d1c68f0f82d9ee4f8757f7967abda372ac6"
PHASE_ONE_IMPLEMENTATION_CHECKPOINT = "084add8778ef36a2e4c86fdbdea4082eb3a1b332"
AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_CHECKPOINT = "9c61871502abbd19ff13278893f9c7785c5b28ba"
AUTONOMY_WORKTREE_INDEPENDENCE_CHECKPOINT = "3d4a43ac026547dd8652796b6186c48891fd7622"
HISTORICAL_PHASE_ZERO_INVENTORY_RAW_SHA256 = (
    "6a3c54258dd1f0c25fc8861c8298cf51d187b33bd5528ec25b1549c0e0021980"
)
AUTONOMY_INVENTORY_RAW_SHA256 = "827b3fb3153366efdd4f59ac30b439612c26523675d134cf502d6d36b3094fec"
CURRENT_RETRY_AUTONOMY_INVENTORY_SCHEMA_RAW_SHA256 = (
    "6a63c33efcb816b9d0e2df0fb3862639edd1cfbe5bae68207e6c2c30cf8bff30"
)
HISTORICAL_COVERAGE_AUTONOMY_INVENTORY_SCHEMA_RAW_SHA256 = (
    "c302b155d7dd138adc150d9f398da279f130dd696a321fb9e0d287c089012bcf"
)
AUTONOMY_INVENTORY_SHA256 = "1cf5af44108c390eebd88f02b88cf0b8ae79c48a99c8a2f6b400400de3e14cda"
AUTONOMY_SOURCE_UNIVERSE_SHA256 = "6fdfd55652cb8776263ef969f168b34ffd5c557aece263cd70a4b7b545888913"
AUTONOMY_DISCOVERY_SEMANTICS_SHA256 = (
    "4af6458862d94af02d77db5f25ff9bdb24ced56c665d2a7402111af795138e99"
)
CURRENT_RETRY_AUTONOMY_INVENTORY_RAW_SHA256 = (
    "5891f71e33238083d7b275e9d2346cf1f68aec89af7ecee4b0576f8df4887010"
)
CURRENT_RETRY_AUTONOMY_INVENTORY_SHA256 = (
    "e2e188cff322c8e62a7ef55211100bb6c8ca3e5b23c457ee000821c87fd9225e"
)
CURRENT_RETRY_AUTONOMY_DISCOVERY_SEMANTICS_SHA256 = (
    "b7c9aea7736b9788a6b67c2eac221c5f4d43312576335a0409f798ea3fb6a4dd"
)
CURRENT_RETRY_AUTONOMY_SOURCE_UNIVERSE_SHA256 = (
    "1547de1024c1a0da5c27fd4bb6aa5005ad6b352b181b2c9edb8cbc7013e05501"
)
HISTORICAL_RUNTIME_ADMISSION_AUTONOMY_INVENTORY_RAW_SHA256 = (
    "cb4a87188260648848a1ceae63345ae1cce626b6ba23d3fb1c09fb8c5e8cfbde"
)
HISTORICAL_RUNTIME_ADMISSION_AUTONOMY_INVENTORY_SHA256 = (
    "3eb687205399afe4ae651af58e3e8596c0afcb9c19f8193819e676f98af61daa"
)
HISTORICAL_RUNTIME_ADMISSION_AUTONOMY_DISCOVERY_SEMANTICS_SHA256 = (
    "cd7e3e92c093d5ac6826b3418281d6a59df84903597bda616bddc2cc7cbff1a9"
)
HISTORICAL_RUNTIME_ADMISSION_AUTONOMY_SOURCE_UNIVERSE_SHA256 = (
    "f6b893223e88f847c42f7a642a6eee9bc385b69b554395e3e7cd4e4eb48c96e5"
)
CURRENT_CONSENSUS_AUTONOMY_INVENTORY_RAW_SHA256 = (
    "1ad5f01be51bc987862186884e319d1cd2685e64a5b70433cc58e586d3f37485"
)
CURRENT_CONSENSUS_AUTONOMY_INVENTORY_SCHEMA_RAW_SHA256 = (
    "cd41245cbb4728c2f9891a8a995bc094c239d4dc4c7be8d6d8d3f5e3a1738714"
)
CURRENT_CONSENSUS_AUTONOMY_INVENTORY_SHA256 = (
    "0a219346ced90d778e9e3127e5413a9a84479523567ff9d8a060e428584bce5a"
)
CURRENT_CONSENSUS_AUTONOMY_DISCOVERY_SEMANTICS_SHA256 = (
    "9e61d9d5b2a3d09bb29da33265bd8eee701dacc56f47845d10e25fc00c43ee88"
)
CURRENT_CONSENSUS_AUTONOMY_SOURCE_UNIVERSE_SHA256 = (
    "892668c971d9e851a9855271e0e7b8a113020c10b526c8145c3a7f5ebea178ac"
)
CURRENT_MODELREFRESH_AUTONOMY_INVENTORY_RAW_SHA256 = (
    "fc34a357c2bbbf3b0a6d624068a520b9745652fccfe2a40e14d0c05fd2398e7b"
)
CURRENT_MODELREFRESH_AUTONOMY_INVENTORY_SHA256 = (
    "133cc9e595d2ce28706d0cbbd937ea78e9703fe13d93c1043675f685ebd33a05"
)
CURRENT_MODELREFRESH_AUTONOMY_DISCOVERY_SEMANTICS_SHA256 = (
    "f6f918fde621de4804483a2b8f154a55a7fe0823f559b8c5a874841dbe6561f2"
)
CURRENT_MODELREFRESH_AUTONOMY_SOURCE_UNIVERSE_SHA256 = (
    "c6c6a72fd363d5ec22a206a29a399ef37b23fc53505dae0bedd8c6ca2f42fca4"
)
CURRENT_RETRYCONT_AUTONOMY_INVENTORY_RAW_SHA256 = (
    "21e1bd93ca816df132441c83c9874e4715abab651186f2c9b05ab1e4d0688700"
)
CURRENT_RETRYCONT_AUTONOMY_INVENTORY_SCHEMA_RAW_SHA256 = (
    "264c341c83422ed8b1ea0c2c4141ac6d53f612173448d08d855e87cd756cd761"
)
CURRENT_RETRYCONT_AUTONOMY_INVENTORY_SHA256 = (
    "9ff119fc6324ab3f3d02cc9eb7a306588b94a2f7a1715385a69cfd707b1c7e9d"
)
CURRENT_RETRYCONT_AUTONOMY_DISCOVERY_SEMANTICS_SHA256 = (
    "b68d4f37488072f37c097b1620daffd3a1397fa32a4773256d71e5d4d893d7b2"
)
CURRENT_RETRYCONT_AUTONOMY_SOURCE_UNIVERSE_SHA256 = (
    "f47561a1fb172db9a8739c5ee5a8492d95ffb06e0e0a5935be635d155d2891f1"
)
CURRENT_SCHEMARETRY_AUTONOMY_INVENTORY_RAW_SHA256 = (
    "6451a873fd2d52d5ee3a9bc6afaa875090f489982e94bca9e1122d9b63ed9bd0"
)
CURRENT_SCHEMARETRY_AUTONOMY_INVENTORY_SCHEMA_RAW_SHA256 = (
    "78e9541c32de209c48632602f368113b0781dacba4104904c26a7817e4ff9b08"
)
CURRENT_SCHEMARETRY_AUTONOMY_INVENTORY_SHA256 = (
    "194b3d3423b992255bc932383b1988d36965040b2e767d9ea4665d43d20b8e23"
)
CURRENT_SCHEMARETRY_AUTONOMY_DISCOVERY_SEMANTICS_SHA256 = (
    "780cba1dc17a14f0bd749f5878eb0a311c84431fcc1ea39ffb89f89a12bb3cc0"
)
CURRENT_SCHEMARETRY_AUTONOMY_SOURCE_UNIVERSE_SHA256 = (
    "924720fbeda73c21f1311d086c4fcc0370d190dcdbe0a754f564dd99892a9f14"
)
CURRENT_RETRIEVAL_AUTONOMY_INVENTORY_RAW_SHA256 = (
    "71bcd46da89cd7a1b31ec0ca35b5a7f4a4004ffbc871fd34ff0e520ab0894073"
)
CURRENT_RETRIEVAL_AUTONOMY_INVENTORY_SCHEMA_RAW_SHA256 = (
    "228db72a188433fa9727fc8f0185b69949c615c81f56abbad1565cc0492af4ab"
)
CURRENT_RETRIEVAL_AUTONOMY_INVENTORY_SHA256 = (
    "ebdcf5520ffe0f82d3a0bcc6fb5669ce2e2724730521ad71f55e54f29e2da830"
)
CURRENT_RETRIEVAL_AUTONOMY_DISCOVERY_SEMANTICS_SHA256 = (
    "63550cead89dcf5425fa06374df61e225a93342b7a55a3774532597b002b33ee"
)
CURRENT_RETRIEVAL_AUTONOMY_SOURCE_UNIVERSE_SHA256 = (
    "d0a1471e64dc50a32e23a3dab4c52a14d56acb22f8ab5f460a2494c7a0f3c6fa"
)
CURRENT_ENDPOINTLIST_DIAGNOSTIC_SCHEMA_RAW_SHA256 = (
    "326cd2a83b5bc1b825018bfbfe2e7244c62587105d1bc188e4dbe3ff7b8a2b72"
)
ROUTE_RUNTIME_EVIDENCE_SCHEMA_RAW_SHA256 = (
    "e3b1280836581456a43c73c0eaa9acc184dc05bb175c0dac4a83973bab79c921"
)
MANAGED_TOOLCHAIN_RAW_SHA256 = "6d427e698d1074be2d20747211bcdd53816509e0e71b4225dff0401c32d6561a"
MANAGED_TOOLCHAIN_SHA256 = "55c412fdb2dd56a2541c0e737d953b5d0e770ece42b4c1c11ebfb7e1c233498d"
MANAGED_TOOLCHAIN_SCHEMA_RAW_SHA256 = (
    "068d3daa7a0c661e6ad6781d4184ce27e53edbc3c8867989d5dc0c877b73c785"
)
AUTONOMY_PHASE_ZERO_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "schemas/autonomy_gate_inventory.schema.json",
        "scripts/generate_release_schemas.py",
        "src/mmaudit/orchestration/autonomy_gate_inventory.py",
        "tests/unit/test_autonomy_gate_inventory.py",
        "tests/unit/test_release_schemas.py",
    }
)
PHASE_ONE_IMPLEMENTATION_PATHS = frozenset(
    {
        "docs/codex_work_queue.md",
        "docs/codex_worklog.md",
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "docs/remediation/v3/review_traceability.json",
        "docs/remediation/v3/runtime_status.json",
        "docs/remediation/v3/work_queue.md",
        "docs/remediation/v3/worklog.md",
        "schemas/managed_toolchain_bundle.schema.json",
        "scripts/generate_release_schemas.py",
        "src/mmaudit/orchestration/autonomy_gate_inventory.py",
        "src/mmaudit/orchestration/managed_toolchain.py",
        "src/mmaudit/resources/managed_toolchain_bundle.json",
        "tests/unit/test_autonomy_gate_inventory.py",
        "tests/unit/test_managed_toolchain.py",
        "tests/unit/test_packaged_scanner_resources.py",
        "tests/unit/test_product_documentation.py",
        "tests/unit/test_product_objective.py",
        "tests/unit/test_release_schemas.py",
    }
)
PHASE_ONE_GOVERNANCE_SUCCESSOR_PATHS = frozenset(
    {
        "docs/codex_work_queue.md",
        "docs/codex_worklog.md",
        "docs/remediation/v3/review_traceability.json",
        "docs/remediation/v3/runtime_status.json",
        "docs/remediation/v3/work_queue.md",
        "docs/remediation/v3/worklog.md",
        "tests/unit/test_product_documentation.py",
        "tests/unit/test_product_objective.py",
    }
)
CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS = PHASE_ONE_GOVERNANCE_SUCCESSOR_PATHS | {
    "docs/models/model_selection.md"
}
PHASE_ONE_CORE_PATHS = PHASE_ONE_IMPLEMENTATION_PATHS - PHASE_ONE_GOVERNANCE_SUCCESSOR_PATHS
AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "schemas/authenticated_runner_smoke_evidence_bundle.schema.json",
        "schemas/autonomy_gate_inventory.schema.json",
        "src/mmaudit/benchmark/cross_lineage_adjudication.py",
        "src/mmaudit/benchmark/models.py",
        "src/mmaudit/cli.py",
        "src/mmaudit/models/authenticated_runner_smoke.py",
        "src/mmaudit/models/usage.py",
        "src/mmaudit/orchestration/authenticated_runner_smoke_openrouter.py",
        "src/mmaudit/orchestration/autonomy_gate_inventory.py",
        "tests/unit/test_authenticated_runner_smoke_benchmark.py",
        "tests/unit/test_authenticated_runner_smoke_cli.py",
        "tests/unit/test_authenticated_runner_smoke_runtime.py",
        "tests/unit/test_autonomy_gate_inventory.py",
        "tests/unit/test_cross_lineage_adjudication.py",
        "tests/unit/test_usage.py",
    }
)
AUTONOMY_WORKTREE_INDEPENDENCE_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/orchestration/autonomy_gate_inventory.py",
        "tests/unit/test_autonomy_gate_inventory.py",
    }
)
AUTHRUNNER_TOKEN_ENVELOPE_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "schemas/authenticated_runner_durable_evidence_bundle.schema.json",
        "schemas/authenticated_runner_smoke_evidence_bundle.schema.json",
        "schemas/authenticated_runner_staged_cost_plan.schema.json",
        "schemas/context_manifest.schema.json",
        "schemas/cross_lineage_adjudication_report.schema.json",
        "schemas/model_execution_artifact.schema.json",
        "schemas/openrouter_structured_request_cost_preview.schema.json",
        "src/mmaudit/benchmark/cross_lineage_adjudication.py",
        "src/mmaudit/benchmark/models.py",
        "src/mmaudit/models/authenticated_runner_smoke.py",
        "src/mmaudit/models/generation_evidence.py",
        "src/mmaudit/models/openrouter.py",
        "src/mmaudit/models/reasoning.py",
        "src/mmaudit/models/schemas.py",
        "src/mmaudit/models/token_planning.py",
        "src/mmaudit/models/usage.py",
        "src/mmaudit/orchestration/authenticated_runner_smoke_openrouter.py",
        "src/mmaudit/orchestration/budgets.py",
        "src/mmaudit/orchestration/context_manifest.py",
        "tests/unit/test_authenticated_runner_smoke_benchmark.py",
        "tests/unit/test_authenticated_runner_smoke_cli.py",
        "tests/unit/test_authenticated_runner_smoke_runtime.py",
        "tests/unit/test_cross_lineage_adjudication.py",
        "tests/unit/test_generation_evidence.py",
        "tests/unit/test_openrouter.py",
        "tests/unit/test_openrouter_request_cost_preview.py",
        "tests/unit/test_reasoning.py",
        "tests/unit/test_token_planning.py",
    }
)
AUTHRUNNER_IDENTITY_DIAGNOSTIC_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/benchmark/models.py",
        "tests/unit/test_authenticated_runner_smoke_benchmark.py",
        "tests/unit/test_openrouter.py",
    }
)
AUTHRUNNER_SCOPE_CUTOFF_HOTFIX_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/benchmark/models.py",
        "src/mmaudit/models/openrouter.py",
        "src/mmaudit/models/usage.py",
        "tests/unit/test_authenticated_runner_smoke_benchmark.py",
        "tests/unit/test_openrouter.py",
        "tests/unit/test_usage.py",
    }
)
AUTHRUNNER_RECEIPT_COMPOSITE_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "pyproject.toml",
        "src/mmaudit/benchmark/cross_lineage_adjudication.py",
        "src/mmaudit/benchmark/models.py",
        "src/mmaudit/models/generation_evidence.py",
        "src/mmaudit/models/openrouter.py",
        "src/mmaudit/models/usage.py",
        "src/mmaudit/orchestration/autonomy_gate_inventory.py",
        "tests/integration/test_openrouter_httpx_response_graph.py",
        "tests/unit/test_authenticated_runner.py",
        "tests/unit/test_authenticated_runner_smoke_benchmark.py",
        "tests/unit/test_autonomy_gate_inventory.py",
        "tests/unit/test_cross_lineage_adjudication.py",
        "tests/unit/test_openrouter.py",
    }
)
AUTHRUNNER_RECEIPT_STATE_SEAL_HOTFIX_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/models/openrouter.py",
        "tests/integration/test_openrouter_httpx_response_graph.py",
        "tests/unit/test_openrouter.py",
    }
)
AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/models/usage.py",
        "tests/unit/test_authenticated_runner_smoke_benchmark.py",
        "tests/unit/test_openrouter.py",
        "tests/unit/test_usage.py",
    }
)
AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/models/usage.py",
        "tests/unit/test_openrouter.py",
        "tests/unit/test_openrouter_request_cost_preview.py",
        "tests/unit/test_usage.py",
    }
)
AUTHRUNNER_CANONICAL_REPLAY_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/models/authenticated_runner_smoke.py",
        "tests/unit/test_authenticated_runner_smoke_runtime.py",
    }
)
PLANCONSTRAINTS_SOURCE_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/models/route_constraints.py",
        "tests/unit/test_endpoint_snapshots.py",
        "tests/unit/test_model_discovery.py",
        "tests/unit/test_route_constraints.py",
    }
)
TRUNCATION_SPECIALIST_SOURCE_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "schemas/scheduler_state.schema.json",
        "src/mmaudit/agents/specialists.py",
        "src/mmaudit/models/scheduler.py",
        "src/mmaudit/models/truncation_recovery_journal.py",
        "src/mmaudit/orchestration/assurance.py",
        "src/mmaudit/orchestration/pipeline.py",
        "src/mmaudit/orchestration/scheduler.py",
        "src/mmaudit/orchestration/truncation_recovery_evidence.py",
        "tests/fake_openrouter.py",
        "tests/integration/test_pipeline.py",
        "tests/integration/test_scheduler_truncation_recovery_pipeline.py",
        "tests/unit/test_assurance.py",
        "tests/unit/test_model_coverage.py",
        "tests/unit/test_specialists.py",
        "tests/unit/test_truncation_recovery_journal.py",
    }
)
HISTORICAL_TRUNCATION_RECURSIVE_SOURCE_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/models/scheduler.py",
        "src/mmaudit/models/truncation_recovery_journal.py",
        "src/mmaudit/orchestration/pipeline.py",
        "src/mmaudit/orchestration/scheduler.py",
        "tests/fake_openrouter.py",
        "tests/integration/test_scheduler_truncation_recovery_pipeline.py",
        "tests/unit/test_truncation_recovery_journal.py",
    }
)
TRUNCATION_PROMOTION_SOURCE_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "schemas/scheduler_state.schema.json",
        "scripts/generate_release_schemas.py",
        "src/mmaudit/models/scheduler.py",
        "src/mmaudit/models/truncation_closure.py",
        "src/mmaudit/models/truncation_recovery_journal.py",
        "src/mmaudit/orchestration/assurance.py",
        "src/mmaudit/orchestration/autonomy_gate_inventory.py",
        "src/mmaudit/orchestration/model_coverage.py",
        "src/mmaudit/orchestration/pipeline.py",
        "src/mmaudit/orchestration/scheduler.py",
        "src/mmaudit/orchestration/truncation_recovery_evidence.py",
        "tests/unit/test_assurance.py",
        "tests/unit/test_autonomy_gate_inventory.py",
        "tests/unit/test_model_coverage.py",
        "tests/unit/test_release_schemas.py",
        "tests/unit/test_scheduler_truncation_promotion_integration.py",
        "tests/unit/test_truncation_recovery_evidence.py",
        "tests/unit/test_truncation_recovery_journal.py",
        "tests/unit/test_truncation_recovery_promotion_models.py",
    }
)
CURRENT_COVERAGE_SOURCE_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "schemas/model_portfolio_resource_preflight.schema.json",
        "schemas/scheduler_state.schema.json",
        "scripts/generate_release_schemas.py",
        "src/mmaudit/models/coverage_planning.py",
        "src/mmaudit/models/openrouter.py",
        "src/mmaudit/models/scheduler.py",
        "src/mmaudit/models/truncation_recovery_journal.py",
        "src/mmaudit/models/usage.py",
        "src/mmaudit/orchestration/autonomy_gate_inventory.py",
        "src/mmaudit/orchestration/budgets.py",
        "src/mmaudit/orchestration/cost_ledger.py",
        "src/mmaudit/orchestration/pipeline.py",
        "src/mmaudit/orchestration/scheduler.py",
        "src/mmaudit/orchestration/scheduler_runtime.py",
        "tests/fake_openrouter.py",
        "tests/integration/test_coverage_pipeline_integration.py",
        "tests/integration/test_pipeline.py",
        "tests/integration/test_scheduler_truncation_recovery_pipeline.py",
        "tests/unit/test_autonomy_gate_inventory.py",
        "tests/unit/test_budgets.py",
        "tests/unit/test_cost_ledger.py",
        "tests/unit/test_coverage_pipeline_wiring.py",
        "tests/unit/test_coverage_planning.py",
        "tests/unit/test_coverage_resource_preview.py",
        "tests/unit/test_logical_request_identity.py",
        "tests/unit/test_release_schemas.py",
        "tests/unit/test_scheduler_journal.py",
        "tests/unit/test_scheduler_manifest.py",
        "tests/unit/test_scheduler_recovery_release_projection.py",
        "tests/unit/test_truncation_recovery_cost_resume.py",
        "tests/unit/test_truncation_recovery_journal.py",
        "tests/unit/test_usage.py",
    }
)
V3_RETRY_SOURCE_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "schemas/autonomy_gate_inventory.schema.json",
        "src/mmaudit/benchmark/models.py",
        "src/mmaudit/config.py",
        "src/mmaudit/models/authenticated_runner_execution.py",
        "src/mmaudit/models/candidate_benchmark.py",
        "src/mmaudit/models/openrouter.py",
        "src/mmaudit/orchestration/authenticated_runner_smoke_openrouter.py",
        "src/mmaudit/orchestration/autonomy_gate_inventory.py",
        "src/mmaudit/templates/mmaudit.example.toml",
        "tests/unit/test_authenticated_runner_execution.py",
        "tests/unit/test_autonomy_gate_inventory.py",
        "tests/unit/test_config.py",
        "tests/unit/test_model_benchmark.py",
        "tests/unit/test_openrouter.py",
        "tests/unit/test_openrouter_qualification_config.py",
        "tests/unit/test_openrouter_request_cost_preview.py",
    }
)
AUTHRUNNER_UNCHANGED_IMPLEMENTATION_PATHS = (
    AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_PATHS - AUTONOMY_WORKTREE_INDEPENDENCE_PATHS
)
PHASE_ONE_CORE_SUCCESSOR_PATHS = PHASE_ONE_CORE_PATHS & (
    AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_PATHS
)
PHASE_ONE_UNCHANGED_CORE_PATHS = PHASE_ONE_CORE_PATHS - PHASE_ONE_CORE_SUCCESSOR_PATHS
OPERATOR_RESULTS_RELATIVE_PATH = "docs/remediation/v3/operator_results.md"
HISTORICAL_50D_OPERATOR_RESULTS_CHECKPOINT_PATHS = frozenset(
    {
        "docs/codex_work_queue.md",
        OPERATOR_RESULTS_RELATIVE_PATH,
    }
)
HISTORICAL_INELIGIBLE_GEMMA_PLAN_SHA256 = (
    "41b5af9ae4def5ef535ae25a13c7c38b95d5819a878a5eef1c1c5bfb8386bf58"
)
HISTORICAL_INELIGIBLE_GEMMA_ROLE_SHA256 = (
    "f1c80252e94bf789d1b78f424a8b9c142f7e750e8ee0ba3bacfaae2a3330aa25"
)
CURRENT_NONAUTHORIZING_SUCCESSOR_PLAN_SHA256 = (
    "bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f"
)
CURRENT_NONAUTHORIZING_SUCCESSOR_ROLE_SHA256 = (
    "7d67d43f98484890bf9f184a5bb89fbba25d0408dee65a7174eef5fdf1a75b14"
)
CURRENT_NONAUTHORIZING_ZAI_ENTRY_SHA256 = (
    "45f0a3f416a806932e2596ca4f6381e12bbc4901d15c301b22fd5d607a7f55ef"
)
CURRENT_NONAUTHORIZING_DEEPSEEK_ENTRY_SHA256 = (
    "da576e8d1835b41be94ea4dab6cd6329ae8c1483b830214d9e05acef44e8617b"
)
CURRENT_NONAUTHORIZING_KIMI_ENTRY_SHA256 = (
    "77217b6dca94bc292a13cc5a5ce84c48c68a6bb2e055462db51048013abd3f11"
)
CURRENT_LINEAGE_MANIFEST_SHA256 = "b097a65613a07930f5c256c63065202a8998d5212a0021312a0e315ff6557b53"
CURRENT_LINEAGE_SEMANTIC_BUNDLE_SHA256 = (
    "815fc0e376682f83f994ac5c21962c5f43556a78f5e736045f93a6ee81e5de0d"
)
NATIVE_STRUCTURED_OUTPUT_GATE_CHECKPOINT = "68d774b2cee5fa69476b1cfea2f8172731a365c8"
HISTORICAL_PAID_DIAGNOSTIC_BASE_CHECKPOINT = "b4134c70641e33cbbff2b430b135910df903733b"
HISTORICAL_R6_R6_R2_OPERATOR_RESULTS_SHA256 = (
    "e7e631be16b5502f6e16b1d2aeae9ac226d8d79050263f27555f5ff8f812b0fd"
)
PRODUCT_VISION_GIT_ATTRIBUTES = f"{PRODUCT_VISION_RELATIVE_PATH} -text"
POLICY_ELIGIBILITY_TICKET = "V3-POLICYELIG-001"
POLICY_ELIGIBILITY_QUEUE_HEADING = (
    "## V3-POLICYELIG-001 — Provider terms and jurisdictional eligibility for model use"
)

ALLOWED_TICKET_STATUSES = frozenset(
    {
        "QUEUED",
        "IN_PROGRESS",
        "COMPLETE",
        "PARTIAL",
        "BLOCKED_TECHNICAL",
        "BLOCKED_SAFETY",
    }
)
README_CAPABILITY_TICKETS = frozenset(
    {
        "V3-SHARD-001",
        "V3-SCHEDULER-001",
        "V3-EXECORIGIN-001",
        "V3-FORKSUITE-001",
        "V3-TESTQUALITY-001",
        "V3-TOKENS-001",
        "V3-OMISSION-001",
        "V3-GRAPHBOUND-001",
    }
)
MODEL_WORK_TICKETS = frozenset(
    {
        "V3-MODELREFRESH-001",
        "V3-LINEAGE-001",
        "V3-CALIBRATE-001",
        "V3-QUALIFY-001",
        "V3-POLICYELIG-001",
    }
)
EXPECTED_REQUIREMENT_IDS = tuple("ABCDEFGHIJKLMNOPQRSTUV")

_LEVEL_TWO_HEADING = re.compile(r"^## (?P<title>[^\n]+)$", re.MULTILINE)
_LEVEL_THREE_HEADING = re.compile(r"^### (?P<title>[^\n]+)$", re.MULTILINE)
_QUEUE_TICKET_HEADING = re.compile(r"^#{2,3} (?P<title>[^\n]+)$", re.MULTILINE)
_TICKET_TITLE = re.compile(r"^(?P<ticket>V3-[A-Z0-9]+(?:-[A-Z0-9]+)*)\b")
_ANY_TICKET_TITLE = re.compile(r"^(?P<ticket>[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)\b")
_TICKET_STATUS = re.compile(
    r"^- \*\*Status:\*\* `(?P<status>[A-Z_]+)`\s*$",
    re.MULTILINE,
)
_STATUS_TABLE_ROW = re.compile(
    r"^\|\s*(?P<label>[^|\n]+?)\s*\|\s*"
    r"`(?P<ticket>V3-[A-Z0-9]+(?:-[A-Z0-9]+)*)`\s*\|\s*"
    r"`(?P<status>[A-Z_]+)`\s*\|(?:\s*[^|\n]+\s*\|)*\s*$",
    re.MULTILINE,
)


def _parse_queue_ticket_statuses(document: str) -> dict[str, str]:
    headings = list(_LEVEL_TWO_HEADING.finditer(document))
    statuses: dict[str, str] = {}
    for index, heading in enumerate(headings):
        ticket_match = _TICKET_TITLE.match(heading.group("title"))
        if ticket_match is None:
            continue
        ticket = ticket_match.group("ticket")
        assert ticket not in statuses, f"duplicate queue ticket heading: {ticket}"
        body_end = headings[index + 1].start() if index + 1 < len(headings) else len(document)
        body = document[heading.end() : body_end]
        status_matches = list(_TICKET_STATUS.finditer(body))
        assert len(status_matches) == 1, (
            f"queue ticket {ticket} must have exactly one anchored Status line; "
            f"found {len(status_matches)}"
        )
        status = status_matches[0].group("status")
        assert status in ALLOWED_TICKET_STATUSES, (
            f"queue ticket {ticket} has unsupported status {status}"
        )
        statuses[ticket] = status
    assert statuses, "queue contains no parseable V3 ticket blocks"
    return statuses


def _parse_all_queue_ticket_statuses(document: str) -> dict[str, str]:
    headings = list(_QUEUE_TICKET_HEADING.finditer(document))
    statuses: dict[str, str] = {}
    for index, heading in enumerate(headings):
        ticket_match = _ANY_TICKET_TITLE.match(heading.group("title"))
        if ticket_match is None:
            continue
        body_end = headings[index + 1].start() if index + 1 < len(headings) else len(document)
        body = document[heading.end() : body_end]
        status_matches = list(_TICKET_STATUS.finditer(body))
        if not status_matches:
            continue
        ticket = ticket_match.group("ticket")
        assert ticket not in statuses, f"duplicate queue ticket heading: {ticket}"
        assert len(status_matches) == 1, (
            f"queue ticket {ticket} must have exactly one anchored Status line; "
            f"found {len(status_matches)}"
        )
        status = status_matches[0].group("status")
        assert status in ALLOWED_TICKET_STATUSES, (
            f"queue ticket {ticket} has unsupported status {status}"
        )
        statuses[ticket] = status
    assert statuses, "queue contains no parseable ticket blocks"
    return statuses


def _isolated_level_two_section(document: str, heading: str) -> str:
    marker = f"{heading}\n"
    assert document.count(marker) == 1, f"expected exactly one {heading!r} section"
    _, _, remainder = document.partition(marker)
    next_heading = _LEVEL_TWO_HEADING.search(remainder)
    return remainder if next_heading is None else remainder[: next_heading.start()]


def _isolated_level_three_section(document: str, heading: str) -> str:
    marker = f"{heading}\n"
    assert document.count(marker) == 1, f"expected exactly one {heading!r} section"
    _, _, remainder = document.partition(marker)
    next_heading = _LEVEL_THREE_HEADING.search(remainder)
    return remainder if next_heading is None else remainder[: next_heading.start()]


def _parse_status_table(document: str, heading: str) -> dict[str, str]:
    section = _isolated_level_two_section(document, heading)
    statuses: dict[str, str] = {}
    for match in _STATUS_TABLE_ROW.finditer(section):
        ticket = match.group("ticket")
        status = match.group("status")
        assert ticket not in statuses, f"duplicate status-table row for {ticket}"
        assert status in ALLOWED_TICKET_STATUSES, (
            f"status-table row for {ticket} has unsupported status {status}"
        )
        assert match.group("label").strip(), f"status-table row for {ticket} has no label"
        statuses[ticket] = status
    assert statuses, f"{heading!r} has no parseable capability rows"
    return statuses


def _derive_requirement_status(
    tickets: Sequence[str],
    queue_statuses: Mapping[str, str],
) -> str:
    assert tickets, "traceability requirement must reference at least one ticket"
    assert len(tickets) == len(set(tickets)), "traceability requirement repeats a ticket"
    if list(tickets) == ["ALL"]:
        assert queue_statuses, "ALL cannot derive from an empty queue"
        return (
            "COMPLETE"
            if all(status == "COMPLETE" for status in queue_statuses.values())
            else "IN_PROGRESS"
        )
    assert "ALL" not in tickets, "ALL cannot be combined with individual ticket IDs"
    unknown = sorted(set(tickets) - set(queue_statuses))
    assert not unknown, f"traceability requirement references unknown tickets: {unknown}"
    mapped = [queue_statuses[ticket] for ticket in tickets]
    if all(status == "COMPLETE" for status in mapped):
        return "COMPLETE"
    if "IN_PROGRESS" in mapped:
        return "IN_PROGRESS"
    if any(status in {"COMPLETE", "PARTIAL"} for status in mapped):
        return "PARTIAL"
    if "BLOCKED_SAFETY" in mapped:
        return "BLOCKED_SAFETY"
    if "BLOCKED_TECHNICAL" in mapped:
        return "BLOCKED_TECHNICAL"
    return "QUEUED"


def _field_default(class_name: str, field_name: str) -> int:
    tree = ast.parse(CONFIG_PATH.read_text(encoding="utf-8"), filename=str(CONFIG_PATH))
    class_nodes = [
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name
    ]
    assert len(class_nodes) == 1, f"expected one {class_name} declaration"
    assignments = [
        node
        for node in class_nodes[0].body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == field_name
    ]
    assert len(assignments) == 1, f"expected one {class_name}.{field_name} declaration"
    value = assignments[0].value
    assert isinstance(value, ast.Call), f"{class_name}.{field_name} must use Field(default=...)"
    default_keywords = [keyword for keyword in value.keywords if keyword.arg == "default"]
    assert len(default_keywords) == 1, (
        f"{class_name}.{field_name} must have exactly one explicit Field default"
    )
    default = ast.literal_eval(default_keywords[0].value)
    assert isinstance(default, int) and not isinstance(default, bool), (
        f"{class_name}.{field_name} default must be an integer"
    )
    return default


def _field_default_factory(class_name: str, field_name: str) -> str:
    tree = ast.parse(CONFIG_PATH.read_text(encoding="utf-8"), filename=str(CONFIG_PATH))
    class_nodes = [
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name
    ]
    assert len(class_nodes) == 1, f"expected one {class_name} declaration"
    assignments = [
        node
        for node in class_nodes[0].body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == field_name
    ]
    assert len(assignments) == 1, f"expected one {class_name}.{field_name} declaration"
    value = assignments[0].value
    assert isinstance(value, ast.Call), (
        f"{class_name}.{field_name} must use Field(default_factory=...)"
    )
    factory_keywords = [keyword for keyword in value.keywords if keyword.arg == "default_factory"]
    assert len(factory_keywords) == 1 and isinstance(factory_keywords[0].value, ast.Name), (
        f"{class_name}.{field_name} must have one named Field default_factory"
    )
    return factory_keywords[0].value.id


def _assert_fails(expected: str, operation: Callable[[], object]) -> None:
    try:
        operation()
    except AssertionError as exc:
        assert expected in str(exc)
    else:
        raise AssertionError(f"operation did not fail with {expected!r}")


def test_queue_parser_rejects_duplicate_missing_and_invalid_statuses() -> None:
    duplicate_heading = """
## V3-ONE-001 — first

- **Status:** `QUEUED`

## V3-ONE-001 — duplicate

- **Status:** `COMPLETE`
"""
    duplicate_status = """
## V3-ONE-001 — duplicate status

- **Status:** `QUEUED`
- **Status:** `COMPLETE`
"""
    missing_status = """
## V3-ONE-001 — missing status

- **Objective:** synthetic parser fixture.
"""
    invalid_status = """
## V3-ONE-001 — invalid status

- **Status:** `DONE`
"""

    _assert_fails(
        "duplicate queue ticket heading",
        lambda: _parse_queue_ticket_statuses(duplicate_heading),
    )
    _assert_fails(
        "exactly one anchored Status line",
        lambda: _parse_queue_ticket_statuses(duplicate_status),
    )
    _assert_fails(
        "exactly one anchored Status line",
        lambda: _parse_queue_ticket_statuses(missing_status),
    )
    _assert_fails(
        "unsupported status",
        lambda: _parse_queue_ticket_statuses(invalid_status),
    )


def test_autonomy_checkpoints_have_exact_historical_and_successor_custody() -> None:
    resolved = subprocess.run(
        ["git", "rev-parse", f"{HISTORICAL_PHASE_ZERO_CHECKPOINT}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            HISTORICAL_PHASE_ZERO_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    source_tree = subprocess.run(
        [
            "git",
            "ls-tree",
            "-r",
            "--name-only",
            HISTORICAL_PHASE_ZERO_CHECKPOINT,
            "src",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    historical_inventory = subprocess.run(
        [
            "git",
            "show",
            f"{HISTORICAL_PHASE_ZERO_CHECKPOINT}:docs/remediation/v3/autonomy_gate_inventory.json",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )

    assert resolved.stdout.strip() == HISTORICAL_PHASE_ZERO_CHECKPOINT
    assert frozenset(changed.stdout.splitlines()) == AUTONOMY_PHASE_ZERO_PATHS
    assert sum(path.endswith(".py") for path in source_tree.stdout.splitlines()) == 207
    assert (
        hashlib.sha256(historical_inventory.stdout).hexdigest()
        == HISTORICAL_PHASE_ZERO_INVENTORY_RAW_SHA256
    )

    resolved = subprocess.run(
        ["git", "rev-parse", f"{PHASE_ONE_IMPLEMENTATION_CHECKPOINT}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            PHASE_ONE_IMPLEMENTATION_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    authrunner_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    authrunner_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    token_envelope_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{AUTHRUNNER_TOKEN_ENVELOPE_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    token_envelope_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            AUTHRUNNER_TOKEN_ENVELOPE_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    identity_diagnostic_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{AUTHRUNNER_IDENTITY_DIAGNOSTIC_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    identity_diagnostic_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            AUTHRUNNER_IDENTITY_DIAGNOSTIC_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    scope_cutoff_hotfix_resolved = subprocess.run(
        ["git", "rev-parse", f"{HISTORICAL_AUTHRUNNER_SCOPE_CUTOFF_CHECKPOINT}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    scope_cutoff_hotfix_parent = subprocess.run(
        ["git", "rev-parse", f"{HISTORICAL_AUTHRUNNER_SCOPE_CUTOFF_CHECKPOINT}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    scope_cutoff_hotfix_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            HISTORICAL_AUTHRUNNER_SCOPE_CUTOFF_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    receipt_composite_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    receipt_composite_parent = subprocess.run(
        ["git", "rev-parse", f"{HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    receipt_composite_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    receipt_state_seal_hotfix_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{HISTORICAL_AUTHRUNNER_RECEIPT_STATE_SEAL_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    receipt_state_seal_hotfix_parent = subprocess.run(
        ["git", "rev-parse", f"{HISTORICAL_AUTHRUNNER_RECEIPT_STATE_SEAL_CHECKPOINT}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    receipt_state_seal_hotfix_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            HISTORICAL_AUTHRUNNER_RECEIPT_STATE_SEAL_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    structured_output_diagnostic_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    structured_output_diagnostic_parent = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT}^",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    structured_output_diagnostic_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    required_provider_parameters_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    required_provider_parameters_parent = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT}^",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    required_provider_parameters_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    canonical_replay_resolved = subprocess.run(
        ["git", "rev-parse", f"{HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    canonical_replay_parent = subprocess.run(
        ["git", "rev-parse", f"{HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    canonical_replay_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    canonical_replay_smoke_bytes = subprocess.run(
        [
            "git",
            "show",
            f"{HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT}:"
            "src/mmaudit/models/authenticated_runner_smoke.py",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    planconstraints_repair_resolved = subprocess.run(
        ["git", "rev-parse", f"{PLANCONSTRAINTS_REPAIR_CHECKPOINT}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    planconstraints_repair_parent = subprocess.run(
        ["git", "rev-parse", f"{PLANCONSTRAINTS_REPAIR_CHECKPOINT}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    planconstraints_repair_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            PLANCONSTRAINTS_REPAIR_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    truncation_specialist_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    truncation_specialist_parent = subprocess.run(
        ["git", "rev-parse", f"{CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    truncation_specialist_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    truncation_recursive_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{HISTORICAL_TRUNCATION_RECURSIVE_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    truncation_recursive_parent = subprocess.run(
        ["git", "rev-parse", f"{HISTORICAL_TRUNCATION_RECURSIVE_CHECKPOINT}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    truncation_recursive_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            HISTORICAL_TRUNCATION_RECURSIVE_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    truncation_promotion_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{CURRENT_TRUNCATION_PROMOTION_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    truncation_promotion_parent = subprocess.run(
        ["git", "rev-parse", f"{CURRENT_TRUNCATION_PROMOTION_CHECKPOINT}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    truncation_promotion_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            CURRENT_TRUNCATION_PROMOTION_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    coverage_resolved = subprocess.run(
        ["git", "rev-parse", f"{CURRENT_COVERAGE_CHECKPOINT}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    coverage_parent = subprocess.run(
        ["git", "rev-parse", f"{CURRENT_COVERAGE_CHECKPOINT}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    coverage_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            CURRENT_COVERAGE_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    retry_resolved = subprocess.run(
        ["git", "rev-parse", f"{CURRENT_RETRY_CHECKPOINT}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    retry_parent = subprocess.run(
        ["git", "rev-parse", f"{CURRENT_RETRY_CHECKPOINT}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    retry_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            CURRENT_RETRY_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    retry_inventory_bytes = subprocess.run(
        [
            "git",
            "show",
            f"{CURRENT_RETRY_CHECKPOINT}:docs/remediation/v3/autonomy_gate_inventory.json",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    retry_inventory = json.loads(retry_inventory_bytes)
    retry_inventory_schema_bytes = subprocess.run(
        [
            "git",
            "show",
            f"{CURRENT_RETRY_CHECKPOINT}:schemas/autonomy_gate_inventory.schema.json",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    operator_results_checkpoint_resolved = subprocess.run(
        ["git", "rev-parse", f"{HISTORICAL_50D_OPERATOR_RESULTS_CHECKPOINT}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    operator_results_checkpoint_parent = subprocess.run(
        ["git", "rev-parse", f"{HISTORICAL_50D_OPERATOR_RESULTS_CHECKPOINT}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    operator_results_checkpoint_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            HISTORICAL_50D_OPERATOR_RESULTS_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    operator_results_remote_ancestry = subprocess.run(
        [
            "git",
            "merge-base",
            "--is-ancestor",
            HISTORICAL_50D_OPERATOR_RESULTS_CHECKPOINT,
            "origin/agent/v3-wip-checkpoint",
        ],
        cwd=ROOT,
        check=False,
    )
    worktree_independence_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{AUTONOMY_WORKTREE_INDEPENDENCE_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    worktree_independence_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            AUTONOMY_WORKTREE_INDEPENDENCE_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert resolved.stdout.strip() == PHASE_ONE_IMPLEMENTATION_CHECKPOINT
    assert len(PHASE_ONE_IMPLEMENTATION_PATHS) == 18
    assert len(PHASE_ONE_CORE_PATHS) == 10
    assert len(PHASE_ONE_CORE_SUCCESSOR_PATHS) == 3
    assert len(PHASE_ONE_UNCHANGED_CORE_PATHS) == 7
    assert len(PHASE_ONE_GOVERNANCE_SUCCESSOR_PATHS) == 8
    assert frozenset(changed.stdout.splitlines()) == PHASE_ONE_IMPLEMENTATION_PATHS
    assert OPERATOR_RESULTS_RELATIVE_PATH not in PHASE_ONE_IMPLEMENTATION_PATHS
    assert authrunner_resolved.stdout.strip() == AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_CHECKPOINT
    assert len(AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_PATHS) == 16
    assert len(AUTHRUNNER_UNCHANGED_IMPLEMENTATION_PATHS) == 13
    assert (
        frozenset(authrunner_changed.stdout.splitlines())
        == AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_PATHS
    )
    assert (
        worktree_independence_resolved.stdout.strip() == AUTONOMY_WORKTREE_INDEPENDENCE_CHECKPOINT
    )
    assert (
        frozenset(worktree_independence_changed.stdout.splitlines())
        == AUTONOMY_WORKTREE_INDEPENDENCE_PATHS
    )
    assert token_envelope_resolved.stdout.strip() == AUTHRUNNER_TOKEN_ENVELOPE_CHECKPOINT
    assert frozenset(token_envelope_changed.stdout.splitlines()) == AUTHRUNNER_TOKEN_ENVELOPE_PATHS
    assert len(AUTHRUNNER_TOKEN_ENVELOPE_PATHS) == 29
    assert identity_diagnostic_resolved.stdout.strip() == AUTHRUNNER_IDENTITY_DIAGNOSTIC_CHECKPOINT
    assert (
        frozenset(identity_diagnostic_changed.stdout.splitlines())
        == AUTHRUNNER_IDENTITY_DIAGNOSTIC_PATHS
    )
    assert len(AUTHRUNNER_IDENTITY_DIAGNOSTIC_PATHS) == 4
    assert (
        scope_cutoff_hotfix_resolved.stdout.strip() == HISTORICAL_AUTHRUNNER_SCOPE_CUTOFF_CHECKPOINT
    )
    assert (
        scope_cutoff_hotfix_parent.stdout.strip()
        == HISTORICAL_AUTHRUNNER_RECEIPT_SCAFFOLD_CHECKPOINT
    )
    assert (
        frozenset(scope_cutoff_hotfix_changed.stdout.splitlines())
        == AUTHRUNNER_SCOPE_CUTOFF_HOTFIX_PATHS
    )
    assert len(AUTHRUNNER_SCOPE_CUTOFF_HOTFIX_PATHS) == 7
    assert (
        receipt_composite_resolved.stdout.strip()
        == HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT
    )
    assert receipt_composite_parent.stdout.strip() == AUTHRUNNER_RECEIPT_COMPOSITE_PARENT_CHECKPOINT
    assert (
        frozenset(receipt_composite_changed.stdout.splitlines())
        == AUTHRUNNER_RECEIPT_COMPOSITE_PATHS
    )
    assert len(AUTHRUNNER_RECEIPT_COMPOSITE_PATHS) == 14
    assert OPERATOR_RESULTS_RELATIVE_PATH not in AUTHRUNNER_RECEIPT_COMPOSITE_PATHS
    assert not (AUTHRUNNER_RECEIPT_COMPOSITE_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS)
    assert (
        receipt_state_seal_hotfix_resolved.stdout.strip()
        == HISTORICAL_AUTHRUNNER_RECEIPT_STATE_SEAL_CHECKPOINT
    )
    assert (
        receipt_state_seal_hotfix_parent.stdout.strip()
        == HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT
    )
    assert (
        frozenset(receipt_state_seal_hotfix_changed.stdout.splitlines())
        == AUTHRUNNER_RECEIPT_STATE_SEAL_HOTFIX_PATHS
    )
    assert len(AUTHRUNNER_RECEIPT_STATE_SEAL_HOTFIX_PATHS) == 4
    assert OPERATOR_RESULTS_RELATIVE_PATH not in AUTHRUNNER_RECEIPT_STATE_SEAL_HOTFIX_PATHS
    assert not (
        AUTHRUNNER_RECEIPT_STATE_SEAL_HOTFIX_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS
    )
    assert (
        structured_output_diagnostic_resolved.stdout.strip()
        == HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT
    )
    assert (
        structured_output_diagnostic_parent.stdout.strip()
        == HISTORICAL_AUTHRUNNER_RECEIPT_STATE_SEAL_CHECKPOINT
    )
    assert (
        frozenset(structured_output_diagnostic_changed.stdout.splitlines())
        == AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_PATHS
    )
    assert len(AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_PATHS) == 5
    assert OPERATOR_RESULTS_RELATIVE_PATH not in AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_PATHS
    assert not (
        AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS
    )
    assert (
        required_provider_parameters_resolved.stdout.strip()
        == HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT
    )
    assert (
        required_provider_parameters_parent.stdout.strip()
        == HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT
    )
    assert (
        frozenset(required_provider_parameters_changed.stdout.splitlines())
        == AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_PATHS
    )
    assert len(AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_PATHS) == 5
    assert OPERATOR_RESULTS_RELATIVE_PATH not in AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_PATHS
    assert not (
        AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS
    )
    assert canonical_replay_resolved.stdout.strip() == HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT
    assert (
        canonical_replay_parent.stdout.strip()
        == HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT
    )
    assert frozenset(canonical_replay_changed.stdout.splitlines()) == (
        AUTHRUNNER_CANONICAL_REPLAY_PATHS
    )
    assert len(AUTHRUNNER_CANONICAL_REPLAY_PATHS) == 3
    assert OPERATOR_RESULTS_RELATIVE_PATH not in AUTHRUNNER_CANONICAL_REPLAY_PATHS
    assert not (AUTHRUNNER_CANONICAL_REPLAY_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS)
    assert hashlib.sha256(canonical_replay_smoke_bytes).hexdigest() == (
        HISTORICAL_AUTHRUNNER_REPLAY_SMOKE_RAW_SHA256
    )
    assert planconstraints_repair_resolved.stdout.strip() == PLANCONSTRAINTS_REPAIR_CHECKPOINT
    assert planconstraints_repair_parent.stdout.strip() == PLANCONSTRAINTS_REPAIR_PARENT_CHECKPOINT
    assert (
        frozenset(planconstraints_repair_changed.stdout.splitlines())
        == PLANCONSTRAINTS_SOURCE_PATHS
    )
    assert len(PLANCONSTRAINTS_SOURCE_PATHS) == 5
    assert OPERATOR_RESULTS_RELATIVE_PATH not in PLANCONSTRAINTS_SOURCE_PATHS
    assert not (PLANCONSTRAINTS_SOURCE_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS)
    assert truncation_specialist_resolved.stdout.strip() == CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT
    assert (
        truncation_specialist_parent.stdout.strip()
        == CURRENT_TRUNCATION_SPECIALIST_PARENT_CHECKPOINT
    )
    assert (
        frozenset(truncation_specialist_changed.stdout.splitlines())
        == TRUNCATION_SPECIALIST_SOURCE_PATHS
    )
    assert len(TRUNCATION_SPECIALIST_SOURCE_PATHS) == 16
    assert OPERATOR_RESULTS_RELATIVE_PATH not in TRUNCATION_SPECIALIST_SOURCE_PATHS
    assert not (TRUNCATION_SPECIALIST_SOURCE_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS)
    assert (
        truncation_recursive_resolved.stdout.strip() == HISTORICAL_TRUNCATION_RECURSIVE_CHECKPOINT
    )
    assert (
        truncation_recursive_parent.stdout.strip()
        == HISTORICAL_TRUNCATION_RECURSIVE_PARENT_CHECKPOINT
    )
    assert (
        frozenset(truncation_recursive_changed.stdout.splitlines())
        == HISTORICAL_TRUNCATION_RECURSIVE_SOURCE_PATHS
    )
    assert len(HISTORICAL_TRUNCATION_RECURSIVE_SOURCE_PATHS) == 8
    assert OPERATOR_RESULTS_RELATIVE_PATH not in HISTORICAL_TRUNCATION_RECURSIVE_SOURCE_PATHS
    assert not (
        HISTORICAL_TRUNCATION_RECURSIVE_SOURCE_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS
    )
    assert truncation_promotion_resolved.stdout.strip() == CURRENT_TRUNCATION_PROMOTION_CHECKPOINT
    assert (
        truncation_promotion_parent.stdout.strip() == CURRENT_TRUNCATION_PROMOTION_PARENT_CHECKPOINT
    )
    assert (
        frozenset(truncation_promotion_changed.stdout.splitlines())
        == TRUNCATION_PROMOTION_SOURCE_PATHS
    )
    assert len(TRUNCATION_PROMOTION_SOURCE_PATHS) == 20
    assert OPERATOR_RESULTS_RELATIVE_PATH not in TRUNCATION_PROMOTION_SOURCE_PATHS
    assert not (TRUNCATION_PROMOTION_SOURCE_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS)
    assert coverage_resolved.stdout.strip() == CURRENT_COVERAGE_CHECKPOINT
    assert coverage_parent.stdout.strip() == CURRENT_COVERAGE_PARENT_CHECKPOINT
    assert frozenset(coverage_changed.stdout.splitlines()) == CURRENT_COVERAGE_SOURCE_PATHS
    assert len(CURRENT_COVERAGE_SOURCE_PATHS) == 33
    assert OPERATOR_RESULTS_RELATIVE_PATH not in CURRENT_COVERAGE_SOURCE_PATHS
    assert not (CURRENT_COVERAGE_SOURCE_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS)
    assert retry_resolved.stdout.strip() == CURRENT_RETRY_CHECKPOINT
    assert retry_parent.stdout.strip() == CURRENT_RETRY_PARENT_CHECKPOINT
    assert frozenset(retry_changed.stdout.splitlines()) == V3_RETRY_SOURCE_PATHS
    assert len(V3_RETRY_SOURCE_PATHS) == 17
    assert OPERATOR_RESULTS_RELATIVE_PATH not in V3_RETRY_SOURCE_PATHS
    assert not (V3_RETRY_SOURCE_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS)
    assert hashlib.sha256(retry_inventory_bytes).hexdigest() == (
        CURRENT_RETRY_AUTONOMY_INVENTORY_RAW_SHA256
    )
    assert hashlib.sha256(retry_inventory_schema_bytes).hexdigest() == (
        CURRENT_RETRY_AUTONOMY_INVENTORY_SCHEMA_RAW_SHA256
    )
    assert retry_inventory["inventory_sha256"] == CURRENT_RETRY_AUTONOMY_INVENTORY_SHA256
    assert retry_inventory["source_discovery_semantics_sha256"] == (
        CURRENT_RETRY_AUTONOMY_DISCOVERY_SEMANTICS_SHA256
    )
    assert retry_inventory["source_universe_sha256"] == (
        CURRENT_RETRY_AUTONOMY_SOURCE_UNIVERSE_SHA256
    )
    assert (
        operator_results_checkpoint_resolved.stdout.strip()
        == HISTORICAL_50D_OPERATOR_RESULTS_CHECKPOINT
    )
    assert operator_results_checkpoint_parent.stdout.strip() == CURRENT_RETRY_CHECKPOINT
    assert (
        frozenset(operator_results_checkpoint_changed.stdout.splitlines())
        == HISTORICAL_50D_OPERATOR_RESULTS_CHECKPOINT_PATHS
    )
    assert operator_results_remote_ancestry.returncode == 0


def test_combined_queue_unfinished_count_is_derived() -> None:
    canonical = _parse_all_queue_ticket_statuses(QUEUE_PATH.read_text(encoding="utf-8"))
    codex = _parse_all_queue_ticket_statuses(CODEX_QUEUE_PATH.read_text(encoding="utf-8"))
    for ticket in canonical.keys() & codex.keys():
        assert canonical[ticket] == codex[ticket], f"queue status disagreement for {ticket}"
    combined = codex | canonical
    unfinished = sum(status != "COMPLETE" for status in combined.values())

    assert combined["V3-TAXONOMY-001"] == "COMPLETE"
    assert combined["V3-RETRIEVAL-001"] == "COMPLETE"
    assert combined["V3-PRICELEXEME-001"] == "IN_PROGRESS"
    assert combined["V3-PRICEFORM-001"] == "QUEUED"
    assert unfinished == 40
    assert (
        f"REMAINING_ACTIONABLE_TICKETS: The combined queues contain {unfinished} unfinished tickets"
    ) in CODEX_WORKLOG_PATH.read_text(encoding="utf-8")


def test_current_worklog_headers_bind_pricelexeme_status_and_retrieval_inventory() -> None:
    exact_status = (
        "V3_PRICELEXEME_001_IN_PROGRESS_SELECTED_PROVIDER_FREE_NONAUTHORIZING_"
        "IMPLEMENTATION_NOT_STARTED_CODEX_ZERO_EXTERNAL_COMMANDS"
    )
    exact_counts = (
        "3895 sources / 3898 occurrences / 3846 gate sources / 49 non-gating controls / "
        "13 source kinds / 35 logical gates / 29 unsatisfied / 15 current-manual"
    )
    inventory_components = (
        f"Raw `{CURRENT_RETRIEVAL_AUTONOMY_INVENTORY_RAW_SHA256}`",
        f"self `{CURRENT_RETRIEVAL_AUTONOMY_INVENTORY_SHA256}`",
        f"discovery `{CURRENT_RETRIEVAL_AUTONOMY_DISCOVERY_SEMANTICS_SHA256}`",
        f"universe `{CURRENT_RETRIEVAL_AUTONOMY_SOURCE_UNIVERSE_SHA256}`",
        f"schema raw `{CURRENT_RETRIEVAL_AUTONOMY_INVENTORY_SCHEMA_RAW_SHA256}`",
    )

    for worklog_path in (CODEX_WORKLOG_PATH, ROOT / "docs/remediation/v3/worklog.md"):
        current_header = worklog_path.read_text(encoding="utf-8").split("\n## ", maxsplit=1)[0]
        assert f"AUTORUN_STATUS: {exact_status}" in current_header
        assert f"CURRENT_LOCAL_SLICE_STATUS: {exact_status}" in current_header
        assert "CURRENT_TICKET: V3-PRICELEXEME-001" in current_header
        assert "CURRENT_TICKET_IMPLEMENTATION_STARTED: false" in current_header
        assert (
            "CURRENT_AUTONOMY_INVENTORY: "
            "CURRENT_RECONCILED_V3_PRICELEXEME_001_SELECTION_AFTER_V3_RETRIEVAL_001_COMPLETE"
            in current_header
        )
        for component in inventory_components:
            assert component in current_header
        assert exact_counts in current_header
        assert "PRE_TRANSITION_GOVERNED_GENERATION_LAST_VERIFIED" not in current_header
        assert "8156 passed, 22 skipped, 12 warnings in 9963.54s (2:46:03)" in current_header


def test_retry_ticket_is_mirrored_complete_and_has_an_exact_source_manifest() -> None:
    for document in (
        QUEUE_PATH.read_text(encoding="utf-8"),
        CODEX_QUEUE_PATH.read_text(encoding="utf-8"),
    ):
        match = re.search(
            r"^#{2,3} V3-RETRY-001\b.*?(?=^#{2,3} V3-[A-Z0-9-]+\b|\Z)",
            document,
            flags=re.MULTILINE | re.DOTALL,
        )
        assert match is not None
        section = " ".join(match.group().split())
        assert "**Status:** `COMPLETE`" in section
        assert "same-route" in section
        assert "default" in section and "zero" in section
        assert "first-attempt" in section
        assert "32-attempt" in section
        assert "private" in section.lower() and "19" in section and "21" in section
        assert "authority" in section.lower()

    assert len(V3_RETRY_SOURCE_PATHS) == 17
    assert all((ROOT / path).is_file() for path in V3_RETRY_SOURCE_PATHS)
    assert OPERATOR_RESULTS_RELATIVE_PATH not in V3_RETRY_SOURCE_PATHS
    assert not (V3_RETRY_SOURCE_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS)


def test_runtime_admission_ticket_is_mirrored_complete_and_nonauthorizing() -> None:
    for document in (
        QUEUE_PATH.read_text(encoding="utf-8"),
        CODEX_QUEUE_PATH.read_text(encoding="utf-8"),
    ):
        match = re.search(
            r"^#{2,3} V3-RUNTIMEADMIT-001\b.*?(?=^#{2,3} V3-[A-Z0-9-]+\b|\Z)",
            document,
            flags=re.MULTILINE | re.DOTALL,
        )
        assert match is not None
        section = " ".join(match.group().split())
        assert "**Status:** `COMPLETE`" in section
        assert "EMPIRICAL_SCHEMA_CONFORMANCE" in section
        assert "TOKEN_DETAIL_REPORTING_CONVENTION" in section
        assert "exact model" in section.replace("*", "").lower()
        assert "route" in section.lower()
        assert "self-attestation" in section
        assert "nonauthorizing" in section.lower()
        assert "private" in section.lower()
        assert "completed_real_audits" in section
        assert "successor" in section.lower()
        assert "no external action" in section.lower()

    schema_bytes = ROUTE_RUNTIME_EVIDENCE_SCHEMA_PATH.read_bytes()
    schema = json.loads(schema_bytes)
    assert hashlib.sha256(schema_bytes).hexdigest() == ROUTE_RUNTIME_EVIDENCE_SCHEMA_RAW_SHA256
    assert schema["$id"] == (
        "https://mmaudit.local/schemas/route_runtime_evidence_artifact.schema.json"
    )
    assert schema["title"] == "mmaudit nonauthorizing exact route runtime evidence"
    observations = schema["properties"]["observations"]
    assert observations["minItems"] == observations["maxItems"] == 3
    for authority_field in (
        "full_corpus_execution_completed",
        "benchmark_authorized",
        "model_qualification_authorized",
        "runner_authority_authorized",
        "provider_call_authorized",
        "campaign_admission_authorized",
        "release_authorized",
    ):
        assert schema["properties"][authority_field]["const"] is False


def test_consensus_ticket_is_mirrored_complete_with_successor_unselected() -> None:
    for document in (
        QUEUE_PATH.read_text(encoding="utf-8"),
        CODEX_QUEUE_PATH.read_text(encoding="utf-8"),
    ):
        match = re.search(
            r"^#{2,3} V3-CONSENSUS-001\b.*?(?=^#{2,3} V3-[A-Z0-9-]+\b|\Z)",
            document,
            flags=re.MULTILINE | re.DOTALL,
        )
        assert match is not None
        section = " ".join(match.group().split())
        statuses = _parse_all_queue_ticket_statuses(document)

        assert "**Status:** `COMPLETE`" in section
        assert "exactly one verifier and two lineage-distinct falsifiers" in section
        assert "globally unique provider generations" in section
        assert "all dissent" in section
        assert "closed deterministic quorum" in section
        assert "single reviewer cannot suppress" in section
        assert "model agreement alone never confirms" in section
        assert "detached replay" in section
        assert "evidence-cap and severity policy" in section
        assert "`614` affected unit tests" in section
        assert "`7` selected synthetic local integrations" in section
        assert "no HIGH/blocking defect" in section
        assert "self-sealed rather than externally authenticated" in section
        assert "scanner evidence is deliberately nonconfirming" in section
        assert "`V3-MULTI-AUDIT-001` remains queued and unselected" in section
        assert "`V3-SINGLE-AUDIT-001` is unresolved" in section
        assert "changing retry/configuration behavior" in section
        assert statuses["V3-CONSENSUS-001"] == "COMPLETE"
    combined_statuses = _parse_all_queue_ticket_statuses(
        CODEX_QUEUE_PATH.read_text(encoding="utf-8")
    ) | _parse_all_queue_ticket_statuses(QUEUE_PATH.read_text(encoding="utf-8"))
    assert combined_statuses["V3-SINGLE-AUDIT-001"] == "QUEUED"
    assert combined_statuses["V3-MULTI-AUDIT-001"] == "QUEUED"


def test_truncation_promotion_custody_remains_partial_after_planconstraints_repair() -> None:
    for document in (
        QUEUE_PATH.read_text(encoding="utf-8"),
        CODEX_QUEUE_PATH.read_text(encoding="utf-8"),
    ):
        match = re.search(
            r"^#{2,3} V3-TRUNCATION-001\b.*?(?=^#{2,3} V3-[A-Z0-9-]+\b|\Z)",
            document,
            flags=re.MULTILINE | re.DOTALL,
        )
        assert match is not None
        section = " ".join(match.group().split())
        assert "**Status:** `PARTIAL`" in section
        assert CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT in section
        assert HISTORICAL_TRUNCATION_RECURSIVE_CHECKPOINT in section
        assert CURRENT_TRUNCATION_PROMOTION_CHECKPOINT in section
        assert "specialist" in section and "v1.2" in section
        assert "one generic zero-retained truncated child" in section
        assert "v1.1 `COVERAGE_CLOSED`" in section
        assert "v1.2 `RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING`" in section
        assert "max-cap refusal" in section
        assert "distinct PID-local opaque verifier" in section
        assert "journal-owned promotion capability for the complete five-request tree" in section
        assert "One v1.1 promotion and v1.1 recovered output" in section
        assert "four public v1.2 recovery requests" in section
        assert "exactly one `SUPERSEDED_TRUNCATED_BRIDGE`" in section
        assert "three `SUCCESSFUL_LEAF` dispositions" in section
        assert "no artifact, review, coverage, floor, specialist, or completion credit" in section
        assert "every direct or recursive promoted composite" in section
        assert "exact parent-provisional and child/leaf ordinary-artifact surface partitions" in (
            section
        )
        assert "zero-retained parent needs no invented composite reference" in section
        assert "unrelated artifacts cannot substitute for either partition" in section
        assert "Local synthetic usage was re-attested only to exercise the REAL-only" in section
        assert "it is not genuine provider execution" in section
        assert "MOCK recursive recovery remains unpromoted and noncrediting" in section
        assert "byte-stable zero transport" in section
        assert "Positive nonempty full-pipeline promotion backed by genuine provider" in section
        assert "Deeper recursion, retained surfaces on the recursive bridge" in section
        assert "specialist-role recursion remain unimplemented" in section
        assert "terminal maximum-assurance result" in section
        assert "Do not infer a provider command or run index" in section
        assert "Resume only the bounded provider-free specialist-role recovery gap" not in section
        assert "Pause this ticket while" not in section


def test_coverage_portfolio_checkpoint_meets_provider_free_acceptance() -> None:
    for document in (
        QUEUE_PATH.read_text(encoding="utf-8"),
        CODEX_QUEUE_PATH.read_text(encoding="utf-8"),
    ):
        match = re.search(
            r"^#{2,3} V3-COVERAGE-001\b.*?(?=^#{2,3} V3-[A-Z0-9-]+\b|\Z)",
            document,
            flags=re.MULTILINE | re.DOTALL,
        )
        assert match is not None
        section = " ".join(match.group().split())
        assert "**Status:** `COMPLETE`" in section
        assert CURRENT_COVERAGE_CHECKPOINT in section
        assert CURRENT_COVERAGE_PARENT_CHECKPOINT in section
        assert "pre-orientation portfolio" in section
        assert "orientation, compact, `source_audit`, and `whole_protocol`" in section
        assert "atomic" in section and "request/token/USD" in section
        assert "22 investigators plus `invariant_review` and `report_quality`" in section
        assert "clean no-candidate" in section
        assert "`710.96s`" in section
        assert "634323f697cb0c8d4ed38dd04452a857c9374f5e026bc1c441122763a142198f" in (section)
        assert "v1.3" in section and "comparison-only" in section
        assert "zero-transport on resume" in section
        assert "synthetic/mock" in section.lower()
        assert "not real/provider" in section.lower()
        assert "`V3-TRUNCATION-001` remains `PARTIAL`" in section
        assert "`V3-CALIBRATE-001` remains `BLOCKED_TECHNICAL`" in section
        assert "not reopened by this closure" in section
        assert "Stop after recording this ticket `COMPLETE`" in section
        assert "do not select AUTHSEAL" in section


def test_retry_closure_preserves_the_exact_coverage_runtime_portfolio() -> None:
    parent_runtime = json.loads(
        subprocess.run(
            [
                "git",
                "show",
                (f"{CURRENT_RETRY_PARENT_CHECKPOINT}:docs/remediation/v3/runtime_status.json"),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    current_runtime = json.loads(RUNTIME_STATUS_PATH.read_text(encoding="utf-8"))

    assert (
        current_runtime["coverage_provider_free_portfolio"]
        == parent_runtime["coverage_provider_free_portfolio"]
    )


def test_actor_model_closure_is_preserved_with_endpoint_candidate_history() -> None:
    traceability_text = TRACEABILITY_PATH.read_text(encoding="utf-8")
    worklogs = (
        CODEX_WORKLOG_PATH.read_text(encoding="utf-8"),
        (ROOT / "docs/remediation/v3/worklog.md").read_text(encoding="utf-8"),
    )
    for raw_worklog in worklogs:
        worklog = " ".join(raw_worklog.split())
        current_header = " ".join(raw_worklog.split("\n## ", maxsplit=1)[0].split())
        newest_entry = " ".join(
            raw_worklog.split("\n## ", maxsplit=1)[1].split("\n## ", maxsplit=1)[0].split()
        )
        retrieval_terminal_entry = " ".join(
            raw_worklog.split("## 2026-09-02T12:10:08Z", maxsplit=1)[1]
            .split("\n## ", maxsplit=1)[0]
            .split()
        )
        pricelexeme_selection_entry = " ".join(
            raw_worklog.split("## 2026-09-02T08:52:48Z", maxsplit=1)[1]
            .split("\n## ", maxsplit=1)[0]
            .split()
        )
        actor_model_completion_entry = " ".join(
            raw_worklog.split("## 2026-08-31T00:16:29Z", maxsplit=1)[1]
            .split("\n## ", maxsplit=1)[0]
            .split()
        )
        operator_decision_entry = " ".join(
            raw_worklog.split("## 2026-08-30T19:47:22Z", maxsplit=1)[1]
            .split("\n## ", maxsplit=1)[0]
            .split()
        )
        endpoint_completion_entry = " ".join(
            raw_worklog.split("## 2026-08-30T19:29:47Z", maxsplit=1)[1]
            .split("\n## ", maxsplit=1)[0]
            .split()
        )
        plan_successor_entry = " ".join(
            raw_worklog.split("## 2026-08-30T15:31:29Z", maxsplit=1)[1]
            .split("\n## ", maxsplit=1)[0]
            .split()
        )
        modelrefresh_entry = " ".join(
            raw_worklog.split("## 2026-08-27T21:47:03Z", maxsplit=1)[1]
            .split("\n## ", maxsplit=1)[0]
            .split()
        )
        learning_entry = " ".join(
            raw_worklog.split("## 2026-08-27T18:36:04Z", maxsplit=1)[1]
            .split("\n## ", maxsplit=1)[0]
            .split()
        )
        historical_retry_reconciliation = " ".join(
            raw_worklog.split("## 2026-08-27T07:21:08Z", maxsplit=1)[1]
            .split("\n## ", maxsplit=1)[0]
            .split()
        )
        schema_retry_entry = " ".join(
            raw_worklog.split("## 2026-08-28T08:10:11Z", maxsplit=1)[1]
            .split("\n## ", maxsplit=1)[0]
            .split()
        )
        candidate_route_entry = " ".join(
            raw_worklog.split("## 2026-08-30T17:49:22Z", maxsplit=1)[1]
            .split("\n## ", maxsplit=1)[0]
            .split()
        )
        reopened_endpoint_entry = " ".join(
            raw_worklog.split("## 2026-08-30T19:09:10Z", maxsplit=1)[1]
            .split("\n## ", maxsplit=1)[0]
            .split()
        )
        historical_endpoint_v1_0_entry = " ".join(
            raw_worklog.split("## 2026-08-30T18:47:27Z", maxsplit=1)[1]
            .split("\n## ", maxsplit=1)[0]
            .split()
        )
        assert "AUTORUN_STATUS:" in current_header
        assert "PROVIDER_FREE" in current_header
        assert "NONAUTHORIZING" in current_header
        assert "CODEX_ZERO_EXTERNAL_COMMANDS" in current_header
        assert "CURRENT_LOCAL_SLICE_STATUS:" in current_header
        assert "CURRENT_TICKET:" in current_header
        assert "LAST_COMPLETED_TICKET:" in current_header
        assert "LAST_PARTIAL_TICKET: V3-CANDROUTE-001" in current_header
        assert "unfinished tickets" in current_header
        assert "OPERATOR_RESULTS_CURRENT_WORKTREE_STATUS: RECONCILED_EXACT_AF7A24E" in (
            current_header
        )
        for status_component in (
            "OPERATOR_DECISION_LOSSLESS_PRICE_LEXEME_CUSTODY",
            "PRICEFORM_REFUSAL_UPHELD",
            "REASONING_EFFORT_REQUIRED",
            "PRICELEXEME_QUEUED",
            "PRIOR_LIVE_V1_0_METADATA_SURVEY",
            "12_MODELS",
            "112_ENDPOINTS",
            "ZERO_ENDPOINT_REASONING_EFFORT_INVENTORIES",
            "V1_0_MODEL_AND_EFFECTIVE_REASONING_OMISSION_CORRECTED_LOCALLY_IN_V1_1",
            "ZERO_ADMISSIBLE_CANDIDATES",
            "ACTIVE_PLAN_UNCHANGED",
            "LEDGER_UNCHANGED",
            "57_ENTRIES",
            "068118684_SPEND",
            "ZERO_COMPLETED_REAL_AUDITS",
            "NONAUTHORIZING",
            "NOT_INDEPENDENTLY_AUTHENTICATED_BY_CODEX",
        ):
            assert status_component in current_header
        assert CURRENT_OPERATOR_RESULTS_SHA256 in current_header
        assert "162656 bytes / 2902 lines" in current_header
        assert "V3-LEARNING-001" in learning_entry
        assert "Phase 1" in learning_entry and "complete" in learning_entry.lower()
        assert "PARTIAL" in learning_entry
        assert "provider-free" in learning_entry
        assert "tenant" in learning_entry.lower()
        assert "manifest" in learning_entry.lower()
        assert "later-established" in learning_entry.lower()
        assert "latest" in learning_entry.lower()
        assert "28" in learning_entry and "62" in learning_entry and "132" in learning_entry
        assert "no blocker/HIGH" in learning_entry
        assert "no provider/network call" in learning_entry.lower()
        assert "authority" in learning_entry.lower()
        assert "private" in learning_entry.lower()
        assert "completed_real_audits" in worklog
        assert "V3-ACTORMODEL-001" in worklog
        assert "V3-TAXONOMY-001" in worklog
        assert "REMAINING_ACTIONABLE_TICKETS:" in current_header
        assert "V3-CANDROUTE-001" in current_header and "PARTIAL" in current_header
        assert "V3-ACTORMODEL-001" in actor_model_completion_entry
        assert "complete" in actor_model_completion_entry.lower()
        assert "operator-authored" in actor_model_completion_entry.lower()
        assert "actor-blind" in actor_model_completion_entry.lower()
        assert (
            "judge" in actor_model_completion_entry.lower()
            and "context" in actor_model_completion_entry.lower()
        )
        assert (
            "baseline" in actor_model_completion_entry.lower()
            and "evaluation" in actor_model_completion_entry.lower()
        )
        assert "provider-free" in actor_model_completion_entry.lower()
        assert "authority" in actor_model_completion_entry.lower()
        assert "operator decision reconciliation" in operator_decision_entry.lower()
        assert "V3-PRICEFORM-001 decision" in operator_decision_entry
        assert "Rejection stands" in operator_decision_entry
        assert "no admissible candidate route exists" in operator_decision_entry
        assert "REASONING_EFFORT_SUPPORT" in operator_decision_entry
        assert "genuinely required of the candidate" in operator_decision_entry
        assert "not relaxed" in operator_decision_entry
        assert "V3-ENDPOINTLIST-001" in endpoint_completion_entry
        assert "schema-v1.1 corrective completion" in endpoint_completion_entry.lower()
        assert "model" in endpoint_completion_entry.lower()
        assert "effective" in endpoint_completion_entry.lower()
        assert "v1.1 has not been exercised live" in endpoint_completion_entry.lower()
        assert "codex did not issue" in endpoint_completion_entry.lower()
        assert "reopened from live diagnostic evidence" in reopened_endpoint_entry.lower()
        assert "`12` models" in reopened_endpoint_entry.lower()
        assert "`112` endpoints" in reopened_endpoint_entry.lower()
        assert "provider-free completion" in historical_endpoint_v1_0_entry.lower()
        assert "list-endpoints" in historical_endpoint_v1_0_entry
        assert "no provider/network enumeration" in historical_endpoint_v1_0_entry.lower()
        assert "V3-CANDROUTE-001" in candidate_route_entry
        assert "provider-free partial closure" in candidate_route_entry.lower()
        assert "schema v1.6" in candidate_route_entry.lower()
        assert "constrained discovery" in candidate_route_entry.lower()
        assert "V3-PLANSUCCESSOR-001" in plan_successor_entry
        assert "complete" in plan_successor_entry.lower()
        assert "predecessor" in plan_successor_entry.lower()
        assert "provider-free" in plan_successor_entry.lower()
        assert "External effects:" in learning_entry
        assert "shares one pure resolver" in endpoint_completion_entry.lower()
        assert "package-pinned negative registry" in modelrefresh_entry.lower()
        assert "tombstone" in modelrefresh_entry.lower()
        assert "max_model_retries" in schema_retry_entry
        assert "schema_validation_failed" in schema_retry_entry.lower()
        assert "no codex provider or operator action" in current_header.lower()
        assert "is current" in current_header
        assert "operator-reports" in worklog.lower()
        assert "index-21" in worklog.lower() or "index21" in worklog.lower()
        assert "r21" in worklog
        assert "EMPIRICAL_SCHEMA_CONFORMANCE" in worklog
        assert "TOKEN_DETAIL_REPORTING_CONVENTION" in worklog
        assert "RUNTIME_EVIDENCE_INVALID" in worklog
        assert "Codex" in worklog and "private" in worklog.lower()
        assert "full admission for one launch" in worklog.lower()
        normalized_newest_entry = newest_entry.lower()
        normalized_retrieval_terminal_entry = retrieval_terminal_entry.lower()
        normalized_selection_entry = pricelexeme_selection_entry.lower()
        assert "selection does not admit or select a candidate route" in normalized_selection_entry
        assert "grant provider or runner authority" in normalized_selection_entry
        assert "or authority action occurred" in normalized_selection_entry
        assert "terminal validation and inventory reconciled" in normalized_retrieval_terminal_entry
        assert "8156 passed, 22 skipped, 12 warnings" in normalized_retrieval_terminal_entry
        assert "sole `in_progress` ticket" in normalized_retrieval_terminal_entry
        assert "implementation_started=false" in normalized_retrieval_terminal_entry
        assert "changes no pricing decoder, retry behavior, runtime configuration" in (
            normalized_retrieval_terminal_entry
        )
        assert "performs no provider" in normalized_retrieval_terminal_entry
        assert "or authority action" in normalized_retrieval_terminal_entry
        assert "documentation reconciliation remote-resolved" in normalized_newest_entry
        assert "update by push" in normalized_newest_entry
        assert "no manual push was attempted" in normalized_newest_entry
        assert "makes no claim about its own eventual remote state" in normalized_newest_entry
        assert "38721e860435ebbfd559d8b0b4f3c98870f191ed" in normalized_newest_entry
        assert "c323a5299c22ced8048f0ed1ff3df7e7bf1f0c8d" in normalized_newest_entry
        assert "137,294 bytes / 2,462" in historical_retry_reconciliation
        assert (
            "latest entry" in historical_retry_reconciliation
            and "2026-08-27T06:37Z" in historical_retry_reconciliation
        )
        assert "max_schema_validation_retries" in worklog
        assert "first-attempt-only" in worklog
        assert "indices 19 and 21" in worklog
        assert "V3-RUNTIMEADMIT-001" in historical_retry_reconciliation
        assert "queued but was not selected" in historical_retry_reconciliation
        assert "failed two regressions and was reverted" in historical_retry_reconciliation
        assert CURRENT_COVERAGE_CHECKPOINT in worklog
        assert CURRENT_COVERAGE_PARENT_CHECKPOINT in worklog
        assert (
            "orientation" in worklog and "source_audit" in worklog and "whole_protocol" in worklog
        )
        assert "clean no-candidate synthetic" in worklog.lower()
        assert "22 investigator roles plus `invariant_review` and `report_quality`" in worklog
        assert "journal publication" in worklog.lower()
        assert "exact legal state transitions" in worklog
        assert "v1.3" in worklog
        assert "`FAILED` / `RELEASED_PRE_SEND_TAIL`" in worklog
        assert "comparison-only" in worklog
        assert "zero-transport resume" in worklog
        assert "4bfac51801ff5999435081ac3fda4b2fa6fe5826cc9f89afd380ee53f4e2eb48" in (worklog)
        assert "6f9be06561bf1d98cbf6c5102560e20b4f8a353cd566681b44156ac73cc6040a" in (worklog)
        assert "d3f7b11db48b6cccf50d058f9d46ed69efed7ea02bc3d10865ce011e553c2f7b" in (worklog)
        assert "8951ede35cacfadafdb893a89548cabaf8cb05c592b8884e42b90407a8d16b42" in (worklog)
        assert "3,685 sources / 3,688 occurrences / 3,642 gate sources" in worklog
        assert "43 non-gating controls / 13 source kinds / 35 logical gates" in worklog
        assert "29 unsatisfied / 15 current-manual" in worklog
        assert "1,945" in worklog and "51" in worklog
        assert "710.96s" in worklog
        assert "634323f697cb0c8d4ed38dd04452a857c9374f5e026bc1c441122763a142198f" in (worklog)
        assert "Counts overlap and are not additive" in worklog
        assert "105.34s" in worklog
        assert "no blocker/HIGH" in worklog
        assert CURRENT_TRUNCATION_PROMOTION_CHECKPOINT in worklog
        assert "`V3-TRUNCATION-001` remains `PARTIAL`" in worklog
        assert "All execution was local synthetic or MOCK" in worklog or (
            "all execution was local synthetic or MOCK" in worklog
        )
        assert "No provider, network, credential, private-ledger" in worklog
        assert "qualification input is unavailable" in worklog
        assert "qualification.py:5316" in worklog
        assert "29-entry ledger unchanged at `0.43458261` USD" in worklog
        assert "AUTHRUNNER smoke path" in worklog
        assert "has succeeded twice" in worklog
        assert "live metadata probes with zero new spend" in worklog
        assert "absence of 24-case campaign completion transport" in worklog
        assert "one-case, nonauthorizing smoke evidence" in worklog
        assert "`mmaudit models benchmark`" in worklog
        assert "predecessor P1/C1" in worklog
        assert "1df14052e97a8ceb2cf3ec9fd25637f5f2f3a821818a54382a7c1f241059da8c" in (worklog)
        assert "`benchmarks/model_corpus/verdict_policy.json`" in worklog
        assert "failed `path.stat()` proves only an absent supplied" in worklog
        assert "artifact version and content at that immediate file stage" in worklog
        assert "remain `UNDETERMINED`" in worklog
        assert "`config/openrouter-qualification.toml`" in worklog
        assert "`_require_qualification_release_pins`" in worklog
        assert "could likely satisfy the current C1 pin" in worklog
        assert "no repository CLI materializer exists" in worklog
        assert "derived P2 would be rejected by current C1" in worklog
        assert "operator inference, not established by the failure" in worklog
        assert "A/P2 publication, source review and C2 pinning" in worklog
        assert "implemented legacy, optional two-campaign bridge" in worklog
        assert "not sufficient for frozen current-objective completion" in worklog
        assert "precommitted constructed/public frozen truth" in worklog
        assert "cross-lineage automated adjudication" in worklog
        assert "exact REAL calibration custody" in worklog
        assert "at least eight complete REAL candidates" in worklog
        assert "at least six reviewed root lineages" in worklog
        assert "no honest runnable operator command exists" in worklog
        assert "Schema-invalid structured output is not retried on the same route" in worklog
        assert "`SCHEMA_VALIDATION_FAILED`" in worklog
        assert "future code change and regressions are required" in worklog
        assert "metadata returned a nonempty endpoint list" in worklog
        assert "proving those plan route identifiers stale" in worklog
        assert "no alternative route identity, operational status, ZDR" in worklog
        assert "A globally usable route remains" in worklog
        assert "`INCONCLUSIVE`, not proven genuinely unserved" in worklog
        assert "Azure was unlisted rather than probed" in worklog
        assert "`V3-CALIBRATE-001` only as the next critical path" in worklog
        assert "do not reopen it in this closure" in worklog

    for historical_runtime_inventory_hash in (
        HISTORICAL_RUNTIME_ADMISSION_AUTONOMY_INVENTORY_RAW_SHA256,
        HISTORICAL_RUNTIME_ADMISSION_AUTONOMY_INVENTORY_SHA256,
        HISTORICAL_RUNTIME_ADMISSION_AUTONOMY_DISCOVERY_SEMANTICS_SHA256,
        HISTORICAL_RUNTIME_ADMISSION_AUTONOMY_SOURCE_UNIVERSE_SHA256,
    ):
        assert historical_runtime_inventory_hash in traceability_text


def test_planconstraints_ticket_is_mirrored_and_fail_closed() -> None:
    def ticket_section(document: str) -> str:
        match = re.search(
            r"^#{2,3} V3-PLANCONSTRAINTS-001\b.*?(?=^#{2,3} V3-[A-Z0-9-]+\b|\Z)",
            document,
            flags=re.MULTILINE | re.DOTALL,
        )
        assert match is not None
        return " ".join(match.group().split())

    canonical = ticket_section(QUEUE_PATH.read_text(encoding="utf-8"))
    codex = ticket_section(CODEX_QUEUE_PATH.read_text(encoding="utf-8"))

    for section in (canonical, codex):
        assert "**Status:** `COMPLETE`" in section
        assert (
            "operator-reported, nonauthorizing `c627f2d` offline-valid sealed one-case" in section
        )
        assert "satisfies only this provider-free prerequisite" in section
        assert "not independent bundle authentication or campaign authority" in section
        assert "successfully sealed and offline-verified" not in section
        assert "mandatory before the 24-case campaign" in section.lower()
        assert "typed, self-hashed route-predicate profile" in section
        assert "same typed predicate implementations" in section or (
            "same typed predicate" in section and "runtime" in section
        )
        assert "exact-model" in section and "selected-endpoint" in section
        assert "`structured_outputs`" in section
        assert "endpoint-first" in section
        assert "exact-model catalog fallback only under the validated" in section
        assert "exact operational accepted state" in section
        assert "provider cap is expressible" in section
        assert "closed" in section and "disposition/reason" in section
        assert "lacks a selection representation" in section
        assert "typed `UNAVAILABLE`" in section
        assert "24-case campaign" in section and "fail" in section.lower()
        assert "wholly runtime-only" in section
        assert "absence of one complete shared predicate profile" in section
        assert "necessary but never proves behavioral schema reliability" in section
        assert "Runtime schema conformance remains a separate empirical" in section
        assert "Item 5" in section and "`ADOPTED_NONAUTHORIZING / IMPLEMENTED`" in section
        assert PLANCONSTRAINTS_REPAIR_CHECKPOINT in section
        assert "five-path checkpoint" in section
        assert "case-insensitive `display_count == 1` selected-name rule" in section
        assert "unrelated Fireworks/Alibaba/Morph collisions" in section
        assert HISTORICAL_PLANCONSTRAINTS_BASE_CHECKPOINT in section
        assert "exact 33-path provider-free implementation" in section
        assert "command" in section and "campaign" in section
        assert "is current" in section
        assert "Keep queued until AUTHRUNNER produces a successful smoke bundle" not in section
        assert "Keep queued until the AUTHRUNNER smoke succeeds" not in section
        assert "Item 3's REPLAY allowlist is historical" in section
        assert "candidate/PRIMARY extension remains advisory" in section
        assert "Items 2, 3, 4, and 6 remain" in section
        assert "`OPERATOR_SUPPLIED_NONAUTHORIZING_ANALYSIS`" in section


def test_modelrefresh_candidate_revocation_closure_is_current() -> None:
    for document in (
        QUEUE_PATH.read_text(encoding="utf-8"),
        CODEX_QUEUE_PATH.read_text(encoding="utf-8"),
    ):
        match = re.search(
            r"^#{2,3} V3-MODELREFRESH-001\b.*?(?=^#{2,3} V3-[A-Z0-9-]+\b|\Z)",
            document,
            flags=re.MULTILINE | re.DOTALL,
        )
        assert match is not None
        section = " ".join(match.group().split())
        assert "No provider or operator action is current" in section
        assert "**Status:** `PARTIAL`" in section
        assert "Candidate-revocation result 2026-08-27" in section
        assert "negative" in section.lower() and "tombstone" in section.lower()
        assert "exact and canonical" in section
        assert "before secrets" in section or "before secret" in section
        assert "Adjacent explicitly pinned endpoints remain eligible" in section or (
            "explicitly pinned adjacent endpoint is not overblocked" in section
        )
        assert "changed neither retry code nor retry configuration" in section


def test_status_reducer_is_derived_and_rejects_unknown_ticket_ids() -> None:
    statuses = {
        "V3-COMPLETE-001": "COMPLETE",
        "V3-ACTIVE-001": "IN_PROGRESS",
        "V3-PARTIAL-001": "PARTIAL",
        "V3-SAFETY-001": "BLOCKED_SAFETY",
        "V3-TECHNICAL-001": "BLOCKED_TECHNICAL",
        "V3-QUEUED-001": "QUEUED",
    }

    assert _derive_requirement_status(["V3-COMPLETE-001"], statuses) == "COMPLETE"
    assert (
        _derive_requirement_status(["V3-COMPLETE-001", "V3-ACTIVE-001"], statuses) == "IN_PROGRESS"
    )
    assert _derive_requirement_status(["V3-COMPLETE-001", "V3-QUEUED-001"], statuses) == "PARTIAL"
    assert _derive_requirement_status(["V3-SAFETY-001"], statuses) == "BLOCKED_SAFETY"
    assert _derive_requirement_status(["V3-TECHNICAL-001"], statuses) == "BLOCKED_TECHNICAL"
    assert _derive_requirement_status(["V3-QUEUED-001"], statuses) == "QUEUED"
    assert _derive_requirement_status(["ALL"], statuses) == "IN_PROGRESS"
    assert _derive_requirement_status(["ALL"], {"V3-ONE-001": "COMPLETE"}) == "COMPLETE"

    _assert_fails(
        "unknown tickets",
        lambda: _derive_requirement_status(["V3-UNKNOWN-001"], statuses),
    )
    _assert_fails(
        "ALL cannot be combined",
        lambda: _derive_requirement_status(["ALL", "V3-QUEUED-001"], statuses),
    )
    _assert_fails(
        "repeats a ticket",
        lambda: _derive_requirement_status(["V3-QUEUED-001", "V3-QUEUED-001"], statuses),
    )


def test_status_table_parser_rejects_duplicate_rows() -> None:
    document = """
## Queue-derived capability status

| Capability | Ticket | Queue status |
| --- | --- | --- |
| One | `V3-ONE-001` | `QUEUED` |
| Duplicate | `V3-ONE-001` | `COMPLETE` |
"""

    _assert_fails(
        "duplicate status-table row",
        lambda: _parse_status_table(document, "## Queue-derived capability status"),
    )


def test_review_traceability_statuses_derive_from_queue_ticket_statuses() -> None:
    queue_statuses = _parse_queue_ticket_statuses(QUEUE_PATH.read_text(encoding="utf-8"))
    traceability_text = TRACEABILITY_PATH.read_text(encoding="utf-8")
    traceability = json.loads(traceability_text)
    requirements = traceability["requirements"]
    requirement_ids = [requirement["id"] for requirement in requirements]
    requirements_by_id = {requirement["id"]: requirement for requirement in requirements}

    assert requirement_ids == list(EXPECTED_REQUIREMENT_IDS), (
        "review traceability must contain the canonical complete A-V requirement sequence"
    )
    assert requirements_by_id["K"]["tickets"] == ["V3-COVERAGE-001", "V3-TAXONOMY-001"]
    assert requirements_by_id["K"]["status"] == "COMPLETE"
    assert "19-item defensive corpus" in requirements_by_id["K"]["evidence"][-1]
    assert requirements_by_id["K"]["remaining_proof"] == (
        "No local Requirement K proof remains. Its completed provider-free evidence supplies no "
        "provider execution, qualification, campaign, audit, benchmark, AUTHSEAL, runtime, or "
        "release authority."
    )
    assert requirements_by_id["U"]["status"] == "IN_PROGRESS"
    assert "V3-RETRIEVAL-001 is COMPLETE" in requirements_by_id["U"]["evidence"][-1]
    assert "V3-PRICELEXEME-001" in requirements_by_id["U"]["evidence"][-1]
    assert "implementation_started=false" in requirements_by_id["U"]["evidence"][-1]
    assert "V3-TAXONOMY-001" in requirements_by_id["U"]["remaining_proof"]
    assert "V3-RETRIEVAL-001" in requirements_by_id["U"]["remaining_proof"]
    assert "V3-PRICELEXEME-001" in requirements_by_id["U"]["remaining_proof"]
    assert "Finish V3-TAXONOMY-001" not in requirements_by_id["U"]["remaining_proof"]
    assert "The current 29375-byte operator log" not in traceability_text
    assert "The current 35771-byte operator record" not in traceability_text
    assert "the current one-entry AUTHRUNNER campaign ledger" not in traceability_text
    assert "the then-current one-entry AUTHRUNNER campaign ledger" in traceability_text
    assert "then-current 29375-byte operator log" in traceability_text
    assert "then-current 35771-byte operator record" in traceability_text
    assert "global 25-entry ledger / 0.396223 USD" in traceability_text
    operator_reconciliation = traceability["operator_evidence_reconciliation"]
    assert operator_reconciliation["critical_path_ticket"] == "V3-PRICELEXEME-001"
    critical_path_status = operator_reconciliation["critical_path_ticket_status"]
    for status_component in (
        "IN_PROGRESS_SELECTED_UNIMPLEMENTED_PROVIDER_FREE_NONAUTHORIZING",
        "PRICEFORM_REFUSAL_UPHELD",
        "EFFORT_HIGH_RETAINED",
        "V3_RETRIEVAL_001_COMPLETE",
        "V3_CANDROUTE_001_PARTIAL_DOWNSTREAM",
    ):
        assert status_component in critical_path_status
    assert (
        operator_reconciliation[
            "critical_path_ticket_newly_selected_started_or_marked_in_progress_this_turn"
        ]
        is True
    )
    assert operator_reconciliation["current_preflight_status"].startswith(
        "LOCAL_V3_PRICELEXEME_001_IN_PROGRESS_SELECTED_UNIMPLEMENTED_PROVIDER_FREE_NONAUTHORIZING"
    )
    assert (
        "RETAINED_LOCAL_V3_ACTORMODEL_001_COMPLETE"
        in (operator_reconciliation["current_preflight_status"])
    )
    assert (
        "RETAINED_LOCAL_V3_ENDPOINTLIST_001_COMPLETE"
        in (operator_reconciliation["current_preflight_status"])
    )
    assert "V3_RETRIEVAL_001_COMPLETE" in operator_reconciliation["current_preflight_status"]
    assert "IMPLEMENTATION_STARTED_FALSE" in operator_reconciliation["current_preflight_status"]
    assert operator_reconciliation["current_local_ticket"] == "V3-PRICELEXEME-001"
    assert operator_reconciliation["current_local_ticket_status"] == (
        "IN_PROGRESS_SELECTED_UNIMPLEMENTED_PROVIDER_FREE_NONAUTHORIZING"
    )
    assert operator_reconciliation["current_taxonomy_ticket"] == "V3-TAXONOMY-001"
    assert operator_reconciliation["current_taxonomy_status"] == (
        "COMPLETE_PROVIDER_FREE_NONAUTHORIZING_CODEX_ZERO_EXTERNAL_COMMANDS"
    )
    assert operator_reconciliation["current_taxonomy_version"] == "1.0"
    assert operator_reconciliation["current_taxonomy_item_count"] == 19
    assert operator_reconciliation["current_taxonomy_critical_item_count"] == 15
    assert operator_reconciliation["current_taxonomy_dispositions"] == [
        "REVIEWED",
        "NOT_APPLICABLE",
        "GAP",
    ]
    for taxonomy_true_field in (
        "current_taxonomy_deterministic_profile_applicability",
        "current_taxonomy_applicability_evidence_backed",
        "current_taxonomy_omission_becomes_gap",
        "current_taxonomy_denominator_reported_with_surface_coverage",
        "current_taxonomy_critical_gap_blocks_maximum_assurance_complete",
        "current_taxonomy_canonical_generation_current",
        "current_taxonomy_release_collection_blocked_technical_before_side_effects",
        "current_taxonomy_affected_matrices_complete",
        "current_taxonomy_complete_sequential_suite_passed",
    ):
        assert operator_reconciliation[taxonomy_true_field] is True
    for taxonomy_false_field in (
        "current_taxonomy_creates_findings",
        "current_taxonomy_finding_authority",
    ):
        assert operator_reconciliation[taxonomy_false_field] is False
    assert (
        operator_reconciliation["current_taxonomy_assurance_report_learning_matrix_passed"] == 291
    )
    assert (
        operator_reconciliation["current_taxonomy_model_coverage_review_manifest_matrix_passed"]
        == 233
    )
    assert operator_reconciliation["current_taxonomy_release_replay_matrix_passed"] == 314
    assert operator_reconciliation["current_taxonomy_scheduler_affected_matrix_passed"] == 350
    assert operator_reconciliation["current_actor_model_ticket"] == "V3-ACTORMODEL-001"
    assert operator_reconciliation["current_actor_model_status"] == (
        "COMPLETE_PROVIDER_FREE_NONAUTHORIZING_CODEX_ZERO_EXTERNAL_COMMANDS"
    )
    assert operator_reconciliation["current_actor_model_schema_paths"] == [
        "schemas/actor_model.schema.json",
        "schemas/actor_model_baseline.schema.json",
        "schemas/actor_model_evaluation.schema.json",
    ]
    assert operator_reconciliation["current_actor_model_fixture_paths"] == [
        "tests/fixtures/actor_model/synthetic_orchard_actor_model.json",
        "tests/fixtures/actor_model/synthetic_correction_scenarios.json",
    ]
    for actor_model_true_field in (
        "current_actor_model_typed_versioned_self_hashed_operator_authored_input",
        "current_actor_model_current_stale_missing_future_and_invalid_handling",
        "current_actor_model_role_occupancy_distinguishes_currently_held_and_admitted_unfilled",
        "current_actor_model_capital_and_loss_waterfall_priority_enforced",
        "current_actor_model_action_against_interest_requires_plausibility_evidence_or_rates_down",
        "current_actor_model_ordinary_legitimate_behavior_increases_likelihood",
        "current_actor_model_ordinary_legitimate_behavior_changes_framing_and_remediation",
        "current_actor_model_absent_or_stale_input_limits_every_finding_severity",
        "current_actor_model_absent_or_stale_input_attaches_limitation_to_every_finding_severity",
        "current_actor_model_typed_code_model_occupancy_governance_conflict",
        "current_actor_model_specialists_actor_blind",
        "current_actor_model_verifiers_actor_blind",
        "current_actor_model_judge_receives_typed_context",
        "current_actor_model_judge_context_only_post_consensus_severity_calibration_when_input_current",
        "current_actor_model_baseline_custody",
        "current_actor_model_evaluation_custody",
        "current_actor_model_judge_decision_custody",
    ):
        assert operator_reconciliation[actor_model_true_field] is True
    for actor_model_false_field in (
        "current_actor_model_judge_classification_controls_consensus_or_confidence_when_input_current",
        "current_actor_model_unknown_actor_facts_inferred",
        "current_actor_model_provider_or_network_accessed_by_codex",
        "current_actor_model_operator_command_emitted_by_codex",
        "current_actor_model_grants_authority",
    ):
        assert operator_reconciliation[actor_model_false_field] is False
    assert operator_reconciliation["current_actor_model_role_occupancy_states"] == [
        "CURRENTLY_HELD",
        "ADMITTED_UNFILLED",
    ]
    assert operator_reconciliation["current_actor_model_validated_correction_scenarios"] == [
        "anchor-first-loss-scope",
        "ordinary-servicer-forbearance",
        "request-cooldown-severity",
    ]
    assert operator_reconciliation["current_candidate_reasoning_effort_requirement_settled"]
    assert operator_reconciliation["current_candidate_reasoning_effort_requirement"] == (
        "EFFORT_HIGH_REQUIRED_BY_SHARED_AUTHRUNNER_PROFILE_ALL_ROLES_ALL_PURPOSES"
    )
    assert operator_reconciliation["current_candidate_reasoning_effort_predicate_relaxed"] is False
    assert operator_reconciliation[
        "current_candidate_price_form_decision_settled_operator_reported"
    ]
    assert operator_reconciliation["current_candidate_price_form_decision"] == (
        "CURRENT_BINARY_FLOAT_CUSTODY_REFUSAL_UPHELD"
    )
    assert operator_reconciliation["current_candidate_price_exactness_requirement_relaxed"] is False
    assert (
        operator_reconciliation[
            "current_candidate_numeric_price_ordinary_json_path_remains_inadmissible"
        ]
        is True
    )
    assert operator_reconciliation["current_candidate_lossless_price_lexeme_custody_ticket"] == (
        "V3-PRICELEXEME-001"
    )
    assert operator_reconciliation[
        "current_candidate_lossless_price_lexeme_custody_ticket_status"
    ] == ("IN_PROGRESS_SELECTED_UNIMPLEMENTED_PROVIDER_FREE_NONAUTHORIZING")
    assert operator_reconciliation[
        "current_candidate_lossless_price_lexeme_parse_float_decimal_fact_operator_reported"
    ]
    assert (
        operator_reconciliation[
            "current_candidate_lossless_price_lexeme_parse_float_decimal_fact_independently_verified_by_codex"
        ]
        is False
    )
    assert operator_reconciliation["current_candidate_conditional_future_route"] == (
        "x-ai/grok-4.6=amazon-bedrock/us-west-2"
    )
    assert (
        operator_reconciliation["current_candidate_conditional_future_route_currently_admissible"]
        is False
    )
    assert operator_reconciliation["current_candidate_conditional_future_route_selected"] is False
    assert (
        operator_reconciliation["current_candidate_lossless_price_lexeme_decision_grants_authority"]
        is False
    )
    assert operator_reconciliation["current_candidate_endpoint_inventory_refresh_supported"]
    assert (
        operator_reconciliation["current_candidate_endpoint_inventory_refresh_schema_version"]
        == "1.6"
    )
    assert operator_reconciliation["current_candidate_endpoint_inventory_refresh_disposition"] == (
        "OPERATOR_STAGED_UNVERIFIED"
    )
    assert operator_reconciliation[
        "current_candidate_endpoint_inventory_refresh_requires_constrained_discovery"
    ]
    assert (
        operator_reconciliation["current_candidate_endpoint_inventory_refresh_grants_authority"]
        is False
    )
    assert operator_reconciliation[
        "current_candidate_endpoint_inventory_refresh_live_route_preflight_proven_synthetic"
    ]
    assert operator_reconciliation["current_endpoint_inventory_diagnostic_ticket"] == (
        "V3-ENDPOINTLIST-001"
    )
    assert operator_reconciliation["current_endpoint_inventory_diagnostic_status"] == (
        "COMPLETE_PROVIDER_FREE_V1_1_MODEL_EFFECTIVE_REASONING_PARITY_NONAUTHORIZING_"
        "OPERATOR_LIVE_V1_0_SURVEY_CODEX_NO_EXTERNAL_ACTION"
    )
    assert operator_reconciliation["current_endpoint_inventory_diagnostic_schema_version"] == "1.1"
    assert (
        operator_reconciliation["current_endpoint_inventory_diagnostic_schema_raw_sha256"]
        == CURRENT_ENDPOINTLIST_DIAGNOSTIC_SCHEMA_RAW_SHA256
    )
    assert operator_reconciliation[
        "current_endpoint_inventory_diagnostic_exact_model_metadata_only"
    ]
    assert operator_reconciliation[
        "current_endpoint_inventory_diagnostic_reports_exact_route_arguments"
    ]
    for field in (
        "current_endpoint_inventory_diagnostic_reports_endpoint_structured_output_inventory",
        "current_endpoint_inventory_diagnostic_reports_model_structured_output_inventory",
        "current_endpoint_inventory_diagnostic_reports_endpoint_reasoning_effort_inventory",
        "current_endpoint_inventory_diagnostic_reports_model_reasoning_effort_inventory",
        "current_endpoint_inventory_diagnostic_reports_effective_reasoning_effort_inventory",
        "current_endpoint_inventory_diagnostic_reports_effective_reasoning_effort_inventory_source",
        "current_endpoint_inventory_diagnostic_shared_reasoning_effort_resolver_with_route_admission",
        "current_endpoint_inventory_diagnostic_exact_catalog_model_read_sealed",
        "current_endpoint_inventory_diagnostic_full_metadata_credential_reflection_scan",
    ):
        assert operator_reconciliation[field]
    assert (
        operator_reconciliation[
            "current_endpoint_inventory_diagnostic_operator_reported_v1_0_live_enumeration_performed"
        ]
        is True
    )
    assert (
        operator_reconciliation[
            "current_endpoint_inventory_diagnostic_corrected_v1_1_live_enumeration_performed"
        ]
        is False
    )
    assert (
        operator_reconciliation[
            "current_endpoint_inventory_diagnostic_live_enumeration_performed_by_codex"
        ]
        is False
    )
    assert (
        operator_reconciliation[
            "current_endpoint_inventory_diagnostic_live_enumeration_independently_authenticated_by_codex"
        ]
        is False
    )
    assert (
        operator_reconciliation[
            "current_endpoint_inventory_diagnostic_operator_reported_model_count"
        ]
        == 12
    )
    assert (
        operator_reconciliation[
            "current_endpoint_inventory_diagnostic_operator_reported_endpoint_count"
        ]
        == 112
    )
    assert (
        operator_reconciliation[
            "current_endpoint_inventory_diagnostic_operator_reported_endpoint_reasoning_inventory_count"
        ]
        == 0
    )
    assert (
        operator_reconciliation[
            "current_endpoint_inventory_diagnostic_operator_reported_route_trial_count"
        ]
        == 4
    )
    assert (
        operator_reconciliation[
            "current_endpoint_inventory_diagnostic_operator_reported_admissible_candidate_count"
        ]
        == 0
    )
    assert (
        operator_reconciliation[
            "current_endpoint_inventory_diagnostic_completion_or_ledger_activity"
        ]
        is False
    )
    assert (
        operator_reconciliation["current_endpoint_inventory_diagnostic_grants_authority"] is False
    )
    assert operator_reconciliation["current_modelrefresh_ticket_status"].startswith(
        "PARTIAL_CANDIDATE_REVOCATION_SLICE_COMPLETE_PROVIDER_FREE"
    )
    assert operator_reconciliation["current_learning_ticket_status"].startswith(
        "PARTIAL_PHASE_1_COMPLETE_PROVIDER_FREE"
    )
    assert operator_reconciliation["last_completed_ticket"] == "V3-RETRIEVAL-001"
    assert operator_reconciliation["last_partial_ticket"] == "V3-CANDROUTE-001"
    assert operator_reconciliation["next_safe_local_ticket"] == "V3-PRICELEXEME-001"
    assert operator_reconciliation["completed_real_audits"] == 0
    next_safe_action = operator_reconciliation["next_safe_action"]
    for next_action_component in (
        "BEGIN",
        "PROVIDER_FREE",
        "V3_PRICELEXEME_001",
        "IMPLEMENTATION",
        "NOT_STARTED",
        "PRICEFORM_REFUSAL",
        "EFFORT_HIGH",
        "V3_CANDROUTE_001_PARTIAL_DOWNSTREAM",
        "NO_PROVIDER_OR_OPERATOR_COMMAND_OR_AUTHORITY_IS_CURRENT",
    ):
        assert next_action_component in next_safe_action
    assert operator_reconciliation["current_candidate_revocation_plan_reconciliation_complete"]
    assert operator_reconciliation["current_candidate_revocation_local_evaluation_scope"] == (
        "REQUESTED_ASSIGNED_ROUTE"
    )
    assert (
        operator_reconciliation["current_candidate_unrevoked_alternative_discovery_succeeds"]
        is False
    )
    assert operator_reconciliation["current_candidate_unrevoked_alternative_discovery_scope"] == (
        "OPERATOR_REPORTED_PLAN_ALLOWED_REAL_ROUTE_SWEEP_NOT_INDEPENDENTLY_AUTHENTICATED"
    )
    assert operator_reconciliation["current_candidate_synthetic_refreshed_route_discovery_succeeds"]
    assert operator_reconciliation["current_candidate_exact_role_isolation_proven_provider_free"]
    assert operator_reconciliation[
        "current_candidate_exact_transport_role_custody_proven_provider_free"
    ]
    assert operator_reconciliation[
        "current_candidate_plan_or_constraint_hash_resurrection_rejected"
    ]
    assert operator_reconciliation["current_candidate_selection_plan_emitter_available"]
    assert operator_reconciliation["current_candidate_plan_successor_ticket_selected"]
    assert operator_reconciliation["current_candidate_plan_successor_ticket_complete"]
    assert operator_reconciliation["current_candidate_plan_successor_schema_version"] == "1.5"
    assert operator_reconciliation["current_candidate_plan_successor_artifact_emitted_or_selected"]
    assert operator_reconciliation[
        "current_candidate_plan_successor_artifact_emitted_operator_reported"
    ]
    assert (
        operator_reconciliation["current_candidate_plan_successor_artifact_inspected_by_codex"]
        is False
    )
    assert (
        operator_reconciliation["current_candidate_plan_successor_selected_as_active_plan"] is False
    )
    assert (
        operator_reconciliation[
            "current_candidate_complete_constrained_sweep_admissible_count_operator_reported"
        ]
        == 0
    )
    assert operator_reconciliation[
        "current_candidate_plan_successor_provider_free_live_route_preflight_proven"
    ]
    assert operator_reconciliation["current_candidate_replacement_selected"] is False
    assert operator_reconciliation["current_schema_retry_ticket_status"].startswith(
        "COMPLETE_PROVIDER_FREE_NONAUTHORIZING"
    )
    assert operator_reconciliation["current_retry_continuity_ticket_status"].startswith(
        "COMPLETE_PROVIDER_FREE_NONAUTHORIZING"
    )
    assert operator_reconciliation["current_consensus_ticket_status"] == (
        "COMPLETE_PROVIDER_FREE_NONAUTHORIZING"
    )
    trace_runtime_mechanism_status = operator_reconciliation[
        "runtime_admission_local_promotion_mechanism_status"
    ]
    assert trace_runtime_mechanism_status.startswith("COMPLETE_CORRECTED")
    assert "PROVIDER_FREE" in trace_runtime_mechanism_status
    assert "NONAUTHORIZING" in trace_runtime_mechanism_status
    assert operator_reconciliation["current_operator_results_sha256"] == (
        CURRENT_OPERATOR_RESULTS_SHA256
    )
    assert operator_reconciliation["current_latest_entry_timestamp"] == (
        CURRENT_OPERATOR_RESULTS_LATEST_ENTRY
    )
    assert (
        operator_reconciliation["current_operator_results_bytes"] == CURRENT_OPERATOR_RESULTS_BYTES
    )
    assert (
        operator_reconciliation["current_operator_results_lines"] == CURRENT_OPERATOR_RESULTS_LINES
    )
    assert (
        operator_reconciliation["current_operator_results_repository_commit"]
        == CURRENT_OPERATOR_RESULTS_REPOSITORY_COMMIT
    )
    assert (
        operator_reconciliation[
            "current_operator_results_repository_commit_pushed_and_remote_resolved"
        ]
        is True
    )
    assert operator_reconciliation["runtime_admission_default_without_evidence_remains_unavailable"]
    assert operator_reconciliation["runtime_admission_current_private_evidence_replayed"] is True
    assert (
        operator_reconciliation["runtime_admission_current_private_evidence_replayed_by_codex"]
        is False
    )
    assert operator_reconciliation[
        "runtime_admission_empirical_schema_conformance_status_operator_reported"
    ] == ("SATISFIED_INDEX22_R23_FOR_FAILED_LAUNCH")
    assert operator_reconciliation[
        "runtime_admission_token_detail_reporting_convention_status_operator_reported"
    ] == ("SATISFIED_INDEX22_R23_FOR_FAILED_LAUNCH")
    assert (
        operator_reconciliation[
            "runtime_admission_corrected_code_private_evidence_replay_performed"
        ]
        is True
    )
    assert (
        operator_reconciliation["runtime_admission_current_full_campaign_admission_satisfied"]
        is False
    )
    assert (
        operator_reconciliation[
            "runtime_admission_full_campaign_admission_satisfied_for_failed_launch_operator_reported"
        ]
        is True
    )
    assert (
        operator_reconciliation["runtime_admission_mechanism_grants_authority_or_campaign_credit"]
        is False
    )
    requirements_by_id = {requirement["id"]: requirement for requirement in requirements}
    assert requirements_by_id["G"]["status"] == "COMPLETE"
    assert "V3-SCHEMARETRY-001 is COMPLETE" in requirements_by_id["G"]["evidence"][-1]
    assert "provider-backed retry execution" in requirements_by_id["G"]["remaining_proof"]
    consensus_a_evidence = requirements_by_id["A"]["evidence"][-1]
    consensus_n_evidence = requirements_by_id["N"]["evidence"][-1]
    consensus_u_evidence = next(
        evidence
        for evidence in reversed(requirements_by_id["U"]["evidence"])
        if evidence.startswith("V3-CONSENSUS-001 completed")
    )
    for consensus_evidence in (
        consensus_a_evidence,
        consensus_n_evidence,
        consensus_u_evidence,
    ):
        assert "V3-CONSENSUS-001" in consensus_evidence
    assert "exact source validation" in consensus_a_evidence
    assert "evidence caps" in consensus_a_evidence
    assert "dissent" in consensus_a_evidence
    assert "terminal report custody" in consensus_a_evidence
    assert "detached replay" in consensus_a_evidence
    assert "nonconfirming" in consensus_a_evidence
    assert "COMPLETE" in consensus_n_evidence
    assert "provider-free" in consensus_n_evidence
    assert "nonauthorizing" in consensus_n_evidence
    assert "one verifier and two lineage-distinct falsifiers" in consensus_n_evidence
    assert "all dissent" in consensus_n_evidence
    assert "one reviewer cannot suppress" in consensus_n_evidence
    assert "Model agreement alone is nonconfirming" in consensus_n_evidence
    assert "614 unit tests" in consensus_n_evidence
    assert "seven selected synthetic local integrations" in consensus_n_evidence
    assert "no HIGH/blocking defect" in consensus_n_evidence
    assert "no REAL provider run" in consensus_n_evidence
    assert "provider-free exact three-review quorum" in consensus_u_evidence
    assert "detached terminal-replay" in consensus_u_evidence
    assert "614 affected units" in consensus_u_evidence
    assert "seven selected integrations" in consensus_u_evidence
    assert "no HIGH/blocking defect" in consensus_u_evidence
    assert "does not alter retry configuration" in consensus_u_evidence
    assert "grants no provider, campaign, audit, runtime, qualification, or release authority" in (
        consensus_u_evidence
    )
    truncation_evidence = " ".join(requirements_by_id["J"]["evidence"])
    assert CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT in truncation_evidence
    assert HISTORICAL_TRUNCATION_RECURSIVE_CHECKPOINT in truncation_evidence
    assert CURRENT_TRUNCATION_PROMOTION_CHECKPOINT in truncation_evidence
    assert CURRENT_TRUNCATION_PROMOTION_PARENT_CHECKPOINT in truncation_evidence
    assert "Exact 20-path checkpoint" in truncation_evidence
    assert "provider-free full-tree live promotion-custody slice" in truncation_evidence
    assert "Distinct PID-local recursive-tree and promoted-surface capabilities" in (
        truncation_evidence
    )
    assert "one exact root v1.1 promotion and recovered output" in truncation_evidence
    assert "four public request schema v1.2 projections" in truncation_evidence
    assert "five exact live usage/context pairs" in truncation_evidence
    assert "SUPERSEDED_TRUNCATED_BRIDGE" in truncation_evidence
    assert "three SUCCEEDED leaves have disposition SUCCESSFUL_LEAF" in truncation_evidence
    assert "universal exact direct and recursive parent plus child/leaf" in truncation_evidence
    assert "vacuous zero-retained parent partitions" in truncation_evidence
    assert "fail-closed substitution negatives" in truncation_evidence
    assert "108 evidence/journal/promotion tests" in truncation_evidence
    assert "63 model-coverage tests" in truncation_evidence
    assert "244 assurance tests" in truncation_evidence
    assert "57 schema/inventory tests" in truncation_evidence
    assert "independent no-blocker/HIGH review passed" in truncation_evidence
    assert "Synthetic REAL attestations" in truncation_evidence
    assert "not genuine provider execution" in truncation_evidence
    truncation_remaining = requirements_by_id["J"]["remaining_proof"]
    assert "genuine provider-backed promotion" in truncation_remaining
    assert "terminal maximum-assurance result" in truncation_remaining
    assert "extend depth beyond two" in truncation_remaining
    assert "retained-bridge recursion" in truncation_remaining
    assert "specialist recursive recovery" in truncation_remaining
    assert "no operator/provider authority exists" in truncation_remaining
    autonomy_evidence = " ".join(requirements_by_id["U"]["evidence"])
    current_autonomy_evidence = next(
        evidence
        for evidence in reversed(requirements_by_id["U"]["evidence"])
        if evidence.startswith("V3-CANDROUTE-001 is PARTIAL locally")
    )
    assert CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT in autonomy_evidence
    assert HISTORICAL_TRUNCATION_RECURSIVE_CHECKPOINT in autonomy_evidence
    assert HISTORICAL_TRUNCATION_RECURSIVE_PARENT_CHECKPOINT in autonomy_evidence
    assert CURRENT_TRUNCATION_PROMOTION_CHECKPOINT in autonomy_evidence
    assert CURRENT_TRUNCATION_PROMOTION_PARENT_CHECKPOINT in autonomy_evidence
    assert AUTONOMY_INVENTORY_RAW_SHA256 in autonomy_evidence
    assert AUTONOMY_INVENTORY_SHA256 in autonomy_evidence
    assert AUTONOMY_DISCOVERY_SEMANTICS_SHA256 in autonomy_evidence
    assert AUTONOMY_SOURCE_UNIVERSE_SHA256 in autonomy_evidence
    assert CURRENT_SCHEMARETRY_AUTONOMY_INVENTORY_RAW_SHA256 in current_autonomy_evidence
    assert CURRENT_SCHEMARETRY_AUTONOMY_INVENTORY_SHA256 in current_autonomy_evidence
    assert CURRENT_SCHEMARETRY_AUTONOMY_DISCOVERY_SEMANTICS_SHA256 in current_autonomy_evidence
    assert CURRENT_SCHEMARETRY_AUTONOMY_SOURCE_UNIVERSE_SHA256 in current_autonomy_evidence
    assert "3815 sources / 3818 occurrences / 3768 gate sources" in current_autonomy_evidence
    assert (
        "47 non-gating controls / 13 source kinds / 35 logical gates / 29 unsatisfied / "
        "15 current-manual"
    ) in current_autonomy_evidence
    assert "3667 unique completion inputs / 3670 occurrences" in autonomy_evidence
    assert "3624 gate sources / 43 non-gating controls" in autonomy_evidence
    assert "13 source kinds / 35 logical gates / 29 unsatisfied / 15 current-manual" in (
        autonomy_evidence
    )
    assert "full-tree live promotion custody" in autonomy_evidence
    assert "all five live usage/context" in autonomy_evidence
    assert "one v1.1 promotion and one v1.1 recovered output" in autonomy_evidence
    assert "one bridge and three leaves" in autonomy_evidence
    assert "universal direct and recursive parent plus child/leaf" in autonomy_evidence
    assert "MOCK remains unpromoted" in autonomy_evidence
    assert "Synthetic REAL attestations" in autonomy_evidence
    assert "not provider execution" in autonomy_evidence
    assert CURRENT_OPERATOR_RESULTS_SHA256 in autonomy_evidence
    assert "V3-RUNTIMEADMIT-001" in autonomy_evidence
    assert "COMPLETE" in autonomy_evidence
    assert "provider-free" in autonomy_evidence
    assert "EMPIRICAL_SCHEMA_CONFORMANCE" in autonomy_evidence
    assert "satisfied" in autonomy_evidence.lower()
    assert "TOKEN_DETAIL_REPORTING_CONVENTION" in autonomy_evidence
    assert "rejected" in autonomy_evidence.lower()
    assert "pre-fix digest join" in autonomy_evidence.lower()
    assert "current operator record reports" in autonomy_evidence.lower()
    assert "no corrected-code private replay exists" in autonomy_evidence.lower()
    assert "FULL" in autonomy_evidence and (
        "false" in autonomy_evidence.lower() or "unproven" in autonomy_evidence.lower()
    )
    autonomy_remaining = requirements_by_id["U"]["remaining_proof"]
    assert "V3-CONSENSUS-001" in requirements_by_id["N"]["remaining_proof"]
    assert (
        "completed provider-free V3-CONSENSUS-001" in (requirements_by_id["N"]["remaining_proof"])
    )
    assert "V3-CONSENSUS-001" in autonomy_remaining
    assert "COMPLETE" in autonomy_remaining
    assert "genuine provider-backed promotion" in autonomy_remaining.lower()
    assert "terminal maximum-assurance" in autonomy_remaining
    assert "V3-RUNTIMEADMIT-001" in autonomy_remaining
    assert "COMPLETE" in autonomy_remaining
    assert "replacement candidate" in autonomy_remaining.lower()
    assert "unbound generation identity" in autonomy_remaining.lower()
    assert "V3-RETRYCONT-001" in autonomy_remaining
    assert "provider-backed retry" in autonomy_remaining.lower()
    assert "V3-CALIBRATE-001" in autonomy_remaining
    assert "No current command or run index exists" in autonomy_remaining
    for requirement in requirements:
        tickets = requirement["tickets"]
        assert isinstance(tickets, list) and all(isinstance(ticket, str) for ticket in tickets)
        expected = _derive_requirement_status(tickets, queue_statuses)
        assert requirement["status"] == expected, (
            f"traceability requirement {requirement['id']} status must derive from queue tickets "
            f"{tickets}: expected {expected}, found {requirement['status']}"
        )


def test_readme_and_model_work_markings_derive_from_queue_ticket_statuses() -> None:
    queue_statuses = _parse_queue_ticket_statuses(QUEUE_PATH.read_text(encoding="utf-8"))
    readme = README_PATH.read_text(encoding="utf-8")
    model_selection = MODEL_SELECTION_PATH.read_text(encoding="utf-8")
    readme_markings = _parse_status_table(readme, "## Queue-derived capability status")
    model_markings = _parse_status_table(
        model_selection,
        "## Queue-derived model-work status",
    )

    assert set(readme_markings) == README_CAPABILITY_TICKETS
    assert set(model_markings) == MODEL_WORK_TICKETS
    for document_name, markings in (
        ("README", readme_markings),
        ("model-selection guide", model_markings),
    ):
        for ticket, marked_status in markings.items():
            assert ticket in queue_statuses, f"{document_name} marks unknown ticket {ticket}"
            assert marked_status == queue_statuses[ticket], (
                f"{document_name} marks {ticket} as {marked_status}, but the queue status is "
                f"{queue_statuses[ticket]}"
            )

    release_matches = re.findall(
        r"^\*\*Repository release status:\*\* `(?P<status>[A-Z_]+)`\s*$",
        _isolated_level_two_section(readme, "## Queue-derived capability status"),
        re.MULTILINE,
    )
    assert len(release_matches) == 1, (
        "README capability section must carry one repository release-status marking"
    )
    runtime_status = json.loads(RUNTIME_STATUS_PATH.read_text(encoding="utf-8"))
    assert release_matches[0] == runtime_status["release_status"]


def test_operator_command_results_have_a_persistent_reconciliation_contract() -> None:
    agents = AGENTS_PATH.read_text(encoding="utf-8")
    model_selection = MODEL_SELECTION_PATH.read_text(encoding="utf-8")
    normalized_model_selection = " ".join(model_selection.split())
    selection_plan = json.loads(SELECTION_PLAN_PATH.read_text(encoding="utf-8"))
    operator_prerequisite_guides = (
        OPERATOR_PREREQUISITES_PATH.read_text(encoding="utf-8"),
        V3_OPERATOR_PREREQUISITES_PATH.read_text(encoding="utf-8"),
    )
    operator_result_bytes = subprocess.run(
        [
            "git",
            "show",
            f"{PLANCONSTRAINTS_REPAIR_PARENT_CHECKPOINT}:{OPERATOR_RESULTS_RELATIVE_PATH}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    operator_results = operator_result_bytes.decode("utf-8")
    current_operator_result_bytes = (ROOT / OPERATOR_RESULTS_RELATIVE_PATH).read_bytes()
    current_operator_results = current_operator_result_bytes.decode("utf-8")
    queues = (
        (ROOT / "docs/codex_work_queue.md").read_text(encoding="utf-8"),
        QUEUE_PATH.read_text(encoding="utf-8"),
    )
    worklogs = (
        CODEX_WORKLOG_PATH.read_text(encoding="utf-8"),
        (ROOT / "docs/remediation/v3/worklog.md").read_text(encoding="utf-8"),
    )
    for worklog in worklogs:
        current_header = worklog.split("\n## ", maxsplit=1)[0]
        assert "AUTORUN_STATUS:" in current_header
        assert "PROVIDER_FREE" in current_header
        assert "NONAUTHORIZING" in current_header
        assert "CODEX_ZERO_EXTERNAL_COMMANDS" in current_header
        assert "CURRENT_TICKET:" in current_header
        assert "CURRENT_LOCAL_SLICE_STATUS:" in current_header
        assert "LAST_COMPLETED_TICKET:" in current_header
        assert "LAST_PARTIAL_TICKET: V3-CANDROUTE-001" in current_header
        assert CURRENT_COVERAGE_CHECKPOINT in worklog
        assert "V3-ACTORMODEL-001" in worklog
        assert "unfinished tickets" in current_header
        assert "V3-TAXONOMY-001" in worklog
        assert "V3-ACTORMODEL-001" in worklog
        assert "REMAINING_ACTIONABLE_TICKETS:" in current_header
        assert "V3-CANDROUTE-001" in current_header and "PARTIAL" in current_header
        assert "ZERO_ADMISSIBLE_CANDIDATES" in current_header
        assert "no codex provider or operator action" in current_header.lower()
        assert "V3-CALIBRATE-001" in worklog and "BLOCKED_TECHNICAL" in worklog
        assert "OPERATOR_RESULTS_CURRENT_WORKTREE_STATUS: RECONCILED_EXACT_AF7A24E" in (
            current_header
        )
        for status_component in (
            "OPERATOR_DECISION_LOSSLESS_PRICE_LEXEME_CUSTODY",
            "PRICEFORM_REFUSAL_UPHELD",
            "REASONING_EFFORT_REQUIRED",
            "PRICELEXEME_QUEUED",
            "PRIOR_LIVE_V1_0_METADATA_SURVEY",
            "12_MODELS",
            "112_ENDPOINTS",
            "ZERO_ENDPOINT_REASONING_EFFORT_INVENTORIES",
            "V1_0_MODEL_AND_EFFECTIVE_REASONING_OMISSION_CORRECTED_LOCALLY_IN_V1_1",
            "ZERO_ADMISSIBLE_CANDIDATES",
            "ACTIVE_PLAN_UNCHANGED",
            "LEDGER_UNCHANGED",
            "57_ENTRIES",
            "068118684_SPEND",
            "ZERO_COMPLETED_REAL_AUDITS",
            "NONAUTHORIZING",
            "NOT_INDEPENDENTLY_AUTHENTICATED_BY_CODEX",
        ):
            assert status_component in current_header
        assert (
            f"LAST_RECONCILED_OPERATOR_RESULTS: `{CURRENT_OPERATOR_RESULTS_SHA256}` / "
            f"{CURRENT_OPERATOR_RESULTS_BYTES} bytes / {CURRENT_OPERATOR_RESULTS_LINES} lines"
        ) in current_header
    normalized_queues = tuple(" ".join(queue.split()) for queue in queues)
    combined_queue_statuses = _parse_all_queue_ticket_statuses(queues[0]) | (
        _parse_all_queue_ticket_statuses(queues[1])
    )
    for raw_queue, normalized_queue in zip(queues, normalized_queues, strict=True):
        assert _parse_all_queue_ticket_statuses(raw_queue)["V3-COVERAGE-001"] == "COMPLETE"
        assert _parse_all_queue_ticket_statuses(raw_queue)["V3-RETRY-001"] == "COMPLETE"
        assert _parse_all_queue_ticket_statuses(raw_queue)["V3-RUNTIMEADMIT-001"] == "COMPLETE"
        assert _parse_all_queue_ticket_statuses(raw_queue)["V3-CONSENSUS-001"] == "COMPLETE"
        assert _parse_all_queue_ticket_statuses(raw_queue)["V3-RETRYCONT-001"] == "COMPLETE"
        assert _parse_all_queue_ticket_statuses(raw_queue)["V3-QUOTE-001"] == "COMPLETE"
        assert _parse_all_queue_ticket_statuses(raw_queue)["V3-SCHEMARETRY-001"] == "COMPLETE"
        assert _parse_all_queue_ticket_statuses(raw_queue)["V3-ENDPOINTLIST-001"] == "COMPLETE"
        assert _parse_all_queue_ticket_statuses(raw_queue)["V3-ACTORMODEL-001"] == "COMPLETE"
        assert _parse_all_queue_ticket_statuses(raw_queue)["V3-LEARNING-001"] == "PARTIAL"
        assert "V3-CALIBRATE-001" in normalized_queue
        assert "Stop after" in normalized_queue and "`COMPLETE`" in normalized_queue
        assert "successor" in normalized_queue.lower()
        assert "no external action" in normalized_queue.lower()
    assert combined_queue_statuses["V3-SINGLE-AUDIT-001"] == "QUEUED"
    assert combined_queue_statuses["V3-MULTI-AUDIT-001"] == "QUEUED"
    assert combined_queue_statuses["V3-REVOKERECON-001"] == "COMPLETE"
    assert combined_queue_statuses["V3-PLANSUCCESSOR-001"] == "COMPLETE"
    assert combined_queue_statuses["V3-ENDPOINTLIST-001"] == "COMPLETE"
    assert combined_queue_statuses["V3-ACTORMODEL-001"] == "COMPLETE"
    assert combined_queue_statuses["V3-CANDROUTE-001"] == "PARTIAL"
    assert combined_queue_statuses["V3-PRICEFORM-001"] == "QUEUED"
    assert combined_queue_statuses["V3-RETRIEVAL-001"] == "COMPLETE"
    assert combined_queue_statuses["V3-PRICELEXEME-001"] == "IN_PROGRESS"
    runtime_status = json.loads(RUNTIME_STATUS_PATH.read_text(encoding="utf-8"))
    current_operator_status = runtime_status["operator_results_current_worktree_status"]
    assert current_operator_status.startswith(
        "RECONCILED_EXACT_AF7A24E_OPERATOR_DECISION_LOSSLESS_PRICE_LEXEME_CUSTODY"
    )
    for status_component in (
        "PRICEFORM_REFUSAL_UPHELD",
        "REASONING_EFFORT_REQUIRED",
        "PRICELEXEME_QUEUED",
        "PRIOR_LIVE_V1_0_METADATA_SURVEY",
        "V1_0_METADATA_SURVEY",
        "12_MODELS",
        "112_ENDPOINTS",
        "ZERO_ENDPOINT_REASONING_EFFORT_INVENTORIES",
        "V1_0_MODEL_AND_EFFECTIVE_REASONING_OMISSION_CORRECTED_LOCALLY_IN_V1_1",
        "ZERO_ADMISSIBLE_CANDIDATES",
        "ACTIVE_PLAN_UNCHANGED",
        "LEDGER_UNCHANGED",
        "57_ENTRIES",
        "068118684_SPEND",
        "ZERO_COMPLETED_REAL_AUDITS",
        "NONAUTHORIZING",
        "NOT_INDEPENDENTLY_AUTHENTICATED_BY_CODEX",
    ):
        assert status_component in current_operator_status
    assert runtime_status["operator_results_current_worktree_required_for_ticket"] is False
    assert (
        runtime_status["last_reconciled_operator_results_sha256"] == CURRENT_OPERATOR_RESULTS_SHA256
    )
    assert (
        runtime_status["last_reconciled_operator_results_bytes"] == CURRENT_OPERATOR_RESULTS_BYTES
    )
    assert (
        runtime_status["last_reconciled_operator_results_lines"] == CURRENT_OPERATOR_RESULTS_LINES
    )
    assert runtime_status["last_reconciled_operator_entry_timestamp"] == (
        CURRENT_OPERATOR_RESULTS_LATEST_ENTRY
    )
    assert (
        hashlib.sha256(current_operator_result_bytes).hexdigest() == CURRENT_OPERATOR_RESULTS_SHA256
    )
    assert len(current_operator_result_bytes) == CURRENT_OPERATOR_RESULTS_BYTES
    assert len(current_operator_results.splitlines()) == CURRENT_OPERATOR_RESULTS_LINES
    assert f"## {CURRENT_OPERATOR_RESULTS_LATEST_ENTRY}" in current_operator_results
    current_operator_entry = _isolated_level_two_section(
        current_operator_results,
        "## 2026-09-01T04:49Z — **OPERATOR DECISION: pursue lossless price-lexeme custody. "
        "The V3-PRICEFORM-001 refusal is upheld, and answered.**",
    )
    normalized_current_operator_entry = " ".join(current_operator_entry.split())
    historical_endpoint_survey_entry = _isolated_level_two_section(
        current_operator_results,
        "## 2026-08-30T19:00Z — **`list-endpoints` WORKS. Live survey of 112 endpoints "
        "across 12 models: still NO admissible candidate**",
    )
    normalized_historical_endpoint_survey_entry = " ".join(historical_endpoint_survey_entry.split())
    historical_plan_successor_entry = _isolated_level_two_section(
        current_operator_results,
        "## 2026-08-30T15:18Z — **V3-PLANSUCCESSOR-001 WORKS. But NO candidate route "
        "is admissible — complete sweep, $0**",
    )
    historical_plan_gap_entry = _isolated_level_two_section(
        current_operator_results,
        "## 2026-08-28T12:56Z — **REVOCATION RECONCILED AND WORKING; replacement "
        "candidates still unusable — plan succession needed**",
    )
    historical_revocation_deadlock_entry = _isolated_level_two_section(
        current_operator_results,
        "## 2026-08-28T07:56Z — **REGRESSION: candidate revocation deadlocks ALL candidate "
        "discovery; reselection sweep cannot run**",
    )
    campaign_operator_entry = _isolated_level_two_section(
        current_operator_results,
        "## 2026-08-27T17:22Z — **FIRST REAL 24-CASE CAMPAIGN LAUNCHED AND FAILED "
        "CLOSED — candidate reselection required**",
    )
    historical_runtime_admission_entry = _isolated_level_two_section(
        current_operator_results,
        "## 2026-08-27T10:28Z — **V3-RUNTIMEADMIT-001 WORKS: schema conformance now "
        "SATISFIED; token-detail isolated to one clause**",
    )
    historical_50d_entry = _isolated_level_two_section(
        current_operator_results,
        "## 2026-08-27T06:37Z — **CAMPAIGN BLOCKER FULLY TRACED: two admission predicates "
        "have no satisfying code path**",
    )
    assert "Both refusals are accepted" in normalized_current_operator_entry
    assert "`REASONING_EFFORT_SUPPORT` is genuinely required" in (normalized_current_operator_entry)
    assert "`model_benchmark` reasoning policy" in normalized_current_operator_entry
    assert "emits `effort=high` and reserves reasoning tokens" in normalized_current_operator_entry
    assert "rejection also stands" in normalized_current_operator_entry
    assert "ordinary JSON parsing" in normalized_current_operator_entry
    assert "`Decimal(str(value))` proves only the chosen reserialization" in (
        normalized_current_operator_entry
    )
    assert "unsound and is withdrawn" in normalized_current_operator_entry
    assert "Pursue lossless price-lexeme custody" in normalized_current_operator_entry
    assert "Do not relax the exactness requirement" in normalized_current_operator_entry
    assert "parse_float=Decimal" in current_operator_entry
    assert "V3-PRICELEXEME-001" in current_operator_entry
    assert "the *requirement* is unchanged and still fails closed" in current_operator_entry
    assert "only the *custody model* changes" in current_operator_entry
    assert "Existing sealed evidence must remain byte-identical and continue to replay" in (
        normalized_current_operator_entry
    )
    assert "x-ai/grok-4.6=amazon-bedrock/us-west-2" in current_operator_entry
    assert "If implemented" in current_operator_entry
    assert "If it cannot be implemented soundly" in normalized_current_operator_entry
    assert "under the current constraint set no admissible candidate route exists" in (
        normalized_current_operator_entry
    )
    assert "No spend" in current_operator_entry
    assert "ledger unchanged at 57 entries" in normalized_current_operator_entry
    assert "`V3-ENDPOINTLIST-001` works and was exercised live" in (
        normalized_historical_endpoint_survey_entry
    )
    assert "all 112 endpoints of all 12 models" in normalized_historical_endpoint_survey_entry
    assert "absent on all 112 endpoints" in normalized_historical_endpoint_survey_entry
    assert "model-level" in normalized_historical_endpoint_survey_entry
    assert "effective resolved value" in normalized_historical_endpoint_survey_entry
    assert "No admissible candidate exists" in normalized_historical_endpoint_survey_entry
    assert "ledger unchanged at 57" in normalized_historical_endpoint_survey_entry
    assert "V3-CANDROUTE-001" in normalized_historical_endpoint_survey_entry
    assert "completed_real_audits` remains `0`" in normalized_historical_endpoint_survey_entry
    assert "Successor plans emit and bind correctly" in historical_plan_successor_entry
    assert "00b6aa8fb1d23640a6b65dae7883d7265e416b9ba4383c3240329e62500f34b3" in (
        historical_plan_successor_entry
    )
    assert "bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f" in (
        historical_plan_successor_entry
    )
    assert "zero admissible candidates" in historical_plan_successor_entry
    assert "REASONING_EFFORT_INVENTORY_UNAVAILABLE" in historical_plan_successor_entry
    assert "provider-free throughout" in historical_plan_successor_entry.lower()
    assert "predecessor" in historical_plan_successor_entry
    assert "unconstrained discovery passing is not evidence of admissibility" in (
        historical_plan_successor_entry.lower()
    )
    assert "V3-REVOKERECON-001` works" in historical_plan_gap_entry
    assert "EMPIRICAL_STRUCTURED_OUTPUT_NONCONFORMANCE" in historical_plan_gap_entry
    assert "google/gemma-4-26b-a4b-it=deepinfra/fp8" in historical_plan_gap_entry
    assert "tencent/hy3=novita" in historical_plan_gap_entry
    assert "ordinary drift, not revocation" in historical_plan_gap_entry
    assert (
        "authenticated runner route lacks constrained discovery evidence"
        in historical_plan_gap_entry
    )
    assert "V3-PLANSUCCESSOR-001" in historical_plan_gap_entry
    assert "ledger unchanged at 57 entries" in historical_plan_gap_entry
    assert "exactly **one** entry" in historical_revocation_deadlock_entry
    assert "every candidate is refused" in historical_revocation_deadlock_entry
    assert "candidate selection route is revoked" in historical_revocation_deadlock_entry
    assert "completed_real_audits` stays `0`" in historical_revocation_deadlock_entry
    assert "paid smoke index `22`" in campaign_operator_entry
    assert "`0.04395915` USD" in campaign_operator_entry
    assert "29702a02f52626deca38ff36401eb3cb7bb4602f07677881760ad26ba40df5d4" in (
        campaign_operator_entry
    )
    assert "`FULL_CAMPAIGN_ADMISSION` satisfied" in campaign_operator_entry
    assert "`0.20264508`" in campaign_operator_entry
    assert "Structured model request failed" in campaign_operator_entry
    assert "x9" in campaign_operator_entry
    assert "Completed response identity is unbound" in campaign_operator_entry
    assert "x15" in campaign_operator_entry
    assert "All `24` new ledger entries are `reconciled`" in campaign_operator_entry
    assert "`57` entries" in campaign_operator_entry
    assert "`0.68118684`" in campaign_operator_entry
    assert "completed_real_audits` remains **0**" in campaign_operator_entry
    assert "Candidate reselection" in campaign_operator_entry
    assert "real sealed evidence" in historical_runtime_admission_entry
    assert "EMPIRICAL_SCHEMA_CONFORMANCE" in historical_runtime_admission_entry
    assert "TOKEN_DETAIL_REPORTING_CONVENTION" in historical_runtime_admission_entry
    assert "RUNTIME_EVIDENCE_INVALID" in historical_runtime_admission_entry
    assert "index-21 bundle + **r21** registries" in historical_runtime_admission_entry
    assert "flagged as a hypothesis, not a finding" in historical_runtime_admission_entry
    assert "The qualification-policy blocker" in historical_50d_entry
    assert "is **cleared**" in historical_50d_entry
    assert "first-attempt-only structured-output scoring" in current_operator_results
    assert "Retry itself remains authorized" in current_operator_results
    assert "failed two regressions" in historical_50d_entry
    assert "was reverted" in historical_50d_entry
    assert "ledger unchanged at 29" in current_operator_results
    assert "0.43458261" in current_operator_results
    current_guide_reconciliation = _isolated_level_three_section(
        model_selection,
        "### Current operator-result reconciliation — 2026-09-01T04:49Z",
    )
    normalized_current_guide_reconciliation = " ".join(current_guide_reconciliation.split())
    assert CURRENT_OPERATOR_RESULTS_SHA256 in current_guide_reconciliation
    assert "162,656 bytes / 2,902 lines" in current_guide_reconciliation
    assert "nonauthorizing" in normalized_current_guide_reconciliation
    assert "not independently authenticated by Codex" in normalized_current_guide_reconciliation
    assert "credentialed metadata-only" in normalized_current_guide_reconciliation
    assert "12 models and 112 endpoints" in normalized_current_guide_reconciliation
    assert "both outstanding refusals" in normalized_current_guide_reconciliation
    assert "reserve reasoning tokens" in normalized_current_guide_reconciliation
    assert "all four route-constraint purposes" in normalized_current_guide_reconciliation
    assert "binary float" in normalized_current_guide_reconciliation
    assert "parse_float=Decimal" in current_guide_reconciliation
    assert "V3-PRICELEXEME-001" in current_guide_reconciliation
    assert "AF7 evidence boundary" in current_guide_reconciliation
    assert "queued, unselected, and unimplemented" in normalized_current_guide_reconciliation
    assert "sole `IN_PROGRESS` ticket" in current_guide_reconciliation
    assert "V3-RETRIEVAL-001" in current_guide_reconciliation
    assert "`COMPLETE`" in current_guide_reconciliation
    assert "`implementation_started=false`" in current_guide_reconciliation
    assert "no decoder, pricing, retry, or configuration change" in (
        normalized_current_guide_reconciliation
    )
    assert "not currently admissible or selected" in normalized_current_guide_reconciliation
    assert "existing sealed evidence must remain byte-identical" in (
        normalized_current_guide_reconciliation.lower()
    )
    assert "schema v1.1" in normalized_current_guide_reconciliation
    assert "has not been exercised live" in normalized_current_guide_reconciliation
    assert "effort=high" in normalized_current_guide_reconciliation
    assert "predicate remains unchanged" in normalized_current_guide_reconciliation
    assert "prior 15:18 entry remains historical" in normalized_current_guide_reconciliation
    assert "zero admissible candidates" in current_guide_reconciliation
    assert "V3-CANDROUTE-001" in current_guide_reconciliation
    assert "57 entries" in current_guide_reconciliation
    assert "0.68118684" in current_guide_reconciliation
    assert "non-runnable" in normalized_current_guide_reconciliation.lower()
    assert "cannot substitute" in current_guide_reconciliation
    assert "No operator command or run index is current or inferred" in (
        normalized_current_guide_reconciliation
    )
    assert "0.20264508" in current_guide_reconciliation
    assert LAST_RECONCILED_OPERATOR_RESULTS_SHA256 not in current_guide_reconciliation
    assert "### Historical r1\u2013r19 accounting and canonical-replay boundary" in model_selection
    assert "### Last reconciled r1\u2013r19 accounting and canonical-replay boundary" not in (
        model_selection
    )
    assert "no successful current provider snapshot" not in normalized_model_selection
    assert "active schema-v1.4 selection plan remains byte-unchanged" in (
        normalized_model_selection
    )
    assert "that assignment non-runnable" in normalized_model_selection
    assert "no replacement candidate is selected" in normalized_model_selection.lower()
    route_profile = selection_plan["authenticated_runner_selection"]["route_predicate_profile"]
    assert route_profile["empirical_schema_conformance_disposition"] == "UNAVAILABLE"
    assert route_profile["token_detail_convention_disposition"] == "UNAVAILABLE"
    assert selection_plan["status"] == "NONAUTHORIZING"
    for authority_field in (
        "provider_call_authorized",
        "source_egress_authorized",
        "qualification_authorized",
        "benchmark_authorized",
        "production_selection_authorized",
        "runner_authority_authorized",
        "seal_publication_authorized",
        "release_authorized",
        "documentary_lineage_identity_authorized",
        "serialized_authority",
    ):
        assert selection_plan[authority_field] is False
    for operator_prerequisites in operator_prerequisite_guides:
        normalized_operator_prerequisites = " ".join(operator_prerequisites.split())
        assert CURRENT_OPERATOR_RESULTS_SHA256 in operator_prerequisites
        assert "162,656 bytes / 2,902 lines" in operator_prerequisites
        assert "credentialed metadata-only" in normalized_operator_prerequisites
        assert "12 models" in normalized_operator_prerequisites
        assert "112 endpoints" in normalized_operator_prerequisites
        assert "accepts both refusals" in normalized_operator_prerequisites
        assert "reserve reasoning tokens" in normalized_operator_prerequisites
        assert "all four route purposes" in normalized_operator_prerequisites
        assert "binary float" in normalized_operator_prerequisites
        assert "parse_float=Decimal" in operator_prerequisites
        assert "V3-PRICELEXEME-001" in operator_prerequisites
        assert "AF7 evidence boundary" in operator_prerequisites
        assert "queued, unselected, and unimplemented" in normalized_operator_prerequisites
        assert "sole `IN_PROGRESS` ticket" in operator_prerequisites
        assert "V3-RETRIEVAL-001" in operator_prerequisites
        assert "`COMPLETE`" in operator_prerequisites
        assert "`implementation_started=false`" in operator_prerequisites
        assert "no decoder, pricing, retry, or configuration change" in (
            normalized_operator_prerequisites
        )
        assert "not currently admissible or selected" in normalized_operator_prerequisites
        assert "no admissible candidate route" in normalized_operator_prerequisites
        assert "No constraint was relaxed" in operator_prerequisites
        assert "schema v1.1" in normalized_operator_prerequisites
        assert "has not been exercised live" in normalized_operator_prerequisites
        assert "no repeat external command is required" in normalized_operator_prerequisites
        assert "--qualification-policy" in operator_prerequisites
        assert "V3-RUNTIMEADMIT-001" in operator_prerequisites
        assert "COMPLETE" in operator_prerequisites
        assert "--runtime-evidence-smoke-bundle" in operator_prerequisites
        assert "r23" in normalized_operator_prerequisites.lower()
        assert "index 22" in normalized_operator_prerequisites.lower()
        assert "failed closed" in normalized_operator_prerequisites.lower()
        assert "0.20264508" in operator_prerequisites
        assert "57" in operator_prerequisites and "0.68118684" in operator_prerequisites
        assert "Codex" in operator_prerequisites and "private" in (
            normalized_operator_prerequisites.lower()
        )
        assert "no reusable admission" in normalized_operator_prerequisites.lower() or (
            "no future authority" in normalized_operator_prerequisites.lower()
        )
        assert "no current operator" in normalized_operator_prerequisites.lower()
        assert "run index" in normalized_operator_prerequisites
        assert "--schema-validation-retries" in operator_prerequisites
        assert "manifest-v1.3" in operator_prerequisites
        assert "max_model_retries" in operator_prerequisites
        assert "transient-only" in operator_prerequisites
    assert runtime_status["current_ticket"] == "V3-PRICELEXEME-001"
    assert runtime_status["last_completed_ticket"] == "V3-RETRIEVAL-001"
    assert runtime_status["last_partial_ticket"] == "V3-CANDROUTE-001"
    assert runtime_status["next_safe_local_ticket"] == "V3-PRICELEXEME-001"
    assert runtime_status["completed_real_audits"] == 0
    current_work = runtime_status["current_provider_free_work"]
    assert current_work["ticket"] == "V3-PRICELEXEME-001"
    assert current_work["slice"] == "LOSSLESS_PROVIDER_PRICE_LEXEME_CUSTODY_SELECTION"
    assert current_work["status"] == (
        "IN_PROGRESS_SELECTED_PROVIDER_FREE_NONAUTHORIZING_IMPLEMENTATION_NOT_STARTED"
    )
    assert current_work["implementation_started"] is False
    assert (
        "BEGIN_PROVIDER_FREE_LOSSLESS_PRICE_LEXEME_IMPLEMENTATION" in (current_work["next_slice"])
    )
    assert current_work["provider_or_network_accessed_by_codex"] is False
    assert current_work["operator_command_emitted_by_codex"] is False
    assert current_work["candidate_or_route_selected"] is False
    assert current_work["grants_authority"] is False
    retrieval_work = runtime_status["last_completed_provider_free_work"]
    assert retrieval_work["ticket"] == "V3-RETRIEVAL-001"
    assert retrieval_work["slice"] == "BOUNDED_READ_ONLY_INDEXED_RETRIEVAL_LOOP"
    assert retrieval_work["status"] == (
        "COMPLETE_PROVIDER_FREE_NONAUTHORIZING_CODEX_ZERO_EXTERNAL_COMMANDS"
    )
    for retrieval_true_field in (
        "fixed_typed_read_only_indexed_lookup_allowlist",
        "secret_taint_and_scope_refusal",
        "static_role_wide_request_byte_token_budgets",
        "private_transcript_and_hash_only_public_custody",
        "failed_primary_transcript_retained",
        "exact_replay_and_resume",
        "single_shot_fallback",
        "canonical_generation_current",
        "active_selection_plan_unchanged",
        "affected_matrices_complete",
    ):
        assert retrieval_work[retrieval_true_field] is True
    for retrieval_false_field in (
        "retry_behavior_changed",
        "retry_configuration_changed",
        "model_completion_issued",
        "cost_ledger_opened_or_mutated",
        "usage_recorded",
        "credential_or_secret_disclosed",
        "candidate_replacement_selected",
        "candidate_or_route_selected",
        "provider_or_network_accessed_by_codex",
        "operator_command_emitted_by_codex",
        "grants_authority",
    ):
        assert retrieval_work[retrieval_false_field] is False
    assert retrieval_work["completed_real_audits"] == 0
    assert "V3_PRICELEXEME_001_SELECTED_IN_PROGRESS" in retrieval_work["next_slice"]
    assert "IMPLEMENTATION_STARTED_FALSE" in retrieval_work["next_slice"]
    assert "KEEP_V3_CANDROUTE_001_PARTIAL_DOWNSTREAM" in retrieval_work["next_slice"]
    terminal_validation = runtime_status["last_validation"]
    complete_sequential_suite_passed = retrieval_work["complete_sequential_suite_passed"]
    assert type(complete_sequential_suite_passed) is bool
    if complete_sequential_suite_passed:
        assert (
            retrieval_work[
                "terminal_full_suite_final_rerun_pending_after_governance_reconciliation"
            ]
            is False
        )
        assert type(retrieval_work["terminal_full_suite_passed"]) is int
        assert retrieval_work["terminal_full_suite_passed"] > 0
        assert type(retrieval_work["terminal_full_suite_skipped"]) is int
        assert retrieval_work["terminal_full_suite_skipped"] >= 0
        assert type(retrieval_work["terminal_full_suite_warnings"]) is int
        assert retrieval_work["terminal_full_suite_warnings"] >= 0
        assert type(retrieval_work["terminal_full_suite_elapsed_seconds"]) in (int, float)
        assert retrieval_work["terminal_full_suite_elapsed_seconds"] > 0
        assert terminal_validation["status"].startswith("V3_RETRIEVAL_001_COMPLETE_PROVIDER_FREE")
        assert "NONAUTHORIZING_CODEX_ZERO_EXTERNAL_COMMANDS" in terminal_validation["status"]
        assert terminal_validation["terminal_full_suite_run"] is True
        assert terminal_validation["terminal_full_suite_attempt_started"] is True
        terminal_suite = terminal_validation["v3_retrieval_001_terminal_full_suite"]
        assert terminal_suite["exit_code"] == 0
        assert terminal_suite["tests_passed"] == retrieval_work["terminal_full_suite_passed"]
        assert terminal_suite["tests_skipped"] == retrieval_work["terminal_full_suite_skipped"]
        assert terminal_suite["warnings"] == retrieval_work["terminal_full_suite_warnings"]
        assert (
            terminal_suite["elapsed_seconds"]
            == retrieval_work["terminal_full_suite_elapsed_seconds"]
        )
        assert terminal_suite["terminal_result_available"] is True
        assert terminal_suite["pass_credit"] is True
        assert terminal_suite["required_local_loopback_permission"] is True
    else:
        assert retrieval_work["terminal_full_suite_passed"] == 0
        assert retrieval_work["terminal_full_suite_skipped"] == 0
        assert retrieval_work["terminal_full_suite_warnings"] == 0
        assert retrieval_work["terminal_full_suite_elapsed_seconds"] == 0.0
        assert (
            retrieval_work[
                "terminal_full_suite_final_rerun_pending_after_governance_reconciliation"
            ]
            is True
        )
        assert "v3_retrieval_001_terminal_full_suite" not in terminal_validation

    successor_status = runtime_status["candidate_selection_plan_successor"]
    assert successor_status["ticket"] == "V3-PLANSUCCESSOR-001"
    assert successor_status["status"] == "COMPLETE_PROVIDER_FREE_NONAUTHORIZING"
    assert successor_status["active_plan_schema_version"] == "1.4"
    assert successor_status["active_plan_sha256"] == CURRENT_NONAUTHORIZING_SUCCESSOR_PLAN_SHA256
    assert successor_status["active_plan_unchanged"] is True
    assert successor_status["successor_plan_schema_version"] == "1.5"
    assert successor_status["candidate_selection_plan_schema_raw_sha256"] == (
        "ea3a9218f1595d3de521b8020e7929235e5940105c5f5d43cfbc45a21a2c3feb"
    )
    assert successor_status["emitter_command"] == "models emit-selection-plan-successor"
    assert successor_status["emitter_available"] is True
    assert successor_status["predecessor_digest_recorded"] is True
    assert successor_status["entry_constraint_profile_role_and_plan_hashes_derived"] is True
    assert successor_status["caller_supplied_hashes_accepted"] is False
    assert successor_status["judge_constraints_carried_forward"] is True
    assert successor_status["current_revocation_enforced_before_publication"] is True
    assert successor_status["historical_structural_validation_independent_of_later_revocation"]
    assert successor_status["predecessor_discovery_evidence_reinterpreted_under_successor"] is False
    assert successor_status["callable_replacement_and_code_mutation_rejected_before_publication"]
    assert successor_status["fresh_private_mode_0600_publication"] is True
    assert successor_status["successor_bound_constrained_discovery_proven_provider_free"] is True
    assert successor_status["successor_bound_live_route_preflight_only_proven_provider_free"]
    assert successor_status["successor_bound_completion_transport_occurred"] is False
    assert successor_status["successor_artifact_checked_in"] is False
    assert successor_status["candidate_replacement_selected"] is False
    assert successor_status["completed_real_audits"] == 0
    for authority_field in (
        "provider_or_network_accessed",
        "secret_material_read",
        "operator_private_artifact_or_ledger_accessed",
        "operator_command_emitted",
        "campaign_or_run_index_selected",
        "qualification_authority",
        "runtime_authority",
        "release_authority",
    ):
        assert successor_status[authority_field] is False

    consensus = runtime_status["consensus_provider_free_adjudication"]
    assert consensus["ticket"] == "V3-CONSENSUS-001"
    assert consensus["status"] == "COMPLETE_PROVIDER_FREE_NONAUTHORIZING"
    assert consensus["reviewer_roles"] == ["VERIFIER", "FALSIFIER_1", "FALSIFIER_2"]
    assert consensus["exact_reviewer_count"] == 3
    for required_consensus_control in (
        "exactly_one_verifier",
        "exactly_two_lineage_distinct_falsifiers",
        "complete_distinct_reviewer_inventory_required",
        "all_dissent_retained",
        "provider_generation_identity_globally_unique",
        "exact_terminal_candidate_validation_bound",
        "complete_and_partial_terminal_replay_bound",
        "detached_replay_requires_scheduler_manifest",
        "evidence_cap_bound_to_trusted_policy",
        "severity_policy_bound_to_trusted_input",
    ):
        assert consensus[required_consensus_control] is True
    for prohibited_consensus_claim in (
        "single_reviewer_can_suppress_candidate_group",
        "model_agreement_receives_confirmation_credit",
        "scanner_exact_full_claim_semantic_binding_available",
        "scanner_claim_confirmation_without_exact_binding",
        "provider_or_network_accessed",
        "credential_or_secret_material_read",
        "operator_private_artifact_accessed",
        "operator_private_ledger_accessed_or_mutated",
        "operator_command_emitted",
        "campaign_or_run_index_selected",
        "retry_behavior_changed",
        "retry_configuration_changed",
        "qualification_authority",
        "runtime_authority",
        "release_authority",
        "successor_ticket_selected",
    ):
        assert consensus[prohibited_consensus_claim] is False
    assert consensus["affected_unit_tests_passed"] == 614
    assert consensus["selected_integration_tests_passed"] == 7
    assert consensus["independent_review"] == "PASS_NO_BLOCKER_OR_HIGH"
    assert consensus["limitations"] == [
        "DETACHED_BUNDLES_ARE_SELF_SEALED_NOT_EXTERNALLY_AUTHENTICATED",
        "SCANNER_OUTPUT_REMAINS_NONCONFIRMING_WITHOUT_EXACT_FULL_CLAIM_BINDING",
        "STANDALONE_CONSENSUS_ARTIFACTS_ARE_NONAUTHORITATIVE_WITHOUT_SCHEDULER_MANIFEST_REPLAY",
        "PROVIDER_FREE_REGRESSIONS_DO_NOT_PROVE_REAL_PROVIDER_EXECUTION_OR_A_COMPLETED_REAL_AUDIT",
    ]
    retry_policy = runtime_status["retry_provider_free_policy"]
    assert retry_policy["ticket"] == "V3-RETRY-001"
    assert retry_policy["status"] == "COMPLETE_PROVIDER_FREE_NONAUTHORIZING"
    assert retry_policy["default_schema_validation_retries"] == 0
    assert retry_policy["default_field_omitted_from_serialization"] is True
    assert retry_policy["retry_quotas_independent"] is True
    assert retry_policy["combined_maximum_model_attempts"] == 32
    assert retry_policy["schema_retryable_failure_codes"] == ["SCHEMA_VALIDATION_FAILED"]
    assert retry_policy["same_route_only"] is True
    assert retry_policy["structured_output_compliance_scope"] == "FIRST_ATTEMPT_ONLY"
    assert retry_policy["retried_success_receives_structured_output_compliance_credit"] is False
    assert retry_policy["private_smoke_r19_r21_replay_independently_proven"] is False
    assert retry_policy["source_checkpoint_commit"] == CURRENT_RETRY_CHECKPOINT
    assert retry_policy["source_checkpoint_parent"] == CURRENT_RETRY_PARENT_CHECKPOINT
    assert retry_policy["source_checkpoint_committed"] is True
    assert retry_policy["source_checkpoint_pushed"] is True
    assert retry_policy["source_checkpoint_remote_resolved"] is True
    assert retry_policy["source_checkpoint_exact_path_count"] == len(V3_RETRY_SOURCE_PATHS)
    assert frozenset(retry_policy["source_checkpoint_exact_paths"]) == V3_RETRY_SOURCE_PATHS
    for authority_key in (
        "provider_or_network_accessed",
        "credential_or_secret_material_read",
        "operator_private_ledger_accessed_or_mutated",
        "operator_command_emitted",
        "campaign_or_run_index_selected",
        "runtime_authority",
        "qualification_authority",
        "release_authority",
    ):
        assert retry_policy[authority_key] is False
    retry_continuity = runtime_status["retry_continuity_provider_free"]
    assert retry_continuity["ticket"] == "V3-RETRYCONT-001"
    assert retry_continuity["status"] == "COMPLETE_PROVIDER_FREE_NONAUTHORIZING"
    assert retry_continuity["default_config_path"] == "config/openrouter-qualification.toml"
    assert retry_continuity["continuity_config_path"] == (
        "config/openrouter-authenticated-runner-retry-continuity.toml"
    )
    assert retry_continuity["default_config_raw_sha256"] == (
        "696b70a811835dc6d711048670dfb4055858b07cf3a07b518cd6a3af9f3a2dca"
    )
    assert retry_continuity["default_effective_config_sha256"] == (
        "e81516464de46b3b10d4533b1c0f792ae895e09c43cafc2d01f60cc2ad5bc438"
    )
    assert retry_continuity["default_execution_config_sha256"] == (
        "2e19ab801f4f18ce66beb757a7009a7cb0a1d5959f8ed199db3a50b9cf1a4a5f"
    )
    assert retry_continuity["continuity_config_raw_sha256"] == (
        "309fab2335472654a2402803bda6af5d1dec6c80fea580ed266463611a021a03"
    )
    assert retry_continuity["continuity_effective_config_sha256"] == (
        "c848ab89d2ecce2c182c635eb2f4825ece82ef39f30907fa3ce0cb63937c8b20"
    )
    assert retry_continuity["continuity_execution_config_sha256"] == (
        "5abc674bbd119ec4b1705265b9b7b7ccb178eb07712a995d860e9cfe358c18f1"
    )
    assert retry_continuity["default_schema_validation_retries"] == 0
    assert retry_continuity["continuity_schema_validation_retries"] == 3
    assert retry_continuity["transient_model_retries"] == 1
    assert retry_continuity["continuity_maximum_attempts_per_logical_request"] == 5
    assert retry_continuity["authenticated_runner_logical_request_count"] == 96
    assert retry_continuity["continuity_maximum_provider_attempts"] == 480
    assert retry_continuity["configured_request_capacity"] == 576
    assert retry_continuity["request_capacity_proven_before_dispatch"] is True
    assert retry_continuity["runner_evidence_full_config_hash_bound"] is True
    assert retry_continuity["durable_bundle_schema_version"] == "1.2"
    assert retry_continuity["historical_v1_0_v1_1_bundles_currently_substitutive"] is False
    assert retry_continuity["historical_failed_campaign_schema_retry_count_changed"] is False
    assert retry_continuity["structured_output_compliance_scope"] == "FIRST_ATTEMPT_ONLY"
    assert retry_continuity["retried_success_receives_structured_output_compliance_credit"] is False
    for authority_key in (
        "provider_or_network_accessed",
        "credential_or_secret_material_read",
        "operator_private_artifact_or_ledger_accessed",
        "operator_command_emitted",
        "campaign_or_run_index_selected",
        "candidate_selected",
        "qualification_authority",
        "runtime_authority",
        "release_authority",
    ):
        assert retry_continuity[authority_key] is False
    schema_retry = runtime_status["schema_retry_provider_free_activation"]
    assert schema_retry["ticket"] == "V3-SCHEMARETRY-001"
    assert schema_retry["status"] == "COMPLETE_PROVIDER_FREE_NONAUTHORIZING"
    assert schema_retry["run_cli_option"] == "--schema-validation-retries"
    assert schema_retry["quote_create_cli_option"] == "--schema-validation-retries"
    assert schema_retry["default_schema_validation_retries"] == 0
    assert schema_retry["omitted_selection_keeps_schema_retry_off"] is True
    assert schema_retry["nonzero_config_requires_exact_explicit_cli_selection"] is True
    assert schema_retry["conflict_rejected_before_paid_controls_or_quote_inputs"] is True
    assert schema_retry["transient_retry_scope"] == "NETWORK_OR_STATUS"
    assert schema_retry["transient_retry_semantics_changed"] is False
    assert schema_retry["combined_maximum_model_attempts"] == 32
    assert schema_retry["schema_retry_failure_code"] == "SCHEMA_VALIDATION_FAILED"
    assert schema_retry["schema_retry_route"] == "SAME_ROUTE"
    assert schema_retry["raw_response_bound_failures_are_schema_retryable"] is False
    assert schema_retry["exact_policy_and_hash_bound_to_quote_acceptance_budget_and_usage"]
    assert schema_retry["exact_policy_and_hash_bound_to_smoke_and_manifest"]
    assert schema_retry["emitted_retry_counts_derive_from_admitted_prior_attempt_outcomes"]
    assert schema_retry["durable_configuration_policy_join_required"]
    assert schema_retry["current_manifest_schema_version"] == "1.3"
    assert schema_retry["current_smoke_bundle_schema_version"] == "1.3"
    assert schema_retry[
        "legacy_manifest_and_smoke_v1_2_require_retry_off_and_absent_split_evidence"
    ]
    assert schema_retry["legacy_verification_requires_explicit_offline_flag"]
    assert schema_retry["structured_output_compliance_scope"] == "FIRST_ATTEMPT_ONLY"
    assert schema_retry["provider_backed_retry_execution_proven"] is False
    assert schema_retry["source_checkpoint_commit"] == ("f8960d92569cb9d8865ada9284981458699e4dab")
    assert schema_retry["source_checkpoint_uncommitted_worktree"] is False
    assert schema_retry["source_checkpoint_pushed"] is True
    assert schema_retry["source_checkpoint_remote_resolved"] is True
    for authority_key in (
        "provider_or_network_accessed",
        "credential_or_secret_material_read",
        "operator_private_artifact_or_ledger_accessed",
        "operator_command_emitted",
        "campaign_or_run_index_selected",
        "candidate_selected",
        "qualification_authority",
        "runtime_authority",
        "release_authority",
    ):
        assert schema_retry[authority_key] is False
    operator_reconciliation = runtime_status["current_operator_result_reconciliation"]
    assert operator_reconciliation["latest_entry_timestamp"] == (
        CURRENT_OPERATOR_RESULTS_LATEST_ENTRY
    )
    assert operator_reconciliation["operator_results_sha256"] == CURRENT_OPERATOR_RESULTS_SHA256
    assert operator_reconciliation["operator_results_bytes"] == CURRENT_OPERATOR_RESULTS_BYTES
    assert operator_reconciliation["operator_results_lines"] == CURRENT_OPERATOR_RESULTS_LINES
    assert operator_reconciliation["operator_results_repository_commit"] == (
        CURRENT_OPERATOR_RESULTS_REPOSITORY_COMMIT
    )
    assert (
        operator_reconciliation["operator_results_repository_commit_pushed_and_remote_resolved"]
        is True
    )
    assert operator_reconciliation["critical_path_ticket"] == "V3-PRICELEXEME-001"
    assert operator_reconciliation[
        "candidate_reasoning_effort_requirement_for_candidate_role_settled"
    ]
    assert operator_reconciliation["candidate_reasoning_effort_requirement"] == (
        "EFFORT_HIGH_REQUIRED_BY_SHARED_AUTHRUNNER_PROFILE_ALL_ROLES_ALL_PURPOSES"
    )
    assert operator_reconciliation["candidate_reasoning_effort_predicate_relaxed"] is False
    assert operator_reconciliation["candidate_price_form_decision_settled_operator_reported"]
    assert operator_reconciliation["candidate_price_form_decision"] == (
        "CURRENT_BINARY_FLOAT_CUSTODY_REFUSAL_UPHELD"
    )
    assert operator_reconciliation["candidate_price_exactness_requirement_relaxed"] is False
    assert operator_reconciliation[
        "candidate_numeric_price_ordinary_json_path_remains_inadmissible"
    ]
    assert operator_reconciliation["candidate_lossless_price_lexeme_custody_ticket"] == (
        "V3-PRICELEXEME-001"
    )
    assert operator_reconciliation["candidate_lossless_price_lexeme_custody_ticket_status"] == (
        "IN_PROGRESS_SELECTED_UNIMPLEMENTED_PROVIDER_FREE_NONAUTHORIZING"
    )
    assert operator_reconciliation[
        "candidate_lossless_price_lexeme_parse_float_decimal_fact_operator_reported"
    ]
    assert (
        operator_reconciliation[
            "candidate_lossless_price_lexeme_parse_float_decimal_fact_independently_verified_by_codex"
        ]
        is False
    )
    assert operator_reconciliation["candidate_conditional_future_route"] == (
        "x-ai/grok-4.6=amazon-bedrock/us-west-2"
    )
    assert (
        operator_reconciliation["candidate_conditional_future_route_currently_admissible"] is False
    )
    assert operator_reconciliation["candidate_conditional_future_route_selected"] is False
    assert (
        operator_reconciliation["candidate_lossless_price_lexeme_decision_grants_authority"]
        is False
    )
    assert (
        operator_reconciliation[
            "critical_path_ticket_newly_selected_started_or_marked_in_progress_this_turn"
        ]
        is True
    )
    assert (
        operator_reconciliation["candidate_route_restoration_ticket_selected_during_this_work_unit"]
        is False
    )
    assert operator_reconciliation["endpoint_inventory_diagnostic_ticket"] == (
        "V3-ENDPOINTLIST-001"
    )
    assert (
        operator_reconciliation[
            "endpoint_inventory_diagnostic_operator_reported_v1_0_live_enumeration_performed"
        ]
        is True
    )
    assert (
        operator_reconciliation[
            "endpoint_inventory_diagnostic_corrected_v1_1_live_enumeration_performed"
        ]
        is False
    )
    assert (
        operator_reconciliation["endpoint_inventory_diagnostic_live_enumeration_performed_by_codex"]
        is False
    )
    assert (
        operator_reconciliation[
            "endpoint_inventory_diagnostic_live_enumeration_independently_authenticated_by_codex"
        ]
        is False
    )
    assert operator_reconciliation["endpoint_inventory_diagnostic_schema_version"] == "1.1"
    assert operator_reconciliation["endpoint_inventory_diagnostic_schema_raw_sha256"] == (
        CURRENT_ENDPOINTLIST_DIAGNOSTIC_SCHEMA_RAW_SHA256
    )
    assert operator_reconciliation["endpoint_inventory_diagnostic_model_completion_issued"] is False
    assert (
        operator_reconciliation["endpoint_inventory_diagnostic_cost_ledger_opened_or_mutated"]
        is False
    )
    critical_path_status = operator_reconciliation["critical_path_ticket_status"]
    for status_component in (
        "IN_PROGRESS_SELECTED_UNIMPLEMENTED_PROVIDER_FREE_NONAUTHORIZING",
        "PRICEFORM_REFUSAL_UPHELD",
        "EFFORT_HIGH_RETAINED",
        "V3_RETRIEVAL_001_COMPLETE",
        "V3_CANDROUTE_001_PARTIAL_DOWNSTREAM",
    ):
        assert status_component in critical_path_status
    runtime_mechanism_status = operator_reconciliation[
        "runtime_admission_local_promotion_mechanism_status"
    ]
    assert runtime_mechanism_status.startswith("COMPLETE_CORRECTED")
    assert "PROVIDER_FREE" in runtime_mechanism_status
    assert "NONAUTHORIZING" in runtime_mechanism_status
    assert operator_reconciliation["runtime_admission_default_without_evidence_remains_unavailable"]
    assert operator_reconciliation[
        "runtime_admission_mechanism_grants_authority_or_campaign_credit"
    ] is (False)
    assert operator_reconciliation["runtime_admission_artifact_schema_path"] == (
        "schemas/route_runtime_evidence_artifact.schema.json"
    )
    assert operator_reconciliation["runtime_admission_artifact_schema_raw_sha256"] == (
        ROUTE_RUNTIME_EVIDENCE_SCHEMA_RAW_SHA256
    )
    assert operator_reconciliation["authority"] is False
    assert (
        operator_reconciliation["runtime_admission_rejection_names_failed_predicates_and_reasons"]
        is True
    )
    assert operator_reconciliation["runtime_admission_current_private_evidence_replayed"] is True
    assert (
        operator_reconciliation[
            "runtime_admission_current_private_evidence_replay_operator_reported"
        ]
        is True
    )
    assert (
        operator_reconciliation["runtime_admission_current_private_evidence_replayed_by_codex"]
        is False
    )
    assert operator_reconciliation[
        "runtime_admission_empirical_schema_conformance_status_operator_reported"
    ] == ("SATISFIED_INDEX22_R23_FOR_FAILED_LAUNCH")
    assert operator_reconciliation[
        "runtime_admission_token_detail_reporting_convention_status_operator_reported"
    ] == ("SATISFIED_INDEX22_R23_FOR_FAILED_LAUNCH")
    assert operator_reconciliation[
        "runtime_admission_corrected_code_private_evidence_replay_performed"
    ] is (True)
    assert (
        operator_reconciliation["runtime_admission_current_full_campaign_admission_satisfied"]
        is False
    )
    assert (
        operator_reconciliation[
            "runtime_admission_full_campaign_admission_satisfied_for_failed_launch_operator_reported"
        ]
        is True
    )
    assert operator_reconciliation["runtime_admission_required_predicates"] == [
        "EMPIRICAL_SCHEMA_CONFORMANCE",
        "TOKEN_DETAIL_REPORTING_CONVENTION",
    ]
    assert operator_reconciliation["qualification_campaign_schema_validation_retry_count"] == 0
    assert operator_reconciliation[
        "qualification_campaign_schema_retry_engaged_in_failed_launch"
    ] is (False)
    assert operator_reconciliation["schema_invalid_candidate_in_request_retry_proven"] is False
    assert (
        operator_reconciliation[
            "schema_invalid_candidate_same_route_retry_under_max_model_retries_one"
        ]
        is False
    )
    assert operator_reconciliation["max_model_retries_one_scope"] == (
        "TRANSIENT_NETWORK_OR_STATUS_ONLY"
    )
    assert operator_reconciliation["schema_invalid_current_disposition"] == (
        "DEFAULT_OFF; WITH_EXACT_EXPLICIT_SELECTION_RETRY_SAME_ROUTE_WITHIN_SEPARATE_"
        "SCHEMA_QUOTA_THEN_USE_CONFIGURED_FALLBACK_OR_TERMINATE"
    )
    assert (
        operator_reconciliation[
            "schema_invalid_candidate_same_route_retry_under_explicit_schema_limit_proven_provider_free"
        ]
        is True
    )
    assert operator_reconciliation["qualification_config_retry_trial_count_operator_reported"] == 3
    assert (
        operator_reconciliation["qualification_config_retry_trial_reverted_operator_reported"]
        is True
    )
    assert (
        operator_reconciliation[
            "operator_selected_same_route_retry_future_change_and_regressions_required"
        ]
        is False
    )
    assert operator_reconciliation[
        "qualification_config_repin_required_to_enable_schema_retry"
    ] is (True)
    assert operator_reconciliation["separate_non_pinned_campaign_continuity_path_available"] is (
        False
    )
    assert operator_reconciliation[
        "separate_package_pinned_campaign_continuity_path_available"
    ] is (True)
    assert (
        "V3-CALIBRATE-001 remains BLOCKED_TECHNICAL"
        in (runtime_status["blocked_tickets"]["V3-CALIBRATE-001"])
    )
    assert (
        "No current command or run index is authorized or inferred"
        in (runtime_status["blocked_tickets"]["V3-CALIBRATE-001"])
    )
    autonomy_inventory_bytes = AUTONOMY_INVENTORY_PATH.read_bytes()
    autonomy_inventory = json.loads(autonomy_inventory_bytes)
    autonomy_schema_bytes = AUTONOMY_INVENTORY_SCHEMA_PATH.read_bytes()
    autonomy_schema = json.loads(autonomy_schema_bytes)
    route_runtime_schema_bytes = ROUTE_RUNTIME_EVIDENCE_SCHEMA_PATH.read_bytes()
    route_runtime_schema = json.loads(route_runtime_schema_bytes)
    managed_toolchain_bytes = MANAGED_TOOLCHAIN_BUNDLE_PATH.read_bytes()
    managed_toolchain = json.loads(managed_toolchain_bytes)
    managed_toolchain_schema_bytes = MANAGED_TOOLCHAIN_SCHEMA_PATH.read_bytes()
    managed_toolchain_schema = json.loads(managed_toolchain_schema_bytes)
    current_phase_zero = runtime_status["autonomy_phase_zero_inventory"]
    assert hashlib.sha256(autonomy_inventory_bytes).hexdigest() == (
        CURRENT_RETRIEVAL_AUTONOMY_INVENTORY_RAW_SHA256
    )
    assert hashlib.sha256(autonomy_schema_bytes).hexdigest() == (
        CURRENT_RETRIEVAL_AUTONOMY_INVENTORY_SCHEMA_RAW_SHA256
    )
    assert hashlib.sha256(route_runtime_schema_bytes).hexdigest() == (
        ROUTE_RUNTIME_EVIDENCE_SCHEMA_RAW_SHA256
    )
    assert route_runtime_schema["$id"] == (
        "https://mmaudit.local/schemas/route_runtime_evidence_artifact.schema.json"
    )
    assert route_runtime_schema["title"] == "mmaudit nonauthorizing exact route runtime evidence"
    assert autonomy_inventory["inventory_sha256"] == (CURRENT_RETRIEVAL_AUTONOMY_INVENTORY_SHA256)
    assert autonomy_inventory["source_discovery_semantics_sha256"] == (
        CURRENT_RETRIEVAL_AUTONOMY_DISCOVERY_SEMANTICS_SHA256
    )
    assert autonomy_inventory["source_universe_sha256"] == (
        CURRENT_RETRIEVAL_AUTONOMY_SOURCE_UNIVERSE_SHA256
    )
    assert current_phase_zero["artifact_raw_sha256"] == (
        CURRENT_RETRIEVAL_AUTONOMY_INVENTORY_RAW_SHA256
    )
    assert current_phase_zero["schema_raw_sha256"] == (
        CURRENT_RETRIEVAL_AUTONOMY_INVENTORY_SCHEMA_RAW_SHA256
    )
    assert current_phase_zero["inventory_sha256"] == (CURRENT_RETRIEVAL_AUTONOMY_INVENTORY_SHA256)
    assert current_phase_zero["source_discovery_semantics_sha256"] == (
        CURRENT_RETRIEVAL_AUTONOMY_DISCOVERY_SEMANTICS_SHA256
    )
    assert current_phase_zero["source_universe_sha256"] == (
        CURRENT_RETRIEVAL_AUTONOMY_SOURCE_UNIVERSE_SHA256
    )
    assert current_phase_zero["source_count"] == 3_895
    assert current_phase_zero["source_occurrence_count"] == 3_898
    assert current_phase_zero["gate_source_count"] == 3_846
    assert current_phase_zero["non_gating_source_count"] == 49
    assert current_phase_zero["source_kind_count"] == 13
    assert current_phase_zero["logical_gate_count"] == 35
    assert current_phase_zero["unsatisfied_gate_count"] == 29
    assert current_phase_zero["current_manual_gate_count"] == 15
    assert current_phase_zero["audit_config_leaf_locator_count"] == 513
    assert current_phase_zero["audit_config_leaf_occurrence_count"] == 516
    assert current_phase_zero["audit_config_shared_locator_count"] == 3
    assert current_phase_zero["explicit_non_field_gate_occurrence_count"] == 2_071
    assert current_phase_zero["completion_entrypoint_parameter_count"] == 336
    assert current_phase_zero["cli_run_parameter_count"] == 53
    assert runtime_status["real_model_calls"] == {
        "attempted": None,
        "succeeded": None,
        "rejected": None,
        "current_aggregate_counts_reported": False,
    }
    assert runtime_status["historical_real_model_calls_through_r9"] == {
        "attempted": 20,
        "succeeded": 2,
        "rejected": 18,
        "is_current_aggregate": False,
    }
    assert runtime_status["openrouter_budget_usd"] == {
        "projection_scope": "LAST_RECONCILED_OPERATOR_RECORD_NOT_CURRENT_USER_OWNED_WORKTREE_STATE",
        "used_value_provenance": (
            "LAST_RECONCILED_OPERATOR_RESULTS_"
            "4616c5a143db158f3af12d0a4d58306e0da6ca9dd4bbb54e6c7484dfc2de0251"
        ),
        "used_value_operator_reported": True,
        "independently_authenticated_by_codex": False,
        "codex_private_ledger_accessed": False,
        "cap": "250.00000000",
        "used": "0.396223",
        "reserved": None,
        "remaining": None,
        "last_reconciled_reserved_and_remaining_reported": False,
        "is_authority": False,
    }
    assert runtime_status["historical_governed_ledger_evidence"] == {
        "entry_count": 11,
        "used_usd": "0.0034764325",
        "reserved_usd": "0.00000000",
        "remaining_usd": "249.9965235675",
        "is_current_live_campaign_ledger": False,
    }
    assert "live_authrunner_campaign_ledger" not in runtime_status
    assert runtime_status["last_reconciled_authrunner_campaign_ledger"] == {
        "projection_scope": "LAST_RECONCILED_OPERATOR_RECORD_NOT_CURRENT_USER_OWNED_WORKTREE_STATE",
        "projection_provenance": (
            "LAST_RECONCILED_OPERATOR_RESULTS_"
            "4616c5a143db158f3af12d0a4d58306e0da6ca9dd4bbb54e6c7484dfc2de0251"
        ),
        "operator_reported": True,
        "independently_authenticated_by_codex": False,
        "codex_private_ledger_accessed": False,
        "entry_count": 25,
        "used_usd": "0.396223",
        "reserved_usd": None,
        "remaining_usd": None,
        "terminal_entry_count": None,
        "last_reconciled_reserved_remaining_and_terminal_count_reported": False,
        "reported_occupied_run_indexes": [
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            18,
            19,
        ],
        "next_unused_run_index": None,
        "next_unused_run_index_stated": False,
        "entry_statuses": {
            "smoke_r1": "reconciled",
            "smoke_r2": "uncertain_accounted",
            "smoke_r3": "reconciled",
            "smoke_r4": "reconciled",
            "smoke_r5": "reconciled",
            "smoke_r6": "reconciled",
            "smoke_r7": "reconciled",
            "smoke_r8": "reconciled",
            "smoke_r9": "reconciled",
            "smoke_r10": "reconciled",
            "smoke_r11": "reconciled",
            "smoke_r12": "reconciled",
            "smoke_r13": "reconciled",
            "smoke_r14": "charged_terminal_status_not_stated",
            "smoke_r15": "charged_terminal_status_not_stated",
            "smoke_r16": "charged_terminal_status_not_stated",
            "smoke_r17": "operator_timeout_one_uncertain_accounted_judge_entry",
            "smoke_r18": "schema_validation_failed_candidate",
            "smoke_r19": "complete_noncrediting_nonauthorizing_closed_four_entry_run",
        },
        "smoke_r1_actual_cost_usd": "0.01680888",
        "smoke_r1_accounted_cost_usd": "0.01680888",
        "smoke_r2_actual_cost_usd": None,
        "smoke_r2_accounted_cost_usd": "0.05225616",
        "smoke_r3_actual_cost_usd": "0.00554796",
        "smoke_r3_accounted_cost_usd": "0.00554796",
        "smoke_r4_actual_cost_usd": "0.00537768",
        "smoke_r4_accounted_cost_usd": "0.00537768",
        "smoke_r5_r6_r7_r8_r9_per_index_cost_mapping_available": False,
        "smoke_r5_through_r9_all_reconciled": True,
        "smoke_r10_r11_r12_r13_per_index_cost_mapping_available": False,
        "smoke_r10_through_r13_all_reconciled": True,
        "smoke_r14_actual_cost_usd": "0.004044",
        "smoke_r15_actual_cost_usd": "0.008478",
        "smoke_r16_actual_cost_usd": "0.006281",
        "smoke_r14_r15_terminal_statuses_stated": False,
        "smoke_r16_terminal_status_stated": False,
        "smoke_r19_bundle_sha256": (
            "e7537a2fc5aed79d274101364442faf0e515dd5879cfd8f6670784fcc2595703"
        ),
        "smoke_r19_bundle_bytes": 282_802,
        "smoke_r19_closed_run_ledger_entry_count": 4,
        "smoke_r19_closed_run_ledger_final_spent_usd": "0.39622262",
        "smoke_r19_canonical_replay_status": (
            "VALID_NONCREDITING_NONAUTHORIZING_OPERATOR_REPORTED_AT_C627F2D"
        ),
        "smoke_r2_releasable_or_reusable": False,
        "every_terminal_entry_releasable_or_reusable": False,
        "is_authority": False,
    }
    preflight_status = runtime_status["historical_authrunner_provider_free_r2_r5_r2_preflight"]
    assert preflight_status["status"] == (
        "VALID_NONAUTHORIZING_NO_PROVIDER_EGRESS_HISTORICAL_R2_R5_R2"
    )
    assert preflight_status["scope"] == "HISTORICAL_R2_R5_R2_AFTER_A1ACE778_DO_NOT_RERUN"
    smoke_status = runtime_status["authrunner_noncrediting_smoke"]
    exact_status = runtime_status["authrunner_exact_cost_admission"]
    assert exact_status["historical_committed_byte_preflight_scope"] == (
        "HISTORICAL_F6ACF206_AND_FD1459B_MECHANISM_EVENTS_NOT_CURRENT_7EF4717_"
        "PREFLIGHT_ROUTE_COMMAND_OR_AUTHORITY"
    )
    assert (
        exact_status["historical_failed_committed_byte_preflight"]["operator_results_sha256"]
        == "3c8fc79c24615fae4f80dbbed6c86a9ddbb4b61cd0b1441ac83d2b020a1b60fd"
    )
    assert (
        exact_status["historical_post_cache_fix_committed_byte_preflight"][
            "operator_results_sha256"
        ]
        == "3af4473feac473c3ef5b7ecd553ed67dc141d6f174647e29bd2c1dc485bc609e"
    )
    assert exact_status["historical_exact_cost_base_checkpoint_commit"] == (
        "f6acf206f2c55eeb57b1a11fcf58cc4694a41208"
    )
    assert exact_status["historical_cache_dominance_fix_checkpoint_commit"] == (
        "fd1459b519ea0ce28a2d123ddeb57653dd2f7918"
    )
    assert exact_status["historical_post_cache_fix_committed_byte_preflight_status"] == (
        "FAILED_SAFE_REASONING_CAPABILITY_AFTER_CACHE_GATE_CLEARED"
    )
    assert exact_status["historical_post_origin_fix_provider_free_smoke_preflight_status"] == (
        "VALID_NONCREDITING_NONAUTHORIZING_NO_PROVIDER_EGRESS_POST_TOKEN_BUDGET_FIX"
    )
    for former_unscoped_preflight_key in (
        "failed_committed_byte_preflight",
        "post_cache_fix_committed_byte_preflight",
        "base_checkpoint_status",
        "base_checkpoint_commit",
        "base_checkpoint_subject",
        "cache_dominance_fix_checkpoint_status",
        "cache_dominance_fix_checkpoint_commit",
        "cache_dominance_fix_checkpoint_subject",
        "post_fix_committed_byte_preflight_status",
        "origin_custody_fix_checkpoint_status",
        "origin_custody_fix_checkpoint_commit",
        "origin_custody_fix_checkpoint_subject",
        "post_origin_fix_provider_free_smoke_preflight_status",
    ):
        assert former_unscoped_preflight_key not in exact_status
    local_contract = preflight_status["local_preflight_contract"]
    lineage_r2_command = (
        ".venv/bin/python scripts/capture_public_model_lineage.py --output-dir "
        "/private/tmp/mmaudit-public-lineage-20260821-r2"
    )
    tencent_r5_command = (
        'MMAUDIT_SECRETS_ENV_FILE="$HOME/.mmaudit/secrets.env" MMAUDIT_BUDGET_USD=250 '
        'MMAUDIT_COST_LEDGER_PATH="$HOME/.mmaudit/private/openrouter-cost-ledger.json" '
        ".venv/bin/mmaudit models discover --candidate tencent/hy3=tencent/fp8 "
        "--config config/openrouter-qualification.toml --secrets-env-file "
        '"$HOME/.mmaudit/secrets.env" --output-dir '
        '"$HOME/.mmaudit/private/model-discovery/authrunner-primary-judge-20260821-r5" '
        "--candidate-selection-plan config/models.selection-plan.json "
        "--candidate-selection-ranking-source "
        "/Users/generalcuster/Documents/dev/CODEX_HANDOFF_v3-unblock-2026-08-17/"
        "model-ranking.py --candidate-selection-lineage-review-source "
        "/Users/generalcuster/Documents/dev/CODEX_HANDOFF_v3-unblock-2026-08-17/"
        "V3-LINEAGE-001-operator-review.md --candidate-registry-output "
        '"$HOME/.mmaudit/private/authrunner/primary-judge-registry-r5.json" --no-color'
    )
    smoke_real_command = (
        "env -u OPENROUTER_API_KEY -u MMAUDIT_SECRETS_ENV_FILE MMAUDIT_BUDGET_USD=250 "
        'MMAUDIT_COST_LEDGER_PATH="$HOME/.mmaudit/private/openrouter-cost-ledger.json" '
        ".venv/bin/mmaudit models authenticated-runner-smoke --candidate-registry "
        '"$HOME/.mmaudit/private/authrunner/candidate-registry-r6.json" '
        '--candidate-discovery-run "$HOME/.mmaudit/private/model-discovery/'
        'authrunner-candidate-20260821-r6" --primary-judge-registry '
        '"$HOME/.mmaudit/private/authrunner/primary-judge-registry-r6.json" '
        '--primary-judge-discovery-run "$HOME/.mmaudit/private/model-discovery/'
        'authrunner-primary-judge-20260821-r6" --replay-judge-registry '
        '"$HOME/.mmaudit/private/authrunner/replay-judge-registry-r2.json" '
        '--replay-judge-discovery-run "$HOME/.mmaudit/private/model-discovery/'
        'authrunner-replay-judge-20260820-r2" '
        "--smoke-corpus benchmarks/model_corpus_smoke "
        '--output "$HOME/.mmaudit/private/authrunner/'
        'authenticated-runner-smoke-evidence-20260821-s1.json" '
        "--candidate-cost-cap-usd-per-attempt 1.00 "
        "--primary-judge-cost-cap-usd-per-attempt 1.00 "
        "--replay-judge-cost-cap-usd-per-attempt 1.00 "
        "--config config/openrouter-qualification.toml "
        "--corpus benchmarks/model_corpus/manifest.json "
        '--cost-ledger "$HOME/.mmaudit/private/openrouter-cost-ledger.json" '
        '--secrets-env-file "$HOME/.mmaudit/secrets.env" '
        "--allow-code-egress --no-color"
    )
    smoke_preflight_command = smoke_real_command.replace(
        "--allow-code-egress --no-color",
        "--allow-code-egress --preflight-only --no-color",
    )
    smoke_live_route_command = smoke_real_command.replace(
        "--allow-code-egress --no-color",
        "--allow-metadata-egress --live-route-preflight-only --no-color",
    )
    current_r9_r8_r8_smoke_real_command = (
        "env -u OPENROUTER_API_KEY -u MMAUDIT_SECRETS_ENV_FILE "
        'PYTHONPATH="$PWD/src" MMAUDIT_BUDGET_USD=250 '
        'MMAUDIT_COST_LEDGER_PATH="$HOME/.mmaudit/private/openrouter-cost-ledger.json" '
        "/Users/generalcuster/Documents/dev/Auditor/.venv/bin/mmaudit models "
        "authenticated-runner-smoke --candidate-registry "
        '"$HOME/.mmaudit/private/authrunner/candidate-registry-r9.json" '
        '--candidate-discovery-run "$HOME/.mmaudit/private/model-discovery/'
        'authrunner-candidate-20260822-r9" --primary-judge-registry '
        '"$HOME/.mmaudit/private/authrunner/primary-judge-registry-r8.json" '
        '--primary-judge-discovery-run "$HOME/.mmaudit/private/model-discovery/'
        'authrunner-primary-judge-20260821-r8" --replay-judge-registry '
        '"$HOME/.mmaudit/private/authrunner/replay-judge-registry-r8.json" '
        '--replay-judge-discovery-run "$HOME/.mmaudit/private/model-discovery/'
        'authrunner-replay-judge-20260822-r8" '
        "--smoke-corpus benchmarks/model_corpus_smoke "
        "--smoke-run-index 2 "
        '--output "$HOME/.mmaudit/private/authrunner/'
        'authenticated-runner-smoke-evidence-20260822-s3.json" '
        "--candidate-cost-cap-usd-per-attempt 1.00 "
        "--primary-judge-cost-cap-usd-per-attempt 1.00 "
        "--replay-judge-cost-cap-usd-per-attempt 1.00 "
        "--config config/openrouter-qualification.toml "
        "--corpus benchmarks/model_corpus/manifest.json "
        '--cost-ledger "$HOME/.mmaudit/private/openrouter-cost-ledger.json" '
        '--secrets-env-file "$HOME/.mmaudit/secrets.env" '
        "--allow-code-egress --no-color"
    )
    current_r9_r8_r8_smoke_live_route_command = current_r9_r8_r8_smoke_real_command.replace(
        "--allow-code-egress --no-color",
        "--allow-metadata-egress --live-route-preflight-only --no-color",
    )
    smoke_verify_command = (
        "env -u OPENROUTER_API_KEY -u MMAUDIT_SECRETS_ENV_FILE MMAUDIT_BUDGET_USD=250 "
        'MMAUDIT_COST_LEDGER_PATH="$HOME/.mmaudit/private/openrouter-cost-ledger.json" '
        ".venv/bin/mmaudit models verify-authenticated-runner-smoke --bundle "
        '"$HOME/.mmaudit/private/authrunner/'
        'authenticated-runner-smoke-evidence-20260821-s1.json" '
        "--smoke-corpus benchmarks/model_corpus_smoke "
        "--corpus benchmarks/model_corpus/manifest.json "
        "--config config/openrouter-qualification.toml --no-color"
    )
    smoke_file_sha256s = {
        "manifest.json": "aa453f655a4d09adf19498387c9cd2b48939119f1494e9517182dbb2b3ee685c",
        "ground_truth.json": "e5e2baef1b986c77ae448fad1eb96052f061a8db1daae1b6f4122f61cbce8765",
        "provenance.json": "d3f9e13733949f660ae4f3eeac8c3576a8b8b620e37adb4f1fc268e45163d46c",
        "verdict_policy.json": "79b1aee6b28fc90f64887fff189b9f404114bd7671a7363bdb437e19d258d68f",
    }
    assert "docs/remediation/v3/operator_results.md" in agents
    assert "Before ending any turn" in agents
    assert "issued, reissued, or depended on an operator command" in agents
    assert "read `docs/remediation/v3/operator_results.md`" in agents
    assert "reconcile its latest result" in agents
    assert "../remediation/v3/operator_results.md" in model_selection
    assert (
        hashlib.sha256(operator_result_bytes).hexdigest()
        == PLANCONSTRAINTS_PARENT_OPERATOR_RESULTS_SHA256
    )
    assert PLANCONSTRAINTS_PARENT_OPERATOR_RESULTS_SHA256 != LAST_RECONCILED_OPERATOR_RESULTS_SHA256
    assert HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT in normalized_model_selection
    assert (
        "activates receipt preparation, dispatch, all-or-none completion-plus-metadata composition"
        in normalized_model_selection
    )
    assert "`INCOMPLETE`, not a pass" in normalized_model_selection
    assert AUTHRUNNER_RECEIPT_COMPOSITE_PARENT_CHECKPOINT in normalized_model_selection
    assert "fails on untouched parent" in normalized_model_selection
    assert "closure-owned live authority-registry dicts or cells" in normalized_model_selection
    assert "coordinated mutation of the outermost checker" in normalized_model_selection
    assert "tracing, profiling, native-memory, or equivalent runtime compromise" in (
        normalized_model_selection
    )
    assert "provider transport receipt cannot seal owned request state" in (
        normalized_model_selection
    )
    assert "positively traverses the repaired receipt-seal boundary" in normalized_model_selection
    assert (
        "`usage_diagnostics=STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS`"
        in normalized_model_selection
    )
    assert "25-entry global ledger totaling `$0.396223`" in normalized_model_selection
    assert "next unused index is not stated" in normalized_model_selection
    assert "explicitly retracts its prior requested-mode hypothesis" in normalized_model_selection
    assert "accounting and canonical-replay boundary" in model_selection
    assert "The current r6/r6/r2 input composition" not in model_selection
    assert "not a current plan, command, or reusable output target" in normalized_model_selection
    assert "same bundle bytes offline" in normalized_model_selection
    assert "without another provider run or new spend" in normalized_model_selection
    assert "operator-supplied verification" in normalized_model_selection
    assert "not independent private-artifact authentication by Codex" in (
        normalized_model_selection
    )
    assert "No AUTHRUNNER command is current" in normalized_model_selection
    for worklog_path in (CODEX_WORKLOG_PATH, ROOT / "docs/remediation/v3/worklog.md"):
        worklog = " ".join(worklog_path.read_text(encoding="utf-8").split())
        assert "boundary-local historical snapshot" in worklog
        assert "not present authority or current action" in worklog
        assert "No next unused index is stated; no current command exists." in worklog
        assert "No next unused index or current command exists." not in worklog
    assert HISTORICAL_PAID_DIAGNOSTIC_OPERATOR_RESULTS_SHA256 in model_selection
    assert all(HISTORICAL_PAID_DIAGNOSTIC_OPERATOR_RESULTS_SHA256 in queue for queue in queues)
    assert all(
        f"Historical selection-plan checkpoint `{HISTORICAL_DCABE_SELECTION_CHECKPOINT}`" in queue
        for queue in normalized_queues
    )
    assert all(PLANCONSTRAINTS_REPAIR_CHECKPOINT in queue for queue in normalized_queues)
    assert all(
        f"Current selection-plan checkpoint `{HISTORICAL_DCABE_SELECTION_CHECKPOINT}`" not in queue
        for queue in normalized_queues
    )
    assert all("Historical exact-cost admission slice 2026-08-21" in queue for queue in queues)
    assert all("Exact-cost admission WIP 2026-08-21" not in queue for queue in queues)
    assert all(
        "Last reconciled operator-reported offline result / limitation" in queue for queue in queues
    )
    assert all(
        "Current operator-reported offline result / limitation" not in queue for queue in queues
    )
    assert all("Current live result / limitation" not in queue for queue in queues)
    assert all("independently verifies the same 282,802-byte" not in queue for queue in queues)
    assert all("No post-`c627f2d` provider call" in queue for queue in normalized_queues)
    assert all("The current 29,375-byte operator-supplied log" not in queue for queue in queues)
    assert all("The then-current 29,375-byte operator-supplied log" in queue for queue in queues)
    assert all("independently confirms the source mismatch" not in queue for queue in queues)
    assert all("The current 44,808-byte" not in queue for queue in queues)
    assert all("The current 50,211-byte" not in queue for queue in queues)
    assert "The current 57,621-byte canonical manifest" not in model_selection
    for filename, expected_sha256 in smoke_file_sha256s.items():
        artifact_bytes = (ROOT / "benchmarks/model_corpus_smoke" / filename).read_bytes()
        assert hashlib.sha256(artifact_bytes).hexdigest() == expected_sha256
        assert expected_sha256 in model_selection
    assert "721f058726cf9509c07cb2aae662fb6ac23b5c30a363db40229faf8895034497" in (model_selection)
    assert selection_plan["plan_sha256"] == CURRENT_NONAUTHORIZING_SUCCESSOR_PLAN_SHA256
    assert selection_plan["plan_sha256"] in model_selection
    assert selection_plan["schema_version"] == "1.4"
    assert selection_plan["authenticated_runner_selection"]["required_reasoning_effort"] == "high"
    assert (
        selection_plan["authenticated_runner_selection"]["required_completion_limit_source"]
        == "metadata"
    )
    assert '`effort = "high"`' in model_selection
    assert "4,096-token atomic reasoning reserve" in normalized_model_selection
    assert "falls back to the exact frozen model-catalog inventory only when" in (
        normalized_model_selection
    )
    assert "MiniMax M3" in model_selection
    assert "It is no longer selected." in model_selection
    assert model_selection.count(lineage_r2_command) == 1
    assert model_selection.count(tencent_r5_command) == 1
    assert "historical command records and must not be rerun" in normalized_model_selection
    assert "9075ca7635c861194cc732e67d9ebb92e6ffa0af" in model_selection
    assert smoke_live_route_command not in model_selection
    assert smoke_real_command not in model_selection
    assert (
        smoke_live_route_command.replace(
            "--allow-metadata-egress --live-route-preflight-only --no-color",
            "--allow-code-egress --no-color",
        )
        == smoke_real_command
    )
    assert smoke_preflight_command not in model_selection
    assert smoke_verify_command not in model_selection
    assert current_r9_r8_r8_smoke_live_route_command not in model_selection
    assert current_r9_r8_r8_smoke_real_command not in model_selection
    assert (
        current_r9_r8_r8_smoke_live_route_command.replace(
            "--allow-metadata-egress --live-route-preflight-only --no-color",
            "--allow-code-egress --no-color",
        )
        == current_r9_r8_r8_smoke_real_command
    )
    assert model_selection.count(".venv/bin/mmaudit models authenticated-runner-smoke") == 0
    assert ".venv/bin/mmaudit models verify-authenticated-runner-smoke" not in model_selection
    assert ".venv/bin/mmaudit models authenticated-runner --" not in model_selection
    assert model_selection.count("--live-route-preflight-only") == 2
    assert model_selection.count("--allow-metadata-egress") == 0
    assert model_selection.count("--allow-code-egress") == 0
    assert " --preflight-only " not in model_selection
    assert "authrunner-candidate-20260822-r9" in model_selection
    assert "primary-judge-registry-r14.json" in model_selection
    assert "replay r8" in model_selection
    assert model_selection.count("--smoke-run-index 2") == 0
    assert AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_CHECKPOINT in model_selection
    assert "385-test implementer matrix" in normalized_model_selection
    assert "independent 363-test review" in normalized_model_selection
    assert 'PYTHONPATH="$PWD/src"' not in model_selection
    assert "no current command or campaign authority exists" in normalized_model_selection
    assert "`V3-AUTONOMY-001` Phase 2 remains paused" in model_selection
    assert "PENDING_TENCENT_LINEAGE_RESEAL_CHECKPOINT" not in model_selection
    assert "a1ace778afcf308b57fe436271cdc16a2bb8e156" in model_selection
    assert "af70559ddaf84178efffee1ec1bf7b99bf0b12df" in model_selection
    assert "Add noncrediting provider smoke path" in normalized_model_selection
    assert "7e9db03145b4afc1834dd47e9f4f97800e1edffb" in model_selection
    assert "Fix smoke null lineage projection" in normalized_model_selection
    assert "f0a0f39ee275bc774709bd0fbff411cfa7ecac04" in model_selection
    assert "Document provider-free smoke preflight" in normalized_model_selection
    assert "provider-free r2/r5/r2 preflight" in normalized_model_selection
    assert "has now completed and is historical; do not rerun it" in (normalized_model_selection)
    assert "Post-origin fixes, failed one-case REAL attempt, and token-budget parity repair" in (
        model_selection
    )
    assert "smoke public lineage returned a non-independent projection" in (
        normalized_model_selection
    )
    assert "root_lineage = None" in model_selection
    assert "The operator ran it verbatim. It is now historical and must not be rerun." in (
        normalized_model_selection
    )
    assert "f5afb2bff074254ee5c4a484386ee4c416b17a88" in model_selection
    assert "historical and unsafe to execute" in normalized_model_selection
    assert "accepted only `RELEASE_PINNED_MODEL_BENCHMARK`" in normalized_model_selection
    assert "`RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION`" in model_selection
    assert "`PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK`" in model_selection
    assert "`PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION`" in model_selection
    assert "after a provider response had been charged and bound" in normalized_model_selection
    assert "REAL bound usage lacks AUTHRUNNER transport-origin custody" in (
        normalized_model_selection
    )
    assert "first paid candidate completion could therefore have spent money and then failed" in (
        normalized_model_selection
    )
    assert "Provider-free preflight cannot exercise that post-response issuer boundary" in (
        normalized_model_selection
    )
    assert "both the paid smoke and its conditional offline verifier were withdrawn" in (
        normalized_model_selection
    )
    assert "request and atomic global input token budgets differ" in normalized_model_selection
    assert "no bundle was published" in normalized_model_selection
    assert "no paid smoke attempt, provider completion, or spend occurred" in (
        normalized_model_selection
    )
    assert "only for a `PENDING` review with a null registry root" in (normalized_model_selection)
    assert "33 focused and 81 bounded smoke/neighbor tests" in normalized_model_selection
    assert "ca63b924f244cc9bcee2d2405d20b000ce0bb9d6" in model_selection
    assert "c9a8923064ef1bb606a67b14641c4c8df55bc9ea" in model_selection
    assert "Bind smoke REAL origin custody" in normalized_model_selection
    assert "four closed proof kinds to its disjoint request namespace" in normalized_model_selection
    assert "release candidate and cross-lineage requests retain only" in normalized_model_selection
    assert "smoke candidate and judge namespaces admit only" in normalized_model_selection
    assert (
        "Missing, malformed, cross-kind, release-to-smoke, smoke-to-release, and forged namespace "
        "mappings reject." in normalized_model_selection
    )
    assert "admitting a smoke proof kind grants no release" in normalized_model_selection
    assert "Implementer validation passed 584 provider-free tests" in normalized_model_selection
    assert "Independent validation passed 371 usage/OpenRouter tests" in normalized_model_selection
    assert "83 runner/smoke/cross-lineage tests" in normalized_model_selection
    assert "123 generation/candidate tests" in normalized_model_selection
    assert "577 broad tests total" in normalized_model_selection
    assert (
        "final focused checks passed 22 usage-scope and three OpenRouter transport-path tests"
        in (normalized_model_selection)
    )
    assert "red-team verdict was clean with no blocker/HIGH" in normalized_model_selection
    assert "repository-wide Ruff passed" in normalized_model_selection
    assert "full 206-source tree" in normalized_model_selection
    assert "whole-repository format check is intentionally not credited" in (
        normalized_model_selection
    )
    assert "59f9f40a97dce41a16fb3ab9243b4d8588bcf3cb" in model_selection
    assert "Bind AUTHRUNNER token budgets" in normalized_model_selection
    assert "136-test five-file AUTHRUNNER matrix" in normalized_model_selection
    assert "Independent paid-readiness review" in normalized_model_selection
    assert "no blocker/HIGH" in normalized_model_selection
    assert "blocking lifecycle gap" in normalized_model_selection
    assert "retained candidate-campaign" in normalized_model_selection
    assert "Negative downstream consumer tests cover" in normalized_model_selection
    assert "every previously emitted AUTHRUNNER command was withdrawn" in (
        normalized_model_selection
    )
    assert "no runnable metadata, discovery, smoke, verifier" in (normalized_model_selection)
    assert "9f5c94d97b3d79d51c10e250b99244591461e959" in model_selection
    assert "3bcac02da30bdad2c7e584d35c091ea5cb75ea7d" in model_selection
    assert "Its first candidate completion reached the real transport" in normalized_model_selection
    assert "SCHEMA_VALIDATION_FAILED" in model_selection
    assert "$0.0547272` was reserved" in model_selection
    assert "$0.01680888` was charged and reconciled" in model_selection
    assert "provider-free `REVOCATION_CASCADE_FIX` is complete and clean" in (
        normalized_model_selection
    )
    assert "692eb173f002818b4434b746c8801b4cbeb852e2" in model_selection
    assert "exact PID-bound campaign and generation revokers" in normalized_model_selection
    assert "parent-to-child cascade" in normalized_model_selection
    assert "traceback-safe execution handoff guards" in normalized_model_selection
    assert "candidate and judge generation-capability revocation" in normalized_model_selection
    assert "229 focused and 266 adjacent tests" in normalized_model_selection
    assert "format over 510 tracked Python files" in normalized_model_selection
    assert "strict mypy over 206 source files" in normalized_model_selection
    assert "independent review reported `CLEAN` with no blocker/HIGH" in model_selection
    assert "no genuine owned-REAL parent capability" in normalized_model_selection
    assert "`NATIVE_JSON_SCHEMA` plus literal `structured_outputs`" in model_selection
    assert "self-hashed selection plan" in normalized_model_selection
    assert selection_plan["authenticated_runner_selection"]["role_assignment_sha256"] in (
        model_selection
    )
    assert "`max_json_repair_attempts = 0` is deliberate" in model_selection
    assert "noncreditable" in normalized_model_selection
    assert "route capability—not repair—is the correction" in normalized_model_selection
    assert "current r2/r5/r2 input composition" not in normalized_model_selection
    assert "candidate-registry-r6.json" in model_selection
    assert "authrunner-candidate-20260821-r6" in model_selection
    assert "primary-judge-registry-r6.json" in model_selection
    assert "authrunner-primary-judge-20260821-r6" in model_selection
    historical_runtime_status = json.loads(
        subprocess.run(
            [
                "git",
                "show",
                f"{HISTORICAL_TRUNCATION_RECURSIVE_PARENT_CHECKPOINT}:"
                "docs/remediation/v3/runtime_status.json",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout
    )
    historical_autonomy_inventory_bytes = subprocess.run(
        [
            "git",
            "show",
            f"{HISTORICAL_TRUNCATION_RECURSIVE_PARENT_CHECKPOINT}:"
            "docs/remediation/v3/autonomy_gate_inventory.json",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    historical_autonomy_inventory = json.loads(historical_autonomy_inventory_bytes)
    historical_autonomy_inventory_raw_sha256 = (
        "82274345013e650e2bb94cced64f951d64c91ace389ac190b16c34555e681dc2"
    )
    historical_autonomy_inventory_sha256 = (
        "349af767d9e07bb44a7483a5ab3e309ee7d8f739d49902f5143508901d79f90e"
    )
    historical_autonomy_source_universe_sha256 = (
        "c0d55db7f01762a1f014290af40544fc1a20842a8bbff72e053b379792d17fa5"
    )
    historical_autonomy_discovery_semantics_sha256 = (
        "4f1adb9e0bc8db7899fa4eb2928ee03f87d4d61d4113a0555fcdae750e260042"
    )

    # Assertions below this boundary preserve the exact historical specialist checkpoint.
    runtime_status = historical_runtime_status
    autonomy_inventory_bytes = historical_autonomy_inventory_bytes
    autonomy_inventory = historical_autonomy_inventory
    assert runtime_status["updated_at"] == "2026-08-24T14:43:31Z"
    assert runtime_status["candidate_commit"] == CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT
    assert (
        runtime_status["candidate_commit_parent"] == CURRENT_TRUNCATION_SPECIALIST_PARENT_CHECKPOINT
    )
    assert runtime_status["candidate_commit_pushed"] is False
    assert runtime_status["candidate_commit_remote_resolved"] is False
    assert runtime_status["candidate_successor_commit"] == CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT
    assert runtime_status["candidate_successor_status"] == (
        "LOCAL_COMMIT_NOT_PUSHED_OR_REMOTE_RESOLVED"
    )
    assert (
        "Exact 16-path provider-free V3-TRUNCATION-001 specialist-role recovery slice"
        in runtime_status["candidate_commit_scope"]
    )
    assert (
        "private successful specialist recovery children"
        in runtime_status["candidate_commit_scope"]
    )
    assert "public v1.1 evidence" in runtime_status["candidate_commit_scope"]
    assert "live REAL promotion" in runtime_status["candidate_commit_scope"]
    assert "byte-stable zero-transport resume" in runtime_status["candidate_commit_scope"]
    assert "recursive recovery-child consumption" in runtime_status["candidate_commit_scope"]
    assert "operator_results" in runtime_status["candidate_commit_scope"]
    assert "operator action are excluded" in runtime_status["candidate_commit_scope"]
    assert (
        "conditionally preauthorized" not in runtime_status["blocked_tickets"]["V3-AUTHRUNNER-001"]
    )
    assert runtime_status["historical_paid_diagnostic_base_commit"] == (
        HISTORICAL_PAID_DIAGNOSTIC_BASE_CHECKPOINT
    )
    assert runtime_status["last_checkpoint_commit"] == CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT
    assert "exact 16-path" in runtime_status["last_checkpoint_commit_scope"]
    assert (
        "V3_TRUNCATION_001_SPECIALIST_ROLE_RECOVERY_SLICE_COMPLETE_TICKET_PARTIAL_"
        "PROVIDER_FREE_NONAUTHORIZING" in runtime_status["last_checkpoint_commit_scope"]
    )
    assert (
        CURRENT_TRUNCATION_SPECIALIST_PARENT_CHECKPOINT
        in runtime_status["last_checkpoint_commit_scope"]
    )
    assert (
        "private v1.2 successful specialist children"
        in runtime_status["last_checkpoint_commit_scope"]
    )
    assert (
        "public v1.1 evidence exposes only the outcome hash"
        in runtime_status["last_checkpoint_commit_scope"]
    )
    assert "recursive child consumption" in runtime_status["last_checkpoint_commit_scope"]
    assert "425502c PLANCONSTRAINTS repair" in runtime_status["last_checkpoint_commit_scope"]
    assert "operator_results" in runtime_status["last_checkpoint_commit_scope"]
    assert "provider/network execution" in runtime_status["last_checkpoint_commit_scope"]
    assert "operator action are excluded" in runtime_status["last_checkpoint_commit_scope"]
    planconstraints_status = runtime_status["planconstraints_provider_free_route_admission"]
    assert planconstraints_status == {
        "ticket": "V3-PLANCONSTRAINTS-001",
        "status": "HISTORICAL_COMPLETE_PROVIDER_FREE_NONAUTHORIZING_REGRESSION_REPAIRED",
        "source_checkpoint_commit": PLANCONSTRAINTS_REPAIR_CHECKPOINT,
        "source_checkpoint_parent": PLANCONSTRAINTS_REPAIR_PARENT_CHECKPOINT,
        "source_checkpoint_subject": "Restore selected endpoint name parity",
        "source_checkpoint_exact_path_count": 5,
        "historical_base_source_checkpoint_commit": HISTORICAL_PLANCONSTRAINTS_BASE_CHECKPOINT,
        "historical_base_source_checkpoint_parent": (
            HISTORICAL_PLANCONSTRAINTS_BASE_PARENT_CHECKPOINT
        ),
        "historical_base_source_checkpoint_exact_path_count": 33,
        "source_checkpoint_pushed": False,
        "source_checkpoint_remote_resolved": False,
        "selection_plan_schema_version": "1.4",
        "selection_plan_raw_sha256": hashlib.sha256(SELECTION_PLAN_PATH.read_bytes()).hexdigest(),
        "selection_plan_sha256": CURRENT_NONAUTHORIZING_SUCCESSOR_PLAN_SHA256,
        "candidate_selection_plan_schema_raw_sha256": (
            "d271ed3ce6ccde084653b9daaf4d56e5573c6f64a7a62f9bf198ce9cdf16b3b5"
        ),
        "authenticated_runner_smoke_evidence_bundle_schema_raw_sha256": (
            "34f264a5fa9ae55ba6d0c02d2e1f78c81aa4abf2c19ab50b6366c2c4d6e75404"
        ),
        "shared_route_constraint_profile_count": 1,
        "shared_route_constraint_predicate_count": 29,
        "shared_route_constraint_profile_sha256": (
            "00b33f3eff0ee7ac7710253c34786ce0a041ffe881baa4015dce0ed4f4b7ce82"
        ),
        "selected_provider_display_name_uniqueness_retained": True,
        "unrelated_provider_display_name_duplicates_allowed": True,
        "complete_provider_identity_inventory_retained": True,
        "display_name_casefolding_retained": True,
        "selection_discovery_registry_candidate_judge_and_runtime_parity_bound": True,
        "runtime_required_output_tokens_bound_to_serialized_max_tokens": True,
        "full_admission_status": "BLOCKED_FAIL_CLOSED_TYPED_UNAVAILABLE_EVIDENCE",
        "typed_unavailable_requirements": [
            "EMPIRICAL_SCHEMA_VALIDATION",
            "RUNTIME_TOKEN_DETAIL_CONVENTION",
        ],
        "adjacent_runner_matrix_tests_passed": 921,
        "focused_route_snapshot_discovery_admission_tests_passed_overlapping": 250,
        "canonical_inventory_tests_passed": 32,
        "ruff_check": "PASS",
        "ruff_format_check": "PASS_FOCUSED_FILES_ALREADY_FORMATTED",
        "strict_mypy_source_files": 1,
        "strict_mypy": "PASS",
        "canonical_generator_write_and_verify": "PASS",
        "pip_check": "PASS_NO_BROKEN_REQUIREMENTS",
        "diff_integrity": "PASS",
        "historical_7ef_independent_mutation_probe_count": 1012,
        "historical_7ef_independent_import_order_count": 6,
        "independent_review": "PASS_NO_BLOCKER_OR_HIGH",
        "provider_or_network_accessed": False,
        "secret_material_read": False,
        "operator_private_ledger_accessed_or_mutated": False,
        "campaign_or_operator_action_executed": False,
        "runtime_authority": False,
        "historical_repository_full_suite_status": "INCOMPLETE_NO_PASS_CREDIT",
        "historical_repository_full_suite_passed": 1492,
        "historical_repository_full_suite_skipped": 25,
        "historical_repository_full_suite_failed": 1,
    }
    assert runtime_status["truncation_provider_free_recovery"] == {
        "ticket": "V3-TRUNCATION-001",
        "status": "PARTIAL_SPECIALIST_ROLE_RECOVERY_SLICE_COMPLETE_PROVIDER_FREE_NONAUTHORIZING",
        "source_checkpoint_commit": CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT,
        "source_checkpoint_parent": CURRENT_TRUNCATION_SPECIALIST_PARENT_CHECKPOINT,
        "source_checkpoint_subject": "Add specialist truncation recovery custody",
        "source_checkpoint_exact_path_count": 16,
        "prior_retained_parent_recovery_checkpoint": PLANCONSTRAINTS_REPAIR_PARENT_CHECKPOINT,
        "historical_planconstraints_repair_checkpoint": PLANCONSTRAINTS_REPAIR_CHECKPOINT,
        "historical_planconstraints_base_checkpoint": HISTORICAL_PLANCONSTRAINTS_BASE_CHECKPOINT,
        "historical_authrunner_replay_checkpoint": HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT,
        "private_successful_child_schema_version": "1.2",
        "private_specialist_accepted_outcome_required_for_exact_specialist_child": True,
        "private_specialist_accepted_outcome_sha256_bound": True,
        "public_recovery_request_evidence_schema_version": "1.1",
        "public_specialist_outcome_projection": "SHA256_ONLY",
        "public_specialist_outcome_body_exposed": False,
        "specialist_credit_requires_live_real_promotion": True,
        "specialist_credit_requires_exact_revalidated_usage": True,
        "selected_parent_remains_truncated": True,
        "serialized_child_is_authority": False,
        "mock_child_is_creditable": False,
        "mock_pipeline_specialist_child_count": 2,
        "mock_pipeline_promotion_count": 0,
        "mock_pipeline_specialist_credit_count": 0,
        "mock_resume_provider_transport_count": 0,
        "mock_resume_journal_byte_stable": True,
        "recursive_child_recovery_complete": False,
        "positive_nonempty_full_pipeline_real_promotion_available": False,
        "final_schema_inventory_specialist_tests_passed": 92,
        "promoted_specialist_assurance_tests_passed": 4,
        "journal_resume_tests_passed": 2,
        "mock_pipeline_integration_tests_passed": 1,
        "earlier_adjacent_tests_passed": 162,
        "ruff_check": "PASS",
        "ruff_format_check": "PASS",
        "strict_mypy": "PASS",
        "canonical_generator_write_and_verify": "PASS",
        "diff_integrity": "PASS",
        "independent_review": "PASS_NO_BLOCKER_OR_HIGH",
        "maximum_assurance_attempt_status": "INCONCLUSIVE_NO_TERMINAL_RESULT_NO_PASS_CREDIT",
        "maximum_assurance_attempt_elapsed_seconds": 602.86,
        "provider_or_network_accessed": False,
        "secret_material_read": False,
        "operator_private_ledger_accessed_or_mutated": False,
        "campaign_or_operator_action_executed": False,
        "runtime_authority": False,
        "next_provider_free_slice": "BOUNDED_RECURSIVE_RECOVERY_CHILD_CONSUMPTION",
    }
    assert runtime_status["autorun_status"] == (
        "V3_TRUNCATION_001_SPECIALIST_RECOVERY_SLICE_COMPLETE_TICKET_PARTIAL_PROVIDER_FREE_"
        "NONAUTHORIZING_NEXT_RECURSIVE_CHILD_RECOVERY_ZERO_CURRENT_EXTERNAL_COMMANDS"
    )
    assert runtime_status["autorun_status_evidence_scope"] == (
        "LOCAL_PROVIDER_FREE_TRUNCATION_SPECIALIST_RECOVERY_CHECKPOINT_721D17A_PLUS_PRIOR_"
        "RETAINED_PARENT_RECOVERY_CHECKPOINT_390E9B2_PLUS_HISTORICAL_PLANCONSTRAINTS_REPAIR_"
        "CHECKPOINT_425502C_AND_BASE_7EF4717_PLUS_HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT_"
        "C627F2D; LAST_RECONCILED_OPERATOR_EVIDENCE_REMAINS_NONAUTHORIZING_AND_NOT_"
        "INDEPENDENTLY_AUTHENTICATED_BY_CODEX; CURRENT_USER_OWNED_OPERATOR_FILE_DRIFTED_AND_"
        "WAS_NOT_OPENED_OR_RECONCILED_FOR_CURRENT_PROVIDER_FREE_SOURCE_TICKET"
    )
    assert (
        runtime_status["autorun_status_operator_evidence_independently_authenticated_by_codex"]
        is False
    )
    assert runtime_status["autorun_status"] != (
        "PAUSED_AFTER_C627F2D_INDEX_19_VALID_NONCREDITING_NONAUTHORIZING_OFFLINE_REPLAY_"
        "ZERO_CURRENT_COMMANDS_NEXT_INDEX_NOT_STATED"
    )
    assert runtime_status["current_ticket"] == "V3-TRUNCATION-001"
    assert runtime_status["last_completed_provider_free_work"] == {
        "ticket": "V3-TRUNCATION-001",
        "slice": "SPECIALIST_ROLE_RECOVERY_COMPLETE_AT_721D17A_WITHIN_PARTIAL_TICKET",
        "status": (
            "PARTIAL_PROVIDER_FREE_NONAUTHORIZING; SPECIALIST_CHILD_PRIVATE_V1_2_AND_PUBLIC_"
            "HASH_ONLY_V1_1_CUSTODY_COMPLETE; CREDIT_REQUIRES_LIVE_REAL_PROMOTION; MOCK_AND_"
            "SERIALIZED_EVIDENCE_NONCREDITING"
        ),
        "next_slice": (
            "IMPLEMENT_BOUNDED_PROVIDER_FREE_RECURSIVE_RECOVERY_CHILD_CONSUMPTION_THEN_RECORD_"
            "BEFORE_POSITIVE_NONEMPTY_FULL_PIPELINE_REAL_PROMOTION"
        ),
        "provider_access_authorized": False,
        "secret_access_authorized": False,
        "private_operator_artifact_access_authorized": False,
        "runtime_authority_granted": False,
        "operator_metadata_egress_command_emitted": False,
        "operator_paid_smoke_command_emitted": False,
        "operator_command_execution_authorized": False,
        "parked_ticket": "V3-AUTONOMY-001",
        "parked_ticket_status": (
            "PARTIAL_PHASE_2_PAUSED_PENDING_SEPARATE_AUTHRUNNER_AUTHORITATIVE_"
            "EVIDENCE_NO_EXTERNAL_SEQUENCE_COMMAND_OR_INDEX_AUTHORIZED"
        ),
        "historical_park_reason": "TIME_SENSITIVE_INDEXED_EXTERNAL_SEQUENCE_ENDED",
    }
    assert runtime_status["prior_provider_free_work"] == {
        "ticket": "V3-TRUNCATION-001",
        "source_checkpoint_commit": PLANCONSTRAINTS_REPAIR_PARENT_CHECKPOINT,
        "source_checkpoint_parent": "b1f8ba9eba7efef94388ab185529f1248fb608c3",
        "source_checkpoint_exact_path_count": 14,
        "completed_slice": "RETAINED_PARENT_SURFACE_RECOVERY",
        "ticket_status": "PARTIAL",
        "specialist_role_recovery_complete": True,
        "specialist_role_recovery_checkpoint": CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT,
        "recursive_child_recovery_complete": False,
        "positive_nonempty_full_pipeline_real_promotion_available": False,
        "provider_or_network_accessed": False,
        "runtime_authority": False,
    }
    phase_zero = runtime_status["autonomy_phase_zero_inventory"]
    assert phase_zero == {
        "status": "COMPLETE_NONAUTHORIZING",
        "implementation_commit": HISTORICAL_PHASE_ZERO_CHECKPOINT,
        "implementation_commit_pushed": False,
        "implementation_commit_remote_resolved": False,
        "current_reconciliation_commit": CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT,
        "current_reconciliation_commit_pushed": False,
        "current_reconciliation_commit_remote_resolved": False,
        "historical_c627_authrunner_entrypoint_successor_path_count": 3,
        "current_reconciliation_exact_path_count": 16,
        "artifact_path": "docs/remediation/v3/autonomy_gate_inventory.json",
        "schema_path": "schemas/autonomy_gate_inventory.schema.json",
        "artifact_reconciled_for_slice": "V3_TRUNCATION_SPECIALIST_ROLE_RECOVERY",
        "artifact_raw_sha256": historical_autonomy_inventory_raw_sha256,
        "schema_raw_sha256": HISTORICAL_COVERAGE_AUTONOMY_INVENTORY_SCHEMA_RAW_SHA256,
        "source_discovery_semantics_sha256": historical_autonomy_discovery_semantics_sha256,
        "source_universe_sha256": historical_autonomy_source_universe_sha256,
        "source_semantics_sha256": None,
        "source_semantics_sha256_reported": False,
        "historical_03d_source_semantics_sha256": (
            "67f1ff32913327913ab19adbe60ff54263bf0fcb347304b151bd009311cfe1b0"
        ),
        "inventory_sha256": historical_autonomy_inventory_sha256,
        "source_count": 3657,
        "source_occurrence_count": 3660,
        "gate_source_count": 3614,
        "non_gating_source_count": 43,
        "source_kind_count": 13,
        "logical_gate_count": 35,
        "unsatisfied_gate_count": 29,
        "current_manual_gate_count": 15,
        "provider_or_network_accessed": False,
        "secret_material_read": False,
        "runtime_authority": False,
        "managed_run_ready": False,
        "historical_structural_successor": "PHASE_2_MANAGED_PROVISIONING_STATE",
        "historical_structural_successor_scope": (
            "COMPONENT_LOCAL_ARCHITECTURAL_SUCCESSOR_NONAUTHORIZING_NOT_CURRENT_"
            "EXECUTION_NEXT_ACTION"
        ),
        "current_execution_status": (
            "TRUNCATION_SPECIALIST_RECOVERY_SLICE_COMPLETE_TICKET_PARTIAL_PROVIDER_FREE_"
            "NONAUTHORIZING; AUTONOMY_PHASE_2_PAUSED; NO_EXTERNAL_SEQUENCE_COMMAND_OR_INDEX"
        ),
        "current_execution_next_action": (
            "IMPLEMENT_PROVIDER_FREE_V3_TRUNCATION_001_RECURSIVE_CHILD_RECOVERY; KEEP_AUTHRUNNER_"
            "PARTIAL_BLOCKED_SAFETY; NO_CURRENT_COMMAND_OR_INDEX_INFERENCE"
        ),
    }
    assert runtime_status["managed_toolchain_phase_one"] == {
        "status": "COMPLETE_NONAUTHORIZING",
        "implementation_commit": PHASE_ONE_IMPLEMENTATION_CHECKPOINT,
        "implementation_commit_pushed": False,
        "implementation_commit_remote_resolved": False,
        "implementation_path_count": 18,
        "implementation_core_path_count": 10,
        "post_checkpoint_governance_successor_path_count": 8,
        "operator_results_in_implementation_checkpoint": False,
        "bundle_path": "src/mmaudit/resources/managed_toolchain_bundle.json",
        "schema_path": "schemas/managed_toolchain_bundle.schema.json",
        "bundle_raw_sha256": MANAGED_TOOLCHAIN_RAW_SHA256,
        "bundle_sha256": MANAGED_TOOLCHAIN_SHA256,
        "schema_raw_sha256": MANAGED_TOOLCHAIN_SCHEMA_RAW_SHA256,
        "first_class_role_count": 28,
        "pinned_role_count": 3,
        "unresolved_role_count": 25,
        "managed_gate_status": "PARTIAL",
        "independently_trusted": False,
        "provisioning_state_verified": False,
        "installed_members_verified": False,
        "transitive_dependency_closure_verified": False,
        "image_side_attestation_verified": False,
        "execution_evidence_verified": False,
        "runtime_authority": False,
        "managed_run_ready": False,
        "provider_or_network_accessed": False,
        "secret_material_read": False,
        "historical_structural_successor": "PHASE_2_MANAGED_PROVISIONING_STATE",
        "historical_structural_successor_scope": (
            "COMPONENT_LOCAL_ARCHITECTURAL_SUCCESSOR_NONAUTHORIZING_NOT_CURRENT_"
            "EXECUTION_NEXT_ACTION"
        ),
        "current_execution_status": (
            "TRUNCATION_SPECIALIST_RECOVERY_SLICE_COMPLETE_TICKET_PARTIAL_PROVIDER_FREE_"
            "NONAUTHORIZING; AUTONOMY_PHASE_2_PAUSED; NO_EXTERNAL_SEQUENCE_COMMAND_OR_INDEX"
        ),
        "current_execution_next_action": (
            "IMPLEMENT_PROVIDER_FREE_V3_TRUNCATION_001_RECURSIVE_CHILD_RECOVERY; KEEP_AUTHRUNNER_"
            "PARTIAL_BLOCKED_SAFETY; NO_CURRENT_COMMAND_OR_INDEX_INFERENCE"
        ),
    }
    assert "next_slice" not in phase_zero
    assert "next_slice" not in runtime_status["managed_toolchain_phase_one"]
    assert (
        hashlib.sha256(autonomy_inventory_bytes).hexdigest()
        == historical_autonomy_inventory_raw_sha256
    )
    assert hashlib.sha256(autonomy_schema_bytes).hexdigest() == (
        CURRENT_RETRIEVAL_AUTONOMY_INVENTORY_SCHEMA_RAW_SHA256
    )
    assert hashlib.sha256(managed_toolchain_bytes).hexdigest() == MANAGED_TOOLCHAIN_RAW_SHA256
    assert (
        hashlib.sha256(managed_toolchain_schema_bytes).hexdigest()
        == MANAGED_TOOLCHAIN_SCHEMA_RAW_SHA256
    )
    assert autonomy_inventory["schema_version"] == "1.0"
    assert autonomy_inventory["phase"] == "PHASE_0_INVENTORY_ONLY"
    assert autonomy_inventory["status"] == "PARTIAL_NONAUTHORIZING"
    assert autonomy_inventory["source_discovery_semantics_sha256"] == (
        historical_autonomy_discovery_semantics_sha256
    )
    assert (
        autonomy_inventory["source_universe_sha256"] == historical_autonomy_source_universe_sha256
    )
    assert autonomy_inventory["inventory_sha256"] == historical_autonomy_inventory_sha256
    assert autonomy_inventory["source_count"] == 3657
    assert autonomy_inventory["source_occurrence_count"] == 3660
    assert autonomy_inventory["gate_source_count"] == 3614
    assert autonomy_inventory["logical_gate_count"] == 35
    assert autonomy_inventory["unsatisfied_gate_count"] == 29
    assert autonomy_inventory["current_manual_gate_count"] == 15
    assert autonomy_inventory["provider_or_network_accessed"] is False
    assert autonomy_inventory["secret_material_read"] is False
    assert autonomy_inventory["runtime_authority"] is False
    assert autonomy_inventory["managed_run_ready"] is False
    assert autonomy_schema["properties"]["runtime_authority"]["const"] is False
    assert autonomy_schema["properties"]["managed_run_ready"]["const"] is False
    managed_gate = next(
        gate
        for gate in autonomy_inventory["logical_gates"]
        if gate["gate_id"] == "gate-managed-toolchain-bundle"
    )
    assert managed_gate["implementation_state"] == "PARTIAL"
    assert "28 first-class managed roles" in managed_gate["implementation_detail"]
    assert (
        "fixed operating-system probe helpers remain unmodeled"
        in (managed_gate["implementation_detail"])
    )
    assert managed_toolchain["schema_version"] == "1.0"
    assert managed_toolchain["status"] == "PARTIAL_NONAUTHORIZING"
    assert managed_toolchain["bundle_sha256"] == MANAGED_TOOLCHAIN_SHA256
    assert len(managed_toolchain["members"]) == 28
    assert sum(member["disposition"] == "PINNED" for member in managed_toolchain["members"]) == 3
    assert (
        sum(member["disposition"] == "UNRESOLVED" for member in managed_toolchain["members"]) == 25
    )
    assert managed_toolchain["limitations"] == [
        "Config projection is not installed or executed process identity evidence.",
        "Generic rootless execution is refused until every image-side executable is modeled.",
        "Image-side executable and relay identities remain unattested until provisioning.",
        "Fixed operating-system probe helpers remain unmodeled and lack exact identity verification.",
        "Single-file hashes do not verify transitive dependency closures.",
    ]
    for flag in (
        "independently_trusted",
        "provisioning_state_verified",
        "installed_members_verified",
        "transitive_dependency_closure_verified",
        "image_side_attestation_verified",
        "execution_evidence_verified",
        "runtime_authority",
        "managed_run_ready",
    ):
        assert managed_toolchain[flag] is False
        assert managed_toolchain_schema["properties"][flag]["const"] is False
    assert runtime_status["last_validation"]["historical_03d_generation_real_provider_accessed"]
    assert runtime_status["last_validation"]["historical_03d_generation_operator_secret_accessed"]
    assert runtime_status["last_validation"][
        "historical_03d_generation_operator_private_ledger_accessed_or_mutated"
    ]
    assert runtime_status["last_validation"]["post_c627_real_provider_accessed"] is False
    assert runtime_status["last_validation"]["post_c627_operator_secret_accessed"] is False
    assert (
        runtime_status["last_validation"]["post_c627_operator_private_ledger_accessed_or_mutated"]
        is False
    )
    assert runtime_status["last_validation"]["post_c627_new_spend"] is False
    current_runtime_status = json.loads(RUNTIME_STATUS_PATH.read_text(encoding="utf-8"))
    pause_state = current_runtime_status["pause_state"]
    historical_action = pause_state["next_action_after_v3_truncation_specialist_recovery"]
    historical_resume = pause_state["resume_action_v3_truncation_recursive_child_recovery"]
    assert "bounded provider-free recursive recovery-child consumption" in historical_action
    assert "original TRUNCATED parent" in historical_action
    assert "live-REAL-only promotion credit" in historical_action
    assert PLANCONSTRAINTS_REPAIR_CHECKPOINT in historical_action
    assert HISTORICAL_PLANCONSTRAINTS_BASE_CHECKPOINT in historical_action
    assert HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT in historical_action
    assert "Do not infer or issue any operator/provider command" in historical_action
    assert "bounded provider-free recursive recovery-child consumption only" in historical_resume
    assert "keep the ticket PARTIAL" in historical_resume
    assert "positive nonempty full-pipeline REAL promotion evidence" in historical_resume
    assert "No operator/provider authority exists" in historical_resume
    historical_taxonomy_action = pause_state["next_action_during_v3_taxonomy_implementation"]
    historical_taxonomy_resume = pause_state["resume_action_during_v3_taxonomy_implementation"]
    assert "remaining taxonomy, governance, local-integration" in historical_taxonomy_action
    assert "complete sequential matrices" in historical_taxonomy_action
    assert "dispose V3-TAXONOMY-001" in historical_taxonomy_action
    assert "BLOCKED_TECHNICAL" in historical_taxonomy_action
    assert "Resume only the active provider-free V3-TAXONOMY-001" in (historical_taxonomy_resume)
    assert "nonfinding taxonomy behavior" in historical_taxonomy_resume
    assert "omission-to-GAP" in historical_taxonomy_resume
    assert "V3-RETRIEVAL-001 only after exact taxonomy disposition" in (historical_taxonomy_resume)
    historical_taxonomy_completion_action = pause_state["next_action_after_v3_taxonomy_completion"]
    historical_taxonomy_completion_resume = pause_state[
        "resume_action_after_v3_taxonomy_completion"
    ]
    assert "STOP after V3-TAXONOMY-001 provider-free closure" in (
        historical_taxonomy_completion_action
    )
    assert "V3-RETRIEVAL-001 is next dependency-ready but remains queued and unselected" in (
        historical_taxonomy_completion_action
    )
    assert "PARTIAL V3-CANDROUTE-001" in historical_taxonomy_completion_action
    assert "queued unimplemented V3-PRICELEXEME-001" in historical_taxonomy_completion_action
    assert "Do not emit or execute a provider/operator command" in (
        historical_taxonomy_completion_action
    )
    assert "At a new work-unit boundary" in historical_taxonomy_completion_resume
    assert "before selecting V3-RETRIEVAL-001 or another bounded ticket" in (
        historical_taxonomy_completion_resume
    )
    assert "Do not infer or select a route from fixtures" in historical_taxonomy_completion_resume
    historical_retrieval_action = pause_state["next_action_during_v3_retrieval_final_validation"]
    historical_retrieval_resume = pause_state["resume_action_during_v3_retrieval_final_validation"]
    assert "Finish only the active provider-free V3-RETRIEVAL-001 validation loop" in (
        historical_retrieval_action
    )
    assert "complete sequential suite" in historical_retrieval_action
    assert "Preserve the unchanged retry code and configuration" in (historical_retrieval_action)
    assert "Do not emit or execute a provider/operator command" in (historical_retrieval_action)
    assert "Resume only V3-RETRIEVAL-001 terminal provider-free validation" in (
        historical_retrieval_resume
    )
    assert "Do not select a successor, route, provider action" in historical_retrieval_resume
    current_action = pause_state["next_action_during_v3_pricelexeme_selection"]
    current_resume = pause_state["resume_action_during_v3_pricelexeme_selection"]
    normalized_current_action = " ".join(current_action.lower().split())
    normalized_current_resume = " ".join(current_resume.lower().split())
    for current_text in (normalized_current_action, normalized_current_resume):
        assert "v3-pricelexeme-001" in current_text
        assert "implementation_started=false" in current_text
        assert "provider-free" in current_text
        assert "price" in current_text and "lexeme" in current_text
        assert "route" in current_text
        assert "authority" in current_text
    assert "begin" in normalized_current_action
    assert "priceform" in normalized_current_action
    assert "reasoning" in normalized_current_action or "effort-high" in normalized_current_action
    assert "partial v3-candroute-001" in normalized_current_action
    assert "provider" in normalized_current_resume
    assert pause_state["non_allowlisted_pause_journal_fields_are_historical"] is True
    assert pause_state["non_allowlisted_pause_journal_fields_are_current_actions"] is False
    assert pause_state["current_semantic_field_allowlist"] == [
        "next_action_during_v3_pricelexeme_selection",
        "resume_action_during_v3_pricelexeme_selection",
    ]
    assert "Every field in this object" in pause_state["historical_pause_journal_scope"]
    assert "validation*" in pause_state["historical_pause_journal_scope"]
    assert "checkpoint*" in pause_state["historical_pause_journal_scope"]
    assert "timestamped_pause_journal_scope" not in pause_state
    assert "timestamped_pause_journal_entries_are_current_actions" not in pause_state
    assert pause_state["current_action_field"] == "next_action_during_v3_pricelexeme_selection"
    assert pause_state["current_resume_field"] == ("resume_action_during_v3_pricelexeme_selection")
    assert (
        "next_action_during_v3_retrieval_final_validation"
        not in pause_state["current_semantic_field_allowlist"]
    )
    assert (
        "resume_action_during_v3_retrieval_final_validation"
        not in pause_state["current_semantic_field_allowlist"]
    )
    assert (
        "next_action_during_v3_taxonomy_implementation"
        not in pause_state["current_semantic_field_allowlist"]
    )
    assert (
        "resume_action_during_v3_taxonomy_implementation"
        not in pause_state["current_semantic_field_allowlist"]
    )
    assert (
        "next_action_after_v3_endpointlist_v1_1_complete"
        not in pause_state["current_semantic_field_allowlist"]
    )
    assert (
        "next_action_after_v3_taxonomy_completion"
        not in pause_state["current_semantic_field_allowlist"]
    )
    assert (
        "resume_action_after_v3_taxonomy_completion"
        not in pause_state["current_semantic_field_allowlist"]
    )
    assert (
        "resume_action_after_v3_endpointlist_v1_1_complete"
        not in pause_state["current_semantic_field_allowlist"]
    )
    assert "result_v3_authrunner_current_r2_r5_r2_preflight" not in pause_state
    assert "result_v3_authrunner_historical_r2_r5_r2_preflight" in pause_state
    assert (
        "terminal full unit gate 5989 passed"
        in pause_state["validation_v3_authrunner_exact_cost_admission"]
    )
    assert (
        "validation_v3_authrunner_exact_cost_admission"
        not in pause_state["current_semantic_field_allowlist"]
    )
    identity_reconciliation = smoke_status["initial_identity_binding_reconciliation"]
    assert identity_reconciliation["checkpoint_commit"] == (
        HISTORICAL_AUTHRUNNER_SCOPE_CUTOFF_CHECKPOINT
    )
    assert identity_reconciliation["historical_unsafe_checkpoint_commit"] == (
        "8058e7bff88594b44aa42b8695ce5c25442ae73c"
    )
    assert identity_reconciliation["full_structural_validation_used_as_scope_classifier"] is False
    assert (
        identity_reconciliation[
            "exact_candidate_and_judge_smoke_scope_classifier_independent_of_validity"
        ]
        is True
    )
    assert (
        identity_reconciliation["intrinsic_invalid_exact_v3_smoke_bypassed_receipt_guard"] is False
    )
    assert identity_reconciliation["exact_smoke_cutoff_precedes_generation_metadata_get"] is True
    assert identity_reconciliation["exact_smoke_cutoff_precedes_usage_ledger_replacement"] is True
    assert identity_reconciliation["exact_smoke_cutoff_precedes_origin_marking"] is True
    assert (
        identity_reconciliation["exact_smoke_cutoff_precedes_generation_verification_capability"]
        is True
    )
    assert identity_reconciliation["strict_usage_diagnostic_maximum_code_count"] == 1
    assert identity_reconciliation["strict_usage_diagnostic_vocabulary_closed"] is True
    assert identity_reconciliation["generic_and_release_behavior_parity_retained"] is True
    assert (
        identity_reconciliation["operator_exact_strict_usage_rejecting_clause_available"] is False
    )
    assert identity_reconciliation["provider_free_strict_usage_diagnostic_clause_available"] is True
    receipt_scaffold = smoke_status["immutable_transport_receipt_scaffold"]
    assert receipt_scaffold["checkpoint_commit"] == ("8058e7bff88594b44aa42b8695ce5c25442ae73c")
    assert receipt_scaffold["scope_cutoff_hotfix_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_SCOPE_CUTOFF_CHECKPOINT
    )
    assert (
        receipt_scaffold["receipt_composite_checkpoint"]
        == HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT
    )
    assert receipt_scaffold["receipt_composite_parent_checkpoint"] == (
        AUTHRUNNER_RECEIPT_COMPOSITE_PARENT_CHECKPOINT
    )
    assert receipt_scaffold["receipt_composite_owned_path_count"] == 14
    assert (
        receipt_scaffold["receipt_state_seal_hotfix_checkpoint"]
        == HISTORICAL_AUTHRUNNER_RECEIPT_STATE_SEAL_CHECKPOINT
    )
    assert (
        receipt_scaffold["receipt_state_seal_hotfix_parent_checkpoint"]
        == HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT
    )
    assert receipt_scaffold["receipt_state_seal_hotfix_owned_path_count"] == 4
    assert (
        receipt_scaffold[
            "candidate_receipt_cutoff_bypassed_by_intrinsic_invalid_scope_classification"
        ]
        is False
    )
    assert receipt_scaffold["production_receipt_dispatch_active"] is True
    assert receipt_scaffold["production_receipt_dispatch_dormant"] is False
    assert receipt_scaffold["production_receipt_dispatch_scope"] == (
        "EXACT_CANONICAL_CANDIDATE_OR_JUDGE_V3_NONCREDITING_SMOKE_ONLY"
    )
    assert receipt_scaffold["generic_and_release_use_historical_path"] is True
    assert receipt_scaffold["completion_receipt_composite_complete"] is True
    assert receipt_scaffold["metadata_receipt_composite_complete"] is True
    assert receipt_scaffold["production_in_flight_transport_proof_complete"] is False
    assert receipt_scaffold["production_in_flight_transport_lifecycle_proved_locally"] is True
    assert receipt_scaffold["historical_pre_hotfix_receipt_state_seal_executed"] is True
    assert receipt_scaffold["historical_pre_hotfix_receipt_state_seal_succeeded"] is False
    assert receipt_scaffold["historical_pre_hotfix_failure"] == (
        "provider transport receipt cannot seal owned request state"
    )
    assert receipt_scaffold["historical_pre_hotfix_failure_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT
    )
    assert receipt_scaffold["historical_pre_hotfix_provider_completion_or_charge"] is False
    assert receipt_scaffold["historical_pre_hotfix_index_14_consumed"] is False
    assert (
        receipt_scaffold["historical_pre_hotfix_operator_diagnosis_independently_proven"] is False
    )
    assert receipt_scaffold["operator_record_predates_receipt_state_seal_hotfix"] is False
    assert receipt_scaffold["provider_free_receipt_state_seal_hotfix_validated"] is True
    assert receipt_scaffold["historical_live_evidence_scope"] == (
        "HISTORICAL_POST_68126E0_THROUGH_03D6E8A_GENERATION_NOT_POST_C627_PROVIDER_EXECUTION"
    )
    assert receipt_scaffold["historical_post_68126e0_provider_call_executed"] is True
    assert receipt_scaffold["historical_post_68126e0_receipt_state_seal_cleared_live"] is True
    assert receipt_scaffold["historical_3a_structured_output_routing_negative_executed"] is True
    for former_unscoped_live_key in (
        "post_hotfix_provider_call_executed",
        "post_hotfix_receipt_state_seal_cleared_live",
        "post_hotfix_structured_output_routing_negative_executed",
        "production_strong_origin_candidate_or_judge_positive_operator_reported",
        "actual_provider_tls_private_response_graph_operator_reported",
    ):
        assert former_unscoped_live_key not in receipt_scaffold
    assert (
        receipt_scaffold["clause_level_diagnostic_source_checkpoint"]
        == HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT
    )
    assert receipt_scaffold["clause_level_diagnostic_owned_path_count"] == 5
    assert receipt_scaffold["clause_level_diagnostic_live_code"] == (
        "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
    )
    assert receipt_scaffold["clause_level_diagnostic_historical_guard_root_count"] == 47
    assert (
        receipt_scaffold["clause_level_diagnostic_historical_reachable_function_state_count"]
        == 1072
    )
    assert receipt_scaffold["historical_required_provider_parameters_join_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT
    )
    assert receipt_scaffold["historical_required_provider_parameters_join_parent_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT
    )
    assert receipt_scaffold["historical_required_provider_parameters_join_owned_path_count"] == 5
    assert (
        receipt_scaffold["historical_required_provider_parameters_join_exact_matrix_tests_passed"]
        == 789
    )
    assert (
        receipt_scaffold[
            "historical_required_provider_parameters_join_request_cost_preview_tests_passed"
        ]
        == 19
    )
    assert (
        receipt_scaffold[
            "historical_required_provider_parameters_join_model_benchmark_tests_passed"
        ]
        == 26
    )
    assert receipt_scaffold["historical_required_provider_parameters_join_guard_root_count"] == 47
    assert (
        receipt_scaffold[
            "historical_required_provider_parameters_join_reachable_function_state_count"
        ]
        == 1073
    )
    assert (
        receipt_scaffold[
            "historical_required_provider_parameters_join_post_fix_provider_call_executed"
        ]
        is True
    )
    assert receipt_scaffold["historical_c627_canonical_replay_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT
    )
    assert receipt_scaffold["historical_c627_canonical_replay_parent_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT
    )
    assert receipt_scaffold["historical_c627_canonical_replay_owned_path_count"] == 3
    assert receipt_scaffold["historical_c627_canonical_replay_runtime_tests_passed"] == 95
    assert receipt_scaffold["historical_c627_canonical_replay_adjacent_tests_passed"] == 111
    assert (
        receipt_scaffold["historical_c627_canonical_replay_retained_authrunner_tests_passed"] == 789
    )
    assert receipt_scaffold["historical_c627_canonical_replay_operator_reported_valid"] is True
    assert receipt_scaffold["historical_c627_canonical_replay_provider_rerun_executed"] is False
    assert receipt_scaffold["historical_c627_canonical_replay_new_spend_incurred"] is False
    assert receipt_scaffold["all_or_none_composite_consumption"] is True
    assert receipt_scaffold["same_client_transport_task_thread_pid_and_ledger_custody"] is True
    assert receipt_scaffold[
        "historical_03d_production_strong_origin_candidate_or_judge_positive_operator_reported"
    ]
    assert receipt_scaffold[
        "historical_03d_actual_provider_tls_private_response_graph_operator_reported"
    ]
    assert (
        receipt_scaffold[
            "operator_reported_production_evidence_independently_authenticated_by_codex"
        ]
        is False
    )
    assert receipt_scaffold["complete_provider_compatibility_proven"] is False
    assert receipt_scaffold["candidate_origin_issuance_source_reachable_and_receipt_gated"] is True
    assert receipt_scaffold["judge_capability_issuance_reachable"] is True
    assert receipt_scaffold["judge_capability_issuance_receipt_gated"] is True
    assert receipt_scaffold["judge_capability_live_positive_executed"] is False
    assert receipt_scaffold["usage_publication_full_rollback_join_behaviorally_executed"] is False
    assert (
        receipt_scaffold["generation_capability_full_rollback_join_behaviorally_executed"] is False
    )
    assert receipt_scaffold["focused_tests_passed"] == 785
    assert receipt_scaffold["local_numeric_loopback_httpx_lifecycle_tests_passed"] == 1
    assert receipt_scaffold["independent_guard_root_count"] == 47
    assert receipt_scaffold["independent_reachable_function_state_count"] == 1071
    assert "REACHABLE_MUTATION_OR_REPLACEMENT" in receipt_scaffold["threat_model_covered"]
    assert "DELIBERATE_INTROSPECTIVE_WRITES" in receipt_scaffold["threat_model_excluded"]
    assert "TRACING_PROFILING_NATIVE_MEMORY" in receipt_scaffold["threat_model_excluded"]
    assert receipt_scaffold["runtime_authority"] is False
    historical_c627_receipt = exact_status["historical_c627_receipt_composite_checkpoint"]
    assert historical_c627_receipt["checkpoint_commit"] == HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT
    assert historical_c627_receipt["parent_commit"] == (
        HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT
    )
    assert historical_c627_receipt["owned_path_count"] == 3
    assert historical_c627_receipt["owned_paths"] == [
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/models/authenticated_runner_smoke.py",
        "tests/unit/test_authenticated_runner_smoke_runtime.py",
    ]
    assert historical_c627_receipt["path_sha256"] == {
        "docs/remediation/v3/autonomy_gate_inventory.json": (
            HISTORICAL_C627_AUTONOMY_INVENTORY_RAW_SHA256
        ),
        "src/mmaudit/models/authenticated_runner_smoke.py": (
            "27e70a3c17ef5f03c503e594bca2c3e433fb2c4193de772eb7be829592c3555a"
        ),
        "tests/unit/test_authenticated_runner_smoke_runtime.py": (
            "58eab4a75a0a944a2290789570aa410f26b2e0471b215cce45622076ad892d0f"
        ),
    }
    assert historical_c627_receipt["receipt_state_seal_hotfix_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_RECEIPT_STATE_SEAL_CHECKPOINT
    )
    assert historical_c627_receipt["receipt_state_seal_hotfix_parent_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT
    )
    assert historical_c627_receipt["receipt_state_seal_hotfix_owned_path_count"] == 4
    assert historical_c627_receipt["base_receipt_composite_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT
    )
    assert historical_c627_receipt["base_receipt_composite_parent_checkpoint"] == (
        AUTHRUNNER_RECEIPT_COMPOSITE_PARENT_CHECKPOINT
    )
    assert historical_c627_receipt["base_receipt_composite_owned_path_count"] == 14
    assert historical_c627_receipt["operator_result_predates_checkpoint"] is False
    assert historical_c627_receipt["operator_result_postdates_checkpoint"] is True
    assert (
        historical_c627_receipt["last_reconciled_operator_results_sha256"]
        == LAST_RECONCILED_OPERATOR_RESULTS_SHA256
    )
    assert historical_c627_receipt["last_reconciled_operator_results_bytes"] == 115_171
    assert historical_c627_receipt["last_reconciled_operator_results_lines"] == 2_111
    assert historical_c627_receipt["operator_results_in_checkpoint"] is False
    assert historical_c627_receipt["generic_and_release_parity"] is True
    assert historical_c627_receipt["historical_receipt_state_seal_focused_tests_passed"] == 785
    assert (
        historical_c627_receipt[
            "historical_receipt_state_seal_local_numeric_loopback_httpx_tests_passed"
        ]
        == 1
    )
    assert (
        historical_c627_receipt["historical_receipt_state_seal_independent_guard_root_count"] == 47
    )
    assert (
        historical_c627_receipt[
            "historical_receipt_state_seal_independent_reachable_function_state_count"
        ]
        == 1071
    )
    assert (
        historical_c627_receipt["historical_c627_authenticated_runner_smoke_runtime_tests_passed"]
        == 95
    )
    assert (
        historical_c627_receipt[
            "historical_c627_adjacent_cli_durable_inventory_release_schema_tests_passed"
        ]
        == 111
    )
    assert (
        historical_c627_receipt["historical_c627_retained_exact_authrunner_matrix_tests_passed"]
        == 789
    )
    assert (
        historical_c627_receipt[
            "historical_c627_retained_exact_authrunner_matrix_known_deprecation_warnings"
        ]
        == 2
    )
    assert historical_c627_receipt["full_suite_status"] == (
        "INCOMPLETE_PREEXISTING_DETERMINISTIC_FAILURE_NO_PASS_CREDIT"
    )
    assert historical_c627_receipt["full_suite_passed_before_failure"] == 1492
    assert historical_c627_receipt["full_suite_skipped_before_failure"] == 25
    assert historical_c627_receipt["full_suite_failed"] == 1
    assert historical_c627_receipt["full_suite_failure_reproduced_on_untouched_parent"] is True
    assert historical_c627_receipt[
        "historical_index_14_metadata_gate_status_at_base_checkpoint"
    ] == ("VALID_OPERATOR_REPORTED_NONAUTHORIZING_AFTER_R15_JUDGE_REFREEZES")
    assert historical_c627_receipt["historical_paid_launch_status_at_base_checkpoint"] == (
        "FAILED_SAFE_PRETRANSPORT_PROVIDER_RECEIPT_STATE_SEAL"
    )
    assert historical_c627_receipt["historical_paid_launch_failure_at_base_checkpoint"] == (
        "provider transport receipt cannot seal owned request state"
    )
    assert (
        historical_c627_receipt["historical_provider_completion_or_charge_at_base_checkpoint"]
        is False
    )
    assert historical_c627_receipt["historical_ledger_changed_at_base_checkpoint"] is False
    assert historical_c627_receipt["historical_index_14_consumed_at_base_checkpoint"] is False
    assert historical_c627_receipt["historical_bundle_published_at_base_checkpoint"] is False
    assert historical_c627_receipt["provider_free_receipt_state_seal_hotfix_validated"] is True
    assert historical_c627_receipt["historical_live_evidence_scope"] == (
        "HISTORICAL_POST_68126E0_THROUGH_03D6E8A_GENERATION_NOT_POST_C627_PROVIDER_EXECUTION"
    )
    assert historical_c627_receipt["historical_post_68126e0_provider_call_executed"] is True
    assert (
        historical_c627_receipt["historical_post_68126e0_receipt_state_seal_cleared_live"] is True
    )
    assert (
        historical_c627_receipt["historical_3a_structured_output_routing_negative_executed"] is True
    )
    for former_unscoped_live_key in (
        "post_hotfix_provider_call_executed",
        "post_hotfix_receipt_state_seal_cleared_live",
        "post_hotfix_structured_output_routing_negative_executed",
        "live_clause_specific_negative_executed",
        "live_clause_specific_diagnostic",
        "production_strong_origin_positive_operator_reported",
        "actual_provider_tls_private_response_graph_operator_reported",
    ):
        assert former_unscoped_live_key not in historical_c627_receipt
    assert historical_c627_receipt["clause_level_diagnostic_source_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT
    )
    assert historical_c627_receipt["clause_level_diagnostic_owned_path_count"] == 5
    assert historical_c627_receipt["clause_level_diagnostic_exact_matrix_tests_passed"] == 789
    assert (
        historical_c627_receipt["clause_level_diagnostic_adjacent_model_benchmark_tests_passed"]
        == 26
    )
    assert historical_c627_receipt["clause_level_diagnostic_independent_tests_passed"] == 564
    assert historical_c627_receipt["clause_level_diagnostic_independent_guard_root_count"] == 47
    assert (
        historical_c627_receipt[
            "clause_level_diagnostic_independent_reachable_function_state_count"
        ]
        == 1072
    )
    assert historical_c627_receipt["historical_required_provider_parameters_join_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT
    )
    assert historical_c627_receipt[
        "historical_required_provider_parameters_join_parent_checkpoint"
    ] == (HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT)
    assert (
        historical_c627_receipt["historical_required_provider_parameters_join_owned_path_count"]
        == 5
    )
    assert (
        historical_c627_receipt[
            "historical_required_provider_parameters_join_exact_authrunner_matrix_tests_passed"
        ]
        == 789
    )
    assert (
        historical_c627_receipt[
            "historical_required_provider_parameters_join_request_cost_preview_tests_passed"
        ]
        == 19
    )
    assert (
        historical_c627_receipt[
            "historical_required_provider_parameters_join_model_benchmark_tests_passed"
        ]
        == 26
    )
    assert (
        historical_c627_receipt[
            "historical_required_provider_parameters_join_overlapping_usage_plus_preview_tests_passed"
        ]
        == 185
    )
    assert (
        historical_c627_receipt[
            "historical_required_provider_parameters_join_overlapping_usage_plus_preview_is_additive"
        ]
        is False
    )
    assert (
        historical_c627_receipt[
            "historical_required_provider_parameters_join_independent_guard_root_count"
        ]
        == 47
    )
    assert (
        historical_c627_receipt[
            "historical_required_provider_parameters_join_independent_reachable_function_state_count"
        ]
        == 1073
    )
    assert historical_c627_receipt["historical_generation_provider_call_executed"] is True
    assert historical_c627_receipt["post_c627_provider_call_executed"] is False
    assert historical_c627_receipt["last_reconciled_complete_smoke_run_index"] == 19
    assert historical_c627_receipt["last_reconciled_complete_smoke_status"] == (
        "COMPLETE_NONCREDITING_NONAUTHORIZING"
    )
    assert historical_c627_receipt["last_reconciled_complete_smoke_bundle_path"] == (
        "$HOME/.mmaudit/private/authrunner/authenticated-runner-smoke-evidence-20260824-s19.json"
    )
    assert historical_c627_receipt["last_reconciled_complete_smoke_bundle_sha256"] == (
        "e7537a2fc5aed79d274101364442faf0e515dd5879cfd8f6670784fcc2595703"
    )
    assert historical_c627_receipt["last_reconciled_complete_smoke_bundle_bytes"] == 282_802
    assert historical_c627_receipt["last_reconciled_complete_smoke_canonical_replay_passed"] is True
    assert historical_c627_receipt["last_reconciled_complete_smoke_canonical_replay_status"] == (
        "VALID_NONCREDITING_NONAUTHORIZING_OPERATOR_REPORTED"
    )
    assert historical_c627_receipt[
        "historical_pre_c627_complete_smoke_canonical_replay_failure"
    ] == ("authenticated runner smoke bundle failed canonical replay")
    assert historical_c627_receipt[
        "historical_pre_c627_complete_smoke_canonical_replay_underlying_error"
    ] == ("AuthenticatedRunnerSmokeError: authenticated runner smoke bytes do not validate")
    assert historical_c627_receipt["historical_c627_offline_replay_caused_provider_rerun"] is False
    assert historical_c627_receipt["historical_c627_offline_replay_caused_new_spend"] is False
    assert (
        historical_c627_receipt[
            "historical_c627_offline_replay_independently_authenticated_by_codex"
        ]
        is False
    )
    assert historical_c627_receipt["last_reconciled_next_unused_run_index"] is None
    assert historical_c627_receipt["last_reconciled_next_unused_run_index_stated"] is False
    assert historical_c627_receipt["historical_3a_live_clause_specific_negative_executed"] is True
    assert historical_c627_receipt["historical_3a_live_clause_specific_diagnostic"] == (
        "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
    )
    assert historical_c627_receipt[
        "historical_03d_production_strong_origin_positive_operator_reported"
    ]
    assert historical_c627_receipt[
        "historical_03d_actual_provider_tls_private_response_graph_operator_reported"
    ]
    assert (
        historical_c627_receipt[
            "operator_reported_production_evidence_independently_authenticated_by_codex"
        ]
        is False
    )
    assert historical_c627_receipt["complete_provider_compatibility_proven"] is False
    assert historical_c627_receipt["full_publication_rollback_joins_behaviorally_executed"] is False
    assert historical_c627_receipt["provider_access_authorized"] is False
    assert historical_c627_receipt["paid_authority"] is False
    assert historical_c627_receipt["runtime_authority"] is False
    assert runtime_status["last_validation"]["terminal_full_suite_run"] is False
    assert runtime_status["last_validation"]["terminal_full_suite_attempt_started"] is False
    operator_reconciliation = runtime_status["last_validation"]["last_reconciled_operator_evidence"]
    assert (
        operator_reconciliation["operator_results_sha256"]
        == LAST_RECONCILED_OPERATOR_RESULTS_SHA256
    )
    assert operator_reconciliation["operator_results_bytes"] == 115_171
    assert operator_reconciliation["operator_results_lines"] == 2_111
    assert operator_reconciliation["generation_source_checkpoint"] == (
        OPERATOR_INDEX_19_SOURCE_CHECKPOINT
    )
    assert operator_reconciliation["offline_replay_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT
    )
    assert operator_reconciliation["smoke_run_index"] == 19
    assert operator_reconciliation["smoke_status"] == (
        "COMPLETE_NONCREDITING_NONAUTHORIZING_OPERATOR_REPORTED"
    )
    assert operator_reconciliation["historical_pre_c627_failure_phase"] == (
        "POST_RUN_CANONICAL_REPLAY"
    )
    assert operator_reconciliation["historical_pre_c627_failure"] == (
        "authenticated runner smoke bundle failed canonical replay"
    )
    assert operator_reconciliation["historical_pre_c627_underlying_failure"] == (
        "AuthenticatedRunnerSmokeError: authenticated runner smoke bytes do not validate"
    )
    assert operator_reconciliation["historical_03d_generation_provider_completion_or_charge"]
    assert operator_reconciliation["post_c627_provider_completion_or_charge"] is False
    assert operator_reconciliation["ledger_entry_count"] == 25
    assert operator_reconciliation["ledger_total_usd"] == "0.396223"
    assert operator_reconciliation["index_19_closed_run_ledger_entry_count"] == 4
    assert operator_reconciliation["index_19_closed_run_ledger_total_usd"] == "0.39622262"
    assert operator_reconciliation["next_unused_run_index"] is None
    assert operator_reconciliation["next_unused_run_index_stated"] is False
    assert operator_reconciliation["bundle_path"] == (
        "$HOME/.mmaudit/private/authrunner/authenticated-runner-smoke-evidence-20260824-s19.json"
    )
    assert operator_reconciliation["bundle_sha256"] == (
        "e7537a2fc5aed79d274101364442faf0e515dd5879cfd8f6670784fcc2595703"
    )
    assert operator_reconciliation["bundle_bytes"] == 282_802
    assert operator_reconciliation["bundle_offline_verified"] is True
    assert operator_reconciliation["bundle_offline_verification_status"] == (
        "VALID_NONCREDITING_NONAUTHORIZING_OPERATOR_REPORTED"
    )
    assert (
        operator_reconciliation["bundle_offline_verification_independently_authenticated_by_codex"]
        is False
    )
    assert operator_reconciliation["replay_caused_provider_rerun"] is False
    assert operator_reconciliation["replay_caused_new_spend"] is False
    assert operator_reconciliation["operator_full_bundle_diagnosis_independently_proven"] is False
    assert (
        operator_reconciliation["narrow_report_level_datetime_defect_reproduced_provider_free"]
        is True
    )
    assert operator_reconciliation["authority"] is False
    assert smoke_status["implementation_checkpoint"] == ("692eb173f002818b4434b746c8801b4cbeb852e2")
    assert smoke_status["historical_post_origin_fix_guide_checkpoint"] == (
        "c137f8bae9d27f5120e7e08eba2d9b5b384e1ca5"
    )
    assert smoke_status["historical_post_origin_fix_guide_state"] == (
        "CHECKPOINTED_PUSHED_REMOTE_VERIFIED_PREFLIGHT_VALID_NONAUTHORIZING"
    )
    assert "post_origin_fix_guide_checkpoint" not in smoke_status
    assert "post_origin_fix_guide_state" not in smoke_status
    assert smoke_status["paid_smoke_guide_checkpoint"] == (
        "7b2db061ceb7449674399d6133428b97b74b4b96"
    )
    assert smoke_status["historical_safety_withdrawal_checkpoint"] == (
        "ca63b924f244cc9bcee2d2405d20b000ce0bb9d6"
    )
    assert "safety_withdrawal_checkpoint" not in smoke_status
    assert "safety_withdrawal_checkpoint_subject" not in smoke_status
    assert "7b2db061ceb7449674399d6133428b97b74b4b96" in model_selection
    historical_preflights = smoke_status["historical_provider_free_preflight_snapshots"]
    assert historical_preflights["scope"] == (
        "HISTORICAL_PRE_C627_PROVIDER_FREE_PREFLIGHTS_NOT_CURRENT_ROUTE_FRESHNESS_"
        "COMMAND_OR_AUTHORITY"
    )
    post_token_budget_preflight = historical_preflights["post_token_budget_fix"]
    assert post_token_budget_preflight["status"] == (
        "VALID_NONCREDITING_NONAUTHORIZING_NO_PROVIDER_EGRESS"
    )
    assert "preflight_status" not in smoke_status
    assert not any(
        key.startswith(
            (
                "post_token_budget_fix_preflight_",
                "successful_preflight_",
                "post_origin_fix_successful_preflight_",
                "failed_preflight_",
            )
        )
        for key in smoke_status
    )
    assert smoke_status["provider_free_preflight_command_emission_status"] == (
        "HISTORICAL_EXECUTED_VALID_DO_NOT_RERUN"
    )
    assert smoke_status["status"] == (
        "PARTIAL_C627F2D_INDEX_19_OPERATOR_REPORTED_VALID_NONCREDITING_NONAUTHORIZING_"
        "ZERO_CURRENT_COMMANDS_REAL_BLOCKED_SAFETY"
    )
    assert smoke_status["ticket_status"] == "PARTIAL"
    assert smoke_status["smoke_run_index_contract"] == {
        "status": "IMPLEMENTED_CHECKPOINTED_NONAUTHORIZING",
        "checkpoint_commit": AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_CHECKPOINT,
        "checkpoint_pushed": False,
        "checkpoint_remote_resolved": False,
        "durable_schema_version": "1.2",
        "durable_schema_raw_sha256": (
            "34f264a5fa9ae55ba6d0c02d2e1f78c81aa4abf2c19ab50b6366c2c4d6e75404"
        ),
        "historical_pre_planconstraints_durable_schema_raw_sha256": (
            "2163642df1d0b7adf463eb04887e2027e462acdd716ec83451d76c49d80db78d"
        ),
        "required_cli_argument": True,
        "required_in_metadata_only_and_paid_modes": True,
        "canonical_minimum": 1,
        "canonical_maximum": 999_999_999,
        "current_emitted_run_index": None,
        "occupied_run_indexes": [
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            18,
            19,
        ],
        "next_unused_run_index": None,
        "next_unused_run_index_stated": False,
        "cumulative_ledger_namespace_reuse_rejected_provider_free": True,
        "attempt_suffixed_namespace_reuse_rejected": True,
        "rejection_precedes_secret_selection": True,
        "rejection_precedes_provider_dispatch": True,
        "rejection_precedes_ledger_mutation": True,
        "historical_reconciled_entry_retained": True,
        "release_namespaces_unchanged_and_disjoint": True,
        "autonomy_entrypoint_source_id": (
            "completion-entrypoint:models_authenticated_runner_smoke:smoke_run_index"
        ),
        "autonomy_entrypoint_logical_gate_id": "gate-authenticated-real-campaign",
        "implementer_focused_tests_passed": 385,
        "independent_focused_tests_passed": 360,
        "independent_adjacent_openrouter_tests_passed": 3,
        "provider_free_contract_access_scope": (
            "LOCAL_PROVIDER_FREE_RUN_INDEX_CONTRACT_IMPLEMENTATION_ONLY_NOT_HISTORICAL_"
            "03D_GENERATION_OR_PRIVATE_LEDGER_PROJECTION"
        ),
        "codex_provider_or_network_accessed_during_provider_free_contract_implementation": (False),
        "codex_operator_secret_accessed_during_provider_free_contract_implementation": False,
        (
            "codex_operator_private_ledger_accessed_or_mutated_during_provider_free_"
            "contract_implementation"
        ): False,
        "runtime_authority": False,
    }
    for former_unscoped_access_key in (
        "provider_or_network_accessed",
        "operator_secret_accessed",
        "operator_private_ledger_accessed_or_mutated",
    ):
        assert former_unscoped_access_key not in smoke_status["smoke_run_index_contract"]
    assert smoke_status["real_execution_status"] == (
        "HISTORICAL_03D6E8A_INDEX_19_COMPLETE_NONCREDITING_NONAUTHORIZING_SEALED_BUNDLE_"
        "HISTORICAL_C627F2D_OFFLINE_REPLAY_OPERATOR_REPORTED_VALID_NO_RERUN_NO_NEW_SPEND"
    )
    assert smoke_status["real_command_emission_status"] == (
        "ZERO_CURRENT_AUTHRUNNER_COMMANDS_NEXT_UNUSED_INDEX_NOT_STATED_PAID_NAMESPACE_NOT_AUTHORITY"
    )
    assert smoke_status["offline_verifier_command_emission_status"] == (
        "HISTORICAL_OPERATOR_EXECUTED_LAST_RECONCILED_RESULT_REPORTED_VALID_NONCREDITING_"
        "NONAUTHORIZING_ZERO_CURRENT_COMMANDS"
    )
    assert smoke_status["live_route_preflight_command_emission_status"] == (
        "ZERO_CURRENT_ROUTE_COMMANDS_POST_C627F2D_INDEX_19_OPERATOR_REPORTED_VALID_"
        "NONCREDITING_NONAUTHORIZING_OFFLINE_REPLAY_NEXT_UNUSED_INDEX_NOT_STATED"
    )
    assert smoke_status["full_24_case_real_command_status"] == "ABSENT_WITHHELD_BLOCKED_SAFETY"
    assert (
        smoke_status["last_reconciled_operator_results_sha256"]
        == LAST_RECONCILED_OPERATOR_RESULTS_SHA256
    )
    assert smoke_status["last_reconciled_operator_results_bytes"] == 115_171
    assert smoke_status["last_reconciled_operator_results_lines"] == 2_111
    complete_smoke = smoke_status["last_reconciled_complete_smoke_offline_replay"]
    assert complete_smoke["generation_source_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT
    )
    assert complete_smoke["offline_replay_checkpoint"] == HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT
    assert complete_smoke["operator_results_sha256"] == LAST_RECONCILED_OPERATOR_RESULTS_SHA256
    assert complete_smoke["operator_results_bytes"] == 115_171
    assert complete_smoke["operator_results_lines"] == 2_111
    assert complete_smoke["smoke_run_index"] == 19
    assert complete_smoke["status"] == "COMPLETE_NONCREDITING_NONAUTHORIZING"
    assert complete_smoke["bundle_path"] == (
        "$HOME/.mmaudit/private/authrunner/authenticated-runner-smoke-evidence-20260824-s19.json"
    )
    assert complete_smoke["bundle_sha256"] == (
        "e7537a2fc5aed79d274101364442faf0e515dd5879cfd8f6670784fcc2595703"
    )
    assert complete_smoke["bundle_bytes"] == 282_802
    assert complete_smoke["closed_run_ledger_entry_count"] == 4
    assert complete_smoke["closed_run_ledger_final_spent_usd"] == "0.39622262"
    assert complete_smoke["global_ledger_entry_count"] == 25
    assert complete_smoke["global_ledger_total_usd"] == "0.396223"
    assert complete_smoke["canonical_replay_status"] == (
        "VALID_NONCREDITING_NONAUTHORIZING_OPERATOR_REPORTED"
    )
    assert complete_smoke["historical_pre_c627_canonical_replay_failure"] == (
        "authenticated runner smoke bundle failed canonical replay"
    )
    assert complete_smoke["historical_pre_c627_canonical_replay_underlying_error"] == (
        "AuthenticatedRunnerSmokeError: authenticated runner smoke bytes do not validate"
    )
    assert (
        complete_smoke["historical_operator_reported_strict_datetime_validation_error_count"] == 15
    )
    assert (
        complete_smoke["operator_full_bundle_evidence_independently_authenticated_by_codex"]
        is False
    )
    assert complete_smoke["narrow_report_level_datetime_defect_reproduced_provider_free"] is True
    assert complete_smoke["narrow_report_level_datetime_failure_count"] == 3
    assert complete_smoke["index_17_status"] == (
        "OPERATOR_TIMEOUT_ONE_UNCERTAIN_ACCOUNTED_JUDGE_ENTRY"
    )
    assert complete_smoke["index_18_status"] == "SCHEMA_VALIDATION_FAILED_CANDIDATE"
    assert complete_smoke["index_19_status"] == "COMPLETE_NONCREDITING_NONAUTHORIZING"
    assert complete_smoke["next_unused_run_index"] is None
    assert complete_smoke["next_unused_run_index_stated"] is False
    assert complete_smoke["offline_verified"] is True
    assert complete_smoke["offline_verification_operator_reported"] is True
    assert complete_smoke["replay_caused_provider_rerun"] is False
    assert complete_smoke["replay_caused_new_spend"] is False
    assert complete_smoke["current_command"] is False
    assert complete_smoke["authority"] is False
    live_negative = smoke_status[
        "historical_post_diagnostic_structured_output_routing_live_negative"
    ]
    assert live_negative["source_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT
    )
    assert (
        live_negative["operator_results_sha256"]
        == HISTORICAL_POST_DIAGNOSTIC_OPERATOR_RESULTS_SHA256
    )
    assert live_negative["operator_results_bytes"] == 108_633
    assert live_negative["operator_results_lines"] == 1_980
    assert live_negative["metadata_gate_run_index"] == 16
    assert live_negative["metadata_gate_status"] == (
        "GREEN_OPERATOR_REPORTED_NONAUTHORIZING_DETAILS_UNSTATED"
    )
    assert live_negative["followup_instrumented_run_index"] is None
    assert live_negative["failure"] == (
        "NONCREDITING_SMOKE identity binding lacks immutable receipt custody"
    )
    assert live_negative["usage_diagnostics"] == (
        "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
    )
    assert live_negative["failure_phase"] == (
        "POSTTRANSPORT_STRICT_STRUCTURED_OUTPUT_ROUTING_IDENTITY_REQUIRED_PROVIDER_PARAMETERS_"
        "BEFORE_IMMUTABLE_IDENTITY_CUSTODY"
    )
    assert live_negative["receipt_state_seal_cleared_live"] is True
    assert live_negative["provider_transport_dispatched"] is True
    assert live_negative["provider_completion_or_charge"] is True
    assert live_negative["ledger_entry_count"] == 16
    assert live_negative["ledger_total_usd"] == "0.151976"
    assert live_negative["index_16_cost_usd"] == "0.006281"
    assert live_negative["ledger_changed"] is True
    assert live_negative["run_index_consumed"] is True
    assert live_negative["next_unused_run_index"] == 17
    assert live_negative["bundle_published"] is None
    assert live_negative["requested_mode_mismatch_hypothesis_retracted_as_wrong"] is True
    assert live_negative["exact_route_artifact_identities_stated_in_new_entry"] is False
    assert live_negative["run_16_terminal_status_stated"] is False
    assert (
        live_negative[
            "reserved_remaining_aggregate_call_counts_metadata_get_count_stated_at_that_boundary"
        ]
        is False
    )
    assert live_negative["operator_diagnosis_independently_proven"] is False
    assert live_negative["current_command"] is False
    assert live_negative["authority"] is False
    historical_partial_metadata = smoke_status["historical_r7_partial_metadata_discovery"]
    assert historical_partial_metadata["implementation_checkpoint"] == (
        NATIVE_STRUCTURED_OUTPUT_GATE_CHECKPOINT
    )
    assert historical_partial_metadata["candidate_status"] == "SUCCESS"
    historical_r7_gate = smoke_status["historical_r7_live_route_gate"]
    assert historical_r7_gate["composition"] == "r7/r7/r7"
    assert historical_r7_gate["metadata_discovery_status"] == "ALL_THREE_REGISTRIES_FROZEN"
    assert historical_r7_gate["live_route_gate_status"] == "FAILED_SAFE_BEFORE_PAID_TRANSPORT"
    assert historical_r7_gate["failure_role"] == "primary"
    assert historical_r7_gate["failure_model_id"] == "google/gemma-4-26b-a4b-it"
    assert historical_r7_gate["required_reasoning_effort"] == "high"
    assert historical_r7_gate["supported_reasoning_efforts"] == []
    assert historical_r7_gate["model_completions"] == 0
    assert historical_r7_gate["incremental_spend_usd"] == "0"
    assert historical_r7_gate["live_campaign_ledger_entry_count"] == 1
    assert historical_r7_gate["authority"] is False
    historical_capture = smoke_status["historical_glm_5_2_lineage_capture_and_reseal"]
    assert historical_capture["operator_results_sha256"] == (
        HISTORICAL_R8_GATE_OPERATOR_RESULTS_SHA256
    )
    assert historical_capture["operator_results_bytes"] == 71_771
    assert historical_capture["operator_results_lines"] == 1_276
    assert historical_capture["reported_capture_source_count"] == 17
    assert historical_capture["capture_status"] == (
        "SUCCESS_ADOPTED_PROVIDER_FREE_DOCUMENTARY_IDENTITY_ONLY"
    )
    assert historical_capture["manifest_sha256"] == CURRENT_LINEAGE_MANIFEST_SHA256
    assert (
        historical_capture["manifest_semantic_bundle_sha256"]
        == CURRENT_LINEAGE_SEMANTIC_BUNDLE_SHA256
    )
    assert historical_capture["reseal_checkpoint"] == CURRENT_LINEAGE_RESEAL_CHECKPOINT
    assert historical_capture["model_completions"] == 0
    assert historical_capture["incremental_spend_usd"] == "0"
    assert historical_capture["output_authority"] is False
    assert historical_capture["current_operator_command_emitted"] is False
    historical_r4_selection = runtime_status[
        "historical_authrunner_primary_r4_candidate_selection_validation"
    ]
    assert historical_r4_selection["scope"] == (
        "HISTORICAL_CB3FC341_MINIMAX_R4_SELECTION_NOT_CURRENT_ECB8_ZAI_PLAN_CUSTODY"
    )
    assert historical_r4_selection["commit"] == "cb3fc34174e028c2d2ff208c50c23a90a4b29d72"
    assert "authrunner_candidate_selection_validation" not in runtime_status
    current_lineage = runtime_status["authrunner_documentary_lineage_reseal"]
    assert current_lineage["manifest_sha256"] == CURRENT_LINEAGE_MANIFEST_SHA256
    assert current_lineage["manifest_size_bytes"] == 61_852
    assert current_lineage["semantic_bundle_sha256"] == CURRENT_LINEAGE_SEMANTIC_BUNDLE_SHA256
    assert current_lineage["source_count"] == 17
    assert current_lineage["alias_count"] == 16
    assert current_lineage["claim_count"] == 18
    assert current_lineage["decision_count"] == 16
    assert current_lineage["confirmed_identity_count"] == 12
    assert current_lineage["unconfirmed_identity_count"] == 4
    assert current_lineage["approved_root_count"] == 11
    assert current_lineage["constraint_count"] == 8
    assert current_lineage["active_runner_triple_directed_independence_pairs_passed"] == 6
    assert current_lineage["current_reseal_checkpoint"] == CURRENT_LINEAGE_RESEAL_CHECKPOINT
    assert current_lineage["current_reseal_checkpoint_pushed"] is False
    assert current_lineage["current_reseal_checkpoint_remote_resolved"] is False
    assert smoke_status["current_live_route_fields_status"] == (
        "ABSENT_ZERO_CURRENT_COMMANDS_INDEX_10_GATE_WITH_PRIMARY_R14_WAS_OPERATOR_"
        "REPORTED_VALID_IMMEDIATELY_BEFORE_PAID_RUN_BUT_IS_NOW_HISTORICAL_"
        "NONAUTHORIZING"
    )
    assert smoke_status["current_live_route_composition"] is None
    assert smoke_status["current_live_route_preflight_run"] is False
    assert smoke_status["current_live_route_preflight_succeeded"] is False
    assert smoke_status["current_live_route_preflight_logical_gets"] is None
    assert smoke_status["current_live_route_preflight_maximum_provider_attempts"] is None
    assert smoke_status["current_live_route_preflight_provider_completions"] is None
    assert smoke_status["current_live_route_preflight_usage_records"] is None
    assert smoke_status["current_live_route_preflight_budget_unchanged"] is None
    assert smoke_status["current_live_route_preflight_atomic_ledger_unchanged"] is None
    assert smoke_status["current_live_route_preflight_output_published"] is None
    assert smoke_status["historical_operator_live_route_preflight_evidence_scope"] == (
        "HISTORICAL_FIRST_LIVE_ROUTE_PREFLIGHT_EVENT_NOT_CURRENT_ROUTE_STATE"
    )
    assert smoke_status["historical_operator_live_route_preflight_frozen_endpoint_count"] == 12
    assert smoke_status["historical_operator_live_route_preflight_observed_endpoint_count"] == 13
    assert smoke_status["historical_observed_primary_discovery_drift_under_hours"] == 7
    assert "live_route_preflight_checkpoint" not in smoke_status
    assert "observed_primary_discovery_drift_under_hours" not in smoke_status
    assert not any(key.startswith("operator_live_route_preflight_") for key in smoke_status)
    assert "operator_live_route_preflight_current_endpoint_count" not in smoke_status
    assert smoke_status["historical_aggregate_live_route_preflight_scope"] == (
        "HISTORICAL_R6_R6_R2_AGGREGATE_EVENT_NOT_CURRENT_ROUTE_FRESHNESS_OR_COMMAND"
    )
    assert smoke_status["historical_aggregate_candidate_registry"] == "candidate-registry-r6.json"
    assert smoke_status["historical_aggregate_primary_judge_registry"] == (
        "primary-judge-registry-r6.json"
    )
    assert smoke_status["historical_aggregate_replay_judge_registry"] == (
        "replay-judge-registry-r2.json"
    )
    for stale_key in (
        "aggregate_live_route_preflight_checkpoint",
        "operator_aggregate_live_route_preflight_run",
        "fresh_candidate_registry",
        "fresh_candidate_discovery_run",
        "fresh_primary_judge_registry",
        "fresh_primary_judge_discovery_run",
        "fresh_replay_judge_registry",
        "fresh_replay_judge_discovery_run",
    ):
        assert stale_key not in smoke_status
    index_ten_gate = smoke_status["historical_index_10_metadata_only_gate"]
    assert index_ten_gate == {
        "status": (
            "OPERATOR_REPORTED_VALID_IMMEDIATELY_BEFORE_INDEX_10_PAID_RUN_NONAUTHORIZING_HISTORICAL"
        ),
        "candidate_registry": None,
        "candidate_discovery_run": None,
        "primary_registry": "primary-judge-registry-r14.json",
        "primary_discovery_run": "authrunner-primary-judge-20260823-r14",
        "replay_registry": None,
        "replay_discovery_run": None,
        "composition": None,
        "logical_metadata_gets": None,
        "maximum_metadata_provider_attempts": None,
        "usage_records": None,
        "budget_unchanged": None,
        "atomic_cost_ledger_unchanged": None,
        "output_published": None,
        "effective_config_sha256": None,
        "primary_sub_hour_drift_observation_count_that_day": 5,
        "paid_index_10_run_occurred": True,
        "current_command": False,
        "authority": False,
    }
    assert "34f264a5fa9ae55ba6d0c02d2e1f78c81aa4abf2c19ab50b6366c2c4d6e75404" in (model_selection)
    assert "Historical AUTHRUNNER replay checkpoint `c627f2d" in model_selection
    assert "Current checkpoint `c627f2d" not in model_selection
    assert "Current `c627f2d`" not in model_selection
    assert smoke_status["zero_command_evidence_checkpoint"] == (
        "02ed5bef89d094e0d0c4852e1bf73914d9960c6b"
    )
    assert smoke_status["historical_command_guide_checkpoint"] == (
        "4bebab16bb2e36d54665918dec64429602b4f4e6"
    )
    assert smoke_status["historical_command_guide_checkpoint_pushed"] is True
    assert smoke_status["historical_command_guide_checkpoint_remote_resolved"] is True
    assert smoke_status["historical_adjacent_pair_emitted_then_paid_executed_and_withdrawn"] is True
    assert smoke_status["adjacent_sequence_required"] is True
    assert smoke_status["current_adjacent_command_count"] == 0
    assert smoke_status["current_adjacent_commands_emitted_not_run"] is False
    assert smoke_status["current_adjacent_composition"] is None
    assert smoke_status["current_smoke_run_index"] is None
    assert smoke_status["current_candidate_registry"] is None
    assert smoke_status["current_candidate_discovery_run"] is None
    assert smoke_status["current_primary_judge_registry"] is None
    assert smoke_status["current_primary_judge_discovery_run"] is None
    assert smoke_status["current_replay_judge_registry"] is None
    assert smoke_status["current_replay_judge_discovery_run"] is None
    assert smoke_status["current_smoke_output"] is None
    assert smoke_status["paused_phase2_working_bytes_may_be_used"] is False
    assert smoke_status["executable_bytes_must_remain_unchanged_between_a_and_b"] is True
    assert smoke_status["paid_execution_adjacency_status"] == (
        "HISTORICAL_INDEX_19_EXECUTION_AND_HISTORICAL_C627F2D_OFFLINE_REPLAY_RECORDED_"
        "NONAUTHORIZING; NO_POST_C627_PROVIDER_RUN; CURRENT_ROUTE_ADJACENCY_NOT_"
        "ESTABLISHED; ZERO_CURRENT_COMMANDS; NEXT_UNUSED_INDEX_NOT_STATED"
    )
    assert smoke_status["paid_path_blocker"] == (
        "HISTORICAL_C627F2D_OFFLINE_REPLAY_IS_OPERATOR_REPORTED_VALID_NONCREDITING_"
        "NONAUTHORIZING_BUT_GRANTS_NO_CAMPAIGN_AUTHORITY; COMPLETED_REAL_AUDITS_ZERO; "
        "ONE_CASE_NOT_24; V3_PLANCONSTRAINTS_001_COMPLETE_PROVIDER_FREE_NONAUTHORIZING_"
        "AFTER_425502C_REPAIR_WITH_HISTORICAL_7EF4717_IMPLEMENTATION_BASE; FULL_BLOCKED_"
        "TYPED_UNAVAILABLE_EMPIRICAL_SCHEMA_AND_TOKEN_DETAIL_EVIDENCE; ZERO_CURRENT_"
        "COMMANDS; NEXT_UNUSED_INDEX_NOT_STATED; ANY_FUTURE_OPERATOR_ACTION_REQUIRES_"
        "SEPARATE_AUTHORIZATION"
    )
    assert smoke_status["commands_must_not_be_chained"] is True
    assert smoke_status["pre_a_ledger_exactly_empty_inspection_required"] is False
    assert smoke_status["pre_a_ledger_exactly_one_reconciled_entry_inspection_required"] is False
    assert smoke_status["pre_a_ledger_expected_used_usd"] is None
    assert smoke_status["pre_a_ledger_expected_reserved_usd"] is None
    assert smoke_status["pre_a_ledger_expected_remaining_usd"] is None
    assert smoke_status["pre_a_smoke_run_index_namespace_must_be_unused"] is False
    assert smoke_status["pre_a_smoke_run_index"] is None
    assert smoke_status["pre_a_output_absent_inspection_required"] is False
    assert smoke_status["pre_a_output_parent_mode_0700_inspection_required"] is False
    assert smoke_status["pre_a_exact_artifact_and_config_inspection_required"] is False
    assert smoke_status["step_a_exit_zero_required"] is True
    assert smoke_status["step_a_complete_exact_result_required"] is True
    assert smoke_status["step_b_separate_operator_authorization_required"] is True
    assert smoke_status["step_b_must_begin_immediately_after_step_a_review"] is True
    assert smoke_status["delay_or_interruption_requires_step_a_rerun"] is True
    assert (
        smoke_status[
            "intervening_source_config_artifact_ledger_output_secret_or_shell_env_change_allowed"
        ]
        is False
    )
    assert smoke_status["normal_provider_free_preflight_currently_emitted"] is False
    assert smoke_status["historical_operator_paid_smoke_run"] is True
    assert smoke_status["historical_operator_paid_smoke_succeeded"] is False
    assert smoke_status["historical_operator_paid_smoke_model_completion_requests"] == 1
    assert smoke_status["historical_operator_paid_smoke_provider_completions"] == 1
    assert smoke_status["historical_operator_paid_smoke_authenticated_metadata_get_count"] is None
    assert smoke_status["historical_operator_paid_smoke_reserved_usd"] == "0.0547272"
    assert smoke_status["historical_operator_paid_smoke_spend_usd"] == "0.01680888"
    assert smoke_status["historical_operator_paid_smoke_accounted_cost_usd"] == "0.01680888"
    assert smoke_status["historical_operator_paid_smoke_ledger_entry_status"] == "reconciled"
    assert smoke_status["historical_operator_paid_smoke_ledger_empty"] is False
    assert smoke_status["historical_operator_paid_smoke_bundle_published"] is False
    assert smoke_status["historical_operator_paid_smoke_verifier_run"] is False
    assert smoke_status["historical_operator_paid_smoke_authenticated_metadata_egress"] is True
    assert smoke_status["historical_operator_paid_smoke_failure"] == (
        "model returned invalid structured data (SCHEMA_VALIDATION_FAILED)"
    )
    assert smoke_status["historical_operator_paid_smoke_failure_phase"] == (
        "STRICT_STRUCTURED_OUTPUT_SCHEMA_VALIDATION"
    )
    assert smoke_status["historical_operator_paid_smoke_failure_cause"] == (
        "SELECTED_CANDIDATE_ROUTE_LACKS_NATIVE_STRUCTURED_OUTPUTS"
    )
    assert smoke_status["historical_operator_paid_smoke_fields_scope"] == (
        "HISTORICAL_FIRST_CHARGED_PAID_ATTEMPT_RETAINED_UNCHANGED"
    )
    assert not any(key.startswith("operator_paid_smoke_") for key in smoke_status)
    assert smoke_status["current_paid_smoke_authorization_status"] == (
        "NOT_AUTHORIZED_ZERO_CURRENT_COMMANDS_POST_C627F2D_INDEX_19_OPERATOR_REPORTED_"
        "VALID_NONCREDITING_NONAUTHORIZING_OFFLINE_REPLAY_NEXT_INDEX_NOT_STATED"
    )
    assert smoke_status["last_reconciled_offline_verifier_status"] == (
        "OPERATOR_REPORTED_VALID_NONCREDITING_NONAUTHORIZING_POST_C627F2D_NO_RERUN_NO_NEW_SPEND"
    )
    assert (
        smoke_status["last_reconciled_offline_verifier_result_independently_authenticated_by_codex"]
        is False
    )
    assert smoke_status["historical_pre_c627_offline_verifier_status"] == (
        "ATTEMPTED_FAILED_SAFE_CANONICAL_REPLAY_NO_PASS_CREDIT"
    )
    assert smoke_status["post_c627_offline_replay_provider_calls"] == 0
    assert smoke_status["post_c627_offline_replay_ledger_mutated"] is False
    assert "provider_calls" not in smoke_status
    assert "ledger_mutated" not in smoke_status
    assert smoke_status["historical_paid_smoke_attempt_9_status"] == (
        "FAILED_SAFE_AFTER_CANDIDATE_TRANSPORT_GENERATION_METADATA_INVALID_AND_MISSING_"
        "USAGE_VALIDATION_R9_RECONCILED_NO_BUNDLE"
    )
    assert smoke_status["historical_paid_smoke_attempt_9_run_index"] == 9
    assert smoke_status["historical_paid_smoke_attempt_9_request_id"] == (
        "authrunner.smoke.r9.candidate.primary:"
        "721f058726cf9509c07cb2aae662fb6ac23b5c30a363db40229faf8895034497"
    )
    assert smoke_status["historical_operator_paid_smoke_group_run_indexes"] == [14, 15, 16]
    assert smoke_status["historical_operator_paid_smoke_group_status"] == (
        "POST_3A1246D_INDEX_16_CHARGED_FAILED_SAFE_AT_IDENTITY_REQUIRED_PROVIDER_"
        "PARAMETERS_BEFORE_IMMUTABLE_IDENTITY_CUSTODY"
    )
    assert (
        smoke_status["historical_operator_paid_smoke_group_per_run_cost_mapping_available"] is True
    )
    assert smoke_status["historical_operator_paid_smoke_group_run_status"] == (
        "charged_terminal_statuses_not_stated"
    )
    assert smoke_status["historical_operator_paid_smoke_group_usage_diagnostics"] == (
        "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
    )
    assert smoke_status["historical_operator_paid_smoke_group_index_14_cost_usd"] == "0.004044"
    assert smoke_status["historical_operator_paid_smoke_group_index_15_cost_usd"] == "0.008478"
    assert smoke_status["historical_operator_paid_smoke_group_index_16_cost_usd"] == "0.006281"
    assert smoke_status["historical_operator_paid_smoke_group_ledger_entry_count"] == 16
    assert smoke_status["historical_operator_paid_smoke_group_ledger_total_usd"] == "0.151976"
    assert smoke_status["historical_operator_paid_smoke_group_ledger_reserved_usd"] is None
    assert smoke_status["historical_operator_paid_smoke_group_ledger_remaining_usd"] is None
    assert smoke_status["historical_operator_paid_smoke_group_bundle_published"] is None
    assert smoke_status["maximum_assurance_json_repair_attempts"] == 0
    assert smoke_status["certification_model_output_repair_allowed"] is False
    assert smoke_status["repaired_output_creditable"] is False
    assert smoke_status["native_structured_output_eligibility_checkpoint"] == (
        NATIVE_STRUCTURED_OUTPUT_GATE_CHECKPOINT
    )
    assert smoke_status["native_structured_output_eligibility_checkpoint_pushed"] is False
    assert smoke_status["native_structured_output_eligibility_checkpoint_remote_verified"] is False
    assert smoke_status["origin_custody_code_fix_status"] == (
        "IMPLEMENTED_CHECKPOINTED_PUSHED_REMOTE_VERIFIED_NONAUTHORIZING"
    )
    assert smoke_status["token_budget_parity_fix_checkpoint"] == (
        "59f9f40a97dce41a16fb3ab9243b4d8588bcf3cb"
    )
    assert smoke_status["historical_component_validation_scope"] == (
        "HISTORICAL_CHECKPOINT_LOCAL_VALIDATIONS_NOT_CURRENT_7EF4717_VALIDATION_OR_REPOSITORY_"
        "FULL_SUITE_CREDIT"
    )
    assert (
        smoke_status["historical_token_budget_parity_fix_validation"][
            "owner_five_file_tests_passed"
        ]
        == 136
    )
    assert (
        smoke_status["historical_token_budget_parity_fix_validation"]["root_five_file_tests_passed"]
        == 136
    )
    assert (
        smoke_status["historical_token_budget_parity_fix_validation"]["independent_tests_passed"]
        == 122
    )
    assert (
        smoke_status["historical_token_budget_parity_fix_validation"][
            "focused_cli_ordering_tests_passed"
        ]
        == 7
    )
    assert (
        smoke_status["historical_origin_custody_fix_validation"][
            "terminal_full_suite_status_for_current_reconciliation"
        ]
        == "INTERRUPTED_CONCURRENT_OPERATOR_EVIDENCE_CHANGE_NO_CREDIT"
    )
    assert (
        smoke_status["historical_origin_custody_fix_validation"][
            "terminal_full_suite_tests_passed_before_interruption"
        ]
        == 82
    )
    assert (
        smoke_status["historical_origin_custody_fix_validation"][
            "terminal_full_suite_prerequisite_skips_before_interruption"
        ]
        == 13
    )
    cascade_validation = smoke_status["historical_revocation_cascade_fix_validation"]
    assert cascade_validation["checkpoint"] == "692eb173f002818b4434b746c8801b4cbeb852e2"
    assert cascade_validation["root_focused_tests_passed"] == 229
    assert cascade_validation["root_adjacent_tests_passed"] == 266
    assert cascade_validation["campaign_revoker_pid_bound"] is True
    assert cascade_validation["generation_revoker_pid_bound"] is True
    assert cascade_validation["parent_cascade"] is True
    assert cascade_validation["traceback_safe_execution_handoff"] is True
    assert cascade_validation["smoke_candidate_generation_immediate_revoke"] is True
    assert cascade_validation["smoke_judge_generation_immediate_revoke"] is True
    assert cascade_validation["tracked_python_format_files_unchanged"] == 510
    assert cascade_validation["strict_mypy_source_files"] == 206
    assert cascade_validation["independent_review"] == "CLEAN_NO_BLOCKER_OR_HIGH"
    for former_unscoped_validation_key in (
        "origin_custody_fix_validation",
        "token_budget_parity_fix_validation",
        "live_route_preflight_validation",
        "revocation_cascade_fix_validation",
        "validation",
    ):
        assert former_unscoped_validation_key not in smoke_status
    assert exact_status["status"] == (
        "PARTIAL_C627F2D_INDEX_19_OPERATOR_REPORTED_VALID_NONCREDITING_NONAUTHORIZING_"
        "ZERO_CURRENT_COMMANDS_REAL_BLOCKED_SAFETY"
    )
    assert exact_status["ticket_status"] == "PARTIAL"
    assert exact_status["autorun_status"] == (
        "PAUSED_AFTER_C627F2D_INDEX_19_OPERATOR_REPORTED_VALID_NONCREDITING_"
        "NONAUTHORIZING_OFFLINE_REPLAY_ZERO_CURRENT_COMMANDS_NEXT_INDEX_NOT_STATED"
    )
    assert exact_status["historical_component_validation_scope"] == (
        "HISTORICAL_CHECKPOINT_LOCAL_VALIDATIONS_NOT_CURRENT_7EF4717_VALIDATION_OR_REPOSITORY_"
        "FULL_SUITE_CREDIT"
    )
    assert (
        exact_status["historical_reasoning_selection_checkpoint_validation"][
            "final_combined_affected_tests_passed"
        ]
        == 433
    )
    assert (
        exact_status["historical_tencent_lineage_reseal_validation"][
            "current_root_affected_tests_passed"
        ]
        == 120
    )
    assert (
        exact_status["historical_origin_custody_fix_checkpoint_validation"][
            "implementer_tests_passed"
        ]
        == 584
    )
    assert (
        exact_status["historical_token_budget_parity_fix_checkpoint_validation"][
            "owner_five_file_tests_passed"
        ]
        == 136
    )
    assert (
        exact_status["historical_live_route_preflight_checkpoint_validation"]["owner_tests_passed"]
        == 164
    )
    assert exact_status["historical_post_origin_fix_guide_state"] == (
        "CHECKPOINTED_PUSHED_REMOTE_VERIFIED_PREFLIGHT_VALID_NONAUTHORIZING"
    )
    for former_unscoped_validation_key in (
        "reasoning_selection_checkpoint_validation",
        "tencent_lineage_reseal_validation",
        "origin_custody_fix_checkpoint_validation",
        "token_budget_parity_fix_checkpoint_validation",
        "live_route_preflight_checkpoint_validation",
        "post_origin_fix_guide_state",
    ):
        assert former_unscoped_validation_key not in exact_status
    assert exact_status["paid_smoke_real_command_status"] == (
        "ABSENT_ZERO_CURRENT_COMMANDS_POST_C627F2D_INDEX_19_OPERATOR_REPORTED_VALID_"
        "NONCREDITING_NONAUTHORIZING_OFFLINE_REPLAY_NEXT_INDEX_NOT_STATED_NO_PAID_AUTHORITY"
    )
    assert exact_status["offline_smoke_verifier_command_status"] == (
        "HISTORICAL_OPERATOR_EXECUTED_LAST_RECONCILED_RESULT_REPORTED_VALID_NONCREDITING_"
        "NONAUTHORIZING_ZERO_CURRENT_COMMANDS"
    )
    assert exact_status["real_command_emission_authorized_for_operator_review"] is False
    revocation_fix = exact_status["revocation_cascade_fix"]
    assert revocation_fix["acceptance_requirement"] == (
        "REVOCATION_INVALIDATES_EVERY_DOWNSTREAM_CONSUMER"
    )
    assert revocation_fix["top_level_runner_lease_revoked"] is True
    assert revocation_fix["retained_campaign_capabilities_explicitly_revoked"] is True
    assert revocation_fix["retained_generation_capabilities_explicitly_revoked"] is True
    assert revocation_fix["current_gap"] is None
    assert revocation_fix["traceback_safe_execution_handoff"] is True
    assert revocation_fix["smoke_candidate_and_judge_generation_capabilities_immediately_revoked"]
    assert revocation_fix["root_focused_tests_passed"] == 229
    assert revocation_fix["root_adjacent_tests_passed"] == 266
    assert revocation_fix["independent_review"] == "CLEAN_NO_BLOCKER_OR_HIGH"
    assert revocation_fix["provider_or_private_execution_required"] is False
    assert revocation_fix["real_path_status"] == (
        "BLOCKED_SAFETY_POSITIVE_OWNED_REAL_PARENT_UNVALIDATED"
    )
    historical_selection = exact_status["historical_ineligible_gemma_selection_and_r7_capture"]
    assert historical_selection["selection_plan_sha256"] == (
        HISTORICAL_INELIGIBLE_GEMMA_PLAN_SHA256
    )
    assert historical_selection["selection_plan_checkpoint_commit"] == (
        HISTORICAL_INELIGIBLE_GEMMA_CHECKPOINT
    )
    assert historical_selection["selection_plan_checkpoint_status"] == (
        "HISTORICAL_INELIGIBLE_LOCAL_COMMIT_NOT_PUSHED_OR_REMOTE_RESOLVED"
    )
    assert historical_selection["selection_plan_schema_version"] == "1.1"
    assert historical_selection["required_output_mode"] == "NATIVE_JSON_SCHEMA"
    assert historical_selection["required_supported_parameters"] == ["structured_outputs"]
    assert historical_selection["candidate_endpoint_tag"] == "fireworks"
    assert historical_selection["primary_model_id"] == "google/gemma-4-26b-a4b-it"
    assert historical_selection["primary_endpoint_tag"] == "deepinfra/fp8"
    plan_entries = {entry["exact_model_id"]: entry for entry in selection_plan["entries"]}
    assert (
        historical_selection["primary_entry_sha256"]
        == plan_entries["google/gemma-4-26b-a4b-it"]["entry_sha256"]
    )
    assert historical_selection["primary_entry_priority_rank"] == 12
    assert plan_entries["tencent/hy3"]["priority_rank"] == 10
    assert historical_selection["role_assignment_sha256"] == HISTORICAL_INELIGIBLE_GEMMA_ROLE_SHA256
    assert historical_selection["operator_results_binding_status"] == (
        "UNRESOLVED_NONAUTHORIZING_LAST_RECONCILED_RECORD"
    )
    assert historical_selection["replay_endpoint_tag"] == "together"
    assert historical_selection["candidate_registry_generation"] == "r7"
    assert historical_selection["candidate_registry"] == "candidate-registry-r7.json"
    assert historical_selection["candidate_discovery_run"] == "authrunner-candidate-20260821-r7"
    assert historical_selection["candidate_frozen_sha256"] == (
        "57b0e8fa7dfd4919fc720c25ba9dfa414a8e466605f8c0f8cbc286df5ea2b9db"
    )
    assert historical_selection["primary_registry_generation"] == "r7"
    assert historical_selection["replay_registry_generation"] == "r7"
    assert historical_selection["fresh_route_registries_present"] is True
    assert historical_selection["fresh_candidate_registry_present"] is True
    assert historical_selection["operationally_viable"] is False
    assert historical_selection["normal_provider_free_preflight_command_currently_emitted"] is False
    assert historical_selection["current_live_route_preflight_command_emitted"] is False
    assert historical_selection["current_paid_smoke_command_emitted"] is False
    historical_dcabe = exact_status["historical_dcabe_selection_plan_checkpoint"]
    assert historical_dcabe["status"] == (
        "HISTORICAL_NONAUTHORIZING_SELECTION_PLAN_CUSTODY_WITH_HISTORICAL_DCABE_ROUTE_EVIDENCE_ONLY"
    )
    assert historical_dcabe["route_evidence_scope"] == (
        "HISTORICAL_DCABE_PLAN_BOUND_SNAPSHOT_NOT_CURRENT_ROUTE_FRESHNESS_OR_COMMAND"
    )
    assert historical_dcabe["selection_plan_sha256"] == (
        "ecb8f621846fec735de5f541f6fc7a28f40b0bdac8c49dbbd57e37384e18b71f"
    )
    assert historical_dcabe["selection_plan_schema_version"] == "1.3"
    assert historical_dcabe["checkpoint_commit"] == HISTORICAL_DCABE_SELECTION_CHECKPOINT
    assert historical_dcabe["checkpoint_status"] == ("LOCAL_COMMIT_NOT_PUSHED_OR_REMOTE_RESOLVED")
    assert historical_dcabe["historical_dcabe_plan_bound_candidate_registry"] == (
        "candidate-registry-r9.json"
    )
    assert historical_dcabe["historical_dcabe_plan_bound_candidate_discovery_run"] == (
        "authrunner-candidate-20260822-r9"
    )
    assert historical_dcabe["historical_dcabe_plan_bound_candidate_frozen_sha256"] == (
        "cc65071ef3723fc075b958aec4ad0180cdc99dc853d19b3a7983015f7e1c34ad"
    )
    assert historical_dcabe["replay_route_selection_mode"] == (
        "EXPLICIT_OPERATOR_CHOICE_NO_AUTOMATIC_FALLBACK"
    )
    assert historical_dcabe["operator_results_binding_status"] == (
        "BOUND_NONAUTHORIZING_HISTORICAL_PLAN_RECORD"
    )
    assert historical_dcabe["operator_results_binding_sha256"] == (
        "302679f3e8e9281cdf9e0ec3d6d1d566d172cb54b389fbac607180d1f0911940"
    )
    assert (
        historical_dcabe["last_reconciled_operator_results_sha256"]
        == LAST_RECONCILED_OPERATOR_RESULTS_SHA256
    )
    assert historical_dcabe["historical_dcabe_plan_bound_live_route_status"] == (
        "ABSENT_AT_DCABE_PLAN_BOUNDARY_R10_R8_R8_GATE_NOT_CURRENT_FRESHNESS"
    )
    assert historical_dcabe["operator_command_emitted_by_dcabe_plan_checkpoint"] is False
    assert historical_dcabe["authority"] is False

    current_successor = exact_status["current_selection_plan_checkpoint"]
    assert current_successor["status"] == "CURRENT_V1_4_NONAUTHORIZING_PLANCONSTRAINTS_CUSTODY"
    assert current_successor["route_evidence_scope"] == (
        "PROVIDER_FREE_STATIC_AND_REPLAY_CUSTODY_NOT_CURRENT_PROVIDER_ROUTE_FRESHNESS_"
        "COMMAND_OR_AUTHORITY"
    )
    assert (
        current_successor["selection_plan_raw_sha256"]
        == hashlib.sha256(SELECTION_PLAN_PATH.read_bytes()).hexdigest()
    )
    assert current_successor["selection_plan_sha256"] == selection_plan["plan_sha256"]
    assert current_successor["selection_plan_sha256"] == (
        CURRENT_NONAUTHORIZING_SUCCESSOR_PLAN_SHA256
    )
    assert current_successor["selection_plan_schema_version"] == "1.4"
    assert current_successor["checkpoint_commit"] == HISTORICAL_PLANCONSTRAINTS_BASE_CHECKPOINT
    assert current_successor["checkpoint_parent"] == (
        HISTORICAL_PLANCONSTRAINTS_BASE_PARENT_CHECKPOINT
    )
    assert current_successor["checkpoint_status"] == "LOCAL_COMMIT_NOT_PUSHED_OR_REMOTE_RESOLVED"
    assert current_successor["checkpoint_pushed"] is False
    assert current_successor["checkpoint_remote_resolved"] is False
    assert current_successor["role_assignment_sha256"] == (
        CURRENT_NONAUTHORIZING_SUCCESSOR_ROLE_SHA256
    )
    assert (
        current_successor["role_assignment_sha256"]
        == (selection_plan["authenticated_runner_selection"]["role_assignment_sha256"])
    )
    assert (
        current_successor["route_predicate_profile_sha256"]
        == (
            selection_plan["authenticated_runner_selection"]["route_predicate_profile"][
                "profile_sha256"
            ]
        )
    )
    assert current_successor["route_predicate_count"] == 29
    assert current_successor["required_output_mode"] == "NATIVE_JSON_SCHEMA"
    assert current_successor["required_supported_parameters"] == ["structured_outputs"]
    assert current_successor["required_reasoning_effort"] == "high"
    assert current_successor["required_completion_limit_source"] == "metadata"
    assert current_successor["required_completion_tokens"] == 8192
    assert current_successor["required_output_tokens"] == 4096
    assert current_successor["reserved_reasoning_tokens"] == 4096
    assert current_successor["candidate_model_id"] == "deepseek/deepseek-v4-pro-0813"
    assert current_successor["candidate_endpoint_tag"] == "parasail/fp8"
    assert current_successor["primary_model_id"] == "z-ai/glm-5.2"
    assert current_successor["primary_endpoint_tag"] == "sail-research/fp8"
    assert current_successor["replay_model_id"] == "moonshotai/kimi-k3"
    assert current_successor["replay_allowed_endpoint_tags"] == ["modal/mxfp4", "phala"]
    assert current_successor["replay_route_selection_mode"] == (
        "EXPLICIT_EXACT_ROUTE_NO_AUTOMATIC_FALLBACK"
    )
    assert current_successor["empirical_schema_conformance_disposition"] == "UNAVAILABLE"
    assert current_successor["token_detail_convention_disposition"] == "UNAVAILABLE"
    assert current_successor["full_admission_authorized"] is False
    assert current_successor["operator_command_emitted_by_checkpoint"] is False
    assert current_successor["authority"] is False
    assert "historical_full_r2_r5_r2_candidate_admission" in exact_status
    assert exact_status["zero_command_evidence_checkpoint"] == (
        "02ed5bef89d094e0d0c4852e1bf73914d9960c6b"
    )
    assert exact_status["historical_paid_diagnostic_last_durable_pushed_checkpoint"] == (
        HISTORICAL_PAID_DIAGNOSTIC_BASE_CHECKPOINT
    )
    assert "last_durable_pushed_checkpoint" not in exact_status
    assert exact_status["historical_paid_diagnostic_base_checkpoint"] == (
        HISTORICAL_PAID_DIAGNOSTIC_BASE_CHECKPOINT
    )
    assert exact_status["historical_ineligible_gemma_plan_checkpoint"] == (
        HISTORICAL_INELIGIBLE_GEMMA_CHECKPOINT
    )
    assert exact_status["historical_ineligible_gemma_plan_checkpoint_pushed"] is False
    assert exact_status["historical_ineligible_gemma_plan_checkpoint_remote_verified"] is False
    assert exact_status["historical_dcabe_selection_plan_candidate_successor_checkpoint"] == (
        HISTORICAL_DCABE_SELECTION_CHECKPOINT
    )
    assert exact_status[
        "historical_dcabe_selection_plan_candidate_successor_checkpoint_status"
    ] == ("LOCAL_COMMIT_NOT_PUSHED_OR_REMOTE_RESOLVED")
    assert "candidate_successor_checkpoint" not in exact_status
    assert "candidate_successor_checkpoint_status" not in exact_status
    assert exact_status["historical_revocation_cascade_validation_status"] == (
        "PASS_PROVIDER_FREE_REVOCATION_CASCADE_FIX_CLEAN_REAL_BLOCKED_SAFETY"
    )
    assert "validation_status" not in exact_status
    assert exact_status["historical_paid_diagnostic_guide_base_checkpoint"] == (
        HISTORICAL_PAID_DIAGNOSTIC_BASE_CHECKPOINT
    )
    assert exact_status["historical_paid_diagnostic_guide_base_pushed"] is True
    assert exact_status["historical_paid_diagnostic_guide_base_remote_resolved"] is True
    assert (
        "ZERO_CURRENT_METADATA_DISCOVERY_SMOKE_VERIFIER"
        in exact_status["historical_paid_diagnostic_guide_base_scope"]
    )
    structured_output_eligibility = exact_status[
        "native_structured_output_eligibility_implementation"
    ]
    assert structured_output_eligibility["checkpoint_commit"] == (
        NATIVE_STRUCTURED_OUTPUT_GATE_CHECKPOINT
    )
    assert structured_output_eligibility["checkpoint_pushed"] is False
    assert structured_output_eligibility["checkpoint_remote_resolved"] is False
    assert structured_output_eligibility["fails_before_secret_selection"] is True
    assert structured_output_eligibility["fails_before_provider_dispatch"] is True
    assert structured_output_eligibility["fails_before_ledger_reservation"] is True
    assert structured_output_eligibility["authority"] is False
    completion_capacity = exact_status["historical_completion_capacity_invariant_origin"]
    assert completion_capacity["current_invariant_status"] == (
        "ACTIVE_FAIL_CLOSED_EXPLICIT_METADATA_COMPLETION_CAPACITY_REQUIRED"
    )
    assert completion_capacity["route_evidence_scope"] == (
        "HISTORICAL_3975_ORIGIN_PLAN_ROUTES_NOT_CURRENT_SELECTION"
    )
    assert completion_capacity["checkpoint_commit"] == HISTORICAL_COMPLETION_CAPACITY_CHECKPOINT
    assert completion_capacity["lineage_reseal_checkpoint"] == CURRENT_LINEAGE_RESEAL_CHECKPOINT
    assert completion_capacity["selection_plan_schema_version"] == "1.3"
    assert completion_capacity["selection_plan_sha256"] == (
        "4e6c744559b1cc49c8ede590c868df103a10402d429d5e5d02cf4f429e0f3a66"
    )
    assert completion_capacity["selection_plan_required_completion_limit_source"] == "metadata"
    assert completion_capacity["historical_origin_plan_candidate_endpoint_tag"] == "parasail/fp8"
    assert completion_capacity["historical_origin_plan_primary_endpoint_tag"] == (
        "sail-research/fp8"
    )
    assert completion_capacity["historical_origin_plan_replay_endpoint_tag"] == "wafer"
    assert completion_capacity["fails_before_secret_selection"] is True
    assert completion_capacity["fails_before_provider_dispatch"] is True
    assert completion_capacity["fails_before_ledger_reservation"] is True
    assert completion_capacity["operator_command_emitted_by_origin_checkpoint"] is False
    assert completion_capacity["authority"] is False
    replay_successor = exact_status["historical_dcabe_selection_plan_replay_allowlist"]
    assert replay_successor["route_evidence_scope"] == (
        "HISTORICAL_PRE_C627_PLAN_BOUND_NO_POST_C627_METADATA_OR_PROVIDER_PROOF"
    )
    assert replay_successor["checkpoint_commit"] == HISTORICAL_DCABE_SELECTION_CHECKPOINT
    assert replay_successor["selection_plan_sha256"] == (
        "ecb8f621846fec735de5f541f6fc7a28f40b0bdac8c49dbbd57e37384e18b71f"
    )
    assert replay_successor["replay_allowed_endpoint_tags"] == ["modal/mxfp4", "phala"]
    assert replay_successor["explicit_operator_route_choice_required"] is True
    assert replay_successor["automatic_fallback_allowed"] is False
    assert replay_successor["historical_dcabe_selected_replay_required_additional_discovery"] is (
        False
    )
    assert replay_successor["historical_dcabe_operator_selected_replay_endpoint_tag"] == (
        "modal/mxfp4"
    )
    assert replay_successor["historical_dcabe_operator_selection_operator_reported"] is True
    assert (
        replay_successor["historical_dcabe_operator_selection_independently_authenticated_by_codex"]
        is False
    )
    assert replay_successor["historical_dcabe_operator_selection_is_current_route_freshness"] is (
        False
    )
    assert "plan_selected_replay_endpoint_tag" not in replay_successor
    assert replay_successor["historical_dcabe_plan_bound_replay_frozen_sha256"] == (
        "75451839c72020a5e34c2f21a433e420f79c6db3e7238adb808e1c382af348f8"
    )
    assert replay_successor["historical_pre_c627_r8_r8_r8_live_route_gate_valid"] is True
    assert replay_successor["operator_command_emitted_by_selection_plan_checkpoint"] is False
    assert "r8_r8_r8_live_route_gate_valid" not in replay_successor
    assert replay_successor["unselected_replay_seed_requiring_fresh_discovery_if_selected"] == (
        "phala"
    )
    assert replay_successor["authority"] is False
    assert runtime_status["last_validation"]["terminal_full_suite_run"] is False
    assert runtime_status["last_validation"]["terminal_full_suite_attempt_started"] is False
    assert runtime_status["last_validation"]["status"] == (
        "V3_TRUNCATION_001_SPECIALIST_ROLE_RECOVERY_SLICE_COMPLETE_TICKET_PARTIAL_PROVIDER_FREE_"
        "NONAUTHORIZING_RECURSIVE_CHILD_RECOVERY_PENDING_MAXIMUM_ASSURANCE_INCONCLUSIVE"
    )
    assert "92 PASS" in runtime_status["last_validation"]["command"]
    assert "4 PASS" in runtime_status["last_validation"]["command"]
    assert "2 PASS" in runtime_status["last_validation"]["command"]
    assert "1 PASS" in runtime_status["last_validation"]["command"]
    assert "162 PASS" in runtime_status["last_validation"]["command"]
    assert "INCONCLUSIVE after 602.86 seconds" in runtime_status["last_validation"]["command"]
    assert (
        "V3-TRUNCATION-001 remains PARTIAL after exact 16-path provider-free specialist recovery "
        f"checkpoint {CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT}"
        in runtime_status["last_validation"]["result"]
    )
    assert (
        "Private successful specialist children use schema v1.2"
        in runtime_status["last_validation"]["result"]
    )
    assert (
        "public recovery request evidence uses v1.1 and exposes only that hash"
        in runtime_status["last_validation"]["result"]
    )
    assert (
        "only live REAL promotion with exact revalidated usage can produce specialist credit"
        in runtime_status["last_validation"]["result"]
    )
    assert (
        "two successful child terminals remain unpromoted and noncrediting"
        in runtime_status["last_validation"]["result"]
    )
    assert "resume performs zero transport" in runtime_status["last_validation"]["result"]
    assert (
        "Recursive recovery-child consumption and positive nonempty full-pipeline REAL promotion "
        "remain absent" in runtime_status["last_validation"]["result"]
    )
    assert (
        "Historical 425502c PLANCONSTRAINTS repair" in runtime_status["last_validation"]["result"]
    )
    assert "7ef4717 implementation base" in runtime_status["last_validation"]["result"]
    assert "c627f2d AUTHRUNNER replay" in runtime_status["last_validation"]["result"]
    assert runtime_status["last_validation"]["maximum_assurance_attempt"] == {
        "status": "INCONCLUSIVE_NO_TERMINAL_RESULT_NO_PASS_CREDIT",
        "elapsed_seconds": 602.86,
        "terminal_result_available": False,
        "pass_credit": False,
    }
    terminal_full_suite_attempt = runtime_status["last_validation"][
        "historical_planconstraints_terminal_full_suite_attempt"
    ]
    assert terminal_full_suite_attempt == {
        "command": ".venv/bin/pytest -q",
        "status": "INCOMPLETE_PREEXISTING_DETERMINISTIC_FAILURE_NO_PASS_CREDIT",
        "elapsed_seconds": 3878.41,
        "passed_before_failure": 1492,
        "skipped_before_failure": 25,
        "failed": 1,
        "failure": (
            "tests/unit/test_candidate_benchmark.py::"
            "test_authenticated_runner_candidate_consumes_exact_cost_preview_inventory"
        ),
        "failure_message": "candidate benchmark request accounting is inconsistent",
        "underlying_context": (
            "benchmark cases reported ReasoningPolicyError with zero observed usage"
        ),
        "same_failure_reproduced_on_untouched_parent": (
            AUTHRUNNER_RECEIPT_COMPOSITE_PARENT_CHECKPOINT
        ),
        "introduced_by_receipt_composite_checkpoint": False,
        "terminal_full_suite_pass_credit": False,
    }
    historical_scheduler_recovery = runtime_status["historical_scheduler_full_suite_recovery"]
    assert historical_scheduler_recovery["scope"] == (
        "HISTORICAL_SCHEDULER_RECOVERY_COMPONENT_EVIDENCE_NOT_CURRENT_7EF4717_REPOSITORY_"
        "FULL_SUITE_CREDIT"
    )
    assert historical_scheduler_recovery["status"] == "HISTORICAL_COMPLETE_COMPONENT"
    assert "exact normalized tree passed 4401 tests" in historical_scheduler_recovery["remaining"]
    assert "scheduler_full_suite_recovery" not in runtime_status
    historical_policy_validation = runtime_status["historical_policy_eligibility_core_validation"]
    assert historical_policy_validation["scope"] == (
        "HISTORICAL_POLICY_ELIGIBILITY_COMPONENT_VALIDATION_NOT_CURRENT_7EF4717_REPOSITORY_"
        "FULL_SUITE_CREDIT"
    )
    assert historical_policy_validation["status"] == ("HISTORICAL_COMPLETE_PROVIDER_FREE_MECHANISM")
    assert "5155 tests passed" in historical_policy_validation["result"]
    assert "policy_eligibility_core_validation" not in runtime_status
    assert terminal_full_suite_attempt["terminal_full_suite_pass_credit"] is False
    historical_base_validation = exact_status["historical_base_checkpoint_validation"]
    assert historical_base_validation["scope"] == (
        "HISTORICAL_F6ACF206_CHECKPOINT_LOCAL_VALIDATION_NOT_CURRENT_7EF4717_REPOSITORY_"
        "FULL_SUITE_CREDIT"
    )
    assert historical_base_validation["terminal_full_unit_tests_passed"] == 5989
    historical_cache_validation = exact_status["historical_cache_dominance_checkpoint_validation"]
    assert historical_cache_validation["scope"] == (
        "HISTORICAL_FD1459B_CHECKPOINT_LOCAL_VALIDATION_NOT_CURRENT_7EF4717_REPOSITORY_"
        "FULL_SUITE_CREDIT"
    )
    assert historical_cache_validation["terminal_full_suite_tests_passed"] == 6230
    assert historical_cache_validation["terminal_full_suite_exit_code"] == 0
    assert "base_checkpoint_validation" not in exact_status
    assert "cache_dominance_checkpoint_validation" not in exact_status
    historical_full_suite_attempt = exact_status[
        "historical_command_guide_successor_full_suite_attempt"
    ]
    assert historical_full_suite_attempt["scope"] == (
        "HISTORICAL_COMMAND_GUIDE_SUCCESSOR_ATTEMPT_NOT_CURRENT_7EF4717_REPOSITORY_FULL_SUITE_CREDIT"
    )
    assert historical_full_suite_attempt["command"] == ".venv/bin/pytest -q"
    assert historical_full_suite_attempt["started_before_final_governance_bytes"] is True
    assert historical_full_suite_attempt["status"] == (
        "INTENTIONALLY_INTERRUPTED_NO_TERMINAL_PASS_CREDIT"
    )
    assert historical_full_suite_attempt["displayed_progress_percent"] == 2
    assert historical_full_suite_attempt["visible_skips"] == 6
    assert historical_full_suite_attempt["interrupted_during_test"] == (
        "test_scheduler_accepts_default_in_repository_private_output_exclusion"
    )
    assert historical_full_suite_attempt["exit_code"] == 130
    assert historical_full_suite_attempt["passed_test_count_printed"] is False
    assert historical_full_suite_attempt["terminal_full_suite_pass_credit"] is False
    assert "passed_test_count" not in historical_full_suite_attempt
    assert "command_guide_successor_full_suite_attempt" not in exact_status
    assert post_token_budget_preflight["operator_results_sha256"] == (
        "76eff45c95116dea28cdaad78115d3926c6da3674a6b322784203335bfef7465"
    )
    assert post_token_budget_preflight["operator_results_bytes"] == 41_806
    assert post_token_budget_preflight["operator_results_lines"] == 756
    historical_charged_smoke = exact_status["historical_first_charged_paid_smoke_attempt"]
    assert historical_charged_smoke["checkpoint_commit"] == (
        HISTORICAL_PAID_DIAGNOSTIC_BASE_CHECKPOINT
    )
    assert historical_charged_smoke["operator_results_sha256"] == (
        HISTORICAL_PAID_DIAGNOSTIC_OPERATOR_RESULTS_SHA256
    )
    assert historical_charged_smoke["operator_results_bytes"] == 54_081
    assert historical_charged_smoke["operator_results_lines"] == 979
    assert historical_charged_smoke["authenticated_metadata_egress"] is True
    assert historical_charged_smoke["provider_completions"] == 1
    assert historical_charged_smoke["model_completion_requests"] == 1
    assert historical_charged_smoke["reserved_usd"] == "0.0547272"
    assert historical_charged_smoke["operator_reported_campaign_spend_usd"] == "0.01680888"
    assert historical_charged_smoke["accounted_cost_usd"] == "0.01680888"
    assert historical_charged_smoke["ledger_entry_status"] == "reconciled"
    assert historical_charged_smoke["operator_reported_campaign_ledger_empty"] is False
    assert historical_charged_smoke["bundle_published"] is False
    assert historical_charged_smoke["offline_verifier_run"] is False
    assert historical_charged_smoke["failure"] == (
        "model returned invalid structured data (SCHEMA_VALIDATION_FAILED)"
    )
    assert historical_charged_smoke["failure_phase"] == (
        "STRICT_STRUCTURED_OUTPUT_SCHEMA_VALIDATION"
    )
    assert historical_charged_smoke["failure_cause"] == (
        "SELECTED_CANDIDATE_ROUTE_LACKS_NATIVE_STRUCTURED_OUTPUTS"
    )
    assert historical_charged_smoke["adjacency_status"] == (
        "UNPROVEN_NO_FRESH_IMMEDIATE_POST_B413_STEP_A_RESULT_RECORDED"
    )
    assert historical_charged_smoke["authority"] is False
    historical_paid_smoke_9 = exact_status["historical_paid_smoke_attempt_9"]
    assert historical_paid_smoke_9["checkpoint_commit"] == AUTHRUNNER_IDENTITY_DIAGNOSTIC_CHECKPOINT
    assert historical_paid_smoke_9["operator_results_sha256"] == (
        "efab7ac219c7a4bea4c2cd513f0d3455fff021483d28af1d958b6dd0eb59413d"
    )
    assert historical_paid_smoke_9["operator_results_bytes"] == 95_945
    assert historical_paid_smoke_9["operator_results_lines"] == 1_728
    assert historical_paid_smoke_9["composition"] is None
    assert historical_paid_smoke_9["smoke_run_index"] == 9
    assert (
        "GENERATION_METADATA_INVALID|GENERATION_METADATA_MISSING"
        in (historical_paid_smoke_9["failure"])
    )
    assert historical_paid_smoke_9["failure_phase"] == ("GENERATION_METADATA_IDENTITY_BINDING")
    assert historical_paid_smoke_9["provisional_identity_strength"] == (
        "CANONICAL_MODEL_AND_ENDPOINT_BOUND"
    )
    assert historical_paid_smoke_9["final_identity_strength"] == "UNBOUND"
    assert historical_paid_smoke_9["identity_binding_status"] == "generation_metadata_unbound"
    assert historical_paid_smoke_9["candidate_transport_reached"] is True
    assert historical_paid_smoke_9["per_index_cost_mapping_available"] is False
    assert historical_paid_smoke_9["ledger_entry_status"] == "reconciled"
    assert historical_paid_smoke_9["ledger_entry_count"] == 9
    assert historical_paid_smoke_9["ledger_used_usd"] == "0.10457436"
    assert historical_paid_smoke_9["ledger_reserved_usd"] == "0"
    assert historical_paid_smoke_9["ledger_remaining_usd"] == "249.89542564"
    assert historical_paid_smoke_9["ledger_entry_released_or_reusable"] is False
    assert historical_paid_smoke_9["bundle_published"] is False
    assert historical_paid_smoke_9["authority"] is False
    latest_paid_smoke = exact_status["historical_index_10_paid_smoke_group"]
    assert latest_paid_smoke["operator_results_sha256"] == (
        PRE_RECEIPT_COMPOSITE_LIVE_OPERATOR_RESULTS_SHA256
    )
    assert latest_paid_smoke["reported_run_indexes"] == [10]
    assert latest_paid_smoke["per_run_cost_mapping_available"] is False
    assert latest_paid_smoke["run_status"] == "reconciled"
    assert latest_paid_smoke["usage_diagnostics"] == "NONE"
    assert latest_paid_smoke["exceptional_smoke_diagnostic_code_count"] == 0
    assert latest_paid_smoke["generic_creditability_proven"] is False
    assert latest_paid_smoke["candidate_completion_receipt_cutoff_reached"] is True
    assert latest_paid_smoke["judge_metadata_receipt_cutoff_live_proven"] is False
    assert latest_paid_smoke["candidate_cutoff_precedes_generation_metadata_get"] is True
    assert latest_paid_smoke["candidate_cutoff_precedes_usage_ledger_replacement"] is True
    assert latest_paid_smoke["candidate_cutoff_precedes_origin_marking"] is True
    assert latest_paid_smoke["candidate_cutoff_precedes_generation_verification_capability"] is True
    assert latest_paid_smoke["ledger_entry_count"] == 13
    assert latest_paid_smoke["ledger_total_usd"] == "0.133173"
    assert latest_paid_smoke["ledger_reserved_usd"] is None
    assert latest_paid_smoke["ledger_remaining_usd"] is None
    assert latest_paid_smoke["bundle_published"] is False
    assert latest_paid_smoke["next_unused_run_index"] == 14
    assert latest_paid_smoke["authority"] is False
    historical_aggregate_route = exact_status[
        "historical_aggregate_live_route_preflight_mismatch_event"
    ]
    assert historical_aggregate_route["scope"] == (
        "HISTORICAL_9F5C94D_R6_R6_R2_MISMATCH_EVENT_NOT_CURRENT_ROUTE_FRESHNESS_OR_COMMAND"
    )
    assert historical_aggregate_route["checkpoint_commit"] == (
        "9f5c94d97b3d79d51c10e250b99244591461e959"
    )
    assert "aggregate_live_route_preflight" not in exact_status
    historical_live_route = exact_status["historical_r6_r6_r2_live_route_preflight"]
    assert historical_live_route["operator_results_sha256"] == (
        HISTORICAL_R6_R6_R2_OPERATOR_RESULTS_SHA256
    )
    assert historical_live_route["composition"] == "r6/r6/r2"
    assert historical_live_route["all_three_routes_validated"] is True
    latest_exact_gate = exact_status["historical_r7_live_route_gate"]
    assert latest_exact_gate["operator_results_sha256"] == HISTORICAL_R7_OPERATOR_RESULTS_SHA256
    assert latest_exact_gate["composition"] == "r7/r7/r7"
    assert latest_exact_gate["status"] == (
        "FAILED_SAFE_PRIMARY_REASONING_PROFILE_INCOMPATIBLE_BEFORE_PAID_TRANSPORT"
    )
    assert latest_exact_gate["provider_completions"] == 0
    assert latest_exact_gate["incremental_spend_usd"] == "0"
    assert latest_exact_gate["authority"] is False
    latest_r8_gate = exact_status["historical_r8_completion_capacity_gate"]
    assert latest_r8_gate["operator_results_sha256"] == (
        "5faa33fe1bd5b332e8dffa0b29ed5718886d0c8b22c65cb1dc67b306eba8d00f"
    )
    assert latest_r8_gate["composition"] == "r7/r8/r7"
    assert latest_r8_gate["primary_endpoint_tag"] == "sail-research/fp8"
    assert latest_r8_gate["primary_registry"] == "primary-judge-registry-r8.json"
    assert latest_r8_gate["primary_frozen_sha256"] == (
        "8f3fc274390d983bde683e3039a91f7cb6ead0f4dfa9aa89caa02ecca7e9ed26"
    )
    assert latest_r8_gate["primary_max_completion_tokens"] == 131_072
    assert latest_r8_gate["candidate_max_completion_tokens"] is None
    assert latest_r8_gate["replay_max_completion_tokens"] is None
    assert latest_r8_gate["status"] == (
        "FAILED_SAFE_EXPLICIT_COMPLETION_CAPACITY_REQUIRED_BEFORE_MODEL_COMPLETION"
    )
    assert latest_r8_gate["provider_completions"] == 0
    assert latest_r8_gate["incremental_spend_usd"] == "0"
    assert latest_r8_gate["bundle_published"] is False
    assert latest_r8_gate["authority"] is False
    historical_r8_gate = smoke_status["historical_r8_r8_r8_live_route_gate"]
    assert historical_r8_gate["operator_results_sha256"] == (
        HISTORICAL_R8_GATE_OPERATOR_RESULTS_SHA256
    )
    assert historical_r8_gate["operator_results_bytes"] == 71_771
    assert historical_r8_gate["operator_results_lines"] == 1_276
    assert historical_r8_gate["composition"] == "r8/r8/r8"
    assert historical_r8_gate["replay_endpoint_tag"] == "modal/mxfp4"
    assert historical_r8_gate["replay_frozen_sha256"] == (
        "75451839c72020a5e34c2f21a433e420f79c6db3e7238adb808e1c382af348f8"
    )
    assert historical_r8_gate["logical_metadata_gets"] == 15
    assert historical_r8_gate["maximum_metadata_provider_attempts"] == 30
    assert historical_r8_gate["provider_completions"] == 0
    assert historical_r8_gate["incremental_spend_usd"] == "0"
    assert historical_r8_gate["output_published"] is False
    assert historical_r8_gate["bundle_published"] is False
    assert historical_r8_gate["authority"] is False
    historical_r9_sequence = smoke_status["historical_r9_r8_r8_smoke_sequence"]
    assert historical_r9_sequence["operator_results_sha256"] == (
        "302679f3e8e9281cdf9e0ec3d6d1d566d172cb54b389fbac607180d1f0911940"
    )
    assert historical_r9_sequence["operator_results_bytes"] == 74_562
    assert historical_r9_sequence["operator_results_lines"] == 1_330
    assert historical_r9_sequence["candidate_registry"] == "candidate-registry-r9.json"
    assert historical_r9_sequence["candidate_frozen_sha256"] == (
        "cc65071ef3723fc075b958aec4ad0180cdc99dc853d19b3a7983015f7e1c34ad"
    )
    assert historical_r9_sequence["composition"] == "r9/r8/r8"
    assert historical_r9_sequence["logical_metadata_gets"] == 15
    assert historical_r9_sequence["paid_smoke_status"] == (
        "FAILED_SAFE_BEFORE_PROVIDER_COMPLETION_REQUEST_ID_ALREADY_RECORDED"
    )
    assert historical_r9_sequence["provider_completions_during_paid_attempt"] == 0
    assert historical_r9_sequence["incremental_spend_usd"] == "0"
    assert historical_r9_sequence["live_ledger_entry_count"] == 1
    assert historical_r9_sequence["existing_entry_released_or_superseded"] is False
    assert historical_r9_sequence["bundle_published"] is False
    assert historical_r9_sequence["authority"] is False
    assert not any(key.startswith("latest_") for key in smoke_status)
    assert {key for key in smoke_status if key.startswith("last_reconciled_")} == {
        "last_reconciled_operator_results_sha256",
        "last_reconciled_operator_results_bytes",
        "last_reconciled_operator_results_lines",
        "last_reconciled_operator_results_status",
        "last_reconciled_complete_smoke_offline_replay",
        "last_reconciled_offline_verifier_status",
        "last_reconciled_offline_verifier_result_independently_authenticated_by_codex",
    }
    assert not any(key.startswith("latest_") for key in exact_status)
    assert exact_status["historical_safety_withdrawal_checkpoint"] == (
        "ca63b924f244cc9bcee2d2405d20b000ce0bb9d6"
    )
    assert "current_safety_withdrawal_checkpoint" not in exact_status
    assert "replay-judge-registry-r2.json" in model_selection
    assert "authrunner-replay-judge-20260820-r2" in model_selection
    assert "A stopped run is not resumable." in model_selection
    assert "Neither CLI has a resume flag" in normalized_model_selection
    assert "requires all five mutable output leaves to be fresh" in normalized_model_selection
    assert "Deterministic logical request IDs collide" in normalized_model_selection
    assert "process-local live custody cannot be recreated" in normalized_model_selection
    assert "neither one-shot runner can adopt that work and spend cannot be refunded" in (
        normalized_model_selection
    )
    assert "do not rerun the same command or reuse/overwrite" in normalized_model_selection
    assert "Changing only the smoke output path does not repair" in normalized_model_selection
    assert "repeats paid candidate work" in normalized_model_selection
    assert "after both candidates and before either judge POST" in normalized_model_selection
    assert "Actual candidate spend plus the aggregate maximum" in normalized_model_selection
    assert "strictly below the USD `250.00` ledger cap" in normalized_model_selection
    assert "fit its USD `1.00` role tripwire" in normalized_model_selection
    assert "reserves before every attempt" in normalized_model_selection
    assert "unknown actual charge is finalized at the reserved amount" in normalized_model_selection
    assert "no separate live USD `8.00` smoke or USD `192.00` full cumulative meter" in (
        normalized_model_selection
    )
    assert "each figure is attempt-count arithmetic" in normalized_model_selection
    assert "not deferred to an end-only interval check" in normalized_model_selection
    assert "checked again when the interval closes" in normalized_model_selection
    assert "Kimi's total judge plan" in normalized_model_selection
    assert "becomes exactly bounded before dispatch" in normalized_model_selection
    assert "The selected endpoint's `provider_name` must be unique" in model_selection
    assert "Duplicate names among unrelated, unselected endpoints" in normalized_model_selection
    assert "do not make the selected identity ambiguous" in normalized_model_selection
    assert "committed-byte provider-free gate" in normalized_model_selection
    assert "full 24-case REAL command is deliberately withheld" in normalized_model_selection
    assert "case-df79ea132113b863" in model_selection
    assert "synthetic/C0015.sol" in model_selection
    assert 'purpose = "NONCREDITING_SMOKE"' in model_selection
    assert "representative_for_calibration = false" in model_selection
    assert "semantic_scores_creditable = false" in model_selection
    assert "smoke_success_authorizes_full_launch = false" in model_selection
    assert "four logical requests" in normalized_model_selection
    assert "at most eight provider attempts" in normalized_model_selection
    assert "four generation refetches" in normalized_model_selection
    assert "--qualification-policy" not in smoke_real_command
    assert "--ground-truth-provenance" not in smoke_real_command
    assert "--primary-campaign-journal" not in smoke_real_command
    assert "--primary-portfolio" not in smoke_real_command
    assert "--replay-campaign-journal" not in smoke_real_command
    assert "--replay-portfolio" not in smoke_real_command
    assert "--candidate anthropic/claude-opus-5=amazon-bedrock" not in model_selection
    assert operator_results.strip()
    assert "cause was initially `INCONCLUSIVE`" in normalized_model_selection
    assert "naive, advisory, and nonauthorizing analysis" in normalized_model_selection
    assert "944343e272b05b9925a0d4c618946ffbd4742f861e792c83be423531af07ea19" in (model_selection)
    assert "b281a184b96ee208284f57de5c17adf59a9a61a72788bfb1fb5b9ac80e25dd3d" in (model_selection)
    assert "0.21890352" in model_selection
    assert "33,621-byte operator record" in normalized_model_selection
    assert "35,771-byte operator record" in normalized_model_selection
    assert "withdrawn before execution" in normalized_model_selection
    assert "f0f367605dd75674b08c8974bf69570190e4137be46a47619c1b5b9d85c83b57" in (model_selection)
    assert "3fc6e535d22baf9bbbdafe4ccb50f9127fdb6d5c2fba7ce0463388765d2f8436" in (model_selection)
    assert "5.27438208" in model_selection
    assert "6ae6e75a1732c05b85ffe189febbc3ecfa8ae2eeeb83000a8a24d30035b966eb" in (model_selection)
    assert "7b6ff67506bceaaf05c944edb2c28bf6d8386df3690444b827035ed5c83bc134" in (model_selection)
    assert "fe3e3daa21eeb370f35558c5eca5746c140f2b92e88a37233952ab77034dc07b" in (model_selection)
    assert "2d825234bfc1cf05fb9ec883c555bc007bd3a6033145507d629d5da7aa5619ad" in (model_selection)
    assert "90389d27f553d6f167a21aab364cebdb40ca5afbdbcc977d9127338ace4a3008" in (model_selection)
    assert "7c6dd26743733ae46aa94b7171ff2ca42f967ac8323b7f2d0aa95cf66f2dbc68" in (model_selection)
    assert "sha256:932e8cdba524bbf5280d368b0cb711bf0bf36b6fb57ea744bda2a86caea534fb" in (
        model_selection
    )
    assert "16 sources totaling 421,754 bytes" in normalized_model_selection
    assert "15 aliases, 17 exact nonoverlapping claims" in normalized_model_selection
    assert "11 confirmed identities across 10 roots" in normalized_model_selection
    assert "seven conservative negative-only constraints" in normalized_model_selection
    assert "All six ordered pair directions" in normalized_model_selection
    assert "capture_public_model_lineage.py --output-dir" in model_selection
    assert "6f46b3c779262cf11b0ec58b1a2fe88947cd71d7ab788734abb36cd9f96374e4" in (model_selection)
    assert "did not exercise the current exact-cost admission implementation" in (
        normalized_model_selection
    )
    assert "Judge admission correctly remains `PENDING_REAL_CANDIDATE_OUTPUTS`" in (
        normalized_model_selection
    )
    assert "two exact retry-inclusive plans are derived" in normalized_model_selection
    assert "f6acf206f2c55eeb57b1a11fcf58cc4694a41208" in model_selection
    assert "That checkpoint is historical and must not be rerun" in normalized_model_selection
    assert "fd1459b519ea0ce28a2d123ddeb57653dd2f7918" in model_selection
    assert "Bound OpenRouter prompt-cache pricing" in model_selection
    assert "full current pre-transport metadata path" not in normalized_model_selection
    assert (
        "then-current r6/r6/r2 pre-transport metadata path at that historical boundary"
        in normalized_model_selection
    )
    assert "origin/agent/v3-wip-checkpoint" in model_selection
    assert "input_cache_read" in model_selection
    assert "provider.max_price.prompt" in model_selection
    assert preflight_status["operator_reported_no_provider_egress"] is True
    assert preflight_status["operator_reported_ledger_unchanged"] is True
    assert preflight_status["operator_reported_provider_completion_calls"] == 0
    assert local_contract == {
        "source": "LOCALLY_VERIFIED_PREFLIGHT_CODE",
        "secret_selection_reached": False,
        "provider_dispatch_reached": False,
        "durable_output_publication_reached": False,
        "transient_private_write_probes_are_created_and_removed": True,
    }
    assert "ledger_unchanged" not in preflight_status
    assert "artifacts_created" not in preflight_status
    assert "secret_selected" not in preflight_status
    assert "provider_egress" not in preflight_status
    assert "provider_completion_calls" not in preflight_status


def test_policy_eligibility_status_and_vision_boundary_are_documented_exactly() -> None:
    queue = QUEUE_PATH.read_text(encoding="utf-8")
    model_selection = MODEL_SELECTION_PATH.read_text(encoding="utf-8")
    vision = PRODUCT_VISION_PATH.read_text(encoding="utf-8")
    queue_statuses = _parse_queue_ticket_statuses(queue)
    model_statuses = _parse_status_table(
        model_selection,
        "## Queue-derived model-work status",
    )

    assert model_statuses[POLICY_ELIGIBILITY_TICKET] == queue_statuses[POLICY_ELIGIBILITY_TICKET]
    queue_section = _isolated_level_two_section(queue, POLICY_ELIGIBILITY_QUEUE_HEADING)
    assert "Section 9.2 of the product vision" in queue_section
    assert "must not be inferred from catalogue" in queue_section
    assert "per exact model and provider endpoint" in queue_section

    vision_marker = "### 9.2 Policy eligibility\n"
    next_marker = "### 9.3 Capability eligibility\n"
    assert vision.count(vision_marker) == 1
    _, _, vision_remainder = vision.partition(vision_marker)
    vision_section, separator, _ = vision_remainder.partition(next_marker)
    assert separator, "policy-eligibility vision section has no capability boundary"
    assert "`ModelPolicyEligibility`" in vision_section
    assert "Unknown or ambiguous policy status must default to exclusion." in vision_section
    assert "A daily automated policy check may flag changes" in vision_section

    normalized_model_selection = " ".join(model_selection.split())
    assert (
        f"policy gate is queued under `{POLICY_ELIGIBILITY_TICKET}`"
        not in normalized_model_selection
    )
    assert "policy eligibility remain queued" not in normalized_model_selection
    assert "distinct commercial-policy mechanism is implemented" in (normalized_model_selection)
    assert "`ELIGIBLE` in this state machine remains technical only" in (normalized_model_selection)
    assert "independently authenticated per-audit policy authority" in (normalized_model_selection)
    assert "No current independently approved determination covers any provider" in (
        normalized_model_selection
    )


def test_vision_and_traceability_bind_current_document_authority() -> None:
    traceability = json.loads(TRACEABILITY_PATH.read_text(encoding="utf-8"))
    queue = QUEUE_PATH.read_text(encoding="utf-8")
    metadata = PRODUCT_VISION_PATH.lstat()
    vision_bytes = PRODUCT_VISION_PATH.read_bytes()

    assert not stat.S_ISLNK(metadata.st_mode)
    assert stat.S_ISREG(metadata.st_mode)
    assert metadata.st_nlink == 1
    assert traceability["product_vision_path"] == PRODUCT_VISION_RELATIVE_PATH
    assert traceability["product_vision_sha256"] == PRODUCT_VISION_SHA256
    assert hashlib.sha256(vision_bytes).hexdigest() == PRODUCT_VISION_SHA256
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    assert PRODUCT_VISION_GIT_ATTRIBUTES in attributes

    authority_section = _isolated_level_two_section(
        queue,
        "## Governing documents and precedence",
    )
    for path, digest in (
        (OBJECTIVE_RELATIVE_PATH, OBJECTIVE_SHA256),
        (PRODUCT_VISION_RELATIVE_PATH, PRODUCT_VISION_SHA256),
    ):
        authority_rows = re.findall(
            rf"^\|\s*`{re.escape(path)}`\s*\|\s*`{digest}`\s*\|",
            authority_section,
            re.MULTILINE,
        )
        assert len(authority_rows) == 1, (
            f"governing-documents table must bind {path} to its exact current digest"
        )

    vision = vision_bytes.decode("utf-8")
    preamble, separator, _ = vision.partition("## 2. Mission")
    assert separator, "product vision lacks its numbered mission section"
    assert f"`{OBJECTIVE_RELATIVE_PATH}`" in preamble
    assert f"`{OBJECTIVE_SHA256}`" in preamble
    normalized_preamble = " ".join(preamble.casefold().split())
    assert "current remediation phase" in normalized_preamble
    assert "objective governs" in normalized_preamble
    assert "vision governs" in normalized_preamble
    assert "target state" in normalized_preamble


def test_readme_context_and_token_limits_match_configuration_defaults() -> None:
    readme = README_PATH.read_text(encoding="utf-8")
    capability_section = _isolated_level_two_section(
        readme,
        "## Queue-derived capability status",
    )
    assert "total role-context allocations to 2 MB" not in readme
    assert _field_default_factory("AuditConfig", "repository") == "RepositoryConfig"
    assert _field_default_factory("AuditConfig", "token_budgets") == "TokenBudgetConfig"

    defaults = {
        "repository.max_total_context_bytes": _field_default(
            "RepositoryConfig", "max_total_context_bytes"
        ),
        "token_budgets.maximum_source_tokens_per_request": _field_default(
            "TokenBudgetConfig", "maximum_source_tokens_per_request"
        ),
        "token_budgets.global_input_token_budget": _field_default(
            "TokenBudgetConfig", "global_input_token_budget"
        ),
        "token_budgets.global_output_token_budget": _field_default(
            "TokenBudgetConfig", "global_output_token_budget"
        ),
    }
    for field, expected in defaults.items():
        match = re.search(
            rf"`{re.escape(field)}\s*=\s*(?P<value>[0-9][0-9_,]*)`",
            capability_section,
        )
        assert match is not None, f"README capability section does not name the {field} default"
        documented = int(match.group("value").replace(",", "").replace("_", ""))
        assert documented == expected, (
            f"README documents {field}={documented}, but AuditConfig defines {expected}"
        )


def test_actor_model_operator_guidance_is_pinned_fresh_and_provider_free() -> None:
    readme = README_PATH.read_text(encoding="utf-8")
    normalized_readme = " ".join(readme.split())
    operator_guides = (
        OPERATOR_PREREQUISITES_PATH.read_text(encoding="utf-8"),
        V3_OPERATOR_PREREQUISITES_PATH.read_text(encoding="utf-8"),
    )
    templates = (
        ROOT / "mmaudit.example.toml",
        ROOT / "src" / "mmaudit" / "templates" / "mmaudit.example.toml",
    )

    for expected in (
        "schemas/actor_model.schema.json",
        "tests/fixtures/actor_model/synthetic_orchard_actor_model.json",
        "expected_subject_id",
        "expected_model_sha256",
        "expected_source_sha256",
        "valid_from <= run_started_at < valid_until",
    ):
        assert expected in readme
        assert all(expected in guide for guide in operator_guides)
    assert "do not use model output to invent actors or incentives" in normalized_readme
    assert all("requires no provider access" in guide for guide in operator_guides)

    for path in templates:
        text = path.read_text(encoding="utf-8")
        payload = tomllib.loads(text)
        assert payload["actor_model"] == {"required": False, "max_bytes": 1_000_000}
        _, separator, remainder = text.partition("[actor_model]\n")
        assert separator, f"{path} has no actor-model example"
        section, separator, _ = remainder.partition("\n[repository]")
        assert separator, f"{path} actor-model example has no repository boundary"
        assert "required = false" in section
        assert "max_bytes = 1000000" in section
        assert '# path = "audit/actor-model.json"' in section
        assert "# expected_subject_id =" in section
        assert "# expected_model_sha256 =" in section
        assert "# expected_source_sha256 =" in section
        assert "optional pin" in section
