<picture>
  <source
    media="(prefers-color-scheme: dark)"
    srcset="assets/brand/corrovera/logos/corrovera-lockup-horizontal-reversed.svg"
  >
  <img
    src="assets/brand/corrovera/logos/corrovera-lockup-horizontal.svg"
    alt="Corrovera Security"
    width="480"
  >
</picture>

# Corrovera Security — mmaudit

`mmaudit` is Corrovera Security's read-only, evidence-driven Solidity/EVM security auditor. Its
`solidity-evm` capability profile combines deterministic scanners and Solidity program modelling
with independent base and specialist model roles, typed stateful/invariant testing, optional formal
engines, adversarial verification and falsification, deterministic location and consensus checks,
and an evidence-capped final judge. A run may report the full maximum-assurance portfolio only for a
detected Solidity/EVM project and only when every required runtime gate passes. The current product
evidence is `INCOMPLETE`: no real audit has completed, no production model ensemble is qualified, and
model superiority remains `NOT_DEMONSTRATED`.

An explicitly selected `generic-source-review` profile provides reduced source review for other
repositories. It does not execute or claim the Solidity/EVM compilation, invariant, economic,
reproduction, or formal portfolio; it can never be reported as EVM maximum assurance. A language
mismatch fails closed instead of silently selecting this reduced profile. Both profiles emit
branded Markdown, versioned JSON, and SARIF 2.1.0 with their achieved capability stated explicitly.

The editable identity system, report templates, social imagery, web icons, and production guidance
are in the [Corrovera brand kit](assets/brand/corrovera/README.md).

It does **not** exploit targets, scan networks, test credentials, contact production systems, modify
application code, create fixes, open issues or pull requests, deploy anything, or execute
model-generated commands. A report is evidence for human review, not proof that software is secure.

## Security and privacy warning

A full run sends selected, redacted source excerpts to OpenRouter and its routed model providers.
That is a real source-code disclosure boundary. Code egress is disabled by default, `.env`, key files,
SSH/cloud/package-registry credential stores, VCS data, dependencies, binaries, generated output,
and common archives are excluded, and likely credentials are detected and redacted locally. With
the default `fail_on_detected_secret = true`, a high-confidence secret blocks every model call.

Review OpenRouter's current [ZDR documentation](https://openrouter.ai/docs/guides/features/zdr),
[provider routing controls](https://openrouter.ai/docs/guides/routing/provider-selection), and your
organization's policies before enabling egress. `STRICT_ZDR` is the default: it requests only ZDR
endpoints, sets provider data collection to `deny`, checks advertised ZDR eligibility, and fails
closed when eligibility cannot be established. `FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT` requires
both an explicit per-run profile selection and an external, self-hashed operator consent bound to
the exact source, models, providers, retention disclosures, expiry, and cost ceiling.
`SYNTHETIC_BENCHMARK` cannot authorize private operator source. Configuration alone never grants
retention consent. Provider policies and endpoint support can still change.

## Installation

Python 3.12 or newer is required.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"

cp operator-secrets.example /absolute/operator/control/mmaudit-secrets.env
chmod 600 /absolute/operator/control/mmaudit-secrets.env
cp mmaudit.example.toml mmaudit.toml
```

The package never loads a target repository's `.env`. Supply the operator control-plane
file explicitly with `--secrets-env-file /absolute/operator/control/mmaudit-secrets.env`
or `MMAUDIT_SECRETS_ENV_FILE`.

For an application repository where this project is vendored under `tools/mmaudit`, use:

```bash
cd tools/mmaudit
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"

cp operator-secrets.example /absolute/operator/control/mmaudit-secrets.env
chmod 600 /absolute/operator/control/mmaudit-secrets.env
cp mmaudit.example.toml mmaudit.toml

mmaudit doctor --language-profile solidity-evm \
  --secrets-env-file /absolute/operator/control/mmaudit-secrets.env
mmaudit scan --repo ../.. --language-profile solidity-evm
mmaudit models init-cost-ledger --cost-ledger /absolute/operator/control/mmaudit-cost-ledger.json
mmaudit run --repo ../.. --language-profile solidity-evm \
  --allow-code-egress --budget-usd 20 \
  --secrets-env-file /absolute/operator/control/mmaudit-secrets.env \
  --learning-tenant-scope-id tenant-scope-<64-lowercase-hex> \
  --cost-ledger /absolute/operator/control/mmaudit-cost-ledger.json
```

Those commands assume the application repository contains the Solidity/EVM project being audited.
Reviewing this Python repository itself requires both `--repo .` and the explicitly reduced
`--language-profile generic-source-review` profile.

## Scanner installation

Adapters are included for:

- Semgrep, using bundled local rules with metrics and version checks disabled;
- Gitleaks, with full secret redaction and no Git-history traversal;
- Trivy filesystem vulnerability, misconfiguration, and secret scanning in offline mode;
- OSV-Scanner v2 source scanning in offline/no-resolve mode;
- CodeQL, optionally, against an explicitly prebuilt database and query suite.
- Slither, optionally, for Solidity static analysis.

Run `scripts/install_scanners.sh` to see the supported plan and
`scripts/install_scanners.sh --install` on a Homebrew-based macOS host. The auditor never installs or
updates scanners during an audit. Prepare Trivy/OSV databases separately from the audit and verify
scanner binaries through their official release channels. CodeQL database creation can execute
project builds, so mmaudit intentionally does not create one; configure only a database produced in a
trusted preparation stage.

For Solidity projects, install Foundry separately if you want opt-in local Foundry compilation.
Hardhat compilation and any scanner path that can load Hardhat configuration instead require the
configured digest-pinned rootless toolchain image; repository JavaScript is never loaded by a host
audit process. Install Slither separately for repositories that cannot load Hardhat configuration,
configure exact `smart_contracts.solc_version` and `smart_contracts.solc_sha256` pins, expose the
canonical compiler path through the configured `solc_executable_env`, then enable Slither with
`[scanners.slither].enabled = true` or `--run-slither`. mmaudit copies that exact compiler into the
private scanner boundary and does not inherit ambient solc-select state. Missing pins, Solidity
tools, or isolation fail closed; their absence is not treated as proof that contracts are safe.

Missing optional scanners are reported and skipped. Set `required = true` for a scanner whose absence
must terminate the audit.

Scanner and build execution is fail-closed: a binary resolved from inside the audited repository is
rejected, the target is copied into a bounded private workspace, included symlinks are rejected,
secret/key files and generated dependency trees are withheld, the environment is scrubbed, and an
OS-level isolation backend is required. Where the host has no supported hardened backend, the tool is
reported as `unavailable`; mmaudit does not silently execute it directly.

## OpenRouter and model selection

Create an OpenRouter API key, place it in a shell/CI secret named `OPENROUTER_API_KEY`, then list
current model metadata:

```bash
mmaudit models list --config mmaudit.toml --refresh
```

Replace every obvious placeholder in `mmaudit.toml` with an exact OpenRouter
`provider/model` identifier. Use at least three genuinely independent model families across the base
analysis roles. Deep and maximum-assurance configurations add narrowly scoped specialists. The
maximum-assurance configuration preflight requires at least five declared families, all configured
specialist responsibilities, and at least eight unique slots unless an explicit downgrade is
allowed. Those configuration counts are not qualification evidence. Certified production selection
separately requires at least eight exact, current Tier A models and six independently approved root
lineages. No exact production model is currently qualified. Quality tiers are operator-maintained
capability labels, not a claim that a changing model is permanently “frontier.” The verifier,
falsifier, and judge should be independent from proposing roles. The catalog list reports the
strongest advertised output mode: native JSON Schema, JSON object, or strictly validated text JSON.
Exact endpoint discovery is authoritative because catalog and endpoint capabilities may differ.
Validate exact identity, duplication, family diversity, endpoint output mode, and current privacy
eligibility:

```bash
mmaudit doctor --allow-code-egress
mmaudit models check --config mmaudit.toml --refresh
```

Automatic random routing is deliberately not used: it undermines reproducibility, independence
accounting, provider-policy enforcement, and spend predictability. OpenRouter may select a serving
endpoint for an exact model; `data_collection = deny` and optionally `zdr = true` constrain that
selection. `require_parameters = true` is emitted only when the exact request depends on
endpoint-routed parameters such as `response_format` or `reasoning`; validated-text requests without
those parameters omit it. Only fallbacks written explicitly in a role's configuration are attempted.
Every request records requested/returned model, provider, timestamp, exact output mode and capability
hash, routing metadata, usage, cost, and prompt/response hashes.

Schema-invalid structured output is not covered by `max_model_retries`, which remains limited to
transient network or status failures. Ordinary paid runs enable bounded same-route schema retry only
through an explicit `--schema-validation-retries N` selection (`1` through `31`); omitting the
option keeps it off. Use the same option with `mmaudit quote create` so the quote, accepted ceiling,
and eventual run bind the identical split retry policy. After that separate quota is exhausted,
`SCHEMA_VALIDATION_FAILED` still follows the configured fallback or terminates.

## Configuration

Run `mmaudit init` to create `mmaudit.toml` and `.mmauditignore`. Existing files are never replaced
unless `--force` is supplied. The example documents all fields.

`repository.ignore_file` is resolved relative to the directory containing the selected
`mmaudit.toml`; its patterns are evaluated against paths in the target repository. CLI runs do not
read or merge a same-named ignore file from the target root. This lets an operator keep configuration
and exclusions together when auditing a separate repository.

`language_profile` is a separate capability choice from audit depth. The default and production
profile is `solidity-evm`; it requires a detected Solidity/EVM project before EVM analysis can run.
Use `generic-source-review` only through explicit configuration or
`--language-profile generic-source-review`. Generic review is always labelled reduced, does not run
Solidity-only engines or gates, and cannot satisfy `maximum-assurance`. Selecting `solidity-evm`
for a repository without an established Solidity project is a configuration failure, not an
implicit fallback.

`[scope].mode` selects `contracts-only`, `contracts-and-deployment`, or `full-protocol`.
The pipeline filters out component classes beyond that request and emits `scope-assessment.json`
with analyzed, missing, and omitted evidence for contracts, deployment material, off-chain
components, documentation, and tests. Set `require_complete = true` (or pass
`--require-complete-scope`) to make any missing or bounded-out required class an incomplete run.
Maximum-assurance runs always request and require full-protocol scope.

`[prior_audit].path` optionally names a repository-relative JSON corpus of historical
findings. The exact file is excluded before repository mapping and model-context
construction, then loaded only after the final independent model request. Each
historical location carries its original source-range SHA-256 and, for a previously
remediated finding, the expected remediated SHA-256. The resulting
`prior-audit-comparison.json` reports rediscovery separately from unresolved,
remediated, regressed, changed-unverified, or source-inconclusive remediation state.
Set `required = true` to require a valid corpus and `fail_on_missed = true` to make
source-valid missed findings an incomplete-run gate. The input contract is published
at `schemas/prior_audit.schema.json`; runtime parsing additionally enforces ordered
line ranges, normalized local paths, unique IDs/locations, and distinct historical
and remediated hashes.

`[actor_model].path` optionally names a repository-relative, operator-authored JSON model of
privileged roles, current holders, admitted-but-unfilled roles, economic exposure, and operational
constraints. Author it from reviewed governance and economic evidence; do not use model output to
invent actors or incentives. The contract is `schemas/actor_model.schema.json`, and the provider-free
example is `tests/fixtures/actor_model/synthetic_orchard_actor_model.json`.

The JSON is self-hashed: `artifact_sha256` is the lowercase SHA-256 of compact, key-sorted UTF-8 JSON
for the validated typed payload excluding `artifact_sha256`. When `path` is set, copy its
`subject_id` and `artifact_sha256` into `expected_subject_id` and `expected_model_sha256`. Set
`expected_source_sha256` as well to pin the exact source bytes rather than only their parsed semantic
content. The configured file is read within `max_bytes`, rejected on any pin mismatch, and withheld
from ordinary repository discovery. At run start it is current only while
`valid_from <= run_started_at < valid_until`; future or stale evidence is not used for calibration.
Set `required = true` when missing, invalid, future, or stale input must make the run incomplete.
Once current actor evidence is configured, unresolved actor assessments are a required quality gate
even when `required = false`.

Useful environment overrides are `MMAUDIT_BUDGET_USD`, `MMAUDIT_CONCURRENCY`,
`MMAUDIT_MAX_FILES`, `MMAUDIT_MAX_WALK_ENTRIES`, `MMAUDIT_MAX_FILE_BYTES`,
`MMAUDIT_MAX_DISCOVERY_BYTES`, `MMAUDIT_MAX_CONTEXT_BYTES`, `MMAUDIT_MAX_REQUEST_BYTES`,
`MMAUDIT_SCOPE`, `MMAUDIT_REQUIRE_COMPLETE_SCOPE`,
`MMAUDIT_PRIOR_AUDIT_PATH`, `MMAUDIT_REQUIRE_PRIOR_AUDIT`,
`MMAUDIT_FAIL_ON_MISSED_PRIOR`,
`MMAUDIT_ALLOW_CODE_EGRESS`, `MMAUDIT_REQUIRE_ZDR`, `MMAUDIT_PROFILE`,
`MMAUDIT_LANGUAGE_PROFILE`,
`MMAUDIT_FORK_BLOCK_NUMBER`, and `MMAUDIT_FORK_CHAIN_ID`. The API key is accepted only through
`OPENROUTER_API_KEY`, never a CLI argument.

Defaults limit files to 2,000, filesystem walk entries to 50,000, individual files to 250 KB, and
retained discovery content to 50 MB. `repository.max_total_context_bytes` is a 2 MB ceiling for each
independently built context package, not a shared run-wide role pool. Exact-route token planning uses
a `0.70` usable-input fraction, a 200,000 estimated-source-token per-request ceiling, and aggregate
ceilings of 8,000,000 input and 2,000,000 output tokens. Serialized model requests are capped at 4 MB
and configured responses at 32,768 tokens. Parallel requests default to three, scanner execution to
15 minutes, model requests to three minutes, model retries to two, and total accounted spend to USD
20. JSON repair is disabled by default and maximum assurance forces it off; outside that profile at
most one syntax-envelope repair may be enabled. Conservative pre-request reservations include the
maximum response allowance. A request is refused if its token or worst-case cost estimate does not
fit the remaining run budget.

Audit-depth profiles are explicit: `quick`, `standard`, `deep`, and `maximum-assurance`. The default
`standard` depth preserves bounded analysis within the selected language capability.
`maximum-assurance` is valid only with `solidity-evm` and enables
isolated Solidity compilation, requires Slither, the full semantic-graph transforms, specialist
review, invariant discovery and execution, generated local-fork reproduction, verifier/falsifier
review, evidence-capped judgment, coverage reporting, and the current required benchmark gate. It never
silently downgrades. `--allow-maximum-assurance-downgrade` is the only downgrade path and the result
is labelled `DOWNGRADED` in Markdown, JSON, and SARIF. Without that flag, a skipped, unavailable,
failed, timed-out, or under-covered mandatory stage prevents `COMPLETE`.

## Queue-derived capability status

These are implementation-work statuses, not claims that an external engine ran for a particular
audit. The ticket identifier and raw status in each row are checked against the authoritative work
queue so a documentation claim cannot silently outrun its evidence.

**Repository release status:** `INCOMPLETE`

The current token-planning defaults are `repository.max_total_context_bytes = 2000000` per context
package, `token_budgets.maximum_source_tokens_per_request = 200000` per request,
`token_budgets.global_input_token_budget = 8000000` per run, and
`token_budgets.global_output_token_budget = 2000000` per run. Exact endpoint limits may reduce the
usable request capacity further.

| Capability | Governing ticket | Queue status | Evidence boundary |
| --- | --- | --- | --- |
| Endpoint-aware token and context planning | `V3-TOKENS-001` | `COMPLETE` | Deterministic and fake-provider validation; no completed paid audit. |
| Coherent semantic sharding | `V3-SHARD-001` | `COMPLETE` | Stable source-bound local artifacts; bounded omissions remain explicit. |
| Resumable seven-pass scheduler | `V3-SCHEDULER-001` | `COMPLETE` | Model passes have deterministic fake-provider evidence, not real multi-lineage credit. |
| Execution-originated candidates | `V3-EXECORIGIN-001` | `COMPLETE` | Exact local provenance and source validation; unavailable engines receive no credit. |
| Repository-suite fork execution | `V3-FORKSUITE-001` | `PARTIAL` | Foundry path validated; real Hardhat execution remains technically blocked. |
| Audited-suite coverage and assertion strength | `V3-TESTQUALITY-001` | `PARTIAL` | Source populations and gaps exist; trusted statement coverage and a real mutation kill artifact do not. |
| Bounded omission accounting | `V3-OMISSION-001` | `COMPLETE` | Local scale regressions prove bounded degradation; omitted source is never counted as reviewed. |
| Bounded semantic graph generation | `V3-GRAPHBOUND-001` | `COMPLETE` | Synthetic over-100 MB pipeline evidence; no claim of unbounded or universal coverage. |

## Quick start from a Solidity/EVM repository

```bash
mmaudit init
# Edit exact model IDs and consciously review [privacy].
mmaudit doctor --language-profile solidity-evm
mmaudit scan --repo . --language-profile solidity-evm
mmaudit models init-cost-ledger --cost-ledger /absolute/operator/control/mmaudit-cost-ledger.json
mmaudit run --repo . --language-profile solidity-evm \
  --allow-code-egress --budget-usd 20 --fail-on high \
  --learning-tenant-scope-id tenant-scope-<64-lowercase-hex> \
  --cost-ledger /absolute/operator/control/mmaudit-cost-ledger.json
```

Private provider audits require an operator-provisioned opaque
`tenant-scope-<64-lowercase-hex>` value. Reuse it only inside one tenant boundary; never derive it
from a repository path, output path, run ID, or source hash. Completed REAL audit runs retain the
resulting nonauthorizing learning record under the private, manifest-bound run directory.

For the maximum-assurance Solidity/EVM path, configure `[reproduction].targets`, pin the fork
block/chain, point
`MMAUDIT_FORK_RPC_URL` at an already-running local fork, then run:

```bash
mmaudit run --repo . \
  --language-profile solidity-evm \
  --profile maximum-assurance \
  --require-maximum-assurance \
  --compile --run-slither \
  --allow-code-egress --allow-fork \
  --budget-usd 20 \
  --learning-tenant-scope-id tenant-scope-<64-lowercase-hex> \
  --cost-ledger /absolute/operator/control/mmaudit-cost-ledger.json
```

`--changed-since origin/main` restricts prioritization to changed files while retaining surrounding
security, test, and dependency context. Other bounded overrides include `--max-files`,
`--max-file-bytes`, `--max-context-bytes`, `--concurrency`, `--severity-threshold`,
`--skip-codeql`, and `--require-zdr`.

To review this Python implementation itself, select the reduced profile explicitly:

```bash
mmaudit scan --repo . --language-profile generic-source-review
```

That result is a reduced generic source review and carries no Solidity/EVM assurance claim.

## Development-only cost estimates

`V3-DEVCOST-001` adds an **offline preview**, not a paid development runner. Given an existing
validated endpoint-snapshot JSON and the exact intended text-only request JSON:

```bash
mmaudit development preview-cost \
  --endpoint-snapshot /absolute/local/endpoint-snapshot.json \
  --request-file /absolute/local/request.json \
  --budget-usd 20 --per-attempt-usd 5 \
  --accept-estimate-risk
```

The explicit acknowledgement is required. These are spending **targets**, not provider-enforced
ceilings: actual charges can exceed both the reservation and total target. The default multiplier
is `2`; `--safety-multiplier` accepts exact decimal strings from `2` through `10`.
`--maximum-attempts` defaults to `1` (no retry), is bounded to `32`, and is included in the estimate.
Per-attempt and aggregate targets are positive exact decimals, at most USD 250, with the former
not exceeding the latter.

Estimation uses maximum retained tier prices, full serialized UTF-8 request bytes as conservative
input units, and the full output-token allowance. Cache-write allowance is at least the prompt
rate even when the quoted cache-write price is zero. Cache reads are counted additionally.
The request must pin one operational ZDR endpoint with no fallback or data collection, and cannot
contain tools, search, images, plugins, or streaming. Unsupported charging units and unavailable
price schedules are rejected. Snapshot prices are observations, not promises of current pricing.

The preview requires absolute input paths and reads bounded local JSON without credentials,
networking, ledger creation, or plan selection. It prints a prompt-free JSON estimate; exceeding
a target prints the estimate but exits `INCOMPLETE`. Its `provider_enforced_ceiling`,
`qualification_eligible`, and `release_eligible`
markers remain false. The schemas are `schemas/development_cost_{policy,estimate}.schema.json`.
Existing `mmaudit run`, qualification, strict price-cap algorithms, and release evidence do not
accept this exception or the new risk switch.

The accompanying `DevelopmentBudgetSession` reuses an existing cumulative ledger with the same
target; it does not initialize or reset one. Reservations are serialized while any prior charge is
pending or unknown. Actual overages are recorded before stopping later reservations, including
after restart. Unknown charges require reconciliation, not another attempt. The separate
`V3-DEVRUN-001` fixture transport below binds dispatch to the estimated request bytes; neither
the preview nor that development transport completes an audit or establishes deployment readiness.

### Pinned development fixture review

`mmaudit development review-fixture --help` documents the new paid-capable, explicitly opt-in
request path. Local integration tests exercise the full CLI with synthetic credentials and HTTP
mocks; no real provider result is implied by those tests.

Only exact copies of `tests/fixtures/solidity/development_review/ControlA.sol` and `ControlB.sol`
are accepted. These are small abstract, non-deployable fixtures for the declared administrator-only
limit-update invariant, including a guarded counterpart. Their filenames and source hashes are
pinned in code. Arbitrary repositories, request JSON, URLs, tools, commands, or source modifications
cannot enter this command. The request uses native JSON Schema, high reasoning, and the existing
strict local decoder without response repair. Findings remain unvalidated model hypotheses.

The command requires absolute, distinct `--endpoint-snapshot`, `--fixture-file`, `--cost-ledger`,
and `--secrets-env-file` paths; an explicit `--request-id`; exact `--budget-usd` and
`--per-attempt-usd` targets; and both `--accept-estimate-risk` and `--allow-code-egress`.
The budget must match the **existing cumulative ledger's cap**, not a new per-command allowance.
The command never creates or resets a ledger and never chooses credentials from the environment.
It clears its explicit credential holder after success or failure and does not print raw HTTP errors,
request bodies, reasoning text, or credentials.

For `review-fixture`, `--endpoint-snapshot` accepts either a standalone
`OpenRouterEndpointSnapshotEvidence` document or the complete `candidate-<model-id-sha256>.json`
file published by `mmaudit models discover` in its explicitly selected output directory. The
complete discovery file is the preferred handoff: ordinary discovery stores model-level reasoning
in `model_supported_reasoning_efforts` outside the nested `endpoint_snapshot`, so extracting only
that snapshot can discard required evidence. Validated structural `OpenRouterModelDiscoveryPayload`
JSON is also accepted for local integration; neither structural nor serialized provenance fields
grant paid, qualification or release authority. `models list-endpoints --json` is a diagnostic
inventory, not one of these input formats. The separate `preview-cost` command still accepts only
the standalone snapshot format.

The review uses the same reasoning-inventory resolver as production admission: endpoint metadata
takes precedence; only its absence permits model-level fallback. Empty, unsupported, contradictory
or wholly missing inventories still refuse the request. A standalone constrained snapshot can use
its already-bound `normalized_route_facts.model_supported_reasoning_efforts`; an unconstrained
snapshot with neither inventory cannot. Complete discovery inputs retain their model/endpoint
bindings and are revalidated again before reservation/dispatch. Published effort names cannot
override negative model parameter support or missing native JSON Schema support.

No new standalone-snapshot producer, extraction script or live discovery invocation is required by
this repair. This command reads supplied local metadata; it does not fetch or refresh it, establish
freshness or adopt the recorded route. A future explicitly selected paid trial still needs current
approved metadata and the existing privacy/accounting controls. No such trial is selected here.

Each invocation makes at most one completion POST, after a durable reservation. `--attempt`
defaults to `1`; a subsequent explicit attempt requires the same logical request ID, a sufficient
`--maximum-attempts` policy, and prior settled accounting. No HTTP, schema, or ambiguous-cost retry
is automatic. The default output allowance is 4096 tokens, configurable by
`--maximum-completion-tokens` within endpoint and policy bounds. Dispatch is fixed to OpenRouter
TLS with no ambient proxy, redirect, fallback, or transport retry, with a 180-second send/read deadline
and a 1 MB response bound. Revocations are checked during preparation and again before dispatch.

The adapter requests [router metadata](https://openrouter.ai/docs/guides/features/router-metadata)
and requires direct, single-attempt routing to the pinned model/provider, without a reported plugin
pipeline. Complete supplied discovery binds the request ID and its exact canonical slug; either
may appear as the returned, selected or attempted model. The router's `requested` field must still
equal the request ID. A standalone snapshot, including a constrained one, permits only that ID:
response strings cannot create new aliases. This follows the documented distinction between
[request IDs and canonical slugs](https://openrouter.ai/docs/guides/overview/models), not proof of
metadata freshness or real execution. Both identities remain subject to revocation.

Non-BYOK evidence must be explicit `false` in router metadata or the documented
[`usage.is_byok` flag](https://openrouter.ai/blog/announcements/gif-prompts-omni-search-tool-caching-and-byok-flags/).
Any `true` or malformed marker in either location refuses, even if the other is `false`.
Absence in both locations is unknown, never silently treated as false.

Decoded HTTP-200 observations include optional `routing_evidence`: a bounded non-authorizing
projection of supplied identity bindings, recognized identities, counts, flags and named refusal
codes. Unknown strings are suppressed; credential/secret-like echoes are redacted. Arbitrary router
metadata, pipeline content, headers and raw response bodies are not retained. Its schema is
`development_routing_observation.schema.json`; runtime validation additionally enforces binding and
refusal consistency. Older observations without this field remain readable with `null` evidence,
not reconstructed diagnostics. Pre-decoding/HTTP failures may also have no routing evidence.

Model or provider mismatch, truncation, refusal, tool output, invalid JSON, secret-like
content, or out-of-range source lines make the observation `INCOMPLETE`. A known reported charge
is still recorded; missing/invalid cost is held as uncertain, and actual overages stop later calls.
Provider-reported cost is an observation, not a billing guarantee or independently authenticated
generation record. In-memory/mock transport labels never grant qualifying usage credit.

JSON output uses `development_fixture_review_observation`; exit success means only a valid
`OBSERVED` request response with settled cost. `findings_validated`, `audit_complete`,
`qualification_eligible`, and `release_eligible` stay false. The response and observation schemas
are `schemas/development_fixture_review_{response,observation}.schema.json`. There is no code
execution, source-to-sharded-audit pipeline, held-out quality measurement, or release evidence in
this fixture-only slice. An operator-reported fixture call returned `INCOMPLETE` with an identity
mismatch; it does not establish a successful review or the cause of that refusal.

### Frozen three-file development audit

`mmaudit development audit-corpus --help` describes the separate opt-in multi-file command. It
accepts only `unit-ledger-a-v1` or `unit-ledger-b-v1`, using the exact three source files under
`tests/fixtures/solidity/development_audit/a` or `b`. The paired abstract synthetic corpora contain
no funds, credentials or deployable application. Other files in the directory are not discovered
or sent; changed or missing required bytes refuse preparation.

The command requires absolute, distinct `--endpoint-snapshot`, `--corpus-root`, `--cost-ledger`,
`--secrets-env-file` and new `--output-dir` paths, plus `--corpus-id`, `--run-id`, `--budget-usd`,
`--per-attempt-usd`, `--accept-estimate-risk` and `--allow-code-egress`. It uses the same metadata
formats, reasoning, routing, source-egress and estimated-cost protections described above. The
budget must match the existing selected ledger's cap. It does not initialize, reset or settle a
ledger, read ambient credentials, select a provider, or establish current metadata freshness.

Preparation covers all primary files exactly once, including the full corpus context in every
request. It validates each estimate and their sum before dispatch. Execution is sequential, with
one attempt per shard, reservation before each POST, and no automatic retry, fallback or resume.
Incomplete responses, unknown costs, overruns, deadline expiry or output failures stop subsequent
requests. `--maximum-run-seconds` defaults to 600 and is bounded to 1800; the existing per-request
180-second deadline also applies. Synchronous local filesystem operations are checked between
steps, not forcibly preempted by a hard process-level deadline.

The output directory's parent must already exist as a private, unlinked directory (mode 0700).
The runner creates only the new run directory; it does not recursively create missing parents.
The private new output directory receives exclusive `plan.json`, `file-01.json` through
`file-03.json` as responses arrive, and `result.json`. Existing paths or previously recorded run
request IDs refuse replay. Aggregate output retains primary-file gaps, per-file hypotheses and
cost entries, including a still-active hold when reconciliation cannot persist. Cancellation
preserves earlier records and makes a best-effort incomplete aggregate before propagating the
interruption. If output custody itself fails, no trustworthy aggregate may be published; retained
files and the ledger must be inspected before any separately authorized attempt.

`OBSERVED_ALL_SHARDS` and exit success mean only three accepted request observations with settled
reported costs. All `findings_validated`, `audit_complete`, `qualification_eligible` and
`release_eligible` fields remain false. Schemas are `development_audit_plan.schema.json`,
`development_audit_shard_observation.schema.json` and `development_audit_observation.schema.json`.
This is not arbitrary-project intake, semantic coverage, exploit/remediation validation, an
unattended qualified audit or evidence of audit quality. The public annotated pair is not a
held-out benchmark. The operator's September-8 report describes two complete non-qualifying corpus
observations; private request/ledger bytes and semantic correctness were not independently verified
here. No paid command is selected by this documentation. Per-shard and aggregate observations
preserve the same bounded routing evidence,
including refusal codes for generation-header mismatch and repeated cross-shard generation IDs.

An optional absolute `--truth-manifest` selects the v2 advisory/invariant response contract and
automatic development measurement. Use the exact paired `truth-a.json` or `truth-b.json` under
`tests/fixtures/solidity/development_audit`; the manifest is never included in a model prompt.
The run retains `benchmark-plan.json` before dispatch and automatically writes `score.json`
alongside its exact `result.json`, including on safely finalized incomplete attempts. Without
this option the v1 request and observation interpretation are unchanged. See
[development measurement](docs/development_benchmark.md) for exact matching rules, denominators,
costs, missing evidence and the explicitly non-qualifying, agent-constructed truth boundary.

## Solidity smart-contract analysis

Solidity discovery is enabled by default and is read-only. `mmaudit` detects Foundry, Hardhat, mixed,
plain Solidity, and multi-package contract layouts; extracts project metadata; reads existing
compiler artifacts when present; optionally compiles in a private copied workspace; builds a
contract/function/modifier/state-variable index; and reports coverage/gaps. Compiler AST and storage
layout data are preferred. Fallback parsing is explicitly labelled lower-confidence.

The persisted semantic model contains inheritance, modifier, internal/external/low-level call,
delegatecall, contract-creation, state read/write/dependency, asset flow, privilege, proxy,
governance, external dependency, initializer, storage-layout/upgrade-compatibility, oracle
dependency, reentrancy, and
event flow/event-to-state, cross-chain-message, off-chain dependency, signature/replay-domain, and
public-entry-point-to-sensitive-sink graphs. Every edge records its path/range, source hash,
provenance, confidence, and producing transformation. Compiler AST event and signature facts remain
distinguishable from fallback source-pattern edges; heuristic edges are never promoted to compiler
facts.

`solidity-graphs.json` is bounded during generation to the same 100 MB ceiling enforced by run
manifest validation. Under pressure, mmaudit retains privilege, asset-flow,
sensitive-reachability, and state-dependency evidence ahead of informational edges. The artifact,
coverage report, shard inventory, and report metadata retain typed per-kind edge and non-edge
omission commitments. A bounded per-record inventory preserves exact retained candidate-occurrence
counts, including normalized duplicates, so omitted facts remain in homogeneous denominators and
prevent a complete assurance claim.

`solidity-shards.json` records deterministic file-primary review units bound to exact source,
semantic facts, cross-shard boundaries, explicit overlap, risk surfaces, and omissions. The
maximum-depth scheduler then executes the closed ordered passes: whole-protocol orientation, blind
shard review, finding reduction, cross-shard integration, adversarial cross-examination,
multi-lineage validation and falsification, and evidence-capped judgment. Stable task, result, shard,
activation, and journal identities permit resuming unfinished work. This is implemented local
orchestration, but its model passes have fake-provider evidence only; they do not establish a real
qualified multi-lineage audit. Automated child-resharding and retry of truncated model responses is
separate queued work and must not be inferred from semantic source sharding.

Compilation is disabled by default because build systems can execute project code. Hardhat
configuration and plugins are permitted only through a digest-pinned rootless container with no
network; without that boundary, the operation fails before resolving or starting Hardhat. Enable
compilation only for a repository you intend to analyze:

```bash
mmaudit scan --repo . --compile --run-slither
mmaudit run --repo . --compile --run-slither --allow-code-egress --budget-usd 20 \
  --learning-tenant-scope-id tenant-scope-<64-lowercase-hex> \
  --cost-ledger /absolute/operator/control/mmaudit-cost-ledger.json
```

Useful controls:

- `--framework auto|foundry|hardhat|mixed|plain`
- `--project-root packages/contracts`
- `--compile` / `--no-compile`
- `--run-slither`
- `--allow-network`, only for supported non-Hardhat compiler preparation when resolution genuinely
  requires it; Hardhat audit execution remains offline

### Offline dependency preparation

Hardhat dependency preparation is disabled by default and never contacts a registry. To opt in,
place an operator-reviewed snapshot in a dedicated repository subdirectory and bind its exact
SHA-256 in `[dependency_preparation]`. The snapshot format is published at
`schemas/dependency_snapshot.schema.json`; it binds each detected Hardhat project to its npm
`package-lock.json`, the exact locked package set, every unpacked package-tree digest, and a
deterministic offline advisory set.

Preparation accepts npm lockfile versions 2 and 3, requires SHA-512 integrity metadata, rejects
links, hardlinks, lifecycle scripts, executable/native/archive files, sensitive filenames, and
private-key payloads, and applies configured project/package/file/byte limits. It does not invoke
npm, Node.js, or package code. Only packages named by both the validated lockfile and snapshot are
copied into private `node_modules`; the snapshot source directory is excluded from the compilation
workspace. Exact-version advisory matches reject the prepared set. Because the advisory list is an
offline, operator-pinned input, a clean result is deterministic but does not imply that a current
external vulnerability database was queried.

Every run emits `dependency-preparation.json` and `dependency-sbom.json`; the latter follows the
bounded schema in `schemas/dependency_sbom.schema.json`. Set `required = true` to make rejection or
validation failure render the run incomplete.

For supplied local npm archives, `mmaudit managed build-dependency-snapshot` now constructs the
snapshot and exact configuration without hand-authoring package-tree hashes:

```bash
mmaudit managed build-dependency-snapshot --repo /absolute/authorized-fixture \
  --archive-root /absolute/local-archive-store \
  --advisory-path /absolute/local-advisories.json --advisory-sha256 <exact-sha256>
```

The archive store must be separate from the target and contain `<sha512-hex>.tgz` files matching
every locked package's actual SHA-512 digest. No archive is downloaded and no package code runs.
The advisory input is explicitly pinned JSON with `schema_version: "1.0"` and an `advisories` list
using the existing snapshot advisory format. All Hardhat roots in the bounded audited-workspace
inventory are included; missing lockfiles, unsafe members, lifecycle scripts, identity mismatches
and resource excess refuse the build. Output is private and content-addressed under
`.mmaudit/managed-dependencies/`, including `snapshot.json`, provenance and `dependencies.toml`.
The TOML contains only the dependency configuration, not the rest of an audit profile.

A repeat verifies every output byte without overwriting it; `--verify-only` cannot create missing
material. Incomplete output remains explicit and is not repaired or reset. Construction authenticates
material against the supplied lockfile, not the trustworthiness of that lockfile or the freshness
and completeness of the advisory data. Runtime readiness remains false.

Once the generated dependency section is explicitly selected in an audit configuration,
`mmaudit managed provision` verifies it and records the existing typed dependency observation.
Verification checks the complete detected Hardhat project set, exact locks, private owned package
directories/files (modes `0700`/`0600`), package identities, inert contents, tree hashes and supplied
exact-version advisories. It applies the selected resource limits, capped at the builder's maximum
limits. It does not download material, run packages, or reauthenticate the original archives.
Aggregate metadata checks and pre/post-publication rechecks reject material drift; a newly published
receipt is rolled back on detected drift, while a pre-existing historical receipt is preserved.
These are point-in-time observations, not a filesystem lock or permission to skip audit-time checks.

New receipts bind setup policy v2; v1 receipts retain their original identity and are not upgraded
by parsing. Missing tooling, CodeQL, fork and other prerequisites still leave the receipt
`REFUSED_INCOMPLETE` and the CLI exits incomplete. Archive/feed distribution, advisory
freshness/completeness, installed-tool verification and a zero-input
end-to-end audit remain unfinished. No receipt grants provider, spend, execution or audit authority.

To build and select dependencies in the same setup operation, use the original audit profile
without existing dependency snapshot pins:

```bash
mmaudit managed provision --repo /absolute/authorized-fixture \
  --config /absolute/audit-profile.toml --output-dir /absolute/private-receipts \
  --archive-root /absolute/local-archive-store \
  --advisory-path /absolute/local-advisories.json --advisory-sha256 <exact-sha256>
```

All three source options are required together; no network source is inferred. The archive-building
step derives only the dependency section, using the tighter of the selected limits and builder defaults.
Existing snapshot pins conflict with this mode even if dependency preparation is disabled; select
either automatic construction or preconfigured material. The original profile is never rewritten.
Repeat with that same original profile and source inputs. `--verify-only` cannot create missing
dependency material or a ledger; failed construction leaves existing material and receipts intact.
The archive store and advisory input must remain outside the receipt output directory.

For programmatic orchestration, `provision_managed_local_run` returns the receipt and a detached
canonical `config` whose stable hash matches the receipt's effective-config binding. The existing
dependency-preparation adapter consumes that config directly, without hand-copied paths or hashes.
Setup also fills the existing compiler/scanner/formal version/hash fields for roles selected by the
effective profile and pinned in the supplied managed bundle. Selected container image/runtime values
are derived where the existing config permits their absence. Explicit conflicts refuse setup before
writes; engine selection, profile, limits and unrelated configuration remain unchanged. The pure
`derive_managed_toolchain_config` API performs the same derivation and requires resolved roles by
default. Partial receipt construction leaves unresolved roles explicit instead of inventing pins.
This does not install or verify tools, their dependency closures, or image contents. Existing
required input fields (including clean-fork Anvil pins) and audit-time verification remain required.
The config/receipt pair is local setup output, not an audit profile persisted or activated on disk,
an executed audit, or permission to bypass any downstream checks.

The same API optionally accepts `host_tool_source=ManagedHostToolSource(blob_root=...)` with a
supplied bundle whose required host roles are already pinned. It copies only matching local
`<sha256>.blob` files into a content-addressed subdirectory of the existing private output root,
outside the audited repository and input store. Files are owned mode-`0500`; the exact canonical
`host-tool-material.json` manifest is mode-`0600` and published last. Per-file and aggregate limits
bound copying. Partial, linked, unexpected or changed material is refused, never overwritten.
The returned `host_tools` carries the same final config as the receipt, including automatically
prepared dependencies. `host_tools.executable_for(role)` reverifies the selected material before
returning an absolute path for a pinned consumer. A repeat may use `ManagedHostToolSource()`
without the original store; `verify_only=True` cannot create missing material.
This is an API-level direct-file preparation capability, not a new CLI installer: the packaged
bundle still has unresolved roles. It performs no PATH search, download, install script or probe.
Declared versions are not observed versions; architecture, interpreter/shared-library closure,
container images and installed readiness remain unverified. Legacy receipts retain the mandatory
installed-toolchain refusal and all runtime/readiness flags remain false.

`ScannerRunner(prepared.config, host_tools=prepared.host_tools)` consumes that
verified material through the existing fixed scanner portfolio. For pipeline-wide preparation,
use the explicit `AuditPipeline` handoff below. With no explicit backend it constructs the selected
Bubblewrap boundary only on a matching declared Linux/CPU platform, verifies the launcher pin and
retains that admission through all six mandatory probes. Every wrap reverifies the closed material
directory and exposes it read-only; writable-private overlap is refused. No PATH discovery or
unsupported-platform/backend fallback runs. An explicitly supplied `backend=backend` is preserved.
Managed mode requires a matching config, rejects custom adapter injection and detaches the config.
It rebuilds fixed adapters for each run and rechecks material/config before queued dispatch and
after outcomes.
Primary host executable paths and Slither/Foundry `solc` paths are explicit; missing paths never
fall back to PATH or the compiler environment variable. Foundry runtime clones preserve both paths.
Disabled scanners and Hardhat's separate image-side refusal remain unchanged. This is not a CLI
managed audit or installed-closure attestation: child-process PATH/dependency resolution, the
doctor paths, image identity and complete backend provisioning
remain outside this verified handoff. Audit-time pin, source and isolation checks still apply.

The existing `compile_solidity_projects` API also accepts `host_tools=prepared.host_tools`
with `prepared.config.smart_contracts`. It selects exact prepared Forge/Solc, rejects mismatched
config or nonstandard build arguments before setup writes, and forces the selected Solc path with
compiler auto-detection disabled. Network-disabled configurations retain the fixed offline build.
Both declared versions must pass isolated probes before compilation; retained file identities are
rechecked during probe preparation and around build execution, including same-byte replacements.
An omitted backend uses the same matching-Linux factory; an explicit backend stays explicit.
Material cannot overlap audited source or writable compiler state. Disabled/plain projects and
Hardhat's off-host boundary remain unchanged. Local integration tests use fixed trusted-Python
controls, not real Forge/Solc; actual managed compiler execution and full-pipeline provisioning
remain unverified. This handoff does not establish installed dependency closure or atomic exec.

`FormalRunner(prepared.config.formal, host_tools=prepared.host_tools)` also accepts exact prepared
material. Managed mode rebuilds the fixed eight-engine portfolio, rejects custom adapters and
config drift, and resolves primary engines without PATH discovery. It checks primary pins and
isolated versions before target execution, passes prepared Z3 to Halmos and prepared Solc to
Foundry invariants with compiler auto-detection disabled. Existing property, trust and Certora
service prerequisites still apply; preparing a CLI does not authorize service use. Retained tool
identities are checked around probes, launch preparation and outcomes; source/private overlap
refuses. An omitted backend uses the matching-Linux factory, with no ambient fallback. Local
controls prove this handoff only: real formal engines, transitive child compiler/interpreter
resolution, Linux isolation and a complete automated audit remain unverified.

`FoundryInvariantRunner(prepared.config.reproduction, prepared.config.smart_contracts,
host_tools=prepared.host_tools)` consumes the same prepared Forge/Solc for enabled source-local
generated invariants. Managed mode rejects explicit path overrides, mismatched config and
source/private overlap; disabled or nonlocal harnesses cannot probe tools or read a fork RPC.
Typed harness/project inputs are detached before probing. Both versions must match their pins;
the compiler is used directly from prepared material with auto-detection disabled, not copied
into writable test source. Retained identities are rechecked through launch preparation, clean
replays and recursive minimization. Existing capability, structured-output and replay checks stay
mandatory. An omitted backend uses the matching-Linux factory; explicit backends remain explicit.
Local integrations use fixed trusted-Python controls and UNVERIFIED execution evidence, not actual
Forge/Solc or Solidity-invariant proof. Installed closure, real Linux execution, fork provisioning
and a complete managed audit remain unverified.

`ForkReproductionRunner(prepared.config.reproduction, prepared.config.smart_contracts,
host_tools=prepared.host_tools)` accepts prepared Forge/Solc as well. Managed reproduction requires
enabled execution, explicit fork acknowledgment, prepared chain/block pins and an isolation backend
that supports the existing loopback-only RPC boundary. It does not start or provision a fork.
Typed candidate/project/test inputs are detached; mismatched candidate IDs, config/path overrides,
source/private overlap and tool drift refuse. Exact pins precede isolated version checks, Solc is
selected directly with auto-detection off, and retained identities are checked through clean replay
and result publication. Disabled/unacknowledged mode does not construct a backend or read the RPC
setting. The matching-Linux factory remains network-denied, so its incompatible fork mode refuses.
Fixed offline Python controls prove path/process handoff only and remain UNVERIFIED; actual engines,
fork isolation/provisioning, installed closure and complete managed auditing remain unverified.

When `prepared.host_tools` is present, `AuditPipeline(prepared.config, repo=repository,
output=audit_output, host_tools=prepared.host_tools)` constructs the fixed scanner, formal,
invariant, reproduction and repository-matrix consumers with one prepared backend, even when
reproduction is disabled.
It also passes that material and backend to compilation. Keep audit output disjoint from the tool
material directory; neither may contain the other. An optional explicit `managed_backend` retains
its existing evidence level; it requires prepared material and cannot grant execution authority.
Custom runner overrides and matrices without prepared Forge/Solc/Anvil roles are rejected. Config, roots,
selected consumers/backends and retained tool identities are rechecked across phase/run boundaries;
failed preflight cannot invoke a compiler with a downgraded configuration. Refusal clears credentials
and closes the run log. Offline scanner-only pipeline controls exercise this composition, including
create/reopen and post-scanner tool replacement; their evidence remains UNVERIFIED and reports
remain incomplete. This is programmatic wiring, not CLI provisioning, real-engine qualification,
atomic execution custody, primary-fork preparation, or proof of an unattended audit. Provider, privacy,
dependency, scope and quality admission remain separate mandatory checks.

The clean-chain launcher also accepts prepared material programmatically through
`TrustedCleanAnvilLauncher(host_tools=material)`. It selects the pinned ANVIL file without an
executable environment lookup and rejects mixed environment overrides. Only the prepared
clean-state configuration is accepted; a detached copy enters the existing private-copy lifecycle
after material, file-identity and root checks. Version, descriptor, state/listener, deadline and
cleanup checks are unchanged. Local version-only controls are not proof of an Anvil engine or a
running chain.

`RepositoryForkMatrixRunner(..., host_tools=material, managed_backend=backend)` composes the fixed
prepared clean launcher and fresh Foundry scanners with explicit Forge/Solc paths. Only paired
declared state overrides are accepted, and each scanner receives detached prepared configuration.
Custom dependencies, configuration/tool identity drift and overlapping or aliased material roots
refuse. Execution still requires the same qualifying baseline, exact prepared Forge pins and an
unchanged currently attested backend that supports local-only fork RPC. These checks are repeated
at state, attempt and result boundaries; existing scope, bridge, deadline and cleanup gates remain.
The managed pipeline uses this composition automatically. The default managed Linux backend still
denies fork RPC; the optional offline-state handoff below does not override that refusal. Offline controls produce
truthful failed matrix reports without running engines or contacting endpoints; they do not prove
real matrix execution, installed closure or a complete unattended audit.

The programmatic `load_offline_fork_rpc_archive` API accepts an absolute source root, a relative
archive path and exact SHA-256/chain/block pins. Its strict `offline_fork_rpc_archive.schema.json`
input contains canonical hash-bound read results, not a complete EVM snapshot. Stable bounded
no-link reads and the shared RPC policy reject missing, malformed or contradictory data; recorded
account summaries must agree with their individual fields. A digest identifies supplied bytes,
not their provenance, state-root correctness or benchmark ground truth.
The returned replay object's `respond(bytes)` handles bounded atomic JSON-RPC requests entirely
in memory. Missing reads fail instead of becoming zero state or upstream requests; lifetime request
and call budgets saturate, and response construction is bounded incrementally. `verify_source()`
explicitly rechecks the original file; later file changes do not alter the already frozen replay.
This API starts no listener, process or chain. It grants no execution or state-completeness
authority. Existing fork, isolation, source-authority and completion gates remain mandatory.

`OfflineForkRpcLease(replay)` provides the separately bounded local transport for that admitted
replay. Its one-shot context manager binds only `127.0.0.1` on an OS-assigned port; no target URL,
upstream connection, DNS discovery or tool execution is accepted. One worker handles one strictly
framed JSON POST per connection. Fixed ceilings cover headers (16 KiB), request bodies (1 MiB),
responses (8 MiB), received/reserved-response traffic (64 MiB) and accepted connections (10,000).
Request deadlines default to two seconds (maximum five); the lease defaults to 300 seconds
(maximum 3,600) and expires without operator cleanup. `stop(deadline=...)` uses the earlier caller
deadline or a two-second shutdown limit. Source is reverified before bind and by the worker after
closing; drift, expiry, exhausted budgets or failed cleanup cannot be reported as a clean stop.
Actual owned-loopback clients and the unchanged scoped bridge are tested against synthetic reads.
This is not a complete state snapshot, chain, engine or isolation attestation. Supported fork
isolation and source authority remain required before a complete unattended matrix run can be claimed.

Managed setup accepts `offline_fork_source=ManagedForkArchiveSource(archive_root=...,
primary_archive_sha256=..., reproduction_archive_sha256=..., invariant_archive_sha256=...)`
as an optional programmatic input. The three digests are optional, separate roles. The primary selects
exactly `<sha256>.json` for the acknowledged Foundry baseline scanner, bound to the final config's
chain/block pins. The reproduction digest binds the acknowledged reproduction runner's exact
final chain/block pins independently of baseline scanner or matrix selection. The invariant digest
joins enabled generated invariants, fork acknowledgement and final chain/block pins without requiring
candidate reproduction to be enabled. Each declared pinned matrix state's existing
`state_source_sha256` separately selects its exact file. Individual and combined role selections
are supported; no directory discovery or URL lookup runs. Selected bytes must match the state
chain/block and full final setup config. At most seven matrix archives plus one primary, one
reproduction and one invariant archive, 16 MiB each and 64 MiB selected total, are read from a store
disjoint from source, output and host material. Each role counts toward the aggregate ceiling, even
when roles share a file. Setup starts no listener and does not change the legacy receipt's fork or
installed-toolchain refusal. It returns a detached `prepared.offline_forks` handle.
Pass that handle with `prepared.host_tools` to `AuditPipeline(..., offline_forks=prepared.offline_forks)`
or the fixed `ScannerRunner`, `ForkReproductionRunner`, `FoundryInvariantRunner` or
`RepositoryForkMatrixRunner`. Consumers reverify exact config, source and roots; managed primary
Foundry, reproduction, invariant and pinned matrix states never fall back to ambient RPC variables
if archives are missing. Each execution gets a fresh owned lease with normal/error cleanup, including
the captured Foundry runtime producer. Primary startup consumes the scanner's existing absolute
deadline; its original three-way timeout policy plus cleanup must fit the service lifetime. Source
drift or failed cleanup prevents returning/registering a result. The entire matrix state budget, including
all repetitions and fixed overhead, must fit the existing 3,600-second lease ceiling and remaining
matrix deadline; child timeouts are never shortened to fit. Larger selections explicitly refuse.
Reproduction and fork invariants own a separate lease per replay attempt, after eligibility/tool
preflight and workspace preparation. Each attempt's original child timeout is reserved alongside
15 seconds for startup, 15 seconds for process cleanup and two seconds for service shutdown.
Budget checks before/after service startup
and process construction reject exhausted capacity; they never shorten the configured timeout.
Child interruption enters process cleanup, then lease closure/source postflight, before attempt
evidence or a result can be returned. Independent runs use distinct private workspaces; an occupied
workspace is not silently reused. Managed fork invariants use the pinned Forge/Solc tools and an
explicit block argument. Source-local invariants remain network-free even when archives are prepared.
Synthetic transport and tool controls remain UNVERIFIED.
This handoff supplies primary Foundry, reproduction and invariant reads, not Hardhat fork consumers,
complete EVM state or real-engine qualification. Scope, qualifying-baseline and current isolation
checks remain mandatory; default managed Linux still refuses local fork RPC. It remains programmatic, not a
CLI-managed audit entry point or evidence of best-in-class or unattended audit completion.

The per-run maximum-assurance requirement is shared by preflight, both quality-gate evaluations
and the final assessment. Requesting it with a standard profile does not silently change the
profile or prepared configuration: missing profile/analysis requirements produce non-complete
reports with failed clauses. JSON, Markdown, SARIF and artifact-manifest checks preserve that
result. Reusing a pipeline resolves the requirement afresh; contradictory explicit require-and-
downgrade options still refuse before output or execution.

The common scanner consumer rejects incomplete or mismatched version/hash pins before copying
source or running a version probe. It observes the canonical host executable with bounded,
nonblocking, no-follow reads and rechecks its bytes and file identity before probing, after the
probe's own preparation, and before the scan starts. Detectable changes refuse execution even when
no pin was requested; unchanged matching pins retain the normal version and isolation checks.
These are boundary-local checks, not atomic custody through exec, transitive-dependency verification,
image-side attestation or installed-toolchain readiness. Setup still refuses incomplete provisioning.

Built-in isolation launchers use the same bounded identity observer before policy construction and
before/after every preflight invocation. Launcher and policy must remain unchanged through all six
mandatory probes; an identity refusal is never a successful negative observation. Process-local
seals retain file identity, so byte restoration or same-byte replacement requires a fresh preflight;
a failed reseal revokes previous evidence. This does not attest helper/dependency closure or hold
the executable atomically through exec. Managed Linux backend construction is implemented, but
its real Linux integration remains unverified on the current macOS development host. Other managed
backends, complete installed provisioning and a fully unattended audit remain incomplete.

The compilation environment is scrubbed, bounded, and uses a temporary private workspace. Hardhat
receives a writable disposable copy inside the rootless boundary; the operator's source tree is
never mounted into that container. It does not receive wallet/private-key environment variables
from the host and does not modify the audited working tree. No contract deployment, transaction
signing, broadcasting, wallet access, or live-chain interaction is implemented.

### Invariants, formal engines, and economic templates

The invariant engine derives source-linked accounting, authorization, token-standard,
state-machine, and economic hypotheses from indexed entities, graphs, and detected protocol
profiles. These are audit hypotheses, not assertions of protocol intent. An invariant becomes
executable only when it is linked to validated source facts and an operator-reviewed typed harness.
The harness DSL permits fixed ABI actions, bounded actors/fuzz values, probes, and comparisons; it
contains no shell command or free-form Solidity field.

A separate `invariant_review` model role reviews those deterministic hypotheses and may propose
missing properties. It uses a non-finding schema. Every proposal must cite supplied source and an
indexed entity, is revalidated locally, has confidence capped as model-only evidence, and is written
to `invariant-review.json`. Proposals cannot enter finding consensus, cannot be marked executable,
and cannot be promoted into tests without a later trusted translation and validation step.

When enabled, formal/property adapters inventory and safely invoke supported installed tools:
Solidity SMTChecker, Mythril, Echidna, Medusa, Foundry invariants, Halmos, and Kontrol. Commands are
fixed, isolated, bounded, and normalized. `unavailable`, `timeout`, and `unknown` are coverage
limitations, never evidence of safety. Outside maximum assurance, specific engines become mandatory
through `[formal].required_tools`. The effective maximum-assurance configuration adds its exact
required fuzz, symbolic, and formal portfolio automatically; an unavailable required engine fails
closed.

Echidna additionally requires exact operator-configured `echidna_version` and
`echidna_sha256` trust pins before the binary is executed. The adapter translates only the
source-linked, no-argument-local-deployment subset of `property-corpus.json`; unsupported target
bindings, token storage seeding, value calls, time movement, and ordering capabilities remain
explicit translation limitations. Campaign seed, bounds, corpus identity, binary hash, and
normalized replay sequence are retained in formal-result evidence.

Medusa applies the same trust and translation contract through `medusa_version` and
`medusa_sha256`. It receives an independently bounded campaign over the same typed property
corpus. Reports retain each engine's property outcome separately and flag disagreement instead of
combining results into a safety claim.

Halmos requires exact `halmos_version`/`halmos_sha256` pins plus
`halmos_solver_version`/`halmos_solver_sha256` pins for its fixed local Z3 dependency. The adapter
translates the shared safe subset into assertion-based invariants, caps invariant depth, loop
unrolling, path width/depth, solver time, memory, and threads, disables FFI, and rejects
repository-provided Halmos option annotations. Symbolic models and bounded-path metadata are
normalized from Halmos JSON; a bounded pass remains a coverage result, not an unbounded proof.

Protocol-aware plans cover ERC4626 donation/inflation, reward-index manipulation, temporary-liquidity
oracle attacks, AMM reserves, liquidation boundaries, non-standard tokens, repeated rounding,
governance races, upgrade/initializer misuse, and sandwich ordering. Plans are declarative and are
reported as unexecuted until a matching validated Foundry harness actually runs. Economic feasibility
and technical reproducibility remain separate claims. JSON and Markdown reports identify whether
each selected economic template currently has a deterministic typed harness; templates without one
are retained as coverage gaps for model/formal review, not as executed evidence.

Executable templates currently include ERC4626 donation/inflation and observed-versus-assumed
accounting for fee-on-transfer or elastic assets. Configure literal `[reproduction].targets`
aliases for the protocol and its asset token, for example `Vault = "0x..."` and
`VaultAsset = "0x..."`. Generated harnesses seed only declared test actors during setup, use fixed
ABI calls, and compare validated probes. The token-behavior property requires assets actually held
by the protocol to cover its recorded user claim. Missing aliases, non-literal addresses,
unsupported signatures, or absent deterministic applicability evidence are limitations, not safety
evidence.

### Specialist ensemble

Maximum assurance requires 22 narrow investigator responsibilities: access control,
reentrancy/control flow, economic game theory, oracle manipulation, accounting/invariants, token
standards, ERC4626, AMMs, lending, governance, upgradeability/storage,
initialization/deployment, signatures/replay, MEV/ordering, denial of service/griefing,
precision/rounding, bridges, dependency/supply chain, formal properties, lifecycle state machines,
randomness/entropy/commit-reveal, and blind false-negative hunting. The exact 24-role
candidate-independent certification portfolio is those 22 investigators plus non-finding invariant
review and report-quality review. Test generation, reproduction planning, and falsification remain
candidate-dependent extras and cannot replace a missing portfolio responsibility. Primary
investigators run blind to one another; later stages receive grouped evidence. Duplicate model IDs,
aliases, retries, or generic repeated agents do not satisfy missing responsibilities, do not create
independent votes, and model agreement alone cannot confirm a Solidity finding.

Generated executable verification is candidate-specific. Models may only emit a strict declarative
Foundry test specification: actors, target aliases, ABI signatures, arguments, value, assertions,
assumptions, block, and chain ID. `mmaudit` translates that specification deterministically into a
test in a disposable workspace and runs only a fixed `forge test` command against a local loopback
fork RPC endpoint. The runner refuses non-local RPC URLs, missing fork acknowledgements, symlink
escapes, repository-local tool binaries, missing hardened isolation when required, wallet/private-key
environment exposure, arbitrary shell commands, and unbounded output or runtime. A complete generated
test can classify as `reproduced`, `reproduced_and_minimized`, `not_reproduced`, `compile_failed`,
`environment_blocked`, `generation_failed`, or another explicit reproduction state.

Every generated test also declares an `AttackerCapabilityPolicy`. It names controlled actors and
contracts, starting capital, temporary liquidity, existing token approvals, timing and ordering
control, oracle influence, governance or privileged roles, and offline cross-chain-message
capabilities. Active capabilities require a justification and must stay within operator-configured
`[reproduction]` ceilings. An undeclared or over-limit capability is rejected before source
generation or tool execution.

Execution evidence is accepted only after a deterministic integrity assessment binds the configured
target aliases, chain and block, generated-test hash, current bounded repository hash, and each
attack call to an exact cited public or external Solidity entry point. At least two fresh disposable
workspace attempts must agree, declared end-state assertions must settle consistently, and any
minimality claim must carry matching bounded evidence. A positive or negative execution result that
fails one of those checks remains unverified and cannot confirm or falsify a finding. This source
binding does not claim that configured deployed bytecode is equivalent to the audited source.

The legacy `[scanners.foundry_fork]` adapter remains limited to pre-existing
`test/audit/*.t.sol` suites. Separately, `[smart_contracts.repository_suite]` supports bounded,
explicit Foundry or Hardhat path and test-name selection with per-test and aggregate ceilings. The
Foundry path has real local pinned-fork integration evidence when its compiler, local RPC, and
hardened isolation prerequisites are available. The Hardhat adapter validates selection and reporter
evidence, but real Hardhat suite execution receives no credit until the required process-attested,
digest-pinned rootless single-loopback toolchain is supplied. Missing prerequisites are
`unavailable`, never a pass. Candidate-specific generated reproduction remains controlled by
`[reproduction]`.

Independent parent-side Hardhat phase capture is locally tested with fixed finite Python controls.
It binds the exact typed request, requires explicit launch inputs and separate private output,
bounds captured streams/report bytes and phase time, observes the real exit, and cleans the owned
process group before returning detached observations. An exclusive retained claim prevents output
reuse. This is a prerequisite only: the production adapter remains `UNAVAILABLE`; capture grants
no execution credit and does not supply image identity, container isolation/teardown, or semantic
report authentication. See the operator guide's Hardhat section for the remaining executor boundary.

Captured inventory now feeds the existing source binder to prepare an exact second-phase request
and selection automatically. Captured test reports rejoin both phases and current source/config,
enforce pinned reporter schemas and combined retained-byte/duration ceilings, and check actual
exit consistency. A normal nonzero exit can retain matching failure observations; skipped tests
stay skipped. These locally tested protocol joins do not authenticate reporter claims or admit a
Hardhat command. The executor still needs a live attested boundary and an aggregate wall-clock
deadline covering the gap between phases and container cleanup.

Request-bound Hardhat command layout now gives inventory and test phases separate, single-use
private output and runtime/CID directories while retaining the exact live bridge and read-only
source mount. Reused layouts, cross-phase paths and changed requests/bindings refuse construction.
Local bridge and fixed-control captures test this prerequisite; the returned command is still
unverified. Image admission, the complete executor deadline and actual container teardown remain
required before the production adapter can run.

The independent two-phase driver now sequences inventory capture, source-bound test preparation,
test capture and protocol consumption under one owned live bridge. Both phases share a deadline
and retained-output budget; bridge shutdown and final source/protocol checks precede a result.
This is locally tested with fixed reporters, not Hardhat. Its required programmatic launch boundary
must independently admit the image/command and finalize containers; no production implementation
or execution authority is supplied. Expiry rejects results while still allowing emergency cleanup.

Rootless cleanup now distinguishes a missing CID from a successful exact-ID absence response.
Runtime errors, ambiguous replies, timeouts and changed CID/runtime custody refuse cleanup credit.
Control processes have bounded output and one finite shared cleanup deadline, with owned-child
reaping on failures and interrupts. The local fixed-process tests mock runtime replies: they do
not prove actual container removal, image identity or launch admission. The production Hardhat
boundary remains unavailable. A started launch must not treat `NO_IDENTIFIER` as verified absence.

A single-use phase finalizer now retains the exact launch environment, host executable observation
and phase/CID custody through typed cleanup. Changed ambient routing cannot redirect cleanup of
an entered phase. Ordinary phase drift still attempts cleanup of the original safe selection;
unsafe cleanup-root or executable drift refuses to invoke a different runtime. Original failures
survive secondary finalization errors, with a non-sensitive incompleteness note. This context is
locally tested inside both fixed-reporter phases; it neither admits a launch nor authenticates an
image, daemon/storage route or actual container. Those production prerequisites remain unproved.

The offline `read_managed_image_metadata` API now joins an existing managed bundle's image and
platform-manifest pins to exact local OCI index/manifest/config bytes. It reads only the selected
SHA-256-named metadata blobs, checks raw hashes/sizes and declared platform compatibility, and
retains ordered layer references and config diff IDs. Config IDs cannot substitute for manifest
digests. The supported subset is one flat OCI index or a direct manifest, with baseline Linux
amd64/arm64; ambiguous selection, alternate descriptor locations and unsupported forms refuse.
This is a metadata-only prerequisite: no layer bytes, final filesystem, executable/reporter,
runtime defaults, daemon or actual execution are attested. Production Hardhat remains UNAVAILABLE.

The next layer of that check, `verify_managed_image_layers`, now reads the actual selected local
tar/gzip layer bytes under shared stored/expanded byte and time limits. A retained read-only stream
authenticates the stored digest before decompression, then rehashes complete consumption and checks
file/path custody before closing. Bounded gzip processing checks complete members and the config
diff IDs; metadata and bundle identity are revalidated before returning. No files are extracted or
written. Zstd content is explicitly unsupported by this consumer. Even matching bytes do not prove
valid tar semantics, filesystem overlays, executable/reporter membership or runtime identity.

The separate `verify_managed_image_files` consumer now derives four selected file hashes from a
bounded in-memory layer view. It reuses that exact byte boundary, supports USTAR and bounded local
PAX records, applies lower-layer whiteouts before same-layer additions and resolves supported
in-image links without host path lookup. Unsupported archive/link semantics refuse. Hardhat, Node
and relay paths use the existing bundle contract; the reporter has the new fixed image path
`/usr/local/lib/mmaudit/hardhat_reporter.cjs` and must match the compiled source hash/version.
Synthetic local controls prove only this static membership join. Image construction, launch use of
the reporter path, transitive dependencies, actual tool versions/architecture, runtime permissions
and container identity remain unproved. Nothing is extracted, executed or admitted; production
Hardhat remains UNAVAILABLE.

A current, hash-bound deterministic execution that violates an invariant may originate a typed
candidate without model attribution. Models may analyze its impact, exploitability, and remediation,
but cannot create, delete, or relocate it; deterministic evidence remains the confirmation cap.
Reports distinguish execution-originated evidence from review-originated findings, and a passing
suite is never evidence of safety.

Audited-suite reporting currently preserves exact source populations, selected/executed/failed test
counts, conservative critical-surface classification, and source-bound coverage gaps that are
explicitly not vulnerability findings. Trusted statement coverage remains `NOT_ANALYZED` without a
trusted normalizer, and no decisive production mutation executor or real mutation kill artifact has
run. Assertion-strength and mutation coverage therefore remain partial capabilities.

Reports include a Solidity coverage section with concrete denominators: projects, Solidity files,
contracts, functions, model-reviewed functions, Slither-covered functions, compilation failures,
unsupported files, missing dependencies, unresolved imports, generated-test attempts, reproduced
claims, stateful harnesses, formal engine states, and graph/context warnings. Do not interpret those
counts as a guarantee of whole-project security coverage.

Source-egress acknowledgement must be explicit either as:

```toml
[privacy]
allow_code_egress = true
```

or as `--allow-code-egress` on that run. Reports record the acknowledgement but never credentials.
For a non-ZDR provider run, also pass the matching `--privacy-profile`,
`--privacy-source-classification`, and absolute `--retention-consent` path. The consent file must be
an operator-controlled regular file outside the audited repository. Reports retain only validated
policy evidence and hashes, not the consent path or operator references.

## Docker

The image runs as UID/GID 10001, includes Bubblewrap as the Linux execution boundary, installs no
scanners or services, and expects a read-only repository plus a separate writable output mount.
The base image has no default: supply an operator-verified digest reference through
`MMAUDIT_BASE_IMAGE`. The build context is allowlisted by `.dockerignore`, so `.env` and unrelated
repository source are not sent to the Docker builder:

```bash
docker build \
  --build-arg MMAUDIT_BASE_IMAGE='python:3.12-slim-bookworm@sha256:<verified-lowercase-digest>' \
  -t mmaudit:local .
docker run --rm \
  --read-only \
  --cpus=2 --memory=4g --pids-limit=256 \
  -e OPENROUTER_API_KEY \
  -v "$PWD:/repo:ro" \
  -v "$PWD/.mmaudit-docker:/output:rw" \
  mmaudit:local run \
  --config /repo/mmaudit.toml \
  --repo /repo --output /output \
  --allow-code-egress --require-zdr --budget-usd 20
```

Enable network access only to reach OpenRouter; the built-in Docker image has no scanner databases.
Docker reduces accidental access but is not a complete security boundary. Do not mount the Docker
socket, home directory, SSH material, or cloud credentials.

For untrusted dynamic tooling, `isolation_backend = "rootless-container"` additionally requires a
locally available rootless Docker or Podman runtime and a final toolchain image reference pinned as
`name@sha256:<digest>`. The backend uses `--pull never`, a read-only root filesystem, a private
temporary home, no network, no capabilities, a deny-by-default syscall profile, fixed
CPU/memory/PID/file limits, and a cleanup CID file. Ordinary target mounts are read-only. Repository
JavaScript receives only a writable disposable copy so local build artifacts can be collected; the
original repository is not mounted.

Every scanner, compiler, reproduction, and formal workspace copy first applies the same bounded
tree validation: unsupported/control-format paths, symlinks, junctions, hardlinks, special files,
oversized files, and excessive entry/file/byte totals are rejected before tool execution. Direct
container arguments cannot traverse above an isolated mount. The synthetic
`tests/fixtures/adversarial_repository/` suite exercises fake local binaries, link and traversal
attempts, private environment/home handling, network/socket denial, bounded child/output behavior,
crafted names, and prompt-injection delimiters. Its real runtime probe is opt-in and is reported as
skipped—not passed—when no verified rootless image is configured.

## Reports and status semantics

Each invocation creates:

```text
.mmaudit/runs/<UTC_TIMESTAMP>-<RUN_SUFFIX>/
├── metadata.json
├── repository-map.json
├── language-capability.json # requested/achieved profile and source-bound evidence
├── scanner-results.json
├── repository-suite-differential.json # when an applicable suite matrix ran
├── solidity-projects.json
├── dependency-preparation.json
├── dependency-sbom.json
├── solidity-compilation.json
├── solidity-index.json
├── solidity-graphs.json
├── solidity-shards.json
├── solidity-invariants.json
├── invariant-review.json
├── invariant-execution-results.json
├── economic-simulation-plan.json
├── formal-results.json
├── solidity-coverage.json     # legacy coverage compatibility output
├── model-review-coverage.json
├── candidate-findings.json
├── execution-origin-dispositions.json
├── verification-results.json
├── reproduction-results.json
├── context-manifest.json
├── scheduler-state.json      # when the seven-pass scheduler ran
├── maximum_assurance_traceability.json
├── run-evidence-manifest.json
├── client-report.md          # concise Corrovera client assessment
├── forensic-report.md        # exhaustive evidence and coverage companion
├── findings.json             # typed final, rejected, and candidate-linked evidence
├── coverage.json             # typed scope and coverage projection
├── model-execution.json      # non-secret model identity, usage, latency, and cost
├── final-findings.json
├── audit-report.md           # legacy exhaustive Markdown compatibility output
├── audit-results.sarif
├── logs/
└── private/                 # scanner output; debug model material only when enabled
```

`run-evidence-manifest.json` is self-hashed and binds the normalized source inventory,
complete effective configuration, allowlisted environment and CLI override layers, non-secret run
options, prompts, model and executable identities, compiler and isolation evidence, campaign seeds,
property corpus, generated harnesses, reproductions, coverage, and every other regular run artifact.
Manifest schema `1.2` additionally requires and semantically reconciles the complete client and
forensic report bundle. It can reconstruct a profile-overridden run without relying on ambient
environment state or operator recollection; supplying `--config` additionally checks the current
base configuration for drift. The manifest excludes itself from the artifact list so its canonical
digest is stable. Schema `1.1` remains readable for pre-bundle runs. Legacy schema `1.0` manifests
remain readable but require an explicit
configuration for verification, replay, and certification.
For `generic-source-review`, Solidity-only artifact leaves may contain explicit non-applicable
evidence or be absent according to their typed contract, and Solidity-only quality gates are not
applied. The language-capability artifact and reduced report banner remain mandatory.
The canonical schema `1.2` public report bundle consists of `client-report.md`,
`forensic-report.md`, `findings.json`, `audit-results.sarif`, `coverage.json`, and
`model-execution.json`. CI requires and stages those exact manifest-bound leaves. The older
`audit-report.md` and `solidity-coverage.json` names remain explicitly allowlisted compatibility
outputs, but the public staging step copies them only when they are present in the verified manifest;
they are not additional canonical public-bundle requirements.
The self-hash provides deterministic integrity and reconciliation, not an external
signature; retain a trusted manifest digest or release attestation when provenance
must survive a fully rewritten artifact set.

Final artifacts are copied to `.mmaudit/latest/`. Use:

```bash
mmaudit explain MMA-0123456789AB --output .mmaudit
```

Statuses mean:

- `confirmed`: verifier acceptance plus reproduced/minimized local fork evidence or strong
  deterministic analyzer evidence with validated reachability and impact. Source-overlapping formal
  counterexamples are retained as nonconfirming observations until an exact candidate-to-property
  binding is available.
- `strongly_supported`: complete validated attack path and independent support, but no reproduction
  or deterministic proof strong enough for confirmation.
- `high_confidence`: one strong source-to-sink analysis, valid locations, verifier acceptance, and no
  identified contradictory control.
- `plausible`: coherent source evidence survived review, but important assumptions remain unverified.
- `needs_review`: a surviving hypothesis that is **not a fact**.
- `insufficient_context` / `unsupported`: required code, configuration, tooling, or safe execution
  support was unavailable.
- `rejected`: unsupported, invalidly located, contradicted, verifier-rejected, or disproven by a
  complete generated test.

Model agreement alone is never enough for `confirmed`. Critical/high/medium/low/informational
severity describes potential impact, while confidence describes evidentiary strength. The judge can
lower deterministic consensus status but cannot raise it or invent findings. SARIF contains surviving
findings and stable fingerprints; JSON retains votes, evidence, validation, generated reproduction
results, disputed/rejected groups, cost, and routing metadata.

For Solidity/EVM maximum assurance, the report also carries a machine-readable contract result:

- `COMPLETE`: every required clause passed;
- `DOWNGRADED`: missing clauses were accepted only through the explicit downgrade flag;
- `FAILED`: a mandatory capability was absent or never analyzed;
- `INCONCLUSIVE`: a required engine was attempted but failed or timed out.

The badge describes execution completeness, not a guarantee that the contracts are safe.

Exit codes are `0` success/below threshold, `1` findings at or above `--fail-on`, `2` configuration or
usage, `3` required scanner/source-integrity failure, `4` provider/model failure, `5` privacy/secret
refusal, and `6` budget exhaustion/incomplete work.

## Benchmarking

`benchmarks/corpus/manifest.json` is a versioned, attributed corpus manifest with vulnerable, patched,
clean, and ambiguous controls. The evaluator scores actual audit reports; it does not count fixture
labels as detections.

```bash
mmaudit benchmark \
  --profile maximum-assurance \
  --corpus benchmarks/corpus/manifest.json \
  --reports /path/to/per-fixture/reports \
  --output-json benchmark-results.json
```

It reports recall by severity, case-level precision and false-positive rates, reproduction success,
cost, token use, runtime, time to first candidate, unique role/family contribution, explicit
coverage numerators/denominators, semantic graph coverage, economic-template execution coverage,
evidence-cap bypasses, and incomplete maximum-assurance reports. With no report directory it
validates the corpus and exits incomplete rather than claiming a score. CI benchmark gates fail on
missed known critical cases, confirmed high/critical safe controls, evidence-cap bypasses, omitted
coverage, or missing per-repository maximum-assurance semantic/economic coverage metrics.

## Candidate-bound release evidence

Automatic release collection and publication currently fail closed before reading inputs, creating
directories, writing evidence, or executing gates. Portable POSIX pathname APIs cannot prove that a
directory opened after `mkdir` is the exact object created when another same-UID process may replace
the name. `scripts/generate_release_report.py` and `make release-generate` therefore terminate with
the explicit technical blocker until evidence construction is descriptor-native or in-memory and
publication can use one exact regular-file handoff.

Standalone validation remains available for an externally prepared report and evidence bundle. It
returns a cryptographic snapshot of the exact bytes observed and does not claim that mutable source
paths stay unchanged after validation:

```bash
python scripts/validate_release_evidence.py --full \
  --report-root /path/to/report/root \
  --report-path release-gate-report.json \
  --evidence-root /path/to/evidence/root \
  --release-repository /path/to/clean/mmaudit \
  --target-repository /path/to/audited/source \
  --configuration-root /path/to/configuration/root \
  --run-dir /path/to/emitted/run \
  --artifact-evidence-file /path/to/artifact-evidence.json \
  --run-verification-file /path/to/current-run-verification.json
```

`--configuration-root` is the exact directory against which the sealed run's relative ignore-file
path was resolved. Add `--require-complete` only when all twelve real maximum-assurance prerequisites
are expected to pass. A committed copy of a report is historical evidence; changing the candidate
commit requires a newly prepared and validated external report.

## CI

Automatic hosted CI is paused during engine stabilization. Both workflow definitions retain only
`workflow_dispatch`; pushes, pull requests, and the daily metadata-refresh schedule do not trigger
them. The two existing workflows in `londonjevans/Auditor` were also disabled on GitHub on
2026-09-06 to stop existing automatic triggers immediately. Manual dispatch requires publishing
these manual-only definitions to the default branch and re-enabling the selected workflow first.
This pause does not make failing checks pass or extend model-metadata freshness windows.

Continue local validation with `make check PYTHON=.venv/bin/python` and focused tests for each
ticket. The fast, read-only `make governance PYTHON=.venv/bin/python` check runs before pytest in
`make test` and `make check`; it verifies queue agreement, current artifact bindings and worklog
headers without granting provider or release authority. Current engineering coordination lives only in
`current_engineering_state` in runtime-status/traceability metadata; surrounding historical fields
retain their original scope and cannot select today's work. Restore automatic CI once the hosted
environment and validation baseline pass reliably, before deployment; use deliberate manual
checkpoints while stabilizing that baseline. Provider
metadata refresh remains an explicit prerequisite whenever current metadata is required.

Framed-review integrity checks regenerate a complete schema inventory on every invocation using
Pydantic's [multi-model schema generation](https://pydantic.dev/docs/validation/latest/api/pydantic/json_schema/#models_json_schema).
Shared definitions are reused only within that invocation. Validator generations, model descriptors,
renderer bindings and mutable schema/configuration inputs are checked across generation; in-place
changes remain visible, including changes made by a later schema callback. The per-call input
snapshot is bounded and rejects unsupported mutable containers. This does not cache a passing
integrity decision or change the provider wire schemas.
Local performance measurements and their scope are recorded in `docs/codex_worklog.md`.

Automatic formatting/lint discovery excludes the exact external-evidence file
`docs/remediation/v3/operator_results.md`, alongside the existing source/capture exclusions.
Its quoted code is an observation, not owned source to rewrite; governance still verifies its
exact bytes and reported accounting. Owned source and adjacent documentation remain in scope.
Ruff's [exclusion rules](https://docs.astral.sh/ruff/settings/#extend-exclude) apply to directory
discovery; explicit file arguments can override them unless `--force-exclude` is supplied.
Do not pass the operator evidence file directly to a mutating formatter.

New operator reports can change the current evidence digest without changing the pinned original
September-4 report. Governance checks preserve that original introduction/history byte-for-byte
and bind today's summary to the exact new report bytes, latest dated entry and explicit reported
accounting. Ordinary line wrapping and inline accounting sentences are accepted without joining
facts across paragraphs or hidden examples. Quoted/code examples, absent or ambiguous accounting,
and stale summaries cannot supply current facts. The [operator guide](docs/remediation/v3/operator_prerequisites.md#current-engineering-coordination-versus-historical-evidence)
describes the bounded report format. This is local consistency checking, not ledger authentication,
an append-only journal for every later report, or paid-execution authority.

`.github/workflows/mmaudit.yml` is the provider-free deterministic path. Manual invocations call
`mmaudit ci`, which is structurally scanner-only and cannot schedule model roles. The workflow file
has no provider-secret reference. Checkout uses full Git history so `--changed-since` can prioritize
the exact base revision without reducing the complete coverage denominator. Existing push and
pull-request event handling is retained for future re-enablement of automatic triggers.

Default-branch runs may save a successful, integrity-checked prior run as a candidate CI baseline.
Pull requests can restore only the cache namespace for their trusted base commit. Admission requires
a deterministic-and-quality-gate success marker bound to that exact commit and semantic validation
of the prior manifest, findings, CI state, complete scanner-workspace hash, effective configuration,
run status, and producer identities; otherwise `mmaudit ci` runs fresh. Cache publication occurs only
after public evidence upload and final gate propagation. A run whose quality, audit, artifact
integrity, or semantic baseline validation failed is never saved as an admissible cache. A cached
run is a comparison-only optimization candidate, never current execution evidence by declaration.
The cache contains only the original self-hashed manifest plus its bound `final-findings.json` and
`ci-state.json`; its commit admission marker sits outside that three-file bundle. The bundle loader
rejects extra files and revalidates the selected bindings and cross-artifact semantics. The workflow
never caches `private/`, logs, raw scanner output, or the complete run directory.

Repository-owned Foundry or Hardhat suites remain subject to mmaudit's configured hardened-isolation
policy. CI does not fall back to executing those suites directly on the host. Missing tools,
unsupported projects, or unavailable isolation are reported as unavailable/incomplete and can fail
the configured gate; they are never presented as successful execution. The example installs
Bubblewrap for networkless local engines, but Bubblewrap does not supply isolated loopback. An
applicable fork suite that requires a pinned local RPC therefore fails closed until the operator
configures an approved rootless backend with that capability. The hosted workflow currently
provisions Bubblewrap and mmaudit itself, not the complete pinned Solidity compiler, Slither,
Foundry, Hardhat, or complementary engine portfolio. Projects that require an unprovisioned tool
therefore remain an explicit external CI execution-stack blocker and fail closed; availability is
not reported as execution.

The audit exit code is captured so artifact observation, integrity verification, public artifact
upload, and eligible SARIF upload still run. The final step then propagates the audit or evidence
failure. Same-repository pull requests can upload SARIF through the isolated `upload-sarif` job,
which has no checkout or shell step. Fork pull requests normally lack `security-events: write`, so
their always-attempted `mmaudit-scanner-reports` artifact is the explicit fallback. Private evidence
and raw model material are never included in that artifact. Each audit writes to a new
`RUNNER_TEMP` directory rather than the checkout. After exactly one run is discovered and verified,
the workflow copies a fixed allowlist of manifest-bound public files into a separate fresh staging
directory. Artifact upload addresses only that directory, never a checkout glob. SARIF upload
addresses one exact manifest-bound `audit-results.sarif`; a companion validation marker binds its
hash to the run ID and manifest. Because the original run manifest also binds prohibited
`private/**` and `logs/**` custody, CI does not mislabel the downloadable artifact as the complete
forensic bundle. Instead, `public-evidence-subset-manifest.json` identifies it as a
`NON_FORENSIC_PUBLIC_SUBSET`, hash-binds every copied public leaf (including the original manifest),
and records the excluded artifact classes. Staging fails on an omitted required leaf, an unknown
top-level artifact, or an unclassified nested artifact. The complete forensic bundle remains the
verified original run directory. This staging remains independent of the finding severity exit, so
valid evidence is retained when the audit gate fails because it found an unsafe condition.

Provider access is isolated in `.github/workflows/mmaudit-model.yml`. It has no pull-request trigger,
runs only for manually selected default-branch revisions, and requires approval through
the named `mmaudit-provider` environment. The example performs an exact-provider preflight; it does
not imply that paid model review ran. GitHub cannot encode environment protection settings in this
file: before storing a credential, configure that environment in repository settings with required
reviewers and a default-branch deployment rule. Commit a reviewed, non-secret `mmaudit.toml` on the
default branch and configure `OPENROUTER_API_KEY` only in that protected environment before enabling
the preflight.

Both workflows use minimal default `contents: read` permissions, explicit timeouts and concurrency,
and commit-pinned third-party actions. SARIF remains best effort because GitHub code scanning can be
unavailable; the uploaded public evidence remains the portable result. Review upstream action
release notes and verify signed/tagged releases before changing a pin. Never replace pins with
mutable branch names.

## Auditor self-threat model

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Source leakage | Explicit acknowledgement, ignore rules, bounds, local redaction, ZDR/data-collection routing | Provider or policy failure; excerpts still leave the machine |
| API-key/log leakage | Environment-only key, scrubbed scanner environments, header/log redaction, hashes by default | Host compromise or explicitly enabled debug storage |
| Repository prompt injection / poisoned scanner output | Uniform untrusted-evidence instructions, no tools, strict schemas, verifier and deterministic gates | Models may still be influenced or omit evidence |
| Symlink/path traversal and malicious filenames | Resolved containment, no default link following, hardlink exclusion, relative-path validation, `.git`/key exclusions | Filesystem races on a hostile local host |
| Scanner or dependency compromise | External binary allowlist-by-adapter, repo-local binary rejection, copied workspace, OS isolation, fixed arrays, scrubbed environment, resource limits, offline modes, no auto-install | Scanner/parser supply-chain compromise and host isolation defects remain possible |
| Unbounded spending or denial of service | Conservative reservation, total/per-role/request/file/context/time/concurrency limits | Token estimates and provider-reported cost can differ |
| Provider substitution | Exact IDs, explicit fallback list, random routing disabled, returned model/provider recorded | Provider endpoint metadata is externally asserted |
| Model hallucination | Exact location hashes, source/sink validation, verifier, consensus caps, stable deduplication | Business logic may require unavailable runtime knowledge |
| Unsafe CI / fork secret exposure | Read-only checkout credentials, minimal permissions, fork gating, artifact-only output | Misconfigured self-hosted runners or repository secrets |
| Large/generated/archive input | Size/count bounds, generated/dependency/binary/archive defaults, logical chunking | Deliberately re-included or unusual formats can consume resources |

The process never opens archives, reads home/SSH/cloud credential files into model context, follows
model-generated commands, accesses the Docker socket, or runs builds unless explicit Solidity
compilation is enabled for an isolated local workspace.

## Troubleshooting and limitations

- `doctor` intentionally fails when the API key, exact model IDs, egress acknowledgement, or safe
  privacy defaults are absent. It never prints the key. For a non-ZDR profile it reports
  account/guardrail ZDR compatibility as unobservable from ordinary API-key metadata; a successful
  consented exact-route runtime preflight is required before a frontier-ensemble claim.
- `models check` requires network access. Metadata is cached under `.mmaudit/cache` for six hours;
  use `--refresh` after model/provider changes.
- Environment-derived HTTP proxy settings are ignored to avoid accidental source/key disclosure.
  Organizations requiring a proxy should add and review an explicit client integration.
- Filesystem roots, the home directory itself, and ancestors containing the home directory are
  rejected as over-broad repository scopes; select the concrete project directory instead.
- Offline Trivy/OSV scans fail or skip when databases were not prepared. Update databases only in a
  separate trusted setup phase.
- Generated-language parsers are intentionally lightweight. Python uses AST-level chunks; other
  languages/configuration use complete blocks. Oversized constructs are omitted rather than split.
- Static source cannot establish runtime WAF, row-level security, identity-provider, deployment,
  feature-flag, or data-classification behavior unless represented in the repository.
- Optional CodeQL analysis requires a trusted prebuilt database and suite.
- Hardened local execution depends on a supported OS sandbox. macOS `sandbox-exec` supports
  loopback-only fork execution. Linux Bubblewrap supports no-network scanners, compilation, and
  formal tools, but deliberately does not claim host-loopback fork capability; maximum assurance
  therefore fails closed on that backend until a reviewed isolated RPC proxy or same-namespace fork
  service is available. Docker runtimes must permit unprivileged Bubblewrap namespaces. Direct host
  execution is never used as a fallback.
- A local fork faithfully reproduces only its pinned chain state and configured market assumptions.
  It cannot prove exploitability under every liquidity, ordering, governance, or cross-chain state.
- A provider outage, role timeout, invalid JSON, exhausted budget, or verifier/judge failure produces
  a clearly marked partial report. Do not interpret absence of findings in an incomplete run.

For payment, identity, custody, safety-critical, regulated, multi-tenant, or other high-impact
systems, use mmaudit as one input and obtain an experienced professional security review and
environment-specific testing before release.
