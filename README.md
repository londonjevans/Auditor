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

`mmaudit` is Corrovera Security's read-only, repository-aware defensive security audit engine. It
combines local deterministic scanners and Solidity program modelling with independent base and
specialist model roles, typed stateful/invariant testing, optional formal engines, an adversarial
verifier and falsifier, deterministic location and consensus checks, and an evidence-capped final
judge. It emits branded Markdown, versioned JSON, and SARIF 2.1.0.

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

mmaudit doctor --secrets-env-file /absolute/operator/control/mmaudit-secrets.env
mmaudit scan --repo ../..
mmaudit models init-cost-ledger --cost-ledger /absolute/operator/control/mmaudit-cost-ledger.json
mmaudit run --repo ../.. --allow-code-egress --budget-usd 20 \
  --secrets-env-file /absolute/operator/control/mmaudit-secrets.env \
  --cost-ledger /absolute/operator/control/mmaudit-cost-ledger.json
```

This repository is the auditor itself, so local commands normally use `--repo .`.

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
then enable it with `[scanners.slither].enabled = true` or `--run-slither`. Missing Solidity tools or
isolation are reported as unavailable; their absence is not treated as proof that contracts are safe.

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
analysis roles. Deep and maximum-assurance configurations add narrowly scoped specialists; maximum
assurance requires at least five independent families, all configured specialist responsibilities,
and at least eight unique high-quality slots unless an explicit downgrade is allowed. Quality tiers
are operator-maintained capability labels, not a claim that a changing model is permanently
“frontier.” The verifier, falsifier, and judge should be independent from proposing roles. The
catalog list reports the strongest advertised output mode: native JSON Schema, JSON object, or
strictly validated text JSON. Exact endpoint discovery is authoritative because catalog and endpoint
capabilities may differ. Validate exact identity, duplication, family diversity, endpoint output
mode, and current privacy eligibility:

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

## Configuration

Run `mmaudit init` to create `mmaudit.toml` and `.mmauditignore`. Existing files are never replaced
unless `--force` is supplied. The example documents all fields.

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

Useful environment overrides are `MMAUDIT_BUDGET_USD`, `MMAUDIT_CONCURRENCY`,
`MMAUDIT_MAX_FILES`, `MMAUDIT_MAX_WALK_ENTRIES`, `MMAUDIT_MAX_FILE_BYTES`,
`MMAUDIT_MAX_DISCOVERY_BYTES`, `MMAUDIT_MAX_CONTEXT_BYTES`, `MMAUDIT_MAX_REQUEST_BYTES`,
`MMAUDIT_SCOPE`, `MMAUDIT_REQUIRE_COMPLETE_SCOPE`,
`MMAUDIT_PRIOR_AUDIT_PATH`, `MMAUDIT_REQUIRE_PRIOR_AUDIT`,
`MMAUDIT_FAIL_ON_MISSED_PRIOR`,
`MMAUDIT_ALLOW_CODE_EGRESS`, `MMAUDIT_REQUIRE_ZDR`, `MMAUDIT_PROFILE`,
`MMAUDIT_FORK_BLOCK_NUMBER`, and `MMAUDIT_FORK_CHAIN_ID`. The API key is accepted only through
`OPENROUTER_API_KEY`, never a CLI argument.

Defaults limit files to 2,000, filesystem walk entries to 50,000, individual files to 250 KB,
retained discovery content to 50 MB, total role-context allocations to 2 MB, parallel requests to
three, serialized model requests to 4 MB, scanner execution to 15 minutes, model requests to three
minutes, model retries to two, JSON repair to one, and total accounted spend to USD 20. Conservative
pre-request reservations include the maximum response allowance. A request is refused if its
worst-case estimate does not fit the remaining run budget.

Audit profiles are explicit: `quick`, `standard`, `deep`, and `maximum-assurance`. The default
`standard` profile preserves the bounded general-purpose behavior. `maximum-assurance` enables
isolated Solidity compilation, requires Slither, the full semantic-graph transforms, specialist
review, invariant discovery and execution, generated local-fork reproduction, verifier/falsifier
review, evidence-capped judgment, coverage reporting, and optionally a benchmark gate. It never
silently downgrades. `--allow-maximum-assurance-downgrade` is the only downgrade path and the result
is labelled `DOWNGRADED` in Markdown, JSON, and SARIF. Without that flag, a skipped, unavailable,
failed, timed-out, or under-covered mandatory stage prevents `COMPLETE`.

## Quick start

```bash
mmaudit init
# Edit exact model IDs and consciously review [privacy].
mmaudit doctor
mmaudit scan --repo .
mmaudit models init-cost-ledger --cost-ledger /absolute/operator/control/mmaudit-cost-ledger.json
mmaudit run --repo . --allow-code-egress --budget-usd 20 --fail-on high \
  --cost-ledger /absolute/operator/control/mmaudit-cost-ledger.json
```

For the stricter Solidity path, configure `[reproduction].targets`, pin the fork block/chain, point
`MMAUDIT_FORK_RPC_URL` at an already-running local fork, then run:

```bash
mmaudit run --repo . \
  --profile maximum-assurance \
  --require-maximum-assurance \
  --compile --run-slither \
  --allow-code-egress --allow-fork \
  --budget-usd 20 \
  --cost-ledger /absolute/operator/control/mmaudit-cost-ledger.json
```

`--changed-since origin/main` restricts prioritization to changed files while retaining surrounding
security, test, and dependency context. Other bounded overrides include `--max-files`,
`--max-file-bytes`, `--max-context-bytes`, `--concurrency`, `--severity-threshold`,
`--skip-codeql`, and `--require-zdr`.

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

Compilation is disabled by default because build systems can execute project code. Hardhat
configuration and plugins are permitted only through a digest-pinned rootless container with no
network; without that boundary, the operation fails before resolving or starting Hardhat. Enable
compilation only for a repository you intend to analyze:

```bash
mmaudit scan --repo . --compile --run-slither
mmaudit run --repo . --compile --run-slither --allow-code-egress --budget-usd 20 \
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
limitations, never evidence of safety. Specific engines become mandatory only through
`[formal].required_tools`.

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

Maximum assurance requires 20 narrow investigator responsibilities: access control,
reentrancy/control flow, economic game theory, oracle manipulation, accounting/invariants, token
standards, ERC4626, AMMs, lending, governance, upgradeability/storage,
initialization/deployment, signatures/replay, MEV/ordering, denial of service/griefing,
precision/rounding, bridges, dependency/supply chain, formal properties, and blind false-negative
hunting. Separate auxiliary passes handle test generation, reproduction planning, non-finding
invariant review, falsification, and report-quality review. Primary investigators run blind to one
another; later stages receive grouped evidence. Duplicate model IDs or generic repeated agents do
not satisfy missing responsibilities, do not create independent votes, and model agreement alone
cannot confirm a Solidity finding.

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

The legacy `[scanners.foundry_fork]` adapter is only for pre-existing `test/audit/*.t.sol` suites.
Candidate-specific generated reproduction is controlled by `[reproduction]` and is the Solidity
evidence gate used by the pipeline.

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
├── scanner-results.json
├── solidity-projects.json
├── dependency-preparation.json
├── dependency-sbom.json
├── solidity-compilation.json
├── solidity-index.json
├── solidity-graphs.json
├── solidity-invariants.json
├── invariant-review.json
├── invariant-execution-results.json
├── economic-simulation-plan.json
├── formal-results.json
├── solidity-coverage.json
├── candidate-findings.json
├── verification-results.json
├── reproduction-results.json
├── maximum_assurance_traceability.json
├── run-evidence-manifest.json
├── final-findings.json
├── audit-report.md
├── audit-results.sarif
├── logs/
└── private/                 # scanner output; debug model material only when enabled
```

`run-evidence-manifest.json` is self-hashed and binds the normalized source inventory,
complete effective configuration, allowlisted environment and CLI override layers, non-secret run
options, prompts, model and executable identities, compiler and isolation evidence, campaign seeds,
property corpus, generated harnesses, reproductions, coverage, and every other regular run artifact.
Manifest schema `1.1` can reconstruct a profile-overridden run without relying on ambient
environment state or operator recollection; supplying `--config` additionally checks the current
base configuration for drift. The manifest excludes itself from the artifact list so its canonical
digest is stable. Legacy schema `1.0` manifests remain readable but require an explicit
configuration for verification, replay, and certification.
The self-hash provides deterministic integrity and reconciliation, not an external
signature; retain a trusted manifest digest or release attestation when provenance
must survive a fully rewritten artifact set.

Final artifacts are copied to `.mmaudit/latest/`. Use:

```bash
mmaudit explain MMA-0123456789AB --output .mmaudit
```

Statuses mean:

- `confirmed`: verifier acceptance plus reproduced/minimized local fork evidence, formal
  proof/counterexample, or strong deterministic analyzer evidence with validated reachability and
  impact.
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

For maximum assurance, the report also carries a machine-readable contract result:

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

Release reporting is derived from an explicit emitted run and a clean exact mmaudit commit. The
generator accepts only pre-existing empty private output directories outside the product candidate,
audited target, and emitted run. It executes the four fixed provider-free quality commands, validates
typed artifact/manifest/schema observations, and preserves unavailable benchmark, model, doctor,
maximum-assurance, and replay prerequisites as blockers.

```bash
mkdir -m 700 /private/tmp/mmaudit-release-evidence /private/tmp/mmaudit-release-report
python scripts/generate_release_report.py \
  --release-id candidate-commit-short-id \
  --release-repository /path/to/clean/mmaudit \
  --target-repository /path/to/audited/source \
  --run-dir /path/to/emitted/run \
  --artifact-evidence-file /path/to/artifact-evidence.json \
  --run-verification-file /path/to/current-run-verification.json \
  --evidence-root /private/tmp/mmaudit-release-evidence \
  --report-root /private/tmp/mmaudit-release-report
```

Generation includes authoritative integrity validation but does not imply completeness. Apply
`scripts/validate_release_evidence.py --full --require-complete` to the explicit report and evidence
paths when all twelve real maximum-assurance prerequisites are expected to pass. A committed copy of
a report is historical evidence; changing the candidate commit requires a newly generated external
report.

## CI

`.github/workflows/mmaudit.yml` is the provider-free deterministic path. Pull requests, default-branch
pushes, and manual invocations all call `mmaudit ci`, which is structurally scanner-only and cannot
schedule model roles. The workflow file has no provider-secret reference. Checkout uses full Git
history so `--changed-since` can prioritize the exact base revision without reducing the complete
coverage denominator.

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
hash to the run ID and manifest. This staging remains independent of the finding severity exit, so
valid evidence is retained when the audit gate fails because it found an unsafe condition.

Provider access is isolated in `.github/workflows/mmaudit-model.yml`. It has no pull-request trigger,
runs only for scheduled or manually selected default-branch revisions, and requires approval through
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
