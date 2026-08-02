"use strict";

// Dependency-free Mocha observation reporter baked into the mmaudit Hardhat image.
// This reporter shares a process with target JavaScript and therefore makes no
// authorship or execution-credit claim. A separate supervisor must bind source,
// process status, and output custody before any downstream evidence can be credited.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const SCHEMA_VERSION = "1.0";
const REPORTER_NAME = "mmaudit-hardhat-reporter";
const REPORTER_VERSION = "1.0.0";
const SHA256 = /^[0-9a-f]{64}$/;
const BLOCK_HASH = /^0x[0-9a-f]{64}$/;
const MAX_TESTS = 10_000;
const MAX_TEXT = 1_000;
const MAX_DETAIL = 8_000;
const PROVENANCE = "untrusted_target_process_observation";

function fail(message) {
  throw new Error(`mmaudit Hardhat reporter: ${message}`);
}

function requireObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  return value;
}

function requireText(value, label, maximum = MAX_TEXT) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    fail(`${label} must be bounded printable text`);
  }
  return value;
}

function requireHash(value, label, pattern = SHA256) {
  if (typeof value !== "string" || !pattern.test(value)) {
    fail(`${label} must be a canonical hash`);
  }
  return value;
}

function requireInteger(value, label, minimum) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    fail(`${label} must be a bounded integer`);
  }
  return value;
}

function requireRelativePath(value, label, allowRoot = false) {
  requireText(value, label);
  if (
    value.includes("\\") ||
    value.startsWith("/") ||
    /^[A-Za-z]:/u.test(value) ||
    (!allowRoot && value === ".") ||
    value === ".." ||
    value.startsWith("../") ||
    value.startsWith("./") ||
    value.includes("/../") ||
    value.includes("/./") ||
    value.endsWith("/..") ||
    value.endsWith("/.") ||
    value.endsWith("/") ||
    value.includes("//")
  ) {
    fail(`${label} must be normalized and repository-relative`);
  }
  return value;
}

function escapedString(value) {
  return JSON.stringify(value).replace(/[^\u0000-\u007e]/gu, (character) =>
    Array.from(character)
      .map((part) => {
        const codePoint = part.codePointAt(0);
        if (codePoint <= 0xffff) {
          return `\\u${codePoint.toString(16).padStart(4, "0")}`;
        }
        const adjusted = codePoint - 0x10000;
        const high = 0xd800 + (adjusted >> 10);
        const low = 0xdc00 + (adjusted & 0x3ff);
        return `\\u${high.toString(16)}\\u${low.toString(16)}`;
      })
      .join(""),
  );
}

function canonicalJson(value, field = null) {
  if (value === null || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    return escapedString(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail("non-finite numbers are prohibited");
    }
    if (field === "duration_seconds" && Number.isInteger(value)) {
      return value.toFixed(1);
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${escapedString(key)}:${canonicalJson(value[key], key)}`)
      .join(",")}}`;
  }
  fail("unsupported value in canonical JSON");
}

function objectHash(value, omittedField) {
  const payload = {};
  for (const [key, item] of Object.entries(value)) {
    if (key !== omittedField) {
      payload[key] = item;
    }
  }
  return crypto.createHash("sha256").update(canonicalJson(payload), "utf8").digest("hex");
}

function reporterOptions(options) {
  const outer = requireObject(options || {}, "Mocha reporter options");
  const configured = requireObject(outer.reporterOptions || {}, "reporterOptions");
  if (configured.schemaVersion !== SCHEMA_VERSION) {
    fail("schema version differs from the committed contract");
  }
  if (!path.isAbsolute(requireText(configured.outputPath, "output path", 4_096))) {
    fail("output path must be absolute");
  }
  if (configured.phase !== "inventory" && configured.phase !== "test") {
    fail("phase must be inventory or test");
  }
  requireHash(configured.reporterSha256, "reporter SHA-256");
  requireHash(configured.requestSha256, "request SHA-256");
  requireHash(configured.repositorySha256, "repository SHA-256");
  if (!path.isAbsolute(requireText(configured.repositoryRoot, "repository root", 4_096))) {
    fail("repository root must be absolute");
  }
  requireRelativePath(configured.projectRoot, "project root", true);
  const normalized = {
    ...configured,
    repositoryRoot: path.resolve(configured.repositoryRoot),
  };
  if (configured.phase === "test") {
    if (!Array.isArray(configured.selectedTests) || configured.selectedTests.length < 1) {
      fail("test phase requires a non-empty selected-test binding");
    }
    if (configured.selectedTests.length > MAX_TESTS) {
      fail("selected-test binding exceeded the test ceiling");
    }
    const bindings = new Map();
    for (const rawBinding of configured.selectedTests) {
      const binding = requireObject(rawBinding, "selected-test binding");
      const observed = {
        project_root: requireRelativePath(
          binding.projectRoot,
          "selected-test project root",
          true,
        ),
        path: requireRelativePath(binding.path, "selected-test path"),
        suite_name: requireText(binding.suiteName, "selected-test suite name"),
        test_name: requireText(binding.testName, "selected-test name"),
      };
      const key = observationKey(observed);
      if (bindings.has(key)) {
        fail("selected-test binding contains a duplicate identity");
      }
      bindings.set(
        key,
        Object.freeze({
          ...observed,
          descriptor_sha256: requireHash(
            binding.descriptorSha256,
            "selected-test descriptor SHA-256",
          ),
        }),
      );
    }
    normalized.bindings = bindings;
  }
  return Object.freeze(normalized);
}

function suiteNameFrom(test) {
  const titles = [];
  const visited = new Set();
  let current = test.parent;
  while (current !== null && current !== undefined) {
    const suite = requireObject(current, "Mocha suite");
    if (visited.has(suite)) {
      fail("Mocha suite ancestry contains a cycle");
    }
    visited.add(suite);
    if (suite.title !== undefined && suite.title !== "") {
      titles.unshift(requireText(suite.title, "Mocha suite title"));
    }
    current = suite.parent;
  }
  return requireText(titles.join(" "), "observed suite name");
}

function observationKey(observation) {
  return [
    observation.project_root,
    observation.path,
    observation.suite_name,
    observation.test_name,
  ].join("\u0000");
}

function observationFrom(test, config) {
  const observedTest = requireObject(test, "Mocha test");
  const rawFile = requireText(observedTest.file, "Mocha test file", 4_096);
  const absoluteFile = path.resolve(rawFile);
  const relativeFile = path.relative(config.repositoryRoot, absoluteFile);
  if (
    relativeFile === "" ||
    path.isAbsolute(relativeFile) ||
    relativeFile === ".." ||
    relativeFile.startsWith(`..${path.sep}`)
  ) {
    fail("Mocha test file escaped the declared repository root");
  }
  const observation = {
    schema_version: SCHEMA_VERSION,
    project_root: config.projectRoot,
    path: requireRelativePath(relativeFile.split(path.sep).join("/"), "observed test path"),
    suite_name: suiteNameFrom(observedTest),
    test_name: requireText(observedTest.title, "observed test name"),
    observation_sha256: "0".repeat(64),
  };
  observation.observation_sha256 = objectHash(observation, "observation_sha256");
  return observation;
}

function resultFrom(test, config, status, terminalDetail) {
  const observation = observationFrom(test, config);
  const binding = config.bindings.get(observationKey(observation));
  if (binding === undefined) {
    fail("test observation was not present in the selected-test binding");
  }
  const milliseconds = test.duration === undefined ? 0 : test.duration;
  if (typeof milliseconds !== "number" || !Number.isFinite(milliseconds) || milliseconds < 0) {
    fail("test duration must be finite and non-negative");
  }
  const result = {
    schema_version: SCHEMA_VERSION,
    descriptor_sha256: binding.descriptor_sha256,
    path: observation.path,
    suite_name: observation.suite_name,
    test_name: observation.test_name,
    status,
    terminal_detail: terminalDetail,
    duration_seconds: milliseconds / 1_000,
    result_sha256: "0".repeat(64),
  };
  result.result_sha256 = objectHash(result, "result_sha256");
  return result;
}

function writeExclusive(outputPath, payload) {
  const encoded = `${canonicalJson(payload)}\n`;
  fs.writeFileSync(outputPath, encoded, { encoding: "utf8", flag: "wx", mode: 0o600 });
}

function compareText(left, right) {
  const leftPoints = Array.from(left, (character) => character.codePointAt(0));
  const rightPoints = Array.from(right, (character) => character.codePointAt(0));
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    if (leftPoints[index] !== rightPoints[index]) {
      return leftPoints[index] < rightPoints[index] ? -1 : 1;
    }
  }
  return leftPoints.length - rightPoints.length;
}

function compareObservation(left, right) {
  const leftKey = [left.project_root, left.path, left.suite_name, left.test_name];
  const rightKey = [
    right.project_root,
    right.path,
    right.suite_name,
    right.test_name,
  ];
  for (let index = 0; index < leftKey.length; index += 1) {
    const compared = compareText(leftKey[index], rightKey[index]);
    if (compared !== 0) {
      return compared;
    }
  }
  return 0;
}

function inventoryEnvelope(config, observations) {
  const tests = observations.slice().sort(compareObservation);
  if (tests.length < 1 || tests.length > MAX_TESTS) {
    fail("inventory must contain a bounded non-empty test set");
  }
  const envelope = {
    schema_version: SCHEMA_VERSION,
    phase: "inventory",
    reporter_name: REPORTER_NAME,
    reporter_version: REPORTER_VERSION,
    reporter_sha256: config.reporterSha256,
    request_sha256: config.requestSha256,
    repository_sha256: config.repositorySha256,
    tests,
    completed: true,
    safety_claim: false,
    authorship_claim: false,
    execution_credit: false,
    provenance: PROVENANCE,
    inventory_sha256: "0".repeat(64),
  };
  envelope.inventory_sha256 = objectHash(envelope, "inventory_sha256");
  return envelope;
}

function executionEnvelope(config, results) {
  requireHash(config.selectionSha256, "selection SHA-256");
  requireInteger(config.chainId, "chain ID", 1);
  requireInteger(config.blockNumber, "block number", 0);
  requireHash(config.blockHash, "block hash", BLOCK_HASH);
  requireHash(config.fuzzSeed, "fuzz seed", BLOCK_HASH);
  const ordered = results
    .slice()
    .sort((left, right) => compareText(left.descriptor_sha256, right.descriptor_sha256));
  if (ordered.length < 1 || ordered.length > MAX_TESTS) {
    fail("execution must contain a bounded non-empty result set");
  }
  const envelope = {
    schema_version: SCHEMA_VERSION,
    phase: "test",
    reporter_name: REPORTER_NAME,
    reporter_version: REPORTER_VERSION,
    reporter_sha256: config.reporterSha256,
    request_sha256: config.requestSha256,
    repository_sha256: config.repositorySha256,
    selection_sha256: config.selectionSha256,
    chain_id: config.chainId,
    block_number: config.blockNumber,
    block_hash: config.blockHash,
    fuzz_seed: config.fuzzSeed,
    results: ordered,
    completed: true,
    safety_claim: false,
    authorship_claim: false,
    execution_credit: false,
    provenance: PROVENANCE,
    report_sha256: "0".repeat(64),
  };
  envelope.report_sha256 = objectHash(envelope, "report_sha256");
  return envelope;
}

class MmauditHardhatReporter {
  constructor(runner, options) {
    const config = reporterOptions(options);
    const observations = new Map();
    const results = [];
    const terminal = new Set();

    if (config.phase === "inventory") {
      const retainObservation = (test) => {
        const observation = observationFrom(test, config);
        observations.set(observationKey(observation), observation);
      };
      runner.on("test", retainObservation);
      runner.on("pending", retainObservation);
    } else {
      runner.on("pass", (test) => {
        terminal.add(test);
        results.push(resultFrom(test, config, "passed", null));
      });
      runner.on("pending", (test) => {
        terminal.add(test);
        results.push(resultFrom(test, config, "skipped", null));
      });
      runner.on("fail", (test, error) => {
        terminal.add(test);
        const message = requireText(String(error && error.message ? error.message : error), "failure detail", MAX_DETAIL);
        results.push(resultFrom(test, config, "failed", message));
      });
      runner.on("test end", (test) => {
        if (!terminal.has(test)) {
          fail("test ended without one classified terminal event");
        }
      });
    }

    runner.once("end", () => {
      const payload =
        config.phase === "inventory"
          ? inventoryEnvelope(config, Array.from(observations.values()))
          : executionEnvelope(config, results);
      writeExclusive(config.outputPath, payload);
    });
  }
}

module.exports = MmauditHardhatReporter;
module.exports.REPORTER_NAME = REPORTER_NAME;
module.exports.REPORTER_VERSION = REPORTER_VERSION;
module.exports.SCHEMA_VERSION = SCHEMA_VERSION;
