"use strict";
// Fixed finite reporter control: no target JavaScript, Mocha, contracts or network.
const EventEmitter = require("node:events");
const path = require("node:path");
const Reporter = require(process.argv[2]);
const outputPath = process.argv[3];
const repositoryRoot = process.argv[4];
const request = JSON.parse(process.argv[5]);
const selection = JSON.parse(process.argv[6]);
const mode = process.argv[7];
const exitCode = Number(process.argv[8]);
if (!["pass", "fail", "skip"].includes(mode) || ![0, 7].includes(exitCode)) {
  process.exit(23);
}
const root = { title: "", parent: null };
const suite = { title: "Vault", parent: root };
const test = {
  file: path.join(repositoryRoot, "test/audit/Vault.ts"),
  title: "preserves accounting",
  parent: suite,
  duration: 0,
};
const reporterOptions = {
  schemaVersion: "1.0",
  phase: request.phase,
  outputPath,
  reporterSha256: request.reporter_sha256,
  repositorySha256: request.repository_sha256,
  requestSha256: request.request_sha256,
  repositoryRoot,
  projectRoot: ".",
};
if (request.phase === "test") {
  Object.assign(reporterOptions, {
    selectedTests: [{
      projectRoot: ".",
      path: "test/audit/Vault.ts",
      suiteName: "Vault",
      testName: "preserves accounting",
      descriptorSha256: selection.tests[0].descriptor_sha256,
    }],
    selectionSha256: request.selection_sha256,
    chainId: request.chain_id,
    blockNumber: request.block_number,
    blockHash: request.block_hash,
    fuzzSeed: request.fuzz_seed,
  });
}
const runner = new EventEmitter();
new Reporter(runner, { reporterOptions });
if (request.phase === "inventory") {
  runner.emit("test", test);
  runner.emit("pending", test);
} else if (mode === "fail") {
  runner.emit("fail", test, new Error("synthetic invariant observation"));
  runner.emit("test end", test);
} else if (mode === "skip") {
  runner.emit("pending", test);
  runner.emit("test end", test);
} else {
  runner.emit("pass", test);
  runner.emit("test end", test);
}
runner.emit("end");
process.exitCode = exitCode;
