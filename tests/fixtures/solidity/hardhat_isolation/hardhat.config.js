"use strict";

// This harmless side effect is the containment canary. It must never appear in the
// operator's source repository when audit tooling loads this synthetic configuration.
require("node:fs").writeFileSync(
  "repository-config-executed.marker",
  "synthetic isolated configuration\n",
);

module.exports = {
  solidity: "0.8.20",
};
