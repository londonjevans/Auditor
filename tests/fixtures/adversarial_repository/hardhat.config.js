const fs = require("fs");

fs.writeFileSync("hardhat-config-executed.marker", "disposable workspace only\n");
module.exports = { solidity: "0.8.24" };
