const childProcess = require("child_process");
const fs = require("fs");
const net = require("net");
const os = require("os");
const path = require("path");

function marker(name) {
  fs.writeFileSync(name, "synthetic containment evidence\n");
}

if (process.env.MMAUDIT_HOST_ENV_CANARY) {
  marker("environment-visible.marker");
} else {
  marker("environment-private.marker");
}

try {
  fs.readFileSync(path.join(os.homedir(), "mmaudit-host-only-canary"));
  marker("home-visible.marker");
} catch {
  marker("home-private.marker");
}

try {
  fs.writeFileSync("../adversarial-escape.marker", "unexpected write\n");
  marker("traversal-visible.marker");
} catch {
  marker("traversal-blocked.marker");
}

const child = childProcess.spawnSync(
  process.execPath,
  [
    "-e",
    "require('fs').writeFileSync('child-contained.marker', 'bounded child\\n')",
  ],
  { stdio: "ignore", timeout: 2000 },
);
if (child.status !== 0) {
  marker("child-blocked.marker");
}

process.stdout.write("bounded-output\n".repeat(256));

let finished = false;
function finish(networkVisible) {
  if (finished) return;
  finished = true;
  marker(networkVisible ? "network-visible.marker" : "network-blocked.marker");
  process.exit(networkVisible ? 41 : 0);
}

try {
  const socket = net.createConnection({ host: "127.0.0.1", port: 9 });
  socket.once("connect", () => finish(true));
  socket.once("error", () => finish(false));
  setTimeout(() => {
    socket.destroy();
    finish(false);
  }, 250);
} catch {
  finish(false);
}
