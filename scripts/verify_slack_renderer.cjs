"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const http = require("node:http");
const https = require("node:https");
const crypto = require("node:crypto");
const { spawn, execFileSync } = require("node:child_process");
const { once } = require("node:events");
const zlib = require("node:zlib");
// Explicit maintainer test: this launches the installed Slack app in a fresh profile.
// Quit Slack first. The offline scanner never invokes this script.
assert.equal(process.platform, "darwin", "This fixture targets macOS Slack");
assert.equal(typeof WebSocket, "function", "Use Node.js 24 or newer");
const appPath = "/Applications/Slack.app";
const executable = appPath + "/Contents/MacOS/Slack";
const running = execFileSync("/bin/ps", ["-axo", "comm="], {
  encoding: "utf8",
});
assert.ok(
  !running.split("\n").some((line) => line.trim() === executable),
  "Quit your normal Slack instance before running this fixture",
);
execFileSync("/usr/bin/codesign", ["--verify", "--deep", "--strict", appPath], {
  stdio: "pipe",
});
function plistValue(file, key) {
  return execFileSync(
    "/usr/libexec/PlistBuddy",
    ["-c", "Print :" + key, file],
    { encoding: "utf8" },
  ).trim();
}
const slackVersion = plistValue(
  appPath + "/Contents/Info.plist",
  "CFBundleShortVersionString",
);
const frameworkVersion = plistValue(
  appPath +
    "/Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist",
  "CFBundleVersion",
);
const root = fs.mkdtempSync(path.join(os.tmpdir(), "brotli-slack-controller-"));
const profileRoot = path.join(
  os.homedir(),
  "Library/Containers/com.tinyspeck.slackmacgap/Data/tmp",
);
fs.mkdirSync(profileRoot, { recursive: true });
const profile = fs.mkdtempSync(path.join(profileRoot, "brotli-slack-profile-"));
const certFile = path.join(profile, "cert.pem");
const keyFile = path.join(profile, "key.pem");
execFileSync(
  "openssl",
  [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-days",
    "1",
    "-keyout",
    keyFile,
    "-out",
    certFile,
    "-subj",
    "/CN=127.0.0.1",
    "-addext",
    "subjectAltName=IP:127.0.0.1",
  ],
  { stdio: "ignore" },
);
const cert = fs.readFileSync(certFile);
const pubkey = execFileSync("openssl", [
  "x509",
  "-in",
  certFile,
  "-pubkey",
  "-noout",
]);
const der = execFileSync("openssl", ["pkey", "-pubin", "-outform", "der"], {
  input: pubkey,
});
const spki = crypto.createHash("sha256").update(der).digest("base64");
const body = "brotli-checker benign Slack renderer fixture\n";
const compressed = zlib.brotliCompressSync(Buffer.from(body));
const requests = [];
const handler = (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  requests.push({
    path: req.url,
    accept_encoding: req.headers["accept-encoding"] ?? null,
  });
  const headers = { "Cache-Control": "no-store", Connection: "close" };
  if (url.pathname === "/page") {
    res.writeHead(200, {
      ...headers,
      "Content-Type": "text/html",
      "Content-Security-Policy": "default-src 'none'; connect-src 'self'",
    });
    res.end("<!doctype html><title>Brotli local measurement</title>");
  } else if (url.pathname === "/redirect") {
    res.writeHead(302, { ...headers, Location: "/body" + url.search });
    res.end();
  } else if (url.pathname === "/body") {
    res.writeHead(200, {
      ...headers,
      "Content-Type": "text/plain",
      "Content-Encoding": "br",
      "Content-Length": compressed.length,
    });
    res.end(compressed);
  } else if (url.pathname === "/plain") {
    res.writeHead(200, { ...headers, "Content-Type": "text/plain" });
    res.end(body);
  } else {
    res.writeHead(404, headers);
    res.end();
  }
};
const servers = [
  http.createServer(handler),
  https.createServer({ key: fs.readFileSync(keyFile), cert }, handler),
];
let child, ws;
let serial = 0;
const pending = new Map();
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function rpc(method, params = {}) {
  const id = ++serial;
  const result = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error("CDP timeout: " + method));
    }, 10000);
    pending.set(id, {
      resolve: (x) => {
        clearTimeout(timer);
        resolve(x);
      },
      reject: (e) => {
        clearTimeout(timer);
        reject(e);
      },
    });
  });
  ws.send(JSON.stringify({ id, method, params }));
  return result;
}
async function attach(url) {
  ws = new WebSocket(url);
  await once(ws, "open");
  ws.addEventListener("message", (event) => {
    const msg = JSON.parse(event.data);
    const item = pending.get(msg.id);
    if (item) {
      pending.delete(msg.id);
      msg.error
        ? item.reject(new Error(JSON.stringify(msg.error)))
        : item.resolve(msg.result);
    }
  });
}
async function evaluate(expression) {
  const result = await rpc("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (result.exceptionDetails)
    throw new Error(JSON.stringify(result.exceptionDetails));
  return result.result.value;
}
async function main() {
  const origins = [];
  for (const [i, server] of servers.entries()) {
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    origins.push(
      (i === 0 ? "http" : "https") + "://127.0.0.1:" + server.address().port,
    );
  }
  const log = fs.openSync(
    path.join(root, "slack-isolated-process.log"),
    "w",
    0o600,
  );
  const args = [
    "--user-data-dir=" + profile,
    "--remote-debugging-port=0",
    "--remote-debugging-address=127.0.0.1",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
    "--no-first-run",
    "--no-default-browser-check",
    "--password-store=basic",
    "--use-mock-keychain",
    "--ignore-certificate-errors-spki-list=" + spki,
    "--proxy-server=http://127.0.0.1:9",
    "--proxy-bypass-list=127.0.0.1",
  ];
  const environment = { ...process.env };
  for (const key of ["NODE_OPTIONS", "NODE_PATH", "ELECTRON_RUN_AS_NODE"])
    delete environment[key];
  child = spawn(executable, args, {
    detached: true,
    env: environment,
    stdio: ["ignore", log, log],
  });
  fs.closeSync(log);
  const activePort = path.join(profile, "DevToolsActivePort");
  for (let i = 0; i < 120 && !fs.existsSync(activePort); i++) {
    if (child.exitCode !== null || child.signalCode !== null)
      throw new Error(
        "Isolated Slack exited before debugging was ready: " + child.exitCode,
      );
    await sleep(250);
  }
  assert.ok(
    fs.existsSync(activePort),
    "Slack did not expose isolated debugging endpoint",
  );
  const port = Number(fs.readFileSync(activePort, "utf8").split("\n")[0]);
  assert.ok(port > 0 && port < 65536);
  let targets = [];
  for (let i = 0; i < 60; i++) {
    targets = await (
      await fetch("http://127.0.0.1:" + port + "/json/list")
    ).json();
    if (targets.some((x) => x.type === "page" && x.webSocketDebuggerUrl)) break;
    await sleep(250);
  }
  const target = targets.find(
    (x) => x.type === "page" && x.webSocketDebuggerUrl,
  );
  assert.ok(target, "No renderer in isolated Slack instance");
  assert.ok(target.webSocketDebuggerUrl.startsWith("ws://127.0.0.1:"));
  await attach(target.webSocketDebuggerUrl);
  await rpc("Page.enable");
  const results = [];
  const cases = [
    { name: "plain_control", path: "/plain", headers: {}, compressed: false },
    { name: "default", path: "/body", headers: {}, compressed: true },
    {
      name: "identity",
      path: "/body",
      headers: { "Accept-Encoding": "identity" },
      compressed: true,
    },
    {
      name: "redirect_identity",
      path: "/redirect",
      headers: { "Accept-Encoding": "identity" },
      compressed: true,
    },
  ];
  let renderer;
  for (const origin of origins) {
    const nav = await rpc("Page.navigate", { url: origin + "/page" });
    assert.ok(!nav.errorText, "Local page navigation failed: " + nav.errorText);
    for (let i = 0; i < 60; i++) {
      if ((await evaluate("location.href")) === origin + "/page") break;
      await sleep(100);
    }
    assert.equal(await evaluate("location.href"), origin + "/page");
    renderer = await evaluate(
      '({user_agent:navigator.userAgent,node_require_available:typeof require!=="undefined",node_process_available:typeof process!=="undefined",secure_context:isSecureContext})',
    );
    for (const test of cases) {
      const start = requests.length;
      const expression =
        "(async()=>{const response=await fetch(" +
        JSON.stringify(origin + test.path + "?case=" + test.name) +
        ",{headers:" +
        JSON.stringify(test.headers) +
        ',signal:AbortSignal.timeout(5000)});return {status:response.status,encoding:response.headers.get("content-encoding"),redirected:response.redirected,body:await response.text()};})()';
      const response = await evaluate(expression);
      assert.equal(response.status, 200);
      assert.equal(response.body, body);
      assert.equal(response.encoding, test.compressed ? "br" : null);
      assert.equal(response.redirected, test.path === "/redirect");
      results.push({
        transport: origin.split(":")[0],
        case: test.name,
        requested_accept_encoding: test.headers["Accept-Encoding"] ?? null,
        requests: requests.slice(start),
        content_encoding: response.encoding,
        decoded_body_matches: true,
        redirected: response.redirected,
      });
    }
  }
  const report = {
    schema_version: 1,
    slack_version: slackVersion,
    framework_version: frameworkVersion,
    platform: process.platform,
    architecture: process.arch,
    scope:
      "Installed signed Slack binary in a new empty profile, remote navigation to our valid loopback fixture; no workspace or messages tested.",
    isolation: {
      separate_profile: true,
      outbound_network:
        "Chromium proxy points to closed loopback port; explicit loopback bypass. Node/OS traffic is not independently blocked.",
      existing_workspace_used: false,
      certificate_trust:
        "Command-line exception restricted to ephemeral fixture certificate public-key hash",
      csp_bypassed: false,
      test_disabled_renderer_sandbox: false,
      application_renderer_sandbox_setting: "not_independently_verified",
    },
    renderer,
    patch_status: "not_assessed_by_probe",
    target_application_input_path:
      "not_assessed; trusted debugger navigation is not a message or preview route",
    exploitability: "not_assessed",
    results,
  };
  const output = JSON.stringify(report, null, 2) + "\n";
  if (process.env.BROTLI_CHECKER_OUTPUT)
    fs.writeFileSync(process.env.BROTLI_CHECKER_OUTPUT, output);
  else process.stdout.write(output);
}
async function cleanup() {
  if (ws) ws.close();
  if (child) {
    try {
      child.kill("SIGTERM");
    } catch {}
    if (child.exitCode === null)
      await Promise.race([once(child, "exit"), sleep(4000)]);
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch {}
  }
  for (const server of servers)
    if (server.listening) {
      await new Promise((resolve) => {
        server.close(resolve);
        server.closeAllConnections();
      });
    }
  fs.rmSync(profile, { recursive: true, force: true });
  fs.rmSync(root, { recursive: true, force: true });
}
const watchdog = setTimeout(() => {
  console.error("Slack measurement timed out");
  cleanup().finally(() => process.exit(1));
}, 65000);
main()
  .then(
    () => cleanup(),
    (error) => {
      console.error(error);
      process.exitCode = 1;
      return cleanup();
    },
  )
  .finally(() => clearTimeout(watchdog));
