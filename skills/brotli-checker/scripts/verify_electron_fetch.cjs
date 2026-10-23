"use strict";

// Trusted, benign fixture for a separately obtained Electron runtime.
// Never launch a target app or use its profile to run this fixture.
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const { X509Certificate } = require("node:crypto");
const { once } = require("node:events");
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const tls = require("node:tls");
const zlib = require("node:zlib");
const { app, BrowserWindow, net, session } = require("electron");

assert.ok(process.versions.electron, "Run with an Electron executable");
const profile = fs.mkdtempSync(
  path.join(os.tmpdir(), "brotli-electron-profile-"),
);
app.setPath("userData", profile);
app.setPath("sessionData", profile);
app.setPath("logs", path.join(profile, "logs"));
app.commandLine.appendSwitch("disable-background-networking");
app.commandLine.appendSwitch("disable-component-update");
app.commandLine.appendSwitch("disable-sync");
app.commandLine.appendSwitch("no-first-run");

const expected = "brotli-checker benign Electron response fixture\n";
const compressed = zlib.brotliCompressSync(Buffer.from(expected));
assert.notEqual(compressed.toString("utf8"), expected);
const requests = [];
const blockedRequests = [];
const certificatePath = path.join(profile, "localhost-cert.pem");
const keyPath = path.join(profile, "localhost-key.pem");
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
    keyPath,
    "-out",
    certificatePath,
    "-subj",
    "/CN=127.0.0.1",
    "-addext",
    "subjectAltName=IP:127.0.0.1",
  ],
  { stdio: "ignore" },
);
const certificate = fs.readFileSync(certificatePath, "utf8");
const fingerprint = new X509Certificate(certificate).fingerprint256;
assert.equal(
  typeof tls.setDefaultCACertificates,
  "function",
  "Electron must embed Node >=24.5",
);
const originalCAs = tls.getCACertificates("default");
tls.setDefaultCACertificates([...originalCAs, certificate]);

function handleRequest(request, response) {
  requests.push({
    path: request.url,
    accept_encoding: request.headers["accept-encoding"] ?? null,
  });
  const url = new URL(request.url, "http://127.0.0.1");
  const headers = { "Cache-Control": "no-store", Connection: "close" };
  if (url.pathname === "/page") {
    response.writeHead(200, {
      ...headers,
      "Content-Type": "text/html",
      "Content-Security-Policy": "default-src 'none'; connect-src 'self'",
    });
    response.end("<!doctype html><title>Local Brotli measurement</title>");
  } else if (url.pathname === "/redirect") {
    response.writeHead(302, {
      ...headers,
      Location: "/body" + url.search,
    });
    response.end();
  } else if (url.pathname === "/body") {
    response.writeHead(200, {
      ...headers,
      "Content-Type": "text/plain",
      "Content-Encoding": "br",
      "Content-Length": compressed.length,
    });
    response.end(compressed);
  } else if (url.pathname === "/plain") {
    response.writeHead(200, { ...headers, "Content-Type": "text/plain" });
    response.end(expected);
  } else {
    response.writeHead(404, headers);
    response.end();
  }
}
const servers = [
  http.createServer(handleRequest),
  https.createServer(
    { key: fs.readFileSync(keyPath), cert: certificate },
    handleRequest,
  ),
];

const descriptor = Object.getOwnPropertyDescriptor(
  zlib,
  "createBrotliDecompress",
);
let decoderCalls = 0;
Object.defineProperty(zlib, "createBrotliDecompress", {
  ...descriptor,
  value: function (...args) {
    decoderCalls += 1;
    return Reflect.apply(descriptor.value, this, args);
  },
});

async function readResponse(fetcher, url, headers) {
  const response = await fetcher(url, {
    headers,
    signal: AbortSignal.timeout(5000),
  });
  return {
    status: response.status,
    content_encoding: response.headers.get("content-encoding"),
    redirected: response.redirected,
    body: await response.text(),
  };
}

function restrictSession(ses, origins) {
  ses.setPermissionRequestHandler((_contents, _permission, callback) =>
    callback(false),
  );
  ses.setPermissionCheckHandler(() => false);
  ses.webRequest.onBeforeRequest((details, callback) => {
    const allowed =
      origins.some((origin) => details.url.startsWith(origin + "/")) ||
      details.url === "about:blank";
    if (!allowed) blockedRequests.push(details.url);
    callback({ cancel: !allowed });
  });
  // Trust this ephemeral certificate only, in these isolated probe sessions.
  ses.setCertificateVerifyProc((request, callback) => {
    const matches =
      request.hostname === "127.0.0.1" &&
      new X509Certificate(request.certificate.data).fingerprint256 ===
        fingerprint;
    callback(matches ? 0 : -2);
  });
}

async function main() {
  await app.whenReady();
  const origins = [];
  for (const [index, server] of servers.entries()) {
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    origins.push(
      (index === 0 ? "http" : "https") +
        "://127.0.0.1:" +
        server.address().port,
    );
  }
  restrictSession(session.defaultSession, origins);
  const isolated = session.fromPartition("brotli-checker-measurement", {
    cache: false,
  });
  restrictSession(isolated, origins);
  await session.defaultSession.setProxy({ mode: "direct" });
  await isolated.setProxy({ mode: "direct" });
  const window = new BrowserWindow({
    show: false,
    webPreferences: {
      session: isolated,
      sandbox: true,
      nodeIntegration: false,
      contextIsolation: true,
      spellcheck: false,
    },
  });
  try {
    await window.loadURL(origins[0] + "/page");
    const renderer = await window.webContents.executeJavaScript(`({
      node_require_available: typeof require !== "undefined",
      node_process_available: typeof process !== "undefined",
      user_agent: navigator.userAgent,
      secure_context: isSecureContext,
    })`);
    assert.equal(renderer.node_require_available, false);
    assert.equal(renderer.node_process_available, false);
    const routes = [
      [
        "main_node_fetch",
        (url, headers) => readResponse(globalThis.fetch, url, headers),
      ],
      [
        "main_net_fetch",
        (url, headers) => readResponse(net.fetch.bind(net), url, headers),
      ],
      [
        "main_session_fetch",
        (url, headers) =>
          readResponse(isolated.fetch.bind(isolated), url, headers),
      ],
      [
        "sandboxed_renderer_fetch",
        (url, headers) =>
          window.webContents.executeJavaScript(
            "(" +
              readResponse.toString() +
              ")(globalThis.fetch," +
              JSON.stringify(url) +
              "," +
              JSON.stringify(headers) +
              ")",
          ),
      ],
    ];
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
    const results = [];
    const violations = [];
    for (const origin of origins) {
      await window.loadURL(origin + "/page");
      for (const [route, fetcher] of routes) {
        for (const test of cases) {
          const start = requests.length;
          const before = decoderCalls;
          let result;
          let error = null;
          try {
            result = await fetcher(
              origin + test.path + "?case=" + route + "_" + test.name,
              test.headers,
            );
          } catch (failure) {
            error = String(failure);
          }
          const observed = requests.slice(start);
          // Instrumentation measures Node's JS/native wrapper, not Chromium calls.
          const calls = decoderCalls - before;
          const decoded = result?.status === 200 && result.body === expected;
          if (
            (!test.compressed ||
              route === "main_node_fetch" ||
              test.name === "default") &&
            !decoded
          ) {
            violations.push(
              origin.split(":")[0] +
                ":" +
                route +
                ":" +
                test.name +
                ": " +
                error,
            );
          }
          if (
            decoded &&
            calls !== (route === "main_node_fetch" && test.compressed ? 1 : 0)
          ) {
            violations.push(
              route +
                ":" +
                test.name +
                ": unexpected Node wrapper count " +
                calls,
            );
          }
          if (
            decoded &&
            result.content_encoding !== (test.compressed ? "br" : null)
          ) {
            violations.push(
              route + ":" + test.name + ": unexpected Content-Encoding",
            );
          }
          results.push({
            transport: origin.split(":")[0],
            route,
            case: test.name,
            requested_accept_encoding: test.headers["Accept-Encoding"] ?? null,
            requests: observed,
            content_encoding: result?.content_encoding ?? null,
            decoded_body_matches: decoded,
            node_zlib_wrapper_calls: calls,
            redirected: result?.redirected ?? null,
            error,
          });
        }
      }
    }
    const report = {
      schema_version: 1,
      platform: process.platform,
      architecture: process.arch,
      versions: process.versions,
      scope:
        "Trusted fixture in a separate Electron runtime; valid loopback HTTP/HTTPS responses only.",
      certificate_trust:
        "Ephemeral loopback certificate pinned for Chromium sessions and added to Node trust for this process only.",
      renderer,
      chromium_wrapper_instrumentation:
        "not_performed; decoded bytes establish response decoding",
      patch_status: "not_assessed_by_probe",
      target_application_input_path: "not_assessed",
      exploitability: "not_assessed",
      blocked_requests: blockedRequests,
      validation_errors: violations,
      results,
    };
    const json = JSON.stringify(report, null, 2) + "\n";
    if (process.env.BROTLI_CHECKER_OUTPUT)
      fs.writeFileSync(process.env.BROTLI_CHECKER_OUTPUT, json);
    else process.stdout.write(json);
    assert.deepEqual(
      violations,
      [],
      "Required decoding/control cases failed; inspect the report",
    );
  } finally {
    window.destroy();
  }
}

const timeout = setTimeout(() => {
  console.error("Electron measurement exceeded 45 seconds");
  app.exit(1);
}, 45000);

main().then(
  () => cleanup(0),
  (error) => {
    console.error(error);
    cleanup(1);
  },
);

async function cleanup(code) {
  clearTimeout(timeout);
  Object.defineProperty(zlib, "createBrotliDecompress", descriptor);
  tls.setDefaultCACertificates(originalCAs);
  for (const server of servers) {
    if (!server.listening) continue;
    await new Promise((resolve) => {
      server.close(resolve);
      server.closeAllConnections();
    });
  }
  if (code !== 0) {
    fs.rmSync(profile, { recursive: true, force: true });
    app.exit(code);
    return;
  }
  app.once("will-quit", () =>
    fs.rmSync(profile, { recursive: true, force: true }),
  );
  process.exitCode = code;
  app.quit();
}
