"use strict";

// Benign loopback-only check of Node's built-in fetch -> node:zlib route.
// Run this trusted fixture, never application code supplied to the inventory.
const assert = require("node:assert/strict");
const { once } = require("node:events");
const http = require("node:http");
const zlib = require("node:zlib");

async function main() {
  assert.equal(typeof globalThis.fetch, "function", "Node must provide built-in fetch");
  const expected = "brotli-checker benign response fixture\n";
  const compressed = zlib.brotliCompressSync(Buffer.from(expected));
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push({
      path: request.url,
      accept_encoding: request.headers["accept-encoding"] ?? null,
    });
    if (request.url === "/redirect") {
      response.writeHead(302, { Location: "/body", Connection: "close" });
      response.end();
      return;
    }
    // Deliberately send br even when the request advertises identity.
    response.writeHead(200, {
      "Content-Type": "text/plain",
      "Content-Encoding": "br",
      "Content-Length": compressed.length,
      Connection: "close",
    });
    response.end(compressed);
  });

  const descriptor = Object.getOwnPropertyDescriptor(zlib, "createBrotliDecompress");
  let decoderCalls = 0;
  Object.defineProperty(zlib, "createBrotliDecompress", {
    ...descriptor,
    value: function (...args) {
      decoderCalls += 1;
      return Reflect.apply(descriptor.value, this, args);
    },
  });

  try {
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const origin = "http://127.0.0.1:" + server.address().port;
    const cases = [
      { name: "default_http", path: "/body", headers: {} },
      { name: "identity_http", path: "/body", headers: { "Accept-Encoding": "identity" } },
      { name: "redirect_identity_http", path: "/redirect", headers: { "Accept-Encoding": "identity" } },
    ];
    const results = [];
    for (const test of cases) {
      const previous = decoderCalls;
      const requestStart = requests.length;
      const response = await globalThis.fetch(origin + test.path, {
        headers: test.headers,
        signal: AbortSignal.timeout(5000),
      });
      const decoded = await response.text();
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("content-encoding"), "br");
      assert.equal(decoded, expected, test.name + " must decode the response");
      assert.ok(decoderCalls > previous, test.name + " must call the native Brotli wrapper");
      assert.equal(response.redirected, test.path === "/redirect");
      const observedRequests = requests.slice(requestStart);
      assert.equal(observedRequests.length, test.path === "/redirect" ? 2 : 1);
      if (test.headers["Accept-Encoding"] === "identity") {
        for (const request of observedRequests) {
          assert.equal(request.accept_encoding, "identity");
        }
      }
      results.push({
        case: test.name,
        requests: observedRequests,
        decoded_body_matches: decoded === expected,
        native_brotli_decoder_calls: decoderCalls - previous,
        redirected: response.redirected,
      });
    }
    console.log(JSON.stringify({
      node: process.version,
      brotli: process.versions.brotli,
      undici: process.versions.undici ?? null,
      scope: "Valid Brotli responses from a loopback HTTP server; no exploit payload.",
      patch_status: "not_assessed",
      exploitability: "not_assessed",
      results,
    }, null, 2));
  } finally {
    Object.defineProperty(zlib, "createBrotliDecompress", descriptor);
    if (server.listening) {
      await new Promise((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
        server.closeAllConnections();
      });
    }
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
