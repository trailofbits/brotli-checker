# Reachability guide

Use this guide for surfaces present in the target. These are investigation
routes, not assertions that a listed project or deployment is vulnerable.

For each copy, collect a concrete chain:

`artifact/revision -> selected decoder -> caller -> input entry point -> input owner`

Build selection needs a manifest, link/build evidence, or corresponding artifact
provenance. Shipment needs the deployed image/package/binary identity. Reachability
needs the call path and active configuration, including attacker influence and
authentication before decoding. A benign controlled request can establish a
decoding path when authorized; do not send malformed or exploit payloads.

## Node.js and HTTP services/clients

Search for `fetch`, `globalThis.fetch`, `undici`, `brotliDecompress`,
`createBrotliDecompress`, `node:zlib`,
`Content-Encoding`, `body-parser`, and request decoding middleware. Follow the
actual middleware order: authentication in a handler can run after automatic
decompression. Check body parsers and proxies at every receiving boundary.
Ordinary response encoding or an `Accept-Encoding: br` advertisement does not
prove vulnerable request decoding.

Inspect outbound fetch/HTTP response decompression too. Identify whether an
attacker can control an origin, redirect target, fetched document, or intermediary
input. Do not assume all clients decode automatically. Tie the executing Node
binary and its bundled decoder to the deployment; a shell's default `node`
can differ from a service, container, Electron embedder, or packaged executable.

### Node's built-in fetch

Node's [built-in `fetch()` uses Undici](https://nodejs.org/api/globals.html#fetch).
The [bundled implementation in Node v24.22.0](https://github.com/nodejs/node/blob/v24.22.0/deps/undici/src/lib/web/fetch/index.js#L2028-L2088)
pipes Brotli-encoded response bodies through `zlib.createBrotliDecompress()`.
An attacker-controlled response can therefore reach the affected decoder on an
unpatched runtime even when the app never imports Brotli or `node:zlib` itself.

Trace URL inputs, redirects, wrappers, and the actual fetch implementation.
Establish the deployed Node build and vendor patch state. A `fetch()` reference
alone does not prove an attacker-controlled URL or an unpatched runtime.
Changing `Accept-Encoding` alone does not disable response decompression: the
reviewed implementation selects its decoder from response `Content-Encoding`.
Its default HTTPS request advertises Brotli; its HTTP request does not, but a
server can still return a Brotli-encoded body.

The offline helper records JavaScript/TypeScript fetch references, global fetch
property references, Undici imports, and Undici dependency declarations. Its
JSON evidence includes source lines and columns, with at most 20 source matches
per file and an explicit truncation flag. Each lead keeps patch status and
reachability unknown until reviewed. Browser/custom bindings and literal template
text can produce extra leads. Computed names, dynamic loading, bundler rewrites,
and unavailable source can hide calls; the heuristic is not a JavaScript parser.

The helper does not resolve bindings, trace URL ownership, or discover the running
Node version. Its `--node-version` option assesses only a separately obtained
version, and does not associate that version with an unresolved source lead.
Identify the real binary/build and follow the call path through wrappers and
redirects. An Undici import alone does not establish use of its fetch API or
automatic response decoding.

A [benign loopback probe](../scripts/verify_node_fetch.cjs) confirmed built-in
fetch invoking Node's Brotli decoder for valid HTTP response bodies, including
with an identity request header and after a redirect. It did not test malformed
streams, deployment reachability, or exploitation; see the
[validation record](https://github.com/trailofbits/brotli-checker/blob/main/docs/validation.md#benign-built-in-fetch-validation).

## Java HTTP stacks and native JNI providers

Look for `com.aayushatharva.brotli4j`, `DecoderJNI`, `BrotliDecoder`, native
classifier JARs, shaded/nested JARs, and extracted `.so`/`.dll`/`.dylib` files.
Resolve the platform-specific native provider selected at runtime; the wrapper
version is not the embedded C library version. A JVM application can call this
C decoder through JNI, while a pure Java implementation requires separate review.

The reviewed Netty source provides a concrete route:
[HttpContentDecompressor](https://github.com/netty/netty/blob/4.1/codec-http/src/main/java/io/netty/handler/codec/http/HttpContentDecompressor.java)
selects a Brotli decoder for `br` when the provider is available, and
[BrotliDecoder](https://github.com/netty/netty/blob/4.1/codec/src/main/java/io/netty/handler/codec/compression/BrotliDecoder.java)
uses Brotli4j's JNI decoder. Presence of Netty or Brotli4j alone does not show
that this handler is installed, this branch/version is shipped, or native bytes
are vulnerable. Follow server and client pipelines separately.

## WOFF2, fonts, document and image processing

[WOFF2's decoder](https://github.com/google/woff2/blob/master/src/woff2_dec.cc)
calls `BrotliDecoderDecompress` while expanding font data. Trace font uploads,
document conversion, preview rendering, browser/font sanitizers, and asynchronous
jobs to the decoder actually linked by the worker. Encoding fonts is a different
operation. A pinned submodule in the inventory does not establish that a product
ships that submodule instead of a patched system library.

Record one-shot versus streaming calls, input segmentation, length checks, and
the process sandbox. Reaching a public decompression API does not itself prove
the malformed-input/error-buffer path or a usable corruption primitive. Do not
assert that a one-shot call is safe or exploitable without implementation evidence.

## workerd and other embedders

[workerd's system streams](https://github.com/cloudflare/workerd/blob/main/src/workerd/api/system-streams.c++)
include KJ Brotli input streams and content-encoding selection under a compatibility
flag. Follow the target revision through KJ/Cap'n Proto, Bazel/module downloads,
selected Brotli inputs, and the deployed workerd binary. Inspect the active
compatibility flags and the code which supplies each stream. Source support
does not establish a cloud service's deployed version or tenant isolation.

## TLS certificate compression — investigate per implementation

[RFC 8879](https://www.rfc-editor.org/rfc/rfc8879.html) defines Brotli as one TLS
certificate compression algorithm. The receiver decompresses the certificate
message before normal certificate parsing and verification. As an inference,
certificate validation cannot protect a decoder invoked earlier in that path;
the actual implementation and negotiation must still be established.

Check both client-side decoding of server certificates and, where implemented
and negotiated, server-side decoding of client certificates. Identify TLS 1.3
support, advertised/selected compression algorithms, registration of a Brotli
decompression callback, its linked library, and attacker control of the peer.
BoringSSL's
[certificate compression extension logic](https://github.com/google/boringssl/blob/main/ssl/extensions.cc)
uses registered compression/decompression callbacks; merely linking BoringSSL
does not establish that a Brotli decoder is registered. Search for
`SSL_CTX_add_cert_compression_alg`, `TLSEXT_cert_compression_brotli`,
`CompressedCertificate`, and `BrotliDecoder` at the call sites and build inputs.

Distinguish certificate compression from HTTP body compression and historical
TLS record compression. A successful TLS handshake or a trusted-certificate
policy alone does not establish this path's patch status or eliminate the
pre-verification input surface. Do not claim universal unauthenticated server
exposure: protocol role, negotiation, provider, buffering, and configuration matter.

## Reporting unresolved cases

If only source is present, leave build selection and shipment unknown. If an
artifact is known but native provenance is missing, leave patch status unknown.
If the caller or active configuration is missing, leave reachability unknown.
Record the next missing evidence for each row so another reviewer can close the
specific gap. Avoid calling an entire application fixed based on one source file,
one package, or one reviewed route.
