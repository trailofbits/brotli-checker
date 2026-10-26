# Ecosystem integration guide

Language-level imports and API calls are discovery leads. They can identify a
wrapper family and a possible decoding route, but they do not identify the
selected package, native provider, deployed version, or code patch state. Keep
the result unknown until those identities are established. A package or runtime
advisory applies only to the implementation and release it names; do not transfer
the C advisory to an independent pure-language port.

For every lead, preserve the source location and trace:

`source call -> selected package/runtime -> shipped decoder -> input owner`

## Python

Treat `import brotli` and `import brotlicffi` as native-decoder integration
leads, including aliases and imports used by an HTTP library. The module name is
not patch evidence.

Google's [`setup.py`](https://github.com/google/brotli/blob/master/setup.py)
builds the PyPI `Brotli` module as an `_brotli` C extension. Its default source
list includes `c/dec/decode.c`; `USE_SYSTEM_BROTLI=1` instead links
`libbrotlidec`, `libbrotlienc`, and `libbrotlicommon`. Therefore, inspect the
installed `_brotli` extension and its package/build provenance. For a system
linked build, also resolve and scan the deployed library provider rather than
assuming the host's current library is selected.

`brotlicffi` is also a native/reference-code binding, not a pure Python decoder.
Its [build script](https://github.com/python-hyper/brotlicffi/blob/main/setup.py)
compiles the `libbrotli/c` sources by default and has a `USE_SHARED_BROTLI`
build mode. Inspect the installed CFFI extension, build configuration, and any
shared provider. The same Python source can select different implementations;
for example, [HTTPX first imports `brotli` and falls back to `brotlicffi`](https://github.com/encode/httpx/blob/master/httpx/_decoders.py),
then feeds response bytes through that selected module's `Decompressor`.

For unmodified ecosystem releases, the PyPA advisory database records `Brotli`
1.2.1 as the first fixed PyPI release in its range and `brotlicffi` 1.2.1.0 as
the first fixed release in its range
([Brotli advisory](https://github.com/pypa/advisory-database/blob/main/vulns/brotli/PYSEC-2026-4322.yaml),
[brotlicffi advisory](https://github.com/pypa/advisory-database/blob/main/vulns/brotlicffi/PYSEC-2026-4323.yaml)).
Do not apply those Python package comparisons to distro revisions, forks, local
rebuilds, or system-linked extensions. For those, use the provider's advisory
and artifact evidence.

Reachability still depends on the caller. Direct `decompress` or `Decompressor`
use may consume files, messages, request bodies, or HTTP responses. For HTTP
clients, confirm that Brotli support is installed and selected, that response
decoding is enabled, and who controls the URL, redirects, and response bytes.
An optional import alone does not prove the decoder runs.

Also inspect direct FFI: a `ctypes.CDLL`/`LoadLibrary` or CFFI `dlopen` of
`libbrotlidec`, plus declarations or calls of exact `BrotliDecoder*` APIs, can
bypass the `brotli` and `brotlicffi` module names. Treat the library string and
ABI declaration as native-provider leads. Resolve the actual loaded file and
deployed search path; an FFI name does not prove provider identity or patch
state.

## JVM

Distinguish the package namespace before applying any C advisory:

- `com.aayushatharva.brotli4j` is a JNI wrapper with platform-specific
  `native-*` artifacts. The
  [Brotli4j advisory](https://github.com/hyperxpro/Brotli4j/security/advisories/GHSA-x524-jrqf-vwq6)
  states that releases through 1.23.0 bundle affected native C decoders and
  that 1.24.0 updates the wrapper and native artifacts to Brotli 1.2.1. It names
  `Decoder`, `DirectDecompress`, `BrotliInputStream`, `BrotliDecoderChannel`, and
  `DecoderJNI` as decoder entry points. Inspect the resolved dependency graph,
  the exact platform classifier JAR, and the extracted `.so`, `.dll`, or
  `.dylib`. Updating the OS Brotli library does not replace Brotli4j's bundled
  provider.
- `org.brotli:dec` is a Java implementation. Its
  [Maven build](https://github.com/google/brotli/blob/master/java/org/brotli/dec/pom.xml)
  packages `org/brotli/dec/*.java`, and
  [`BrotliInputStream`](https://github.com/google/brotli/blob/master/java/org/brotli/dec/BrotliInputStream.java)
  calls the Java `Decode` implementation. The C CVE and C release version rules
  do not classify this port. Review Java-specific advisories and implementation
  behavior separately. This does not clear a second JNI or native copy in the
  same application.

A bounded static spot-check of Google Brotli tags `v1.2.0` and `v1.2.1` found
byte-identical Java
[`Decode.java`](https://github.com/google/brotli/blob/db24a98aed38a16de78cc05ca15cdd8dc2a0d92d/java/org/brotli/dec/Decode.java)
files. For one block type, `readMetablockPartition` installs a `1 << 28`
sentinel. A regular metablock is at most `1 << 24` output bytes, and the command
loop leaves the metablock before any one-type literal, command, or distance
counter can exhaust that sentinel. Therefore the exact invalid-block-switch
condition fixed in the C decoder is unreachable through this reviewed Java
state path. This bounded result is not a whole-port safety claim and does not
transfer C release status to Java.

For Maven or Gradle, resolve effective versions, constraints, classifiers,
shading, and the runtime classpath; a declaration can be overridden or unused.
For a built JAR/WAR, inspect dependency metadata and class namespaces. A shaded
or renamed namespace may remain unknown. For Brotli4j, follow the actual JNI
loading path to the shipped native member. Then trace the decoder call through
HTTP handlers or file parsers to the input owner and active configuration.

## .NET

`System.IO.Compression.BrotliStream` and `BrotliDecoder` are runtime/native
decoder leads, not stand-alone NuGet dependency evidence. The .NET runtime
[interop source](https://github.com/dotnet/runtime/blob/main/src/libraries/Common/src/Interop/Interop.Brotli.cs)
imports `BrotliDecoderCreateInstance`, `BrotliDecoderDecompressStream`, and
`BrotliDecoderDecompress` from `Libraries.CompressionNative`.

Use Microsoft's
[CVE-2026-111497 advisory](https://github.com/dotnet/runtime/security/advisories/GHSA-p3jp-9v83-76w9)
for .NET release status. It identifies explicit `BrotliStream`/`BrotliDecoder`
use, ASP.NET Core request decompression with `br`, and `HttpClient` automatic
Brotli response decompression as relevant routes. It also states that ASP.NET
Core and `HttpClient` do not enable those Brotli routes by default and that
.NET Framework is not affected.

Resolve the deployment model before checking the version:

- For a framework-dependent application, identify the shared runtime actually
  selected on the serving host or container, verify its update, and confirm the
  process restarted.
- For a self-contained deployment, inspect the runtime shipped with the
  application. Updating only the machine-wide runtime does not replace it;
  rebuild and redeploy with an updated SDK/runtime.
- For NativeAOT, identify the SDK, ILCompiler/runtime-pack inputs, and published
  executable. Microsoft's advisory says the decoder can be linked into the
  application, so a shared-runtime update does not replace it.

A target framework in a `.csproj`, a developer-machine SDK, or an API call does
not establish the deployed runtime version. Trace source configuration and API
calls to the deployed artifact, then determine whether request bodies, response
bodies, files, or other attacker-influenced streams reach the decoder.

Do not confuse the built-in runtime with `BrotliSharpLib`, an independent C#
port. Its
[0.3.3 source](https://github.com/master131/BrotliSharpLib/blob/c070999692e36a28889131953ac08b2e3ba180ea/BrotliSharpLib/Decode/Decode.cs)
uses unsafe pointers and unmanaged allocations. A bounded static review found
that one-type block counters are also initialized to `1 << 28`, while a regular
metablock and every parsed insert-length overshoot remain below that sentinel.
The exact invalid-block-switch helper is therefore unreachable through the
reviewed public decode state. This does not review unrelated unsafe operations
or establish whole-library safety. Do not classify `BrotliSharpLib` under
Microsoft's .NET runtime ranges or Google's C ranges.

## Rust

Separate native wrappers from Rust implementations:

- `brotli2` is a binding to the official C implementation and uses
  `brotli-sys`; the
  [`brotli-sys` build script](https://github.com/bitemyapp/brotli2-rs/blob/master/brotli-sys/build.rs)
  compiles vendored `brotli/dec/decode.c`. `brotlic` similarly describes itself
  as a thin wrapper requiring a C compiler and contains `brotlic-sys`
  ([project and API documentation](https://github.com/AronParker/brotlic)).
  Resolve the crate version, vendored Brotli revision, features, and rebuilt
  artifact; the Rust wrapper version is not the embedded C version.
- Dropbox's `brotli` and `brotli-decompressor` are Rust implementations. The
  [`brotli` manifest](https://github.com/dropbox/rust-brotli/blob/master/Cargo.toml)
  describes safe Rust code and depends on `brotli-decompressor`. Its optional
  C-compatible exports, and the related `brotli-ffi` crate, do not turn that
  implementation into Google's C decoder. Do not apply C release ranges to
  these crates.

  The Rust port independently retained the same invalid-block-switch status
  conflation. Its
  [fix commit](https://github.com/dropbox/rust-brotli-decompressor/commit/cc7ee0edae39870daa7f0d7c1456e113b759e752)
  changes all switch paths to return and propagate the dedicated format error;
  `brotli-decompressor` 6.2.0 contains that fix. Exact review found the old
  boolean path in tags 4.0.0 through 6.1.1. The `brotli` wrapper 9.1.0 requires
  the fixed decompressor generation, but resolve the actual lockfile version
  rather than inferring it from a wrapper constraint. This is independent-port
  evidence: do not claim the C out-of-bounds write or its impact. A focused
  internal-state test distinguished the old and fixed status behavior; a
  crafted public compressed-input path and impact were not reproduced.

Cargo manifests and locks usually retain the native crate name, even when the
dependency key is aliased. Source/build evidence can still reveal copied or
renamed wrappers: `#[link(name = "brotlidec")]`, a
`cargo:rustc-link-lib`/pkg-config selection of `libbrotlidec`, or exact
`BrotliDecoder*` declarations inside an `extern "C"` boundary. Treat these as
native-provider leads only. Inspect the final executable or shared library and
resolve dynamic providers. Do not add generic `decompress`, `Decoder`, or
`curl-sys` matches: libcurl's Brotli support is build-dependent and must be
established from the selected libcurl and shipped provider.

For reachability, locate construction and reads/writes through the selected
decoder, then trace the input to an HTTP response/body, uploaded file, message,
or other owner. A crate in `Cargo.lock` does not prove that its code is linked or
called.

## Go

Google's `github.com/google/brotli/go/cbrotli` is a C binding. Its
[`cgo.go`](https://github.com/google/brotli/blob/master/go/cbrotli/cgo.go)
selects `libbrotlicommon`, `libbrotlidec`, and `libbrotlienc` through
pkg-config. Its
[`Reader`](https://github.com/google/brotli/blob/master/go/cbrotli/reader.go)
includes `brotli/decode.h` and calls `C.BrotliDecoderCreateInstance`,
`C.BrotliDecoderDecompressStream`, and related APIs. A `go get` update alone
does not replace the system library selected by that cgo build; inspect build
records, the executable, and its deployed provider.

An ordinary module graph exposes the `cbrotli` import in go.mod/go.sum. Copied,
replaced, or internally renamed wrappers may only expose a `.go` cgo directive.
High-confidence native leads are the exact official import path, a `#cgo`
pkg-config/LDFLAGS directive naming `libbrotlidec`, or `import "C"` together
with `brotli/decode.h` or exact `C.BrotliDecoder*` calls. Generic `NewReader`,
`Decode`, `br`, and decompression names are too noisy.

[`github.com/andybalholm/brotli`](https://github.com/andybalholm/brotli)
describes itself as a pure-Go encoder and decoder. Do not classify it, or other
Go ports, with Google's C version rules unless native linkage is independently
proved.

This Go port independently retained the analogous boolean/status bug. The
maintainer accepted
[issue 82](https://github.com/andybalholm/brotli/issues/82) and fixed it in
[commit 33c2a98](https://github.com/andybalholm/brotli/commit/33c2a9884269798192b5ecf171288f98939dbe42),
tagged v1.2.7. Exact review found the old path in every tag from v1.0.0 through
v1.2.6. Treat those as an implementation-specific update/review concern, not
as evidence of native memory corruption. A focused internal-state test
distinguished v1.2.6 from v1.2.7, but did not reproduce a crafted compressed
input through the public API; the reporter's suggested panic impact remains an
inference.

Trace `cbrotli.NewReader`, `cbrotli.Decode`, or a reviewed wrapper alias to the
input owner and deployment. An import establishes neither a live code path nor
attacker control.

## Ruby

The `miyucy/brotli` gem is a native extension. Its
[`gemspec`](https://github.com/miyucy/brotli/blob/master/brotli.gemspec)
registers `ext/brotli/extconf.rb`; the
[`extconf.rb`](https://github.com/miyucy/brotli/blob/master/ext/brotli/extconf.rb)
either links system `libbrotlicommon`, `libbrotlidec`, and `libbrotlienc` or
compiles vendored Google Brotli C sources. Do not use the gem version as the C
version or assume that updating the OS library replaces a vendored extension.

Inspect Gemfile and Gemfile.lock selection, the installed gem specification,
native extension, build log/configuration, and vendored submodule or dynamic
provider. Source uses such as `require "brotli"` with `Brotli.inflate`,
`Brotli::Reader`, or `Brotli::Decompressor` are reachability leads. A generic
`inflate` method or `Content-Encoding` string is not.

Trace the selected API through Rack middleware, HTTP clients, file processing,
or background jobs to the compressed input owner. Presence in the bundle does
not establish that the native decoder is loaded or called.

## PHP

`kjdev/php-ext-brotli` is a native PHP extension. Its
[`config.m4`](https://github.com/kjdev/php-ext-brotli/blob/master/config.m4)
supports system `libbrotlidec` through pkg-config and otherwise compiles bundled
`brotli/c/dec/decode.c`. Composer's
[`ext-<name>` platform packages](https://getcomposer.org/doc/01-basic-usage.md#platform-packages)
represent PHP extensions, so an `ext-brotli` requirement is a precise extension
lead but supplies no native decoder version.

Inspect composer.json/composer.lock, deployment extension installation, loaded
`brotli.so`, build configuration, and bundled or dynamic provider. Exact calls
to `brotli_uncompress`, `brotli_uncompress_init`, and
`brotli_uncompress_add`, and an `extension=brotli.so` setting, are useful source
or configuration leads. Do not match generic `uncompress`, `br`, or compression
settings.

Trace one-shot and incremental decompression separately through request parsing,
HTTP clients, uploads, queues, or other input paths. The extension's output
compression feature is encoding and does not by itself establish a decoder
route.

## JavaScript, TypeScript, WebAssembly, and packaged runtimes

Use explicit Brotli imports and APIs as leads; do not seed a generic
`decompress`, `fetch`, `WebAssembly.instantiate`, or `Accept-Encoding: br`
reference. JavaScript package names and globals are replaceable, and conditional
exports can select different code for Node, browsers, bundlers, and workers.
Preserve the import location, then resolve the selected package entry point and
the shipped decoder bytes.

Separate these common families:

- Node's `node:zlib` APIs (`brotliDecompress`, `brotliDecompressSync`,
  `createBrotliDecompress`, and `BrotliDecompress`) are native-runtime leads.
  Node's [`node_zlib.cc`](https://github.com/nodejs/node/blob/main/src/node_zlib.cc)
  includes `brotli/decode.h` and implements Brotli contexts around that API.
  Node-compatible APIs in Bun, Deno, or another runtime do not prove that Node's
  provider is selected.
- `new DecompressionStream("brotli")` explicitly selects Brotli but leaves the
  provider runtime-specific. Brotli is part of the
  [WHATWG Compression format enum](https://compression.spec.whatwg.org/), and
  Node added the format in 22.20.0/24.7.0 according to its
  [Web Streams documentation](https://nodejs.org/api/webstreams.html#new-decompressionstreamformat).
  Browser engines and other runtimes require their own artifact/advisory evidence.
- Bun is an example where package/runtime identity matters. Its
  [CVE-2026-111497 advisory](https://github.com/oven-sh/bun/security/advisories/GHSA-663w-cv8g-jj2p)
  names automatic `fetch` response decoding, `node:zlib`, and
  `DecompressionStream("brotli")`, and warns that `bun build --compile`
  executables embed the runtime and must be rebuilt. Do not transfer Bun's
  version rule to Node, a browser, or a userland package.
- [`brotli-wasm`](https://github.com/httptoolkit/brotli-wasm) wraps Dropbox's
  Rust Brotli crate in WebAssembly. [`brotli-dec-wasm`](https://github.com/ustclug-dev/brotli-dec-wasm)
  and [`@nick/brotli`](https://github.com/nberlette/brotli) use the Rust
  `brotli-decompressor` implementation. These are not Google C decoder evidence.
- [`brotli`](https://github.com/foliojs/brotli.js) uses an independent hand-ported
  JavaScript decoder. `brotli-compress` can select a Rust/Wasm entry point or a
  JavaScript port. Resolve the imported entry point instead of classifying either
  package from its name.
- A package such as `@wasm-zoo/brotli` can instead ship Google Brotli C compiled
  to WebAssembly. A Brotli-named `.wasm` import is therefore an artifact lead,
  not proof of Rust, JavaScript, or C provenance. The ELF matcher does not
  classify WebAssembly code; retain unknown until the module's source revision
  and shipped bytes are reviewed.

### Independent JavaScript port spot check

The foliojs decoder was inspected separately at commit
[`4011e59a5c35bb602f3e97f114727aa662f795f7`](https://github.com/foliojs/brotli.js/tree/4011e59a5c35bb602f3e97f114727aa662f795f7).
Its block-switch structure differs from the affected C state machine:

- `DecodeMetaBlockLength` uses at most six size nibbles for a non-metadata
  metablock, so its decoded length is at most `1 << 24`
  ([source](https://github.com/foliojs/brotli.js/blob/4011e59a5c35bb602f3e97f114727aa662f795f7/dec/decode.js#L98-L143)).
- Each metablock initializes all three block lengths to `1 << 28`, and only
  replaces a length after decoding block trees when the corresponding block-type
  count is at least two
  ([source](https://github.com/foliojs/brotli.js/blob/4011e59a5c35bb602f3e97f114727aa662f795f7/dec/decode.js#L639-L717)).
- The command, literal, and distance switch sites run only when those lengths
  reach zero
  ([source](https://github.com/foliojs/brotli.js/blob/4011e59a5c35bb602f3e97f114727aa662f795f7/dec/decode.js#L755-L838)).

Consequently, the reviewed one-shot port does not expose the same
`max_block_type <= 1` forced-switch path as the affected C decoder: a single-type
length starts sixteen times above the maximum metablock length. A benign upstream
fixture (`quickfox.compressed`) decoded byte-for-byte at this revision. This is a
bounded structural spot check, not a general unaffected verdict: no malformed
corpus/fuzz campaign was run, later releases can change the state machine, and a
deployment can contain this port alongside a separate native or C/Wasm decoder.
