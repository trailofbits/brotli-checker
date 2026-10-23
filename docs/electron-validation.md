# Electron and Slack measurements

Measured on **2026-10-23**, on macOS ARM64. Valid compressed text responses
confirmed Brotli decoding in Electron and in the installed Slack renderer.
**No malformed stream or exploit payload was used. Slack's decoder patch status
and reachability from messages, previews, or uploads remain unknown.**

## Installed Slack

The checked Mac App Store installation was Slack **4.51.180**, with Electron
**43.1.1** and Chromium **150.0.7871.114**. Its code signature verified. The
framework's SHA-256 was unchanged after testing. The inspection and binary
comparison are recorded in [the artifact](artifacts/slack-4.51.180-inspection.json).

A separate Slack instance used a fresh temporary profile inside its app
container. The user's normal Slack instance was closed before the successful
run. A loopback debugging connection navigated the test renderer to our own
local page and evaluated browser `fetch()`. No workspace login, message,
upload, or production preview was used. The page supplied its own restrictive
content security policy; the test did not bypass CSP or disable the renderer
sandbox. The application's actual renderer sandbox setting was not independently
verified. `require` was unavailable in the page; a `process` object was present,
which alone does not establish access to Node APIs.

The fixture served known plain text or that same text compressed with Brotli.
Both HTTP and HTTPS servers bound to `127.0.0.1`. HTTPS used an ephemeral
self-signed certificate, trusted through a command-line exception restricted to
that certificate's public-key hash. Chromium's other HTTP traffic used an
unavailable loopback proxy. This proxy does not independently block Node or OS
network traffic. The test profile and test process were removed afterwards.

These results were identical over HTTP and HTTPS:

| Slack renderer request | Observed Accept-Encoding | Correct body | Redirect followed |
| --- | --- | --- | --- |
| Plain response control | `gzip, deflate, br, zstd` | Yes | No |
| Default fetch, Brotli response | `gzip, deflate, br, zstd` | Yes | No |
| Attempted identity header, Brotli response | `gzip, deflate, br, zstd` | Yes | No |
| Attempted identity header, redirect to Brotli response | `gzip, deflate, br, zstd` on both requests | Yes | Yes |

All **eight cases passed**, including **six Brotli responses**. The browser
did not send the attempted `Accept-Encoding: identity` header. This is not
evidence that a browser request actually sent identity and decoded anyway.
[Raw Slack results](artifacts/slack-renderer-validation-4.51.180.json).

This establishes response decoding in the installed application's renderer
when opened on the fixture by a trusted debugger. It does not establish that an
attacker can cause the normal Slack UI to load that page or deliver arbitrary
compressed bytes through a message, preview, attachment, or redirect.

Two earlier startup attempts used an additional `sandbox-exec` wrapper. Local
crash reports identified those test processes trapping in
`_libsecinit_appsandbox` during dynamic-loader initialization, before reaching
the fixture. Removing that wrapper allowed the measurement. Those startup
crashes are not Brotli CVE trigger evidence.

## Separate official Electron runtime

The official Electron **43.1.1 macOS ARM64** archive was checked against its
release's `SHASUMS256.txt`:

```text
electron-v43.1.1-darwin-arm64.zip
d6d0598d042ef4d146278d08d84deac9dde145eae31eb4f32ef46206d6bd6169
```

The release archive checksum matched. macOS `codesign --verify --deep --strict`
on the extracted official app returned an error: "code has no resources but
signature indicates they must be present". Signature verification of that
archive is therefore not claimed. The installed Slack signature verified
separately.

The runtime reported Node **24.18.0**, Undici **7.28.0**, Brotli **1.2.0**, and
Chromium **150.0.7871.114**. A hidden sandboxed window with Node integration
disabled used an isolated in-memory session. The fixture also tested Node
fetch, Electron `net.fetch`, and `session.fetch` in the main process.

The following results were identical over HTTP and HTTPS:

| API | Default Brotli response | Explicit/attempted identity | Identity plus redirect |
| --- | --- | --- | --- |
| Main-process Node fetch | Decoded | Identity sent; decoded | Identity sent; decoded |
| Electron net.fetch | Decoded | Identity sent; `ERR_CONTENT_DECODING_FAILED` | Identity sent; same error |
| Electron session.fetch | Decoded | Identity sent; `ERR_CONTENT_DECODING_FAILED` | Identity sent; same error |
| Sandboxed renderer fetch | Decoded | Browser omitted identity; decoded | Browser omitted identity; decoded |

All eight plain-response controls also decoded correctly. The **32-case
measurement** recorded the expected decoding results and rejection cases with
no validation errors. The native Node Brotli wrapper was called once for each
of Node fetch's six compressed responses and zero times for its plain controls.
The Chromium paths did not call that Node wrapper. Chromium's native decoder
was not instrumented; the matching decoded bytes establish response decoding.
The rejection cases do not prove absence of native decoder entry.
[Raw Electron results](artifacts/electron-fetch-validation-43.1.1.json).

The fixture hashes in the raw reports identify the script bytes used for those
runs. The checked-in scripts were subsequently formatted without behavioral
changes; both formatted scripts pass Node's syntax check.

## Patch evidence and its limits

Electron 43.1.1's [DEPS](https://github.com/electron/electron/blob/v43.1.1/DEPS)
select Chromium 150.0.7871.114 and Node 24.18.0. Its
[Node build patch](https://github.com/electron/electron/blob/v43.1.1/patches/node/build_add_gn_build_files.patch#L323-L338)
replaces Node's bundled Brotli dependency with Chromium's decoder and encoder.
Chromium's [component record](https://github.com/chromium/chromium/blob/150.0.7871.114/third_party/brotli/README.chromium)
selects Brotli revision `cfa184a997ac19454d5a3ae97f6d600aac2445a6`, a descendant
of the [upstream fix](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b).

This is source/build-selection evidence. The installed Slack framework's ARM64
machine-code section differs in both size and hash from official Electron
43.1.1. A matching version label cannot authenticate Slack's decoder code.
The offline helper does not classify Mach-O code, and ASAR packages need
separate static inspection. Neither normal decompression nor a component
version string distinguishes this vulnerability's affected and fixed logic.
**Slack's shipped decoder patch state remains unknown.**

## Repeat the measurements

These are explicit maintainer fixtures; the offline scanner never launches them.
Use an independently obtained, checksum-verified Electron runtime:

```sh
env -u NODE_OPTIONS -u NODE_PATH -u ELECTRON_RUN_AS_NODE \
  BROTLI_CHECKER_OUTPUT=electron-result.json \
  /path/to/Electron.app/Contents/MacOS/Electron \
  "$PWD/skills/brotli-checker/scripts/verify_electron_fetch.cjs"
```

The Electron fixture requires OpenSSL on PATH and a runtime embedding Node
24.5 or newer for temporary CA configuration. No CA is installed in the OS.

To repeat the installed Slack renderer test, **quit normal Slack first** and
use Node 24 or newer:

```sh
env -u NODE_OPTIONS -u NODE_PATH \
  BROTLI_CHECKER_OUTPUT=slack-result.json \
  node scripts/verify_slack_renderer.cjs
```

The Slack fixture verifies the installed app's signature and refuses to launch
while a normal Slack main process is present. It targets `/Applications/Slack.app`
and the standard macOS app container. It launches the app, navigates its test
window through a loopback debugging connection, and closes that instance.
Do not wrap the App Sandbox build in another `sandbox-exec` profile.
No test asserts that the whole application is fixed or exploitable.
