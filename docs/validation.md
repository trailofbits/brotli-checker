# Validation record

Checked on **2026-10-23**. This record describes source detection, scanner
behavior, and a benign local fetch-decoding test. **No deployed application or
binary was tested, and no malformed or exploit payload was executed.** The
fetch test demonstrates a decoding route, not CVE triggerability or exploitation.

## Vulnerable reference and fixed control

The vulnerable target was [Google Brotli v1.2.0's decoder source](https://github.com/google/brotli/blob/v1.2.0/c/dec/decode.c).
The fixed control was [v1.0.10's decoder source](https://github.com/google/brotli/blob/v1.0.10/c/dec/decode.c).
Neither source file was compiled or executed for this scanner validation.

| Target | Expected and observed classification | SHA-256 |
| --- | --- | --- |
| v1.2.0 `c/dec/decode.c` | `vulnerable_source` | `f7749b1296128c0add4eaa454b9d82ee1c7b0451c1c9ed47d96733e6de6f2d7b` |
| v1.0.10 `c/dec/decode.c` | `fixed_source` | `44a4c1973553725c693dc38136cd32a5ec97a471bba8bf5c25bd23fa5b486542` |

A direct CLI scan of these two files returned exit 1, retained both findings,
and reported no scan gaps. Both findings retained `build_selection: unknown`,
`shipment: unknown`, `reachability: unknown`, and `exploitability: not_assessed`.
The fixed control did not clear the vulnerable source finding.

To repeat this check, download the two linked decoder files into a separate
directory, verify the hashes above, and pass both filenames to:

```sh
python3 skills/brotli-checker/scripts/brotli_inventory.py vulnerable.c fixed.c --json
```

## Full fingerprint verification

```sh
uv run --locked python scripts/verify_fingerprints.py
```

This online maintainer check downloaded all 20 registered reference files,
verified their byte lengths, SHA-256 and Git blob identities, checked the
block-switch patterns against the recorded state, and confirmed all expected
source classifications: 17 vulnerable and three fixed. It also appended an
annotation to each source and confirmed 20 modified-source classifications:
old logic warns; modified fixed-looking logic remains unknown.

Reference bytes are inspected in memory and never executed. URLs, states, and
hashes are retained in [the packaged registry](../skills/brotli-checker/references/fingerprints.json).

## Benign built-in fetch validation

Run the trusted maintainer fixture with a Node.js runtime that provides built-in fetch:

```sh
make verify-node-fetch
```

The [probe](../skills/brotli-checker/scripts/verify_node_fetch.cjs) starts an ephemeral HTTP server
bound to `127.0.0.1`. It serves only a known, valid Brotli-compressed text body.
It instruments `node:zlib.createBrotliDecompress`, calls built-in fetch, consumes
the response, and asserts both the decoded text and invocation of that native
decoder wrapper. It restores the wrapper and closes the server afterwards.
The scanner itself never runs this probe or target application code.

Observed on both of these local runtimes:

| Node runtime | Bundled Undici | Reported Brotli |
| --- | --- | --- |
| v20.9.0 | 5.26.3 | 1.0.9 |
| v24.22.1 | 7.30.1 | 1.2.0 |

| Request case (both runtimes) | Observed Accept-Encoding | Correct decoded body | Native Brotli wrapper calls |
| --- | --- | --- | --- |
| Default HTTP fetch | `gzip, deflate` | Yes | 1 |
| Explicit identity | `identity` | Yes | 1 |
| Follow a loopback redirect with identity | `identity` on both requests | Yes | 1 |

The raw JSON results for [Node 20.9.0](artifacts/node-fetch-validation.json) and
[Node 24.22.1](artifacts/node-fetch-validation-24.22.1.json) record the runtimes,
requests, and assertions. The results confirm that a Brotli response can reach
the built-in fetch decoder even without a request advertising Brotli.
The identity header does not disable that response decoding in either tested runtime.

The Node 24.22.1 macOS ARM64 distribution was obtained from
[nodejs.org](https://nodejs.org/dist/v24.22.1/) and verified against the official
[SHA-256 checksums](https://nodejs.org/dist/v24.22.1/SHASUMS256.txt):
`89c682593d76cd44233fa53b1563264e7de9cbb189cad169135c5b4fadfbc0a7`.
It still reports Brotli 1.2.0; the component version string alone does not
identify the runtime's vendor patches. Verify the Node build and advisory
rather than treating that string as proof of an unpatched decoder.

These are local valid-response tests. They do not exercise the invalid
block-switch bug, establish a vendor binary's patch state, prove exploitation,
or establish attacker control of URLs/responses in a real application. The
runtime strings are recorded for reproducibility; this old runtime is not a
deployment recommendation.

## Scanner regression coverage

The offline suite covers version boundaries, mixed copies, hidden dependency
trees, renamed ZIP/TAR archives, compressed streams, extensionless nested image
layers, unsupported package signatures and names, size/count/depth limits,
unreadable paths, symlinks, and safe text rendering under strict UTF-8 output.
It also checks actionable advice for metadata, binaries, and end-of-life Node
versions. Fetch coverage includes built-in/global references, aliases, optional
calls, template expressions, Undici imports and lockfiles, source inside nested
archives, bounded evidence with line/column locations, and comments/string
controls. Browser/custom fetch references remain unresolved; supplied fixed Node
or Brotli versions cannot clear an unrelated fetch lead. Archive members are
never extracted, and JavaScript targets are never executed.

The container test constructs a TAR layer containing a Brotli-named library
fixture inside an extensionless blob in an outer TAR. Supplying a separately
fixed Brotli version must still return review-required status because the
library's patch status is unknown. This is a synthetic packaging test, not a
scan of a real deployed image or proof that a binary is vulnerable.

Observed results: all **115 tests passed on Python 3.12, 3.13, 3.14, and 3.15**.
The Python 3.12 run reported **92.03% combined line and branch coverage**.
Ruff formatting/lint, ty type checks, and zizmor's offline pedantic checks passed.
These local runs do not establish the result of a future hosted CI run.
CI is configured to repeat the benign fetch probe on Node 24.22.1 alongside
the Python matrix.

## Open-issue regressions

The following fixes preserve conservative verdicts while correcting reporting:

| Issue | Verified behavior |
| --- | --- |
| [#1: truncated gap details](https://github.com/trailofbits/brotli-checker/issues/1) | At 200 and 202 gaps, JSON distinguishes total, retained, and omitted details. Text only promises the retained details available in JSON and states when paths were discarded. |
| [#2: unknown version identity](https://github.com/trailofbits/brotli-checker/issues/2) | Every supplied version retains its component and original string. Text names the component and explains ambiguity, missing snapshot rules, or end-of-life status, with the corresponding build/vendor check. |
| [#3: stored nested archive clues](https://github.com/trailofbits/brotli-checker/issues/3) | Complete traversal of a stored WAR/JAR fixture reports only the leaf component's name/symbol clues, grouped into one display row. Depth/budget limits retain raw markers as container evidence in a separate display section, without treating them as independent decoder copies. |
| [#4: archive counter semantics](https://github.com/trailofbits/brotli-checker/issues/4) | Corrupt ZIP, TAR, and gzip inputs each record one attempt and zero successful opens. A ZIP that opens but has a member CRC failure records one successful open and a gap. A gzip-wrapped TAR counts once. |

The JSON schema retains `archives_opened`, now counting successful opens rather
than failed attempts. The additive `archives_attempted` field records parser
invocations; recognized unsupported formats and depth limits block parsing
before an attempt. ZIP/TAR opens count once the parser opens the container.
Compressed streams count after a bounded decompression read returns; opening
their inner TAR does not count again. Later member failures do not undo an
open and always leave coverage gaps.

`gap_count` includes all observed gaps. `gap_details_retained` is the length of
`gaps`, capped at 200; `gap_details_omitted` counts discarded detail records.
Omitted paths cannot be recovered by switching output formats.

Run the offline suite and static checks with:

```sh
make lint
make test
zizmor --offline --pedantic .github/workflows/checks.yml
```

## What remains unvalidated

- Selection of an affected source file by an application's actual build.
- Patch state of a real shipped binary, including stripped or static copies.
- Which decoder a running process uses, or whether untrusted input reaches it.
- Built-in Node.js fetch processing a malformed CVE-triggering stream, or a
  deployed app's fetch path and attacker-controlled URL/response inputs.
- A crash, memory corruption, or exploitation in an application.
- Complete inventory of arbitrary containers, encodings, or deployments.

Known unsupported formats are reported as gaps, but arbitrary signature-free
compression cannot always be recognized. Symlink targets must be checked
directly; targets outside the traversed files remain gaps. Container layer
inspection does not apply whiteouts or reconstruct the final filesystem.

These limits apply even when an individual source file or supplied version
meets a known fix rule. The scanner's exit 0 never certifies an application safe.
